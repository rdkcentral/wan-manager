/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/* ---- Include Files ---------------------------------------- */
#include <unistd.h>
#include <time.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/filter.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include "ipc_msg.h"
#include "wanmgr_network_monitor.h"
#include "ansc_platform.h"
#include "ansc_string_util.h"
#include <sysevent/sysevent.h>
#include "secure_wrapper.h"
#include "wanmgr_dhcpv6_apis.h"

/* ---- Global Variables ------------------------------------ */
int sysevent_nwm_fd = -1;
token_t sysevent_token;

static int maxFd = 50;
int netlinkRouteMonitorFd = -1; //subscribe to route change events

/* Optional ICMPv6 Neighbour Discovery debug listener.
 *
 * A virtual WAN interface (e.g. 'vdsl0') is often layered on top of a base interface
 * (e.g. 'ptm0'). Depending on how the stack is built, the kernel may put the ND frames
 * on the base device rather than on the virtual one, so both are captured in parallel
 * and each capture is reported independently. */
#define ND_MON_MAX_IFACES 2 // slot 0: virtual interface, slot 1: its base interface
#define ND_MON_HEARTBEAT_SEC 30

/* Per interface ICMPv6 counters maintained by the kernel itself, see /proc/net/dev_snmp6 */
typedef struct
{
    unsigned long long outNS;
    unsigned long long outNA;
    unsigned long long inNS;
    unsigned long long inNA;
} NdMonitorIcmp6Stats_t;

typedef struct
{
    int           fd;
    char          ifname[IF_NAMESIZE];
    unsigned int  ifindex;
    char          attempt[IF_NAMESIZE]; // interface the last open was attempted for
    time_t        lastAttempt;
    time_t        lastIfindexCheck;
    unsigned long pktSeen;
    /* PACKET_STATISTICS is cleared by the kernel on every read, so the totals are kept here */
    unsigned long long    statsAccepted;
    unsigned long long    statsDropped;
    NdMonitorIcmp6Stats_t icmp6Base; // kernel counters sampled when the capture was opened
    bool                  icmp6BaseValid;
} NdMonitorSlot_t;

/* Owned by the network monitor thread, fds are set to -1 by NetMonitor_InitNdMonitorSlots() */
static NdMonitorSlot_t ndMonitorSlot[ND_MON_MAX_IFACES];
static time_t ndMonitorLastHeartbeat = 0;
/* Set by the interface state machine threads, protected by ndMonitorMutex */
static pthread_mutex_t ndMonitorMutex = PTHREAD_MUTEX_INITIALIZER;
static char ndMonitorReqIfname[ND_MON_MAX_IFACES][IF_NAMESIZE] = {{0}};
/* Absolute time the capture window closes, anchored on the start request. Protected by
 * ndMonitorMutex, 0 when no capture is requested. */
static time_t ndMonitorDeadline = 0;
/* TRUE once the state machine has asked for the capture to stop, so the fact that the
 * window is being held open is reported only once per capture */
static bool ndMonitorStopNoted = FALSE;
fd_set readFdsMaster;
static fd_set errorFdsMaster;
static bool g_toggle_flag = TRUE;
#define UPDATE_MAXFD(f) (maxFd = (f > maxFd) ? f : maxFd)

#define LOOP_TIMEOUT 100000 // timeout in milliseconds. This is the state machine loop interval
#define SYSEVENT_IPV6_TOGGLE        "ipv6Toggle"
#define SYSEVENT_OPEN_MAX_RETRIES   6
#define SE_SERVER_WELL_KNOWN_PORT   52367
#define SE_VERSION                  1
#define NETMONITOR_SYSNAME          "netmonitor"
#define SYS_IP_ADDR                 "127.0.0.1"

/* ICMPv6 Neighbour Discovery capture, driven by the interface state machine */
#define ND_MON_RETRY_INTERVAL_SEC   2
#define ND_MON_IFINDEX_CHECK_SEC    5
/* Packets drained per loop iteration, and the receive buffer that has to hold anything
 * arriving in between. Both are sized so that no captured NS/NA is lost to a burst. */
#define ND_MON_MAX_BURST_READ       64
#define ND_MON_RCVBUF_BYTES         (256 * 1024)
/* Every captured NS/NA is logged, nothing is rate limited away, because a missed packet
 * is exactly the evidence this capture exists to provide. What bounds the log volume is
 * the capture window itself: it closes this many seconds after it was started, whether or
 * not the state machine has asked for it to stop. */
#define ND_MON_MAX_CAPTURE_SEC      300
/* Operator driven override, so a capture can be run on demand for as long as it is needed
 * (e.g. to watch a manual 'ndisc6' probe or an 'ip -6 addr add' DAD run) without having to
 * wait for the DHCPv6 client to restart. While it is set it replaces the interfaces asked
 * for by the state machine and suspends the capture window entirely:
 *   sysevent set wanmgr_nd_capture "vdsl0 ptm0"  -> capture both, with no time limit
 *   sysevent set wanmgr_nd_capture ""            -> back to the automatic behaviour */
#define SYSEVENT_ND_CAPTURE         "wanmgr_nd_capture"
#define ND_MON_SYSEVENT_POLL_SEC    2
/* The RDK logger silently truncates each message at ~320 characters. A fully decoded NA
 * needs more than that, and what fell off the end was the tail of the line: the option
 * dump, the packet type and the interface. Losing the interface made the same frame seen
 * on both the virtual and the base device look like two identical duplicates. The decoded
 * packet is therefore emitted in chunks small enough that the logger always keeps them,
 * so no field is lost however many ND options a packet carries. */
#define ND_MON_LOG_CHUNK            240
/* Cache of the capture interface's own IPv6 addresses, used only to explain why a
 * solicitation for one of them is never answered on the wire */
#define ND_MON_LOCAL_ADDR_MAX       16
#define ND_MON_LOCAL_ADDR_REFRESH   5

#if defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)
#define SYSEVENT_MAP_BR_IPV6_PREFIX "map_br_ipv6_prefix"
#define SYSEVENT_MAPT_CONFIG_FLAG "mapt_config_flag"
#define SET "set"

#define MTU_DEFAULT_SIZE (1500)
#define MAPT_MTU_SIZE (1520)
#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
#define MAP_WAN_IFACE "current_wan_ifname"
#else
#define MAP_WAN_IFACE "wan_ifname"
#endif
#define BUFLEN_64 64
#define BUFLEN_128 128
#define BUFLEN_256 256
#define BUFLEN_1024 1024
#endif
/* ---- Private Function Prototypes -------------------------- */
static void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len); // Parse the route entries
static ANSC_STATUS parse_addrattr(struct nlmsghdr *nlh); // Parse the interface address entries
static ANSC_STATUS isDefaultGatewaypresent(struct nlmsghdr* nlmsgHdr); // check for default gateway
static time_t NetMonitor_MonotonicSec(void); // steady clock, unaffected by NTP stepping the wall clock
static void NetMonitor_InitNdMonitorSlots(void); // mark every ICMPv6 ND capture slot as closed
static void NetMonitor_ApplyNdMonitorRequest(void); // start/stop the ICMPv6 ND capture on request
static void NetMonitor_ProcessNdMonitorFd(NdMonitorSlot_t *slot); // parse the captured ICMPv6 NS/NA packets
static void NetMonitor_DeInitNdMonitorFd(NdMonitorSlot_t *slot);
static void* NetworkMonitorThread( void *arg );

#if defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)
static int get_v6_default_gw_wan(char *defGateway, size_t length)
{
    int ret = ANSC_STATUS_SUCCESS,pclose_ret = 0;
    char line[BUFLEN_1024] = {0};
    struct in6_addr in6Addr;
    FILE *fp;


    fp = v_secure_popen("r","ip -6 route show default | grep default | awk '{print $3}'");

    if (fp)
    {
        if (fgets(line, sizeof(line), fp) != NULL)
        {
            char *token = strtok(line, "\n");
            if (token)
            {
                if (inet_pton (AF_INET6, token, &in6Addr) <= 0)
                {
                    CcspTraceError(("Invalid ipv6 address=%s \n", token));
                    ret = ANSC_STATUS_FAILURE;
                    return ret;
                }
                strncpy(defGateway, token, length);
                CcspTraceInfo(("IPv6 Default GW address  = %s \n", defGateway));
            }
            else
            {
                CcspTraceError(("Could not parse ipv6 gw addr\n"));
                ret = ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            CcspTraceError(("Could not read ipv6 gw addr \n"));
            ret = ANSC_STATUS_FAILURE;
        }
        pclose_ret = v_secure_pclose(fp);
	if(pclose_ret !=0)
	{
	    CcspTraceInfo(("Failed in closing the pipe ret %d \n",pclose_ret));
	}
    }
    else
    {
        CcspTraceError(("Failed to get the default gw address \n"));
        ret = ANSC_STATUS_FAILURE;
    }

    return ret;
}

static int WanManager_MaptRouteSetting()
{
    CcspTraceInfo(("%s Enter \n", __FUNCTION__));

    char brIPv6Prefix[BUFLEN_256] = {0};
    char vlanIf[BUFLEN_64] = {0};
    char defaultGatewayV6[BUFLEN_128] = {0};
    int ret =0;
    char partnerID[BUFLEN_32]    = {0};

    syscfg_get(NULL, "PartnerID", partnerID, sizeof(partnerID));
    int mtu_size_mapt = MTU_DEFAULT_SIZE; /* 1500 */

    if ( 0 == strcmp("sky-italia", partnerID) )
    {
        mtu_size_mapt = MAPT_MTU_SIZE; /* 1520 */
    }

    CcspTraceInfo(("MAPT MTU Size = %d \n", mtu_size_mapt));

    sysevent_get(sysevent_nwm_fd, sysevent_token, MAP_WAN_IFACE, vlanIf, sizeof(vlanIf));
    if (!strcmp(vlanIf, "\0"))
    {
        CcspTraceInfo(("%s Failed to get sysevent (%s) \n", __FUNCTION__, MAP_WAN_IFACE));
        return ANSC_STATUS_FAILURE;
    }

    sysevent_get(sysevent_nwm_fd, sysevent_token, SYSEVENT_MAP_BR_IPV6_PREFIX, brIPv6Prefix, sizeof(brIPv6Prefix));
    if (!strcmp(brIPv6Prefix, "\0"))
    {
        CcspTraceError(("%s Failed to get sysevent (%s) \n", __FUNCTION__, SYSEVENT_MAP_BR_IPV6_PREFIX));
        return ANSC_STATUS_FAILURE;
    }

    if(get_v6_default_gw_wan(defaultGatewayV6, sizeof(defaultGatewayV6)) == ANSC_STATUS_FAILURE)
    {
        return ANSC_STATUS_FAILURE;
    }

    /*
     * Configure IPv6 default route with MTU for specific partner "sky-italia"
     * Todo: Cleanup should be done to configure MTU based on delegated leases from DHCPv6 server or partners configurations
     */
    if ( 0 == strcmp(partnerID, "sky-italia") )
    {
        ret = v_secure_system("ip -6 route change default via %s dev %s mtu %d", defaultGatewayV6, vlanIf, MTU_DEFAULT_SIZE);
        if(ret != 0) {
            CcspTraceError(("%s %d: Failure in executing command via v_secure_system. ret:[%d] \n", __FUNCTION__,__LINE__,ret));
        }
    }
    ret = v_secure_system("ip -6 route replace %s via %s dev %s mtu %d", brIPv6Prefix, defaultGatewayV6, vlanIf, mtu_size_mapt);
    if(ret != 0) {
          CcspTraceError(("%s %d: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,__LINE__,ret));
    }
}
#endif // FEATURE_MAPT && NAT46_KERNEL_SUPPORT

static void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }

        rta = RTA_NEXT(rta,len);
    }
}

static ANSC_STATUS parse_addrattr(struct nlmsghdr *nlh) 
{
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;
    struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
    char ifname[IF_NAMESIZE] = {0},
         ipv6_addr[INET6_ADDRSTRLEN] = {0};
    unsigned int  prefix_length = 0,
                  pref_lifetime = 0,
                  valid_lifetime = 0;
    /* ifa_flags only carries the low 8 bits, the IFA_FLAGS attribute below carries all 32 */
    unsigned int  addr_flags = ifa->ifa_flags;
    IPv6NetLinkAddrEvent stAddrEvent;

    //Allow only for Global Scope
    if (ifa->ifa_scope != RT_SCOPE_UNIVERSE) {
        return ret;
    }

    if (if_indextoname(ifa->ifa_index, ifname) == NULL) {
        CcspTraceError(("%s-%d [ADDR EVENT] Failed to retreive interface name for ifindex=%d\n", __FUNCTION__, __LINE__, ifa->ifa_index));
        return ret;
    }

    //CcspTraceInfo(("%s-%d [ADDR EVENT] ifindex=%d name=%s family=%d\n", __FUNCTION__, __LINE__, ifa->ifa_index, ifname, ifa->ifa_family));

    int len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
    struct rtattr *rta = IFA_RTA(ifa);

    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == IFA_ADDRESS) {
            if (ifa->ifa_family == AF_INET6) {
                inet_ntop(AF_INET6, RTA_DATA(rta), ipv6_addr, sizeof(ipv6_addr));

                //Ignore link-local & multicast addresses
                if (strncmp(ipv6_addr, "fe80", 4) == 0 || strncmp(ipv6_addr, "ff", 2) == 0) {
                    continue;
                }

                prefix_length = ifa->ifa_prefixlen;
                CcspTraceInfo(("%s-%d [ADDR EVENT] IPv6 address: %s/%d\n", __FUNCTION__, __LINE__, ipv6_addr, ifa->ifa_prefixlen));
            }
        }
        if (rta->rta_type == IFA_CACHEINFO) {
            struct ifa_cacheinfo *ci = RTA_DATA(rta);
            pref_lifetime   = ci->ifa_prefered;
            valid_lifetime  = ci->ifa_valid;
            CcspTraceInfo(("%s-%d [ADDR EVENT] preferred_lft=%u sec, valid_lft=%u sec\n",
                                                    __FUNCTION__, __LINE__,
                                                    ci->ifa_prefered, ci->ifa_valid));
        }
        if (rta->rta_type == IFA_FLAGS) {
            addr_flags = *(unsigned int *)RTA_DATA(rta);
        }
    }

    CcspTraceInfo(("%s-%d [ADDR EVENT] flags=0x%08x%s%s%s%s\n", __FUNCTION__, __LINE__, addr_flags,
                   (addr_flags & IFA_F_TENTATIVE)  ? " TENTATIVE"  : "",
                   (addr_flags & IFA_F_DADFAILED)  ? " DADFAILED"  : "",
                   (addr_flags & IFA_F_DEPRECATED) ? " DEPRECATED" : "",
                   (addr_flags & IFA_F_PERMANENT)  ? " PERMANENT"  : ""));

    if (nlh->nlmsg_type == RTM_NEWADDR) 
    {
       memset(&stAddrEvent, 0, sizeof(IPv6NetLinkAddrEvent));
       snprintf(stAddrEvent.event, sizeof(stAddrEvent.event), "NEWADDR");
       snprintf(stAddrEvent.ifname, sizeof(stAddrEvent.ifname), "%s", ifname);
       snprintf(stAddrEvent.addr, sizeof(stAddrEvent.addr), "%s", ipv6_addr);
       stAddrEvent.prefix_len    = prefix_length;
       stAddrEvent.preferred_lft = pref_lifetime;
       stAddrEvent.valid_lft     = valid_lifetime;

       CcspTraceInfo(("%s-%d [ADDR EVENT] RTM_NEWADDR (new/updated address) for '%s' interface, Info 'NEWADDR|%s|%u|%u|%u'\n", __FUNCTION__, __LINE__, ifname, ipv6_addr, prefix_length, pref_lifetime, valid_lifetime));
       WanMgr_Handle_Dhcpv6_NetLink_Address_Event(&stAddrEvent);

       /* The kernel reports a DAD failure as an RTM_NEWADDR carrying IFA_F_DADFAILED, not as a separate event.
        * Recovery is handled by checkIpv6AddressIsReadyToUse() in the interface state machine, not here. */
       if ((addr_flags & IFA_F_DADFAILED) && (ipv6_addr[0] != '\0'))
       {
           CcspTraceError(("%s-%d [ADDR EVENT] DAD FAILED for address %s/%u on '%s' interface, flags=0x%08x\n",
                           __FUNCTION__, __LINE__, ipv6_addr, prefix_length, ifname, addr_flags));
       }

       ret = ANSC_STATUS_SUCCESS;
    } 
    else if (nlh->nlmsg_type == RTM_DELADDR) 
    {
       memset(&stAddrEvent, 0, sizeof(IPv6NetLinkAddrEvent));
       snprintf(stAddrEvent.event, sizeof(stAddrEvent.event), "DELADDR");
       snprintf(stAddrEvent.ifname, sizeof(stAddrEvent.ifname), "%s", ifname);
       snprintf(stAddrEvent.addr, sizeof(stAddrEvent.addr), "%s", ipv6_addr);
       stAddrEvent.prefix_len    = prefix_length;
       stAddrEvent.preferred_lft = pref_lifetime;
       stAddrEvent.valid_lft     = valid_lifetime;

       CcspTraceInfo(("%s-%d [ADDR EVENT] RTM_DELADDR (address removed/expired) for '%s' interface, Info 'DELADDR|%s|%u|%u|%u'\n", __FUNCTION__, __LINE__, ifname, ipv6_addr, prefix_length, pref_lifetime, valid_lifetime));
       WanMgr_Handle_Dhcpv6_NetLink_Address_Event(&stAddrEvent);
       ret = ANSC_STATUS_SUCCESS;
    }

    return ret;
}

static ANSC_STATUS isDefaultGatewaypresent(struct nlmsghdr* nlmsgHdr)
{
    struct rtmsg* route_entry = NLMSG_DATA(nlmsgHdr);
    struct rtattr* tb[RTA_MAX+1];
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;

    int len = nlmsgHdr->nlmsg_len - NLMSG_LENGTH(sizeof(*route_entry));

    if (len < 0) {
        CcspTraceError(("%s Wrong message length \n", __FUNCTION__));
        return ret;
    }

    // We are just interested in main routing table
    if (route_entry->rtm_table != RT_TABLE_MAIN) {
        return ret;
    }

    parse_rtattr(tb, RTA_MAX, RTM_RTA(route_entry), len);

    if ( (tb[RTA_DST] == 0)  && (route_entry->rtm_dst_len == 0) ) {
        CcspTraceInfo(("%s-%d: Found Default gateway in route event \n", __FUNCTION__, __LINE__));
        ret = ANSC_STATUS_SUCCESS;
    }

    return ret;
}

static ANSC_STATUS NetMonitor_InitNetlinkRouteMonitorFd()
{
    struct sockaddr_nl addr;

    CcspTraceInfo(("%s Enter \n", __FUNCTION__));

    netlinkRouteMonitorFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (netlinkRouteMonitorFd < 0)
    {
        CcspTraceError(("%s Failed to create netlink socket: %s\n", __FUNCTION__, strerror(errno)));
        return ANSC_STATUS_FAILURE;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
    if (0 > bind(netlinkRouteMonitorFd, (struct sockaddr *) &addr, sizeof(addr)))
    {
        CcspTraceError(("%s Failed to bind netlink socket: %s\n", __FUNCTION__, strerror(errno)));
        close(netlinkRouteMonitorFd);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s Bound netlinkRouteMonitorFd to 0x%x  \n", __FUNCTION__, addr.nl_groups));

    return ANSC_STATUS_SUCCESS;
}

static void NetMonitor_DoToggleV6Status(bool flag)
{
    CcspTraceInfo(("%s-%d: Enter \n", __FUNCTION__, __LINE__));

    g_toggle_flag = flag;

    if (g_toggle_flag == TRUE)
    {
        CcspTraceInfo(("%s-%d: Toggle Needed \n", __FUNCTION__, __LINE__));
        sysevent_set(sysevent_nwm_fd, sysevent_token, SYSEVENT_IPV6_TOGGLE, "TRUE", 0);
        g_toggle_flag = FALSE;
    }
    else
    {
        CcspTraceInfo(("%s-%d: No Toggle Needed \n", __FUNCTION__, __LINE__));
        sysevent_set(sysevent_nwm_fd, sysevent_token, SYSEVENT_IPV6_TOGGLE, "FALSE", 0); 
    }
}

static void netMonitor_SyseventInit()
{
    int try = 0;

    /* Open sysevent descriptor to send messages */
    while(try < SYSEVENT_OPEN_MAX_RETRIES)
    {
       sysevent_nwm_fd =  sysevent_open(SYS_IP_ADDR, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, NETMONITOR_SYSNAME, &sysevent_token);
       if(sysevent_nwm_fd >= 0)
       {
          break;
       }
       try++;
       usleep(50000);
    }
        CcspTraceInfo(("%s-%d: Started \n", __FUNCTION__, __LINE__));
}

/* All ICMPv6 ND capture timing is measured with this rather than with time(NULL).
 *
 * time(NULL) follows CLOCK_REALTIME, which NTP is free to step. On a CPE the clock is
 * typically wrong at boot and gets corrected a minute or two later, and that correction
 * is a forward jump of arbitrary size. Measuring the capture window against it meant a
 * single NTP step could retire a 300 sec window after only a few seconds of real time,
 * closing the listeners long before the traffic they were opened for appeared.
 * CLOCK_MONOTONIC cannot be stepped, so the window always lasts as long as it claims. */
static time_t NetMonitor_MonotonicSec(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return time(NULL); // should not happen, a steadily increasing value is all that matters
    }
    return ts.tv_sec;
}

static void NetMonitor_ProcessNetlinkRouteMonitorFd()
{
    struct sockaddr_nl local;   // local addr struct
    char buf[8192];             // message buffer
    struct iovec iov;           // message structure
    iov.iov_base = buf;         // set message buffer as io
    iov.iov_len = sizeof(buf);  // set size
    struct nlmsghdr *nl_msgHdr;
    static bool gw_v6_flag = FALSE;
#if defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)
    char maptConfigFlag[BUFLEN_128] = {0};
#endif

    // initialize protocol message header
    struct msghdr msg;
    {
        msg.msg_name = &local;                  // local address
        msg.msg_namelen = sizeof(local);        // address size
        msg.msg_iov = &iov;                     // io vector
        msg.msg_iovlen = 1;                     // io size
    }

    //DBG_MONITOR_PRINT("%s-%d: \n", __FUNCTION__, __LINE__);

    ssize_t status = recvmsg(netlinkRouteMonitorFd, &msg, 0);
    if (status <= 0) {
        CcspTraceError(("%s-%d: Received Message Status Failed %d \n", __FUNCTION__, __LINE__, status));
        return;
    }

    for(nl_msgHdr = (struct nlmsghdr *) buf; NLMSG_OK (nl_msgHdr, (unsigned int)status); nl_msgHdr = NLMSG_NEXT (nl_msgHdr, status))
    {
        /* Finish reading */
        if (nl_msgHdr->nlmsg_type == NLMSG_DONE)
        {
            return;
        }
        /* Message is some kind of error */
        if (nl_msgHdr->nlmsg_type == NLMSG_ERROR)
        {
            CcspTraceInfo(("%s netlink message error \n", __FUNCTION__));
            return;
        }

        switch(nl_msgHdr->nlmsg_type)
        {

            case RTM_NEWROUTE:
                 {
                     if(isDefaultGatewaypresent(nl_msgHdr) == ANSC_STATUS_SUCCESS){
                         if(gw_v6_flag == FALSE){
                             CcspTraceInfo((" %s  IPv6 Default route update - ADD \n", __FUNCTION__));
                             NetMonitor_DoToggleV6Status(FALSE);
#if defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)
                             sysevent_get(sysevent_nwm_fd, sysevent_token, SYSEVENT_MAPT_CONFIG_FLAG, maptConfigFlag, sizeof(maptConfigFlag));
                             if (!strcmp(maptConfigFlag, SET))
                             {
                                 WanManager_MaptRouteSetting();
                             }
#endif
                             gw_v6_flag = TRUE;
                         }
                     }
                     break;
                 }
            case RTM_DELROUTE:
                 {
                     if(isDefaultGatewaypresent(nl_msgHdr) == ANSC_STATUS_SUCCESS){
                         if(gw_v6_flag == TRUE){
                             CcspTraceInfo((" %s  IPv6 Default route update - DEL \n", __FUNCTION__));
                             NetMonitor_DoToggleV6Status(TRUE);
                             gw_v6_flag = FALSE;
                         }
                     }
                     break;
                }
            case RTM_NEWADDR:
            case RTM_DELADDR:
                {
                    parse_addrattr(nl_msgHdr);
                    break;
                }
            default:
                break;
        }
    }
    return;
}

static void NetMonitor_DeInitNetlinkRouteMonitorFd()
{
    if (netlinkRouteMonitorFd >= 0)
    {
        CcspTraceInfo(("%s-%d: \n", __FUNCTION__, __LINE__));
        close(netlinkRouteMonitorFd);
        netlinkRouteMonitorFd = -1;
    }
}

/* ---- IPv6 Neighbour Discovery (NS/NA) debug listener ---------------------
 *
 * Netlink only reports the *result* of Duplicate Address Detection (an
 * RTM_NEWADDR carrying IFA_F_DADFAILED). It never carries the ICMPv6 Neighbour
 * Advertisement that caused the failure, so it cannot tell us who defended the
 * address. This optional AF_PACKET listener captures ND traffic on the WAN
 * interface and logs the sender (link layer address, NA flags, target address)
 * so a DAD failure can be attributed to a real duplicate, an ND proxy, or a
 * router (e.g. VRRP) answering a Neighbour Solicitation on behalf of the address.
 *
 * Disabled by default. The interface state machine drives it through
 * WanMgr_NdMonitor_Start()/WanMgr_NdMonitor_Stop(): the capture is started when the
 * DHCPv6 client is started on a virtual interface and runs for a fixed window from
 * that point. WanMgr_NdMonitor_Stop() only records that the state machine no longer
 * needs it; it does not close the sockets, because the state machine reaches its DAD
 * verdict before the kernel has finished DAD for the global address and closing early
 * discarded exactly the frames this listener exists to show.
 *
 * Every captured NS/NA is logged in full, nothing is rate limited away. The bounded
 * window, not a log budget, is what keeps the volume in check.
 *
 * The capture runs in parallel on the virtual interface and on its base interface,
 * because the ND frames may only be visible on the underlying device.
 *
 * Note: AF_PACKET sockets require CAP_NET_RAW. If the capability is not granted
 * to wanmanager the socket creation fails with EPERM and the capture stays off.
 */

/* Keeps only ICMPv6 Neighbour Solicitation (135) and Neighbour Advertisement (136).
 *
 * The socket is bound with ETH_P_ALL (see NetMonitor_InitNdMonitorFd), so frames of every
 * protocol are offered to this filter and the IPv6 ethertype has to be checked explicitly.
 * It is read from the skb metadata rather than from the packet data because a SOCK_DGRAM
 * packet socket does not expose the link layer header to the filter.
 *
 * All other offsets are relative to the start of the IPv6 header, which is where the kernel
 * points the filter for a SOCK_DGRAM packet socket in both the receive and the transmit path. */
static struct sock_filter ndMonitorFilter[] = {
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, (unsigned int)(SKF_AD_OFF + SKF_AD_PROTOCOL)),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IPV6, 0, 6),          /* A is in host byte order */
    BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, 6),                       /* A <- IPv6 next header   */
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 4),
    BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, 40),                      /* A <- ICMPv6 type        */
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 1, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),                          /* accept                  */
    BPF_STMT(BPF_RET + BPF_K, 0),                                   /* drop                    */
};

static void NetMonitor_FormatLinkAddr(const unsigned char *lladdr, unsigned int len, char *out, size_t outlen)
{
    size_t off = 0;

    if (out == NULL || outlen == 0)
    {
        return;
    }

    if (lladdr == NULL || len == 0)
    {
        snprintf(out, outlen, "<none>");
        return;
    }

    out[0] = '\0';
    for (unsigned int i = 0; (i < len) && ((off + 3) < outlen); i++)
    {
        off += snprintf(out + off, outlen - off, (i == 0) ? "%02x" : ":%02x", lladdr[i]);
    }
}

/* Routers using VRRP answer with a virtual MAC of 00:00:5e:00:01:VRID (IPv4) or
 * 00:00:5e:00:02:VRID (IPv6), which identifies the BNG rather than a real host. */
static void NetMonitor_DescribeLinkAddr(const unsigned char *lladdr, unsigned int len, char *out, size_t outlen)
{
    if (out == NULL || outlen == 0)
    {
        return;
    }
    out[0] = '\0';

    if ((lladdr == NULL) || (len != ETH_ALEN))
    {
        return;
    }

    if ((lladdr[0] == 0x00) && (lladdr[1] == 0x00) && (lladdr[2] == 0x5e) && (lladdr[3] == 0x00))
    {
        if (lladdr[4] == 0x02)
        {
            snprintf(out, outlen, " (VRRP IPv6 virtual MAC, VRID=%u)", lladdr[5]);
        }
        else if (lladdr[4] == 0x01)
        {
            snprintf(out, outlen, " (VRRP IPv4 virtual MAC, VRID=%u)", lladdr[5]);
        }
    }
}

static const unsigned char* NetMonitor_FindNdOption(const unsigned char *opt, int len, unsigned char type, unsigned int *dataLen)
{
    while (len >= 8)
    {
        int optLen = opt[1] * 8; // ND option length is expressed in units of 8 octets

        if ((optLen <= 0) || (optLen > len))
        {
            break;
        }
        if (opt[0] == type)
        {
            *dataLen = (unsigned int)(optLen - 2);
            return opt + 2;
        }
        opt += optLen;
        len -= optLen;
    }

    return NULL;
}

static bool NetMonitor_IsAllNodesMulticast(const struct in6_addr *addr)
{
    static const unsigned char allNodes[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

    return (memcmp(addr->s6_addr, allNodes, sizeof(allNodes)) == 0);
}

/* The solicited-node multicast address of a target is ff02::1:ffXX:XXXX, built from its
 * low 24 bits (RFC 4291 Section 2.7.1). A DAD probe or an address resolution NS must be
 * sent to the one derived from its own target, anything else is worth flagging. */
static bool NetMonitor_IsSolicitedNodeMulticastOf(const struct in6_addr *addr, const struct in6_addr *target)
{
    static const unsigned char prefix[13] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff};

    return ((memcmp(addr->s6_addr, prefix, sizeof(prefix)) == 0) &&
            (memcmp(&addr->s6_addr[13], &target->s6_addr[13], 3) == 0));
}

/* How the link layer delivered the frame, which tells a frame addressed to us apart from
 * one we only saw because it was multicast or because we transmitted it ourselves */
static const char* NetMonitor_PktTypeToStr(unsigned char pkttype)
{
    switch (pkttype)
    {
        case PACKET_HOST:      return "to-us";
        case PACKET_BROADCAST: return "broadcast";
        case PACKET_MULTICAST: return "multicast";
        case PACKET_OTHERHOST: return "other-host";
        case PACKET_OUTGOING:  return "outgoing";
        default:               return "unknown";
    }
}

static const char* NetMonitor_NdOptTypeToStr(unsigned char type)
{
    switch (type)
    {
        case ND_OPT_SOURCE_LINKADDR: return "src_lladdr";
        case ND_OPT_TARGET_LINKADDR: return "tgt_lladdr";
        case ND_OPT_PREFIX_INFORMATION: return "prefix_info";
        case ND_OPT_REDIRECTED_HEADER:  return "redirected_hdr";
        case ND_OPT_MTU:             return "mtu";
        case 14:                     return "nonce"; // RFC 7527, used to detect looped back DAD probes
        default:                     return "unknown";
    }
}

/* Dumps every ND option present, so an unexpected or malformed option is visible rather
 * than silently ignored by the single-option lookups above */
static void NetMonitor_FormatNdOptions(const unsigned char *opt, int len, char *out, size_t outLen)
{
    size_t used = 0;
    int count = 0;

    out[0] = '\0';
    while (len >= 8)
    {
        int optLen = opt[1] * 8;
        int written;

        if ((optLen <= 0) || (optLen > len))
        {
            written = snprintf(out + used, outLen - used, "%s<malformed opt type=%u len=%u rem=%d>",
                               (count > 0) ? "," : "", opt[0], opt[1], len);
            if ((written > 0) && ((size_t)written < (outLen - used)))
            {
                used += (size_t)written;
            }
            return;
        }

        written = snprintf(out + used, outLen - used, "%s%s(t=%u,%uB)",
                           (count > 0) ? "," : "", NetMonitor_NdOptTypeToStr(opt[0]), opt[0], (unsigned int)optLen);
        if ((written <= 0) || ((size_t)written >= (outLen - used)))
        {
            return; // out of room, what is already formatted is still useful
        }
        used += (size_t)written;

        opt += optLen;
        len -= optLen;
        count++;
    }

    if (count == 0)
    {
        snprintf(out, outLen, "<none>");
    }
}

/* <linux/if_packet.h> cannot be included alongside <netpacket/packet.h> (both define
 * 'struct sockaddr_ll'/'struct packet_mreq'), so the PACKET_STATISTICS getsockopt() ABI
 * (two kernel-counted 32-bit counters) is declared locally instead. */
struct ndMonitorPacketStats
{
    unsigned int tp_packets; /* frames accepted by the attached BPF filter */
    unsigned int tp_drops;   /* accepted frames dropped because the socket receive buffer was full */
};

/* Kernel-side counters, independent of any userspace parsing. If the accepted total is 0 the
 * attached filter never matched any frame on this interface; if it is non-zero but no NS/NA
 * were logged, the bug is in the userspace parsing path instead.
 *
 * The option level must be SOL_PACKET. PACKET_STATISTICS has the same numeric value as
 * SO_BROADCAST, so reading it at SOL_SOCKET level silently succeeds and always reports zero.
 *
 * The kernel also clears the counters as part of this getsockopt(), so each call returns only
 * what accumulated since the previous one and the running totals are kept here. */
static void NetMonitor_LogNdSocketStats(NdMonitorSlot_t *slot, const char *context)
{
    struct ndMonitorPacketStats stats;
    socklen_t statsLen = sizeof(stats);

    if (slot->fd < 0)
    {
        return;
    }

    memset(&stats, 0, sizeof(stats));
    if (getsockopt(slot->fd, SOL_PACKET, PACKET_STATISTICS, &stats, &statsLen) == 0)
    {
        slot->statsAccepted += stats.tp_packets;
        slot->statsDropped  += stats.tp_drops;
        CcspTraceInfo(("%s-%d [ND MONITOR] %s kernel filter stats for '%s' (fd=%d): accepted=%llu dropped=%llu\n",
                       __FUNCTION__, __LINE__, context, slot->ifname, slot->fd,
                       slot->statsAccepted, slot->statsDropped));

        if (slot->statsDropped > 0)
        {
            CcspTraceError(("%s-%d [ND MONITOR] %llu frame(s) accepted by the filter on '%s' were dropped before "
                            "they could be read, the socket receive buffer overflowed\n",
                            __FUNCTION__, __LINE__, slot->statsDropped, slot->ifname));
        }
    }
    else
    {
        CcspTraceError(("%s-%d [ND MONITOR] Failed to read socket stats for '%s': %s\n",
                        __FUNCTION__, __LINE__, slot->ifname, strerror(errno)));
    }
}

/* Reads the per interface ICMPv6 counters the kernel exports in /proc/net/dev_snmp6/<ifname>.
 * These are incremented by the IPv6 stack itself, so they are completely independent of this
 * capture and of any BPF filter. */
static bool NetMonitor_ReadIcmp6DevStats(const char *ifname, NdMonitorIcmp6Stats_t *out)
{
    char path[64] = {0};
    char line[128] = {0};
    char name[64] = {0};
    unsigned long long value = 0;
    FILE *fp = NULL;

    memset(out, 0, sizeof(*out));

    snprintf(path, sizeof(path), "/proc/net/dev_snmp6/%s", ifname);
    fp = fopen(path, "r");
    if (fp == NULL)
    {
        return FALSE;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        if (sscanf(line, "%63s %llu", name, &value) != 2)
        {
            continue;
        }
        if (strcmp(name, "Icmp6OutNeighborSolicits") == 0)
        {
            out->outNS = value;
        }
        else if (strcmp(name, "Icmp6OutNeighborAdvertisements") == 0)
        {
            out->outNA = value;
        }
        else if (strcmp(name, "Icmp6InNeighborSolicits") == 0)
        {
            out->inNS = value;
        }
        else if (strcmp(name, "Icmp6InNeighborAdvertisements") == 0)
        {
            out->inNA = value;
        }
    }
    fclose(fp);

    return TRUE;
}

/* Ground truth for "did the kernel send/receive any ND on this interface at all".
 * If the deltas are zero the stack never produced an NS on this device, so there was simply
 * nothing to capture. If they are non-zero but the capture stayed empty, the frames bypass
 * the packet socket tap (hardware acceleration, or a different device carries them).
 *
 * The counters are a bonus, not a requirement: /proc/net/dev_snmp6 is not readable on every
 * platform, in which case the baseline read in NetMonitor_InitNdMonitorFd() already reported
 * it once and this is silently skipped for the rest of the capture. */
static void NetMonitor_LogIcmp6DevStats(NdMonitorSlot_t *slot, const char *context)
{
    NdMonitorIcmp6Stats_t now;

    if (!slot->icmp6BaseValid)
    {
        return;
    }

    if (!NetMonitor_ReadIcmp6DevStats(slot->ifname, &now))
    {
        slot->icmp6BaseValid = FALSE;
        return;
    }

    CcspTraceInfo(("%s-%d [ND MONITOR] %s kernel ICMPv6 ND counters for '%s' since capture started: "
                   "outNS=+%llu outNA=+%llu inNS=+%llu inNA=+%llu (absolute outNS=%llu inNA=%llu)\n",
                   __FUNCTION__, __LINE__, context, slot->ifname,
                   now.outNS - slot->icmp6Base.outNS, now.outNA - slot->icmp6Base.outNA,
                   now.inNS  - slot->icmp6Base.inNS,  now.inNA  - slot->icmp6Base.inNA,
                   now.outNS, now.inNA));

    /* The capture is only broken if the kernel did move ND traffic that we failed to see */
    if ((slot->pktSeen == 0) && (now.outNS != slot->icmp6Base.outNS))
    {
        CcspTraceError(("%s-%d [ND MONITOR] The kernel transmitted %llu Neighbour Solicitation(s) on '%s' "
                        "but the packet socket captured none, the frames are not reaching the AF_PACKET tap\n",
                        __FUNCTION__, __LINE__, now.outNS - slot->icmp6Base.outNS, slot->ifname));
    }
}

static const char* NetMonitor_ArphrdToStr(unsigned short type)
{
    switch (type)
    {
        case ARPHRD_ETHER:     return "ETHER";
        case ARPHRD_PPP:       return "PPP";
        case ARPHRD_LOOPBACK:  return "LOOPBACK";
        case ARPHRD_TUNNEL:    return "IPIP_TUNNEL";
        case ARPHRD_TUNNEL6:   return "IP6IP6_TUNNEL";
        case ARPHRD_SIT:       return "SIT";
        case ARPHRD_NONE:      return "NONE (no hardware header, e.g. tunnel/software device)";
        default:               return "OTHER";
    }
}

/* DAD requires the kernel to multicast a Neighbour Solicitation on the solicited-node address.
 * Linux skips that transmission entirely - jumping straight from TENTATIVE to PERMANENT -
 * for devices that are NOARP, point-to-point without multicast support, or loopback
 * (see addrconf_dad_start() in the kernel). On such a device this capture will legitimately
 * never see a frame, regardless of how correct the capture code is. */
static void NetMonitor_LogIfaceDadCapability(int fd, const char *ifname)
{
    struct ifreq ifr;
    unsigned int flags = 0;
    unsigned short hwtype = 0;

    if ((fd < 0) || (ifname == NULL))
    {
        return;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0)
    {
        flags = (unsigned int)ifr.ifr_flags;
    }
    else
    {
        CcspTraceError(("%s-%d [ND MONITOR] SIOCGIFFLAGS failed for '%s': %s\n",
                        __FUNCTION__, __LINE__, ifname, strerror(errno)));
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
    {
        hwtype = ifr.ifr_hwaddr.sa_family;
    }
    else
    {
        CcspTraceError(("%s-%d [ND MONITOR] SIOCGIFHWADDR failed for '%s': %s\n",
                        __FUNCTION__, __LINE__, ifname, strerror(errno)));
    }

    /* A NOARP, point-to-point or loopback device completes DAD without ever transmitting an
     * NS, so for those an empty capture is the expected result rather than a capture bug. */
    CcspTraceInfo(("%s-%d [ND MONITOR] '%s' link type=%s(%u) flags=0x%x [%s%s%s%s]\n",
                   __FUNCTION__, __LINE__, ifname, NetMonitor_ArphrdToStr(hwtype), hwtype, flags,
                   (flags & IFF_NOARP)       ? "NOARP "       : "",
                   (flags & IFF_POINTOPOINT) ? "POINTOPOINT " : "",
                   (flags & IFF_MULTICAST)   ? "MULTICAST "   : "NO-MULTICAST ",
                   (flags & IFF_LOOPBACK)    ? "LOOPBACK "    : ""));
}

/* A static zero initialised slot would hold fd 0, which is stdin and must never be
 * selected on or closed, so every slot is explicitly marked as closed first */
static void NetMonitor_InitNdMonitorSlots(void)
{
    for (int i = 0; i < ND_MON_MAX_IFACES; i++)
    {
        ndMonitorSlot[i].fd = -1;
    }
}

static ANSC_STATUS NetMonitor_InitNdMonitorFd(NdMonitorSlot_t *slot, const char *ifname, bool logFailure)
{
    struct sockaddr_ll sll;
    struct sock_fprog prog;
    int fd = -1;
    unsigned int ifindex = if_nametoindex(ifname);

    if (ifindex == 0)
    {
        if (logFailure)
        {
            CcspTraceError(("%s-%d [ND MONITOR] Interface '%s' not found, will retry\n", __FUNCTION__, __LINE__, ifname));
        }
        return ANSC_STATUS_FAILURE;
    }

    /* Created with protocol 0 so that no unfiltered packet can be queued before the filter is attached */
    fd = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        if (logFailure)
        {
            CcspTraceError(("%s-%d [ND MONITOR] Failed to create AF_PACKET socket for '%s': %s%s\n", __FUNCTION__, __LINE__,
                            ifname, strerror(errno), (errno == EPERM) ? " (CAP_NET_RAW is required)" : ""));
        }
        return ANSC_STATUS_FAILURE;
    }

    prog.len    = sizeof(ndMonitorFilter) / sizeof(ndMonitorFilter[0]);
    prog.filter = ndMonitorFilter;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
    {
        CcspTraceError(("%s-%d [ND MONITOR] Failed to attach ND packet filter for '%s': %s\n",
                        __FUNCTION__, __LINE__, ifname, strerror(errno)));
        close(fd);
        return ANSC_STATUS_FAILURE;
    }

    /* Every captured packet has to be logged, so the receive queue must be able to absorb a
     * burst that arrives between two iterations of the monitor loop. The default receive
     * buffer can be small on an embedded build, and once it overflows the kernel drops
     * frames that would never reach the log. A failure here is not fatal, PACKET_STATISTICS
     * reports any drop that does happen. */
    {
        int rcvbuf = ND_MON_RCVBUF_BYTES;

        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
        {
            CcspTraceError(("%s-%d [ND MONITOR] Failed to raise the receive buffer to %d bytes for '%s': %s\n",
                            __FUNCTION__, __LINE__, rcvbuf, ifname, strerror(errno)));
        }
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    /* ETH_P_ALL is required, not just desirable. A packet socket bound to a specific protocol
     * is registered in the kernel ptype_base hash, which is only walked on the receive path.
     * Locally transmitted frames are offered to packet sockets by dev_queue_xmit_nit(), and
     * that only walks ptype_all. Binding to ETH_P_IPV6 would therefore hide our own outgoing
     * DAD Neighbour Solicitation, which is exactly the frame this capture exists to show.
     * The BPF filter above is what narrows the traffic back down to ICMPv6 NS/NA. */
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)ifindex;
    if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
    {
        CcspTraceError(("%s-%d [ND MONITOR] Failed to bind AF_PACKET socket to '%s': %s\n", __FUNCTION__, __LINE__, ifname, strerror(errno)));
        close(fd);
        return ANSC_STATUS_FAILURE;
    }

    slot->fd            = fd;
    slot->ifindex       = ifindex;
    slot->pktSeen       = 0;
    slot->statsAccepted = 0;
    slot->statsDropped  = 0;
    snprintf(slot->ifname, sizeof(slot->ifname), "%s", ifname);
    CcspTraceInfo(("%s-%d [ND MONITOR] Listening for ICMPv6 NS/NA on '%s' (ifindex=%u, fd=%d)\n",
                   __FUNCTION__, __LINE__, ifname, ifindex, fd));
    NetMonitor_LogIfaceDadCapability(fd, ifname);

    slot->icmp6BaseValid = NetMonitor_ReadIcmp6DevStats(ifname, &slot->icmp6Base);
    if (!slot->icmp6BaseValid)
    {
        /* Only an optional cross check, the capture itself works without it */
        CcspTraceInfo(("%s-%d [ND MONITOR] Kernel ICMPv6 counters for '%s' are unavailable (%s: %s), "
                       "continuing without them\n", __FUNCTION__, __LINE__, ifname,
                       "/proc/net/dev_snmp6", strerror(errno)));
    }

    return ANSC_STATUS_SUCCESS;
}

static void NetMonitor_DeInitNdMonitorFd(NdMonitorSlot_t *slot)
{
    if (slot->fd >= 0)
    {
        /* The monitor thread can be held up elsewhere, for example inside the netlink
         * address handler while another thread owns the interface data lock. Frames the
         * kernel already accepted are then still sitting in the socket receive queue and
         * close() would silently discard them, so the queue is drained one last time. */
        NetMonitor_ProcessNdMonitorFd(slot);

        CcspTraceInfo(("%s-%d [ND MONITOR] Stopped listening on '%s', %lu ND packet(s) captured\n",
                       __FUNCTION__, __LINE__, slot->ifname, slot->pktSeen));
        NetMonitor_LogNdSocketStats(slot, "Final");
        NetMonitor_LogIcmp6DevStats(slot, "Final");
        FD_CLR(slot->fd, &readFdsMaster);
        close(slot->fd);
        slot->fd = -1;
    }
    slot->ifname[0] = '\0';
    slot->ifindex = 0;
    slot->icmp6BaseValid = FALSE;
}

/* Called by the interface state machine threads. Only the request is updated here,
 * the sockets themselves are always opened and closed by the network monitor thread.
 *
 * @param ifname     virtual interface the DHCPv6 client runs on, e.g. 'vdsl0'
 * @param baseIfname its base/parent interface, e.g. 'ptm0'. Optional, may be NULL.
 */
void WanMgr_NdMonitor_Start(const char *ifname, const char *baseIfname)
{
    const char *requested[ND_MON_MAX_IFACES] = { ifname, baseIfname };
    bool changed = FALSE;

    if ((ifname == NULL) || (ifname[0] == '\0'))
    {
        return;
    }

    /* The base interface is only worth a second capture if it is a different device */
    if ((baseIfname != NULL) && (strcmp(baseIfname, ifname) == 0))
    {
        requested[1] = NULL;
    }

    pthread_mutex_lock(&ndMonitorMutex);
    for (int i = 0; i < ND_MON_MAX_IFACES; i++)
    {
        const char *name = ((requested[i] != NULL) && (requested[i][0] != '\0')) ? requested[i] : "";

        if (strcmp(ndMonitorReqIfname[i], name) != 0)
        {
            changed = TRUE;
        }
        snprintf(ndMonitorReqIfname[i], sizeof(ndMonitorReqIfname[i]), "%s", name);
    }
    /* The window is anchored on the start, so repeated start requests for the same
     * interfaces cannot keep pushing the deadline out and extend the capture forever */
    if (changed || (ndMonitorDeadline == 0))
    {
        ndMonitorDeadline = NetMonitor_MonotonicSec() + ND_MON_MAX_CAPTURE_SEC;
        ndMonitorStopNoted = FALSE;
    }
    pthread_mutex_unlock(&ndMonitorMutex);

    if (changed)
    {
        CcspTraceInfo(("%s-%d [ND MONITOR] ICMPv6 ND capture requested on '%s' and base interface '%s', capturing every NS/NA for the next %d sec\n",
                       __FUNCTION__, __LINE__, ifname,
                       (requested[1] != NULL) ? requested[1] : "<none>", ND_MON_MAX_CAPTURE_SEC));
    }
}

void WanMgr_NdMonitor_Stop(const char *ifname)
{
    bool report = FALSE;
    time_t remaining = 0;

    /* The capture is deliberately not torn down here. The state machine reaches its own
     * DAD verdict well before the kernel has finished DAD for the global address, and it
     * was closing the socket in exactly that gap that lost the NS/NA this capture exists
     * for. The window instead runs to the deadline set by WanMgr_NdMonitor_Start(), which
     * is what bounds the log volume, and the sockets are released there. */
    pthread_mutex_lock(&ndMonitorMutex);
    if ((ndMonitorReqIfname[0][0] != '\0') && ((ifname == NULL) || (strcmp(ndMonitorReqIfname[0], ifname) == 0)))
    {
        report = !ndMonitorStopNoted;
        ndMonitorStopNoted = TRUE;
        remaining = ndMonitorDeadline - NetMonitor_MonotonicSec();
    }
    pthread_mutex_unlock(&ndMonitorMutex);

    if (report)
    {
        CcspTraceInfo(("%s-%d [ND MONITOR] ICMPv6 ND capture no longer required on '%s', keeping it open for the remaining %ld sec of the window\n",
                       __FUNCTION__, __LINE__, (ifname != NULL) ? ifname : "any interface",
                       (remaining > 0) ? (long)remaining : 0L));
    }
}

/* Splits the SYSEVENT_ND_CAPTURE value ("vdsl0", "vdsl0,ptm0", "vdsl0 ptm0", ...) into
 * interface names. Returns FALSE when the value is empty or an explicit off token, which
 * is what hands control back to the interface state machine. */
static bool NetMonitor_ParseManualNdRequest(const char *value, char out[ND_MON_MAX_IFACES][IF_NAMESIZE])
{
    const char *p = value;
    int n = 0;

    for (int i = 0; i < ND_MON_MAX_IFACES; i++)
    {
        out[i][0] = '\0';
    }

    if (value == NULL)
    {
        return FALSE;
    }

    while ((*p != '\0') && (n < ND_MON_MAX_IFACES))
    {
        size_t len = 0;

        while ((*p == ',') || (*p == ' ') || (*p == '\t') || (*p == '\n') || (*p == '\r'))
        {
            p++;
        }
        while ((p[len] != '\0') && (p[len] != ',') && (p[len] != ' ') &&
               (p[len] != '\t') && (p[len] != '\n') && (p[len] != '\r'))
        {
            len++;
        }
        if (len == 0)
        {
            break; // trailing separators only
        }
        if (len >= IF_NAMESIZE)
        {
            len = IF_NAMESIZE - 1;
        }
        memcpy(out[n], p, len);
        out[n][len] = '\0';
        p += len;
        n++;
    }

    if (n == 0)
    {
        return FALSE;
    }

    if ((n == 1) && ((strcasecmp(out[0], "stop") == 0) || (strcasecmp(out[0], "off") == 0) ||
                     (strcasecmp(out[0], "false") == 0) || (strcmp(out[0], "0") == 0)))
    {
        out[0][0] = '\0';
        return FALSE;
    }
    return TRUE;
}

/* Polls the operator override. The sysevent round trip is throttled because this runs from
 * the monitor loop, which spins every LOOP_TIMEOUT. */
static bool NetMonitor_GetManualNdRequest(char out[ND_MON_MAX_IFACES][IF_NAMESIZE], time_t now)
{
    static time_t lastPoll = 0;
    static bool   active = FALSE;
    static char   cached[ND_MON_MAX_IFACES][IF_NAMESIZE] = {{0}};

    if ((sysevent_nwm_fd >= 0) && ((lastPoll == 0) || ((now - lastPoll) >= ND_MON_SYSEVENT_POLL_SEC)))
    {
        char parsed[ND_MON_MAX_IFACES][IF_NAMESIZE] = {{0}};
        char value[(IF_NAMESIZE * ND_MON_MAX_IFACES) + 16] = {0};
        bool wasActive = active;

        lastPoll = now;
        if (sysevent_get(sysevent_nwm_fd, sysevent_token, SYSEVENT_ND_CAPTURE, value, sizeof(value)) != 0)
        {
            value[0] = '\0';
        }
        active = NetMonitor_ParseManualNdRequest(value, parsed);

        if ((active != wasActive) || (memcmp(parsed, cached, sizeof(cached)) != 0))
        {
            if (active)
            {
                CcspTraceInfo(("%s-%d [ND MONITOR] Manual capture requested via '%s' on '%s' and '%s', "
                               "every NS/NA will be logged with no time limit until the sysevent is cleared\n",
                               __FUNCTION__, __LINE__, SYSEVENT_ND_CAPTURE,
                               parsed[0], (parsed[1][0] != '\0') ? parsed[1] : "<none>"));
            }
            else if (wasActive)
            {
                CcspTraceInfo(("%s-%d [ND MONITOR] Manual capture cleared via '%s', returning to the interface state machine request\n",
                               __FUNCTION__, __LINE__, SYSEVENT_ND_CAPTURE));
            }
        }
        memcpy(cached, parsed, sizeof(cached));
    }

    memcpy(out, cached, sizeof(cached));
    return active;
}

/* Opens, rebinds or closes the capture socket of a single slot to match its request */
static void NetMonitor_ApplyNdMonitorSlot(NdMonitorSlot_t *slot, const char *reqIfname, time_t now)
{
    bool firstAttempt = FALSE;

    if (reqIfname[0] == '\0')
    {
        if ((slot->fd >= 0) || (slot->attempt[0] != '\0'))
        {
            NetMonitor_DeInitNdMonitorFd(slot);
            slot->attempt[0] = '\0';
        }
        return;
    }

    if (slot->fd >= 0)
    {
        if (strcmp(slot->ifname, reqIfname) == 0)
        {
            if ((now - slot->lastIfindexCheck) < ND_MON_IFINDEX_CHECK_SEC)
            {
                return; // already listening on the requested interface
            }
            slot->lastIfindexCheck = now;

            /* The socket stays bound to the old ifindex if the interface is recreated */
            if (if_nametoindex(slot->ifname) == slot->ifindex)
            {
                return;
            }
            CcspTraceInfo(("%s-%d [ND MONITOR] Interface '%s' was recreated, rebinding\n", __FUNCTION__, __LINE__, slot->ifname));
        }
        NetMonitor_DeInitNdMonitorFd(slot);
        slot->attempt[0] = '\0';
    }

    firstAttempt = (strcmp(slot->attempt, reqIfname) != 0);
    if (!firstAttempt && ((now - slot->lastAttempt) < ND_MON_RETRY_INTERVAL_SEC))
    {
        return; // interface is not usable yet, retry on a later iteration
    }
    slot->lastAttempt = now;
    snprintf(slot->attempt, sizeof(slot->attempt), "%s", reqIfname);

    if (NetMonitor_InitNdMonitorFd(slot, reqIfname, firstAttempt) == ANSC_STATUS_SUCCESS)
    {
        slot->lastIfindexCheck = now;
        FD_SET(slot->fd, &readFdsMaster);
        UPDATE_MAXFD(slot->fd);
    }
}

static void NetMonitor_ApplyNdMonitorRequest(void)
{
    char reqIfname[ND_MON_MAX_IFACES][IF_NAMESIZE] = {{0}};
    char manualIfname[ND_MON_MAX_IFACES][IF_NAMESIZE] = {{0}};
    time_t now = NetMonitor_MonotonicSec();
    bool heartbeat = FALSE;
    bool expired = FALSE;
    bool manual = FALSE;

    /* An operator driven capture overrides the state machine request and is not bounded by
     * the capture window, so an on demand NS/NA trace can be left running for as long as the
     * test needs. It is read before the window is evaluated so that a manual capture cannot
     * be retired by a deadline that was armed for an earlier, automatic one. */
    manual = NetMonitor_GetManualNdRequest(manualIfname, now);

    pthread_mutex_lock(&ndMonitorMutex);
    /* The capture window closes a fixed time after it was started, whether or not the
     * state machine asked for it to stop. This is what bounds the log volume, since every
     * captured NS/NA is logged. */
    if (!manual && (ndMonitorReqIfname[0][0] != '\0') && (now >= ndMonitorDeadline))
    {
        for (int i = 0; i < ND_MON_MAX_IFACES; i++)
        {
            ndMonitorReqIfname[i][0] = '\0';
        }
        ndMonitorDeadline = 0;
        ndMonitorStopNoted = FALSE;
        expired = TRUE;
    }
    for (int i = 0; i < ND_MON_MAX_IFACES; i++)
    {
        snprintf(reqIfname[i], sizeof(reqIfname[i]), "%s", ndMonitorReqIfname[i]);
    }
    pthread_mutex_unlock(&ndMonitorMutex);

    if (manual)
    {
        memcpy(reqIfname, manualIfname, sizeof(reqIfname));
    }

    if (expired)
    {
        CcspTraceInfo(("%s-%d [ND MONITOR] Capture window of %d sec has elapsed, closing the listeners. "
                       "Run \"sysevent set %s '<ifname> <base ifname>'\" to capture every NS/NA on demand\n",
                       __FUNCTION__, __LINE__, ND_MON_MAX_CAPTURE_SEC, SYSEVENT_ND_CAPTURE));
    }

    /* Heartbeat so the logs can distinguish "fd is open but no matching traffic was seen"
     * from "the fd never got opened/bound in the first place" */
    if ((now - ndMonitorLastHeartbeat) >= ND_MON_HEARTBEAT_SEC)
    {
        heartbeat = TRUE;
        ndMonitorLastHeartbeat = now;
    }

    for (int i = 0; i < ND_MON_MAX_IFACES; i++)
    {
        NdMonitorSlot_t *slot = &ndMonitorSlot[i];

        if (heartbeat && (slot->fd >= 0))
        {
            CcspTraceInfo(("%s-%d [ND MONITOR] Still listening on '%s' (ifindex=%u, fd=%d) in %s mode, %lu ND packet(s) captured so far\n",
                           __FUNCTION__, __LINE__, slot->ifname, slot->ifindex, slot->fd,
                           manual ? "manual" : "automatic", slot->pktSeen));
            NetMonitor_LogNdSocketStats(slot, "Periodic");
            NetMonitor_LogIcmp6DevStats(slot, "Periodic");
        }

        NetMonitor_ApplyNdMonitorSlot(slot, reqIfname[i], now);
    }
}

/* TRUE when addr is configured on ifname itself.
 *
 * Soliciting an address that the box owns produces no NA on the wire: the reply is
 * destined for another of our own addresses, so the kernel routes it through the
 * loopback path and the frame never reaches the device a packet socket is bound to.
 * That is indistinguishable from a lost NA unless the capture says so explicitly.
 * The lookup is cached because it is only needed to annotate the log. */
static bool NetMonitor_IsLocalIfaceAddr(const char *ifname, const struct in6_addr *addr, time_t now)
{
    static time_t          lastRefresh = 0;
    static char            cachedIf[IF_NAMESIZE] = {0};
    static struct in6_addr cache[ND_MON_LOCAL_ADDR_MAX];
    static int             cacheCount = 0;

    if ((strcmp(cachedIf, ifname) != 0) || ((now - lastRefresh) >= ND_MON_LOCAL_ADDR_REFRESH))
    {
        struct ifaddrs *ifaList = NULL;

        cacheCount = 0;
        snprintf(cachedIf, sizeof(cachedIf), "%s", ifname);
        lastRefresh = now;

        if (getifaddrs(&ifaList) == 0)
        {
            for (struct ifaddrs *it = ifaList; (it != NULL) && (cacheCount < ND_MON_LOCAL_ADDR_MAX); it = it->ifa_next)
            {
                if ((it->ifa_addr != NULL) && (it->ifa_addr->sa_family == AF_INET6) &&
                    (it->ifa_name != NULL) && (strcmp(it->ifa_name, ifname) == 0))
                {
                    cache[cacheCount++] = ((struct sockaddr_in6 *) it->ifa_addr)->sin6_addr;
                }
            }
            freeifaddrs(ifaList);
        }
    }

    for (int i = 0; i < cacheCount; i++)
    {
        if (IN6_ARE_ADDR_EQUAL(&cache[i], addr))
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* Emits one decoded packet, split across as many log messages as it takes for the RDK
 * logger to keep all of it. Splits are made on field boundaries so a value is never cut
 * in half, and every chunk repeats the packet number so the parts stay correlated. */
static void NetMonitor_LogNdPacket(bool isError, unsigned long seq, bool rx, const char *line)
{
    size_t len = strlen(line);
    size_t off = 0;
    int part = 0;

    do
    {
        char chunk[ND_MON_LOG_CHUNK + 1];
        size_t n = len - off;

        if (n > ND_MON_LOG_CHUNK)
        {
            n = ND_MON_LOG_CHUNK;
            while ((n > 1) && (line[off + n] != ' '))
            {
                n--; // back up to a field boundary
            }
            if (n <= 1)
            {
                n = ND_MON_LOG_CHUNK; // single oversized field, cut it rather than loop forever
            }
        }

        memcpy(chunk, line + off, n);
        chunk[n] = '\0';
        off += n;
        while ((off < len) && (line[off] == ' '))
        {
            off++;
        }

        if (isError)
        {
            CcspTraceError(("%s-%d [ND MONITOR] #%lu %s %s%s\n", __FUNCTION__, __LINE__,
                            seq, rx ? "RX" : "TX", (part == 0) ? "" : "...cont ", chunk));
        }
        else
        {
            CcspTraceInfo(("%s-%d [ND MONITOR] #%lu %s %s%s\n", __FUNCTION__, __LINE__,
                           seq, rx ? "RX" : "TX", (part == 0) ? "" : "...cont ", chunk));
        }
        part++;
    } while (off < len);
}

static void NetMonitor_ProcessNdMonitorFd(NdMonitorSlot_t *slot)
{
    unsigned char buf[1500];
    struct sockaddr_ll sll;
    socklen_t sllLen;
    ssize_t len;

    for (int pkt = 0; pkt < ND_MON_MAX_BURST_READ; pkt++)
    {
        struct ip6_hdr *ip6       = (struct ip6_hdr *) buf;
        struct icmp6_hdr *icmp6   = NULL;
        const unsigned char *opts = NULL;
        const unsigned char *optLinkAddr = NULL;
        unsigned int optLinkAddrLen = 0;
        size_t ip6TotalLen = 0;
        int optLen = 0;
        char src[INET6_ADDRSTRLEN] = {0},
             dst[INET6_ADDRSTRLEN] = {0},
             target[INET6_ADDRSTRLEN] = {0};
        char srcMac[32] = {0},
             srcMacInfo[64] = {0},
             optMac[32] = {0},
             optList[160] = {0},
             line[896] = {0};
        bool dadDefence = FALSE;
        bool rx = TRUE;

        memset(&sll, 0, sizeof(sll));
        sllLen = sizeof(sll);

        len = recvfrom(slot->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *) &sll, &sllLen);
        if (len < 0)
        {
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR))
            {
                CcspTraceError(("%s-%d [ND MONITOR] recvfrom failed on '%s': %s\n",
                                __FUNCTION__, __LINE__, slot->ifname, strerror(errno)));
            }
            return;
        }

        /* The BPF filter attached in NetMonitor_InitNdMonitorFd() should already guarantee
         * only ICMPv6 NS/NA reach us. If any of these checks ever trip it points at a filter
         * or offset bug rather than normal traffic, so they are logged as errors. */

        /* An NS and an NA have the same fixed size, so both are covered by this check */
        if (len < (ssize_t)(sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert)))
        {
            CcspTraceError(("%s-%d [ND MONITOR] Dropping runt packet on '%s', len=%zd (expected >= %zu)\n",
                            __FUNCTION__, __LINE__, slot->ifname, len,
                            sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert)));
            continue;
        }
        if (((ip6->ip6_vfc & 0xf0) != 0x60) || (ip6->ip6_nxt != IPPROTO_ICMPV6))
        {
            CcspTraceError(("%s-%d [ND MONITOR] Dropping unexpected packet on '%s', vfc=0x%02x nxt=%u (expected IPv6/ICMPv6)\n",
                            __FUNCTION__, __LINE__, slot->ifname, ip6->ip6_vfc, ip6->ip6_nxt));
            continue;
        }

        /* Drop any link layer padding so that the option walk stays inside the IPv6 payload */
        ip6TotalLen = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
        if (ip6TotalLen < (size_t)len)
        {
            len = (ssize_t)ip6TotalLen;
            if (len < (ssize_t)(sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert)))
            {
                CcspTraceError(("%s-%d [ND MONITOR] Dropping packet on '%s', ip6_plen truncates it below the minimum ND size (ip6TotalLen=%zu)\n",
                                __FUNCTION__, __LINE__, slot->ifname, ip6TotalLen));
                continue;
            }
        }

        slot->pktSeen++;
        if (slot->pktSeen == 1)
        {
            CcspTraceInfo(("%s-%d [ND MONITOR] First ICMPv6 ND packet captured on '%s'\n", __FUNCTION__, __LINE__, slot->ifname));
        }

        icmp6  = (struct icmp6_hdr *)(buf + sizeof(struct ip6_hdr));
        opts   = buf + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert);
        optLen = (int)len - (int)(sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert));

        /* Our own transmitted frames are visible here only because the socket is bound with
         * ETH_P_ALL, which is what lets our DAD probe be correlated with the answer it triggered. */
        rx = (sll.sll_pkttype != PACKET_OUTGOING);

        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
        NetMonitor_FormatLinkAddr(sll.sll_addr, sll.sll_halen, srcMac, sizeof(srcMac));
        NetMonitor_DescribeLinkAddr(sll.sll_addr, sll.sll_halen, srcMacInfo, sizeof(srcMacInfo));
        NetMonitor_FormatNdOptions(opts, optLen, optList, sizeof(optList));

        if (icmp6->icmp6_type == ND_NEIGHBOR_ADVERT)
        {
            struct nd_neighbor_advert *na = (struct nd_neighbor_advert *) icmp6;
            uint32_t flags = na->nd_na_flags_reserved; // the ND_NA_FLAG_* masks are already in network byte order
            bool solicited = ((flags & ND_NA_FLAG_SOLICITED) != 0);

            inet_ntop(AF_INET6, &na->nd_na_target, target, sizeof(target));
            optLinkAddr = NetMonitor_FindNdOption(opts, optLen, ND_OPT_TARGET_LINKADDR, &optLinkAddrLen);
            NetMonitor_FormatLinkAddr(optLinkAddr, optLinkAddrLen, optMac, sizeof(optMac));

            /* A node defending an address against DAD answers the unspecified source with an
             * unsolicited NA sent to the all-nodes multicast address (RFC 4862 Section 5.4.3).
             * Anything else is an ordinary NA, which the kernel still treats as a DAD failure
             * when the target matches one of our tentative addresses. */
            dadDefence = (!solicited && NetMonitor_IsAllNodesMulticast(&ip6->ip6_dst));

            snprintf(line, sizeof(line),
                     "NA %s if=%s(idx=%u) pkttype=%s target=%s src=%s dst=%s src_mac=%s%s tgt_lladdr=%s "
                     "flags=[R=%d S=%d O=%d] rsvd=0x%06x code=%u cksum=0x%04x hoplimit=%u tclass=0x%02x plen=%u caplen=%zd opts=[%s]",
                     dadDefence ? "(unsolicited to all-nodes, DAD defence pattern)" :
                                  (solicited ? "(solicited reply)" : "(unsolicited)"),
                     slot->ifname, (unsigned int)sll.sll_ifindex,
                     NetMonitor_PktTypeToStr(sll.sll_pkttype),
                     target, src, dst, srcMac, srcMacInfo, optMac,
                     (flags & ND_NA_FLAG_ROUTER)   ? 1 : 0,
                     solicited                     ? 1 : 0,
                     (flags & ND_NA_FLAG_OVERRIDE) ? 1 : 0,
                     (unsigned int)(ntohl(flags) & 0x1fffffff),
                     icmp6->icmp6_code, ntohs(icmp6->icmp6_cksum),
                     (unsigned int)ip6->ip6_hlim,
                     (unsigned int)((ntohl(ip6->ip6_flow) >> 20) & 0xff),
                     ntohs(ip6->ip6_plen), len, optList);
        }
        else if (icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT)
        {
            struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *) icmp6;
            bool isDad = IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src);
            bool solicitedNodeDst = NetMonitor_IsSolicitedNodeMulticastOf(&ip6->ip6_dst, &ns->nd_ns_target);
            const char *kind;

            inet_ntop(AF_INET6, &ns->nd_ns_target, target, sizeof(target));
            optLinkAddr = NetMonitor_FindNdOption(opts, optLen, ND_OPT_SOURCE_LINKADDR, &optLinkAddrLen);
            NetMonitor_FormatLinkAddr(optLinkAddr, optLinkAddrLen, optMac, sizeof(optMac));

            /* An NS sent from the unspecified address is a DAD probe. Otherwise a multicast
             * destination means address resolution and a unicast destination means the
             * sender is re-validating a neighbour it already knows (NUD, RFC 4861 7.2.5). */
            if (isDad)
            {
                kind = "(DAD probe)";
            }
            else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
            {
                kind = "(address resolution)";
            }
            else
            {
                kind = "(NUD unicast probe)";
            }

            snprintf(line, sizeof(line),
                     "NS %s if=%s(idx=%u) pkttype=%s target=%s src=%s dst=%s%s src_mac=%s%s src_lladdr=%s "
                     "code=%u cksum=0x%04x hoplimit=%u tclass=0x%02x plen=%u caplen=%zd opts=[%s]",
                     kind,
                     slot->ifname, (unsigned int)sll.sll_ifindex,
                     NetMonitor_PktTypeToStr(sll.sll_pkttype),
                     target, src, dst,
                     /* A DAD probe or a resolution NS must go to the solicited-node group of its
                      * own target, so a mismatch points at a spoofed or misdirected packet */
                     (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) && !solicitedNodeDst) ? "[!not target's solicited-node group]" : "",
                     srcMac, srcMacInfo, optMac,
                     icmp6->icmp6_code, ntohs(icmp6->icmp6_cksum),
                     (unsigned int)ip6->ip6_hlim,
                     (unsigned int)((ntohl(ip6->ip6_flow) >> 20) & 0xff),
                     ntohs(ip6->ip6_plen), len, optList);

            /* RFC 4861 Section 4.3: a DAD probe must not carry a source link-layer address
             * option, since there is no source address to associate it with */
            if (isDad && (optLinkAddr != NULL))
            {
                CcspTraceError(("%s-%d [ND MONITOR] DAD probe for %s on '%s' carries a source link-layer option (%s), which RFC 4861 forbids\n",
                                __FUNCTION__, __LINE__, target, slot->ifname, optMac));
            }

            /* Soliciting one of our own addresses (e.g. "ndisc6 <our address> <our iface>")
             * is answered internally, so the absence of an NA here is expected rather than
             * a missed capture. Say so, otherwise it reads as a hole in the capture. */
            if (!isDad && !rx &&
                NetMonitor_IsLocalIfaceAddr(slot->ifname, &ns->nd_ns_target, NetMonitor_MonotonicSec()))
            {
                CcspTraceInfo(("%s-%d [ND MONITOR] NS #%lu solicits %s, which is a local address of '%s'. The kernel answers "
                               "from the loopback path, so no NA for it is transmitted on the interface and none can be captured. "
                               "Solicit a remote neighbour (e.g. the default gateway) to see an NA on the wire\n",
                               __FUNCTION__, __LINE__, slot->pktSeen, target, slot->ifname));
            }
        }
        else
        {
            CcspTraceError(("%s-%d [ND MONITOR] Dropping packet on '%s' with unexpected ICMPv6 type=%u (filter should only pass NS/NA)\n",
                            __FUNCTION__, __LINE__, slot->ifname, icmp6->icmp6_type));
            continue;
        }

        /* A hop limit other than 255 means the packet was not generated on-link (RFC 4861 Section 11.2) */
        NetMonitor_LogNdPacket(((rx && dadDefence) || (ip6->ip6_hlim != 255)), slot->pktSeen, rx, line);
    }
}

static void* NetworkMonitorThread( void *arg )
{
    //detach thread from caller stack
    pthread_detach(pthread_self());
    
    //event handler
    int n = 0;
    struct timeval tv;

    CcspTraceInfo(("%s-%d: \n", __FUNCTION__, __LINE__));

    fd_set readFds;
    fd_set errorFds;

    NetMonitor_InitNdMonitorSlots();

    /* Route events : set up all the fd stuff for select */
    FD_ZERO(&readFdsMaster);
    FD_ZERO(&errorFdsMaster);

    netMonitor_SyseventInit();

    NetMonitor_InitNetlinkRouteMonitorFd();
    if (netlinkRouteMonitorFd != -1)
    {
        FD_SET(netlinkRouteMonitorFd, &readFdsMaster);
        UPDATE_MAXFD(netlinkRouteMonitorFd);
    }
    while(1)
    {
        /* The ND capture is started and stopped by the interface state machine */
        NetMonitor_ApplyNdMonitorRequest();

        tv.tv_sec = 0;
        tv.tv_usec = LOOP_TIMEOUT;

        readFds = readFdsMaster;
        errorFds = errorFdsMaster;

        n = select(maxFd+1, &readFds, NULL, &errorFds, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }
        if ((netlinkRouteMonitorFd != -1) && FD_ISSET(netlinkRouteMonitorFd, &readFds))
        {
            NetMonitor_ProcessNetlinkRouteMonitorFd();
        }
        for (int i = 0; i < ND_MON_MAX_IFACES; i++)
        {
            if ((ndMonitorSlot[i].fd != -1) && FD_ISSET(ndMonitorSlot[i].fd, &readFds))
            {
                NetMonitor_ProcessNdMonitorFd(&ndMonitorSlot[i]);
            }
        }
    }
    NetMonitor_DeInitNetlinkRouteMonitorFd();
    for (int i = 0; i < ND_MON_MAX_IFACES; i++)
    {
        NetMonitor_DeInitNdMonitorFd(&ndMonitorSlot[i]);
    }

    pthread_exit(NULL);
}

ANSC_STATUS WanMgr_StartNetWorkMonitor( void )
{
    pthread_t nwMonThreadId;
    ANSC_STATUS retStatus = ANSC_STATUS_FAILURE;
    int ret = -1;

    //create thread
    ret = pthread_create( &nwMonThreadId, NULL, &NetworkMonitorThread, NULL );

    if( 0 != ret )
    {
        CcspTraceError(("%s %d - Failed to start Network Monitor Thread Error:%d\n", __FUNCTION__, __LINE__, ret));
    }
    else
    {
        CcspTraceInfo(("%s %d - Network Monitor Thread Started Successfully\n", __FUNCTION__, __LINE__));
        retStatus = ANSC_STATUS_SUCCESS;
    }

    return retStatus ;
}