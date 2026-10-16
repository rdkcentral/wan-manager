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
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/filter.h>
#include <net/if.h>
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
static int ndMonitorFd = -1; //optional ICMPv6 Neighbour Discovery debug listener
/* Owned by the network monitor thread */
static char ndMonitorIfname[IF_NAMESIZE] = {0};
static unsigned int ndMonitorIfindex = 0;
static char ndMonitorAttempt[IF_NAMESIZE] = {0};
/* Set by the interface state machine threads, protected by ndMonitorMutex */
static pthread_mutex_t ndMonitorMutex = PTHREAD_MUTEX_INITIALIZER;
static char ndMonitorReqIfname[IF_NAMESIZE] = {0};
static time_t ndMonitorDeadline = 0;
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
#define ND_MON_MAX_CAPTURE_SEC      300
#define ND_MON_LOG_WINDOW_SEC       10
#define ND_MON_LOG_BURST            20
#define ND_MON_MAX_BURST_READ       16

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
static void NetMonitor_ApplyNdMonitorRequest(void); // start/stop the ICMPv6 ND capture on request
static void NetMonitor_ProcessNdMonitorFd(void); // parse the captured ICMPv6 NS/NA packets
static void NetMonitor_DeInitNdMonitorFd(void);
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
 * DHCPv6 client is started on a virtual interface and stopped once DAD has succeeded
 * for that interface, so only the window where a DAD failure can happen is captured.
 *
 * Note: AF_PACKET sockets require CAP_NET_RAW. If the capability is not granted
 * to wanmanager the socket creation fails with EPERM and the capture stays off.
 */

/* Keeps only ICMPv6 Neighbour Solicitation (135) and Neighbour Advertisement (136).
 * Offsets are relative to the start of the IPv6 header because the socket is a
 * SOCK_DGRAM packet socket, for which the link layer header is not part of the data. */
static struct sock_filter ndMonitorFilter[] = {
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

/* ND traffic can be bursty, keep the listener from flooding the log */
static bool NetMonitor_NdLogAllowed(void)
{
    static time_t windowStart = 0;
    static unsigned int logged = 0;
    time_t now = time(NULL);

    if ((now - windowStart) >= ND_MON_LOG_WINDOW_SEC)
    {
        windowStart = now;
        logged = 0;
    }

    logged++;
    if (logged == (ND_MON_LOG_BURST + 1))
    {
        CcspTraceError(("%s-%d [ND MONITOR] More than %d ND packets in %d seconds, suppressing logs until the end of the window\n",
                        __FUNCTION__, __LINE__, ND_MON_LOG_BURST, ND_MON_LOG_WINDOW_SEC));
    }

    return (logged <= ND_MON_LOG_BURST);
}

static ANSC_STATUS NetMonitor_InitNdMonitorFd(const char *ifname, bool logFailure)
{
    struct sockaddr_ll sll;
    struct sock_fprog prog;
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
    ndMonitorFd = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (ndMonitorFd < 0)
    {
        if (logFailure)
        {
            CcspTraceError(("%s-%d [ND MONITOR] Failed to create AF_PACKET socket: %s%s\n", __FUNCTION__, __LINE__,
                            strerror(errno), (errno == EPERM) ? " (CAP_NET_RAW is required)" : ""));
        }
        return ANSC_STATUS_FAILURE;
    }

    prog.len    = sizeof(ndMonitorFilter) / sizeof(ndMonitorFilter[0]);
    prog.filter = ndMonitorFilter;
    if (setsockopt(ndMonitorFd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
    {
        CcspTraceError(("%s-%d [ND MONITOR] Failed to attach ND packet filter: %s\n", __FUNCTION__, __LINE__, strerror(errno)));
        close(ndMonitorFd);
        ndMonitorFd = -1;
        return ANSC_STATUS_FAILURE;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IPV6);
    sll.sll_ifindex  = (int)ifindex;
    if (bind(ndMonitorFd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
    {
        CcspTraceError(("%s-%d [ND MONITOR] Failed to bind AF_PACKET socket to '%s': %s\n", __FUNCTION__, __LINE__, ifname, strerror(errno)));
        close(ndMonitorFd);
        ndMonitorFd = -1;
        return ANSC_STATUS_FAILURE;
    }

    snprintf(ndMonitorIfname, sizeof(ndMonitorIfname), "%s", ifname);
    ndMonitorIfindex = ifindex;
    CcspTraceInfo(("%s-%d [ND MONITOR] Listening for ICMPv6 NS/NA on '%s' (ifindex=%u)\n", __FUNCTION__, __LINE__, ifname, ifindex));

    return ANSC_STATUS_SUCCESS;
}

static void NetMonitor_DeInitNdMonitorFd(void)
{
    if (ndMonitorFd >= 0)
    {
        CcspTraceInfo(("%s-%d [ND MONITOR] Stopped listening on '%s'\n", __FUNCTION__, __LINE__, ndMonitorIfname));
        FD_CLR(ndMonitorFd, &readFdsMaster);
        close(ndMonitorFd);
        ndMonitorFd = -1;
    }
    ndMonitorIfname[0] = '\0';
    ndMonitorIfindex = 0;
}

/* Called by the interface state machine threads. Only the request is updated here,
 * the socket itself is always opened and closed by the network monitor thread. */
void WanMgr_NdMonitor_Start(const char *ifname)
{
    bool changed = FALSE;

    if ((ifname == NULL) || (ifname[0] == '\0'))
    {
        return;
    }

    pthread_mutex_lock(&ndMonitorMutex);
    changed = (strcmp(ndMonitorReqIfname, ifname) != 0);
    snprintf(ndMonitorReqIfname, sizeof(ndMonitorReqIfname), "%s", ifname);
    ndMonitorDeadline = time(NULL) + ND_MON_MAX_CAPTURE_SEC;
    pthread_mutex_unlock(&ndMonitorMutex);

    if (changed)
    {
        CcspTraceInfo(("%s-%d [ND MONITOR] ICMPv6 ND capture requested on '%s'\n", __FUNCTION__, __LINE__, ifname));
    }
}

void WanMgr_NdMonitor_Stop(const char *ifname)
{
    bool stopped = FALSE;

    pthread_mutex_lock(&ndMonitorMutex);
    /* A capture started for another interface must not be cancelled from here */
    if ((ndMonitorReqIfname[0] != '\0') && ((ifname == NULL) || (strcmp(ndMonitorReqIfname, ifname) == 0)))
    {
        ndMonitorReqIfname[0] = '\0';
        ndMonitorDeadline = 0;
        stopped = TRUE;
    }
    pthread_mutex_unlock(&ndMonitorMutex);

    if (stopped)
    {
        CcspTraceInfo(("%s-%d [ND MONITOR] ICMPv6 ND capture no longer needed on '%s'\n", __FUNCTION__, __LINE__,
                       (ifname != NULL) ? ifname : "any interface"));
    }
}

static void NetMonitor_ApplyNdMonitorRequest(void)
{
    static time_t lastAttempt = 0;
    static time_t lastIfindexCheck = 0;
    char reqIfname[IF_NAMESIZE] = {0};
    time_t now = time(NULL);
    bool expired = FALSE;
    bool firstAttempt = FALSE;

    pthread_mutex_lock(&ndMonitorMutex);
    /* Safety net, the capture is a debug aid and must not run forever if the state
     * machine never reaches a DAD verdict for the interface */
    if ((ndMonitorReqIfname[0] != '\0') && (now >= ndMonitorDeadline))
    {
        ndMonitorReqIfname[0] = '\0';
        ndMonitorDeadline = 0;
        expired = TRUE;
    }
    snprintf(reqIfname, sizeof(reqIfname), "%s", ndMonitorReqIfname);
    pthread_mutex_unlock(&ndMonitorMutex);

    if (expired)
    {
        CcspTraceError(("%s-%d [ND MONITOR] Capture stopped, the %d second limit was reached without a DAD verdict\n",
                        __FUNCTION__, __LINE__, ND_MON_MAX_CAPTURE_SEC));
    }

    if (reqIfname[0] == '\0')
    {
        if ((ndMonitorFd >= 0) || (ndMonitorAttempt[0] != '\0'))
        {
            NetMonitor_DeInitNdMonitorFd();
            ndMonitorAttempt[0] = '\0';
        }
        return;
    }

    if (ndMonitorFd >= 0)
    {
        if (strcmp(ndMonitorIfname, reqIfname) == 0)
        {
            if ((now - lastIfindexCheck) < ND_MON_IFINDEX_CHECK_SEC)
            {
                return; // already listening on the requested interface
            }
            lastIfindexCheck = now;

            /* The socket stays bound to the old ifindex if the interface is recreated */
            if (if_nametoindex(ndMonitorIfname) == ndMonitorIfindex)
            {
                return;
            }
            CcspTraceInfo(("%s-%d [ND MONITOR] Interface '%s' was recreated, rebinding\n", __FUNCTION__, __LINE__, ndMonitorIfname));
        }
        NetMonitor_DeInitNdMonitorFd();
        ndMonitorAttempt[0] = '\0';
    }

    firstAttempt = (strcmp(ndMonitorAttempt, reqIfname) != 0);
    if (!firstAttempt && ((now - lastAttempt) < ND_MON_RETRY_INTERVAL_SEC))
    {
        return; // interface is not usable yet, retry on a later iteration
    }
    lastAttempt = now;
    snprintf(ndMonitorAttempt, sizeof(ndMonitorAttempt), "%s", reqIfname);

    if (NetMonitor_InitNdMonitorFd(reqIfname, firstAttempt) == ANSC_STATUS_SUCCESS)
    {
        lastIfindexCheck = now;
        FD_SET(ndMonitorFd, &readFdsMaster);
        UPDATE_MAXFD(ndMonitorFd);
    }
}

static void NetMonitor_ProcessNdMonitorFd(void)
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
             line[512] = {0};
        bool dadDefence = FALSE;
        bool rx = TRUE;

        memset(&sll, 0, sizeof(sll));
        sllLen = sizeof(sll);

        len = recvfrom(ndMonitorFd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *) &sll, &sllLen);
        if (len < 0)
        {
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR))
            {
                CcspTraceError(("%s-%d [ND MONITOR] recvfrom failed: %s\n", __FUNCTION__, __LINE__, strerror(errno)));
            }
            return;
        }

        /* An NS and an NA have the same fixed size, so both are covered by this check */
        if (len < (ssize_t)(sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert)))
        {
            continue;
        }
        if (((ip6->ip6_vfc & 0xf0) != 0x60) || (ip6->ip6_nxt != IPPROTO_ICMPV6))
        {
            continue;
        }

        /* Drop any link layer padding so that the option walk stays inside the IPv6 payload */
        ip6TotalLen = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
        if (ip6TotalLen < (size_t)len)
        {
            len = (ssize_t)ip6TotalLen;
            if (len < (ssize_t)(sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert)))
            {
                continue;
            }
        }

        if (!NetMonitor_NdLogAllowed())
        {
            continue;
        }

        icmp6  = (struct icmp6_hdr *)(buf + sizeof(struct ip6_hdr));
        opts   = buf + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert);
        optLen = (int)len - (int)(sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert));

        /* A packet socket also sees the packets we transmit ourselves, which is what allows our
         * own DAD probe to be correlated with the answer it triggered. */
        rx = (sll.sll_pkttype != PACKET_OUTGOING);

        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
        NetMonitor_FormatLinkAddr(sll.sll_addr, sll.sll_halen, srcMac, sizeof(srcMac));
        NetMonitor_DescribeLinkAddr(sll.sll_addr, sll.sll_halen, srcMacInfo, sizeof(srcMacInfo));

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
                     "NA %s target=%s src=%s dst=%s src_mac=%s%s tgt_lladdr=%s flags=[R=%d S=%d O=%d] hoplimit=%u if=%s",
                     dadDefence ? "(unsolicited to all-nodes, DAD defence pattern)" :
                                  (solicited ? "(solicited reply)" : "(unsolicited)"),
                     target, src, dst, srcMac, srcMacInfo, optMac,
                     (flags & ND_NA_FLAG_ROUTER)   ? 1 : 0,
                     solicited                     ? 1 : 0,
                     (flags & ND_NA_FLAG_OVERRIDE) ? 1 : 0,
                     (unsigned int)ip6->ip6_hlim, ndMonitorIfname);
        }
        else if (icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT)
        {
            struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *) icmp6;

            inet_ntop(AF_INET6, &ns->nd_ns_target, target, sizeof(target));
            optLinkAddr = NetMonitor_FindNdOption(opts, optLen, ND_OPT_SOURCE_LINKADDR, &optLinkAddrLen);
            NetMonitor_FormatLinkAddr(optLinkAddr, optLinkAddrLen, optMac, sizeof(optMac));

            snprintf(line, sizeof(line),
                     "NS %s target=%s src=%s dst=%s src_mac=%s%s src_lladdr=%s hoplimit=%u if=%s",
                     IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) ? "(DAD probe)" : "(address resolution)",
                     target, src, dst, srcMac, srcMacInfo, optMac, (unsigned int)ip6->ip6_hlim, ndMonitorIfname);
        }
        else
        {
            continue;
        }

        /* A hop limit other than 255 means the packet was not generated on-link (RFC 4861 Section 11.2) */
        if ((rx && dadDefence) || (ip6->ip6_hlim != 255))
        {
            CcspTraceError(("%s-%d [ND MONITOR] %s %s\n", __FUNCTION__, __LINE__, rx ? "RX" : "TX", line));
        }
        else
        {
            CcspTraceInfo(("%s-%d [ND MONITOR] %s %s\n", __FUNCTION__, __LINE__, rx ? "RX" : "TX", line));
        }
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
        if ((ndMonitorFd != -1) && FD_ISSET(ndMonitorFd, &readFds))
        {
            NetMonitor_ProcessNdMonitorFd();
        }
    }
    NetMonitor_DeInitNetlinkRouteMonitorFd();
    NetMonitor_DeInitNdMonitorFd();

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