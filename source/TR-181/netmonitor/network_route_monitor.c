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
#include <linux/rtnetlink.h>
#include "ipc_msg.h"
#include "network_route_monitor.h"
#include "ansc_platform.h"
#include "ansc_string_util.h"
#include <sysevent/sysevent.h>
#include "secure_wrapper.h"
/* ---- Global Variables ------------------------------------ */
int sysevent_fd = -1;
token_t sysevent_token;

static int maxFd = 50;
int netlinkRouteMonitorFd = -1; //subscribe to route change events
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
static ANSC_STATUS isDefaultGatewaypresent(struct nlmsghdr* nlmsgHdr); // check for default gateway

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
                    DBG_MONITOR_PRINT("Invalid ipv6 address=%s \n", token);
                    ret = ANSC_STATUS_FAILURE;
                    return ret;
                }
                strncpy(defGateway, token, length);
                DBG_MONITOR_PRINT("IPv6 Default GW address  = %s \n", defGateway);
            }
            else
            {
                DBG_MONITOR_PRINT("Could not parse ipv6 gw addr\n");
                ret = ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            DBG_MONITOR_PRINT("Could not read ipv6 gw addr \n");
            ret = ANSC_STATUS_FAILURE;
        }
        pclose_ret = v_secure_pclose(fp);
	if(pclose_ret !=0)
	{
	    DBG_MONITOR_PRINT("Failed in closing the pipe ret %d \n",pclose_ret);
	}
    }
    else
    {
        DBG_MONITOR_PRINT("Failed to get the default gw address \n");
        ret = ANSC_STATUS_FAILURE;
    }

    return ret;
}

static int WanManager_MaptRouteSetting()
{
    DBG_MONITOR_PRINT("%s Enter \n", __FUNCTION__);

    char brIPv6Prefix[BUFLEN_256] = {0};
    char vlanIf[BUFLEN_64] = {0};
    char defaultGatewayV6[BUFLEN_128] = {0};
    int ret =0;
    char partnerID[BUFLEN_32]    = {0};

    syscfg_get(NULL, "PartnerID", partnerID, sizeof(partnerID));
    int mtu_size_mapt = MTU_DEFAULT_SIZE; /* 1500 */
#if !(defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)) || defined (_RDKB_GLOBAL_PRODUCT_REQ_) // XB6 and CBR use 1500 MTU size for MAPT.
    if (strcmp("sky-uk", partnerID) != 0)
    {
        mtu_size_mapt = MAPT_MTU_SIZE; /* 1520 */
    }
#endif
    DBG_MONITOR_PRINT("MAPT MTU Size = %d \n", mtu_size_mapt);

    sysevent_get(sysevent_fd, sysevent_token, MAP_WAN_IFACE, vlanIf, sizeof(vlanIf));
    if (!strcmp(vlanIf, "\0"))
    {
        DBG_MONITOR_PRINT("%s Failed to get sysevent (%s) \n", __FUNCTION__, MAP_WAN_IFACE);
        return ANSC_STATUS_FAILURE;
    }

    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAP_BR_IPV6_PREFIX, brIPv6Prefix, sizeof(brIPv6Prefix));
    if (!strcmp(brIPv6Prefix, "\0"))
    {
        DBG_MONITOR_PRINT("%s Failed to get sysevent (%s) \n", __FUNCTION__, SYSEVENT_MAP_BR_IPV6_PREFIX);
        return ANSC_STATUS_FAILURE;
    }

    if(get_v6_default_gw_wan(defaultGatewayV6, sizeof(defaultGatewayV6)) == ANSC_STATUS_FAILURE)
    {
        return ANSC_STATUS_FAILURE;
    }

    ret = v_secure_system("ip -6 route change default via %s dev %s mtu %d", defaultGatewayV6, vlanIf, MTU_DEFAULT_SIZE);
    if(ret != 0) {
         DBG_MONITOR_PRINT("%s %d: Failure in executing command via v_secure_system. ret:[%d] \n", __FUNCTION__,__LINE__,ret);
    }
    ret = v_secure_system("ip -6 route replace %s via %s dev %s mtu %d", brIPv6Prefix, defaultGatewayV6, vlanIf, mtu_size_mapt);
    if(ret != 0) {
          DBG_MONITOR_PRINT("%s %d: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,__LINE__,ret);
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

static ANSC_STATUS isDefaultGatewaypresent(struct nlmsghdr* nlmsgHdr)
{
    struct rtmsg* route_entry = NLMSG_DATA(nlmsgHdr);
    struct rtattr* tb[RTA_MAX+1];
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;

    int len = nlmsgHdr->nlmsg_len - NLMSG_LENGTH(sizeof(*route_entry));

    if (len < 0) {
        DBG_MONITOR_PRINT("%s Wrong message length \n", __FUNCTION__);
        return ret;
    }

    // We are just interested in main routing table
    if (route_entry->rtm_table != RT_TABLE_MAIN) {
        return ret;
    }

    parse_rtattr(tb, RTA_MAX, RTM_RTA(route_entry), len);

    if ( (tb[RTA_DST] == 0)  && (route_entry->rtm_dst_len == 0) ) {
        DBG_MONITOR_PRINT("%s-%d: Found Default gateway in route event \n", __FUNCTION__, __LINE__);
        ret = ANSC_STATUS_SUCCESS;
    }

    return ret;
}

static ANSC_STATUS NetMonitor_InitNetlinkRouteMonitorFd()
{
    struct sockaddr_nl addr;

    DBG_MONITOR_PRINT("%s Enter \n", __FUNCTION__);

    netlinkRouteMonitorFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (netlinkRouteMonitorFd < 0)
    {
        DBG_MONITOR_PRINT("%s Failed to create netlink socket: %s\n", __FUNCTION__, strerror(errno));
        return ANSC_STATUS_FAILURE;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV6_ROUTE;
    if (0 > bind(netlinkRouteMonitorFd, (struct sockaddr *) &addr, sizeof(addr)))
    {
        DBG_MONITOR_PRINT("%s Failed to bind netlink socket: %s\n", __FUNCTION__, strerror(errno));
        close(netlinkRouteMonitorFd);
        return ANSC_STATUS_FAILURE;
    }
    DBG_MONITOR_PRINT("%s Bound netlinkRouteMonitorFd to 0x%x  \n", __FUNCTION__, addr.nl_groups);

    return ANSC_STATUS_SUCCESS;
}

static void NetMonitor_DoToggleV6Status(bool flag)
{
    DBG_MONITOR_PRINT("%s-%d: Enter \n", __FUNCTION__, __LINE__);

    g_toggle_flag = flag;

    if (g_toggle_flag == TRUE)
    {
        DBG_MONITOR_PRINT("%s-%d: Toggle Needed \n", __FUNCTION__, __LINE__);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_TOGGLE, "TRUE", 0);
        g_toggle_flag = FALSE;
    }
    else
    {
        DBG_MONITOR_PRINT("%s-%d: No Toggle Needed \n", __FUNCTION__, __LINE__);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_TOGGLE, "FALSE", 0); 
    }
}

static void netMonitor_SyseventInit()
{
    int try = 0;

    /* Open sysevent descriptor to send messages */
    while(try < SYSEVENT_OPEN_MAX_RETRIES)
    {
       sysevent_fd =  sysevent_open(SYS_IP_ADDR, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, NETMONITOR_SYSNAME, &sysevent_token);
       if(sysevent_fd >= 0)
       {
          break;
       }
       try++;
       usleep(50000);
    }
        DBG_MONITOR_PRINT("%s-%d: Started \n", __FUNCTION__, __LINE__);
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
        DBG_MONITOR_PRINT("%s-%d: Received Message Status Failed %d \n", __FUNCTION__, __LINE__, status);
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
            DBG_MONITOR_PRINT("%s netlink message error \n", __FUNCTION__);
            return;
        }

        switch(nl_msgHdr->nlmsg_type)
        {

            case RTM_NEWROUTE:
                 {
                     if(isDefaultGatewaypresent(nl_msgHdr) == ANSC_STATUS_SUCCESS){
                         if(gw_v6_flag == FALSE){
                             DBG_MONITOR_PRINT(" %s  IPv6 Default route update - ADD \n", __FUNCTION__);
                             NetMonitor_DoToggleV6Status(FALSE);
#if defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)
                             sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_CONFIG_FLAG, maptConfigFlag, sizeof(maptConfigFlag));
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
                             DBG_MONITOR_PRINT(" %s  IPv6 Default route update - DEL \n", __FUNCTION__);
                             NetMonitor_DoToggleV6Status(TRUE);
                             gw_v6_flag = FALSE;
                         }
                     }
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
        DBG_MONITOR_PRINT("%s-%d: \n", __FUNCTION__, __LINE__);
        close(netlinkRouteMonitorFd);
        netlinkRouteMonitorFd = -1;
    }
}

int main(int argc, char* argv[])
{
    //event handler
    int n = 0;
    struct timeval tv;

    DBG_MONITOR_PRINT("%s-%d: \n", __FUNCTION__, __LINE__);

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
    }
    NetMonitor_DeInitNetlinkRouteMonitorFd();
    return 0;
}
