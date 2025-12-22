/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
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
#include <arpa/inet.h> /* for inet_pton */
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <time.h>
#include <sysevent/sysevent.h>
#include "wanmgr_sysevents.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_dhcpv4_apis.h"
#include "wanmgr_dhcpv6_apis.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_ssp_internal.h"
#include "ansc_platform.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <ifaddrs.h>
//#include "platform_hal.h"
#include <sys/sysinfo.h>
#include <syscfg/syscfg.h>
#include "dhcp_client_utils.h"
#include "wanmgr_sysevents.h"
#include <sysevent/sysevent.h>
#include "secure_wrapper.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>

#if defined(FEATURE_464XLAT)
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <netdb.h>
#endif

#define BROADCAST_IP "255.255.255.255"
/* To ignore link local addresses configured as DNS servers,
 * it covers the range 169.254.x.x */
#define LINKLOCAL_RANGE "169.254"
/* To ignore loopback addresses configured as DNS servers,
 * it covers the range 127.x.x.x */
#define LOOPBACK_RANGE "127"

#define BASE_IFNAME_PPPoA "atm0"
#define BASE_IFNAME_PPPoE "vlan101"
#define DEFAULT_IFNAME    "erouter0"
#define MAP_INTERFACE "map0"
#define DSL_INTERFACE "dsl0"
#define PTM_INTERFACE "ptm0"
#define NF_NAT_FTP_MODULE "nf_nat_ftp"
#define ROUTE_TABLE_FILE "/etc/iproute2/rt_tables"

/** Macro to determine if a string parameter is empty or not */
#define IS_EMPTY_STR(s)    ((s == NULL) || (*s == '\0'))

#define DHCPV4C_PID_FILE "/tmp/erouter_dhcp4c.pid"
#define MTU_SIZE (1520)
#define MTU_DEFAULT_SIZE (1500)
#define DHCPV6_OPTION_STR_LEN 288
#define DEFAULT_SER_FIELD_LEN 64
#define DHCPV6_OPTIONS_FILE "/var/skydhcp6_options.txt"
#ifdef FEATURE_IPOE_HEALTH_CHECK
#define DHCP6C_RENEW_PREFIX_FILE    "/tmp/erouter0.dhcpc6c_renew_prefix.conf"
#endif

/** Some defines for selecting which address family (IPv4 or IPv6) we want.
 *  Note: are bits for use in bitmasks (not integers)
 */
#define AF_SELECT_IPV4       0x0001
#define AF_SELECT_IPV6       0x0002

extern ANSC_HANDLE bus_handle;
extern int sysevent_fd;
extern token_t sysevent_token;

extern int stop_dhcpv4_client (dhcp_params * params);

#if defined (DUID_UUID_ENABLE)
#define DUID_TYPE "0004"  /* duid-type duid-uuid 4 */
#else
#define DUID_TYPE "00:03:"  /* duid-type duid-ll 3 */
#define HW_TYPE "00:01:"    /* hw type is always 1 */
#endif

#define DIBBLER_IPV6_CLIENT_ENABLE      "Device.DHCPv6.Client.%d.Enable"

#define IPMONITOR_WAIT_MAX_TIMEOUT 240
#define IPMONITOR_QUERY_INTERVAL 1

#define MODEM_TABLE_NAME "MODEM"
#define WAN_BRIDGE       "brWAN"

#define SET_MAX_RETRY_COUNT 10 // max. retry count for set requests
/***************************************************************************
 * @brief API used to check the incoming ipv4 address is a valid ipv4 address
 * @param input string contains ipv4 address
 * @return TRUE if its a valid IP address else returned false.
 ****************************************************************************/
static BOOL IsValidIpv4Address(const char *input);

/***************************************************************************
 * @brief API used to check the incoming ip address is a valid one
 * @param ipvx ip address family either v4 or v6
 * @param addr string contains ip address
 * @return TRUE if its a valid IP address else returned false.
 ****************************************************************************/
static BOOL IsZeroIpvxAddress(uint32_t ipvx, const char *addr);

/***************************************************************************
 * @brief API used to parse ipv6 prefix address
 * @param prefixAddr ipv6 prefix address
 * @param address string contains ip address
 * @param plen holds length of the prefix address
 * @return TRUE if its a valid IP address else returned false.
 ****************************************************************************/
static int ParsePrefixAddress(const char *prefixAddr, char *address, uint32_t *plen);

static int WanManager_CalculatePsidAndV4Index(char *pdIPv6Prefix, int v6PrefixLen, int iapdPrefixLen, int v4PrefixLen, int *psidValue, int *ipv4IndexValue, int *psidLen);

#if defined(FEATURE_464XLAT)
#define XLAT_INTERFACE "xlat"
int gen_xlat_ipv6_address(char *interface, char *address)
{
	int socket_inet6;
	struct icmp6_filter filter;
	struct sockaddr_in6 inet6Addr;
	socklen_t len = sizeof(inet6Addr);
	int ipv6Result = 0;
	char xlatAddress[512] = {0};
	
	//Check wan interface status 
	socket_inet6  = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	ICMP6_FILTER_SETBLOCKALL(&filter);
	setsockopt(socket_inet6 , IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
	setsockopt(socket_inet6 , SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface));
	memset(&inet6Addr, 0, sizeof(inet6Addr));
	inet6Addr.sin6_family = AF_INET6;
	inet6Addr.sin6_addr.s6_addr32[0] = htonl(0x2001);
	inet6Addr.sin6_addr.s6_addr32[1] = htonl(0xdb8);
	if (connect(socket_inet6 , (struct sockaddr*)&inet6Addr, sizeof(inet6Addr)))
	{
		return -1;
	}
	if(getsockname(socket_inet6 , (struct sockaddr*)&inet6Addr, &len))
	{
		return -1;
	}
	
	if(IN6_IS_ADDR_LINKLOCAL(&inet6Addr.sin6_addr))
	{
		return -1;
	}
	
	//Generate clat interface ipv6 address by wan interface.
	struct ipv6_mreq multicastReq  = {inet6Addr.sin6_addr, if_nametoindex(interface)};

	if (IN6_IS_ADDR_LINKLOCAL(&multicastReq.ipv6mr_multiaddr))
	{
		return -1;
	}
	//Create a random ipv6 address
	srandom(multicastReq.ipv6mr_multiaddr.s6_addr32[0] ^ multicastReq.ipv6mr_multiaddr.s6_addr32[1] ^ multicastReq.ipv6mr_multiaddr.s6_addr32[2] ^ multicastReq.ipv6mr_multiaddr.s6_addr32[3]);
	multicastReq.ipv6mr_multiaddr.s6_addr32[2] = random();
	multicastReq.ipv6mr_multiaddr.s6_addr32[3] = random();
	
	if (setsockopt(socket_inet6 , SOL_IPV6, IPV6_JOIN_ANYCAST, &multicastReq, sizeof(multicastReq)))
	{
		return -1;
	}

	inet_ntop(AF_INET6, &multicastReq.ipv6mr_multiaddr, xlatAddress, sizeof(xlatAddress));
	
	snprintf(address,512,"%s",xlat_address);
	
	return 0;
}

int xlat_configure(char *interface, char *xlat_address)
{
	char ipv6address[512] = {0}; 
	char platformPrefix[512] = {0};
	struct addrinfo socketHints = { .ai_family = AF_INET6 }; 
	struct addrinfo *returnInfo;
	int errcode = 1;
	char host[128] = {0};
	char cmd[512] = {0};
	FILE *xlat ;
	char dntInterface[256] = {0};
	int ipv6Result = 0;
	//Get ipv4only.arpa ipv6 address from dns64 server
	snprintf(host,sizeof(host),"ipv4only.arpa");
	//Sometimes fails but works on retry
	errcode = getaddrinfo (host, NULL, &socketHints, &returnInfo);
	if (errcode == 1)
	{
		errcode = getaddrinfo (host, NULL, &socketHints, &returnInfo);
		if (errcode == 1)
		{
			return -1;
		}
	}
	struct sockaddr_in6 *sockin6 = (struct sockaddr_in6*)returnInfo->ai_addr;
	//dns64 will return "ipv4only.arpa" ipv6 address as "ipv6prfix"+"ipv4 address of ipv4only.arpa".
	//ex : 64:ff9b::192.0.0.170 .
	//We need the prefix , and prefix length is /96.
 	inet_ntop(AF_INET6, &sockin6->sin6_addr, platformPrefix, sizeof(platformPrefix));
	strcat(platformPrefix, "/96");
	freeaddrinfo(returnInfo);
	snprintf(dntInterface,sizeof(dntInterface),"%s",interface);
	ipv6Result = gen_xlat_ipv6_address(dntInterface,ipv6address);
	if(ipv6Result < 0)
	{
		return -1;
	}
	
	xlat = fopen("/proc/net/nat46/control", "w");
    if(xlat)
	{
		//Write to nat46 kernel
		//e.g : add xlat config xlat local.style NONE local.v4 /32 local.v6 2607:fb90:ec92:c52c:8274:4d68:66a2:8955/128 remote.style RFC6052 remote.v6 192.0.0.1
		//More detail : https://github.com/ayourtch/nat46/blob/master/nat46/modules/README
		snprintf(cmd,sizeof(cmd),"add %s\nconfig %s local.style NONE local.v4 %s/32 local.v6 %s/128 remote.style RFC6052 remote.v6 %s\n",XLAT_INTERFACE, XLAT_INTERFACE, "192.0.0.1", ipv6address, platformPrefix);
		if(fprintf(xlat,cmd) <0)
		{
			fclose(xlat);
			return -1;
		}
		fclose(xlat);
	}else
	{
		return -1;
	}

	return 0;	
}

int xlat_reconfigure(void)
{
	FILE *nat46 = fopen("/proc/net/nat46/control", "w");
	
	nat46 = fopen("/proc/net/nat46/control", "w");
	if (nat46) {
		fprintf(nat46, "del %s\n", XLAT_INTERFACE);
		fclose(nat46);
	}
	
	return 0;
}
#endif

#ifdef FEATURE_MAPT
/*************************************************************************************
 * @brief checks kernel module loaded.
 * This API calls the proc entry.
 * @param moduleName is the kernal modulename
 * @return RETURN_OK upon success else RETURN_ERR returned
 **************************************************************************************/
int isModuleLoaded(char *moduleName)
{
    char line[BUFLEN_64] = {0};
    int  ret = RETURN_ERR,pclose_ret = 0;
    FILE *file = NULL;

    if (moduleName == NULL)
    {
        return ret;
    }

  

    file = v_secure_popen("r","cat /proc/modules | grep %s", moduleName);

    if(file == NULL)
    {
        CcspTraceError(("[%s][%d]Failed to open  /proc/modules \n", __FUNCTION__, __LINE__));
    }
    else
    {
        if(fgets (line, BUFLEN_64, file) != NULL)
        {
            if(strstr(line, moduleName))
            {
                ret = RETURN_OK;
                CcspTraceInfo(("[%s][%d] %s module is loaded \n", __FUNCTION__, __LINE__, moduleName));
            }
        }
        pclose_ret = v_secure_pclose(file);
	if(pclose_ret !=0)
	{
	    CcspTraceError(("Failed in closing the pipe ret %d\n",pclose_ret));
	}

    }

    return ret;
}
#endif

 /***************************************************************************
 * @brief Thread that sets enable/disable data model of dhcpv6 client
 * @param arg: enable/disable flag to start and stop dhcp6c client
 ****************************************************************************/
static INT IsIPObtained(char *pInterfaceName);

int WanManager_Ipv6PrefixUtil(char *ifname, Ipv6OperType opr, int preflft, int vallft)
{
    char cmdLine[128] = {0};
    char prefix[BUFLEN_48] = {0};
    char prefixAddr[BUFLEN_48] = {0};
    char IfaceName[BUFLEN_16] = {0};
    int BridgeMode = 0;

    memset(prefix, 0, sizeof(prefix));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIX, prefix, sizeof(prefix));

    memset(prefixAddr, 0, sizeof(prefixAddr));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_GLOBAL_IPV6_PREFIX_SET, prefixAddr, sizeof(prefixAddr));

    { //TODO : temporary debug code to identify the bridgemode sysevent failure issue.
        char Output[BUFLEN_16] = {0};
        if (sysevent_get(sysevent_fd, sysevent_token, "bridge_mode", Output, sizeof(Output)) !=0)
        {
            CcspTraceError(("%s-%d: bridge_mode sysevent get failed. \n", __FUNCTION__, __LINE__));
        }
        BridgeMode = atoi(Output);
        CcspTraceInfo(("%s-%d: <<DEBUG>> bridge_mode sysevent value set to =%d \n", __FUNCTION__, __LINE__,  BridgeMode));
    }

    /*TODO:
     *Below Code should be removed once V6 Prefix/IP is assigned on erouter0 Instead of brlan0 for sky Devices. 
     */
    strcpy(IfaceName, LAN_BRIDGE_NAME);
    if (WanMgr_isBridgeModeEnabled() == TRUE)
    {
        memset(IfaceName, 0, sizeof(IfaceName));
        strncpy(IfaceName, ifname, strlen(ifname));
    }

    CcspTraceInfo(("%s-%d: IfaceName=%s \n", __FUNCTION__, __LINE__, IfaceName));

    switch (opr)
    {
        case DEL_ADDR:
        {
            if (strlen(prefix) > 0)
            {
#if !(defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)) || defined(_RDKB_GLOBAL_PRODUCT_REQ_) //Do not delete prefix from LAn bridge for the comcast platforms.
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                WanMgr_Config_Data_t    *pWanConfigData = WanMgr_GetConfigData_locked();
                unsigned char           ConfigureWANIPv6OnLANBridgeSupport = FALSE;

                if( NULL != pWanConfigData )
                {
                    ConfigureWANIPv6OnLANBridgeSupport = pWanConfigData->data.ConfigureWANIPv6OnLANBridgeSupport;
                    WanMgrDml_GetConfigData_release(pWanConfigData);
                }

                if ( TRUE == ConfigureWANIPv6OnLANBridgeSupport )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
                {
                    memset(cmdLine, 0, sizeof(cmdLine));
                    snprintf(cmdLine, sizeof(cmdLine), "ip -6 addr del %s/64 dev %s", prefixAddr, IfaceName);
                    if (WanManager_DoSystemActionWithStatus("ip -6 addr del ADDR dev xxxx", cmdLine) != 0)
                        CcspTraceError(("failed to run cmd: %s", cmdLine));
                }
#endif
                memset(cmdLine, 0, sizeof(cmdLine));
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
                snprintf(cmdLine, sizeof(cmdLine), "ip -6 route flush match %s ", prefix);
#else
                snprintf(cmdLine, sizeof(cmdLine), "ip -6 route flush %s ", prefix);
#endif
                if (WanManager_DoSystemActionWithStatus("ip -6 route flush PREFIX ", cmdLine) != 0)
                    CcspTraceError(("failed to run cmd: %s", cmdLine));

                CcspTraceInfo(("%s-%d: Successfully del addr and route from Interface %s, prefix=%s, prefixAddr=%s \n",
       	                               __FUNCTION__, __LINE__, IfaceName, prefix, prefixAddr));

                memset(cmdLine, 0, sizeof(cmdLine));
                snprintf(cmdLine, sizeof(cmdLine), "ip -6 route delete default");
                if (WanManager_DoSystemActionWithStatus("ip -6 route delete default", cmdLine) != 0)
                    CcspTraceError(("failed to run cmd: %s", cmdLine));

            }
            else
            {
                CcspTraceError(("%s-%d: Failed to delete addr and route from Interface %s, prefix=%s, prefixAddr=%s \n",
       	                                __FUNCTION__, __LINE__, IfaceName, prefix, prefixAddr));
            }
            break;
        }
        case SET_LFT:
        {
            if (strlen(prefixAddr) > 0)
            {
                memset(cmdLine, 0, sizeof(cmdLine));
                snprintf(cmdLine, sizeof(cmdLine), "ip -6 addr change %s dev %s valid_lft %d preferred_lft %d ", prefixAddr, IfaceName, vallft, preflft);
                if (WanManager_DoSystemActionWithStatus("processDhcp6cStateChanged: ip -6 addr change L3IfName", (cmdLine)) != 0)
                    CcspTraceError(("failed to run cmd: %s", cmdLine));

                CcspTraceInfo(("%s-%d: Successfully updated addr from Interface %s, prefixAddr=%s, vallft=%d, preflft=%d \n",
                                       __FUNCTION__, __LINE__, IfaceName, prefixAddr, vallft, preflft));
            }
	    else
            {
                CcspTraceError(("%s-%d: Failed to update addr from Interface %s, prefixAddr=%s, vallft=%d, preflft=%d \n",
                                        __FUNCTION__, __LINE__, IfaceName, prefixAddr, vallft, preflft));
            }
            break;
        }
    }

    return 0;
}


int WanManager_RestartDhcpv6Client(DML_VIRTUAL_IFACE* pVirtIf, IFACE_TYPE IfaceType)
{
    if (pVirtIf == NULL)
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return 0;
    }

    CcspTraceInfo(("%s %d: Restarting dhcpv6 client for interface %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
#if  defined( FEATURE_RDKB_DHCP_MANAGER )
    char dmlName[256] = {0};

    snprintf( dmlName, sizeof(dmlName), "%s.X_RDK_Restart", pVirtIf->IP.DHCPv6Iface );
    if (ANSC_STATUS_SUCCESS == WanMgr_RdkBus_SetParamValues(DHCPMGR_COMPONENT_NAME, DHCPMGR_DBUS_PATH, dmlName, "true", ccsp_boolean, TRUE))
    {
        CcspTraceInfo(("%s %d - Successfully set [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
        pVirtIf->IP.Dhcp6cStatus = DHCPC_STARTED;
        CcspTraceInfo(("%s %d - ReStarted dhcpv4 client on interface %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
    }
    else
    {
        CcspTraceInfo(("%s %d - Failed setting [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
    }
    pVirtIf->IP.Dhcp4cPid = 1; //Set a dummy value to indicate dhcp client is started
    return 0;
#endif
    // Stop the DHCPv6 client
    if (WanManager_StopDhcpv6Client(pVirtIf, STOP_DHCP_WITH_RELEASE) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Failed to stop dhcpv6 client for interface %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
        return -1;
    }

    // Start the DHCPv6 client
    if (WanManager_StartDhcpv6Client(pVirtIf, IfaceType) != 0)
    {
        CcspTraceError(("%s %d: Failed to start dhcpv6 client for interface %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
        return -1;
    }

    CcspTraceInfo(("%s %d: Successfully restarted dhcpv6 client for interface %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
    return 0;
}

int WanManager_StartDhcpv6Client(DML_VIRTUAL_IFACE* pVirtIf, IFACE_TYPE IfaceType)
{
    if (pVirtIf == NULL)
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return 0;
    }

    // Send RS(Solicited) request when IPv6 source as SLAAC to comply RA(Solicited) response
    if ( DML_WAN_IP_SOURCE_SLAAC == pVirtIf->IP.IPv6Source )
    {
       if ( ANSC_STATUS_FAILURE == WanManager_SendRS_And_ProcessRA(pVirtIf) )
       {
            CcspTraceError(("%s %d: Failed to send Router Solicit for '%s' so not proceeding further.\n", __FUNCTION__, __LINE__, pVirtIf->Name));
            pVirtIf->IP.Dhcp6cStatus = DHCPC_FAILED;
            pVirtIf->IP.Dhcp6cPid = -1;
            return -1;
       }
       else if ( FALSE == pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag )
       {
            CcspTraceError(("%s %d: Router Advertisement complying with SLAAC only configuration for '%s' so not proceeding further for DHCPv6 client start.\n", __FUNCTION__, __LINE__, pVirtIf->Name));
            pVirtIf->IP.Dhcp6cStatus = DHCPC_DISABLED;
            pVirtIf->IP.Dhcp6cPid = -1;
            return -1;
       }
    }
    else
    {
        WanManager_send_and_receive_rs(pVirtIf);
    }

#if  defined( FEATURE_RDKB_DHCP_MANAGER )
    char dmlName[256] = {0};
    WanMgr_SubscribeDhcpClientEvents(pVirtIf->IP.DHCPv6Iface);
    snprintf( dmlName, sizeof(dmlName), "%s.Interface", pVirtIf->IP.DHCPv6Iface );
    WanMgr_RdkBus_SetParamValues(DHCPMGR_COMPONENT_NAME, DHCPMGR_DBUS_PATH, dmlName, pVirtIf->Name, ccsp_string, TRUE);
    memset(dmlName, 0, sizeof(dmlName));

    snprintf( dmlName, sizeof(dmlName), "%s.Enable", pVirtIf->IP.DHCPv6Iface );

    if (ANSC_STATUS_SUCCESS == WanMgr_RdkBus_SetParamValues(DHCPMGR_COMPONENT_NAME, DHCPMGR_DBUS_PATH, dmlName , "true", ccsp_boolean, TRUE))
    {
        CcspTraceInfo(("%s %d - Successfully set [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
        CcspTraceInfo(("%s %d - Started dhcpv6 client on interface %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
        pVirtIf->IP.Dhcp6cStatus = DHCPC_STARTED;
        
    }
    else
    {
        pVirtIf->IP.Dhcp6cStatus = DHCPC_FAILED;
        CcspTraceInfo(("%s %d - Failed setting [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
    }
    pVirtIf->IP.Dhcp6cPid = 1; //Set a dummy value to indicate dhcp client is started
    return 0;
#else
    int pid = 0;
    dhcp_params params;
    memset (&params, 0, sizeof(dhcp_params));
    params.ifname = pVirtIf->Name;
    params.ifType = IfaceType;

    CcspTraceInfo(("Enter WanManager_StartDhcpv6Client for  %s \n", pVirtIf->Name));
    pid = start_dhcpv6_client(&params);
    if (pid == 0) 
    {
        CcspTraceError(("%s %d: dhcpv6 client failed to start. Returing pid -1.\n", __FUNCTION__, __LINE__));
        pVirtIf->IP.Dhcp6cStatus = DHCPC_FAILED;
        pVirtIf->IP.Dhcp6cPid = -1;
        return -1;
    }
    pVirtIf->IP.Dhcp6cPid = pid;
    pVirtIf->IP.Dhcp6cStatus = DHCPC_STARTED;
    CcspTraceInfo(("%s %d - Started dhcpv6 client on interface %s, dhcpv6_pid %d \n", __FUNCTION__, __LINE__, pVirtIf->Name, pVirtIf->IP.Dhcp6cPid));
    return 0;
#endif
}

/**
 * @brief This function will stop the DHCPV6 client(WAN side) in router
 *
 * @param boolDisconnect : This indicates whether this function called from disconnect context or not.
 *              TRUE (disconnect context) / FALSE (Non disconnect context)
 */
ANSC_STATUS WanManager_StopDhcpv6Client(DML_VIRTUAL_IFACE* pVirtIf, DHCP_RELEASE_BEHAVIOUR is_release_required)
{
    if (pVirtIf == NULL)
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return 0;
    }

    CcspTraceInfo (("%s %d: Stopping dhcpv6 client for %s %s\n", __FUNCTION__, __LINE__, pVirtIf->Name, (is_release_required==STOP_DHCP_WITH_RELEASE)? "With release": "."));

#if  defined( FEATURE_RDKB_DHCP_MANAGER )
    char dmlName[256] = {0};
    snprintf( dmlName, sizeof(dmlName), "%s.Enable", pVirtIf->IP.DHCPv6Iface );
    if (ANSC_STATUS_SUCCESS == WanMgr_RdkBus_SetParamValues(DHCPMGR_COMPONENT_NAME, DHCPMGR_DBUS_PATH, dmlName, "false", ccsp_boolean, TRUE))
    {
        CcspTraceInfo(("%s %d - Successfully set [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
        pVirtIf->IP.Dhcp6cStatus = DHCPC_STOPPED;
        pVirtIf->IP.Dhcp6cPid = 0; 
    }
    else
    {
        CcspTraceInfo(("%s %d - Failed setting [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
    }
    WanMgr_UnSubscribeDhcpClientEvents(pVirtIf->IP.DHCPv6Iface);
    return ANSC_STATUS_SUCCESS;
#else
    if (is_release_required == STOP_DHCP_WITH_RELEASE)
    {
        // send unicast DHCPv6 RELEASE
        int fd = 0;
        fd = creat("/tmp/dhcpv6_release",S_IRUSR | S_IWUSR | S_IRGRP);
        if(fd != -1)
        {
            close(fd);
        }
    }
    int ret;
    dhcp_params params;

    memset (&params, 0, sizeof(dhcp_params));
    params.ifname = pVirtIf->Name;

    ret = stop_dhcpv6_client(&params);
    pVirtIf->IP.Dhcp6cStatus = DHCPC_STOPPED;
    pVirtIf->IP.Dhcp6cPid = 0;
    return ret;
#endif
}


int WanManager_StartDhcpv4Client(DML_VIRTUAL_IFACE* pVirtIf, char* baseInterface, IFACE_TYPE IfaceType)
{
    if (pVirtIf == NULL)
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return 0;
    }
#if  defined( FEATURE_RDKB_DHCP_MANAGER )
    char dmlName[256] = {0};
    WanMgr_SubscribeDhcpClientEvents(pVirtIf->IP.DHCPv4Iface);
    snprintf( dmlName, sizeof(dmlName), "%s.Interface", pVirtIf->IP.DHCPv4Iface );
    WanMgr_RdkBus_SetParamValues(DHCPMGR_COMPONENT_NAME, DHCPMGR_DBUS_PATH, dmlName, pVirtIf->Name, ccsp_string, TRUE);
    memset(dmlName, 0, sizeof(dmlName));
    snprintf( dmlName, sizeof(dmlName), "%s.Enable", pVirtIf->IP.DHCPv4Iface );
    if (ANSC_STATUS_SUCCESS == WanMgr_RdkBus_SetParamValues(DHCPMGR_COMPONENT_NAME, DHCPMGR_DBUS_PATH, dmlName, "true", ccsp_boolean, TRUE))
    {
        CcspTraceInfo(("%s %d - Successfully set [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
        pVirtIf->IP.Dhcp4cStatus = DHCPC_STARTED;
        CcspTraceInfo(("%s %d - Started dhcpv4 client on interface %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
    }
    else
    {
        pVirtIf->IP.Dhcp4cStatus = DHCPC_FAILED;
        CcspTraceInfo(("%s %d - Failed setting [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
    }
    pVirtIf->IP.Dhcp4cPid = 1; //Set a dummy value to indicate dhcp client is started
    return 0;
#else
#if defined(_DT_WAN_Manager_Enable_)
    WanManager_CreateDHCPService(pVirtIf);
    return 0;//TODO:Read and return PID
#endif
    dhcp_params params;
    int pid = 0;

    memset (&params, 0, sizeof(dhcp_params));
    params.ifname = pVirtIf->Name;
    params.baseIface = baseInterface;
    params.ifType = IfaceType;

    CcspTraceInfo(("Starting DHCPv4 Client for iface: %s \n", params.ifname));
    pid = start_dhcpv4_client(&params);
    
    if (pid == 0)  
    {
        CcspTraceError(("%s %d: dhcpv4 client failed to start. Returing pid -1.\n", __FUNCTION__, __LINE__));
        pVirtIf->IP.Dhcp4cPid = -1;
        pVirtIf->IP.Dhcp4cStatus = DHCPC_FAILED;
        return -1;
    }

    pVirtIf->IP.Dhcp4cStatus = DHCPC_STARTED;
    pVirtIf->IP.Dhcp4cPid = pid;
    CcspTraceInfo(("%s %d - Started dhcpc on interface %s, dhcpv4_pid %d \n", __FUNCTION__, __LINE__, pVirtIf->Name, pVirtIf->IP.Dhcp4cPid));
    return 0;
#endif
}

ANSC_STATUS WanManager_StopDhcpv4Client(DML_VIRTUAL_IFACE* pVirtIf, DHCP_RELEASE_BEHAVIOUR IsReleaseNeeded)
{
    if (pVirtIf == NULL)
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return 0;
    }
    CcspTraceInfo (("%s %d: Stopping dhcpv4 client for %s %s\n", __FUNCTION__, __LINE__, pVirtIf->Name, (IsReleaseNeeded==STOP_DHCP_WITH_RELEASE)? "With release": "."));
#if  defined( FEATURE_RDKB_DHCP_MANAGER )
    char dmlName[256] = {0};
    snprintf( dmlName, sizeof(dmlName), "%s.Enable", pVirtIf->IP.DHCPv4Iface );
    if (ANSC_STATUS_SUCCESS == WanMgr_RdkBus_SetParamValues(DHCPMGR_COMPONENT_NAME, DHCPMGR_DBUS_PATH, dmlName, "false", ccsp_boolean, TRUE))
    {
        CcspTraceInfo(("%s %d - Successfully set [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
        pVirtIf->IP.Dhcp4cStatus = DHCPC_STOPPED;
        pVirtIf->IP.Dhcp4cPid = 0;
    }
    else
    {
        CcspTraceInfo(("%s %d - Failed setting [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
    }
    WanMgr_UnSubscribeDhcpClientEvents(pVirtIf->IP.DHCPv4Iface);
    if (IsReleaseNeeded == STOP_DHCP_WITH_RELEASE)
    {
        //TODO: sleep added to allow dhcpv4 client to send release before interface deconfig. This should be handled by dhcpmanager itself.
        CcspTraceInfo(("%s %d - sleep 3 seconds for dhcpv4 client to send release \n", __FUNCTION__, __LINE__));
        sleep(3);
    }    
    return ANSC_STATUS_SUCCESS;
#else
#if defined(_DT_WAN_Manager_Enable_)
    WanManager_StopUdhcpcService(iface_name);
    return ANSC_STATUS_SUCCESS;
#endif

    dhcp_params params;
    ANSC_STATUS ret;

    memset (&params, 0, sizeof(dhcp_params));
    params.ifname = pVirtIf->Name;
    params.is_release_required = (IsReleaseNeeded==STOP_DHCP_WITH_RELEASE)?true:false;

    ret = stop_dhcpv4_client(&params);

    if (IsReleaseNeeded == STOP_DHCP_WITH_RELEASE)
    {
        // Need to review during DHCP Manager integration.
        CcspTraceInfo(("%s %d - sleep 2 seconds for dhcpv4 client to send release \n", __FUNCTION__, __LINE__));
        sleep(2);
    }
    pVirtIf->IP.Dhcp4cStatus = DHCPC_STOPPED;
    pVirtIf->IP.Dhcp4cPid = 0;
    return ret;
#endif
}

void WanManager_PrintBootEvents (WanBootEventState state)
{

    BOOLEAN BootToWanUp = FALSE;
    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        BootToWanUp = pWanConfigData->data.BootToWanUp;

        if (BootToWanUp == TRUE)
        {
            WanMgrDml_GetConfigData_release(pWanConfigData);
            CcspTraceInfo(("%s %d: Wan was already up so no need to print Boot logs\n", __FUNCTION__, __LINE__));
            return;
        }

        if (state == WAN_INIT_COMPLETE)
        {
            CcspTraceInfo(("%s %d: Setting BootToWanUp to TRUE\n", __FUNCTION__, __LINE__));
            pWanConfigData->data.BootToWanUp = TRUE;
        }
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }


    if (state == WAN_INIT_START )
    {
        CcspTraceInfo(("%s %d:Logging Waninit_start\n", __FUNCTION__, __LINE__));
        v_secure_system("print_uptime \"Waninit_start\"");
    }
    else if (state == WAN_INIT_COMPLETE)
    {
        CcspTraceInfo(("%s %d:Logging Waninit_complete\n", __FUNCTION__, __LINE__));
        v_secure_system("print_uptime \"Waninit_complete\"");
        v_secure_system("print_uptime \"boot_to_wan_uptime\"");
    }

}


#ifdef FEATURE_MAPT
const char *nat44PostRoutingTable = "OUTBOUND_POSTROUTING";
char ipv6AddressString[BUFLEN_256] = {0};
#ifdef FEATURE_MAPT_DEBUG
void WanManager_UpdateMaptLogFile(ipc_mapt_data_t *dhcp6cMAPTMsgBody);
#endif // FEATURE_MAPT_DEBUG
static int WanManager_ConfigureIpv6Sysevents(char *pdIPv6Prefix, char *ipAddressString, int psidValue);
#ifdef NAT46_KERNEL_SUPPORT
static int get_V6_defgateway_wan_interface(char *defGateway);
#endif // NAT46_KERNEL_SUPPORT

static unsigned WanManager_GetMAPTbits(unsigned value, int pos, int num)
{
    return (value >> (pos + 1 - num)) & ~(~0 << num);
}
/*
 *   Returns LAN IP Address in the form X.X.X.X/Y, e.g. 192.168.0.1/24
 */
static ANSC_STATUS WanManager_GetLANIPAddress(char *ipAddress, size_t length)
{
    char lan_ip_address[IP_ADDR_LENGTH];
    char lan_subnet_mask[IP_ADDR_LENGTH];

    if (syscfg_get(NULL, SYSCFG_LAN_IP_ADDRESS, lan_ip_address, sizeof(lan_ip_address)) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("Failed to get LAN IP address \n"));
        return ANSC_STATUS_FAILURE;
    }

    if (syscfg_get(NULL, SYSCFG_LAN_NET_MASK, lan_subnet_mask, sizeof(lan_subnet_mask)) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("Failed to get LAN subnet mask \n"));
        return ANSC_STATUS_FAILURE;
    }

    // count number of bits set in subnet mask.
    unsigned int lanSubnetMask = inet_network(lan_subnet_mask);
    unsigned int subnetCount = 0;
    while (lanSubnetMask)
    {
        subnetCount += lanSubnetMask & 1;
        lanSubnetMask = lanSubnetMask >> 1;
    }

    CcspTraceInfo(("LAN IP address/subnet mask = %s/%u \n", lan_ip_address, subnetCount));

    snprintf(ipAddress, length, "%s/%u", lan_ip_address, subnetCount);

    return ANSC_STATUS_SUCCESS;
}

#define UPnPIGD_ENABLE_DML "Device.UPnP.Device.UPnPIGD"
BOOL g_UPnPIGDServiceStopped = false;
int WanMgr_RdkBus_ConfigureUPnPIGDService (BOOL configure_UPnPIGD)
{
    if( configure_UPnPIGD && g_UPnPIGDServiceStopped)
    {
        CcspTraceInfo(("%s %d: upnp_igd was stopped while configuring MAPT. Starting the service again\n", __FUNCTION__, __LINE__));
        if (WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, UPnPIGD_ENABLE_DML, "true", ccsp_boolean, TRUE ) == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s %d: Succesfully set %s to true\n", __FUNCTION__, __LINE__, UPnPIGD_ENABLE_DML));
        }
        g_UPnPIGDServiceStopped = false;
    }
    else if(!configure_UPnPIGD)
    {
        char syscfg_enabled[BUFLEN_8] = {0};
        syscfg_get(NULL, "upnp_igd_enabled", syscfg_enabled, sizeof(syscfg_enabled));
        if('1' == syscfg_enabled[0])
        {
            CcspTraceInfo(("%s %d: Stopping UPnPIGD service \n", __FUNCTION__, __LINE__));
            if (WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, UPnPIGD_ENABLE_DML, "false", ccsp_boolean, TRUE ) == ANSC_STATUS_SUCCESS)
            {
                CcspTraceInfo(("%s %d: Succesfully set %s to false\n", __FUNCTION__, __LINE__, UPnPIGD_ENABLE_DML));
            }
            g_UPnPIGDServiceStopped = true;
        }
        else
        {
            CcspTraceInfo(("%s %d: UPnPIGD is not enabled in syscfg upnp_igd_enabled\n", __FUNCTION__, __LINE__));
        }
    }
    return 0;
}

ANSC_STATUS WanManager_VerifyMAPTConfiguration(ipc_mapt_data_t *dhcp6cMAPTMsgBody, WANMGR_MAPT_CONFIG_DATA *MaptConfig)
{
    int ret = RETURN_OK;
    int ipv4IndexValue = 0;
    struct in_addr result;
    unsigned char ipAddressBytes[BUFLEN_4];
    unsigned long int ipValue = 0;

    if (dhcp6cMAPTMsgBody == NULL)
    {
        CcspTraceError(("%s %d: Invalid args. MAPTMsgBody is NULL \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (MaptConfig == NULL)
    {
        CcspTraceError(("%s %d: Invalid args. MaptConfig is NULL \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    //The sharing ratio cannot be zero, a value of zero means the sharing ratio is 1
    if (dhcp6cMAPTMsgBody->ratio == 0)
        dhcp6cMAPTMsgBody->ratio = 1;

#ifdef FEATURE_MAPT_DEBUG
    WanManager_UpdateMaptLogFile(dhcp6cMAPTMsgBody);
#endif

#if defined(IVI_KERNEL_SUPPORT) || (NAT46_KERNEL_SUPPORT)
    if ((dhcp6cMAPTMsgBody->psidLen > 0) && (dhcp6cMAPTMsgBody->eaLen == 0))
    {
        MaptConfig->psidValue = dhcp6cMAPTMsgBody->psid;
        MaptConfig->psidLen = dhcp6cMAPTMsgBody->psidLen;
        ipv4IndexValue = 0;
#ifdef FEATURE_MAPT_DEBUG
        MaptInfo("Using psid value from dhcp6c options : %d", MaptConfig->psidValue);
        MaptInfo("Using psidLen value from dhcp6c options : %d", MaptConfig->psidLen);
        MaptInfo("Using psidOffset value from dhcp6c options : %d", dhcp6cMAPTMsgBody->psidOffset);
#endif
    }
    else
    {
        ret = WanManager_CalculatePsidAndV4Index(dhcp6cMAPTMsgBody->pdIPv6Prefix, dhcp6cMAPTMsgBody->v6Len, dhcp6cMAPTMsgBody->iapdPrefixLen,
                dhcp6cMAPTMsgBody->v4Len, &(MaptConfig->psidValue), &ipv4IndexValue, &(MaptConfig->psidLen));
    }

    if (ret != RETURN_OK)
    {
        CcspTraceError(("Error in calculating MAPT PSID value \n"));
#ifdef FEATURE_MAPT_DEBUG
        MaptInfo("Exiting MAPT configuration, MAPT will not be configured, error found in getting PSID value");
#endif
        CcspTraceNotice(("FEATURE_MAPT: MAP-T configuration failed\n"));
        return ANSC_STATUS_FAILURE;
    }
#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("--- MAP-T Computed Values - START ---");
    MaptInfo("mapt: PSID Value: %d, ipv4IndexValue: %d", MaptConfig->psidValue, ipv4IndexValue);
    MaptInfo("mapt: PSID Length: %d", MaptConfig->psidLen);
#endif

    inet_pton(AF_INET, dhcp6cMAPTMsgBody->ruleIPv4Prefix, &(result));

    ipValue = htonl(result.s_addr) + ipv4IndexValue;

    ipAddressBytes[0] = ipValue & 0xFF;
    ipAddressBytes[1] = (ipValue >> 8) & 0xFF;
    ipAddressBytes[2] = (ipValue >> 16) & 0xFF;
    ipAddressBytes[3] = (ipValue >> 24) & 0xFF;

    //store new ipv4 address
    snprintf(MaptConfig->ipAddressString, sizeof(MaptConfig->ipAddressString), "%d.%d.%d.%d", ipAddressBytes[3], ipAddressBytes[2], ipAddressBytes[1], ipAddressBytes[0]);

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("mapt: ipAddressString:%s", MaptConfig->ipAddressString);
#endif

    //get LAN IP Address
    if ((ret = WanManager_GetLANIPAddress(MaptConfig->ipLANAddressString, sizeof(MaptConfig->ipLANAddressString))) != RETURN_OK)
    {
        CcspTraceError(("Could not get LAN IP Address"));
        return ANSC_STATUS_FAILURE;
    }

    if ((ret = WanManager_ConfigureIpv6Sysevents(dhcp6cMAPTMsgBody->pdIPv6Prefix, MaptConfig->ipAddressString, MaptConfig->psidValue)) != RETURN_OK)
    {
        CcspTraceError(("Failed to configure ipv6Tablerules"));
        return ANSC_STATUS_FAILURE;
    }

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("mapt: map ipv6 address:%s", ipv6AddressString);
    MaptInfo("--- MAP-T Computed Values - END ---");
#endif

    return ANSC_STATUS_SUCCESS;
}

int WanManager_ProcessMAPTConfiguration(ipc_mapt_data_t *dhcp6cMAPTMsgBody, WANMGR_MAPT_CONFIG_DATA *MaptConfig, const char *baseIf, const WANMGR_IPV6_DATA *ipv6Data)
{
    /* IVI_KERNEL_SUPPORT : To Enable IVI sopprted MAPT work flow
     * NAT46_KERNEL_SUPPORT : To Enable NAT46 sopprted MAPT work flow
     * Enable any one of the build flag at a time */
    int ret = RETURN_OK;
    char cmdDMRConfig[BUFLEN_128 + BUFLEN_64];
    char cmdBMRConfig[BUFLEN_256];
    char cmdStartMAPT[BUFLEN_256];
    char cmdStartMAPTMeshBr[BUFLEN_256];
    char cmdDisableMapFiltering[BUFLEN_64];
    char cmdConfigureMTUSize[BUFLEN_64] = "";
    char cmdEnableIpv4Traffic[BUFLEN_64] = "";
    char cmdEnableDefaultIpv4Route[BUFLEN_64] = "";
    char layer2_iface[BUFLEN_32] = {0};
    const char *vlanIf = ipv6Data->ifname;
    MaptData_t maptInfo;

    /* Get PartnerID. In sky-uk MTU size is 1500 and else case its 1520. */
    char partnerID[BUFLEN_32]    = {0};
    syscfg_get(NULL, "PartnerID", partnerID, sizeof(partnerID));
    int mtu_size_mapt = MTU_DEFAULT_SIZE; /* 1500 */

    if (strcmp("sky-italia", partnerID) == 0)
    {
        mtu_size_mapt = MTU_SIZE; /* 1520. */
    }

    MaptInfo("mapt: PartnerID: %s MTU Size = %d \n", partnerID[0] != '\0' ? partnerID : "Unknown", mtu_size_mapt);

    /* Stopping UPnP, if mapt ratio is not 1:1 */
    if(dhcp6cMAPTMsgBody->ratio > 1)
    {
        CcspTraceInfo(("%s %d: MAPT ratio is %d. Stopping UPnP IGD \n", __FUNCTION__, __LINE__, dhcp6cMAPTMsgBody->ratio));
        WanMgr_RdkBus_ConfigureUPnPIGDService(false);
    }

    /* RM16042: Since erouter0 is vlan interface on top of eth3 ptm, we need
       to first set the MTU size of eth3 to 1520 and then change MTU of erouter0.
       Otherwise we can't configure MTU as we are getting `Numerical result out of range` error.
       Configure eth3 MTU size to 1520.
    */
    if(!strcmp(DSL_INTERFACE, baseIf))
    {
        strcpy(layer2_iface, PTM_INTERFACE);
        snprintf(cmdConfigureMTUSize, sizeof(cmdConfigureMTUSize), "ip link set dev %s mtu %d ", layer2_iface, mtu_size_mapt);
    }
    else
    {
        snprintf(cmdConfigureMTUSize, sizeof(cmdConfigureMTUSize), "ip link set dev %s mtu %d ", baseIf, mtu_size_mapt);
    }

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("mapt: cmdConfigureMTUSize:%s", cmdConfigureMTUSize);
#endif

    if ((ret = WanManager_DoSystemActionWithStatus("map", cmdConfigureMTUSize)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdConfigureMTUSize, ret));
        return ret;
    }

    /*  Configure erouter0 MTU size. */
    snprintf(cmdConfigureMTUSize, sizeof(cmdConfigureMTUSize), "ip link set dev %s mtu %d ", vlanIf, mtu_size_mapt);

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("mapt: cmdConfigureMTUSize:%s", cmdConfigureMTUSize);
#endif
    if ((ret = WanManager_DoSystemActionWithStatus("map", cmdConfigureMTUSize)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdConfigureMTUSize, ret));
        return ret;
    }

#endif  // (IVI_KERNEL_SUPPORT) || (NAT46_KERNEL_SUPPORT)

#ifdef NAT46_KERNEL_SUPPORT
    /* We currently have an issue with the netfilter module, as on the MAP-T 16:1 line the
       netfilter ftp module(nf_nat_ftp.ko) is not able to use the assigned ports generated
       from the PSID values.
       The below snippet removes netfitler ftp kernel module when on MAP-T 16:1 line and loads it
       back when we have changed the line type to 1:1 line.
    */
    int isNatFtpModuleLoaded = RETURN_ERR;
    isNatFtpModuleLoaded = isModuleLoaded(NF_NAT_FTP_MODULE);
#ifdef MAPT_NAT46_FTP_ACTIVE_MODE
    char port_range[BUFLEN_1024] = {'\0'};
    char cmd_ftp_load[BUFLEN_1024] = {'\0'};
#endif

    if(dhcp6cMAPTMsgBody->ratio != 1)
    {
        if(isNatFtpModuleLoaded == RETURN_OK)
        {
            if (WanManager_DoSystemActionWithStatus("wanmanager", "rmmod -f /lib/modules/`uname -r`/kernel/net/netfilter/nf_nat_ftp.ko") != RETURN_OK)
            {
                CcspTraceError(("%s %d rmmod:!!!!! Failed to remove nf_nat_ftp.ko !!!!!\n", __FUNCTION__, __LINE__));
            }
            else
            {
                CcspTraceInfo(("%s %d !!!!! nf_nat_ftp.ko module removed !!!!! \n", __FUNCTION__, __LINE__));
            }
        }
#ifdef MAPT_NAT46_FTP_ACTIVE_MODE
        WanManager_CalculateMAPTPortRange(dhcp6cMAPTMsgBody->psidOffset, MaptConfig->psidLen, MaptConfig->psidValue, port_range);
        if(port_range[0] != '\0')
        {
            snprintf(cmd_ftp_load, BUFLEN_1024, "insmod /lib/modules/`uname -r`/kernel/net/netfilter/nf_nat_ftp.ko port_range_array=%s", port_range);
            if (WanManager_DoSystemActionWithStatus("wanmanager", cmd_ftp_load) != RETURN_OK)
            {
                CcspTraceError(("%s %d insmod: !!!!! Failed to add nf_nat_ftp.ko !!!!! \n", __FUNCTION__, __LINE__));
            }
        }
        else
        {
            CcspTraceInfo(("%s %d MAPT port range is empty \n", __FUNCTION__, __LINE__));
        }
#endif
    }
    else
    {
        if(isNatFtpModuleLoaded != RETURN_OK)
        {
            if (WanManager_DoSystemActionWithStatus("wanmanager", "insmod /lib/modules/`uname -r`/kernel/net/netfilter/nf_nat_ftp.ko") != RETURN_OK)
            {
                CcspTraceError(("%s %d insmod: !!!!! Failed to add nf_nat_ftp.ko !!!!! \n", __FUNCTION__, __LINE__));
            }
            else
            {
                CcspTraceInfo(("%s %d!!!!! nf_nat_ftp.ko added !!!!!\n", __FUNCTION__, __LINE__));
            }
        }
    }
#endif

#ifdef IVI_KERNEL_SUPPORT
    /*Configure Default Ipv4 route*/
    snprintf(cmdEnableDefaultIpv4Route, sizeof(cmdEnableDefaultIpv4Route), "ip -4 r a default dev %s ", vlanIf);
#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("mapt: cmdEnableDefaultIpv4Route:%s", cmdEnableDefaultIpv4Route);
#endif

    if ((ret = WanManager_DoSystemActionWithStatus("map", cmdEnableDefaultIpv4Route)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdEnableDefaultIpv4Route, ret));
        return ret;
    }


    if (dhcp6cMAPTMsgBody->ratio == 1)
        snprintf(cmdDMRConfig, sizeof(cmdDMRConfig), "ivictl -r -d -P %s -R 1 -T", dhcp6cMAPTMsgBody->brIPv6Prefix);
    else
        snprintf(cmdDMRConfig, sizeof(cmdDMRConfig), "ivictl -r -d -P %s -T", dhcp6cMAPTMsgBody->brIPv6Prefix);

#ifdef FEATURE_MAPT_DEBUG
    /*Configure Default Ipv4 route*/
    MaptInfo("### ivictl commands - START ###");
    MaptInfo("ivictl:DMR config:%s", cmdDMRConfig);
#endif //FEATURE_MAPT_DEBUG

    if ((ret = WanManager_DoSystemActionWithStatus("ivictl", cmdDMRConfig)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdDMRConfig, ret));
        return ret;
    }


    snprintf(cmdBMRConfig, sizeof(cmdBMRConfig), "ivictl -r -p %s/%d -P %s -z %d -R %d -T", dhcp6cMAPTMsgBody->ruleIPv4Prefix,dhcp6cMAPTMsgBody->v4Len,
             dhcp6cMAPTMsgBody->ruleIPv6Prefix, dhcp6cMAPTMsgBody->psidOffset, dhcp6cMAPTMsgBody->ratio);

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("ivictl:BMR config:%s", cmdBMRConfig);
#endif

    if ((ret = WanManager_DoSystemActionWithStatus("ivictl", cmdBMRConfig)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdBMRConfig, ret));
        return ret;
    }

    // create MAP-T command string
    // On a sharing ratio of 1, since the psid value is zero, we don't require to specify PSID, in the MAP-T command string
    {
        snprintf(cmdStartMAPT, sizeof(cmdStartMAPT), "ivictl -s -i %s -I %s -H -a %s -A %s/%d -P %s -z %d -R %d -T ", ETH_BRIDGE_NAME, vlanIf,
                 MaptConfig->ipLANAddressString, MaptConfig->ipAddressString, dhcp6cMAPTMsgBody->v4Len, dhcp6cMAPTMsgBody->ruleIPv6Prefix, dhcp6cMAPTMsgBody->psidOffset,
                 dhcp6cMAPTMsgBody->ratio);
#ifdef IVI_MULTI_BRIDGE_SUPPORT
        snprintf(cmdStartMAPTMeshBr, sizeof(cmdStartMAPTMeshBr), "ivictl -s -i %s -I %s -H -a %s/%d -A %s/%d -P %s -z %d -R %d -o %d -T", ETH_MESH_BRIDGE, vlanIf,
                 MESH_BRIP,MESH_BRMASK, MaptConfig->ipAddressString, dhcp6cMAPTMsgBody->v4Len, dhcp6cMAPTMsgBody->ruleIPv6Prefix, dhcp6cMAPTMsgBody->psidOffset,
                 dhcp6cMAPTMsgBody->ratio, MaptConfig->psidValue);
#endif  //IVI_MULTI_BRIDGE_SUPPORT
    }
    else
    {
        snprintf(cmdStartMAPT, sizeof(cmdStartMAPT), "ivictl -s -i %s -I %s -H -a %s -A %s/%d -P %s -z %d -R %d -T -o %d", ETH_BRIDGE_NAME, vlanIf,
                 MaptConfig->ipLANAddressString, MaptConfig->ipAddressString, dhcp6cMAPTMsgBody->v4Len, dhcp6cMAPTMsgBody->ruleIPv6Prefix, dhcp6cMAPTMsgBody->psidOffset,
                 dhcp6cMAPTMsgBody->ratio, MaptConfig->psidValue);
#ifdef IVI_MULTI_BRIDGE_SUPPORT
        snprintf(cmdStartMAPTMeshBr, sizeof(cmdStartMAPTMeshBr), "ivictl -s -i %s -I %s -H -a %s/%d -A %s/%d -P %s -z %d -R %d -T -o %d", ETH_MESH_BRIDGE, vlanIf,
                MESH_BRIP,MESH_BRMASK, MaptConfig->ipAddressString, dhcp6cMAPTMsgBody->v4Len, dhcp6cMAPTMsgBody->ruleIPv6Prefix, dhcp6cMAPTMsgBody->psidOffset,
                dhcp6cMAPTMsgBody->ratio, MaptConfig->psidValue);
#endif  //IVI_MULTI_BRIDGE_SUPPORT
    }

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("ivictl:startMapt Command:%s", cmdStartMAPT);
#endif
    ret = WanManager_DoSystemActionWithStatus("ivictl", cmdStartMAPT);

    //Added check since the 'system' command is not returning the expected value
    if (ret == IVICTL_COMMAND_ERROR)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdStartMAPT, ret));
        return ret;
    }

#ifdef IVI_MULTI_BRIDGE_SUPPORT
#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("ivictl:startMapt Command:%s", cmdStartMAPTMeshBr);
#endif
    ret = WanManager_DoSystemActionWithStatus("ivictl", cmdStartMAPTMeshBr);
    if (ret == IVICTL_COMMAND_ERROR)
    {
       CcspTraceError(("Failed to run: %s:%d", cmdStartMAPTMeshBr, ret));
       return ret;
    }
#endif  //IVI_MULTI_BRIDGE_SUPPORT
#endif  //IVI_KERNEL_SUPPORT

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("mapt: Disable RP Filtering: echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter", vlanIf);
#endif

    if (sysctl_iface_set("/proc/sys/net/ipv4/conf/%s/rp_filter", vlanIf, "0") != 0)
    {
        CcspTraceError(("%s-%d : Failure writing to /proc file\n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

#ifdef NAT46_KERNEL_SUPPORT
    char cmdinterfaceCreate[BUFLEN_512];
    char cmdInterfaceConfig[BUFLEN_1024];
    char cmdInterfaceUp[BUFLEN_512];
    char cmdInterfaceDefaultRouteDefault[BUFLEN_512];
    char cmdInterfaceDefaultRoDel[BUFLEN_512];
    char defaultGatewayV6[BUFLEN_128];
    char cmdInterfaceMTU1[BUFLEN_512];
    char cmdInterfaceMTU2[BUFLEN_512];
    char cmdInterfaceMTU3[BUFLEN_512];

    snprintf(cmdinterfaceCreate , sizeof(cmdinterfaceCreate), "echo add %s > /proc/net/nat46/control", MAP_INTERFACE);
    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdinterfaceCreate)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdinterfaceCreate, ret));
        return ret;
    }

#if defined (_COSA_BCM_ARM_) && defined (_XB6_PRODUCT_REQ_) 
    //Adding local.pd info for the Broadcom specific platforms to support MAP-T accelaration. TODO: this could be added generically.
    snprintf(cmdInterfaceConfig , sizeof(cmdInterfaceConfig), "echo config %s local.style MAP local.v4 %s/%d local.v6 %s local.ea-len %d local.psid-offset %d remote.v4 0.0.0.0/0 remote.v6 %s remote.style RFC6052 remote.ea-len 0 remote.psid-offset 0 debug -1 local.pd %s > /proc/net/nat46/control",
    MAP_INTERFACE, dhcp6cMAPTMsgBody->ruleIPv4Prefix, dhcp6cMAPTMsgBody->v4Len, dhcp6cMAPTMsgBody->ruleIPv6Prefix, dhcp6cMAPTMsgBody->eaLen, dhcp6cMAPTMsgBody->psidOffset, dhcp6cMAPTMsgBody->brIPv6Prefix, ipv6Data->sitePrefix);
#else
    snprintf(cmdInterfaceConfig , sizeof(cmdInterfaceConfig), "echo config %s local.style MAP local.v4 %s/%d local.v6 %s local.ea-len %d local.psid-offset %d remote.v4 0.0.0.0/0 remote.v6 %s remote.style RFC6052 remote.ea-len 0 remote.psid-offset 0 debug -1 > /proc/net/nat46/control",
    MAP_INTERFACE, dhcp6cMAPTMsgBody->ruleIPv4Prefix, dhcp6cMAPTMsgBody->v4Len, dhcp6cMAPTMsgBody->ruleIPv6Prefix, dhcp6cMAPTMsgBody->eaLen, dhcp6cMAPTMsgBody->psidOffset, dhcp6cMAPTMsgBody->brIPv6Prefix);
#endif
    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdInterfaceConfig)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdInterfaceConfig, ret));
        return ret;
    }

    snprintf(cmdInterfaceUp , sizeof(cmdInterfaceUp), "ip link set %s up", MAP_INTERFACE);
    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdInterfaceUp)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdInterfaceUp, ret));
        return ret;
    }

    int defGatewayCheckMaxRetry = 20; // 5 seconds
    while(defGatewayCheckMaxRetry > 0)
    {
        defGatewayCheckMaxRetry--;
        if(get_V6_defgateway_wan_interface(defaultGatewayV6) == RETURN_OK)
        {
            break;
        }
        if(defGatewayCheckMaxRetry == 0)
        {
            CcspTraceInfo(("%s %d :: Default gateway route is missing, so can't configure MAP-T (5 seonds wait timed out)\n", __FUNCTION__, __LINE__));
            return RETURN_ERR;
        }
        else
        {
            usleep(250000); // 250 milliseconds
        }
    }

    snprintf(cmdInterfaceDefaultRoDel , sizeof(cmdInterfaceDefaultRoDel), "ip route del default");
    snprintf(cmdConfigureMTUSize, sizeof(cmdConfigureMTUSize), "ip link set dev %s mtu %d ", MAP_INTERFACE, mtu_size_mapt);
    snprintf(cmdInterfaceMTU1, sizeof(cmdInterfaceMTU1), "echo %d > /proc/sys/net/ipv6/conf/%s/mtu", MTU_DEFAULT_SIZE, vlanIf);
    
    /*
     * Configure IPv6 default route with MTU for specific partner "sky-italia"
     * Todo: Cleanup should be done to configure MTU based on delegated leases from DHCPv6 server or partners configurations
     */
    cmdInterfaceMTU2[0] = '\0';
    if ( 0 == strcmp(partnerID, "sky-italia") )
    {
        snprintf(cmdInterfaceMTU2, sizeof(cmdInterfaceMTU2), "ip -6 ro change default via %s dev %s mtu %d", defaultGatewayV6, vlanIf, MTU_DEFAULT_SIZE);
    }
#if !(defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
        snprintf(cmdEnableIpv4Traffic, sizeof(cmdEnableIpv4Traffic), "ip ro rep default dev %s mtu %d", MAP_INTERFACE, MTU_DEFAULT_SIZE) ;
    #else // XB6 and CBR use 1500 -28 MTU size for route
        snprintf(cmdEnableIpv4Traffic, sizeof(cmdEnableIpv4Traffic), "ip ro rep default dev %s mtu %d", MAP_INTERFACE, MTU_DEFAULT_SIZE-28) ;
    #endif
    snprintf(cmdInterfaceMTU3, sizeof(cmdInterfaceMTU3), "ip -6 ro rep %s via %s dev %s mtu %d", dhcp6cMAPTMsgBody->brIPv6Prefix, defaultGatewayV6, vlanIf, mtu_size_mapt);
    snprintf(cmdInterfaceDefaultRouteDefault , sizeof(cmdInterfaceDefaultRouteDefault), "ip -6 ro rep %s/128 dev %s mtu %d", ipv6AddressString, MAP_INTERFACE, mtu_size_mapt);
#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("--- map_nat46: Configuration Starts ---");
    MaptInfo("map_nat46: %s", cmdinterfaceCreate);
    MaptInfo("map_nat46: %s", cmdInterfaceConfig);
    MaptInfo("map_nat46: %s", cmdInterfaceUp);
    MaptInfo("map_nat46: %s", cmdInterfaceDefaultRoDel);
    MaptInfo("map_nat46: %s", cmdConfigureMTUSize);
    MaptInfo("map_nat46: %s", cmdInterfaceMTU1);
    MaptInfo("map_nat46: %s", cmdInterfaceMTU2[0] != '\0' ? cmdInterfaceMTU2 : "N/A");
    MaptInfo("map_nat46: %s", cmdEnableIpv4Traffic);
    MaptInfo("map_nat46: %s", cmdInterfaceMTU3);
    MaptInfo("map_nat46: %s", cmdInterfaceDefaultRouteDefault);
    MaptInfo("--- map_nat46: Configuration Ends ---");
#endif

    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdInterfaceDefaultRoDel)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdInterfaceDefaultRoDel, ret));
        return ret;
    }
    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdConfigureMTUSize)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdConfigureMTUSize, ret));
        return ret;
    }
    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdInterfaceMTU1)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdInterfaceMTU1, ret));
        return ret;
    }
    if ((cmdInterfaceMTU2[0] != '\0') && ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdInterfaceMTU2)) < RETURN_OK))
    {
        CcspTraceError(("Failed to run: %s:%d", cmdInterfaceMTU2, ret));
        return ret;
    }
    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdEnableIpv4Traffic)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdEnableIpv4Traffic, ret));
        return ret;
    }
    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdInterfaceMTU3)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdInterfaceMTU3, ret));
        return ret;
    }
    if ((ret = WanManager_DoSystemActionWithStatus("map_nat46", cmdInterfaceDefaultRouteDefault)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdInterfaceDefaultRouteDefault, ret));
        return ret;
    }
#endif  // NAT46_KERNEL_SUPPORT

/*
 * Any VoIP/SIP application running on the CPE itself or in the home LAN, MUST send some form of SIP keepalives (Options or Register messages), 
 * more frequent than the nf_conntrack_udp_timeout_stream value to allow unsolicited inbound calls to not be blocked by the firewall.   
 * Either increase this value above the SIP keepalive frequency, or ensure SIP applications are configured to send keepalives more frequent than Linux's default value of 120 seconds.
 */
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)
    // This is a configuration specific for Comcast. Sky devices has nf_conntrack_udp_timeout_stream set to 300 seconds.
    CcspTraceInfo(("%s %d :Setting nf_conntrack_udp_timeout to 30 seconds for MAPT! \n", __FUNCTION__, __LINE__));
    if ( v_secure_system("sysctl -w net.netfilter.nf_conntrack_udp_timeout=30") )
    {
        CcspTraceError(("%s %d : Failed to set nf_conntrack_udp_timeout! \n", __FUNCTION__, __LINE__));
    }

    CcspTraceInfo(("%s %d :Setting nf_conntrack_udp_timeout_stream to 120 seconds for MAPT! \n", __FUNCTION__, __LINE__));
    if ( v_secure_system("sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=120") )
    {
        CcspTraceError(("%s %d : Failed to set nf_conntrack_udp_timeout_stream! \n", __FUNCTION__, __LINE__));
    }
#endif

#if defined(IVI_KERNEL_SUPPORT) || (NAT46_KERNEL_SUPPORT)
    /**
     * Firewall rules are changed to utopia firewall
     * To update the firewall rules, required the MAPT specific values, so
     * updated sysvents and restart firewall.
     * First set MAPT_CONFIG_FLAG to set, so firewall can add rules for the MAPT configuration. */
    memset(&maptInfo, 0, sizeof(maptInfo));
    snprintf(maptInfo.maptConfigFlag, sizeof(maptInfo.maptConfigFlag), "%s", SET);
    snprintf(maptInfo.ruleIpAddressString, sizeof(maptInfo.ruleIpAddressString), "%s", dhcp6cMAPTMsgBody->ruleIPv4Prefix);
    snprintf(maptInfo.ruleIpv6AddressString, sizeof(maptInfo.ruleIpv6AddressString), "%s", dhcp6cMAPTMsgBody->ruleIPv6Prefix);
    snprintf(maptInfo.brIpv6PrefixString, sizeof(maptInfo.brIpv6PrefixString), "%s", dhcp6cMAPTMsgBody->brIPv6Prefix);
    snprintf(maptInfo.ipAddressString, sizeof(maptInfo.ipAddressString), "%s", MaptConfig->ipAddressString);
    snprintf(maptInfo.ipv6AddressString, sizeof(maptInfo.ipv6AddressString), "%s", ipv6AddressString);
    maptInfo.psidValue = MaptConfig->psidValue;
    maptInfo.psidLen = MaptConfig->psidLen;
    maptInfo.ratio = dhcp6cMAPTMsgBody->ratio;
    maptInfo.psidOffset = dhcp6cMAPTMsgBody->psidOffset;
    maptInfo.eaLen = dhcp6cMAPTMsgBody->eaLen;
    maptInfo.maptAssigned = TRUE;
    maptInfo.mapeAssigned = FALSE;
    maptInfo.isFMR = dhcp6cMAPTMsgBody->isFMR;;
    maptInfo.v4Len = dhcp6cMAPTMsgBody->v4Len;

    if ((ret = maptInfo_set(&maptInfo)) != RETURN_OK)
    {
        CcspTraceError(("Failed to set sysevents for MAPT feature to set firewall rules \n"));
        return ret;
    }
#endif  // (IVI_KERNEL_SUPPORT) || (NAT46_KERNEL_SUPPORT)

    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);

#if defined(IVI_KERNEL_SUPPORT)
    snprintf(cmdEnableIpv4Traffic, sizeof(cmdEnableIpv4Traffic), "ip ro rep default dev %s", vlanIf);

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("ivictl:cmdEnableIpv4Traffic:%s", cmdEnableIpv4Traffic);
#endif
    if ((ret = WanManager_DoSystemActionWithStatus("ivictl", cmdEnableIpv4Traffic)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdEnableIpv4Traffic, ret));
        return ret;
    }
#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("### ivictl commands - ENDS  ###");
#endif
#endif //IVI_KERNEL_SUPPORT

    WanManager_DisplayMAPTFeatureStatus();

    CcspTraceNotice(("FEATURE_MAPT: MAP-T configuration done\n"));
    return RETURN_OK;
}

void WanManager_DisplayMAPTFeatureStatus(void)
{
    char isEnabled[BUFLEN_8];

    if (syscfg_get(NULL, "upnp_igd_enabled", isEnabled, sizeof(isEnabled)) == 0)
    {
        if ( '1' == isEnabled[0] )
        {
            CcspTraceInfo(("%s - MAP-T_enabled_UPnP_IGD_enabled\n", __FUNCTION__));
        }
        else
        {
            CcspTraceInfo(("%s - MAP-T_enabled_UPnP_IGD_disabled\n", __FUNCTION__));
        }
    }

    if (syscfg_get(NULL, "dmz_enabled", isEnabled, sizeof(isEnabled)) == 0)
    {
        if ( '1' == isEnabled[0] )
        {
            CcspTraceInfo(("%s - MAP-T_enabled_DMZ_enabled\n", __FUNCTION__));
        }
        else
        {
            CcspTraceInfo(("%s - MAP-T_enabled_DMZ_disabled\n", __FUNCTION__));
        }
    }

    if (syscfg_get("CosaNAT", "port_forward_enabled", isEnabled, sizeof(isEnabled)) == 0)
    {
        if ( '1' == isEnabled[0] )
        {
            CcspTraceInfo(("%s - MAP-T_enabled_Port_Forwarding_enabled\n", __FUNCTION__));
        }
        else
        {
            CcspTraceInfo(("%s - MAP-T_enabled_Port_Forwarding_disabled\n", __FUNCTION__));
        }
    }

    if (syscfg_get("CosaNAT", "port_trigger_enabled", isEnabled, sizeof(isEnabled)) == 0)
    {
        if ( '1' == isEnabled[0] )
        {
            CcspTraceInfo(("%s - MAP-T_enabled_Port_Triggering_enabled\n", __FUNCTION__));
        }
        else
        {
            CcspTraceInfo(("%s - MAP-T_enabled_Port_Triggering_disabled\n", __FUNCTION__));
        }
    }

    if (syscfg_get(NULL, "mgmt_wan_httpaccess_ert", isEnabled, sizeof(isEnabled)) == 0)
    {
        if ( '1' == isEnabled[0] )
        {
            CcspTraceInfo(("%s - MAP-T_enabled_User_Remote_Mgt_http_enabled\n", __FUNCTION__));
        }
        else
        {
            CcspTraceInfo(("%s - MAP-T_enabled_User_Remote_Mgt_http_disabled\n", __FUNCTION__));
        }
    }
    else if (syscfg_get(NULL, "mgmt_wan_httpaccess", isEnabled, sizeof(isEnabled)) == 0)
    {
        if ( '1' == isEnabled[0] )
        {
            CcspTraceInfo(("%s - MAP-T_enabled_User_Remote_Mgt_http_enabled\n", __FUNCTION__));
        }
        else
        {
            CcspTraceInfo(("%s - MAP-T_enabled_User_Remote_Mgt_http_disabled\n", __FUNCTION__));
        }
    }

    if (syscfg_get(NULL, "mgmt_wan_httpsaccess", isEnabled, sizeof(isEnabled)) == 0)
    {
        if ( '1' == isEnabled[0] )
        {
            CcspTraceInfo(("%s - MAP-T_enabled_User_Remote_Mgt_https_enabled\n", __FUNCTION__));
        }
        else
        {
            CcspTraceInfo(("%s - MAP-T_enabled_User_Remote_Mgt_https_disabled\n", __FUNCTION__));
        }
    }
}

#ifdef NAT46_KERNEL_SUPPORT
static int get_V6_defgateway_wan_interface(char *defGateway)
{
    int ret = RETURN_OK,pclose_ret = 0;
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
                    ret = RETURN_ERR;
                    return ret;
                }
                strncpy(defGateway, token, BUFLEN_128);
                CcspTraceNotice(("IPv6 Default GW address  = %s \n", defGateway));
            }
            else
            {
                CcspTraceError(("Could not parse ipv6 gw addr\n"));
                ret = RETURN_ERR;
            }
        }
        else
        {
            CcspTraceError(("Could not read ipv6 gw addr \n"));
            ret = RETURN_ERR;
        }
        pclose_ret = v_secure_pclose(fp);
	if(pclose_ret !=0)
        {
            CcspTraceError(("Failed in closing the pipe ret %d\n",pclose_ret));
        }

    }
    else
    {
        CcspTraceError(("Failed to get the default gw address \n"));
        ret = RETURN_ERR;
    }

    return ret;
}
#endif  // NAT46_KERNEL_SUPPORT

static int WanManager_CalculatePsidAndV4Index(char *pdIPv6Prefix, int v6PrefixLen, int iapdPrefixLen, int v4PrefixLen, int *psidValue, int *ipv4IndexValue, int *psidLen)
{

    int ret = RETURN_OK;
    int ipv4BitIndexLen = 0, psidBitIndexLen = 0, tempShift = 0;
    int EAlen = 0, EAStartByte = 0, EAStartByteShift = 0,  startV4Offset = 0;
    int EAStartPos = 0;
    unsigned long EAbytes = 0;
    struct in6_addr in6Addr;
    
    ipv4BitIndexLen = 32 - v4PrefixLen;
    startV4Offset  = v6PrefixLen;
    EAlen = iapdPrefixLen - startV4Offset;
    psidBitIndexLen = EAlen - ipv4BitIndexLen;

    if (iapdPrefixLen <= startV4Offset)
    {
        CcspTraceError(("Error: Invalid dhcpc6 option,iapdPrefixLen(%d) has a value which <= startV4Offset(%d) \n", iapdPrefixLen, startV4Offset));
	ret = RETURN_ERR;
	return ret;
    }

    if (inet_pton (AF_INET6, pdIPv6Prefix, &in6Addr) <= 0)
    {
        CcspTraceError(("Invalid ipv6 address=%s \n", pdIPv6Prefix));
	ret = RETURN_ERR;
	return ret;
    }

    EAStartByte = startV4Offset / 8;
    EAStartByteShift = startV4Offset % 8;

    if(EAlen <= 8)
    {
        EAbytes = (in6Addr.s6_addr[EAStartByte]) ;
        tempShift = 8;
    }
    else if(EAlen <= 16)
    {
        EAbytes = (in6Addr.s6_addr[EAStartByte] << 8) | (in6Addr.s6_addr[EAStartByte + 1]);
        tempShift = 16;
    }
    else if(EAlen <= 24)
    {
        EAbytes = (in6Addr.s6_addr[EAStartByte] << 16) | (in6Addr.s6_addr[EAStartByte + 1] << 8 ) |
              (in6Addr.s6_addr[startV4Offset / 8 + 2]);
        tempShift = 24;
    }
    else if(EAlen <= 32)
    {
        EAbytes = (in6Addr.s6_addr[EAStartByte] << 24) | (in6Addr.s6_addr[EAStartByte + 1] << 16 ) |
              (in6Addr.s6_addr[EAStartByte + 2] << 8) | (in6Addr.s6_addr[EAStartByte + 3])  ;
        tempShift = 32;
    }
    else if(EAlen <= 40)
    {
        EAbytes = ((unsigned long)(in6Addr.s6_addr[EAStartByte]) << 32) |((unsigned long)(in6Addr.s6_addr[EAStartByte + 1]) << 24) | 
              (in6Addr.s6_addr[EAStartByte + 2] << 16 ) | (in6Addr.s6_addr[EAStartByte + 3] << 8) | 
	      (in6Addr.s6_addr[EAStartByte + 4]);
        tempShift = 40;
    }
    else if(EAlen <= 48)
    {
        EAbytes = ((unsigned long)(in6Addr.s6_addr[EAStartByte]) << 40) |((unsigned long)(in6Addr.s6_addr[EAStartByte + 1]) << 32) |
              (in6Addr.s6_addr[EAStartByte + 2] << 24) | (in6Addr.s6_addr[EAStartByte + 3] << 16 ) |
              (in6Addr.s6_addr[EAStartByte + 4] << 8) | (in6Addr.s6_addr[EAStartByte + 5])  ;
        tempShift = 48;
    }

    EAStartPos = tempShift - EAStartByteShift -1;

    if(EAStartByteShift) {
        EAbytes <<= 8;
        EAbytes |= (in6Addr.s6_addr[EAStartByte + (tempShift/8)]);
	EAStartPos += 8;
    }

    *ipv4IndexValue = WanManager_GetMAPTbits(EAbytes, EAStartPos, ipv4BitIndexLen);
    *psidValue = WanManager_GetMAPTbits(EAbytes, EAStartPos - ipv4BitIndexLen, psidBitIndexLen);
    *psidLen = psidBitIndexLen;

    return ret;
}

static int WanManager_ConfigureIpv6Sysevents(char *pdIPv6Prefix, char *ipAddressString, int psidValue)
{
    int ret = RETURN_OK;
    struct in6_addr in6Addr;
    unsigned char ipAddressBytes[BUFLEN_4];
    struct in_addr result;
    unsigned int ipValue = 0;

    inet_pton(AF_INET, ipAddressString, &(result));

    ipValue = htonl(result.s_addr);

    ipAddressBytes[0] = ipValue & 0xFF;
    ipAddressBytes[1] = (ipValue >> 8) & 0xFF;
    ipAddressBytes[2] = (ipValue >> 16) & 0xFF;
    ipAddressBytes[3] = (ipValue >> 24) & 0xFF;

    if (inet_pton(AF_INET6, pdIPv6Prefix, &in6Addr) <= 0)
    {
        CcspTraceError(("Invalid ipv6 address=%s", pdIPv6Prefix));
        ret = RETURN_ERR;
        return ret;
    }

    snprintf(ipv6AddressString, sizeof(ipv6AddressString), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", in6Addr.s6_addr[0], in6Addr.s6_addr[1], in6Addr.s6_addr[2], in6Addr.s6_addr[3], in6Addr.s6_addr[4], in6Addr.s6_addr[5], in6Addr.s6_addr[6], in6Addr.s6_addr[7], 0x0, 0x0, ipAddressBytes[3], ipAddressBytes[2], ipAddressBytes[1], ipAddressBytes[0], ((psidValue >> 8) & 0xFF ), (psidValue & 0xFF));

    return ret;
}

int WanManager_ResetMAPTConfiguration(const char *baseIf, const char *vlanIf)
{
    char cmdConfigureMTUSize[BUFLEN_64] = "";
    int ret = RETURN_OK;

    /* RM16042: Since we have configures MTU size to 1520 for the MAPT functionality,
     * we need to reconfigure it back to 1500 when we reset from MAPT configuration.
     * Reconfigure eth3 mtu size to 1500. */
    snprintf(cmdConfigureMTUSize, sizeof(cmdConfigureMTUSize), "ip link set dev %s mtu %d ", baseIf, MTU_DEFAULT_SIZE);

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("ivictl:cmdConfigureMTUSize:%s", cmdConfigureMTUSize);
#endif

    if ((ret = WanManager_DoSystemActionWithStatus("mapt", cmdConfigureMTUSize)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdConfigureMTUSize, ret));
        return ret;
    }

    /*  ReConfigure erouter0 MTU size to 1500 */
    snprintf(cmdConfigureMTUSize, sizeof(cmdConfigureMTUSize), "ip link set dev %s mtu %d ", vlanIf, MTU_DEFAULT_SIZE);

#ifdef FEATURE_MAPT_DEBUG
    MaptInfo("ivictl:cmdConfigureMTUSize:%s", cmdConfigureMTUSize);
#endif

    if ((ret = WanManager_DoSystemActionWithStatus("mapt", cmdConfigureMTUSize)) < RETURN_OK)
    {
        CcspTraceError(("Failed to run: %s:%d", cmdConfigureMTUSize, ret));
        return ret;
    }

    /* Reset MAPT configuration.
     * All the firewall rules should remove once this called.
     * To do this we have reset the value for sysevent field
     * `mapt_configure_flag` and restart the firewall. */
    //Reset MAP sysevent parameters
    maptInfo_reset();

    /* Starting UPnP, if we have stopped it  while configuring MAPT */
    WanMgr_RdkBus_ConfigureUPnPIGDService(true);

    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
    CcspTraceNotice(("FEATURE_MAPT: MAP-T configuration cleared\n"));
    return RETURN_OK;
}

#ifdef FEATURE_MAPT_DEBUG
void WanManager_UpdateMaptLogFile(ipc_mapt_data_t *dhcp6cMAPTMsgBody)
{

    MaptInfo("--- MAP-T Options Received from DHCPv6 - START ---");
    MaptInfo("ruleIPv6Prefix:%s", dhcp6cMAPTMsgBody->ruleIPv6Prefix);
    MaptInfo("ruleIPv4Prefix:%s", dhcp6cMAPTMsgBody->ruleIPv4Prefix);
    MaptInfo("brIPv6Prefix:%s", dhcp6cMAPTMsgBody->brIPv6Prefix);
    MaptInfo("pdIPv6Prefix:%s", dhcp6cMAPTMsgBody->pdIPv6Prefix);
    MaptInfo("iapdPrefixLen:%d", dhcp6cMAPTMsgBody->iapdPrefixLen);
    MaptInfo("psidOffset:%d", dhcp6cMAPTMsgBody->psidOffset);
    MaptInfo("psidLen:%d", dhcp6cMAPTMsgBody->psidLen);
    MaptInfo("psid:%d", dhcp6cMAPTMsgBody->psid);
    MaptInfo("ratio:%d", dhcp6cMAPTMsgBody->ratio);
    MaptInfo("v4Len:%d", dhcp6cMAPTMsgBody->v4Len);
    MaptInfo("v6Len:%d", dhcp6cMAPTMsgBody->v6Len);
    MaptInfo("eaLen:%d", dhcp6cMAPTMsgBody->eaLen);
    MaptInfo("--- MAP-T Options Received from DHCPv6 - END ---");

    CcspTraceInfo(("SKYWANMGR:MAP-T_OPTIONS:%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d",
                 dhcp6cMAPTMsgBody->ruleIPv6Prefix,
                 dhcp6cMAPTMsgBody->ruleIPv4Prefix,
                 dhcp6cMAPTMsgBody->brIPv6Prefix,
                 dhcp6cMAPTMsgBody->pdIPv6Prefix,
                 dhcp6cMAPTMsgBody->iapdPrefixLen,
                 dhcp6cMAPTMsgBody->psidOffset,
                 dhcp6cMAPTMsgBody->psidLen,
                 dhcp6cMAPTMsgBody->psid,
                 dhcp6cMAPTMsgBody->ratio,
                 dhcp6cMAPTMsgBody->v4Len,
                 dhcp6cMAPTMsgBody->v6Len,
                 dhcp6cMAPTMsgBody->eaLen));
}
#endif /* FEATURE_MAPT_DEBUG */

#endif /* FEATURE_MAPT */

int IsValidDnsServer(int32_t af, const char *nameServer)
{
    if ((nameServer == NULL) || (nameServer[0] == '\0'))
    {
        CcspTraceError(("%s %d - invalid argument \n",__FUNCTION__,__LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if(af == AF_INET)
    {
        if(!(IsValidIpAddress(af, nameServer)))
        {
            CcspTraceError(("%s %d - invalid nameserver: %s \n",__FUNCTION__,__LINE__, nameServer));
            return RETURN_ERR;
        }
        if(IsZeroIpvxAddress(AF_SELECT_IPV4,nameServer))
        {
            CcspTraceError(("%s %d - invalid nameserver: %s \n",__FUNCTION__,__LINE__, nameServer));
            return RETURN_ERR;
        }
        if(!(strncmp(BROADCAST_IP, nameServer, strlen(BROADCAST_IP))))
        {
            CcspTraceError(("%s %d - invalid nameserver: %s \n",__FUNCTION__,__LINE__, nameServer));
            return RETURN_ERR;
        }
        if(!(strncmp(LINKLOCAL_RANGE, nameServer, strlen(LINKLOCAL_RANGE))))
        {
            CcspTraceError(("%s %d - invalid nameserver: %s \n",__FUNCTION__,__LINE__, nameServer));
            return RETURN_ERR;
        }
        if(!(strncmp(LOOPBACK_RANGE, nameServer, strlen(LOOPBACK_RANGE))))
        {
            CcspTraceError(("%s %d - invalid nameserver: %s \n",__FUNCTION__,__LINE__, nameServer));
            return RETURN_ERR;
        }
    }
    else
    {
        if(!(IsValidIpAddress(af, nameServer)))
        {
            CcspTraceError(("%s %d - invalid nameserver: %s \n",__FUNCTION__,__LINE__, nameServer));
            return RETURN_ERR;
        }
        if(IsZeroIpvxAddress(AF_SELECT_IPV6, nameServer))
        {
            CcspTraceError(("%s %d - invalid nameserver: %s \n",__FUNCTION__,__LINE__, nameServer));
            return RETURN_ERR;
        }
    }
    return RETURN_OK;
}


int WanManager_GetBCastFromIpSubnetMask(const char* inIpStr, const char* inSubnetMaskStr, char *outBcastStr)
{
   struct in_addr ip;
   struct in_addr subnetMask;
   struct in_addr bCast;
   int ret = RETURN_OK;

   if (inIpStr == NULL || inSubnetMaskStr == NULL || outBcastStr == NULL)
   {
      return RETURN_ERR;
   }

   ip.s_addr = inet_addr(inIpStr);
   subnetMask.s_addr = inet_addr(inSubnetMaskStr);
   bCast.s_addr = ip.s_addr | ~subnetMask.s_addr;
   strncpy(outBcastStr, inet_ntoa(bCast),strlen(inet_ntoa(bCast))+1);

   return ret;
}

int WanManager_DelDefaultGatewayRoute(DEVICE_NETWORKING_MODE DeviceNwMode, BOOL DeviceNwModeChange, const WANMGR_IPV4_DATA* pIpv4Info)
{
    char cmd[BUFLEN_128]={0};
    int ret = RETURN_OK;
    DEVICE_NETWORKING_MODE ModeConfigToDelete;


    if (DeviceNwModeChange == TRUE)
    {
        if (DeviceNwMode == GATEWAY_MODE)
        {
            // DeviceNwMode changed from MODEM_MODE to GATEWAY_MODE
            CcspTraceInfo(("%s %d: DeviceNwMode changed from MODEM_MODE->GATEWAY_MODE. So deleting MODEM_MODE def routes\n", __FUNCTION__, __LINE__));
            ModeConfigToDelete = MODEM_MODE;
        }
        else
        {
            // DeviceNwMode changed from GATEWAY_MODE to MODEM_MODE
            CcspTraceInfo(("%s %d: DeviceNwMode changed from GATEWAY_MODE->MODEM_MODE. So deleting GATEWAY_MODE def route\n", __FUNCTION__, __LINE__));
            ModeConfigToDelete = GATEWAY_MODE;
        }
    }
    else
    {
        // No change is DeviceNwMode, so delete config for current DeviceNwMode
        ModeConfigToDelete =  DeviceNwMode;
    }


    if (ModeConfigToDelete == GATEWAY_MODE)
    {
        /* delete default gateway first before add  */
        snprintf(cmd, sizeof(cmd), "route del default 2>/dev/null");
        WanManager_DoSystemAction("SetUpDefaultSystemGateway:", cmd);
    }
    else
    {
        snprintf(cmd, sizeof(cmd), "ip rule flush table %s", MODEM_TABLE_NAME);
        WanManager_DoSystemAction("SetUpDefaultSystemGateway:", cmd);

        memset (cmd, 0 , sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "ip ro flush table %s", MODEM_TABLE_NAME);
        WanManager_DoSystemAction("SetUpDefaultSystemGateway:", cmd);

        WanManager_DoSystemAction("SetUpDefaultSystemGateway:", "ip route flush cache");
    }

    return ret;
}

int WanManager_AddDefaultGatewayRoute(DEVICE_NETWORKING_MODE DeviceNwMode, const WANMGR_IPV4_DATA* pIpv4Info)
{
    char cmd[BUFLEN_128]={0};
    int ret = RETURN_OK;

    if (DeviceNwMode == GATEWAY_MODE)
    {
        CcspTraceInfo(("%s %d: Device in Gateway Mode. So configure default route in main routing table\n", __FUNCTION__, __LINE__));
        /* Sets default gateway route entry */
        /* For IPoE, always use gw IP address. */
        if (IsValidIpv4Address(pIpv4Info->gateway) && !(IsZeroIpvxAddress(AF_SELECT_IPV4, pIpv4Info->gateway)))
        {
            snprintf(cmd, sizeof(cmd), "route add default gw %s dev %s", pIpv4Info->gateway, pIpv4Info->ifname);
            WanManager_DoSystemAction("SetUpDefaultSystemGateway:", cmd);
            CcspTraceInfo(("%s %d - The default gateway route entries set!, cmd(%s)\n",__FUNCTION__,__LINE__, cmd));
        }
    }
    else if (DeviceNwMode == MODEM_MODE)   
    {
        CcspTraceInfo(("%s %d: Device in MODEM Mode. So configure default route in user defined MODEM routing table\n", __FUNCTION__, __LINE__));

        // add rule for packets from brWan to lookup MODEM table
        memset (cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "ip rule add iif %s table %s", WAN_BRIDGE, MODEM_TABLE_NAME);
        WanManager_DoSystemAction("SetUpDefaultSystemGateway:", cmd);

        // add route to extender gateway via extender wan interface
        memset (cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "ip route add default via %s dev %s table MODEM", pIpv4Info->gateway, pIpv4Info->ifname, WAN_BRIDGE, MODEM_TABLE_NAME);
        WanManager_DoSystemAction("SetUpDefaultSystemGateway:", cmd);

        // put the previous rule/route to action
        WanManager_DoSystemAction("SetUpDefaultSystemGateway:", "ip route flush cache");

    }

    return ret;
}

static BOOL IsValidIpv4Address(const char* ipAddress)
{
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ipAddress, &(sa.sin_addr)) != 1)
   {
      return FALSE;
   }
    if (strcmp(ipAddress, "0.0.0.0") == 0)
   {
        return FALSE;
   }
    return TRUE;

}


static BOOL IsZeroIpvxAddress(uint32_t ipvx, const char *addr)
{
   if (IS_EMPTY_STR(addr))
   {
      return TRUE;
   }

   /*
    * Technically, the ::/0 is not an all zero address, but it is used by our
    * routing code to specify the default route.  See Wikipedia IPv6_address
    */
   if (((ipvx & AF_SELECT_IPV4) && !strcmp(addr, "0.0.0.0")) ||
       ((ipvx & AF_SELECT_IPV6) &&
           (!strcmp(addr, "0:0:0:0:0:0:0:0") ||
            !strcmp(addr, "::") ||
            !strcmp(addr, "::/128") ||
            !strcmp(addr, "::/0")))  )
   {
      return TRUE;
   }

   return FALSE;
}

BOOL IsValidIpAddress(int32_t af, const char* address)
{
   if ( IS_EMPTY_STRING(address) ) return FALSE;
   if (af == AF_INET6)
   {
      struct in6_addr in6Addr;
      uint32_t plen;
      char   addr[IP_ADDR_LENGTH];

      if (ParsePrefixAddress(address, addr, &plen) != ANSC_STATUS_SUCCESS)
      {
         CcspTraceInfo(("Invalid ipv6 address=%s", address));
         return FALSE;
      }

      if (inet_pton(AF_INET6, addr, &in6Addr) <= 0)
      {
         CcspTraceInfo(("Invalid ipv6 address=%s", address));
         return FALSE;
      }

      return TRUE;
   }
   else
   {
      if (af == AF_INET)
      {
         return IsValidIpv4Address(address);
      }
      else
      {
         return FALSE;
      }
   }
}

static int ParsePrefixAddress(const char *prefixAddr, char *address, uint32_t *plen)
{
   int ret = RETURN_OK;
   char *tmpBuf;
   char *separator;
   uint32_t len;

   if (prefixAddr == NULL || address == NULL || plen == NULL)
   {
      return RETURN_ERR;
   }

   *address = '\0';
   *plen    = 128;

   len = strlen(prefixAddr);

   if ((tmpBuf = malloc(len+1)) == NULL)
   {
      CcspTraceError(("%s %d - alloc of %d bytes failed",__FUNCTION__,__LINE__, len));
      ret = RETURN_ERR;
   }
   else
   {
      memcpy(tmpBuf, prefixAddr, len + 1);
      separator = strchr(tmpBuf, '/');
      if (separator != NULL)
      {
         /* break the string into two strings */
         *separator = 0;
         separator++;
         while ((isspace(*separator)) && (*separator != 0))
         {
            /* skip white space after comma */
            separator++;
         }

         *plen = atoi(separator);
      }

      if (strlen(tmpBuf) < BUFLEN_40 && *plen <= 128)
      {
         strncpy(address, tmpBuf, strlen(tmpBuf) + 1);
      }
      else
      {
         ret = RETURN_ERR;
      }
      free(tmpBuf);
   }

   return ret;

}

static ANSC_STATUS getIfAddr6(const char *ifname , uint32_t addrIdx,
                      char *ipAddr, uint32_t *ifIndex, uint32_t *prefixLen, uint32_t *scope, uint32_t *ifaFlags)
{
    int   ret = ANSC_STATUS_FAILURE;
    FILE     *fp;
    uint32_t   count = 0;
    char     line[BUFLEN_64];

    *ipAddr = '\0';

    if ((fp = fopen("/proc/net/if_inet6", "r")) == NULL)
    {
        CcspTraceInfo(("failed to open /proc/net/if_inet6"));
        return ANSC_STATUS_FAILURE;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        /* remove the carriage return char */
        line[strlen(line)-1] = '\0';

        if (strstr(line, ifname) != NULL)
        {
            char *addr, *ifidx, *plen, *scp, *flags, *devname;
            char *nextToken = NULL;

            /* the first token in the line is the ip address */
            addr = strtok_r(line, " ", &nextToken);

            /* the second token is the Netlink device number (interface index) in hexadecimal */
            ifidx = strtok_r(NULL, " ", &nextToken);
            if (ifidx == NULL)
            {
                CcspTraceInfo(("Invalid /proc/net/if_inet6 line"));
                ret = ANSC_STATUS_FAILURE;
                break;
            }

            /* the third token is the Prefix length in hexadecimal */
            plen = strtok_r(NULL, " ", &nextToken);
            if (plen == NULL)
            {
                CcspTraceInfo(("Invalid /proc/net/if_inet6 line"));
                ret = ANSC_STATUS_FAILURE;
                break;
            }

            /* the forth token is the Scope value */
            scp = strtok_r(NULL, " ", &nextToken);
            if (scp == NULL)
            {
                CcspTraceInfo(("Invalid /proc/net/if_inet6 line"));
                ret = ANSC_STATUS_FAILURE;
                break;
            }

            /* the fifth token is the ifa flags */
            flags = strtok_r(NULL, " ", &nextToken);
            if (flags == NULL)
            {
                CcspTraceInfo(("Invalid /proc/net/if_inet6 line"));
                ret = ANSC_STATUS_FAILURE;
                break;
            }

            /* the sixth token is the device name */
            devname = strtok_r(NULL, " ", &nextToken);
            if (devname == NULL)
            {
                CcspTraceInfo(("Invalid /proc/net/if_inet6 line"));
                ret = ANSC_STATUS_FAILURE;
                break;
            }
            else
            {
                if (strcmp(devname, ifname) != 0)
                {
                    continue;
                }
                else if (count == addrIdx)
                {
                    int32_t   i;
                    char     *p1, *p2;

                    *ifIndex   = strtoul(ifidx, NULL, 16);
                    *prefixLen = strtoul(plen, NULL, 16);
                    *scope     = strtoul(scp, NULL, 16);
                    *ifaFlags  = strtoul(flags, NULL, 16);

                    /* insert a colon every 4 digits in the address string */
                    p2 = ipAddr;
                    for (i = 0, p1 = addr; *p1 != '\0'; i++)
                    {
                        if (i == 4)
                        {
                            i = 0;
                            *p2++ = ':';
                        }
                        *p2++ = *p1++;
                    }
                    *p2 = '\0';

                    ret = ANSC_STATUS_SUCCESS;
                    break;   /* done */
                }
                else
                {
                    count++;
                }
            }
        }
    }  /* while */

    fclose(fp);

    return ret;

}  /* End of getIfAddr6() */

ANSC_STATUS WanManager_getGloballyUniqueIfAddr6(const char *ifname, char *ipAddr, uint32_t *prefixLen)
{
   uint32_t addrIdx=0;
   uint32_t netlinkIndex=0;
   uint32_t scope=0;
   uint32_t ifaflags=0;
   int ret= ANSC_STATUS_SUCCESS;

   while (ANSC_STATUS_SUCCESS == ret)
   {
      ret = getIfAddr6(ifname, addrIdx, ipAddr, &netlinkIndex,
                              prefixLen, &scope, &ifaflags);
      if ((ANSC_STATUS_SUCCESS == ret) && (0 == scope))  // found it
         return ANSC_STATUS_SUCCESS;

      addrIdx++;
   }

   return ANSC_STATUS_FAILURE;
}


#ifdef FEATURE_802_1P_COS_MARKING
void Marking_UpdateInitValue(ANSC_HANDLE hInsContext, ULONG ulIfInstanceNumber, ULONG nIndex,DML_MARKING* pmark)
{
    PSINGLE_LINK_ENTRY  pSListEntry = NULL;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(ulIfInstanceNumber);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            pSListEntry       = AnscSListGetEntryByIndex(&(pWanDmlIface->Marking.MarkingList), nIndex);
            if ( pSListEntry )
            {
                CONTEXT_MARKING_LINK_OBJECT* pCxtLink      = ACCESS_CONTEXT_MARKING_LINK_OBJECT(pSListEntry);
                DML_MARKING*                    p_Marking  = pCxtLink->hContext;
                pCxtLink->bNew  = FALSE;
                /*Copy values from pmark to p_Marking */
                strcpy(p_Marking->Alias,pmark->Alias);
                p_Marking->SKBPort = pmark->SKBPort;
                p_Marking->SKBMark = pmark->SKBMark;
                p_Marking->InstanceNumber = pmark->InstanceNumber;
                p_Marking->EthernetPriorityMark = pmark->EthernetPriorityMark;
                CcspTraceInfo(("%s %d - copied to dml [%s,%u,%u,%d]\n",__FUNCTION__,__LINE__,p_Marking->Alias,p_Marking->SKBPort,p_Marking->SKBMark,p_Marking->EthernetPriorityMark));
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
}

ANSC_HANDLE WanManager_AddIfaceMarking(DML_WAN_IFACE* pWanDmlIface, ULONG* pInsNumber)
{
    DATAMODEL_MARKING*              pDmlMarking     = (DATAMODEL_MARKING*) &(pWanDmlIface->Marking);
    DML_MARKING*                    p_Marking       = NULL;
    CONTEXT_MARKING_LINK_OBJECT*    pMarkingCxtLink = NULL;

    //Verify limit of the marking table
    if( WAN_IF_MARKING_MAX_LIMIT < pDmlMarking->ulNextInstanceNumber )
    {
        CcspTraceError(("%s %d - Failed to add Marking entry due to maximum limit(%d)\n",__FUNCTION__,__LINE__,WAN_IF_MARKING_MAX_LIMIT));
        return NULL;
    }

    p_Marking       = (DML_MARKING*)AnscAllocateMemory(sizeof(DML_MARKING));
    pMarkingCxtLink = (CONTEXT_MARKING_LINK_OBJECT*)AnscAllocateMemory(sizeof(CONTEXT_MARKING_LINK_OBJECT));
    if((p_Marking == NULL) || (pMarkingCxtLink == NULL))
    {
        if( NULL != pMarkingCxtLink )
        {
          AnscFreeMemory(pMarkingCxtLink);
          pMarkingCxtLink = NULL;
        }

        if( NULL != p_Marking )
        {
          AnscFreeMemory(p_Marking);
          p_Marking = NULL;
        }
        return NULL;
    }


    /* now we have this link content */
    pMarkingCxtLink->hContext = (ANSC_HANDLE)p_Marking;
    pMarkingCxtLink->bNew     = TRUE;

    pMarkingCxtLink->InstanceNumber  = pDmlMarking->ulNextInstanceNumber;
    *pInsNumber                      = pDmlMarking->ulNextInstanceNumber;

    //Assign actual instance number
    p_Marking->InstanceNumber = pDmlMarking->ulNextInstanceNumber;

    pDmlMarking->ulNextInstanceNumber++;

    //Assign WAN interface instance for reference
    p_Marking->ulWANIfInstanceNumber = pWanDmlIface->uiInstanceNumber;

    //Initialise all marking members
    memset( p_Marking->Alias, 0, sizeof( p_Marking->Alias ) );
    p_Marking->SKBPort = 0;
    p_Marking->SKBMark = 0;
    p_Marking->EthernetPriorityMark = -1;

    SListPushMarkingEntryByInsNum(&pDmlMarking->MarkingList, (PCONTEXT_LINK_OBJECT)pMarkingCxtLink);

    return (ANSC_HANDLE)pMarkingCxtLink;
}


#endif /* * FEATURE_802_1P_COS_MARKING */

int WanManager_AddGatewayRoute(const WANMGR_IPV4_DATA* pIpv4Info)
{
    char cmd[BUFLEN_128]={0};
    int ret = RETURN_OK;
    FILE *fp = NULL;
    
    /* delete gateway first before add  */
    snprintf(cmd, sizeof(cmd), "route del %s dev %s", pIpv4Info->gateway, pIpv4Info->ifname);
    WanManager_DoSystemAction("SetUpSystemGateway:", cmd);

    /* Sets gateway route entry */
    if (IsValidIpv4Address(pIpv4Info->gateway) && !(IsZeroIpvxAddress(AF_SELECT_IPV4, pIpv4Info->gateway)))
    {
        snprintf(cmd, sizeof(cmd), "ip route add %s dev %s", pIpv4Info->gateway, pIpv4Info->ifname);
        WanManager_DoSystemAction("SetUpSystemGateway:", cmd);
        CcspTraceInfo(("%s %d - The gateway route entries set!\n",__FUNCTION__,__LINE__));
    }

    return ret;
}

ANSC_STATUS WanManager_CheckGivenPriorityExists(INT IfIndex, UINT uiTotalIfaces, INT priority, BOOL *Status)
{
    ANSC_STATUS             retStatus    = ANSC_STATUS_SUCCESS;
    INT                     uiLoopCount   = 0;
    INT                     wan_if_count = 0;

    *Status = FALSE;
    if ( uiTotalIfaces <= 0 )
    {
        CcspTraceError(("%s Invalid Parameter\n", __FUNCTION__ ));
        return ANSC_STATUS_FAILURE;
    }

    for( uiLoopCount = 0; uiLoopCount < uiTotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if( uiLoopCount == IfIndex )
            {
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                continue;
            }
            if(pWanIfaceData->Selection.Priority == priority)
            {
                *Status = TRUE;
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                return retStatus;
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return retStatus;
}

ANSC_STATUS WanManager_CheckGivenTypeExists(INT IfIndex, UINT uiTotalIfaces, DML_WAN_IFACE_TYPE priorityType, INT priority, BOOL *Status)
{
    ANSC_STATUS             retStatus    = ANSC_STATUS_SUCCESS;
    INT                     uiLoopCount   = 0;
    INT                     wan_if_count = 0;

    if ( uiTotalIfaces <= 0 )
    {
        CcspTraceError(("%s Invalid Parameter\n", __FUNCTION__ ));
        return ANSC_STATUS_FAILURE;
    }

    for( uiLoopCount = 0; uiLoopCount < uiTotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if( uiLoopCount == IfIndex )
            {
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                continue;
            }
            if(pWanIfaceData->Type == priorityType)
            {
                if ( pWanIfaceData->Selection.Priority == priority)
                {
                    *Status = TRUE;
                    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                    return retStatus;
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return retStatus;
}

static INT IsIPObtained(char *pInterfaceName)
{
    char buff[256] = {0};
    FILE *fp = NULL;
    int pclose_ret = 0;
    if (!pInterfaceName)
    {
        return 0;
    }

    /* Validate IPv4 Connection on WAN interface */
    memset(buff,0,sizeof(buff));

    /* Open the command for reading. */
    fp = v_secure_popen("r","ip addr show %s |grep -i 'inet ' |awk '{print $2}' |cut -f2 -d:", pInterfaceName);
    if (fp == NULL)
    {
        CcspTraceError(("%s-%d : Error popen\n", __FUNCTION__, __LINE__));
    }
    else
    {
        /* Read the output a line at a time - output it. */
        if (fgets(buff, 50, fp) != NULL)
        {
            CcspTraceInfo(("%s-%d : assigned IP(%s), On Interface(%s) \n", __FUNCTION__, __LINE__, buff, pInterfaceName));
        }
        /* close */
        pclose_ret = v_secure_pclose(fp);
	if(pclose_ret !=0)
        {
            CcspTraceError(("Failed in closing the pipe ret %d\n",pclose_ret));
        }

        if(buff[0] != 0)
        {
            CcspTraceInfo(("%s %d - IP obtained %s\n", __FUNCTION__, __LINE__,pInterfaceName));
            return 1;
        }
    }

    /* Validate IPv6 Connection on WAN interface */
    
   
    memset(buff,0,sizeof(buff));

    /* Open the command for reading. */
    fp = v_secure_popen("r","ip addr show %s |grep -i 'inet6 ' |grep -i 'Global' |awk '{print $2}'", pInterfaceName);
    if (fp == NULL)
    {
        CcspTraceError(("%s-%d : Error popen\n", __FUNCTION__, __LINE__));
    }
    else
    {
        /* Read the output a line at a time - output it. */
        if (fgets(buff, 50, fp) != NULL)
        {
            CcspTraceInfo(("%s-%d : assigned IP(%s), On Interface(%s) \n", __FUNCTION__, __LINE__, buff, pInterfaceName));
        }
        /* close */
        pclose_ret = v_secure_pclose(fp);
	if(pclose_ret !=0)
        {
            CcspTraceError(("Failed in closing the pipe ret %d\n",pclose_ret));
        }

        if(buff[0] != 0)
        {
            CcspTraceInfo(("%s %d - IP obtained %s \n", __FUNCTION__, __LINE__,pInterfaceName));
            return 2;
        }
    }
    return 0;
}


void* ThreadWanMgr_MonitorAndUpdateIpStatus( void *arg )
{
    UINT counter = 0;
    UINT  *puIndex = NULL;
    INT ipstatus = 0;
    DML_WAN_IFACE* pFixedInterface = NULL;

    pthread_detach(pthread_self());

    if ( NULL == arg )
    {
       CcspTraceError(("%s %d Invalid buffer\n", __FUNCTION__,__LINE__));
       //Cleanup current thread when exit
       pthread_exit(NULL);
    }
    puIndex = (UINT*)arg;
    CcspTraceInfo(("%s %d index %d\n", __FUNCTION__,__LINE__,*puIndex));
    while(1)
    {
       WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(*puIndex);
        if (!pWanDmlIfaceData)
        {
            break;
        }
        pFixedInterface = &pWanDmlIfaceData->data;
        if (!pFixedInterface)
        {
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            break;
        }
        ipstatus = IsIPObtained(pFixedInterface->VirtIfList->Name);
        if (ipstatus != 0)
        {
            if (ipstatus == 1)
            {
                pFixedInterface->VirtIfList->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_UP;
            }
            if (ipstatus == 2)
            {
                pFixedInterface->VirtIfList->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_UP;
            }
            CcspTraceInfo(("%s-%d : IP Monitor Successful, Interface(%s) \n", __FUNCTION__, __LINE__, pFixedInterface->VirtIfList->Name));
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            break;
        }
        if (counter >= IPMONITOR_WAIT_MAX_TIMEOUT)
        {
            pFixedInterface->VirtIfList->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_DOWN;
            pFixedInterface->VirtIfList->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_DOWN;
            CcspTraceWarning(("%s-%d : IP Monitor timer expire, Interface(%s) \n", __FUNCTION__, __LINE__, pFixedInterface->VirtIfList->Name));
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            break;
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        sleep(IPMONITOR_QUERY_INTERVAL);
        counter += IPMONITOR_QUERY_INTERVAL;
    }
    free(puIndex);
    return arg;
}

INT WanMgr_StartIpMonitor(UINT iface_index)
{
    INT  iErrorCode     = 0;
    pthread_t ipMonitorThreadId;

    UINT *pIndex = malloc(sizeof(UINT));
    if (pIndex)
    {
        *pIndex = iface_index;
        iErrorCode = pthread_create( &ipMonitorThreadId, NULL, &ThreadWanMgr_MonitorAndUpdateIpStatus, (void*)pIndex );
    }
    return iErrorCode;
}
#ifdef MAPT_NAT46_FTP_ACTIVE_MODE
void WanManager_CalculateMAPTPortRange(int offset, int psidLen, int psid, char* port_range)
{
    int a = 0, m = 0, contigous_port = 0, ratio = 0;
    int index = 0, len = 0;
    int initialPortValue = 0, finalPortValue = 0;
    char single_port_range[BUFLEN_32]={0};

    if (offset == 0)
        offset = 6;

    a = (1 << offset);
    m = 16 - (psidLen + offset);
    contigous_port = (1 << m);
    ratio = 16 - offset;

    for(index=1; index < (a); index++)
    {
        initialPortValue = (index<<ratio) + (psid <<(m));
        finalPortValue   = initialPortValue + (contigous_port - 1);
        snprintf(single_port_range, BUFLEN_32, "%d,%d,", initialPortValue, finalPortValue);
        strncat(port_range, single_port_range, BUFLEN_32);
        memset(single_port_range, 0, BUFLEN_32);
    }
    len = strlen(port_range);
    port_range[len - 1] = '\0';
}
#endif

bool IsDefaultRoutePresent(char *IfaceName, bool IsV4)
{
    int pclose_ret = 0;
    bool ret = false;
    char line[BUFLEN_1024] = {0};
    FILE *fp;

    if ((strlen(IfaceName) <=0 ) || (IfaceName[0] == '\0'))
    {
        CcspTraceError(("%s-%d : Interface Name is Null\n", __FUNCTION__, __LINE__));
        return false;
    }

    if (IsV4)
    {
        fp = v_secure_popen("r","ip -4 route show default | grep default | awk '{print $5}'");
    }
    else
    {
        fp = v_secure_popen("r","ip -6 route show default | grep default | awk '{print $5}'");
    }
    if (fp)
    {
        if (fgets(line, sizeof(line), fp) != NULL)
        {
            char *token = strtok(line, "\n");
            if (token)
            {
                CcspTraceError(("%s-%d : Default Route Iface Name(%s)/Expected Iface Name(%s) \n", __FUNCTION__, __LINE__, token, IfaceName));
                if ((strcmp(IfaceName, token) == 0))
                {
                    CcspTraceInfo(("%s-%d : Default %s Route found for Interface(%s) \n", __FUNCTION__, __LINE__, (IsV4? "IPv4":"IPv6"), IfaceName));
                    ret = true;
                }
            }
            else
            {
                CcspTraceError(("%s-%d : Failed to Parse Route, Expected Iface Name(%s) \n", __FUNCTION__, __LINE__, IfaceName));
                ret = false;
            }
        }
        else
        {
            CcspTraceError(("%s-%d : Could not read default route \n", __FUNCTION__, __LINE__));
            ret = false;
        }
        pclose_ret = v_secure_pclose(fp);
        if(pclose_ret !=0)
        {
            CcspTraceError(("%s-%d : Failed in closing the pipe ret %d \n", __FUNCTION__, __LINE__, pclose_ret));
        }
    }
    else
    {
        CcspTraceError(("%s-%d : Failed to get the default route \n", __FUNCTION__, __LINE__));
        ret = false;
    }

    return ret;
}

bool WanManager_IsNetworkInterfaceAvailable( char *IfaceName ) 
{
    int skfd = -1;
    struct ifreq ifr = {0};

    if( NULL == IfaceName )
    {
       return FALSE;
    }
  
    AnscCopyString(ifr.ifr_name, IfaceName);
    
    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd == -1)
       return FALSE;
   
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        if (errno == ENODEV) {
            close(skfd); 
            return FALSE;
        }
    }

    close(skfd);
    return TRUE;
}

bool WanManager_IsNetworkInterfaceUp( char *IfaceName ) 
{
    int skfd = -1;
    struct ifreq ifr = {0};

    if( NULL == IfaceName )
    {
       return FALSE;
    }
  
    AnscCopyString(ifr.ifr_name, IfaceName);
    
    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd == -1)
       return FALSE;
   
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        if (errno == ENODEV) {
            close(skfd); 
            return FALSE;
        }
    }

    close(skfd);

    // Check both IFF_UP and IFF_RUNNING
    if ((ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING)) {
        return TRUE; // Interface is up and running
    }

    return FALSE;
}

int WanMgr_RdkBus_AddIntfToLanBridge (char * PhyPath, BOOL AddToBridge)
{
    if (PhyPath == NULL)
    {
        CcspTraceError(("%s %d: Invalid args...\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (strstr(PhyPath, "Ethernet") == NULL)
    {
        CcspTraceInfo(("%s %d: Interface is not Ethernet based, so LAN Bridge operation required\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_SUCCESS;
    }

    int retry_count = SET_MAX_RETRY_COUNT;
    char param_name[BUFLEN_256] = {0};
    char param_value[BUFLEN_256] = {0};
    parameterValStruct_t varStruct[1] = {0};

    strncpy(param_name, PhyPath, sizeof(param_name)-1);
    strncat(param_name, ETH_ADDTOLANBRIDGE_DM_SUFFIX, sizeof(param_name) - strlen(param_name));
    if (AddToBridge)
    {
        strncpy(param_value, "true", sizeof(param_value));
    }
    else
    {
        strncpy(param_value, "false", sizeof(param_value));
    }

    while (retry_count--)
    {
        if (WanMgr_RdkBus_SetParamValues(ETH_COMPONENT_NAME, ETH_COMPONENT_PATH, param_name, param_value, ccsp_boolean, TRUE ) == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s %d: Succesfully set %s = %s\n", __FUNCTION__, __LINE__, param_name, param_value));
            return ANSC_STATUS_SUCCESS;
        }
        usleep(500000);
    }

    CcspTraceError(("%s %d: unable to set %s as %s\n", __FUNCTION__, __LINE__, param_name, param_value));
    return ANSC_STATUS_FAILURE;

}

ANSC_STATUS WanManager_get_interface_mac(char *interfaceName, char* macAddress, int macAddressSize)
{
   FILE *fp = NULL;
   char *ptr = NULL;
   char cmd[BUFLEN_128] = {0};
   ANSC_STATUS  returnStatus = ANSC_STATUS_FAILURE;
   char fOutput[BUFLEN_128] = {0};

   CcspTraceInfo(("%s %d: interfaceName = [%s]\n", __FUNCTION__, __LINE__, interfaceName));
   if(interfaceName == NULL || interfaceName[0] == '\0')
   {
       return returnStatus;
   }

   snprintf(cmd, sizeof(cmd), "/sys/class/net/%s/address" ,interfaceName);

   fp = fopen(cmd, "r");
   if(NULL != fp)
   {
      fgets(fOutput, sizeof(fOutput), fp);
      fclose(fp);

      if((fOutput[0] != '\0') && (strlen(fOutput) != 0))
      {
          /* Remove \n char from the buffer */
          if ((ptr = strchr(fOutput, '\n')))
          {
              *ptr = 0;
          }

          if(strlen(fOutput) != 0)
          {
              snprintf(macAddress, macAddressSize, "%s", fOutput);
              CcspTraceInfo(("%s %d: [%s] Interface MAC Address = [%s]\n", __FUNCTION__, __LINE__, interfaceName, macAddress));
              returnStatus = ANSC_STATUS_SUCCESS;
          }
      }
   }

   return returnStatus;
}

//Send and receive RS
int  WanManager_send_and_receive_rs(DML_VIRTUAL_IFACE * p_VirtIf) 
{
    struct in6_addr addr;
    int ret = -1;
    char command[256];
    char buffer[512];
    FILE *fp;

    CcspTraceInfo(("%s %d: Requesting Router solicit for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
    // Prepare the command to execute rdisc6 on the specified interface
    snprintf(command, sizeof(command), "rdisc6 %s", p_VirtIf->Name );

    // Execute the command and open a pipe to read its output
    if ((fp = popen(command, "r")) == NULL) 
    {
        perror("popen");
        return -1;
    }

    // Read the output line by line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) 
    {
        if (strstr(buffer, "Router lifetime")) 
        {
            sscanf(buffer, " Router lifetime : %d", &p_VirtIf->IP.Ipv6RA.uiRouterLifetime);
        }

        // Look for the "from" line to identify the default route address
        if (strstr(buffer, "from")) 
        {
            sscanf(buffer, " from %s",  p_VirtIf->IP.Ipv6RA.acDefaultGw);
            if (inet_pton(AF_INET6, p_VirtIf->IP.Ipv6RA.acDefaultGw, &addr) == 1)  //check parsed value is a valid ipv6 address
            {
                ret = 0;
                break;
            }
        }
    }

    // Close the pipe
    pclose(fp);

    if(ret == 0)
    {
        CcspTraceInfo(("%s %d: Received Router Advertisement with default route %s lifetime %d\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv6RA.acDefaultGw, p_VirtIf->IP.Ipv6RA.uiRouterLifetime));
    }

    return ret;
}

/** WanManager_SendRS_And_ProcessRA() */
ANSC_STATUS WanManager_SendRS_And_ProcessRA(DML_VIRTUAL_IFACE *pVirtIf)
{
    ANSC_STATUS     returnStatus    = ANSC_STATUS_FAILURE;
    FILE            *fp             = NULL;
    char            cmd[BUFLEN_256]    = {0},
                    line[BUFLEN_512]   = {0},
                    acPrefix[BUFLEN_128] = {0};

    unsigned int    uiReachableTime = 0,
                    uiRetransmitTime = 0,
                    uiValidLifetime = 0,
                    uiPreferredLifetime = 0,
                    uiHopLimit = 0,
                    uiMTUSize = 0,
                    uiDnssCount = 0;
    char            acDnss[WANMGR_MAX_RA_DNS_SUPPORT][BUFLEN_64] = {0};    // Up to WANMGR_MAX_RA_DNS_SUPPORT DNS servers
    bool            IsRAReceived = FALSE,           // Confirms whether RA received or not
                    IsMFlagSet = FALSE,             // Stateful address conf. (Managed) M-flag
                    IsOFlagSet = FALSE,             // Stateful other conf. (Other) O-flag
                    IsAFlagSet = FALSE;             // PIO(Prefix Information Option) Autonomous address conf. A-flag (from prefix)

    // NULL check on received params
    if ( NULL == pVirtIf )
    {
       CcspTraceError(("%s %d: Invalid argument\n", __FUNCTION__, __LINE__));
       return returnStatus;
    }

    //Clear all memory of RA info since we haven't received any of the RA response
    memset(&pVirtIf->IP.Ipv6RA, 0, sizeof(WANMGR_IPV6_RA_DATA));

    //Wait until interface ready
    if ( ANSC_STATUS_FAILURE == WanManager_Wait_Until_IPv6_LinkLocal_ReadyToUse( pVirtIf->Name, INTF_V6LL_TIMEOUT_IN_MSEC ) )
    {
       CcspTraceError(("%s %d: Interface not ready to use for IPv6 request so ignoring solicit request for '%s' \n", __FUNCTION__, __LINE__, pVirtIf->Name));
       return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s %d: Requesting Router solicit for %s \n", __FUNCTION__, __LINE__, pVirtIf->Name));

    // Exit as soon as the first advertisement is received
    snprintf(cmd, sizeof(cmd), "rdisc6 -1 %s 2>/dev/null", pVirtIf->Name);
    fp = popen(cmd, "r");
    if (!fp) {
        CcspTraceError(("%s %d: Error Failed to Send Solicit for '%s' interface \n", __FUNCTION__, __LINE__, pVirtIf->Name));
        return ANSC_STATUS_FAILURE;
    }

    //Parse rdisc6 output
    while (fgets(line, sizeof(line), fp)) {
        // Normalize by trimming trailing newline (optional)
        // but we can parse with strstr directly.
        if (strstr(line, "Hop limit") ||
            strstr(line, "Router preference") ||
            strstr(line, "Prefix ")) {
            IsRAReceived = TRUE; // any of these indicate an RA parsed
        }

        if (strstr(line, "Stateful address conf.") && strstr(line, "Yes")){
            IsMFlagSet = TRUE;
        }
        else if (strstr(line, "Stateful other conf.") && strstr(line, "Yes")){
            IsOFlagSet = TRUE;
        }
        else if (strstr(line, "Autonomous address conf.") && strstr(line, "Yes")){
            IsAFlagSet = TRUE;
        }
        else if (strstr(line, "Hop limit")) {
            sscanf(line, "  Hop limit           : %u", &uiHopLimit);
        }
        else if (strstr(line, "MTU")) {
            sscanf(line, "  MTU                 : %u", &uiMTUSize);
        }
        else if (strstr(line, "Router lifetime")) {
            sscanf(line, "  Router lifetime     : %u", &pVirtIf->IP.Ipv6RA.uiRouterLifetime);
        }
        else if (strstr(line, "Reachable time")) {
            sscanf(line, "  Reachable time      : %u", &uiReachableTime);
        }
        else if (strstr(line, "Retransmit time")) {
            sscanf(line, "  Retransmit time     : %u", &uiRetransmitTime);
        }
        else if (strstr(line, "Prefix")) {
            sscanf(line, "  Prefix              : %126s", acPrefix);
        }
        else if (strstr(line, "Valid time")) {
            sscanf(line, "      Valid time      : %u", &uiValidLifetime);
        }
        else if (strstr(line, "Pref. time")) {
            sscanf(line, "      Pref. time      : %u", &uiPreferredLifetime);
        }
        else if (strstr(line, "from")) { 
            char gw[INET6_ADDRSTRLEN] = {0};
            if (sscanf(line, " from %s", gw) == 1) {
                struct in6_addr addr;
                if (inet_pton(AF_INET6, gw, &addr) == 1)  //check parsed value is a valid ipv6 address
                {
                    strncpy(pVirtIf->IP.Ipv6RA.acDefaultGw, gw, sizeof(pVirtIf->IP.Ipv6RA.acDefaultGw)-1);
                }
            }
        }
        else if (strstr(line, "Recursive DNS server")) {
            char dns[BUFLEN_64] = {0};
            if (sscanf(line, "  Recursive DNS server : %63s", dns) == 1) {
                if (uiDnssCount < WANMGR_MAX_RA_DNS_SUPPORT) {
                    strncpy(acDnss[uiDnssCount], dns, 63);
                    acDnss[uiDnssCount][63] = '\0';
                    uiDnssCount++;
                }
            }
        }
    }

    if( NULL != fp )
    {
        pclose(fp);
        fp = NULL;
    }

    CcspTraceInfo(("*************************** RA Info ***********************************\n"));
    CcspTraceInfo(("Parsed RA Flags: M(Managed flag)=%s, O(OtherConfig flag)=%s, A(PIO-Autoconf flag)=%s, ra_sent=%s, seen_any_ra=%s\n",
                                                    IsMFlagSet ? "Yes" : "No",
                                                    IsOFlagSet ? "Yes" : "No",
                                                    IsAFlagSet ? "Yes" : "No",
                                                    "yes",
                                                    IsRAReceived ? "Yes" : "No"));
    CcspTraceInfo(("Interface: %s\n", pVirtIf->Name));
    CcspTraceInfo(("Default GW: %s\n", pVirtIf->IP.Ipv6RA.acDefaultGw[0] ? pVirtIf->IP.Ipv6RA.acDefaultGw : "(none)"));
    CcspTraceInfo(("Hop limit: %u\n", uiHopLimit));
    CcspTraceInfo(("MTU: %u\n", uiMTUSize));
    CcspTraceInfo(("Router lifetime: %u\n", pVirtIf->IP.Ipv6RA.uiRouterLifetime));
    CcspTraceInfo(("Reachable time: %u\n", uiReachableTime));
    CcspTraceInfo(("Retransmit time: %u\n", uiRetransmitTime));
    CcspTraceInfo(("Prefix: %s\n", acPrefix[0] ? acPrefix : "(none)"));
    CcspTraceInfo(("  Valid lifetime: %u\n", uiValidLifetime));
    CcspTraceInfo(("  Preferred lifetime: %u\n", uiPreferredLifetime));
    CcspTraceInfo(("Recursive DNS servers:\n"));
    for (int i = 0; i < uiDnssCount; i++) {
        CcspTraceInfo(("  %s\n", acDnss[i]));
    }
    if (uiDnssCount == 0) {
        CcspTraceInfo(("  (none)\n"));
    }
    CcspTraceInfo(("***********************************************************************\n"));
    
    /*
    IPv6 Determination based on RA
    ------------------------------
    | M flag | O flag | Decision                                 |
    | -----: | :----: | ---------------------------------------- |
    |      1 |   \*   | **DHCPv6 (stateful)**                    |
    |      0 |    1   | **SLAAC + DHCPv6 (stateless)**           |
    |      0 |    0   | **SLAAC only**                           |
    */

    pVirtIf->IP.Ipv6RA.enIPv6RAStatus      = IPV6_RA_UNKNOWN;
    pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag = FALSE;

    if ( FALSE == IsRAReceived )
    {
        CcspTraceError(("%s %d: RA has not received for '%s' interface\n", __FUNCTION__, __LINE__, pVirtIf->Name));
    }
    else
    {
        if ( ( FALSE == IsMFlagSet ) && ( FALSE == IsOFlagSet ) )
        {
            pVirtIf->IP.Ipv6RA.enIPv6RAStatus = IPV6_RA_VALID_SLAAC;
            pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag = FALSE;
            CcspTraceInfo(("%s %d: RA doesn't have DHCPv6 information for '%s' interface RAStatus:%d DHCPStartFlag:%d\n", __FUNCTION__, __LINE__, pVirtIf->Name, pVirtIf->IP.Ipv6RA.enIPv6RAStatus, pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag));
        }
        else if ( TRUE == IsMFlagSet )
        {
            pVirtIf->IP.Ipv6RA.enIPv6RAStatus = IPV6_RA_VALID_ADDRESS_ON_DHCP;
            pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag = TRUE;
            CcspTraceInfo(("%s %d: RA has DHCPv6 information for '%s' interface so we can go ahead of DHCPv6 server start to acquire all the IPv6 information. RAStatus:%d DHCPStartFlag:%d\n", __FUNCTION__, __LINE__, pVirtIf->Name, pVirtIf->IP.Ipv6RA.enIPv6RAStatus, pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag));
        }
        else if ( TRUE == IsOFlagSet )
        {
            pVirtIf->IP.Ipv6RA.enIPv6RAStatus = IPV6_RA_VALID_DNS_ON_DHCP;
            pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag = TRUE;
            CcspTraceInfo(("%s %d: RA has SLAAC IPv6 but Other information like DNS at DHCPv6 server for '%s' interface so we can go ahead of DHCPv6 server start to acquire other information. RAStatus:%d DHCPStartFlag:%d\n", __FUNCTION__, __LINE__, pVirtIf->Name, pVirtIf->IP.Ipv6RA.enIPv6RAStatus, pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag));
        }

        //SLAAC Only use case
        if ( TRUE == IsAFlagSet )
        {
            pVirtIf->IP.Ipv6RA.enIPv6RAStatus = IPV6_RA_VALID_SLAAC;
            CcspTraceInfo(("%s %d: RA have Autonomous Address Configuration for '%s' interface. RAStatus:%d DHCPStartFlag:%d\n", __FUNCTION__, __LINE__, pVirtIf->Name, pVirtIf->IP.Ipv6RA.enIPv6RAStatus, pVirtIf->IP.Ipv6RA.DHCPStartStatusFlag));
        }

        //Read RA IPv6 and DNS Info and Update into WAN Virtual Interface Data Structure
        if ( ( TRUE == IsMFlagSet ) || ( TRUE == IsOFlagSet ) || ( TRUE == IsAFlagSet ) )
        {
            //WAN Interface Name
            snprintf( pVirtIf->IP.Ipv6Data.ifname, sizeof(pVirtIf->IP.Ipv6Data.ifname), "%s", pVirtIf->Name );

            //DNS Information from RA
            if ( 0 < uiDnssCount )
            {
                if( '\0' != acDnss[0][0] )
                snprintf(pVirtIf->IP.Ipv6Data.nameserver, sizeof(pVirtIf->IP.Ipv6Data.nameserver), "%s", acDnss[0]);
                
                if( '\0' != acDnss[1][0] )
                snprintf(pVirtIf->IP.Ipv6Data.nameserver1, sizeof(pVirtIf->IP.Ipv6Data.nameserver1), "%s", acDnss[1]);
            }
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/** WanManager_Wait_Until_IPv6_LinkLocal_ReadyToUse() */
ANSC_STATUS WanManager_Wait_Until_IPv6_LinkLocal_ReadyToUse(char *pInterfaceName, unsigned int uiTimeout)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_FAILURE;

    // NULL check on received params
    if ( NULL == pInterfaceName )
    {
       CcspTraceError(("%s %d: Invalid argument\n", __FUNCTION__, __LINE__));
       return returnStatus;
    }

    //Check if interface is ipv6 ready with a link-local address
    unsigned int waitTime = uiTimeout;
    char cmd[BUFLEN_128] = {0};
    snprintf(cmd, sizeof(cmd), "ip -6 address show dev %s tentative", pInterfaceName);
    while (waitTime > 0) 
    {
        FILE *fp_dad   = NULL;
        char buffer[BUFLEN_256] = {0};
 
        fp_dad = popen(cmd, "r");
        if(fp_dad != NULL) 
        {
            BOOL IsTentativeLinklocalFound = FALSE;

            while (fgets(buffer, sizeof(buffer), fp_dad) != NULL) 
            {
                // Look only for link-local addresses (fe80::/10)
                if (strstr(buffer, "fe80") != NULL) {
                    IsTentativeLinklocalFound = TRUE;
                    CcspTraceError(("%s %d: Interface(%s) still tentative: %s\n", __FUNCTION__, __LINE__, pInterfaceName, buffer));
                }
            }

            pclose(fp_dad);

            //Interface is not tentative which means DAD process has been completed for link local especially
            if ( FALSE == IsTentativeLinklocalFound )
            {
                break;
            }
        }
        usleep(INTF_V6LL_INTERVAL_IN_MSEC * USECS_IN_MSEC);
        waitTime -= INTF_V6LL_INTERVAL_IN_MSEC;
    }

    if (waitTime <= 0)
    {
        CcspTraceError(("%s %d: Interface %s doesnt have link local address\n", __FUNCTION__, __LINE__, pInterfaceName));
        returnStatus = ANSC_STATUS_FAILURE;
    }
    else
    {
        CcspTraceInfo(("%s %d: interface %s has valid link local address\n", __FUNCTION__, __LINE__, pInterfaceName));
        returnStatus = ANSC_STATUS_SUCCESS;
    }

    return returnStatus;
}