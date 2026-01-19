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

#ifndef _WANMGR_NET_UTILS_H_
#define _WANMGR_NET_UTILS_H_

/* ---- Include Files ---------------------------------------- */
#include <stdio.h>
#include <stdbool.h>
#include "wanmgr_rdkbus_common.h"
#include "ipc_msg.h"
#include "wanmgr_dml.h"
#include "wanmgr_utils.h"
//
//
/* ---- Global Constants -------------------------- */
#define DHCPV6_CLIENT_NAME "dibbler-client"
//


#define PTM_IFC_STR                 "ptm"
#define PHY_WAN_IF_NAME             "erouter0"
#define ETH_BRIDGE_NAME             "brlan0"
#define LAN_BRIDGE_NAME             "brlan0"
//

#define WAN_STATUS_UP   "up"
#define WAN_STATUS_DOWN "down"

#define MSECS_IN_SEC                      1000
#define USECS_IN_MSEC                     1000
#define INTF_V6LL_INTERVAL_IN_MSEC       (0.5 * MSECS_IN_SEC)  // 0.5 sec - half a second
#define INTF_V6LL_TIMEOUT_IN_MSEC        (5 * MSECS_IN_SEC)    // 5 sec

#define WAN_IF_MARKING_MAX_LIMIT       ( 15 )

typedef  struct _CONTEXT_MARKING_LINK_OBJECT
{
    CONTEXT_LINK_CLASS_CONTENT
    BOOL    bFound;
} CONTEXT_MARKING_LINK_OBJECT;



#define  ACCESS_CONTEXT_MARKING_LINK_OBJECT(p)              \
         ACCESS_CONTAINER(p, CONTEXT_MARKING_LINK_OBJECT, Linkage)



#ifdef FEATURE_MAPT_DEBUG
#define MaptError(fmt, arg...) \
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.MAPTLOG", fmt "\n", ##arg);
#define MaptNotice(fmt, arg...) \
        RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.MAPTLOG", fmt "\n", ##arg);
#define MaptInfo(fmt, arg...) \
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.MAPTLOG", fmt "\n", ##arg);
#endif /*FEATURE_MAPT_DEBUG*/

typedef enum
{
    DEL_ADDR = 0,
    SET_LFT = 1
} Ipv6OperType;

typedef enum
{
    WAN_INIT_START = 0,
    WAN_INIT_COMPLETE = 1
}WanBootEventState;

typedef enum {
    STOP_DHCP_WITH_RELEASE = 0,
    STOP_DHCP_WITHOUT_RELEASE,
} DHCP_RELEASE_BEHAVIOUR;

/* ---- Global Variables -------------------------- */

/* ---- Global Prototypes -------------------------- */
/***************************************************************************
 * @brief API used to start Dhcpv6 client application.
 * @param pcInterfaceName Interface name on which the dhcpv6 needs to start
 * @param isPPP indicates PPP enabled or nor
 * @return ANSC_STATUS_SUCCESS upon success else returned error code.
 ***************************************************************************/
int WanManager_StartDhcpv6Client(DML_VIRTUAL_IFACE* pVirtIf, IFACE_TYPE IfaceType);

/**
 * @brief Restarts the DHCPv6 client for the specified virtual interface.
 *
 * This function is responsible for restarting the DHCPv6 client associated
 * with the given virtual interface and interface type.
 *
 * @param[in] pVirtIf   Pointer to the virtual interface structure.
 * @param[in] IfaceType The type of the interface (e.g., Ethernet, DSL, etc.).
 *
 * @return int Returns 0 on success, or a negative value on failure.
 */
int WanManager_RestartDhcpv6Client(DML_VIRTUAL_IFACE* pVirtIf, IFACE_TYPE IfaceType);


/***************************************************************************
 * @brief API used to stop Dhcpv6 client application.
 * @param intf Interface name on which the dhcpv4 needs to stop
 * @return ANSC_STATUS_SUCCESS upon success else returned error code.
 ***************************************************************************/
ANSC_STATUS WanManager_StopDhcpv6Client(DML_VIRTUAL_IFACE* pVirtIf, DHCP_RELEASE_BEHAVIOUR IsReleaseNeeded);

/***************************************************************************
 * @brief API used to start Dhcpv4 client application.
 * @param intf Interface name on which the dhcpv4 needs to start
 * @return ANSC_STATUS_SUCCESS upon success else returned error code.
 ***************************************************************************/
int WanManager_StartDhcpv4Client(DML_VIRTUAL_IFACE* pVirtIf, char* baseInterface ,IFACE_TYPE IfaceType);

/***************************************************************************
 * @brief API used to stop Dhcpv4 client application.
 * @param pcInterfaceName Interface name for which dhcp v4 app needs to be stopped
 * @param IsReleaseNeeded whether release required or not during dhcp stop
 * @return ANSC_STATUS_SUCCESS upon success else returned error code.
 ***************************************************************************/
ANSC_STATUS WanManager_StopDhcpv4Client(DML_VIRTUAL_IFACE* pVirtIf, DHCP_RELEASE_BEHAVIOUR IsReleaseNeeded);

/***************************************************************************
 * @brief API used to restart Dhcpv6 client application.
 * @param ifName_info interface name
 * @param dynamicIpEnabled indicates dynamicip needs to be enable
 * @param pdEnabled indicates packket delegation enabled
 * @return ANSC_STATUS_SUCCESS upon success else returned error code.
 ***************************************************************************/
uint32_t WanManager_RestartDhcp6c(const char *ifName_info, BOOL dynamicIpEnabled,
                            BOOL pdEnabled, BOOL aftrName);




/***************************************************************************
 * @brief Utility function used to check Application is running.
 * @param appName string indicates application name
 * @param args string indicates parameter
 * @return status of system() call.
 ***************************************************************************/
BOOL WanManager_IsApplicationRunning(const char *appName, const char * args);

/***************************************************************************
 * @brief Utility function used to perform operation on IPV6 addresses
 * for a particular interface
 * @param ifname string indicates interface name
 * @param opr indicates operation type (Delete/Set)
 * @param preflft indicates preferred lifetime
 * @param vallft indicates valid lifetime
 * @return 0 upon success else -1 returned
 ***************************************************************************/
int WanManager_Ipv6PrefixUtil(char *ifname,Ipv6OperType opr,int preflft,int vallft);

/***************************************************************************
 * @brief Utility function used to check a process is running using PID
 * @param pid PID of the process to be checked
 * @return TRUE upon success else FALSE returned
 ***************************************************************************/
BOOL WanMgr_IsPIDRunning(int pid);

#if defined(FEATURE_464XLAT)
int xlat_configure(char *interface, char *xlat_address);
int xlat_reconfigure(void);
#endif

#ifdef FEATURE_MAPT
/*************************************************************************************
 * @brief checks kernel module loaded.
 * This API calls the proc entry.
 * @param moduleName is the kernal modulename
 * @return RETURN_OK upon success else RETURN_ERR returned
 **************************************************************************************/
int isModuleLoaded(char *moduleName); // checks kernel module loaded.

/***********************************************************************************
 * @brief This API used to process mapt configuration data.
 * @param dhcp6cMAPTMsgBody Hold the mapt data received from dhcp6 server.
 * @param baseIf Base interface name
 * @param vlanIf Vlan interface name
 * @return RETURN_OK in case of success else error code returned.
 ************************************************************************************/
int WanManager_ProcessMAPTConfiguration(ipc_map_data_t *dhcp6cMAPTMsgBody, WANMGR_MAPT_CONFIG_DATA *MaptConfig, const char *baseIf, const WANMGR_IPV6_DATA *ipv6Data);

ANSC_STATUS WanManager_VerifyMAPTConfiguration(ipc_map_data_t *dhcp6cMAPTMsgBody, WANMGR_MAPT_CONFIG_DATA *MaptConfig);

/***********************************************************************************
 * @brief This API used to display mapt feature status.
 ************************************************************************************/
void WanManager_DisplayMAPTFeatureStatus(void);
#endif

#ifdef MAPT_NAT46_FTP_ACTIVE_MODE
/***********************************************************************************
 * @brief This API used to calculate mapt portrange.
 * @param port_range will hold calculated ouput of the port range.
 ************************************************************************************/
void WanManager_CalculateMAPTPortRange(int offset, int psidLen, int psid, char* port_range);
#endif

/***********************************************************************************
 * @brief This API used to reset mapt configuration data.
 * @param baseIf Base interface name
 * @param vlanIf Vlan interface name
 * @return RETURN_OK in case of success else error code returned.
 ************************************************************************************/
int WanManager_ResetMAPTConfiguration(const char *baseIf, const char *vlanIf);

/***************************************************************************
 * @brief API used to update default ipv4 gateway
 * @param ipv4Info pointer to ipc_dhcpv4_data_t holds the IPv4 configuration
 * @param DeviceNwMode Gateway/Extender Mode
 * @return RETURN_OK upon success else returned error code.
 ****************************************************************************/
int WanManager_AddDefaultGatewayRoute(DEVICE_NETWORKING_MODE DeviceNwMode, const WANMGR_IPV4_DATA* ipv4Info);
int WanManager_DelDefaultGatewayRoute(DEVICE_NETWORKING_MODE DeviceNwMode, BOOL DeviceNwModeChange, const WANMGR_IPV4_DATA* pIpv4Info);
/***************************************************************************
 * @brief API used to get broadcast IP from IP and subnet mask
 * @param inIpStr IP address
 * @param inSubnetMaskStr Subnet mask
 * @param outBcastStr Stores the broadcast address
 * @return RETURN_OK upon success else returned error code.
 ****************************************************************************/
int WanManager_GetBCastFromIpSubnetMask(const char *inIpStr, const char *inSubnetMaskStr, char *outBcastStr);

/***************************************************************************
 * @brief API used to update ipv4 gateway
 * @param ipv4Info pointer to dhcpv4_data_t holds the IPv4 configuration
 * @return RETURN_OK upon success else returned error code.
 ****************************************************************************/
int WanManager_AddGatewayRoute(const WANMGR_IPV4_DATA* ipv4Info);

/***************************************************************************
 * @brief API used to get interface mac
 * @param interfaceName name of the interface
 * @param macAddress buffer to store mac address
 * @param macAddress buffer size to store mac address
 * @return ANSC_STATUS_SUCCESS upon success else returned error code.
 ***************************************************************************/
ANSC_STATUS WanManager_get_interface_mac(char *interfaceName, char* macAddress, int macAddressLen);

ANSC_STATUS WanManager_getGloballyUniqueIfAddr6(const char *ifname, char *ipAddr, uint32_t *prefixLen);
bool IsDefaultRoutePresent(char *IfaceName, bool IsV4);

#ifdef FEATURE_802_1P_COS_MARKING
ANSC_HANDLE WanManager_AddIfaceMarking(DML_WAN_IFACE* pWanDmlIface, ULONG* pInsNumber);
#endif /* * FEATURE_802_1P_COS_MARKING */
ANSC_STATUS WanManager_CheckGivenTypeExists(INT IfIndex, UINT uiTotalIfaces, DML_WAN_IFACE_TYPE priorityType, INT priority, BOOL *Status);
ANSC_STATUS WanManager_CheckGivenPriorityExists(INT IfIndex, UINT uiTotalIfaces, INT priority, BOOL *Status);
INT WanMgr_StartIpMonitor(UINT iface_index);
bool WanManager_IsNetworkInterfaceAvailable( char *IfaceName );
bool WanManager_IsNetworkInterfaceUp( char *IfaceName ) ;
int WanMgr_RdkBus_AddIntfToLanBridge (char * PhyPath, BOOL AddToBridge);
void WanManager_PrintBootEvents (WanBootEventState state);
/***************************************************************************
 * @brief API used to check the incoming ipv address is a valid.
 * @param af indicates address family
 * @param address string contains ip address
 * @return TRUE if its a valid IP address else returned false.
 ****************************************************************************/
BOOL IsValidIpAddress(int32_t af, const char *address);


int WanManager_send_and_receive_rs(DML_VIRTUAL_IFACE * pVirtIf);

ANSC_STATUS WanManager_Wait_Until_IPv6_LinkLocal_ReadyToUse(char *pInterfaceName, unsigned int uiTimeout);
ANSC_STATUS WanManager_SendRS_And_ProcessRA(DML_VIRTUAL_IFACE *pVirtIf);

#endif // _WANMGR_NET_UTILS_H_
