#ifndef _WANMGR_RDKBUS_UTILS_H_
#define _WANMGR_RDKBUS_UTILS_H_

/*
   If not stated otherwise in this file or this component's LICENSE file the
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


/**************************************************************************

    module: wan_controller_utils.c

    For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        State machine to manage a Wan Controller

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        13/02/2020    initial revision.

**************************************************************************/


#include "dmsb_tr181_psm_definitions.h"
#include "ccsp_psm_helper.h"
#include "wanmgr_data.h"
#include "wanmgr_rdkbus_common.h"
#include "wanmgr_data.h"
#include "ansc_platform.h"
#include "wanmgr_sysevents.h"
#include <sysevent/sysevent.h>
extern int sysevent_fd;
extern token_t sysevent_token;

#include <syscfg/syscfg.h>

#define UPSTREAM_DM_SUFFIX                  ".Upstream"
#define WAN_CONFIG_PORT_DM_SUFFIX           ".WanConfigPort"

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
#define WAN_INTERFACE_TABLE                         "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d"
#define WAN_ENABLE_CUSTOM_CONFIG_PARAM_NAME         "Device.X_RDK_WanManager.Interface.%d.EnableCustomConfig"
#define WAN_CUSTOM_CONFIG_PATH_PARAM_NAME           "Device.X_RDK_WanManager.Interface.%d.CustomConfigPath"
#define WAN_CONFIGURE_WAN_ENABLE_PARAM_NAME         "Device.X_RDK_WanManager.Interface.%d.ConfigureWanEnable"
#define WAN_ENABLE_OPER_STATUS_MONITOR_PARAM_NAME   "Device.X_RDK_WanManager.Interface.%d.EnableOperStatusMonitor"
#define WAN_NAME_PARAM_NAME                         "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.1.Name"
#define WAN_PHY_PATH_PARAM_NAME                     "Device.X_RDK_WanManager.Interface.%d.BaseInterface"
#define WAN_PPP_PATH_PARAM_NAME                     "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.1.PPP.Interface"
#else
#define WAN_ENABLE_CUSTOM_CONFIG_PARAM_NAME         "Device.X_RDK_WanManager.CPEInterface.%d.EnableCustomConfig"
#define WAN_CUSTOM_CONFIG_PATH_PARAM_NAME           "Device.X_RDK_WanManager.CPEInterface.%d.CustomConfigPath"
#define WAN_CONFIGURE_WAN_ENABLE_PARAM_NAME         "Device.X_RDK_WanManager.CPEInterface.%d.ConfigureWanEnable"
#define WAN_ENABLE_OPER_STATUS_MONITOR_PARAM_NAME   "Device.X_RDK_WanManager.CPEInterface.%d.EnableOperStatusMonitor"
#define WAN_NAME_PARAM_NAME                         "Device.X_RDK_WanManager.CPEInterface.%d.Wan.Name"
#define WAN_PHY_PATH_PARAM_NAME                     "Device.X_RDK_WanManager.CPEInterface.%d.Phy.Path"
#define WAN_PPP_PATH_PARAM_NAME                     "Device.X_RDK_WanManager.CPEInterface.%d.PPP.Path"
#endif /* WAN_MANAGER_UNIFICATION_ENABLED */
#define STATUS_DM_SUFFIX                    ".Status"
#define VLAN_ETHLINK_STATUS_PARAM_NAME      "Device.X_RDK_Ethernet.Link.%d.Status"
#define VLAN_ETHLINK_NAME_PARAM_NAME        "Device.X_RDK_Ethernet.Link.%d.Name"

//Cellular manager
#define CELLULARMGR_WAN_NAME                         "wwan0"
#define CELLULARMGR_PHY_STATUS_DM_SUFFIX             ".X_RDK_PhyConnectedStatus"
#define CELLULARMGR_LINK_STATUS_DM_SUFFIX            ".X_RDK_LinkAvailableStatus"
#define CELLULARMGR_IPADDRESS                        ".X_RDK_ContextProfile.1.Ipv4Adress"
#define CELLULARMGR_SUBNET_MASK                      ".X_RDK_ContextProfile.1.Ipv4SubnetMask"
#define CELLULARMGR_GATEWAY                          ".X_RDK_ContextProfile.1.Ipv4Gateway"
#define CELLULARMGR_PRIMARY_DNS                      ".X_RDK_ContextProfile.1.Ipv4PrimaryDns"
#define CELLULARMGR_SECONDARY_DNS                    ".X_RDK_ContextProfile.1.Ipv4SecondaryDns"
#define CELLULARMGR_MTU_SIZE                         ".X_RDK_ContextProfile.1.MtuSize"
#define CELLULARMGR_IPv6_ADDRESS                     ".X_RDK_ContextProfile.1.Ipv6Address"
#define CELLULARMGR_COMPONENT_NAME                   "eRT.com.cisco.spvtg.ccsp.cellularmanager"
#define CELLULARMGR_DBUS_PATH                        "/com/cisco/spvtg/ccsp/cellularmanager"
#define CCSP_COMMON_FIFO                             "/tmp/ccsp_common_fifo"

//VLAN Agent
#define VLAN_DBUS_PATH                     "/com/cisco/spvtg/ccsp/vlanmanager"
#define VLAN_COMPONENT_NAME                "eRT.com.cisco.spvtg.ccsp.vlanmanager"
#define VLAN_ETHLINK_NOE_PARAM_NAME        "Device.X_RDK_Ethernet.LinkNumberOfEntries"
#define VLAN_ETHLINK_TABLE_NAME            "Device.X_RDK_Ethernet.Link."
#define VLAN_ETHLINK_TABLE_FORMAT          "Device.X_RDK_Ethernet.Link.%d."
#define VLAN_ETHLINK_REFRESH_PARAM_NAME    "Device.X_RDK_Ethernet.Link.%d.X_RDK_Refresh"
#define VLAN_ETHLINK_ENABLE_PARAM_NAME     "Device.X_RDK_Ethernet.Link.%d.Enable"
#define VLAN_TERMINATION_TABLE             "Device.X_RDK_Ethernet.VLANTermination."
//XDSL Manager
#define DSL_COMPONENT_NAME "eRT.com.cisco.spvtg.ccsp.xdslmanager"
#define DSL_COMPONENT_PATH "/com/cisco/spvtg/ccsp/xdslmanager"
#define DSL_UPSTREAM_NAME  UPSTREAM_DM_SUFFIX
//Eth Manager
#define ETH_COMPONENT_NAME "eRT.com.cisco.spvtg.ccsp.ethagent"
#define ETH_COMP_NAME_WITHOUTSUBSYSTEM "com.cisco.spvtg.ccsp.ethagent"
#define ETH_COMPONENT_PATH "/com/cisco/spvtg/ccsp/ethagent"
#define ETH_UPSTREAM_NAME  UPSTREAM_DM_SUFFIX
#define ETH_ADDTOLANBRIDGE_DM_SUFFIX  ".AddToLanBridge"
#ifdef FEATURE_RDKB_AUTO_PORT_SWITCH
#define ETH_INTERFACE_PORTCAPABILITY            ".PortCapability"
#endif  //FEATURE_RDKB_AUTO_PORT_SWITCH

#define ETH_PHY_PATH_DM             "Device.Ethernet.X_RDK_Interface.%d"
#define ETH_HW_CONFIG_PHY_PATH      "Device.Ethernet.Interface.%d"
#define ETHWAN_PHY_STATUS_DM_SUFFIX "LinkStatus"

//Dm for HW configuration in XB devices
#define SELECTED_OPERATIONAL_MODE           "Device.X_RDKCENTRAL-COM_EthernetWAN.SelectedOperationalMode"

//CM Agent
#define CMAGENT_COMPONENT_NAME "eRT.com.cisco.spvtg.ccsp.cm"
#define CMAGENT_COMP_NAME_WITHOUTSUBSYSTEM "com.cisco.spvtg.ccsp.cm"
#define CMAGENT_COMPONENT_PATH "/com/cisco/spvtg/ccsp/cm"
#define CMAGENT_PHY_STATUS_DM_SUFFIX             "CMStatus"

//Cellular Manager
#define CELLULAR_COMPONENT_NAME "eRT.com.cisco.spvtg.ccsp.cellularmanager"
#define CELLULAR_COMP_NAME_WITHOUTSUBSYSTEM "com.cisco.spvtg.ccsp.cellularmanager"
#define CELLULAR_COMPONENT_PATH "/com/cisco/spvtg/ccsp/cellularmanager"
#define CELLULAR_UPSTREAM_NAME ".Upstream"

//General Param for interfaces
#define PARAM_NAME_REQUEST_PHY_STATUS "RequestPhyStatus"
#define PARAM_NAME_REQUEST_OPERATIONAL_STATUS "RequestOperationalStatus"
#define PARAM_NAME_CONFIGURE_WAN "ConfigureWan"
#define PARAM_NAME_CUSTOM_CONFIG_WAN "CustomWanConfigUpdate"
#define PARAM_NAME_POST_CFG_WAN_FINALIZE "PostCfgWanFinalize"

ANSC_STATUS WanMgr_RdkBus_SetParamValues( char *pComponent, char *pBus, char *pParamName, char *pParamVal, enum dataType_e type, BOOLEAN bCommit );
ANSC_STATUS WanMgr_RdkBus_GetParamValues( char *pComponent, char *pBus, char *pParamName, char *pReturnVal );
ANSC_STATUS WanMgr_RdkBus_GetParamValueFromAnyComp( char * pQuery, char *pValue);

int WanMgr_RdkBus_GetParamValuesFromDB( char *pParamName, char *pReturnVal, int ReturnValLength );
int WanMgr_RdkBus_SetParamValuesToDB( char *pParamName, char *pParamVal );

ANSC_STATUS WanMgr_RdkBus_setWanEnableToPsm(BOOL WanEnable);
ANSC_STATUS WanMgr_RdkBus_setAllowRemoteIfaceToPsm(BOOL Enable);
ANSC_STATUS WanMgr_RdkBus_updateInterfaceUpstreamFlag(char *phyPath, BOOL flag);
void* WanMgr_RdkBus_WanIfRefreshThread( void *arg );

ANSC_STATUS DmlGetInstanceByKeywordFromPandM(char *ifname, int *piInstanceNumber);
ANSC_STATUS WanMgr_RdkBus_SetRequestIfComponent(char *pPhyPath, char *pInputparamName, char *pInputParamValue, enum dataType_e type);
ANSC_STATUS WaitForInterfaceComponentReady(char *pPhyPath);
ANSC_STATUS WanMgr_RdkBus_setRestorationDelay(UINT delay);
ANSC_STATUS WanManager_ConfigurePPPSession(DML_VIRTUAL_IFACE* pVirtIf, BOOL PPPEnable);
ANSC_STATUS WanMgr_RdkBus_ConfigureVlan(DML_VIRTUAL_IFACE* pVirtIf, BOOL VlanEnable);
ANSC_STATUS WanManager_RdkBus_EnableInterface(DML_WAN_IFACE* pInterface, BOOL Enable);

/* WanMgr_GetBaseInterfaceStatus()
 * Updates current BaseInterfaceStatus of WanInterfaces using a DM get of BaseInterface Dml.
 * This function will update BaseInterfaceStatus if WanManager restarted or BaseInterfaceStatus is already set by other components before WanManager rbus is ready.
 * Args: DML_WAN_IFACE struct
 * Returns: ANSC_STATUS_SUCCESS on successful get, else ANSC_STATUS_FAILURE.
 */
ANSC_STATUS WanMgr_GetBaseInterfaceStatus (DML_WAN_IFACE *pWanIfaceData);

ANSC_STATUS WanMgr_RdkBus_setDhcpv6DnsServerInfo(void);

#ifdef FEATURE_RDKB_AUTO_PORT_SWITCH
void WanMgr_SetPortCapabilityForEthIntf(DML_WAN_POLICY eWanPolicy);
#endif  //FEATURE_RDKB_AUTO_PORT_SWITCH

#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
ANSC_STATUS WanMgr_RdkBus_setWanIpInterfaceData(DML_VIRTUAL_IFACE*  pVirtIf);
#endif

ANSC_STATUS WanMgr_RdkBusDeleteVlanLink(DML_WAN_IFACE* pInterface );

#if defined(FEATURE_SUPPORT_MAPT_NAT46)
int WanMgr_SetMAPTEnableToPSM(DML_VIRTUAL_IFACE* pVirtIf, BOOL Enable);
#endif

/**************************************************************************************
 * @brief Select the IP mode.
 * The function should select the IP Mode based.
 * @param Interface data structure
 * @return ANSC_STATUS_SUCCESS upon success else ANSC_STATUS_FAILURE
 **************************************************************************************/
ANSC_STATUS WanMgr_GetSelectedIPMode(DML_VIRTUAL_IFACE * pVirtIf);

ANSC_STATUS  WanMgr_SetDnsConnectivityCheck(BOOL Enable);
BOOL WanMgr_GetDnsConnectivityCheck(void);
ANSC_STATUS WanMgr_SetConnectivityCheckTypeToPSM(DML_VIRTUAL_IFACE* pVirtIf, CONNECTIVITY_CHECK_TYPE type);

/**
 * @brief Wanmgr_TriggerReboot() - Initiates a device reboot.
 * 
 * This API is invoked when the platform needs to reboot to apply new WAN configurations. 
 * 
 * @note This function retains the last reboot reason for the current reboot due to dependencies 
 * from WebPA and Webconfig on various reboot scenarios (e.g., factory reset, reboot command, etc.).
 * 
 * @param void
 * @return void
 */
void Wanmgr_TriggerReboot();

/**
 * @brief Checks if the system is operating in Bridge Mode based on the 
 *        configuration from the PandM module.
 *
 * This function determines whether the current LAN bridge configuration
 * is set to Bridge Mode by querying the PandM  module.
 *
 * @return BOOL
 *         - TRUE if the system is in Bridge Mode.
 *         - FALSE otherwise.
 */

 BOOL WanMgr_isBridgeModeEnabled();
#ifdef FEATURE_DSLITE_V2
ANSC_STATUS WanMgr_SysCfgGetBool(const CHAR *key, BOOL *value);
ANSC_STATUS WanMgr_SysCfgGetUint(const CHAR *key, UINT *value);
ANSC_STATUS WanMgr_SysCfgGetStr(const CHAR *key, CHAR *dst, ULONG dst_len);
ANSC_STATUS WanMgr_SysCfgSetUint(const CHAR *key, UINT value);
ANSC_STATUS WanMgr_SysCfgSetStr(const CHAR *key, const CHAR *value);
#define DSLITE_WRITE_IF_CHANGED(cond, call)          \
    do                                               \
    {                                                \
        if ((cond) && (call) != ANSC_STATUS_SUCCESS) \
            ret = ANSC_STATUS_FAILURE;               \
    } while (0)
#endif
#endif /* _WANMGR_RDKBUS_UTILS_H_ */
