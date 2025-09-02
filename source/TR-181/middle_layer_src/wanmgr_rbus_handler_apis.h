/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _WANMGR_RBUS_H_
#define _WANMGR_RBUS_H_
#ifdef RBUS_BUILD_FLAG_ENABLE
#include "ansc_platform.h"
#include <rbus/rbus.h>
#include "ccsp_base_api.h"

#define WANMGR_CONFIG_WAN_CURRENTACTIVEINTERFACE     "Device.X_RDK_WanManager.CurrentActiveInterface"
#define WANMGR_CONFIG_WAN_CURRENT_STATUS             "Device.X_RDK_WanManager.CurrentStatus"
#define WANMGR_CONFIG_WAN_CURRENTSTANDBYINTERFACE    "Device.X_RDK_WanManager.CurrentStandbyInterface"
#define WANMGR_CONFIG_WAN_INTERFACEAVAILABLESTATUS   "Device.X_RDK_WanManager.InterfaceAvailableStatus"
#define WANMGR_CONFIG_WAN_INTERFACEACTIVESTATUS      "Device.X_RDK_WanManager.InterfaceActiveStatus"
#define WANMGR_CONFIG_WAN_CURRENTACTIVEDNS           "Device.X_RDK_WanManager.CurrentActiveDNS"
#define WANMGR_DEVICE_NETWORKING_MODE                "Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode"
#define X_RDK_REMOTE_DEVICECHANGE                    "Device.X_RDK_Remote.DeviceChange"
#define X_RDK_REMOTE_INVOKE                          "Device.X_RDK_Remote.Invoke()"
#define X_RDK_REMOTE_DEVICE_NUM_OF_ENTRIES           "Device.X_RDK_Remote.DeviceNumberOfEntries"
#define X_RDK_REMOTE_DEVICE_MAC                      "Device.X_RDK_Remote.Device.%d.MAC"
#define X_RDK_REMOTE_DEVICE_STATUS                   "Device.X_RDK_Remote.Device.%d.Status"
#define MAX_NO_OF_RBUS_REMOTE_PARAMS                 64

#define WANMGR_EVENT_INITIAL_SCAN_COMPLETED          "Device.X_RDK_WanManager.InitialScanComplete"
#define WANMGR_EVENT_WAN_INTERFACEIPSTATUS           "Device.X_RDK_WanManager.InterfaceIpStatus"

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
#define WANMGR_INFACE                                 "Device.X_RDK_WanManager.Interface.{i}."
#define WANMGR_INFACE_TABLE                           "Device.X_RDK_WanManager.Interface"
#define WANMGR_VIRTUAL_INFACE                         "Device.X_RDK_WanManager.Interface.{i}.VirtualInterface.{i}."
#define WANMGR_VIRTUAL_INFACE_TABLE                   "Device.X_RDK_WanManager.Interface.%d.VirtualInterface"
#define WANMGR_VIRTUAL_INFACE_TABLE_ALIAS             "Device.X_RDK_WanManager.Interface.\[%s\].VirtualInterface"
#define WANMGR_INFACE_PHY_STATUS                      "Device.X_RDK_WanManager.Interface.{i}.BaseInterfaceStatus"
#define WANMGR_INFACE_WAN_STATUS                      "Device.X_RDK_WanManager.Interface.{i}.VirtualInterface.{i}.Status"
#define WANMGR_INFACE_WAN_LINKSTATUS                  "Device.X_RDK_WanManager.Interface.{i}.VirtualInterface.{i}.VlanStatus"
#define WANMGR_INFACE_IPv4_ADDRESS                    "Device.X_RDK_WanManager.Interface.{i}.VirtualInterface.{i}.IP.IPv4Address"
#define WANMGR_INFACE_IPv6_ADDRESS                    "Device.X_RDK_WanManager.Interface.{i}.VirtualInterface.{i}.IP.IPv6Address"
#define WANMGR_INFACE_IPv6_PREFIX                     "Device.X_RDK_WanManager.Interface.{i}.VirtualInterface.{i}.IP.IPv6Prefix"
#define WANMGR_INFACE_WAN_ENABLE                      "Device.X_RDK_WanManager.Interface.{i}.Selection.Enable"
#define WANMGR_INFACE_ALIASNAME                       "Device.X_RDK_WanManager.Interface.{i}.Alias"

#define WANMGR_VIRTUALINFACE_TABLE_PREFIX             "VirtualInterface"
#define WANMGR_INFACE_PHY_STATUS_SUFFIX               ".BaseInterfaceStatus"
#define WANMGR_INFACE_WAN_STATUS_SUFFIX               ".Status"
#define WANMGR_INFACE_WAN_LINKSTATUS_SUFFIX           ".VlanStatus"
#define WANMGR_INFACE_WAN_ENABLE_SUFFIX               ".Selection.Enable"
#define WANMGR_INFACE_ALIASNAME_SUFFIX                ".Alias"

#define WANMGR_REMOTE_INFACE_DISPLAYNAME              "Device.X_RDK_WanManager.Interface.1.DisplayName"
#define WANMGR_REMOTE_INFACE_ALIAS                    "Device.X_RDK_WanManager.Interface.1.Alias"
#define WANMGR_REMOTE_INFACE_PHY_STATUS               "Device.X_RDK_WanManager.Interface.1.BaseInterfaceStatus"
#define WANMGR_REMOTE_INFACE_WAN_STATUS               "Device.X_RDK_WanManager.Interface.1.VirtualInterface.1.Status"
#define WANMGR_REMOTE_INFACE_LINK_STATUS              "Device.X_RDK_WanManager.Interface.1.VirtualInterface.1.VlanStatus"

#define WANMGR_REMOTE_DEVICE_WAN_DML_VERSION          "Device.X_RDK_WanManager.Version"

#define WANMGR_V1_INFACE                              "Device.X_RDK_WanManager.CPEInterface.{i}."
#define WANMGR_V1_INFACE_TABLE                        "Device.X_RDK_WanManager.CPEInterface"
#define WANMGR_V1_INFACE_PHY_STATUS                   "Device.X_RDK_WanManager.CPEInterface.{i}.Phy.Status"
#define WANMGR_V1_INFACE_WAN_STATUS                   "Device.X_RDK_WanManager.CPEInterface.{i}.Wan.Status"
#define WANMGR_V1_INFACE_WAN_LINKSTATUS               "Device.X_RDK_WanManager.CPEInterface.{i}.Wan.LinkStatus"

#define WANMGR_V1_INFACE_PHY_STATUS_SUFFIX            ".Phy.Status"
#define WANMGR_V1_INFACE_WAN_STATUS_SUFFIX            ".Wan.Status"
#define WANMGR_V1_INFACE_WAN_LINKSTATUS_SUFFIX        ".Wan.LinkStatus"
#define WANMGR_V1_INFACE_ALIASNAME_SUFFIX             ".AliasName"

#define WANMGR_PHY_STATUS_CHECK                       (strstr(name, WANMGR_INFACE_PHY_STATUS_SUFFIX) || (strstr(name, WANMGR_V1_INFACE_PHY_STATUS_SUFFIX)) )
#define WANMGR_WAN_STATUS_CHECK                       (strstr(name, WANMGR_INFACE_WAN_STATUS_SUFFIX) || (strstr(name, WANMGR_V1_INFACE_WAN_STATUS_SUFFIX)) )
#define WANMGR_WAN_LINKSTATUS_CHECK                   (strstr(name, WANMGR_INFACE_WAN_LINKSTATUS_SUFFIX) || (strstr(name, WANMGR_V1_INFACE_WAN_LINKSTATUS_SUFFIX)) )
#define WANMGR_ALIASNAME_CHECK                        (strstr(name, WANMGR_INFACE_ALIASNAME_SUFFIX) || (strstr(name, WANMGR_V1_INFACE_ALIASNAME_SUFFIX)) )

#define WANMGR_REMOTE_V1_INFACE_DISPLAYNAME           "Device.X_RDK_WanManager.CPEInterface.1.DisplayName"
#define WANMGR_REMOTE_V1_INFACE_ALIAS                 "Device.X_RDK_WanManager.CPEInterface.1.AliasName"
#define WANMGR_REMOTE_V1_INFACE_PHY_STATUS            "Device.X_RDK_WanManager.CPEInterface.1.Phy.Status"
#define WANMGR_REMOTE_V1_INFACE_WAN_STATUS            "Device.X_RDK_WanManager.CPEInterface.1.Wan.Status"
#define WANMGR_REMOTE_V1_INFACE_LINK_STATUS           "Device.X_RDK_WanManager.CPEInterface.1.Wan.LinkStatus"
#else
#define WANMGR_INFACE                                 "Device.X_RDK_WanManager.CPEInterface.{i}."
#define WANMGR_INFACE_TABLE                           "Device.X_RDK_WanManager.CPEInterface"
#define WANMGR_VIRTUAL_INFACE_TABLE                   "Device.X_RDK_WanManager.CPEInterface"
#define WANMGR_INFACE_PHY_STATUS                      "Device.X_RDK_WanManager.CPEInterface.{i}.Phy.Status"
#define WANMGR_INFACE_WAN_STATUS                      "Device.X_RDK_WanManager.CPEInterface.{i}.Wan.Status"
#define WANMGR_INFACE_WAN_LINKSTATUS                  "Device.X_RDK_WanManager.CPEInterface.{i}.Wan.LinkStatus"
#define WANMGR_INFACE_WAN_ENABLE                      "Device.X_RDK_WanManager.CPEInterface.{i}.Wan.Enable"
#define WANMGR_INFACE_ALIASNAME                       "Device.X_RDK_WanManager.CPEInterface.{i}.AliasName"

#define WANMGR_INFACE_PHY_STATUS_SUFFIX               ".Phy.Status"
#define WANMGR_INFACE_WAN_STATUS_SUFFIX               ".Wan.Status"
#define WANMGR_INFACE_WAN_LINKSTATUS_SUFFIX           ".Wan.LinkStatus"
#define WANMGR_INFACE_WAN_ENABLE_SUFFIX               ".Wan.Enable"
#define WANMGR_INFACE_ALIASNAME_SUFFIX                ".AliasName"

#define WANMGR_REMOTE_INFACE_DISPLAYNAME              "Device.X_RDK_WanManager.CPEInterface.1.DisplayName"
#define WANMGR_REMOTE_INFACE_ALIAS                    "Device.X_RDK_WanManager.CPEInterface.1.AliasName"
#define WANMGR_REMOTE_INFACE_PHY_STATUS               "Device.X_RDK_WanManager.CPEInterface.1.Phy.Status"
#define WANMGR_REMOTE_INFACE_WAN_STATUS               "Device.X_RDK_WanManager.CPEInterface.1.Wan.Status"
#define WANMGR_REMOTE_INFACE_LINK_STATUS              "Device.X_RDK_WanManager.CPEInterface.1.Wan.LinkStatus"

#define WANMGR_PHY_STATUS_CHECK                       (strstr(name, WANMGR_INFACE_PHY_STATUS_SUFFIX))
#define WANMGR_WAN_STATUS_CHECK                       (strstr(name, WANMGR_INFACE_WAN_STATUS_SUFFIX))
#define WANMGR_WAN_LINKSTATUS_CHECK                   (strstr(name, WANMGR_INFACE_WAN_LINKSTATUS_SUFFIX))
#define WANMGR_ALIASNAME_CHECK                        (strstr(name, WANMGR_INFACE_ALIASNAME_SUFFIX))
#endif /* WAN_MANAGER_UNIFICATION_ENABLED */

//TandD connectivity check DML
#define TANDD_START_CONNECTIVITY_CHECK               "Device.X_RDK_DNSInternet.StartConnectivityCheck()"
#define TANDD_STOP_CONNECTIVITY_CHECK                "Device.X_RDK_DNSInternet.StopConnectivityCheck()"
#define TANDD_CONNECTIVITY_CHECK_RESULT              "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.[%s].MonitorResult"
#define TANDD_CONNECTIVITY_CHECK_TREE                "Device.Diagnostics.X_RDK_DNSInternet.WANInterface."
#define TANDD_CONNECTIVITY_CHECK_MONITOR_STR         "MonitorResult"

typedef enum _IDM_MSG_OPERATION
{
    IDM_SET = 1,
    IDM_GET,
    IDM_SUBS,
    IDM_REQUEST,

}IDM_MSG_OPERATION;

typedef enum _IDM_REMOTE_DEVICE_STATUS
{
   DEVICE_NOT_DETECTED = 0,
   DEVICE_DETECTED,
   DEVICE_AUTHENTICATED,
   DEVICE_CONNECTED
} IDM_REMOTE_DEVICE_STATUS;

typedef struct _DeviceChangeEvent {
    char         mac_addr[64];
    bool         available;
} WanMgr_DeviceChangeEvent;

typedef struct _idm_invoke_method_Params
{
    IDM_MSG_OPERATION operation;
    char Mac_dest[18];
    char param_name[128];
    char param_value[2048];
    uint timeout;
    enum dataType_e type;
    rbusMethodAsyncHandle_t asyncHandle;
}idm_invoke_method_Params_t;

/***********************************************************************
 WanMgr_IDM_Invoke():
Description:
    Send Invoke request to IDM
Arguments:
    idm_invoke_method_Params_t*

    struct list:
    IDM_MSG_OPERATION operation : DM GET/SET/SUBSCRIBE
    char Mac_dest[18]           : Destination device (identifier) MAC
    char param_name[128]        : DM name
    char param_value[2048]      : DM value
    uint timeout                : Timeout for async call back
    enum dataType_e type        : DM data type
    rbusMethodAsyncHandle_t asyncHandle : Async call back handler pointer
Return value:
    ANSC_STATUS

 ***********************************************************************/
ANSC_STATUS WanMgr_IDM_Invoke(idm_invoke_method_Params_t *IDM_request);

ANSC_STATUS WanMgr_Rbus_Init();
ANSC_STATUS WanMgr_Rbus_Exit();
ANSC_STATUS WanMgr_Rbus_EventPublishHandler(const char *dm_event, void *dm_value, rbusValueType_t valueType);
ANSC_STATUS WanMgr_Rbus_String_EventPublish(char *dm_event, void *dm_value);
ANSC_STATUS WanMgr_Rbus_String_EventPublish_OnValueChange(char *dm_event, void *prev_dm_value, void *dm_value);
ANSC_STATUS WanMgr_Rbus_getUintParamValue(char * param, UINT * value);
void WanMgr_Rbus_UpdateLocalWanDb(void);
void WanMgr_Rbus_SubscribeDML(void);
void WanMgr_Rbus_UnSubscribeDML(void);
ANSC_STATUS WanMgr_RestartUpdateRemoteIface();
ANSC_STATUS WanMgr_WanRemoteIfaceConfigure(WanMgr_DeviceChangeEvent * pDeviceChangeEvent);
ANSC_STATUS WanManager_ManageInterfaceStatusSubscription(char *pParam, bool bSubscribeFlag);
#endif //RBUS_BUILD_FLAG_ENABLE
void WanMgr_Rbus_SubscribeWanReady();
/* WCC - Wan Connectivity Check*/
ANSC_STATUS WanMgr_Configure_TAD_WCC(DML_VIRTUAL_IFACE *pVirtIf, WCC_EVENT Event);

#if  defined( FEATURE_RDKB_DHCP_MANAGER )
void WanMgr_SubscribeDhcpClientEvents(const char *DhcpInterface);
void WanMgr_UnSubscribeDhcpClientEvents(const char *DhcpInterface);
#endif
#endif
