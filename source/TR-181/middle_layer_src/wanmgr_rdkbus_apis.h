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


#ifndef  _WANMGR_RDKBUS_APIS_H_
#define  _WANMGR_RDKBUS_APIS_H_

#include "wanmgr_apis.h"
#include "ccsp_psm_helper.h"
#include "ansc_platform.h"
#include "ansc_string_util.h"
#include "wanmgr_dml.h"
#include "wanmgr_data.h"

//TelcoVoiceManager
#define VOICE_DBUS_PATH           "/com/cisco/spvtg/ccsp/telcovoicemanager"
#define VOICE_COMPONENT_NAME      "eRT.com.cisco.spvtg.ccsp.telcovoicemanager"
#define VOICE_BOUND_IF_NAME       "Device.Services.VoiceService.1.X_RDK_BoundIfName"

//PPP Manager
#define PPPMGR_COMPONENT_NAME       "eRT.com.cisco.spvtg.ccsp.pppmanager"
#define PPPMGR_DBUS_PATH            "/com/cisco/spvtg/ccsp/pppmanager"

// DHCP Manager
#define DHCPMGR_COMPONENT_NAME       "eRT.com.cisco.spvtg.ccsp.dhcpmgr"
#define DHCPMGR_DBUS_PATH            "/com/cisco/spvtg/ccsp/dhcpmgr"

#define PPP_INTERFACE_TABLE          "Device.PPP.Interface."
#define PPP_INTERFACE_INSTANCE       "Device.PPP.Interface.%d."
#define PPP_INTERFACE_ENABLE         "Device.PPP.Interface.%d.Enable"
#define PPP_INTERFACE_LOWERLAYERS    "Device.PPP.Interface.%d.LowerLayers"
#define PPP_IPCP_LOCAL_IPADDRESS     "Device.PPP.Interface.%d.IPCP.LocalIPAddress"
#define PPP_IPCP_REMOTEIPADDRESS     "Device.PPP.Interface.%d.IPCP.RemoteIPAddress"
#define PPP_IPCP_DNS_SERVERS         "Device.PPP.Interface.%d.IPCP.DNSServers"
#define PPP_IPV6CP_REMOTE_IDENTIFIER "Device.PPP.Interface.%d.IPv6CP.RemoteInterfaceIdentifier"

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
#define MARKING_TABLE             "Device.X_RDK_WanManager.Interface.%d.Marking."
#define WANMGR_IFACE_WAN_STATUS   "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.Status"
#else
#define MARKING_TABLE             "Device.X_RDK_WanManager.CPEInterface.%d.Marking."
#define WANMGR_IFACE_WAN_STATUS   "Device.X_RDK_WanManager.CPEInterface.%d.Wan.Status"
#endif 

struct IFACE_INFO
{
    INT     Priority;
    CHAR    AvailableStatus[BUFLEN_64];
    CHAR    InterfaceIpStatus[BUFLEN_64];
    CHAR    ActiveStatus[BUFLEN_64];
    CHAR    CurrentActive[BUFLEN_64];
    CHAR    CurrentStandby[BUFLEN_64];
    struct IFACE_INFO *next;
};

ANSC_STATUS DmlSetWanIfCfg( INT LineIndex, DML_WAN_IFACE* pstLineInfo );
ANSC_STATUS DmlAddMarking(ANSC_HANDLE hContext,DML_MARKING* pMarking);
ANSC_STATUS DmlDeleteMarking(ANSC_HANDLE hContext, DML_MARKING* pMarking);
ANSC_STATUS DmlSetMarking(ANSC_HANDLE hContext, DML_MARKING*   pMarking);
ANSC_STATUS WanMgr_WanIfaceMarkingInit ();

ANSC_STATUS WanMgr_Publish_WanStatus(UINT IfaceIndex, UINT VirId);
ANSC_STATUS DmlSetWanActiveLinkInPSMDB( UINT uiInterfaceIdx, bool flag );
ANSC_STATUS WanController_ClearWanConfigurationsInPSM();
ANSC_STATUS Update_Interface_Status();
void WanMgr_getRemoteWanParamsFromPSM(DML_VIRTUAL_IFACE * pVirtIf);
int get_Wan_Interface_ParametersFromPSM(ULONG instancenum, DML_WAN_IFACE* p_Interface);
int write_Wan_Interface_ParametersFromPSM(ULONG instancenum, DML_WAN_IFACE* p_Interface);
int get_Virtual_Interface_FromPSM(ULONG instancenum, ULONG virtInsNum ,DML_VIRTUAL_IFACE * pVirtIf);
int write_Virtual_Interface_ToPSM(ULONG instancenum, ULONG virtInsNum ,DML_VIRTUAL_IFACE * pVirtIf);
int write_VirtMarking_ParametersToPSM(DML_VIRTIF_MARKING* p_Marking);
int write_VlanInterface_ParametersToPSM(DML_VLAN_IFACE_TABLE *pVlanInterface);
ANSC_STATUS WanMgr_WanConfInit (DML_WANMGR_CONFIG* pWanConfig);

ANSC_STATUS DmlGetTotalNoOfGroups(int *wan_if_count);
ANSC_STATUS WanMgr_RdkBus_setWanPolicy(DML_WAN_POLICY wan_policy, UINT groupId);
ANSC_STATUS WanMgr_Read_GroupConf_FromPSM(WANMGR_IFACE_GROUP *pGroup, UINT groupId);

/**
 * @brief Updates the VLAN in use parameter and stores it to persisted memory.
 *
 * This function compares the VLANInUse field with the CurrentVlan field of the provided
 * DML_VIRTUAL_IFACE structure. If they differ, it updates VLANInUse ,
 * and persists the new value to the database using WanMgr_RdkBus_SetParamValuesToDB.
 *
 * @param[in,out] pVirtIf Pointer to the DML_VIRTUAL_IFACE structure whose VLAN information is to be updated.
 *
 * @return ANSC_STATUS_SUCCESS Always returns success status.
 */
ANSC_STATUS UpdateAndPersistVLANInUse(DML_VIRTUAL_IFACE * pVirtIf);

ANSC_STATUS DmlGetTotalNoOfWanInterfaces(int *wan_if_count);
int get_Remote_Virtual_Interface_FromPSM(ULONG instancenum, ULONG virtInsNum ,DML_VIRTUAL_IFACE * pVirtIf);
#endif /* _WANMGR_RDKBUS_APIS_H_ */
