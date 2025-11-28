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

#ifndef  _WANMGR_DATA_H_
#define  _WANMGR_DATA_H_

#include <stdbool.h>
#include "ansc_platform.h"
#include "ansc_string_util.h"
#include "wanmgr_dml.h"
#include "wanmgr_rbus_handler_apis.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_utils.h"
#include "wanmgr_sysevents.h"

//Minimum SelectionTimeOut Value
#define SELECTION_TIMEOUT_DEFAULT_MIN 20
#define MAX_WAN_INTERFACE_ENTRY       32
#ifdef FEATURE_DSLITE_V2
#define MAX_DSLITE_CONFIG_ENTRY      16
#endif
//WAN CONFIG
WanMgr_Config_Data_t* WanMgr_GetConfigData_locked(void);
void WanMgrDml_GetConfigData_release(WanMgr_Config_Data_t* pWanConfigData);
void WanMgr_SetConfigData_Default(DML_WANMGR_CONFIG* pWanDmlConfig);

//WAN IFACE
UINT WanMgr_IfaceData_GetTotalWanIface(void);
WanMgr_Iface_Data_t* WanMgr_GetIfaceData_locked(UINT iface_index);
DML_VIRTUAL_IFACE* WanMgr_getVirtualIface_locked(UINT baseIfidx, UINT virtIfIdx);
void WanMgr_VirtualIfaceData_release(DML_VIRTUAL_IFACE* pVirtIf);
WanMgr_Iface_Data_t* WanMgr_GetIfaceDataByName_locked(char* iface_name);
DML_VIRTUAL_IFACE* WanMgr_GetVirtualIfaceByName_locked(const char* iface_name);
DML_VIRTUAL_IFACE* WanMgr_GetVIfByName_VISM_running_locked(const char* iface_name);
void WanMgrDml_GetIfaceData_release(WanMgr_Iface_Data_t* pWanIfaceData);
void WanMgr_IfaceData_Init(WanMgr_Iface_Data_t* pIfaceData, UINT uiInstNumber);
ANSC_STATUS WanMgr_WanDataInit(void);
void WanMgr_GetIfaceAliasNameByIndex(UINT iface_index, char *AliasName);
UINT WanMgr_GetIfaceIndexByAliasName(char* AliasName);

//WAN IFACE CTRL
void WanMgr_SetIfaceCtrl_Default(WanMgr_IfaceCtrl_Data_t* pWanIfaceCtrl);

// WAN MGR
void WanMgr_Data_Init(void);
ANSC_STATUS WanMgr_Data_Delete(void);

// WAN MGR REMOTE INTERFACE
ANSC_STATUS WanMgr_Remote_IfaceData_configure(char *remoteCPEMac, int *iface_index);
void WanMgr_Remote_IfaceData_Update(WanMgr_Iface_Data_t* pIfaceData, UINT iface_index);

ANSC_STATUS WanMgr_WanConfigInit(void);
ANSC_STATUS WanMgr_WanIfaceConfInit(WanMgr_IfaceCtrl_Data_t* pWanIfaceCtrl);

UINT WanMgr_GetTotalNoOfGroups();
DML_VIRTUAL_IFACE* WanMgr_getVirtualIfaceById(DML_VIRTUAL_IFACE* virIface, UINT inst);
ANSC_STATUS WanMgr_AddVirtualToList(DML_VIRTUAL_IFACE** head, DML_VIRTUAL_IFACE *newNode);

DML_VIRTIF_MARKING* WanMgr_getVirtMakingById(DML_VIRTIF_MARKING* marking, UINT inst);
ANSC_STATUS WanMgr_AddVirtMarkingToList(DML_VIRTIF_MARKING** head, DML_VIRTIF_MARKING *newNode);
DML_VLAN_IFACE_TABLE* WanMgr_getVirtVlanIfById(DML_VLAN_IFACE_TABLE* VlanIface, UINT inst);
ANSC_STATUS WanMgr_AddVirtVlanIfToList(DML_VLAN_IFACE_TABLE** head, DML_VLAN_IFACE_TABLE *newNode);

DML_VLAN_IFACE_TABLE* WanMgr_getVlanIface_locked(UINT baseIfidx, UINT virtIfIdx, UINT vlanid);
void WanMgr_VlanIfaceMutex_release(DML_VLAN_IFACE_TABLE* vlanIf);
DML_VIRTIF_MARKING* WanMgr_getVirtualMarking_locked(UINT baseIfidx, UINT virtIfIdx, UINT Markingid);
void WanMgr_VirtMarkingMutex_release(DML_VIRTIF_MARKING* virtMarking);
DML_VIRTUAL_IFACE* WanMgr_GetVirtIfDataByAlias_locked(char* iface_name);
DML_VIRTUAL_IFACE* WanMgr_GetActiveVirtIfData_locked(void);
WANMGR_IFACE_GROUP* WanMgr_GetIfaceGroup_locked(UINT iface_index);
void WanMgrDml_GetIfaceGroup_release(void);
ANSC_STATUS WanMgr_UpdatePrevData(void);
void WanMgr_VirtIface_Init(DML_VIRTUAL_IFACE * pVirtIf, UINT iface_index);

#ifdef FEATURE_DSLITE_V2
/* Data access and list management functions */
BOOL WanMgr_DSLite_isEnabled(DML_VIRTUAL_IFACE *p_VirtIf);
DML_VIRTUAL_IFACE* WanMgr_GetVirtIfDataByDSLiteAlias_locked(char* Alias);
ANSC_STATUS WanMgr_DSLite_RemoveFromList(UINT inst);
ANSC_STATUS WanMgr_DSLite_AddToList(UINT inst);
DML_DSLITE_LIST *WanMgr_getDSLiteEntryByInstance_locked(UINT inst);
DML_DSLITE_LIST *WanMgr_getDSLiteEntryByIdx_locked(UINT idx);
DML_DSLITE_LIST *WanMgr_getDSLiteEntryByAlias_locked(char *Alias);
WanMgr_DSLite_Data_t* WanMgr_GetDSLiteData_locked(void);
void WanMgr_GetDSLiteData_release(void);
#endif
#endif  //_WANMGR_DATA_H_
