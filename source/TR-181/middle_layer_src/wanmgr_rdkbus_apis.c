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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

//!!!  This code assumes that all data structures are the SAME in middle-layer APIs and HAL layer APIs
//!!!  So it uses casting from one to the other
#include "wanmgr_rdkbus_apis.h"
#include "dmsb_tr181_psm_definitions.h"
#include "wanmgr_net_utils.h"
#ifdef RBUS_BUILD_FLAG_ENABLE
#include "wanmgr_rbus_handler_apis.h"
#endif //RBUS_BUILD_FLAG_ENABLE
#include "wanmgr_telemetry.h"

#define PSM_ENABLE_STRING_TRUE  "TRUE"
#define PSM_ENABLE_STRING_FALSE  "FALSE"
#define PPP_LINKTYPE_PPPOA "PPPoA"
#define PPP_LINKTYPE_PPPOE "PPPoE"

#define MESH_IFNAME        "br-home"

#define DATA_SKB_MARKING_LOCATION "/tmp/skb_marking.conf"
#define WAN_DBUS_PATH             "/com/cisco/spvtg/ccsp/wanmanager"
#define WAN_COMPONENT_NAME        "eRT.com.cisco.spvtg.ccsp.wanmanager"
#define RESOLV_CONF_FILE          "/etc/resolv.conf"
extern WANMGR_DATA_ST gWanMgrDataBase;
extern char g_Subsystem[32];
extern ANSC_HANDLE bus_handle;

int get_Wan_Interface_ParametersFromPSM(ULONG instancenum, DML_WAN_IFACE* p_Interface)
{
    int retPsmGet = CCSP_SUCCESS;
    char param_value[256];
    char param_name[512];
    CcspTraceInfo(("%s %d Update Wan Virtual iface Conf from PSM \n", __FUNCTION__, __LINE__));

    p_Interface->uiInstanceNumber = instancenum;

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_ENABLE, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        if(strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
        {
             p_Interface->Selection.Enable = TRUE;
        }
        else
        {
             p_Interface->Selection.Enable = FALSE;
        }
    }
    else
    {
        p_Interface->Selection.Enable = FALSE;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_ACTIVELINK, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        if(strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
        {
             p_Interface->Selection.ActiveLink = TRUE;
        }
        else
        {
             p_Interface->Selection.ActiveLink = FALSE;
        }
    }
    else
    {
        p_Interface->Selection.ActiveLink = FALSE;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_NAME, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        AnscCopyString(p_Interface->Name, param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_DISPLAY_NAME, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        AnscCopyString(p_Interface->DisplayName, param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_ALIAS, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        AnscCopyString(p_Interface->AliasName, param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_BASEINTERFACE, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        AnscCopyString(p_Interface->BaseInterface, param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_TYPE, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(p_Interface->Type));
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_PRIORITY, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(p_Interface->Selection.Priority));
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_TIMEOUT, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(p_Interface->Selection.Timeout));
    }
    if (p_Interface->Selection.Timeout < SELECTION_TIMEOUT_DEFAULT_MIN)
    {
        p_Interface->Selection.Timeout = SELECTION_TIMEOUT_DEFAULT_MIN;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_GROUP, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(p_Interface->Selection.Group));
    }


    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_REQUIRES_REBOOT, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        if(strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
        {
             p_Interface->Selection.RequiresReboot = TRUE;
        }
        else
        {
             p_Interface->Selection.RequiresReboot = FALSE;
        }
    }
    else
    {
        p_Interface->Selection.RequiresReboot = FALSE;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_COUNT, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(p_Interface->NoOfVirtIfs));
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_CONNECTION_TYPE, instancenum);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(p_Interface->IfaceConnectionType));
    }

    return ANSC_STATUS_SUCCESS;
}

int get_Virtual_Interface_FromPSM(ULONG instancenum, ULONG virtInsNum ,DML_VIRTUAL_IFACE * pVirtIf)
{
    int retPsmGet = CCSP_SUCCESS;
    char param_value[256];
    char param_name[512];
    CcspTraceInfo(("%s %d Update Wan Virtual iface Conf from PSM \n", __FUNCTION__, __LINE__));

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ENABLE_MAPT, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    /* Checking MAPT_Enable syscfg to handle RFC migration scenarios */
    char maptRfc[16] ={0};
    syscfg_get(NULL, "MAPT_Enable", maptRfc, sizeof(maptRfc));
    
    if(strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
    {
        pVirtIf->EnableMAPT = TRUE;
    }
    else if( strcmp(maptRfc, "true") == 0)
    {
        CcspTraceInfo(("%s %d Enabling MAPT based on MAPT_Enable syscfg \n", __FUNCTION__, __LINE__));
        pVirtIf->EnableMAPT = TRUE;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ENABLE_DSLITE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if(strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
    {
        pVirtIf->EnableDSLite = TRUE;
    }

#ifdef FEATURE_DSLITE_V2
    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_DSLITE_PATH, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    AnscCopyString(pVirtIf->DSLite.Path, param_value);
#endif
    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ENABLE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if(strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
    {
        pVirtIf->Enable = TRUE;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_NAME, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    AnscCopyString(pVirtIf->Name, param_value);

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ALIAS, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    AnscCopyString(pVirtIf->Alias, param_value);

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_PPP_INTERFACE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    AnscCopyString(pVirtIf->PPP.Interface, param_value);
    if(!strncmp(pVirtIf->PPP.Interface, PPP_INTERFACE_TABLE, strlen(PPP_INTERFACE_TABLE)))
    {
        CcspTraceInfo(("%s %d Valid PPP interface is configured. Use PPP\n", __FUNCTION__, __LINE__));
        pVirtIf->PPP.Enable = TRUE;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_INTERFACE_COUNT, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    _ansc_sscanf(param_value, "%d", &(pVirtIf->VLAN.NoOfInterfaceEntries));

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_TIMEOUT, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    _ansc_sscanf(param_value, "%d", &(pVirtIf->VLAN.Timeout));

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_INUSE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    AnscCopyString(pVirtIf->VLAN.VLANInUse, param_value);
    if(!strncmp(pVirtIf->VLAN.VLANInUse, VLAN_TERMINATION_TABLE, strlen(VLAN_TERMINATION_TABLE)) || pVirtIf->VLAN.NoOfInterfaceEntries > 0)
    {
        CcspTraceInfo(("%s %d Valid VLAN interface is configured. Use VLAN\n", __FUNCTION__, __LINE__));
        pVirtIf->VLAN.Enable = TRUE;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_DISCOVERY_MODE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    _ansc_sscanf(param_value, "%d", &(pVirtIf->VLAN.DiscoveryMode));

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_MARKING_COUNT, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    _ansc_sscanf(param_value, "%d", &(pVirtIf->VLAN.NoOfMarkingEntries));

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_INTERFACE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    AnscCopyString(pVirtIf->IP.Interface, param_value);

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_MODE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pVirtIf->IP.Mode));
        WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_IP_MODE);	
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_V4SOURCE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if(retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pVirtIf->IP.IPv4Source));
        WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_IPv4_CONFIG_TYPE);	
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_DHCPv4, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    AnscCopyString(pVirtIf->IP.DHCPv4Iface, param_value);

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_V6SOURCE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if(retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pVirtIf->IP.IPv6Source));
        WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_IPv6_CONFIG_TYPE);	
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_DHCPv6, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    AnscCopyString(pVirtIf->IP.DHCPv6Iface, param_value);

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_PREFERREDMODE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if(retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pVirtIf->IP.PreferredMode));
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_MODE_FORCE_ENABLE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if(strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
    {
        pVirtIf->IP.ModeForceEnable = TRUE;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_CONNECTIVITY_CHECK_TYPE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if(retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pVirtIf->IP.ConnectivityCheckType));
        WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_CONNECTIVITY_CHECK_TYPE);	
    }
}

int get_Remote_Virtual_Interface_FromPSM(ULONG instancenum, ULONG virtInsNum ,DML_VIRTUAL_IFACE * pVirtIf)
{
    int retPsmGet = CCSP_SUCCESS;
    char param_value[256] = {0};
    char param_name[512] = {0};
    CcspTraceInfo(("%s %d Update Remote Wan Virtual iface Conf from PSM \n", __FUNCTION__, __LINE__));

    _ansc_sprintf(param_name, PSM_WANMANAGER_CONNECTIVITY_CHECK_TYPE, instancenum, (virtInsNum + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if(retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pVirtIf->IP.ConnectivityCheckType));
        WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_CONNECTIVITY_CHECK_TYPE);	
    }
}

void WanMgr_getRemoteWanParamsFromPSM(DML_VIRTUAL_IFACE * pVirtIf)
{
    char param_value[256] = {0};
    int retPsmGet = CCSP_SUCCESS;
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(PSM_MESH_WAN_IFNAME,param_value,sizeof(param_value));
    if(retPsmGet == CCSP_SUCCESS)
    {
        snprintf(pVirtIf->Name,sizeof(pVirtIf->Name),"%s",param_value);
    }
    else
    {
        CcspTraceError(("%s-%d :Failed to get Remote WAN IfName from PSM, using default\n", __FUNCTION__, __LINE__));
        snprintf(pVirtIf->Name,sizeof(pVirtIf->Name),"%s",REMOTE_INTERFACE_NAME);
    }

    CcspTraceWarning(("%s-%d :Remote WAN IfName is (%s)\n", __FUNCTION__, __LINE__, pVirtIf->Name));

    memset(param_value, 0, sizeof(param_value));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(PSM_MESH_WAN_DHCPv4,param_value,sizeof(param_value));

    if(retPsmGet == CCSP_SUCCESS)
    {
        snprintf(pVirtIf->IP.DHCPv4Iface,sizeof(pVirtIf->IP.DHCPv4Iface),"%s",param_value);
    }
    else
    {
        CcspTraceError(("%s-%d :Failed to get Remote WAN DHCP interface from PSM,\n", __FUNCTION__, __LINE__));
    }
    CcspTraceWarning(("%s-%d :Remote WAN DHCPv4Iface is (%s)\n", __FUNCTION__, __LINE__, pVirtIf->IP.DHCPv4Iface));
    return;
}

int write_Wan_Interface_ParametersFromPSM(ULONG instancenum, DML_WAN_IFACE* p_Interface)
{
    int retPsmSet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};

    CcspTraceInfo(("%s %d Entered\n", __FUNCTION__, __LINE__));
    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    if(p_Interface->Selection.Enable)
    {
        _ansc_sprintf(param_value, "TRUE");
    }
    else
    {
        _ansc_sprintf(param_value, "FALSE");
    }
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_ENABLE, instancenum);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", p_Interface->Type );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_TYPE, instancenum);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", p_Interface->Selection.Timeout );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_TIMEOUT, instancenum);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", p_Interface->Selection.Group );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_GROUP, instancenum);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    if(p_Interface->Selection.RequiresReboot)
    {
        _ansc_sprintf(param_value, PSM_ENABLE_STRING_TRUE);
    }
    else
    {
        _ansc_sprintf(param_value, PSM_ENABLE_STRING_FALSE);
    }
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_REQUIRES_REBOOT, instancenum);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", p_Interface->Selection.Priority );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_PRIORITY, instancenum);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    snprintf(param_value, sizeof(param_value), "%s", p_Interface->BaseInterface );
    snprintf(param_name, sizeof(param_name), PSM_WANMANAGER_IF_BASEINTERFACE, instancenum);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);
#endif

    return ANSC_STATUS_SUCCESS;
}

int write_Virtual_Interface_ToPSM(ULONG instancenum, ULONG virtInsNum ,DML_VIRTUAL_IFACE * pVirtIf)
{
    int retPsmSet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};

    CcspTraceInfo(("%s %d Entered\n", __FUNCTION__, __LINE__));

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    if(pVirtIf->EnableDSLite == TRUE)
    {
        _ansc_sprintf(param_value, "TRUE");
    }
    else
    {
        _ansc_sprintf(param_value, "FALSE");
    }
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ENABLE_DSLITE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    if(pVirtIf->EnableMAPT == TRUE)
    {
        _ansc_sprintf(param_value, "TRUE");
    }
    else
    {
        _ansc_sprintf(param_value, "FALSE");
    }
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ENABLE_MAPT, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    if(pVirtIf->Enable == TRUE)
    {
        _ansc_sprintf(param_value, "TRUE");
    }
    else
    {
        _ansc_sprintf(param_value, "FALSE");
    }
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ENABLE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    AnscCopyString(param_value, pVirtIf->Name);
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_NAME, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    AnscCopyString(param_value, pVirtIf->Alias);
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ALIAS, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    AnscCopyString(param_value, pVirtIf->PPP.Interface);
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_PPP_INTERFACE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", pVirtIf->VLAN.Timeout );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_TIMEOUT, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", pVirtIf->VLAN.NoOfInterfaceEntries );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_INTERFACE_COUNT, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", pVirtIf->VLAN.NoOfMarkingEntries );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_MARKING_COUNT, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    AnscCopyString(param_value, pVirtIf->IP.Interface);
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_INTERFACE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", pVirtIf->IP.Mode );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_MODE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", pVirtIf->IP.IPv4Source );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_V4SOURCE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    AnscCopyString(param_value, pVirtIf->IP.DHCPv4Iface);
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_DHCPv4, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", pVirtIf->IP.IPv6Source );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_V6SOURCE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    AnscCopyString(param_value, pVirtIf->IP.DHCPv6Iface);
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_DHCPv6, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);
    
    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", pVirtIf->IP.PreferredMode );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_PREFERREDMODE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    if(pVirtIf->IP.ModeForceEnable == TRUE)
    {
        _ansc_sprintf(param_value, "TRUE");
    }
    else
    {
        _ansc_sprintf(param_value, "FALSE");
    }
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_IP_MODE_FORCE_ENABLE, instancenum, (virtInsNum + 1));
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);
#endif
    return 0;
}

int write_VirtMarking_ParametersToPSM(DML_VIRTIF_MARKING* p_Marking)
{
        int retPsmSet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};

    CcspTraceInfo(("%s %d Entered\n", __FUNCTION__, __LINE__));


    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%d", p_Marking->Entry );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_MARKING_ENTRY, p_Marking->baseIfIdx +1,p_Marking->VirIfIdx+1,p_Marking->VirtMarkingInstanceNumber+1);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    return 0;
}

int write_VlanInterface_ParametersToPSM(DML_VLAN_IFACE_TABLE *pVlanInterface)
{
        int retPsmSet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};

    CcspTraceInfo(("%s %d Entered\n", __FUNCTION__, __LINE__));


    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    _ansc_sprintf(param_value, "%s", pVlanInterface->Interface );
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_MARKING_ENTRY, pVlanInterface->baseIfIdx +1, pVlanInterface->VirIfIdx+1, pVlanInterface->Index+1);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    return 0;
}
/* DmlWanGetPSMRecordValue() */
static int
DmlWanGetPSMRecordValue
    (
         char *pPSMEntry,
         char *pOutputString
    )
{
    int   retPsmGet = CCSP_SUCCESS;
    char  strValue[256]  = {0};

    //Validate buffer
    if( ( NULL == pPSMEntry ) && ( NULL == pOutputString ) )
    {
        CcspTraceError(("%s %d Invalid buffer\n",__FUNCTION__,__LINE__));
        return retPsmGet;
    }

    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB( pPSMEntry, strValue, sizeof(strValue) );
    if ( retPsmGet == CCSP_SUCCESS )
    {
        //Copy till end of the string
        snprintf( pOutputString, strlen( strValue ) + 1, "%s", strValue );
    }

    return retPsmGet;
}

/* DmlWanSetPSMRecordValue() */
static int
DmlWanSetPSMRecordValue
    (
         char *pPSMEntry,
         char *pSetString
    )
{
    int   retPsmGet = CCSP_SUCCESS;

    //Validate buffer
    if( ( NULL == pPSMEntry ) && ( NULL == pSetString ) )
    {
        CcspTraceError(("%s %d Invalid buffer\n",__FUNCTION__,__LINE__));
        return retPsmGet;
    }

    retPsmGet = WanMgr_RdkBus_SetParamValuesToDB(pPSMEntry,pSetString);

    return retPsmGet;
}

/* DmlWanDeletePSMRecordValue() */
static int
DmlWanDeletePSMRecordValue
    (
         char *pPSMEntry
    )
{
    int   retPsmGet = CCSP_SUCCESS;

    //Validate buffer
    if( NULL == pPSMEntry )
    {
        CcspTraceError(("%s %d Invalid buffer\n",__FUNCTION__,__LINE__));
        return retPsmGet;
    }

    retPsmGet = PSM_Del_Record( bus_handle, g_Subsystem, pPSMEntry );

    return retPsmGet;
}


#ifdef FEATURE_802_1P_COS_MARKING

#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
static void AddSkbMarkingToConfFile(UINT data_skb_mark)
{
   FILE * fp = fopen(DATA_SKB_MARKING_LOCATION, "w+");
   if (!fp)
   {
      AnscTraceError(("%s Error writing skb mark\n", __FUNCTION__));
   }
   else
   {
      fprintf(fp, "data_skb_marking %d\n",data_skb_mark);
      fclose(fp);
   }
}
#endif

static void WanMgr_RemoveMarkingEntryFromPSMList(char *acOldMarkingList, char *markingEntry, ULONG ulIfInstanceNumber)
{
    /* If entry avilable in Marking list and Marking entries(Alias,SKBPort,... ) are not availbale, PSM could be truncated. 
     * In this case don't add TR181 Marking table Entry and remove entry from PSM LIST to avoid Marking entry add failure. 
     * If entry is deleted from List, TelcoVoice manager will add voice marking entries and wan refresh will be triggered. 
     */
    char acNewMarkingList[64] = { 0 };
    char *save_ptr;
    char *tmpToken = NULL;
    INT     iTotalMarking        = 0;
    char                     acPSMQuery[128]    = { 0 },
                             acPSMValue[64]     = { 0 };

    //split marking table value
    tmpToken = strtok_r( acOldMarkingList, "-",&save_ptr );
    //check and add
    while ( tmpToken != NULL )
    {
        //Copy all the values except delete alias
        if( 0 != strcmp( markingEntry, tmpToken ) )
        {
            if( 0 == iTotalMarking )
            {
                snprintf( acNewMarkingList, sizeof( acNewMarkingList ), "%s", tmpToken );
            }
            else
            {
                //Append remaining marking strings
                strncat( acNewMarkingList, "-", strlen("-") + 1 );
                strncat( acNewMarkingList, tmpToken, strlen( tmpToken ) + 1 );
            }
            iTotalMarking++;
        }
        tmpToken = strtok_r( NULL, "-",&save_ptr );
    }

    //Check whether any marking available or not
    if( iTotalMarking == 0 )
    {
        snprintf( acPSMValue, sizeof( acPSMValue ), "%s", "" ); //Copy empty
    }
    else
    {
        snprintf( acPSMValue, sizeof( acPSMValue ), "%s", acNewMarkingList ); //Copy new string
    }

    //Set Marking LIST into PSM
    snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_LIST, ulIfInstanceNumber );
    DmlWanSetPSMRecordValue( acPSMQuery, acPSMValue );
    return;
}
/* DmlWanIfMarkingInit() */
ANSC_STATUS WanMgr_WanIfaceMarkingInit ()
{
    INT iLoopCount  = 0;

    WanMgr_IfaceCtrl_Data_t* pWanIfaceCtrl = &(gWanMgrDataBase.IfaceCtrl);
    //Validate received buffer
    if( NULL == pWanIfaceCtrl )
    {
        CcspTraceError(("%s %d - Invalid buffer\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
    if( FALSE == gWanMgrDataBase.Config.data.InterfaceVLANMarkingSupport )
    {
        CcspTraceInfo(("%s %d - Interface VLAN Marking Not Supported\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_SUCCESS;  
    }
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */

    //Initialise Marking Params
    for( iLoopCount = 0; iLoopCount < pWanIfaceCtrl->ulTotalNumbWanInterfaces; iLoopCount++ )
    {
            ULONG                    ulIfInstanceNumber = 0;
            char                     acPSMQuery[128]    = { 0 },
                                     acPSMValue[64]     = { 0 };

            //Interface instance number
            ulIfInstanceNumber = iLoopCount + 1;
            /* Query MarkingNumberOfEntries once to refresh dbus memory before adding tables if WanManager restarted. */
            snprintf( acPSMQuery, sizeof( acPSMQuery ), "%s%d.MarkingNumberOfEntries",TABLE_NAME_WAN_INTERFACE,ulIfInstanceNumber);
            WanMgr_RdkBus_GetParamValues(WAN_COMPONENT_NAME,WAN_DBUS_PATH, acPSMQuery, acPSMValue);

            memset( acPSMQuery, 0, sizeof( acPSMQuery ) );
            memset( acPSMValue, 0, sizeof( acPSMValue ) );
            //Query marking list for corresponding interface
            snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_LIST, ulIfInstanceNumber );
            if ( ( CCSP_SUCCESS == DmlWanGetPSMRecordValue( acPSMQuery, acPSMValue ) ) && \
                 ( strlen( acPSMValue ) > 0 ) )
            {
                char acTmpString[64] = { 0 };
                char *token          = NULL;
                char acOldMarkingList[64] = { 0 };


                //Parse PSM output
                snprintf( acTmpString, sizeof( acTmpString ), acPSMValue );
                snprintf( acOldMarkingList, sizeof( acOldMarkingList ), acPSMValue );

                //split marking table value
                token = strtok( acTmpString, "-" );

                //check and add
                while ( token != NULL )
                {
                    char aTableName[512] = {0};
                    ULONG                                ulInstanceNumber  = 0;

                    DML_MARKING    Marking;
                    DML_MARKING*   p_Marking = &Marking;
                    //Stores into tmp buffer
                    char acTmpMarkingData[ 32 ] = { 0 };
                    snprintf( acTmpMarkingData, sizeof( acTmpMarkingData ), "%s", token );
                    //Get Alias from PSM
                    memset( acPSMQuery, 0, sizeof( acPSMQuery ) );
                    memset( acPSMValue, 0, sizeof( acPSMValue ) );
                    snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_ALIAS, ulIfInstanceNumber, acTmpMarkingData );
                    if ( ( CCSP_SUCCESS == DmlWanGetPSMRecordValue( acPSMQuery, acPSMValue ) ) && \
                            ( strlen( acPSMValue ) > 0 ) )
                    {
                        snprintf( p_Marking->Alias, sizeof( p_Marking->Alias ), "%s", acPSMValue );
                    }
                    else
                    {
                        WanMgr_RemoveMarkingEntryFromPSMList(acOldMarkingList, acTmpMarkingData, ulIfInstanceNumber);
                        CcspTraceInfo(("%s %d - PSM entry for Alias Failed. Don't add Marking table Entry for token: (%s)\n", __FUNCTION__, __LINE__, token));
                        token = strtok( NULL, "-" );
                        continue;
                    }

                    
                        //Get SKB Port from PSM
                        memset( acPSMQuery, 0, sizeof( acPSMQuery ) );
                        memset( acPSMValue, 0, sizeof( acPSMValue ) );
                        
                        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_SKBPORT, ulIfInstanceNumber, acTmpMarkingData );
                        if ( ( CCSP_SUCCESS == DmlWanGetPSMRecordValue( acPSMQuery, acPSMValue ) ) && \
                                ( strlen( acPSMValue ) > 0 ) )
                        {
                            p_Marking->SKBPort = atoi( acPSMValue );
                                
                        }
                        else
                        {
                            WanMgr_RemoveMarkingEntryFromPSMList(acOldMarkingList, acTmpMarkingData, ulIfInstanceNumber);
                            CcspTraceInfo(("%s %d - PSM entry for SKBPort Failed. Don't add Marking table Entry for token: (%s)\n", __FUNCTION__, __LINE__, token));
                            token = strtok( NULL, "-" );
                            continue;
                        }
                    
                        //Get SKB Mark from PSM
                        memset( acPSMQuery, 0, sizeof( acPSMQuery ) );
                        memset( acPSMValue, 0, sizeof( acPSMValue ) );
                        
                        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_SKBMARK, ulIfInstanceNumber, acTmpMarkingData );
                        if ( ( CCSP_SUCCESS == DmlWanGetPSMRecordValue( acPSMQuery, acPSMValue ) ) && \
                                ( strlen( acPSMValue ) > 0 ) )
                        {
                            p_Marking->SKBMark = atoi( acPSMValue );
                        }
                        else
                        {
                            WanMgr_RemoveMarkingEntryFromPSMList(acOldMarkingList, acTmpMarkingData, ulIfInstanceNumber);
                            CcspTraceInfo(("%s %d - PSM entry for SKBMark Failed. Don't add Marking table Entry for token: (%s)\n", __FUNCTION__, __LINE__, token));
                            token = strtok( NULL, "-" );
                            continue;
                        }
                    
                        //Get Ethernet Priority Mark from PSM
                        memset( acPSMQuery, 0, sizeof( acPSMQuery ) );
                        memset( acPSMValue, 0, sizeof( acPSMValue ) );
                        
                        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_ETH_PRIORITY_MASK, ulIfInstanceNumber, acTmpMarkingData );
                        if ( ( CCSP_SUCCESS == DmlWanGetPSMRecordValue( acPSMQuery, acPSMValue ) ) && \
                                ( strlen( acPSMValue ) > 0 ) )
                        {
                            p_Marking->EthernetPriorityMark = atoi( acPSMValue );
                        }
                        else
                        {
                            WanMgr_RemoveMarkingEntryFromPSMList(acOldMarkingList, acTmpMarkingData, ulIfInstanceNumber);
                            CcspTraceInfo(("%s %d - PSM entry for EthernetPriorityMark Failed. Don't add Marking table Entry for token: (%s)\n", __FUNCTION__, __LINE__, token));
                            token = strtok( NULL, "-" );
                            continue;
                        }
                    /* Insert into marking table */
                    snprintf(aTableName, sizeof(aTableName), MARKING_TABLE, ulIfInstanceNumber);
                    if (CCSP_SUCCESS == CcspBaseIf_AddTblRow(bus_handle,WAN_COMPONENT_NAME,WAN_DBUS_PATH, 0, aTableName,&ulInstanceNumber))
                    {
                        /* a) SKBPort is derived from InstanceNumber.
                           b) Since InstanceNumber starts with Zero, to make it non-zero (add 1)
                           c) Voice packet get EthernetPriotityMark based on SKBPort.*/
                        p_Marking->InstanceNumber = ulInstanceNumber + 1;

                        //Re-adjust SKB Port if it is not matching with instance number
                        if ( p_Marking->InstanceNumber != p_Marking->SKBPort )
                        {
                            p_Marking->SKBPort = p_Marking->InstanceNumber;

                            //Set SKB Port into PSM
                            memset( acPSMQuery, 0, sizeof( acPSMQuery ) );
                            memset( acPSMValue, 0, sizeof( acPSMValue ) );
                            snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_SKBPORT, ulIfInstanceNumber, acTmpMarkingData );
                            snprintf( acPSMValue, sizeof( acPSMValue ), "%u", p_Marking->SKBPort );
                            DmlWanSetPSMRecordValue( acPSMQuery, acPSMValue );
                        }

                        /*
                         * Re-adjust SKB Mark
                         *
                         * 0x100000 * InstanceNumber(1,2,3, etc)
                         * 1048576 is decimal equalent to 0x100000 hexa decimal
                         */
                        p_Marking->SKBMark = ( p_Marking->InstanceNumber ) * ( 1048576 );

                        //Set SKB Port into PSM
                        memset( acPSMQuery, 0, sizeof( acPSMQuery ) );
                        memset( acPSMValue, 0, sizeof( acPSMValue ) );
                        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_SKBMARK, ulIfInstanceNumber, acTmpMarkingData );
                        snprintf( acPSMValue, sizeof( acPSMValue ), "%u", p_Marking->SKBMark );
                        DmlWanSetPSMRecordValue( acPSMQuery, acPSMValue );

                        CcspTraceInfo(("%s - Name[%s] Data[%s,%u,%u,%d]\n", __FUNCTION__, acTmpMarkingData, p_Marking->Alias, p_Marking->SKBPort, p_Marking->SKBMark, p_Marking->EthernetPriorityMark));
                            
                            Marking_UpdateInitValue(pWanIfaceCtrl->pIface,ulIfInstanceNumber-1,ulInstanceNumber,p_Marking);
#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                            /* Adding skb mark to config file if alis is 'DATA', so that udhcpc could use it to mark dhcp packets */
                            if(0 == strncmp(p_Marking->Alias, "DATA", 4))
                            {
                                AddSkbMarkingToConfFile(p_Marking->SKBMark);
                            }
#endif
                       }

                   token = strtok( NULL, "-" );
                }
            }

    }

    return ANSC_STATUS_SUCCESS;
}

/* * SListPushMarkingEntryByInsNum() */
ANSC_STATUS
SListPushMarkingEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCONTEXT_LINK_OBJECT   pLinkContext
    )
{
    ANSC_STATUS                 returnStatus      = ANSC_STATUS_SUCCESS;
    PCONTEXT_LINK_OBJECT   pLineContextEntry = (PCONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY          pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                       ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pLinkContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pLineContextEntry = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pLinkContext->InstanceNumber < pLineContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pLinkContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pLinkContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
DmlCheckAndProceedMarkingOperations
    (
        ANSC_HANDLE         hContext,
        DML_MARKING*   pMarking,
        DML_WAN_MARKING_DML_OPERATIONS enMarkingOp
    )
{
    char    acPSMQuery[128]    = { 0 },
            acPSMValue[64]     = { 0 };
    ULONG   ulIfInstanceNumber = 0;

    //Validate param
    if ( NULL == pMarking )
    {
        CcspTraceError(("%s %d Invalid Buffer\n", __FUNCTION__,__LINE__));
        return ANSC_STATUS_FAILURE;
    }

#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
    WanMgr_Config_Data_t    *pWanConfigData = WanMgr_GetConfigData_locked();
    unsigned char           InterfaceVLANMarkingSupport = FALSE;

    if( NULL != pWanConfigData )
    {
        InterfaceVLANMarkingSupport = pWanConfigData->data.InterfaceVLANMarkingSupport;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    if( FALSE == InterfaceVLANMarkingSupport )
    {
        CcspTraceError(("%s %d - Interface VLAN Marking Not Supported. So ignoring %d request\n", __FUNCTION__, __LINE__, enMarkingOp));
        return ANSC_STATUS_FAILURE;  
    }
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */

    //Find the Marking entry in PSM
    ulIfInstanceNumber = pMarking->ulWANIfInstanceNumber;

    //Query marking list for corresponding interface
    snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_MARKING_LIST, ulIfInstanceNumber );
    if ( CCSP_SUCCESS == DmlWanGetPSMRecordValue( acPSMQuery, acPSMValue ) )
    {
        char     acTmpString[64]          = { 0 },
                 acFoundMarkingRecord[64] = { 0 };
        char     *token                   = NULL;
        BOOL     IsMarkingRecordFound     = FALSE;

        //Parse PSM output
        snprintf( acTmpString, sizeof( acTmpString ), acPSMValue );

        //split marking table value
        token = strtok( acTmpString, "-" );

        //check and add
        while ( token != NULL )
        {
            if( 0 == strcmp( pMarking->Alias, token ) )
            {
                IsMarkingRecordFound = TRUE;
                snprintf( acFoundMarkingRecord, sizeof( acFoundMarkingRecord ), "%s", token );
                break;
            }

            token = strtok( NULL, "-" );
        }

        /*
         *
         * Note:
         * ----
         * If record found when add then reject that process
         * If record not found when add then needs to create new entry and update fields and LIST
         *
         * If record not found when delete then reject that process
         * If record found when delete then needs to delete all corresponding fields in DB and update LIST
         *
         * If record not found when update then reject that process
         * If record found when update then needs to update fields only not LIST
         *
         */
        switch( enMarkingOp )
        {
             case WAN_MARKING_ADD:
             {
                char    acPSMRecEntry[64],
                        acPSMRecValue[64];

                if( TRUE == IsMarkingRecordFound )
                {
                    CcspTraceError(("%s %d - Failed to add since record(%s) already exists!\n",__FUNCTION__,__LINE__,acFoundMarkingRecord));
                    return ANSC_STATUS_FAILURE;
                }

                //Set LIST into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_LIST, ulIfInstanceNumber );

                //Check whether already LIST is having another MARKING or not.
                if( 0 < strlen( acPSMValue ) )
                {
                    snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%s-%s", acPSMValue, pMarking->Alias );
                }
                else
                {
                    snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%s", pMarking->Alias );
                }

                //Check set is proper or not
                if ( CCSP_SUCCESS != DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue ) )
                {
                    CcspTraceError(("%s %d Failed to set PSM record %s\n", __FUNCTION__,__LINE__,acPSMRecEntry));
                    return ANSC_STATUS_FAILURE;
                }

                //Set Alias into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_ALIAS, ulIfInstanceNumber, pMarking->Alias );
                snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%s", pMarking->Alias );
                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                //Set SKBPort into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_SKBPORT, ulIfInstanceNumber, pMarking->Alias );

                /* a) SKBPort is derived from InstanceNumber.
                   b) Since InstanceNumber starts with Zero, to make it non-zero (add 1)
                   c) Voice packet get EthernetPriotityMark based on SKBPort.*/

                pMarking->InstanceNumber = pMarking->InstanceNumber + 1;

                /*
                 * Generate SKB port
                 *
                 * Stores the SKB Port for the entry. This is auto-generated for each entry starting from "1".
                 * Its value matches the instance index.
                 */

                pMarking->SKBPort = pMarking->InstanceNumber;

                snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%u", pMarking->SKBPort );
                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                //Set SKBMark into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_SKBMARK, ulIfInstanceNumber, pMarking->Alias );

                /*
                 * Generate SKB Mark
                 *
                 * Stores the SKB Mark for the entry. This is auto-generated for each entry starting from "0x100000".
                 * Its value increments by "0x100000", so the next would be "0x200000", then "0x300000", etc...
                 *
                 * 0x100000 * InstanceNumber(1,2,3, etc)
                 * 1048576 is decimal equalent to 0x100000 hexa decimal
                 */
                pMarking->SKBMark = ( pMarking->InstanceNumber ) * ( 1048576 );
                snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%u", pMarking->SKBMark );
                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                //Set Ethernet Priority Mark into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_ETH_PRIORITY_MASK, ulIfInstanceNumber, pMarking->Alias );
                snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%d", pMarking->EthernetPriorityMark );
                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                CcspTraceInfo(("%s Marking table(%s) and records added successfully\n",__FUNCTION__,pMarking->Alias));
             }
             break; /* * WAN_MARKING_ADD */

             case WAN_MARKING_UPDATE:
             {
                char    acPSMRecEntry[64],
                        acPSMRecValue[64];

                if( FALSE == IsMarkingRecordFound )
                {
                    CcspTraceError(("%s %d - Failed to update since record(%s) not exists!\n",__FUNCTION__,__LINE__,pMarking->Alias));
                    return ANSC_STATUS_FAILURE;
                }

                //Set Alias into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_ALIAS, ulIfInstanceNumber, pMarking->Alias );
                snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%s", pMarking->Alias );
                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                //Set SKBPort into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_SKBPORT, ulIfInstanceNumber, pMarking->Alias );
                snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%u", pMarking->SKBPort );
                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                //Set SKBMark into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_SKBMARK, ulIfInstanceNumber, pMarking->Alias );
                snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%u", pMarking->SKBMark );
                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                //Set Ethernet Priority Mark into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );
                memset( acPSMRecValue, 0, sizeof( acPSMRecValue ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_ETH_PRIORITY_MASK, ulIfInstanceNumber, pMarking->Alias );
                snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%d", pMarking->EthernetPriorityMark );
                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                CcspTraceInfo(("%s Marking table(%s) and records updated successfully\n",__FUNCTION__,pMarking->Alias));
             }
             break; /* * WAN_MARKING_UPDATE */

             case WAN_MARKING_DELETE:
             {
                char    acPSMRecEntry[64],
                        acPSMRecValue[64],
                        acNewMarkingList[64] = { 0 },
                        acNewTmpString[64]   = { 0 },
                        *tmpToken            = NULL;
                INT     iTotalMarking        = 0;


                if( FALSE == IsMarkingRecordFound )
                {
                    CcspTraceError(("%s %d - Failed to delete since record(%s) not exists!\n",__FUNCTION__,__LINE__,pMarking->Alias));
                    return ANSC_STATUS_FAILURE;
                }

                //Set Alias into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_ALIAS, ulIfInstanceNumber, pMarking->Alias );
                DmlWanDeletePSMRecordValue( acPSMRecEntry );

                //Set SKBPort into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_SKBPORT, ulIfInstanceNumber, pMarking->Alias );
                DmlWanDeletePSMRecordValue( acPSMRecEntry );

                //Set SKBMark into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_SKBMARK, ulIfInstanceNumber, pMarking->Alias );
                DmlWanDeletePSMRecordValue( acPSMRecEntry );

                //Set Ethernet Priority Mark into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_ETH_PRIORITY_MASK, ulIfInstanceNumber, pMarking->Alias );
                DmlWanDeletePSMRecordValue( acPSMRecEntry );

                //Remove entry from LIST

                //Parse PSM output
                snprintf( acNewTmpString, sizeof( acNewTmpString ), acPSMValue );

                //split marking table value
                tmpToken = strtok( acNewTmpString, "-" );

                //check and add
                while ( tmpToken != NULL )
                {
                    //Copy all the values except delete alias
                    if( 0 != strcmp( pMarking->Alias, tmpToken ) )
                    {
                        if( 0 == iTotalMarking )
                        {
                            snprintf( acNewMarkingList, sizeof( acNewMarkingList ), "%s", tmpToken );
                        }
                        else
                        {
                            //Append remaining marking strings
                            strncat( acNewMarkingList, "-", strlen("-") + 1 );
                            strncat( acNewMarkingList, tmpToken, strlen( tmpToken ) + 1 );
                        }

                        iTotalMarking++;
                    }

                    tmpToken = strtok( NULL, "-" );
                }

                //Check whether any marking available or not
                if( iTotalMarking == 0 )
                {
                    snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%s", "" ); //Copy empty
                }
                else
                {
                    snprintf( acPSMRecValue, sizeof( acPSMRecValue ), "%s", acNewMarkingList ); //Copy new string
                }

                //Set Marking LIST into PSM
                memset( acPSMRecEntry, 0, sizeof( acPSMRecEntry ) );

                snprintf( acPSMRecEntry, sizeof( acPSMRecEntry ), PSM_MARKING_LIST, ulIfInstanceNumber );

                DmlWanSetPSMRecordValue( acPSMRecEntry, acPSMRecValue );

                CcspTraceInfo(("%s Marking table(%s) and records deleted successfully\n",__FUNCTION__,pMarking->Alias));
             }
             break; /* * WAN_MARKING_DELETE */

             default:
             {
                 CcspTraceWarning(("%s default case\n",__FUNCTION__));
                 return ANSC_STATUS_FAILURE;
             }
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/* * DmlAddMarking() */
ANSC_STATUS
DmlAddMarking
    (
        ANSC_HANDLE         hContext,
        DML_MARKING*   pMarking
    )
{
    ANSC_STATUS                 returnStatus      = ANSC_STATUS_SUCCESS;

    //Validate param
    if ( NULL == pMarking )
    {
        CcspTraceError(("%s %d Invalid Buffer\n", __FUNCTION__,__LINE__));
        return ANSC_STATUS_FAILURE;
    }

    returnStatus = DmlCheckAndProceedMarkingOperations( hContext, pMarking, WAN_MARKING_ADD );

    if( ANSC_STATUS_SUCCESS != returnStatus )
    {
        CcspTraceError(("%s %d - Failed to Add Marking Entry\n",__FUNCTION__,__LINE__));
    }

    return ANSC_STATUS_SUCCESS;
}

/* * DmlDeleteMarking() */
ANSC_STATUS
DmlDeleteMarking
    (
        ANSC_HANDLE         hContext,
        DML_MARKING*   pMarking
    )
{
    ANSC_STATUS                 returnStatus      = ANSC_STATUS_SUCCESS;

    //Validate param
    if ( NULL == pMarking )
    {
        CcspTraceError(("%s %d Invalid Buffer\n", __FUNCTION__,__LINE__));
        return ANSC_STATUS_FAILURE;
    }

    returnStatus = DmlCheckAndProceedMarkingOperations( hContext, pMarking, WAN_MARKING_DELETE );

    if( ANSC_STATUS_SUCCESS != returnStatus )
    {
        CcspTraceError(("%s %d - Failed to Delete Marking Entry\n",__FUNCTION__,__LINE__));
    }

    return returnStatus;
}

/* * DmlSetMarking() */
ANSC_STATUS
DmlSetMarking
    (
        ANSC_HANDLE         hContext,
        DML_MARKING*   pMarking
    )
{
    ANSC_STATUS                 returnStatus      = ANSC_STATUS_SUCCESS;

    //Validate param
    if ( NULL == pMarking )
    {
        CcspTraceError(("%s %d Invalid Buffer\n", __FUNCTION__,__LINE__));
        return ANSC_STATUS_FAILURE;
    }

    returnStatus = DmlCheckAndProceedMarkingOperations( hContext, pMarking, WAN_MARKING_UPDATE );

    if( ANSC_STATUS_SUCCESS != returnStatus )
    {
        CcspTraceError(("%s %d - Failed to Update Marking Entry\n",__FUNCTION__,__LINE__));
    }

    return returnStatus;
}
#endif /* * FEATURE_802_1P_COS_MARKING */

/* DmlGetTotalNoOfGroups() */
ANSC_STATUS DmlGetTotalNoOfGroups(int *if_count)
{
    int ret_val = ANSC_STATUS_SUCCESS;
    int retPsmGet = CCSP_SUCCESS;
    char param_value[64] = {0};

    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(PSM_WANMANAGER_GROUP_COUNT,param_value,sizeof(param_value));
    if (retPsmGet != CCSP_SUCCESS) { \
        AnscTraceFlow(("%s Error %d reading %s\n", __FUNCTION__, retPsmGet,  PSM_WANMANAGER_GROUP_COUNT));
        ret_val = ANSC_STATUS_FAILURE;
    }
    else if(param_value[0] != '\0') {
        _ansc_sscanf(param_value, "%d", if_count);
    }

    return ret_val;
}

ANSC_STATUS WanMgr_RdkBus_setWanPolicy(DML_WAN_POLICY wan_policy, UINT groupId)
{
    int result = ANSC_STATUS_SUCCESS;
    int retPsmSet = CCSP_SUCCESS;
    char param_name[BUFLEN_256] = {0};
    char param_value[BUFLEN_256] = {0};

    /* Update the wan policy information in PSM */
    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    snprintf(param_value, sizeof(param_value), "%d", wan_policy);
    _ansc_sprintf(param_name, PSM_WANMANAGER_GROUP_POLICY, (groupId +1)); 

    retPsmSet = WanMgr_RdkBus_SetParamValuesToDB(param_name, param_value);
    if (retPsmSet != CCSP_SUCCESS) {
        AnscTraceError(("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, param_name, param_value));
        result = ANSC_STATUS_FAILURE;
    }

    return result;
}

ANSC_STATUS WanMgr_Read_GroupConf_FromPSM(WANMGR_IFACE_GROUP *pGroup, UINT groupId)
{
    int result = ANSC_STATUS_SUCCESS;
    int retPsmGet = CCSP_SUCCESS;
    char param_value[BUFLEN_256] = {0};
    char param_name[BUFLEN_256]= {0};

    _ansc_sprintf(param_name, PSM_WANMANAGER_GROUP_POLICY, (groupId + 1)); 
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS && param_value[0] != '\0') {
        pGroup->Policy = strtol(param_value, NULL, 10);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_GROUP_EXTERNAL_CONTROL, (groupId + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS && strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
    {
        CcspTraceWarning(("%s %d: External control enabled for group %d. WFO policy will not control this Group and its interfaces. \n", __FUNCTION__, __LINE__, (groupId + 1)));
        pGroup->State = STATE_GROUP_DEACTIVATED;
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_GROUP_PERSIST_SELECTED_IFACE, (groupId + 1));
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS && strcmp(param_value, PSM_ENABLE_STRING_TRUE) == 0)
    {
        //TODO : cleanup. No longer a requirement.
        CcspTraceInfo(("%s %d - PSM entry for PersistSelectedIface is not used.\n", __FUNCTION__, __LINE__));
        //pGroup->PersistSelectedIface = TRUE;
    }

    return result;
}

/* DmlGetTotalNoOfWanInterfaces() */
ANSC_STATUS DmlGetTotalNoOfWanInterfaces(int *wan_if_count)
{
    int ret_val = ANSC_STATUS_SUCCESS;
    int retPsmGet = CCSP_SUCCESS;
    char param_value[64] = {0};

    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(PSM_WANMANAGER_WANIFCOUNT,param_value,sizeof(param_value));
    if (retPsmGet != CCSP_SUCCESS) { \
        AnscTraceFlow(("%s Error %d reading %s\n", __FUNCTION__, retPsmGet, PSM_WANMANAGER_WANIFCOUNT));
        ret_val = ANSC_STATUS_FAILURE;
    }
    else if(param_value[0] != '\0') {
        _ansc_sscanf(param_value, "%d", wan_if_count);
    }

    return ret_val;
}

/* DmlGetWanIfCfg() */
ANSC_STATUS DmlGetWanIfCfg( INT LineIndex, DML_WAN_IFACE* pstLineInfo )
{
    return ANSC_STATUS_SUCCESS;
}


/* DmlSetWanIfCfg() */
ANSC_STATUS DmlSetWanIfCfg( INT LineIndex, DML_WAN_IFACE* pstLineInfo )
{
    int ret_val = ANSC_STATUS_SUCCESS;
    ret_val = write_Wan_Interface_ParametersFromPSM(LineIndex, pstLineInfo);
    if(ret_val != ANSC_STATUS_SUCCESS) {
        AnscTraceFlow(("%s Failed!! Error code: %d", __FUNCTION__, ret_val));
    }
    for(int i=0; i< pstLineInfo->NoOfVirtIfs; i++)
    {   
        DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pstLineInfo->VirtIfList, i);
        write_Virtual_Interface_ToPSM(LineIndex, i, p_VirtIf);
    }
    return ret_val;
}

ANSC_STATUS WanMgr_WanConfInit (DML_WANMGR_CONFIG* pWanConfig)
{
    unsigned int wan_enable;
    unsigned int wan_policy;
    unsigned int wan_allow_remote_iface = 0;
    unsigned int wan_restoration_delay = 0;
    unsigned int wan_idle_timeout;
    int ret_val = ANSC_STATUS_SUCCESS;
    int retPsmGet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};

    CcspTraceInfo(("%s %d Initialize WanConf \n", __FUNCTION__, __LINE__));

    memset(param_name, 0, sizeof(param_name));
    memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_WANENABLE);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS && param_value[0] != '\0')
        wan_enable = atoi(param_value);
    else
        ret_val = ANSC_STATUS_FAILURE;

    pWanConfig->Enable = wan_enable;

    memset(param_name, 0, sizeof(param_name));
    memset(param_value, 0, sizeof(param_value));

    _ansc_sprintf(param_name, PSM_WANMANAGER_ALLOW_REMOTE_IFACE);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS && param_value[0] != '\0')
        wan_allow_remote_iface = atoi(param_value);

    pWanConfig->AllowRemoteInterfaces = wan_allow_remote_iface;

    memset(param_name, 0, sizeof(param_name));
    memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_RESTORATION_DELAY);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS && param_value[0] != '\0')
        wan_restoration_delay = atoi(param_value);

    pWanConfig->RestorationDelay = wan_restoration_delay;

    memset(param_name, 0, sizeof(param_name));
    memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_BACKUPWANDNS_SUPPORT);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if ((retPsmGet == CCSP_SUCCESS) && (param_value[0] != '\0') && (0 == strncmp(param_value, "FALSE", 5)))
        pWanConfig->BackupWanDnsSupport = FALSE;

    memset(param_name, 0, sizeof(param_name));
    memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_IPV6EUI64FORMAT_SUPPPORT);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if ((retPsmGet == CCSP_SUCCESS) && (param_value[0] != '\0') && (0 == strncmp(param_value, "FALSE", 5)))
        pWanConfig->IPv6EUI64FormatSupport = FALSE;

    memset(param_name, 0, sizeof(param_name));
    memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_CONFIGUREWANIPV6ON_LANBRIDGE_SUPPPORT);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if ((retPsmGet == CCSP_SUCCESS) && (param_value[0] != '\0') && (0 == strncmp(param_value, "TRUE", 4)))
        pWanConfig->ConfigureWANIPv6OnLANBridgeSupport = TRUE;

    memset(param_name, 0, sizeof(param_name));
    memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_USEWANMAC_FOR_MGMT_SERVICES);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if ((retPsmGet == CCSP_SUCCESS) && (param_value[0] != '\0') && (0 == strncmp(param_value, "TRUE", 4)))
        pWanConfig->UseWANMACForManagementServices = TRUE;

    memset(param_name, 0, sizeof(param_name));
    memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_WANMANAGER_INTERFACE_VLAN_MARKING_SUPPORT);
    retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
    if ((retPsmGet == CCSP_SUCCESS) && (param_value[0] != '\0') && (0 == strncmp(param_value, "TRUE", 4)))
        pWanConfig->InterfaceVLANMarkingSupport = TRUE;

    return ret_val;
}

ANSC_STATUS
SListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCONTEXT_LINK_OBJECT   pContext
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PCONTEXT_LINK_OBJECT       pContextEntry = (PCONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pContextEntry = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pContext->InstanceNumber < pContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}

PCONTEXT_LINK_OBJECT SListGetEntryByInsNum( PSLIST_HEADER pListHead, ULONG InstanceNumber)
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PCONTEXT_LINK_OBJECT            pContextEntry = (PCONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        return NULL;
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pContextEntry = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pContextEntry->InstanceNumber == InstanceNumber )
            {
                return pContextEntry;
            }
        }
    }

    return NULL;
}
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
ANSC_STATUS UpdateAndPersistVLANInUse(DML_VIRTUAL_IFACE * pVirtIf)
{
    char param_value[256] = {0};
    char param_name[512] = {0};

    // Compare VLANInUse with CurrentVlan and update if different
    if (strcmp(pVirtIf->VLAN.VLANInUse, pVirtIf->VLAN.CurrentVlan) != 0)
    {
        CcspTraceInfo(("%s %d VLANInUse changed, updating: %s => %s\n", 
                       __FUNCTION__, __LINE__, pVirtIf->VLAN.VLANInUse, pVirtIf->VLAN.CurrentVlan));
        AnscCopyString(pVirtIf->VLAN.VLANInUse, pVirtIf->VLAN.CurrentVlan);
    
        AnscCopyString(param_value, pVirtIf->VLAN.VLANInUse);
        _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_VLAN_INUSE, (pVirtIf->baseIfIdx +1), (pVirtIf->VirIfIdx + 1));
        CcspTraceInfo(("%s %d Update VLANInUse to PSM %s => %s\n", __FUNCTION__, __LINE__,param_name,param_value));
        WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);
    }
     return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS DmlSetWanActiveLinkInPSMDB( UINT uiInterfaceIdx , bool storeValue )
{
    int retPsmSet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    if(storeValue == TRUE)
    {
        _ansc_sprintf(param_value, PSM_ENABLE_STRING_TRUE);
    }
    else
    {
        _ansc_sprintf(param_value, PSM_ENABLE_STRING_FALSE);
    }
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_ACTIVELINK, (uiInterfaceIdx + 1));
    CcspTraceInfo(("%s %d: setting %s = %s\n", __FUNCTION__, __LINE__, param_name, param_value));
    if (WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value) != CCSP_SUCCESS)
    {
        CcspTraceError(("%s %d: setting %s = %s in PSM failed\n", __FUNCTION__, __LINE__, param_name, param_value));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanController_ClearWanConfigurationsInPSM()
{
    char param_name[256] = {0};
    char param_value[256] = {0};
    UINT        uiTotalIfaces;
    ANSC_STATUS result;

    result = DmlGetTotalNoOfWanInterfaces(&uiTotalIfaces);
    if(result != ANSC_STATUS_SUCCESS) 
    {
        return ANSC_STATUS_FAILURE;
    }

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    for(int instancenum = 1; instancenum <=uiTotalIfaces; instancenum++)
    {
        _ansc_sprintf(param_value, PSM_ENABLE_STRING_FALSE);
        _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_ACTIVELINK, (instancenum));
        WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);
    }
    return ANSC_STATUS_SUCCESS;
}

void SortedInsert( struct IFACE_INFO** head_ref,  struct IFACE_INFO *new_node)
{
    struct IFACE_INFO* current;
    if (*head_ref == NULL
            || (*head_ref)->Priority
            >= new_node->Priority) {
        new_node->next = *head_ref;
        *head_ref = new_node;
    }else
    {
        current = *head_ref;
        while (current->next != NULL
                && current->next->Priority < new_node->Priority) {
            current = current->next;
        }
        new_node->next = current->next;
        current->next = new_node;
    }
}
int Update_Current_ActiveDNS(char* CurrentActiveDNS)
{
    FILE *fp = NULL;
    char buf[64] = {0};
    char* token = NULL;
    
    memset(CurrentActiveDNS,0,sizeof(CurrentActiveDNS));

    if((fp = fopen(RESOLV_CONF_FILE, "r")) == NULL)
    {
        CcspTraceError(("%s %d - Open %s error!\n", __FUNCTION__, __LINE__, RESOLV_CONF_FILE));
#ifdef ENABLE_FEATURE_TELEMETRY2_0
		t2_event_d("SYST_ERROR_DNSFAIL", 1);
#endif
        return RETURN_ERR;
    }

    while((fgets(buf, sizeof(buf), fp)) != NULL)
    {
        token = strtok(buf, " ");
        if(!strcmp(token,"nameserver"))
    	{
            token = strtok(NULL, " ");
            if(strlen(token)>0)
            {
                if(strlen(CurrentActiveDNS) > 0 )
	        	{
                    strcat(CurrentActiveDNS,",");
                }
        		if(token[strlen(token)-1] == '\n')
		        {
                    token[strlen(token)-1] = '\0';
        		}
                strcat(CurrentActiveDNS,token);
            }
    	}
        memset(buf, 0 , sizeof(buf));
        token = NULL;
    }
    if (fp != NULL)
    {
        fclose(fp);
    }    
    return RETURN_OK;
}

ANSC_STATUS Update_Interface_Status()
{
    struct IFACE_INFO *head = NULL;
    DEVICE_NETWORKING_MODE devMode = GATEWAY_MODE;
    CHAR    InterfaceAvailableStatus[BUFLEN_64]  = {0};
    CHAR    InterfaceIpStatus[BUFLEN_64]  = {0};
    CHAR    InterfaceActiveStatus[BUFLEN_64]     = {0};
    CHAR    CurrentActiveInterface[BUFLEN_64] = {0};
    CHAR    CurrentStandbyInterface[BUFLEN_64] = {0};
    CHAR    CurrentActiveDNS[BUFLEN_256] ={0};

    CHAR    prevInterfaceAvailableStatus[BUFLEN_64]  = {0};
    CHAR    prevInterfaceActiveStatus[BUFLEN_64]     = {0};
    CHAR    prevCurrentActiveInterface[BUFLEN_64] = {0};
    CHAR    prevCurrentStandbyInterface[BUFLEN_64] = {0};
    CHAR    prevCurrentActiveDNS[BUFLEN_256] = {0};

#ifdef RBUS_BUILD_FLAG_ENABLE
    CHAR    CurrentWanStatus[BUFLEN_16] = "Down";
    bool    publishAvailableStatus  = FALSE;
    bool    publishActiveStatus = FALSE;
    bool    publishCurrentActiveInf  = FALSE;
    bool    publishCurrentStandbyInf = FALSE;
    bool    publishCurrentActiveDNS = FALSE;
#endif
    int uiLoopCount;

    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if (pWanConfigData != NULL)
    {
        DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);
        devMode = pWanDmlData->DeviceNwMode;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    int TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();
    for (uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanIfaceData->Selection.Enable == TRUE)
            {
                //TODO: NEW_DESIGN revisit this code for Name and status
                for(int virIf_id=0; virIf_id< pWanIfaceData->NoOfVirtIfs; virIf_id++)
                {
                //Note: This function uses first Virtual interface as primary to set status information.
                DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, virIf_id);
                struct IFACE_INFO *newIface = calloc(1, sizeof( struct IFACE_INFO));
                newIface->next = NULL;

                newIface->Priority = pWanIfaceData->Selection.Priority;
                if(pWanIfaceData->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP)
                {
                    snprintf(newIface->AvailableStatus, sizeof(newIface->AvailableStatus), "%s,1", pWanIfaceData->DisplayName);
                }else
                    snprintf(newIface->AvailableStatus, sizeof(newIface->AvailableStatus), "%s,0", pWanIfaceData->DisplayName);

                if((pWanIfaceData->Selection.Status == WAN_IFACE_ACTIVE) &&
                   ((pWanIfaceData->IfaceType == REMOTE_IFACE &&
                     p_VirtIf->Status == WAN_IFACE_STATUS_UP &&
                     p_VirtIf->RemoteStatus == WAN_IFACE_STATUS_UP) ||
                    (pWanIfaceData->IfaceType == LOCAL_IFACE &&
                     p_VirtIf->Status == WAN_IFACE_STATUS_UP)) )
                {
                    snprintf(newIface->ActiveStatus, sizeof(newIface->ActiveStatus), "%s,1", pWanIfaceData->DisplayName);
                }else
                    snprintf(newIface->ActiveStatus, sizeof(newIface->ActiveStatus), "%s,0", pWanIfaceData->DisplayName);

                if((p_VirtIf->Status == WAN_IFACE_STATUS_UP || 
                    p_VirtIf->Status == WAN_IFACE_STATUS_STANDBY || 
                    p_VirtIf->Status == WAN_IFACE_STATUS_VALID) &&
                    (pWanIfaceData->IfaceType != REMOTE_IFACE || p_VirtIf->RemoteStatus == WAN_IFACE_STATUS_UP)) //If its a remote interface, check remote status
                {
                    snprintf(newIface->InterfaceIpStatus, sizeof(newIface->InterfaceIpStatus), "%s,1", pWanIfaceData->DisplayName);
                }else
                    snprintf(newIface->InterfaceIpStatus, sizeof(newIface->InterfaceIpStatus), "%s,0", pWanIfaceData->DisplayName);

                /*
                 * In Gateway Mode, CurrentActiveInterface should be an actual virtual Interface Name
                 * In Modem/Extender Mode, CurrentActiveInterface should be always Mesh Interface Name
                 */

                if(pWanIfaceData->Selection.Status == WAN_IFACE_ACTIVE)
                {
                    snprintf(newIface->CurrentActive, sizeof(newIface->CurrentActive), "%s", (devMode == GATEWAY_MODE) ? p_VirtIf->Name : MESH_IFNAME);
#ifdef RBUS_BUILD_FLAG_ENABLE
                    snprintf(CurrentWanStatus,sizeof(CurrentWanStatus), "%s", (p_VirtIf->Status == WAN_IFACE_STATUS_UP)?"Up":"Down");
#endif
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
                    if (devMode == GATEWAY_MODE)
                    {
                        /* Update Only for Gateway mode. Wan IP Interface entry not added in PAM for MODEM_MODE */
                        WanMgr_RdkBus_setWanIpInterfaceData(p_VirtIf);
                    }
#endif
                }
                else if(pWanIfaceData->Selection.Status == WAN_IFACE_SELECTED)
                {
                    snprintf(newIface->CurrentStandby, sizeof(newIface->CurrentStandby), "%s", p_VirtIf->Name);
                }

                /* Sort the link list based on priority */
                SortedInsert(&head, newIface);
            }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    struct IFACE_INFO* pHead = head;
    struct IFACE_INFO* tmp = NULL;
    while(pHead!= NULL)
    {
        if(strlen(CurrentActiveInterface)>0 && strlen(pHead->CurrentActive)>0)
        {
            strcat(CurrentActiveInterface,",");
        }
        strcat(CurrentActiveInterface,pHead->CurrentActive);

        if(strlen(CurrentStandbyInterface)>0 && strlen(pHead->CurrentStandby)>0)
        {
            strcat(CurrentStandbyInterface,",");
        }
        strcat(CurrentStandbyInterface,pHead->CurrentStandby);

        if(strlen(InterfaceAvailableStatus)>0 && strlen(pHead->AvailableStatus)>0)
        {
            strcat(InterfaceAvailableStatus,"|");
        }
        strcat(InterfaceAvailableStatus,pHead->AvailableStatus);

        if(strlen(InterfaceActiveStatus)>0 && strlen(pHead->ActiveStatus)>0)
        {
            strcat(InterfaceActiveStatus,"|");
        }
        strcat(InterfaceActiveStatus,pHead->ActiveStatus);
        if(strlen(InterfaceIpStatus)>0 && strlen(pHead->InterfaceIpStatus)>0)
        {
            strcat(InterfaceIpStatus,"|");
        }
        strcat(InterfaceIpStatus,pHead->InterfaceIpStatus);
        tmp = pHead->next;
        free(pHead);
        pHead = tmp;
    }

    pWanConfigData = WanMgr_GetConfigData_locked();
    if (pWanConfigData != NULL)
    {
        DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);
        if(strcmp(pWanDmlData->InterfaceAvailableStatus,InterfaceAvailableStatus) != 0)
        {
            strncpy(prevInterfaceAvailableStatus,pWanDmlData->InterfaceAvailableStatus, sizeof(prevInterfaceAvailableStatus)-1);
            memset(pWanDmlData->InterfaceAvailableStatus,0, sizeof(pWanDmlData->InterfaceAvailableStatus));
            strncpy(pWanDmlData->InterfaceAvailableStatus,InterfaceAvailableStatus, sizeof(pWanDmlData->InterfaceAvailableStatus) - 1);
#ifdef RBUS_BUILD_FLAG_ENABLE
            publishAvailableStatus = TRUE;
#endif
        }
        if(strcmp(pWanDmlData->InterfaceActiveStatus,InterfaceActiveStatus) != 0)
        {
            strncpy(prevInterfaceActiveStatus,pWanDmlData->InterfaceActiveStatus, sizeof(prevInterfaceActiveStatus)-1);
            memset(pWanDmlData->InterfaceActiveStatus,0, sizeof(pWanDmlData->InterfaceActiveStatus));
            strncpy(pWanDmlData->InterfaceActiveStatus,InterfaceActiveStatus, sizeof(pWanDmlData->InterfaceActiveStatus)-1);
#ifdef RBUS_BUILD_FLAG_ENABLE
            publishActiveStatus = TRUE;
#endif
        }

        if(strcmp(pWanDmlData->InterfaceIpStatus,InterfaceIpStatus) != 0)
        {
#ifdef RBUS_BUILD_FLAG_ENABLE
            WanMgr_Rbus_String_EventPublish_OnValueChange(WANMGR_EVENT_WAN_INTERFACEIPSTATUS, pWanDmlData->InterfaceIpStatus, InterfaceIpStatus);
#endif
            strncpy(pWanDmlData->InterfaceIpStatus,InterfaceIpStatus, sizeof(pWanDmlData->InterfaceIpStatus)-1);
        }

    	if(RETURN_OK == Update_Current_ActiveDNS(CurrentActiveDNS))
    	{
            if(strcmp(pWanDmlData->CurrentActiveDNS,CurrentActiveDNS) != 0)
            {
                CcspTraceInfo(("%s %d CurrentActiveDNS- [%s] [%s]\n",__FUNCTION__,__LINE__,pWanDmlData->CurrentActiveDNS,CurrentActiveDNS));
 	            strncpy(prevCurrentActiveDNS,pWanDmlData->CurrentActiveDNS,sizeof(prevCurrentActiveDNS)-1);
                memset(pWanDmlData->CurrentActiveDNS,0, sizeof(pWanDmlData->CurrentActiveDNS));
                strncpy(pWanDmlData->CurrentActiveDNS,CurrentActiveDNS, sizeof(pWanDmlData->CurrentActiveDNS) - 1);
#ifdef RBUS_BUILD_FLAG_ENABLE
                publishCurrentActiveDNS = TRUE;
#endif
                CcspTraceInfo(("%s %d - SYS_INFO_DNS_updated - old : [%s] new : [%s]\n",__FUNCTION__,__LINE__,prevCurrentActiveDNS,CurrentActiveDNS));
				
#ifdef ENABLE_FEATURE_TELEMETRY2_0
				t2_event_d("SYS_INFO_DNS_updated", 1);
				struct timespec uptime;
	            long long uptime_ms = 0;
	            char uptime_str[32]="0";
				static bool dns_start_sent = 0; 
			
	        
				if (!dns_start_sent) {
	               if (CurrentActiveDNS && strlen(CurrentActiveDNS) > 0 &&
                       strcmp(CurrentActiveDNS, "127.0.0.1") != 0 &&
                       strcmp(CurrentActiveDNS, "::1") != 0 ) { 
					   if (clock_gettime(CLOCK_MONOTONIC, &uptime) == 0)
                       {
                           uptime_ms = (long long)uptime.tv_sec * 1000LL + (uptime.tv_nsec / 1000000LL);
                       }
				       snprintf(uptime_str, sizeof(uptime_str), "%lld", uptime_ms);
					   
	                   t2_event_s("SYST_INFO_DNSSTART_split", uptime_str);
				       dns_start_sent = 1; 
				   }
				}
#endif
            }
        }

        CcspTraceInfo(("%s %d -CurrentActiveInterface- [%s] [%s]\n",__FUNCTION__,__LINE__,pWanDmlData->CurrentActiveInterface,CurrentActiveInterface));
        if(strlen(CurrentActiveInterface) > 0)
        {
            if(strcmp(pWanDmlData->CurrentActiveInterface,CurrentActiveInterface) != 0 )
            {
                strncpy(prevCurrentActiveInterface,pWanDmlData->CurrentActiveInterface, sizeof(prevCurrentActiveInterface) - 1);
                memset(pWanDmlData->CurrentActiveInterface, 0, sizeof(pWanDmlData->CurrentActiveInterface));
                strncpy(pWanDmlData->CurrentActiveInterface,CurrentActiveInterface, sizeof(pWanDmlData->CurrentActiveInterface) - 1);
#ifdef RBUS_BUILD_FLAG_ENABLE
                publishCurrentActiveInf = TRUE;
#endif //RBUS_BUILD_FLAG_ENABLE
            }
        }
        else
        {
            CcspTraceInfo(("%s %d -CurrentActiveInterface- No update\n",__FUNCTION__,__LINE__));
        }

#ifdef RBUS_BUILD_FLAG_ENABLE
        if(strcmp(pWanDmlData->CurrentStatus, CurrentWanStatus) != 0)
        { 
            CcspTraceInfo(("%s %d -Publishing Wan CurrentStatus change - old status [%s] => new status [%s]\n",__FUNCTION__,__LINE__,pWanDmlData->CurrentStatus, CurrentWanStatus));
            WanMgr_Rbus_String_EventPublish_OnValueChange(WANMGR_CONFIG_WAN_CURRENT_STATUS, pWanDmlData->CurrentStatus, CurrentWanStatus);
            memset(pWanDmlData->CurrentStatus, 0, sizeof(pWanDmlData->CurrentStatus));
            strncpy(pWanDmlData->CurrentStatus, CurrentWanStatus, sizeof(pWanDmlData->CurrentStatus) - 1);
            if(strlen(CurrentActiveInterface) > 0 && strncmp(CurrentWanStatus,"Up",sizeof(CurrentWanStatus)) == 0)
            {
                DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked((devMode == GATEWAY_MODE) ? CurrentActiveInterface : CELLULARMGR_WAN_NAME);
                if(pVirtIf != NULL)
                {
                    WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_WAN_UP);
                    WanMgr_VirtualIfaceData_release(pVirtIf);
                }
           }
	    
        }
#endif

        CcspTraceInfo(("%s %d -CurrentStandbyInterface- [%s] [%s]\n",__FUNCTION__,__LINE__,pWanDmlData->CurrentStandbyInterface,CurrentStandbyInterface));
        if(strcmp(pWanDmlData->CurrentStandbyInterface,CurrentStandbyInterface) != 0)
        {
            strncpy(prevCurrentStandbyInterface, pWanDmlData->CurrentStandbyInterface, sizeof(prevCurrentStandbyInterface) - 1);
            memset(pWanDmlData->CurrentStandbyInterface, 0, sizeof(pWanDmlData->CurrentStandbyInterface));
            strncpy(pWanDmlData->CurrentStandbyInterface, CurrentStandbyInterface, sizeof(pWanDmlData->CurrentStandbyInterface) - 1);
#ifdef RBUS_BUILD_FLAG_ENABLE
            publishCurrentStandbyInf = TRUE;
#endif //RBUS_BUILD_FLAG_ENABLE
        }
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }
#ifdef RBUS_BUILD_FLAG_ENABLE
    if(publishCurrentActiveInf == TRUE)
    {
        WanMgr_Rbus_String_EventPublish_OnValueChange(WANMGR_CONFIG_WAN_CURRENTACTIVEINTERFACE, prevCurrentActiveInterface, CurrentActiveInterface);
    }

    if(publishCurrentStandbyInf == TRUE)
    {
        WanMgr_Rbus_String_EventPublish_OnValueChange(WANMGR_CONFIG_WAN_CURRENTSTANDBYINTERFACE, prevCurrentStandbyInterface, CurrentStandbyInterface);
    }
    if(publishAvailableStatus == TRUE)
    {
        WanMgr_Rbus_String_EventPublish_OnValueChange(WANMGR_CONFIG_WAN_INTERFACEAVAILABLESTATUS, prevInterfaceAvailableStatus, InterfaceAvailableStatus);
    }
    if(publishActiveStatus == TRUE)
    {
        WanMgr_Rbus_String_EventPublish_OnValueChange(WANMGR_CONFIG_WAN_INTERFACEACTIVESTATUS, prevInterfaceActiveStatus, InterfaceActiveStatus);
    }
    if(publishCurrentActiveDNS == TRUE)
    {
    	WanMgr_Rbus_String_EventPublish_OnValueChange(WANMGR_CONFIG_WAN_CURRENTACTIVEDNS,prevCurrentActiveDNS,CurrentActiveDNS);
    }

#endif //RBUS_BUILD_FLAG_ENABLE
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_Publish_WanStatus(UINT IfaceIndex, UINT VirId)
{
    char param_name[256] = {0};
    static UINT PrevWanStatus = 0;
    UINT tmpCurrWanStatus = 0,
         tmpWanStatusSub  = 0;
    WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(IfaceIndex);
    if(pWanDmlIfaceData != NULL)
    {
        DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
        DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, VirId);
   
        tmpCurrWanStatus = p_VirtIf->Status; 
        tmpWanStatusSub  = pWanIfaceData->Sub.WanStatusSub;

        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

        if (tmpCurrWanStatus != PrevWanStatus)
        {
            PrevWanStatus = tmpCurrWanStatus;
            if (tmpWanStatusSub)
            {
                memset(param_name, 0, sizeof(param_name));
                _ansc_sprintf(param_name, WANMGR_IFACE_WAN_STATUS, (IfaceIndex+1), (VirId+1));
#ifdef RBUS_BUILD_FLAG_ENABLE
                WanMgr_Rbus_String_EventPublish(param_name, &PrevWanStatus);
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
                char DmlNameV1[128] = {0};
                snprintf(DmlNameV1, sizeof(DmlNameV1), WANMGR_V1_INFACE_TABLE".%d"WANMGR_V1_INFACE_WAN_STATUS_SUFFIX,(IfaceIndex+1));
                CcspTraceInfo(("%s-%d : V1 DML Publish Event %s\n", __FUNCTION__, __LINE__,DmlNameV1 ));
                WanMgr_Rbus_String_EventPublish(DmlNameV1, &PrevWanStatus);
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
#endif
            }
        }
    }
    return ANSC_STATUS_SUCCESS;
}
