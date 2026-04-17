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

#include "wanmgr_dml_apis.h"

#include "wanmgr_data.h"
#include "wanmgr_controller.h"
#include "wanmgr_rdkbus_utils.h"
#include "secure_wrapper.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_webconfig_apis.h"

BOOL
WanManager_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    BOOL ret = FALSE;

    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);

        if (strcmp(ParamName, "Policy") == 0)
        {
            WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((0));
            if (pWanIfaceGroup != NULL)
            {
                *puLong = pWanIfaceGroup->Policy;
                WanMgrDml_GetIfaceGroup_release();
            }

            ret = TRUE;
        }
        if (strcmp(ParamName, "RestorationDelay") == 0)
        {
            *puLong= pWanDmlData->RestorationDelay;
            ret = TRUE;
        }

        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    return ret;
}

BOOL
WanManager_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    BOOL ret = FALSE;
    ANSC_STATUS retStatus;

    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);

        if (strcmp(ParamName, "Policy") == 0)
        {
#if !defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
            if(uValue == PARALLEL_SCAN)
            {
                CcspTraceError(("%s: PARALLEL_SCAN Not supported \n",__FUNCTION__));
                ret = FALSE;
            }else
#endif
            {
                retStatus = WanMgr_RdkBus_setWanPolicy((DML_WAN_POLICY)uValue, 0); 
                if(retStatus == ANSC_STATUS_SUCCESS)
                {
                    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((0)); 
                    if (pWanIfaceGroup != NULL)
                    {
                        if(pWanIfaceGroup->Policy != uValue)
                        {
                            pWanIfaceGroup->Policy = uValue;
                            pWanIfaceGroup->ConfigChanged = TRUE;
                        }
                        WanMgrDml_GetIfaceGroup_release();
                    }
                    ret = TRUE;
                }
            }
        }
        if (strcmp(ParamName, "RestorationDelay") == 0)
        {
            retStatus = WanMgr_RdkBus_setRestorationDelay(uValue);
            if(retStatus == ANSC_STATUS_SUCCESS)
            {
                if(pWanDmlData->RestorationDelay != uValue)
                {
                    pWanDmlData->RestorationDelay = uValue;
                }
                ret = TRUE;
            }
        }

        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    return ret;
}

BOOL
WanManager_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    BOOL ret = FALSE;

    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);
        if (strcmp(ParamName, "Enable") == 0)
        {
            *pBool= pWanDmlData->Enable;
            ret = TRUE;
        }

        if (strcmp(ParamName, "ResetActiveInterface") == 0)
        {
            WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((0)); 
            if (pWanIfaceGroup != NULL)
            {
                *pBool = pWanIfaceGroup->ResetSelectedInterface;
                WanMgrDml_GetIfaceGroup_release();
            }
            ret = TRUE;
        }

        if (strcmp(ParamName, "AllowRemoteInterfaces") == 0)
        {
            *pBool= pWanDmlData->AllowRemoteInterfaces;
            ret = TRUE;
        }

        if (strcmp(ParamName, "ResetDefaultConfig") == 0)
        {
            *pBool= FALSE;
            ret = TRUE;
        }

        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    return ret;
}

BOOL WanManager_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    BOOL ret = FALSE;
    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();

    if(pWanConfigData != NULL)
    {
        DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);

        if (strcmp(ParamName, "Data") == 0)
        {
            char *webConf = NULL;
            size_t webSize = 0;

            webConf = AnscBase64Decode(pString, &webSize);
            if(!webConf)
            {
                CcspTraceError(("%s: Failed to decode webconfig blob..\n",__FUNCTION__));
                WanMgrDml_GetConfigData_release(pWanConfigData);
                return ret;
            }
            if ( ANSC_STATUS_SUCCESS == WanMgrDmlWanDataSet(webConf,webSize) )
            {
                CcspTraceInfo(("%s Success in parsing web config blob..\n",__FUNCTION__));
                ret = TRUE;
            }
            else
            {
                CcspTraceError(("%s Failed to parse webconfig blob..\n",__FUNCTION__));
            }
            AnscFreeMemory(webConf);
        }

        else if (strcmp(ParamName, "WanFailoverData") == 0)
        {
            char *webConf = NULL;
            size_t webSize = 0;

            webConf = AnscBase64Decode(pString, &webSize);
            if(!webConf)
            {
                CcspTraceError(("%s: Failed to decode webconfig blob..\n",__FUNCTION__));
                WanMgrDml_GetConfigData_release(pWanConfigData);
                return ret;
            }
            if ( ANSC_STATUS_SUCCESS == WanMgrDmlWanFailOverDataSet(webConf,webSize) )
            {
                CcspTraceInfo(("%s Success in parsing web config blob..\n",__FUNCTION__));
                ret = TRUE;
            }
            else
            {
                CcspTraceError(("%s Failed to parse webconfig blob..\n",__FUNCTION__));
            }
            AnscFreeMemory(webConf);

        }

        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    return ret;
}

LONG WanManager_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pulSize)
{
    LONG ret = -1;

    if (strcmp(ParamName, "Data") == 0)
    {
        /* Data value should be empty for all get */
        snprintf(pValue, *pulSize, "%s", "");
        ret = 0;
    }
    else if (strcmp(ParamName, "Version") == 0)
    {
        snprintf(pValue, *pulSize, "%s", WAN_MANAGER_VERSION);
        ret = 0;
    }
    else if (strcmp(ParamName, "WanFailoverData") == 0)
    {
        /* Data value should be empty for all get */
        snprintf(pValue, *pulSize, "%s", "");
        ret = 0;
    }

    return ret;
}

BOOL WanManager_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    BOOL ret = FALSE;

    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);


        if (strcmp(ParamName, "Enable") == 0)
        {
            WanMgr_RdkBus_setWanEnableToPsm(bValue);
            pWanDmlData->Enable = bValue;
            ret = TRUE;
        }

        if (strcmp(ParamName, "ResetActiveInterface") == 0)
        {
            WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((0)); 
            if (pWanIfaceGroup != NULL)
            {
                pWanIfaceGroup->ResetSelectedInterface = bValue;
                WanMgrDml_GetIfaceGroup_release();
            }
            ret = TRUE;
        }

        if (strcmp(ParamName, "AllowRemoteInterfaces") == 0)
        {
#ifdef WAN_FAILOVER_SUPPORTED
            pWanDmlData->AllowRemoteInterfaces = bValue;
            WanMgr_RdkBus_setAllowRemoteIfaceToPsm(bValue);
            ret = TRUE;
#else
            ret = FALSE;
#endif
        }

        if (strcmp(ParamName, "ResetDefaultConfig") == 0)
        {
            if(bValue == TRUE)
            {
                unlink("/nvram/.wanmanager_upgrade");
                v_secure_system("sed -i '/dmsb.wanmanager./d' /nvram/bbhm_bak_cfg.xml");
            }

            ret = TRUE;
        }

        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    return ret;
}
ULONG WanManager_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

ULONG WanManager_Commit(ANSC_HANDLE hInsContext)
{
    ULONG ret = 0;

    return ret;
}

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
BOOL
WanManagerGroup_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return TRUE;
}

ULONG
WanManagerGroup_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

ULONG WanManagerGroup_GetEntryCount(ANSC_HANDLE hInsContext)
{
    return WanMgr_GetTotalNoOfGroups();
}

ANSC_HANDLE WanManagerGroup_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber)
{
    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(nIndex);
    if(pWanIfaceGroup != NULL)
    {
        *pInsNumber = nIndex + 1;
        WanMgrDml_GetIfaceGroup_release();

        return pWanIfaceGroup;
    }

    return NULL;
}

BOOL
WanManagerGroup_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    BOOL ret = FALSE;

    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(((WANMGR_IFACE_GROUP*) hInsContext)->groupIdx);
    if(pWanIfaceGroup != NULL)
    {

        if (strcmp(ParamName, "ResetSelectedInterface") == 0)
        {
            *pBool= pWanIfaceGroup->ResetSelectedInterface;
            ret = TRUE;
        }

        WanMgrDml_GetIfaceGroup_release();
    }

    return ret;
}

BOOL WanManagerGroup_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    BOOL ret = FALSE;

    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(((WANMGR_IFACE_GROUP*) hInsContext)->groupIdx);
    if(pWanIfaceGroup != NULL)
    {
        if (strcmp(ParamName, "ResetSelectedInterface") == 0)
        {
            CcspTraceInfo(("%s %d group (%d), ResetSelectedInterface set to %s \n", __FUNCTION__, __LINE__,pWanIfaceGroup->groupIdx, bValue?"TRUE":"FALSE"));
            if(bValue == TRUE && pWanIfaceGroup->SelectedInterface == 0)
            {
                CcspTraceInfo(("%s %d  Group (%d) Interface is not selected yet. ResetSelectedInterface is not required \n", __FUNCTION__, __LINE__,pWanIfaceGroup->groupIdx));
            }else
            {
                pWanIfaceGroup->ResetSelectedInterface = bValue;
            }
            ret = TRUE;
        }
        WanMgrDml_GetIfaceGroup_release();
    }

    return ret;
}

BOOL
WanManagerGroup_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    BOOL ret = FALSE;

    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(((WANMGR_IFACE_GROUP*) hInsContext)->groupIdx);
    if(pWanIfaceGroup != NULL)
    {
        if (strcmp(ParamName, "Policy") == 0)
        {
            *puLong= pWanIfaceGroup->Policy;
            ret = TRUE;
        }
        WanMgrDml_GetIfaceGroup_release();
    }

    return ret;
}

BOOL
WanManagerGroup_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    BOOL ret = FALSE;
    ANSC_STATUS retStatus;

    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(((WANMGR_IFACE_GROUP*) hInsContext)->groupIdx);
    if(pWanIfaceGroup != NULL)
    {
        if (strcmp(ParamName, "Policy") == 0)
        {
            retStatus = WanMgr_RdkBus_setWanPolicy((DML_WAN_POLICY)uValue, pWanIfaceGroup->groupIdx);
            if(retStatus == ANSC_STATUS_SUCCESS)
            {
                if(pWanIfaceGroup->Policy != uValue)
                {
                    pWanIfaceGroup->Policy = uValue;
                    pWanIfaceGroup->ConfigChanged = TRUE;
                }
                ret = TRUE;
            }
        }
        WanMgrDml_GetIfaceGroup_release();
    }

    return ret;
}

ULONG WanManagerGroup_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

ULONG WanManagerGroup_Commit(ANSC_HANDLE hInsContext)
{
    ULONG ret = 0;

    return ret;
}
#endif /* WAN_MANAGER_UNIFICATION_ENABLED */


/***********************************************************************

 APIs for Object:

    X_RDK_WanManager.DnsConnectivityCheck.

    *  WanMgr_DnsConnectivityCheck_GetParamBoolValue
    *  WanMgr_DnsConnectivityCheck_SetParamBoolValue

***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanMgr_DnsConnectivityCheck_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool);

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WanMgr_DnsConnectivityCheck_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    BOOL ret = FALSE;

    if (strcmp(ParamName, "Enable") == 0)
    {
       *pBool= WanMgr_GetDnsConnectivityCheck();
        ret = TRUE;
    }
    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanMgr_DnsConnectivityCheck_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue);

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL WanMgr_DnsConnectivityCheck_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    BOOL ret = FALSE;

    if (strcmp(ParamName, "Enable") == 0)
    {
        if ( WanMgr_SetDnsConnectivityCheck(bValue) == ANSC_STATUS_SUCCESS)
        {
            ret = TRUE;
        }
    }
    return ret;
}

