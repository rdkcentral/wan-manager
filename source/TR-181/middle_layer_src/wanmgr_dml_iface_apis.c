#if !defined(WAN_MANAGER_UNIFICATION_ENABLED)
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

#include "wanmgr_dml_iface_apis.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_dhcpv4_apis.h"
#include "wanmgr_dhcpv6_apis.h"
#include "wanmgr_data.h"
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)
#include "wanmgr_utils.h"
#endif

extern WANMGR_DATA_ST gWanMgrDataBase;
/***********************************************************************

 APIs for Object:

    X_RDK_WanManager.CPEInterface.

    *  WanIf_GetEntryCount
    *  WanIf_GetEntry
    *  WanIf_GetParamStringValue
    *  WanIf_SetParamStringValue
    *  WanIf_GetParamBoolValue
    *  WanIf_SetParamBoolValue
    *  WanIf_Validate
    *  WanIf_Commit
    *  WanIf_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG WanIf_GetEntryCount(ANSC_HANDLE hInsContext);

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG WanIf_GetEntryCount(ANSC_HANDLE hInsContext)
{
    ULONG count = 0;
    count = (ULONG)WanMgr_IfaceData_GetTotalWanIface();
    return count;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE WanIf_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber);

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE WanIf_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber)
{
    ANSC_HANDLE pDmlEntry = NULL;

    WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(nIndex);
    if(pWanDmlIfaceData != NULL)
    {
        *pInsNumber = nIndex + 1;
        pDmlEntry = (ANSC_HANDLE) pWanDmlIfaceData;

        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    return pDmlEntry;
}

/**********************************************************************

    caller:     owner of this object

    prototype:
        BOOL
        WanIf_IsUpdated
            (
                ANSC_HANDLE                 hInsContext
            );

    description:
        This function is checking whether the table is updated or not.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     TRUE or FALSE.

**********************************************************************/

BOOL
WanIf_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{

    if( gWanMgrDataBase.IfaceCtrl.update == 1)
    {
        return FALSE;
    }
    else
    {
        gWanMgrDataBase.IfaceCtrl.update = 1;
        return TRUE;
    }
}

/**********************************************************************

    caller:     owner of this object

    prototype:
        ULONG
        WanIf_Synchronize
            (
                ANSC_HANDLE                 hInsContext
            );

    description:
        This function is called to synchronize the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/

ULONG
WanIf_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG WanIf_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize);

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG WanIf_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    ULONG ret = -1;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            ///* check the parameter name and return the corresponding value */
            if (strcmp(ParamName, "Name") == 0)
            {
               /* collect value */
               if ( ( sizeof( pWanDmlIface->Name ) - 1 ) < *pUlSize )
               {
                   AnscCopyString( pValue, pWanDmlIface->Name );
                   ret = 0;
               }
               else
               {
                   *pUlSize = sizeof( pWanDmlIface->Name );
                   ret = 1;
               }
            }
            else if (strcmp(ParamName, "DisplayName") == 0)
            {
               /* collect value */
               if ( ( sizeof( pWanDmlIface->DisplayName ) - 1 ) < *pUlSize )
               {
                   AnscCopyString( pValue, pWanDmlIface->DisplayName );
                   ret = 0;
               }
               else
               {
                   *pUlSize = sizeof( pWanDmlIface->DisplayName );
                   ret = 1;
               }
            }

            if (strcmp(ParamName, "CustomConfigPath") == 0)
            {
               /* collect value */
               if ( ( sizeof( pWanDmlIface->CustomConfigPath ) - 1 ) < *pUlSize )
               {
                   AnscCopyString( pValue, pWanDmlIface->CustomConfigPath );
                   ret = 0;
               }
               else
               {
                   *pUlSize = sizeof( pWanDmlIface->CustomConfigPath );
                   ret = 1;
               }
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIf_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString);

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIf_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Name") == 0)
            {
                AnscCopyString(pWanDmlIface->Name, pString);
                ret = TRUE;
            }

            if (strcmp(ParamName, "CustomConfigPath") == 0)
            {
                AnscCopyString(pWanDmlIface->CustomConfigPath, pString);
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)
                WanMgr_SetRestartWanInfo(WAN_CUSTOM_CONFIG_PATH_PARAM_NAME, pWanDmlIface->uiIfaceIdx, pString);
#endif
                ret = TRUE;
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIf_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool);

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
BOOL WanIf_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            //* check the parameter name and return the corresponding value */
            if (strcmp(ParamName, "EnableOperStatusMonitor") == 0)
            {
                *pBool = pWanDmlIface->MonitorOperStatus;
                ret = TRUE;
            }

            if (strcmp(ParamName, "EnableCustomConfig") == 0)
            {
                *pBool = pWanDmlIface->CustomConfigEnable;
                ret = TRUE;
            }

            if (strcmp(ParamName, "ConfigureWanEnable") == 0)
            {
                *pBool = pWanDmlIface->WanConfigEnabled;
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIf_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue);

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
BOOL WanIf_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "ConfigureWanEnable") == 0)
            {
                pWanDmlIface->WanConfigEnabled  = bValue;
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)
                WanMgr_SetRestartWanInfo(WAN_CONFIGURE_WAN_ENABLE_PARAM_NAME, pWanDmlIface->uiIfaceIdx, pWanDmlIface->WanConfigEnabled?"true":"false");
#endif
                ret = TRUE;
            }
            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "EnableCustomConfig") == 0)
            {
                pWanDmlIface->CustomConfigEnable  = bValue;
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)
                WanMgr_SetRestartWanInfo(WAN_ENABLE_CUSTOM_CONFIG_PARAM_NAME, pWanDmlIface->uiIfaceIdx, pWanDmlIface->CustomConfigEnable?"true":"false");
#endif
                ret = TRUE;
            }
            if (strcmp(ParamName, "EnableOperStatusMonitor") == 0)
            {
                pWanDmlIface->MonitorOperStatus = bValue;
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)
                WanMgr_SetRestartWanInfo(WAN_ENABLE_OPER_STATUS_MONITOR_PARAM_NAME, pWanDmlIface->uiIfaceIdx, pWanDmlIface->MonitorOperStatus?"true":"false");
#endif
                ret = TRUE;
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}



/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIf_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL WanIf_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIf_Commit(ANSC_HANDLE hInsContext);

    description:
        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIf_Commit(ANSC_HANDLE hInsContext)
{
    return 0;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIf_Rollback(ANSC_HANDLE hInsContext);

    description:
        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIf_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    X_RDK_WanManager.CPEInterface.{i}.Wan.

    *  WanIfCfg_GetParamUlongValue
    *  WanIfCfg_SetParamUlongValue
    *  WanIfCfg_GetParamBoolValue
    *  WanIfCfg_SetParamBoolValue
    *  WanIfCfg_GetParamIntValue
    *  WanIfCfg_SetParamIntValue
    *  WanIfCfg_Validate
    *  WanIfCfg_Commit
    *  WanIfCfg_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfCfg_GetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int* pInt);

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfCfg_GetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int* pInt)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Priority") == 0)
            {
                *pInt = pWanDmlIface->Selection.Priority;
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfCfg_SetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int iValue);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated int value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfCfg_SetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int iValue)
{
    BOOL ret = FALSE;
    UINT uiTotalIfaces = -1;
    INT  IfIndex = 0;
    BOOL Status = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);
            IfIndex =  pWanDmlIface->uiIfaceIdx;
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Priority") == 0)
            {
                uiTotalIfaces = WanIf_GetEntryCount(NULL);

                if ( WanManager_CheckGivenPriorityExists(IfIndex, uiTotalIfaces, iValue, &Status) == ANSC_STATUS_SUCCESS )
                {
                    if(Status)
                    {
                        CcspTraceError(("%s Another interface with same type is already exists with given priority \n", __FUNCTION__));
                        return FALSE;
                    }
                    WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
                    if(pWanDmlIfaceData != NULL)
                    {
                        pWanDmlIface->Selection.Priority = iValue;
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        return TRUE;
                    }
                }
            }
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfCfg_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong);

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfCfg_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and return the corresponding value */
            if (strcmp(ParamName, "SelectionTimeout") == 0)
            {
                *puLong = pWanDmlIface->Selection.Timeout;
                ret = TRUE;
            }
#if !RBUS_BUILD_FLAG_ENABLE
            if (strcmp(ParamName, "Status") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->Status;
                ret = TRUE;
            }
#endif
            if (strcmp(ParamName, "Type") == 0)
            {
                *puLong = pWanDmlIface->Type;
                ret = TRUE;
            }
            if (strcmp(ParamName, "Priority") == 0)
            {
                *puLong = pWanDmlIface->Selection.Priority;
                ret = TRUE;
            }
#if !RBUS_BUILD_FLAG_ENABLE
            if (strcmp(ParamName, "LinkStatus") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->VLAN.Status;
                ret = TRUE;
            }

#endif
            if (strcmp(ParamName, "OperationalStatus") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->OperationalStatus;
                ret = TRUE;
            }
	    if (strcmp(ParamName, "Group") == 0)
            {
                *puLong = pWanDmlIface->Selection.Group;
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfCfg_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfCfg_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    BOOL ret = FALSE;
    UINT uiTotalIfaces = -1;
    INT  IfIndex = 0;
    INT  priority;
    BOOL Status = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "SelectionTimeout") == 0)
            {
                pWanDmlIface->Selection.Timeout = uValue;
                ret = TRUE;
            }
            if( strcmp(ParamName, "Group") == 0)
            {
                if(uValue > WanMgr_GetTotalNoOfGroups())
                {
                    CcspTraceWarning(("%s %d Group Id(%d) is not supported. MAX_INTERFACE GROUP %d \n", __FUNCTION__, __LINE__,uValue, WanMgr_GetTotalNoOfGroups()));
                }
                else if(pWanDmlIface->Selection.Group != uValue)
                {
                    /*Update GroupCfgChanged */
                    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((uValue -1));
                    if (pWanIfaceGroup != NULL)
                    {
                        CcspTraceInfo(("%s %d Group(%d) configuration changed  \n", __FUNCTION__, __LINE__,uValue));
                        pWanIfaceGroup->ConfigChanged = TRUE;
                        /* Add Interface to New group Available list */
                        pWanIfaceGroup->InterfaceAvailable |= (1<<pIfaceDmlEntry->data.uiIfaceIdx);
                        WanMgrDml_GetIfaceGroup_release();
                        pWanIfaceGroup = NULL;
                    }

                    pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pWanDmlIface->Selection.Group -1));
                    if (pWanIfaceGroup != NULL)
                    {
                        CcspTraceInfo(("%s %d Group(%d) configuration changed  \n", __FUNCTION__, __LINE__,pWanDmlIface->Selection.Group));
                        pWanIfaceGroup->ConfigChanged = TRUE;
                        /* Remove Interface from Old group Available list */
                        pWanIfaceGroup->InterfaceAvailable &= ~(1<<pIfaceDmlEntry->data.uiIfaceIdx);
                        WanMgrDml_GetIfaceGroup_release();
                    }

                    pWanDmlIface->Selection.Group = uValue;
                }
                ret = TRUE;
            }
            if (strcmp(ParamName, "Type") == 0)
            {
                IfIndex =  pWanDmlIface->uiIfaceIdx;
                priority =  pWanDmlIface->Selection.Priority;
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                uiTotalIfaces = WanIf_GetEntryCount(NULL);
                if ( WanManager_CheckGivenTypeExists(IfIndex, uiTotalIfaces, uValue, priority, &Status) == ANSC_STATUS_SUCCESS )
                {
                    if(Status)
                    {
                        CcspTraceError(("%s Another interface with same type and priority already exists\n", __FUNCTION__));
                        return FALSE;
                    }
                    WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
                    if(pWanDmlIfaceData != NULL)
                    {
                        pWanDmlIface->Type = uValue;
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        return TRUE;
                    }
                    return FALSE;
                }

            }
#if !RBUS_BUILD_FLAG_ENABLE
            if (strcmp(ParamName, "LinkStatus") == 0)
            {
                pWanDmlIface->VirtIfList->VLAN.Status = uValue;
                ret = TRUE;
            }

#endif
            if (strcmp(ParamName, "OperationalStatus") == 0)
            {
                pWanDmlIface->VirtIfList->OperationalStatus = uValue;
                ret = TRUE;
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfCfg_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool);

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
BOOL WanIfCfg_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            //* check the parameter name and return the corresponding value */
#ifndef RBUS_BUILD_FLAG_ENABLE
            if (strcmp(ParamName, "Enable") == 0)
            {
                *pBool = pWanDmlIface->Selection.Enable;
                ret = TRUE;
            }
#endif //RBUS_BUILD_FLAG_ENABLE
            if (strcmp(ParamName, "Refresh") == 0)
            {
                //TODO: Update all Virtual interfaces
                *pBool = pWanDmlIface->VirtIfList->Reset;
                ret = TRUE;
            }
            if (strcmp(ParamName, "ActiveLink") == 0)
            {
                if (pWanDmlIface->Selection.Status == WAN_IFACE_ACTIVE)
                {
                    *pBool = TRUE;
                }
                else
		{
                    *pBool = FALSE;
                }
                ret = TRUE;
            }
            if (strcmp(ParamName, "EnableDSLite") == 0)
            {
                *pBool = pWanDmlIface->VirtIfList->EnableDSLite;
                ret = TRUE;
            }
            if (strcmp(ParamName, "EnableIPoEHealthCheck") == 0)
            {
                *pBool = FALSE;
                if (pWanDmlIface->VirtIfList->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_IHC)
                {
                    *pBool = TRUE;
                }
                ret = TRUE;
            }
            if (strcmp(ParamName, "EnableMAPT") == 0)
            {
                *pBool = pWanDmlIface->VirtIfList->EnableMAPT;
                ret = TRUE;
            }
            if (strcmp(ParamName, "RebootOnConfiguration") == 0)
            {
                *pBool = pWanDmlIface->Selection.RequiresReboot;
                ret = TRUE;
            }
            if (strcmp(ParamName, "EnableDHCP") == 0)
            {
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfCfg_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue);

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
BOOL WanIfCfg_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
#ifndef RBUS_BUILD_FLAG_ENABLE
            if (strcmp(ParamName, "Enable") == 0)
            {
                pWanDmlIface->Selection.Enable  = bValue;
                ret = TRUE;
            }
#endif //RBUS_BUILD_FLAG_ENABLE
            if (strcmp(ParamName, "Refresh") == 0)
            {
                //TODO: Update all Virtual interfaces
                pWanDmlIface->VirtIfList->Reset = bValue;
                ret = TRUE;
            }
            if (strcmp(ParamName, "EnableDSLite") == 0)
            {
                pWanDmlIface->VirtIfList->EnableDSLite = bValue;
                ret = TRUE;
            }
            if (strcmp(ParamName, "EnableIPoEHealthCheck") == 0)
            {
                CONNECTIVITY_CHECK_TYPE type = bValue? WAN_CONNECTIVITY_TYPE_IHC:WAN_CONNECTIVITY_TYPE_NO_CHECK;
                /*the below condition is, to avoid multiple time same value set and
                 * unsetting value of IPOE and DNS RFC DML from eachother */
                if((type != pWanDmlIface->VirtIfList->IP.ConnectivityCheckType) &&
                   ((type != WAN_CONNECTIVITY_TYPE_NO_CHECK) ||
                    (pWanDmlIface->VirtIfList->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_IHC)))
                {
                    WanMgr_SetConnectivityCheckTypeToPSM(pWanDmlIface->VirtIfList, type);
                    pWanDmlIface->VirtIfList->IP.WCC_TypeChanged = TRUE;
                    pWanDmlIface->VirtIfList->IP.ConnectivityCheckType = type;
                    ret = TRUE;
                }
            }
            if (strcmp(ParamName, "EnableMAPT") == 0)
            {
                pWanDmlIface->VirtIfList->EnableMAPT = bValue;
                ret = TRUE;
            }
            if (strcmp(ParamName, "RebootOnConfiguration") == 0)
            {
                pWanDmlIface->Selection.RequiresReboot = bValue;
                ret = TRUE;
            }
            if (strcmp(ParamName, "EnableDHCP") == 0)
            {
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG WanIfCfg_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize);

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG WanIfCfg_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    ULONG ret = -1;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* collect value */
            if ( ( sizeof( pWanDmlIface->VirtIfList->Name ) - 1 ) < *pUlSize )
            {
                AnscCopyString( pValue, pWanDmlIface->VirtIfList->Name );
                ret = 0;
            }
            else
            {
                *pUlSize = sizeof( pWanDmlIface->VirtIfList->Name );
                ret = 1;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfCfg_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString);

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfCfg_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Name") == 0)
            {
                AnscCopyString(pWanDmlIface->VirtIfList->Name, pString);
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)
                WanMgr_SetRestartWanInfo(WAN_NAME_PARAM_NAME, pWanDmlIface->uiIfaceIdx, pString);
#endif
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfCfg_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfCfg_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfCfg_Commit(ANSC_HANDLE hInsContext);

    description:
        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfCfg_Commit(ANSC_HANDLE hInsContext)
{
    ULONG ret = -1;

    ANSC_STATUS result;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            result = DmlSetWanIfCfg( pWanDmlIface->uiInstanceNumber, pWanDmlIface );
            if(result != ANSC_STATUS_SUCCESS)
            {
                AnscTraceError(("%s: Failed \n", __FUNCTION__));
            }
            else
            {
                ret = 0;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfCfg_Rollback(ANSC_HANDLE hInsContext);

    description:
        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfCfg_Rollback(ANSC_HANDLE hInsContext)
{
    return TRUE;
}


/***********************************************************************

 APIs for Object:

    X_RDK_WanManager.CPEInterface.{i}.Phy.

    *  WanIfPhy_GetParamStringValue
    *  WanIfPhy_SetParamStringValue
    *  WanIfPhy_GetParamUlongValue
    *  WanIfPhy_SetParamUlongValue
    *  WanIfPhy_Validate
    *  WanIfPhy_Commit
    *  WanIfPhy_Rollback

***********************************************************************/


ULONG WanIfPhy_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    ULONG ret = -1;


    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
               /* collect value */
               if ( ( sizeof( pWanDmlIface->BaseInterface ) - 1 ) < *pUlSize )
               {
                   AnscCopyString( pValue, pWanDmlIface->BaseInterface );
                   ret = 0;
               }
               else
               {
                   *pUlSize = sizeof( pWanDmlIface->BaseInterface );
                   ret = 1;
               }
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfPhy_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString);

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL WanIfPhy_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{

    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
                AnscCopyString(pWanDmlIface->BaseInterface, pString);
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfPhy_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong);

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL WanIfPhy_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
#if !RBUS_BUILD_FLAG_ENABLE
            if (strcmp(ParamName, "Status") == 0)
            {
                *puLong = pWanDmlIface->BaseInterfaceStatus;
                ret = TRUE;
            }
#endif

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfPhy_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL WanIfPhy_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);
#if !RBUS_BUILD_FLAG_ENABLE
            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Status") == 0)
            {
                pWanDmlIface->BaseInterfaceStatus = uValue;
                ret = TRUE;
            }
#endif
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfPhy_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfPhy_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfPhy_Commit(ANSC_HANDLE hInsContext);

    description:
        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfPhy_Commit(ANSC_HANDLE hInsContext)
{
    return 0;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfPhy_Rollback(ANSC_HANDLE hInsContext);

    description:
        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfPhy_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}



/***********************************************************************

 APIs for Object:

    X_RDK_WanManager.CPEInterface.{i}.IP.

    *  WanIfIpCfg_GetParamUlongValue
    *  WanIfIpCfg_SetParamUlongValue
    *  WanIfIpCfg_GetParamStringValue
    *  WanIfIpCfg_SetParamStringValue
    *  WanIfIpCfg_Validate
    *  WanIfIpCfg_Commit
    *  WanIfIpCfg_Rollback

***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfIpCfg_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong);

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfIpCfg_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "IPv4Status") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->IP.Ipv4Status;
                ret = TRUE;
            }
            if (strcmp(ParamName, "IPv6Status") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->IP.Ipv6Status;
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfIpCfg_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfIpCfg_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "IPv4Status") == 0)
            {
                pWanDmlIface->VirtIfList->IP.Ipv4Status = uValue;
                ret = TRUE;
            }
            if (strcmp(ParamName, "IPv6Status") == 0)
            {
                pWanDmlIface->VirtIfList->IP.Ipv6Status = uValue;
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG WanIfIpCfg_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize);

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG WanIfIpCfg_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    ULONG ret = -1;


    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
                /* collect value */
                if ( ( sizeof( pWanDmlIface->VirtIfList->IP.Interface ) - 1 ) < *pUlSize )
                {
                    AnscCopyString( pValue, pWanDmlIface->VirtIfList->IP.Interface );
                    ret = 0;
                }
                else
                {
                    *pUlSize = sizeof( pWanDmlIface->VirtIfList->IP.Interface );
                    ret = 1;
                }
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfIpCfg_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString);

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfIpCfg_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
                AnscCopyString(pWanDmlIface->VirtIfList->IP.Interface, pString);
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfIpCfg_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfIpCfg_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfIpCfg_Commit(ANSC_HANDLE hInsContext);

    description:
        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfIpCfg_Commit(ANSC_HANDLE hInsContext)
{
    return 0;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfIpCfg_Rollback(ANSC_HANDLE hInsContext);

    description:
        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfIpCfg_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    X_RDK_WanManager.CPEInterface.{i}.MAPT.

    *  WanIfMapt_GetParamUlongValue
    *  WanIfMapt_SetParamUlongValue
    *  WanIfMapt_GetParamStringValue
    *  WanIfMapt_SetParamStringValue
    *  WanIfMapt_Validate
    *  WanIfMapt_Commit
    *  WanIfMapt_Rollback

***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfMapt_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong);

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfMapt_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "MAPTStatus") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->MAP.MaptStatus;
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfMapt_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfMapt_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "MAPTStatus") == 0)
            {
#ifdef FEATURE_MAPT
                pWanDmlIface->VirtIfList->MAP.MaptStatus = uValue;
                ret = TRUE;
#endif /* * FEATURE_MAPT */
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG WanIfMapt_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize);

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG WanIfMapt_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    ULONG ret = -1;



    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
                /* collect value */
                if ( ( sizeof( pWanDmlIface->VirtIfList->MAP.Path ) - 1 ) < *pUlSize )
                {
                    AnscCopyString( pValue, pWanDmlIface->VirtIfList->MAP.Path );
                    ret = 0;
                }
                else
                {
                    *pUlSize = sizeof( pWanDmlIface->VirtIfList->MAP.Path );
                    ret = 1;
                }
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;

}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfMapt_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString);

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfMapt_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
#ifdef FEATURE_MAPT
                AnscCopyString(pWanDmlIface->VirtIfList->MAP.Path, pString);
                ret = TRUE;
#endif /* * FEATURE_MAPT */
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfMapt_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfMapt_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfMapt_Commit(ANSC_HANDLE hInsContext);

    description:
        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfMapt_Commit(ANSC_HANDLE hInsContext)
{
    return 0;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfMapt_Rollback(ANSC_HANDLE hInsContext);

    description:
        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfMapt_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    X_RDK_WanManager.CPEInterface.{i}.MAPT.

    *  WanIfDSLite_GetParamUlongValue
    *  WanIfDSLite_SetParamUlongValue
    *  WanIfDSLite_GetParamStringValue
    *  WanIfDSLite_SetParamStringValue
    *  WanIfDSLite_Validate
    *  WanIfDSLite_Commit
    *  WanIfDSLite_Rollback

***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfDSLite_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong);

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfDSLite_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Status") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->DSLite.Status;
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfDSLite_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfDSLite_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Status") == 0)
            {
                pWanDmlIface->VirtIfList->DSLite.Status = uValue;
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG WanIfDSLite_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize);

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG WanIfDSLite_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    ULONG ret = -1;



    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
                /* collect value */
                if ( ( sizeof( pWanDmlIface->VirtIfList->DSLite.Path ) - 1 ) < *pUlSize )
                {
                    AnscCopyString( pValue, pWanDmlIface->VirtIfList->DSLite.Path );
                    ret = 0;
                }
                else
                {
                    *pUlSize = sizeof( pWanDmlIface->VirtIfList->DSLite.Path );
                    ret = 1;
                }
            }


            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL WanIfDSLite_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString);

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfDSLite_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
                AnscCopyString(pWanDmlIface->VirtIfList->DSLite.Path, pString);
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

       BOOL WanIfDSLite_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL WanIfDSLite_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfDSLite_Commit(ANSC_HANDLE hInsContext);

    description:
        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfDSLite_Commit(ANSC_HANDLE hInsContext)
{
    return 0;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG WanIfDSLite_Rollback(ANSC_HANDLE hInsContext);

    description:
        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/
ULONG WanIfDSLite_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    Device.X_RDK_WanManager.CPEInterface.{I}.Marking.{i}.

    *  Marking_GetEntryCount
    *  Marking_GetEntry
    *  Marking_AddEntry
    *  Marking_DelEntry
    *  Marking_GetParamUlongValue
    *  Marking_GetParamStringValue
    *  Marking_GetParamIntValue
    *  Marking_SetParamUlongValue
    *  Marking_SetParamStringValue
    *  Marking_SetParamIntValue
    *  Marking_Validate
    *  Marking_Commit
    *  Marking_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG Marking_GetEntryCount(ANSC_HANDLE hInsContext);

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/

ULONG Marking_GetEntryCount(ANSC_HANDLE hInsContext)
{

    ULONG count = 0;



#ifdef FEATURE_802_1P_COS_MARKING
    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            count = AnscSListQueryDepth( &(pWanDmlIface->Marking.MarkingList) );

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
#endif /* * FEATURE_802_1P_COS_MARKING */

    return count;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE Marking_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber);

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/

ANSC_HANDLE Marking_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber)
{
    PSINGLE_LINK_ENTRY  pSListEntry = NULL;
    *pInsNumber= 0;

#ifdef FEATURE_802_1P_COS_MARKING
    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            pSListEntry       = AnscSListGetEntryByIndex(&(pWanDmlIface->Marking.MarkingList), nIndex);
            if ( pSListEntry )
            {
                CONTEXT_MARKING_LINK_OBJECT* pCxtLink      = ACCESS_CONTEXT_MARKING_LINK_OBJECT(pSListEntry);
                *pInsNumber   = pCxtLink->InstanceNumber;
            }


            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
#endif /* * FEATURE_802_1P_COS_MARKING */

    return (ANSC_HANDLE)pSListEntry;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE Marking_AddEntry(ANSC_HANDLE hInsContext, ULONG* pInsNumber);

    description:

        This function is called to add a new entry.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle of new added entry.

**********************************************************************/

ANSC_HANDLE Marking_AddEntry(ANSC_HANDLE hInsContext, ULONG* pInsNumber)
{
    ANSC_HANDLE newMarking = NULL;

#ifdef FEATURE_802_1P_COS_MARKING
    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            newMarking = WanManager_AddIfaceMarking(pWanDmlIface, pInsNumber);

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
#endif /* * FEATURE_802_1P_COS_MARKING */

    return newMarking;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG Marking_DelEntry(ANSC_HANDLE hInsContext, ANSC_HANDLE hInstance);

    description:

        This function is called to delete an exist entry.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ANSC_HANDLE                 hInstance
                The exist entry handle;

    return:     The status of the operation.

**********************************************************************/

ULONG Marking_DelEntry(ANSC_HANDLE hInsContext, ANSC_HANDLE hInstance)
{

    ULONG returnStatus = -1;

#ifdef FEATURE_802_1P_COS_MARKING
    CONTEXT_MARKING_LINK_OBJECT* pMarkingCxtLink   = (CONTEXT_MARKING_LINK_OBJECT*)hInstance;
    if(pMarkingCxtLink == NULL)
    {
        return -1;
    }


    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);


            if ( pMarkingCxtLink->bNew )
            {
                /* Set bNew to FALSE to indicate this node is not going to save to SysRegistry */
                pMarkingCxtLink->bNew = FALSE;
            }

            DML_MARKING* p_Marking = (DML_MARKING*)pMarkingCxtLink->hContext;

            returnStatus = DmlDeleteMarking( NULL, p_Marking );

            if ( ( ANSC_STATUS_SUCCESS == returnStatus ) && \
                ( AnscSListPopEntryByLink(&(pWanDmlIface->Marking.MarkingList), &pMarkingCxtLink->Linkage) ) )
            {
                AnscFreeMemory(pMarkingCxtLink->hContext);
                AnscFreeMemory(pMarkingCxtLink);
            }


            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
#endif /* * FEATURE_802_1P_COS_MARKING */

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL Marking_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong);

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL Marking_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    BOOL                                ret = FALSE;
    CONTEXT_MARKING_LINK_OBJECT*        pCxtLink      = (CONTEXT_MARKING_LINK_OBJECT*)hInsContext;
    DML_MARKING*                        p_Marking     = (DML_MARKING* )pCxtLink->hContext;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "SKBPort") == 0)
    {
        *puLong = p_Marking->SKBPort;
        ret = TRUE;
    }
    if (strcmp(ParamName, "SKBMark") == 0)
    {
        *puLong = p_Marking->SKBMark;
        ret = TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG Marking_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize);

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/

ULONG Marking_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    CONTEXT_MARKING_LINK_OBJECT*        pCxtLink      = (CONTEXT_MARKING_LINK_OBJECT*)hInsContext;
    DML_MARKING*                        p_Marking     = (DML_MARKING* )pCxtLink->hContext;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Alias") == 0)
    {
        if ( AnscSizeOfString(p_Marking->Alias) < *pUlSize)
        {
            AnscCopyString(pValue, p_Marking->Alias);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(p_Marking->Alias)+1;
            return 1;
        }
    }

    if (strcmp(ParamName, "DSCPMark") == 0)
    {
        if ( AnscSizeOfString(p_Marking->DSCPMark) < *pUlSize)
        {
            AnscCopyString(pValue, p_Marking->DSCPMark);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(p_Marking->DSCPMark)+1;
            return 1;
        }
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL Marking_GetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int* pInt);

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL Marking_GetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int* pInt)
{
    BOOL ret = FALSE;
    CONTEXT_MARKING_LINK_OBJECT*        pCxtLink      = (CONTEXT_MARKING_LINK_OBJECT*)hInsContext;
    DML_MARKING*                        p_Marking     = (DML_MARKING* )pCxtLink->hContext;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "EthernetPriorityMark") == 0)
    {
        *pInt = p_Marking->EthernetPriorityMark;
        ret = TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL Marking_SetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int iValue);

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL Marking_SetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int iValue)
{
    BOOL ret = FALSE;
    CONTEXT_MARKING_LINK_OBJECT*        pCxtLink      = (CONTEXT_MARKING_LINK_OBJECT*)hInsContext;
    DML_MARKING*                        p_Marking     = (DML_MARKING* )pCxtLink->hContext;

    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "EthernetPriorityMark") == 0)
    {
        p_Marking->EthernetPriorityMark = iValue;
        ret = TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL Marking_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue);

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL Marking_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL Marking_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString);

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL Marking_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    BOOL ret = FALSE;
    CONTEXT_MARKING_LINK_OBJECT*        pCxtLink      = (CONTEXT_MARKING_LINK_OBJECT*)hInsContext;
    DML_MARKING*                        p_Marking     = (DML_MARKING* )pCxtLink->hContext;

    /* check the parameter name and set the corresponding value */

    if (strcmp(ParamName, "Alias") == 0)
    {
        //Alias should not overwrite after set
        if( 0 < AnscSizeOfString(p_Marking->Alias) )
        {
            return FALSE;
        }

        AnscCopyString(p_Marking->Alias, pString);
        ret = TRUE;
    }

    if (strcmp(ParamName, "DSCPMark") == 0)
    {
        AnscCopyString(p_Marking->DSCPMark, pString);
        ret = TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL Marking_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/

BOOL Marking_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG Marking_Commit(ANSC_HANDLE hInsContext);

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/

ULONG Marking_Commit(ANSC_HANDLE hInsContext)
{

    ANSC_STATUS                              returnStatus  = ANSC_STATUS_SUCCESS;

#ifdef FEATURE_802_1P_COS_MARKING
    CONTEXT_MARKING_LINK_OBJECT*        pCxtLink      = (CONTEXT_MARKING_LINK_OBJECT*)hInsContext;
    DML_MARKING*                        p_Marking     = (DML_MARKING* )pCxtLink->hContext;

    if ( pCxtLink->bNew )
    {
        //Add new marking params
        returnStatus = DmlAddMarking( NULL, p_Marking );

        if ( returnStatus == ANSC_STATUS_SUCCESS )
        {
            pCxtLink->bNew = FALSE;
        }
        else
        {
            //Re-init all memory
            memset( p_Marking->Alias, 0, sizeof( p_Marking->Alias ) );
            p_Marking->SKBPort = 0;
            p_Marking->SKBMark = 0;
            p_Marking->EthernetPriorityMark = -1;
            memset( p_Marking->DSCPMark, 0, sizeof( p_Marking->DSCPMark ) );
        }
    }
    else
    {
        //Update marking param values
        returnStatus = DmlSetMarking( NULL, p_Marking );
    }
#endif /* * FEATURE_802_1P_COS_MARKING */

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG Marking_Rollback(ANSC_HANDLE hInsContext);

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/

ULONG Marking_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    X_RDK_WanManager.CPEInterface.{i}.PPP.

    *  WanIfPPPCfg_GetParamUlongValue
    *  WanIfPPPCfg_SetParamUlongValue
    *  WanIfPPPCfg_GetParamStringValue
    *  WanIfPPPCfg_SetParamStringValue
    *  WanIfPPPCfg_GetParamBoolValue
    *  WanIfPPPCfg_SetParamBoolValue
    *  WanIfPPPCfg_Validate
    *  WanIfPPPCfg_Commit
    *  WanPPPIpCfg_Rollback

***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WanIfPPPCfg_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
WanIfPPPCfg_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and return the corresponding value */
            if (strcmp(ParamName, "IPCPStatus") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->PPP.IPCPStatus;
                ret = TRUE;
            }
            if (strcmp(ParamName, "IPv6CPStatus") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->PPP.IPV6CPStatus;
                ret = TRUE;
            }
            if (strcmp(ParamName, "LCPStatus") == 0)
            {
                ret = TRUE;
                *puLong = 0;
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
            }
            if (strcmp(ParamName, "LinkStatus") == 0)
            {
                *puLong = pWanDmlIface->VirtIfList->PPP.LinkStatus;
                ret = TRUE;
            }
            if (strcmp(ParamName, "LinkType") == 0)
            {
                *puLong = 0;
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return ret;

}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WanIfPPPCfg_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
WanIfPPPCfg_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    BOOL ret = FALSE;
    int iErrorCode = 0;
    char *pInterface = NULL;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "IPCPStatus") == 0)
            {
                pWanDmlIface->VirtIfList->PPP.IPCPStatus = uValue;
                    ret = TRUE;
            }
            if (strcmp(ParamName, "IPv6CPStatus") == 0)
            {
                pWanDmlIface->VirtIfList->PPP.IPV6CPStatus = uValue;
                    ret = TRUE;
            }
            if (strcmp(ParamName, "LCPStatus") == 0)
            {
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }
            if (strcmp(ParamName, "LinkStatus") == 0)
            {
                pWanDmlIface->VirtIfList->PPP.LinkStatus = uValue;
                ret = TRUE;
            }
            if (strcmp(ParamName, "LinkType") == 0)
            {
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }


    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return ret;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        WanIfPPPCfg_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/

ULONG
WanIfPPPCfg_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    ULONG ret = -1;


    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
               /* collect value */
               if ( ( sizeof( pWanDmlIface->BaseInterface ) - 1 ) < *pUlSize )
               {
                   AnscCopyString( pValue, pWanDmlIface->VirtIfList->PPP.Interface);
                   ret = 0;
               }
               else
               {
                   *pUlSize = sizeof( pWanDmlIface->VirtIfList->PPP.Interface );
                   ret = 1;
               }
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WanIfPPPCfg_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
WanIfPPPCfg_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);
            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Path") == 0)
            {
                AnscCopyString(pWanDmlIface->VirtIfList->PPP.Interface, pString);
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WanIfPPPCfg_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

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

ULONG
WanIfPPPCfg_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);
            /* check the parameter name and return the corresponding value */
            if (strcmp(ParamName, "Enable") == 0)
            {
                *pBool = FALSE;
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }
            if (strcmp(ParamName, "IPCPEnable") == 0)
            {
                *pBool = TRUE;
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }
            if (strcmp(ParamName, "IPv6CPEnable") == 0)
            {
                *pBool =TRUE;
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WanIfPPPCfg_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
WanIfPPPCfg_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    BOOL ret = FALSE;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            /* check the parameter name and set the corresponding value */
            if (strcmp(ParamName, "Enable") == 0)
            {
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }
            if (strcmp(ParamName, "IPCPEnable") == 0)
            {
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }
            if (strcmp(ParamName, "IPv6CPEnable") == 0)
            {
                CcspTraceInfo(("%s %d: %s not supported \n", __FUNCTION__, __LINE__,ParamName));
                ret = TRUE;
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return ret;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WanIfPPPCfg_Validate
        (
            ANSC_HANDLE                 hInsContext,
            char*                       pReturnParamName,
            ULONG*                      puLength
        )
    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
WanIfPPPCfg_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG
        WanIfPPPCfg_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:
        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/

ULONG
WanIfPPPCfg_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ULONG ret = -1;

    ANSC_STATUS result;

    WanMgr_Iface_Data_t* pIfaceDmlEntry = (WanMgr_Iface_Data_t*) hInsContext;
    if(pIfaceDmlEntry != NULL)
    {
        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pIfaceDmlEntry->data.uiIfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

            result = DmlSetWanIfCfg( pWanDmlIface->uiInstanceNumber, pWanDmlIface );
            if(result != ANSC_STATUS_SUCCESS)
            {
                AnscTraceError(("%s: Failed \n", __FUNCTION__));
            }
            else
            {
                ret = 0;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return ret;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        ULONG
        WanIfPPPCfg_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:
        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.
**********************************************************************/

ULONG
WanIfPPPCfg_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return TRUE;
}
#endif /* !WAN_MANAGER_UNIFICATION_ENABLED */
