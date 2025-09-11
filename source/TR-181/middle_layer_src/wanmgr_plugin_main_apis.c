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


/***********************************************************************

    module: plugin_main_apis.c

        Implement COSA Data Model Library Init and Unload apis.
        This files will hold all data in it.
    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Dslh Var Record Object.

        *   BackEndManagerCreate
        *   BackEndManagerInitialize
        *   BackEndManagerRemove
    ---------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    ---------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**********************************************************************/

#include <syscfg/syscfg.h>

//#include "dml_tr181_custom_cfg.h"
#include "wanmgr_plugin_main_apis.h"
#include "wanmgr_map_internal.h"
#include "wanmgr_dhcpv4_internal.h"
#include "wanmgr_dhcpv6_internal.h"

/*PCOSA_DIAG_PLUGIN_INFO             g_pCosaDiagPluginInfo;*/
COSAGetParamValueByPathNameProc    g_GetParamValueByPathNameProc;
COSASetParamValueByPathNameProc    g_SetParamValueByPathNameProc;
COSAGetParamValueStringProc        g_GetParamValueString;
COSAGetParamValueUlongProc         g_GetParamValueUlong;
COSAGetParamValueIntProc           g_GetParamValueInt;
COSAGetParamValueBoolProc          g_GetParamValueBool;
COSASetParamValueStringProc        g_SetParamValueString;
COSASetParamValueUlongProc         g_SetParamValueUlong;
COSASetParamValueIntProc           g_SetParamValueInt;
COSASetParamValueBoolProc          g_SetParamValueBool;
COSAGetInstanceNumbersProc         g_GetInstanceNumbers;

COSAValidateHierarchyInterfaceProc g_ValidateInterface;
COSAGetHandleProc                  g_GetRegistryRootFolder;
COSAGetInstanceNumberByIndexProc   g_GetInstanceNumberByIndex;
COSAGetInterfaceByNameProc         g_GetInterfaceByName;
COSAGetHandleProc                  g_GetMessageBusHandle;
COSAGetSubsystemPrefixProc         g_GetSubsystemPrefix;
PCCSP_CCD_INTERFACE                g_pPnmCcdIf;
ANSC_HANDLE                        g_MessageBusHandle;
char*                              g_SubsystemPrefix;
COSARegisterCallBackAfterInitDmlProc  g_RegisterCallBackAfterInitDml;
COSARepopulateTableProc            g_COSARepopulateTable;

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE BackEndManagerCreate(VOID);

    description:

        This function constructs cosa datamodel object and return handle.

    argument:

    return:     newly created qos object.

**********************************************************************/

ANSC_HANDLE BackEndManagerCreate(VOID)
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    WANMGR_BACKEND_OBJ*             pMyObject    = (WANMGR_BACKEND_OBJ*)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (WANMGR_BACKEND_OBJ*)AnscAllocateMemory(sizeof(WANMGR_BACKEND_OBJ));
    if ( pMyObject == NULL )
    {
        return (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    pMyObject->Oid               = DATAMODEL_BASE_OID;
    pMyObject->Create            = BackEndManagerCreate;
    pMyObject->Remove            = BackEndManagerRemove;
    pMyObject->Initialize        = BackEndManagerInitialize;

    /*pMyObject->Initialize   ((ANSC_HANDLE)pMyObject);*/

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS BackEndManagerInitialize(ANSC_HANDLE hThisObject);

    description:

        This function initiate cosa manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS BackEndManagerInitialize(ANSC_HANDLE hThisObject)
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    WANMGR_BACKEND_OBJ*             pMyObject    = (WANMGR_BACKEND_OBJ*)hThisObject;

    if (pMyObject == NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

#ifdef _COSA_SIM_
        pMyObject->has_moca_slap  = 0;
        pMyObject->has_wifi_slap  = 0;
#endif

    AnscTraceWarning(("%s...\n", __FUNCTION__));

    //Wan Manager Configuration
    WanMgr_WanConfigInit();

#ifdef RBUS_BUILD_FLAG_ENABLE
    //Starts the Rbus Initialize
    if(WanMgr_Rbus_Init() != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d - Rbus Init failed !\n", __FUNCTION__, __LINE__ ));
    }
#endif //RBUS_BUILD_FLAG_ENABLE

    pMyObject->hDhcpv4        = (ANSC_HANDLE)WanMgr_Dhcpv4Create();
    AnscTraceWarning(("  WanMgr_Dhcpv4Create done!\n"));

    pMyObject->hDhcpv6        = (ANSC_HANDLE)WanMgr_Dhcpv6Create();
    AnscTraceWarning(("  WanMgr_Dhcpv6Create done!\n"));

    pMyObject->hMap           = (ANSC_HANDLE)WanMgr_MapCreate();
    AnscTraceWarning(("  WanMgr_MapCreate done!\n"));

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS BackEndManagerRemove(ANSC_HANDLE hThisObject);

    description:

        This function remove cosa manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS BackEndManagerRemove(ANSC_HANDLE hThisObject)
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    WANMGR_BACKEND_OBJ*             pMyObject    = (WANMGR_BACKEND_OBJ*)hThisObject;

    if (pMyObject == NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    if ( pMyObject->hDhcpv4 )
    {
        WanMgr_Dhcpv4Remove((ANSC_HANDLE)pMyObject->hDhcpv4);
    }

    if ( pMyObject->hDhcpv6 )
    {
        WanMgr_Dhcpv6Remove((ANSC_HANDLE)pMyObject->hDhcpv6);
    }

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}
