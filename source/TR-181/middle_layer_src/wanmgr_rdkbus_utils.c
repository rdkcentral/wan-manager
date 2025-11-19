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

        Platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        13/02/2020    initial revision.

**************************************************************************/

/* ---- Include Files ---------------------------------------- */
#include <syscfg/syscfg.h>
#include "dmsb_tr181_psm_definitions.h"
#include "wanmgr_rdkbus_utils.h"
#include "ansc_platform.h"
#include "ccsp_psm_helper.h"
#include "wanmgr_data.h"
#include "wanmgr_dhcpv4_apis.h"
#include "wanmgr_dhcpv6_apis.h"
#include "wanmgr_telemetry.h"

#define UPSTREAM_SET_MAX_RETRY_COUNT 10 // max. retry count for Upstream set requests
#define DATAMODEL_PARAM_LENGTH 256

extern char g_Subsystem[32];
extern ANSC_HANDLE bus_handle;

ANSC_STATUS WanMgr_SetConnectivityCheckTypeToPSM(DML_VIRTUAL_IFACE* pVirtIf, CONNECTIVITY_CHECK_TYPE type)
{
    int result = ANSC_STATUS_SUCCESS;
    int retPsmSet = CCSP_SUCCESS;
    char param_name[BUFLEN_256] = {0};
    char param_value[BUFLEN_256] = {0};

    snprintf(param_value, sizeof(param_value), "%d", type);
    _ansc_sprintf(param_name, PSM_WANMANAGER_CONNECTIVITY_CHECK_TYPE, pVirtIf->baseIfIdx +1, pVirtIf->VirIfIdx+1);

    retPsmSet = WanMgr_RdkBus_SetParamValuesToDB(param_name, param_value);
    if (retPsmSet != CCSP_SUCCESS) {
        AnscTraceError(("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, param_name, param_value));
        result = ANSC_STATUS_FAILURE;
    }
    return result;
}

BOOL WanMgr_GetDnsConnectivityCheck(void)
{
    BOOL ctl = false;
    int uiLoopCount;

    int TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();
    for (uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if (pWanIfaceData->NoOfVirtIfs > 0)
            {
                int virIf_id = 0; /* default first virtual interface index */
                DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, virIf_id);
                if(p_VirtIf != NULL)
                {
                    ctl = (p_VirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_TAD)? true:false;
                    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                    return ctl;
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
    return ctl;
}

ANSC_STATUS  WanMgr_SetDnsConnectivityCheck(BOOL Enable)
{
    ANSC_STATUS retStatus = ANSC_STATUS_FAILURE;
    int uiLoopCount;

    int TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();

    CONNECTIVITY_CHECK_TYPE type = Enable? WAN_CONNECTIVITY_TYPE_TAD:WAN_CONNECTIVITY_TYPE_NO_CHECK;

    for (uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            for(int virIf_id=0; virIf_id< pWanIfaceData->NoOfVirtIfs; virIf_id++)
            {
                DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, virIf_id);
                /*the below condition is, to avoid multiple time same value set and 
		 * unsetting value of IPOE and DNS RFC DML from eachother */
                if((type != p_VirtIf->IP.ConnectivityCheckType) &&
                   ((type != WAN_CONNECTIVITY_TYPE_NO_CHECK) ||
                    (p_VirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_TAD)))
                {
                    if (WanMgr_SetConnectivityCheckTypeToPSM(p_VirtIf, type) == ANSC_STATUS_SUCCESS)
                    {
                        p_VirtIf->IP.ConnectivityCheckType = type;
                        p_VirtIf->IP.WCC_TypeChanged = TRUE;
                        retStatus = ANSC_STATUS_SUCCESS;
                        WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_INFO_CONNECTIVITY_CHECK_TYPE);
                        CcspTraceInfo(("%s-%d: RFC- DNS Connectivity Check %s, Type=%s", __FUNCTION__, __LINE__,
                                        (Enable? "Enabled":"Disabled"), (Enable? "TAD":"None")));
                    }
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
    return retStatus;
}

/*TODO:
 *Should be Reviewed while Implementing MAPT Unification.
 */
#if defined(FEATURE_SUPPORT_MAPT_NAT46)
int WanMgr_SetMAPTEnableToPSM(DML_VIRTUAL_IFACE* pVirtIf, BOOL Enable)
{
    int retPsmSet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
    if(Enable == TRUE)
    {
        _ansc_sprintf(param_value, "TRUE");
    }
    else
    {
        _ansc_sprintf(param_value, "FALSE");
    }
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ENABLE_MAPT, pVirtIf->baseIfIdx +1, pVirtIf->VirIfIdx+1);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);
    CcspTraceInfo(("%s-%d: MAPTEnable(%s) set to (%s)\n", __FUNCTION__, __LINE__, param_name, param_value));
    return 0;
}
#endif

ANSC_STATUS WanMgr_RdkBus_setRestorationDelay(UINT delay)
{
    int result = ANSC_STATUS_SUCCESS;
    int retPsmSet = CCSP_SUCCESS;
    char param_name[BUFLEN_256] = {0};
    char param_value[BUFLEN_256] = {0};

    /* Update the wan policy information in PSM */
    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    snprintf(param_value, sizeof(param_value), "%d", delay);
    _ansc_sprintf(param_name, PSM_WANMANAGER_RESTORATION_DELAY);

    retPsmSet = WanMgr_RdkBus_SetParamValuesToDB(param_name, param_value);
    if (retPsmSet != CCSP_SUCCESS) {
        AnscTraceError(("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, param_name, param_value));
        result = ANSC_STATUS_FAILURE;
    }

    return result;
}

ANSC_STATUS WanMgr_RdkBus_setWanEnableToPsm(BOOL WanEnable)
{
    int result = ANSC_STATUS_SUCCESS;
    int retPsmSet = CCSP_SUCCESS;
    char param_name[BUFLEN_256] = {0};
    char param_value[BUFLEN_256] = {0};

    /* Update the wan Enable information in PSM */
    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    snprintf(param_value, sizeof(param_value), "%d", WanEnable);
    _ansc_sprintf(param_name, PSM_WANMANAGER_WANENABLE);

    retPsmSet = WanMgr_RdkBus_SetParamValuesToDB(param_name, param_value);
    if (retPsmSet != CCSP_SUCCESS) {
        AnscTraceError(("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, param_name, param_value));
        result = ANSC_STATUS_FAILURE;
    }

    return result;
}

ANSC_STATUS WanMgr_RdkBus_setAllowRemoteIfaceToPsm(BOOL Enable)
{
    int result = ANSC_STATUS_SUCCESS;
    int retPsmSet = CCSP_SUCCESS;
    char param_name[BUFLEN_256] = {0};
    char param_value[BUFLEN_256] = {0};

    /* Update the AllowRemoteIface information in PSM */
    snprintf(param_value, sizeof(param_value), "%d", Enable);
    _ansc_sprintf(param_name, PSM_WANMANAGER_ALLOW_REMOTE_IFACE);

    retPsmSet = WanMgr_RdkBus_SetParamValuesToDB(param_name, param_value);
    if (retPsmSet != CCSP_SUCCESS) {
        AnscTraceError(("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, param_name, param_value));
        result = ANSC_STATUS_FAILURE;
    }

    return result;
}

static void checkComponentHealthStatus(char * compName, char * dbusPath, char *status, int *retStatus)
{
    int ret = 0, val_size = 0;
    parameterValStruct_t **parameterval = NULL;
    char *parameterNames[1] = {};
    char tmp[256];
    char str[256];
    char l_Subsystem[128] = { 0 };

    sprintf(tmp,"%s.%s",compName, "Health");
    parameterNames[0] = tmp;

    strncpy(l_Subsystem, "eRT.",sizeof(l_Subsystem));
    snprintf(str, sizeof(str), "%s%s", l_Subsystem, compName);
    CcspTraceDebug(("str is:%s\n", str));

    ret = CcspBaseIf_getParameterValues(bus_handle, str, dbusPath,  parameterNames, 1, &val_size, &parameterval);
    CcspTraceDebug(("ret = %d val_size = %d\n",ret,val_size));
    if(ret == CCSP_SUCCESS)
    {
        CcspTraceDebug(("parameterval[0]->parameterName : %s parameterval[0]->parameterValue : %s\n",parameterval[0]->parameterName,parameterval[0]->parameterValue));
        strncpy(status, parameterval[0]->parameterValue, strlen(parameterval[0]->parameterValue) + 1 );
        CcspTraceDebug(("status of component:%s\n", status));
    }
    free_parameterValStruct_t (bus_handle, val_size, parameterval);

    *retStatus = ret;
}

ANSC_STATUS WaitForInterfaceComponentReady(char *pPhyPath)
{
    char status[32] = {'\0'};
    int count = 0;
    int ret = -1;
    char  pCompName[BUFLEN_64] = {0};
    char  pCompPath[BUFLEN_64] = {0};

    if (pPhyPath == NULL)
    {
        CcspTraceInfo(("%s %d Error: BaseInterface is NULL \n", __FUNCTION__, __LINE__ ));
        return ANSC_STATUS_FAILURE;
    }
        
    if(strstr(pPhyPath, "CableModem") != NULL) { // CM wan interface
        strncpy(pCompName, CMAGENT_COMP_NAME_WITHOUTSUBSYSTEM, sizeof(pCompName));
        strncpy(pCompPath, CMAGENT_COMPONENT_PATH, sizeof(pCompPath));
    }
    else if(strstr(pPhyPath, "Ethernet") != NULL) { // ethernet wan interface
        strncpy(pCompName, ETH_COMP_NAME_WITHOUTSUBSYSTEM, sizeof(pCompName));
        strncpy(pCompPath, ETH_COMPONENT_PATH, sizeof(pCompPath));
    }
    else if(strstr(pPhyPath, "Cellular") != NULL) { // cellular wan interface
        strncpy(pCompName, CELLULAR_COMP_NAME_WITHOUTSUBSYSTEM, sizeof(pCompName));
        strncpy(pCompPath, CELLULAR_COMPONENT_PATH, sizeof(pCompPath));
    }

    while(1)
    {
        checkComponentHealthStatus(pCompName, pCompPath, status,&ret);
        if(ret == CCSP_SUCCESS && (strcmp(status, "Green") == 0))
        {
            CcspTraceInfo(("%s component health is %s, continue\n", pCompName, status));
            return ANSC_STATUS_SUCCESS;
        }
        else
        {
            count++;
            if(count%5== 0)
            {
                CcspTraceError(("%s component Health, ret:%d, waiting\n", pCompName, ret));
            }
            sleep(5);
        }
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_RdkBus_SetRequestIfComponent(char *pPhyPath, char *pInputparamName, char *pInputParamValue, enum dataType_e type)
{
    char param_name[BUFLEN_256];
    char  pCompName[BUFLEN_64] = {0};
    char  pCompPath[BUFLEN_64] = {0};
    char *faultParam = NULL;
    int ret = 0;

    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t param_info[1] = {0};

    if((pPhyPath == NULL) || (pInputparamName == NULL) || (pInputParamValue == NULL)) {
        CcspTraceInfo(("%s %d Error: BaseInterface/inputParamName is NULL \n", __FUNCTION__, __LINE__ ));
        return ANSC_STATUS_FAILURE;
    }

    snprintf(param_name, sizeof(param_name), "%s%s", pPhyPath, pInputparamName);

    if(strstr(param_name, "CableModem") != NULL) { // CM wan interface
        strncpy(pCompName, CMAGENT_COMPONENT_NAME, sizeof(pCompName));
        strncpy(pCompPath, CMAGENT_COMPONENT_PATH, sizeof(pCompPath));
    }
    else if(strstr(param_name, "Ethernet") != NULL) { // ethernet wan interface
        strncpy(pCompName, ETH_COMPONENT_NAME, sizeof(pCompName));
        strncpy(pCompPath, ETH_COMPONENT_PATH, sizeof(pCompPath));
    }
    else if(strstr(param_name, "Cellular") != NULL) { // cellular wan interface
        strncpy(pCompName, CELLULAR_COMPONENT_NAME, sizeof(pCompName));
        strncpy(pCompPath, CELLULAR_COMPONENT_PATH, sizeof(pCompPath));
    }

     CcspTraceInfo(("%s: Param Name %s value %s\n", __FUNCTION__,param_name,pInputParamValue));
    param_info[0].parameterName = param_name;
    param_info[0].parameterValue = pInputParamValue;
    param_info[0].type = type;

    ret = CcspBaseIf_setParameterValues(bus_handle, pCompName, pCompPath,
                                        0, 0x0,   /* session id and write id */
                                        param_info, 1, TRUE,   /* Commit  */
                                        &faultParam);

    if ( ( ret != CCSP_SUCCESS ) && ( faultParam )) {
        CcspTraceInfo(("%s CcspBaseIf_setParameterValues failed with error %d\n",__FUNCTION__, ret ));
        bus_info->freefunc( faultParam );
        return ANSC_STATUS_FAILURE;
    }
    
    return ANSC_STATUS_SUCCESS;
}

#ifdef FEATURE_RDKB_AUTO_PORT_SWITCH
void WanMgr_SetPortCapabilityForEthIntf (DML_WAN_POLICY eWanPolicy)
{
    ANSC_STATUS result = ANSC_STATUS_FAILURE;
    char dmQuery[BUFLEN_256] = {0};
    char dmValue[BUFLEN_32]  = {0};
    int foundPhyPath = 0;
    int uiLoopCount;
    int TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();

    if(eWanPolicy == PRIMARY_PRIORITY)
        strcpy(dmValue,"WAN");
    else
        strcpy(dmValue,"WAN_LAN");

    CcspTraceInfo(("%s %d: TotalIfaces:%d \n", __FUNCTION__, __LINE__, TotalIfaces));
    for (uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if (strstr(pWanIfaceData->BaseInterface,"Ethernet") != NULL)
            {
                foundPhyPath = 1;
                snprintf(dmQuery, sizeof(dmQuery)-1, "%s%s", pWanIfaceData->BaseInterface, ETH_INTERFACE_PORTCAPABILITY);
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
    if(foundPhyPath)
    {
        CcspTraceInfo(("%s: dmQuery[%s] dmValue[%s]\n", __FUNCTION__, dmQuery,dmValue));
        result = WanMgr_RdkBus_SetParamValues(ETH_COMPONENT_NAME, ETH_COMPONENT_PATH, dmQuery, dmValue, ccsp_string, TRUE );
    }
    CcspTraceInfo(("%s: result[%s]\n", __FUNCTION__, (result != ANSC_STATUS_SUCCESS)?"FAILED":"SUCCESS"));
}
#endif  //FEATURE_RDKB_AUTO_PORT_SWITCH

static ANSC_STATUS WanMgr_RdkBus_GetParamNames( char *pComponent, char *pBus, char *pParamName, char a2cReturnVal[][BUFLEN_256], int *pReturnSize )
{
    CCSP_MESSAGE_BUS_INFO  *bus_info         = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterInfoStruct_t  **retInfo;
    char                    *ParamName[ 1 ];
    int                    ret               = 0,
                           nval;

    ret = CcspBaseIf_getParameterNames(
                                    bus_handle,
                                    pComponent,
                                    pBus,
                                    pParamName,
                                    1,
                                    &nval,
                                    &retInfo);

    //Copy the value
    if( CCSP_SUCCESS == ret )
    {
        int iLoopCount;

        *pReturnSize = nval;

        for( iLoopCount = 0; iLoopCount < nval; iLoopCount++ )
        {
           if( NULL != retInfo[iLoopCount]->parameterName )
           {
              //CcspTraceInfo(("%s parameterName[%d,%s]\n",__FUNCTION__,iLoopCount,retInfo[iLoopCount]->parameterName));
              snprintf( a2cReturnVal[iLoopCount], strlen( retInfo[iLoopCount]->parameterName ) + 1, "%s", retInfo[iLoopCount]->parameterName );
           }
        }

        if( retInfo )
        {
          free_parameterInfoStruct_t(bus_handle, nval, retInfo);
        }

        return ANSC_STATUS_SUCCESS;
    }

    if( retInfo )
    {
      free_parameterInfoStruct_t(bus_handle, nval, retInfo);
    }

    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS WanMgr_RdkBus_GetParamValueFromAnyComp( char * pQuery, char *pValue)
{
    if ((pQuery == NULL) || (pValue == NULL))
    {
        CcspTraceError (("%s %d: invalid args..\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    int ret ;
    int size = 0;
    char dst_pathname_cr[BUFLEN_256] = {0};
    componentStruct_t ** ppComponents = NULL;

    snprintf(dst_pathname_cr, sizeof(dst_pathname_cr) - 1, "eRT.%s", CCSP_DBUS_INTERFACE_CR);

    // Get the component name and dbus path which has the data model 
    ret = CcspBaseIf_discComponentSupportingNamespace
        (
         bus_handle,
         dst_pathname_cr,
         pQuery,
         "",
         &ppComponents,
         &size
        );

    if ((ret != CCSP_SUCCESS) || (size <= 0))
    {
        CcspTraceError (("%s %d: CcspBaseIf_discComponentSupportingNamespace() call failed\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    // query the data model from the component
    CcspTraceInfo (("%s %d: quering dm:%s from component:%s of dbuspath:%s\n", 
                __FUNCTION__, __LINE__, pQuery, ppComponents[0]->componentName, ppComponents[0]->dbusPath));
    if (WanMgr_RdkBus_GetParamValues (ppComponents[0]->componentName, ppComponents[0]->dbusPath, pQuery, pValue) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError (("%s %d: CcspBaseIf_discComponentSupportingNamespace() call failed\n", __FUNCTION__, __LINE__));
        free_componentStruct_t(bus_handle, size, ppComponents);
        return ANSC_STATUS_FAILURE;
    }

    free_componentStruct_t(bus_handle, size, ppComponents);
    CcspTraceInfo (("%s %d: dm:%s got value %s\n", __FUNCTION__, __LINE__, pQuery, pValue));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_RdkBus_GetParamValues( char *pComponent, char *pBus, char *pParamName, char *pReturnVal )
{
    CCSP_MESSAGE_BUS_INFO  *bus_info         = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t   **retVal = NULL;
    char                    *ParamName[ 1 ] = {0};
    int                    ret               = 0,
                           nval              = 0;

    //Assign address for get parameter name
    ParamName[0] = pParamName;

    ret = CcspBaseIf_getParameterValues(
                                    bus_handle,
                                    pComponent,
                                    pBus,
                                    ParamName,
                                    1,
                                    &nval,
                                    &retVal);

    //Copy the value
    if( CCSP_SUCCESS == ret )
    {
        //CcspTraceInfo(("%s parameterValue[%s]\n",__FUNCTION__,retVal[0]->parameterValue));

        if( NULL != retVal[0]->parameterValue )
        {
            memcpy( pReturnVal, retVal[0]->parameterValue, strlen( retVal[0]->parameterValue ) + 1 );
        }

        if( retVal )
        {
            free_parameterValStruct_t (bus_handle, nval, retVal);
        }

        return ANSC_STATUS_SUCCESS;
    }

    if( retVal )
    {
       free_parameterValStruct_t (bus_handle, nval, retVal);
    }

    return ANSC_STATUS_FAILURE;
}



ANSC_STATUS WanMgr_RdkBus_SetParamValues( char *pComponent, char *pBus, char *pParamName, char *pParamVal, enum dataType_e type, BOOLEAN bCommit )
{
    CCSP_MESSAGE_BUS_INFO *bus_info              = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t   param_val[1]          = { 0 };
    char                  *faultParam            = NULL;
    char                   acParameterName[BUFLEN_256]  = { 0 },
                           acParameterValue[BUFLEN_128] = { 0 };
    int                    ret                   = 0;

    //Copy Name
    snprintf( acParameterName,sizeof(acParameterName)-1, "%s", pParamName );
    param_val[0].parameterName  = acParameterName;

    //Copy Value
    snprintf( acParameterValue,sizeof(acParameterValue)-1, "%s", pParamVal );
    param_val[0].parameterValue = acParameterValue;

    //Copy Type
    param_val[0].type           = type;

    ret = CcspBaseIf_setParameterValues(
                                        bus_handle,
                                        pComponent,
                                        pBus,
                                        0,
                                        0,
                                        param_val,
                                        1,
                                        bCommit,
                                        &faultParam
                                       );

    if(ret != CCSP_SUCCESS )
    {
        if ( faultParam != NULL )
        {
            bus_info->freefunc( faultParam );
        }
        CcspTraceError(("%s-%d Failed to set %s\n",__FUNCTION__,__LINE__,pParamName));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

/* * WanMgr_RdkBus_GetInterfaceInstanceInOtherAgent() */
static ANSC_STATUS WanMgr_RdkBus_GetInterfaceInstanceInOtherAgent( WAN_NOTIFY_ENUM enNotifyAgent, char *pIfName, INT *piInstanceNumber )
{
    //Validate buffer
    if( ( NULL == pIfName ) || ( NULL == piInstanceNumber ) )
    {
        CcspTraceError(("%s Invalid Buffer\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Initialise default value
    *piInstanceNumber   = -1;

    switch( enNotifyAgent )
    {
        case NOTIFY_TO_VLAN_AGENT:
        {
            char acTmpReturnValue[BUFLEN_256] = { 0 },
                 a2cTmpTableParams[10][BUFLEN_256] = { 0 };
            INT  iLoopCount,
                 iTotalNoofEntries;

            if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, VLAN_ETHLINK_NOE_PARAM_NAME, acTmpReturnValue ) )
            {
                CcspTraceError(("%s %d Failed to get param value\n", __FUNCTION__, __LINE__));
                return ANSC_STATUS_FAILURE;
            }

            //Total count
            iTotalNoofEntries = atoi( acTmpReturnValue );
            CcspTraceInfo(("%s %d - TotalNoofEntries:%d\n", __FUNCTION__, __LINE__, iTotalNoofEntries));

            if( 0 >= iTotalNoofEntries )
            {
               return ANSC_STATUS_SUCCESS;
            }

            //Get table names
            iTotalNoofEntries = 0;
            if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamNames( VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, VLAN_ETHLINK_TABLE_NAME, a2cTmpTableParams , &iTotalNoofEntries ))
            {
                CcspTraceError(("%s %d Failed to get param value\n", __FUNCTION__, __LINE__));
                return ANSC_STATUS_FAILURE;
            }

            //Traverse from loop
            for ( iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++ )
            {
                char acTmpQueryParam[BUFLEN_256] = { 0 };

                //Query
                snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ), "%sX_RDK_BaseInterface", a2cTmpTableParams[ iLoopCount ] );

                memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
                if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
                {
                    CcspTraceError(("%s %d Failed to get param value\n", __FUNCTION__, __LINE__));
                    continue;
                }

                //Compare ifname
#ifdef _HUB4_PRODUCT_REQ_
                // The base interface name is ptm0 in vlanmanager but in wanmanager we have dsl0 this needs to addressed in wan unification.
                if(0 == strncmp(acTmpReturnValue, "ptm0", 4))
                {
                     strncpy(acTmpReturnValue, "dsl0", 4);
                }
#endif
                if( 0 == strncmp(acTmpReturnValue, pIfName, BUFLEN_256) )
                {
                    char  tmpTableParam[BUFLEN_256] = { 0 };
                    const char *last_two;

                    //Copy table param
                    snprintf( tmpTableParam, sizeof(tmpTableParam), "%s", a2cTmpTableParams[ iLoopCount ] );

                    //Get last two chareters from return value and cut the instance
                    sscanf(tmpTableParam, VLAN_ETHLINK_TABLE_FORMAT , piInstanceNumber);
                    break;
                }
            }
        }
        break; /* * NOTIFY_TO_VLAN_AGENT */

        default:
        {
            CcspTraceError(("%s Invalid Case\n", __FUNCTION__));
        }
        break; /* * default */
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_RdkBusDeleteVlanLink(DML_WAN_IFACE* pInterface )
{
    char    acSetParamName[BUFLEN_256];
    INT     iVLANInstance   = -1;

    //Get Instance for corresponding name
    WanMgr_RdkBus_GetInterfaceInstanceInOtherAgent( NOTIFY_TO_VLAN_AGENT, pInterface->Name, &iVLANInstance );

    //Index is not present. so no need to do anything any VLAN instance
    if( -1 != iVLANInstance )
    {
        CcspTraceInfo(("%s %d VLAN Instance:%d\n",__FUNCTION__, __LINE__,iVLANInstance));

        //Set VLAN EthLink Refresh
        memset( acSetParamName, 0, sizeof(acSetParamName) );
        snprintf( acSetParamName, sizeof(acSetParamName), VLAN_ETHLINK_ENABLE_PARAM_NAME, iVLANInstance );
        WanMgr_RdkBus_SetParamValues( VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, "false", ccsp_boolean, TRUE );

        CcspTraceInfo(("%s %d Successfully notified disable event to VLAN Agent for %s interface[%s]\n", __FUNCTION__, __LINE__, pInterface->Name,acSetParamName));

        /*
         * Delete Device.Ethernet.Link. Instance.
         * VLANAgent will delete the vlan interface as part table deletion process.
         */
        memset(acSetParamName, 0, sizeof(acSetParamName));
        snprintf(acSetParamName, sizeof(acSetParamName), "%s%d.", VLAN_ETHLINK_TABLE_NAME, iVLANInstance);
        if (CCSP_SUCCESS != CcspBaseIf_DeleteTblRow(
                    bus_handle,
                    VLAN_COMPONENT_NAME,
                    VLAN_DBUS_PATH,
                    0, /* session id */
                    acSetParamName))
        {
            CcspTraceError(("%s Failed to delete table %s\n", __FUNCTION__, acSetParamName));
            return ANSC_STATUS_FAILURE;
        }
    }
    else
    {
        CcspTraceError(("%s Vlan link entry not found. \n", __FUNCTION__ ));
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d Successfully deleted vlan link %s \n", __FUNCTION__, __LINE__, acSetParamName));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS DmlGetInstanceByKeywordFromPandM(char *ifname, int *piInstanceNumber)
{
    char acTmpReturnValue[256] = {0};
    int iLoopCount,
        iTotalNoofEntries;
    if (ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues(PAM_COMPONENT_NAME, PAM_DBUS_PATH, PAM_NOE_PARAM_NAME, acTmpReturnValue))
    {
        CcspTraceError(("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    //Total count
    iTotalNoofEntries = atoi(acTmpReturnValue);

    if ( 0 >= iTotalNoofEntries )
    {
        return ANSC_STATUS_SUCCESS;
    }

    //Traverse from loop
    for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
    {
        char acTmpQueryParam[256] = {0};

        //Query
        snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), PAM_IF_PARAM_NAME, iLoopCount + 1);
        memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
        if (ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues(PAM_COMPONENT_NAME, PAM_DBUS_PATH, acTmpQueryParam, acTmpReturnValue))
        {
            CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
            continue;
        }

        //Compare name
        if (0 == strcmp(acTmpReturnValue, ifname))
        {
            *piInstanceNumber = iLoopCount + 1;
             break;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

int WanMgr_RdkBus_GetParamValuesFromDB( char *pParamName, char *pReturnVal, int returnValLength )
{
    int     retPsmGet     = CCSP_SUCCESS;
    CHAR   *param_value   = NULL, tmpOutput[BUFLEN_256] = {0};

    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pReturnVal ) || ( 0 >= returnValLength ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }

#ifndef WAN_DB_USAGE_BY_SYSCFG
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, pParamName, NULL, &param_value); 
    if (retPsmGet != CCSP_SUCCESS) { 
        CcspTraceError(("%s Error %d reading %s\n", __FUNCTION__, retPsmGet, pParamName));
    } 
    else { 
        /* Copy DB Value */
        snprintf(pReturnVal, returnValLength, "%s", param_value);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(param_value);
    } 
#else
    if( 0 == syscfg_get( NULL, pParamName, tmpOutput, sizeof(tmpOutput)) )
    {
        /* Copy DB Value */
        snprintf(pReturnVal, returnValLength, "%s", tmpOutput);
        retPsmGet = CCSP_SUCCESS;
    }
    else
    {
        retPsmGet = CCSP_FAILURE;
    }
#endif
    //CcspTraceInfo(("PSM Read => %s : %s\n", pParamName, pReturnVal));

   return retPsmGet;
}

int WanMgr_RdkBus_SetParamValuesToDB( char *pParamName, char *pParamVal )
{
    int     retPsmSet  = CCSP_SUCCESS;

    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pParamVal ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }

#ifndef WAN_DB_USAGE_BY_SYSCFG
    retPsmSet = PSM_Set_Record_Value2(bus_handle,g_Subsystem, pParamName, ccsp_string, pParamVal); 
    if (retPsmSet != CCSP_SUCCESS) { 
        CcspTraceError(("%s Error %d writing %s\n", __FUNCTION__, retPsmSet, pParamName));
    } 
#else
    if ( syscfg_set_commit(NULL, pParamName, pParamVal) != 0 )
    {
        CcspTraceError(("%s Error writing %s\n", __FUNCTION__,pParamName));
        retPsmSet  = CCSP_FAILURE;
    }
#endif

    return retPsmSet;
}

/* WanMgr_GetBaseInterfaceStatus()
 * Updates current BaseInterfaceStatus of WanInterfaces using a DM get of BaseInterface Dml.
 * This function will update BaseInterfaceStatus if WanManager restarted or BaseInterfaceStatus is already set by other components before WanManager rbus is ready.
 * Args: DML_WAN_IFACE struct
 * Returns: ANSC_STATUS_SUCCESS on successful get, else ANSC_STATUS_FAILURE.
 */

ANSC_STATUS WanMgr_GetBaseInterfaceStatus (DML_WAN_IFACE *pWanIfaceData)
{
    //get PHY status
    char dmQuery[BUFLEN_256] = {0};
    char dmValue[BUFLEN_256] = {0};

    if(pWanIfaceData->BaseInterface == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if(strstr(pWanIfaceData->BaseInterface, "Cellular") != NULL)
    {
        snprintf(dmQuery, sizeof(dmQuery)-1, "%s%s", pWanIfaceData->BaseInterface, CELLULARMGR_PHY_STATUS_DM_SUFFIX);
        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, dmValue))
        {
            CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
            return ANSC_STATUS_FAILURE;
        }

        if(strcmp(dmValue,"true") == 0)
        {
            pWanIfaceData->BaseInterfaceStatus = WAN_IFACE_PHY_STATUS_UP;
        }

    }
    else if(strstr(pWanIfaceData->BaseInterface, "EthernetWAN") != NULL)
    {
        snprintf(dmQuery, sizeof(dmQuery)-1, "%s%s", pWanIfaceData->BaseInterface, ETHWAN_PHY_STATUS_DM_SUFFIX);
        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, dmValue))
        {
            CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
            return ANSC_STATUS_FAILURE;
        }

        if(strcmp(dmValue,"true") == 0)
        {
            pWanIfaceData->BaseInterfaceStatus = WAN_IFACE_PHY_STATUS_UP;
        }

    }
    else if(strstr(pWanIfaceData->BaseInterface, "CableModem") != NULL)
    {
        snprintf(dmQuery, sizeof(dmQuery)-1, "%s%s", pWanIfaceData->BaseInterface, CMAGENT_PHY_STATUS_DM_SUFFIX);
        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, dmValue))
        {
            CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
            return ANSC_STATUS_FAILURE;
        }

        if(strcmp(dmValue,"OPERATIONAL") == 0)
        {
            pWanIfaceData->BaseInterfaceStatus = WAN_IFACE_PHY_STATUS_UP;
        }

    }
    else
    {
        snprintf(dmQuery, sizeof(dmQuery)-1, "%s%s", pWanIfaceData->BaseInterface, STATUS_DM_SUFFIX);
        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, dmValue))
        {
            CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
            return ANSC_STATUS_FAILURE;
        }

        if(strcmp(dmValue,"Up") == 0)
        {
            pWanIfaceData->BaseInterfaceStatus = WAN_IFACE_PHY_STATUS_UP;
        }
    }
    CcspTraceInfo(("%s %d  %s : %s \n", __FUNCTION__, __LINE__, dmQuery, dmValue));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_RdkBus_setDhcpv6DnsServerInfo(void)
{
    ANSC_STATUS retStatus = ANSC_STATUS_FAILURE;
    char sysevent_buf[BUFLEN_128] = {'\0'};

    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_ULA_ADDRESS, sysevent_buf, BUFLEN_128);
    if(sysevent_buf[0] != '\0')
    {
        retStatus = WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, "Device.DHCPv6.Server.Pool.1.X_RDKCENTRAL-COM_DNSServersEnabled", "true", ccsp_boolean, TRUE );
        if(retStatus == ANSC_STATUS_SUCCESS)
        {
            retStatus = WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, "Device.DHCPv6.Server.Pool.1.X_RDKCENTRAL-COM_DNSServers", sysevent_buf, ccsp_string, TRUE );
            if(retStatus != ANSC_STATUS_SUCCESS)
            {
                CcspTraceError(("%s %d - SetDataModelParameter() failed for X_RDKCENTRAL-COM_DNSServers parameter \n", __FUNCTION__, __LINE__));
            }
        }
        else
        {
            CcspTraceError(("%s %d - SetDataModelParameter() failed for X_RDKCENTRAL-COM_DNSServersEnabled parameter \n", __FUNCTION__, __LINE__));
        }
    } 
    else
    {
        CcspTraceInfo(("%s %d - sysevent ula_address is empty \n", __FUNCTION__, __LINE__));
    }
    return retStatus;
}
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
ANSC_STATUS WanMgr_RdkBus_setWanIpInterfaceData(DML_VIRTUAL_IFACE*  pVirtIf)
{
    ANSC_STATUS retStatus = ANSC_STATUS_SUCCESS;
    char dmQuery[BUFLEN_256] = {0};
    snprintf(dmQuery, sizeof(dmQuery)-1, "%s.LowerLayers", pVirtIf->IP.Interface);
    if(pVirtIf->PPP.Enable == TRUE)
    {
        retStatus = WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, dmQuery, pVirtIf->PPP.Interface, ccsp_string, TRUE );
        CcspTraceInfo(("%s %d - Updating %s => %s\n", __FUNCTION__, __LINE__,dmQuery, pVirtIf->PPP.Interface));
    }else if(pVirtIf->VLAN.Enable == TRUE)
    {
        retStatus = WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, dmQuery, pVirtIf->VLAN.CurrentVlan, ccsp_string, TRUE );
        CcspTraceInfo(("%s %d - Updating %s => %s\n", __FUNCTION__, __LINE__,dmQuery,pVirtIf->VLAN.CurrentVlan));
    }
    return retStatus;
}
#endif

ANSC_STATUS  WanMgr_RdkBus_ConfigureVlan(DML_VIRTUAL_IFACE* pVirtIf, BOOL VlanEnable)
{
    if(pVirtIf ==NULL)
    {
        CcspTraceError(("%s Invalid Args\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    char acSetParamName[BUFLEN_256] ={0};
    char acSetParamValue[256] = {0};
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;
    if(VlanEnable && pVirtIf->VLAN.NoOfInterfaceEntries > 1)
    {
        //Start VLAN discovery Timer
        CcspTraceInfo(("%s %d  Starting VlanTimer\n", __FUNCTION__,__LINE__));
        memset(&(pVirtIf->VLAN.TimerStart), 0, sizeof(struct timespec));
        clock_gettime(CLOCK_MONOTONIC_RAW, &(pVirtIf->VLAN.TimerStart));
    }
    CcspTraceInfo(("%s %d %s VLAN %s\n", __FUNCTION__,__LINE__, VlanEnable? "Enabling":"Disabling",pVirtIf->VLAN.CurrentVlan));
    snprintf( acSetParamName, sizeof(acSetParamName), "%s.Enable", pVirtIf->VLAN.CurrentVlan);
    snprintf( acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", VlanEnable? "true":"false" );

    ret = WanMgr_RdkBus_SetParamValues( VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_boolean, TRUE );
    if(ret != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d DM set %s %s failed\n", __FUNCTION__,__LINE__, acSetParamName, acSetParamValue));
        WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_ERROR_VLAN_CREATION_FAILED);	
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s %d DM set %s %s Successful\n", __FUNCTION__,__LINE__, acSetParamName, acSetParamValue));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanManager_ConfigurePPPSession(DML_VIRTUAL_IFACE* pVirtIf, BOOL PPPEnable)
{

    char acSetParamName[256] = {0};
    char acSetParamValue[256] = {0};
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;

    syscfg_set_commit(NULL, SYSCFG_WAN_INTERFACE_NAME, pVirtIf->Name);

#ifdef DYNAMIC_CONFIGURE_PPP_LOWERLAYER
    snprintf( acSetParamName, sizeof(acSetParamName), "%s.Name", pVirtIf->VLAN.CurrentVlan);

    ret = WanMgr_RdkBus_GetParamValues( VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue );
    if(ret != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d DM get %s %s failed\n", __FUNCTION__,__LINE__, acSetParamName, acSetParamValue));
        return ANSC_STATUS_FAILURE;
    }
    strncpy(pVirtIf->Name, acSetParamValue, sizeof(pVirtIf->Name));

    memset(acSetParamName, 0, sizeof(acSetParamName));
    memset(acSetParamValue, 0, sizeof(acSetParamValue));
    snprintf( acSetParamName, sizeof(acSetParamName), "%s.LowerLayers", pVirtIf->PPP.Interface);
    snprintf( acSetParamValue, sizeof(acSetParamValue), WAN_INTERFACE_TABLE, (pVirtIf->baseIfIdx + 1), (pVirtIf->VirIfIdx + 1));
    ret = WanMgr_RdkBus_SetParamValues( PPPMGR_COMPONENT_NAME, PPPMGR_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_string, TRUE );

    if(ret != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d DM set %s %s failed\n", __FUNCTION__,__LINE__, acSetParamName, acSetParamValue));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s %d DM set %s %s Successful\n", __FUNCTION__,__LINE__, acSetParamName, acSetParamValue));
#endif

    //Set PPP Enable
    CcspTraceInfo(("%s %d %s PPP %s\n", __FUNCTION__,__LINE__, PPPEnable? "Enabling":"Disabling",pVirtIf->PPP.Interface));
    snprintf( acSetParamName, DATAMODEL_PARAM_LENGTH, "%s.Enable", pVirtIf->PPP.Interface );
    snprintf( acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", PPPEnable? "true":"false" );
    ret = WanMgr_RdkBus_SetParamValues( PPPMGR_COMPONENT_NAME, PPPMGR_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_boolean, TRUE );

    if(ret != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d DM set %s %s failed\n", __FUNCTION__,__LINE__, acSetParamName, acSetParamValue));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s %d DM set %s %s Successful\n", __FUNCTION__,__LINE__, acSetParamName, acSetParamValue));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_GetSelectedIPMode(DML_VIRTUAL_IFACE * pVirtIf)
{
    char param_value[256] = {0};

    // start default as dual stack.
    pVirtIf->IP.SelectedMode = DUAL_STACK_MODE;

    // ModeForceEnable set to true on changing the IP.Mode data model.
    // IP.Mode will have precedence over Preferred Mode when ModeForceEnable is set to true.
    // ModeForceEnable is reset to false only on Factory Reset.
    if(pVirtIf->IP.ModeForceEnable == FALSE)
    {
        if(CCSP_SUCCESS == WanMgr_RdkBus_GetParamValuesFromDB("Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.IPModeEnable",param_value,sizeof(param_value)))
        {
            if(strcmp(param_value, "1") == 0)
            {
                pVirtIf->IP.SelectedMode = pVirtIf->IP.PreferredMode;
                CcspTraceInfo(("%s %d - Prefrred Mode set to Selected Mode \n", __FUNCTION__, __LINE__));
            }
        }
        else
        {
            CcspTraceInfo(("%s %d - Failed to get IPModeEnable param from psm \n", __FUNCTION__, __LINE__));
            return ANSC_STATUS_FAILURE;
        }
    }
    CcspTraceInfo(("%s %d - IP SelectedMode=[%d] IP ModeForceEnable=[%d]\n", __FUNCTION__, __LINE__, pVirtIf->IP.SelectedMode, pVirtIf->IP.ModeForceEnable));
    return ANSC_STATUS_SUCCESS;
}

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

void Wanmgr_TriggerReboot()
{
    char lastRebootReason[64] = {'\0'};
    // set reboot reason as previous reboot reason because of webPA and Webconfig dependency on various reboot scenarios.
    if(syscfg_get( NULL, "X_RDKCENTRAL-COM_LastRebootReason", lastRebootReason, sizeof(lastRebootReason)) == 0)
    {
        if(lastRebootReason[0] != '\0')
        {
            CcspTraceInfo(("%s %d: X_RDKCENTRAL-COM_LastRebootReason = [%s]\n", __FUNCTION__, __LINE__, lastRebootReason));
            CcspTraceInfo(("%s %d: WanManager is triggering the reboot and setting the reboot reason as last reboot reason \n", __FUNCTION__, __LINE__));

            if (syscfg_set_commit(NULL, "X_RDKCENTRAL-COM_LastRebootReason", lastRebootReason) != 0)
            {
                CcspTraceInfo(("%s %d: Failed to set LastRebootReason\n", __FUNCTION__, __LINE__));
            }
            if (syscfg_set_commit(NULL, "X_RDKCENTRAL-COM_LastRebootCounter", "1") != 0)
            {
                CcspTraceInfo(("%s %d: Failed to set LastRebootCounter\n", __FUNCTION__, __LINE__));
            }
        }
        else
        {
            CcspTraceInfo(("%s %d: lastRebootReason is empty \n", __FUNCTION__, __LINE__));
        }
    }
    else
    {
        CcspTraceInfo(("%s %d: Failed to get LastRebootReason\n", __FUNCTION__, __LINE__));
    }

    // work around if the CPE fails to reboot from the below call and gets stuck.
    wanmgr_sysevent_hw_reconfig_reboot();

    // Call Device Reboot and Exit from state machine.
    if((WanMgr_RdkBus_SetParamValues(PAM_COMPONENT_NAME, PAM_DBUS_PATH, "Device.X_CISCO_COM_DeviceControl.RebootDevice", "Device", ccsp_string, TRUE) == ANSC_STATUS_SUCCESS))
    {
        CcspTraceInfo(("%s %d: WanManager triggered a reboot successfully \n", __FUNCTION__, __LINE__));
    }
    else
    {
        CcspTraceError(("%s %d: WanManager Failed to trigger reboot \n", __FUNCTION__, __LINE__));
    }
}

#define TR181_LANMODE_PARAM "Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode"

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

BOOL WanMgr_isBridgeModeEnabled()
{
    char dmlValue[64] = {0};

    //Query
    if (ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues(PAM_COMPONENT_NAME, PAM_DBUS_PATH, TR181_LANMODE_PARAM, dmlValue))
    {
        CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
        return FALSE;
    }

    //Possible DML values  bridge-dhcp,bridge-static,router
    if(strcmp(dmlValue, "bridge-dhcp") == 0 || strcmp(dmlValue, "bridge-static") == 0 || strcmp(dmlValue, "full-bridge-static") == 0)
    {
        CcspTraceInfo(("%s %d - CPE is in Bridge Mode\n", __FUNCTION__, __LINE__));
        return TRUE;
    }
    else
    {
        CcspTraceInfo(("%s %d - CPE is in Router Mode\n", __FUNCTION__, __LINE__));
        return FALSE;
    }

    return FALSE;
}

ANSC_STATUS WanManager_RdkBus_EnableInterface(DML_WAN_IFACE* pInterface, BOOL Enable)
{
    char acSetParamName[256]  = {0};
    char acSetParamValue[256] = {0};
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;

    //Manage Subcription for Interface Status
    snprintf( acSetParamName, DATAMODEL_PARAM_LENGTH, "%s.Status", pInterface->BaseInterface );
    ret = WanManager_ManageInterfaceStatusSubscription( acSetParamName, Enable );
    if(ret != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to %s %s\n", __FUNCTION__, __LINE__, ((Enable) ? "Subscribe" : "Unsubscribe"), acSetParamName));
        return ANSC_STATUS_FAILURE;
    }
    
    //Interface Enable/Disable
    CcspTraceInfo(("%s %d %s Interface %s\n", __FUNCTION__,__LINE__, Enable? "Enabling":"Disabling",pInterface->Name));
    snprintf( acSetParamName, DATAMODEL_PARAM_LENGTH, "%s.Enable", pInterface->BaseInterface );
    snprintf( acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", Enable? "true":"false" );
    ret = WanMgr_RdkBus_SetParamValues(NULL, NULL, acSetParamName, acSetParamValue, ccsp_boolean, TRUE);
    if(ret != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d DM %s %s %s failed\n", __FUNCTION__,__LINE__, ((Enable) ? "Set" : "Unset"), acSetParamName, acSetParamValue));
        return ANSC_STATUS_FAILURE;
    }   

    CcspTraceInfo(("%s %d DM %s(value:%s) and %s is for %s param Successful\n", __FUNCTION__,__LINE__, ((Enable) ? "Set" : "Unset"), acSetParamValue, ((Enable) ? "Subscribe" : "Unsubscribe"), acSetParamName));
    return ANSC_STATUS_SUCCESS;
}

#ifdef FEATURE_DSLITE_V2
int WanMgr_SetDSLiteEnableToPSM(DML_VIRTUAL_IFACE* pVirtIf, BOOL Enable)
{
    int retPsmSet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};

    _ansc_sprintf(param_value, Enable ? "TRUE" : "FALSE");
    _ansc_sprintf(param_name, PSM_WANMANAGER_IF_VIRIF_ENABLE_DSLITE, pVirtIf->baseIfIdx +1, pVirtIf->VirIfIdx+1);
    WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);
    CcspTraceInfo(("%s-%d: EnableDSLite(%s) set to (%s)\n", __FUNCTION__, __LINE__, param_name, param_value));
    return 0;
}

ANSC_STATUS WanMgr_SysCfgGetBool(const CHAR *key, BOOL *value)
{
    if (!key || !value)
        return ANSC_STATUS_BAD_PARAMETER;

    char buf[8] = {0};

    if (syscfg_get(NULL, key, buf, sizeof(buf)) != 0)
        return ANSC_STATUS_FAILURE;

    if (strcasecmp(buf, "true") == 0 || buf[0] == '1')
        *value = TRUE;
    else
        *value = FALSE;

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_SysCfgGetUint(const CHAR *key, UINT *value)
{
    if (!key || !value)
        return ANSC_STATUS_BAD_PARAMETER;

    char buf[64] = {0};

    if (syscfg_get(NULL, key, buf, sizeof(buf)) != 0)
        return ANSC_STATUS_FAILURE;

    *value = atoi(buf);
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_SysCfgGetStr(const CHAR *key, CHAR *dst, ULONG dst_len)
{
    if (!key || !dst || dst_len == 0)
        return ANSC_STATUS_BAD_PARAMETER;

    dst[0] = '\0';

    char buf[512] = {0};

    if (syscfg_get(NULL, key, buf, sizeof(buf)) != 0)
        return ANSC_STATUS_FAILURE;

    buf[sizeof(buf) - 1] = '\0';
    snprintf(dst, dst_len, "%s", buf);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_SysCfgSetUint(const CHAR *key, UINT value)
{
    if (!key)
        return ANSC_STATUS_BAD_PARAMETER;

    char buf[32];
    snprintf(buf, sizeof(buf), "%u", value);

    if (syscfg_set(NULL, key, buf) != 0)
        return ANSC_STATUS_FAILURE;

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_SysCfgSetStr(const CHAR *key, const CHAR *value)
{
    if (!key || !value)
        return ANSC_STATUS_BAD_PARAMETER;

    if (syscfg_set(NULL, key, value) != 0)
        return ANSC_STATUS_FAILURE;

    return ANSC_STATUS_SUCCESS;
}
#endif