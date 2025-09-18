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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "wanmgr_controller.h"
#include "wanmgr_data.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_interface_sm.h"
#include "wanmgr_platform_events.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_wan_failover.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_telemetry.h"

#define ETH_HW_CONFIGURATION_DM     "Device.Ethernet.Interface.%d.Upstream"
#define ETH_PHY_PATH_DM             "Device.Ethernet.X_RDK_Interface.%d"

/* ---- Global Constants -------------------------- */
#define SELECTION_PROCESS_LOOP_TIMEOUT 250000 // timeout in microseconds. This is the state machine loop interval
#define MAX_PRIORITY_VALUE 255

extern ANSC_HANDLE bus_handle;

typedef enum {
    STATE_PARALLEL_SCAN_SCANNING_INTERFACE = 0,
    STATE_PARALLEL_SCAN_CHECK_RECONFIGURATION,
    STATE_PARALLEL_SCAN_RECONFIGURE_PLATFORM,
    STATE_PARALLEL_SCAN_REBOOT,
    STATE_PARALLEL_SCAN_SELECTED_INTERFACE_UP,
    STATE_PARALLEL_SCAN_SELECTED_INTERFACE_DOWN,
    STATE_PARALLEL_SCAN_INTERFACE_TEAR_DOWN,
    STATE_PARALLEL_SCAN_POLICY_EXIT,
    STATE_PARALLEL_SCAN_POLICY_ERROR,
} WcPsPolicyState_t;



/* SELECTION STATES */
static WcPsPolicyState_t State_ScanningInterface (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t State_CheckReconfiguration (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t State_ReconfigurePaltform (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t State_Reboot (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t State_SelectedInterfaceUp (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t State_SelectedInterfaceDown (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t State_InterfaceTearDown (WanMgr_Policy_Controller_t * pWanController);

/* TRANSITIONS */
static WcPsPolicyState_t Transition_Start (WanMgr_Policy_Controller_t* pWanController);
static WcPsPolicyState_t Transition_NewInterfaceConnected (UINT IfaceId);
static WcPsPolicyState_t Transition_SelectingInterface (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t Transition_ReconfiguringPlatfrom (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t Transition_InterfaceSelected (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t Transition_SelectedInterfaceDown (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t Transition_SelectedInterfaceUp (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t Transition_RestartScan (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t Transition_TearingDown (WanMgr_Policy_Controller_t * pWanController);
static WcPsPolicyState_t Transition_Reboot (WanMgr_Policy_Controller_t * pWanController);

/*
 * WanMgr_UpdateControllerData()
 * - updates the controller data
 * - this function is called every time in the begining of the loop,
 *   so that the states/transition can work with the current data
 */
static void WanMgr_UpdateControllerData (WanMgr_Policy_Controller_t* pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return;
    }

    //Update Wan config
    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        pWanController->WanEnable = pWanConfigData->data.Enable;
        pWanController->AllowRemoteInterfaces = pWanConfigData->data.AllowRemoteInterfaces;

        WanMgrDml_GetConfigData_release(pWanConfigData);
    }
    pWanController->TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();

    //Update group info
    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pWanController->GroupInst - 1));
    if (pWanIfaceGroup != NULL)
    {
        pWanController->GroupCfgChanged = pWanIfaceGroup->ConfigChanged;
        pWanController->GroupPersistSelectedIface = pWanIfaceGroup->PersistSelectedIface;
        pWanController->ResetSelectedInterface = pWanIfaceGroup->ResetSelectedInterface;
        WanMgrDml_GetIfaceGroup_release();
    }
}

/*
 * WanMgr_CheckIfPlatformReconfiguringRequired()
 * - Check EthWan port HW configuration.
 * - If WANoE not selected, Add eth WAn port to LAN bridge.
 * - If eth Wan enabled but WANoE not selected return TRUE.
 * - If eth Wan disabled but WANoE selected return TRUE.
 * - Else return FALSE.
 */
static bool WanMgr_CheckIfPlatformReconfiguringRequired(WanMgr_Policy_Controller_t* pWanController)
{
    UINT uiLoopCount;
    UINT index = 0;
    char dmQuery[BUFLEN_256] = {0};
    char dmValue[BUFLEN_256] = {0};

    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return FALSE;
    }

    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                if(strstr(pWanIfaceData->BaseInterface, "Ethernet") != NULL) 
                {
                    // get WAN Hardware configuration
                    sscanf(pWanIfaceData->BaseInterface, "%*[^0-9]%d", &index);
                    snprintf(dmQuery, sizeof(dmQuery)-1, ETH_HW_CONFIGURATION_DM, index); 
                    if (WanMgr_RdkBus_GetParamValues (ETH_COMPONENT_NAME, ETH_COMPONENT_PATH, dmQuery, dmValue) != ANSC_STATUS_SUCCESS)
                    {
                        CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        return FALSE;
                    }

                    //remove WANoE port to  LAN bridge
                    if ((uiLoopCount != pWanController->activeInterfaceIdx))
                    {
                        CcspTraceInfo(("%s %d:  Adding WANoE port %s to LAN bridge  \n", __FUNCTION__, __LINE__,pWanIfaceData->Name));
                        WanMgr_RdkBus_AddIntfToLanBridge(pWanIfaceData->BaseInterface, TRUE);
                    }

                    if((uiLoopCount == pWanController->activeInterfaceIdx) && (strncasecmp(dmValue, "true", 5) != 0))
                    {
                        CcspTraceInfo(("%s %d:WANOE is selected but eth WAN HW configuration set to LAN, so platform reconf required\n", __FUNCTION__, __LINE__));
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        return TRUE;
                    }else if((uiLoopCount != pWanController->activeInterfaceIdx) && (strncasecmp(dmValue, "true", 5) == 0))
                    {

                        CcspTraceInfo(("%s %d:WANOE is not selected but eth WAN HW configuration set to WAN, so platform reconf required\n", __FUNCTION__, __LINE__));
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        return TRUE;
                    }
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
    return FALSE;
}

/*
 * WanMgr_CheckRescanRequired()
 * Checks ResetSelectedInterface required or NOT.
 * - If ActiveIface Phy status is NOT UP or Wan Staus is NOT UP. Return TRUE.
 * - If Higher Priority interface available. Return TRUE.
 * - If ActiveIface is the highest Priority interface. Reset ResetSelectedInterface flag and Return FALSE;
 */
static BOOL WanMgr_CheckRescanRequired(WanMgr_Policy_Controller_t* pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return TRUE;
    }

    UINT uiLoopCount;
    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);

    if(pActiveInterface->BaseInterfaceStatus != WAN_IFACE_PHY_STATUS_UP || pActiveInterface->VirtIfList->Status != WAN_IFACE_STATUS_UP)
    {
        CcspTraceInfo(("%s %d: ActiveIface %s is not UP. Rescan required\n", __FUNCTION__, __LINE__,pActiveInterface->DisplayName));
        return TRUE;
    }

    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group && pWanIfaceData->Selection.Enable == TRUE)
            {
                /* Compare the Selection.Priority of all the interface */
                if(uiLoopCount != pWanController->activeInterfaceIdx)
                {
                    if(pWanIfaceData->Selection.Priority < pActiveInterface->Selection.Priority)
                    {
                        CcspTraceInfo(("%s %d: Higher Priority interface available. Rescan required\n", __FUNCTION__, __LINE__));
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        return TRUE;
                    }
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    CcspTraceInfo(("%s %d:ActiveIface %s is the highest Priority interface. Rescan not required\n", __FUNCTION__, __LINE__,pActiveInterface->DisplayName));
    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pWanController->GroupInst - 1));
    if (pWanIfaceGroup != NULL)
    {
        pWanIfaceGroup->ResetSelectedInterface = FALSE;
        pWanController->ResetSelectedInterface = FALSE;
        WanMgrDml_GetIfaceGroup_release();
    }
    return FALSE;

}

/*********************************************************************************/
/************************** TRANSITIONS ******************************************/
/*********************************************************************************/

/*
 * Transition_Start()
 * If the ActiveLink flag of any interface is set to TRUE and the interface is disabled (Enable = FALSE): Set ActiveLink to FALSE and persist it in PSM.
 * Move all ethWan ports out of LAN bridge.
 * Set Scanning Timeout value as the LONGEST Selection.Timeout value for all interfaces in the CPE Interface table whose Enable is true and start Timer.
 * Go to state Scanning Interface.
 */
static WcPsPolicyState_t Transition_Start (WanMgr_Policy_Controller_t* pWanController)
{
    UINT uiLoopCount;

    if(pWanController == NULL)
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                if(pWanIfaceData->Selection.Enable == TRUE)
                {
                    if(pWanController->GroupPersistSelectedIface == TRUE && pWanIfaceData->Selection.ActiveLink == TRUE)
                    {
                        CcspTraceInfo(("%s %d GroupPersistSelectedIface is enabled and only last ActiveLink %s ISM will be started\n", __FUNCTION__, __LINE__, pWanIfaceData->DisplayName));
                    }
                    /* Find the maximum timeout Value */
                    if(pWanIfaceData->Selection.Timeout > pWanController->InterfaceSelectionTimeOut)
                    {
                        pWanController->InterfaceSelectionTimeOut = pWanIfaceData->Selection.Timeout;
                    }
                }else if(pWanIfaceData->Selection.ActiveLink == TRUE)
                {
                    /* Selection.Enable is FALSE, reset ActiveLink to FALSE */
                    pWanIfaceData->Selection.ActiveLink == FALSE;
                    DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE);
                }
                //remove all WANoE ports from LAn bridge
                if (strstr(pWanIfaceData->BaseInterface, "Ethernet") != NULL)
                {
                    CcspTraceInfo(("%s %d:  remove WANoE port %s from LAN bridge \n", __FUNCTION__, __LINE__,pWanIfaceData->Name));
                    WanMgr_RdkBus_AddIntfToLanBridge(pWanIfaceData->BaseInterface, FALSE);
                } 
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pWanController->GroupInst - 1));
    if (pWanIfaceGroup != NULL)
    {
        //Parallel scan checks all interfaces simultaniously. Set InitialScanComplete to TRUE.
        pWanIfaceGroup->InitialScanComplete = TRUE;
        CcspTraceInfo(("%s %d  group(%d) Initial Scan Completed\n", __FUNCTION__, __LINE__, pWanController->GroupInst));
        WanMgrDml_GetIfaceGroup_release();
    }


    CcspTraceInfo(("%s %d Maximum Timeout Value %d \n", __FUNCTION__, __LINE__, pWanController->InterfaceSelectionTimeOut));
    //Start the selectionTimer
    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(pWanController->SelectionTimeOutStart));

    return STATE_PARALLEL_SCAN_SCANNING_INTERFACE;
}

/* Transition_NewInterfaceConnected()
 * Set Selection.Status to WAN_IFACE_VALIDATING.
 * Start InterfaceStateMachine thread for connected Interface.
 * Return to the state scanning interface.
 */
static WcPsPolicyState_t Transition_NewInterfaceConnected (UINT IfaceId)
{
    if (IfaceId < 0)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_SCANNING_INTERFACE;
    }
    WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(IfaceId);
    if(pWanDmlIfaceData != NULL)
    {
        DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
        /* Set Selection.Status to WAN_IFACE_VALIDATING */
        pWanIfaceData->Selection.Status = WAN_IFACE_VALIDATING;
        pWanIfaceData->VirtIfChanged = FALSE;

        for(int VirtId=0; VirtId < pWanIfaceData->NoOfVirtIfs; VirtId++)
        {
            DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIface_locked(IfaceId, VirtId);
            if(p_VirtIf != NULL)
            {
                if (p_VirtIf->Enable == FALSE)
                {
                    CcspTraceError(("%s %d: virtual if(%d) : %s is not enabled. Not starting VISM\n", __FUNCTION__, __LINE__,p_VirtIf->VirIfIdx, p_VirtIf->Alias));
                    WanMgr_VirtualIfaceData_release(p_VirtIf);
                    continue;
                }
                WanMgr_VirtualIfaceData_release(p_VirtIf);
            }

            /*Start Interface SM */
            WanMgr_IfaceSM_Controller_t wanIfCtrl;
            WanMgr_IfaceSM_Init(&wanIfCtrl, IfaceId, VirtId);

            if (WanMgr_StartInterfaceStateMachine(&wanIfCtrl) != 0)
            {
                CcspTraceError(("%s %d: Unable to start interface state machine \n", __FUNCTION__, __LINE__));
                return STATE_PARALLEL_SCAN_SCANNING_INTERFACE;
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }
    return STATE_PARALLEL_SCAN_SCANNING_INTERFACE;

}

/* Transition_SelectingInterface()
 * Stop the timer.
 * For the selected interface, set Selection.Status to Selected.
 * Stop the WAN Interface State Machine for ALL OTHER interfaces. Set Selection.Status to "Not Selected" for all these interfaces in the group.
 * Set Link to TRUE for the selected interface. And set Active.Link to FALSE for all other interfaces in the group.
 * Update group config with selected interface details.
 * Go to State Check Reconfiguration.
 */
static WcPsPolicyState_t Transition_SelectingInterface (WanMgr_Policy_Controller_t * pWanController)
{
    UINT uiLoopCount;
    if(pWanController == NULL)
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    /* Reset the Timer */
    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));

    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group && pWanIfaceData->Selection.Enable == TRUE)
            {
                /* Update Selection.Status and ActiveLink for all interfaces in the group. */
                if(uiLoopCount == pWanController->activeInterfaceIdx)
                {
                    pWanIfaceData->Selection.Status = WAN_IFACE_SELECTED;
                    pWanIfaceData->Selection.ActiveLink = TRUE;
                    DmlSetWanActiveLinkInPSMDB(uiLoopCount, TRUE);
                }else
                {
                    pWanIfaceData->Selection.Status = WAN_IFACE_NOT_SELECTED;
                    pWanIfaceData->Selection.ActiveLink = FALSE;
                    DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE);
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }    

    /* Update Group config details with selected interface */
    CcspTraceInfo(("%s %d: setting GroupSelectedInterface(%d) to Group : (%d) \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx, pWanController->GroupInst));
    if (WanMgr_SetGroupSelectedIface (pWanController->GroupInst, (pWanController->activeInterfaceIdx+1)) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s-%d: Failed to set GroupSelectedInterface %d \n",
                    __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    }

    return STATE_PARALLEL_SCAN_CHECK_RECONFIGURATION;
}

/* Transition_ReconfiguringPlatfrom()
 * Reconfigure the platform with the new HW configuration (either Ethernet WAN enabled or disabled).
 * Go to state reconfigure platform.
 */
static WcPsPolicyState_t Transition_ReconfiguringPlatfrom (WanMgr_Policy_Controller_t * pWanController)
{
    UINT ethWanPort;
    char paramName[256] = {0};
    char paramValue[256] = {0};
    parameterValStruct_t upstream_param[1] = {0};
    char *faultParam = NULL;
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    int ret = 0;
    UINT uiLoopCount;

    if(pWanController == NULL)
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    /* get eth interface index from BaseInterface */ 
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                if(strstr(pWanIfaceData->BaseInterface, "Ethernet") != NULL)
                {
                    sscanf(pWanIfaceData->BaseInterface, "%*[^0-9]%d", &ethWanPort);
                    if(uiLoopCount == pWanController->activeInterfaceIdx)
                    {
                        strncpy(paramValue, "true", sizeof(paramValue));
                    }else
                    {
                        strncpy(paramValue, "false", sizeof(paramValue));
                    }
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    /* Set ETH_HW_CONFIGURATION_DM to reconfigure HW */
    snprintf(paramName, sizeof(paramName)-1, ETH_HW_CONFIGURATION_DM, ethWanPort); 

    upstream_param[0].parameterName = paramName;
    upstream_param[0].parameterValue = paramValue;
    upstream_param[0].type = ccsp_boolean;

    ret = CcspBaseIf_setParameterValues(bus_handle, ETH_COMPONENT_NAME , ETH_COMPONENT_PATH,
            0, 0x0,   /* session id and write id */
            upstream_param, 1, TRUE,   /* Commit  */
            &faultParam);

    if ( ( ret != CCSP_SUCCESS ) && ( faultParam )) {
        CcspTraceInfo(("%s CcspBaseIf_setParameterValues %s failed with error %d\n",__FUNCTION__, paramName, ret ));
        bus_info->freefunc( faultParam );
    }

    return STATE_PARALLEL_SCAN_RECONFIGURE_PLATFORM;
}

/* Transition_InterfaceSelected()
 * Do nothing. The interface is already up and ready to be used.
 * Go to State Selected Interface UP.
 */
static WcPsPolicyState_t Transition_InterfaceSelected (WanMgr_Policy_Controller_t * pWanController)
{

    if(pWanController == NULL)
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    return STATE_PARALLEL_SCAN_SELECTED_INTERFACE_UP;
}

/* Transition_SelectedInterfaceDown()
 * Do Nothing. Interface SM will exit with PHY down.
 * Go to State Selected Interface Down.
 */
static WcPsPolicyState_t Transition_SelectedInterfaceDown (WanMgr_Policy_Controller_t * pWanController)
{
    if(pWanController == NULL)
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    return STATE_PARALLEL_SCAN_SELECTED_INTERFACE_DOWN; 
}

/* Transition_SelectedInterfaceUp()
 * Start Interface State Machine thread for selected Interface.
 * Go to state selected interface Up
 */
static WcPsPolicyState_t Transition_SelectedInterfaceUp (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    for(int VirtId=0; VirtId < pActiveInterface->NoOfVirtIfs; VirtId++)
    {
        DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIface_locked(pWanController->activeInterfaceIdx, VirtId);
        if(p_VirtIf != NULL)
        {
            if (p_VirtIf->Enable == FALSE)
            {
                CcspTraceError(("%s %d: virtual if(%d) : %s is not enabled. Not starting VISM\n", __FUNCTION__, __LINE__,p_VirtIf->VirIfIdx, p_VirtIf->Alias));
                WanMgr_VirtualIfaceData_release(p_VirtIf);
                continue;
            }
            WanMgr_VirtualIfaceData_release(p_VirtIf);
        }

        /*Start Interface SM */
        WanMgr_IfaceSM_Controller_t wanIfCtrl;
        WanMgr_IfaceSM_Init(&wanIfCtrl, pWanController->activeInterfaceIdx, VirtId); 

        if (WanMgr_StartInterfaceStateMachine(&wanIfCtrl) != 0)
        {
            CcspTraceError(("%s %d: Unable to start interface state machine \n", __FUNCTION__, __LINE__));
            return STATE_PARALLEL_SCAN_SELECTED_INTERFACE_DOWN;
        }
    }
    pActiveInterface->VirtIfChanged = FALSE;
    return STATE_PARALLEL_SCAN_SELECTED_INTERFACE_UP;
}

/* Transition_RestartScan()
 * Set Selection.Status to WAN_IFACE_VALIDATING for the selected Interface.
 * Set ActiveLink to FALSE for all interfaces of the Group.
 * Move all ethWan ports out of LAN bridge.
 * Set ResetSelectedInterface to False.
 * Set ResetFailOverScan to True.
 * Set Scanning Timeout value as the LONGEST Selection.Timeout value for all interfaces in the CPE Interface table whose Enable is true and start Timer.
 * Go to state Scanning.
 */
static WcPsPolicyState_t Transition_RestartScan (WanMgr_Policy_Controller_t * pWanController)
{
    UINT uiLoopCount;

    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    /* Set Selection.Status to WAN_IFACE_VALIDATING */
    pActiveInterface->Selection.Status = WAN_IFACE_VALIDATING;
    /* Reset Group config */
    WanMgr_SetGroupSelectedIface (pWanController->GroupInst, 0);

    /* Reset Timeout */
    pWanController->InterfaceSelectionTimeOut = 0;
    pWanController->activeInterfaceIdx = -1;

    /* Reset ActiveLink for all interfaces in the group. */
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                pWanIfaceData->Selection.ActiveLink = FALSE;
                DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE);

                /* Update the max timeout */
                if(pWanIfaceData->Selection.Enable == TRUE)
                {
                    /* Find the maximum timeout Value */
                    if(pWanIfaceData->Selection.Timeout > pWanController->InterfaceSelectionTimeOut)
                    {
                        pWanController->InterfaceSelectionTimeOut = pWanIfaceData->Selection.Timeout;
                    }
                }

                //remove all WANoE ports from LAn bridge
                if (strstr(pWanIfaceData->BaseInterface, "Ethernet") != NULL)
                {
                    CcspTraceInfo(("%s %d:  remove WANoE port %s from LAN bridge \n", __FUNCTION__, __LINE__,pWanIfaceData->Name));
                    WanMgr_RdkBus_AddIntfToLanBridge(pWanIfaceData->BaseInterface, FALSE);
                }
            }
    	    pWanIfaceData->bSendSelectionTimerExpired = TRUE;
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pWanController->GroupInst - 1));
    if (pWanIfaceGroup != NULL)
    {
        pWanIfaceGroup->ResetSelectedInterface = FALSE;
        pWanController->ResetSelectedInterface = FALSE;
        WanMgrDml_GetIfaceGroup_release();
    }

    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        pWanConfigData->data.ResetFailOverScan = TRUE;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    CcspTraceInfo(("%s %d Maximum Timeout Value %d \n", __FUNCTION__, __LINE__, pWanController->InterfaceSelectionTimeOut));
    //ReStart the selectionTimer
    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(pWanController->SelectionTimeOutStart));

    return STATE_PARALLEL_SCAN_SCANNING_INTERFACE;
}

/* Transition_TearingDown()
 * Stop the WAN Interface State Machine for all the interfaces in the group by setting Selection.Status to Not Selected.
 * Reset Interface table by changing Status of INVALID interfaces to Disabled. 
 * Reset selected interface details in Group config to the default values.
 * If Policy is changed. Set ActiveLink to FALSE for all interfaces of the Group.
 * Go to State Interface Tear Down.
 */
static WcPsPolicyState_t Transition_TearingDown (WanMgr_Policy_Controller_t * pWanController)
{
    UINT uiLoopCount;

    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    /* Reset ActiveLink for all interfaces in the group. */
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                pWanIfaceData->Selection.Status = WAN_IFACE_NOT_SELECTED;
                /* set INVALID interfaces as DISABLED */
                if (pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_INVALID)
                {
                    pWanIfaceData->VirtIfList->Status = WAN_IFACE_STATUS_DISABLED;
                    CcspTraceInfo(("%s-%d: VirtIfList->Status=Disabled, Interface-Idx=%d, Interface-Name=%s\n",
                                __FUNCTION__, __LINE__, uiLoopCount, pWanIfaceData->DisplayName));
                }
                if(pWanController->GroupCfgChanged == TRUE)
                {
                    pWanIfaceData->Selection.ActiveLink = FALSE;
                    DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE);
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    /* Reset Group config */
    WanMgr_SetGroupSelectedIface (pWanController->GroupInst, 0);

    return STATE_PARALLEL_SCAN_INTERFACE_TEAR_DOWN;
}
/* Transition_Reboot()
 * Reboot the unit using system call.
 * Go to state Reboot.
 */
static WcPsPolicyState_t Transition_Reboot (WanMgr_Policy_Controller_t * pWanController)
{
    if(pWanController == NULL)
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    CcspTraceInfo(("%s %d: wanmanager triggering reboot. \n", __FUNCTION__, __LINE__));
    Wanmgr_TriggerReboot();

    return STATE_PARALLEL_SCAN_REBOOT;
}
/*********************************************************************************/
/**************************** STATES *********************************************/
/*********************************************************************************/

/*
 * State_ScanningInterface()
 * If, Enable is false OR X_RDK_WanManager.Policy is changed OR Group configuration is changed, Tearing Down Transition will be called.
 * If, for any interface, Status is Up AND ActiveLink is true (i.e. Last active WAN before reboot.) whose Selection.Enable is true. 
 The interface is selected and Selecting Interface Transition will be called.
 * If, for any interface, Status is Up AND Selection.Priority is the HIGHEST out of all interfaces in the group whose Selection.Enable is true AND no valid last ActiveLink interface available. 
 The interface is selected and Selecting Interface Transition will be called.
 * If, for any interface, Status is Up AND this interface is the ONLY interface in the group whose Selection.Enable is true. 
 The interface is selected and Selecting Interface Transition will be called.
 * If, for any interface, Status is Up AND Selection.Priority is the HIGHEST out of all valid interfaces AND Timer value is greater than the Scanning Timeout value. 
 The interface is selected and Selecting Interface Transition will be called.
 * If, for any interface, Status is Up AND Selection.Enable is True AND Selection.Group equals the input Group parameter AND VirtIfList->Status is Disabled. New Interface Connected transition called.
 */
static WcPsPolicyState_t State_ScanningInterface (WanMgr_Policy_Controller_t * pWanController)
{
    UINT highPriorityValidIface = -1;
    UINT highPriorityValue = MAX_PRIORITY_VALUE; //Set maximum priority value
    UINT highPriorityActiveValue = MAX_PRIORITY_VALUE;
    struct timespec CurrentTime;
    UINT uiLoopCount;
    BOOL lastSelectedIfaceFound = FALSE;

    if(pWanController == NULL)
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    if(pWanController->WanEnable == FALSE ||
            pWanController->GroupCfgChanged == TRUE )
    {
        CcspTraceInfo(("%s %d  Tearing Down Selection Policy \n", __FUNCTION__, __LINE__));
        return Transition_TearingDown(pWanController);
    }

    /* Select the valid interface */
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group && pWanIfaceData->Selection.Enable == TRUE)
            {
                if(pWanIfaceData->Selection.ActiveLink == TRUE)
                {
                    lastSelectedIfaceFound = TRUE;
                    highPriorityValidIface = uiLoopCount;
                    highPriorityValue = -1; //set negative value to give highest priority for last active link interface

                    if(pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_UP ||
                            pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_STANDBY ||
                                    pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_VALID)
                    {
                        pWanController->activeInterfaceIdx = uiLoopCount;
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        break;
                    }
                }

                /* Set the highest priority Valid interface */
                if(pWanIfaceData->Selection.Priority <= highPriorityValue)
                {
                    highPriorityValidIface = uiLoopCount;
                    highPriorityValue = pWanIfaceData->Selection.Priority;
                }

                /* Set the highest priority Active interface */
                if((pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_UP ||
                        pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_STANDBY ||
                            pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_VALID) &&
                                pWanIfaceData->Selection.Priority <= highPriorityActiveValue)
                {
                    pWanController->activeInterfaceIdx = uiLoopCount;
                    highPriorityActiveValue = pWanIfaceData->Selection.Priority;
                }

            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    /* get the current time */
    memset(&(CurrentTime), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(CurrentTime));

    if(highPriorityValidIface != -1 && pWanController->activeInterfaceIdx != -1 )
    {
        if(highPriorityValidIface == pWanController->activeInterfaceIdx )
        {
            CcspTraceInfo(("%s %d  Selecting Highest priority interface id(%d)\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
            return Transition_SelectingInterface(pWanController);
        }
        else if(difftime(CurrentTime.tv_sec, pWanController->SelectionTimeOutStart.tv_sec) > pWanController->InterfaceSelectionTimeOut)
        {
            /*If timer expired select the highest priority active interface */
            CcspTraceInfo(("%s %d  SelectionTimeOut expired. Selecting Highest(available) priority interface id(%d)\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));

            WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(highPriorityValidIface);
            if(pWanDmlIfaceData != NULL)
            {
                DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
		WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanIfaceData->VirtIfList,0),WAN_WARN_IP_OBTAIN_TIMER_EXPIRED);
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            }	    
            return Transition_SelectingInterface(pWanController);
        }else
        {
            pWanController->activeInterfaceIdx = -1;
        }
    }

    /* Check for new connected interface */
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group && 
                    pWanIfaceData->Selection.Enable == TRUE &&
                    pWanIfaceData->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP &&
                    pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_DISABLED &&
                    /* If GroupPersistSelectedIface is TRUE and we have a last selected interface, don't start VISM for other interfaces */
                    (!(pWanController->GroupPersistSelectedIface == TRUE && lastSelectedIfaceFound == TRUE && pWanIfaceData->Selection.ActiveLink == FALSE)))
            {
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                CcspTraceInfo(("%s %d  Found New interface %s id(%d). Starting Interface State Machine\n", __FUNCTION__, __LINE__, pWanIfaceData->DisplayName, uiLoopCount));
                return Transition_NewInterfaceConnected(uiLoopCount);
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    return STATE_PARALLEL_SCAN_SCANNING_INTERFACE;
}

/* State_CheckReconfiguration()
 * If, Enable is false OR X_RDK_WanManager.Policy is changed, OR Group configuration is changed, Tearing Down Transition will be called.
 * Check the HW configuration status (WAN/LAN) for the selected interface, if the current HW configuration status is LAN, Reconfiguring Platform transition will be called.
 * Check the HW configuration status (WAN/LAN) for the other interfaces (not selected), if the current HW configuration status is WAN, Reconfiguring Platform transition will be called.
 * If HW reconfiguration is not required, Interface Selected Transition will be called.
 */
static WcPsPolicyState_t State_CheckReconfiguration (WanMgr_Policy_Controller_t * pWanController)
{

    if(pWanController == NULL)
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    if(pWanController->WanEnable == FALSE ||
            pWanController->GroupCfgChanged == TRUE )
    {
        CcspTraceInfo(("%s %d  Tearing Down Selection Policy \n", __FUNCTION__, __LINE__));
        return Transition_TearingDown(pWanController);
    }

    if(WanMgr_CheckIfPlatformReconfiguringRequired(pWanController) == TRUE)
    {
        return Transition_ReconfiguringPlatfrom(pWanController);    
    }else
    {
        return Transition_InterfaceSelected(pWanController);
    }

    return STATE_PARALLEL_SCAN_CHECK_RECONFIGURATION;
}

/* State_ReconfigurePaltform()
 * If the platform has been reconfigured AND RebootRequired is True. Go to state Reboot.
 * If the platform has been reconfigured AND RebootRequired is False. Interface Selected Transition will be called.
 */
static WcPsPolicyState_t State_ReconfigurePaltform (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if (pActiveInterface->Selection.RequiresReboot == TRUE)
    {
        return Transition_Reboot(pWanController);
    }else
    {
        return Transition_InterfaceSelected(pWanController);
    }

    return STATE_PARALLEL_SCAN_RECONFIGURE_PLATFORM;
}

/* State_SelectedInterfaceUp()
 * If, Enable is false OR X_RDK_WanManager.Policy is changed OR Group configuration is changed, Tearing Down Transition will be called.
 * If ResetSelectedInterface is True, Restart scan Transition will be called.
 * If Status is Down for the selected interface. Transition Selected interface down will be called.
 */
static WcPsPolicyState_t State_SelectedInterfaceUp (WanMgr_Policy_Controller_t * pWanController)
{
    if((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    if(pWanController->WanEnable == FALSE ||
            pWanController->GroupCfgChanged == TRUE )
    {
        CcspTraceInfo(("%s %d  Tearing Down Selection Policy \n", __FUNCTION__, __LINE__));
        return Transition_TearingDown(pWanController);
    }

    if(pWanController->ResetSelectedInterface == TRUE && WanMgr_CheckRescanRequired(pWanController))
    {
        return Transition_RestartScan(pWanController);
    }

    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if (pActiveInterface->BaseInterfaceStatus != WAN_IFACE_PHY_STATUS_UP || pActiveInterface->Selection.Enable == FALSE)
    {
        return Transition_SelectedInterfaceDown(pWanController);
    }

    if(pActiveInterface->VirtIfChanged == TRUE)
    {
        for(int VirtId=0; VirtId < pActiveInterface->NoOfVirtIfs; VirtId++)
        {
            DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIface_locked(pWanController->activeInterfaceIdx, VirtId);
            if(p_VirtIf != NULL) 
            {
                if(p_VirtIf->Enable == TRUE && p_VirtIf->Interface_SM_Running == FALSE)
                {
                    CcspTraceInfo(("%s %d Starting virtual InterfaceStateMachine for %d \n", __FUNCTION__, __LINE__, VirtId));
                    WanMgr_IfaceSM_Controller_t wanIfCtrl;
                    WanMgr_IfaceSM_Init(&wanIfCtrl, pWanController->activeInterfaceIdx, VirtId);
                    if (WanMgr_StartInterfaceStateMachine(&wanIfCtrl) != 0)
                    {
                        CcspTraceError(("%s %d: Unable to start interface state machine \n", __FUNCTION__, __LINE__));
                    }
                }
                WanMgr_VirtualIfaceData_release(p_VirtIf);
            }
        }
        pActiveInterface->VirtIfChanged = FALSE;
    }

    return STATE_PARALLEL_SCAN_SELECTED_INTERFACE_UP;
}

/* State_SelectedInterfaceDown()
 * If, Enable is false OR X_RDK_WanManager.Policy is changed OR Group configuration is changed, Tearing Down Transition will be called.
 * If ResetSelectedInterface is True, Restart scan Transition will be called.
 * Wait for the Interface state machine for the selected interface to exit. To avoid starting another SM for the same interface simultaneously.
 * After selected interface SM exit, If Status is Up for the selected interface. Transition Selected interface Up will be called.
 */
static WcPsPolicyState_t State_SelectedInterfaceDown (WanMgr_Policy_Controller_t * pWanController)
{
    if((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    if(pWanController->WanEnable == FALSE ||
            pWanController->GroupCfgChanged == TRUE )
    {
        CcspTraceInfo(("%s %d  Tearing Down Selection Policy \n", __FUNCTION__, __LINE__));
        return Transition_TearingDown(pWanController);
    }

    if(pWanController->ResetSelectedInterface == TRUE)
    {
        return Transition_RestartScan(pWanController);
    }

    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if (pActiveInterface->VirtIfList->Status != WAN_IFACE_STATUS_DISABLED)
    {
        return STATE_PARALLEL_SCAN_SELECTED_INTERFACE_DOWN;
    }

    if(pActiveInterface->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP && pActiveInterface->Selection.Enable == TRUE)
    {
        return Transition_SelectedInterfaceUp(pWanController);
    }

    return STATE_PARALLEL_SCAN_SELECTED_INTERFACE_DOWN;
}

/* State_Reboot()
 * Wait for system to reboot.
 */
static WcPsPolicyState_t State_Reboot (WanMgr_Policy_Controller_t * pWanController)
{

    return STATE_PARALLEL_SCAN_REBOOT;
}

/* State_InterfaceTearDown()
 * Wait for all interface state machines to exit from this group.
 * After all interface state machines exit, If Enable is false OR X_RDK_WanManager.Policy is changed OR Group configuration is changed, Go to State Policy Exit
 */
static WcPsPolicyState_t State_InterfaceTearDown (WanMgr_Policy_Controller_t * pWanController)
{
    bool InterfaceSM_Running = false;
    UINT uiLoopCount;

    if((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d pWanController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_PARALLEL_SCAN_POLICY_ERROR;
    }

    /* Check Interface SM status */
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                if (pWanIfaceData->VirtIfList->Status != WAN_IFACE_STATUS_DISABLED)
                {
                    InterfaceSM_Running = true;
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    if(!InterfaceSM_Running)
    {
        return STATE_PARALLEL_SCAN_POLICY_EXIT;
    }

    return STATE_PARALLEL_SCAN_INTERFACE_TEAR_DOWN;
}

/*********************************************************************************/
/**************************** SM THREAD ******************************************/
/*********************************************************************************/ 
void *WanMgr_ParallelScanSelectionProcess (void* arg)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));


    bool bRunning = true;
    WanMgr_Policy_Controller_t    WanController;
    WcPsPolicyState_t ps_sm_state;
    struct timeval tv;
    int n = 0;

    // initialising policy data
    if(WanMgr_Controller_PolicyCtrlInit(&WanController) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Policy Controller Error \n", __FUNCTION__, __LINE__));
        return NULL;
    }

    WanController.GroupInst = (UINT)arg;
    // detach thread from caller stack
    pthread_detach(pthread_self()); 

    // updates policy controller data
    WanMgr_UpdateControllerData (&WanController);

    CcspTraceInfo(("%s %d: SelectionProcess Thread Starting for Group ID %d\n", __FUNCTION__, __LINE__, WanController.GroupInst));

    if(WanController.activeInterfaceIdx != -1)
    {
        // lock Iface Data & update selected iface data in controller data
        WanController.pWanActiveIfaceData = WanMgr_GetIfaceData_locked(WanController.activeInterfaceIdx);
    }

    ps_sm_state = Transition_Start(&WanController); // do this first before anything else to init variables

    while (bRunning)
    {
        /* Wait up to 250 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = SELECTION_PROCESS_LOOP_TIMEOUT;

        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }

        // updates policy controller data
        WanMgr_UpdateControllerData (&WanController);

        if(WanController.activeInterfaceIdx != -1 && WanController.pWanActiveIfaceData == NULL)
        {
            // lock Iface Data & update selected iface data in controller data
            WanController.pWanActiveIfaceData = WanMgr_GetIfaceData_locked(WanController.activeInterfaceIdx);
        }
        // process states
        switch (ps_sm_state)
        {
            case STATE_PARALLEL_SCAN_SCANNING_INTERFACE:
                ps_sm_state = State_ScanningInterface(&WanController);
                break;
            case STATE_PARALLEL_SCAN_CHECK_RECONFIGURATION:
                ps_sm_state = State_CheckReconfiguration(&WanController);
                break;
            case STATE_PARALLEL_SCAN_RECONFIGURE_PLATFORM:
                ps_sm_state = State_ReconfigurePaltform(&WanController);
                break;
            case STATE_PARALLEL_SCAN_REBOOT:
                ps_sm_state = State_Reboot(&WanController);
                break;
            case STATE_PARALLEL_SCAN_SELECTED_INTERFACE_UP:
                ps_sm_state = State_SelectedInterfaceUp(&WanController);
                break;
            case STATE_PARALLEL_SCAN_SELECTED_INTERFACE_DOWN:
                ps_sm_state = State_SelectedInterfaceDown(&WanController);
                break;
            case STATE_PARALLEL_SCAN_INTERFACE_TEAR_DOWN:
                ps_sm_state = State_InterfaceTearDown(&WanController);
                break;
            case STATE_PARALLEL_SCAN_POLICY_EXIT:
                bRunning = false;
                break;
            case STATE_PARALLEL_SCAN_POLICY_ERROR:
            default:
                CcspTraceInfo(("%s %d: Failure Case \n", __FUNCTION__, __LINE__));
                bRunning = false;
                break;
        }
        // release lock iface data
        if(WanController.pWanActiveIfaceData != NULL)
        {
            WanMgrDml_GetIfaceData_release(WanController.pWanActiveIfaceData);
            WanController.pWanActiveIfaceData = NULL;
        }

    }

    if(WanController.GroupCfgChanged == TRUE)
    {
        WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
        if(pWanConfigData != NULL)
        {
            CcspTraceInfo(("%s %d: Resetting FO scan thread\n", __FUNCTION__, __LINE__));
            pWanConfigData->data.ResetFailOverScan = TRUE;
            //TODO: NEW_DESIGN Reset ActiveLinks if group changed.
            WanMgrDml_GetConfigData_release(pWanConfigData);
        }
    }

    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((WanController.GroupInst - 1));
    if (pWanIfaceGroup != NULL)
    {
        pWanIfaceGroup->ThreadId = 0;
        pWanIfaceGroup->SelectedInterface = 0;
        pWanIfaceGroup->ConfigChanged = 0;
        if(pWanIfaceGroup->State != STATE_GROUP_DEACTIVATED)
        {
            pWanIfaceGroup->State = STATE_GROUP_STOPPED;
        }
        WanMgrDml_GetIfaceGroup_release();
    }
    CcspTraceInfo(("%s %d - Exit from SelectionProcess Group(%d) state machine\n", __FUNCTION__, __LINE__, WanController.GroupInst));

    pthread_exit(NULL);
}

