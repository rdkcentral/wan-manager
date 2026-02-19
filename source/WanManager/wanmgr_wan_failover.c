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


/* ---- Include Files ---------------------------------------- */

#include "wanmgr_data.h"
#include "wanmgr_wan_failover.h"
#ifdef ENABLE_FEATURE_TELEMETRY2_0
#include <telemetry_busmessage_sender.h>
#endif

#define FAILOVER_SM_LOOP_TIMEOUT 300000 // timeout 

extern void *WanMgr_AutoWanSelectionProcess (void* arg);
extern void *WanMgr_ParallelScanSelectionProcess (void* arg);

/* SELECTION STATES */
static WcFailOverState_t State_ScanningGroup (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t State_GroupActive (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t State_RestorationWait (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t State_DeactivateGroup (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t State_IdleMonitor (WanMgr_FailOver_Controller_t * pFailOverController);


/* TRANSITIONS */
static WcFailOverState_t Transition_Start (WanMgr_FailOver_Controller_t* pFailOverController);
static WcFailOverState_t Transition_ActivateGroup (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t Transition_Restoration (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t Transition_DeactivateGroup (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t Transition_RestorationFail (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t Transition_ResetScan (WanMgr_FailOver_Controller_t * pFailOverController);
static WcFailOverState_t Transition_Idle (WanMgr_FailOver_Controller_t * pFailOverController);

ANSC_STATUS MarkHighPriorityGroup (WanMgr_FailOver_Controller_t* pFailOverController, bool WaitForHigherGroup);

static const char * const TelemetryEventStr[] =
{
[WAN_FAILOVER_SUCCESS] = "WAN_FAILOVER_SUCCESS_COUNT",
[WAN_FAILOVER_FAIL] = "WAN_FAILOVER_FAIL_COUNT",
[WAN_RESTORE_SUCCESS] = "WAN_RESTORE_SUCCESS_COUNT",
[WAN_RESTORE_FAIL] = "WAN_RESTORE_FAIL_COUNT",
};

/*
 * Trigger Telemetry Events for FailOver Between Groups.
 */
void WanMgr_TelemetryEventTrigger(WanMgr_FailOver_Controller_t* pFailOverController)
{
    static TelemetryEvent_t lastEvent = 0; 
    if (lastEvent != pFailOverController->TelemetryEvent)
    {
        //WanFailover / Restoration telemetry with timer
        if(pFailOverController->TelemetryEvent == WAN_FAILOVER_SUCCESS || pFailOverController->TelemetryEvent == WAN_RESTORE_SUCCESS)
        {
            char TelemetryLog[256] = {0};
            /* get the current time */
            struct timespec CurrentTime;
            memset(&(CurrentTime), 0, sizeof(struct timespec));
            clock_gettime(CLOCK_MONOTONIC_RAW, &(CurrentTime));
            double elapsedTime = CurrentTime.tv_sec - pFailOverController->FailOverTimer.tv_sec  + (double) (CurrentTime.tv_nsec - pFailOverController->FailOverTimer.tv_nsec)/1.0e9;
            if(pFailOverController->TelemetryEvent  == WAN_RESTORE_SUCCESS)
            {
                elapsedTime -= pFailOverController->RestorationDelay;
                snprintf(TelemetryLog, sizeof(TelemetryLog), "WFO_RESTORE_SUCCESS: Total Time Taken in %.3f",elapsedTime);
            }else
            {
                snprintf(TelemetryLog, sizeof(TelemetryLog), "WFO_FAILOVER_SUCCESS: Total Time Taken in %.3f",elapsedTime);
            }
            CcspTraceInfo(("%s-%d : %s \n", __FUNCTION__, __LINE__, TelemetryLog));
#ifdef ENABLE_FEATURE_TELEMETRY2_0
            t2_event_d(TelemetryLog, 1);
#endif
        }
        lastEvent = pFailOverController->TelemetryEvent;

        CcspTraceInfo(("%s-%d : Telemetry Event Trigger : %s \n", __FUNCTION__, __LINE__, TelemetryEventStr[lastEvent]));
#ifdef ENABLE_FEATURE_TELEMETRY2_0
        t2_event_d(TelemetryEventStr[lastEvent], 1);
#endif
    }
}

/*
 * WanMgr_FailOverCtrlInit()
 * Init FailoverDeatails
 */
ANSC_STATUS WanMgr_FailOverCtrlInit(WanMgr_FailOver_Controller_t* pFailOverController)
{
    if (pFailOverController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    pFailOverController->WanEnable = FALSE;
    pFailOverController->FailOverType = HOTSWAP;
    pFailOverController->CurrentActiveGroup = 0;
    pFailOverController->HighestValidGroup = 0;
    pFailOverController->RestorationDelay = 0;
    pFailOverController->TelemetryEvent = 0;
    pFailOverController->AllowRemoteInterfaces = FALSE;
    pFailOverController->ActiveIfaceState = -1;
    pFailOverController->PhyState = WAN_IFACE_PHY_STATUS_UNKNOWN;
    pFailOverController->DisableAutoRouting = FALSE;
    pFailOverController->InitialScanCompleted = FALSE;
    /* Update group Interface */
    UINT TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();
    for (int i = 0 ; i < TotalIfaces; i++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(i);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pWanIfaceData->Selection.Group - 1));
            if (pWanIfaceGroup != NULL)
            {
                pWanIfaceGroup->InterfaceAvailable |= (1<<i);
                WanMgrDml_GetIfaceGroup_release();
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    //Read Failover type from PSM
    char param_value[256] = {0};
    int retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(PSM_WANMANAGER_FAILOVER_TYPE, param_value,sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pFailOverController->FailOverType));
    }

    return ANSC_STATUS_SUCCESS;
}

/*
 * WanMgr_UpdateFOControllerData()
 * - updates the controller data
 * - this function is called every time in the begining of the loop,
 so that the states/transition can work with the current data
 */
static void WanMgr_UpdateFOControllerData (WanMgr_FailOver_Controller_t* pFailOverController)
{
    if (pFailOverController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return;
    }

    //Update Wan config
    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        pFailOverController->WanEnable = pWanConfigData->data.Enable;
        pFailOverController->RestorationDelay = pWanConfigData->data.RestorationDelay;
        pFailOverController->ResetScan = pWanConfigData->data.ResetFailOverScan;
        pFailOverController->AllowRemoteInterfaces = pWanConfigData->data.AllowRemoteInterfaces;
        pWanConfigData->data.ResetFailOverScan = false; //Reset Global data
        pFailOverController->DisableAutoRouting = pWanConfigData->data.DisableAutoRouting;

        WanMgrDml_GetConfigData_release(pWanConfigData);
    }
}

/*
 * WanMgr_SetGroupSelectedIface()
 * - sets the Group Selected Interface.
 */
int WanMgr_SetGroupSelectedIface (UINT GroupInst, UINT IfaceInst)
{
    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((GroupInst - 1));
    if (pWanIfaceGroup != NULL)
    {
        pWanIfaceGroup->SelectedInterface = IfaceInst;
        pWanIfaceGroup->InitialScanComplete = TRUE;//if interface is selected set InitialScanComplete to true
        CcspTraceInfo(("%s %d  group(%d) SelectedInterface %d\n", __FUNCTION__, __LINE__, GroupInst, pWanIfaceGroup->SelectedInterface));
        CcspTraceInfo(("%s %d  group(%d) Initial Scan Completed\n", __FUNCTION__, __LINE__, GroupInst));
        WanMgrDml_GetIfaceGroup_release();
    }
    return ANSC_STATUS_SUCCESS;
}

/* WanMgr_DeactivateGroup()
 * Calls WanMgr_DeactivateInterface for the selected interface in the group.
 */
static ANSC_STATUS WanMgr_DeactivateGroup(UINT groupId)
{
    CcspTraceInfo(("%s %d Deactivating group %d \n", __FUNCTION__, __LINE__, groupId));
    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((groupId - 1));
    if (pWanIfaceGroup != NULL)
    {
        WanMgr_DeactivateInterface(pWanIfaceGroup->SelectedInterface - 1);
        WanMgrDml_GetIfaceGroup_release();
    }
    return ANSC_STATUS_SUCCESS;
}

/* WanMgr_ActivateGroup()
 * Calls WanMgr_ActivateInterface for the selected interface in the group.
 */
static ANSC_STATUS WanMgr_ActivateGroup(UINT groupId)
{

    CcspTraceInfo(("%s %d Activating group %d \n", __FUNCTION__, __LINE__, groupId));
    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((groupId - 1));
    if (pWanIfaceGroup != NULL)
    {
        if (pWanIfaceGroup->SelectedInterface)
        {
            if(WanMgr_ActivateInterface(pWanIfaceGroup->SelectedInterface - 1) == 0)
            {
                pWanIfaceGroup->ActivationCount++; //update group activation count
                CcspTraceInfo(("%s %d Group %d ActivationCount : %d\n", __FUNCTION__, __LINE__, groupId,pWanIfaceGroup->ActivationCount));
            }
        }
        WanMgrDml_GetIfaceGroup_release();
    }

    return ANSC_STATUS_SUCCESS;
}

static void WanMgr_FO_IfaceGroupMonitor()
{
    for(int i = 0; i < WanMgr_GetTotalNoOfGroups(); i++)
    {
        WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((i));
        if (pWanIfaceGroup != NULL)
        {
            if( pWanIfaceGroup->InterfaceAvailable && pWanIfaceGroup->State != STATE_GROUP_RUNNING && pWanIfaceGroup->State != STATE_GROUP_DEACTIVATED )
            {
                pWanIfaceGroup->SelectionTimeOut = 0;
                pWanIfaceGroup->InitialScanComplete = FALSE;
                pWanIfaceGroup->ActivationCount = 0;
                UINT TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();
                for( int uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++ )
                {
                    WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
                    if(pWanDmlIfaceData != NULL)
                    {
                        DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
                        if((i+1) == pWanIfaceData->Selection.Group)
                        {
                            if(pWanIfaceData->Selection.Timeout > pWanIfaceGroup->SelectionTimeOut)
                            {
                                pWanIfaceGroup->SelectionTimeOut = pWanIfaceData->Selection.Timeout;
                            }
                        }
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                    }
                }

                pWanIfaceGroup->ConfigChanged = FALSE; 

                int ret;
                switch (pWanIfaceGroup->Policy) 
                {
                    //TODO: NEW_DESIGN add other policies. 
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
                    case PARALLEL_SCAN: 
                        CcspTraceInfo(("%s %d - Creating PARALLEL_SCAN selection thread for Group(%d) \n", __FUNCTION__, __LINE__, (i+1)));
                        ret = pthread_create( &pWanIfaceGroup->ThreadId, NULL, &WanMgr_ParallelScanSelectionProcess, (void *)(i+1));
                        break;
#endif
                    case AUTOWAN_MODE:
                    default:
                        pWanIfaceGroup->Policy = AUTOWAN_MODE; //set dafault mode AUTOWAN_MODE if policy not supported.  
                        CcspTraceInfo(("%s %d - Creating AUTOWAN_MODE selection thread for Group(%d) \n", __FUNCTION__, __LINE__, (i+1)));
                        ret = pthread_create( &pWanIfaceGroup->ThreadId, NULL, &WanMgr_AutoWanSelectionProcess, (void *)(i+1));
                        break;
                }

                if (ret != 0)
                {
                    CcspTraceError(("%s %d - Failed to Create Group(%d) Thread\n", __FUNCTION__, __LINE__, (i+1)));
                }else
                {
                    CcspTraceInfo(("%s %d - Successfully Created Group(%d) Thread Id :%lu \nSelectionTimeOut %d Interfaces_mask %d\n", __FUNCTION__, __LINE__, (i+1), pWanIfaceGroup->ThreadId, pWanIfaceGroup->SelectionTimeOut, pWanIfaceGroup->InterfaceAvailable));
                    pWanIfaceGroup->State = STATE_GROUP_RUNNING;
                }
            }
            WanMgrDml_GetIfaceGroup_release();
        }

    }
}

#if defined(FEATURE_RDKB_LED_MANAGER)
ANSC_STATUS UpdateLedStatus (WanMgr_FailOver_Controller_t* pFailOverController)
{
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    /* We have a Active Group */ 
    if(pFailOverController->CurrentActiveGroup != 0)
    {
        WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pFailOverController->CurrentActiveGroup -1));
        if (pWanIfaceGroup != NULL)
        {
            /* Active group has a selected Ineterface */
            if(pWanIfaceGroup->SelectedInterface > 0)
            {
                WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked((pWanIfaceGroup->SelectedInterface - 1));
                if (pWanDmlIfaceData != NULL)
                {
                    DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
                    /* Update the Wan/IP connection status of the interface to LED*/
                    // Group selected and State machine is running, so update v4/v6/map_t status accordingly
                    if(pWanIfaceData->VirtIfList->eCurrentState != pFailOverController->ActiveIfaceState ||  //Wan State changed
                        pWanIfaceData->BaseInterfaceStatus != pFailOverController->PhyState) //Phy status changed
                    {
                        CcspTraceInfo(("%s %d Updating LED status of Selected Interface (%s) BaseInterface (%s) \n", __FUNCTION__, __LINE__,pWanIfaceData->DisplayName, pWanIfaceData->BaseInterface));
                        wanmgr_setWanLedState(pWanIfaceData->VirtIfList->eCurrentState);

                        /* For the following states, Update the PHY connection status of the interface to LED */
                        if((pWanIfaceData->VirtIfList->eCurrentState == WAN_STATE_EXIT ||
                                pWanIfaceData->VirtIfList->eCurrentState == WAN_STATE_PHY_DOWN ||
                                pWanIfaceData->VirtIfList->eCurrentState == WAN_STATE_PHY_CONFIGURING))
                        {
                            if(pWanIfaceData->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP)
                            {
                                wanmgr_sysevents_setWanState(WAN_LINK_UP_STATE);
                            }else if(pWanIfaceData->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_INITIALIZING && 
                                    ((strstr(pWanIfaceData->BaseInterface,"PTM")) || (strstr(pWanIfaceData->BaseInterface,"ATM"))) != NULL)
                            {
                                /* Update DSL_Training only for DSL connection */
                                wanmgr_sysevents_setWanState(DSL_TRAINING);

                            }else
                            {
                                wanmgr_sysevents_setWanState(WAN_LINK_DOWN_STATE);
                            }
                        }
                        pFailOverController->ActiveIfaceState = pWanIfaceData->VirtIfList->eCurrentState;
                        pFailOverController->PhyState = pWanIfaceData->BaseInterfaceStatus;
                    }
                    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                }
            }
            WanMgrDml_GetIfaceGroup_release();
        }
    }else
    {
        /* Active group is not selected, Update the PHY status of all Wan Interfaces  to LED*/
        DML_WAN_IFACE_PHY_STATUS BaseInterfaceStatus = WAN_IFACE_PHY_STATUS_DOWN;
        UINT uiTotalIfaces = 0;
        UINT uiLoopCount   = 0;
      
        //Get uiTotalIfaces
        uiTotalIfaces = WanMgr_IfaceData_GetTotalWanIface();

        if(uiTotalIfaces > 0)
        {
            for( uiLoopCount = 0; uiLoopCount < uiTotalIfaces; uiLoopCount++ )
            {

                WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
                if(pWanDmlIfaceData != NULL)
                {
                    DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
                    /* if any Wan Interface Phy is Up, set LED Wan link UP,
                       if all Wan Interfaces Phy is DOWN,  set LED Wan link DOWN */
                    if(pWanIfaceData->BaseInterfaceStatus > BaseInterfaceStatus && pWanIfaceData->BaseInterfaceStatus != WAN_IFACE_PHY_STATUS_UNKNOWN)
                    {
                        if(pWanIfaceData->BaseInterfaceStatus != WAN_IFACE_PHY_STATUS_INITIALIZING || 
                          (pWanIfaceData->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_INITIALIZING && (strstr(pWanIfaceData->BaseInterface,"PTM") || strstr(pWanIfaceData->BaseInterface,"ATM")) != NULL))
                        {
                            /* Update DSL_Training (PHY_STATUS_INITIALIZING) only for DSL connection */
                            BaseInterfaceStatus = pWanIfaceData->BaseInterfaceStatus;
                        }
                    }
                    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                }
            }
        }

        if(BaseInterfaceStatus != pFailOverController->PhyState)
        {
            CcspTraceInfo(("%s %d No Selected Interface. Updating BaseInterface status of all WanLink to LED\n", __FUNCTION__, __LINE__));
            if(BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP)
            {
                wanmgr_sysevents_setWanState(WAN_LINK_UP_STATE);
            }else if(BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_INITIALIZING)
            {
                wanmgr_sysevents_setWanState(DSL_TRAINING);
            }else 
            {
                wanmgr_sysevents_setWanState(WAN_LINK_DOWN_STATE);
            }
        }
        pFailOverController->PhyState = BaseInterfaceStatus;
    }
}
#endif
/*********************************************************************************/
/************************** TRANSITIONS ******************************************/
/*********************************************************************************/

static WcFailOverState_t Transition_Start (WanMgr_FailOver_Controller_t* pFailOverController)
{
    CcspTraceInfo(("%s %d  \n", __FUNCTION__, __LINE__));

    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    pFailOverController->CurrentActiveGroup =  0;
    pFailOverController->HighestValidGroup = 0;

    //Start the selectionTimer
    memset(&(pFailOverController->GroupSelectionTimer), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(pFailOverController->GroupSelectionTimer));

    if(pFailOverController->FailOverType == COLDSWAP)
    {
        CcspTraceInfo(("%s %d FailOverType is set to COLDSWAP. starting all group in decativated state \n", __FUNCTION__, __LINE__));
        for(int i = 0; i < WanMgr_GetTotalNoOfGroups(); i++)
        {
            WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((i));
            if (pWanIfaceGroup != NULL)
            {
                pWanIfaceGroup->State = STATE_GROUP_DEACTIVATED;
                WanMgrDml_GetIfaceGroup_release();
            }
        }
    }

    return STATE_FAILOVER_SCANNING_GROUP;
}

ANSC_STATUS MarkHighPriorityGroup (WanMgr_FailOver_Controller_t* pFailOverController, bool WaitForHigherGroup)
{
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    bool GroupChanged = false;
    struct timespec CurrentTime;
    pFailOverController->HighestValidGroup = 0; 

    for(int i = 0; i < WanMgr_GetTotalNoOfGroups(); i++)
    {
        WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((i));
        if (pWanIfaceGroup != NULL)
        {
            if (pWanIfaceGroup->SelectedInterface && !pFailOverController->HighestValidGroup)
            {
                WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked((pWanIfaceGroup->SelectedInterface - 1));
                if (pWanDmlIfaceData != NULL)
                {
                    DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
                    if(pWanIfaceGroup->State != STATE_GROUP_DEACTIVATED && // Group should not be in DEACTIVATED state
                        (pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_STANDBY ||
                        pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_UP) &&
                        (!(pWanIfaceData->IfaceType == REMOTE_IFACE &&  // Check RemoteStatus also for REMOTE_IFACE
                        pWanIfaceData->VirtIfList->RemoteStatus != WAN_IFACE_STATUS_UP)) && 
                        (pWanIfaceData->VirtIfList->IP.Ipv4ConnectivityStatus == WAN_CONNECTIVITY_UP || //Ipv4ConnectivityStatus should be UP OR
                        pWanIfaceData->VirtIfList->IP.Ipv6ConnectivityStatus == WAN_CONNECTIVITY_UP )) //Ipv6ConnectivityStatus should be UP
                    {
                        pFailOverController->HighestValidGroup = (i+1);
                    }
                    else if (pFailOverController->CurrentActiveGroup == (i+1) && pWanIfaceData->VirtIfList->Reset == TRUE)
                    {
                        //If VirtIfList->Reset is  in progress for CurrentActiveGroup, don't change the selected group.
                        pFailOverController->HighestValidGroup = pFailOverController->CurrentActiveGroup;
                    }
                    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                }
            }

            if(pFailOverController->FailOverType == COLDSWAP && !pFailOverController->HighestValidGroup)
            { 
                if(pWanIfaceGroup->State == STATE_GROUP_DEACTIVATED)
                {
                    CcspTraceInfo(("%s %d: Group (%d) state set to VALID\n", __FUNCTION__, __LINE__, i+1));
                    pWanIfaceGroup->State = STATE_GROUP_STOPPED;
                }
            }

            if(pWanIfaceGroup->ConfigChanged)
            {
                /* If group Change inprogress, don't select highestValidGroup */
                CcspTraceInfo(("%s %d: Group list change is in progress. Don't select Interface now. \n", __FUNCTION__, __LINE__));
                pFailOverController->HighestValidGroup = pFailOverController->CurrentActiveGroup;
                WanMgrDml_GetIfaceGroup_release();
                break;
            }

            if(WaitForHigherGroup && pWanIfaceGroup->State == STATE_GROUP_RUNNING)
            {
                /* get the current time */
                memset(&(CurrentTime), 0, sizeof(struct timespec));
                clock_gettime(CLOCK_MONOTONIC_RAW, &(CurrentTime));
                /* If wait for WaitForHigherGroup TRUE, it is called from initial scan(No interface is activated yet). Wait for SelectionTimeOut and InitialScanComplete */
                if((difftime(CurrentTime.tv_sec, pFailOverController->GroupSelectionTimer.tv_sec) < pWanIfaceGroup->SelectionTimeOut) || pWanIfaceGroup->InitialScanComplete == FALSE)
                {
                    WanMgrDml_GetIfaceGroup_release();
                    break;
                }
                if(pFailOverController->InitialScanCompleted == FALSE )
                {
                    pFailOverController->InitialScanCompleted = TRUE; //Initial scan completed
                    CcspTraceInfo(("%s %d: Initial Scan Completed. \n", __FUNCTION__, __LINE__));
                    WanMgr_Rbus_EventPublishHandler(WANMGR_EVENT_INITIAL_SCAN_COMPLETED, &(pFailOverController->InitialScanCompleted), RBUS_BOOLEAN);
                }
            }

            WanMgrDml_GetIfaceGroup_release();
        }
    }

    return ANSC_STATUS_SUCCESS;
}

static WcFailOverState_t Transition_ActivateGroup (WanMgr_FailOver_Controller_t * pFailOverController)
{
    CcspTraceInfo(("%s %d  \n", __FUNCTION__, __LINE__));
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    if(pFailOverController->HighestValidGroup)
    {

        //Update Telemetry
        if(pFailOverController->CurrentActiveGroup)
        {
            if(pFailOverController->CurrentActiveGroup < pFailOverController->HighestValidGroup)
                pFailOverController->TelemetryEvent = WAN_FAILOVER_SUCCESS;
            else if(pFailOverController->CurrentActiveGroup > pFailOverController->HighestValidGroup)
                pFailOverController->TelemetryEvent = WAN_RESTORE_SUCCESS;
        }

        if(WanMgr_ActivateGroup(pFailOverController->HighestValidGroup) != ANSC_STATUS_SUCCESS)
        {
            return STATE_FAILOVER_SCANNING_GROUP;
        }

        pFailOverController->CurrentActiveGroup = pFailOverController->HighestValidGroup;

        if(pFailOverController->FailOverType == COLDSWAP)
        {
            /* Cold swap Enabled. DEACTIVATE(Stop) all the lower priority groups  */
            //pFailOverController->CurrentActiveGroup varibale holds current active group index +1
            for(int i = pFailOverController->CurrentActiveGroup; i < WanMgr_GetTotalNoOfGroups(); i++)
            {
                WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((i));
                if (pWanIfaceGroup != NULL)
                {
                    /* STATE_GROUP_DEACTIVATED will stop the selection policy and all the VISM started by it. 
                     * Do not confuse with Transition_DeactivateGroup which only deactivates the selcted interface from active WAN connection. */
                    if(pWanIfaceGroup->State == STATE_GROUP_RUNNING)
                    {
                        pWanIfaceGroup->State = STATE_GROUP_DEACTIVATED;
                        pWanIfaceGroup->ConfigChanged = TRUE;
                        CcspTraceInfo(("%s %d: Group (%d) state set to DEACTIVATED. Selection thread will be stopped. \n", __FUNCTION__, __LINE__, pFailOverController->CurrentActiveGroup+1));
                    }
                    WanMgrDml_GetIfaceGroup_release();
                } 
            }
        }
    }else //We should never reach this case.
    {
        CcspTraceError(("%s %d HighestValidGroup not available.\n", __FUNCTION__, __LINE__));
    }

    return STATE_FAILOVER_GROUP_ACTIVE;
}

static WcFailOverState_t Transition_DeactivateGroup (WanMgr_FailOver_Controller_t * pFailOverController)
{
    CcspTraceInfo(("%s %d  \n", __FUNCTION__, __LINE__));
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }
    if(pFailOverController->CurrentActiveGroup)
    {
        if(WanMgr_DeactivateGroup(pFailOverController->CurrentActiveGroup) != ANSC_STATUS_SUCCESS)
        {
            return STATE_FAILOVER_GROUP_ACTIVE;
        }
    }
    return STATE_FAILOVER_DEACTIVATE_GROUP;

}

static WcFailOverState_t Transition_Restoration (WanMgr_FailOver_Controller_t * pFailOverController)
{
    CcspTraceInfo(("%s %d  RestorationDelay %d\n", __FUNCTION__, __LINE__, pFailOverController->RestorationDelay));
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    //Start the selectionTimer. Using selection timer as restration timer.
    memset(&(pFailOverController->GroupSelectionTimer), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(pFailOverController->GroupSelectionTimer));

    return STATE_FAILOVER_RESTORATION_WAIT;
}

static WcFailOverState_t Transition_RestorationFail (WanMgr_FailOver_Controller_t * pFailOverController)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    pFailOverController->TelemetryEvent = WAN_RESTORE_FAIL;
    /* Do nothing */
    return STATE_FAILOVER_GROUP_ACTIVE;
}

static WcFailOverState_t Transition_ResetScan (WanMgr_FailOver_Controller_t * pFailOverController)
{
    CcspTraceInfo(("%s %d  \n", __FUNCTION__, __LINE__));

    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    if(pFailOverController->CurrentActiveGroup)
    {
        WanMgr_DeactivateGroup(pFailOverController->CurrentActiveGroup);
    }

    pFailOverController->CurrentActiveGroup =  0;
    pFailOverController->HighestValidGroup = 0;
    pFailOverController->ResetScan = false;

    //Update LED
    wanmgr_setWanLedState(WAN_STATE_EXIT); 
    pFailOverController->ActiveIfaceState = -1;
    pFailOverController->PhyState = WAN_IFACE_PHY_STATUS_UNKNOWN;

    //Start the selectionTimer
    memset(&(pFailOverController->GroupSelectionTimer), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(pFailOverController->GroupSelectionTimer));

    return STATE_FAILOVER_SCANNING_GROUP;
}

/**
 * @brief Sets the externally controlled group as the active group and transitions to the idle state.
 *
 * @param[in,out] pFailOverController Pointer to the WAN failover controller structure.
 *
 * @return The new failover state after the transition (idle).
 */
static WcFailOverState_t Transition_Idle (WanMgr_FailOver_Controller_t * pFailOverController)
{
    CcspTraceInfo(("%s %d  External control requested\n", __FUNCTION__, __LINE__));

    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    pFailOverController->CurrentActiveGroup = 0;
    pFailOverController->HighestValidGroup = 0;
    
    //Update LED
    wanmgr_setWanLedState(WAN_STATE_EXIT); 
    pFailOverController->ActiveIfaceState = -1;
    pFailOverController->PhyState = WAN_IFACE_PHY_STATUS_UNKNOWN;
   
    return STATE_FAILOVER_IDLE_MONITOR;
}

/*********************************************************************************/
/**************************** STATES *********************************************/
/*********************************************************************************/

static WcFailOverState_t State_ScanningGroup (WanMgr_FailOver_Controller_t * pFailOverController)
{
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    if(pFailOverController->WanEnable == FALSE)
    {
        return STATE_FAILOVER_EXIT;
    }

    if (pFailOverController->DisableAutoRouting == TRUE)
    {
        return Transition_Idle(pFailOverController);
    }

    MarkHighPriorityGroup(pFailOverController, true);

    if( pFailOverController->HighestValidGroup)
    {
        return Transition_ActivateGroup(pFailOverController);
    }

    return STATE_FAILOVER_SCANNING_GROUP;
}

static WcFailOverState_t State_GroupActive (WanMgr_FailOver_Controller_t * pFailOverController)
{
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    if(pFailOverController->WanEnable == FALSE || (pFailOverController->DisableAutoRouting == TRUE))
    {
        return Transition_DeactivateGroup(pFailOverController);
    }

    if(pFailOverController->ResetScan == TRUE )
    {
        return Transition_ResetScan(pFailOverController);
    }

    MarkHighPriorityGroup(pFailOverController, false);

    if(pFailOverController->HighestValidGroup)
    {
        UINT HighestGrpActivationCount = -1;
        WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pFailOverController->HighestValidGroup -1));
        if (pWanIfaceGroup != NULL)
        {
            /* if ActivationCount is 0, group is activated for the first time */
            HighestGrpActivationCount = pWanIfaceGroup->ActivationCount;
            WanMgrDml_GetIfaceGroup_release();
        }

        if(pFailOverController->CurrentActiveGroup < pFailOverController->HighestValidGroup ||
          //If the higher group up for the first time, don't wait for restoration delay. Activate Immediatly
          (HighestGrpActivationCount == 0 && pFailOverController->CurrentActiveGroup > pFailOverController->HighestValidGroup)) 
        {
            CcspTraceInfo(("%s %d : CurrentActiveGroup(%d) Down. Activating Next Highest available group (%d) \n", __FUNCTION__, __LINE__,
                                    pFailOverController->CurrentActiveGroup , pFailOverController->HighestValidGroup));
            //Start the FailOver Timer for telemetry
            memset(&(pFailOverController->FailOverTimer), 0, sizeof(struct timespec));
            clock_gettime(CLOCK_MONOTONIC_RAW, &(pFailOverController->FailOverTimer));

            return Transition_DeactivateGroup (pFailOverController); 
        }
        else if (pFailOverController->CurrentActiveGroup > pFailOverController->HighestValidGroup)
        {
            CcspTraceInfo(("%s %d :  Found Highest available group (%d). Starting Restoration Timer \n", __FUNCTION__, __LINE__,pFailOverController->HighestValidGroup));
            //Start the FailOver Timer for telemetry
            memset(&(pFailOverController->FailOverTimer), 0, sizeof(struct timespec));
            clock_gettime(CLOCK_MONOTONIC_RAW, &(pFailOverController->FailOverTimer));
            return Transition_Restoration (pFailOverController);
        }
    } 
    else if(pFailOverController->CurrentActiveGroup == 1 && pFailOverController->AllowRemoteInterfaces)
    {
        //If Allow RemoteInterface is true and we don't have a group to failover when current Group is down Update telemetry.
        pFailOverController->TelemetryEvent = WAN_FAILOVER_FAIL;
    }

    return STATE_FAILOVER_GROUP_ACTIVE;
}

static WcFailOverState_t State_RestorationWait (WanMgr_FailOver_Controller_t * pFailOverController)
{
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    if(pFailOverController->WanEnable == FALSE || (pFailOverController->DisableAutoRouting == TRUE))
    {
        return Transition_DeactivateGroup(pFailOverController);
    }

    bool HighestValidGroup_Down = false;

    WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pFailOverController->HighestValidGroup -1));
    if (pWanIfaceGroup != NULL)
    {
        if (pWanIfaceGroup->SelectedInterface )
        {
            WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked((pWanIfaceGroup->SelectedInterface - 1));
            if (pWanDmlIfaceData != NULL)
            {
                DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
                if((pWanIfaceData->VirtIfList->Status != WAN_IFACE_STATUS_STANDBY &&
                            pWanIfaceData->VirtIfList->Status != WAN_IFACE_STATUS_UP))
                {
                    HighestValidGroup_Down = true;
                }
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            }
        }   
        WanMgrDml_GetIfaceGroup_release();
    }
    if(HighestValidGroup_Down)
    {
        return Transition_RestorationFail(pFailOverController);
    }

    /* get the current time */
    struct timespec CurrentTime;
    memset(&(CurrentTime), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(CurrentTime));
    if(difftime(CurrentTime.tv_sec, pFailOverController->GroupSelectionTimer.tv_sec) > pFailOverController->RestorationDelay) 
    {
        CcspTraceInfo(("%s %d : Restoration timer expired. Deactivating current group and activating high priority group. \n", __FUNCTION__, __LINE__));
        return Transition_DeactivateGroup(pFailOverController);
    }

    return STATE_FAILOVER_RESTORATION_WAIT;
}

static WcFailOverState_t State_DeactivateGroup (WanMgr_FailOver_Controller_t * pFailOverController)
{
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    bool CurrentActiveGroup_Deactivated = false;
    if(!pFailOverController->CurrentActiveGroup)
    {
        CurrentActiveGroup_Deactivated = true;
    }else
    {
        WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pFailOverController->CurrentActiveGroup -1));
        if (pWanIfaceGroup != NULL)
        {
            if (pWanIfaceGroup->SelectedInterface )
            {
                WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked((pWanIfaceGroup->SelectedInterface - 1));
                if (pWanDmlIfaceData != NULL)
                {
                    DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
                    if((pWanIfaceData->VirtIfList->Status != WAN_IFACE_STATUS_UP))
                    {
                        CurrentActiveGroup_Deactivated = true;
                    }
                    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                }
            }else
            {
                CurrentActiveGroup_Deactivated = true;
            }
            WanMgrDml_GetIfaceGroup_release();
        }
    }
    if(CurrentActiveGroup_Deactivated)
    {
        if(pFailOverController->WanEnable == FALSE)
        {
            return STATE_FAILOVER_EXIT;
        } 
        else if (pFailOverController->DisableAutoRouting == TRUE)
        {
            return Transition_Idle(pFailOverController);
        }
        
        return Transition_ActivateGroup(pFailOverController);
    }

    return STATE_FAILOVER_DEACTIVATE_GROUP;
}

/**
 * @brief Handles the Idle Monitor state in the WAN Failover Controller state machine.
 *
 * Monitors the ExternalControl variable. If the control is released,
 * resets the selection and moves to the scanning state.
 *
 * @param[in,out] pFailOverController Pointer to the WAN FailOver Controller structure.
 *
 * @return The next state to transition to, as a value of WcFailOverState_t.
 */
static WcFailOverState_t State_IdleMonitor (WanMgr_FailOver_Controller_t * pFailOverController)
{
    if(pFailOverController == NULL)
    {
        CcspTraceError(("%s %d pFWController object is NULL \n", __FUNCTION__, __LINE__));
        return STATE_FAILOVER_ERROR;
    }

    if(pFailOverController->WanEnable == FALSE)
    {
        return STATE_FAILOVER_EXIT;
    }

    if(pFailOverController->DisableAutoRouting == FALSE)
    {
        CcspTraceInfo(("%s %d: ExternalControl Released. Resetting scan and returning to scanning state.\n", __FUNCTION__, __LINE__));
        return Transition_ResetScan(pFailOverController);
    }

    // Check if any interface has been externally activated.
    // If found, update the controller's active and highest valid group accordingly.
    BOOL activeInterfaceFound = FALSE;
    UINT TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();
    for (int i = 0 ; i < TotalIfaces; i++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(i);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanIfaceData->Selection.Status == WAN_IFACE_ACTIVE )
            {
                if(pWanIfaceData->Selection.Group != pFailOverController->CurrentActiveGroup)
                {
                    //Ideally this group should be external controlled group.
                    CcspTraceInfo(("%s %d: Found Active Interface (%s) in group %d. Setting it as CurrentActiveGroup.\n", __FUNCTION__, __LINE__, pWanIfaceData->DisplayName, pWanIfaceData->Selection.Group));
                    pFailOverController->CurrentActiveGroup = pWanIfaceData->Selection.Group; //Set CurrentActiveGroup to the group of the active interface
                    pFailOverController->HighestValidGroup = pWanIfaceData->Selection.Group; // Set HighestValidGroup to the group of the active interface
                    WanMgr_SetGroupSelectedIface (pWanIfaceData->Selection.Group, i+1);
                }
                activeInterfaceFound = TRUE;
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
    
    if(!activeInterfaceFound && pFailOverController->CurrentActiveGroup !=0)
    {
        //If no active interface found, reset the CurrentActiveGroup and HighestValidGroup
        CcspTraceInfo(("%s %d: No Active Interface found. Resetting CurrentActiveGroup and HighestValidGroup.\n", __FUNCTION__, __LINE__));
        pFailOverController->CurrentActiveGroup = 0;
        pFailOverController->HighestValidGroup = 0;
        //Update LED
        wanmgr_setWanLedState(WAN_STATE_EXIT); 
        pFailOverController->ActiveIfaceState = -1;
        pFailOverController->PhyState = WAN_IFACE_PHY_STATUS_UNKNOWN;
    }

    return STATE_FAILOVER_IDLE_MONITOR;
}
/*********************************************************************************/
/**************************** SM THREAD ******************************************/
/*********************************************************************************/

ANSC_STATUS WanMgr_FailOverThread (void)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    pthread_detach(pthread_self());

    bool bRunning = true;
    int n = 0;
    struct timeval loopTimer;
    WcFailOverState_t fo_sm_state;
    WanMgr_FailOver_Controller_t  FWController;

    // initialising Failover data
    if(WanMgr_FailOverCtrlInit(&FWController) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Policy Controller Error \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }


    WanMgr_UpdateFOControllerData(&FWController);

    fo_sm_state = Transition_Start(&FWController);
    WanMgr_FO_IfaceGroupMonitor();

    while (bRunning)
    {
        /* Wait up to 300 milliseconds */
        loopTimer.tv_sec = 0;
        loopTimer.tv_usec = FAILOVER_SM_LOOP_TIMEOUT;

        n = select(0, NULL, NULL, NULL, &loopTimer);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }

        WanMgr_UpdateFOControllerData(&FWController);
        WanMgr_FO_IfaceGroupMonitor();
#if defined(FEATURE_RDKB_LED_MANAGER)
        UpdateLedStatus(&FWController);
#endif
        WanMgr_TelemetryEventTrigger(&FWController);
        // process states
        switch (fo_sm_state)
        {
            case STATE_FAILOVER_SCANNING_GROUP:
                fo_sm_state = State_ScanningGroup(&FWController);
                break;
            case STATE_FAILOVER_GROUP_ACTIVE:
                fo_sm_state = State_GroupActive(&FWController);
                break;
            case STATE_FAILOVER_RESTORATION_WAIT:
                fo_sm_state = State_RestorationWait(&FWController);
                break;
            case STATE_FAILOVER_DEACTIVATE_GROUP:
                fo_sm_state = State_DeactivateGroup(&FWController);
                break;
            case STATE_FAILOVER_IDLE_MONITOR:
                fo_sm_state = State_IdleMonitor(&FWController);
                break;
            case STATE_FAILOVER_EXIT:
                bRunning = false;
                break;
            case STATE_FAILOVER_ERROR:
            default:
                CcspTraceInfo(("%s %d: Failure Case \n", __FUNCTION__, __LINE__));
                bRunning = false;
                break;
        }

    }

    /* Wait for All selection thread to exit */
    while(true)
    {
        bool selectionThreadRunning = false;
        for(int i = 0; i < WanMgr_GetTotalNoOfGroups(); i++)
        {
            WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((i));
            if (pWanIfaceGroup != NULL)
            {
                if(pWanIfaceGroup->State == STATE_GROUP_RUNNING)
                {
                    selectionThreadRunning = true;
                }
                WanMgrDml_GetIfaceGroup_release();
            }
        }
        if(!selectionThreadRunning)
        {
            break;
        }
    }
    CcspTraceInfo(("%s %d - Exit from Failover Thread\n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_SUCCESS;
}

