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
#include "wanmgr_interface_apis.h"

/* ---- Global Constants -------------------------- */
#define SELECTION_PROCESS_LOOP_TIMEOUT 250000 // timeout in microseconds. This is the state machine loop interval

extern WANMGR_DATA_ST gWanMgrDataBase;

typedef enum {
    STATE_AUTO_WAN_INTERFACE_SELECTING = 0,
    STATE_AUTO_WAN_INTERFACE_SCANNING,
    STATE_AUTO_WAN_INTERFACE_TEARDOWN,
    STATE_AUTO_WAN_INTERFACE_RECONFIGURATION,
    STATE_AUTO_WAN_REBOOT_PLATFORM,
    STATE_AUTO_WAN_INTERFACE_ACTIVE,
    STATE_AUTO_WAN_ERROR,
    STATE_AUTO_WAN_TEARING_DOWN,
    STATE_AUTO_WAN_SM_EXIT
} WcAwPolicyState_t;



/* SELECTION STATES */
static WcAwPolicyState_t State_SelectingInterface (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t State_ScanningInterface (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t State_WaitingForIfaceTearDown (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t State_InterfaceReconfiguration (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t State_RebootingPlatform (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t State_WanInterfaceActive (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t State_WaitingForInterfaceSMExit(WanMgr_Policy_Controller_t* pWanController);

/* TRANSITIONS */
static WcAwPolicyState_t Transition_Start (WanMgr_Policy_Controller_t* pWanController);
static WcAwPolicyState_t Transition_InterfaceSelected (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_InterfaceInvalid (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_TryingNextInterface (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_InterfaceFound (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_InterfaceDeselect (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_InterfaceValidated (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_RestartSelectionInterface (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_ReconfigurePlatform (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_ActivatingInterface (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_ResetSelectedInterface (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_AutoWanTearDown (WanMgr_Policy_Controller_t * pWanController);
static WcAwPolicyState_t Transition_RebootDevice (void);

static int WanMgr_RdkBus_AddAllIntfsToLanBridge (WanMgr_Policy_Controller_t * pWanController, BOOL AddToBridge)
{
    if ((pWanController == NULL) || (pWanController->WanEnable != TRUE)
            || (pWanController->TotalIfaces == 0))
    {
        CcspTraceError(("%s %d: Invalid args or Global Wan disabled\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    UINT uiLoopCount;
    int ret = 0;
    char PhyPath[BUFLEN_128];
    memset (PhyPath, 0, sizeof(PhyPath));

    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        DML_WAN_IFACE * pWanIfaceData = &(pWanDmlIfaceData->data);
        if(pWanDmlIfaceData != NULL)
        {
            if(pWanController->GroupInst != pWanIfaceData->Selection.Group)
            {
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                continue;
            }
            strncpy (PhyPath, pWanIfaceData->BaseInterface, sizeof(PhyPath)-1);
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

            if (strlen(PhyPath) > 0)
            {
                ret = WanMgr_RdkBus_AddIntfToLanBridge(PhyPath, AddToBridge);
                if (ret == ANSC_STATUS_FAILURE)
                {
                    CcspTraceError(("%s %d: unable to config LAN bridge for index %d BaseInterface %s\n", __FUNCTION__, __LINE__, uiLoopCount, PhyPath));
                }
                memset (PhyPath, 0, sizeof(PhyPath));
            }
        }
    }

    return ANSC_STATUS_SUCCESS;

}
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_))
//TODO: this is a workaround to support upgarde from Comcast autowan policy to Unification build
#define MAX_WanModeToIfaceMap 2
#define WAN_INDEX_DOCSIS      2
#define WAN_INDEX_ETHWAN      1

bool isLastActiveLinkFromSysCfg(DML_WAN_IFACE* pWanIfaceData)
{
    char buf[10] ={0};
    if (syscfg_get(NULL, "last_wan_mode", buf, sizeof(buf)) == 0)
    {
        int mode = atoi(buf);
        UINT IfaceIndex = WAN_INDEX_DOCSIS;

        if ( strstr(pWanIfaceData->BaseInterface, "CableModem") )
        {
            IfaceIndex = WAN_INDEX_DOCSIS;
        }
        else if ( strstr(pWanIfaceData->BaseInterface, "Ethernet") )
        {
            IfaceIndex = WAN_INDEX_ETHWAN;
        }
        else
	{
	   IfaceIndex = WAN_INDEX_DOCSIS;
	}

        if(pWanIfaceData->uiIfaceIdx < MAX_WanModeToIfaceMap && mode == IfaceIndex)
        {
            CcspTraceInfo(("%s %d: Iface Id %d is the last_wan_mode and will be scanned first\n", __FUNCTION__, __LINE__, pWanIfaceData->uiIfaceIdx));
            return TRUE;
        }
    }
    return FALSE;
}

void setActiveLinkToSysCfg(WanMgr_Policy_Controller_t *pWanController)
{
    char           buf[10]         = {0};
    UINT           IfaceIndex      = WAN_INDEX_DOCSIS;
    DML_WAN_IFACE *pActiveInterface = &(pWanController->pWanActiveIfaceData->data);

    if ( strstr(pActiveInterface->BaseInterface, "CableModem") )
    {
        IfaceIndex = WAN_INDEX_DOCSIS;
    }
    else if ( strstr(pActiveInterface->BaseInterface, "Ethernet") )
    {
        IfaceIndex = WAN_INDEX_ETHWAN;
    }

    CcspTraceInfo(("%s %d:  last_wan_mode, curr_wan_mode set to %d\n", __FUNCTION__, __LINE__, IfaceIndex));
    snprintf(buf, sizeof(buf), "%d", IfaceIndex);
    syscfg_set_commit(NULL, "last_wan_mode", buf); 
    syscfg_set_commit(NULL, "curr_wan_mode", buf);
}
#endif
/*
 * WanMgr_SetActiveLink()
* - sets the ActiveLink locallt and saves it to PSM
 */
static int WanMgr_SetActiveLink (WanMgr_Policy_Controller_t * pWanController, bool storeValue)
{
    if ((pWanController == NULL) || (pWanController->activeInterfaceIdx == -1)
            || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    // set ActiveLink in Interface data
    DML_WAN_IFACE* pIfaceData = &(pWanController->pWanActiveIfaceData->data);
    if(pIfaceData->Selection.ActiveLink != storeValue)
    {
        pIfaceData->Selection.ActiveLink = storeValue;
        // save ActiveLink value in PSM
        if (DmlSetWanActiveLinkInPSMDB(pWanController->activeInterfaceIdx, storeValue) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s %d: Failed to set ActiveLink in PSM, SelectedInterface %d \n",
                        __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
        }
    }
    return ANSC_STATUS_SUCCESS;
}


/*
 * WanMgr_GetPrevSelectedInterface()
 * - returns the interface index of previously selected interface
 */
static int WanMgr_GetPrevSelectedInterface (WanMgr_Policy_Controller_t* pWanController)
{
    if ((pWanController == NULL) || (pWanController->TotalIfaces == 0))
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return -1;
    }

    // select iface with ActiveLink = TRUE
    UINT uiLoopCount;
    int uiInterfaceIdx = -1;

    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
        {
            WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
            if(pWanDmlIfaceData != NULL)
            {
                DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
                if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
                {
                    if (pWanIfaceData->Selection.ActiveLink == TRUE)
                    {
                        if (pWanIfaceData->Selection.Enable != TRUE)
                        {
                            CcspTraceInfo(("%s %d: Previous ActiveLink Interface Index:%d is Wan disabled, So setting ActiveLink to FALSE and saving it to PSM\n",
                                        __FUNCTION__, __LINE__, uiLoopCount));
                            if (DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE) != ANSC_STATUS_SUCCESS)
                            {
                                CcspTraceError(("%s-%d: Failed to set ActiveLink in PSM, SelectedInterface %d \n",
                                            __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
                            }
                            pWanIfaceData->Selection.ActiveLink = FALSE;
                            uiInterfaceIdx = -1;
                        }
                        else
                        {
                            CcspTraceInfo(("%s %d: Previous ActiveLink Interface Index:%d\n",
                                        __FUNCTION__, __LINE__, uiLoopCount));
                            uiInterfaceIdx = uiLoopCount;
                        }
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        return uiInterfaceIdx;
                    }
                }
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            }
        }
    return uiInterfaceIdx;
}


/*
 * WanMgr_Policy_Auto_GetHighPriorityIface()
 * - returns highest priority interface that is Selection.Enable == TRUE && VirtIfList->Status == WAN_IFACE_STATUS_DISABLED
 */
static void WanMgr_Policy_Auto_GetHighPriorityIface(WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->WanEnable != TRUE)
        || (pWanController->TotalIfaces == 0))
    {
        CcspTraceError(("%s %d: Invalid args or Global Wan disabled\n", __FUNCTION__, __LINE__));
        return;
    }

    UINT uiLoopCount;
    INT iSelInterface = -1;
    INT iSelPriority = DML_WAN_IFACE_PRIORITY_MAX;

    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                //Check Iface Wan Enable and Wan Status
                if ((pWanIfaceData->Selection.Enable == TRUE) && 
                        (pWanIfaceData->Selection.Priority >= 0) &&
                        (pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_DISABLED))
                {
                    if((pWanController->AllowRemoteInterfaces == FALSE) && (pWanIfaceData->IfaceType == REMOTE_IFACE))
                    {
                        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                        continue;
                    }
                    // pWanIfaceData - is Wan-Enabled & has valid Priority
                    if(pWanIfaceData->Selection.Priority < iSelPriority
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_))
                        //TODO: this is a workaround to support upgarde from Comcast autowan policy to Unification build
                        || isLastActiveLinkFromSysCfg(pWanIfaceData)
#endif    
                      )
                    {
                        // update Primary iface with high priority iface
                        iSelInterface = uiLoopCount;
                        iSelPriority = pWanIfaceData->Selection.Priority;
                    }
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    if (iSelInterface != -1)
    {
        pWanController->activeInterfaceIdx = iSelInterface;
        CcspTraceInfo(("%s %d: Current Selected iface index =%d \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    }

    return;
}

/*
 * WanMgr_UpdateControllerData()
 * - updates the controller data 
 * - this function is called every time in the begining of the loop,
         so that the states/transition can work with the current data
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
 * WanMgr_ResetActiveLinkOnAllIface()
 * - reset ActiveLink to false and saves it in PSM
 * - this will prevent any newly connected high priority iface to become second ActiveLink, 
        in case ResetActiveLinkflag is set
 */
static int WanMgr_ResetActiveLinkOnAllIface (WanMgr_Policy_Controller_t* pWanController)
{
    if ((pWanController == NULL) || (pWanController->TotalIfaces == 0))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    UINT uiLoopCount;
    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                CcspTraceInfo(("%s %d: setting Interface index:%d, ActiveLink = FALSE and saving it in PSM \n", __FUNCTION__, __LINE__, uiLoopCount));
                pWanIfaceData->Selection.ActiveLink = FALSE;
                if (DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE) != ANSC_STATUS_SUCCESS)
                {
                    CcspTraceError(("%s %d: Failed to set ActiveLink in PSM, SelectedInterface %d \n",
                                __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
                    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                    return ANSC_STATUS_FAILURE;
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
    return ANSC_STATUS_SUCCESS;
}

/*
 * WanMgr_ResetGroupSelectedIface()
 */
static int WanMgr_ResetGroupSelectedIface (WanMgr_Policy_Controller_t* pWanController)
{
    if ((pWanController == NULL) || (pWanController->TotalIfaces == 0))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (WanMgr_SetGroupSelectedIface (pWanController->GroupInst, 0) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Failed to set ActiveLink in PSM, SelectedInterface %d \n",
                        __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    }
    return ANSC_STATUS_SUCCESS;
}

/*
 * WanMgr_ResetIfaceTable()
 * - iterates thorugh the interface table and sets INVALID interfaces as DISABLED
 */
static void WanMgr_ResetIfaceTable (WanMgr_Policy_Controller_t* pWanController)
{
    if ((pWanController == NULL) || (pWanController->TotalIfaces == 0))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return;
    }

    UINT uiLoopCount;
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                if (pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_INVALID)
                {
                    pWanIfaceData->VirtIfList->Status = WAN_IFACE_STATUS_DISABLED;
                    CcspTraceInfo(("%s-%d: VirtIfList->Status=Disabled, Interface-Idx=%d, Interface-Name=%s\n",
                                __FUNCTION__, __LINE__, uiLoopCount, pWanIfaceData->DisplayName));
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

}

/*
 * WanMgr_CheckIfSelectedIfaceOnlyPossibleWanLink()
 * - checks if the selected iface is the only possible wan link
 * - if yes, returns TRUE, else returns FALSE
 */
static bool WanMgr_CheckIfSelectedIfaceOnlyPossibleWanLink (WanMgr_Policy_Controller_t* pWanController)
{
    if ((pWanController == NULL) || (pWanController->activeInterfaceIdx == -1)
        || (pWanController->TotalIfaces == 0))
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return FALSE;
    }

    /* If GroupPersistSelectedIface is TRUE and we have a last selected interface, 
     * don't start ISM for other interfaces. Last ActiveLink will be the only possible link.
     */
    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if(pWanController->GroupPersistSelectedIface == TRUE && pActiveInterface->Selection.ActiveLink == TRUE)
    {
        return TRUE;
    }

    UINT uiLoopCount;
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        if (uiLoopCount == pWanController->activeInterfaceIdx)
            continue;

        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                if (pWanIfaceData->Selection.Enable == TRUE)
                {
                    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                    return FALSE;
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
    return TRUE; 

}

/*
 * Transition_Start()
 * - If the ActiveLink flag of any interface is set to TRUE, then that interface is selected and moved out of bridge
 * - else, all interfaces are moved out of LAN bridge and the interface with the highest priority in the table ("0" is the highest) will be selected
 */
static WcAwPolicyState_t Transition_Start (WanMgr_Policy_Controller_t* pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args \n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    char phyPath[BUFLEN_128] = {0};
    if (pWanController->WanEnable == TRUE)
    {
        // select the previously used Active Link
        pWanController->activeInterfaceIdx = WanMgr_GetPrevSelectedInterface (pWanController);
        if (pWanController->activeInterfaceIdx != -1)
        {
            CcspTraceInfo(("%s %d: Previous ActiveLink interface from DB is %d\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
            // previously used ActiveLink found
            WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pWanController->activeInterfaceIdx);
            DML_WAN_IFACE * pActiveInterface = &(pWanDmlIfaceData->data);
            if (pActiveInterface != NULL)
            {
                if(pWanController->GroupPersistSelectedIface == TRUE)
                {
                    CcspTraceInfo(("%s %d GroupPersistSelectedIface is enabled and only last ActiveLink %s ISM will be started\n", __FUNCTION__, __LINE__, pActiveInterface->DisplayName));
                }
                strncpy (phyPath, pActiveInterface->BaseInterface, sizeof(phyPath)-1);
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                if (strstr(phyPath, "Ethernet") != NULL)
                {
                    // previous ActiveLink is an WANoE interface, so remove it from LAN bridge
                    CcspTraceInfo(("%s %d:  previous ActiveLink is WANoE \n", __FUNCTION__, __LINE__));
                    WanMgr_RdkBus_AddIntfToLanBridge(phyPath, FALSE);
                }
                else
                {
                    CcspTraceInfo(("%s %d:  previous ActiveLink is not WANoE \n", __FUNCTION__, __LINE__));
                    WanMgr_RdkBus_AddAllIntfsToLanBridge(pWanController, FALSE);
                }
            }
        }
        else
        {
            CcspTraceInfo(("%s %d: unable to select an previous active interface from psm\n", __FUNCTION__, __LINE__));
            // No previous ActiveLink available
            WanMgr_RdkBus_AddAllIntfsToLanBridge(pWanController, FALSE);
            WanMgr_Policy_Auto_GetHighPriorityIface(pWanController);
        }
    }

    CcspTraceInfo(("%s %d: State changed to STATE_AUTO_WAN_INTERFACE_SELECTING \n", __FUNCTION__, __LINE__));

    return STATE_AUTO_WAN_INTERFACE_SELECTING;

}

/*
 * Transition_InterfaceSelected()
 * - Interface is Selected but not validated
 * - Start the timer, and go to the Wait for Interface State
 */
static WcAwPolicyState_t Transition_InterfaceSelected (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // update the  controller SelectedTimeOut for new selected active iface
    DML_WAN_IFACE* pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    pWanController->InterfaceSelectionTimeOut = pActiveInterface->Selection.Timeout;
    CcspTraceInfo(("%s %d: selected interface idx=%d, name=%s, selectionTimeOut=%d \n",
                __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx, pActiveInterface->DisplayName,
                pWanController->InterfaceSelectionTimeOut));

    // Start Timer based on SelectiontimeOut
    CcspTraceInfo(("%s %d: Starting timer for interface %d \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(pWanController->SelectionTimeOutStart));
    pWanController->SelectionTimeOutStart.tv_sec += pWanController->InterfaceSelectionTimeOut;

#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_))
    /* TODO: For Xb devices DOCSIS and Ethrenet hal are controlled by a single DM. 
     * Setting SELECTED_OPERATIONAL_MODE DM to a mode will disable other stack. 
     * We have to set this DM to start Wan operation on a specific interface. 
     */
    if (strstr(pActiveInterface->BaseInterface, "CableModem") || (strstr(pActiveInterface->BaseInterface, "Ethernet")))
    {    
        setActiveLinkToSysCfg(pWanController);
#if defined(AUTOWAN_ENABLE)
        char operationalMode[64] ={0};
        strncpy(operationalMode, strstr(pActiveInterface->BaseInterface, "CableModem")?"DOCSIS":"Ethernet", sizeof(operationalMode));

        if (WanMgr_RdkBus_SetParamValues(ETH_COMPONENT_NAME, ETH_COMPONENT_PATH, SELECTED_OPERATIONAL_MODE, operationalMode, ccsp_string, TRUE) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s %d: unable to change %s = %s. Retry...\n", __FUNCTION__, __LINE__, SELECTED_OPERATIONAL_MODE, operationalMode));
            return STATE_AUTO_WAN_INTERFACE_SELECTING;
        }
        else
        {
            CcspTraceInfo(("%s %d: succesfully changed %s to %s\n",__FUNCTION__, __LINE__,SELECTED_OPERATIONAL_MODE, operationalMode));
        }
#endif /* AUTOWAN_ENABLE */
    }
#endif

    CcspTraceInfo(("%s %d: State changed to STATE_AUTO_WAN_INTERFACE_SCANNING \n", __FUNCTION__, __LINE__));

    return Transition_InterfaceFound(pWanController);;
}

/*
 * Transition_InterfaceInvalid()
 * - called when interface failed to be validated before its SelectionTimeout, or WAN disbaled for interface
 * - Mark the selected interface as Invalid (VirtIfList->Status = Invalid)
 * - Set ActiveLink to FALSE, and persist it in PSM
 * - Deselect the interface
 * - Return to Selecting Interface State
 */
static WcAwPolicyState_t Transition_InterfaceInvalid (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL)
            || (pWanController->activeInterfaceIdx == -1))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // set VirtIfList->Status = INVALID and ActiveLink as FALSE for selected interface before deselecting it
    DML_WAN_IFACE* pIfaceData = &(pWanController->pWanActiveIfaceData->data);
    CcspTraceInfo(("%s %d: setting Interface index:%d, VirtIfList->Status=InValid \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    pIfaceData->VirtIfList->Status = WAN_IFACE_STATUS_INVALID;

    // set ActiveLink = FALSE and save it to PSM
    CcspTraceInfo(("%s %d: setting Interface index:%d, ActiveLink = False and saving it in PSM \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));

    if (WanMgr_SetActiveLink (pWanController, FALSE) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Failed to set ActiveLink in PSM, SelectedInterface %d \n",
                    __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    }

    // deselect the interface
    CcspTraceInfo(("%s %d: de-selecting interface \n", __FUNCTION__, __LINE__));
    pWanController->activeInterfaceIdx = -1;

    return STATE_AUTO_WAN_INTERFACE_SELECTING;

}

/*
 * Transition_TryingNextInterface()
 * - no interface selected yet
 * - Select an interface with highest priority - iface with VirtIfList->Status = Disabled
 * - if unable to select an interface, then mark all interface disabled
 * - got to Selecting Interface State in all cases
 */
static WcAwPolicyState_t Transition_TryingNextInterface (WanMgr_Policy_Controller_t * pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    WanMgr_Policy_Auto_GetHighPriorityIface(pWanController);

    if (pWanController->activeInterfaceIdx == -1)
    {
        WANMGR_IFACE_GROUP* pWanIfaceGroup = WanMgr_GetIfaceGroup_locked((pWanController->GroupInst - 1));
        if (pWanIfaceGroup != NULL)
        {
            //All interfaces are scanned atleast once. set InitialScanComplete to TRUE
            if(pWanIfaceGroup->InitialScanComplete == FALSE)
            {
                pWanIfaceGroup->InitialScanComplete = TRUE;
                CcspTraceInfo(("%s %d  group(%d) Initial Scan Completed\n", __FUNCTION__, __LINE__, pWanController->GroupInst));
            }
            WanMgrDml_GetIfaceGroup_release();
        }

        WanMgr_ResetIfaceTable(pWanController);
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_))
        if(pWanController->GroupInst == 1) //Reset only for primary group
        {
            //Reset last_wan_mode, curr_wan_mode to AUTO
            CcspTraceInfo(("%s %d: resetting last_wan_mode and curr_wan_mode to Auto\n", __FUNCTION__, __LINE__));
            syscfg_set_commit(NULL, "last_wan_mode", "0");
            syscfg_set_commit(NULL, "curr_wan_mode", "0");
        }
#endif
    }

    return STATE_AUTO_WAN_INTERFACE_SELECTING;
}

/*
 * Transition_InterfaceFound()
 * selected iface is PHY UP
 * Set Selection.Status to “Active” and start Interface State Machine thread
 * Go to Scanning Interface State
 */
static WcAwPolicyState_t Transition_InterfaceFound (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // Set Selection.Status = SELECTED & start Interface State Machine
    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);

    if(WanMgr_StartWanVISM(pWanController->activeInterfaceIdx, WAN_IFACE_SELECTED) != 0)
    {
        CcspTraceError(("%s %d: Failed to start WAN for interface %d \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
        return STATE_AUTO_WAN_ERROR;
    }

#ifdef WAN_MANAGER_SELECTION_SCAN_TIMEOUT_DISABLE
    // update the  controller SelectedTimeOut for new selected active iface
    pWanController->InterfaceSelectionTimeOut = pActiveInterface->Selection.Timeout;
    CcspTraceInfo(("%s %d: selected interface idx=%d, name=%s, selectionTimeOut=%d \n",
                __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx, pActiveInterface->DisplayName,
                pWanController->InterfaceSelectionTimeOut));

    // Start Timer based on SelectiontimeOut
    CcspTraceInfo(("%s %d: Starting timer for interface %d \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(pWanController->SelectionTimeOutStart));
    pWanController->SelectionTimeOutStart.tv_sec += pWanController->InterfaceSelectionTimeOut;
#endif

    return STATE_AUTO_WAN_INTERFACE_SCANNING;
}

/*
 * Transition_InterfaceDeselect()
 * - Selected interface is Phy DOWN
 * - Call WanMgr_StopWanVISM() to stop the interface state machine
 * - Go to Waiting Interface Teardown State 
 */
static WcAwPolicyState_t Transition_InterfaceDeselect (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    CcspTraceInfo(("%s %d: Calling WanMgr_StopWanVISM for interface %d\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    WanMgr_StopWanVISM(pWanController->activeInterfaceIdx);

    return STATE_AUTO_WAN_INTERFACE_TEARDOWN;

}

/*
 * Transition_InterfaceValidated()
 * selected interface is 
 * - Set ActiveLink to TRUE, and persist it in PSM
 * - Stop WAN scan timer
 * - Go to Interface Reconfiguration State
 */
static WcAwPolicyState_t Transition_InterfaceValidated (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL)) 
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // Set ActiveLink to TRUE and store it in PSM
    if (WanMgr_SetActiveLink (pWanController, TRUE) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Failed to set ActiveLink in PSM, SelectedInterface %d \n",
                    __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    }

    CcspTraceInfo(("%s %d: setting GroupSelectedInterface(%d) \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    if (WanMgr_SetGroupSelectedIface (pWanController->GroupInst, (pWanController->activeInterfaceIdx+1)) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s-%d: Failed to set GroupSelectedInterface %d \n",
                    __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    }

    // stop timer
    CcspTraceInfo(("%s %d: stopping timer\n", __FUNCTION__, __LINE__));
    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));

    return STATE_AUTO_WAN_INTERFACE_RECONFIGURATION;

}

/*
 * Transition_RestartSelectionInterface()
 * - Deselect the interface (previously selected)
 * - Reset table, interfaces marked as Invalid should be marked as Disabled
 * - Set ResetActiveLink flag is set to “FALSE”
 * - Go to Selecting Interface State
 */
static WcAwPolicyState_t Transition_RestartSelectionInterface (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // reset ActiveLink to false for all interfaces and save it in PSM
    if (WanMgr_ResetActiveLinkOnAllIface(pWanController) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Unable to reset ActiveLink in all interfaces\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // reset ResetSelectedInterface to FALSE
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
        CcspTraceInfo(("%s %d: Resetting FO scan thread\n", __FUNCTION__, __LINE__));
        pWanConfigData->data.ResetFailOverScan = TRUE;
        DML_WAN_IFACE* pWanIfaceData = &(pWanConfigData->data);
        pWanIfaceData->bSendSelectionTimerExpired = TRUE;	
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    // deselect interface 
    CcspTraceInfo(("%s %d: de-selecting interface\n", __FUNCTION__, __LINE__));
    pWanController->activeInterfaceIdx = -1;

    // reset all interfaces for selection
    CcspTraceInfo(("%s %d: So resetting interface table\n", __FUNCTION__, __LINE__));
    WanMgr_ResetIfaceTable(pWanController);
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_))
    if(pWanController->GroupInst == 1) //Reset only for primary group
    {
        //Reset last_wan_mode, curr_wan_mode to AUTO
        CcspTraceInfo(("%s %d: resetting last_wan_mode and curr_wan_mode to Auto\n", __FUNCTION__, __LINE__));
        syscfg_set_commit(NULL, "last_wan_mode", "0");
        syscfg_set_commit(NULL, "curr_wan_mode", "0");
    }
#endif

    // remove all interface from LAN bridge
    WanMgr_RdkBus_AddAllIntfsToLanBridge(pWanController, FALSE);

    if (WanMgr_ResetGroupSelectedIface(pWanController) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Unable to reset GroupSelectedInterface \n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    return STATE_AUTO_WAN_INTERFACE_SELECTING;
}

/*
 * Transition_ReconfigurePlatform()
 * - need to reconfigure platform
 * - Call WanMgr_StopWanVISM() to stop the interface state machine, this will trigger the interface state machine thread teardown.
 * - Go to Rebooting Platform
 */
static WcAwPolicyState_t Transition_ReconfigurePlatform (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL)) 
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    //  Call WanMgr_StopWanVISM() to stop the interface state machine
    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    CcspTraceInfo(("%s %d: Calling WanMgr_StopWanVISM for interface %d\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    WanMgr_StopWanVISM(pWanController->activeInterfaceIdx); 
    pActiveInterface->Selection.RebootTriggerStatus = TRUE;
    

    return STATE_AUTO_WAN_REBOOT_PLATFORM;
}

/**
 * @brief Handles the transition to the Auto WAN Tear Down state.
 *
 * This function manages the state transition logic for tearing down the AUTO WAN policy.
 * It stops the WAN interface state machine and prepares for the WAN policy to be torn down.
 *
 * @param[in,out] pWanController Pointer to the WAN policy controller structure.
 *
 * @return The new state of the WAN policy after the transition.
 */
static WcAwPolicyState_t Transition_AutoWanTearDown (WanMgr_Policy_Controller_t * pWanController)
{
    if (pWanController == NULL|| (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // Call WanMgr_StopWanVISM() to stop the interface state machine
    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    CcspTraceInfo(("%s %d: Calling WanMgr_StopWanVISM for interface %d\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    WanMgr_StopWanVISM(pWanController->activeInterfaceIdx);
    
    return STATE_AUTO_WAN_TEARING_DOWN;
    
}

/*
 * Transition_ActivatingInterface()
 * - Go to WAN Interface Active State
 */
static WcAwPolicyState_t Transition_ActivatingInterface (WanMgr_Policy_Controller_t * pWanController)
{
    CcspTraceInfo(("%s %d: moving to state State_WanInterfaceActive()\n", __FUNCTION__, __LINE__));
    return STATE_AUTO_WAN_INTERFACE_ACTIVE;
}

/*
 * Transition_ResetSelectedInterface()
 * - Call WanMgr_StopWanVISM() to stop the interface state machine, this will trigger the interface state machine thread teardown.
 */

static WcAwPolicyState_t Transition_ResetSelectedInterface (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL)) 
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    CcspTraceInfo(("%s %d: Calling WanMgr_StopWanVISM for interface %d. moving to State_WaitingForIfaceTearDown()\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    WanMgr_StopWanVISM(pWanController->activeInterfaceIdx); 

    return STATE_AUTO_WAN_INTERFACE_TEARDOWN;
}

static WcAwPolicyState_t Transition_RebootDevice(void)
{
    CcspTraceInfo(("%s %d: wanmanager triggering reboot. \n", __FUNCTION__, __LINE__));
    Wanmgr_TriggerReboot();
    return STATE_AUTO_WAN_SM_EXIT;
}

/*
 * State_SelectingInterface()
 * - If some interface was selected, the Interface Selected Transition will be called
 * - Else, if no interface was selected, the Trying Next Interface Transition will be called
 */
static WcAwPolicyState_t State_SelectingInterface (WanMgr_Policy_Controller_t * pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    if(pWanController->WanEnable == FALSE || pWanController->GroupCfgChanged == TRUE)
    {
        return STATE_AUTO_WAN_SM_EXIT;
    }

    if (pWanController->activeInterfaceIdx != -1)
    {
        CcspTraceInfo (("%s %d: Selected interface index:%d\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
        return Transition_InterfaceSelected (pWanController);
    }

    return Transition_TryingNextInterface (pWanController);

}

/*
 * State_ScanningInterface()
 * - If the selected interface is the only Interface enabled (Selection.Enable = TRUE), the Interface Validated Transition will be called
 * - If the BaseInterfaceStatus flag is set to "DOWN", the Interface Deselected Transition will be called
 * - If the VirtIfList->Status is set to "UP", indicating that the interface was validated, the Interface Validated Transition will be called
 * - If the WAN scan timer expires (and the interface selected is not the only possible interface), the Interface Deselected Transition will be called.
 */
static WcAwPolicyState_t State_ScanningInterface (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    if(pWanController->WanEnable == FALSE || pWanController->GroupCfgChanged == TRUE)
    {
        CcspTraceInfo(("%s %d: Scanning Interface index : %d, WanEnable = %d, pWanController->GroupCfgChanged = %d", __FUNCTION__, __LINE__, pWanController->WanEnable, pWanController->GroupCfgChanged));
        return Transition_InterfaceDeselect(pWanController);
    }

    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data); 
    bool SelectedIfaceLastWanLink = WanMgr_CheckIfSelectedIfaceOnlyPossibleWanLink(pWanController);

    // If selected Interface is the only WAN enabled, move to Interface Validation Transition
    if (SelectedIfaceLastWanLink)
    { 
        CcspTraceInfo(("%s %d: Interface index %d is only WAN Link, so moving it to validated\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
        return Transition_InterfaceValidated(pWanController);
    }

    // If Interace is WAN disabled, move to interface deselect transition
    if (pActiveInterface->Selection.Enable == FALSE)
    { 
        CcspTraceInfo(("%s %d: selected interface index:%d is BaseInetrfaceStatus = %s, Selection.Enable = %d\n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx, 
                    (pActiveInterface->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP)?"UP":"DOWN", pActiveInterface->Selection.Enable));
        return Transition_InterfaceDeselect(pWanController);
    }
    
    // checked if iface is validated or only interface enabled
    if ((pActiveInterface->VirtIfList->Status == WAN_IFACE_STATUS_UP) || 
        (pActiveInterface->VirtIfList->Status == WAN_IFACE_STATUS_STANDBY) ||
        (pActiveInterface->VirtIfList->Status == WAN_IFACE_STATUS_VALID))
    {
        CcspTraceInfo(("%s %d: Interface validated\n", __FUNCTION__, __LINE__));
        return Transition_InterfaceValidated(pWanController);
    }

    // if timer is expired and there is another iface that can be used as Wan, deselect interface
    if((pWanController->SelectionTimeOutStart.tv_sec > 0) && 
            (SelectedIfaceLastWanLink == FALSE))
    {
        clock_gettime( CLOCK_MONOTONIC_RAW, &(pWanController->SelectionTimeOutEnd));
        if(difftime(pWanController->SelectionTimeOutEnd.tv_sec, pWanController->SelectionTimeOutStart.tv_sec ) > 0)
        {
            CcspTraceInfo(("%s %d: Validation Timer expired for interface index:%d and there is another iface that can be possibly used as Wan interface\n", 
                        __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
            WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pActiveInterface->VirtIfList,0),WAN_WARN_IP_OBTAIN_TIMER_EXPIRED);    
            return Transition_InterfaceDeselect(pWanController);
        }
    }

    return STATE_AUTO_WAN_INTERFACE_SCANNING;

}

/*
 * State_WaitingForIfaceTearDown()
 * - wait for iface state machine to go down
 * - After the Interface State Machine thread terminate
 *       check for ResetSelectedInterface flag - if TRUE goto Restart Selection Transition
 *       else go to iface invalid transition
 */
static WcAwPolicyState_t State_WaitingForIfaceTearDown (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // check if iface sm is running
    if (WanMgr_Get_ISM_RunningStatus(pWanController->activeInterfaceIdx) == TRUE)
    {
        return STATE_AUTO_WAN_INTERFACE_TEARDOWN;
    }

    if(pWanController->WanEnable == FALSE || pWanController->GroupCfgChanged == TRUE)
    {
        return Transition_AutoWanTearDown(pWanController);
    }

    CcspTraceInfo(("%s %d: Iface state machine has exited\n", __FUNCTION__, __LINE__));

    // check ResetSelectedInterface
    if (pWanController->ResetSelectedInterface == TRUE)
    {
        CcspTraceInfo(("%s %d: ResetSelectedInterface flag detected\n", __FUNCTION__, __LINE__));
        return Transition_RestartSelectionInterface(pWanController);
    }

    return Transition_InterfaceInvalid (pWanController);

}

/*
 * State_InterfaceReconfiguration()
 * interfaces that are not selected must be added to LAN bridge
 * Check the HW configstatus (WAN/LAN), if the current HW config is LAN and the Selection.RequiresReboot is set to “TRUE”
 */
static WcAwPolicyState_t State_InterfaceReconfiguration (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // add interface that is not selected in LAN bridge
    UINT uiLoopCount;
    int ret = 0;
    char PhyPath[BUFLEN_128];
    memset (PhyPath, 0, sizeof(PhyPath));
    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        if (uiLoopCount == pWanController->activeInterfaceIdx)
        {
            // skip LAN bridge config for selected interface
            continue;
        }
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE * pWanIfaceData = &(pWanDmlIfaceData->data);

             if(pWanController->GroupInst != pWanIfaceData->Selection.Group)
             {
                 WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                 continue;
             }

            strncpy (PhyPath, pWanIfaceData->BaseInterface, sizeof(PhyPath)-1);
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

            if ((strlen(PhyPath) > 0) && (strstr(PhyPath, "Ethernet")))
            {
                ret = WanMgr_RdkBus_AddIntfToLanBridge(PhyPath, TRUE);
                if (ret == ANSC_STATUS_FAILURE)
                {
                    CcspTraceError(("%s %d: unable to config LAN bridge for index %d BaseInterface %s\n", __FUNCTION__, __LINE__, uiLoopCount, PhyPath));
                }
                memset (PhyPath, 0, sizeof(PhyPath));
            }
        }
    }

#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_))
    // HW configuration already done using SelectedOperationalMode for XB platforms. Skipping this state.
    CcspTraceInfo(("%s %d: HW configuration already done using SelectedOperationalMode.\n", __FUNCTION__, __LINE__));
    return Transition_ActivatingInterface (pWanController);
#endif

// check if Hardware Configuration is required
    bool ConfigChanged = FALSE;
    bool CurrIntfHwRebootConfig = FALSE;
    bool RebootRequired = FALSE;
    char dmQuery[BUFLEN_256] = {0};
    char buff[BUFLEN_256] = {0};
    char dmValue[BUFLEN_256] = {0};

    for( uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++ )
    {
        memset (PhyPath, 0, sizeof(PhyPath));

        // for every interface that has WAN Hardware configuration, check if hw config is correct 
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if ((strstr(pWanIfaceData->BaseInterface, "Ethernet") == NULL) || pWanController->GroupInst != pWanIfaceData->Selection.Group)
            {
                // no hardware configuration needed for this interface
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                continue;
            }

            CurrIntfHwRebootConfig = pWanIfaceData->Selection.RequiresReboot;
            strncpy(PhyPath, pWanIfaceData->BaseInterface,  sizeof(PhyPath) - 1);

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

            CcspTraceInfo (("%s %d: Interfce idx:%d has BaseInterface :%s and RebootRequired:%d\n", __FUNCTION__, __LINE__, uiLoopCount, PhyPath, CurrIntfHwRebootConfig));

            // get WAN Hardware configuration 
            UINT index = 0;
            ConfigChanged = FALSE;
            memset(dmQuery, 0, BUFLEN_256);
            sscanf(PhyPath, "%*[^0-9]%d", &index);
            snprintf(buff, sizeof(buff), ETH_HW_CONFIG_PHY_PATH, index);
            snprintf(dmQuery, sizeof(dmQuery), "%s%s", buff, UPSTREAM_DM_SUFFIX);
            if (WanMgr_RdkBus_GetParamValues (ETH_COMPONENT_NAME, ETH_COMPONENT_PATH, dmQuery, dmValue) != ANSC_STATUS_SUCCESS) 
            {
                CcspTraceError(("%s %d: unable to get %s value\n", __FUNCTION__, __LINE__, dmQuery));
                continue;
            }

            if (uiLoopCount == pWanController->activeInterfaceIdx)
            {
                // active interface should have WAN capabilities enabled in hw
                if (strncasecmp(dmValue, "true", 4) != 0)
                {
                    // set WAN capabilities for on active interface on hw
                    if (WanMgr_RdkBus_SetParamValues(ETH_COMPONENT_NAME, ETH_COMPONENT_PATH, dmQuery, "true", ccsp_boolean, TRUE) != ANSC_STATUS_SUCCESS)
                    {
                        CcspTraceError(("%s %d: unable to change %s = true for seleted active interface %d\n", __FUNCTION__, __LINE__, dmQuery, uiLoopCount));
                    }
                    else
                    {
                        CcspTraceInfo(("%s %d: succesfully changed %s = true for selected active interface %d\n",__FUNCTION__, __LINE__, dmQuery, uiLoopCount));
                        ConfigChanged = TRUE;
                    }
                }
            }
            else
            {
                // interface that are not selected need WAN capabilities disabled on hw
                if (strncasecmp(dmValue, "false", 5) != 0)
                {
                    // set WAN capabilities for on active interface on hw
                    if (WanMgr_RdkBus_SetParamValues(ETH_COMPONENT_NAME, ETH_COMPONENT_PATH, dmQuery, "false", ccsp_boolean, TRUE) != ANSC_STATUS_SUCCESS)
                    {
                        CcspTraceError(("%s %d: unable to change %s = false for unselected interface %d\n", __FUNCTION__, __LINE__, dmQuery, uiLoopCount));
                    }
                    else
                    {
                        CcspTraceInfo(("%s %d: succesfully changed %s = false for unselected interface %d\n", __FUNCTION__, __LINE__, dmQuery, uiLoopCount));
                        ConfigChanged = TRUE;
                    }
                }
            }

            if (CurrIntfHwRebootConfig && ConfigChanged)
            {
                // hw config changed and Interface need reboot to enable/disable WAN capabilities
                RebootRequired = TRUE;
            }
        }

    }

    if (RebootRequired)
    { 
        CcspTraceInfo(("%s %d: Hardware reconfiguration required\n", __FUNCTION__, __LINE__));
        return Transition_ReconfigurePlatform (pWanController);
    }

    return Transition_ActivatingInterface (pWanController);
}

/*
 * State_RebootingPlatform ()
 * - If interface State Machine thread still up, stay in this state
 * - after Interface State Machine thread has exited, reboot
 */
static WcAwPolicyState_t State_RebootingPlatform (WanMgr_Policy_Controller_t * pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // check if interface state machine is still running
    if (WanMgr_Get_ISM_RunningStatus(pWanController->activeInterfaceIdx) == TRUE)
    {
        CcspTraceInfo(("%s %d: Iface state machine still running..\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_REBOOT_PLATFORM;
    }

    return Transition_RebootDevice();
}

/*
 * State_WanInterfaceActive()
 * - If the ResetActiveLink flag is set to "TRUE", the Reset Active Interface Transition will be called
 * - If the BaseInterfaceStatus flag is set to "DOWN", the WAN Interface Down Transition will be called
 */
static WcAwPolicyState_t State_WanInterfaceActive (WanMgr_Policy_Controller_t * pWanController)
{
    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL)) 
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_AUTO_WAN_ERROR;
    }

    // check ResetSelectedInterface
    if ((pWanController->WanEnable == FALSE) 
            || (pWanController->GroupCfgChanged == TRUE) 
            || (pWanController->ResetSelectedInterface == TRUE))
    {
        CcspTraceInfo(("%s %d: ResetSelectedInterface flag detected\n", __FUNCTION__, __LINE__));
        return Transition_ResetSelectedInterface (pWanController);
    }

    DML_WAN_IFACE * pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if((pActiveInterface->VirtIfChanged == TRUE) || (pActiveInterface->Selection.Enable == TRUE))
    {
        
        for(int VirtId=0; VirtId < pActiveInterface->NoOfVirtIfs; VirtId++)
        {
            DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIface_locked(pWanController->activeInterfaceIdx, VirtId);
            if(p_VirtIf != NULL )
            {
                if(p_VirtIf->Enable == TRUE && p_VirtIf->Interface_SM_Running == FALSE)
                {
                    CcspTraceInfo(("%s %d: Starting virtual InterfaceStateMachine for %d, Selection.Status=%d\n", __FUNCTION__, __LINE__, VirtId, pActiveInterface->Selection.Status));
                    if(WanMgr_StartWanVISM(pWanController->activeInterfaceIdx, (pActiveInterface->Selection.Status == WAN_IFACE_ACTIVE )?WAN_IFACE_ACTIVE:WAN_IFACE_SELECTED) != 0)
                    {
                        CcspTraceError(("%s %d: Failed to start WAN for interface %d \n", __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
                        return STATE_AUTO_WAN_ERROR;
                    }
                }
                WanMgr_VirtualIfaceData_release(p_VirtIf);
            }
        }
        pActiveInterface->VirtIfChanged = FALSE;
    }

    return STATE_AUTO_WAN_INTERFACE_ACTIVE;
}

static WcAwPolicyState_t State_WaitingForInterfaceSMExit(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE* pFixedInterface = NULL;

    if((pWanController != NULL) && (pWanController->pWanActiveIfaceData != NULL))
    {
        pFixedInterface = &(pWanController->pWanActiveIfaceData->data);
    }

    if(pFixedInterface == NULL)
    {
        return STATE_AUTO_WAN_TEARING_DOWN;
    }

    if(WanMgr_Get_ISM_RunningStatus(pWanController->activeInterfaceIdx) == TRUE)
    {
        return STATE_AUTO_WAN_TEARING_DOWN;
    }

    WanMgr_ResetIfaceTable(pWanController);

    WanMgr_ResetGroupSelectedIface(pWanController);

    if(pWanController->GroupCfgChanged == TRUE)
    {
        WanMgr_ResetActiveLinkOnAllIface(pWanController);
    }

    return STATE_AUTO_WAN_SM_EXIT;
}

void *WanMgr_AutoWanSelectionProcess (void* arg)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));

    bool bRunning = true;
    int n = 0;
    UINT IfaceGroup = 0;
    WanMgr_Policy_Controller_t    WanController;
    WcAwPolicyState_t aw_sm_state;
    struct timeval loopTimer;

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

    CcspTraceInfo(("%s %d: SelectionProcess Thread Starting for GroupId(%d) \n", __FUNCTION__, __LINE__, WanController.GroupInst));

    aw_sm_state = Transition_Start(&WanController); // do this first before anything else to init variables

    while (bRunning)
    {
        /* Wait up to 250 milliseconds */
        loopTimer.tv_sec = 0;
        loopTimer.tv_usec = SELECTION_PROCESS_LOOP_TIMEOUT;

        n = select(0, NULL, NULL, NULL, &loopTimer);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }

        // updates policy controller data
        WanMgr_UpdateControllerData (&WanController);

        // lock Iface Data & update selected iface data in controller data
        WanController.pWanActiveIfaceData = WanMgr_GetIfaceData_locked(WanController.activeInterfaceIdx);
        if (WanController.pWanActiveIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(WanController.pWanActiveIfaceData->data);
            WanController.InterfaceSelectionTimeOut = pWanIfaceData->Selection.Timeout;
            if (!WanController.GroupInst)
            {
                WanController.GroupInst = pWanIfaceData->Selection.Group;
            }
        }

        // process states
        switch (aw_sm_state)
        {
            case STATE_AUTO_WAN_INTERFACE_SELECTING:
                aw_sm_state = State_SelectingInterface(&WanController);
                break;
            case STATE_AUTO_WAN_INTERFACE_SCANNING:
                aw_sm_state = State_ScanningInterface(&WanController);
                break;
            case STATE_AUTO_WAN_INTERFACE_TEARDOWN:
                aw_sm_state = State_WaitingForIfaceTearDown(&WanController);
                break;
            case STATE_AUTO_WAN_INTERFACE_RECONFIGURATION:
                aw_sm_state = State_InterfaceReconfiguration(&WanController);
                break;
            case STATE_AUTO_WAN_REBOOT_PLATFORM:
                aw_sm_state = State_RebootingPlatform(&WanController);
                break;
            case STATE_AUTO_WAN_INTERFACE_ACTIVE:
                aw_sm_state = State_WanInterfaceActive(&WanController);
                break;
            case STATE_AUTO_WAN_TEARING_DOWN:
                aw_sm_state = State_WaitingForInterfaceSMExit(&WanController);
                break;
            case STATE_AUTO_WAN_SM_EXIT:
                bRunning = false;
                break;
            case STATE_AUTO_WAN_ERROR:
            default:
                CcspTraceInfo(("%s %d: Failure Case \n", __FUNCTION__, __LINE__));
                bRunning = false;
                break;
        }
        // release lock iface data
        if(WanController.pWanActiveIfaceData != NULL)
        {
            WanMgrDml_GetIfaceData_release(WanController.pWanActiveIfaceData);
        }

    }

    if(WanController.GroupCfgChanged == TRUE)
    {
        WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
        if(pWanConfigData != NULL)
        {
            CcspTraceInfo(("%s %d: Resetting FO scan thread\n", __FUNCTION__, __LINE__));
            pWanConfigData->data.ResetFailOverScan = TRUE;
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

