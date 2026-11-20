/*********************************************************************************
 If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 Deutsche Telekom AG.
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

*********************************************************************************/

/**************************************************************************************
 * @file wanmgr_policy_multiwan_impl.c
 * @author Sherik Sensin A (sherik.a@telekom-digital.com)
 * @brief One thread per group, started by WanMgr_FO_IfaceGroupMonitor() when
 *        Group.Policy is MULTIWAN_MODE. Built only with --enable-multiwan
 *        (-DFEATURE_RDKB_MULTIWAN).
 *
 *************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sys/select.h>
#include "wanmgr_controller.h"
#include "wanmgr_data.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_interface_sm.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_wan_failover.h"
#include "wanmgr_telemetry.h"
#include "wanmgr_interface_apis.h"

#define SELECTION_PROCESS_LOOP_TIMEOUT 250000 /* microseconds */
#define MAX_PRIORITY_VALUE 255

typedef enum {
    STATE_MULTIWAN_SCANNING_INTERFACE = 0,
    STATE_MULTIWAN_CHECK_RECONFIGURATION,
    STATE_MULTIWAN_REBOOT,
    STATE_MULTIWAN_SELECTED_INTERFACE_UP,
    STATE_MULTIWAN_SELECTED_INTERFACE_DOWN,
    STATE_MULTIWAN_INTERFACE_TEAR_DOWN,
    STATE_MULTIWAN_POLICY_EXIT,
    STATE_MULTIWAN_POLICY_ERROR
} WcMwPolicyState_t;

static WcMwPolicyState_t Transition_Start(WanMgr_Policy_Controller_t *pWanController);
static WcMwPolicyState_t Transition_NewInterfaceConnected(INT IfaceId);
static WcMwPolicyState_t Transition_SelectingInterface(WanMgr_Policy_Controller_t *pWanController);
static WcMwPolicyState_t Transition_InterfaceSelected(WanMgr_Policy_Controller_t *pWanController);
static WcMwPolicyState_t Transition_SelectedInterfaceDown(WanMgr_Policy_Controller_t *pWanController);
static WcMwPolicyState_t Transition_SelectedInterfaceUp(WanMgr_Policy_Controller_t *pWanController);
static WcMwPolicyState_t Transition_RestartScan(WanMgr_Policy_Controller_t *pWanController);
static WcMwPolicyState_t Transition_TearingDown(WanMgr_Policy_Controller_t *pWanController);
static WcMwPolicyState_t Transition_Reboot(WanMgr_Policy_Controller_t *pWanController);

/* Clear group ThreadId/selection and mark group STOPPED (unless DEACTIVATED). */
static void WanMgr_MarkGroupStopped(UINT groupInst)
{
    WANMGR_IFACE_GROUP *pWanIfaceGroup = NULL;

    if (groupInst == 0)
    {
        CcspTraceError(("%s %d: Invalid group instance\n", __FUNCTION__, __LINE__));
        return;
    }

    pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(groupInst - 1);
    if (pWanIfaceGroup == NULL)
    {
        CcspTraceError(("%s %d: Group %u not found\n", __FUNCTION__, __LINE__, groupInst));
        return;
    }

    pWanIfaceGroup->ThreadId = 0;
    pWanIfaceGroup->SelectedInterface = 0;
    pWanIfaceGroup->ConfigChanged = FALSE;
    if (pWanIfaceGroup->State != STATE_GROUP_DEACTIVATED)
    {
        pWanIfaceGroup->State = STATE_GROUP_STOPPED;
    }
    WanMgrDml_GetIfaceGroup_release();
}

/* Refresh controller WanEnable, TotalIfaces, and group ConfigChanged/Reset flags. */
static void WanMgr_UpdateControllerData(WanMgr_Policy_Controller_t *pWanController)
{
    WanMgr_Config_Data_t *pWanConfigData = NULL;
    WANMGR_IFACE_GROUP *pWanIfaceGroup = NULL;

    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return;
    }

    pWanConfigData = WanMgr_GetConfigData_locked();
    if (pWanConfigData != NULL)
    {
        pWanController->WanEnable = pWanConfigData->data.Enable;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    pWanController->TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();

    if (pWanController->GroupInst == 0)
    {
        return;
    }

    pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(pWanController->GroupInst - 1);
    if (pWanIfaceGroup != NULL)
    {
        pWanController->GroupCfgChanged = pWanIfaceGroup->ConfigChanged;
        pWanController->ResetSelectedInterface = pWanIfaceGroup->ResetSelectedInterface;
        WanMgrDml_GetIfaceGroup_release();
    }
}

/*
 * Rescan only when another enabled iface in this group has a strictly better
 * priority and its base link is already up. A higher-priority iface that is
 * only configured, with the link down, does not drop the working WAN.
 * The reset flag is cleared when no better-priority iface exists.
 */
static BOOL WanMgr_CheckRescanRequired(WanMgr_Policy_Controller_t *pWanController)
{
    UINT uiLoopCount = 0;
    BOOL betterConfigured = FALSE;
    DML_WAN_IFACE *pActiveInterface = NULL;

    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return FALSE;
    }

    pActiveInterface = &(pWanController->pWanActiveIfaceData->data);

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if ((pWanController->GroupInst == pWanIfaceData->Selection.Group) &&
            (pWanIfaceData->Selection.Enable == TRUE) &&
            ((INT)uiLoopCount != pWanController->activeInterfaceIdx) &&
            (pWanIfaceData->Selection.Priority < pActiveInterface->Selection.Priority))
        {
            betterConfigured = TRUE;
            if (pWanIfaceData->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP)
            {
                CcspTraceInfo(("%s %d: Higher priority iface %s link is up. Rescan required\n",
                               __FUNCTION__, __LINE__, pWanIfaceData->DisplayName));
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                return TRUE;
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    if (betterConfigured == FALSE)
    {
        WANMGR_IFACE_GROUP *pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(pWanController->GroupInst - 1);
        if (pWanIfaceGroup != NULL)
        {
            pWanIfaceGroup->ResetSelectedInterface = FALSE;
            pWanController->ResetSelectedInterface = FALSE;
            WanMgrDml_GetIfaceGroup_release();
        }
        CcspTraceInfo(("%s %d: %s is the highest priority iface. Rescan not required\n",
                       __FUNCTION__, __LINE__, pActiveInterface->DisplayName));
    }

    return FALSE;
}

/* TRUE if any iface in this group still has a non-DISABLED VirtIf SM. */
static BOOL WanMgr_GroupVirtIfSmRunning(WanMgr_Policy_Controller_t *pWanController)
{
    UINT uiLoopCount = 0;
    BOOL running = FALSE;

    if (pWanController == NULL)
    {
        return FALSE;
    }

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if ((pWanController->GroupInst == pWanIfaceData->Selection.Group) &&
            (pWanIfaceData->VirtIfList != NULL) &&
            (pWanIfaceData->VirtIfList->Status != WAN_IFACE_STATUS_DISABLED))
        {
            running = TRUE;
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            break;
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    return running;
}

/* Init scan timeout from group ifaces and enter SCANNING. */
static WcMwPolicyState_t Transition_Start(WanMgr_Policy_Controller_t *pWanController)
{
    UINT uiLoopCount = 0;

    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    pWanController->InterfaceSelectionTimeOut = 0;

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        BOOL clearActiveLink = FALSE;

        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if (pWanController->GroupInst == pWanIfaceData->Selection.Group)
        {
            if (pWanIfaceData->Selection.Enable == TRUE)
            {
                if (pWanIfaceData->Selection.Timeout > pWanController->InterfaceSelectionTimeOut)
                {
                    pWanController->InterfaceSelectionTimeOut = pWanIfaceData->Selection.Timeout;
                }
            }
            else if (pWanIfaceData->Selection.ActiveLink == TRUE)
            {
                pWanIfaceData->Selection.ActiveLink = FALSE;
                clearActiveLink = TRUE;
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

        if (clearActiveLink == TRUE)
        {
            DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE);
        }
    }

    if (pWanController->GroupInst != 0)
    {
        WANMGR_IFACE_GROUP *pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(pWanController->GroupInst - 1);
        if (pWanIfaceGroup != NULL)
        {
            /* Candidates are considered together, so the group scan is complete
               for the failover controller as soon as this thread is running. */
            pWanIfaceGroup->InitialScanComplete = TRUE;
            WanMgrDml_GetIfaceGroup_release();
        }
    }

    CcspTraceInfo(("%s %d: Maximum timeout %u\n", __FUNCTION__, __LINE__,
                   pWanController->InterfaceSelectionTimeOut));
    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &(pWanController->SelectionTimeOutStart)) != 0)
    {
        CcspTraceError(("%s %d: clock_gettime failed\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    return STATE_MULTIWAN_SCANNING_INTERFACE;
}

/* Start VISM in VALIDATING for a newly linked-up candidate iface. */
static WcMwPolicyState_t Transition_NewInterfaceConnected(INT IfaceId)
{
    if (IfaceId < 0)
    {
        CcspTraceError(("%s %d: Invalid interface id\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_SCANNING_INTERFACE;
    }

    if (WanMgr_StartWanVISM(IfaceId, WAN_IFACE_VALIDATING) != 0)
    {
        CcspTraceError(("%s %d: Failed to start WAN for interface %d\n", __FUNCTION__, __LINE__, IfaceId));
    }

    return STATE_MULTIWAN_SCANNING_INTERFACE;
}

/* Mark selected iface SELECTED/ActiveLink; stop other group VISMs. */
static WcMwPolicyState_t Transition_SelectingInterface(WanMgr_Policy_Controller_t *pWanController)
{
    UINT uiLoopCount = 0;

    if ((pWanController == NULL) || (pWanController->activeInterfaceIdx < 0))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        BOOL inGroup = FALSE;
        BOOL selected = FALSE;

        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if ((pWanController->GroupInst == pWanIfaceData->Selection.Group) &&
            (pWanIfaceData->Selection.Enable == TRUE))
        {
            inGroup = TRUE;
            if ((INT)uiLoopCount == pWanController->activeInterfaceIdx)
            {
                pWanIfaceData->Selection.Status = WAN_IFACE_SELECTED;
                pWanIfaceData->Selection.ActiveLink = TRUE;
                selected = TRUE;
            }
            else
            {
                pWanIfaceData->Selection.ActiveLink = FALSE;
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

        if (inGroup == TRUE)
        {
            if (selected == TRUE)
            {
                DmlSetWanActiveLinkInPSMDB(uiLoopCount, TRUE);
            }
            else
            {
                WanMgr_StopWanVISM((int)uiLoopCount);
                DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE);
            }
        }
    }

    CcspTraceInfo(("%s %d: Selected interface %d for group %u\n", __FUNCTION__, __LINE__,
                   pWanController->activeInterfaceIdx, pWanController->GroupInst));
    if (WanMgr_SetGroupSelectedIface(pWanController->GroupInst,
                                     (UINT)(pWanController->activeInterfaceIdx + 1)) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Failed to set group selected interface %d\n",
                        __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
    }

    return STATE_MULTIWAN_CHECK_RECONFIGURATION;
}

/* Enter SELECTED_INTERFACE_UP after reconfiguration check. */
static WcMwPolicyState_t Transition_InterfaceSelected(WanMgr_Policy_Controller_t *pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    return STATE_MULTIWAN_SELECTED_INTERFACE_UP;
}

/* Enter SELECTED_INTERFACE_DOWN when selected PHY/enable drops. */
static WcMwPolicyState_t Transition_SelectedInterfaceDown(WanMgr_Policy_Controller_t *pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    return STATE_MULTIWAN_SELECTED_INTERFACE_DOWN;
}

/* Restart VISM for selected iface and return to SELECTED_INTERFACE_UP. */
static WcMwPolicyState_t Transition_SelectedInterfaceUp(WanMgr_Policy_Controller_t *pWanController)
{
    DML_WAN_IFACE *pActiveInterface = NULL;
    WANMGR_IFACE_SELECTION selection = WAN_IFACE_SELECTED;

    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL) ||
        (pWanController->activeInterfaceIdx < 0))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if (pActiveInterface->Selection.Status == WAN_IFACE_ACTIVE)
    {
        selection = WAN_IFACE_ACTIVE;
    }

    if (WanMgr_StartWanVISM(pWanController->activeInterfaceIdx, selection) != 0)
    {
        CcspTraceError(("%s %d: Failed to start WAN for interface %d\n",
                        __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    return STATE_MULTIWAN_SELECTED_INTERFACE_UP;
}

/* Clear selection and restart SCANNING for a higher-priority candidate. */
static WcMwPolicyState_t Transition_RestartScan(WanMgr_Policy_Controller_t *pWanController)
{
    UINT uiLoopCount = 0;

    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL) ||
        (pWanController->GroupInst == 0))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    if (pWanController->pWanActiveIfaceData->data.Selection.Enable == TRUE)
    {
        pWanController->pWanActiveIfaceData->data.Selection.Status = WAN_IFACE_VALIDATING;
    }

    WanMgr_SetGroupSelectedIface(pWanController->GroupInst, 0);
    pWanController->InterfaceSelectionTimeOut = 0;
    pWanController->activeInterfaceIdx = -1;

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        BOOL inGroup = FALSE;

        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if (pWanController->GroupInst == pWanIfaceData->Selection.Group)
        {
            inGroup = TRUE;
            pWanIfaceData->Selection.ActiveLink = FALSE;
            if ((pWanIfaceData->Selection.Enable == TRUE) &&
                (pWanIfaceData->Selection.Timeout > pWanController->InterfaceSelectionTimeOut))
            {
                pWanController->InterfaceSelectionTimeOut = pWanIfaceData->Selection.Timeout;
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

        if (inGroup == TRUE)
        {
            DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE);
        }
    }

    {
        WANMGR_IFACE_GROUP *pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(pWanController->GroupInst - 1);
        if (pWanIfaceGroup != NULL)
        {
            pWanIfaceGroup->ResetSelectedInterface = FALSE;
            pWanController->ResetSelectedInterface = FALSE;
            WanMgrDml_GetIfaceGroup_release();
        }
    }

    CcspTraceInfo(("%s %d: Restarting scan, timeout %u\n", __FUNCTION__, __LINE__,
                   pWanController->InterfaceSelectionTimeOut));
    memset(&(pWanController->SelectionTimeOutStart), 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &(pWanController->SelectionTimeOutStart)) != 0)
    {
        CcspTraceError(("%s %d: clock_gettime failed\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    return STATE_MULTIWAN_SCANNING_INTERFACE;
}

/* Stop all group VISMs and enter INTERFACE_TEAR_DOWN. */
static WcMwPolicyState_t Transition_TearingDown(WanMgr_Policy_Controller_t *pWanController)
{
    UINT uiLoopCount = 0;

    if ((pWanController == NULL) || (pWanController->GroupInst == 0))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        BOOL inGroup = FALSE;
        BOOL clearActiveLink = FALSE;

        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if (pWanController->GroupInst == pWanIfaceData->Selection.Group)
        {
            inGroup = TRUE;
            if ((pWanIfaceData->VirtIfList != NULL) &&
                (pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_INVALID))
            {
                pWanIfaceData->VirtIfList->Status = WAN_IFACE_STATUS_DISABLED;
            }
            if (pWanController->GroupCfgChanged == TRUE)
            {
                pWanIfaceData->Selection.ActiveLink = FALSE;
                clearActiveLink = TRUE;
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

        if (inGroup == TRUE)
        {
            WanMgr_StopWanVISM((int)uiLoopCount);
            if (clearActiveLink == TRUE)
            {
                DmlSetWanActiveLinkInPSMDB(uiLoopCount, FALSE);
            }
        }
    }

    WanMgr_SetGroupSelectedIface(pWanController->GroupInst, 0);
    return STATE_MULTIWAN_INTERFACE_TEAR_DOWN;
}

/* Trigger platform reboot when selected iface RequiresReboot. */
static WcMwPolicyState_t Transition_Reboot(WanMgr_Policy_Controller_t *pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    CcspTraceInfo(("%s %d: MultiWAN triggering reboot\n", __FUNCTION__, __LINE__));
    Wanmgr_TriggerReboot();
    return STATE_MULTIWAN_REBOOT;
}

/* Scan group ifaces by priority; start VISM or select when ready/timeout. */
static WcMwPolicyState_t State_ScanningInterface(WanMgr_Policy_Controller_t *pWanController)
{
    INT highPriorityValidIface = -1;
    INT highPriorityValue = MAX_PRIORITY_VALUE;
    INT highPriorityActiveValue = MAX_PRIORITY_VALUE;
    UINT maxScanTimeout = 0;
    BOOL betterPriorityPending = FALSE;
    struct timespec currentTime;
    UINT uiLoopCount = 0;

    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    if ((pWanController->WanEnable == FALSE) || (pWanController->GroupCfgChanged == TRUE))
    {
        CcspTraceInfo(("%s %d: Tearing down MultiWAN selection\n", __FUNCTION__, __LINE__));
        return Transition_TearingDown(pWanController);
    }

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if ((pWanController->GroupInst == pWanIfaceData->Selection.Group) &&
            (pWanIfaceData->Selection.Enable == TRUE))
        {
            if (pWanIfaceData->Selection.Priority <= highPriorityValue)
            {
                highPriorityValidIface = (INT)uiLoopCount;
                highPriorityValue = pWanIfaceData->Selection.Priority;
            }

            if ((pWanIfaceData->VirtIfList != NULL) &&
                ((pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_UP) ||
                 (pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_STANDBY) ||
                 (pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_VALID)) &&
                (pWanIfaceData->Selection.Priority <= highPriorityActiveValue))
            {
                pWanController->activeInterfaceIdx = (INT)uiLoopCount;
                highPriorityActiveValue = pWanIfaceData->Selection.Priority;
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if ((pWanController->GroupInst == pWanIfaceData->Selection.Group) &&
            (pWanIfaceData->Selection.Enable == TRUE) &&
            (pWanIfaceData->Selection.Priority < highPriorityActiveValue) &&
            (pWanIfaceData->Selection.Timeout > maxScanTimeout))
        {
            maxScanTimeout = pWanIfaceData->Selection.Timeout;
            betterPriorityPending = TRUE;
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    if (betterPriorityPending == TRUE)
    {
        pWanController->InterfaceSelectionTimeOut = maxScanTimeout;
    }

    memset(&currentTime, 0, sizeof(currentTime));
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &currentTime) != 0)
    {
        CcspTraceError(("%s %d: clock_gettime failed\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_SCANNING_INTERFACE;
    }

    if ((highPriorityValidIface != -1) && (pWanController->activeInterfaceIdx != -1))
    {
        if (highPriorityValidIface == pWanController->activeInterfaceIdx)
        {
            CcspTraceInfo(("%s %d: Selecting highest priority interface %d\n",
                           __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
            return Transition_SelectingInterface(pWanController);
        }

        if (difftime(currentTime.tv_sec, pWanController->SelectionTimeOutStart.tv_sec) >
            (double)pWanController->InterfaceSelectionTimeOut)
        {
            WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked((UINT)highPriorityValidIface);
            CcspTraceInfo(("%s %d: Selection timeout %u expired. Selecting interface %d\n",
                           __FUNCTION__, __LINE__, pWanController->InterfaceSelectionTimeOut,
                           pWanController->activeInterfaceIdx));
            if (pWanDmlIfaceData != NULL)
            {
                if (pWanDmlIfaceData->data.VirtIfList != NULL)
                {
                    WanMgr_ProcessTelemetryMarker(pWanDmlIfaceData->data.VirtIfList,
                                                  WAN_WARN_IP_OBTAIN_TIMER_EXPIRED);
                }
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            }
            return Transition_SelectingInterface(pWanController);
        }

        pWanController->activeInterfaceIdx = -1;
    }

    for (uiLoopCount = 0; uiLoopCount < pWanController->TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        BOOL startSm = FALSE;
        char displayName[BUFLEN_64] = {0};

        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanIfaceData = &(pWanDmlIfaceData->data);
        if ((pWanController->GroupInst == pWanIfaceData->Selection.Group) &&
            (pWanIfaceData->Selection.Enable == TRUE) &&
            (pWanIfaceData->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP) &&
            (pWanIfaceData->VirtIfList != NULL) &&
            (pWanIfaceData->VirtIfList->Status == WAN_IFACE_STATUS_DISABLED) &&
            (pWanIfaceData->VirtIfList->Interface_SM_Running == FALSE) &&
            (pWanIfaceData->Selection.Priority <= highPriorityActiveValue))
        {
            startSm = TRUE;
            snprintf(displayName, sizeof(displayName), "%s", pWanIfaceData->DisplayName);
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

        if (startSm == TRUE)
        {
            CcspTraceInfo(("%s %d: Link up on %s id(%u). Starting interface state machine\n",
                           __FUNCTION__, __LINE__, displayName, uiLoopCount));
            return Transition_NewInterfaceConnected((INT)uiLoopCount);
        }
    }

    return STATE_MULTIWAN_SCANNING_INTERFACE;
}

/* After select: tear down, reboot, or proceed to SELECTED_INTERFACE_UP. */
static WcMwPolicyState_t State_CheckReconfiguration(WanMgr_Policy_Controller_t *pWanController)
{
    DML_WAN_IFACE *pActiveInterface = NULL;

    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    if ((pWanController->WanEnable == FALSE) || (pWanController->GroupCfgChanged == TRUE))
    {
        return Transition_TearingDown(pWanController);
    }

    pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if (pActiveInterface->Selection.RequiresReboot == TRUE)
    {
        return Transition_Reboot(pWanController);
    }

    return Transition_InterfaceSelected(pWanController);
}

/* Hold selected iface UP; handle rescan, PHY down, or VirtIfChanged. */
static WcMwPolicyState_t State_SelectedInterfaceUp(WanMgr_Policy_Controller_t *pWanController)
{
    DML_WAN_IFACE *pActiveInterface = NULL;

    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    if ((pWanController->WanEnable == FALSE) || (pWanController->GroupCfgChanged == TRUE))
    {
        return Transition_TearingDown(pWanController);
    }

    if ((pWanController->ResetSelectedInterface == TRUE) &&
        (WanMgr_CheckRescanRequired(pWanController) == TRUE))
    {
        return Transition_RestartScan(pWanController);
    }

    pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if ((pActiveInterface->BaseInterfaceStatus != WAN_IFACE_PHY_STATUS_UP) ||
        (pActiveInterface->Selection.Enable == FALSE))
    {
        return Transition_SelectedInterfaceDown(pWanController);
    }

    if (pActiveInterface->VirtIfChanged == TRUE)
    {
        if (WanMgr_StartWanVISM(pWanController->activeInterfaceIdx,
                                (pActiveInterface->Selection.Status == WAN_IFACE_ACTIVE) ?
                                WAN_IFACE_ACTIVE : WAN_IFACE_SELECTED) != 0)
        {
            CcspTraceError(("%s %d: Failed to start WAN for interface %d\n",
                            __FUNCTION__, __LINE__, pWanController->activeInterfaceIdx));
            return STATE_MULTIWAN_POLICY_ERROR;
        }
        pActiveInterface->VirtIfChanged = FALSE;
    }

    return STATE_MULTIWAN_SELECTED_INTERFACE_UP;
}

/* Wait for VISM stop; restore on PHY up or restart scan if disabled. */
static WcMwPolicyState_t State_SelectedInterfaceDown(WanMgr_Policy_Controller_t *pWanController)
{
    DML_WAN_IFACE *pActiveInterface = NULL;

    if ((pWanController == NULL) || (pWanController->pWanActiveIfaceData == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    if ((pWanController->WanEnable == FALSE) || (pWanController->GroupCfgChanged == TRUE))
    {
        return Transition_TearingDown(pWanController);
    }

    pActiveInterface = &(pWanController->pWanActiveIfaceData->data);
    if ((pActiveInterface->VirtIfList != NULL) &&
        (pActiveInterface->VirtIfList->Status != WAN_IFACE_STATUS_DISABLED))
    {
        return STATE_MULTIWAN_SELECTED_INTERFACE_DOWN;
    }

    if ((pActiveInterface->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP) &&
        (pActiveInterface->Selection.Enable == TRUE))
    {
        return Transition_SelectedInterfaceUp(pWanController);
    }

    if ((pActiveInterface->Selection.Enable == FALSE) ||
        (pWanController->ResetSelectedInterface == TRUE))
    {
        return Transition_RestartScan(pWanController);
    }

    return STATE_MULTIWAN_SELECTED_INTERFACE_DOWN;
}

/* Idle in REBOOT after Wanmgr_TriggerReboot(). */
static WcMwPolicyState_t State_Reboot(WanMgr_Policy_Controller_t *pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    return STATE_MULTIWAN_REBOOT;
}

/* Wait until group VirtIf SMs stop, then exit policy thread. */
static WcMwPolicyState_t State_InterfaceTearDown(WanMgr_Policy_Controller_t *pWanController)
{
    if (pWanController == NULL)
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return STATE_MULTIWAN_POLICY_ERROR;
    }

    if (WanMgr_GroupVirtIfSmRunning(pWanController) == FALSE)
    {
        return STATE_MULTIWAN_POLICY_EXIT;
    }

    return STATE_MULTIWAN_INTERFACE_TEAR_DOWN;
}

/* MultiWAN selection SM thread entry; arg is group instance (1-based). */
void *WanMgr_MultiWanSelectionProcess(void *arg)
{
    unsigned long groupInst   = (unsigned long)arg;
    BOOL bRunning             = true;
    WanMgr_Policy_Controller_t WanController;
    WcMwPolicyState_t mwState = STATE_MULTIWAN_POLICY_ERROR;
    struct timeval tv;
    INT n                     = 0;

    if (groupInst == 0)
    {
        CcspTraceError(("%s %d: Invalid group instance\n", __FUNCTION__, __LINE__));
        return NULL;
    }

    if (WanMgr_Controller_PolicyCtrlInit(&WanController) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d: Policy controller init failed\n", __FUNCTION__, __LINE__));
        WanMgr_MarkGroupStopped((UINT)groupInst);
        return NULL;
    }

    WanController.GroupInst = (UINT)groupInst;
    pthread_detach(pthread_self());
    WanMgr_UpdateControllerData(&WanController);

    CcspTraceInfo(("%s %d: MultiWAN selection thread starting for group %u\n",
                   __FUNCTION__, __LINE__, WanController.GroupInst));

    mwState = Transition_Start(&WanController);

    while (bRunning == true)
    {
        tv.tv_sec = 0;
        tv.tv_usec = SELECTION_PROCESS_LOOP_TIMEOUT;
        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            continue;
        }

        WanMgr_UpdateControllerData(&WanController);

        if ((WanController.activeInterfaceIdx != -1) && (WanController.pWanActiveIfaceData == NULL))
        {
            WanController.pWanActiveIfaceData = WanMgr_GetIfaceData_locked((UINT)WanController.activeInterfaceIdx);
        }

        switch (mwState)
        {
            case STATE_MULTIWAN_SCANNING_INTERFACE:
                mwState = State_ScanningInterface(&WanController);
                break;
            case STATE_MULTIWAN_CHECK_RECONFIGURATION:
                mwState = State_CheckReconfiguration(&WanController);
                break;
            case STATE_MULTIWAN_REBOOT:
                mwState = State_Reboot(&WanController);
                break;
            case STATE_MULTIWAN_SELECTED_INTERFACE_UP:
                mwState = State_SelectedInterfaceUp(&WanController);
                break;
            case STATE_MULTIWAN_SELECTED_INTERFACE_DOWN:
                mwState = State_SelectedInterfaceDown(&WanController);
                break;
            case STATE_MULTIWAN_INTERFACE_TEAR_DOWN:
                mwState = State_InterfaceTearDown(&WanController);
                break;
            case STATE_MULTIWAN_POLICY_EXIT:
                bRunning = false;
                break;
            case STATE_MULTIWAN_POLICY_ERROR:
            default:
                CcspTraceError(("%s %d: MultiWAN policy error\n", __FUNCTION__, __LINE__));
                bRunning = false;
                break;
        }

        if (WanController.pWanActiveIfaceData != NULL)
        {
            WanMgrDml_GetIfaceData_release(WanController.pWanActiveIfaceData);
            WanController.pWanActiveIfaceData = NULL;
        }
    }

    if (WanController.GroupCfgChanged == TRUE)
    {
        WanMgr_Config_Data_t *pWanConfigData = WanMgr_GetConfigData_locked();
        if (pWanConfigData != NULL)
        {
            pWanConfigData->data.ResetFailOverScan = TRUE;
            WanMgrDml_GetConfigData_release(pWanConfigData);
        }
    }

    WanMgr_MarkGroupStopped(WanController.GroupInst);
    CcspTraceInfo(("%s %d: MultiWAN selection thread exit for group %u\n",
                   __FUNCTION__, __LINE__, WanController.GroupInst));
    return NULL;
}
