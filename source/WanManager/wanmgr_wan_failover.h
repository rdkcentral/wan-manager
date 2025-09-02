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

#ifndef _WANMGR_WAN_FAILOVER_H_
#define _WANMGR_WAN_FAILOVER_H_

#include "wanmgr_rdkbus_common.h"
#include "wanmgr_controller.h"
#include "wanmgr_data.h"
#include "wanmgr_rdkbus_utils.h"

typedef enum TelemetryEvents
{
    WAN_FAILOVER_SUCCESS = 1,
    WAN_FAILOVER_FAIL,
    WAN_RESTORE_SUCCESS,
    WAN_RESTORE_FAIL,
}TelemetryEvent_t;

typedef  struct _WANMGR_FAILOVER_CONTROLLER_
{
    BOOL                    WanEnable;
    FAILOVER_TYPE           FailOverType;
    UINT                    CurrentActiveGroup;
    UINT                    HighestValidGroup;
    struct timespec         GroupSelectionTimer;
    struct timespec         FailOverTimer;
    UINT                    RestorationDelay;
    BOOL                    ResetScan;
    DML_WAN_IFACE_PHY_STATUS PhyState;
    eWanState_t             ActiveIfaceState;
    TelemetryEvent_t        TelemetryEvent; 
    BOOL                    AllowRemoteInterfaces;
    BOOL                    DisableAutoRouting;
    BOOL                    InitialScanCompleted;
} WanMgr_FailOver_Controller_t;


typedef enum {
    STATE_FAILOVER_SCANNING_GROUP = 0,
    STATE_FAILOVER_GROUP_ACTIVE,
    STATE_FAILOVER_RESTORATION_WAIT,
    STATE_FAILOVER_DEACTIVATE_GROUP,
    STATE_FAILOVER_IDLE_MONITOR,
    STATE_FAILOVER_EXIT,
    STATE_FAILOVER_ERROR,
} WcFailOverState_t;

int WanMgr_SetGroupSelectedIface (UINT GroupInst, UINT IfaceInst);
void WanMgr_TelemetryEventTrigger(WanMgr_FailOver_Controller_t* pFailOverController);
#endif /* _WANMGR_WAN_FAILOVER_H_ */
