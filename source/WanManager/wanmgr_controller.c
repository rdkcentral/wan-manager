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

#include "ansc_platform.h"
#include "wanmgr_controller.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_data.h"
#include "secure_wrapper.h"

/* WanController_Init_StateMachine */
ANSC_STATUS WanController_Init_StateMachine(void)
{
    BOOLEAN WanEnable = TRUE;
    // event handler
    int n = 0;
    struct timeval tv;
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__ ));
    while(1)
    {
        /* Wait up to 500 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }
        //Get Policy
        WanMgr_Config_Data_t* pWanConfigData = WanMgr_GetConfigData_locked();
        if(pWanConfigData != NULL)
        {
            DML_WANMGR_CONFIG* pWanConfig = &(pWanConfigData->data);
            WanEnable = pWanConfig->Enable;
            WanMgrDml_GetConfigData_release(pWanConfigData);
        }
        if(WanEnable == FALSE)
        {
            continue;
        }
#if 0
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)) && !defined(WAN_MANAGER_UNIFICATION_ENABLED)
        CcspTraceInfo(("%s %d Starting Comcast WanMgr_Policy_AutoWan \n", __FUNCTION__, __LINE__));
        WanMgr_Policy_AutoWan();
#else
        /* Start Fail Over */
        WanMgr_FailOverThread();
#endif
#endif

    }
    return ANSC_STATUS_SUCCESS;
}
ANSC_STATUS WanMgr_Controller_PolicyCtrlInit(WanMgr_Policy_Controller_t* pWanPolicyCtrl)
{
    ANSC_STATUS retStatus = ANSC_STATUS_FAILURE;

    if(pWanPolicyCtrl != NULL)
    {
        pWanPolicyCtrl->WanEnable = FALSE;
        pWanPolicyCtrl->activeInterfaceIdx = -1;
        pWanPolicyCtrl->selSecondaryInterfaceIdx = -1;
        pWanPolicyCtrl->pWanActiveIfaceData = NULL;
        memset(&(pWanPolicyCtrl->SelectionTimeOutStart), 0, sizeof(struct timespec));
        memset(&(pWanPolicyCtrl->SelectionTimeOutEnd), 0, sizeof(struct timespec));
        pWanPolicyCtrl->InterfaceSelectionTimeOut = 0;
        pWanPolicyCtrl->TotalIfaces = 0;
        pWanPolicyCtrl->WanOperationalMode = -1;
        pWanPolicyCtrl->GroupIfaceList = 0;
        pWanPolicyCtrl->GroupInst = 0;
        pWanPolicyCtrl->GroupCfgChanged = FALSE;
        pWanPolicyCtrl->ResetSelectedInterface = FALSE;
        retStatus = ANSC_STATUS_SUCCESS;
    }

   return retStatus;
}
