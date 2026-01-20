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

#ifndef _WANMGR_IPC_H_
#define _WANMGR_IPC_H_


#include "ansc_platform.h"
#include "ipc_msg.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_interface_sm.h"

#ifdef FEATURE_IPOE_HEALTH_CHECK
ANSC_STATUS WanMgr_SendMsgToIHC (ipoe_msg_type_t msgType, DML_VIRTUAL_IFACE *p_VirtIf);
#endif


ANSC_STATUS WanMgr_StartIpcServer(); /*IPC server to handle WAN Manager clients*/
ANSC_STATUS Wan_ForceRenewDhcpIPv6(char * ifName);
ANSC_STATUS WanMgr_SetInterfaceStatus(char *ifName, wanmgr_iface_status_t state);

#endif /*_WANMGR_IPC_H_*/
