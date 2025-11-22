/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
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

#ifndef _WANMGR_DSLITE_H_
#define _WANMGR_DSLITE_H_

#include "ansc_platform.h"
#include "wanmgr_dml.h"
#include "wanmgr_net_utils.h"

#define DSLITE_SET_DEFAULTVALUE(__pCfg)                 \
    do                                                  \
    {                                                   \
        memset((__pCfg), 0, sizeof(*(__pCfg)));         \
        (__pCfg)->Enable = FALSE;                       \
        (__pCfg)->Status = WAN_IFACE_DSLITE_STATE_DOWN; \
        (__pCfg)->Mode = DSLITE_ENDPOINT_DHCPV6;        \
        (__pCfg)->Type = DSLITE_ENDPOINT_IPV6ADDRESS;   \
        (__pCfg)->Origin = DSLITE_ENDPOINT_DHCPV6;      \
        (__pCfg)->TcpMss = 1420;                        \
    } while (0)

/* DSLite initialization */
ANSC_STATUS WanMgr_DSLiteInit(void);

/* DSLite configuration management */
ANSC_STATUS WanMgr_DSLite_SaveMainConfig(void);
ANSC_STATUS WanMgr_DSLite_SaveEntryConfig(UINT inst);
ANSC_STATUS WanMgr_DSLite_DeleteEntryConfig(ULONG inst);
ANSC_STATUS WanMgr_DSLite_HandleConfigChange(UINT inst);

/* DSLite endpoint name management */
void WanMgr_DSLite_UpdateEndPointName(DML_VIRTUAL_IFACE* pVirtIf, const char* newEndpoint);
bool WanMgr_DSLite_isEndpointNameChanged(DML_VIRTUAL_IFACE* pVirtIf, const char* newFqdn);
bool WanMgr_DSLite_isEndpointAssigned(DML_VIRTUAL_IFACE* pVirtIf);

/* DSLite tunnel management */
ANSC_STATUS WanMgr_DSLite_SetupTunnel(DML_VIRTUAL_IFACE *pVirtIf);
ANSC_STATUS WanMgr_DSLite_TeardownTunnel(DML_VIRTUAL_IFACE *pVirtIf);
void WanMgr_Dslite_AddIpRules(const char *if_name);
void WanMgr_Dslite_DelIpRules(const char *if_name, const char *wan_ipv4);

#endif /* _WANMGR_DSLITE_H_ */
