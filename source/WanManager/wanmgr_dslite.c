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

#include "wanmgr_dml_dslite_apis.h"
#include "wanmgr_dslite.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_data.h"

/* Get whole DSLite conf from syscfg */
ANSC_STATUS WanMgr_DSLiteInit(void)
{
    WanMgr_DSLite_Data_t *pDSLiteData;
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;

    pDSLiteData = WanMgr_GetDSLiteData_locked();
    if (!pDSLiteData)
        return ANSC_STATUS_FAILURE;

    memset(pDSLiteData, 0, sizeof(*pDSLiteData));

    /* Device.DSLite.Enable */
    WanMgr_SysCfgGetBool("dslite_enable", &pDSLiteData->Enable);
    WanMgr_SysCfgGetUint("dslite_count", &pDSLiteData->InterfaceSettingNumberOfEntries);
    if (WanMgr_SysCfgGetUint("dslite_next_insNum", &pDSLiteData->NextInstanceNumber) != ANSC_STATUS_SUCCESS)
    {
        /* assume InterfaceSettingNumberOfEntries + 1 */
        pDSLiteData->NextInstanceNumber = pDSLiteData->InterfaceSettingNumberOfEntries + 1;
    }

    for (UINT insNum = 1; insNum < pDSLiteData->NextInstanceNumber; insNum++)
    {
        DML_DSLITE_LIST *entry;
        char key[BUFLEN_64];
        UINT tmp = 0;

        snprintf(key, sizeof(key), "dslite_InsNum_%d", insNum);
        ret = WanMgr_SysCfgGetUint(key, &tmp);
        if (ret != ANSC_STATUS_SUCCESS || tmp == 0)
        {
            /* Find existing DSLite configs by the insNum field */
            continue;
        }

        /* Sanity Check */
        if (tmp != insNum)
        {
            CcspTraceError(("%s: syscfg_get(%s) returned mismatched insNum %lu (expected %d), skipping\n",
                              __FUNCTION__, key, tmp, insNum));
            continue;
        }

        entry = (DML_DSLITE_LIST *)AnscAllocateMemory(sizeof(DML_DSLITE_LIST));
        if (!entry)
        {
            CcspTraceError(("%s: Allocation failed for DML_DSLITE_LIST (insNum=%d)\n", __FUNCTION__, insNum));
            ret = ANSC_STATUS_RESOURCES;
            break;
        }
        entry->InstanceNumber = insNum;

        DML_DSLITE_CONFIG cfg;
        DSLITE_SET_DEFAULTVALUE(&cfg);  /* start from known defaults */

        snprintf(key, sizeof(key), "dslite_active_%d", insNum);
        WanMgr_SysCfgGetBool(key, &cfg.Enable);

        snprintf(key, sizeof(key), "dslite_alias_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.Alias, sizeof(cfg.Alias));

        snprintf(key, sizeof(key), "dslite_mode_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.Mode);

        snprintf(key, sizeof(key), "dslite_addr_type_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.Type);

        snprintf(key, sizeof(key), "dslite_addr_fqdn_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.AddrFqdn, sizeof(cfg.AddrFqdn));

        snprintf(key, sizeof(key), "dslite_addr_ipv6_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.AddrIPv6, sizeof(cfg.AddrIPv6));

        snprintf(key, sizeof(key), "dslite_mss_clamping_enable_%d", insNum);
        WanMgr_SysCfgGetBool(key, &cfg.MssClampingEnable);

        snprintf(key, sizeof(key), "dslite_tcpmss_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.TcpMss);

        snprintf(key, sizeof(key), "dslite_ipv6_frag_enable_%d", insNum);
        WanMgr_SysCfgGetBool(key, &cfg.Ipv6FragEnable);

        snprintf(key, sizeof(key), "dslite_status_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.Status);

        snprintf(key, sizeof(key), "dslite_addr_inuse_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.AddrInUse, sizeof(cfg.AddrInUse));

        snprintf(key, sizeof(key), "dslite_origin_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.Origin);

        snprintf(key, sizeof(key), "dslite_tunnel_interface_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.TunnelIface, sizeof(cfg.TunnelIface));

        snprintf(key, sizeof(key), "dslite_tunneled_interface_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.TunneledIface, sizeof(cfg.TunneledIface));

        snprintf(key, sizeof(key), "dslite_tunnel_v4addr_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.TunnelV4Addr, sizeof(cfg.TunnelV4Addr));

        entry->PrevCfg          = cfg;
        entry->CurrCfg          = cfg;
        entry->next             = pDSLiteData->DSLiteList;
        pDSLiteData->DSLiteList = entry;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

