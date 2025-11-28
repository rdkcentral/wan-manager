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
    {
        return ANSC_STATUS_FAILURE;
    }

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
        WanMgr_SysCfgGetStr(key, cfg.EndpointName, sizeof(cfg.EndpointName));

        snprintf(key, sizeof(key), "dslite_addr_ipv6_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.EndpointAddr, sizeof(cfg.EndpointAddr));

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

ANSC_STATUS WanMgr_DSLite_HandleConfigChange(UINT inst)
{
    DML_DSLITE_LIST *entry;
    DML_VIRTUAL_IFACE *p_VirtIf;
    DML_DSLITE_CONFIG *prev, *curr;

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
    {
        return ANSC_STATUS_FAILURE;
    }

    prev = &entry->PrevCfg;
    curr = &entry->CurrCfg;

    p_VirtIf = WanMgr_GetVirtIfDataByDSLiteAlias_locked(curr->Alias);
    if (!p_VirtIf)
    {
        WanMgr_GetDSLiteData_release();
        return ANSC_STATUS_SUCCESS;  /* Not mapped to any VirtIf, nothing to do */
    }

    /* Check if any user-configurable fields changed (excludes runtime fields like Status, AddrInUse, etc.) */
    if (prev->Enable != curr->Enable ||
        strcmp(prev->Alias, curr->Alias) != 0 ||
        prev->Mode != curr->Mode ||
        prev->Type != curr->Type ||
        strcmp(prev->EndpointName, curr->EndpointName) != 0 ||
        strcmp(prev->EndpointAddr, curr->EndpointAddr) != 0 ||
        strcmp(prev->TunnelV4Addr, curr->TunnelV4Addr) != 0 ||
        prev->MssClampingEnable != curr->MssClampingEnable ||
        prev->TcpMss != curr->TcpMss ||
        prev->Ipv6FragEnable != curr->Ipv6FragEnable)
    {
        /* Trigger state machine reconfiguration */
        p_VirtIf->DSLite.Changed = TRUE;
        CcspTraceInfo(("%s: DSLite entry %lu config changed, triggering VirtIf %s reconfiguration\n",
                      __FUNCTION__, inst, p_VirtIf->Name));
    }

    *prev = *curr;

    WanMgr_VirtualIfaceData_release(p_VirtIf);
    WanMgr_GetDSLiteData_release();

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_DSLite_SaveMainConfig(void)
{
    WanMgr_DSLite_Data_t *pDSLiteData;
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;

    pDSLiteData = WanMgr_GetDSLiteData_locked();
    if (!pDSLiteData)
    {
        return ANSC_STATUS_FAILURE;
    }

    if (pDSLiteData->Changed)
    {
        CcspTraceInfo(("%s: Writing DSLite main config to sysCfg\n", __FUNCTION__));

        if (WanMgr_SysCfgSetUint("dslite_next_insNum", pDSLiteData->NextInstanceNumber) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set dslite_next_instance_number in syscfg\n", __FUNCTION__));
            ret = ANSC_STATUS_FAILURE;
        }
        if (WanMgr_SysCfgSetUint("dslite_count", pDSLiteData->InterfaceSettingNumberOfEntries) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set dslite_count in syscfg\n", __FUNCTION__));
            ret = ANSC_STATUS_FAILURE;
        }
        if (WanMgr_SysCfgSetUint("dslite_enable", pDSLiteData->Enable ? 1 : 0) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set dslite_enable in syscfg\n", __FUNCTION__));
            ret = ANSC_STATUS_FAILURE;
        }
        pDSLiteData->Changed = FALSE;
        if (syscfg_commit() != 0)
        {
            CcspTraceError(("%s: syscfg_commit() failed\n", __FUNCTION__));
            ret = ANSC_STATUS_FAILURE;
        }
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

ANSC_STATUS WanMgr_DSLite_SaveEntryConfig(UINT inst)
{
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;
    DML_DSLITE_CONFIG *prev, *curr;
    DML_DSLITE_LIST *entry;
    char key[BUFLEN_64];

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
    {
        return ANSC_STATUS_FAILURE;
    }

    prev = &entry->PrevCfg;
    curr = &entry->CurrCfg;

    if (!entry->New && memcmp(prev, curr, sizeof(*prev)) == 0)
    {
        /* Nothing changed.. Returning */
        WanMgr_GetDSLiteData_release();
        return ANSC_STATUS_SUCCESS;
    }

    CcspTraceInfo(("%s: Writing DSLite entry with InsNum=%lu to sysCfg\n", __FUNCTION__, inst));

    if (entry->New)
    {
        snprintf(key, sizeof(key), "dslite_InsNum_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, inst) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || prev->Enable != curr->Enable)
    {
        snprintf(key, sizeof(key), "dslite_active_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, curr->Enable ? 1 : 0) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || strcmp(prev->Alias, curr->Alias) != 0)
    {
        snprintf(key, sizeof(key), "dslite_alias_%lu", inst);
        if (WanMgr_SysCfgSetStr(key, curr->Alias) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || prev->Mode != curr->Mode)
    {
        snprintf(key, sizeof(key), "dslite_mode_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, curr->Mode) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || prev->Type != curr->Type)
    {
        snprintf(key, sizeof(key), "dslite_addr_type_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, curr->Type) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || strcmp(prev->EndpointName, curr->EndpointName) != 0)
    {
        snprintf(key, sizeof(key), "dslite_addr_fqdn_%lu", inst);
        if (WanMgr_SysCfgSetStr(key, curr->EndpointName) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || strcmp(prev->EndpointAddr, curr->EndpointAddr) != 0)
    {
        snprintf(key, sizeof(key), "dslite_addr_ipv6_%lu", inst);
        if (WanMgr_SysCfgSetStr(key, curr->EndpointAddr) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || prev->MssClampingEnable != curr->MssClampingEnable)
    {
        snprintf(key, sizeof(key), "dslite_mss_clamping_enable_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, curr->MssClampingEnable ? 1 : 0) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || prev->TcpMss != curr->TcpMss)
    {
        snprintf(key, sizeof(key), "dslite_tcpmss_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, curr->TcpMss) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || prev->Ipv6FragEnable != curr->Ipv6FragEnable)
    {
        snprintf(key, sizeof(key), "dslite_ipv6_frag_enable_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, curr->Ipv6FragEnable ? 1 : 0) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (entry->New || strcmp(prev->TunnelV4Addr, curr->TunnelV4Addr) != 0)
    {
        snprintf(key, sizeof(key), "dslite_tunnel_v4addr_%lu", inst);
        if (WanMgr_SysCfgSetStr(key, curr->TunnelV4Addr) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    /* Update DSLite tunnel syscfg parameters only if values changed */
    if (prev->Status != curr->Status)
    {
        snprintf(key, sizeof(key), "dslite_status_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, curr->Status) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (strcmp(prev->AddrInUse, curr->AddrInUse) != 0)
    {
        snprintf(key, sizeof(key), "dslite_addr_inuse_%lu", inst);
        if (WanMgr_SysCfgSetStr(key, curr->AddrInUse) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (prev->Origin != curr->Origin)
    {
        snprintf(key, sizeof(key), "dslite_origin_%lu", inst);
        if (WanMgr_SysCfgSetUint(key, curr->Origin) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (strcmp(prev->TunnelIface, curr->TunnelIface) != 0)
    {
        snprintf(key, sizeof(key), "dslite_tunnel_interface_%lu", inst);
        if (WanMgr_SysCfgSetStr(key, curr->TunnelIface) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (strcmp(prev->TunneledIface, curr->TunneledIface) != 0)
    {
        snprintf(key, sizeof(key), "dslite_tunneled_interface_%lu", inst);
        if (WanMgr_SysCfgSetStr(key, curr->TunneledIface) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: Failed to set %s\n", __FUNCTION__, key));
            goto error;
        }
    }

    if (syscfg_commit() != 0)
    {
        CcspTraceError(("%s: syscfg_commit() failed\n", __FUNCTION__));
        goto error;
    }

    entry->New = FALSE;
    WanMgr_GetDSLiteData_release();
    return ANSC_STATUS_SUCCESS;

error:
    WanMgr_GetDSLiteData_release();
    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS WanMgr_DSLite_DeleteEntryConfig(ULONG inst)
{
    char key[BUFLEN_64];
    int rc = 0;

    const char *fields[] = {
        "dslite_InsNum_%lu",
        "dslite_active_%lu",
        "dslite_alias_%lu",
        "dslite_mode_%lu",
        "dslite_addr_type_%lu",
        "dslite_addr_fqdn_%lu",
        "dslite_addr_ipv6_%lu",
        "dslite_mss_clamping_enable_%lu",
        "dslite_tcpmss_%lu",
        "dslite_ipv6_frag_enable_%lu",
        "dslite_tunnel_v4addr_%lu"
    };

    for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); i++)
    {
        snprintf(key, sizeof(key), fields[i], inst);
        if (syscfg_unset(NULL, key) != 0)
        {
            CcspTraceError(("%s: syscfg_unset(%s) failed\n",
                            __FUNCTION__, key));
            rc = -1;
        }
    }

    if (syscfg_commit() != 0)
    {
        CcspTraceError(("%s: syscfg_commit() failed\n", __FUNCTION__));
        rc = -1;
    }

    return (rc == 0) ? ANSC_STATUS_SUCCESS : ANSC_STATUS_FAILURE;
}

bool WanMgr_DSLite_isEndpointNameChanged(DML_VIRTUAL_IFACE* pVirtIf, const char* newEndpoint)
{
    DML_DSLITE_LIST *entry;
    bool changed = false;

    if (!newEndpoint || !pVirtIf)
    {
        return false;
    }

    entry = WanMgr_getDSLiteEntryByAlias_locked(pVirtIf->DSLite.Path);
    if (!entry)
    {
        return false;
    }
    changed = (strcasecmp(entry->CurrCfg.EndpointName, newEndpoint) != 0);

    WanMgr_GetDSLiteData_release();
    return changed;
}

void WanMgr_DSLite_UpdateEndPointName(DML_VIRTUAL_IFACE* pVirtIf, const char* newEndpoint)
{
    DML_DSLITE_LIST *entry;

    if (!newEndpoint || !pVirtIf)
    {
        return;
    }

    entry = WanMgr_getDSLiteEntryByAlias_locked(pVirtIf->DSLite.Path);
    if (!entry)
    {
        return;
    }

    strncpy(entry->CurrCfg.EndpointName, newEndpoint, sizeof(entry->CurrCfg.EndpointName) - 1);
    entry->CurrCfg.EndpointName[sizeof(entry->CurrCfg.EndpointName) - 1] = '\0';

    WanMgr_GetDSLiteData_release();
    return;
}

bool WanMgr_DSLite_isEndpointAssigned(DML_VIRTUAL_IFACE *pVirtIf)
{
    DML_DSLITE_LIST *entry;
    bool assigned = false;

    entry = WanMgr_getDSLiteEntryByAlias_locked(pVirtIf->DSLite.Path);
    if (!entry)
    {
        return false;
    }

    if (entry->CurrCfg.Mode == DSLITE_ENDPOINT_DHCPV6)
    {
        assigned = !IS_EMPTY_STRING(entry->CurrCfg.EndpointName);
    }
    else if (entry->CurrCfg.Mode == DSLITE_ENDPOINT_STATIC)
    {
        if (entry->CurrCfg.Type == DSLITE_ENDPOINT_FQDN)
        {
            assigned = !IS_EMPTY_STRING(entry->CurrCfg.EndpointName);
        }
        else if (entry->CurrCfg.Type == DSLITE_ENDPOINT_IPV6ADDRESS)
        {
            assigned = !IS_EMPTY_STRING(entry->CurrCfg.EndpointAddr);
        }
    }

    WanMgr_GetDSLiteData_release();
    return assigned;
}