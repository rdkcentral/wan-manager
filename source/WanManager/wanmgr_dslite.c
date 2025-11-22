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

#include <event2/event.h>
#include <event2/dns.h>

#include "wanmgr_dml_dslite_apis.h"
#include "wanmgr_dslite.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_data.h"
typedef struct
{
    struct event_base *base;
    struct in6_addr *result;
    int ttl;
} DSLITE_DNS_CTX;

static void Dslite_DnsCallback(int result, char type, int count, int ttl, void *addresses, void *arg)
{
    DSLITE_DNS_CTX *ctx = (DSLITE_DNS_CTX *)arg;

    if (!ctx)
    {
        return;
    }

    ctx->result = NULL;
    ctx->ttl = 0;

    if (result == DNS_ERR_NONE &&
        type == DNS_IPv6_AAAA &&
        count > 0 &&
        addresses != NULL)
    {
        ctx->result = (struct in6_addr *)malloc(sizeof(struct in6_addr));
        if (ctx->result)
        {
            memcpy(ctx->result, addresses, sizeof(struct in6_addr));
            ctx->ttl = ttl;
        }
    }

    if (ctx->base)
    {
        event_base_loopexit(ctx->base, NULL);
    }
}

static struct in6_addr *Dslite_ResolveFqdnToIpv6(const char *fqdn, unsigned int *dnsttl, const char *nameserver)
{
    struct event_base *evbase = NULL;
    struct evdns_base *dns_base = NULL;
    struct evdns_request *req = NULL;
    DSLITE_DNS_CTX ctx;
    struct in6_addr *ret = NULL;

    if (!fqdn || !nameserver)
    {
        return NULL;
    }

    memset(&ctx, 0, sizeof(ctx));

    evbase = event_base_new();
    if (!evbase)
    {
        return NULL;
    }
    ctx.base = evbase;

    dns_base = evdns_base_new(evbase, 0);
    if (!dns_base)
    {
        event_base_free(evbase);
        return NULL;
    }

    evdns_base_nameserver_ip_add(dns_base, nameserver);

    req = evdns_base_resolve_ipv6(dns_base, fqdn, DNS_QUERY_NO_SEARCH, Dslite_DnsCallback, &ctx);
    if (!req)
    {
        evdns_base_free(dns_base, 0);
        event_base_free(evbase);
        return NULL;
    }

    event_base_dispatch(evbase);

    if (ctx.result)
    {
        ret = ctx.result;
    }

    if (dnsttl)
    {
        *dnsttl = (ret ? (unsigned int)ctx.ttl : 0);
    }

    evdns_base_free(dns_base, 0);
    event_base_free(evbase);

    return ret;
}

/* Select AFTR value based on DSLite AFTR source (Mode) */
static int Dslite_GetEndpointInfo(const DML_DSLITE_CONFIG *cfg, char *endpointBuf, size_t endpointBufLen)
{
    const char *src = NULL;

    if (!cfg || !endpointBuf || endpointBufLen == 0)
    {
        CcspTraceError(("%s: Invalid input\n", __FUNCTION__));
        return -1;
    }

    endpointBuf[0] = '\0';

    /* DHCPv6 */
    if (cfg->Mode == DSLITE_ENDPOINT_DHCPV6)
    {
        src = cfg->EndpointName;
    }
    /* Static */
    else if (cfg->Mode == DSLITE_ENDPOINT_STATIC)
    {
        if (cfg->Type == DSLITE_ENDPOINT_FQDN)
        {
            src = cfg->EndpointName;
        }
        else if (cfg->Type == DSLITE_ENDPOINT_IPV6ADDRESS)
        {
            src = cfg->EndpointAddr;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        CcspTraceError(("%s: Invalid DSLite mode %d\n", __FUNCTION__, cfg->Mode));
        return -1;
    }

    if (IS_EMPTY_STRING(src) || strcmp(src, "none") == 0)
    {
        CcspTraceError(("%s: Endpoint is empty/none\n", __FUNCTION__));
        return -1;
    }

    snprintf(endpointBuf, endpointBufLen, "%s", src);

    return (int)cfg->Mode;
}

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

        snprintf(key, sizeof(key), "dslite_tunnel_interface_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.TunnelIface, sizeof(cfg.TunnelIface));

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

    /* Update DSLite tunnel syscfg parameter only if values changed */

    if (strcmp(prev->TunnelIface, curr->TunnelIface) != 0)
    {
        snprintf(key, sizeof(key), "dslite_tunnel_interface_%lu", inst);
        if (WanMgr_SysCfgSetStr(key, curr->TunnelIface) != ANSC_STATUS_SUCCESS)
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

void WanMgr_Dslite_AddIpRules(const char *if_name)
{
    char cmd[BUFLEN_256];

    if (IS_EMPTY_STRING(if_name))
    {
        return;
    }

    snprintf(cmd, sizeof(cmd),
             "ip rule add iif %s lookup all_lans; "
             "ip rule add oif %s lookup erouter",
             if_name,
             if_name);

    WanManager_DoSystemAction("WanMgr_Dslite_AddIpRules:", cmd);
}

void WanMgr_Dslite_DelIpRules(const char *if_name, const char *wan_ipv4)
{
    char cmd[BUFLEN_512];

    if (IS_EMPTY_STRING(if_name))
    {
        return;
    }

    if (!IS_EMPTY_STRING(wan_ipv4))
    {
        snprintf(cmd, sizeof(cmd),
                 "ip rule del from %s lookup all_lans; "
                 "ip rule del from %s lookup erouter; "
                 "ip rule del iif %s lookup all_lans; "
                 "ip rule del oif %s lookup erouter",
                 wan_ipv4,
                 wan_ipv4,
                 if_name,
                 if_name);
    }
    else
    {
        snprintf(cmd, sizeof(cmd),
                 "ip rule del iif %s lookup all_lans; "
                 "ip rule del oif %s lookup erouter",
                 if_name,
                 if_name);
    }

    WanManager_DoSystemAction("WanMgr_Dslite_DelIpRules:", cmd);
}

ANSC_STATUS WanMgr_DSLite_AddFirewallRules(UINT inst, const char *tunnelIf, const DML_DSLITE_CONFIG *cfg)
{
    if (!tunnelIf || !cfg)
    {
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s: Adding DSLite firewall rules for tunnel %s (inst %u)\n", __FUNCTION__, tunnelIf, inst));

    char rule[BUFLEN_256];
    char retbuf[BUFLEN_256];
    char key[BUFLEN_64];

    memset(retbuf, 0, sizeof(retbuf));
    snprintf(rule, sizeof(rule), "-I FORWARD -o %s -j ACCEPT\n", tunnelIf);

    sysevent_set_unique(sysevent_fd, sysevent_token, "GeneralPurposeFirewallRule", rule, retbuf, sizeof(retbuf));

    snprintf(key, sizeof(key), "dslite_rule_sysevent_id_%u_1", inst);
    sysevent_set(sysevent_fd, sysevent_token, key, retbuf, 0);

    memset(retbuf, 0, sizeof(retbuf));
    snprintf(rule, sizeof(rule), "-I FORWARD -i %s -j ACCEPT\n", tunnelIf);

    sysevent_set_unique(sysevent_fd, sysevent_token, "GeneralPurposeFirewallRule", rule, retbuf, sizeof(retbuf));

    snprintf(key, sizeof(key), "dslite_rule_sysevent_id_%u_2", inst);
    sysevent_set(sysevent_fd, sysevent_token, key, retbuf, 0);

    if (cfg->MssClampingEnable)
    {
        char rule_mss_out[BUFLEN_256];
        char rule_mss_in[BUFLEN_256];

        if ((cfg->TcpMss > 0) && (cfg->TcpMss <= 1460))
        {
            snprintf(rule_mss_out, sizeof(rule_mss_out), "-I FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %lu\n", tunnelIf, cfg->TcpMss);
            snprintf(rule_mss_in, sizeof(rule_mss_in), "-I FORWARD -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %lu\n", tunnelIf, cfg->TcpMss);
        }
        else
        {
            snprintf(rule_mss_out, sizeof(rule_mss_out), "-I FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n", tunnelIf);
            snprintf(rule_mss_in, sizeof(rule_mss_in), "-I FORWARD -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n", tunnelIf);
        }

        /* Apply MSS outbound rule */
        memset(retbuf, 0, sizeof(retbuf));
        sysevent_set_unique(sysevent_fd, sysevent_token, "GeneralPurposeMangleRule", rule_mss_out, retbuf, sizeof(retbuf));

        snprintf(key, sizeof(key), "dslite_rule_sysevent_id_%u_3", inst);
        sysevent_set(sysevent_fd, sysevent_token, key, retbuf, 0);

        /* Apply MSS inbound rule */
        memset(retbuf, 0, sizeof(retbuf));
        sysevent_set_unique(sysevent_fd, sysevent_token, "GeneralPurposeMangleRule", rule_mss_in, retbuf, sizeof(retbuf));

        snprintf(key, sizeof(key), "dslite_rule_sysevent_id_%u_4", inst);
        sysevent_set(sysevent_fd, sysevent_token, key, retbuf, 0);
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_DSLite_DeleteFirewallRules(UINT inst)
{
    CcspTraceInfo(("%s: Removing DSLite firewall rules (inst %u)\n", __FUNCTION__, inst));

    char key[BUFLEN_64];
    char rule_id[BUFLEN_64];

    for (int i = 1; i <= 4; i++)
    {
        snprintf(key, sizeof(key), "dslite_rule_sysevent_id_%u_%d", inst, i);

        memset(rule_id, 0, sizeof(rule_id));
        sysevent_get(sysevent_fd, sysevent_token, key, rule_id, sizeof(rule_id));

        if (rule_id[0] != '\0')
        {
            sysevent_set(sysevent_fd, sysevent_token, rule_id, "", 0);

            sysevent_set(sysevent_fd, sysevent_token, key, "", 0);
        }
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_DSLite_SetupTunnel(DML_VIRTUAL_IFACE *pVirtIf)
{
    UINT inst = 0;
    char tunnelIf[BUFLEN_64];
    char wan6_addr[BUFLEN_256];
    char dns_list[2][BUFLEN_256];
    int dns_count = 0;

    DML_DSLITE_LIST *entry = NULL;
    DML_DSLITE_CONFIG *cfg = NULL;

    char endpoint_buf[BUFLEN_256] = {0};
    char resolved_endpoint[BUFLEN_256] = {0};
    struct in6_addr tmpv6;
    struct in6_addr *addrp = NULL;
    unsigned int dns_ttl = 0;

    char tnl_ipv6[BUFLEN_64] = {0};
    char cmd_str[512];
    int mode = 0;

    if (!pVirtIf || !pVirtIf->DSLite.Path || !pVirtIf->Name)
    {
        CcspTraceError(("%s: Invalid input\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if (pVirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_UP)
    {
        CcspTraceInfo(("%s: Already UP, skipping setup\n", __FUNCTION__));
        return ANSC_STATUS_SUCCESS;
    }

    entry = WanMgr_getDSLiteEntryByAlias_locked(pVirtIf->DSLite.Path);
    if (entry == NULL)
    {
        CcspTraceError(("%s: DSLite entry not found for Alias %s\n", __FUNCTION__, pVirtIf->DSLite.Path));
        return ANSC_STATUS_FAILURE;
    }

    cfg = &entry->CurrCfg;
    inst = entry->InstanceNumber;

    snprintf(tunnelIf, sizeof(tunnelIf), "ipip6tun%u", inst ? inst - 1 : 0);
    CcspTraceInfo(("%s: Starting DSLite setup for instance %u using tunnel interface %s\n", __FUNCTION__, inst, tunnelIf));

    memset(wan6_addr, 0, sizeof(wan6_addr));
    memset(dns_list, 0, sizeof(dns_list));

    if (!IS_EMPTY_STRING(pVirtIf->IP.Ipv6Data.address))
    {
        strncpy(wan6_addr, pVirtIf->IP.Ipv6Data.address, sizeof(wan6_addr) - 1);
    }

    if (!IS_EMPTY_STRING(pVirtIf->IP.Ipv6Data.nameserver))
    {
        strncpy(dns_list[dns_count++], pVirtIf->IP.Ipv6Data.nameserver, sizeof(dns_list[0]) - 1);
    }

    if (!IS_EMPTY_STRING(pVirtIf->IP.Ipv6Data.nameserver1))
    {
        strncpy(dns_list[dns_count++], pVirtIf->IP.Ipv6Data.nameserver1, sizeof(dns_list[1]) - 1);
    }

    if (strlen(wan6_addr) < 2 || dns_count == 0)
    {
        CcspTraceError(("%s: Invalid WAN IPv6 (%s) or no DNS servers (count=%d)\n", __FUNCTION__, wan6_addr, dns_count));
        WanMgr_GetDSLiteData_release();
        return ANSC_STATUS_FAILURE;
    }

    /* Get Endpoint Mode & Address */
    mode = Dslite_GetEndpointInfo(cfg, endpoint_buf, sizeof(endpoint_buf));
    if (mode < 0)
    {
        WanMgr_GetDSLiteData_release();
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s: mode=%d, endpoint buffer=%s\n", __FUNCTION__, mode, endpoint_buf));

    /* Construct Tunnel IPv6 ("40"+suffix) */
    if (strlen(wan6_addr) >= 2)
    {
        tnl_ipv6[0] = '4';
        tnl_ipv6[1] = '0';
        strncpy(&tnl_ipv6[2], &wan6_addr[2], sizeof(tnl_ipv6) - 3);
        tnl_ipv6[sizeof(tnl_ipv6) - 1] = '\0';
    }

    if (inet_pton(AF_INET6, endpoint_buf, &tmpv6) == 1)
    {
        strncpy(resolved_endpoint, endpoint_buf, sizeof(resolved_endpoint) - 1);
        CcspTraceInfo(("%s: Endpoint address is already IPv6 literal: %s\n", __FUNCTION__, resolved_endpoint));

        memset(&(cfg->DnsResolveTime), 0, sizeof(cfg->DnsResolveTime));
        cfg->DnsTtl = 0;
    }
    else
    {
        // Check if we already have a recently resolved address (e.g., from TTL expiration check)
        if (!IS_EMPTY_STRING(cfg->AddrInUse) &&
            cfg->DnsResolveTime.tv_sec != 0 &&
            cfg->DnsTtl != 0)
        {
            struct timespec CurrentTime;
            clock_gettime(CLOCK_MONOTONIC_RAW, &CurrentTime);
            time_t elapsed = (CurrentTime.tv_sec - cfg->DnsResolveTime.tv_sec);

            if (elapsed < (time_t)cfg->DnsTtl)
            {
                strncpy(resolved_endpoint, cfg->AddrInUse, sizeof(resolved_endpoint) - 1);
                CcspTraceInfo(("%s: Reusing cached endpoint address %s (age=%lds, TTL=%u)\n",
                              __FUNCTION__, resolved_endpoint, elapsed, cfg->DnsTtl));
            }
        }

        // If no cached address available, perform DNS resolution
        if (resolved_endpoint[0] == '\0')
        {
            CcspTraceInfo(("%s: Resolving endpoint FQDN %s\n", __FUNCTION__, endpoint_buf));

            if (Dslite_ResolveEndpointFqdn(endpoint_buf, dns_list, dns_count, resolved_endpoint, sizeof(resolved_endpoint), &dns_ttl) == ANSC_STATUS_SUCCESS)
            {
                CcspTraceInfo(("%s: DNS resolution TTL = %u\n", __FUNCTION__, dns_ttl));

                // Check if endpoint address changed from previous resolution
                if (!IS_EMPTY_STRING(cfg->AddrInUse) &&
                    strcmp(cfg->AddrInUse, resolved_endpoint) != 0)
                {
                    CcspTraceWarning(("%s: Endpoint address changed! Old=%s, New=%s\n",
                                      __FUNCTION__, cfg->AddrInUse, resolved_endpoint));
                }

                // Store DNS resolution info for TTL tracking
                clock_gettime(CLOCK_MONOTONIC_RAW, &(cfg->DnsResolveTime));
                cfg->DnsTtl = dns_ttl;
                CcspTraceInfo(("%s: Stored DNS TTL=%u for TTL expiration tracking\n",
                               __FUNCTION__, dns_ttl));
            }
        }
    }

    if (resolved_endpoint[0] == '\0' || strcmp(resolved_endpoint, "::") == 0)
    {
        CcspTraceError(("%s: Unable to resolve endpoint FQDN '%s' for inst=%u\n", __FUNCTION__, endpoint_buf, inst));
        WanMgr_GetDSLiteData_release();
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s: Endpoint resolved to %s\n", __FUNCTION__, resolved_endpoint));
    WanMgr_Dslite_DelIpRules(pVirtIf->Name, pVirtIf->IP.Ipv4Data.ip);

    /* Create tunnel interface */
    snprintf(cmd_str, sizeof(cmd_str),
             "ip -6 tunnel add %s mode ip4ip6 remote %s local %s dev %s encaplimit none tos inherit",
             tunnelIf, resolved_endpoint, wan6_addr, pVirtIf->Name);

    if (WanManager_DoSystemActionWithStatus("WanMgr_DSLite_SetupTunnel", cmd_str) != RETURN_OK)
    {
        CcspTraceError(("%s: Failed to create tunnel interface %s\n", __FUNCTION__, tunnelIf));
        WanMgr_GetDSLiteData_release();
        return ANSC_STATUS_FAILURE;
    }

    /* Enable IPv6 Autoconf */
    if (sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/autoconf", tunnelIf, "1") != 0)
    {
        CcspTraceError(("Failed to enable IPv6 autoconfiguration on interface %s!\n", tunnelIf));
    }

    /* Configure Addresses */
    if (cfg->TunnelV4Addr[0] != '\0')
    {
        snprintf(cmd_str, sizeof(cmd_str),
                "ip link set dev %s txqueuelen 1000 up; "
                "ip -6 addr add %s dev %s; "
                "ip addr add %s dev %s; "
                "ip -4 addr flush %s",
                tunnelIf,
                tnl_ipv6, tunnelIf,
                cfg->TunnelV4Addr, tunnelIf,
                pVirtIf->Name);
    }
    else
    {
        snprintf(cmd_str, sizeof(cmd_str),
                "ip link set dev %s txqueuelen 1000 up; "
                "ip -6 addr add %s dev %s; "
                "ip -4 addr flush %s",
                tunnelIf,
                tnl_ipv6, tunnelIf,
                pVirtIf->Name);
    }

    WanManager_DoSystemAction("WanMgr_DSLite_SetupTunnel", cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "ip route add default dev %s table erouter", tunnelIf);
    WanManager_DoSystemAction("WanMgr_DSLite_SetupTunnel", cmd_str);

    snprintf(cmd_str, sizeof(cmd_str),"ip route add default dev %s table 14", tunnelIf);
    WanManager_DoSystemAction("WanMgr_DSLite_SetupTunnel", cmd_str);


    WanMgr_DSLite_AddFirewallRules(inst, tunnelIf, cfg);

    strncpy(cfg->AddrInUse, resolved_endpoint, sizeof(cfg->AddrInUse) - 1);
    strncpy(cfg->TunnelIface, tunnelIf, sizeof(cfg->TunnelIface) - 1);
    strncpy(cfg->TunneledIface, pVirtIf->Name, sizeof(cfg->TunneledIface) - 1);

    cfg->Origin = (mode == DSLITE_ENDPOINT_DHCPV6) ? DSLITE_ENDPOINT_DHCPV6 : DSLITE_ENDPOINT_STATIC;
    cfg->Status = WAN_IFACE_DSLITE_STATE_UP;

    WanMgr_GetDSLiteData_release();
    WanMgr_DSLite_SaveEntryConfig(inst);

    CcspTraceInfo(("%s: DSLITE setup complete for instance %u (tunnel=%s)\n", __FUNCTION__, inst, tunnelIf));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_DSLite_TeardownTunnel(DML_VIRTUAL_IFACE *pVirtIf)
{
    UINT inst = 0;
    char tunnelIf[BUFLEN_64];
    char remote_addr[BUFLEN_64] = {0};
    char local_addr[BUFLEN_64] = {0};
    char cmd_str[256];
    FILE *fp = NULL;

    DML_DSLITE_LIST *entry = NULL;
    DML_DSLITE_CONFIG *cfg = NULL;

    if (!pVirtIf || !pVirtIf->DSLite.Path || !pVirtIf->Name)
    {
        CcspTraceError(("%s: Invalid input\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if (pVirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_DOWN)
    {
        CcspTraceInfo(("%s: Already DOWN, nothing to tear down\n", __FUNCTION__));
        return ANSC_STATUS_SUCCESS;
    }

    entry = WanMgr_getDSLiteEntryByAlias_locked(pVirtIf->DSLite.Path);
    if (!entry)
    {
        CcspTraceError(("%s: DSLite entry not found for Alias %s\n", __FUNCTION__, pVirtIf->DSLite.Path));
        return ANSC_STATUS_FAILURE;
    }

    cfg = &entry->CurrCfg;
    inst = entry->InstanceNumber;

    snprintf(tunnelIf, sizeof(tunnelIf), "ipip6tun%u", (unsigned int)(inst ? inst - 1 : 0));
    CcspTraceInfo(("%s: Tearing down DSLITE inst=%u tunnel=%s\n", __FUNCTION__, inst, tunnelIf));

    /* Get Remote Address */
    fp = v_secure_popen("r", "ip -6 tunnel show | grep %s | awk '/remote/{print $4}'", tunnelIf);
    if (fp)
    {
        WanManager_Util_GetShell_output(fp, remote_addr, sizeof(remote_addr));
        v_secure_pclose(fp);
        CcspTraceInfo(("%s: remote = %s\n", __FUNCTION__, remote_addr));
    }

    /* Get Local Address */
    fp = v_secure_popen("r", "ip -6 tunnel show | grep %s | awk '/remote/{print $6}'", tunnelIf);
    if (fp)
    {
        WanManager_Util_GetShell_output(fp, local_addr, sizeof(local_addr));
        v_secure_pclose(fp);
        CcspTraceInfo(("%s: local = %s\n", __FUNCTION__, local_addr));
    }

    if ((strlen(remote_addr) != 0) && (strlen(local_addr) != 0))
    {
        snprintf(cmd_str, sizeof(cmd_str),
                 "ip -6 tunnel del %s mode ip4ip6 remote %s local %s dev %s encaplimit none",
                 tunnelIf, remote_addr, local_addr, pVirtIf->Name);

        WanManager_DoSystemAction("WanMgr_DSLite_TeardownTunnel", cmd_str);
    }
    else
    {
        CcspTraceInfo(("%s: Tunnel already deleted (inst=%u)\n",
                        __FUNCTION__, inst));
    }

    cfg = &entry->CurrCfg;
    cfg->AddrInUse[0] = '\0';
    cfg->TunnelIface[0] = '\0';
    cfg->TunneledIface[0] = '\0';
    cfg->Status = WAN_IFACE_DSLITE_STATE_DOWN;

    WanMgr_GetDSLiteData_release();
    WanMgr_DSLite_SaveEntryConfig(inst);

    snprintf(cmd_str, sizeof(cmd_str), "ip route del default dev %s table erouter", tunnelIf);
    WanManager_DoSystemAction("WanMgr_DSLite_TeardownTunnel", cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "ip route del default dev %s table 14", tunnelIf);
    WanManager_DoSystemAction("WanMgr_DSLite_TeardownTunnel", cmd_str);

    WanMgr_DSLite_DeleteFirewallRules(inst);

    CcspTraceInfo(("%s: Teardown complete for DSLITE inst=%u\n", __FUNCTION__, inst));

    return ANSC_STATUS_SUCCESS;
}

