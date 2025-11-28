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
#include "wanmgr_dslite.h"
#include "wanmgr_dml_dslite_apis.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_data.h"
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)
#include "wanmgr_utils.h"
#endif
#include "wanmgr_telemetry.h"

extern WANMGR_DATA_ST gWanMgrDataBase;

BOOL DSLite_GetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL *pBool)
{
    UNREFERENCED_PARAMETER(hInsContext);
    WanMgr_DSLite_Data_t *pDSLiteData;
    BOOL ret = FALSE;

    pDSLiteData = WanMgr_GetDSLiteData_locked();
    if (!pDSLiteData)
        return ret;

    if (strcmp(ParamName, "Enable") == 0)
    {
        *pBool = pDSLiteData->Enable;
        ret = TRUE;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

BOOL DSLite_SetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL bValue)
{
    UNREFERENCED_PARAMETER(hInsContext);
    WanMgr_DSLite_Data_t *pDSLiteData;
    BOOL ret = FALSE;

    pDSLiteData = WanMgr_GetDSLiteData_locked();
    if (!pDSLiteData)
        return ret;

    if (strcmp(ParamName, "Enable") == 0)
    {
        if (pDSLiteData->Enable != bValue)
        {
            UINT deviceMode = 0;

            WanMgr_SysCfgGetUint("last_erouter_mode", &deviceMode);
            if (bValue && (DML_WAN_DEVICE_MODE)deviceMode != DML_WAN_DEVICE_MODE_Ipv6)
            {
                CcspTraceWarning(("Cannot set DSLite, the device mode is not ipv6 only! \n"));
                ret = FALSE;
            }
            else
            {
                pDSLiteData->Enable = bValue;
                pDSLiteData->Changed = TRUE;
                ret = TRUE;
            }
        }
        else
        {
            ret = TRUE;
        }
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

BOOL DSLite_GetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG *pUlong)
{
    UNREFERENCED_PARAMETER(hInsContext);
    WanMgr_DSLite_Data_t *pDSLiteData;
    BOOL ret = FALSE;

    pDSLiteData = WanMgr_GetDSLiteData_locked();
    if (pDSLiteData == NULL)
        return ret;

    if (strcmp(ParamName, "InterfaceSettingNumberOfEntries") == 0)
    {
        *pUlong = (ULONG)pDSLiteData->InterfaceSettingNumberOfEntries;
        ret = TRUE;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

BOOL InterfaceSetting4_GetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL *pBool)
{
    UINT inst = (UINT)(uintptr_t)hInsContext;
    BOOL ret = FALSE;
    DML_DSLITE_CONFIG *cfg;
    DML_DSLITE_LIST *entry;

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
        return ret;

    cfg = &entry->CurrCfg;

    if (strcmp(ParamName, "Enable") == 0)
    {
        *pBool = cfg->Enable;
        ret = TRUE;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_MssClampingEnable") == 0)
    {
        *pBool = (cfg->MssClampingEnable);
        ret = TRUE;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_IPv6FragEnable") == 0)
    {
        *pBool = (cfg->Ipv6FragEnable);
        ret = TRUE;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

ULONG InterfaceSetting4_GetParamStringValue(ANSC_HANDLE hInsContext, char *ParamName, char *pValue, ULONG *pUlSize)
{
    UINT inst = (UINT)(uintptr_t)hInsContext;
    INT ret = -1;
    const char *src = NULL;
    DML_DSLITE_LIST *entry;
    DML_DSLITE_CONFIG *cfg;

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
        return ret;

    cfg = &entry->CurrCfg;

    if (strcmp(ParamName, "Alias") == 0)
        src = cfg->Alias;
    else if (strcmp(ParamName, "EndpointAddressInUse") == 0)
        src = cfg->AddrInUse;
    else if (strcmp(ParamName, "EndpointName") == 0) /* TODO: ensure backend fills correctly */
        src = cfg->AddrFqdn;
    else if (strcmp(ParamName, "EndpointAddress") == 0)
        src = cfg->AddrIPv6;
    else if (strcmp(ParamName, "TunnelInterface") == 0)
        src = cfg->TunnelIface;
    else if (strcmp(ParamName, "TunneledInterface") == 0)
        src = cfg->TunneledIface;
    else if (strcmp(ParamName, "TunnelV4Addr") == 0)
        src = cfg->TunnelV4Addr;
    else
    {
        WanMgr_GetDSLiteData_release();
        return ret;
    }

    ULONG len = AnscSizeOfString(src);
    if (len >= *pUlSize)
    {
        *pUlSize = len + 1;
        ret = 1;
    }
    else
    {
        strncpy(pValue, src, len + 1);
        pValue[len] = '\0';
        ret = 0;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

BOOL InterfaceSetting4_GetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG *pUlong)
{
    UINT inst = (UINT)(uintptr_t)hInsContext;
    DML_DSLITE_LIST *entry;
    DML_DSLITE_CONFIG *cfg;
    BOOL ret = FALSE;

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
        return ret;

    cfg = &entry->CurrCfg;

    if (strcmp(ParamName, "Status") == 0)
    {
        *pUlong = (ULONG)cfg->Status; /* TODO: ensure backend keeps this updated */
        ret = TRUE;
    }
    else if (strcmp(ParamName, "EndpointAssignmentPrecedence") == 0)
    {
        *pUlong = (ULONG)cfg->Mode;
        ret = TRUE;
    }
    else if (strcmp(ParamName, "EndpointAddressTypePrecedence") == 0)
    {
        *pUlong = (ULONG)cfg->Type;
        ret = TRUE;
    }
    else if (strcmp(ParamName, "Origin") == 0)
    {
        *pUlong = (ULONG)cfg->Origin;
        ret = TRUE;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_Tcpmss") == 0)
    {
        *pUlong = (ULONG)cfg->TcpMss;
        ret = TRUE;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

BOOL InterfaceSetting4_SetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL bValue)
{
    UINT inst = (UINT)(uintptr_t)hInsContext;
    DML_DSLITE_LIST *entry;
    DML_DSLITE_CONFIG *cfg;
    UINT deviceMode = 0;
    BOOL ret = FALSE;

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
        return ret;

    WanMgr_SysCfgGetUint("last_erouter_mode", &deviceMode);
    if ((DML_WAN_DEVICE_MODE)deviceMode != DML_WAN_DEVICE_MODE_Ipv6)
    {
        CcspTraceWarning(("Cannot set DSLite.InterfaceSetting, device mode is not ipv6 only\n"));
        WanMgr_GetDSLiteData_release();
        return FALSE;
    }

    cfg = &entry->CurrCfg;

    if (strcmp(ParamName, "Enable") == 0)
    {
        cfg->Enable = bValue;
        ret = TRUE;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_MssClampingEnable") == 0)
    {
        cfg->MssClampingEnable = bValue;
        ret = TRUE;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_IPv6FragEnable") == 0)
    {
        cfg->Ipv6FragEnable = bValue;
        ret = TRUE;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

BOOL InterfaceSetting4_SetParamStringValue(ANSC_HANDLE hInsContext, char *ParamName, char *pString)
{
    UINT inst = (UINT)(uintptr_t)hInsContext;
    DML_DSLITE_LIST *entry;
    DML_DSLITE_CONFIG *cfg;
    char *dst = NULL;
    size_t dst_size = 0;
    BOOL ret = FALSE;

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
        return ret;

    cfg = &entry->CurrCfg;

    CcspTraceWarning(("Dslite: set %s to %s\n", ParamName, pString));

    if (strcmp(ParamName, "Alias") == 0)
    {
        dst = cfg->Alias;
        dst_size = sizeof(cfg->Alias);
    }
    else if (strcmp(ParamName, "EndpointName") == 0)
    {
        /* EndpointName writable only when EndpointAssignmentPrecedence is Static */
        if (cfg->Mode != DSLITE_ENDPOINT_STATIC)
        {
            WanMgr_GetDSLiteData_release();
            return FALSE;
        }
        dst = cfg->AddrFqdn;
        dst_size = sizeof(cfg->AddrFqdn);
    }
    else if (strcmp(ParamName, "EndpointAddress") == 0)
    {
        dst = cfg->AddrIPv6;
        dst_size = sizeof(cfg->AddrIPv6);
    }
    else if (strcmp(ParamName, "TunnelV4Addr") == 0)
    {
        dst = cfg->TunnelV4Addr;
        dst_size = sizeof(cfg->TunnelV4Addr);
    }

    if (dst == NULL || (strlen(pString) >= dst_size))
    {
        ret = FALSE;
    }
    else
    {
        strncpy(dst, pString, dst_size);
        dst[dst_size - 1] = '\0';
        ret = TRUE;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

BOOL InterfaceSetting4_SetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG uValue)
{
    UINT inst = (UINT)(uintptr_t)hInsContext;
    DML_DSLITE_LIST *entry;
    DML_DSLITE_CONFIG *cfg;
    BOOL ret = FALSE;

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
        return ret;

    cfg = &entry->CurrCfg;

    if (strcmp(ParamName, "EndpointAssignmentPrecedence") == 0)
    {
        cfg->Mode = (DML_WAN_DSLITE_ADDR_METHOD)uValue;
        ret = TRUE;
    }
    else if (strcmp(ParamName, "EndpointAddressTypePrecedence") == 0)
    {
        cfg->Type = (DML_WAN_DSLITE_ADDR_PRECEDENCE)uValue;
        ret = TRUE;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_Tcpmss") == 0)
    {
        cfg->TcpMss = uValue;
        ret = TRUE;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

ULONG InterfaceSetting4_GetEntryCount(ANSC_HANDLE hInsContext)
{
    UNREFERENCED_PARAMETER(hInsContext);
    WanMgr_DSLite_Data_t *pDSLiteData;
    ULONG count = 0;

    pDSLiteData = WanMgr_GetDSLiteData_locked();
    if (!pDSLiteData)
        return 0;

    count = (ULONG)pDSLiteData->InterfaceSettingNumberOfEntries;

    WanMgr_GetDSLiteData_release();
    return count;
}

ANSC_HANDLE InterfaceSetting4_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG *pInsNumber)
{
    UNREFERENCED_PARAMETER(hInsContext);
    UINT inst;
    DML_DSLITE_LIST *entry;

    entry = WanMgr_getDSLiteEntryByIdx_locked(nIndex);
    if (!entry)
        return NULL;

    *pInsNumber = entry->InstanceNumber;
    inst = entry->InstanceNumber;

    WanMgr_GetDSLiteData_release();
    return (ANSC_HANDLE)(uintptr_t)inst;
}

ANSC_HANDLE InterfaceSetting4_AddEntry(ANSC_HANDLE hInsContext, ULONG *pInsNumber)
{
    UNREFERENCED_PARAMETER(hInsContext);
    UINT inst;
    WanMgr_DSLite_Data_t *pDSLiteData;

    pDSLiteData = WanMgr_GetDSLiteData_locked();
    if (!pDSLiteData)
        return NULL;

    if (pDSLiteData->InterfaceSettingNumberOfEntries >= MAX_DSLITE_CONFIG_ENTRY)
    {
        CcspTraceError(("%s: reached max entries %d\n",
                        __FUNCTION__, MAX_DSLITE_CONFIG_ENTRY));
        WanMgr_GetDSLiteData_release();
        return NULL;
    }
    inst = pDSLiteData->NextInstanceNumber++;
    WanMgr_GetDSLiteData_release();

    if (WanMgr_DSLite_AddToList(inst) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: WanMgr_DSLite_AddToList failed\n", __FUNCTION__));
        return NULL;
    }
    *pInsNumber = inst;

    return (ANSC_HANDLE)(uintptr_t)inst;
}

ULONG InterfaceSetting4_DelEntry(ANSC_HANDLE hInsContext, ANSC_HANDLE hInstance)
{
    UNREFERENCED_PARAMETER(hInsContext);
    UINT inst = (UINT)(uintptr_t)hInstance;

    if (WanMgr_DSLite_DelFromList(inst) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: WanMgr_DSLite_DelFromList failed\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if (WanMgr_DSLite_DelFromSyscfg(inst) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: WanMgr_DSLite_DelFromSyscfg failed\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if (WanMgr_DSLite_WriteDSLiteCfgToSyscfg() != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: Failed to write DSLite main config after delete\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

BOOL InterfaceSetting4_Validate(ANSC_HANDLE hInsContext, char *pReturnParamName, ULONG *puLength)
{
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    WanMgr_DSLite_Data_t* pDSLiteData;
    DML_DSLITE_CONFIG *cfgThis;
    DML_DSLITE_LIST *pThis, *entry;
    UINT inst = (UINT)(uintptr_t)hInsContext;
    BOOL ret = TRUE;

    pThis = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!pThis)
        return FALSE;

    pDSLiteData = &gWanMgrDataBase.DSLite;
    cfgThis = &pThis->CurrCfg;
    if (cfgThis->Alias[0] != '\0')
    {
        /* Validate this instance by checking if another instance with the same Alias exists */
        entry = pDSLiteData->DSLiteList; // Called under lock, so no problem
        while (entry)
        {
            if (entry != pThis)
            {
                DML_DSLITE_CONFIG *cfgOther = &entry->CurrCfg;

                if (strcmp(cfgOther->Alias, cfgThis->Alias) == 0)
                {
                    ret = FALSE;
                    break;
                }
            }
            entry = entry->next;
        }
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

ULONG InterfaceSetting4_Commit(ANSC_HANDLE hInsContext)
{
    UINT inst = (UINT)(uintptr_t)hInsContext;

    if (WanMgr_DSLite_WriteDSLiteCfgToSyscfg() != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: Failed to write DSLite main config to syscfg\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if (WanMgr_DSLite_WriteEntryCfgToSyscfg(inst) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: Failed to write DSLite entry to syscfg\n", __FUNCTION__));

        return ANSC_STATUS_FAILURE;
    }

    if (WanMgr_DSLite_UpdateVirtIfDSLiteCfg(inst) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: Failed to write DSLite entry to syscfg\n", __FUNCTION__));

        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

ULONG InterfaceSetting4_Rollback(ANSC_HANDLE hInsContext)
{
    UINT inst = (UINT)(uintptr_t)hInsContext;
    WanMgr_DSLite_Data_t* pDSLiteData;
    DML_DSLITE_LIST *entry;

    entry = WanMgr_getDSLiteEntryByInstance_locked(inst);
    if (!entry)
        return ANSC_STATUS_FAILURE;

    pDSLiteData = &gWanMgrDataBase.DSLite;

    if (entry->New)
    {
        /* remove from list and free it */
        DML_DSLITE_LIST *prev = NULL;
        DML_DSLITE_LIST *curr = pDSLiteData->DSLiteList; // called under lock. So no problem

        while (curr)
        {
            if (curr == entry)
            {
                if (prev)
                    prev->next = curr->next;
                else
                    pDSLiteData->DSLiteList = curr->next;

                AnscFreeMemory(curr);
                if (pDSLiteData->InterfaceSettingNumberOfEntries > 0)
                    pDSLiteData->InterfaceSettingNumberOfEntries--;

                WanMgr_GetDSLiteData_release();
                return ANSC_STATUS_SUCCESS;
            }

            prev = curr;
            curr = curr->next;
        }
    }
    else
    {
        entry->CurrCfg = entry->PrevCfg;
    }

    WanMgr_GetDSLiteData_release();
    return ANSC_STATUS_SUCCESS;
}
