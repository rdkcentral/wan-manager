/*********************************************************************************
 If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 Deutsche Telekom AG.
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
#include <sys/inotify.h>
#include <sysevent/sysevent.h>
#include <math.h>
#include "secure_wrapper.h"
#include "wanmgr_apis.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_map_apis.h"

#define MAX_ULONG             4294967295
#define NET_STATS_FILE        "/proc/net/dev"
#define BUFF_SIZE_16          16
#define BUFF_SIZE_64          64
#define BUFF_SIZE_1024        1024

PWAN_PRI_MAP_DOM_FULL g_pDomainFull  = NULL;
static ULONG          maxDomainCount = 1;
static unsigned long long strtoul_custom(char *number);
static DML_VIRTUAL_IFACE* GetPreferredMAPInterface();

static unsigned long long strtoul_custom(char *number)
{
    unsigned long long int value;
    unsigned long int ret;

    if (!number)
    {
        CcspTraceWarning(("Input parameter  is NULL\n"));
        return 0;
    }

    value = strtoull(number, NULL, 10);
    if(value < MAX_ULONG) {
        return value;
    }

    ret = (value - ((value / MAX_ULONG) *MAX_ULONG));
    return ret;
}

static DML_VIRTUAL_IFACE* GetPreferredMAPInterface()
{
    DML_VIRTUAL_IFACE *pVirtList = WanMgr_GetActiveVirtIfData_locked();
    DML_VIRTUAL_IFACE *pVirtIf = NULL;

    if (!pVirtList)
    {
        return NULL;
    }

    for (DML_VIRTUAL_IFACE *cur = pVirtList; cur != NULL; cur = cur->next)
    {
        if (cur->Status == WAN_IFACE_STATUS_UP && cur->MAP.dhcp6cMAPparameters.mapType == MAP_TYPE_MAPE && strcmp(cur->Alias, "DATA") == 0)
        {
            pVirtIf = cur;
            break;
        }
    }

    if (!pVirtIf)
    {
        for (DML_VIRTUAL_IFACE *cur = pVirtList; cur != NULL; cur = cur->next)
        {
            if (cur->Status == WAN_IFACE_STATUS_UP && cur->EnableMAPT)
            {
                pVirtIf = cur;
                break;
            }
        }
    }

    return pVirtIf;
}

/**********************************************************************
    caller:     self
    prototype:
        ULONG
        WanDmlMapDomGetNumberOfEntries
            (
                ANSC_HANDLE                 hContext
             );
    Description:
        The API retrieves the number of MAP domaian in the system.
    Arguments:
                ANSC_HANDLE                 hContext
    Return:
                The number of entries in the Interface table.
**********************************************************************/
ULONG
WanDmlMapDomGetNumberOfEntries
    (
        ANSC_HANDLE                 hContext
    )
{
    return (maxDomainCount);
}

/**********************************************************************
    caller:     self
    prototype:
        ANSC_STATUS
        WanDmlMapDomGetEntry
            (
                ANSC_HANDLE                 hContext,
                ULONG                       ulIndex,
                PWAN_DML_MAP_DOM_FULL       pEntry
             );
    Description:
           The API retrieves the complete info of the MAP domain designated by index.
           The usual process is the caller gets the total number of entries, then iterate
           through those by calling this API.
    Arguments:
               ANSC_HANDLE                 hContext,
               ULONG                       ulIndex,
               PWAN_DML_MAP_DOM_FULL       pEntry
    Return:
        The ulIndex entry of the table
**********************************************************************/
ANSC_STATUS
WanDmlMapDomGetEntry
(
    ANSC_HANDLE                 hContext,
    ULONG                       ulIndex,
    PWAN_DML_DOMAIN_FULL        pEntry
)
{
    if ((pEntry == NULL) || ulIndex >= maxDomainCount)
    {
        AnscTraceError(("%s:%d:: Invalid parameter or index\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (!g_pDomainFull)
    {
        g_pDomainFull = (PWAN_PRI_MAP_DOM_FULL)AnscAllocateMemory(sizeof(WAN_PRI_MAP_DOM_FULL) * maxDomainCount);
        if (!g_pDomainFull)
        {
            AnscTraceError(("%s:%d:: Memory allocation failed\n", __FUNCTION__, __LINE__));
            return ANSC_STATUS_FAILURE;
        }
    }
    
    PWAN_PRI_MAP_DOM_FULL pFull = &g_pDomainFull[ulIndex];
    if(pFull->Info.IfaceName[0] != '\0' )
    {
        memset(pFull, 0, sizeof(WAN_PRI_MAP_DOM_FULL));
    }
    pFull->ulNumOfRule = 1;
    pFull->Cfg.InstanceNumber = ulIndex + 1;

    if (WanDmlMapDomGetCfg_Data(pFull->Cfg.InstanceNumber, &pFull->Cfg) != ANSC_STATUS_SUCCESS)
    {
        //AnscTraceWarning(("%s:%d:: Failed to refresh domain config\n", __FUNCTION__, __LINE__));
    }

    if (WanDmlMapDomGetInfo_Data(pFull->Cfg.InstanceNumber, &pFull->Info) != ANSC_STATUS_SUCCESS)
    {
        //AnscTraceWarning(("%s:%d:: Failed to refresh domain info\n", __FUNCTION__, __LINE__));
    }

        // Prepare the output structure (only return Cfg + Info as per PWAN_DML_DOMAIN_FULL)
    pEntry->Cfg = pFull->Cfg;
    pEntry->Info = pFull->Info;

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomGetCfg
           (
                ANSC_HANDLE                 hContext,
                PWAN_DML_DOMAIN_CFG         pCfg
           );
    Description:
        API to get the Domain configuration.
    Arguments:
                ANSC_HANDLE                 hContext,
                PWAN_DML_DOMAIN_CFG         pCfg
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomGetCfg
    (
        ANSC_HANDLE                 hContext,
        PWAN_DML_DOMAIN_CFG         pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);

    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;

    if (NULL ==  pCfg)
    {
        AnscTraceFlow(("%s: Null parameter\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    AnscCopyMemory(pCfg, &g_pDomainFull[pCfg->InstanceNumber-1].Cfg, sizeof(WAN_DML_DOMAIN_CFG));

    return returnStatus;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomGetCfg_Data
           (
                ULONG                       ulInstanceNumber
                PWAN_DML_DOMAIN_CFG          pDomCfg
           );
    Description:
        API to get the Domain configuration address
    Arguments:
                ULONG                       ulInstanceNumber
                PWAN_DML_DOMAIN_CFG         pDomCfg
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomGetCfg_Data
(
    ULONG ulInstanceNumber,
    PWAN_DML_DOMAIN_CFG pDomCfg
)
{
    if (pDomCfg == NULL)
    {
        AnscTraceError(("%s:%d:: Invalid input\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    DML_VIRTUAL_IFACE *pVirtIf = GetPreferredMAPInterface();
    
    WanMgrDml_GetIfaceData_release(NULL); // Unlock

    if (pVirtIf == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    MAP_TYPE mapType = pVirtIf->MAP.dhcp6cMAPparameters.mapType;
    pDomCfg->InstanceNumber = ulInstanceNumber;

    if ((pVirtIf->MAP.MapeStatus == WAN_IFACE_MAPE_STATE_UP) || (pVirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP))
    {
        AnscCopyString(pDomCfg->Alias, (mapType == MAP_TYPE_MAPE) ? "Domain_mape" : "Domain_mapt");
	pDomCfg->bEnabled = ((mapType == MAP_TYPE_MAPE || mapType == MAP_TYPE_MAPT) && pVirtIf->Enable && (pVirtIf->MAP.dhcp6cMAPparameters.pdIPv6Prefix[0] != '\0'));
	AnscCopyString(pDomCfg->WANInterface, pVirtIf->IP.Interface);
        AnscCopyString(pDomCfg->IPv6Prefix, pVirtIf->MAP.dhcp6cMAPparameters.pdIPv6Prefix);
        AnscCopyString(pDomCfg->BRIPv6Prefix, pVirtIf->MAP.dhcp6cMAPparameters.brIPv6Prefix);
        pDomCfg->DSCPMarkPolicy = 0;

        pDomCfg->IfaceEnable = TRUE;
        AnscCopyString(pDomCfg->IfaceAlias, "Interface_tunnel");
        pDomCfg->IfaceLowerLayers[0] = '\0';
    }
    else
    {
        AnscCopyString(pDomCfg->Alias, "Domain_unknown");
        pDomCfg->bEnabled = FALSE;
        pDomCfg->IfaceEnable = FALSE;
    }
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomSetCfg
          (
                ANSC_HANDLE                 hContext,
                PWAN_DML_DOMAIN_CFG         pCfg
            );
    Description:
        API to set the Domain configuration.
    Arguments:
                ANSC_HANDLE                 hContext,
                PWAN_DML_DOMAIN_CFG         pCfg
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomSetCfg
    (
        ANSC_HANDLE                 hContext,
        PWAN_DML_DOMAIN_CFG         pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);

    if (NULL ==  pCfg)
    {
        AnscTraceFlow(("%s: Null parameter\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PWAN_DML_DOMAIN_CFG             pBuf_cfg     = NULL;

    pBuf_cfg = &g_pDomainFull[pCfg->InstanceNumber-1].Cfg;

    if (0 != strcmp(pCfg->Alias, pBuf_cfg->Alias))
    {
        AnscCopyString(pBuf_cfg->Alias, pCfg->Alias);
    }

    if (pCfg->bEnabled != pBuf_cfg->bEnabled)
    {
        pBuf_cfg->bEnabled = pCfg->bEnabled;
    }

    if (0 != strcmp(pCfg->WANInterface, pBuf_cfg->WANInterface))
    {
        AnscCopyString(pBuf_cfg->WANInterface, pCfg->WANInterface);
    }

    if (0 != strcmp(pCfg->IPv6Prefix, pBuf_cfg->IPv6Prefix))
    {
        AnscCopyString(pBuf_cfg->IPv6Prefix, pCfg->IPv6Prefix);
    }

    if (0 != strcmp(pCfg->BRIPv6Prefix, pBuf_cfg->BRIPv6Prefix))
    {
        AnscCopyString(pBuf_cfg->BRIPv6Prefix, pCfg->BRIPv6Prefix);
    }

    if (pCfg->DSCPMarkPolicy != pBuf_cfg->DSCPMarkPolicy)
    {
        pBuf_cfg->DSCPMarkPolicy = pCfg->DSCPMarkPolicy;
    }

    if (pCfg->IfaceEnable != pBuf_cfg->IfaceEnable)
    {
        pBuf_cfg->IfaceEnable = pCfg->IfaceEnable;
    }

    if (0 != strcmp(pCfg->BRIPv6Prefix, pBuf_cfg->BRIPv6Prefix))
    {
        AnscCopyString(pBuf_cfg->BRIPv6Prefix, pCfg->BRIPv6Prefix);
    }

    if (0 != strcmp(pCfg->IfaceAlias, pBuf_cfg->IfaceAlias))
    {
        AnscCopyString(pBuf_cfg->IfaceAlias, pCfg->IfaceAlias);
    }

    if (0 != strcmp(pCfg->IfaceLowerLayers, pBuf_cfg->IfaceLowerLayers))
    {
        AnscCopyString(pBuf_cfg->IfaceLowerLayers, pCfg->IfaceLowerLayers);
    }

    return returnStatus;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomGetInfo
           (
                ANSC_HANDLE                 hContext,
                ULONG                       ulInstanceNumber,
                PWAN_DML_DOMAIN_INFO        pInfo
           );
    Description:
        API to get the Domain info.
    Arguments:
                ANSC_HANDLE                 hContext,
                ULONG                       ulInstanceNumber,
                PWAN_DML_DOMAIN_INFO        pInfo
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomGetInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PWAN_DML_DOMAIN_INFO        pInfo
    )
{
    UNREFERENCED_PARAMETER(hContext);

    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    if (NULL ==  pInfo)
    {
        AnscTraceFlow(("%s: Null parameter\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if ((ulInstanceNumber > 0) && (ulInstanceNumber <= maxDomainCount))
    {
        AnscCopyMemory(pInfo, &g_pDomainFull[ulInstanceNumber-1].Info, sizeof(WAN_DML_DOMAIN_INFO));
    }
    else
    {
        AnscTraceError(("%s:%d:: Invalid Domain instance number\n", __FUNCTION__, __LINE__));
    }

    return returnStatus;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomGetInfo_Data
           (
                ULONG                       ulInstanceNumber
                PWAN_DML_DOMAIN_INFO        pDomInfo
           );
    Description:
        API to get the Domain info address.
    Arguments:
                ULONG                       ulInstanceNumber
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomGetInfo_Data
(
    ULONG ulInstanceNumber,
    PWAN_DML_DOMAIN_INFO pDomInfo
)
{
    if (pDomInfo == NULL)
    {
        AnscTraceError(("%s:%d:: Invalid input\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    DML_VIRTUAL_IFACE *pVirtIf = GetPreferredMAPInterface();

    WanMgrDml_GetIfaceData_release(NULL); // Unlock

    if (pVirtIf == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    MAP_TYPE mapType = pVirtIf->MAP.dhcp6cMAPparameters.mapType;
    if (pVirtIf->Enable && ((pVirtIf->MAP.MapeStatus == WAN_IFACE_MAPE_STATE_UP) || (pVirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)))
    {
        pDomInfo->Status = WAN_DML_DOMAIN_STATUS_Enabled;
        pDomInfo->IfaceStatus = (pVirtIf->Status == WAN_IFACE_STATUS_UP) ? WAN_DML_INTERFACE_STATUS_Up : WAN_DML_INTERFACE_STATUS_Down;
        pDomInfo->IfaceLastChange = 0;

        switch (mapType)
        {
            case MAP_TYPE_MAPE:
                AnscCopyString(pDomInfo->Name, "MAPE");
                pDomInfo->TransportMode = WAN_DML_DOMAIN_TRANSPORT_MAPE;
                AnscCopyString(pDomInfo->IfaceName, "ip6tnl");
                break;

            case MAP_TYPE_MAPT:
                AnscCopyString(pDomInfo->Name, "MAPT");
                pDomInfo->TransportMode = WAN_DML_DOMAIN_TRANSPORT_MAPT;
                AnscCopyString(pDomInfo->IfaceName, "map0");
                break;

            default:
                AnscCopyString(pDomInfo->Name, "UNKNOWN");
		pDomInfo->TransportMode  = WAN_DML_DOMAIN_TRANSPORT_UNKNOWN;
                pDomInfo->IfaceName[0] = '\0';
		break;
         }
    }
    else
    {
	pDomInfo->Status = WAN_DML_DOMAIN_STATUS_Disabled;
        AnscCopyString(pDomInfo->Name, "UNKNOWN");
        pDomInfo->TransportMode  = WAN_DML_DOMAIN_TRANSPORT_UNKNOWN;
	pDomInfo->IfaceStatus    = WAN_DML_INTERFACE_STATUS_Down;
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomSetInfo
          (
                ANSC_HANDLE                 hContext,
                ULONG                       ulInstanceNumber,
                PWAN_DML_DOMAIN_INFO        pInfo
            );
    Description:
        API to set the Domain info.
    Arguments:
                ANSC_HANDLE                 hContext,
                ULONG                       ulInstanceNumber,
                PWAN_DML_DOMAIN_INFO        pInfo
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomSetInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PWAN_DML_DOMAIN_INFO        pInfo
    )
{
    UNREFERENCED_PARAMETER(hContext);

    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PWAN_DML_DOMAIN_INFO            pBuf_info    = NULL;

    if (NULL ==  pInfo)
    {
        AnscTraceFlow(("%s: Null parameter\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if ((ulInstanceNumber <= 0) || (ulInstanceNumber > maxDomainCount))
    {
        AnscTraceError(("%s:%d:: Invalid Domain instance number\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    pBuf_info = &g_pDomainFull[ulInstanceNumber-1].Info;

    if (pInfo->Status != pBuf_info->Status)
    {
        pBuf_info->Status = pInfo->Status;
    }

    if (0 != strcmp(pInfo->Name, pBuf_info->Name))
    {
        AnscCopyString(pBuf_info->Name, pInfo->Name);
    }

    if (pInfo->TransportMode != pBuf_info->TransportMode)
    {
        pBuf_info->TransportMode = pInfo->TransportMode;
    }

    if (pInfo->IfaceStatus != pBuf_info->IfaceStatus)
    {
        pBuf_info->IfaceStatus = pInfo->IfaceStatus;
    }

    if (0 != strcmp(pInfo->IfaceName, pBuf_info->IfaceName))
    {
        AnscCopyString(pBuf_info->IfaceName, pInfo->IfaceName);
    }

    if (pInfo->IfaceLastChange != pBuf_info->IfaceLastChange)
    {
        pBuf_info->IfaceLastChange = pInfo->IfaceLastChange;
    }

    return returnStatus;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomGetNumberOfRules
           (
                ANSC_HANDLE                 hContext,
                ULONG                           ulIpIfInstanceNumber,
           );
    Description:
        The API retrieves the number of MAP rules in the system.
    Arguments:
                ANSC_HANDLE                 hContext,
                ULONG                       ulIpIfInstanceNumber
    Return:
        The number of MAP Rules.
**********************************************************************/
ULONG
WanDmlMapDomGetNumberOfRules
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulMapDomInstanceNumber
    )
{
    ULONG                           noOfRules    = -1;

    if((ulMapDomInstanceNumber > 0) && (ulMapDomInstanceNumber <= maxDomainCount))
    {
        noOfRules = g_pDomainFull[ulMapDomInstanceNumber - 1].ulNumOfRule;
    }
    else
    {
        AnscTraceError(("%s:%d:: Invalid Domain instance number\n", __FUNCTION__, __LINE__));
    }

    return noOfRules;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomGetRule
           (
                ANSC_HANDLE                 hContext,
                ULONG                       ulMapDomInstanceNumber,
                ULONG                       ulIndex,
                PWAN_DML_MAP_RULE           pEntry
           );
    Description:
        The API adds one IP interface into the system.
    Arguments:
        ANSC_HANDLE                 hContext,
        ULONG                       ulMapDomInstanceNumber,
        ULONG                       ulIndex,
        PWAN_DML_MAP_RULE           pEntry
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomGetRule
(
    ANSC_HANDLE               hContext,
    ULONG                     ulMapDomInstanceNumber,
    ULONG                     ulIndex,
    PWAN_DML_MAP_RULE         pEntry
)
{
    if (pEntry == NULL)
    {
        AnscTraceError(("%s:%d:: Invalid parameter\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (ulMapDomInstanceNumber > maxDomainCount)
    {
        AnscTraceError(("%s:%d:: Invalid domain instance number: %lu\n", __FUNCTION__, __LINE__, ulMapDomInstanceNumber));
        return ANSC_STATUS_FAILURE;
    }

    PWAN_PRI_MAP_DOM_FULL pFull = &g_pDomainFull[ulMapDomInstanceNumber - 1];

    // Allocate memory for rule list if not already present
    if (pFull->pRuleList == NULL)
    {
        pFull->pRuleList = (PWAN_DML_MAP_RULE)AnscAllocateMemory(sizeof(WAN_DML_MAP_RULE) * pFull->ulNumOfRule);
        if (pFull->pRuleList == NULL)
        {
            AnscTraceError(("%s:%d:: Failed to allocate memory for rule list\n", __FUNCTION__, __LINE__));
            return ANSC_STATUS_FAILURE;
        }
        pFull->pRuleList[ulIndex].InstanceNumber = ulIndex + 1;
        for (int i = 0; i < pFull->ulNumOfRule; i++)
        {
            if (WanDmlMapDomGetRule_Data(ulMapDomInstanceNumber, i, &pFull->pRuleList[i]) != ANSC_STATUS_SUCCESS)
            {
                AnscTraceWarning(("%s:%d:: Failed to get rule data for index %d\n", __FUNCTION__, __LINE__, i));
            }
        }
    }
    if (ulIndex >= pFull->ulNumOfRule)
    {
        AnscTraceError(("%s:%d:: Invalid rule index: %lu\n", __FUNCTION__, __LINE__, ulIndex));
        return ANSC_STATUS_FAILURE;
    }

    *pEntry = pFull->pRuleList[ulIndex];

    return ANSC_STATUS_SUCCESS;    
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomGetRule_Data
           (
                ULONG                       ulMapDomInstanceNumber,
                ULONG                       ulIndex
                PWAN_DML_MAP_RULE           pMapRule
           );
    Description:
        The API to get MAP rule address.
    Arguments:
        ULONG                       ulMapDomInstanceNumber,
        ULONG                       ulIndex
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomGetRule_Data
(
    ULONG ulMapDomInstanceNumber,
    ULONG ulIndex,
    PWAN_DML_MAP_RULE pMapRule
)
{
    if (pMapRule == NULL)
    {
        AnscTraceError(("%s:%d:: Invalid input\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    ULONG maxRuleCount = g_pDomainFull[ulMapDomInstanceNumber - 1].ulNumOfRule;

    if (ulIndex >= maxRuleCount)
    {
        AnscTraceError(("%s:%d:: Invalid Rule index: %lu (max %lu)\n", __FUNCTION__, __LINE__, ulIndex, maxRuleCount));
        return ANSC_STATUS_FAILURE;
    }

    DML_VIRTUAL_IFACE *pVirtIf = GetPreferredMAPInterface();

    WanMgrDml_GetIfaceData_release(NULL); // Unlock

    if (pVirtIf == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }
    
    if ((pVirtIf->MAP.MapeStatus == WAN_IFACE_MAPE_STATE_UP) || (pVirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP))
    {
        // Populate pMapRule directly
        pMapRule->InstanceNumber = ulIndex + 1;
        pMapRule->Enable = TRUE;
        pMapRule->Status = WAN_DML_RULE_STATUS_Enabled;

        snprintf(pMapRule->Alias, sizeof(pMapRule->Alias), "Rule_%lu", ulIndex + 1);
        AnscCopyString(pMapRule->Origin, "DHCPv6");
        AnscCopyString(pMapRule->IPv6Prefix, pVirtIf->MAP.dhcp6cMAPparameters.ruleIPv6Prefix);
        AnscCopyString(pMapRule->IPv4Prefix, pVirtIf->MAP.dhcp6cMAPparameters.ruleIPv4Prefix);

        pMapRule->EABitsLength = pVirtIf->MAP.dhcp6cMAPparameters.eaLen;
        pMapRule->IsFMR = pVirtIf->MAP.dhcp6cMAPparameters.isFMR;
        pMapRule->PSIDOffset = pVirtIf->MAP.dhcp6cMAPparameters.psidOffset;
        pMapRule->PSIDLength = pVirtIf->MAP.dhcp6cMAPparameters.psidLen;
        pMapRule->PSID = pVirtIf->MAP.dhcp6cMAPparameters.psid;
        pMapRule->IncludeSystemPorts = FALSE;
    }
    else
    {
	pMapRule->InstanceNumber = ulIndex + 1;
        pMapRule->Enable = FALSE;
        pMapRule->Status = WAN_DML_RULE_STATUS_Disabled;

        snprintf(pMapRule->Alias, sizeof(pMapRule->Alias), "Rule_%lu", ulIndex + 1);
        AnscCopyString(pMapRule->Origin, "DHCPv6");
        pMapRule->IPv6Prefix[0] = '\0';
        pMapRule->IPv4Prefix[0] = '\0';
        pMapRule->EABitsLength = 0;
        pMapRule->IsFMR = 0;
        pMapRule->PSIDOffset = 0;
        pMapRule->PSIDLength = 0;
        pMapRule->PSID = 0;
        pMapRule->IncludeSystemPorts = FALSE;
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************
    caller:     self
    prototype:
       ANSC_STATUS
       WanDmlMapDomSetRule
           (
                ANSC_HANDLE                 hContext,
                ULONG                       ulMapDomInstanceNumber,
                ULONG                       ulIndex,
                PWAN_DML_MAP_RULE           pEntry
           );
    Description:
        API to set the Rule values.
    Arguments:
                ANSC_HANDLE                 hContext,
                ULONG                       ulMapDomInstanceNumber,
                ULONG                       ulIndex,
                PWAN_DML_MAP_RULE           pEntry
    Return:
        The status of the operation.
**********************************************************************/
ANSC_STATUS
WanDmlMapDomSetRule
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulMapDomInstanceNumber,
        ULONG                       ulIndex,
        PWAN_DML_MAP_RULE           pEntry
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PWAN_DML_MAP_RULE               pBuf_rule    = NULL;
    UINT                            maxRuleCount = -1;

    if (NULL ==  pEntry)
    {
        AnscTraceFlow(("%s: Null parameter\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if((ulMapDomInstanceNumber < 0) || (ulMapDomInstanceNumber > maxDomainCount))
    {
        AnscTraceError(("%s:%d:: Invalid Domain instance number\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    maxRuleCount = g_pDomainFull[ulMapDomInstanceNumber - 1].ulNumOfRule;
    if((ulIndex < 0) || (ulIndex >= maxRuleCount))
    {
        AnscTraceError(("%s:%d:: Invalid Rule instance number\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    pBuf_rule = &g_pDomainFull[ulMapDomInstanceNumber - 1].pRuleList[ulIndex];

    if (pEntry->Enable != pBuf_rule->Enable)
    {
        pBuf_rule->Enable = pEntry->Enable;
    }

    if (pEntry->Status != pBuf_rule->Status)
    {
        pBuf_rule->Status = pEntry->Status;
    }

    if (0 != strcmp(pEntry->Alias, pBuf_rule->Alias))
    {
        AnscCopyString(pBuf_rule->Alias, pEntry->Alias);
    }

    if (0 != strcmp(pEntry->Origin, pBuf_rule->Origin))
    {
        AnscCopyString(pBuf_rule->Origin, pEntry->Origin);
    }

    if (0 != strcmp(pEntry->IPv6Prefix, pBuf_rule->IPv6Prefix))
    {
        AnscCopyString(pBuf_rule->IPv6Prefix, pEntry->IPv6Prefix);
    }

    if (0 != strcmp(pEntry->IPv4Prefix, pBuf_rule->IPv4Prefix))
    {
        AnscCopyString(pBuf_rule->IPv4Prefix, pEntry->IPv4Prefix);
    }

    if (pEntry->EABitsLength != pBuf_rule->EABitsLength)
    {
        pBuf_rule->EABitsLength = pEntry->EABitsLength;
    }

    if (pEntry->IsFMR != pBuf_rule->IsFMR)
    {
        pBuf_rule->IsFMR = pEntry->IsFMR;
    }

    if (pEntry->PSIDOffset != pBuf_rule->PSIDOffset)
    {
        pBuf_rule->PSIDOffset = pEntry->PSIDOffset;
    }

    if (pEntry->PSIDLength != pBuf_rule->PSIDLength)
    {
        pBuf_rule->PSIDLength = pEntry->PSIDLength;
    }

    if (pEntry->PSID != pBuf_rule->PSID)
    {
        pBuf_rule->PSID = pEntry->PSID;
    }

    if (pEntry->IncludeSystemPorts != pBuf_rule->IncludeSystemPorts)
    {
        pBuf_rule->IncludeSystemPorts = pEntry->IncludeSystemPorts;
    }

    return returnStatus;
}

/**********************************************************************
    caller:     self
    prototype:
       INT
       WanDmlMapDomGetIfStats
           (
                CHAR                        *ifname,
                PWAN_DML_INTERFACE_STAT      pStats
           );
    Description:
        API to get the interface statistics.
    Arguments:
                CHAR                        *ifname,
                PWAN_DML_INTERFACE_STAT      pStats
    Return:
        The status of the operation.
**********************************************************************/
INT
WanDmlMapDomGetIfStats
    (
        CHAR *ifname,
        PWAN_DML_INTERFACE_STAT pStats
    )
{
    INT  ret                                  = 0;
    INT  idx                                  = -1;
    FILE *fp                                  = NULL;
    CHAR *p                                   = NULL;
    CHAR BytesReceived[BUFF_SIZE_16]          = {0};
    CHAR PacketsReceived[BUFF_SIZE_16]        = {0};
    CHAR ErrorsReceived[BUFF_SIZE_16]         = {0};
    CHAR DiscardPacketsReceived[BUFF_SIZE_16] = {0};
    CHAR BytesSent[BUFF_SIZE_16]              = {0};
    CHAR PacketsSent[BUFF_SIZE_16]            = {0};
    CHAR ErrorsSent[BUFF_SIZE_16]             = {0};
    CHAR DiscardPacketsSent[BUFF_SIZE_16]     = {0};
    CHAR buffStats[BUFF_SIZE_1024]            = {0};
    CHAR searchStr[BUFF_SIZE_64]              = {0};

    if(NULL != ifname)
    {
        sprintf(searchStr, "%s:", ifname);
    }
    else
    {
        CcspTraceError(("%s: Invalid interface name!\n", __FUNCTION__));
        return ret;
    }

    fp = fopen(NET_STATS_FILE, "r");
    if(NULL != fp)
    {
        idx = 0;
        while(fgets(buffStats, sizeof(buffStats), fp))
        {
            if(++idx <= 2)
                continue;

            if(p = strstr(buffStats, searchStr))
            {
                memset(pStats, 0, sizeof(WAN_DML_INTERFACE_STAT));

                if (8 == sscanf(p, "%*s %s %s %s %s %*lu %*lu %*lu %*lu %s %s %s %s %*lu %*lu %*lu %*lu",
                BytesReceived, PacketsReceived, ErrorsReceived, DiscardPacketsReceived,
                BytesSent, PacketsSent, ErrorsSent, DiscardPacketsSent))
                {
                    pStats->BytesReceived          = strtoul_custom(BytesReceived);
                    pStats->PacketsReceived        = strtoul_custom(PacketsReceived);
                    pStats->ErrorsReceived         = strtoul_custom(ErrorsReceived);
                    pStats->DiscardPacketsReceived = strtoul_custom(DiscardPacketsReceived);
                    pStats->BytesSent              = strtoul_custom(BytesSent);
                    pStats->PacketsSent            = strtoul_custom(PacketsSent);
                    pStats->ErrorsSent             = strtoul_custom(ErrorsSent);
                    pStats->DiscardPacketsSent     = strtoul_custom(DiscardPacketsSent);

                    ret = 1;
                    break;
                }
            }
        }

        fclose(fp);
    }

    return ret;
}
