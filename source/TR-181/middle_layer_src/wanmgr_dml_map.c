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
********************************************************************************/
#include "wanmgr_apis.h"
#include "wanmgr_map_internal.h"
#include "wanmgr_map_apis.h"

/************************************************************************
 APIs for Object: 
      MAP.
      WanMap_GetParamBoolValue
      WanMap_SetParamBoolValue
      WanMap_Validate
      WanMap_Commit
***********************************************************************/
/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMap_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );
    description:
        This function is called to retrieve Boolean parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL*                       pBool
                The buffer of returned boolean value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMap_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    PDATAMODEL_MAP     pMyObject     = (PDATAMODEL_MAP)g_pWanMgrBE->hMap;
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
       *pBool = pMyObject->bEnable;
    }
    return TRUE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMap_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );
    description:
        This function is called to assign Boolean parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL*                       pBool
                Boolean value to be set;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMap_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    PDATAMODEL_MAP     pMyObject     = (PDATAMODEL_MAP)g_pWanMgrBE->hMap;
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
       pMyObject->bEnable = bValue;
    }
    return TRUE;
}
/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMap_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );
    description:
        This function is called to finally commit all the update.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 
                ULONG*                      puLength
                The output length of the param name. 
    return:     TRUE if there's no validation.
**********************************************************************/
ULONG WanMap_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    CcspTraceWarning(("%s-%d: \n",__FUNCTION__, __LINE__));
    return TRUE;
}
/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMap_Commit
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to finally commit all the update.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The status of the operation.
**********************************************************************/
ULONG WanMap_Commit(ANSC_HANDLE hInsContext)
{
    CcspTraceWarning(("%s-%d: \n",__FUNCTION__, __LINE__));
    ULONG ret = 0;
    return ret;
}
/************************************************************************
 APIs for Object: 
         MAP.Domain.{i}.
         WanMapDomain_GetEntryCount
         WanMapDomain_GetEntry
         WanMapDomain_GetParamUlongValue
         WanMapDomain_GetParamStringValue
         WanMapDomain_GetParamBoolValue
         WanMapDomain_GetParamIntValue
         WanMapDomain_SetParamUlongValue
         WanMapDomain_SetParamStringValue
         WanMapDomain_SetParamBoolValue
         WanMapDomain_SetParamIntValue
         WanMapDomain_Validate
         WanMapDomain_Commit
         WanMapDomain_Rollback
*************************************************************************/
/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapDomain_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to retrieve the count of the table.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The count of the table
**********************************************************************/
ULONG WanMapDomain_GetEntryCount(ANSC_HANDLE hInsContext)
{
    PDATAMODEL_MAP pMyObject = (PDATAMODEL_MAP)g_pWanMgrBE->hMap;

    return AnscSListQueryDepth(&pMyObject->DomainList);
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ANSC_HANDLE
        WanMapDomain_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );
    description:
        This function is called to retrieve the entry specified by the index.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                ULONG                       nIndex,
                The index of this entry;
                ULONG*                      pInsNumber
                The output instance number;
    return:     The handle to identify the entry
**********************************************************************/
ANSC_HANDLE WanMapDomain_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber)
{
    PDATAMODEL_MAP              pMyObject     = (PDATAMODEL_MAP)g_pWanMgrBE->hMap; 
    PSLIST_HEADER               pDomIfHead    = (PSLIST_HEADER)&pMyObject->DomainList;
    PCONTEXT_LINK_OBJECT        pCosaContext  = (PCONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY          pLink         = (PSINGLE_LINK_ENTRY       )NULL;

    pLink = AnscSListGetEntryByIndex(pDomIfHead, nIndex);

    if ( pLink )
    {
        pCosaContext = ACCESS_CONTEXT_LINK_OBJECT(pLink);
        *pInsNumber = pCosaContext->InstanceNumber;
    }

    return pCosaContext;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapDomain_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );
    description:
        This function is called to retrieve ULONG parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG*                      puLong
                The buffer of returned ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapDomain_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        /* collect value */
        *puLong = pMAPDomain->Info.Status;

         return TRUE;
    }

    if( AnscEqualString(ParamName, "TransportMode", TRUE))
    {
        /* collect value */
         *puLong = pMAPDomain->Info.TransportMode;

         return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapDomain_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to retrieve string parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The string value buffer;
                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;
    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.
**********************************************************************/
ULONG WanMapDomain_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pMAPDomain->Cfg.Alias);
        return 0;
    }

    if( AnscEqualString(ParamName, "WanInterface", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pMAPDomain->Cfg.WANInterface);
        return 0;
    }

    if( AnscEqualString(ParamName, "IPv6Prefix", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pMAPDomain->Cfg.IPv6Prefix);
        return 0;
    }

    if( AnscEqualString(ParamName, "BRIPv6Prefix", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pMAPDomain->Cfg.BRIPv6Prefix);
        return 0;
    }

    return -1;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapDomain_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );
    description:
        This function is called to retrieve Boolean parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL*                       pBool
                The buffer of returned boolean value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapDomain_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* collect value */
        *pBool = pMAPDomain->Cfg.bEnabled;

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        WanMapDomain_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );
    description:
        This function is called to retrieve integer parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                int*                        pInt
                The buffer of returned integer value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL
WanMapDomain_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT )hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "DSCPMarkPolicy", TRUE))
    {
        /* collect value */
         *pInt = pMAPDomain->Cfg.DSCPMarkPolicy;

         return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapDomain_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );
    description:
        This function is called to set ULONG parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG                       uValue
                The updated ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapDomain_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "TransportMode", TRUE))
    {
        /* save update to backup */
        pMAPDomain->Info.TransportMode = uValue;

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapDomain_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );
    description:
        This function is called to set string parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pString
                The updated string value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapDomain_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pMAPDomain->Cfg.Alias, pString);

        return TRUE;
    }

    if( AnscEqualString(ParamName, "WanInterface", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pMAPDomain->Cfg.WANInterface, pString);

        return TRUE;
    }

    if( AnscEqualString(ParamName, "IPv6Prefix", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pMAPDomain->Cfg.IPv6Prefix, pString);

        return TRUE;
    }

    if( AnscEqualString(ParamName, "BRIPv6Prefix", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pMAPDomain->Cfg.BRIPv6Prefix, pString);

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapDomain_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );
    description:
        This function is called to retrieve Boolean parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL                        bValue
                The buffer of returned boolean value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapDomain_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* save update to backup */
        pMAPDomain->Cfg.bEnabled = bValue;

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        WanMapDomain_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );
    description:
        This function is called to set integer parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                int                         iValue
                The updated integer value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL
WanMapDomain_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "DSCPMarkPolicy", TRUE))
    {
        /* save update to backup */
        pMAPDomain->Cfg.DSCPMarkPolicy = iValue;

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapDomain_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );
    description:
        This function is called to finally commit all the update.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 
                ULONG*                      puLength
                The output length of the param name. 
    return:     TRUE if there's no validation.
**********************************************************************/
ULONG WanMapDomain_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapDomain_Commit
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to finally commit all the update.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The status of the operation.
**********************************************************************/
ULONG WanMapDomain_Commit(ANSC_HANDLE hInsContext)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    WanDmlMapDomSetCfg(NULL, &pMAPDomain->Cfg);
    WanDmlMapDomSetInfo(NULL, pMAPDomain->Cfg.InstanceNumber, &pMAPDomain->Info);

    return 0;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapDomain_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to roll back the update whenever there's a 
        validation found.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The status of the operation.
**********************************************************************/
ULONG WanMapDomain_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}

/************************************************************************
 APIs for Object: 
         MAP.Domain.{i}.Rule.{i}.
         WanMapRule_GetEntryCount
         WanMapRule_GetEntry
         WanMapRule_GetParamUlongValue
         WanMapRule_GetParamStringValue
         WanMapRule_GetParamBoolValue
         WanMapRule_SetParamUlongValue
         WanMapRule_SetParamStringValue
         WanMapRule_SetParamBoolValue
         WanMapRule_Validate
         WanMapRule_Commit
*************************************************************************/
/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapRule_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to retrieve the count of the table.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The count of the table
**********************************************************************/
ULONG WanMapRule_GetEntryCount(ANSC_HANDLE hInsContext)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMapDomain = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    return AnscSListQueryDepth(&pMapDomain->RuleList);

}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ANSC_HANDLE
        WanMapRule_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );
    description:
        This function is called to retrieve the entry specified by the index.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                ULONG                       nIndex,
                The index of this entry;
                ULONG*                      pInsNumber
                The output instance number;
    return:     The handle to identify the entry
**********************************************************************/
ANSC_HANDLE WanMapRule_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber)
{
    PCONTEXT_LINK_OBJECT       pCosaContext     = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMapDomain       = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;
    PSINGLE_LINK_ENTRY         pLink            = (PSINGLE_LINK_ENTRY)NULL;
    PCONTEXT_LINK_OBJECT       pSubCosaContext  = (PCONTEXT_LINK_OBJECT)NULL;

    pLink = AnscSListGetEntryByIndex((PSLIST_HEADER)&pMapDomain->RuleList, nIndex);

    if ( pLink )
    {
        pSubCosaContext = ACCESS_CONTEXT_LINK_OBJECT(pLink);
        *pInsNumber = pSubCosaContext->InstanceNumber;
    }

    return pSubCosaContext;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapRule_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );
    description:
        This function is called to retrieve ULONG parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG*                      puLong
                The buffer of returned ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapRule_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_MAP_RULE          pDomainRule  = (PWAN_DML_MAP_RULE)pCosaContext->hContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomaian  = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hParentTable;

    /* Get the internal Rule data */
    WanDmlMapDomGetRule(NULL, pMAPDomaian->Cfg.InstanceNumber, (pDomainRule->InstanceNumber - 1), pDomainRule);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        /* collect value */
        *puLong = pDomainRule->Status;

         return TRUE;
    }

    if( AnscEqualString(ParamName, "EABitsLength", TRUE))
    {
        /* collect value */
        *puLong = pDomainRule->EABitsLength;

         return TRUE;
    }

    if( AnscEqualString(ParamName, "PSIDOffset", TRUE))
    {
        /* collect value */
        *puLong = pDomainRule->PSIDOffset;

         return TRUE;
    }

    if( AnscEqualString(ParamName, "PSIDLength", TRUE))
    {
        /* collect value */
        *puLong = pDomainRule->PSIDLength;

         return TRUE;
    }

    if( AnscEqualString(ParamName, "PSID", TRUE))
    {
        /* collect value */
        *puLong = pDomainRule->PSID;

         return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapRule_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to retrieve string parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The string value buffer;
                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;
    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.
**********************************************************************/
BOOL WanMapRule_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_MAP_RULE          pDomainRule  = (PWAN_DML_MAP_RULE)pCosaContext->hContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomaian  = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hParentTable;

    /* Get the internal Rule data */
    WanDmlMapDomGetRule(NULL, pMAPDomaian->Cfg.InstanceNumber, (pDomainRule->InstanceNumber - 1), pDomainRule);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pDomainRule->Alias);
        return 0;
    }

    if( AnscEqualString(ParamName, "Origin", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pDomainRule->Origin);
        return 0;
    }

    if( AnscEqualString(ParamName, "IPv6Prefix", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pDomainRule->IPv6Prefix);
        return 0;
    }

    if( AnscEqualString(ParamName, "IPv4Prefix", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pDomainRule->IPv4Prefix);
        return 0;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapRule_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );
    description:
        This function is called to retrieve Boolean parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL*                       pBool
                The buffer of returned boolean value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapRule_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_MAP_RULE          pDomainRule  = (PWAN_DML_MAP_RULE)pCosaContext->hContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomaian  = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hParentTable;

    /* Get the internal Rule data */
    WanDmlMapDomGetRule(NULL, pMAPDomaian->Cfg.InstanceNumber, (pDomainRule->InstanceNumber - 1), pDomainRule);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* collect value */
        *pBool = pDomainRule->Enable;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "IsFMR", TRUE))
    {
        /* collect value */
        *pBool = pDomainRule->IsFMR;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "IncludeSystemPorts", TRUE))
    {
        /* collect value */
        *pBool = pDomainRule->IncludeSystemPorts;

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapRule_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );
    description:
        This function is called to set ULONG parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG                       uValue
                The updated ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapRule_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_MAP_RULE          pDomainRule  = (PWAN_DML_MAP_RULE)pCosaContext->hContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomaian  = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hParentTable;

    /* Get the internal Rule data */
    WanDmlMapDomGetRule(NULL, pMAPDomaian->Cfg.InstanceNumber, (pDomainRule->InstanceNumber - 1), pDomainRule);

    if( AnscEqualString(ParamName, "EABitsLength", TRUE))
    {
        /* save update to backup */
        pDomainRule->EABitsLength = uValue;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "PSIDOffset", TRUE))
    {
        /* save update to backup */
        pDomainRule->PSIDOffset = uValue;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "PSIDLength", TRUE))
    {
        /* save update to backup */
        pDomainRule->PSIDLength = uValue;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "PSID", TRUE))
    {
        /* save update to backup */
        pDomainRule->PSID = uValue;

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapRule_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );
    description:
        This function is called to set string parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pString
                The updated string value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapRule_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_MAP_RULE          pDomainRule  = (PWAN_DML_MAP_RULE)pCosaContext->hContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomaian  = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hParentTable;

    /* Get the internal Rule data */
    WanDmlMapDomGetRule(NULL, pMAPDomaian->Cfg.InstanceNumber, (pDomainRule->InstanceNumber - 1), pDomainRule);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pDomainRule->Alias, pString);

        return TRUE;
    }
    if( AnscEqualString(ParamName, "Origin", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pDomainRule->Origin, pString);

        return TRUE;
    }

    if( AnscEqualString(ParamName, "IPv6Prefix", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pDomainRule->IPv6Prefix, pString);

        return TRUE;
    }

    if( AnscEqualString(ParamName, "IPv4Prefix", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pDomainRule->IPv4Prefix, pString);

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapRule_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );
    description:
        This function is called to retrieve Boolean parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL                        bValue
                The buffer of returned boolean value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapRule_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_MAP_RULE          pDomainRule  = (PWAN_DML_MAP_RULE)pCosaContext->hContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomaian  = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hParentTable;

    /* Get the internal Rule data */
    WanDmlMapDomGetRule(NULL, pMAPDomaian->Cfg.InstanceNumber, (pDomainRule->InstanceNumber - 1), pDomainRule);

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* save update to backup */
        pDomainRule->Enable = bValue;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "IsFMR", TRUE))
    {
        /* save update to backup */
        pDomainRule->IsFMR = bValue;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "IncludeSystemPorts", TRUE))
    {
        /* save update to backup */
        pDomainRule->IncludeSystemPorts = bValue;

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapRule_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );
    description:
        This function is called to finally commit all the update.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 
                ULONG*                      puLength
                The output length of the param name. 
    return:     TRUE if there's no validation.
**********************************************************************/
ULONG WanMapRule_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapRule_Commit
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to finally commit all the update.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The status of the operation.
**********************************************************************/
ULONG WanMapRule_Commit(ANSC_HANDLE hInsContext)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_MAP_RULE          pDomainRule  = (PWAN_DML_MAP_RULE)pCosaContext->hContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomaian  = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hParentTable;

    /* Set the internal Rule data */
    WanDmlMapDomSetRule(NULL, pMAPDomaian->Cfg.InstanceNumber, (pDomainRule->InstanceNumber -1), pDomainRule);
    return 0;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapRule_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to roll back the update whenever there's a 
        validation found.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The status of the operation.
**********************************************************************/
ULONG WanMapRule_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}

/************************************************************************
 APIs for Object: 
         MAP.Domain.{i}.Interface.
         WanMapInterface_GetParamUlongValue
         WanMapInterface_GetParamStringValue
         WanMapInterface_GetParamBoolValue
         WanMapInterface_SetParamUlongValue
         WanMapInterface_SetParamStringValue
         WanMapInterface_SetParamBoolValue
         WanMapInterface_Validate
         WanMapInterface_Commit
         WanMapInterface_Rollback
*************************************************************************/
/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapInterface_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );
    description:
        This function is called to retrieve ULONG parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG*                      puLong
                The buffer of returned ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapInterface_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        /* collect value */
        *puLong = pMAPDomain->Info.IfaceStatus;

         return TRUE;
    }

    if( AnscEqualString(ParamName, "LastChange", TRUE))
    {
        /* collect value */
        *puLong = pMAPDomain->Info.IfaceLastChange;

         return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapInterface_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to retrieve string parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The string value buffer;
                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;
    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.
**********************************************************************/
ULONG WanMapInterface_GetParamStringValue(ANSC_HANDLE hInsContext,char* ParamName, char* pValue, ULONG* pUlSize)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pMAPDomain->Cfg.IfaceAlias);

        return 0;
    }

    if( AnscEqualString(ParamName, "Name", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pMAPDomain->Info.IfaceName);

        return 0;
    }

    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pMAPDomain->Cfg.IfaceLowerLayers);

        return 0;
    }

    return -1;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapInterface_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );
    description:
        This function is called to retrieve Boolean parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL*                       pBool
                The buffer of returned boolean value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapInterface_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* collect value */
        *pBool = pMAPDomain->Cfg.IfaceEnable;

        return TRUE;
    }

    return FALSE;
}
/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapInterface_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );
    description:
        This function is called to set ULONG parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG                       uValue
                The updated ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapInterface_SetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(uValue);

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapInterface_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );
    description:
        This function is called to set string parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pString
                The updated string value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapInterface_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* pString)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pMAPDomain->Cfg.IfaceAlias, pString);

        return TRUE;
    }

    if( AnscEqualString(ParamName, "Name", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pMAPDomain->Info.IfaceName, pString);

        return TRUE;
    }

    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pMAPDomain->Cfg.IfaceLowerLayers, pString);

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapInterface_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );
    description:
        This function is called to retrieve Boolean parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL                        bValue
                The buffer of returned boolean value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapInterface_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    /* Get the internal Domain data */
    WanDmlMapDomGetEntry(NULL, (pMAPDomain->Cfg.InstanceNumber -1), (PWAN_DML_DOMAIN_FULL)pMAPDomain);

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* save update to backup */
        pMAPDomain->Cfg.IfaceEnable = bValue;

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapInterface_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );
    description:
        This function is called to finally commit all the update.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 
                ULONG*                      puLength
                The output length of the param name. 
    return:     TRUE if there's no validation.
**********************************************************************/
ULONG WanMapInterface_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    return TRUE;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapInterface_Commit
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to finally commit all the update.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The status of the operation.
**********************************************************************/
ULONG WanMapInterface_Commit(ANSC_HANDLE hInsContext)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT)hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;

    WanDmlMapDomSetCfg(NULL, &pMAPDomain->Cfg);
    WanDmlMapDomSetInfo(NULL, pMAPDomain->Cfg.InstanceNumber, &pMAPDomain->Info);

    return 0;
}

/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        ULONG
        WanMapInterface_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is called to roll back the update whenever there's a 
        validation found.
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
    return:     The status of the operation.
**********************************************************************/
ULONG WanMapInterface_Rollback(ANSC_HANDLE hInsContext)
{
    return 0;
}

/************************************************************************
 APIs for Object: 
         MAP.Domain.{i}.Interface.Stats.
         WanMapStats_GetParamUlongValue
*************************************************************************/
/**********************************************************************  
    caller:     owner of this object 
    prototype: 
        BOOL
        WanMapStats_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );
    description:
        This function is called to retrieve ULONG parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG*                      puLong
                The buffer of returned ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL WanMapStats_GetParamUlongValue(ANSC_HANDLE hInsContext, char* ParamName, ULONG* puLong)
{
    PCONTEXT_LINK_OBJECT       pCosaContext = (PCONTEXT_LINK_OBJECT )hInsContext;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain   = (PWAN_DML_DOMAIN_FULL2)pCosaContext->hContext;
    WAN_DML_INTERFACE_STAT     Stats        = {0};

    if (!pMAPDomain || !pMAPDomain->Info.IfaceName || strlen(pMAPDomain->Info.IfaceName) == 0)
    {
        *puLong = 0;  // Return default safe value
        return TRUE;
    }

    if (WanDmlMapDomGetIfStats(pMAPDomain->Info.IfaceName, &Stats) != 1)
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "BytesSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.BytesSent;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "BytesReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.BytesReceived;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "PacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.PacketsSent;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "PacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.PacketsReceived;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "ErrorsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.ErrorsSent;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "ErrorsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.ErrorsReceived;

        return (TRUE);
    }
     if( AnscEqualString(ParamName, "UnicastPacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.UnicastPacketsSent;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "UnicastPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.UnicastPacketsReceived;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "DiscardPacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.DiscardPacketsSent;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "DiscardPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.DiscardPacketsReceived;

        return (TRUE);
    }
     if( AnscEqualString(ParamName, "MulticastPacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.MulticastPacketsSent;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "MulticastPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.MulticastPacketsReceived;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "BroadcastPacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.BroadcastPacketsSent;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "BroadcastPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.BroadcastPacketsReceived;

        return (TRUE);
    }

    if( AnscEqualString(ParamName, "UnknownProtoPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.UnknownProtoPacketsReceived;

        return (TRUE);
    }

    return (FALSE);
}
