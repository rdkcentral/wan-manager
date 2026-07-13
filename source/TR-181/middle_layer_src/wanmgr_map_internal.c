/*********************************************************************************
 If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 Deutsche Telekom AG
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
#include "wanmgr_map_apis.h"
#include "wanmgr_map_internal.h"
#include "wanmgr_plugin_main_apis.h"
#include "poam_irepfo_interface.h"

extern void * g_pDslhDmlAgent;

/**************************************************************************
    module: wan_map_internal.c
        For COSA Data Model Library Development
    -------------------------------------------------------------------
    description:
        This file implementes back-end apis for the COSA Data Model Library
        *  WanMgr_MapCreate
        *  WanMgr_MapInitialize
        *  WanMgr_MapRemove
**************************************************************************/

/* Common Headers */

/**********************************************************************
    caller:     owner of the object
    prototype:
        ANSC_HANDLE
        WanMgr_MapCreate
            (
            );
    description:
        This function constructs cosa nat object and return handle.
    argument:  
    return:     newly created nat object.
**********************************************************************/
ANSC_HANDLE
WanMgr_MapCreate
    (
        VOID
    )
{
    ANSC_STATUS    returnStatus = ANSC_STATUS_SUCCESS;
    PDATAMODEL_MAP pMyObject    = (PDATAMODEL_MAP)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
    */
    pMyObject = (PDATAMODEL_MAP)AnscAllocateMemory(sizeof(DATAMODEL_MAP));

    if ( !pMyObject )
    {
        return  ((ANSC_HANDLE)NULL);
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    //pMyObject->Oid               = WAN_MAP_DATA_OID;
    pMyObject->Create            = WanMgr_MapCreate;
    pMyObject->Remove            = WanMgr_MapRemove;
    pMyObject->Initialize        = WanMgr_MapInitialize;

    pMyObject->Initialize((ANSC_HANDLE)pMyObject);

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************
    caller:     self
    prototype:
        ANSC_STATUS
        WanMgr_MapInitialize
            (
                ANSC_HANDLE                 hThisObject
            );
    description:
        This function initiate  cosa nat object and return handle.
    argument:    ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.
    return:     operation status.
**********************************************************************/
ANSC_STATUS
WanMgr_MapInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                returnStatus                 = ANSC_STATUS_SUCCESS;
    PDATAMODEL_MAP             pMyObject                    = (PDATAMODEL_MAP)hThisObject;
    PPOAM_IREP_FOLDER_OBJECT   pPoamIrepFoCOSA              = (PPOAM_IREP_FOLDER_OBJECT)NULL;
    PPOAM_IREP_FOLDER_OBJECT   pPoamIrepFoMapDom            = (PPOAM_IREP_FOLDER_OBJECT)NULL;
    PPOAM_IREP_FOLDER_OBJECT   pPoamIrepFoNextIns           = (PPOAM_IREP_FOLDER_OBJECT)NULL;
    PSLAP_VARIABLE             pSlapVariable                = (PSLAP_VARIABLE          )NULL;
    PWAN_DML_DOMAIN_FULL2      pMAPDomain                   = (PWAN_DML_DOMAIN_FULL2   )NULL;
    PWAN_DML_MAP_RULE          pRule                        = (PWAN_DML_MAP_RULE       )NULL;
    PCONTEXT_LINK_OBJECT       pCosaContext                 = (PCONTEXT_LINK_OBJECT    )NULL;
    PCONTEXT_LINK_OBJECT       pSubCosaContext              = (PCONTEXT_LINK_OBJECT    )NULL;
    CHAR                       FolderName[DML_BUFF_SIZE_32] = {0};
    ULONG                      ulEntryCount                 = 0;
    ULONG                      ulIndex                      = 0;
    ULONG                      ulSubEntryCount              = 0;
    ULONG                      ulSubIndex                   = 0;

    /* Initiation all functions */
    pMyObject->bEnable                      = TRUE;
    pMyObject->ulDomainCount                = 0;
    pMyObject->ulNextDomainInsNum           = 1;

    AnscSListInitializeHeader(&pMyObject->DomainList)

    pMyObject->hIrepFolderCOSA = g_GetRegistryRootFolder(g_pDslhDmlAgent);

    pPoamIrepFoCOSA = (PPOAM_IREP_FOLDER_OBJECT)pMyObject->hIrepFolderCOSA;
    if ( !pPoamIrepFoCOSA )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto  EXIT;
    }

    pPoamIrepFoMapDom = (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoCOSA->GetFolder
                        (
                            (ANSC_HANDLE)pPoamIrepFoCOSA,
                            MAP_DOMAIN_IREP_FOLDER_NAME
                        );

    if ( !pPoamIrepFoMapDom )
    {
        pPoamIrepFoMapDom = pPoamIrepFoCOSA->AddFolder
                            (
                                (ANSC_HANDLE)pPoamIrepFoCOSA,
                                MAP_DOMAIN_IREP_FOLDER_NAME,
                                0
                            );
    }

    if ( !pPoamIrepFoMapDom )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto  EXIT;
    }
    else
    {        
        pMyObject->hIrepFolderMapDomain = (ANSC_HANDLE)pPoamIrepFoMapDom;
    }

    /* Retrieve the next Instance Number for MAP Domain */
    if ( TRUE )
    {
        _ansc_sprintf
        (
            FolderName, 
            "%s%d", 
            COSA_DML_RR_NAME_DOMAIN_NextInsNum,
            0
        );

        pPoamIrepFoNextIns = (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoMapDom->GetFolder
                                (
                                    (ANSC_HANDLE)pPoamIrepFoMapDom,
                                    FolderName
                                );

        AnscZeroMemory(FolderName, DML_BUFF_SIZE_32);

        if ( pPoamIrepFoNextIns )
        {
            pSlapVariable = (PSLAP_VARIABLE)pPoamIrepFoNextIns->GetRecord
                                (
                                    (ANSC_HANDLE)pPoamIrepFoNextIns,
                                    COSA_DML_RR_NAME_DOMAIN_NextInsNum,
                                    NULL
                                );

            if ( pSlapVariable )
            {
                pMyObject->ulNextDomainInsNum = pSlapVariable->Variant.varUint32;

                SlapFreeVariable(pSlapVariable);
            }

            pPoamIrepFoNextIns->Remove((ANSC_HANDLE)pPoamIrepFoNextIns);
            pPoamIrepFoNextIns = NULL;
        }
    }

    /* Initialize middle layer for Device.MAP.Domain.{i}.  */

    ulEntryCount = WanDmlMapDomGetNumberOfEntries(pMyObject->hSbContext);

    for ( ulIndex = 0; ulIndex < ulEntryCount; ulIndex++ )
    {
        pMAPDomain = (PWAN_DML_DOMAIN_FULL2)AnscAllocateMemory(sizeof(WAN_DML_DOMAIN_FULL2));

        if ( !pMAPDomain )
        {
            returnStatus = ANSC_STATUS_RESOURCES;

            goto  EXIT;
        }

        AnscSListInitializeHeader(&pMAPDomain->RuleList);

        pMAPDomain->ulNextRuleInsNum = 1;

        WanDmlMapDomGetEntry(pMyObject->hSbContext, ulIndex, (PWAN_DML_DOMAIN_FULL)pMAPDomain);

        if ( TRUE )
        {
            pCosaContext = (PCONTEXT_LINK_OBJECT)AnscAllocateMemory(sizeof(CONTEXT_LINK_OBJECT));

            if ( !pCosaContext )
            {
                AnscFreeMemory(pMAPDomain);               

                returnStatus = ANSC_STATUS_RESOURCES;

                goto  EXIT;
            }

            if ( 0 != pMAPDomain->Cfg.InstanceNumber )
            {
                pCosaContext->InstanceNumber = pMAPDomain->Cfg.InstanceNumber;

                if ( pMyObject->ulNextDomainInsNum <=  pMAPDomain->Cfg.InstanceNumber )
                {
                    pMyObject->ulNextDomainInsNum =  pMAPDomain->Cfg.InstanceNumber + 1;

                    if ( 0 == pMyObject->ulNextDomainInsNum )
                    {
                        pMyObject->ulNextDomainInsNum = 1;
                    }
                }
            }
            else
            {
                pCosaContext->InstanceNumber = pMyObject->ulNextDomainInsNum;  

                pMAPDomain->Cfg.InstanceNumber = pCosaContext->InstanceNumber ;

                pMyObject->ulNextDomainInsNum++;

                if ( 0 == pMyObject->ulNextDomainInsNum )
                {
                    pMyObject->ulNextDomainInsNum = 1;
                }
            }

            pCosaContext->hContext      = (ANSC_HANDLE)pMAPDomain;            
            pCosaContext->hParentTable  = NULL;            
            pCosaContext->bNew          = FALSE;

            SListPushEntryByInsNum(&pMyObject->DomainList, pCosaContext);
        }

        /* Initialize middle layer for Device.MAP.Domain.{i}.Rule.{i}. */
        if ( TRUE )
        {
            _ansc_sprintf
            (
                FolderName, 
                "%s%d", 
                COSA_DML_RR_NAME_RULE_NextInsNum, 
                pMAPDomain->Cfg.InstanceNumber
            );

            pPoamIrepFoNextIns = 
                (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoMapDom->GetFolder
                    (
                        (ANSC_HANDLE)pPoamIrepFoMapDom,
                        FolderName
                    );

            if ( pPoamIrepFoNextIns )
            {
                pSlapVariable =
                    (PSLAP_VARIABLE)pPoamIrepFoNextIns->GetRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoNextIns,
                            COSA_DML_RR_NAME_RULE_NextInsNum,
                            NULL
                        );

                if ( pSlapVariable )
                {
                    pMAPDomain->ulNextRuleInsNum = pSlapVariable->Variant.varUint32;

                    SlapFreeVariable(pSlapVariable);
                }

                pPoamIrepFoNextIns->Remove((ANSC_HANDLE)pPoamIrepFoNextIns);
                pPoamIrepFoNextIns = NULL;
            } 
        }

        ulSubEntryCount = WanDmlMapDomGetNumberOfRules(pMyObject->hSbContext, pMAPDomain->Cfg.InstanceNumber);

        for ( ulSubIndex = 0; ulSubIndex < ulSubEntryCount; ulSubIndex++ )
        {
            pRule = (PWAN_DML_MAP_RULE)AnscAllocateMemory(sizeof(WAN_DML_MAP_RULE));

            if ( !pRule )
            {
                returnStatus = ANSC_STATUS_RESOURCES;

                goto  EXIT;
            }

            WanDmlMapDomGetRule(pMyObject->hSbContext, pMAPDomain->Cfg.InstanceNumber, ulSubIndex, pRule);

            if ( TRUE )
            {
                pSubCosaContext = (PCONTEXT_LINK_OBJECT)AnscAllocateMemory(sizeof(CONTEXT_LINK_OBJECT));

                if ( !pSubCosaContext )
                {
                    AnscFreeMemory(pRule);

                    returnStatus = ANSC_STATUS_RESOURCES;

                    goto  EXIT;  
                }

                if ( 0 != pRule->InstanceNumber )
                {
                    pSubCosaContext->InstanceNumber = pRule->InstanceNumber;

                    if ( pMAPDomain->ulNextRuleInsNum <= pRule->InstanceNumber )
                    {
                        pMAPDomain->ulNextRuleInsNum = pRule->InstanceNumber + 1;

                        if ( pMAPDomain->ulNextRuleInsNum == 0 )
                        {
                            pMAPDomain->ulNextRuleInsNum = 1;
                        }
                    }  
                }
                else
                {
                    pSubCosaContext->InstanceNumber = pRule->InstanceNumber = pMAPDomain->ulNextRuleInsNum;

                    pMAPDomain->ulNextRuleInsNum++;

                    if ( pMAPDomain->ulNextRuleInsNum == 0 )
                    {
                        pMAPDomain->ulNextRuleInsNum = 1;
                    }

                    /* Generate Alias */
                    _ansc_sprintf(pRule->Alias, "Rule%d", pSubCosaContext->InstanceNumber);
                }

                pSubCosaContext->hContext     = (ANSC_HANDLE)pRule;
                pSubCosaContext->hParentTable = (ANSC_HANDLE)pMAPDomain;
                pSubCosaContext->bNew         = FALSE;

                SListPushEntryByInsNum(&pMAPDomain->RuleList, pSubCosaContext);
            }
        }
    }

    EXIT:

    return returnStatus;
}

/**********************************************************************
    caller:     self
    prototype:
        ANSC_STATUS
        WanMgr_MapRemove
            (
                ANSC_HANDLE                 hThisObject
            );
    description:
        This function initiate  cosa nat object and return handle.
    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.
    return:     operation status.
**********************************************************************/
ANSC_STATUS
WanMgr_MapRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    /* Add logic here */
    return returnStatus;
}
