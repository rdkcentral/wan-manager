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

/**************************************************************************

    module: wan_dhcpv4_internal.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

        *  WanMgr_Dhcpv4Create
        *  WanMgr_Dhcpv4Initialize
        *  WanMgr_Dhcpv4Remove
        *  WanMgr_Dhcpv4RegGetDhcpv4Info
        *  WanMgr_Dhcpv4RegSetDhcpv4Info
        *  WanMgr_Dhcpv4ClientHasDelayAddedChild

**************************************************************************/
#include "wanmgr_apis.h"
#include "wanmgr_dhcpv4_apis.h"
#include "wanmgr_dhcpv4_internal.h"
#include "wanmgr_plugin_main_apis.h"
#include "poam_irepfo_interface.h"
#include "sys_definitions.h"

extern void * g_pDslhDmlAgent;
PWAN_DHCPV4_DATA g_pDhcpv4;


/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        WanMgr_Dhcpv4Create
            (
            );

    description:

        This function constructs cosa nat object and return handle.

    argument:  

    return:     newly created nat object.

**********************************************************************/

ANSC_HANDLE WanMgr_Dhcpv4Create ( VOID )
{
    ANSC_STATUS       returnStatus  =  ANSC_STATUS_SUCCESS;
	PWAN_DHCPV4_DATA  pMyObject     =  (PWAN_DHCPV4_DATA) NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
    */
    pMyObject = (PWAN_DHCPV4_DATA)AnscAllocateMemory(sizeof(WAN_DHCPV4_DATA));
    if ( pMyObject == NULL )
    {
        return  (ANSC_HANDLE)NULL;
    }
    /*
     * Initialize the common variables and functions for a container object.
    */
    pMyObject->Oid               = WAN_DHCPV4_DATA_OID;
    pMyObject->Create            = WanMgr_Dhcpv4Create;
    pMyObject->Remove            = WanMgr_Dhcpv4Remove;
    pMyObject->Initialize        = WanMgr_Dhcpv4Initialize;

    pMyObject->Initialize((ANSC_HANDLE)pMyObject);

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        WanMgr_Dhcpv4Initialize
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

ANSC_STATUS WanMgr_Dhcpv4Initialize ( ANSC_HANDLE hThisObject )
{
    ANSC_STATUS               returnStatus      = ANSC_STATUS_SUCCESS;
    PWAN_DHCPV4_DATA          pMyObject         = (PWAN_DHCPV4_DATA) hThisObject;

    if (pMyObject == NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
        /* Initiation all functions */
        AnscSListInitializeHeader( &pMyObject->ClientList );
        pMyObject->maxInstanceOfClient  = 0;
        AnscZeroMemory(pMyObject->AliasOfClient, sizeof(pMyObject->AliasOfClient));

        /* We need get NextInstanceNumber from backend. By the way, the whole tree 
           was created. Moreover, we also need get delay-added entry and put them
           into our tree. */
        WanMgr_Dhcpv4RegGetDhcpv4Info((ANSC_HANDLE)pMyObject);

        /* Firstly we create the whole system from backend */
        WanMgr_Dhcpv4BackendGetDhcpv4Info((ANSC_HANDLE)pMyObject);

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        WanMgr_Dhcpv4Remove
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

ANSC_STATUS WanMgr_Dhcpv4Remove ( ANSC_HANDLE hThisObject )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PWAN_DHCPV4_DATA           pMyObject      = (PWAN_DHCPV4_DATA)hThisObject;

    PDHCPC_CONTEXT_LINK_OBJECT pCxtDhcpcLink       = NULL;
    PCONTEXT_LINK_OBJECT       pCxtLink            = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry         = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry2        = NULL;

    /* Remove necessary resource */
    
    if (pMyObject != NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
        pSListEntry         = AnscSListPopEntry(&pMyObject->ClientList);
        while( pSListEntry != NULL)
        {
            pCxtDhcpcLink     = ACCESS_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
            pSListEntry       = AnscSListGetNextEntry(pSListEntry);

            pSListEntry2         = AnscSListPopEntry(&pCxtDhcpcLink->SendOptionList);
            while( pSListEntry2 != NULL)
            {
                pCxtLink         = ACCESS_CONTEXT_LINK_OBJECT(pSListEntry2);
                pSListEntry2       = AnscSListGetNextEntry(pSListEntry2);

                AnscFreeMemory(pCxtLink->hContext);
                AnscFreeMemory(pCxtLink);
            }

            pSListEntry2         = AnscSListPopEntry(&pCxtDhcpcLink->ReqOptionList);
            while( pSListEntry2 != NULL)
            {
                pCxtLink         = ACCESS_CONTEXT_LINK_OBJECT(pSListEntry2);
                pSListEntry2       = AnscSListGetNextEntry(pSListEntry2);

                AnscFreeMemory(pCxtLink->hContext);
                AnscFreeMemory(pCxtLink);
            }

            AnscFreeMemory(pCxtDhcpcLink->hContext);
            AnscFreeMemory(pCxtDhcpcLink);
    }

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        WanMgr_Dhcpv4RegGetDhcpv4Info
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the NextInstanceNumber for every table, Create
        the link tree. For delay_added entry, we also need create them.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of dhcpv4
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS WanMgr_Dhcpv4BackendGetDhcpv4Info (ANSC_HANDLE hThisObject)
{
    ANSC_STATUS                returnStatus      = ANSC_STATUS_SUCCESS;    
    PWAN_DHCPV4_DATA           pDhcpv4           = (PWAN_DHCPV4_DATA)hThisObject;

    PDML_DHCPC_FULL            pDhcpc            = NULL;
    PDML_DHCPC_REQ_OPT         pReqOption        = NULL;
    PCOSA_DML_DHCP_OPT         pSendOption       = NULL;
    ULONG                      clientCount       = 0;
    ULONG                      count             = 0;
    ULONG                      ulIndex           = 0;
    ULONG                      ulIndex2          = 0;

    PDHCPC_CONTEXT_LINK_OBJECT pClientCxtLink    = NULL;    
    PDHCPC_CONTEXT_LINK_OBJECT pClientCxtLink2   = NULL;       
    PCONTEXT_LINK_OBJECT       pCxtLink          = NULL;
    PCONTEXT_LINK_OBJECT       pCxtLink2         = NULL;
    BOOL                       bNeedSave         = FALSE;

    /* Get DHCPv4.Client.{i} */
    clientCount = WanMgr_DmlDhcpcGetNumberOfEntries(NULL);
    for ( ulIndex = 0; ulIndex < clientCount; ulIndex++ )
    {
        pDhcpc  = (PDML_DHCPC_FULL)AnscAllocateMemory( sizeof(DML_DHCPC_FULL) );
        if ( !pDhcpc )
        {
            break;
        }

        DHCPV4_CLIENT_SET_DEFAULTVALUE(pDhcpc);
        returnStatus = WanMgr_DmlDhcpcGetEntry(NULL, ulIndex, pDhcpc);
        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            AnscFreeMemory(pDhcpc);
            break;
        }

        pClientCxtLink = (PDHCPC_CONTEXT_LINK_OBJECT)AnscAllocateMemory( sizeof(DHCPC_CONTEXT_LINK_OBJECT) );
        if ( !pClientCxtLink )
        {
            AnscFreeMemory(pDhcpc);
            break;
        }

        DHCPV4_CLIENT_INITIATION_CONTEXT(pClientCxtLink)
        pClientCxtLink->hContext       = (ANSC_HANDLE)pDhcpc;
        pClientCxtLink->bNew           = FALSE;

        if ( !pDhcpc->Cfg.InstanceNumber )
        {
            if ( !++pDhcpv4->maxInstanceOfClient )
            {
                pDhcpv4->maxInstanceOfClient = 1;
            }
            bNeedSave                        = TRUE;

            pDhcpc->Cfg.InstanceNumber     = pDhcpv4->maxInstanceOfClient;
            pClientCxtLink->InstanceNumber = pDhcpc->Cfg.InstanceNumber;
            
            _ansc_sprintf(pDhcpc->Cfg.Alias, "DHCPv4%lu", pDhcpc->Cfg.InstanceNumber);

            returnStatus = WanMgr_DmlDhcpcSetValues
                            (
                                NULL, 
                                ulIndex,
                                pDhcpc->Cfg.InstanceNumber, 
                                pDhcpc->Cfg.Alias
                            );

            if ( returnStatus != ANSC_STATUS_SUCCESS )
            {
                AnscFreeMemory(pDhcpc);
                AnscFreeMemory(pClientCxtLink);
                break;
            }

            /* Put into our list */
            SListPushEntryByInsNum(&pDhcpv4->ClientList, (PCONTEXT_LINK_OBJECT)pClientCxtLink);
        }
        else
        {
            pClientCxtLink->InstanceNumber = pDhcpc->Cfg.InstanceNumber;

            /* This case never happen. Add it just for simulation code run well */
            if ( pDhcpv4->maxInstanceOfClient < pClientCxtLink->InstanceNumber )
            {
                pDhcpv4->maxInstanceOfClient = pClientCxtLink->InstanceNumber;
                bNeedSave                    = TRUE;
            }

            /* if this entry is in link tree already because it's the parent of delay_added table */
            pClientCxtLink2 = (PDHCPC_CONTEXT_LINK_OBJECT)SListGetEntryByInsNum(&pDhcpv4->ClientList, pClientCxtLink->InstanceNumber);
            if ( !pClientCxtLink2 )
            {
                SListPushEntryByInsNum(&pDhcpv4->ClientList, (PCONTEXT_LINK_OBJECT)pClientCxtLink);
            }
            else
            {
                AnscFreeMemory( pClientCxtLink2->hContext );
                pClientCxtLink2->hContext       = (ANSC_HANDLE)pDhcpc;
                if ( pClientCxtLink2->bNew )
                {
                    pClientCxtLink2->bNew       = FALSE;
                    bNeedSave                   = TRUE;
                }
                
                AnscFreeMemory(pClientCxtLink);
                pClientCxtLink                  = pClientCxtLink2;
                pClientCxtLink2                 = NULL;
            }            
        }

        /* We begin treat DHCPv4.Client.{i}.ReqOption.{i} */
        count = WanMgr_DmlDhcpcGetNumberOfReqOption
                    (
                        NULL,
                        pDhcpc->Cfg.InstanceNumber
                    );
        
        for ( ulIndex2 = 0; ulIndex2 < count; ulIndex2++ )
        {
            pReqOption  = (PDML_DHCPC_REQ_OPT)AnscAllocateMemory( sizeof(DML_DHCPC_REQ_OPT) );
            if ( !pReqOption )
            {
                break;
            }
        
            DHCPV4_REQOPTION_SET_DEFAULTVALUE(pReqOption);
            returnStatus = WanMgr_DmlDhcpcGetReqOption
                            (
                                NULL, 
                                pDhcpc->Cfg.InstanceNumber, 
                                ulIndex2, 
                                pReqOption
                            );
            if ( returnStatus != ANSC_STATUS_SUCCESS )
            {
                AnscFreeMemory(pReqOption);
                break;
            }
        
            pCxtLink = (PCONTEXT_LINK_OBJECT)AnscAllocateMemory( sizeof(CONTEXT_LINK_OBJECT) );
            if ( !pCxtLink )
            {
                AnscFreeMemory(pReqOption);
                break;
            }
        
            CONTEXT_LINK_INITIATION_CONTENT(pCxtLink);
            pCxtLink->hContext       = (ANSC_HANDLE)pReqOption;
            pCxtLink->hParentTable   = (ANSC_HANDLE)pClientCxtLink;
            pCxtLink->bNew           = FALSE;
        
            if ( !pReqOption->InstanceNumber )
            {
                if ( !++pClientCxtLink->maxInstanceOfReq )
                {
                    pClientCxtLink->maxInstanceOfReq = 1;
                }
                bNeedSave                        = TRUE;

                pReqOption->InstanceNumber = pClientCxtLink->maxInstanceOfReq;
        
                _ansc_sprintf( pReqOption->Alias, "ReqOption%lu", pReqOption->InstanceNumber );
        
                returnStatus = WanMgr_DmlDhcpcSetReqOptionValues
                                (
                                    NULL,
                                    pDhcpc->Cfg.InstanceNumber,
                                    ulIndex, 
                                    pReqOption->InstanceNumber, 
                                    pReqOption->Alias
                                );
        
                if ( returnStatus != ANSC_STATUS_SUCCESS )
                {
                    AnscFreeMemory(pReqOption);
                    AnscFreeMemory(pCxtLink);
                    break;                    
                }
                pCxtLink->InstanceNumber = pReqOption->InstanceNumber; 
                
                /* Put into our list */
                SListPushEntryByInsNum(&pClientCxtLink->ReqOptionList, (PCONTEXT_LINK_OBJECT)pCxtLink);
            } 
            else
            {
                 pCxtLink->InstanceNumber = pReqOption->InstanceNumber; 
                
                /* This case never happen. Add it just for simulation code run well */
                if ( pClientCxtLink->maxInstanceOfReq < pReqOption->InstanceNumber )
                {
                    pClientCxtLink->maxInstanceOfReq = pReqOption->InstanceNumber;
                    bNeedSave                  = TRUE;
                }

                /* if this entry is in link tree already because it's  delay_added table */
                pCxtLink2 = (PCONTEXT_LINK_OBJECT)SListGetEntryByInsNum(&pClientCxtLink->ReqOptionList, pReqOption->InstanceNumber);
                if ( !pCxtLink2 )
                {
                    SListPushEntryByInsNum(&pClientCxtLink->ReqOptionList, (PCONTEXT_LINK_OBJECT)pCxtLink);
                }
                else
                {
                    AnscFreeMemory( pCxtLink2->hContext );                
                    pCxtLink2->hContext       = (ANSC_HANDLE)pSendOption;
                    if ( pCxtLink2->bNew )
                    {
                        pCxtLink2->bNew       = FALSE;
                        bNeedSave             = TRUE;
                    }
                    
                    AnscFreeMemory(pCxtLink);
                    AnscFreeMemory(pReqOption);
                    pCxtLink                  = pCxtLink2;
                    pCxtLink2                 = NULL;
                }
                
            }
        }

        /* We begin treat DHCPv4.Client.{i}.SentOption.{i} */
        count = WanMgr_DmlDhcpcGetNumberOfSentOption
                    (
                        NULL,
                        pDhcpc->Cfg.InstanceNumber
                    );
        
        for ( ulIndex2 = 0; ulIndex2 < count; ulIndex2++ )
        {
            pSendOption  = (PCOSA_DML_DHCP_OPT)AnscAllocateMemory( sizeof(COSA_DML_DHCP_OPT) );
            if ( !pSendOption )
            {
                break;
            }
        
            DHCPV4_SENDOPTION_SET_DEFAULTVALUE(pSendOption);
            returnStatus = WanMgr_DmlDhcpcGetSentOption
                            (
                                NULL, 
                                pDhcpc->Cfg.InstanceNumber, 
                                ulIndex2, 
                                pSendOption
                            );
            if ( returnStatus != ANSC_STATUS_SUCCESS )
            {
                AnscFreeMemory(pSendOption);
                break;
            }
        
            pCxtLink = (PCONTEXT_LINK_OBJECT)AnscAllocateMemory( sizeof(CONTEXT_LINK_OBJECT) );
            if ( !pCxtLink )
            {
                AnscFreeMemory(pSendOption);
                break;
            }
        
            CONTEXT_LINK_INITIATION_CONTENT(pCxtLink);
            pCxtLink->hContext       = (ANSC_HANDLE)pSendOption;
            pCxtLink->hParentTable   = (ANSC_HANDLE)pClientCxtLink;
            pCxtLink->bNew           = FALSE;
        
            if ( !pSendOption->InstanceNumber )
            {
                if ( !++pClientCxtLink->maxInstanceOfSend )
                {
                    pClientCxtLink->maxInstanceOfSend = 1;
                    bNeedSave                  = TRUE;
                }
                bNeedSave                        = TRUE;
                pSendOption->InstanceNumber = pClientCxtLink->maxInstanceOfSend;

                _ansc_sprintf( pSendOption->Alias, "SentOption%lu", pSendOption->InstanceNumber );
        
                returnStatus = WanMgr_DmlDhcpcSetSentOptionValues
                                (
                                    NULL,
                                    pDhcpc->Cfg.InstanceNumber,
                                    ulIndex, 
                                    pSendOption->InstanceNumber, 
                                    pSendOption->Alias
                                );
        
                if ( returnStatus != ANSC_STATUS_SUCCESS )
                {
                    AnscFreeMemory(pSendOption);
                    AnscFreeMemory(pCxtLink);
                    break;                    
                }

                pCxtLink->InstanceNumber = pSendOption->InstanceNumber; 
            
                /* Put into our list */
                SListPushEntryByInsNum(&pClientCxtLink->SendOptionList, (PCONTEXT_LINK_OBJECT)pCxtLink);
                
            } 
            else
            {
                pCxtLink->InstanceNumber = pSendOption->InstanceNumber; 
                
                /* This case never happen. Add it just for simulation code run well */
                if ( pClientCxtLink->maxInstanceOfSend < pSendOption->InstanceNumber )
                {
                    pClientCxtLink->maxInstanceOfSend = pSendOption->InstanceNumber;
                }

                /* if this entry is in link tree already because it's  delay_added table */
                pCxtLink2 = (PCONTEXT_LINK_OBJECT)SListGetEntryByInsNum(&pClientCxtLink->SendOptionList, pSendOption->InstanceNumber);
                if ( !pCxtLink2 )
                {
                    SListPushEntryByInsNum(&pClientCxtLink->SendOptionList, (PCONTEXT_LINK_OBJECT)pCxtLink);
                }
                else
                {
                    AnscFreeMemory( pCxtLink2->hContext );                
                    pCxtLink2->hContext       = (ANSC_HANDLE)pSendOption;
                    if ( pCxtLink2->bNew )
                    {
                        pCxtLink2->bNew       = FALSE;
                        bNeedSave             = TRUE;
                    }

                    AnscFreeMemory(pCxtLink);
                    pCxtLink                  = pCxtLink2;
                    pCxtLink2                 = NULL;
                }            

            }
        }
    }

    /* Max InstanceNumber is changed. Save now.*/
    if (bNeedSave)
    {
        WanMgr_Dhcpv4RegSetDhcpv4Info(pDhcpv4);
    }

    return returnStatus;    
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        WanMgr_Dhcpv4RegGetDhcpv4Info
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve backend inform and put them into our trees.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of dhcpv4
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
WanMgr_Dhcpv4RegGetDhcpv4Info
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PWAN_DHCPV4_DATA          pMyObject         = (PWAN_DHCPV4_DATA   )hThisObject;
    
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoDhcpv4 = (PPOAM_IREP_FOLDER_OBJECT )pMyObject->hIrepFolderDhcpv4;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoClient = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoReqOpt = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoSndOpt = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoEnumClient       = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoEnumReqOpt       = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoEnumSndOpt       = (PPOAM_IREP_FOLDER_OBJECT )NULL;

    PDHCPC_CONTEXT_LINK_OBJECT pDhcpcContext = NULL;
    PCONTEXT_LINK_OBJECT       pDhcpcReqOptionContext      = NULL;
    PCONTEXT_LINK_OBJECT       pDhcpcSendOptionContext     = NULL;
    PSLAP_VARIABLE                  pSlapVariable     = NULL;
    ULONG                           ulEntryCount      = 0;
    ULONG                           ulIndex           = 0;
    ULONG                           ulEntryCount2     = 0;
    ULONG                           ulIndex2          = 0;
    ULONG                           uInstanceNumber   = 0;
    BOOL                            bNew              = FALSE;
    char*                           pAliasClient      = NULL;
    char*                           pAliasReqOption   = NULL;
    char*                           pAliasSendOption  = NULL;
    char*                           pFolderName       = NULL;
    
    PDML_DHCPC_FULL            pDhcpv4Client     = NULL;
    PDML_DHCPC_REQ_OPT         pDhcpv4ReqOpt     = NULL;
    PCOSA_DML_DHCP_OPT              pDhcpv4SndOpt     = NULL;

    if ( !pPoamIrepFoDhcpv4 )
    {
        return ANSC_STATUS_FAILURE;
    }

    /* This is saved structure for dhcpv4
        *****************************************
              <Dhcpv4>
                  <client>
                      <NextInstanceNumber> xxx </>
                      <1>
                           <alias>xxx</>
                           <bNew>false</>
                           <ReqOption>
                               <NextInstanceNumber> xxx </>
                               <1>
                                   <alias>xxx</>
                                   <bNew>true</>
                               </1>
                           </ReqOption>
                          <SendOption>
                              <NextInstanceNumber> xxx </>
                              <1>
                                  <alias>xxx</>
                                  <bNew>true</>
                              </1>
                          </SendOption>
                     </1>
               </client>
              <pool>
                    <NextInstanceNumber> xxx </>
                    <1>
                        <alias>xxx</>
                        <bNew>true</>
                        <staticAddress>
                            <NextInstanceNumber> xxx </>
                            <1>
                                <alias>xxx</>
                                <bNew>true</>
                            </1>
                        </staticAddress>
                       <option>
                           <NextInstanceNumber> xxx </>
                           <1>
                               <alias>xxx</>
                               <bNew>true</>
                           </1>
                       </option>
                    </1>
              </pool>
            </Dhcpv4>
      ****************************************************
      */

    /* Get Folder Client */ 
    pPoamIrepFoClient  = 
        (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoDhcpv4->GetFolder
            (
                (ANSC_HANDLE)pPoamIrepFoDhcpv4,
                DHCPV4_IREP_FOLDER_NAME_CLIENT
            );

    if ( !pPoamIrepFoClient )
    {
        returnStatus      = ANSC_STATUS_FAILURE;
        goto EXIT1;
    }

    /* Get Maximum number */
    if ( TRUE )
    {
        pSlapVariable =
            (PSLAP_VARIABLE)pPoamIrepFoClient->GetRecord
                (
                    (ANSC_HANDLE)pPoamIrepFoClient,
                    COSA_DML_RR_NAME_Dhcpv4NextInsNunmber,
                    NULL
                );

        if ( pSlapVariable )
        {
            pMyObject->maxInstanceOfClient = pSlapVariable->Variant.varUint32;

            SlapFreeVariable(pSlapVariable);
        }
    }

    /* enumerate client.{i} */
    ulEntryCount = pPoamIrepFoClient->GetFolderCount((ANSC_HANDLE)pPoamIrepFoClient);
    for ( ulIndex = 0; ulIndex < ulEntryCount; ulIndex++ )
    {
        /* Get i in client.{i} */
        pFolderName =
            pPoamIrepFoClient->EnumFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoClient,
                    ulIndex
                );

        if ( !pFolderName )
        {
            continue;
        }

        uInstanceNumber = _ansc_atol(pFolderName);

        if ( uInstanceNumber == 0 )
        {
            AnscFreeMemory(pFolderName);
            continue;
        }

        pPoamIrepFoEnumClient = pPoamIrepFoClient->GetFolder((ANSC_HANDLE)pPoamIrepFoClient, pFolderName);

        AnscFreeMemory(pFolderName);

        if ( !pPoamIrepFoEnumClient )
        {
            continue;
        }

        /* Get client.{i}.Alias value*/
        if ( TRUE )
        {
            pSlapVariable =
                (PSLAP_VARIABLE)pPoamIrepFoEnumClient->GetRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoEnumClient,
                        COSA_DML_RR_NAME_Dhcpv4Alias,
                        NULL
                    );

            if ( pSlapVariable )
            {
                pAliasClient = AnscCloneString(pSlapVariable->Variant.varString);

                SlapFreeVariable(pSlapVariable);
            }
        }

        /* Get client.{i}.bNew value*/
        if ( TRUE )
        {
            pSlapVariable =
                (PSLAP_VARIABLE)pPoamIrepFoEnumClient->GetRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoEnumClient,
                        COSA_DML_RR_NAME_Dhcpv4bNew,
                        NULL
                    );

            if ( pSlapVariable )
            {
                bNew = pSlapVariable->Variant.varBool;

                SlapFreeVariable(pSlapVariable);
            }
            else
            {
                bNew = TRUE;
            }
        }

        /* Create one entry and keep this delay_added entry */
        pDhcpv4Client = (PDML_DHCPC_FULL)AnscAllocateMemory(sizeof(DML_DHCPC_FULL));
        if ( !pDhcpv4Client )
        {
            returnStatus = ANSC_STATUS_FAILURE;            
            goto EXIT2;
        }

        /* set some default value firstly */
        DHCPV4_CLIENT_SET_DEFAULTVALUE(pDhcpv4Client);

        /* save alias and instanceNumber */
        pDhcpv4Client->Cfg.InstanceNumber = uInstanceNumber;
        AnscCopyString( pDhcpv4Client->Cfg.Alias, pAliasClient );

        /* Create one link point */
        pDhcpcContext = (PDHCPC_CONTEXT_LINK_OBJECT)AnscAllocateMemory(sizeof(DHCPC_CONTEXT_LINK_OBJECT));
        if ( !pDhcpcContext )
        {
            returnStatus = ANSC_STATUS_FAILURE;
            goto EXIT3;
        }

        DHCPV4_CLIENT_INITIATION_CONTEXT(pDhcpcContext)

        pDhcpcContext->InstanceNumber = uInstanceNumber;
        pDhcpcContext->hContext       = (ANSC_HANDLE)pDhcpv4Client;
        pDhcpv4Client                     = 0;
        pDhcpcContext->bNew           = bNew; /* set to true */

        SListPushEntryByInsNum(&pMyObject->ClientList, (PCONTEXT_LINK_OBJECT)pDhcpcContext);

        /*************************************
               * Begin treat client.{i}.reqOption.                *
               *************************************/
        pPoamIrepFoReqOpt = 
            (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoEnumClient->GetFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoEnumClient,
                    DHCPV4_IREP_FOLDER_NAME_REQOPTION
                );
        
        if ( !pPoamIrepFoReqOpt )
        {
            goto SentOption;
        }
        
        /* Get Maximum number */
        if ( TRUE )
        {
            pSlapVariable =
                (PSLAP_VARIABLE)pPoamIrepFoReqOpt->GetRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoReqOpt,
                        COSA_DML_RR_NAME_Dhcpv4NextInsNunmber,
                        NULL
                    );
        
            if ( pSlapVariable )
            {
                pDhcpcContext->maxInstanceOfReq = pSlapVariable->Variant.varUint32;
        
                SlapFreeVariable(pSlapVariable);
            }
        }

        /* enumerate client.{i}.reqOption.{i} */
        ulEntryCount2 = pPoamIrepFoReqOpt->GetFolderCount((ANSC_HANDLE)pPoamIrepFoReqOpt);

        for ( ulIndex2 = 0; ulIndex2 < ulEntryCount2; ulIndex2++ )
        {
            /* Get i in client.{i}.reqOption.{i} */
            pFolderName =
                pPoamIrepFoReqOpt->EnumFolder
                    (
                        (ANSC_HANDLE)pPoamIrepFoReqOpt,
                        ulIndex2
                    );
            
            if ( !pFolderName )
            {
                continue;
            }
            
            uInstanceNumber = _ansc_atol(pFolderName);
            
            if ( uInstanceNumber == 0 )
            {
                AnscFreeMemory(pFolderName); /* tom*/
                continue;
            }

            pPoamIrepFoEnumReqOpt = pPoamIrepFoReqOpt->GetFolder((ANSC_HANDLE)pPoamIrepFoReqOpt, pFolderName);

            AnscFreeMemory(pFolderName);
            
            if ( !pPoamIrepFoEnumReqOpt )
            {
                continue;
            }
            
            /* Get client.{i}.reqOption.{i}.Alias value*/
            if ( TRUE )
            {
                pSlapVariable =
                    (PSLAP_VARIABLE)pPoamIrepFoEnumReqOpt->GetRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoEnumReqOpt,
                            COSA_DML_RR_NAME_Dhcpv4Alias,
                            NULL
                        );
            
                if ( pSlapVariable )
                {
                    pAliasReqOption= AnscCloneString(pSlapVariable->Variant.varString);
            
                    SlapFreeVariable(pSlapVariable);
                }
            }
            
            /* Get client.{i}.reqOption.{i}.bNew value*/
            if ( TRUE )
            {
                pSlapVariable =
                    (PSLAP_VARIABLE)pPoamIrepFoEnumReqOpt->GetRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoEnumReqOpt,
                            COSA_DML_RR_NAME_Dhcpv4bNew,
                            NULL
                        );
            
                if ( pSlapVariable )
                {
                    bNew = pSlapVariable->Variant.varBool;
            
                    SlapFreeVariable(pSlapVariable);
                }
                else
                {
                    bNew = TRUE;
                }
            }
            

            /* Create one link and ask backend to get content */
            pDhcpv4ReqOpt = (PDML_DHCPC_REQ_OPT)AnscAllocateMemory(sizeof(DML_DHCPC_REQ_OPT));
            if ( !pDhcpv4ReqOpt )
            {
                returnStatus = ANSC_STATUS_FAILURE;                
                goto EXIT3;
            }

            /* set some default value firstly */
            DHCPV4_REQOPTION_SET_DEFAULTVALUE(pDhcpv4ReqOpt);

            /* save alias and instanceNumber */
            pDhcpv4ReqOpt->InstanceNumber = uInstanceNumber;
            AnscCopyString( pDhcpv4ReqOpt->Alias, pAliasReqOption );

            /* Create one link */
            pDhcpcReqOptionContext = (PCONTEXT_LINK_OBJECT)AnscAllocateMemory(sizeof(CONTEXT_LINK_OBJECT));
            if ( !pDhcpcReqOptionContext )
            {
                returnStatus = ANSC_STATUS_FAILURE;
                AnscFreeMemory( pDhcpv4ReqOpt ); /*RDKB-6735, CID-33487, free unused resource before exit*/
                pDhcpv4ReqOpt = NULL;
                goto EXIT2;
            }

            CONTEXT_LINK_INITIATION_CONTENT(pDhcpcReqOptionContext);

            pDhcpcReqOptionContext->InstanceNumber = uInstanceNumber;
            pDhcpcReqOptionContext->hContext       = (ANSC_HANDLE)pDhcpv4ReqOpt;
            pDhcpv4ReqOpt                         = NULL;
            pDhcpcReqOptionContext->hParentTable   = (ANSC_HANDLE)pDhcpcContext;
            pDhcpcReqOptionContext->bNew           = bNew;
            
            SListPushEntryByInsNum(&pDhcpcContext->ReqOptionList, (PCONTEXT_LINK_OBJECT)pDhcpcReqOptionContext);

            /* release some memory */
            if (pAliasReqOption)
            {
                AnscFreeMemory(pAliasReqOption);
                pAliasReqOption = NULL;
            }
            
            pPoamIrepFoEnumReqOpt->Remove((ANSC_HANDLE)pPoamIrepFoEnumReqOpt);
            pPoamIrepFoEnumReqOpt = NULL;
        }

        pPoamIrepFoReqOpt->Remove((ANSC_HANDLE)pPoamIrepFoReqOpt);
        pPoamIrepFoReqOpt = NULL;

SentOption:
        /* 
                   Begin treat client.{i}.sentOption. 
                */
        pPoamIrepFoSndOpt = 
            (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoEnumClient->GetFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoEnumClient,
                    DHCPV4_IREP_FOLDER_NAME_SENTOPTION
                );
        
        if ( !pPoamIrepFoSndOpt )
        {
            goto ClientEnd;
        }
        
        /* Get Maximum number */
        if ( TRUE )
        {
            pSlapVariable =
                (PSLAP_VARIABLE)pPoamIrepFoSndOpt->GetRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoSndOpt,
                        COSA_DML_RR_NAME_Dhcpv4NextInsNunmber,
                        NULL
                    );
        
            if ( pSlapVariable )
            {
                pDhcpcContext->maxInstanceOfSend = pSlapVariable->Variant.varUint32;
        
                SlapFreeVariable(pSlapVariable);
            }
        }
        
        /* enumerate client.{i}.sentOption.{i} */
        ulEntryCount2 = pPoamIrepFoSndOpt->GetFolderCount((ANSC_HANDLE)pPoamIrepFoSndOpt);

        for ( ulIndex2 = 0; ulIndex2 < ulEntryCount2; ulIndex2++ )
        {
            /* Get i in client.{i}.sentOption.{i} */
            pFolderName =
                pPoamIrepFoSndOpt->EnumFolder
                    (
                        (ANSC_HANDLE)pPoamIrepFoSndOpt,
                        ulIndex2
                    );
            
            if ( !pFolderName )
            {
                continue;
            }
            
            uInstanceNumber = _ansc_atol(pFolderName);
            
            if ( uInstanceNumber == 0 )
            {
                AnscFreeMemory(pFolderName); /* tom*/
                continue;
            }
        
            pPoamIrepFoEnumSndOpt = pPoamIrepFoSndOpt->GetFolder((ANSC_HANDLE)pPoamIrepFoSndOpt, pFolderName);
        
            AnscFreeMemory(pFolderName);
            
            if ( !pPoamIrepFoEnumSndOpt )
            {
                continue;
            }
            
            /* Get client.{i}.sentOption.{i}.Alias value*/
            if ( TRUE )
            {
                pSlapVariable =
                    (PSLAP_VARIABLE)pPoamIrepFoEnumSndOpt->GetRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoEnumSndOpt,
                            COSA_DML_RR_NAME_Dhcpv4Alias,
                            NULL
                        );
            
                if ( pSlapVariable )
                {
                    pAliasSendOption = AnscCloneString(pSlapVariable->Variant.varString);
            
                    SlapFreeVariable(pSlapVariable);
                }
            }
            
            /* Get client.{i}.sentOption.{i}.bNew value*/
            if ( TRUE )
            {
                pSlapVariable =
                    (PSLAP_VARIABLE)pPoamIrepFoEnumSndOpt->GetRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoEnumSndOpt,
                            COSA_DML_RR_NAME_Dhcpv4bNew,
                            NULL
                        );
            
                if ( pSlapVariable )
                {
                    bNew = pSlapVariable->Variant.varBool;
            
                    SlapFreeVariable(pSlapVariable);
                }
                else
                {
                    bNew = TRUE;
                }
            }

            /* Create one link and ask backend to get content */
            pDhcpv4SndOpt = (PCOSA_DML_DHCP_OPT)AnscAllocateMemory(sizeof(COSA_DML_DHCP_OPT));
            if ( !pDhcpv4SndOpt )
            {
                returnStatus = ANSC_STATUS_FAILURE;                
                goto EXIT3;
            }

            /* set some default value firstly */
            DHCPV4_SENDOPTION_SET_DEFAULTVALUE(pDhcpv4SndOpt);

            /* save alias and instanceNumber */
            pDhcpv4SndOpt->InstanceNumber = uInstanceNumber;
            AnscCopyString( pDhcpv4SndOpt->Alias, pAliasSendOption );

            pDhcpcSendOptionContext = (PCONTEXT_LINK_OBJECT)AnscAllocateMemory(sizeof(CONTEXT_LINK_OBJECT));
            if ( !pDhcpcSendOptionContext )
            {
                AnscFreeMemory(pDhcpv4SndOpt); /*RDKB-6735, CID-33261, free unused resource before exit*/
                pDhcpv4SndOpt = NULL;
                returnStatus = ANSC_STATUS_FAILURE;            
                goto EXIT2;
            }

            CONTEXT_LINK_INITIATION_CONTENT(pDhcpcSendOptionContext);

            pDhcpcSendOptionContext->InstanceNumber = uInstanceNumber;
            pDhcpcSendOptionContext->hContext       = (ANSC_HANDLE)pDhcpv4SndOpt;
            pDhcpv4SndOpt = NULL;
            pDhcpcSendOptionContext->hParentTable   = pDhcpcContext;
            pDhcpcSendOptionContext->bNew           = bNew;

            SListPushEntryByInsNum(&pDhcpcContext->SendOptionList, (PCONTEXT_LINK_OBJECT)pDhcpcSendOptionContext);
        
            /* release some memory */
            
            if (pAliasSendOption)
            {
                AnscFreeMemory(pAliasSendOption);
                pAliasSendOption = NULL;
            }
            
            pPoamIrepFoEnumSndOpt->Remove((ANSC_HANDLE)pPoamIrepFoEnumSndOpt);
            pPoamIrepFoEnumSndOpt = NULL;
        }

        pPoamIrepFoSndOpt->Remove((ANSC_HANDLE)pPoamIrepFoSndOpt);
        pPoamIrepFoSndOpt = NULL;

ClientEnd:

        /* release some memory */
        if (pAliasClient)
        {
            AnscFreeMemory(pAliasClient);
            pAliasClient = NULL;
        }
        
        pPoamIrepFoEnumClient->Remove((ANSC_HANDLE)pPoamIrepFoEnumClient);
        pPoamIrepFoEnumClient = NULL;
    }

    pPoamIrepFoClient->Remove((ANSC_HANDLE)pPoamIrepFoClient);
    pPoamIrepFoClient = NULL;


EXIT3:
    if(pDhcpv4Client)
        AnscFreeMemory(pDhcpv4Client);

    if(pDhcpv4ReqOpt )
        AnscFreeMemory(pDhcpv4ReqOpt);
    
    if(pDhcpv4SndOpt )
        AnscFreeMemory(pDhcpv4SndOpt);

EXIT2:
    
    if(pAliasReqOption)
        AnscFreeMemory(pAliasReqOption);

    if(pAliasSendOption)
        AnscFreeMemory(pAliasSendOption);
    
    if(pAliasClient)
        AnscFreeMemory(pAliasClient);
    
EXIT1:
    
    if ( pPoamIrepFoClient )
        pPoamIrepFoClient->Remove((ANSC_HANDLE)pPoamIrepFoClient);

    if ( pPoamIrepFoEnumClient )
        pPoamIrepFoEnumClient->Remove((ANSC_HANDLE)pPoamIrepFoEnumClient);

    if ( pPoamIrepFoReqOpt)
        pPoamIrepFoReqOpt->Remove((ANSC_HANDLE)pPoamIrepFoReqOpt);

    if ( pPoamIrepFoEnumReqOpt )
        pPoamIrepFoEnumReqOpt->Remove((ANSC_HANDLE)pPoamIrepFoEnumReqOpt);

    if ( pPoamIrepFoSndOpt)
        pPoamIrepFoSndOpt->Remove((ANSC_HANDLE)pPoamIrepFoSndOpt);

    if ( pPoamIrepFoEnumSndOpt)
        pPoamIrepFoEnumSndOpt->Remove((ANSC_HANDLE)pPoamIrepFoEnumSndOpt);
    
    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        WanMgr_Dhcpv4RegSetDhcpv4Info
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to save current NextInstanceNumber and Delay_added
        entry into sysregistry.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of dhcpv4
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS WanMgr_Dhcpv4RegSetDhcpv4Info ( ANSC_HANDLE hThisObject )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PWAN_DHCPV4_DATA          pMyObject         = (PWAN_DHCPV4_DATA   )hThisObject;
    
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoDhcpv4 = (PPOAM_IREP_FOLDER_OBJECT )pMyObject->hIrepFolderDhcpv4;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoClient = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoReqOpt = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoSndOpt = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoEnumClient      = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoEnumReqOpt      = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoEnumSndOpt      = (PPOAM_IREP_FOLDER_OBJECT )NULL;

    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry2      = (PSINGLE_LINK_ENTRY       )NULL;
    PDHCPC_CONTEXT_LINK_OBJECT pDhcpcContext = NULL;
    PCONTEXT_LINK_OBJECT       pDhcpcReqOptionContext       = NULL;
    PCONTEXT_LINK_OBJECT       pDhcpcSendOptionContext      = NULL;
    PSLAP_VARIABLE                  pSlapVariable     = NULL;
    ULONG                           ulEntryCount      = 0;
    ULONG                           ulIndex           = 0;
    ULONG                           ulEntryCount2     = 0;
    ULONG                           ulIndex2          = 0;
    ULONG                           uInstanceNumber   = 0;
    char*                           pAliasClient      = NULL;
    char*                           pAliasReqOption   = NULL;
    char*                           pAliasSendOption  = NULL;
    char*                           pFolderName       = NULL;
    char                            FolderName[16]    = {0};
    
    PDML_DHCPC_FULL            pDhcpv4Client     = NULL;
    PDML_DHCPC_REQ_OPT         pDhcpv4ReqOpt     = NULL;
    PCOSA_DML_DHCP_OPT              pDhcpv4SndOpt     = NULL;

    if ( !pPoamIrepFoDhcpv4 )
    {
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        pPoamIrepFoDhcpv4->EnableFileSync((ANSC_HANDLE)pPoamIrepFoDhcpv4, FALSE);
    }

    if ( TRUE )
    {
        pPoamIrepFoDhcpv4->Clear((ANSC_HANDLE)pPoamIrepFoDhcpv4);

        SlapAllocVariable(pSlapVariable);

        if ( !pSlapVariable )
        {
            returnStatus = ANSC_STATUS_RESOURCES;

            goto  EXIT1;
        }
    }

    /* This is saved structure for dhcpv4
        *****************************************
              <Dhcpv4>
                  <client>
                      <NextInstanceNumber> xxx </>
                      <1>
                           <alias>xxx</>
                           <bNew>false</>
                           <ReqOption>
                               <NextInstanceNumber> xxx </>
                               <1>
                                   <alias>xxx</>
                                   <bNew>false</>
                               </1>
                           </ReqOption>
                          <SendOption>
                              <NextInstanceNumber> xxx </>
                              <1>
                                  <alias>xxx</>
                                  <bNew>true</>
                              </1>
                          </SendOption>
                     </1>
               </client>
              <pool>
                    <NextInstanceNumber> xxx </>
                    <1>
                        <alias>xxx</>
                        <bNew>true</>
                        <staticAddress>
                            <NextInstanceNumber> xxx </>
                            <1>
                                <alias>xxx</>
                                <bNew>true</>
                            </1>
                        </staticAddress>
                       <option>
                           <NextInstanceNumber> xxx </>
                           <1>
                               <alias>xxx</>
                               <bNew>true</>
                           </1>
                       </option>
                    </1>
              </pool>
            </Dhcpv4>
      ****************************************************
      */

    /* Add dhcpv4.client.*/
    pPoamIrepFoClient =
        pPoamIrepFoDhcpv4->AddFolder
            (
                (ANSC_HANDLE)pPoamIrepFoDhcpv4,
                DHCPV4_IREP_FOLDER_NAME_CLIENT,
                0
            );

    if ( !pPoamIrepFoClient )
    {
        goto EXIT1;
    }

    /* add client.{i}.maxInstanceNumber  */
    if ( TRUE )
    {
        pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_uint32;
        pSlapVariable->Variant.varUint32 = pMyObject->maxInstanceOfClient;
    
        returnStatus =
            pPoamIrepFoClient->AddRecord
                (
                    (ANSC_HANDLE)pPoamIrepFoClient,
                    COSA_DML_RR_NAME_Dhcpv4NextInsNunmber,
                    SYS_REP_RECORD_TYPE_UINT,
                    SYS_RECORD_CONTENT_DEFAULT,
                    pSlapVariable,
                    0
                );
    
        SlapCleanVariable(pSlapVariable);
        SlapInitVariable (pSlapVariable);
    }
    
    pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->ClientList);

    while ( pSLinkEntry )
    {
        /* create dhcpv4.client.{i} */
        
        pDhcpcContext = ACCESS_CONTEXT_DHCPC_LINK_OBJECT(pSLinkEntry);
        pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

        pDhcpv4Client = (PDML_DHCPC_FULL)pDhcpcContext->hContext;

        /* When this entry has been added to backend, has not any child and maxInstanceNumber is 0
                  We need not save this entry  */
        if ( !pDhcpcContext->bNew && 
             !AnscSListQueryDepth(&pDhcpcContext->ReqOptionList  ) &&
             !AnscSListQueryDepth(&pDhcpcContext->SendOptionList ) &&
             pDhcpcContext->maxInstanceOfSend == 0 &&
             pDhcpcContext->maxInstanceOfReq  == 0 
           )
        {
            continue;
        }

        _ansc_sprintf(FolderName, "%lu", pDhcpcContext->InstanceNumber);

        pPoamIrepFoEnumClient =
            pPoamIrepFoClient->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoClient,
                    FolderName,
                    0
                );

        if ( !pPoamIrepFoEnumClient )
        {
            continue;
        }

        /* add  dhcpv4.client.{i}.alias */
        if ( TRUE )
        {
            pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_string;
            pSlapVariable->Variant.varString = AnscCloneString(pDhcpv4Client->Cfg.Alias);

            returnStatus =
                pPoamIrepFoEnumClient->AddRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoEnumClient,
                        COSA_DML_RR_NAME_Dhcpv4Alias,
                        SYS_REP_RECORD_TYPE_ASTR,
                        SYS_RECORD_CONTENT_DEFAULT,
                        pSlapVariable,
                        0
                    );

            SlapCleanVariable(pSlapVariable);
            SlapInitVariable (pSlapVariable);
        }

        /* add  dhcpv4.client.{i}.bNew */
        if ( TRUE )
        {
            pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_bool;
            pSlapVariable->Variant.varBool   = pDhcpcContext->bNew;

            returnStatus =
                pPoamIrepFoEnumClient->AddRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoEnumClient,
                        COSA_DML_RR_NAME_Dhcpv4bNew,
                        SYS_REP_RECORD_TYPE_BOOL,
                        SYS_RECORD_CONTENT_DEFAULT,
                        pSlapVariable,
                        0
                    );

            SlapCleanVariable(pSlapVariable);
            SlapInitVariable (pSlapVariable);
        }

        /*
                    begin add reqOption
                */

        if ( !AnscSListQueryDepth(&pDhcpcContext->ReqOptionList) )
        {
            goto SentOption;
        }
            
        /* Add dhcpv4.client.{i}.reqOption */
        pPoamIrepFoReqOpt =
            pPoamIrepFoEnumClient->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoEnumClient,
                    DHCPV4_IREP_FOLDER_NAME_REQOPTION,
                    0
                );

        if ( !pPoamIrepFoReqOpt )
        {
            goto EXIT1;
        }

        /* add client.{i}.reqOption.maxInstanceNumber  */
        if ( TRUE )
        {
            pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_uint32;
            pSlapVariable->Variant.varUint32 = pDhcpcContext->maxInstanceOfReq;
        
            returnStatus =
                pPoamIrepFoReqOpt->AddRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoReqOpt,
                        COSA_DML_RR_NAME_Dhcpv4NextInsNunmber,
                        SYS_REP_RECORD_TYPE_UINT,
                        SYS_RECORD_CONTENT_DEFAULT,
                        pSlapVariable,
                        0
                    );
        
            SlapCleanVariable(pSlapVariable);
            SlapInitVariable (pSlapVariable);
        }

        pSLinkEntry2 = AnscSListGetFirstEntry(&pDhcpcContext->ReqOptionList);

        while ( pSLinkEntry2 )
        {
            /* create dhcpv4.client.{i}.reqOption.{i} */

            pDhcpcReqOptionContext = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry2);
            pSLinkEntry2          = AnscSListGetNextEntry(pSLinkEntry2);
        
            pDhcpv4ReqOpt= (PDML_DHCPC_REQ_OPT)pDhcpcReqOptionContext->hContext;

            if ( !pDhcpcReqOptionContext->bNew )
            {
                continue;
            }
            
            _ansc_sprintf(FolderName, "%lu", pDhcpcReqOptionContext->InstanceNumber);
        
            pPoamIrepFoEnumReqOpt =
                pPoamIrepFoReqOpt->AddFolder
                    (
                        (ANSC_HANDLE)pPoamIrepFoReqOpt,
                        FolderName,
                        0
                    );
        
            if ( !pPoamIrepFoEnumReqOpt )
            {
                continue;
            }

            /* create dhcpv4.client.{i}.reqOption.{i}.alias */
            if ( TRUE )
            {
                pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_string;
                pSlapVariable->Variant.varString = AnscCloneString(pDhcpv4ReqOpt->Alias);

                returnStatus =
                    pPoamIrepFoEnumReqOpt->AddRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoEnumReqOpt,
                            COSA_DML_RR_NAME_Dhcpv4Alias,
                            SYS_REP_RECORD_TYPE_ASTR,
                            SYS_RECORD_CONTENT_DEFAULT,
                            pSlapVariable,
                            0
                        );
                
                SlapCleanVariable(pSlapVariable);
                SlapInitVariable (pSlapVariable);
            }

            /* create dhcpv4.client.{i}.reqOption.{i}.alias */
            if ( TRUE )
            {
                pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_bool;
                pSlapVariable->Variant.varBool   = pDhcpcReqOptionContext->bNew;

                returnStatus =
                    pPoamIrepFoEnumReqOpt->AddRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoEnumReqOpt,
                            COSA_DML_RR_NAME_Dhcpv4bNew,
                            SYS_REP_RECORD_TYPE_BOOL,
                            SYS_RECORD_CONTENT_DEFAULT,
                            pSlapVariable,
                            0
                        );
                
                SlapCleanVariable(pSlapVariable);
                SlapInitVariable (pSlapVariable);
            }

            pPoamIrepFoEnumReqOpt->Remove((ANSC_HANDLE)pPoamIrepFoEnumReqOpt);
            pPoamIrepFoEnumReqOpt = NULL;
        }

        pPoamIrepFoReqOpt->Remove((ANSC_HANDLE)pPoamIrepFoReqOpt);
        pPoamIrepFoReqOpt = NULL;

        /*
                    begin add sendOption
                */
SentOption:

        if ( !AnscSListQueryDepth(&pDhcpcContext->SendOptionList) )
        {
            goto ClientEnd;
        }

        /* Add dhcpv4.client.{i}.sendOption */
        pPoamIrepFoSndOpt =
            pPoamIrepFoEnumClient->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoEnumClient,
                    DHCPV4_IREP_FOLDER_NAME_SENTOPTION,
                    0
                );
        
        if ( !pPoamIrepFoSndOpt )
        {
            goto EXIT1;
        }
        
        /* add client.{i}.sendOption.maxInstanceNumber  */
        if ( TRUE )
        {
            pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_uint32;
            pSlapVariable->Variant.varUint32 = pDhcpcContext->maxInstanceOfSend;
        
            returnStatus =
                pPoamIrepFoSndOpt->AddRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoSndOpt,
                        COSA_DML_RR_NAME_Dhcpv4NextInsNunmber,
                        SYS_REP_RECORD_TYPE_UINT,
                        SYS_RECORD_CONTENT_DEFAULT,
                        pSlapVariable,
                        0
                    );
        
            SlapCleanVariable(pSlapVariable);
            SlapInitVariable (pSlapVariable);
        }
        
        pSLinkEntry2 = AnscSListGetFirstEntry(&pDhcpcContext->SendOptionList);
        
        while ( pSLinkEntry2 )
        {
            /* create dhcpv4.client.{i}.sendOption.{i} */
        
            pDhcpcSendOptionContext = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry2);
            pSLinkEntry2          = AnscSListGetNextEntry(pSLinkEntry2);
        
            pDhcpv4SndOpt= (PCOSA_DML_DHCP_OPT)pDhcpcSendOptionContext->hContext;

            if ( !pDhcpcSendOptionContext->bNew )
            {
                continue;
            }
        
            _ansc_sprintf(FolderName, "%lu", pDhcpcSendOptionContext->InstanceNumber);
        
            pPoamIrepFoEnumSndOpt =
                pPoamIrepFoSndOpt->AddFolder
                    (
                        (ANSC_HANDLE)pPoamIrepFoSndOpt,
                        FolderName,
                        0
                    );
        
            if ( !pPoamIrepFoEnumSndOpt )
            {
                continue;
            }

            /* create dhcpv4.client.{i}.sendOption.{i}.alias */
            if ( TRUE )
            {
                pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_string;
                pSlapVariable->Variant.varString = AnscCloneString(pDhcpv4SndOpt->Alias);
        
                returnStatus =
                    pPoamIrepFoEnumSndOpt->AddRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoEnumSndOpt,
                            COSA_DML_RR_NAME_Dhcpv4Alias,
                            SYS_REP_RECORD_TYPE_ASTR,
                            SYS_RECORD_CONTENT_DEFAULT,
                            pSlapVariable,
                            0
                        );
                
                SlapCleanVariable(pSlapVariable);
                SlapInitVariable (pSlapVariable);
            }

            /* create dhcpv4.client.{i}.sendOption.{i}.bNew */
            if ( TRUE )
            {
                pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_bool;
                pSlapVariable->Variant.varBool   = pDhcpcSendOptionContext->bNew;
        
                returnStatus =
                    pPoamIrepFoEnumSndOpt->AddRecord
                        (
                            (ANSC_HANDLE)pPoamIrepFoEnumSndOpt,
                            COSA_DML_RR_NAME_Dhcpv4bNew,
                            SYS_REP_RECORD_TYPE_BOOL,
                            SYS_RECORD_CONTENT_DEFAULT,
                            pSlapVariable,
                            0
                        );
                
                SlapCleanVariable(pSlapVariable);
                SlapInitVariable (pSlapVariable);
            }

            pPoamIrepFoEnumSndOpt->Remove((ANSC_HANDLE)pPoamIrepFoEnumSndOpt);
            pPoamIrepFoEnumSndOpt = NULL;
        }
        
        pPoamIrepFoSndOpt->Remove((ANSC_HANDLE)pPoamIrepFoSndOpt);
        pPoamIrepFoSndOpt = NULL;
        
ClientEnd:

        /*release some resource */        
        pPoamIrepFoEnumClient->Remove((ANSC_HANDLE)pPoamIrepFoEnumClient);
        pPoamIrepFoEnumClient = NULL;
    }
    
    pPoamIrepFoClient->Remove((ANSC_HANDLE)pPoamIrepFoClient);
    pPoamIrepFoClient = NULL;

EXIT1:
    if ( pSlapVariable )
    {
        SlapFreeVariable(pSlapVariable);
        pSlapVariable = NULL;
    }

    if ( pPoamIrepFoClient )
        pPoamIrepFoClient->Remove((ANSC_HANDLE)pPoamIrepFoClient);

    if ( pPoamIrepFoEnumClient )
        pPoamIrepFoEnumClient->Remove((ANSC_HANDLE)pPoamIrepFoEnumClient);

    if ( pPoamIrepFoReqOpt)
        pPoamIrepFoReqOpt->Remove((ANSC_HANDLE)pPoamIrepFoReqOpt);

    if ( pPoamIrepFoEnumReqOpt )
        pPoamIrepFoEnumReqOpt->Remove((ANSC_HANDLE)pPoamIrepFoEnumReqOpt);

    if ( pPoamIrepFoSndOpt)
        pPoamIrepFoSndOpt->Remove((ANSC_HANDLE)pPoamIrepFoSndOpt);

    if ( pPoamIrepFoEnumSndOpt)
        pPoamIrepFoEnumSndOpt->Remove((ANSC_HANDLE)pPoamIrepFoEnumSndOpt);
    
    pPoamIrepFoDhcpv4->EnableFileSync((ANSC_HANDLE)pPoamIrepFoDhcpv4, TRUE);

    return returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WanMgr_Dhcpv4ClientHasDelayAddedChild
            (
                PDHCPC_CONTEXT_LINK_OBJECT                       hContext
            );

    description:

        This function is called to check whether this is child is pending added. If yes,
        return TRUE. Or else return FALSE.

    argument:   PDHCPC_CONTEXT_LINK_OBJECT                hThisObject
                This handle is actually the pointer of one context link point.

    return:     TRUE or FALSE.

**********************************************************************/
BOOL WanMgr_Dhcpv4ClientHasDelayAddedChild ( PDHCPC_CONTEXT_LINK_OBJECT hContext )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PDHCPC_CONTEXT_LINK_OBJECT pDhcpcContext = hContext;
    
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY )NULL;
    PCONTEXT_LINK_OBJECT       pCxtLink      = NULL;

    pSLinkEntry = AnscSListGetFirstEntry(&pDhcpcContext->ReqOptionList);
    while ( pSLinkEntry )
    {
        pCxtLink          = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
        pSLinkEntry           = AnscSListGetNextEntry(pSLinkEntry);
    
        if ( pCxtLink->bNew )
        {
            return TRUE;
        }
        
    }

    pSLinkEntry = AnscSListGetFirstEntry(&pDhcpcContext->SendOptionList);
    while ( pSLinkEntry )
    {
        pCxtLink          = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
        pSLinkEntry           = AnscSListGetNextEntry(pSLinkEntry);
    
        if ( pCxtLink->bNew )
        {
            return TRUE;
        }
        
    }

    return FALSE;
}

BOOL
WanMgr_DmlSetIpaddr
    (
        PULONG pIPAddr, 
        PCHAR pString, 
        ULONG MaxNumber 
    )
{                                                       
    CHAR           *pTmpString          = pString;                                                       
    ULONG           i                   = 0;                                                       
    ULONG           j                   = 0;                                                       
    ULONG           n                   = 0;
    BOOL            bReturn             = TRUE;
    ULONG           pIPAddr2[DML_DHCP_MAX_ENTRIES]  = {0};

    if ( !pIPAddr || !pString || !MaxNumber )
        return FALSE;

    while( pTmpString[i] )                                                       
    {
        if ( pTmpString[i] == ',' )
        {
            pTmpString[i] = 0;                                                                
            pIPAddr2[n]  = _ansc_inet_addr(&pTmpString[j]);      
            if (pIPAddr2[n] == INADDR_NONE)                
            {                                              
                pTmpString[i] = ',';                                                       

                pIPAddr2[n] = 0;                  
                n = MaxNumber;                                 
                bReturn = FALSE;                               
                goto EXIT;                                         
            }               
            
            pTmpString[i] = ',';                                                       
            j = i + 1;                                                       
            n++;         
            
            if ( n >= MaxNumber )                                                       
            {                                                       
                break;                                                       
            }                                                       
        }                                                                  
        i++;                                                                   
    }  
    
    /* The last one  */                                                       
    if ( ( n < MaxNumber ) && ( (i-j) >= 7 ) )
    {                                                       
        pIPAddr2[n]  = _ansc_inet_addr(&pTmpString[j]); 
        if (pIPAddr2[n] == INADDR_NONE)                
        {                                              
            pIPAddr2[n] = 0;                  
            bReturn = FALSE;                               
            goto EXIT;
        }
    }                                                       
    else if ( (i-j) > 1 )                                   
    {                                    
        /*This case means there a illegal length ip address.*/
        bReturn = FALSE;                                    
        goto EXIT;
    }

    /*The setting may be NULL. So this also may clear backend. */
    for(n=0; n < MaxNumber; n++){
        pIPAddr[n] = pIPAddr2[n];
    }

EXIT:
    return bReturn;
}                                                 
    
BOOL 
WanMgr_DmlGetIpaddrString
    (
        PUCHAR pString, 
        PULONG pulStrLength, 
        PULONG pIPAddr, 
        ULONG  MaxNumber
    )
{        
    UCHAR              *pTmpString      = pString;
    ULONG               n               = 0;
    PULONG              pIPAddr2        = pIPAddr;

    if ( !pString || !pulStrLength || !pIPAddr || !MaxNumber )
        return FALSE;
    
    while( pIPAddr2[n] && ( n < MaxNumber ) && ( (*pulStrLength- (pTmpString - pString)) > 15 ) )
    {
        AnscCopyString((char *)pTmpString, _ansc_inet_ntoa( *((struct in_addr*)&(pIPAddr2[n]))) );
    
        pTmpString[AnscSizeOfString((const char *)pTmpString)] = ',';
    
        pTmpString = &pTmpString[AnscSizeOfString((const char *)pTmpString)];
        
        n++;
    }
    
    if ( pTmpString != pString )
    {
        pTmpString[AnscSizeOfString((const char *)pTmpString) -1] = 0;
    }
    
    if ( (*pulStrLength - (pTmpString - pString)) <= 15 )
    {
        *pulStrLength = MaxNumber * 16 + 1;
        
        return FALSE;
    }
    
    return TRUE;
}


