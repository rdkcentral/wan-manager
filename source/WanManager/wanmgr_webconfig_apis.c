
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

#include <assert.h>
#include <stdlib.h>
#include "ansc_status.h"
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include "ccsp_trace.h"
#include "ccsp_syslog.h"
#include "ccsp_message_bus.h"
#include "ccsp_base_api.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_webconfig_apis.h"
#include "wanmgr_webconfig.h"
#include "wanmgr_data.h"
#include "wanmgr_dml_apis.h"
#include "messagebus_interface_helper.h"
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
#include "wanmgr_dml_iface_v2_apis.h"
#else
#include "wanmgr_dml_iface_apis.h"
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */

/* WanMgr_Process_Webconfig_Request: */
/**
* @description Handle webconfig blob request.
*
* @param void*      Data - Blob data.
*
* @return The status of the operation.
* @retval BLOB_EXEC_SUCCESS if successful.
* @retval BLOB_EXEC_FAILURE if any error is detected
*
* @execution Callback.
* @sideeffect None.
*
*/
pErr WanMgr_Process_Webconfig_Request(void *Data)
{
    pErr execRetVal = NULL;
    int i, j;
    char alias[BUFFER_LENGTH_16];
    char dmlAlias[BUFFER_LENGTH_16];
    char dmlIfName[BUFFER_LENGTH_64];
    char markingPath[BUFFER_LENGTH_512];
    UINT uiTotalIfaces = 0;
    ULONG nameLength = 0;
    ULONG ifInsNum;
    ULONG insNum;
    WanMgr_Iface_Data_t*   pWanDmlIfaceData = NULL;

    CcspTraceInfo(("%s : Starting WAN Blob Data Processing\n",__FUNCTION__));
    if (Data == NULL) {
        CcspTraceError(("%s: Input Data is NULL\n",__FUNCTION__));
        return execRetVal;
    }

    WanMgr_WebConfig_t *pWebConfig = (WanMgr_WebConfig_t *) Data;

    execRetVal = (pErr ) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        CcspTraceError(("%s : Malloc failed for pErr\n",__FUNCTION__));
        return execRetVal;
    }

    memset(execRetVal,0,(sizeof(Err)));

    // update wanmanager global config
    if (pWebConfig->pWanFailOverData != NULL)
    {
        WanManager_SetParamBoolValue(NULL, PARAM_NAME_ALLOW_REMOTE_IFACE, pWebConfig->pWanFailOverData->AllowRemoteIface);
        CcspTraceInfo(("%s %d: Set %s value to %d\n", __FUNCTION__, __LINE__, PARAM_NAME_ALLOW_REMOTE_IFACE, pWebConfig->pWanFailOverData->AllowRemoteIface));
    }

    if (pWebConfig->ifTable != NULL)
    {
    // update interface specific config
    uiTotalIfaces = WanIf_GetEntryCount(NULL);

        for( i = 0; i < pWebConfig->ifCount; i++ ) // Iterate for each interface in blob
        {
            WebConfig_Wan_Interface_Table_t *pIfCfg = &(pWebConfig->ifTable[i]);
            CcspTraceInfo(("%s : Processing Interface: %s..\n",__FUNCTION__, pWebConfig->ifTable[i].name));

            for(j = 0; j < uiTotalIfaces; j++) // Find the interface in dml with same name of the current blob entry
            {
                pWanDmlIfaceData = WanIf_GetEntry(NULL, j, &ifInsNum);
                if(pWanDmlIfaceData != NULL)
                {
                    memset(dmlIfName, 0, sizeof(dmlIfName));
                    nameLength = sizeof(dmlIfName);
                    if(ANSC_STATUS_SUCCESS == WanIf_GetParamStringValue((ANSC_HANDLE)pWanDmlIfaceData,
                                PARAM_NAME_IF_NAME, dmlIfName, &nameLength))
                    {
                        if(!strncmp(pWebConfig->ifTable[i].name, dmlIfName, sizeof(dmlIfName)))
                        {
                            CcspTraceInfo(("%s : Found dml entry for Interface: %s..\n",
                                        __FUNCTION__, pWebConfig->ifTable[i].name));
                            break;
                        }
                    }
                }
            }

            if(j < uiTotalIfaces)
            {
                for (j = 0; j < pWebConfig->ifTable[i].markingCount; j++)  // Iterate for each new marking entry
                {
                    ULONG markIdx;
                    PSINGLE_LINK_ENTRY pSListEntry = NULL;
                    CONTEXT_MARKING_LINK_OBJECT* pCxtLink = NULL;

                    CcspTraceInfo(("%s : Processing Marking Entry: %s..\n",__FUNCTION__,
                                pWebConfig->ifTable[i].markingTable[j].alias));

                    ULONG markingCount = Marking_GetEntryCount((ANSC_HANDLE)pWanDmlIfaceData);
                    if (strncmp(pWebConfig->ifTable[i].markingTable[j].alias, "network_control",
                                sizeof(pWebConfig->ifTable[i].markingTable[j].alias)))
                    {
                        strncpy(alias, pWebConfig->ifTable[i].markingTable[j].alias, sizeof(alias)-1);
                    }
                    else
                    {
                        strncpy(alias, "DATA", sizeof(alias)-1);
                    }
                    for(markIdx = 0; markIdx < markingCount; markIdx++)
                    {
                        pCxtLink = Marking_GetEntry((ANSC_HANDLE)pWanDmlIfaceData, markIdx, &insNum);
                        if (pCxtLink)
                        {
                            memset(dmlAlias, 0, sizeof(dmlAlias));
                            nameLength = sizeof(dmlAlias);
                            if(ANSC_STATUS_SUCCESS == Marking_GetParamStringValue((ANSC_HANDLE)pCxtLink,
                                        PARAM_NAME_MARK_ALIAS, dmlAlias, &nameLength))
                            {
                                if(!strncmp(alias, dmlAlias, sizeof(alias)))
                                {
                                    //Alias already present, update the entry
                                    CcspTraceInfo(("%s : Alias already present, Entry would be updated ..\n",
                                                __FUNCTION__));
                                    Marking_SetParamIntValue((ANSC_HANDLE) pCxtLink, PARAM_NAME_ETHERNET_PRIORITY_MARK,
                                            pWebConfig->ifTable[i].markingTable[j].ethernetPriorityMark);
                                    pCxtLink->bNew = false;
                                    CcspTraceInfo(("%s : Committing marking entry instance: %lu..\n",
                                                __FUNCTION__, insNum));
                                    Marking_Commit((ANSC_HANDLE)pCxtLink);
                                    break;
                                }
                            }
                            else
                            {
                                CcspTraceError(("%s : Failed to read Alias for marking entry: %d..\n",
                                            __FUNCTION__, markIdx));
                            }
                        }
                        else
                        {
                            CcspTraceError(("%s : Failed to fetch entry at index: %d..\n",
                                        __FUNCTION__, markIdx));
                        }
                    }
                    if(markIdx >= markingCount)
                    {
                        // Matching entry not found, add a new entry with new Alias and EthernetPriorityMark
                        snprintf(markingPath,sizeof(markingPath),"%s%d.%s", TABLE_NAME_WAN_INTERFACE,
                                ifInsNum, TABLE_NAME_WAN_MARKING);
                        if (CCSP_SUCCESS == CcspCcMbi_AddTblRow( 0, markingPath, (int *)&insNum, NULL) )
                        {
                            CcspTraceInfo(("%s : Added new entry at %s, instnce-number: %lu..\n", __FUNCTION__,
                                        markingPath, insNum));
                            pCxtLink = Marking_GetEntry((ANSC_HANDLE)pWanDmlIfaceData, markingCount, &insNum);

                            if(pCxtLink)
                            {
                                CcspTraceInfo(("%s : Fetched new entry , instnce-number: %lu..\n", __FUNCTION__, insNum));
                                Marking_SetParamStringValue((ANSC_HANDLE)pCxtLink, PARAM_NAME_MARK_ALIAS, alias);
                                Marking_SetParamIntValue((ANSC_HANDLE)pCxtLink, PARAM_NAME_ETHERNET_PRIORITY_MARK,
                                        pWebConfig->ifTable[i].markingTable[j].ethernetPriorityMark);
                                pCxtLink->bNew = true;
                                CcspTraceInfo(("%s : Committing marking entry instance: %lu ..\n", __FUNCTION__, insNum));
                                Marking_Commit((ANSC_HANDLE)pCxtLink);
                            }
                            else
                            {
                                CcspTraceError(("%s : Failed to fetch new entry at index: %d..\n",
                                            __FUNCTION__, markingCount));
                            }
                        }
                        else
                        {
                            CcspTraceError(("%s : Failed to create new table row on path: %s..\n",
                                        __FUNCTION__, markingPath));
                        }

                    }
                }
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
                WanIf_SetParamBoolValue((ANSC_HANDLE)pWanDmlIfaceData, PARAM_NAME_WAN_REFRESH, true);
#else
                WanIfCfg_SetParamBoolValue((ANSC_HANDLE)pWanDmlIfaceData, PARAM_NAME_WAN_REFRESH, true);
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
            }
            else
            {
                CcspTraceInfo(("%s : Failed to find dml entry for Interface: %s..\n",
                            __FUNCTION__, pWebConfig->ifTable[i].name));
                execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
                return execRetVal;
            }
        }
    }

    CcspTraceInfo(("%s : WAN Blob Data Applied Successfully\n",__FUNCTION__));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    return execRetVal;
}

/* WanMgr_WanData_Timeout_Handler: */
/**
* @description  Calculates timeout value for blob request.
*
* @param size_t      size_tsize_t - Number of blob entries.
*
* @return timeout value.
*
* @execution Callback.
* @sideeffect None.
*
*/
size_t WanMgr_WanData_Timeout_Handler(size_t numOfEntries)
{
    return (numOfEntries * WANDATA_DEFAULT_TIMEOUT);
}

/* WanMgr_WanData_Rollback_Handler: */
/**
* @description Function to rollback to previous configs if apply failed.
*
* @return 0.
*
* @execution Callback.
* @sideeffect None.
*
*/
int WanMgr_WanData_Rollback_Handler(void)
{
    //TODO
    return 0;
}

/* WanMgr_WanData_Free_Resources: */
/**
* @description API to free the resources after blob apply.
*
* @param void *      arg - Resource structure allocated in WanMgrDmlWanDataSet.
*
* @return void.
*
* @execution Callback.
* @sideeffect None.
*
*/
void WanMgr_WanData_Free_Resources(void *arg)
{
    int i;
    CcspTraceInfo(("Entering: %s\n",__FUNCTION__));

    if ( arg == NULL )
    {
        CcspTraceError(("%s: Input Data is NULL\n",__FUNCTION__));
        return;
    }

    execData *blob_exec_data  = (execData*) arg;
    WanMgr_WebConfig_t *pWebConfig   = (WanMgr_WebConfig_t *) blob_exec_data->user_data;
    free(blob_exec_data);

    if ( NULL != pWebConfig )
    {
        if (NULL != pWebConfig->pWanFailOverData)
        {
            free(pWebConfig->pWanFailOverData);
        }
        if( NULL != pWebConfig->ifTable )
        {
            for (i = 0;i < pWebConfig->ifCount; i++)
            {
                if(pWebConfig->ifTable[i].markingTable != NULL)
                {
                    free(pWebConfig->ifTable[i].markingTable);
                    pWebConfig->ifTable[i].markingTable = NULL;
                    pWebConfig->ifTable[i].markingCount = 0;
                }
            }
            free(pWebConfig->ifTable);
            pWebConfig->ifTable = NULL;
        }

        free(pWebConfig);
        pWebConfig = NULL;

        CcspTraceInfo(("%s:Success in clearing WAN webconfig resources\n",__FUNCTION__));
    }
}

ANSC_STATUS WanMgrDmlWanFailOverDataSet (const void * pData, size_t len)
{
    size_t offset = 0;
    int i = 0;
    msgpack_object_map *map = NULL;
    msgpack_object_kv *map_ptr  = NULL;
    WanMgr_WebConfig_t *pWebConfig = NULL;
    execData * execDataPf = NULL;
    msgpack_unpacked msg;
    msgpack_unpack_return mp_rv;

    msgpack_unpacked_init( &msg );
    len +=  1;

    /* The outermost wrapper MUST be a map. */
    mp_rv = msgpack_unpack_next( &msg, (const char*) pData, len, &offset );
    if (mp_rv != MSGPACK_UNPACK_SUCCESS) {
        CcspTraceError(("%s: Failed to unpack WAN msg blob. Error %d",__FUNCTION__,mp_rv));
        msgpack_unpacked_destroy( &msg );
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s:Msg unpack success. Offset is %lu\n", __FUNCTION__,offset));
    msgpack_object obj = msg.data;

    map = &msg.data.via.map;

    map_ptr = obj.via.map.ptr;
    if ((!map) || (!map_ptr)) {
        CcspTraceError(("Failed to get object map\n"));
        msgpack_unpacked_destroy( &msg );
        return ANSC_STATUS_FAILURE;
    }

    if (msg.data.type != MSGPACK_OBJECT_MAP) {
        CcspTraceError(("%s: Invalid msgpack type",__FUNCTION__));
        msgpack_unpacked_destroy( &msg );
        return ANSC_STATUS_FAILURE;
    }

    /* Allocate memory for WAN structure */
    pWebConfig = (WanMgr_WebConfig_t *) malloc(sizeof(WanMgr_WebConfig_t));
    if ( pWebConfig == NULL )
    {
        CcspTraceError(("%s: WAN Struct malloc error\n",__FUNCTION__));
        msgpack_unpacked_destroy( &msg );
        return ANSC_STATUS_FAILURE;
    }

    memset( pWebConfig, 0, sizeof(WanMgr_WebConfig_t) );

    for (i = 0; i < map->size; i++)
    {
        if (strncmp(map_ptr->key.via.str.ptr, "wanfailover", map_ptr->key.via.str.size) == 0) 
        {
            if (WanMgr_WebConfig_Process_WanFailOver_Params(map_ptr->val, pWebConfig) != ANSC_STATUS_SUCCESS) 
            {
                CcspTraceError(("%s:Failed to copy wanfailover params",__FUNCTION__));
                msgpack_unpacked_destroy( &msg );
                if ( NULL != pWebConfig ) {
                    free(pWebConfig);
                    pWebConfig = NULL;
                }

                return ANSC_STATUS_FAILURE;
            }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "subdoc_name",map_ptr->key.via.str.size) == 0)
        {
            if (map_ptr->val.type == MSGPACK_OBJECT_STR) {
                strncpy(pWebConfig->subdocName, map_ptr->val.via.str.ptr, map_ptr->val.via.str.size);
                pWebConfig->subdocName[map_ptr->val.via.str.size] = '\0';
                CcspTraceInfo(("subdoc name :%s\n", pWebConfig->subdocName));
            }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "version",map_ptr->key.via.str.size) == 0)
        {
            if (map_ptr->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                pWebConfig->version = (unsigned long) map_ptr->val.via.u64;
                CcspTraceInfo(("Version :%lu\n",pWebConfig->version));
            }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "transaction_id",map_ptr->key.via.str.size) == 0)
        {
            if (map_ptr->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                pWebConfig->transactionId = (unsigned short) map_ptr->val.via.u64;
                CcspTraceInfo(("Tx id :%d\n",pWebConfig->transactionId));
            }
        }

        ++map_ptr;
    }

    //Free allocated resource
    msgpack_unpacked_destroy( &msg );

    //Push blob request after collection
    execDataPf = (execData*) malloc (sizeof(execData));
    if ( execDataPf != NULL )
    {
        memset(execDataPf, 0, sizeof(execData));
        execDataPf->txid = pWebConfig->transactionId;
        execDataPf->version = pWebConfig->version;
        execDataPf->numOfEntries = 1;
        strncpy(execDataPf->subdoc_name,pWebConfig->subdocName, sizeof(execDataPf->subdoc_name)-1);
        execDataPf->user_data = (void*) pWebConfig;
        execDataPf->calcTimeout = WanMgr_WanData_Timeout_Handler;
        execDataPf->executeBlobRequest = WanMgr_Process_Webconfig_Request;
        execDataPf->rollbackFunc = WanMgr_WanData_Rollback_Handler;
        execDataPf->freeResources = WanMgr_WanData_Free_Resources;
        PushBlobRequest(execDataPf);
        CcspTraceInfo(("%s PushBlobRequest Complete\n",__FUNCTION__));
    }

    return ANSC_STATUS_SUCCESS;
}

/* WanMgrDmlWanDataSet: */
/**
* @description set the blob data and register callbacks
*
* @param char *pData - CJSON data
*
* @return The status of the operation.
* @retval ANSC_STATUS_SUCCESS if successful.
* @retval ANSC_STATUS_FAILURE if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
*/
ANSC_STATUS WanMgrDmlWanDataSet(const void *pData, size_t len)
{
    size_t offset = 0;
    msgpack_unpacked msg;
    msgpack_unpack_return mp_rv;
    msgpack_object_map *map = NULL;
    msgpack_object_kv* map_ptr  = NULL;
    execData *execDataPf = NULL;
    WanMgr_WebConfig_t *pWebConfig = NULL;
    int i = 0;

    msgpack_unpacked_init( &msg );
    len +=  1;

    /* The outermost wrapper MUST be a map. */
    mp_rv = msgpack_unpack_next( &msg, (const char*) pData, len, &offset );
    if (mp_rv != MSGPACK_UNPACK_SUCCESS) {
        CcspTraceError(("%s: Failed to unpack WAN msg blob. Error %d",__FUNCTION__,mp_rv));
        msgpack_unpacked_destroy( &msg );
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s:Msg unpack success. Offset is %lu\n", __FUNCTION__,offset));
    msgpack_object obj = msg.data;

    map = &msg.data.via.map;

    map_ptr = obj.via.map.ptr;
    if ((!map) || (!map_ptr)) {
        CcspTraceError(("Failed to get object map\n"));
        msgpack_unpacked_destroy( &msg );
        return ANSC_STATUS_FAILURE;
    }

    if (msg.data.type != MSGPACK_OBJECT_MAP) {
        CcspTraceError(("%s: Invalid msgpack type",__FUNCTION__));
        msgpack_unpacked_destroy( &msg );
        return ANSC_STATUS_FAILURE;
    }

    /* Allocate memory for WAN structure */
    pWebConfig = (WanMgr_WebConfig_t *) malloc(sizeof(WanMgr_WebConfig_t));
    if ( pWebConfig == NULL )
    {
        CcspTraceError(("%s: WAN Struct malloc error\n",__FUNCTION__));
        msgpack_unpacked_destroy( &msg );
        return ANSC_STATUS_FAILURE;
    }

    memset( pWebConfig, 0, sizeof(WanMgr_WebConfig_t) );

    /* Parsing Config Msg String to WAN Structure */
    for (i = 0;i < map->size;i++)
    {
        if (strncmp(map_ptr->key.via.str.ptr, "wanmanager",map_ptr->key.via.str.size) == 0) {
            if (WanMgr_WebConfig_Process_Wanmanager_Params(map_ptr->val, pWebConfig) != ANSC_STATUS_SUCCESS) {
                CcspTraceError(("%s:Failed to copy wanmanager params",__FUNCTION__));
                msgpack_unpacked_destroy( &msg );
                if ( NULL != pWebConfig ) {
                    if( NULL != pWebConfig->ifTable )
                    {
                        int ifIndex;
                        for (ifIndex = 0; ifIndex < pWebConfig->ifCount; ifIndex++)
                        {
                            if(NULL != pWebConfig->ifTable[ifIndex].markingTable)
                            {
                                free(pWebConfig->ifTable[ifIndex].markingTable);
                            }
                        }
                        free(pWebConfig->ifTable);
                        pWebConfig->ifTable = NULL;
                    }
                    free(pWebConfig);
                    pWebConfig = NULL;
                }

                return ANSC_STATUS_FAILURE;
            }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "subdoc_name",map_ptr->key.via.str.size) == 0)
        {
            if (map_ptr->val.type == MSGPACK_OBJECT_STR) {
                strncpy(pWebConfig->subdocName, map_ptr->val.via.str.ptr, map_ptr->val.via.str.size);
                pWebConfig->subdocName[map_ptr->val.via.str.size] = '\0';
                CcspTraceInfo(("subdoc name :%s\n", pWebConfig->subdocName));
            }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "version",map_ptr->key.via.str.size) == 0)
        {
            if (map_ptr->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                pWebConfig->version = (unsigned long) map_ptr->val.via.u64;
                CcspTraceInfo(("Version :%lu\n",pWebConfig->version));
            }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "transaction_id",map_ptr->key.via.str.size) == 0)
        {
            if (map_ptr->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                pWebConfig->transactionId = (unsigned short) map_ptr->val.via.u64;
                CcspTraceInfo(("Tx id :%d\n",pWebConfig->transactionId));
            }
        }

        ++map_ptr;
    }

    //Free allocated resource
    msgpack_unpacked_destroy( &msg );

    //Push blob request after collection
    execDataPf = (execData*) malloc (sizeof(execData));
    if ( execDataPf != NULL )
    {
        memset(execDataPf, 0, sizeof(execData));
        execDataPf->txid = pWebConfig->transactionId;
        execDataPf->version = pWebConfig->version;
        execDataPf->numOfEntries = 1;
        strncpy(execDataPf->subdoc_name,pWebConfig->subdocName, sizeof(execDataPf->subdoc_name)-1);
        execDataPf->user_data = (void*) pWebConfig;
        execDataPf->calcTimeout = WanMgr_WanData_Timeout_Handler;
        execDataPf->executeBlobRequest = WanMgr_Process_Webconfig_Request;
        execDataPf->rollbackFunc = WanMgr_WanData_Rollback_Handler;
        execDataPf->freeResources = WanMgr_WanData_Free_Resources;
        PushBlobRequest(execDataPf);
        CcspTraceInfo(("%s PushBlobRequest Complete\n",__FUNCTION__));
    }

    return ANSC_STATUS_SUCCESS;
}

/* getWanDataBlobVersion: */
/**
* @description API to get Blob version from Utopia db
*
* @param char    *pSubDoc - Pointer to name of the subdoc
* @return version number if present, 0 otherwise.
*
* @execution Callback.
* @sideeffect None.
*
*/
static unsigned int getWanDataBlobVersion(char *pSubDoc)
{
    char  subdoc_ver[BUFFER_LENGTH_64] = {0},
          buf[BUFFER_LENGTH_64]        = {0};
    int retval;
    unsigned int version = 0;

    //Get blob version from DB
    snprintf(buf,sizeof(buf), "%s_version", pSubDoc);
    if ( syscfg_get( NULL, buf, subdoc_ver, sizeof(subdoc_ver)) == 0 )
    {
        version = strtoul(subdoc_ver, NULL, 10);
        CcspTraceInfo(("%s wan manager data %s blob version %s\n",__FUNCTION__, pSubDoc, subdoc_ver));
        return version;
    }

    CcspTraceInfo(("%s Failed to get wan manager Data %s blob version\n",__FUNCTION__, pSubDoc));

    return 0;
}

/* setWanDataBlobVersion: */
/**
* @description API to set Blob version in Utopia db
*
* @param char         *pSubDoc - Pointer to name of the subdoc
* @param unsigned int version  - Version number
* @return 0 on success, error otherwise.
*
* @execution Callback.
* @sideeffect None.
*
*/
static int setWanDataBlobVersion(char *pSubDoc, unsigned int version)
{
    char subdoc_ver[BUFFER_LENGTH_64] = {0},
         buf[BUFFER_LENGTH_64]        = {0};

    snprintf(subdoc_ver, sizeof(subdoc_ver), "%u", version);
    snprintf(buf, sizeof(buf), "%s_version", pSubDoc);

    //Set blob version to DB
    if( syscfg_set_commit( NULL, buf, subdoc_ver ) != 0 )
    {
        return -1;
    }

    CcspTraceInfo(("%s wan manager data %s blob version %s set successfully\n",__FUNCTION__, pSubDoc, subdoc_ver));

    return 0;
}

/* WanMgrDmlWanWebConfigInit: */
/**
* @description register wan manager subdoc
*
* @return The status of the operation.
* @retval ANSC_STATUS_SUCCESS if successful.
* @retval ANSC_STATUS_FAILURE if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
*/
ANSC_STATUS WanMgrDmlWanWebConfigInit( void )
{
    char *sub_docs[WANDATA_SUBDOC_COUNT+1]= {"wanmanager", "wanfailover", (char *) 0 };
    blobRegInfo *blobData        = NULL,
                *blobDataPointer = NULL;
    int i;

    //Allocate memory for blob registration structure
    blobData = (blobRegInfo*) malloc(WANDATA_SUBDOC_COUNT * sizeof(blobRegInfo));

    //Validate Memory
    if (blobData == NULL)
    {
        CcspTraceError(("%s: Failed to allocate memory\n",__FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    memset(blobData, 0, WANDATA_SUBDOC_COUNT * sizeof(blobRegInfo));

    //Separate subdocs information
    blobDataPointer = blobData;
    for ( i = 0; i < WANDATA_SUBDOC_COUNT; i++ )
    {
        strncpy(blobDataPointer->subdoc_name, sub_docs[i], sizeof(blobDataPointer->subdoc_name) - 1);
        blobDataPointer++;
    }
    blobDataPointer = blobData;

    //Register subdocs
    getVersion versionGet = getWanDataBlobVersion;
    setVersion versionSet = setWanDataBlobVersion;
    register_sub_docs(blobData, WANDATA_SUBDOC_COUNT, versionGet, versionSet);

    CcspTraceInfo(("%s Wan manager Webconfig Subdoc Registration Complete\n",__FUNCTION__));

    return ANSC_STATUS_SUCCESS;
}
