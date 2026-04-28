/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include "wanmgr_data.h"
#include "wanmgr_rbus_handler_apis.h"
#include "ipc_msg.h"
#include "wanmgr_interface_sm.h"
#include "wanmgr_dhcp_client_events.h"


#define DHCP_MGR_DHCPv4_TABLE "Device.DHCPv4.Client"
#define DHCP_MGR_DHCPv6_TABLE "Device.DHCPv6.Client"

extern rbusHandle_t rbusHandle;

/*
 * DHCP event queue – FIFO linked list protected by mutex + condvar.
 * A single persistent worker thread drains the queue so events are
 * always processed in the order they arrive.
 */
static DhcpEventThreadArgs *g_dhcpEventQueueHead = NULL;
static DhcpEventThreadArgs *g_dhcpEventQueueTail = NULL;
static pthread_mutex_t      g_dhcpEventQueueMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t       g_dhcpEventQueueCond  = PTHREAD_COND_INITIALIZER;
static int                  g_dhcpEventWorkerRunning = 0;

static BOOL WanMgr_DhcpEvents_ResolveIfName(const char *eventName, char *ifNameBuf, size_t ifNameBufLen)
{
    const char *suffix = ".Events";
    size_t eventNameLen = 0;
    size_t suffixLen = strlen(suffix);
    char dhcpIfacePath[128] = {0};
    UINT totalIfaces = 0;

    if (eventName == NULL || ifNameBuf == NULL || ifNameBufLen == 0)
    {
        return FALSE;
    }

    eventNameLen = strlen(eventName);
    if (eventNameLen <= suffixLen || strcmp(eventName + (eventNameLen - suffixLen), suffix) != 0)
    {
        return FALSE;
    }

    if ((eventNameLen - suffixLen) >= sizeof(dhcpIfacePath))
    {
        return FALSE;
    }

    strncpy(dhcpIfacePath, eventName, eventNameLen - suffixLen);
    dhcpIfacePath[eventNameLen - suffixLen] = '\0';

    totalIfaces = WanMgr_IfaceData_GetTotalWanIface();
    for (UINT ifaceIndex = 0; ifaceIndex < totalIfaces; ifaceIndex++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(ifaceIndex);
        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        DML_WAN_IFACE *pWanDmlIface = &(pWanDmlIfaceData->data);
        DML_VIRTUAL_IFACE *pVirtIf = pWanDmlIface->VirtIfList;

        while (pVirtIf != NULL)
        {
            if ((strcmp(pVirtIf->IP.DHCPv4Iface, dhcpIfacePath) == 0) ||
                (strcmp(pVirtIf->IP.DHCPv6Iface, dhcpIfacePath) == 0))
            {
                strncpy(ifNameBuf, pVirtIf->Name, ifNameBufLen - 1);
                ifNameBuf[ifNameBufLen - 1] = '\0';
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                return TRUE;
            }
            pVirtIf = pVirtIf->next;
        }

        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    return FALSE;
}

/* Worker thread: drains the queue in strict FIFO order. */
static void* WanMgr_DhcpEventQueueWorker(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    while (1)
    {
        DhcpEventThreadArgs *eventData = NULL;

        pthread_mutex_lock(&g_dhcpEventQueueMutex);
        /* Wait until there is at least one event in the queue */
        while (g_dhcpEventQueueHead == NULL)
        {
            pthread_cond_wait(&g_dhcpEventQueueCond, &g_dhcpEventQueueMutex);
        }

        /* Dequeue the head element */
        eventData = g_dhcpEventQueueHead;
        g_dhcpEventQueueHead = eventData->next;
        if (g_dhcpEventQueueHead == NULL)
        {
            g_dhcpEventQueueTail = NULL;
        }
        eventData->next = NULL;
        pthread_mutex_unlock(&g_dhcpEventQueueMutex);

        /* Process the event — this runs outside the queue lock so that
         * new events can still be enqueued while we process. */
        CcspTraceInfo(("%s-%d : Dequeued DHCP event (type %d) for %s\n",
                       __FUNCTION__, __LINE__, eventData->type, eventData->ifName));
        WanMgr_ProcessDhcpClientEvent(eventData);
        free(eventData);
    }

    return NULL;
}

/* Enqueue a DHCP event and ensure the worker thread is running. */
void WanMgr_DhcpEventQueue_Enqueue(DhcpEventThreadArgs *eventData)
{
    if (eventData == NULL)
    {
        return;
    }

    eventData->next = NULL;

    pthread_mutex_lock(&g_dhcpEventQueueMutex);

    /* Append to tail of queue */
    if (g_dhcpEventQueueTail != NULL)
    {
        g_dhcpEventQueueTail->next = eventData;
    }
    else
    {
        g_dhcpEventQueueHead = eventData;
    }
    g_dhcpEventQueueTail = eventData;

    /* Start the worker thread on first use */
    if (!g_dhcpEventWorkerRunning)
    {
        pthread_t workerThread;
        if (pthread_create(&workerThread, NULL, WanMgr_DhcpEventQueueWorker, NULL) == 0)
        {
            g_dhcpEventWorkerRunning = 1;
            CcspTraceInfo(("%s-%d : DHCP event queue worker thread started\n", __FUNCTION__, __LINE__));
        }
        else
        {
            CcspTraceError(("%s-%d : Failed to create DHCP event queue worker thread\n", __FUNCTION__, __LINE__));
        }
    }

    /* Signal the worker that a new event is available */
    pthread_cond_signal(&g_dhcpEventQueueCond);
    pthread_mutex_unlock(&g_dhcpEventQueueMutex);
}

static void WanMgr_DhcpClientEventsHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;
    rbusObject_t dataObj = NULL;
    rbusValue_t wrappedValue = NULL;
    const char* eventName = event->name;
    CcspTraceInfo(("%s %d:<<DEBUG>> Received event %s\n", __FUNCTION__, __LINE__, eventName));
    if((event == NULL) || (eventName == NULL) || (event->data == NULL))
    {
        CcspTraceError(("%s : FAILED , value is NULL\n",__FUNCTION__));
        return;
    }

    dataObj = event->data;
    wrappedValue = rbusObject_GetValue(event->data, "value");
    if ((wrappedValue != NULL) && (rbusValue_GetType(wrappedValue) == RBUS_OBJECT))
    {
        rbusObject_t nestedObj = rbusValue_GetObject(wrappedValue);
        if (nestedObj != NULL)
        {
            dataObj = nestedObj;
            CcspTraceInfo(("%s %d: Unwrapped auto-publish payload from value object\n", __FUNCTION__, __LINE__));
        }
    }
  
    CcspTraceInfo(("%s %d: Received %s\n", __FUNCTION__, __LINE__, eventName));
    if (strstr(eventName, DHCP_MGR_DHCPv4_TABLE) || strstr(eventName, DHCP_MGR_DHCPv6_TABLE) )
    {
        CcspTraceInfo(("%s %d:<<DEBUG>> Processing DHCP client event %s\n", __FUNCTION__, __LINE__, eventName));
        DhcpEventThreadArgs *eventData = malloc(sizeof(DhcpEventThreadArgs));
        memset(eventData, 0, sizeof(DhcpEventThreadArgs));
        eventData->version = strstr(eventName, DHCP_MGR_DHCPv4_TABLE) ? DHCPV4 : DHCPV6;
        rbusValue_t value;
        value = rbusObject_GetValue(dataObj, "IfName");
        if(value == NULL)
        {
            if (WanMgr_DhcpEvents_ResolveIfName(eventName, eventData->ifName, sizeof(eventData->ifName)))
            {
                CcspTraceInfo(("%s %d: IfName missing in payload, resolved from event name %s -> %s\n",
                                __FUNCTION__, __LINE__, eventName, eventData->ifName));
            }
            else
            {
                CcspTraceError(("%s %d: Failed to get IfName from event data and failed to resolve from %s\n",
                                __FUNCTION__, __LINE__, eventName));
                free(eventData);
                return;
            }
        }

        if (value != NULL)
        {
            const char *ifName = rbusValue_GetString(value, NULL);
            if (ifName == NULL || ifName[0] == '\0')
            {
                CcspTraceError(("%s %d: IfName value is empty\n", __FUNCTION__, __LINE__));
                free(eventData);
                return;
            }
            strncpy(eventData->ifName , ifName, sizeof(eventData->ifName)-1);
        }
        CcspTraceInfo(("%s-%d : DHCP client event %s received for  %s\n", __FUNCTION__, __LINE__, eventName, eventData->ifName));

        value = rbusObject_GetValue(dataObj, "MsgType");
        if(value == NULL)
        {
            CcspTraceError(("%s %d: Failed to get MsgType from event data\n", __FUNCTION__, __LINE__));
            free(eventData);
            return;
        }
        eventData->type = rbusValue_GetUInt32(value);

        if(eventData->type == DHCP_LEASE_UPDATE)
        {
            int bytes_len=0;
            value = rbusObject_GetValue(dataObj, "LeaseInfo");
            uint8_t const* ptr = rbusValue_GetBytes(value, &bytes_len);
            if(eventData->version == DHCPV4)
            {
                if((size_t)bytes_len == sizeof(DHCP_MGR_IPV4_MSG))
                {
                    memcpy(&(eventData->lease.v4), ptr, bytes_len);
                }
                else 
                {
                    CcspTraceError(("%s-%d : DHCPv4 lease length %d and expected %d\n", __FUNCTION__, __LINE__, bytes_len,sizeof(DHCP_MGR_IPV4_MSG) ));   
                }
            }
            else
            {
                if((size_t)bytes_len == sizeof(DHCP_MGR_IPV6_MSG))
                {
                    memcpy(&(eventData->lease.v6), ptr, bytes_len);
                }
                else
                {
                    CcspTraceError(("%s-%d : DHCPv6 lease length %d and expected %d\n", __FUNCTION__, __LINE__, bytes_len,sizeof(DHCP_MGR_IPV6_MSG) ));   
                }
            }
        }

        /* Enqueue the event for ordered processing by the worker thread */
        WanMgr_DhcpEventQueue_Enqueue(eventData);
    }
}

void WanMgr_SubscribeDhcpClientEvents(const char *DhcpInterface)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    char eventName[64] = {0};

    snprintf(eventName, sizeof(eventName), "%s.Events", DhcpInterface);
    rbusEventSubscription_t subscription = {eventName, NULL, 0, 0, WanMgr_DhcpClientEventsHandler, NULL, NULL, NULL, true};

    rc = rbusEvent_SubscribeEx(rbusHandle, &subscription, 1, 60);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, eventName, rbusError_ToString(rc)));
        return;
    }
    
    CcspTraceInfo(("%s %d: Subscribed to %s  n", __FUNCTION__, __LINE__, eventName));
}

void WanMgr_UnSubscribeDhcpClientEvents(const char *DhcpInterface)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    char eventName[64] = {0};
    snprintf(eventName, sizeof(eventName), "%s.Events", DhcpInterface);
    rc = rbusEvent_Unsubscribe(rbusHandle, eventName);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to UnSubscribe %s, Error=%s \n", __FUNCTION__, __LINE__, eventName, rbusError_ToString(rc)));
        return;
    }
    
    CcspTraceInfo(("%s %d: UnSubscribed to %s  n", __FUNCTION__, __LINE__, eventName));
}