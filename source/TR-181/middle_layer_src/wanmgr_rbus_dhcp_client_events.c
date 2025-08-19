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

static void WanMgr_DhcpClientEventsHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    const char* eventName = event->name;

    if((eventName == NULL))
    {
        CcspTraceError(("%s : FAILED , value is NULL\n",__FUNCTION__));
        return;
    }

    pthread_t dhcpEvent_thread;

    //CcspTraceInfo(("%s %d: Received %s\n", __FUNCTION__, __LINE__, eventName));
    if (strstr(eventName, DHCP_MGR_DHCPv4_TABLE) || strstr(eventName, DHCP_MGR_DHCPv6_TABLE) )
    {
        DhcpEventThreadArgs *eventData = malloc(sizeof(DhcpEventThreadArgs));
        memset(eventData, 0, sizeof(DhcpEventThreadArgs));
        eventData->version = strstr(eventName, DHCP_MGR_DHCPv4_TABLE) ? DHCPV4 : DHCPV6;
        rbusValue_t value;
        value = rbusObject_GetValue(event->data, "IfName");
        strncpy(eventData->ifName , rbusValue_GetString(value, NULL), sizeof(eventData->ifName)-1);
        CcspTraceInfo(("%s-%d : DHCP client event %s received for  %s\n", __FUNCTION__, __LINE__, eventName, eventData->ifName));

        value = rbusObject_GetValue(event->data, "MsgType");
        eventData->type = rbusValue_GetUInt32(value);

        if(eventData->type == DHCP_LEASE_UPDATE)
        {
            int bytes_len=0;
            value = rbusObject_GetValue(event->data, "LeaseInfo");
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

        if(pthread_create(&dhcpEvent_thread, NULL, WanMgr_DhcpClientEventsHandler_Thread, eventData) != 0)
        {
            CcspTraceError(("%s %d: Failed to create thread for DHCPv4 event\n", __FUNCTION__, __LINE__));
            free(eventData);
            return;
        }
        /* Adding sleep to make sure the thread locks the DhcpClientEvents_mutex */
        usleep(10000);
    }
}

void WanMgr_SubscribeDhcpClientEvents(const char *DhcpInterface)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    char eventName[64] = {0};
    snprintf(eventName, sizeof(eventName), "%s.Events", DhcpInterface);
    rc = rbusEvent_Subscribe(rbusHandle, eventName, WanMgr_DhcpClientEventsHandler, NULL, 60);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, eventName, rbusError_ToString(rc)));
        return NULL;
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
        return NULL;
    }
    
    CcspTraceInfo(("%s %d: UnSubscribed to %s  n", __FUNCTION__, __LINE__, eventName));
}