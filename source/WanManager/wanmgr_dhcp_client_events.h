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

#ifndef _WANMGR_DHCP_EVENTS_H_
#define _WANMGR_DHCP_EVENTS_H_

typedef enum _DHCP_VERSION
{
    DHCPV4 = 0,
    DHCPV6
}DHCP_VERSION;
typedef struct _DhcpEventThreadArgs 
{
    char ifName[20];
    DHCP_MESSAGE_TYPE type;
    DHCP_VERSION version;
    union 
    {
        DHCP_MGR_IPV4_MSG v4;
        DHCP_MGR_IPV6_MSG v6;
    }lease;
    struct _DhcpEventThreadArgs *next; /* linked-list pointer for event queue */
}DhcpEventThreadArgs;

/* Process a single DHCP client event (called by queue worker thread). */
void WanMgr_ProcessDhcpClientEvent(DhcpEventThreadArgs *eventData);

/* Enqueue a DHCP event for ordered processing; starts worker thread on first call. */
void WanMgr_DhcpEventQueue_Enqueue(DhcpEventThreadArgs *eventData);

#endif //_WANMGR_DHCP_EVENTS_H_