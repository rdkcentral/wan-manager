/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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

#ifndef _NETWORK_ROUTE_MONITOR_H_
#define _NETWORK_ROUTE_MONITOR_H_

#include "ansc_platform.h"

ANSC_STATUS WanMgr_StartNetWorkMonitor( void );

/**
 * @brief Starts an ICMPv6 Neighbour Discovery capture on the given interface.
 *
 * Netlink reports a DAD failure (RTM_NEWADDR with IFA_F_DADFAILED) but not the
 * Neighbour Advertisement that caused it. This capture logs the NS/NA exchange,
 * including the sender link layer address and the NA flags, so a DAD failure can
 * be attributed to a real duplicate, an ND proxy or a router answering for the
 * address. Called by the interface state machine when the DHCPv6 client starts.
 *
 * The capture stops on its own if it is not stopped within a few minutes.
 *
 * @param ifname Interface to capture on, e.g. the virtual interface name.
 */
void WanMgr_NdMonitor_Start( const char *ifname );

/**
 * @brief Stops the ICMPv6 Neighbour Discovery capture started for an interface.
 *
 * Called by the interface state machine once DAD has succeeded, or when the
 * DHCPv6 client is stopped. The request is ignored if the capture is currently
 * running for a different interface.
 *
 * @param ifname Interface the capture was started for, NULL to stop unconditionally.
 */
void WanMgr_NdMonitor_Stop( const char *ifname );

#endif /* _NETWORK_ROUTE_MONITOR_H_ */
