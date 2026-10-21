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
 * The capture runs for a fixed window (5 minutes) starting from this call and then
 * closes itself. Every NS/NA it sees is logged in full, nothing is rate limited away,
 * so the window is what bounds the log volume.
 *
 * On platforms where the WAN runs over a virtual interface the kernel may transmit
 * the ND frames on the base interface instead, so both can be captured at once.
 *
 * @param ifname     Interface to capture on, e.g. the virtual interface name 'vdsl0'.
 * @param baseIfname Base interface of @p ifname, e.g. 'ptm0'. Captured in addition to
 *                   @p ifname. May be NULL, empty or equal to @p ifname, in which case
 *                   only @p ifname is captured.
 */
void WanMgr_NdMonitor_Start( const char *ifname, const char *baseIfname );

/**
 * @brief Records that the ICMPv6 Neighbour Discovery capture is no longer required.
 *
 * Called by the interface state machine once DAD has succeeded, or when the DHCPv6
 * client is stopped. The request is ignored if the capture is currently running for
 * a different interface.
 *
 * This does not tear the capture down. The state machine reaches its own DAD verdict
 * before the kernel has necessarily finished DAD for the global address, and closing
 * the socket in that gap discards the very NS/NA this capture exists for. The capture
 * instead runs to the end of the window opened by WanMgr_NdMonitor_Start().
 *
 * @param ifname Interface the capture was started for, NULL to match unconditionally.
 */
void WanMgr_NdMonitor_Stop( const char *ifname );

#endif /* _NETWORK_ROUTE_MONITOR_H_ */
