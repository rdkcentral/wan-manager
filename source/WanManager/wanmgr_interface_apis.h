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

#ifndef _WANMGR_INTERFACE_APIS_H_
#define _WANMGR_INTERFACE_APIS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>
#include "wanmgr_data.h"
#include "wanmgr_interface_sm.h"


/**
 * @brief Starts the interface state machine to obtain a WAN lease on all virtual interfaces configured for the specified interface.
 *
 * @param[in] interfaceIndex Index of the WAN interface to start.
 * @param[in] selectionStatus Selection status for the interface. Possible values:
 *   - WAN_IFACE_UNKNOWN: Interface selection status is unknown.
 *   - WAN_IFACE_NOT_SELECTED: Interface is not selected.
 *   - WAN_IFACE_VALIDATING: Start WAN and move to standby state.
 *   - WAN_IFACE_SELECTED: Start WAN and move to standby state.
 *   - WAN_IFACE_ACTIVE: Start WAN and activate the interface if it obtains an IP address.
 *
 * @return Status of the operation.
 */
int WanMgr_StartWanVISM(int interfaceIndex, WANMGR_IFACE_SELECTION selectionStatus);

/**
 * @brief Stop WAN .
 *
 * This function stops the WAN interface state machine and sets the selection status to not selected.
 *
 * @param[in] interfaceIndex Index of the WAN interface to deactivate.
 * @return Status of the operation.
 */
int WanMgr_StopWanVISM(int interfaceIndex);

/**
 * @brief Activates the WAN interface specified by the given index.
 *
 * If the interface is not already active, this function activates it by configuring
 * the default route, firewall, DNS, and MAP-T settings of the device based on the lease,
 * and transitions the interface to the active state. 
 * If a different interface is already active, it returns failure.
 *
 * @param interfaceIndex The index of the WAN interface to activate.
 * @return Returns 0 on success, or a negative error code on failure.
 */
int WanMgr_ActivateInterface(int interfaceIndex);

/**
 * @brief Deactivates the WAN interface and deconfigures the default route, firewall, DNS, and WAN IP, moving the interface back to the standby state.
 *
 * This function Deactivates the specified WAN interface, removes its default route, firewall, DNS settings, and WAN IP configuration, and transitions the interface to the standby state.
 *
 * @param[in] interfaceIndex The index of the WAN interface to deactivate.
 * @return 0 on success, or a negative error code on failure.
 */
int WanMgr_DeactivateInterface(int interfaceIndex);

#endif /* _WANMGR_INTERFACE_APIS_H_ */