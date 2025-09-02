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
#ifndef _WANMGR_MAPE_H_
#define _WANMGR_MAPE_H_

#include <stdio.h>
#include <stdbool.h>
#include "wanmgr_rdkbus_common.h"
#include "ipc_msg.h"
#include "wanmgr_dml.h"
#include "wanmgr_utils.h"

#ifdef FEATURE_MAPE

#define TUNNEL_MTU            1440
#define TUNNEL_NAME           "ip6tnl"
#define IPV4_ADDR_LEN_IN_BITS 32

/****************************************************************************
 * @brief Configure MAP-E tunnel based on DHCPv6 MAP-E parameters
 *
 * @param[in] dhcp6cMAPEMsgBody  MAP-E parameters received via DHCPv6
 * @param[in] ipv6Data           WAN IPv6 interface data
 * @return ANSC_STATUS_SUCCESS on success, ANSC_STATUS_FAILURE on failure
 ***************************************************************************/
ANSC_STATUS WanManager_MAPEConfiguration(ipc_map_data_t *dhcp6cMAPEMsgBody, const WANMGR_IPV6_DATA *ipv6Data);

/****************************************************************************
 * @brief Calculate MAP-E PSID and IPv4 suffix from EA bits
 *
 * @param[in]  pdIPv6Prefix     Delegated IPv6 prefix (string)
 * @param[in]  v6PrefixLen      IPv6 prefix length
 * @param[in]  v4PrefixLen      IPv4 prefix length
 * @param[in]  ea_length        Embedded Address length
 * @param[out] psidValue        Calculated PSID value
 * @param[out] ipv4IndexValue   Calculated IPv4 index value
 * @param[out] psidLen          Calculated PSID length
 * @return RETURN_OK on success
 ***************************************************************************/
INT WanManager_CalculateMAPEPsid(CHAR *pdIPv6Prefix, INT v6PrefixLen, INT v4PrefixLen, INT ea_length, USHORT *psidValue, UINT *ipv4IndexValue, UINT *psidLen);

/****************************************************************************
 * @brief Reset MAP-E syscfg parameters to defaults
 ***************************************************************************/
VOID WanManager_MAPE_ResetSyscfgDefaults(VOID);

#endif /* FEATURE_MAPE */

#endif /* _WANMGR_MAPE_H_ */
