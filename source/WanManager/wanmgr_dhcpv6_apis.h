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

#ifndef _WANMGR_DHCPV6_APIS_H_
#define _WANMGR_DHCPV6_APIS_H_
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "ansc_platform.h"
#include "ipc_msg.h"
#include "wanmgr_dhcpv4_apis.h"


/**********************************************************************
                STRUCTURE AND CONSTANT DEFINITIONS
**********************************************************************/
#define IFADDRCONF_ADD 0
#define IFADDRCONF_REMOVE 1

#define CCSP_COMMON_FIFO "/tmp/ccsp_common_fifo"

#define  DML_DHCP_MAX_ENTRIES                  4
#define  DML_DHCP_MAX_RESERVED_ADDRESSES       8
#define  DML_DHCP_MAX_OPT_ENTRIES              8

#define _DEBUG_DHCPV6
#ifdef _DEBUG_DHCPV6
    #define ULOGF ulogf
#else
    #define ULOGF
#endif

#define COSA_DML_DHCPV6_SERVER_IFNAME                 CFG_TR181_DHCPv6_SERVER_IfName

#define COSA_DML_DHCPV6C_PREF_SYSEVENT_NAME           "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_v6pref"
#define COSA_DML_DHCPV6C_PREF_IAID_SYSEVENT_NAME      "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_pref_iaid"
#define COSA_DML_DHCPV6C_PREF_T1_SYSEVENT_NAME        "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_pref_t1"
#define COSA_DML_DHCPV6C_PREF_T2_SYSEVENT_NAME        "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_pref_t2"
#define COSA_DML_DHCPV6C_PREF_PRETM_SYSEVENT_NAME     "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_pref_pretm"
#define COSA_DML_DHCPV6C_PREF_VLDTM_SYSEVENT_NAME     "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_pref_vldtm"

#define COSA_DML_DHCPV6C_ADDR_SYSEVENT_NAME           "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_v6addr"
#define COSA_DML_DHCPV6C_ADDR_IAID_SYSEVENT_NAME      "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_addr_iaid"
#define COSA_DML_DHCPV6C_ADDR_T1_SYSEVENT_NAME        "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_addr_t1"
#define COSA_DML_DHCPV6C_ADDR_T2_SYSEVENT_NAME        "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_addr_t2"
#define COSA_DML_DHCPV6C_ADDR_PRETM_SYSEVENT_NAME     "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_addr_pretm"
#define COSA_DML_DHCPV6C_ADDR_VLDTM_SYSEVENT_NAME     "tr_"DML_DHCP_CLIENT_IFNAME"_dhcpv6_client_addr_vldtm"

#if defined (CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) || defined (INTEL_PUMA7)
#define COSA_DML_DHCPV6S_ADDR_SYSEVENT_NAME      "ipv6_"COSA_DML_DHCPV6_SERVER_IFNAME"-addr"
#else
#define COSA_DML_DHCPV6S_ADDR_SYSEVENT_NAME      "tr_"COSA_DML_DHCPV6_SERVER_IFNAME"_dhcpv6_server_v6addr"
#endif

typedef struct {
    char event[BUFLEN_16];                  // e.g. "NEWADDR" or "DELADDR"
    char ifname[BUFLEN_32];                 // interface name, e.g. wlan0
    char addr[INET6_ADDRSTRLEN];            // IPv6 full address
    unsigned int prefix_len;                // prefix length
    unsigned int preferred_lft;             // preferred lifetime
    unsigned int valid_lft;                 // valid lifetime
} IPv6NetLinkAddrEvent;

/*
 *  DHCP Client
 */

#ifdef FEATURE_MAPT
#define SYSEVENT_MAPT_CONFIG_FLAG "mapt_config_flag"
#define SYSEVENT_MAPT_RATIO "mapt_ratio"
#define SYSEVENT_MAP_RULE_IPADDRESS "map_rule_ip_address"
#define SYSEVENT_MAPT_PSID_OFFSET "mapt_psid_offset"
#define SYSEVENT_MAPT_PSID_VALUE "mapt_psid_value"
#define SYSEVENT_MAPT_PSID_LENGTH "mapt_psid_length"
#define SYSEVENT_MAP_RULE_IPV6_ADDRESS "map_rule_ipv6_address"
#define SYSEVENT_MAP_EA_LEN "map_ea_length"
#define SYSEVENT_MAP_TRANSPORT_MODE "map_transport_mode"
#define SYSEVENT_MAP_IS_FMR "map_is_fmr"
#define SYSEVENT_MAP_BR_IPV6_PREFIX        "map_br_ipv6_prefix"
#define SYSEVENT_MAPT_IPADDRESS "mapt_ip_address"
#endif

typedef  struct
_DML_DHCPCV6_SVR
{
    UCHAR                           SourceAddress[40];
    UCHAR                           DUID[131]; /* IP interface name */
    UCHAR                           InformationRefreshTime[32];
}
DML_DHCPCV6_SVR,  *PDML_DHCPCV6_SVR;

typedef  struct
_DML_DHCPCV6_CFG
{
    ULONG                           InstanceNumber;
    UCHAR                           Alias[DML_ALIAS_NAME_LENGTH];
    LONG                            SuggestedT1;
    LONG                            SuggestedT2;
    UCHAR                           Interface[DML_ALIAS_NAME_LENGTH]; /* IP interface name */
    UCHAR                           RequestedOptions[512];
    BOOLEAN                         bEnabled;
    BOOLEAN                         RequestAddresses;
    BOOLEAN                         RequestPrefixes;
    BOOLEAN                         RapidCommit;
    BOOLEAN                         Renew;
}
DML_DHCPCV6_CFG,  *PDML_DHCPCV6_CFG;

typedef struct
_DML_DHCPCV6_INFO
{
    DML_DHCP_STATUS            Status;
    UCHAR                           SupportedOptions[512];
    UCHAR                           DUID[131];
}
DML_DHCPCV6_INFO,  *PDML_DHCPCV6_INFO;


typedef  struct
_DML_DHCPCV6_FULL
{
    DML_DHCPCV6_CFG              Cfg;
    DML_DHCPCV6_INFO             Info;
}
DML_DHCPCV6_FULL, *PDML_DHCPCV6_FULL;

typedef  struct
_DML_DHCPCV6_SENT
{
    ULONG                           InstanceNumber;
    UCHAR                           Alias[DML_ALIAS_NAME_LENGTH];

    BOOLEAN                         bEnabled;
    ULONG                           Tag;
    UCHAR                           Value[255];
}
DML_DHCPCV6_SENT,  *PDML_DHCPCV6_SENT;

struct
_DML_DHCPCV6_RECV
{
    SINGLE_LINK_ENTRY               Link;
    ULONG                           Tag;
    UCHAR                           Server[255];
    UCHAR                           Value[1024];
};
typedef struct _DML_DHCPCV6_RECV DML_DHCPCV6_RECV,  *PDML_DHCPCV6_RECV;

#define  ACCESS_DHCPV6_RECV_LINK_OBJECT(p)              \
         ACCESS_CONTAINER(p, DML_DHCPCV6_RECV, Link)


BOOL tagPermitted(int tag);
int _datetime_to_secs(char * p_dt);

/**********************************************************************
                FUNCTION PROTOTYPES
**********************************************************************/

ULONG
WanMgr_DmlDhcpv6cGetNumberOfEntries
    (
        ANSC_HANDLE                 hContext
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cGetEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PDML_DHCPCV6_FULL      pEntry
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cSetValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cAddEntry
    (
        ANSC_HANDLE                 hContext,
        PDML_DHCPCV6_FULL      pEntry
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cDelEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cSetCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_DHCPCV6_CFG       pCfg
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cGetCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_DHCPCV6_CFG       pCfg
    );

BOOL
WanMgr_DmlDhcpv6cGetEnabled
    (
        ANSC_HANDLE                 hContext
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cGetInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PDML_DHCPCV6_INFO      pInfo
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cGetServerCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_SVR      *ppCfg,
        PULONG                      pSize
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cRenew
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    );

ULONG
WanMgr_DmlDhcpv6cGetNumberOfSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cGetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        PDML_DHCPCV6_SENT      pEntry
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cGetSentOptionbyInsNum
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_SENT      pEntry
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cSetSentOptionValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cAddSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_SENT      pEntry
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cDelSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulInstanceNumber
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cSetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_SENT      pEntry
    );

ANSC_STATUS
WanMgr_DmlDhcpv6cGetReceivedOptionCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_RECV     *pEntry,
        PULONG                      pSize
    );
/* TBC  -- the functions below should be reviewed, on necessity and name convention */
void     
WanMgr_DmlDhcpv6Remove
    (
        ANSC_HANDLE hContext
    );

int 
WanMgr_DmlStartDHCP6Client
    (
    void
    );



/**
 * @brief API to process DHCP state change event message.
 * @param msg - Pointer to msg_payload_t structure contains Dhcpv6 configuration as part of ipc message
 * @return ANSC_STATUS_SUCCESS upon success else error code returned.
 */
ANSC_STATUS wanmgr_handle_dhcpv6_event_data(DML_VIRTUAL_IFACE * pVirtIf);

void _get_shell_output(FILE *fp, char * out, int len);

/************************************************************************************
 * @brief Set v6 prefixe required for lan configuration
 * @return RETURN_OK on success else RETURN_ERR
 ************************************************************************************/
int setUpLanPrefixIPv6(DML_VIRTUAL_IFACE* pVirtIf);

ANSC_STATUS WanMgr_Handle_Dhcpv6_NetLink_Address_Event(IPv6NetLinkAddrEvent *pstAddrEvent);

#endif //_WANMGR_DHCPV6_APIS_H_
