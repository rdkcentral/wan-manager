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
*********************************************************************************/
#ifndef  _WANMGR_MAP_APIS_H
#define  _WANMGR_MAP_APIS_H


#define DML_BUFF_SIZE_32    32
#define DML_BUFF_SIZE_64    64

typedef enum
_WAN_DML_DOMAIN_STATUS
{
    WAN_DML_DOMAIN_STATUS_Disabled = 1,
    WAN_DML_DOMAIN_STATUS_Enabled
} WAN_DML_DOMAIN_STATUS;

typedef enum
_WAN_DML_RULE_STATUS
{
    WAN_DML_RULE_STATUS_Disabled = 1,
    WAN_DML_RULE_STATUS_Enabled
} WAN_DML_RULE_STATUS;

typedef enum _WAN_DML_DOMAIN_TRANSPORT
{
    WAN_DML_DOMAIN_TRANSPORT_MAPE = 1,
    WAN_DML_DOMAIN_TRANSPORT_MAPT,
    WAN_DML_DOMAIN_TRANSPORT_UNKNOWN
} WAN_DML_DOMAIN_TRANSPORT;

typedef enum _WAN_DML_INTERFACE_STATUS
{
    WAN_DML_INTERFACE_STATUS_Up = 1,
    WAN_DML_INTERFACE_STATUS_Down
} WAN_DML_INTERFACE_STATUS;

/*
 *  Structure definitions for MAP Domain
 */
typedef  struct
_WAN_DML_DOMAIN_CFG
{
    ULONG                         InstanceNumber;
    CHAR                          Alias[DML_BUFF_SIZE_32];
    BOOLEAN                       bEnabled;
    CHAR                          WANInterface[DML_BUFF_SIZE_32];
    CHAR                          IPv6Prefix[DML_BUFF_SIZE_64];
    CHAR                          BRIPv6Prefix[DML_BUFF_SIZE_64];
    INT                           DSCPMarkPolicy;
    /*
     * Interface
     */
    BOOLEAN                       IfaceEnable;
    CHAR                          IfaceAlias[DML_BUFF_SIZE_32];
    CHAR                          IfaceLowerLayers[DML_BUFF_SIZE_64];
}
WAN_DML_DOMAIN_CFG,  *PWAN_DML_DOMAIN_CFG;

typedef  struct
_WAN_DML_DOMAIN_INFO
{
    WAN_DML_DOMAIN_STATUS         Status;
    CHAR                          Name[DML_BUFF_SIZE_64];
    WAN_DML_DOMAIN_TRANSPORT      TransportMode;
    /*
     * Interface
     */
    WAN_DML_INTERFACE_STATUS      IfaceStatus;
    CHAR                          IfaceName[DML_BUFF_SIZE_64];
    ULONG                         IfaceLastChange;
}WAN_DML_DOMAIN_INFO,  *PWAN_DML_DOMAIN_INFO;

typedef  struct
_WAN_DML_DOMAIN_FULL
{
    WAN_DML_DOMAIN_CFG            Cfg;
    WAN_DML_DOMAIN_INFO           Info;
}
WAN_DML_DOMAIN_FULL, *PWAN_DML_DOMAIN_FULL;

typedef  struct
_WAN_DML_DOMAIN_FULL2
{
    WAN_DML_DOMAIN_CFG            Cfg;
    WAN_DML_DOMAIN_INFO           Info;
    SLIST_HEADER                  RuleList;
    ULONG                         ulNextRuleInsNum;
}
WAN_DML_DOMAIN_FULL2, *PWAN_DML_DOMAIN_FULL2;

 /* Interface Stat structure */
typedef struct
_WAN_DML_INTERFACE_STAT
{
    ULONG                         BytesSent;
    ULONG                         BytesReceived;
    ULONG                         PacketsSent;
    ULONG                         PacketsReceived;
    ULONG                         ErrorsSent;
    ULONG                         ErrorsReceived;
    ULONG                         UnicastPacketsSent;
    ULONG                         UnicastPacketsReceived;
    ULONG                         DiscardPacketsSent;
    ULONG                         DiscardPacketsReceived;
    ULONG                         MulticastPacketsSent;
    ULONG                         MulticastPacketsReceived;
    ULONG                         BroadcastPacketsSent;
    ULONG                         BroadcastPacketsReceived;
    ULONG                         UnknownProtoPacketsReceived;

}WAN_DML_INTERFACE_STAT, *PWAN_DML_INTERFACE_STAT;

 /* Domain Rule structure */
typedef struct
_WAN_DML_MAP_RULE
{
    ULONG                         InstanceNumber;
    BOOL                          Enable;
    WAN_DML_RULE_STATUS           Status;
    CHAR                          Alias[DML_BUFF_SIZE_32];
    CHAR                          Origin[DML_BUFF_SIZE_32];
    CHAR                          IPv6Prefix[DML_BUFF_SIZE_64];
    CHAR                          IPv4Prefix[DML_BUFF_SIZE_64];
    UINT                          EABitsLength;
    BOOL                          IsFMR;
    UINT                          PSIDOffset;
    UINT                          PSIDLength;
    UINT                          PSID;
    BOOL                          IncludeSystemPorts;
}WAN_DML_MAP_RULE, *PWAN_DML_MAP_RULE;

typedef  struct
_WAN_PRI_MAP_DOM_FULL
{
    WAN_DML_DOMAIN_CFG            Cfg;
    WAN_DML_DOMAIN_INFO           Info;
    USHORT                        ulNumOfRule;
    PWAN_DML_MAP_RULE             pRuleList;
}
WAN_PRI_MAP_DOM_FULL, *PWAN_PRI_MAP_DOM_FULL;

/*
    Function declaration
*/
ULONG
WanDmlMapDomGetNumberOfEntries
    (
        ANSC_HANDLE                 hContext
    );

ANSC_STATUS
WanDmlMapDomGetEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PWAN_DML_DOMAIN_FULL        pEntry
    );

ANSC_STATUS
WanDmlMapDomGetCfg
    (
        ANSC_HANDLE                 hContext,
        PWAN_DML_DOMAIN_CFG         pCfg
    );

ANSC_STATUS
WanDmlMapDomGetCfg_Data
    (
        ULONG                       ulInstanceNumber,
        PWAN_DML_DOMAIN_CFG         pDomCfg
    );

ANSC_STATUS
WanDmlMapDomSetCfg
    (
        ANSC_HANDLE                 hContext,
        PWAN_DML_DOMAIN_CFG         pCfg
    );

ANSC_STATUS
WanDmlMapDomGetInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PWAN_DML_DOMAIN_INFO        pInfo
    );

ANSC_STATUS
WanDmlMapDomGetInfo_Data
    (
        ULONG                       ulInstanceNumber,
        PWAN_DML_DOMAIN_INFO        pDomInfo
    );

ANSC_STATUS
WanDmlMapDomSetInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PWAN_DML_DOMAIN_INFO        pInfo
    );

ULONG
WanDmlMapDomGetNumberOfRules
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulMapDomInstanceNumber
    );

ANSC_STATUS
WanDmlMapDomGetRule
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulMapDomInstanceNumber,
        ULONG                       ulIndex,
        PWAN_DML_MAP_RULE           pEntry
    );

ANSC_STATUS
WanDmlMapDomGetRule_Data
    (
        ULONG                       ulMapDomInstanceNumber,
        ULONG                       ulIndex,
        PWAN_DML_MAP_RULE           pMapRule
    );

ANSC_STATUS
WanDmlMapDomSetRule
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulMapDomInstanceNumber,
        ULONG                       ulIndex,
        PWAN_DML_MAP_RULE           pEntry
    );

INT
WanDmlMapDomGetIfStats
    (
        CHAR *ifname,
        PWAN_DML_INTERFACE_STAT pStats
    );

#endif /* _WANMGR_MAP_APIS_H */
