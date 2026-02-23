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

#ifndef  _WANMGR_DML_H_
#define  _WANMGR_DML_H_

#include "ipc_msg.h"

#define PAM_COMPONENT_NAME          "eRT.com.cisco.spvtg.ccsp.pam"
#define PAM_DBUS_PATH               "/com/cisco/spvtg/ccsp/pam"
#define PAM_NOE_PARAM_NAME          "Device.IP.InterfaceNumberOfEntries"
#define PAM_IF_TABLE_OBJECT         "Device.IP.Interface.%d."
#define PAM_IF_PARAM_NAME           "Device.IP.Interface.%d.Name"
#define DML_WAN_IFACE_PRIORITY_MAX  255
#define REMOTE_INTERFACE_NAME       "brRWAN"
#define REMOTE_INTERFACE_GROUP        2
#define MAX_INTERFACE_GROUP           2
#define WAN_MANAGER_VERSION         "1.5"
#define WIFI_BASE_IFACE_PATH        "Device.WiFi.EndPoint."
#define WANMGR_MAX_RA_DNS_SUPPORT       5   // Up to 5 DNS servers

typedef enum _WANMGR_IFACE_SELECTION_STATUS
{
    WAN_IFACE_UNKNOWN,
    WAN_IFACE_NOT_SELECTED,
    WAN_IFACE_VALIDATING,
    WAN_IFACE_SELECTED,
    WAN_IFACE_ACTIVE
} WANMGR_IFACE_SELECTION;

typedef enum _DML_WAN_POLICY
{
   FIXED_MODE_ON_BOOTUP = 1,
   FIXED_MODE,
   PRIMARY_PRIORITY_ON_BOOTUP,
   PRIMARY_PRIORITY,
   MULTIWAN_MODE,
   AUTOWAN_MODE,
   PARALLEL_SCAN
} DML_WAN_POLICY;

typedef enum _DEVICE_NETWORKING_MODE_
{
    GATEWAY_MODE = 1,
    MODEM_MODE
} DEVICE_NETWORKING_MODE;

typedef enum _DML_WAN_IFACE_OPER_STATUS
{
    WAN_OPERSTATUS_UNKNOWN = 1,
    WAN_OPERSTATUS_OPERATIONAL,
    WAN_OPERSTATUS_NOT_OPERATIONAL
} DML_WAN_IFACE_OPER_STATUS;

typedef enum _DML_WAN_IFACE_STATUS
{
    WAN_IFACE_STATUS_DISABLED = 1,
    WAN_IFACE_STATUS_INITIALISING,
    WAN_IFACE_STATUS_VALIDATING,
    WAN_IFACE_STATUS_VALID,
    WAN_IFACE_STATUS_UP,
    WAN_IFACE_STATUS_INVALID,
    WAN_IFACE_STATUS_STANDBY
} DML_WAN_IFACE_STATUS;

typedef enum _WANMGR_IFACE_CONNECTION_TYPE
{
    WAN_IFACE_CONN_TYPE_PRIMARY = 0,
    WAN_IFACE_CONN_TYPE_COLD_STANDBY,
    WAN_IFACE_CONN_TYPE_HOT_STANDBY
} WANMGR_IFACE_CONNECTION_TYPE;

typedef enum _DML_WAN_IFACE_SCAN_STATUS
{
    WAN_IFACE_STATUS_NOT_SCANNED = 1,
    WAN_IFACE_STATUS_SCANNED,
} DML_WAN_IFACE_SCAN_STATUS;

typedef enum _DML_WAN_IFACE_LINKSTATUS
{
    WAN_IFACE_LINKSTATUS_DOWN = 1,
    WAN_IFACE_LINKSTATUS_CONFIGURING,
    WAN_IFACE_LINKSTATUS_UP
} DML_WAN_IFACE_LINKSTATUS;
typedef enum _WAN_MANAGER_STATUS
{
    WAN_MANAGER_DOWN = 1,
    WAN_MANAGER_UP
} WAN_MANAGER_STATUS;

/** enum wan iface phy status */
typedef enum _DML_WAN_IFACE_PHY_STATUS
{
    WAN_IFACE_PHY_STATUS_DOWN = 1,
    WAN_IFACE_PHY_STATUS_INITIALIZING,
    WAN_IFACE_PHY_STATUS_UP,
    WAN_IFACE_PHY_STATUS_UNKNOWN
} DML_WAN_IFACE_PHY_STATUS;

/** enum wan status */
typedef enum _DML_WAN_IFACE_TYPE
{
    WAN_IFACE_TYPE_UNCONFIGURED = 1,
    WAN_IFACE_TYPE_PRIMARY,
    WAN_IFACE_TYPE_SECONDARY
} DML_WAN_IFACE_TYPE;

/** enum wan status */
typedef enum _DML_WAN_IFACE_IPV4_STATUS
{
    WAN_IFACE_IPV4_STATE_UP = 1,
    WAN_IFACE_IPV4_STATE_DOWN,
    WAN_IFACE_IPV4_STATE_UNKNOWN
} DML_WAN_IFACE_IPV4_STATUS;

/** enum wan status */
typedef enum _DML_WAN_IFACE_IPV6_STATUS
{
    WAN_IFACE_IPV6_STATE_UP = 1,
    WAN_IFACE_IPV6_STATE_DOWN,
    WAN_IFACE_IPV6_STATE_UNKNOWN
} DML_WAN_IFACE_IPV6_STATUS;

/** enum wan status */
typedef enum _DML_WAN_IFACE_MAPT_STATUS
{
    WAN_IFACE_MAPT_STATE_UP = 1,
    WAN_IFACE_MAPT_STATE_DOWN
} DML_WAN_IFACE_MAPT_STATUS;

/** enum map-e status */
typedef enum _DML_WAN_IFACE_MAPE_STATUS
{
    WAN_IFACE_MAPE_STATE_UP = 1,
    WAN_IFACE_MAPE_STATE_DOWN
} DML_WAN_IFACE_MAPE_STATUS;

/** enum dslite status */
typedef enum _DML_WAN_IFACE_DSLITE_STATUS
{
    WAN_IFACE_DSLITE_STATE_UP = 1,
    WAN_IFACE_DSLITE_STATE_DOWN
} DML_WAN_IFACE_DSLITE_STATUS;

/** enum wan status */
typedef enum _WAN_NOTIFY_ENUM
{
    NOTIFY_TO_VLAN_AGENT        = 1
} WAN_NOTIFY_ENUM;

/** Enum IP (IPV4/IPV6/MAPT) state type. **/
typedef enum _DML_WAN_IFACE_IP_STATE_TYPE
{
    WAN_IFACE_IPV4_STATE = 0,
    WAN_IFACE_IPV6_STATE,
    WAN_IFACE_MAPT_STATE,
    WAN_IFACE_DSLITE_STATE
} DML_WAN_IFACE_IP_STATE_TYPE;

/** Enum IP state. UP/DOWN */
typedef enum _DML_WAN_IFACE_IP_STATE
{
    WAN_IFACE_IP_STATE_UP = 1,
    WAN_IFACE_IP_STATE_DOWN,
} DML_WAN_IFACE_IP_STATE;

typedef enum _DML_WAN_IP_SOURCE
{
    DML_WAN_IP_SOURCE_STATIC = 1,
    DML_WAN_IP_SOURCE_DHCP,
    DML_WAN_IP_SOURCE_PPP,
    DML_WAN_IP_SOURCE_SLAAC,
    DML_WAN_IP_SOURCE_MAX
} DML_WAN_IP_SOURCE;

typedef enum _DML_WAN_IP_MODE
{
    DML_WAN_IP_MODE_IPV4_ONLY = 1,
    DML_WAN_IP_MODE_IPV6_ONLY,
    DML_WAN_IP_MODE_DUAL_STACK,
    DML_WAN_IP_MODE_NO_IP,
    DML_WAN_IP_MODE_MAX
} DML_WAN_IP_MODE;

typedef enum _DML_WAN_IP_PREFERRED_MODE
{
    DUAL_STACK_MODE = 1,
    MAPT_MODE,
    MAPE_MODE,
    DSLITE_MODE
} DML_WAN_IP_PREFERRED_MODE;

typedef enum _WANMGR_DHCPC_STATUS
{
    DHCPC_STATE_UNKNOWN = 1,
    DHCPC_STARTED,
    DHCPC_STOPPED,
    DHCPC_FAILED,
    DHCPC_DISABLED,
} WANMGR_DHCPC_STATUS;

typedef enum _TIMER_STATUS
{
    NOTSTARTED = 1,
    EXPIRED,
    RUNNING,
    COMPLETE
} TIMER_STATUS;

/*
 *  Wan Marking object
 */
typedef enum _DML_WAN_MARKING_DML_OPERATIONS
{
    WAN_MARKING_ADD = 1,
    WAN_MARKING_DELETE,
    WAN_MARKING_UPDATE
} DML_WAN_MARKING_DML_OPERATIONS;

typedef struct _DML_MARKING
{
    ULONG      InstanceNumber;
    ULONG      ulWANIfInstanceNumber;
    CHAR       Alias[BUFLEN_64];
    UINT       SKBPort;
    UINT       SKBMark;
    INT        EthernetPriorityMark;
} DML_MARKING;

typedef struct _DATAMODEL_MARKING
{
    SLIST_HEADER      MarkingList;
    ULONG             ulNextInstanceNumber;
} DATAMODEL_MARKING;

/*** RDK WAN Interface ***/
typedef enum _DML_WAN_IFACE_IPCP_STATUS
{
    WAN_IFACE_IPCP_STATUS_DOWN = 1,
    WAN_IFACE_IPCP_STATUS_UP
} DML_WAN_IFACE_IPCP_STATUS;

typedef enum _DML_WAN_IFACE_IPV6CP_STATUS
{
    WAN_IFACE_IPV6CP_STATUS_DOWN = 1,
    WAN_IFACE_IPV6CP_STATUS_UP,
} DML_WAN_IFACE_IPV6CP_STATUS;

typedef enum _DML_WAN_IFACE_PPP_LINK_STATUS
{
    WAN_IFACE_PPP_LINK_STATUS_DOWN = 1,
    WAN_IFACE_PPP_LINK_STATUS_CONFIGURING,
    WAN_IFACE_PPP_LINK_STATUS_UP,
} DML_WAN_IFACE_PPP_LINK_STATUS;

typedef enum _IFACE_TYPE 
{
    LOCAL_IFACE = 1,
    REMOTE_IFACE
} IFACE_TYPE;

typedef enum {
    STATE_GROUP_UNKNOWN = 1,
    STATE_GROUP_RUNNING,
    STATE_GROUP_STOPPED,
    STATE_GROUP_DEACTIVATED,
} WAN_IFACE_GROUP_STATUS;

typedef enum {
    HOTSWAP = 1,
    COLDSWAP
} FAILOVER_TYPE;

typedef enum {
    WAN_CONNECTION_UNKNOWN =0,
    WAN_CONNECTIVITY_UP = 1,
    WAN_CONNECTIVITY_DOWN,
} CONNECTIVITY_STATUS;

typedef enum {
    WAN_CONNECTIVITY_TYPE_NO_CHECK,
    WAN_CONNECTIVITY_TYPE_IHC,
    WAN_CONNECTIVITY_TYPE_TAD,
    WAN_CONNECTIVITY_TYPE_MAX
} CONNECTIVITY_CHECK_TYPE;

typedef enum {
    CONNECTION_MSG_IPV4 = 1,
    CONNECTION_MSG_IPV6
} CONNECTION_TYPE;

/* WCC -  WAN CONNECTIVITY CHECK */
typedef enum {
    WCC_STOP = 0,
    WCC_START,
    WCC_RESTART,
} WCC_EVENT;

typedef enum {
    IPV6_RA_UNKNOWN = 0,            /** if CPE failed to receive RA for RS request */
    IPV6_RA_VALID_SLAAC,            /** if Managed Address flag(M) and Other Configuration(O) flag is Off  or Autonomous Configuration is set */
    IPV6_RA_VALID_ADDRESS_ON_DHCP,  /** if Managed Address flag(M) is On */
    IPV6_RA_VALID_DNS_ON_DHCP,      /** if Other Configuration(O) flag is On */
} IPV6_RA_STATUS;

typedef struct _DATAMODEL_PPP
{
    BOOL                          Enable;
    CHAR                          Interface[BUFLEN_64];
    DML_WAN_IFACE_IPCP_STATUS     IPCPStatus;
    DML_WAN_IFACE_IPV6CP_STATUS   IPV6CPStatus;
    BOOL                          IPCPStatusChanged;
    BOOL                          IPV6CPStatusChanged;
    DML_WAN_IFACE_PPP_LINK_STATUS LinkStatus;
} DATAMODEL_PPP;

typedef struct _WANMGR_IPV4_DATA
{
    char ifname[BUFLEN_64];
    char ip[BUFLEN_32];                /** New IP address, if addressAssigned==TRUE */
    char mask[BUFLEN_32];              /** New netmask, if addressAssigned==TRUE */
    char gateway[BUFLEN_32];           /** New gateway, if addressAssigned==TRUE */
    char dnsServer[BUFLEN_64];         /** New dns Server, if addressAssigned==TRUE */
    char dnsServer1[BUFLEN_64];        /** New dns Server, if addressAssigned==TRUE */
    uint32_t mtuSize;                  /** New MTU size, if mtuAssigned==TRUE */
    uint32_t leaseReceivedTime;        /** Lease received time*/
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
    int32_t timeOffset;                /** New time offset, if addressAssigned==TRUE */
    bool isTimeOffsetAssigned;         /** Is the time offset assigned ? */
    char timeZone[BUFLEN_64];          /** New time zone, if addressAssigned==TRUE */
    uint32_t upstreamCurrRate;         /** Upstream rate */
    uint32_t downstreamCurrRate;       /** Downstream rate */
    char dhcpServerId[BUFLEN_64];      /** Dhcp server id */
    char dhcpState[BUFLEN_64];         /** Dhcp state. */
    uint32_t leaseTime;                /** Lease time */
#endif
} WANMGR_IPV4_DATA;


typedef struct _WANMGR_IPV6_DATA
{
   char ifname[BUFLEN_32];
   char address[BUFLEN_48];      /**< New IPv6 address, if addrAssigned==TRUE */
   char pdIfAddress[BUFLEN_48];      /**< New IPv6 address of PD interface */
   char nameserver[BUFLEN_128];  /**< New nameserver, if addressAssigned==TRUE */
   char nameserver1[BUFLEN_128];  /**< New nameserver, if addressAssigned==TRUE */
   char domainName[BUFLEN_64];  /**< New domain Name, if addressAssigned==TRUE */
   char sitePrefix[BUFLEN_48];   /**< New site prefix, if prefixAssigned==TRUE */
   uint32_t prefixPltime;
   uint32_t prefixVltime;
   char sitePrefixOld[BUFLEN_48]; /**< add support for RFC7084 requirement L-13 */
    uint32_t ipv6_TimeOffset;
   #if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
   /* Params to store the IPv6 IPC message */
   bool addrAssigned;
   uint32_t addrCmd;
   bool prefixAssigned;  /**< Have we been assigned a site prefix ? */
   uint32_t prefixCmd;
   bool domainNameAssigned;     /**< Have we been assigned dns server addresses ? */
   #endif
} WANMGR_IPV6_DATA;

typedef struct _WANMGR_IPV6_RA_DATA 
{
    IPV6_RA_STATUS       enIPv6RAStatus;
    bool                 DHCPStartStatusFlag;    // Confirms whether DHCP client needs to start or not based on RA flags
    char                 acDefaultGw[INET6_ADDRSTRLEN];                          // Default Router
    unsigned int         uiRouterLifetime;       //Router LifeTime
} WANMGR_IPV6_RA_DATA;

typedef struct _DML_WANIFACE_IP
{
    CHAR                        Interface[BUFLEN_64];
    CHAR                        DHCPv4Iface[BUFLEN_128];
    CHAR                        DHCPv6Iface[BUFLEN_128];
    DML_WAN_IFACE_IPV4_STATUS   Ipv4Status;
    DML_WAN_IFACE_IPV6_STATUS   Ipv6Status;
    CONNECTIVITY_CHECK_TYPE     ConnectivityCheckType;
    CONNECTIVITY_STATUS         Ipv4ConnectivityStatus;
    CONNECTIVITY_STATUS         Ipv6ConnectivityStatus;
    DML_WAN_IP_SOURCE           IPv4Source;
    DML_WAN_IP_SOURCE           IPv6Source;
    BOOL                        ConnectivityCheckRunning;
    BOOL                        RestartConnectivityCheck;
    BOOL                        WCC_TypeChanged; // Flag to notify change in ConnectivityCheckType
    BOOL                        RefreshDHCP;
    DML_WAN_IP_MODE             Mode;
    DML_WAN_IP_PREFERRED_MODE   PreferredMode;
    DML_WAN_IP_PREFERRED_MODE   SelectedMode;
    struct timespec             SelectedModeTimerStart;
    TIMER_STATUS                SelectedModeTimerStatus;
    BOOL                        ModeForceEnable;
    BOOL                        Ipv4Changed;
    BOOL                        Ipv6Changed;
    BOOL                        Ipv4Renewed;
    BOOL                        Ipv6Renewed;
    WANMGR_IPV4_DATA            Ipv4Data;
    WANMGR_IPV6_DATA            Ipv6Data;
    WANMGR_IPV6_RA_DATA         Ipv6RA;
    ipc_dhcpv4_data_t*          pIpcIpv4Data;
    ipc_dhcpv6_data_t*          pIpcIpv6Data;
    int                         Dhcp4cPid;
    WANMGR_DHCPC_STATUS         Dhcp4cStatus; //Status of DHCPv4 client
    int                         Dhcp6cPid;
    WANMGR_DHCPC_STATUS         Dhcp6cStatus; //Status of DHCPv6 client
} DML_WANIFACE_IP;

#ifdef FEATURE_MAPT
/* Data body for MAPT information to set sysevents*/
typedef struct
{
    char maptConfigFlag[BUFLEN_8]; //Flag to indicates to set/reset firewall rules. [SET/RESET]
    UINT ratio;
    char baseIfName[BUFLEN_64];
    char ipAddressString[BUFLEN_32];
    char ruleIpAddressString[BUFLEN_32];
    char ipv6AddressString[BUFLEN_128];
    char brIpv6PrefixString[BUFLEN_128];
    char ruleIpv6AddressString[BUFLEN_128];
    UINT psidOffset;
    UINT psidValue;
    UINT psidLen;
    UINT eaLen;
    UINT v4Len;
    BOOL mapeAssigned;     /**< Have we been assigned mape config ? */
    BOOL maptAssigned;     /**< Have we been assigned mapt config ? */
    BOOL isFMR;
}MaptData_t;

typedef struct _WANMGR_MAPT_CONFIG_DATA_
{
    int psidValue;
    char ipAddressString[BUFLEN_32];
    char ipLANAddressString[BUFLEN_32];
    int psidLen;
}WANMGR_MAPT_CONFIG_DATA;

#endif

typedef struct _DML_WANIFACE_MAP
{
    DML_WAN_IFACE_MAPT_STATUS   MaptStatus;
    DML_WAN_IFACE_MAPE_STATUS   MapeStatus;
    CHAR                        Path[BUFLEN_64];
    BOOL                        MaptChanged;
    ipc_map_data_t              dhcp6cMAPparameters;
#ifdef FEATURE_MAPT
    WANMGR_MAPT_CONFIG_DATA     MaptConfig;
#endif
} DML_WANIFACE_MAP;

typedef struct _DML_WANIFACE_DSLITE
{
    CHAR                        Path[BUFLEN_64];
    DML_WAN_IFACE_DSLITE_STATUS Status;
    BOOL                        Changed;
} DML_WANIFACE_DSLITE;


typedef struct _DML_WANIFACE_SUBSCRIBE
{
    UINT BaseInterfaceStatusSub;
    UINT WanStatusSub;
    UINT WanLinkStatusSub;
    UINT WanEnableSub;
} DML_WANIFACE_SUBSCRIBE;

typedef enum
{
    WAN_STATE_EXIT = 0,
    WAN_STATE_PHY_CONFIGURING,
    WAN_STATE_PHY_DOWN,
    WAN_STATE_VLAN_CONFIGURING,
    WAN_STATE_PPP_CONFIGURING,
    WAN_STATE_VALIDATING_WAN,
    WAN_STATE_OBTAINING_IP_ADDRESSES,
    WAN_STATE_IPV4_LEASED,
    WAN_STATE_IPV6_LEASED,
    WAN_STATE_DUAL_STACK_ACTIVE,
    WAN_STATE_MAP_ACTIVE,
    WAN_STATE_REFRESHING_WAN,
    WAN_STATE_DECONFIGURING_WAN,
    WAN_STATE_STANDBY
} eWanState_t;

typedef struct _WANMGR_IFACE_GROUP_DATA_
{
    pthread_t          ThreadId;
    UINT               State;
    UINT               groupIdx;
    UINT               InterfaceAvailable;
    UINT               SelectedInterface;
    UINT               SelectionTimeOut;
    UINT               ActivationCount;
    BOOLEAN            PersistSelectedIface;
    DML_WAN_POLICY     Policy;
    BOOLEAN            ConfigChanged;
    BOOLEAN            ResetSelectedInterface;
    BOOLEAN            InitialScanComplete;
}WANMGR_IFACE_GROUP;

typedef struct _WANMGR_IFACE_GROUP_
{
    UINT                       ulTotalNumbWanIfaceGroup;
    WANMGR_IFACE_GROUP*        Group;
}WanMgr_IfaceGroup_t;

typedef struct _DML_VIRTIF_MARKING
{
    struct _DML_VIRTIF_MARKING* next;
    ULONG                       VirtMarkingInstanceNumber;
    UINT                        VirIfIdx;
    UINT                        baseIfIdx;
    UINT                        Entry;
}DML_VIRTIF_MARKING;

typedef struct _DML_VLAN_IFACE_TABLE
{
    struct _DML_VLAN_IFACE_TABLE* next;
    ULONG                       Index;
    UINT                        VirIfIdx;
    UINT                        baseIfIdx;
    CHAR                        Interface[BUFLEN_128];
}DML_VLAN_IFACE_TABLE;

typedef enum _VLAN_DISCOVERY_MODE
{
    VLAN_DISCOVERY_MODE_ALWAYS = 0, //Do VLAN discovery every reboot
    VLAN_DISCOVERY_MODE_ONCE,  // Do VLAN discovery only if we did not find any VLANs previously
} VLAN_DISCOVERY_MODE;

typedef struct _DML_VIRTUALIF_VLAN
{
    BOOL                        Enable;
    CHAR                        VLANInUse[BUFLEN_128]; //Valid VLAN found from the discovery (will be persisted)
    CHAR                        CurrentVlan[BUFLEN_128]; //Temp variable for currently used/tried VLAN in the VISM. TODO : could be moved to VISM internal temp variable
    UINT                        ActiveIndex;
    UINT                        Timeout;
    UINT                        NoOfInterfaceEntries;
    VLAN_DISCOVERY_MODE         DiscoveryMode;
    DML_VLAN_IFACE_TABLE*       InterfaceList;
    UINT                        NoOfMarkingEntries;
    DML_VIRTIF_MARKING*         VirtMarking;
    DML_WAN_IFACE_LINKSTATUS    Status;
    BOOL                        Expired;
    BOOL                        Reset;
    struct timespec             TimerStart;
} DML_VIRTUALIF_VLAN;

typedef struct _DML_VIRTUAL_IFACE
{
    struct _DML_VIRTUAL_IFACE*  next;
    UINT                        VirIfIdx;
    UINT                        baseIfIdx;
    CHAR                        Name[BUFLEN_64];
    CHAR                        Alias[BUFLEN_64];
    BOOL                        Enable; 
    BOOL                        EnableMAPT;
    BOOL                        EnableDSLite;
    DML_WAN_IFACE_STATUS        Status;
    DML_WAN_IFACE_STATUS        RemoteStatus;
    DML_VIRTUALIF_VLAN          VLAN;
    BOOL                        Reset;
    DML_WAN_IFACE_OPER_STATUS   OperationalStatus;
    DML_WANIFACE_IP             IP;
    DATAMODEL_PPP               PPP;
    DML_WANIFACE_MAP            MAP;
    DML_WANIFACE_DSLITE         DSLite;
    eWanState_t                 eCurrentState; 
    BOOLEAN                     Interface_SM_Running;  // flag to check whether Interface State machine is running
} DML_VIRTUAL_IFACE;

typedef struct _DML_IFACE_SELECTION
{
    BOOL                        Enable; 
    INT                         Priority;
    UINT                        Timeout;
    WANMGR_IFACE_SELECTION      Status;
    BOOL                        ActiveLink;
    UINT                        Group;
    BOOL                        RequiresReboot;
    BOOL                        RebootTriggerStatus;
} DML_IFACE_SELECTION;

typedef struct _DML_WAN_INTERFACE
{
    UINT                        uiIfaceIdx;
    UINT                        uiInstanceNumber;
    CHAR                        Name[BUFLEN_64];
    CHAR                        DisplayName[BUFLEN_64];
    CHAR                        AliasName[BUFLEN_64];
    BOOL                        MonitorOperStatus;
    BOOL                        WanConfigEnabled;
    BOOL                        VirtIfChanged;
    BOOL                        CustomConfigEnable;
    WANMGR_IFACE_CONNECTION_TYPE IfaceConnectionType;
    CHAR                        CustomConfigPath[BUFLEN_128];
    DML_WAN_IFACE_SCAN_STATUS   InterfaceScanStatus;
    CHAR                        RemoteCPEMac[BUFLEN_128];
    CHAR                        BaseInterface[BUFLEN_128];
    DML_WAN_IFACE_TYPE          Type; //TODO: Comcast use
    DML_WAN_IFACE_PHY_STATUS    BaseInterfaceStatus;
    DML_IFACE_SELECTION         Selection;
    IFACE_TYPE                  IfaceType;
    DML_WANIFACE_SUBSCRIBE      Sub; // TODO: NEW_DESIGN : remove
    DATAMODEL_MARKING           Marking;
    UINT                        NoOfVirtIfs;
    DML_VIRTUAL_IFACE*          VirtIfList;
    BOOL                        bSendSelectionTimerExpired;
} DML_WAN_IFACE;


/*** RDK WAN Manager ***/
typedef struct _DML_WANMGR_CONFIG_
{
    BOOLEAN Enable;
    DEVICE_NETWORKING_MODE DeviceNwMode;
    BOOLEAN DeviceNwModeChanged;    // Set if DeviceNwMode is changed and config needs to be applied
    BOOLEAN ResetFailOverScan;
    BOOLEAN DisableAutoRouting;
    BOOLEAN AllowRemoteInterfaces;
    BOOLEAN BootToWanUp;            // Set if Wan was UP after boot
    CHAR    InterfaceAvailableStatus[BUFLEN_64];
    CHAR    InterfaceActiveStatus[BUFLEN_64];
    CHAR    InterfaceIpStatus[BUFLEN_64];
    CHAR    CurrentActiveInterface[BUFLEN_64];
    CHAR    CurrentStatus[BUFLEN_16];
    CHAR    CurrentStandbyInterface[BUFLEN_64];
    UINT    RestorationDelay;
    CHAR    CurrentActiveDNS[BUFLEN_256];
    BOOLEAN BackupWanDnsSupport;    
    BOOLEAN IPv6EUI64FormatSupport;
    BOOLEAN ConfigureWANIPv6OnLANBridgeSupport;
    BOOLEAN UseWANMACForManagementServices;
    BOOLEAN InterfaceVLANMarkingSupport;            
} DML_WANMGR_CONFIG;

//WAN CONFIG
typedef struct _WANMGR_CONFIG_DATA_
{
    DML_WANMGR_CONFIG       data;
} WanMgr_Config_Data_t;


//WAN IFACE
typedef struct _WANMGR_IFACE_DATA_
{
    DML_WAN_IFACE           data;
}WanMgr_Iface_Data_t;

typedef struct _WANMGR_IFACECTRL_DATA_
{
    UINT                        ulTotalNumbWanInterfaces;
    WanMgr_Iface_Data_t*        pIface;
    UINT                        update;
}WanMgr_IfaceCtrl_Data_t;

typedef enum _DML_MAP_STATUS
{
    WAN_MAP_STATUS_DISABLED = 1,
    WAN_MAP_STATUS_ENABLED
} DML_MAP_STATUS;

typedef enum _DML_MAP_TRANSPORT
{
    WAN_MAP_TRANSPORT_ENCAPSULATED = 1,
    WAN_MAP_TRANSPORT_TRANSLATION
} DML_MAP_TRANSPORT;

typedef enum _DML_MAP_DOMAININTERFACE_STATUS
{
    WAN_MAPDOMAININTERFACE_STATUS_Up = 1,
    WAN_MAPDOMAININTERFACE_STATUS_Down
} DML_MAP_DOMAININTERFACE_STATUS;

 /* Interface Stat structure */
typedef struct _DML_MAP_DOMAININTERFACESTAT
{
    ULONG BytesSent;
    ULONG BytesReceived;
    ULONG PacketsSent;
    ULONG PacketsReceived;
    ULONG ErrorsSent;
    ULONG ErrorsReceived;
    ULONG UnicastPacketsSent;
    ULONG UnicastPacketsReceived;
    ULONG DiscardPacketsSent;
    ULONG DiscardPacketsReceived;
    ULONG MulticastPacketsSent;
    ULONG MulticastPacketsReceived;
    ULONG BroadcastPacketsSent;
    ULONG BroadcastPacketsReceived;
    ULONG UnknownProtoPacketsReceived;
}DML_MAP_DOMAININTERFACESTAT;

 /* DomainInterface structure */
typedef struct _DML_MAP_DOMAININTERFACE
{
    BOOL Enable;
    DML_MAP_DOMAININTERFACE_STATUS Status;
    CHAR Alias[BUFLEN_32];
    CHAR Name[BUFLEN_32];
    UINT LastChange;
    CHAR LowerLayers[BUFLEN_32];
    DML_MAP_DOMAININTERFACESTAT data;
}DML_MAP_DOMAININTERFACE;

 /* DomainRule structure */
typedef struct _DML_MAP_DOMAINRULE
{
    BOOL Enable;
    DML_MAP_STATUS Status;
    CHAR Alias[BUFLEN_32];
    CHAR Origin[BUFLEN_32];
    CHAR IPv6Prefix[BUFLEN_32];
    CHAR IPv4Prefix[BUFLEN_32];
    UINT EABitsLength;
    BOOL IsFMR;
    UINT PSIDOffset;
    UINT PSIDLength;
    UINT PSID;
    BOOL IncludeSystemPorts;
    UINT uiIfaceIdx;
    UINT uiInstanceNumber;
}DML_MAP_DOMAINRULE;
 /* Map Domain structure */
typedef struct _DML_MAP_DOMAIN
{
    BOOL Enable;
    DML_MAP_STATUS Status;
    CHAR Alias[BUFLEN_32];
    DML_MAP_TRANSPORT TransportMode;
    CHAR WANInterface[BUFLEN_32];
    CHAR IPv6Prefix[BUFLEN_32];
    CHAR BRIPv6Prefix[BUFLEN_32];
    UINT DSCPMarkPolicy;
    UINT uiIfaceIdx;
    UINT uiInstanceNumber;
}DML_MAP_DOMAIN;

typedef struct _WANMGR_MAPDOMAINRULE_DATA_
{
   UINT    ulTotalNumWanMapDomainRuleEntries;
   DML_MAP_DOMAINRULE data;
}WanMgr_Map_DomainRule_t;

typedef struct _WANMGR_MAP_DOMAIN_
{
    DML_MAP_DOMAIN      Domaindata;
    WanMgr_Map_DomainRule_t* pRule;
    DML_MAP_DOMAININTERFACE data;
}WanMgr_Map_Domain_t;

typedef struct _WANMGR_MAPDOMAINCTRL_DATA_
{
    UINT                        ulTotalNumWanMapDomainEntries;
    BOOL                        Enable;
    WanMgr_Map_Domain_t*        pDomain;
    pthread_mutex_t             mDataMutex;
}WanMgr_MapDomainCtrl_Data_t;

typedef struct WANMGR_MAP_ST
{
   WanMgr_MapDomainCtrl_Data_t MapDomainCtrl;
} WANMGR_MAP_ST;

typedef struct _WANMGR_DATA_ST_
{
    //Mutex
    pthread_mutex_t             gDataMutex;

    //WAN CONFIG
    WanMgr_Config_Data_t        Config;

    //WAN IFACE
    WanMgr_IfaceCtrl_Data_t     IfaceCtrl;

    //Iface Group
    WanMgr_IfaceGroup_t         IfaceGroup;
} WANMGR_DATA_ST;
#endif //_WANMGR_DML_H_
