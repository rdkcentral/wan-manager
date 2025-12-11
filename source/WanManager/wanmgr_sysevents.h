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


#ifndef  _WANMGR_SYSEVENTS_H_
#define  _WANMGR_SYSEVENTS_H_

#include "ansc_platform.h"
#include "wanmgr_dml.h"

/**********************************************************************
                STRUCTURE AND CONSTANT DEFINITIONS
**********************************************************************/
// /* sysevent/syscfg configurations used/managed by wanmanager.

//Led sysevent
#define SYSEVENT_LED_STATE "led_event"
#define SYSEVENT_WAN_LED_STATE "rdkb_wan_status"

#define WAN_LINK_DOWN_STATE            "rdkb_wan_link_down"
#define WAN_LINK_UP_STATE              "rdkb_wan_link_up"
#define DSL_TRAINING                  "rdkb_dsl_training"

/* The following defines are used for sysevent retrieval. */
#define SYSEVENT_IPV4_CONNECTION_STATE "ipv4_connection_state"
#define SYSEVENT_CURRENT_IPV4_LINK_STATE  "current_ipv4_link_state"
#define SYSEVENT_IPV6_CONNECTION_STATE "ipv6_connection_state"
#define SYSEVENT_CURRENT_WAN_STATE "current_wan_state"
#define SYSEVENT_WAN_START_TIME "wan_start_time"
#define SYSEVENT_IPV4_IP_ADDRESS "ipv4_%s_ipaddr"
#define SYSEVENT_IPV4_WAN_ADDRESS "ipv4_wan_ipaddr"
#define SYSEVENT_IPV4_SUBNET "ipv4_%s_subnet"
#define SYSEVENT_IPV4_WAN_SUBNET "ipv4_wan_subnet"
#define SYSEVENT_IPV4_NO_OF_DNS_SUPPORTED "2"
#define SYSEVENT_IPV4_DNS_NUMBER "ipv4_%s_dns_number"
#define SYSEVENT_IPV4_WANIFNAME_DNS_PRIMARY "ipv4_%s_dns_0"
#define SYSEVENT_IPV4_WANIFNAME_DNS_SECONDARY "ipv4_%s_dns_1"
#define SYSEVENT_FIELD_IPV4_DNS_PRIMARY       "ipv4_dns_0"
#define SYSEVENT_FIELD_IPV4_DNS_SECONDARY     "ipv4_dns_1"
#define SYSEVENT_IPV4_GW_NUMBER "ipv4_%s_gw_number"
#define SYSEVENT_IPV4_GW_ADDRESS "ipv4_%s_gw_0"
#define SYSEVENT_VENDOR_CLASS "vendor_class"
#define SYSEVENT_IPV4_DEFAULT_ROUTER "default_router"
#define SYSEVENT_IPV4_TIME_OFFSET "ipv4-timeoffset"
#define SYSEVENT_IPV4_TIME_ZONE "ipv4_timezone"
#define SYSEVENT_DHCPV4_TIME_OFFSET "dhcpv4_time_offset"
#define SYSEVENT_IPV4_US_CURRENT_RATE "ipv4_%s_us_current_rate_0"
#define SYSEVENT_IPV4_DS_CURRENT_RATE "ipv4_%s_ds_current_rate_0"
#define SYSEVENT_FIELD_SERVICE_ROUTED_STATUS "routed-status"
#define SYSEVENT_IPV4_MTU_SIZE "ipv4_%s_mtu"
#define SYSEVENT_IPV6_STATUS "ipv6-status"
#define SYSEVENT_WAN6_IP_ADDRESS "wan6_ipaddr"
#define SYSEVENT_IPV6_NS "ipv6_nameserver"
#define SYSEVENT_IPV6_TIME_OFFSET "ipv6-timeoffset"
#define SYSEVENT_IPV6_WAN_ADDRESS "tr_erouter0_dhcpv6_client_v6addr"
#define SYSEVENT_LAN_IPV6_ADDRESS "lan_ipaddr_v6"
#define WAN_STATUS_UP "up"
#define WAN_STATUS_DOWN "down"

#define MESH_IFNAME        "br-home"
#if defined (RDKB_EXTENDER_ENABLED)
#define SYSEVENT_MESH_WAN_LINK_STATUS "mesh_wan_linkstatus"
#endif /* RDKB_EXTENDER_ENABLED */

/*dhcp server restart*/
#define SYSEVENT_DHCP_SERVER_RESTART "dhcp_server-restart"

#define SYSCFG_FIELD_IPV6_ADDRESS                   "wan_ipv6addr"
#define SYSCFG_FIELD_IPV6_PREFIX                    "ipv6_prefix"
#define SYSCFG_FIELD_IPV6_PREFIX_ADDRESS            "ipv6_prefix_address"
#define SYSCFG_FIELD_IPV6_GW_ADDRESS                "wan_ipv6_default_gateway"
#define SYSCFG_FIELD_PREVIOUS_IPV6_PREFIX           "previousipv6_prefix"
#define SYSEVENT_FIELD_IPV6_PREFIX                  "ipv6_prefix"
#define SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIX         "previous_ipv6_prefix"
#define SYSEVENT_FIELD_LAN_IPV6_START               "lan_ipv6-start"
#define SYSEVENT_FIELD_IPV6_DNS_PRIMARY             "ipv6_dns_0"
#define SYSEVENT_FIELD_IPV6_DNS_SECONDARY           "ipv6_dns_1"
#define SYSEVENT_FIELD_IPV6_DOMAIN                  "ipv6_domain"
#define SYSEVENT_FIELD_IPV6_PREFIXVLTIME            "ipv6_prefix_vldtime"
#define SYSEVENT_FIELD_IPV6_PREFIXPLTIME            "ipv6_prefix_prdtime"
#define SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIXVLTIME   "previous_ipv6_prefix_vldtime"
#define SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIXPLTIME   "previous_ipv6_prefix_prdtime"
#define SYSEVENT_RADVD_RESTART                      "radvd_restart"
#define SYSEVENT_GLOBAL_IPV6_PREFIX_SET             "lan_prefix_set"
#define SYSEVENT_ULA_ADDRESS                        "ula_address"
#define SYSEVENT_ULA_ENABLE                         "lan_ula_enable"
#define SYSEVENT_IPV6_ENABLE                        "lan_ipv6_enable"
#define SYSEVENT_SYNC_NTP_STATUS                    "sync_ntp_status"
#define SYSEVENT_FACTORY_RESET_STATUS               "factory_reset-status"
#define SYSEVENT_NTP_TIME_SYNC                      "ntp_time_sync"
#define NTP_TIME_SYNCD                              "1"

#define SYSEVENT_FIELD_TR_BRLAN0_DHCPV6_SERVER_ADDRESS        "tr_brlan0_dhcpv6_server_v6addr"
#define SYSEVENT_FIELD_TR_EROUTER_DHCPV6_CLIENT_PREFIX        "tr_erouter0_dhcpv6_client_v6pref"

/*WAN specific sysevent fieldnames*/
#define SYSEVENT_CURRENT_WAN_IFNAME "current_wan_ifname"
#define SYSEVENT_WAN_STATUS         "wan-status"
#define SYSEVENT_LAN_STATUS         "lan-status"
#define SYSEVENT_CURRENT_WAN_IPADDR "current_wan_ipaddr"
#define SYSEVENT_CURRENT_WAN_SUBNET "current_wan_subnet"
#define SYSEVENT_WAN_SERVICE_STATUS "wan_service-status"
#define SYSEVENT_LAN_START          "lan-start"
#define SYSEVENT_DHCP_SERVER_RESYNC "dhcp_server-resync"
#define SYSEVENT_START_MISC         "start-misc"
#define SYSEVENT_L3NET_INSTANCES    "l3net_instances"
#define SYSEVENT_IPV4_UP            "ipv4-up"
#define SYSEVENT_VENDOR_SPEC        "vendor_spec"
#define SYSEVENT_PRIMARY_LAN_L3NET  "primary_lan_l3net"
#define SYSEVENT_IPV6_PREFIX        "ipv6_prefix"
#define SYSEVENT_RADVD_RESTART      "radvd_restart"
#define SYSEVENT_GLOBAL_IPV6_PREFIX_CLEAR   "lan_prefix_clear"
#define SYSEVENT_ETHWAN_INITIALIZED   "ethwan-initialized"
#define SYSEVENT_ETH_WAN_MAC          "eth_wan_mac"
#define SYSEVENT_WAN_START            "wan-start"
#define SYSCFG_NTP_ENABLED            "ntp_enabled"
#define SYSCFG_WAN_INTERFACE_NAME     "wan_physical_ifname"
#define SYSEVENT_WAN_ROUTED_STATUS    "routed-status"
#if defined (RDKB_EXTENDER_ENABLED)
#define SYSCFG_DEVICE_NETWORKING_MODE "Device_Mode"
#endif /* RDKB_EXTENDER_ENABLED */

//firewall restart
#define SYSEVENT_FIREWALL_RESTART "firewall-restart"
#define SYSEVENT_FIREWALL_STATUS "firewall-status"

#define SYSEVENT_IPV4_LEASE_TIME  "ipv4_%s_lease_time"
#define SYSEVENT_IPV4_DHCP_SERVER "ipv4_%s_dhcp_server"
#define SYSEVENT_IPV4_DHCP_STATE  "ipv4_%s_dhcp_state"
#define SYSEVENT_IPV4_START_TIME  "ipv4_%s_start_time"

#define SYSEVENT_WAN_STOP            "wan-stop"
#define SYSEVENT_WAN_RESTART         "wan-restart"
#define SYSEVENT_SSHD_RESTART         "sshd-restart"

#define WAN_STATUS_STARTED      "started"
#define WAN_STATUS_STOPPED      "stopped"
#define FIREWALL_STATUS_STARTED "started"
#define STATUS_UP_STRING        "up"
#define STATUS_DOWN_STRING      "down"
#define SET "set"
#define UNSET "unset"
#define RESET "reset"

#if defined(FEATURE_TAD_HEALTH_CHECK)
#define SYSEVENT_IPV4_GATEWAY      "ipv4_router"
#define SYSEVENT_IPV4_DNS          "ipv4_dns"
#define SYSEVENT_IPV6_DNS          "wan6_ns"
#define SYSEVENT_BACKUP_IPv4_DNS   "backupwan_router_addr"
#define SYSEVENT_BACKUP_IPV6_DNS   "MeshWANInterface_UlaAddr"
#define SYSEVENT_IPV6_ADDRESS      "wan6_ipaddr"
#endif

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
#define SYSCFG_MAPT_FEATURE_ENABLE   "MAPT_Enable"
#define SYSEVENT_MAPT_FEATURE_ENABLE   "MAPT_Enable"
#endif

#ifdef FEATURE_MAPT
/* MAPT specific field names. */
#define SYSEVENT_BASE_INTERFACE_NAME "base_interface_name"
#define SYSEVENT_MAPT_CONFIG_FLAG "mapt_config_flag"
#define SYSEVENT_MAPT_RATIO "mapt_ratio"
#define SYSEVENT_MAPT_IPADDRESS "mapt_ip_address"
#define SYSEVENT_MAPT_PSID_OFFSET "mapt_psid_offset"
#define SYSEVENT_MAPT_PSID_VALUE "mapt_psid_value"
#define SYSEVENT_MAPT_PSID_LENGTH "mapt_psid_length"
#define SYSEVENT_MAPT_IPV6_ADDRESS "mapt_ipv6_address"
#define SYSEVENT_MAP_RULE_IPADDRESS "map_rule_ip_address"
#define SYSEVENT_MAP_RULE_IPV6_ADDRESS "map_rule_ipv6_address"
#define SYSEVENT_MAP_BR_IPV6_PREFIX "map_br_ipv6_prefix"
#define SYSEVENT_MAP_EA_LENGTH "map_ea_length"
#define SYSEVENT_MAP_TRANSPORT_MODE "map_transport_mode"
#define SYSEVENT_MAP_IS_FMR "map_is_fmr"
#define SYSEVENT_MAPT_V4LENGTH "map_v4len"
/* Lan specific syscfg field names. */
#define SYSCFG_LAN_IP_ADDRESS "lan_ipaddr"
#define SYSCFG_LAN_NET_MASK "lan_netmask"
#define IVICTL_COMMAND_ERROR             0xff
#endif // FEATURE_MAPT

#define SYSEVENT_DHCPV4_OPT_43    "dhcpv4_option_43"
#define PSM_DHCPV4_OPT_43         "dmsb.dhcpv4.option.43"

#define  WANMNGR_INTERFACE_DEFAULT_MTU_SIZE          (1500)

/* IPOE_HEALTH_CHECK_LAN_SYNC_SUPPORT - stops and starts IPOE HEALTH CHECK Service based on lan events(SYSEVENT_LAN_STATUS).
 * SKY IPoE Health check depends on the global ipv6 address configured on brlan0 and during the lan stop event brlan0 interface
 * is made down affecting the IPoE service.
 * */
#if defined(FEATURE_IPOE_HEALTH_CHECK) && defined(IPOE_HEALTH_CHECK_LAN_SYNC_SUPPORT)
typedef enum{
    LAN_STATE_RESET = 0,
    LAN_STATE_STOPPED,
    LAN_STATE_STARTED,
}lanState_t;
#endif

//Bridge Mode
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
#define SYSEVENT_BRIDGE_MODE           "bridge_mode"
#define SYSEVENT_BRIDGE_STATUS         "bridge-status"
#define SYSEVENT_MULTINET1_STATUS         "multinet_1-status"

typedef enum{
BRIDGE_MODE_STATUS_UNKNOWN = 0,
BRIDGE_MODE_STATUS_STARTED,
BRIDGE_MODE_STATUS_STOPPED,
}BridgeModeStatus_t;

#endif

/**********************************************************************
                FUNCTION PROTOTYPES
**********************************************************************/
ANSC_STATUS WanMgr_SysEvents_Init(void);
ANSC_STATUS WanMgr_SysEvents_Finalise(void);

/*
 * @brief Utility function used to init all IPv6 values in sysevent
 * @param[in] None
 * @return Returns ANSC_STATUS.
*/
ANSC_STATUS wanmgr_sysevents_ipv6Info_init();

/*
 * @brief Utility function used to init all IPv4 values in sysevent
 * @param[in]
 * @return Returns ANSC_STATUS.
*/
ANSC_STATUS wanmgr_sysevents_ipv4Info_init(const char *wanIfName, DEVICE_NETWORKING_MODE DeviceNwMode);

/*
 * @brief Utility function used to store all dhcpv4_data_t values in sysevent
 * @param[in] dhcpv4_data_t *dhcp4Info
 * @return Returns ANSC_STATUS.
*/
ANSC_STATUS wanmgr_set_Ipv4Sysevent(const WANMGR_IPV4_DATA* dhcp4Info, DEVICE_NETWORKING_MODE DeviceNwMode);
ANSC_STATUS wanmgr_sysevents_ipv4Info_set(const ipc_dhcpv4_data_t* dhcp4Info, const char *wanIfName);

/*
 * @brief Utility function used to set led state.
 * @param[in] const char* LedState - Indicates the led state value
 * @return Returns NONE.
*/
void wanmgr_sysevents_setWanState(const char * LedState);

/*
 * @brief Utility function used to set to reboot via selfheal.
 * @return Returns NONE.
*/
void wanmgr_sysevent_hw_reconfig_reboot(void);

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
/*
 * @brief Utility function used to check mapt_feature enable status.
 * @return Returns TRUE if Enabled, FALSE if Disabled.
*/
int wanmanager_mapt_feature();
#endif
INT WanMgr_GetWanStatus(void);
ANSC_STATUS wanmgr_setwanstart();
ANSC_STATUS wanmgr_setwanstop();
ANSC_STATUS wanmgr_sshd_restart();
ANSC_STATUS wanmgr_services_restart();
ANSC_STATUS wanmgr_setwanrestart();
INT wanmgr_isWanStarted();
INT WanMgr_IsWanStopped(void);
ANSC_STATUS wanmgr_firewall_restart(void);
INT WanMgr_GetWanServiceStatus(void);
INT WanMgr_GetWanRoutedStatus(void);
INT wanmgr_isWanStandby();
//#ifdef FEATURE_MAPT
///*
// * @brief Utility function used to store MAPT specific values in sysevent/
// * @param[in] MaptData_t *maptInfo
// * @return Returns ANSC_STATUS_SUCCESS if data properly update in sysevent.
//
//ANSC_STATUS maptInfo_set(const MaptData_t *maptInfo);
//ANSC_STATUS maptInfo_reset();
//#endif // FEATURE_MAPT

/*
 * @brief Utility function used to toggle ipv6 based on sysevent from netmonitor.
 * @return Returns NONE.
*/
void WanMgr_CheckDefaultRA(DML_VIRTUAL_IFACE * pVirtIf);

/*
 * @brief Utility function used to toggle ipv6 triggered from ISM.
 * This function will not check existing default route.
 * @param : Interface name.
 * @return Returns NONE.
*/
int Force_IPv6_toggle (char* wanInterface);

/*
 * @brief Utility function used to Configure accept_ra from ISM.
 * @param : Virtual Interface and Enable.
 * @return Returns NONE.
 */
void WanMgr_Configure_accept_ra(DML_VIRTUAL_IFACE * pVirtIf, BOOL EnableRa);

#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
/*
 * @brief Utility function used to get current wan interface name.
 * @return Returns NONE.
*/
void wanmgr_get_wan_interface(char *wanInterface);
#endif

void  wanmgr_setWanLedState(eWanState_t state);

void  wanmgr_restart_zebra (void);

#endif //_WANMGR_SYSEVENTS_H_
