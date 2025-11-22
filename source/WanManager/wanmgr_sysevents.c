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

#include <sysevent/sysevent.h>
#include <pthread.h>
#include <syscfg/syscfg.h>

#include "wanmgr_sysevents.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_ipc.h"
#include "secure_wrapper.h"

int sysevent_fd = -1;
token_t sysevent_token;
static int sysevent_msg_fd = -1;
static token_t sysevent_msg_token;

#define PAM_COMPONENT_NAME          "eRT.com.cisco.spvtg.ccsp.pam"
#define PAM_DBUS_PATH               "/com/cisco/spvtg/ccsp/pam"
#define WANMGR_SYSNAME_RCV          "wanmanager"
#define WANMGR_SYSNAME_SND          "wanmgr"
#define SYS_IP_ADDR                 "127.0.0.1"
#define BUFLEN_42                   42
#define SYSEVENT_IPV6_TOGGLE        "ipv6Toggle"
#define SYSEVENT_VALUE_TRUE        "true"
#define SYSEVENT_VALUE_FALSE        "false"
#define SYSEVENT_VALUE_READY        "ready"
#define SYSEVENT_VALUE_STARTED      "started"
#define SYSEVENT_VALUE_STOPPED      "stopped"
#define SYSEVENT_OPEN_MAX_RETRIES   6
#define BRG_INST_SIZE 5
#define BUF_SIZE 256
#define SKY_DHCPV6_OPTIONS "/var/skydhcp6_options.txt"
#define ENTERPRISE_ID 3561 //Broadband Forum.
#define OPTION_16 16
#define WAN_PHY_ADDRESS "/sys/class/net/erouter0/address"
#define LAN_BRIDGE_NAME "brlan0"

/*Below Code should be remove, Once Comcast policy Deprecated.*/
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)) && !defined(WAN_MANAGER_UNIFICATION_ENABLED)
#if defined(FEATURE_TAD_HEALTH_CHECK)
static char primary_v4gateway[128] = {0};
static char primary_v4dns[128] = {0};
static char primary_v6dns[256] = {0};
static char backup_v4dns[128] = {0};
static char backup_v6dns[256] = {0};
static char primary_v6ip_address[128] = {0};

extern int WanMgr_TriggerBackupDnsConnectivityRestart(void);
extern int WanMgr_TriggerPrimaryDnsConnectivityRestart(void);
#endif
#endif

static int isDefaultGatewayAdded = 0; //global varibale for default route status.
static int lan_wan_started = 0;
static int ipv4_connection_up = 0;
static int ipv6_connection_up = 0;
static void check_lan_wan_ready();
static int set_default_conf_entry();
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
int mapt_feature_enable_changed = FALSE;
#endif

#if defined(FEATURE_IPOE_HEALTH_CHECK) && defined(IPOE_HEALTH_CHECK_LAN_SYNC_SUPPORT)
lanState_t lanState = LAN_STATE_RESET;
#endif

#if defined(_DT_WAN_Manager_Enable_)
bool needDibblerRestart = TRUE;
#endif

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
static int BridgeModePrev = 0;
static BridgeModeStatus_t BridgeModeStatus = BRIDGE_MODE_STATUS_UNKNOWN;
#endif

static ANSC_STATUS WanMgr_SyseventInit()
{
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;
    bool send_fd_status = FALSE;
    bool recv_fd_status = FALSE;
    int try = 0;

    /* Open sysevent descriptor to send messages */
    while(try < SYSEVENT_OPEN_MAX_RETRIES)
    {
       sysevent_fd =  sysevent_open(SYS_IP_ADDR, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, WANMGR_SYSNAME_SND, &sysevent_token);
       if(sysevent_fd >= 0)
       {
          send_fd_status = TRUE;
          break;
       }
       try++;
       usleep(50000);
    }

    try = 0;
    /* Open sysevent descriptor to receive messages */
    while(try < SYSEVENT_OPEN_MAX_RETRIES)
    {
        sysevent_msg_fd =  sysevent_open(SYS_IP_ADDR, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, WANMGR_SYSNAME_RCV, &sysevent_msg_token);
        if(sysevent_msg_fd >= 0)
        {
            recv_fd_status = TRUE;
            break;
        }
        try++;
        usleep(50000);
    }

    if (send_fd_status == FALSE || recv_fd_status == FALSE)
    {
        ret = ANSC_STATUS_FAILURE;
    }

    return ret;
}

static void WanMgr_SyseventClose()
{
    if (0 <= sysevent_fd)
    {
        sysevent_close(sysevent_fd, sysevent_token);
    }

    if (0 <= sysevent_msg_fd)
    {
        sysevent_close(sysevent_msg_fd, sysevent_msg_token);
    }
}

ANSC_STATUS wanmgr_sysevents_ipv6Info_init()
{
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_FIELD_IPV6_DOMAIN, "", 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_CONNECTION_STATE, WAN_STATUS_DOWN, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_STATUS, "down", 0);
    syscfg_set_commit(NULL, SYSCFG_FIELD_IPV6_PREFIX_ADDRESS, "");
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wanmgr_sysevents_ipv4Info_set(const ipc_dhcpv4_data_t* dhcp4Info, const char *wanIfName)
{
    char name[BUFLEN_64] = {0};
    char value[BUFLEN_64] = {0};

    snprintf(name, sizeof(name), SYSEVENT_IPV4_DS_CURRENT_RATE, wanIfName);
    snprintf(value, sizeof(value), "%d", dhcp4Info->downstreamCurrRate);
    sysevent_set(sysevent_fd, sysevent_token,name, value, 0);

    snprintf(name, sizeof(name), SYSEVENT_IPV4_US_CURRENT_RATE, wanIfName);
    snprintf(value, sizeof(value), "%d", dhcp4Info->upstreamCurrRate);
    sysevent_set(sysevent_fd, sysevent_token,name, value, 0);

    /* Generic sysevent will be set when IPv4 address configured by Interface SM */
    if (dhcp4Info->isTimeOffsetAssigned)
    {
        snprintf(value, sizeof(value), "@%d", dhcp4Info->timeOffset);
        sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_IPV4_TIME_OFFSET, value, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCPV4_TIME_OFFSET, SET, 0);
    }

    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_IPV4_TIME_ZONE, dhcp4Info->timeZone, 0);

    snprintf(name,sizeof(name),SYSEVENT_IPV4_DHCP_SERVER,dhcp4Info->dhcpcInterface);
    sysevent_set(sysevent_fd, sysevent_token,name, dhcp4Info->dhcpServerId,0);

    snprintf(name,sizeof(name),SYSEVENT_IPV4_DHCP_STATE ,dhcp4Info->dhcpcInterface);
    sysevent_set(sysevent_fd, sysevent_token,name, dhcp4Info->dhcpState,0);

    snprintf(name,sizeof(name), SYSEVENT_IPV4_LEASE_TIME, dhcp4Info->dhcpcInterface);
    snprintf(value, sizeof(value), "%u",dhcp4Info->leaseTime);
    sysevent_set(sysevent_fd, sysevent_token,name, value, 0);

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS wanmgr_set_Ipv4Sysevent(const WANMGR_IPV4_DATA* dhcp4Info, DEVICE_NETWORKING_MODE DeviceNwMode)
{
    char name[BUFLEN_64] = {0};
    char value[BUFLEN_64] = {0};
    char ipv6_status[BUFLEN_16] = {0};
    char ifaceMacAddress[BUFLEN_128] = {0};

    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, name, sizeof(name));
    if (DeviceNwMode == GATEWAY_MODE)
    {
        if (((strlen(name) == 0) || (strcmp(name, dhcp4Info->ifname) != 0)) && (strlen(dhcp4Info->ifname) > 0))
        {
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, dhcp4Info->ifname, 0);
        }
        snprintf(name, sizeof(name), SYSEVENT_IPV4_IP_ADDRESS, dhcp4Info->ifname);
    }
    else 
    {
        if ((strlen(name) == 0) || (strcmp(name, MESH_IFNAME) != 0))
        {
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, MESH_IFNAME, 0);
        }
        snprintf(name, sizeof(name), SYSEVENT_IPV4_IP_ADDRESS, MESH_IFNAME);
    }
    sysevent_set(sysevent_fd, sysevent_token,name, dhcp4Info->ip, 0);

#if (!defined (_XB6_PRODUCT_REQ_) && !defined (_CBR2_PRODUCT_REQ_)) || defined (_RDKB_GLOBAL_PRODUCT_REQ_) //parodus uses cmac for xb platforms
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
    WanMgr_Config_Data_t    *pWanConfigData = WanMgr_GetConfigData_locked();
    unsigned char           UseWANMACForManagementServices = FALSE;

    if( NULL != pWanConfigData )
    {
        UseWANMACForManagementServices = pWanConfigData->data.UseWANMACForManagementServices;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

if ( TRUE == UseWANMACForManagementServices )
#endif /* _RDKB_GLOBAL_PRODUCT_REQ_ */
    {
        // set wan mac because parodus depends on it to start.
        if(ANSC_STATUS_SUCCESS == WanManager_get_interface_mac(dhcp4Info->ifname, ifaceMacAddress, sizeof(ifaceMacAddress)))
        {
            CcspTraceInfo(("%s %d - setting sysevent eth_wan_mac = [%s]  \n", __FUNCTION__, __LINE__, ifaceMacAddress));
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_ETH_WAN_MAC, ifaceMacAddress, 0);
        }   
    }
#endif

    //same as SYSEVENT_IPV4_IP_ADDRESS. But this is required in other components
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_IPV4_WAN_ADDRESS, dhcp4Info->ip, 0);

    snprintf(name, sizeof(name), SYSEVENT_IPV4_SUBNET, dhcp4Info->ifname);
    sysevent_set(sysevent_fd, sysevent_token,name, dhcp4Info->mask, 0);

    //same as SYSEVENT_IPV4_SUBNET. But this is required in other components
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_IPV4_WAN_SUBNET, dhcp4Info->mask, 0);

    snprintf(name, sizeof(name), SYSEVENT_IPV4_GW_NUMBER, dhcp4Info->ifname);
    sysevent_set(sysevent_fd, sysevent_token, name, "1", 0);

    snprintf(name, sizeof(name), SYSEVENT_IPV4_GW_ADDRESS, dhcp4Info->ifname);
    sysevent_set(sysevent_fd, sysevent_token,name, dhcp4Info->gateway, 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_IPV4_DEFAULT_ROUTER, dhcp4Info->gateway, 0);

    snprintf(name,sizeof(name), SYSEVENT_IPV4_MTU_SIZE, dhcp4Info->ifname);
    snprintf(value, sizeof(value), "%u",dhcp4Info->mtuSize);
    sysevent_set(sysevent_fd, sysevent_token,name, value, 0);

#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
    snprintf(name, sizeof(name), SYSEVENT_IPV4_DS_CURRENT_RATE, dhcp4Info->ifname);
    snprintf(value, sizeof(value), "%d", dhcp4Info->downstreamCurrRate);
    sysevent_set(sysevent_fd, sysevent_token,name, value, 0);

    snprintf(name, sizeof(name), SYSEVENT_IPV4_US_CURRENT_RATE, dhcp4Info->ifname);
    snprintf(value, sizeof(value), "%d", dhcp4Info->upstreamCurrRate);
    sysevent_set(sysevent_fd, sysevent_token,name, value, 0);

    /* Generic sysevent will be set when IPv4 address configured by Interface SM */
    if (dhcp4Info->isTimeOffsetAssigned)
    {
        snprintf(value, sizeof(value), "@%d", dhcp4Info->timeOffset);
        sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_IPV4_TIME_OFFSET, value, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCPV4_TIME_OFFSET, SET, 0);
    }

    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_IPV4_TIME_ZONE, dhcp4Info->timeZone, 0);

    snprintf(name,sizeof(name),SYSEVENT_IPV4_DHCP_SERVER,dhcp4Info->ifname);
    sysevent_set(sysevent_fd, sysevent_token,name, dhcp4Info->dhcpServerId,0);

    snprintf(name,sizeof(name),SYSEVENT_IPV4_DHCP_STATE ,dhcp4Info->ifname);
    sysevent_set(sysevent_fd, sysevent_token,name, dhcp4Info->dhcpState,0);

    snprintf(name,sizeof(name), SYSEVENT_IPV4_LEASE_TIME, dhcp4Info->ifname);
    snprintf(value, sizeof(value), "%u",dhcp4Info->leaseTime);
    sysevent_set(sysevent_fd, sysevent_token,name, value, 0);

#endif
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wanmgr_sysevents_ipv4Info_init(const char *wanIfName, DEVICE_NETWORKING_MODE DeviceNwMode)
{
    char name[BUFLEN_64] = {0};
    char value[BUFLEN_64] = {0};
    ipc_dhcpv4_data_t ipc_ipv4Data;
    WANMGR_IPV4_DATA ipv4Data;

    memset(&ipv4Data, 0, sizeof(WANMGR_IPV4_DATA));
    memset(&ipc_ipv4Data, 0, sizeof(ipc_dhcpv4_data_t));

    strncpy(ipc_ipv4Data.dhcpcInterface, wanIfName, sizeof(ipc_ipv4Data.dhcpcInterface)-1);
    strncpy(ipv4Data.ifname, wanIfName, sizeof(ipv4Data.ifname)-1);
    strncpy(ipv4Data.ip, "0.0.0.0", sizeof(ipv4Data.ip)-1);
    strncpy(ipv4Data.mask, "0.0.0.0", sizeof(ipv4Data.mask)-1);
    strncpy(ipv4Data.gateway, "0.0.0.0", sizeof(ipv4Data.gateway)-1);
    strncpy(ipv4Data.dnsServer, "0.0.0.0", sizeof(ipv4Data.dnsServer)-1);
    strncpy(ipv4Data.dnsServer1, "0.0.0.0", sizeof(ipv4Data.dnsServer1)-1);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_CURRENT_WAN_IPADDR, "0.0.0.0", 0);
    snprintf(name, sizeof(name), SYSEVENT_IPV4_START_TIME, wanIfName);
    sysevent_set(sysevent_fd, sysevent_token,name, "0", 0);
    ipv4Data.mtuSize = WANMNGR_INTERFACE_DEFAULT_MTU_SIZE;
    
    wanmgr_sysevents_ipv4Info_set(&ipc_ipv4Data, wanIfName);
    return wanmgr_set_Ipv4Sysevent(&ipv4Data, DeviceNwMode);
}

void  wanmgr_setWanLedState(eWanState_t state)
{
    if (sysevent_fd == -1)      return;
    bool ipv4_state = false;
    bool ipv6_state = false;
    bool mapt_state = false;
    bool SetLinkUp  = false;
    bool valid_state = true;
    char buff[128] = {0};
    switch (state)
    {
        case WAN_STATE_DUAL_STACK_ACTIVE:
            ipv4_state = true;
            ipv6_state = true;
            break;
        case WAN_STATE_IPV6_LEASED:
            ipv6_state = true;
            break;
        case WAN_STATE_IPV4_LEASED:
            ipv4_state = true;
            break;
        case WAN_STATE_MAPT_ACTIVE:
            ipv6_state = true;
            mapt_state = true;
            break;
        case WAN_STATE_OBTAINING_IP_ADDRESSES:
            SetLinkUp = true;
        case WAN_STATE_EXIT:
            break;
        default:
            // handle wan states related to IPv4/IPv6/MAPT UP/DOWN
            valid_state = false;
    }

    if (valid_state == false)
        return;

    memset (buff, 0, sizeof(buff));
    snprintf(buff, sizeof(buff) - 1, "ipv4_state:%s,ipv6_state:%s,mapt_state:%s", ipv4_state?"up":"down", ipv6_state?"up":"down", mapt_state?"up":"down");
    CcspTraceInfo(("%s %d: Setting LED event %s state to %s\n", __FUNCTION__, __LINE__, SYSEVENT_WAN_LED_STATE, buff));
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_LED_STATE, buff, 0);
    if(SetLinkUp)
    {
        wanmgr_sysevents_setWanState(WAN_LINK_UP_STATE);
    }
}

void wanmgr_sysevents_setWanState(const char * LedState)
{
    if (sysevent_fd == -1)      return;
    CcspTraceInfo(("Setting WAN LED state to %s\n", LedState));
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_LED_STATE, LedState, 0);
}


#if defined(FEATURE_SUPPORT_MAPT_NAT46)
/*TODO:
 *Should be Removed once MAPT Unified.
 */
static void  WanMgr_MAPTEnable(BOOL Enable)
{
    int uiLoopCount;

    int TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();
    for (uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            for(int virIf_id=0; virIf_id< pWanIfaceData->NoOfVirtIfs; virIf_id++)
            {
                DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, virIf_id);
                p_VirtIf->EnableMAPT = Enable;
                CcspTraceInfo(("%s-%d: MAPTEnable Changed to %d", __FUNCTION__, __LINE__, Enable));
                WanMgr_SetMAPTEnableToPSM(p_VirtIf, Enable);
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
}
#endif

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
int wanmanager_mapt_feature()
{
    int ret = FALSE;
    char mapt_feature_enable[BUFLEN_16] = {0};

    if (syscfg_get(NULL, SYSCFG_MAPT_FEATURE_ENABLE, mapt_feature_enable, sizeof(mapt_feature_enable)) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("Failed to get MAPT_Enable \n"));
    }
    else
    {
        if (strcmp(mapt_feature_enable, "true") == 0)
            ret = TRUE;
        else
            ret = FALSE;
    }

    return ret;
}
#endif

#if defined(FEATURE_MAPT)
ANSC_STATUS maptInfo_set(const MaptData_t *maptInfo)
{
    if (NULL == maptInfo)
    {
        CcspTraceError(("Invalid arguments \n"));
        return ANSC_STATUS_FAILURE;
    }

    char value[32];

    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAPT_CONFIG_FLAG, maptInfo->maptConfigFlag, 0);

    snprintf(value, sizeof(value), "%d", maptInfo->ratio);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAPT_RATIO, value, 0);

    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAPT_IPADDRESS, maptInfo->ipAddressString, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAP_BR_IPV6_PREFIX, maptInfo->brIpv6PrefixString, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAP_RULE_IPADDRESS, maptInfo->ruleIpAddressString, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAPT_IPV6_ADDRESS, maptInfo->ipv6AddressString, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAP_RULE_IPV6_ADDRESS, maptInfo->ruleIpv6AddressString, 0);

    snprintf(value, sizeof(value), "%d", maptInfo->psidOffset);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAPT_PSID_OFFSET, value, 0);

    snprintf(value, sizeof(value), "%d", maptInfo->psidValue);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAPT_PSID_VALUE, value, 0);

    snprintf(value, sizeof(value), "%d", maptInfo->psidLen);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAPT_PSID_LENGTH, value, 0);

    if (maptInfo->maptAssigned)
    {
        snprintf(value, sizeof(value), "%s", "MAPT");
    }
    else if (maptInfo->mapeAssigned)
    {
        snprintf(value, sizeof(value), "%s", "MAPE");
    }
    else
    {
        snprintf(value, sizeof(value), "%s", "NON-MAP");
    }
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAP_TRANSPORT_MODE, value, 0);

    if (maptInfo->isFMR == 1)
    {
        snprintf(value, sizeof(value), "%s", "TRUE");
    }
    else
    {
        snprintf(value, sizeof(value), "%s", "FALSE");
    }
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAP_IS_FMR, value, 0);

    snprintf(value, sizeof(value), "%d", maptInfo->eaLen);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_MAP_EA_LENGTH, value, 0);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS maptInfo_reset()
{
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAPT_CONFIG_FLAG, RESET, 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAPT_RATIO, "", 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAPT_IPADDRESS, "", 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAPT_IPV6_ADDRESS, "", 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAPT_PSID_OFFSET, "", 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAPT_PSID_VALUE, "", 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAPT_PSID_LENGTH, "", 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAP_TRANSPORT_MODE, "NONE", 0);//default value
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAP_IS_FMR, "", 0);
    sysevent_set(sysevent_fd, sysevent_token,SYSEVENT_MAP_EA_LENGTH, "", 0);

    return ANSC_STATUS_SUCCESS;
}
#endif // FEATURE_MAPT

static int set_default_conf_entry()
{
    char result[BUFLEN_128];
    FILE *fp;
#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
    char wanInterface[BUFLEN_64] = {'\0'};
    char cmd[BUFLEN_128];

    wanmgr_get_wan_interface(wanInterface);
    snprintf(cmd, sizeof(cmd), "/sys/class/net/%s/address", wanInterface);
    fp = fopen(cmd,"r");
#else
    fp = fopen(WAN_PHY_ADDRESS,"r");
#endif
    if (! fp) {
        CcspTraceError(("%s %d cannot open file \n", __FUNCTION__, __LINE__));
        return 0;
    }
    memset(result, 0, sizeof(result));
    fgets(result, sizeof(result), fp);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_ETH_WAN_MAC, result, 0);
    fclose(fp);
    // By default unset dhcpv4 time offset. If dhcpv4 time offset is used, it will be set by function "wanmgr_sysevents_ipv4Info_set"
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCPV4_TIME_OFFSET, UNSET, 0);
    syscfg_set_commit(NULL, SYSCFG_NTP_ENABLED, "1"); // Enable NTP in case of ETHWAN

    // set DHCPv4 Vendor specific option 43
    memset(result, 0, sizeof(result));
    if (WanMgr_RdkBus_GetParamValuesFromDB(PSM_DHCPV4_OPT_43, result, sizeof(result)) == CCSP_SUCCESS)
    {
        CcspTraceInfo(("%s %d: found dhcp option 43 from PSM: %s\n", __FUNCTION__, __LINE__, result));
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCPV4_OPT_43, result, 0);
    }

    return 0;
}

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
static void  WanMgr_BridgeModeChanged(int BridgeMode)
{
    int uiLoopCount;
    bool ret = false;

    int TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();
    for (uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++)
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanIfaceData->Selection.Enable == TRUE)
            {
                for(int virIf_id=0; virIf_id< pWanIfaceData->NoOfVirtIfs; virIf_id++)
                {
                    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, virIf_id);
                    if (p_VirtIf->Status == WAN_IFACE_STATUS_UP)
                    {
                        CcspTraceInfo(("%s-%d: BridgeMode(%d) Changed, Active Virtual Interface Reset", __FUNCTION__, __LINE__, BridgeMode));
                        p_VirtIf->Reset = TRUE;
                        ret = true;
                    }
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }
    if (!ret)
    {
        CcspTraceInfo(("%s-%d: BridgeMode(%d) Changed, But No Active Virtual Interface Found", __FUNCTION__, __LINE__, BridgeMode));
    }
}
#endif //WAN_MANAGER_UNIFICATION_ENABLED

static void *WanManagerSyseventHandler(void *args)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));

    //detach thread from caller stack
    pthread_detach(pthread_self());

    async_id_t wanamangr_status_asyncid;
    async_id_t lan_ula_address_event_asyncid;
    async_id_t default_route_change_event_asyncid;
    async_id_t lan_ula_enable_asyncid;
    async_id_t lan_ipv6_enable_asyncid;
    async_id_t wan_status_asyncid;
    async_id_t radvd_restart_asyncid;
    async_id_t ipv6_down_asyncid;
#ifdef NTP_STATUS_SYNC_EVENT
    async_id_t ntp_time_asyncid;
    async_id_t sync_ntp_statusid;
#endif
#if defined (RDKB_EXTENDER_ENABLED)
    async_id_t mesh_wan_link_status_asyncid;
#endif /* RDKB_EXTENDER_ENABLED */

#if defined (FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    async_id_t factory_reset_status_asyncid;
#endif /* FEATURE_MAPT */

#if defined (WAN_MANAGER_UNIFICATION_ENABLED)
    async_id_t bridge_status_asyncid;
    async_id_t multinet1_status_asyncid;
#endif //WAN_MANAGER_UNIFICATION_ENABLED

/*Below Code should be remove, Once Comcast policy Deprecated.*/
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)) && !defined(WAN_MANAGER_UNIFICATION_ENABLED)
#if defined(FEATURE_TAD_HEALTH_CHECK)
    async_id_t primary_v4gateway_asyncid;
    async_id_t primary_v4dns_asyncid;
    async_id_t primary_v6dns_asyncid;
    async_id_t backup_v4dns_asyncid;
    async_id_t backup_v6dns_asyncid;
    async_id_t primary_v6ipaddress_asyncid;
#endif
#endif

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV6_TOGGLE, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV6_TOGGLE, &default_route_change_event_asyncid);
#if defined (_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_ULA_ADDRESS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_ULA_ADDRESS, &lan_ula_address_event_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_ULA_ENABLE, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_ULA_ENABLE, &lan_ula_enable_asyncid);

#endif
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV6_ENABLE, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV6_ENABLE, &lan_ipv6_enable_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_WAN_STATUS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_WAN_STATUS,  &wan_status_asyncid);

#if defined(_DT_WAN_Manager_Enable_)
    async_id_t dibbler_restart_asyncid;
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, "dibbler-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, "dibbler-restart",  &dibbler_restart_asyncid);
#endif

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_RADVD_RESTART, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_RADVD_RESTART, &radvd_restart_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_GLOBAL_IPV6_PREFIX_CLEAR, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_GLOBAL_IPV6_PREFIX_CLEAR, &ipv6_down_asyncid);

#ifdef NTP_STATUS_SYNC_EVENT
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_NTP_TIME_SYNC, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_NTP_TIME_SYNC, &ntp_time_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_SYNC_NTP_STATUS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_SYNC_NTP_STATUS, &sync_ntp_statusid);
#endif
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_MAPT_FEATURE_ENABLE, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_MAPT_FEATURE_ENABLE, &ipv6_down_asyncid);
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_FACTORY_RESET_STATUS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_FACTORY_RESET_STATUS, &factory_reset_status_asyncid);
#endif

#if defined (RDKB_EXTENDER_ENABLED)
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_MESH_WAN_LINK_STATUS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_MESH_WAN_LINK_STATUS, &mesh_wan_link_status_asyncid);
#endif /* RDKB_EXTENDER_ENABLED */

#if defined (WAN_MANAGER_UNIFICATION_ENABLED)
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_BRIDGE_STATUS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_BRIDGE_STATUS, &bridge_status_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_MULTINET1_STATUS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_MULTINET1_STATUS, &multinet1_status_asyncid);
    
#endif /* WAN_MANAGER_UNIFICATION_ENABLED */

/*Below Code should be remove, Once Comcast policy Deprecated.*/
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)) && !defined(WAN_MANAGER_UNIFICATION_ENABLED)
#if defined(FEATURE_TAD_HEALTH_CHECK)
    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV4_GATEWAY, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV4_GATEWAY, &primary_v4gateway_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV4_DNS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV4_DNS, &primary_v4dns_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV6_DNS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV6_DNS, &primary_v6dns_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_BACKUP_IPv4_DNS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_BACKUP_IPv4_DNS, &backup_v4dns_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_BACKUP_IPV6_DNS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_BACKUP_IPV6_DNS, &backup_v6dns_asyncid);

    sysevent_set_options(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV6_ADDRESS, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_msg_fd, sysevent_msg_token, SYSEVENT_IPV6_ADDRESS, &primary_v6ipaddress_asyncid);
#endif
#endif

    for(;;)
    {
        char name[BUFLEN_42] = {0};
        char val[BUFLEN_42] = {0};
        char cmd_str[BUF_SIZE] = {0};
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
	int fd = 0;
        async_id_t getnotification_asyncid;
        int err = 0;
        ANSC_STATUS result = 0;
        char *datamodel_value = NULL;

        err = sysevent_getnotification(sysevent_msg_fd, sysevent_msg_token, name, &namelen,  val, &vallen, &getnotification_asyncid);

        if(err)
        {
            CcspTraceError(("%s %d sysevent_getnotification failed with error: %d \n", __FUNCTION__, __LINE__, err ));
            sleep(2);
        }
        else
        {
            CcspTraceInfo(("%s %d - received notification event %s:%s\n", __FUNCTION__, __LINE__, name, val ));
            if ( strcmp(name, SYSEVENT_ULA_ADDRESS) == 0 )
            {
		#if defined (_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                datamodel_value = (char *) malloc(sizeof(char) * 256);
                if(datamodel_value != NULL)
                {
                    memset(datamodel_value, 0, 256);
                    strncpy(datamodel_value, val, sizeof(val));
                    result = WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, "Device.DHCPv6.Server.Pool.1.X_RDKCENTRAL-COM_DNSServersEnabled", "true", ccsp_boolean, TRUE );
                    if(result == ANSC_STATUS_SUCCESS)
                    {
                        result = WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, "Device.DHCPv6.Server.Pool.1.X_RDKCENTRAL-COM_DNSServers", datamodel_value, ccsp_string, TRUE );
                        if(result != ANSC_STATUS_SUCCESS) {
                            CcspTraceError(("%s %d - SetDataModelParameter() failed for X_RDKCENTRAL-COM_DNSServers parameter \n", __FUNCTION__, __LINE__));
                        }
                    }
                    else {
                        CcspTraceError(("%s %d - SetDataModelParameter() failed for X_RDKCENTRAL-COM_DNSServersEnabled parameter \n", __FUNCTION__, __LINE__));
                    }
                    free(datamodel_value);
                }
                snprintf(cmd_str, sizeof(cmd_str), "ip -6 addr add %s/64 dev %s", val, LAN_BRIDGE_NAME);
                if (WanManager_DoSystemActionWithStatus("wanmanager", cmd_str) != RETURN_OK)
                {
                    CcspTraceError(("%s %d failed set command: %s\n", __FUNCTION__, __LINE__, cmd_str));
                }
		#endif
            }
            else if ( strcmp(name, SYSEVENT_IPV6_TOGGLE) == 0 )
            {
                if(strcmp(val, "FALSE") == 0)
                {
                    isDefaultGatewayAdded = 1;
                    CcspTraceWarning(("%s %d Netmonitor Update : IPv6 default route Added \n", __FUNCTION__, __LINE__ ));
                }
                else
                {
                    isDefaultGatewayAdded = 0;
                    CcspTraceWarning(("%s %d Netmonitor Update : IPv6 default route Deleted \n", __FUNCTION__, __LINE__ ));
                }
            }
            else if ( strcmp(name, SYSEVENT_ULA_ENABLE) == 0 )
            {
		#if defined (_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                datamodel_value = (char *) malloc(sizeof(char) * 256);
                if(datamodel_value != NULL)
                {
                    memset(datamodel_value, 0, 256);
                    strncpy(datamodel_value, val, sizeof(val));
                    result = WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, "Device.DHCPv6.Server.Pool.1.X_RDKCENTRAL-COM_DNSServersEnabled", datamodel_value, ccsp_boolean, TRUE );
                    if(result != ANSC_STATUS_SUCCESS)
                    {
                        CcspTraceError(("%s %d - SetDataModelParameter failed on dns_enable request \n", __FUNCTION__, __LINE__));
                    }
                }
                free(datamodel_value);
		#endif
            }
#ifdef NTP_STATUS_SYNC_EVENT
            else if (strcmp(name,SYSEVENT_SYNC_NTP_STATUS) == 0)
            {
                /* NTP Status sync will be missed in case of quick sync failure and following time sync success from NTPD daemon..,So handling that scenario here */
                /* SKYH4-6572 setting NTP STATUS to 3 (which means *synchronized*)  upon receiving SYSEVENT_SYNC_NTP_STATUS event from NTPD daemon on time sync */
                v_secure_system("syscfg set ntp_status 3");
                v_secure_system("sysevent set ntp_time_sync 1");
            }
            else if (strcmp(name,SYSEVENT_NTP_TIME_SYNC) == 0)
            {
                /*This script to set the ipv4-timeoffset sysevent value with "Europe/CET"
                 * or "Europe/London" time zone based on serial number.
                 * SKYH4-6730 This is required to set Timeoffset for Local time*/
                v_secure_system("/etc/sky/sync_timeoffset.sh");
            }
#endif
            else if ( strcmp(name, SYSEVENT_IPV6_ENABLE) == 0 )
            {
                datamodel_value = (char *) malloc(sizeof(char) * 256);
                if(datamodel_value != NULL)
                {
                    memset(datamodel_value, 0, 256);
                    strncpy(datamodel_value, val, sizeof(val));
                    result = WanMgr_RdkBus_SetParamValues( PAM_COMPONENT_NAME, PAM_DBUS_PATH, "Device.DHCPv6.Server.Pool.1.Enable", datamodel_value, ccsp_boolean, TRUE );
                    if(result != ANSC_STATUS_SUCCESS)
                    {
                        CcspTraceError(("%s %d - SetDataModelParameter failed on ipv6_enable request \n", __FUNCTION__, __LINE__ ));
                    }
                    free(datamodel_value);
#ifdef LAN_MGR_SUPPORT
                    v_secure_system("sysevent set dhcpv6_raserver-restart");
#else
                    v_secure_system("sysevent set zebra-restart");
#endif
                }
            }
            else if ((strcmp(name, SYSEVENT_WAN_STATUS) == 0) && (strcmp(val, SYSEVENT_VALUE_STARTED) == 0))
            {
                if (!lan_wan_started)
                {
                    check_lan_wan_ready();
                }
                fd = creat("/tmp/phylink_wan_state_up",S_IRUSR| S_IWUSR| S_IRGRP| S_IROTH);
		if(fd != -1)
		{
		    close(fd);
		}
#if defined(_DT_WAN_Manager_Enable_)
                                sysevent_set(sysevent_fd, sysevent_token, "sendImmediateRA", "true", 0);
            }
            else if ((strcmp(name, "dibbler-restart") == 0) && (strcmp(val, "true") == 0))
            {
                needDibblerRestart = TRUE;
                v_secure_system("sysevent set dibbler-restart false");

            }
            else if ((strcmp(name, SYSEVENT_WAN_STATUS) == 0) && (strcmp(val, SYSEVENT_VALUE_STOPPED) == 0))
            {
                needDibblerRestart = TRUE;
	        sysevent_set(sysevent_fd, sysevent_token, "sendImmediateRA", "true", 0);
#endif
            }
#if defined (RDKB_EXTENDER_ENABLED)
            else if ((strcmp(name, SYSEVENT_MESH_WAN_LINK_STATUS) == 0))
            {
                CcspTraceInfo(("%s %d: Detected '%s' event value '%s'\n", __FUNCTION__, __LINE__,name,val));

                char buf[BUF_SIZE] = {0};
                memset(buf,0,sizeof(buf));
                if( 0 == syscfg_get(NULL, SYSCFG_DEVICE_NETWORKING_MODE, buf, sizeof(buf)) ) 
                { 
                    //1-Extender Mode 0-Gateway Mode
                    if (strcmp(buf,"1") == 0)
                    {
                        CcspTraceInfo(("%s %d: DeviceNetworkMode is EXTENDER_MODE\n", __FUNCTION__, __LINE__));
                        
                        //When Device is in Extender Mode after mesh link status up then we need to configure wan if name
                        if(strcmp(val, STATUS_UP_STRING) == 0)
                        {
                            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, MESH_IFNAME, 0);
                            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, WAN_STATUS_STARTED, 0);
                        }
                    }
                    else
                    {
                        CcspTraceInfo(("%s %d: DeviceNetworkMode is GATEWAY_MODE\n", __FUNCTION__, __LINE__));
                    }
                }
                else
                {
                    CcspTraceError(("%s %d: DeviceNetworkMode syscfg get fail\n", __FUNCTION__, __LINE__));
                }
            }
#endif /* RDKB_EXTENDER_ENABLED */
            else if (strcmp(name, SYSEVENT_RADVD_RESTART) == 0)
            {
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_SERVICE_ROUTED_STATUS, "", 0);
                v_secure_system("service_routed radv-restart");
            }
            else if (strcmp(name, SYSEVENT_GLOBAL_IPV6_PREFIX_CLEAR) == 0)
            {
                /*ToDo
                 *This is temporary changes because of Voice Issue,
                 * For More Info, please Refer RDKB-38461.
                 */
                char ifName[64] = {0};
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_CONNECTION_STATE, STATUS_DOWN_STRING, 0);
                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, ifName, sizeof(ifName));
                if(strlen(ifName) > 0)
                {
                    WanMgr_SetInterfaceStatus(ifName, WANMGR_IFACE_CONNECTION_IPV6_DOWN);
                    Wan_ForceRenewDhcpIPv6(ifName);
                }
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
            }
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
            else if (strcmp(name, SYSEVENT_MAPT_FEATURE_ENABLE) == 0)
            {
#if defined(FEATURE_SUPPORT_MAPT_NAT46)
                if (!strcmp(val, SYSEVENT_VALUE_TRUE))
                {
                    WanMgr_MAPTEnable(TRUE);
                }
                else if (!strcmp(val, SYSEVENT_VALUE_FALSE))
                {
                    WanMgr_MAPTEnable(FALSE);
                }
#endif
                if (!strcmp(val, SYSEVENT_VALUE_TRUE) || !strcmp(val, SYSEVENT_VALUE_FALSE))
                {
                    mapt_feature_enable_changed = TRUE;
                }
            }
            else if (strcmp(name, SYSEVENT_FACTORY_RESET_STATUS) == 0)
            {
                CcspTraceInfo(("%s %d - received notification event %s:%s\n", __FUNCTION__, __LINE__, name, val ));
                if (strcmp(val, SYSEVENT_VALUE_STARTED) == 0) 
                {
                    char ifName[64] = {0},
                         maptStatus[16] = {0};
                    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_FEATURE_ENABLE, maptStatus, sizeof(maptStatus));
                    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, ifName, sizeof(ifName));
    
                    CcspTraceInfo(("%s %d - IsMAP-TEnabled:%s WAN IfName:%s\n", __FUNCTION__, __LINE__, maptStatus, ifName ));

                    if (!strcmp(maptStatus, SYSEVENT_VALUE_FALSE) && (strlen(ifName) > 0))
                    {
#ifdef FEATURE_IPOE_HEALTH_CHECK
                        char output[16] = {0};
                        FILE *fp = NULL;   
                        fp = v_secure_popen("r","pidof "IHC_CLIENT_NAME);
                        if(fp)
			{
			    WanManager_Util_GetShell_output(fp, output, sizeof(output));
			    v_secure_pclose(fp);
			}
                        CcspTraceInfo(("%s %d - Stopping IPoE App(PID:%d) for WAN IfName:%s\n", __FUNCTION__, __LINE__, atoi(output), ifName));
                        WanManager_StopIpoeHealthCheckService(atoi(output));
#endif /* FEATURE_IPOE_HEALTH_CHECK */
                        //TODO: not a correct place to stop dhcpv6 client, virtual interface state machine may restart it again.  
                        CcspTraceInfo(("%s %d - Stopping DHCPv6 client for WAN IfName:%s\n", __FUNCTION__, __LINE__, ifName ));
                        DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVirtualIfaceByName_locked(ifName);
                        if(pVirtIf != NULL)
                        {
                            WanManager_StopDhcpv6Client(pVirtIf, TRUE);
                            WanMgr_VirtualIfaceData_release(pVirtIf);
                        }
                    }
                }
            }
#endif
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
            /*TODO:
             *The Below code is workaround and should be removed after Bridge Mode Unification.
             */
            else if (strcmp(name, SYSEVENT_BRIDGE_STATUS) == 0)
            {
                char output[4] = {0};
                int BridgeMode = 0;

                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_BRIDGE_MODE, output, sizeof(output));
                CcspTraceInfo(("%s-%d: Bridge Mode Changed to %s, %s=%s, Previous BridgeMode=%d\n",
                                        __FUNCTION__, __LINE__, output, SYSEVENT_BRIDGE_STATUS, val, BridgeModePrev));

                BridgeMode = atoi(output);
                if ((BridgeMode == 2) && (strcmp(val, SYSEVENT_VALUE_STARTED) == 0))
                {
                    BridgeModeStatus = BRIDGE_MODE_STATUS_STARTED;
                }
                else if ((BridgeMode == 0) && (strcmp(val, SYSEVENT_VALUE_STOPPED) == 0))
                {
                    BridgeModeStatus = BRIDGE_MODE_STATUS_STOPPED;
                }
            }
            else if (strcmp(name, SYSEVENT_MULTINET1_STATUS) == 0)
            {
                char output[4] = {0};
                int BridgeMode = 0;

                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_BRIDGE_MODE, output, sizeof(output));
                if (((BridgeModeStatus == BRIDGE_MODE_STATUS_STARTED) || 
                     (BridgeModeStatus == BRIDGE_MODE_STATUS_STOPPED)) && 
                     (strcmp(val, "ready") == 0))
                {
                    CcspTraceInfo(("%s-%d: Bridge Mode Changed to %s, BridgeModeStatus=%d, %s=%s, Previous BridgeMode=%d\n", 
                                    __FUNCTION__, __LINE__, output, BridgeModeStatus, SYSEVENT_MULTINET1_STATUS, val, BridgeModePrev));
                    BridgeModeStatus = BRIDGE_MODE_STATUS_UNKNOWN;
                    BridgeMode = atoi(output);
                    if (BridgeMode != BridgeModePrev)
                    {
                        BridgeModePrev = BridgeMode;
                        WanMgr_BridgeModeChanged(BridgeMode);
                    }
                }
            }
#endif
/*Below Code should be remove, Once Comcast policy Deprecated.*/
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)) && !defined(WAN_MANAGER_UNIFICATION_ENABLED)
#if defined(FEATURE_TAD_HEALTH_CHECK)
            else if ((strcmp(name, SYSEVENT_WAN_STATUS) == 0) && (strcmp(val, SYSEVENT_VALUE_STOPPED) == 0))
            {
                memset(primary_v4gateway, 0, sizeof(primary_v4gateway));
                memset(primary_v4dns, 0, sizeof(primary_v4dns));
                memset(primary_v6dns, 0, sizeof(primary_v6dns));
                memset(primary_v6ip_address, 0, sizeof(primary_v6ip_address));
            }
            else if (strcmp(name, SYSEVENT_IPV6_ADDRESS) == 0)
            {
                char output[32] = {0};
                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV6_ADDRESS, output, sizeof(output));
                if((strlen(output) > 0) && (strcmp(output, primary_v6ip_address) != 0))
                {
                    CcspTraceInfo(("%s-%d: Primary v6 Ip Address Changed to =%s, Val=%s, current_v6ip_Address=%s, prev_v6ip_address=%s \n",
                                    __FUNCTION__, __LINE__, name, val, output, primary_v6ip_address));
                    if(WanMgr_TriggerPrimaryDnsConnectivityRestart() == -1)
                    {
                    }
                    else
                    {
                        memset(primary_v6ip_address, 0, sizeof(primary_v6ip_address));
                        strncpy(primary_v6ip_address, output, sizeof(primary_v6ip_address));
                    }
                }
            }
            else if (strcmp(name, SYSEVENT_IPV4_GATEWAY) == 0)
            {
                char output[32] = {0};
                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV4_GATEWAY, output, sizeof(output));
                if((strlen(output) > 0) && (strcmp(output, primary_v4gateway) != 0))
                {
                    CcspTraceInfo(("%s-%d: Primary Gateway Name=%s, Val=%s, current_vgateway=%s, prev_v4gateway=%s \n",
                                    __FUNCTION__, __LINE__, name, val, output, primary_v4gateway));
                    if(WanMgr_TriggerPrimaryDnsConnectivityRestart() == -1)
                    {
                    }
                    else
                    {
                        memset(primary_v4gateway, 0, sizeof(primary_v4gateway));
                        strncpy(primary_v4gateway, output, sizeof(primary_v4gateway));
                    }
                }
            }

            else if (strcmp(name, SYSEVENT_IPV4_DNS) == 0)
            {
                char output[32] = {0};
                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV4_DNS, output, sizeof(output));
                if((strlen(output) > 0) && (strcmp(output, primary_v4dns) != 0))
                {
                    CcspTraceInfo(("%s-%d: Primary Name=%s, Val=%s, current_ipv4dns=%s, prev_ipv4dns=%s \n", 
                                    __FUNCTION__, __LINE__, name, val, output, primary_v4dns));
                    if(WanMgr_TriggerPrimaryDnsConnectivityRestart() == -1)
                    {
                    }
                    else
                    {
                        memset(primary_v4dns, 0, sizeof(primary_v4dns));
                        strncpy(primary_v4dns, output, sizeof(primary_v4dns));
                    }
                }
            }

            else if (strcmp(name, SYSEVENT_IPV6_DNS) == 0)
            {
                char output[32] = {0};
                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV6_DNS, output, sizeof(output));
                if((strlen(output) > 0) && (strcmp(output, primary_v6dns) != 0))
                {
                    CcspTraceInfo(("%s-%d: Primary Name=%s, Val=%s, current_ipv6dns=%s, prev_ipv6dns=%s \n", 
                                    __FUNCTION__, __LINE__, name, val, output, primary_v6dns));
                    if(WanMgr_TriggerPrimaryDnsConnectivityRestart() == -1)
                    {
                    }
                    else
                    {
                        memset(primary_v6dns, 0, sizeof(primary_v6dns));
                        strncpy(primary_v6dns, output, sizeof(primary_v6dns));
                    }
                }
            }

            else if (strcmp(name, SYSEVENT_BACKUP_IPv4_DNS) == 0)
            {
                char output[32] = {0};
                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_BACKUP_IPv4_DNS, output, sizeof(output));
                if((strlen(output) > 0) && (strcmp(output, backup_v4dns) != 0))
                {
                    CcspTraceInfo(("%s-%d: Backup Name=%s, Val=%s, current_ipv4dns=%s, prev_ipv4dns=%s \n", 
                                    __FUNCTION__, __LINE__, name, val, output, backup_v4dns));
                    if(WanMgr_TriggerBackupDnsConnectivityRestart() == -1)
                    {
                    }
                    else
                    {
                        memset(backup_v4dns, 0, sizeof(backup_v4dns));
                        strncpy(backup_v4dns, output, sizeof(backup_v4dns));
                    }
                }
            }

            else if (strcmp(name, SYSEVENT_BACKUP_IPV6_DNS) == 0)
            {
                char output[32] = {0};
                sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_BACKUP_IPV6_DNS, output, sizeof(output));
                if((strlen(output) > 0) && (strcmp(output, backup_v6dns) != 0))
                {
                    CcspTraceInfo(("%s-%d: Backup: Name=%s, Val=%s, current_ipv6dns=%s, prev_ipv6dns=%s \n", 
                                    __FUNCTION__, __LINE__, name, val, output, backup_v6dns));
                    if(WanMgr_TriggerBackupDnsConnectivityRestart() == -1)
                    {
                    }
                    else
                    {
                        memset(backup_v6dns, 0, sizeof(backup_v6dns));
                        strncpy(backup_v6dns, output, sizeof(backup_v6dns));
                    }
                }
            }
#endif
#endif
            else
            {
                CcspTraceWarning(("%s %d undefined event %s:%s \n", __FUNCTION__, __LINE__, name, val));
            }
        }
    }

    CcspTraceInfo(("%s %d - WanManagerSyseventHandler Exit \n", __FUNCTION__, __LINE__));
    return 0;
}

static void check_lan_wan_ready()
{
    char lan_st[BUFLEN_16];
    char wan_st[BUFLEN_16];
    memset(lan_st,0,sizeof(lan_st));
    memset(wan_st,0,sizeof(wan_st));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_LAN_STATUS, lan_st, sizeof(lan_st));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, wan_st, sizeof(wan_st));

    CcspTraceInfo(("****************************************************\n"));
    CcspTraceInfo(("    Lan Status = %s   Wan Status = %s\n", lan_st, wan_st));
    CcspTraceInfo(("****************************************************\n"));
    if (!strcmp(lan_st, SYSEVENT_VALUE_STARTED) && !strcmp(wan_st, SYSEVENT_VALUE_STARTED))
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_START_MISC, SYSEVENT_VALUE_READY, 0);
        lan_wan_started = 1;
    }
    return;
}

static int CheckV6DefaultRule (char *wanInterface)
{
    char output[256];
    int ret = FALSE;
    int pclose_ret = 0;
    FILE *fp;

    if ((fp = v_secure_popen("r", "ip -6 ro")) == NULL)
    {
        CcspTraceError(("%s %d - Failed to open file descripter %d(%s) \n", __FUNCTION__, __LINE__, errno, strerror(errno)));
        return FALSE;
    }

    while (fgets(output, sizeof(output), fp) != NULL)
    {
        if ((strncmp(output, "default via ", strlen("default via ")) == 0) &&
            (strstr(output, wanInterface) != NULL))
        {
            ret = TRUE; // Default route entry exists
            break;
        }
    }

    pclose_ret = v_secure_pclose(fp);

    if (pclose_ret != 0)
    {
        CcspTraceError(("Failed in closing the pipe ret %d \n",pclose_ret));
    }
    CcspTraceInfo(("%s %d - Default route %sfound for interface %s\n", __FUNCTION__, __LINE__, (ret == TRUE) ? "" : "not ", wanInterface));
    return ret;
}

/*
 * @brief Utility function used to toggle ipv6 triggered from ISM.
 * This function will not check existing default route.
 * @param : Interface name.
 * @return Returns NONE.
 */
int Force_IPv6_toggle (char* wanInterface)
{
    int ret = 0;
    CcspTraceInfo(("%s %d force toggle initiated\n", __FUNCTION__, __LINE__));

    if (sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/disable_ipv6", wanInterface, "1") != 0)
    {
        CcspTraceWarning(("%s-%d : Failure writing to /proc file\n", __FUNCTION__, __LINE__));
    }

    if (sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/disable_ipv6", wanInterface, "0") != 0)
    {
        CcspTraceWarning(("%s-%d : Failure writing to /proc file\n", __FUNCTION__, __LINE__));
    }

    isDefaultGatewayAdded = 1; //Reset isDefaultGatewayAdded flag;
    
    return ret;
}

/*
 * @brief Utility function used to check the default route and send router solicit if not available.
 * @param : Virtual Interface Interface .
 * @return Returns NONE.
 */
void WanMgr_CheckDefaultRA (DML_VIRTUAL_IFACE * pVirtIf)
{
    //TODO : Move router monitor to a WanManager thread ? 
    if(!isDefaultGatewayAdded )
    {
        //TODO: add check for remote device ( static ip )
        if (CheckV6DefaultRule(pVirtIf->Name) == TRUE ||  WanManager_send_and_receive_rs(pVirtIf) == 0)
        {
            isDefaultGatewayAdded = 1; //Reset isDefaultGatewayAdded flag;
        }
    }
}

/*
 * @brief Utility function used to Configure accept_ra_defrtr from ISM.
 * @param : Virtual Interface and Enable.
 * @return Returns NONE.
 */
void WanMgr_Configure_accept_ra(DML_VIRTUAL_IFACE * pVirtIf, BOOL EnableRa)
{
    /* TODO: PPP connection default route is added by IPv6CP session. 
     * Use Device.PPP.Interface.1.IPv6CP.RemoteInterfaceIdentifier get default ipv6 route .
     */

    if( pVirtIf->PPP.Enable == TRUE)
    {
        CcspTraceWarning(("%s-%d : %s is a PPP interface. Not changing accept_ra \n", __FUNCTION__, __LINE__,pVirtIf->Name));
        return;
    }

    CcspTraceInfo(("%s %d %s accept_ra for interface %s\n", __FUNCTION__, __LINE__,EnableRa?"Enabling":"Disabling", pVirtIf->Name));
    //Enable accept_ra to allow receiving RA all the time. This funtion  only blocks learning defult route from RA.
    v_secure_system("sysctl -w net.ipv6.conf.%s.accept_ra=2",pVirtIf->Name);

    //SLAAC use case, Kernel should be handling the IP assignment over interface
    if ( DML_WAN_IP_SOURCE_SLAAC == pVirtIf->IP.IPv6Source )
    {
        v_secure_system("sysctl -w net.ipv6.conf.%s.accept_ra_pinfo=1",pVirtIf->Name);
    }
    else
    {
        v_secure_system("sysctl -w net.ipv6.conf.%s.accept_ra_pinfo=0",pVirtIf->Name);
    }

    if(EnableRa)
    {
        v_secure_system("sysctl -w net.ipv6.conf.%s.router_solicitations=3",pVirtIf->Name);
        v_secure_system("sysctl -w net.ipv6.conf.%s.forwarding=1",pVirtIf->Name);
        v_secure_system("sysctl -w net.ipv6.conf.%s.accept_ra_defrtr=1",pVirtIf->Name); //Learn defult route from the RA.
        v_secure_system("sysctl -w net.ipv6.conf.all.forwarding=1");
        CcspTraceInfo(("%s %d Enabling forwarding for interface %s\n", __FUNCTION__, __LINE__,pVirtIf->Name));
    }
    else
    {
        //Only accept_ra_defrtr set to false to block setting default route.
        v_secure_system("sysctl -w net.ipv6.conf.%s.router_solicitations=0",pVirtIf->Name);
        v_secure_system("sysctl -w net.ipv6.conf.%s.accept_ra_defrtr=0",pVirtIf->Name); 
    }
}

INT wanmgr_isWanStandby()
{
    char wan_st[BUFLEN_16];
    memset(wan_st,0,sizeof(wan_st));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, wan_st, sizeof(wan_st));

    if (!strcmp(wan_st, "standby"))
    {
        return 1;
    }

    return 0;
}

INT wanmgr_isWanStarted()
{
    char wan_st[BUFLEN_16];
    memset(wan_st,0,sizeof(wan_st));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, wan_st, sizeof(wan_st));

    if (!strcmp(wan_st, SYSEVENT_VALUE_STARTED))
    {
        return 1;
    }

    return 0;
}

INT WanMgr_GetWanServiceStatus(void)
{
    INT ret = -1;
    char wan_st[BUFLEN_16];
    memset(wan_st,0,sizeof(wan_st));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, wan_st, sizeof(wan_st));

    if (strcmp(wan_st, SYSEVENT_VALUE_STARTED) == 0)
    {
        ret = 1;
    }
    else if (strcmp(wan_st, SYSEVENT_VALUE_STOPPED) == 0)
    {
        ret = 0;
    }

    return ret;
}

INT WanMgr_GetWanStatus(void)
{
    INT ret = -1;
    char wan_st[BUFLEN_16];
    memset(wan_st,0,sizeof(wan_st));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, wan_st, sizeof(wan_st));

    if (strcmp(wan_st, SYSEVENT_VALUE_STARTED) == 0)
    {
        ret = 1;
    }
    else if (strcmp(wan_st, SYSEVENT_VALUE_STOPPED) == 0)
    {
        ret = 0;
    }

    return ret;
}

INT WanMgr_GetWanRoutedStatus(void)
{
    INT ret = -1;
    char wan_st[BUFLEN_16];
    memset(wan_st,0,sizeof(wan_st));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_ROUTED_STATUS, wan_st, sizeof(wan_st));

    if (strcmp(wan_st, SYSEVENT_VALUE_STARTED) == 0)
    {
        ret = 1;
    }
    else if (strcmp(wan_st, SYSEVENT_VALUE_STOPPED) == 0)
    {
        ret = 0;
    }

    return ret;
}

INT WanMgr_IsWanStopped(void)
{
    if ( (WanMgr_GetWanServiceStatus() == 0) &&
         (WanMgr_GetWanStatus() == 0) &&
         (WanMgr_GetWanRoutedStatus() == 0) )
    {
        return 1;
    }
    return 0;
}

ANSC_STATUS wanmgr_setwanstart()
{
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_START, "", 0);
    CcspTraceInfo(("%s %d - wan started\n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wanmgr_setwanrestart()
{
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_RESTART, "", 0);
    CcspTraceInfo(("%s %d - wan restarted\n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wanmgr_setwanstop()
{
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_STOP, "", 0);
    CcspTraceInfo(("%s %d - wan stop\n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wanmgr_sshd_restart()
{
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_SSHD_RESTART, "", 0);
    CcspTraceInfo(("%s %d - sshd restart\n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_SUCCESS;
}

#ifdef SNMPV3_ENABLED
static ANSC_STATUS wanmgr_snmpv3_restart()
{

    CcspTraceInfo(("%s %d\n", __FUNCTION__, __LINE__));

    // Restart snmpv3 service
    if (access("/lib/rdk/handlesnmpv3.sh", F_OK) == 0)
    {
        v_secure_system("sh /lib/rdk/handlesnmpv3.sh &");
        return ANSC_STATUS_SUCCESS;
    }

    return ANSC_STATUS_FAILURE;
}
#endif // SNMPV3_ENABLED

ANSC_STATUS wanmgr_services_restart()
{
    /** 
     * Below WAN services will be refreshed during below use cases
     * 1. WAN refresh
     * 2. MAP-T to DualStack migration and vice versa
     * 
     * We need to ensure below WAN services restart may affect slow service distruption which were already 
     * in progress. Like snmpv3 query may happen from outside of CPE and may reconnect,
     * Someone trying to connect CPE via reversessh and it may delay or reconnect
     */
    wanmgr_sshd_restart();
#ifdef SNMPV3_ENABLED
    wanmgr_snmpv3_restart();
#endif // SNMPV3_ENABLED

#ifdef _CBR2_PRODUCT_REQ_
    v_secure_system("sh /etc/network_response.sh &");
#endif // _CBR2_PRODUCT_REQ_
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wanmgr_firewall_restart(void)
{
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, "", 0);
    CcspTraceInfo(("%s %d - firewall restart\n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_SysEvents_Init(void)
{
    ANSC_STATUS retStatus = ANSC_STATUS_SUCCESS;
    pthread_t sysevent_tid;

    // Initialize sysevent daemon
    retStatus = WanMgr_SyseventInit();
    if (retStatus != ANSC_STATUS_SUCCESS)
    {
        WanMgr_SyseventClose();
        CcspTraceError(("%s %d - WanMgr_SyseventInit failed \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
#if defined(_HUB4_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_)
    set_default_conf_entry();
#endif

    /*TODO:
     *it should be removed with BridgeMode Proper Design Implementation.
     */
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    char output[4] = {0};
    if (syscfg_get(NULL, SYSEVENT_BRIDGE_MODE, output, sizeof(output)) == ANSC_STATUS_SUCCESS)
    {
       BridgeModePrev = atoi(output);
    }
#endif
    //Init msg status handler
    if(pthread_create(&sysevent_tid, NULL, WanManagerSyseventHandler, NULL) == 0) {
        CcspTraceInfo(("%s %d - DmlWanMsgHandler -- pthread_create successfully \n", __FUNCTION__, __LINE__));
    }
    else {
        CcspTraceError(("%s %d - DmlWanMsgHandler -- pthread_create failed \n", __FUNCTION__, __LINE__));
    }

    //Initialize syscfg value of ipv6 address to release previous value
    syscfg_set_commit(NULL, SYSCFG_FIELD_IPV6_PREFIX_ADDRESS, "");

    return retStatus;
}

ANSC_STATUS WanMgr_SysEvents_Finalise(void)
{
    ANSC_STATUS retStatus = ANSC_STATUS_SUCCESS;

    WanMgr_SyseventClose();

    return retStatus;
}

void wanmgr_sysevent_hw_reconfig_reboot(void)
{
    if (sysevent_fd == -1)      return;
    CcspTraceInfo(("Setting hw reconfiguration reboot event.\n"));
    sysevent_set(sysevent_fd, sysevent_token, "wanmanager_reboot_status", "1", 0);
}

#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
void wanmgr_get_wan_interface(char *wanInterface)
{
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, wanInterface, BUFLEN_64);

    if (wanInterface[0] == '\0')
    {
        strcpy(wanInterface,"erouter0"); // default wan interface
    }
}
#endif

void  wanmgr_restart_zebra (void)
{
    FILE *zebra_pid_fd;
    FILE *zebra_cmdline_fd;
    char pid_str[10];
    char cmdline_buf[255];
    int pid = -1;
    int restart_needed = 1;

    if ((zebra_pid_fd = fopen("/var/zebra.pid", "rb")) != NULL)
    {
        if (fgets(pid_str, sizeof(pid_str), zebra_pid_fd) != NULL && atoi(pid_str) > 0)
        {
            pid = atoi(pid_str);
        }
        fclose(zebra_pid_fd);
    }

    if (pid > 0)
    {
        sprintf(cmdline_buf, "/proc/%d/cmdline", pid);
        if ((zebra_cmdline_fd = fopen(cmdline_buf, "rb")) != NULL)
        {
            if (fgets(cmdline_buf, sizeof(cmdline_buf), zebra_cmdline_fd) != NULL)
            {
                if (strstr(cmdline_buf, "zebra"))
                {
                    restart_needed = 0;
                }
            }
            fclose(zebra_cmdline_fd);
        }
    }

    if (restart_needed)
    {
        sysevent_set(sysevent_fd, sysevent_token, "zebra-restart", "", 0);
    }
}
