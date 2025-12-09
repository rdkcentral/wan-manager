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

#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <sys/syscall.h>
#include "wanmgr_interface_sm.h"
#include "wanmgr_utils.h"
#include "platform_hal.h"
#include "wanmgr_sysevents.h"
#include "wanmgr_ipc.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_data.h"
#include "wanmgr_interface_sm.h"
#include "wanmgr_platform_events.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_dhcpv4_apis.h"
#include "wanmgr_dhcpv6_apis.h"
#include "secure_wrapper.h"
#include "wanmgr_telemetry.h"
#ifdef ENABLE_FEATURE_TELEMETRY2_0
#include <telemetry_busmessage_sender.h>
#endif
#ifdef FEATURE_DSLITE_V2
#include "wanmgr_dslite.h"
#endif
#define IF_SIZE      32
#define LOOP_TIMEOUT 50000 // timeout in microseconds. This is the state machine loop interval
#define RESOLV_CONF_FILE "/etc/resolv.conf"
#define LOOPBACK "127.0.0.1"

// TODO: Consider extending datamodel for DSLITE_RETRY_INTERVAL_SEC
#ifdef FEATURE_DSLITE_V2
#define DSLITE_RETRY_INTERVAL_SEC 5
#endif

#ifdef FEATURE_IPOE_HEALTH_CHECK
#define IPOE_HEALTH_CHECK_V4_STATUS "ipoe_health_check_ipv4_status"
#define IPOE_HEALTH_CHECK_V6_STATUS "ipoe_health_check_ipv6_status"
#define IPOE_STATUS_FAILED "failed"
#define IPOE_STATUS_IDLE "idle"
#endif

#define POSTD_START_FILE "/tmp/.postd_started"
#define SELECTED_MODE_TIMEOUT_SECONDS 10

#if defined(FEATURE_IPOE_HEALTH_CHECK) && defined(IPOE_HEALTH_CHECK_LAN_SYNC_SUPPORT)
extern lanState_t lanState;
#endif

#if defined(FEATURE_464XLAT)
typedef enum
{
    XLAT_ON = 10,
    XLAT_OFF
} XLAT_State_t;
static XLAT_State_t xlat_state_get(void);
#endif


/*WAN Manager States*/
static eWanState_t wan_state_vlan_configuring(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_ppp_configuring(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_validating_wan(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_obtaining_ip_addresses(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_standby(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_ipv4_leased(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_ipv6_leased(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_dual_stack_active(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
static eWanState_t wan_state_mapt_active(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
#endif //FEATURE_MAPT
#if defined(FEATURE_DSLITE_V2)
static eWanState_t wan_state_dslite_active(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
#endif //FEATURE_DSLITE_V2
static eWanState_t wan_state_refreshing_wan(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_deconfiguring_wan(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_exit(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_phy_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_state_phy_configuring(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);

/*WAN Manager Transitions*/
static eWanState_t wan_transition_start(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_ppp_configure(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_physical_interface_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_wan_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_wan_validated(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_wan_refreshed(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_ipv4_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_ipv4_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_ipv6_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_ipv6_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_dual_stack_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_standby(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_standby_deconfig_ips(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_vlan_configure(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
static eWanState_t wan_transition_mapt_feature_refresh(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_mapt_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_mapt_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
extern int mapt_feature_enable_changed;
#endif //FEATURE_MAPT
#if defined(FEATURE_DSLITE_V2)
static eWanState_t wan_transition_dslite_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_dslite_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
#endif //FEATURE_DSLITE_V2
static eWanState_t wan_transition_configuring_interface(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_phy_deconfiguring(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_wan_deconfigured(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static eWanState_t wan_transition_exit(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);

static ANSC_STATUS WanMgr_StartConnectivityCheck(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static ANSC_STATUS WanMgr_StopConnectivityCheck(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
static ANSC_STATUS WanMgr_SendMsgTo_ConnectivityCheck(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl , CONNECTION_TYPE type, BOOL ConnStatus);
#ifdef FEATURE_IPOE_HEALTH_CHECK
static ANSC_STATUS WanManager_StopIHC(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl);
#endif

/***************************************************************************
 * @brief API used to check the incoming nameserver is valid
 * @param af indicates ip address family
 * @param nameserver dns namserver name
 * @return RETURN_OK if execution successful else returned error.
 ****************************************************************************/
int IsValidDnsServer(int32_t af, const char *nameServer);

/********************************************************************************
 * @brief Configure IPV4 configuration on the interface.
 * This API calls the HAL routine to configure ipv4.
 * @param pWanIfaceCtrl Interface state machine data - iface and config wan data
 * @return RETURN_OK upon success else returned error code.
 *********************************************************************************/
static int wan_setUpIPv4(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl);

/********************************************************************************
 * @brief clear IPv4 adress from the interface.
 * This API calls the HAL/linux system routine to configure ipv4.
 * @param pWanIfaceCtrl Interface state machine data - iface and config wan data
 * @return RETURN_OK upon success else returned error code.
 *********************************************************************************/
static int wan_deconfigIPv4onInterface(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl);

/********************************************************************************
 * @brief Unconfig IPV4 configuration on the interface.
 * This API calls the HAL routine to unconfig ipv4.
 * @param pWanIfaceCtrl Interface state machine data - iface and config wan data
 * @return RETURN_OK upon success else returned error code.
 *********************************************************************************/
static int wan_tearDownIPv4(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl);

/*************************************************************************************
 * @brief Configure IPV6 configuration on the interface.
 * This API calls the HAL routine to config ipv6.
 * @param pWanIfaceCtrl Interface state machine data - iface and config wan data
 * @return  RETURN_OK upon success else returned error code.
 **************************************************************************************/
static int wan_setUpIPv6(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl);

/*************************************************************************************
 * @brief Unconfig IPV6 configuration on the interface.
 * This API calls the HAL routine to unconfig ipv6.
 * @param pWanIfaceCtrl Interface state machine data - iface and config wan data
 * @return RETURN_OK upon success else returned error code.
 **************************************************************************************/
static int wan_tearDownIPv6(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl);

/**************************************************************************************
 * @brief Update DNS configuration into /etc/resolv.conf
 * @param pWanIfaceCtrl Interface state machine data - iface and config wan data
 * @param addIPv4 boolean flag indicates whether IPv4 DNS data needs to be update
 * @param addIPv6 boolean flag indicates whether IPv6 DNS data needs to be update
 * @return RETURN_OK upon success else ERROR code returned
 **************************************************************************************/
int wan_updateDNS(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl, BOOL addIPv4, BOOL addIPv6);

/**************************************************************************************
 * @brief Clear the DHCP client data stored.
 * It should be used to clear the old data before start a new DHCP client.
 * @param Interface data structure
 * @return ANSC_STATUS_SUCCESS upon success else ANSC_STATUS_FAILURE
 **************************************************************************************/
static ANSC_STATUS WanManager_ClearDHCPData(DML_VIRTUAL_IFACE * pVirtIf);

/*************************************************************************************
 * @brief Check IPv6 address assigned to interface or not.
 * This API internally checks ipv6 prefix being set, received valid gateway and
 * lan ipv6 address ready to use.
 * @return RETURN_OK on success else RETURN_ERR
 *************************************************************************************/
static int checkIpv6LanAddressIsReadyToUse(DML_VIRTUAL_IFACE* p_VirtIf);

#ifdef FEATURE_DSLITE_V2
/*************************************************************************************
 * @brief Enable DSLite configuration on the interface.
 * This API calls the HAL routine to Enable DSLite.
 * @return RETURN_OK upon success else ERROR code returned
 **************************************************************************************/
static int wan_setUpDslite(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl);

/*************************************************************************************
 * @brief Disable DSLite configuration on the interface.
 * This API calls the HAL routine to disable DSLite.
 * @return RETURN_OK upon success else ERROR code returned
 **************************************************************************************/
static int wan_tearDownDslite(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl);
#endif

#ifdef FEATURE_MAPT

/*************************************************************************************
 * @brief Enable mapt configuration on the interface.
 * This API calls the HAL routine to Enable mapt.
 * @return RETURN_OK upon success else ERROR code returned
 **************************************************************************************/
static int wan_setUpMapt();

/*************************************************************************************
 * @brief Disable mapt configuration on the interface.
 * This API calls the HAL routine to disable mapt.
 * @return RETURN_OK upon success else ERROR code returned
 **************************************************************************************/
static int wan_tearDownMapt();

/*************************************************************************************
 * @brief checks kernel module loaded.
 * This API calls the proc entry.
 * @param moduleName is the kernal modulename
 * @return RETURN_OK upon success else RETURN_ERR returned
 **************************************************************************************/

#define NAT46_MODULE "nat46"
#define MTU_DEFAULT_SIZE (1500)
#define MAP_INTERFACE "map0"

static int wan_setUpMapt()
{
    int ret = RETURN_OK;

    //Configure mapt packet acceleration for supported platforms
    if ( !access("/proc/sys/net/flowmgr/disable_mapt_accel", F_OK) )
    {
        if (sysctl_iface_set("/proc/sys/net/flowmgr/disable_mapt_accel", NULL, "0") != 0)
        {
            CcspTraceError(("Failed to enable mapt packet acceleration!\n"));
        }
    }
    else
    {
        CcspTraceWarning(("Mapt packet acceleration is not supported!\n"));
    }

#if defined(IVI_KERNEL_SUPPORT)
    if (WanManager_DoSystemActionWithStatus("wanmanager", "insmod /lib/modules/`uname -r`/extra/ivi.ko") != RETURN_OK)
    {
        CcspTraceError(("%s %d -insmod: Failed to add ivi.ko \n", __FUNCTION__, __LINE__));
        ret = RETURN_ERR;
    }
#elif defined(NAT46_KERNEL_SUPPORT)
    if ((isModuleLoaded(NAT46_MODULE) != RETURN_OK) && (WanManager_DoSystemActionWithStatus("wanmanager", "insmod /lib/modules/`uname -r`/extra/nat46.ko zero_csum_pass=1") != RETURN_OK))
    {
        CcspTraceError(("%s %d -insmod: Failed to add nat46.ko \n", __FUNCTION__, __LINE__));
        ret = RETURN_ERR;
    }
#endif //IVI_KERNEL_SUPPORT

    return ret;
}

static int wan_tearDownMapt()
{
    int ret = RETURN_OK;
    FILE *file;
    char line[BUFLEN_64];
    char cmd[BUFLEN_128] = {0};

#if defined(IVI_KERNEL_SUPPORT)
    file = popen("cat /proc/modules | grep ivi","r");

    if( file == NULL) {
        CcspTraceError(("[%s][%d]Failed to open  /proc/modules \n", __FUNCTION__, __LINE__));
        ret = RETURN_ERR;
    }
    else {
        if( fgets (line, BUFLEN_64, file) !=NULL ) {
            if( strstr(line, "ivi")) {
                if (WanManager_DoSystemActionWithStatus("wanmanager", "ivictl -q") != RETURN_OK)
                {
                    CcspTraceError(("%s %d ivictl: Failed to stop \n", __FUNCTION__, __LINE__));
                    ret = RETURN_ERR;
                }
                else
                {
                    CcspTraceInfo(("%s %d ivictl stopped successfully\n", __FUNCTION__, __LINE__));
                }

                if (WanManager_DoSystemActionWithStatus("wanmanager", "rmmod -f /lib/modules/`uname -r`/extra/ivi.ko") != RETURN_OK)
                {
                    CcspTraceError(("%s %d rmmod: Failed to remove ivi.ko \n", __FUNCTION__, __LINE__));
                    ret = RETURN_ERR;
                }
                else
                {
                    CcspTraceInfo(("%s %d ivi.ko removed\n", __FUNCTION__, __LINE__));
                }
            }
        }
        pclose(file);
    }
#elif defined(NAT46_KERNEL_SUPPORT)
    snprintf(cmd, BUFLEN_128, "echo del %s > /proc/net/nat46/control", MAP_INTERFACE);
    if ((isModuleLoaded(NAT46_MODULE) == RETURN_OK) && (WanManager_DoSystemActionWithStatus("wanmanager", cmd) != RETURN_OK))
    {
        CcspTraceError(("%s %d Clear nat46 configurations Failed \n", __FUNCTION__, __LINE__));
    }
    else
    {
        CcspTraceInfo(("%s %d Clear nat46 configurations Success \n", __FUNCTION__, __LINE__));
    }
#endif //IVI_KERNEL_SUPPORT

    //Configure mapt packet acceleration for supported platforms
    if ( !access("/proc/sys/net/flowmgr/disable_mapt_accel", F_OK) )
    {
        if (sysctl_iface_set("/proc/sys/net/flowmgr/disable_mapt_accel", NULL, "3") != 0)
        {
            CcspTraceError(("Failed to disable mapt packet acceleration!\n"));
        }
    }
    else
    {
        CcspTraceWarning(("Mapt packet acceleration is not supported!\n"));
    }

    return ret;
}
#endif

/************************************************************************************
 * @brief Get the status of Interface State Machine.
 * @return TRUE on running else FALSE
 ************************************************************************************/
BOOL WanMgr_Get_ISM_RunningStatus(UINT ifaceIdx)
{
    BOOL status = FALSE;

    WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(ifaceIdx);
    if(pWanDmlIfaceData != NULL)
    {
        DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
        for(int virIf_id=0; virIf_id< pWanIfaceData->NoOfVirtIfs; virIf_id++)
        {
            DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, virIf_id);
            status = p_VirtIf->Interface_SM_Running;
            if(status == TRUE)
                break;
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    return status;
}

/************************************************************************************
 * @brief Gets existing l3 interface status
 * @return TRUE if interface already availbale and running else FALSE
 ************************************************************************************/
static BOOL WanMgr_RestartFindExistingLink (WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    //get PHY status
    char dmQuery[BUFLEN_256] = {0};
    char dmValue[BUFLEN_256] = {0};
    BOOL ret = FALSE;

    DML_WAN_IFACE* pWanIfaceData = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    //TODO: NEW_DESIGN check Cellular
    if(strstr(pWanIfaceData->BaseInterface, "Cellular") != NULL)
    {
        snprintf(dmQuery, sizeof(dmQuery)-1, "%s%s", pWanIfaceData->BaseInterface, CELLULARMGR_LINK_STATUS_DM_SUFFIX);
        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, dmValue))
        {
            CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
            ret = FALSE;
        }

        if(strcmp(dmValue,"true") == 0)
        {
            //TODO : NEW_DESIGN check VLAN status for Cellular
            p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_UP;

            if(p_VirtIf->Name[0] == '\0')
                strncpy(p_VirtIf->Name, CELLULARMGR_WAN_NAME, sizeof(p_VirtIf->Name));
            ret = TRUE;
        }
    }

    if(p_VirtIf->PPP.Enable == TRUE && (strlen(p_VirtIf->PPP.Interface) > 0))
    {
        char ppp_Status[BUFLEN_256]             = {0};
        snprintf(dmQuery, sizeof(dmQuery)-1, "%s.Status", p_VirtIf->PPP.Interface);
        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, ppp_Status))
        {
            CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
            ret = FALSE;
        }

        CcspTraceInfo(("%s %d PPP entry Status: %s\n",__FUNCTION__, __LINE__, ppp_Status));

        if(!strcmp(ppp_Status, "Up"))
        {
            p_VirtIf->PPP.LinkStatus = WAN_IFACE_PPP_LINK_STATUS_UP;
            p_VirtIf->PPP.IPV6CPStatus = WAN_IFACE_IPV6CP_STATUS_UP;    // setting IPv6CP UP to validate the link
            ret = TRUE;
        }
    }

    if(p_VirtIf->VLAN.Enable == TRUE && (strlen(p_VirtIf->VLAN.CurrentVlan) > 0))
    {
        snprintf(dmQuery, sizeof(dmQuery)-1,"%s.Status",p_VirtIf->VLAN.CurrentVlan);

        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, dmValue))
        {
            CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
            ret = FALSE;
        }

        if(strcmp(dmValue,"Up") == 0)
        {
            p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_UP;
            ret = TRUE;
            /* If we are here. WanManager is restarted. Do a IPv6 toggle to avoid DAD. */
            Force_IPv6_toggle(p_VirtIf->Name); 
        }

    }
    return ret;
}

static void WanMgr_MonitorDhcpApps (WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if (pWanIfaceCtrl == NULL || pWanIfaceCtrl->WanEnable == FALSE)
    {
        CcspTraceError(("%s %d: invalid args..\n", __FUNCTION__, __LINE__));
        return;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    if (pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED || 
        pInterface->Selection.Enable == FALSE )
    {
        CcspTraceError(("%s %d: monitoring dhcp apps not needed for this interface\n", __FUNCTION__, __LINE__));
        return;
    }

    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);
    if (p_VirtIf->IP.RefreshDHCP == TRUE)
    {
        // let the caller state handle RefreshDHCP=TRUE scenario
        CcspTraceError(("%s %d: IP Mode change detected, handle RefreshDHCP & later monitor DHCP apps\n", __FUNCTION__, __LINE__));
        //reset flag here, if the IP mode and source changes are addressed.
        if((((p_VirtIf->IP.IPv6Source != DML_WAN_IP_SOURCE_DHCP && p_VirtIf->IP.IPv6Source != DML_WAN_IP_SOURCE_SLAAC) || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_NO_IP) && p_VirtIf->IP.Dhcp4cStatus != DHCPC_STARTED && p_VirtIf->IP.Dhcp6cStatus != DHCPC_STARTED)|| //TODO : check why only IP.IPv6Source checked?
            (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY && p_VirtIf->IP.Dhcp4cStatus != DHCPC_STARTED && p_VirtIf->IP.Dhcp6cStatus == DHCPC_STARTED) || //IPv6 only mode, reset if DHCPv4 not running and v6 running
            (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV4_ONLY && p_VirtIf->IP.Dhcp4cStatus == DHCPC_STARTED&& p_VirtIf->IP.Dhcp6cStatus != DHCPC_STARTED) || //IPv4 only mode, reset if DHCPv4 running and v6 not running
            (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK && p_VirtIf->IP.Dhcp4cStatus == DHCPC_STARTED && p_VirtIf->IP.Dhcp6cStatus == DHCPC_STARTED))  //Dual stack mode, reset if DHCPv4 running and v6 running
        {
            CcspTraceInfo(("%s %d: IP Mode change processed. Resetting flag. \n", __FUNCTION__, __LINE__));
            p_VirtIf->IP.RefreshDHCP = FALSE;
	    }	
        return;
    }

#ifndef FEATURE_RDKB_DHCP_MANAGER
    //Check if IPv4 dhcp client is still running - handling runtime crash of dhcp scenario
    if ((p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV4_ONLY || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK) &&  // IP.Mode supports V4
        p_VirtIf->IP.IPv4Source == DML_WAN_IP_SOURCE_DHCP && (p_VirtIf->PPP.Enable == FALSE) &&                 // uses DHCP client
        p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_DOWN &&                                                // MAPT status is DOWN
        p_VirtIf->IP.SelectedModeTimerStatus != RUNNING  &&                                                     // Prefered mode timer Running. Wait for it to expire.
        (p_VirtIf->IP.Dhcp4cPid == -1 ||                                                                        // DHCP cleint failed to start OR
        (p_VirtIf->IP.Dhcp4cPid > 0 &&                                                                          // dhcp started by ISM
        WanMgr_IsPIDRunning(p_VirtIf->IP.Dhcp4cPid) != TRUE)))                                                  // but DHCP client not running
    {
        WanManager_StartDhcpv4Client(p_VirtIf, pInterface->Name, pInterface->IfaceType);
        CcspTraceInfo(("%s %d - SELFHEAL - Started dhcpc on interface %s\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
#ifdef ENABLE_FEATURE_TELEMETRY2_0
        t2_event_d("SYS_ERROR_DHCPV4Client_notrunning", 1);
#endif
    }

    //Check if IPv6 dhcp client is still running - handling runtime crash of dhcp client
    if ((p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK) &&  // IP.Mode supports V6
        ( p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_DHCP || p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_SLAAC ) &&  // uses DHCP client
        (((p_VirtIf->IP.Dhcp6cPid == -1) && (p_VirtIf->IP.Dhcp6cStatus != DHCPC_DISABLED)) ||                   // DHCP client failed to start
        (p_VirtIf->IP.Dhcp6cPid > 0 &&                                                                          // dhcp started by ISM
        WanMgr_IsPIDRunning(p_VirtIf->IP.Dhcp6cPid) != TRUE)))                                                   // but DHCP client not running
    {
        if (p_VirtIf->IP.Dhcp6cPid == -1 )
        {
            /* DHCPv6c client can fail to start due to DAD failuer on the link local address. 
             * This could happen if multiple WAN interfaces are up with same MAC address. Toggling will restart the DAD again.
             */
            CcspTraceInfo(("%s %d - DHCPv6c client failed to start on interface %s. Toggeling Ipv6 before retry... \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            Force_IPv6_toggle(p_VirtIf->Name); 
        }
        WanManager_StartDhcpv6Client(p_VirtIf, pInterface->IfaceType);
        CcspTraceInfo(("%s %d - SELFHEAL - Started dhcp6c on interface %s, dhcpv6_pid %d \n", __FUNCTION__, __LINE__, p_VirtIf->Name, p_VirtIf->IP.Dhcp6cPid));
#ifdef ENABLE_FEATURE_TELEMETRY2_0
        t2_event_d("SYS_ERROR_DHCPV6Client_notrunning", 1);
#endif
    }
#endif

    /* Handling Runtime IP.ConnectivityCheckType change */
    if(p_VirtIf->IP.WCC_TypeChanged  == TRUE)
    {
        if(p_VirtIf->IP.ConnectivityCheckRunning == TRUE)
        {
            /* If IP.WCC_TypeChanged is set, we have lost the previous configuration of  ConnectivityCheckType.
             * Try to stop the Connectivity check services if running.
             */
#ifdef FEATURE_IPOE_HEALTH_CHECK
            if(pWanIfaceCtrl->IhcPid > 0)
            {
                WanManager_StopIHC(pWanIfaceCtrl);        
            }
            else
#endif
            {
                WanMgr_Configure_TAD_WCC( p_VirtIf,  WCC_STOP);        
            }
            p_VirtIf->IP.ConnectivityCheckRunning = FALSE;
            //Since we are stopping Connectivity Check, Reset ConnectivityStatus to UP.
            p_VirtIf->IP.Ipv4ConnectivityStatus = WAN_CONNECTIVITY_UP;
            p_VirtIf->IP.Ipv6ConnectivityStatus = WAN_CONNECTIVITY_UP;
        }

        //Start the new connectivity check 
        WanMgr_StartConnectivityCheck(pWanIfaceCtrl); 
        p_VirtIf->IP.WCC_TypeChanged  = FALSE; //Reset the flag

#ifdef FEATURE_IPOE_HEALTH_CHECK
        if ( p_VirtIf->Status == WAN_IFACE_STATUS_UP && pWanIfaceCtrl->IhcPid > 0 )
        { 
            if(p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP)
                WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV4 , TRUE);

            if(p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)
                WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
        }
#endif
    }

#ifdef FEATURE_IPOE_HEALTH_CHECK
    if(p_VirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_IHC &&
       p_VirtIf->IP.ConnectivityCheckRunning == TRUE &&
       pWanIfaceCtrl->IhcPid > 0 &&
      (WanMgr_IsPIDRunning(pWanIfaceCtrl->IhcPid) != TRUE)) 
    {
        WanMgr_StartConnectivityCheck(pWanIfaceCtrl);
        if(pWanIfaceCtrl->IhcV4Status == IHC_STARTED)
        {
            pWanIfaceCtrl->IhcV4Status = IHC_STOPPED; //Reset status falg to start 
            WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV4 , TRUE);
        }

        if(pWanIfaceCtrl->IhcV6Status == IHC_STARTED)
        {
            pWanIfaceCtrl->IhcV6Status = IHC_STOPPED; //Reset status falg to start 
            WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
        }
        CcspTraceInfo(("%s %d - SELFHEAL - Started ipoe_health_check  on interface %s, pid %d \n", __FUNCTION__, __LINE__, p_VirtIf->Name, pWanIfaceCtrl->IhcPid));
    }
#endif
}

#if defined(FEATURE_464XLAT)
static XLAT_State_t xlat_state_get(void)
{
	char buf[BUFLEN_128];
	char status[BUFLEN_128]={0};
	

	if (syscfg_get(NULL, "xlat_status", status, sizeof(status))!=0)
	{
		if(strcmp(status,"up")==0)
		{
			CcspTraceInfo(("%s %d - 464 xlat is on\n", __FUNCTION__, __LINE__));
			return XLAT_ON;
		}
		else
		{
			CcspTraceInfo(("%s %d - 464 xlat is off\n", __FUNCTION__, __LINE__));
			return XLAT_OFF;
		}
	}else
	{
		return XLAT_OFF;
	}
}
#endif

/*
 * WanManager_ConfigureMarking() 
 * This function will Apply virtual Interface specific Qos Marking using Linux utils : Iproute2
 * QoS egress map setting is moved from VlanManager to here. This is because of the
 * difficulty in creating VlanManager's marking table dynamically from WanManager. 
 */
static ANSC_STATUS WanManager_ConfigureMarking(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    char command[256] = {0};
    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    /* QoS egress map setting is moved from VlanManager to here. This is because of the */
    /* difficulty in creating VlanManager's marking table dynamically from WanManager.  */
    for(int Markingid=0; Markingid < p_VirtIf->VLAN.NoOfMarkingEntries; Markingid++)
    {
        DML_VIRTIF_MARKING* p_virtMarking = WanMgr_getVirtMakingById(p_VirtIf->VLAN.VirtMarking, Markingid);
        CcspTraceInfo(("%s %d Applying Interface Marking Entry %d\n", __FUNCTION__, __LINE__,p_virtMarking->Entry));
        /* Get Interface Marking Entry */
        PSINGLE_LINK_ENTRY  pSListEntry = AnscSListGetEntryByIndex(&(pInterface->Marking.MarkingList), p_virtMarking->Entry);
        if ( pSListEntry )
        {
            DML_MARKING* p_WanIfMarking = (ACCESS_CONTEXT_MARKING_LINK_OBJECT(pSListEntry))->hContext;
            memset(command, 0, sizeof(command));
            snprintf(command, sizeof(command), "ip link set %s type vlan egress-qos-map %d:%d", p_VirtIf->Name, p_WanIfMarking->SKBMark, p_WanIfMarking->EthernetPriorityMark);
            WanManager_DoSystemAction("Apply QOS marking:", command);

        }
    }
    return ANSC_STATUS_SUCCESS;
}

/*********************************************************************************/
/**************************** ACTIONS ********************************************/
/*********************************************************************************/
void WanManager_UpdateInterfaceStatus(DML_VIRTUAL_IFACE* pVirtIf, wanmgr_iface_status_t iface_status)
{
    CcspTraceInfo(("ifName: %s, link: %s, ipv4: %s, ipv6: %s\n", ((pVirtIf != NULL) ? pVirtIf->Name : "NULL"),
                   ((iface_status == WANMGR_IFACE_LINK_UP) ? "UP" : (iface_status == WANMGR_IFACE_LINK_DOWN) ? "DOWN" : "N/A"),
                   ((iface_status == WANMGR_IFACE_CONNECTION_UP) ? "UP" : (iface_status == WANMGR_IFACE_CONNECTION_DOWN) ? "DOWN" : "N/A"),
                   ((iface_status == WANMGR_IFACE_CONNECTION_IPV6_UP) ? "UP" : (iface_status == WANMGR_IFACE_CONNECTION_IPV6_DOWN) ? "DOWN" : "N/A")
                ));

    if(pVirtIf == NULL)
    {
        return;
    }

    switch (iface_status)
    {
        case WANMGR_IFACE_LINK_UP:
        {
            break;
        }
        case WANMGR_IFACE_LINK_DOWN:
        {
            break;
        }
        case WANMGR_IFACE_CONNECTION_UP:
        {
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
            /*Set Generic sysevents only if Interface is active. Else will be configured by ISM when interface is selected. */
            if(pVirtIf->Status == WAN_IFACE_STATUS_UP) 
            {
                if (pVirtIf->IP.Ipv4Data.isTimeOffsetAssigned)
                {
                    char value[64] = {0};
                    snprintf(value, sizeof(value), "@%d", pVirtIf->IP.Ipv4Data.timeOffset);
                    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV4_TIME_OFFSET, value, 0);
                    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCPV4_TIME_OFFSET, SET, 0);
                }

                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV4_TIME_ZONE, pVirtIf->IP.Ipv4Data.timeZone, 0);
            }
#endif
            WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_IPv4_UP);	    
            pVirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_UP;
            break;
        }
        case WANMGR_IFACE_CONNECTION_DOWN:
        {
            WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_ERROR_IPv4_DOWN);		
            pVirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_DOWN;
            pVirtIf->IP.Ipv4Changed = FALSE;
            pVirtIf->IP.Ipv4Renewed = FALSE;
            strncpy(pVirtIf->IP.Ipv4Data.ip, "", sizeof(pVirtIf->IP.Ipv4Data.ip));
            break;
        }
        case WANMGR_IFACE_CONNECTION_IPV6_UP:
        {
            WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_IPv6_UP);		
            pVirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_UP;
            break;
        }
        case WANMGR_IFACE_CONNECTION_IPV6_DOWN:
        {
            WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_ERROR_IPv6_DOWN);
            WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_ERROR_MAPT_STATUS_DOWN);		
            pVirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_DOWN;
            pVirtIf->IP.Ipv6Changed = FALSE;
            pVirtIf->IP.Ipv6Renewed = FALSE;
            pVirtIf->MAP.MaptStatus = WAN_IFACE_MAPT_STATE_DOWN;     // reset MAPT flag
            pVirtIf->MAP.MaptChanged = FALSE;                        // reset MAPT flag
            strncpy(pVirtIf->IP.Ipv6Data.address, "", sizeof(pVirtIf->IP.Ipv6Data.address));
            strncpy(pVirtIf->IP.Ipv6Data.pdIfAddress, "", sizeof(pVirtIf->IP.Ipv6Data.pdIfAddress));
            strncpy(pVirtIf->IP.Ipv6Data.sitePrefix, "", sizeof(pVirtIf->IP.Ipv6Data.sitePrefix));
            strncpy(pVirtIf->IP.Ipv6Data.nameserver, "", sizeof(pVirtIf->IP.Ipv6Data.nameserver));
            strncpy(pVirtIf->IP.Ipv6Data.nameserver1, "", sizeof(pVirtIf->IP.Ipv6Data.nameserver1));
            wanmgr_sysevents_ipv6Info_init(); // reset the sysvent/syscfg fields
            break;
        }
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
        case WANMGR_IFACE_MAPT_START:
        {
            WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_MAPT_STATUS_UP);		
            pVirtIf->MAP.MaptStatus = WAN_IFACE_MAPT_STATE_UP;
            CcspTraceInfo(("mapt: %s \n",
                   ((iface_status == WANMGR_IFACE_MAPT_START) ? "UP" : (iface_status == WANMGR_IFACE_MAPT_STOP) ? "DOWN" : "N/A")));

            break;
        }
        case WANMGR_IFACE_MAPT_STOP:
        {
            WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_ERROR_MAPT_STATUS_DOWN);		
            pVirtIf->MAP.MaptStatus = WAN_IFACE_MAPT_STATE_DOWN;     // reset MAPT flag
            pVirtIf->MAP.MaptChanged = FALSE;                        // reset MAPT flag
            CcspTraceInfo(("mapt: %s \n",
                   ((iface_status == WANMGR_IFACE_MAPT_START) ? "UP" : (iface_status == WANMGR_IFACE_MAPT_STOP) ? "DOWN" : "N/A")));

            break;
        }
#endif
        default:
            /* do nothing */
            break;
    }

    return;
}


int wan_updateDNS(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl, BOOL addIPv4, BOOL addIPv6)
{

    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        CcspTraceError(("%s %d - Invalid args \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    DEVICE_NETWORKING_MODE deviceMode = pWanIfaceCtrl->DeviceNwMode;
    DML_WAN_IFACE * pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)) //TODO:  XB devices use the DNS of primary for backup.
    if(strstr(pInterface->AliasName, "REMOTE"))
    {
        CcspTraceError(("%s %d - Not updating DNS of the remote interface \n", __FUNCTION__, __LINE__));
        return RETURN_OK;
    }
#endif
    bool valid_dns = FALSE;
    int ret = RETURN_OK;
    FILE *fp = NULL;
    char syseventParam[BUFLEN_128]={0};

    char v4nameserver1[BUFLEN_64];
    char v4nameserver2[BUFLEN_64];
    char v6nameserver1[BUFLEN_128];
    char v6nameserver2[BUFLEN_128]; 
    bool resolv_conf_changed = FALSE;

    if (deviceMode == GATEWAY_MODE)
    {
        if((fp = fopen(RESOLV_CONF_FILE, "w+")) == NULL)
        {
            CcspTraceError(("%s %d - Open %s error!\n", __FUNCTION__, __LINE__, RESOLV_CONF_FILE));
            return RETURN_ERR;
        }
    }

    // save the current configured nameserver address
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_PRIMARY, v4nameserver1, sizeof(v4nameserver1));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_SECONDARY, v4nameserver2, sizeof(v4nameserver2));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_PRIMARY, v6nameserver1, sizeof(v6nameserver1));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_SECONDARY, v6nameserver2, sizeof(v6nameserver2));

    CcspTraceInfo(("%s %d: v4nameserver1 = %s v4nameserver2 = %s\n", __FUNCTION__, __LINE__, v4nameserver1, v4nameserver2));
    CcspTraceInfo(("%s %d: v6nameserver1 = %s v6nameserver2 = %s\n", __FUNCTION__, __LINE__, v6nameserver1, v6nameserver2));

    if (addIPv4 == FALSE && addIPv6 == FALSE)
    {
        // No WAN connectivity
        // clear all DNS sysevents
        snprintf(syseventParam, sizeof(syseventParam), SYSEVENT_IPV4_WANIFNAME_DNS_PRIMARY, p_VirtIf->Name);
        sysevent_set(sysevent_fd, sysevent_token, syseventParam, "", 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_PRIMARY, "", 0);

        snprintf(syseventParam, sizeof(syseventParam), SYSEVENT_IPV4_WANIFNAME_DNS_SECONDARY, p_VirtIf->Name);
        sysevent_set(sysevent_fd, sysevent_token, syseventParam, "", 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_SECONDARY, "", 0);

        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_PRIMARY, "", 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_SECONDARY, "", 0);

        if (fp != NULL)
        {
            CcspTraceError(("%s %d - No valid nameserver is available, adding loopback address for nameserver\n", __FUNCTION__,__LINE__));
            fprintf(fp, "nameserver %s \n", LOOPBACK);
            fclose(fp);
            Update_Interface_Status();
        }
        // new and curr nameservers are different, so apply configuration
        CcspTraceInfo(("%s %d: Setting %s\n", __FUNCTION__, __LINE__, SYSEVENT_DHCP_SERVER_RESTART));
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCP_SERVER_RESTART, NULL, 0);
        return RETURN_OK;
    }

    if (addIPv4)
    {
        snprintf(syseventParam, sizeof(syseventParam), SYSEVENT_IPV4_WANIFNAME_DNS_PRIMARY, p_VirtIf->Name);

        // v4 DNS1
        if(IsValidDnsServer(AF_INET, p_VirtIf->IP.Ipv4Data.dnsServer) == RETURN_OK)
        {
            // v4 DNS1 is a valid
            if (fp != NULL)
            {
                // GATEWAY Mode
                CcspTraceInfo(("%s %d: adding nameserver %s >> %s\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv4Data.dnsServer, RESOLV_CONF_FILE));
                fprintf(fp, "nameserver %s\n", p_VirtIf->IP.Ipv4Data.dnsServer);
	            resolv_conf_changed = TRUE;
            }
            sysevent_set(sysevent_fd, sysevent_token, syseventParam, p_VirtIf->IP.Ipv4Data.dnsServer, 0);
            CcspTraceInfo(("%s %d: new v4 DNS Server = %s\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv4Data.dnsServer));
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_PRIMARY, p_VirtIf->IP.Ipv4Data.dnsServer, 0);
            valid_dns = TRUE;
        }
        else
        {
            // v4 DNS1 is a invalid
            sysevent_set(sysevent_fd, sysevent_token, syseventParam, "", 0);
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_PRIMARY, "", 0);
        }

        // v4 DNS2
        snprintf(syseventParam, sizeof(syseventParam), SYSEVENT_IPV4_WANIFNAME_DNS_SECONDARY, p_VirtIf->Name);
        if(IsValidDnsServer(AF_INET, p_VirtIf->IP.Ipv4Data.dnsServer1) == RETURN_OK)
        {
            // v4 DNS2 is a valid
            if (fp != NULL)
            {
                // GATEWAY Mode
                CcspTraceInfo(("%s %d: adding nameserver %s >> %s\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv4Data.dnsServer1, RESOLV_CONF_FILE));
                fprintf(fp, "nameserver %s\n", p_VirtIf->IP.Ipv4Data.dnsServer1);
	            resolv_conf_changed = TRUE;
            }
            CcspTraceInfo(("%s %d: new v4 DNS Server = %s\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv4Data.dnsServer1));
            sysevent_set(sysevent_fd, sysevent_token, syseventParam, p_VirtIf->IP.Ipv4Data.dnsServer1, 0);
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_SECONDARY, p_VirtIf->IP.Ipv4Data.dnsServer1, 0);
            if (valid_dns == TRUE)
            {
                snprintf(syseventParam, sizeof(syseventParam), SYSEVENT_IPV4_DNS_NUMBER, p_VirtIf->Name);
                sysevent_set(sysevent_fd, sysevent_token, syseventParam, SYSEVENT_IPV4_NO_OF_DNS_SUPPORTED, 0);
            }
            valid_dns = TRUE;
        }
        else
        {
            // v4 DNS2 is a invalid
            sysevent_set(sysevent_fd, sysevent_token, syseventParam, "", 0);
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_SECONDARY, "", 0);
        }
    }
    else
    {
        snprintf(syseventParam, sizeof(syseventParam), SYSEVENT_IPV4_WANIFNAME_DNS_PRIMARY, p_VirtIf->Name);
        sysevent_set(sysevent_fd, sysevent_token, syseventParam, "", 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_PRIMARY, "", 0);

        snprintf(syseventParam, sizeof(syseventParam), SYSEVENT_IPV4_WANIFNAME_DNS_SECONDARY, p_VirtIf->Name);
        sysevent_set(sysevent_fd, sysevent_token, syseventParam, "", 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV4_DNS_SECONDARY, "", 0);
    }

    if (addIPv6)
    {
        // v6 DNS1
        if(IsValidDnsServer(AF_INET6, p_VirtIf->IP.Ipv6Data.nameserver) == RETURN_OK)
        {
            // v6 DNS1 is valid
            if (fp != NULL)
            {
                // GATEWAY Mode
                CcspTraceInfo(("%s %d: adding nameserver %s >> %s\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv6Data.nameserver, RESOLV_CONF_FILE));
                fprintf(fp, "nameserver %s\n", p_VirtIf->IP.Ipv6Data.nameserver);
        		resolv_conf_changed = TRUE;
            }
            CcspTraceInfo(("%s %d: new v6 DNS Server = %s\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv6Data.nameserver));
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_PRIMARY, p_VirtIf->IP.Ipv6Data.nameserver, 0);
            valid_dns = TRUE;
        }
        else
        {
            // v6 DNS1 is invalid
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_PRIMARY, "", 0);
        }

        // v6 DNS2
        if(IsValidDnsServer(AF_INET6, p_VirtIf->IP.Ipv6Data.nameserver1) == RETURN_OK)
        {
            // v6 DNS2 is valid
            if (fp != NULL)
            {
                CcspTraceInfo(("%s %d: adding nameserver %s >> %s\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv6Data.nameserver1, RESOLV_CONF_FILE));
                fprintf(fp, "nameserver %s\n", p_VirtIf->IP.Ipv6Data.nameserver1);
		        resolv_conf_changed = TRUE;
            }
            CcspTraceInfo(("%s %d: new v6 DNS Server = %s\n", __FUNCTION__, __LINE__, p_VirtIf->IP.Ipv6Data.nameserver1));
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_SECONDARY, p_VirtIf->IP.Ipv6Data.nameserver1, 0);
            valid_dns = TRUE;
        }
        else
        {
            // v6 DNS2 is invalid
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_SECONDARY, "", 0);
        }
    }
    else
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_PRIMARY, "", 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DNS_SECONDARY, "", 0);
    }


    if ( strcmp(p_VirtIf->IP.Ipv4Data.dnsServer, v4nameserver1) || strcmp(p_VirtIf->IP.Ipv4Data.dnsServer1, v4nameserver2)
        || strcmp(p_VirtIf->IP.Ipv6Data.nameserver, v6nameserver1) || strcmp (p_VirtIf->IP.Ipv6Data.nameserver1, v6nameserver2))
    {
        // new and curr nameservers are differen, so apply configuration
        CcspTraceInfo(("%s %d: Setting %s\n", __FUNCTION__, __LINE__, SYSEVENT_DHCP_SERVER_RESTART));
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCP_SERVER_RESTART, NULL, 0);
    }
    else
    {
        CcspTraceInfo(("%s %d: No change not Setting %s\n", __FUNCTION__, __LINE__, SYSEVENT_DHCP_SERVER_RESTART));
    }

    if (valid_dns == TRUE)
    {
        CcspTraceInfo(("%s %d - Active domainname servers set!\n", __FUNCTION__,__LINE__));
    }
    else
    {
        CcspTraceError(("%s %d - No valid nameserver is available, adding loopback address for nameserver\n", __FUNCTION__,__LINE__));
        if (fp != NULL)
        {
            fprintf(fp, "nameserver %s \n", LOOPBACK);
    	    resolv_conf_changed = TRUE;
        }
    }
    if (fp != NULL)
    {
        fclose(fp);
    }

    if(resolv_conf_changed)
    {
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_))
        //TODO: this is a workaround for the devices using the primary DNS for the backup interfaces. CurrentActiveDNS may not have the right value. 
        WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
        if (pWanConfigData != NULL)
        {
            DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);
            memset(pWanDmlData->CurrentActiveDNS, 0, sizeof(pWanDmlData->CurrentActiveDNS));
            WanMgrDml_GetConfigData_release(pWanConfigData);
        }
#endif
        Update_Interface_Status();
    }

    return ret;
}

/* Check Duplicate Address Detection (DAD) status. The way it works is that
   after an address is added to an interface, the operating system uses the
   Neighbor Discovery Protocol to check if any other host on the network
   has the same address. The whole process will take around 3 to 4 seconds
   to complete. Also we need to check and ensure that the gateway has
   a valid default route entry.
 */
static int checkIpv6LanAddressIsReadyToUse(DML_VIRTUAL_IFACE* p_VirtIf)
{
    char buffer[BUFLEN_256] = {0};
    FILE *fp_dad   = NULL;
    FILE *fp_route = NULL;
    int dad_flag       = 0;
    int route_flag     = 0;
    int i;
    char IfaceName[BUFLEN_16] = {0};
    int BridgeMode = 0;

    { //TODO : temporary debug code to identify the bridgemode sysevent failure issue.
        char Output[BUFLEN_16] = {0};
        if (sysevent_get(sysevent_fd, sysevent_token, "bridge_mode", Output, sizeof(Output)) !=0)
        {
            CcspTraceError(("%s-%d: bridge_mode sysevent get failed. \n", __FUNCTION__, __LINE__));
        }
        BridgeMode = atoi(Output);
        CcspTraceInfo(("%s-%d: <<DEBUG>> bridge_mode sysevent value set to =%d \n", __FUNCTION__, __LINE__,  BridgeMode));
    }
     /*TODO:
     *Below Code should be removed once V6 Prefix/IP is assigned on erouter0 Instead of brlan0 for sky Devices.
     */
    strncpy(IfaceName, ETH_BRIDGE_NAME, sizeof(IfaceName)-1);
    if (WanMgr_isBridgeModeEnabled() == TRUE)
    {
        CcspTraceInfo(("%s-%d: Device is in bridge mode. Assigning IPv6 address on WAN interface.\n", __FUNCTION__, __LINE__));
        memset(IfaceName, 0, sizeof(IfaceName));
        strncpy(IfaceName, p_VirtIf->Name, sizeof(IfaceName)-1);
    }
    CcspTraceInfo(("%s-%d: IfaceName=%s, BridgeMode=%d \n", __FUNCTION__, __LINE__, IfaceName, BridgeMode));

    /* TODO: the below code assumes if the LAN ipv6 address is tentaive for 15 seconds DAD has failed. Do we need additional check?
     * IANA dad is handled in the DHCPv6 client for the Wan Interface.
     * Should we remove the IP from LAN bridge and request a different Delegated prefix?
     * Should we use EUI-64 based Interface identifiers for all platforms?
     */

    for(i=0; i<15; i++) 
    {
        buffer[0] = '\0';
        if(dad_flag == 0) 
        {
            if ((fp_dad = v_secure_popen("r","ip address show dev %s tentative", IfaceName))) 
            {
                if(fp_dad != NULL) 
                {
                    fgets(buffer, BUFLEN_256, fp_dad);
                    if(strlen(buffer) == 0 ) 
                    {
                        dad_flag = 1;
                    }
                    v_secure_pclose(fp_dad);
                }
            }
        }

        if(dad_flag == 0) 
        {
            sleep(1);
        }
        else 
        {
            break;
        }
    }

    buffer[0] = '\0';
    if ((fp_route = popen("ip -6 ro | grep default", "r"))) {
        if(fp_route != NULL) {
            fgets(buffer, BUFLEN_256, fp_route);
            if(strlen(buffer) > 0 ) {
                route_flag = 1;
            }
            pclose(fp_route);
        }
    }

    //if DAD failed on LAN bridge, log an ERROR message and continue with the WAN process.
    if(dad_flag == 0 || route_flag == 0) 
    {
        CcspTraceError(("%s %d dad_flag[%d] route_flag[%d] Failed \n", __FUNCTION__, __LINE__,dad_flag,route_flag));
    }

    if(route_flag == 0)
    {
        //If the default route is not present, Send a router solicit.
        WanManager_send_and_receive_rs(p_VirtIf);
        return -1;
    }

    return 0;
}

static void updateInterfaceToVoiceManager(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl, bool voip_started)
{
    ANSC_STATUS retStatus        = ANSC_STATUS_FAILURE;
    bool isUpdate                = false;
    char voipIfName[IF_SIZE]     = {0};

    if((NULL == pWanIfaceCtrl) || (NULL == pWanIfaceCtrl->pIfaceData))
    {
        CcspTraceWarning(("%s %d Invalid function parameter \n",__FUNCTION__, __LINE__));
        return;
    }

    DML_WAN_IFACE* pWanIfaceData = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (0 == strcmp("VOIP", p_VirtIf->Alias))
    {
        /* Update VOIP vlan name to TelcoVoiceManager */
        isUpdate = true;

	// Update the Interface name after auto wan sesning is complete.
        // When interface is down (due to cable removal etc) set Interface name to empty string
        if (voip_started)
            strncpy(voipIfName, p_VirtIf->Name, sizeof(voipIfName));
    }
    else if(0 == strcmp("DATA", p_VirtIf->Alias))
    {
        isUpdate = true;

        // Update the Interface name after auto wan sesning is complete.
        // When interface is down (due to cable removal etc) set Interface name to empty string
        if (voip_started)
            strncpy(voipIfName, p_VirtIf->Name, sizeof(voipIfName));

        /* If there is a VOIP interface present, then do not update DATA vlan name to TelecoVoiceManager. */
        for(int virIf_id=0; virIf_id< pWanIfaceData->NoOfVirtIfs; virIf_id++)
        {
            DML_VIRTUAL_IFACE* VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceData->VirtIfList, virIf_id);

            if (0 == strcmp("VOIP", VirtIf->Alias))
            {
                isUpdate = false;
                break;
            }
        }
    }
    else
    {
        isUpdate = false;
        CcspTraceWarning(("%s %d Invalid Virtual Interface Alias[%s] \n",__FUNCTION__, __LINE__, p_VirtIf->Alias));
    }

    if (true == isUpdate)
    {

        /* Set X_RDK_BoundIfName of TelcoVoiceManager */
        retStatus = WanMgr_RdkBus_SetParamValues(VOICE_COMPONENT_NAME, VOICE_DBUS_PATH, VOICE_BOUND_IF_NAME, voipIfName, ccsp_string, TRUE);
        if (ANSC_STATUS_SUCCESS == retStatus)
        {
            CcspTraceInfo(("%s %d - Successfully set [%s] to VoiceManager \n", __FUNCTION__, __LINE__, voipIfName));
        }
        else
        {
            CcspTraceInfo(("%s %d - Failed setting [%s] to VoiceManager \n", __FUNCTION__, __LINE__, voipIfName));
        }
    }
}

static int wan_deconfigIPv4onInterface(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl)
{
    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        CcspTraceError(("%s %d - Invalid args \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    int ret = RETURN_OK;
    char cmdStr[BUFLEN_256] = {0}; 

    DML_WAN_IFACE * pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

#ifdef LTE_USB_FEATURE_ENABLED
    if( 0 != strcmp(p_VirtIf->Name, "usb0" ) )
#endif /** LTE_USB_FEATURE_ENABLED */
    {
        /* Need to remove the network from the routing table by
        * doing "ifconfig L3IfName 0.0.0.0"
        * wanData->ipv4Data.ifname is Empty.
        */
        snprintf(cmdStr, sizeof(cmdStr), "ifconfig %s 0.0.0.0", p_VirtIf->Name);
        if (WanManager_DoSystemActionWithStatus("wan_deconfigIPv4onInterface: ifconfig L3IfName 0.0.0.0", (cmdStr)) != 0)
        {
            CcspTraceError(("%s %d - failed to run cmd: %s", __FUNCTION__, __LINE__, cmdStr));
            ret = RETURN_ERR;
        }
    }
    return ret;
}

static int wan_setUpIPv4(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl)
{

    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        CcspTraceError(("%s %d - Invalid args \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    int ret = RETURN_OK;
    char cmdStr[BUFLEN_128 + IP_ADDR_LENGTH] = {0};
    char bCastStr[IP_ADDR_LENGTH] = {0};
    char buf[BUFLEN_32] = {0};

    DEVICE_NETWORKING_MODE DeviceNwMode = pWanIfaceCtrl->DeviceNwMode;
    DML_WAN_IFACE * pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

     if (wanmgr_set_Ipv4Sysevent(&p_VirtIf->IP.Ipv4Data, pWanIfaceCtrl->DeviceNwMode) != ANSC_STATUS_SUCCESS)
     {
         CcspTraceError(("%s %d - Could not store ipv4 data!", __FUNCTION__, __LINE__));
     }

    /** configure DNS */
    if (RETURN_OK != wan_updateDNS(pWanIfaceCtrl, TRUE, (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)))
    {
        CcspTraceError(("%s %d - Failed to configure IPv4 DNS servers \n", __FUNCTION__, __LINE__));
        ret = RETURN_ERR;
    }
    else
    {
        CcspTraceInfo(("%s %d -  IPv4 DNS servers configures successfully \n", __FUNCTION__, __LINE__));
    }

        /** Set default gatway. */
    if (WanManager_AddDefaultGatewayRoute(DeviceNwMode, &p_VirtIf->IP.Ipv4Data) != RETURN_OK)
    {
        CcspTraceError(("%s %d - Failed to set up default system gateway", __FUNCTION__, __LINE__));
        ret = RETURN_ERR;
    }

    /** Update required sysevents. */

    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV4_CONNECTION_STATE, WAN_STATUS_UP, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_IPV4_LINK_STATE, WAN_STATUS_UP, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IPADDR, p_VirtIf->IP.Ipv4Data.ip, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_SUBNET, p_VirtIf->IP.Ipv4Data.mask, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_STATE, WAN_STATUS_UP, 0);

    char syseventParam[BUFLEN_128] = {0};

    snprintf(syseventParam, sizeof(syseventParam), "%u", WanManager_getUpTime());
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_START_TIME, syseventParam, 0);

    //Enabling IP forwarding 
    CcspTraceInfo(("%s %d - net.ipv4.ip_forward set to 1 \n", __FUNCTION__, __LINE__));
    v_secure_system("sysctl -w net.ipv4.ip_forward=1");

    if (strstr(pInterface->BaseInterface, "Ethernet"))
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_ETHWAN_INITIALIZED, "1", 0);
    }
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, buf, sizeof(buf));
    //TODO: Firewall IPv6 FORWARD rules are not working if SYSEVENT_WAN_SERVICE_STATUS is set for REMOTE_IFACE. Modify firewall similar for backup interface similar to primary.
    if (strcmp(buf, WAN_STATUS_STARTED) && pInterface->IfaceType != REMOTE_IFACE)
    {
        int  uptime = 0;
        char buffer[64] = {0};

        /*TODO: touch /var/wan_started for wan-initialized.path in systemd and register /etc/utopia/post.d/. 
         *This is a comcast specific configuration, should be removed from Wan state machine */
        v_secure_system("touch /var/wan_started");
        /* Register services from /etc/utopia/post.d/ if not registered.*/
        if (access(POSTD_START_FILE, F_OK) != 0)
        {
            CcspTraceInfo(("%s %d - Starting post.d from WanManager\n", __FUNCTION__, __LINE__));
            v_secure_system("touch " POSTD_START_FILE "; execute_dir /etc/utopia/post.d/");
        }

        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, WAN_STATUS_STARTED, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, WAN_STATUS_STARTED, 0);
        CcspTraceInfo(("%s %d - wan-status event set to started \n", __FUNCTION__, __LINE__));

        if(p_VirtIf->IP.Ipv4Data.ifname[0] != '\0' && pInterface->IfaceType != REMOTE_IFACE && (WAN_IFACE_CONN_TYPE_COLD_STANDBY != pInterface->IfaceConnectionType))
        {
            syscfg_set_commit(NULL, SYSCFG_WAN_INTERFACE_NAME, p_VirtIf->IP.Ipv4Data.ifname);
        }
        wanmgr_services_restart();
        //Get WAN uptime
        WanManager_GetDateAndUptime( buffer, &uptime );
        LOG_CONSOLE("%s [tid=%ld] v4: Wan_init_complete for interface index %d at %d\n", buffer, syscall(SYS_gettid), pWanIfaceCtrl->interfaceIdx, uptime);

        WanManager_PrintBootEvents (WAN_INIT_COMPLETE);
    }

#if defined(_DT_WAN_Manager_Enable_)
    wanmgr_setSharedCGNAddress(p_VirtIf->IP.Ipv4Data.ip);
#endif
    /* Firewall restart. */
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
    WanMgr_StartConnectivityCheck(pWanIfaceCtrl);
    return ret;
}


static int wan_tearDownIPv4(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl)
{
    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        CcspTraceError(("%s %d - Invalid args \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    int ret = RETURN_OK;
    char cmdStr[BUFLEN_64] = {0};
    char buf[BUFLEN_32] = {0};

    DEVICE_NETWORKING_MODE DeviceNwMode = pWanIfaceCtrl->DeviceNwMode;
    DML_WAN_IFACE * pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    /** Reset IPv4 DNS configuration. */
#if (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_))
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
    WanMgr_Config_Data_t    *pWanConfigData = WanMgr_GetConfigData_locked();
    unsigned char           BackupWanDnsSupport = TRUE;

    if( NULL != pWanConfigData )
    {
        BackupWanDnsSupport = pWanConfigData->data.BackupWanDnsSupport;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    if ( ( FALSE == BackupWanDnsSupport ) && 
         (p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP && strstr(pInterface->BaseInterface, "Ethernet") == NULL) )
#else
    //TODO:  XB devices use the DNS of primary for backup interfaces. Clear V4 DNS only if MAPT is up
    /* FIXME: Issue in DNS ipv6 resolution when ethwan enabled *//* Workaround: We keep the ipv4 entries for name resolution */
    if(p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP && strstr(pInterface->BaseInterface, "Ethernet") == NULL)
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */ 
#endif
    {
        if (RETURN_OK != wan_updateDNS(pWanIfaceCtrl, FALSE, (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)))
        {
            CcspTraceError(("%s %d - Failed to unconfig IPv4 DNS servers \n", __FUNCTION__, __LINE__));
            ret = RETURN_ERR;
        }
        else
        {
            CcspTraceInfo(("%s %d -  IPv4 DNS servers unconfig successfully \n", __FUNCTION__, __LINE__));
        }   
    }

    if (WanManager_DelDefaultGatewayRoute(DeviceNwMode, pWanIfaceCtrl->DeviceNwModeChanged, &p_VirtIf->IP.Ipv4Data) != RETURN_OK)
    {
        CcspTraceError(("%s %d - Failed to Del default system gateway", __FUNCTION__, __LINE__));
        ret = RETURN_ERR;
    }

    /* ReSet the required sysevents. */
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV4_CONNECTION_STATE, WAN_STATUS_DOWN, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_IPV4_LINK_STATE, WAN_STATUS_DOWN, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_STATE, WAN_STATUS_DOWN, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_START_TIME, "0", 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IPADDR, "0.0.0.0", 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_SUBNET, "255.255.255.0", 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
    if (strstr(pInterface->BaseInterface, "Ethernet"))
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_ETHWAN_INITIALIZED, "0", 0);
    }

    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, buf, sizeof(buf));
    if ((strcmp(buf, WAN_STATUS_STOPPED) != 0) && (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_DOWN))
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, WAN_STATUS_STOPPED, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, WAN_STATUS_STOPPED, 0);
        CcspTraceInfo(("%s %d - wan-status event set to stopped \n", __FUNCTION__, __LINE__));
    }

    return ret;
}

static int wan_setUpIPv6(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl)
{

    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        CcspTraceError(("%s %d - Invalid args \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    int ret = RETURN_OK;
    char buf[BUFLEN_128] = {0};

    DML_WAN_IFACE * pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pInterface == NULL)
    {
        CcspTraceError(("%s %d - Invalid memory \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    /** Reset IPv6 DNS configuration. */
    if (wan_updateDNS(pWanIfaceCtrl, (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP), TRUE) != RETURN_OK)
    {
        CcspTraceError(("%s %d - Failed to configure IPv6 DNS servers \n", __FUNCTION__, __LINE__));
        ret = RETURN_ERR;
    }
    else
    {
        CcspTraceInfo(("%s %d -  IPv6 DNS servers configured successfully \n", __FUNCTION__, __LINE__));
    }
    
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_STATUS, WAN_STATUS_UP, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN6_IP_ADDRESS, p_VirtIf->IP.Ipv6Data.address, 0);
    snprintf(buf, sizeof(buf), "%s %s", p_VirtIf->IP.Ipv6Data.nameserver, p_VirtIf->IP.Ipv6Data.nameserver1);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_NS, buf, 0);
    if(p_VirtIf->IP.Ipv6Data.ipv6_TimeOffset)
    {
        snprintf(buf, sizeof(buf), "%d", p_VirtIf->IP.Ipv6Data.ipv6_TimeOffset);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_TIME_OFFSET, buf, 0);
    }

    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_CONNECTION_STATE, WAN_STATUS_UP, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_RADVD_RESTART, NULL, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCP_SERVER_RESTART, NULL, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, buf, sizeof(buf));

    //TODO: Firewall IPv6 FORWARD rules are not working if SYSEVENT_WAN_SERVICE_STATUS is set for REMOTE_IFACE. Modify firewall similar for backup interface similar to primary.
    if (strcmp(buf, WAN_STATUS_STARTED)&& pInterface->IfaceType != REMOTE_IFACE)
    {
        /*TODO: touch /var/wan_started for wan-initialized.path in systemd and register /etc/utopia/post.d/. 
         *This is a comcast specific configuration, should be removed from Wan state machine */
        v_secure_system("touch /var/wan_started");
        /* Register services from /etc/utopia/post.d/ if not registered.*/
        if (access(POSTD_START_FILE, F_OK) != 0)
        {
            CcspTraceInfo(("%s %d - Starting post.d from WanManager\n", __FUNCTION__, __LINE__));
            v_secure_system("touch " POSTD_START_FILE "; execute_dir /etc/utopia/post.d/");
        }

        int  uptime = 0;
        char buffer[64] = {0};
        char ifaceMacAddress[BUFLEN_128] = {0};
        char buf[BUFLEN_128] = {0};

        //Get WAN uptime
        WanManager_GetDateAndUptime( buffer, &uptime );
        LOG_CONSOLE("%s [tid=%ld] v6: Wan_init_complete for interface index %d at %d\n", buffer, syscall(SYS_gettid), pWanIfaceCtrl->interfaceIdx, uptime);

        WanManager_PrintBootEvents (WAN_INIT_COMPLETE);

        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, WAN_STATUS_STARTED, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, WAN_STATUS_STARTED, 0);



        CcspTraceInfo(("%s %d - wan-status event set to started \n", __FUNCTION__, __LINE__));

        /* Set the current WAN Interface name */
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, p_VirtIf->IP.Ipv6Data.ifname, 0);
        if(p_VirtIf->IP.Ipv6Data.ifname[0] != '\0' && pInterface->IfaceType != REMOTE_IFACE && (WAN_IFACE_CONN_TYPE_COLD_STANDBY != pInterface->IfaceConnectionType) )
        {
            syscfg_set_commit(NULL, SYSCFG_WAN_INTERFACE_NAME, p_VirtIf->IP.Ipv6Data.ifname);
        }
        wanmgr_services_restart();

#if (!defined (_XB6_PRODUCT_REQ_) && !defined (_CBR2_PRODUCT_REQ_) && !defined(_PLATFORM_RASPBERRYPI_)) || defined (_RDKB_GLOBAL_PRODUCT_REQ_) //parodus uses cmac for xb platforms
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
    WanMgr_Config_Data_t    *pWanConfigData = WanMgr_GetConfigData_locked();
    unsigned char           UseWANMACForManagementServices = FALSE;

    if( NULL != pWanConfigData )
    {
        UseWANMACForManagementServices = pWanConfigData->data.UseWANMACForManagementServices;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    if ( TRUE == UseWANMACForManagementServices )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
    {
        // set wan mac because parodus depends on it to start.
        if(ANSC_STATUS_SUCCESS == WanManager_get_interface_mac(p_VirtIf->IP.Ipv6Data.ifname, ifaceMacAddress, sizeof(ifaceMacAddress)))
        {
            CcspTraceInfo(("%s %d - setting sysevent eth_wan_mac = [%s]  \n", __FUNCTION__, __LINE__, ifaceMacAddress));
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_ETH_WAN_MAC, ifaceMacAddress, 0);
        }
    }
#endif
    }
  
    WanMgr_StartConnectivityCheck(pWanIfaceCtrl);
    return ret;
}

static int wan_tearDownIPv6(WanMgr_IfaceSM_Controller_t * pWanIfaceCtrl)
{

    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        CcspTraceError(("%s %d - Invalid args \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    int ret = RETURN_OK;
    char buf[BUFLEN_32] = {0};
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
    WanMgr_Config_Data_t    *pWanConfigData = NULL;
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */

    DML_WAN_IFACE * pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    //TODO: FIXME: XB devices use the DNS of primary for backup and doesn't deconfigure the primary ipv6 prefix from the LAN interface. 
#if (!(defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_))) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
    unsigned char BackupWanDnsSupport = TRUE;

    pWanConfigData = WanMgr_GetConfigData_locked();
    if( NULL != pWanConfigData )
    {
        BackupWanDnsSupport = pWanConfigData->data.BackupWanDnsSupport;
        WanMgrDml_GetConfigData_release(pWanConfigData);
        pWanConfigData = NULL;
    }

    if ( FALSE == BackupWanDnsSupport ) 
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
    {
        /** Reset IPv6 DNS configuration. */
        if (RETURN_OK == wan_updateDNS(pWanIfaceCtrl, (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP), FALSE))
        {
            CcspTraceInfo(("%s %d -  IPv6 DNS servers unconfig successfully \n", __FUNCTION__, __LINE__));
        }
        else
        {
            CcspTraceError(("%s %d - Failed to unconfig IPv6 DNS servers \n", __FUNCTION__, __LINE__));
            ret = RETURN_ERR;
        }
    }
#endif
    /** Unconfig IPv6. */
    if ( WanManager_Ipv6PrefixUtil(p_VirtIf->Name, DEL_ADDR,0,0) < 0)
    {
        AnscTraceError(("%s %d -  Failed to remove inactive address \n", __FUNCTION__,__LINE__));
    }

    //Remove the default route and IPv6 address explicitly
    char acCmdLine[BUFLEN_128] = {0};
    CcspTraceInfo(("%s %d -  Deleting IPv6 default route for '%s' interface\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
    snprintf(acCmdLine, sizeof(acCmdLine), "ip -6 route del default dev %s", p_VirtIf->Name);
    if (WanManager_DoSystemActionWithStatus("ip -6 route delete default", acCmdLine) != 0)
        CcspTraceError(("%s-%d Failed to run cmd: %s", __FUNCTION__, __LINE__, acCmdLine));

    CcspTraceInfo(("%s %d -  Deleting IPv6 global address route for '%s' interface\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
    memset(acCmdLine, 0, sizeof(acCmdLine));
    snprintf(acCmdLine, sizeof(acCmdLine), "ip -6 addr flush scope global dev %s", p_VirtIf->Name);
    if (WanManager_DoSystemActionWithStatus("ip -6 addr flush scope global dev", acCmdLine) != 0)
        CcspTraceError(("%s-%d Failed to run cmd: %s", __FUNCTION__, __LINE__, acCmdLine));

    // Reset sysvevents.
    char previousPrefix[BUFLEN_48] = {0};
    char previousPrefix_vldtime[BUFLEN_48] = {0};
    char previousPrefix_prdtime[BUFLEN_48] = {0};
    /* set ipv6 down sysevent notification. */
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIX, previousPrefix, sizeof(previousPrefix));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIXVLTIME, previousPrefix_vldtime, sizeof(previousPrefix_vldtime));
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIXPLTIME, previousPrefix_prdtime, sizeof(previousPrefix_prdtime));
    if (strncmp(previousPrefix, "", BUFLEN_48) != 0)
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIX, previousPrefix, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIXVLTIME, previousPrefix_vldtime, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIXPLTIME, previousPrefix_prdtime, 0);
    }
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIX, "", 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_TR_EROUTER_DHCPV6_CLIENT_PREFIX, "", 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_CONNECTION_STATE, WAN_STATUS_DOWN, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_GLOBAL_IPV6_PREFIX_SET, "", 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);

//RBUS_WAN_IP
#if defined (RBUS_WAN_IP)
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
    unsigned char ConfigureWANIPv6OnLANBridgeSupport = FALSE;

    pWanConfigData = WanMgr_GetConfigData_locked();
    if( NULL != pWanConfigData )
    {
        ConfigureWANIPv6OnLANBridgeSupport = pWanConfigData->data.ConfigureWANIPv6OnLANBridgeSupport;
        WanMgrDml_GetConfigData_release(pWanConfigData);
        pWanConfigData = NULL;
    }

    if ( TRUE == ConfigureWANIPv6OnLANBridgeSupport )
    {   
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_LAN_IPV6_ADDRESS, "::", 0);
    }
    else
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_WAN_ADDRESS, "::", 0);
    }
#elif defined (_HUB4_PRODUCT_REQ_) || defined (_SR213_PRODUCT_REQ_)
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_LAN_IPV6_ADDRESS, "::", 0);
#else
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_WAN_ADDRESS, "::", 0);
#endif
#endif

    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, buf, sizeof(buf));
    if ((strcmp(buf, WAN_STATUS_STOPPED) != 0) && ((p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_DOWN) && (p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_DOWN)))
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_STATUS, WAN_STATUS_STOPPED, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, WAN_STATUS_STOPPED, 0);
        CcspTraceInfo(("%s %d - wan-status , wan_service-status event set to stopped \n", __FUNCTION__, __LINE__));
    }

    return ret;
}

#ifdef FEATURE_DSLITE_V2
static int wan_tearDownDSLite(WanMgr_IfaceSM_Controller_t *pWanIfaceCtrl)
{
    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        CcspTraceError(("%s %d - Invalid args \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }
    DML_WAN_IFACE *pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (WanMgr_DSLite_TeardownTunnel(p_VirtIf) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("%s %d - DSLite tunnel teardown failed for interface %s.\n",__FUNCTION__, __LINE__, p_VirtIf->Name));
        WanMgr_ProcessTelemetryMarker(p_VirtIf, WAN_ERROR_DSLITE_STATUS_FAILED);
        return RETURN_ERR;
    }

    if (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY)
    {
        /* IPv6-only mode: disable LAN-to-WAN IPv4 forwarding */
        if (sysctl_iface_set("/proc/sys/net/ipv4/ip_forward", NULL, "0") != 0)
        {
            CcspTraceError(("%s %d - Failure writing to /proc file\n", __FUNCTION__, __LINE__));
        }
    }
    else
    {
        /* Dual-stack mode: update routing */
        WanMgr_Dslite_AddIpRules(p_VirtIf->Name);

        // TODO: Check if LAN-side DHCP/DNS/IGMP service restarts are actually required
#if defined(_LG_OFW_)
        v_secure_system("/etc/utopia/service.d/service_dhcp_server.sh dhcp_server-stop" "; "
                        "/etc/utopia/service.d/service_dhcp_server.sh dhcp_server-start" "; "
                        "/etc/utopia/service.d/service_mcastproxy.sh mcastproxy-restart");
#else
        v_secure_system("systemctl stop dnsmasq.service" "; "
                        "systemctl start dnsmasq.service" "; "
                        "/etc/utopia/service.d/service_mcastproxy.sh mcastproxy-restart");
#endif
    }

    WanMgr_ProcessTelemetryMarker(p_VirtIf, WAN_ERROR_DSLITE_STATUS_DOWN);
    p_VirtIf->DSLite.Status = WAN_IFACE_DSLITE_STATE_DOWN;

    return RETURN_OK;
}

static int wan_setUpDSLite(WanMgr_IfaceSM_Controller_t *pWanIfaceCtrl)
{
    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        CcspTraceError(("%s %d - Invalid args \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    DML_WAN_IFACE *pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (WanMgr_DSLite_SetupTunnel(p_VirtIf) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("%s %d - DSLite tunnel setup failed for interface %s.\n", __FUNCTION__, __LINE__, p_VirtIf->Name));

        WanMgr_ProcessTelemetryMarker(p_VirtIf, WAN_ERROR_DSLITE_STATUS_FAILED);
        p_VirtIf->DSLite.Status = WAN_IFACE_DSLITE_STATE_ERROR;

        clock_gettime(CLOCK_MONOTONIC_RAW, &(p_VirtIf->DSLite.LastRetryTime));
        return RETURN_ERR;
    }

    wanmgr_restart_zebra();

    // IPv6 only mode, we need to start the LAN to WAN IPv4 function
    if (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY)
    {
        if (sysctl_iface_set ("/proc/sys/net/ipv4/ip_forward", NULL, "1") != 0)
        {
            CcspTraceError(("%s %d - Failure writing to /proc file\n", __FUNCTION__, __LINE__));
        }
    }
    else
    {
       // TODO: Check if LAN-side DHCP/DNS/IGMP service restarts are actually required
#if defined(_LG_OFW_)
        v_secure_system ("/etc/utopia/service.d/service_dhcp_server.sh dhcp_server-stop" "; "
                "/etc/utopia/service.d/service_dhcp_server.sh dhcp_server-start" "; "
                "/etc/utopia/service.d/service_mcastproxy.sh mcastproxy-restart");
#else
        v_secure_system ("systemctl stop dnsmasq.service" "; "
                "systemctl start dnsmasq.service" "; "
                "/etc/utopia/service.d/service_mcastproxy.sh mcastproxy-restart");
#endif
    }

    WanMgr_ProcessTelemetryMarker(p_VirtIf, WAN_INFO_DSLITE_STATUS_UP);
    p_VirtIf->DSLite.Status = WAN_IFACE_DSLITE_STATE_UP;

    memset(&(p_VirtIf->DSLite.LastRetryTime), 0, sizeof(p_VirtIf->DSLite.LastRetryTime));

    return RETURN_OK;
}

#endif

#ifdef FEATURE_IPOE_HEALTH_CHECK
static ANSC_STATUS WanMgr_IfaceSM_IHC_Init(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("[%s:%d] Init IHC details in Intf StateMachine data\n", __FUNCTION__, __LINE__));
    if (pWanIfaceCtrl == NULL)
    {
        CcspTraceError(("%s %d - Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    pWanIfaceCtrl->IhcPid = 0;
    pWanIfaceCtrl->IhcV4Status = IHC_STOPPED;
    pWanIfaceCtrl->IhcV6Status = IHC_STOPPED;
    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS WanManager_StopIHC(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if (pWanIfaceCtrl == NULL)
    {
        CcspTraceError(("%s %d - invalid args \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    CcspTraceInfo(("[%s:%d] Stopping IHC App\n", __FUNCTION__, __LINE__));
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);
    if (WanManager_StopIpoeHealthCheckService(pWanIfaceCtrl->IhcPid) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("%s %d - Failed to kill IHC process interface %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        return ANSC_STATUS_FAILURE;
    }
    WanMgr_IfaceSM_IHC_Init(pWanIfaceCtrl);
    return ANSC_STATUS_SUCCESS;
}
#endif

static ANSC_STATUS WanMgr_StartConnectivityCheck(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("[%s:%d] \n", __FUNCTION__, __LINE__));
    if (pWanIfaceCtrl == NULL || pWanIfaceCtrl->pIfaceData == NULL)
    {
        CcspTraceError(("%s %d - Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* pVirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if(pVirtIf->IP.ConnectivityCheckRunning == TRUE && pVirtIf->IP.RestartConnectivityCheck == FALSE )
    {
        CcspTraceInfo(("[%s:%d] ConnectivityCheck already running\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_SUCCESS;
    }

    if(pVirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_TAD)
    {
        CcspTraceInfo(("%s %d ConnectivityCheck Type is TAD \n", __FUNCTION__, __LINE__));
        WanMgr_Configure_TAD_WCC( pVirtIf, (pVirtIf->IP.ConnectivityCheckRunning && pVirtIf->IP.RestartConnectivityCheck) ? WCC_RESTART : WCC_START);
        pVirtIf->IP.ConnectivityCheckRunning = TRUE;    
    }
    else if(pVirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_IHC)
    {
        CcspTraceInfo(("%s %d ConnectivityCheck Type is IHC \n", __FUNCTION__, __LINE__));
#ifdef FEATURE_IPOE_HEALTH_CHECK
        if ( pVirtIf->Status == WAN_IFACE_STATUS_UP && pWanIfaceCtrl->IhcPid <= 0 )
        {
            // IHC enabled but not running, So Starting IHC
            UINT IhcPid = 0;
            IhcPid = WanManager_StartIpoeHealthCheckService(pVirtIf->Name);
            if (IhcPid > 0)
            {
                pWanIfaceCtrl->IhcPid = IhcPid;
                CcspTraceInfo(("%s %d - Starting IPoE Health Check pid - %u for interface %s \n",
                                __FUNCTION__, __LINE__, pWanIfaceCtrl->IhcPid, pVirtIf->Name));
            }
            else
            {
                CcspTraceError(("%s %d - Failed to start IPoE Health Check for interface %s \n", __FUNCTION__, __LINE__, pVirtIf->Name));
            }
            pVirtIf->IP.ConnectivityCheckRunning = TRUE;    
        }
#endif
    }else
    {
        CcspTraceInfo(("[%s:%d] ConnectivityCheck not configured.\n", __FUNCTION__, __LINE__));
    }
    
    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS WanMgr_StopConnectivityCheck(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("[%s:%d] \n", __FUNCTION__, __LINE__));
    if (pWanIfaceCtrl == NULL || pWanIfaceCtrl->pIfaceData == NULL)
    {
        CcspTraceError(("%s %d - Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* pVirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if(pVirtIf->IP.ConnectivityCheckRunning == FALSE)
    {
        CcspTraceInfo(("[%s:%d] ConnectivityCheck Already stopped.\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_SUCCESS;
    }

    if(pVirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_TAD)
    {
        CcspTraceInfo(("%s %d ConnectivityCheck Type is TAD \n", __FUNCTION__, __LINE__));
        WanMgr_Configure_TAD_WCC( pVirtIf,  WCC_STOP);
    }
    else if(pVirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_IHC)
    {
        CcspTraceInfo(("%s %d ConnectivityCheck Type is IHC \n", __FUNCTION__, __LINE__));
#ifdef FEATURE_IPOE_HEALTH_CHECK
        if(pWanIfaceCtrl->IhcPid > 0)
        {
            WanManager_StopIHC(pWanIfaceCtrl);
        }
#endif  // FEATURE_IPOE_HEALTH_CHECK

    }else
    {
        CcspTraceInfo(("[%s:%d] ConnectivityCheck not configured.\n", __FUNCTION__, __LINE__));
    }

    pVirtIf->IP.ConnectivityCheckRunning = FALSE;
    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS WanMgr_SendMsgTo_ConnectivityCheck(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl , CONNECTION_TYPE type, BOOL ConnStatus)
{
    CcspTraceInfo(("[%s:%d] \n", __FUNCTION__, __LINE__));
    if (pWanIfaceCtrl == NULL || pWanIfaceCtrl->pIfaceData == NULL)
    {
        CcspTraceError(("%s %d - Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if(p_VirtIf->IP.ConnectivityCheckRunning == FALSE)
    {
        CcspTraceInfo(("[%s:%d] ConnectivityCheck Not running. Starting \n", __FUNCTION__, __LINE__));
        WanMgr_StartConnectivityCheck(pWanIfaceCtrl);
    }

    if(p_VirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_TAD)
    {
        //Currently TestAndDiagnostic dns check doesn't require additional message afte start. DO nothing.
    }
    else if(p_VirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_IHC)
    {
#ifdef FEATURE_IPOE_HEALTH_CHECK
        char IHC_status[BUFLEN_16] = {0};
        if(type == CONNECTION_MSG_IPV4 && ConnStatus == TRUE)
        {
            sysevent_get(sysevent_fd, sysevent_token, IPOE_HEALTH_CHECK_V4_STATUS, IHC_status, sizeof(IHC_status));
            if(pWanIfaceCtrl->IhcV4Status == IHC_STOPPED ||
                    p_VirtIf->IP.Ipv4Changed == TRUE  ||
                    (p_VirtIf->IP.Ipv4Renewed == TRUE && (strcmp(IHC_status, IPOE_STATUS_FAILED) == 0)))
            {
                if(p_VirtIf->IP.Ipv4Renewed == TRUE && (strcmp(IHC_status, IPOE_STATUS_FAILED) == 0))
                {
                    WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_WARN_CONNECTIVITY_CHECK_STATUS_FAILED_IPV4);			
                    //Restarting firewall to add IPOE_HEALTH_CHECK firewall rules.
                    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
                }
                WanMgr_SendMsgToIHC(IPOE_MSG_WAN_CONNECTION_UP, p_VirtIf->Name);
                pWanIfaceCtrl->IhcV4Status = IHC_STARTED;
            }
        }
        else if(type == CONNECTION_MSG_IPV4 && ConnStatus == FALSE)
        {
                CcspTraceInfo(("%s %d Sending IPOE_MSG_WAN_CONNECTION_DOWN \n", __FUNCTION__, __LINE__));
                WanMgr_SendMsgToIHC(IPOE_MSG_WAN_CONNECTION_DOWN, p_VirtIf->Name);
                pWanIfaceCtrl->IhcV4Status = IHC_STOPPED;
        }
        else if(type == CONNECTION_MSG_IPV6 && ConnStatus == TRUE)
        {
            sysevent_get(sysevent_fd, sysevent_token, IPOE_HEALTH_CHECK_V6_STATUS, IHC_status, sizeof(IHC_status));
            if(pWanIfaceCtrl->IhcV6Status == IHC_STOPPED ||
                    p_VirtIf->IP.Ipv6Changed == TRUE  ||
                    (p_VirtIf->IP.Ipv6Renewed == TRUE && (strcmp(IHC_status, IPOE_STATUS_FAILED) == 0)))
            {
                if(p_VirtIf->IP.Ipv6Renewed == TRUE && (strcmp(IHC_status, IPOE_STATUS_FAILED) == 0))
                {
                    WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_WARN_CONNECTIVITY_CHECK_STATUS_FAILED_IPV6);			
                    //Restarting firewall to add IPOE_HEALTH_CHECK firewall rules.
                    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
                }
               WanMgr_SendMsgToIHC(IPOE_MSG_WAN_CONNECTION_IPV6_UP, p_VirtIf->Name);
               pWanIfaceCtrl->IhcV6Status = IHC_STARTED;
            }
        }
        else if(type == CONNECTION_MSG_IPV6 && ConnStatus == FALSE)
        {
                CcspTraceInfo(("%s %d Sending IPOE_MSG_WAN_CONNECTION_IPV6_DOWN \n", __FUNCTION__, __LINE__));
                WanMgr_SendMsgToIHC(IPOE_MSG_WAN_CONNECTION_IPV6_DOWN, p_VirtIf->Name);
                pWanIfaceCtrl->IhcV6Status = IHC_STOPPED;
        }

#endif

    }else
    {
        CcspTraceInfo(("[%s:%d] ConnectivityCheck not configured.\n", __FUNCTION__, __LINE__));
    }

    return ANSC_STATUS_SUCCESS;
}

/* WanManager_ClearDHCPData */
/* This function must be used only with the mutex locked */
static ANSC_STATUS WanManager_ClearDHCPData(DML_VIRTUAL_IFACE * pVirtIf)
{
    if(pVirtIf == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d  \n", __FUNCTION__, __LINE__));
    /* DHCPv4 client */
    pVirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_DOWN;
    pVirtIf->IP.Ipv4Changed = FALSE;
    pVirtIf->IP.Ipv4Renewed = FALSE;
    memset(&(pVirtIf->IP.Ipv4Data), 0, sizeof(WANMGR_IPV4_DATA));
    pVirtIf->IP.Dhcp4cPid = 0;
    pVirtIf->IP.Dhcp4cStatus = DHCPC_STOPPED;
    if(pVirtIf->IP.pIpcIpv4Data != NULL)
    {
        free(pVirtIf->IP.pIpcIpv4Data);
        pVirtIf->IP.pIpcIpv4Data = NULL;
    }

    /* DHCPv6 client */
    pVirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_DOWN;
    pVirtIf->MAP.MaptStatus = WAN_IFACE_MAPT_STATE_DOWN;
    pVirtIf->DSLite.Status = WAN_IFACE_DSLITE_STATE_DOWN;
    pVirtIf->IP.Ipv6Changed = FALSE;
    pVirtIf->IP.Ipv6Renewed = FALSE;
    memset(&(pVirtIf->IP.Ipv6Data), 0, sizeof(WANMGR_IPV6_DATA));
    memset(&(pVirtIf->IP.Ipv6RA), 0, sizeof(WANMGR_IPV6_RA_DATA));
    pVirtIf->IP.Dhcp6cPid = 0;
    pVirtIf->IP.Dhcp6cStatus = DHCPC_STOPPED;
    if(pVirtIf->IP.pIpcIpv6Data != NULL)
    {
        free(pVirtIf->IP.pIpcIpv6Data);
        pVirtIf->IP.pIpcIpv6Data = NULL;
    }

    return ANSC_STATUS_SUCCESS;
}

/*********************************************************************************/
/************************** TRANSITIONS ******************************************/
/*********************************************************************************/
static eWanState_t wan_transition_start(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    p_VirtIf->Interface_SM_Running = TRUE;

    p_VirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_DOWN;
    p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_DOWN;
    p_VirtIf->MAP.MaptStatus = WAN_IFACE_MAPT_STATE_DOWN;
    p_VirtIf->DSLite.Status = WAN_IFACE_DSLITE_STATE_DOWN;
    memset(p_VirtIf->VLAN.CurrentVlan, 0, sizeof(p_VirtIf->VLAN.CurrentVlan));

    p_VirtIf->Status = WAN_IFACE_STATUS_DISABLED;

    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    /*If WanManger restarted, get the status of existing VLAN, PPP inetrfaces.*/
    if(WanMgr_RestartFindExistingLink(pWanIfaceCtrl) == TRUE)
    {
        CcspTraceInfo(("%s %d - Already WAN interface %s created\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
    }

    /*Should Update available status */
    Update_Interface_Status();

    WanMgr_GetSelectedIPMode(p_VirtIf); //Get SelectedIPMode

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION START\n", __FUNCTION__, __LINE__, pInterface->Name));

    return WAN_STATE_PHY_CONFIGURING;
}

static eWanState_t wan_transition_vlan_configure(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);
    int  uptime = 0;
    char buffer[64] = {0};

    p_VirtIf->Status = WAN_IFACE_STATUS_INITIALISING;

    /*TODO: VLAN should not be set for Remote Interface, for More info, refer RDKB-42676*/
    if(  p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status == WAN_IFACE_LINKSTATUS_DOWN && pInterface->IfaceType != REMOTE_IFACE)
    {
        if(strlen(p_VirtIf->VLAN.VLANInUse) > 0)
        {
            CcspTraceInfo(("%s %d - interface %s : using previously found VLAN %s\n", __FUNCTION__, __LINE__, p_VirtIf->Name, p_VirtIf->VLAN.VLANInUse));
            strncpy(p_VirtIf->VLAN.CurrentVlan, p_VirtIf->VLAN.VLANInUse, sizeof(p_VirtIf->VLAN.CurrentVlan));
            p_VirtIf->VLAN.CurrentVlan[sizeof(p_VirtIf->VLAN.CurrentVlan) - 1] = '\0';
        }
        else
        {
            CcspTraceInfo(("%s %d - interface %s : no previously found VLAN. Using first VLAN from the list\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            p_VirtIf->VLAN.ActiveIndex = 0;
            DML_VLAN_IFACE_TABLE* pVlanIf = WanMgr_getVirtVlanIfById(p_VirtIf->VLAN.InterfaceList, p_VirtIf->VLAN.ActiveIndex);
            strncpy(p_VirtIf->VLAN.CurrentVlan, pVlanIf->Interface, sizeof(p_VirtIf->VLAN.CurrentVlan));
            p_VirtIf->VLAN.CurrentVlan[sizeof(p_VirtIf->VLAN.CurrentVlan) - 1] = '\0';
        }

        p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_CONFIGURING;
        WanMgr_RdkBus_ConfigureVlan(p_VirtIf, TRUE);
    }

    /* Update available status */
    Update_Interface_Status();

    /* Update WAN Init Start BootTime Information */
    WanManager_GetDateAndUptime( buffer, &uptime );
    LOG_CONSOLE("%s [tid=%ld] Wan_init_start:%d\n", buffer, syscall(SYS_gettid), uptime);
    WanManager_PrintBootEvents (WAN_INIT_START);

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION VLAN CONFIGURE\n", __FUNCTION__, __LINE__, pInterface->Name));

    return WAN_STATE_VLAN_CONFIGURING;
}

static eWanState_t wan_transition_ppp_configure(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if( p_VirtIf->PPP.Enable == TRUE && p_VirtIf->PPP.LinkStatus == WAN_IFACE_PPP_LINK_STATUS_DOWN)
    {
        p_VirtIf->PPP.LinkStatus = WAN_IFACE_PPP_LINK_STATUS_CONFIGURING;
        WanManager_ConfigurePPPSession(p_VirtIf, TRUE);
    }

    return WAN_STATE_PPP_CONFIGURING;
}

static eWanState_t wan_transition_physical_interface_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    if(p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)
    {
        wan_transition_mapt_down(pWanIfaceCtrl);
    }
#endif

#ifdef FEATURE_DSLITE_V2
    if (p_VirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_UP)
    {
        wan_transition_dslite_down(pWanIfaceCtrl);
    }
#endif

    if(p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP)
    {
        wan_transition_ipv4_down(pWanIfaceCtrl);
    }

    if(p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)
    {
        wan_transition_ipv6_down(pWanIfaceCtrl);
    }

    /* Stops DHCPv4 client */
    if(p_VirtIf->IP.Dhcp4cStatus == DHCPC_STARTED)
    {
        // v4 config is teared down if already configured, stop DHCPv4 client if running without RELEASE
        CcspTraceInfo(("%s %d: Stopping DHCP v4\n", __FUNCTION__, __LINE__));
        WanManager_StopDhcpv4Client(p_VirtIf, STOP_DHCP_WITHOUT_RELEASE); 
    }

    /* Stops DHCPv6 client */
    if(p_VirtIf->IP.Dhcp6cStatus == DHCPC_STARTED)
    {
        // v6 config is teared down if already configured, stop DHCPv6 client if running without RELEASE
        CcspTraceInfo(("%s %d: Stopping DHCP v6\n", __FUNCTION__, __LINE__));
        WanManager_StopDhcpv6Client(p_VirtIf, STOP_DHCP_WITHOUT_RELEASE);
    }

    p_VirtIf->IP.SelectedModeTimerStatus = NOTSTARTED; // Reset Timer
    WanMgr_StopConnectivityCheck(pWanIfaceCtrl);

    if (p_VirtIf->PPP.Enable == TRUE)
    {
        /* Disable PPP session */
        WanManager_ConfigurePPPSession(p_VirtIf, FALSE);
        if( p_VirtIf->PPP.LinkStatus == WAN_IFACE_PPP_LINK_STATUS_CONFIGURING)
        {
            CcspTraceInfo(("%s %d: ppp LinkStatus is still CONFIGURING. Set to down\n", __FUNCTION__, __LINE__));
            p_VirtIf->PPP.LinkStatus = WAN_IFACE_PPP_LINK_STATUS_DOWN;
        }
    }

    if(p_VirtIf->VLAN.Enable == TRUE)
    {
        if (pInterface->IfaceType != REMOTE_IFACE) //TODO NEW_DESIGN rework for remote interface
        {
            WanMgr_RdkBus_ConfigureVlan(p_VirtIf, FALSE);        
            WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_ERROR_VLAN_DOWN);	    
            /* VLAN link is not created yet if LinkStatus is CONFIGURING. Change it to down. */
            if( p_VirtIf->VLAN.Status == WAN_IFACE_LINKSTATUS_CONFIGURING || p_VirtIf->VLAN.Status == WAN_IFACE_LINKSTATUS_UP )
            {
                CcspTraceInfo(("%s %d: LinkStatus is still CONFIGURING. Set to down\n", __FUNCTION__, __LINE__));
                p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_DOWN;
            }
        }
    }

    Update_Interface_Status();

    if(p_VirtIf->Reset == TRUE || p_VirtIf->VLAN.Reset == TRUE || p_VirtIf->VLAN.Expired == TRUE)
    {
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION REFRESHING WAN\n", __FUNCTION__, __LINE__, pInterface->Name));
        return WAN_STATE_REFRESHING_WAN;
    }

#if defined(_DT_WAN_Manager_Enable_)
    Enable_CaptivePortal(TRUE);
#endif
    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION DECONFIGURING WAN\n", __FUNCTION__, __LINE__, pInterface->Name));

    return WAN_STATE_DECONFIGURING_WAN;
}

static eWanState_t wan_transition_wan_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);


    p_VirtIf->Status = WAN_IFACE_STATUS_VALIDATING;

    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION VALIDATING WAN\n", __FUNCTION__, __LINE__, pInterface->Name));

    return WAN_STATE_VALIDATING_WAN;
}

static eWanState_t wan_transition_wan_validated(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if((p_VirtIf->IP.IPv4Source == DML_WAN_IP_SOURCE_DHCP || p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_DHCP || p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_SLAAC ) && (p_VirtIf->IP.SelectedModeTimerStatus != EXPIRED) )
    {
        /* Clear DHCP data */
        WanManager_ClearDHCPData(p_VirtIf);
    }

    //Init ConnectivityStatus to UP
    p_VirtIf->IP.Ipv4ConnectivityStatus = WAN_CONNECTIVITY_UP;
    p_VirtIf->IP.Ipv6ConnectivityStatus = WAN_CONNECTIVITY_UP;

    if ((p_VirtIf->IP.SelectedMode == MAPT_MODE || p_VirtIf->IP.SelectedMode == DSLITE_MODE) &&
        p_VirtIf->IP.SelectedModeTimerStatus != EXPIRED)
    {
        /* Start all interface with accept ra disabled */
        WanMgr_Configure_accept_ra(p_VirtIf, FALSE);
        /* Start DHCPv6 Client */
        WanManager_StartDhcpv6Client(p_VirtIf, pInterface->IfaceType);
        CcspTraceInfo(("%s %d - %s_MODE preferred \n", __FUNCTION__, __LINE__,
                       p_VirtIf->IP.SelectedMode == MAPT_MODE ? "MAPT" : "DSLITE"));
        // clock start
        p_VirtIf->IP.SelectedModeTimerStatus = RUNNING;
        memset(&(p_VirtIf->IP.SelectedModeTimerStart), 0, sizeof(struct timespec));
        clock_gettime(CLOCK_MONOTONIC_RAW, &(p_VirtIf->IP.SelectedModeTimerStart));
    }
    else
    {
        if (p_VirtIf->IP.IPv4Source == DML_WAN_IP_SOURCE_DHCP &&
            (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV4_ONLY))
        {
            /* Start DHCPv4 client */
            WanManager_StartDhcpv4Client(p_VirtIf,pInterface->Name, pInterface->IfaceType);
        }

        if(((p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_DHCP) || (p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_SLAAC) ) && (p_VirtIf->IP.Dhcp6cStatus != DHCPC_STARTED) &&
            (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY))
        {
            /* Start all interface with accept ra disbaled */
            WanMgr_Configure_accept_ra(p_VirtIf, FALSE);
            /* Start DHCPv6 Client */
            WanManager_StartDhcpv6Client(p_VirtIf, pInterface->IfaceType);
        }
    }

    if(strstr(pInterface->BaseInterface, "Cellular") != NULL)
    {
        CcspTraceInfo(("%s %d - Configuring IP from Cellular Manager \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        WanMgr_UpdateIpFromCellularMgr(pWanIfaceCtrl);
    }

#if defined(_DT_WAN_Manager_Enable_)
    Enable_CaptivePortal(FALSE);
#endif

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION OBTAINING IP ADDRESSES\n", __FUNCTION__, __LINE__, pInterface->Name));
    CcspTraceInfo(("%s %d - Interface '%s' - Started in %s IP Mode\n", __FUNCTION__, __LINE__, pInterface->Name, p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK ?"Dual Stack":
        p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY?"IPv6 Only": p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV4_ONLY?"IPv4 Only":"No IP"));

    // wan interface is now validated, lets fetch lease information for this interface if available
    if(p_VirtIf->PPP.Enable == TRUE && (strlen(p_VirtIf->PPP.Interface) > 0))
    {
        char dmQuery[BUFLEN_256] = {0};
        char ppp_ConnectionStatus[BUFLEN_256]   = {0};
        snprintf(dmQuery, sizeof(dmQuery)-1, "%s.ConnectionStatus", p_VirtIf->PPP.Interface);
        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, ppp_ConnectionStatus))
        {
            CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
            return WAN_STATE_OBTAINING_IP_ADDRESSES;
        }

        if(!strcmp(ppp_ConnectionStatus, "Connected"))
        {
            p_VirtIf->PPP.IPCPStatusChanged = TRUE;
            p_VirtIf->PPP.IPV6CPStatusChanged = TRUE;
        }
        else
        {
            p_VirtIf->PPP.IPCPStatus = WAN_IFACE_IPCP_STATUS_DOWN;
            p_VirtIf->PPP.IPV6CPStatus = WAN_IFACE_IPV6CP_STATUS_DOWN;
        }
    }

    if(pInterface->IfaceType == REMOTE_IFACE)
    {
        /* Mesh ULA ipv6 address is statically assigned for remote interface. copying to WanManager struct for tr181 DML */
        CcspTraceInfo(("%s %d - Interface '%s' - Assigning Static ULA Ipv6 Address\n", __FUNCTION__, __LINE__, pInterface->Name));
        sysevent_get(sysevent_fd, sysevent_token, "MeshRemoteWANInterface_UlaAddr", p_VirtIf->IP.Ipv6Data.address, sizeof(p_VirtIf->IP.Ipv6Data.address));
        char *backslashPosition = strchr(p_VirtIf->IP.Ipv6Data.address, '/');  // Find the first occurrence of '/'. 
        if (backslashPosition != NULL) 
            *backslashPosition = '\0';  // Replace the backslash with a null character
    }

    return WAN_STATE_OBTAINING_IP_ADDRESSES;
}

//TODO: NEW_DESIGN use this transition for vlan discovery reconfiguration
static eWanState_t wan_transition_wan_refreshed(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if(  p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status == WAN_IFACE_LINKSTATUS_DOWN && pInterface->IfaceType != REMOTE_IFACE)
    {
        if(p_VirtIf->VLAN.Expired == TRUE || p_VirtIf->VLAN.Reset == TRUE)
        {
            DML_VLAN_IFACE_TABLE* pVlanIf = NULL;
            if (p_VirtIf->VLAN.Reset == TRUE || p_VirtIf->VLAN.ActiveIndex == -1)
            {
                /* Reset to first Vlan Interface*/
                pVlanIf = p_VirtIf->VLAN.InterfaceList;
            }else
            {
                pVlanIf = WanMgr_getVirtVlanIfById(p_VirtIf->VLAN.InterfaceList, p_VirtIf->VLAN.ActiveIndex);
                if(pVlanIf == NULL || pVlanIf->next == NULL)
                {
                    /* Next Vlan Interface not available reset to Head*/
                    pVlanIf = p_VirtIf->VLAN.InterfaceList;
                }else
                {
                    /* Try next Vlan Interface*/
                    pVlanIf = pVlanIf->next;
                }

            }
            p_VirtIf->VLAN.ActiveIndex = pVlanIf->Index;
            strncpy(p_VirtIf->VLAN.CurrentVlan, pVlanIf->Interface, (sizeof(p_VirtIf->VLAN.CurrentVlan) - 1));
            p_VirtIf->VLAN.CurrentVlan[sizeof(p_VirtIf->VLAN.CurrentVlan) - 1] = '\0';
            CcspTraceInfo(("%s %d VLAN Discovery . Trying VlanIndex: %d : %s\n", __FUNCTION__, __LINE__,p_VirtIf->VLAN.ActiveIndex, p_VirtIf->VLAN.CurrentVlan));
        }

        p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_CONFIGURING;
        //TODO: NEW_DESIGN check for VLAN table
        WanMgr_RdkBus_ConfigureVlan(p_VirtIf, TRUE);
    }
    if(p_VirtIf->Reset == TRUE)
    {
        //Trigger Reset WFO scan if Wan Refresh/reset is triggered. 
        WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
        if(pWanConfigData != NULL)
        {
            CcspTraceInfo(("%s %d: Resetting FO scan thread\n", __FUNCTION__, __LINE__));
            pWanConfigData->data.ResetFailOverScan = TRUE;
            WanMgrDml_GetConfigData_release(pWanConfigData);
        }
    }
    p_VirtIf->Reset = FALSE;
    p_VirtIf->VLAN.Reset = FALSE;
    p_VirtIf->VLAN.Expired = FALSE;

    return WAN_STATE_VLAN_CONFIGURING;
}

static eWanState_t wan_transition_ipv4_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    ANSC_STATUS ret;
    char buf[BUFLEN_128] = {0};

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    /* successfully got the v4 lease from the interface, so lets mark it validated */
    p_VirtIf->Status = WAN_IFACE_STATUS_UP;

#if defined(_DT_WAN_Manager_Enable_)
    if ((0 == strcmp("DATA", p_VirtIf->Alias)) || (0 == strcmp("VOIP", p_VirtIf->Alias)))
    {
        /* Update voice interface name to TelcoVoiceManager */
        updateInterfaceToVoiceManager(pWanIfaceCtrl, true);
    }

    if(strcmp(p_VirtIf->Alias, "DATA"))
    {
        return WAN_STATE_IPV4_LEASED;
    }
    v_secure_system("echo 2 > /proc/sys/net/ipv6/conf/erouter0/accept_ra");
    v_secure_system("echo 0 > /proc/sys/net/ipv6/conf/erouter0/accept_ra_mtu");

#endif

    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    /* Configure IPv4. */
    ret = wan_setUpIPv4(pWanIfaceCtrl);
    if (ret != RETURN_OK)
    {
        CcspTraceError(("%s %d - Failed to configure IPv4 successfully \n", __FUNCTION__, __LINE__));
    }

    WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV4 , TRUE);

    /* Force reset ipv4 state global flag. */
    p_VirtIf->IP.Ipv4Changed = FALSE;
    p_VirtIf->IP.Ipv4Renewed = FALSE;

    Update_Interface_Status();
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, buf, sizeof(buf));
    //TODO: Firewall IPv6 FORWARD rules are not working if SYSEVENT_WAN_SERVICE_STATUS is set for REMOTE_IFACE. Modify firewall similar for backup interface similar to primary.
    if (strcmp(buf, WAN_STATUS_STARTED) && pInterface->IfaceType != REMOTE_IFACE)
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, WAN_STATUS_STARTED, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
    }

    memset(buf, 0, BUFLEN_128);
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV6_CONNECTION_STATE, buf, sizeof(buf));

    if(p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP && !strcmp(buf, WAN_STATUS_UP))
    {
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION DUAL STACK ACTIVE\n", __FUNCTION__, __LINE__, pInterface->Name));
        return WAN_STATE_DUAL_STACK_ACTIVE;
    }

    UpdateAndPersistVLANInUse(p_VirtIf);
    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION IPV4 LEASED\n", __FUNCTION__, __LINE__, pInterface->Name));

    return WAN_STATE_IPV4_LEASED;
}

static eWanState_t wan_transition_ipv4_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    char buf[BUFLEN_128] = {0};

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        p_VirtIf->Enable == FALSE ||
        p_VirtIf->Reset == TRUE ||
        p_VirtIf->VLAN.Reset == TRUE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP ||
        (p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_DOWN) ||
        (p_VirtIf->IP.RefreshDHCP == TRUE && (p_VirtIf->IP.IPv4Source != DML_WAN_IP_SOURCE_DHCP || 
        (p_VirtIf->IP.Mode != DML_WAN_IP_MODE_IPV4_ONLY && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_DUAL_STACK))))
    {
        // Stopping DHCPv4 client, so we can send a unicast DHCP Release packet
        if(p_VirtIf->IP.Dhcp4cStatus == DHCPC_STARTED)
        {
            CcspTraceInfo(("%s %d: Stopping DHCP v4\n", __FUNCTION__, __LINE__));
            DHCP_RELEASE_BEHAVIOUR release_action = STOP_DHCP_WITH_RELEASE;  // STOP_DHCP_WITH_RELEASE by default, v4 config available

            if ((pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)                                   // WAN BaseInterface Down, STOP_DHCP_WITHOUT_RELEASE
                    || p_VirtIf->Reset == TRUE                                                                  // WAN Refresh going on, STOP_DHCP_WITHOUT_RELEASE
                    || (p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status == WAN_IFACE_LINKSTATUS_DOWN)    // VLAN Link Down, STOP_DHCP_WITHOUT_RELEASE
                    || (pInterface->Selection.RebootTriggerStatus == TRUE))           // Hardware Reconfiguration reboot going on, STOP_DHCP_WITHOUT_RELEASE
            {
                release_action = STOP_DHCP_WITHOUT_RELEASE;
            }
            WanManager_StopDhcpv4Client(p_VirtIf, release_action);
        }
    }
    else
    {
        // start DHCPv4 client if it is not running, DSLite and MAP-T not configured and PPP Disable scenario.
        if (p_VirtIf->IP.Dhcp4cStatus != DHCPC_STARTED &&
            (p_VirtIf->PPP.Enable == FALSE) &&
            (!(p_VirtIf->EnableMAPT == TRUE && (pInterface->Selection.Status == WAN_IFACE_ACTIVE) &&
               (p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)))
#ifdef FEATURE_DSLITE_V2
            && (!(WanMgr_DSLite_isEnabled(p_VirtIf) == TRUE && (pInterface->Selection.Status == WAN_IFACE_ACTIVE) &&
               (p_VirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_UP)))
#endif
        )
        {
            WanManager_StartDhcpv4Client(p_VirtIf, pInterface->Name, pInterface->IfaceType);
            CcspTraceInfo(("%s %d - SELFHEAL - Started dhcpc on interface %s\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
    WanManager_UpdateInterfaceStatus (p_VirtIf, WANMGR_IFACE_CONNECTION_DOWN);

#if defined(_DT_WAN_Manager_Enable_)
    if(strcmp(p_VirtIf->Alias, "DATA"))
    {
        return WAN_STATE_OBTAINING_IP_ADDRESSES;
    }
#endif

    wan_deconfigIPv4onInterface(pWanIfaceCtrl); //delete IPv4 address from the interface
    if(p_VirtIf->Status == WAN_IFACE_STATUS_UP)
    {
        if (wan_tearDownIPv4(pWanIfaceCtrl) != RETURN_OK)
        {
            CcspTraceError(("%s %d - Failed to tear down IPv4 for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
        wanmgr_sysevents_ipv4Info_init(p_VirtIf->Name, pWanIfaceCtrl->DeviceNwMode); // reset the sysvent/syscfg fields
    }

    WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV4 , FALSE);

    char param_name[256] = {0};
    snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv4Address",  p_VirtIf->baseIfIdx+1, p_VirtIf->VirIfIdx+1);
    WanMgr_Rbus_EventPublishHandler(param_name, "",RBUS_STRING);

    Update_Interface_Status();
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV6_CONNECTION_STATE, buf, sizeof(buf));

    if(p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP && !strcmp(buf, WAN_STATUS_UP))
    {
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION IPV6 LEASED\n", __FUNCTION__, __LINE__, pInterface->Name));
        return WAN_STATE_IPV6_LEASED;
    }

    if(p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_DOWN)
    {
        //If Ipv6 is already down disbale accept_ra
        WanMgr_Configure_accept_ra(p_VirtIf, FALSE);
    }

    /* RDKB-46612 - Empty set caused the cujo firewall rules to currupt and led to IHC IDLE.
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, "", 0);*/

    p_VirtIf->Status = WAN_IFACE_STATUS_VALIDATING;
    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION OBTAINING IP ADDRESSES\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_OBTAINING_IP_ADDRESSES;
}

#if defined(FEATURE_464XLAT)
int sc_myPipe(FILE *fp, char **output)
{
    char buf[1024];
	char *pt = NULL;
    int len=0;
    *output=malloc(3);
    strcpy(*output, "");
    while((fgets(buf, sizeof(buf), fp)) != NULL){
        len=strlen(*output)+strlen(buf);
        if((*output=realloc(*output, (sizeof(char) * (len+1))))==NULL)
        {
            return(-1);
        }
        strcat(*output, buf);
    }
	if ((pt = strchr(*output, '\n')) != NULL)
	{
		*pt = '\0';
	}

    return len;
}

void xlat_process_start(char *interface)
{
	char xlatcfg_output[256] = {0};
	char *kernel_path = NULL;
	int ret = 0;
	FILE *fp = NULL;
	fp = v_secure_popen("r","uname -r");
	if(fp)
	{
	    sc_myPipe(fp,&kernel_path);
	    v_secure_pclose(fp);
	}
	v_secure_system("insmod /lib/modules/'%s'/extra/nat46.ko",kernel_path);
	free(kernel_path);
	ret = xlat_configure(interface, xlatcfg_output);
	if(ret == 0 || strlen(xlatcfg_output) > 3)
	{
		v_secure_system("ifconfig xlat up");
		sleep(1);
		v_secure_system("ip ro del default");
		v_secure_system("ip route add default dev xlat");
		v_secure_system("echo 200 464xlat >> /etc/iproute2/rt_tables");
		v_secure_system("ip -6 rule del from all lookup local");
		v_secure_system("ip -6 rule add from all lookup local pref 1");
		v_secure_system("ip -6 rule add to %s lookup 464xlat pref 0",xlatcfg_output);
		v_secure_system("ip -6 route add %s dev xlat proto static metric 1024 pref medium table 464xlat",xlatcfg_output);
		syscfg_set(NULL, "xlat_status", "up");
        syscfg_set(NULL, "xlat_addrdss", xlatcfg_output);
		v_secure_system("sync;sync");
		syscfg_commit();
		v_secure_system("sysevent set firewall-restart 0");
	}else
	{
		v_secure_system("rmmod nat46");
	}
}

void xlat_process_stop(char *interface)
{
	char xlat_addr[128] = {0};
	
	v_secure_system("ip route del default dev xlat");
	v_secure_system("ip ro add default dev %s scope link",interface);
	v_secure_system("iptables -t nat -D POSTROUTING  -o xlat -j SNAT --to-source  192.0.0.1");
	v_secure_system("ifconfig xlat down");
	xlat_reconfigure();
	v_secure_system("rmmod nat46");
	if (syscfg_get(NULL, "xlat_addrdss", xlat_addr, sizeof(xlat_addr))!=0)
	{
		if(strlen(xlat_addr) > 3)
		{
			v_secure_system("ip -6 rule del to %s lookup 464xlat",xlat_addr);
		}
	}
	v_secure_system("ip -6 rule del from all lookup local");
	v_secure_system("ip -6 rule add from all lookup local pref 0");
	v_secure_system("syscfg unset xlat_status");
	v_secure_system("syscfg unset xlat_addrdss");
	v_secure_system("syscfg commit");
}
#endif

static eWanState_t wan_transition_ipv6_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    ANSC_STATUS ret;
    char buf[BUFLEN_128] = {0};
#if defined(FEATURE_464XLAT)
	XLAT_State_t xlat_status;
#endif
	

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    /* successfully got the v6 lease from the interface, so lets mark it validated */
    p_VirtIf->Status = WAN_IFACE_STATUS_UP;

#if defined(_DT_WAN_Manager_Enable_)
    if ((0 == strcmp("DATA", p_VirtIf->Alias)) || (0 == strcmp("VOIP", p_VirtIf->Alias)))
    {
        /* Update voice interface name to TelcoVoiceManager */
        updateInterfaceToVoiceManager(pWanIfaceCtrl, true);
    }
#endif
    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    /* Configure IPv6. */
    ret = wan_setUpIPv6(pWanIfaceCtrl);
    if (ret != RETURN_OK)
    {
        CcspTraceError(("%s %d - Failed to configure IPv6 successfully \n", __FUNCTION__, __LINE__));
    }

    WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);

    Update_Interface_Status();
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, buf, sizeof(buf));
    //TODO: Firewall IPv6 FORWARD rules are not working if SYSEVENT_WAN_SERVICE_STATUS is set for REMOTE_IFACE. Modify firewall similar for backup interface similar to primary.
    if (strcmp(buf, WAN_STATUS_STARTED) && pInterface->IfaceType != REMOTE_IFACE)
    {
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_WAN_SERVICE_STATUS, WAN_STATUS_STARTED, 0);
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
    }
#if defined(FEATURE_464XLAT)
	CcspTraceInfo(("%s %d - 464xlat STARTING \n", __FUNCTION__, __LINE__));
	xlat_status = xlat_state_get();
	CcspTraceInfo(("%s %d - xlat_status = %d \n", __FUNCTION__, __LINE__,xlat_status));
	if(xlat_status == XLAT_OFF)
	{
		CcspTraceInfo(("%s %d - START 464xlat\n", __FUNCTION__, __LINE__));
		xlat_process_start(p_VirtIf->Name);
	}
	else
	{
		CcspTraceInfo(("%s %d - RESTART 464xlat\n", __FUNCTION__, __LINE__));
		xlat_process_stop(p_VirtIf->Name);
		xlat_process_start(p_VirtIf->Name);
	}
	CcspTraceInfo(("%s %d -  464xlat END\n", __FUNCTION__, __LINE__));
#endif
    memset(buf, 0, BUFLEN_128);
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV4_CONNECTION_STATE, buf, sizeof(buf));

    if( p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP && !strcmp(buf, WAN_STATUS_UP))
    {
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION DUAL STACK ACTIVE\n", __FUNCTION__, __LINE__, pInterface->Name));
        return WAN_STATE_DUAL_STACK_ACTIVE;
    }

    UpdateAndPersistVLANInUse(p_VirtIf);
    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION IPV6 LEASED\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_IPV6_LEASED;
}

static eWanState_t wan_transition_ipv6_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    char buf[BUFLEN_128] = {0};
#if defined(FEATURE_464XLAT)
	XLAT_State_t xlat_status;
#endif

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        p_VirtIf->Enable == FALSE ||
        p_VirtIf->Reset == TRUE ||
        p_VirtIf->VLAN.Reset == TRUE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP ||
        (p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_DOWN) ||
        (p_VirtIf->PPP.Enable == TRUE && p_VirtIf->PPP.LinkStatus != WAN_IFACE_PPP_LINK_STATUS_UP) ||
        (p_VirtIf->IP.RefreshDHCP == TRUE && ((p_VirtIf->IP.IPv6Source != DML_WAN_IP_SOURCE_DHCP && p_VirtIf->IP.IPv6Source != DML_WAN_IP_SOURCE_SLAAC) ||
        (p_VirtIf->IP.Mode != DML_WAN_IP_MODE_IPV6_ONLY && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_DUAL_STACK))))
    {
        CcspTraceInfo(("%s %d: Stopping DHCP v6\n", __FUNCTION__, __LINE__));
        DHCP_RELEASE_BEHAVIOUR release_action = STOP_DHCP_WITH_RELEASE;  // STOP_DHCP_WITH_RELEASE by default, v4 config available

        if ((pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)                                   // WAN BaseInterface Down, STOP_DHCP_WITHOUT_RELEASE
                || p_VirtIf->Reset == TRUE                                                                  // WAN Refresh going on, STOP_DHCP_WITHOUT_RELEASE
                || (p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status == WAN_IFACE_LINKSTATUS_DOWN)    // VLAN Link Down, STOP_DHCP_WITHOUT_RELEASE
                || (pInterface->Selection.RebootTriggerStatus == TRUE))           // Hardware Reconfiguration reboot going on, STOP_DHCP_WITHOUT_RELEASE
        {
            release_action = STOP_DHCP_WITHOUT_RELEASE;
        }
        WanManager_StopDhcpv6Client(p_VirtIf, release_action);
    }
    else
    {

        if(p_VirtIf->IP.Dhcp6cStatus != DHCPC_STARTED)
        {
            /* Start DHCPv6 Client */
            CcspTraceInfo(("%s %d - Starting dibbler-client on interface %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            WanManager_StartDhcpv6Client(p_VirtIf, pInterface->IfaceType);
            CcspTraceInfo(("%s %d - SELFHEAL - Started dibbler-client on interface %s\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }

    char param_name[256] = {0};
    snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv6Address",  p_VirtIf->baseIfIdx+1, p_VirtIf->VirIfIdx+1);
    WanMgr_Rbus_EventPublishHandler(param_name, "", RBUS_STRING);
    snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv6Prefix",  p_VirtIf->baseIfIdx+1, p_VirtIf->VirIfIdx+1);
    WanMgr_Rbus_EventPublishHandler(param_name, "", RBUS_STRING);
    WanManager_UpdateInterfaceStatus (p_VirtIf, WANMGR_IFACE_CONNECTION_IPV6_DOWN);

    //Disable accept_ra
    WanMgr_Configure_accept_ra(p_VirtIf, FALSE);

    if(p_VirtIf->Status == WAN_IFACE_STATUS_UP)
    {
        if (wan_tearDownIPv6(pWanIfaceCtrl) != RETURN_OK)
        {
            CcspTraceError(("%s %d - Failed to tear down IPv6 for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
#if defined(FEATURE_464XLAT)
	xlat_status = xlat_state_get();
	if(xlat_status == XLAT_ON)
	{
		CcspTraceInfo(("%s %d - STOP 464xlat\n", __FUNCTION__, __LINE__));
		xlat_process_stop(p_VirtIf->Name);
	}
#endif
    WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , FALSE);

    Update_Interface_Status();
    sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV4_CONNECTION_STATE, buf, sizeof(buf));

    if(p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP && !strcmp(buf, WAN_STATUS_UP))
    {
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION IPV4 LEASED\n", __FUNCTION__, __LINE__, pInterface->Name));
        return WAN_STATE_IPV4_LEASED;
    }

    /* RDKB-46612 - Empty set caused the cujo firewall rules to currupt and led to IHC IDLE.
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, "", 0);*/

    p_VirtIf->Status = WAN_IFACE_STATUS_VALIDATING;

    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION OBTAINING IP ADDRESSES\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_OBTAINING_IP_ADDRESSES;

}

static eWanState_t wan_transition_dual_stack_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    p_VirtIf->Status = WAN_IFACE_STATUS_VALIDATING;

    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    wan_transition_ipv4_down(pWanIfaceCtrl);
    wan_transition_ipv6_down(pWanIfaceCtrl);

    CcspTraceInfo(("%s %d - TRANSITION OBTAINING IP ADDRESSES\n", __FUNCTION__, __LINE__));
    return WAN_STATE_OBTAINING_IP_ADDRESSES;
}

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
static eWanState_t wan_transition_mapt_feature_refresh(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    wan_transition_ipv6_down(pWanIfaceCtrl);

    /* DHCPv6 client */
    p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_DOWN;
    p_VirtIf->IP.Ipv6Changed = FALSE;
    p_VirtIf->IP.Ipv6Renewed = FALSE;
    memset(&(p_VirtIf->IP.Ipv6Data), 0, sizeof(WANMGR_IPV6_DATA));
    if(p_VirtIf->IP.pIpcIpv6Data != NULL)
    {
        free(p_VirtIf->IP.pIpcIpv6Data);
        p_VirtIf->IP.pIpcIpv6Data = NULL;
    }


    if(p_VirtIf->PPP.Enable == TRUE)
    {
        /* Disbale & Enable PPP interface*/
        //TODO: NEW_DESIGN send PPP reset DM and Wait for the status
        WanManager_ConfigurePPPSession(p_VirtIf, FALSE);

        WanManager_ConfigurePPPSession(p_VirtIf, TRUE);
    }

    if ((p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_DHCP || p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_SLAAC ) &&
       (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY))
    {
        // MAPT config changed, if we got a v6 lease at this stage, send a v6 RELEASE
        WanManager_RestartDhcpv6Client(p_VirtIf, pInterface->IfaceType);
    }

    CcspTraceInfo(("%s %d - TRANSITION OBTAINING IP ADDRESSES\n", __FUNCTION__, __LINE__));

    return WAN_STATE_OBTAINING_IP_ADDRESSES; //TODO NEW_DESIGN check for new return status
}

static eWanState_t wan_transition_mapt_up(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    ANSC_STATUS ret;
    char buf[BUFLEN_128] = {0};
    char cmdEnableIpv4Traffic[BUFLEN_256] = {'\0'};

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    // verify mapt configuration
    memset(&(p_VirtIf->MAP.MaptConfig), 0, sizeof(WANMGR_MAPT_CONFIG_DATA));
    if (WanManager_VerifyMAPTConfiguration(&(p_VirtIf->MAP.dhcp6cMAPTparameters), &(p_VirtIf->MAP.MaptConfig)) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("%s %d - Error verifying MAP-T Parameters \n", __FUNCTION__, __LINE__));
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION to State=%d \n", __FUNCTION__, __LINE__, pInterface->Name, p_VirtIf->eCurrentState));
        return(p_VirtIf->eCurrentState);
    }
    else
    {
        CcspTraceInfo(("%s %d - MAPT Configuration verification success \n", __FUNCTION__, __LINE__));
    }


    p_VirtIf->MAP.MaptChanged = FALSE;

    /* if V4 data already recieved, let it configure */
    if((p_VirtIf->IP.Ipv4Changed == TRUE) && (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP))
    {
        wan_transition_ipv4_up(pWanIfaceCtrl);
    }

    // configure mapt module
    ret = wan_setUpMapt();
    if (ret != RETURN_OK)
    {
        CcspTraceError(("%s %d - Failed to configure MAP-T \n", __FUNCTION__, __LINE__));
        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pInterface->VirtIfList,0),WAN_ERROR_MAPT_STATUS_FAILED);	
    }

    if (p_VirtIf->IP.Dhcp4cStatus == DHCPC_STARTED)
    {
        // MAPT is configured, stop DHCPv4 client with RELEASE if v4 configured
        CcspTraceInfo(("%s %d: Stopping DHCP v4\n", __FUNCTION__, __LINE__));
        WanManager_StopDhcpv4Client(p_VirtIf, STOP_DHCP_WITH_RELEASE);
    }

    /* if V4 already configured, let it teardown */
    if((p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP))
    {
        wan_transition_ipv4_down(pWanIfaceCtrl);

#if defined(IVI_KERNEL_SUPPORT)
        snprintf(cmdEnableIpv4Traffic,sizeof(cmdEnableIpv4Traffic),"ip ro rep default dev %s", p_VirtIf->Name);
#elif defined(NAT46_KERNEL_SUPPORT)
        snprintf(cmdEnableIpv4Traffic, sizeof(cmdEnableIpv4Traffic), "ip ro rep default dev %s mtu %d", MAP_INTERFACE, MTU_DEFAULT_SIZE);
#endif
#ifdef FEATURE_MAPT_DEBUG
        MaptInfo("mapt: default route after v4 teardown:%s",cmdEnableIpv4Traffic);
#endif
        if (WanManager_DoSystemActionWithStatus("mapt:", cmdEnableIpv4Traffic) < RETURN_OK)
        {
            CcspTraceError(("%s %d - Failed to run: %s \n", __FUNCTION__, __LINE__, cmdEnableIpv4Traffic));
        }
    }

    if( p_VirtIf->PPP.Enable == TRUE )
    {
        WanManager_ConfigurePPPSession(p_VirtIf, FALSE);
    }

    //Enabling IP forwarding 
    CcspTraceInfo(("%s %d - net.ipv4.ip_forward set to 1 \n", __FUNCTION__, __LINE__));
    v_secure_system("sysctl -w net.ipv4.ip_forward=1");

    /* Configure MAPT. */
    if (WanManager_ProcessMAPTConfiguration(&(p_VirtIf->MAP.dhcp6cMAPTparameters), &(p_VirtIf->MAP.MaptConfig), pInterface->Name, &(p_VirtIf->IP.Ipv6Data)) != RETURN_OK)
    {
        CcspTraceError(("%s %d - Error processing MAP-T Parameters \n", __FUNCTION__, __LINE__));
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION to State=%d \n", __FUNCTION__, __LINE__, pInterface->Name, p_VirtIf->eCurrentState));
        return(p_VirtIf->eCurrentState);
    }

    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
    wanmgr_services_restart();

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION WAN_STATE_MAPT_ACTIVE\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_MAPT_ACTIVE;
}

static eWanState_t wan_transition_mapt_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    char buf[BUFLEN_128] = {0};

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    WanManager_UpdateInterfaceStatus (p_VirtIf, WANMGR_IFACE_MAPT_STOP);

    if(p_VirtIf->Status == WAN_IFACE_STATUS_UP)
    {
        if (wan_tearDownMapt() != RETURN_OK)
        {
            CcspTraceError(("%s %d - Failed to tear down MAP-T for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }

    if (WanManager_ResetMAPTConfiguration(pInterface->Name, p_VirtIf->Name) != RETURN_OK)
    {
        CcspTraceError(("%s %d Error resetting MAP-T configuration", __FUNCTION__, __LINE__));
    }

    /* Clear DHCPv4 client */
    WanManager_UpdateInterfaceStatus (p_VirtIf, WANMGR_IFACE_CONNECTION_DOWN);
    memset(&(p_VirtIf->IP.Ipv4Data), 0, sizeof(WANMGR_IPV4_DATA));

    if(p_VirtIf->IP.pIpcIpv4Data != NULL)
    {
        free(p_VirtIf->IP.pIpcIpv4Data);
        p_VirtIf->IP.pIpcIpv4Data = NULL;
    }

    if (pWanIfaceCtrl->WanEnable == TRUE &&
        pInterface->Selection.Enable == TRUE &&
        pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
        p_VirtIf->Enable == TRUE &&
        p_VirtIf->Reset == FALSE &&
        p_VirtIf->VLAN.Reset == FALSE &&
        pInterface->BaseInterfaceStatus ==  WAN_IFACE_PHY_STATUS_UP)
    {
        if( p_VirtIf->PPP.Enable == FALSE )
        {
            WanManager_StartDhcpv4Client(p_VirtIf, pInterface->Name, pInterface->IfaceType);
            CcspTraceInfo(("%s %d - Started dhcpc on interface %s\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
        else
        {
            WanManager_ConfigurePPPSession(p_VirtIf, TRUE);
        }
    }

    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION IPV6 LEASED\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_IPV6_LEASED;
}
#endif //FEATURE_MAPT

#ifdef FEATURE_DSLITE_V2
static eWanState_t wan_transition_dslite_up(WanMgr_IfaceSM_Controller_t *pWanIfaceCtrl)
{
    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE *pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    p_VirtIf->DSLite.Changed = FALSE; // Reset flag even if tunnel setup attempts fails

    if (wan_setUpDSLite(pWanIfaceCtrl) != RETURN_OK)
    {
        CcspTraceError(("%s %d - Failed to setup DS-Lite for %s, will retry after %d seconds\n",
                       __FUNCTION__, __LINE__, p_VirtIf->Name, DSLITE_RETRY_INTERVAL_SEC));
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION IPV6 LEASED \n", __FUNCTION__, __LINE__, pInterface->Name));
        return WAN_STATE_IPV6_LEASED;
    }

#ifdef FEATURE_DSLITE_V2_DUALSTACK_SUPPORT
    if (p_VirtIf->IP.Dhcp4cStatus == DHCPC_STARTED)
    {
        // DS-Lite is configured, stop DHCPv4 client with RELEASE if v4 configured
        CcspTraceInfo(("%s %d: Stopping DHCP v4\n", __FUNCTION__, __LINE__));
        WanManager_StopDhcpv4Client(p_VirtIf, STOP_DHCP_WITH_RELEASE);
    }
    if((p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP))
    {
        wan_transition_ipv4_down(pWanIfaceCtrl);
    }
#endif

    wanmgr_firewall_restart();

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION DSLITE ACTIVE\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_DSLITE_ACTIVE;
}

static eWanState_t wan_transition_dslite_down(WanMgr_IfaceSM_Controller_t *pWanIfaceCtrl)
{
    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE *pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (wan_tearDownDSLite(pWanIfaceCtrl) != RETURN_OK)
    {
        CcspTraceError(("%s %d - Failed to tear down DS-Lite for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION IPV6 LEASED \n", __FUNCTION__, __LINE__, pInterface->Name));
        return WAN_STATE_IPV6_LEASED;
    }

#if defined (FEATURE_DSLITE_V2) && defined (FEATURE_DSLITE_V2_DUALSTACK_SUPPORT)

    WanManager_UpdateInterfaceStatus (p_VirtIf, WANMGR_IFACE_CONNECTION_DOWN);
    memset(&(p_VirtIf->IP.Ipv4Data), 0, sizeof(WANMGR_IPV4_DATA));

    if(p_VirtIf->IP.pIpcIpv4Data != NULL)
    {
        free(p_VirtIf->IP.pIpcIpv4Data);
        p_VirtIf->IP.pIpcIpv4Data = NULL;
    }

    if (pWanIfaceCtrl->WanEnable == TRUE &&
        pInterface->Selection.Enable == TRUE &&
        pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
        p_VirtIf->Enable == TRUE &&
        p_VirtIf->Reset == FALSE &&
        p_VirtIf->VLAN.Reset == FALSE &&
        pInterface->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP &&
        p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK)
    {
        if (p_VirtIf->PPP.Enable == FALSE)
        {
            WanManager_StartDhcpv4Client(p_VirtIf, pInterface->Name, pInterface->IfaceType);
            CcspTraceInfo(("%s %d - Started dhcpc on interface %s\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
        else
        {
            WanManager_ConfigurePPPSession(p_VirtIf, TRUE);
        }
    }
#endif

    wanmgr_firewall_restart();

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION IPV6 LEASED\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_IPV6_LEASED;
}
#endif

static eWanState_t wan_transition_configuring_interface(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;

    // Check the interface type is cold standby then needs to be activate/deactivate at runtime
    if( WAN_IFACE_CONN_TYPE_COLD_STANDBY == pInterface->IfaceConnectionType )
    {
        // Configure Interface
        if ( ANSC_STATUS_FAILURE == WanManager_RdkBus_EnableInterface(pInterface, TRUE) )
        {
            CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION PHY CONFIGURING\n", __FUNCTION__, __LINE__, pInterface->Name));
            return WAN_STATE_PHY_CONFIGURING;
        }
    }

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION STATE PHY DOWN\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_PHY_DOWN;
}

static eWanState_t wan_transition_phy_deconfiguring(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;

    // Check the interface type is cold standby then needs to be activate/decativate at runtime
    if( WAN_IFACE_CONN_TYPE_COLD_STANDBY == pInterface->IfaceConnectionType )
    {
       // Configure Interface
       WanManager_RdkBus_EnableInterface(pInterface, FALSE);
       pInterface->BaseInterfaceStatus = WAN_IFACE_PHY_STATUS_DOWN;
    }

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION STATE PHY CONFIGURING\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_PHY_CONFIGURING;
}

static eWanState_t wan_transition_wan_deconfigured(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    p_VirtIf->Status = WAN_IFACE_STATUS_DISABLED;
    p_VirtIf->Reset = FALSE;

    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }
    else
    {
        CcspTraceError(("%s %d - WAN Control InterfaceIdx(%d) is invalid for %s\n", __FUNCTION__, __LINE__, pWanIfaceCtrl->interfaceIdx, pInterface->Name));
    }

    Update_Interface_Status();

    /* Clear DHCP data */
    WanManager_ClearDHCPData(p_VirtIf);

    WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_ERROR_WAN_DOWN);

    CcspTraceInfo(("%s %d - Interface '%s' - TRANSITION STATE PHY DOWN\n", __FUNCTION__, __LINE__, pInterface->Name));
    return WAN_STATE_PHY_DOWN;
}

static eWanState_t wan_transition_exit(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    p_VirtIf->Status = WAN_IFACE_STATUS_DISABLED;

    p_VirtIf->Reset = FALSE;

    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    Update_Interface_Status();
    CcspTraceInfo(("%s %d - Interface '%s' - EXITING STATE MACHINE\n", __FUNCTION__, __LINE__, pInterface->Name));

    WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_ERROR_WAN_DOWN);
    p_VirtIf->Interface_SM_Running = FALSE;
    
    return WAN_STATE_EXIT;
}

static eWanState_t wan_transition_standby(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    WanMgr_ProcessTelemetryMarker(p_VirtIf, WAN_INFO_WAN_STANDBY);
    p_VirtIf->Status = WAN_IFACE_STATUS_STANDBY;

    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    WanMgr_StartConnectivityCheck(pWanIfaceCtrl);

    Update_Interface_Status();
    UpdateAndPersistVLANInUse(p_VirtIf);
    CcspTraceInfo(("%s %d - TRANSITION WAN_STATE_STANDBY\n", __FUNCTION__, __LINE__));
    return WAN_STATE_STANDBY;
}

static eWanState_t wan_transition_standby_deconfig_ips(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

#ifdef FEATURE_MAPT
    if(p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)
    {
        CcspTraceInfo(("%s %d - Deconfiguring MAP-T for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        if (wan_tearDownMapt() != RETURN_OK)
        {
            CcspTraceError(("%s %d - Failed to tear down MAP-T for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }

        if (WanManager_ResetMAPTConfiguration(pInterface->Name, p_VirtIf->Name) != RETURN_OK)
        {
            CcspTraceError(("%s %d Error resetting MAP-T configuration", __FUNCTION__, __LINE__));
        }
    }
#endif

#ifdef FEATURE_DSLITE_V2
    if (p_VirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_UP)
    {
        CcspTraceInfo(("%s %d - Deconfiguring DSLite for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        if (wan_tearDownDSLite(pWanIfaceCtrl) != RETURN_OK)
        {
            CcspTraceError(("%s %d - Failed to tear down DSLite for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
#endif

    //FIXME: Currently ipoe_health_check doesn't support multiple instances. Kill the process if the inetrface is not active.
    if(p_VirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_IHC)
    {
        CcspTraceInfo(("%s %d -Moving to standby. Stopping connectivity check. %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        WanMgr_StopConnectivityCheck(pWanIfaceCtrl);
    }

    if (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP)
    {
        CcspTraceInfo(("%s %d - Deconfiguring Ipv4 for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        if (wan_tearDownIPv4(pWanIfaceCtrl) != RETURN_OK)
        {
            CcspTraceError(("%s %d - Failed to tear down IPv4 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }

    WanMgr_Configure_accept_ra(p_VirtIf, FALSE);

    if (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)
    {
        CcspTraceInfo(("%s %d - Deconfiguring Ipv6 for %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        if (wan_tearDownIPv6(pWanIfaceCtrl) != RETURN_OK)
        {
            CcspTraceError(("%s %d - Failed to tear down IPv6 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
        p_VirtIf->IP.Ipv6Changed = TRUE; //We have deconfigured Ipv6 from the device. set this flag to configure again when moves back to active.
    }

    WanMgr_ProcessTelemetryMarker(p_VirtIf, WAN_INFO_WAN_STANDBY);

    p_VirtIf->Status = WAN_IFACE_STATUS_STANDBY;
    if (pWanIfaceCtrl->interfaceIdx != -1)
    {
        WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
    }

    Update_Interface_Status();
     CcspTraceInfo(("%s %d - TRANSITION WAN_STATE_STANDBY\n", __FUNCTION__, __LINE__));
    return WAN_STATE_STANDBY;
}

/*********************************************************************************/
/**************************** STATES *********************************************/
/*********************************************************************************/
static eWanState_t wan_state_phy_configuring(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
            pInterface->Selection.Enable == FALSE ||
            p_VirtIf->Enable == FALSE ||
            pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED)
    {
        return wan_transition_exit(pWanIfaceCtrl);
    }

    return wan_transition_configuring_interface(pWanIfaceCtrl);
}

static eWanState_t wan_state_phy_down(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
            pInterface->Selection.Enable == FALSE ||
            p_VirtIf->Enable == FALSE ||
            pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED)
    {
        return wan_transition_phy_deconfiguring(pWanIfaceCtrl);
    }

    if ( pInterface->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP )
    {
        return wan_transition_vlan_configure(pWanIfaceCtrl);
    }

    return WAN_STATE_PHY_DOWN;
}

static eWanState_t wan_state_vlan_configuring(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
            pInterface->Selection.Enable == FALSE ||
            p_VirtIf->Enable == FALSE ||
            pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
            pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }

    if ((p_VirtIf->VLAN.NoOfInterfaceEntries > 1) && // Multiple VLANs configured, we can do discovery
        !(p_VirtIf->VLAN.DiscoveryMode == VLAN_DISCOVERY_MODE_ONCE && strlen(p_VirtIf->VLAN.VLANInUse) > 0)) // If discovery mode is ONCE and we have already discovered a VLAN, skip the vlan discovery check
    {
        struct timespec CurrentTime;
        /* get the current time */
        memset(&(CurrentTime), 0, sizeof(struct timespec));
        clock_gettime(CLOCK_MONOTONIC_RAW, &(CurrentTime));

        if(p_VirtIf->VLAN.Reset == TRUE || difftime(CurrentTime.tv_sec, p_VirtIf->VLAN.TimerStart.tv_sec) > p_VirtIf->VLAN.Timeout)
        {
            CcspTraceInfo(("%s %d VlanDiscovery timer expired.\n", __FUNCTION__, __LINE__));
            p_VirtIf->VLAN.Expired = TRUE;
            return wan_transition_physical_interface_down(pWanIfaceCtrl);
        }
    }

    if(p_VirtIf->VLAN.Enable == TRUE)
    {
        if(p_VirtIf->VLAN.Status !=  WAN_IFACE_LINKSTATUS_UP)
        {
            return WAN_STATE_VLAN_CONFIGURING;
        }

#if defined(_DT_WAN_Manager_Enable_)
        /* VLAN status is successful. Add QOS markings*/
        //TODO: This is not a sky use case currently. For Sky markings are applied from VLAN Manager.
        WanManager_ConfigureMarking(pWanIfaceCtrl);
#endif
    }
    else
    {
        CcspTraceInfo(("%s %d VLAN not enabled. Moivng to wan_transition_ppp_configure \n", __FUNCTION__, __LINE__));
    }
    //TODO: NEW_DESIGN check for Cellular case
    return wan_transition_ppp_configure(pWanIfaceCtrl);
}

static eWanState_t wan_state_ppp_configuring(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
            pInterface->Selection.Enable == FALSE ||
            pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
            p_VirtIf->Enable == FALSE ||
            pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }


    if ((p_VirtIf->VLAN.NoOfInterfaceEntries > 1) && // Multiple VLANs configured, we can do discovery
        !(p_VirtIf->VLAN.DiscoveryMode == VLAN_DISCOVERY_MODE_ONCE && strlen(p_VirtIf->VLAN.VLANInUse) > 0)) // If discovery mode is ONCE and we have already discovered a VLAN, skip the vlan discovery check
    {
        struct timespec CurrentTime;
        /* get the current time */
        memset(&(CurrentTime), 0, sizeof(struct timespec));
        clock_gettime(CLOCK_MONOTONIC_RAW, &(CurrentTime));

        if(p_VirtIf->VLAN.Reset == TRUE || difftime(CurrentTime.tv_sec, p_VirtIf->VLAN.TimerStart.tv_sec) > p_VirtIf->VLAN.Timeout)
        {
            CcspTraceInfo(("%s %d VlanDiscovery timer expired.\n", __FUNCTION__, __LINE__));
            p_VirtIf->VLAN.Expired = TRUE;
            return wan_transition_physical_interface_down(pWanIfaceCtrl);
        }
    }

    if(p_VirtIf->PPP.Enable == TRUE)
    {
        if(p_VirtIf->PPP.LinkStatus ==  WAN_IFACE_PPP_LINK_STATUS_UP && 
                !((p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_DHCP && 
                (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY)) && 
                p_VirtIf->PPP.IPV6CPStatus != WAN_IFACE_IPV6CP_STATUS_UP)) //If dhcpv6 used on PPP interface wait for IPv6cp status
        {
            return wan_transition_wan_up(pWanIfaceCtrl);
        }
    }else
    {
        CcspTraceInfo(("%s %d PPP not enabled. Moivng to wan_transition_wan_up \n", __FUNCTION__, __LINE__));
        return wan_transition_wan_up(pWanIfaceCtrl);
    }

    return WAN_STATE_PPP_CONFIGURING;
}

static eWanState_t wan_state_validating_wan(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
            pInterface->Selection.Enable == FALSE ||
            pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
            p_VirtIf->Enable == FALSE ||
            pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }

    if ((p_VirtIf->VLAN.NoOfInterfaceEntries > 1) && // Multiple VLANs configured, we can do discovery
        !(p_VirtIf->VLAN.DiscoveryMode == VLAN_DISCOVERY_MODE_ONCE && strlen(p_VirtIf->VLAN.VLANInUse) > 0)) // If discovery mode is ONCE and we have already discovered a VLAN, skip the vlan discovery check
    {
        struct timespec CurrentTime;
        /* get the current time */
        memset(&(CurrentTime), 0, sizeof(struct timespec));
        clock_gettime(CLOCK_MONOTONIC_RAW, &(CurrentTime));

        if(p_VirtIf->VLAN.Reset == TRUE || difftime(CurrentTime.tv_sec, p_VirtIf->VLAN.TimerStart.tv_sec) > p_VirtIf->VLAN.Timeout)
        {
            CcspTraceInfo(("%s %d VlanDiscovery timer expired.\n", __FUNCTION__, __LINE__));
            p_VirtIf->VLAN.Expired = TRUE;
            return wan_transition_physical_interface_down(pWanIfaceCtrl);
        }
    }

    //Check whether virtual interface is Up and Running or not to proceed further
    if ( FALSE == WanManager_IsNetworkInterfaceUp( p_VirtIf->Name ))
    {
        CcspTraceError(("%s %d: Interface '%s' is not ready\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        return WAN_STATE_VALIDATING_WAN;
    }

    //TODO: VLAN and PPP are validated in previous states. Use this state to validate WAN interface that does not use PPP or VLAN
    return wan_transition_wan_validated(pWanIfaceCtrl);

}

static eWanState_t wan_state_obtaining_ip_addresses(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        p_VirtIf->Enable == FALSE ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP ||
        p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_CONFIGURING ||
        p_VirtIf->PPP.LinkStatus ==  WAN_IFACE_PPP_LINK_STATUS_CONFIGURING ||
        p_VirtIf->Reset == TRUE)
    {
        if ((0 == strcmp("DATA", p_VirtIf->Alias)) || (0 == strcmp("VOIP", p_VirtIf->Alias)))
        {
            /* Update voice interface name to TelcoVoiceManager */
            updateInterfaceToVoiceManager(pWanIfaceCtrl, false);
        }

        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }

    struct timespec CurrentTime;
    /* get the current time */
    memset(&(CurrentTime), 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC_RAW, &(CurrentTime));

    if (((p_VirtIf->VLAN.NoOfInterfaceEntries > 1) && // Multiple VLANs configured, we can do discovery
        !(p_VirtIf->VLAN.DiscoveryMode == VLAN_DISCOVERY_MODE_ONCE && strlen(p_VirtIf->VLAN.VLANInUse) > 0) && // If discovery mode is ONCE and we have already discovered a VLAN, skip the vlan discovery check
       (p_VirtIf->VLAN.Reset == TRUE || difftime(CurrentTime.tv_sec, p_VirtIf->VLAN.TimerStart.tv_sec) > p_VirtIf->VLAN.Timeout))||
       (p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_DOWN ) ||
       (p_VirtIf->PPP.Enable == TRUE && p_VirtIf->PPP.LinkStatus ==  WAN_IFACE_PPP_LINK_STATUS_DOWN))
    {
        CcspTraceInfo(("%s %d VlanDiscovery timer expired Or VLAN/PPP status DOWN \n", __FUNCTION__, __LINE__));
        p_VirtIf->VLAN.Expired = TRUE;

        if ((0 == strcmp("DATA", p_VirtIf->Alias)) || (0 == strcmp("VOIP", p_VirtIf->Alias)))
        {
            /* Update voice interface name to TelcoVoiceManager */
            updateInterfaceToVoiceManager(pWanIfaceCtrl, false);
        }

        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }

    if (p_VirtIf->IP.SelectedMode == MAPT_MODE ||
        p_VirtIf->IP.SelectedMode == DSLITE_MODE)
    {
        bool is_mapt = p_VirtIf->IP.SelectedMode == MAPT_MODE;
        const char *mode_str = is_mapt ? "MAPT" : "DSLITE";
        bool iface_state_up = is_mapt
                                  ? (p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)
                                  : (p_VirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_UP);

        if (iface_state_up)
        {
            p_VirtIf->IP.SelectedModeTimerStatus = COMPLETE;
            CcspTraceInfo(("%s %d %s option received in %s Preferred Mode - Timer complete \n", __FUNCTION__, __LINE__, mode_str, mode_str));
        }
        else if (p_VirtIf->IP.SelectedModeTimerStatus == RUNNING)
        {
            if (difftime(CurrentTime.tv_sec, p_VirtIf->IP.SelectedModeTimerStart.tv_sec) > SELECTED_MODE_TIMEOUT_SECONDS ||
                p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)
            {
                p_VirtIf->IP.SelectedModeTimerStatus = EXPIRED;
                CcspTraceInfo(("%s %d %s option not received in %s Preferred Mode - Timer Expired \n", __FUNCTION__, __LINE__, mode_str, mode_str));
                return wan_transition_wan_validated(pWanIfaceCtrl);
            }
            return WAN_STATE_OBTAINING_IP_ADDRESSES;
        }
    }

    // Ip source changed changed to TRUE
    if (p_VirtIf->IP.RefreshDHCP == TRUE)
    {
        if(p_VirtIf->IP.IPv4Source == DML_WAN_IP_SOURCE_DHCP &&
           (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV4_ONLY || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK))
        {
            if(p_VirtIf->IP.Dhcp4cStatus != DHCPC_STARTED)
            {
                WanManager_StartDhcpv4Client(p_VirtIf, pInterface->Name, pInterface->IfaceType);
            }
        }else if(p_VirtIf->IP.Dhcp4cStatus == DHCPC_STARTED)
        {
            // DHCP config changed, if we got a v4 lease at this stage, send a v4 RELEASE
            CcspTraceInfo(("%s %d: Stopping DHCP v4\n", __FUNCTION__, __LINE__));
            WanManager_StopDhcpv4Client(p_VirtIf, STOP_DHCP_WITH_RELEASE);
        }

        if((p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_DHCP || p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_SLAAC ) && 
           (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK))
        {
            if(p_VirtIf->IP.Dhcp6cStatus != DHCPC_STARTED) 
            {
                WanManager_StartDhcpv6Client(p_VirtIf, pInterface->IfaceType);
            }
        }
        else if (p_VirtIf->IP.Dhcp6cStatus == DHCPC_STARTED)
        {
            // DHCP config changed, if we got a v6 lease at this stage, send a v6 RELEASE
            CcspTraceInfo(("%s %d: Stopping DHCP v6\n", __FUNCTION__, __LINE__));
            WanManager_StopDhcpv6Client(p_VirtIf, STOP_DHCP_WITH_RELEASE); // release dhcp lease
        }

        if ((p_VirtIf->IP.Dhcp4cStatus != DHCPC_STARTED) && (p_VirtIf->IP.Dhcp6cStatus != DHCPC_STARTED))
        {
            p_VirtIf->Status = WAN_IFACE_STATUS_VALIDATING;
            if (pWanIfaceCtrl->interfaceIdx != -1)
            {
                WanMgr_Publish_WanStatus(pWanIfaceCtrl->interfaceIdx, pWanIfaceCtrl->VirIfIdx);
            }
        }
        p_VirtIf->IP.RefreshDHCP = FALSE;

        return WAN_STATE_OBTAINING_IP_ADDRESSES;
    }

    // Start DHCP apps if not started
    WanMgr_MonitorDhcpApps(pWanIfaceCtrl);

    if (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP)
    {
        if (pInterface->Selection.Status == WAN_IFACE_ACTIVE)
        {
            return wan_transition_ipv4_up(pWanIfaceCtrl);
        }
        else
        {
            return wan_transition_standby(pWanIfaceCtrl);
        }
    }
    else if (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)
    {
        if (pInterface->Selection.Status == WAN_IFACE_ACTIVE)
        {
            if(p_VirtIf->IP.Ipv6Changed == TRUE)
            {
                /* Set sysevents to trigger P&M */
                if (setUpLanPrefixIPv6(p_VirtIf) != RETURN_OK)
                {
                    CcspTraceError((" %s %d - Failed to configure IPv6 prefix \n", __FUNCTION__, __LINE__));
                }
                /* Reset isIPv6ConfigChanged  */
                p_VirtIf->IP.Ipv6Changed = FALSE;
                return WAN_STATE_OBTAINING_IP_ADDRESSES;
            }
            if (checkIpv6LanAddressIsReadyToUse(p_VirtIf) == RETURN_OK)
            {
                return wan_transition_ipv6_up(pWanIfaceCtrl);
            }
        }
        else
        {
            return wan_transition_standby(pWanIfaceCtrl);
        }
    }
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    else if (p_VirtIf->EnableMAPT == TRUE &&
            pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
            mapt_feature_enable_changed == TRUE &&
            p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_DOWN)
    {
        if (TRUE == wanmanager_mapt_feature())
        {
            mapt_feature_enable_changed = FALSE;
            return wan_transition_mapt_feature_refresh(pWanIfaceCtrl);
        }
    }
#endif

    return WAN_STATE_OBTAINING_IP_ADDRESSES;
}

static eWanState_t wan_state_standby(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    eWanState_t ret = WAN_STATE_STANDBY;

    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        p_VirtIf->Enable == FALSE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }

    // Start DHCP apps if not started
    WanMgr_MonitorDhcpApps(pWanIfaceCtrl);

    if ((p_VirtIf->VLAN.Enable == TRUE &&  p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_DOWN) ||
             (p_VirtIf->PPP.Enable == TRUE && p_VirtIf->PPP.LinkStatus != WAN_IFACE_PPP_LINK_STATUS_UP)|| // PPP is Enabled but DOWN
             (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_DOWN &&
             p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_DOWN) ||
             p_VirtIf->IP.RefreshDHCP == TRUE)
    {
        return WAN_STATE_OBTAINING_IP_ADDRESSES;
    }
    else if (pInterface->Selection.Status == WAN_IFACE_ACTIVE)
    {
        if (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)
        {
            if (p_VirtIf->IP.Ipv6Changed == TRUE)
            {
                if (setUpLanPrefixIPv6(p_VirtIf) == RETURN_OK)
                {
                    CcspTraceInfo((" %s %d - configure IPv6 prefix \n", __FUNCTION__, __LINE__));
                }
                p_VirtIf->IP.Ipv6Changed = FALSE;
            }
            if (checkIpv6LanAddressIsReadyToUse(p_VirtIf) == RETURN_OK)
            {
                ret = wan_transition_ipv6_up(pWanIfaceCtrl);
                CcspTraceInfo((" %s %d - IPv6 Address Assigned to Bridge Yet.\n", __FUNCTION__, __LINE__));
            }
        }
        if (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP)
        {
            ret = wan_transition_ipv4_up(pWanIfaceCtrl);
        }
        return ret;
    }

    //FIXME : IPoE health check won't work if the interface is standby
    if(p_VirtIf->IP.RestartConnectivityCheck == TRUE && p_VirtIf->IP.ConnectivityCheckType == WAN_CONNECTIVITY_TYPE_TAD)
    {
        WanMgr_StartConnectivityCheck(pWanIfaceCtrl);
    }

    return WAN_STATE_STANDBY;
}

static eWanState_t wan_state_ipv4_leased(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    //Start dhcpv6 client if Ip mode changed runtime
    if(p_VirtIf->IP.RefreshDHCP == TRUE &&
      ( p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_DHCP || p_VirtIf->IP.IPv6Source == DML_WAN_IP_SOURCE_SLAAC ) &&
      p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK &&
      p_VirtIf->IP.Dhcp6cStatus != DHCPC_STARTED && p_VirtIf->IP.Dhcp6cStatus != DHCPC_DISABLED)
    {
        /* Start DHCPv6 Client */
        WanManager_StartDhcpv6Client(p_VirtIf, pInterface->IfaceType);
        CcspTraceInfo(("%s %d - Started dhcpv6 client on interface %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        CcspTraceInfo(("%s %d - Interface '%s' - Running in Dual Stack IP Mode\n", __FUNCTION__, __LINE__, pInterface->Name));
    }

    // Start DHCP apps if not started
    WanMgr_MonitorDhcpApps(pWanIfaceCtrl);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        p_VirtIf->Enable == FALSE ||
        p_VirtIf->Reset == TRUE ||
        p_VirtIf->VLAN.Reset == TRUE ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }
    else if (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_DOWN ||
            (p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_DOWN )||
            (p_VirtIf->PPP.Enable == TRUE && p_VirtIf->PPP.LinkStatus != WAN_IFACE_PPP_LINK_STATUS_UP) || // PPP is Enabled but DOWN
            (p_VirtIf->IP.RefreshDHCP == TRUE && (p_VirtIf->IP.IPv4Source != DML_WAN_IP_SOURCE_DHCP ||    // IPv4Source not dhcp
            (p_VirtIf->IP.Mode != DML_WAN_IP_MODE_IPV4_ONLY && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_DUAL_STACK))))
    {
        return wan_transition_ipv4_down(pWanIfaceCtrl);
    }
    else if ((pInterface->Selection.Status != WAN_IFACE_ACTIVE) || (pWanIfaceCtrl->DeviceNwModeChanged == TRUE))
    {
        return wan_transition_standby_deconfig_ips(pWanIfaceCtrl);
    }
    else if (p_VirtIf->IP.Ipv4Changed == TRUE)
    {
        if (wan_tearDownIPv4(pWanIfaceCtrl) == RETURN_OK)
        {
            if (wan_setUpIPv4(pWanIfaceCtrl) == RETURN_OK)
            {
                WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV4 , TRUE);
                p_VirtIf->IP.Ipv4Changed = FALSE;
                CcspTraceInfo(("%s %d - Successfully updated IPv4 configure Changes for %s Interface \n",
                            __FUNCTION__, __LINE__, p_VirtIf->Name));
            }
            else
            {
                CcspTraceError(("%s %d - Failed to configure IPv4 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            }
        }
        else
        {
            CcspTraceError(("%s %d - Failed to tear down IPv4 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
    else if (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)
    {
        if(p_VirtIf->IP.Ipv6Changed == TRUE)
        {
            /* Set sysevents to trigger P&M */
            if (setUpLanPrefixIPv6(p_VirtIf) != RETURN_OK)
            {
                CcspTraceError((" %s %d - Failed to configure IPv6 prefix \n", __FUNCTION__, __LINE__));
            }
            /* Reset isIPv6ConfigChanged  */
            p_VirtIf->IP.Ipv6Changed = FALSE;
            return WAN_STATE_IPV4_LEASED;
        }
        if (checkIpv6LanAddressIsReadyToUse(p_VirtIf) == RETURN_OK)
        {
            return wan_transition_ipv6_up(pWanIfaceCtrl);
        }
    }
    else if (p_VirtIf->IP.Ipv4Renewed == TRUE)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV4 , TRUE);
        p_VirtIf->IP.Ipv4Renewed = FALSE;
    }
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    else if (p_VirtIf->EnableMAPT == TRUE &&
            pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
            mapt_feature_enable_changed == TRUE &&
            p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_DOWN)
    {
        if (TRUE == wanmanager_mapt_feature())
        {
            mapt_feature_enable_changed = FALSE;
            return wan_transition_mapt_feature_refresh(pWanIfaceCtrl);
        }
    }
#endif

    return WAN_STATE_IPV4_LEASED;
}

static eWanState_t wan_state_ipv6_leased(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    //Start dhcpv4 client if Ip mode changed runtime
    if(p_VirtIf->IP.RefreshDHCP == TRUE && 
      p_VirtIf->IP.IPv4Source == DML_WAN_IP_SOURCE_DHCP &&
      p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK &&
      p_VirtIf->IP.SelectedModeTimerStatus != COMPLETE &&
      p_VirtIf->IP.Dhcp4cStatus != DHCPC_STARTED)
    {
        WanManager_StartDhcpv4Client(p_VirtIf, pInterface->Name, pInterface->IfaceType);
        CcspTraceInfo(("%s %d - Started dhcpc on interface %s\n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        CcspTraceInfo(("%s %d - Interface '%s' - Running in Dual Stack IP Mode\n", __FUNCTION__, __LINE__, pInterface->Name));
    }

    // Start DHCP apps if not started
    WanMgr_MonitorDhcpApps(pWanIfaceCtrl); 

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        p_VirtIf->Enable == FALSE ||
        p_VirtIf->Reset == TRUE ||
        p_VirtIf->VLAN.Reset == TRUE ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }
    else if (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_DOWN ||
             (p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_DOWN )||
             (p_VirtIf->PPP.Enable == TRUE && p_VirtIf->PPP.LinkStatus != WAN_IFACE_PPP_LINK_STATUS_UP)|| // PPP is Enabled but DOWN
            (p_VirtIf->IP.RefreshDHCP == TRUE && ((p_VirtIf->IP.IPv6Source != DML_WAN_IP_SOURCE_DHCP && p_VirtIf->IP.IPv6Source != DML_WAN_IP_SOURCE_SLAAC ) ||    // Ipv6source is not dhcp
            (p_VirtIf->IP.Mode != DML_WAN_IP_MODE_IPV6_ONLY && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_DUAL_STACK))))
    {
        return wan_transition_ipv6_down(pWanIfaceCtrl);
    }
    else if ((pInterface->Selection.Status != WAN_IFACE_ACTIVE)  || (pWanIfaceCtrl->DeviceNwModeChanged == TRUE))
    {
        return wan_transition_standby_deconfig_ips(pWanIfaceCtrl);
    }
    else if (p_VirtIf->IP.Ipv6Changed == TRUE)
    {
        if (wan_tearDownIPv6(pWanIfaceCtrl) == RETURN_OK)
        {
            if (setUpLanPrefixIPv6(p_VirtIf) == RETURN_OK)
            {
                if (wan_setUpIPv6(pWanIfaceCtrl) == RETURN_OK)
                {
                    WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
                    p_VirtIf->IP.Ipv6Changed = FALSE;
                    CcspTraceInfo(("%s %d - Successfully updated IPv6 configure Changes for %s Interface \n",
                                    __FUNCTION__, __LINE__, p_VirtIf->Name));
                }
                else
                {
                    CcspTraceError(("%s %d - Failed to configure IPv6 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
                }
            }
            else
            {
                CcspTraceError((" %s %d - Failed to configure IPv6 prefix for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            }
        }
        else
        {
            CcspTraceError(("%s %d - Failed to tear down IPv6 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
    else if (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP)
    {
        return wan_transition_ipv4_up(pWanIfaceCtrl);
    }
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    else if (p_VirtIf->EnableMAPT == TRUE &&
            pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
            p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)
    {
        if (checkIpv6LanAddressIsReadyToUse(p_VirtIf) == RETURN_OK) // Wait for default gateway before MAP-T configuration
        {
            return wan_transition_mapt_up(pWanIfaceCtrl);
        } 
    }
    else if (p_VirtIf->EnableMAPT == TRUE &&
             pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
             mapt_feature_enable_changed == TRUE &&
             p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_DOWN)
    {
        if (TRUE == wanmanager_mapt_feature())
        {
            mapt_feature_enable_changed = FALSE;
            return wan_transition_mapt_feature_refresh(pWanIfaceCtrl);
        }
    }
#endif //FEATURE_MAPT

#ifdef FEATURE_DSLITE_V2
    else if (WanMgr_DSLite_isEnabled(p_VirtIf) == TRUE &&
             WanMgr_DSLite_isEndpointAssigned(p_VirtIf) == TRUE &&
             pInterface->Selection.Status == WAN_IFACE_ACTIVE)
    {
        if (p_VirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_DOWN)
        {
            if (checkIpv6LanAddressIsReadyToUse(p_VirtIf) == RETURN_OK)
            {
                return wan_transition_dslite_up(pWanIfaceCtrl);
            }
        }
        else if (p_VirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_ERROR)
        {
            struct timespec CurrentTime;
            clock_gettime(CLOCK_MONOTONIC_RAW, &CurrentTime);

            time_t elapsed = (CurrentTime.tv_sec - p_VirtIf->DSLite.LastRetryTime.tv_sec);

            // Immediate retry only if there was a change in DSLite params
            if (p_VirtIf->DSLite.Changed == TRUE || elapsed >= DSLITE_RETRY_INTERVAL_SEC)
            {
                CcspTraceInfo(("%s - Retrying DSLite setup for %s after %ld seconds [DS-Lite Cfg changed=%s]\n",
                               __FUNCTION__, p_VirtIf->Name, elapsed, p_VirtIf->DSLite.Changed ? "true" : "false"));
                p_VirtIf->DSLite.Status = WAN_IFACE_DSLITE_STATE_DOWN; // let the next iteration handle it
            }
        }
    }
#endif
    else if (p_VirtIf->IP.Ipv6Renewed == TRUE)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
        p_VirtIf->IP.Ipv6Renewed = FALSE;
    }

    WanMgr_CheckDefaultRA(p_VirtIf);

#if defined(FEATURE_IPOE_HEALTH_CHECK) && defined(IPOE_HEALTH_CHECK_LAN_SYNC_SUPPORT)
    if(lanState == LAN_STATE_STOPPED)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , FALSE);
        lanState = LAN_STATE_RESET;
    }
    else if(lanState == LAN_STATE_STARTED)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
        lanState = LAN_STATE_RESET;
    }
#endif
    return WAN_STATE_IPV6_LEASED;
}

static eWanState_t wan_state_dual_stack_active(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        p_VirtIf->Enable == FALSE ||
        p_VirtIf->Reset == TRUE ||
        p_VirtIf->VLAN.Reset == TRUE ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }
    else if ((p_VirtIf->VLAN.Enable == TRUE &&  p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_DOWN)   // VLAN is Enabled but Down
            || (p_VirtIf->PPP.Enable == TRUE && p_VirtIf->PPP.LinkStatus != WAN_IFACE_PPP_LINK_STATUS_UP)) // PPP is Enabled but DOWN
    {
        return wan_transition_dual_stack_down(pWanIfaceCtrl);
    }
    else if (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_DOWN ||
            (p_VirtIf->IP.RefreshDHCP == TRUE && ( p_VirtIf->IP.IPv4Source != DML_WAN_IP_SOURCE_DHCP ||
            (p_VirtIf->IP.Mode != DML_WAN_IP_MODE_DUAL_STACK && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_IPV4_ONLY))))
    {
        /* TODO: Add IPoE Health Check failed for IPv4 here */
        return wan_transition_ipv4_down(pWanIfaceCtrl);
    }
    else if ((pInterface->Selection.Status != WAN_IFACE_ACTIVE) || (pWanIfaceCtrl->DeviceNwModeChanged == TRUE))
    {
        return wan_transition_standby_deconfig_ips(pWanIfaceCtrl);
    }

    else if (p_VirtIf->IP.Ipv4Changed == TRUE)
    {
        if (wan_tearDownIPv4(pWanIfaceCtrl) == RETURN_OK)
        {
            if (wan_setUpIPv4(pWanIfaceCtrl) == RETURN_OK)
            {
                WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV4 , TRUE);
                p_VirtIf->IP.Ipv4Changed = FALSE;
                CcspTraceInfo(("%s %d - Successfully updated IPv4 configure Changes for %s Interface \n",
                            __FUNCTION__, __LINE__, p_VirtIf->Name));
            }
            else
            {
                CcspTraceError(("%s %d - Failed to configure IPv4 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            }
        }
        else
        {
            CcspTraceError(("%s %d - Failed to tear down IPv4 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
    else if (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_DOWN ||
            (p_VirtIf->IP.RefreshDHCP == TRUE && ( ( p_VirtIf->IP.IPv6Source != DML_WAN_IP_SOURCE_DHCP && p_VirtIf->IP.IPv6Source != DML_WAN_IP_SOURCE_SLAAC ) ||
            (p_VirtIf->IP.Mode != DML_WAN_IP_MODE_DUAL_STACK && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_IPV6_ONLY))))
    {
        /* TODO: Add IPoE Health Check failed for IPv6 here */
        return wan_transition_ipv6_down(pWanIfaceCtrl);
    }
    else if (p_VirtIf->IP.Ipv6Changed == TRUE)
    {
        if (wan_tearDownIPv6(pWanIfaceCtrl) == RETURN_OK)
        {
            if (setUpLanPrefixIPv6(p_VirtIf) == RETURN_OK)
            {
                if (wan_setUpIPv6(pWanIfaceCtrl) == RETURN_OK)
                {
                    WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
                    p_VirtIf->IP.Ipv6Changed = FALSE;
                    CcspTraceInfo(("%s %d - Successfully updated IPv6 configure Changes for %s Interface \n",
                                __FUNCTION__, __LINE__, p_VirtIf->Name));
                }
                else
                {
                    CcspTraceError(("%s %d - Failed to configure IPv6 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
                }
            }
            else
            {
                CcspTraceError((" %s %d - Failed to configure IPv6 prefix for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            }
        }
        else
        {
            CcspTraceError(("%s %d - Failed to tear down IPv6 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    else if (p_VirtIf->EnableMAPT == TRUE &&
            pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
            p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)
    {
        if (checkIpv6LanAddressIsReadyToUse(p_VirtIf) == RETURN_OK) // Wait for default gateway before MAP-T configuration
        {
            return wan_transition_mapt_up(pWanIfaceCtrl);
        }
    }
    else if (p_VirtIf->EnableMAPT == TRUE &&
            pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
            mapt_feature_enable_changed == TRUE &&
            p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_DOWN)
    {
        if (TRUE == wanmanager_mapt_feature())
        {
            mapt_feature_enable_changed = FALSE;
            return wan_transition_mapt_feature_refresh(pWanIfaceCtrl);
        }
    }
#endif //FEATURE_MAPT
#if defined (FEATURE_DSLITE_V2) && defined (FEATURE_DSLITE_V2_DUALSTACK_SUPPORT)
    else if (WanMgr_DSLite_isEnabled(p_VirtIf) == TRUE &&
             WanMgr_DSLite_isEndpointAssigned(p_VirtIf) == TRUE &&
             pInterface->Selection.Status == WAN_IFACE_ACTIVE)
    {
        if (p_VirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_DOWN)
        {
            if (checkIpv6LanAddressIsReadyToUse(p_VirtIf) == RETURN_OK)
            {
                return wan_transition_dslite_up(pWanIfaceCtrl);
            }
        }
        else if (p_VirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_ERROR)
        {
            struct timespec CurrentTime;
            clock_gettime(CLOCK_MONOTONIC_RAW, &CurrentTime);

            time_t elapsed = (CurrentTime.tv_sec - p_VirtIf->DSLite.LastRetryTime.tv_sec);

            // Immediate retry only if there was a change in DSLite params
            if (p_VirtIf->DSLite.Changed == TRUE || elapsed >= DSLITE_RETRY_INTERVAL_SEC)
            {
                CcspTraceInfo(("%s - Retrying DSLite setup for %s after %ld seconds [DS-Lite Cfg changed=%s]\n",
                               __FUNCTION__, p_VirtIf->Name, elapsed, p_VirtIf->DSLite.Changed ? "true" : "false"));
                p_VirtIf->DSLite.Status = WAN_IFACE_DSLITE_STATE_DOWN; // let the next iteration handle it
            }
        }
    }
#endif // FEATURE_DSLITE_V2
    else if (p_VirtIf->IP.Ipv4Renewed == TRUE)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV4 , TRUE);
        p_VirtIf->IP.Ipv4Renewed = FALSE;
    }
    else if (p_VirtIf->IP.Ipv6Renewed == TRUE)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
        p_VirtIf->IP.Ipv6Renewed = FALSE;
    }

    // Start DHCP apps if not started
    WanMgr_MonitorDhcpApps(pWanIfaceCtrl);
    WanMgr_CheckDefaultRA(p_VirtIf);

#if defined(FEATURE_IPOE_HEALTH_CHECK) && defined(IPOE_HEALTH_CHECK_LAN_SYNC_SUPPORT)
    if(lanState == LAN_STATE_STOPPED)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , FALSE);
        lanState = LAN_STATE_RESET;
    }
    else if(lanState == LAN_STATE_STARTED)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
        lanState = LAN_STATE_RESET;
    }
#endif
    return WAN_STATE_DUAL_STACK_ACTIVE;
}

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
static eWanState_t wan_state_mapt_active(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        p_VirtIf->Enable == FALSE ||
        p_VirtIf->Reset == TRUE ||
        p_VirtIf->VLAN.Reset == TRUE ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }
    else if ((pInterface->Selection.Status != WAN_IFACE_ACTIVE) || (pWanIfaceCtrl->DeviceNwModeChanged == TRUE))
    {
        return wan_transition_standby_deconfig_ips(pWanIfaceCtrl);
    }
    else if (p_VirtIf->EnableMAPT == FALSE ||
            p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_DOWN ||
            p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_DOWN ||
            (p_VirtIf->IP.RefreshDHCP == TRUE && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_IPV6_ONLY && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_DUAL_STACK)||
            (p_VirtIf->VLAN.Enable == TRUE &&  p_VirtIf->VLAN.Status ==  WAN_IFACE_LINKSTATUS_DOWN ))
    {
        CcspTraceInfo(("%s %d - LinkStatus=[%d] \n", __FUNCTION__, __LINE__, p_VirtIf->VLAN.Status));
        return wan_transition_mapt_down(pWanIfaceCtrl);
    }
    else if (mapt_feature_enable_changed == TRUE)
    {
        if (FALSE == wanmanager_mapt_feature())
        {
            mapt_feature_enable_changed = FALSE;
            wan_transition_mapt_down(pWanIfaceCtrl);
            return wan_transition_mapt_feature_refresh(pWanIfaceCtrl);
        }
    }
    else if (p_VirtIf->IP.Ipv6Changed == TRUE)
    {
        if (wan_tearDownIPv6(pWanIfaceCtrl) == RETURN_OK)
        {
            if (setUpLanPrefixIPv6(p_VirtIf) == RETURN_OK)
            {
                if (wan_setUpIPv6(pWanIfaceCtrl) == RETURN_OK)
                {
                    WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
                    p_VirtIf->IP.Ipv6Changed = FALSE;
                    CcspTraceInfo(("%s %d - Successfully updated IPv6 configure Changes for %s Interface \n",
                                __FUNCTION__, __LINE__, p_VirtIf->Name));

                    if (p_VirtIf->EnableMAPT == TRUE &&
                            pInterface->Selection.Status == WAN_IFACE_ACTIVE &&
                            p_VirtIf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)
                    {
                        p_VirtIf->MAP.MaptChanged = TRUE; // Reconfigure MAPT if V6 Updated
                    }
                }
                else
                {
                    CcspTraceError(("%s %d - Failed to configure IPv6 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
                }
            }
            else
            {
                CcspTraceError((" %s %d - Failed to configure IPv6 prefix for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            }
        }
        else
        {
            CcspTraceError(("%s %d - Failed to tear down IPv6 for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
#if defined(FEATURE_MAPT)
    else if (p_VirtIf->MAP.MaptChanged == TRUE)
    {
        if (wan_tearDownMapt() == RETURN_OK)
        {
            if (WanManager_ResetMAPTConfiguration(pInterface->Name, p_VirtIf->Name) != RETURN_OK)
            {
                CcspTraceError(("%s %d Error resetting MAP-T configuration", __FUNCTION__, __LINE__));
            }

            if (wan_setUpMapt() == RETURN_OK)
            {
                memset(&(p_VirtIf->MAP.MaptConfig), 0, sizeof(WANMGR_MAPT_CONFIG_DATA));
                if (WanManager_VerifyMAPTConfiguration(&(p_VirtIf->MAP.dhcp6cMAPTparameters), &(p_VirtIf->MAP.MaptConfig)) == ANSC_STATUS_SUCCESS)
                {
                    CcspTraceInfo(("%s %d - MAPT Configuration verification success \n", __FUNCTION__, __LINE__));
                    if (WanManager_ProcessMAPTConfiguration(&(p_VirtIf->MAP.dhcp6cMAPTparameters), &(p_VirtIf->MAP.MaptConfig), pInterface->Name, &(p_VirtIf->IP.Ipv6Data)) == RETURN_OK)
                    {
                        p_VirtIf->MAP.MaptChanged = FALSE;
                        CcspTraceInfo(("%s %d - Successfully updated MAP-T configure Changes for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
                    }
                    else
                    {
                        CcspTraceError(("%s %d - Failed to configure MAP-T for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
                    }
                }
                else
                {
                    CcspTraceError(("%s %d - Failed to verify and configure MAP-T for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
                }
            }
            else
            {
                CcspTraceError((" %s %d - Failed to configure  MAP-T for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
            }
        }
        else
        {
            CcspTraceError(("%s %d - Failed to tear down MAP-T for %s Interface \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
        }
    }
#endif
    else if (p_VirtIf->IP.Ipv6Renewed == TRUE)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
        p_VirtIf->IP.Ipv6Renewed = FALSE;
    }

    // Start DHCP apps if not started
    WanMgr_MonitorDhcpApps(pWanIfaceCtrl);

    WanMgr_CheckDefaultRA(p_VirtIf);
#if defined(FEATURE_IPOE_HEALTH_CHECK) && defined(IPOE_HEALTH_CHECK_LAN_SYNC_SUPPORT)
    if(lanState == LAN_STATE_STOPPED)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , FALSE);
        lanState = LAN_STATE_RESET;
    }
    else if(lanState == LAN_STATE_STARTED)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6 , TRUE);
        lanState = LAN_STATE_RESET;
    }
#endif
    return WAN_STATE_MAPT_ACTIVE;
}
#endif //FEATURE_MAPT

#ifdef FEATURE_DSLITE_V2
static eWanState_t wan_state_dslite_active(WanMgr_IfaceSM_Controller_t *pWanIfaceCtrl)
{
    if ((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE *pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        p_VirtIf->Enable == FALSE ||
        p_VirtIf->Reset == TRUE ||
        p_VirtIf->VLAN.Reset == TRUE ||
        pInterface->BaseInterfaceStatus != WAN_IFACE_PHY_STATUS_UP)
    {
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }
    else if ((pInterface->Selection.Status != WAN_IFACE_ACTIVE) || (pWanIfaceCtrl->DeviceNwModeChanged == TRUE))
    {
        return wan_transition_standby_deconfig_ips(pWanIfaceCtrl);
    }
    else if (WanMgr_DSLite_isEnabled(p_VirtIf) == FALSE ||
             (WanMgr_DSLite_isEndpointAssigned(p_VirtIf) == FALSE) ||
             (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_DOWN) ||
             (p_VirtIf->IP.RefreshDHCP == TRUE && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_IPV6_ONLY && p_VirtIf->IP.Mode != DML_WAN_IP_MODE_DUAL_STACK) ||
             (p_VirtIf->VLAN.Enable == TRUE && p_VirtIf->VLAN.Status == WAN_IFACE_LINKSTATUS_DOWN))
    {
        CcspTraceInfo(("%s %d - LinkStatus=[%d] \n", __FUNCTION__, __LINE__, p_VirtIf->VLAN.Status));
        return wan_transition_dslite_down(pWanIfaceCtrl);
    }
    else if (p_VirtIf->IP.Ipv6Changed == TRUE || p_VirtIf->DSLite.Changed == TRUE)
    {
        CcspTraceInfo(("%s - %s configuration is changed! Deconfigure DS-Lite\n", __FUNCTION__,
                       p_VirtIf->IP.Ipv6Changed ? "IPv6" : "DS-Lite"));
        return wan_transition_dslite_down(pWanIfaceCtrl);
    }
    else if (p_VirtIf->IP.Ipv6Renewed == TRUE)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6, TRUE);
        p_VirtIf->IP.Ipv6Renewed = FALSE;
    }

    // Check if DNS TTL has expired, re-resolve endpoint, and restart tunnel only if address changed
    if (WanMgr_DSLite_CheckAndHandleTtlExpiration(p_VirtIf) == TRUE)
    {
        return wan_transition_dslite_down(pWanIfaceCtrl);
    }

    // Start DHCP apps if not started
    WanMgr_MonitorDhcpApps(pWanIfaceCtrl);

    WanMgr_CheckDefaultRA(p_VirtIf);
#if defined(FEATURE_IPOE_HEALTH_CHECK) && defined(IPOE_HEALTH_CHECK_LAN_SYNC_SUPPORT)
    if (lanState == LAN_STATE_STOPPED)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6, FALSE);
        lanState = LAN_STATE_RESET;
    }
    else if (lanState == LAN_STATE_STARTED)
    {
        WanMgr_SendMsgTo_ConnectivityCheck(pWanIfaceCtrl, CONNECTION_MSG_IPV6, TRUE);
        lanState = LAN_STATE_RESET;
    }
#endif
    return WAN_STATE_DSLITE_ACTIVE;
}
#endif // FEATURE_DSLITE_V2

static eWanState_t wan_state_refreshing_wan(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if (pWanIfaceCtrl->WanEnable == FALSE ||
        pInterface->Selection.Enable == FALSE ||
        pInterface->Selection.Status == WAN_IFACE_NOT_SELECTED ||
        p_VirtIf->Enable == FALSE ||
        pInterface->BaseInterfaceStatus !=  WAN_IFACE_PHY_STATUS_UP)
    {
         p_VirtIf->Reset = FALSE;
         p_VirtIf->VLAN.Reset = FALSE;
         p_VirtIf->VLAN.Expired = FALSE; //Reset VLAN.Expired
        return wan_transition_physical_interface_down(pWanIfaceCtrl);
    }
    
    if( p_VirtIf->PPP.Enable == TRUE)
    {
        if(p_VirtIf->PPP.LinkStatus != WAN_IFACE_PPP_LINK_STATUS_DOWN)
            return WAN_STATE_REFRESHING_WAN;
    }

    if( p_VirtIf->VLAN.Enable == TRUE)
    {
        if (p_VirtIf->VLAN.Status != WAN_IFACE_LINKSTATUS_DOWN )
            return WAN_STATE_REFRESHING_WAN;
    }

        return wan_transition_wan_refreshed(pWanIfaceCtrl);
}

static eWanState_t wan_state_deconfiguring_wan(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if( p_VirtIf->PPP.Enable == TRUE)
    {
        if(p_VirtIf->PPP.LinkStatus != WAN_IFACE_PPP_LINK_STATUS_DOWN)
            return WAN_STATE_DECONFIGURING_WAN;
    }

    if( p_VirtIf->VLAN.Enable == TRUE)
    {
        if (p_VirtIf->VLAN.Status != WAN_IFACE_LINKSTATUS_DOWN )
            return WAN_STATE_DECONFIGURING_WAN;
    }

    return wan_transition_wan_deconfigured(pWanIfaceCtrl);
}

static eWanState_t wan_state_exit(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceCtrl->pIfaceData->VirtIfList, pWanIfaceCtrl->VirIfIdx);
    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    /* Clear DHCP data */
    WanManager_ClearDHCPData(p_VirtIf);

    CcspTraceInfo(("%s %d - Interface '%s' - EXITING STATE MACHINE\n", __FUNCTION__, __LINE__, pInterface->Name));

    return WAN_STATE_EXIT;
}

/*********************************************************************************/
/*********************************************************************************/
/*********************************************************************************/
ANSC_STATUS WanMgr_InterfaceSMThread_Init(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    int retStatus = ANSC_STATUS_SUCCESS;
    return retStatus;
}

static ANSC_STATUS WanMgr_IfaceIpcMsg_handle(WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    if((pWanIfaceCtrl == NULL) || (pWanIfaceCtrl->pIfaceData == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }

    DML_WAN_IFACE* pInterface = pWanIfaceCtrl->pIfaceData;
    DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pInterface->VirtIfList, pWanIfaceCtrl->VirIfIdx);

    if(p_VirtIf->PPP.Enable == TRUE)
    {
        if(p_VirtIf->PPP.IPCPStatusChanged == TRUE)
        {
            CcspTraceInfo(("%s %d IPCPStatus Changed \n", __FUNCTION__, __LINE__));
            if(p_VirtIf->IP.IPv4Source == DML_WAN_IP_SOURCE_PPP && (p_VirtIf->IP.Mode == DML_WAN_IP_MODE_IPV4_ONLY || p_VirtIf->IP.Mode == DML_WAN_IP_MODE_DUAL_STACK))
            {
                IPCPStateChangeHandler(p_VirtIf);
            }
            p_VirtIf->PPP.IPCPStatusChanged = FALSE;
        }

        if(p_VirtIf->PPP.IPV6CPStatusChanged == TRUE)
        {
            CcspTraceInfo(("%s %d IPV6CPStatus Changed \n", __FUNCTION__, __LINE__));
            p_VirtIf->PPP.IPV6CPStatusChanged = FALSE;
        }
    }

    if (p_VirtIf->IP.pIpcIpv4Data != NULL )
    {
        wanmgr_handle_dhcpv4_event_data(p_VirtIf);
    }

    if (p_VirtIf->IP.pIpcIpv6Data != NULL )
    {
        wanmgr_handle_dhcpv6_event_data(p_VirtIf);
    }

#if defined(_DT_WAN_Manager_Enable_)
       /* Get interface IPv4 data */
       p_VirtIf->IP.Ipv4Status = getInterfaceIPv4Data(p_VirtIf->Name, &(p_VirtIf->IP.Ipv4Data));

#endif
    return ANSC_STATUS_SUCCESS;
}


static void* WanMgr_InterfaceSMThread( void *arg )
{
    CcspTraceInfo(("%s %d \n", __FUNCTION__, __LINE__));

    //Validate buffer
    if ( NULL == arg )
    {
       CcspTraceError(("%s %d Invalid buffer\n", __FUNCTION__,__LINE__));
       //Cleanup current thread when exit
       pthread_exit(NULL);
    }

    //SM variables
    WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl = ( WanMgr_IfaceSM_Controller_t *) arg;
    WanMgr_Iface_Data_t* pWanDmlIfaceData = NULL;
    eWanState_t iface_sm_state = WAN_STATE_EXIT;
    bool bRunning = true;

    // event handler
    int n = 0;
    struct timeval tv;


    //detach thread from caller stack
    pthread_detach(pthread_self());


    CcspTraceInfo(("%s %d - Interface state machine (TID %lu) initialising for iface idx %d\n", __FUNCTION__, __LINE__, syscall(SYS_gettid), pWanIfaceCtrl->interfaceIdx));


    // initialise state machine
    if(WanMgr_InterfaceSMThread_Init(pWanIfaceCtrl) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d Policy Controller Error \n", __FUNCTION__, __LINE__));
        return (void *)ANSC_STATUS_FAILURE;
    }

    //Transition Start
    pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pWanIfaceCtrl->interfaceIdx);
    if(pWanDmlIfaceData != NULL)
    {
        pWanIfaceCtrl->pIfaceData = &(pWanDmlIfaceData->data);
        iface_sm_state = wan_transition_start(pWanIfaceCtrl); // do this first before anything else to init variables
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }
    else
    {
        bRunning = false;
    }

    while (bRunning)
    {
        pWanIfaceCtrl->pIfaceData = NULL;

        /* Wait up to 50 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = LOOP_TIMEOUT;

        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }

        //Update Wan config
        WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
        if(pWanConfigData != NULL)
        {
            pWanIfaceCtrl->WanEnable = pWanConfigData->data.Enable;
            pWanIfaceCtrl->DeviceNwMode = pWanConfigData->data.DeviceNwMode;
            pWanIfaceCtrl->DeviceNwModeChanged = pWanConfigData->data.DeviceNwModeChanged;
            pWanConfigData->data.DeviceNwModeChanged = FALSE;   // setting DeviceNwMode to FALSE, pWanIfaceCtrl->DeviceNwModeChanged will handle the current value
            WanMgrDml_GetConfigData_release(pWanConfigData);
        }

        //Get Interface data
        pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pWanIfaceCtrl->interfaceIdx);
        if(pWanDmlIfaceData != NULL)
        {
            pWanIfaceCtrl->pIfaceData = &(pWanDmlIfaceData->data);
        }

        //Handle IPC messages
        WanMgr_IfaceIpcMsg_handle(pWanIfaceCtrl);

        // Store current state
        pWanIfaceCtrl->eCurrentState = iface_sm_state;
        DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanIfaceCtrl->pIfaceData->VirtIfList, pWanIfaceCtrl->VirIfIdx);
        p_VirtIf->eCurrentState = iface_sm_state;

        // process state
        switch (iface_sm_state)
        {
            case WAN_STATE_PHY_CONFIGURING:
                {
                    iface_sm_state = wan_state_phy_configuring(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_PHY_DOWN:
                {
                    iface_sm_state = wan_state_phy_down(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_VLAN_CONFIGURING:
                {
                    iface_sm_state = wan_state_vlan_configuring(pWanIfaceCtrl);
                    break;
                }
           case WAN_STATE_PPP_CONFIGURING:
                {
                    iface_sm_state = wan_state_ppp_configuring(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_VALIDATING_WAN:
                {
                    iface_sm_state = wan_state_validating_wan(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_OBTAINING_IP_ADDRESSES:
                {
                    iface_sm_state = wan_state_obtaining_ip_addresses(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_IPV4_LEASED:
                {
                    iface_sm_state = wan_state_ipv4_leased(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_IPV6_LEASED:
                {
                    iface_sm_state = wan_state_ipv6_leased(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_DUAL_STACK_ACTIVE:
                {
                    iface_sm_state = wan_state_dual_stack_active(pWanIfaceCtrl);
                    break;
                }
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
            case WAN_STATE_MAPT_ACTIVE:
                {
                    iface_sm_state = wan_state_mapt_active(pWanIfaceCtrl);
                    break;
                }
#endif //FEATURE_MAPT
#ifdef FEATURE_DSLITE_V2
            case WAN_STATE_DSLITE_ACTIVE:
                {
                    iface_sm_state = wan_state_dslite_active(pWanIfaceCtrl);
                    break;
                }
#endif //FEATURE_DSLITE_V2
            case WAN_STATE_REFRESHING_WAN:
                {
                    iface_sm_state = wan_state_refreshing_wan(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_DECONFIGURING_WAN:
                {
                    iface_sm_state = wan_state_deconfiguring_wan(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_STANDBY:
                {
                    iface_sm_state = wan_state_standby(pWanIfaceCtrl);
                    break;
                }
            case WAN_STATE_EXIT :
            default:
                {
                    iface_sm_state = wan_state_exit(pWanIfaceCtrl);
                    bRunning = false;
                    CcspTraceInfo(("%s %d - Exit from state machine\n", __FUNCTION__, __LINE__));
                    break;
                }
        }

        if(pWanDmlIfaceData != NULL)
        {
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }

    }

    CcspTraceInfo(("%s %d - Interface state machine (TID %lu) exiting for iface idx %d\n", __FUNCTION__, __LINE__, syscall(SYS_gettid), pWanIfaceCtrl->interfaceIdx));

    int  uptime = 0;
    char buffer[64];
    memset(&buffer, 0, sizeof(buffer));
    WanManager_GetDateAndUptime( buffer, &uptime );
    LOG_CONSOLE("%s [tid=%ld] Wan_exit_complete at %d\n",buffer, syscall(SYS_gettid), uptime);

    //Free current private resource before exit
    if(NULL != pWanIfaceCtrl)
    {
        free(pWanIfaceCtrl);
        pWanIfaceCtrl = NULL;
    }
    pthread_exit(NULL);
}


int WanMgr_StartInterfaceStateMachine(WanMgr_IfaceSM_Controller_t *wanIf)
{
    WanMgr_IfaceSM_Controller_t *     wanIfLocal = NULL;
    pthread_t                wanSmThreadId;
    int                      iErrorCode     = 0;
    static int               siKeyCreated   = 0;

    //Allocate memory and pass it to thread
    wanIfLocal = ( WanMgr_IfaceSM_Controller_t * )malloc( sizeof( WanMgr_IfaceSM_Controller_t ) );
    if( NULL == wanIfLocal )
    {
        CcspTraceError(("%s %d Failed to allocate memory\n", __FUNCTION__, __LINE__));
        return -1;
    }

    //Copy buffer
    memcpy( wanIfLocal , wanIf, sizeof(WanMgr_IfaceSM_Controller_t) );

    CcspTraceInfo (("%s %d - WAN interface data received in the state machine (iface idx %d) \n", __FUNCTION__, __LINE__, wanIfLocal->interfaceIdx));

    //Wanmanager state machine thread
    iErrorCode = pthread_create( &wanSmThreadId, NULL, &WanMgr_InterfaceSMThread, (void*)wanIfLocal );

    if( 0 != iErrorCode )
    {
        CcspTraceError(("%s %d - Failed to start WanManager State Machine Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
    }
    else
    {
        CcspTraceInfo(("%s %d - WanManager State Machine Thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    }
    return iErrorCode ;
}


void WanMgr_IfaceSM_Init(WanMgr_IfaceSM_Controller_t* pWanIfaceSMCtrl, INT iface_idx, INT VirIfIdx)
{
    if(pWanIfaceSMCtrl != NULL)
    {
        memset(pWanIfaceSMCtrl, 0 , sizeof(WanMgr_IfaceSM_Controller_t));
        pWanIfaceSMCtrl->WanEnable = FALSE;
        pWanIfaceSMCtrl->interfaceIdx = iface_idx;
        pWanIfaceSMCtrl->VirIfIdx = VirIfIdx;
#ifdef FEATURE_IPOE_HEALTH_CHECK
        WanMgr_IfaceSM_IHC_Init(pWanIfaceSMCtrl);
#endif
        pWanIfaceSMCtrl->pIfaceData = NULL;        
    }
}
