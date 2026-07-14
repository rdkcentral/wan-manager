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
#include "wanmgr_data.h"
#include "wanmgr_dhcpv4_apis.h"
#include "wanmgr_interface_sm.h"
#include "wanmgr_sysevents.h"
#include "wanmgr_ipc.h"
#include "wanmgr_utils.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_dhcpv4_internal.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include <syscfg/syscfg.h>
#include "dhcpv4c_api.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <cjson/cJSON.h>
#include "secure_wrapper.h"

#include "ccsp_psm_helper.h"
#include "sysevent/sysevent.h"
#include "dmsb_tr181_psm_definitions.h"

extern int sysevent_fd;
extern token_t sysevent_token;
extern PWAN_DHCPV4_DATA g_pDhcpv4;

extern WANMGR_BACKEND_OBJ* g_pWanMgrBE;

#define COSA_DHCP4_SYSCFG_NAMESPACE NULL

DML_DHCPC_FULL     CH_g_dhcpv4_client[DML_DHCP_MAX_ENTRIES];
COSA_DML_DHCP_OPT  g_dhcpv4_client_sent[DML_DHCP_MAX_ENTRIES][DML_DHCP_MAX_OPT_ENTRIES];
DML_DHCPC_REQ_OPT  g_dhcpv4_client_req[DML_DHCP_MAX_ENTRIES][DML_DHCP_MAX_OPT_ENTRIES];

ULONG          g_Dhcp4ClientNum = 0;
ULONG          g_Dhcp4ClientSentOptNum[DML_DHCP_MAX_ENTRIES] = {0,0,0,0};
ULONG          g_Dhcp4ClientReqOptNum[DML_DHCP_MAX_ENTRIES]  = {0,0,0,0};

// for PSM access
extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];

#define P2P_SUB_NET_MASK   "255.255.255.255"
#define DHCP_STATE_UP      "Up"
#define DHCP_STATE_RENEW   "renew"
#define DHCP_STATE_DOWN    "Down"
#define DHCP_STATE_BOUND   "bound"

static ANSC_STATUS wanmgr_dchpv4_get_ipc_msg_info(WANMGR_IPV4_DATA* pDhcpv4Data, ipc_dhcpv4_data_t* pIpcIpv4Data)
{
    if((pDhcpv4Data == NULL) || (pIpcIpv4Data == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }
    memcpy(pDhcpv4Data->ifname, pIpcIpv4Data->dhcpcInterface, BUFLEN_64);
    memcpy(pDhcpv4Data->ip, pIpcIpv4Data->ip, BUFLEN_32);
    memcpy(pDhcpv4Data->mask , pIpcIpv4Data->mask, BUFLEN_32);
    memcpy(pDhcpv4Data->gateway, pIpcIpv4Data->gateway, BUFLEN_32);
    memcpy(pDhcpv4Data->dnsServer, pIpcIpv4Data->dnsServer, BUFLEN_64);
    memcpy(pDhcpv4Data->dnsServer1, pIpcIpv4Data->dnsServer1, BUFLEN_64);
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
    memcpy(pDhcpv4Data->timeZone, pIpcIpv4Data->timeZone, BUFLEN_64);
    pDhcpv4Data->isTimeOffsetAssigned = pIpcIpv4Data->isTimeOffsetAssigned;
    pDhcpv4Data->timeOffset = pIpcIpv4Data->timeOffset;
    pDhcpv4Data->leaseTime = pIpcIpv4Data->leaseTime;
    pDhcpv4Data->upstreamCurrRate = pIpcIpv4Data->upstreamCurrRate;
    pDhcpv4Data->downstreamCurrRate = pIpcIpv4Data->downstreamCurrRate;
    memcpy(pDhcpv4Data->dhcpServerId, pIpcIpv4Data->dhcpServerId, BUFLEN_64);
    memcpy(pDhcpv4Data->dhcpState, pIpcIpv4Data->dhcpState, BUFLEN_64);
#endif

    if( ( TRUE == pIpcIpv4Data->mtuAssigned ) && ( 0 != pIpcIpv4Data->mtuSize ) )
    {
        pDhcpv4Data->mtuSize =  pIpcIpv4Data->mtuSize;
    }
    else
    {
        pDhcpv4Data->mtuSize =  WANMNGR_INTERFACE_DEFAULT_MTU_SIZE;
    }

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS wanmgr_handle_dhcpv4_event_data(DML_VIRTUAL_IFACE* pVirtIf)
{
    if(NULL == pVirtIf)
    {
       return ANSC_STATUS_FAILURE;
    }

    ipc_dhcpv4_data_t* pDhcpcInfo = pVirtIf->IP.pIpcIpv4Data;
    if(NULL == pDhcpcInfo)
    {
       return ANSC_STATUS_BAD_PARAMETER;
    }

    CcspTraceInfo(("%s %d - Enter \n", __FUNCTION__, __LINE__));
    bool IPv4ConfigChanged = FALSE;


    if( strcmp(pDhcpcInfo->gateway, "0.0.0.0") == 0)
    {
        CcspTraceInfo(("%s %d - gateway=[%s] Iface Status to VALID\n", __FUNCTION__, __LINE__, pDhcpcInfo->gateway));
        if (pVirtIf->IP.pIpcIpv4Data != NULL )
        {
            //free memory
            free(pVirtIf->IP.pIpcIpv4Data);
            pVirtIf->IP.pIpcIpv4Data = NULL;
        }

        //Don't set the status to  VALID if it is already UP or STANDBY
        if(pVirtIf->Status != WAN_IFACE_STATUS_STANDBY && pVirtIf->Status != WAN_IFACE_STATUS_UP)
        {
            CcspTraceInfo(("%s %d - Setting Iface Status to VALID\n", __FUNCTION__, __LINE__, pDhcpcInfo->gateway));
            pVirtIf->Status = WAN_IFACE_STATUS_VALID;
        }
        return ANSC_STATUS_SUCCESS;
    }

    if (strcmp(pVirtIf->IP.Ipv4Data.ip, pDhcpcInfo->ip) ||
      strcmp(pVirtIf->IP.Ipv4Data.mask, pDhcpcInfo->mask) ||
      strcmp(pVirtIf->IP.Ipv4Data.gateway, pDhcpcInfo->gateway) ||
      strcmp(pVirtIf->IP.Ipv4Data.dnsServer, pDhcpcInfo->dnsServer) ||
      strcmp(pVirtIf->IP.Ipv4Data.dnsServer1, pDhcpcInfo->dnsServer1))
    {
        CcspTraceInfo(("%s %d - IPV4 configuration changed \n", __FUNCTION__, __LINE__));
        IPv4ConfigChanged = TRUE;
        CcspTraceInfo(("%s %d - RestartConnectivityCheck triggered. \n", __FUNCTION__, __LINE__));
        pVirtIf->IP.RestartConnectivityCheck = TRUE;
    }

    char name[64] = {0};
    char value[64] = {0};
    uint32_t up_time = 0;

    /* ipv4_start_time should be set in every v4 packets */
    snprintf(name,sizeof(name),SYSEVENT_IPV4_START_TIME,pDhcpcInfo->dhcpcInterface);
    up_time = WanManager_getUpTime();
    snprintf(value, sizeof(value), "%u", up_time);
    sysevent_set(sysevent_fd, sysevent_token, name, value, 0);

    if (pDhcpcInfo->addressAssigned)
    {
        CcspTraceInfo(("assigned ip=%s netmask=%s gateway=%s dns server=%s,%s leasetime = %d, rebindtime = %d, renewaltime = %d, dhcp state = %s mtu = %d\n",
                     pDhcpcInfo->ip,
                     pDhcpcInfo->mask,
                     pDhcpcInfo->gateway,
                     pDhcpcInfo->dnsServer,
                     pDhcpcInfo->dnsServer1,
                     pDhcpcInfo->leaseTime,
                     pDhcpcInfo->rebindingTime,
                     pDhcpcInfo->renewalTime,
                     pDhcpcInfo->dhcpState,
                     pDhcpcInfo->mtuSize));

        if (IPv4ConfigChanged)
        {
#if !defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE) //Sysevents will be configured by ISM while selecting Iface as Active.
            if (wanmgr_sysevents_ipv4Info_set(pDhcpcInfo, pDhcpcInfo->dhcpcInterface) != ANSC_STATUS_SUCCESS)
            {
                CcspTraceError(("%s %d - Could not store ipv4 data!", __FUNCTION__, __LINE__));
            }
#endif
            //Update isIPv4ConfigChanged flag.
            pVirtIf->IP.Ipv4Changed = TRUE;
        }
        else
        {
            //FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE : Handle IP Renew packets in Handler
            CcspTraceInfo(("%s %d - IPV4 optional configuration received \n", __FUNCTION__, __LINE__));
            snprintf(name, sizeof(name), SYSEVENT_IPV4_DS_CURRENT_RATE, pDhcpcInfo->dhcpcInterface);
            snprintf(value, sizeof(value), "%d", pDhcpcInfo->downstreamCurrRate);
            sysevent_set(sysevent_fd, sysevent_token, name, value, 0);

            snprintf(name, sizeof(name), SYSEVENT_IPV4_US_CURRENT_RATE, pDhcpcInfo->dhcpcInterface);
            snprintf(value, sizeof(value), "%d", pDhcpcInfo->upstreamCurrRate);
            sysevent_set(sysevent_fd, sysevent_token, name, value, 0);


#if !defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
            if (pDhcpcInfo->isTimeOffsetAssigned)
            {
                snprintf(value, sizeof(value), "@%d", pDhcpcInfo->timeOffset);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV4_TIME_OFFSET, value, 0);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_DHCPV4_TIME_OFFSET, SET, 0);
            }

            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV4_TIME_ZONE, pDhcpcInfo->timeZone, 0);
#endif
            pVirtIf->IP.Ipv4Renewed = TRUE;
        }

        // update current IPv4 data
        wanmgr_dchpv4_get_ipc_msg_info(&(pVirtIf->IP.Ipv4Data), pDhcpcInfo);
        pVirtIf->IP.Ipv4Data.leaseReceivedTime = up_time;

        /* Assign the address to the inetrface when received. Remaining configurations are updated when activated from VISM*/
        CcspTraceInfo(("%s %d -  Received Ipv4 lease for interface %s. Configuring address on interface\n", __FUNCTION__, __LINE__, pVirtIf->IP.Ipv4Data.ifname));
        /** Setup IPv4: such as
         * "ifconfig eth0 10.6.33.165 netmask 255.255.255.192 broadcast 10.6.33.191 up"
         */
        char cmdStr[BUFLEN_256] = {0};
        char bCastStr[IP_ADDR_LENGTH] = {0};
        if (WanManager_GetBCastFromIpSubnetMask(pVirtIf->IP.Ipv4Data.ip, pVirtIf->IP.Ipv4Data.mask, bCastStr) != RETURN_OK)
        {
            CcspTraceError((" %s %d - bad address %s/%s \n",__FUNCTION__,__LINE__, pVirtIf->IP.Ipv4Data.ip, pVirtIf->IP.Ipv4Data.mask));
            return ANSC_STATUS_FAILURE;
        }

        snprintf(cmdStr, sizeof(cmdStr), "ifconfig %s %s netmask %s broadcast %s mtu %u",
                pVirtIf->IP.Ipv4Data.ifname, pVirtIf->IP.Ipv4Data.ip, pVirtIf->IP.Ipv4Data.mask, bCastStr, pVirtIf->IP.Ipv4Data.mtuSize);
        CcspTraceInfo(("%s %d -  IP configuration = %s \n", __FUNCTION__, __LINE__, cmdStr));
        WanManager_DoSystemAction("setupIPv4:", cmdStr);

        /** Need to manually add route if the connection is PPP connection*/
        if (pVirtIf->PPP.Enable == TRUE)
        {
            if (WanManager_AddGatewayRoute(&pVirtIf->IP.Ipv4Data) != RETURN_OK)
            {
                CcspTraceError(("%s %d - Failed to set up system gateway", __FUNCTION__, __LINE__));
            }
        }

        WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_UP);
    }
    else if (pDhcpcInfo->isExpired)
    {
        CcspTraceInfo(("DHCPC Lease expired!!!!!!!!!!\n"));
        // update current IPv4 data
        wanmgr_dchpv4_get_ipc_msg_info(&(pVirtIf->IP.Ipv4Data), pDhcpcInfo);
        WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_DOWN);
    }

    if(IPv4ConfigChanged == TRUE)
    {
        char param_name[256] = {0};
        snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv4Address",  pVirtIf->baseIfIdx+1, pVirtIf->VirIfIdx+1);
        WanMgr_Rbus_EventPublishHandler(param_name, pVirtIf->IP.Ipv4Data.ip, RBUS_STRING);
    }

    if (pVirtIf->IP.pIpcIpv4Data != NULL )
    {
        //free memory
        free(pVirtIf->IP.pIpcIpv4Data);
        pVirtIf->IP.pIpcIpv4Data = NULL;
    }

    return ANSC_STATUS_SUCCESS;
}

void WanMgr_UpdateIpFromCellularMgr (WanMgr_IfaceSM_Controller_t* pWanIfaceCtrl)
{
    char acTmpReturnValue[256] = {0};
    char acTmpQueryParam[256] = {0};

    CcspTraceInfo(("%s %d Enter \n", __FUNCTION__, __LINE__));
    //get iface data
    if(pWanIfaceCtrl != NULL)
    {
        DML_WAN_IFACE* pIfaceData = pWanIfaceCtrl->pIfaceData;
        DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pIfaceData->VirtIfList, pWanIfaceCtrl->VirIfIdx);
        //check if previously message was already handled. 
        //TODO: This is a workaround for cellular. We should remove check for ipv4 state. get Ip from cellular manager only if IPV4_STATE_DOWN.
        if(p_VirtIf->IP.pIpcIpv4Data == NULL && p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_DOWN)
        {
            //allocate
            p_VirtIf->IP.pIpcIpv4Data = (ipc_dhcpv4_data_t*) malloc(sizeof(ipc_dhcpv4_data_t));
            if(p_VirtIf->IP.pIpcIpv4Data != NULL)
            {
                memset(p_VirtIf->IP.pIpcIpv4Data, 0, sizeof(ipc_dhcpv4_data_t));

                p_VirtIf->IP.pIpcIpv4Data->isExpired = FALSE;
                p_VirtIf->IP.pIpcIpv4Data->addressAssigned = TRUE;
                /* we don't receive ntp time offset value from cellular network */
                p_VirtIf->IP.pIpcIpv4Data->isTimeOffsetAssigned = FALSE;

                //GET IP address
                snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ),"%s%s", pIfaceData->BaseInterface, CELLULARMGR_IPADDRESS);
                memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
                if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( CELLULARMGR_COMPONENT_NAME, CELLULARMGR_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
                {
                    CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
                    return;
                }
                if (acTmpReturnValue[0] != '\0')
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->ip, acTmpReturnValue, BUFLEN_32);
                }
                else
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->dhcpState, DHCP_STATE_DOWN, BUFLEN_64);
                    p_VirtIf->IP.pIpcIpv4Data->addressAssigned = FALSE;
                }
                //get gateway IP
                memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
                memset( acTmpQueryParam, 0, sizeof( acTmpQueryParam ) );
                snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ),"%s%s", pIfaceData->BaseInterface, CELLULARMGR_GATEWAY);

                if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( CELLULARMGR_COMPONENT_NAME, CELLULARMGR_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
                {
                    CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
                    return;
                }
                if (acTmpReturnValue[0] != '\0')
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->gateway, acTmpReturnValue, BUFLEN_32);
                }
                else
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->dhcpState, DHCP_STATE_DOWN, BUFLEN_64);
                    p_VirtIf->IP.pIpcIpv4Data->addressAssigned = FALSE;
                }
                //Query for DNS Servers
                memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
                memset( acTmpQueryParam, 0, sizeof( acTmpQueryParam ) );
                snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ),"%s%s", pIfaceData->BaseInterface, CELLULARMGR_PRIMARY_DNS);

                if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( CELLULARMGR_COMPONENT_NAME, CELLULARMGR_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
                {
                    CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
                    return;
                }
                if (acTmpReturnValue[0] != '\0')
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->dnsServer, acTmpReturnValue, BUFLEN_64);
                }
                else
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->dhcpState, DHCP_STATE_DOWN, BUFLEN_64);
                    p_VirtIf->IP.pIpcIpv4Data->addressAssigned = FALSE;
                }

                memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
                memset( acTmpQueryParam, 0, sizeof( acTmpQueryParam ) );
                snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ),"%s%s", pIfaceData->BaseInterface, CELLULARMGR_SECONDARY_DNS);

                if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( CELLULARMGR_COMPONENT_NAME, CELLULARMGR_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
                {
                    CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
                    return;
                }
                if (acTmpReturnValue[0] != '\0')
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->dnsServer1, acTmpReturnValue, BUFLEN_64);
                }

                //update iface name 
                strncpy(p_VirtIf->IP.pIpcIpv4Data->dhcpcInterface, p_VirtIf->Name, sizeof(p_VirtIf->IP.pIpcIpv4Data->dhcpcInterface) - 1);

                //query mask
                memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
                memset( acTmpQueryParam, 0, sizeof( acTmpQueryParam ) );
                snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ),"%s%s", pIfaceData->BaseInterface, CELLULARMGR_SUBNET_MASK);

                if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( CELLULARMGR_COMPONENT_NAME, CELLULARMGR_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
                {
                    CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
                    return;
                }
                if (acTmpReturnValue[0] != '\0')
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->mask, acTmpReturnValue, BUFLEN_32);
                }
                else
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->dhcpState, DHCP_STATE_DOWN, BUFLEN_64);
                    p_VirtIf->IP.pIpcIpv4Data->addressAssigned = FALSE;
                }

                //query mtu size

                memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
                memset( acTmpQueryParam, 0, sizeof( acTmpQueryParam ) );
                snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ),"%s%s", pIfaceData->BaseInterface, CELLULARMGR_MTU_SIZE);

                if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( CELLULARMGR_COMPONENT_NAME, CELLULARMGR_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
                {
                    CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
                    return;
                }
                if (acTmpReturnValue[0] != '\0')
                {
                    p_VirtIf->IP.pIpcIpv4Data->mtuSize = atoi(acTmpReturnValue);
                    p_VirtIf->IP.pIpcIpv4Data->mtuAssigned = TRUE;
                }
                else
                {
                    strncpy (p_VirtIf->IP.pIpcIpv4Data->dhcpState, DHCP_STATE_DOWN, BUFLEN_64);
                    p_VirtIf->IP.pIpcIpv4Data->addressAssigned = FALSE;
                }

                //update Ipv4 data
                wanmgr_handle_dhcpv4_event_data(p_VirtIf);
            }    
        }
        //IPv6 data

        memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
        memset( acTmpQueryParam, 0, sizeof( acTmpQueryParam ) );
        snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ),"%s%s", pIfaceData->BaseInterface, CELLULARMGR_IPv6_ADDRESS);

        if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( CELLULARMGR_COMPONENT_NAME, CELLULARMGR_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
        {
            CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
            return;
        }
        if (acTmpReturnValue[0] != '\0')
        {
            //TODO: send ipv6 lease info via pandm. review and modify the code to directly update IPv6 from CellularManager.

            // CELLULARMGR sends us only the ipv6 address, so assigning the default value for rest of the values
            char * fifo_pattern = "dibbler-client add '%s' '1' '\\0' '\\0' '\\0' '\\0' '\\0' 0 '1' '\\0' '\\0' '3600' '7200' ''";
            char ipv6_addr [128] = {0};
            char buff [512] = {0};
            int sock   = -1;
            int bytes  = -1;

            // copy the ipv6_addr to local buff
            strncpy (ipv6_addr, acTmpReturnValue, sizeof(ipv6_addr) - 1);

            // copy the ipv6_addr to string pattern so reading side can parse it
            snprintf(buff, sizeof (buff), fifo_pattern,ipv6_addr);

            // open fifo
            sock = open(CCSP_COMMON_FIFO, O_WRONLY);
            if (sock < 0)
            {
                CcspTraceInfo(("%s %d: Failed to create the socket , error = [%d][%s]\n", __FUNCTION__, __LINE__, errno, strerror(errno)));
                return;
            }

            // write data
            bytes = write(sock, buff, strlen(buff));
            if (bytes == 0)
            {
                CcspTraceInfo(("%s %d: Failed to write in fifo , error = [%d][%s]\n", __FUNCTION__, __LINE__, errno, strerror(errno)));
                close(sock);
                return;
            }

            // close fifo
            close(sock);
        }
    }
}

ANSC_STATUS IPCPStateChangeHandler (DML_VIRTUAL_IFACE* pVirtIf) 
{
    //get iface data
    if(pVirtIf == NULL)
    {
        CcspTraceError(("%s %d Invalid memory \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if(pVirtIf->IP.pIpcIpv4Data != NULL)
    {
        CcspTraceError(("%s %d Need to handle current IP config from PPP before handling new config \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    char *token = NULL;
    int index = -1;

    // Get PPP instance number
    sscanf(pVirtIf->PPP.Interface, "%*[^0-9]%d", &index);


    char acTmpQueryParam[256] = {0};
    char localIPAddr[128] = {0};
    char remoteIPAddr[128] = {0};

    // Lets get the Local & Remote IP Address
    snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ), PPP_IPCP_LOCAL_IPADDRESS, index );
    if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( PPPMGR_COMPONENT_NAME, PPPMGR_DBUS_PATH, acTmpQueryParam, localIPAddr ) )
    {
        CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
        return ANSC_STATUS_FAILURE;
    }

    snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ), PPP_IPCP_REMOTEIPADDRESS, index );
    if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( PPPMGR_COMPONENT_NAME, PPPMGR_DBUS_PATH, acTmpQueryParam, remoteIPAddr ) )
    {
        CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
        return ANSC_STATUS_FAILURE;
    }

    // validate if localIPAddr & RemoteIPAddr are valid v4 IP addr
    if ((IsValidIpAddress(AF_INET, localIPAddr) == FALSE) || 
            (IsValidIpAddress(AF_INET, remoteIPAddr) == FALSE))
    {
        // IPs not valid, set IPCP status to TRUE
        pVirtIf->PPP.IPCPStatus = WAN_IFACE_IPCP_STATUS_DOWN;
        pVirtIf->PPP.IPV6CPStatus = WAN_IFACE_IPV6CP_STATUS_DOWN;
        CcspTraceInfo(("%s %d: invalid Local and Remote IP from PPP interface. IPCPStatus = WAN_IFACE_IPCP_STATUS_DOWN\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_SUCCESS;
    }

    // create a ipc msg with IP lease info
    pVirtIf->IP.pIpcIpv4Data = (ipc_dhcpv4_data_t*) malloc(sizeof(ipc_dhcpv4_data_t));
    memset (pVirtIf->IP.pIpcIpv4Data, 0, sizeof(ipc_dhcpv4_data_t));

    pVirtIf->IP.pIpcIpv4Data->addressAssigned = TRUE;
    pVirtIf->IP.pIpcIpv4Data->mtuAssigned = FALSE;
    pVirtIf->IP.pIpcIpv4Data->isTimeOffsetAssigned = FALSE;
    pVirtIf->IP.pIpcIpv4Data->isExpired = FALSE;
    strncpy (pVirtIf->IP.pIpcIpv4Data->dhcpState, DHCP_STATE_UP, sizeof(pVirtIf->IP.pIpcIpv4Data->dhcpState) - 1);

    // copy local and remote IP address in new ipc msg
    strncpy (pVirtIf->IP.pIpcIpv4Data->ip, localIPAddr, sizeof(pVirtIf->IP.pIpcIpv4Data->ip) - 1);
    strncpy (pVirtIf->IP.pIpcIpv4Data->gateway, remoteIPAddr, sizeof(pVirtIf->IP.pIpcIpv4Data->gateway) - 1);
    pVirtIf->IP.pIpcIpv4Data->addressAssigned = TRUE;
    pVirtIf->PPP.IPCPStatus = WAN_IFACE_IPCP_STATUS_UP;
    pVirtIf->PPP.IPV6CPStatus = WAN_IFACE_IPV6CP_STATUS_UP;

    //Query for DNS Servers
    char acTmpReturnValue[256] = {0};
    snprintf( acTmpQueryParam, sizeof(acTmpQueryParam ), PPP_IPCP_DNS_SERVERS, index );
    memset( acTmpReturnValue, 0, sizeof( acTmpReturnValue ) );
    if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValues( PPPMGR_COMPONENT_NAME, PPPMGR_DBUS_PATH, acTmpQueryParam, acTmpReturnValue ) )
    {
        CcspTraceError(("%s %d Failed to get param value for paramname %s \n", __FUNCTION__, __LINE__, acTmpQueryParam));
        return ANSC_STATUS_FAILURE;
    }
    if (acTmpReturnValue[0] != '\0')
    {
        //Return first DNS Server
        token = strtok(acTmpReturnValue, ",");
        if (token != NULL)
        {
            strncpy (pVirtIf->IP.pIpcIpv4Data->dnsServer, token,sizeof(pVirtIf->IP.pIpcIpv4Data->dnsServer)-1);
            //Return first DNS Server
            token = strtok(NULL, ",");
            if (IsValidIpAddress(AF_INET, token) == TRUE)
            {
                strncpy (pVirtIf->IP.pIpcIpv4Data->dnsServer1, token,sizeof(pVirtIf->IP.pIpcIpv4Data->dnsServer1)-1);
            }
        }
    }

    strncpy(pVirtIf->IP.pIpcIpv4Data->dhcpcInterface, pVirtIf->Name, sizeof(pVirtIf->IP.pIpcIpv4Data->dhcpcInterface) - 1);
    strncpy(pVirtIf->IP.pIpcIpv4Data->mask, P2P_SUB_NET_MASK, sizeof(pVirtIf->IP.pIpcIpv4Data->mask)-1);

    CcspTraceInfo(("%s %d: New IPC message from PPP with LocalIPAddress=%s RemoteIPAddress=%s DNS1=%s DNS2=%s \n", 
                __FUNCTION__, __LINE__, pVirtIf->IP.pIpcIpv4Data->ip, pVirtIf->IP.pIpcIpv4Data->gateway, pVirtIf->IP.pIpcIpv4Data->dnsServer, pVirtIf->IP.pIpcIpv4Data->dnsServer1));

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API retrieves the number of DHCP clients in the system.
 */
ULONG
WanMgr_DmlDhcpcGetNumberOfEntries
    (
        ANSC_HANDLE                 hContext
    )
{
    UNREFERENCED_PARAMETER(hContext);
    return 1;
}

/*
    Description:
        The API retrieves the complete info of the DHCP clients designated by index. The usual process is the caller gets the total number of entries, then iterate through those by calling this API.
    Arguments:
        ulIndex        Indicates the index number of the entry.
        pEntry        To receive the complete info of the entry.
*/
ANSC_STATUS WanMgr_DmlDhcpcGetEntry ( ANSC_HANDLE hContext, ULONG ulIndex, PDML_DHCPC_FULL pEntry )
{
    UNREFERENCED_PARAMETER(hContext);
    if(ulIndex >0)
        return(ANSC_STATUS_FAILURE);
    pEntry->Cfg.InstanceNumber = 1;
    WanMgr_DmlDhcpcGetCfg(hContext, &pEntry->Cfg);
    WanMgr_DmlDhcpcGetInfo(hContext, ulIndex,&pEntry->Info);
    return ANSC_STATUS_SUCCESS;  
}

/*
    Function Name: WanMgr_DmlDhcpcSetValues
    Description:
        The API set the the DHCP clients' instance number and alias to the syscfg DB.
    Arguments:
        ulIndex        Indicates the index number of the entry.
        ulInstanceNumber Client's Instance number 
        pAlias          pointer to the Client's Alias
*/
ANSC_STATUS WanMgr_DmlDhcpcSetValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulIndex);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    UNREFERENCED_PARAMETER(pAlias);
    return ANSC_STATUS_FAILURE;
}

/*
    Description:
        The API adds DHCP client. 
    Arguments:
        pEntry        Caller fills in pEntry->Cfg, except Alias field. Upon return, callee fills pEntry->Cfg.Alias field and as many as possible fields in pEntry->Info.
*/
ANSC_HANDLE WanMgr_DmlDhcpcAddEntry ( ANSC_HANDLE hContext, ULONG pInsNumber )
{
    PDHCPC_CONTEXT_LINK_OBJECT        pCxtLink          = NULL;
    PDML_DHCPC_FULL                 pDhcpc              = NULL;
    PWAN_DHCPV4_DATA                pDhcpv4     = (PWAN_DHCPV4_DATA)g_pWanMgrBE->hDhcpv4;
    ULONG                            i                  = 0;

    UNREFERENCED_PARAMETER(hContext);
    if (pDhcpv4 != NULL)
    {
        pDhcpc    = (PDML_DHCPC_FULL)AnscAllocateMemory( sizeof(DML_DHCPC_FULL) );
        if ( !pDhcpc )
        {
            return NULL; /* return the handle */
        }

        /* Set default value */
        DHCPV4_CLIENT_SET_DEFAULTVALUE(pDhcpc);

        /* Add into our link tree*/
        pCxtLink = (PDHCPC_CONTEXT_LINK_OBJECT)AnscAllocateMemory( sizeof(DHCPC_CONTEXT_LINK_OBJECT) );
        if ( !pDhcpc )
        {
            AnscFreeMemory(pDhcpc);
            return NULL;
        }

        DHCPV4_CLIENT_INITIATION_CONTEXT(pCxtLink)

        pCxtLink->hContext         = (ANSC_HANDLE)pDhcpc;
        pCxtLink->bNew             = TRUE;

        if ( !++pDhcpv4->maxInstanceOfClient )
        {
            pDhcpv4->maxInstanceOfClient = 1;
        }
        pDhcpc->Cfg.InstanceNumber = pDhcpv4->maxInstanceOfClient;
        pCxtLink->InstanceNumber   = pDhcpc->Cfg.InstanceNumber;

        _ansc_sprintf( pDhcpc->Cfg.Alias, "Client%d", pDhcpc->Cfg.InstanceNumber);

        /* Put into our list */
        SListPushEntryByInsNum(&pDhcpv4->ClientList, (PCONTEXT_LINK_OBJECT)pCxtLink);
    
        /* we recreate the configuration because we has new delay_added entry for dhcpv4 */
        WanMgr_Dhcpv4RegSetDhcpv4Info(pDhcpv4);
    }
    return pCxtLink;
}

/*
    Description:
        The API removes the designated DHCP client entry. 
    Arguments:
        pAlias        The entry is identified through Alias.
*/
ANSC_STATUS
WanMgr_DmlDhcpcDelEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    return ANSC_STATUS_FAILURE;
}

/*
Description:
    The API re-configures the designated DHCP client entry. 
Arguments:
    pAlias        The entry is identified through Alias.
    pEntry        The new configuration is passed through this argument, even Alias field can be changed.
*/

ANSC_STATUS
WanMgr_DmlDhcpcSetCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_DHCPC_CFG         pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(pCfg);
    ULONG                           index  = 0;
    /*don't allow to change dhcp configuration*/ 

    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
WanMgr_DmlDhcpcGetCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_DHCPC_CFG         pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ULONG       i = 0;
    char ifname[32] = {0};

    if ( !pCfg )
    {
        return ANSC_STATUS_FAILURE;
    }

    sprintf(pCfg->Alias,"eRouter");
    pCfg->bEnabled = TRUE;
    pCfg->InstanceNumber = 1;

    DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_GetActiveVirtIfData_locked();
    if(p_VirtIf != NULL){
        snprintf(pCfg->Interface, sizeof(pCfg->Interface), "%s", p_VirtIf->IP.Ipv4Data.ifname);
        WanMgrDml_GetIfaceData_release(NULL);
    }
    pCfg->PassthroughEnable = TRUE;
    pCfg->PassthroughDHCPPool[0] = 0;

    return ANSC_STATUS_SUCCESS;
}

#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
ANSC_STATUS
WanMgr_DmlDhcpcGetInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PDML_DHCPC_INFO        pInfo
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ANSC_STATUS  rc;

    if ( (!pInfo) || (ulInstanceNumber != 1) ){
        return ANSC_STATUS_FAILURE;
    }

    pInfo->Status = DML_DHCP_STATUS_Enabled;

    DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_GetActiveVirtIfData_locked();
    if(p_VirtIf != NULL)
    {
        pInfo->IPAddress.Value     = inet_addr(p_VirtIf->IP.Ipv4Data.ip);
        pInfo->SubnetMask.Value    = inet_addr(p_VirtIf->IP.Ipv4Data.mask);
        pInfo->IPRouters[0].Value  = inet_addr(p_VirtIf->IP.Ipv4Data.gateway);
        pInfo->DNSServers[0].Value = inet_addr(p_VirtIf->IP.Ipv4Data.dnsServer);
        pInfo->DNSServers[1].Value = inet_addr(p_VirtIf->IP.Ipv4Data.dnsServer1);

        pInfo->DHCPServer.Value = inet_addr(p_VirtIf->IP.Ipv4Data.dhcpServerId);
	pInfo->DHCPStatus = ((strcmp(p_VirtIf->IP.Ipv4Data.dhcpState, DHCP_STATE_BOUND) == 0) || 
                       (strcmp(p_VirtIf->IP.Ipv4Data.dhcpState, DHCP_STATE_RENEW) == 0)) ? DML_DHCPC_STATUS_Bound : DML_DHCPC_STATUS_Init;
        if (pInfo->DHCPStatus == DML_DHCPC_STATUS_Bound)
        {
            pInfo->LeaseTimeRemaining  = (p_VirtIf->IP.Ipv4Data.leaseReceivedTime + p_VirtIf->IP.Ipv4Data.leaseTime) - WanManager_getUpTime();
        }
        else 
        {
            pInfo->LeaseTimeRemaining = 0;
        }    
        WanMgrDml_GetIfaceData_release(NULL);
    }

    pInfo->NumDnsServers = 2;
    pInfo->NumIPRouters = 1;
    return ANSC_STATUS_SUCCESS;
}

#else
/*TODO: Should be removed once Unified DhcpManager  */
ANSC_STATUS
WanMgr_DmlDhcpcGetInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PDML_DHCPC_INFO        pInfo
    )
{
    UNREFERENCED_PARAMETER(hContext);
        ULONG i;
        dhcpv4c_ip_list_t ad;

    if ( (!pInfo) || (ulInstanceNumber != 1) ){
        return ANSC_STATUS_FAILURE;
    }

        pInfo->Status = DML_DHCP_STATUS_Enabled;
        dhcpv4c_get_ert_fsm_state((int*)&pInfo->DHCPStatus);
        dhcpv4c_get_ert_ip_addr((unsigned int*)&pInfo->IPAddress.Value);
        dhcpv4c_get_ert_mask((unsigned int*)&pInfo->SubnetMask.Value);
        pInfo->NumIPRouters = 1;
        dhcpv4c_get_ert_gw((unsigned int*)&pInfo->IPRouters[0].Value);
        ad.number = 0;
        dhcpv4c_get_ert_dns_svrs(&ad);
        pInfo->NumDnsServers = ad.number;
    if (pInfo->NumDnsServers > DML_DHCP_MAX_ENTRIES)
    {
        CcspTraceError(("!!! Max DHCP Entry Overflow: %d",ad.number));
            pInfo->NumDnsServers = DML_DHCP_MAX_ENTRIES; // Fail safe
    }
        for(i=0; i< pInfo->NumDnsServers;i++)
                pInfo->DNSServers[i].Value = ad.addrs[i];
    if (pInfo->DHCPStatus == DML_DHCPC_STATUS_Bound)
    {
        dhcpv4c_get_ert_remain_lease_time((unsigned int*)&pInfo->LeaseTimeRemaining);
    }
    else 
    {
        pInfo->LeaseTimeRemaining = 0;
    }   
        dhcpv4c_get_ert_dhcp_svr((unsigned int*)&pInfo->DHCPServer);

    return ANSC_STATUS_SUCCESS;
}
#endif
/*
    Description:
        The API initiates a DHCP client renewal. 
    Arguments:
        pAlias        The entry is identified through Alias.
*/
ANSC_STATUS
WanMgr_DmlDhcpcRenew
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    if(ulInstanceNumber != 1)
        return(ANSC_STATUS_FAILURE);
#ifndef _HUB4_PRODUCT_REQ_ //TODO : clean up ?
    v_secure_system("sysevent set dhcp_client-renew");
#endif
    return(ANSC_STATUS_SUCCESS);
}

/*
 *  DHCP Client Send/Req Option
 *
 *  The options are managed on top of a DHCP client,
 *  which is identified through pClientAlias
 */

ULONG
WanMgr_DmlDhcpcGetNumberOfSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    return 0;
}

ANSC_STATUS
WanMgr_DmlDhcpcGetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        PCOSA_DML_DHCP_OPT          pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(ulIndex);
    UNREFERENCED_PARAMETER(pEntry);
    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
WanMgr_DmlDhcpcGetSentOptionbyInsNum
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCP_OPT          pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ULONG index   = 0;
    ULONG i     = 0;

    for(i = 0; i < g_Dhcp4ClientNum; i++)
    {
        if ( CH_g_dhcpv4_client[i].Cfg.InstanceNumber ==  ulClientInstanceNumber)
        {
            for( index = 0;  index < g_Dhcp4ClientSentOptNum[i]; index++)
            {
                if ( pEntry->InstanceNumber == g_dhcpv4_client_sent[i][index].InstanceNumber )
                {
                    AnscCopyMemory( pEntry, &g_dhcpv4_client_sent[i][index], sizeof(COSA_DML_DHCP_OPT));
                    return ANSC_STATUS_SUCCESS;
                }
            } 
        }
    }

    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
WanMgr_DmlDhcpcSetSentOptionValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
WanMgr_DmlDhcpcAddSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCP_OPT          pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(pEntry);
    return ANSC_STATUS_FAILURE;
}



ANSC_STATUS
WanMgr_DmlDhcpcDelSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
WanMgr_DmlDhcpcSetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCP_OPT          pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(pEntry);
    return ANSC_STATUS_FAILURE;
}

/*
 *  DHCP Client Send/Req Option
 *
 *  The options are managed on top of a DHCP client,
 *  which is identified through pClientAlias
 */
ULONG
WanMgr_DmlDhcpcGetNumberOfReqOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    return 0;
}

ANSC_STATUS
WanMgr_DmlDhcpcGetReqOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        PDML_DHCPC_REQ_OPT     pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(ulIndex);
    UNREFERENCED_PARAMETER(pEntry);
    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
WanMgr_DmlDhcpcGetReqOptionbyInsNum
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPC_REQ_OPT     pEntry
    )
{
   UNREFERENCED_PARAMETER(hContext);
   UNREFERENCED_PARAMETER(ulClientInstanceNumber);
   UNREFERENCED_PARAMETER(pEntry);
   return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
WanMgr_DmlDhcpcSetReqOptionValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(ulIndex);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    UNREFERENCED_PARAMETER(pAlias);
    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
WanMgr_DmlDhcpcAddReqOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPC_REQ_OPT     pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(pEntry);
    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
WanMgr_DmlDhcpcDelReqOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
WanMgr_DmlDhcpcSetReqOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPC_REQ_OPT          pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UNREFERENCED_PARAMETER(pEntry);
    return ANSC_STATUS_FAILURE;
}
