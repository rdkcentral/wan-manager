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

/* ---- Include Files ---------------------------------------- */
#include <sys/un.h>
#include <errno.h>
#include <sysevent/sysevent.h>
#include "wanmgr_ipc.h"
#include "wanmgr_data.h"
#include "wanmgr_sysevents.h"
#include "wanmgr_dhcpv4_apis.h"
#include "wanmgr_telemetry.h"

#define WANMGR_MAX_IPC_PROCCESS_TRY             5
#define WANMGR_IPC_PROCCESS_TRY_WAIT_TIME       100000 //us


typedef struct _WanIpcCtrl_t_
{
    INT interfaceIdx;
} WanIpcCtrl_t;


extern int sysevent_fd;
extern token_t sysevent_token;


/* ---- Private Functions ------------------------------------ */
#ifdef FEATURE_IPOE_HEALTH_CHECK
static ANSC_STATUS Wan_ForceRenewDhcpIPv4(char * ifName);
#endif /*FEATURE_IPOE_HEALTH_CHECK*/



/* ---- Private Variables ------------------------------------ */



//ANSC_STATUS WanManager_sendIpcMsgToClient_AndGetReplyWithTimeout(ipc_msg_payload_t * payload)
//{
//    return ANSC_STATUS_SUCCESS;
//}
//
//
//ANSC_STATUS WanManager_sendIpcMsgToClient(ipc_msg_payload_t * payload)
//{
//    return ANSC_STATUS_SUCCESS;
//}


static ANSC_STATUS WanMgr_IpcNewIpv4Msg(ipc_dhcpv4_data_t* pNewIpv4Msg)
{
    ANSC_STATUS retStatus = ANSC_STATUS_FAILURE;
    INT try = 0;

    CcspTraceInfo(("%s %d - Received Ipc Ipv4Msg for %s\n", __FUNCTION__, __LINE__,pNewIpv4Msg->dhcpcInterface));

    while((retStatus != ANSC_STATUS_SUCCESS) && (try < WANMGR_MAX_IPC_PROCCESS_TRY))
    {
        //get iface data
        DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(pNewIpv4Msg->dhcpcInterface);
        if(pVirtIf != NULL)
        {
            //check if previously message was already handled
            if(pVirtIf->IP.pIpcIpv4Data == NULL)
            {
                //allocate
                pVirtIf->IP.pIpcIpv4Data = (ipc_dhcpv4_data_t*) malloc(sizeof(ipc_dhcpv4_data_t));
                if(pVirtIf->IP.pIpcIpv4Data != NULL)
                {
                    // copy data
                    memcpy(pVirtIf->IP.pIpcIpv4Data, pNewIpv4Msg, sizeof(ipc_dhcpv4_data_t));
                    retStatus = ANSC_STATUS_SUCCESS;
                }
            }

            //release lock
            WanMgr_VirtualIfaceData_release(pVirtIf);
        }

        if(retStatus != ANSC_STATUS_SUCCESS)
        {
            try++;
            usleep(WANMGR_IPC_PROCCESS_TRY_WAIT_TIME);
        }
    }

    return retStatus;
}


static ANSC_STATUS WanMgr_IpcNewIpv6Msg(ipc_dhcpv6_data_t* pNewIpv6Msg)
{
    ANSC_STATUS retStatus = ANSC_STATUS_FAILURE;
    INT try = 0;

    CcspTraceInfo(("%s %d - Received Ipc Ipv6Msg for %s\n", __FUNCTION__, __LINE__, pNewIpv6Msg->ifname));

    while((retStatus != ANSC_STATUS_SUCCESS) && (try < WANMGR_MAX_IPC_PROCCESS_TRY))
    {
        //get iface data
        DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(pNewIpv6Msg->ifname);
        if(pVirtIf != NULL)
        {
            //check if previously message was already handled
            if(pVirtIf->IP.pIpcIpv6Data == NULL)
            {
                //allocate
                pVirtIf->IP.pIpcIpv6Data = (ipc_dhcpv6_data_t*) malloc(sizeof(ipc_dhcpv6_data_t));
                if(pVirtIf->IP.pIpcIpv6Data != NULL)
                {
                    // copy data
                    memcpy(pVirtIf->IP.pIpcIpv6Data, pNewIpv6Msg, sizeof(ipc_dhcpv6_data_t));
                    retStatus = ANSC_STATUS_SUCCESS;
                }
            }

            //release lock
            WanMgr_VirtualIfaceData_release(pVirtIf);
        }

        if(retStatus != ANSC_STATUS_SUCCESS)
        {
            try++;
            usleep(WANMGR_IPC_PROCCESS_TRY_WAIT_TIME);
        }
    }

    return retStatus;
}

ANSC_STATUS WanMgr_SetInterfaceStatus(char *ifName, wanmgr_iface_status_t state)
{
    DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVirtualIfaceByName_locked(ifName);

    if(pVirtIf != NULL)
    {
        WanManager_UpdateInterfaceStatus(pVirtIf, state);
        WanMgr_VirtualIfaceData_release(pVirtIf);
        return ANSC_STATUS_SUCCESS;
    }
    return ANSC_STATUS_FAILURE;
}

#ifdef FEATURE_IPOE_HEALTH_CHECK

static ANSC_STATUS WanMgr_IpcNewIhcMsg(ipc_ihc_data_t *pIhcMsg)
{
    if (pIhcMsg == NULL)
    {
        CcspTraceError(("[%s-%d] Failed to process IPoE v6 Echo Renew Event \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    char conn_status[BUFLEN_16] = {0};

    switch(pIhcMsg->msgType)
    {
        case IPOE_MSG_IHC_ECHO_RENEW_IPV6:
            CcspTraceInfo(("[%s-%d] Received IPOE_MSG_IHC_ECHO_RENEW_IPV6 from IHC for intf: %s \n", __FUNCTION__, __LINE__, pIhcMsg->ifName));
            if (Wan_ForceRenewDhcpIPv6(pIhcMsg->ifName) != ANSC_STATUS_SUCCESS)
            {
                CcspTraceError(("[%s-%d] Failed to process IPoE v6 Echo Renew Event \n", __FUNCTION__, __LINE__));
                return ANSC_STATUS_FAILURE;
            }
            break;
        case IPOE_MSG_IHC_ECHO_RENEW_IPV4:
            CcspTraceInfo(("[%s-%d] Received IPOE_MSG_IHC_ECHO_RENEW_IPV4 from IHC for intf: %s \n", __FUNCTION__, __LINE__, pIhcMsg->ifName));
            if (Wan_ForceRenewDhcpIPv4(pIhcMsg->ifName) != ANSC_STATUS_SUCCESS)
            {
                CcspTraceError(("[%s-%d] Failed to process IPoE v6 Echo Renew Event \n", __FUNCTION__, __LINE__));
                return ANSC_STATUS_FAILURE;
            }
            break;
        case IPOE_MSG_IHC_ECHO_IPV6_UP:
            /* Check if we get the IPv6 connection UP message from the
               IPOE Health Check, in case the IPV6 status is DOWN set
               it to UP.
               */
            CcspTraceInfo(("[%s-%d] Received IPOE_MSG_IHC_ECHO_IPV6_UP from IHC for intf: %s \n", __FUNCTION__, __LINE__, pIhcMsg->ifName));
            sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV6_CONNECTION_STATE, conn_status, sizeof(conn_status));
            if(strcmp(conn_status, WAN_STATUS_DOWN) == 0)
            {
                CcspTraceInfo(("Setting IPV6 Connection state to UP \n"));
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV6_CONNECTION_STATE, WAN_STATUS_UP, 0);
            }
            {
                DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(pIhcMsg->ifName);
                if(pVirtIf != NULL)
                {
                    WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_CONNECTIVITY_CHECK_STATUS_UP_IPV6);
                    WanMgr_VirtualIfaceData_release(pVirtIf);
                }
            }			    
            break;
        case IPOE_MSG_IHC_ECHO_IPV4_UP:
            /* Check if we get the IPv4 connection UP message from the
               IPOE Health Check, in case the IPv4 status is DOWN, set
               it to UP.
               */
            CcspTraceInfo(("[%s-%d] Received IPOE_MSG_IHC_ECHO_IPV4_UP from IHC for intf: %s \n", __FUNCTION__, __LINE__, pIhcMsg->ifName));
            sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_IPV4_CONNECTION_STATE, conn_status, sizeof(conn_status));
            if(strcmp(conn_status, WAN_STATUS_DOWN) == 0)
            {
                CcspTraceInfo(("Setting IPv4 Connection state to UP \n"));
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IPV4_CONNECTION_STATE, WAN_STATUS_UP, 0);
            }
            {
                DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(pIhcMsg->ifName);
                if(pVirtIf != NULL)
                {
                    WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_INFO_CONNECTIVITY_CHECK_STATUS_UP_IPV4);		
                    WanMgr_VirtualIfaceData_release(pVirtIf);
                }
            }		    
            break;
        case IPOE_MSG_IHC_ECHO_FAIL_IPV4:
            CcspTraceInfo(("[%s-%d] Received IPOE_MSG_IHC_ECHO_FAIL_IPV4 from IHC for intf: %s \n", __FUNCTION__, __LINE__, pIhcMsg->ifName));
            {
                DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(pIhcMsg->ifName);
                if(pVirtIf != NULL)
                {
                    WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_WARN_CONNECTIVITY_CHECK_STATUS_FAILED_IPV4);
                    WanMgr_VirtualIfaceData_release(pVirtIf);
                }
            }	    	    	    
            return WanMgr_SetInterfaceStatus(pIhcMsg->ifName, WANMGR_IFACE_CONNECTION_DOWN);
            break;
        case IPOE_MSG_IHC_ECHO_FAIL_IPV6:
            CcspTraceInfo(("[%s-%d] Received IPOE_MSG_IHC_ECHO_FAIL_IPV6 from IHC for intf: %s \n", __FUNCTION__, __LINE__, pIhcMsg->ifName));
            {
                DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(pIhcMsg->ifName);
                if(pVirtIf != NULL)
                {
                    WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_WARN_CONNECTIVITY_CHECK_STATUS_FAILED_IPV6);
                    WanMgr_VirtualIfaceData_release(pVirtIf);
                }    
            }		    
            return WanMgr_SetInterfaceStatus(pIhcMsg->ifName, WANMGR_IFACE_CONNECTION_IPV6_DOWN);
            break;
        case IPOE_MSG_IHC_ECHO_IPV4_IDLE:
            CcspTraceInfo(("[%s-%d] Received IPOE_MSG_IHC_ECHO_IPV4_IDLE from IHC for intf: %s \n", __FUNCTION__, __LINE__, pIhcMsg->ifName));
            {
                DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(pIhcMsg->ifName);
                if(pVirtIf != NULL)
                {
                    WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_WARN_CONNECTIVITY_CHECK_STATUS_IDLE_IPV4);
                    WanMgr_VirtualIfaceData_release(pVirtIf);
                }
            }
            break;
        case IPOE_MSG_IHC_ECHO_IPV6_IDLE:
            CcspTraceInfo(("[%s-%d] Received IPOE_MSG_IHC_ECHO_FAIL_IPV4 from IHC for intf: %s \n", __FUNCTION__, __LINE__, pIhcMsg->ifName));
            {
                DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(pIhcMsg->ifName);
                if(pVirtIf != NULL)
                {
                    WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_WARN_CONNECTIVITY_CHECK_STATUS_IDLE_IPV6);
                    WanMgr_VirtualIfaceData_release(pVirtIf);
                }
            }	    
            break;			    
        default:
            CcspTraceError(("[%s-%d] Invalid message type \n", __FUNCTION__, __LINE__));
            return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS Wan_ForceRenewDhcpIPv4(char *ifName)
{
#if  defined( FEATURE_RDKB_DHCP_MANAGER )
    char dmlName[256] = {0};
    DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVirtualIfaceByName_locked(ifName);
    if(pVirtIf != NULL)
    {
        snprintf( dmlName, sizeof(dmlName), "%s.Renew", pVirtIf->IP.DHCPv4Iface );
        if (ANSC_STATUS_SUCCESS == WanMgr_RdkBus_SetParamValues(DHCPMGR_COMPONENT_NAME, DHCPMGR_DBUS_PATH, dmlName , "true", ccsp_boolean, TRUE))
        {
            CcspTraceInfo(("%s %d - Successfully set [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
        }
        else
        {
            CcspTraceInfo(("%s %d - Failed setting [%s] to DHCP Manager \n", __FUNCTION__, __LINE__, pVirtIf->Name));
        }
        WanMgr_VirtualIfaceData_release(pVirtIf);
        return ANSC_STATUS_SUCCESS;
    }
    
#else
    /*send triggered renew request to DHCPC*/
    int pid = util_getPidByName(DHCPV4_CLIENT_NAME, ifName);
    if (pid > 0)
    {
        CcspTraceInfo(("sending SIGUSR1 to %s[pid=%d], this will let the %s to send renew packet out \n", DHCPV4_CLIENT_NAME, pid, DHCPV4_CLIENT_NAME));
        util_signalProcess(pid, SIGUSR1);
    }
#endif
    return  ANSC_STATUS_SUCCESS; 
}

#endif

ANSC_STATUS Wan_ForceRenewDhcpIPv6(char *ifName)
{

    /*send triggered renew request to DHCPv6C*/
    int pid = util_getPidByName(DHCPV6_CLIENT_NAME, ifName);
    if (pid > 0 )
    {
        CcspTraceInfo(("sending SIGUSR2 to dhcp6c, this will let the dhcp6c to send renew packet out \n"));
        util_signalProcess(pid, SIGUSR2);
    }

    return  ANSC_STATUS_SUCCESS; 
}

static void* IpcServerThread( void *arg )
{

    //detach thread from caller stack
    pthread_detach(pthread_self());

    // local variables
    BOOL bRunning = TRUE;
    int   ipcListenFd;   /* Unix domain IPC listening socket fd */
    while(1)
    {

        CcspTraceError(("%s %d Creating nn_socket and binding %s\n", __FUNCTION__, __LINE__,WAN_MANAGER_ADDR));
        ipcListenFd = nn_socket(AF_SP, NN_PULL);

        if (ipcListenFd < 0)
        {
            CcspTraceError(("Error: nn_socket failed[%s]\n",nn_strerror(nn_errno ())));
            return NULL;
        }

        if (nn_bind(ipcListenFd, WAN_MANAGER_ADDR) < 0)
        {
            CcspTraceError(("Error: nn_bind failed[%s] to %s retry...\n",nn_strerror(nn_errno ()), WAN_MANAGER_ADDR));
            nn_close (ipcListenFd);
            sleep(5);
        }else
        {
            CcspTraceInfo(("%s %d ipcListenFd %d bind is successful\n", __FUNCTION__, __LINE__, ipcListenFd));
            break;
        }
    }


    int bytes = 0;
    int msg_size = sizeof(ipc_msg_payload_t);
    ipc_msg_payload_t ipc_msg;
    memset (&ipc_msg, 0, sizeof(ipc_msg_payload_t));

    while (bRunning)
    {
        bytes = nn_recv(ipcListenFd, (ipc_msg_payload_t *)&ipc_msg, msg_size, 0);
        if ((bytes == msg_size))
        {
            switch(ipc_msg.msg_type)
            {
                case DHCPC_STATE_CHANGED:
                    if (WanMgr_IpcNewIpv4Msg(&(ipc_msg.data.dhcpv4)) != ANSC_STATUS_SUCCESS)
                    {
                        CcspTraceError(("[%s-%d] Failed to proccess DHCPv4 state change message \n", __FUNCTION__, __LINE__));
                    }
                    break;
                case DHCP6C_STATE_CHANGED:
                    if (WanMgr_IpcNewIpv6Msg(&(ipc_msg.data.dhcpv6)) != ANSC_STATUS_SUCCESS)
                    {
                        CcspTraceError(("[%s-%d] Failed to proccess DHCPv6 state change message for %s \n", __FUNCTION__, __LINE__,ipc_msg.data.dhcpv6.ifname));
                    }
                    break;
#ifdef FEATURE_IPOE_HEALTH_CHECK
                case IHC_STATE_CHANGE:
                    if (WanMgr_IpcNewIhcMsg(&(ipc_msg.data.ihcData)) != ANSC_STATUS_SUCCESS)
                    {
                        CcspTraceError(("[%s-%d] Failed to proccess IHC state change message \n", __FUNCTION__, __LINE__));
                    }
                    break;
#endif
                default:
                        CcspTraceError(("[%s-%d] Invalid  Message sent to Wan Manager\n", __FUNCTION__, __LINE__));
            }
        }
        else
        {
            CcspTraceError(("[%s-%d] message size unexpected\n", __FUNCTION__, __LINE__));
        }
    }

    pthread_exit(NULL);
}


#ifdef FEATURE_IPOE_HEALTH_CHECK
static void WanMgr_RemoveSingleQuote(char *buf)
{
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int data_len = strlen(buf);

    if(data_len > 0)
    {
        while (buf[i] != '\0' && i < data_len) {
            if (buf[i] != '\'') {
                buf[j++] = buf[i];
            }
            i++;
        }
    }
    buf[j] = '\0';
    return 0;
}

ANSC_STATUS WanMgr_SendMsgToIHC (ipoe_msg_type_t msgType, char *ifName)
{
    int sock = -1;
    int conn = -1;

    ipc_ihc_data_t msgBody;
    memset (&msgBody, 0, sizeof(ipc_ihc_data_t));
    msgBody.msgType = msgType;
    char domainName[128] = {0};

    if (msgType == IPOE_MSG_WAN_CONNECTION_IPV6_UP)
    {
        // V6 UP Message needs Wan V6 IP
        char* pattern = NULL;
        char ipv6_prefix[INET6_ADDRSTRLEN] = {0};

        sysevent_get(sysevent_fd, sysevent_token, SYSCFG_FIELD_IPV6_PREFIX, ipv6_prefix, sizeof(ipv6_prefix));
        if(ipv6_prefix == NULL  || *ipv6_prefix == '\0'|| (0 == strncmp(ipv6_prefix, "(null)", strlen("(null)"))))
        {
            CcspTraceError(("[%s-%d] Unable to get ipv6_prefix..\n",  __FUNCTION__, __LINE__));
            return ANSC_STATUS_FAILURE;
        }

        pattern = strstr(ipv6_prefix, "/");
        if (pattern == NULL)
        {
            CcspTraceError(("[%s-%d] Invalid ipv6_prefix :%s\n", __FUNCTION__, __LINE__, ipv6_prefix));
            return ANSC_STATUS_FAILURE;
        }
        sprintf(pattern, "%c%c", '1', '\0'); //Form the global address with ::1
        strncpy(msgBody.ipv6Address, ipv6_prefix, sizeof(ipv6_prefix));

        if( 0 == syscfg_get( NULL, "ntp_server1", domainName, sizeof(domainName)) )
        {
            WanMgr_RemoveSingleQuote(domainName);
            snprintf(msgBody.domainName, sizeof(msgBody.domainName), "%s", domainName);
        }
        else
        {
            CcspTraceError(("[%s-%d] syscfg_get ntp_server1 failed\n", __FUNCTION__, __LINE__));
        }

        CcspTraceInfo(("[%s-%d] Sending IPOE_MSG_WAN_CONNECTION_IPV6_UP msg with addr :%s and domainName: [%s] \n", __FUNCTION__, __LINE__, msgBody.ipv6Address, msgBody.domainName));
    }
    else if (msgType == IPOE_MSG_WAN_CONNECTION_UP)
    {
        char ipv4_wan_address[IP_ADDR_LENGTH] = {0};
        char sysevent_param_name[BUFLEN_64] = {0};
        snprintf(sysevent_param_name, sizeof(sysevent_param_name), SYSEVENT_IPV4_IP_ADDRESS, ifName);
        sysevent_get(sysevent_fd, sysevent_token, sysevent_param_name, ipv4_wan_address, sizeof(ipv4_wan_address));
        if(ipv4_wan_address == NULL  || *ipv4_wan_address == '\0'|| (0 == strncmp(ipv4_wan_address, "(null)", strlen("(null)"))))
        {
            CcspTraceError(("[%s-%d] Unable to get ipv4_erouter0_ipaddr..\n",  __FUNCTION__, __LINE__));
            return ANSC_STATUS_FAILURE;
        }
        strncpy(msgBody.ipv4Address, ipv4_wan_address, sizeof(ipv4_wan_address));

        if( 0 == syscfg_get( NULL, "ntp_server1", domainName, sizeof(domainName)) )
        {
            WanMgr_RemoveSingleQuote(domainName);
            snprintf(msgBody.domainName, sizeof(msgBody.domainName), "%s", domainName);
        }
        else
        {
            CcspTraceError(("[%s-%d] syscfg_get ntp_server1 failed\n", __FUNCTION__, __LINE__));
        }

        CcspTraceInfo(("[%s-%d] Sending IPOE_MSG_WAN_CONNECTION_UP msg with addr :%s and domainName: [%s] \n", __FUNCTION__, __LINE__, msgBody.ipv4Address, msgBody.domainName));
    }
    strncpy(msgBody.ifName, ifName, IFNAME_LENGTH-1);

    CcspTraceInfo(("[%s-%d] Sending msg = %d for interface %s  \n", __FUNCTION__, __LINE__, msgType, ifName));

    int bytes = 0;
    int msgSize = sizeof(ipc_ihc_data_t);
    int socket_timeout_ms = DEFAULT_IPC_SOCKET_TIMEOUT;

    sock = nn_socket(AF_SP, NN_PUSH);
    if (sock < 0)
    {
        CcspTraceError(("[%s-%d] nn_socket failed\n"));
        return ANSC_STATUS_FAILURE;
    }
        
    CcspTraceInfo(("[%s %d]  Setting NN_SNDTIMEO, NN_RCVTIMEO to %d ms \n", __FUNCTION__, __LINE__, socket_timeout_ms));
    nn_setsockopt(sock, NN_SOL_SOCKET, NN_SNDTIMEO, &socket_timeout_ms, sizeof(int));
    nn_setsockopt(sock, NN_SOL_SOCKET, NN_RCVTIMEO, &socket_timeout_ms, sizeof(int));

    conn = nn_connect(sock, IHC_IPC_ADDR);
    if (conn < 0)
    {
        CcspTraceError(("[%s-%d] Failed to connect to the IPoE HEalth Check IPC socket \n", __FUNCTION__, __LINE__));
        nn_close (sock);
        return ANSC_STATUS_FAILURE;
    }
    bytes = nn_send(sock, (char *) &msgBody, msgSize, 0);
    if (bytes < 0)
    {
        CcspTraceError(("[%s-%d] Failed to send data to IPoE HEalth Check error=[%d][%s] \n", __FUNCTION__, __LINE__,errno, strerror(errno)));
        nn_close (sock);
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("[%s-%d] Successfully send %d bytes over nano msg  \n", __FUNCTION__, __LINE__,bytes));
    nn_close (sock);
    return ANSC_STATUS_SUCCESS;
}
#endif


ANSC_STATUS WanMgr_StartIpcServer()
{
    pthread_t ipcThreadId;
    ANSC_STATUS retStatus = ANSC_STATUS_FAILURE;
    int ret = -1;

    //create thread
    ret = pthread_create( &ipcThreadId, NULL, &IpcServerThread, NULL );

    if( 0 != ret )
    {
        CcspTraceInfo(("%s %d - Failed to start IPC Thread Error:%d\n", __FUNCTION__, __LINE__, ret));
    }
    else
    {
        CcspTraceInfo(("%s %d - IPC Thread Started Successfully\n", __FUNCTION__, __LINE__));
        retStatus = ANSC_STATUS_SUCCESS;
    }

#if defined(WAN_MANAGER_UNIFICATION_ENABLED) && !defined( RDKB_EXTENDER_ENABLED) && !defined( FEATURE_RDKB_DHCP_MANAGER )
    //TODO: XLE is still using the legacy CcspPaM dhcpv6c_dbg_thrd thread
    WanMgr_DhcpV6MsgHandlerInit();
#endif 

    return retStatus ;
}

