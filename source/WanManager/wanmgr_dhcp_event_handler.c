/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "wanmgr_data.h"
#include "wanmgr_rbus_handler_apis.h"
#include "ipc_msg.h"
#include "wanmgr_interface_sm.h"
#include "wanmgr_dhcp_client_events.h"
#include "wanmgr_net_utils.h"




static void copyDhcpv4Data(WANMGR_IPV4_DATA* pDhcpv4Data, const DHCP_MGR_IPV4_MSG* leaseInfo) 
{
    CcspTraceInfo(("\n"
        "=========================================\n"
        "|       New IPv4 Lease Information      |\n"
        "=========================================\n"
        "| ifname              : %-15s |\n"
        "| ip                  : %-15s |\n"
        "| mask                : %-15s |\n"
        "| gateway             : %-15s |\n"
        "| dnsServer           : %-15s |\n"
        "| dnsServer1          : %-15s |\n"
        "| timeZone            : %-15s |\n"
        "| mtuSize             : %-15u |\n"
        "| timeOffset          : %-15d |\n"
        "| isTimeOffsetAssigned: %-15d |\n"
        "| upstreamCurrRate    : %-15u |\n"
        "=========================================\n",
        leaseInfo->ifname, leaseInfo->address, leaseInfo->netmask, leaseInfo->gateway,
        leaseInfo->dnsServer, leaseInfo->dnsServer1, leaseInfo->timeZone, leaseInfo->mtuSize, leaseInfo->timeOffset,
        leaseInfo->isTimeOffsetAssigned, leaseInfo->upstreamCurrRate));

    strncpy(pDhcpv4Data->ifname, leaseInfo->ifname, sizeof(pDhcpv4Data->ifname) - 1);
    strncpy(pDhcpv4Data->ip, leaseInfo->address, sizeof(pDhcpv4Data->ip) - 1);
    strncpy(pDhcpv4Data->mask, leaseInfo->netmask, sizeof(pDhcpv4Data->mask) - 1);
    strncpy(pDhcpv4Data->gateway, leaseInfo->gateway, sizeof(pDhcpv4Data->gateway) - 1);
    strncpy(pDhcpv4Data->dnsServer, leaseInfo->dnsServer, sizeof(pDhcpv4Data->dnsServer) - 1);
    strncpy(pDhcpv4Data->dnsServer1, leaseInfo->dnsServer1, sizeof(pDhcpv4Data->dnsServer1) - 1);
    strncpy(pDhcpv4Data->timeZone, leaseInfo->timeZone, sizeof(pDhcpv4Data->timeZone) - 1);
    pDhcpv4Data->mtuSize = leaseInfo->mtuSize;
    pDhcpv4Data->timeOffset = leaseInfo->timeOffset;
    pDhcpv4Data->isTimeOffsetAssigned = leaseInfo->isTimeOffsetAssigned;
    pDhcpv4Data->upstreamCurrRate = leaseInfo->upstreamCurrRate;
}

static void copyDhcpv6Data(WANMGR_IPV6_DATA* pDhcpv6Data, const DHCP_MGR_IPV6_MSG* leaseInfo) 
{
    CcspTraceInfo(("\n"
        "==================================================================\n"
        "|                New IPv6 Lease Information                      |\n"
        "==================================================================\n"
        "| ifname              : %-40s |\n"
        "| address             : %-40s |\n"
        "| nameserver          : %-40s |\n"
        "| nameserver1         : %-40s |\n"
        "| domainName          : %-40s |\n"
        "| sitePrefix          : %-40s |\n"
        "| prefixPltime        : %-40u |\n"
        "| prefixVltime        : %-40u |\n"
        "| addrAssigned        : %-40d |\n"
        "| prefixAssigned      : %-40d |\n"
        "| domainNameAssigned  : %-40d |\n"
#ifdef FEATURE_MAPT
        "| maptAssigned        : %-40d |\n"
#endif
#ifdef FEATURE_DSLITE_V2
        "| endpointName        : %-40s |\n"
#endif
        "=================================================================\n",
        leaseInfo->ifname, leaseInfo->address, leaseInfo->nameserver, leaseInfo->nameserver1,
        leaseInfo->domainName, leaseInfo->sitePrefix, leaseInfo->prefixPltime, leaseInfo->prefixVltime,
        leaseInfo->addrAssigned, leaseInfo->prefixAssigned, leaseInfo->domainNameAssigned
#ifdef FEATURE_MAPT
        , leaseInfo->maptAssigned
#endif
#ifdef FEATURE_DSLITE_V2
        , leaseInfo->endpointName
#endif
    ));

    strncpy(pDhcpv6Data->ifname, leaseInfo->ifname, sizeof(pDhcpv6Data->ifname) - 1);
    strncpy(pDhcpv6Data->address, leaseInfo->address, sizeof(pDhcpv6Data->address) - 1);
    strncpy(pDhcpv6Data->nameserver, leaseInfo->nameserver, sizeof(pDhcpv6Data->nameserver) - 1);
    strncpy(pDhcpv6Data->nameserver1, leaseInfo->nameserver1, sizeof(pDhcpv6Data->nameserver1) - 1);
    strncpy(pDhcpv6Data->domainName, leaseInfo->domainName, sizeof(pDhcpv6Data->domainName) - 1);
    strncpy(pDhcpv6Data->sitePrefix, leaseInfo->sitePrefix, sizeof(pDhcpv6Data->sitePrefix) - 1);
    pDhcpv6Data->prefixPltime = leaseInfo->prefixPltime;
    pDhcpv6Data->prefixVltime = leaseInfo->prefixVltime;
    pDhcpv6Data->addrAssigned = leaseInfo->addrAssigned;
    pDhcpv6Data->prefixAssigned = leaseInfo->prefixAssigned;
    pDhcpv6Data->domainNameAssigned = leaseInfo->domainNameAssigned;
    pDhcpv6Data->ipv6_TimeOffset = leaseInfo->ipv6_TimeOffset;
#ifdef FEATURE_DSLITE_V2
    strncpy(pDhcpv6Data->endpointName, leaseInfo->endpointName, sizeof(pDhcpv6Data->endpointName) - 1);
#endif
}

pthread_mutex_t DhcpClientEvents_mutex = PTHREAD_MUTEX_INITIALIZER;

void* WanMgr_DhcpClientEventsHandler_Thread(void *arg)
{
    DhcpEventThreadArgs *eventData = (DhcpEventThreadArgs *)arg;
    pthread_mutex_lock(&DhcpClientEvents_mutex);
    pthread_detach(pthread_self());

    DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(eventData->ifName);
    if(pVirtIf != NULL)
    {
        if(eventData->version == DHCPV4)
        {    
            switch (eventData->type)
            {
                case DHCP_CLIENT_STARTED:
                    CcspTraceInfo(("%s-%d : DHCPv4 client started for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    pVirtIf->IP.Dhcp4cStatus = DHCPC_STARTED;
                    break;

                case DHCP_CLIENT_STOPPED:
                    CcspTraceInfo(("%s-%d : DHCPv4 client stopped for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    pVirtIf->IP.Dhcp4cStatus = DHCPC_STOPPED;
                    break;

                case DHCP_CLIENT_FAILED:
                    CcspTraceInfo(("%s-%d : DHCPv4 client failed for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    pVirtIf->IP.Dhcp4cStatus = DHCPC_FAILED;
                    break;

                case DHCP_LEASE_RENEW:
                    // TODO: Check for sysevents
                    pVirtIf->IP.Ipv4Renewed = TRUE;
                    CcspTraceInfo(("%s-%d : DHCPv4 lease renewed for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_UP);
                    break;

                case DHCP_LEASE_DEL:
                    CcspTraceInfo(("%s-%d : DHCPv4 lease expired for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_DOWN);
                    break;

                case DHCP_LEASE_UPDATE:
                    CcspTraceInfo(("%s-%d : DHCPv4 lease updated for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    copyDhcpv4Data(&(pVirtIf->IP.Ipv4Data), &(eventData->lease.v4));
                    pVirtIf->IP.Ipv4Changed = TRUE;
                    WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_UP);

                    char param_name[256] = {0};
                    snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv4Address", pVirtIf->baseIfIdx + 1, pVirtIf->VirIfIdx + 1);
                    WanMgr_Rbus_EventPublishHandler(param_name, pVirtIf->IP.Ipv4Data.ip, RBUS_STRING);
                    // TODO: Check for sysevents
                    break;

                default:
                    CcspTraceError(("%s-%d : Unknown DHCPv4 event type %d for %s\n", __FUNCTION__, __LINE__, eventData->type, pVirtIf->Name));
                    break;
            }
        }
        else if(eventData->version == DHCPV6)
        {
            switch (eventData->type)
            {
                case DHCP_CLIENT_STARTED:
                    CcspTraceInfo(("%s-%d : DHCPv6 client started for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    pVirtIf->IP.Dhcp6cStatus = DHCPC_STARTED;
                    break;

                case DHCP_CLIENT_STOPPED:
                    CcspTraceInfo(("%s-%d : DHCPv6 client stopped for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    pVirtIf->IP.Dhcp6cStatus = DHCPC_STOPPED;
                    break;

                case DHCP_CLIENT_FAILED:
                    CcspTraceInfo(("%s-%d : DHCPv6 client failed for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    pVirtIf->IP.Dhcp6cStatus = DHCPC_FAILED;
                    break;

                case DHCP_LEASE_RENEW:
                    pVirtIf->IP.Ipv6Renewed = TRUE;
                    //TODO: Check for sysevents
                    if(pVirtIf->IP.Ipv6Data.prefixAssigned == TRUE)
                    {
                        WanManager_Ipv6PrefixUtil(pVirtIf->Name, SET_LFT, pVirtIf->IP.Ipv6Data.prefixPltime, pVirtIf->IP.Ipv6Data.prefixVltime);
                        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_RADVD_RESTART, NULL, 0);
                    }
                    CcspTraceInfo(("%s-%d : DHCPv6 lease renewed for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_IPV6_UP);
                    break;

                case DHCP_LEASE_DEL:
                    CcspTraceInfo(("%s-%d : DHCPv6 lease expired for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_IPV6_DOWN);
                    break;

                case DHCP_LEASE_UPDATE:
                    CcspTraceInfo(("%s-%d : DHCPv6 lease updated for %s\n", __FUNCTION__, __LINE__, pVirtIf->Name));
                    DHCP_MGR_IPV6_MSG* leaseInfo = &(eventData->lease.v6);
                    copyDhcpv6Data(&(pVirtIf->IP.Ipv6Data), leaseInfo);
                    pVirtIf->IP.Ipv6Changed = TRUE;
                    //TODO : WAN ip creation from IA_PD if required. address assignment on LAN bridge.
                    WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_IPV6_UP);

#ifdef FEATURE_MAPT
                    CcspTraceNotice(("FEATURE_MAPT: MAP-T Enable %d\n", leaseInfo->maptAssigned));
                    if (leaseInfo->maptAssigned)
                    {
#ifdef FEATURE_MAPT_DEBUG
                        MaptInfo("--------- Got a new event in Wanmanager for MAPT_CONFIG ---------");
#endif
                        //Compare  MAP-T previous data
                        if (memcmp(&(pVirtIf->MAP.dhcp6cMAPTparameters), &(leaseInfo->mapt), sizeof(ipc_mapt_data_t)) != 0)
                        {
                            pVirtIf->MAP.MaptChanged = TRUE;
                            CcspTraceInfo(("MAPT configuration has been changed \n"));
                        }
                        memcpy(&(pVirtIf->MAP.dhcp6cMAPTparameters), &(leaseInfo->mapt), sizeof(ipc_mapt_data_t));
                        // update MAP-T flags
                        WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_MAPT_START);
                    }
                    else
                    {
                        if (leaseInfo->prefixAssigned && !IS_EMPTY_STRING(leaseInfo->sitePrefix) && leaseInfo->prefixPltime != 0 && leaseInfo->prefixVltime != 0)
                        {
#ifdef FEATURE_MAPT_DEBUG
                            MaptInfo("--------- Got an event in Wanmanager for MAPT_STOP ---------");
#endif
                            // reset MAP-T parameters
                            memset(&(pVirtIf->MAP.dhcp6cMAPTparameters), 0, sizeof(ipc_mapt_data_t));
                            WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_MAPT_STOP);
                        }
                    }
#endif // FEATURE_MAPT
                    char param_name[256] = {0};
                    snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv6Address",  pVirtIf->baseIfIdx+1, pVirtIf->VirIfIdx+1);
                    WanMgr_Rbus_EventPublishHandler(param_name, pVirtIf->IP.Ipv6Data.address,RBUS_STRING);
                    snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv6Prefix",  pVirtIf->baseIfIdx+1, pVirtIf->VirIfIdx+1);
                    WanMgr_Rbus_EventPublishHandler(param_name, pVirtIf->IP.Ipv6Data.sitePrefix,RBUS_STRING);
                    //TODO: Check for sysevents
                    break;

                default:
                    CcspTraceError(("%s-%d : Unknown DHCPv6 event type %d for %s\n", __FUNCTION__, __LINE__, eventData->type, pVirtIf->Name));
                    break;
            }
        } 
        WanMgr_VirtualIfaceData_release(pVirtIf);
    }
    free(eventData);
    pthread_mutex_unlock(&DhcpClientEvents_mutex);
    pthread_exit(NULL);
    return NULL;
}
