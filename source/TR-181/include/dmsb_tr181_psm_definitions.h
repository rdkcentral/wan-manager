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

#ifndef _DMSB_TR181_PSM_DEFINITIONS_
#define _DMSB_TR181_PSM_DEFINITIONS_

/**********************************************************************
                       X_RDK_WanManager.
**********************************************************************/

#define PSM_WANMANAGER_WANENABLE                            "dmsb.wanmanager.wanenable"
#define PSM_WANMANAGER_WANMODE                              "dmsb.wanmanager.wanmode"
#define PSM_WANMANAGER_FAILOVER_TYPE                        "dmsb.wanmanager.FailOverType"
#define PSM_WANMANAGER_RESTORATION_DELAY                    "dmsb.wanmanager.RestorationDelay"
#define PSM_WANMANAGER_ALLOW_REMOTE_IFACE                   "dmsb.wanmanager.allowremoteinterfaces"
#define PSM_WANMANAGER_BACKUPWANDNS_SUPPORT                 "dmsb.wanmanager.BackupWanDnsSupport"
#define PSM_WANMANAGER_IPV6EUI64FORMAT_SUPPPORT             "dmsb.wanmanager.IPv6EUI64FormatSupport"
#define PSM_WANMANAGER_CONFIGUREWANIPV6ON_LANBRIDGE_SUPPPORT  "dmsb.wanmanager.ConfigureWANIPv6OnLANBridgeSupport"
#define PSM_WANMANAGER_USEWANMAC_FOR_MGMT_SERVICES            "dmsb.wanmanager.UseWANMACForManagementServices"
#define PSM_WANMANAGER_INTERFACE_VLAN_MARKING_SUPPORT       "dmsb.wanmanager.InterfaceVLANMarkingSupport"

#define PSM_WANMANAGER_GROUP_COUNT                          "dmsb.wanmanager.group.Count"
#define PSM_WANMANAGER_GROUP_PERSIST_SELECTED_IFACE         "dmsb.wanmanager.group.%d.PersistSelectedInterface"
#define PSM_WANMANAGER_GROUP_EXTERNAL_CONTROL               "dmsb.wanmanager.group.%d.ExternalControl"
#define PSM_WANMANAGER_IF_NAME                              "dmsb.wanmanager.if.%d.Name"
#define PSM_WANMANAGER_IF_DISPLAY_NAME                      "dmsb.wanmanager.if.%d.DisplayName"
#define PSM_WANMANAGER_IF_ALIAS                             "dmsb.wanmanager.if.%d.AliasName"
#define PSM_WANMANAGER_IF_TYPE                              "dmsb.wanmanager.if.%d.Type"
#define PSM_WANMANAGER_IF_CONNECTION_TYPE                   "dmsb.wanmanager.if.%d.ConnectionType"
#define PSM_WANMANAGER_IF_BASEINTERFACE                     "dmsb.wanmanager.if.%d.BaseInterface"
#define PSM_WANMANAGER_IF_VIRIF_COUNT                       "dmsb.wanmanager.if.%d.VirtualInterfaceifcount"
#define PSM_WANMANAGER_IF_VIRIF_PPP_INTERFACE               "dmsb.wanmanager.if.%d.VirtualInterface.%d.PPPInterface"
#define PSM_WANMANAGER_IF_VIRIF_VLAN_INUSE                  "dmsb.wanmanager.if.%d.VirtualInterface.%d.VlanInUse"
#define PSM_WANMANAGER_IF_VIRIF_VLAN_TIMEOUT                "dmsb.wanmanager.if.%d.VirtualInterface.%d.Timeout" //VLAN timeout
#define PSM_WANMANAGER_IF_VIRIF_VLAN_INTERFACE_COUNT        "dmsb.wanmanager.if.%d.VirtualInterface.%d.VlanCount"
#define PSM_WANMANAGER_IF_VIRIF_VLAN_DISCOVERY_MODE         "dmsb.wanmanager.if.%d.VirtualInterface.%d.VlanDiscoveryMode"
#define PSM_WANMANAGER_IF_VIRIF_VLAN_INTERFACE_ENTRY        "dmsb.wanmanager.if.%d.VirtualInterface.%d.VLAN.%d.Interface"
#define PSM_WANMANAGER_IF_VIRIF_VLAN_MARKING_COUNT          "dmsb.wanmanager.if.%d.VirtualInterface.%d.MarkingCount"
#define PSM_WANMANAGER_IF_VIRIF_VLAN_MARKING_ENTRY          "dmsb.wanmanager.if.%d.VirtualInterface.%d.Marking.%d.Entry"
#define PSM_WANMANAGER_IF_VIRIF_ENABLE                      "dmsb.wanmanager.if.%d.VirtualInterface.%d.Enable"
#define PSM_WANMANAGER_IF_VIRIF_ALIAS                       "dmsb.wanmanager.if.%d.VirtualInterface.%d.Alias"
#define PSM_WANMANAGER_IF_VIRIF_NAME                        "dmsb.wanmanager.if.%d.VirtualInterface.%d.Name"
#define PSM_WANMANAGER_IF_VIRIF_IP_INTERFACE                "dmsb.wanmanager.if.%d.VirtualInterface.%d.IPInterface"
#define PSM_WANMANAGER_IF_VIRIF_IP_MODE                     "dmsb.wanmanager.if.%d.VirtualInterface.%d.IP.Mode"
#define PSM_WANMANAGER_IF_VIRIF_IP_V4SOURCE                 "dmsb.wanmanager.if.%d.VirtualInterface.%d.IP.IPv4Source"
#define PSM_WANMANAGER_IF_VIRIF_IP_DHCPv4                   "dmsb.wanmanager.if.%d.VirtualInterface.%d.IP.DHCPV4Interface"
#define PSM_WANMANAGER_IF_VIRIF_IP_V6SOURCE                 "dmsb.wanmanager.if.%d.VirtualInterface.%d.IP.IPv6Source"
#define PSM_WANMANAGER_IF_VIRIF_IP_DHCPv6                   "dmsb.wanmanager.if.%d.VirtualInterface.%d.IP.DHCPV6Interface"
#define PSM_WANMANAGER_IF_VIRIF_IP_PREFERREDMODE            "dmsb.wanmanager.if.%d.VirtualInterface.%d.IP.PreferredMode"
#define PSM_WANMANAGER_IF_VIRIF_IP_MODE_FORCE_ENABLE        "dmsb.wanmanager.if.%d.VirtualInterface.%d.IP.ModeForceEnable"
#define PSM_WANMANAGER_CONNECTIVITY_CHECK_TYPE              "dmsb.wanmanager.if.%d.VirtualInterface.%d.IP.ConnectivityCheckType"

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
#define PSM_WANMANAGER_IF_SELECTION_ENABLE                  "dmsb.wanmanager.if.%d.Selection.Enable"
#define PSM_WANMANAGER_IF_SELECTION_ACTIVELINK              "dmsb.wanmanager.if.%d.Selection.ActiveLink"
#define PSM_WANMANAGER_IF_SELECTION_REQUIRES_REBOOT         "dmsb.wanmanager.if.%d.Selection.RequiresReboot"
#define PSM_WANMANAGER_IF_SELECTION_GROUP                   "dmsb.wanmanager.if.%d.Selection.Group"
#define PSM_WANMANAGER_IF_SELECTION_PRIORITY                "dmsb.wanmanager.if.%d.Selection.Priority"
#define PSM_WANMANAGER_IF_SELECTION_TIMEOUT                 "dmsb.wanmanager.if.%d.Selection.Timeout"

#define PSM_WANMANAGER_IF_VIRIF_ENABLE_MAPT                 "dmsb.wanmanager.if.%d.VirtualInterface.%d.EnableMAPT"
#define PSM_WANMANAGER_IF_VIRIF_ENABLE_DSLITE               "dmsb.wanmanager.if.%d.VirtualInterface.%d.EnableDSLite"
#ifdef FEATURE_DSLITE_V2
#define PSM_WANMANAGER_IF_VIRIF_DSLITE_PATH                 "dmsb.wanmanager.if.%d.VirtualInterface.%d.DSLite.Path"
#endif
#define PSM_WANMANAGER_GROUP_POLICY                         "dmsb.wanmanager.group.%d.policy"
#define PSM_WANMANAGER_WANIFCOUNT                           "dmsb.wanmanager.wan.interfacecount"

#else

#define PSM_WANMANAGER_WANIFCOUNT                           "dmsb.wanmanager.wanifcount"
#define PSM_WANMANAGER_GROUP_POLICY                         "dmsb.wanmanager.wanpolicy"

#define PSM_WANMANAGER_IF_SELECTION_ENABLE                  "dmsb.wanmanager.if.%d.Enable"
#define PSM_WANMANAGER_IF_SELECTION_ACTIVELINK              "dmsb.wanmanager.if.%d.ActiveLink"
#define PSM_WANMANAGER_IF_SELECTION_PRIORITY                "dmsb.wanmanager.if.%d.Priority"
#define PSM_WANMANAGER_IF_SELECTION_TIMEOUT                 "dmsb.wanmanager.if.%d.SelectionTimeout"
#define PSM_WANMANAGER_IF_SELECTION_REQUIRES_REBOOT         "dmsb.wanmanager.if.%d.RebootOnConfiguration"
#define PSM_WANMANAGER_IF_SELECTION_GROUP                   "dmsb.wanmanager.if.%d.Group"

#define PSM_WANMANAGER_IF_VIRIF_ENABLE_MAPT                   "dmsb.wanmanager.if.%d.EnableMAPT"
#define PSM_WANMANAGER_IF_VIRIF_ENABLE_DSLITE                 "dmsb.wanmanager.if.%d.EnableDSLite"
#define PSM_WANMANAGER_IF_VIRIF_PPP_ENABLE                    "dmsb.wanmanager.if.%d.PPPEnable"
#define PSM_WANMANAGER_IF_WAN_PPP_LINKTYPE                  "dmsb.wanmanager.if.%d.PPPLinkType"
#define PSM_WANMANAGER_IF_WAN_PPP_IPCP_ENABLE               "dmsb.wanmanager.if.%d.PPPIPCPEnable"
#define PSM_WANMANAGER_IF_WAN_PPP_IPV6CP_ENABLE             "dmsb.wanmanager.if.%d.PPPIPV6CPEnable"
#define PSM_WANMANAGER_IF_VIRIF_ENABLE_DHCP                   "dmsb.wanmanager.if.%d.EnableDHCP"

#endif

#define PSM_WANMANAGER_IF_HOTSTANDBY                        "dmsb.wanmanager.if.%d.HotStandby"
#define PSM_SELFHEAL_REBOOT_STATUS                          "dmsb.selfheal.rebootstatus"

#define PSM_MESH_WAN_IFNAME                                     "dmsb.Mesh.WAN.Interface.Name"
#define PSM_MESH_WAN_DHCPv4                                     "dmsb.Mesh.WAN.Interface.DHCPV4Interface"

/**********************************************************************
                       Interface.{i}.Marking.{i}.
**********************************************************************/
#define PSM_MARKING_LIST                     "dmsb.wanmanager.if.%d.Marking.List"
#define PSM_MARKING_ALIAS                    "dmsb.wanmanager.if.%d.Marking.%s.Alias"
#define PSM_MARKING_SKBPORT                  "dmsb.wanmanager.if.%d.Marking.%s.SKBPort"
#define PSM_MARKING_SKBMARK                  "dmsb.wanmanager.if.%d.Marking.%s.SKBMark"
#define PSM_MARKING_ETH_PRIORITY_MASK        "dmsb.wanmanager.if.%d.Marking.%s.EthernetPriorityMark"

#endif
