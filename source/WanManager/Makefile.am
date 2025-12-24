##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2020 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

bin_PROGRAMS = wanmanager

wanmanager_DEPENDENCIES = \
        $(EXTRA_DEPENDENCIES) \
        ${top_builddir}/source/TR-181/middle_layer_src/libCcspWanManager_middle_layer_src.la

wanmanager_CPPFLAGS = -I$(top_srcdir)/source/TR-181/middle_layer_src \
                      -I$(top_srcdir)/source/TR-181/include \
                      -I$(top_srcdir)/source/WanManager/MaptParsing \ 
                      -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus

wanmanager_CFLAGS = -DFEATURE_SUPPORT_RDKLOG $(SYSTEMD_CFLAGS)
wanmanager_CFLAGS += -DGIT_VERSION=\"$(GIT_VERSION)\"

wanmanager_SOURCES = wanmgr_webconfig_apis.c wanmgr_webconfig.c wanmgr_main.c  wanmgr_ssp_action.c wanmgr_ssp_messagebus_interface.c wanmgr_core.c wanmgr_controller.c wanmgr_data.c wanmgr_sysevents.c wanmgr_interface_sm.c wanmgr_utils.c wanmgr_net_utils.c wanmgr_dhcpv4_apis.c wanmgr_dhcpv6_apis.c wanmgr_ipc.c wanmgr_dhcpv4_internal.c wanmgr_dhcpv6_internal.c wanmgr_policy_auto_impl.c dm_pack_datamodel.c wanmgr_wan_failover.c wanmgr_policy_parallel_scan_impl.c wanmgr_dhcp_legacy_apis.c wanmgr_interface_apis.c wanmgr_telemetry.c wanmgr_t2_telemetry.c wanmgr_network_monitor.c
wanmanager_LDADD = $(wanmanager_DEPENDENCIES) -lccsp_common -lrdkloggers $(SYSTEMD_LDFLAGS) -lhal_platform -lapi_dhcpv4c -lnanomsg -lwebconfig_framework -lmsgpackc  -lprivilege -lrbus -lsecure_wrapper -levent


if WAN_UNIFICATION_ENABLED 
if !DHCPMANAGER_ENABLED
wanmanager_SOURCES +=  DHCPv6cMsgHandler/dhcpv6c_msg_apis.c
endif
else 
wanmanager_SOURCES += wanmgr_policy_autowan_impl.c
endif

if DHCPMANAGER_ENABLED
wanmanager_SOURCES += wanmgr_dhcp_event_handler.c
else
wanmanager_LDADD += -ldhcp_client_utils
endif

if DSLITE_SUPPORT
wanmanager_SOURCES += wanmgr_dslite.c
endif