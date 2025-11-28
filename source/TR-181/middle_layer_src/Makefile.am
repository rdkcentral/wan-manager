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
AM_CFLAGS =

ACLOCAL_AMFLAGS = -I m4

noinst_LTLIBRARIES = libCcspWanManager_middle_layer_src.la

libCcspWanManager_middle_layer_src_la_CPPFLAGS = -I$(top_srcdir)/source/TR-181/middle_layer_src \
                                                 -I$(top_srcdir)/source/TR-181/include \
                                                 -I$(top_srcdir)/source/WanManager

libCcspWanManager_middle_layer_src_la_SOURCES = wanmgr_plugin_main.c wanmgr_plugin_main_apis.c wanmgr_dml_apis.c wanmgr_dml_iface_v2_apis.c wanmgr_dml_iface_apis.c wanmgr_rdkbus_utils.c wanmgr_rdkbus_apis.c wanmgr_dml_dhcpv4.c wanmgr_dml_dhcpv6.c
libCcspWanManager_middle_layer_src_la_LDFLAGS = -lccsp_common -lsyscfg -lsysevent -lpthread

libCcspWanManager_middle_layer_src_la_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus
libCcspWanManager_middle_layer_src_la_SOURCES += wanmgr_rbus_handler_apis.c
libCcspWanManager_middle_layer_src_la_LDFLAGS += -lrbus

if DHCPMANAGER_ENABLED
libCcspWanManager_middle_layer_src_la_SOURCES += wanmgr_rbus_dhcp_client_events.c
endif

if DSLITE_SUPPORT
libCcspWanManager_middle_layer_src_la_SOURCES += wanmgr_dml_dslite_apis.c
endif
