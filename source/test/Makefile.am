#############################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2024 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CPPFLAGS = -Wall -g -Werror -Wno-error=format
AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = RdkWanManager_gtest.bin


RdkWanManager_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
-I${top_srcdir}/gtest/include \
-I${top_srcdir}/source \
-I${top_srcdir}/source/include \
-I${top_srcdir}/source/WanManager \
-I$(top_srcdir)/source/TR-181/include \
-I$(top_srcdir)/source/TR-181/middle_layer_src \
-I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/dbus-1.0 \
-I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus \
-I${PKG_CONFIG_SYSROOT_DIR}$(libdir)/dbus-1.0/include \
-I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ccsp 
RdkWanManager_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov

#TODO:Compiling all files due to limited time. This should be modified to compile only the required files
RdkWanManager_gtest_bin_SOURCES =    ../WanManager/wanmgr_core.c ../WanManager/wanmgr_controller.c ../WanManager/wanmgr_data.c ../WanManager/wanmgr_sysevents.c ../WanManager/wanmgr_interface_sm.c ../WanManager/wanmgr_utils.c ../WanManager/wanmgr_net_utils.c  ../WanManager/wanmgr_dhcpv6_apis.c ../WanManager/wanmgr_ipc.c  ../WanManager/wanmgr_policy_autowan_impl.c ../WanManager/wanmgr_policy_auto_impl.c ../WanManager/dm_pack_datamodel.c ../WanManager/wanmgr_wan_failover.c ../WanManager/wanmgr_policy_parallel_scan_impl.c ../WanManager/wanmgr_dhcp_legacy_apis.c ../TR-181/middle_layer_src/wanmgr_rbus_handler_apis.c ../TR-181/middle_layer_src/wanmgr_rdkbus_utils.c ../TR-181/middle_layer_src/wanmgr_rdkbus_apis.c \
gtest_main.cpp  RdkWanManagerTest.cpp  Test_wanmgr_rbus_handler_apis.cpp 

# TODO: Partially added RdkbGmock libs. Complete this once all mocks are available. 
RdkWanManager_gtest_bin_LDADD =  -lrdkloggers  -lapi_dhcpv4c -lnanomsg -lwebconfig_framework -lmsgpackc -ldhcp_client_utils  -lsyscfg -lsysevent -lpthread \
 -lmock_privilege -lmock_rbus -lmock_secure_wrapper -lccsp_common -lmock_platform_hal 


