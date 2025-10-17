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

bin_PROGRAMS = netmonitor

ACLOCAL_AMFLAGS = -I m4

netmonitor_CPPFLAGS = -I$(top_srcdir)/source/TR-181/middle_layer_src \
                      -I$(top_srcdir)/source/TR-181/include \
                      -I$(top_srcdir)/source/WanManager

netmonitor_CFLAGS = -DFEATURE_SUPPORT_RDKLOG $(SYSTEMD_CFLAGS)
netmonitor_SOURCES = network_route_monitor.c
netmonitor_LDADD = -lccsp_common -lrdkloggers $(SYSTEMD_LDFLAGS) -lhal_platform -lapi_dhcpv4c -lwebconfig_framework -lmsgpackc -lnanomsg -lsyscfg -lsysevent -lpthread -lsecure_wrapper
