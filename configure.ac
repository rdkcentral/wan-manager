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
dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

dnl AC_PREREQ([2.69])
AC_INIT(RdkWanManager-rdkb, version-1.0)
AC_CONFIG_SRCDIR([])
AM_CONFIG_HEADER(cfg/config.h)
AC_CONFIG_MACRO_DIR([cfg])
AC_CONFIG_AUX_DIR([cfg])
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-bzip2 1.9])
LT_INIT

dnl subdirectories.
SUBDIRS=""

dnl Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_CPP
AC_PROG_CXXCPP

dnl use pretty build output with automake >= 1.11
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],
  [AM_DEFAULT_VERBOSITY=1
   AC_SUBST(AM_DEFAULT_VERBOSITY)])

m4_define([GITVERSION],
  m4_esyscmd_s([git describe --tags --always --dirty 2>/dev/null || echo "undefined"])
)
AC_SUBST([GIT_VERSION], [GITVERSION])


dnl **********************************
dnl checks for dependencies
dnl **********************************
AC_HEADER_STDC

SYSTEMD_CFLAGS=" "
SYSTEMD_LDFLAGS=" "

AC_ARG_ENABLE([notify],
        AS_HELP_STRING([--enable-notify],[enable systemd notify]),
        [
          case "${enableval}" in
           yes) SYSTEMD_CFLAGS="-DENABLE_SD_NOTIFY"
                SYSTEMD_LDFLAGS="-lsystemd" ;;
           no) AC_MSG_ERROR([systemd notify is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-notify ]) ;;
           esac
           ],
         [echo "systemd notify is disabled."])

AC_SUBST(SYSTEMD_CFLAGS)
AC_SUBST(SYSTEMD_LDFLAGS)

GTEST_ENABLE_FLAG = ""

AC_ARG_ENABLE([gtestapp],
             AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
             [
               case "${enableval}" in
                yes) GTEST_SUPPORT_ENABLED=true
                     GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
                     m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile])]);;
                no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
               esac
             ],
             [echo "Gtestapp is disabled"])
AM_CONDITIONAL([WITH_GTEST_SUPPORT], [test x$GTEST_SUPPORT_ENABLED = xtrue])

AC_ARG_ENABLE([wanunificationsupport],
             AS_HELP_STRING([--enable-wanunificationsupport],[enable wan unification support (default is no)]),
             [
              case "${enableval}" in
               yes) WAN_UNIFICATION_SUPPORT_ENABLED=true;;
               no)  WAN_UNIFICATION_SUPPORT_ENABLED=false;;
               *) AC_MSG_ERROR([bad value ${enableval} for --enable-wanunificationsupport ]);;
              esac
             ],
             [echo "mapt unification is disabled"])
AM_CONDITIONAL(WAN_UNIFICATION_ENABLED, test "x$WAN_UNIFICATION_SUPPORT_ENABLED" = xtrue)

AC_ARG_ENABLE([dhcp_manager],
             AS_HELP_STRING([--enable-dhcp_manager],[enable dhcpmanager support (default is no)]),
             [
              case "${enableval}" in
               yes) DHCPMANAGER_SUPPORT_ENABLED=true;;
               no)  DHCPMANAGER_SUPPORT_ENABLED=false;;
               *) AC_MSG_ERROR([bad value ${enableval} for --enable-dhcp_manager ]);;
              esac
             ],
             [echo "dhcp manager is disabled"])
AM_CONDITIONAL(DHCPMANAGER_ENABLED, test "x$DHCPMANAGER_SUPPORT_ENABLED" = xtrue)

AC_ARG_ENABLE([dslite_v2],
             AS_HELP_STRING([--enable-dslite-v2],[enable next generation DSLite support (default is no)]),
             [
              case "${enableval}" in
               yes) DSLITE_SUPPORT_ENABLED=true;;
               no)  DSLITE_SUPPORT_ENABLED=false;;
               *) AC_MSG_ERROR([bad value ${enableval} for --enable-dslite-v2 ]);;
              esac
             ],
             [echo "DSLite support is disabled"])
AM_CONDITIONAL(DSLITE_SUPPORT, test "x$DSLITE_SUPPORT_ENABLED" = xtrue)

dnl Checks for header files.
AC_CHECK_HEADERS([limits.h memory.h stdlib.h string.h sys/socket.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
dnl AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT8_T

dnl Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strerror])

AC_CONFIG_FILES([Makefile
		source/Makefile
		source/TR-181/Makefile
		source/TR-181/middle_layer_src/Makefile
		source/WanManager/Makefile])
AC_SUBST(GTEST_ENABLE_FLAG)

AC_OUTPUT

