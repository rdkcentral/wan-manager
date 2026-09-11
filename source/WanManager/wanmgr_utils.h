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

#ifndef _WANMGR_UTILS_H_
#define _WANMGR_UTILS_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>


#include "wanmgr_rdkbus_common.h"
//#include "ipc_msg.h"


#ifndef RETURN_OK
#define RETURN_OK   0
#endif

#ifndef RETURN_ERROR
#define RETURN_ERROR   -1
#endif

#ifndef RETURN_ERR
#define RETURN_ERR   -1
#endif

#define IS_EMPTY_STRING(s)    ((s == NULL) || (*s == '\0'))

#define USECS_IN_MSEC 1000
#define MSECS_IN_SEC  1000

#ifdef FEATURE_IPOE_HEALTH_CHECK
#define IHC_CLIENT_NAME "ipoe_health_check"
#endif /* FEATURE_IPOE_HEALTH_CHECK */

#define WANMGR_RESTART_INFO_FILE          "/tmp/rdkwanmanager.db"
#define WANMGR_RESTART_INFO_TMP_FILE      "/tmp/rdkwanmanager_tmp.db"

/***************************************************************************
 * @brief Utility function used to start application
 * @param appName string contains the application name
 * @param cmdLineArgs string contains arguments passed to application
 * @return Return PID of the started application.
 ***************************************************************************/
int WanManager_DoStartApp (const char *appName, const char *cmdLineArgs);

/***************************************************************************
 * @brief Utility function used to restart Application
 * @param appName string contains the application name
 * @param cmdLineArgs string contains arguments passed to application
 * @return Return PID of the started application.
 ***************************************************************************/
int WanManager_DoRestartApp(const char *appName, const char *cmdLineArgs);

/***************************************************************************
 * @brief Utility function used to stop Application
 * @param appName string contains the application name
 * @return None
 ***************************************************************************/
void WanManager_DoStopApp(const char *appName);

/***************************************************************************
 * @brief Utility function used to clean zombie Application.
 * @param appName string contains the application name
 * @return None
 ***************************************************************************/
void WanManager_DoCollectApp(const char *appName);

/***************************************************************************
 * @brief Utility function used to execute system command
 * @param from string indicates caller
 * @param cmd string indicates the commandline arguments
 * @return None
 ***************************************************************************/
void WanManager_DoSystemAction(const char* from, char *cmd);

/***************************************************************************
 * @brief Utility function used to execute system command
 * @param from string indicates caller
 * @param cmd string indicates the commandline arguments
 * @return status of system() call.
 ***************************************************************************/
int WanManager_DoSystemActionWithStatus(const char* from, char *cmd);

/***************************************************************************
 * @brief Validates that a candidate network interface name only contains
 *        characters that are safe to embed in shell commands (ifconfig/ip/etc).
 *        Used at DML/RBUS/webconfig set boundaries to reject names that could
 *        otherwise be used for shell command injection.
 * @param name candidate interface name string
 * @return true if name is non-empty, within IFNAMSIZ bounds and made up only
 *         of [A-Za-z0-9._:-] characters; false otherwise.
 ***************************************************************************/
bool WanManager_IsValidIfaceName(const char *name);

/***************************************************************************
 * @brief API used to collect all the zombie processes
 * @param pid pid of the application
 * @return None
 ****************************************************************************/
void CollectApp(int pid);


#ifdef FEATURE_IPOE_HEALTH_CHECK
/***************************************************************************
 * @brief API used to start IPoE health check application.
 * @return PID upon success else returns 0.
 ***************************************************************************/
UINT WanManager_StartIpoeHealthCheckService();

/***************************************************************************
 * @brief API used to atop IPoE health check application.
 * @return ANSC_STATUS_SUCCESS upon success else returned error code.
 ***************************************************************************/
ANSC_STATUS WanManager_StopIpoeHealthCheckService(UINT IhcPid);
#endif //FEATURE_IPOE_HEALTH_CHECK

/***************************************************************************
 * @brief API used to find path of the requested application
 * @param name Name of the application
 * @param buf Used to store the path
 * @param len Buffer length
 * @return pid of the launched application.
 ****************************************************************************/
int GetPathToApp(const char *name, char *buf, uint32_t len);

/***************************************************************************
 * @brief API used to get data and uptime from system
 * @param buffer to store date
 * @param uptime to store uptime value
 ****************************************************************************/
void WanManager_GetDateAndUptime(char *buffer, int *uptime);

/*****************************************************************************************
 * @brief  Utility API to get up time in seconds
 * @return return uptime in seconds
 ******************************************************************************************/
uint32_t WanManager_getUpTime();


int util_spawnProcess(const char *execName, const char *processInfo, int * processId);
int util_terminateProcessForcefully(int32_t pid);
int util_signalProcess(int32_t pid, int32_t sig);
int util_getPidByName(const char *name, const char * args);
int util_getNameByPid(int pid, char *nameBuf, int nameBufLen);
int util_collectProcess(int pid, int timeout);
int util_runCommandInShellBlocking(char *command);
int util_getZombiePidByName(char * name);
void WanManager_Util_GetShell_output(FILE *fp, char *out, int len);
int WanMgr_SetRestartWanInfo (const char * param, int idx, char * value);

ANSC_STATUS WanMgr_RestartUpdateCfg (const char * param, int idx, char * output, int size);
ANSC_STATUS WanMgr_RestartUpdateCfg_Bool (const char * param, int idx, BOOL* output);

int sysctl_iface_set(const char *path, const char *ifname, const char *content);

#endif /* _WANMGR_UTILS_H_ */
