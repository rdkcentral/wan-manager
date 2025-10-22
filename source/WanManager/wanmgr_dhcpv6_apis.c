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
#include "wanmgr_dhcpv6_apis.h"
#include "wanmgr_interface_sm.h"
#include "wanmgr_sysevents.h"
#include "wanmgr_ipc.h"
#include "wanmgr_utils.h"
#include "wanmgr_net_utils.h"


#include <sysevent/sysevent.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <syscfg/syscfg.h>
#include "secure_wrapper.h"

extern int sysevent_fd;
extern token_t sysevent_token;
extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];

#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && defined(_COSA_BCM_MIPS_)
#include <netinet/in.h>
#endif
#define CLIENT_DUID_FILE "/var/lib/dibbler/client-duid"
#define DHCPS6V_SERVER_RESTART_FIFO "/tmp/ccsp-dhcpv6-server-restart-fifo.txt"

#define CLIENT_BIN     "dibbler-client"

#if defined (INTEL_PUMA7)
#define NO_OF_RETRY 90
#if defined(MULTILAN_FEATURE)
#define IPV6_PREF_MAXLEN 128
#endif
#endif

#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
#define COSA_DML_WANIface_ADDR_SYSEVENT_NAME           "tr_%s_dhcpv6_client_v6addr"
char PreviousIPv6Address[128] = {0}; //Global varibale to store previous IPv6 address
#endif

static struct {
    pthread_t          dhcpv6c_thread;
}gDhcpv6c_ctx;

extern WANMGR_BACKEND_OBJ* g_pWanMgrBE;

/*erouter topology mode*/
enum tp_mod {
    TPMOD_UNKNOWN,
    FAVOR_DEPTH,
    FAVOR_WIDTH,
};

typedef struct pd_pool {
    char start[INET6_ADDRSTRLEN];
    char end[INET6_ADDRSTRLEN];
    int  prefix_length;
    int  pd_length;
} pd_pool_t;

typedef struct ia_info {
    union {
        char v6addr[INET6_ADDRSTRLEN];
        char v6pref[INET6_ADDRSTRLEN];
    } value;

    char t1[32], t2[32], iaid[32], pretm[32], vldtm[32];
    int len;
} ia_pd_t;

typedef struct ipv6_prefix {
    char value[INET6_ADDRSTRLEN];
    int  len;
    //int  b_used;
} ipv6_prefix_t;

#if defined(MULTILAN_FEATURE)
#define IPV6_PREF_MAXLEN 128
static char v6addr_prev[IPV6_PREF_MAXLEN] = {0};
#endif

void _get_shell_output(FILE *fp, char * out, int len);
static int _prepare_client_conf(PDML_DHCPCV6_CFG       pCfg);
static int _dibbler_client_operation(char * arg);

static DML_DHCPCV6_FULL  g_dhcpv6_client;

void _cosa_dhcpsv6_refresh_config();


void _get_shell_output(FILE *fp, char * out, int len)
{
    char * p;
    if (fp)
    {
        fgets(out, len, fp);
        /*we need to remove the \n char in buf*/
        if ((p = strchr(out, '\n'))) 
        {
            *p = '\0';
        }
    }

}

static ANSC_STATUS syscfg_set_string(const char* name, const char* value)
{
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;
    if (syscfg_set_commit(NULL, name, value) != 0)
    {
        CcspTraceError(("syscfg_set failed: %s %s\n", name, value));
        ret = ANSC_STATUS_FAILURE;
    }

    return ret;
}


/*
    Description:
        The API retrieves the number of DHCP clients in the system.
 */
ULONG
WanMgr_DmlDhcpv6cGetNumberOfEntries
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
static int _get_client_duid(UCHAR * out, int len)
{
    char buf[256] = {0};
    FILE * fp = fopen(CLIENT_DUID_FILE, "r+");
    int  i = 0;
    int  j = 0;

    if(fp)
    {
        fgets(buf, sizeof(buf), fp);

        if(buf[0])
        {
            while(j<len && buf[i])
            {
                if (buf[i] != ':')
                    out[j++] = buf[i];

                i++;
            }
        }
        fclose(fp);
    }

    return 0;
}


ANSC_STATUS
WanMgr_DmlDhcpv6cGetEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PDML_DHCPCV6_FULL      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    char out[16];

    if (ulIndex)
        return ANSC_STATUS_FAILURE;

    pEntry->Cfg.InstanceNumber = 1;

    /*Cfg members*/
    syscfg_get(NULL, "tr_dhcpv6c_alias", pEntry->Cfg.Alias, sizeof(pEntry->Cfg.Alias));

    pEntry->Cfg.SuggestedT1 = pEntry->Cfg.SuggestedT2 = 0;

    if (syscfg_get(NULL, "tr_dhcpv6c_t1", out, sizeof(out)) == 0)
    {
        sscanf(out, "%lu", &pEntry->Cfg.SuggestedT1);
    }

    if (syscfg_get(NULL, "tr_dhcpv6c_t2", out, sizeof(out)) == 0)
    {
        sscanf(out, "%lu", &pEntry->Cfg.SuggestedT2);
    }

    /*pEntry->Cfg.Interface stores interface name, dml will calculate the full path name*/
    snprintf(pEntry->Cfg.Interface, sizeof(pEntry->Cfg.Interface), "%s", DML_DHCP_CLIENT_IFNAME);

    syscfg_get(NULL, "tr_dhcpv6c_requested_options", pEntry->Cfg.RequestedOptions, sizeof(pEntry->Cfg.RequestedOptions));

    syscfg_get(NULL, "tr_dhcpv6c_enabled", out, sizeof(out));
    pEntry->Cfg.bEnabled = (out[0] == '1') ? TRUE : FALSE;

    syscfg_get(NULL, "tr_dhcpv6c_iana_enabled", out, sizeof(out));
    pEntry->Cfg.RequestAddresses = (out[0] == '1') ? TRUE : FALSE;

    syscfg_get(NULL, "tr_dhcpv6c_iapd_enabled", out, sizeof(out));
    pEntry->Cfg.RequestPrefixes = (out[0] == '1') ? TRUE : FALSE;

    syscfg_get(NULL, "tr_dhcpv6c_rapidcommit_enabled", out, sizeof(out));
    pEntry->Cfg.RapidCommit = (out[0] == '1') ? TRUE : FALSE;

    /*Info members*/
    if (pEntry->Cfg.bEnabled)
        pEntry->Info.Status = DML_DHCP_STATUS_Enabled;
    else
        pEntry->Info.Status = DML_DHCP_STATUS_Disabled;

    /*TODO: supported options*/

    _get_client_duid(pEntry->Info.DUID, sizeof(pEntry->Info.DUID));

    /*if we don't have alias, set a default one*/
    if (pEntry->Cfg.Alias[0] == 0) {
        syscfg_set_commit(NULL, "tr_dhcpv6c_alias", "Client1");
        snprintf(pEntry->Cfg.Alias, sizeof(pEntry->Cfg.Alias), "%s", "Client1");
    }

    AnscCopyMemory(&g_dhcpv6_client, pEntry, sizeof(g_dhcpv6_client));

    if (pEntry->Cfg.bEnabled)
        _prepare_client_conf(&pEntry->Cfg);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
WanMgr_DmlDhcpv6cSetValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulInstanceNumber);

    if (ulIndex)
    {
        return ANSC_STATUS_FAILURE;
    }

    strncpy(g_dhcpv6_client.Cfg.Alias, pAlias,sizeof(g_dhcpv6_client.Cfg.Alias)-1);


    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API adds DHCP client.
    Arguments:
        pEntry        Caller fills in pEntry->Cfg, except Alias field. Upon return, callee fills pEntry->Cfg.Alias field and as many as possible fields in pEntry->Info.
*/
ANSC_STATUS
WanMgr_DmlDhcpv6cAddEntry
    (
        ANSC_HANDLE                 hContext,
        PDML_DHCPCV6_FULL        pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(pEntry);
    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API removes the designated DHCP client entry.
    Arguments:
        pAlias        The entry is identified through Alias.
*/
ANSC_STATUS
WanMgr_DmlDhcpv6cDelEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    return ANSC_STATUS_SUCCESS;
}

/*
A sample content of client.conf
iface wan0 {
    rapid-commit yes
    ia {
    t1 1000
    t2 2000
    }
    pd {
    t1 1000
    t2 2000
    }
}
*/
#if defined(_DT_WAN_Manager_Enable_)
#define TMP_CLIENT_CONF "/etc/dibbler/.dibbler_client_conf"
#else
#define TMP_CLIENT_CONF "/tmp/.dibbler_client_conf"
#endif
#define CLIENT_CONF_LOCATION  "/etc/dibbler/client.conf"
#define TMP_SERVER_CONF "/tmp/.dibbler_server_conf"
#define SERVER_CONF_LOCATION  "/etc/dibbler/server.conf"
#define CLIENT_NOTIFY "/etc/dibbler/client-notify.sh"

static int _prepare_client_conf(PDML_DHCPCV6_CFG       pCfg)
{
    FILE * fp = fopen(TMP_CLIENT_CONF, "w+");

    if (fp)
    {
        /*we need this to get IANA IAPD info from dibbler*/
#if defined(_DT_WAN_Manager_Enable_)
        fprintf(fp, "log-level 7\n");
        fprintf(fp, "log-mode full\n");
        fprintf(fp, "script \"%s\" \n", CLIENT_NOTIFY);
        fprintf(fp, "reconfigure-accept 1\n");
#else
        fprintf(fp, "notify-scripts\n");
#endif
        fprintf(fp, "duid-type duid-ll\n");
        fprintf(fp, "iface %s {\n", pCfg->Interface);

        if (pCfg->RapidCommit)
            fprintf(fp, "    rapid-commit yes\n");

        if ((pCfg->SuggestedT1) || (pCfg->SuggestedT2))
        {
            if (pCfg->RequestAddresses)
            {
                fprintf(fp, "    ia {\n");

                if (pCfg->SuggestedT1)
                {
                    fprintf(fp, "    t1 %lu\n", pCfg->SuggestedT1);
                }
    
                if (pCfg->SuggestedT2)
                {
                    fprintf(fp, "    t2 %lu\n", pCfg->SuggestedT2);
                }

                fprintf(fp, "    }\n");
            }
    
            if (pCfg->RequestPrefixes)
            {
                fprintf(fp, "    pd {\n");

                if (pCfg->SuggestedT1)
                {
                    fprintf(fp, "    t1 %lu\n", pCfg->SuggestedT1);
                }
    
                if (pCfg->SuggestedT2)
                {
                    fprintf(fp, "    t2 %lu\n", pCfg->SuggestedT2);
                }

                fprintf(fp, "    }\n");
            }
        }
        else {
            /* RFC3315 - Set T1 and T2 to 0 for IA_NA / IA_PD requests to indicate no preference for it from the gateway side instead operator network(BNG) provides T1/T2 values to gateway. */
            if (pCfg->RequestAddresses) {
                fprintf(fp, "    ia {\n");
                fprintf(fp, "           t1 0\n");
                fprintf(fp, "           t2 0\n");
                fprintf(fp, "    }\n");
            }
            if (pCfg->RequestPrefixes) {
                fprintf(fp, "    pd {\n");
                fprintf(fp, "           t1 0\n");
                fprintf(fp, "           t2 0\n");
                fprintf(fp, "    }\n");
            }
        }

        fprintf(fp, "    option dns-server\n");
        fprintf(fp, "    option domain\n");
 
        fprintf(fp, "}\n");

        fclose(fp);
    }

    /*we will copy the updated conf file at once*/
    if (rename(TMP_CLIENT_CONF, CLIENT_CONF_LOCATION))
        CcspTraceWarning(("%s rename failed %s\n", __FUNCTION__, strerror(errno)));

    return 0;
}

static int _dibbler_client_operation(char * arg)
{
    char out[256] = {0};
    FILE *fp = NULL;
    int ret =0;
    int pidval = 0;
    int32_t rc;
#if defined (INTEL_PUMA7)
    int watchdog = NO_OF_RETRY;
#endif

    if (!strncmp(arg, "stop", 4))
    {
        CcspTraceInfo(("%s stop\n", __func__));
        /*TCXB6 is also calling service_dhcpv6_client.sh but the actuall script is installed from meta-rdk-oem layer as the intel specific code
                   had to be removed */
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(DHCPV6_PREFIX_FIX)
        sysevent_set(sysevent_fd, sysevent_token, "dhcpv6_client-stop", "", 0);
#elif defined(CORE_NET_LIB)
        v_secure_system("/usr/bin/service_dhcpv6_client dhcpv6_client_service_disable");
        CcspTraceInfo(("%s  Calling service_dhcpv6_client.c with dhcpv6_client_service_disable from wanmgr_dhcpv6_apis.c\n", __func__));
#else
        v_secure_system("/etc/utopia/service.d/service_dhcpv6_client.sh disable &");
#endif

#ifdef _COSA_BCM_ARM_
        if (TRUE == WanManager_IsApplicationRunning (CLIENT_BIN, NULL))
        {
#if defined(_DT_WAN_Manager_Enable_)
            if ((pidval = util_getPidByName(CLIENT_BIN, NULL)) >= 0)
            {
                if ((rc = kill(pidval, SIGTERM)) < 0)
                {
                    CcspTraceError(("Failed to stop dibbler-client"));
                }
            }
            v_secure_system("rm -f /tmp/dibbler/client.pid /tmp/dibbler/client-AddrMgr.xml");

#else //_DT_WAN_Manager_Enable_
            CcspTraceInfo(("%s-%d [%s] is already running, killing it \n", __FUNCTION__,__LINE__,CLIENT_BIN));
            v_secure_system("killall " CLIENT_BIN);
            sleep(2);
#ifdef _HUB4_PRODUCT_REQ_ //TODO : clean up ?
            fp = v_secure_popen("r", "ps | grep "CLIENT_BIN " | grep -v grep");
#else
            fp = v_secure_popen("r", "ps -A|grep "CLIENT_BIN);
#endif // _HUB4_PRODUCT_REQ_
            if(!fp)
            {
                CcspTraceError(("%s %d Error in opening pipe! \n",__FUNCTION__,__LINE__));
            }
            else
            {
                _get_shell_output(fp, out, sizeof(out));
	        ret = v_secure_pclose(fp);
	        if(ret !=0) {
                    CcspTraceError(("[%s-%d] failed to closing  v_secure_pclose pipe ret [%d]!! \n", __FUNCTION__, __LINE__,ret));
                }
            }
            if (strstr(out, CLIENT_BIN))
            {
                v_secure_system("killall -9 "CLIENT_BIN);
            }
#endif //_DT_WAN_Manager_Enable_
        }
#endif
    }
    else if (!strncmp(arg, "start", 5))
    {
        CcspTraceInfo(("%s start\n", __func__));

#if defined(INTEL_PUMA7)
        char buf[8] = {0};
        unsigned char IsEthWANEnabled = FALSE;

        if((0 == access("/nvram/ETHWAN_ENABLE", F_OK)) && 
           ((0 == syscfg_get( NULL, "eth_wan_enabled", buf, sizeof(buf))) && 
            (buf[0] != '\0') && 
            (strncmp(buf, "true", strlen("true")) == 0)))
        {
            IsEthWANEnabled = TRUE;
        }

        //No need to wait if ETHWAN enabled case
        if( FALSE == IsEthWANEnabled )
        {
            //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
            /* Waiting for the TLV file to be parsed correctly so that the right erouter mode can be used in the code below.
            For ANYWAN please extend the below code to support the case of TLV config file not being there. */
            do{
              fp = v_secure_popen("r","sysevent get TLV202-status");
              if(!fp)
              {
                  CcspTraceError(("[%s-%d] failed to opening v_secure_popen pipe !! \n", __FUNCTION__, __LINE__));
              }
              else 
              {
                  _get_shell_output(fp, out, sizeof(out));
              ret = v_secure_pclose(fp);
              if(ret !=0) {
                      CcspTraceError(("[%s-%d] failed to closing v_secure_pclose() pipe ret [%d] !! \n", __FUNCTION__, __LINE__,ret));
                  }
              }

              fprintf( stderr, "\n%s:%s(): Waiting for CcspGwProvApp to parse TLV config file\n", __FILE__, __FUNCTION__);
              sleep(1);//sleep(1) is to avoid lots of trace msgs when there is latency
              watchdog--;
            }while((!strstr(out,"success")) && (watchdog != 0));

            if(watchdog == 0)
            {
                //When 60s have passed and the file is still not configured by CcspGwprov module
                fprintf(stderr, "\n%s()%s(): TLV data has not been initialized by CcspGwProvApp.Continuing with the previous configuration\n",__FILE__, __FUNCTION__);
            }
        }
#endif
        /*This is for ArrisXB6 */
        /*TCXB6 is also calling service_dhcpv6_client.sh but the actuall script is installed from meta-rdk-oem layer as the intel specific code
         had to be removed */
        CcspTraceInfo(("%s  Callin service_dhcpv6_client.sh enable \n", __func__));
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(DHCPV6_PREFIX_FIX)
        sysevent_set(sysevent_fd, sysevent_token, "dhcpv6_client-start", "", 0);
#elif defined(CORE_NET_LIB)
        v_secure_system("/usr/bin/service_dhcpv6_client dhcpv6_client_service_enable");
        CcspTraceInfo(("%s  Calling service_dhcpv6_client.c with dhcpv6_client_service_enable from wanmgr_dhcpv6_apis.c\n", __func__));
#else
        v_secure_system("/etc/utopia/service.d/service_dhcpv6_client.sh enable &");
#endif

#ifdef _COSA_BCM_ARM_
        /* Dibbler-init is called to set the pre-configuration for dibbler */
        CcspTraceInfo(("%s dibbler-init.sh Called \n", __func__));
#if defined(_DT_WAN_Manager_Enable_)
        _prepare_client_conf(&g_dhcpv6_client.Cfg);
#endif
        v_secure_system("/lib/rdk/dibbler-init.sh");
        /*Start Dibber client for tchxb6*/
        CcspTraceInfo(("%s Dibbler Client Started \n", __func__));
        v_secure_system(CLIENT_BIN " start");
#endif
    }
    else if (!strncmp(arg, "restart", 7))
    {
        _dibbler_client_operation("stop");
        sleep(2);
        _dibbler_client_operation("start");
    }

    return 0;
}
/*internal.c will call this when obtained Client and SentOptions. so we don't need to start service in getEntry for Client and SentOptions.*/
int  WanMgr_DmlStartDHCP6Client()
{
    pthread_detach(pthread_self());
#if defined(_COSA_INTEL_XB3_ARM_)
    CcspTraceInfo(("Not restarting ti_dhcp6c for XB3 case\n"));
#else
   // _dibbler_client_operation("restart");
#endif
    return 0;
}
/*
Description:
    The API re-configures the designated DHCP client entry.
Arguments:
    pAlias        The entry is identified through Alias.
    pEntry        The new configuration is passed through this argument, even Alias field can be changed.
*/
ANSC_STATUS
WanMgr_DmlDhcpv6cSetCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_DHCPCV6_CFG       pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);
    int commit = 0;
    int need_to_restart_service = 0;

    if (pCfg->InstanceNumber != 1)
        return ANSC_STATUS_FAILURE;

    if (strcmp((char *) pCfg->Alias, (char *) g_dhcpv6_client.Cfg.Alias) != 0)
    {
        syscfg_set(NULL, "tr_dhcpv6c_alias", pCfg->Alias);
        commit = 1;
    }

    if (pCfg->SuggestedT1 != g_dhcpv6_client.Cfg.SuggestedT1)
    {
        syscfg_set_u(NULL, "tr_dhcpv6c_t1", pCfg->SuggestedT1);
        commit = 1;
        need_to_restart_service = 1;
    }

    if (pCfg->SuggestedT2 != g_dhcpv6_client.Cfg.SuggestedT2)
    {
        syscfg_set_u(NULL, "tr_dhcpv6c_t2", pCfg->SuggestedT2);
        commit = 1;
        need_to_restart_service = 1;
    }

    if (strcmp((char *) pCfg->RequestedOptions, (char *) g_dhcpv6_client.Cfg.RequestedOptions) != 0)
    {
        syscfg_set(NULL, "tr_dhcpv6c_requested_options", (char *) pCfg->RequestedOptions);
        commit = 1;
        need_to_restart_service = 1;
    }

    if (pCfg->bEnabled != g_dhcpv6_client.Cfg.bEnabled)
    {
        syscfg_set(NULL, "tr_dhcpv6c_enabled", pCfg->bEnabled ? "1" : "0");
        commit = 1;
        need_to_restart_service = 1;
    }

    if (pCfg->RequestAddresses != g_dhcpv6_client.Cfg.RequestAddresses)
    {
        syscfg_set(NULL, "tr_dhcpv6c_iana_enabled", pCfg->RequestAddresses ? "1" : "0");
        commit = 1;
        need_to_restart_service = 1;
    }

    if (pCfg->RequestPrefixes != g_dhcpv6_client.Cfg.RequestPrefixes)
    {
        syscfg_set(NULL, "tr_dhcpv6c_iapd_enabled", pCfg->RequestPrefixes ? "1" : "0");
        commit = 1;
        need_to_restart_service = 1;
    }

    if (pCfg->RapidCommit != g_dhcpv6_client.Cfg.RapidCommit)
    {
        syscfg_set(NULL, "tr_dhcpv6c_rapidcommit_enabled", pCfg->RapidCommit ? "1" : "0");
        commit = 1;
        need_to_restart_service = 1;
        g_dhcpv6_client.Cfg.RapidCommit = pCfg->RapidCommit;
    }

    if (commit)
    {
        syscfg_commit();
    }

    /*update dibbler-client service if necessary*/
    if (need_to_restart_service)
    {
        if ( pCfg->bEnabled != g_dhcpv6_client.Cfg.bEnabled &&  !pCfg->bEnabled )
        {
#if defined(_DT_WAN_Manager_Enable_)
            g_dhcpv6_client.Cfg.bEnabled = pCfg->bEnabled;
#endif
            _dibbler_client_operation("stop");
        }
        else if (pCfg->bEnabled != g_dhcpv6_client.Cfg.bEnabled &&  pCfg->bEnabled )
        {
            _prepare_client_conf(pCfg);
#if defined(_DT_WAN_Manager_Enable_)
            _dibbler_client_operation("stop");
            if (pCfg->RequestAddresses || pCfg->RequestPrefixes)
                _dibbler_client_operation("start");
#else
            _dibbler_client_operation("restart");
#endif
        }
        else if (pCfg->bEnabled == g_dhcpv6_client.Cfg.bEnabled && !pCfg->bEnabled)
        {
            /*do nothing*/
        }
        else if (pCfg->bEnabled == g_dhcpv6_client.Cfg.bEnabled && pCfg->bEnabled)
        {
            _prepare_client_conf(pCfg);
#if defined(_DT_WAN_Manager_Enable_)
            _dibbler_client_operation("stop");
            if (pCfg->RequestAddresses || pCfg->RequestPrefixes)
                _dibbler_client_operation("start");
#else
            _dibbler_client_operation("restart");
#endif
        }
    }

    AnscCopyMemory(&g_dhcpv6_client.Cfg, pCfg, sizeof(DML_DHCPCV6_CFG));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
WanMgr_DmlDhcpv6cGetCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_DHCPCV6_CFG       pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);
    /*for rollback*/
    if (pCfg->InstanceNumber != 1)
        return ANSC_STATUS_FAILURE;

    AnscCopyMemory(pCfg,  &g_dhcpv6_client.Cfg, sizeof(DML_DHCPCV6_CFG));

    return ANSC_STATUS_SUCCESS;
}

BOOL
WanMgr_DmlDhcpv6cGetEnabled
    (
        ANSC_HANDLE                 hContext
    )
{
    UNREFERENCED_PARAMETER(hContext);
    BOOL bEnabled = FALSE;
    char out[256] = {0};
    BOOL dibblerEnabled = FALSE;

// For XB3, AXB6 if dibbler flag enabled, check dibbler-client process status
#if defined(_COSA_INTEL_XB3_ARM_) || defined(INTEL_PUMA7)
        char buf[8];
        if(( syscfg_get( NULL, "dibbler_client_enable_v2", buf, sizeof(buf))==0) && (strcmp(buf, "true") == 0))
    {
        dibblerEnabled = TRUE;
    }
#endif

#if defined (_COSA_BCM_ARM_) || defined (_HUB4_PRODUCT_REQ_)
    FILE *fp = popen("ps |grep -i dibbler-client | grep -v grep", "r");

#elif defined (_XF3_PRODUCT_REQ_)
   FILE *fp = popen("/usr/sbin/dibbler-client status |grep  client", "r");

#else
    FILE *fp;
    // For XB3, AXB6 if dibbler flag enabled, check dibbler-client process status
    if(dibblerEnabled)
        fp = popen("ps |grep -i dibbler-client | grep -v grep", "r");
    else
            fp = popen("ps |grep -i ti_dhcp6c | grep erouter0 | grep -v grep", "r");
#endif

    if ( fp != NULL){
        if ( fgets(out, sizeof(out), fp) != NULL ){
#if defined (_COSA_BCM_ARM_) || defined (_HUB4_PRODUCT_REQ_)
            if ( _ansc_strstr(out, "dibbler-client") )
                bEnabled = TRUE;
#elif defined (_XF3_PRODUCT_REQ_)
            if ( strstr(out, "RUNNING,") )
                bEnabled = TRUE;
#else
    // For XB3, AXB6 if dibbler flag enabled, check dibbler-client process status
    if ( dibblerEnabled && _ansc_strstr(out, "dibbler-client") )
                bEnabled = TRUE;
        if ( _ansc_strstr(out, "erouter_dhcp6c") )
                bEnabled = TRUE;
#endif
       }
        pclose(fp);
    }

    return bEnabled;
}

ANSC_STATUS
WanMgr_DmlDhcpv6cGetInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PDML_DHCPCV6_INFO      pInfo
    )
{
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    PDML_DHCPCV6_FULL            pDhcpc            = (PDML_DHCPCV6_FULL)hContext;

    _get_client_duid(g_dhcpv6_client.Info.DUID, sizeof(pInfo->DUID));

    if (pDhcpc)
    {
        if (pDhcpc->Cfg.bEnabled)
            g_dhcpv6_client.Info.Status = pDhcpc->Info.Status = DML_DHCP_STATUS_Enabled;
        else
            g_dhcpv6_client.Info.Status = pDhcpc->Info.Status = DML_DHCP_STATUS_Disabled;
    }

    AnscCopyMemory(pInfo,  &g_dhcpv6_client.Info, sizeof(DML_DHCPCV6_INFO));

    return ANSC_STATUS_SUCCESS;
}

#define CLIENT_SERVER_INFO_FILE "/tmp/.dibbler-info/client_server"
/*this file's format:
 line 1: addr server_ipv6_addr
 line 2: duid server_duid*/
/* this memory need to be freed by caller */
ANSC_STATUS
WanMgr_DmlDhcpv6cGetServerCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_SVR      *ppCfg,
        PULONG                      pSize
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    FILE * fp = fopen(CLIENT_SERVER_INFO_FILE, "r+");

    *pSize = 0;
    if (fp)
    {
        char buf[1024] = {0};
        char val[1024] = {0};
        int  entry_count = 0;

        /*we only support one entry of ServerCfg*/
        *ppCfg = (PDML_DHCPCV6_SVR)AnscAllocateMemory( sizeof(DML_DHCPCV6_SVR) );
        memset(*ppCfg, 0, sizeof(DML_DHCPCV6_SVR));

        /*InformationRefreshTime not supported*/
        strncpy((char*)(*ppCfg)->InformationRefreshTime, "0001-01-01T00:00:00Z",sizeof((*ppCfg)->InformationRefreshTime)-1);

        while(fgets(buf, sizeof(buf)-1, fp))
        {
            memset(val, 0, sizeof(val));
            if (sscanf(buf, "addr %1023s", val))
            {
                strncpy((char*)(*ppCfg)->SourceAddress, val,sizeof((*ppCfg)->SourceAddress)-1);
                entry_count |= 1;
            }
            else if (sscanf(buf, "duid %1023s", val))
            {
                unsigned int i = 0, j = 0;
                /*the file stores duid in this format 00:01:..., we need to transfer it to continuous hex*/

                for (i=0; i<strlen(val) && j < sizeof((*ppCfg)->DUID)-1; i++)
                {
                    if (val[i] != ':')
                        ((*ppCfg)->DUID)[j++] = val[i];
                }

                entry_count |= 2;
            }

            /*only we have both addr and  duid we think we have a whole server-info*/
            if (entry_count == 3)
                *pSize = 1;

            memset(buf, 0, sizeof(buf));
        }
        fclose(fp);
    }

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API initiates a DHCP client renewal.
    Arguments:
        pAlias        The entry is identified through Alias.
*/
ANSC_STATUS
WanMgr_DmlDhcpv6cRenew
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    v_secure_system("killall -SIGUSR2 "CLIENT_BIN);
    return ANSC_STATUS_SUCCESS;
}

/*
 *  DHCP Client Send/Req Option
 *
 *  The options are managed on top of a DHCP client,
 *  which is identified through pClientAlias
 */
#define SYSCFG_DHCP6C_SENT_OPTION_FORMAT "tr_dhcp6c_sent_option_%lu"
static int g_sent_option_num;
static DML_DHCPCV6_SENT * g_sent_options;
static int g_recv_option_num   = 0;
static DML_DHCPCV6_RECV * g_recv_options = NULL;

ULONG
WanMgr_DmlDhcpv6cGetNumberOfSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    char out[32];

    if (syscfg_get(NULL, "tr_dhcp6c_sent_option_num", out, sizeof(out)) == 0 )
    {
        g_sent_option_num = atoi(out);
    }

    if (g_sent_option_num)
    {
        g_sent_options = (DML_DHCPCV6_SENT *)AnscAllocateMemory(sizeof(DML_DHCPCV6_SENT)* g_sent_option_num);
    }

    return g_sent_option_num;

}

#define CLIENT_SENT_OPTIONS_FILE "/tmp/.dibbler-info/client_sent_options"
/*this function will generate sent_option info file to dibbler-client,
 the format of CLIENT_SENT_OPTIONS_FILE:
    option-type:option-len:option-data*/
static int _write_dibbler_sent_option_file(void)
{
    FILE * fp = fopen(CLIENT_SENT_OPTIONS_FILE, "w+");
    int  i = 0;

    if (fp)
    {
        for (i=0; i<g_sent_option_num; i++)
        {
            if (g_sent_options[i].bEnabled)
                fprintf(fp, "%lu:%d:%s\n",
                        g_sent_options[i].Tag,
                        strlen((const char*)g_sent_options[i].Value)/2,
                        g_sent_options[i].Value);
        }

        fclose(fp);
    }

    return 0;
}

ANSC_STATUS
WanMgr_DmlDhcpv6cGetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        PDML_DHCPCV6_SENT      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    char namespace[64];
    char buf[128];
    char out[32];

    if ((int) ulIndex > g_sent_option_num - 1 || !g_sent_options)
    {
        return ANSC_STATUS_FAILURE;
    }

    /*note in syscfg, sent_options start from 1*/
    snprintf(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, ulIndex + 1);
    if (syscfg_get(NULL, namespace, out, sizeof(out)) == 0)
    {
        sscanf(out, "%lu", &pEntry->InstanceNumber);
    }

    snprintf(buf, sizeof(buf), "%s_alias", namespace);
    syscfg_get(NULL, buf, pEntry->Alias, sizeof(pEntry->Alias));

    snprintf(buf, sizeof(buf), "%s_enabled", namespace);
    if (syscfg_get(NULL, buf, out, sizeof(out)) == 0)
    {
        pEntry->bEnabled = (out[0] == '1') ? TRUE : FALSE;
    }

    snprintf(buf, sizeof(buf), "%s_tag", namespace);
    if (syscfg_get(NULL, buf, out, sizeof(out)) == 0)
    {
        sscanf(out, "%lu", &pEntry->Tag);
    }

    snprintf(buf, sizeof(buf), "%s_value", namespace);
    syscfg_get(NULL, buf, pEntry->Value, sizeof(pEntry->Value));

    AnscCopyMemory( &g_sent_options[ulIndex], pEntry, sizeof(DML_DHCPCV6_SENT));

    /*we only wirte to file when obtaining the last entry*/
    if (ulIndex == (g_sent_option_num - 1))
    {
        _write_dibbler_sent_option_file();
    }

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
WanMgr_DmlDhcpv6cGetSentOptionbyInsNum
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_SENT      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    ULONG                           index  = 0;

    for( index=0;  index<g_sent_option_num; index++)
    {
        if ( pEntry->InstanceNumber == g_sent_options[index].InstanceNumber )
        {
            AnscCopyMemory( pEntry, &g_sent_options[index], sizeof(DML_DHCPCV6_SENT));
             return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
WanMgr_DmlDhcpv6cSetSentOptionValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    char namespace[64];
    char buf[128];

    if (ulClientInstanceNumber != g_dhcpv6_client.Cfg.InstanceNumber)
        return ANSC_STATUS_FAILURE;

    if ( (int)ulIndex+1 > g_sent_option_num )
        return ANSC_STATUS_SUCCESS;

    g_sent_options[ulIndex].InstanceNumber = ulInstanceNumber;
    AnscCopyString((char *) g_sent_options[ulIndex].Alias, pAlias);

    snprintf(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, ulIndex + 1);
    syscfg_set_u(NULL, namespace, ulInstanceNumber);

    snprintf(buf, sizeof(buf), "%s_alias", namespace);
    syscfg_set_commit(NULL, buf, pAlias);

    return ANSC_STATUS_SUCCESS;
}

static int _syscfg_add_sent_option(PDML_DHCPCV6_SENT pEntry, int index)
{
    char namespace[64];
    char buf[128];

    if (!pEntry)
        return -1;

    snprintf(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, index);
    syscfg_set_u(NULL, namespace, pEntry->InstanceNumber);

    snprintf(buf, sizeof(buf), "%s_alias", namespace);
    syscfg_set(NULL, buf, pEntry->Alias);

    snprintf(buf, sizeof(buf), "%s_enabled", namespace);
    syscfg_set(NULL, buf, pEntry->bEnabled ? "1" : "0");

    snprintf(buf, sizeof(buf), "%s_tag", namespace);
    syscfg_set_u(NULL, buf, pEntry->Tag);

    snprintf(buf, sizeof(buf), "%s_value", namespace);
    syscfg_set(NULL, buf, pEntry->Value);

    return 0;
}

ANSC_STATUS
WanMgr_DmlDhcpv6cAddSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_SENT      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    char *realloc_tmp;

    /*we only have one client*/
    if (ulClientInstanceNumber != g_dhcpv6_client.Cfg.InstanceNumber)
        return ANSC_STATUS_FAILURE;

    realloc_tmp = realloc(g_sent_options, (++g_sent_option_num)* sizeof(DML_DHCPCV6_SENT));
    if (!realloc_tmp)
    {
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        g_sent_options = (DML_DHCPCV6_SENT *)realloc_tmp;
    }

    _syscfg_add_sent_option(pEntry, g_sent_option_num);

    syscfg_set_u_commit(NULL, "tr_dhcp6c_sent_option_num", g_sent_option_num);

    g_sent_options[g_sent_option_num-1] = *pEntry;

    /*if the added entry is disabled, don't update dibbler-info file*/
    if (pEntry->bEnabled)
    {
        _write_dibbler_sent_option_file();
        _dibbler_client_operation("restart");
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
WanMgr_DmlDhcpv6cDelSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    char namespace[64];
    int  i = 0;
    int  j = 0;
    int  saved_enable = 0;

    /*we only have one client*/
    if (ulClientInstanceNumber != g_dhcpv6_client.Cfg.InstanceNumber)
        return ANSC_STATUS_FAILURE;

    for (i=0; i<g_sent_option_num; i++)
    {
        if (g_sent_options[i].InstanceNumber == ulInstanceNumber)
            break;
    }

    if (i == g_sent_option_num)
        return ANSC_STATUS_CANT_FIND;

    saved_enable = g_sent_options[i].bEnabled;

    for (j=i; j<g_sent_option_num-1; j++)
    {
        g_sent_options[j] = g_sent_options[j+1];

        /*move syscfg ahead to fill in the deleted one*/
        _syscfg_add_sent_option(g_sent_options+j+1, j+1);
    }

    g_sent_option_num--;

    /*syscfg unset the last one, since we move the syscfg table ahead*/
    snprintf(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, (ULONG)(g_sent_option_num + 1));

    syscfg_unset(namespace, "inst_num");
    syscfg_unset(namespace, "alias");
    syscfg_unset(namespace, "enabled");
    syscfg_unset(namespace, "tag");
    syscfg_unset(namespace, "value");

    syscfg_set_u_commit(NULL, "tr_dhcp6c_sent_option_num", g_sent_option_num);

    /*only take effect when the deleted entry was enabled*/
    if (saved_enable)
    {
        _write_dibbler_sent_option_file();
        _dibbler_client_operation("restart");
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
WanMgr_DmlDhcpv6cSetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_SENT      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    ULONG index = 0;

    for (index = 0; index < g_sent_option_num; index++)
    {
        if (pEntry->InstanceNumber == g_sent_options[index].InstanceNumber)
        {
            char namespace[64];
            char buf[128];
            PDML_DHCPCV6_SENT p_old_entry = &g_sent_options[index];
            int commit = 0;
            int need_restart_service = 0;

            snprintf(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, index + 1);

            if (strcmp(pEntry->Alias, p_old_entry->Alias) != 0)
            {
                snprintf(buf, sizeof(buf), "%s_alias", namespace);
                syscfg_set(NULL, buf, pEntry->Alias);
                commit = 1;
            }

            if (pEntry->bEnabled != p_old_entry->bEnabled)
            {
                snprintf(buf, sizeof(buf), "%s_enabled", namespace);
                syscfg_set(NULL, buf, pEntry->bEnabled ? "1" : "0");
                commit = 1;
                need_restart_service = 1;
            }

            if (pEntry->Tag != p_old_entry->Tag)
            {
                snprintf(buf, sizeof(buf), "%s_tag", namespace);
                syscfg_set_u(NULL, buf, pEntry->Tag);
                commit = 1;
                need_restart_service = 1;
            }

            if (strcmp(pEntry->Value, p_old_entry->Value) != 0)
            {
                snprintf(buf, sizeof(buf), "%s_value", namespace);
                syscfg_set(NULL, buf, pEntry->Value);
                commit = 1;
                need_restart_service = 1;
            }

            if (commit)
            {
                syscfg_commit();
            }

            AnscCopyMemory( &g_sent_options[index], pEntry, sizeof(DML_DHCPCV6_SENT));

            if (need_restart_service)
            {
                _write_dibbler_sent_option_file();
                _dibbler_client_operation("restart");
            }

            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/* This is to get all
 */
#define CLIENT_RCVED_OPTIONS_FILE "/tmp/.dibbler-info/client_received_options"
/*this file has the following format:
 ......
 line n : opt-len opt-type opt-data(HexBinary)
 ......
*/
ANSC_STATUS
WanMgr_DmlDhcpv6cGetReceivedOptionCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PDML_DHCPCV6_RECV     *ppEntry,
        PULONG                      pSize
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    FILE *                          fp = fopen(CLIENT_RCVED_OPTIONS_FILE, "r+");
    SLIST_HEADER                    option_list;
    DML_DHCPCV6_RECV *         p_rcv = NULL;
    char                            buf[1024] = {0};
    PSINGLE_LINK_ENTRY              pSLinkEntry       = NULL;
    ULONG                           ulIndex = 0;

    AnscSListInitializeHeader( &option_list );

    if (fp)
    {
        while (fgets(buf, sizeof(buf)-1, fp))
        {
            int  opt_len = 0;
            char opt_data[1024] = {0};
            char * p = NULL;

            p_rcv = (DML_DHCPCV6_RECV * )AnscAllocateMemory(sizeof(*p_rcv));
            memset(p_rcv, 0, sizeof(*p_rcv));
            if (!p_rcv)
                break;

            if (sscanf(buf, "%d %lu", &opt_len, &p_rcv->Tag) != 2)
            {
                AnscFreeMemory(p_rcv); /*RDKB-6780, CID-33399, free unused resource*/
                p_rcv = NULL;
                continue;
            }

            /*don't trust opt_len record in file, calculate by self*/
            if ((p = strrchr(buf, ' ')))
            {
                p++;
                if ((unsigned int)opt_len*2 < (strlen(buf)- (p-buf)))
                    opt_len = (strlen(buf)- (p-buf))/2;
            }
            else
            {
                AnscFreeMemory(p_rcv); /*RDKB-6780, CID-33399, free unused resource*/
                p_rcv = NULL;
                continue;
            }

            if ((unsigned int)opt_len*2 >= sizeof(p_rcv->Value))
            {
                AnscFreeMemory(p_rcv); /*RDKB-6780, CID-33399, free unused resource*/
                p_rcv = NULL;
                continue;
            }

            /*finally we are safe, copy string into Value*/
            if (sscanf(buf, "%*d %*d %1023s", p_rcv->Value) != 1)
            {
                AnscFreeMemory(p_rcv); /*RDKB-6780, CID-33399, free unused resource*/
                p_rcv = NULL;
                continue;
            }
            /*we only support one server, hardcode it*/
            strncpy((char*)p_rcv->Server, "Device.DHCPv6.Client.1.Server.1",sizeof(p_rcv->Server)-1);
            AnscSListPushEntryAtBack(&option_list, &p_rcv->Link);

            memset(buf, 0, sizeof(buf));
        }
        fclose(fp);
    }

    if (!AnscSListGetFirstEntry(&option_list))
    {
        *pSize = 0;
        return ANSC_STATUS_SUCCESS;
    }

    *ppEntry = (PDML_DHCPCV6_RECV)AnscAllocateMemory( AnscSListQueryDepth(&option_list) *sizeof(DML_DHCPCV6_RECV) );

    pSLinkEntry = AnscSListGetFirstEntry(&option_list);

    for ( ulIndex = 0; ulIndex < option_list.Depth; ulIndex++ )
    {
        p_rcv = ACCESS_DHCPV6_RECV_LINK_OBJECT(pSLinkEntry);
        pSLinkEntry = AnscSListGetNextEntry(pSLinkEntry);

        AnscCopyMemory( *ppEntry + ulIndex, p_rcv, sizeof(*p_rcv) );
        AnscFreeMemory(p_rcv);
    }

    *pSize = AnscSListQueryDepth(&option_list);

    /* we need keep this for reference in server*/
    if ( g_recv_options )
        AnscFreeMemory(g_recv_options);

    g_recv_option_num = *pSize;
    g_recv_options = (DML_DHCPCV6_RECV *)AnscAllocateMemory( sizeof(DML_DHCPCV6_RECV) * g_recv_option_num );
    AnscCopyMemory(g_recv_options, *ppEntry, sizeof(DML_DHCPCV6_RECV) * g_recv_option_num);

    return ANSC_STATUS_SUCCESS;
}

void
WanMgr_DmlDhcpv6Remove(ANSC_HANDLE hContext)
{
    UNREFERENCED_PARAMETER(hContext);
    /*remove backend memory*/
    if (g_sent_options)
        AnscFreeMemory(g_sent_options);
    return;
}

#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
 /* dhcpv6_assign_global_ip Copied from PAM module */
int dhcpv6_assign_global_ip(char * prefix, char * intfName, char * ipAddr)
{

    unsigned int    length           = 0;
    char            globalIP[64]     = {0};
    char           *pMac             = NULL;
    unsigned int    i                = 0;
    unsigned int    j                = 0;
    unsigned int    k                = 0;
    char            out[256]         = {0};
    char            tmp[8]           = {0};
    FILE *fp = NULL;

     _ansc_strcpy( globalIP, prefix);
    /* Prepare the first part. */

    i = _ansc_strlen(globalIP);

    while( (globalIP[i-1] != '/') && (i>0) ) i--;

    if ( i == 0 ){
        CcspTraceError(("error, there is not '/' in prefix:%s\n", prefix));
        return 1;
    }

    length = atoi(&globalIP[i]);

    if ( length > 64 ){
        CcspTraceError(("error, length is bigger than 64. prefix:%s, length:%d\n", prefix, length));
        return 1;
    }

    globalIP[i-1] = '\0';

    i = i-1;

    if ( (globalIP[i-1]!=':') && (globalIP[i-2]!=':') ){
        CcspTraceError(("error, there is not '::' in prefix:%s\n", prefix));
        return 1;
    }
#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
    WanMgr_Config_Data_t    *pWanConfigData = WanMgr_GetConfigData_locked();
    unsigned char           IPv6EUI64FormatSupport = TRUE;

    if( NULL != pWanConfigData )
    {
        IPv6EUI64FormatSupport = pWanConfigData->data.IPv6EUI64FormatSupport;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    if ( FALSE == IPv6EUI64FormatSupport )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
    {
        if(strncmp(intfName, COSA_DML_DHCPV6_SERVER_IFNAME, strlen(intfName)) == 0)
        {
            snprintf(ipAddr, 128, "%s1", globalIP);
            CcspTraceInfo(("the full part is:%s\n", ipAddr));
            return 0;
        }
    }
#endif

    j = i-2;
    k = 0;
    while( j>0 ){
        if ( globalIP[j-1] == ':' )
            k++;
        j--;
    }

    if ( k == 3 )
    {
        globalIP[i-1] = '\0';
        i = i - 1;
    }

    CcspTraceInfo(("the first part is:%s\n", globalIP));

    /* prepare second part */
    fp = v_secure_popen("r", "ifconfig %s | grep HWaddr", intfName );
    _get_shell_output(fp, out, sizeof(out));
    v_secure_pclose(fp);
    pMac =_ansc_strstr(out, "HWaddr");
    if ( pMac == NULL ){
        CcspTraceError(("error, this interface has not a mac address .\n"));
        return 1;
    }
    pMac += _ansc_strlen("HWaddr");
    while( pMac && (pMac[0] == ' ') )
        pMac++;

    /* switch 7bit to 1*/
    tmp[0] = pMac[1];

    k = strtol(tmp, (char **)NULL, 16);

    k = k ^ 0x2;
    if ( k < 10 )
        k += '0';
    else
        k += 'A' - 10;

    pMac[1] = k;
    pMac[17] = '\0';

    //00:50:56: FF:FE:  92:00:22
    _ansc_strncpy(out, pMac, 9);
    out[9] = '\0';
    _ansc_strcat(out, "FF:FE:");
    _ansc_strcat(out, pMac+9);

    for(k=0,j=0;out[j];j++){
        if ( out[j] == ':' )
            continue;
        globalIP[i++] = out[j];
        if ( ++k == 4 ){
           globalIP[i++] = ':';
           k = 0;
        }
    }

    globalIP[i-1] = '\0';

    CcspTraceInfo(("the full part is:%s\n", globalIP));
    _ansc_strncpy(ipAddr, globalIP, sizeof(globalIP) - 1);
    /* This IP should be unique. If not I have no idea. */
    return 0;
}
#endif

static ANSC_STATUS wanmgr_dchpv6_get_ipc_msg_info(WANMGR_IPV6_DATA* pDhcpv6Data, ipc_dhcpv6_data_t* pIpcIpv6Data)
{
    if((pDhcpv6Data == NULL) || (pIpcIpv6Data == NULL))
    {
        return ANSC_STATUS_FAILURE;
    }
    memcpy(pDhcpv6Data->ifname, pIpcIpv6Data->ifname, BUFLEN_32);
    memcpy(pDhcpv6Data->address, pIpcIpv6Data->address, BUFLEN_48);
    memcpy(pDhcpv6Data->pdIfAddress, pIpcIpv6Data->pdIfAddress, BUFLEN_48);
    memcpy(pDhcpv6Data->nameserver, pIpcIpv6Data->nameserver, BUFLEN_128);
    memcpy(pDhcpv6Data->nameserver1, pIpcIpv6Data->nameserver1, BUFLEN_128);
    memcpy(pDhcpv6Data->domainName, pIpcIpv6Data->domainName, BUFLEN_64);
    memcpy(pDhcpv6Data->sitePrefix, pIpcIpv6Data->sitePrefix, BUFLEN_48);
    pDhcpv6Data->prefixPltime = pIpcIpv6Data->prefixPltime;
    pDhcpv6Data->prefixVltime = pIpcIpv6Data->prefixVltime;
    memcpy(pDhcpv6Data->sitePrefixOld, pIpcIpv6Data->sitePrefixOld, BUFLEN_48);
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
    pDhcpv6Data->addrAssigned = pIpcIpv6Data->addrAssigned;
    pDhcpv6Data->addrCmd = pIpcIpv6Data->addrCmd;
    pDhcpv6Data->prefixAssigned = pIpcIpv6Data->prefixAssigned;
    pDhcpv6Data->prefixCmd = pIpcIpv6Data->prefixCmd;
    pDhcpv6Data->domainNameAssigned = pIpcIpv6Data->domainNameAssigned;
#endif
    return ANSC_STATUS_SUCCESS;
}

#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
/**
 * @brief Copies the previous prefix from the old IPv6 data to the new IPv6 data.
 *
 * This function handles the copying of IAPD details from the old data structure
 * to the new one, ensuring that the previous IAPD details are used if only IANA is renewed.
 *
 * @param[in] pOld Pointer to the old WANMGR_IPV6_DATA structure.
 * @param[in] pNew Pointer to the new WANMGR_IPV6_DATA structure.
 * @return int Status code indicating success or failure.
 */
static int WanMgr_CopyPreviousPrefix(WANMGR_IPV6_DATA* pOld, WANMGR_IPV6_DATA* pNew)
{
    if((pOld == NULL) || (pNew == NULL))
    {
        return -1;
    }
    strncpy(pNew->sitePrefix, pOld->sitePrefix, sizeof(pNew->sitePrefix));
    strncpy(pNew->pdIfAddress, pOld->pdIfAddress, sizeof(pNew->pdIfAddress));
    memcpy(pNew->sitePrefixOld, pOld->sitePrefixOld, BUFLEN_48);
    pNew->prefixAssigned = true;
    pNew->prefixCmd = pOld->prefixCmd;
    pNew->prefixPltime = pOld->prefixPltime;
    pNew->prefixVltime = pOld->prefixVltime;
    return 0;
}
#endif

ANSC_STATUS wanmgr_handle_dhcpv6_event_data(DML_VIRTUAL_IFACE * pVirtIf)
{
    if(NULL == pVirtIf)
    {
       return ANSC_STATUS_FAILURE;
    }

    ipc_dhcpv6_data_t* pNewIpcMsg = pVirtIf->IP.pIpcIpv6Data;
    WANMGR_IPV6_DATA* pDhcp6cInfoCur = &(pVirtIf->IP.Ipv6Data);
    if((NULL == pDhcp6cInfoCur) || (NULL == pNewIpcMsg))
    {
       return ANSC_STATUS_BAD_PARAMETER;
    }

    BOOL connected = FALSE;
    char set_value[BUFLEN_64];

    memset(set_value, 0, sizeof(set_value));

    CcspTraceInfo(("IPv6 new Lease info: \nprefixAssigned=%d prefixCmd=%d sitePrefix=%s pdIfAddress=%s \n"
                   "prefixPltime=%d prefixVltime=%d\n"
                   "addrAssigned=%d addrCmd=%d address=%s ifname=%s\n"
                   "maptAssigned=%d mapeAssigned=%d\n"
                   "dnsAssigned=%d nameserver=%s,%s aftrAssigned=%d aftr=%s isExpired=%d \n",
                   pNewIpcMsg->prefixAssigned, pNewIpcMsg->prefixCmd, pNewIpcMsg->sitePrefix,
                   pNewIpcMsg->pdIfAddress, pNewIpcMsg->prefixPltime, pNewIpcMsg->prefixVltime,
                   pNewIpcMsg->addrAssigned, pNewIpcMsg->addrCmd, pNewIpcMsg->address, pNewIpcMsg->ifname,
                   pNewIpcMsg->maptAssigned, pNewIpcMsg->mapeAssigned,
                   pNewIpcMsg->dnsAssigned, pNewIpcMsg->nameserver, pNewIpcMsg->nameserver1, pNewIpcMsg->aftrAssigned, pNewIpcMsg->aftr, pNewIpcMsg->isExpired));

    WANMGR_IPV6_DATA Ipv6DataNew; // Holds the new lease from the IPC message
    memset(&Ipv6DataNew, 0, sizeof(Ipv6DataNew));
    wanmgr_dchpv6_get_ipc_msg_info(&(Ipv6DataNew), pNewIpcMsg);

    /*Check lease expiry*/
    if (pNewIpcMsg->isExpired)
    {
        CcspTraceInfo(("DHCP6LeaseExpired\n"));
        // update current IPv6 data
        WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_IPV6_DOWN);

        //Free buffer
        if (pVirtIf->IP.pIpcIpv6Data != NULL )
        {
            //free memory
            free(pVirtIf->IP.pIpcIpv6Data);
            pVirtIf->IP.pIpcIpv6Data = NULL;
        }

        return ANSC_STATUS_SUCCESS;
    }
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)

    /* dhcp6c receives an IPv6 address for WAN interface */
    if (pNewIpcMsg->addrAssigned)
    {
        if (pNewIpcMsg->addrCmd == IFADDRCONF_ADD)
        {
            CcspTraceInfo(("assigned IPv6 address \n"));
            connected = TRUE;

            /* TODO: Assign IPv6 address on Wan Interface when received, if dhcpv6 client didn't assign on the ineterface.
             * Currently dibbler client will assign IA_NA to the interface.
             * VISM will assign the prefix on LAN interface.
             */
        }
    }
    else if(pDhcp6cInfoCur->addrAssigned && Ipv6DataNew.prefixAssigned)
    {
        /* In an IPv6 lease, both IANA and IAPD details are sent together in a struct. 
         * If only one of them is renewed, the other field will be set to its default value.
         * In this scenario, we should not consider IANA or IAPD as deleted. 
         * If we reach this point, only IAPD has been renewed. Use the previous IANA details. */

        CcspTraceWarning(("%s %d IANA is not assigned in this IPC msg, but we have IANA configured from previous lease. Assuming only IAPD renewed. \n", __FUNCTION__, __LINE__));
        strncpy(Ipv6DataNew.address, pDhcp6cInfoCur->address, sizeof(Ipv6DataNew.address));
        Ipv6DataNew.addrAssigned = true;
        pNewIpcMsg->addrAssigned = true;
        Ipv6DataNew.addrCmd = pDhcp6cInfoCur->addrCmd;
    }

    /* dhcp6c receives prefix delegation for LAN */
    if (pNewIpcMsg->prefixAssigned && !IS_EMPTY_STRING(pNewIpcMsg->sitePrefix))
    {
        if (pNewIpcMsg->prefixCmd == IFADDRCONF_ADD &&
            pNewIpcMsg->prefixPltime != 0 && pNewIpcMsg->prefixVltime != 0)
        {
            CcspTraceInfo(("assigned prefix=%s \n", pNewIpcMsg->sitePrefix));
            connected = TRUE;
        }
        else /* IFADDRCONF_REMOVE: prefix remove */
        {
            /* Validate if the prefix to be removed is the same as the stored prefix */
            if (strcmp(pDhcp6cInfoCur->sitePrefix, pNewIpcMsg->sitePrefix) == 0)
            {
                CcspTraceInfo(("remove prefix \n"));
                WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_IPV6_DOWN);
            }
        }
    }
    else if(pDhcp6cInfoCur->prefixAssigned &&  Ipv6DataNew.addrAssigned)
    {
        /* In an IPv6 lease, both IANA and IAPD details are sent together in a struct. 
         * If only one of them is renewed, the other field will be set to its default value.
         * In this scenario, we should not consider IANA or IAPD as deleted. 
         * If we reach this point, only IAPD has been renewed. Use the previous IAPD details. */
        CcspTraceWarning(("%s %d IAPD is not assigned in this IPC msg, but we have IAPD configured from previous lease. Assuming only IANA renewed. \n", __FUNCTION__, __LINE__));
        WanMgr_CopyPreviousPrefix(pDhcp6cInfoCur, &Ipv6DataNew);
    }

#else
    /* dhcp6c receives an IPv6 address for WAN interface */
    if (pNewIpcMsg->addrAssigned)
    {
        if (pNewIpcMsg->addrCmd == IFADDRCONF_ADD)
        {
            CcspTraceInfo(("assigned IPv6 address \n"));
            connected = TRUE;
            if (strcmp(pDhcp6cInfoCur->address, pNewIpcMsg->address))
            {
                syscfg_set_string(SYSCFG_FIELD_IPV6_ADDRESS, pNewIpcMsg->address);
            }
        }
        else /* IFADDRCONF_REMOVE */
        {
            CcspTraceInfo(("remove IPv6 address \n"));
            syscfg_set_string(SYSCFG_FIELD_IPV6_ADDRESS, "");
        }
    }

    /* dhcp6c receives prefix delegation for LAN */
    if (pNewIpcMsg->prefixAssigned && !IS_EMPTY_STRING(pNewIpcMsg->sitePrefix))
    {
        if (pNewIpcMsg->prefixCmd == IFADDRCONF_ADD &&
            pNewIpcMsg->prefixPltime != 0 && pNewIpcMsg->prefixVltime != 0)
        {
            CcspTraceInfo(("assigned prefix=%s \n", pNewIpcMsg->sitePrefix));
            connected = TRUE;

            /* Update the WAN prefix validity time in the persistent storage */
            if (pDhcp6cInfoCur->prefixVltime != pNewIpcMsg->prefixVltime)
            {
                snprintf(set_value, sizeof(set_value), "%d", pNewIpcMsg->prefixVltime);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIXVLTIME, set_value, 0);
            }

            if (pDhcp6cInfoCur->prefixPltime != pNewIpcMsg->prefixPltime)
            {
                snprintf(set_value, sizeof(set_value), "%d", pNewIpcMsg->prefixPltime);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIXPLTIME, set_value, 0);
            }

            if (strcmp(pDhcp6cInfoCur->sitePrefixOld, pNewIpcMsg->sitePrefixOld))
            {
                syscfg_set_string(SYSCFG_FIELD_PREVIOUS_IPV6_PREFIX, pNewIpcMsg->sitePrefixOld);
            }

            if (strcmp(pDhcp6cInfoCur->sitePrefix, pNewIpcMsg->sitePrefix))
            {
                syscfg_set_string(SYSCFG_FIELD_IPV6_PREFIX, pNewIpcMsg->sitePrefix);
            }

            // create global IPv6 address (<prefix>::1)
            char prefix[BUFLEN_64] = {0};
            memset(prefix, 0, sizeof(prefix));

            int index = strcspn(pNewIpcMsg->sitePrefix, "/");
            if (index < strlen(pNewIpcMsg->sitePrefix) && index < sizeof(prefix))
            {
                strncpy(prefix, pNewIpcMsg->sitePrefix, index);                                            // only copy prefix without the prefix length
                snprintf(set_value, sizeof(set_value), "%s1", prefix);                                        // concatenate "1" onto the prefix, which is in the form "xxxx:xxxx:xxxx:xxxx::"
                snprintf(pNewIpcMsg->pdIfAddress, sizeof(pNewIpcMsg->pdIfAddress), "%s/64", set_value); // concatenate prefix address with length "/64"

                if (strcmp(pDhcp6cInfoCur->pdIfAddress, pNewIpcMsg->pdIfAddress))
                {
                    syscfg_set_string(SYSCFG_FIELD_IPV6_PREFIX_ADDRESS, pNewIpcMsg->pdIfAddress);
                    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_TR_BRLAN0_DHCPV6_SERVER_ADDRESS, set_value, 0);
                }

                if (strcmp(pDhcp6cInfoCur->sitePrefix, pNewIpcMsg->sitePrefix) != 0)
                {
                    CcspTraceInfo(("%s %d new prefix = %s, current prefix = %s \n", __FUNCTION__, __LINE__, pNewIpcMsg->sitePrefix, pDhcp6cInfoCur->sitePrefix));
                    strncat(prefix, "/64",sizeof(prefix)-1);
                    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIX, prefix, 0);
                }
            }
        }
        else /* IFADDRCONF_REMOVE: prefix remove */
        {
            /* Validate if the prefix to be removed is the same as the stored prefix */
            if (strcmp(pDhcp6cInfoCur->sitePrefix, pNewIpcMsg->sitePrefix) == 0)
            {
                CcspTraceInfo(("remove prefix \n"));
                syscfg_set(NULL, SYSCFG_FIELD_IPV6_PREFIX, "");
                syscfg_set(NULL, SYSCFG_FIELD_PREVIOUS_IPV6_PREFIX, "");
                syscfg_set_commit(NULL, SYSCFG_FIELD_IPV6_PREFIX_ADDRESS, "");
                WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_CONNECTION_IPV6_DOWN);
            }
        }
    }

    /* dhcp6c receives domain name information */
    if (pNewIpcMsg->domainNameAssigned && !IS_EMPTY_STRING(pNewIpcMsg->domainName))
    {
        CcspTraceInfo(("assigned domain name=%s \n", pNewIpcMsg->domainName));

        if (strcmp(pDhcp6cInfoCur->domainName, pNewIpcMsg->domainName))
        {
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DOMAIN, pNewIpcMsg->domainName, 0);
        }
    }
#endif

    /* Even when dhcp6c is not used to get the WAN interface IP address,
     *  * use this message as a trigger to check the WAN interface IP.
     *   * Maybe we've been assigned an address by SLAAC.*/

    if (!pNewIpcMsg->addrAssigned)
    {
        char guAddrPrefix[IP_ADDR_LENGTH] = {0};
        char guAddr[IP_ADDR_LENGTH] = {0};
        uint32_t prefixLen = 0;
        ANSC_STATUS r2;

        r2 = WanManager_getGloballyUniqueIfAddr6(pVirtIf->Name, guAddr, &prefixLen);

        if (ANSC_STATUS_SUCCESS == r2)
        {
            snprintf(guAddrPrefix,sizeof(guAddrPrefix)-1, "%s/%d", guAddr, prefixLen);
            CcspTraceInfo(("Detected GloballyUnique Addr6 %s, mark connection up! \n", guAddrPrefix));
            connected = TRUE;

            if (strcmp(pDhcp6cInfoCur->address, guAddrPrefix))
            {
                strncpy(Ipv6DataNew.address, guAddr, sizeof(Ipv6DataNew.address)-1);
                pNewIpcMsg->addrAssigned = true;
#if !defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
                syscfg_set_string(SYSCFG_FIELD_IPV6_ADDRESS, guAddrPrefix);
#endif
            }
        }
    }

    /*
     * dhcp6c receives AFTR information
     * TODO: should we update aftr even WAN is not connected?
     */
    if (connected && pNewIpcMsg->aftrAssigned && !IS_EMPTY_STRING(pNewIpcMsg->aftr))
    {
        CcspTraceInfo(("assigned aftr=%s \n", pNewIpcMsg->aftr));
    }

    if (connected)
    {
        if ((strlen(Ipv6DataNew.address) > 0 && strcmp(Ipv6DataNew.address, pDhcp6cInfoCur->address)) ||
                ((strlen(Ipv6DataNew.pdIfAddress) > 0) && (strcmp(Ipv6DataNew.pdIfAddress, pDhcp6cInfoCur->pdIfAddress))) ||
                ((strlen(Ipv6DataNew.sitePrefix) > 0) && (strcmp(Ipv6DataNew.sitePrefix, pDhcp6cInfoCur->sitePrefix)))||
                strcmp(Ipv6DataNew.nameserver, pDhcp6cInfoCur->nameserver) ||
                strcmp(Ipv6DataNew.nameserver1, pDhcp6cInfoCur->nameserver1))
        {
            CcspTraceInfo(("IPv6 configuration has been changed \n"));
            pVirtIf->IP.Ipv6Changed = TRUE;

            char param_name[256] = {0};
            snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv6Address",  pVirtIf->baseIfIdx+1, pVirtIf->VirIfIdx+1);
            WanMgr_Rbus_EventPublishHandler(param_name, Ipv6DataNew.address,RBUS_STRING);
            snprintf(param_name, sizeof(param_name), "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.%d.IP.IPv6Prefix",  pVirtIf->baseIfIdx+1, pVirtIf->VirIfIdx+1);
            WanMgr_Rbus_EventPublishHandler(param_name, Ipv6DataNew.sitePrefix,RBUS_STRING);

            pVirtIf->IP.RestartConnectivityCheck = TRUE;
            CcspTraceInfo(("%s %d - RestartConnectivityCheck triggered. \n", __FUNCTION__, __LINE__));
        }
        else
        {
            if(pVirtIf->Status == WAN_IFACE_STATUS_UP &&  pNewIpcMsg->prefixPltime > 0 && pNewIpcMsg->prefixVltime > 0 ) //Update life time only if the interface is active.
            {
#if !(defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_)) || defined(_RDKB_GLOBAL_PRODUCT_REQ_) //Do not add prefix on LAN bridge for the Comcast platforms.
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
            WanMgr_Config_Data_t    *pWanConfigData = WanMgr_GetConfigData_locked();
            unsigned char           ConfigureWANIPv6OnLANBridgeSupport = FALSE;

            if( NULL != pWanConfigData )
            {
                ConfigureWANIPv6OnLANBridgeSupport = pWanConfigData->data.ConfigureWANIPv6OnLANBridgeSupport;
                WanMgrDml_GetConfigData_release(pWanConfigData);
            }

            if ( TRUE == ConfigureWANIPv6OnLANBridgeSupport )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
            {
                //call function for changing the prlft and vallft
                if ((WanManager_Ipv6PrefixUtil(pVirtIf->Name, SET_LFT, pNewIpcMsg->prefixPltime, pNewIpcMsg->prefixVltime) < 0))
                {
                    CcspTraceError(("Life Time Setting Failed"));
                }
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_RADVD_RESTART, NULL, 0);
            }
#endif
            }
            pVirtIf->IP.Ipv6Renewed = TRUE;
        }
        // update current IPv6 Data
        memcpy(&(pVirtIf->IP.Ipv6Data), &(Ipv6DataNew), sizeof(WANMGR_IPV6_DATA));
	// update IPv6 Status
        WanManager_UpdateInterfaceStatus(pVirtIf,WANMGR_IFACE_CONNECTION_IPV6_UP);		
    }

#ifdef FEATURE_MAPT
    ipc_mapt_data_t dhcp6cMAPTMsgBodyPrvs;
    CcspTraceNotice(("FEATURE_MAPT: MAP-T Enable %d\n", pNewIpcMsg->maptAssigned));
    if (pNewIpcMsg->maptAssigned)
    {
#ifdef FEATURE_MAPT_DEBUG
        MaptInfo("--------- Got a new event in Wanmanager for MAPT_CONFIG ---------");
#endif

        //get MAP-T previous data
        memcpy(&dhcp6cMAPTMsgBodyPrvs, &(pVirtIf->MAP.dhcp6cMAPTparameters), sizeof(ipc_mapt_data_t));

        if (memcmp(&(pNewIpcMsg->mapt), &dhcp6cMAPTMsgBodyPrvs, sizeof(ipc_mapt_data_t)) != 0)
        {
            pVirtIf->MAP.MaptChanged = TRUE;
            CcspTraceInfo(("MAPT configuration has been changed \n"));
        }

        // store MAP-T parameters locally
        memcpy(&(pVirtIf->MAP.dhcp6cMAPTparameters), &(pNewIpcMsg->mapt), sizeof(ipc_mapt_data_t));

        // update MAP-T flags
        WanManager_UpdateInterfaceStatus(pVirtIf, WANMGR_IFACE_MAPT_START);
    }
    else
    {
        if (pNewIpcMsg->prefixAssigned && !IS_EMPTY_STRING(pNewIpcMsg->sitePrefix) && pNewIpcMsg->prefixPltime != 0 && pNewIpcMsg->prefixVltime != 0)
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

    //Free buffer
    if (pVirtIf->IP.pIpcIpv6Data != NULL )
    {
        //free memory
        free(pVirtIf->IP.pIpcIpv6Data);
        pVirtIf->IP.pIpcIpv6Data = NULL;
    }

    return ANSC_STATUS_SUCCESS;
} /* End of ProcessDhcp6cStateChanged() */

int setUpLanPrefixIPv6(DML_VIRTUAL_IFACE* pVirtIf)
{
    if (pVirtIf == NULL)
    {
        CcspTraceError(("%s %d - Invalid memory \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    CcspTraceInfo(("%s %d Updating SYSEVENT_CURRENT_WAN_IFNAME %s\n", __FUNCTION__, __LINE__,pVirtIf->IP.Ipv6Data.ifname));
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_CURRENT_WAN_IFNAME, pVirtIf->IP.Ipv6Data.ifname, 0);

    /* Enable accept ra */
    WanMgr_Configure_accept_ra(pVirtIf, TRUE);

    int index = strcspn(pVirtIf->IP.Ipv6Data.sitePrefix, "/");
    if (index < strlen(pVirtIf->IP.Ipv6Data.sitePrefix))
    {
        char lanPrefix[BUFLEN_48] = {0};
        strncpy(lanPrefix, pVirtIf->IP.Ipv6Data.sitePrefix, index);
        if ((sizeof(lanPrefix) - index) > 3)
        {
            char previousPrefix[BUFLEN_48] = {0};
            char previousPrefix_vldtime[BUFLEN_48] = {0};
            char previousPrefix_prdtime[BUFLEN_48] = {0};
            strncat(lanPrefix, "/64",sizeof(lanPrefix)-1);
            sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIX, previousPrefix, sizeof(previousPrefix));
            sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIXVLTIME, previousPrefix_vldtime, sizeof(previousPrefix_vldtime));
            sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIXPLTIME, previousPrefix_prdtime, sizeof(previousPrefix_prdtime));
            if (strncmp(previousPrefix, lanPrefix, BUFLEN_48) == 0)
            {
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIX, "", 0);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIXVLTIME, "0", 0);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIXPLTIME, "0", 0);
            }
            else if (strncmp(previousPrefix, "", BUFLEN_48) != 0)
            {
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIX, previousPrefix, 0);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIXVLTIME, previousPrefix_vldtime, 0);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_PREVIOUS_IPV6_PREFIXPLTIME, previousPrefix_prdtime, 0);
            }
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIX, lanPrefix, 0);
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_TR_EROUTER_DHCPV6_CLIENT_PREFIX, pVirtIf->IP.Ipv6Data.sitePrefix, 0);
        }
    }
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
    /* moved from PAM */
    int ret = RETURN_OK;
    char globalIP[128] = {0};
    char set_value[BUFLEN_64] = {0};
    char cmdLine[BUFLEN_256];

    WanMgr_RdkBus_setWanIpInterfaceData(pVirtIf);

    if (pVirtIf->IP.Ipv6Data.prefixPltime != 0 && pVirtIf->IP.Ipv6Data.prefixVltime != 0)
    {
        ret = dhcpv6_assign_global_ip(pVirtIf->IP.Ipv6Data.sitePrefix, COSA_DML_DHCPV6_SERVER_IFNAME, globalIP);
        if(ret != 0) {
            CcspTraceInfo(("Assign global ip error \n"));
        }
        else 
        {
#if !(defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_))  //Do not add prefix on LAN bridge for the Comcast platforms.
            CcspTraceInfo(("%s Going to set [%s] address on brlan0 interface \n", __FUNCTION__, globalIP));
            memset(cmdLine, 0, sizeof(cmdLine));
            snprintf(cmdLine, sizeof(cmdLine), "ip -6 addr add %s/64 dev %s valid_lft %d preferred_lft %d",
                    globalIP, COSA_DML_DHCPV6_SERVER_IFNAME, pVirtIf->IP.Ipv6Data.prefixVltime, pVirtIf->IP.Ipv6Data.prefixPltime);
            if (WanManager_DoSystemActionWithStatus(__FUNCTION__, cmdLine) != 0)
                CcspTraceError(("failed to run cmd: %s", cmdLine));
#endif
            CcspTraceInfo(("%s lan_ipaddr_v6 set to [%s]  \n", __FUNCTION__, globalIP));
            /*This is for brlan0 interface */
            char pref_len[10] ={0};
            sscanf (pVirtIf->IP.Ipv6Data.sitePrefix,"%*[^/]/%s" ,pref_len);
            sysevent_set(sysevent_fd, sysevent_token, "lan_prefix_v6", pref_len, 0);
            sysevent_set(sysevent_fd, sysevent_token, "lan_ipaddr_v6", globalIP, 0);
            sysevent_set(sysevent_fd, sysevent_token, "lan_prefix_set", globalIP, 0); //TODO: This was a event to Wanmanager. if no other process listens to it. remove it.
        }
        memset(cmdLine, 0, sizeof(cmdLine));
        snprintf(cmdLine, sizeof(cmdLine), "ip -6 route add %s dev %s", pVirtIf->IP.Ipv6Data.sitePrefix, COSA_DML_DHCPV6_SERVER_IFNAME);
        if (WanManager_DoSystemActionWithStatus(__FUNCTION__, cmdLine) != 0)
        {
            CcspTraceError(("failed to run cmd: %s", cmdLine));
        }
    }

    /* Sysevent set moved from wanmgr_handle_dhcpv6_event_data */
    if(pVirtIf->IP.Ipv6Data.addrAssigned )
    {
        if (pVirtIf->IP.Ipv6Data.addrCmd == IFADDRCONF_ADD)
        {
            CcspTraceInfo(("assigned IPv6 address \n"));
            syscfg_set_string(SYSCFG_FIELD_IPV6_ADDRESS, pVirtIf->IP.Ipv6Data.address);
            memset(cmdLine, 0, sizeof(cmdLine));
            snprintf(cmdLine, sizeof(cmdLine), COSA_DML_WANIface_ADDR_SYSEVENT_NAME ,pVirtIf->Name);
            sysevent_set(sysevent_fd, sysevent_token, cmdLine, pVirtIf->IP.Ipv6Data.address, 0);
        }
        else /* IFADDRCONF_REMOVE */
        {
            CcspTraceInfo(("remove IPv6 address \n"));
            syscfg_set_string(SYSCFG_FIELD_IPV6_ADDRESS, "");
        }
    }

    if (pVirtIf->IP.Ipv6Data.prefixAssigned && !IS_EMPTY_STRING(pVirtIf->IP.Ipv6Data.sitePrefix))
    {
        if (pVirtIf->IP.Ipv6Data.prefixCmd == IFADDRCONF_ADD &&
                pVirtIf->IP.Ipv6Data.prefixPltime != 0 && pVirtIf->IP.Ipv6Data.prefixVltime != 0)
        {
            CcspTraceInfo(("assigned prefix=%s \n", pVirtIf->IP.Ipv6Data.sitePrefix));
            snprintf(set_value, sizeof(set_value), "%d", pVirtIf->IP.Ipv6Data.prefixVltime);
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIXVLTIME, set_value, 0);
            snprintf(set_value, sizeof(set_value), "%d", pVirtIf->IP.Ipv6Data.prefixPltime);
            sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIXPLTIME, set_value, 0);
            syscfg_set_string(SYSCFG_FIELD_PREVIOUS_IPV6_PREFIX, pVirtIf->IP.Ipv6Data.sitePrefixOld);
            syscfg_set_string(SYSCFG_FIELD_IPV6_PREFIX, pVirtIf->IP.Ipv6Data.sitePrefix);
            // create global IPv6 address (<prefix>::1)
            char prefix[BUFLEN_64] = {0};
            memset(prefix, 0, sizeof(prefix));

            int index = strcspn(pVirtIf->IP.Ipv6Data.sitePrefix, "/");
            if (index < strlen(pVirtIf->IP.Ipv6Data.sitePrefix) && index < sizeof(prefix))
            {
                strncpy(prefix, pVirtIf->IP.Ipv6Data.sitePrefix, index);                                            // only copy prefix without the prefix length
                snprintf(set_value, sizeof(set_value), "%s1", prefix);                                        // concatenate "1" onto the prefix, which is in the form "xxxx:xxxx:xxxx:xxxx::"
                snprintf(pVirtIf->IP.Ipv6Data.pdIfAddress, sizeof(pVirtIf->IP.Ipv6Data.pdIfAddress), "%s/64", set_value); // concatenate prefix address with length "/64"
                syscfg_set_string(SYSCFG_FIELD_IPV6_PREFIX_ADDRESS, pVirtIf->IP.Ipv6Data.pdIfAddress);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_TR_BRLAN0_DHCPV6_SERVER_ADDRESS, set_value, 0);
                CcspTraceInfo(("%s %d new prefix = %s\n", __FUNCTION__, __LINE__, pVirtIf->IP.Ipv6Data.sitePrefix));
                strncat(prefix, "/64",sizeof(prefix)-1);
                sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_PREFIX, prefix, 0);
                sysevent_set(sysevent_fd, sysevent_token, "lan_prefix", prefix, 0);
            }
        }else /* IFADDRCONF_REMOVE: prefix remove */
        {
            CcspTraceInfo(("remove prefix \n"));
            syscfg_set(NULL, SYSCFG_FIELD_IPV6_PREFIX, "");
            syscfg_set(NULL, SYSCFG_FIELD_PREVIOUS_IPV6_PREFIX, "");
            syscfg_set_commit(NULL, SYSCFG_FIELD_IPV6_PREFIX_ADDRESS, "");
        }
    }

    /* dhcp6c receives domain name information */
    if (pVirtIf->IP.Ipv6Data.domainNameAssigned && !IS_EMPTY_STRING(pVirtIf->IP.Ipv6Data.domainName))
    {
        CcspTraceInfo(("assigned domain name=%s \n", pVirtIf->IP.Ipv6Data.domainName));

        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIELD_IPV6_DOMAIN, pVirtIf->IP.Ipv6Data.domainName, 0);
    }
    /* Sysevent set moved from wanmgr_handle_dhcpv6_event_data end */

#ifdef LAN_MGR_SUPPORT
    //Restart RA(stateless) server
    sysevent_set(sysevent_fd, sysevent_token, "dhcpv6_raserver-restart", NULL, 0);
    //recreate Stateful v6 conf
    sysevent_set(sysevent_fd, sysevent_token, "redirect_URL", NULL, 0);
    //Restart Stateful V6 server
    sysevent_set(sysevent_fd, sysevent_token, "dhcpv6-restart", NULL, 0);

#else
    sysevent_set(sysevent_fd, sysevent_token, "zebra-restart", NULL, 0);
    CcspTraceWarning(("Restart lan%s:%d\n", __func__,__LINE__));
    /* This is for IP.Interface.1. use */
    sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6S_ADDR_SYSEVENT_NAME, globalIP, 0);

    CcspTraceWarning(("%s: setting lan-restart\n", __FUNCTION__));
    sysevent_set(sysevent_fd, sysevent_token, "lan-restart", "1", 0);
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(DHCPV6_PREFIX_FIX) 
    CcspTraceWarning(("%s: setting dhcpv6_server-restart\n", __FUNCTION__));
    sysevent_set(sysevent_fd, sysevent_token, "dhcpv6_server-restart", "", 0);
#else
    // Below code copied from CosaDmlDHCPv6sTriggerRestart(FALSE) PAm function.
    int fd = 0;
    char str[32] = "restart";
    fd= open(DHCPS6V_SERVER_RESTART_FIFO, O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr, "open dhcpv6 server restart fifo when writing.\n");
        return 1;
    }
    write( fd, str, sizeof(str) );
    close(fd);
#endif
#endif
#endif
    return RETURN_OK;
}

/** WanMgr_Handle_Dhcpv6_NetLink_Address_Event() */
ANSC_STATUS WanMgr_Handle_Dhcpv6_NetLink_Address_Event(IPv6NetLinkAddrEvent *pstAddrEvent)
{
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;

    if( NULL == pstAddrEvent )
    {
        CcspTraceError(("%s %d - Invalid memory \n", __FUNCTION__, __LINE__));
        return ret;
    }

    UINT uiLoopCount;
    UINT TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();

    for( uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data); 

            //CcspTraceInfo(("%s %d: '%s' <Entry> Event checking for '%s' interface\n", __FUNCTION__, __LINE__, pstAddrEvent->event, pstAddrEvent->ifname));

            for(int VirtId=0; VirtId < pWanIfaceData->NoOfVirtIfs; VirtId++)
            {
                DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIface_locked(uiLoopCount, VirtId);
                if( NULL != p_VirtIf )
                {
                    //Allow only for SLAAC use
                    if ( ( p_VirtIf->Enable == TRUE ) && \
                            ( DML_WAN_IP_SOURCE_SLAAC == p_VirtIf->IP.IPv6Source ) && \
                            ( 0 == strncmp( p_VirtIf->Name, pstAddrEvent->ifname, strlen(pstAddrEvent->ifname) ) ) && \
                            ( IPV6_RA_VALID_SLAAC == p_VirtIf->IP.Ipv6RA.enIPv6RAStatus ) )
                    {
                        if ( 0 == strncmp(pstAddrEvent->event, "NEWADDR", strlen("NEWADDR")) ) //Address Add
                        {
                            if ( ( 0 != strncmp( p_VirtIf->IP.Ipv6Data.address, pstAddrEvent->addr, strlen(pstAddrEvent->addr) ) ) ||
                                 ( WAN_IFACE_IPV6_STATE_UP != p_VirtIf->IP.Ipv6Status ) )
                            {
                                CcspTraceInfo(("%s %d: [SLAAC] IPv6 Address Changed for '%s' Previous Address[%s], Current Address[%s]\n", __FUNCTION__, __LINE__, p_VirtIf->Name, p_VirtIf->IP.Ipv6Data.address, pstAddrEvent->addr));

                                snprintf(p_VirtIf->IP.Ipv6Data.address, sizeof(p_VirtIf->IP.Ipv6Data.address), "%s", pstAddrEvent->addr);
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
                                p_VirtIf->IP.Ipv6Data.addrAssigned   = TRUE;
                                p_VirtIf->IP.Ipv6Data.addrCmd        = IFADDRCONF_ADD;
#endif /** FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE */
                                p_VirtIf->IP.Ipv6Changed             = TRUE;
                                p_VirtIf->IP.Ipv6Status              = WAN_IFACE_IPV6_STATE_UP;
                            }
                        }
                        else if ( 0 == strncmp(pstAddrEvent->event, "DELADDR", strlen("DELADDR")) ) //Address Delete
                        {
                            CcspTraceInfo(("%s %d: [SLAAC] IPv6 Address Deleted for '%s' Deleted Address[%s]\n", __FUNCTION__, __LINE__, p_VirtIf->Name, pstAddrEvent->addr));
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
                            p_VirtIf->IP.Ipv6Data.addrCmd        = IFADDRCONF_REMOVE;
#endif /** FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE */
                            p_VirtIf->IP.Ipv6Status              = WAN_IFACE_IPV6_STATE_DOWN;
                        }
                    }

                    WanMgr_VirtualIfaceData_release(p_VirtIf);
                }
            }

            //CcspTraceInfo(("%s %d: '%s' <Exit> Event checking for '%s' interface\n", __FUNCTION__, __LINE__, pstAddrEvent->event, pstAddrEvent->ifname));
        }   

        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }
                        
    return ANSC_STATUS_SUCCESS;
}
