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

 /***********************************************************************
  * TODO: This file has legacy Ipv6/Ipv4 handling APIs. 
  * This file should be removed once all platforms moved to DHCP manager 
  * Currently this APIs are used only by DT. This file also has DT specific APIs
  *************************************************************************/

#include "wanmgr_data.h"
#include "wanmgr_dhcpv6_apis.h"
#include "wanmgr_interface_sm.h"
#include "wanmgr_sysevents.h"
#include "wanmgr_ipc.h"
#include "wanmgr_utils.h"
#include "wanmgr_net_utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "secure_wrapper.h"
#ifdef _ONESTACK_PRODUCT_REQ_
#include <rdkb_feature_mode_gate.h>
#endif
#if defined(_DT_WAN_Manager_Enable_)
int _get_shell_output2(char * cmd, char * dststr)
{
    FILE * fp;
    char   buf[256];
    char * p;
    int   bFound = 0;

    fp = popen(cmd, "r");

    if (fp)
    {
        while( fgets(buf, sizeof(buf), fp) )
        {
            if (strstr(buf, dststr))
            {
                bFound = 1;;
                break;
            }
        }

        pclose(fp);
    }

    return bFound;
}

#define HOSTS "/etc/hosts"
#define TEMP_HOST "/tmp/tmp_host.txt"
#define MAXCHAR 128
char GUEST_PREVIOUS_PREFIX[MAXCHAR]={0};
int brlan1_prefix_changed=0;
char GUEST_PREVIOUS_IP[128]={0};
extern bool needDibblerRestart;

/* Thread for assessing Router Advertisement flags */
static struct {
    pthread_t rtadv_dbgthread;
}rtadv_thread;

static void * rtadv_dbg_thread(void * in);
#define RA_COMMON_FIFO "/tmp/ra_common_fifo"
#define IPv6_RT_MON_NOTIFY_CMD "kill -10 `pidof ipv6rtmon`"
typedef struct
{
    char managedFlag;
    char otherFlag;
} desiredRtAdvInfo;


static int set_syscfg(char *param, char *pValue)
{
    if((syscfg_set(NULL, param, pValue) != 0))
    {
        return -1;
    }
    else
    {
        if(syscfg_commit() != 0)
        {
            return -1;
        }
        return 0;
    }
}

void _get_shell_output3(FILE *fp, char *buf, int len)
{
    char * p;

    if (fp && buf && (len>0))
    {
        if(fgets (buf, len, fp) != NULL)
        {
            if ((p = strchr(buf, '\n'))) {
                *p = '\0';
            }
        }
    v_secure_pclose(fp);
    }
}

static int format_time(char *time)
{
    if (time == NULL)
        return -1;
    for (int i = 0; i < strlen(time); i++) {
        if(time[i] == '\'') time[i] = ' ';
    }
    return 0;
}

void enable_IPv6(char* if_name)
{
        FILE *fp = NULL;

        CcspTraceInfo(("%s : Enabling ipv6 on iface %s\n",__FUNCTION__,if_name));
        char tbuff[100] = {0} , ipv6_addr[128] = {0} , cmd[128] = {0} ;
        char guest_v6pref[64] = {0};
        char guest_globalIP[128] = {0};
        unsigned int prefixLen = 0;
        int ret = 0;
        memset(ipv6_addr,0,sizeof(ipv6_addr));
        memset(tbuff,0,sizeof(tbuff));
        fp = v_secure_popen("r","sysctl net.ipv6.conf.%s.autoconf",if_name);
        _get_shell_output3(fp, tbuff, sizeof(tbuff));
        if(tbuff[strlen(tbuff)-1] == '0')
        {
                v_secure_system("sysctl -w net.ipv6.conf.%s.autoconf=1",if_name);
                v_secure_system("ifconfig %s down;ifconfig %s up",if_name,if_name);
        }

        memset(cmd,0,sizeof(cmd));
        _ansc_sprintf(cmd, "%s_ipaddr_v6",if_name);
         sysevent_get(sysevent_fd, sysevent_token, cmd, ipv6_addr, sizeof(ipv6_addr));
        v_secure_system("ip -6 route add %s dev %s", ipv6_addr, if_name);
        /*Clean 'iif if_name table erouter' if exist already to avoid duplication*/
        v_secure_system("ip -6 rule del iif %s table erouter", if_name);
        v_secure_system("ip -6 rule add iif %s lookup erouter",if_name);
        sysevent_get(sysevent_fd, sysevent_token, "wan6_prefix", guest_v6pref, sizeof(guest_v6pref));
        prefixLen=_ansc_strlen(guest_v6pref);
        if( (guest_v6pref[prefixLen-1] == ':') && (guest_v6pref[prefixLen-2] == ':') ){
            guest_v6pref[prefixLen-3] = '1' ;
        }
        sprintf(guest_v6pref+strlen(guest_v6pref), "/%d", 64);

        if(brlan1_prefix_changed == 0)
        {
            sysevent_get(sysevent_fd, sysevent_token, "brlan1_IPv6_prefix", GUEST_PREVIOUS_PREFIX, sizeof(GUEST_PREVIOUS_PREFIX));
        }
        else
              brlan1_prefix_changed = 0;
        if (_ansc_strncmp(GUEST_PREVIOUS_PREFIX, guest_v6pref,strlen(GUEST_PREVIOUS_PREFIX)) != 0)
        {
            sysevent_set(sysevent_fd, sysevent_token, "brlan1_previous_ipv6_prefix", GUEST_PREVIOUS_PREFIX, 0);
            _ansc_strncpy(GUEST_PREVIOUS_PREFIX, guest_v6pref, sizeof(guest_v6pref));
        }

        sysevent_set(sysevent_fd, sysevent_token, "brlan1_IPv6_prefix", guest_v6pref , 0);
        ret = dhcpv6_assign_global_ip(guest_v6pref, "brlan1", guest_globalIP);
        if ( ret != 0 ){
            AnscTrace("error, assign global ip error.\n");
        }
        else{
            sysevent_set(sysevent_fd, sysevent_token, "brlan1_ipaddr_v6", guest_globalIP , 0);
            if ( GUEST_PREVIOUS_IP[0] && (_ansc_strcmp(GUEST_PREVIOUS_IP, guest_globalIP ) != 0) ){
                sysevent_set(sysevent_fd, sysevent_token,"brlan1_previous_ipaddr_v6", GUEST_PREVIOUS_IP, 0);
                 v_secure_system("ip -6 addr del %s/64 dev brlan1 valid_lft forever preferred_lft forever", GUEST_PREVIOUS_IP);
                 _ansc_strcpy(GUEST_PREVIOUS_IP, guest_globalIP);
            }
            v_secure_system("ip -6 addr add %s/64 dev brlan1 valid_lft forever preferred_lft forever", guest_globalIP);
        }
}

ANSC_STATUS
WanMgr_DmlDhcpv6SMsgHandler
    (
        ANSC_HANDLE                 hContext
    )
{
    char ret[16] = {0};
    CcspTraceWarning(("%s -- %d Inside WanMgr_DmlDhcpv6SMsgHandler \n", __FUNCTION__, __LINE__));
    CcspTraceWarning(("%s -- %d dhcpv6c_dbg_thrd invoking  \n", __FUNCTION__, __LINE__));
    /*we start a thread to hear dhcpv6 client message about prefix/address */
    if ( ( !mkfifo(CCSP_COMMON_FIFO, 0666) || errno == EEXIST ) )
    {
        if (pthread_create(&gDhcpv6c_ctx.dhcpv6c_thread, NULL, dhcpv6c_dbg_thrd, NULL)  || pthread_detach(gDhcpv6c_ctx.dhcpv6c_thread))
            CcspTraceWarning(("%s error in creating dhcpv6c_dbg_thrd\n", __FUNCTION__));
    }

    /* Spawning thread for assessing Router Advertisement message from FIFO file written by ipv6rtmon daemon */
    if ( !mkfifo(RA_COMMON_FIFO, 0666) || errno == EEXIST )
    {
        if (pthread_create(&rtadv_thread.rtadv_dbgthread, NULL, rtadv_dbg_thread, NULL)  || pthread_detach(rtadv_thread.rtadv_dbgthread))
            CcspTraceWarning(("%s error in creating rtadv_dbg_thread\n", __FUNCTION__));
    }

    return 0;
}

ANSC_STATUS
WanMgr_DmlDhcpv6Init
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext
    )
{
    DSLHDMAGNT_CALLBACK *  pEntry = NULL;
    CcspTraceWarning(("Inside %s %d \n", __FUNCTION__, __LINE__));
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(_CBR_PRODUCT_REQ_) && ! defined(_BCI_FEATURE_REQ) && !defined(_ONESTACK_PRODUCT_REQ_)

#else
    #ifdef _ONESTACK_PRODUCT_REQ_
    if (!isFeatureSupportedInCurrentMode(FEATURE_IPV6_DELEGATION))
#endif
    {
        /* handle message from wan dhcp6 client */
        WanMgr_DmlDhcpv6SMsgHandler(NULL);
    }
#endif


    return ANSC_STATUS_SUCCESS;
}



int dhcpv6_assign_global_ip(char * prefix, char * intfName, char * ipAddr)
{
    unsigned int    length           = 0;
    char            globalIP[64]     = {0};
    char           *pMac             = NULL;
    unsigned int    prefixLen           = 0;
    unsigned int    iteratorI,iteratorJ = 0;
    char            out[256]         = {0};
    char            tmp[8]           = {0};
    FILE *fp = NULL;
    int ret =0;

    _ansc_strcpy( globalIP, prefix);

    /* Prepare the first part. */

    prefixLen = _ansc_strlen(globalIP);

    while( (globalIP[prefixLen-1] != '/') && (prefixLen>0) ) prefixLen--;

    if ( prefixLen == 0 ){
        AnscTrace("error, there is not '/' in prefix:%s\n", prefix);
        return 1;
    }

    length = atoi(&globalIP[prefixLen]);

    if ( length > 64 ){
        AnscTrace("error, length is bigger than 64. prefix:%s, length:%d\n", prefix, length);
        return 1;
    }

    globalIP[prefixLen-1] = '\0';

    prefixLen = prefixLen-1;

    if ( (globalIP[prefixLen-1]!=':') && (globalIP[prefixLen-2]!=':') ){
        AnscTrace("error, there is not '::' in prefix:%s\n", prefix);
        return 1;
    }

    iteratorI = prefixLen-2;
    iteratorJ = 0;
    while( iteratorI > 0 ){
        if ( globalIP[iteratorI-1] == ':' )
            iteratorJ++;
        iteratorI--;
    }

    if ( iteratorJ == 3 )
    {
        globalIP[prefixLen-1] = '\0';
        prefixLen = prefixLen - 1;
    }

    AnscTrace("the first part is:%s\n", globalIP);


    /* prepare second part */
    fp = v_secure_popen("r", "ifconfig %s | grep HWaddr\n", intfName );
    if(!fp)
    {
        CcspTraceError(("[%s-%d] failed to opening v_secure_popen pipe !! \n", __FUNCTION__, __LINE__));
    }
    else
    {
        _get_shell_output(fp, out, sizeof(out));
        ret = v_secure_pclose(fp);
        if(ret !=0) {
            CcspTraceError(("[%s-%d] failed to closing  v_secure_pclose pipe ret [%d]!! \n", __FUNCTION__, __LINE__,ret));
        }
    }

    pMac =_ansc_strstr(out, "HWaddr");
    if ( pMac == NULL ){
        AnscTrace("error, this interface has not a mac address .\n");
        return 1;
    }

    pMac += _ansc_strlen("HWaddr");
    while( pMac && (pMac[0] == ' ') )
        pMac++;

    /* switch 7bit to 1*/
    tmp[0] = pMac[1];

    iteratorJ = strtol(tmp, (char **)NULL, 16);

    iteratorJ = iteratorJ ^ 0x2;
    if ( iteratorJ < 10 )
        iteratorJ += '0';
    else
        iteratorJ += 'A' - 10;

    pMac[1] = iteratorJ;
    pMac[17] = '\0';

    //00:50:56: FF:FE:  92:00:22
    _ansc_strncpy(out, pMac, 9);
    out[9] = '\0';
    strncat(out, "FF:FE:",sizeof(out)-1);
    strncat(out, pMac+9,sizeof(out)-1);

    for(iteratorJ=0,iteratorI=0; out[iteratorI]; iteratorI++){
        if ( out[iteratorI] == ':' )
            continue;
        globalIP[prefixLen++] = out[iteratorI];
        if ( ++iteratorJ == 4 ){
           globalIP[prefixLen++] = ':';
           iteratorJ = 0;
        }
    }

    globalIP[prefixLen-1] = '\0';

    AnscTrace("the full part is:%s\n", globalIP);

    _ansc_strncpy(ipAddr, globalIP, sizeof(globalIP) - 1);

    /* This IP should be unique. If not I have no idea. */
    return 0;
}


#define POS_PREFIX_DELEGATION 7
int CalcIPv6Prefix(char *GlobalPref, char *pref,int index)
{
    unsigned char buf[sizeof(struct in6_addr)];
    int domain, s;
    char str[INET6_ADDRSTRLEN];
   domain = AF_INET6;
   s = inet_pton(domain, GlobalPref, buf);
    if (s <= 0) {
        if (s == 0)
            fprintf(stderr, "Not in presentation format");
        else
            perror("inet_pton");
           return 0;
    }
   buf[POS_PREFIX_DELEGATION] = buf[POS_PREFIX_DELEGATION] + index;
   if (inet_ntop(domain, buf, str, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
            return 0;
    }
    printf("%s\n", str);
    strncpy(pref,str,sizeof(str));
    return 1;
}

int GenIPv6Prefix(char *ifName,char *GlobalPref, char *pref)
{
int len = 0;
int index = 0;
char cmd[100];
char out[100];
static int interface_num = 4; // Reserving first 4 /64s for dhcp configurations
    if(ifName == NULL)
    return 0;

    memset(cmd,0,sizeof(cmd));
    memset(out,0,sizeof(out));
    _ansc_sprintf(cmd, "%s%s",ifName,"_ipv6_index");
    sysevent_get(sysevent_fd, sysevent_token,cmd, out, sizeof(out));
    if(strlen(out) != 0)
    {
        index = atoi(out);
    }

    len = strlen(GlobalPref);
    strncpy(pref,GlobalPref, len + 1);
    if(index == 0)
    {
        if(CalcIPv6Prefix(GlobalPref,pref,interface_num)== 0)
        return 0;
        memset(cmd,0,sizeof(cmd));
        snprintf(cmd, sizeof(cmd)-1, "%s%s",ifName,"_ipv6_index");
        _ansc_sprintf(out, "%d",interface_num);
        sysevent_set(sysevent_fd, sysevent_token, cmd, out , 0);
        interface_num++;
    }
    else
    {
        if(CalcIPv6Prefix(GlobalPref,pref,index)==0 )
        return 0;
    }
    strncat(pref,"/64",sizeof("/64"));
        CcspTraceInfo(("%s: pref %s\n", __func__, pref));
return 1;

}
/* This thread is added to handle the LnF interface IPv6 rule, because LnF is coming up late in XB6 devices.
This thread can be generic to handle the operations depending on the interfaces. Other interface and their events can be register here later based on requirement */
static int sysevent_fd_1;
static token_t sysevent_token_1;
static pthread_t InfEvtHandle_tid;
static void *InterfaceEventHandler_thrd(void *data)
{
    UNREFERENCED_PARAMETER(data);
    async_id_t interface_asyncid;
    async_id_t interface_XHS_asyncid;

    CcspTraceWarning(("%s started\n",__FUNCTION__));
    sysevent_fd_1 = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "Interface_evt_handler", &sysevent_token_1);

    sysevent_set_options(sysevent_fd_1, sysevent_token_1, "multinet_6-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd_1, sysevent_token_1, "multinet_6-status",  &interface_asyncid);
    sysevent_set_options(sysevent_fd_1, sysevent_token_1, "multinet_2-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd_1, sysevent_token_1, "multinet_2-status",  &interface_XHS_asyncid);
    FILE *fp = NULL;
    char *Inf_name = NULL;
    int retPsmGet = CCSP_SUCCESS;
    char tbuff[100];
    int err;
    char name[25] = {0}, val[42] = {0},buf[128] = {0},cmd[128] = {0};
    memset(cmd,0,sizeof(cmd));
    memset(buf,0,sizeof(buf));
    _ansc_sprintf(cmd, "multinet_2-status");
    sysevent_get(sysevent_fd, sysevent_token, cmd, buf, sizeof(buf));

    CcspTraceWarning(("%s multinet_2-status is %s\n",__FUNCTION__,buf));

    if(strcmp((const char*)buf, "ready") == 0)
    {
        retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, "dmsb.l2net.2.Port.1.Name", NULL, &Inf_name);
        if (retPsmGet == CCSP_SUCCESS)
        {
            memset(tbuff,0,sizeof(tbuff));
            fp = v_secure_popen("r","sysctl net.ipv6.conf.%s.autoconf",Inf_name);
            _get_shell_output3(fp, tbuff, sizeof(tbuff));
            if(tbuff[strlen(tbuff)-1] == '0')
            {
                enable_IPv6(Inf_name);
            }
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(Inf_name);
            Inf_name = NULL;
        }

    }

    memset(cmd,0,sizeof(cmd));
    memset(buf,0,sizeof(buf));
    while(1)
    {
         async_id_t getnotification_asyncid;
         memset(name,0,sizeof(name));
         memset(val,0,sizeof(val));
         memset(cmd,0,sizeof(cmd));
         memset(buf,0,sizeof(buf));
         int namelen = sizeof(name);
         int vallen  = sizeof(val);
	 int ret = 0;
        err = sysevent_getnotification(sysevent_fd_1, sysevent_token_1, name, &namelen,  val, &vallen, &getnotification_asyncid);

            if (err)
            {
                   CcspTraceWarning(("sysevent_getnotification failed with error: %d %s\n", err,__FUNCTION__));
                   CcspTraceWarning(("sysevent_getnotification failed name: %s val : %s\n", name,val));
            if ( 0 != v_secure_system("pidof syseventd")) {

                       CcspTraceWarning(("%s syseventd not running ,breaking the receive notification loop \n",__FUNCTION__));
                break;
            }
            }
            else
            {

                   CcspTraceWarning(("%s Recieved notification event  %s\n",__FUNCTION__,name));
            if(strcmp((const char*)name,"multinet_6-status") == 0)
            {
                if(strcmp((const char*)val, "ready") == 0)
                {
                                        sysevent_get(sysevent_fd, sysevent_token,"br106_ipaddr_v6", buf, sizeof(buf));
                    ret = v_secure_system("ip -6 route add %s dev br106",buf);
		    if(ret != 0) {
                       CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,ret));
                    }

                    #ifdef _COSA_INTEL_XB3_ARM_
                                        
                   ret = v_secure_system("ip -6 route add %s dev br106 table erouter",buf);
		   if(ret != 0) {
                       CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,ret));
                   }
                       
                    #endif
                                      
                                        v_secure_system("ip -6 rule add iif br106 lookup erouter");
                }

            }
            if(strcmp((const char*)name,"multinet_2-status") == 0)
            {
                if(strcmp((const char*)val, "ready") == 0)
                {
                    Inf_name = NULL;
		    FILE *fp = NULL;
                    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, "dmsb.l2net.2.Port.1.Name", NULL, &Inf_name);
                            if (retPsmGet == CCSP_SUCCESS)
                    {
                        enable_IPv6(Inf_name);
                        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(Inf_name);
                    }
                    else
                    {
                        CcspTraceWarning(("%s PSM get failed for interface name\n", __FUNCTION__));
                    }
                }

            }

        }
    }

}


static int sysevent_fd_global = 0;
static token_t sysevent_token_global;

static void *
dhcpv6c_dbg_thrd(void * in)
{
    UNREFERENCED_PARAMETER(in);
    int fd=0 , fd1=0;
    char msg[1024] = {0};
    int i;
    char * p = NULL;
    char globalIP2[128] = {0};
    char out[128] = {0};
    //When PaM restart, this is to get previous addr.
    sysevent_get(sysevent_fd, sysevent_token,"lan_ipaddr_v6", globalIP2, sizeof(globalIP2));
    if ( globalIP2[0] )
        CcspTraceWarning(("%s  It seems there is old value(%s)\n", __FUNCTION__, globalIP2));

    sysevent_fd_global = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "Multinet Status", &sysevent_token_global);

    CcspTraceWarning(("%s sysevent_fd_global is %d\n", __FUNCTION__, sysevent_fd_global));

    unsigned char lan_multinet_state[16] ;

    int return_val=0;

    fd_set rfds;
    struct timeval tm;

    fd= open(CCSP_COMMON_FIFO, O_RDWR);

    if (fd< 0)
    {
        fprintf(stderr,"open common fifo!!!!!!!!!!!!\n");
        goto EXIT;
    }

    while (1)
    {
    int retCode = 0;
        tm.tv_sec  = 60;
        tm.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        retCode = select( (fd+1), &rfds, NULL, NULL, &tm);
        /* When return -1, it's error.
           When return 0, it's timeout
           When return >0, it's the number of valid fds */
        if (retCode < 0) {
        fprintf(stderr, "dbg_thrd : select returns error \n" );

            if (errno == EINTR)
                continue;

            CcspTraceWarning(("%s -- select(): %s", __FUNCTION__, strerror(errno)));
            goto EXIT;
        }
    else if(retCode == 0 )
        continue;
        if ( FD_ISSET(fd, &rfds) )
        {
         memset(msg, 0, sizeof(msg));
             read(fd, msg, sizeof(msg));

        }
    else
        continue;

        if (msg[0] != 0)
        {
            CcspTraceInfo(("%s: get message %s\n", __func__, msg));
        } else {
        //Message is empty. Wait 5 sec before trying the select again.
            sleep(5);
            continue;
        }

        if (!strncmp(msg, "dibbler-client", strlen("dibbler-client")))
        {
            char v6addr[64] = {0};
            char v6pref[128] = {0};
            char v6pref_addr[128] = {0};
            char v6Tpref[128] = {0};
            int pref_len = 0;

            char iana_t1[32]    = {0};
            char iana_t2[32]    = {0};
            char iana_iaid[32]  = {0};
            char iana_pretm[32] = {0};
            char iana_vldtm[32] = {0};

            char iapd_t1[32]    = {0};
            char iapd_t2[32]    = {0};
            char iapd_iaid[32]  = {0};
            char iapd_pretm[32] = {0};
            char iapd_vldtm[32] = {0};

            int t1 = 0;
            int idx = 0;
            char action[64] = {0};
            char objName[128] = {0};
            char globalIP[128] = {0};
            BOOL bRestartLan = FALSE;
            BOOL bRestartFirewall = FALSE;
            int  ret = 0;
#ifdef _HUB4_PRODUCT_REQ_
            char ula_address[64] = {0};
#endif
            /*the format is :
             add 2000::ba7a:1ed4:99ea:cd9f :: 0 t1
             action, address, prefix, pref_len 3600
            now action only supports "add", "del"*/

            p = msg+strlen("dibbler-client");
            while(isblank(*p)) p++;

            fprintf(stderr, "%s -- %d !!! get event from v6 client: %s \n", __FUNCTION__, __LINE__,p);

            if (sscanf(p, "%63s %63s %31s %31s %31s %31s %31s %63s %d %31s %31s %31s %31s %31s",
                       action, v6addr,    iana_iaid, iana_t1, iana_t2, iana_pretm, iana_vldtm,
                       v6pref, &pref_len, iapd_iaid, iapd_t1, iapd_t2, iapd_pretm, iapd_vldtm ) <= 14)
            {
                if (!strncmp(action, "add", 3))
                {
                    CcspTraceInfo(("%s: add\n", __func__));

// Waiting until private lan interface is ready , so that we can assign global ipv6 address and also start dhcp server.
            while (1)
            {

                    memset(lan_multinet_state,0,sizeof(lan_multinet_state));
                            return_val=sysevent_get(sysevent_fd_global, sysevent_token_global, "multinet_1-status", lan_multinet_state, sizeof(lan_multinet_state));

                            CcspTraceWarning(("%s multinet_1-status is %s, ret val is %d\n",__FUNCTION__,lan_multinet_state,return_val));

                if(strcmp((const char*)lan_multinet_state, "ready") == 0)
                {
                    break;
                }

                sleep(5);
              }

                    /*for now we only support one address, one prefix notify, if need multiple addr/prefix, must modify dibbler-client code*/
                    if (strncmp(v6addr, "::", 2) != 0 && strcmp(v6addr, "''") != 0)
                    {
                        if (strncmp(v6addr, "''", 2) == 0)
                        {
                            sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_ADDR_SYSEVENT_NAME, "" , 0);
                        }
                        else
                        {
                            sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_ADDR_SYSEVENT_NAME, v6addr , 0);
                        }
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_ADDR_IAID_SYSEVENT_NAME,  iana_iaid , 0);
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_ADDR_T1_SYSEVENT_NAME,    iana_t1 , 0);
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_ADDR_T2_SYSEVENT_NAME,    iana_t2 , 0);
                        if (format_time(iana_pretm) == 0 && format_time(iana_vldtm) == 0) 
                        {
                            CcspTraceInfo(("%s : Going to trim ' from preferred and valid lifetime, values are %s %s\n",__FUNCTION__,iana_pretm,iana_vldtm));
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_ADDR_PRETM_SYSEVENT_NAME, iana_pretm , 0);
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_ADDR_VLDTM_SYSEVENT_NAME, iana_vldtm , 0);
                        }
                    }

                    if (strncmp(v6pref, "::", 2) != 0 && strcmp(v6pref, "''") != 0)
                    {
            memset(v6Tpref,0,sizeof(v6Tpref));
            strncpy(v6Tpref,v6pref,sizeof(v6Tpref));
                        /*We just delegate longer and equal 64bits. Use zero to fill in the slot naturally. */
#if defined (MULTILAN_FEATURE)
                        sprintf(v6pref+strlen(v6pref), "/%d", pref_len);
#else
            if ( pref_len >= 64 )
                            sprintf(v6pref+strlen(v6pref), "/%d", pref_len);
                        else
                        {
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) || defined(_ONESTACK_PRODUCT_REQ_)
    #if defined(_ONESTACK_PRODUCT_REQ_)
    if (isFeatureSupportedInCurrentMode(FEATURE_IPV6_DELEGATION))
    #endif
    {
                            sprintf(v6pref+strlen(v6pref), "/%d", pref_len);
    }
#endif
#if !defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) || defined(_ONESTACK_PRODUCT_REQ_)
    #if defined(_ONESTACK_PRODUCT_REQ_)
    if (!isFeatureSupportedInCurrentMode(FEATURE_IPV6_DELEGATION))
    #endif
    {
                            sprintf(v6pref+strlen(v6pref), "/%d", 64);
    }
#endif
                        }
#endif
    char cmd[100];
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && \
    defined(_CBR_PRODUCT_REQ_) && \
    !defined(_ONESTACK_PRODUCT_REQ_)
#else

#ifdef _ONESTACK_PRODUCT_REQ_
    if (!isFeatureSupportedInCurrentMode(FEATURE_IPV6_DELEGATION))
#endif
    {
            char out1[100];
            char *token = NULL;char *pt;
            char s[2] = ",";
	    FILE *fp = NULL;
            char interface_name[32] = {0};
            char ipv6_addr[100]= {0};
            if(pref_len < 64)
            {
                memset(out,0,sizeof(out));
                memset(out1,0,sizeof(out1));
                fp = v_secure_popen("r", "syscfg get IPv6subPrefix");
		if(!fp)
                {
                     CcspTraceError(("[%s-%d] failed to opening v_secure_popen pipe !! \n", __FUNCTION__, __LINE__));
                }
                else
                {
                    _get_shell_output(fp, out, sizeof(out));
                    ret = v_secure_pclose(fp);
                    if(ret !=0) {
                        CcspTraceError(("[%s-%d] failed to closing  v_secure_pclose pipe ret [%d]!! \n", __FUNCTION__, __LINE__,ret));
                    }
                }

                if(!strcmp(out,"true"))
                {
                                static int first = 0;

                memset(out,0,sizeof(out));
                fp = v_secure_popen("r", "syscfg get IPv6_Interface");
		if(!fp)
                {
                     CcspTraceError(("[%s-%d] failed to opening v_secure_popen pipe !! \n", __FUNCTION__, __LINE__));
                }
                else
                {
                    _get_shell_output(fp, out, sizeof(out));
		    ret = v_secure_pclose(fp);
                    if(ret !=0) {
                        CcspTraceError(("[%s-%d] failed to closing  v_secure_pclose pipe ret [%d]!! \n", __FUNCTION__, __LINE__,ret));
                    }
                }

                pt = out;
                while((token = strtok_r(pt, ",", &pt)))
                 {

                    if(GenIPv6Prefix(token,v6Tpref,out1))
                    {
                        char tbuff[100];
                        memset(cmd,0,sizeof(cmd));
                        _ansc_sprintf(cmd, "%s%s",token,"_ipaddr_v6");
                        memset(interface_name,0,sizeof(interface_name));
                        strncpy(interface_name,token,sizeof(interface_name)-1);
                        _ansc_sprintf(cmd, "%s%s",interface_name,"_ipaddr_v6");
		                sysevent_get(sysevent_fd, sysevent_token, "brlan1_ipaddr_v6", GUEST_PREVIOUS_IP, sizeof(GUEST_PREVIOUS_IP));
                        sysevent_set(sysevent_fd, sysevent_token, cmd, out1 , 0);
                        enable_IPv6(interface_name);
                        memset(out1,0,sizeof(out1));
                    }
                }
                                        memset(out,0,sizeof(out));
                                        if(first == 0)
                                        {       first = 1;
                                                pthread_create(&InfEvtHandle_tid, NULL, InterfaceEventHandler_thrd, NULL);
                                        }
                }
            }
    }
#endif
            char previous_v6pref[128] = {0};
            sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix", previous_v6pref, sizeof(previous_v6pref));
            if (strcmp(previous_v6pref, "") != 0  && strcmp(previous_v6pref, v6pref) != 0) {
                CcspTraceInfo(("%s : New prefix obtained from operator network - setting current prefix %s as previous one\n",__FUNCTION__,previous_v6pref));
                sysevent_set(sysevent_fd, sysevent_token, "previous_ipv6_prefix", previous_v6pref, 0);
                sysevent_set(sysevent_fd, sysevent_token, "previous_ipv6_prefix_vldtime", "0", 0); // Set valid lifetime for deprecated prefix
                bRestartFirewall = TRUE;
            }
            else if (strcmp(previous_v6pref,"") == 0) {
                sysevent_get(sysevent_fd, sysevent_token,"previous_ipv6_prefix", previous_v6pref, sizeof(previous_v6pref));
                if (strcmp(previous_v6pref, "") != 0 && strcmp(previous_v6pref, v6pref) == 0) {
                    CcspTraceInfo(("%s : Renewal for prefix %s obtained from operator network - setting prefix %s as current one.\n",__FUNCTION__, v6pref, previous_v6pref));
                    sysevent_set(sysevent_fd, sysevent_token, "previous_ipv6_prefix", "", 0);
                    sysevent_set(sysevent_fd, sysevent_token, "previous_ipv6_prefix_vldtime", "0", 0);
		    set_syscfg("prev_ip6prefix", v6pref);
                    bRestartFirewall = TRUE;
                }
            }

     	    set_syscfg("prev_ip6prefix", v6pref);

            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6C_PREF_SYSEVENT_NAME, v6pref , 0);
            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6C_PREF_IAID_SYSEVENT_NAME,  iapd_iaid , 0);
            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6C_PREF_IAID_SYSEVENT_NAME,  iapd_iaid , 0);
            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6C_PREF_T1_SYSEVENT_NAME,    iapd_t1 , 0);
            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6C_PREF_T2_SYSEVENT_NAME,    iapd_t2 , 0);
            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6C_PREF_PRETM_SYSEVENT_NAME, iapd_pretm , 0);
            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6C_PREF_VLDTM_SYSEVENT_NAME, iapd_vldtm , 0);
            if (format_time(iapd_pretm) == 0 && format_time(iapd_vldtm) == 0) {
                CcspTraceInfo(("%s : Going to trim ' from preferred and valid lifetime, values are %s %s\n",__FUNCTION__,iapd_pretm,iapd_vldtm));
            }
            sysevent_set(sysevent_fd, sysevent_token, "ipv6_prefix_prdtime", iapd_pretm, 0);
            sysevent_set(sysevent_fd, sysevent_token, "ipv6_prefix_vldtime", iapd_vldtm, 0);
            set_syscfg("prev_ip6prefix_vldtime", iapd_vldtm);


#if defined (MULTILAN_FEATURE)
                        if ((v6addr_prev[0] == '\0') || ( _ansc_strcmp(v6addr_prev, v6pref ) !=0))
                        {
                            _ansc_strncpy( v6addr_prev, v6pref, sizeof(v6pref));
                            sysevent_set(sysevent_fd, sysevent_token,"ipv6-restart", "1", 0);
                        }
                        else
                        {
                            sysevent_set(sysevent_fd, sysevent_token,"ipv6_addr-set", "", 0);
                        }
#endif

#ifdef MULTILAN_FEATURE
/* Service IPv6 will assign IP address and prefix allocation,
   for all lan interfaces.
*/
#if !defined(INTEL_PUMA7) && !defined(_COSA_INTEL_XB3_ARM_)
                        // not the best place to add route, just to make it work
                        // delegated prefix need to route to LAN interface
                        ret = v_secure_system( "ip -6 route add %s dev %s proto dhcp", v6pref, COSA_DML_DHCPV6_SERVER_IFNAME);
                        if(ret != 0) {
                            CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__, ret));
                        }

            #ifdef _COSA_INTEL_XB3_ARM_
                        ret = v_secure_system("ip -6 route add %s dev " COSA_DML_DHCPV6_SERVER_IFNAME " table erouter",v6pref);
			if(ret != 0) {
                             CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__, ret));
                        }

            #endif
            
                        /* we need save this for zebra to send RA
                           ipv6_prefix           // xx:xx::/yy
                         */
                        
                        ret = v_secure_system("sysevent set ipv6_prefix %s \n",v6pref);
			if(ret != 0) {
                            CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__, ret));
                        }

                        CcspTraceWarning(("!run cmd1:sysevent set ipv6_prefix %s \n",v6pref));

                        DHCPv6sDmlTriggerRestart(FALSE);
#if defined(_COSA_BCM_ARM_) || defined(INTEL_PUMA7) || defined(_COSA_QCA_ARM_)
                        CcspTraceWarning((" %s dhcpv6_assign_global_ip to brlan0 \n", __FUNCTION__));
                        ret = dhcpv6_assign_global_ip(v6pref, "brlan0", globalIP);
#elif defined _COSA_BCM_MIPS_
                        ret = dhcpv6_assign_global_ip(v6pref, COSA_DML_DHCPV6_SERVER_IFNAME, globalIP);
#else
                        /*We need get a global ip addres */
                        ret = dhcpv6_assign_global_ip(v6pref, "l2sd0", globalIP);
#endif
                        CcspTraceWarning(("%s: globalIP %s globalIP2 %s\n", __func__,
                            globalIP, globalIP2));
                        if ( _ansc_strcmp(globalIP, globalIP2 ) ){
                            bRestartLan = TRUE;

                            //PaM may restart. When this happen, we should not overwrite previous ipv6
                            if ( globalIP2[0] )
                            {
                               sysevent_set(sysevent_fd, sysevent_token,"lan_ipaddr_v6_prev", globalIP2, 0);
                               sysevent_set(sysevent_fd, sysevent_token,"sendImmediateRA", "true", 0);
                            }

                            _ansc_strcpy(globalIP2, globalIP);
                        }else{
                                char lanrestart[8] = {0};
                                sysevent_get(sysevent_fd, sysevent_token,"lan_restarted",lanrestart, sizeof(lanrestart));
                                fprintf(stderr,"lan restart staus is %s \n",lanrestart);
                                      if (strcmp("true",lanrestart) == 0)
                                    bRestartLan = TRUE;
                                else
                                    bRestartLan = FALSE;
                        }
                        CcspTraceWarning(("%s: bRestartLan %d\n", __func__, bRestartLan));

                        fprintf(stderr, "%s -- %d !!! ret:%d bRestartLan:%d %s %s \n", __FUNCTION__, __LINE__,ret,  bRestartLan,  globalIP, globalIP2);

                        if ( ret != 0 )
                        {
                            AnscTrace("error, assign global ip error.\n");
                        }else if ( bRestartLan == FALSE ){
                            AnscTrace("Same global IP, Need not restart.\n");
                        }else{
                            /* This is for IP.Interface.1. use */
                            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6S_ADDR_SYSEVENT_NAME, globalIP, 0);

                            /*This is for brlan0 interface */
                            sysevent_set(sysevent_fd, sysevent_token,"lan_ipaddr_v6", globalIP, 0);
                            _ansc_sprintf(cmd, "%d", pref_len);
                            sysevent_set(sysevent_fd, sysevent_token,"lan_prefix_v6", cmd, 0);

                            sysevent_set(sysevent_fd, sysevent_token,"lan-restart", "1", 0);
                        }
#endif
#else
#ifdef _HUB4_PRODUCT_REQ_
                        if ((iapd_vldtm[0]=='\0') || (iapd_pretm[0]=='\0')){
                            strncpy(iapd_pretm, "forever", sizeof(iapd_pretm));
                            strncpy(iapd_vldtm, "forever", sizeof(iapd_vldtm));
                        }
                        sysevent_get(sysevent_fd, sysevent_token,SYSEVENT_FIELD_IPV6_ULA_ADDRESS, ula_address, sizeof(ula_address));
                        if(ula_address[0] != '\0') {
                            ret = v_secure_system("ip -6 addr add %s/64 dev "COSA_DML_DHCPV6_SERVER_IFNAME,ula_address);
                            if(ret != 0) {
                                CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,ret));
                            }
                        }
                        ret = dhcpv6_assign_global_ip(v6pref, COSA_DML_DHCPV6_SERVER_IFNAME, globalIP);
                        if(ret != 0) {
                            CcspTraceInfo(("Assign global ip error \n"));
                        }
                        else {
                            sysevent_set(sysevent_fd, sysevent_token,"lan_ipaddr_v6", globalIP, 0);
                            CcspTraceInfo(("Going to execute: ip -6 addr add %s/64 dev %s valid_lft %s preferred_lft %s",
                                globalIP, COSA_DML_DHCPV6_SERVER_IFNAME, iapd_vldtm, iapd_pretm));
                            ret = v_secure_system("ip -6 addr add %s/64 dev " COSA_DML_DHCPV6_SERVER_IFNAME " valid_lft %s preferred_lft %s",globalIP,iapd_vldtm, iapd_pretm);
			    if(ret != 0) {
                                CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,ret));
                            }
                        }
                        if(strlen(v6pref) > 0) {
                            strncpy(v6pref_addr, v6pref, (strlen(v6pref)-5));
                            CcspTraceInfo(("Going to set ::1 address on brlan0 interface \n"));
                            CcspTraceInfo(("Going to execute: ip -6 addr add %s::1/64 dev %s valid_lft %s preferred_lft %s",
                                v6pref_addr, COSA_DML_DHCPV6_SERVER_IFNAME, iapd_vldtm, iapd_pretm));
                            ret = v_secure_system("ip -6 addr add %s::1/64 dev " COSA_DML_DHCPV6_SERVER_IFNAME " valid_lft %s preferred_lft %s",v6pref_addr,iapd_vldtm, iapd_pretm);
			    if(ret != 0) {
                                CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,ret));
                            }   
                        }
                        // send an event to Sky-pro app manager that Global-prefix is set
                        sysevent_set(sysevent_fd, sysevent_token,"lan_prefix_set", globalIP, 0);
                        /**
                        * Send data to wanmanager.
                        */
                        int ipv6_wan_status = 0;
                        char dns_server[256] = {'\0'};
                        unsigned int prefix_pref_time = 0;
                        unsigned int prefix_valid_time = 0;
                        char c;
                        DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_GetVirtualIfaceByName_locked(PHY_WAN_IF_NAME);
                        if(p_VirtIf != NULL)
                        {
                            if(p_VirtIf->IP.pIpcIpv6Data == NULL)
                            {
                                p_VirtIf->IP.pIpcIpv6Data = (ipc_dhcpv6_data_t*) malloc(sizeof(ipc_dhcpv6_data_t));
                                if(p_VirtIf->IP.pIpcIpv6Data != NULL)
                                {
                                    strncpy(p_VirtIf->IP.pIpcIpv6Data->ifname, p_VirtIf->Name, sizeof(p_VirtIf->IP.pIpcIpv6Data->ifname));
                                    if(strlen(v6pref) == 0)
                                    {
                                        p_VirtIf->IP.pIpcIpv6Data->isExpired = TRUE;
                                    }
                                    else
                                    {
                                        p_VirtIf->IP.pIpcIpv6Data->isExpired = FALSE;
                                        p_VirtIf->IP.pIpcIpv6Data->prefixAssigned = TRUE;
                                        strncpy(p_VirtIf->IP.pIpcIpv6Data->sitePrefix, v6pref, sizeof(p_VirtIf->IP.pIpcIpv6Data->sitePrefix));
                                        strncpy(p_VirtIf->IP.pIpcIpv6Data->pdIfAddress, "", sizeof(p_VirtIf->IP.pIpcIpv6Data->pdIfAddress));
                                        /** DNS servers. **/
                                        sysevent_get(sysevent_fd, sysevent_token,SYSEVENT_FIELD_IPV6_DNS_SERVER, dns_server, sizeof(dns_server));
                                        if (strlen(dns_server) != 0)
                                        {
                                            p_VirtIf->IP.pIpcIpv6Data->dnsAssigned = TRUE;
                                            sscanf (dns_server, "%s %s", p_VirtIf->IP.pIpcIpv6Data->nameserver,
                                                                         p_VirtIf->IP.pIpcIpv6Data->nameserver1);
                                        }
                                        sscanf(iapd_pretm, "%c%u%c", &c, &prefix_pref_time, &c);
                                        sscanf(iapd_vldtm, "%c%u%c", &c, &prefix_valid_time, &c);
                                        p_VirtIf->IP.pIpcIpv6Data->prefixPltime = prefix_pref_time;
                                        p_VirtIf->IP.pIpcIpv6Data->prefixVltime = prefix_valid_time;
                                        p_VirtIf->IP.pIpcIpv6Data->maptAssigned = FALSE;
                                        p_VirtIf->IP.pIpcIpv6Data->mapeAssigned = FALSE;
                                        p_VirtIf->IP.pIpcIpv6Data->prefixCmd = 0;
                                    }
                                    if (wanmgr_handle_dhcpv6_event_data(p_VirtIf) != ANSC_STATUS_SUCCESS)
                                    {
                                        CcspTraceError(("[%s-%d] Failed to send dhcpv6 data to wanmanager!!! \n", __FUNCTION__, __LINE__));
                                    }
                                }
                            }
                            WanMgr_VirtualIfaceData_release(p_VirtIf);
                        }
#endif
                        // not the best place to add route, just to make it work
                        // delegated prefix need to route to LAN interface
                        ret = v_secure_system("ip -6 route add %s dev %s proto dhcp", v6pref, COSA_DML_DHCPV6_SERVER_IFNAME);
			if(ret != 0) {
                            CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,ret));
                        }     
            #ifdef _COSA_INTEL_XB3_ARM_
            
                        ret = v_secure_system("ip -6 route add %s dev "COSA_DML_DHCPV6_SERVER_IFNAME " table erouter");
			if(ret != 0) {
                           CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,ret));
                        }   
            #endif
                        /* we need save this for zebra to send RA
                           ipv6_prefix           // xx:xx::/yy
                         */
#ifndef _HUB4_PRODUCT_REQ_
                      
                        ret = v_secure_system("sysevent set ipv6_prefix %s \n",v6pref);
			if(ret != 0) {
                            CcspTraceWarning(("%s: Failure in executing command via v_secure_system. ret:[%d] \n",__FUNCTION__,ret));
                        }
#else
#ifdef LAN_MGR_SUPPORT
                        v_secure_system("sysevent set dhcpv6_raserver-restart");
#else
                        v_secure_system("sysevent set zebra-restart \n");
#endif
#endif
                        //CcspTraceWarning(("!run cmd1:%s", cmd));

                        DHCPv6sDmlTriggerRestart(FALSE);

                        /*We need get a global ip addres */
#if defined(_COSA_BCM_ARM_) || defined(INTEL_PUMA7) || defined(_COSA_QCA_ARM_)
                        /*this is for tchxb6*/
                        CcspTraceWarning((" %s dhcpv6_assign_global_ip to brlan0 \n", __FUNCTION__));
                        ret = dhcpv6_assign_global_ip(v6pref, "brlan0", globalIP);
#elif defined _COSA_BCM_MIPS_
                        ret = dhcpv6_assign_global_ip(v6pref, COSA_DML_DHCPV6_SERVER_IFNAME, globalIP);
#else
                        ret = dhcpv6_assign_global_ip(v6pref, "l2sd0", globalIP);
#endif
                        CcspTraceWarning(("%s: globalIP %s globalIP2 %s\n", __func__,
                            globalIP, globalIP2));
                        if ( _ansc_strcmp(globalIP, globalIP2 ) ){
                            bRestartLan = TRUE;

                            //PaM may restart. When this happen, we should not overwrite previous ipv6
                            if ( globalIP2[0] )
                            {
                                sysevent_set(sysevent_fd, sysevent_token,"sendImmediateRA", "true", 0);
                               sysevent_set(sysevent_fd, sysevent_token,"lan_ipaddr_v6_prev", globalIP2, 0);
                            }

                            _ansc_strcpy(globalIP2, globalIP);
                        }else{
                char lanrestart[8] = {0};
                    sysevent_get(sysevent_fd, sysevent_token,"lan_restarted",lanrestart, sizeof(lanrestart));
                fprintf(stderr,"lan restart staus is %s \n",lanrestart);
                   if (strcmp("true",lanrestart) == 0)
                    bRestartLan = TRUE;
                    else
                                bRestartLan = FALSE;
            }
                        CcspTraceWarning(("%s: bRestartLan %d\n", __func__, bRestartLan));

                        fprintf(stderr, "%s -- %d !!! ret:%d bRestartLan:%d %s %s \n", __FUNCTION__, __LINE__,ret,  bRestartLan,  globalIP, globalIP2);

                        if ( ret != 0 )
                        {
                            AnscTrace("error, assign global ip error.\n");
                        }else if ( bRestartLan == FALSE ){
                            AnscTrace("Same global IP, Need not restart.\n");
                        }else{
                            char string[MAXCHAR];
                            memset(string,0,MAXCHAR);
                            sysevent_get(sysevent_fd, sysevent_token, "lan_ipaddr_v6", string, sizeof(string));
                            /* This is for IP.Interface.1. use */
                            sysevent_set(sysevent_fd, sysevent_token,COSA_DML_DHCPV6S_ADDR_SYSEVENT_NAME, globalIP, 0);

                            /*This is for brlan0 interface */
                            sysevent_set(sysevent_fd, sysevent_token,"lan_ipaddr_v6", globalIP, 0);
                            _ansc_sprintf(cmd, "%d", pref_len);
                            sysevent_set(sysevent_fd, sysevent_token,"lan_prefix_v6", cmd, 0);

                            sysevent_set(sysevent_fd, sysevent_token,"lan-restart", "1", 0);
                           char line[MAXCHAR];
                           char hostname[MAXCHAR];
                           FILE *fp = fopen(HOSTS,"r");
                           FILE *tp = fopen(TEMP_HOST,"w");
                           if (!fp)
                               goto EXIT;
                           memset(line,0,MAXCHAR);
                           memset(hostname,0,MAXCHAR);
                           syscfg_get(NULL, "hostname", hostname, sizeof(hostname));
                           if(string[0]!= '\0'){
                               while ( fgets( line, MAXCHAR, fp ) != NULL )
                               {
                                   if(strstr(line, string ) == NULL )
                                       fprintf(tp,"%s",line );
                               }
                               fflush(tp);
                               fclose(fp);
                               fclose(tp);
                               fp = fopen(HOSTS,"w");
                               tp = fopen(TEMP_HOST,"r");
                               memset(line,0,MAXCHAR);
                               while ( fgets( line, MAXCHAR, tp ) != NULL )
                               {
                                   fprintf(fp,"%s",line );
                                   memset(line,0,MAXCHAR);
                               }
                               fflush(fp);
                               fclose(fp);
                               fclose(tp);
                               unlink(TEMP_HOST);
                            }
                           FILE *fpp = fopen(HOSTS,"a+");
                           if (!fpp)
                                goto EXIT;
                            fprintf(fpp,"%s      %s\n", globalIP,hostname);
                            fclose(fpp);
                            v_secure_system("killall -HUP dnsmasq");
                            v_secure_system("systemctl restart CcspWebUI.service");
                        }
#endif
                    }
                }
                else if (!strncmp(action, "del", 3))
                {
                    /*todo*/
                    CcspTraceInfo(("%s: del\n", __func__));
                    char previous_v6pref[128] = {0};
                    char current_pref[128] = {0};
                    char buf[128] = {0};
                    char guest_globalIP[128] = {0};
		    int ret = 0;
                    strcpy(buf, v6pref);
                    if ( pref_len >= 64 )
                        sprintf(v6pref+strlen(v6pref), "/%d", pref_len);
                    else {
                        pref_len = 64;
                        sprintf(v6pref+strlen(v6pref), "/%d", pref_len);
                    }
                    sysevent_get(sysevent_fd, sysevent_token, "previous_ipv6_prefix", previous_v6pref, sizeof(previous_v6pref));
                    sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix", current_pref, sizeof(current_pref));
                    if (strcmp(previous_v6pref, "") != 0 && strcmp(previous_v6pref, v6pref) == 0) { // Previous prefix expiry occurred
                        CcspTraceInfo(("%s : Previous prefix %s got expired. Removing it from the bridge.\n", __FUNCTION__ , previous_v6pref));
                        sysevent_set(sysevent_fd, sysevent_token, "previous_ipv6_prefix", "", 0);
                        sysevent_set(sysevent_fd, sysevent_token, "previous_ipv6_prefix_vldtime", "0", 0);
                        bRestartFirewall = TRUE;
                        CcspTraceInfo(("%s : Command ip -6 addr del %s1/%d dev brlan0 executed\n", __FUNCTION__,buf, pref_len));
                        ret = v_secure_system("ip -6 addr del %s1/%d dev brlan0", buf, pref_len);
			if(ret !=0)
			{
				CcspTraceWarning("Failed in executing the command via v_secure_system ret val %d \n",ret);
			}
                        memset(buf,0,sizeof(buf));
                        sysevent_get(sysevent_fd, sysevent_token,"brlan1_previous_ipaddr_v6", buf, sizeof(buf));
                        v_secure_system("ip -6 addr del %s dev brlan1 valid_lft forever preferred_lft forever", buf);
                        
                    }
                    else if (strcmp(current_pref, "") != 0 && strcmp(current_pref,v6pref) == 0) { // current prefix expiry occurred
                        CcspTraceInfo(("%s : Current prefix %s got expired. Setting it as previous one.\n", __FUNCTION__ , v6pref));
                        sysevent_set(sysevent_fd, sysevent_token, "previous_ipv6_prefix", v6pref, 0);
                        sysevent_set(sysevent_fd, sysevent_token, "previous_ipv6_prefix_vldtime", "0", 0);
			set_syscfg("prev_ip6prefix", v6pref);
                        bRestartFirewall = TRUE;
                        strcpy(v6pref, "");
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_PREF_SYSEVENT_NAME,       v6pref, 0);
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_PREF_IAID_SYSEVENT_NAME,  iapd_iaid, 0);
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_PREF_T1_SYSEVENT_NAME,    iapd_t1, 0);
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_PREF_T2_SYSEVENT_NAME,    iapd_t2, 0);
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_PREF_PRETM_SYSEVENT_NAME, iapd_pretm, 0);
                        sysevent_set(sysevent_fd, sysevent_token, COSA_DML_DHCPV6C_PREF_VLDTM_SYSEVENT_NAME, iapd_vldtm, 0);
                        if (format_time(iapd_pretm) == 0 && format_time(iapd_vldtm) == 0) {
                            CcspTraceInfo(("%s : Going to trim ' from preferred and valid lifetime, values are %s %s\n",__FUNCTION__,iapd_pretm,iapd_vldtm));
                        }
                        sysevent_set(sysevent_fd, sysevent_token, "ipv6_prefix_prdtime", iapd_pretm, 0);
                        sysevent_set(sysevent_fd, sysevent_token, "ipv6_prefix_vldtime", iapd_vldtm, 0);
                        sysevent_set(sysevent_fd, sysevent_token, "ipv6_prefix", v6pref, 0);
                        sysevent_get(sysevent_fd, sysevent_token, "brlan1_IPv6_prefix", GUEST_PREVIOUS_PREFIX, sizeof(GUEST_PREVIOUS_PREFIX));
                        brlan1_prefix_changed = 1;
                        sysevent_set(sysevent_fd, sysevent_token, "brlan1_IPv6_prefix", v6pref, 0);
                        memset(buf,0,sizeof(buf));
                        sysevent_get(sysevent_fd, sysevent_token,"brlan1_previous_ipaddr_v6", buf, sizeof(buf));
                        v_secure_system("ip -6 addr del %s dev brlan1 valid_lft forever preferred_lft forever", buf);
                    }
                }
                if (bRestartFirewall) { // Needs firewall restart as deprecation of prefix occurred
                    v_secure_system("sysevent set firewall-restart");
                    bRestartFirewall = FALSE;
                }
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && \
    (defined(_CBR_PRODUCT_REQ_) || defined(_BCI_FEATURE_REQ_)) && \
    !defined(_ONESTACK_PRODUCT_REQ_)

#else
#ifdef _ONESTACK_PRODUCT_REQ_
    if (!isFeatureSupportedInCurrentMode(FEATURE_IPV6_DELEGATION))
#endif
    {
#ifdef LAN_MGR_SUPPORT
        v_secure_system("sysevent set dhcpv6_raserver-restart");
#else
        v_secure_system("sysevent set zebra-restart");
#endif
    }
#endif
            }

        }
#ifdef _DEBUG
        else if (!strncmp(msg, "mem", 3))
        {
            /*add the test funcs in the run time.*/

            AnscTraceMemoryTable();
        }
#endif
    }

EXIT:
    if(fd>=0) {
        close(fd);
    }

    if(fd1>=0) {
        close(fd1);
    }

    return NULL;
}

static void *
rtadv_dbg_thread(void * in)
{
    int fd = 0;
    char msg[64] = {0};
    char *buf = NULL;
    fd_set rfds;
    char prev_Mflag_val = '-';
    char temp[5] = {0};
    /* Message format written to the FIFO by ipv6rtmon daemon would be either one of the below :
             "ra-flags 0 0"
             "ra-flags 0 1"
             "ra-flags 1 0"
       Possible values for managedFlag and otherFlag set by the daemon will ONLY be 0 or 1 and no other positive values.
    */
    desiredRtAdvInfo rtAdvInfo = {'\0', '\0'};
    const size_t ra_flags_len = 13; /* size of ra_flags message including terminating character */
    fd = open(RA_COMMON_FIFO, O_RDWR);
    if (fd < 0)
    {
        CcspTraceError(("%s : Open failed for fifo file %s due to error %s.\n", __FUNCTION__, RA_COMMON_FIFO, strerror(errno)));
        goto EXIT;
    }
    v_secure_system(IPv6_RT_MON_NOTIFY_CMD); /* SIGUSR1 for ipv6rtmon daemon upon creation of FIFO file from the thread. */
    CcspTraceInfo(("%s : Inside %s %d\n", __FUNCTION__, __FUNCTION__, fd));

    while (1)
    {
        int retCode = 0;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        retCode = select(fd+1, &rfds, NULL, NULL, NULL);

        if (retCode < 0) {

            if (errno == EINTR)
                continue;

            CcspTraceError(("%s -- select() returns error %s.\n", __FUNCTION__, strerror(errno)));
            goto EXIT;
        }
        else if (retCode == 0)
            continue;

        if (FD_ISSET(fd, &rfds))
        {
            size_t ofst = 0;
            memset(msg, 0, sizeof(msg));
            while (ofst < ra_flags_len) {
                ssize_t ret = read(fd, &msg[ofst], ra_flags_len - ofst);
                if (ret < 0) {
                    CcspTraceError(("%s : read() returned error %s after already reading %zu. Ignoring the message...\n", __FUNCTION__, strerror(errno), ret));
                    continue;
                }
                ofst += ret;
            }
        }
        else
            continue;

        if (!strncmp(msg, "ra-flags", strlen("ra-flags"))) /*Ensure that message has "ra-flags" as the first substring. */
        {
            CcspTraceInfo(("%s: get message %s\n", __func__, msg));
            memset(&rtAdvInfo, '\0', sizeof(rtAdvInfo));
            int needEnable = 0;
            buf = msg + strlen("ra-flags");
            while (isblank(*buf))
                buf++;

            memset(temp, 0, sizeof(temp));
            if ((syscfg_get(NULL, "tr_dhcpv6c_enabled", temp, sizeof(temp)) == 0) && (!strcmp(temp, "1")))
                needEnable = 1;

            if (sscanf(buf, "%c %c", &rtAdvInfo.managedFlag, &rtAdvInfo.otherFlag)) { /* Possible managedFlag and otherFlag values will be either 0 or 1 only. */
                if (needDibblerRestart) {
                    prev_Mflag_val = '-';
                    needDibblerRestart = FALSE;
                }
                if (prev_Mflag_val == rtAdvInfo.managedFlag)
                    continue;
                prev_Mflag_val = rtAdvInfo.managedFlag;
                g_SetParamValueBool("Device.DHCPv6.Client.1.Enable", false); /* disable client before setting Address or Prefix DM. */
                g_SetParamValueBool("Device.DHCPv6.Client.1.RequestAddresses", (rtAdvInfo.managedFlag == '1'));
                g_SetParamValueBool("Device.DHCPv6.Client.1.RequestPrefixes", ((rtAdvInfo.managedFlag == '1') || (rtAdvInfo.otherFlag == '1')));
                g_SetParamValueBool("Device.DHCPv6.Client.1.Enable", (needEnable == 1)); /* start dibbler-client if syscfg 'tr_dhcpv6c_enabled' is true. */
            }
        }
    }
EXIT:
    if (fd >= 0) {
        close(fd);
    }

    return NULL;
}


/* DHCPV4 APIs  */
void Enable_CaptivePortal(BOOL enable)
{
    if( enable == TRUE )
    {
        if ( syscfg_set(NULL, "CaptivePortal_Enable", "true") != 0 )
        {
            CcspTraceError(("%s: syscfg_set failed for parameter CaptivePortal_Enable\n",__FUNCTION__));
        }
        v_secure_system("sh /etc/redirect_url.sh &");
    }
    else
    {
        if ( syscfg_set(NULL, "CaptivePortal_Enable", "false") != 0 )
        {
            CcspTraceError(("%s: syscfg_set failed for parameter CaptivePortal_Enable\n",__FUNCTION__));
        }
        v_secure_system("sh /etc/revert_redirect.sh &");
    }

    if (syscfg_commit() != 0)
    {
        CcspTraceError(("%s: syscfg_set failed for syscfg_commit\n",__FUNCTION__));
    }
    v_secure_system("sh /etc/webgui.sh &");
}

static int WanManager_CreateDHCPService(DML_VIRTUAL_IFACE* p_VirtIf)
{
    char buff[BUFLEN_16]         = {0};
    FILE *fp                     = NULL;
    char pidFilePath[BUFLEN_32]  = {0};
    char pidStr[BUFLEN_16]       = {0};
    int  pid                     = -1;
    char partnerID[BUFLEN_32]    = {0};
    char model[BUFLEN_32]        = {0};

    if(NULL == p_VirtIf)
    {
        CcspTraceError(("%s %d Null functin argument \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if(p_VirtIf->IP.IPv4Source == DML_WAN_IP_SOURCE_DHCP)
    {
        sprintf(pidFilePath, "/tmp/udhcpc.%s.pid", p_VirtIf->Name);
        if((fp = fopen(pidFilePath, "w+")) != NULL)
        {
            if(fgets(pidStr, sizeof(pidStr), fp) != NULL && atoi(pidStr) > 0)
            pid = atoi(pidStr);
            fclose(fp);
        }
    }

    if ( pid < 0 || 0 != kill(pid, 0))
    {
        syscfg_get(NULL, "PartnerID", partnerID, sizeof(partnerID));
        if (strcmp("IPTV", p_VirtIf->Alias) == 0) { // Fix suggested by Broadcom in CSP CS00012239021 for RDKSI-7103
            v_secure_system("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter");
            v_secure_system("echo 0 > /proc/sys/net/ipv4/conf/'%s'/rp_filter", p_VirtIf->Name);
        }

        if((strcmp("telekom-hr", partnerID) == 0 || strcmp("telekom-dev-hr", partnerID) == 0 ||
            strcmp("telekom-hr-test", partnerID) == 0) && (strcmp("IPTV", p_VirtIf->Alias) == 0))
        {
            /* For HR : Setting vendor class identifier for option60 */
            if (platform_hal_GetModelName(model) == 0)
            {
                v_secure_system("/sbin/udhcpc -b -i %s -p /tmp/udhcpc.%s.pid -O 121 -V HT_STB_%s -s /etc/udhcpc_vlan.script"
                                     ,p_VirtIf->Name, p_VirtIf->Name,  model);
            }
        }
        /* TODO: Need to revist when new wanmanager and dhcp changes are in place.*/
        else if(((strcmp("telekom-hr", partnerID) == 0) || (strcmp("telekom-hr-test", partnerID) == 0) ||
                 (strcmp("telekom-dev-hr", partnerID) == 0)) && (strcmp("VOIP", p_VirtIf->Alias) == 0))
        {
            /* Setting vendor class identifier for option60 and Hostname for option 12 */
            if (platform_hal_GetModelName(model) == 0)
            {
                v_secure_system("/sbin/udhcpc -b -i %s -p /tmp/udhcpc.%s.pid -O 121 -x hostname:%s -V %s -s /etc/udhcpc_vlan.script"
                                     ,p_VirtIf->Name, p_VirtIf->Name, model, model);
            }
        }
        else
        {
            v_secure_system("/sbin/udhcpc -b -i %s -p /tmp/udhcpc.%s.pid -O 121 -s /etc/udhcpc_vlan.script"
                             ,p_VirtIf->Name, p_VirtIf->Name);
        }
    CcspTraceInfo(("%s %d Started udhcpc for Virtual Interface %s \n", __FUNCTION__, __LINE__, p_VirtIf->Name));
     }

     return RETURN_OK;
}

static int WanManager_StopUdhcpcService(const char* const iFaceName)
{
    char buff[BUFLEN_16]         = {0};
    FILE *fp                     = NULL;
    char pidFilePath[BUFLEN_32]  = {0};
    char pidStr[BUFLEN_16]       = {0};
    char *endptr                 = NULL;
    int  pid                     = -1;

    if (NULL == iFaceName)
    {
        CcspTraceError(("%s %d - Invalid function argument \n", __FUNCTION__, __LINE__));
        return RETURN_ERR;
    }

    /* Get the dhcp service process ID from pid file and kill the service. */
    sprintf(pidFilePath, "/tmp/udhcpc.%s.pid", iFaceName);
    if ((fp = fopen(pidFilePath, "r")) != NULL)
    {
        if (fgets(pidStr, sizeof(pidStr), fp) != NULL)
        {
           pid = strtol(pidStr, &endptr, 10);
        }
        fclose(fp);
    }

    if (pid > 0)
    {
         kill(pid, SIGKILL);
    }

    return RETURN_OK;
}

DML_WAN_IFACE_IP_STATE getInterfaceIPv4Data(const char *const iFaceName, WANMGR_IPV4_DATA *IPv4Data)
{
    struct ifaddrs *ifaddr              = NULL;
    struct ifaddrs *ifa                 = NULL;
    char ipAddr[NI_MAXHOST]             = {0};
    char mask[NI_MAXHOST]               = {0};
    DML_WAN_IFACE_IP_STATE iFaceStatus = WAN_IFACE_IP_STATE_DOWN;

    if ((NULL == iFaceName) || (NULL == IPv4Data))
    {
        CcspTraceError(("%s %d - Invalid Input! \n", __FUNCTION__, __LINE__));
        return WAN_IFACE_IP_STATE_DOWN;
    }

    /* Get address of network interfaces on the local system */
    if (!getifaddrs(&ifaddr))
    {
        /* Traverse across the network interfaces */
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (NULL == ifa->ifa_addr)
            {
                continue;
            }

            if ((!strcmp(ifa->ifa_name, iFaceName)) && (AF_INET == ifa->ifa_addr->sa_family))
            {
                /* Address to name translation for IP address */
                getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), ipAddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                /* Address to name translation for sub-netmask */
                getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

                strncpy(IPv4Data->ip, ipAddr, sizeof(IPv4Data->ip));
                strncpy(IPv4Data->mask, mask, sizeof(IPv4Data->mask));

                iFaceStatus = WAN_IFACE_IP_STATE_UP;
                break;
            }
        }
    }
    else
    {
        iFaceStatus = WAN_IFACE_IP_STATE_DOWN;
        CcspTraceError(("%s %d - Failed to get Interface informations! \n", __FUNCTION__, __LINE__));
    }

    freeifaddrs(ifaddr);

    return (iFaceStatus);
}

#define CG_NAT_ADDR  "100.64.0.0"
#define CG_NAT_MASK  "255.192.0.0"
void wanmgr_setSharedCGNAddress(char *IpAddress)
{
    // Shared Address Space address range 100.64.0.0/10 as per IANA for Carrier Grade NAT
    unsigned long cgnat_addr = 0xffffffff, cgnat_mask = 0xffffffff;
    inet_pton(AF_INET, CG_NAT_ADDR, &cgnat_addr);
    inet_pton(AF_INET, CG_NAT_MASK, &cgnat_mask);
    unsigned long wan_address = 0xffffffff;
    inet_pton(AF_INET, IpAddress, &wan_address);
    if((wan_address & cgnat_mask) == (cgnat_addr & cgnat_mask)) {
        if( syscfg_set(NULL, "UseSharedCGNAddress", "true") != 0 && syscfg_commit() != 0)
            CcspTraceError(("%s %d - syscfg_set failed for parameter UseSharedCGNAddress \n", __FUNCTION__, __LINE__));
    }
    else {
        if( syscfg_set(NULL, "UseSharedCGNAddress", "false") != 0 && syscfg_commit() != 0)
            CcspTraceError(("%s %d - syscfg_set failed for parameter UseSharedCGNAddress \n", __FUNCTION__, __LINE__));
    }
}
#endif//_DT_WAN_Manager_Enable_

#if defined(WAN_MANAGER_UNIFICATION_ENABLED) && (defined (_XB6_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_))
#define DEFAULT_PSM_FILE          "/usr/ccsp/config/bbhm_def_cfg.xml"
/* TODO : This is a function to recover v2 PSM entries if it is written with wrong values in older builds. 
 * This should be removed after successful migration to unification builds 
 */
ANSC_STATUS WanMgr_CheckAndResetV2PSMEntries(UINT IfaceCount)
{ 
    int retPsmGet = CCSP_SUCCESS;
    char param_value[256];
    char param_name[512];
    FILE * fp = NULL;
    size_t len = 0;
    char *line = NULL;
    BOOL psmDefaultSetRequired = FALSE;

    CcspTraceInfo(("%s %d Enter \n", __FUNCTION__, __LINE__));

    /* For Unification enabled builds, BASEINTERFACE entry should always have a valid string. 
     * If BASEINTERFACE is empty PSm could be corrupted. Reset V2 PSM entries to default
     */

    for(int i = 1; i <= IfaceCount; i++)
    {
        snprintf(param_name, sizeof(param_name) ,PSM_WANMANAGER_IF_BASEINTERFACE, i);
        retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
        if (retPsmGet == CCSP_SUCCESS && strlen(param_value) <= 0)
        {
            CcspTraceError(("%s %d %s is empty  \n", __FUNCTION__, __LINE__,param_name));
            psmDefaultSetRequired = TRUE;
            break;
        }

        /* If selection enable is TRUE and virtual interface are set to false. PSM could be corrupted. Reset V2 PSM entries to default*/
        memset(param_name, 0, sizeof(param_name));
        memset(param_value, 0, sizeof(param_value));
        snprintf(param_name,sizeof(param_name), PSM_WANMANAGER_IF_SELECTION_ENABLE, i);
        retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));
        if(!strcmp(param_value, "TRUE"))
        {
            memset(param_name, 0, sizeof(param_name));
            memset(param_value, 0, sizeof(param_value));
            snprintf(param_name,sizeof(param_name), PSM_WANMANAGER_IF_VIRIF_ENABLE, i , 1);
            retPsmGet = WanMgr_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

            psmDefaultSetRequired = strcmp(param_value, "TRUE");
        }
    }

    if(!psmDefaultSetRequired)
    {
        return ANSC_STATUS_SUCCESS;
    }

    CcspTraceError(("%s %d %s Resetting V2 dml PSM entries to default psm value.  \n", __FUNCTION__, __LINE__,param_name));
    fp = fopen(DEFAULT_PSM_FILE, "r");
    if (fp == NULL)
    {
        CcspTraceError(("%s %d: unable to open file %s", __FUNCTION__, __LINE__, strerror(errno)));
        return ANSC_STATUS_FAILURE;
    }

    while (getline(&line, &len, fp) != -1)
    {
        if(strstr(line, "dmsb.wanmanager.if.") != NULL && (strstr(line, ".BaseInterface") != NULL || strstr(line, ".VirtualInterface")!= NULL ))
        {
            memset(param_value, 0, sizeof(param_value));
            memset(param_name, 0, sizeof(param_name));
            sscanf (line,"%*[^<]<Record name=\"%[^\"]%*[^>]>%[^<]%*[^\n]", param_name, param_value);
            CcspTraceWarning(("%s default value: %s  \n",param_name, param_value));
            WanMgr_RdkBus_SetParamValuesToDB(param_name,param_value);    
        }
    }

    if (line)
    {
        free(line);
    }
    fclose (fp);

    return ANSC_STATUS_SUCCESS;

}
#endif
