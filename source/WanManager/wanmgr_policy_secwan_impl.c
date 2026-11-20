/*********************************************************************************
 If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 Deutsche Telekom AG.
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

*********************************************************************************/

/**************************************************************************************
 * @file wanmgr_policy_secwan_impl.c
 * @author Sherik Sensin A (sherik.a@telekom-digital.com)
 * @brief Secondary group interface policy state machine.
 *************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>
#include <pthread.h>
#include <sysevent/sysevent.h>
#include <signal.h>
#include "wanmgr_controller.h"
#include "wanmgr_data.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_sysevents.h"
#include "wanmgr_rbus_handler_apis.h"
#include "wanmgr_wan_failover.h"
#include "secure_wrapper.h"

extern INT sysevent_fd;
extern token_t sysevent_token;

#define LOOP_TIMEOUT                      500000 /* microseconds — SM loop interval */
#define MULTIWAN_GROUP_INSTANCE           1
#define SECONDARY_WAN_GROUP_INSTANCE      2
#define BACKUP_WAN_DHCPC_PID_FILE         "/var/run/bkupwan_dhcpc.pid"
#define BACKUP_WAN_DHCPC_SOURCE_FILE      "/etc/udhcpc_backupwan.script"

typedef enum
{
    WAN_START_FOR_VALIDATION = 0,
    WAN_START_FOR_BACKUP_WAN
}WanStartCallSource_t;

/* States */
typedef enum {
    STATE_SEC_WAN_WAITING_INTERFACE = 0,
    STATE_SEC_WAN_SELECTING_INTERFACE,
    STATE_SEC_WAN_INTERFACE_DOWN,
    STATE_SEC_WAN_AVAILABLE,
    STATE_SEC_WAN_ACQUIRING_IP,
    STATE_SEC_WAN_INTERFACE_ACTIVE,
    STATE_SEC_WAN_INTERFACE_INACTIVE,
    STATE_SEC_WAN_EXIT,
    STATE_SEC_WAN_ERROR
} WcSecWanPolicyState_t;

/*************************************************************************************/
/************************** Local Utils **********************************************/
/*************************************************************************************/
/* Secondary wan policy state machine thread function */
static void *Wanmgr_SecondaryWan_StateMachineThread(VOID *arg);

static void WanMgr_Policy_CheckAndStopUDHCPClientOverWanInterface(CHAR *ifname, CHAR *pidfile);
static INT WanMgr_Policy_CheckAndStartUDHCPClientOverWanInterface(CHAR *IfaceName, WanStartCallSource_t enCallSource, CHAR* pidfile, CHAR* script);
static BOOL WanMgr_SecWan_CaptureCmdOutput(const CHAR *ifName, BOOL isV6, CHAR *out, size_t outLen);
static void WanMgr_SecWan_TrimLine(CHAR *buff);
static void WanMgr_SecWan_CaptureDefaultGw(const CHAR *ifName, BOOL isV6, CHAR *out, size_t outLen);
static void WanMgr_SecWan_DeriveGwFromIpMask(const CHAR *ip, const CHAR *maskStr, CHAR *out, size_t outLen);
static void WanMgr_SecWan_CaptureIpv4Mask(const CHAR *ifName, CHAR *out, size_t outLen);
static DML_VIRTUAL_IFACE *WanMgr_SecWan_GetDataVirtIf(DML_WAN_IFACE *pIface);
static BOOL WanMgr_SecWan_IsIfaceLinkUp(const DML_WAN_IFACE *pIface);
static BOOL WanMgr_SecWan_IsPrimaryPhysicallyDown(void);
static void WanMgr_SecWan_MarkGroupStopped(UINT groupInst);
static ANSC_STATUS WanMgr_getUdhcpcClientID (CHAR * buff, INT len);

/* State Functions */
static WcSecWanPolicyState_t State_WaitingSecondaryWanInterface         (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t State_SelectingSecondaryWanInterface       (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t State_SecondaryWanInterfaceDown            (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t State_SecondaryWanAvailable                (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t State_SecondaryWanAcquiringIP              (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t State_SecondaryWanInterfaceActive          (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t State_SecondaryWanInterfaceInActive        (WanMgr_Policy_Controller_t* pWanController);

/* Transition Functions */
static WcSecWanPolicyState_t Transition_StartSecondaryWan               (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t Transition_SecondaryWanAvailable           (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t Transition_SecondaryWanAcquiringIP         (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t Transition_SecondaryWanInterfaceDown       (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t Transition_SecondaryWanInterfaceActive     (WanMgr_Policy_Controller_t* pWanController);
static WcSecWanPolicyState_t Transition_SecondaryWanInterfaceInActive   (WanMgr_Policy_Controller_t* pWanController);

/*
 * Read first token from a shell command into out (trimmed of newline).
 * Returns TRUE if non-empty output was captured.
 */
static BOOL WanMgr_SecWan_CaptureCmdOutput(const CHAR *ifName, BOOL isV6, CHAR *out, size_t outLen)
{
    FILE *fp = NULL;
    CHAR buff[BUFLEN_128] = {0};
    INT pclose_ret = 0;

    if ((ifName == NULL) || (ifName[0] == '\0') || (out == NULL) || (outLen == 0))
    {
        return FALSE;
    }

    out[0] = '\0';
    if (isV6 == FALSE)
    {
        fp = v_secure_popen("r",
                            "ip -4 addr show %s | awk '/inet / {print $2; exit}' | cut -d/ -f1",
                            ifName);
    }
    else
    {
        fp = v_secure_popen("r",
                            "ip -6 addr show %s | awk '/inet6 / && /global/ {print $2; exit}' | cut -d/ -f1",
                            ifName);
    }

    if (fp == NULL)
    {
        return FALSE;
    }

    if (fgets(buff, sizeof(buff), fp) != NULL)
    {
        size_t n = strlen(buff);
        while ((n > 0) && ((buff[n - 1] == '\n') || (buff[n - 1] == '\r')))
        {
            buff[--n] = '\0';
        }
        if (n > 0)
        {
            snprintf(out, outLen, "%s", buff);
        }
    }

    pclose_ret = v_secure_pclose(fp);
    if (pclose_ret != 0)
    {
        CcspTraceError(("%s: v_secure_pclose failed ret=%d\n", __FUNCTION__, pclose_ret));
    }

    return (out[0] != '\0') ? TRUE : FALSE;
}

/* Strip trailing CR/LF/space from buff in place. */
static void WanMgr_SecWan_TrimLine(CHAR *buff)
{
    size_t n = 0;

    if (buff == NULL)
    {
        return;
    }
    n = strlen(buff);
    while ((n > 0) && ((buff[n - 1] == '\n') || (buff[n - 1] == '\r') || (buff[n - 1] == ' ')))
    {
        buff[--n] = '\0';
    }
}

/* Capture default gateway for ifName from ip route or /proc/net/route. */
static void WanMgr_SecWan_CaptureDefaultGw(const CHAR *ifName, BOOL isV6, CHAR *out, size_t outLen)
{
    FILE     *fp              = NULL;
    CHAR     buff[BUFLEN_128] = {0};
    CHAR     iface[BUFLEN_32] = {0};
    unsigned dest             = 0;
    unsigned gateway          = 0;
    unsigned flags            = 0;
    unsigned refcnt           = 0;
    unsigned use              = 0;
    unsigned metric           = 0;
    unsigned mask             = 0;
    INT      n                = 0;

    if ((ifName == NULL) || (ifName[0] == '\0') || (out == NULL) || (outLen == 0))
    {
        return;
    }
    out[0] = '\0';

    /* 1) ip route show default (may be empty until we install the route). */
    if (isV6 == FALSE)
    {
        fp = v_secure_popen("r",
                            "ip -4 route show default | awk -v IF='%s' '{via=\"\"; dev=\"\"; for(i=1;i<=NF;i++){if($i==\"via\")via=$(i+1); if($i==\"dev\")dev=$(i+1);} if(via!=\"\" && (dev==IF || IF==\"\")){print via; exit}}'",
                            ifName);
    }
    else
    {
        fp = v_secure_popen("r",
                            "ip -6 route show default | awk -v IF='%s' '{via=\"\"; dev=\"\"; for(i=1;i<=NF;i++){if($i==\"via\")via=$(i+1); if($i==\"dev\")dev=$(i+1);} if(via!=\"\" && (dev==IF || IF==\"\")){print via; exit}}'",
                            ifName);
    }

    if (fp != NULL)
    {
        if (fgets(buff, sizeof(buff), fp) != NULL)
        {
            WanMgr_SecWan_TrimLine(buff);
            if (buff[0] != '\0')
            {
                snprintf(out, outLen, "%s", buff);
            }
        }
        (void)v_secure_pclose(fp);
        fp = NULL;
    }

    if ((out[0] != '\0') || (isV6 == TRUE))
    {
        return;
    }

    /* 2) /proc/net/route — default Dest=00000000 for this iface (hex LE gateway). */
    fp = fopen("/proc/net/route", "r");
    if (fp == NULL)
    {
        return;
    }
    /* skip header */
    if (fgets(buff, sizeof(buff), fp) == NULL)
    {
        fclose(fp);
        return;
    }
    while (fgets(buff, sizeof(buff), fp) != NULL)
    {
        n = sscanf(buff, "%31s %x %x %x %u %u %u %x",
                   iface, &dest, &gateway, &flags, &refcnt, &use, &metric, &mask);
        (void)refcnt;
        (void)use;
        (void)metric;
        if ((n >= 4) && (dest == 0) && (gateway != 0) &&
            (strcmp(iface, ifName) == 0) && ((flags & 0x2) != 0)) /* RTF_GATEWAY */
        {
            snprintf(out, outLen, "%u.%u.%u.%u",
                     (unsigned)(gateway & 0xff),
                     (unsigned)((gateway >> 8) & 0xff),
                     (unsigned)((gateway >> 16) & 0xff),
                     (unsigned)((gateway >> 24) & 0xff));
            break;
        }
    }
    fclose(fp);
}

/* If still no gateway, derive .1 of the IPv4 subnet (common USB-LTE pattern). */
static void WanMgr_SecWan_DeriveGwFromIpMask(const CHAR *ip, const CHAR *maskStr, CHAR *out, size_t outLen)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    unsigned m1 = 0, m2 = 0, m3 = 0, m4 = 0;
    unsigned ipn = 0;
    unsigned msk = 0;
    unsigned net = 0;

    if ((ip == NULL) || (maskStr == NULL) || (out == NULL) || (outLen == 0))
    {
        return;
    }
    if (out[0] != '\0')
    {
        return;
    }
    if ((sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) ||
        (sscanf(maskStr, "%u.%u.%u.%u", &m1, &m2, &m3, &m4) != 4))
    {
        return;
    }
    ipn = (a << 24) | (b << 16) | (c << 8) | d;
    msk = (m1 << 24) | (m2 << 16) | (m3 << 8) | m4;
    if (msk == 0)
    {
        return;
    }
    net = ipn & msk;
    /* Prefer network+1 as gateway (e.g. 192.168.8.100/24 -> 192.168.8.1). */
    net = net + 1;
    if ((net == ipn) || ((net & msk) != (ipn & msk)))
    {
        return;
    }
    snprintf(out, outLen, "%u.%u.%u.%u",
             (net >> 24) & 0xff, (net >> 16) & 0xff, (net >> 8) & 0xff, net & 0xff);
}

/* Capture IPv4 prefix length from iface and convert to dotted mask (e.g. /24 -> 255.255.255.0). */
static void WanMgr_SecWan_CaptureIpv4Mask(const CHAR *ifName, CHAR *out, size_t outLen)
{
    FILE *fp = NULL;
    CHAR buff[BUFLEN_32] = {0};
    unsigned prefix = 0;
    unsigned long mask = 0;
    unsigned i = 0;

    if ((ifName == NULL) || (out == NULL) || (outLen < BUFLEN_16))
    {
        return;
    }
    out[0] = '\0';

    fp = v_secure_popen("r",
                        "ip -4 addr show %s | awk '/inet / {split($2,a,\"/\"); print a[2]; exit}'",
                        ifName);
    if (fp == NULL)
    {
        return;
    }
    if (fgets(buff, sizeof(buff), fp) != NULL)
    {
        prefix = (unsigned)atoi(buff);
    }
    (void)v_secure_pclose(fp);

    if ((prefix == 0) || (prefix > 32))
    {
        return;
    }

    for (i = 0; i < prefix; i++)
    {
        mask |= (1UL << (31 - i));
    }
    snprintf(out, outLen, "%u.%u.%u.%u",
             (unsigned)((mask >> 24) & 0xff),
             (unsigned)((mask >> 16) & 0xff),
             (unsigned)((mask >> 8) & 0xff),
             (unsigned)(mask & 0xff));
}

/*
 * Refresh VirtIf addresses/gateway/mask for HandleWanChange/UpdateDNS.
 * Does NOT set Ipv4/Ipv6 Status UP — that is reserved for Active apply so
 * HandleWanChange is not skipped. Clears Status to DOWN when address is gone.
 * Sources: live iface IP/route/mask and Backup-style sysevents (no Cellular DM).
 * Log only when values change (SecWan SM is single-threaded).
 */
static void WanMgr_SecWan_RefreshVirtIfIpData(DML_WAN_IFACE *pSecInterface, DML_VIRTUAL_IFACE *p_VirtIf)
{
    CHAR ifName[BUFLEN_64] = {0};
    CHAR ipv4[BUFLEN_32] = {0};
    CHAR ipv6[BUFLEN_64] = {0};
    CHAR gw4[BUFLEN_32] = {0};
    CHAR gw6[BUFLEN_64] = {0};
    CHAR mask[BUFLEN_16] = {0};
    CHAR dnsOut[BUFLEN_256] = {0};
    CHAR *token = NULL;
    CHAR *saveptr = NULL;
    static CHAR s_prevIf[BUFLEN_64] = {0};
    static CHAR s_prevV4[BUFLEN_32] = {0};
    static CHAR s_prevV6[BUFLEN_64] = {0};
    static CHAR s_prevGw4[BUFLEN_32] = {0};

    if ((pSecInterface == NULL) || (p_VirtIf == NULL))
    {
        CcspTraceError(("%s: NULL iface/VirtIf\n", __FUNCTION__));
        return;
    }

    if (p_VirtIf->Name[0] != '\0')
    {
        snprintf(ifName, sizeof(ifName), "%s", p_VirtIf->Name);
    }
    else if (pSecInterface->Name[0] != '\0')
    {
        snprintf(ifName, sizeof(ifName), "%s", pSecInterface->Name);
        snprintf(p_VirtIf->Name, sizeof(p_VirtIf->Name), "%s", ifName);
    }

    if (ifName[0] == '\0')
    {
        CcspTraceWarning(("%s: no L3 ifname yet for secondary\n", __FUNCTION__));
        return;
    }

    snprintf(p_VirtIf->IP.Ipv4Data.ifname, sizeof(p_VirtIf->IP.Ipv4Data.ifname), "%s", ifName);
    snprintf(p_VirtIf->IP.Ipv6Data.ifname, sizeof(p_VirtIf->IP.Ipv6Data.ifname), "%s", ifName);

    /* --- IPv4 address (fill only; do not mark UP here) --- */
    (void)WanMgr_SecWan_CaptureCmdOutput(ifName, FALSE, ipv4, sizeof(ipv4));
    if (ipv4[0] != '\0')
    {
        snprintf(p_VirtIf->IP.Ipv4Data.ip, sizeof(p_VirtIf->IP.Ipv4Data.ip), "%s", ipv4);
    }
    else
    {
        p_VirtIf->IP.Ipv4Data.ip[0] = '\0';
        p_VirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_DOWN;
    }

    /* --- IPv6 address --- */
    (void)WanMgr_SecWan_CaptureCmdOutput(ifName, TRUE, ipv6, sizeof(ipv6));
    if (ipv6[0] != '\0')
    {
        snprintf(p_VirtIf->IP.Ipv6Data.address, sizeof(p_VirtIf->IP.Ipv6Data.address), "%s", ipv6);
    }
    else
    {
        p_VirtIf->IP.Ipv6Data.address[0] = '\0';
        p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_DOWN;
    }

    /* --- Mask (always refresh from iface when present) --- */
    WanMgr_SecWan_CaptureIpv4Mask(ifName, mask, sizeof(mask));
    if (mask[0] != '\0')
    {
        snprintf(p_VirtIf->IP.Ipv4Data.mask, sizeof(p_VirtIf->IP.Ipv4Data.mask), "%s", mask);
    }

    /* --- Gateway: default route, sysevent, then subnet+1 heuristic --- */
    WanMgr_SecWan_CaptureDefaultGw(ifName, FALSE, gw4, sizeof(gw4));
    if (gw4[0] == '\0')
    {
        memset(dnsOut, 0, sizeof(dnsOut));
        sysevent_get(sysevent_fd, sysevent_token, "ipv4_router", dnsOut, sizeof(dnsOut));
        if (dnsOut[0] != '\0')
        {
            token = strtok_r(dnsOut, " \t", &saveptr);
            if (token != NULL)
            {
                snprintf(gw4, sizeof(gw4), "%s", token);
            }
        }
    }
    if ((gw4[0] == '\0') && (p_VirtIf->IP.Ipv4Data.ip[0] != '\0') &&
        (p_VirtIf->IP.Ipv4Data.mask[0] != '\0'))
    {
        WanMgr_SecWan_DeriveGwFromIpMask(p_VirtIf->IP.Ipv4Data.ip,
                                         p_VirtIf->IP.Ipv4Data.mask,
                                         gw4, sizeof(gw4));
    }
    if (gw4[0] != '\0')
    {
        snprintf(p_VirtIf->IP.Ipv4Data.gateway, sizeof(p_VirtIf->IP.Ipv4Data.gateway), "%s", gw4);
    }

    WanMgr_SecWan_CaptureDefaultGw(ifName, TRUE, gw6, sizeof(gw6));
    if (gw6[0] != '\0')
    {
        snprintf(p_VirtIf->IP.Ipv6RA.acDefaultGw, sizeof(p_VirtIf->IP.Ipv6RA.acDefaultGw), "%s", gw6);
    }

    /*
     * DNS: not refreshed here. WanManager_UpdateDNS() fills VirtIf dnsServer* /
     * nameserver* from Backup-style sysevents when secondary applies.
     */

    if ((strcmp(s_prevIf, ifName) != 0) ||
        (strcmp(s_prevV4, p_VirtIf->IP.Ipv4Data.ip) != 0) ||
        (strcmp(s_prevV6, p_VirtIf->IP.Ipv6Data.address) != 0) ||
        (strcmp(s_prevGw4, p_VirtIf->IP.Ipv4Data.gateway) != 0))
    {
        CcspTraceInfo(("%s: if=%s v4=%s(%d) v6=%s(%d) gw4=%s mask=%s\n",
                       __FUNCTION__, ifName,
                       p_VirtIf->IP.Ipv4Data.ip, p_VirtIf->IP.Ipv4Status,
                       p_VirtIf->IP.Ipv6Data.address, p_VirtIf->IP.Ipv6Status,
                       p_VirtIf->IP.Ipv4Data.gateway,
                       p_VirtIf->IP.Ipv4Data.mask));
        snprintf(s_prevIf, sizeof(s_prevIf), "%s", ifName);
        snprintf(s_prevV4, sizeof(s_prevV4), "%s", p_VirtIf->IP.Ipv4Data.ip);
        snprintf(s_prevV6, sizeof(s_prevV6), "%s", p_VirtIf->IP.Ipv6Data.address);
        snprintf(s_prevGw4, sizeof(s_prevGw4), "%s", p_VirtIf->IP.Ipv4Data.gateway);
    }
}

/* Return DATA VirtIf if present, else first VirtIf on the iface. */
static DML_VIRTUAL_IFACE *WanMgr_SecWan_GetDataVirtIf(DML_WAN_IFACE *pIface)
{
    DML_VIRTUAL_IFACE *pVirtIf = NULL;
    DML_VIRTUAL_IFACE *pFirst = NULL;

    if ((pIface == NULL) || (pIface->VirtIfList == NULL))
    {
        return NULL;
    }

    pFirst = pIface->VirtIfList;
    for (pVirtIf = pFirst; pVirtIf != NULL; pVirtIf = pVirtIf->next)
    {
        if (AnscEqualString(pVirtIf->Alias, "DATA", TRUE))
        {
            return pVirtIf;
        }
    }
    return pFirst;
}

/* TRUE when BaseInterfaceStatus is PHY UP. */
static BOOL WanMgr_SecWan_IsIfaceLinkUp(const DML_WAN_IFACE *pIface)
{
    if (pIface == NULL)
    {
        return FALSE;
    }
    return (pIface->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP) ? TRUE : FALSE;
}

/*
 * BackupWan CheckAnyLocalWANIsPhysicallyActive equivalent for FO Group1:
 * primary is up if any enabled Group1 iface has BaseInterfaceStatus PHY UP.
 * Iface locks only — never take a group lock here.
 */
static BOOL WanMgr_SecWan_IsPrimaryPhysicallyDown(void)
{
    UINT uiWanIdx = 0;
    UINT uiTotalIfaces = WanMgr_IfaceData_GetTotalWanIface();

    for (uiWanIdx = 0; uiWanIdx < uiTotalIfaces; uiWanIdx++)
    {
        WanMgr_Iface_Data_t *pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiWanIdx);
        DML_WAN_IFACE *pInterface = NULL;

        if (pWanDmlIfaceData == NULL)
        {
            continue;
        }

        pInterface = &(pWanDmlIfaceData->data);
        /* Group1 only — do not treat Group2/LTE PHY as primary. */
        if ((pInterface->Selection.Enable == TRUE) &&
            (pInterface->Selection.Group == MULTIWAN_GROUP_INSTANCE) &&
            (pInterface->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP))
        {
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            return FALSE;
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    return TRUE;
}

/* Clear group ThreadId/selection and mark group STOPPED (unless DEACTIVATED). */
static void WanMgr_SecWan_MarkGroupStopped(UINT groupInst)
{
    WANMGR_IFACE_GROUP *pGrp = NULL;

    if (groupInst == 0)
    {
        return;
    }
    pGrp = WanMgr_GetIfaceGroup_locked(groupInst - 1);
    if (pGrp == NULL)
    {
        return;
    }
    pGrp->ThreadId = 0;
    pGrp->SelectedInterface = 0;
    pGrp->ConfigChanged = FALSE;
    if (pGrp->State != STATE_GROUP_DEACTIVATED)
    {
        pGrp->State = STATE_GROUP_STOPPED;
    }
    WanMgrDml_GetIfaceGroup_release();
}

/* Build udhcpc client-id option string from base MAC (0x3D:<mac>). */
static ANSC_STATUS WanMgr_getUdhcpcClientID (CHAR * buff, INT len)
{
    if (buff == NULL || len <= 0)
    {
        CcspTraceError(("%s %d: invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    CHAR mac[BUFLEN_32] = {0};
    CHAR tmp[BUFLEN_32] = {0};
    if (platform_hal_GetBaseMacAddress (tmp) != RETURN_OK)
    {
        CcspTraceError(("%s %d: unable to get Base MAC Address\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    // remove the : character
    for (INT i = 0, j = 0; i < strlen(tmp); i++)
    {
        if (tmp[i] == ':')
            continue;
        mac[j] = tmp[i];
        j++;
    }

    if (strlen(mac) == 0 )
    {
        CcspTraceError(("%s %d: unable to get Base MAC Address from %s\n", __FUNCTION__, __LINE__, tmp));
        return ANSC_STATUS_FAILURE;
    }

    snprintf(buff, len, "0x3D:%s", mac);

    return ANSC_STATUS_SUCCESS;
    
    
}

/* Kill local udhcpc for ifname using pidfile, then unlink pidfile. */
static void WanMgr_Policy_CheckAndStopUDHCPClientOverWanInterface(CHAR *ifname, CHAR *pidfile)
{
    INT  iPIDofBackupWAN   = -1;
    CHAR output[BUFLEN_16] = {0};
    FILE *fp               = NULL;

    if ((ifname == NULL) || (pidfile == NULL))
    {
        CcspTraceError(("%s-%d : Null parameters\n", __FUNCTION__, __LINE__));
        return;
    }
    if ((strlen(ifname) <= 0) || (ifname[0] == '\0'))
    {
        CcspTraceWarning(("%s-%d : Interface Name is empty\n", __FUNCTION__, __LINE__));
    }

    fp = fopen(pidfile, "r");
    if(fp)
    {
        WanManager_Util_GetShell_output(fp, output, sizeof(output));
        fclose(fp);
    }

    if( '\0' != output[0] )
    {
        iPIDofBackupWAN = atoi(output);

        if ( iPIDofBackupWAN > 0 )
        {
            CcspTraceInfo(("%s: DHCP client has already running as PID %d\n", __FUNCTION__, iPIDofBackupWAN));
            kill(iPIDofBackupWAN, SIGKILL);
            CcspTraceInfo(("%s: Stopped local udhcpc client for '%s' interface\n", __FUNCTION__, ifname));
        }
    }

    unlink(pidfile);
}

/* Stop any prior udhcpc, then start one-shot udhcpc for IfaceName. Returns 0 on lease. */
static INT WanMgr_Policy_CheckAndStartUDHCPClientOverWanInterface(CHAR *IfaceName, WanStartCallSource_t enCallSource, CHAR* pidfile, CHAR* script)
{
    CHAR logPrefixString[256] = {0};
    CHAR cValidationOptions[] = "-q";
    CHAR isValidating = 0;

    if( (strlen(IfaceName) <= 0) || (IfaceName[0] == '\0') || ( FALSE == WanManager_IsNetworkInterfaceAvailable( IfaceName ) ) )
    {
        return -1;
    }

    //Log Purpose and more
    if( WAN_START_FOR_VALIDATION == enCallSource )
    {
        snprintf(logPrefixString, sizeof(logPrefixString), "Validating");
        isValidating = 1;
    }
    else
    {
        snprintf(logPrefixString, sizeof(logPrefixString), "Effecting");
        isValidating = 0;
    }

    //Cleanup - Stop UDHCPC client before start another instance
    WanMgr_Policy_CheckAndStopUDHCPClientOverWanInterface(IfaceName, pidfile);

    CcspTraceInfo(("%s-%d : %s : Starting udhcpc client locally for '%s' interface\n",__FUNCTION__, __LINE__, logPrefixString, IfaceName));

    /* To start local udhcpc server over interface to check whether it is getting leases or not */

    // Add Client Identifier 
    CHAR clientId[32] = {0};

    WanMgr_getUdhcpcClientID(clientId, sizeof(clientId));

    INT ret = v_secure_system("/sbin/udhcpc -t 5 -n %s -O 125 -i %s -p %s -s %s -x %s", isValidating ? cValidationOptions : "", IfaceName, pidfile, script, clientId);

    CcspTraceInfo(("%s-%d : %s WAN: Cmd Str[/sbin/udhcpc -t 5 -n %s -O 125 -i %s -p %s -s %s -x %s]\n",__FUNCTION__, __LINE__, logPrefixString,isValidating ? cValidationOptions : "", IfaceName, pidfile, script, clientId));
    /* DHCP client didn't able to get Ipv4 configurations */
    if ( ret != 0 )
    {
        CcspTraceInfo(("%s-%d : %s WAN service not able to get IPv4 configuration ret val %d \n",__FUNCTION__, __LINE__, logPrefixString,ret));
        return -1;
    }
    else
    {
        CcspTraceInfo(("%s-%d : %s WAN interface '%s' got leases ret val %d \n", __FUNCTION__, __LINE__, logPrefixString, IfaceName,ret));
    }

    return 0;
}

/*************************************************************************************/
/************************** TRANSITIONS **********************************************/
/*************************************************************************************/
/**************************************************************************************
 * @brief Transition_StartSecondaryWan()
 *      - Transition start function
 * 
 * @param[in,out] pWanController: Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR              : Error state
 *       - STATE_SEC_WAN_SELECTING_INTERFACE: State to select an interface
 *************************************************************************************/
static WcSecWanPolicyState_t Transition_StartSecondaryWan(WanMgr_Policy_Controller_t* pWanController)
{
    if (NULL == pWanController)
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pWanController->activeInterfaceIdx = -1;

    CcspTraceInfo(("%s %d - State changed to STATE_SEC_WAN_SELECTING_INTERFACE \n", __FUNCTION__, __LINE__));

    return STATE_SEC_WAN_SELECTING_INTERFACE;
}

/**************************************************************************************
 * @brief Transition_SecondaryWanAvailable()
 *      - Transition to STATE_SEC_WAN_AVAILABLE state
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR    : Error state
 *       - STATE_SEC_WAN_AVAILABLE: Secondary group WAN available
 *************************************************************************************/
static WcSecWanPolicyState_t Transition_SecondaryWanAvailable(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE*     pSecInterface = NULL;
    DML_VIRTUAL_IFACE* p_VirtIf      = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);
    p_VirtIf = WanMgr_SecWan_GetDataVirtIf(pSecInterface);
    if (p_VirtIf == NULL)
    {
        CcspTraceError(("%s %d: No VirtIf for secondary\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    /* BackupWan Transition_BackupWanAvailable field updates. */
    pSecInterface->Selection.ActiveLink = TRUE;
    pSecInterface->Selection.Status = WAN_IFACE_SELECTED;
    p_VirtIf->Status = WAN_IFACE_STATUS_DISABLED;
    (void)Update_Interface_Status();

    CcspTraceInfo(("%s %d - State changed to STATE_SEC_WAN_AVAILABLE \n", __FUNCTION__, __LINE__));

    return STATE_SEC_WAN_AVAILABLE;
}

/**************************************************************************************
 * @brief Transition_SecondaryWanAcquiringIP()
 *      - Transition to STATE_SEC_WAN_ACQUIRING_IP state
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR       : Error state
 *       - STATE_SEC_WAN_ACQUIRING_IP: State to acquire IP
 *************************************************************************************/
static WcSecWanPolicyState_t Transition_SecondaryWanAcquiringIP(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE*     pSecInterface = NULL;
    DML_VIRTUAL_IFACE* p_VirtIf      = NULL;
    const CHAR*        ifName        = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);
    p_VirtIf = WanMgr_SecWan_GetDataVirtIf(pSecInterface);
    if (p_VirtIf == NULL)
    {
        CcspTraceError(("%s %d: No VirtIf for secondary\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    /* Reset IP state before acquire (BackupWan pattern). */
    p_VirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_UNKNOWN;
    p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_UNKNOWN;
    memset(p_VirtIf->IP.Ipv4Data.ip, 0, sizeof(p_VirtIf->IP.Ipv4Data.ip));
    memset(p_VirtIf->IP.Ipv6Data.address, 0, sizeof(p_VirtIf->IP.Ipv6Data.address));

    ifName = (p_VirtIf->Name[0] != '\0') ? p_VirtIf->Name : pSecInterface->Name;

    /* DHCP path (BackupWan Transition_BackupWanInterfaceUp). */
    if ((ifName != NULL) && (ifName[0] != '\0') &&
        (p_VirtIf->IP.IPv4Source == DML_WAN_IP_SOURCE_DHCP))
    {
        if (-1 == WanMgr_Policy_CheckAndStartUDHCPClientOverWanInterface(
                (CHAR *)ifName, WAN_START_FOR_BACKUP_WAN,
                BACKUP_WAN_DHCPC_PID_FILE, BACKUP_WAN_DHCPC_SOURCE_FILE))
        {
            CcspTraceWarning(("%s: udhcpc failed on %s — will poll iface\n",
                              __FUNCTION__, ifName));
        }
    }

    /* BackupWan Transition_BackupWanInterfaceUp VirtIf link/status updates. */
    p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_UP;
    p_VirtIf->Status = WAN_IFACE_STATUS_UP;
    (void)Update_Interface_Status();

    /* BackupWan: StartIpMonitor sets Ipv4/Ipv6 Status UP once kernel has an address. */
    CcspTraceInfo(("%s - Starting IP Monitoring for ifaceIdx=%d (%s)\n",
                   __FUNCTION__, pWanController->activeInterfaceIdx, ifName ? ifName : ""));
    (void)WanMgr_StartIpMonitor((UINT)pWanController->activeInterfaceIdx);

    /* Seed VirtIf from iface immediately (IpMonitor only sets status). */
    WanMgr_SecWan_RefreshVirtIfIpData(pSecInterface, p_VirtIf);

    CcspTraceInfo(("%s %d - State changed to STATE_SEC_WAN_ACQUIRING_IP \n", __FUNCTION__, __LINE__));

    return STATE_SEC_WAN_ACQUIRING_IP;
}

/**************************************************************************************
 * @brief Transition_SecondaryWanInterfaceActive()
 *      - Transition to STATE_SEC_WAN_INTERFACE_ACTIVE state
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR           : Error state
 *       - STATE_SEC_WAN_INTERFACE_ACTIVE: State interface active
 *************************************************************************************/
static WcSecWanPolicyState_t Transition_SecondaryWanInterfaceActive(WanMgr_Policy_Controller_t* pWanController)
{
    INT                  primaryUpTime          = 0;
    CHAR                 paramValue[BUFLEN_256] = {0};
    CHAR                 time_buf[BUFLEN_32]    = {0};
    DML_WAN_IFACE*       pSecInterface          = NULL;
    WANMGR_IFACE_GROUP*  pWanIfaceGroup         = NULL;
    WANMGR_IFACE_GROUP*  pWanDmlGrp             = NULL;
    DML_VIRTUAL_IFACE*   p_VirtIf               = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }
    
    pSecInterface         = &(pWanController->pWanActiveIfaceData->data);

    /* FO publish: ACTIVE + connectivity so MarkHighPriorityGroup sees us.
     * Aligned with BackupWan Transition_BackupWanInterfaceActive field updates. */
    pSecInterface->Selection.Status = WAN_IFACE_ACTIVE;
    pSecInterface->Selection.ActiveLink = TRUE;
    p_VirtIf = WanMgr_SecWan_GetDataVirtIf(pSecInterface);
    if (p_VirtIf != NULL)
    {
        p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_UP;
        p_VirtIf->Status = WAN_IFACE_STATUS_UP;
        p_VirtIf->IP.Ipv4ConnectivityStatus = WAN_CONNECTIVITY_UP;
    }
    (void)WanMgr_SetGroupSelectedIface(pWanController->GroupInst,
                                       (UINT)(pWanController->activeInterfaceIdx + 1));
    (void)Update_Interface_Status();

    pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(pWanController->GroupInst - 1);
    if (NULL != pWanIfaceGroup)
    {
        pWanDmlGrp = pWanIfaceGroup;
        pWanDmlGrp->SelectedInterface = (1 + pWanController->activeInterfaceIdx);
        /* FO: publish UP via VirtIf + ACTIVE; keep group RUNNING */
        pWanDmlGrp->State             = STATE_GROUP_RUNNING;

        WanMgrDml_GetIfaceGroup_release();
    }

    /*
     * Apply WAN once on Active entry: fill gw/mask, mark IP UP, install default
     * route + DNS. Refresh alone must not mark UP (that skipped this path).
     */
    if (p_VirtIf != NULL)
    {
        WanMgr_SecWan_RefreshVirtIfIpData(pSecInterface, p_VirtIf);

        if (p_VirtIf->IP.Ipv4Data.ip[0] != '\0')
        {
            p_VirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_UP;
            WanManager_HandleWanChange(pSecInterface, p_VirtIf, WAN_IFACE_IPV4_STATE);
            WanManager_UpdateDNS(pSecInterface, p_VirtIf, WAN_IFACE_IPV4_STATE);
        }
        if (p_VirtIf->IP.Ipv6Data.address[0] != '\0')
        {
            p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_UP;
            WanManager_HandleWanChange(pSecInterface, p_VirtIf, WAN_IFACE_IPV6_STATE);
            WanManager_UpdateDNS(pSecInterface, p_VirtIf, WAN_IFACE_IPV6_STATE);
            wanmgr_firewall_restart();
        }
    }

    CcspTraceInfo(("%s %d - State changed to STATE_SEC_WAN_INTERFACE_ACTIVE \n", __FUNCTION__, __LINE__));

    return STATE_SEC_WAN_INTERFACE_ACTIVE;
}

/**************************************************************************************
 * @brief Transition_SecondaryWanInterfaceInActive()
 *      - Transition to STATE_SEC_WAN_INTERFACE_INACTIVE state
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR             : Error state
 *       - STATE_SEC_WAN_INTERFACE_INACTIVE: State interface inactive
 *************************************************************************************/
static WcSecWanPolicyState_t Transition_SecondaryWanInterfaceInActive(WanMgr_Policy_Controller_t* pWanController)
{
    INT                  virtualIfaceCount     = 0;
    INT                  vIfaceIdx             = 0;
    INT                  bckUpTimeout          = 0;
    DML_WAN_IFACE*       pSecInterface         = NULL;
    WANMGR_IFACE_GROUP*  pWanIfaceGroup        = NULL;
    WANMGR_IFACE_GROUP*  pWanDmlGrp            = NULL;
    DML_VIRTUAL_IFACE*  p_VirtIf               = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);

    pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(SECONDARY_WAN_GROUP_INSTANCE - 1);
    if (pWanIfaceGroup != NULL)
    {
        pWanDmlGrp = pWanIfaceGroup;
        pWanDmlGrp->State = STATE_GROUP_RUNNING;

        WanMgrDml_GetIfaceGroup_release();
    }

    /*
     * BackupWan Transition_BackupWanInterfaceInActive: demote to SELECTED standby.
     * Tear FO routes via HandleWanChange but keep VirtIf Status/IP (standby ready).
     */
    pSecInterface->Selection.Status = WAN_IFACE_SELECTED;

    virtualIfaceCount = 1; /* VirtIfList via WanMgr_SecWan_GetDataVirtIf */
    for (vIfaceIdx = 0; vIfaceIdx < virtualIfaceCount; vIfaceIdx++)
    {
        p_VirtIf   = WanMgr_SecWan_GetDataVirtIf(pSecInterface);
        if ((NULL != p_VirtIf) && ((p_VirtIf->Alias[0] == '\0') || AnscEqualString(p_VirtIf->Alias, "DATA", TRUE) || (p_VirtIf == WanMgr_SecWan_GetDataVirtIf(pSecInterface))))
        {
            /*
             * Tear secondary defaults while ifname/gw are still valid. HandleWanChange(DOWN)
             * is iface-specific and safe with primary PHY UP. Skip UpdateDNS wipe —
             * primary owns resolv.conf once Group1 is restoring.
             */
            WanManager_HandleWanChange(pSecInterface, p_VirtIf, WAN_IFACE_IP_STATE_DOWN);
            if (WanMgr_SecWan_IsPrimaryPhysicallyDown() == TRUE)
            {
                WanManager_UpdateDNS(pSecInterface, p_VirtIf, WAN_IFACE_IP_STATE_DOWN);
            }

            p_VirtIf->IP.Ipv4ConnectivityStatus = WAN_CONNECTIVITY_DOWN;
            p_VirtIf->IP.Ipv6ConnectivityStatus = WAN_CONNECTIVITY_DOWN;
        }
    }

    (void)Update_Interface_Status();
    wanmgr_firewall_restart();

    CcspTraceInfo(("%s %d - State changed to STATE_SEC_WAN_INTERFACE_INACTIVE \n", __FUNCTION__, __LINE__));

    return STATE_SEC_WAN_INTERFACE_INACTIVE;
}

/**************************************************************************************
 * @brief Transition_SecondaryWanInterfaceDown()
 *      - Transition to STATE_SEC_WAN_INTERFACE_DOWN state
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR         : Error state
 *       - STATE_SEC_WAN_INTERFACE_DOWN: State interface down
 *************************************************************************************/
static WcSecWanPolicyState_t Transition_SecondaryWanInterfaceDown(WanMgr_Policy_Controller_t* pWanController)
{
    INT                  virtualIfaceCount     = 0;
    INT                  vIfaceIdx             = 0;
    DML_WAN_IFACE*       pSecInterface         = NULL;
    DML_VIRTUAL_IFACE*   p_VirtIf              = NULL;
    WANMGR_IFACE_GROUP*  pWanDmlGrp            = NULL;
    WANMGR_IFACE_GROUP*  pWanIfaceGroup        = NULL;
    CHAR                 time_buf[32]          = {0};
    const CHAR*          ifName                = NULL;
    BOOL                 tearedDown            = FALSE;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);

    /* BackupWan Transition_BackupWanInterfaceDown: publish status first. */
    (void)Update_Interface_Status();

    pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(SECONDARY_WAN_GROUP_INSTANCE - 1);
    if (pWanIfaceGroup != NULL)
    {
        pWanDmlGrp = pWanIfaceGroup;
        pWanDmlGrp->State = STATE_GROUP_RUNNING;

        WanMgrDml_GetIfaceGroup_release();
    }

    virtualIfaceCount = 1; /* VirtIfList via WanMgr_SecWan_GetDataVirtIf */
    for (vIfaceIdx = 0; vIfaceIdx < virtualIfaceCount; vIfaceIdx++)
    {
        p_VirtIf   = WanMgr_SecWan_GetDataVirtIf(pSecInterface);
        if ((NULL != p_VirtIf) && ((p_VirtIf->Alias[0] == '\0') || AnscEqualString(p_VirtIf->Alias, "DATA", TRUE) || (p_VirtIf == WanMgr_SecWan_GetDataVirtIf(pSecInterface))))
        {
            /* Tear routes while ifname/gw still valid, then reset VirtIf. */
            WanManager_HandleWanChange(pSecInterface, p_VirtIf, WAN_IFACE_IP_STATE_DOWN);
            if (WanMgr_SecWan_IsPrimaryPhysicallyDown() == TRUE)
            {
                WanManager_UpdateDNS(pSecInterface, p_VirtIf, WAN_IFACE_IP_STATE_DOWN);
            }

            WanManager_ClearIfaceAlias(p_VirtIf->Name);

            /* BackupWan teardown field updates. */
            pSecInterface->Selection.ActiveLink = FALSE;
            p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_DOWN;
            pSecInterface->Selection.Status = WAN_IFACE_NOT_SELECTED;
            p_VirtIf->Status = WAN_IFACE_STATUS_DISABLED;
            p_VirtIf->IP.Ipv4ConnectivityStatus = WAN_CONNECTIVITY_DOWN;
            p_VirtIf->IP.Ipv6ConnectivityStatus = WAN_CONNECTIVITY_DOWN;
            p_VirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_UNKNOWN;
            p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_UNKNOWN;
            memset(p_VirtIf->IP.Ipv6Data.address, 0, sizeof(p_VirtIf->IP.Ipv6Data.address));
            memset(p_VirtIf->IP.Ipv4Data.ip, 0, sizeof(p_VirtIf->IP.Ipv4Data.ip));
            memset(p_VirtIf->IP.Ipv4Data.gateway, 0, sizeof(p_VirtIf->IP.Ipv4Data.gateway));
            memset(p_VirtIf->IP.Ipv6RA.acDefaultGw, 0, sizeof(p_VirtIf->IP.Ipv6RA.acDefaultGw));

            ifName = (p_VirtIf->Name[0] != '\0') ? p_VirtIf->Name : pSecInterface->Name;
            if ((ifName != NULL) && (ifName[0] != '\0'))
            {
                WanMgr_Policy_CheckAndStopUDHCPClientOverWanInterface((CHAR *)ifName,
                                                                       BACKUP_WAN_DHCPC_PID_FILE);
            }
            tearedDown = TRUE;
            break;
        }
    }

    if (tearedDown == FALSE)
    {
        pSecInterface->Selection.ActiveLink = FALSE;
        pSecInterface->Selection.Status = WAN_IFACE_NOT_SELECTED;
    }

    (void)Update_Interface_Status();

    CcspTraceInfo(("%s %d - State changed to STATE_SEC_WAN_INTERFACE_DOWN \n", __FUNCTION__, __LINE__));
    wanmgr_firewall_restart();

    return STATE_SEC_WAN_INTERFACE_DOWN;
}

/*************************************************************************************/
/**************************** STATES *************************************************/
/*************************************************************************************/
/**************************************************************************************
 * @brief State_WaitingSecondaryWanInterface()
 *      - Wait for a secondary interface to come UP
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR            : Error state
 *       - STATE_SEC_WAN_AVAILABLE        : Secondary WAN link is UP
 *       - STATE_SEC_WAN_WAITING_INTERFACE: Current state
 *************************************************************************************/
static WcSecWanPolicyState_t State_WaitingSecondaryWanInterface(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE* pSecInterface = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);

    if(WanMgr_SecWan_IsIfaceLinkUp(pSecInterface) == TRUE)
    {
        return Transition_SecondaryWanAvailable(pWanController);
    }

    return STATE_SEC_WAN_WAITING_INTERFACE;
}

/**************************************************************************************
 * @brief State_SelectingSecondaryWanInterface()
 *      - Select the secondary group interface
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR              : Error state
 *       - STATE_SEC_WAN_WAITING_INTERFACE  : Wait for the selected interface to come UP
 *       - STATE_SEC_WAN_SELECTING_INTERFACE: Current state
 *************************************************************************************/
static WcSecWanPolicyState_t State_SelectingSecondaryWanInterface(WanMgr_Policy_Controller_t* pWanController)
{
    UINT                 totalWanIfaces   = 0;
    UINT                 uiLoopCount      = 0;
    WANMGR_IFACE_GROUP* /* was DML_WAN_GRP */         pWanDmlGrp       = NULL;
    DML_WAN_IFACE*       pWanIfaceData    = NULL;
    WANMGR_IFACE_GROUP*   pWanIfaceGroup   = NULL;
    WanMgr_Iface_Data_t* pWanDmlIfaceData = NULL;

    if (NULL == pWanController)
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    totalWanIfaces = WanMgr_IfaceData_GetTotalWanIface();

    for (uiLoopCount = 0; uiLoopCount < totalWanIfaces; uiLoopCount++)
    {
        pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(NULL != pWanDmlIfaceData)
        {
            pWanIfaceData = &(pWanDmlIfaceData->data);
            if(pWanController->GroupInst == pWanIfaceData->Selection.Group)
            {
                DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_SecWan_GetDataVirtIf(pWanIfaceData);

                pWanController->activeInterfaceIdx = uiLoopCount;

                /* BackupWan Transition_BackupWanInterfaceSelected reset. */
                pWanIfaceData->Selection.ActiveLink = FALSE;
                pWanIfaceData->Selection.Status = WAN_IFACE_NOT_SELECTED;
                if (p_VirtIf != NULL)
                {
                    p_VirtIf->VLAN.Status = WAN_IFACE_LINKSTATUS_DOWN;
                    p_VirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_UNKNOWN;
                    p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_UNKNOWN;
                    p_VirtIf->Status = WAN_IFACE_STATUS_DISABLED;
                }
                (void)Update_Interface_Status();

                CcspTraceInfo(("%s %d: Selecting interface(%s) index %d \n", __FUNCTION__, __LINE__, pWanIfaceData->Name, uiLoopCount));
                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
                break;
            }

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
    }

    if (pWanController->activeInterfaceIdx != -1)
    {
        /* Update the Group data */
        pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(pWanController->GroupInst - 1);
        if(NULL != pWanIfaceGroup)
        {
            pWanDmlGrp = pWanIfaceGroup;
            pWanDmlGrp->SelectedInterface = (1 + pWanController->activeInterfaceIdx);

            WanMgrDml_GetIfaceGroup_release();
        }
        (void)WanMgr_SetGroupSelectedIface(pWanController->GroupInst,
                                           (UINT)(pWanController->activeInterfaceIdx + 1));

        return STATE_SEC_WAN_WAITING_INTERFACE;
    }

    return STATE_SEC_WAN_SELECTING_INTERFACE;
}

/**************************************************************************************
 * @brief State_SecondaryWanInterfaceDown()
 *      - Secondary group interface is Down
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR         : Error state
 *       - STATE_SEC_WAN_AVAILABLE     : Secondary interface link is UP
 *       - STATE_SEC_WAN_INTERFACE_DOWN: Current state
 *************************************************************************************/
static WcSecWanPolicyState_t State_SecondaryWanInterfaceDown(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE* pSecInterface = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return  STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);

    if(WanMgr_SecWan_IsIfaceLinkUp(pSecInterface) == TRUE)
    {
        return Transition_SecondaryWanAvailable(pWanController);
    }

    return STATE_SEC_WAN_INTERFACE_DOWN;
}

/**************************************************************************************
 * @brief State_SecondaryWanAvailable()
 *      - State secondary group WAN is available
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR         : Error state
 *       - STATE_SEC_WAN_INTERFACE_DOWN: Secondary interface link Down
 *       - STATE_SEC_WAN_ACQUIRING_IP  : Primary Group1 PHY is Down — acquire secondary IP
 *       - STATE_SEC_WAN_AVAILABLE     : Current state
 *************************************************************************************/
static WcSecWanPolicyState_t State_SecondaryWanAvailable(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE* pSecInterface = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);

    if (WanMgr_SecWan_IsIfaceLinkUp(pSecInterface) == FALSE)
    {
        CcspTraceInfo(("%s secondary interface %s is down \n", __FUNCTION__, pSecInterface->Name));

        return Transition_SecondaryWanInterfaceDown(pWanController);
    }

    /* BackupWan-style: when no Group1 PHY is UP, start secondary IP. */
    if (WanMgr_SecWan_IsPrimaryPhysicallyDown() == TRUE)
    {
        CcspTraceInfo(("%s %d: Primary PHY down — acquiring secondary IP on %s\n",
                       __FUNCTION__, __LINE__, pSecInterface->Name));
        return Transition_SecondaryWanAcquiringIP(pWanController);
    }

    return STATE_SEC_WAN_AVAILABLE;
}

/**************************************************************************************
 * @brief State_SecondaryWanAcquiringIP()
 *      - State secondary group WAN acquiring IP
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR           : Error state
 *       - STATE_SEC_WAN_INTERFACE_DOWN  : Interface goes Down
 *       - STATE_SEC_WAN_INTERFACE_ACTIVE: Interface active with an IP
 *       - STATE_SEC_WAN_ACQUIRING_IP    : Current state
 *************************************************************************************/
static WcSecWanPolicyState_t State_SecondaryWanAcquiringIP(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE*     pSecInterface = NULL;
    DML_VIRTUAL_IFACE* p_VirtIf      = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);
    p_VirtIf = WanMgr_SecWan_GetDataVirtIf(pSecInterface);
    if (p_VirtIf == NULL)
    {
        return STATE_SEC_WAN_ERROR;
    }

    /* Handle secondary link-down event. */
    if (WanMgr_SecWan_IsIfaceLinkUp(pSecInterface) == FALSE)
    {
        CcspTraceInfo(("%s secondary interface %s is down \n", __FUNCTION__, pSecInterface->Name));
        return Transition_SecondaryWanInterfaceDown(pWanController);
    }

    /* Primary restored while we were acquiring — go back to AVAILABLE standby. */
    if (WanMgr_SecWan_IsPrimaryPhysicallyDown() == FALSE)
    {
        CcspTraceInfo(("%s %d: Primary PHY back up — abort secondary IP acquire\n",
                       __FUNCTION__, __LINE__));
        return Transition_SecondaryWanAvailable(pWanController);
    }

    /* Keep VirtIf addresses in sync; do not mark Status UP until Active apply. */
    WanMgr_SecWan_RefreshVirtIfIpData(pSecInterface, p_VirtIf);

    /* Ready when kernel has an address (or IpMonitor already set UP). */
    if ((p_VirtIf->IP.Ipv4Data.ip[0] != '\0') ||
        (p_VirtIf->IP.Ipv6Data.address[0] != '\0') ||
        (p_VirtIf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP) ||
        (p_VirtIf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP))
    {
        CcspTraceInfo(("%s: IP ready on %s (v4=%s v6=%s) — go ACTIVE\n",
                       __FUNCTION__, p_VirtIf->Name,
                       p_VirtIf->IP.Ipv4Data.ip, p_VirtIf->IP.Ipv6Data.address));
        return Transition_SecondaryWanInterfaceActive(pWanController);
    }

    return STATE_SEC_WAN_ACQUIRING_IP;
}

/**************************************************************************************
 * @brief State_SecondaryWanInterfaceActive()
 *      - State secondary group WAN interface is active with an IP
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR             : Error state
 *       - STATE_SEC_WAN_INTERFACE_DOWN    : Interface goes Down
 *       - STATE_SEC_WAN_INTERFACE_ACTIVE  : Interface is active with an IP
 *       - STATE_SEC_WAN_INTERFACE_INACTIVE: Primary group is active
 *************************************************************************************/
static WcSecWanPolicyState_t State_SecondaryWanInterfaceActive(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE*       pSecInterface            = NULL;
    INT                  virtualIfaceCount        = 0;
    INT                  vIfaceIdx                = 0;
    DML_VIRTUAL_IFACE*  p_VirtIf                 = NULL;
    static CHAR          Ipv6AddrPrev[BUFLEN_64]  = {0};
    static CHAR          Ipv6GWPrev[BUFLEN_64]    = {0};

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);

    /* Handle secondary link-down event. */
    if (WanMgr_SecWan_IsIfaceLinkUp(pSecInterface) == FALSE)
    {
        CcspTraceInfo(("%s : secondary interface %s is down \n", __FUNCTION__, pSecInterface->Name));

        memset(Ipv6AddrPrev, 0, sizeof(Ipv6AddrPrev));
        memset(Ipv6GWPrev, 0, sizeof(Ipv6GWPrev));

        return Transition_SecondaryWanInterfaceDown(pWanController);
    }

    virtualIfaceCount = 1; /* VirtIfList via WanMgr_SecWan_GetDataVirtIf */
    for (vIfaceIdx = 0; vIfaceIdx < virtualIfaceCount; vIfaceIdx++)
    {
        p_VirtIf = WanMgr_SecWan_GetDataVirtIf(pSecInterface);
        if ((NULL != p_VirtIf) && ((p_VirtIf->Alias[0] == '\0') || AnscEqualString(p_VirtIf->Alias, "DATA", TRUE) || (p_VirtIf == WanMgr_SecWan_GetDataVirtIf(pSecInterface))))
        {
            /* Refresh from iface while Active (Backup relies on IpMonitor + lease). */
            WanMgr_SecWan_RefreshVirtIfIpData(pSecInterface, p_VirtIf);

            /* IPv6 Handling — VirtIf filled in Acquiring / Transition_Active. */
            if ((WAN_IFACE_IPV6_STATE_UP != p_VirtIf->IP.Ipv6Status) &&
                ('\0' != p_VirtIf->IP.Ipv6Data.address[0]))
            {
                p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_UP;

                WanManager_HandleWanChange(pSecInterface, p_VirtIf, WAN_IFACE_IPV6_STATE);

                wanmgr_firewall_restart();
            }
            else if (WAN_IFACE_IPV6_STATE_UP == p_VirtIf->IP.Ipv6Status)
            {
                if ('\0' == p_VirtIf->IP.Ipv6Data.address[0])
                {
                    p_VirtIf->IP.Ipv6Status = WAN_IFACE_IPV6_STATE_DOWN;
                }

                /* IPv6 address and gateway can change independently — re-apply if either changes. */
                if ('\0' != p_VirtIf->IP.Ipv6Data.address[0])
                {
                    if ((!AnscEqualString(p_VirtIf->IP.Ipv6Data.address, Ipv6AddrPrev, TRUE)) ||
                        (!AnscEqualString(p_VirtIf->IP.Ipv6RA.acDefaultGw, Ipv6GWPrev, TRUE)))
                    {
                        /* Add IPv6 default route with metric 300 */
                        v_secure_system("ip -6 route replace default via %s dev %s metric 300", p_VirtIf->IP.Ipv6RA.acDefaultGw, p_VirtIf->Name);

                        WanManager_UpdateDNS(pSecInterface, p_VirtIf, WAN_IFACE_IPV6_STATE);

                        AnscCopyString(Ipv6AddrPrev, p_VirtIf->IP.Ipv6Data.address);
                        AnscCopyString(Ipv6GWPrev, p_VirtIf->IP.Ipv6RA.acDefaultGw);
                    }
                }
            }

            /* IPv4 Handling — apply once when status goes UP; Transition_Active already applied. */
            if ((WAN_IFACE_IPV4_STATE_UP != p_VirtIf->IP.Ipv4Status) &&
                ('\0' != p_VirtIf->IP.Ipv4Data.ip[0]))
            {
                p_VirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_UP;

                WanManager_HandleWanChange(pSecInterface, p_VirtIf, WAN_IFACE_IPV4_STATE);
                WanManager_UpdateDNS(pSecInterface, p_VirtIf, WAN_IFACE_IPV4_STATE);
            }
            else if ((WAN_IFACE_IPV4_STATE_UP == p_VirtIf->IP.Ipv4Status) &&
                     ('\0' == p_VirtIf->IP.Ipv4Data.ip[0]))
            {
                p_VirtIf->IP.Ipv4Status = WAN_IFACE_IPV4_STATE_DOWN;
                WanManager_UpdateDNS(pSecInterface, p_VirtIf, WAN_IFACE_IPV4_STATE);
            }
        }
    }

    /* Backup path: when Group1 PHY is UP again, demote secondary to inactive. */
    if (WanMgr_SecWan_IsPrimaryPhysicallyDown() == FALSE)
    {
        memset(Ipv6AddrPrev, 0, sizeof(Ipv6AddrPrev));
        memset(Ipv6GWPrev, 0, sizeof(Ipv6GWPrev));

        return Transition_SecondaryWanInterfaceInActive(pWanController);
    }

    return STATE_SEC_WAN_INTERFACE_ACTIVE;
}

/**************************************************************************************
 * @brief State_SecondaryWanInterfaceInActive()
 *      - State secondary group WAN interface is inactive
 * 
 * @param[in,out] pWanController Address of state machine policy control data
 * 
 * @return WcSecWanPolicyState_t
 *       - STATE_SEC_WAN_ERROR             : Error state
 *       - STATE_SEC_WAN_INTERFACE_DOWN    : Interface goes Down
 *       - STATE_SEC_WAN_ACQUIRING_IP      : Primary group is Down
 *       - STATE_SEC_WAN_INTERFACE_INACTIVE: Current state
 *************************************************************************************/
static WcSecWanPolicyState_t State_SecondaryWanInterfaceInActive(WanMgr_Policy_Controller_t* pWanController)
{
    DML_WAN_IFACE* pSecInterface = NULL;

    if ((NULL == pWanController) || (NULL == pWanController->pWanActiveIfaceData))
    {
        CcspTraceError(("%s %d: NULL Parameter!\n", __FUNCTION__, __LINE__));
        return STATE_SEC_WAN_ERROR;
    }

    pSecInterface = &(pWanController->pWanActiveIfaceData->data);
    if (WanMgr_SecWan_IsIfaceLinkUp(pSecInterface) == FALSE)
    {
        return Transition_SecondaryWanInterfaceDown(pWanController);
    }

    /* BackupWan-style: primary PHY down again → re-acquire secondary IP. */
    if (WanMgr_SecWan_IsPrimaryPhysicallyDown() == TRUE)
    {
        CcspTraceInfo(("%s %d: Primary PHY down — re-acquiring secondary IP\n",
                       __FUNCTION__, __LINE__));
        return Transition_SecondaryWanAcquiringIP(pWanController);
    }

    return STATE_SEC_WAN_INTERFACE_INACTIVE;
}

/*************************************************************************************/
/******************************** SM THREAD ******************************************/
/*************************************************************************************/
/**************************************************************************************
 * @brief Wanmgr_SecondaryWan_StateMachineThread()
 *      - Secondary group state machine thread function.
 *
 * @param[in] arg: Thread input data
 * 
 * @return ANSC_STATUS 
 *       - ANSC_STATUS_FAILURE: Error value
 *************************************************************************************/
static void *Wanmgr_SecondaryWan_StateMachineThread(VOID *arg)
{
    BOOL                       bRunning       = true;
    INT                        n              = 0;
    struct timeval             tv             = {0};
    WANMGR_IFACE_GROUP* /* was DML_WAN_GRP */               pWanDmlGrp     = NULL;
    WanMgr_Policy_Controller_t WanController  = {0};
    WcSecWanPolicyState_t      fmob_sm_state  = STATE_SEC_WAN_ERROR;
    WANMGR_IFACE_GROUP*         pWanIfaceGroup = NULL;
    unsigned long              groupInst      = (unsigned long)arg;

    pthread_detach(pthread_self());

    CcspTraceInfo(("%s %d group=%lu\n", __FUNCTION__, __LINE__, groupInst));

    if (groupInst == 0)
    {
        groupInst = SECONDARY_WAN_GROUP_INSTANCE;
    }

    /* Initialise state machine */
    if(ANSC_STATUS_SUCCESS != WanMgr_Controller_PolicyCtrlInit(&WanController))
    {
        CcspTraceError(("%s %d Policy Controller Error \n", __FUNCTION__, __LINE__));
        WanMgr_SecWan_MarkGroupStopped((UINT)groupInst);
        return NULL;
    }

    WanController.GroupInst = (UINT)groupInst;

    /* Initialize Group Data */
    pWanIfaceGroup = WanMgr_GetIfaceGroup_locked(WanController.GroupInst - 1);
    if(NULL != pWanIfaceGroup)
    {
        pWanDmlGrp = pWanIfaceGroup;
        pWanDmlGrp->State             = STATE_GROUP_RUNNING;
        pWanDmlGrp->SelectedInterface = 0;
        pWanDmlGrp->InitialScanComplete = TRUE;

        WanMgrDml_GetIfaceGroup_release();
    }

    fmob_sm_state = Transition_StartSecondaryWan(&WanController);

    while (bRunning)
    {
        /* Wait up to 500 milliseconds */
        tv.tv_sec  = 0;
        tv.tv_usec = LOOP_TIMEOUT;

        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }

        if(WanController.activeInterfaceIdx != -1 && WanController.pWanActiveIfaceData == NULL)
        {
            /* Lock Iface Data & update selected iface data in controller data */
            WanController.pWanActiveIfaceData = WanMgr_GetIfaceData_locked(WanController.activeInterfaceIdx);
        }

        /* process state */
        switch (fmob_sm_state)
        {
            case STATE_SEC_WAN_SELECTING_INTERFACE:
                fmob_sm_state = State_SelectingSecondaryWanInterface(&WanController);
                break;
            case STATE_SEC_WAN_WAITING_INTERFACE:
                fmob_sm_state = State_WaitingSecondaryWanInterface(&WanController);
                break;
            case STATE_SEC_WAN_INTERFACE_DOWN:
                fmob_sm_state = State_SecondaryWanInterfaceDown(&WanController);
                break;
            case STATE_SEC_WAN_AVAILABLE:
                fmob_sm_state = State_SecondaryWanAvailable(&WanController);
                break;
            case STATE_SEC_WAN_ACQUIRING_IP:
                fmob_sm_state = State_SecondaryWanAcquiringIP(&WanController);
                break;
            case STATE_SEC_WAN_INTERFACE_ACTIVE:
                fmob_sm_state = State_SecondaryWanInterfaceActive(&WanController);
                break;
            case STATE_SEC_WAN_INTERFACE_INACTIVE:
                fmob_sm_state = State_SecondaryWanInterfaceInActive(&WanController);
                break;
            case STATE_SEC_WAN_EXIT:
            case STATE_SEC_WAN_ERROR:
            default:
                CcspTraceInfo(("%s %d - Case: default/exit state=%d\n", __FUNCTION__, __LINE__, fmob_sm_state));
                bRunning = false;
                break;
        }

        /* Release Lock Iface Data */
        if(WanController.pWanActiveIfaceData != NULL)
        {
            WanMgrDml_GetIfaceData_release(WanController.pWanActiveIfaceData);
            WanController.pWanActiveIfaceData = NULL;
        }
    }

    WanMgr_SecWan_MarkGroupStopped(WanController.GroupInst);
    CcspTraceInfo(("%s %d - Exit from state machine group %u\n",
                   __FUNCTION__, __LINE__, WanController.GroupInst));

    return NULL;
}

/*
 * FO entry point (SECWAN_MODE)
 */
void *WanMgr_SecWanSelectionProcess(void *arg)
{
    return Wanmgr_SecondaryWan_StateMachineThread(arg);
}

/**************************************************************************************
 * @brief WanMgr_Policy_SecondaryWan()
 *      - Secondary group state machine thread start function.
 * 
 * @return ANSC_STATUS
 *       - ANSC_STATUS_SUCCESS State machine start success
 *       - ANSC_STATUS_FAILURE Failed to start state machine
 *************************************************************************************/
ANSC_STATUS WanMgr_Policy_SecondaryWan(VOID)
{
    INT         pthread_ret         = 0;
    ANSC_STATUS retStatus           = ANSC_STATUS_FAILURE;
    pthread_t   secondaryWanThread;

    /* Initiate the thread for Secondary WAN policy (Group 2) */
    pthread_ret = pthread_create(&secondaryWanThread, NULL, &Wanmgr_SecondaryWan_StateMachineThread,
                                 (VOID*)(unsigned long)SECONDARY_WAN_GROUP_INSTANCE);
    if (0 != pthread_ret)
    {
        CcspTraceError(("%s %d - Failed to start Secondary policy State Machine. Thread-pthread error code = %d!\n", __FUNCTION__, __LINE__, pthread_ret));
        retStatus = ANSC_STATUS_FAILURE;
    }
    else
    {
        CcspTraceInfo(("%s %d - Secondary Policy State Machine Thread Started Successfully!\n", __FUNCTION__, __LINE__));
        retStatus = ANSC_STATUS_SUCCESS;
    }

    return retStatus;
}
