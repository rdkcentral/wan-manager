/*********************************************************************************
 If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 Deutsche Telekom AG.
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
#include "wanmgr_mape.h"
#include <arpa/inet.h> /* for inet_pton */
#include <sysevent/sysevent.h>
#include "wanmgr_sysevents.h"
#include "ansc_platform.h"
#include <syscfg/syscfg.h>
#include "secure_wrapper.h"
#include "wanmgr_dhcpv6_apis.h"

#ifdef FEATURE_MAPE

ANSC_STATUS WanManager_MAPEConfiguration(ipc_map_data_t *dhcp6cMAPEMsgBody, const WANMGR_IPV6_DATA *ipv6Data)
{
    INT ret = 0;
    INT v4_prefix_len = 0, v6_prefix_len = 0, psid_offset = 0, pd_length = 0;
    INT ea_len = 0;
    UINT ipv4IndexValue = 0, psidLen = 0, ipValue = 0;
    UINT mask                       = 0;
    USHORT psidValue                = 0;
    CHAR *save_opt                  = NULL;
    CHAR *ptr                       = NULL;
    struct in_addr result           = {0};
    struct in6_addr in6             = {0};
    CHAR mape_ipv4_addr[BUFLEN_16]  = {0};
    CHAR ipAddressString[BUFLEN_32] = {0};
    CHAR charBuff[BUFLEN_32]        = {0};
    CHAR v4_prefix[BUFLEN_64]       = {0};
    CHAR tunnel_source[BUFLEN_64]   = {0};
    CHAR v6_prefix[BUFLEN_128]      = {0};
    CHAR br_prefix[BUFLEN_128]      = {0};
    CHAR pd_prefix[BUFLEN_128]      = {0};
    CHAR pd_ipv6_prefix[BUFLEN_128] = {0};
    CHAR br_ipv6_prefix[BUFLEN_128] = {0};
    UCHAR ipAddressBytes[BUFLEN_4]  = {0};
    const char *vlanIf = ipv6Data->ifname;

    /* Set default values for map syscfg parameters */
    WanManager_MAPE_ResetSyscfgDefaults();

    ea_len      = dhcp6cMAPEMsgBody->eaLen;
    psid_offset = dhcp6cMAPEMsgBody->psidOffset;
    v4_prefix_len = dhcp6cMAPEMsgBody->v4Len;
    v6_prefix_len = dhcp6cMAPEMsgBody->v6Len;
    AnscCopyString(v4_prefix, dhcp6cMAPEMsgBody->ruleIPv4Prefix);
    AnscCopyString(v6_prefix, dhcp6cMAPEMsgBody->ruleIPv6Prefix);
    AnscCopyString(br_prefix, dhcp6cMAPEMsgBody->brIPv6Prefix);

    //Get IAPD and v6 length
    sysevent_get(sysevent_fd, sysevent_token,"ipv6_prefix", pd_prefix, sizeof(pd_prefix));

    if(strlen(pd_prefix) == 0)
    {
        CcspTraceError(("%s: %d ipv6_prefix is empty \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    ptr = strtok_r(pd_prefix, "/", &save_opt);
    snprintf(pd_ipv6_prefix, sizeof(pd_ipv6_prefix), "%s", ptr);
    pd_length = atoi(save_opt);

    ptr      = NULL;
    save_opt = NULL;
    ptr      = strtok_r(br_prefix, "/", &save_opt);
    snprintf(br_ipv6_prefix, sizeof(br_ipv6_prefix), "%s", ptr);

    //Calculate PSID
    WanManager_CalculateMAPEPsid(pd_ipv6_prefix, v6_prefix_len, v4_prefix_len, ea_len, &psidValue, &ipv4IndexValue, &psidLen);
    dhcp6cMAPEMsgBody->psidLen = psidLen;
    dhcp6cMAPEMsgBody->psid    = psidValue;

    //MAP-E IPv4 Address
    inet_pton(AF_INET,v4_prefix, &(result));
    ipValue = htonl(result.s_addr);

    /* Calculate tunnel IPv4 address by embedding suffix bits from EA bits */
    mask = (1 << (ea_len-psidLen)) - 1;
    ipValue = ipValue & ~mask;
    ipValue |= ipv4IndexValue;

    ipAddressBytes[0] = ipValue & 0xFF;
    ipAddressBytes[1] = (ipValue >> 8) & 0xFF;
    ipAddressBytes[2] = (ipValue >> 16) & 0xFF;
    ipAddressBytes[3] = (ipValue >> 24) & 0xFF;

    snprintf(ipAddressString, sizeof(ipAddressString), "%d.%d.%d.%d", ipAddressBytes[3], ipAddressBytes[2], ipAddressBytes[1], ipAddressBytes[0]);

    inet_pton(AF_INET6, pd_ipv6_prefix, &in6);
    strcpy(mape_ipv4_addr, ipAddressString);
    in6.s6_addr16[7] = htons(psidValue);
    in6.s6_addr16[5] = inet_addr(mape_ipv4_addr) & 0x0000ffff;
    in6.s6_addr16[6] = inet_addr(mape_ipv4_addr) >> 16;
    in6.s6_addr16[4] = 0;
    inet_ntop(AF_INET6, &in6, tunnel_source, sizeof(tunnel_source));

    //tunnel_source
    ret = v_secure_system("ip -6 tunnel add %s mode ip4ip6 remote %s local %s encaplimit none dev %s", TUNNEL_NAME, br_ipv6_prefix, tunnel_source, vlanIf);
    if(ret)
    {
	CcspTraceError(("%s: %d Couldn't create the MAPE tunnel interface\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    ret = v_secure_system("ifconfig %s add %s/128", TUNNEL_NAME, tunnel_source);
    if(ret)
    {
       CcspTraceError(("%s: %d Couldn't add tunnel source\n", __FUNCTION__, __LINE__));
       return ANSC_STATUS_FAILURE;
    }

    ret = v_secure_system("ifconfig %s mtu %d", TUNNEL_NAME, TUNNEL_MTU);
    if(ret)
    {
	CcspTraceError(("%s: %d Couldn't add tunnel mtu\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    ret = v_secure_system("ip link set dev %s up", TUNNEL_NAME);
    if(ret)
    {
	CcspTraceError(("%s: %d Couldn't bring tunnel interface up\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    ret = v_secure_system("ifconfig %s %s netmask 255.255.255.255", TUNNEL_NAME, mape_ipv4_addr);
    if(ret)
    {
	CcspTraceError(("%s: %d Couldn't update the netmask for tunnel interface\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    v_secure_system("ip route add to default dev %s", TUNNEL_NAME);

    /* Generate syscfg for psid_offset,psidValue,psidLen,ipAddressString,mape_config_flag to use in firewall.c */
    snprintf(charBuff, sizeof(charBuff), "%d", psid_offset);
    if ( syscfg_set(NULL, "mape_psid_offset", charBuff) != 0 )
    {
        CcspTraceError(("%s: syscfg_set failed for parameter mape_psid_offset\n", __FUNCTION__));
    }

    memset(charBuff, 0, sizeof(charBuff));
    snprintf(charBuff, sizeof(charBuff), "%d", psidValue);
    if ( syscfg_set(NULL, "mape_psid", charBuff) != 0 )
    {
        CcspTraceError(("%s: syscfg_set failed for parameter mape_psid\n", __FUNCTION__));
    }

    memset(charBuff, 0, sizeof(charBuff));
    snprintf(charBuff, sizeof(charBuff), "%d", psidLen);
    if ( syscfg_set(NULL, "mape_psid_len", charBuff) != 0 )
    {
        CcspTraceError(("%s: syscfg_set failed for parameter mape_psid_len\n", __FUNCTION__));
    }

    if ( syscfg_set(NULL, "mape_ipv4_address", ipAddressString) != 0 )
    {
        CcspTraceError(("%s: syscfg_set failed for parameter mape_ipv4_address\n", __FUNCTION__));
    }

    if ( syscfg_set(NULL, "mape_config_flag", "true") != 0 )
    {
        CcspTraceError(("%s: syscfg_set failed for parameter mape_config_flag\n", __FUNCTION__));
    }

    v_secure_system("/bin/echo '%d,%d,%u' > /proc/nat_port", psid_offset, psidLen, psidValue);

    //Restart firewall
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);
    sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_IGD_RESTART, NULL, 0);

    return ANSC_STATUS_SUCCESS;
}

INT WanManager_CalculateMAPEPsid
    (
        CHAR *pdIPv6Prefix,
        INT v6PrefixLen,
        INT v4PrefixLen,
        INT ea_length,
        USHORT *psidValue,
        UINT *ipv4IndexValue,
        UINT *psidLen
    )
{
    INT  ret                 = RETURN_OK;
    UINT ea_bytes            = 0;
    UINT v4_suffix           = 0;
    UINT psid                = 0;
    INT  ea_offset_byte      = 0;
    INT  ea_offset_remainder = 0;
    INT  bitIndex            = 0;
    INT  psid_len            = 0;
    INT  byteIndex           = 0;
    struct in6_addr in6      = {0};

    ea_offset_byte      = v6PrefixLen/8;
    ea_offset_remainder = v6PrefixLen%8;
    psid_len            = ea_length - (IPV4_ADDR_LEN_IN_BITS - v4PrefixLen);

    inet_pton(AF_INET6, pdIPv6Prefix, &in6);

    for(byteIndex = 0; byteIndex < 4; byteIndex++)
    {
        ea_bytes |= in6.s6_addr[ea_offset_byte + byteIndex]<<(4 - byteIndex - 1)*8;
    }

    if(ea_offset_remainder)
    {
        ea_bytes = ea_bytes<<ea_offset_remainder;
    }

    ea_bytes        = ea_bytes>>(IPV4_ADDR_LEN_IN_BITS - ea_length);
    v4_suffix       = ea_bytes>>psid_len;
    psid            = ea_bytes^(v4_suffix<<psid_len);
    *psidValue      = (USHORT)(psid);
    *ipv4IndexValue = v4_suffix;
    *psidLen        = psid_len;

    return ret;
}

VOID WanManager_MAPE_ResetSyscfgDefaults(VOID)
{
    syscfg_unset (NULL, "mape_config_flag");
    syscfg_unset (NULL, "mape_psid_offset");
    syscfg_unset (NULL, "mape_psid");
    syscfg_unset (NULL, "mape_psid_len");
    syscfg_unset (NULL, "mape_ipv4_address");
}
#endif
