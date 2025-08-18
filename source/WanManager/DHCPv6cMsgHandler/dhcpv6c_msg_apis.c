/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sysevent/sysevent.h>

#include "ccsp_psm_helper.h"
#include "ansc_platform.h"
#include <syscfg/syscfg.h>
#include "ccsp_psm_helper.h"
#include "sys_definitions.h"
#include "secure_wrapper.h"

#include "wanmgr_dml.h"
#include "wanmgr_data.h"
#include "dhcpv6c_msg_apis.h"
#include "wanmgr_telemetry.h"

/*
 * Macro definitions
 */

#define STRING_TO_HEX(pStr) ( (pStr-'a'<0)? (pStr-'A'<0)? pStr-'0' : pStr-'A'+10 : pStr-'a'+10 )

#define ERR_CHK(x) 
#define CCSP_COMMON_FIFO                             "/tmp/ccsp_common_fifo"

extern int sysevent_fd;
extern token_t sysevent_token;

/*
 * Static function prototypes
 */
#if defined (MAPT_UNIFICATION_ENABLED)
static RETURN_STATUS CosaDmlMaptParseResponse (PUCHAR pOptionBuf, UINT16 uiOptionBufLen);
static RETURN_STATUS CosaDmlMaptGetIPv6StringFromHex (PUCHAR pIPv6AddrH, PCHAR pIPv6AddrS);
static RETURN_STATUS CosaDmlMaptConvertStringToHexStream (PUCHAR pOptionBuf, PUINT16 uiOptionBufLen);
/*
 * Global definitions
 */
static COSA_DML_MAPT_DATA   g_stMaptData;

/*
 * Static function definitions
 */
static RETURN_STATUS
CosaDmlMaptGetIPv6StringFromHex
(
    PUCHAR         pIPv6AddrH,
    PCHAR          pIPv6AddrS
)
{
  int rc  = -1;
  MAPT_LOG_INFO("Entry");

  if ( !(pIPv6AddrH && pIPv6AddrS) )
  {
       MAPT_LOG_ERROR("NULL inputs(%s - %s) for IPv6 hex to string conversion!",
                       pIPv6AddrH, pIPv6AddrS);
       return STATUS_FAILURE;
  }

  rc = memset(pIPv6AddrS, 0, BUFLEN_40);
  ERR_CHK(rc);

  if ( !inet_ntop(AF_INET6, pIPv6AddrH, pIPv6AddrS, BUFLEN_40) )
  {
       MAPT_LOG_ERROR("Invalid IPv6 hex address");
       return STATUS_FAILURE;
  }

  return STATUS_SUCCESS;
}

static RETURN_STATUS
CosaDmlMaptParseResponse
(
    PUCHAR         pOptionBuf,
    UINT16         uiOptionBufLen
)
{
  RETURN_STATUS retStatus = STATUS_SUCCESS;
  PCOSA_DML_MAPT_OPTION  pStartBuf  = NULL;
  PCOSA_DML_MAPT_OPTION  pNxtOption = NULL;
  PCOSA_DML_MAPT_OPTION  pEndBuf    = NULL;
  UINT16  uiOptionLen = 0;
  UINT16  uiOption    = 0;
  PUCHAR  pCurOption  = 0;
  int rc = -1;

  MAPT_LOG_INFO("Entry");

  if ( !(pOptionBuf && *(pOptionBuf+1)) )
  {
       MAPT_LOG_ERROR("MAPT Option-95 Response is NULL !!");
       return STATUS_FAILURE;
  }

  pStartBuf = (PCOSA_DML_MAPT_OPTION)pOptionBuf;
  pEndBuf   = (PCOSA_DML_MAPT_OPTION)((PCHAR)pOptionBuf + uiOptionBufLen);
MAPT_LOG_INFO("<<<TRACE>>> Start : %p | End : %p", pStartBuf,pEndBuf);
  for ( ;pStartBuf + 1 <= pEndBuf; pStartBuf = pNxtOption )
  {
       uiOptionLen = ntohs(pStartBuf->OptLen);
       uiOption    = ntohs(pStartBuf->OptType);

       pCurOption  = (PUCHAR)(pStartBuf + 1);
       pNxtOption  = (PCOSA_DML_MAPT_OPTION)(pCurOption + uiOptionLen);
       MAPT_LOG_INFO("<<<TRACE>>> Cur : %p | Nxt : %p", pCurOption,pNxtOption);
       MAPT_LOG_INFO("<<<TRACE>>> Opt : %u | OpLen : %u", uiOption,uiOptionLen);

       /* option length field overrun */
       if ( pNxtOption > pEndBuf )
       {
            MAPT_LOG_ERROR("Malformed MAP options!");
            retStatus = STATUS_FAILURE; //STATUS_BAD_PAYLOAD
            break;
       }

       switch ( uiOption )
       {
            case MAPT_OPTION_S46_RULE:
            {
               UINT8 bytesLeftOut  = 0;
               UINT8 v6ByteLen     = 0;
               UINT8 v6BitLen      = 0;
               UCHAR v6Addr[BUFLEN_24];

               g_stMaptData.bFMR    = (*pCurOption & 0x01)? TRUE : FALSE;
               g_stMaptData.EaLen   =  *++pCurOption;
               g_stMaptData.RuleIPv4PrefixLen =  *++pCurOption;
               pCurOption++;

               rc = snprintf (g_stMaptData.RuleIPv4Prefix, sizeof(g_stMaptData.RuleIPv4Prefix),
                               "%d.%d.%d.%d",
                               pCurOption[0], pCurOption[1], pCurOption[2], pCurOption[3]);
               ERR_CHK(rc);

               g_stMaptData.RuleIPv6PrefixLen = *(pCurOption += 4);
               v6ByteLen = g_stMaptData.RuleIPv6PrefixLen / 8;
               v6BitLen  = g_stMaptData.RuleIPv6PrefixLen % 8;
               pCurOption++;

               rc = memset (&v6Addr, 0, sizeof(v6Addr));
               ERR_CHK(rc);
               rc = memcpy (&v6Addr,  pCurOption, (v6ByteLen+(v6BitLen?1:0))*sizeof(CHAR));
               ERR_CHK(rc);

               if ( v6BitLen )
               {
                    *((PCHAR)&v6Addr + v6ByteLen) &= 0xFF << (8 - v6BitLen);
               }

               rc = memcpy (&g_stMaptData.RuleIPv6PrefixH, v6Addr,
                                                         (v6ByteLen+(v6BitLen?1:0))*sizeof(CHAR));
               ERR_CHK(rc);
               CosaDmlMaptGetIPv6StringFromHex (g_stMaptData.RuleIPv6PrefixH,
                       g_stMaptData.RuleIPv6Prefix);
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.bFMR              : %d", g_stMaptData.bFMR);
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.EaLen             : %u", g_stMaptData.EaLen);
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.RuleIPv4PrefixLen : %u", g_stMaptData.RuleIPv4PrefixLen);
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.RuleIPv4Prefix    : %s", g_stMaptData.RuleIPv4Prefix);
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.RuleIPv6PrefixLen : %u", g_stMaptData.RuleIPv6PrefixLen);
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.RuleIPv6Prefix    : %s", g_stMaptData.RuleIPv6Prefix);
               MAPT_LOG_INFO("Parsing OPTION_S46_RULE Successful.");

               /*
                * check port parameter option:
                * prefix6_len, located at 8th byte in rule option, specifies
                * the length of following v6prefix. So the length of port
                * param option, if any, must be rule_opt_len minus 8 minus v6ByteLen minus (1 or 0)
                */
               bytesLeftOut = uiOptionLen - 8 - v6ByteLen - (v6BitLen?1:0);

               g_stMaptData.Ratio = 1 << (g_stMaptData.EaLen -
                                                    (BUFLEN_32 - g_stMaptData.RuleIPv4PrefixLen));
               /* RFC default */
               g_stMaptData.PsidOffset = 6;
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.Ratio             : %u", g_stMaptData.Ratio);
               MAPT_LOG_INFO("<<<TRACE>>> bytesLeftOut                   : %u", bytesLeftOut);
               if ( bytesLeftOut > 0 )
               {
                    /* this rule option includes port param option */
                    if ( bytesLeftOut == 8 ) // Only support one port param option per rule option
                    {
                         UINT16 uiSubOptionLen = 0;
                         UINT16 uiSubOption    = 0;

                         pCurOption += v6ByteLen + (v6BitLen?1:0);
                         uiSubOptionLen = ntohs(((PCOSA_DML_MAPT_OPTION)pCurOption)->OptLen);
                         uiSubOption    = ntohs(((PCOSA_DML_MAPT_OPTION)pCurOption)->OptType);

                         if ( uiSubOption == MAPT_OPTION_S46_PORT_PARAMS &&
                              uiSubOptionLen == 4 )
                         {
                              g_stMaptData.PsidOffset  = (*(pCurOption += uiSubOptionLen))?
                                                                 *pCurOption:6;
                              g_stMaptData.PsidLen     = *++pCurOption;

                              if ( !g_stMaptData.EaLen )
                              {
                                   g_stMaptData.Ratio = 1 << g_stMaptData.PsidLen;
                              }
                              /*
                               * RFC 7598: 4.5: 16 bits long. The first k bits on the left of
                               * this field contain the PSID binary value. The remaining (16 - k)
                               * bits on the right are padding zeros.
                               */
                              g_stMaptData.Psid = ntohs(*((PUINT16)++pCurOption)) >>
                                  (16 - g_stMaptData.PsidLen);
                              MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.Psid       : %u", g_stMaptData.Psid);
                              MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.PsidLen    : %u", g_stMaptData.PsidLen);
                              MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.PsidOffset : %u", g_stMaptData.PsidOffset);
                              MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.Ratio      : %u", g_stMaptData.Ratio);
                              MAPT_LOG_INFO("Parsing OPTION_S46_PORT_PARAM Successful.");
                         }
                         else
                         {
                              MAPT_LOG_WARNING("OPTION_S46_PORT_PARAM option length(%d) varies!"
                                              , uiSubOptionLen);
                         }
                    }
                    else
                    {
                         MAPT_LOG_WARNING("Port param option length(%d) not equal to 8"
                                         , bytesLeftOut);
                    }
               }
               break;
            }

            case MAPT_OPTION_S46_BR:
            {
               MAPT_LOG_WARNING("Parsing OPTION_S46_BR is not supported !");
               //retStatus = STATUS_NOT_SUPPORTED;
               break;
            }

            case MAPT_OPTION_S46_DMR:
            {
               UCHAR ipv6Addr[BUFLEN_24];

               g_stMaptData.BrIPv6PrefixLen = *pCurOption++;

               /* RFC 6052: 2.2: g_stMaptData.BrIPv6PrefixLen%8 must be 0! */
               rc = memset (&ipv6Addr, 0, sizeof(ipv6Addr));
               ERR_CHK(rc);
               rc = memcpy (&ipv6Addr, pCurOption, g_stMaptData.BrIPv6PrefixLen/8);
               ERR_CHK(rc);

               CosaDmlMaptGetIPv6StringFromHex (ipv6Addr, g_stMaptData.BrIPv6Prefix);
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.BrIPv6PrefixLen : %u", g_stMaptData.BrIPv6PrefixLen);
               MAPT_LOG_INFO("<<<TRACE>>> g_stMaptData.BrIPv6Prefix    : %s", g_stMaptData.BrIPv6Prefix);
               MAPT_LOG_INFO("Parsing OPTION_S46_DMR Successful.");
               break;
            }

            default:
               MAPT_LOG_ERROR("Unknown or unexpected MAP option : %d | option len : %d"
                             , uiOption, uiOptionLen);
               //retStatus = STATUS_NOT_SUPPORTED;
               break;
       }
  }

  /* Check a parameter from each mandatory options */
  if ( !g_stMaptData.RuleIPv6PrefixLen || !g_stMaptData.BrIPv6PrefixLen)
  {
       MAPT_LOG_ERROR("Mandatory mapt options are missing !");
       retStatus = STATUS_FAILURE;
  }

  return retStatus;
}


static RETURN_STATUS
CosaDmlMaptConvertStringToHexStream
(
    PUCHAR         pWriteBf,
    PUINT16        uiOptionBufLen
)
{
  PUCHAR pReadBf  = pWriteBf;
  MAPT_LOG_INFO("Entry");

  if ( !pWriteBf )
  {
       MAPT_LOG_ERROR("MAPT string buffer is empty !!");
       return STATUS_FAILURE;
  }

  if ( *pReadBf == '\'' && pReadBf++ ) {}

  if ( pReadBf[strlen((PCHAR)pReadBf)-1] == '\'' )
  {
       pReadBf[strlen((PCHAR)pReadBf)-1] = '\0';
  }

  MAPT_LOG_INFO("<<<Trace>>> pOptionBuf is %p : %s",pReadBf, pReadBf);
  while ( *pReadBf && *(pReadBf+1) )
  {
      if ( *pReadBf == ':' && pReadBf++ ) {}

      *pWriteBf  = (STRING_TO_HEX(*pReadBf) << 4) | STRING_TO_HEX(*(pReadBf+1));

      ++pWriteBf;
      ++pReadBf;
      ++pReadBf;
      ++*uiOptionBufLen;
  }
  *pWriteBf = '\0';
  MAPT_LOG_INFO("<<<Trace>>> BufLen : %d", *uiOptionBufLen);

  return STATUS_SUCCESS;
}

static RETURN_STATUS
CosaDmlMaptValidate
(
    PCHAR          pPdIPv6Prefix,
    UINT16         ui16PdPrefixLen,
    UINT16         ui16v6PrefixLen,
    UINT16         ui16v4PrefixLen,
    UINT32         ui32PsidOffset
)
{
  UINT8 ui8v4BitIdxLen = 0, ui8PsidBitIdxLen = 0;
  UINT8 ui8EaLen       = 0 ;
  struct in6_addr ipv6Addr;

  MAPT_LOG_INFO("Entry");

  // V4 suffix bits length
  ui8v4BitIdxLen = BUFLEN_32 - ui16v4PrefixLen;

  // EA bits length
  ui8EaLen = ui16PdPrefixLen - ui16v6PrefixLen;

  // PSID length
  ui8PsidBitIdxLen = ui8EaLen - ui8v4BitIdxLen;

  MAPT_LOG_INFO("<<<Trace>>> ui8v4BitIdxLen(IPV4 Suffix Bits): %u", ui8v4BitIdxLen);
  MAPT_LOG_INFO("<<<Trace>>> ui8EaLen (EA bits)                    : %u", ui8EaLen);
  MAPT_LOG_INFO("<<<Trace>>> ui8PsidBitIdxLen(PSID length)         : %u", ui8PsidBitIdxLen);

  if (ui8EaLen != g_stMaptData.EaLen)
  {
       MAPT_LOG_INFO("Calculated EA-bits and received MAP EA-bits does not match!");
       return STATUS_FAILURE;
  }

  if ( ui16PdPrefixLen < ui16v6PrefixLen )
  {
       MAPT_LOG_ERROR("Invalid MAPT option, ui16PdPrefixLen(%d) < ui16v6PrefixLen(%d)",
               ui16PdPrefixLen, ui16v6PrefixLen);
       return STATUS_FAILURE;
  }

  if ( inet_pton(AF_INET6, pPdIPv6Prefix, &ipv6Addr) <= 0 )
  {
       MAPT_LOG_ERROR("Invalid IPv6 address = %s", pPdIPv6Prefix);
       return STATUS_FAILURE;
  }

   MAPT_LOG_INFO("MAPT validation successful.");
  return STATUS_SUCCESS;
}

/**
 * @brief Parses the MAPT option 95 response.
 *
 * This function processes the MAPT option 95 response, extracts the relevant information and updates ipc_dhcpv6_data_t struct with mapt details
 *
 * @param[in] pPdIPv6Prefix Pointer to the IPv6 prefix.
 * @param[in] pOptionBuf Pointer to the buffer containing the option 95 data.
 * @param[out] dhcpv6_data Pointer to the structure where the parsed DHCPv6 data will be stored.
 *
 * @return ANSC_STATUS indicating the success or failure of the operation.
 */

ANSC_STATUS WanMgr_MaptParseOpt95Response
(
    PCHAR          pPdIPv6Prefix,
    PUCHAR         pOptionBuf,
    ipc_dhcpv6_data_t *dhcpv6_data
)
{
  RETURN_STATUS ret = STATUS_SUCCESS;
  UINT16  uiOptionBufLen = 0;
  int rc = -1;

  MAPT_LOG_INFO("Entry");

  /* Convert the received string buffer into hex stream */
  rc = memset (&g_stMaptData, 0, sizeof(g_stMaptData));
  ERR_CHK(rc);
  if ( CosaDmlMaptConvertStringToHexStream (pOptionBuf, &uiOptionBufLen) != STATUS_SUCCESS )
  {
       MAPT_LOG_ERROR("MAPT string buffer to HexStream conversion Failed !!");
       ret = STATUS_FAILURE;
  }

  /* Store IPv6 prefix and length */
  rc = memcpy (&g_stMaptData.PdIPv6Prefix, pPdIPv6Prefix,
                                              (strchr(pPdIPv6Prefix, '/') - pPdIPv6Prefix));
  ERR_CHK(rc);
  g_stMaptData.PdIPv6PrefixLen = strtol((strchr(pPdIPv6Prefix, '/') + 1), NULL, 10);
  MAPT_LOG_INFO("<<<Trace>>> Received PdIPv6Prefix : %s/%u", g_stMaptData.PdIPv6Prefix
                                                         , g_stMaptData.PdIPv6PrefixLen);
  if ( !ret && !g_stMaptData.PdIPv6Prefix[0] )
  {
       MAPT_LOG_ERROR("PdIPv6Prefix is NULL !!");
       ret = STATUS_FAILURE;
  }

  /* Parse the hex buffer for mapt options */
  if ( !ret && CosaDmlMaptParseResponse (pOptionBuf, uiOptionBufLen) != STATUS_SUCCESS )
  {
       MAPT_LOG_ERROR("MAPT Parsing Response Failed !!");
       ret = STATUS_FAILURE;
  }

  /* validate MAPT responce */
  if ( !ret && CosaDmlMaptValidate ( g_stMaptData.PdIPv6Prefix
                                                   , g_stMaptData.PdIPv6PrefixLen
                                                   , g_stMaptData.RuleIPv6PrefixLen
                                                   , g_stMaptData.RuleIPv4PrefixLen , 
                                                g_stMaptData.PsidOffset) != STATUS_SUCCESS )
  {
       MAPT_LOG_ERROR("MAPT Psid and IPv4 Suffix Validation Failed !!");
       rc = memset (&g_stMaptData, 0, sizeof(g_stMaptData));
       ERR_CHK(rc);
       ret = STATUS_FAILURE;
  }


  if( ret == STATUS_SUCCESS )
  {
     //Fill Required MAP-T information
     dhcpv6_data->maptAssigned = TRUE;
     dhcpv6_data->mapt.v6Len = g_stMaptData.RuleIPv6PrefixLen;
     dhcpv6_data->mapt.isFMR = g_stMaptData.bFMR ? TRUE : FALSE;
     dhcpv6_data->mapt.eaLen = g_stMaptData.EaLen;
     dhcpv6_data->mapt.v4Len = g_stMaptData.RuleIPv4PrefixLen;
     dhcpv6_data->mapt.psidOffset = g_stMaptData.PsidOffset;
     dhcpv6_data->mapt.psidLen = g_stMaptData.PsidLen;
     dhcpv6_data->mapt.psid = g_stMaptData.Psid;
     dhcpv6_data->mapt.iapdPrefixLen = g_stMaptData.PdIPv6PrefixLen;
     dhcpv6_data->mapt.ratio = g_stMaptData.Ratio;

     rc = snprintf (dhcpv6_data->mapt.pdIPv6Prefix, BUFLEN_40, "%s", g_stMaptData.PdIPv6Prefix);
     ERR_CHK(rc);
     rc = snprintf (dhcpv6_data->mapt.ruleIPv4Prefix, BUFLEN_40, "%s", g_stMaptData.RuleIPv4Prefix);
     ERR_CHK(rc);
     rc = snprintf (dhcpv6_data->mapt.ruleIPv6Prefix, BUFLEN_40, "%s/%u", g_stMaptData.RuleIPv6Prefix
                                                                      , g_stMaptData.RuleIPv6PrefixLen);
     ERR_CHK(rc);
     rc = snprintf (dhcpv6_data->mapt.brIPv6Prefix,   BUFLEN_40, "%s/%u", g_stMaptData.BrIPv6Prefix
                                                                      , g_stMaptData.BrIPv6PrefixLen);
     ERR_CHK(rc);

     MAPT_LOG_INFO("MAPT configuration complete.\n");
  }

  return ((ret) ? ANSC_STATUS_FAILURE : ANSC_STATUS_SUCCESS);
}

#endif // MAPT_UNIFICATION_ENABLED

int remove_single_quote (char *buf)
{
  int i = 0;
  int j = 0;

  while (buf[i] != '\0' && i < 255) {
    if (buf[i] != '\'') {
      buf[j++] = buf[i];
    }
    i++;
  }
  buf[j] = '\0';
  return 0;
}

typedef struct 
{
    char* value;       // Pointer to the IANA/IAPD value etc..
    char* eventName;   // Corresponding event name
} Ipv6SyseventMap;

/* processIpv6LeaseSysevents()
 * This funtion is used to set the IPv6 lease related sysevents
 */
void processIpv6LeaseSysevents(Ipv6SyseventMap* eventMaps, size_t size, const char* IfaceName) 
{

    // Loop through the eventMaps array
    for (size_t i = 0; i < size; i++) 
    {
        if (eventMaps[i].value[0] != '\0' &&  strcmp(eventMaps[i].value, "\'\'") != 0)
        {
            char sysEventName[256] = {0};
            remove_single_quote(eventMaps[i].value);
            snprintf(sysEventName, sizeof(sysEventName), eventMaps[i].eventName, IfaceName);
            CcspTraceInfo(("%s - %d: Setting sysevent %s to %s \n", __FUNCTION__, __LINE__, sysEventName, eventMaps[i].value));
            sysevent_set(sysevent_fd, sysevent_token, sysEventName, eventMaps[i].value, 0);
        }
    }
}

/* This thread is used to parse the Ipv6 lease iformation sent by the DHCPv6 clients and sends the information to WanManager.
 * 
 */
static void * WanMgr_DhcpV6MsgHandler()
{
    int fd=0 ;
    char msg[1024];
    char * p = NULL;

    CcspTraceInfo(("%s - %d: created (WanManager Unified Version) ", __FUNCTION__, __LINE__));

    fd_set rfds;
    struct timeval tm;
    fd= open(CCSP_COMMON_FIFO, O_RDWR);
    if (fd< 0)
    {
        CcspTraceError(("%s - %d: open common fifo!!!!!!!!!!!! : %s . Exit thread", __FUNCTION__, __LINE__, strerror(errno)));
        pthread_exit(NULL);
    }
    while (1)
    {
        int retCode = 0;
        tm.tv_sec  = 60;
        tm.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        retCode = select(fd+1, &rfds, NULL, NULL, &tm);
        /* When return -1, it's error.
           When return 0, it's timeout
           When return >0, it's the number of valid fds */
        if (retCode < 0) {
            fprintf(stderr, "dbg_thrd : select returns error \n" );
            if (errno == EINTR)
                continue;

            CcspTraceWarning(("%s -- select(): %s. Exit thread", __FUNCTION__, strerror(errno)));
            pthread_exit(NULL);
        }
        else if(retCode == 0 )
            continue;

        if ( FD_ISSET(fd, &rfds) )
        {
            ssize_t msg_len = 0;
            msg[0] = 0;
            msg_len = read(fd, msg, sizeof(msg)-1);
            if(msg_len > 0)
                msg[msg_len] = 0;
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
            //Interface name
            char IfaceName[64] = {0};
            //Action (add or delete)
            char action[64] = {0}; 
            //IANA related varibales
            char v6addr[64] = {0}, iana_t1[32] = {0}, iana_t2[32] = {0}, iana_iaid[32] = {0}, iana_pretm[32] = {0}, iana_vldtm[32] = {0};
            //IAPD related varibales
            char v6pref[128] = {0}, preflen[12] = {0}, iapd_t1[32] = {0}, iapd_t2[32] = {0}, iapd_iaid[32] = {0}, iapd_pretm[32] = {0}, iapd_vldtm[32] = {0};
            int pref_len = 0;

            p = msg+strlen("dibbler-client");
            while(isblank(*p)) p++;
            fprintf(stderr, "%s -- %d !!! get event from v6 client: %s \n", __FUNCTION__, __LINE__,p);
#if defined (MAPT_UNIFICATION_ENABLED)
            unsigned char  opt95_dBuf[BUFLEN_256] = {0};
            int dataLen = sscanf(p, "%63s %63s %63s %31s %31s %31s %31s %31s %63s %11s %31s %31s %31s %31s %31s %255s",
                    action, IfaceName, v6addr,    iana_iaid, iana_t1, iana_t2, iana_pretm, iana_vldtm,
                    v6pref, preflen, iapd_iaid, iapd_t1, iapd_t2, iapd_pretm, iapd_vldtm,
                    opt95_dBuf);
            CcspTraceDebug(("%s,%d: dataLen = %d\n", __FUNCTION__, __LINE__, dataLen));
            if (dataLen == 16)
#else // MAPT_UNIFICATION_ENABLED
                int dataLen = sscanf(p, "%63s %63s %63s %31s %31s %31s %31s %31s %63s %11s %31s %31s %31s %31s %31s",
                        action, IfaceName, v6addr,    iana_iaid, iana_t1, iana_t2, iana_pretm, iana_vldtm,
                        v6pref, preflen, iapd_iaid, iapd_t1, iapd_t2, iapd_pretm, iapd_vldtm);
            if (dataLen == 15)
#endif
            {
                remove_single_quote(v6addr);
                remove_single_quote(v6pref);
                remove_single_quote(preflen);
                remove_single_quote(IfaceName);
                pref_len = atoi(preflen);
                CcspTraceDebug(("%s,%d: v6addr=%s, v6pref=%s, pref_len=%d\n", __FUNCTION__, __LINE__, v6addr, v6pref, pref_len));

                if (!strncmp(action, "add", 3))
                {
                    CcspTraceInfo(("%s: add\n", __func__));
                    //TODO :  Waiting until private lan interface is ready ?
                    // Waiting until private lan interface is ready , so that we can assign global ipv6 address and also start dhcp server.

                    ipc_dhcpv6_data_t dhcpv6_data;
                    memset(&dhcpv6_data, 0, sizeof(ipc_dhcpv6_data_t));
                    strncpy(dhcpv6_data.ifname, IfaceName, sizeof(dhcpv6_data.ifname));
                    if(strlen(v6pref) == 0 && strlen(v6addr) ==0) 
                    {
                        dhcpv6_data.isExpired = TRUE;
                    } else 
                    {
                        dhcpv6_data.isExpired = FALSE;
                        //Reset MAP flags
                        dhcpv6_data.maptAssigned = FALSE;
                        dhcpv6_data.mapeAssigned = FALSE;
                        if(strlen(v6pref) > 0 && strncmp(v6pref, "\\0",2)!=0)
                        {
                            CcspTraceInfo(("%s %d Prefix Assigned\n", __FUNCTION__, __LINE__));
                            snprintf(dhcpv6_data.sitePrefix, sizeof(dhcpv6_data.sitePrefix), "%s/%d", v6pref, pref_len);

                            dhcpv6_data.prefixAssigned = TRUE;
                            strncpy(dhcpv6_data.pdIfAddress, "", sizeof(dhcpv6_data.pdIfAddress));
                            dhcpv6_data.prefixCmd = 0;
                            remove_single_quote(iapd_pretm);
                            remove_single_quote(iapd_vldtm);
                            sscanf(iapd_pretm, "%d", &(dhcpv6_data.prefixPltime));
                            sscanf(iapd_vldtm, "%d", &(dhcpv6_data.prefixVltime));

                            //IPv6 prefix related sysevents
                            // Define the eventMaps array as before
                            Ipv6SyseventMap eventMaps[] = {
                                {dhcpv6_data.sitePrefix, COSA_DML_WANIface_PREF_SYSEVENT_NAME},
                                {iapd_iaid, COSA_DML_WANIface_PREF_IAID_SYSEVENT_NAME},
                                {iapd_t1,   COSA_DML_WANIface_PREF_T1_SYSEVENT_NAME},
                                {iapd_t2,   COSA_DML_WANIface_PREF_T2_SYSEVENT_NAME},
                                {iapd_pretm,COSA_DML_WANIface_PREF_PRETM_SYSEVENT_NAME},
                                {iapd_vldtm,COSA_DML_WANIface_PREF_VLDTM_SYSEVENT_NAME}
                            };
                            /* Set Interface specific sysevnts. This is used for Ip interface DM */
                            processIpv6LeaseSysevents(eventMaps, sizeof(eventMaps) / sizeof(eventMaps[0]), IfaceName);

#if defined (MAPT_UNIFICATION_ENABLED)
                            if (opt95_dBuf[0] == '\0' || strlen((char*)opt95_dBuf) <=0 || strcmp((char*)opt95_dBuf, "\'\'") == 0)
                            {
                                CcspTraceInfo(("%s: MAP-T configuration not available.\n", __FUNCTION__));
                            }
                            else 
                            {
                                if(STATUS_SUCCESS != WanMgr_MaptParseOpt95Response(dhcpv6_data.sitePrefix, opt95_dBuf, &dhcpv6_data))
				{
                                    DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(dhcpv6_data.ifname);
                                    if(pVirtIf != NULL)
                                    {
                                        WanMgr_ProcessTelemetryMarker(pVirtIf,WAN_ERROR_MAPT_STATUS_FAILED);
                                        WanMgr_VirtualIfaceData_release(pVirtIf);
                                    }
                                }				    
                            }
#endif // MAPT_UNIFICATION_ENABLED
                        }

                        if(strlen(v6addr) > 0 && strncmp(v6addr, "\\0",2)!=0)
                        {
                            CcspTraceInfo(("%s %d Addr Assigned\n", __FUNCTION__, __LINE__));
                            dhcpv6_data.addrAssigned = TRUE;
                            strncpy(dhcpv6_data.address, v6addr, sizeof(dhcpv6_data.address)-1);
                            dhcpv6_data.addrCmd   = 0;

                            //IPv6 IANA related sysevents
                            // Define the eventMaps array as before
                            Ipv6SyseventMap eventMaps[] = {
                                {v6addr,    COSA_DML_WANIface_ADDR_SYSEVENT_NAME},
                                {iana_iaid, COSA_DML_WANIface_ADDR_IAID_SYSEVENT_NAME},
                                {iana_t1,   COSA_DML_WANIface_ADDR_T1_SYSEVENT_NAME},
                                {iana_t2,   COSA_DML_WANIface_ADDR_T2_SYSEVENT_NAME},
                                {iana_pretm,COSA_DML_WANIface_ADDR_PRETM_SYSEVENT_NAME},
                                {iana_vldtm,COSA_DML_WANIface_ADDR_VLDTM_SYSEVENT_NAME},
                            };

                            /* Set Interface specific sysevnts. This is used for Ip interface DM */
                            processIpv6LeaseSysevents(eventMaps, sizeof(eventMaps) / sizeof(eventMaps[0]), IfaceName);
                        }

                        /** DNS servers. **/
                        char dns_server[256] = {'\0'};
                        //DNS server details are shared using sysvent, it is not part of the dibbler fifo
                        sysevent_get(sysevent_fd, sysevent_token, "ipv6_nameserver", dns_server, sizeof(dns_server));
                        if (strlen(dns_server) != 0)
                        {
                            dhcpv6_data.dnsAssigned = TRUE;
                            sscanf (dns_server, "%s %s", dhcpv6_data.nameserver, dhcpv6_data.nameserver1);
                        }
                    }

                    //get iface data
                    DML_VIRTUAL_IFACE* pVirtIf = WanMgr_GetVIfByName_VISM_running_locked(dhcpv6_data.ifname);
                    if(pVirtIf != NULL)
                    {
                        //check if previously message was already handled
                        if(pVirtIf->IP.pIpcIpv6Data == NULL)
                        {
                            //allocate
                            pVirtIf->IP.pIpcIpv6Data = (ipc_dhcpv6_data_t*) malloc(sizeof(ipc_dhcpv6_data_t));
                            if(pVirtIf->IP.pIpcIpv6Data != NULL)
                            {
                                // copy data 
                                memcpy(pVirtIf->IP.pIpcIpv6Data, &dhcpv6_data, sizeof(ipc_dhcpv6_data_t));
                                CcspTraceInfo(("%s %d IPv6 lease info add to Interface ID(%d), Virtual interface Name : %s , Alias %s \n", __FUNCTION__, __LINE__, pVirtIf->baseIfIdx+1, pVirtIf->Name, pVirtIf->Alias));
                            }
                        }
                        //release lock
                        WanMgr_VirtualIfaceData_release(pVirtIf);
                    }


                }
                else if (!strncmp(action, "del", 3))
                {
                    /*todo*/
                }
            }
        }
    }
    if(fd>=0) {
        close(fd);
    }
    return NULL;
}

ANSC_STATUS WanMgr_DhcpV6MsgHandlerInit()
{
    ANSC_STATUS retStatus = ANSC_STATUS_FAILURE;
    int ret = -1;

    //create thread
    pthread_t ipv6LeaseParser;
    if ( ( !mkfifo(CCSP_COMMON_FIFO, 0666) || errno == EEXIST ) )
    {
        ret = pthread_create( &ipv6LeaseParser, NULL, &WanMgr_DhcpV6MsgHandler, NULL );

        if( 0 != ret )
        {
            CcspTraceError(("%s %d - Failed to start WanMgr_DhcpV6MsgHandler Thread Error:%d\n", __FUNCTION__, __LINE__, ret));
        }
        else
        {
            CcspTraceInfo(("%s %d - WanMgr_DhcpV6MsgHandler Thread Started Successfully\n", __FUNCTION__, __LINE__));
            retStatus = ANSC_STATUS_SUCCESS;
        }
    }
    else
    {
        CcspTraceError(("%s %d - Failed to create %s \n", __FUNCTION__, __LINE__, CCSP_COMMON_FIFO));
    }
    return retStatus ;
}


