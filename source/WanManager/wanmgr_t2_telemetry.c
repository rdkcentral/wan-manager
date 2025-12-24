#include "wanmgr_t2_telemetry.h"
#include "wanmgr_rdkbus_utils.h"

#define BUFFER_LENGTH_256 256
static char MarkerArguments[BUFFER_LENGTH_256] = {0};

/*append api appends key value in pairs, separated by DELIMITER*/
static void wanmgr_telemetry_append_key_value(char* key, const char* value)
{
    if(value != NULL && strlen(MarkerArguments) < BUFFER_LENGTH_256 )
    {
	if(strlen(MarkerArguments)>0)
        {
            strncat(MarkerArguments,WANMGR_T2_TELEMETRY_MARKER_ARG_DELIMITER,sizeof(MarkerArguments));
        }
        strncat(MarkerArguments,key,sizeof(MarkerArguments));
        strncat(MarkerArguments,WANMGR_T2_TELEMETRY_MARKER_KEY_VALUE_DELIMITER,sizeof(MarkerArguments));
        strncat(MarkerArguments,value,sizeof(MarkerArguments));
    }
}

/*This api processes the Marker struct,
 * gets the data required to send to T2 marker*/
ANSC_STATUS wanmgr_process_T2_telemetry_event(WanMgr_Telemetry_Marker_t *Marker)
{
    DML_WAN_IFACE *pIntf = Marker->pInterface;
    DML_VIRTUAL_IFACE *pVirtIntf = Marker->pVirtInterface;
    memset(MarkerArguments,0,sizeof(MarkerArguments));
    char tempStr[128] = {0};

    if(pIntf == NULL || pVirtIntf == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    wanmgr_telemetry_append_key_value(WANMGR_T2_PHY_INTERFACE_STRING,pIntf->DisplayName);
    wanmgr_telemetry_append_key_value(WANMGR_T2_WAN_INTERFACE_STRING,pIntf->Name);

    switch(Marker->enTelemetryMarkerID)
    {        
        case WAN_ERROR_PHY_DOWN:
            if(pIntf->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_DOWN)
            {
                return ANSC_STATUS_SUCCESS;
            }
            break;

        case WAN_INFO_PHY_UP:
            if(pIntf->BaseInterfaceStatus == WAN_IFACE_PHY_STATUS_UP)
            {
                return ANSC_STATUS_SUCCESS;
            }
            break;

        case WAN_INFO_WAN_UP:
            break;

        case WAN_ERROR_WAN_DOWN:
            if(!(pIntf->Selection.Status == WAN_IFACE_VALIDATING || 
                pIntf->Selection.Status == WAN_IFACE_SELECTED ||
                pIntf->Selection.Status == WAN_IFACE_ACTIVE))
            {
                return ANSC_STATUS_SUCCESS;
            }
            break;

        case WAN_INFO_WAN_STANDBY:
            if(pVirtIntf->Status == WAN_IFACE_STATUS_STANDBY)
            {
                return ANSC_STATUS_SUCCESS;
            }
            break;

        case WAN_INFO_IPv4_CONFIG_TYPE:
            memset(tempStr,0,sizeof(tempStr));
            strcat(tempStr,"IPv4Source-");
            strcat(tempStr,WanMgr_Telemetry_IpSourceStr[pVirtIntf->IP.IPv4Source]);
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING, tempStr);	
            break;

        case WAN_INFO_IPv6_CONFIG_TYPE:
            memset(tempStr,0,sizeof(tempStr));
            strcat(tempStr,"IPv6Source-");
            strcat(tempStr,WanMgr_Telemetry_IpSourceStr[pVirtIntf->IP.IPv6Source]);
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,tempStr);
            break;

        case WAN_INFO_CONNECTIVITY_CHECK_TYPE:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,WanMgr_Telemetry_ConnectivityTypeStr[pVirtIntf->IP.ConnectivityCheckType]);
            break;

        case WAN_INFO_CONNECTIVITY_CHECK_STATUS_UP_IPV4:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,"IPv4");
            break;

        case WAN_INFO_CONNECTIVITY_CHECK_STATUS_UP_IPV6:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,"IPv6");
            break;

        case WAN_ERROR_CONNECTIVITY_CHECK_STATUS_DOWN_IPV4:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,"IPv4");
            break;

        case WAN_ERROR_CONNECTIVITY_CHECK_STATUS_DOWN_IPV6:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,"IPv6");
            break;

        case WAN_WARN_CONNECTIVITY_CHECK_STATUS_FAILED_IPV4:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,"IPv4");
            break;

        case WAN_WARN_CONNECTIVITY_CHECK_STATUS_FAILED_IPV6:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,"IPv6");
            break;

        case WAN_WARN_CONNECTIVITY_CHECK_STATUS_IDLE_IPV4:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,"IPv4");
            break;

        case WAN_WARN_CONNECTIVITY_CHECK_STATUS_IDLE_IPV6:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,"IPv6");
            break;

        case WAN_INFO_IP_MODE:
            wanmgr_telemetry_append_key_value(WANMGR_T2_WANMGR_SPLIT_VAL_STRING,WanMgr_Telemetry_IpModeStr[pVirtIntf->IP.Mode]);
            break;

        case WAN_INFO_IPv4_UP:
            if(pVirtIntf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_UP)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_SELECTION_STATUS_STRING,(pIntf->Selection.Status == WAN_IFACE_ACTIVE) ? "Active" : (pIntf->Selection.Status == WAN_IFACE_VALIDATING) ? "Validating" : (pIntf->Selection.Status == WAN_IFACE_SELECTED ) ? "Selected" : "Standby");
            break;

        case WAN_ERROR_IPv4_DOWN:
            if(pVirtIntf->IP.Ipv4Status == WAN_IFACE_IPV4_STATE_DOWN)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_SELECTION_STATUS_STRING,(pIntf->Selection.Status == WAN_IFACE_ACTIVE) ? "Active" : (pIntf->Selection.Status == WAN_IFACE_VALIDATING) ? "Validating" : (pIntf->Selection.Status == WAN_IFACE_SELECTED ) ? "Selected" : "Standby");
            break;

        case WAN_INFO_IPv6_UP:
            if(pVirtIntf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_UP)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_SELECTION_STATUS_STRING,(pIntf->Selection.Status == WAN_IFACE_ACTIVE) ? "Active" : (pIntf->Selection.Status == WAN_IFACE_VALIDATING) ? "Validating" : (pIntf->Selection.Status == WAN_IFACE_SELECTED ) ? "Selected" : "Standby");
            break;

        case WAN_ERROR_IPv6_DOWN:
            if(pVirtIntf->IP.Ipv6Status == WAN_IFACE_IPV6_STATE_DOWN)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_SELECTION_STATUS_STRING,(pIntf->Selection.Status == WAN_IFACE_ACTIVE) ? "Active" : (pIntf->Selection.Status == WAN_IFACE_VALIDATING) ? "Validating" : (pIntf->Selection.Status == WAN_IFACE_SELECTED ) ? "Selected" : "Standby");
            break;

        case WAN_INFO_MAPT_STATUS_UP:
            if(pVirtIntf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_UP)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_SELECTION_STATUS_STRING,(pIntf->Selection.Status == WAN_IFACE_ACTIVE) ? "Active" : (pIntf->Selection.Status == WAN_IFACE_VALIDATING) ? "Validating" : (pIntf->Selection.Status == WAN_IFACE_SELECTED ) ? "Selected" : "Standby");
            break;

        case WAN_ERROR_MAPT_STATUS_DOWN:
            if(pVirtIntf->MAP.MaptStatus == WAN_IFACE_MAPT_STATE_DOWN)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_SELECTION_STATUS_STRING,(pIntf->Selection.Status == WAN_IFACE_ACTIVE) ? "Active" : (pIntf->Selection.Status == WAN_IFACE_VALIDATING) ? "Validating" : (pIntf->Selection.Status == WAN_IFACE_SELECTED ) ? "Selected" : "Standby");
            break;

        case WAN_ERROR_MAPT_STATUS_FAILED:
            break;

        case WAN_INFO_DSLITE_STATUS_UP:
            if(pVirtIntf->DSLite.Status == WAN_IFACE_DSLITE_STATE_UP)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_SELECTION_STATUS_STRING,(pIntf->Selection.Status == WAN_IFACE_ACTIVE) ? "Active" : (pIntf->Selection.Status == WAN_IFACE_VALIDATING) ? "Validating" : (pIntf->Selection.Status == WAN_IFACE_SELECTED ) ? "Selected" : "Standby");
            break;

        case WAN_ERROR_DSLITE_STATUS_DOWN:
            if(pVirtIntf->DSLite.Status == WAN_IFACE_DSLITE_STATE_DOWN)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_SELECTION_STATUS_STRING,(pIntf->Selection.Status == WAN_IFACE_ACTIVE) ? "Active" : (pIntf->Selection.Status == WAN_IFACE_VALIDATING) ? "Validating" : (pIntf->Selection.Status == WAN_IFACE_SELECTED ) ? "Selected" : "Standby");
            break;

        case WAN_ERROR_DSLITE_STATUS_FAILED:
            break;

        case WAN_ERROR_VLAN_DOWN:
            if(pVirtIntf->VLAN.Status == WAN_IFACE_LINKSTATUS_DOWN)
            {
                return ANSC_STATUS_SUCCESS;
            }
            wanmgr_telemetry_append_key_value(WANMGR_T2_VIRT_WAN_INTERFACE_STRING,pVirtIntf->Name);
            break;

        case WAN_ERROR_VLAN_CREATION_FAILED:
            wanmgr_telemetry_append_key_value(WANMGR_T2_VIRT_WAN_INTERFACE_STRING,pVirtIntf->Name);
            break;

        case WAN_WARN_IP_OBTAIN_TIMER_EXPIRED:
            if(pIntf->bSendSelectionTimerExpired != TRUE)
            {
                return ANSC_STATUS_SUCCESS;
            }
            pIntf->bSendSelectionTimerExpired = FALSE;
            break;

        default:
            ;
    }
    t2_event_s(WanMgr_TelemetryEventStr[Marker->enTelemetryMarkerID],MarkerArguments);
    CcspTraceInfo(("%s %d: Successfully sent Telemetry event [%s] with arguments = [%s].\n",__FUNCTION__, __LINE__,WanMgr_TelemetryEventStr[Marker->enTelemetryMarkerID],MarkerArguments));
    return ANSC_STATUS_SUCCESS;
}
