#include "wanmgr_telemetry.h"
#include "wanmgr_rdkbus_utils.h"
#include "wanmgr_data.h"
#ifdef ENABLE_FEATURE_TELEMETRY2_0
#include "wanmgr_t2_telemetry.h"
#endif

/* A generic api for telemetry marker,
 * it gets the pVirtIf, fills necessary struct info and
 * sends them to appropriate telemetry api (either T2 or T3 and so on) 
 * to be further processed.*/

ANSC_STATUS WanMgr_ProcessTelemetryMarker( DML_VIRTUAL_IFACE *pVirtIf , WanMgr_TelemetryEvent_t telemetry_marker)
{
    if(pVirtIf == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }
    WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(pVirtIf->baseIfIdx);
    if(pWanDmlIfaceData == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }
    DML_WAN_IFACE *pIntf = &(pWanDmlIfaceData->data);
    WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

    WanMgr_Telemetry_Marker_t Marker = {0};
    Marker.pVirtInterface = pVirtIf;
    Marker.pInterface = pIntf;
    Marker.enTelemetryMarkerID = telemetry_marker;

#ifdef ENABLE_FEATURE_TELEMETRY2_0
    if(ANSC_STATUS_FAILURE == wanmgr_process_T2_telemetry_event(&Marker))
    {
        CcspTraceError(("%s %d: ERROR processing telemetry event %s.\n",__FUNCTION__, __LINE__,WanMgr_TelemetryEventStr[Marker.enTelemetryMarkerID]));
    }
    else
    {
        CcspTraceInfo(("%s %d: SUCCESS processing telemetry event %s.\n",__FUNCTION__, __LINE__,WanMgr_TelemetryEventStr[Marker.enTelemetryMarkerID]));
    }
#endif

    return ANSC_STATUS_SUCCESS;
}
