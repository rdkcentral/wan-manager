/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifdef RBUS_BUILD_FLAG_ENABLE
#include "wanmgr_data.h"
#include "wanmgr_net_utils.h"
#include "wanmgr_rbus_handler_apis.h"
#include "wanmgr_rdkbus_apis.h"
#include "dmsb_tr181_psm_definitions.h"
#include "wanmgr_telemetry.h"
#include "wanmgr_interface_apis.h"

enum {
ENUM_PHY = 1,
ENUM_WAN_STATUS,
ENUM_WAN_LINKSTATUS
};

#define  ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))
#define  MAC_ADDR_SIZE 18
rbusHandle_t rbusHandle;

char componentName[32] = "WANMANAGER";

BOOL wan_ready_to_go = false;
UINT  uiTotalIfaces = 0;

rbusError_t WanMgr_Rbus_SubscribeHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish);
rbusError_t WanMgr_Rbus_getHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t *opts);

rbusError_t wanMgrDmlPublishEventHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* name, rbusFilter_t filter, int32_t interval, bool* autoPublish);
rbusError_t WanMgr_Interface_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t WanMgr_Interface_SetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts);
static void CPEInterface_AsyncMethodHandler( rbusHandle_t handle, char const* methodName, rbusError_t error, rbusObject_t params);
static int WanMgr_Remote_IfaceData_index(const char *macAddress);

rbusError_t WanMgr_rbusMethod_Iface_StartWan(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle);
rbusError_t WanMgr_rbusMethod_Iface_StopWan(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle);
rbusError_t WanMgr_rbusMethod_Iface_ActivateWan(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle);
rbusError_t WanMgr_rbusMethod_Iface_DeactivateWan(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle);
rbusError_t WanMgr_rbusMethod_DisableAutoRouting(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle);
rbusError_t WanMgr_rbusMethod_EnableAutoRouting(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle);


typedef struct
{
    char* name;
    bool  get_request;
    bool  subscription_request;
} RemoteDM_list;

typedef struct TAD_WCC_Event_ {
    char         IfaceName[64];
    char         Alias[64];
    char         IPv4_DNS_Servers[512];
    char         IPv6_DNS_Servers[512];
    char         IPv4_Gateway[32];
    char         IPv6_Gateway[256];
    WCC_EVENT    Event;
} TAD_WCC_Event;
void *WanMgr_Configure_WCC_Thread(void *arg);

/***********************************************************************

  Data Elements declaration:

 ***********************************************************************/
rbusDataElement_t wanMgrRbusDataElements[] = {
    {WANMGR_CONFIG_WAN_CURRENTACTIVEINTERFACE,  RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Rbus_getHandler, NULL, NULL, NULL, WanMgr_Rbus_SubscribeHandler, NULL}},
    {WANMGR_CONFIG_WAN_CURRENT_STATUS,  RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Rbus_getHandler, NULL, NULL, NULL, WanMgr_Rbus_SubscribeHandler, NULL}},
    {WANMGR_CONFIG_WAN_CURRENTSTANDBYINTERFACE, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Rbus_getHandler, NULL, NULL, NULL, WanMgr_Rbus_SubscribeHandler, NULL}},
    {WANMGR_CONFIG_WAN_INTERFACEAVAILABLESTATUS,RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Rbus_getHandler, NULL, NULL, NULL, WanMgr_Rbus_SubscribeHandler, NULL}},
    {WANMGR_CONFIG_WAN_INTERFACEACTIVESTATUS,    RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Rbus_getHandler, NULL, NULL, NULL, WanMgr_Rbus_SubscribeHandler, NULL}},
    {WANMGR_CONFIG_WAN_CURRENTACTIVEDNS,    RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Rbus_getHandler, NULL, NULL, NULL, WanMgr_Rbus_SubscribeHandler, NULL}},
    {WANMGR_EVENT_INITIAL_SCAN_COMPLETED,    RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, WanMgr_Rbus_SubscribeHandler, NULL}},
    {WANMGR_EVENT_WAN_INTERFACEIPSTATUS,    RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, WanMgr_Rbus_SubscribeHandler, NULL}},
};

rbusDataElement_t wanMgrIfacePublishElements[] = {
    {WANMGR_INFACE, RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL}},
    {WANMGR_INFACE_WAN_ENABLE,  RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, WanMgr_Interface_SetHandler, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    {WANMGR_INFACE_ALIASNAME, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, WanMgr_Interface_SetHandler, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    {WANMGR_INFACE_PHY_STATUS, RBUS_ELEMENT_TYPE_PROPERTY,{WanMgr_Interface_GetHandler, WanMgr_Interface_SetHandler, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    {WANMGR_VIRTUAL_INFACE, RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL}},
    {WANMGR_V1_INFACE, RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL}},
    {WANMGR_V1_INFACE_PHY_STATUS, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, NULL, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    {WANMGR_V1_INFACE_WAN_STATUS, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, NULL, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    {WANMGR_V1_INFACE_WAN_LINKSTATUS, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, NULL, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    {WANMGR_INFACE_IPv4_ADDRESS, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, NULL, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    {WANMGR_INFACE_IPv6_ADDRESS, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, NULL, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    {WANMGR_INFACE_IPv6_PREFIX, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, NULL, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
    {WANMGR_INFACE_WAN_STATUS, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, WanMgr_Interface_SetHandler, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    {WANMGR_INFACE_WAN_LINKSTATUS, RBUS_ELEMENT_TYPE_PROPERTY, {WanMgr_Interface_GetHandler, WanMgr_Interface_SetHandler, NULL, NULL, wanMgrDmlPublishEventHandler, NULL}},
    { "Device.X_RDK_WanManager.Interface.{i}.WanStart()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, WanMgr_rbusMethod_Iface_StartWan} },
    { "Device.X_RDK_WanManager.Interface.{i}.WanStop()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, WanMgr_rbusMethod_Iface_StopWan} },
    { "Device.X_RDK_WanManager.Interface.{i}.Activate()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, WanMgr_rbusMethod_Iface_ActivateWan} },
    { "Device.X_RDK_WanManager.Interface.{i}.Deactivate()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, WanMgr_rbusMethod_Iface_DeactivateWan} },
    { "Device.X_RDK_WanManager.DisableAutoRouting()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, WanMgr_rbusMethod_DisableAutoRouting} },
    { "Device.X_RDK_WanManager.EnableAutoRouting()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, WanMgr_rbusMethod_EnableAutoRouting} },
};

RemoteDM_list RemoteDMs[] = {
    {WANMGR_REMOTE_INFACE_DISPLAYNAME,TRUE, FALSE},
    {WANMGR_REMOTE_INFACE_ALIAS,TRUE, FALSE},
    {WANMGR_REMOTE_INFACE_PHY_STATUS,TRUE,TRUE},
    {WANMGR_REMOTE_INFACE_WAN_STATUS,TRUE,TRUE},
    {WANMGR_REMOTE_INFACE_LINK_STATUS,TRUE,TRUE},
};

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
RemoteDM_list RemoteV1DMs[] = {
    {WANMGR_REMOTE_V1_INFACE_DISPLAYNAME,TRUE, FALSE},
    {WANMGR_REMOTE_V1_INFACE_ALIAS,TRUE, FALSE},
    {WANMGR_REMOTE_V1_INFACE_PHY_STATUS,TRUE,TRUE},
    {WANMGR_REMOTE_V1_INFACE_WAN_STATUS,TRUE,TRUE},
    {WANMGR_REMOTE_V1_INFACE_LINK_STATUS,TRUE,TRUE},
};
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */

RemoteDM_list RemoteDMsQueryList[MAX_NO_OF_RBUS_REMOTE_PARAMS];

static void WanMgr_EnumToString(UINT Enum, UINT EnumType, char* String)
{
    char *Ptr = NULL;

    if (EnumType == ENUM_PHY)
    {
        Ptr = ((Enum == WAN_IFACE_PHY_STATUS_DOWN)? "Down":((Enum == WAN_IFACE_PHY_STATUS_INITIALIZING)?
                "Initializing":((Enum == WAN_IFACE_PHY_STATUS_UP)? "Up":"Unknown")));
    }
    else if (EnumType == ENUM_WAN_STATUS)
    {
        Ptr = ((Enum == WAN_IFACE_STATUS_INITIALISING)? "Initialising":
               ((Enum == WAN_IFACE_STATUS_VALIDATING)? "Validating":
               ((Enum == WAN_IFACE_STATUS_UP)? "Up":
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
               ((Enum == WAN_IFACE_STATUS_STANDBY)? "Up":
#else
               ((Enum == WAN_IFACE_STATUS_STANDBY)? "Standby":
#endif
               ((Enum == WAN_IFACE_STATUS_VALID)? "Standby": // Valid to standby only for dm display
               ((Enum == WAN_IFACE_STATUS_INVALID)? "Invalid":"Disabled"))))));
    }
    else if (EnumType == ENUM_WAN_LINKSTATUS)
    {
        Ptr = ((Enum == WAN_IFACE_LINKSTATUS_CONFIGURING)? "Configuring":((Enum == WAN_IFACE_LINKSTATUS_UP)? "Up":"Down"));
    }
    if (Ptr != NULL)
    {
        AnscCopyString(String , Ptr);
    }
}

static void WanMgr_StringToEnum(UINT *Enum, UINT EnumType, const char* String)
{

    if (EnumType == ENUM_PHY)
    {
        *Enum = (strcmp(String ,"Down") == 0)? WAN_IFACE_PHY_STATUS_DOWN:
                ((strcmp(String, "Initializing") == 0)? WAN_IFACE_PHY_STATUS_INITIALIZING:
                ((strcmp(String, "Up") == 0))? WAN_IFACE_PHY_STATUS_UP:WAN_IFACE_PHY_STATUS_UNKNOWN);
    }
    else if (EnumType == ENUM_WAN_STATUS)
    {
        *Enum = ((strcmp(String, "Initialising") == 0)? WAN_IFACE_STATUS_INITIALISING:
                ((strcmp(String, "Validating")== 0)? WAN_IFACE_STATUS_VALIDATING:
                ((strcmp(String, "Up") == 0)? WAN_IFACE_STATUS_UP:
                ((strcmp(String, "Standby") == 0)? WAN_IFACE_STATUS_STANDBY:
                ((strcmp(String, "Invalid") == 0)? WAN_IFACE_STATUS_INVALID:WAN_IFACE_STATUS_DISABLED)))));
    }
    else if (EnumType == ENUM_WAN_LINKSTATUS)
    {
        *Enum = ((strcmp(String, "Configuring") == 0)? WAN_IFACE_LINKSTATUS_CONFIGURING:
                ((strcmp(String, "Up") == 0)? WAN_IFACE_LINKSTATUS_UP:WAN_IFACE_LINKSTATUS_DOWN));
    }
}

rbusError_t wanMgrDmlPublishEventHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* name, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    char *subscribe_action = NULL;
    UINT index = 0;
    char AliasName[64] = {0};

    CcspTraceInfo(("%s %d - Event %s has been subscribed from subscribed\n", __FUNCTION__, __LINE__,name ));
    subscribe_action = action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe";
    CcspTraceInfo(("%s %d - action=%s \n", __FUNCTION__, __LINE__, subscribe_action ));

    if(name == NULL)
    {
        CcspTraceError(("%s %d - Property get name is NULL\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_BUS_ERROR;
    }

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    if(strstr(name, WANMGR_V1_INFACE_TABLE))
    {
        sscanf(name, WANMGR_V1_INFACE_TABLE".%d.", &index);
    }
    else
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
    {
        sscanf(name, WANMGR_INFACE_TABLE".%d.", &index);
    }

    if(index  == 0)
    {
        sscanf(name, WANMGR_INFACE_TABLE".%63s.", &AliasName);
        index = WanMgr_GetIfaceIndexByAliasName(AliasName);
    }
    if(index <= 0)
    {
        CcspTraceError(("%s %d - Invalid index\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked((index - 1));
    if(pWanDmlIfaceData != NULL)
    {
        DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);

        if(WANMGR_PHY_STATUS_CHECK)
        {
            if (action == RBUS_EVENT_ACTION_SUBSCRIBE)
            {
                if (pWanDmlIface->Sub.BaseInterfaceStatusSub == 0)
                {
                    pWanDmlIface->Sub.BaseInterfaceStatusSub = 1;
                }
                else
                {
                    pWanDmlIface->Sub.BaseInterfaceStatusSub++;
                }
               CcspTraceInfo(("%s-%d : BaseInterfaceStatus Sub(%d) \n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.BaseInterfaceStatusSub));
            }
            else
            {
                if (pWanDmlIface->Sub.BaseInterfaceStatusSub)
                    pWanDmlIface->Sub.BaseInterfaceStatusSub--;
               CcspTraceInfo(("%s-%d : BaseInterfaceStatus UnSub(%d) \n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.BaseInterfaceStatusSub));
            }
        }
        else if(WANMGR_WAN_LINKSTATUS_CHECK)
        {
            if (action == RBUS_EVENT_ACTION_SUBSCRIBE)
            {
                if (pWanDmlIface->Sub.WanLinkStatusSub == 0)
                {
                    pWanDmlIface->Sub.WanLinkStatusSub = 1;
                }
                else
                {
                    pWanDmlIface->Sub.WanLinkStatusSub++;
                }
                CcspTraceInfo(("%s-%d : VlanStatus Sub(%d) \n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanLinkStatusSub));
            }
            else
            {
                if (pWanDmlIface->Sub.WanLinkStatusSub)
                    pWanDmlIface->Sub.WanLinkStatusSub--;
                CcspTraceInfo(("%s-%d : VlanStatus UnSub(%d) \n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanLinkStatusSub));
            }
        }
        else if(WANMGR_WAN_STATUS_CHECK)
        {
            if (action == RBUS_EVENT_ACTION_SUBSCRIBE)
            {
                if (pWanDmlIface->Sub.WanStatusSub == 0)
                {
                    pWanDmlIface->Sub.WanStatusSub = 1;
                }
                else
                {
                    pWanDmlIface->Sub.WanStatusSub++;
                }
                CcspTraceInfo(("%s-%d : Virtual interface Status Sub(%d) \n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanStatusSub));
            }
            else
            {
                if (pWanDmlIface->Sub.WanStatusSub)
                    pWanDmlIface->Sub.WanStatusSub--;
                CcspTraceInfo(("%s-%d : Virtual interface Status UnSub(%d) \n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanStatusSub));
            }
        }
        else if(strstr(name, WANMGR_INFACE_WAN_ENABLE_SUFFIX))
        {
            if (action == RBUS_EVENT_ACTION_SUBSCRIBE)
            {
                if (pWanDmlIface->Sub.WanEnableSub == 0)
                {
                    pWanDmlIface->Sub.WanEnableSub = 1;
                }
                else
                {
                    pWanDmlIface->Sub.WanEnableSub++;
                }
                CcspTraceInfo(("%s-%d : Selection Enable Sub(%d) \n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanEnableSub));
            }
            else
            {
                if (pWanDmlIface->Sub.WanEnableSub)
                    pWanDmlIface->Sub.WanEnableSub--;
                CcspTraceInfo(("%s-%d : Selection Enable UnSub(%d) \n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanEnableSub));
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }
    return RBUS_ERROR_SUCCESS;
}

rbusError_t WanMgr_Interface_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    UINT index = 0, VirtIfIndex = 1; //Set default Virtual interface index
    char AliasName[64] = {0};
    rbusError_t ret = RBUS_ERROR_SUCCESS;

    if(name == NULL)
    {
        CcspTraceError(("%s %d - Property get name is NULL\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_Init(&value);

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    if(strstr(name, WANMGR_V1_INFACE_TABLE))
    {
        sscanf(name, WANMGR_V1_INFACE_TABLE".%d.", &index);
    }
    else
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
    {
        sscanf(name, WANMGR_VIRTUAL_INFACE_TABLE".%d.", &index, &VirtIfIndex);
    }

    if(index  == 0)
    {
        sscanf(name, WANMGR_INFACE_TABLE".%63s.", &AliasName);
        index = WanMgr_GetIfaceIndexByAliasName(AliasName);
    }
    if(index <= 0)
    {
        CcspTraceError(("%s %d - Invalid index\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked((index - 1));
    if(pWanDmlIfaceData != NULL)
    {
        DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);
        DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanDmlIface->VirtIfList, (VirtIfIndex - 1));

        if(WANMGR_PHY_STATUS_CHECK)
        {
            char String[20] = {0};
            WanMgr_EnumToString(pWanDmlIface->BaseInterfaceStatus, ENUM_PHY, String);
            rbusValue_SetString(value, String);
        }
        else if(WANMGR_WAN_LINKSTATUS_CHECK)
        {
            char String[20] = {0};
            WanMgr_EnumToString(p_VirtIf->VLAN.Status, ENUM_WAN_LINKSTATUS, String);
            rbusValue_SetString(value, String);
        }
        else if(WANMGR_WAN_STATUS_CHECK)
        {
            char String[20] = {0};
            if(pWanDmlIface->IfaceType == REMOTE_IFACE && p_VirtIf->RemoteStatus != WAN_IFACE_STATUS_UP)
            {
                WanMgr_EnumToString(p_VirtIf->RemoteStatus, ENUM_WAN_STATUS, String);
            }else
            {
                WanMgr_EnumToString(p_VirtIf->Status, ENUM_WAN_STATUS, String);
            }
            rbusValue_SetString(value, String);
        }
        else if(strstr(name, WANMGR_INFACE_WAN_ENABLE_SUFFIX))
        {
            BOOL Enable = pWanDmlIface->Selection.Enable;
            rbusValue_SetBoolean(value, Enable);
        }
        else if(strstr(name, WANMGR_INFACE_ALIASNAME_SUFFIX))
        {
            rbusValue_SetString(value, pWanDmlIface->AliasName);
        }
        else if(strstr(name, "IP.IPv4Address"))
        {
            rbusValue_SetString(value, p_VirtIf->IP.Ipv4Data.ip);
        }
        else if(strstr(name, "IP.IPv6Address"))
        {
            rbusValue_SetString(value, p_VirtIf->IP.Ipv6Data.address);
        }
        else if(strstr(name, "IP.IPv6Prefix"))
        {
            rbusValue_SetString(value, p_VirtIf->IP.Ipv6Data.sitePrefix);
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }
    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return ret;
}

rbusError_t WanMgr_Interface_SetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    char const* name = rbusProperty_GetName(prop);
    rbusValue_t value = rbusProperty_GetValue(prop);
    rbusValueType_t type = rbusValue_GetType(value);
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    UINT index = 0, VirtIfIndex = 1; //Set default Virtual interface index
    char AliasName[64] = {0};

    if(name == NULL)
    {
        CcspTraceError(("%s %d - Property get name is NULL\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_BUS_ERROR;
    }

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    if(strstr(name, WANMGR_V1_INFACE_TABLE))
    {
        sscanf(name, WANMGR_V1_INFACE_TABLE".%d.", &index);
    }
    else
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
    {
        sscanf(name, WANMGR_VIRTUAL_INFACE_TABLE".%d.", &index, &VirtIfIndex);
    }

    if(index  == 0)
    {
        sscanf(name, WANMGR_INFACE_TABLE".%63s.", &AliasName);
        index = WanMgr_GetIfaceIndexByAliasName(AliasName);
    }
    if(index <= 0)
    {
        CcspTraceError(("%s %d - Invalid index\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked((index - 1));
    if(pWanDmlIfaceData != NULL)
    {
        DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);
        DML_VIRTUAL_IFACE* p_VirtIf = WanMgr_getVirtualIfaceById(pWanDmlIface->VirtIfList, (VirtIfIndex - 1));
        if(strstr(name, WANMGR_INFACE_PHY_STATUS_SUFFIX))
        {
            if (type == RBUS_STRING)
            {
                char String[20] = {0};
                strncpy(String , rbusValue_GetString(value, NULL),sizeof(String)-1);
                CcspTraceInfo(("%s-%d : %s BaseInterfaceStatus changed to %s\n", __FUNCTION__, __LINE__, pWanDmlIface->Name, String));
                if (strncmp(String,"Down",strlen(String)) == 0)
                {
                    WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_ERROR_PHY_DOWN);
                }
                else if (strncmp(String,"Up",strlen(String)) == 0) 
                {
                    WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_INFO_PHY_UP);
                }			
                WanMgr_StringToEnum(&pWanDmlIface->BaseInterfaceStatus, ENUM_PHY, String);
                if (pWanDmlIface->Sub.BaseInterfaceStatusSub)
                {
                    CcspTraceInfo(("%s-%d : BaseInterfaceStatus Publish Event, SubCount(%d)\n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.BaseInterfaceStatusSub));
                    WanMgr_Rbus_EventPublishHandler(name, &String, type);
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
                    char DmlNameV1[128] = {0};
                    snprintf(DmlNameV1, sizeof(DmlNameV1), WANMGR_V1_INFACE_TABLE".%d"WANMGR_V1_INFACE_PHY_STATUS_SUFFIX,index);
                    CcspTraceInfo(("%s-%d : V1 DML Publish Event %s\n", __FUNCTION__, __LINE__,DmlNameV1 ));
                    WanMgr_Rbus_EventPublishHandler(DmlNameV1, &String, type);
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
                }
            }
            else
            {
                ret = RBUS_ERROR_INVALID_INPUT;
            }
        }
        else if(strstr(name, WANMGR_INFACE_WAN_LINKSTATUS_SUFFIX))
        {
            if (type == RBUS_STRING)
            {
                char String[20] = {0};
                strncpy(String , rbusValue_GetString(value, NULL),sizeof(String)-1);
                if(strncmp(String,"Down",strlen(String)) == 0)
                {
                    WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_ERROR_VLAN_DOWN);
                }			
                WanMgr_StringToEnum(&p_VirtIf->VLAN.Status, ENUM_WAN_LINKSTATUS, String);
                if (pWanDmlIface->Sub.WanLinkStatusSub)
                {
                    CcspTraceInfo(("%s-%d : VLAN Status Publish Event, SubCount(%d)\n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanLinkStatusSub));
                    WanMgr_Rbus_EventPublishHandler(name, &String, type);
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
                    char DmlNameV1[128] = {0};
                    snprintf(DmlNameV1, sizeof(DmlNameV1), WANMGR_V1_INFACE_TABLE".%d"WANMGR_V1_INFACE_WAN_LINKSTATUS_SUFFIX,index);
                    CcspTraceInfo(("%s-%d : V1 DML Publish Event %s\n", __FUNCTION__, __LINE__,DmlNameV1 ));
                    WanMgr_Rbus_EventPublishHandler(DmlNameV1, &String, type);
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
                }
            }
            else
            {
                ret = RBUS_ERROR_INVALID_INPUT;
            }
        }
        else if(strstr(name, WANMGR_INFACE_WAN_STATUS_SUFFIX))
        {
            if (type == RBUS_STRING)
            {
                char String[20] = {0};
                strncpy(String , rbusValue_GetString(value, NULL),sizeof(String)-1);
                WanMgr_StringToEnum(&p_VirtIf->Status, ENUM_WAN_STATUS, String);
                if (pWanDmlIface->Sub.WanStatusSub)
                {
                    CcspTraceInfo(("%s-%d : Virtual interface Status Publish Event, SubCount(%d)\n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanStatusSub));
                    WanMgr_Rbus_EventPublishHandler(name, &String, type);
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
                    char DmlNameV1[128] = {0};
                    snprintf(DmlNameV1, sizeof(DmlNameV1), WANMGR_V1_INFACE_TABLE".%d"WANMGR_V1_INFACE_WAN_STATUS_SUFFIX,index);
                    CcspTraceInfo(("%s-%d : V1 DML Publish Event %s\n", __FUNCTION__, __LINE__,DmlNameV1 ));
                    WanMgr_Rbus_EventPublishHandler(DmlNameV1, &String, type);
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
                }
            }
            else
            {
                ret = RBUS_ERROR_INVALID_INPUT;
            }
        }
        else if(strstr(name, WANMGR_INFACE_WAN_ENABLE_SUFFIX))
        {
            if (type == RBUS_BOOLEAN)
            {
                BOOL Enable = FALSE;
                char param_name[256] = {0};
                _ansc_sprintf(param_name, PSM_WANMANAGER_IF_SELECTION_ENABLE, index);
                if(rbusValue_GetBoolean(value))
                {
                    pWanDmlIface->Selection.Enable = TRUE;
                    WanMgr_RdkBus_SetParamValuesToDB(param_name,"TRUE");
                    Enable = TRUE;
                }
                else
                {
                    pWanDmlIface->Selection.Enable = FALSE;
                    WanMgr_RdkBus_SetParamValuesToDB(param_name,"FALSE");
                    Enable = FALSE;
                }
                if (pWanDmlIface->Sub.WanEnableSub)
                {
                    CcspTraceInfo(("%s-%d : Selection Enable Publish Event, SubCount(%d)\n", __FUNCTION__, __LINE__, pWanDmlIface->Sub.WanEnableSub));
                    WanMgr_Rbus_EventPublishHandler(name, &Enable, type);
                }
            }
            else
            {
                ret = RBUS_ERROR_INVALID_INPUT;
            }
        }
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }
    return ret;
}

rbusError_t WanMgr_Rbus_getHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t *opts)
{
    (void)handle;
    (void)opts;
    char const* name = rbusProperty_GetName(property);

    rbusValue_t value;
    rbusValue_Init(&value);

    WanMgr_Config_Data_t* pWanConfigData = WanMgr_GetConfigData_locked();
    if (pWanConfigData != NULL)
    {
        DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);
        if (strcmp(name, WANMGR_CONFIG_WAN_CURRENTACTIVEINTERFACE) == 0)
        {
            rbusValue_SetString(value, pWanDmlData->CurrentActiveInterface);
        }
        else if (strcmp(name, WANMGR_CONFIG_WAN_CURRENTSTANDBYINTERFACE) == 0)
        {
            rbusValue_SetString(value, pWanDmlData->CurrentStandbyInterface);
        }
        else if (strcmp(name, WANMGR_CONFIG_WAN_INTERFACEAVAILABLESTATUS) == 0)
        {
            rbusValue_SetString(value, pWanDmlData->InterfaceAvailableStatus);
        }
        else if (strcmp(name, WANMGR_CONFIG_WAN_INTERFACEACTIVESTATUS) == 0)
        {
            rbusValue_SetString(value, pWanDmlData->InterfaceActiveStatus);
        }
        else if (strcmp(name, WANMGR_CONFIG_WAN_CURRENT_STATUS) == 0)
        {
            rbusValue_SetString(value, pWanDmlData->CurrentStatus);
        }
        else if (strcmp(name, WANMGR_CONFIG_WAN_CURRENTACTIVEDNS) == 0)
        {
            rbusValue_SetString(value, pWanDmlData->CurrentActiveDNS);
        }	
        else
        {
            WanMgrDml_GetConfigData_release(pWanConfigData);
            CcspTraceWarning(("WanMgr_Rbus_getHandler: Invalid Input\n"));
            rbusValue_Release(value);
            return RBUS_ERROR_INVALID_INPUT;
        }

        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}

ANSC_STATUS WanMgr_Rbus_getUintParamValue (char * param, UINT * value)
{
    if ((param == NULL) || (value == NULL))
    {
        CcspTraceError(("%s %d: invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (rbus_getUint(rbusHandle, param, value) != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d: unable to get value of param %s\n", __FUNCTION__, __LINE__, param));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s %d: %s = %d\n", __FUNCTION__, __LINE__, param, *value));

    return ANSC_STATUS_SUCCESS;
}



static void WanMgr_Rbus_EventReceiveHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    const char* eventName = event->name;
    int  cpeInterfaceIndex   = -1;

    if((eventName == NULL))
    {
        CcspTraceError(("%s : FAILED , value is NULL\n",__FUNCTION__));
        return;
    }
    if (strcmp(eventName, WANMGR_DEVICE_NETWORKING_MODE) == 0)
    {
        rbusValue_t valBuff = rbusObject_GetValue(event->data, NULL );
        CcspTraceInfo(("%s %d: change in %s\n", __FUNCTION__, __LINE__, eventName));
        UINT newValue = rbusValue_GetUInt32(valBuff);
        // Save here
        WanMgr_Config_Data_t* pWanConfigData = WanMgr_GetConfigData_locked();
        if (pWanConfigData != NULL)
        {
            DML_WANMGR_CONFIG* pWanDmlData = &(pWanConfigData->data);
            DEVICE_NETWORKING_MODE prevDeviceNwMode = pWanDmlData->DeviceNwMode;

            if (newValue == 1)
            {
                pWanDmlData->DeviceNwMode = MODEM_MODE;
                CcspTraceInfo(("%s %d: DeviceNetworkMode changed to MODEM_MODE\n", __FUNCTION__, __LINE__));
            }
            else if (newValue == 0)
            {
                pWanDmlData->DeviceNwMode = GATEWAY_MODE;
                CcspTraceInfo(("%s %d: DeviceNetworkMode changed to GATEWAY_MODE\n", __FUNCTION__, __LINE__));
            }

            if (pWanDmlData->DeviceNwMode != prevDeviceNwMode)
            {
                CcspTraceInfo(("%s %d: DeviceNetworkMode changed identified. PreviousMode:%d CurrentMode:%d\n", __FUNCTION__, __LINE__, prevDeviceNwMode, pWanDmlData->DeviceNwMode));
                pWanDmlData->DeviceNwModeChanged = TRUE;
            }

            WanMgrDml_GetConfigData_release(pWanConfigData);
        }

        CcspTraceInfo(("%s:%d Received [%s:%u]\n",__FUNCTION__, __LINE__,eventName, newValue));
    }
    else if (strcmp(eventName, X_RDK_REMOTE_DEVICECHANGE) == 0)
    {
        CcspTraceInfo(("%s:%d Received [%s] \n",__FUNCTION__, __LINE__,eventName));

        rbusValue_t value;
        value = rbusObject_GetValue(event->data, "Capabilities");
        CcspTraceInfo(("%s %d - Capabilities %s\n", __FUNCTION__, __LINE__,rbusValue_GetString(value, NULL)));

        value = rbusObject_GetValue(event->data, "Index");
        UINT Index = rbusValue_GetUInt32(value);
        CcspTraceInfo(("%s %d - Index %d\n", __FUNCTION__, __LINE__,Index));

        value = rbusObject_GetValue(event->data, "Mac_addr");
        char *remoteMac = malloc(MAC_ADDR_SIZE + 1);

        if(remoteMac == NULL  )
        {
            CcspTraceError(("%s %d - Memory allocation failed \n", __FUNCTION__, __LINE__));
            return;
        }
        const char *Mac = rbusValue_GetString(value, NULL);
        if(Mac != NULL)
        {
            strncpy(remoteMac,Mac,MAC_ADDR_SIZE);
            CcspTraceInfo(("%s %d - from source MAC %s\n", __FUNCTION__, __LINE__, remoteMac));
        }else
        {
            CcspTraceError(("%s %d - Mac_addr get failed \n", __FUNCTION__, __LINE__));
            if(remoteMac != NULL)
            {
                free(remoteMac);
            }
            return;
        }

        if (Index > 0)
        {
            DEVICE_NETWORKING_MODE  DeviceMode;
            WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
            if(pWanConfigData != NULL)
            {
                DeviceMode = pWanConfigData->data.DeviceNwMode;
                WanMgrDml_GetConfigData_release(pWanConfigData);

                if (DeviceMode == GATEWAY_MODE)
                {
                    CcspTraceInfo(("%s %d -DeviceNwMode set to GATEWAY_MODE. Configure remote Iface\n", __FUNCTION__, __LINE__));

                    WanMgr_DeviceChangeEvent * pDeviceChangeEvent;
                    pDeviceChangeEvent = malloc (sizeof(WanMgr_DeviceChangeEvent));
                    if (pDeviceChangeEvent == NULL)
                    {
                        CcspTraceError(("%s %d: malloc failure:%s\n", __FUNCTION__, __LINE__, strerror(errno)));
                        return;
                    }
                    memset(pDeviceChangeEvent, 0, sizeof(WanMgr_DeviceChangeEvent));
                    strncpy(pDeviceChangeEvent->mac_addr, remoteMac, sizeof(pDeviceChangeEvent->mac_addr)-1);
                    value = rbusObject_GetValue(event->data, "available");
                    pDeviceChangeEvent->available = rbusValue_GetBoolean(value);

                    CcspTraceInfo(("%s %d: Received remote iface with MAC:%s available:%d\n", __FUNCTION__, __LINE__, pDeviceChangeEvent->mac_addr, pDeviceChangeEvent->available));

                    WanMgr_WanRemoteIfaceConfigure(pDeviceChangeEvent);
                }else
                    CcspTraceInfo(("%s %d -DeviceNwMode is not GATEWAY_MODE. Do not configure remote Iface\n", __FUNCTION__, __LINE__));
            }
        }

    }
    else if(strcmp(eventName, X_RDK_REMOTE_INVOKE) == 0)
    {
        DEVICE_NETWORKING_MODE  DeviceMode = GATEWAY_MODE;
        WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
        if(pWanConfigData != NULL)
        {
            DeviceMode = pWanConfigData->data.DeviceNwMode;
            WanMgrDml_GetConfigData_release(pWanConfigData);
        }

        if (DeviceMode != GATEWAY_MODE) //Wanmanger subscribes remote device status only in GATEWAY_MODE
        {
            return;
        }
        CcspTraceInfo(("%s:%d Received IDM event [%s] \n",__FUNCTION__, __LINE__,eventName));

        rbusValue_t value;
        value = rbusObject_GetValue(event->data, "Mac_source");
        const char *pMac = rbusValue_GetString(value, NULL);
        CcspTraceInfo(("%s %d - from source MAC %s\n", __FUNCTION__, __LINE__, pMac));

        cpeInterfaceIndex = WanMgr_Remote_IfaceData_index(pMac);

        if (cpeInterfaceIndex >= 0)
        {
            value = rbusObject_GetValue(event->data, "param_name");
            const char *pParamName = rbusValue_GetString(value, NULL);
            CcspTraceInfo(("%s %d - param_name %s\n", __FUNCTION__, __LINE__, pParamName));

            value = rbusObject_GetValue(event->data, "param_value");
            const char *pValue = rbusValue_GetString(value, NULL);
            CcspTraceInfo(("%s %d - param_value %s\n", __FUNCTION__, __LINE__, pValue));

            WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(cpeInterfaceIndex);
            if(pWanDmlIfaceData != NULL)
            {
                DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);

                if( strstr(pParamName, WANMGR_INFACE_PHY_STATUS_SUFFIX) != NULL )
                {
                    if(strncmp(pValue,"Down",strlen(pValue)) == 0)
                    {
                        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanIfaceData->VirtIfList,0),WAN_ERROR_PHY_DOWN);
                    }
                    else if (strncmp(pValue,"Up",strlen(pValue)) == 0)
                    {
                        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanIfaceData->VirtIfList,0),WAN_INFO_PHY_UP);
                    }					
                    WanMgr_StringToEnum(&pWanIfaceData->BaseInterfaceStatus, ENUM_PHY, pValue);
                }
                else if( strstr(pParamName, WANMGR_INFACE_WAN_LINKSTATUS_SUFFIX) != NULL )
                {
                    if (strncmp(pValue,"Down",strlen(pValue)) == 0 )
                    {
                        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanIfaceData->VirtIfList,0),WAN_ERROR_VLAN_DOWN);
                    }				
                    WanMgr_StringToEnum(&pWanIfaceData->VirtIfList->VLAN.Status, ENUM_WAN_LINKSTATUS, pValue);
                    if(pWanIfaceData->VirtIfList->VLAN.Status == WAN_IFACE_LINKSTATUS_UP)
                    {
                        WanMgr_getRemoteWanParamsFromPSM(pWanIfaceData->VirtIfList);
                    }
                }
                else if( strstr(pParamName, WANMGR_INFACE_WAN_STATUS_SUFFIX) != NULL )
                {
                    WanMgr_StringToEnum(&pWanIfaceData->VirtIfList->RemoteStatus, ENUM_WAN_STATUS, pValue);
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
        else
        {
            CcspTraceError(("%s %d - Remote Interface Not found \n", __FUNCTION__, __LINE__));
        }
    }
    else  if (strcmp(eventName, "wan_ready_to_go") == 0)
    {
        rbusValue_t valBuff = rbusObject_GetValue(event->data, NULL );
        CcspTraceInfo(("%s %d: change in %s\n", __FUNCTION__, __LINE__, eventName));
        wan_ready_to_go = rbusValue_GetBoolean(valBuff);

        CcspTraceInfo(("%s:%d Received [%s:%d]\n",__FUNCTION__, __LINE__,eventName, wan_ready_to_go));
    }

    else
    {
        CcspTraceError(("%s:%d Unexpected Event Received [%s]\n",__FUNCTION__, __LINE__,eventName));
    }
}

void WanMgr_Rbus_SubscribeWanReady()
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    /* Adding 120 seconds as the duration of the subscription since this event is needed only at the bootup. This event will be unsubscribed after 120 seconds */
    rbusEventSubscription_t subscription = {"wan_ready_to_go", NULL, 0, 120, WanMgr_Rbus_EventReceiveHandler, NULL,NULL, NULL, true};
    ret = rbusEvent_SubscribeEx(rbusHandle, &subscription, 1, 60);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, rbusError_ToString(ret), "wan_ready_to_go"));
    }
    CcspTraceInfo(("%s:%d wan_ready_to_go subscribed\n",__FUNCTION__, __LINE__));
}

void WanMgr_Rbus_UpdateLocalWanDb(void)
{
    UINT ret = 0;

    // get DeviceNetworking Mode
    char dev_type[16] = {0};
    syscfg_get(NULL, "Device_Mode", dev_type, sizeof(dev_type));
    ret = atoi(dev_type);

    //Update Wan config
    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        if (ret == 1)
        {
            pWanConfigData->data.DeviceNwMode = MODEM_MODE;
        }
        else
        {
            pWanConfigData->data.DeviceNwMode = GATEWAY_MODE;
        }
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }

}

void WanMgr_Rbus_SubscribeDML(void)
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;
#if defined  (WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
    ret = rbusEvent_Subscribe(rbusHandle, WANMGR_DEVICE_NETWORKING_MODE, WanMgr_Rbus_EventReceiveHandler, NULL, 60);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, rbusError_ToString(ret), WANMGR_DEVICE_NETWORKING_MODE));
    }
    else
    {
        // subscription of WANMGR_DEVICE_NETWORKING_MODE is successful, update the value in local DB
        UINT DeviceNwMode;
        if (WanMgr_Rbus_getUintParamValue(WANMGR_DEVICE_NETWORKING_MODE, &DeviceNwMode) == ANSC_STATUS_SUCCESS)
        {
            WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
            if(pWanConfigData != NULL)
            {
                if (DeviceNwMode == 1)
                {
                    pWanConfigData->data.DeviceNwMode = MODEM_MODE;
                }
                else
                {
                    pWanConfigData->data.DeviceNwMode = GATEWAY_MODE;
                }
                WanMgrDml_GetConfigData_release(pWanConfigData);
            }
        }
        else
        {
            CcspTraceError(("%s %d: unable to fetch %s\n", __FUNCTION__, __LINE__, WANMGR_DEVICE_NETWORKING_MODE));
        } 
    }
#endif

#ifdef FEATURE_RDKB_INTER_DEVICE_MANAGER
    ret = rbusEvent_Subscribe(rbusHandle, X_RDK_REMOTE_DEVICECHANGE, WanMgr_Rbus_EventReceiveHandler, NULL, 60);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, rbusError_ToString(ret), X_RDK_REMOTE_DEVICECHANGE));
    }

    ret = rbusEvent_Subscribe(rbusHandle, X_RDK_REMOTE_INVOKE, WanMgr_Rbus_EventReceiveHandler, NULL, 60);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, rbusError_ToString(ret), X_RDK_REMOTE_INVOKE));
    }
#endif
    CcspTraceInfo(("WanMgr_Rbus_SubscribeDML done\n"));
}

void WanMgr_Rbus_UnSubscribeDML(void)
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;

    ret = rbusEvent_Unsubscribe(rbusHandle, WANMGR_DEVICE_NETWORKING_MODE);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, WANMGR_DEVICE_NETWORKING_MODE, rbusError_ToString(ret)));
    }

    ret = rbusEvent_Unsubscribe(rbusHandle, X_RDK_REMOTE_DEVICECHANGE);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, X_RDK_REMOTE_DEVICECHANGE, rbusError_ToString(ret)));
    }

    ret = rbusEvent_Unsubscribe(rbusHandle, X_RDK_REMOTE_INVOKE);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, X_RDK_REMOTE_INVOKE, rbusError_ToString(ret)));
    }

    CcspTraceInfo(("WanMgr_Rbus_UnSubscribeDML done\n"));
}

/***********************************************************************
 WanMgr_IDM_Invoke():
Description:
    Send Invoke request to IDM
Arguments:
    idm_invoke_method_Params_t*

    struct list:
    IDM_MSG_OPERATION operation : DM GET/SET/SUBSCRIBE
    char Mac_dest[18]           : Destination device (identifier) MAC
    char param_name[128]        : DM name
    char param_value[2048]      : DM value
    uint timeout                : Timeout for async call back
    enum dataType_e type        : DM data type
    rbusMethodAsyncHandle_t asyncHandle : Async call back handler pointer
Return value:
    ANSC_STATUS

 ***********************************************************************/

ANSC_STATUS WanMgr_IDM_Invoke(idm_invoke_method_Params_t *IDM_request)
{
    rbusObject_t inParams;
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;

    CcspTraceInfo(("%s %d - sendind rbus request to %s \n", __FUNCTION__, __LINE__,IDM_request->Mac_dest));

    rbusObject_Init(&inParams, NULL);

    rbusValue_Init(&value);
    rbusValue_SetString(value, IDM_request->Mac_dest );
    rbusObject_SetValue(inParams, "DEST_MAC_ADDR", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, IDM_request->param_name);
    rbusObject_SetValue(inParams, "paramName", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value,IDM_request->param_value);
    rbusObject_SetValue(inParams, "paramValue", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, IDM_request->timeout);
    rbusObject_SetValue(inParams, "Timeout", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, IDM_request->type);
    rbusObject_SetValue(inParams, "DataType", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, IDM_request->operation);
    rbusObject_SetValue(inParams, "Operation", value);
    rbusValue_Release(value);

    rc = rbusMethod_InvokeAsync(rbusHandle, X_RDK_REMOTE_INVOKE, inParams, IDM_request->asyncHandle, IDM_request->timeout);

    rbusObject_Release(inParams);
    if(rc == RBUS_ERROR_SUCCESS)
    {
        CcspTraceInfo(("%s %d -consumer: rbusMethod_Invoke(Device.X_RDK_Remote.Invoke()) success\n",__FUNCTION__, __LINE__));
        return ANSC_STATUS_SUCCESS;
    }else
    {
        CcspTraceError(("%s %d -consumer: rbusMethod_Invoke(Device.X_RDK_Remote.Invoke()) failed\n",__FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
}

ANSC_STATUS WanMgr_IDM_InvokeSync(idm_invoke_method_Params_t *IDM_request)
{
    rbusObject_t inParams;
    rbusObject_t outParams = NULL;
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;
    rbusProperty_t prop = NULL;

    CcspTraceInfo(("%s %d - sendind rbus request to %s \n", __FUNCTION__, __LINE__,IDM_request->Mac_dest));

    rbusObject_Init(&inParams, NULL);

    rbusValue_Init(&value);
    rbusValue_SetString(value, IDM_request->Mac_dest );
    rbusObject_SetValue(inParams, "DEST_MAC_ADDR", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, IDM_request->param_name);
    rbusObject_SetValue(inParams, "paramName", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value,IDM_request->param_value);
    rbusObject_SetValue(inParams, "paramValue", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, IDM_request->timeout);
    rbusObject_SetValue(inParams, "Timeout", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, IDM_request->type);
    rbusObject_SetValue(inParams, "DataType", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, IDM_request->operation);
    rbusObject_SetValue(inParams, "Operation", value);
    rbusValue_Release(value);

    rc = rbusMethod_Invoke(rbusHandle, X_RDK_REMOTE_INVOKE, inParams, &outParams);
    rbusObject_Release(inParams);
    if(rc == RBUS_ERROR_SUCCESS)
    {
        char *str_value = NULL;

        prop = rbusObject_GetProperties(outParams);
        value = rbusProperty_GetValue(prop);
        str_value = rbusValue_ToString(value,NULL,0);

        CcspTraceInfo(("%s %d - Consumer: rbusMethod_Invoke success, Param:%s Value:%s\n",__FUNCTION__, __LINE__, IDM_request->param_name, (str_value) ? str_value : "empty" ));
        
        //Release allocated resource
        if(str_value)
        free(str_value);

        if(outParams)
        rbusObject_Release(outParams);

        return ANSC_STATUS_SUCCESS;
    }
    else
    {
        //Release allocated resource
        if(outParams)
        rbusObject_Release(outParams);

        CcspTraceError(("%s %d - Consumer: rbusMethod_Invoke(Device.X_RDK_Remote.Invoke()) failed\n",__FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
}

/***********************************************************************
  WanMgr_Rbus_Init(): Initialize Rbus and data elements
 ***********************************************************************/

ANSC_STATUS WanMgr_Rbus_Init()
{
    int rc = ANSC_STATUS_FAILURE;

    char AliasName[64] = {0};
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    char tmpVIfTableName[256] = {0};
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */

    rc = rbus_open(&rbusHandle, componentName);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("WanMgr_Rbus_Init rbus initialization failed\n"));
        return rc;
    }

    // Register data elements
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(wanMgrRbusDataElements), wanMgrRbusDataElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        CcspTraceWarning(("rbus register data elements failed\n"));
        rbus_close(rbusHandle);
        return rc;
    }

    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(wanMgrIfacePublishElements), wanMgrIfacePublishElements);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s %d - Failed to Register Iface Table 1 Elements, Error=%d \n", __FUNCTION__, __LINE__, rc));
    }

    if(DmlGetTotalNoOfWanInterfaces(&uiTotalIfaces) != ANSC_STATUS_SUCCESS)
    {
        return ANSC_STATUS_FAILURE;
    }

    for (int i = 0; i < uiTotalIfaces; i++)
    {
        WanMgr_GetIfaceAliasNameByIndex(i,AliasName);
        rc = rbusTable_registerRow(rbusHandle, WANMGR_INFACE_TABLE, (i+1), AliasName);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Iterface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, i, WANMGR_INFACE_TABLE, rc));
            return rc;
        }
        else
        {
             CcspTraceInfo(("%s %d - Iterface(%d) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, i, WANMGR_INFACE_TABLE, AliasName));
        }

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
        rc = rbusTable_registerRow(rbusHandle, WANMGR_V1_INFACE_TABLE, (i+1), AliasName);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Iterface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, i, WANMGR_V1_INFACE_TABLE, rc));
            return rc;
        }
        else
        {
             CcspTraceInfo(("%s %d - Iterface(%d) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, i, WANMGR_V1_INFACE_TABLE, AliasName));
        }

        WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(i);
        if(pWanDmlIfaceData != NULL)
        {
            for(int VirId=0; VirId< pWanDmlIfaceData->data.NoOfVirtIfs; VirId++)
            {
                snprintf(tmpVIfTableName, sizeof(tmpVIfTableName), WANMGR_VIRTUAL_INFACE_TABLE, (i+1));
                rc = rbusTable_registerRow(rbusHandle, tmpVIfTableName, (VirId+1), AliasName); //TODO: NEW_DESIGN get Alias name for virtual table
                if(rc != RBUS_ERROR_SUCCESS)
                {
                    CcspTraceError(("%s %d - VirtualInterface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, (VirId+1), tmpVIfTableName, rc));
                    return rc;
                }
                else
                {
                    CcspTraceInfo(("%s %d - VirtualInterface(%d) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, (VirId+1), tmpVIfTableName, AliasName));
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
        memset(tmpVIfTableName,0,sizeof(tmpVIfTableName));
#endif /** WAN_MANAGER_UNIFICATION_ENABLED*/

        memset(AliasName,0,64);
     }

    return ANSC_STATUS_SUCCESS;
}

/*******************************************************************************
  WanMgr_RbusExit(): Unreg data elements and Exit
 ********************************************************************************/
ANSC_STATUS WanMgr_RbusExit()
{
    int rc = ANSC_STATUS_FAILURE;
    char param_name[256] = {0};

    CcspTraceInfo(("%s %d - WanMgr_RbusExit called\n", __FUNCTION__, __LINE__ ));
    rbus_unregDataElements(rbusHandle, (int)ARRAY_SZ(wanMgrRbusDataElements), wanMgrRbusDataElements);

    rbus_unregDataElements(rbusHandle, (int)ARRAY_SZ(wanMgrIfacePublishElements), wanMgrIfacePublishElements);
    for (int i = 0; i < uiTotalIfaces; i++)
    {
        memset(param_name, 0, sizeof(param_name));
        snprintf(param_name,sizeof(param_name), "%s.%d", WANMGR_INFACE_TABLE, (i+1));
        rc = rbusTable_unregisterRow(rbusHandle, WANMGR_INFACE_TABLE);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Interface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, i, param_name, rc));
            return rc;
        }
        else
        {
            CcspTraceInfo(("%s %d - Interface(%d) Table (%s) Registartion Successfully\n", __FUNCTION__, __LINE__, i, param_name));
        }

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
        snprintf(param_name,sizeof(param_name) ,"%s.%d.%s.%d",  WANMGR_INFACE_TABLE, (i+1), WANMGR_VIRTUALINFACE_TABLE_PREFIX, (1));
        rc = rbusTable_unregisterRow(rbusHandle, param_name);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Virtual Interface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, 1, param_name, rc));
            return rc;
        }
        else
        {
            CcspTraceInfo(("%s %d - Virtual Interface(%d) Table (%s) Registartion Successfully\n", __FUNCTION__, __LINE__, 1, param_name));
        }

        memset(param_name, 0, sizeof(param_name));
        snprintf(param_name,sizeof(param_name) ,"%s.%d", WANMGR_V1_INFACE_TABLE, (i+1));
        rc = rbusTable_unregisterRow(rbusHandle, WANMGR_V1_INFACE_TABLE);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Interface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, i, param_name, rc));
            return rc;
        }
        else
        {
            CcspTraceInfo(("%s %d - Interface(%d) Table (%s) Registartion Successfully\n", __FUNCTION__, __LINE__, i, param_name));
        }
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
    }

    WanMgr_Rbus_UnSubscribeDML();

    rbus_close(rbusHandle);
    return ANSC_STATUS_SUCCESS;
}

/*******************************************************************************
  WanMgr_Rbus_EventPublishHandler(): publish rbus events
 ********************************************************************************/
ANSC_STATUS WanMgr_Rbus_EventPublishHandler(const char *dm_event, void *dm_value, rbusValueType_t valueType)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    if(dm_event == NULL || dm_value == NULL)
    {
        CcspTraceInfo(("%s %d - Failed publishing\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, dm_event, value);
    CcspTraceInfo(("%s %d - dm_event[%s] valueType[%d]\n", __FUNCTION__, __LINE__, dm_event,valueType));
    switch(valueType)
    {
        case RBUS_BOOLEAN:
            rbusValue_SetBoolean(value, (*(bool*)(dm_value)));
            CcspTraceInfo(("%s %d - dm_value[%s]\n", __FUNCTION__, __LINE__, (*(bool*)(dm_value))?"True":"False"));
            break;
        case RBUS_UINT64:
            rbusValue_SetUInt64(value, (*(int*)(dm_value)));
            CcspTraceInfo(("%s %d - dm_value[%d]\n", __FUNCTION__, __LINE__, dm_value));
            break;
        case RBUS_STRING:
            rbusValue_SetString(value, (char*)dm_value);
            CcspTraceInfo(("%s %d - dm_value[%s]\n", __FUNCTION__, __LINE__, dm_value));
            break;
        default:
            CcspTraceError(("%s %d - Cannot identify valueType %d\n", __FUNCTION__, __LINE__, valueType));
            return ANSC_STATUS_FAILURE;
    }

    event.name = dm_event;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;
    rbusError_t rt = rbusEvent_Publish(rbusHandle, &event);
    if( rt != RBUS_ERROR_SUCCESS && rt != RBUS_ERROR_NOSUBSCRIBERS) //Ignore No subscribers present Error
    {
        CcspTraceError(("%s %d - event pusblishing failed. Error : %d\n", __FUNCTION__, __LINE__, rt));
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully Pusblished event for event %s \n", __FUNCTION__, __LINE__, dm_event));
    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return ANSC_STATUS_SUCCESS;
}
/*******************************************************************************
  WanMgr_Rbus_String_EventPublish_OnValueChange(): publish rbus events on value change
 ********************************************************************************/
ANSC_STATUS WanMgr_Rbus_String_EventPublish_OnValueChange(char *dm_event, void *prev_dm_value, void *dm_value)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t Value, preValue, byVal;
    int rc = ANSC_STATUS_FAILURE;

    if(dm_event == NULL || dm_value == NULL)
    {
        CcspTraceError(("%s %d - Failed publishing\n", __FUNCTION__, __LINE__));
        return rc;
    }

    rbusValue_Init(&Value);
    rbusValue_SetString(Value, (char*)dm_value);

    rbusValue_Init(&preValue);
    rbusValue_SetString(preValue, (char*)prev_dm_value);

    rbusValue_Init(&byVal);
    rbusValue_SetString(byVal, componentName);

    rbusObject_Init(&rdata, NULL);
    rbusObject_SetValue(rdata, "value", Value);
    rbusObject_SetValue(rdata, "oldValue", preValue);
    rbusObject_SetValue(rdata, "by", byVal);

    event.name = dm_event;
    event.data = rdata;
    event.type = RBUS_EVENT_VALUE_CHANGED;

    CcspTraceInfo(("%s %d - dm_event[%s],prev_dm_value[%s],dm_value[%s]\n", __FUNCTION__, __LINE__, dm_event, prev_dm_value, dm_value));

    if(rbusEvent_Publish(rbusHandle, &event) != RBUS_ERROR_SUCCESS)
    {
        CcspTraceWarning(("%s %d - Event [%s] published failed\n", __FUNCTION__, __LINE__,dm_event));
    }
    else
    {
        CcspTraceInfo(("%s %d - Event [%s] published successfully\n", __FUNCTION__, __LINE__, dm_event));
        rc = ANSC_STATUS_SUCCESS;
    }

    rbusValue_Release(Value);
    rbusValue_Release(preValue);
    rbusValue_Release(byVal);
    rbusObject_Release(rdata);
    return rc;
}

/*******************************************************************************
  WanMgr_Rbus_String_EventPublish(): publish rbus string events
 ********************************************************************************/
ANSC_STATUS WanMgr_Rbus_String_EventPublish(char *dm_event, void *dm_value)
{
    char *name = dm_event;
    if (WANMGR_WAN_STATUS_CHECK)
    {
       char String[20] = {0};
       WanMgr_EnumToString((*(UINT *)dm_value), ENUM_WAN_STATUS, String);
        CcspTraceInfo(("%s-%d : Virtual interface Status(%s)(%d) Publish\n", __FUNCTION__, __LINE__, String, (*(UINT *)dm_value)));
        return WanMgr_Rbus_EventPublishHandler(dm_event, &String, RBUS_STRING);
    }
    else
    {
        CcspTraceWarning(("WanMgr_Rbus_String_EventPublish: Invalid Input\n"));
        return ANSC_STATUS_FAILURE;
    }
}

/***********************************************************************
  Event subscribe handler API for objects:
 ***********************************************************************/
rbusError_t WanMgr_Rbus_SubscribeHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish)
{
    (void)handle;
    (void)filter;
    (void)interval;

    *autoPublish = false;

    CcspTraceWarning(("WanMgr_Rbus_SubscribeHandler called.\n"));

    if (action == RBUS_EVENT_ACTION_SUBSCRIBE)
    {
        CcspTraceInfo((" %s %d - %s Subscribed \n", __FUNCTION__, __LINE__, eventName));
    }
    else
    {
        CcspTraceInfo((" %s %d - %s Unsubscribed \n", __FUNCTION__, __LINE__, eventName));
    }
    return RBUS_ERROR_SUCCESS;
}

void *WanMgr_WanRemoteIfaceConfigure_thread(void *arg);
pthread_mutex_t RemoteIfaceConfigure_mutex = PTHREAD_MUTEX_INITIALIZER;

ANSC_STATUS WanMgr_WanRemoteIfaceConfigure(WanMgr_DeviceChangeEvent * pDeviceChangeEvent)
{
    if (pDeviceChangeEvent == NULL)
    {
        CcspTraceError(("%s %d:Invalid args..\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    pthread_t                threadId;
    int                      iErrorCode     = 0;

    iErrorCode = pthread_create( &threadId, NULL, &WanMgr_WanRemoteIfaceConfigure_thread, pDeviceChangeEvent);
    if( 0 != iErrorCode )
    {
        CcspTraceError(("%s %d - Failed to start WanMgr_WanRemoteIfaceConfigure_thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        if(pDeviceChangeEvent != NULL)
        {
            free(pDeviceChangeEvent);
        }
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - WanMgr_WanRemoteIfaceConfigure_thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    /* Adding sleep to make sure the thread locks RemoteIfaceConfigure_mutex */
    usleep(10000);
    return ANSC_STATUS_SUCCESS;
}
void *WanMgr_WanRemoteIfaceConfigure_thread(void *arg)
{
    int  cpeInterfaceIndex   = -1;
    int  newInterfaceIndex   = -1;
    int  rc = ANSC_STATUS_FAILURE;
    int  sizeOfRemoteDMsList = 0;
    WanMgr_DeviceChangeEvent * pDeviceChangeEvent = (WanMgr_DeviceChangeEvent *) arg;
    char AliasName[64] = {0};
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    char tmpVIfTableName[256] = {0};
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
    pthread_detach(pthread_self());
    pthread_mutex_lock(&RemoteIfaceConfigure_mutex);
    CcspTraceInfo(("%s %d - Enter \n", __FUNCTION__, __LINE__));

    CcspTraceInfo(("%s %d - remoteMac %s \n", __FUNCTION__, __LINE__, pDeviceChangeEvent->mac_addr));
    // check the interface table and return index of the match
    cpeInterfaceIndex =  WanMgr_Remote_IfaceData_index(pDeviceChangeEvent->mac_addr);

    if (cpeInterfaceIndex < 0)
    {
        if (pDeviceChangeEvent->available != true)
        {
            // No need to add new remote device if its not available
            CcspTraceError(("%s %d - Remote device not connected. So no need to add it in Interface table.\n", __FUNCTION__, __LINE__));
            free(pDeviceChangeEvent);
            pthread_mutex_unlock(&RemoteIfaceConfigure_mutex);
            /* it is detached and no one has joined, return null */
            return NULL;
        }

        // Initialise remote CPE's wan interface with default
        if (WanMgr_Remote_IfaceData_configure(pDeviceChangeEvent->mac_addr, &newInterfaceIndex) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s %d - Failed to configure remote Wan Interface Entry.\n", __FUNCTION__, __LINE__));
            free(pDeviceChangeEvent);
            pthread_mutex_unlock(&RemoteIfaceConfigure_mutex);
            return NULL;
        }

        WanMgr_GetIfaceAliasNameByIndex(newInterfaceIndex,AliasName);
        CcspTraceInfo(("%s %d - Iterface(%d) AliasName[%s]\n", __FUNCTION__, __LINE__, newInterfaceIndex, AliasName));

        rc = rbusTable_registerRow(rbusHandle, WANMGR_INFACE_TABLE, (newInterfaceIndex+1), AliasName);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Iterface(%d) Table (%s) Registartion failed, Error=%d \n", 
                            __FUNCTION__, __LINE__, (newInterfaceIndex+1), WANMGR_INFACE_TABLE, rc));
            free(pDeviceChangeEvent);
            pthread_mutex_unlock(&RemoteIfaceConfigure_mutex);
            return NULL;
        }
        CcspTraceInfo(("%s %d - Iterface(%d) Table (%s) Registartion Successfully AliasName[%s]\n", 
                       __FUNCTION__, __LINE__, (newInterfaceIndex+1), WANMGR_INFACE_TABLE,AliasName));

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
        rc = rbusTable_registerRow(rbusHandle, WANMGR_V1_INFACE_TABLE, (newInterfaceIndex+1), AliasName);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Iterface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, (newInterfaceIndex+1), WANMGR_V1_INFACE_TABLE, rc));
            pthread_mutex_unlock(&RemoteIfaceConfigure_mutex);
            return NULL;
        }
        else
        {
             CcspTraceInfo(("%s %d - Iterface(%d) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, (newInterfaceIndex+1), WANMGR_V1_INFACE_TABLE, AliasName));
        }

        //Virtual Interface Table
        snprintf(tmpVIfTableName, sizeof(tmpVIfTableName), WANMGR_VIRTUAL_INFACE_TABLE, (newInterfaceIndex+1));
        rc = rbusTable_registerRow(rbusHandle, tmpVIfTableName, (1), AliasName);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - VirtualInterface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, 1, tmpVIfTableName, rc));
            free(pDeviceChangeEvent);
            pthread_mutex_unlock(&RemoteIfaceConfigure_mutex);
            return NULL;
        }
        else
        {
             CcspTraceInfo(("%s %d - VirtualInterface(%d) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, 1, tmpVIfTableName, AliasName));
        }
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
        cpeInterfaceIndex = newInterfaceIndex;
    }

    WanMgr_Iface_Data_t * pWanDmlIfaceData = WanMgr_GetIfaceData_locked(cpeInterfaceIndex);
    if (pWanDmlIfaceData != NULL)
    {
        DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);
        if (pDeviceChangeEvent->available != true)
        {
            CcspTraceInfo(("%s %d: Remote device is not available. so setting interface:%d to Selection.Enable = FALSE\n", 
                            __FUNCTION__, __LINE__, cpeInterfaceIndex));
            pWanDmlIface->Selection.Enable = FALSE;
            pWanDmlIface->BaseInterfaceStatus = WAN_IFACE_PHY_STATUS_DOWN;

            free(pDeviceChangeEvent);
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            pthread_mutex_unlock(&RemoteIfaceConfigure_mutex);
            return NULL;
        }

        CcspTraceInfo(("%s %d: Setting interface:%d to Selection.Enable = TRUE\n", __FUNCTION__, __LINE__, cpeInterfaceIndex));
        pWanDmlIface->Selection.Enable = TRUE;
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }

    pthread_mutex_unlock(&RemoteIfaceConfigure_mutex);
    idm_invoke_method_Params_t IDM_request;

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    /** Check whether remote device has latest DML or not */
    CcspTraceInfo(("%s %d - Requesting  %s\n", __FUNCTION__, __LINE__,WANMGR_REMOTE_DEVICE_WAN_DML_VERSION));
    memset(&IDM_request,0, sizeof(idm_invoke_method_Params_t));
    strncpy(IDM_request.Mac_dest, pDeviceChangeEvent->mac_addr,sizeof(IDM_request.Mac_dest)-1);
    strncpy(IDM_request.param_name, WANMGR_REMOTE_DEVICE_WAN_DML_VERSION, sizeof(IDM_request.param_name)-1);
    IDM_request.timeout = 30;
    IDM_request.operation = IDM_GET;
    if(ANSC_STATUS_SUCCESS !=  WanMgr_IDM_InvokeSync(&IDM_request) )
    {
        memset( RemoteDMsQueryList, 0, sizeof(RemoteDMsQueryList) );
        memcpy( &RemoteDMsQueryList, &RemoteV1DMs, sizeof(RemoteV1DMs) );
        sizeOfRemoteDMsList = ARRAY_SZ(RemoteV1DMs);
    }
    else
#endif /** WAN_MANAGER_UNIFICATION_ENABLED */
    {
        memset( RemoteDMsQueryList, 0, sizeof(RemoteDMsQueryList) );
        memcpy( &RemoteDMsQueryList, &RemoteDMs, sizeof(RemoteDMs) );
        sizeOfRemoteDMsList = ARRAY_SZ(RemoteDMs);
    }

    /* IDM get request*/
    for (int i =0; i< sizeOfRemoteDMsList; i++)
    {
        if(RemoteDMsQueryList[i].get_request)
        {
            /* IDM get request*/
            CcspTraceInfo(("%s %d - Requesting  %s \n", __FUNCTION__, __LINE__,RemoteDMsQueryList[i]));
            memset(&IDM_request,0, sizeof(idm_invoke_method_Params_t));

            /* Update request parameters */
            strncpy(IDM_request.Mac_dest, pDeviceChangeEvent->mac_addr,sizeof(IDM_request.Mac_dest)-1);
            strncpy(IDM_request.param_name, RemoteDMsQueryList[i].name, sizeof(IDM_request.param_name)-1);
            IDM_request.timeout = 30;
            IDM_request.operation = IDM_GET;
            IDM_request.asyncHandle = &CPEInterface_AsyncMethodHandler; //pointer to callback

            WanMgr_IDM_Invoke(&IDM_request);
        }
    }

    sleep(3);
    /* IDM subscription request*/
    for (int i =0; i< sizeOfRemoteDMsList; i++)
    {
        if(RemoteDMsQueryList[i].subscription_request)
        {
            /* IDM get request*/
            CcspTraceInfo(("%s %d - Requesting  subscription %s \n", __FUNCTION__, __LINE__,RemoteDMsQueryList[i]));
            memset(&IDM_request,0, sizeof(idm_invoke_method_Params_t));

            /* Update request parameters */
            strncpy(IDM_request.Mac_dest, pDeviceChangeEvent->mac_addr,sizeof(IDM_request.Mac_dest)-1);
            strncpy(IDM_request.param_name, RemoteDMsQueryList[i].name, sizeof(IDM_request.param_name)-1);
            IDM_request.timeout = 600;
            IDM_request.operation = IDM_SUBS;
            IDM_request.asyncHandle = &CPEInterface_AsyncMethodHandler; //pointer to callback

            WanMgr_IDM_Invoke(&IDM_request);
        }
    }

    pWanDmlIfaceData = WanMgr_GetIfaceData_locked(cpeInterfaceIndex);
    if (pWanDmlIfaceData != NULL)
    {
        DML_WAN_IFACE* pWanDmlIface = &(pWanDmlIfaceData->data);
        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanDmlIface->VirtIfList,0),WAN_INFO_IPv4_CONFIG_TYPE);
        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanDmlIface->VirtIfList,0),WAN_INFO_IPv6_CONFIG_TYPE);
        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanDmlIface->VirtIfList,0),WAN_INFO_CONNECTIVITY_CHECK_TYPE);
        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanDmlIface->VirtIfList,0),WAN_INFO_IP_MODE);
        WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
    }
    free(pDeviceChangeEvent);
    pthread_exit(NULL);
    return NULL;
}

static void CPEInterface_AsyncMethodHandler(
    rbusHandle_t handle,
    char const* methodName,
    rbusError_t error,
    rbusObject_t params)
{
    (void)handle;
    int cpeInterfaceIndex = -1;

    CcspTraceInfo(("%s %d - asyncMethodHandler called: %s  error=%d\n", __FUNCTION__, __LINE__, methodName, error));
    if(error == RBUS_ERROR_SUCCESS)
    {
        CcspTraceInfo(("%s %d - asyncMethodHandler request success\n", __FUNCTION__, __LINE__));
        rbusObject_fwrite(params, 1, stdout);
    }else
    {
        CcspTraceError(("%s %d - asyncMethodHandler request failed\n", __FUNCTION__, __LINE__));
        return;
    }

    if(strcmp(methodName, "Device.X_RDK_Remote.Invoke()") == 0)
    {
        /* get the return values from IDM */
        rbusValue_t value;

        value = rbusObject_GetValue(params, "Mac_source");
        const char *pMac = rbusValue_GetString(value, NULL);
        CcspTraceInfo(("%s %d - from source MAC %s\n", __FUNCTION__, __LINE__, pMac));

        cpeInterfaceIndex =  WanMgr_Remote_IfaceData_index(pMac);

        if (cpeInterfaceIndex >= 0)
        {
            value = rbusObject_GetValue(params, "param_name");
            const char *name = rbusValue_GetString(value, NULL);
            CcspTraceInfo(("%s %d - param_name %s\n", __FUNCTION__, __LINE__, name));

            value = rbusObject_GetValue(params, "param_value");
            const char *pValue = rbusValue_GetString(value, NULL);
            CcspTraceInfo(("%s %d - param_value %s\n", __FUNCTION__, __LINE__, pValue));

            WanMgr_Iface_Data_t* pWanDmlIfaceData = WanMgr_GetIfaceData_locked(cpeInterfaceIndex);
            if(pWanDmlIfaceData != NULL)
            {
                DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);

                if( strstr(name, ".Name") != NULL)
                {
                    strncpy( pWanIfaceData->Name, pValue ,sizeof(pWanIfaceData->Name)-1);
                }
                else if( strstr(name, ".DisplayName") != NULL)
                {
                    char DisplayName[64] = {0};
                    snprintf(DisplayName, sizeof(DisplayName), "REMOTE_%s" , pValue);
                    strncpy( pWanIfaceData->DisplayName, DisplayName ,sizeof(pWanIfaceData->DisplayName)-1);
                }
                else if( WANMGR_ALIASNAME_CHECK )
                {
                    char AliasName[64] = {0};
                    snprintf(AliasName, sizeof(AliasName), "REMOTE_%s" , pValue);
                    if(strcmp(AliasName,pWanIfaceData->AliasName) !=0)
                    {
                        strncpy( pWanIfaceData->AliasName, AliasName,sizeof(pWanIfaceData->AliasName)-1 );
                        //Set Alias name of Virtual interface
                        strncpy( pWanIfaceData->VirtIfList->Alias, AliasName,sizeof(pWanIfaceData->VirtIfList->Alias)-1 );
                        //Register the interface again if Alias changed
                        char param_name[256] = {0};
                        snprintf(param_name,sizeof(param_name), "%s.%d", WANMGR_INFACE_TABLE, (cpeInterfaceIndex+1));
                        rbusTable_unregisterRow(rbusHandle, param_name);

                        int rc = -1;
                        rc = rbusTable_registerRow(rbusHandle, WANMGR_INFACE_TABLE, (cpeInterfaceIndex+1), AliasName);
                        if(rc != RBUS_ERROR_SUCCESS)
                        {
                            CcspTraceError(("%s %d - Iterface(%d) Table (%s) Registartion failed \n", 
                                        __FUNCTION__, __LINE__, (cpeInterfaceIndex+1), WANMGR_INFACE_TABLE));
                        }
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
                        char tmpVIfTableName[256] = {0};
                        for(int VirId=0; VirId< pWanDmlIfaceData->data.NoOfVirtIfs; VirId++)
                        {
                            snprintf(tmpVIfTableName, sizeof(tmpVIfTableName), WANMGR_VIRTUAL_INFACE_TABLE_ALIAS, AliasName);
                            rc = rbusTable_registerRow(rbusHandle, tmpVIfTableName, (VirId+1), AliasName); //TODO: NEW_DESIGN get Alias name for virtual table
                            if(rc != RBUS_ERROR_SUCCESS)
                            {
                                CcspTraceError(("%s %d - VirtualInterface(%d) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, (VirId+1), tmpVIfTableName, rc));
                            }
                            else
                            {
                                CcspTraceInfo(("%s %d - VirtualInterface(%d) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, (VirId+1), tmpVIfTableName, AliasName));
                            }
                        }
#endif
                    }
                }
                else if( WANMGR_PHY_STATUS_CHECK )
                {
                    if(strncmp(pValue,"Down",strlen(pValue)) == 0)
                    {
                        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanIfaceData->VirtIfList,0),WAN_ERROR_PHY_DOWN);
                    }
                    else if(strncmp(pValue,"Up",strlen(pValue)) == 0)
                    {
                        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanIfaceData->VirtIfList,0),WAN_INFO_PHY_UP);
                    }				
                    WanMgr_StringToEnum(&pWanIfaceData->BaseInterfaceStatus, ENUM_PHY, pValue);
                }
                else if( WANMGR_WAN_LINKSTATUS_CHECK )
                {
                    if(strncmp(pValue,"Down",strlen(pValue)) == 0)
                    {
                        WanMgr_ProcessTelemetryMarker(WanMgr_getVirtualIfaceById( pWanIfaceData->VirtIfList,0),WAN_ERROR_VLAN_DOWN);
                    }				
                    WanMgr_StringToEnum(&pWanIfaceData->VirtIfList->VLAN.Status, ENUM_WAN_LINKSTATUS, pValue);
                    if(pWanIfaceData->VirtIfList->VLAN.Status == WAN_IFACE_LINKSTATUS_UP)
                    {
                        strncpy(pWanIfaceData->VirtIfList->Name, REMOTE_INTERFACE_NAME, sizeof(pWanIfaceData->VirtIfList->Name));
                        WanMgr_getRemoteWanParamsFromPSM(pWanIfaceData->VirtIfList);

                    }
                }
                else if( WANMGR_WAN_STATUS_CHECK )
                {
                    WanMgr_StringToEnum(&pWanIfaceData->VirtIfList->RemoteStatus, ENUM_WAN_STATUS, pValue);
                }
            }
            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
        }
        else
        {
            CcspTraceError(("%s %d - Remote Interface Not found \n", __FUNCTION__, __LINE__));
        }
    }
}

static int WanMgr_Remote_IfaceData_index(const char *macAddress)
{
    int cpeInterfaceIndex = -1;
    UINT uiTotalIfaces = 0;
    UINT uiLoopCount   = 0;

    CcspTraceInfo(("%s %d - index search for macAddress=[%s]\n", __FUNCTION__, __LINE__, macAddress));

    //Get uiTotalIfaces
    uiTotalIfaces = WanMgr_IfaceData_GetTotalWanIface();

    if(uiTotalIfaces > 0)
    {
        for( uiLoopCount = 0; uiLoopCount < uiTotalIfaces; uiLoopCount++ )
        {

            WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
            if(pWanDmlIfaceData != NULL)
            {
                DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data);
                if((0 == strncasecmp(pWanIfaceData->RemoteCPEMac, macAddress, BUFLEN_128)) && (pWanIfaceData->IfaceType == REMOTE_IFACE))
                {
                    cpeInterfaceIndex = uiLoopCount ;
                }

                WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);
            }
            if(cpeInterfaceIndex >= 0)
            {
                break;
            }
        }
    }
    CcspTraceInfo(("%s %d - End cpeInterfaceIndex=[%d]\n", __FUNCTION__, __LINE__, cpeInterfaceIndex));
    return cpeInterfaceIndex;
}

ANSC_STATUS WanMgr_RestartUpdateRemoteIface()
{
    char dmQuery[BUFLEN_256] = {0};
    char dmValue[BUFLEN_256] = {0};
    int numofRemoteEntries = 0;
    ANSC_STATUS status = ANSC_STATUS_SUCCESS;

    CcspTraceInfo(("%s %d - Enter \n", __FUNCTION__, __LINE__));

    DEVICE_NETWORKING_MODE  DeviceMode;
    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        DeviceMode = pWanConfigData->data.DeviceNwMode;
        WanMgrDml_GetConfigData_release(pWanConfigData);

        if (DeviceMode == GATEWAY_MODE)
        {
            CcspTraceInfo(("%s %d -DeviceNwMode set to GATEWAY_MODE. Configure remote Iface\n", __FUNCTION__, __LINE__));
        }
        else
        {
            CcspTraceInfo(("%s %d -DeviceNwMode is not GATEWAY_MODE. Do not configure remote Iface\n", __FUNCTION__, __LINE__));
            return ANSC_STATUS_SUCCESS;
        }
    }

    // get mac of connected remote CPE
    snprintf(dmQuery, sizeof(dmQuery)-1, X_RDK_REMOTE_DEVICE_NUM_OF_ENTRIES);

    if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, dmValue))
    {
        CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
        return ANSC_STATUS_FAILURE;
    }

    numofRemoteEntries = atoi(dmValue);
    CcspTraceInfo(("%s %d - numofRemoteEntries = %d\n", __FUNCTION__, __LINE__,numofRemoteEntries));

    //IDM first entry will be local device.
    if(numofRemoteEntries > 1)
    {
        UINT deviceStatus = DEVICE_NOT_DETECTED;
        WanMgr_DeviceChangeEvent * pDeviceChangeEvent;

        for( int i = 2; i <= numofRemoteEntries; i++)
        {
            memset(dmQuery, 0, sizeof(dmQuery));
            memset(dmValue, 0, sizeof(dmValue));
            snprintf(dmQuery, sizeof(dmQuery)-1, X_RDK_REMOTE_DEVICE_MAC, i);
            if ( ANSC_STATUS_FAILURE == WanMgr_RdkBus_GetParamValueFromAnyComp (dmQuery, dmValue))
            {
                CcspTraceError(("%s-%d: %s, Failed to get param value\n", __FUNCTION__, __LINE__, dmQuery));
                status = ANSC_STATUS_FAILURE;
                continue;
            }
            CcspTraceInfo(("%s %d - Remote device MAC %s \n", __FUNCTION__, __LINE__,dmValue));

            pDeviceChangeEvent = (WanMgr_DeviceChangeEvent *)malloc (sizeof(WanMgr_DeviceChangeEvent));
            if (pDeviceChangeEvent == NULL)
            {
                CcspTraceError(("%s %d: malloc failure:%s\n", __FUNCTION__, __LINE__, strerror(errno)));
                status = ANSC_STATUS_FAILURE;
                break;
            }
            memset(pDeviceChangeEvent, 0, sizeof(WanMgr_DeviceChangeEvent));
            strncpy(pDeviceChangeEvent->mac_addr, dmValue, sizeof(pDeviceChangeEvent->mac_addr)-1);
            /* check if device is available */
            memset(dmQuery, 0, sizeof(dmQuery));
            snprintf(dmQuery, sizeof(dmQuery)-1, X_RDK_REMOTE_DEVICE_STATUS, i); 
            if (WanMgr_Rbus_getUintParamValue(dmQuery, &deviceStatus) == ANSC_STATUS_SUCCESS)
                pDeviceChangeEvent->available = (deviceStatus == DEVICE_CONNECTED) ? true : false;
            else
                pDeviceChangeEvent->available = false;
            CcspTraceInfo(("%s %d: Received remote iface with MAC:%s available:%d\n", __FUNCTION__, __LINE__, pDeviceChangeEvent->mac_addr, pDeviceChangeEvent->available));
            WanMgr_WanRemoteIfaceConfigure(pDeviceChangeEvent);
        }
    }
    return status;
}
#endif
static void WanMgr_TandD_EventHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    const char* eventName = event->name;

    if((eventName == NULL))
    {
        CcspTraceError(("%s : FAILED , value is NULL\n",__FUNCTION__));
        return;
    }

    if (strstr(eventName, TANDD_CONNECTIVITY_CHECK_TREE) && strstr(eventName, TANDD_CONNECTIVITY_CHECK_MONITOR_STR))
    {
        char Alias[64] = {0};
        CcspTraceInfo(("%s %d: Received %s\n", __FUNCTION__, __LINE__, eventName));
        sscanf(eventName, "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.[%63[^]]].MonitorResult", Alias);
        CcspTraceInfo(("%s %d MonitorResult interface Alias : %s\n", __FUNCTION__, __LINE__,Alias));
        rbusValue_t value;
        value = rbusObject_GetValue(event->data, "value");
        CONNECTIVITY_STATUS res = rbusValue_GetUInt32(value);

        DML_VIRTUAL_IFACE *p_VirtIf = WanMgr_GetVirtIfDataByAlias_locked(Alias);
        if(p_VirtIf != NULL)
        {           
            if(res == WAN_CONNECTIVITY_UP)
            {
                WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_INFO_CONNECTIVITY_CHECK_STATUS_UP_IPV4);
                WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_INFO_CONNECTIVITY_CHECK_STATUS_UP_IPV6);
            }
            else if(res == WAN_CONNECTIVITY_DOWN)
            {
                WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_ERROR_CONNECTIVITY_CHECK_STATUS_DOWN_IPV4);
                WanMgr_ProcessTelemetryMarker(p_VirtIf,WAN_ERROR_CONNECTIVITY_CHECK_STATUS_DOWN_IPV6);
            }		
            p_VirtIf->IP.Ipv4ConnectivityStatus = res;
            p_VirtIf->IP.Ipv6ConnectivityStatus = res;
            WanMgr_VirtualIfaceData_release(p_VirtIf);
            CcspTraceInfo(("%s %d: Successfully assigned Connectivity Result %s for interface %s\n", __FUNCTION__, __LINE__, (res==1)?"WAN_CONNECTIVITY_UP":"WAN_CONNECTIVITY_DOWN", Alias));
        }
    }
}

/* WCC - Wan Connectivity Check*/
ANSC_STATUS WanMgr_Configure_TAD_WCC(DML_VIRTUAL_IFACE *p_VirtIf,  WCC_EVENT Event)
{
    pthread_t                threadId;
    int                      iErrorCode     = 0;


    if(Event != WCC_STOP && (p_VirtIf->IP.Ipv4Data.dnsServer[0] == '\0') && (p_VirtIf->IP.Ipv4Data.dnsServer1[0] == '\0') &&
      (p_VirtIf->IP.Ipv6Data.nameserver[0] == '\0') && (p_VirtIf->IP.Ipv6Data.nameserver1[0] == '\0'))
    {
        CcspTraceError(("%s %d: DNS servers are not configured. (TAD) DNS health check not triggered\n",__FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    TAD_WCC_Event *pTADEvent = malloc(sizeof(TAD_WCC_Event));
    memset(pTADEvent, 0, sizeof(TAD_WCC_Event));
    strncpy(pTADEvent->IfaceName, p_VirtIf->Name, sizeof(pTADEvent->IfaceName)-1);
    strncpy(pTADEvent->Alias, p_VirtIf->Alias, sizeof(pTADEvent->Alias)-1);
    snprintf(pTADEvent->IPv4_DNS_Servers, sizeof(pTADEvent->IPv4_DNS_Servers), "%s,%s",p_VirtIf->IP.Ipv4Data.dnsServer,p_VirtIf->IP.Ipv4Data.dnsServer1);
    snprintf(pTADEvent->IPv4_Gateway, sizeof(pTADEvent->IPv4_Gateway), "%s",p_VirtIf->IP.Ipv4Data.gateway);
    snprintf(pTADEvent->IPv6_DNS_Servers, sizeof(pTADEvent->IPv6_DNS_Servers), "%s,%s",p_VirtIf->IP.Ipv6Data.nameserver,p_VirtIf->IP.Ipv6Data.nameserver1);
    snprintf(pTADEvent->IPv6_Gateway, sizeof(pTADEvent->IPv6_Gateway), "%s",p_VirtIf->IP.Ipv6RA.acDefaultGw);
    pTADEvent->Event = Event;

    //Run in thread to avoid mutex deadlock between WanManager and rbus handle
    iErrorCode = pthread_create( &threadId, NULL, &WanMgr_Configure_WCC_Thread, pTADEvent);
    if( 0 != iErrorCode )
    {
        CcspTraceError(("%s %d - Failed to start WanMgr_Configure_WCC_Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        free(pTADEvent);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - WanMgr_Configure_WCC_Thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    p_VirtIf->IP.RestartConnectivityCheck = FALSE; //RESET RestartConnectivityCheck trigger
    return ANSC_STATUS_SUCCESS;
}



void *WanMgr_Configure_WCC_Thread(void *arg)
{

    TAD_WCC_Event * pTADEvent = (TAD_WCC_Event *) arg;
    pthread_detach(pthread_self());

    rbusObject_t inParams;
    rbusObject_t outParams = NULL;
    rbusValue_t value;

    rbusObject_Init(&inParams, NULL);

    CcspTraceInfo(("%s %d:  TAD connectivity check event for  Name:%s Alias :%s Event :%s\n"
                , __FUNCTION__, __LINE__, pTADEvent->IfaceName, pTADEvent->Alias,
                pTADEvent->Event == WCC_START?"START":(pTADEvent->Event == WCC_RESTART?"RESTART":"STOP")));

    // set linux interface name
    rbusValue_Init(&value);
    rbusValue_SetString(value, pTADEvent->IfaceName );
    rbusObject_SetValue(inParams, "linux_interface_name", value);
    rbusValue_Release(value);

    // set alias
    rbusValue_Init(&value);
    rbusValue_SetString(value, pTADEvent->Alias );
    rbusObject_SetValue(inParams, "alias", value);
    rbusValue_Release(value);


    // set IPv4 nameserver list
    CcspTraceInfo(("%s %d:  IPv4_DNS_Servers %s  \n", __FUNCTION__, __LINE__, pTADEvent->IPv4_DNS_Servers));

    rbusValue_Init(&value);
    rbusValue_SetString(value, pTADEvent->IPv4_DNS_Servers );
    rbusObject_SetValue(inParams, "IPv4_DNS_Servers", value);
    rbusValue_Release(value);

    // set IPv4 Gateway
    CcspTraceInfo(("%s %d:  IPv4_Gateway %s  \n", __FUNCTION__, __LINE__, pTADEvent->IPv4_Gateway));
    rbusValue_Init(&value);
    rbusValue_SetString(value, pTADEvent->IPv4_Gateway);
    rbusObject_SetValue(inParams, "IPv4_Gateway", value);
    rbusValue_Release(value);

    //TODO: MeshWANInterface_UlaAddr is a workaround for remote interfaces, Should be removed after moving ULA ipv6 configurations to WanManager.
    if(strncmp(pTADEvent->Alias, "REMOTE", 6)==0)
    {
        char MeshWANInterfaceUla[512] = {0};
        sysevent_get(sysevent_fd, sysevent_token, "MeshWANInterface_UlaAddr", MeshWANInterfaceUla, sizeof(MeshWANInterfaceUla));
        strtok(MeshWANInterfaceUla, "/");
        snprintf(pTADEvent->IPv6_DNS_Servers, sizeof(pTADEvent->IPv6_DNS_Servers), "%s,", strtok(MeshWANInterfaceUla, "/"));
        snprintf(pTADEvent->IPv6_Gateway, sizeof(pTADEvent->IPv6_Gateway), "%s", strtok(MeshWANInterfaceUla, "/"));
    }

    // set IPv6 nameserver list
    CcspTraceInfo(("%s %d:  IPv6_DNS_Servers %s  \n", __FUNCTION__, __LINE__, pTADEvent->IPv6_DNS_Servers));
    rbusValue_Init(&value);
    rbusValue_SetString(value,  pTADEvent->IPv6_DNS_Servers );
    rbusObject_SetValue(inParams, "IPv6_DNS_Servers", value);
    rbusValue_Release(value);

    // set IPv6 Gateway
    CcspTraceInfo(("%s %d:  IPv6_Gateway %s  \n", __FUNCTION__, __LINE__, pTADEvent->IPv6_Gateway));
    rbusValue_Init(&value);
    rbusValue_SetString(value, pTADEvent->IPv6_Gateway);
    rbusObject_SetValue(inParams, "IPv6_Gateway", value);
    rbusValue_Release(value);

    rbusError_t rc = RBUS_ERROR_SUCCESS;

    char dml[512] = {0};
    snprintf(dml, sizeof(dml), TANDD_CONNECTIVITY_CHECK_RESULT, pTADEvent->Alias);


    if(pTADEvent->Event == WCC_STOP || pTADEvent->Event == WCC_RESTART )
    {
        //Unsubscribe TANDD_CONNECTIVITY_CHECK_RESULT 
        rc = rbusEvent_Unsubscribe(rbusHandle, dml);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Failed to Unsubscribe %s, Error=%s \n", __FUNCTION__, __LINE__, dml, rbusError_ToString(rc)));
        }else 
            CcspTraceInfo(("%s %d:  Unsubscribed to %s  \n", __FUNCTION__, __LINE__, dml));

        //Stop connectivity check 
        rc = rbusMethod_Invoke(rbusHandle, TANDD_STOP_CONNECTIVITY_CHECK, inParams, &outParams);

        //Currently, TandD doesn't send reply outParams Release if resource allocated resource.
        if(outParams)
            rbusObject_Release(outParams);

        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d: ConnectivityCheck: rbusMethod_Invoke(%s) failed\n",__FUNCTION__, __LINE__, TANDD_STOP_CONNECTIVITY_CHECK));
        }else 
            CcspTraceInfo(("%s %d: ConnectivityCheck: rbusMethod_Invoke %s success\n",__FUNCTION__, __LINE__ , TANDD_STOP_CONNECTIVITY_CHECK ));
    }

    if(pTADEvent->Event == WCC_START || pTADEvent->Event == WCC_RESTART )
    {
        //Start connectivity check 
        rc = rbusMethod_Invoke(rbusHandle, TANDD_START_CONNECTIVITY_CHECK, inParams, &outParams);

        //Currently, TandD doesn't send reply outParams Release if resource allocated resource.
        if(outParams)
            rbusObject_Release(outParams);

        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d: ConnectivityCheck: rbusMethod_Invoke(%s) failed\n",__FUNCTION__, __LINE__, TANDD_START_CONNECTIVITY_CHECK));
            free(pTADEvent);
            return NULL;
        }
        CcspTraceInfo(("%s %d: ConnectivityCheck: rbusMethod_Invoke %s success\n",__FUNCTION__, __LINE__ , TANDD_START_CONNECTIVITY_CHECK));

        //Subcribe TANDD_CONNECTIVITY_CHECK_RESULT 
        rc = RBUS_ERROR_SUCCESS;
        rc = rbusEvent_Subscribe(rbusHandle, dml, WanMgr_TandD_EventHandler, NULL, 60);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, dml, rbusError_ToString(rc)));
            free(pTADEvent);
            return NULL;
        }
        CcspTraceInfo(("%s %d: startConnectivityCheck() Subscribed to %s  n", __FUNCTION__, __LINE__, dml));
    }

    rbusObject_Release(inParams);
    free(pTADEvent);
    pthread_exit(NULL);
    return NULL;
}

UINT WanMgr_ParseIndexFromAPIName(const char *name)
{
    UINT index = 0; //Set default  interface index
    char AliasName[64] = {0};

    if(name == NULL)
    {
        CcspTraceError(("%s %d - Invalid input parameters\n", __FUNCTION__, __LINE__));
        return 0;
    }
    
    sscanf(name, WANMGR_INFACE_TABLE".%d.", &index);
    if(index  == 0)
    {
        sscanf(name, WANMGR_INFACE_TABLE".%63s.", &AliasName);
        index = WanMgr_GetIfaceIndexByAliasName(AliasName);
    }

    sscanf(name, WANMGR_INFACE_TABLE".%d.", &index);

    if(index == 0)
    {
        CcspTraceError(("%s %d - Invalid index in API name: %s\n", __FUNCTION__, __LINE__, name));
        return -1;
    }
    return index;
}

/**
 * @brief Starts the WAN interface state machine for the specified interface.
 *
 * This handler checks if the requested WAN interface is disabled. If it is not disabled,
 * it initiates the state machine for the interface. The API expects the alias name to be
 * provided in the methodName parameter.
 *
 * @param handle        The rbus handle.
 * @param methodName    The name of the method, expected to contain the interface alias.
 * @param inParams      Input parameters as an rbus object.
 * @param outParams     Output parameters as an rbus object.
 * @param asyncHandle   Handle for asynchronous method invocation.
 * @return              rbusError_t indicating success or failure of the operation.
 */

rbusError_t WanMgr_rbusMethod_Iface_StartWan(rbusHandle_t handle, char const* name, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
    (void)handle;
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    UINT index = WanMgr_ParseIndexFromAPIName(name);
    
    if(index <= 0)
    {
        CcspTraceError(("%s %d - Invalid index\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    CcspTraceInfo(("%s %d: Starting WAN interface SM for Interface %d\n", __FUNCTION__, __LINE__, index));
    if(WanMgr_StartWanVISM(index -1, WAN_IFACE_SELECTED) != 0)
    {
        CcspTraceError(("%s %d: Failed to start WAN for interface %d \n", __FUNCTION__, __LINE__, index));
        ret = RBUS_ERROR_BUS_ERROR;
    }

    return ret;
}


/**
 * @brief Handles the RBUS method call to stop a WAN interface.
 *
 * This function is invoked when an RBUS method call is received to stop a specific WAN interface.
 * It processes the input parameters, performs the necessary operations to stop the WAN interface,
 * and populates the output parameters with the result.
 *
 * @param[in] handle         The RBUS handle associated with the current session.
 * @param[in] methodName     The name of the RBUS method being invoked.
 * @param[in] inParams       The input parameters for the method call.
 * @param[out] outParams     The output parameters to be populated with the result.
 * @param[in] asyncHandle    The handle for asynchronous method invocation, if applicable.
 *
 * @return rbusError_t       Returns RBUS error code indicating success or failure of the operation.
 */
rbusError_t WanMgr_rbusMethod_Iface_StopWan(rbusHandle_t handle, char const* name, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
     (void)handle;
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    UINT index = WanMgr_ParseIndexFromAPIName(name);
    
    if(index <= 0)
    {
        CcspTraceError(("%s %d - Invalid index\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    CcspTraceInfo(("%s %d: Calling WanMgr_StopWanVISM for interface %d\n", __FUNCTION__, __LINE__, index));
    if(WanMgr_StopWanVISM(index - 1) != 0)
    {
        CcspTraceError(("%s %d: Failed to stop WAN for interface %d \n", __FUNCTION__, __LINE__, index));
        ret = RBUS_ERROR_BUS_ERROR;
    }

    return ret;
}


/**
 * @brief Handles the RBUS method call to activate a WAN interface.
 *
 * This function is invoked when an RBUS method call is received to activate a specific WAN interface.
 * It processes the input parameters, performs the necessary operations to activate the WAN interface,
 * and returns the appropriate RBUS error code.
 *
 * @param[in] handle         The RBUS handle associated with the current session.
 * @param[in] name           The name of the RBUS method being invoked.
 * @param[in] inParams       The input parameters for the method call.
 * @param[out] outParams     The output parameters to be populated with the result.
 * @param[in] asyncHandle    The handle for asynchronous method invocation, if applicable.
 *
 * @return rbusError_t       Returns RBUS error code indicating success or failure of the operation.
 */
rbusError_t WanMgr_rbusMethod_Iface_ActivateWan(rbusHandle_t handle, char const* name, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
    (void)handle;
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;

    rbusError_t ret = RBUS_ERROR_SUCCESS;
    UINT index = WanMgr_ParseIndexFromAPIName(name);
    
    if(index <= 0)
    {
        CcspTraceError(("%s %d - Invalid index\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    CcspTraceInfo(("%s %d: Activating WAN interface for Interface %d\n", __FUNCTION__, __LINE__, index));
    if( WanMgr_ActivateInterface(index - 1) != 0)
    {
        CcspTraceError(("%s %d: Failed to activate WAN for interface %d \n", __FUNCTION__, __LINE__, index));
        ret = RBUS_ERROR_BUS_ERROR;
    }

    return ret;
}

/**
 * @brief Handles the RBUS method call to deactivate a WAN interface.
 *
 * This function is invoked when an RBUS method call is received to deactivate a specific WAN interface.
 * It processes the input parameters, performs the necessary operations to deactivate the WAN interface,
 * and returns the appropriate RBUS error code.
 *
 * @param[in] handle         The RBUS handle associated with the current session.
 * @param[in] name           The name of the RBUS method being invoked.
 * @param[in] inParams       The input parameters for the method call.
 * @param[out] outParams     The output parameters to be populated with the result.
 * @param[in] asyncHandle    The handle for asynchronous method invocation, if applicable.
 *
 * @return rbusError_t       Returns RBUS error code indicating success or failure of the operation.
 */
rbusError_t WanMgr_rbusMethod_Iface_DeactivateWan(rbusHandle_t handle, char const* name, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
    (void)handle;
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    UINT index = WanMgr_ParseIndexFromAPIName(name);
    
    if(index <= 0)
    {
        CcspTraceError(("%s %d - Invalid index\n", __FUNCTION__, __LINE__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    CcspTraceInfo(("%s %d: Deactivating WAN interface for Interface %d\n", __FUNCTION__, __LINE__, index));
    if(WanMgr_DeactivateInterface(index - 1) != 0)
    {
        CcspTraceError(("%s %d: Failed to deactivate WAN for interface %d \n", __FUNCTION__, __LINE__, index));
        ret = RBUS_ERROR_BUS_ERROR;
    }
    return ret;
}


/**
 * @brief Handles DisableAutoRouting RBUS method for WAN Manager.
 *
 * This function is used to request or take control from the WAN failover policy
 * to activate or deactivate a group. It processes the DisableAutoRouting
 * RBUS method, handling the input and output parameters as required.
 *
 * @param[in] handle         The RBUS handle for the current session.
 * @param[in] methodName     The name of the invoked RBUS method.
 * @param[in] inParams       The input parameters for the method call.
 * @param[out] outParams     The output parameters to be populated by this function.
 * @param[in] asyncHandle    The asynchronous method handle, if applicable.
 *
 * @return rbusError_t       Returns RBUS error code indicating success or failure.
 */
rbusError_t WanMgr_rbusMethod_DisableAutoRouting(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
    (void)handle;
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;

    CcspTraceInfo(("%s %d - DisableAutoRouting called for method: %s\n", __FUNCTION__, __LINE__, methodName));

    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        pWanConfigData->data.DisableAutoRouting = TRUE;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }
    CcspTraceInfo(("%s %d - SelectionControl Requested\n", __FUNCTION__, __LINE__));
    
    return RBUS_ERROR_SUCCESS;
}

/**
 * @brief Releases control back to the WAN failover policy.
 *
 * This function handles the RBUS method call to release control from a external component
 * and returns it to the WAN failover policy. It processes the EnableAutoRouting RBUS method,
 * handling the input and output parameters as required.
 *
 * @param[in] handle         The RBUS handle for the current session.
 * @param[in] methodName     The name of the invoked RBUS method.
 * @param[in] inParams       The input parameters for the method call.
 * @param[out] outParams     The output parameters to be populated by this function.
 * @param[in] asyncHandle    The asynchronous method handle, if applicable.
 *
 * @return rbusError_t       Returns RBUS error code indicating success or failure.
 */
rbusError_t WanMgr_rbusMethod_EnableAutoRouting(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
    (void)handle;
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;

    CcspTraceInfo(("%s %d - EnableAutoRouting called for method: %s\n", __FUNCTION__, __LINE__, methodName));

    WanMgr_Config_Data_t*   pWanConfigData = WanMgr_GetConfigData_locked();
    if(pWanConfigData != NULL)
    {
        pWanConfigData->data.DisableAutoRouting = FALSE;
        WanMgrDml_GetConfigData_release(pWanConfigData);
    }
    CcspTraceInfo(("%s %d - SelectionControl Released\n", __FUNCTION__, __LINE__));

    return RBUS_ERROR_SUCCESS;
}

static void WanMgr_InterfaceStatus_EventHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    const char* eventName = event->name;

    if((eventName == NULL))
    {
        CcspTraceError(("%s %d : FAILED , value is NULL\n",__FUNCTION__, __LINE__));
        return;
    }

    rbusValue_t value;
    value = rbusObject_GetValue(event->data, NULL);

    char acStatus[16] = {0};
    strncpy(acStatus , rbusValue_GetString(value, NULL),sizeof(acStatus)-1);

    CcspTraceInfo(("%s %d: Received '%s' event value is '%s'\n", __FUNCTION__, __LINE__, eventName, ((acStatus[0] != '\0') ? acStatus : "Empty")));

    //Ignore further processing when value is not valid
    if ( '\0' == acStatus[0] )
    {
        CcspTraceInfo(("%s %d: Received '%s' event value is empty so ignoring process further\n", __FUNCTION__, __LINE__, eventName));
        return;
    }

    UINT uiLoopCount;
    UINT TotalIfaces = WanMgr_IfaceData_GetTotalWanIface();
    BOOL bIsIfaceFound = FALSE;

    for( uiLoopCount = 0; uiLoopCount < TotalIfaces; uiLoopCount++ )
    {
        WanMgr_Iface_Data_t*   pWanDmlIfaceData = WanMgr_GetIfaceData_locked(uiLoopCount);
        if(pWanDmlIfaceData != NULL)
        {
            DML_WAN_IFACE* pWanIfaceData = &(pWanDmlIfaceData->data); 

            if( 0 == strncmp( eventName, pWanIfaceData->BaseInterface, strlen(pWanIfaceData->BaseInterface) ) )    
            {
                pWanIfaceData->BaseInterfaceStatus = ( 0 == strncmp(acStatus, "Up", strlen("Up")) ) ?  WAN_IFACE_PHY_STATUS_UP : WAN_IFACE_PHY_STATUS_DOWN;

                CcspTraceInfo(("%s %d: Prefix Value %s, phy status %d\n", __FUNCTION__, __LINE__, acStatus, pWanIfaceData->BaseInterfaceStatus));

                bIsIfaceFound = TRUE;
            }   

            WanMgrDml_GetIfaceData_release(pWanDmlIfaceData);

            if( bIsIfaceFound )
            {
                break;
            }
        }
    } 
}

ANSC_STATUS WanManager_ManageInterfaceStatusSubscription(char *pParam, bool bSubscribeFlag)
{
    char acSetParamName[256]  = {0};
    char acSetParamValue[256] = {0};
    rbusError_t rc = RBUS_ERROR_SUCCESS;

    if( NULL == pParam )
    {
        CcspTraceError(("%s %d - Invalid Parameter Value NULL\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    //Manage Subcription for Interface Status
    if( bSubscribeFlag )
    {
        rc = rbusEvent_Subscribe(rbusHandle, pParam, WanMgr_InterfaceStatus_EventHandler, NULL, 60);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Failed to Subscribe %s, Error=%s \n", __FUNCTION__, __LINE__, pParam, rbusError_ToString(rc)));
            return ANSC_STATUS_FAILURE;
        }
    }
    else
    {
        rc = rbusEvent_Unsubscribe(rbusHandle, pParam);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s %d - Failed to Unsubscribe %s, Error=%s \n", __FUNCTION__, __LINE__, pParam, rbusError_ToString(rc)));
            return ANSC_STATUS_FAILURE;
        }
    }

    CcspTraceInfo(("%s %d DM %s %s Successful\n", __FUNCTION__,__LINE__, pParam, ((bSubscribeFlag) ? "Subscribe": "Unsubscribe" )));
    return ANSC_STATUS_SUCCESS;
}
