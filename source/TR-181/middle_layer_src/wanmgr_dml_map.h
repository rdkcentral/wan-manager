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
********************************************************************************/
#ifndef _MAP_DML_H
#define _MAP_DML_H

#include "wanmgr_apis.h"
/***********************************************************************
 APIs for Object:
    MAP.
    *  WanMap_GetParamBoolValue
    *  WanMap_SetParamBoolValue
    *  WanMap_Validate
    *  WanMap_Commit
***********************************************************************/
BOOL WanMap_GetParamBoolValue(ANSC_HANDLE hInsContext,char* ParamName, BOOL* pBool);
BOOL WanMap_SetParamBoolValue(ANSC_HANDLE hInsContext,char* ParamName,BOOL* pBool);
ULONG WanMap_Validate(ANSC_HANDLE hInsContext,char* pReturnParamName,ULONG* puLength);
ULONG WanMap_Commit(ANSC_HANDLE hInsContext);
/************************************************************************
APIs for Object:
         MAP.Domain.{i}.
         WanMapDomain_GetEntryCount
         WanMapDomain_GetEntry
         WanMapDomain_GetParamUlongValue
         WanMapDomain_GetParamStringValue
         WanMapDomain_GetParamBoolValue
         WanMapDomain_GetParamIntValue
         WanMapDomain_SetParamUlongValue
         WanMapDomain_SetParamStringValue
         WanMapDomain_SetParamBoolValue
         WanMapDomain_SetParamIntValue
         WanMapDomain_Validate
         WanMapDomain_Commit
         WanMapDomain_Rollback
*************************************************************************/
ULONG WanMapDomain_GetEntryCount(ANSC_HANDLE hInsContext);
ANSC_HANDLE WanMapDomain_GetEntry(ANSC_HANDLE hInsContext,ULONG nIndex,ULONG* pInsNumber);
BOOL WanMapDomain_GetParamUlongValue(ANSC_HANDLE hInsContext,char* ParamName,ULONG* puLong);
BOOL WanMapDomain_GetParamStringValue(ANSC_HANDLE hInsContext,char* ParamName,char* pValue,ULONG* pUlSize);
BOOL WanMapDomain_GetParamBoolValue(ANSC_HANDLE hInsContext,char* ParamName,BOOL* pBool);
BOOL WanMapDomain_GetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int* pInt);
BOOL WanMapDomain_SetParamUlongValue(ANSC_HANDLE hInsContext,char* ParamName,ULONG uValue);
BOOL WanMapDomain_SetParamStringValue(ANSC_HANDLE hInsContext,char* ParamName,char* pString);
BOOL WanMapDomain_SetParamBoolValue(ANSC_HANDLE hInsContext,char* ParamName,BOOL* pBool);
BOOL WanMapDomain_SetParamIntValue(ANSC_HANDLE hInsContext, char* ParamName, int iValue);
ULONG WanMapDomain_Validate( ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);
ULONG WanMapDomain_Commit(ANSC_HANDLE hInsContext);
ULONG WanMapDomain_Rollback(ANSC_HANDLE hInsContext);
/****************************************************************************
APIs for Object:
         MAP.Domain.{i}.Rule.{i}.
         WanMapRule_GetEntryCount
         WanMapRule_GetEntry
         WanMapRule_GetParamUlongValue
         WanMapRule_GetParamStringValue
         WanMapRule_GetParamBoolValue
         WanMapRule_SetParamUlongValue
         WanMapRule_SetParamStringValue
         WanMapRule_SetParamBoolValue
         WanMapRule_Validate
         WanMapRule_Commit
         WanMapRule_Rollback
*************************************************************************/
ULONG WanMapRule_GetEntryCount(ANSC_HANDLE hInsContext);
ANSC_HANDLE WanMapRule_GetEntry(ANSC_HANDLE hInsContext,ULONG nIndex,ULONG* pInsNumber);
BOOL WanMapRule_GetParamUlongValue(ANSC_HANDLE hInsContext,char* ParamName,ULONG* puLong);
BOOL WanMapRule_GetParamStringValue(ANSC_HANDLE hInsContext,char* ParamName,char* pValue,ULONG* pUlSize);
BOOL WanMapRule_GetParamBoolValue(ANSC_HANDLE hInsContext,char* ParamName,BOOL* pBool);
BOOL WanMapRule_SetParamUlongValue(ANSC_HANDLE hInsContext,char* ParamName,ULONG uValue);
BOOL WanMapRule_SetParamStringValue(ANSC_HANDLE hInsContext,char* ParamName,char* pString);
BOOL WanMapRule_SetParamBoolValue(ANSC_HANDLE hInsContext,char* ParamName,BOOL* pBool);
ULONG WanMapRule_Validate( ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);
ULONG WanMapRule_Commit(ANSC_HANDLE hInsContext);
ULONG WanMapRule_Rollback(ANSC_HANDLE hInsContext);
/****************************************************************************
APIs for Object:
         MAP.Domain.{i}.Interface.
         WanMapInterface_GetParamUlongValue
         WanMapInterface_GetParamStringValue
         WanMapInterface_GetParamBoolValue
         WanMapInterface_SetParamUlongValue
         WanMapInterface_SetParamStringValue
         WanMapInterface_SetParamBoolValue
         WanMapInterface_Validate
         WanMapInterface_Commit
         WanMapInterface_Rollback
*************************************************************************/
BOOL WanMapInterface_GetParamUlongValue(ANSC_HANDLE hInsContext,char* ParamName,ULONG* puLong);
BOOL WanMapInterface_GetParamStringValue(ANSC_HANDLE hInsContext,char* ParamName,char* pValue,ULONG* pUlSize);
BOOL WanMapInterface_GetParamBoolValue(ANSC_HANDLE hInsContext,char* ParamName,BOOL* pBool);
BOOL WanMapInterface_SetParamUlongValue(ANSC_HANDLE hInsContext,char* ParamName,ULONG uValue);
BOOL WanMapInterface_SetParamStringValue(ANSC_HANDLE hInsContext,char* ParamName,char* pString);
BOOL WanMapInterface_SetParamBoolValue(ANSC_HANDLE hInsContext,char* ParamName,BOOL* pBool);
ULONG WanMapInterface_Validate( ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength);
ULONG WanMapInterface_Commit(ANSC_HANDLE hInsContext);
ULONG WanMapInterface_Rollback(ANSC_HANDLE hInsContext);

/****************************************************************************
APIs for Object:
         MAP.Domain.{i}.Interface.Stats.
         WanMapStats_GetParamUlongValue
*************************************************************************/
BOOL WanMapStats_GetParamUlongValue(ANSC_HANDLE hInsContext,char* ParamName,ULONG* puLong);

#endif
