/**********************************************************************
 * Copyright 2025 RDK Management
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
**********************************************************************/

#ifndef  _WANMGR_DML_DSLITE_APIS_H
#define  _WANMGR_DML_DSLITE_APIS_H

#include "ansc_platform.h"


/***********************************************************************

 APIs for Object:

    DSLite.

    *  DSLite_GetParamBoolValue
    *  DSLite_SetParamBoolValue

    *  InterfaceSetting4_GetEntryCount
    *  InterfaceSetting4_GetEntry
    *  InterfaceSetting4_AddEntry
    *  InterfaceSetting4_DelEntry

    *  InterfaceSetting4_GetParamBoolValue
    *  InterfaceSetting4_GetParamStringValue
    *  InterfaceSetting4_GetParamUlongValue

    *  InterfaceSetting4_SetParamBoolValue
    *  InterfaceSetting4_SetParamStringValue
    *  InterfaceSetting4_SetParamUlongValue

    *  InterfaceSetting4_Validate
    *  InterfaceSetting4_Commit
    *  InterfaceSetting4_Rollback

***********************************************************************/

BOOL DSLite_GetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL *pBool);
BOOL DSLite_SetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL bValue);
BOOL DSLite_GetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG *pUlong);

ULONG InterfaceSetting4_GetEntryCount(ANSC_HANDLE hInsContext);
ANSC_HANDLE InterfaceSetting4_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG *pInsNumber);
ANSC_HANDLE InterfaceSetting4_AddEntry(ANSC_HANDLE hInsContext, ULONG *pInsNumber);
ULONG InterfaceSetting4_DelEntry(ANSC_HANDLE hInsContext, ANSC_HANDLE hInstance);

BOOL InterfaceSetting4_GetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL *pBool);
ULONG InterfaceSetting4_GetParamStringValue(ANSC_HANDLE hInsContext, char *ParamName, char *pValue, ULONG *pUlSize);
BOOL InterfaceSetting4_GetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG *pUlong);

BOOL InterfaceSetting4_SetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL bValue);
BOOL InterfaceSetting4_SetParamStringValue(ANSC_HANDLE hInsContext, char *ParamName, char *strValue);
BOOL InterfaceSetting4_SetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG uValue);

BOOL InterfaceSetting4_Validate(ANSC_HANDLE hInsContext, char *pReturnParamName, ULONG *puLength);
ULONG InterfaceSetting4_Commit(ANSC_HANDLE hInsContext);
ULONG InterfaceSetting4_Rollback(ANSC_HANDLE hInsContext);

#endif
