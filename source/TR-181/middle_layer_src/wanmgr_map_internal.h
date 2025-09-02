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
#ifndef  _WANMGR_MAP_INTERNAL_H
#define  _WANMGR_MAP_INTERNAL_H

#include "wanmgr_apis.h"

#define  MAP_DOMAIN_IREP_FOLDER_NAME                  "MAPDomain"
#define  COSA_DML_RR_NAME_DOMAIN_NextInsNum           "NextInstanceNumber"
#define  COSA_DML_RR_NAME_RULE_NextInsNum             "NextRuleInstanceNum"

/*
*  This struct is for dhcp.
*/
#define  DATAMODEL_MAP_CLASS_CONTENT                           \
    /* duplication of the base object class content */         \
    BASE_CONTENT                                               \
    /* start of MAP object class content */                    \
    BOOL                            bEnable;                   \
    SLIST_HEADER                    DomainList;                \
    ULONG                           ulDomainCount;             \
    ULONG                           ulNextDomainInsNum;        \
    ANSC_HANDLE                     hIrepFolderCOSA;           \
    ANSC_HANDLE                     hIrepFolderMapDomain;      \


typedef  struct
_DATAMODEL_MAP
{
    DATAMODEL_MAP_CLASS_CONTENT
}
DATAMODEL_MAP,  *PDATAMODEL_MAP;

/*
    Function declaration 
*/ 
ANSC_HANDLE
WanMgr_MapCreate
    (
        VOID
    );

ANSC_STATUS
WanMgr_MapInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
WanMgr_MapRemove
    (
        ANSC_HANDLE                 hThisObject
    );

#endif /* _WANMGR_MAP_INTERNAL_H */
