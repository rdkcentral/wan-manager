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

#ifndef  _WANMGR_RDKBUS_COMMON_H_
#define  _WANMGR_RDKBUS_COMMON_H_

#include "ansc_platform.h"
#include "ansc_string_util.h"

typedef  ANSC_HANDLE (*PFN_DM_CREATE)(VOID);
typedef  ANSC_STATUS (*PFN_DM_REMOVE)(ANSC_HANDLE hThisObject);
typedef  ANSC_STATUS (*PFN_DM_INITIALIZE) (ANSC_HANDLE hThisObject);

/*
 * the main struct in cosa_xxx_apis.h need includes this struct and realize all functions.
 */
#define  BASE_CONTENT                                                                  \
    /* start of object class content */                                                     \
    ULONG                           Oid;                                                    \
    ANSC_HANDLE                     hSbContext;                                             \
                                                                                            \
    PFN_DM_CREATE               Create;                                                 \
    PFN_DM_REMOVE               Remove;                                                 \
    PFN_DM_INITIALIZE           Initialize;                                             \

typedef  struct _BASE_OBJECT
{
    BASE_CONTENT
} BASE_OBJECT,  *PBASE_OBJECT;

/*
*  This struct is for creating entry context link in writable table when call GetEntry()
*/
#define  CONTEXT_LINK_CLASS_CONTENT                                                    \
         SINGLE_LINK_ENTRY                Linkage;                                          \
         ANSC_HANDLE                      hContext;                                         \
         ANSC_HANDLE                      hParentTable;  /* Back pointer */                 \
         ULONG                            InstanceNumber;                                   \
         BOOL                             bNew;                                             \
         ANSC_HANDLE                      hPoamIrepUpperFo;                                 \
         ANSC_HANDLE                      hPoamIrepFo;                                      \

typedef  struct _CONTEXT_LINK_OBJECT
{
    CONTEXT_LINK_CLASS_CONTENT
} CONTEXT_LINK_OBJECT,  *PCONTEXT_LINK_OBJECT;

#define  ACCESS_CONTEXT_LINK_OBJECT(p)              \
         ACCESS_CONTAINER(p, CONTEXT_LINK_OBJECT, Linkage)

#define CONTEXT_LINK_INITIATION_CONTENT(cxt)                                      \
    (cxt)->hContext            = (ANSC_HANDLE)NULL;                                    \
    (cxt)->hParentTable        = (ANSC_HANDLE)NULL;                                    \
    (cxt)->InstanceNumber      = 0;                                                    \
    (cxt)->bNew                = FALSE;                                                \
    (cxt)->hPoamIrepUpperFo    = (ANSC_HANDLE)NULL;                                    \
    (cxt)->hPoamIrepFo         = (ANSC_HANDLE)NULL;                                    \

#define  DML_ALIAS_NAME_LENGTH                 64
#define  DML_DHCP_CLIENT_IFNAME                "erouter0"


ANSC_STATUS SListPushEntryByInsNum (PSLIST_HEADER pListHead, PCONTEXT_LINK_OBJECT pLinkContext);
PCONTEXT_LINK_OBJECT SListGetEntryByInsNum (PSLIST_HEADER pListHead, ULONG InstanceNumber);

#endif //_WANMGR_RDKBUS_COMMON_H_
