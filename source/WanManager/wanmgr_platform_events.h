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


#ifndef _WANMGR_PLATFORM_EVENTS_H_
#define _WANMGR_PLATFORM_EVENTS_H_
/* ---- Global Types -------------------------- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "wanmgr_rdkbus_common.h"
#include "wanmgr_sysevents.h"

#define CONSOLE_LOG_FILE "/rdklogs/logs/Consolelog.txt.0"
#define LOG_CONSOLE(fmt ...)     {\
                                        FILE     *fp        = NULL;\
                                        int       console_fd = open ( CONSOLE_LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);\
                                        fp = (console_fd >= 0) ? fdopen(console_fd, "a") : NULL;\
                                        if (fp)\
                                        {\
                                            fprintf(fp,fmt);\
                                            fclose(fp);\
                                        }\
                                        else if (console_fd >= 0)\
                                        {\
                                            close(console_fd);\
                                        }\
                               }\


#endif /*_WANMGR_PLATFORM_EVENTS_H_*/
