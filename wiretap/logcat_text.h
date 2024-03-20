/** @file
 *
 * Copyright 2014, Michal Orynicz for Tieto Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __LOGCAT_TEXT_H__
#define __LOGCAT_TEXT_H__

#include <glib.h>

#include "wtap.h"

#define SPECIAL_STRING "[-]+ (beginning of \\/?.+)"
#define BRIEF_STRING "([IVDWEF])/(.*?)\\( *(\\d+)\\): (.*)"
#define TAG_STRING "([IVDWEF])/(.*?): (.*)"
#define TIME_STRING "(\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}) ([IVDWEF])/(.*?)\\( *(\\d+)\\): (.*)"
#define THREAD_STRING "([IVDWEF])\\( *(\\d+): *(\\d+)\\) (.*)"
#define PROCESS_STRING "([IVDWEF])\\( *(\\d+)\\) (.*)"
#define THREADTIME_STRING "(\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}) +(\\d+) +(\\d+) ([IVDWEF]) (.*?): (.*)"
#define LONG_STRING "\\[ (\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}) +(\\d+): *(\\d+) ([IVDWEF])/(.+) ]\\R(.*)"

wtap_open_return_val logcat_text_open(wtap *wth, int *err, char **err_info);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
