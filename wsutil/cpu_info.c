/* cpu_info.c
 * Routines to report CPU information
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <glib.h>

#include <wsutil/ws_cpuid.h>
#include <wsutil/cpu_info.h>

/*
 * Get the CPU info, and append it to the GString
 */
void
get_cpu_info(GString *str)
{
    guint32 CPUInfo[4];
    char CPUBrandString[0x40];
    unsigned nExIds;

    /* https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex */

    /* Calling __cpuid with 0x80000000 as the InfoType argument */
    /* gets the number of valid extended IDs. */
    if (!ws_cpuid(CPUInfo, 0x80000000))
        return;

    nExIds = CPUInfo[0];

    if (nExIds<0x80000005)
        return;

    memset(CPUBrandString, 0, sizeof(CPUBrandString));

    /* Interpret CPU brand string */
    ws_cpuid(CPUInfo, 0x80000002);
    memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
    ws_cpuid(CPUInfo, 0x80000003);
    memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
    ws_cpuid(CPUInfo, 0x80000004);
    memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));

    if (str->len > 0)
        g_string_append(str, ", with ");

    g_string_append_printf(str, "%s", g_strstrip(CPUBrandString));

    if (ws_cpuid_sse42())
        g_string_append(str, " (with SSE4.2)");
}

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
