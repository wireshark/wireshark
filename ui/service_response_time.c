/* service_response_time.c
 * Copied from ui/gtk/service_response_time_table.h, 2003 Ronnie Sahlberg
 * Helper routines and structs common to all service response time statistics
 * taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "service_response_time.h"

extern const char*
service_response_time_get_column_name (int idx)
{
    static const char *default_titles[] = { "Index", "Procedure", "Calls", "Min SRT (s)", "Max SRT (s)", "Avg SRT (s)", "Sum SRT (s)" };

    if (idx < 0 || idx >= NUM_SRT_COLUMNS) return "(Unknown)";
    return default_titles[idx];
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
