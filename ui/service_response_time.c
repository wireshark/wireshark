/* service_response_time.c
 * Copied from ui/gtk/service_response_time_table.h, 2003 Ronnie Sahlberg
 * Helper routines and structs common to all service response time statistics
 * taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
