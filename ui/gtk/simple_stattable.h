/* simple_stattable.h
 *
 * Based on response_time_delay_table.h
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

#ifndef __SIMPLE_STAT_TABLE_H__
#define __SIMPLE_STAT_TABLE_H__

#include <gtk/gtk.h>
#include "epan/stat_tap_ui.h"

/** Register function to register dissectors that support a "simple" statistics table.
 *
 * @param data stat_tap_table_ui* representing dissetor stat table
 * @param user_data is unused
 */
void register_simple_stat_tables(gpointer data, gpointer user_data);

#endif /* __SIMPLE_STAT_TABLE_H__ */
