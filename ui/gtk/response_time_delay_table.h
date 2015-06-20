/* response_time_delay_table.h
 *
 * Based on service_response_time_table.h
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

#ifndef __RESPONSE_TIME_DELAY_TABLE_H__
#define __RESPONSE_TIME_DELAY_TABLE_H__

#include <gtk/gtk.h>
#include "wsutil/nstime.h"
#include "epan/rtd_table.h"


/** Suggested width of RTD window */
#define RTD_PREFERRED_WIDTH 650

/** Register function to register dissectors that support RTD for GTK.
 *
 * @param data register_rtd_t* representing dissetor RTD table
 * @param user_data is unused
 */
void register_response_time_delay_tables(gpointer data, gpointer user_data);

#endif /* __RESPONSE_TIME_DELAY_TABLE_H__ */
