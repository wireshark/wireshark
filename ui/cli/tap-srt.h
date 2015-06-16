/* tap-srt.h
 * TShark service_response_time_table based on GTK version by Ronnie Sahlberg
 * Helper routines common to all service response time statistics
 * tap.
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

#ifndef __TAP_SRT_H__
#define __TAP_SRT_H__

#include "wsutil/nstime.h"
#include "epan/srt_table.h"

/** @file
 *  Helper routines common to all service response time statistics tap.
 */

/** Draw the srt table data.
 *
 * @param rst the srt table
 * @param draw_header draw the header
 * @param draw_footer draw the footer
 */
void draw_srt_table_data(srt_stat_table *rst, gboolean draw_footer);

#endif /* __TAP_SRT_H__ */
