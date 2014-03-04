/* timestats.h
 * Routines and definitions for time statistics
 * Copyrigth 2003 Lars Roland
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

#ifndef _time_stat
#define _time_stat

#include <glib.h>
#include "epan/packet_info.h"
#include "wsutil/nstime.h"

 /* Summary of time statistics*/
typedef struct _timestat_t {
	guint32 num;	 /* number of samples */
	guint32	min_num; /* frame number of minimum */
	guint32	max_num; /* frame number of maximum */
	nstime_t min;
	nstime_t max;
	nstime_t tot;
	gdouble variance;
} timestat_t;

/* functions */

/* Initialize a timestat_t struct */
WS_DLL_PUBLIC void time_stat_init(timestat_t *stats);

/* Update a timestat_t struct with a new sample */
WS_DLL_PUBLIC void time_stat_update(timestat_t *stats, const nstime_t *delta, packet_info *pinfo);

WS_DLL_PUBLIC gdouble get_average(const nstime_t *sum, guint32 num);

#endif
