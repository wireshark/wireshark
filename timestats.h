/* timestats.h
 * Routines and definitions for time statistics
 * Copyrigth 2003 Lars Roland
 *
 * $Id: timestats.h,v 1.1 2003/04/16 07:24:04 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _time_stat
#define _time_stat

#include <glib.h>
#include "epan/packet_info.h"
#include "epan/nstime.h"

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
extern void get_timedelta(nstime_t *delta, nstime_t *b, nstime_t *a ); /* delta = b - a */
extern void addtime(nstime_t *sum, nstime_t *a); 			/* sum += a */

extern gdouble nstime_to_msec(nstime_t *time); /* converts nstime to gdouble, time base is milli seconds*/

extern void time_stat_update(timestat_t *stats, nstime_t *delta, packet_info *pinfo);
extern gdouble get_average(nstime_t *sum, guint32 num);

#endif
