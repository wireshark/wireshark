/* timestats.c
 * routines for time statistics
 * Copyrigth 2003 Lars Roland
 *
 * $Id$
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

#include "timestats.h"

/* Initialize a timestat_t struct */
void
time_stat_init(timestat_t *stats)
{
	stats->num = 0;
	stats->min.secs = 0;
	stats->min.nsecs = 0;
	stats->max.secs = 0;
	stats->max.nsecs = 0;
	stats->tot.secs = 0;
	stats->tot.nsecs = 0;
}

/* Update a timestat_t struct with a new sample */
void
time_stat_update(timestat_t *stats, const nstime_t *delta, packet_info *pinfo)
{
	if(stats->num==0){
		stats->max=*delta;
		stats->max_num=pinfo->fd->num;
		stats->min=*delta;
		stats->min_num=pinfo->fd->num;
	}

	if( (delta->secs<stats->min.secs)
	||( (delta->secs==stats->min.secs)
	  &&(delta->nsecs<stats->min.nsecs) ) ){
		stats->min=*delta;
		stats->min_num=pinfo->fd->num;
	}

	if( (delta->secs>stats->max.secs)
	||( (delta->secs==stats->max.secs)
	  &&(delta->nsecs>stats->max.nsecs) ) ){
		stats->max=*delta;
		stats->max_num=pinfo->fd->num;
	}

	nstime_add(&stats->tot, delta);

	stats->num++;
}

/*
 * get_average - function
 *
 * function to calculate the average
 * returns the average as a gdouble , time base is milli seconds
 */

gdouble get_average(const nstime_t *sum, guint32 num)
{
	gdouble average;

	if(num > 0) {
		average = (double)sum->secs*1000 + (double)sum->nsecs/1000000;
		average /= num;
	}
	else {
		average = 0;
	}
	return average;
}
