/* timestats.c
 * routines for time statistics
 * Copyrigth 2003 Lars Roland
 *
 * $Id: timestats.c,v 1.1 2003/04/16 07:24:04 guy Exp $
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

/*
 * function: get_timedelta
 * delta = b - a
 */

void get_timedelta(nstime_t *delta, nstime_t *b, nstime_t *a )
{
	delta->secs = b->secs - a->secs;
	delta->nsecs= b->nsecs - a->nsecs;
	if(delta->nsecs<0){
		delta->nsecs+=1000000000;
		delta->secs--;
	}
}

/*
 * function: addtime
 * sum += a
 */

void addtime(nstime_t *sum, nstime_t *a)
{
	sum->secs += a->secs;
	sum->nsecs += a->nsecs;
	if(sum->nsecs>1000000000){
		sum->nsecs-=1000000000;
		sum->secs++;
	}
}

/*
 * function: nstime_to_msec
 * converts nstime to gdouble, time base is milli seconds
 */

gdouble nstime_to_msec(nstime_t *time)
{
	return ((double)time->secs*1000 + (double)time->nsecs/1000000);
}

/* A Function to update a timestat_t struct with a new sample*/

void
time_stat_update(timestat_t *stats, nstime_t *delta, packet_info *pinfo)
{
	if((stats->max.secs==0)
	&& (stats->max.nsecs==0) ){
		stats->max.secs=delta->secs;
		stats->max.nsecs=delta->nsecs;
		stats->max_num=pinfo->fd->num;
	}

	if((stats->min.secs==0)
	&& (stats->min.nsecs==0) ){
		stats->min.secs=delta->secs;
		stats->min.nsecs=delta->nsecs;
		stats->min_num=pinfo->fd->num;
	}

	if( (delta->secs<stats->min.secs)
	||( (delta->secs==stats->min.secs)
	  &&(delta->nsecs<stats->min.nsecs) ) ){
		stats->min.secs=delta->secs;
		stats->min.nsecs=delta->nsecs;
		stats->min_num=pinfo->fd->num;
	}

	if( (delta->secs>stats->max.secs)
	||( (delta->secs==stats->max.secs)
	  &&(delta->nsecs>stats->max.nsecs) ) ){
		stats->max.secs=delta->secs;
		stats->max.nsecs=delta->nsecs;
		stats->max_num=pinfo->fd->num;
	}

	stats->tot.secs += delta->secs;
	stats->tot.nsecs += delta->nsecs;
	if(stats->tot.nsecs>1000000000){
		stats->tot.nsecs-=1000000000;
		stats->tot.secs++;
	}

	stats->num++;
}

/*
 * get_average - function
 *
 * function to calculate the average
 * returns the average as a gdouble , time base is milli seconds
 */

gdouble get_average(nstime_t *sum, guint32 num)
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
