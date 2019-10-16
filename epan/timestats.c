/* timestats.c
 * routines for time statistics
 * Copyright 2003 Lars Roland
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "timestats.h"

/* Initialize a timestat_t struct */
void
time_stat_init(timestat_t *stats)
{
	stats->num = 0;
	stats->min_num = 0;
	stats->max_num = 0;
	nstime_set_zero(&stats->min);
	nstime_set_zero(&stats->max);
	nstime_set_zero(&stats->tot);
	stats->variance = 0.0;
}

/* Update a timestat_t struct with a new sample */
void
time_stat_update(timestat_t *stats, const nstime_t *delta, packet_info *pinfo)
{
	if(stats->num==0){
		stats->max=*delta;
		stats->max_num=pinfo->num;
		stats->min=*delta;
		stats->min_num=pinfo->num;
	}

	if( (delta->secs<stats->min.secs)
	||( (delta->secs==stats->min.secs)
	  &&(delta->nsecs<stats->min.nsecs) ) ){
		stats->min=*delta;
		stats->min_num=pinfo->num;
	}

	if( (delta->secs>stats->max.secs)
	||( (delta->secs==stats->max.secs)
	  &&(delta->nsecs>stats->max.nsecs) ) ){
		stats->max=*delta;
		stats->max_num=pinfo->num;
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

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
