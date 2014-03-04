/* timestamp.c
 * Routines for timestamp type setting.
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

#include "config.h"

#include "timestamp.h"

/* Init with an invalid value, so that "recent" in ui/gtk/menu.c can detect this
 * and distinguish it from a command line value */
static ts_type timestamp_type = TS_NOT_SET;

static int timestamp_precision = TS_PREC_AUTO_USEC;

static ts_seconds_type timestamp_seconds_type = TS_SECONDS_NOT_SET;

ts_type timestamp_get_type(void)
{
	return timestamp_type;
}

void timestamp_set_type(ts_type ts_t)
{
	timestamp_type = ts_t;
}


int timestamp_get_precision(void)
{
	return timestamp_precision;
}

void timestamp_set_precision(int tsp)
{
	timestamp_precision = tsp;
}


ts_seconds_type timestamp_get_seconds_type(void)
{
	return timestamp_seconds_type;
}

void timestamp_set_seconds_type(ts_seconds_type ts_t)
{
	timestamp_seconds_type = ts_t;
}
