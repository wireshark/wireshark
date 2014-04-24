/* time_util.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include "config.h"

#include "time_util.h"

/* converts a broken down date representation, relative to UTC,
 * to a timestamp; it uses timegm() if it's available.
 * Copied from Glib source gtimer.c
 */
time_t
mktime_utc(struct tm *tm)
{
#ifndef HAVE_TIMEGM
	time_t retval;

	static const int days_before[] =
		{
			0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
		};

	int yr;

	if (tm->tm_mon < 0 || tm->tm_mon > 11)
		return (time_t) -1;

	retval = (tm->tm_year - 70) * 365;

	/* count number of leap years */
	yr  = tm->tm_year + 1900;
	if (tm->tm_mon + 1 < 3 && (yr % 4) == 0 && ((yr % 100) != 0 || (yr % 400) == 0))
		yr--;
	retval += (((yr / 4) - (yr / 100) + (yr / 400)) - 477); /* 477 = ((1970 / 4) - (1970 / 100) + (1970 / 400)) */

	retval += days_before[tm->tm_mon] + tm->tm_mday - 1;

	retval = ((((retval * 24) + tm->tm_hour) * 60) + tm->tm_min) * 60 + tm->tm_sec;

	return retval;
#else
	return timegm(tm);
#endif /* !HAVE_TIMEGM */
}
