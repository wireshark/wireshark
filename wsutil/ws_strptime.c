/*-
 * Copyright (c) 1997, 1998, 2005, 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code was contributed to The NetBSD Foundation by Klaus Klein.
 * Heavily optimised by David Laight
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#define _GNU_SOURCE
#include "config.h"
#include "ws_strptime.h"
#include <time.h>
#include <wsutil/time_util.h> /* For ws_localtime_r() */
#include <wsutil/strtoi.h>

#ifdef _WIN32
#define tzset		_tzset
#define tzname		_tzname
#define timezone	_timezone
#define daylight	_daylight
#endif

static const unsigned char *conv_num(const unsigned char *, int *, unsigned, unsigned);
static const unsigned char *find_string(const unsigned char *, int *, const char * const *,
	const char * const *, int);

#define SECSPERMIN	60
#define MINSPERHOUR	60
#define HOURSPERDAY	24
#define DAYSPERWEEK	7
#define DAYSPERNYEAR	365
#define DAYSPERLYEAR	366
#define SECSPERHOUR	(SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY	((int_fast32_t) SECSPERHOUR * HOURSPERDAY)
#define MONSPERYEAR	12

#define TM_SUNDAY	0
#define TM_MONDAY	1
#define TM_TUESDAY	2
#define TM_WEDNESDAY	3
#define TM_THURSDAY	4
#define TM_FRIDAY	5
#define TM_SATURDAY	6

#define TM_JANUARY	0
#define TM_FEBRUARY	1
#define TM_MARCH	2
#define TM_APRIL	3
#define TM_MAY		4
#define TM_JUNE		5
#define TM_JULY		6
#define TM_AUGUST	7
#define TM_SEPTEMBER	8
#define TM_OCTOBER	9
#define TM_NOVEMBER	10
#define TM_DECEMBER	11

#define TM_YEAR_BASE	1900

#define EPOCH_YEAR	1970
#define EPOCH_WDAY	TM_THURSDAY

#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

/*
** Since everything in isleap is modulo 400 (or a factor of 400), we know that
**	isleap(y) == isleap(y % 400)
** and so
**	isleap(a + b) == isleap((a + b) % 400)
** or
**	isleap(a + b) == isleap(a % 400 + b % 400)
** This is true even if % means modulo rather than Fortran remainder
** (which is allowed by C89 but not C99).
** We use this to avoid addition overflow problems.
*/

#define isleap_sum(a, b)	isleap((a) % 400 + (b) % 400)

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define ALT_E			0x01
#define ALT_O			0x02
#define LEGAL_ALT(x)		{ if (alt_format & ~(x)) return NULL; }

#define S_YEAR			(1 << 0)
#define S_MON			(1 << 1)
#define S_YDAY			(1 << 2)
#define S_MDAY			(1 << 3)
#define S_WDAY			(1 << 4)
#define S_HOUR			(1 << 5)

#define HAVE_MDAY(s)		(s & S_MDAY)
#define HAVE_MON(s)		(s & S_MON)
#define HAVE_WDAY(s)		(s & S_WDAY)
#define HAVE_YDAY(s)		(s & S_YDAY)
#define HAVE_YEAR(s)		(s & S_YEAR)
#define HAVE_HOUR(s)		(s & S_HOUR)

static const char utc[] = { "UTC" };
/* RFC-822/RFC-2822 */
static const char * const nast[5] = {
       "EST",    "CST",    "MST",    "PST",    "\0\0\0"
};
static const char * const nadt[5] = {
       "EDT",    "CDT",    "MDT",    "PDT",    "\0\0\0"
};

static const char * const cloc_am_pm[] = {"AM", "PM", NULL};

static const char * const cloc_abday[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", NULL
};

static const char * const cloc_day[] = {
	"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
	"Saturday", NULL
};

static const char * const cloc_abmon[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
	"Oct", "Nov", "Dec", NULL
};

static const char * const cloc_mon[] = {
	"January", "February", "March", "April", "May", "June", "July",
	"August", "September", "October", "November", "December", NULL
};

/*
 * Table to determine the ordinal date for the start of a month.
 * Ref: http://en.wikipedia.org/wiki/ISO_week_date
 */
static const int start_of_month[2][13] = {
	/* non-leap year */
	{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
	/* leap year */
	{ 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
};

/*
 * Calculate the week day of the first day of a year. Valid for
 * the Gregorian calendar, which began Sept 14, 1752 in the UK
 * and its colonies. Ref:
 * http://en.wikipedia.org/wiki/Determination_of_the_day_of_the_week
 */

static int
first_wday_of(int yr)
{
	return ((2 * (3 - (yr / 100) % 4)) + (yr % 100) + ((yr % 100) /  4) +
	    (isleap(yr) ? 6 : 0) + 1) % 7;
}

#define delim(p)	((p) == '\0' || g_ascii_isspace((unsigned char)(p)))

#define SET_ZONEP(p, off, zone) \
	do { if (p) { p->tm_gmtoff = off; p->tm_zone = zone; } } while (0)

/*
 * This is spectacularly ugly.
 *
 * POSIX require that there be a variable named "timezone", which contains
 * "the difference, in seconds, between Coordinated Universal Time (UTC)
 * and local standard time.".
 *
 * Most of the platforms on which we run have this.
 *
 * FreeBSD, however, does not.  Instead, it provides a function named
 * "timezone", which takes two integer arguments, "zone" and "dst",
 * and "returns a pointer to a time zone abbreviation for the specified
 * zone and dst values.  The zone argument is the number of minutes west
 * of GMT and dst is non-zero if daylight savings time is in effect."
 *
 * So we need a way to get "the difference, in seconds, between Coordinated
 * Universal Time (UTC) and local standard time."
 *
 * The FreeBSD Wireshark port, as of 2023-12-05, does so by handing
 * a time_t value of 0, meaning 1970-01-01 00:00:00 UTC (the Unix Epoch),
 * to localtime() and using the tm_gmtoff value from the resulting
 * struct tm.  That works in countries that were in standard time
 * then, but doesn't work in countries that were not in standard time
 * then, meaning it doesn't work correctly in countries in the Southern
 * Hemisphere that were in Daylight Saving Tie at that point, and may or
 * may not work correctly in Ireland, depending on how "standard time"
 * is defined (don't ask).
 *
 * For now, we use a similar mechanism to the one above, but we check
 * whether tm_isdst is greater than 0 in the resulting struct tm and,
 * if it is, use a time_t value of 86400*(365/2), in the hopes that,
 * halfway through 1970, the location in question was in standard
 * time.
 *
 * Also, for now, we test for FreeBSD rather than doing a configure-
 * time check; checking whether the symbol "timezone" is defined
 * won't work, as it's defined in FreeBSD as a function, so we'd
 * have to check *how* it's defined.
 *
 * So we have a function to return the difference in question. It
 * returns a long because timezone is defined to be a long in POSIX
 * and because the tm_gmtoff member of a struct tm, if such a member
 * is present, is also a long.
 */
static long
utc_offset(void)
{
#if defined(__FreeBSD__)
	/*
	 * We only calculate the standard time UTC offset once, under the
	 * assumption that we won't change what time zone we're in.
	 *
	 * XXX - that assumption is violated if:
	 *
	 *   you're running on an OS where you can set the current
	 *   time zone and that will affect all running programs,
	 *   or where the OS tries to determine where you're located
	 *   and changes the time zone to match (for example, macOS,
	 *   in which both of those are the case);
	 *
	 *   you're in a location that has moved between time zones
	 *   since 1970-01-01 00:00:00 UTC (there are some, and the
	 *   IANA time zone database, at least, takes that into
	 *   account);
	 *
	 *   we add support for the if_iana_tzname Interface
	 *   Description Block option, so that, when looking
	 *   at a file with that option for one or more
	 *   interfaces, and using the timezone from that
	 *   option rather than the local timezone, the
	 *   offset from UTC may change from file to file.
	 *
	 * This *probably* won't make much of a difference, as
	 * we have to do this sort of hackery only when parsing
	 * a date that doesn't use the "Obsolete Date and Time",
	 * as it's called in RFC 2822.
	 */
	static bool got_utcoffset = false;
	static struct tm *gtm;
	time_t then = 0;

	if (got_utcoffset) {
		if (gtm != NULL)
			return gtm->tm_gmtoff;
		else
			return 0;	/* localtime() failed on us */
	}

	gtm = localtime(&then);
	got_utcoffset = true;
	if (gtm == NULL) {
		/*
		 * Oh, heck, it can't convert the Epoch.  Just
		 * return 0 and say to hell with it.
		 */
		return 0;
	}
	if (gtm->tm_isdst > 0) {
		/*
		 * Sorry, we were in Daylight Saving Time on
		 * 1970-01-01 at 00:00:00 UTC.  Try the middle
		 * of the year.  (We don't bother making sure
		 * we weren't in DST then.)
		 */
		then = 86400*(365/2);
		gtm = localtime(&then);
		if (gtm == NULL) {
			/* See above. */
			return 0;
		}
	}
	return gtm->tm_gmtoff;
#else
	return timezone;
#endif
}

char *
ws_strptime_p(const char *buf, const char *format, struct tm *tm)
{
#ifdef HAVE_STRPTIME
    return strptime(buf, format, tm);
#else
    return ws_strptime(buf, format, tm, NULL);
#endif
}

char *
ws_strptime(const char *buf, const char *fmt, struct tm *tm, struct ws_timezone *zonep)
{
	unsigned char c;
	const unsigned char *bp, *ep, *zname;
	int alt_format, i, split_year = 0, neg = 0, state = 0,
	    day_offset = -1, week_offset = 0, offs, mandatory;
	const char *new_fmt;
	long tm_gmtoff;
	const char *tm_zone;

	bp = (const unsigned char *)buf;

	while (bp != NULL && (c = *fmt++) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;
		i = 0;

		/* Eat up white-space. */
		if (g_ascii_isspace(c)) {
			while (g_ascii_isspace(*bp))
				bp++;
			continue;
		}

		if (c != '%')
			goto literal;


again:		switch (c = *fmt++) {
		case '%':	/* "%%" is converted to "%". */
literal:
			if (c != *bp++)
				return NULL;
			LEGAL_ALT(0);
			continue;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		case 'E':	/* "%E?" alternative conversion modifier. */
			LEGAL_ALT(0);
			alt_format |= ALT_E;
			goto again;

		case 'O':	/* "%O?" alternative conversion modifier. */
			LEGAL_ALT(0);
			alt_format |= ALT_O;
			goto again;

		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
		case 'c':	/* Date and time, using the locale's format. */
			new_fmt = "%a %b %e %H:%M:%S %Y";
			state |= S_WDAY | S_MON | S_MDAY | S_YEAR;
			goto recurse;

		case 'D':	/* The date as "%m/%d/%y". */
			new_fmt = "%m/%d/%y";
			LEGAL_ALT(0);
			state |= S_MON | S_MDAY | S_YEAR;
			goto recurse;

		case 'F':	/* The date as "%Y-%m-%d". */
			new_fmt = "%Y-%m-%d";
			LEGAL_ALT(0);
			state |= S_MON | S_MDAY | S_YEAR;
			goto recurse;

		case 'R':	/* The time as "%H:%M". */
			new_fmt = "%H:%M";
			LEGAL_ALT(0);
			goto recurse;

		case 'r':	/* The time in 12-hour clock representation. */
			new_fmt = "%I:%M:%S %p";
			LEGAL_ALT(0);
			goto recurse;

		case 'T':	/* The time as "%H:%M:%S". */
			new_fmt = "%H:%M:%S";
			LEGAL_ALT(0);
			goto recurse;

		case 'X':	/* The time, using the locale's format. */
			new_fmt = "%H:%M:%S";
			goto recurse;

		case 'x':	/* The date, using the locale's format. */
			new_fmt = "%m/%d/%y";
			state |= S_MON | S_MDAY | S_YEAR;
		    recurse:
			bp = (const unsigned char *)ws_strptime((const char *)bp,
							    new_fmt, tm, zonep);
			LEGAL_ALT(ALT_E);
			continue;

		/*
		 * "Elementary" conversion rules.
		 */
		case 'A':	/* The day of week, using the locale's form. */
		case 'a':
			bp = find_string(bp, &tm->tm_wday, cloc_day, cloc_abday, 7);
			LEGAL_ALT(0);
			state |= S_WDAY;
			continue;

		case 'B':	/* The month, using the locale's form. */
		case 'b':
		case 'h':
			bp = find_string(bp, &tm->tm_mon, cloc_mon, cloc_abmon, 12);
			LEGAL_ALT(0);
			state |= S_MON;
			continue;

		case 'C':	/* The century number. */
			i = 20;
			bp = conv_num(bp, &i, 0, 99);

			i = i * 100 - TM_YEAR_BASE;
			if (split_year)
				i += tm->tm_year % 100;
			split_year = 1;
			tm->tm_year = i;
			LEGAL_ALT(ALT_E);
			state |= S_YEAR;
			continue;

		case 'd':	/* The day of month. */
		case 'e':
			bp = conv_num(bp, &tm->tm_mday, 1, 31);
			LEGAL_ALT(ALT_O);
			state |= S_MDAY;
			continue;

		case 'k':	/* The hour (24-hour clock representation). */
			LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'H':
			bp = conv_num(bp, &tm->tm_hour, 0, 23);
			LEGAL_ALT(ALT_O);
			state |= S_HOUR;
			continue;

		case 'l':	/* The hour (12-hour clock representation). */
			LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'I':
			bp = conv_num(bp, &tm->tm_hour, 1, 12);
			if (tm->tm_hour == 12)
				tm->tm_hour = 0;
			LEGAL_ALT(ALT_O);
			state |= S_HOUR;
			continue;

		case 'j':	/* The day of year. */
			i = 1;
			bp = conv_num(bp, &i, 1, 366);
			tm->tm_yday = i - 1;
			LEGAL_ALT(0);
			state |= S_YDAY;
			continue;

		case 'M':	/* The minute. */
			bp = conv_num(bp, &tm->tm_min, 0, 59);
			LEGAL_ALT(ALT_O);
			continue;

		case 'm':	/* The month. */
			i = 1;
			bp = conv_num(bp, &i, 1, 12);
			tm->tm_mon = i - 1;
			LEGAL_ALT(ALT_O);
			state |= S_MON;
			continue;

		case 'p':	/* The locale's equivalent of AM/PM. */
			bp = find_string(bp, &i, cloc_am_pm,
			    NULL, 2);
			if (HAVE_HOUR(state) && tm->tm_hour > 11)
				return NULL;
			tm->tm_hour += i * 12;
			LEGAL_ALT(0);
			continue;

		case 'S':	/* The seconds. */
			bp = conv_num(bp, &tm->tm_sec, 0, 61);
			LEGAL_ALT(ALT_O);
			continue;

		case 's':	/* seconds since the epoch */
			{
				int64_t secs;
				const char *endptr;
				time_t sse;

				/* Extract the seconds as a 64-bit signed number. */
				if (!ws_strtoi64(bp, &endptr, &secs)) {
					bp = NULL;
					continue;
				}
				bp = endptr;

				/* For now, reject times before the Epoch. */
				if (secs < 0) {
					bp = NULL;
					continue;
				}

				/* Make sure it fits. */
				sse = (time_t)secs;
				if (sse != secs) {
					bp = NULL;
					continue;
				}

				if (ws_localtime_r(&sse, tm) == NULL)
					bp = NULL;
				else
					state |= S_YDAY | S_WDAY |
					    S_MON | S_MDAY | S_YEAR;
			}
			continue;

		case 'U':	/* The week of year, beginning on sunday. */
		case 'W':	/* The week of year, beginning on monday. */
			/*
			 * This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so save the
			 * week for now in case it can be used later.
			 */
			bp = conv_num(bp, &i, 0, 53);
			LEGAL_ALT(ALT_O);
			if (c == 'U')
				day_offset = TM_SUNDAY;
			else
				day_offset = TM_MONDAY;
			week_offset = i;
			continue;

		case 'w':	/* The day of week, beginning on sunday. */
			bp = conv_num(bp, &tm->tm_wday, 0, 6);
			LEGAL_ALT(ALT_O);
			state |= S_WDAY;
			continue;

		case 'u':	/* The day of week, monday = 1. */
			bp = conv_num(bp, &i, 1, 7);
			tm->tm_wday = i % 7;
			LEGAL_ALT(ALT_O);
			state |= S_WDAY;
			continue;

		case 'g':	/* The year corresponding to the ISO week
				 * number but without the century.
				 */
			bp = conv_num(bp, &i, 0, 99);
			continue;

		case 'G':	/* The year corresponding to the ISO week
				 * number with century.
				 */
			do
				bp++;
			while (g_ascii_isdigit(*bp));
			continue;

		case 'V':	/* The ISO 8601:1988 week number as decimal */
			bp = conv_num(bp, &i, 1, 53);
			continue;

		case 'Y':	/* The year. */
			i = TM_YEAR_BASE;	/* just for data sanity... */
			bp = conv_num(bp, &i, 0, 9999);
			tm->tm_year = i - TM_YEAR_BASE;
			LEGAL_ALT(ALT_E);
			state |= S_YEAR;
			continue;

		case 'y':	/* The year within 100 years of the epoch. */
			/* LEGAL_ALT(ALT_E | ALT_O); */
			bp = conv_num(bp, &i, 0, 99);

			if (split_year)
				/* preserve century */
				i += (tm->tm_year / 100) * 100;
			else {
				split_year = 1;
				if (i <= 68)
					i = i + 2000 - TM_YEAR_BASE;
				else
					i = i + 1900 - TM_YEAR_BASE;
			}
			tm->tm_year = i;
			state |= S_YEAR;
			continue;

		case 'Z':
		case 'z':
			tzset();
			mandatory = c == 'z';
			/*
			 * We recognize all ISO 8601 formats:
			 * Z	= Zulu time/UTC
			 * [+-]hhmm
			 * [+-]hh:mm
			 * [+-]hh
			 * We recognize all RFC-822/RFC-2822 formats:
			 * UT|GMT
			 *          North American : UTC offsets
			 * E[DS]T = Eastern : -4 | -5
			 * C[DS]T = Central : -5 | -6
			 * M[DS]T = Mountain: -6 | -7
			 * P[DS]T = Pacific : -7 | -8
			 *          Nautical/Military
			 * [A-IL-M] = -1 ... -9 (J not used)
			 * [N-Y]  = +1 ... +12
			 * Note: J maybe used to denote non-nautical
			 *       local time
			 */
			if (mandatory)
				while (g_ascii_isspace(*bp))
					bp++;

			zname = bp;
			switch (*bp++) {
			case 'G':
				if (*bp++ != 'M')
					goto namedzone;
				/*FALLTHROUGH*/
			case 'U':
				if (*bp++ != 'T')
					goto namedzone;
				else if (!delim(*bp) && *bp++ != 'C')
					goto namedzone;
				/*FALLTHROUGH*/
			case 'Z':
				if (!delim(*bp))
					goto namedzone;
				tm->tm_isdst = 0;
				tm_gmtoff = 0;
				tm_zone = utc;
				SET_ZONEP(zonep, tm_gmtoff, tm_zone);
				continue;
			case '+':
				neg = 0;
				break;
			case '-':
				neg = 1;
				break;
			default:
namedzone:
				bp = zname;

				/* Nautical / Military style */
				if (delim(bp[1]) &&
				    ((*bp >= 'A' && *bp <= 'I') ||
				     (*bp >= 'L' && *bp <= 'Y'))) {
					/* Argh! No 'J'! */
					if (*bp >= 'A' && *bp <= 'I')
						tm_gmtoff =
						    (int)*bp - ('A' - 1);
					else if (*bp >= 'L' && *bp <= 'M')
						tm_gmtoff = (int)*bp - 'A';
					else if (*bp >= 'N' && *bp <= 'Y')
						tm_gmtoff = 'M' - (int)*bp;
					else {
						/* Not reached. */
						ws_critical("Not reached!");
						goto out;
					}
					tm_gmtoff *= SECSPERHOUR;
					tm_zone = NULL; /* XXX */
					SET_ZONEP(zonep, tm_gmtoff, tm_zone);
					bp++;
					continue;
				}
				/* 'J' is local time */
				if (delim(bp[1]) && *bp == 'J') {
					tm_gmtoff = -utc_offset();
					tm_zone = NULL; /* XXX */
					SET_ZONEP(zonep, tm_gmtoff, tm_zone);
					bp++;
					continue;
				}

				/*
				 * From our 3 letter hard-coded table
				 */
				ep = find_string(bp, &i, nast, NULL, 4);
				if (ep != NULL) {
					tm_gmtoff = (-5 - i) * SECSPERHOUR;
					tm_zone = nast[i];
					SET_ZONEP(zonep, tm_gmtoff, tm_zone);
					bp = ep;
					continue;
				}
				ep = find_string(bp, &i, nadt, NULL, 4);
				if (ep != NULL) {
					tm->tm_isdst = 1;
					tm_gmtoff = (-4 - i) * SECSPERHOUR;
					tm_zone = nadt[i];
					SET_ZONEP(zonep, tm_gmtoff, tm_zone);
					bp = ep;
					continue;
				}
				/*
				 * Our current timezone
				 */
				ep = find_string(bp, &i,
						 (const char * const *)tzname,
						 NULL, 2);
				if (ep != NULL) {
					tm->tm_isdst = i;
					tm_gmtoff = -utc_offset();
					tm_zone = tzname[i];
					SET_ZONEP(zonep, tm_gmtoff, tm_zone);
					bp = ep;
					continue;
				}
				goto out;
			}
			offs = 0;
			for (i = 0; i < 4; ) {
				if (g_ascii_isdigit(*bp)) {
					offs = offs * 10 + (*bp++ - '0');
					i++;
					continue;
				}
				if (i == 2 && *bp == ':') {
					bp++;
					continue;
				}
				break;
			}
			if (g_ascii_isdigit(*bp))
				goto out;
			switch (i) {
			case 2:
				offs *= SECSPERHOUR;
				break;
			case 4:
				i = offs % 100;
				offs /= 100;
				if (i >= SECSPERMIN)
					goto out;
				/* Convert minutes into decimal */
				offs = offs * SECSPERHOUR + i * SECSPERMIN;
				break;
			default:
			out:
				if (mandatory)
					return NULL;
				bp = zname;
				continue;
			}
			/* ISO 8601 & RFC 3339 limit to 23:59 max */
			if (offs >= (HOURSPERDAY * SECSPERHOUR))
				goto out;
			if (neg)
				offs = -offs;
			tm->tm_isdst = 0;	/* XXX */
			tm_gmtoff = offs;
			tm_zone = NULL;	/* XXX */
			SET_ZONEP(zonep, tm_gmtoff, tm_zone);
			continue;

		/*
		 * Miscellaneous conversions.
		 */
		case 'n':	/* Any kind of white-space. */
		case 't':
			while (g_ascii_isspace(*bp))
				bp++;
			LEGAL_ALT(0);
			continue;


		default:	/* Unknown/unsupported conversion. */
			return NULL;
		}
	}

	if (!HAVE_YDAY(state) && HAVE_YEAR(state)) {
		if (HAVE_MON(state) && HAVE_MDAY(state)) {
			/* calculate day of year (ordinal date) */
			tm->tm_yday =  start_of_month[isleap_sum(tm->tm_year,
			    TM_YEAR_BASE)][tm->tm_mon] + (tm->tm_mday - 1);
			state |= S_YDAY;
		} else if (day_offset != -1) {
			/*
			 * Set the date to the first Sunday (or Monday)
			 * of the specified week of the year.
			 */
			if (!HAVE_WDAY(state)) {
				tm->tm_wday = day_offset;
				state |= S_WDAY;
			}
			tm->tm_yday = (7 -
			    first_wday_of(tm->tm_year + TM_YEAR_BASE) +
			    day_offset) % 7 + (week_offset - 1) * 7 +
			    tm->tm_wday  - day_offset;
			state |= S_YDAY;
		}
	}

	if (HAVE_YDAY(state) && HAVE_YEAR(state)) {
		int isleap;

		if (!HAVE_MON(state)) {
			/* calculate month of day of year */
			i = 0;
			isleap = isleap_sum(tm->tm_year, TM_YEAR_BASE);
			while (tm->tm_yday >= start_of_month[isleap][i])
				i++;
			if (i > 12) {
				i = 1;
				tm->tm_yday -= start_of_month[isleap][12];
				tm->tm_year++;
			}
			tm->tm_mon = i - 1;
			state |= S_MON;
		}

		if (!HAVE_MDAY(state)) {
			/* calculate day of month */
			isleap = isleap_sum(tm->tm_year, TM_YEAR_BASE);
			tm->tm_mday = tm->tm_yday -
			    start_of_month[isleap][tm->tm_mon] + 1;
			state |= S_MDAY;
		}

		if (!HAVE_WDAY(state)) {
			/* calculate day of week */
			i = 0;
			week_offset = first_wday_of(tm->tm_year);
			while (i++ <= tm->tm_yday) {
				if (week_offset++ >= 6)
					week_offset = 0;
			}
			tm->tm_wday = week_offset;
		}
	}

	return (char *)bp;
}


static const unsigned char *
conv_num(const unsigned char *buf, int *dest, unsigned llim, unsigned ulim)
{
	unsigned result = 0;
	unsigned char ch;

	/* The limit also determines the number of valid digits. */
	unsigned rulim = ulim;

	ch = *buf;
	if (ch < '0' || ch > '9')
		return NULL;

	do {
		result *= 10;
		result += ch - '0';
		rulim /= 10;
		ch = *++buf;
	} while ((result * 10 <= ulim) && rulim && ch >= '0' && ch <= '9');

	if (result < llim || result > ulim)
		return NULL;

	*dest = result;
	return buf;
}

static const unsigned char *
find_string(const unsigned char *bp, int *tgt, const char * const *n1,
		const char * const *n2, int c)
{
	int i;
	size_t len;

	/* check full name - then abbreviated ones */
	for (; n1 != NULL; n1 = n2, n2 = NULL) {
		for (i = 0; i < c; i++, n1++) {
			len = strlen(*n1);
			if (g_ascii_strncasecmp(*n1, (const char *)bp, len) == 0) {
				*tgt = i;
				return bp + len;
			}
		}
	}

	/* Nothing matched */
	return NULL;
}
