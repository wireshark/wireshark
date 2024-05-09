/** @file
 *
 * Definitions of epoch values for various absolute time types.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EPOCHS_H__
#define __EPOCHS_H__

#include <glib.h>

/*
 * Deltas between the epochs for various non-UN*X time stamp formats and
 * the January 1, 1970, 00:00:00 (proleptic?) UTC epoch for the UN*X time
 * stamp format.
 */

/*
 * 1900-01-01 00:00:00 (proleptic?) UTC.
 * Used by a number of time formats.
 */
#define EPOCH_DELTA_1900_01_01_00_00_00_UTC 2208988800U

/*
 * 1904-01-01 00:00:00 (proleptic?) UTC.
 * Used in the classic Mac OS, and by formats, such as MPEG-4 Part 14 (MP4),
 * which is based on Apple's QuickTime format.
 */
#define EPOCH_DELTA_1904_01_01_00_00_00_UTC  2082844800U

/*
 * 1601-01-01 (proleptic Gregorian) 00:00:00 (proleptic?) UTC.
 * The Windows NT epoch, used in a number of places, as it is
 * the start of a 400 year Gregorian cycle.
 *
 * This is
 *
 *     369*365.25*24*60*60-(3*24*60*60+6*60*60)
 *
 * or equivalently,
 *
 *     (89*4*365.25+(3*4+1)*365)*24*60*60
 *
 * 1970-1601 is 369; 365.25 is the average length of a year in days,
 * including leap years.
 *
 * 369 = 4*92 + 1, so there are 92 groups of 4 consecutive years plus
 * one leftover year, 1969, with 365 days.
 *
 * All but three of the groups of 4 consecutive years average 365.25 days
 * per year, as they have one leap year in the group. However, 1700, 1800,
 * and 1900 were not leap years, as, while they're all evenly divisible by 4,
 * they're also evenly divisible by 100, but not evenly divisible by 400.
 *
 * So we have 89 groups of 4 consecutive years that average 365.25
 * days per year, 3 groups of 4 consecutive years that average 365 days
 * (as they lack a leap year), and one leftover year, 1969, that is
 * 365 days long.
 */
#define EPOCH_DELTA_1601_01_01_00_00_00_UTC UINT64_C(11644473600)

/*
 * 2000-01-01 00:00:00 UTC.
 * Used by the Zigbee Zigbee Cluster Library protocol.
 */
#define EPOCH_DELTA_2000_01_01_00_00_00_UTC ((unsigned)(((3*365 + 366)*7 + 2*365)*24*3600))

#endif /* __EPOCHS_H__ */
