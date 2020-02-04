/* epochs.h
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
 * The Windows NT epoch, used in a number of places.
 *
 * This is
 *
 *     369*365.25*24*60*60-(3*24*60*60+6*60*60)
 *
 * 1970-1601 is 369; 365.25 is the average length of a year in days,
 * including leap years.
 *
 * 3 days are subtracted because 1700, 1800, and 1900 were not leap
 * years, as, while they're all evenly divisible by 4, they're also
 * evently divisible by 100, but not evently divisible by 400, so
 * we need to compensate for using the average length of a year in
 * days, which assumes a leap year every 4 years, *including* every
 * 100 years.
 *
 * I'm not sure what the extra 6 hours are that are being subtracted.
 */
#define EPOCH_DELTA_1601_01_01_00_00_00_UTC G_GUINT64_CONSTANT(11644473600)

#endif /* __EPOCHS_H__ */
