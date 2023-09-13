/** @file
 * Defines for packet timestamps
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TIMESTAMP_H__
#define __TIMESTAMP_H__

#include "ws_symbol_export.h"

#include <wsutil/nstime.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Type of time-stamp shown in the summary display.
 */
typedef enum {
	TS_RELATIVE,            /* Since start of capture */
	TS_ABSOLUTE,		/* Local absolute time, without date */
	TS_ABSOLUTE_WITH_YMD,	/* Local absolute time, with date in YYYY-MM-DD form */
	TS_ABSOLUTE_WITH_YDOY,	/* Local absolute time, with date in YYYY DOY form */
	TS_DELTA,               /* Since previous captured packet */
	TS_DELTA_DIS,           /* Since previous displayed packet */
	TS_EPOCH,               /* Seconds (and fractions) since epoch */
	TS_UTC,			/* UTC absolute time, without date */
	TS_UTC_WITH_YMD,	/* UTC absolute time, with date in YYYY-MM-DD form */
	TS_UTC_WITH_YDOY,	/* UTC absolute time, with date in YYYY DOY form */

/*
 * Special value used for the command-line setting in Wireshark, to indicate
 * that no value has been set from the command line.
 */
	TS_NOT_SET
} ts_type;

typedef enum {
	TS_PREC_AUTO           = -1,	/* Use what the capture file specifies */
	TS_PREC_FIXED_SEC      = WS_TSPREC_SEC,
	TS_PREC_FIXED_100_MSEC = WS_TSPREC_100_MSEC,
	TS_PREC_FIXED_10_MSEC  = WS_TSPREC_10_MSEC,
	TS_PREC_FIXED_MSEC     = WS_TSPREC_MSEC,
	TS_PREC_FIXED_100_USEC = WS_TSPREC_100_USEC,
	TS_PREC_FIXED_10_USEC  = WS_TSPREC_10_USEC,
	TS_PREC_FIXED_USEC     = WS_TSPREC_USEC,
	TS_PREC_FIXED_100_NSEC = WS_TSPREC_100_NSEC,
	TS_PREC_FIXED_10_NSEC  = WS_TSPREC_10_NSEC,
	TS_PREC_FIXED_NSEC     = WS_TSPREC_NSEC,

/*
 * Special value used for the command-line setting in Wireshark, to indicate
 * that no value has been set from the command line.
 */
	TS_PREC_NOT_SET    = -2
} ts_precision;

typedef enum {
	TS_SECONDS_DEFAULT,	/* recent */
	TS_SECONDS_HOUR_MIN_SEC,/* recent */

/*
 * Special value used for the command-line setting in Wireshark, to indicate
 * that no value has been set from the command line.
 */
	TS_SECONDS_NOT_SET
} ts_seconds_type;

WS_DLL_PUBLIC ts_type timestamp_get_type(void);
WS_DLL_PUBLIC void timestamp_set_type(ts_type);

WS_DLL_PUBLIC int timestamp_get_precision(void);
WS_DLL_PUBLIC void timestamp_set_precision(int tsp);

WS_DLL_PUBLIC ts_seconds_type timestamp_get_seconds_type(void);
WS_DLL_PUBLIC void timestamp_set_seconds_type(ts_seconds_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* timestamp.h */
