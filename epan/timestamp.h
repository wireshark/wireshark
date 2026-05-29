/** @file
 * Defines for packet timestamps
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "ws_symbol_export.h"

#include <wsutil/nstime.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Format used to display packet timestamps in the summary packet list.
 */
typedef enum {
    TS_RELATIVE,          /**< Time elapsed since the first captured frame */
    TS_RELATIVE_CAP,      /**< Time elapsed since the start of the capture session */
    TS_ABSOLUTE,          /**< Local wall-clock time, without date */
    TS_ABSOLUTE_WITH_YMD, /**< Local wall-clock time, with date in YYYY-MM-DD form */
    TS_ABSOLUTE_WITH_YDOY,/**< Local wall-clock time, with date in YYYY DOY (day-of-year) form */
    TS_DELTA,             /**< Time elapsed since the previous captured packet */
    TS_DELTA_DIS,         /**< Time elapsed since the previous displayed packet */
    TS_EPOCH,             /**< Seconds (and fractional seconds) since the Unix epoch */
    TS_UTC,               /**< UTC absolute time, without date */
    TS_UTC_WITH_YMD,      /**< UTC absolute time, with date in YYYY-MM-DD form */
    TS_UTC_WITH_YDOY,     /**< UTC absolute time, with date in YYYY DOY (day-of-year) form */
    TS_NOT_SET            /**< Sentinel indicating that no timestamp format has been set via the command line */
} ts_type;


/**
 * @brief Sub-second precision used when formatting packet timestamps.
 */
typedef enum {
    TS_PREC_AUTO           = -1,              /**< Use the precision specified by the capture file */
    TS_PREC_FIXED_SEC      = WS_TSPREC_SEC,      /**< Display timestamps with whole-second precision */
    TS_PREC_FIXED_100_MSEC = WS_TSPREC_100_MSEC, /**< Display timestamps with 100-millisecond precision */
    TS_PREC_FIXED_10_MSEC  = WS_TSPREC_10_MSEC,  /**< Display timestamps with 10-millisecond precision */
    TS_PREC_FIXED_MSEC     = WS_TSPREC_MSEC,     /**< Display timestamps with millisecond (1 ms) precision */
    TS_PREC_FIXED_100_USEC = WS_TSPREC_100_USEC, /**< Display timestamps with 100-microsecond precision */
    TS_PREC_FIXED_10_USEC  = WS_TSPREC_10_USEC,  /**< Display timestamps with 10-microsecond precision */
    TS_PREC_FIXED_USEC     = WS_TSPREC_USEC,     /**< Display timestamps with microsecond (1 µs) precision */
    TS_PREC_FIXED_100_NSEC = WS_TSPREC_100_NSEC, /**< Display timestamps with 100-nanosecond precision */
    TS_PREC_FIXED_10_NSEC  = WS_TSPREC_10_NSEC,  /**< Display timestamps with 10-nanosecond precision */
    TS_PREC_FIXED_NSEC     = WS_TSPREC_NSEC,     /**< Display timestamps with nanosecond (1 ns) precision */
    TS_PREC_NOT_SET        = -2                  /**< Sentinel indicating that no precision has been set via the command line */
} ts_precision;


/**
 * @brief Controls how the seconds component of a timestamp is formatted for display.
 */
typedef enum {
    TS_SECONDS_DEFAULT,      /**< Display seconds as a plain decimal value (default/recent preference) */
    TS_SECONDS_HOUR_MIN_SEC, /**< Display seconds in HH:MM:SS format (recent preference) */
    TS_SECONDS_NOT_SET       /**< Sentinel indicating that no seconds format has been set via the command line */
} ts_seconds_type;

/**
 * @brief Get the current timestamp type.
 *
 * @return ts_type The current timestamp type.
 */
WS_DLL_PUBLIC ts_type timestamp_get_type(void);

/**
 * @brief Set the timestamp type.
 *
 * @param ts_t The timestamp type to set.
 */
WS_DLL_PUBLIC void timestamp_set_type(ts_type ts_t);

/**
 * @brief Get the current timestamp precision.
 *
 * @return The current timestamp precision.
 */
WS_DLL_PUBLIC int timestamp_get_precision(void);

/**
 * @brief Set the timestamp precision.
 *
 * @param tsp The timestamp precision to set.
 */
WS_DLL_PUBLIC void timestamp_set_precision(int tsp);

/**
 * @brief Get the current timestamp seconds type.
 *
 * @return ts_seconds_type The current timestamp seconds type.
 */
WS_DLL_PUBLIC ts_seconds_type timestamp_get_seconds_type(void);

/**
 * @brief Set the timestamp seconds type.
 *
 * @param ts_t The timestamp seconds type to set.
 */
WS_DLL_PUBLIC void timestamp_set_seconds_type(ts_seconds_type ts_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */
