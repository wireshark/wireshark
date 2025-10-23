/* nstime.h
 * Definition of data structure to hold time values with nanosecond resolution
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NSTIME_H__
#define __NSTIME_H__

#include <wireshark.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Definition of data structure to hold time values with nanosecond resolution
 */

/** data structure to hold time values with nanosecond resolution*/
typedef struct {
	time_t	secs;
	int	nsecs;
} nstime_t;

/* Macros that expand to nstime_t initializers */

/* Initialize to zero */
#define NSTIME_INIT_ZERO {0, 0}

/* Initialize to unset */
#define NSTIME_INIT_UNSET {0, INT_MAX}

/* Initialize to a specified number of seconds and nanoseconds */
#define NSTIME_INIT_SECS_NSECS(secs, nsecs)	{(secs) + ((nsecs) / 1000000000), (nsecs) % 1000000000}

/* Initialize to a specified number of seconds and microseconds */
#define NSTIME_INIT_SECS_USECS(secs, usecs)	{(secs) + ((usecs) / 1000000), ((usecs) % 1000000) * 1000}

/* Initialize to a specified number of seconds and milliseconds */
#define NSTIME_INIT_SECS_MSECS(secs, msecs)	{(secs) + ((msecs) / 1000), ((msecs) % 1000) * 1000000}

/* Initialize to a specified number of seconds */
#define NSTIME_INIT_SECS(secs)			{secs, 0}

/* Initialize to the maximum possible value */
#define NSTIME_INIT_MAX	{sizeof(time_t) > sizeof(int) ? LONG_MAX : INT_MAX, INT_MAX}

/* functions */

/**
 * @brief Sets the given nstime_t to zero.
 *
 * Initializes the time value to 0 seconds and 0 nanoseconds.
 *
 * @param nstime Pointer to the nstime_t structure to modify.
 */
WS_DLL_PUBLIC void nstime_set_zero(nstime_t *nstime);

/**
 * @brief Checks whether the given nstime_t is zero.
 *
 * Determines if the time value represents exactly 0 seconds and 0 nanoseconds.
 *
 * @param nstime Pointer to the nstime_t structure to check.
 * @return true if the time is zero, false otherwise.
 */
WS_DLL_PUBLIC bool nstime_is_zero(const nstime_t *nstime);

/**
 * @brief Checks whether the given nstime_t is negative.
 *
 * Determines if the time value represents a negative duration.
 *
 * @param nstime Pointer to the nstime_t structure to check.
 * @return true if the time is negative, false otherwise.
 */
WS_DLL_PUBLIC bool nstime_is_negative(const nstime_t *nstime);

/**
 * @brief Marks the given nstime_t as "unset".
 *
 * Sets the time value to (0, INT_MAX) to indicate an unset state.
 * This allows distinguishing between a true zero timestamp and an uninitialized one.
 *
 * @note This was created as a fix for bug 1056.
 *
 * @param nstime Pointer to the nstime_t structure to modify.
 */
WS_DLL_PUBLIC void nstime_set_unset(nstime_t *nstime);

/**
 * @brief Checks whether the given nstime_t is marked as "unset".
 *
 * Determines if the time value is (0, INT_MAX), which is used to represent an unset timestamp.
 *
 * @param nstime Pointer to the nstime_t structure to check.
 * @return true if the time is unset, false otherwise.
 */
WS_DLL_PUBLIC bool nstime_is_unset(const nstime_t *nstime);

/**
 * @brief Copies one nstime_t value to another.
 *
 * Performs a deep copy of the time value from source to destination.
 * Effectively: a = b
 *
 * @param a Pointer to the destination nstime_t structure.
 * @param b Pointer to the source nstime_t structure.
 */
WS_DLL_PUBLIC void nstime_copy(nstime_t *a, const nstime_t *b);

/**
 * @brief Calculates the time delta between two timestamps.
 *
 * Computes the difference between two time values, allowing for negative results.
 * The result is stored in the `delta` structure as `delta = b - a`.
 * It is safe for any of the arguments to refer to the same structure.
 *
 * @param delta Pointer to the destination nstime_t structure to store the result.
 * @param b Pointer to the later (or second) time value.
 * @param a Pointer to the earlier (or first) time value.
 */
WS_DLL_PUBLIC void nstime_delta(nstime_t *delta, const nstime_t *b, const nstime_t *a);

/**
 * @brief Calculates the sum of two time values.
 *
 * Adds two time values together and stores the result in the `sum` structure as `sum = a + b`.
 * It is safe for any of the arguments to refer to the same structure.
 *
 * @param sum Pointer to the destination nstime_t structure to store the result.
 * @param a Pointer to the first time value.
 * @param b Pointer to the second time value.
 */
WS_DLL_PUBLIC void nstime_sum(nstime_t *sum, const nstime_t *a, const nstime_t *b);

/**
 * @def nstime_add(sum, a)
 * @brief Adds a time value to an existing sum.
 *
 * Performs in-place addition: `sum += a`.
 *
 * @param sum Pointer to the destination nstime_t structure.
 * @param a Pointer to the time value to add.
 */
#define nstime_add(sum, a) nstime_sum(sum, sum, a)

/**
 * @def nstime_subtract(sum, a)
 * @brief Subtracts a time value from an existing sum.
 *
 * Performs in-place subtraction: `sum -= a`.
 *
 * @param sum Pointer to the destination nstime_t structure.
 * @param a Pointer to the time value to subtract.
 */
#define nstime_subtract(sum, a) nstime_delta(sum, sum, a)

/**
 * @brief Compares two time values.
 *
 * Returns a value similar to memcmp() or strcmp():
 * - > 0 if `a > b`
 * -   0 if `a == b`
 * - < 0 if `a < b`
 *
 * @param a Pointer to the first time value.
 * @param b Pointer to the second time value.
 * @return An integer indicating the comparison result.
 */
WS_DLL_PUBLIC int nstime_cmp(const nstime_t *a, const nstime_t *b);

/**
 * @brief Computes a hash value for a time value.
 *
 * Generates a hash suitable for use in hash tables or maps.
 *
 * @param nstime Pointer to the time value to hash.
 * @return A hash value representing the time.
 */
WS_DLL_PUBLIC unsigned nstime_hash(const nstime_t *nstime);

/**
 * @brief Converts a time value to milliseconds.
 *
 * Returns the time as a double-precision value in milliseconds.
 *
 * @param nstime Pointer to the time value.
 * @return Time in milliseconds.
 */
WS_DLL_PUBLIC double nstime_to_msec(const nstime_t *nstime);

/**
 * @brief Converts a time value to seconds.
 *
 * Returns the time as a double-precision value in seconds.
 *
 * @param nstime Pointer to the time value.
 * @return Time in seconds.
 */
WS_DLL_PUBLIC double nstime_to_sec(const nstime_t *nstime);

/**
 * @brief Converts a Windows FILETIME to nstime.
 *
 * Converts a 64-bit FILETIME value (in 100-nanosecond units since 1601)
 * to an nstime_t structure.
 *
 * @param nstime Pointer to the destination nstime_t structure.
 * @param filetime The FILETIME value to convert.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC bool filetime_to_nstime(nstime_t *nstime, uint64_t filetime);

/**
 * @brief Converts a nanosecond-based FILETIME to nstime.
 *
 * Converts a 64-bit time value expressed in nanoseconds to an nstime_t structure.
 * Caller must ensure the input is trusted and properly scaled.
 *
 * @param nstime Pointer to the destination nstime_t structure.
 * @param nsfiletime The nanosecond-based time value to convert.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC bool filetime_ns_to_nstime(nstime_t *nstime, uint64_t nsfiletime);

/**
 * @brief Converts a second-based FILETIME to nstime.
 *
 * Converts a 64-bit time value expressed in seconds to an nstime_t structure.
 *
 * @param nstime Pointer to the destination nstime_t structure.
 * @param filetime The second-based time value to convert.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC bool filetime_1sec_to_nstime(nstime_t *nstime, uint64_t filetime);

typedef enum {
    ISO8601_DATETIME,       /** e.g. 2014-07-04T12:34:56.789+00:00 */
    ISO8601_DATETIME_BASIC, /** ISO8601 Basic format, i.e. no - : separators */
    ISO8601_DATETIME_AUTO,  /** Autodetect the presence of separators */
} iso8601_fmt_e;

/**
 * @brief Parses an ISO 8601 formatted datetime string into an nstime_t.
 *
 * Converts a string in ISO 8601 format (e.g., "2025-10-22T23:10:00.123Z") into an nstime_t structure.
 * On failure, returns NULL and sets the nstime to "unset".
 *
 * @param nstime Pointer to the destination nstime_t structure.
 * @param ptr Pointer to the ISO 8601 string to parse.
 * @param format The expected format variant (e.g., extended or basic).
 * @return Pointer to the first character after the parsed input, or NULL on failure.
 */
WS_DLL_PUBLIC const char * iso8601_to_nstime(nstime_t *nstime, const char *ptr, iso8601_fmt_e format);

/**
 * @brief Parses a Unix epoch timestamp string into an nstime_t.
 *
 * Converts a string representing a Unix timestamp (seconds since epoch) into an nstime_t structure.
 * On failure, returns NULL and sets the nstime to "unset".
 *
 * @param nstime Pointer to the destination nstime_t structure.
 * @param ptr Pointer to the Unix timestamp string to parse.
 * @return Pointer to the first character after the parsed input, or NULL on failure.
 */
WS_DLL_PUBLIC const char * unix_epoch_to_nstime(nstime_t *nstime, const char *ptr);

/**
 * @def NSTIME_ISO8601_BUFSIZE
 * @brief Buffer size required to store a full ISO 8601 timestamp string.
 *
 * Includes space for nanosecond precision and the trailing 'Z' character.
 */
#define NSTIME_ISO8601_BUFSIZE  sizeof("YYYY-MM-DDTHH:MM:SS.123456789Z")

/**
 * @brief Converts an nstime_t to an ISO 8601 formatted string.
 *
 * Formats the given time value into a string using ISO 8601 format with nanosecond precision.
 *
 * @param buf Destination buffer to hold the formatted string.
 * @param buf_size Size of the destination buffer.
 * @param nstime Pointer to the time value to format.
 * @return Number of characters written to the buffer (excluding null terminator).
 */
WS_DLL_PUBLIC size_t nstime_to_iso8601(char *buf, size_t buf_size, const nstime_t *nstime);

/**
 * @def NSTIME_UNIX_BUFSIZE
 * @brief Buffer size required to store a full Unix timestamp string with nanosecond precision.
 *
 * Includes space for a 64-bit signed integer and fractional nanoseconds.
 */
#define NSTIME_UNIX_BUFSIZE  (20+10+1)

/**
 * @brief Converts an nstime_t to a Unix timestamp string.
 *
 * Formats the given time value into a string representing seconds since the Unix epoch,
 * with optional nanosecond precision.
 *
 * @param buf Destination buffer to hold the formatted string.
 * @param buf_size Size of the destination buffer.
 * @param nstime Pointer to the time value to format.
 */
WS_DLL_PUBLIC void nstime_to_unix(char *buf, size_t buf_size, const nstime_t *nstime);

/**
 * @enum ws_tsprec_e
 * @brief Timestamp precision levels.
 *
 * Defines the number of digits of precision after the integral part of a timestamp.
 * These values are used to control formatting and interpretation of time values
 * across various subsystems (e.g., capture, display, export).
 */
typedef enum {
    WS_TSPREC_SEC      = 0, /**< Precision to whole seconds (0 digits) */
    WS_TSPREC_100_MSEC = 1, /**< Precision to 100 milliseconds (1 digit) */
    WS_TSPREC_10_MSEC  = 2, /**< Precision to 10 milliseconds (2 digits) */
    WS_TSPREC_MSEC     = 3, /**< Precision to 1 millisecond (3 digits) */
    WS_TSPREC_100_USEC = 4, /**< Precision to 100 microseconds (4 digits) */
    WS_TSPREC_10_USEC  = 5, /**< Precision to 10 microseconds (5 digits) */
    WS_TSPREC_USEC     = 6, /**< Precision to 1 microsecond (6 digits) */
    WS_TSPREC_100_NSEC = 7, /**< Precision to 100 nanoseconds (7 digits) */
    WS_TSPREC_10_NSEC  = 8, /**< Precision to 10 nanoseconds (8 digits) */
    WS_TSPREC_NSEC     = 9  /**< Precision to 1 nanosecond (9 digits) */
} ws_tsprec_e;

/**
 * @def WS_TSPREC_MAX
 * @brief Maximum supported timestamp precision.
 *
 * Indicates the highest precision level supported (nanoseconds).
 * @note Extending beyond this would require expanding the fractional part of `nstime_t` to 64 bits.
 */
#define WS_TSPREC_MAX 9

/**
 * @def NUM_WS_TSPREC_VALS
 * @brief Total number of valid timestamp precision values.
 *
 * Represents the count of defined precision levels from seconds to nanoseconds.
 */
#define NUM_WS_TSPREC_VALS (WS_TSPREC_MAX + 1)

/**
 * @brief Rounds a time value to the specified precision.
 *
 * Adjusts the fractional part of the time value to match the requested precision.
 * For example, rounding to milliseconds will zero out micro- and nanosecond components.
 * It is safe for `a` and `b` to point to the same structure.
 *
 * @param a Pointer to the destination `nstime_t` structure.
 * @param b Pointer to the source `nstime_t` structure.
 * @param prec The desired precision level.
 */
WS_DLL_PUBLIC void nstime_rounded(nstime_t *a, const nstime_t *b, ws_tsprec_e prec);

/**
 * @def nstime_round(a, prec)
 * @brief In-place rounding of a time value to the specified precision.
 *
 * Equivalent to calling `nstime_rounded(a, a, prec)`.
 *
 * @param a Pointer to the `nstime_t` structure to round.
 * @param prec The desired precision level.
 */
#define nstime_round(a, prec) nstime_rounded(a, a, prec)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __NSTIME_H__  */
