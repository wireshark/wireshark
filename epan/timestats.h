/** @file
 * Routines and definitions for time statistics
 * Copyright 2003 Lars Roland
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "epan/packet_info.h"
#include "wsutil/nstime.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Accumulates time delay samples for computing min, max, total, and variance statistics over a set of measurements.
 */
typedef struct _timestat_t {
    uint32_t num;     /**< Total number of time samples collected. */
    uint32_t min_num; /**< Frame number of the packet that produced the minimum time sample. */
    uint32_t max_num; /**< Frame number of the packet that produced the maximum time sample. */
    nstime_t min;     /**< Minimum time value observed across all samples. */
    nstime_t max;     /**< Maximum time value observed across all samples. */
    nstime_t tot;     /**< Sum of all time samples, used to compute the mean. */
    double   variance; /**< Variance of the time samples, used to compute standard deviation. */
} timestat_t;

/* functions */

/**
 * @brief Initialize a timestat_t structure.
 *
 * @param stats Pointer to the timestat_t structure to initialize.
 */
WS_DLL_PUBLIC void time_stat_init(timestat_t *stats);

/**
 * @brief Update time statistics with a new sample.
 *
 * This function updates the minimum, maximum, and total time statistics based on the given delta.
 *
 * @param stats Pointer to the timestat_t structure to be updated.
 * @param delta Pointer to the nstime_t structure representing the time difference.
 * @param pinfo Pointer to the packet_info structure containing information about the current packet.
 */
WS_DLL_PUBLIC void time_stat_update(timestat_t *stats, const nstime_t *delta, packet_info *pinfo);

/**
 * @brief Calculate the average time from a sum of time values.
 *
 * @param sum Pointer to the nstime_t structure containing the total time.
 * @param num Number of time values included in the sum.
 * @return double The calculated average time in milliseconds.
 */
WS_DLL_PUBLIC double get_average(const nstime_t *sum, uint32_t num);

#ifdef __cplusplus
}
#endif /* __cplusplus */
