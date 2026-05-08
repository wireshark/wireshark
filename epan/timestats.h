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

 /* Summary of time statistics*/
typedef struct _timestat_t {
	uint32_t num;	 /* number of samples */
	uint32_t	min_num; /* frame number of minimum */
	uint32_t	max_num; /* frame number of maximum */
	nstime_t min;
	nstime_t max;
	nstime_t tot;
	double variance;
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
