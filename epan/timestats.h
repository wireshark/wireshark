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

#ifndef __TIMESTATS_H__
#define __TIMESTATS_H__

#include <glib.h>
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

/* Initialize a timestat_t struct */
WS_DLL_PUBLIC void time_stat_init(timestat_t *stats);

/* Update a timestat_t struct with a new sample */
WS_DLL_PUBLIC void time_stat_update(timestat_t *stats, const nstime_t *delta, packet_info *pinfo);

WS_DLL_PUBLIC double get_average(const nstime_t *sum, uint32_t num);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TIMESTATS_H__ */
