/** @file
 *
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TIME_SHIFT_H__
#define __TIME_SHIFT_H__

#include "cfile.h"
#include <wsutil/nstime.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * XXX - We might want to move all of this somewhere more accessible to
 * editcap so that we can make its time adjustments more versatile.
 */

/**
 * Parse a time string and fill in each component.
 *
 * If year, month, and day are non-NULL a full time format "[YYYY-MM-DD] hh:mm:ss[.decimals]"
 * is allowed. Otherwise an offset format "[-][[hh:]mm:]ss[.decimals]" is allowed.
 *
 * @param time_text Time string
 * @param year Year. May be NULL
 * @param month Month. May be NULL
 * @param day Day. May be NULL.
 * @param negative Time offset is negative. May be NULL if year, month, and day are not NULL.
 * @param hour Hours. Must not be NULL.
 * @param minute Minutes. Must not be NULL.
 * @param second Seconds. Must not be NULL.
 *
 * @return NULL on success or an error description on failure.
 */

const char * time_string_parse(const char *time_text, int *year, int *month, int *day, bool *negative, int *hour, int *minute, long double *second);

/** Shift all packets by an offset
 *
 * @param cf Capture file to shift
 * @param offset_text String representation of the offset.
 *
 * @return NULL on success or an error description on failure.
 */
const char * time_shift_all(capture_file *cf, const char *offset_text);

/* Set the time for a single packet
 *
 * @param cf Capture file to set
 * @param packet_num Packet to set
 * @param time_text String representation of the time
 *
 * @return NULL on success or an error description on failure.
 */
const char * time_shift_settime(capture_file *cf, unsigned packet_num, const char *time_text);

/* Set the time for two packets and extrapolate the rest
 *
 * @param cf Capture file to set
 * @param packet1_num First packet to set
 * @param time1_text String representation of the first packet time
 * @param packet2_num Second packet to set
 * @param time2_text String representation of the second packet time
 *
 * @return NULL on success or an error description on failure.
 */
const char * time_shift_adjtime(capture_file *cf, unsigned packet1_num, const char *time1_text, unsigned packet2_num, const char *time2_text);

/* Reset the times for all packets
 *
 * @param cf Capture file to set
 *
 * @return NULL on success or an error description on failure.
 */
const char * time_shift_undo(capture_file *cf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TIME_SHIFT_H__ */
