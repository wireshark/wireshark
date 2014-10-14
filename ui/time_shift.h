/* time_shift.h
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

const gchar * time_string_parse(const gchar *time_text, int *year, int *month, int *day, gboolean *negative, int *hour, int *minute, long double *second);

/** Shift all packets by an offset
 *
 * @param cf Capture file to shift
 * @param offset_text String representation of the offset.
 *
 * @return NULL on success or an error description on failure.
 */
const gchar * time_shift_all(capture_file *cf, const gchar *offset_text);

/* Set the time for a single packet
 *
 * @param cf Capture file to set
 * @param packet_num Packet to set
 * @param time_text String representation of the time
 *
 * @return NULL on success or an error description on failure.
 */
const gchar * time_shift_settime(capture_file *cf, guint packet_num, const gchar *time_text);

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
const gchar * time_shift_adjtime(capture_file *cf, guint packet1_num, const gchar *time1_text, guint packet2_num, const gchar *time2_text);

/* Reset the times for all packets
 *
 * @param cf Capture file to set
 *
 * @return NULL on success or an error description on failure.
 */
const gchar * time_shift_undo(capture_file *cf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TIME_SHIFT_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
