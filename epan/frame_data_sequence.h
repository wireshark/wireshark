/* frame_data_sequence.h
 * Implements a sequence of frame_data structures
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

#ifndef __FRAME_DATA_SEQUENCE_H__
#define __FRAME_DATA_SEQUENCE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _frame_data_sequence frame_data_sequence;

WS_DLL_PUBLIC frame_data_sequence *new_frame_data_sequence(void);

WS_DLL_PUBLIC frame_data *frame_data_sequence_add(frame_data_sequence *fds,
    frame_data *fdata);

/*
 * Find the frame_data for the specified frame number.
 */
WS_DLL_PUBLIC frame_data *frame_data_sequence_find(frame_data_sequence *fds,
    guint32 num);

/*
 * Free a frame_data_sequence and all the frame_data structures in it.
 */
WS_DLL_PUBLIC void free_frame_data_sequence(frame_data_sequence *fds);

WS_DLL_PUBLIC void find_and_mark_frame_depended_upon(gpointer data, gpointer user_data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FRAME_DATA_SEQUENCE_H__ */
