/* frame_data_sequence.h
 * Implements a sequence of frame_data structures
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
