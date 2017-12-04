/* frame_set.h
 * Definition of frame_set structure.  It holds information about a
 * fdfdkfslf;ajkdf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __EPAN_FRAME_SET_H__
#define __EPAN_FRAME_SET_H__

#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>

#include "ws_symbol_export.h"

typedef struct {
  wtap        *wth;                  /* Wiretap session */
  const frame_data *ref;
  frame_data  *prev_dis;
  frame_data  *prev_cap;
  frame_data_sequence *frames;       /* Sequence of frames, if we're keeping that information */
  GTree       *frames_user_comments; /* BST with user comments for frames (key = frame_data) */
} frame_set;

WS_DLL_PUBLIC const char *frame_set_get_interface_name(frame_set *fs, guint32 interface_id);
WS_DLL_PUBLIC const char *frame_set_get_interface_description(frame_set *fs, guint32 interface_id);

#endif /* frame_set.h */
