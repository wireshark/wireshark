/** @file
 *
 * Declarations of platform-dependent capture info functions.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/** @file
 *
 * Capture info functions.
 *
 */

#ifndef __CAPTURE_INFO_H__
#define __CAPTURE_INFO_H__

#include "capture_opts.h"
#include <capture/capture_session.h>
#include <epan/capture_dissectors.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Current Capture info. */
typedef struct _capture_info {
    /* handle */
    void *          ui;             /**< user interface handle */

    /* capture info */
    packet_counts   *counts;        /**< protocol specific counters */
    int             new_packets;    /**< packets since last update */
} capture_info;

typedef struct _info_data {
    packet_counts     counts;     /* Packet counting */
    capture_info      ui;         /* user interface data */
} info_data_t;

/** Create the capture info dialog */
extern void
capture_info_ui_create(capture_info *cinfo, capture_session *cap_session);

/** Update the capture info counters in the dialog */
extern void capture_info_ui_update(
capture_info    *cinfo);

/** Destroy the capture info dialog again */
extern void capture_info_ui_destroy(
capture_info    *cinfo);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ui/capture_info.h */
