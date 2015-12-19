/* capture_info.h
 * capture info functions
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


/** @file
 *
 * Capture info functions.
 *
 */

/*
 * GTK+ only.
 * If we add this to the Qt UI we should modernize the statistics we show.
 * At the very least we should remove or hide IPX and VINES.
 */

#ifndef __CAPTURE_INFO_H__
#define __CAPTURE_INFO_H__

#include "capture_opts.h"
#include <capchild/capture_session.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    GHashTable*       counts_hash; /* packet counters keyed by proto */
    gint              other;      /* Packets not counted in the hash total */
    gint              total;      /* Cache of total packets */

} packet_counts;

/** Current Capture info. */
typedef struct {
    /* handle */
    gpointer        ui;             /**< user interface handle */

    /* capture info */
    packet_counts   *counts;        /**< protocol specific counters */
    time_t          running_time;   /**< running time since last update */
    gint            new_packets;    /**< packets since last update */
} capture_info;

typedef struct _info_data {
    packet_counts     counts;     /* Packet counting */
    struct wtap*      wtap;       /* current wtap file */
    capture_info      ui;         /* user interface data */
} info_data_t;

/* open the info - init values (wtap, counts), create dialog */
extern void capture_info_open(capture_session *cap_session, info_data_t* cap_info);

/* new file arrived - (eventually close old wtap), open wtap */
extern gboolean capture_info_new_file(const char *new_filename, info_data_t* cap_info);

/* new packets arrived - read from wtap, count */
extern void capture_info_new_packets(int to_read, info_data_t* cap_info);

/* close the info - close wtap, destroy dialog */
extern void capture_info_close(info_data_t* cap_info);

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

#endif /* capture_info.h */

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
