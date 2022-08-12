/* file-pcapng.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __FILE_PCAPNG_H__
#define __FILE_PCAPNG_H__

/* Used by custom dissector */

/* File info */
struct info {
    guint32        section_number;
    guint32        interface_number;
    guint32        darwin_process_event_number;
    guint32        frame_number;
    guint          encoding;
    wmem_array_t  *interfaces;
    wmem_array_t  *darwin_process_events;
};

struct interface_description {
    guint32  link_type;
    guint32  snap_len;
    guint64  timestamp_resolution;
    guint64  timestamp_offset;
};

struct darwin_process_event_description {
    guint32  process_id;
};

/* Dissect one PCAPNG Block */
extern gint dissect_block(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, struct info *info);

#endif
