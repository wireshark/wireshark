/* packet-moq-lite.h
 * Media over QUIC Lite (moq-lite) payload handoff
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MOQ_LITE_H__
#define __PACKET_MOQ_LITE_H__

#include <stdbool.h>
#include <stdint.h>

/*
 * Information passed as the "data" argument to dissectors registered on the
 * "moql.payload" heuristic list. moq-lite frame payloads are opaque, so the
 * application protocol (e.g. hang) is selected by the broadcast path and track
 * name rather than by anything in the payload.
 */
typedef struct _moql_payload_info {
    const char *broadcast_path;     /* NULL if the track is unknown. */
    const char *track_name;         /* NULL if the track is unknown. */
    unsigned    version;            /* moq-lite draft number in use. */

    /*
     * Identifies the group the frame belongs to within this capture: the same
     * value for every frame of a group, and distinct across groups. NULL for
     * datagrams, which always carry a single frame group.
     */
    const void *group_key;
    uint64_t    group_sequence;
    bool        group_sequence_known;
    /* Stream offset of the frame; strictly increasing within a group. */
    uint64_t    frame_offset;
    bool        first_in_group;

    /* The moq-lite level timestamp, in the track's timescale, if any. */
    int64_t     timestamp;
    bool        timestamp_known;
} moql_payload_info_t;

#endif /* __PACKET_MOQ_LITE_H__ */
