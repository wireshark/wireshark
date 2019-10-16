/* packet-exablaze.c
 * Routines for dissection of Exablaze trailers
 * Copyright 2018 Exablaze
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>

void proto_register_exablaze(void);
void proto_reg_handoff_exablaze(void);

static int proto_exablaze = -1;

static int hf_exablaze_original_fcs = -1;
static int hf_exablaze_device = -1;
static int hf_exablaze_port = -1;
static int hf_exablaze_timestamp = -1;
static int hf_exablaze_timestamp_integer = -1;
static int hf_exablaze_timestamp_fractional = -1;

static gint ett_exablaze = -1;
static gint ett_exablaze_timestamp = -1;

static int
dissect_exablaze(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *exablaze_tree;
    proto_tree *timestamp_tree;

    guint trailer_length;
    guint fcs_length;
    guint offset;
    gboolean trailer_found;

    guint8 device;
    guint8 port;
    guint32 timestamp_sec;
    guint64 timestamp_frac;

    nstime_t timestamp;
    double timestamp_frac_double;
    struct tm *tm;

    trailer_length = tvb_reported_length(tvb);

    if (trailer_length != tvb_captured_length(tvb)) {
        /* The heuristics require the whole trailer to be captured */
        return 0;
    }

    /* Try matching with and without FCS */
    trailer_found = FALSE;
    for (fcs_length = 0; fcs_length <= 4; fcs_length += 4)
    {
        if (trailer_length < fcs_length + 16)
            continue;

        offset = trailer_length - fcs_length - 16;

        device = tvb_get_guint8(tvb, offset + 4);
        port = tvb_get_guint8(tvb, offset + 5);
        timestamp_sec = tvb_get_ntohl(tvb, offset + 6);
        timestamp_frac = tvb_get_ntoh40(tvb, offset + 10);

        /* If the capture time and timestamp differ by more than a week,
         * then this is probably not a valid Exablaze trailer */
        if (timestamp_sec > (guint)pinfo->abs_ts.secs) {
            if (timestamp_sec - pinfo->abs_ts.secs > 604800)
                continue;
        } else {
            if (pinfo->abs_ts.secs - timestamp_sec > 604800)
                continue;
        }

        trailer_found = TRUE;
        break;
    }

    if (!trailer_found)
        return 0;

    /* Fractional part is a 40 bit binary fraction of a second */
    timestamp.secs = timestamp_sec;
    timestamp_frac_double = ldexp((double)timestamp_frac, -40);
    timestamp.nsecs = (int)(timestamp_frac_double * 1000000000);

    ti = proto_tree_add_item(tree, proto_exablaze, tvb, offset, 16, ENC_NA);
    proto_item_append_text(ti, ", Device: %u, Port: %u, Timestamp: ",
            device, port);

    tm = localtime(&timestamp.secs);
    if (tm)
        proto_item_append_text(ti, "%02u:%02u:%02.12f",
                tm->tm_hour, tm->tm_min, tm->tm_sec + timestamp_frac_double);
    else
        proto_item_append_text(ti, "<Not representable>");

    exablaze_tree = proto_item_add_subtree(ti, ett_exablaze);
    proto_tree_add_item(exablaze_tree, hf_exablaze_original_fcs, tvb,
            offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(exablaze_tree, hf_exablaze_device, tvb,
            offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exablaze_tree, hf_exablaze_port, tvb,
            offset + 5, 1, ENC_BIG_ENDIAN);

    ti = proto_tree_add_time(exablaze_tree, hf_exablaze_timestamp, tvb,
            offset + 6, 9, &timestamp);
    timestamp_tree = proto_item_add_subtree(ti, ett_exablaze_timestamp);

    proto_tree_add_item(timestamp_tree, hf_exablaze_timestamp_integer, tvb,
            offset + 6, 4, ENC_BIG_ENDIAN);
    proto_tree_add_double_format_value(timestamp_tree,
            hf_exablaze_timestamp_fractional, tvb, offset + 10, 5,
            timestamp_frac_double, "%.12f", timestamp_frac_double);

    return offset + 16;
}

void
proto_register_exablaze(void)
{
    static hf_register_info hf[] = {
        {
            &hf_exablaze_original_fcs,
            {
                "Original FCS", "exablaze.original_fcs",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_exablaze_device,
            {
                "Device ID", "exablaze.device",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_exablaze_port,
            {
                "Port", "exablaze.port",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_exablaze_timestamp,
            {
                "Timestamp", "exablaze.timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL
            }
        },
        {   &hf_exablaze_timestamp_integer,
            {
                "Seconds since epoch", "exablaze.timestamp.seconds",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        {   &hf_exablaze_timestamp_fractional,
            {
                "Fractional seconds",
                "exablaze.timestamp.fractional_seconds",
                FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL
            }
        }
    };

    static gint *ett[] = {
        &ett_exablaze,
        &ett_exablaze_timestamp
    };

    proto_exablaze = proto_register_protocol("Exablaze trailer", "Exablaze",
            "exablaze");
    proto_register_field_array(proto_exablaze, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_exablaze(void)
{
    heur_dissector_add("eth.trailer", dissect_exablaze, "Exablaze trailer",
            "exablaze_eth", proto_exablaze, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
