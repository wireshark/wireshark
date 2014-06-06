/* packet-esl.c
 * Routines for EtherCAT Switch Link disassembly
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_esl(void);

#if 0
/* XXX: using bitfields is compiler dependent: See README.developer */

typedef union _EslFlagsUnion
{
    struct
    {
        guint16    port7        : 1;
        guint16    port6        : 1;
        guint16    port5        : 1;
        guint16    port4        : 1;
        guint16    port3        : 1;
        guint16    port2        : 1;
        guint16    port1        : 1;
        guint16    port0        : 1;
        guint16    extended     : 1;
	guint16    port11       : 1;
	guint16    port10       : 1;
        guint16    crcError     : 1;
        guint16    alignError   : 1;
        guint16    timeStampEna : 1;
        guint16    port9        : 1;
        guint16    port8        : 1;
    }d;
    struct
    {
        guint8     loPorts      : 1;
        guint8     flagsHiPorts : 1;
    }lo_hi_flags;
    guint   flags;
} EslFlagsUnion;
#endif

#define esl_port7_bitmask        0x0001
#define esl_port6_bitmask        0x0002
#define esl_port5_bitmask        0x0004
#define esl_port4_bitmask        0x0008
#define esl_port3_bitmask        0x0010
#define esl_port2_bitmask        0x0020
#define esl_port1_bitmask        0x0040
#define esl_port0_bitmask        0x0080
#define esl_extended_bitmask     0x0100
#define esl_port11_bitmask       0x0200
#define esl_port10_bitmask       0x0400
#define esl_crcError_bitmask     0x0800
#define esl_alignError_bitmask   0x1000
#define esl_timeStampEna_bitmask 0x2000
#define esl_port9_bitmask        0x4000
#define esl_port8_bitmask        0x8000

#if 0
typedef struct _EslHeader
{
    guint8         eslCookie[6];           /* 01 01 05 10 00 00 */
    EslFlagsUnion  flags;
    guint64        timeStamp;
} EslHeader, *PEslHeader;
#endif


#define SIZEOF_ESLHEADER 16

static dissector_handle_t eth_withoutfcs_handle;
static int esl_enable_dissector = FALSE;

void proto_reg_handoff_esl(void);

/* Define the esl proto */
int proto_esl  = -1;

static int ett_esl           = -1;

static int hf_esl_timestamp  = -1;
static int hf_esl_port       = -1;
static int hf_esl_crcerror   = -1;
static int hf_esl_alignerror = -1;

/* Note: using external tfs strings apparently doesn't work in a plugin */
static const true_false_string flags_yes_no = {
    "yes",
    "no"
};

#if 0
/* XXX: using bitfields is compiler dependent: See README.developer */
static guint16 flags_to_port(guint16 flagsValue) {
    EslFlagsUnion flagsUnion;
    flagsUnion.flags = flagsValue;
    if ( flagsUnion.d.port0 )
        return 0;
    else if ( flagsUnion.d.port1 )
        return 1;
    else if ( flagsUnion.d.port2 )
        return 2;
    else if ( flagsUnion.d.port3 )
        return 3;
    else if ( flagsUnion.d.port4 )
        return 4;
    else if ( flagsUnion.d.port5 )
        return 5;
    else if ( flagsUnion.d.port6 )
        return 6;
    else if ( flagsUnion.d.port7 )
        return 7;
    else if ( flagsUnion.d.port8 )
        return 8;
    else if ( flagsUnion.d.port9 )
        return 9;

    return -1;
}
#endif

static guint16 flags_to_port(guint16 flagsValue) {
    if ( (flagsValue & esl_port0_bitmask) != 0 )
        return 0;
    else if ( (flagsValue & esl_port1_bitmask) != 0 )
        return 1;
    else if ( (flagsValue & esl_port2_bitmask) != 0 )
        return 2;
    else if ( (flagsValue & esl_port3_bitmask) != 0 )
        return 3;
    else if ( (flagsValue & esl_port4_bitmask) != 0 )
        return 4;
    else if ( (flagsValue & esl_port5_bitmask) != 0 )
        return 5;
    else if ( (flagsValue & esl_port6_bitmask) != 0 )
        return 6;
    else if ( (flagsValue & esl_port7_bitmask) != 0 )
        return 7;
    else if ( (flagsValue & esl_port8_bitmask) != 0 )
        return 8;
    else if ( (flagsValue & esl_port9_bitmask) != 0 )
        return 9;
    else if ( (flagsValue & esl_port10_bitmask) != 0 )
        return 10;
    else if ( (flagsValue & esl_port11_bitmask) != 0 )
        return 11;

    return -1;
}

/*esl*/
static void
dissect_esl_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree) {

    proto_item *ti = NULL;
    proto_tree *esl_header_tree;
    gint offset = 0;

    guint esl_length = tvb_reported_length(tvb);
    if ( esl_length >= SIZEOF_ESLHEADER )
    {
        if (tree)
        {
            guint16 flags;

            ti = proto_tree_add_item(tree, proto_esl, tvb, 0, SIZEOF_ESLHEADER, ENC_NA);
            esl_header_tree = proto_item_add_subtree(ti, ett_esl);
            offset+=6;

            flags =  tvb_get_letohs(tvb, offset);
            proto_tree_add_uint(esl_header_tree, hf_esl_port, tvb, offset, 2, flags_to_port(flags));

            proto_tree_add_item(esl_header_tree, hf_esl_crcerror, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(esl_header_tree, hf_esl_alignerror, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            proto_tree_add_item(esl_header_tree, hf_esl_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
    }
}

typedef struct _ref_time_frame_info
{
    frame_data  *fd;
    guint64      esl_ts;
    nstime_t     abs_ts;
    guint32      num;
} ref_time_frame_info;

static ref_time_frame_info ref_time_frame;

static gboolean is_esl_header(tvbuff_t *tvb, gint offset)
{
    return tvb_get_guint8(tvb, offset) == 0x01 &&
        tvb_get_guint8(tvb, offset+1) == 0x01 &&
        tvb_get_guint8(tvb, offset+2) == 0x05 &&
        (tvb_get_guint8(tvb, offset+3) == 0x10 ||tvb_get_guint8(tvb, offset+3) == 0x11)&&
        tvb_get_guint8(tvb, offset+4) == 0x00 &&
        tvb_get_guint8(tvb, offset+5) == 0x00;
}

static void modify_times(tvbuff_t *tvb, gint offset, packet_info *pinfo)
{
    if ( ref_time_frame.fd == NULL )
    {
        ref_time_frame.esl_ts = tvb_get_letoh64(tvb, offset+8);
        ref_time_frame.fd = pinfo->fd;
        ref_time_frame.num = pinfo->fd->num;
        ref_time_frame.abs_ts = pinfo->fd->abs_ts;
    }
    else if ( !pinfo->fd->flags.visited )
    {
        guint64 nsecs = tvb_get_letoh64(tvb, offset+8) - ref_time_frame.esl_ts;
        guint64 secs = nsecs/1000000000;
        nstime_t ts;
        nstime_t ts_delta;

        ts.nsecs = ref_time_frame.abs_ts.nsecs + (int)(nsecs-(secs*1000000000));
        if ( ts.nsecs > 1000000000 )
        {
            ts.nsecs-=1000000000;
            secs++;
        }

        ts.secs = ref_time_frame.abs_ts.secs+(int)secs;
        nstime_delta(&ts_delta, &ts, &pinfo->fd->abs_ts);

        pinfo->fd->abs_ts = ts;
        nstime_add(&pinfo->rel_ts, &ts_delta);
    }
}

static gboolean
dissect_esl_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static gboolean  in_heur    = FALSE;
    gboolean         result;
    tvbuff_t        *next_tvb;
    guint            esl_length = tvb_length(tvb);

    if ( in_heur )
        return FALSE;

    in_heur = TRUE;
    /*TRY */
    {
        if ( ref_time_frame.fd != NULL && !pinfo->fd->flags.visited && pinfo->fd->num <= ref_time_frame.num )
            ref_time_frame.fd = NULL;

        /* Check that there's enough data */
        if ( tvb_length(tvb) < SIZEOF_ESLHEADER )
            return FALSE;

        /* check for Esl frame, this has a unique destination MAC from Beckhoff range
           First 6 bytes must be: 01 01 05 10 00 00 */
        if ( is_esl_header(tvb, 0) )
        {
            dissect_esl_header(tvb, pinfo, tree);
            if ( eth_withoutfcs_handle != NULL )
            {
                next_tvb = tvb_new_subset_remaining(tvb, SIZEOF_ESLHEADER);
                call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
            }
            modify_times(tvb, 0, pinfo);
            result = TRUE;
        }
        else if ( is_esl_header(tvb, esl_length-SIZEOF_ESLHEADER) )
        {
            if ( eth_withoutfcs_handle != NULL )
            {
                next_tvb = tvb_new_subset_length(tvb, 0, esl_length-SIZEOF_ESLHEADER);
                call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
            }
            next_tvb = tvb_new_subset_length(tvb, esl_length-SIZEOF_ESLHEADER, SIZEOF_ESLHEADER);
            dissect_esl_header(next_tvb, pinfo, tree);
            modify_times(tvb, esl_length-SIZEOF_ESLHEADER, pinfo);

            result = TRUE;
        }
        else
        {
            result = FALSE;
        }
    }
    /*CATCH_ALL{
      in_heur = FALSE;
      RETHROW;
      }ENDTRY;*/
    in_heur = FALSE;
    return result;
}

void
proto_register_esl(void) {
    static hf_register_info hf[] = {
        { &hf_esl_port,
          { "Port", "esl.port",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_esl_crcerror,
          { "Crc Error", "esl.crcerror",
            FT_BOOLEAN, 16, TFS(&flags_yes_no), esl_crcError_bitmask,
            NULL, HFILL }
        },
        { &hf_esl_alignerror,
          { "Alignment Error", "esl.alignerror",
            FT_BOOLEAN, 16, TFS(&flags_yes_no), esl_alignError_bitmask,
            NULL, HFILL }
        },
        { &hf_esl_timestamp,
          { "timestamp", "esl.timestamp",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_esl,
    };

    module_t *esl_module;

    proto_esl = proto_register_protocol("EtherCAT Switch Link",
                                        "ESL","esl");

    esl_module = prefs_register_protocol(proto_esl, proto_reg_handoff_esl);

    prefs_register_bool_preference(esl_module, "enable", "Enable dissector",
                                   "Enable this dissector (default is false)",
                                   &esl_enable_dissector);

    proto_register_field_array(proto_esl,hf,array_length(hf));
    proto_register_subtree_array(ett,array_length(ett));

    register_dissector("esl", dissect_esl_header, proto_esl);
}

void
proto_reg_handoff_esl(void) {
    static gboolean initialized = FALSE;

    if (!initialized) {
        eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
        heur_dissector_add("eth", dissect_esl_heur, proto_esl);
        initialized = TRUE;
    }
    proto_set_decoding(proto_esl, esl_enable_dissector);
}
