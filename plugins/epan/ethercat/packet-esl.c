/* packet-esl.c
 * Routines for EtherCAT Switch Link disassembly
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_esl(void);

#if 0
/* XXX: using bitfields is compiler dependent: See README.developer */

typedef union _EslFlagsUnion
{
    struct
    {
        uint16_t   port7        : 1;
        uint16_t   port6        : 1;
        uint16_t   port5        : 1;
        uint16_t   port4        : 1;
        uint16_t   port3        : 1;
        uint16_t   port2        : 1;
        uint16_t   port1        : 1;
        uint16_t   port0        : 1;
        uint16_t   extended     : 1;
        uint16_t   port11       : 1;
        uint16_t   port10       : 1;
        uint16_t   alignError   : 1;
        uint16_t   crcError     : 1;
        uint16_t   timeStampEna : 1;
        uint16_t   port9        : 1;
        uint16_t   port8        : 1;
    }d;
    struct
    {
        uint8_t    loPorts      : 1;
        uint8_t    flagsHiPorts : 1;
    }lo_hi_flags;
    unsigned   flags;
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
#define esl_alignError_bitmask   0x0800
#define esl_crcError_bitmask     0x1000
#define esl_timeStampEna_bitmask 0x2000
#define esl_port9_bitmask        0x4000
#define esl_port8_bitmask        0x8000

#if 0
typedef struct _EslHeader
{
    uint8_t        eslCookie[6];           /* 01 01 05 10 00 00 */
    EslFlagsUnion  flags;
    uint64_t       timeStamp;
} EslHeader, *PEslHeader;
#endif


#define SIZEOF_ESLHEADER 16

static dissector_handle_t eth_withoutfcs_handle;

void proto_reg_handoff_esl(void);

/* Define the esl proto */
int proto_esl;

static int ett_esl;

static int hf_esl_timestamp;
static int hf_esl_port;
static int hf_esl_crcerror;
static int hf_esl_alignerror;

/* Note: using external tfs strings apparently doesn't work in a plugin */
static const true_false_string flags_yes_no = {
    "yes",
    "no"
};

#if 0
/* XXX: using bitfields is compiler dependent: See README.developer */
static uint16_t flags_to_port(uint16_t flagsValue) {
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

static uint16_t flags_to_port(uint16_t flagsValue) {
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
static int
dissect_esl_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {

    proto_item *ti = NULL;
    proto_tree *esl_header_tree;
    int offset = 0;

    unsigned esl_length = tvb_reported_length(tvb);
    if ( esl_length >= SIZEOF_ESLHEADER )
    {
        if (tree)
        {
            uint16_t flags;

            ti = proto_tree_add_item(tree, proto_esl, tvb, 0, SIZEOF_ESLHEADER, ENC_NA);
            esl_header_tree = proto_item_add_subtree(ti, ett_esl);
            offset+=6;

            flags =  tvb_get_letohs(tvb, offset);
            proto_tree_add_uint(esl_header_tree, hf_esl_port, tvb, offset, 2, flags_to_port(flags));

            proto_tree_add_item(esl_header_tree, hf_esl_alignerror, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(esl_header_tree, hf_esl_crcerror, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            offset+=2;

            proto_tree_add_item(esl_header_tree, hf_esl_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
    }
    return tvb_captured_length(tvb);
}

typedef struct _ref_time_frame_info
{
    frame_data  *fd;
    uint64_t     esl_ts;
    nstime_t     abs_ts;
    uint32_t     num;
} ref_time_frame_info;

static ref_time_frame_info ref_time_frame;

static bool is_esl_header(tvbuff_t *tvb, int offset)
{
    return tvb_get_uint8(tvb, offset) == 0x01 &&
        tvb_get_uint8(tvb, offset+1) == 0x01 &&
        tvb_get_uint8(tvb, offset+2) == 0x05 &&
        (tvb_get_uint8(tvb, offset+3) == 0x10 ||tvb_get_uint8(tvb, offset+3) == 0x11)&&
        tvb_get_uint8(tvb, offset+4) == 0x00 &&
        tvb_get_uint8(tvb, offset+5) == 0x00;
}

static void modify_times(tvbuff_t *tvb, int offset, packet_info *pinfo)
{
    if ( ref_time_frame.fd == NULL )
    {
        ref_time_frame.esl_ts = tvb_get_letoh64(tvb, offset+8);
        ref_time_frame.fd = pinfo->fd;
        ref_time_frame.num = pinfo->num;
        ref_time_frame.abs_ts = pinfo->abs_ts;
    }
    else if ( !pinfo->fd->visited )
    {
        uint64_t nsecs = tvb_get_letoh64(tvb, offset+8) - ref_time_frame.esl_ts;
        uint64_t secs = nsecs/1000000000;
        nstime_t ts;
        nstime_t ts_delta;

        ts.nsecs = ref_time_frame.abs_ts.nsecs + (int)(nsecs-(secs*1000000000));
        if ( ts.nsecs > 1000000000 )
        {
            ts.nsecs-=1000000000;
            secs++;
        }

        ts.secs = ref_time_frame.abs_ts.secs+(int)secs;
        nstime_delta(&ts_delta, &ts, &pinfo->abs_ts);

        pinfo->abs_ts = ts;
        pinfo->fd->abs_ts = ts;
        nstime_add(&pinfo->rel_ts, &ts_delta);
    }
}

static bool
dissect_esl_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static bool      in_heur    = false;
    bool             result;
    tvbuff_t        *next_tvb;
    unsigned         esl_length = tvb_captured_length(tvb);

    if ( in_heur )
        return false;

    in_heur = true;
    /*TRY */
    {
        if ( ref_time_frame.fd != NULL && !pinfo->fd->visited && pinfo->num <= ref_time_frame.num )
            ref_time_frame.fd = NULL;

        /* Check that there's enough data */
        if ( esl_length < SIZEOF_ESLHEADER )
            return false;

        /* check for Esl frame, this has a unique destination MAC from Beckhoff range
           First 6 bytes must be: 01 01 05 10 00 00 */
        if ( is_esl_header(tvb, 0) )
        {
            dissect_esl_header(tvb, pinfo, tree, data);
            if ( eth_withoutfcs_handle != NULL )
            {
                next_tvb = tvb_new_subset_remaining(tvb, SIZEOF_ESLHEADER);
                call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
            }
            modify_times(tvb, 0, pinfo);
            result = true;
        }
        else if ( is_esl_header(tvb, esl_length-SIZEOF_ESLHEADER) )
        {
            if ( eth_withoutfcs_handle != NULL )
            {
                next_tvb = tvb_new_subset_length(tvb, 0, esl_length-SIZEOF_ESLHEADER);
                call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
            }
            next_tvb = tvb_new_subset_length(tvb, esl_length-SIZEOF_ESLHEADER, SIZEOF_ESLHEADER);
            dissect_esl_header(next_tvb, pinfo, tree, data);
            modify_times(tvb, esl_length-SIZEOF_ESLHEADER, pinfo);

            result = true;
        }
        else
        {
            result = false;
        }
    }
    /*CATCH_ALL{
      in_heur = false;
      RETHROW;
      }ENDTRY;*/
    in_heur = false;
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

    static int *ett[] = {
        &ett_esl,
    };

    module_t *esl_module;

    proto_esl = proto_register_protocol("EtherCAT Switch Link",
                                        "ESL","esl");

    esl_module = prefs_register_protocol_obsolete(proto_esl);

    prefs_register_obsolete_preference(esl_module, "enable");

    proto_register_field_array(proto_esl,hf,array_length(hf));
    proto_register_subtree_array(ett,array_length(ett));

    register_dissector("esl", dissect_esl_header, proto_esl);
}

void
proto_reg_handoff_esl(void) {
    static bool initialized = false;

    if (!initialized) {
        eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_esl);
        heur_dissector_add("eth", dissect_esl_heur, "EtherCAT over Ethernet", "esl_eth", proto_esl, HEURISTIC_DISABLE);
        initialized = true;
    }
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
