/* packet-ifcp.c
 * Routines for iFCP dissection
 * RFC 3821, RFC 3643
 *
 * Copyright 2005   Aboo Valappil     (valappil_aboo@emc.com)
 *           2006 ronnie sahlberg   major refactoring
 *
 *
 * Significantly based on packet-fcip.c by
 *       Copyright 2001, Dinesh G Dutt (ddutt@cisco.com)
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

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"
#include "packet-fc.h"

void proto_register_ifcp(void);
void proto_reg_handoff_ifcp(void);

#define iFCP_ENCAP_HEADER_LEN     28
#define iFCP_MIN_HEADER_LEN       16 /* upto frame len field */

typedef enum {
    iFCP_EOFn    = 0x41,
    iFCP_EOFt    = 0x42,
    iFCP_EOFrt   = 0x44,
    iFCP_EOFdt   = 0x46,
    iFCP_EOFni   = 0x49,
    iFCP_EOFdti  = 0x4E,
    iFCP_EOFrti  = 0x4F,
    iFCP_EOFa    = 0x50
} ifcp_eof_t;

typedef enum {
    iFCP_SOFf    = 0x28,
    iFCP_SOFi4   = 0x29,
    iFCP_SOFi2   = 0x2D,
    iFCP_SOFi3   = 0x2E,
    iFCP_SOFn4   = 0x31,
    iFCP_SOFn2   = 0x35,
    iFCP_SOFn3   = 0x36,
    iFCP_SOFc4   = 0x39
} ifcp_sof_t;

typedef enum {
    FCENCAP_PROTO_FCIP = 1,
    FCENCAP_PROTO_iFCP = 2
} fcencap_proto_t;

static const value_string ifcp_eof_vals[] = {
    {iFCP_EOFn,   "EOFn" },
    {iFCP_EOFt,   "EOFt" },
    {iFCP_EOFrt,  "EOFrt" },
    {iFCP_EOFdt,  "EOFdt" },
    {iFCP_EOFni,  "EOFni" },
    {iFCP_EOFdti, "EOFdti" },
    {iFCP_EOFrti, "EOFrti" },
    {iFCP_EOFa,   "EOFa" },
    {0, NULL},
};

static const value_string ifcp_sof_vals[] = {
    {iFCP_SOFf,  "SOFf" },
    {iFCP_SOFi4, "SOFi4" },
    {iFCP_SOFi2, "SOFi2" },
    {iFCP_SOFi3, "SOFi3" },
    {iFCP_SOFn4, "SOFn4" },
    {iFCP_SOFn2, "SOFn2" },
    {iFCP_SOFn3, "SOFn3" },
    {iFCP_SOFc4, "SOFc4" },
    {0, NULL},
};

static const value_string fcencap_proto_vals[] = {
    {FCENCAP_PROTO_iFCP, "iFCP"},
    {FCENCAP_PROTO_iFCP, "iFCP"},
    {0, NULL},
};

/* RFC 4172 section 5.3.1 shows a chart of the iFCP encapsulated Header Format.
 * It says that bytes 4-7 MUST be zeros.  In reality most vendors are putting
 * some information in these 4 bytes, particularly Nishon.
 */
static const guint8 ifcp_header_4_bytes[4] = {
    0x02, 0x01, 0xFD, 0xFE
};

static int proto_ifcp                = -1;

static int hf_ifcp_protocol          = -1;
static int hf_ifcp_protocol_c        = -1;
static int hf_ifcp_version           = -1;
static int hf_ifcp_version_c         = -1;
static int hf_ifcp_encap_flags_c     = -1;
static int hf_ifcp_framelen          = -1;
static int hf_ifcp_framelen_c        = -1;
static int hf_ifcp_tsec              = -1;
static int hf_ifcp_tusec             = -1;
static int hf_ifcp_encap_crc         = -1;
static int hf_ifcp_sof               = -1;
static int hf_ifcp_sof_c             = -1;
static int hf_ifcp_eof               = -1;
static int hf_ifcp_eof_c             = -1;
static int hf_ifcp_ls_command_acc    = -1;
static int hf_ifcp_flags             = -1;
static int hf_ifcp_flags_ses         = -1;
static int hf_ifcp_flags_trp         = -1;
static int hf_ifcp_flags_spc         = -1;
static int hf_ifcp_common_flags      = -1;
static int hf_ifcp_common_flags_crcv = -1;

static int ett_ifcp              = -1;
static int ett_ifcp_sof          = -1;
static int ett_ifcp_eof          = -1;
static int ett_ifcp_flags        = -1;
static int ett_ifcp_common_flags = -1;
static int ett_ifcp_protocol     = -1;
static int ett_ifcp_version      = -1;
static int ett_ifcp_frame_len    = -1;

static gboolean ifcp_desegment    = TRUE;

static dissector_handle_t ifcp_handle = NULL;
static dissector_handle_t fc_handle   = NULL;


/* This function checks the first 16 bytes of the "header" that it looks sane
 * and returns TRUE if this looks like iFCP and FALSE if it doesn't.
 */
static gboolean
ifcp_header_test(tvbuff_t *tvb, int offset)
{
    guint16 flen, flen1;

    /* we can only do this test if we have 16 bytes or more */
    if(tvb_captured_length_remaining(tvb, offset)<iFCP_MIN_HEADER_LEN){
        return FALSE;
    }

    /*
    * As per the iFCP standard, the following tests must PASS:
    * 1)  Frame Length field validation -- 15 < Frame Length < 545;
    * 2)  Comparison of Frame Length field to its ones complement; and
    * 3)  A valid EOF is found in the word preceding the start of the next
    *     iFCP header as indicated by the Frame Length field, to be tested
    *     as follows:
    *     1)  Bits 24-31 and 16-23 contain identical legal EOF values (the
    *         list of legal EOF values is in the FC Frame Encapsulation
    *         [21]); and
    *     2)  Bits 8-15 and 0-7 contain the ones complement of the EOF
    *         value found in bits 24-31.
    *
    * As per the iFCP standard, in addition, at least 3 of the following
    * set of tests must be performed to identify that we've located the
    * start of an iFCP frame.
    * a)  Protocol# ones complement field (1 test);
    * b)  Version ones complement field (1 test);
    * c)  Replication of encapsulation word 0 in word 1 (1 test);
    * d)  Reserved field and its ones complement (2 tests);
    * e)  Flags field and its ones complement (2 tests);
    *    f)  CRC field is equal to zero (1 test); (DON'T DO THIS TEST!)
    * g)  SOF fields and ones complement fields (4 tests);
    * h)  Format and values of FC header (1 test);
    * i)  CRC of FC Frame (2 tests);
    * j)  FC Frame Encapsulation header information in the next iFCP Frame
    *     (1 test).
    *
    * At least 3 of the 16 tests listed above SHALL be performed. Failure
    * of any of the above tests actually performed SHALL indicate an
    * encapsulation error and the FC Frame SHALL NOT be forwarded on to
    * the FC Entity.
    */


    /*
     * Tests a, b and c
     */
    if(tvb_memeql(tvb, offset, ifcp_header_4_bytes, 4) != 0){
        return FALSE;
        }

    /* check the frame length */
    flen=tvb_get_ntohs(tvb, offset+12)&0x03FF;
    if((flen < 15) || (flen > 545)){
        return FALSE;
    }

    /* check the complement of the frame length */
    flen1=tvb_get_ntohs(tvb, offset+14)&0x03FF;
    if(flen!=((~flen1)&0x03FF)){
        return FALSE;
    }


    /* this should be good enough for our heuristics */
    return TRUE;
}


#define IFCP_FLAGS_SES      0x04
#define IFCP_FLAGS_TRP      0x02
#define IFCP_FLAGS_SPC      0x01

static const true_false_string ifcp_flags_ses_tfs = {
    "This is a SESSION CONTROL FRAME",
    "This is a normal frame"
};

static const true_false_string ifcp_flags_trp_tfs = {
    "Address TRANSPARENT Mode Enabled",
    "Address TRANSLATION Mode Enabled"
};

static const true_false_string ifcp_flags_spc_tfs = {
    "This frame requires SPECIAL PROCESSING",
    "This is a normal frame"
};

static int
dissect_ifcpflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    static const int * flags[] = {
        &hf_ifcp_flags_ses,
        &hf_ifcp_flags_trp,
        &hf_ifcp_flags_spc,
        NULL
    };
    proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ifcp_flags,
                           ett_ifcp_flags, flags, ENC_BIG_ENDIAN);

    offset++;
    return offset;
}


#define IFCP_COMMON_FLAGS_CRCV      0x04

static void
dissect_commonflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    static const int * flags[] = {
        &hf_ifcp_common_flags_crcv,
        NULL
    };

    proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ifcp_common_flags,
                           ett_ifcp_common_flags, flags, ENC_BIG_ENDIAN);
}

static int
dissect_ifcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    gint        offset = 0, frame_len = 0;
    guint8      sof    = 0, eof = 0;
    proto_item *ti;
    proto_tree *tree           = NULL;
    tvbuff_t   *next_tvb;
    guint8      protocol;
    proto_tree *protocol_tree  = NULL;
    proto_tree *version_tree   = NULL;
    proto_tree *frame_len_tree = NULL;
    proto_tree *sof_tree       = NULL;
    proto_tree *eof_tree       = NULL;
    fc_data_t   fc_data;

    /* verify we have a full header  (do we need to do this? */
    if(tvb_captured_length(tvb)<iFCP_ENCAP_HEADER_LEN){
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iFCP");

    frame_len = (tvb_get_ntohs (tvb, offset+12) & 0x03FF)*4;


        if (parent_tree) {
            if (tvb_bytes_exist (tvb, offset, frame_len-4)) {
                sof = tvb_get_guint8 (tvb, offset+iFCP_ENCAP_HEADER_LEN);
                eof = tvb_get_guint8 (tvb, offset+frame_len - 4);

                ti = proto_tree_add_protocol_format (parent_tree, proto_ifcp, tvb, offset,
                                                     iFCP_ENCAP_HEADER_LEN,
                                                     "iFCP (%s/%s)",
                                                     val_to_str (sof, ifcp_sof_vals,
                                                                 "0x%x"),
                                                     val_to_str (eof, ifcp_eof_vals,
                                                                 "0x%x"));
            } else {
                sof = tvb_get_guint8 (tvb, offset+iFCP_ENCAP_HEADER_LEN);

                ti = proto_tree_add_protocol_format (parent_tree, proto_ifcp, tvb, offset,
                                                     iFCP_ENCAP_HEADER_LEN,
                                                     "iFCP (%s/%s)",
                                                     val_to_str (sof, ifcp_sof_vals,
                                                                 "0x%x"),
                                                     "NA");
            }
            tree = proto_item_add_subtree (ti, ett_ifcp);
        }



    /* The Common FC Encap header */
    /* protocol */
    protocol = tvb_get_guint8 (tvb, offset);
    ti=proto_tree_add_item(tree, hf_ifcp_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
    protocol_tree=proto_item_add_subtree(ti, ett_ifcp_protocol);

    offset++;

    /* version */
    ti=proto_tree_add_item(tree, hf_ifcp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    version_tree=proto_item_add_subtree(ti, ett_ifcp_version);
    offset++;

    /* protocol complement */
    proto_tree_add_item(protocol_tree, hf_ifcp_protocol_c, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* version complement */
    proto_tree_add_item(version_tree, hf_ifcp_version_c, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* 4 reserved bytes */
    offset+=4;

    /* iFCP specific fields */
    if(protocol==FCENCAP_PROTO_iFCP){
        /* LS_COMMAND_ACC */
        proto_tree_add_item(tree, hf_ifcp_ls_command_acc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* iFCP Flags */
        offset=dissect_ifcpflags(tvb, offset, tree);

        /* SOF */
        ti=proto_tree_add_item(tree, hf_ifcp_sof, tvb, offset, 1, ENC_BIG_ENDIAN);
        sof_tree=proto_item_add_subtree(ti, ett_ifcp_sof);
        offset++;

        /* EOF */
        ti=proto_tree_add_item(tree, hf_ifcp_eof, tvb, offset, 1, ENC_BIG_ENDIAN);
        eof_tree=proto_item_add_subtree(ti, ett_ifcp_eof);
        offset++;
    } else {
        offset+=4;
        sof_tree=tree; /* better than nothing */
        eof_tree=tree;
    }

    /* Common Flags */
    dissect_commonflags(tvb, offset, tree);

    /* frame len */
    ti=proto_tree_add_item(tree, hf_ifcp_framelen, tvb, offset, 2, ENC_BIG_ENDIAN);
    frame_len_tree=proto_item_add_subtree(ti, ett_ifcp_frame_len);
    offset+=2;

    /* complement of flags and frame len */
    proto_tree_add_item(frame_len_tree, hf_ifcp_encap_flags_c, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(frame_len_tree, hf_ifcp_framelen_c, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* timestamp seconds */
    proto_tree_add_item(tree, hf_ifcp_tsec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* timestamp fractions */
    proto_tree_add_item(tree, hf_ifcp_tusec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* crc */
    proto_tree_add_item(tree, hf_ifcp_encap_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;


    /* FC SOF/-SOF */
    proto_tree_add_item(sof_tree, hf_ifcp_sof, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(sof_tree, hf_ifcp_sof, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(sof_tree, hf_ifcp_sof_c, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(sof_tree, hf_ifcp_sof_c, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* FC EOF/-EOF */
    if(tvb_bytes_exist(tvb, frame_len-4, 4)) {
        proto_tree_add_item(eof_tree, hf_ifcp_eof, tvb, frame_len-4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(eof_tree, hf_ifcp_eof, tvb, frame_len-3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(eof_tree, hf_ifcp_eof_c, tvb, frame_len-2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(eof_tree, hf_ifcp_eof_c, tvb, frame_len-1, 1, ENC_BIG_ENDIAN);
        }


    /* Call the FC Dissector if this is carrying an FC frame */
    /* Set the SOF/EOF flags in the packet_info header */
    fc_data.sof_eof = 0;

    switch(sof){
    case iFCP_SOFi3:
    case iFCP_SOFi2:
    case iFCP_SOFi4:
        fc_data.sof_eof = FC_DATA_SOF_FIRST_FRAME;
        break;
    case iFCP_SOFf:
        fc_data.sof_eof = FC_DATA_SOF_SOFF;
        break;
    default:
        if(sof){
            if (eof != iFCP_EOFn) {
                fc_data.sof_eof |= FC_DATA_EOF_LAST_FRAME;
                    } else if (eof != iFCP_EOFt) {
                fc_data.sof_eof |= FC_DATA_EOF_INVALID;
            }
        }
    }

    next_tvb=tvb_new_subset_length(tvb, offset, frame_len-offset-4);
    fc_data.ethertype = 0;

    if(fc_handle){
        call_dissector_with_data(fc_handle, next_tvb, pinfo, parent_tree, &fc_data);
    } else {
        call_data_dissector(next_tvb, pinfo, parent_tree);
    }

    return tvb_captured_length(tvb);
}

static guint
get_ifcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint pdu_len;

    if(!ifcp_header_test(tvb, offset)){
        return 0;
    }

    pdu_len=(tvb_get_ntohs(tvb, offset+12)&0x03FF)*4;
    return pdu_len;
}

static int
dissect_ifcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, parent_tree, ifcp_desegment, iFCP_MIN_HEADER_LEN, get_ifcp_pdu_len, dissect_ifcp_pdu, data);
    return tvb_captured_length(tvb);
}


/* This is called for those sessions where we have explicitly said
 * this to be iFCP using "Decode As..."
 * In this case we will not check the port number for sanity and just
 * do as the user said.
 */
static int
dissect_ifcp_handle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    return dissect_ifcp(tvb, pinfo, tree, data);
}

static gboolean
dissect_ifcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if(!ifcp_header_test(tvb, 0)){
        return FALSE;
    }

    dissect_ifcp(tvb, pinfo, tree, data);

    /* our heuristics are so strong that if the heuristics above passed
     * and the dissection of the pdu did not cause any exceptions
     * then we can set this as our conversation dissector
     */
    if(ifcp_handle){
        conversation_t* ifcp_conv;

        ifcp_conv=find_or_create_conversation(pinfo);
        /* XXX why does this not work? it doesn't result in dissect_ifcp_handle being called    look into later*/
        conversation_set_dissector(ifcp_conv, ifcp_handle);
    }

    return TRUE;
}

void
proto_register_ifcp (void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_ifcp_protocol,
          {"Protocol", "ifcp.encap.proto", FT_UINT8, BASE_DEC, VALS(fcencap_proto_vals), 0,
           NULL, HFILL }},
        { &hf_ifcp_protocol_c,
          {"Protocol (1's Complement)", "ifcp.encap.protoc", FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_ifcp_version,
          {"Version", "ifcp.encap.version", FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_ifcp_version_c,
          {"Version (1's Complement)", "ifcp.encap.versionc", FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_ifcp_encap_flags_c,
          {"iFCP Encapsulation Flags (1's Complement)", "ifcp.encap_flagsc", FT_UINT8, BASE_HEX, NULL, 0xFC,
           NULL, HFILL}},
        { &hf_ifcp_framelen,
          {"Frame Length (in Words)", "ifcp.encap.framelen", FT_UINT16, BASE_DEC, NULL, 0x03FF,
           NULL, HFILL}},
        { &hf_ifcp_framelen_c,
          {"Frame Length (1's Complement)", "ifcp.encap.framelenc", FT_UINT16, BASE_DEC, NULL, 0x03FF,
           NULL, HFILL}},
        { &hf_ifcp_tsec,
          {"Time (secs)", "ifcp.encap.tsec", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_ifcp_tusec,
          {"Time (fraction)", "ifcp.encap.tusec", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_ifcp_encap_crc,
          {"CRC", "ifcp.encap.crc", FT_UINT32, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_ifcp_sof,
          {"SOF", "ifcp.sof", FT_UINT8, BASE_HEX, VALS (ifcp_sof_vals), 0,
           NULL, HFILL}},
        { &hf_ifcp_eof,
          {"EOF", "ifcp.eof", FT_UINT8, BASE_HEX, VALS (ifcp_eof_vals), 0,
           NULL, HFILL}},
        { &hf_ifcp_sof_c,
          {"SOF Compliment", "ifcp.sof_c", FT_UINT8, BASE_HEX, NULL , 0,
           NULL, HFILL}},
        { &hf_ifcp_eof_c,
          {"EOF Compliment", "ifcp.eof_c", FT_UINT8, BASE_HEX, NULL , 0,
           NULL, HFILL}},
        { &hf_ifcp_ls_command_acc,
          {"Ls Command Acc", "ifcp.ls_command_acc", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_ifcp_common_flags,
          {"Flags", "ifcp.common_flags", FT_UINT8, BASE_HEX , NULL, 0xfc,
           NULL, HFILL }},
        { &hf_ifcp_common_flags_crcv,
          {"CRC", "ifcp.common_flags.crcv", FT_BOOLEAN, 8, TFS(&tfs_valid_not_valid), IFCP_COMMON_FLAGS_CRCV,
           "Is the CRC field valid?", HFILL }},
        { &hf_ifcp_flags,
          {"iFCP Flags", "ifcp.flags", FT_UINT8, BASE_HEX , NULL, 0,
           NULL, HFILL }},
        { &hf_ifcp_flags_ses,
          {"SES", "ifcp.flags.ses", FT_BOOLEAN, 8, TFS(&ifcp_flags_ses_tfs), IFCP_FLAGS_SES,
           "Is this a Session control frame", HFILL }},
        { &hf_ifcp_flags_trp,
          {"TRP", "ifcp.flags.trp", FT_BOOLEAN, 8, TFS(&ifcp_flags_trp_tfs), IFCP_FLAGS_TRP,
           "Is address transparent mode enabled", HFILL }},
        { &hf_ifcp_flags_spc,
          {"SPC", "ifcp.flags.spc", FT_BOOLEAN, 8, TFS(&ifcp_flags_spc_tfs), IFCP_FLAGS_SPC,
           "Is frame part of link service", HFILL }},
    };

    static gint *ett[] = {
        &ett_ifcp,
        &ett_ifcp_sof,
        &ett_ifcp_eof,
        &ett_ifcp_protocol,
        &ett_ifcp_version,
    &ett_ifcp_frame_len,
        &ett_ifcp_flags,
        &ett_ifcp_common_flags,
    };

    module_t *ifcp_module;

    /* Register the protocol name and description */
    proto_ifcp = proto_register_protocol("iFCP", "iFCP", "ifcp");

    proto_register_field_array(proto_ifcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ifcp_module = prefs_register_protocol(proto_ifcp, NULL);
    prefs_register_bool_preference(ifcp_module,
                                   "desegment",
                                   "Reassemble iFCP messages spanning multiple TCP segments",
                                   "Whether the iFCP dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &ifcp_desegment);
    prefs_register_obsolete_preference(ifcp_module, "target_port");
}

void
proto_reg_handoff_ifcp (void)
{
    heur_dissector_add("tcp", dissect_ifcp_heur, "iFCP over TCP", "ifcp_tcp", proto_ifcp, HEURISTIC_ENABLE);

    ifcp_handle = create_dissector_handle(dissect_ifcp_handle, proto_ifcp);
    dissector_add_for_decode_as("tcp.port", ifcp_handle);

    fc_handle = find_dissector_add_dependency("fc_ifcp", proto_ifcp);
}

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
