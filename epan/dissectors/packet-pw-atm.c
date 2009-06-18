/* packet-pw-atm.c
 * Routines for ATM PW dissection: it should be conform to RFC 4717.
 *
 * Copyright 2009 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
    DONE:
        - ATM N-to-One Cell Mode (with CW)
        - ATM N-to-One Cell Mode (no CW)
    TODO:
        - ATM One-to-One Cell Mode
        - ATM AAL5 SDU Mode
        - ATM AAL5 PDU Mode

        Please pick an item from the TODO list, move code out of #if 0
        (see below) and implement a dissector for the given encapsulation
        mode.  The N-to-One Cell Mode is the only mandatory encap
        mode.  One-to-One/SDU/PDU modes are optional.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#include "packet-mpls.h"

static gint proto_pw_atm_n2o_cw = -1;
static gint proto_pw_atm_n2o_nocw = -1;
#if 0
static gint proto_pw_atm_o2o_cw = -1;
static gint proto_pw_atm_o2o_nocw = -1;
static gint proto_pw_atm_aal5_pdu_cw = -1;
static gint proto_pw_atm_aal5_pdu_nocw = -1;
static gint proto_pw_atm_aal5_sdu_cw = -1;
static gint proto_pw_atm_aal5_sdu_nocw = -1;
#endif

static gint ett_pw_atm = -1;

static int hf_pw_atm_n2o_cw = -1;
static int hf_pw_atm_n2o_cw_flags = -1;
static int hf_pw_atm_n2o_cw_length = -1;
static int hf_pw_atm_n2o_cw_sequence_number = -1;
static int hf_pw_atm_n2o_nocw = -1;
#if 0
static int hf_pw_atm_o2o_cw = -1;
static int hf_pw_atm_o2o_cw_sequence_number = -1;
static int hf_pw_atm_o2o_cw_flags = -1;
static int hf_pw_atm_o2o_cw_flags_m = -1;
static int hf_pw_atm_o2o_cw_flags_v = -1;
static int hf_pw_atm_o2o_cw_flags_res = -1;
static int hf_pw_atm_o2o_cw_flags_pti = -1;
static int hf_pw_atm_o2o_cw_flags_c = -1;
static int hf_pw_atm_o2o_nocw = -1;
static int hf_pw_atm_aal5_pdu_cw = -1;
static int hf_pw_atm_aal5_pdu_cw_sequence_number = -1;
static int hf_pw_atm_aal5_pdu_nocw = -1;
static int hf_pw_atm_aal5_sdu_cw = -1;
static int hf_pw_atm_aal5_sdu_cw_sequence_number = -1;
static int hf_pw_atm_aal5_sdu_nocw = -1;
#endif

static dissector_handle_t data_h;
static dissector_handle_t atm_h;

/* ATM One-to-One Cell Mode bits in "ATM Specific" CW field */
#define PW_ATM_O2O_CW_M   0x80
#define PW_ATM_O2O_CW_V   0x40
#define PW_ATM_O2O_CW_RES 0x30
#define PW_ATM_O2O_CW_PTI 0x0E
#define PW_ATM_O2O_CW_C   0x01

static void
dissect_pw_atm_n2o_cw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree *pw_atm_tree = NULL;
        proto_item *ti = NULL;
        tvbuff_t *next_tvb = NULL;
        guint16 sequence_number = 0;
        guint8 flags = 0;
        guint8 length = 0;
        guint16 ncells = 0;
        guint16 remains = 0;
        guint16 i = 0;

        if (tvb_reported_length_remaining(tvb, 0) < 4) {
                if (tree)
                        proto_tree_add_text(tree, tvb, 0, -1, 
                                            "Error processing Message");
                return;
        }

        if (tree) {
                ti = proto_tree_add_boolean(tree, hf_pw_atm_n2o_cw, 
                                            tvb, 0, 0, TRUE);
                PROTO_ITEM_SET_HIDDEN(ti);
                ti = proto_tree_add_item(tree, proto_pw_atm_n2o_cw, 
                                         tvb, 0, 4, FALSE);
                pw_atm_tree = proto_item_add_subtree(ti, ett_pw_atm);
                if (pw_atm_tree == NULL)
                        return;

                flags = tvb_get_guint8(tvb, 0) & 0x0F;
                proto_tree_add_uint_format(
                        pw_atm_tree,
                        hf_pw_atm_n2o_cw_flags,
                        tvb, 0, 1, flags,
                        "Flags: 0x%02x",
                        flags);

                length = tvb_get_guint8(tvb, 1) & 0x3F;
                proto_tree_add_uint_format(
                        pw_atm_tree,
                        hf_pw_atm_n2o_cw_length,
                        tvb, 1, 1, length,
                        "Length: %u",
                        flags);

                sequence_number = tvb_get_ntohs(tvb, 2);
                proto_tree_add_uint_format(
                        pw_atm_tree,
                        hf_pw_atm_n2o_cw_sequence_number,
                        tvb, 2, 2, sequence_number,
                        "Sequence Number: %u",
                        sequence_number);
        }

        /* FF: pass info to the ATM dissector, see packet_info.h for details */
        pinfo->pw_atm_encap_type = 1;

        /*
         * FF: RFC 4717: "The number of cells encapsulated in a particular 
         * frame can be inferred by the frame length" but "if the control 
         * word is used, then the flag and length bits in the control word 
         * are not used [and must be set to 0]" so... no reported_length in
         * tvb_new_subset().
         */
        ncells = tvb_length_remaining(tvb, 4) / 52;
        pinfo->pw_atm_ncells = ncells;
        remains = tvb_length_remaining(tvb, 4) % 52;

        for (i = 0; i < ncells; i++) {
                next_tvb = tvb_new_subset(tvb, 
                                          4 + (i * 52), 
                                          52, 
                                          -1);
                call_dissector(atm_h, next_tvb, pinfo, tree);
        }

        /* 
         * FF: RFC 4717 "if the pseudowire traverses a network link that 
         * requires a minimum frame size, with a minimum frame size of 64 
         * octets, then such links will apply padding to the pseudowire PDU 
         * to reach its minimum frame size" or this is a malformed PDU,
         * anyway...
         */
        if (remains) {
                next_tvb = tvb_new_subset(tvb,
                                          4 + (i * 52), 
                                          remains, 
                                          -1);
                call_dissector(data_h, next_tvb, pinfo, tree);
        }
}

static void
dissect_pw_atm_n2o_nocw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_item *ti = NULL;
        tvbuff_t *next_tvb = NULL;
        guint16 ncells = 0;
        guint16 remains = 0;
        guint16 i = 0;

        /* 
         * FF: all comments in dissect_pw_atm_n2o_cw() apply here
         * as well, thus not repeated.
         */

        if (tvb_reported_length_remaining(tvb, 0) < 52) {
                if (tree)
                        proto_tree_add_text(tree, tvb, 0, -1, 
                                            "Error processing Message");
                return;
        }

        if (tree) {
                ti = proto_tree_add_boolean(tree, hf_pw_atm_n2o_nocw, 
                                            tvb, 0, 0, TRUE);
                PROTO_ITEM_SET_HIDDEN(ti);
        }

        pinfo->pw_atm_encap_type = 1;
        ncells = tvb_length_remaining(tvb, 0) / 52;
        pinfo->pw_atm_ncells = ncells;
        remains = tvb_length_remaining(tvb, 0) % 52;

        for (i = 0; i < ncells; i++) {
                next_tvb = tvb_new_subset(tvb, 
                                          (i * 52), 
                                          52, 
                                          -1);
                call_dissector(atm_h, next_tvb, pinfo, tree);
        }

        if (remains) {
                next_tvb = tvb_new_subset(tvb,
                                          (i * 52), 
                                          remains, 
                                          -1);
                call_dissector(data_h, next_tvb, pinfo, tree);
        }
}

#if 0
static void
dissect_pw_atm_o2o_cw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        (void)tvb;
        (void)pinfo;
        (void)tree;
}

static void
dissect_pw_atm_o2o_nocw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        (void)tvb;
        (void)pinfo;
        (void)tree;
}


static void
dissect_pw_atm_aal5_pdu_cw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        (void)tvb;
        (void)pinfo;
        (void)tree;
}


static void
dissect_pw_atm_aal5_pdu_nocw(tvbuff_t *tvb, packet_info *pinfo, 
                             proto_tree *tree)
{
        (void)tvb;
        (void)pinfo;
        (void)tree;
}

static void
dissect_pw_atm_aal5_sdu_cw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        (void)tvb;
        (void)pinfo;
        (void)tree;
}

static void
dissect_pw_atm_aal5_sdu_nocw(tvbuff_t *tvb, packet_info *pinfo, 
                             proto_tree *tree)
{
        (void)tvb;
        (void)pinfo;
        (void)tree;
}
#endif

void
proto_register_pw_atm(void)
{
        static hf_register_info hf[] = {
                /* FF: general */
                {
                        &hf_pw_atm_n2o_cw,
                        {
                                "ATM PW, N-to-one Cell Mode (with CW)", 
                                "pw_atm_n2o_cw", FT_BOOLEAN, 
                                BASE_NONE, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_atm_n2o_nocw,
                        {
                                "ATM PW, N-to-one Cell Mode (no CW)", 
                                "pw_atm_n2o_nocw", FT_BOOLEAN, 
                                BASE_NONE, NULL, 0x0, NULL, HFILL
                        }
                },
#if 0
                {
                        &hf_pw_atm_o2o_cw,
                        {
                                "ATM PW, One-to-one Cell Mode (with CW)", 
                                "pw_atm_o2o_cw", FT_BOOLEAN, 
                                0, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_atm_o2o_nocw,
                        {
                                "ATM PW, One-to-one Cell Mode (no CW)", 
                                "pw_atm_o2o_nocw", FT_BOOLEAN, 
                                0, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_atm_aal5_pdu_cw,
                        {
                                "ATM PW, AAL5 PDU Frame Mode (with CW)", 
                                "pw_atm_aal5_pdu_cw", FT_BOOLEAN, 
                                0, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_atm_aal5_pdu_nocw,
                        {
                                "ATM PW, AAL5 PDU Frame Mode (no CW)", 
                                "pw_atm_aal5_pdu_nocw", FT_BOOLEAN, 
                                0, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_atm_aal5_sdu_cw,
                        {
                                "ATM PW, AAL5 SDU Frame Mode (with CW)", 
                                "pw_atm_aal5_sdu_cw", FT_BOOLEAN, 
                                0, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_atm_aal5_sdu_nocw,
                        {
                                "ATM PW, AAL5 SDU Frame Mode (no CW)", 
                                "pw_atm_aal5_sdu_nocw", FT_BOOLEAN, 
                                0, NULL, 0x0, NULL, HFILL
                        }
                },
                /* FF: ATM One-to-one Cell Mode Control Word fields */
                {
                        &hf_pw_atm_o2o_cw_sequence_number,
                        {
                                "ATM One-to-one Cell Mode sequence number", 
                                "pw_atm_o2o_cw_sequence_number", FT_UINT16, 
                                BASE_DEC, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_atm_o2o_cw_flags,
                        {
                                "ATM One-to-one Cell Mode flags",
                                "pw_atm_o2o_cw_flags", FT_UINT8, 
                                BASE_HEX, NULL, 0x0, NULL, HFILL 
                        }

                },
                {
                        &hf_pw_atm_o2o_cw_flags_m,
                        {
                                "M (transport mode) bit",
                                "pw_atm_o2o_cw_flags_m", FT_BOOLEAN, 
                                8, TFS(&flags_set_truth), PW_ATM_O2O_CW_M,
                                NULL, HFILL 
                        }
                },
                {
                        &hf_pw_atm_o2o_cw_flags_v,
                        {
                                "V (VCI present) bit",
                                "pw_atm_o2o_cw_flags_v", FT_BOOLEAN, 
                                8, TFS(&flags_set_truth), PW_ATM_O2O_CW_V,
                                NULL, HFILL 
                        }
                },
                {
                        &hf_pw_atm_o2o_cw_flags_res,
                        {
                                "Reserved bits",
                                "pw_atm_o2o_cw_flags_res", FT_BOOLEAN, 
                                8, TFS(&flags_set_truth), PW_ATM_O2O_CW_RES,
                                NULL, HFILL 
                        }
                },
                {
                        &hf_pw_atm_o2o_cw_flags_pti,
                        {
                                "PTI bits",
                                "pw_atm_o2o_cw_flags_pti", FT_BOOLEAN, 
                                8, TFS(&flags_set_truth), PW_ATM_O2O_CW_PTI,
                                NULL, HFILL 
                        }
                },
                {
                        &hf_pw_atm_o2o_cw_flags_c,
                        {
                                "C (CLP) bit",
                                "pw_atm_o2o_cw_flags_c", FT_BOOLEAN, 
                                8, TFS(&flags_set_truth), PW_ATM_O2O_CW_C,
                                NULL, HFILL 
                        }
                },
                /* FF: AAL5 PDU Frame Mode Control Word fields */
                {
                        &hf_pw_atm_aal5_pdu_cw_sequence_number,
                        {
                                "AAL5 PDU Frame Mode sequence number", 
                                "pw_atm_aal5_pdu_cw_sequence_number", 
                                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
                        }
                },
                /* FF: AAL5 SDU Frame Mode Control Word fields */
                {
                        &hf_pw_atm_aal5_sdu_cw_sequence_number,
                        {
                                "AAL5 SDU Frame Mode sequence number", 
                                "pw_atm_aal5_sdu_cw_sequence_number", 
                                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
                        }
                },
#endif
                /* FF: ATM N-to-one Cell Mode Control Word fields */
                {
                        &hf_pw_atm_n2o_cw_flags,
                        {
                                "ATM N-to-one Cell Mode flags",
                                "pw_atm_n2o_cw_flags", FT_UINT8, 
                                BASE_HEX, NULL, 0x0, NULL, HFILL 
                        }

                },
                {
                        &hf_pw_atm_n2o_cw_length,
                        {
                                "ATM N-to-one Cell Mode flags",
                                "pw_atm_n2o_cw_length", FT_UINT8, 
                                BASE_HEX, NULL, 0x0, NULL, HFILL 
                        }

                },
                {
                        &hf_pw_atm_n2o_cw_sequence_number,
                        {
                                "ATM N-to-one Cell Mode sequence number", 
                                "pw_atm_n2o_cw_sequence_number", FT_UINT16, 
                                BASE_DEC, NULL, 0x0, NULL, HFILL
                        }
                },
        };

        static gint *ett[] = {
                &ett_pw_atm
        };

        proto_pw_atm_n2o_cw = 
          proto_register_protocol("ATM PW, N-to-one Cell Mode Control Word",
                                  "ATM PW, N-to-one Cell Mode (with CW)",
                                  "pw_atm_n2o_cw");
        proto_pw_atm_n2o_nocw = 
          proto_register_protocol("ATM PW, N-to-one Cell Mode (no CW)",
                                  "ATM PW, N-to-one Cell Mode (no CW)",
                                  "pw_atm_n2o_nocw");
#if 0
        proto_pw_atm_o2o_cw = 
          proto_register_protocol("ATM PW, One-to-one Cell Mode Control Word",
                                  "ATM PW, One-to-one Cell Mode (with CW)",
                                  "pw_atm_o2o_cw");
        proto_pw_atm_o2o_nocw = 
          proto_register_protocol("ATM PW, One-to-one Cell Mode (no CW)",
                                  "ATM PW, One-to-one Cell Mode (no CW)",
                                  "pw_atm_o2o_nocw");
        proto_pw_atm_aal5_pdu_cw = 
          proto_register_protocol("ATM PW, AAL5 PDU Frame Mode Control Word",
                                  "ATM PW, AAL5 PDU Frame Mode (with CW)",
                                  "pw_atm_aal5_pdu_cw");
        proto_pw_atm_aal5_pdu_nocw = 
          proto_register_protocol("ATM PW, AAL5 PDU Frame Mode (no CW)",
                                  "ATM PW, AAL5 PDU Frame Mode (no CW)",
                                  "pw_atm_aal5_pdu_nocw");
        proto_pw_atm_aal5_sdu_cw = 
          proto_register_protocol("ATM PW, AAL5 SDU Frame Mode Control Word",
                                  "ATM PW, AAL5 SDU Frame Mode (with CW)",
                                  "pw_atm_aal5_sdu_cw");
        proto_pw_atm_aal5_sdu_nocw = 
          proto_register_protocol("ATM PW, AAL5 SDU Frame Mode (no CW)",
                                  "ATM PW, AAL5 SDU Frame Mode (no CW)",
                                  "pw_atm_aal5_sdu_nocw");
#endif

        proto_register_field_array(proto_pw_atm_n2o_cw, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));   

        register_dissector("pw_atm_n2o_cw", 
                           dissect_pw_atm_n2o_cw, 
                           proto_pw_atm_n2o_cw);
        register_dissector("pw_atm_n2o_nocw", 
                           dissect_pw_atm_n2o_nocw, 
                           proto_pw_atm_n2o_nocw);
#if 0
        register_dissector("pw_atm_o2o_cw", 
                           dissect_pw_atm_o2o_cw, 
                           proto_pw_atm_o2o_cw);
        register_dissector("pw_atm_o2o_nocw", 
                           dissect_pw_atm_o2o_nocw, 
                           proto_pw_atm_o2o_nocw);
        register_dissector("pw_atm_aal5_pdu_cw", 
                           dissect_pw_atm_aal5_pdu_cw, 
                           proto_pw_atm_aal5_pdu_cw);
        register_dissector("pw_atm_aal5_pdu_nocw", 
                           dissect_pw_atm_aal5_pdu_nocw, 
                           proto_pw_atm_aal5_pdu_nocw);
        register_dissector("pw_atm_aal5_sdu_cw", 
                           dissect_pw_atm_aal5_sdu_cw, 
                           proto_pw_atm_aal5_sdu_cw);
        register_dissector("pw_atm_aal5_sdu_nocw", 
                           dissect_pw_atm_aal5_sdu_nocw, 
                           proto_pw_atm_aal5_sdu_nocw);
#endif
}

void
proto_reg_handoff_pw_atm(void)
{
        dissector_handle_t pw_atm_n2o_cw_h; 
        dissector_handle_t pw_atm_n2o_nocw_h;
#if 0
        dissector_handle_t pw_atm_o2o_cw_h;
        dissector_handle_t pw_atm_o2o_nocw_h;
        dissector_handle_t pw_atm_aal5_pdu_cw_h;
        dissector_handle_t pw_atm_aal5_pdu_nocw_h;
        dissector_handle_t pw_atm_aal5_sdu_cw_h;
        dissector_handle_t pw_atm_aal5_sdu_nocw_h;
#endif

        pw_atm_n2o_cw_h = find_dissector("pw_atm_n2o_cw");
        dissector_add("mpls.label", LABEL_INVALID, pw_atm_n2o_cw_h);

        pw_atm_n2o_nocw_h = find_dissector("pw_atm_n2o_nocw");
        dissector_add("mpls.label", LABEL_INVALID, pw_atm_n2o_nocw_h);
#if 0
        pw_atm_o2o_cw_h = find_dissector("pw_atm_o2o_cw");
        dissector_add("mpls.label", LABEL_INVALID, pw_atm_o2o_cw_h);

        pw_atm_o2o_nocw_h = find_dissector("pw_atm_o2o_nocw");
        dissector_add("mpls.label", LABEL_INVALID, pw_atm_o2o_nocw_h);

        pw_atm_aal5_pdu_cw_h = find_dissector("pw_atm_aal5_pdu_cw");
        dissector_add("mpls.label", LABEL_INVALID, pw_atm_aal5_pdu_cw_h);

        pw_atm_aal5_pdu_nocw_h = find_dissector("pw_atm_aal5_pdu_nocw");
        dissector_add("mpls.label", LABEL_INVALID, pw_atm_aal5_pdu_nocw_h);

        pw_atm_aal5_sdu_cw_h = find_dissector("pw_atm_aal5_sdu_cw");
        dissector_add("mpls.label", LABEL_INVALID, pw_atm_aal5_sdu_cw_h);

        pw_atm_aal5_sdu_nocw_h = find_dissector("pw_atm_aal5_sdu_nocw");
        dissector_add("mpls.label", LABEL_INVALID, pw_atm_aal5_sdu_nocw_h);
#endif

        data_h = find_dissector("data");
        atm_h = find_dissector("atm_4717");
}
