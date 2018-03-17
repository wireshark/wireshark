/* Routines for 5G/NR MAC disassembly
 *
 * Based on packet-mac-lte.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>

#include "packet-mac-nr.h"

void proto_register_mac_nr(void);
void proto_reg_handoff_mac_nr(void);

/* Described in:
 * 3GPP TS 38.321 NR; Medium Access Control (MAC) protocol specification v15.0.0
 */

/* Initialize the protocol and registered fields. */
int proto_mac_nr = -1;

/* Decoding context */
static int hf_mac_nr_context = -1;
static int hf_mac_nr_context_radio_type = -1;
static int hf_mac_nr_context_direction = -1;
static int hf_mac_nr_context_rnti = -1;
static int hf_mac_nr_context_rnti_type = -1;
static int hf_mac_nr_context_ueid = -1;

static int hf_mac_nr_subheader = -1;
static int hf_mac_nr_subheader_reserved = -1;
static int hf_mac_nr_subheader_f = -1;
static int hf_mac_nr_subheader_length_1_byte = -1;
static int hf_mac_nr_subheader_length_2_bytes = -1;
static int hf_mac_nr_ulsch_lcid = -1;
static int hf_mac_nr_dlsch_lcid = -1;
static int hf_mac_nr_dlsch_sdu = -1;
static int hf_mac_nr_ulsch_sdu = -1;


static int hf_mac_nr_control_crnti = -1;
static int hf_mac_nr_control_ue_contention_resolution_identity = -1;
static int hf_mac_nr_control_timing_advance_tagid = -1;
static int hf_mac_nr_control_timing_advance_command = -1;
static int hf_mac_nr_control_se_phr_reserved = -1;
static int hf_mac_nr_control_se_phr_ph = -1;
static int hf_mac_nr_control_se_phr_pcmax_c = -1;
static int hf_mac_nr_control_dupl_act_deact_drb7 = -1;
static int hf_mac_nr_control_dupl_act_deact_drb6 = -1;
static int hf_mac_nr_control_dupl_act_deact_drb5 = -1;
static int hf_mac_nr_control_dupl_act_deact_drb4 = -1;
static int hf_mac_nr_control_dupl_act_deact_drb3 = -1;
static int hf_mac_nr_control_dupl_act_deact_drb2 = -1;
static int hf_mac_nr_control_dupl_act_deact_drb1 = -1;
static int hf_mac_nr_control_dupl_act_deact_reserved = -1;
static int hf_mac_nr_control_scell_act_deact_cell7 = -1;
static int hf_mac_nr_control_scell_act_deact_cell6 = -1;
static int hf_mac_nr_control_scell_act_deact_cell5 = -1;
static int hf_mac_nr_control_scell_act_deact_cell4 = -1;
static int hf_mac_nr_control_scell_act_deact_cell3 = -1;
static int hf_mac_nr_control_scell_act_deact_cell2 = -1;
static int hf_mac_nr_control_scell_act_deact_cell1 = -1;
static int hf_mac_nr_control_scell_act_deact_reserved = -1;
static int hf_mac_nr_control_scell_act_deact_cell15 = -1;
static int hf_mac_nr_control_scell_act_deact_cell14 = -1;
static int hf_mac_nr_control_scell_act_deact_cell13 = -1;
static int hf_mac_nr_control_scell_act_deact_cell12 = -1;
static int hf_mac_nr_control_scell_act_deact_cell11 = -1;
static int hf_mac_nr_control_scell_act_deact_cell10 = -1;
static int hf_mac_nr_control_scell_act_deact_cell9 = -1;
static int hf_mac_nr_control_scell_act_deact_cell8 = -1;
static int hf_mac_nr_control_scell_act_deact_cell23 = -1;
static int hf_mac_nr_control_scell_act_deact_cell22 = -1;
static int hf_mac_nr_control_scell_act_deact_cell21 = -1;
static int hf_mac_nr_control_scell_act_deact_cell20 = -1;
static int hf_mac_nr_control_scell_act_deact_cell19 = -1;
static int hf_mac_nr_control_scell_act_deact_cell18 = -1;
static int hf_mac_nr_control_scell_act_deact_cell17 = -1;
static int hf_mac_nr_control_scell_act_deact_cell16 = -1;
static int hf_mac_nr_control_scell_act_deact_cell31 = -1;
static int hf_mac_nr_control_scell_act_deact_cell30 = -1;
static int hf_mac_nr_control_scell_act_deact_cell29 = -1;
static int hf_mac_nr_control_scell_act_deact_cell28 = -1;
static int hf_mac_nr_control_scell_act_deact_cell27 = -1;
static int hf_mac_nr_control_scell_act_deact_cell26 = -1;
static int hf_mac_nr_control_scell_act_deact_cell25 = -1;
static int hf_mac_nr_control_scell_act_deact_cell24 = -1;
static int hf_mac_nr_control_short_trunc_bsr_lcg_id = -1;
static int hf_mac_nr_control_short_trunc_bsr_bs = -1;
static int hf_mac_nr_control_short_bsr_lcg_id = -1;
static int hf_mac_nr_control_short_bsr_bs = -1;
static int hf_mac_nr_control_long_trunc_bsr_lcg7 = -1;
static int hf_mac_nr_control_long_trunc_bsr_lcg6 = -1;
static int hf_mac_nr_control_long_trunc_bsr_lcg5 = -1;
static int hf_mac_nr_control_long_trunc_bsr_lcg4 = -1;
static int hf_mac_nr_control_long_trunc_bsr_lcg3 = -1;
static int hf_mac_nr_control_long_trunc_bsr_lcg2 = -1;
static int hf_mac_nr_control_long_trunc_bsr_lcg1 = -1;
static int hf_mac_nr_control_long_trunc_bsr_lcg0 = -1;
static int hf_mac_nr_control_long_trunc_bsr_bs_lcg0 = -1;
static int hf_mac_nr_control_long_trunc_bsr_bs_lcg7 = -1;
static int hf_mac_nr_control_long_trunc_bsr_bs_lcg6 = -1;
static int hf_mac_nr_control_long_trunc_bsr_bs_lcg5 = -1;
static int hf_mac_nr_control_long_trunc_bsr_bs_lcg4 = -1;
static int hf_mac_nr_control_long_trunc_bsr_bs_lcg3 = -1;
static int hf_mac_nr_control_long_trunc_bsr_bs_lcg2 = -1;
static int hf_mac_nr_control_long_trunc_bsr_bs_lcg1 = -1;

static int hf_mac_nr_rar = -1;
static int hf_mac_nr_rar_subheader = -1;
static int hf_mac_nr_rar_e = -1;
static int hf_mac_nr_rar_t = -1;
static int hf_mac_nr_rar_reserved = -1;

static int hf_mac_nr_rar_bi = -1;
static int hf_mac_nr_rar_rapid = -1;
static int hf_mac_nr_rar_ta = -1;
static int hf_mac_nr_rar_grant = -1;
static int hf_mac_nr_rar_temp_crnti = -1;

static int hf_mac_nr_padding = -1;

/* Subtrees. */
static int ett_mac_nr = -1;
static int ett_mac_nr_context = -1;
static int ett_mac_nr_subheader = -1;
static int ett_mac_nr_rar_subheader = -1;

static expert_field ei_mac_nr_no_per_frame_data = EI_INIT;

/* Constants and value strings */

static const value_string radio_type_vals[] =
{
    { FDD_RADIO,      "FDD"},
    { TDD_RADIO,      "TDD"},
    { 0, NULL }
};

static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};

static const value_string rnti_type_vals[] =
{
    { NO_RNTI,     "NO-RNTI"},
    { P_RNTI,      "P-RNTI"},
    { RA_RNTI,     "RA-RNTI"},
    { C_RNTI,      "C-RNTI"},
    { SI_RNTI,     "SI-RNTI"},
    { CS_RNTI,     "CS-RNTI"},
    { 0, NULL }
};


#define DUPLICATION_ACTIVATION_DEACTIVATION_LCID   0x38
#define SCELL_ACTIVATION_DEACTIVATION_4            0x39
#define SCELL_ACTIVATION_DEACTIVATION_1            0x3a
#define LONG_DRX_COMMAND_LCID                      0x3b
#define DRX_COMMAND_LCID                           0x3c
#define TIMING_ADVANCE_COMMAND_LCID                0x3d
#define UE_CONTENTION_RESOLUTION_IDENTITY_LCID     0x3e
#define PADDING_LCID                               0x3f

static const value_string dlsch_lcid_vals[] =
{
    { 0,                                        "CCCH"},
    { 1,                                        "1"},
    { 2,                                        "2"},
    { 3,                                        "3"},
    { 4,                                        "4"},
    { 5,                                        "5"},
    { 6,                                        "6"},
    { 7,                                        "7"},
    { 8,                                        "8"},
    { 9,                                        "9"},
    { 10,                                       "10"},
    { 11,                                       "11"},
    { 12,                                       "12"},
    { 13,                                       "13"},
    { 14,                                       "14"},
    { 15,                                       "15"},
    { 16,                                       "16"},
    { 17,                                       "17"},
    { 18,                                       "18"},
    { 19,                                       "19"},
    { 20,                                       "20"},
    { 21,                                       "21"},
    { 22,                                       "22"},
    { 23,                                       "23"},
    { 24,                                       "24"},
    { 25,                                       "25"},
    { 26,                                       "26"},
    { 27,                                       "27"},
    { 28,                                       "28"},
    { 29,                                       "29"},
    { 30,                                       "30"},
    { 31,                                       "31"},
    { 32,                                       "32"},
    { DUPLICATION_ACTIVATION_DEACTIVATION_LCID, "Duplication Activation/Deactivation"},
    { SCELL_ACTIVATION_DEACTIVATION_4,          "SCell Activation/Deactivation (4 octet)"},
    { SCELL_ACTIVATION_DEACTIVATION_1,          "SCell Activation/Deactivation (1 octet)"},
    { LONG_DRX_COMMAND_LCID,                    "Long DRX Command"},
    { DRX_COMMAND_LCID,                         "DRX Command"},
    { TIMING_ADVANCE_COMMAND_LCID,              "Timing Advance Command"},
    { UE_CONTENTION_RESOLUTION_IDENTITY_LCID,   "UE Contention Resolution Identity"},
    { PADDING_LCID,                             "Padding"},
    { 0, NULL }
};
static value_string_ext dlsch_lcid_vals_ext = VALUE_STRING_EXT_INIT(dlsch_lcid_vals);

#define CONFIGURED_GRANT_CONFIGURATION_LCID  0x37
#define MULTIPLE_ENTRY_PHR_LCID              0x38
#define SINGLE_ENTRY_PHR_LCID                0x39
#define C_RNTI_LCID                          0x3a
#define SHORT_TRUNCATED_BSR_LCID             0x3b
#define LONG_TRUNCATED_BSR_LCID              0x3c
#define SHORT_BSR_LCID                       0x3d
#define LONG_BSR_LCID                        0x3e
#define PADDING_LCID                         0x3f

static const value_string ulsch_lcid_vals[] =
{
    { 0,                                    "CCCH"},
    { 1,                                    "1"},
    { 2,                                    "2"},
    { 3,                                    "3"},
    { 4,                                    "4"},
    { 5,                                    "5"},
    { 6,                                    "6"},
    { 7,                                    "7"},
    { 8,                                    "8"},
    { 9,                                    "9"},
    { 10,                                   "10"},
    { 11,                                   "11"},
    { 12,                                   "12"},
    { 13,                                   "13"},
    { 14,                                   "14"},
    { 15,                                   "15"},
    { 16,                                   "16"},
    { 17,                                   "17"},
    { 18,                                   "18"},
    { 19,                                   "19"},
    { 20,                                   "20"},
    { 21,                                   "21"},
    { 22,                                   "22"},
    { 23,                                   "23"},
    { 24,                                   "24"},
    { 25,                                   "25"},
    { 26,                                   "26"},
    { 27,                                   "27"},
    { 28,                                   "28"},
    { 29,                                   "29"},
    { 30,                                   "30"},
    { 31,                                   "31"},
    { 32,                                   "32"},
    { CONFIGURED_GRANT_CONFIGURATION_LCID,  "Configured Grant Confirmation"},
    { MULTIPLE_ENTRY_PHR_LCID,              "Multiple Entry PHR"},
    { SINGLE_ENTRY_PHR_LCID,                "Single Entry PHR"},
    { C_RNTI_LCID,                          "C-RNTI"},
    { SHORT_TRUNCATED_BSR_LCID,             "Short Truncated BSR"},
    { LONG_TRUNCATED_BSR_LCID,              "Long Truncated BSR"},
    { SHORT_BSR_LCID,                       "Short BSR"},
    { LONG_BSR_LCID,                        "Long BSR"},
    { PADDING_LCID,                         "Padding"},
    { 0, NULL }
};
static value_string_ext ulsch_lcid_vals_ext = VALUE_STRING_EXT_INIT(ulsch_lcid_vals);

static const true_false_string rar_ext_vals =
{
    "Another MAC subPDU follows",
    "Last MAC subPDU"
};

static const true_false_string rar_type_vals =
{
    "RAPID present",
    "Backoff Indicator present"
};

static const value_string rar_bi_vals[] =
{
    { 0,  "5ms"},
    { 1,  "10ms"},
    { 2,  "20ms"},
    { 3,  "30ms"},
    { 4,  "40ms"},
    { 5,  "60ms"},
    { 6,  "80ms"},
    { 7,  "120ms"},
    { 8,  "160ms"},
    { 9,  "240ms"},
    { 10, "320ms"},
    { 11, "480ms"},
    { 12, "960ms"},
    { 13, "1920ms"},
    { 14, "Reserved"},
    { 15, "Reserved"},
    { 0, NULL }
};

static const value_string buffer_size_5bits_vals[] =
{
    { 0,  "BS = 0"},
    { 1,  "0 < BS <= 10"},
    { 2,  "10 < BS <= 14"},
    { 3,  "14 < BS <= 20"},
    { 4,  "20 < BS <= 28"},
    { 5,  "28 < BS <= 38"},
    { 6,  "38 < BS <= 53"},
    { 7,  "53 < BS <= 74"},
    { 8,  "74 < BS <= 102"},
    { 9,  "102 < BS <= 142"},
    { 10, "142 < BS <= 198"},
    { 11, "198 < BS <= 276"},
    { 12, "276 < BS <= 384"},
    { 13, "384 < BS <= 535"},
    { 14, "535 < BS <= 745"},
    { 15, "745 < BS <= 1038"},
    { 16, "1038 < BS <= 1446"},
    { 17, "1446 < BS <= 2014"},
    { 18, "2014 < BS <= 2806"},
    { 19, "2806 < BS <= 3909"},
    { 20, "3909 < BS <= 5446"},
    { 21, "5446 < BS <= 7587"},
    { 22, "7587 < BS <= 10570"},
    { 23, "10570 < BS <= 14726"},
    { 24, "14726 < BS <= 20516"},
    { 25, "20516 < BS <= 28581"},
    { 26, "28581 < BS <= 39818"},
    { 27, "39818 < BS <= 55474"},
    { 28, "55474 < BS <= 77284"},
    { 29, "77284 < BS <= 107669"},
    { 30, "107669 < BS <= 150000"},
    { 31, "BS > 150000"},
    { 0, NULL }
};
static value_string_ext buffer_size_5bits_vals_ext = VALUE_STRING_EXT_INIT(buffer_size_5bits_vals);


static const value_string buffer_size_8bits_vals[] =
{
    { 0,  "BS = 0"},
    { 1,  "0 < BS <= 10"},
    { 2,  "10 < BS <= 11"},
    { 3,  "11 < BS <= 12"},
    { 4,  "12 < BS <= 13"},
    { 5,  "12 < BS <= 13"},  /* N.B. same as previous index, but wrong in spec! */
    { 6,  "13 < BS <= 14"},
    { 7,  "14 < BS <= 15"},
    { 8,  "15 < BS <= 16"},
    { 9,  "16 < BS <= 17"},
    { 10, "17 < BS <= 18"},
    { 11, "18 < BS <= 19"},
    { 12, "19 < BS <= 20"},
    { 13, "20 < BS <= 22"},
    { 14, "22 < BS <= 23"},
    { 15, "23 < BS <= 25"},
    { 16, "25 < BS <= 26"},
    { 17, "26 < BS <= 28"},
    { 18, "28 < BS <= 30"},
    { 19, "30 < BS <= 32"},
    { 20, "32 < BS <= 34"},
    { 21, "34 < BS <= 36"},
    { 22, "36 < BS <= 38"},
    { 23, "38 < BS <= 40"},
    { 24, "40 < BS <= 43"},
    { 25, "43 < BS <= 46"},
    { 26, "46 < BS <= 49"},
    { 27, "49 < BS <= 52"},
    { 28, "52 < BS <= 55"},
    { 29, "52 < BS <= 59"},
    { 30, "59 < BS <= 62"},
    { 31, "62 < BS <= 66"},
    { 32, "66 < BS <= 71"},
    { 33, "71 < BS <= 75"},
    { 34, "75 < BS <= 80"},
    { 35, "80 < BS <= 85"},
    { 36, "85 < BS <= 91"},
    { 37, "91 < BS <= 97"},
    { 38, "97 < BS <= 103"},
    { 39, "103 < BS <= 110"},
    { 40, "110 < BS <= 117"},
    { 41, "117 < BS <= 124"},
    { 42, "124 < BS <= 132"},
    { 43, "132 < BS <= 141"},
    { 44, "141 < BS <= 150"},
    { 45, "150 < BS <= 160"},
    { 46, "160 < BS <= 170"},
    { 47, "170 < BS <= 181"},
    { 48, "181 < BS <= 193"},
    { 49, "193 < BS <= 205"},
    { 50, "205 < BS <= 218"},
    { 51, "218 < BS <= 233"},
    { 52, "233 < BS <= 248"},
    { 53, "248 < BS <= 264"},
    { 54, "264 < BS <= 281"},
    { 55, "281 < BS <= 299"},
    { 56, "299 < BS <= 318"},
    { 57, "318 < BS <= 339"},
    { 58, "339 < BS <= 361"},
    { 59, "361 < BS <= 384"},
    { 60, "384 < BS <= 409"},
    { 61, "409 < BS <= 436"},
    { 62, "436 < BS <= 464"},
    { 63, "464 < BS <= 494"},
    { 64, "494 < BS <= 526"},
    { 65, "526 < BS <= 560"},
    { 66, "560 < BS <= 597"},
    /* TODO: given the size of this table, and repeated range in V15.0.0 for indices 4,5,
     * will finish entering these when the new version appears */
    { 255, "BS > 81338368"},
    { 0, NULL }
};
static value_string_ext buffer_size_8bits_vals_ext = VALUE_STRING_EXT_INIT(buffer_size_8bits_vals);


/* Forward declarations */
static int dissect_mac_nr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void*);

/* Write the given formatted text to:
   - the info column (if pinfo != NULL)
   - 1 or 2 other labels (optional)
*/
static void write_pdu_label_and_info(proto_item *ti1, proto_item *ti2,
                                     packet_info *pinfo, const char *format, ...)
{
    #define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];
    va_list ap;

    if ((ti1 == NULL) && (ti2 == NULL) && (pinfo == NULL)) {
        return;
    }

    va_start(ap, format);
    g_vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    if (pinfo != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    }
    if (ti1 != NULL) {
        proto_item_append_text(ti1, "%s", info_buffer);
    }
    if (ti2 != NULL) {
        proto_item_append_text(ti2, "%s", info_buffer);
    }
}

/* Version of function above, where no g_vsnprintf() call needed */
static void write_pdu_label_and_info_literal(proto_item *ti1, proto_item *ti2,
                                             packet_info *pinfo, const char *info_buffer)
{
    /* Add to indicated places */
    if (pinfo != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    }
    if (ti1 != NULL) {
        proto_item_append_text(ti1, "%s", info_buffer);
    }
    if (ti2 != NULL) {
        proto_item_append_text(ti2, "%s", info_buffer);
    }
}



static void dissect_rar(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        proto_item *pdu_ti _U_, guint32 offset,
                        mac_nr_info *p_mac_nr_info _U_)
{
    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "RAR (RA-RNTI=%u, SFN=%-4u, SF=%u) ",
                             p_mac_nr_info->rnti, p_mac_nr_info->sysframeNumber, p_mac_nr_info->subframeNumber);

    /* Create hidden 'virtual root' so can filter on mac-nr.rar */
    proto_item *ti = proto_tree_add_item(tree, hf_mac_nr_rar, tvb, offset, -1, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(ti);

    gboolean E, T;

    do {
        /* Subheader */
        proto_item *subheader_ti = proto_tree_add_item(tree,
                                                       hf_mac_nr_rar_subheader,
                                                       tvb, offset, 0, ENC_ASCII|ENC_NA);
        proto_tree *rar_subheader_tree = proto_item_add_subtree(subheader_ti, ett_mac_nr_rar_subheader);

        /* Note extension & T bits */
        proto_tree_add_item_ret_boolean(rar_subheader_tree, hf_mac_nr_rar_e, tvb, offset, 1, ENC_BIG_ENDIAN, &E);
        proto_tree_add_item_ret_boolean(rar_subheader_tree, hf_mac_nr_rar_t, tvb, offset, 1, ENC_BIG_ENDIAN, &T);

        if (!T) {
            /* BI */

            /* 2 reserved bits */
            proto_tree_add_item(rar_subheader_tree, hf_mac_nr_rar_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* BI */
            guint32 BI;
            proto_tree_add_item_ret_uint(rar_subheader_tree, hf_mac_nr_rar_bi, tvb, offset, 1, ENC_BIG_ENDIAN, &BI);
            offset++;

            write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                     "BI=%u ", BI);
        }
        else {
            /* RAPID */
            guint32 rapid;
            proto_tree_add_item_ret_uint(rar_subheader_tree, hf_mac_nr_rar_rapid, tvb, offset, 1, ENC_BIG_ENDIAN, &rapid);
            offset++;
            if (TRUE) {
                /* SubPDU.  Not for SI request - TODO: define RAPID range for SI request in mac_nr_info */
                /* TA (12 bits) */
                guint32 ta;
                proto_tree_add_item_ret_uint(rar_subheader_tree, hf_mac_nr_rar_ta, tvb, offset, 2, ENC_BIG_ENDIAN, &ta);
                offset++;

                /* Grant (20 bits).  TODO: break down! */
                proto_tree_add_item(rar_subheader_tree, hf_mac_nr_rar_grant, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;

                /* C-RNTI (2 bytes) */
                guint32 c_rnti;
                proto_tree_add_item_ret_uint(rar_subheader_tree, hf_mac_nr_rar_temp_crnti, tvb, offset, 2, ENC_BIG_ENDIAN, &c_rnti);
                offset += 2;

                write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                         "(RAPID=%u TA=%u Temp C-RNTI=%u) ", rapid, ta, c_rnti);
            }
            else {
                write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                         "(RAPID=%u) ", rapid);
            }
        }
        /* Set subheader (+subpdu..) length */
        proto_item_set_end(subheader_ti, tvb, offset);

    } while (E);

    /* Any remaining length is padding */
    if (tvb_reported_length_remaining(tvb, offset)) {
        proto_tree_add_item(tree, hf_mac_nr_padding, tvb, offset, -1, ENC_NA);
    }
}

static gboolean is_fixed_sized_lcid(guint8 lcid, guint8 direction)
{
    if (direction == DIRECTION_UPLINK) {
        switch (lcid) {
            case CONFIGURED_GRANT_CONFIGURATION_LCID:
            case SINGLE_ENTRY_PHR_LCID:
            case C_RNTI_LCID:
            case SHORT_TRUNCATED_BSR_LCID:
            case SHORT_BSR_LCID:
            case PADDING_LCID:
                return TRUE;
            default:
                return FALSE;
        }
    }
    else {
        switch (lcid) {
            case DUPLICATION_ACTIVATION_DEACTIVATION_LCID:
            case SCELL_ACTIVATION_DEACTIVATION_4:
            case SCELL_ACTIVATION_DEACTIVATION_1:
            case LONG_DRX_COMMAND_LCID:
            case DRX_COMMAND_LCID:
            case TIMING_ADVANCE_COMMAND_LCID:
            case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
            case PADDING_LCID:
                return TRUE;
            default:
                return FALSE;
        }
    }
}

static true_false_string subheader_f_vals = {
    "16 bits",
    "8 bits"
};

/* UL-SCH and DL-SCH formats have much in common, so handle them in a common
   function */
static void dissect_ulsch_or_dlsch(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                   proto_item *pdu_ti _U_, guint32 offset,
                                   mac_nr_info *p_mac_nr_info,
                                   proto_tree *context_tree _U_)
{
    /************************************************************************/
    /* Dissect each sub-pdu.                                             */
    do {
        /* Subheader */
        proto_item *subheader_ti = proto_tree_add_item(tree,
                                                       hf_mac_nr_subheader,
                                                       tvb, offset, 0, ENC_ASCII|ENC_NA);
        proto_tree *subheader_tree = proto_item_add_subtree(subheader_ti, ett_mac_nr_subheader);


        gboolean F, fixed_len;
        guint32 SDU_length=0;

        /* 1st bit is always reserved */
        /* 2nd bit depends upon LCID */
        guint8 lcid = tvb_get_guint8(tvb, offset) & 0x3f;
        fixed_len = is_fixed_sized_lcid(lcid, p_mac_nr_info->direction);
        if (fixed_len) {
            proto_tree_add_bits_item(subheader_tree, hf_mac_nr_subheader_reserved, tvb, offset<<3, 2, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_bits_item(subheader_tree, hf_mac_nr_subheader_reserved, tvb, offset<<3, 1, ENC_BIG_ENDIAN);
            /* Data, so check F bit and length */
            proto_tree_add_item_ret_boolean(subheader_tree, hf_mac_nr_subheader_f, tvb, offset, 1, ENC_BIG_ENDIAN, &F);
        }

        /* LCID */
        proto_tree_add_uint(subheader_tree,
                            (p_mac_nr_info->direction == DIRECTION_UPLINK) ?
                                hf_mac_nr_ulsch_lcid : hf_mac_nr_dlsch_lcid,
                            tvb, offset, 1, lcid);
        offset++;

        if (!fixed_len) {
            if (F) {
                /* Long length */
                proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_subheader_length_2_bytes, tvb, offset, 2, ENC_BIG_ENDIAN, &SDU_length);
                offset += 2;
            }
            else {
                /* Short length */
                proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_subheader_length_1_byte, tvb, offset, 1, ENC_BIG_ENDIAN, &SDU_length);
                offset++;
            }
        }

        if (lcid <= 32) {

            /* Add SDU, for now just as hex data */
            if (p_mac_nr_info->direction == DIRECTION_UPLINK) {
                proto_tree_add_item(subheader_tree, hf_mac_nr_ulsch_sdu,
                                    tvb, offset, SDU_length, ENC_NA);
            }
            else {
                proto_tree_add_item(subheader_tree, hf_mac_nr_dlsch_sdu,
                                    tvb, offset, SDU_length, ENC_NA);
            }
            write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                     "(LCID:%u %u bytes) ", lcid, SDU_length);
            offset += SDU_length;
        }
        else {
            /* Control Elements */
            if (p_mac_nr_info->direction == DIRECTION_UPLINK) {
                guint32 phr_ph, phr_pcmac_c, c_rnti, lcg_id, bs;

                switch (lcid) {
                    case CONFIGURED_GRANT_CONFIGURATION_LCID:
                        /* Fixed size of zero bits */
                        write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo,
                                                         "(Configured Grant Config) ");
                        break;
                    case MULTIPLE_ENTRY_PHR_LCID:
                        /* variable size or deduced from bits? */
                        write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo,
                                                         "(Multi-entry PHR) ");
                        offset += SDU_length;
                        break;
                    case SINGLE_ENTRY_PHR_LCID:
                        /* R R PH (6 bits) */
                        proto_tree_add_item(subheader_tree, hf_mac_nr_control_se_phr_reserved,
                                            tvb, offset, 1, ENC_NA);
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_se_phr_ph,
                                                     tvb, offset, 1, ENC_NA, &phr_ph);
                        offset++;

                        /* R R PCMAXC (6 bits) */
                        proto_tree_add_item(subheader_tree, hf_mac_nr_control_se_phr_reserved,
                                            tvb, offset, 1, ENC_NA);
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_se_phr_pcmax_c,
                                                     tvb, offset, 1, ENC_NA, &phr_pcmac_c);
                        offset++;
                        write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                                 "(PHR PH=%u PCMAC_C=%u) ", phr_ph, phr_pcmac_c);
                        break;
                    case C_RNTI_LCID:
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_crnti,
                                                     tvb, offset, 2, ENC_BIG_ENDIAN, &c_rnti);
                        write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                                 "(C-RNTI=%u) ", c_rnti);
                        offset += 2;
                        break;
                    case SHORT_TRUNCATED_BSR_LCID:
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_short_trunc_bsr_lcg_id,
                                                     tvb, offset, 1, ENC_BIG_ENDIAN, &lcg_id);
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_short_trunc_bsr_bs,
                                                     tvb, offset, 1, ENC_BIG_ENDIAN, &bs);
                        write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                                 "(Short Truncated BSR LCG ID=%u BS=%u) ", lcg_id, bs);
                        offset++;
                        break;

                    case SHORT_BSR_LCID:
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_short_bsr_lcg_id,
                                                     tvb, offset, 1, ENC_BIG_ENDIAN, &lcg_id);
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_short_bsr_bs,
                                                     tvb, offset, 1, ENC_BIG_ENDIAN, &bs);
                        write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                                 "(Short BSR LCG ID=%u BS=%u) ", lcg_id, bs);
                        offset++;
                        break;
                    case LONG_BSR_LCID:
                    case LONG_TRUNCATED_BSR_LCID:
                        {
                            static const int * long_bsr_flags[] = {
                                &hf_mac_nr_control_long_trunc_bsr_lcg7,
                                &hf_mac_nr_control_long_trunc_bsr_lcg6,
                                &hf_mac_nr_control_long_trunc_bsr_lcg5,
                                &hf_mac_nr_control_long_trunc_bsr_lcg4,
                                &hf_mac_nr_control_long_trunc_bsr_lcg3,
                                &hf_mac_nr_control_long_trunc_bsr_lcg2,
                                &hf_mac_nr_control_long_trunc_bsr_lcg1,
                                &hf_mac_nr_control_long_trunc_bsr_lcg0,
                                NULL
                            };

                            guint8 flags = tvb_get_guint8(tvb, offset);
                            proto_tree_add_bitmask_list(subheader_tree, tvb, offset, 1, long_bsr_flags, ENC_NA);
                            guint CE_start = offset;
                            offset++;

                            /* Show BSR values.  TODO: break out into a function so can report in expert info if
                               Long BSR case is truncated... */
                            if ((flags & 0x01) && ((offset-CE_start) < SDU_length)) proto_tree_add_item(subheader_tree, hf_mac_nr_control_long_trunc_bsr_bs_lcg0, tvb, offset++, 1, ENC_NA);
                            if ((flags & 0x02) && ((offset-CE_start) < SDU_length)) proto_tree_add_item(subheader_tree, hf_mac_nr_control_long_trunc_bsr_bs_lcg1, tvb, offset++, 1, ENC_NA);
                            if ((flags & 0x04) && ((offset-CE_start) < SDU_length)) proto_tree_add_item(subheader_tree, hf_mac_nr_control_long_trunc_bsr_bs_lcg2, tvb, offset++, 1, ENC_NA);
                            if ((flags & 0x08) && ((offset-CE_start) < SDU_length)) proto_tree_add_item(subheader_tree, hf_mac_nr_control_long_trunc_bsr_bs_lcg3, tvb, offset++, 1, ENC_NA);
                            if ((flags & 0x10) && ((offset-CE_start) < SDU_length)) proto_tree_add_item(subheader_tree, hf_mac_nr_control_long_trunc_bsr_bs_lcg4, tvb, offset++, 1, ENC_NA);
                            if ((flags & 0x20) && ((offset-CE_start) < SDU_length)) proto_tree_add_item(subheader_tree, hf_mac_nr_control_long_trunc_bsr_bs_lcg5, tvb, offset++, 1, ENC_NA);
                            if ((flags & 0x40) && ((offset-CE_start) < SDU_length)) proto_tree_add_item(subheader_tree, hf_mac_nr_control_long_trunc_bsr_bs_lcg6, tvb, offset++, 1, ENC_NA);
                            if ((flags & 0x80) && ((offset-CE_start) < SDU_length)) proto_tree_add_item(subheader_tree, hf_mac_nr_control_long_trunc_bsr_bs_lcg7, tvb, offset++, 1, ENC_NA);

                            /* TODO: check change in offset against PDU_length */
                            /* TODO: show in string here how many BSs were seen */
                            if (lcid == LONG_BSR_LCID) {
                                write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo,
                                                                 "(Long BSR) ");
                            }
                            else {
                                write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo,
                                                                 "(Long Truncated BSR) ");
                            }
                        }
                        break;
                    case PADDING_LCID:
                        write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo, "(Padding) ");
                        /* The rest of the PDU is padding */
                        proto_tree_add_item(subheader_tree, hf_mac_nr_padding, tvb, offset, -1, ENC_NA);
                        offset = tvb_captured_length(tvb);
                        break;
                }
            }
            else {
                /* Downlink control elements */
                guint32 ta_tag_id, ta_ta;

                switch (lcid) {
                    case DUPLICATION_ACTIVATION_DEACTIVATION_LCID:
                        {
                            static const int * dupl_act_deact_flags[] = {
                                &hf_mac_nr_control_dupl_act_deact_drb7,
                                &hf_mac_nr_control_dupl_act_deact_drb6,
                                &hf_mac_nr_control_dupl_act_deact_drb5,
                                &hf_mac_nr_control_dupl_act_deact_drb4,
                                &hf_mac_nr_control_dupl_act_deact_drb3,
                                &hf_mac_nr_control_dupl_act_deact_drb2,
                                &hf_mac_nr_control_dupl_act_deact_drb1,
                                &hf_mac_nr_control_dupl_act_deact_reserved,
                                NULL
                            };
                            proto_tree_add_bitmask_list(subheader_tree, tvb, offset, 1, dupl_act_deact_flags, ENC_NA);
                            offset++;
                            write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo,
                                                             "(Dupl Act/Deact) ");
                        }
                        break;
                    case SCELL_ACTIVATION_DEACTIVATION_4:
                        {
                            static const int * scell_act_deact_1_flags[] = {
                                &hf_mac_nr_control_scell_act_deact_cell7,
                                &hf_mac_nr_control_scell_act_deact_cell6,
                                &hf_mac_nr_control_scell_act_deact_cell5,
                                &hf_mac_nr_control_scell_act_deact_cell4,
                                &hf_mac_nr_control_scell_act_deact_cell3,
                                &hf_mac_nr_control_scell_act_deact_cell2,
                                &hf_mac_nr_control_scell_act_deact_cell1,
                                &hf_mac_nr_control_scell_act_deact_reserved,
                                NULL
                            };
                            static const int * scell_act_deact_2_flags[] = {
                                &hf_mac_nr_control_scell_act_deact_cell15,
                                &hf_mac_nr_control_scell_act_deact_cell14,
                                &hf_mac_nr_control_scell_act_deact_cell13,
                                &hf_mac_nr_control_scell_act_deact_cell12,
                                &hf_mac_nr_control_scell_act_deact_cell11,
                                &hf_mac_nr_control_scell_act_deact_cell10,
                                &hf_mac_nr_control_scell_act_deact_cell9,
                                &hf_mac_nr_control_scell_act_deact_cell8,
                                NULL
                            };
                            static const int * scell_act_deact_3_flags[] = {
                                &hf_mac_nr_control_scell_act_deact_cell23,
                                &hf_mac_nr_control_scell_act_deact_cell22,
                                &hf_mac_nr_control_scell_act_deact_cell21,
                                &hf_mac_nr_control_scell_act_deact_cell20,
                                &hf_mac_nr_control_scell_act_deact_cell19,
                                &hf_mac_nr_control_scell_act_deact_cell18,
                                &hf_mac_nr_control_scell_act_deact_cell17,
                                &hf_mac_nr_control_scell_act_deact_cell16,
                                NULL
                            };
                            static const int * scell_act_deact_4_flags[] = {
                                &hf_mac_nr_control_scell_act_deact_cell31,
                                &hf_mac_nr_control_scell_act_deact_cell30,
                                &hf_mac_nr_control_scell_act_deact_cell29,
                                &hf_mac_nr_control_scell_act_deact_cell28,
                                &hf_mac_nr_control_scell_act_deact_cell27,
                                &hf_mac_nr_control_scell_act_deact_cell26,
                                &hf_mac_nr_control_scell_act_deact_cell25,
                                &hf_mac_nr_control_scell_act_deact_cell24,
                                NULL
                            };
                            proto_tree_add_bitmask_list(subheader_tree, tvb, offset, 1, scell_act_deact_1_flags, ENC_NA);
                            offset++;
                            proto_tree_add_bitmask_list(subheader_tree, tvb, offset, 1, scell_act_deact_2_flags, ENC_NA);
                            offset++;
                            proto_tree_add_bitmask_list(subheader_tree, tvb, offset, 1, scell_act_deact_3_flags, ENC_NA);
                            offset++;
                            proto_tree_add_bitmask_list(subheader_tree, tvb, offset, 1, scell_act_deact_4_flags, ENC_NA);
                            offset++;

                            write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo,
                                                             "(SCell Act/Deact 4) ");
                        }
                        break;
                    case SCELL_ACTIVATION_DEACTIVATION_1:
                        {
                            static const int * scell_act_deact_1_flags[] = {
                                &hf_mac_nr_control_scell_act_deact_cell7,
                                &hf_mac_nr_control_scell_act_deact_cell6,
                                &hf_mac_nr_control_scell_act_deact_cell5,
                                &hf_mac_nr_control_scell_act_deact_cell4,
                                &hf_mac_nr_control_scell_act_deact_cell3,
                                &hf_mac_nr_control_scell_act_deact_cell2,
                                &hf_mac_nr_control_scell_act_deact_cell1,
                                &hf_mac_nr_control_scell_act_deact_reserved,
                                NULL
                            };
                            proto_tree_add_bitmask_list(subheader_tree, tvb, offset, 1, scell_act_deact_1_flags, ENC_NA);
                            offset++;

                            write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo, "(SCell Act/Deact 1) ");
                        }
                        break;
                    case LONG_DRX_COMMAND_LCID:
                        /* Fixed size of zero bits */
                        write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo, "(Long DRX) ");
                        break;
                    case DRX_COMMAND_LCID:
                        write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo, "(DRX) ");
                        break;
                    case TIMING_ADVANCE_COMMAND_LCID:
                        /* TAG ID (2 bits) */
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_timing_advance_tagid,
                                                     tvb, offset, 1, ENC_BIG_ENDIAN, &ta_tag_id);

                        /* Timing Advance Command (6 bits) */
                        proto_tree_add_item_ret_uint(subheader_tree, hf_mac_nr_control_timing_advance_command,
                                                     tvb, offset, 1, ENC_BIG_ENDIAN, &ta_ta);
                        offset++;

                        write_pdu_label_and_info(pdu_ti, subheader_ti, pinfo,
                                                 "(TAG=%u TA=%u) ", ta_tag_id, ta_ta);
                        break;
                    case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
                        proto_tree_add_item(subheader_tree, hf_mac_nr_control_ue_contention_resolution_identity,
                                            tvb, offset, 6, ENC_NA);
                        offset += 6;
                        write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo, "(Contention Resolution) ");
                        break;
                    case PADDING_LCID:
                        write_pdu_label_and_info_literal(pdu_ti, subheader_ti, pinfo, "(Padding) ");

                        /* The rest of the PDU is padding */
                        proto_tree_add_item(subheader_tree, hf_mac_nr_padding, tvb, offset, -1, ENC_NA);
                        offset = tvb_captured_length(tvb);
                        break;
                }
            }
        }

        /* Set subheader extent here */
        proto_item_set_end(subheader_ti, tvb, offset);

    } while (tvb_reported_length_remaining(tvb, offset));

}


/*****************************/
/* Main dissection function. */
static int dissect_mac_nr(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, void* data _U_)
{
    proto_tree          *mac_nr_tree;
    proto_item          *pdu_ti;
    proto_tree          *context_tree;
    proto_item          *context_ti, *ti;
    gint                 offset = 0;
    struct mac_nr_info *p_mac_nr_info;

    /* Set protocol name */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC-NR");

    /* Create protocol tree */
    pdu_ti = proto_tree_add_item(tree, proto_mac_nr, tvb, offset, tvb_reported_length(tvb), ENC_NA);
    proto_item_append_text(pdu_ti, " ");
    mac_nr_tree = proto_item_add_subtree(pdu_ti, ett_mac_nr);

    /* Look for packet info! */
    p_mac_nr_info = (mac_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_nr, 0);

    /* Can't dissect anything without it... */
    if (p_mac_nr_info == NULL) {
        proto_tree_add_expert(mac_nr_tree, pinfo, &ei_mac_nr_no_per_frame_data, tvb, offset, -1);
        return 0;
    }

    /* Clear info column */
    col_clear(pinfo->cinfo, COL_INFO);


    /*****************************************/
    /* Show context information              */

    /* Create context root */
    context_ti = proto_tree_add_string_format(mac_nr_tree, hf_mac_nr_context,
                                              tvb, offset, 0, "", "Context");
    context_tree = proto_item_add_subtree(context_ti, ett_mac_nr_context);
    PROTO_ITEM_SET_GENERATED(context_ti);

    /* Radio type */
    ti = proto_tree_add_uint(context_tree, hf_mac_nr_context_radio_type,
                             tvb, 0, 0, p_mac_nr_info->radioType);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Direction */
    ti = proto_tree_add_uint(context_tree, hf_mac_nr_context_direction,
                             tvb, 0, 0, p_mac_nr_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    /* RNTI type and value */
    if (p_mac_nr_info->rntiType != NO_RNTI) {
        ti = proto_tree_add_uint(context_tree, hf_mac_nr_context_rnti,
                                 tvb, 0, 0, p_mac_nr_info->rnti);
        PROTO_ITEM_SET_GENERATED(ti);
        proto_item_append_text(context_ti, " (RNTI=%u)", p_mac_nr_info->rnti);
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_nr_context_rnti_type,
                             tvb, 0, 0, p_mac_nr_info->rntiType);
    PROTO_ITEM_SET_GENERATED(ti);

    /* UEId */
    if (p_mac_nr_info->ueid != 0) {
        ti = proto_tree_add_uint(context_tree, hf_mac_nr_context_ueid,
                                 tvb, 0, 0, p_mac_nr_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    /* Dissect the MAC PDU itself. Format depends upon RNTI type. */
    switch (p_mac_nr_info->rntiType) {

        case P_RNTI:
            /* PCH PDU */
//            dissect_pch(tvb, pinfo, mac_nr_tree, pdu_ti, offset, p_mac_nr_info, tap_info);
            break;

        case RA_RNTI:
            /* RAR PDU */
            dissect_rar(tvb, pinfo, mac_nr_tree, pdu_ti, offset, p_mac_nr_info);
            break;

        case C_RNTI:
        case CS_RNTI:
            /* Can be UL-SCH or DL-SCH */
            dissect_ulsch_or_dlsch(tvb, pinfo, mac_nr_tree, pdu_ti, offset,
                                   p_mac_nr_info,
                                   context_tree);
            break;

        case SI_RNTI:
            /* BCH over DL-SCH */
//            dissect_bch(tvb, pinfo, mac_nr_tree, pdu_ti, offset, p_mac_nr_info);
            break;

        case NO_RNTI:
            /* Must be BCH over BCH... */
//            dissect_bch(tvb, pinfo, mac_nr_tree, pdu_ti, offset, p_mac_nr_info);
            break;


        default:
            break;
    }

    return -1;
}

/* Heuristic dissector looks for supported framing protocol (see header file for details) */
static gboolean dissect_mac_nr_heur(tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, void *data _U_)
{
    gint        offset = 0;
    mac_nr_info *p_mac_nr_info;
    tvbuff_t    *mac_tvb;
    guint8      tag;

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of MAC PDU payload */
    if (tvb_captured_length_remaining(tvb, offset) < (gint)(strlen(MAC_NR_START_STRING)+3+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, MAC_NR_START_STRING, strlen(MAC_NR_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(MAC_NR_START_STRING);

    /* If redissecting, use previous info struct (if available) */
    p_mac_nr_info = (mac_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_nr, 0);
    if (p_mac_nr_info == NULL) {
        /* Allocate new info struct for this frame */
        p_mac_nr_info = wmem_new0(wmem_file_scope(), mac_nr_info);

        /* Read fixed fields */
        p_mac_nr_info->radioType = tvb_get_guint8(tvb, offset++);
        p_mac_nr_info->direction = tvb_get_guint8(tvb, offset++);
        p_mac_nr_info->rntiType = tvb_get_guint8(tvb, offset++);

        /* Read optional fields */
        do {
            /* Process next tag */
            tag = tvb_get_guint8(tvb, offset++);
            switch (tag) {
                case MAC_NR_RNTI_TAG:
                    p_mac_nr_info->rnti = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case MAC_NR_UEID_TAG:
                    p_mac_nr_info->ueid = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case MAC_NR_FRAME_SUBFRAME_TAG:
                    p_mac_nr_info->sysframeNumber = tvb_get_bits16(tvb, offset<<3, 12, ENC_BIG_ENDIAN);
                    p_mac_nr_info->subframeNumber = tvb_get_bits8(tvb, ((offset+1)<<3)+4, 4);
                    offset += 2;
                    break;
                case MAC_NR_PAYLOAD_TAG:
                    /* Have reached data, so set payload length and get out of loop */
                    /* TODO: this is not correct if there is padding which isn't in frame */
                    p_mac_nr_info->length = tvb_reported_length_remaining(tvb, offset);
                    continue;
                default:
                    /* It must be a recognised tag */
                    wmem_free(wmem_file_scope(), p_mac_nr_info);
                    return FALSE;
            }
        } while (tag != MAC_NR_PAYLOAD_TAG);

        p_add_proto_data(wmem_file_scope(), pinfo, proto_mac_nr, 0, p_mac_nr_info);
    }
    else {
        offset = tvb_reported_length(tvb) - p_mac_nr_info->length;
    }

    /**************************************/
    /* OK, now dissect as MAC NR          */

    /* Create tvb that starts at actual MAC PDU */
    mac_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_mac_nr(mac_tvb, pinfo, tree, NULL);

    return TRUE;
}

/* Function to be called from outside this module (e.g. in a plugin) to get per-packet data */
mac_nr_info *get_mac_nr_proto_data(packet_info *pinfo)
{
    return (mac_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_nr, 0);
}

/* Function to be called from outside this module (e.g. in a plugin) to set per-packet data */
void set_mac_nr_proto_data(packet_info *pinfo, mac_nr_info *p_mac_nr_info)
{
    p_add_proto_data(wmem_file_scope(), pinfo, proto_mac_nr, 0, p_mac_nr_info);
}

void proto_register_mac_nr(void)
{
    static hf_register_info hf[] =
    {
        /**********************************/
        /* Items for decoding context     */
        { &hf_mac_nr_context,
            { "Context",
              "mac-nr.context", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_context_radio_type,
            { "Radio Type",
              "mac-nr.radio-type", FT_UINT8, BASE_DEC, VALS(radio_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_context_direction,
            { "Direction",
              "mac-nr.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_mac_nr_context_rnti,
            { "RNTI",
              "mac-nr.rnti", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              "RNTI associated with message", HFILL
            }
        },
        { &hf_mac_nr_context_rnti_type,
            { "RNTI Type",
              "mac-nr.rnti-type", FT_UINT8, BASE_DEC, VALS(rnti_type_vals), 0x0,
              "Type of RNTI associated with message", HFILL
            }
        },
        { &hf_mac_nr_context_ueid,
            { "UEId",
              "mac-nr.ueid", FT_UINT16, BASE_DEC, NULL, 0x0,
              "User Equipment Identifier associated with message", HFILL
            }
        },

        { &hf_mac_nr_subheader,
            { "Subheader",
              "mac-nr.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_subheader_reserved,
            { "Reserved",
              "mac-nr.subheader.reserved", FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_subheader_f,
            { "Format",
              "mac-nr.subheader.f", FT_BOOLEAN, 8, TFS(&subheader_f_vals), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_subheader_length_1_byte,
            { "SDU Length",
              "mac-nr.subheader.sdu-length", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_subheader_length_2_bytes,
            { "SDU Length",
              "mac-nr.subheader.sdu-length", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_ulsch_lcid,
            { "LCID",
              "mac-nr.ulsch.lcid", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ulsch_lcid_vals_ext, 0x3f,
              "UL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_nr_dlsch_lcid,
            { "LCID",
              "mac-nr.dlsch.lcid", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &dlsch_lcid_vals_ext, 0x3f,
              "DL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_nr_ulsch_sdu,
            { "UL-SCH SDU",
              "mac-nr.ulsch.sdu", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_dlsch_sdu,
            { "DL-SCH SDU",
              "mac-nr.dlsch.sdu", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },


        /*********************************/
        /* RAR fields                    */
        { &hf_mac_nr_rar,
            { "RAR",
              "mac-nr.rar", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_rar_e,
            { "Extension",
              "mac-nr.rar.e", FT_BOOLEAN, 8, TFS(&rar_ext_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_rar_t,
            { "Type",
              "mac-nr.rar.t", FT_BOOLEAN, 8, TFS(&rar_type_vals), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_rar_reserved,
            { "Reserved",
              "mac-nr.rar.reserved", FT_UINT8, BASE_DEC, NULL, 0x30,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_rar_subheader,
            { "Subheader",
              "mac-nr.rar.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_rar_bi,
            { "Backoff Indicator",
              "mac-nr.rar.bi", FT_UINT8, BASE_DEC, VALS(rar_bi_vals), 0x0f,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_rar_rapid,
            { "RAPID",
              "mac-nr.rar.rapid", FT_UINT8, BASE_DEC, NULL, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_rar_ta,
            { "Timing Advance",
              "mac-nr.rar.ta", FT_UINT16, BASE_DEC, NULL, 0xfff0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_rar_grant,
            { "Grant",
              "mac-nr.rar.grant", FT_UINT24, BASE_DEC, NULL, 0x0fffff,
              "UL Grant details", HFILL
            }
        },
        { &hf_mac_nr_rar_temp_crnti,
            { "Temporary C-RNTI",
              "mac-nr.rar.temp_crnti", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_nr_padding,
            { "Padding",
              "mac-nr.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_nr_control_crnti,
            { "C-RNTI",
              "mac-nr.control.crnti", FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_ue_contention_resolution_identity,
            { "UE Contention Resolution Identity",
              "mac-nr.control.ue-contention-resolution.identity", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_timing_advance_tagid,
            { "TAG ID",
              "mac-nr.control.timing-advance.tag-id", FT_UINT8, BASE_DEC, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_timing_advance_command,
            { "Timing Advance Command",
              "mac-nr.control.timing-advance.command", FT_UINT8, BASE_DEC, NULL, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_se_phr_reserved,
            { "Reserved",
              "mac-nr.control.se-phr.reserved", FT_UINT8, BASE_HEX, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_se_phr_ph,
            { "Power Headroom",
              "mac-nr.control.se-phr.ph", FT_UINT8, BASE_DEC, NULL, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_se_phr_pcmax_c,
            { "Pcmax,c",
              "mac-nr.control.se-phr.pcmax_c", FT_UINT8, BASE_DEC, NULL, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_dupl_act_deact_drb7,
            { "DRB 7",
              "mac-nr.control.dupl-act-deact.drb7", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_dupl_act_deact_drb6,
            { "DRB 6",
              "mac-nr.control.dupl-act-deact.drb6", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_dupl_act_deact_drb5,
            { "DRB 5",
              "mac-nr.control.dupl-act-deact.drb5", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x20,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_dupl_act_deact_drb4,
            { "DRB 4",
              "mac-nr.control.dupl-act-deact.drb4", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x10,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_dupl_act_deact_drb3,
            { "DRB 3",
              "mac-nr.control.dupl-act-deact.drb3", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_dupl_act_deact_drb2,
            { "DRB 2",
              "mac-nr.control.dupl-act-deact.drb2", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x04,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_dupl_act_deact_drb1,
            { "DRB 1",
              "mac-nr.control.dupl-act-deact.drb1", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_dupl_act_deact_reserved,
            { "Reserved",
              "mac-nr.control.dupl-act-deact.reserved", FT_UINT8, BASE_HEX, NULL, 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell7,
            { "Cell 7",
              "mac-nr.control.scell-act-deact.cell7", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell6,
            { "Cell 6",
              "mac-nr.control.scell-act-deact.cell6", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell5,
            { "Cell 5",
              "mac-nr.control.scell-act-deact.cell5", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x20,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell4,
            { "Cell 4",
              "mac-nr.control.scell-act-deact.cell4", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x10,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell3,
            { "Cell 3",
              "mac-nr.control.scell-act-deact.cell3", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell2,
            { "Cell 2",
              "mac-nr.control.scell-act-deact.cell2", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x04,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell1,
            { "Cell 1",
              "mac-nr.control.scell-act-deact.cell1", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_reserved,
            { "Reserved",
              "mac-nr.control.scell-act-deact.reserved", FT_UINT8, BASE_HEX, NULL, 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell15,
            { "Cell 15",
              "mac-nr.control.scell-act-deact.cell15", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell14,
            { "Cell 14",
              "mac-nr.control.scell-act-deact.cell14", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell13,
            { "Cell 13",
              "mac-nr.control.scell-act-deact.cell13", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x20,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell12,
            { "Cell 12",
              "mac-nr.control.scell-act-deact.cell12", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x10,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell11,
            { "Cell 11",
              "mac-nr.control.scell-act-deact.cell11", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell10,
            { "Cell 10",
              "mac-nr.control.scell-act-deact.cell10", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x04,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell9,
            { "Cell 9",
              "mac-nr.control.scell-act-deact.cell9", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell8,
            { "Cell 8",
              "mac-nr.control.scell-act-deact.cell8", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell23,
            { "Cell 23",
              "mac-nr.control.scell-act-deact.cell23", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell22,
            { "Cell 22",
              "mac-nr.control.scell-act-deact.cell22", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell21,
            { "Cell 21",
              "mac-nr.control.scell-act-deact.cell21", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x20,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell20,
            { "Cell 20",
              "mac-nr.control.scell-act-deact.cell20", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x10,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell19,
            { "Cell 19",
              "mac-nr.control.scell-act-deact.cell19", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell18,
            { "Cell 18",
              "mac-nr.control.scell-act-deact.cell18", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x04,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell17,
            { "Cell 17",
              "mac-nr.control.scell-act-deact.cell17", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell16,
            { "Cell 16",
              "mac-nr.control.scell-act-deact.cell16", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell31,
            { "Cell 31",
              "mac-nr.control.scell-act-deact.cell31", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell30,
            { "Cell 30",
              "mac-nr.control.scell-act-deact.cell30", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell29,
            { "Cell 29",
              "mac-nr.control.scell-act-deact.cell29", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x20,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell28,
            { "Cell 28",
              "mac-nr.control.scell-act-deact.cell28", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x10,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell27,
            { "Cell 27",
              "mac-nr.control.scell-act-deact.cell27", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell26,
            { "Cell 26",
              "mac-nr.control.scell-act-deact.cell26", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x04,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell25,
            { "Cell 25",
              "mac-nr.control.scell-act-deact.cell25", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_scell_act_deact_cell24,
            { "Cell 24",
              "mac-nr.control.scell-act-deact.cell24", FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_short_trunc_bsr_lcg_id,
            { "Logical Channel Group ID",
              "mac-nr.control.short-trunc-bsr.lcg-id", FT_UINT8, BASE_DEC, NULL, 0xe0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_short_trunc_bsr_bs,
            { "Buffer Size",
              "mac-nr.control.short-trunc-bsr.bs", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_5bits_vals_ext, 0x1f,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_short_bsr_lcg_id,
            { "Logical Channel Group ID",
              "mac-nr.control.short-bsr.lcg-id", FT_UINT8, BASE_DEC, NULL, 0xe0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_short_bsr_bs,
            { "Buffer Size",
              "mac-nr.control.short-bsr.bs", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_5bits_vals_ext, 0x1f,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_lcg7,
            { "LCG7",
              "mac-nr.control.long-bsr.lcg7", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_lcg6,
            { "LCG6",
              "mac-nr.control.long-bsr.lcg6", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_lcg5,
            { "LCG5",
              "mac-nr.control.long-bsr.lcg5", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_lcg4,
            { "LCG4",
              "mac-nr.control.long-bsr.lcg4", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_lcg3,
            { "LCG3",
              "mac-nr.control.long-bsr.lcg3", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_lcg2,
            { "LCG2",
              "mac-nr.control.long-bsr.lcg2", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_lcg1,
            { "LCG1",
              "mac-nr.control.long-bsr.lcg1", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_lcg0,
            { "LCG0",
              "mac-nr.control.long-bsr.lcg0", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_bs_lcg7,
            { "Buffer Size for LCG7",
              "mac-nr.control.long-trunc-bsr.bs.lcg7", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_8bits_vals_ext, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_bs_lcg6,
            { "Buffer Size for LCG6",
              "mac-nr.control.long-trunc-bsr.bs.lcg6", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_8bits_vals_ext, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_bs_lcg5,
            { "Buffer Size for LCG5",
              "mac-nr.control.long-trunc-bsr.bs.lcg5", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_8bits_vals_ext, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_bs_lcg4,
            { "Buffer Size for LCG4",
              "mac-nr.control.long-trunc-bsr.bs.lcg4", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_8bits_vals_ext, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_bs_lcg3,
            { "Buffer Size for LCG3",
              "mac-nr.control.long-trunc-bsr.bs.lcg3", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_8bits_vals_ext, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_bs_lcg2,
            { "Buffer Size for LCG2",
              "mac-nr.control.long-trunc-bsr.bs.lcg2", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_8bits_vals_ext, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_bs_lcg1,
            { "Buffer Size for LCG1",
              "mac-nr.control.long-trunc-bsr.bs.lcg1", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_8bits_vals_ext, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_nr_control_long_trunc_bsr_bs_lcg0,
            { "Buffer Size for LCG0",
              "mac-nr.control.long-trunc-bsr.bs.lcg0", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_8bits_vals_ext, 0x0,
              NULL, HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_mac_nr,
        &ett_mac_nr_context,
        &ett_mac_nr_subheader,
        &ett_mac_nr_rar_subheader
    };

    static ei_register_info ei[] = {
        { &ei_mac_nr_no_per_frame_data, { "mac-nr.no_per_frame_data", PI_UNDECODED, PI_WARN, "Can't dissect NR MAC frame because no per-frame info was attached!", EXPFILL }},
    };

    expert_module_t* expert_mac_nr;

    /* Register protocol. */
    proto_mac_nr = proto_register_protocol("MAC-NR", "MAC-NR", "mac-nr");
    proto_register_field_array(proto_mac_nr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mac_nr = expert_register_protocol(proto_mac_nr);
    expert_register_field_array(expert_mac_nr, ei, array_length(ei));

    /* Allow other dissectors to find this one by name. */
    register_dissector("mac-nr", dissect_mac_nr, proto_mac_nr);
}

void proto_reg_handoff_mac_nr(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_mac_nr_heur, "MAC-NR over UDP", "mac_nr_udp", proto_mac_nr, HEURISTIC_DISABLE);
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
