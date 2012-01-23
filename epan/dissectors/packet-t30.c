/* packet-t30.c
 * Routines for T.30 packet dissection
 * 2006  Alejandro Vaquero, add T30 reassemble and dissection
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <glib/gprintf.h>

#include <string.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/expert.h>

#include "packet-t38.h"
#include "packet-t30.h"

/* T30 */
static int proto_t30 = -1;
static int hf_t30_Address = -1;
static int hf_t30_Control = -1;
static int hf_t30_Facsimile_Control = -1;
static int hf_t30_fif_sm = -1;
static int hf_t30_fif_rtif = -1;
static int hf_t30_fif_3gmn = -1;
static int hf_t30_fif_v8c = -1;
static int hf_t30_fif_op = -1;
static int hf_t30_fif_rtfc = -1;
static int hf_t30_fif_rfo = -1;
static int hf_t30_fif_dsr = -1;
static int hf_t30_fif_dsr_dcs = -1;
static int hf_t30_fif_res = -1;
static int hf_t30_fif_tdcc = -1;
static int hf_t30_fif_rwc = -1;
static int hf_t30_fif_rw_dcs = -1;
static int hf_t30_fif_rlc = -1;
static int hf_t30_fif_rl_dcs = -1;
static int hf_t30_fif_msltcr = -1;
static int hf_t30_fif_mslt_dcs = -1;
static int hf_t30_fif_ext = -1;
static int hf_t30_fif_cm = -1;
static int hf_t30_fif_ecm = -1;
static int hf_t30_fif_fs_dcs = -1;
static int hf_t30_fif_t6 = -1;
static int hf_t30_fif_fvc = -1;
static int hf_t30_fif_mspc = -1;
static int hf_t30_fif_ps = -1;
static int hf_t30_fif_t43 = -1;
static int hf_t30_fif_pi = -1;
static int hf_t30_fif_vc32k = -1;
static int hf_t30_fif_r8x15 = -1;
static int hf_t30_fif_300x300 = -1;
static int hf_t30_fif_r16x15 = -1;
static int hf_t30_fif_ibrp = -1;
static int hf_t30_fif_mbrp = -1;
static int hf_t30_fif_msltchr = -1;
static int hf_t30_fif_rts = -1;
static int hf_t30_fif_sp = -1;
static int hf_t30_fif_sc = -1;
static int hf_t30_fif_passw = -1;
static int hf_t30_fif_sit = -1;
static int hf_t30_fif_rttd = -1;
static int hf_t30_fif_bft = -1;
static int hf_t30_fif_dtm = -1;
static int hf_t30_fif_edi = -1;
static int hf_t30_fif_btm = -1;
static int hf_t30_fif_rttcmmd = -1;
static int hf_t30_fif_chrm = -1;
static int hf_t30_fif_mm = -1;
static int hf_t30_fif_pm26 = -1;
static int hf_t30_fif_dnc = -1;
static int hf_t30_fif_do = -1;
static int hf_t30_fif_jpeg = -1;
static int hf_t30_fif_fcm = -1;
static int hf_t30_fif_pht = -1;
static int hf_t30_fif_12c = -1;
static int hf_t30_fif_ns = -1;
static int hf_t30_fif_ci = -1;
static int hf_t30_fif_cgr = -1;
static int hf_t30_fif_nalet = -1;
static int hf_t30_fif_naleg = -1;
static int hf_t30_fif_spscb = -1;
static int hf_t30_fif_spsco = -1;
static int hf_t30_fif_hkm = -1;
static int hf_t30_fif_rsa = -1;
static int hf_t30_fif_oc = -1;
static int hf_t30_fif_hfx40 = -1;
static int hf_t30_fif_acn2c = -1;
static int hf_t30_fif_acn3c = -1;
static int hf_t30_fif_hfx40i = -1;
static int hf_t30_fif_ahsn2 = -1;
static int hf_t30_fif_ahsn3 = -1;
static int hf_t30_fif_t441 = -1;
static int hf_t30_fif_t442 = -1;
static int hf_t30_fif_t443 = -1;
static int hf_t30_fif_plmss = -1;
static int hf_t30_fif_cg300 = -1;
static int hf_t30_fif_100x100cg = -1;
static int hf_t30_fif_spcbft = -1;
static int hf_t30_fif_ebft = -1;
static int hf_t30_fif_isp = -1;
static int hf_t30_fif_ira = -1;
static int hf_t30_fif_600x600 = -1;
static int hf_t30_fif_1200x1200 = -1;
static int hf_t30_fif_300x600 = -1;
static int hf_t30_fif_400x800 = -1;
static int hf_t30_fif_600x1200 = -1;
static int hf_t30_fif_cg600x600 = -1;
static int hf_t30_fif_cg1200x1200 = -1;
static int hf_t30_fif_dspcam = -1;
static int hf_t30_fif_dspccm = -1;
static int hf_t30_fif_bwmrcp = -1;
static int hf_t30_fif_t45 = -1;
static int hf_t30_fif_sdmc = -1;
static int hf_t30_fif_number = -1;
static int hf_t30_fif_country_code = -1;
static int hf_t30_fif_non_stand_bytes = -1;
static int hf_t30_t4_frame_num = -1;
static int hf_t30_t4_data = -1;
static int hf_t30_partial_page_fcf2 = -1;
static int hf_t30_partial_page_i1 = -1;
static int hf_t30_partial_page_i2 = -1;
static int hf_t30_partial_page_i3 = -1;
static int hf_t30_partial_page_request_frame_count = -1;
static int hf_t30_partial_page_request_frames = -1;

static gint ett_t30 = -1;
static gint ett_t30_fif = -1;

static const value_string t30_control_vals[] = {
    { 0xC0, "non-final frames within the procedure" },
    { 0xC8, "final frames within the procedure" },
    { 0,    NULL }
};

#define T30_FC_DIS  0x01
#define T30_FC_CSI  0x02
#define T30_FC_NSF  0x04
#define T30_FC_DTC  0x81
#define T30_FC_CIG  0x82
#define T30_FC_NSC  0x84
#define T30_FC_PWD  0x83
#define T30_FC_SEP  0x85
#define T30_FC_PSA  0x86
#define T30_FC_CIA  0x87
#define T30_FC_ISP  0x88
#define T30_FC_DCS  0x41
#define T30_FC_TSI  0x42
#define T30_FC_NSS  0x44
#define T30_FC_SUB  0x43
#define T30_FC_SID  0x45
#define T30_FC_TSA  0x46
#define T30_FC_IRA  0x47
#define T30_FC_CFR  0x21
#define T30_FC_FTT  0x22
#define T30_FC_CSA  0x24
#define T30_FC_EOM  0x71
#define T30_FC_MPS  0x72
#define T30_FC_EOP  0x74
#define T30_FC_PRI_EOM  0x79
#define T30_FC_PRI_MPS  0x7A
#define T30_FC_PRI_EOP  0x7C
#define T30_FC_PRI_EOP2 0x78
#define T30_FC_MCF  0x31
#define T30_FC_RTP  0x33
#define T30_FC_RTN  0x32
#define T30_FC_PIP  0x35
#define T30_FC_PIN  0x34
#define T30_FC_FDM  0x3F
#define T30_FC_DCN  0x5F
#define T30_FC_CRP  0x58
#define T30_FC_FNV  0x53
#define T30_FC_TNR  0x57
#define T30_FC_TR   0x56
#define T30_FC_MCF  0x31
#define T30_FC_PID  0x36
#define T30_FC_PPR  0x3D
#define T30_FC_RNR  0x37
#define T30_FC_CRP  0x58
#define T30_FC_CTC  0x48
#define T30_FC_CTR  0x23
#define T30_FC_PPS  0x7D
#define T30_FC_EOR  0x73
#define T30_FC_RR   0x76
#define T30_FC_ERR  0x38
#define T30_FC_FCD  0x60
#define T30_FC_RCP  0x61

const value_string t30_facsimile_control_field_vals[] = {
    { T30_FC_DIS, "Digital Identification Signal" },
    { T30_FC_CSI, "Called Subscriber Identification" },
    { T30_FC_NSF, "Non-Standard Facilities" },
    { T30_FC_DTC, "Digital Transmit Command" },
    { T30_FC_CIG, "Calling Subscriber Identification" },
    { T30_FC_NSC, "Non-Standard facilities Command" },
    { T30_FC_PWD, "Password" },
    { T30_FC_SEP, "Selective Polling" },
    { T30_FC_PSA, "Polled Subaddress" },
    { T30_FC_CIA, "Calling subscriber Internet Address" },
    { T30_FC_ISP, "Internet Selective Polling Address" },
    { T30_FC_DCS, "Digital Command Signal" },
    { T30_FC_TSI, "Transmitting Subscriber Identification" },
    { T30_FC_NSS, "Non-Standard facilities Set-up" },
    { T30_FC_SUB, "Subaddress" },
    { T30_FC_SID, "Sender Identification" },
    { T30_FC_TSA, "Transmitting Subscriber Internet address" },
    { T30_FC_IRA, "Internet Routing Address" },
    { T30_FC_CFR, "Confirmation To Receive" },
    { T30_FC_FTT, "Failure To Train" },
    { T30_FC_CSA, "Called Subscriber Internet Address" },
    { T30_FC_EOM, "End Of Message" },
    { T30_FC_MPS, "MultiPage Signal" },
    { T30_FC_EOP, "End Of Procedure" },
    { T30_FC_PRI_EOM, "Procedure Interrupt-End Of Message" },
    { T30_FC_PRI_MPS, "Procedure Interrupt-MultiPage Signal" },
    { T30_FC_PRI_EOP, "Procedure Interrupt-End Of Procedure" },
    { T30_FC_PRI_EOP2, "Procedure Interrupt-End Of Procedure" },
    { T30_FC_MCF, "Message Confirmation" },
    { T30_FC_RTP, "Retrain Positive" },
    { T30_FC_RTN, "Retrain Negative" },
    { T30_FC_PIP, "Procedure Interrupt Positive" },
    { T30_FC_PIN, "Procedure Interrupt Negative" },
    { T30_FC_FDM, "File Diagnostics Message" },
    { T30_FC_DCN, "Disconnect" },
    { T30_FC_CRP, "Command Repeat" },
    { T30_FC_FNV, "Field Not Valid" },
    { T30_FC_TNR, "Transmit not ready" },
    { T30_FC_TR, "Transmit ready" },
    { T30_FC_MCF, "Message Confirmation" },
    { T30_FC_PID, "Procedure Interrupt Disconnect" },
    { T30_FC_PPR, "Partial Page Request" },
    { T30_FC_RNR, "Receive Not Ready" },
    { T30_FC_CRP, "Command Repeat" },
    { T30_FC_CTC, "Continue To Correct" },
    { T30_FC_CTR, "Response for Continue To Correct" },
    { T30_FC_PPS, "Partial Page Signal" },
    { T30_FC_EOR, "End Of Retransmission" },
    { T30_FC_RR, "Receive Ready" },
    { T30_FC_ERR, "Response for End of Retransmission" },
    { T30_FC_FCD, "Facsimile coded data" },
    { T30_FC_RCP, "Return to control for partial page" },
    { 0, NULL }
};

const value_string t30_facsimile_control_field_vals_short[] = {
    { T30_FC_DIS, "DIS" },
    { T30_FC_CSI, "CSI" },
    { T30_FC_NSF, "NSF" },
    { T30_FC_DTC, "DTC" },
    { T30_FC_CIG, "CIG" },
    { T30_FC_NSC, "NSC" },
    { T30_FC_PWD, "PWD" },
    { T30_FC_SEP, "SEP" },
    { T30_FC_PSA, "PSA" },
    { T30_FC_CIA, "CIA" },
    { T30_FC_ISP, "ISP" },
    { T30_FC_DCS, "DCS" },
    { T30_FC_TSI, "TSI" },
    { T30_FC_NSS, "NSS" },
    { T30_FC_SUB, "SUB" },
    { T30_FC_SID, "SID" },
    { T30_FC_TSA, "TSA" },
    { T30_FC_IRA, "IRA" },
    { T30_FC_CFR, "CFR" },
    { T30_FC_FTT, "FTT" },
    { T30_FC_CSA, "CSA" },
    { T30_FC_EOM, "EOM" },
    { T30_FC_MPS, "MPS" },
    { T30_FC_EOP, "EOP" },
    { T30_FC_PRI_EOM, "PRI_EOM" },
    { T30_FC_PRI_MPS, "PRI_MPS" },
    { T30_FC_PRI_EOP, "EOP" },
    { T30_FC_PRI_EOP2, "EOP2" },
    { T30_FC_MCF, "MCF" },
    { T30_FC_RTP, "RTP" },
    { T30_FC_RTN, "RTN" },
    { T30_FC_PIP, "PIP" },
    { T30_FC_PIN, "PIN" },
    { T30_FC_FDM, "FDM" },
    { T30_FC_DCN, "DCN" },
    { T30_FC_CRP, "CRP" },
    { T30_FC_FNV, "FNV" },
    { T30_FC_TNR, "TNR" },
    { T30_FC_TR, "TR" },
    { T30_FC_MCF, "MCF" },
    { T30_FC_PID, "PID" },
    { T30_FC_PPR, "PPR" },
    { T30_FC_RNR, "RNR" },
    { T30_FC_CRP, "CRP" },
    { T30_FC_CTC, "CTC" },
    { T30_FC_CTR, "CTR" },
    { T30_FC_PPS, "PPS" },
    { T30_FC_EOR, "EOR" },
    { T30_FC_RR, "RR" },
    { T30_FC_ERR, "ERR" },
    { T30_FC_FCD, "FCD" },
    { T30_FC_RCP, "RCP" },
    { 0, NULL }
};

static const value_string t30_data_signalling_rate_vals[] = {
    { 0x00, "ITU-T V.27 ter fall-back mode" },
    { 0x04, "ITU-T V.27 ter" },
    { 0x08, "ITU-T V.29" },
    { 0x0C, "ITU-T V.27 ter and V.29" },
    { 0x02, "Not used" },
    { 0x06, "Reserved" },
    { 0x0A, "Not used" },
    { 0x0E, "Invalid" },
    { 0x01, "Not used" },
    { 0x05, "Reserved" },
    { 0x09, "Not used" },
    { 0x0D, "ITU-T V.27 ter, V.29, and V.17" },
    { 0x03, "Not used" },
    { 0x07, "Reserved" },
    { 0x0B, "Not used" },
    { 0x0F, "Reserved" },
    { 0,    NULL }
};

static const value_string t30_data_signalling_rate_dcs_vals[] = {
    { 0x00, "2400 bit/s, ITU-T V.27 ter" },
    { 0x04, "4800 bit/s, ITU-T V.27 ter" },
    { 0x08, "9600 bit/s, ITU-T V.29" },
    { 0x0C, "7200 bit/s, ITU-T V.29" },
    { 0x02, "Invalid" },
    { 0x06, "Invalid" },
    { 0x0A, "Reserved" },
    { 0x0E, "Reserved" },
    { 0x01, "14 400 bit/s, ITU-T V.17" },
    { 0x05, "12 000 bit/s, ITU-T V.17" },
    { 0x09, "9600 bit/s, ITU-T V.17" },
    { 0x0D, "7200 bit/s, ITU-T V.17" },
    { 0x03, "Reserved" },
    { 0x07, "Reserved" },
    { 0x0B, "Reserved" },
    { 0x0F, "Reserved" },
    { 0,    NULL }
};

static const value_string t30_recording_width_capabilities_vals[] = {
    { 0x00, "Scan line length 215 mm +- 1%" },
    { 0x01, "Scan line length 215 mm +- 1% and Scan line length 255 mm +- 1% and Scan line length 303 mm +- 1%" },
    { 0x02, "Scan line length 215 mm +- 1% and Scan line length 255 mm +- 1%" },
    { 0x03, "Invalid" },
    { 0,    NULL }
};

static const value_string t30_recording_width_dcs_vals[] = {
    { 0x00, "Scan line length 215 mm +- 1%" },
    { 0x01, "Scan line length 303 mm +- 1%" },
    { 0x02, "Scan line length 255 mm +- 1%" },
    { 0x03, "Invalid" },
    { 0,    NULL }
};

static const value_string t30_recording_length_capability_vals[] = {
    { 0x00, "A4 (297 mm)" },
    { 0x01, "Unlimited" },
    { 0x02, "A4 (297 mm) and B4 (364 mm)" },
    { 0x03, "Invalid" },
    { 0,    NULL }
};

static const value_string t30_recording_length_dcs_vals[] = {
    { 0x00, "A4 (297 mm)" },
    { 0x01, "Unlimited" },
    { 0x02, "B4 (364 mm)" },
    { 0x03, "Invalid" },
    { 0,    NULL }
};

static const value_string t30_minimum_scan_line_time_rec_vals[] = {
    { 0x00, "20 ms at 3.85 l/mm: T7.7 = T3.85" },
    { 0x01, "40 ms at 3.85 l/mm: T7.7 = T3.85" },
    { 0x02, "10 ms at 3.85 l/mm: T7.7 = T3.85" },
    { 0x04, "05 ms at 3.85 l/mm: T7.7 = T3.85" },
    { 0x03, "10 ms at 3.85 l/mm: T7.7 = 1/2 T3.85" },
    { 0x06, "20 ms at 3.85 l/mm: T7.7 = 1/2 T3.85" },
    { 0x05, "40 ms at 3.85 l/mm: T7.7 = 1/2 T3.85" },
    { 0x07, "00 ms at 3.85 l/mm: T7.7 = T3.85" },
    { 0,    NULL }
};

static const value_string t30_partial_page_fcf2_vals[] = {
    { 0x00, "NULL code which indicates the partial page boundary" },
    { 0xF1, "EOM in optional T.4 error correction mode" },
    { 0xF2, "MPS in optional T.4 error correction mode" },
    { 0xF4, "EOP in optional T.4 error correction mode" },
    { 0xF8, "EOS in optional T.4 error correction mode" },
    { 0xF9, "PRI-EOM in optional T.4 error correction mode" },
    { 0xFA, "PRI-MPS in optional T.4 error correction mode" },
    { 0xFC, "PRI-EOP in optional T.4 error correction mode" },
    { 0,    NULL }
};

static const value_string t30_minimum_scan_line_time_dcs_vals[] = {
    { 0x00, "20 ms" },
    { 0x01, "40 ms" },
    { 0x02, "10 ms" },
    { 0x04, "05 ms" },
    { 0x07, "00 ms" },
    { 0,    NULL }
};

static const value_string t30_SharedDataMemory_capacity_vals[] = {
    { 0x00, "Not available" },
    { 0x01, "Level 1 = 1.0 Mbytes" },
    { 0x02, "Level 2 = 2.0 Mbytes" },
    { 0x03, "Level 3 = unlimited (i.e. >= 32 Mbytes)" },
    { 0,    NULL }
};

static const true_false_string t30_octets_preferred_value = {
    "64 octets preferred",
    "256 octets preferred",
};

static const true_false_string t30_extension_ind_value = {
    "information continues through the next octet",
    "last octet",
};

static const true_false_string t30_compress_value = {
    "Uncompressed mode",
    "Compressed mode",
};

static const true_false_string t30_minimum_scan_value = {
    "T15.4 = 1/2 T7.7",
    "T15.4 = T7.7",
};

static const true_false_string t30_duplex_operation_value = {
    "Duplex  and half duplex operation",
    "Half duplex operation only",
};

static const true_false_string t30_frame_size_dcs_value = {
    "64 octets",
    "256 octets",
};

static const true_false_string t30_res_type_sel_value = {
    "inch based resolution",
    "metric based resolution",
};

static guint8
reverse_byte(guint8 val)
{
    return ( ((val & 0x80)>>7) | ((val & 0x40)>>5) |
        ((val & 0x20)>>3) | ((val & 0x10)>>1) |
        ((val & 0x08)<<1) | ((val & 0x04)<<3) |
        ((val & 0x02)<<5) | ((val & 0x01)<<7) );
}

#define LENGTH_T30_NUM  20
static gchar *
t30_get_string_numbers(tvbuff_t *tvb, int offset, int len)
{
    gchar *buf;
    int i;

    /* the length must be 20 bytes per T30 rec*/
    if (len != LENGTH_T30_NUM)
        return NULL;

    buf=ep_alloc(LENGTH_T30_NUM+1);

    for (i=0; i<LENGTH_T30_NUM; i++)
        buf[LENGTH_T30_NUM-i-1] = reverse_byte(tvb_get_guint8(tvb, offset+i));

    /* add end of string */
    buf[LENGTH_T30_NUM] = '\0';

    return g_strstrip(buf);

}

static void
dissect_t30_numbers(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
    gchar *str_num=NULL;

    str_num = t30_get_string_numbers(tvb, offset, len);
    if (str_num) {
        proto_tree_add_string_format(tree, hf_t30_fif_number, tvb, offset, LENGTH_T30_NUM, str_num,
                                     "Number: %s", str_num);

        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Number:%s", str_num );

        if (pinfo->private_data)
            g_snprintf(((t38_packet_info*)pinfo->private_data)->desc, MAX_T38_DESC, "Num: %s", str_num);
    }
    else {
        proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                            "[MALFORMED OR SHORT PACKET: number of digits must be 20]");

        col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET: number of digits must be 20]" );
    }
}

static void
dissect_t30_facsimile_coded_data(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
    guint8 octet;
    guint8 *t4_data;

    if (len < 2) {
        proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                            "[MALFORMED OR SHORT PACKET: FCD length must be at least 2 bytes]");
        expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 FCD length must be at least 2 bytes");
        col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");
        return;
    }

    octet = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_t30_t4_frame_num, tvb, offset, 1, reverse_byte(octet));
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_append_fstr(pinfo->cinfo, COL_INFO, " - Frame num:%d", reverse_byte(octet));

    if (pinfo->private_data)
        g_snprintf(((t38_packet_info*)pinfo->private_data)->desc, MAX_T38_DESC, "Frm num: %d", reverse_byte(octet));

    t4_data = ep_alloc(len-1);
    tvb_memcpy(tvb, t4_data, offset, len-1);
    proto_tree_add_bytes(tree, hf_t30_t4_data, tvb, offset, len-1, t4_data);
}

static void
dissect_t30_non_standard_cap(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
    guint8 octet;
    guint8 *non_standard_bytes;

    if (len < 2) {
        proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                            "[MALFORMED OR SHORT PACKET: NSC length must be at least 2 bytes]");
        expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 NSC length must be at least 2 bytes");
        col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");
        return;
    }

    octet = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_t30_fif_country_code, tvb, offset, 1, octet);
    offset++;

    non_standard_bytes = ep_alloc(len-1);
    tvb_memcpy(tvb, non_standard_bytes, offset, len-1);
    proto_tree_add_bytes(tree, hf_t30_fif_non_stand_bytes, tvb, offset, len-1, non_standard_bytes);

}

static void
dissect_t30_partial_page_signal(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
    guint8 octet, page_count, block_count, frame_count;

    if (len != 4) {
        proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                            "[MALFORMED OR SHORT PACKET: PPS length must be 4 bytes]");
        expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 PPS length must be 4 bytes");
        col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");
        return;
    }

    octet = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_t30_partial_page_fcf2, tvb, offset, 1, octet);
    offset += 1;

    octet = tvb_get_guint8(tvb, offset);
    page_count = reverse_byte(octet);
    proto_tree_add_uint(tree, hf_t30_partial_page_i1, tvb, offset, 1, page_count);
    offset++;

    octet = tvb_get_guint8(tvb, offset);
    block_count = reverse_byte(octet);
    proto_tree_add_uint(tree, hf_t30_partial_page_i2, tvb, offset, 1, block_count);
    offset++;

    octet = tvb_get_guint8(tvb, offset);
    frame_count = reverse_byte(octet);
    proto_tree_add_uint(tree, hf_t30_partial_page_i3, tvb, offset, 1, frame_count);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_append_fstr(pinfo->cinfo, COL_INFO, " - PC:%d BC:%d FC:%d", page_count, block_count, frame_count);

    if (pinfo->private_data)
        g_snprintf(((t38_packet_info*)pinfo->private_data)->desc, MAX_T38_DESC,
                   "PC:%d BC:%d FC:%d", page_count, block_count, frame_count);

}

static void
dissect_t30_partial_page_request(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
    int frame_count = 0;
    int frame;
#define BUF_SIZE  (10*1 + 90*2 + 156*3 + 256*2 + 1) /* 0..9 + 10..99 + 100..255 + 256*', ' + \0 */
    gchar *buf = ep_alloc(BUF_SIZE);
    gchar *buf_top = buf;

    if (len != 32) {
        proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                            "[MALFORMED OR SHORT PACKET: PPR length must be 32 bytes]");
        expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 PPR length must be 32 bytes");
        col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");
        return;
    }

    for (frame=0; frame < 255; ) {
        guint8 octet = tvb_get_guint8(tvb, offset);
        guint8 bit = 1<<7;

        for (;bit;) {
            if (octet & bit) {
                ++frame_count;
                buf_top += g_snprintf(buf_top, BUF_SIZE - (gulong)(buf_top - buf), "%u, ", frame);
            }
            bit >>= 1;
            ++frame;
        }
        ++offset;
    }
    proto_tree_add_uint(tree, hf_t30_partial_page_request_frame_count, tvb, offset, 1, frame_count);
    if (buf_top > buf+1) {
        buf_top[-2] = '\0';
        proto_tree_add_string_format(tree, hf_t30_partial_page_request_frames, tvb, offset, (gint)(buf_top-buf),
                                     buf, "Frames: %s", buf);
    }

    if (check_col(pinfo->cinfo, COL_INFO))
        col_append_fstr(pinfo->cinfo, COL_INFO, " - %d frames", frame_count);

}

static void
dissect_t30_dis_dtc(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree, gboolean dis_dtc)
{
    guint8 octet;

    if (len < 3) {
        proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                            "[MALFORMED OR SHORT PACKET: DIS length must be at least 4 bytes]");
        expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 DIS length must be at least 4 bytes");
        col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");
        return;
    }

    /* bits 1 to 8 */
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_sm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_rtif, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_3gmn, tvb, offset, 1, octet);
    if (dis_dtc) {
        proto_tree_add_boolean(tree, hf_t30_fif_v8c, tvb, offset, 1, octet);
        proto_tree_add_boolean(tree, hf_t30_fif_op, tvb, offset, 1, octet);
    }
    /* bits 9 to 16 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    if (dis_dtc)
        proto_tree_add_boolean(tree, hf_t30_fif_rtfc, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_rfo, tvb, offset, 1, octet);
    if (dis_dtc) {
        proto_tree_add_uint(tree, hf_t30_fif_dsr, tvb, offset, 1, octet);

        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " - DSR:%s",
                            val_to_str_const((octet&0x3C) >> 2, t30_data_signalling_rate_vals, "<unknown>"));

        if (pinfo->private_data)
          g_snprintf(((t38_packet_info*)pinfo->private_data)->desc, MAX_T38_DESC,
                     "DSR:%s",
                     val_to_str_const((octet&0x3C) >> 2, t30_data_signalling_rate_vals, "<unknown>"));
    }
    else {
        proto_tree_add_uint(tree, hf_t30_fif_dsr_dcs, tvb, offset, 1, octet);

        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " - DSR:%s",
                            val_to_str_const((octet&0x3C) >> 2, t30_data_signalling_rate_dcs_vals, "<unknown>"));

        if (pinfo->private_data)
          g_snprintf(((t38_packet_info*)pinfo->private_data)->desc, MAX_T38_DESC,
                     "DSR:%s",
                     val_to_str_const((octet&0x3C) >> 2, t30_data_signalling_rate_dcs_vals, "<unknown>"));
    }
    proto_tree_add_boolean(tree, hf_t30_fif_res, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_tdcc, tvb, offset, 1, octet);

    /* bits 17 to 24 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    if (dis_dtc) {
        proto_tree_add_uint(tree, hf_t30_fif_rwc, tvb, offset, 1, octet);
        proto_tree_add_uint(tree, hf_t30_fif_rlc, tvb, offset, 1, octet);
        proto_tree_add_uint(tree, hf_t30_fif_msltcr, tvb, offset, 1, octet);
    } else {
        proto_tree_add_uint(tree, hf_t30_fif_rw_dcs, tvb, offset, 1, octet);
        proto_tree_add_uint(tree, hf_t30_fif_rl_dcs, tvb, offset, 1, octet);
        proto_tree_add_uint(tree, hf_t30_fif_mslt_dcs, tvb, offset, 1, octet);
    }
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 4) )
        return; /* no extension */

    /* bits 25 to 32 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_cm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ecm, tvb, offset, 1, octet);
    if (!dis_dtc)
        proto_tree_add_boolean(tree, hf_t30_fif_fs_dcs, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t6, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 5) )
        return; /* no extension */

    /* bits 33 to 40 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_fvc, tvb, offset, 1, octet);
    if (dis_dtc) {
        proto_tree_add_boolean(tree, hf_t30_fif_mspc, tvb, offset, 1, octet);
        proto_tree_add_boolean(tree, hf_t30_fif_ps, tvb, offset, 1, octet);
    }
    proto_tree_add_boolean(tree, hf_t30_fif_t43, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_pi, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_vc32k, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 6) )
        return; /* no extension */

    /* bits 41 to 48 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_r8x15, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_300x300, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_r16x15, tvb, offset, 1, octet);
    if (dis_dtc) {
        proto_tree_add_boolean(tree, hf_t30_fif_ibrp, tvb, offset, 1, octet);
        proto_tree_add_boolean(tree, hf_t30_fif_mbrp, tvb, offset, 1, octet);
        proto_tree_add_boolean(tree, hf_t30_fif_msltchr, tvb, offset, 1, octet);
        proto_tree_add_boolean(tree, hf_t30_fif_sp, tvb, offset, 1, octet);
    } else {
        proto_tree_add_boolean(tree, hf_t30_fif_rts, tvb, offset, 1, octet);
    }
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 7) )
        return; /* no extension */

    /* bits 49 to 56 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_sc, tvb, offset, 1, octet);
    if (dis_dtc) {
        proto_tree_add_boolean(tree, hf_t30_fif_passw, tvb, offset, 1, octet);
        proto_tree_add_boolean(tree, hf_t30_fif_rttd, tvb, offset, 1, octet);
    } else {
        proto_tree_add_boolean(tree, hf_t30_fif_sit, tvb, offset, 1, octet);
    }
    proto_tree_add_boolean(tree, hf_t30_fif_bft, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_dtm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_edi, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 8) )
        return; /* no extension */

    /* bits 57 to 64 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_btm, tvb, offset, 1, octet);
    if (dis_dtc)
        proto_tree_add_boolean(tree, hf_t30_fif_rttcmmd, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_chrm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_mm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 9) )
        return; /* no extension */

    /* bits 65 to 72 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_pm26, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_dnc, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_do, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_jpeg, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_fcm, tvb, offset, 1, octet);
    if (!dis_dtc)
        proto_tree_add_boolean(tree, hf_t30_fif_pht, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_12c, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 10) )
        return;    /* no extension */

    /* bits 73 to 80 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_ns, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ci, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_cgr, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_nalet, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_naleg, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_spscb, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_spsco, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 11) )
        return;    /* no extension */

    /* bits 81 to 88 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_hkm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_rsa, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_oc, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_hfx40, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_acn2c, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_acn3c, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_hfx40i, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 12) )
        return;    /* no extension */

    /* bits 89 to 96 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_ahsn2, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ahsn3, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t441, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t442, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t443, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_plmss, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 13) )
        return;    /* no extension */

    /* bits 97 to 104 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_cg300, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_100x100cg, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_spcbft, tvb, offset, 1, octet);
    if (dis_dtc) {
        proto_tree_add_boolean(tree, hf_t30_fif_ebft, tvb, offset, 1, octet);
        proto_tree_add_boolean(tree, hf_t30_fif_isp, tvb, offset, 1, octet);
    }
    proto_tree_add_boolean(tree, hf_t30_fif_ira, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 14) )
        return;    /* no extension */

    /* bits 105 to 112 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_600x600, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_1200x1200, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_300x600, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_400x800, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_600x1200, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_cg600x600, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_cg1200x1200, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) || (len < 15) )
        return;    /* no extension */

    /* bits 113 to 120 */
    offset += 1;
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_dspcam, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_dspccm, tvb, offset, 1, octet);
    if (dis_dtc)
        proto_tree_add_boolean(tree, hf_t30_fif_bwmrcp, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t45, tvb, offset, 1, octet);
    proto_tree_add_uint(tree, hf_t30_fif_sdmc, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

    if ( !(octet & 0x01) )
        return;  /* no extension */

}

static int
dissect_t30_hdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_item *it;
    proto_tree *tr;
    proto_tree *tr_fif;
    proto_item *it_fcf;
    guint8 octet;
    guint32 frag_len;
    proto_item *item;

    if (tvb_reported_length_remaining(tvb, offset) < 3) {
        proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                            "[MALFORMED OR SHORT PACKET: hdlc T30 length must be at least 4 bytes]");
        expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 length must be at least 4 bytes");
        col_append_str(pinfo->cinfo, COL_INFO, " (HDLC Reassembled: [MALFORMED OR SHORT PACKET])");
        return offset;
    }

    col_append_str(pinfo->cinfo, COL_INFO, " (HDLC Reassembled:");

    it=proto_tree_add_protocol_format(tree, proto_t30, tvb, offset, -1,
                                      "ITU-T Recommendation T.30");
    tr=proto_item_add_subtree(it, ett_t30);

    octet = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_uint(tr, hf_t30_Address, tvb, offset, 1, octet);
    if (octet != 0xFF)
        expert_add_info_format(pinfo, item, PI_REASSEMBLE, PI_WARN, "T30 Address must be 0xFF");
    offset += 1;

    octet = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_uint(tr, hf_t30_Control, tvb, offset, 1, octet);
    if ((octet != 0xC0) && (octet != 0xC8))
        expert_add_info_format(pinfo, item, PI_REASSEMBLE, PI_WARN, "T30 Control Field must be 0xC0 or 0xC8");
    offset += 1;

    octet = tvb_get_guint8(tvb, offset);
    it_fcf = proto_tree_add_uint(tr, hf_t30_Facsimile_Control, tvb, offset, 1, octet & 0x7F);
    offset += 1;

    tr_fif = proto_item_add_subtree(it_fcf, ett_t30_fif);

    frag_len = tvb_length_remaining(tvb, offset);
    if (pinfo->private_data)
        ((t38_packet_info*)pinfo->private_data)->t30_Facsimile_Control = octet;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " %s - %s",
                        val_to_str_const(octet & 0x7F, t30_facsimile_control_field_vals_short, "<unknown>"),
                        val_to_str(octet & 0x7F, t30_facsimile_control_field_vals, "<unknown>") );

    switch (octet & 0x7F) {
    case T30_FC_DIS:
    case T30_FC_DTC:
        dissect_t30_dis_dtc(tvb, offset, pinfo, frag_len, tr_fif, TRUE);
        break;
    case T30_FC_DCS:
        dissect_t30_dis_dtc(tvb, offset, pinfo, frag_len, tr_fif, FALSE);
        break;
    case T30_FC_CSI:
    case T30_FC_CIG:
    case T30_FC_TSI:
    case T30_FC_PWD:
    case T30_FC_SEP:
    case T30_FC_SUB:
    case T30_FC_SID:
    case T30_FC_PSA:
        dissect_t30_numbers(tvb, offset, pinfo, frag_len, tr_fif);
        break;
    case T30_FC_NSF:
    case T30_FC_NSC:
    case T30_FC_NSS:
        dissect_t30_non_standard_cap(tvb, offset, pinfo, frag_len, tr_fif);
        break;
    case T30_FC_FCD:
        dissect_t30_facsimile_coded_data(tvb, offset, pinfo, frag_len, tr_fif);
        break;
    case T30_FC_PPS:
        dissect_t30_partial_page_signal(tvb, offset, pinfo, frag_len, tr_fif);
        break;
    case T30_FC_PPR:
        dissect_t30_partial_page_request(tvb, offset, pinfo, frag_len, tr_fif);
        break;
    }

    col_append_str(pinfo->cinfo, COL_INFO, ")");

    return offset;
}

/* Wireshark Protocol Registration */
void
proto_register_t30(void)
{
    static hf_register_info hf_t30[] =
    {
        {  &hf_t30_Address,
            { "Address", "t30.Address", FT_UINT8, BASE_HEX,
              NULL, 0, "Address Field", HFILL }},
        {  &hf_t30_Control,
            { "Control", "t30.Control", FT_UINT8, BASE_HEX,
              VALS(t30_control_vals), 0, "Control Field", HFILL }},
        {  &hf_t30_Facsimile_Control,
            { "Facsimile Control", "t30.FacsimileControl", FT_UINT8, BASE_DEC,
              VALS(t30_facsimile_control_field_vals), 0, NULL, HFILL }},

        {  &hf_t30_fif_sm,
            { "Store and forward Internet fax- Simple mode (ITU-T T.37)", "t30.fif.sm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_rtif,
            { "Real-time Internet fax (ITU T T.38)", "t30.fif.rtif", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_3gmn,
            { "3rd Generation Mobile Network", "t30.fif.3gmn", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_v8c,
            { "V.8 capabilities", "t30.fif.v8c", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
        {  &hf_t30_fif_op,
            { "Octets preferred", "t30.fif.op", FT_BOOLEAN,  8,
              TFS(&t30_octets_preferred_value), 0x02, NULL, HFILL }},
        {  &hf_t30_fif_rtfc,
            { "Ready to transmit a facsimile document (polling)", "t30.fif.rtfc", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_rfo,
            { "Receiver fax operation", "t30.fif.rfo", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_dsr,
            { "Data signalling rate", "t30.fif.dsr", FT_UINT8,  BASE_HEX,
              VALS(t30_data_signalling_rate_vals), 0x3C, NULL, HFILL }},
        {  &hf_t30_fif_dsr_dcs,
            { "Data signalling rate", "t30.fif.dsr_dcs", FT_UINT8,  BASE_HEX,
              VALS(t30_data_signalling_rate_dcs_vals), 0x3C, NULL, HFILL }},
        {  &hf_t30_fif_res,
            { "R8x7.7 lines/mm and/or 200x200 pels/25.4 mm", "t30.fif.res", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},
        {  &hf_t30_fif_tdcc,
            { "Two dimensional coding capability", "t30.fif.tdcc", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x01, NULL, HFILL }},
        {  &hf_t30_fif_rwc,
            { "Recording width capabilities", "t30.fif.rwc", FT_UINT8,  BASE_HEX,
              VALS(t30_recording_width_capabilities_vals), 0xC0, NULL, HFILL }},
        {  &hf_t30_fif_rw_dcs,
            { "Recording width", "t30.fif.rw_dcs", FT_UINT8,  BASE_HEX,
              VALS(t30_recording_width_dcs_vals), 0xC0, NULL, HFILL }},
        {  &hf_t30_fif_rlc,
            { "Recording length capability", "t30.fif.rlc", FT_UINT8,  BASE_HEX,
              VALS(t30_recording_length_capability_vals), 0x30, NULL, HFILL }},
        {  &hf_t30_fif_rl_dcs,
            { "Recording length capability", "t30.fif.rl_dcs", FT_UINT8,  BASE_HEX,
              VALS(t30_recording_length_dcs_vals), 0x30, NULL, HFILL }},
        {  &hf_t30_fif_msltcr,
            { "Minimum scan line time capability at the receiver", "t30.fif.msltcr", FT_UINT8,  BASE_HEX,
              VALS(t30_minimum_scan_line_time_rec_vals), 0x0E, NULL, HFILL }},
        {  &hf_t30_fif_mslt_dcs,
            { "Minimum scan line time", "t30.fif.mslt_dcs", FT_UINT8,  BASE_HEX,
              VALS(t30_minimum_scan_line_time_dcs_vals), 0x0E, NULL, HFILL }},
        {  &hf_t30_fif_ext,
            { "Extension indicator", "t30.fif.ext", FT_BOOLEAN,  8,
              TFS(&t30_extension_ind_value), 0x01, NULL, HFILL }},

        {  &hf_t30_fif_cm,
            { "Compress/Uncompress mode", "t30.fif.cm", FT_BOOLEAN,  8,
              TFS(&t30_compress_value), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_ecm,
            { "Error correction mode", "t30.fif.ecm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_fs_dcs,
            { "Frame size", "t30.fif.fs_dcm", FT_BOOLEAN,  8,
              TFS(&t30_frame_size_dcs_value), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_t6,
            { "T.6 coding capability", "t30.fif.t6", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},

        {  &hf_t30_fif_fvc,
            { "Field valid capability", "t30.fif.fvc", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_mspc,
            { "Multiple selective polling capability", "t30.fif.mspc", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_ps,
            { "Polled Subaddress", "t30.fif.ps", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_t43,
            { "T.43 coding", "t30.fif.t43", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_pi,
            { "Plane interleave", "t30.fif.pi", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_vc32k,
            { "Voice coding with 32k ADPCM (ITU T G.726)", "t30.fif.vc32k", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},

        {  &hf_t30_fif_r8x15,
            { "R8x15.4 lines/mm", "t30.fif.r8x15", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_300x300,
            { "300x300 pels/25.4 mm", "t30.fif.300x300", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_r16x15,
            { "R16x15.4 lines/mm and/or 400x400 pels/25.4 mm", "t30.fif.r16x15", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_ibrp,
            { "Inch based resolution preferred", "t30.fif.ibrp", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_mbrp,
            { "Metric based resolution preferred", "t30.fif.mbrp", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_msltchr,
            { "Minimum scan line time capability for higher resolutions", "t30.fif.msltchr", FT_BOOLEAN,  8,
              TFS(&t30_minimum_scan_value), 0x04, NULL, HFILL }},
        {  &hf_t30_fif_rts,
            { "Resolution type selection", "t30.fif.rts", FT_BOOLEAN,  8,
              TFS(&t30_res_type_sel_value), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_sp,
            { "Selective polling", "t30.fif.sp", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},

        {  &hf_t30_fif_sc,
            { "Subaddressing capability", "t30.fif.sc", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_passw,
            { "Password", "t30.fif.passw", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_sit,
            { "Sender Identification transmission", "t30.fif.sit", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_rttd,
            { "Ready to transmit a data file (polling)", "t30.fif.rttd", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_bft,
            { "Binary File Transfer (BFT)", "t30.fif.bft", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_dtm,
            { "Document Transfer Mode (DTM)", "t30.fif.dtm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
        {  &hf_t30_fif_edi,
            { "Electronic Data Interchange (EDI)", "t30.fif.edi", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},

        {  &hf_t30_fif_btm,
            { "Basic Transfer Mode (BTM)", "t30.fif.btm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_rttcmmd,
            { "Ready to transmit a character or mixed mode document (polling)", "t30.fif.rttcmmd", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_chrm,
            { "Character mode", "t30.fif.chrm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_mm,
            { "Mixed mode (Annex E/T.4)", "t30.fif.mm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},

        {  &hf_t30_fif_pm26,
            { "Processable mode 26 (ITU T T.505)", "t30.fif.pm26", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_dnc,
            { "Digital network capability", "t30.fif.dnc", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_do,
            { "Duplex operation", "t30.fif.do", FT_BOOLEAN,  8,
              TFS(&t30_duplex_operation_value), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_jpeg,
            { "JPEG coding", "t30.fif.jpeg", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_fcm,
            { "Full colour mode", "t30.fif.fcm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_pht,
            { "Preferred Huffman tables", "t30.fif.pht", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_12c,
            { "12 bits/pel component", "t30.fif.12c", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},

        {  &hf_t30_fif_ns,
            { "No subsampling (1:1:1)", "t30.fif.ns", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_ci,
            { "Custom illuminant", "t30.fif.ci", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_cgr,
            { "Custom gamut range", "t30.fif.cgr", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_nalet,
            { "North American Letter (215.9 x 279.4 mm) capability", "t30.fif.nalet", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_naleg,
            { "North American Legal (215.9 x 355.6 mm) capability", "t30.fif.naleg", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_spscb,
            { "Single-progression sequential coding (ITU-T T.85) basic capability", "t30.fif.spscb", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
        {  &hf_t30_fif_spsco,
            { "Single-progression sequential coding (ITU-T T.85) optional L0 capability", "t30.fif.spsco", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},

        {  &hf_t30_fif_hkm,
            { "HKM key management capability", "t30.fif.hkm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_rsa,
            { "RSA key management capability", "t30.fif.rsa", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_oc,
            { "Override capability", "t30.fif.oc", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_hfx40,
            { "HFX40 cipher capability", "t30.fif.hfx40", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_acn2c,
            { "Alternative cipher number 2 capability", "t30.fif.acn2c", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_acn3c,
            { "Alternative cipher number 3 capability", "t30.fif.acn3c", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
        {  &hf_t30_fif_hfx40i,
            { "HFX40-I hashing capability", "t30.fif.hfx40i", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},

        {  &hf_t30_fif_ahsn2,
            { "Alternative hashing system number 2 capability", "t30.fif.ahsn2", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_ahsn3,
            { "Alternative hashing system number 3 capability", "t30.fif.ahsn3", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_t441,
            { "T.44 (Mixed Raster Content)", "t30.fif.t441", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_t442,
            { "T.44 (Mixed Raster Content)", "t30.fif.t442", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_t443,
            { "T.44 (Mixed Raster Content)", "t30.fif.t443", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
        {  &hf_t30_fif_plmss,
            { "Page length maximum strip size for T.44 (Mixed Raster Content)", "t30.fif.plmss", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},

        {  &hf_t30_fif_cg300,
            { "Colour/gray-scale 300 pels/25.4 mm x 300 lines/25.4 mm or 400 pels/25.4 mm x 400 lines/25.4 mm resolution", "t30.fif.cg300", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_100x100cg,
            { "100 pels/25.4 mm x 100 lines/25.4 mm for colour/gray scale", "t30.fif.100x100cg", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_spcbft,
            { "Simple Phase C BFT Negotiations capability", "t30.fif.spcbft", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_ebft,
            { "Extended BFT Negotiations capability", "t30.fif.ebft", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_isp,
            { "Internet Selective Polling Address (ISP)", "t30.fif.isp", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_ira,
            { "Internet Routing Address (IRA)", "t30.fif.ira", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},

        {  &hf_t30_fif_600x600,
            { "600 pels/25.4 mm x 600 lines/25.4 mm", "t30.fif.600x600", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_1200x1200,
            { "1200 pels/25.4 mm x 1200 lines/25.4 mm", "t30.fif.1200x1200", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_300x600,
            { "300 pels/25.4 mm x 600 lines/25.4 mm", "t30.fif.300x600", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_400x800,
            { "400 pels/25.4 mm x 800 lines/25.4 mm", "t30.fif.400x800", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_600x1200,
            { "600 pels/25.4 mm x 1200 lines/25.4 mm", "t30.fif.600x1200", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
        {  &hf_t30_fif_cg600x600,
            { "Colour/gray scale 600 pels/25.4 mm x 600 lines/25.4 mm resolution", "t30.fif.cg600x600", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
        {  &hf_t30_fif_cg1200x1200,
            { "Colour/gray scale 1200 pels/25.4 mm x 1200 lines/25.4 mm resolution", "t30.fif.cg1200x1200", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x02, NULL, HFILL }},

        {  &hf_t30_fif_dspcam,
            { "Double sided printing capability (alternate mode)", "t30.fif.dspcam", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
        {  &hf_t30_fif_dspccm,
            { "Double sided printing capability (continuous mode)", "t30.fif.dspccm", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
        {  &hf_t30_fif_bwmrcp,
            { "Black and white mixed raster content profile (MRCbw)", "t30.fif.bwmrcp", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x20, NULL, HFILL }},
        {  &hf_t30_fif_t45,
            { "T.45 (run length colour encoding)", "t30.fif.t45", FT_BOOLEAN,  8,
              TFS(&tfs_set_notset), 0x10, NULL, HFILL }},
        {  &hf_t30_fif_sdmc,
            { "SharedDataMemory capacity", "t30.fif.sdmc", FT_UINT8,  BASE_HEX,
              VALS(t30_SharedDataMemory_capacity_vals), 0x0C, NULL, HFILL }},

        {  &hf_t30_fif_number,
            { "Number", "t30.fif.number", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL }},

        {  &hf_t30_fif_country_code,
            { "ITU-T Country code", "t30.fif.country_code", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        {  &hf_t30_fif_non_stand_bytes,
            { "Non-standard capabilities", "t30.fif.non_standard_cap", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }},

        {  &hf_t30_t4_frame_num,
            { "T.4 Frame number", "t30.t4.frame_num", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        {  &hf_t30_t4_data,
            { "T.4 Facsimile data field", "t30.t4.data", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }},

        {  &hf_t30_partial_page_fcf2,
            { "Post-message command", "t30.pps.fcf2", FT_UINT8, BASE_DEC,
              VALS(t30_partial_page_fcf2_vals), 0, NULL, HFILL }},
        {  &hf_t30_partial_page_i1,
            { "Page counter", "t30.t4.page_count", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        {  &hf_t30_partial_page_i2,
            { "Block counter", "t30.t4.block_count", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        {  &hf_t30_partial_page_i3,
            { "Frame counter", "t30.t4.frame_count", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},

        {  &hf_t30_partial_page_request_frame_count,
            { "Frame counter", "t30.ppr.frame_count", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        {  &hf_t30_partial_page_request_frames,
            { "Frames", "t30.ppr.frames", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL }},

    };

    static gint *t30_ett[] =
    {
        &ett_t30,
        &ett_t30_fif,
    };


    /* T30 */
    proto_t30 = proto_register_protocol("T.30", "T.30", "t30");
    proto_register_field_array(proto_t30, hf_t30, array_length(hf_t30));
    proto_register_subtree_array(t30_ett, array_length(t30_ett));

    new_register_dissector("t30.hdlc", dissect_t30_hdlc, proto_t30);

}

