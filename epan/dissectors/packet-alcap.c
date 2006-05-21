/* packet-alcap.c
* Routines for ALCAP (Q.2630.3) dissection
* AAL type 2 signalling protocol - Capability set 3
* 10/2003
*
* Copyright 2003, Michael Lum <mlum [AT] telostech.com>
* In association with Telos Technology Inc.
*
* Copyright 2005, Luis E. Garcia Ontanon <luis.ontanon [AT] gmail.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/prefs.h>
#include "packet-alcap.h"
#include <epan/dissectors/packet-isup.h>
#include <epan/expert.h>
#include <epan/strutil.h>

#define	ALCAP_MSG_HEADER_LEN	6
#define	ALCAP_PARM_HEADER_LEN	3
#define	FIELD_NSAP_ADDRESS_LEN	20

#define	ALCAP_SI		12

static const value_string msg_type_strings[] = {
{ 1,	"Block confirm (BLC)" },
{ 2,	"Block request (BLO)" },
{ 3,	"Confusion (CFN)" },
{ 4,	"Establish confirm (ECF)" },
{ 5,	"Establish request (ERQ)" },
{ 6,	"Release confirm (RLC)" },
{ 7,	"Release request (REL)" },
{ 8,	"Reset confirm (RSC)" },
{ 9,	"Reset request (RES)" },
{ 10,	"Unblock confirm (UBC)" },
{ 11,	"Unblock request (UBL)" },
{ 12,   "Modify Ack (MOA)" },
{ 13,   "Modify Reject (MOR)" },
{ 14,   "Modify Request (MOD)" },
{ 0, NULL }
};

static const value_string send_notification[] = {
    { 0, "Do Not Send Notification"},
    { 1, "Send Notification" },
    { 0, NULL }
};

static const value_string instruction_indicator[] = {
    { 0, "Pass On Message or Parameter"},
    { 1, "Discard Parameter" },
    { 2, "Discard Message" },
    { 3, "Release Connection" },
    { 0, NULL }
};

static const value_string msg_parm_strings[] = {
    { 1,	"Cause (CAU)" },
    { 2,	"Connection element identifier (CEID)" },
    { 3,	"Destination E.164 service endpoint address (DESEA)" },
    { 4,	"Destination NSAP service endpoint address (DNSEA)" },
    { 5,	"Link characteristics (ALC)" },
    { 6,	"Originating signalling association identifier (OSAID)" },
    { 7,	"Served user generated reference (SUGR)" },
    { 8,	"Served user transport (SUT)" },
    { 9,	"Service specific information (audio) (SSIA)" },
    { 10,	"Service specific information (multirate) (SSIM)" },
    { 11,	"Service specific information (SAR-assured) (SSISA)" },
    { 12,	"Service specific information (SAR-unassured) (SSISU)" },
    { 13,	"Test connection identifier (TCI)" },
    { 14,   "Modify Support for Link Characteristics (MSLC)" },
    { 15,   "Modify Support for Service Specific Information (MSSSI)" },
    { 16,   "Path Type (PT)" },
    { 17,   "Preferred Link Characteristics (PLC)" },
    { 18,   "Preferred Service Specific Information - Audio Extended (PSSIAE)" },
    { 19,   "Preferred Service Specific Information - Multirate Extended (PSSIME)" },
    { 20,   "Served User Correlation ID (SUCI)" },
    { 21,   "Origination NSAP Service Endpoint Address (ONSEA)" },
    { 22,   "Service Specific Information - Audio Extended (SSIAE)" },
    { 23,   "Service Specific Information - Multirate Extended (SSIME)" },
    { 24,   "Automatic Congestion Control (ACC)" },
    { 25,   "Connection Priority (CP)" },
    { 26,   "Hop Counter (HC)" },
    { 27,   "Origination E.164 Service Endpoint Address (OESEA)" },
    { 28,   "Preferred Transfer Capability - FBW (PFBW)" },
    { 29,   "Preferred Transfer Capability - VBWS (PVBWS)" },
    { 30,   "Preferred Transfer Capability - VBWT (PVBWT)" },
    { 31,   "TAR Controlled Connection (TCC)" },
    { 32,   "Transfer Capability (FBW)" },
    { 33,   "Transfer Capability (VBWS)" },
    { 34,   "Transfer Capability (VBWT)" },
    { 35,   "Transfer Capability Support (TCS)" },
    { 0, NULL },
};


static const value_string enabled_disabled[] = {
    {0, "disabled" },
    {1, "enabled" },
    {0,NULL}
};

static const value_string alaw_ulaw[] = {
    {0, "A-Law" },
    {1, "u-Law" },
    {0,NULL}
};

static const value_string cause_coding_vals[] = {
    {0, "ITU (Q.850 - Q.2610)"},
    {1, "ISO/IEC"},
    {2, "National"},
    {3, "Private"},
    {0,NULL}
};


static const value_string cause_values_itu[] = {
    { 1, "Unallocated (unassigned) number"},
    { 3, "No route to destination"},
    { 31, "Normal, unspecified"},
    { 34, "No circuit/channel available"},
    { 38, "Network out of order"},
    { 41, "Temporary failure"},
    { 42, "Switching equipment congestion"},
    { 44, "Requested circuit/channel not available"},
    { 47, "Resource unavailable, unspecified"},
    { 93, "AAL parameters cannot be supported"},
    { 95, "Invalid message, unspecified"},
    { 96, "Mandatory information element is missing"},
    { 97, "Message type non-existent or not implemented"},
    { 99, "Information element/parameter non-existent or not implemented"},
    { 100, "Invalid information element contents"},
    { 102, "Recovery on timer expiry"},
    { 110, "Message with unrecognized parameter, discarded"},
    { 111, "Protocol error, unspecified"},
    { 0, NULL }
};

static const value_string audio_profile_type[] = {
    { 0, "From I.366.2" },
    { 1, "From Organization" },
    { 2, "Custom" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const value_string congestion_level[] = {
    { 0, "Spare" },
    { 1, "Congestin Level 1 exceeded" },
    { 2, "Congestin Level 2 exceeded" },
    { 0, NULL }
};

static const value_string connection_priority[] = {
    { 0, "Level 1 (Highest)" },
    { 1, "Level 2" },
    { 2, "Level 3" },
    { 3, "Level 4" },
    { 4, "Level 5 (Lowest)" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL }
};



static const char *alcap_proto_name = "AAL type 2 signalling protocol (Q.2630)";
static const char *alcap_proto_name_short = "ALCAP";

/* Initialize the subtree pointers */
static gint ett_alcap = -1;
static gint ett_leg = -1;
static gint ett_compat = -1;
static gint ett_cau_diag = -1;

/* Initialize the protocol and registered fields */
static int proto_alcap = -1;

static int hf_alcap_dsaid = -1;
static int hf_alcap_msg_id = -1;
static int hf_alcap_compat = -1;
static int hf_alcap_compat_pass_on_sni = -1;
static int hf_alcap_compat_pass_on_ii = -1;
static int hf_alcap_compat_general_sni = -1;
static int hf_alcap_compat_general_ii = -1;

static int hf_alcap_param_id = -1;
static int hf_alcap_param_len = -1;

static int hf_alcap_unknown = -1;

static int hf_alcap_cau_coding = -1;
static int hf_alcap_cau_value_itu = -1;
static int hf_alcap_cau_value_non_itu = -1;
static int hf_alcap_cau_diag = -1;
static int hf_alcap_cau_diag_len = -1;
static int hf_alcap_cau_diag_msg = -1;
static int hf_alcap_cau_diag_param_id = -1;
static int hf_alcap_cau_diag_field_num = -1;

static int hf_alcap_ceid_pathid = -1;
static int hf_alcap_ceid_cid = -1;

static int hf_alcap_dnsea = -1;

static int hf_alcap_alc_max_br_fw = -1;
static int hf_alcap_alc_max_br_bw = -1;
static int hf_alcap_alc_avg_br_fw = -1;
static int hf_alcap_alc_avg_br_bw = -1;
static int hf_alcap_alc_max_sdu_fw = -1;
static int hf_alcap_alc_max_sdu_bw = -1;
static int hf_alcap_alc_avg_sdu_fw = -1;
static int hf_alcap_alc_avg_sdu_bw = -1;

static int hf_alcap_osaid = -1;

static int hf_alcap_sugr = -1;

static int hf_alcap_sut_len = -1;
static int hf_alcap_sut = -1;

static int hf_alcap_ssia_pr_type = -1;
static int hf_alcap_ssia_pr_id = -1;
static int hf_alcap_ssia_frm = -1;
static int hf_alcap_ssia_cmd = -1;
static int hf_alcap_ssia_mfr2 = -1;
static int hf_alcap_ssia_mfr1 = -1;
static int hf_alcap_ssia_dtmf = -1;
static int hf_alcap_ssia_cas = -1;
static int hf_alcap_ssia_fax = -1;
static int hf_alcap_ssia_pcm = -1;
static int hf_alcap_ssia_max_len = -1;
static int hf_alcap_ssia_oui = -1;

static int hf_alcap_ssim_frm = -1;
static int hf_alcap_ssim_mult = -1;
static int hf_alcap_ssim_max = -1;

static int hf_alcap_ssisa_max_sssar_fw = -1;
static int hf_alcap_ssisa_max_sssar_bw = -1;
static int hf_alcap_ssisa_max_sscop_sdu_fw = -1;
static int hf_alcap_ssisa_max_sscop_sdu_bw = -1;
static int hf_alcap_ssisa_max_sscop_uu_fw = -1;
static int hf_alcap_ssisa_max_sscop_uu_bw = -1;

static int hf_alcap_ssisu_max_sssar_fw = -1;
static int hf_alcap_ssisu_max_sssar_bw = -1;
static int hf_alcap_ssisu_ted = -1;

static int hf_alcap_pt = -1;

static int hf_alcap_plc_max_br_fw = -1;
static int hf_alcap_plc_max_br_bw = -1;
static int hf_alcap_plc_avg_br_fw = -1;
static int hf_alcap_plc_avg_br_bw = -1;
static int hf_alcap_plc_max_sdu_fw = -1;
static int hf_alcap_plc_max_sdu_bw = -1;
static int hf_alcap_plc_avg_sdu_fw = -1;
static int hf_alcap_plc_avg_sdu_bw = -1;

static int hf_alcap_pssiae_pr_type = -1;
static int hf_alcap_pssiae_pr_id = -1;
static int hf_alcap_pssiae_lb = -1;
static int hf_alcap_pssiae_rc = -1;
static int hf_alcap_pssiae_syn = -1;
static int hf_alcap_pssiae_frm = -1;
static int hf_alcap_pssiae_cmd = -1;
static int hf_alcap_pssiae_mfr2 = -1;
static int hf_alcap_pssiae_mfr1 = -1;
static int hf_alcap_pssiae_dtmf = -1;
static int hf_alcap_pssiae_cas = -1;
static int hf_alcap_pssiae_fax = -1;
static int hf_alcap_pssiae_pcm = -1;
static int hf_alcap_pssiae_max_len = -1;
static int hf_alcap_pssiae_oui = -1;

static int hf_alcap_pssime_frm = -1;
static int hf_alcap_pssime_lb = -1;
static int hf_alcap_pssime_mult = -1;
static int hf_alcap_pssime_max = -1;

static int hf_alcap_suci = -1;

static int hf_alcap_onsea = -1;

static int hf_alcap_ssiae_pr_type = -1;
static int hf_alcap_ssiae_pr_id = -1;
static int hf_alcap_ssiae_lb = -1;
static int hf_alcap_ssiae_rc = -1;
static int hf_alcap_ssiae_syn = -1;
static int hf_alcap_ssiae_frm = -1;
static int hf_alcap_ssiae_cmd = -1;
static int hf_alcap_ssiae_mfr2 = -1;
static int hf_alcap_ssiae_mfr1 = -1;
static int hf_alcap_ssiae_dtmf = -1;
static int hf_alcap_ssiae_cas = -1;
static int hf_alcap_ssiae_fax = -1;
static int hf_alcap_ssiae_pcm = -1;
static int hf_alcap_ssiae_max_len = -1;
static int hf_alcap_ssiae_oui = -1;

static int hf_alcap_ssime_frm = -1;
static int hf_alcap_ssime_lb = -1;
static int hf_alcap_ssime_mult = -1;
static int hf_alcap_ssime_max = -1;

static int hf_alcap_acc_level = -1;

static int hf_alcap_cp = -1;

static int hf_alcap_hc = -1;

static int hf_alcap_pfbw_br_fw = -1;
static int hf_alcap_pfbw_br_bw = -1;
static int hf_alcap_pfbw_bucket_fw = -1;
static int hf_alcap_pfbw_bucket_bw = -1;
static int hf_alcap_pfbw_size_fw = -1;
static int hf_alcap_pfbw_size_bw = -1;

static int hf_alcap_pvbws_br_fw = -1;
static int hf_alcap_pvbws_br_bw = -1;
static int hf_alcap_pvbws_bucket_fw = -1;
static int hf_alcap_pvbws_bucket_bw = -1;
static int hf_alcap_pvbws_size_fw = -1;
static int hf_alcap_pvbws_size_bw = -1;
static int hf_alcap_pvbws_stt = -1;

static int hf_alcap_pvbwt_peak_br_fw = -1;
static int hf_alcap_pvbwt_peak_br_bw = -1;
static int hf_alcap_pvbwt_peak_bucket_fw = -1;
static int hf_alcap_pvbwt_peak_bucket_bw = -1;
static int hf_alcap_pvbwt_sust_br_fw = -1;
static int hf_alcap_pvbwt_sust_br_bw = -1;
static int hf_alcap_pvbwt_sust_bucket_fw = -1;
static int hf_alcap_pvbwt_sust_bucket_bw = -1;
static int hf_alcap_pvbwt_size_fw = -1;
static int hf_alcap_pvbwt_size_bw = -1;

static int hf_alcap_fbw_br_fw = -1;
static int hf_alcap_fbw_br_bw = -1;
static int hf_alcap_fbw_bucket_fw = -1;
static int hf_alcap_fbw_bucket_bw = -1;
static int hf_alcap_fbw_size_fw = -1;
static int hf_alcap_fbw_size_bw = -1;

static int hf_alcap_vbws_br_fw = -1;
static int hf_alcap_vbws_br_bw = -1;
static int hf_alcap_vbws_bucket_fw = -1;
static int hf_alcap_vbws_bucket_bw = -1;
static int hf_alcap_vbws_size_fw = -1;
static int hf_alcap_vbws_size_bw = -1;
static int hf_alcap_vbws_stt = -1;

static int hf_alcap_vbwt_peak_br_fw = -1;
static int hf_alcap_vbwt_peak_br_bw = -1;
static int hf_alcap_vbwt_peak_bucket_fw = -1;
static int hf_alcap_vbwt_peak_bucket_bw = -1;
static int hf_alcap_vbwt_sust_br_fw = -1;
static int hf_alcap_vbwt_sust_br_bw = -1;
static int hf_alcap_vbwt_sust_bucket_fw = -1;
static int hf_alcap_vbwt_sust_bucket_bw = -1;
static int hf_alcap_vbwt_size_fw = -1;
static int hf_alcap_vbwt_size_bw = -1;


static int hf_alcap_leg_osaid = -1;
static int hf_alcap_leg_dsaid = -1;
static int hf_alcap_leg_pathid = -1;
static int hf_alcap_leg_cid = -1;
static int hf_alcap_leg_sugr = -1;
static int hf_alcap_leg_dnsea = -1;
static int hf_alcap_leg_onsea = -1;
static int hf_alcap_leg_frame = -1;
static int hf_alcap_leg_release_cause = -1;

static gboolean keep_persistent_info = TRUE;

se_tree_t* legs_by_dsaid = NULL;
se_tree_t* legs_by_osaid = NULL;
se_tree_t* legs_by_bearer = NULL;

static gchar* dissect_fields_unknown(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    proto_item* pi = proto_tree_add_item(tree,hf_alcap_unknown,tvb,offset,len,FALSE);
    proto_item_set_expert_flags(pi, PI_UNDECODED, PI_WARN);
    return NULL;
}

static gchar* dissect_fields_cau(packet_info* pinfo, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info) {
    /*
     * Q.2630.1 -> 7.3.1 Cause
     *
     * 7.4.16 Cause Value
     * 7.4.17 Diagnostics
     */
    
    guint coding;
    gchar* ret_str = NULL;
    proto_item* pi;
    
    if (len < 2) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    msg_info->release_cause = tvb_get_guint8(tvb, offset+1) & 0x7f;
    
    coding = tvb_get_guint8(tvb, offset) & 0x3;
    
    proto_tree_add_item(tree, hf_alcap_cau_coding, tvb, offset, 1, FALSE);
    
    if (coding == 0) {
        pi = proto_tree_add_item(tree, hf_alcap_cau_value_itu, tvb, offset+1, 1, FALSE);
        
        if ( msg_info->release_cause && msg_info->release_cause != 31 )
            expert_add_info_format(pinfo, pi, PI_RESPONSE_CODE, PI_WARN, "Abnormal Release");
        
        ret_str = ep_strdup(val_to_str(msg_info->release_cause, cause_values_itu, "Unknown(%u)"));
    } else {
        proto_tree_add_item(tree, hf_alcap_cau_value_non_itu, tvb, offset+1 , 1, FALSE);
        ret_str = ep_strdup_printf("%u", msg_info->release_cause);
    }
    
    if (!tree) return ret_str;
    
    offset += 2;
    
    if (len > 2)  {
        int diag_len = tvb_get_guint8(tvb,offset);
        
        pi = proto_tree_add_item(tree,hf_alcap_cau_diag, tvb, offset,len-2,FALSE);
        tree = proto_item_add_subtree(pi,ett_cau_diag);
        
        proto_tree_add_item(tree, hf_alcap_cau_diag_len, tvb, offset, 1, FALSE);
        
        if (diag_len) {
            switch (msg_info->release_cause) {
                case 97:
                case 99:
                case 110: {
                    proto_tree_add_item(tree, hf_alcap_cau_diag_msg, tvb, ++offset, 1, FALSE);
                    
                    while(diag_len >= 2) {
                        proto_tree_add_item(tree, hf_alcap_cau_diag_param_id, tvb, ++offset, 1, FALSE);
                        proto_tree_add_item(tree, hf_alcap_cau_diag_field_num, tvb, ++offset, 1, FALSE);
                        diag_len -= 2;
                    }
                }
                default:
                    /* XXX - TODO Q.2610 */
                    pi = proto_tree_add_text(tree,tvb,offset,diag_len,"Undecoded");
                    proto_item_set_expert_flags(pi, PI_UNDECODED, PI_WARN);
                    break;
            }
        }
    }
    return ret_str;
}

static gchar* dissect_fields_ceid(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info) {
    /*
     * Q.2630.1 -> 7.3.2 Connection Element Identifier
     *
     * 7.4.3 Path Identifier
     * 7.4.4 Channel Identifier
     */
    proto_item* pi;
    
    if (len != 5) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }        
    
    pi = proto_tree_add_item(tree,hf_alcap_ceid_pathid,tvb,offset,4,FALSE);
    
    msg_info->pathid = tvb_get_ntohl(tvb,offset);
    msg_info->cid = tvb_get_guint8(tvb,offset+4);
    
    if (msg_info->pathid == 0) {
        proto_item_append_text(pi," (All Paths in association)");
        return "Path: 0 (All Paths)";
    }
    
    pi = proto_tree_add_item(tree,hf_alcap_ceid_cid,tvb,offset+4,1,FALSE);
    
    if (msg_info->cid == 0) {
        proto_item_append_text(pi," (All CIDs in the Path)");        
        return ep_strdup_printf("Path: %u CID: 0 (Every CID)",msg_info->pathid);
    } else {
        return ep_strdup_printf("Path: %u CID: %u",msg_info->pathid,msg_info->cid);
    }    
}

static gchar* dissect_fields_desea(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.3 Destination E.164 service endpoint address
     *
     * 7.4.13 Nature of Address
     * 7.4.14 E.164 Address
     */
    e164_info_t* e164;

    if (len < 2) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }        
    
    e164 = ep_alloc(sizeof(e164_info_t));
    
    e164->e164_number_type = CALLED_PARTY_NUMBER;
    e164->nature_of_address = tvb_get_guint8(tvb,offset) & 0x7f;
    e164->E164_number_str = tvb_get_ephemeral_string(tvb,offset+1,len);
    e164->E164_number_length = len-1;
    
    dissect_e164_number(tvb, tree, offset-1, len, *e164);
    
    return NULL;
}

static gchar* dissect_fields_oesea(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.23 Origination E.164 service endpoint address
     *
     * 7.4.13 Nature of Address
     * 7.4.14 E.164 Address
     */
    e164_info_t* e164;
    
    if (len < 2) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }        
    
    e164 = ep_alloc(sizeof(e164_info_t));
    
    e164->e164_number_type = CALLING_PARTY_NUMBER;
    e164->nature_of_address = tvb_get_guint8(tvb,offset) & 0x7f;
    e164->E164_number_str = tvb_get_ephemeral_string(tvb,offset+1,len);
    e164->E164_number_length = len-1;
    
    dissect_e164_number(tvb, tree, offset-1, len, *e164);
        
    return NULL;
}

static gchar* dissect_fields_dnsea(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.4 Destination NSAP service endpoint address
     *
     * 7.4.15 NSAP Address
     */
    
    if (len < 1) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }        
    
    msg_info->dest_nsap = tvb_bytes_to_str(tvb,offset,20);

    proto_tree_add_item(tree, hf_alcap_dnsea, tvb, offset, 20, FALSE);
	dissect_nsap(tvb, offset,20, tree);
    
    return NULL;
}

static gchar* dissect_fields_onsea(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.24 Origination NSAP service endpoint address
     *
     * 7.4.15 NSAP Address
     */
    
    if (len < 1) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    msg_info->orig_nsap = tvb_bytes_to_str(tvb,offset,20);
    
    proto_tree_add_item(tree, hf_alcap_onsea, tvb, offset, 20, FALSE);
	dissect_nsap(tvb, offset,20, tree);
    
    return NULL;
}

static gchar* dissect_fields_alc(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.5 Link characteristics
     *
     * 7.4.11 CPS-SDU Bit Rate -> Maximum CPS-SDU Bit Rate
     * 7.4.11 CPS-SDU Bit Rate -> Average CPS-SDU Bit Rate
     * 7.4.12 CPS-SDU Size -> Maximum CPS-SDU Size
     * 7.4.12 CPS-SDU Size -> Average CPS-SDU Size
     */
    
    if (len != 12) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree, hf_alcap_alc_max_br_fw, tvb, offset+0, 2, FALSE);
    proto_tree_add_item(tree, hf_alcap_alc_max_br_bw, tvb, offset+2, 2, FALSE);
    proto_tree_add_item(tree, hf_alcap_alc_avg_br_fw, tvb, offset+4, 2, FALSE);
    proto_tree_add_item(tree, hf_alcap_alc_avg_br_bw, tvb, offset+6, 2, FALSE);
    proto_tree_add_item(tree, hf_alcap_alc_max_sdu_fw, tvb, offset+8, 1, FALSE);
    proto_tree_add_item(tree, hf_alcap_alc_max_sdu_bw, tvb, offset+9, 1, FALSE);
    proto_tree_add_item(tree, hf_alcap_alc_avg_sdu_fw, tvb, offset+10, 1, FALSE);
    proto_tree_add_item(tree, hf_alcap_alc_avg_sdu_bw, tvb, offset+11, 1, FALSE);
    
    return NULL;
}

static gchar* dissect_fields_plc(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.2 -> 7.3.19 Preferred Link characteristics
     *
     * 7.4.11 CPS-SDU Bit Rate -> Maximum CPS-SDU Bit Rate
     * 7.4.11 CPS-SDU Bit Rate -> Average CPS-SDU Bit Rate
     * 7.4.12 CPS-SDU Size -> Maximum CPS-SDU Size
     * 7.4.12 CPS-SDU Size -> Average CPS-SDU Size
     */
    
    if (len != 12) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree, hf_alcap_plc_max_br_fw, tvb, offset+0, 2, FALSE);
    proto_tree_add_item(tree, hf_alcap_plc_max_br_bw, tvb, offset+2, 2, FALSE);
    proto_tree_add_item(tree, hf_alcap_plc_avg_br_fw, tvb, offset+4, 2, FALSE);
    proto_tree_add_item(tree, hf_alcap_plc_avg_br_bw, tvb, offset+6, 2, FALSE);
    proto_tree_add_item(tree, hf_alcap_plc_max_sdu_fw, tvb, offset+8, 1, FALSE);
    proto_tree_add_item(tree, hf_alcap_plc_max_sdu_bw, tvb, offset+9, 1, FALSE);
    proto_tree_add_item(tree, hf_alcap_plc_avg_sdu_fw, tvb, offset+10, 1, FALSE);
    proto_tree_add_item(tree, hf_alcap_plc_avg_sdu_bw, tvb, offset+11, 1, FALSE);
    
    return NULL;
}

static gchar* dissect_fields_osaid(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.6 Originating signalling association identifier
     *
     * 7.4.2 Signalling Association Identifier -> Originating Signalling Association
     */
    if (len != 4) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    msg_info->osaid = tvb_get_ntohl(tvb,offset);
    
    proto_tree_add_item(tree, hf_alcap_osaid, tvb, offset, 4, FALSE);
    
    return NULL;
}

static gchar* dissect_fields_sugr(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.7 Served user generated reference
     *
     * 7.4.10 Served User Generated Reference
     */
    if (len != 4) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    msg_info->sugr = tvb_get_ntohl(tvb,offset);
    
    proto_tree_add_item(tree, hf_alcap_sugr, tvb, offset, 4, FALSE);
    
    return NULL;
}

static gchar* dissect_fields_suci(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.2 -> 7.3.22 Served user correlation ID
     *
     * 7.4.22 Served user correlation ID
     */
    if (len != 4) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree, hf_alcap_suci, tvb, offset, len, FALSE);
    
    return NULL;
}

static gchar* dissect_fields_ssia(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.2 -> 7.3.9 Service specific information (Audio)
     *
     * 7.4.5 Organizational Unique Identifier
     */
    if (len != 8) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree, hf_alcap_ssia_pr_type, tvb, offset+0,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_ssia_pr_id, tvb, offset+2,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_ssia_frm, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssia_cmd, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssia_mfr2, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssia_mfr1, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssia_dtmf, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssia_cas, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssia_fax, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssia_pcm, tvb, offset+3,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_ssia_max_len, tvb, offset+4,2,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_ssia_oui, tvb, offset+5,3,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_ssim(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.10 Service specific information (Multirate)
     *
     * 7.4.7 Multirate Service
     */
    if (len != 3) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_ssim_frm,tvb,offset,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssim_mult,tvb,offset,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssim_max,tvb,offset+1,2,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_ssisa(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.11 Service specific information (SAR-assured)
     *
     * 7.4.8 Segmentation and Reassembly (Assured Data Transfer)
     */
    if (len != 14) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }

    proto_tree_add_item(tree,hf_alcap_ssisa_max_sssar_fw,tvb,offset,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssisa_max_sssar_bw,tvb,offset+3,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssisa_max_sscop_sdu_fw,tvb,offset+6,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssisa_max_sscop_sdu_bw,tvb,offset+8,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssisa_max_sscop_uu_fw,tvb,offset+10,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssisa_max_sscop_uu_bw,tvb,offset+12,2,FALSE);

    proto_tree_add_text(tree,tvb,offset,14,"Not yet decoded: Q.2630.1 7.4.8");
    
    return NULL;
}

static gchar* dissect_fields_ssisu(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.12 Service specific information (SAR-unassured)
     *
     * 7.4.9 Segmentation and Reassembly (Unassured Data Transfer)
     */
    if (len != 7) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_ssisu_max_sssar_fw,tvb,offset,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssisu_max_sssar_bw,tvb,offset+3,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssisu_ted,tvb,offset+6,1,FALSE);
    proto_tree_add_text(tree,tvb,offset,7,"Not yet decoded: Q.2630.1 7.4.9");
    
    return NULL;
}

static gchar* dissect_fields_none(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * used for parameters that have no fields, just checks if len==0
     *
     * Q.2630.1 -> 7.3.13 Test connection indicator
     * Q.2630.2 -> 7.3.20 Modify support for link characteristics
     * Q.2630.2 -> 7.3.21 Modify support for service specific information
     * Q.2630.3 -> 7.3.35 Transfer capability support
     *
     */
    if (len != 0) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    return NULL;
}

static gchar* dissect_fields_ssiae(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.2 -> 7.3.15 Service specific information (Audio Extended)
     *
     * 7.4.19 Audio extended service
     * 7.4.5 Organizational unique identifier
     */
    if (len != 8) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree, hf_alcap_ssiae_pr_type, tvb, offset,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_lb, tvb, offset,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_rc, tvb, offset,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_syn, tvb, offset,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_ssiae_pr_id, tvb, offset+1,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_ssiae_frm, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_cmd, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_mfr2, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_mfr1, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_dtmf, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_cas, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_fax, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_ssiae_pcm, tvb, offset+3,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_ssiae_max_len, tvb, offset+4,2,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_ssiae_oui, tvb, offset+5,3,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_pssiae(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.2 -> 7.3.17 Preferred service specific information (Audio Extended)
     *
     * 7.4.19 Audio extended service
     * 7.4.5 Organizational unique identifier
     */
    if (len != 8) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree, hf_alcap_pssiae_pr_type, tvb, offset,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_lb, tvb, offset,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_rc, tvb, offset,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_syn, tvb, offset,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_pssiae_pr_id, tvb, offset+1,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_pssiae_frm, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_cmd, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_mfr2, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_mfr1, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_dtmf, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_cas, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_fax, tvb, offset+3,1,FALSE);
    proto_tree_add_item(tree, hf_alcap_pssiae_pcm, tvb, offset+3,1,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_pssiae_max_len, tvb, offset+4,2,FALSE);
    
    proto_tree_add_item(tree, hf_alcap_pssiae_oui, tvb, offset+5,3,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_ssime(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.2 -> 7.3.16 Service specific information (Multirate Extended)
     *
     * 7.4.20 Multirate extended service
     */
    if (len != 3) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_ssime_frm,tvb,offset,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssime_lb,tvb,offset,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssime_mult,tvb,offset,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_ssime_max,tvb,offset+1,2,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_pssime(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.2 -> 7.3.18 Preferred service specific information (Multirate Extended)
     *
     * 7.4.20 Multirate extended service
     */
    if (len != 3) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_pssime_frm,tvb,offset,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_pssime_lb,tvb,offset,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_pssime_mult,tvb,offset,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_pssime_max,tvb,offset+1,2,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_acc(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.25 Automatic congestion control
     *
     * 7.4.23 AAL type 2 Node Automatic Congestion Level
     */
    if (len != 1) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_acc_level,tvb,offset,len,FALSE);
    return NULL;
}


static gchar* dissect_fields_cp(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.26 Connection Priority
     *
     * 7.4.24 Priority
     */
    if (len != 1) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_cp,tvb,offset,len,FALSE);
    return NULL;
}

static gchar* dissect_fields_pt(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.2 -> 7.3.14 Path Type
     *
     * 7.4.21 AAL Type 2 Path QoS Codepoint
     */
    if (len != 1) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_pt,tvb,offset,len,FALSE);
    return NULL;
}


static gchar* dissect_fields_hc(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.27 Hop counter
     *
     * 7.4.25 AAL type 2 Hop Counter
     */
    if (len != 1) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_hc,tvb,offset,len,FALSE);
    return NULL;
}


static gchar* dissect_fields_fbw(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.32 Fixed bandwidth transfer capability
     *
     * 7.4.26 CPS Bit rate -> Peak CPS bit rate
     * 7.4.27 CPS Token Bucket Size -> CPS token bucket size associated with Peak CPS bit rate
     * 7.4.28 Maximum allowed CPS packet size
     */
    if (len != 12) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_fbw_br_fw,tvb,offset,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_fbw_br_bw,tvb,offset+3,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_fbw_bucket_fw,tvb,offset+6,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_fbw_bucket_bw,tvb,offset+8,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_fbw_size_fw,tvb,offset+10,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_fbw_size_bw,tvb,offset+11,1,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_pfbw(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.29 Preferred fixed bandwidth transfer capability
     *
     * 7.4.26 CPS Bit rate -> Peak CPS bit rate
     * 7.4.27 CPS Token Bucket Size -> CPS token bucket size associated with Peak CPS bit rate
     * 7.4.28 Maximum allowed CPS packet size
     */
    if (len != 12) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_pfbw_br_fw,tvb,offset,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_pfbw_br_bw,tvb,offset+3,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_pfbw_bucket_fw,tvb,offset+6,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_pfbw_bucket_bw,tvb,offset+8,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_pfbw_size_fw,tvb,offset+10,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_pfbw_size_bw,tvb,offset+11,1,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_vbws(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.33 Variable bandwidth stringent transfer capability
     *
     * 7.4.26 CPS Bit rate -> Peak CPS bit rate
     * 7.4.27 CPS Token Bucket Size -> CPS token bucket size associated with Peak CPS bit rate
     * 7.4.28 Maximum allowed CPS packet size
     * 7.4.29 Source Traffic Type
     */
    if (len != 13) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_vbws_br_fw,tvb,offset,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbws_br_bw,tvb,offset+3,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbws_bucket_fw,tvb,offset+6,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbws_bucket_bw,tvb,offset+8,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbws_size_fw,tvb,offset+10,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbws_size_bw,tvb,offset+11,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbws_size_bw,tvb,offset+11,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbws_stt,tvb,offset+12,1,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_pvbws(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.30 Preferred variable bandwidth stringent transfer capability
     *
     * 7.4.26 CPS Bit rate -> Peak CPS bit rate
     * 7.4.27 CPS Token Bucket Size -> CPS token bucket size associated with Peak CPS bit rate
     * 7.4.28 Maximum allowed CPS packet size
     * 7.4.29 Source Traffic Type
     */
    if (len != 13) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_pvbws_br_fw,tvb,offset,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbws_br_bw,tvb,offset+3,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbws_bucket_fw,tvb,offset+6,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbws_bucket_bw,tvb,offset+8,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbws_size_fw,tvb,offset+10,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbws_size_bw,tvb,offset+11,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbws_size_bw,tvb,offset+11,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbws_stt,tvb,offset+12,1,FALSE);
    
    return NULL;
}


static gchar* dissect_fields_pvbwt(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.31 Preferred variable bandwidth tolerant transfer capability
     *
     * 7.4.26 CPS Bit rate -> Peak CPS bit rate
     * 7.4.27 CPS Token Bucket Size -> CPS token bucket size associated with Peak CPS bit rate
     * 7.4.26 CPS Bit rate -> Sustainable CPS bit rate
     * 7.4.27 CPS Token Bucket Size -> CPS token bucket size associated with Sustainable CPS bit rate
     * 7.4.28 Maximum allowed CPS packet size
     */
    
    if (len != 22) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_pvbwt_peak_br_fw,tvb,offset,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbwt_peak_br_bw,tvb,offset+3,3,FALSE);
    
    proto_tree_add_item(tree,hf_alcap_pvbwt_peak_bucket_fw,tvb,offset+6,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbwt_peak_bucket_bw,tvb,offset+8,2,FALSE);
    
    proto_tree_add_item(tree,hf_alcap_pvbwt_sust_br_fw,tvb,offset+10,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbwt_sust_br_bw,tvb,offset+13,3,FALSE);
    
    proto_tree_add_item(tree,hf_alcap_pvbwt_sust_bucket_fw,tvb,offset+16,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbwt_sust_bucket_bw,tvb,offset+18,2,FALSE);
    
    proto_tree_add_item(tree,hf_alcap_pvbwt_size_fw,tvb,offset+20,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_pvbwt_size_bw,tvb,offset+21,1,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_vbwt(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.3 -> 7.3.34 Variable bandwidth tolerant transfer capability
     *
     * 7.4.26 CPS Bit rate -> Peak CPS bit rate
     * 7.4.27 CPS Token Bucket Size -> CPS token bucket size associated with Peak CPS bit rate
     * 7.4.26 CPS Bit rate -> Sustainable CPS bit rate
     * 7.4.27 CPS Token Bucket Size -> CPS token bucket size associated with Sustainable CPS bit rate
     * 7.4.28 Maximum allowed CPS packet size
     */
    if (len != 22) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    proto_tree_add_item(tree,hf_alcap_vbwt_peak_br_fw,tvb,offset,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbwt_peak_br_bw,tvb,offset+3,3,FALSE);
    
    proto_tree_add_item(tree,hf_alcap_vbwt_peak_bucket_fw,tvb,offset+6,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbwt_peak_bucket_bw,tvb,offset+8,2,FALSE);
    
    proto_tree_add_item(tree,hf_alcap_vbwt_sust_br_fw,tvb,offset+10,3,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbwt_sust_br_bw,tvb,offset+13,3,FALSE);
    
    proto_tree_add_item(tree,hf_alcap_vbwt_sust_bucket_fw,tvb,offset+16,2,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbwt_sust_bucket_bw,tvb,offset+18,2,FALSE);
    
    proto_tree_add_item(tree,hf_alcap_vbwt_size_fw,tvb,offset+20,1,FALSE);
    proto_tree_add_item(tree,hf_alcap_vbwt_size_bw,tvb,offset+21,1,FALSE);
    
    return NULL;
}

static gchar* dissect_fields_sut(packet_info* pinfo _U_, tvbuff_t *tvb, proto_tree *tree, int offset, int len, alcap_message_info_t* msg_info _U_) {
    /*
     * Q.2630.1 -> 7.3.8 Served user transport
     *
     * 7.4.18 Served User Transport
     */
    guint sut_len;
    
    if (len < 2) {
        proto_item* bad_length = proto_tree_add_text(tree, tvb, offset, len,"[Wrong length for parameter fields]");
        proto_item_set_expert_flags(bad_length, PI_MALFORMED, PI_WARN);
        return NULL;
    }
    
    sut_len = tvb_get_guint8(tvb,offset);
    
    proto_tree_add_item(tree, hf_alcap_sut_len, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_alcap_sut, tvb, offset, sut_len, FALSE);
    
    return NULL;
}

typedef gchar* (*alcap_parameter_dissector_t) (packet_info* pinfo, tvbuff_t*, proto_tree*, int, int, alcap_message_info_t*);

typedef struct _alcap_param_info_t {
    gint ett;
    const gchar* name;
    alcap_parameter_dissector_t dissect_fields;
    gboolean run_wo_tree;
} alcap_param_info_t;

static alcap_param_info_t param_infos[]  = {
    {-1, "Unknown", dissect_fields_unknown , FALSE},
    {-1, "CAU", dissect_fields_cau, TRUE},
    {-1, "CEID", dissect_fields_ceid, TRUE},
    {-1, "DESEA", dissect_fields_desea, FALSE},
    {-1, "DNSEA", dissect_fields_dnsea, TRUE},
    {-1, "ALC", dissect_fields_alc, FALSE},
    {-1, "OSAID", dissect_fields_osaid, TRUE},
    {-1, "SUGR", dissect_fields_sugr, TRUE},
    {-1, "SUT", dissect_fields_sut, FALSE},
    {-1, "SSIA", dissect_fields_ssia, FALSE},
    {-1, "SSIM", dissect_fields_ssim, FALSE},
    {-1, "SSISA", dissect_fields_ssisa, FALSE},
    {-1, "SSISU", dissect_fields_ssisu, FALSE},
    {-1, "TCI", dissect_fields_none, FALSE},
    {-1, "MSLC", dissect_fields_none, FALSE},
    {-1, "MSSSI", dissect_fields_none, FALSE},
    {-1, "PT", dissect_fields_pt, FALSE},
    {-1, "PLC", dissect_fields_plc, FALSE},
    {-1, "PSSIAE", dissect_fields_pssiae, FALSE},
    {-1, "PSSIME", dissect_fields_pssime, FALSE},
    {-1, "SUCI", dissect_fields_suci, FALSE},
    {-1, "ONSEA", dissect_fields_onsea, TRUE},
    {-1, "SSIAE", dissect_fields_ssiae, FALSE},
    {-1, "SSIME", dissect_fields_ssime, FALSE},
    {-1, "ACC", dissect_fields_acc, FALSE},
    {-1, "CP", dissect_fields_cp, FALSE},
    {-1, "HC", dissect_fields_hc, FALSE},
    {-1, "OESEA", dissect_fields_oesea, FALSE},
    {-1, "PFBW", dissect_fields_pfbw, FALSE},
    {-1, "PVBWS", dissect_fields_pvbws, FALSE},
    {-1, "PVBWT", dissect_fields_pvbwt, FALSE},
    {-1, "TTC", dissect_fields_none, FALSE},
    {-1, "FBW", dissect_fields_fbw, FALSE},
    {-1, "VBWS", dissect_fields_vbws, FALSE},
    {-1, "VBWT", dissect_fields_vbwt, FALSE},
    {-1, "TCS", dissect_fields_none, FALSE}
};

#define GET_PARAM_INFO(id) ( array_length(param_infos) <= id ? &(param_infos[0]) : &(param_infos[id]) )

typedef struct _alcap_msg_type_info_t {
    const gchar* abbr;
    int severity;
} alcap_msg_type_info_t;

static const alcap_msg_type_info_t msg_types[] = {
    { "Unknown Message ", PI_ERROR },
    { "BLC ", PI_NOTE },
    { "BLO ", PI_NOTE },
    { "CFN ", PI_WARN },
    { "ECF ", PI_CHAT },
    { "ERQ ", PI_CHAT },
    { "RLC ", PI_CHAT },
    { "REL ", PI_CHAT },
    { "RSC ", PI_NOTE },
    { "RES ", PI_NOTE },
    { "UBC ", PI_NOTE },
    { "UBL ", PI_NOTE },
    { "MOA ", PI_CHAT },
    { "MOR ", PI_CHAT },
    { "MOD ", PI_CHAT },
    { NULL, 0 }
};

static void alcap_leg_tree(proto_tree* tree, tvbuff_t* tvb, const alcap_leg_info_t* leg) {
    proto_item* pi = proto_tree_add_text(tree,tvb,0,0,"[ALCAP Leg Info]");
    
    tree = proto_item_add_subtree(pi,ett_leg);
    
    if (leg->dsaid) {
        pi = proto_tree_add_uint(tree,hf_alcap_leg_dsaid,tvb,0,0,leg->dsaid);
        PROTO_ITEM_SET_GENERATED(pi);
    }
    
    if (leg->osaid) {
        pi = proto_tree_add_uint(tree,hf_alcap_leg_osaid,tvb,0,0,leg->osaid);
        PROTO_ITEM_SET_GENERATED(pi);
    }
    
    if (leg->pathid) {
        pi = proto_tree_add_uint(tree,hf_alcap_leg_pathid,tvb,0,0,leg->pathid);
        PROTO_ITEM_SET_GENERATED(pi);
    }
    
    if (leg->cid) {
        pi = proto_tree_add_uint(tree,hf_alcap_leg_cid,tvb,0,0,leg->cid);
        PROTO_ITEM_SET_GENERATED(pi);
    }
    
    if (leg->sugr) {
        pi = proto_tree_add_uint(tree,hf_alcap_leg_sugr,tvb,0,0,leg->sugr);
        PROTO_ITEM_SET_GENERATED(pi);
    }
    
    if (leg->orig_nsap) {
        pi = proto_tree_add_string(tree,hf_alcap_leg_onsea,tvb,0,0,leg->orig_nsap);
        PROTO_ITEM_SET_GENERATED(pi);
    }
    
    if (leg->dest_nsap) {
        pi = proto_tree_add_string(tree,hf_alcap_leg_dnsea,tvb,0,0,leg->dest_nsap);
        PROTO_ITEM_SET_GENERATED(pi);
    }
    
    if(leg->release_cause) {
        pi = proto_tree_add_uint(tree,hf_alcap_leg_release_cause,tvb,0,0,leg->release_cause);
        PROTO_ITEM_SET_GENERATED(pi);
        if (leg->release_cause && leg->release_cause != 31)
            proto_item_set_expert_flags(pi, PI_RESPONSE_CODE, PI_WARN);
    }
    
    if(leg->msgs) {
        alcap_msg_data_t* msg = leg->msgs;
        proto_item* pi = proto_tree_add_text(tree,tvb,0,0,"[Messages in this leg]");
        proto_tree* tree = proto_item_add_subtree(pi,ett_leg);
        
        
        do {
            pi = proto_tree_add_uint(tree,hf_alcap_leg_frame,tvb,0,0,msg->framenum);
            proto_item_set_text(pi,"%s in frame %u", val_to_str(msg->msg_type,msg_type_strings,"Unknown message"),msg->framenum);
            PROTO_ITEM_SET_GENERATED(pi);
        } while (( msg = msg->next));
        
    }
    
}


extern void alcap_tree_from_bearer_key(proto_tree* tree, tvbuff_t* tvb, const  gchar* key) {
    alcap_leg_info_t* leg = se_tree_lookup_string(legs_by_bearer,key);
    
    if (leg) {
        alcap_leg_tree(tree,tvb,leg);
    }
}

#define GET_MSG_TYPE(id) ( array_length(msg_types) <= id ? &(msg_types[0]) : &(msg_types[id]) )

static void dissect_alcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    proto_tree	*alcap_tree = NULL;
    alcap_message_info_t* msg_info = ep_alloc0(sizeof(alcap_message_info_t));
    int	len = tvb_length(tvb);
    int offset;
    proto_item* pi;
    proto_tree* compat_tree;
    const alcap_msg_type_info_t* msg_type;
    
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, alcap_proto_name_short);
    
    if (tree) {
		proto_item	*alcap_item = proto_tree_add_item(tree, proto_alcap, tvb, 0, -1, FALSE);
		alcap_tree = proto_item_add_subtree(alcap_item, ett_alcap);
    }
	
    proto_tree_add_item(alcap_tree,hf_alcap_dsaid,tvb,0,4,FALSE);
    pi = proto_tree_add_item(alcap_tree,hf_alcap_msg_id,tvb,4,1,FALSE);
    
    msg_info->dsaid = tvb_get_ntohl(tvb, 0);
    msg_info->msg_type = tvb_get_guint8(tvb, 4);

    msg_type = GET_MSG_TYPE(msg_info->msg_type);
    
    expert_add_info_format(pinfo, pi, PI_RESPONSE_CODE, msg_type->severity, " ");
    
    if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, msg_type->abbr);
    
    
    pi = proto_tree_add_item(alcap_tree,hf_alcap_compat,tvb,5,1,FALSE);
    compat_tree = proto_item_add_subtree(pi,ett_compat);
    proto_tree_add_item(compat_tree,hf_alcap_compat_pass_on_sni,tvb,5,1,FALSE);
    proto_tree_add_item(compat_tree,hf_alcap_compat_pass_on_ii,tvb,5,1,FALSE);
    proto_tree_add_item(compat_tree,hf_alcap_compat_general_sni,tvb,5,1,FALSE);
    proto_tree_add_item(compat_tree,hf_alcap_compat_general_ii,tvb,5,1,FALSE);
    
    len -= ALCAP_MSG_HEADER_LEN;
    offset = ALCAP_MSG_HEADER_LEN;
    
    while(len > 0) {
        guint param_id = tvb_get_guint8(tvb,offset);
        guint param_len = tvb_get_guint8(tvb,offset+2);
        const alcap_param_info_t* param_info = GET_PARAM_INFO(param_id);
        proto_tree* param_tree;
        gchar* colinfo_str = NULL;
        
        pi = proto_tree_add_item(alcap_tree,hf_alcap_param_id,tvb,offset,1,FALSE);
        param_tree = proto_item_add_subtree(pi,param_info->ett);
        
        pi = proto_tree_add_item(param_tree,hf_alcap_compat,tvb,offset+1,1,FALSE);        
        compat_tree = proto_item_add_subtree(pi,ett_compat);
        proto_tree_add_item(compat_tree,hf_alcap_compat_pass_on_sni,tvb,offset+1,1,FALSE);
        proto_tree_add_item(compat_tree,hf_alcap_compat_pass_on_ii,tvb,offset+1,1,FALSE);
        proto_tree_add_item(compat_tree,hf_alcap_compat_general_sni,tvb,offset+1,1,FALSE);
        proto_tree_add_item(compat_tree,hf_alcap_compat_general_ii,tvb,offset+1,1,FALSE);
        
        proto_tree_add_item(param_tree,hf_alcap_param_len,tvb,offset+2,1,FALSE);
        
        if ( alcap_tree || param_info->run_wo_tree )
            colinfo_str = param_info->dissect_fields(pinfo,tvb,param_tree,offset+3,param_len,msg_info);
        
        if (colinfo_str && check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s",colinfo_str);
        }
        
        len -= 3 + param_len;
        offset += 3 + param_len;
    }
	
    if (keep_persistent_info) {
        alcap_leg_info_t* leg = NULL;
        switch (msg_info->msg_type) {
            case 5: /* ERQ */
                if( ! ( leg = se_tree_lookup32(legs_by_osaid,msg_info->osaid) )) { 
                    leg = se_alloc(sizeof(alcap_leg_info_t));
                    
                    leg->dsaid = 0;
                    leg->osaid = msg_info->osaid;
                    leg->pathid = msg_info->pathid;
                    leg->cid = msg_info->cid;
                    leg->sugr = msg_info->sugr;
					leg->orig_nsap = NULL;
					leg->dest_nsap = NULL;
					
					if (msg_info->orig_nsap) {
                        gchar* key = se_strdup_printf("%s:%.8X",msg_info->orig_nsap,leg->sugr);
                        g_strdown(key);
						
                        leg->orig_nsap = se_strdup(msg_info->orig_nsap);
                        
                        if (!se_tree_lookup_string(legs_by_bearer,key)) {
                            se_tree_insert_string(legs_by_bearer,key,leg);
                        }
					}
					
                    if (msg_info->dest_nsap) {
                        gchar* key = se_strdup_printf("%s:%.8X",msg_info->dest_nsap,leg->sugr);
                        g_strdown(key);
						
                        leg->dest_nsap = se_strdup(msg_info->dest_nsap);
						
                        if (!se_tree_lookup_string(legs_by_bearer,key)) {
                            se_tree_insert_string(legs_by_bearer,key,leg);
                        }
                    }
                    
                    leg->msgs = NULL;
                    leg->release_cause = 0;
                    
                    se_tree_insert32(legs_by_osaid,leg->osaid,leg);
                }
                break;
            case 4: /* ECF */
                if(( leg = se_tree_lookup32(legs_by_osaid,msg_info->dsaid) )) { 
                    leg->dsaid = msg_info->osaid;
                    se_tree_insert32(legs_by_dsaid,leg->dsaid,leg);	
                }
                break;
            case 6: /* RLC */
            case 12:  /* MOA */
            case 13: /* MOR */
            case 14: /* MOD */
                if( ( leg = se_tree_lookup32(legs_by_osaid,msg_info->dsaid) )
                    || ( leg = se_tree_lookup32(legs_by_dsaid,msg_info->dsaid) ) ) { 
                    
                    if(msg_info->release_cause)
                        leg->release_cause =  msg_info->release_cause;
                    
                }
                break;
            case 7: /* REL */
                leg = se_tree_lookup32(legs_by_osaid,msg_info->dsaid);
                
                if(leg) {
                    leg->release_cause =  msg_info->release_cause;
                } else if (( leg = se_tree_lookup32(legs_by_dsaid,msg_info->dsaid) )) {
                    leg->release_cause =  msg_info->release_cause;
                }
                    break;
            default:
                break;			
        }
        
        if (leg && ( (! leg->msgs) || leg->msgs->last->framenum < pinfo->fd->num ) ) {
            alcap_msg_data_t* msg = se_alloc(sizeof(alcap_msg_data_t));
            msg->msg_type = msg_info->msg_type;
            msg->framenum = pinfo->fd->num;
            msg->next = NULL;
            msg->last = NULL;
            
            if (leg->msgs) {
                leg->msgs->last->next = msg;
            } else {
                leg->msgs = msg;
            }
            
            leg->msgs->last = msg;
            
        }
        
        if (tree && leg) alcap_leg_tree(alcap_tree,tvb,leg);
    }
}

void
proto_register_alcap(void)
{
    module_t *alcap_module;
    
    static hf_register_info hf[] = {
    { &hf_alcap_dsaid, { "DSAID", "alcap.dsaid", FT_UINT32, BASE_HEX, NULL, 0, "Destination Service Association ID", HFILL }},
    { &hf_alcap_msg_id, { "Message Type", "alcap.msg_type", FT_UINT8, BASE_DEC, VALS(msg_type_strings), 0, "", HFILL }},
    { &hf_alcap_compat, { "Message Compatibility", "alcap.compat", FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }},
    { &hf_alcap_compat_pass_on_sni, { "Pass-On SNI", "alcap.compat.pass.sni", FT_UINT8, BASE_DEC, VALS(send_notification), 0x40, "Send Notificaation Indicator", HFILL }},
    { &hf_alcap_compat_pass_on_ii, { "Pass-On II", "alcap.compat.pass.ii", FT_UINT8, BASE_DEC, VALS(instruction_indicator), 0x30, "Instruction Indicator", HFILL }},
    { &hf_alcap_compat_general_sni, { "General SNI", "alcap.compat.general.sni", FT_UINT8, BASE_DEC, VALS(send_notification), 0x04, "Send Notificaation Indicator", HFILL }},
    { &hf_alcap_compat_general_ii, { "General II", "alcap.compat.general.ii", FT_UINT8, BASE_DEC, VALS(instruction_indicator), 0x03, "Instruction Indicator", HFILL }},
        
    { &hf_alcap_unknown, { "Unknown Field Data", "alcap.unknown.field", FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }},
        
    { &hf_alcap_param_id, { "Parameter", "alcap.param", FT_UINT8, BASE_DEC, VALS(msg_parm_strings), 0, "Parameter Id", HFILL }},
    { &hf_alcap_param_len, { "Length", "alcap.param.len", FT_UINT8, BASE_DEC, NULL, 0, "Parameter Length", HFILL }},
        
    { &hf_alcap_cau_coding, { "Cause Coding", "alcap.cau.coding", FT_UINT8, BASE_DEC, VALS(cause_coding_vals), 0x03, "", HFILL }},
    { &hf_alcap_cau_value_itu, { "Cause Value (ITU)", "alcap.cau.value", FT_UINT8, BASE_DEC, VALS(cause_values_itu), 0x7f, "", HFILL }},
    { &hf_alcap_cau_value_non_itu, { "Cause Value (Other)", "alcap.cau.value", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
    { &hf_alcap_cau_diag, { "Diagnostic", "alcap.cau.diag", FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }},
    { &hf_alcap_cau_diag_len, { "Length", "alcap.cau.diag.len", FT_UINT8, BASE_DEC, NULL, 0, "Diagnostics Length", HFILL }},
    { &hf_alcap_cau_diag_msg, { "Message Identifier", "alcap.cau.diag.msg", FT_UINT8, BASE_DEC, VALS(msg_type_strings), 0, "", HFILL }},
    { &hf_alcap_cau_diag_param_id, { "Parameter Identifier", "alcap.cau.diag.param", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_cau_diag_field_num, { "Field Number", "alcap.cau.diag.field_num", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_ceid_pathid, { "Path ID", "alcap.ceid.pathid", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ceid_cid, { "CID", "alcap.ceid.cid", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_dnsea, { "Address", "alcap.dnsea.addr", FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }},
        
    { &hf_alcap_alc_max_br_fw, { "Maximum Forward Bit Rate", "alcap.alc.bitrate.max.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_alc_max_br_bw, { "Maximum Backwards Bit Rate", "alcap.alc.bitrate.max.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_alc_avg_br_fw, { "Average Forward Bit Rate", "alcap.alc.bitrate.avg.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_alc_avg_br_bw, { "Average Backwards Bit Rate", "alcap.alc.bitrate.avg.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_alc_max_sdu_fw, { "Maximum Forward CPS SDU Size", "alcap.alc.sdusize.max.fw", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
    { &hf_alcap_alc_max_sdu_bw, { "Maximum Backwards CPS SDU Size", "alcap.alc.sdusize.max.bw", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
    { &hf_alcap_alc_avg_sdu_fw, { "Average Forward CPS SDU Size", "alcap.alc.sdusize.avg.fw", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
    { &hf_alcap_alc_avg_sdu_bw, { "Average Backwards CPS SDU Size", "alcap.alc.sdusize.avg.bw", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
        
    { &hf_alcap_osaid, { "OSAID", "alcap.osaid", FT_UINT32, BASE_HEX, NULL, 0, "Originating Service Association ID", HFILL }},
        
    { &hf_alcap_sugr, { "SUGR", "alcap.sugr", FT_BYTES, BASE_HEX, NULL, 0, "Served User Generated Reference", HFILL }},
        
    { &hf_alcap_sut_len, { "SUT Length", "alcap.sut.sut_len", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},
    { &hf_alcap_sut, { "SUT", "alcap.sut.transport", FT_BYTES, BASE_HEX, NULL, 0, "Served User Transport", HFILL }},
        
    { &hf_alcap_ssia_pr_type, { "Profile Type", "alcap.ssia.profile.type", FT_UINT8, BASE_DEC, VALS(audio_profile_type), 0xc0, "I.366.2 Profile Type", HFILL }},
    { &hf_alcap_ssia_pr_id, { "Profile Id", "alcap.ssia.profile.id", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssia_frm, { "Frame Mode", "alcap.ssia.frm", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x80, "", HFILL }},
    { &hf_alcap_ssia_cmd, { "Circuit Mode", "alcap.ssia.cmd", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x40, "", HFILL }},
    { &hf_alcap_ssia_mfr2, { "Multi-Frequency R2", "alcap.ssia.mfr2", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x20, "", HFILL }},
    { &hf_alcap_ssia_mfr1, { "Multi-Frequency R1", "alcap.ssia.mfr1", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x10, "", HFILL }},
    { &hf_alcap_ssia_dtmf, { "DTMF", "alcap.ssia.dtmf", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x08, "", HFILL }},
    { &hf_alcap_ssia_cas, { "CAS", "alcap.ssia.cas", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x04, "Channel Associated Signalling", HFILL }},
    { &hf_alcap_ssia_fax, { "Fax", "alcap.ssia.fax", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x02, "Facsimile", HFILL }},
    { &hf_alcap_ssia_pcm, { "PCM Mode", "alcap.ssia.pcm", FT_UINT8, BASE_DEC, VALS(alaw_ulaw), 0x01, "", HFILL }},
    { &hf_alcap_ssia_max_len, { "Max Len of FM Data", "alcap.ssia.max_fmdata_len", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssia_oui, { "OUI", "alcap.ssia.oui", FT_BYTES, BASE_HEX, NULL, 0, "Organizational Unique Identifier", HFILL }},
        
    { &hf_alcap_ssim_frm, { "Frame Mode", "alcap.ssim.frm", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x80, "", HFILL }},
    { &hf_alcap_ssim_mult, { "Multiplier", "alcap.ssim.mult", FT_UINT8, BASE_DEC, NULL, 0x1f, "", HFILL }},
    { &hf_alcap_ssim_max, { "Max Len", "alcap.ssim.max", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_ssisa_max_sssar_fw, { "Maximum Len of SSSAR-SDU Forward", "alcap.ssisa.sssar.max_len.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssisa_max_sssar_bw, { "Maximum Len of SSSAR-SDU Backwards", "alcap.ssisa.sssar.max_len.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssisa_max_sscop_sdu_fw, { "Maximum Len of SSSAR-SDU Forward", "alcap.ssisa.sscop.max_sdu_len.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssisa_max_sscop_sdu_bw, { "Maximum Len of SSSAR-SDU Backwards", "alcap.ssisa.sscop.max_sdu_len.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssisa_max_sscop_uu_fw, { "Maximum Len of SSSAR-SDU Forward", "alcap.ssisa.sscop.max_uu_len.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssisa_max_sscop_uu_bw, { "Maximum Len of SSSAR-SDU Backwards", "alcap.ssisa.sscop.max_uu_len.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_ssisu_max_sssar_fw, { "Maximum Len of SSSAR-SDU Forward", "alcap.ssisu.sssar.max_len.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssisu_max_sssar_bw, { "Maximum Len of SSSAR-SDU Backwards", "alcap.ssisu.sssar.max_len.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssisu_ted, { "Transmission Error Detection", "alcap.ssisu.ted", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x80, "", HFILL }},
        
    { &hf_alcap_pt, { "QoS Codepoint", "alcap.pt.codepoint", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        
    { &hf_alcap_plc_max_br_fw, { "Maximum Forward Bit Rate", "alcap.plc.bitrate.max.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_plc_max_br_bw, { "Maximum Backwards Bit Rate", "alcap.plc.bitrate.max.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_plc_avg_br_fw, { "Average Forward Bit Rate", "alcap.plc.bitrate.avg.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_plc_avg_br_bw, { "Average Backwards Bit Rate", "alcap.plc.bitrate.avg.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_plc_max_sdu_fw, { "Maximum Forward CPS SDU Size", "alcap.plc.sdusize.max.fw", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
    { &hf_alcap_plc_max_sdu_bw, { "Maximum Backwards CPS SDU Size", "alcap.plc.sdusize.max.bw", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
    { &hf_alcap_plc_avg_sdu_fw, { "Maximum Forward CPS SDU Size", "alcap.plc.sdusize.max.fw", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
    { &hf_alcap_plc_avg_sdu_bw, { "Maximum Backwards CPS SDU Size", "alcap.plc.sdusize.max.bw", FT_UINT8, BASE_DEC, NULL, 0x7f, "", HFILL }},
        
    { &hf_alcap_pssiae_pr_type, { "Profile Type", "alcap.pssiae.profile.type", FT_UINT8, BASE_DEC, VALS(audio_profile_type), 0xc0, "I.366.2 Profile Type", HFILL }},
    { &hf_alcap_pssiae_pr_id, { "Profile Id", "alcap.pssiae.profile.id", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pssiae_lb, { "Loopback", "alcap.pssiae.lb", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0xc0, "", HFILL }},
    { &hf_alcap_pssiae_rc, { "Rate Conctrol", "alcap.pssiae.rc", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0xc0, "", HFILL }},
    { &hf_alcap_pssiae_syn, { "Syncronization", "alcap.pssiae.syn", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0xc0, "Transport of synchronization of change in SSCS operation", HFILL }},
    { &hf_alcap_pssiae_frm, { "Frame Mode", "alcap.pssiae.frm", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x80, "", HFILL }},
    { &hf_alcap_pssiae_cmd, { "Circuit Mode", "alcap.pssiae.cmd", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x40, "", HFILL }},
    { &hf_alcap_pssiae_mfr2, { "Multi-Frequency R2", "alcap.pssiae.mfr2", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x20, "", HFILL }},
    { &hf_alcap_pssiae_mfr1, { "Multi-Frequency R1", "alcap.pssiae.mfr1", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x10, "", HFILL }},
    { &hf_alcap_pssiae_dtmf, { "DTMF", "alcap.pssiae.dtmf", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x08, "", HFILL }},
    { &hf_alcap_pssiae_cas, { "CAS", "alcap.pssiae.cas", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x04, "Channel Associated Signalling", HFILL }},
    { &hf_alcap_pssiae_fax, { "Fax", "alcap.pssiae.fax", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x02, "Facsimile", HFILL }},
    { &hf_alcap_pssiae_pcm, { "PCM Mode", "alcap.pssiae.pcm", FT_UINT8, BASE_DEC, VALS(alaw_ulaw), 0x01, "", HFILL }},
    { &hf_alcap_pssiae_oui, { "OUI", "alcap.pssiae.oui", FT_BYTES, BASE_HEX, NULL, 0, "Organizational Unique Identifier", HFILL }},
        
    { &hf_alcap_pssime_frm, { "Frame Mode", "alcap.pssime.frm", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x80, "", HFILL }},
    { &hf_alcap_pssime_lb, { "Loopback", "alcap.pssime.lb", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x40, "", HFILL }},
    { &hf_alcap_pssime_mult, { "Multiplier", "alcap.pssime.mult", FT_UINT8, BASE_DEC, NULL, 0x1f, "", HFILL }},
    { &hf_alcap_pssime_max, { "Max Len", "alcap.pssime.max", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_suci, { "SUCI", "alcap.suci", FT_UINT8, BASE_HEX, NULL, 0, "Served User Correlation Id", HFILL }},
        
    { &hf_alcap_onsea, { "Address", "alcap.onsea.addr", FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }},
        
    { &hf_alcap_ssiae_pr_type, { "Profile Type", "alcap.ssiae.profile.type", FT_UINT8, BASE_DEC, VALS(audio_profile_type), 0xc0, "I.366.2 Profile Type", HFILL }},
    { &hf_alcap_ssiae_lb, { "Loopback", "alcap.ssiae.lb", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0xc0, "", HFILL }},
    { &hf_alcap_ssiae_rc, { "Rate Conctrol", "alcap.ssiae.rc", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0xc0, "", HFILL }},
    { &hf_alcap_ssiae_syn, { "Syncronization", "alcap.ssiae.syn", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0xc0, "Transport of synchronization of change in SSCS operation", HFILL }},
    { &hf_alcap_ssiae_pr_id, { "Profile Id", "alcap.ssiae.profile.id", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_ssiae_frm, { "Frame Mode", "alcap.ssiae.frm", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x80, "", HFILL }},
    { &hf_alcap_ssiae_cmd, { "Circuit Mode", "alcap.ssiae.cmd", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x40, "", HFILL }},
    { &hf_alcap_ssiae_mfr2, { "Multi-Frequency R2", "alcap.ssiae.mfr2", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x20, "", HFILL }},
    { &hf_alcap_ssiae_mfr1, { "Multi-Frequency R1", "alcap.ssiae.mfr1", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x10, "", HFILL }},
    { &hf_alcap_ssiae_dtmf, { "DTMF", "alcap.ssiae.dtmf", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x08, "", HFILL }},
    { &hf_alcap_ssiae_cas, { "CAS", "alcap.ssiae.cas", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x04, "Channel Associated Signalling", HFILL }},
    { &hf_alcap_ssiae_fax, { "Fax", "alcap.ssiae.fax", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x02, "Facsimile", HFILL }},
    { &hf_alcap_ssiae_pcm, { "PCM Mode", "alcap.ssiae.pcm", FT_UINT8, BASE_DEC, VALS(alaw_ulaw), 0x01, "", HFILL }},
    { &hf_alcap_ssiae_oui, { "OUI", "alcap.ssiae.oui", FT_BYTES, BASE_HEX, NULL, 0, "Organizational Unique Identifier", HFILL }},
        
    { &hf_alcap_ssime_frm, { "Frame Mode", "alcap.ssime.frm", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x80, "", HFILL }},
    { &hf_alcap_ssime_lb, { "Loopback", "alcap.ssime.lb", FT_UINT8, BASE_DEC, VALS(enabled_disabled), 0x40, "", HFILL }},
    { &hf_alcap_ssime_mult, { "Multiplier", "alcap.ssime.mult", FT_UINT8, BASE_DEC, NULL, 0x1f, "", HFILL }},
    { &hf_alcap_ssime_max, { "Max Len", "alcap.ssime.max", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_acc_level, { "Congestion Level", "alcap.acc.level", FT_UINT8, BASE_DEC, VALS(congestion_level), 0, "", HFILL }},
        
    { &hf_alcap_cp, { "Level", "alcap.cp.level", FT_UINT8, BASE_DEC, VALS(connection_priority), 0x07, "", HFILL }},
        
    { &hf_alcap_hc, { "Codepoint", "alcap.hc.codepoint", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_pfbw_br_fw, { "CPS Forward Bitrate", "alcap.pfbw.bitrate.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pfbw_br_bw, { "CPS Backwards Bitrate", "alcap.pfbw.bitrate.bw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pfbw_bucket_fw, { "Forward CPS Bucket Size", "alcap.pfbw.bucket_size.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pfbw_bucket_bw, { "Backwards CPS Bucket Size", "alcap.pfbw.bucket_size.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pfbw_size_fw, { "Forward CPS Packet Size", "alcap.pfbw.max_size.fw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pfbw_size_bw, { "Backwards CPS Packet Size", "alcap.pfbw.max_size.bw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_pvbws_br_fw, { "Peak CPS Forward Bitrate", "alcap.pvbws.bitrate.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbws_br_bw, { "Peak CPS Backwards Bitrate", "alcap.pvbws.bitrate.bw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbws_bucket_fw, { "Peak Forward CPS Bucket Size", "alcap.pvbws.bucket_size.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbws_bucket_bw, { "Peak Backwards CPS Bucket Size", "alcap.pvbws.bucket_size.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbws_size_fw, { "Forward CPS Packet Size", "alcap.pvbws.max_size.fw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbws_size_bw, { "Backwards CPS Packet Size", "alcap.pvbws.max_size.bw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbws_stt, { "Source Traffic Type", "alcap.pvbws.stt", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_pvbwt_peak_br_fw, { "Peak CPS Forward Bitrate", "alcap.pvbwt.bitrate.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_peak_br_bw, { "Peak CPS Backwards Bitrate", "alcap.pvbwt.bitrate.bw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_peak_bucket_fw, { "Peak Forward CPS Bucket Size", "alcap.pvbwt.bucket_size.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_peak_bucket_bw, { "Peak Backwards CPS Bucket Size", "alcap.pvbwt.bucket_size.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_sust_br_fw, { "Sustainable CPS Forward Bitrate", "alcap.pvbwt.bitrate.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_sust_br_bw, { "Sustainable CPS Backwards Bitrate", "alcap.pvbwt.bitrate.bw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_sust_bucket_fw, { "Sustainable Forward CPS Bucket Size", "alcap.pvbwt.bucket_size.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_sust_bucket_bw, { "Sustainable Backwards CPS Bucket Size", "alcap.pvbwt.bucket_size.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_size_fw, { "Forward CPS Packet Size", "alcap.pvbwt.max_size.fw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_pvbwt_size_bw, { "Backwards CPS Packet Size", "alcap.pvbwt.max_size.bw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_fbw_br_fw, { "CPS Forward Bitrate", "alcap.fbw.bitrate.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_fbw_br_bw, { "CPS Backwards Bitrate", "alcap.fbw.bitrate.bw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_fbw_bucket_fw, { "Forward CPS Bucket Size", "alcap.fbw.bucket_size.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_fbw_bucket_bw, { "Backwards CPS Bucket Size", "alcap.fbw.bucket_size.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_fbw_size_fw, { "Forward CPS Packet Size", "alcap.fbw.max_size.fw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_fbw_size_bw, { "Backwards CPS Packet Size", "alcap.fbw.max_size.bw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_vbws_br_fw, { "CPS Forward Bitrate", "alcap.vbws.bitrate.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbws_br_bw, { "CPS Backwards Bitrate", "alcap.vbws.bitrate.bw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbws_bucket_fw, { "Forward CPS Bucket Size", "alcap.vbws.bucket_size.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbws_bucket_bw, { "Backwards CPS Bucket Size", "alcap.vbws.bucket_size.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbws_size_fw, { "Forward CPS Packet Size", "alcap.vbws.max_size.fw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbws_size_bw, { "Backwards CPS Packet Size", "alcap.vbws.max_size.bw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbws_stt, { "Source Traffic Type", "alcap.vbws.stt", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
    { &hf_alcap_vbwt_peak_br_fw, { "Peak CPS Forward Bitrate", "alcap.vbwt.bitrate.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_peak_br_bw, { "Peak CPS Backwards Bitrate", "alcap.vbwt.bitrate.bw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_peak_bucket_fw, { "Peak Forward CPS Bucket Size", "alcap.vbwt.bucket_size.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_peak_bucket_bw, { "Peak Backwards CPS Bucket Size", "alcap.vbwt.bucket_size.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_sust_br_fw, { "Sustainable CPS Forward Bitrate", "alcap.vbwt.bitrate.fw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_sust_br_bw, { "Sustainable CPS Backwards Bitrate", "alcap.vbwt.bitrate.bw", FT_UINT24, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_sust_bucket_fw, { "Sustainable Forward CPS Bucket Size", "alcap.vbwt.bucket_size.fw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_sust_bucket_bw, { "Sustainable Backwards CPS Bucket Size", "alcap.vbwt.bucket_size.bw", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_size_fw, { "Forward CPS Packet Size", "alcap.vbwt.max_size.fw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
    { &hf_alcap_vbwt_size_bw, { "Backwards CPS Packet Size", "alcap.vbwt.max_size.bw", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
        
	{ &hf_alcap_leg_osaid, { "Leg's ERQ OSA id",	"alcap.leg.osaid", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL } },
	{ &hf_alcap_leg_dsaid, { "Leg's ECF OSA id",	"alcap.leg.dsaid", FT_UINT32, BASE_HEX, NULL, 0,"", HFILL } },
	{ &hf_alcap_leg_pathid, { "Leg's path id",	"alcap.leg.pathid", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL } },
	{ &hf_alcap_leg_cid, { "Leg's channel id",	"alcap.leg.cid", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL } },
	{ &hf_alcap_leg_sugr, { "Leg's SUGR",	"alcap.leg.sugr", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL } },
	{ &hf_alcap_leg_dnsea, { "Leg's destination NSAP",	"alcap.leg.dnsea", FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
	{ &hf_alcap_leg_onsea, { "Leg's originating NSAP",	"alcap.leg.onsea", FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
	{ &hf_alcap_leg_frame, { "a message of this leg",	"alcap.leg.msg", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL } },
    { &hf_alcap_leg_release_cause, { "Leg's cause value in REL",	"alcap.leg.cause", FT_UINT8, BASE_DEC, VALS(cause_values_itu), 0, "", HFILL }},
        
    };
    
    gint* ett[] = {
        &ett_alcap,
        &ett_leg,
        &ett_compat,
        &ett_cau_diag,
        &param_infos[0].ett,
        &param_infos[1].ett,
        &param_infos[2].ett,
        &param_infos[3].ett,
        &param_infos[4].ett,
        &param_infos[5].ett,
        &param_infos[6].ett,
        &param_infos[7].ett,
        &param_infos[8].ett,
        &param_infos[9].ett,
        &param_infos[10].ett,
        &param_infos[11].ett,
        &param_infos[12].ett,
        &param_infos[13].ett,
        &param_infos[14].ett,
        &param_infos[15].ett,
        &param_infos[16].ett,
        &param_infos[17].ett,
        &param_infos[18].ett,
        &param_infos[19].ett,
        &param_infos[20].ett,
        &param_infos[21].ett,
        &param_infos[22].ett,
        &param_infos[23].ett,
        &param_infos[24].ett,
        &param_infos[25].ett,
        &param_infos[26].ett,
        &param_infos[27].ett,
        &param_infos[28].ett,
        &param_infos[29].ett,
        &param_infos[30].ett,
        &param_infos[31].ett,
        &param_infos[32].ett,
        &param_infos[33].ett,
        &param_infos[34].ett,
        &param_infos[35].ett,
    };
    
    proto_alcap = proto_register_protocol(alcap_proto_name, alcap_proto_name_short, "alcap");
    
	register_dissector("alcap", dissect_alcap, proto_alcap);
	
    proto_register_field_array(proto_alcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
	
    alcap_module = prefs_register_protocol(proto_alcap, NULL);
    
    prefs_register_bool_preference(alcap_module, "leg_info",
                                   "Keep Leg Information",
                                   "Whether persistent call leg information is to be kept",
                                   &keep_persistent_info);
    
	legs_by_dsaid = se_tree_create(SE_TREE_TYPE_RED_BLACK, "legs_by_dsaid");
	legs_by_osaid = se_tree_create(SE_TREE_TYPE_RED_BLACK, "legs_by_osaid");
	legs_by_bearer = se_tree_create(SE_TREE_TYPE_RED_BLACK, "legs_by_bearer");
	
}


void
proto_reg_handoff_alcap(void)
{
    dissector_handle_t	alcap_handle = create_dissector_handle(dissect_alcap, proto_alcap);
    dissector_add("mtp3.service_indicator", ALCAP_SI, alcap_handle);
}
