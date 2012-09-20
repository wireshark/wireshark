/* packet-v150fw.c
 *
 * v150fw = v.150.1 SSE messages, contained in RTP packets
 *
 * $Id$
 *
 * Written by Jamison Adcock <jamison.adcock@cobham.com>
 * for Sparta Inc., dba Cobham Analytic Solutions
 * This code is largely based on the RTP parsing code
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

#include <glib.h>

#include <epan/packet.h>

/* Initialize the protocol & registered fields
 * Look familiar?  This is in the same format as an NTE (named telephone event) from RFC 2833:
 */
static int proto_v150fw =                   -1;

static int hf_v150fw_event_id =             -1; /* 6 bits */
static int hf_v150fw_force_response_bit =   -1;
static int hf_v150fw_extension_bit =        -1;

static int hf_v150fw_reason_id_code =                       -1; /* value & string */

static int hf_v150fw_reason_id_code_info =                  -1; /* 16 bits */

static int hf_v150fw_ric_info_mod_avail =                   -1; /* ric = 1,2 */
static int hf_v150fw_cm_jm_mod_avail_pcm_mode =             -1;
static int hf_v150fw_cm_jm_mod_avail_v34_duplex =           -1;
static int hf_v150fw_cm_jm_mod_avail_v34_half_duplex =      -1;
static int hf_v150fw_cm_jm_mod_avail_v32_v32bis =           -1;
static int hf_v150fw_cm_jm_mod_avail_v22_v22bis =           -1;
static int hf_v150fw_cm_jm_mod_avail_v17 =                  -1;
static int hf_v150fw_cm_jm_mod_avail_v29_half_duplex =      -1;
static int hf_v150fw_cm_jm_mod_avail_v27ter =               -1;
static int hf_v150fw_cm_jm_mod_avail_v26ter =               -1;
static int hf_v150fw_cm_jm_mod_avail_v26bis =               -1;
static int hf_v150fw_cm_jm_mod_avail_v23_duplex =           -1;
static int hf_v150fw_cm_jm_mod_avail_v23_half_duplex =      -1;
static int hf_v150fw_cm_jm_mod_avail_v21 =                  -1;
static int hf_v150fw_cm_jm_mod_avail_v90_or_v92_analog =    -1;
static int hf_v150fw_cm_jm_mod_avail_v90_or_v92_digital =   -1;
static int hf_v150fw_cm_jm_mod_avail_v91 =                  -1;

static int hf_v150fw_ric_info_timeout =                     -1; /* ric= 18 */
static int hf_v150fw_ric_info_timeout_vendor =              -1;

static int hf_v150fw_ric_info_cleardown =                   -1; /* ric = 20 */
static int hf_v150fw_ric_info_cleardown_reserved =          -1;
static int hf_v150fw_ric_info_cleardown_vendor_tag =        -1; /* extension fields */
static int hf_v150fw_ric_info_cleardown_vendor_info =       -1;

static int hf_v150fw_reserved =             -1; /* 5 bits */
static int hf_v150fw_extension_len =        -1; /* 11 bits */
static int hf_v150fw_remainder =            -1;

/* initialize the subtree pointers */
static gint ett_v150fw = -1;
static gint ett_available_modulations = -1;

/* for some "range_string"s, there's only one value in the range  */
#define V150FW_VALUE_RANGE(a) a,a


/* V.150.1 State Signalling Events (SSE): */
#define V150FW_EVENT_RESERVED1          0
#define V150FW_EVENT_INITIAL_AUDIO      1
#define V150FW_EVENT_VOICEBAND_DATA     2
#define V150FW_EVENT_MODEM_RELAY        3
#define V150FW_EVENT_FAX_RELAY          4
#define V150FW_EVENT_TEXT_RELAY         5
#define V150FW_EVENT_TEXT_PROBE         6 /* new in ITU-T Rec. V.150.1 (2003)/Amd.2 (05/2006) */
/* 7 - 31 reserved for future use */
#define V150FW_EVENT_RESERVED2_START    7
#define V150FW_EVENT_RESERVED2_END      31
/* 32 - 63 vendor-defined */
#define V150FW_EVENT_VENDOR_START       32
#define V150FW_EVENT_VENDOR_END         63


/* V.150.1 SSE reason ID codes: */
#define V150FW_RIC_NULL                     0
#define V150FW_RIC_CM                       1
#define V150FW_RIC_JM                       2
#define V150FW_RIC_AA                       3
#define V150FW_RIC_AC                       4
#define V150FW_RIC_USB1                     5
#define V150FW_RIC_SB1                      6
#define V150FW_RIC_S1                       7
#define V150FW_RIC_V21_CH2                  8
#define V150FW_RIC_V21_CH1                  9
#define V150FW_RIC_V23_HIGH_CHANNEL         10
#define V150FW_RIC_V23_LOW_CHANNEL          11
#define V150FW_RIC_TONE_2225_HZ             12
#define V150FW_RIC_V21_CH2_HDLC_FLAGS       13
#define V150FW_RIC_INDETERMINATE_SIGNAL     14
#define V150FW_RIC_SILENCE                  15
#define V150FW_RIC_CNG                      16
#define V150FW_RIC_VOICE                    17
#define V150FW_RIC_TIMEOUT                  18
#define V150FW_RIC_P_STATE_TRANS            19
#define V150FW_RIC_CLEARDOWN                20
#define V150FW_RIC_ANS_CED_2100_HZ          21
#define V150FW_RIC_ANSAM                    22
#define V150FW_RIC_SLASH_ANS                23
#define V150FW_RIC_SLASH_ANSAM              24
#define V150FW_RIC_QC1A                     25
#define V150FW_RIC_QC1D                     26
#define V150FW_RIC_QC2A                     27
#define V150FW_RIC_QC2D                     28
#define V150FW_RIC_CRE                      29
#define V150FW_RIC_CRD                      30
/* new from ITU-T V.150.1 Amendment 1: */
#define V150FW_RIC_TIA_825A_45              31
#define V150FW_RIC_TIA_825A_50              32
#define V150FW_RIC_EDT                      33
#define V150FW_RIC_BELL_103_MODEM           34
#define V150FW_RIC_V21_TEXT_PHONE_T50       35
#define V150FW_RIC_V23_TEXT_MINITEL         36
#define V150FW_RIC_V18_TEXT_PHONE_T140      37
#define V150FW_RIC_DTMF_BASED_TEXT_RELAY    38
#define V150FW_RIC_CTM                      39
/* 40 - 127 reserved */
#define V150FW_RIC_RESERVED_START           40
#define V150FW_RIC_RESERVED_END             127
/* 128 - 255 for vendor use */
#define V150FW_RIC_VENDOR_START             128
#define V150FW_RIC_VENDOR_END               255


/* Timeout (V150FW_RIC_TIMEOUT) reason info: */
#define V150FW_RIC_INFO_TIMEOUT_NULL                            0
#define V150FW_RIC_INFO_TIMEOUT_CALL_DISCRIMINATION_TIMEOUT     1
#define V150FW_RIC_INFO_TIMEOUT_IP_TLP_TIMEOUT                  2
#define V150FW_RIC_INFO_TIMEOUT_SSE_EXPLICIT_ACK_TIMEOUT        3


/* Cleardown (V150FW_RIC_CLEARDOWN) reason info: */
#define V150FW_RIC_INFO_CLEARDOWN_UNKNOWN                       0
#define V150FW_RIC_INFO_CLEARDOWN_PHYSICAL_LAYER_RELEASE        1
#define V150FW_RIC_INFO_CLEARDOWN_LINK_LAYER_DISCONNECT         2
#define V150FW_RIC_INFO_CLEARDOWN_DATA_COMPRESSION_DISCONNECT   3
#define V150FW_RIC_INFO_CLEARDOWN_ABORT                         4
#define V150FW_RIC_INFO_CLEARDOWN_ON_HOOK                       5
#define V150FW_RIC_INFO_CLEARDOWN_NETWORK_LAYER_TERMINATION     6
#define V150FW_RIC_INFO_CLEARDOWN_ADMINISTRATIVE                7

/* value strings & range strings */
static const range_string v150fw_event_id_name[] = {
    { V150FW_VALUE_RANGE(V150FW_EVENT_RESERVED1),               "Event ID reserved" },
    { V150FW_VALUE_RANGE(V150FW_EVENT_INITIAL_AUDIO),           "Initial audio" },
    { V150FW_VALUE_RANGE(V150FW_EVENT_VOICEBAND_DATA),          "Voice band data" },
    { V150FW_VALUE_RANGE(V150FW_EVENT_MODEM_RELAY),             "Modem relay" },
    { V150FW_VALUE_RANGE(V150FW_EVENT_FAX_RELAY),               "Fax relay" },
    { V150FW_VALUE_RANGE(V150FW_EVENT_TEXT_RELAY),              "Text relay" },
    { V150FW_VALUE_RANGE(V150FW_EVENT_TEXT_PROBE),              "Text probe" },
    { V150FW_EVENT_RESERVED2_START, V150FW_EVENT_RESERVED2_END, "Reserved for ITU_T" },
    { V150FW_EVENT_VENDOR_START, V150FW_EVENT_VENDOR_END,       "Vendor-defined event" },
    { 0, 0, NULL }
};

static const range_string v150fw_ric_name[] = {
    { V150FW_VALUE_RANGE(V150FW_RIC_NULL),                  "None" },
    { V150FW_VALUE_RANGE(V150FW_RIC_CM),                    "CM" },
    { V150FW_VALUE_RANGE(V150FW_RIC_JM),                    "JM" },
    { V150FW_VALUE_RANGE(V150FW_RIC_AA),                    "AA" },
    { V150FW_VALUE_RANGE(V150FW_RIC_AC),                    "AC" },
    { V150FW_VALUE_RANGE(V150FW_RIC_USB1),                  "USB1" },
    { V150FW_VALUE_RANGE(V150FW_RIC_SB1),                   "SB1" },
    { V150FW_VALUE_RANGE(V150FW_RIC_S1),                    "S1" },
    { V150FW_VALUE_RANGE(V150FW_RIC_V21_CH2),               "V.21 Ch2" },
    { V150FW_VALUE_RANGE(V150FW_RIC_V21_CH1),               "V.21 Ch1" },
    { V150FW_VALUE_RANGE(V150FW_RIC_V23_HIGH_CHANNEL),      "V.23 High Channel" },
    { V150FW_VALUE_RANGE(V150FW_RIC_V23_LOW_CHANNEL),       "V.23 Low Channel" },
    { V150FW_VALUE_RANGE(V150FW_RIC_TONE_2225_HZ),          "Tone (2225 Hz)" },
    { V150FW_VALUE_RANGE(V150FW_RIC_V21_CH2_HDLC_FLAGS),    "V.21 Ch2 HDLC Flags" },
    { V150FW_VALUE_RANGE(V150FW_RIC_INDETERMINATE_SIGNAL),  "Indeterminate signal" },
    { V150FW_VALUE_RANGE(V150FW_RIC_SILENCE),               "Silence" },
    { V150FW_VALUE_RANGE(V150FW_RIC_CNG),                   "CNG" },
    { V150FW_VALUE_RANGE(V150FW_RIC_VOICE),                 "Voice" },
    { V150FW_VALUE_RANGE(V150FW_RIC_TIMEOUT),               "Timeout" },
    { V150FW_VALUE_RANGE(V150FW_RIC_P_STATE_TRANS),         "p' State Transition" },
    { V150FW_VALUE_RANGE(V150FW_RIC_CLEARDOWN),             "Cleardown" },
    { V150FW_VALUE_RANGE(V150FW_RIC_ANS_CED_2100_HZ),       "ANS/CED (2100Hz)" },
    { V150FW_VALUE_RANGE(V150FW_RIC_ANSAM),                 "ANSam" },
    { V150FW_VALUE_RANGE(V150FW_RIC_SLASH_ANS),             "/ANS" },
    { V150FW_VALUE_RANGE(V150FW_RIC_SLASH_ANSAM),           "/ANSam" },
    { V150FW_VALUE_RANGE(V150FW_RIC_QC1A),                  "QC1a" },
    { V150FW_VALUE_RANGE(V150FW_RIC_QC1D),                  "QC1d" },
    { V150FW_VALUE_RANGE(V150FW_RIC_QC2A),                  "QC2a" },
    { V150FW_VALUE_RANGE(V150FW_RIC_QC2D),                  "QC2d" },
    { V150FW_VALUE_RANGE(V150FW_RIC_CRE),                   "Cre" },
    { V150FW_VALUE_RANGE(V150FW_RIC_CRD),                   "CRd" },
    { V150FW_VALUE_RANGE(V150FW_RIC_TIA_825A_45),           "TIA-825A (45.45 bit/s)" },
    { V150FW_VALUE_RANGE(V150FW_RIC_TIA_825A_50),           "TIA-825A (50 bit/s)" },
    { V150FW_VALUE_RANGE(V150FW_RIC_EDT),                   "EDT (European Deaf Telephone)" },
    { V150FW_VALUE_RANGE(V150FW_RIC_BELL_103_MODEM),        "Bell 103 Modem" },
    { V150FW_VALUE_RANGE(V150FW_RIC_V21_TEXT_PHONE_T50),    "V.21 text telephone, T-50 encoding" },
    { V150FW_VALUE_RANGE(V150FW_RIC_V23_TEXT_MINITEL),      "V.23 text (Minitel)" },
    { V150FW_VALUE_RANGE(V150FW_RIC_V18_TEXT_PHONE_T140),   "V.18 text telephone, T-140 encoding" },
    { V150FW_VALUE_RANGE(V150FW_RIC_DTMF_BASED_TEXT_RELAY), "DTMF based Text Relay (Annex B/V.18)" },
    { V150FW_VALUE_RANGE(V150FW_RIC_CTM),                   "CTM" },
    { V150FW_RIC_RESERVED_START, V150FW_RIC_RESERVED_END,   "Reserved for use by ITU-T" },
    { V150FW_RIC_VENDOR_START, V150FW_RIC_VENDOR_END,       "For use by vendor" },
    { 0, 0, NULL }
};

static const value_string v150fw_ric_info_timeout_type[] = {
    { V150FW_RIC_INFO_TIMEOUT_NULL,                         "Null" },
    { V150FW_RIC_INFO_TIMEOUT_CALL_DISCRIMINATION_TIMEOUT,  "Call discrimination timeout" },
    { V150FW_RIC_INFO_TIMEOUT_IP_TLP_TIMEOUT,               "IP TLP timeout" },
    { V150FW_RIC_INFO_TIMEOUT_SSE_EXPLICIT_ACK_TIMEOUT,     "Explicit acknowledgement timeout" },
    { 0, NULL }
};

static const value_string v150fw_ric_info_cleardown_type[] = {
    { V150FW_RIC_INFO_CLEARDOWN_UNKNOWN,                     "Unknown/unspecified" },
    { V150FW_RIC_INFO_CLEARDOWN_PHYSICAL_LAYER_RELEASE,      "Physical layer release" },
    { V150FW_RIC_INFO_CLEARDOWN_LINK_LAYER_DISCONNECT,       "Link layer disconnect" },
    { V150FW_RIC_INFO_CLEARDOWN_DATA_COMPRESSION_DISCONNECT, "Data compression disconnect" },
    { V150FW_RIC_INFO_CLEARDOWN_ABORT,                       "Abort" },
    { V150FW_RIC_INFO_CLEARDOWN_ON_HOOK,                     "On hook" },
    { V150FW_RIC_INFO_CLEARDOWN_NETWORK_LAYER_TERMINATION,   "Network layer termination" },
    { V150FW_RIC_INFO_CLEARDOWN_ADMINISTRATIVE,              "Administrative" },
    { 0, NULL }
};


#if 0 /* XXX: The following doesn't actually dissect anything. Is dissect_v150fw() supposed to be called ? */
static gboolean
dissect_v150fw_heur(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_)
{
    guint8 octet1;
    guint8 extb, ric;
    guint16 ric_info;
    gint payload_length = tvb_length(tvb);
    unsigned int offset = 0;

    /* see appendix C (State Signalling Events) in ITU-T Rec. V.150.1 for details */

    /* Get the fields */
    octet1 = tvb_get_guint8(tvb, offset);
    extb = octet1 & 0x01;
    ric = tvb_get_guint8(tvb, offset + 1) & 0xFF;

    ric_info = tvb_get_ntohs(tvb, offset + 2);

    /* minimum lengths */
    if(!extb && payload_length <= 4) /* extb is not set, so minimum length is 4 bytes */
        return FALSE;
    if(extb && payload_length <= 6) /* ext bit is set, but no extension found? */
        return FALSE;

    if(ric == 0 || (ric >= 6 && ric <= 31)) /* values reserved for future use */
        return FALSE;

    switch(ric)
    {
        case 0:
            if(ric_info != 0) /* ric_info must be NULL if ric is NULL */
                return FALSE;
        case V150FW_RIC_CM:
        case V150FW_RIC_JM:
            if(!extb && payload_length > 4) /* payload too long */
                return FALSE;
            break;
        case V150FW_RIC_TIMEOUT:
        case V150FW_RIC_CLEARDOWN:
            break;
        default:
            if(ric < 31 && ric_info != 0) /* ric_info is zero unless ric is CM, JM, TIMEOUT ro CLEARDOWN */
                return FALSE;
            if(ric >= 31 && ric <= 127) /* 31 - 127 are reserved for future use */
                return FALSE;
            /* 128 - 255 are vendor-specific */
            break;
    }

    return TRUE;
}
#endif

static int
dissect_v150fw(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *v150fw_tree, *field_tree;
    guint8 extb, ric;
    guint16 ext_len = 0;
    gint payload_length;
    unsigned int offset = 0;

    if(tree)
    {
        /* create the trees */
        ti = proto_tree_add_item(tree, proto_v150fw, tvb, 0, -1, ENC_NA);
        v150fw_tree = proto_item_add_subtree(ti, ett_v150fw);

        payload_length = tvb_length(tvb);

        /* Get fields needed for further dissection */
        extb = tvb_get_guint8(tvb, offset) & 0x01; /* extension bit */
        ric = tvb_get_guint8(tvb, offset + 1);

        if(extb && payload_length >= 6) /* get optional extension fields */
            ext_len = tvb_get_ntohs(tvb, offset + 4) & 0x07FF;

        proto_tree_add_item(v150fw_tree, hf_v150fw_event_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(v150fw_tree, hf_v150fw_force_response_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(v150fw_tree, hf_v150fw_extension_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(v150fw_tree, hf_v150fw_reason_id_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* reason identifier code information */
        switch(ric)
        {
        case V150FW_RIC_CM:
        case V150FW_RIC_JM:
            ti = proto_tree_add_item(v150fw_tree, hf_v150fw_ric_info_mod_avail, tvb, offset, 2, ENC_BIG_ENDIAN);
            field_tree = proto_item_add_subtree(ti, ett_available_modulations);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_pcm_mode,           tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v34_duplex,         tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v34_half_duplex,    tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v32_v32bis,         tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v22_v22bis,         tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v17,                tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v29_half_duplex,    tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v27ter,             tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v26ter,             tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v26bis,             tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v23_duplex,         tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v23_half_duplex,    tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v21,                tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v90_or_v92_analog,  tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v90_or_v92_digital, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_v150fw_cm_jm_mod_avail_v91,                tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        case V150FW_RIC_TIMEOUT:
            proto_tree_add_item(v150fw_tree, hf_v150fw_ric_info_timeout,                  tvb, offset,     1, ENC_BIG_ENDIAN);
            proto_tree_add_item(v150fw_tree, hf_v150fw_ric_info_timeout_vendor,           tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            break;
        case V150FW_RIC_CLEARDOWN:
            proto_tree_add_item(v150fw_tree, hf_v150fw_ric_info_cleardown,                tvb, offset,     1, ENC_BIG_ENDIAN);
            proto_tree_add_item(v150fw_tree, hf_v150fw_ric_info_cleardown_reserved,       tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            break;
        default:
            proto_tree_add_item(v150fw_tree, hf_v150fw_reason_id_code_info,               tvb, offset,     2, ENC_BIG_ENDIAN);
            break;
        } /* switch(ric) */
        offset += 2;

        if(extb && payload_length >= 6) /* display optional extension fields */
        {
            proto_tree_add_item(v150fw_tree, hf_v150fw_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            if(ext_len != (payload_length - 6))
            {
                /* TODO - ext field len doesn't match actual len... that isn't illegal, but is perhaps worth noting */
                proto_tree_add_item(v150fw_tree, hf_v150fw_extension_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            } else {
                proto_tree_add_item(v150fw_tree, hf_v150fw_extension_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            }
            offset += 2;

            /* display optional extension fields */
            switch(ric) {
            case V150FW_RIC_CLEARDOWN: /* show vendor tag & vendor-specific info */
                proto_tree_add_item(v150fw_tree, hf_v150fw_ric_info_cleardown_vendor_tag,  tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(v150fw_tree, hf_v150fw_ric_info_cleardown_vendor_info, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                break;
            default:
                /* just dump the bytes for now */
                proto_tree_add_item(v150fw_tree, hf_v150fw_remainder, tvb, offset, (payload_length - 6), ENC_NA);
                break;
            }
        }
    }

    return tvb_length(tvb);
}

void
proto_register_v150fw(void)
{
    /* set up header fields */
    static hf_register_info hf[] =
    {
        {
            &hf_v150fw_event_id,
            {
                "Event ID",
                "v150fw.event",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(v150fw_event_id_name),
                0xFC,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_force_response_bit,
            {
                "Force response",
                "v150fw.frb",
                FT_BOOLEAN,
                8,
                TFS(&tfs_yes_no),
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_extension_bit,
            {
                "Payload extension",
                "v150fw.extb",
                FT_BOOLEAN,
                8,
                TFS(&tfs_present_absent),
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_reason_id_code, /* ric value + string */
            {
                "Reason ID",
                "v150fw.ric",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(v150fw_ric_name),
                0xFF,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_reason_id_code_info,
            {
                "Info",
                "v150fw.ricinfo",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0xFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_ric_info_timeout,
            {
                "Timeout type",
                "v150fw.ricinfo.timeout",
                FT_UINT16,
                BASE_HEX,
                VALS(v150fw_ric_info_timeout_type),
                0xFF00,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_ric_info_timeout_vendor,
            {
                "Vendor-specific timeout info",
                "v150fw.ricinfo.timeout_vendor",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x00FF,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_ric_info_cleardown,
            {
                "Cleardown type",
                "v150fw.ricinfo.cleardown",
                FT_UINT16,
                BASE_HEX,
                VALS(v150fw_ric_info_cleardown_type),
                0xFF00,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_ric_info_cleardown_reserved,
            {
                "Reserved for use by the ITU-T",
                "v150fw.ricinfo.cleardown_reserved",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x00FF,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_ric_info_cleardown_vendor_tag,
            {
                "Vendor tag",
                "v150fw.cleardown_vendor_tag",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0xFF,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_ric_info_cleardown_vendor_info,
            {
                "Vendor-specific info",
                "v150fw.cleardown_vendor_info",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0xFF,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_ric_info_mod_avail,
            {
                "Modulation availability",
                "v150fw.rinfo.mod_avail",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0xFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_pcm_mode,
            {
                "PCM mode",
                "v150fw.rinfo.mod_avail.pcm_mode",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x8000,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v34_duplex,
            {
                "V.34 duplex",
                "v150fw.rinfo.mod_avail.v34_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x4000,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v34_half_duplex,
            {
                "V.34 half-duplex",
                "v150fw.rinfo.mod_avail.v34_half_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x2000,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v32_v32bis,
            {
                "V.32/V.32bis",
                "v150fw.rinfo.mod_avail.v32_v32bis",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x1000,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v22_v22bis,
            {
                "V.22/V.22bis",
                "v150fw.rinfo.mod_avail.v22_v22bis",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0800,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v17,
            {
                "V.17",
                "v150fw.rinfo.mod_avail.v17",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0400,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v29_half_duplex,
            {
                "V.29 half-duplex",
                "v150fw.rinfo.mod_avail.v29_half_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0200,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v27ter,
            {
                "V.27ter",
                "v150fw.rinfo.mod_avail.v27ter",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0100,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v26ter,
            {
                "V.26ter",
                "v150fw.rinfo.mod_avail.v26ter",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0080,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v26bis,
            {
                "V.26bis",
                "v150fw.rinfo.mod_avail.v26bis",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0040,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v23_duplex,
            {
                "V.23 duplex",
                "v150fw.rinfo.mod_avail.v23_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0020,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v23_half_duplex,
            {
                "V.23 half-duplex",
                "v150fw.rinfo.mod_avail.half_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0010,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v21,
            {
                "V.21",
                "v150fw.rinfo.mod_avail.v21",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0008,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v90_or_v92_analog,
            {
                "V.90 or V.92 analog",
                "v150fw.rinfo.mod_avail.v90_or_v92_analog",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0004,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v90_or_v92_digital,
            {
                "V.90 or V.92 digital",
                "v150fw.rinfo.mod_avail.v90_or_v92_digital",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0002,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_cm_jm_mod_avail_v91,
            {
                "V.91",
                "v150fw.rinfo.mod_avail.v91",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0001,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_reserved,
            {
                "Reserved",
                "v150fw.reserved",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0xF800,
                NULL, HFILL
            }
        },
        {
            &hf_v150fw_extension_len,
            {
                "Extension field length",
                "v150fw.eflen",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x07FF,
                NULL, HFILL
            }
        },
        /* dump remaining bytes: */
        {
            &hf_v150fw_remainder,
            {
                "Remaining bytes",
                "v150fw.remainder",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        }
    }; /* hf_register_info hf[] */

    /* setup protocol subtree array */
    static gint *ett[] = {
        &ett_v150fw,
        &ett_available_modulations
    };

    /* register protocol name & description */
    proto_v150fw = proto_register_protocol("v150fw State Signaling Event", "v150fw", "v150fw");

    /* required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_v150fw, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* register the dissector */
    new_register_dissector("v150fw", dissect_v150fw, proto_v150fw);
}

