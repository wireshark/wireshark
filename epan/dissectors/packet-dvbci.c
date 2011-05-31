/* packet-dvbci.c
 * Routines for DVB-CI (Common Interface) dissection
 * Copyright 2011, Martin Kaiser <martin@kaiser.cx>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* The dissector supports DVB-CI as defined in EN50221.
 * Reassembly of fragmented data is not implemented yet.
 * Some resources are incomplete, most notably MMI.
 *
 * Missing functionality and CI+ support (www.ci-plus.com) will be
 *  added in future versions.
 *
 * The pcap input format for this dissector is documented at
 * http://www.kaiser.cx/pcap-dvbci.html.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-ber.h"


/* event byte in the pseudo-header */
#define DATA_CAM_TO_HOST  0xFF
#define DATA_HOST_TO_CAM  0xFE
#define CIS_READ          0xFD
#define COR_WRITE         0xFC
#define HW_EVT            0xFB

#define IS_DATA_TRANSFER(e) (e==DATA_CAM_TO_HOST || e==DATA_HOST_TO_CAM)

/* for [as]pdu_info_t when the message is allowed in either direction */
#define DIRECTION_ANY 0x0

/* source/destination address field */
#define ADDR_HOST "Host"
#define ADDR_CAM  "CAM"

/* hardware event */
#define CAM_IN    0x01
#define CAM_OUT   0x02
#define POWER_ON  0x03
#define POWER_OFF 0x04
#define TS_ROUTE  0x05
#define TS_BYPASS 0x06
#define RESET_H   0x07
#define RESET_L   0x08
#define READY_H   0x09
#define READY_L   0x0A


/* link layer */
#define ML_MORE 0x80
#define ML_LAST 0x00

/* transport layer */
#define NO_TAG        0x00
#define T_SB          0x80
#define T_RCV         0x81
#define T_CREATE_T_C  0x82
#define T_C_T_C_REPLY 0x83
#define T_DELETE_T_C  0x84
#define T_D_T_C_REPLY 0x85
#define T_REQUEST_T_C 0x86
#define T_NEW_T_C     0x87
#define T_T_C_ERROR   0x88
#define T_DATA_LAST   0xA0
#define T_DATA_MORE   0xA1

#define SB_VAL_MSG_AVAILABLE    0x80
#define SB_VAL_NO_MSG_AVAILABLE 0x00

/* session layer */
#define T_SESSION_NUMBER          0x90
#define T_OPEN_SESSION_REQUEST    0x91
#define T_OPEN_SESSION_RESPONSE   0x92
#define T_CREATE_SESSION          0x93
#define T_CREATE_SESSION_RESPONSE 0x94
#define T_CLOSE_SESSION_REQUEST   0x95
#define T_CLOSE_SESSION_RESPONSE  0x96

/* status for open/create session */
#define SESS_OPENED                   0x00
#define SESS_NOT_OPENED_RES_NON_EXIST 0xF0
#define SESS_NOT_OPENED_RES_UNAVAIL   0xF1
#define SESS_NOT_OPENED_RES_VER_LOWER 0xF2
#define SESS_NOT_OPENED_RES_BUSY      0xF3

/* status for close session */
#define SESS_CLOSED       0x00
#define SESS_NB_NOT_ALLOC 0xF0

/* resource id */
#define RES_ID_TYPE_MASK 0xC0000000
#define RES_CLASS_MASK   0x3FFF0000
#define RES_TYPE_MASK    0x0000FFC0
#define RES_VER_MASK     0x0000003F

/* resource class */
#define RES_CLASS_RM  0x01
#define RES_CLASS_AP  0x02
#define RES_CLASS_CA  0x03
#define RES_CLASS_HC  0x20
#define RES_CLASS_DT  0x24
#define RES_CLASS_MMI 0x40
#define RES_CLASS_AMI 0x41
#define RES_CLASS_LSC 0x60
#define RES_CLASS_CC  0x8C
#define RES_CLASS_HLC 0x8D
#define RES_CLASS_CUP 0x8E
#define RES_CLASS_OPP 0x8F
#define RES_CLASS_SAS 0x96

#define RES_ID_LEN 4 /* bytes */
#define RES_CLASS(_res_id) (_res_id & RES_CLASS_MASK) >> 16
#define RES_VER(_res_id)   (_res_id & RES_VER_MASK)

/* appinfo resource */
#define APP_TYPE_CA  0x1
#define APP_TYPE_EPG 0x2

/* ca resource */
#define LIST_MGMT_MORE   0x0
#define LIST_MGMT_FIRST  0x1
#define LIST_MGMT_LAST   0x2
#define LIST_MGMT_ONLY   0x3
#define LIST_MGMT_ADD    0x4
#define LIST_MGMT_UPDATE 0x5

#define CMD_ID_OK_DESCR     0x1
#define CMD_ID_OK_MMI       0x2
#define CMD_ID_QUERY        0x3
#define CMD_ID_NOT_SELECTED 0x4

#define CA_DESC_TAG 0x9


/* application layer */

#define APDU_TAG_SIZE 3

/* "don't care" value for min_len_field and len_field (this can't be 0) */
#define LEN_FIELD_ANY G_MAXUINT32

static GHashTable *apdu_table = NULL;

typedef struct _apdu_info_t {
    guint32 tag;
    /* the minimum length required for this apdu */
    guint32 min_len_field;
    /* if the apdu has a well-known length, we enforce it here
     * (otherwise, we set this to LEN_FIELD_ANY) */
    guint32 len_field;
    guint8 direction;
    void (*dissect_payload)(guint32, gint,
            tvbuff_t *, gint, packet_info *, proto_tree *);
} apdu_info_t;

static void
dissect_dvbci_payload_rm(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree);
static void
dissect_dvbci_payload_ap(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree);
static void
dissect_dvbci_payload_ca(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree);
static void
dissect_dvbci_payload_hc(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree);
static void
dissect_dvbci_payload_dt(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree);


/* apdu defines */
#define T_PROFILE_ENQ     0x9F8010
#define T_PROFILE         0x9F8011
#define T_PROFILE_CHANGE  0x9F8012
#define T_APP_INFO_ENQ    0x9F8020
#define T_APP_INFO        0x9F8021
#define T_ENTER_MENU      0x9F8022
#define T_CA_INFO_ENQ     0x9F8030
#define T_CA_INFO         0x9F8031
#define T_CA_PMT          0x9F8032
#define T_TUNE            0x9F8400
#define T_REPLACE         0x9F8401
#define T_CLEAR_REPLACE   0x9F8402
#define T_ASK_RELEASE     0x9F8403
#define T_DATE_TIME_ENQ   0x9F8440
#define T_DATE_TIME       0x9F8441

/* the following apdus are recognized but not dissected in the 1st release */
#define T_CA_PMT_REPLY    0x9F8033
#define T_CLOSE_MMI       0x9F8800
#define T_DISPLAY_CONTROL 0x9F8801
#define T_DISPLAY_REPLY   0x9F8802
#define T_TEXT_LAST       0x9F8803
#define T_TEXT_MORE       0x9F8804
#define T_ENQ             0x9F8807
#define T_ANSW            0x9F8808
#define T_MENU_LAST       0x9F8809
#define T_MENU_MORE       0x9F880A
#define T_MENU_ANSW       0x9F880B
#define T_LIST_LAST       0x9F880C
#define T_LIST_MORE       0x9F880D

static const apdu_info_t apdu_info[] = {
    {T_PROFILE_ENQ,    0, 0,             DIRECTION_ANY,    NULL},
    {T_PROFILE,        0, LEN_FIELD_ANY, DIRECTION_ANY,    dissect_dvbci_payload_rm},
    {T_PROFILE_CHANGE, 0, 0,             DIRECTION_ANY,    NULL},

    {T_APP_INFO_ENQ,   0, 0,             DATA_HOST_TO_CAM, NULL},
    {T_APP_INFO,       6, LEN_FIELD_ANY, DATA_CAM_TO_HOST, dissect_dvbci_payload_ap},
    {T_ENTER_MENU,     0, 0,             DATA_HOST_TO_CAM, NULL},

    {T_CA_INFO_ENQ,    0, 0,             DATA_HOST_TO_CAM, NULL},
    {T_CA_INFO,        0, LEN_FIELD_ANY, DATA_CAM_TO_HOST, dissect_dvbci_payload_ca},
    {T_CA_PMT,         6, LEN_FIELD_ANY, DATA_HOST_TO_CAM, dissect_dvbci_payload_ca},

    { T_TUNE,          0, 8,             DATA_CAM_TO_HOST, dissect_dvbci_payload_hc},
    { T_REPLACE,       0, 5,             DATA_CAM_TO_HOST, dissect_dvbci_payload_hc},
    { T_CLEAR_REPLACE, 0, 1,             DATA_CAM_TO_HOST, dissect_dvbci_payload_hc},
    { T_ASK_RELEASE,   0, 0,             DATA_HOST_TO_CAM, NULL},
 
    {T_DATE_TIME_ENQ,  0, 1,             DATA_CAM_TO_HOST, dissect_dvbci_payload_dt},
    {T_DATE_TIME,      5, LEN_FIELD_ANY, DATA_HOST_TO_CAM, dissect_dvbci_payload_dt}
};

static const value_string dvbci_apdu_tag[] = {
    { T_PROFILE_ENQ,     "Profile enquiry" },
    { T_PROFILE,         "Profile information" },
    { T_PROFILE_CHANGE,  "Profile change notification" },
    { T_APP_INFO_ENQ,    "Application info enquiry" },
    { T_APP_INFO,        "Application info" },
    { T_ENTER_MENU,      "Enter menu" },
    { T_CA_INFO_ENQ,     "CA info enquiry" },
    { T_CA_INFO,         "CA info" },
    { T_CA_PMT,          "CA PMT" },
    { T_DATE_TIME_ENQ,   "Date-Time enquiry" },
    { T_DATE_TIME,       "Date-Time" },
    { T_CA_PMT_REPLY,    "CA PMT reply" },
    { T_TUNE,            "Tune" },
    { T_REPLACE,         "Replace" },
    { T_CLEAR_REPLACE,   "Clear replace" },
    { T_ASK_RELEASE,     "Ask release" },
    { T_CLOSE_MMI,       "Close MMI" },
    { T_DISPLAY_CONTROL, "Display control" },
    { T_DISPLAY_REPLY,   "Display reply" },
    { T_TEXT_LAST,       "Text last" },
    { T_TEXT_MORE,       "Text more" },
    { T_ENQ,             "Enquiry" },
    { T_ANSW,            "Answer" },
    { T_MENU_LAST,       "Menu last" },
    { T_MENU_MORE,       "Menu more" },
    { T_MENU_ANSW,       "Menu answer" },
    { T_LIST_LAST,       "List last" },
    { T_LIST_MORE,       "List more" },
    { 0, NULL }
};

/* convert a byte that contains two 4bit BCD digits into a decimal value */
#define BCD44_TO_DEC(x)  (((x&0xf0) >> 4) * 10 + (x&0x0f))


void proto_reg_handoff_dvbci(void);


static int proto_dvbci = -1;

static gint ett_dvbci = -1;
static gint ett_dvbci_hdr = -1;
static gint ett_dvbci_link = -1;
static gint ett_dvbci_transport = -1;
static gint ett_dvbci_session = -1;
static gint ett_dvbci_res = -1;
static gint ett_dvbci_application = -1;
static gint ett_dvbci_es = -1;
static gint ett_dvbci_ca_desc = -1;

static int hf_dvbci_event = -1;
static int hf_dvbci_hw_event = -1;
static int hf_dvbci_buf_size = -1;
static int hf_dvbci_tcid = -1;
static int hf_dvbci_ml = -1;
static int hf_dvbci_c_tpdu_tag = -1;
static int hf_dvbci_r_tpdu_tag = -1;
static int hf_dvbci_t_c_id = -1;
static int hf_dvbci_sb_value = -1;
static int hf_dvbci_spdu_tag = -1;
static int hf_dvbci_sess_status = -1;
static int hf_dvbci_sess_nb = -1;
static int hf_dvbci_close_sess_status = -1;
static int hf_dvbci_apdu_tag = -1;
static int hf_dvbci_app_type = -1;
static int hf_dvbci_app_manf = -1;
static int hf_dvbci_manf_code = -1;
static int hf_dvbci_menu_str_len = -1;
static int hf_dvbci_ca_sys_id = -1;
static int hf_dvbci_ca_pmt_list_mgmt = -1;
static int hf_dvbci_prog_num = -1;
static int hf_dvbci_prog_info_len = -1;
static int hf_dvbci_stream_type = -1;
static int hf_dvbci_es_pid = -1;
static int hf_dvbci_es_info_len = -1;
static int hf_dvbci_ca_pmt_cmd_id = -1;
static int hf_dvbci_descr_len = -1;
static int hf_dvbci_ca_pid = -1;
static int hf_dvbci_network_id = -1;
static int hf_dvbci_original_network_id = -1;
static int hf_dvbci_transport_stream_id = -1;
static int hf_dvbci_service_id = -1;
static int hf_dvbci_replacement_ref = -1;
static int hf_dvbci_replaced_pid = -1;
static int hf_dvbci_replacement_pid = -1;
static int hf_dvbci_resp_intv = -1;
static int hf_dvbci_utc_time = -1;
static int hf_dvbci_local_offset = -1;

typedef struct _spdu_info_t {
    guint8 tag;
    guint8 direction;
    guint8 len_field;
} spdu_info_t;

static const value_string dvbci_event[] = {
    { DATA_HOST_TO_CAM,  "data transfer Host -> CAM" },
    { DATA_CAM_TO_HOST,  "data transfer CAM -> Host" },
    { CIS_READ,          "read the Card Information Structure (CIS)" },
    { COR_WRITE,         "write into the Configuration Option Register (COR)" },
    { HW_EVT,            "hardware event" },
    { 0, NULL }
};
static const value_string dvbci_hw_event[] = {
    { CAM_IN,    "CI Module is inserted" },
    { CAM_OUT,   "CI Module is removed" },
    { POWER_ON,  "CI slot power on" },
    { POWER_OFF, "CI slot power off" },
    { TS_ROUTE,  "Transport stream routed through the CI Module" },
    { TS_BYPASS, "Transport stream bypasses the CI Module" },
    { RESET_H,   "Reset pin is high" },
    { RESET_L,   "Reset pin is low" },
    { READY_H,   "Ready pin is high" },
    { READY_L,   "Ready pin is low" },
    { 0, NULL }
};
static const value_string dvbci_ml[] = {
    { ML_MORE, "more TPDU fragments pending" },
    { ML_LAST, "last TPDU fragment" },
    { 0, NULL }
};
static const value_string dvbci_c_tpdu[] = {
    { T_RCV, "T_RCV" },
    { T_CREATE_T_C,  "T_create_t_c" },
    { T_DELETE_T_C,  "T_delete_t_c" },
    { T_D_T_C_REPLY, "T_d_t_c_reply" },
    { T_NEW_T_C,     "T_new_t_c" },
    { T_T_C_ERROR,   "T_t_c_error" },
    { T_DATA_LAST,   "T_data_last" },
    { T_DATA_MORE,   "T_data_more" },
    { 0, NULL }
};
static const value_string dvbci_r_tpdu[] = {
    { T_C_T_C_REPLY, "T_c_tc_reply" },
    { T_DELETE_T_C,  "T_delete_t_c" },
    { T_D_T_C_REPLY, "T_d_t_c_reply" },
    { T_REQUEST_T_C, "T_request_t_c" },
    { T_DATA_LAST,   "T_data_last" },
    { T_DATA_MORE,   "T_data_more" },
    { 0, NULL }
};
static const value_string dvbci_sb_value[] = {
    { SB_VAL_MSG_AVAILABLE,    "message available" },
    { SB_VAL_NO_MSG_AVAILABLE, "no message available" },
    { 0, NULL }
};
static const value_string dvbci_spdu_tag[] = {
    { T_SESSION_NUMBER,          "Session Number (payload data)" },
    { T_OPEN_SESSION_REQUEST,    "Open Session Request" },
    { T_OPEN_SESSION_RESPONSE,   "Open Session Response" },
    { T_CREATE_SESSION,          "Create Session" },
    { T_CREATE_SESSION_RESPONSE, "Create Session Response" },
    { T_CLOSE_SESSION_REQUEST,   "Close Session Request" },
    { T_CLOSE_SESSION_RESPONSE,  "Close Session Response" },
    { 0, NULL }
};
static GHashTable *spdu_table = NULL;
static const spdu_info_t spdu_info[] = {
    { T_SESSION_NUMBER,          DIRECTION_ANY, 2 },
    { T_OPEN_SESSION_REQUEST,    DATA_CAM_TO_HOST, 4 },
    { T_OPEN_SESSION_RESPONSE,   DATA_HOST_TO_CAM, 7 },
    { T_CREATE_SESSION,          DATA_HOST_TO_CAM, 6 },
    { T_CREATE_SESSION_RESPONSE, DATA_CAM_TO_HOST, 7 },
    { T_CLOSE_SESSION_REQUEST,   DIRECTION_ANY, 2 },
    { T_CLOSE_SESSION_RESPONSE,  DIRECTION_ANY, 3 }
};
static const value_string dvbci_sess_status[] = {
    { SESS_OPENED,
      "Session opened" },
    { SESS_NOT_OPENED_RES_NON_EXIST,
      "Resource does not exist" },
    { SESS_NOT_OPENED_RES_UNAVAIL,
      "Resource exists but it's unavailable" },
    { SESS_NOT_OPENED_RES_VER_LOWER,
      "Existing resource's version is lower than requested version" },
    { SESS_NOT_OPENED_RES_BUSY,
      "Resource is busy" },
    { 0, NULL }
};
static const value_string dvbci_close_sess_status[] = {
    { SESS_CLOSED,       "Session closed" },
    { SESS_NB_NOT_ALLOC, "Session number not allocated" },
    { 0, NULL }
};
static const value_string dvbci_res_class[] = {
    { RES_CLASS_RM,  "Resource Manager" },
    { RES_CLASS_AP,  "Application Info" },
    { RES_CLASS_CA,  "Conditional Access" },
    { RES_CLASS_HC,  "Host Control" },
    { RES_CLASS_DT,  "Date-Time" },
    { RES_CLASS_MMI, "Man-machine interface (MMI)" },
    { RES_CLASS_AMI, "Application MMI" },
    { RES_CLASS_LSC, "Low-Speed Communication" },
    { RES_CLASS_CC,  "Content Control" },
    { RES_CLASS_HLC, "Host Language & Country" },
    { RES_CLASS_CUP, "CAM Upgrade" },
    { RES_CLASS_OPP, "Operator Profile" },
    { RES_CLASS_SAS, "Specific Application Support" },
    { 0, NULL }
};
static const value_string dvbci_app_type[] = {
    { APP_TYPE_CA,  "Conditional Access" },
    { APP_TYPE_EPG, "Electronic Progam Guide" },
    { 0, NULL }
};
static const value_string dvbci_ca_pmt_list_mgmt[] = {
    { LIST_MGMT_MORE,   "more" },
    { LIST_MGMT_FIRST,  "first" },
    { LIST_MGMT_LAST,   "last" },
    { LIST_MGMT_ONLY,   "only" },
    { LIST_MGMT_ADD,    "add" },
    { LIST_MGMT_UPDATE, "update" },
    { 0, NULL }
};
static const value_string dvbci_ca_pmt_cmd_id[] = {
    { CMD_ID_OK_DESCR,     "ok descrambling" },
    { CMD_ID_OK_MMI,       "ok mmi" },
    { CMD_ID_QUERY,        "query" },
    { CMD_ID_NOT_SELECTED, "not selected" },
    { 0, NULL }
};


static guint16 buf_size_cam;    /* buffer size proposal by the CAM */
/* buffer size proposal by the host == negotiated buffer size */
static guint16 buf_size_host;

/* this must be a function, not a macro,
   so that we can enforce the return type */
static inline gint16 two_comp_to_int16(guint16 x)
{
   return (x&0x8000) ? -~(x-1) : x;
}   


/* initialize/reset per capture state data */
static void
dvbci_init(void)
{
    buf_size_cam  = 0;
    buf_size_host = 0;
}

/* dissect a ca descriptor in the ca_pmt */
static gint
dissect_ca_desc(tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree)
{
    gint offset_start;
    proto_item *pi;
    guint8 tag, len_byte;
    proto_item *ti = NULL;
    proto_tree *ca_desc_tree = NULL;

    offset_start = offset;

    tag = tvb_get_guint8(tvb,offset);
    if (tag != CA_DESC_TAG) {
        /* we could skip unknown descriptors and make this a warning */
        pi = proto_tree_add_text(tree, tvb, offset, 1, "Invalid descriptor");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "The ca_pmt shall only contain ca descriptors (tag 0x9)");
        return 0;
    }
    if (tree) {
        ti = proto_tree_add_text(
                tree, tvb, offset_start, -1, "Conditional Access descriptor");
        ca_desc_tree = proto_item_add_subtree(ti, ett_dvbci_ca_desc);
    }
    offset++;

    len_byte = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(
            ca_desc_tree, hf_dvbci_descr_len, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(
            ca_desc_tree, hf_dvbci_ca_sys_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(
            ca_desc_tree, hf_dvbci_ca_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if ((len_byte-4) != 0) {
        proto_tree_add_text(
                ca_desc_tree, tvb, offset, len_byte-4, "private data");
        offset += (len_byte-4);
    }

    if (ti)
        proto_item_set_len(ti, offset-offset_start);
    return offset-offset_start;
}


/* dissect an elementary stream entry in the ca_pmt */
static gint
dissect_es(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *es_tree = NULL;
    gint offset_start, ca_desc_len;
    gint es_info_len, all_len;

    offset_start = offset;

    if (tree) {
        ti = proto_tree_add_text(
                tree, tvb, offset_start, -1, "Elementary Stream");
        es_tree = proto_item_add_subtree(ti, ett_dvbci_application);
    }

    proto_tree_add_item(
            es_tree, hf_dvbci_stream_type, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(
            es_tree, hf_dvbci_es_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    es_info_len = tvb_get_ntohs(tvb, offset) & 0x0FFF;
    /* the definition of hf_dvbci_es_info_len also applies the mask */
    proto_tree_add_item(
            es_tree, hf_dvbci_es_info_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (es_info_len != 0) {
        all_len = offset + es_info_len;

        proto_tree_add_item(
                es_tree, hf_dvbci_ca_pmt_cmd_id, tvb, offset, 1, ENC_NA);
        offset++;
        while (offset < all_len) {
            ca_desc_len = dissect_ca_desc(tvb, offset, pinfo, es_tree);
            if (ca_desc_len <= 0)
                return -1;
            offset += ca_desc_len;
        }
    }
    else {
        proto_tree_add_text(
                es_tree, tvb, 0, 0,
                "No CA descriptors for this elementary stream");
    }

    if (ti)
        proto_item_set_len(ti, offset-offset_start);
    return offset-offset_start;
}


static void
dissect_dvbci_res_id(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree, guint32 res_id,
        gboolean show_col_info)
{
    proto_item *ti   = NULL;
    proto_tree *res_tree = NULL;

    if (show_col_info) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s Version %d",
                val_to_str_const(RES_CLASS(res_id), dvbci_res_class,
                    "Invalid Resource class"),
                RES_VER(res_id));
    }

    if (tree) {
        ti = proto_tree_add_text(
                tree, tvb, offset, RES_ID_LEN, "Resource ID: 0x%04x", res_id);

        res_tree = proto_item_add_subtree(ti, ett_dvbci_res);

        proto_tree_add_text(res_tree, tvb, 0, 0, "%s",
                decode_numeric_bitfield(res_id, RES_ID_TYPE_MASK, 32,
                    "Resource ID Type: 0x%x"));
        proto_tree_add_text(res_tree, tvb, 0, 0, "%s",
                decode_enumerated_bitfield_shifted(res_id, RES_CLASS_MASK, 32,
                    dvbci_res_class, "Resource Class: %s"));
        proto_tree_add_text(res_tree, tvb, 0, 0, "%s",
                decode_numeric_bitfield(res_id, RES_TYPE_MASK, 32,
                    "Resource Type: 0x%x"));
        proto_tree_add_text(res_tree, tvb, 0, 0, "%s",
                decode_numeric_bitfield(res_id, RES_VER_MASK, 32,
                    "Resource Version: 0x%x"));
    }
}

/* dissect the body of a resource manager apdu */
static void
dissect_dvbci_payload_rm(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree)
{
   const gchar *tag_str;
   proto_item *pi;
   guint32 res_id;

   if (tag==T_PROFILE) {
       if (len_field % RES_ID_LEN) {
           tag_str = val_to_str(tag, dvbci_apdu_tag, "Unknown: %d");
           pi = proto_tree_add_text(tree, tvb, 0, APDU_TAG_SIZE,
                   "Invalid APDU length field");
           expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                   "Length field for %s must be a multiple of 4 bytes",
                   tag_str);
           return;
       }

       while (tvb_reported_length_remaining(tvb, offset) != 0) {
           res_id = tvb_get_ntohl(tvb, offset);
           dissect_dvbci_res_id(tvb, offset, pinfo, tree, res_id, FALSE);
           offset += RES_ID_LEN;
       }
   }
}

static void
dissect_dvbci_payload_ap(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree)
{
    guint8 menu_str_len;
    guint8 *menu_string;

    if (tag==T_APP_INFO) {
        proto_tree_add_item(tree, hf_dvbci_app_type, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(
                tree, hf_dvbci_app_manf, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        proto_tree_add_item(
                tree, hf_dvbci_manf_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        menu_str_len = tvb_get_guint8(tvb,offset);
        proto_tree_add_item(
                tree, hf_dvbci_menu_str_len, tvb, offset, 1, ENC_NA);
        offset++;
        /* ephemeral -> string is freed automatically when dissection
           of this packet is finished
           tvb_get_ephemeral_string() always returns a 0-terminated string */
        menu_string = tvb_get_ephemeral_string(tvb, offset, menu_str_len);
        if (menu_string) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "Module name %s", menu_string);
            proto_tree_add_text(tree, tvb, offset, menu_str_len,
                    "Menu string: %s", menu_string);
        }
        offset += menu_str_len;
    }
}

static void
dissect_dvbci_payload_ca(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree)
{
    const gchar *tag_str;
    proto_item *pi;
    guint16 prog_num;
    guint8 byte;
    guint prog_info_len;
    gint es_info_len, all_len;
    gint ca_desc_len;


    if (tag==T_CA_INFO) {
        if (len_field % 2) {
            tag_str = val_to_str(tag, dvbci_apdu_tag, "Unknown: %d");
            pi = proto_tree_add_text(tree, tvb, 0, APDU_TAG_SIZE,
                    "Invalid APDU length field");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "Length field for %s must be a multiple of 2 bytes",
                    tag_str);
            return;
        }

        while (tvb_reported_length_remaining(tvb, offset) != 0) {
            proto_tree_add_item(
                    tree, hf_dvbci_ca_sys_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }
    else if (tag==T_CA_PMT) {
        proto_tree_add_item(
                tree, hf_dvbci_ca_pmt_list_mgmt, tvb, offset, 1, ENC_NA);
        offset++;
        prog_num = tvb_get_ntohs(tvb, offset);
        col_append_sep_fstr(
                pinfo->cinfo, COL_INFO, NULL, "Program number %x", prog_num);
        proto_tree_add_item(
                tree, hf_dvbci_prog_num, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        byte = tvb_get_guint8(tvb,offset);
        proto_tree_add_text(tree, tvb, offset, 1, 
                "Version number: 0x%x, Current-next indicator: 0x%x",
                (byte&0x3E) >> 1, byte&0x01);
        offset++;
        prog_info_len = tvb_get_ntohs(tvb, offset) & 0x0FFF;
        /* the definition of hf_dvbci_prog_info_len also applies the mask */
        proto_tree_add_item(
                tree, hf_dvbci_prog_info_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        if (prog_info_len != 0) {
            all_len = offset + prog_info_len;

            proto_tree_add_item(
                    tree, hf_dvbci_ca_pmt_cmd_id, tvb, offset, 1, ENC_NA);
            offset++;
            while (offset < all_len) {
                ca_desc_len = dissect_ca_desc(tvb, offset, pinfo, tree);
                if (ca_desc_len <= 0)
                    return;
                offset += ca_desc_len;
            }
        }
        else {
            proto_tree_add_text(
                    tree, tvb, 0, 0, "No CA descriptors at program level");
        }

        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            es_info_len = dissect_es(tvb, offset, pinfo, tree);
            if (es_info_len <= 0)
                return;
            offset += es_info_len;
        }
    }
}


static void
dissect_dvbci_payload_hc(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree)
{
    proto_item *pi;
    guint16 nid, onid, tsid, svcid;
    guint8 ref;
    guint16 old_pid, new_pid;


    if (tag==T_TUNE) {
        nid = tvb_get_ntohs(tvb, offset);
        pi = proto_tree_add_item(
            tree, hf_dvbci_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        if (nid) {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_NOTE,
                    "Network ID is usually ignored by hosts");
        }
        offset += 2;
        onid = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(
            tree, hf_dvbci_original_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        tsid = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(
            tree, hf_dvbci_transport_stream_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        svcid = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(
            tree, hf_dvbci_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                "nid 0x%x, onid 0x%x, tsid 0x%x, svcid 0x%x",
                nid, onid, tsid, svcid);
    }
    else if (tag==T_REPLACE) {
        ref = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(
            tree, hf_dvbci_replacement_ref, tvb, offset, 1, ENC_NA);
        offset++;
        old_pid = tvb_get_ntohs(tvb, offset) & 0x1FFF;
        proto_tree_add_item(
            tree, hf_dvbci_replaced_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        new_pid = tvb_get_ntohs(tvb, offset) & 0x1FFF;
        proto_tree_add_item(
            tree, hf_dvbci_replacement_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                "ref 0x%x, 0x%x -> 0x%x", ref, old_pid, new_pid);
     }
    else if (tag==T_CLEAR_REPLACE) {
        ref = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(
            tree, hf_dvbci_replacement_ref, tvb, offset, 1, ENC_NA);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "ref 0x%x", ref);
    }
}


static void
dissect_dvbci_payload_dt(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree)
{
    nstime_t resp_intv;
    proto_item *pi = NULL;
    const gchar *tag_str;
    nstime_t utc_time;
    gint16 local_offset;  /* field in the apdu */
    gint bcd_time_offset; /* start offset of the bcd time in the tvbuff */
    guint8 hour, min, sec;


    if (tag==T_DATE_TIME_ENQ) {
        nstime_set_zero(&resp_intv);
        resp_intv.secs = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_time_format(tree, hf_dvbci_resp_intv,
                tvb, offset, 1, &resp_intv, "Response interval is %s",
                rel_time_to_str(&resp_intv));
        if (resp_intv.secs==0) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "individual query");
            if (pi)
                proto_item_append_text(pi, " (individual query)");
        }
        else {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "update every %s", rel_time_to_str(&resp_intv));
        }
    }
    else if (tag==T_DATE_TIME) {
        if (len_field!=5 && len_field!=7) {
            tag_str = match_strval(tag, dvbci_apdu_tag);
            pi = proto_tree_add_text(tree, tvb, APDU_TAG_SIZE, offset-APDU_TAG_SIZE,
                    "Invalid APDU length field");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "Length field for %s must be 5 or 7 bytes", tag_str);
            return;
        }
        /* the 40bit utc_time field is encoded according to DVB-SI spec,
         * section 5.2.5:
         * 16bit modified julian day (MJD), 24bit 6*4bit BCD digits hhmmss */
        nstime_set_zero(&utc_time);
        utc_time.secs = (tvb_get_ntohs(tvb, offset) - 40587) * 86400;
        bcd_time_offset = offset+2;
        hour = BCD44_TO_DEC(tvb_get_guint8(tvb, bcd_time_offset));
        min = BCD44_TO_DEC(tvb_get_guint8(tvb, bcd_time_offset+1));
        sec = BCD44_TO_DEC(tvb_get_guint8(tvb, bcd_time_offset+2));
        if (hour>23 || min>59 || sec>59) {
            pi = proto_tree_add_text(
                tree, tvb, bcd_time_offset, 3, "Invalid BCD time");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "BCD time must be hhmmss");
            return;
        }
        utc_time.secs += hour*3600 + min*60 + sec;

        proto_tree_add_time_format(tree, hf_dvbci_utc_time, tvb, offset, 5,
            &utc_time, "%s UTC",
            abs_time_to_str(&utc_time, ABSOLUTE_TIME_UTC, FALSE));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
            "%s UTC", abs_time_to_str(&utc_time, ABSOLUTE_TIME_UTC, FALSE));
        offset += 5;

        if (len_field==7) {
            local_offset = two_comp_to_int16(tvb_get_ntohs(tvb, offset));
            proto_tree_add_int_format(tree, hf_dvbci_local_offset,
                    tvb, offset, 2, local_offset,
                    "offset between UTC and local time is %d minutes",
                    local_offset);
        }
        else {
            proto_tree_add_text(tree, tvb, 0, 0,
                    "Offset between UTC and local time is unknown");
        }
    }
}


static void
dissect_dvbci_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction)
{
    proto_item *ti;
    proto_tree *app_tree = NULL;
    guint32 apdu_len, tag, len_field;
    const gchar *tag_str;
    gint offset;
    proto_item *pi;
    apdu_info_t *ai;


    apdu_len = tvb_reported_length(tvb);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, apdu_len, "Application Layer");
        app_tree = proto_item_add_subtree(ti, ett_dvbci_application);
    }

    tag = tvb_get_ntoh24(tvb, 0);
    tag_str = match_strval(tag, dvbci_apdu_tag);
    offset = APDU_TAG_SIZE;

    col_set_str(pinfo->cinfo, COL_INFO,
            val_to_str_const(tag, dvbci_apdu_tag, "Unknown/invalid APDU"));
    if (tag_str) {
        proto_tree_add_item(
                app_tree, hf_dvbci_apdu_tag, tvb, 0, APDU_TAG_SIZE, ENC_NA);
    }
    else {
        pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                "Invalid or unsupported APDU tag");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Invalid or unsupported APDU tag");
        return;
    }

    offset = dissect_ber_length(pinfo, app_tree, tvb, offset, &len_field, NULL);
    if ((offset+len_field) > apdu_len) {
        pi = proto_tree_add_text(app_tree, tvb,
                APDU_TAG_SIZE, offset-APDU_TAG_SIZE,
                "Length field mismatch");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Length field mismatch");
        return;
    }

    ai = (apdu_info_t *)g_hash_table_lookup(apdu_table,
                                            GUINT_TO_POINTER((guint)tag));
    if (!ai) {
        pi = proto_tree_add_text(
                app_tree, tvb, 0, APDU_TAG_SIZE, "Unknown APDU");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Dissection of this APDU is not supported");
        return;
    }
    if (ai->direction!=DIRECTION_ANY && ai->direction!=direction) {
        pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                "Invalid APDU direction");
        if (ai->direction==DATA_HOST_TO_CAM) {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "This APDU must be sent from host to CAM");
        }
        else {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "This APDU must be sent from CAM to host");
        }
        /* don't return, we can continue dissecting the APDU */
    }
    if (ai->min_len_field!=LEN_FIELD_ANY && len_field<ai->min_len_field) {
        pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                "Invalid APDU length field");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Minimum length field for %s is %d",
                tag_str, ai->min_len_field);
        return;
    }
    if (ai->len_field!=LEN_FIELD_ANY && len_field!=ai->len_field) {
        pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                "Invalid APDU length field");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Length field for %s must be %d", tag_str, ai->len_field);
        return;
    }
    if (ai->len_field!=0) {
        if (!ai->dissect_payload) {
            /* don't display an error, getting here means we have illegal
             * data in apdu_info[] */
            return;
        }
        ai->dissect_payload(tag, len_field, tvb, offset, pinfo, app_tree);
    }
}

static void
dissect_dvbci_spdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction)
{
    guint32 spdu_len;
    proto_item *ti = NULL;
    proto_tree *sess_tree = NULL;
    guint8 tag;
    const gchar *tag_str;
    gint offset;
    proto_item *pi;
    guint32 len_field;
    const spdu_info_t *si;
    guint32 res_id;
    guint8 sess_stat;
    tvbuff_t *payload_tvb = NULL;
    gint payload_len;


    spdu_len = tvb_reported_length(tvb);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, -1, "Session Layer");
        sess_tree = proto_item_add_subtree(ti, ett_dvbci_session);
    }

    tag = tvb_get_guint8(tvb,0);
    tag_str = match_strval(tag, dvbci_spdu_tag);
    col_add_str(pinfo->cinfo, COL_INFO,
            val_to_str_const(tag, dvbci_spdu_tag, "Invalid SPDU"));
    if (tag_str) {
        proto_tree_add_item(sess_tree, hf_dvbci_spdu_tag, tvb, 0, 1, ENC_NA);
    }
    else {
        pi = proto_tree_add_text(sess_tree, tvb, 0, 1, "Invalid SPDU tag");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "See table 14 in the DVB-CI specification");
        return;
    }

    offset = dissect_ber_length(pinfo, sess_tree, tvb, 1, &len_field, NULL);

    si = (spdu_info_t *)g_hash_table_lookup(spdu_table,
                                            GUINT_TO_POINTER((guint)tag));
    if (!si)
        return;
    if (si->direction!=0 && si->direction!=direction) {
        pi = proto_tree_add_text(sess_tree, tvb, 0, 1,
                "Invalid SPDU direction");
        if (si->direction==DATA_HOST_TO_CAM) {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "This SPDU must be sent from host to CAM");
        }
        else {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "This SPDU must be sent from CAM to host");
        }
    }
    if (si->len_field != len_field) {
        /* offset points to 1st byte after the length field */
        pi = proto_tree_add_text(sess_tree, tvb, 1, offset-1,
                "Invalid SPDU length field");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Correct length field for %s is %d", tag_str, si->len_field);
        return;
    }

    switch(tag)
    {
        case T_OPEN_SESSION_REQUEST:
            res_id = tvb_get_ntohl(tvb, offset); /* get 32bit big-endian */
            dissect_dvbci_res_id(tvb, offset, pinfo, sess_tree, res_id, TRUE);
            break;
        case T_CREATE_SESSION:
            res_id = tvb_get_ntohl(tvb, offset);
            dissect_dvbci_res_id(tvb, offset, pinfo, sess_tree, res_id, TRUE);
            /* DVB-CI uses network byte order == big endian */
            proto_tree_add_item(
                    sess_tree, hf_dvbci_sess_nb, tvb,
                    offset+4, 2, ENC_BIG_ENDIAN);
            break;
        case T_OPEN_SESSION_RESPONSE:
        case T_CREATE_SESSION_RESPONSE:
            sess_stat = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(
                    sess_tree, hf_dvbci_sess_status, tvb, offset, 1, ENC_NA);
            res_id = tvb_get_ntohl(tvb, offset+1);
            dissect_dvbci_res_id(tvb, offset+1, pinfo, sess_tree, res_id, TRUE);
            proto_tree_add_item(sess_tree, hf_dvbci_sess_nb, tvb,
                    offset+1+RES_ID_LEN, 2, ENC_BIG_ENDIAN);
            if (sess_stat == SESS_OPENED)
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                        "Session opened");
            else
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Error");
            break;
        case T_CLOSE_SESSION_REQUEST:
            proto_tree_add_item(
                    sess_tree, hf_dvbci_sess_nb, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            break;
        case T_CLOSE_SESSION_RESPONSE:
            sess_stat = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(
                    sess_tree, hf_dvbci_close_sess_status, tvb,
                    offset, 1, ENC_NA);
            proto_tree_add_item(
                    sess_tree, hf_dvbci_sess_nb, tvb,
                    offset+1, 2, ENC_BIG_ENDIAN);
            if (sess_stat == SESS_CLOSED) {
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                        "Session closed");
            }
            else
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Error");
            break;
        case T_SESSION_NUMBER:
            proto_tree_add_item(
                    sess_tree, hf_dvbci_sess_nb, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            payload_len = tvb_reported_length_remaining(tvb, offset+2);
            payload_tvb =
                tvb_new_subset(tvb, offset+2, payload_len, payload_len);
            break;
        default:
            break;
    }
    offset += len_field;

    if (payload_tvb) {
        proto_item_set_len(ti, spdu_len-tvb_reported_length(payload_tvb));
        dissect_dvbci_apdu(payload_tvb, pinfo, tree, direction);
    }
    else {
        proto_item_set_len(ti, spdu_len);
    }
}

/* dissect the status of an r_tpdu, return its length or -1 for error */
static gint
dissect_dvbci_tpdu_status(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree,
        guint8 lpdu_tcid, guint8 r_tpdu_tag)
{
    gint offset_new, len_start_offset;
    guint8 tag;
    guint32 len_field;
    guint8 t_c_id, sb_value;
    const gchar *sb_str;
    proto_item *pi;

    offset_new = offset;

    tag = tvb_get_guint8(tvb, offset_new);
    if (tag!=T_SB) {
        pi = proto_tree_add_text(
                tree, tvb, offset_new, 1, "Invalid status tag");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "This must always be T_SB (0x80)");
        return -1;
    }
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "T_SB");
    proto_tree_add_text(tree, tvb, offset_new, 1, "Response TPDU status");
    offset_new++;

    len_start_offset = offset_new;
    offset_new = dissect_ber_length(
            pinfo, tree, tvb, offset_new, &len_field, NULL);
    if (len_field != 2) {
        pi = proto_tree_add_text(
                tree, tvb, len_start_offset, offset_new-len_start_offset,
                "Invalid status length field");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "This must always be 2");

        return -1;
    }

    t_c_id = tvb_get_guint8(tvb, offset_new);
    proto_tree_add_item(tree, hf_dvbci_t_c_id, tvb, offset_new, 1, ENC_NA);
    /* tcid in transport header and link layer must only match for data
     * transmission commands */
    if (t_c_id!=lpdu_tcid) {
        if (r_tpdu_tag==NO_TAG ||
                r_tpdu_tag==T_DATA_MORE || r_tpdu_tag==T_DATA_LAST) {

            pi = proto_tree_add_text(tree, tvb, offset_new, 1,
                    "Transport Connection ID mismatch");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                 "tcid is %d in the transport layer and %d in the link layer",
                    t_c_id, lpdu_tcid);

            return -1;
        }
    }
    offset_new++;

    sb_value = tvb_get_guint8(tvb, offset_new);
    sb_str = match_strval(sb_value, dvbci_sb_value);
    if (sb_str) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s", sb_str);
        proto_tree_add_item(tree, hf_dvbci_sb_value, tvb,
                offset_new, 1, ENC_NA);
    }
    else {
        pi = proto_tree_add_text(tree, tvb, offset_new, 1,
                "Invalid SB_value");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Must be 0x00 or 0x80");
    }
    offset_new++;

    return offset_new-offset;
}


/* dissect the header of a c_tpdu or r_tpdu
   return the length of the header (tag, len_field, t_c_id) or -1 for error */
static gint
dissect_dvbci_tpdu_hdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction, guint8 lpdu_tcid, guint32 tpdu_len,
        guint8 *hdr_tag, guint32 *body_len)
{
    guint8 c_tpdu_tag, r_tpdu_tag, *tag=NULL;
    const gchar *c_tpdu_str, *r_tpdu_str;
    proto_item *pi;
    gint offset;
    guint32 len_field;
    guint8 t_c_id;

    if (direction==DATA_HOST_TO_CAM) {
        c_tpdu_tag = tvb_get_guint8(tvb, 0);
        tag = &c_tpdu_tag;
        c_tpdu_str = match_strval(c_tpdu_tag, dvbci_c_tpdu);
        if (c_tpdu_str) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", c_tpdu_str);
            proto_tree_add_item(tree, hf_dvbci_c_tpdu_tag, tvb, 0, 1, ENC_NA);
        }
        else {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "Invalid Command-TPDU tag");
            pi = proto_tree_add_text(
                    tree, tvb, 0, 1, "Invalid Command-TPDU tag");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "see DVB-CI specification, table A.16 for valid values");
            return -1;
        }
    }
    else {
        r_tpdu_tag = tvb_get_guint8(tvb, 0);
        tag = &r_tpdu_tag;
        r_tpdu_str = match_strval(r_tpdu_tag, dvbci_r_tpdu);
        if (r_tpdu_str) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", r_tpdu_str);
            proto_tree_add_item(tree, hf_dvbci_r_tpdu_tag, tvb, 0, 1, ENC_NA);
        }
        else {
            if (r_tpdu_tag == T_SB) {
                /* we have an r_tpdu without header and body,
                   it contains only the status part */
                if (hdr_tag)
                    *hdr_tag = NO_TAG;
                if (body_len)
                    *body_len = 0;
                return 0;
            }
            else {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                        "Invalid Response-TPDU tag");
                pi = proto_tree_add_text(
                        tree, tvb, 0, 1, "Invalid Response-TPDU tag");
                expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                   "see DVB-CI specification, table A.16 for valid values");
                return -1;
            }
        }
    }

    offset = dissect_ber_length(pinfo, tree, tvb, 1, &len_field, NULL);
    if (((direction==DATA_HOST_TO_CAM) && ((offset+len_field)!=tpdu_len)) ||
        ((direction==DATA_CAM_TO_HOST) && ((offset+len_field)>tpdu_len))) {
        /* offset points to 1st byte after the length field */
        pi = proto_tree_add_text(
                tree, tvb, 1, offset-1, "Length field mismatch");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Length field mismatch");
        return -1;
    }

    t_c_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_dvbci_t_c_id, tvb, offset, 1, ENC_NA);
    /* tcid in transport header and link layer must only match for
     * data transmission commands */
    if (t_c_id!=lpdu_tcid) {
        if (tag && (*tag==T_RCV || *tag==T_DATA_MORE || *tag==T_DATA_LAST)) {
            pi = proto_tree_add_text(tree, tvb, offset, 1,
                    "Transport Connection ID mismatch");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
               "tcid is %d in the transport layer and %d in the link layer",
                    t_c_id, lpdu_tcid);
        }
    }
    else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "tcid %d", t_c_id);
    }
    offset++;

    if (hdr_tag && tag)
        *hdr_tag = *tag;
    if (body_len)
        *body_len = len_field-1;  /* -1 for t_c_id */
    return offset;
}

static void
dissect_dvbci_tpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction, guint8 lpdu_tcid)
{
    guint32 tpdu_len, body_len;
    proto_item *ti = NULL;
    proto_tree *trans_tree = NULL;
    gint offset, status_len;
    guint8 hdr_tag = NO_TAG;
    tvbuff_t *payload_tvb = NULL;
    proto_item *pi;


    tpdu_len = tvb_reported_length(tvb);

    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, -1, "Transport Layer");
        trans_tree = proto_item_add_subtree(ti, ett_dvbci_transport);
    }

    offset = dissect_dvbci_tpdu_hdr(tvb, pinfo, trans_tree, direction,
            lpdu_tcid, tpdu_len, &hdr_tag, &body_len);
    if (offset==-1)
        return;
    proto_item_set_len(ti, offset);
    if ((offset>0) && (body_len!=0)) {
        payload_tvb = tvb_new_subset(tvb, offset, body_len, body_len);
        offset += body_len;
    }

    if (direction==DATA_CAM_TO_HOST) {
        /* minimum length of an rtpdu status is 4 bytes */
        if (tpdu_len-offset < 4) {
            pi = proto_tree_add_text(trans_tree, tvb, 0, 0,
                    "Response TPDU's status part is missing");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "RTPDU status is mandatory");
            return;
        }
        status_len = dissect_dvbci_tpdu_status(
                tvb, offset, pinfo, trans_tree, lpdu_tcid, hdr_tag);
        if (status_len<0)
            return;
        proto_tree_set_appendix(trans_tree, tvb, offset, status_len);
    }

    if (payload_tvb)
        dissect_dvbci_spdu(payload_tvb, pinfo, tree, direction);
}


static void
dissect_dvbci_lpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction)
{
    proto_item *ti;
    proto_tree *link_tree = NULL;
    guint32 payload_len;
    guint8 tcid, more_last;
    proto_item *pi;
    tvbuff_t *payload_tvb = NULL;


    payload_len = tvb_reported_length(tvb);

    col_add_str(pinfo->cinfo, COL_INFO, "LPDU");

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, 2, "Link Layer");
        link_tree = proto_item_add_subtree(ti, ett_dvbci_link);
    }

    tcid = tvb_get_guint8(tvb, 0);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "tcid %d", tcid);
    proto_tree_add_item(link_tree, hf_dvbci_tcid, tvb, 0, 1, ENC_NA);

    more_last = tvb_get_guint8(tvb, 1);
    if (more_last == ML_MORE) {
        col_append_sep_fstr(
                pinfo->cinfo, COL_INFO, NULL, "more fragments follow");
    }
    else if (more_last == ML_LAST)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "last fragment");

    if (match_strval(more_last, dvbci_ml)) {
        proto_tree_add_item(link_tree, hf_dvbci_ml, tvb, 1, 1, ENC_NA);
    }
    else {
        pi = proto_tree_add_text(
                link_tree, tvb, 1, 1, "Invalid More/Last indicator");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Second byte of an LPDU must be 0x80 or 0x00");
    }
    /* keep this error case separate, it'll be removed soon */
    if (more_last == ML_MORE) {
        pi = proto_tree_add_text(link_tree, tvb, 1, 1, "Unsupported LPDU");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Reassembly of fragmented packets is not implemented yet");
        return;
    }

    if (payload_len > buf_size_host) {
        pi = proto_tree_add_text(
                link_tree, tvb, 2, payload_len, "Payload too large");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
           "Maximum payload length is the negotiated buffer size (%d bytes)",
                buf_size_host);
    }

    payload_tvb = tvb_new_subset(tvb, 2, -1, -1);
    dissect_dvbci_tpdu(payload_tvb, pinfo, tree, direction, tcid);
}

/* dissect DVB-CI buffer size negotiation */
static void
dissect_dvbci_buf_neg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction)
{
    guint16 buf_size;
    proto_item *pi;

    buf_size = tvb_get_ntohs(tvb, 0);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %u bytes",
                 direction == DATA_HOST_TO_CAM ?
                 "negotiated buffer size" : "buffer size proposal",
                 buf_size);

    if (direction == DATA_HOST_TO_CAM) {
        buf_size_host = buf_size;
        proto_tree_add_uint_format(tree, hf_dvbci_buf_size, tvb,
                0, 2, buf_size,
                "Negotiated buffer size: %u bytes", buf_size);
        if (buf_size_host > buf_size_cam) {
            /* ATTENTION:
               wireshark may run through each packet multiple times
               if we didn't check the direction, we'd get the error when
               wireshark runs through the initial CAM packet for the 2nd time
             */
            pi = proto_tree_add_text(tree, tvb, 0, 2,
                    "Illegal buffer size command");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                                   "Host shall not request a buffer size larger than the CAM proposal");
        }
    }
    else if (direction == DATA_CAM_TO_HOST) {
        buf_size_cam = buf_size;
        proto_tree_add_uint_format(tree, hf_dvbci_buf_size, tvb,
                0, 2, buf_size,
                "Buffer size proposal by the CAM: %u bytes", buf_size);
    }

    if (buf_size < 16) {
        pi = proto_tree_add_text(tree, tvb, 0, 2, "Illegal buffer size");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Minimum buffer size is 16 bytes");
    }
}

static int
dissect_dvbci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint packet_len, offset = 0, offset_ver, offset_evt, offset_len_field;
    guint8 version, event;
    const gchar *event_str;
    guint16 len_field;
    proto_item *ti, *ti_hdr;
    proto_tree *dvbci_tree = NULL, *hdr_tree = NULL;
    tvbuff_t *payload_tvb;
    guint16 cor_addr;
    guint8 cor_value;
    proto_item *pi;
    guint8 hw_event;

    if (tvb_length(tvb) < 4)
        return 0;

    offset_ver = offset;
    version = tvb_get_guint8(tvb, offset++);
    if (version != 0)
        return 0;

    offset_evt = offset;
    event = tvb_get_guint8(tvb, offset++);
    event_str = match_strval(event, dvbci_event);
    if (!event_str)
        return 0;

    packet_len = tvb_reported_length(tvb);
    offset_len_field = offset;
    len_field = tvb_get_ntohs(tvb, offset);
    if (len_field != (packet_len-4))
        return 0;
    offset += 2;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DVB-CI");
    col_set_str(pinfo->cinfo, COL_INFO, event_str);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_dvbci,
                tvb, 0, packet_len, "DVB Common Interface: %s", event_str);
        dvbci_tree = proto_item_add_subtree(ti, ett_dvbci);
        ti_hdr = proto_tree_add_text(dvbci_tree, tvb, 0, offset, "Pseudo header");
        hdr_tree = proto_item_add_subtree(ti_hdr, ett_dvbci_hdr);
        proto_tree_add_text(hdr_tree, tvb, offset_ver, 1, "Version: %d", version);
        proto_tree_add_item(hdr_tree, hf_dvbci_event, tvb, offset_evt, 1, ENC_NA);
        proto_tree_add_text(hdr_tree, tvb, offset_len_field, 2,
                "Length field: %d", len_field);
    }

    if (IS_DATA_TRANSFER(event)) {
        if (event == DATA_HOST_TO_CAM) {
            SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR_HOST)+1, ADDR_HOST);
            SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR_CAM)+1 , ADDR_CAM);
        }
        else {
            SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR_CAM)+1 , ADDR_CAM);
            SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR_HOST)+1, ADDR_HOST);
        }

        payload_tvb = tvb_new_subset( tvb, offset, -1, -1);
        if (len_field == 2) {
            dissect_dvbci_buf_neg(payload_tvb, pinfo, dvbci_tree, event);
        }
        else {
            dissect_dvbci_lpdu(payload_tvb, pinfo, dvbci_tree, event);
        }
    }
    else if (event==COR_WRITE) {
        /* I did not assign hf_... values for cor_addr and cor_value
           there's no need to filter against them */
        cor_addr = tvb_get_ntohs(tvb, offset);
        if (cor_addr == 0xffff) {
            proto_tree_add_text(dvbci_tree, tvb, offset, 2,
                "COR address is unknown");
            col_append_sep_str(pinfo->cinfo, COL_INFO, ": ", "unknown address");
        }
        else if (cor_addr > 0xFFE) {
            pi = proto_tree_add_text(tree, tvb, offset, 2, "Invalid COR address");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "COR address must not be greater than 0xFFE (DVB-CI spec, A.5.6)");
        }
        else {
            proto_tree_add_text(dvbci_tree, tvb, offset, 2,
                "COR address: 0x%x", cor_addr);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                "address 0x%x", cor_addr);
        }
        offset += 2;
        cor_value = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(dvbci_tree, tvb, offset, 1,
                "COR value: 0x%x", cor_value);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
            "value 0x%x", cor_value);
        offset++;
    }
    else if (event==HW_EVT) {
        hw_event = tvb_get_guint8(tvb, offset);
        col_set_str(pinfo->cinfo, COL_INFO,
                val_to_str_const(hw_event, dvbci_hw_event, "Invalid hardware event"));
        proto_tree_add_item(dvbci_tree, hf_dvbci_hw_event,
                tvb, offset, 1, ENC_NA);
        offset++;
    }

    return packet_len;
}


void
proto_register_dvbci(void)
{
    guint i;

    static gint *ett[] = {
        &ett_dvbci,
        &ett_dvbci_hdr,
        &ett_dvbci_link,
        &ett_dvbci_transport,
        &ett_dvbci_session,
        &ett_dvbci_res,
        &ett_dvbci_application,
        &ett_dvbci_es,
        &ett_dvbci_ca_desc
    };

    static hf_register_info hf[] = {
        { &hf_dvbci_event,
            { "Event", "dvbci.event", FT_UINT8, BASE_HEX,
                VALS(dvbci_event), 0, NULL, HFILL } },
        { &hf_dvbci_hw_event,
            { "Hardware event", "dvbci.hw_event", FT_UINT8, BASE_HEX,
                VALS(dvbci_hw_event), 0, NULL, HFILL } },
        { &hf_dvbci_buf_size,
            { "Buffer Size", "dvbci.buf_size", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_dvbci_tcid,
            { "Transport Connection ID", "dvbci.tcid", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_dvbci_ml,
            { "More/Last indicator", "dvbci.more_last", FT_UINT8, BASE_HEX,
                VALS(dvbci_ml), 0, NULL, HFILL } },
        { &hf_dvbci_c_tpdu_tag,
            { "Command TPDU Tag", "dvbci.c_tpdu_tag", FT_UINT8, BASE_HEX,
                VALS(dvbci_c_tpdu), 0, NULL, HFILL } },
        { &hf_dvbci_r_tpdu_tag,
            { "Response TPDU Tag", "dvbci.r_tpdu_tag", FT_UINT8, BASE_HEX,
                VALS(dvbci_r_tpdu), 0, NULL, HFILL } },
        { &hf_dvbci_t_c_id,
            { "Transport Connection ID", "dvbci.t_c_id", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_dvbci_sb_value,
            { "SB Value", "dvbci.sb_value", FT_UINT8, BASE_HEX,
                VALS(dvbci_sb_value), 0, NULL, HFILL } },
        { &hf_dvbci_spdu_tag,
            { "SPDU Tag", "dvbci.spdu_tag", FT_UINT8, BASE_HEX,
                VALS(dvbci_spdu_tag), 0, NULL, HFILL } },
        { &hf_dvbci_sess_status,
            { "Session Status", "dvbci.session_status", FT_UINT8, BASE_HEX,
                VALS(dvbci_sess_status), 0, NULL, HFILL } },
        { &hf_dvbci_sess_nb,
            { "Session Number", "dvbci.session_nb", FT_UINT16, BASE_DEC,
                NULL , 0, NULL, HFILL } },
        { &hf_dvbci_close_sess_status,
            { "Session Status", "dvbci.close_session_status", FT_UINT8,
                BASE_HEX, VALS(dvbci_close_sess_status), 0, NULL, HFILL } },
        { &hf_dvbci_apdu_tag,
            { "APDU Tag", "dvbci.apdu_tag", FT_UINT24, BASE_HEX,
                VALS(dvbci_apdu_tag), 0, NULL, HFILL } },
        { &hf_dvbci_app_type,
            { "Application type", "dvbci.application_type", FT_UINT8,
                BASE_HEX, VALS(dvbci_app_type), 0, NULL, HFILL } },
        { &hf_dvbci_app_manf,
            { "Application manufacturer", "dvbci.application_manufacturer",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvbci_manf_code,
            { "Manufacturer code", "dvbci.manufacturer_code", FT_UINT16,
                BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvbci_menu_str_len,
            { "Menu string length", "dvbci.menu_string_length",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_dvbci_ca_sys_id,
            { "CA system ID", "dvbci.ca_system_id", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_dvbci_ca_pmt_list_mgmt,
            { "CA PMT list management", "dvbci.ca_pmt_list_management",
                FT_UINT8, BASE_HEX, VALS(dvbci_ca_pmt_list_mgmt), 0, NULL,
                HFILL } },
        { &hf_dvbci_prog_num,
            { "Program number", "dvbci.program_number", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_dvbci_prog_info_len,
            { "Program info length", "dvbci.program_info_length", FT_UINT16,
                BASE_HEX, NULL, 0x0FFF, NULL, HFILL } },
        { &hf_dvbci_stream_type,
            { "Stream type", "dvbci.stream_type", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_dvbci_es_pid,
            { "Elementary stream PID", "dvbci.elementary_pid", FT_UINT16,
                BASE_HEX, NULL, 0x1FFF, NULL, HFILL } },
        { &hf_dvbci_es_info_len,
            { "Elementary stream info length", "dvbci.es_info_length",
                FT_UINT16, BASE_HEX, NULL, 0x0FFF, NULL, HFILL } },
        { &hf_dvbci_ca_pmt_cmd_id,
            { "CA PMT command ID", "dvbci.ca_pmt_cmd_id", FT_UINT8, BASE_HEX,
                VALS(dvbci_ca_pmt_cmd_id), 0, NULL, HFILL } },
        { &hf_dvbci_descr_len,
            { "CA descriptor length", "dvbci.ca_desc_len", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_dvbci_ca_pid,
            { "CA PID", "dvbci.ca_pid", FT_UINT16, BASE_HEX,
                NULL, 0x1FFF, NULL, HFILL } },
        { &hf_dvbci_network_id,
           { "Network ID", "dvbci.hc.nid", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL } },
        { &hf_dvbci_original_network_id,
           { "Original network ID", "dvbci.hc.onid", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL } },
        { &hf_dvbci_transport_stream_id,
           { "Transport stream ID", "dvbci.hc.tsid", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL } },
        { &hf_dvbci_service_id,
           { "Service ID", "dvbci.hc.svcid", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL } },
        { &hf_dvbci_replacement_ref,
           { "Replacement reference", "dvbci.hc.replacement_ref",
              FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvbci_replaced_pid,
           { "Replaced PID", "dvbci.hc.replaced_pid", FT_UINT16,
              BASE_HEX, NULL, 0x1FFF, NULL, HFILL } },
        { &hf_dvbci_replacement_pid,
           { "Replacement PID", "dvbci.hc.replacement_pid", FT_UINT16,
              BASE_HEX, NULL, 0x1FFF, NULL, HFILL } },
        { &hf_dvbci_resp_intv,
            { "Response interval", "dvbci.dt.resp_interval",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_dvbci_utc_time,
            { "UTC time", "dvbci.dt.utc_time",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL } },
        /* we have to use FT_INT16 instead of FT_RELATIVE_TIME,
           local offset can be negative */
        { &hf_dvbci_local_offset,
            { "Local time offset", "dvbci.dt.local_offset", FT_INT16, BASE_DEC,
                NULL, 0, NULL, HFILL } }
   };

    spdu_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!spdu_table)
        return;
    for(i=0; i<array_length(spdu_info); i++) {
        g_hash_table_insert(spdu_table,
                GUINT_TO_POINTER((guint)spdu_info[i].tag),
                (gpointer)(&spdu_info[i]));
    }
    apdu_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!apdu_table)
        return;
    for(i=0; i<array_length(apdu_info); i++) {
        g_hash_table_insert(apdu_table,
                GUINT_TO_POINTER((guint)apdu_info[i].tag),
                (gpointer)(&apdu_info[i]));
    }

    proto_dvbci = proto_register_protocol(
            "DVB Common Interface", "DVB-CI", "dvb-ci");
    proto_register_field_array(proto_dvbci, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(dvbci_init);
}


void
proto_reg_handoff_dvbci(void)
{
    dissector_handle_t dvbci_handle;

    dvbci_handle = new_create_dissector_handle(dissect_dvbci, proto_dvbci);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_DVBCI, dvbci_handle);
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
 * vi: shiftwidth=4 tabstop=8 expandtab
 * :indentSize=4:tabSize=8:noTabs=true:
 */
