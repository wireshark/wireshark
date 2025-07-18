/* packet-sasp.c
 * Routines for sasp packet dissection
 * Copyright 2010, Venkateshwaran Dorai<venkateshwaran.d@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include "packet-tcp.h"

/* forward reference */
void proto_register_sasp(void);
void proto_reg_handoff_sasp(void);

static dissector_handle_t sasp_handle;

static void dissect_reg_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t offset);
static void dissect_dereg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset);
static void dissect_reg_rep(tvbuff_t *tvb, proto_tree *tree, uint32_t offset);
static void dissect_dereg_rep(tvbuff_t *tvb, proto_tree *tree, uint32_t offset);
static void dissect_sendwt(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t offset);
static void dissect_setmemstate_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t offset);
static void dissect_setmemstate_rep(tvbuff_t *tvb, proto_tree *tree, uint32_t offset);
static void dissect_setlbstate_req(tvbuff_t *tvb, proto_tree *tree, uint32_t offset);
static void dissect_setlbstate_rep(tvbuff_t *tvb, proto_tree *tree, uint32_t offset);
static void dissect_wt_req(tvbuff_t *tvb, proto_tree *tree, uint32_t offset);
static void dissect_wt_rep(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t offset);
static uint32_t dissect_grpdatacomp(tvbuff_t *tvb, proto_tree *tree, uint32_t offset);
static uint32_t dissect_grp_memdatacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t offset);
static uint32_t dissect_grp_memstatedatacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t offset);
static uint32_t dissect_memstatedatacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t offset);
static uint32_t dissect_grp_wt_entry_datacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t offset);

/* Initialize the protocol and registered fields */
static int proto_sasp;
static int hf_sasp_type;
static int hf_sasp_length;
static int hf_sasp_vrsn;
static int hf_msg_len;
static int hf_msg_id;
static int hf_msg_type;

/*reg reply*/
static int hf_sasp_reg_rep_rcode;
static int hf_sasp_reg_rep_sz;

/*reg req*/
static int hf_sasp_reg_req_sz;
static int hf_reg_req_lbflag;
static int hf_sasp_gmd_cnt;

/*dereg req*/
static int hf_sasp_dereg_req_sz;
static int hf_dereg_req_lbflag;
/* static int hf_dereg_req_reason; */
static int hf_dereg_req_reason_flag;

/*dereg reply*/
static int hf_sasp_dereg_rep_rcode;
static int hf_sasp_dereg_rep_sz;

/*send wt*/
static int hf_sasp_sendwt_gwedcnt;
static int hf_sasp_sendwt_sz;

/*setmemstate req*/
static int hf_sasp_setmemstate_req_sz;
static int hf_setmemstate_req_lbflag;
/*static int hf_sasp_setmemstate_req_data;*/
static int hf_sasp_setmemstate_req_gmsd_cnt;

/*setmemstate reply*/
/* static int hf_sasp_setmemstate_rep; */
static int hf_sasp_setmemstate_rep_rcode;
static int hf_sasp_setmemstate_rep_sz;

/*mem data comp */
static int hf_sasp_memdatacomp_type;
static int hf_sasp_memdatacomp_sz;
static int hf_sasp_memdatacomp_protocol;
static int hf_sasp_memdatacomp_port;
static int hf_sasp_memdatacomp_ip;
static int hf_sasp_memdatacomp_lab_len;
static int hf_sasp_memdatacomp_label;

/*grp data comp */
static int hf_sasp_grpdatacomp;
static int hf_sasp_grpdatacomp_sz;
static int hf_sasp_grpdatacomp_LB_uid_len;
static int hf_sasp_grpdatacomp_LB_uid;
static int hf_sasp_grpdatacomp_grp_name_len;
static int hf_sasp_grpdatacomp_grp_name;

/*grp mem data comp */
static int hf_sasp_grp_memdatacomp;
static int hf_sasp_grp_memdatacomp_sz;
static int hf_sasp_grp_memdatacomp_cnt;

/*weight req*/
static int hf_sasp_wt_req_sz;
static int hf_sasp_wt_req_gd_cnt;

/*weight rep*/
static int hf_sasp_wt_rep_sz;
static int hf_sasp_wt_rep_rcode;
static int hf_sasp_wt_rep_interval;
static int hf_sasp_wt_rep_gwed_cnt;

/*setlbstate req*/
static int hf_sasp_setlbstate_req_sz;
static int hf_sasp_setlbstate_req_LB_uid_len;
static int hf_sasp_setlbstate_req_LB_uid;
static int hf_sasp_setlbstate_req_LB_health;
/*static int hf_sasp_setlbstate_req_LB_flag;*/
/* static int hf_lbstate_flag; */
static int hf_sasp_pushflag;
static int hf_sasp_trustflag;
static int hf_sasp_nochangeflag;

/*setlbstate reply*/
/* static int hf_sasp_setlbstate_rep; */
static int hf_sasp_setlbstate_rep_rcode;
static int hf_sasp_setlbstate_rep_sz;

/*grp mem state data*/
static int hf_sasp_grp_memstatedatacomp;
static int hf_sasp_grp_memstatedatacomp_sz;
static int hf_sasp_grp_memstatedatacomp_cnt;

/*mem state data comp*/
static int hf_sasp_memstatedatacomp_instance;
static int hf_sasp_memstatedatacomp_sz;
static int hf_sasp_memstatedatacomp_state;
static int hf_sasp_memstatedatacomp_quiesce_flag;

/*wt entry dat  comp*/
static int hf_sasp_weight_entry_data_comp_type;
static int hf_sasp_weight_entry_data_comp_sz;
static int hf_sasp_weight_entry_data_comp_state;
/* static int hf_wtstate_flag; */
static int hf_sasp_wed_contactsuccess_flag;
static int hf_sasp_wed_quiesce_flag;
static int hf_sasp_wed_registration_flag;
static int hf_sasp_wed_confident_flag;
static int hf_sasp_weight_entry_data_comp_weight;

/*grp wt entry data comp */
static int hf_sasp_grp_wt_entry_datacomp_type;
static int hf_sasp_grp_wt_entry_datacomp_sz;
static int hf_sasp_grp_wt_entry_datacomp_cnt;

/* Initialize the subtree pointers */
static int ett_sasp_data;
static int ett_sasp_header;
static int ett_sasp_msg;
static int ett_sasp_payload;
static int ett_sasp_reg_req;
static int ett_sasp_reg_rep;
static int ett_sasp_reg_req_sz;
static int ett_sasp_dereg_req_sz;
static int ett_sasp_dereg_rep;
static int ett_sasp_sendwt;
static int ett_sasp_setmemstate_rep;
static int ett_sasp_memdatacomp;
static int ett_sasp_grpdatacomp;
static int ett_sasp_grp_memdatacomp;
static int ett_sasp_setlbstate_req;
static int ett_sasp_setlbstate_rep;
static int ett_sasp_getwt;
static int ett_sasp_setmemstate_req;
static int ett_setlbstate_req_lbflag;
static int ett_sasp_grp_memstatedatacomp;
static int ett_sasp_memstatedatacomp;
/*static int ett_dereg_req_reason_flag;*/
static int ett_sasp_grp_wt_entry_datacomp;
static int ett_sasp_weight_entry_data_comp;
static int ett_wt_entry_data_flag;
static int ett_sasp_wt_rep;

static expert_field ei_msg_type_invalid;

/* desegmentation of SASP over TCP */
static bool sasp_desegment = true;

static const value_string msg_table[] = {
    { 0x1010, "Registration Request" },
    { 0x1015, "Registration Reply"},
    { 0x1020, "DeRegistration Request"},
    { 0x1025, "DeRegistration Reply"},
    { 0x1030, "Get Weights Request"},
    { 0x1035, "Get Weights Reply" },
    { 0x1040, "Send Weights"},
    { 0x1050, "Set LB State Request"},
    { 0x1055, "Set LB State Reply"},
    { 0x1060, "Set Member State Request"},
    { 0x1065, "Set Member State Reply"},
    { 0x3010, "Member Data Component"},
    { 0x3011, "Group Data Component"},
    { 0x3012, "Weight Entry Data Component"},
    { 0x3013, "Member State Instance"},
    { 0x4010, "Group of Member Data"},
    { 0x4011, "Group of Weight Entry Data" },
    { 0x4012, "Group of Member State Data" },
    {      0,  NULL }
};
static value_string_ext msg_table_ext = VALUE_STRING_EXT_INIT(msg_table);

static const value_string protocol_table[] = {
    { 0x06, "TCP" },
    { 0x11, "UDP" },
    {    0,  NULL }
};

static const value_string lbstate_healthtable[] = {
    { 0x00, "Least Healthy" },
    { 0x7f, "Most Healthy" },
    {    0, NULL }
};

static const value_string reg_reply_response_code[] = {
    { 0x00, "Successful" },
    { 0x10, "Message not understood" },
    { 0x11, "GWM will not accept this message from the sender" },
    { 0x40, "Member already registered" },
    { 0x44, "Duplicate Member in Request" },
    { 0x45, "Invalid Group (determined by the GWM)"},
    { 0x50, "Invalid Group Name Size (size == 0)"},
    { 0x51, "Invalid LB uid Size (size == 0 or > max)"},
    { 0x61, "Member is registering itself, but LB hasn't yet contacted the GWM."
        "  This registration will not be processed."},
    {    0, NULL }
};

static const value_string dereg_reply_response_code[] = {
    { 0x00, "Successful" },
    { 0x10, "Message not understood" },
    { 0x11, "GWM will not accept this message from the sender" },
    { 0x41, "Application or System not registered" },
    { 0x42, "Unknown Group Name" },
    { 0x43, "Unknown LB uid" },
    { 0x44, "Duplicate Member in Request"},
    { 0x46, "Duplicate Group in Request (for remove all members/groups requests)"},
    { 0x51, "Invalid LB uid Size (size == 0 or > max)"},
    { 0x61, "Member is deregistering itself, but LB hasn't yet contacted the GWM."
        "  This deregistration will not be processed."},
    {    0, NULL }
};

static const value_string get_weights_reply_response_code[] = {
    { 0x00, "Successful" },
    { 0x10, "Message not understood" },
    { 0x11, "GWM will not accept this message from the sender" },
    { 0x42, "Unknown Group Name" },
    { 0x43, "Unknown LB uid" },
    { 0x46, "Duplicate Group in Request"},
    { 0x51, "Invalid LB uid Size (size == 0 or > max)"},
    {    0, NULL }
};

static const value_string set_lb_state_reply_response_code[] = {
    { 0x00, "Successful" },
    { 0x10, "Message not understood" },
    { 0x11, "GWM will not accept this message from the sender" },
    { 0x51, "Invalid LB uid Size (size == 0 or > max)"},
    {    0, NULL }
};

static const value_string set_mem_state_reply_response_code[] = {
    { 0x00, "Successful" },
    { 0x10, "Message not understood" },
    { 0x11, "GWM will not accept this message from the sender" },
    { 0x41, "Application or System not registered" },
    { 0x42, "Unknown Group Name" },
    { 0x43, "Unknown LB uid" },
    { 0x44, "Duplicate Member in Request"},
    { 0x46, "Duplicate Group in Request (for remove all members/groups requests)"},
    { 0x50, "Invalid Group Name Size (size == 0)"},
    { 0x51, "Invalid LB uid Size (size == 0 or > max)"},
    {    0, NULL }
};


#define SASP_GLOBAL_PORT        3860
#define SASP_MIN_PACKET_LEN     13

#define SASP_DEREG_REQ_REASON_LEARNED   0x01
#define SASP_DEREG_REQ_NOREASON_FLAG    0x00
#define SASP_HDR_TYPE           0x2010
#define SASP_WED_CONTACT_SUCCESS_FLAG   0x01
#define SASP_WED_QUIESCE_FLAG       0x02
#define SASP_WED_REG_FLAG       0x04
#define SASP_WED_CONF_FLAG      0x08
#define SASP_PUSH_FLAG          0x01
#define SASP_TRUST_FLAG         0x02
#define SASP_NOCHANGE_FLAG      0x04
#define SASP_QUIESCE_FLAG       0x01


static unsigned
get_sasp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    /* Get the length of the SASP packet. */
    return tvb_get_ntohl(tvb, offset + 5);
}

/* Called from tcp_dissect_pdus with a complete SASP pdu */
static int
dissect_sasp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_item *hti;
    proto_item *mti;
    proto_tree *sasp_tree;
    proto_tree *msg_tree;
    proto_tree *pay_load;
    uint16_t    msg_type;
    uint16_t    hdr_type;
    uint32_t    offset = 0;

    /*protocol is being displayed*/

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SASP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_sasp, tvb, offset, -1, ENC_NA);
    sasp_tree = proto_item_add_subtree(ti, ett_sasp_header);

    hdr_type = tvb_get_ntohs(tvb, offset);
    hti = proto_tree_add_uint_format_value(sasp_tree, hf_sasp_type, tvb, offset, 2, hdr_type,
        "%s", (hdr_type == SASP_HDR_TYPE) ? "SASP" : "[Invalid]");
    if (hdr_type != SASP_HDR_TYPE)
    {
        expert_add_info_format(pinfo, hti, &ei_msg_type_invalid,
            "Invalid SASP Header Type [0x%04x]", hdr_type);
        /* XXX: The following should actually happen automatically ? */
        col_set_str(pinfo->cinfo, COL_INFO, "[Malformed: Invalid SASP Header Type]");
        return tvb_reported_length(tvb);
    }
    offset += 2;

    /*length*/
    proto_tree_add_item(sasp_tree, hf_sasp_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*Header Version */
    proto_tree_add_item(sasp_tree, hf_sasp_vrsn, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*Message*/
    msg_tree = proto_item_add_subtree(ti, ett_sasp_msg);

    /*Message Len*/
    proto_tree_add_item(msg_tree, hf_msg_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*Message Id*/
    proto_tree_add_item(msg_tree, hf_msg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*Message Type*/
    msg_type = tvb_get_ntohs(tvb, offset);
    mti = proto_tree_add_item(msg_tree, hf_msg_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    pay_load = proto_item_add_subtree(ti, ett_sasp_payload);
    offset += 2;

    switch(msg_type)
    {
        case 0x1010:
            /* Registration  Request */
            col_set_str(pinfo->cinfo, COL_INFO, "Registration Request");
            dissect_reg_req(tvb, pinfo, pay_load, offset);
            break;

        case 0x1015:
            /* Registration Reply */
            col_set_str(pinfo->cinfo, COL_INFO, "Registration Reply");
            dissect_reg_rep(tvb, pay_load, offset);
            break;

        case 0x1020:
            /* Deregistration Request */
            col_set_str(pinfo->cinfo, COL_INFO, "Deregistration Request");
            dissect_dereg_req(tvb, pinfo, pay_load, offset);
            break;

        case 0x1025:
            /* Deregistration Reply */
            col_set_str(pinfo->cinfo, COL_INFO, "Deregistration Reply");
            dissect_dereg_rep(tvb, pay_load, offset);
            break;

        case 0x1030:
            /* Get Weights Request */
            col_set_str(pinfo->cinfo, COL_INFO, "Get Weights Request");
            dissect_wt_req(tvb, pay_load, offset);
            break;

        case 0x1035:
            /* Get Weights Response */
            col_set_str(pinfo->cinfo, COL_INFO, "Get Weights Response");
            dissect_wt_rep(tvb, pinfo, pay_load, offset);
            break;

        case 0x1040:
            /* Send Weights Request */
            col_set_str(pinfo->cinfo, COL_INFO, "Send Weights Request");
            dissect_sendwt(tvb, pinfo, pay_load, offset);
            break;

        case 0x1050:
            /* Set LB State Request */
            col_set_str(pinfo->cinfo, COL_INFO, "Set LB State Request");
            dissect_setlbstate_req(tvb, pay_load, offset);
            break;

        case 0x1055:
            /* Set LB state Reply */
            col_set_str(pinfo->cinfo, COL_INFO, "Set LB State Reply");
            dissect_setlbstate_rep(tvb, pay_load, offset);
            break;

        case 0x1060:
            /* Set Member State Request*/
            col_set_str(pinfo->cinfo, COL_INFO, "Set Member State Request");
            dissect_setmemstate_req(tvb, pinfo, pay_load, offset);
            break;

        case 0x1065:
            /* Set Member State Reply */
            col_set_str(pinfo->cinfo, COL_INFO, "Set Member State Reply");
            dissect_setmemstate_rep(tvb, pay_load, offset);
            break;

        default:
            /* Unknown SASP Message Type */
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "[Malformed: Unknown Message Type [0x%04x]", msg_type);
            expert_add_info_format(pinfo, mti, &ei_msg_type_invalid,
                "Unknown SASP Message Type: 0x%4x", msg_type);
            break;
    }
    return tvb_reported_length(tvb);
}


static int
dissect_sasp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, sasp_desegment, SASP_MIN_PACKET_LEN, get_sasp_pdu_len,
                        dissect_sasp_pdu, data);
    return tvb_reported_length(tvb);
}


static void dissect_reg_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *reg_req_data;
    uint16_t    gmd_cnt, i;

    reg_req_data = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_reg_req_sz, NULL, "Reg Request");

    /* Reg Req Size */
    proto_tree_add_item(reg_req_data, hf_sasp_reg_req_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Reg Req LB Flag */
    proto_tree_add_item(reg_req_data, hf_reg_req_lbflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    gmd_cnt = tvb_get_ntohs(tvb, offset);

    /* Group MEM Data Count */
    proto_tree_add_item(reg_req_data, hf_sasp_gmd_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for (i=0; i<gmd_cnt; i++)
        offset = dissect_grp_memdatacomp(tvb, pinfo, reg_req_data, offset);
}


static void dissect_reg_rep(tvbuff_t *tvb, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *reg_rep_tree;

    reg_rep_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1 , ett_sasp_reg_rep, NULL, "Reg Reply");

    /* Size */
    proto_tree_add_item(reg_rep_tree, hf_sasp_reg_rep_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Response Code */
    proto_tree_add_item(reg_rep_tree, hf_sasp_reg_rep_rcode, tvb, offset, 1, ENC_BIG_ENDIAN);
}


static void dissect_dereg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pay_load, uint32_t offset)
{
    /*proto_item *dereg_req_reason_flag;*/
    /*proto_tree *dereg_req_reason_flag_tree;*/
    uint16_t         gmd_cnt, i;
    proto_tree      *dereg_req_data;
    uint8_t          reason_flag;
    static bool      first_flag         = true;
    wmem_strbuf_t   *reasonflags_strbuf = wmem_strbuf_create(pinfo->pool);
    static const char *fstr[] = {"No Reason", "Learned & Purposeful" };

    dereg_req_data = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_dereg_req_sz, NULL, "DeReg Request");

    /* Size */
    proto_tree_add_item(dereg_req_data, hf_sasp_dereg_req_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* LB Flag */
    proto_tree_add_item(dereg_req_data, hf_dereg_req_lbflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Reason */
    wmem_strbuf_truncate(reasonflags_strbuf, 0);
    reason_flag = tvb_get_uint8(tvb, offset);

    if ((reason_flag & SASP_DEREG_REQ_REASON_LEARNED) == 0)
        wmem_strbuf_append_printf(reasonflags_strbuf, "%s%s", first_flag ? "" : ", ", fstr[0]);
    else
        wmem_strbuf_append_printf(reasonflags_strbuf, "%s%s", first_flag ? "" : ", ", fstr[1]);
    first_flag = false;

    /*dereg_req_reason_flag =*/
    proto_tree_add_uint_format(dereg_req_data, hf_dereg_req_reason_flag, tvb,
        offset, 1, reason_flag, "Reason: 0x%02x (%s)", reason_flag,
        wmem_strbuf_get_str(reasonflags_strbuf));
#if 0   /* XXX: ToDo?? Flags to be displayed under a subtree ? */
    dereg_req_reason_flag_tree = proto_item_add_subtree(dereg_req_reason_flag, ett_dereg_req_reason_flag);
#endif
    offset += 1;

    gmd_cnt = tvb_get_ntohs(tvb, offset);

    /* Group Mem Data Count */
    proto_tree_add_item(dereg_req_data, hf_sasp_gmd_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*Group Mem Data */
    for (i=0; i<gmd_cnt; i++)
        offset = dissect_grp_memdatacomp(tvb, pinfo, dereg_req_data, offset);
}


static void dissect_dereg_rep(tvbuff_t *tvb, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *dereg_rep_tree;

    dereg_rep_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_dereg_rep, NULL, "Dereg Reply");

    /* Size */
    proto_tree_add_item(dereg_rep_tree, hf_sasp_dereg_rep_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Return Code */
    proto_tree_add_item(dereg_rep_tree, hf_sasp_dereg_rep_rcode, tvb, offset, 1, ENC_BIG_ENDIAN);
}


static void dissect_sendwt(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *sendwt_tree;
    uint16_t    gwed_cnt, i;

    sendwt_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_sendwt, NULL, "Send Weight");

    /* Size */
    proto_tree_add_item(sendwt_tree, hf_sasp_sendwt_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    gwed_cnt = tvb_get_ntohs(tvb, offset);

    /* Group Wt Entry Data Count */
    proto_tree_add_item(sendwt_tree, hf_sasp_sendwt_gwedcnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for (i=0; i<gwed_cnt; i++)
        offset = dissect_grp_wt_entry_datacomp(tvb, pinfo, sendwt_tree, offset);
}


static void dissect_setmemstate_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *setmemstate_req_data;
    uint32_t    gmsd_cnt, i;

    setmemstate_req_data = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_setmemstate_req, NULL, "Set Mem State Request");

    /* Size */
    proto_tree_add_item(setmemstate_req_data, hf_sasp_setmemstate_req_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*LB Flag*/
    proto_tree_add_item(setmemstate_req_data, hf_setmemstate_req_lbflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*Group Data Count*/
    proto_tree_add_item_ret_uint(setmemstate_req_data, hf_sasp_setmemstate_req_gmsd_cnt, tvb, offset, 2, ENC_BIG_ENDIAN, &gmsd_cnt);
    offset += 2;

    for (i=0; i<gmsd_cnt; i++)
        offset = dissect_grp_memstatedatacomp(tvb, pinfo, setmemstate_req_data, offset);
}

static void dissect_setmemstate_rep(tvbuff_t *tvb, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *setmemstate_rep_tree;

    setmemstate_rep_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_setmemstate_rep, NULL, "Set Mem State Reply");

    /* Size */
    proto_tree_add_item(setmemstate_rep_tree, hf_sasp_setmemstate_rep_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Response Code */
    proto_tree_add_item(setmemstate_rep_tree, hf_sasp_setmemstate_rep_rcode, tvb, offset, 1, ENC_BIG_ENDIAN);
}


static uint32_t dissect_memdatacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset, proto_tree **mdct_p)
{
    proto_item  *memdatacomp;
    proto_tree  *memdatacomp_tree;
    uint8_t      lab_len;
    const char *ip_str;
    ws_in6_addr ipv6_address;

    tvb_get_ipv6(tvb, offset+7, &ipv6_address);
    ip_str = tvb_ip6_to_str(pinfo->pool, tvb, offset+7);

    lab_len = tvb_get_uint8(tvb, offset+23);

    memdatacomp = proto_tree_add_ipv6_format(pay_load, hf_sasp_memdatacomp_ip,
        tvb, offset, 24+lab_len, &ipv6_address,
        "Member Data Comp (%s)", ip_str);

    memdatacomp_tree = proto_item_add_subtree(memdatacomp, ett_sasp_memdatacomp);

    /* Message Type */
    proto_tree_add_item(memdatacomp_tree, hf_sasp_memdatacomp_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Size */
    proto_tree_add_item(memdatacomp_tree, hf_sasp_memdatacomp_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Protocol */
    proto_tree_add_item(memdatacomp_tree, hf_sasp_memdatacomp_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Port */
    proto_tree_add_item(memdatacomp_tree, hf_sasp_memdatacomp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*Ip*/
    proto_tree_add_item(memdatacomp_tree, hf_sasp_memdatacomp_ip, tvb, offset, 16, ENC_NA);
    offset += 16;

    /*Label Len*/
    proto_tree_add_item(memdatacomp_tree, hf_sasp_memdatacomp_lab_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*Label*/
    proto_tree_add_item(memdatacomp_tree, hf_sasp_memdatacomp_label, tvb, offset, lab_len, ENC_ASCII);
    offset += lab_len;

    if (mdct_p != NULL)
        *mdct_p = memdatacomp_tree;

    return offset;
}


static uint32_t dissect_grpdatacomp(tvbuff_t *tvb, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *grpdatacomp_tree;
    uint8_t     LB_uid_len;
    uint8_t     grp_name_len;

    grpdatacomp_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_grpdatacomp, NULL, "Group Data Component");

    /*Type*/
    proto_tree_add_item(grpdatacomp_tree, hf_sasp_grpdatacomp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*Size*/
    proto_tree_add_item(grpdatacomp_tree, hf_sasp_grpdatacomp_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    LB_uid_len = tvb_get_uint8(tvb, offset);

    /* LB UID Len*/
    proto_tree_add_item(grpdatacomp_tree, hf_sasp_grpdatacomp_LB_uid_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(grpdatacomp_tree, hf_sasp_grpdatacomp_LB_uid,
        tvb, offset, LB_uid_len, ENC_ASCII);
    offset += (uint8_t)LB_uid_len;

    grp_name_len = tvb_get_uint8(tvb, offset);

    /*Group Name Len */
    proto_tree_add_item(grpdatacomp_tree, hf_sasp_grpdatacomp_grp_name_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*Group Name*/
    proto_tree_add_item(grpdatacomp_tree, hf_sasp_grpdatacomp_grp_name,
        tvb, offset, grp_name_len, ENC_ASCII);
    offset += grp_name_len;

    return offset;
}


static uint32_t dissect_grp_memdatacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *grp_memdatacomp_tree;
    uint16_t    mem_cnt;
    uint16_t    i;

    grp_memdatacomp_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_grp_memdatacomp, NULL, "Group Of Member Data");

    /* Group MEM Data */
    proto_tree_add_item(grp_memdatacomp_tree, hf_sasp_grp_memdatacomp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Group MEM Data Size*/
    proto_tree_add_item(grp_memdatacomp_tree, hf_sasp_grp_memdatacomp_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    mem_cnt = tvb_get_ntohs(tvb, offset);

    /* Group MEM Data Count*/
    proto_tree_add_item(grp_memdatacomp_tree, hf_sasp_grp_memdatacomp_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset = dissect_grpdatacomp(tvb, grp_memdatacomp_tree, offset);

    /* array of memdata */
    for (i=0; i<mem_cnt; i++)
        offset = dissect_memdatacomp(tvb, pinfo, grp_memdatacomp_tree, offset, NULL);

    return offset;
}


static void dissect_wt_req(tvbuff_t *tvb, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *get_wt_tree;
    uint16_t    gd_cnt, i;

    get_wt_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_getwt, NULL, "Get Wt Req");

    /* Size */
    proto_tree_add_item(get_wt_tree, hf_sasp_wt_req_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    gd_cnt = tvb_get_ntohs(tvb, offset);

    /* Group Data Count */
    proto_tree_add_item(get_wt_tree, hf_sasp_wt_req_gd_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for (i=0; i<gd_cnt; i++)
        offset = dissect_grpdatacomp(tvb, get_wt_tree, offset);
}


static void dissect_wt_rep(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *wt_rep_tree;
    uint32_t    gwed_cnt, i;

    wt_rep_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_wt_rep, NULL, "Get Weights Reply");

    /* Size */
    proto_tree_add_item(wt_rep_tree, hf_sasp_wt_rep_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Response Code */
    proto_tree_add_item(wt_rep_tree, hf_sasp_wt_rep_rcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Interval */
    proto_tree_add_item(wt_rep_tree, hf_sasp_wt_rep_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Count of Group of Wt Entry Data */
    proto_tree_add_item_ret_uint(wt_rep_tree, hf_sasp_wt_rep_gwed_cnt, tvb, offset, 2, ENC_BIG_ENDIAN, &gwed_cnt);
    offset += 2;

    for (i=0; i<gwed_cnt; i++)
        offset = dissect_grp_wt_entry_datacomp(tvb, pinfo, wt_rep_tree, offset);
}


static void dissect_setlbstate_req(tvbuff_t *tvb, proto_tree *pay_load, uint32_t offset)
{
    uint8_t LB_uid_len;

    static int * const lbflags[] = {
        &hf_sasp_pushflag,
        &hf_sasp_trustflag,
        &hf_sasp_nochangeflag,
        NULL
    };

    proto_tree *setlbstate_req_tree;

    setlbstate_req_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_setlbstate_req, NULL, "Set LB State Req");

    /* Size*/
    proto_tree_add_item(setlbstate_req_tree, hf_sasp_setlbstate_req_sz,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    LB_uid_len = tvb_get_uint8(tvb, offset);

    /* LB UID Len */
    proto_tree_add_item(setlbstate_req_tree, hf_sasp_setlbstate_req_LB_uid_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*LB UID*/
    proto_tree_add_item(setlbstate_req_tree, hf_sasp_setlbstate_req_LB_uid,
        tvb, offset, LB_uid_len, ENC_ASCII);
    offset += (uint8_t)LB_uid_len;

    /*LB Health*/
    proto_tree_add_item(setlbstate_req_tree, hf_sasp_setlbstate_req_LB_health,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_bitmask_text(setlbstate_req_tree, tvb, offset, 1, "LB Flags:", NULL,
        ett_setlbstate_req_lbflag, lbflags, ENC_BIG_ENDIAN, 0);
}


static void dissect_setlbstate_rep(tvbuff_t *tvb, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *setlbstate_rep_tree;

    setlbstate_rep_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_setlbstate_rep, NULL, "Set LB State Rep");

    /* Size */
    proto_tree_add_item(setlbstate_rep_tree, hf_sasp_setlbstate_rep_sz,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Response Code */
    proto_tree_add_item(setlbstate_rep_tree, hf_sasp_setlbstate_rep_rcode,
        tvb, offset, 1, ENC_BIG_ENDIAN);
}


static uint32_t dissect_grp_memstatedatacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *grp_memstatedatacomp_tree;
    uint16_t    mem_cnt;
    uint16_t    i;

    grp_memstatedatacomp_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1,
                        ett_sasp_grp_memstatedatacomp, NULL, "Group Mem State Comp");

    /* Type */
    proto_tree_add_item(grp_memstatedatacomp_tree, hf_sasp_grp_memstatedatacomp,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Size */
    proto_tree_add_item(grp_memstatedatacomp_tree, hf_sasp_grp_memstatedatacomp_sz,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    mem_cnt = tvb_get_ntohs(tvb, offset);

    /* Count */
    proto_tree_add_item(grp_memstatedatacomp_tree, hf_sasp_grp_memstatedatacomp_cnt,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Group Data TLV */
    offset = dissect_grpdatacomp(tvb, grp_memstatedatacomp_tree, offset);

    /* Array of Mem State Data */
    for (i=0; i<mem_cnt; i++)
        offset = dissect_memstatedatacomp(tvb, pinfo, grp_memstatedatacomp_tree, offset);

    return offset;
}


static uint32_t dissect_memstatedatacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *memstatedatacomp_tree;
    proto_tree *memdatacomp_tree;

    offset = dissect_memdatacomp(tvb, pinfo, pay_load, offset, &memdatacomp_tree);

    memstatedatacomp_tree = proto_tree_add_subtree(memdatacomp_tree, tvb, offset, -1, ett_sasp_memstatedatacomp, NULL, "Member State Data");

    /* Type */
    proto_tree_add_item(memstatedatacomp_tree, hf_sasp_memstatedatacomp_instance,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Size */
    proto_tree_add_item(memstatedatacomp_tree, hf_sasp_memstatedatacomp_sz,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* State */
    proto_tree_add_item(memstatedatacomp_tree, hf_sasp_memstatedatacomp_state,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Quiesce flag*/
    proto_tree_add_item(memstatedatacomp_tree, hf_sasp_memstatedatacomp_quiesce_flag,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}


static uint32_t dissect_weight_entry_data_comp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *weight_entry_data_comp_tree;

    static int * const wtflags[] = {
        &hf_sasp_wed_contactsuccess_flag,
        &hf_sasp_wed_quiesce_flag,
        &hf_sasp_wed_registration_flag,
        &hf_sasp_wed_confident_flag,
        NULL
    };

    offset = dissect_memdatacomp(tvb, pinfo, pay_load, offset, NULL);

    weight_entry_data_comp_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1,
                            ett_sasp_weight_entry_data_comp, NULL, "Weight Entry Data");

    /* Type */
    proto_tree_add_item(weight_entry_data_comp_tree, hf_sasp_weight_entry_data_comp_type,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Size */
    proto_tree_add_item(weight_entry_data_comp_tree, hf_sasp_weight_entry_data_comp_sz,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(weight_entry_data_comp_tree, hf_sasp_weight_entry_data_comp_state,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_bitmask_text(weight_entry_data_comp_tree, tvb, offset, 1, "Flags:", NULL,
        ett_wt_entry_data_flag, wtflags, ENC_BIG_ENDIAN, 0);
    offset += 1;

    /* Weight */
    proto_tree_add_item(weight_entry_data_comp_tree, hf_sasp_weight_entry_data_comp_weight,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}


static uint32_t dissect_grp_wt_entry_datacomp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *pay_load, uint32_t offset)
{
    proto_tree *grp_wt_entry_datacomp_tree;
    uint16_t    wt_entry_cnt;
    uint16_t    i;

    grp_wt_entry_datacomp_tree = proto_tree_add_subtree(pay_load, tvb, offset, -1, ett_sasp_grp_wt_entry_datacomp, NULL, "Group of Wt Entry Data");

    /* Type */
    proto_tree_add_item(grp_wt_entry_datacomp_tree, hf_sasp_grp_wt_entry_datacomp_type,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Size */
    proto_tree_add_item(grp_wt_entry_datacomp_tree, hf_sasp_grp_wt_entry_datacomp_sz,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    wt_entry_cnt = tvb_get_ntohs(tvb, offset);

    /* Wt Entry Count*/
    proto_tree_add_item(grp_wt_entry_datacomp_tree, hf_sasp_grp_wt_entry_datacomp_cnt,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Group Data */
    offset = dissect_grpdatacomp(tvb, grp_wt_entry_datacomp_tree, offset);

    /* Member Data */
    for (i=0; i<wt_entry_cnt; i++)
        offset = dissect_weight_entry_data_comp(tvb, pinfo, grp_wt_entry_datacomp_tree, offset);

    return offset;
}


/* sasp protocol register */
void proto_register_sasp(void)
{
    static hf_register_info hf[] = {
        /*SASP Header */
        { &hf_sasp_type,
          { "Type", "sasp.type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "SASP Header", HFILL }
        },

        { &hf_sasp_length,
          { "Length", "sasp.header.Len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Header Length", HFILL }
        },

        { &hf_sasp_vrsn,
          { "Version", "sasp.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "SASP Version", HFILL }
        },

        { &hf_msg_len,
          { "Message Len", "sasp.msg.len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SASP Msg Len", HFILL }
        },

        { &hf_msg_id,
          { "Message Id", "sasp.msg.id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SASP Msg Id", HFILL }
        },

        /*Message Type*/
        { &hf_msg_type,
          { "Message Type", "sasp.msg.type",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &msg_table_ext, 0x0,
            "SASP Msg Type", HFILL }
        },

        /*Reg Request*/
        { &hf_sasp_reg_req_sz,
          { "Reg Req-Size", "sasp.reg-req.size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SASP Reg Req Size", HFILL }
        },

        { &hf_reg_req_lbflag,
          { "Reg Req-LB Flag", "sasp.reg-req.lbflag",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "SASP Reg Req LB Flag", HFILL } },

        { &hf_sasp_gmd_cnt,
          { "Grp Mem Data-Count", "sasp.grp-mem-data.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Grp Mem Data Count", HFILL } },

        /* Reg Reply */

        { &hf_sasp_reg_rep_sz,
          { "Reg Reply-Size", "sasp.reg-rep.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Reg Reply size", HFILL } },

        { &hf_sasp_reg_rep_rcode,
          { "Reg Reply-Return Code", "sasp.reg-rep.retcode",
            FT_UINT8, BASE_HEX, VALS(reg_reply_response_code), 0x0,
            "SASP Reg Rep Return Code", HFILL } },

        /* Dereg Req */
        { &hf_sasp_dereg_req_sz,
          { "Dereg Req-Size", "sasp.dereg-req.size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SASP Dereg Req Size", HFILL } },

        { &hf_dereg_req_lbflag,
          { "Dereg Req-LB Flag", "sasp.dereg-req.lbflag",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "SASP Dereg Req LB Flag", HFILL } },

        { &hf_dereg_req_reason_flag,
          { "Reason Flags", "sasp.flags.reason",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },

#if 0
        { &hf_dereg_req_reason,
          { "Dereg Req-Reason", "sasp.dereg-req.reason",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "SASP Dereg Req Reason", HFILL } },
#endif

        /* Dereg Rep */
        { &hf_sasp_dereg_rep_sz,
          { "Dereg Rep-Size", "sasp.dereg-rep.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Dereg Rep Size", HFILL } },

        { &hf_sasp_dereg_rep_rcode,
          { "Dereg Rep-Return Code", "sasp.dereg-rep.retcode",
            FT_UINT8, BASE_HEX, VALS(dereg_reply_response_code), 0x0,
            "SASP Dereg Rep Return Code", HFILL } },

        /* Send weight */

        { &hf_sasp_sendwt_sz,
          { "Sendwt-Size", "sasp.sendwt.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Sendwt-Size", HFILL } },

        { &hf_sasp_sendwt_gwedcnt,
          { "Sendwt-Grp Wt EntryData Count", "sasp.sendwt-grp-wtentrydata.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Sendwt Grp Wt Entry Data Count", HFILL } },

        /*Set Mem State Req*/

        { &hf_sasp_setmemstate_req_sz,
          { "Set Memstate Req-Size", "sasp.setmemstate-req.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Set Memstate Req Size", HFILL } },

        { &hf_setmemstate_req_lbflag,
          { "Set Memstate Req-LB Flag", "sasp.setmemstate-req.lbflag",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "SASP Set Memstate Req LB Flag", HFILL } },

        { &hf_sasp_setmemstate_req_gmsd_cnt,
          { "Set Memstate Req-Gmsd Count", "sasp.group-memstate.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Group Of Member State Data Count", HFILL } },

        /* Set Mem State Reply */
#if 0
        { &hf_sasp_setmemstate_rep,
          { "Set Memstate Reply", "sasp.setmemstate-rep",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "SASP Set Memstate Reply", HFILL } },
#endif

        { &hf_sasp_setmemstate_rep_sz,
          { "Set Memstate Rep-Size", "sasp.setmemstate-rep.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Set Memstate Rep Size", HFILL } },

        { &hf_sasp_setmemstate_rep_rcode,
          { "Set Memstate Rep-Return Code", "sasp.setmemstate-rep.retcode",
            FT_UINT8, BASE_HEX, VALS(set_mem_state_reply_response_code), 0x0,
            "SASP Set Memstate Rep Return Code", HFILL } },

        /*Mem Data Component*/

        { &hf_sasp_memdatacomp_type,
          { "Message Type", "sasp.msg.type",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &msg_table_ext, 0x0,
            "SASP Mem Data Comp", HFILL } },

        { &hf_sasp_memdatacomp_sz,
          { "Mem Data Comp-Size", "sasp.memdatacomp.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Mem Data Comp Size", HFILL } },

        { &hf_sasp_memdatacomp_protocol,
          { "Mem Data Comp-Protocol", "sasp.memdatacomp.protocol",
            FT_UINT8, BASE_HEX, VALS(protocol_table), 0x0,
            "SASP Mem Data Comp Protocol", HFILL } },

        { &hf_sasp_memdatacomp_port,
          { "Mem Data Comp-Port", "sasp.memdatacomp.port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Mem Data Comp Port", HFILL } },

        { &hf_sasp_memdatacomp_ip,
          { "Mem Data Comp-Ip", "sasp.memdatacomp.ip",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "SASP Mem Data Comp Ip", HFILL } },

        { &hf_sasp_memdatacomp_lab_len,
          { "Mem Data Comp-Label Len", "sasp.memdatacomp.label.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "SASP Mem Data Comp Label Length", HFILL } },

        { &hf_sasp_memdatacomp_label,
          { "Mem Data Comp-Label", "sasp.memdatacomp.label",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "SASP Mem Data Comp Label", HFILL } },

        /*Get Weight Request*/

        { &hf_sasp_wt_req_sz,
          { "Get Wt Req-Size", "sasp.getwt.req.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Get Wt Req Size", HFILL } },

        { &hf_sasp_wt_req_gd_cnt,
          { "Get Wt Req-Grp Data Count", "sasp.getwt-req-grpdata.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Get Wt Grp Data Count", HFILL } },

        /*Get Weight Reply*/

        { &hf_sasp_wt_rep_sz,
          { "Get Wt Rep-Size", "sasp.getwt.rep.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Get Wt Rep Size", HFILL } },

        { &hf_sasp_wt_rep_rcode,
          { "Get Wt Rep-Return Code", "sasp.getwt-rep.retcode",
            FT_UINT8, BASE_HEX, VALS(get_weights_reply_response_code), 0x0,
            "SASP Get Wt Rep Return Code", HFILL } },

        { &hf_sasp_wt_rep_interval,
          { "Get Wt Rep-Interval", "sasp.getwt-rep.interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Get Wt Rep Interval", HFILL } },

        { &hf_sasp_wt_rep_gwed_cnt,
          { "Get Wt Rep-Grp WtEntry Data Cnt", "sasp.getwt-rep-grpwtentrydata.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Get Wt Rep Grp Wt Entry Data Cnt", HFILL } },

        /*Set LB State Rep */

#if 0
        { &hf_sasp_setlbstate_rep,
          { "Set Lbstate Rep", "sasp.msg.type",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "SASP Set Lbstate Rep", HFILL } },
#endif

        { &hf_sasp_setlbstate_rep_sz,
          { "Set Lbstate Rep-Size", "sasp.setlbstate-rep.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Set Lbstate Rep Size", HFILL } },

        { &hf_sasp_setlbstate_rep_rcode,
          { "Set Lbstate Rep-Return Code", "sasp.setlbstate-rep.retcode",
            FT_UINT8, BASE_HEX, VALS(set_lb_state_reply_response_code), 0x0,
            "SASP Set Lbstate Rep Return Code", HFILL } },


        /*grp data comp */

        { &hf_sasp_grpdatacomp,
          { "Message Type", "sasp.msg.type",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &msg_table_ext, 0x0,
            "SASP Grp Data Comp", HFILL } },

        { &hf_sasp_grpdatacomp_sz,
          { "Grp Data Comp-Size", "sasp.grpdatacomp.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Grp Data Comp size", HFILL } },

        { &hf_sasp_grpdatacomp_LB_uid_len,
          { "Grp Data Comp-Label UID Len", "sasp.grpdatacomp.label.uid.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "SASP Grp Data Comp Label Uid Len", HFILL } },

        { &hf_sasp_grpdatacomp_LB_uid,
          { "Grp Data Comp-Label UID", "sasp.grpdatacomp.label.uid",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "SASP Grp Data Comp Label Uid", HFILL } },

        { &hf_sasp_grpdatacomp_grp_name_len,
          { "Grp Data Comp-Grp Name Len", "sasp.grpdatacomp.grpname.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "SASP Grp Data Comp Grp Name Len", HFILL } },

        { &hf_sasp_grpdatacomp_grp_name,
          { "Grp Data Comp-Grp Name", "sasp.grpdatacomp.grpname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "SASP Grp Data Comp Grp Name", HFILL } },

        /*grp mem data comp */

        { &hf_sasp_grp_memdatacomp,
          { "Message Type", "sasp.msg.type",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &msg_table_ext, 0x0,
            "SASP Grp Mem Data Comp", HFILL } },


        { &hf_sasp_grp_memdatacomp_sz,
          { "Grp Mem Data Comp-Size", "sasp.grp-memdatacomp.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Grp Mem Data Comp Size", HFILL } },

        { &hf_sasp_grp_memdatacomp_cnt,
          { "Grp Mem Data Comp-Count", "sasp.grp.memdatacomp.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Grp Mem Data Comp Cnt", HFILL } },


        /*set LB state req*/

        { &hf_sasp_setlbstate_req_sz,
          { "Set LB State Req-Size", "sasp.setlbstate-req.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Set LB State Req  Size", HFILL } },

        { &hf_sasp_setlbstate_req_LB_uid_len,
          { "Set LB State Req-LB UID Len", "sasp.setlbstate-req.lbuid.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "SASP Set LB State Req  LB Uid Len", HFILL } },

        { &hf_sasp_setlbstate_req_LB_uid,
          { "Set LB State Req-LB UID", "sasp.setlbstate-req.lbuid",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "SASP Set LB State Req LB UID", HFILL } },

        { &hf_sasp_setlbstate_req_LB_health,
          { "Set LB State Req-LB Health", "sasp.setlbstate-req.lbhealth",
            FT_UINT8, BASE_HEX, VALS(lbstate_healthtable), 0x0,
            "SASP Set LB State Req LB Health", HFILL } },

#if 0
        { &hf_lbstate_flag,
          { "Flags", "sasp.flags.lbstate",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
#endif

        { &hf_sasp_pushflag,
          { "PUSH", "sasp.flags.push",
            FT_BOOLEAN, 8, NULL, SASP_PUSH_FLAG,
            "SASP Push Flag", HFILL } },

        { &hf_sasp_trustflag,
          { "TRUST", "sasp.flags.trust",
            FT_BOOLEAN, 8, NULL, SASP_TRUST_FLAG,
            "SASP Trust Flag", HFILL } },

        { &hf_sasp_nochangeflag,
          { "NOCHANGE", "sasp.flags.nochange",
            FT_BOOLEAN, 8, NULL, SASP_NOCHANGE_FLAG,
            "SASP Nochange Flag", HFILL } },

        /*grp mem state data comp */

        { &hf_sasp_grp_memstatedatacomp,
          { "Message Type", "sasp.msg.type",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &msg_table_ext, 0x0,
            "SASP Message Type", HFILL } },


        { &hf_sasp_grp_memstatedatacomp_sz,
          { "Grp Mem State-Size", "sasp.grp.memstate.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Grp Mem State Data Comp Size", HFILL } },

        { &hf_sasp_grp_memstatedatacomp_cnt,
          { "Grp Mem State-Count", "sasp.grp.memstate.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Grp Mem State Data Comp Count", HFILL } },

        /*mem state instance */

        { &hf_sasp_memstatedatacomp_instance,
          { "Message Type", "sasp.msg.type",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &msg_table_ext, 0x0,
            "SASP Message Type", HFILL } },


        { &hf_sasp_memstatedatacomp_sz,
          { "Mem State-Size", "sasp.memstate.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Mem State Data Comp Size", HFILL } },

        { &hf_sasp_memstatedatacomp_state,
          { "Mem State-State", "sasp.memstate.state",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "SASP Mem State Data Comp State", HFILL } },

        { &hf_sasp_memstatedatacomp_quiesce_flag,
          { "Mem State-Quiesce Flag", "sasp.flags.quiesce",
            FT_BOOLEAN, 8, NULL, SASP_QUIESCE_FLAG,
            "SASP Quiesce Flag", HFILL } },

        /*weight entry data comp*/

        { &hf_sasp_weight_entry_data_comp_type,
          { "Wt Entry Data Comp", "sasp.wtentry.datacomp",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &msg_table_ext, 0x0,
            "SASP Wt Entry Data Comp", HFILL } },

        { &hf_sasp_weight_entry_data_comp_sz,
          { "Wt Entry Data Comp-Size", "sasp.wtentry.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Wt Entry Data Comp Size", HFILL } },

        { &hf_sasp_weight_entry_data_comp_state,
          { "Wt Entry Data Comp-state", "sasp.wtentry.state",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "SASP Wt Entry Data Comp State", HFILL } },

#if 0
        { &hf_wtstate_flag,
          { "Flags", "sasp.flags.wtstate",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
#endif

        { &hf_sasp_wed_contactsuccess_flag,
          { "Contact Success", "sasp.flags.contactsuccess",
            FT_BOOLEAN, 8, NULL, SASP_WED_CONTACT_SUCCESS_FLAG,
            "SASP Contact Success Flag", HFILL } },

        { &hf_sasp_wed_quiesce_flag,
          { "Quiesce", "sasp.flags.quiesce",
            FT_BOOLEAN, 8, NULL, SASP_WED_QUIESCE_FLAG,
            "SASP Quiesce Flag", HFILL } },

        { &hf_sasp_wed_registration_flag,
          { "Registration", "sasp.flags.registration",
            FT_BOOLEAN, 8, NULL, SASP_WED_REG_FLAG,
            "SASP Registration Flag", HFILL } },

        { &hf_sasp_wed_confident_flag,
          { "Confident", "sasp.flags.confident",
            FT_BOOLEAN, 8, NULL, SASP_WED_CONF_FLAG,
            "SASP Confident Flag", HFILL } },

        { &hf_sasp_weight_entry_data_comp_weight,
          { "Wt Entry Data Comp-weight", "sasp.wtentrydatacomp.weight",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Wt Entry Data Comp weight", HFILL } },


        /*grp wt entry data comp */

        { &hf_sasp_grp_wt_entry_datacomp_type,
          { "Grp Wt Entry Data Comp", "sasp.msg.type",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &msg_table_ext, 0x0,
            "SASP Grp Wt Entry Data Comp", HFILL } },

        { &hf_sasp_grp_wt_entry_datacomp_sz,
          { "Grp Wt Entry Data Comp Size", "sasp.grp-wtentrydata.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Grp Wt Entry Data Comp Size", HFILL } },

        { &hf_sasp_grp_wt_entry_datacomp_cnt,
          { "Grp Wt Entry Data Comp Cnt", "sasp.grp-wtentrydata.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SASP Grp Wt Entry Data Comp Cnt", HFILL } }
    };

    /* Setup protocol subtree array */

    static int *ett[] = {
        &ett_sasp_data,
        &ett_sasp_header,
        &ett_sasp_msg,
        &ett_sasp_payload,
        &ett_sasp_reg_req,
        &ett_sasp_reg_rep,
        &ett_sasp_reg_req_sz,
        &ett_sasp_dereg_req_sz,
        &ett_sasp_dereg_rep,
        &ett_sasp_sendwt,
        &ett_sasp_setmemstate_req,
        &ett_sasp_setmemstate_rep,
        &ett_sasp_memdatacomp,
        &ett_sasp_grpdatacomp,
        &ett_sasp_grp_memdatacomp,
        &ett_sasp_setlbstate_req,
        &ett_sasp_setlbstate_rep,
        &ett_sasp_getwt,
        &ett_setlbstate_req_lbflag,
        &ett_sasp_grp_memstatedatacomp,
        &ett_sasp_memstatedatacomp,
/*      &ett_dereg_req_reason_flag, */
        &ett_sasp_grp_wt_entry_datacomp,
        &ett_sasp_weight_entry_data_comp,
        &ett_wt_entry_data_flag,
        &ett_sasp_wt_rep
    };

    static ei_register_info ei[] = {
        { &ei_msg_type_invalid, { "sasp.msg.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid Type", EXPFILL }}
    };

    module_t *sasp_module;
    expert_module_t* expert_sasp;

    proto_sasp = proto_register_protocol("Server/Application State Protocol", "SASP", "sasp");
    sasp_handle = register_dissector("sasp", dissect_sasp, proto_sasp);

    proto_register_field_array(proto_sasp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_sasp = expert_register_protocol(proto_sasp);
    expert_register_field_array(expert_sasp, ei, array_length(ei));

    sasp_module = prefs_register_protocol(proto_sasp, NULL);
    prefs_register_bool_preference(sasp_module, "desegment_sasp_messages",
        "Reassemble SASP messages spanning multiple TCP segments",
        "Whether the SASP dissector should reassemble messages"
        " spanning multiple TCP segments."
        " To use this option, you must also enable"
        " \"Allow subdissectors to reassemble TCP streams\""
        " in the TCP protocol settings.",
        &sasp_desegment);
}


/* Handing off to TCP */
void
proto_reg_handoff_sasp(void)
{
    dissector_add_uint_with_preference("tcp.port", SASP_GLOBAL_PORT, sasp_handle);
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
