/* packet-log3gpp.c
 * Routines for dissecting phone logs containing 3GPP protocol messages.
 * Copyright 2008, Vincent Helfre
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include <wsutil/strtoi.h>

#include "packet-mac-lte.h"
#include "packet-pdcp-lte.h"
#include "packet-rlc-lte.h"

#define FD1 0
#define REL8 1

void proto_register_log3gpp(void);
void proto_reg_handoff_log3gpp(void);

/* Protocol and registered fields. */
static int proto_log3gpp = -1;


static int hf_log3gpp_timestamp = -1;
static int hf_log3gpp_protocol = -1;
static int hf_log3gpp_direction = -1;
static int hf_log3gpp_dissector_option = -1;
static int hf_log3gpp_unparsed_data = -1;
static int hf_log3gpp_dissected_length = -1;

/* Protocol subtree. */
static int ett_log3gpp = -1;

/* Variables used to select a version for RRC and NAS */
static int lte_rrc_prot_version = REL8;
static int nas_eps_prot_version = REL8;

static const enum_val_t lte_rrc_dissector_version[] = {
  {"FD1", "FD1", FD1},
  {"Rel8 dec 2008", "Rel8 dec 2008", REL8}, /* Add new dissector version after */
  {NULL, NULL, -1}
};

static const enum_val_t nas_eps_dissector_version[] = {
  {"FD1", "FD1", FD1},
  {"Rel8 dec 2008", "Rel8 dec 2008", REL8}, /* Add new dissector version after */
  {NULL, NULL, -1}
};

typedef enum packet_direction_t
{
    UPLINK,
    DOWNLINK
} packet_direction_t;

static const value_string direction_vals[] = {
    { 0,   "Uplink" },
    { 1,   "Downlink" },
    { 0,   NULL },
};
/* Pseudo header functions*/
typedef gboolean (*pseudo_hdr_func_ptr_t) (char *, packet_info *pinfo, guint16, packet_direction_t);

static gboolean lte_mac_pseudo_hdr(char *, packet_info *pinfo, guint16, packet_direction_t);
static gboolean lte_rlc_pseudo_hdr(char *, packet_info *pinfo, guint16, packet_direction_t);
static gboolean lte_pdcp_pseudo_hdr(char *, packet_info *pinfo, guint16, packet_direction_t);

typedef struct
{
  const char * protocol_name;
  const char * ul_dissector_name;
  const char * dl_dissector_name;
  dissector_handle_t ul_dissector_handle;
  dissector_handle_t dl_dissector_handle;
  pseudo_hdr_func_ptr_t hdr_process;
} lookup_dissector_element_t;

/* Look up table for protocol name /dissector: should be in alphabetic order!!!
   the purpose is to match a protocol name with a dissector,
   and to store the dissector handle the first time to avoid looking it up every time.
   This table should contain all 3GPP specified protocols */
lookup_dissector_element_t dissector_lookup_table[] = {
  {"DATA","data","data",0,0,NULL},
  {"GAN.TCP","umatcp","umatcp",0,0,NULL},
  {"GAN.UDP","umaudp","umaudp",0,0,NULL},
  {"GSM.CCCH","gsm_a_ccch","gsm_a_ccch",0,0,NULL},
  {"GSM.SACCH","gsm_a_sacch","gsm_a_sacch",0,0,NULL},
  {"GTP","gtp","gtp",0,0,NULL},
  {"LLC","llcgprs","llcgprs",0,0,NULL},
  {"LTE-MAC","mac-lte","mac-lte",0,0, lte_mac_pseudo_hdr},
  {"LTE-PDCP","pdcp-lte","pdcp-lte",0,0, lte_pdcp_pseudo_hdr},
  {"LTE-RLC","rlc-lte","rlc-lte",0,0, lte_rlc_pseudo_hdr},
  {"LTE-RRC.BCCH.BCH",0,0,0,0,NULL}, /* Dissector set according to preferences (depending on the release) */
  {"LTE-RRC.BCCH.DL.SCH",0,0,0,0,NULL}, /* Dissector set according to preferences (depending on the release) */
  {"LTE-RRC.CCCH",0,0,0,0,NULL}, /* Dissector set according to preferences (depending on the release) */
  {"LTE-RRC.DCCH",0,0,0,0,NULL}, /* Dissector set according to preferences (depending on the release) */
  {"LTE-RRC.PCCH",0,0,0,0,NULL}, /* Dissector set according to preferences (depending on the release) */
  {"NAS","gsm_a_dtap","gsm_a_dtap",0,0,NULL},
  {"NAS-EPS",0,0,0,0,NULL}, /* Dissector set according to preferences (depending on the release) */
  {"RR","gsm_a_dtap","gsm_a_dtap",0,0,NULL},
  {"RRC.BCCH.BCH","rrc.bcch.bch","rrc.bcch.bch",0,0,NULL},
  {"RRC.BCCH.FACH","rrc.bcch.fach","rrc.bcch.fach",0,0,NULL},
  {"RRC.CCCH","rrc.ul.ccch","rrc.dl.ccch",0,0,NULL},
  {"RRC.DCCH","rrc.ul.dcch","rrc.dl.dcch",0,0,NULL},
  {"RRC.MCCH","rrc.mcch","rrc.mcch",0,0,NULL},
  {"RRC.MSCH","rrc.msch","rrc.msch",0,0,NULL},
  {"RRC.PCCH","rrc.pcch","rrc.pcch",0,0,NULL},
  {"RRC.SHCCH","rrc.ul.shcch","rrc.dl.shcch",0,0,NULL},
  {"RRC.SI.MIB","rrc.si.mib","rrc.si.mib",0,0,NULL},
  {"RRC.SI.SB1","rrc.sb1","rrc.sb1",0,0,NULL},
  {"RRC.SI.SB2","rrc.sb2","rrc.sb2",0,0,NULL},
  {"RRC.SI.SIB1","rrc.si.sib1","rrc.si.sib1",0,0,NULL},
  {"RRC.SI.SIB10","rrc.si.sib10","rrc.si.sib10",0,0,NULL},
  {"RRC.SI.SIB11","rrc.si.sib11","rrc.si.sib11",0,0,NULL},
  {"RRC.SI.SIB11bis","rrc.si.sib11bis","rrc.si.sib11bis",0,0,NULL},
  {"RRC.SI.SIB12","rrc.si.sib12","rrc.si.sib12",0,0,NULL},
  {"RRC.SI.SIB13","rrc.si.sib13","rrc.si.sib13",0,0,NULL },
  {"RRC.SI.SIB13-1","rrc.si.sib13-1","rrc.si.sib13-1",0,0,NULL},
  {"RRC.SI.SIB13-2","rrc.si.sib13-2","rrc.si.sib13-2",0,0,NULL},
  {"RRC.SI.SIB13-3","rrc.si.sib13-3","rrc.si.sib13-3",0,0,NULL },
  {"RRC.SI.SIB13-4","rrc.si.sib13-4","rrc.si.sib13-4",0,0,NULL},
  {"RRC.SI.SIB14","rrc.si.sib14","rrc.si.sib14",0,0,NULL},
  {"RRC.SI.SIB15","rrc.si.sib15","rrc.si.sib15",0,0,NULL},
  {"RRC.SI.SIB15bis","rrc.si.sib15bis","rrc.si.sib15bis",0,0,NULL},
  {"RRC.SI.SIB15-1","rrc.si.sib15-1","rrc.si.sib15-1",0,0,NULL},
  {"RRC.SI.SIB15-1bis","rrc.si.sib15-1bis","rrc.si.sib15-1bis",0,0,NULL },
  {"RRC.SI.SIB15-2","rrc.si.sib15-2","rrc.si.sib15-2",0,0,NULL},
  {"RRC.SI.SIB15-2bis","rrc.si.sib15-2bis","rrc.si.sib15-2bis",0,0,NULL},
  {"RRC.SI.SIB15-3","rrc.si.sib15-3","rrc.si.sib15-3",0,0,NULL},
  {"RRC.SI.SIB15-3bis","rrc.si.sib15-3bis","rrc.si.sib15-3bis",0,0,NULL},
  {"RRC.SI.SIB15-4","rrc.si.sib15-4","rrc.si.sib15-4",0,0,NULL},
  {"RRC.SI.SIB15-5","rrc.si.sib15-5","rrc.si.sib15-5",0,0,NULL},
  {"RRC.SI.SIB15-6","rrc.si.sib15-6","rrc.si.sib15-6",0,0,NULL},
  {"RRC.SI.SIB15-7","rrc.si.sib15-7","rrc.si.sib15-7",0,0,NULL},
  {"RRC.SI.SIB15-8","rrc.si.sib15-8","rrc.si.sib15-8",0,0,NULL},
  {"RRC.SI.SIB18","rrc.si.sib18","rrc.si.sib18",0,0,NULL},
  {"RRC.SI.SIB17","rrc.si.sib17","rrc.si.sib17",0,0,NULL},
  {"RRC.SI.SIB18","rrc.si.sib18","rrc.si.sib18",0,0,NULL},
  {"RRC.SI.SIB2","rrc.si.sib2","rrc.si.sib2",0,0,NULL},
  {"RRC.SI.SIB3","rrc.si.sib3","rrc.si.sib3",0,0,NULL},
  {"RRC.SI.SIB4","rrc.si.sib4","rrc.si.sib4",0,0,NULL},
  {"RRC.SI.SIB5","rrc.si.sib5","rrc.si.sib5",0,0,NULL},
  {"RRC.SI.SIB5bis","rrc.si.sib5bis","rrc.si.sib5bis",0,0,NULL},
  {"RRC.SI.SIB6","rrc.si.sib6","rrc.si.sib6",0,0,NULL},
  {"RRC.SI.SIB7","rrc.si.sib7","rrc.si.sib7",0,0,NULL},
  {"RRC.SI.SIB8","rrc.si.sib8","rrc.si.sib8",0,0,NULL},
  {"RRC.SI.SIB9","rrc.si.sib9","rrc.si.sib9",0,0,NULL},
  {"SNDCP","sndcp","sndcp",0,0,NULL},
  {"SNDCPXID","sndcpxid","sndcpxid",0,0,NULL}
};


static int
dissector_element_compare(const void *protocol_name, const void *element)
{
  return strcmp((const char *)protocol_name, ((const lookup_dissector_element_t *) element)->protocol_name);
}

static dissector_handle_t
look_for_dissector(char* protocol_name, packet_direction_t direction, pseudo_hdr_func_ptr_t* func_ptr _U_)
{
    lookup_dissector_element_t* element_ptr;
    dissector_handle_t dissector_handle = NULL;

    element_ptr = (lookup_dissector_element_t*)bsearch((void*)protocol_name,
        (void*)dissector_lookup_table,
        sizeof(dissector_lookup_table) / sizeof(lookup_dissector_element_t),
        sizeof(lookup_dissector_element_t),
        dissector_element_compare);
    if (element_ptr != NULL) {
        if (direction == UPLINK)
        {
            if (element_ptr->ul_dissector_handle == 0)
            {
                element_ptr->ul_dissector_handle = find_dissector(element_ptr->ul_dissector_name);
            }
            dissector_handle = element_ptr->ul_dissector_handle;
        }
        else
        {
            if (element_ptr->dl_dissector_handle == 0)
            {
                element_ptr->dl_dissector_handle = find_dissector(element_ptr->dl_dissector_name);
            }
            dissector_handle = element_ptr->dl_dissector_handle;
        }

    }

    return dissector_handle;
}

static void
update_dissector_name(const char* protocol_name, packet_direction_t direction, const char* dissector_name)
{
    lookup_dissector_element_t* element_ptr;

    element_ptr = (lookup_dissector_element_t*)bsearch((void*)protocol_name,
        (void*)dissector_lookup_table,
        sizeof(dissector_lookup_table) / sizeof(lookup_dissector_element_t),
        sizeof(lookup_dissector_element_t),
        dissector_element_compare);
    if (element_ptr != NULL) {
        if (direction == UPLINK)
        {
            element_ptr->ul_dissector_handle = 0;
            element_ptr->ul_dissector_name = dissector_name;
        }
        else
        {
            element_ptr->dl_dissector_handle = 0;
            element_ptr->dl_dissector_name = dissector_name;
        }

    }
}

/******************************************************************************/
/* pseudo header functions: used for the dissectors that needs pseudo headers */
/******************************************************************************/


/* In the optional string, MAC info should be set as follow (M = mandatory, O = optional):
 * Radio type (M):  "FDD" or "TDD"
 * RNTI type (M): "NO_RNTI" or "P_RNTI" or "RA_RNTI" or "C_RNTI" or "SI_RNT" followed by rnti value in decimal format
 * subframe number (M): "SFN" followed by the subframe number in decimal format
 */
static gboolean
lte_mac_pseudo_hdr(char* option_str, packet_info* pinfo, guint16 length, packet_direction_t direction)
{
    struct mac_lte_info* p_mac_lte_info;
    char* par_opt_field;
    char option[30];
    static int proto_mac_lte = 0;

    /* look up for protocol handle */
    if (proto_mac_lte == 0)
    {
        proto_mac_lte = proto_get_id_by_filter_name("mac-lte");
    }

    /* Need to copy the string in a local buffer since strtok will modify it */
    g_strlcpy(option, option_str, 30);

    /* Only need to set info once per session. */
    p_mac_lte_info = (struct mac_lte_info*)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0);
    if (p_mac_lte_info != NULL)
    {
        return 1;
    }

    /* Allocate & zero struct */
    p_mac_lte_info = (struct mac_lte_info*) wmem_new0(wmem_packet_scope(), mac_lte_info);

    /* First mandatory parameter */
    par_opt_field = strtok(option, " ");
    if (par_opt_field == NULL)
    {
        return 0;
    }
    if (strcmp(par_opt_field, "FDD") == 0)
    {
        p_mac_lte_info->radioType = FDD_RADIO;
    }
    else if (strcmp(par_opt_field, "TDD") == 0)
    {
        p_mac_lte_info->radioType = TDD_RADIO;
    }
    else
    {
        return 0;
    }

    /* Second mandatory parameter */
    par_opt_field = strtok(NULL, " ");
    if (par_opt_field == NULL)
    {
        return 0;
    }
    if (strcmp(par_opt_field, "NO_RNTI") == 0)
    {
        p_mac_lte_info->rntiType = NO_RNTI;
    }
    else if (strcmp(par_opt_field, "P_RNTI") == 0)
    {
        p_mac_lte_info->rntiType = P_RNTI;
    }
    else if (strcmp(par_opt_field, "RA_RNTI") == 0)
    {
        p_mac_lte_info->rntiType = RA_RNTI;
    }
    else if (strcmp(par_opt_field, "C_RNTI") == 0)
    {
        p_mac_lte_info->rntiType = C_RNTI;
    }
    else if (strcmp(par_opt_field, "SI_RNTI") == 0)
    {
        p_mac_lte_info->rntiType = SI_RNTI;
    }
    else
    {
        return 0;
    }
    /* Get the associated rnti value */
    par_opt_field = strtok(NULL, " ");
    if (par_opt_field)
    {
        ws_strtoi16(par_opt_field, NULL, &p_mac_lte_info->rnti);
    }
    else
    {
        return 0;
    }

    /* First optional parameter */
    p_mac_lte_info->subframeNumber = 0;
    par_opt_field = strtok(NULL, " ");
    if (par_opt_field == NULL)
    {
        return 0;
    }
    if (strcmp(par_opt_field, "SFN") == 0)
    {
        par_opt_field = strtok(NULL, " ");
        if (par_opt_field != NULL)
        {
            ws_strtoi16(par_opt_field, NULL, &p_mac_lte_info->subframeNumber);
        }
    }
    p_mac_lte_info->direction = (direction == UPLINK) ? DIRECTION_UPLINK : DIRECTION_DOWNLINK;
    p_mac_lte_info->length = length;

    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0, p_mac_lte_info);

    return 1;
}

/* In the optional string, RLC info should be set as follow (M = mandatory, O = optional):
 * Channel type (M): "SRB" or "DRB" followed by the RB ID
 * RLC mode (M): "TM" or  "UM" or "AM" or "NA"
 * UM Sequence nb length (O): "SN_5b" or "SN_10b"
 */

static gboolean
lte_rlc_pseudo_hdr(char* option_str, packet_info* pinfo, guint16 length, packet_direction_t direction)
{
    struct rlc_lte_info* p_rlc_lte_info;
    char* par_opt_field;
    char option[30];
    static int proto_rlc_lte = 0;

    /* look up for protocol handle */
    if (proto_rlc_lte == 0)
    {
        proto_rlc_lte = proto_get_id_by_filter_name("rlc-lte");
    }
    g_strlcpy(option, option_str, 30);

    /* Only need to set info once per session. */
    p_rlc_lte_info = (struct rlc_lte_info*)p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0);
    if (p_rlc_lte_info != NULL)
    {
        return 1;
    }

    /* Allocate & zero struct */
    p_rlc_lte_info = (struct rlc_lte_info*) wmem_new0(wmem_packet_scope(), rlc_lte_info);
    /* First mandatory parameter */
    par_opt_field = strtok(option, " ");
    if (par_opt_field == NULL)
    {
        return 0;
    }
    if (strcmp(par_opt_field, "SRB") == 0)
    {
        p_rlc_lte_info->channelType = CHANNEL_TYPE_SRB;
    }
    else if (strcmp(par_opt_field, "DRB") == 0)
    {
        p_rlc_lte_info->channelType = CHANNEL_TYPE_DRB;
    }
    else
    {
        return 0;
    }
    /* Fill in the RB ID */
    par_opt_field = strtok(NULL, " ");
    if (par_opt_field == NULL)
    {
        return 0;
    }
    ws_strtou16(par_opt_field, NULL, &p_rlc_lte_info->channelId);

    /* Second mandatory parameter */
    par_opt_field = strtok(NULL, " ");
    if (par_opt_field == NULL)
    {
        return 0;
    }
    if (strcmp(par_opt_field, "TM") == 0)
    {
        p_rlc_lte_info->rlcMode = RLC_TM_MODE;
    }
    else if (strcmp(par_opt_field, "UM") == 0)
    {
        p_rlc_lte_info->rlcMode = RLC_UM_MODE;
    }
    else if (strcmp(par_opt_field, "AM") == 0)
    {
        p_rlc_lte_info->rlcMode = RLC_AM_MODE;
    }
    else if (strcmp(par_opt_field, "NA") == 0)
    {
        p_rlc_lte_info->rlcMode = RLC_PREDEF;
    }
    else
    {
        return 0;
    }

    /* First optional parameter */
    par_opt_field = strtok(NULL, " ");
    if (par_opt_field != NULL)
    {
        if (strcmp(par_opt_field, "SN_5b") == 0)
        {
            p_rlc_lte_info->sequenceNumberLength = UM_SN_LENGTH_5_BITS;
        }
        else if (strcmp(par_opt_field, "SN_10b") == 0)
        {
            p_rlc_lte_info->sequenceNumberLength = UM_SN_LENGTH_10_BITS;
        }
    }
    p_rlc_lte_info->direction = (direction == UPLINK) ? DIRECTION_UPLINK : DIRECTION_DOWNLINK;
    p_rlc_lte_info->priority = 0;
    p_rlc_lte_info->ueid = 0;
    p_rlc_lte_info->pduLength = length;

    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0, p_rlc_lte_info);

    return (1);
}

/* In the optional string, PDCP info should be set as follow (M = mandatory, O = optional):
 * Plane: "SRB" or "DRB"
 * Sequence number length: "SN_7b" or "SN_12b"
 */
static gboolean
lte_pdcp_pseudo_hdr(char* option_str, packet_info* pinfo, guint16 length _U_, packet_direction_t direction)
{
    struct pdcp_lte_info* p_pdcp_lte_info;
    char* par_opt_field;
    char option[30];
    static int proto_pdcp_lte = 0;

    /* look up for protocol handle */
    if (proto_pdcp_lte == 0)
    {
        proto_pdcp_lte = proto_get_id_by_filter_name("pdcp-lte");
    }
    g_strlcpy(option, option_str, 30);

    /* Only need to set info once per session. */
    p_pdcp_lte_info = (struct pdcp_lte_info*)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0);
    if (p_pdcp_lte_info != NULL)
    {
        return 1;
    }

    /* Allocate & zero struct */
    p_pdcp_lte_info = (struct pdcp_lte_info*) wmem_new0(wmem_packet_scope(), pdcp_lte_info);
    /* First mandatory parameter */
    par_opt_field = strtok(option, " ");
    if (par_opt_field == NULL)
    {
        return 0;
    }
    if (strcmp(par_opt_field, "SRB") == 0)
    {
        p_pdcp_lte_info->plane = SIGNALING_PLANE;
    }
    else if (strcmp(par_opt_field, "DRB") == 0)
    {
        p_pdcp_lte_info->plane = USER_PLANE;
    }
    else
    {
        return 0;
    }
    /* Second mandatory parameter */
    par_opt_field = strtok(NULL, " ");
    if (par_opt_field == NULL)
    {
        return 0;
    }
    if (strcmp(par_opt_field, "SN_7b") == 0)
    {
        p_pdcp_lte_info->seqnum_length = PDCP_SN_LENGTH_7_BITS;
    }
    else if (strcmp(par_opt_field, "SN_12b") == 0)
    {
        p_pdcp_lte_info->seqnum_length = PDCP_SN_LENGTH_12_BITS;
    }
    else
    {
        return 0;
    }
    p_pdcp_lte_info->no_header_pdu = 0;
    p_pdcp_lte_info->rohc.rohc_compression = 0;
    p_pdcp_lte_info->direction = (direction == UPLINK) ? DIRECTION_UPLINK : DIRECTION_DOWNLINK;

    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0, p_pdcp_lte_info);

    return (1);
}


/*****************************************/
/* Main dissection function.             */
/*****************************************/
static int
dissect_log3gpp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_tree* prot3gpp_tree = NULL;
    proto_item* ti = NULL;
    gint        offset = 0;
    gint        protocol_name_start;
    gint        protocol_name_length;
    gint        protocol_option_start;
    gint        protocol_option_length;
    gint        timestamp_start;
    gint        timestamp_length;
    packet_direction_t      direction;
    tvbuff_t* next_tvb;
    dissector_handle_t protocol_handle = 0;
    int sub_dissector_result = 0;
    char* protocol_name;
    char* protocol_option;
    gboolean is_hex_data;

    /* Clear Info */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create root (protocol) tree. */
    ti = proto_tree_add_item(tree, proto_log3gpp, tvb, offset, -1, FALSE);
    prot3gpp_tree = proto_item_add_subtree(ti, ett_log3gpp);

    /*********************************************************************/
    /* Note that these are the fields of the stub header as written out  */
    /* by the wiretap module                                             */

    /* Timestamp in file */
    timestamp_start = offset;
    timestamp_length = tvb_strsize(tvb, offset);
    if (prot3gpp_tree) {
        proto_tree_add_double_format_value(prot3gpp_tree, hf_log3gpp_timestamp, tvb,
            offset, timestamp_length,
            g_ascii_strtod(tvb_format_text(tvb, offset, timestamp_length), NULL),
            "%s", tvb_format_text(tvb, offset, timestamp_length - 1));
    }
    offset += timestamp_length;


    /* protocol name */
    protocol_name_start = offset;
    protocol_name_length = tvb_strsize(tvb, offset);
    if (prot3gpp_tree) {
        proto_tree_add_item(prot3gpp_tree, hf_log3gpp_protocol, tvb, offset, protocol_name_length, ENC_ASCII | ENC_NA);
    }
    offset += protocol_name_length;

    /* Direction */
    direction = (packet_direction_t)tvb_get_guint8(tvb, offset);
    if (prot3gpp_tree) {
        proto_tree_add_item(prot3gpp_tree, hf_log3gpp_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    /* protocol option */
    protocol_option_start = offset;
    protocol_option_length = tvb_strsize(tvb, offset);
    if (prot3gpp_tree) {
        proto_tree_add_item(prot3gpp_tree, hf_log3gpp_dissector_option, tvb, offset, protocol_option_length, ENC_ASCII | ENC_NA);
    }
    offset += protocol_option_length;

    if (prot3gpp_tree)
    {
        /* Set selection length of prot3gpp tree */
        proto_item_set_len(prot3gpp_tree, offset);
    }

    /* Add useful details to protocol tree label */
    protocol_name = (char*)tvb_get_string_enc(pinfo->pool, tvb, protocol_name_start, protocol_name_length, ENC_UTF_8 | ENC_NA);
    /* Set Protocol */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, protocol_name);
    /* To know whether the data following is row byte stream or text data */
    is_hex_data = strcmp(protocol_name, "TXT");

    proto_item_append_text(ti, " t=%s   %c   prot=%s",
        tvb_get_string_enc(wmem_packet_scope(), tvb, timestamp_start, timestamp_length, ENC_UTF_8 | ENC_NA),
        (direction == 0) ? 'U' : 'D',
        protocol_name);

    if (is_hex_data)
    {
        /* We might need to prepend pseudo header for the dissector */
        pseudo_hdr_func_ptr_t func_ptr = NULL;

        /* Look up for the optional information */
        protocol_option = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, protocol_option_start, protocol_option_length, ENC_UTF_8 | ENC_NA);

        /* look up for the right dissector handle */
        protocol_handle = look_for_dissector(protocol_name, direction, &func_ptr);

        /***********************************************************************/
        /* Now hand off to the dissector of intended packet encapsulation type */

        /* Try appropriate dissector, if one has been selected */
        if (protocol_handle != 0)
        {
            /* Dissect the remainder of the frame using chosen protocol handle */
            next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, tvb_reported_length(tvb) - offset);

            /* This part is optional, only for dissector that need pseudo header information */
            if (func_ptr != NULL && strlen(protocol_option) != 0)
            {
                if (func_ptr(protocol_option, pinfo, offset, direction) == 0)
                {
                    /* There was an error, return */
                    return tvb_reported_length(tvb);
                }
            }
            sub_dissector_result = call_dissector(protocol_handle, next_tvb, pinfo, tree);
        }
    }

    if (protocol_handle == 0 || sub_dissector_result == 0)
    {
        /* Could get here because:
          - desired protocol is unavailable (probably disabled), OR
          - protocol rejected our data
          Show remaining bytes as unparsed data */
        proto_tree_add_item(prot3gpp_tree, hf_log3gpp_unparsed_data, tvb, offset, -1, ENC_NA);

        if (!is_hex_data)
        {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "%s",
                tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tvb_reported_length(tvb) - offset, ENC_UTF_8 | ENC_NA));
        }
        else
        {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Not dissected  ( t=%s   %c   prot=%s)",
                tvb_get_string_enc(wmem_packet_scope(), tvb, timestamp_start, timestamp_length, ENC_UTF_8 | ENC_NA),
                (direction == 0) ? 'U' : 'D',
                tvb_get_string_enc(wmem_packet_scope(), tvb, protocol_name_start, protocol_name_length, ENC_UTF_8 | ENC_NA));
        }
    }
    else
    {
        /* Show number of dissected bytes */
        proto_item* ti_local = proto_tree_add_uint(prot3gpp_tree,
            hf_log3gpp_dissected_length,
            tvb, 0, 0, tvb_reported_length(tvb) - offset);
        PROTO_ITEM_SET_GENERATED(ti_local);
    }
    return tvb_reported_length(tvb);
}

/******************************************************************************/
/* Associate this protocol with the log3gpp file encapsulation type. */
/******************************************************************************/
void proto_reg_handoff_log3gpp(void)
{
    static gboolean init = FALSE;

    if (init == FALSE)
    {
        dissector_handle_t log3gpp_handle;

        log3gpp_handle = find_dissector("prot3gpp");
        dissector_add_uint("wtap_encap", WTAP_ENCAP_LOG_3GPP, log3gpp_handle);
        init = TRUE;
    }
    if (lte_rrc_prot_version == REL8)
    {
        update_dissector_name("LTE-RRC.BCCH.BCH", UPLINK, "lte-rrc.bcch.bch");
        update_dissector_name("LTE-RRC.BCCH.BCH", DOWNLINK, "lte-rrc.bcch.bch");
        update_dissector_name("LTE-RRC.BCCH.DL.SCH", UPLINK, "lte-rrc.bcch.dl.sch");
        update_dissector_name("LTE-RRC.BCCH.DL.SCH", DOWNLINK, "lte-rrc.bcch.dl.sch");
        update_dissector_name("LTE-RRC.CCCH", UPLINK, "lte-rrc.ul.ccch");
        update_dissector_name("LTE-RRC.CCCH", DOWNLINK, "lte-rrc.dl.ccch");
        update_dissector_name("LTE-RRC.DCCH", UPLINK, "lte-rrc.ul.dcch");
        update_dissector_name("LTE-RRC.DCCH", DOWNLINK, "lte-rrc.dl.dcch");
        update_dissector_name("LTE-RRC.PCCH", UPLINK, "lte-rrc.pcch");
        update_dissector_name("LTE-RRC.PCCH", DOWNLINK, "lte-rrc.pcch");
    }
    else if (lte_rrc_prot_version == FD1)
    {
        update_dissector_name("LTE-RRC.BCCH.BCH", UPLINK, "lte-rrc-fd1.bcch.bch");
        update_dissector_name("LTE-RRC.BCCH.BCH", DOWNLINK, "lte-rrc-fd1.bcch.bch");
        update_dissector_name("LTE-RRC.BCCH.DL.SCH", UPLINK, "lte-rrc-fd1.bcch.dl.sch");
        update_dissector_name("LTE-RRC.BCCH.DL.SCH", DOWNLINK, "lte-rrc-fd1.bcch.dl.sch");
        update_dissector_name("LTE-RRC.CCCH", UPLINK, "lte-rrc-fd1.ul.ccch");
        update_dissector_name("LTE-RRC.CCCH", DOWNLINK, "lte-rrc-fd1.dl.ccch");
        update_dissector_name("LTE-RRC.DCCH", UPLINK, "lte-rrc-fd1.ul.dcch");
        update_dissector_name("LTE-RRC.DCCH", DOWNLINK, "lte-rrc-fd1.dl.dcch");
        update_dissector_name("LTE-RRC.PCCH", UPLINK, "lte-rrc-fd1.pcch");
        update_dissector_name("LTE-RRC.PCCH", DOWNLINK, "lte-rrc-fd1.pcch");
    }
    if (nas_eps_prot_version == REL8)
    {
        update_dissector_name("NAS-EPS", UPLINK, "nas-eps");
        update_dissector_name("NAS-EPS", DOWNLINK, "nas-eps");
    }
    else if (nas_eps_prot_version == FD1)
    {
        update_dissector_name("NAS-EPS", UPLINK, "nas-eps-fd1");
        update_dissector_name("NAS-EPS", DOWNLINK, "nas-eps-fd1");
    }
}

/****************************************/
/* Register the protocol                */
/****************************************/
void proto_register_log3gpp(void)
{
  module_t *log3gpp_module;
    static hf_register_info hf[] =
    {
        { &hf_log3gpp_timestamp,
            { "Timestamp",
              "log3gpp.timestamp", FT_DOUBLE, BASE_NONE, NULL, 0x0,
              "File timestamp", HFILL
            }
        },
        { &hf_log3gpp_protocol,
            { "3GPP protocol",
              "log3gpp.protocol", FT_STRING, BASE_NONE, NULL, 0x0,
              "Original 3GPP protocol name", HFILL
            }
        },
        { &hf_log3gpp_dissector_option,
            { "option",
              "log3gpp.option", FT_STRING, BASE_NONE, NULL, 0x0,
              "Protocol option", HFILL
            }
        },
        { &hf_log3gpp_direction,
            { "Direction",
              "log3gpp.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Frame direction (Uplink or Downlink)", HFILL
            }
        },
        { &hf_log3gpp_unparsed_data,
            { "Unparsed protocol data",
              "log3gpp.unparsed_data", FT_BYTES, BASE_NONE, NULL, 0x0,
              "Unparsed 3GPP protocol data", HFILL
            }
        },
        { &hf_log3gpp_dissected_length,
            { "Dissected length",
              "log3gpp.dissected-length", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Number of bytes dissected by subdissector(s)", HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_log3gpp
    };

    /* Register protocol. */
    proto_log3gpp = proto_register_protocol("3GPP log packet",
                                            "LOG3GPP",
                                            "log3gpp");
    proto_register_field_array(proto_log3gpp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    log3gpp_module = prefs_register_protocol(proto_log3gpp, proto_reg_handoff_log3gpp);
    prefs_register_enum_preference(log3gpp_module,
                                   "rrc_release_version",
                                   "Select the release version of LTE RRC protocol",
                                   "There might be plugins corresponding to different version of the specification "
                                   "If they are present they should be listed here.",
                                   &lte_rrc_prot_version,
                                   lte_rrc_dissector_version,
                                   FALSE);

    prefs_register_enum_preference(log3gpp_module,
                                   "nas_eps_release_version",
                                   "Select the release version of NAS EPS protocol",
                                   "There might be plugins corresponding to different version of the specification "
                                   "If they are present they should be listed here.",
                                   &nas_eps_prot_version,
                                   nas_eps_dissector_version,
                                   FALSE);

    /* Allow dissector to find be found by name. */
    register_dissector("prot3gpp", dissect_log3gpp, proto_log3gpp);
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
