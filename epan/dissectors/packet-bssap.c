/* packet-bssap.c
 * Routines for Base Station Subsystem Application Part (BSSAP/BSAP) dissection
 * Specifications from 3GPP2 (www.3gpp2.org) and 3GPP (www.3gpp.org)
 *  IOS 4.0.1 (BSAP)
 *  GSM 08.06 (BSSAP)
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Added BSSAP+ according to ETSI TS 129 018 V6.3.0 (2005-3GPP TS 29.018 version 6.3.0 Release 6)
 * Copyright 2006, Anders Broman <Anders.Broman [AT] ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>

#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"

void proto_reg_handoff_bssap(void);

#define BSSAP 0
#define BSAP  1

#define GSM_INTERFACE 0
#define LB_INTERFACE  1

#define BSSAP_OR_BSAP_DEFAULT BSSAP

#define GSM_OR_LB_INTERFACE_DEFAULT GSM_INTERFACE

#define PDU_TYPE_OFFSET 0
#define PDU_TYPE_LENGTH 1

/* Same as below but with names typed out */
static const value_string bssap_pdu_type_values[] = {
    { BSSAP_PDU_TYPE_BSSMAP,    "BSS Management" },
    { BSSAP_PDU_TYPE_DTAP,  "Direct Transfer" },
    { 0,            NULL } };

static const value_string bsap_pdu_type_values[] = {
    { BSSAP_PDU_TYPE_BSSMAP,    "BS Management" },
    { BSSAP_PDU_TYPE_DTAP,  "Direct Transfer" },
    { 0,            NULL } };

/* Same as above but in acronym for (for the Info column) */
static const value_string bssap_pdu_type_acro_values[] = {
    { BSSAP_PDU_TYPE_BSSMAP,    "BSSMAP" },
    { BSSAP_PDU_TYPE_DTAP,  "DTAP" },
    { 0,            NULL } };

/* Same as above but in acronym for (for the Info column) */
static const value_string bsap_pdu_type_acro_values[] = {
    { BSSAP_PDU_TYPE_BSSMAP,    "BSMAP" },
    { BSSAP_PDU_TYPE_DTAP,  "DTAP" },
    { 0,            NULL } };

#define PARAMETER_DLCI      0x00
#define PARAMETER_LENGTH    0x01
#define PARAMETER_DATA      0x02

#define DLCI_LENGTH     1
#define LENGTH_LENGTH       1
#define DATA_LENGTH     1

#define CC_MASK         0xc0
#define SPARE_MASK      0x38
#define SAPI_MASK       0x07

static guint global_bssap_ssn = 98;

static const value_string bssap_cc_values[] = {
    { 0x00,     "not further specified" },
    { 0x80,     "FACCH or SDCCH" },
    { 0xc0,     "SACCH" },
    { 0,        NULL } };

static const value_string bsap_cc_values[] = {
    { 0x00,     "default for TIA/EIA/IS-2000" },
    { 0,        NULL } };

static const value_string bssap_sapi_values[] = {
    { 0x00,     "RR/MM/CC" },
    { 0x03,     "SMS" },
    { 0,        NULL } };

static const value_string bsap_sapi_values[] = {
    { 0x00,     "Not used" },
    { 0,        NULL } };

#define BSSAP_PAGING_REQUEST                1
#define BSSAP_PAGING_REJECT                 2                   /*  17.1.18 */
#define BSSAP_DOWNLINK_TUNNEL_REQUEST       7                   /*  17.1.4  */
#define BSSAP_UPLINK_TUNNEL_REQUEST         8                   /*  17.1.23 */
#define BSSAP_LOCATION_UPDATE_REQUEST       9                   /*  17.1.11 */
#define BSSAP_LOCATION_UPDATE_ACCEPT        10                  /*  17.1.9  */
#define BSSAP_LOCATION_UPDATE_REJECT        11                  /*  17.1.10 */
#define BSSAP_TMSI_REALLOCATION_COMPLETE    12                  /*  17.1.22 */
#define BSSAP_ALERT_REQUEST                 13                  /*  17.1.3  */
#define BSSAP_ALERT_ACK                     14                  /*  17.1.1  */
#define BSSAP_ALERT_REJECT                  15                  /*  17.1.2  */
#define BSSAP_MS_ACTIVITY_INDICATION        16                  /*  17.1.14 */
#define BSSAP_GPRS_DETACH_INDICATION        17                  /*  17.1.6  */
#define BSSAP_GPRS_DETACH_ACK               18                  /*  17.1.5  */
#define BSSAP_IMSI_DETACH_INDICATION        19                  /*  17.1.8  */
#define BSSAP_IMSI_DETACH_ACK               20                  /*  17.1.7  */
#define BSSAP_RESET_INDICATION              21                  /*  17.1.21 */
#define BSSAP_RESET_ACK                     22                  /*  17.1.20 */
#define BSSAP_MS_INFORMATION_REQUEST        23                  /*  17.1.15 */
#define BSSAP_MS_INFORMATION_RESPONSE       24                  /*  17.1.16 */
#define BSSAP_MM_INFORMATION_REQUEST        26                  /*  17.1.12 */
#define BSSAP_MOBILE_STATUS                 29                  /*  17.1.13 */
#define BSSAP_MS_UNREACHABLE                31                  /*  17.1.17 */

static const value_string bssap_plus_message_type_values[] = {
    { 0x00,                                 "Unassigned: treated as an unknown Message type." },
    { BSSAP_PAGING_REQUEST,                 "BSSAP+-PAGING-REQUEST" },                              /*  17.1.19 */
    { BSSAP_PAGING_REJECT,                  "BSSAP+-PAGING-REJECT" },                               /*  17.1.18 */
    { 0x03,                                 "Unassigned: treated as an unknown Message type." },
    { 0x04,                                 "Unassigned: treated as an unknown Message type." },
    { 0x05,                                 "Unassigned: treated as an unknown Message type." },
    { 0x06,                                 "Unassigned: treated as an unknown Message type." },
    { BSSAP_DOWNLINK_TUNNEL_REQUEST,        "BSSAP+-DOWNLINK-TUNNEL-REQUEST" },                     /*  17.1.4  */
    { BSSAP_UPLINK_TUNNEL_REQUEST,          "BSSAP+-UPLINK-TUNNEL-REQUEST" },                       /*  17.1.23 */
    { BSSAP_LOCATION_UPDATE_REQUEST,        "BSSAP+-LOCATION-UPDATE-REQUEST" },                     /*  17.1.11 */
    { BSSAP_LOCATION_UPDATE_ACCEPT,         "BSSAP+-LOCATION-UPDATE-ACCEPT" },                      /*  17.1.9  */
    { BSSAP_LOCATION_UPDATE_REJECT,         "BSSAP+-LOCATION-UPDATE-REJECT" },                      /*  17.1.10 */
    { BSSAP_TMSI_REALLOCATION_COMPLETE,     "BSSAP+-TMSI-REALLOCATION-COMPLETE" },                  /*  17.1.22 */
    { BSSAP_ALERT_REQUEST,                  "BSSAP+-ALERT-REQUEST" },                               /*  17.1.3  */
    { BSSAP_ALERT_ACK,                      "BSSAP+-ALERT-ACK" },                                   /*  17.1.1  */
    { BSSAP_ALERT_REJECT,                   "BSSAP+-ALERT-REJECT" },                                /*  17.1.2  */
    { BSSAP_MS_ACTIVITY_INDICATION,         "BSSAP+-MS-ACTIVITY-INDICATION" },                      /*  17.1.14 */
    { BSSAP_GPRS_DETACH_INDICATION,         "BSSAP+-GPRS-DETACH-INDICATION" },                      /*  17.1.6  */
    { BSSAP_GPRS_DETACH_ACK,                "BSSAP+-GPRS-DETACH-ACK" },                             /*  17.1.5  */
    { BSSAP_IMSI_DETACH_INDICATION,         "BSSAP+-IMSI-DETACH-INDICATION" },                      /*  17.1.8  */
    { BSSAP_IMSI_DETACH_ACK,                "BSSAP+-IMSI-DETACH-ACK" },                             /*  17.1.7  */
    { BSSAP_RESET_INDICATION,               "BSSAP+-RESET-INDICATION" },                            /*  17.1.21 */
    { BSSAP_RESET_ACK,                      "BSSAP+-RESET-ACK" },                                   /*  17.1.20 */
    { BSSAP_MS_INFORMATION_REQUEST,         "BSSAP+-MS-INFORMATION-REQUEST" },                      /*  17.1.15 */
    { BSSAP_MS_INFORMATION_RESPONSE,        "BSSAP+-MS-INFORMATION-RESPONSE" },                     /*  17.1.16 */
    { 0x19,                                 "Unassigned: treated as an unknown Message type." },
    { BSSAP_MM_INFORMATION_REQUEST,         "BSSAP+-MM-INFORMATION-REQUEST" },                      /*  17.1.12 */
    { BSSAP_MOBILE_STATUS,                  "BSSAP+-MOBILE-STATUS" },                               /*  17.1.13 */
    { 0x1e,                                 "Unassigned: treated as an unknown Message type." },
    { BSSAP_MS_UNREACHABLE,                 "BSSAP+-MS-UNREACHABLE" },                              /*  17.1.17 */
    { 0,        NULL }
};

#define BSSAP_IMSI                      1
#define BSSAP_VLR_NUMBER                2
#define BSSAP_TMSI                      3
#define BSSAP_LOC_AREA_ID               4
#define BSSAP_CHANNEL_NEEDED            5
#define BSSAP_EMLPP_PRIORITY            6
#define BSSAP_TMSI_STATUS               7
#define BSSAP_GS_CAUSE                  8
#define BSSAP_SGSN_NUMBER               9
#define BSSAP_GPRS_LOC_UPD_TYPE         0x0a
#define BSSAP_GLOBAL_CN_ID              0x0b
#define BSSAP_MOBILE_STN_CLS_MRK1       0x0d
#define BSSAP_MOBILE_ID                 0x0e
#define BSSAP_REJECT_CAUSE              0x0f
#define BSSAP_IMSI_DET_FROM_GPRS_SERV_TYPE      0x10
#define BSSAP_IMSI_DET_FROM_NON_GPRS_SERV_TYPE  0x11
#define BSSAP_INFO_REQ                  0x12
#define BSSAP_PTMSI                     0x13
#define BSSAP_IMEI                      0x14
#define BSSAP_IMEISV                    0x15
#define BSSAP_MM_INFORMATION            0x17
#define BSSAP_CELL_GBL_ID               0x18
#define BSSAP_LOC_INF_AGE               0x19
#define BSSAP_MOBILE_STN_STATE          0x1a
#define BSSAP_SERVICE_AREA_ID           0x1e
#define BSSAP_ERRONEOUS_MSG             0x1b
#define BSSAP_DLINK_TNL_PLD_CTR_AND_INF 0x1c
#define BSSAP_ULINK_TNL_PLD_CTR_AND_INF 0x1d



static const value_string bssap_plus_ie_id_values[] = {
    { BSSAP_IMSI,                               "IMSI" },                                       /* 18.4.10 */
    { BSSAP_VLR_NUMBER,                         "VLR number" },                                 /* 18.4.26 */
    { BSSAP_TMSI,                               "TMSI" },                                       /* 18.4.23 */
    { BSSAP_LOC_AREA_ID,                        "Location area identifier" },                   /* 18.4.14 */
    { BSSAP_CHANNEL_NEEDED,                     "Channel Needed" },                             /* 18.4.2  */
    { BSSAP_EMLPP_PRIORITY,                     "eMLPP Priority" },                             /* 18.4.4  */
    { BSSAP_TMSI_STATUS,                        "TMSI status" },                                /* 18.4.24 */
    { BSSAP_GS_CAUSE,                           "Gs cause" },                                   /* 18.4.7  */
    { BSSAP_SGSN_NUMBER,                        "SGSN number" },                                /* 18.4.22 */
    { BSSAP_GPRS_LOC_UPD_TYPE,                  "GPRS location update type" },                  /* 18.4.6  */
    { BSSAP_GLOBAL_CN_ID,                       "Global CN-Id" },                               /* 18.4.27 */
    { 0x0c,                                     "Unassigned: treated as an unknown IEI." },     /* 18 and 16 */
    { BSSAP_MOBILE_STN_CLS_MRK1,                "Mobile station classmark 1" },                 /* 18.4.18 */
    { BSSAP_MOBILE_ID,                          "Mobile identity" },                            /* 18.4.17 */
    { BSSAP_REJECT_CAUSE,                       "Reject cause" },                               /* 18.4.21 */
    { BSSAP_IMSI_DET_FROM_GPRS_SERV_TYPE,       "IMSI detach from GPRS service type" },         /* 18.4.11 */
    { BSSAP_IMSI_DET_FROM_NON_GPRS_SERV_TYPE,   "IMSI detach from non-GPRS service type" },     /* 18.4.12 */
    { BSSAP_INFO_REQ,                           "Information requested" },                      /* 18.4.13 */
    { BSSAP_PTMSI,                              "PTMSI" },                                      /* 18.4.20 */
    { BSSAP_IMEI,                               "IMEI" },                                       /* 18.4.8  */
    { BSSAP_IMEISV,                             "IMEISV" },                                     /* 18.4.9 */
    { 0x16,                                     "Unassigned: treated as an unknown IEI." },     /* 18 and 16 */
    { BSSAP_MM_INFORMATION,                     "MM information" },                             /* 18.4.16 */
    { BSSAP_CELL_GBL_ID,                        "Cell Global Identity" },                       /* 18.4.1 */
    { BSSAP_LOC_INF_AGE,                        "Location information age" },                   /* 18.4.15 */
    { BSSAP_MOBILE_STN_STATE,                   "Mobile station state" },                       /* 18.4.19 */
    { BSSAP_ERRONEOUS_MSG,                      "Erroneous message" },                          /* 18.4.5 */
    { BSSAP_DLINK_TNL_PLD_CTR_AND_INF,          "Downlink Tunnel Payload Control and Info" },   /* 18.4.3 */
    { BSSAP_ULINK_TNL_PLD_CTR_AND_INF,          "Uplink Tunnel Payload Control and Info" },     /* 18.4.25 */
    { BSSAP_SERVICE_AREA_ID,                    "Service Area Identification" },                /* 18.4.21b */
    { 0,                NULL }
};

/* Initialize the protocol and registered fields */
static int proto_bssap = -1;
/*static int proto_bssap_plus = -1;*/
static int hf_bssap_pdu_type = -1;
static int hf_bsap_pdu_type = -1;
static int hf_bssap_dlci_cc = -1;
static int hf_bsap_dlci_cc = -1;
static int hf_bssap_dlci_spare = -1;
static int hf_bsap_dlci_rsvd = -1;
static int hf_bssap_dlci_sapi = -1;
static int hf_bsap_dlci_sapi = -1;
static int hf_bssap_length = -1;
static int hf_bssap_plus_ie = -1;
static int hf_bssap_plus_ie_len = -1;

static int hf_bssap_plus_message_type = -1;
static int hf_bssap_imsi_ie = -1;
static int hf_bssap_imsi_det_from_gprs_serv_type_ie = -1;
static int hf_bssap_imsi_det_from_non_gprs_serv_type_ie = -1;
static int hf_bssap_info_req_ie = -1;
static int hf_bssap_loc_area_id_ie = -1;
static int hf_bssap_loc_inf_age_ie = -1;
static int hf_bssap_mm_information_ie = -1;
static int hf_bssap_mobile_id_ie = -1;
static int hf_bssap_mobile_stn_cls_mrk1_ie = -1;
static int hf_bssap_mobile_station_state_ie = -1;
static int hf_bssap_ptmsi_ie = -1;
static int hf_bssap_reject_cause_ie = -1;
static int hf_bssap_service_area_id_ie = -1;
static int hf_bssap_sgsn_nr_ie = -1;
static int hf_bssap_tmsi_ie = -1;
static int hf_bssap_tmsi_status_ie = -1;
static int hf_bssap_vlr_number_ie = -1;
static int hf_bssap_global_cn_id_ie = -1;
static int hf_bssap_plus_ie_data = -1;

static int hf_bssap_extension = -1;
static int hf_bssap_type_of_number = -1;
static int hf_bssap_numbering_plan_id = -1;
static int hf_bssap_sgsn_number = -1;
static int hf_bssap_vlr_number = -1;
static int hf_bssap_call_priority = -1;
static int hf_bssap_gprs_loc_upd_type_ie = -1;
static int hf_bssap_Gs_cause_ie = -1;
static int hf_bssap_imei_ie = -1;
static int hf_bssap_imesiv_ie = -1;
static int hf_bssap_cell_global_id_ie = -1;
static int hf_bssap_channel_needed_ie = -1;
static int hf_bssap_dlink_tnl_pld_cntrl_amd_inf_ie = -1;
static int hf_bssap_ulink_tnl_pld_cntrl_amd_inf_ie = -1;
static int hf_bssap_emlpp_prio_ie = -1;
static int hf_bssap_gprs_erroneous_msg_ie = -1;

static int hf_bssap_gprs_loc_upd_type = -1;
static int hf_bssap_Gs_cause = -1;
static int hf_bssap_imei = -1;
static int hf_bssap_imeisv = -1;
static int hf_bssap_imsi = -1;
static int hf_bssap_imsi_det_from_gprs_serv_type = -1;
static int hf_bssap_info_req = -1;
static int hf_bssap_loc_inf_age = -1;
static int hf_bssap_mobile_station_state = -1;
static int hf_bssap_ptmsi = -1;
static int hf_bssap_tmsi = -1;
static int hf_bssap_tmsi_status = -1;
static int hf_bssap_tom_prot_disc = -1;
static int hf_bssap_e_bit = -1;
static int hf_bssap_tunnel_prio = -1;
static int hf_bssap_global_cn_id = -1;
static int hf_bssap_plmn_id = -1;
static int hf_bssap_cn_id = -1;
static int hf_bssap_cell_global_id = -1;

/* Initialize the subtree pointers */
static gint ett_bssap = -1;
static gint ett_bssap_dlci = -1;
static gint ett_bssap_imsi = -1;
static gint ett_bssap_imsi_det_from_gprs_serv_type = -1;
static gint ett_bssap_imsi_det_from_non_gprs_serv_type = -1;
static gint ett_bssap_info_req = -1;
static gint ett_bssap_loc_area_id = -1;
static gint ett_bssap_loc_inf_age = -1;
static gint ett_bssap_mm_information = -1;
static gint ett_bssap_mobile_id = -1;
static gint ett_bssap_sgsn_nr = -1;
static gint ett_bssap_tmsi = -1;
static gint ett_bssap_tmsi_status = -1;
static gint ett_bssap_vlr_number = -1;
static gint ett_bssap_global_cn = -1;
static gint ett_bssap_gprs_loc_upd = -1;
static gint ett_bassp_Gs_cause = -1;
static gint ett_bassp_imei = -1;
static gint ett_bassp_imesiv = -1;
static gint ett_bssap_cell_global_id = -1;
static gint ett_bssap_cgi = -1;
static gint ett_bssap_channel_needed = -1;
static gint ett_bssap_dlink_tnl_pld_cntrl_amd_inf = -1;
static gint ett_bssap_ulink_tnl_pld_cntrl_amd_inf = -1;
static gint ett_bssap_emlpp_prio = -1;
static gint ett_bssap_erroneous_msg = -1;
static gint ett_bssap_mobile_stn_cls_mrk1 = -1;
static gint ett_bssap_mobile_station_state = -1;
static gint ett_bssap_ptmsi = -1;
static gint ett_bssap_reject_cause = -1;
static gint ett_bssap_service_area_id =-1;
static gint ett_bssap_global_cn_id = -1;
static gint ett_bssap_plmn = -1;

static dissector_handle_t data_handle;
static dissector_handle_t rrlp_handle;

static dissector_table_t bssap_dissector_table;
static dissector_table_t bsap_dissector_table;

static dissector_handle_t bsap_dissector_handle;

/*
 * Keep track of pdu_type so we can call appropriate sub-dissector
 */
static guint8   pdu_type = 0xFF;

static gint bssap_or_bsap_global = BSSAP_OR_BSAP_DEFAULT;

static gint    gsm_or_lb_interface_global = GSM_OR_LB_INTERFACE_DEFAULT;

static void
dissect_bssap_unknown_message(tvbuff_t *message_tvb, proto_tree *bssap_tree)
{
    guint32 message_length;

    message_length = tvb_length(message_tvb);

    proto_tree_add_text(bssap_tree, message_tvb, 0, message_length,
                "Unknown message (%u byte%s)",
                message_length, plurality(message_length, "", "s"));
}

static void
dissect_bssap_unknown_param(tvbuff_t *tvb, proto_tree *tree, guint8 type, guint16 length)
{
    proto_tree_add_text(tree, tvb, 0, length,
                "Unknown parameter 0x%x (%u byte%s)",
                type, length, plurality(length, "", "s"));
}

static void
dissect_bssap_data_param(tvbuff_t *tvb, packet_info *pinfo,
            proto_tree *bssap_tree, proto_tree *tree)
{
    if ((pdu_type <= 0x01))
    {
        if (bssap_or_bsap_global == BSSAP)
        {
            /* BSSAP */
            if((gsm_or_lb_interface_global == LB_INTERFACE) && (pdu_type == BSSAP_PDU_TYPE_BSSMAP))
            {
                bsap_dissector_handle = find_dissector("gsm_bssmap_le");

                if(bsap_dissector_handle == NULL) return;

                call_dissector(bsap_dissector_handle, tvb, pinfo, tree);

                return;
            }
            else if((gsm_or_lb_interface_global == GSM_INTERFACE) && (pdu_type == BSSAP_PDU_TYPE_BSSMAP))
            {
                bsap_dissector_handle = find_dissector("gsm_a_bssmap");

                if(bsap_dissector_handle == NULL) return;

                call_dissector(bsap_dissector_handle, tvb, pinfo, tree);

                return;
            }
            else
            {
                if (dissector_try_uint(bssap_dissector_table, pdu_type, tvb, pinfo, tree)) return;
            }
        }
        else
        {
            /* BSAP */
            if (dissector_try_uint(bsap_dissector_table, pdu_type, tvb, pinfo, tree))
                return;
        }
    }

    /* No sub-dissection occured, treat it as raw data */
    call_dissector(data_handle, tvb, pinfo, bssap_tree);
}

static void
dissect_bssap_dlci_param(tvbuff_t *tvb, proto_tree *tree, guint16 length)
{
    proto_item  *dlci_item = 0;
    proto_tree  *dlci_tree = 0;
    guint8  oct;

    dlci_item =
        proto_tree_add_text(tree, tvb, 0, length,
                    "Data Link Connection Identifier");

    dlci_tree = proto_item_add_subtree(dlci_item, ett_bssap_dlci);

    oct = tvb_get_guint8(tvb, 0);

    if (bssap_or_bsap_global == BSSAP)
    {
        proto_tree_add_uint(dlci_tree, hf_bssap_dlci_cc, tvb, 0, length, oct);
        proto_tree_add_uint(dlci_tree, hf_bssap_dlci_spare, tvb, 0, length, oct);
        proto_tree_add_uint(dlci_tree, hf_bssap_dlci_sapi, tvb, 0, length, oct);
    }
    else
    {
        proto_tree_add_uint(dlci_tree, hf_bsap_dlci_cc, tvb, 0, length, oct);
        proto_tree_add_uint(dlci_tree, hf_bsap_dlci_rsvd, tvb, 0, length, oct);
        proto_tree_add_uint(dlci_tree, hf_bsap_dlci_sapi, tvb, 0, length, oct);
    }
}

static void
dissect_bssap_length_param(tvbuff_t *tvb, proto_tree *tree, guint16 length)
{
    guint8  data_length;

    data_length = tvb_get_guint8(tvb, 0);
    proto_tree_add_uint(tree, hf_bssap_length, tvb, 0, length, data_length);
}

/*
 * Dissect a parameter given its type, offset into tvb, and length.
 */
static guint16
dissect_bssap_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bssap_tree,
               proto_tree *tree, guint8 parameter_type, gint offset,
               guint16 parameter_length)
{
    tvbuff_t *parameter_tvb;

    parameter_tvb = tvb_new_subset(tvb, offset, parameter_length, parameter_length);

    switch (parameter_type)
    {
    case PARAMETER_DLCI:
        dissect_bssap_dlci_param(parameter_tvb, bssap_tree, parameter_length);
        break;

    case PARAMETER_LENGTH:
        dissect_bssap_length_param(parameter_tvb, bssap_tree, parameter_length);
        break;

    case PARAMETER_DATA:
        dissect_bssap_data_param(parameter_tvb, pinfo, bssap_tree, tree);
        break;

    default:
        dissect_bssap_unknown_param(parameter_tvb, bssap_tree, parameter_type,
                        parameter_length);
        break;
    }

    return(parameter_length);
}

static guint16
dissect_bssap_var_parameter(tvbuff_t *tvb, packet_info *pinfo,
                proto_tree *bssap_tree, proto_tree *tree,
                guint8 parameter_type, gint offset)
{
    guint16 parameter_length;
    guint8  length_length;

    parameter_length = tvb_get_guint8(tvb, offset);
    length_length = LENGTH_LENGTH;

    offset += length_length;

    dissect_bssap_parameter(tvb, pinfo, bssap_tree, tree, parameter_type,
                offset, parameter_length);

    return(parameter_length + length_length);
}

static int
dissect_bssap_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bssap_tree,
             proto_tree *tree)
{
    gint    offset = 0;

    /*
     * Extract the PDU type
     */
    pdu_type = tvb_get_guint8(tvb, PDU_TYPE_OFFSET);
    offset = PDU_TYPE_LENGTH;

    if (bssap_tree)
    {
        /*
         * add the message type to the protocol tree
         */
        proto_tree_add_uint(bssap_tree,
                    (bssap_or_bsap_global == BSSAP) ? hf_bssap_pdu_type : hf_bsap_pdu_type,
                    tvb, PDU_TYPE_OFFSET, PDU_TYPE_LENGTH, pdu_type);
    }

    /* Starting a new message dissection */

    switch (pdu_type)
    {
    case BSSAP_PDU_TYPE_BSSMAP:
        offset += dissect_bssap_parameter(tvb, pinfo, bssap_tree, tree,
                          PARAMETER_LENGTH, offset,
                          LENGTH_LENGTH);
        offset += dissect_bssap_var_parameter(tvb, pinfo, bssap_tree, tree,
                              PARAMETER_DATA,
                              (offset - LENGTH_LENGTH));
        break;

    case BSSAP_PDU_TYPE_DTAP:
        offset += dissect_bssap_parameter(tvb, pinfo, bssap_tree, tree,
                          PARAMETER_DLCI,
                          offset, DLCI_LENGTH);
        offset += dissect_bssap_parameter(tvb, pinfo, bssap_tree, tree,
                          PARAMETER_LENGTH, offset,
                          LENGTH_LENGTH);
        offset += dissect_bssap_var_parameter(tvb, pinfo, bssap_tree, tree,
                              PARAMETER_DATA,
                              (offset - LENGTH_LENGTH));
        break;

    default:
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
                val_to_str_const(pdu_type,
                                 ((bssap_or_bsap_global == BSSAP) ?
                                  bssap_pdu_type_acro_values : bsap_pdu_type_acro_values),
                                 "Unknown"));
        dissect_bssap_unknown_message(tvb, bssap_tree);
        break;
    }
    return offset;
}

static void
dissect_bssap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *bssap_item;
    proto_tree  *bssap_tree = NULL;

    /*
     * Make entry in the Protocol column on summary display
     */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, ((bssap_or_bsap_global == BSSAP) ? "BSSAP" : "BSAP"));

    if ( pinfo->sccp_info && pinfo->sccp_info->data.co.assoc  )
        pinfo->sccp_info->data.co.assoc->payload = SCCP_PLOAD_BSSAP;

    /*
     * create the bssap protocol tree
     */
    bssap_item = proto_tree_add_protocol_format(tree, proto_bssap, tvb, 0, -1,
        (bssap_or_bsap_global == BSSAP) ? "BSSAP" : "BSAP");
    bssap_tree = proto_item_add_subtree(bssap_item, ett_bssap);

    /* dissect the message */

    dissect_bssap_message(tvb, pinfo, bssap_tree, tree);
}


/*
 * BSSAP+ Routines
 */

#ifdef REMOVED
static dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#'
    }
};
#endif

static dgt_set_t Dgt1_9_bcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?'
    }
};
/* Assumes the rest of the tvb contains the digits to be turned into a string
 */
static const char*
unpack_digits(tvbuff_t *tvb, int offset,dgt_set_t *dgt,gboolean skip_first){

    int length;
    guint8 octet;
    int i=0;
    char *digit_str;

    length = tvb_length(tvb);
    if (length < offset)
        return "";
    digit_str = ep_alloc((length - offset)*2+1);

    while ( offset < length ){

        octet = tvb_get_guint8(tvb,offset);
        if (!skip_first){
            digit_str[i] = dgt->out[octet & 0x0f];
            i++;
        }
        skip_first = FALSE;

        /*
         * unpack second value in byte
         */
        octet = octet >> 4;

        if (octet == 0x0f)  /* odd number bytes - hit filler */
            break;

        digit_str[i] = dgt->out[octet & 0x0f];
        i++;
        offset++;

    }
    digit_str[i]= '\0';
    return digit_str;
}

static gboolean
check_ie(tvbuff_t *tvb, proto_tree *tree, int *offset, guint8 expected_ie){
    guint8  ie_type;
    guint8  ie_len;

    ie_type = tvb_get_guint8(tvb,*offset);
    if (ie_type != expected_ie){
        proto_tree_add_text(tree, tvb, *offset, 1, "Mandatory IE %s expected but IE %s Found",
                            val_to_str(expected_ie,bssap_plus_ie_id_values,"Unknown %u"),
                            val_to_str(ie_type,bssap_plus_ie_id_values,"Unknown %u"));
        (*offset)++;
        ie_len = tvb_get_guint8(tvb,*offset);
        *offset = *offset + ie_len;
        return FALSE;
    }

    return TRUE;

}

static gboolean
check_optional_ie(tvbuff_t *tvb, int offset, guint8 expected_ie){
    guint8  ie_type;

    ie_type = tvb_get_guint8(tvb,offset);
    if (ie_type != expected_ie){
        return FALSE;
    }
    return TRUE;

}

/* 18.4.1 Cell global identity */
static int
dissect_bssap_cell_global_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    proto_item  *cgi_item = NULL;
    proto_tree  *cgi_tree = NULL;
    guint8           ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_cell_global_id_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_cell_global_id);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*
     * The rest of the information element is coded as the the value part
     * of the cell global id IE defined in 3GPP TS 48.018 (not including
     * 3GPP TS 48.018 IEI and 3GPP TS 48.018 length indicator).
     */
    cgi_item= proto_tree_add_item(ie_tree, hf_bssap_cell_global_id, tvb, offset, ie_len, ENC_NA);
    cgi_tree = proto_item_add_subtree(cgi_item, ett_bssap_cgi);
    /*  octets 3-8 Octets 3 to 8 contain the value part (starting with octet 2) of the
     *  Routing Area Identification IE defined in 3GPP TS 24.008, not
     *  including 3GPP TS 24.008 IEI
     */
    de_gmm_rai(tvb, cgi_tree, pinfo, offset, ie_len, NULL, 0);
    /*  Octets 9 and 10 contain the value part (starting with octet 2) of the
     *  Cell Identity IE defined in 3GPP TS 24.008, not including
     *  3GPP TS 24.008 IEI
     */
    offset = offset + 6;
    de_cell_id(tvb, cgi_tree, pinfo, offset, ie_len, NULL, 0);
    offset = offset + 2;

    return offset;

}
/* 18.4.2 Channel needed */
static int
dissect_bssap_channel_needed(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8           ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_channel_needed_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_channel_needed);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*
     * The rest of the information element is coded as the IEI part and the
     * value part of the Channel Needed IE defined in 3GPP TS 44.018.
     * 10.5.2.8 Channel Needed
     */
    de_rr_chnl_needed(tvb, ie_tree, pinfo, offset, ie_len, NULL, 0);

    return offset + ie_len;

}
/* 18.4.3 Downlink Tunnel Payload Control and Info */
static int
dissect_bssap_dlink_tunnel_payload_control_and_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *item = NULL;
    proto_tree *ie_tree = NULL;
    tvbuff_t *next_tvb;
    guint8 ie_len;
    guint8 octet;
    guint8 prot_disc;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_dlink_tnl_pld_cntrl_amd_inf_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_dlink_tnl_pld_cntrl_amd_inf);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Bit 8 Spare */
    /* Bit 7 - 4
     * TOM Protocol Discriminator: Identifies the protocol using tunnelling of non-GSM signalling.
     * For coding, see 3GPP TS 44.064.
     */

    proto_tree_add_item(ie_tree, hf_bssap_tom_prot_disc, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = tvb_get_guint8(tvb,offset);
    prot_disc = (octet&0x78)>>3;

    /* octet 3 bit 3 E: Cipher Request. When set to 1 indicates that the SGSN received the payload in ciphered form,
     * when set to 0 indicates that the SGSN did not receive the payload in ciphered form.
     */
    proto_tree_add_item(ie_tree, hf_bssap_e_bit, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* octet 3 bit 2 - 1
     * Tunnel Priority: Indicates the priority of the Tunnel Payload. For coding, see Table 20.1: Association
     * between Tunnel Priority and LLC SAPs.
     */
    proto_tree_add_item(ie_tree, hf_bssap_tunnel_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Tunnel payload */
    next_tvb = tvb_new_subset(tvb, offset, ie_len-4, ie_len-4);

    if ((prot_disc == 2)&&(rrlp_handle))
        call_dissector(rrlp_handle, next_tvb, pinfo, ie_tree);
    else
        call_dissector(data_handle, next_tvb, pinfo, ie_tree);


    return offset + ie_len;

}

/* 18.4.4 eMLPP Priority */
/* Call priority */
static const value_string bssap_call_priority_values[] = {
    { 0x00,             "No priority applied" },
    { 0x01,             "Call priority level 4" },
    { 0x02,             "Call priority level 3" },
    { 0x03,             "Call priority level 2" },
    { 0x04,             "Call priority level 1" },
    { 0x05,             "Call priority level 0" },
    { 0x06,             "Call priority level B" },
    { 0x07,             "Call priority level A" },
    { 0,                NULL }
};
static int
dissect_bssap_emlpp_priority(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_emlpp_prio_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_emlpp_prio);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The rest of the information element is coded as the value part of
        the eMLPP-Priority IE defined in 3GPP TS 48.008 (not including
        3GPP TS 48.008 IEI and 3GPP TS 48.008 length indicator).
        3.2.2.56 eMLPP Priority
        The call priority field (bit 3 to 1 of octet 2) is coded in the same way
        as the call priority field (bit 3 to 1 of octet 5) in the Descriptive group
        or broadcast call reference information element as defined in 3GPP TS 24.008.
     */
    proto_tree_add_item(ie_tree, hf_bssap_call_priority, tvb, offset, ie_len, ENC_BIG_ENDIAN);

    return offset + ie_len;

}
/* 18.4.5 Erroneous message */
    /* Erroneous message including the message type. */

static int
dissect_bssap_gprs_erroneous_msg(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_gprs_erroneous_msg_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_erroneous_msg);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Erroneous message including the message type. */
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_data, tvb, offset, ie_len, ENC_NA);

    return offset + ie_len;

}


static const value_string bssap_plus_GPRS_loc_upd_type_values[] = {
    { 0x00,             "Shall not be sent in this version of the protocol. If received, shall be treated as '00000010'." },
    { 0x01,             "IMSI attach" },
    { 0x02,             "Normal location update" },
    { 0,                NULL }
};
/* 18.4.6 GPRS location update type */
static int
dissect_bssap_gprs_location_update_type(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_gprs_loc_upd_type_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_gprs_loc_upd);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* GPRS location update type value (octet 3) */
    proto_tree_add_item(ie_tree, hf_bssap_gprs_loc_upd_type, tvb, offset, ie_len, ENC_BIG_ENDIAN);

    return offset + ie_len;
}

/* Gs Cause value (octet 3) */
static const value_string bssap_Gs_cause_values[] = {

    { 0x00,     "Normal, unspecified in this version of the protocol." },
    { 0x01,     "IMSI detached for GPRS services" },
    { 0x02,     "IMSI detached for GPRS and non-GPRS services" },
    { 0x03,     "IMSI unknown" },
    { 0x04,     "IMSI detached for non-GPRS services" },
    { 0x05,     "IMSI implicitly detached for non-GPRS services" },
    { 0x06,     "MS unreachable" },
    { 0x07,     "Message not compatible with the protocol state" },
    { 0x08,     "Missing mandatory information element" },
    { 0x09,     "Invalid mandatory information" },
    { 0x0a,     "Conditional IE error" },
    { 0x0b,     "Semantically incorrect message" },
    { 0x0c,     "Message unknown" },
    { 0x0d,     "Address error" },
    { 0x0e,     "TOM functionality not supported" },
    { 0x0f,     "Ciphering request cannot be accommodated" },
    { 0,        NULL }
};

/* 18.4.7 Gs cause */
static int
dissect_bssap_Gs_cause(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_Gs_cause_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bassp_Gs_cause);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Gs Cause value (octet 3) */
    proto_tree_add_item(ie_tree, hf_bssap_Gs_cause, tvb, offset, ie_len, ENC_BIG_ENDIAN);


    return offset + ie_len;

}
/* 18.4.8 IMEI */
static int
dissect_bssap_imei(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *item = NULL;
    proto_tree *ie_tree = NULL;
    guint8 ie_len;
    tvbuff_t *ie_tvb;
    const char *digit_str;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_imei_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bassp_imei);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* The IMEI is coded as a sequence of BCD digits, compressed two into each octet.
     * The IMEI consists of 15 digits (see 3GPP TS 23.003).
     */
    ie_tvb = tvb_new_subset(tvb, offset, ie_len, ie_len);
    digit_str = unpack_digits(ie_tvb, 0, &Dgt1_9_bcd, ENC_BIG_ENDIAN);
    proto_tree_add_string(ie_tree, hf_bssap_imei, ie_tvb, 0, -1, digit_str);

    return offset + ie_len;

}
/* 18.4.9 IMEISV */
static int
dissect_bssap_imesiv(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *item = NULL;
    proto_tree *ie_tree = NULL;
    guint8 ie_len;
    tvbuff_t *ie_tvb;
    const char *digit_str;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_imesiv_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bassp_imesiv);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The IMEISV is coded as a sequence of BCD digits, compressed two into each octet.
     *  The IMEISV consists of 16 digits (see 3GPP TS 23.003).
     */
    ie_tvb = tvb_new_subset(tvb, offset, ie_len, ie_len);
    digit_str = unpack_digits(ie_tvb, 0, &Dgt1_9_bcd, ENC_BIG_ENDIAN);
    proto_tree_add_string(ie_tree, hf_bssap_imeisv, ie_tvb, 0, -1, digit_str);

    return offset + ie_len;

}
/* 18.4.10 IMSI
 * The IMSI is coded as a sequence of BCD digits, compressed two into each octet.
 * This is a variable length element, and includes a length indicator.
 * The IMSI is defined in 3GPP TS 23.003. It shall not exceed 15 digits (see 3GPP TS 23.003).
 */


static int
dissect_bssap_imsi(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *item = NULL;
    proto_tree *ie_tree = NULL;
    guint8 ie_len;
    tvbuff_t *ie_tvb;
    const char *digit_str;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_imsi_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_imsi);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ie_tvb = tvb_new_subset(tvb, offset, ie_len,ie_len);
    digit_str = unpack_digits(ie_tvb, 0, &Dgt1_9_bcd, TRUE);
    proto_tree_add_string(ie_tree, hf_bssap_imsi, ie_tvb, 0, -1, digit_str);

    return offset + ie_len;

}
static const value_string bssap_imsi_det_from_gprs_serv_type_values[] _U_ = {
    { 0x00,     "Interpreted as reserved in this version of the protocol" },
    { 0x01,     "Network initiated IMSI detach from GPRS service" },
    { 0x02,     "MS initiated IMSI detach from GPRS service" },
    { 0x03,     "GPRS services not allowed" },
    { 0,                NULL }
};

/* 18.4.11 IMSI detach from GPRS service type */
static int
dissect_bssap_imsi_det_from_gprs_serv_type(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_imsi_det_from_gprs_serv_type_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_imsi_det_from_gprs_serv_type);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* IMSI detach from GPRS service type value (octet 3)*/
    proto_tree_add_item(ie_tree, hf_bssap_imsi_det_from_gprs_serv_type, tvb, offset, ie_len, ENC_BIG_ENDIAN);


    return offset + ie_len;

}
/* 18.4.12 IMSI detach from non-GPRS service type */
static int
dissect_bssap_imsi_det_from_non_gprs_serv_type(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_imsi_det_from_non_gprs_serv_type_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_imsi_det_from_non_gprs_serv_type);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_data, tvb, offset, ie_len, ENC_NA);


    return offset + ie_len;

}
static const value_string bssap_info_req_values[] = {
    { 0x00,     "Interpreted as Not supported in this version of the protocol." },
    { 0x01,     "PTMSI" },
    { 0x02,     "IMEI" },
    { 0x03,     "IMEISV" },
    { 0x04,     "PTMSI and IMEI" },
    { 0x05,     "PTMSI and IMEISV" },
    { 0x06,     "IMEI and IMEISV" },
    { 0x07,     "PTMSI, IMEI, and IMEISV" },
    { 0x08,     "Mobile location information" },
    { 0x09,     "TMSI" },
    { 0,                NULL }
};
/* 18.4.13 Information requested */
static int
dissect_bssap_info_req(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_info_req_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_info_req);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*Information requested value (octet 3) */
    proto_tree_add_item(ie_tree, hf_bssap_info_req, tvb, offset, ie_len, ENC_BIG_ENDIAN);


    return offset + ie_len;

}
/* 18.4.14 Location area identifier */
static int
dissect_bssap_loc_area_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_loc_area_id_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_loc_area_id);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The rest of the information element is coded as the value part of
     *  the location area identifier IE defined in 3GPP TS 48.018 (not
     *  including 3GPP TS 48.018 IEI and 3GPP TS 48.018 length
     *  indicator).
     */
    de_lai(tvb, ie_tree, pinfo, offset, ie_len, NULL, 0);

    return offset + ie_len;

}
/* 18.4.15 Location information age */
static int
dissect_bssap_location_information_age(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_loc_inf_age_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_loc_inf_age);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* The rest of the IE is coded as the value part of the
     * AgeOfLocationInformation as specified in 3GPP TS 29.002.:
     *   AgeOfLocationInformation ::= INTEGER (0..32767)
     * -- the value represents the elapsed time in minutes since the last
     * -- network contact of the mobile station (i.e. the actuality of the
     * -- location information).
     * -- value '0' indicates that the MS is currently in contact with the
     * -- network
     * -- value '32767' indicates that the location information is at least
     * -- 32767 minutes old
     */
    proto_tree_add_item(ie_tree, hf_bssap_loc_inf_age, tvb, offset, ie_len, ENC_BIG_ENDIAN);


    return offset + ie_len;

}
/* 18.4.16 MM information */
static int
dissect_bssap_MM_information(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_mm_information_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_mm_information);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* User information: This field is composed of one or more of the
     *  information elements of the MM information message as defined
     *  3GPP TS 24.008, excluding the Protocol discriminator, Skip
     *  indicator and Message type. This field includes the IEI and length
     *  indicatior of the other information elements.
     */
    dtap_mm_mm_info(tvb, ie_tree, pinfo, offset, ie_len);


    return offset + ie_len;

}
/* 18.4.17 Mobile identity */
static int
dissect_bssap_mobile_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_mobile_id_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_mobile_id);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The rest of the information element is coded as the value part of
     *  the mobile identity IE defined in 3GPP TS 24.008 (not including
     *  3GPP TS 24.008 IEI and 3GPP TS 24.008 length indicator).
     */
    de_mid(tvb, ie_tree, pinfo, offset, ie_len, NULL, 0);


    return offset + ie_len;

}
/* 18.4.18 Mobile station classmark 1 */
static int
dissect_bssap_mobile_stn_cls_mrk1(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_mobile_stn_cls_mrk1_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_mobile_stn_cls_mrk1);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The rest of the information element is coded as the value part of
     *  the mobile station classmark 1 IE defined in 3GPP TS 24.008 (not
     *  including 3GPP TS 24.008 IEI)
     */
    de_ms_cm_1(tvb, ie_tree, pinfo, offset, ie_len, NULL, 0);

    return offset + ie_len;

}
/* 18.4.19 Mobile station state */
static const value_string bssap_mobile_station_state_values[] = {
    { 0x00,     "IDLE or PMM-DETACHED" },
    { 0x01,     "STANDBY or PMM-IDLE, 0 PDP contexts active" },
    { 0x02,     "STANDBY or PMM-IDLE, 1 or more PDP contexts active" },
    { 0x03,     "SUSPENDED, 0 PDP contexts active" },
    { 0x04,     "SUSPENDED, 1 or more PDP contexts active" },
    { 0x05,     "READY or PMM-CONNECTED, 0 PDP contexts active" },
    { 0x06,     "READY or PMM-CONNECTED, 1 or more PDP contexts active" },
    { 0x07,     "IMSI unknown" },
    { 0x08,     "Information requested not supported" },
    { 0,                NULL }
};
static int
dissect_bssap_mobile_station_state(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_mobile_station_state_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_mobile_station_state);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Mobile station state value (octet 3) */
    proto_tree_add_item(ie_tree, hf_bssap_mobile_station_state, tvb, offset, ie_len, ENC_BIG_ENDIAN);

    return offset + ie_len;

}
/* 18.4.20 PTMSI */
static int
dissect_bssap_ptmsi(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_ptmsi_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_ptmsi);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* The PTMSI consists of 4 octets. It can be coded using a full hexadecimal representation
     * (see 3GPP TS 23.003).
     */
    proto_tree_add_item(ie_tree, hf_bssap_ptmsi, tvb, offset, ie_len, ENC_NA);

    return offset + ie_len;

}
/* 18.4.21 Reject cause */
static int
dissect_bssap_reject_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_reject_cause_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_reject_cause);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The rest of the information element is coded as the value part of
     *  the reject cause IE defined in 3GPP TS 24.008, not including
     *  3GPP TS 24.008 IEI.
     */
    de_rej_cause(tvb, ie_tree, pinfo, offset, ie_len, NULL, 0);

    return offset + ie_len;

}

/* 18.4.21b Service Area Identification */
static int
dissect_bssap_service_area_id(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_service_area_id_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_service_area_id);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The rest of the information element is coded as the the value part
     *  of the SAI IE defined in 3GPP TS 25.413 (not including
     *  3GPP TS 25.413 IEI and 3GPP TS 25.413 length indicator).
     */
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_data, tvb, offset, ie_len, ENC_NA);

    return offset + ie_len;

}

/* 18.4.22 SGSN number */

static const true_false_string bssap_extension_value = {
  "No Extension",
  "Extension"
};

static int
dissect_bssap_sgsn_number(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *item = NULL;
    proto_tree *ie_tree = NULL;
    guint8 ie_len;
    tvbuff_t *number_tvb;
    const char *digit_str;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_sgsn_nr_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_sgsn_nr);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* The SGSN number is coded as a sequence of TBCD digits (as specified in 3GPP TS 29.002),
     * compressed two into each octet. The Number is in international E.164 format as indicated by Octet 3
     * which coding is specified in 3GPP TS 29.002. This is a variable length information element,
     * and includes a length indicator. The value part of the SGSN number information element
     * (not including IEI, Length indicator and Octet 3) shall not exceed 15 digits.
     */
    proto_tree_add_item(ie_tree, hf_bssap_extension, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_bssap_type_of_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_bssap_numbering_plan_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    number_tvb = tvb_new_subset(tvb, offset, ie_len-1,ie_len-1);
    digit_str = unpack_digits(number_tvb, 0, &Dgt1_9_bcd, ENC_BIG_ENDIAN);
    proto_tree_add_string(ie_tree, hf_bssap_sgsn_number, number_tvb, 0, -1, digit_str);


    return offset + ie_len-1;

}
/* 18.4.23 TMSI */
static int
dissect_bssap_tmsi(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_tmsi_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_tmsi);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* The TMSI consists of 4 octets. It can be coded using a full hexadecimal representation
     * (see 3GPP TS 23.003).
     */
    proto_tree_add_item(ie_tree, hf_bssap_tmsi, tvb, offset, ie_len, ENC_NA);


    return offset + ie_len;

}

/* 18.4.24 TMSI status */
static const true_false_string bssap_tmsi_flag = {
  "Valid TMSI available",
  "No valid TMSI available"
};
static int
dissect_bssap_tmsi_status(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_tmsi_status_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_tmsi_status);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* TMSI flag (octet 3) */
    proto_tree_add_item(ie_tree, hf_bssap_tmsi_status, tvb, offset, ie_len, ENC_BIG_ENDIAN);


    return offset + ie_len;

}
/* 18.4.25 Uplink Tunnel Payload Control and Info */
static const true_false_string bssap_E_flag = {
  "SGSN received the payload in ciphered",
  "SGSN did not receive the payload in ciphered form"
};
/* 3GPP TS 44.064 B.1.1 TOM Protocol Discriminator */
static const value_string bssap_tom_prot_disc_values[] = {
    { 0x00,     "Not specified" },
    { 0x01,     "TIA/EIA-136" },
    { 0x02,     "RRLP" },
    { 0x03,     "Reserved for extension" },
    { 0,                NULL }
};
static int
dissect_bssap_ulink_tunnel_payload_control_and_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    tvbuff_t *next_tvb;
    guint8 ie_len;
    guint8 octet;
    guint8 prot_disc;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_ulink_tnl_pld_cntrl_amd_inf_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_ulink_tnl_pld_cntrl_amd_inf);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* octet 3 bit 8 Spare */
    /* octet 3 bit 7 - 4
     * TOM Protocol Discriminator: Identifies the protocol using tunnelling of non-GSM signalling.
     * For coding, see 3GPP TS 44.064.
     */
    proto_tree_add_item(ie_tree, hf_bssap_tom_prot_disc, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = tvb_get_guint8(tvb,offset);
    prot_disc = (octet&0x78)>>3;

    /* octet 3 bit 3 E: Cipher Request. When set to 1 indicates that the SGSN received the payload in ciphered form,
     * when set to 0 indicates that the SGSN did not receive the payload in ciphered form.
     */
    proto_tree_add_item(ie_tree, hf_bssap_e_bit, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* octet 3 bit 2 - 1
     * Tunnel Priority: Indicates the priority of the Tunnel Payload. For coding, see Table 20.1: Association
     * between Tunnel Priority and LLC SAPs.
     */
    proto_tree_add_item(ie_tree, hf_bssap_tunnel_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Tunnel payload */
    next_tvb = tvb_new_subset(tvb, offset, ie_len-4, ie_len-4);

    if ((prot_disc == 2)&&(rrlp_handle))
        call_dissector(rrlp_handle, next_tvb, pinfo, ie_tree);
    else
        call_dissector(data_handle, next_tvb, pinfo, ie_tree);

    return offset + ie_len;

}

/* 18.4.26 VLR number */
static int
dissect_bssap_vlr_number(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *item = NULL;
    proto_tree *ie_tree = NULL;
    guint8 ie_len;
    tvbuff_t *number_tvb;
    const char *digit_str;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_vlr_number_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_vlr_number);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The VLR number is coded as a sequence of TBCD digits (as specified in 3GPP TS 29.002),
     *  compressed two into each octet. The Number is in international E.164 format as indicated by Octet 3
     *  which coding is specified in 3GPP TS 29.002. This is a variable length information element,
     *  and includes a length indicator. The value part of the VLR number information element
     *  (not including IEI, length indicator and Octet 3), shall not exceed 15 digits.
     */

    proto_tree_add_item(ie_tree, hf_bssap_extension, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_bssap_type_of_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_bssap_numbering_plan_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    number_tvb = tvb_new_subset(tvb, offset, ie_len-1,ie_len-1);
    digit_str = unpack_digits(number_tvb, 0, &Dgt1_9_bcd, ENC_BIG_ENDIAN);
    proto_tree_add_string(ie_tree, hf_bssap_sgsn_number, number_tvb, 0, -1, digit_str);

    return offset + ie_len-1;

}
/* 18.4.27 Global CN-Id */
static int
dissect_bssap_global_cn_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item  *item = NULL;
    proto_tree  *ie_tree = NULL;
    proto_item  *plmn_item = NULL;
    proto_tree  *plmn_tree = NULL;
    proto_item  *global_cn_id_item = NULL;
    proto_tree  *global_cn_id_tree = NULL;
    guint8 ie_len;

    ie_len = tvb_get_guint8(tvb,offset+1);
    item = proto_tree_add_item(tree, hf_bssap_global_cn_id_ie, tvb, offset, ie_len+2, ENC_NA);
    ie_tree = proto_item_add_subtree(item, ett_bssap_global_cn);

    proto_tree_add_item(ie_tree, hf_bssap_plus_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_bssap_plus_ie_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* The Global CN-Id consists of a PLMN-Id and a CN-Id, see 3GPP TS 23.003.
     *  The PLMN-Id consists of MCC and MNC coded according to Location Area Identification
     * in 3GPP TS 24.008. The CN-Id is an integer defined by O&M.
     * The least significant bit of the CN-Id field is bit 1 of octet 7 and
     * the most significant bit is bit 8 of octet 6. If the CN-Id does not fill the field reserved for it,
     * the rest of the bits are set to '0'.
     */
    global_cn_id_item = proto_tree_add_item(ie_tree, hf_bssap_global_cn_id, tvb, offset, ie_len, ENC_NA);
    global_cn_id_tree = proto_item_add_subtree(global_cn_id_item, ett_bssap_global_cn_id);
    /* Octet 3 - 5 PLMN-Id Coded as octets 2 to 4 of the Location Area Identification IE,
     * defined in 3GPP TS 24.008 (not including 3GPP TS 24.008 IEI and LAC).
     */
    plmn_item = proto_tree_add_item(global_cn_id_tree, hf_bssap_plmn_id, tvb, offset, 3, ENC_NA);
    plmn_tree = proto_item_add_subtree(plmn_item, ett_bssap_plmn);
    dissect_e212_mcc_mnc(tvb, pinfo, plmn_tree, offset, TRUE);
    offset = offset + 3;

    /* Octet 6 - 7 CN-Id (INTEGER 0..4095) */
    proto_tree_add_item(global_cn_id_tree, hf_bssap_cn_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset+2;

    return offset;

}

static void dissect_bssap_plus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *bssap_item;
    proto_tree  *bssap_tree = NULL;
    guint8      message_type;
    int         offset = 0;

    /*
     * Make entry in the Protocol column on summary display
     */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BSSAP+");

    if (pinfo->sccp_info && pinfo->sccp_info->data.co.assoc)
        pinfo->sccp_info->data.co.assoc->payload = SCCP_PLOAD_BSSAP;

    /* create the BSSAP+ protocol tree */
    bssap_item = proto_tree_add_item(tree, proto_bssap, tvb, 0, -1, ENC_NA);
    bssap_tree = proto_item_add_subtree(bssap_item, ett_bssap);

    message_type = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(bssap_tree, hf_bssap_plus_message_type, tvb, offset, 1,ENC_BIG_ENDIAN);
    offset++;

    col_add_str(pinfo->cinfo,COL_INFO, val_to_str(message_type,bssap_plus_message_type_values,"Unknown %u"));

    switch(message_type){
    case BSSAP_PAGING_REQUEST:
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* VLR number VLR number 18.4.26 M TLV 5-11 */
        if ( check_ie(tvb, tree, &offset, BSSAP_VLR_NUMBER))
            offset = dissect_bssap_vlr_number(tvb, bssap_tree, offset);

        /* End of mandatory elements */
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* TMSI TMSI 18.4.23 O TLV 6 */
        if ( check_optional_ie(tvb, offset, BSSAP_TMSI))
            offset = dissect_bssap_tmsi(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Location area identifier Location area identifier 18.4.14 O TLV 7 */
        if ( check_optional_ie(tvb, offset, BSSAP_LOC_AREA_ID))
            offset = dissect_bssap_loc_area_id(tvb, bssap_tree, pinfo, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Channel needed Channel needed 18.4.2 O TLV 3 */
        if ( check_optional_ie(tvb, offset, BSSAP_CHANNEL_NEEDED))
            offset = dissect_bssap_channel_needed(tvb, bssap_tree, pinfo, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* eMLPP Priority eMLPP Priority 18.4.4 O TLV 3 */
        if ( check_optional_ie(tvb, offset, BSSAP_EMLPP_PRIORITY))
            offset = dissect_bssap_emlpp_priority(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Global CN-Id Global CN-Id 18.4.27 O TLV 7 */
        if ( check_optional_ie(tvb, offset, BSSAP_GLOBAL_CN_ID))
            offset = dissect_bssap_global_cn_id(tvb, pinfo, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_PAGING_REJECT:                   /*  17.1.18 */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);
        /* Gs Cause Gs Cause 18.4.7 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_GS_CAUSE))
            offset = dissect_bssap_Gs_cause(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_DOWNLINK_TUNNEL_REQUEST:         /*  17.1.4  */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* VLR number VLR number 18.4.26 M TLV 5-11 */
        if ( check_ie(tvb, tree, &offset, BSSAP_VLR_NUMBER))
            offset = dissect_bssap_vlr_number(tvb, bssap_tree, offset);

        /* Downlink Tunnel Payload Control and Info 18.4.3 M TLV 3-223 */
        if ( check_ie(tvb, tree, &offset, BSSAP_DLINK_TNL_PLD_CTR_AND_INF))
            offset = dissect_bssap_dlink_tunnel_payload_control_and_info(tvb, pinfo, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_UPLINK_TUNNEL_REQUEST:           /*  17.1.23 */
        /* SGSN number 18.4.22 M TLV 5-11 */
        if ( check_ie(tvb, tree, &offset, BSSAP_SGSN_NUMBER))
            offset = dissect_bssap_sgsn_number(tvb, bssap_tree, offset);

        /* Uplink Tunnel Payload Control and Info 18.4.25 M TLV 3-223 */
        if ( check_ie(tvb, tree, &offset, BSSAP_ULINK_TNL_PLD_CTR_AND_INF))
            offset = dissect_bssap_ulink_tunnel_payload_control_and_info(tvb, pinfo, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_LOCATION_UPDATE_REQUEST:         /*  17.1.11 BSSAP+-LOCATION-UPDATE-REQUEST */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* SGSN number SGSN number 18.4.22 M TLV 5-11 */
        if ( check_ie(tvb, tree, &offset, BSSAP_SGSN_NUMBER))
            offset = dissect_bssap_sgsn_number(tvb, bssap_tree, offset);

        /* Update type GPRS location update type 18.4.6 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_GPRS_LOC_UPD_TYPE))
            offset = dissect_bssap_gprs_location_update_type(tvb, bssap_tree, offset);

        /* New Cell global identity Cell global identity 18.4.1 M TLV 10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_CELL_GBL_ID))
            offset = dissect_bssap_cell_global_id(tvb, bssap_tree, pinfo, offset);

        /* Mobile station classmark Mobile station classmark 1 18.4.18 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_MOBILE_STN_CLS_MRK1))
            offset = dissect_bssap_mobile_stn_cls_mrk1(tvb, bssap_tree, pinfo, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Old location area identifier Location area identifier 18.4.14 O TLV 7 */
        if ( check_optional_ie(tvb, offset, BSSAP_LOC_AREA_ID))
            offset = dissect_bssap_loc_area_id(tvb, bssap_tree, pinfo, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* TMSI status TMSI status 18.4.24 O TLV 3 */
        if ( check_optional_ie(tvb, offset, BSSAP_TMSI_STATUS))
            offset = dissect_bssap_tmsi_status(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* New service area identification Service area identification 18.4.21b O TLV 9 */
        if ( check_optional_ie(tvb, offset, BSSAP_SERVICE_AREA_ID))
            offset = dissect_bssap_service_area_id(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* IMEISV IMEISV 18.4.9 O TLV 10 */
        if ( check_optional_ie(tvb, offset, BSSAP_IMEISV))
            offset = dissect_bssap_imesiv(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_LOCATION_UPDATE_ACCEPT:          /*  17.1.9  */
        /* IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* Location area identifier Location area identifier 18.4.14 M TLV 7 */
        if ( check_ie(tvb, tree, &offset, BSSAP_LOC_AREA_ID))
            offset = dissect_bssap_loc_area_id(tvb, bssap_tree, pinfo, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* New TMSI, or IMSI Mobile identity 18.4.17 O TLV 6-10 */
        if ( check_optional_ie(tvb, offset, BSSAP_MOBILE_ID))
            offset = dissect_bssap_mobile_id(tvb, bssap_tree, pinfo, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_LOCATION_UPDATE_REJECT:          /*  17.1.10 */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);
        /* Reject cause Reject cause 18.4.21 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_REJECT_CAUSE))
            offset = dissect_bssap_reject_cause(tvb, bssap_tree, pinfo, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_TMSI_REALLOCATION_COMPLETE:      /*  17.1.22 */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Cell global identity Cell global identity 18.4.1 O TLV 10 */
        if ( check_optional_ie(tvb, offset, BSSAP_CELL_GBL_ID))
            offset = dissect_bssap_cell_global_id(tvb, bssap_tree, pinfo, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Service area identification Service area identification 18.4.21b O TLV 9 */
        if ( check_optional_ie(tvb, offset, BSSAP_SERVICE_AREA_ID))
            offset = dissect_bssap_service_area_id(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_ALERT_REQUEST:                   /*  17.1.3  */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_ALERT_ACK:                       /*  17.1.1  */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_ALERT_REJECT:                    /*  17.1.2  */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* Gs Cause Gs Cause 18.4.7 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_GS_CAUSE))
            offset = dissect_bssap_Gs_cause(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_MS_ACTIVITY_INDICATION:          /*  17.1.14 */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Cell global identity Cell global identity 18.4.1 O TLV 10 */
        if ( check_optional_ie(tvb, offset, BSSAP_CELL_GBL_ID))
            offset = dissect_bssap_cell_global_id(tvb, bssap_tree, pinfo, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Service area identification Service area identification 18.4.21b O TLV 9 */
        if ( check_optional_ie(tvb, offset, BSSAP_SERVICE_AREA_ID))
            offset = dissect_bssap_service_area_id(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_GPRS_DETACH_INDICATION:          /*  17.1.6  */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* SGSN number SGSN number 18.4.22 M TLV 5-11 */
        if ( check_ie(tvb, tree, &offset, BSSAP_SGSN_NUMBER))
            offset = dissect_bssap_sgsn_number(tvb, bssap_tree, offset);

        /* IMSI detach from GPRS service type IMSI detach from GPRS service type 18.4.17 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI_DET_FROM_GPRS_SERV_TYPE))
            offset = dissect_bssap_imsi_det_from_gprs_serv_type(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Cell global identity Cell global identity 18.4.1 O TLV 10 */
        if ( check_optional_ie(tvb, offset, BSSAP_CELL_GBL_ID))
            offset = dissect_bssap_cell_global_id(tvb, bssap_tree, pinfo, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Service area identification Service area identification 18.4.21b O TLV 9 */
        if ( check_optional_ie(tvb, offset, BSSAP_SERVICE_AREA_ID))
            offset = dissect_bssap_service_area_id(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_GPRS_DETACH_ACK:                 /*  17.1.5  */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_IMSI_DETACH_INDICATION:          /*  17.1.8  */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* SGSN number SGSN number 18.4.22 M TLV 5-11 */
        if ( check_ie(tvb, tree, &offset, BSSAP_SGSN_NUMBER))
            offset = dissect_bssap_sgsn_number(tvb, bssap_tree, offset);

        /* Detach type IMSI detach from non-GPRS service type 18.4.11 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI_DET_FROM_NON_GPRS_SERV_TYPE))
            offset = dissect_bssap_imsi_det_from_non_gprs_serv_type(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Cell global identity Cell global identity 18.4.1 O TLV 10 */
        if ( check_optional_ie(tvb, offset, BSSAP_CELL_GBL_ID))
            offset = dissect_bssap_cell_global_id(tvb, bssap_tree, pinfo, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Location information age Location information age 18.4.14 O TLV 4 */
        if ( check_optional_ie(tvb, offset, BSSAP_LOC_INF_AGE))
            offset = dissect_bssap_location_information_age(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Service area identification Service area identification 18.4.21b O TLV 9 */
        if ( check_optional_ie(tvb, offset, BSSAP_SERVICE_AREA_ID))
            offset = dissect_bssap_service_area_id(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_IMSI_DETACH_ACK:                 /*  17.1.7  */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_RESET_INDICATION:                /*  17.1.21 */
        /* Conditional IE:s */
        /* SGSN number SGSN number 18.4.22 C TLV 5-11 */
        if ( check_optional_ie(tvb, offset, BSSAP_SGSN_NUMBER)){
            offset = dissect_bssap_sgsn_number(tvb, bssap_tree, offset);
            if (tvb_length_remaining(tvb,offset) <= 0)
                return;
            proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        }else{
            /* VLR number VLR number 18.4.26 C TLV 5-11 */
            if ( check_optional_ie(tvb, offset, BSSAP_VLR_NUMBER)){
                offset = dissect_bssap_vlr_number(tvb, bssap_tree, offset);
                if (tvb_length_remaining(tvb,offset) <= 0)
                    return;
                proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
            }
        }
        proto_tree_add_text(tree, tvb, offset, -1, "Conditional IE");
        break;
    case BSSAP_RESET_ACK:                       /*  17.1.20 */
        /* Conditional IE:s */
        /* SGSN number SGSN number 18.4.22 C TLV 5-11 */
        if ( check_optional_ie(tvb, offset, BSSAP_SGSN_NUMBER)){
            offset = dissect_bssap_sgsn_number(tvb, bssap_tree, offset);
            if (tvb_length_remaining(tvb,offset) <= 0)
                return;
            proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        }else{
            /* VLR number VLR number 18.4.26 C TLV 5-11 */
            if ( check_optional_ie(tvb, offset, BSSAP_VLR_NUMBER)){
                offset = dissect_bssap_vlr_number(tvb, bssap_tree, offset);
                if (tvb_length_remaining(tvb,offset) <= 0)
                    return;
                proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
            }
        }
        proto_tree_add_text(tree, tvb, offset, -1, "Conditional IE");
        break;
    case BSSAP_MS_INFORMATION_REQUEST:          /*  17.1.15 */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* Information requested Information requested 18.4.13 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_INFO_REQ))
            offset = dissect_bssap_info_req(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_MS_INFORMATION_RESPONSE:         /*  17.1.16 */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* TMSI TMSI 18.4.23 O TLV 6 */
        if ( check_optional_ie(tvb, offset, BSSAP_TMSI))
            offset = dissect_bssap_tmsi(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* PTMSI PTMSI 18.4.20 O TLV 6 BSSAP_PTMSI*/
        if ( check_optional_ie(tvb, offset, BSSAP_PTMSI))
            offset = dissect_bssap_ptmsi(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* IMEI IMEI 18.4.8 O TLV 10 */
        if ( check_optional_ie(tvb, offset, BSSAP_IMEI))
            offset = dissect_bssap_imei(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        /* IMEISV IMEISV 18.4.9 O TLV 10 BSSAP_IMEISV*/
        if ( check_optional_ie(tvb, offset, BSSAP_IMEISV))
            offset = dissect_bssap_imesiv(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Cell global identity Cell global identity 18.4.1 O TLV 10 */
        if ( check_optional_ie(tvb, offset, BSSAP_CELL_GBL_ID))
            offset = dissect_bssap_cell_global_id(tvb, bssap_tree, pinfo, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        /* Location information age Location information age 18.4.15 O TLV 4 */
        if ( check_optional_ie(tvb, offset, BSSAP_LOC_INF_AGE))
            offset = dissect_bssap_location_information_age(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Mobile station state Mobile station state 18.4.19 O TLV 3 */
        if ( check_optional_ie(tvb, offset, BSSAP_MOBILE_STN_STATE))
            offset = dissect_bssap_mobile_station_state(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;

        /* Service area identification Service area identification 18.4.21b O TLV 9 */
        if ( check_optional_ie(tvb, offset, BSSAP_SERVICE_AREA_ID))
            offset = dissect_bssap_service_area_id(tvb, bssap_tree, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_MM_INFORMATION_REQUEST:          /*  17.1.12 */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        /* MM information MM information 18.4.16 O TLV 3-n */
        if ( check_optional_ie(tvb, offset, BSSAP_MM_INFORMATION))
            offset = dissect_bssap_MM_information(tvb, bssap_tree, pinfo, offset);
        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_MOBILE_STATUS:                   /*  17.1.13 */
        /* IMSI IMSI 18.4.10 O TLV 6-10 */
        if ( check_optional_ie(tvb, offset, BSSAP_IMSI))
                offset = dissect_bssap_imsi(tvb, bssap_tree, offset);
        /* Gs Cause Gs Cause 18.4.7 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_GS_CAUSE))
            offset = dissect_bssap_Gs_cause(tvb, bssap_tree, offset);

        /* Erroneous message Erroneous message 18.4.5 M TLV 3-n BSSAP_ERRONEOUS_MSG*/
        if ( check_ie(tvb, tree, &offset, BSSAP_ERRONEOUS_MSG))
            offset = dissect_bssap_gprs_erroneous_msg(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    case BSSAP_MS_UNREACHABLE:                  /*  17.1.17 */
        /* IMSI IMSI 18.4.10 M TLV 6-10 */
        if ( check_ie(tvb, tree, &offset, BSSAP_IMSI))
            offset = dissect_bssap_imsi(tvb, bssap_tree, offset);

        /* Gs Cause Gs Cause 18.4.7 M TLV 3 */
        if ( check_ie(tvb, tree, &offset, BSSAP_GS_CAUSE))
            offset = dissect_bssap_Gs_cause(tvb, bssap_tree, offset);

        if (tvb_length_remaining(tvb,offset) <= 0)
            return;
        proto_tree_add_text(tree, tvb, offset, -1, "Extraneous data");
        break;
    default:
        break;
    }
}

static gboolean
dissect_bssap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Is it a BSSAP/BSAP packet?
     *    If octet_1 == 0x00 and octet_2 == length(tvb) - 2
     * or if octet_1 == 0x01 and octet_3 == length(tvb) - 3
     * then we'll assume it is a bssap packet
     *    If octet_1 == 0x00 a further check is done
     *    to differentiate a BSSMAP BLOCK message from a
     *    RANAP DirectTransfer (under certain conditions)
     */
    switch (tvb_get_guint8(tvb, 0))
    {
    case 0x00:
        if (tvb_get_guint8(tvb, 1) != (tvb_length(tvb) - 2)) { return(ENC_BIG_ENDIAN); }
        if (tvb_get_guint8(tvb, 2) == 0x40 && tvb_get_guint8(tvb, 3) != 0x01) {
            return(ENC_BIG_ENDIAN); }
        break;

    case 0x01:
        if (tvb_get_guint8(tvb, 2) != (tvb_length(tvb) - 3)) { return(ENC_BIG_ENDIAN); }
        break;

    default:
        return(ENC_BIG_ENDIAN);
    }

    dissect_bssap(tvb, pinfo, tree);

    return(TRUE);
}

/* Register the protocol with Wireshark */
void
proto_register_bssap(void)
{
    module_t    *bssap_module;

    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_bssap_pdu_type,
          { "Message Type", "bssap.pdu_type",
        FT_UINT8, BASE_HEX, VALS(bssap_pdu_type_values), 0x0,
        NULL, HFILL}},
        { &hf_bsap_pdu_type,
          { "Message Type", "bsap.pdu_type",
        FT_UINT8, BASE_HEX, VALS(bsap_pdu_type_values), 0x0,
        NULL, HFILL}},
        { &hf_bssap_dlci_cc,
          { "Control Channel", "bssap.dlci.cc",
        FT_UINT8, BASE_HEX, VALS(bssap_cc_values), CC_MASK,
        NULL, HFILL}},
        { &hf_bsap_dlci_cc,
          { "Control Channel", "bsap.dlci.cc",
        FT_UINT8, BASE_HEX, VALS(bsap_cc_values), CC_MASK,
        NULL, HFILL}},
        { &hf_bssap_dlci_spare,
          { "Spare", "bssap.dlci.spare",
        FT_UINT8, BASE_HEX, NULL, SPARE_MASK,
        NULL, HFILL}},
        { &hf_bsap_dlci_rsvd,
          { "Reserved", "bsap.dlci.rsvd",
        FT_UINT8, BASE_HEX, NULL, SPARE_MASK,
        NULL, HFILL}},
        { &hf_bssap_dlci_sapi,
          { "SAPI", "bssap.dlci.sapi",
        FT_UINT8, BASE_HEX, VALS(bssap_sapi_values), SAPI_MASK,
        NULL, HFILL}},
        { &hf_bsap_dlci_sapi,
          { "SAPI", "bsap.dlci.sapi",
        FT_UINT8, BASE_HEX, VALS(bsap_sapi_values), SAPI_MASK,
        NULL, HFILL}},
        { &hf_bssap_length,
          { "Length", "bssap.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_bssap_plus_message_type,
          { "Message Type", "bssap_plus.msg_type",
        FT_UINT8, BASE_DEC, VALS(bssap_plus_message_type_values), 0x0,
        NULL, HFILL}},
        { &hf_bssap_plus_ie,
          { "IEI", "bssap_plus.iei",
        FT_UINT8, BASE_DEC, VALS(bssap_plus_ie_id_values), 0x0,
        NULL, HFILL}},
        { &hf_bssap_plus_ie_len,
          { "Length indicator", "bssap_plus.ie_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
        { &hf_bssap_extension,
          { "Extension", "bssap.extension",
            FT_BOOLEAN, 8, TFS(&bssap_extension_value), 0x80,
            NULL, HFILL }},
        { &hf_bssap_type_of_number,
          { "Type of number", "bssap.type_of_number",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_type_of_number_values), 0x70,
            NULL, HFILL }},
        { &hf_bssap_numbering_plan_id,
          { "Numbering plan identification", "bssap.number_plan",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_numbering_plan_id_values), 0x0f,
            NULL, HFILL }},
        { &hf_bssap_sgsn_number,
          { "SGSN number", "bssap.sgsn_number",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_vlr_number,
          { "VLR number", "bssap.vlr_number",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_cell_global_id_ie,
          { "Cell global identity IE", "bssap.cell_global_id_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_channel_needed_ie,
          { "Channel needed IE", "bssap.channel_needed_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_dlink_tnl_pld_cntrl_amd_inf_ie,
          { "Downlink Tunnel Payload Control and Info IE", "bssap.dlink_tnl_pld_cntrl_amd_inf_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_ulink_tnl_pld_cntrl_amd_inf_ie,
          { "Uplink Tunnel Payload Control and Info IE", "bssap.ulink_tnl_pld_cntrl_amd_inf_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_emlpp_prio_ie,
          { "eMLPP Priority IE", "bssap.emlpp_prio_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_gprs_erroneous_msg_ie,
          { "Erroneous message IE", "bssap.erroneous_msg_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_gprs_loc_upd_type_ie,
          { "GPRS location update type IE", "bssap.loc_upd_type_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_Gs_cause_ie,
          { "Gs Cause IE", "bssap.Gs_cause_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_imei_ie,
          { "IMEI IE", "bssap.imei_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_imesiv_ie,
          { "IMEISV IE", "bssap.imesiv",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_imsi_ie,
          { "IMSI IE", "bssap.imsi_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_imsi_det_from_gprs_serv_type_ie,
          { "IMSI detach from GPRS service type IE", "bssap.msi_det_from_gprs_serv_type_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_imsi_det_from_non_gprs_serv_type_ie,
          { "IMSI detach from non-GPRS service IE", "bssap.msi_det_from_non_gprs_serv_type_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_info_req_ie,
          { "Information requested IE", "bssap.info_req_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_loc_area_id_ie,
          { "Location area identifier IE", "bssap.loc_area_id_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_loc_inf_age_ie,
          { "Location information age IE", "bssap.loc_inf_age_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_mm_information_ie,
          { "MM information IE", "bssap.mm_information",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_mobile_id_ie,
          { "Mobile identity IE", "bssap.mobile_id_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_mobile_stn_cls_mrk1_ie,
          { "Mobile station classmark 1 IE", "bssap.mobile_stn_cls_mrk1_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_mobile_station_state_ie,
          { "Mobile station state IE", "bssap.mobile_station_state_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_ptmsi_ie,
          { "PTMSI IE", "bssap.ptmsi_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_reject_cause_ie,
          { "Reject cause IE", "bssap.reject_cause_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_service_area_id_ie,
          { "Service area identification IE", "bssap.service_area_id_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            "Mobile station classmark 1", HFILL }},
        { &hf_bssap_sgsn_nr_ie,
          { "SGSN number IE", "bssap.sgsn_nr_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_tmsi_ie,
          { "TMSI IE", "bssap.tmsi_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_tmsi_status_ie,
          { "TMSI status IE", "bssap.tmsi_status_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_vlr_number_ie,
          { "VLR number IE", "bssap.vlr_number_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_global_cn_id_ie,
          { "Global CN-Id IE", "bssap.global_cn_id_ie",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_bssap_plus_ie_data,
          { "IE Data", "bssap.ie_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_bssap_call_priority,
          { "eMLPP Priority", "bssap.call_priority",
        FT_UINT8, BASE_DEC, VALS(bssap_call_priority_values), 0x07,
        NULL, HFILL}},
        { &hf_bssap_gprs_loc_upd_type,
          { "GPRS location update type", "bssap.gprs_loc_upd_type",
        FT_UINT8, BASE_DEC, VALS(bssap_plus_GPRS_loc_upd_type_values), 0x0,
        NULL, HFILL}},
        { &hf_bssap_Gs_cause,
          { "Gs cause", "bssap.Gs_cause",
        FT_UINT8, BASE_DEC, VALS(bssap_Gs_cause_values), 0x0,
        NULL, HFILL}},
        { &hf_bssap_imei,
          { "IMEI", "bssap.imei",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_imeisv,
          { "IMEISV", "bssap.imeisv",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_imsi,
          { "IMSI", "bssap.imsi",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_bssap_imsi_det_from_gprs_serv_type,
          { "IMSI detach from GPRS service type", "bssap.imsi_det_from_gprs_serv_type",
        FT_UINT8, BASE_DEC, VALS(bssap_Gs_cause_values), 0x0,
        NULL, HFILL}},
        { &hf_bssap_info_req,
          { "Information requested", "bssap.info_req",
        FT_UINT8, BASE_DEC, VALS(bssap_info_req_values), 0x0,
        NULL, HFILL}},
        { &hf_bssap_loc_inf_age,
          { "AgeOfLocationInformation in minutes", "bssap.loc_inf_age",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
        { &hf_bssap_mobile_station_state,
          { "Mobile station state", "bssap.mobile_station_state",
        FT_UINT8, BASE_DEC, VALS(bssap_mobile_station_state_values), 0x0,
        NULL, HFILL}},
        { &hf_bssap_ptmsi,
          { "PTMSI", "bssap.ptmsi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
        { &hf_bssap_tmsi,
          { "TMSI", "bssap.tmsi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
        { &hf_bssap_tmsi_status,
          { "TMSI status", "bssap.tmsi_status",
            FT_BOOLEAN, 8, TFS(&bssap_tmsi_flag), 0x01,
            NULL, HFILL }},
        { &hf_bssap_tom_prot_disc,
          { "TOM Protocol Discriminator", "bssap.Tom_prot_disc",
            FT_UINT8, BASE_DEC, VALS(bssap_tom_prot_disc_values), 0x78,
            NULL, HFILL}},
        { &hf_bssap_e_bit,
          { "E: Cipher Request", "bssap.e_bit",
            FT_BOOLEAN, 8, TFS(&bssap_E_flag), 0x04,
            NULL, HFILL }},
        { &hf_bssap_tunnel_prio,
          { "Tunnel Priority", "bssap.tunnel_prio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
        { &hf_bssap_global_cn_id,
          { "Global CN-Id", "bssap.global_cn_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
        { &hf_bssap_plmn_id,
          { "PLMN-Id", "bssap.plmn_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
        { &hf_bssap_cn_id,
          { "CN-Id", "bssap.cn_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
        { &hf_bssap_cell_global_id,
          { "Cell global identity", "bssap.cell_global_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bssap,
        &ett_bssap_dlci,
        &ett_bssap_imsi,
        &ett_bssap_imsi_det_from_gprs_serv_type,
        &ett_bssap_imsi_det_from_non_gprs_serv_type,
        &ett_bssap_info_req,
        &ett_bssap_loc_area_id,
        &ett_bssap_loc_inf_age,
        &ett_bssap_mm_information,
        &ett_bssap_mobile_id,
        &ett_bssap_sgsn_nr,
        &ett_bssap_tmsi,
        &ett_bssap_tmsi_status,
        &ett_bssap_vlr_number,
        &ett_bssap_global_cn,
        &ett_bssap_gprs_loc_upd,
        &ett_bassp_Gs_cause,
        &ett_bassp_imei,
        &ett_bassp_imesiv,
        &ett_bssap_cell_global_id,
        &ett_bssap_cgi,
        &ett_bssap_channel_needed,
        &ett_bssap_dlink_tnl_pld_cntrl_amd_inf,
        &ett_bssap_ulink_tnl_pld_cntrl_amd_inf,
        &ett_bssap_emlpp_prio,
        &ett_bssap_erroneous_msg,
        &ett_bssap_mobile_stn_cls_mrk1,
        &ett_bssap_mobile_station_state,
        &ett_bssap_ptmsi,
        &ett_bssap_reject_cause,
        &ett_bssap_service_area_id,
        &ett_bssap_global_cn_id,
        &ett_bssap_plmn,
    };

    static enum_val_t gsm_or_lb_interface_options[] = {
        { "gsm a",    "GSM A",    GSM_INTERFACE },
        { "lb",    "Lb",    LB_INTERFACE  },
        { NULL,        NULL,        0 }
    };

    static enum_val_t bssap_or_bsap_options[] = {
        { "bssap",  "BSSAP",    BSSAP },
        { "bsap",   "BSAP",     BSAP  },
        { NULL,     NULL,       0 }
    };


    /* Register the protocol name and description */
    proto_bssap = proto_register_protocol("BSSAP/BSAP", "BSSAP", "bssap");
    /*proto_bssap_plus = proto_register_protocol("BSSAP2", "BSSAP2", "bssap2");*/

    register_dissector("bssap", dissect_bssap, proto_bssap);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bssap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bssap_module = prefs_register_protocol(proto_bssap, proto_reg_handoff_bssap);

    prefs_register_enum_preference(bssap_module,
                       "bsap_or_bssap",
                       "Identify to sub-dissector as",
                       "For the sake of sub-dissectors registering to accept data "
                       "from the BSSAP/BSAP dissector, this defines whether it is "
                       "identified as BSSAP or BSAP.",
                       &bssap_or_bsap_global,
                       bssap_or_bsap_options,
                       ENC_BIG_ENDIAN);

    prefs_register_enum_preference(bssap_module,
                       "gsm_or_lb_interface",
                       "Identify the BSSAP interface",
                       "GSM-A is the interface between the BSC and the MSC. Lb is the interface between the BSC and the SMLC.",
                       &gsm_or_lb_interface_global,
                       gsm_or_lb_interface_options,
                       ENC_BIG_ENDIAN);

    prefs_register_uint_preference(bssap_module, "ssn",
                       "Subsystem number used for BSSAP",
                       "Set Subsystem number used for BSSAP/BSSAP+",
                       10, &global_bssap_ssn);
    bssap_dissector_table = register_dissector_table("bssap.pdu_type", "BSSAP Message Type", FT_UINT8, BASE_DEC);
    bsap_dissector_table = register_dissector_table("bsap.pdu_type", "BSAP Message Type", FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_bssap(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t bssap_plus_handle;
    static guint old_bssap_ssn;

    if (!initialized) {
        heur_dissector_add("sccp", dissect_bssap_heur, proto_bssap);
        heur_dissector_add("sua", dissect_bssap_heur, proto_bssap);
        /* BSSAP+ */
        bssap_plus_handle = create_dissector_handle(dissect_bssap_plus, proto_bssap);

        data_handle = find_dissector("data");
        rrlp_handle = find_dissector("rrlp");
        initialized = TRUE;
    } else {
        dissector_delete_uint("sccp.ssn", old_bssap_ssn, bssap_plus_handle);
    }

    dissector_add_uint("sccp.ssn", global_bssap_ssn, bssap_plus_handle);
    old_bssap_ssn = global_bssap_ssn;
}
