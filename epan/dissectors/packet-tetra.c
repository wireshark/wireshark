/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-tetra.c                                                             */
/* ../../tools/asn2wrs.py -u -p tetra -c ./tetra.cnf -s ./packet-tetra-template -D . -O ../../epan/dissectors tetra.asn */

/* Input file: packet-tetra-template.c */

#line 1 "../../asn1/tetra/packet-tetra-template.c"
/* packet-tetra.c
 * Routines for TETRA packet dissection
 *
 *$Id$
 *
 * Copyright (c) 2007 - 2011 Professional Mobile Communication Research Group,
 *    Beijing Institute of Technology, China
 * Copyright (c) 2011 Holger Hans Peter Freyther
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
 *
 * REF: ETSI EN 300 392-2 V3.2.1
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include <stdio.h>
#include <string.h>

#include <epan/dissectors/packet-per.h>
#include "packet-tetra.h"

#define PROTO_TAG_tetra	"TETRA"

/* Wireshark ID of the tetra protocol */
static int proto_tetra = -1;

/* These are the handles of our subdissectors */
static dissector_handle_t data_handle = NULL;

static dissector_handle_t tetra_handle;
static void dissect_tetra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int global_tetra_port = 7074;

/* Whether the capture data include carrier numbers */
static gboolean include_carrier_number = TRUE;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_tetra()
*/
/** Kts attempt at defining the protocol */
static gint hf_tetra = -1;
static gint hf_tetra_header = -1;
static gint hf_tetra_channels = -1;
static gint hf_tetra_channel1 = -1;
static gint hf_tetra_channel2 = -1;
static gint hf_tetra_channel3 = -1;
static gint hf_tetra_txreg = -1;
static gint hf_tetra_timer = -1;
static gint hf_tetra_pdu = -1;
static gint hf_tetra_rvstr = -1;
static gint hf_tetra_carriernumber = -1;
static gint hf_tetra_rxchannel1 = -1;
static gint hf_tetra_rxchannel2 = -1;
static gint hf_tetra_rxchannel3 = -1;
static gint hf_tetra_crc = -1;
static gint hf_tetra_len0 = -1;


/*--- Included file: packet-tetra-hf.c ---*/
#line 1 "../../asn1/tetra/packet-tetra-hf.c"
static int hf_tetra_AACH_PDU = -1;                /* AACH */
static int hf_tetra_BSCH_PDU = -1;                /* BSCH */
static int hf_tetra_BNCH_PDU = -1;                /* BNCH */
static int hf_tetra_MAC_ACCESS_PDU = -1;          /* MAC_ACCESS */
static int hf_tetra_MAC_FRAG_PDU = -1;            /* MAC_FRAG */
static int hf_tetra_MAC_FRAG120_PDU = -1;         /* MAC_FRAG120 */
static int hf_tetra_MAC_END_UPLINK_PDU = -1;      /* MAC_END_UPLINK */
static int hf_tetra_MAC_END_UP114_PDU = -1;       /* MAC_END_UP114 */
static int hf_tetra_MAC_END_HU_PDU = -1;          /* MAC_END_HU */
static int hf_tetra_MAC_END_DOWNLINK_PDU = -1;    /* MAC_END_DOWNLINK */
static int hf_tetra_MAC_END_DOWN111_PDU = -1;     /* MAC_END_DOWN111 */
static int hf_tetra_MAC_RESOURCE_PDU = -1;        /* MAC_RESOURCE */
static int hf_tetra_MAC_ACCESS_DEFINE_PDU = -1;   /* MAC_ACCESS_DEFINE */
static int hf_tetra_function = -1;                /* INTEGER_0_3 */
static int hf_tetra_field1 = -1;                  /* INTEGER_0_63 */
static int hf_tetra_field2 = -1;                  /* INTEGER_0_63 */
static int hf_tetra_system_code = -1;             /* System_Code */
static int hf_tetra_colour_code = -1;             /* Colour_Code */
static int hf_tetra_timeslot_number = -1;         /* Timeslot_Number */
static int hf_tetra_frame_number = -1;            /* Frame_Number */
static int hf_tetra_multiple_frame_number = -1;   /* Multiple_Frame_Number */
static int hf_tetra_sharing_mod = -1;             /* Sharing_Mod */
static int hf_tetra_ts_reserved_frames = -1;      /* TS_Reserved_Frames */
static int hf_tetra_u_plane_dtx = -1;             /* U_Plane_DTX */
static int hf_tetra_frame_18_extension = -1;      /* Frame_18_Extension */
static int hf_tetra_reserved = -1;                /* Reserved */
static int hf_tetra_tm_sdu = -1;                  /* MLE_Sync */
static int hf_tetra_mcc = -1;                     /* INTEGER_0_1023 */
static int hf_tetra_mnc = -1;                     /* INTEGER_0_16383 */
static int hf_tetra_neighbour_cell_broadcast = -1;  /* INTEGER_0_3 */
static int hf_tetra_cell_service_level = -1;      /* INTEGER_0_3 */
static int hf_tetra_late_entry_information = -1;  /* INTEGER_0_1 */
static int hf_tetra_pdu_type = -1;                /* INTEGER_0_3 */
static int hf_tetra_broadcast_type = -1;          /* INTEGER_0_3 */
static int hf_tetra_main_carrier = -1;            /* INTEGER_0_4095 */
static int hf_tetra_frequency_band = -1;          /* INTEGER_0_15 */
static int hf_tetra_offset = -1;                  /* Offset */
static int hf_tetra_duplex_spacing = -1;          /* INTEGER_0_7 */
static int hf_tetra_reverse_operation = -1;       /* Reverse_Operation */
static int hf_tetra_sencond_ctl_carrier = -1;     /* Sencond_Ctl_Carrier */
static int hf_tetra_ms_txpwr_max_cell = -1;       /* MS_TXPWR_MAX_CELL */
static int hf_tetra_rxlev_access_min = -1;        /* RXLEV_ACCESS_MIN */
static int hf_tetra_access_parameter = -1;        /* ACCESS_PARAMETER */
static int hf_tetra_radio_downlink_timeout = -1;  /* RADIO_DOWNLINK_TIMEOUT */
static int hf_tetra_hyperframe_or_cck = -1;       /* T_hyperframe_or_cck */
static int hf_tetra_hyperframe = -1;              /* INTEGER_0_65535 */
static int hf_tetra_cckid = -1;                   /* INTEGER_0_65535 */
static int hf_tetra_optional_params = -1;         /* T_optional_params */
static int hf_tetra_even_multiframe = -1;         /* TS_COMMON_FRAMES */
static int hf_tetra_odd_multiframe = -1;          /* TS_COMMON_FRAMES */
static int hf_tetra_access_a_code = -1;           /* Default_Code_A */
static int hf_tetra_extend_service = -1;          /* Extended_Services_Broadcast */
static int hf_tetra_la = -1;                      /* INTEGER_0_16383 */
static int hf_tetra_subscriber_class = -1;        /* INTEGER_0_65535 */
static int hf_tetra_registriation = -1;           /* INTEGER_0_1 */
static int hf_tetra_de_registration = -1;         /* INTEGER_0_1 */
static int hf_tetra_priority_cell = -1;           /* INTEGER_0_1 */
static int hf_tetra_minimum_mode_service = -1;    /* INTEGER_0_1 */
static int hf_tetra_migration = -1;               /* INTEGER_0_1 */
static int hf_tetra_system_wide_service = -1;     /* INTEGER_0_1 */
static int hf_tetra_tetra_voice_service = -1;     /* INTEGER_0_1 */
static int hf_tetra_circuit_mode_data_service = -1;  /* INTEGER_0_1 */
static int hf_tetra_reserved_01 = -1;             /* INTEGER_0_1 */
static int hf_tetra_sndcp_service = -1;           /* INTEGER_0_1 */
static int hf_tetra_air_interface_encryption = -1;  /* INTEGER_0_1 */
static int hf_tetra_advanced_link_support = -1;   /* INTEGER_0_1 */
static int hf_tetra_frame1 = -1;                  /* FRAME */
static int hf_tetra_frame2 = -1;                  /* FRAME */
static int hf_tetra_frame3 = -1;                  /* FRAME */
static int hf_tetra_frame4 = -1;                  /* FRAME */
static int hf_tetra_frame5 = -1;                  /* FRAME */
static int hf_tetra_frame6 = -1;                  /* FRAME */
static int hf_tetra_frame7 = -1;                  /* FRAME */
static int hf_tetra_frame8 = -1;                  /* FRAME */
static int hf_tetra_frame9 = -1;                  /* FRAME */
static int hf_tetra_frame10 = -1;                 /* FRAME */
static int hf_tetra_frame11 = -1;                 /* FRAME */
static int hf_tetra_frame12 = -1;                 /* FRAME */
static int hf_tetra_frame13 = -1;                 /* FRAME */
static int hf_tetra_frame14 = -1;                 /* FRAME */
static int hf_tetra_frame15 = -1;                 /* FRAME */
static int hf_tetra_frame16 = -1;                 /* FRAME */
static int hf_tetra_frame17 = -1;                 /* FRAME */
static int hf_tetra_frame18 = -1;                 /* FRAME */
static int hf_tetra_imm = -1;                     /* IMM */
static int hf_tetra_wt = -1;                      /* WT */
static int hf_tetra_nu = -1;                      /* NU */
static int hf_tetra_frame_len_factor = -1;        /* Frame_Len_Factor */
static int hf_tetra_timeslot_pointer = -1;        /* Timeslot_Pointer */
static int hf_tetra_min_pdu_priority = -1;        /* Min_Pdu_Priority */
static int hf_tetra_security_information = -1;    /* INTEGER_0_255 */
static int hf_tetra_sds_tl_addressing_method = -1;  /* SDS_TL_Addressing_Method */
static int hf_tetra_gck_supported = -1;           /* INTEGER_0_1 */
static int hf_tetra_section = -1;                 /* T_section */
static int hf_tetra_present_1 = -1;               /* PRESENT1 */
static int hf_tetra_present_2 = -1;               /* INTEGER_0_127 */
static int hf_tetra_present_3 = -1;               /* INTEGER_0_127 */
static int hf_tetra_present_4 = -1;               /* INTEGER_0_127 */
static int hf_tetra_data_priority_supported = -1;  /* Data_Priority_Supported */
static int hf_tetra_reserved_02 = -1;             /* INTEGER_0_7 */
static int hf_tetra_section_2_information = -1;   /* Section_Information */
static int hf_tetra_section_3_information = -1;   /* Section_Information */
static int hf_tetra_section_4_information = -1;   /* Section_Information */
static int hf_tetra_pdu_type_01 = -1;             /* INTEGER_0_1 */
static int hf_tetra_fill_bit_indication = -1;     /* Fill_Bit_Indication */
static int hf_tetra_encrypted_flag = -1;          /* Encrypted_Flag */
static int hf_tetra_address = -1;                 /* Address */
static int hf_tetra_data = -1;                    /* T_data */
static int hf_tetra_sdu1 = -1;                    /* U_LLC_PDU */
static int hf_tetra_sdu2 = -1;                    /* ComplexSDU */
static int hf_tetra_ssi = -1;                     /* INTEGER_0_16777215 */
static int hf_tetra_eventLabel = -1;              /* INTEGER_0_1023 */
static int hf_tetra_ussi = -1;                    /* INTEGER_0_16777215 */
static int hf_tetra_smi = -1;                     /* INTEGER_0_16777215 */
static int hf_tetra_bl_adata = -1;                /* U_BL_ADATA */
static int hf_tetra_bl_data = -1;                 /* U_BL_DATA */
static int hf_tetra_bl_udata = -1;                /* U_MLE_PDU */
static int hf_tetra_bl_ack = -1;                  /* U_BL_ACK */
static int hf_tetra_bl_adata_fcs = -1;            /* U_BL_ADATA_FCS */
static int hf_tetra_bl_data_fcs = -1;             /* U_BL_DATA_FCS */
static int hf_tetra_bl_udata_fcs = -1;            /* U_MLE_PDU_FCS */
static int hf_tetra_bl_ack_fcs = -1;              /* U_BL_ACK_FCS */
static int hf_tetra_al_setup = -1;                /* NULL */
static int hf_tetra_al_data = -1;                 /* NULL */
static int hf_tetra_al_udata = -1;                /* NULL */
static int hf_tetra_al_ack = -1;                  /* NULL */
static int hf_tetra_al_reconnect = -1;            /* NULL */
static int hf_tetra_reserve1 = -1;                /* NULL */
static int hf_tetra_reserve2 = -1;                /* NULL */
static int hf_tetra_al_disc = -1;                 /* NULL */
static int hf_tetra_nr = -1;                      /* INTEGER_0_1 */
static int hf_tetra_tl_sdu = -1;                  /* U_MLE_PDU */
static int hf_tetra_fcs = -1;                     /* OCTET_STRING_SIZE_4 */
static int hf_tetra_u_mle_pdu = -1;               /* U_MLE_PDU */
static int hf_tetra_ns = -1;                      /* INTEGER_0_1 */
static int hf_tetra_u_mle_reserved1 = -1;         /* NULL */
static int hf_tetra_mm = -1;                      /* U_MM_PDU */
static int hf_tetra_cmce = -1;                    /* U_CMCE_PDU */
static int hf_tetra_u_mle_reserved2 = -1;         /* NULL */
static int hf_tetra_sndcp = -1;                   /* NULL */
static int hf_tetra_mle = -1;                     /* UMLE_PDU */
static int hf_tetra_tetra_management_entity_protocol = -1;  /* NULL */
static int hf_tetra_u_mle_reserved3 = -1;         /* NULL */
static int hf_tetra_lengthIndicationOrCapacityRequest = -1;  /* T_lengthIndicationOrCapacityRequest */
static int hf_tetra_lengthIndication = -1;        /* LengthIndication */
static int hf_tetra_capacityRequest = -1;         /* FRAG */
static int hf_tetra_tm_sdu_01 = -1;               /* U_LLC_PDU */
static int hf_tetra_frag = -1;                    /* Frag1 */
static int hf_tetra_reservation_requirement = -1;  /* SLOT_APPLY */
static int hf_tetra_sub_type = -1;                /* INTEGER_0_1 */
static int hf_tetra_tm_sdu_02 = -1;               /* BIT_STRING_SIZE_264 */
static int hf_tetra_tm_sdu_03 = -1;               /* BIT_STRING_SIZE_120 */
static int hf_tetra_lengthInd_ReservationReq = -1;  /* LengthIndOrReservationReq */
static int hf_tetra_tm_sdu_04 = -1;               /* BIT_STRING_SIZE_258 */
static int hf_tetra_pdu_subtype = -1;             /* INTEGER_0_1 */
static int hf_tetra_tm_sdu_05 = -1;               /* BIT_STRING_SIZE_114 */
static int hf_tetra_lengthInd_ReservationReq_01 = -1;  /* T_lengthInd_ReservationReq */
static int hf_tetra_lengthInd = -1;               /* LengthIndMacHu */
static int hf_tetra_tm_sdu_06 = -1;               /* BIT_STRING_SIZE_85 */
static int hf_tetra_position_of_grant = -1;       /* Position_Of_Grant */
static int hf_tetra_lengthIndication_01 = -1;     /* LengthIndicationMacEndDl */
static int hf_tetra_slot_granting = -1;           /* T_slot_granting */
static int hf_tetra_none = -1;                    /* NULL */
static int hf_tetra_slot_granting_param = -1;     /* SlotGranting */
static int hf_tetra_channel_allocation = -1;      /* T_channel_allocation */
static int hf_tetra_channel_allocation_element = -1;  /* ChannelAllocation */
static int hf_tetra_tm_sdu_07 = -1;               /* BIT_STRING_SIZE_255 */
static int hf_tetra_capacity_allocation = -1;     /* Capacity_Allocation */
static int hf_tetra_granting_delay = -1;          /* Granting_delay */
static int hf_tetra_allocation_type = -1;         /* T_allocation_type */
static int hf_tetra_timeslot_assigned = -1;       /* Timeslot_Assigned */
static int hf_tetra_up_down_assigned = -1;        /* T_up_down_assigned */
static int hf_tetra_clch_permission = -1;         /* CLCH_permission */
static int hf_tetra_cell_change = -1;             /* Cell_change_flag */
static int hf_tetra_carrier_number = -1;          /* INTEGER_0_4095 */
static int hf_tetra_extend_carrier_flag = -1;     /* T_extend_carrier_flag */
static int hf_tetra_extended = -1;                /* Extended_carrier_flag */
static int hf_tetra_monitoring_pattern = -1;      /* T_monitoring_pattern */
static int hf_tetra_one = -1;                     /* Monitoring_pattern */
static int hf_tetra_none1 = -1;                   /* NULL */
static int hf_tetra_none2 = -1;                   /* NULL */
static int hf_tetra_none3 = -1;                   /* NULL */
static int hf_tetra_offset_01 = -1;               /* INTEGER_0_3 */
static int hf_tetra_reverse_operation_01 = -1;    /* T_reverse_operation */
static int hf_tetra_pdu_type_02 = -1;             /* INTEGER_0_7 */
static int hf_tetra_fill_bit_ind = -1;            /* BOOLEAN */
static int hf_tetra_position_of_grant_01 = -1;    /* INTEGER_0_1 */
static int hf_tetra_slot_granting_01 = -1;        /* T_slot_granting_01 */
static int hf_tetra_channel_allocation_01 = -1;   /* T_channel_allocation_01 */
static int hf_tetra_tm_sdu_08 = -1;               /* BIT_STRING_SIZE_111 */
static int hf_tetra_encryption_mode = -1;         /* INTEGER_0_3 */
static int hf_tetra_access_ack = -1;              /* T_access_ack */
static int hf_tetra_lengthIndication_02 = -1;     /* LengthIndicationMacResource */
static int hf_tetra_address_01 = -1;              /* AddressMacResource */
static int hf_tetra_power_control = -1;           /* T_power_control */
static int hf_tetra_powerParameters = -1;         /* PowerControl */
static int hf_tetra_slot_granting_02 = -1;        /* T_slot_granting_02 */
static int hf_tetra_channel_allocation_02 = -1;   /* T_channel_allocation_02 */
static int hf_tetra_tm_sdu_09 = -1;               /* D_LLC_PDU */
static int hf_tetra_null_pdu = -1;                /* NULL */
static int hf_tetra_ssi_01 = -1;                  /* SSI_NEED */
static int hf_tetra_eventLabel_01 = -1;           /* EVENT_NEED */
static int hf_tetra_ussi_01 = -1;                 /* USSI_NEED */
static int hf_tetra_smi_01 = -1;                  /* SMI_NEED */
static int hf_tetra_ssi_eventLabel = -1;          /* SSI_EVENT_NEED */
static int hf_tetra_ssi_usage_maker = -1;         /* SSI_USAGE_NEED */
static int hf_tetra_smi_eventLabel = -1;          /* SMI_EVENT_NEED */
static int hf_tetra_other = -1;                   /* OTHER_DATA */
static int hf_tetra_eventlabel = -1;              /* INTEGER_0_1023 */
static int hf_tetra_ventlabel = -1;               /* INTEGER_0_1023 */
static int hf_tetra_usage_maker = -1;             /* INTEGER_0_63 */
static int hf_tetra_smi_eventlabel = -1;          /* BIT_STRING_SIZE_34 */
static int hf_tetra_broadcast_channel = -1;       /* INTEGER_0_1 */
static int hf_tetra_access_code = -1;             /* INTEGER_0_3 */
static int hf_tetra_imm_01 = -1;                  /* INTEGER_0_15 */
static int hf_tetra_wt_01 = -1;                   /* INTEGER_0_15 */
static int hf_tetra_nu_01 = -1;                   /* INTEGER_0_15 */
static int hf_tetra_frame_len_factor_01 = -1;     /* INTEGER_0_1 */
static int hf_tetra_timeslot_pointer_01 = -1;     /* INTEGER_0_15 */
static int hf_tetra_min_priority = -1;            /* INTEGER_0_7 */
static int hf_tetra_optional_field = -1;          /* T_optional_field */
static int hf_tetra_class_bitmap = -1;            /* INTEGER_0_65535 */
static int hf_tetra_gssi = -1;                    /* INTEGER_0_33554431 */
static int hf_tetra_reserved_03 = -1;             /* NULL */
static int hf_tetra_filler_bits = -1;             /* INTEGER_0_7 */
static int hf_tetra_bl_adata_01 = -1;             /* D_BL_ADATA */
static int hf_tetra_bl_data_01 = -1;              /* D_BL_DATA */
static int hf_tetra_bl_udata_01 = -1;             /* D_MLE_PDU */
static int hf_tetra_bl_ack_01 = -1;               /* D_BL_ACK */
static int hf_tetra_bl_adata_fcs_01 = -1;         /* D_BL_ADATA_FCS */
static int hf_tetra_bl_data_fcs_01 = -1;          /* D_BL_DATA_FCS */
static int hf_tetra_bl_udata_fcs_01 = -1;         /* D_MLE_PDU_FCS */
static int hf_tetra_bl_ack_fcs_01 = -1;           /* D_BL_ACK_FCS */
static int hf_tetra_tl_sdu_01 = -1;               /* D_MLE_PDU */
static int hf_tetra_d_mle_pdu = -1;               /* D_MLE_PDU */
static int hf_tetra_mm_01 = -1;                   /* D_MM_PDU */
static int hf_tetra_cmce_01 = -1;                 /* D_CMCE_PDU */
static int hf_tetra_mle_01 = -1;                  /* DMLE_PDU */
static int hf_tetra_u_prepare = -1;               /* U_PREPARE */
static int hf_tetra_umle_reserved1 = -1;          /* NULL */
static int hf_tetra_umle_reserved2 = -1;          /* NULL */
static int hf_tetra_umle_reserved3 = -1;          /* NULL */
static int hf_tetra_u_restore = -1;               /* U_RESTORE */
static int hf_tetra_umle_reserved4 = -1;          /* NULL */
static int hf_tetra_umle_reserved5 = -1;          /* NULL */
static int hf_tetra_umle_reserved6 = -1;          /* NULL */
static int hf_tetra_d_new_cell = -1;              /* D_NEW_CELL */
static int hf_tetra_d_prepare_fail = -1;          /* D_PREPARE_FAIL */
static int hf_tetra_d_nwrk_broadcast = -1;        /* D_NWRK_BRDADCAST */
static int hf_tetra_dmle_reserved1 = -1;          /* NULL */
static int hf_tetra_d_restore_ack = -1;           /* D_RESTORE_ACK */
static int hf_tetra_d_restore_fail = -1;          /* D_RESTORE_FAIL */
static int hf_tetra_dmle_reserved2 = -1;          /* NULL */
static int hf_tetra_dmle_reserved3 = -1;          /* NULL */
static int hf_tetra_optional_elements = -1;       /* T_optional_elements */
static int hf_tetra_no_type2 = -1;                /* NULL */
static int hf_tetra_type2_parameters = -1;        /* T_type2_parameters */
static int hf_tetra_cell_number = -1;             /* T_cell_number */
static int hf_tetra_cell_number_01 = -1;          /* INTEGER_0_65535 */
static int hf_tetra_sdu = -1;                     /* BIT_STRING */
static int hf_tetra_optional_elements_01 = -1;    /* T_optional_elements_01 */
static int hf_tetra_type2_parameters_01 = -1;     /* T_type2_parameters_01 */
static int hf_tetra_mcc_01 = -1;                  /* T_mcc */
static int hf_tetra_mnc_01 = -1;                  /* T_mnc */
static int hf_tetra_la_01 = -1;                   /* T_la */
static int hf_tetra_channel_command_valid = -1;   /* INTEGER_0_3 */
static int hf_tetra_optional_elements_02 = -1;    /* T_optional_elements_02 */
static int hf_tetra_fail_cause = -1;              /* INTEGER_0_3 */
static int hf_tetra_optional_elements_03 = -1;    /* T_optional_elements_03 */
static int hf_tetra_cell_re_select_parameters = -1;  /* INTEGER_0_65535 */
static int hf_tetra_optional_elements_04 = -1;    /* T_optional_elements_04 */
static int hf_tetra_type2_parameters_02 = -1;     /* T_type2_parameters_02 */
static int hf_tetra_tetra_network_time = -1;      /* T_tetra_network_time */
static int hf_tetra_tetra_network_time_01 = -1;   /* TETRA_NETWORK_TIME */
static int hf_tetra_number_of_neighbour_cells = -1;  /* T_number_of_neighbour_cells */
static int hf_tetra_number_of_neighbour_cells_01 = -1;  /* INTEGER_0_7 */
static int hf_tetra_network_time = -1;            /* T_network_time */
static int hf_tetra_local_time_offset_sign = -1;  /* INTEGER_0_1 */
static int hf_tetra_local_time_offset = -1;       /* INTEGER_0_63 */
static int hf_tetra_year = -1;                    /* INTEGER_0_63 */
static int hf_tetra_reserved_04 = -1;             /* T_reserved */
static int hf_tetra_u_Authentication = -1;        /* NULL */
static int hf_tetra_u_Itsi_Detach = -1;           /* NULL */
static int hf_tetra_u_Location_Update_Demand = -1;  /* U_LOCATION_UPDATE_DEMAND */
static int hf_tetra_u_MM_Status = -1;             /* U_MM_STATUS */
static int hf_tetra_u_MM_reserved1 = -1;          /* NULL */
static int hf_tetra_u_WK = -1;                    /* NULL */
static int hf_tetra_u_MM_reserved3 = -1;          /* NULL */
static int hf_tetra_u_Attach_Detach_Group_Identity = -1;  /* U_ATTACH_DETACH_GROUP_IDENTITY */
static int hf_tetra_u_Attach_Detach_Group_Identity_Ack = -1;  /* U_ATTACH_DETACH_GROUP_IDENTITY_ACK */
static int hf_tetra_u_TEI_Provide = -1;           /* NULL */
static int hf_tetra_u_MM_reserved6 = -1;          /* NULL */
static int hf_tetra_u_Disabled_Status = -1;       /* NULL */
static int hf_tetra_u_MM_reserved7 = -1;          /* NULL */
static int hf_tetra_u_MM_reserved8 = -1;          /* NULL */
static int hf_tetra_u_MM_reserved9 = -1;          /* NULL */
static int hf_tetra_u_MM_Function_Not_Support = -1;  /* NULL */
static int hf_tetra_d_Otar = -1;                  /* NULL */
static int hf_tetra_d_Authentication = -1;        /* NULL */
static int hf_tetra_d_Authentication_Reject = -1;  /* NULL */
static int hf_tetra_d_Disable = -1;               /* NULL */
static int hf_tetra_d_Enable = -1;                /* NULL */
static int hf_tetra_d_Location_Update_Accept = -1;  /* D_LOCATION_UPDATE_ACCEPT */
static int hf_tetra_d_Location_Update_Command = -1;  /* NULL */
static int hf_tetra_d_Location_Update_Reject = -1;  /* D_LOCATION_UPDATE_REJECT */
static int hf_tetra_d_MM_reserved2 = -1;          /* NULL */
static int hf_tetra_d_Location_Update_Proceeding = -1;  /* NULL */
static int hf_tetra_d_Attach_Detach_Group_Identity = -1;  /* D_ATTACH_DETACH_GROUP_IDENTITY */
static int hf_tetra_d_Attach_Detach_Group_Identity_Ack = -1;  /* D_ATTACH_DETACH_GROUP_IDENTITY_ACK */
static int hf_tetra_d_MM_Status = -1;             /* D_MM_STATUS */
static int hf_tetra_d_MM_reserved5 = -1;          /* NULL */
static int hf_tetra_d_MM_reserved6 = -1;          /* NULL */
static int hf_tetra_d_MM_Function_Not_Support = -1;  /* NULL */
static int hf_tetra_attach_detach_identifiet = -1;  /* T_attach_detach_identifiet */
static int hf_tetra_attach = -1;                  /* T_attach */
static int hf_tetra_lifetime = -1;                /* INTEGER_0_3 */
static int hf_tetra_class_of_usage = -1;          /* INTEGER_0_7 */
static int hf_tetra_detach = -1;                  /* T_detach */
static int hf_tetra_detach_downlike = -1;         /* T_detach_downlike */
static int hf_tetra_address_type = -1;            /* T_address_type */
static int hf_tetra_gssi_01 = -1;                 /* OCTET_STRING_SIZE_3 */
static int hf_tetra_gssi_extension = -1;          /* T_gssi_extension */
static int hf_tetra_extension = -1;               /* OCTET_STRING_SIZE_3 */
static int hf_tetra_vgssi = -1;                   /* OCTET_STRING_SIZE_3 */
static int hf_tetra_attach_detach_identifiet_01 = -1;  /* T_attach_detach_identifiet_01 */
static int hf_tetra_attach_01 = -1;               /* T_attach_01 */
static int hf_tetra_detach_01 = -1;               /* T_detach_01 */
static int hf_tetra_detach_uplike = -1;           /* T_detach_uplike */
static int hf_tetra_address_type_01 = -1;         /* T_address_type_01 */
static int hf_tetra_gssi_extension_01 = -1;       /* T_gssi_extension_01 */
static int hf_tetra_location_update_type = -1;    /* UPDATE_TYPE */
static int hf_tetra_optional_elements_05 = -1;    /* T_optional_elements_05 */
static int hf_tetra_type2_parameters_03 = -1;     /* T_type2_parameters_03 */
static int hf_tetra_ssi_02 = -1;                  /* T_ssi */
static int hf_tetra_ssi_03 = -1;                  /* OCTET_STRING_SIZE_3 */
static int hf_tetra_address_extension = -1;       /* T_address_extension */
static int hf_tetra_address_extension_01 = -1;    /* OCTET_STRING_SIZE_3 */
static int hf_tetra_suscriber_class = -1;         /* T_suscriber_class */
static int hf_tetra_suscriber_class_01 = -1;      /* INTEGER_0_32767 */
static int hf_tetra_energy_saving_mode = -1;      /* T_energy_saving_mode */
static int hf_tetra_energy_saving_mode_01 = -1;   /* INTEGER_0_7 */
static int hf_tetra_scch_info = -1;               /* T_scch_info */
static int hf_tetra_scch_info_01 = -1;            /* INTEGER_0_16383 */
static int hf_tetra_type3 = -1;                   /* T_type3 */
static int hf_tetra_no_type3 = -1;                /* NULL */
static int hf_tetra_type3_elements = -1;          /* T_type3_elements */
static int hf_tetra_type2_existance = -1;         /* BOOLEAN */
static int hf_tetra_type3_identifier = -1;        /* TYPE3_IDENTIFIER */
static int hf_tetra_new_ra = -1;                  /* T_new_ra */
static int hf_tetra_new_ra_01 = -1;               /* INTEGER_0_3 */
static int hf_tetra_group_identity_location_accept = -1;  /* T_group_identity_location_accept */
static int hf_tetra_group_identity_location_accept_01 = -1;  /* INTEGER_0_3 */
static int hf_tetra_group_predefined_lifetime = -1;  /* T_group_predefined_lifetime */
static int hf_tetra_group_predefined_lifetime_01 = -1;  /* INTEGER_0_3 */
static int hf_tetra_group_identity_downlink = -1;  /* T_group_identity_downlink */
static int hf_tetra_group_identity_downlink_01 = -1;  /* INTEGER_0_15 */
static int hf_tetra_proprietary = -1;             /* T_proprietary */
static int hf_tetra_proprietary_01 = -1;          /* INTEGER_0_7 */
static int hf_tetra_reject_cause = -1;            /* INTEGER_0_31 */
static int hf_tetra_cipher_control = -1;          /* BOOLEAN */
static int hf_tetra_status_uplink = -1;           /* INTEGER_0_63 */
static int hf_tetra_scanning_on_off = -1;         /* T_scanning_on_off */
static int hf_tetra_status_downlink = -1;         /* INTEGER_0_63 */
static int hf_tetra_u_Alert = -1;                 /* U_ALERT */
static int hf_tetra_reserved1 = -1;               /* NULL */
static int hf_tetra_u_Connect = -1;               /* U_CONNECT */
static int hf_tetra_reserved2 = -1;               /* NULL */
static int hf_tetra_u_Disconnect = -1;            /* U_DISCONNECT */
static int hf_tetra_u_Info = -1;                  /* U_INFO */
static int hf_tetra_u_Release = -1;               /* U_RELEASE */
static int hf_tetra_u_Setup = -1;                 /* U_SETUP */
static int hf_tetra_u_Status = -1;                /* U_STATUS */
static int hf_tetra_u_Tx_Ceased = -1;             /* U_TX_CEASED */
static int hf_tetra_u_Tx_Demand = -1;             /* U_TX_DEMAND */
static int hf_tetra_reserved3 = -1;               /* NULL */
static int hf_tetra_reserved4 = -1;               /* NULL */
static int hf_tetra_reserved5 = -1;               /* NULL */
static int hf_tetra_u_Call_Restore = -1;          /* U_CALL_RESTORE */
static int hf_tetra_u_SDS_Data = -1;              /* U_SDS_DATA */
static int hf_tetra_u_Facility = -1;              /* NULL */
static int hf_tetra_call_identifier = -1;         /* INTEGER_0_16383 */
static int hf_tetra_disconnect_cause = -1;        /* INTEGER_0_31 */
static int hf_tetra_area_selection = -1;          /* INTEGER_0_15 */
static int hf_tetra_called_party_type_identifier = -1;  /* T_called_party_type_identifier */
static int hf_tetra_sna = -1;                     /* INTEGER_0_255 */
static int hf_tetra_ssi_extension = -1;           /* BIT_STRING_SIZE_48 */
static int hf_tetra_short_data_type_identifier = -1;  /* T_short_data_type_identifier */
static int hf_tetra_data_1 = -1;                  /* INTEGER_0_65535 */
static int hf_tetra_data_2 = -1;                  /* OCTET_STRING_SIZE_4 */
static int hf_tetra_data_3 = -1;                  /* BIT_STRING_SIZE_64 */
static int hf_tetra_length_indicator_data_4 = -1;  /* INTEGER_0_4194304 */
static int hf_tetra_called_party_type_identifier_01 = -1;  /* T_called_party_type_identifier_01 */
static int hf_tetra_short_number_address = -1;    /* INTEGER_0_255 */
static int hf_tetra_called_ssi_called_extension = -1;  /* BIT_STRING_SIZE_48 */
static int hf_tetra_pre_coded_status = -1;        /* INTEGER_0_65535 */
static int hf_tetra_call_id = -1;                 /* INTEGER_0_16383 */
static int hf_tetra_poll_response = -1;           /* INTEGER_0_1 */
static int hf_tetra_d_Alert = -1;                 /* D_ALERT */
static int hf_tetra_d_Call_Proceeding = -1;       /* D_CALL_PROCEEDING */
static int hf_tetra_d_Connect = -1;               /* D_CONNECT */
static int hf_tetra_d_Connect_Ack = -1;           /* D_CONNECT_ACK */
static int hf_tetra_d_Disconnect = -1;            /* D_DISCONNECT */
static int hf_tetra_d_Info = -1;                  /* D_INFO */
static int hf_tetra_d_Release = -1;               /* D_RELEASE */
static int hf_tetra_d_Setup = -1;                 /* D_SETUP */
static int hf_tetra_d_Status = -1;                /* D_STATUS */
static int hf_tetra_d_Tx_Ceased = -1;             /* D_TX_CEASED */
static int hf_tetra_d_Tx_Continue = -1;           /* D_TX_CONTINUE */
static int hf_tetra_d_Tx_Granted = -1;            /* D_TX_GRANTED */
static int hf_tetra_d_Tx_Wait = -1;               /* D_TX_WAIT */
static int hf_tetra_d_Tx_Interrupt = -1;          /* NULL */
static int hf_tetra_d_Call_Restore = -1;          /* D_CALL_RESTORE */
static int hf_tetra_d_SDS_Data = -1;              /* D_SDS_DATA */
static int hf_tetra_d_Facility = -1;              /* NULL */
static int hf_tetra_calling_party_type_identifier = -1;  /* T_calling_party_type_identifier */
static int hf_tetra_ssi_extension_01 = -1;        /* OCTET_STRING_SIZE_6 */
static int hf_tetra_short_data_type_identifier_01 = -1;  /* T_short_data_type_identifier_01 */
static int hf_tetra_data_3_01 = -1;               /* OCTET_STRING_SIZE_8 */
static int hf_tetra_calling_party_type_identifier_01 = -1;  /* T_calling_party_type_identifier_01 */
static int hf_tetra_calling_party_address_SSI = -1;  /* INTEGER_0_16777215 */
static int hf_tetra_reset_call_time_out_timer = -1;  /* INTEGER_0_1 */
static int hf_tetra_poll_request = -1;            /* INTEGER_0_1 */
static int hf_tetra_transmission_request_permission = -1;  /* INTEGER_0_1 */
static int hf_tetra_continue = -1;                /* INTEGER_0_1 */
static int hf_tetra_request_to_append_LA = -1;    /* BOOLEAN */
static int hf_tetra_cipher_control_01 = -1;       /* T_cipher_control */
static int hf_tetra_no_cipher = -1;               /* NULL */
static int hf_tetra_ciphering_parameters = -1;    /* INTEGER_0_1023 */
static int hf_tetra_class_of_MS = -1;             /* OCTET_STRING_SIZE_4 */
static int hf_tetra_optional_elements_06 = -1;    /* T_optional_elements_06 */
static int hf_tetra_type2_parameters_04 = -1;     /* T_type2_parameters_04 */
static int hf_tetra_energy_saving_mode_02 = -1;   /* T_energy_saving_mode_01 */
static int hf_tetra_la_information = -1;          /* T_la_information */
static int hf_tetra_la_information_01 = -1;       /* INTEGER_0_16383 */
static int hf_tetra_ssi_04 = -1;                  /* T_ssi_01 */
static int hf_tetra_address_extension_02 = -1;    /* T_address_extension_01 */
static int hf_tetra_type3_01 = -1;                /* T_type3_01 */
static int hf_tetra_type3_elements_01 = -1;       /* T_type3_elements_01 */
static int hf_tetra_group_identity_location_demand = -1;  /* T_group_identity_location_demand */
static int hf_tetra_group_identity_location_demand_01 = -1;  /* INTEGER_0_3 */
static int hf_tetra_group_report_response = -1;   /* T_group_report_response */
static int hf_tetra_group_report_response_01 = -1;  /* BOOLEAN */
static int hf_tetra_group_identity_uplink = -1;   /* T_group_identity_uplink */
static int hf_tetra_group_identity_uplink_01 = -1;  /* INTEGER_0_15 */
static int hf_tetra_proprietary_02 = -1;          /* T_proprietary_01 */
static int hf_tetra_group_identity_report = -1;   /* BOOLEAN */
static int hf_tetra_group_identity_attach_detach_mode = -1;  /* BOOLEAN */
static int hf_tetra_optional_elements_07 = -1;    /* T_optional_elements_07 */
static int hf_tetra_type2_element = -1;           /* T_type2_element */
static int hf_tetra_type3_02 = -1;                /* T_type3_02 */
static int hf_tetra_type3_elements_02 = -1;       /* T_type3_elements_02 */
static int hf_tetra_length = -1;                  /* INTEGER_0_2047 */
static int hf_tetra_repeat_num = -1;              /* INTEGER_0_63 */
static int hf_tetra_group_identity_uplink_02 = -1;  /* GROUP_IDENTITY_UPLINK */
static int hf_tetra_group_identity_ack_type = -1;  /* BOOLEAN */
static int hf_tetra_optional_elements_08 = -1;    /* T_optional_elements_08 */
static int hf_tetra_type2_element_01 = -1;        /* T_type2_element_01 */
static int hf_tetra_type3_03 = -1;                /* T_type3_03 */
static int hf_tetra_type3_elements_03 = -1;       /* T_type3_elements_03 */
static int hf_tetra_hook_method_selection = -1;   /* BOOLEAN */
static int hf_tetra_simple_duplex_selection = -1;  /* T_simple_duplex_selection */
static int hf_tetra_basic_service_information = -1;  /* Basic_service_information */
static int hf_tetra_request_transmit_send_data = -1;  /* INTEGER_0_1 */
static int hf_tetra_call_priority = -1;           /* INTEGER_0_15 */
static int hf_tetra_clir_control = -1;            /* INTEGER_0_3 */
static int hf_tetra_called_party_address = -1;    /* Called_party_address_type */
static int hf_tetra_optional_elements_09 = -1;    /* T_optional_elements_09 */
static int hf_tetra_type2_parameters_05 = -1;     /* T_type2_parameters_05 */
static int hf_tetra_external_subscriber_number = -1;  /* T_external_subscriber_number */
static int hf_tetra_external_subscriber_number_01 = -1;  /* INTEGER_0_31 */
static int hf_tetra_prop = -1;                    /* T_prop */
static int hf_tetra_prop_01 = -1;                 /* Proprietary */
static int hf_tetra_circuit_mode = -1;            /* CIRCUIT */
static int hf_tetra_encryption = -1;              /* INTEGER_0_1 */
static int hf_tetra_communication = -1;           /* INTEGER_0_3 */
static int hf_tetra_slots_or_speech = -1;         /* INTEGER_0_3 */
static int hf_tetra_call_identifier_01 = -1;      /* INTEGER_0_1023 */
static int hf_tetra_simplex_duplex_selection = -1;  /* T_simplex_duplex_selection */
static int hf_tetra_optional_elements_10 = -1;    /* T_optional_elements_10 */
static int hf_tetra_type2_parameters_06 = -1;     /* T_type2_parameters_06 */
static int hf_tetra_basic_service_information_01 = -1;  /* T_basic_service_information */
static int hf_tetra_prop_02 = -1;                 /* T_prop_01 */
static int hf_tetra_simplex_duplex_selection_01 = -1;  /* T_simplex_duplex_selection_01 */
static int hf_tetra_optional_elements_11 = -1;    /* T_optional_elements_11 */
static int hf_tetra_type2_parameters_07 = -1;     /* T_type2_parameters_07 */
static int hf_tetra_basic_service_information_02 = -1;  /* T_basic_service_information_01 */
static int hf_tetra_prop_03 = -1;                 /* T_prop_02 */
static int hf_tetra_optional_elements_12 = -1;    /* T_optional_elements_12 */
static int hf_tetra_type2_parameters_08 = -1;     /* T_type2_parameters_08 */
static int hf_tetra_prop_04 = -1;                 /* T_prop_03 */
static int hf_tetra_tx_demand_priority = -1;      /* INTEGER_0_3 */
static int hf_tetra_encryption_control = -1;      /* INTEGER_0_1 */
static int hf_tetra_optional_elements_13 = -1;    /* T_optional_elements_13 */
static int hf_tetra_type2_parameters_09 = -1;     /* T_type2_parameters_09 */
static int hf_tetra_prop_05 = -1;                 /* T_prop_04 */
static int hf_tetra_optional_elements_14 = -1;    /* T_optional_elements_14 */
static int hf_tetra_type2_parameters_10 = -1;     /* T_type2_parameters_10 */
static int hf_tetra_prop_06 = -1;                 /* T_prop_05 */
static int hf_tetra_request_to_transmit_send_data = -1;  /* INTEGER_0_1 */
static int hf_tetra_other_party_address = -1;     /* Other_party_address_type */
static int hf_tetra_optional_elements_15 = -1;    /* T_optional_elements_15 */
static int hf_tetra_type2_parameters_11 = -1;     /* T_type2_parameters_11 */
static int hf_tetra_prop_07 = -1;                 /* T_prop_06 */
static int hf_tetra_call_time_out = -1;           /* INTEGER_0_15 */
static int hf_tetra_hook_method_selection_01 = -1;  /* INTEGER_0_1 */
static int hf_tetra_simplex_duplex_selection_02 = -1;  /* T_simplex_duplex_selection_02 */
static int hf_tetra_transmission_grant = -1;      /* INTEGER_0_3 */
static int hf_tetra_optional_elements_16 = -1;    /* T_optional_elements_16 */
static int hf_tetra_type2_parameters_12 = -1;     /* T_type2_parameters_12 */
static int hf_tetra_calling_party_address = -1;   /* T_calling_party_address */
static int hf_tetra_calling_party_address_01 = -1;  /* Calling_party_address_type */
static int hf_tetra_external_subscriber_number_02 = -1;  /* T_external_subscriber_number_01 */
static int hf_tetra_external_subscriber_number_03 = -1;  /* INTEGER_0_15 */
static int hf_tetra_prop_08 = -1;                 /* T_prop_07 */
static int hf_tetra_call_time_out_setup_phase = -1;  /* INTEGER_0_7 */
static int hf_tetra_simplex_duplex_selection_03 = -1;  /* INTEGER_0_1 */
static int hf_tetra_optional_elements_17 = -1;    /* T_optional_elements_17 */
static int hf_tetra_type2_parameters_13 = -1;     /* T_type2_parameters_13 */
static int hf_tetra_basic_service_information_03 = -1;  /* T_basic_service_information_02 */
static int hf_tetra_call_status = -1;             /* T_call_status */
static int hf_tetra_call_status_01 = -1;          /* INTEGER_0_7 */
static int hf_tetra_notification_indicator = -1;  /* T_notification_indicator */
static int hf_tetra_notification_indicator_01 = -1;  /* INTEGER_0_63 */
static int hf_tetra_prop_09 = -1;                 /* T_prop_08 */
static int hf_tetra_simplex_duplex_selection_04 = -1;  /* T_simplex_duplex_selection_03 */
static int hf_tetra_call_queued = -1;             /* BOOLEAN */
static int hf_tetra_optional_elements_18 = -1;    /* T_optional_elements_18 */
static int hf_tetra_type2_parameters_14 = -1;     /* T_type2_parameters_14 */
static int hf_tetra_basic_service_infomation = -1;  /* T_basic_service_infomation */
static int hf_tetra_basic_service_infomation_01 = -1;  /* Basic_service_information */
static int hf_tetra_notification_indicator_02 = -1;  /* T_notification_indicator_01 */
static int hf_tetra_prop_10 = -1;                 /* T_prop_09 */
static int hf_tetra_call_time_out_01 = -1;        /* INTEGER_0_31 */
static int hf_tetra_simplex_duplex_selection_05 = -1;  /* T_simplex_duplex_selection_04 */
static int hf_tetra_call_ownership = -1;          /* INTEGER_0_1 */
static int hf_tetra_optional_elements_19 = -1;    /* T_optional_elements_19 */
static int hf_tetra_type2_parameters_15 = -1;     /* T_type2_parameters_15 */
static int hf_tetra_call_priority_01 = -1;        /* T_call_priority */
static int hf_tetra_call_priority_02 = -1;        /* INTEGER_0_31 */
static int hf_tetra_basic_service_information_04 = -1;  /* T_basic_service_information_03 */
static int hf_tetra_temporary_address = -1;       /* T_temporary_address */
static int hf_tetra_temporary_address_01 = -1;    /* Calling_party_address_type */
static int hf_tetra_notification_indicator_03 = -1;  /* T_notification_indicator_02 */
static int hf_tetra_prop_11 = -1;                 /* T_prop_10 */
static int hf_tetra_optional_elements_20 = -1;    /* T_optional_elements_20 */
static int hf_tetra_type2_parameters_16 = -1;     /* T_type2_parameters_16 */
static int hf_tetra_notification_indicator_04 = -1;  /* T_notification_indicator_03 */
static int hf_tetra_prop_12 = -1;                 /* T_prop_11 */
static int hf_tetra_optional_elements_21 = -1;    /* T_optional_elements_21 */
static int hf_tetra_type2_parameters_17 = -1;     /* T_type2_parameters_17 */
static int hf_tetra_notification_indicator_05 = -1;  /* T_notification_indicator_04 */
static int hf_tetra_prop_13 = -1;                 /* T_prop_12 */
static int hf_tetra_reset_call_time_out = -1;     /* INTEGER_0_1 */
static int hf_tetra_optional_elements_22 = -1;    /* T_optional_elements_22 */
static int hf_tetra_type2_parameters_18 = -1;     /* T_type2_parameters_18 */
static int hf_tetra_new_call_identifier = -1;     /* T_new_call_identifier */
static int hf_tetra_new_call_identifier_01 = -1;  /* INTEGER_0_1023 */
static int hf_tetra_call_time_out_02 = -1;        /* T_call_time_out */
static int hf_tetra_call_time_out_03 = -1;        /* INTEGER_0_7 */
static int hf_tetra_call_status_02 = -1;          /* T_call_status_01 */
static int hf_tetra_modify = -1;                  /* T_modify */
static int hf_tetra_modify_01 = -1;               /* Modify_type */
static int hf_tetra_notification_indicator_06 = -1;  /* T_notification_indicator_05 */
static int hf_tetra_prop_14 = -1;                 /* T_prop_13 */
static int hf_tetra_optional_elements_23 = -1;    /* T_optional_elements_23 */
static int hf_tetra_type2_parameters_19 = -1;     /* T_type2_parameters_19 */
static int hf_tetra_notification_indicator_07 = -1;  /* T_notification_indicator_06 */
static int hf_tetra_prop_15 = -1;                 /* T_prop_14 */
static int hf_tetra_group_identity_ack_request = -1;  /* BOOLEAN */
static int hf_tetra_optional_elements_24 = -1;    /* T_optional_elements_24 */
static int hf_tetra_type2_element_02 = -1;        /* T_type2_element_02 */
static int hf_tetra_type3_04 = -1;                /* T_type3_04 */
static int hf_tetra_type3_elements_04 = -1;       /* T_type3_elements_04 */
static int hf_tetra_group_identity_downlink_02 = -1;  /* GROUP_IDENTITY_DOWNLINK */
static int hf_tetra_group_identity_attach_detach_accept = -1;  /* BOOLEAN */
static int hf_tetra_optional_elements_25 = -1;    /* T_optional_elements_25 */
static int hf_tetra_type2_element_03 = -1;        /* T_type2_element_03 */
static int hf_tetra_type3_05 = -1;                /* T_type3_05 */
static int hf_tetra_type3_elements_05 = -1;       /* T_type3_elements_05 */
static int hf_tetra_called_party_sna = -1;        /* INTEGER_0_255 */
static int hf_tetra_called_party_ssi = -1;        /* INTEGER_0_16777215 */
static int hf_tetra_called_party_ssi_extention = -1;  /* T_called_party_ssi_extention */
static int hf_tetra_called_party_extention = -1;  /* INTEGER_0_16777215 */
static int hf_tetra_data_01 = -1;                 /* T_data_01 */
static int hf_tetra_element1 = -1;                /* Type1 */
static int hf_tetra_element = -1;                 /* Type2 */
static int hf_tetra_proprietary_element_owner = -1;  /* Proprietary_element_owner */
static int hf_tetra_proprietary_element_owner_extension = -1;  /* BIT_STRING */
static int hf_tetra_simplex_duplex_selection_06 = -1;  /* T_simplex_duplex_selection_05 */

/*--- End of included file: packet-tetra-hf.c ---*/
#line 86 "../../asn1/tetra/packet-tetra-template.c"

/* Initialize the subtree pointers */
/* These are the ids of the subtrees that we may be creating */
static gint ett_tetra = -1;
static gint ett_tetra_header = -1;
static gint ett_tetra_length = -1;
static gint ett_tetra_txreg = -1;
static gint ett_tetra_text = -1;


/*--- Included file: packet-tetra-ett.c ---*/
#line 1 "../../asn1/tetra/packet-tetra-ett.c"
static gint ett_tetra_AACH = -1;
static gint ett_tetra_BSCH = -1;
static gint ett_tetra_MLE_Sync = -1;
static gint ett_tetra_BNCH = -1;
static gint ett_tetra_T_hyperframe_or_cck = -1;
static gint ett_tetra_T_optional_params = -1;
static gint ett_tetra_TS_COMMON_FRAMES = -1;
static gint ett_tetra_Default_Code_A = -1;
static gint ett_tetra_Extended_Services_Broadcast = -1;
static gint ett_tetra_T_section = -1;
static gint ett_tetra_PRESENT1 = -1;
static gint ett_tetra_MAC_ACCESS = -1;
static gint ett_tetra_T_data = -1;
static gint ett_tetra_Address = -1;
static gint ett_tetra_U_LLC_PDU = -1;
static gint ett_tetra_U_BL_ACK_FCS = -1;
static gint ett_tetra_U_MLE_PDU_FCS = -1;
static gint ett_tetra_U_BL_DATA_FCS = -1;
static gint ett_tetra_U_BL_ADATA_FCS = -1;
static gint ett_tetra_U_MLE_PDU = -1;
static gint ett_tetra_ComplexSDU = -1;
static gint ett_tetra_T_lengthIndicationOrCapacityRequest = -1;
static gint ett_tetra_FRAG = -1;
static gint ett_tetra_MAC_FRAG = -1;
static gint ett_tetra_MAC_FRAG120 = -1;
static gint ett_tetra_MAC_END_UPLINK = -1;
static gint ett_tetra_MAC_END_UP114 = -1;
static gint ett_tetra_MAC_END_HU = -1;
static gint ett_tetra_T_lengthInd_ReservationReq = -1;
static gint ett_tetra_MAC_END_DOWNLINK = -1;
static gint ett_tetra_T_slot_granting = -1;
static gint ett_tetra_T_channel_allocation = -1;
static gint ett_tetra_SlotGranting = -1;
static gint ett_tetra_ChannelAllocation = -1;
static gint ett_tetra_T_extend_carrier_flag = -1;
static gint ett_tetra_T_monitoring_pattern = -1;
static gint ett_tetra_Extended_carrier_flag = -1;
static gint ett_tetra_MAC_END_DOWN111 = -1;
static gint ett_tetra_T_slot_granting_01 = -1;
static gint ett_tetra_T_channel_allocation_01 = -1;
static gint ett_tetra_MAC_RESOURCE = -1;
static gint ett_tetra_OTHER_DATA = -1;
static gint ett_tetra_T_power_control = -1;
static gint ett_tetra_T_slot_granting_02 = -1;
static gint ett_tetra_T_channel_allocation_02 = -1;
static gint ett_tetra_AddressMacResource = -1;
static gint ett_tetra_SSI_NEED = -1;
static gint ett_tetra_EVENT_NEED = -1;
static gint ett_tetra_USSI_NEED = -1;
static gint ett_tetra_SMI_NEED = -1;
static gint ett_tetra_SSI_EVENT_NEED = -1;
static gint ett_tetra_SSI_USAGE_NEED = -1;
static gint ett_tetra_SMI_EVENT_NEED = -1;
static gint ett_tetra_MAC_ACCESS_DEFINE = -1;
static gint ett_tetra_T_optional_field = -1;
static gint ett_tetra_D_LLC_PDU = -1;
static gint ett_tetra_D_BL_ACK_FCS = -1;
static gint ett_tetra_D_MLE_PDU_FCS = -1;
static gint ett_tetra_D_BL_ADATA_FCS = -1;
static gint ett_tetra_D_BL_DATA_FCS = -1;
static gint ett_tetra_U_BL_ACK = -1;
static gint ett_tetra_D_BL_ACK = -1;
static gint ett_tetra_U_BL_DATA = -1;
static gint ett_tetra_D_BL_DATA = -1;
static gint ett_tetra_U_BL_ADATA = -1;
static gint ett_tetra_D_BL_ADATA = -1;
static gint ett_tetra_D_MLE_PDU = -1;
static gint ett_tetra_UMLE_PDU = -1;
static gint ett_tetra_DMLE_PDU = -1;
static gint ett_tetra_U_PREPARE = -1;
static gint ett_tetra_T_optional_elements = -1;
static gint ett_tetra_T_type2_parameters = -1;
static gint ett_tetra_T_cell_number = -1;
static gint ett_tetra_U_RESTORE = -1;
static gint ett_tetra_T_optional_elements_01 = -1;
static gint ett_tetra_T_type2_parameters_01 = -1;
static gint ett_tetra_T_mcc = -1;
static gint ett_tetra_T_mnc = -1;
static gint ett_tetra_T_la = -1;
static gint ett_tetra_D_NEW_CELL = -1;
static gint ett_tetra_T_optional_elements_02 = -1;
static gint ett_tetra_D_PREPARE_FAIL = -1;
static gint ett_tetra_T_optional_elements_03 = -1;
static gint ett_tetra_D_NWRK_BRDADCAST = -1;
static gint ett_tetra_T_optional_elements_04 = -1;
static gint ett_tetra_T_type2_parameters_02 = -1;
static gint ett_tetra_T_tetra_network_time = -1;
static gint ett_tetra_T_number_of_neighbour_cells = -1;
static gint ett_tetra_TETRA_NETWORK_TIME = -1;
static gint ett_tetra_D_RESTORE_ACK = -1;
static gint ett_tetra_D_RESTORE_FAIL = -1;
static gint ett_tetra_U_MM_PDU = -1;
static gint ett_tetra_D_MM_PDU = -1;
static gint ett_tetra_GROUP_IDENTITY_DOWNLINK = -1;
static gint ett_tetra_T_attach_detach_identifiet = -1;
static gint ett_tetra_T_attach = -1;
static gint ett_tetra_T_detach = -1;
static gint ett_tetra_T_address_type = -1;
static gint ett_tetra_T_gssi_extension = -1;
static gint ett_tetra_GROUP_IDENTITY_UPLINK = -1;
static gint ett_tetra_T_attach_detach_identifiet_01 = -1;
static gint ett_tetra_T_attach_01 = -1;
static gint ett_tetra_T_detach_01 = -1;
static gint ett_tetra_T_address_type_01 = -1;
static gint ett_tetra_T_gssi_extension_01 = -1;
static gint ett_tetra_D_LOCATION_UPDATE_ACCEPT = -1;
static gint ett_tetra_T_optional_elements_05 = -1;
static gint ett_tetra_T_type2_parameters_03 = -1;
static gint ett_tetra_T_ssi = -1;
static gint ett_tetra_T_address_extension = -1;
static gint ett_tetra_T_suscriber_class = -1;
static gint ett_tetra_T_energy_saving_mode = -1;
static gint ett_tetra_T_scch_info = -1;
static gint ett_tetra_T_type3 = -1;
static gint ett_tetra_T_type3_elements = -1;
static gint ett_tetra_T_new_ra = -1;
static gint ett_tetra_T_group_identity_location_accept = -1;
static gint ett_tetra_T_group_predefined_lifetime = -1;
static gint ett_tetra_T_group_identity_downlink = -1;
static gint ett_tetra_T_proprietary = -1;
static gint ett_tetra_D_LOCATION_UPDATE_REJECT = -1;
static gint ett_tetra_U_MM_STATUS = -1;
static gint ett_tetra_D_MM_STATUS = -1;
static gint ett_tetra_U_CMCE_PDU = -1;
static gint ett_tetra_U_RELEASE = -1;
static gint ett_tetra_U_SDS_DATA = -1;
static gint ett_tetra_T_called_party_type_identifier = -1;
static gint ett_tetra_T_short_data_type_identifier = -1;
static gint ett_tetra_U_STATUS = -1;
static gint ett_tetra_T_called_party_type_identifier_01 = -1;
static gint ett_tetra_U_INFO = -1;
static gint ett_tetra_D_CMCE_PDU = -1;
static gint ett_tetra_D_SDS_DATA = -1;
static gint ett_tetra_T_calling_party_type_identifier = -1;
static gint ett_tetra_T_short_data_type_identifier_01 = -1;
static gint ett_tetra_D_STATUS = -1;
static gint ett_tetra_T_calling_party_type_identifier_01 = -1;
static gint ett_tetra_D_DISCONNECT = -1;
static gint ett_tetra_D_INFO = -1;
static gint ett_tetra_D_TX_WAIT = -1;
static gint ett_tetra_D_TX_CONTINUE = -1;
static gint ett_tetra_U_LOCATION_UPDATE_DEMAND = -1;
static gint ett_tetra_T_cipher_control = -1;
static gint ett_tetra_T_optional_elements_06 = -1;
static gint ett_tetra_T_type2_parameters_04 = -1;
static gint ett_tetra_T_energy_saving_mode_01 = -1;
static gint ett_tetra_T_la_information = -1;
static gint ett_tetra_T_ssi_01 = -1;
static gint ett_tetra_T_address_extension_01 = -1;
static gint ett_tetra_T_type3_01 = -1;
static gint ett_tetra_T_type3_elements_01 = -1;
static gint ett_tetra_T_group_identity_location_demand = -1;
static gint ett_tetra_T_group_report_response = -1;
static gint ett_tetra_T_group_identity_uplink = -1;
static gint ett_tetra_T_proprietary_01 = -1;
static gint ett_tetra_U_ATTACH_DETACH_GROUP_IDENTITY = -1;
static gint ett_tetra_T_optional_elements_07 = -1;
static gint ett_tetra_T_type2_element = -1;
static gint ett_tetra_T_type3_02 = -1;
static gint ett_tetra_T_type3_elements_02 = -1;
static gint ett_tetra_U_ATTACH_DETACH_GROUP_IDENTITY_ACK = -1;
static gint ett_tetra_T_optional_elements_08 = -1;
static gint ett_tetra_T_type2_element_01 = -1;
static gint ett_tetra_T_type3_03 = -1;
static gint ett_tetra_T_type3_elements_03 = -1;
static gint ett_tetra_U_SETUP = -1;
static gint ett_tetra_T_optional_elements_09 = -1;
static gint ett_tetra_T_type2_parameters_05 = -1;
static gint ett_tetra_T_external_subscriber_number = -1;
static gint ett_tetra_T_prop = -1;
static gint ett_tetra_Basic_service_information = -1;
static gint ett_tetra_U_ALERT = -1;
static gint ett_tetra_T_optional_elements_10 = -1;
static gint ett_tetra_T_type2_parameters_06 = -1;
static gint ett_tetra_T_basic_service_information = -1;
static gint ett_tetra_T_prop_01 = -1;
static gint ett_tetra_U_CONNECT = -1;
static gint ett_tetra_T_optional_elements_11 = -1;
static gint ett_tetra_T_type2_parameters_07 = -1;
static gint ett_tetra_T_basic_service_information_01 = -1;
static gint ett_tetra_T_prop_02 = -1;
static gint ett_tetra_U_TX_CEASED = -1;
static gint ett_tetra_T_optional_elements_12 = -1;
static gint ett_tetra_T_type2_parameters_08 = -1;
static gint ett_tetra_T_prop_03 = -1;
static gint ett_tetra_U_TX_DEMAND = -1;
static gint ett_tetra_T_optional_elements_13 = -1;
static gint ett_tetra_T_type2_parameters_09 = -1;
static gint ett_tetra_T_prop_04 = -1;
static gint ett_tetra_U_DISCONNECT = -1;
static gint ett_tetra_T_optional_elements_14 = -1;
static gint ett_tetra_T_type2_parameters_10 = -1;
static gint ett_tetra_T_prop_05 = -1;
static gint ett_tetra_U_CALL_RESTORE = -1;
static gint ett_tetra_T_optional_elements_15 = -1;
static gint ett_tetra_T_type2_parameters_11 = -1;
static gint ett_tetra_T_prop_06 = -1;
static gint ett_tetra_D_SETUP = -1;
static gint ett_tetra_T_optional_elements_16 = -1;
static gint ett_tetra_T_type2_parameters_12 = -1;
static gint ett_tetra_T_calling_party_address = -1;
static gint ett_tetra_T_external_subscriber_number_01 = -1;
static gint ett_tetra_T_prop_07 = -1;
static gint ett_tetra_D_CALL_PROCEEDING = -1;
static gint ett_tetra_T_optional_elements_17 = -1;
static gint ett_tetra_T_type2_parameters_13 = -1;
static gint ett_tetra_T_basic_service_information_02 = -1;
static gint ett_tetra_T_call_status = -1;
static gint ett_tetra_T_notification_indicator = -1;
static gint ett_tetra_T_prop_08 = -1;
static gint ett_tetra_D_ALERT = -1;
static gint ett_tetra_T_optional_elements_18 = -1;
static gint ett_tetra_T_type2_parameters_14 = -1;
static gint ett_tetra_T_basic_service_infomation = -1;
static gint ett_tetra_T_notification_indicator_01 = -1;
static gint ett_tetra_T_prop_09 = -1;
static gint ett_tetra_D_CONNECT = -1;
static gint ett_tetra_T_optional_elements_19 = -1;
static gint ett_tetra_T_type2_parameters_15 = -1;
static gint ett_tetra_T_call_priority = -1;
static gint ett_tetra_T_basic_service_information_03 = -1;
static gint ett_tetra_T_temporary_address = -1;
static gint ett_tetra_T_notification_indicator_02 = -1;
static gint ett_tetra_T_prop_10 = -1;
static gint ett_tetra_D_CONNECT_ACK = -1;
static gint ett_tetra_T_optional_elements_20 = -1;
static gint ett_tetra_T_type2_parameters_16 = -1;
static gint ett_tetra_T_notification_indicator_03 = -1;
static gint ett_tetra_T_prop_11 = -1;
static gint ett_tetra_D_RELEASE = -1;
static gint ett_tetra_T_optional_elements_21 = -1;
static gint ett_tetra_T_type2_parameters_17 = -1;
static gint ett_tetra_T_notification_indicator_04 = -1;
static gint ett_tetra_T_prop_12 = -1;
static gint ett_tetra_D_CALL_RESTORE = -1;
static gint ett_tetra_T_optional_elements_22 = -1;
static gint ett_tetra_T_type2_parameters_18 = -1;
static gint ett_tetra_T_new_call_identifier = -1;
static gint ett_tetra_T_call_time_out = -1;
static gint ett_tetra_T_call_status_01 = -1;
static gint ett_tetra_T_modify = -1;
static gint ett_tetra_T_notification_indicator_05 = -1;
static gint ett_tetra_T_prop_13 = -1;
static gint ett_tetra_D_TX_CEASED = -1;
static gint ett_tetra_T_optional_elements_23 = -1;
static gint ett_tetra_T_type2_parameters_19 = -1;
static gint ett_tetra_T_notification_indicator_06 = -1;
static gint ett_tetra_T_prop_14 = -1;
static gint ett_tetra_D_TX_GRANTED = -1;
static gint ett_tetra_D_ATTACH_DETACH_GROUP_IDENTITY = -1;
static gint ett_tetra_T_optional_elements_24 = -1;
static gint ett_tetra_T_type2_element_02 = -1;
static gint ett_tetra_T_type3_04 = -1;
static gint ett_tetra_T_type3_elements_04 = -1;
static gint ett_tetra_D_ATTACH_DETACH_GROUP_IDENTITY_ACK = -1;
static gint ett_tetra_T_optional_elements_25 = -1;
static gint ett_tetra_T_type2_element_03 = -1;
static gint ett_tetra_T_type3_05 = -1;
static gint ett_tetra_T_type3_elements_05 = -1;
static gint ett_tetra_Calling_party_address_type = -1;
static gint ett_tetra_T_called_party_ssi_extention = -1;
static gint ett_tetra_Proprietary = -1;
static gint ett_tetra_T_data_01 = -1;
static gint ett_tetra_Type1 = -1;
static gint ett_tetra_Type2 = -1;
static gint ett_tetra_Modify_type = -1;

/*--- End of included file: packet-tetra-ett.c ---*/
#line 96 "../../asn1/tetra/packet-tetra-template.c"


/*--- Included file: packet-tetra-fn.c ---*/
#line 1 "../../asn1/tetra/packet-tetra-fn.c"


static int
dissect_tetra_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_tetra_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AACH_sequence[] = {
  { &hf_tetra_function      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_field1        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_field2        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_AACH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_AACH, AACH_sequence);

  return offset;
}


static const value_string tetra_System_Code_vals[] = {
  {   0, "ets-300-392-2" },
  {   1, "ets-300-392-2anden-300-392-7" },
  {   2, "en-300-392-2-v2-3-2orlateranden-300-392-7" },
  {   3, "v-d-reserved" },
  {   4, "v-d-reserved" },
  {   5, "v-d-reserved" },
  {   6, "v-d-reserved" },
  {   7, "v-d-reserved" },
  {   8, "reserved" },
  {   9, "reserved" },
  {  10, "direct-mode-operation" },
  {  11, "direct-mode-operation" },
  {  12, "direct-mode-operation" },
  {  13, "direct-mode-operation" },
  {  14, "direct-mode-operation" },
  {  15, "direct-mode-operation" },
  { 0, NULL }
};


static int
dissect_tetra_System_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Colour_Code_vals[] = {
  {   0, "pre-defined" },
  {   1, "operator-defined" },
  {   2, "operator-defined" },
  {   3, "operator-defined" },
  {   4, "operator-defined" },
  {   5, "operator-defined" },
  {   6, "operator-defined" },
  {   7, "operator-defined" },
  {   8, "operator-defined" },
  {   9, "operator-defined" },
  {  10, "operator-defined" },
  {  11, "operator-defined" },
  {  12, "operator-defined" },
  {  13, "operator-defined" },
  {  14, "operator-defined" },
  {  15, "operator-defined" },
  {  16, "operator-defined" },
  {  17, "operator-defined" },
  {  18, "operator-defined" },
  {  19, "operator-defined" },
  {  20, "operator-defined" },
  {  21, "operator-defined" },
  {  22, "operator-defined" },
  {  23, "operator-defined" },
  {  24, "operator-defined" },
  {  25, "operator-defined" },
  {  26, "operator-defined" },
  {  27, "operator-defined" },
  {  28, "operator-defined" },
  {  29, "operator-defined" },
  {  30, "operator-defined" },
  {  31, "operator-defined" },
  {  32, "operator-defined" },
  {  33, "operator-defined" },
  {  34, "operator-defined" },
  {  35, "operator-defined" },
  {  36, "operator-defined" },
  {  37, "operator-defined" },
  {  38, "operator-defined" },
  {  39, "operator-defined" },
  {  40, "operator-defined" },
  {  41, "operator-defined" },
  {  42, "operator-defined" },
  {  43, "operator-defined" },
  {  44, "operator-defined" },
  {  45, "operator-defined" },
  {  46, "operator-defined" },
  {  47, "operator-defined" },
  {  48, "operator-defined" },
  {  49, "operator-defined" },
  {  50, "operator-defined" },
  {  51, "operator-defined" },
  {  52, "operator-defined" },
  {  53, "operator-defined" },
  {  54, "operator-defined" },
  {  55, "operator-defined" },
  {  56, "operator-defined" },
  {  57, "operator-defined" },
  {  58, "operator-defined" },
  {  59, "operator-defined" },
  {  60, "operator-defined" },
  {  61, "operator-defined" },
  {  62, "operator-defined" },
  {  63, "operator-defined" },
  { 0, NULL }
};


static int
dissect_tetra_Colour_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Timeslot_Number_vals[] = {
  {   0, "timeslot-1" },
  {   1, "timeslot-2" },
  {   2, "timeslot-3" },
  {   3, "timeslot-4" },
  { 0, NULL }
};


static int
dissect_tetra_Timeslot_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Frame_Number_vals[] = {
  {   0, "reserved" },
  {   1, "frame-1" },
  {   2, "frame-2" },
  {   3, "frame-3" },
  {   4, "frame-4" },
  {   5, "frame-5" },
  {   6, "frame-6" },
  {   7, "frame-7" },
  {   8, "frame-8" },
  {   9, "frame-9" },
  {  10, "frame-10" },
  {  11, "frame-11" },
  {  12, "frame-12" },
  {  13, "frame-13" },
  {  14, "frame-14" },
  {  15, "frame-15" },
  {  16, "frame-16" },
  {  17, "frame-17" },
  {  18, "frame-18" },
  {  19, "reserved" },
  {  20, "reserved" },
  {  21, "reserved" },
  {  22, "reserved" },
  {  23, "reserved" },
  {  24, "reserved" },
  {  25, "reserved" },
  {  26, "reserved" },
  {  27, "reserved" },
  {  28, "reserved" },
  {  29, "reserved" },
  {  30, "reserved" },
  {  31, "reserved" },
  { 0, NULL }
};


static int
dissect_tetra_Frame_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Multiple_Frame_Number_vals[] = {
  {   0, "reserved" },
  {   1, "multiframe-1" },
  {   2, "multiframe-2" },
  {   3, "multiframe-3" },
  {   4, "multiframe-4" },
  {   5, "multiframe-5" },
  {   6, "multiframe-6" },
  {   7, "multiframe-7" },
  {   8, "multiframe-8" },
  {   9, "multiframe-9" },
  {  10, "multiframe-10" },
  {  11, "multiframe-11" },
  {  12, "multiframe-12" },
  {  13, "multiframe-13" },
  {  14, "multiframe-14" },
  {  15, "multiframe-15" },
  {  16, "multiframe-16" },
  {  17, "multiframe-17" },
  {  18, "multiframe-18" },
  {  19, "multiframe-19" },
  {  20, "multiframe-20" },
  {  21, "multiframe-21" },
  {  22, "multiframe-22" },
  {  23, "multiframe-23" },
  {  24, "multiframe-24" },
  {  25, "multiframe-25" },
  {  26, "multiframe-26" },
  {  27, "multiframe-27" },
  {  28, "multiframe-28" },
  {  29, "multiframe-29" },
  {  30, "multiframe-30" },
  {  31, "multiframe-31" },
  {  32, "multiframe-32" },
  {  33, "multiframe-33" },
  {  34, "multiframe-34" },
  {  35, "multiframe-35" },
  {  36, "multiframe-36" },
  {  37, "multiframe-37" },
  {  38, "multiframe-38" },
  {  39, "multiframe-39" },
  {  40, "multiframe-40" },
  {  41, "multiframe-41" },
  {  42, "multiframe-42" },
  {  43, "multiframe-43" },
  {  44, "multiframe-44" },
  {  45, "multiframe-45" },
  {  46, "multiframe-46" },
  {  47, "multiframe-47" },
  {  48, "multiframe-48" },
  {  49, "multiframe-49" },
  {  50, "multiframe-50" },
  {  51, "multiframe-51" },
  {  52, "multiframe-52" },
  {  53, "multiframe-53" },
  {  54, "multiframe-54" },
  {  55, "multiframe-55" },
  {  56, "multiframe-56" },
  {  57, "multiframe-57" },
  {  58, "multiframe-58" },
  {  59, "multiframe-59" },
  {  60, "multiframe-60" },
  {  61, "reserved" },
  {  62, "reserved" },
  {  63, "reserved" },
  { 0, NULL }
};


static int
dissect_tetra_Multiple_Frame_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Sharing_Mod_vals[] = {
  {   0, "continuous-transmission" },
  {   1, "carrier-sharing" },
  {   2, "mcch-sharing" },
  {   3, "traffic-carrier-sharing" },
  { 0, NULL }
};


static int
dissect_tetra_Sharing_Mod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_TS_Reserved_Frames_vals[] = {
  {   0, "frame-reserved-1" },
  {   1, "frames-reserved-2" },
  {   2, "frames-reserved-3" },
  {   3, "frames-reserved-4" },
  {   4, "frames-reserved-6" },
  {   5, "frames-reserved-9" },
  {   6, "frames-reserved-12" },
  {   7, "frames-reserved-18" },
  { 0, NULL }
};


static int
dissect_tetra_TS_Reserved_Frames(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_U_Plane_DTX_vals[] = {
  {   0, "not-allowed" },
  {   1, "allowed" },
  { 0, NULL }
};


static int
dissect_tetra_U_Plane_DTX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Frame_18_Extension_vals[] = {
  {   0, "not-allowed" },
  {   1, "allowed" },
  { 0, NULL }
};


static int
dissect_tetra_Frame_18_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Reserved_vals[] = {
  {   0, "default" },
  {   1, "not-used" },
  { 0, NULL }
};


static int
dissect_tetra_Reserved(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_tetra_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_tetra_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}



static int
dissect_tetra_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MLE_Sync_sequence[] = {
  { &hf_tetra_mcc           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_mnc           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_neighbour_cell_broadcast, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_cell_service_level, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_late_entry_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MLE_Sync(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MLE_Sync, MLE_Sync_sequence);

  return offset;
}


static const per_sequence_t BSCH_sequence[] = {
  { &hf_tetra_system_code   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_System_Code },
  { &hf_tetra_colour_code   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Colour_Code },
  { &hf_tetra_timeslot_number, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Timeslot_Number },
  { &hf_tetra_frame_number  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Frame_Number },
  { &hf_tetra_multiple_frame_number, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Multiple_Frame_Number },
  { &hf_tetra_sharing_mod   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Sharing_Mod },
  { &hf_tetra_ts_reserved_frames, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_TS_Reserved_Frames },
  { &hf_tetra_u_plane_dtx   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_Plane_DTX },
  { &hf_tetra_frame_18_extension, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Frame_18_Extension },
  { &hf_tetra_reserved      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Reserved },
  { &hf_tetra_tm_sdu        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_MLE_Sync },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_BSCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_BSCH, BSCH_sequence);

  return offset;
}



static int
dissect_tetra_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_tetra_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string tetra_Offset_vals[] = {
  {   0, "offset-0" },
  {   1, "offset-positive-6-point-25" },
  {   2, "offset-minus-6-point-25" },
  {   3, "offset-12-point-5" },
  { 0, NULL }
};


static int
dissect_tetra_Offset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_tetra_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string tetra_Reverse_Operation_vals[] = {
  {   0, "normal" },
  {   1, "reverse" },
  { 0, NULL }
};


static int
dissect_tetra_Reverse_Operation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Sencond_Ctl_Carrier_vals[] = {
  {   0, "none" },
  {   1, "timeslot-2" },
  {   2, "timeslots-2and3" },
  {   3, "timeslots-2and3and4" },
  { 0, NULL }
};


static int
dissect_tetra_Sencond_Ctl_Carrier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_MS_TXPWR_MAX_CELL_vals[] = {
  {   0, "reserved" },
  {   1, "dbm-15" },
  {   2, "dbm-20" },
  {   3, "dbm-25" },
  {   4, "dbm-30" },
  {   5, "dbm-35" },
  {   6, "dbm-40" },
  {   7, "dbm-45" },
  { 0, NULL }
};


static int
dissect_tetra_MS_TXPWR_MAX_CELL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_RXLEV_ACCESS_MIN_vals[] = {
  {   0, "dbm-125" },
  {   1, "dbm-120" },
  {   2, "dbm-115" },
  {   3, "dbm-110" },
  {   4, "dbm-105" },
  {   5, "dbm-100" },
  {   6, "dbm-95" },
  {   7, "dnm-90" },
  {   8, "dbm-85" },
  {   9, "dbm-80" },
  {  10, "dbm-75" },
  {  11, "dbm-70" },
  {  12, "dbm-65" },
  {  13, "dbm-60" },
  {  14, "dbm-55" },
  {  15, "dbm-50" },
  { 0, NULL }
};


static int
dissect_tetra_RXLEV_ACCESS_MIN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_ACCESS_PARAMETER_vals[] = {
  {   0, "dbm-53" },
  {   1, "dbm-51" },
  {   2, "dbm-49" },
  {   3, "dbm-47" },
  {   4, "dbm-45" },
  {   5, "dbm-43" },
  {   6, "dbm-41" },
  {   7, "dbm-39" },
  {   8, "dbm-37" },
  {   9, "dbm-35" },
  {  10, "dbm-33" },
  {  11, "dbm-31" },
  {  12, "dbm-29" },
  {  13, "dbm-27" },
  {  14, "dbm-25" },
  {  15, "dbm-23" },
  { 0, NULL }
};


static int
dissect_tetra_ACCESS_PARAMETER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_RADIO_DOWNLINK_TIMEOUT_vals[] = {
  {   0, "disable" },
  {   1, "timeslots-144" },
  {   2, "timeslots-288" },
  {   3, "timeslots-432" },
  {   4, "timeslots-576" },
  {   5, "timeslots-720" },
  {   6, "timeslots-864" },
  {   7, "timeslots-1008" },
  {   8, "timeslots-1152" },
  {   9, "timeslots-1296" },
  {  10, "timeslots-1440" },
  {  11, "timeslots-1584" },
  {  12, "timeslots-1728" },
  {  13, "timeslots-1872" },
  {  14, "timeslots-2016" },
  {  15, "timeslots-2160" },
  { 0, NULL }
};


static int
dissect_tetra_RADIO_DOWNLINK_TIMEOUT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_tetra_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string tetra_T_hyperframe_or_cck_vals[] = {
  {   0, "hyperframe" },
  {   1, "cckid" },
  { 0, NULL }
};

static const per_choice_t T_hyperframe_or_cck_choice[] = {
  {   0, &hf_tetra_hyperframe    , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_65535 },
  {   1, &hf_tetra_cckid         , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_65535 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_hyperframe_or_cck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_hyperframe_or_cck, T_hyperframe_or_cck_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_FRAME_vals[] = {
  {   0, "not-common" },
  {   1, "common" },
  { 0, NULL }
};


static int
dissect_tetra_FRAME(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t TS_COMMON_FRAMES_sequence[] = {
  { &hf_tetra_frame1        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame2        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame3        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame4        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame5        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame6        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame7        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame8        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame9        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame10       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame11       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame12       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame13       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame14       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame15       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame16       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame17       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { &hf_tetra_frame18       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_FRAME },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_TS_COMMON_FRAMES(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_TS_COMMON_FRAMES, TS_COMMON_FRAMES_sequence);

  return offset;
}


static const value_string tetra_IMM_vals[] = {
  {   0, "always-randomize" },
  {   1, "randomize-after-imm-tdma" },
  {   2, "randomize-after-imm-tdma" },
  {   3, "randomize-after-imm-tdma" },
  {   4, "randomize-after-imm-tdma" },
  {   5, "randomize-after-imm-tdma" },
  {   6, "randomize-after-imm-tdma" },
  {   7, "randomize-after-imm-tdma" },
  {   8, "randomize-after-imm-tdma" },
  {   9, "randomize-after-imm-tdma" },
  {  10, "randomize-after-imm-tdma" },
  {  11, "randomize-after-imm-tdma" },
  {  12, "randomize-after-imm-tdma" },
  {  13, "randomize-after-imm-tdma" },
  {  14, "randomize-after-imm-tdma" },
  {  15, "immediate-access-allowed" },
  { 0, NULL }
};


static int
dissect_tetra_IMM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_WT_vals[] = {
  {   0, "reserved" },
  {   1, "response-within-wt-downlink" },
  {   2, "response-within-wt-downlink" },
  {   3, "response-within-wt-downlink" },
  {   4, "response-within-wt-downlink" },
  {   5, "response-within-wt-downlink" },
  {   6, "response-within-wt-downlink" },
  {   7, "response-within-wt-downlink" },
  {   8, "response-within-wt-downlink" },
  {   9, "response-within-wt-downlink" },
  {  10, "response-within-wt-downlink" },
  {  11, "response-within-wt-downlink" },
  {  12, "response-within-wt-downlink" },
  {  13, "response-within-wt-downlink" },
  {  14, "response-within-wt-downlink" },
  {  15, "response-within-wt-downlink" },
  { 0, NULL }
};


static int
dissect_tetra_WT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_NU_vals[] = {
  {   0, "no-random" },
  {   1, "random-1" },
  {   2, "random-2" },
  {   3, "random-3" },
  {   4, "random-4" },
  {   5, "random-5" },
  {   6, "random-6" },
  {   7, "random-7" },
  {   8, "random-8" },
  {   9, "random-9" },
  {  10, "random-10" },
  {  11, "random-11" },
  {  12, "random-12" },
  {  13, "random-13" },
  {  14, "random-14" },
  {  15, "random-15" },
  { 0, NULL }
};


static int
dissect_tetra_NU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Frame_Len_Factor_vals[] = {
  {   0, "multiply-1" },
  {   1, "multiply-4" },
  { 0, NULL }
};


static int
dissect_tetra_Frame_Len_Factor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Timeslot_Pointer_vals[] = {
  {   0, "same-as-downlink" },
  {   1, "timeslot-4" },
  {   2, "timeslot-bit-map" },
  {   3, "timeslot-bit-map" },
  {   4, "timeslot-bit-map" },
  {   5, "timeslot-bit-map" },
  {   6, "timeslot-bit-map" },
  {   7, "timeslot-bit-map" },
  {   8, "timeslot-bit-map" },
  {   9, "timeslot-bit-map" },
  {  10, "timeslot-bit-map" },
  {  11, "timeslot-bit-map" },
  {  12, "timeslot-bit-map" },
  {  13, "timeslot-bit-map" },
  {  14, "timeslot-bit-map" },
  {  15, "all-four-timeslots" },
  { 0, NULL }
};


static int
dissect_tetra_Timeslot_Pointer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Min_Pdu_Priority_vals[] = {
  {   0, "priority-0" },
  {   1, "priority-1" },
  {   2, "priority-2" },
  {   3, "priority-3" },
  {   4, "priority-4" },
  {   5, "priority-5" },
  {   6, "priority-6" },
  {   7, "priority-7" },
  { 0, NULL }
};


static int
dissect_tetra_Min_Pdu_Priority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Default_Code_A_sequence[] = {
  { &hf_tetra_imm           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_IMM },
  { &hf_tetra_wt            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_WT },
  { &hf_tetra_nu            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_NU },
  { &hf_tetra_frame_len_factor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Frame_Len_Factor },
  { &hf_tetra_timeslot_pointer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Timeslot_Pointer },
  { &hf_tetra_min_pdu_priority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Min_Pdu_Priority },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_Default_Code_A(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_Default_Code_A, Default_Code_A_sequence);

  return offset;
}



static int
dissect_tetra_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string tetra_SDS_TL_Addressing_Method_vals[] = {
  {   0, "reserved" },
  {   1, "service-centre" },
  {   2, "never-use-service-centre" },
  {   3, "ms-choice-to-use-service-centre" },
  { 0, NULL }
};


static int
dissect_tetra_SDS_TL_Addressing_Method(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Data_Priority_Supported_vals[] = {
  {   0, "not-supported" },
  {   1, "supported" },
  { 0, NULL }
};


static int
dissect_tetra_Data_Priority_Supported(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Section_Information_vals[] = {
  {   0, "no-information" },
  {   1, "futher-information" },
  { 0, NULL }
};


static int
dissect_tetra_Section_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PRESENT1_sequence[] = {
  { &hf_tetra_data_priority_supported, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Data_Priority_Supported },
  { &hf_tetra_reserved_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_section_2_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Section_Information },
  { &hf_tetra_section_3_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Section_Information },
  { &hf_tetra_section_4_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Section_Information },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_PRESENT1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_PRESENT1, PRESENT1_sequence);

  return offset;
}



static int
dissect_tetra_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const value_string tetra_T_section_vals[] = {
  {   0, "present-1" },
  {   1, "present-2" },
  {   2, "present-3" },
  {   3, "present-4" },
  { 0, NULL }
};

static const per_choice_t T_section_choice[] = {
  {   0, &hf_tetra_present_1     , ASN1_NO_EXTENSIONS     , dissect_tetra_PRESENT1 },
  {   1, &hf_tetra_present_2     , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_127 },
  {   2, &hf_tetra_present_3     , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_127 },
  {   3, &hf_tetra_present_4     , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_127 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_section(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_section, T_section_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Extended_Services_Broadcast_sequence[] = {
  { &hf_tetra_security_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_255 },
  { &hf_tetra_sds_tl_addressing_method, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_SDS_TL_Addressing_Method },
  { &hf_tetra_gck_supported , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_section       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_section },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_Extended_Services_Broadcast(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_Extended_Services_Broadcast, Extended_Services_Broadcast_sequence);

  return offset;
}


static const value_string tetra_T_optional_params_vals[] = {
  {   0, "even-multiframe" },
  {   1, "odd-multiframe" },
  {   2, "access-a-code" },
  {   3, "extend-service" },
  { 0, NULL }
};

static const per_choice_t T_optional_params_choice[] = {
  {   0, &hf_tetra_even_multiframe, ASN1_NO_EXTENSIONS     , dissect_tetra_TS_COMMON_FRAMES },
  {   1, &hf_tetra_odd_multiframe, ASN1_NO_EXTENSIONS     , dissect_tetra_TS_COMMON_FRAMES },
  {   2, &hf_tetra_access_a_code , ASN1_NO_EXTENSIONS     , dissect_tetra_Default_Code_A },
  {   3, &hf_tetra_extend_service, ASN1_NO_EXTENSIONS     , dissect_tetra_Extended_Services_Broadcast },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_params(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_params, T_optional_params_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BNCH_sequence[] = {
  { &hf_tetra_pdu_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_broadcast_type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_main_carrier  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_4095 },
  { &hf_tetra_frequency_band, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_offset        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Offset },
  { &hf_tetra_duplex_spacing, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_reverse_operation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Reverse_Operation },
  { &hf_tetra_sencond_ctl_carrier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Sencond_Ctl_Carrier },
  { &hf_tetra_ms_txpwr_max_cell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_MS_TXPWR_MAX_CELL },
  { &hf_tetra_rxlev_access_min, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_RXLEV_ACCESS_MIN },
  { &hf_tetra_access_parameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_ACCESS_PARAMETER },
  { &hf_tetra_radio_downlink_timeout, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_RADIO_DOWNLINK_TIMEOUT },
  { &hf_tetra_hyperframe_or_cck, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_hyperframe_or_cck },
  { &hf_tetra_optional_params, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_params },
  { &hf_tetra_la            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_subscriber_class, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_65535 },
  { &hf_tetra_registriation , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_de_registration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_priority_cell , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_minimum_mode_service, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_migration     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_system_wide_service, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tetra_voice_service, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_circuit_mode_data_service, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_reserved_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_sndcp_service , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_air_interface_encryption, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_advanced_link_support, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_BNCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_BNCH, BNCH_sequence);

  return offset;
}


static const value_string tetra_Fill_Bit_Indication_vals[] = {
  {   0, "no-present" },
  {   1, "present" },
  { 0, NULL }
};


static int
dissect_tetra_Fill_Bit_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Encrypted_Flag_vals[] = {
  {   0, "not-encrypted" },
  {   1, "encrypted" },
  { 0, NULL }
};


static int
dissect_tetra_Encrypted_Flag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_tetra_INTEGER_0_16777215(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, NULL, FALSE);

  return offset;
}


static const value_string tetra_Address_vals[] = {
  {   0, "ssi" },
  {   1, "eventLabel" },
  {   2, "ussi" },
  {   3, "smi" },
  { 0, NULL }
};

static const per_choice_t Address_choice[] = {
  {   0, &hf_tetra_ssi           , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16777215 },
  {   1, &hf_tetra_eventLabel    , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_1023 },
  {   2, &hf_tetra_ussi          , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16777215 },
  {   3, &hf_tetra_smi           , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16777215 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_Address, Address_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string tetra_UPDATE_TYPE_vals[] = {
  {   0, "roaming-location-updating" },
  {   1, "temporary-registration" },
  {   2, "periodic-location-updating" },
  {   3, "itsi-attach" },
  {   4, "call-restoration-roaming" },
  {   5, "migrating-or-call-restoration-migrating" },
  {   6, "demand-location-updating" },
  {   7, "disabled-MS-updating" },
  { 0, NULL }
};


static int
dissect_tetra_UPDATE_TYPE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_tetra_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string tetra_T_cipher_control_vals[] = {
  {   0, "no-cipher" },
  {   1, "ciphering-parameters" },
  { 0, NULL }
};

static const per_choice_t T_cipher_control_choice[] = {
  {   0, &hf_tetra_no_cipher     , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_ciphering_parameters, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_1023 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_cipher_control(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_cipher_control, T_cipher_control_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_OCTET_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const value_string tetra_T_energy_saving_mode_01_vals[] = {
  {   0, "none" },
  {   1, "energy-saving-mode" },
  { 0, NULL }
};

static const per_choice_t T_energy_saving_mode_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_energy_saving_mode_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_7 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_energy_saving_mode_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_energy_saving_mode_01, T_energy_saving_mode_01_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_la_information_vals[] = {
  {   0, "none" },
  {   1, "la-information" },
  { 0, NULL }
};

static const per_choice_t T_la_information_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_la_information_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16383 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_la_information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_la_information, T_la_information_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const value_string tetra_T_ssi_01_vals[] = {
  {   0, "none" },
  {   1, "ssi" },
  { 0, NULL }
};

static const per_choice_t T_ssi_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_ssi_03        , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_ssi_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_ssi_01, T_ssi_01_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_address_extension_01_vals[] = {
  {   0, "none" },
  {   1, "address-extension" },
  { 0, NULL }
};

static const per_choice_t T_address_extension_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_address_extension_01, ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_address_extension_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_address_extension_01, T_address_extension_01_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_TYPE3_IDENTIFIER_vals[] = {
  {   0, "reserved" },
  {   1, "default-group-attachment-lifetime" },
  {   2, "new-registered-area" },
  {   3, "group-identity-location-demand" },
  {   4, "group-report-response" },
  {   5, "group-identity-location-accept" },
  {   6, "dm-ms-address" },
  {   7, "group-identity-downlink" },
  {   8, "group-identity-uplink" },
  {   9, "authentication-uplink" },
  {  10, "authentication-downlink" },
  {  11, "reserved" },
  {  12, "reserved1" },
  {  13, "reserved2" },
  {  14, "reserved3" },
  {  15, "proprietary" },
  { 0, NULL }
};


static int
dissect_tetra_TYPE3_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_group_identity_location_demand_vals[] = {
  {   0, "none" },
  {   1, "group-identity-location-demand" },
  { 0, NULL }
};

static const per_choice_t T_group_identity_location_demand_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_group_identity_location_demand_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_group_identity_location_demand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_group_identity_location_demand, T_group_identity_location_demand_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_group_report_response_vals[] = {
  {   0, "none" },
  {   1, "group-report-response" },
  { 0, NULL }
};

static const per_choice_t T_group_report_response_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_group_report_response_01, ASN1_NO_EXTENSIONS     , dissect_tetra_BOOLEAN },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_group_report_response(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_group_report_response, T_group_report_response_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_group_identity_uplink_vals[] = {
  {   0, "none" },
  {   1, "group-identity-uplink" },
  { 0, NULL }
};

static const per_choice_t T_group_identity_uplink_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_group_identity_uplink_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_15 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_group_identity_uplink(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_group_identity_uplink, T_group_identity_uplink_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_proprietary_01_vals[] = {
  {   0, "none" },
  {   1, "proprietary" },
  { 0, NULL }
};

static const per_choice_t T_proprietary_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_proprietary_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_7 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_proprietary_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_proprietary_01, T_proprietary_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type3_elements_01_sequence[] = {
  { &hf_tetra_type3_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_TYPE3_IDENTIFIER },
  { &hf_tetra_group_identity_location_demand, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_group_identity_location_demand },
  { &hf_tetra_group_report_response, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_group_report_response },
  { &hf_tetra_group_identity_uplink, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_group_identity_uplink },
  { &hf_tetra_proprietary_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_proprietary_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type3_elements_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type3_elements_01, T_type3_elements_01_sequence);

  return offset;
}


static const value_string tetra_T_type3_01_vals[] = {
  {   0, "no-type3" },
  {   1, "type3-elements" },
  { 0, NULL }
};

static const per_choice_t T_type3_01_choice[] = {
  {   0, &hf_tetra_no_type3      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type3_elements_01, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type3_elements_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_type3_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_type3_01, T_type3_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_04_sequence[] = {
  { &hf_tetra_energy_saving_mode_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_energy_saving_mode_01 },
  { &hf_tetra_la_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_la_information },
  { &hf_tetra_ssi_04        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_ssi_01 },
  { &hf_tetra_address_extension_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_address_extension_01 },
  { &hf_tetra_type3_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_type3_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_04, T_type2_parameters_04_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_06_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_06_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_04, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_06, T_optional_elements_06_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_LOCATION_UPDATE_DEMAND_sequence[] = {
  { &hf_tetra_location_update_type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_UPDATE_TYPE },
  { &hf_tetra_request_to_append_LA, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_cipher_control_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_cipher_control },
  { &hf_tetra_class_of_MS   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { &hf_tetra_optional_elements_06, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_06 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_LOCATION_UPDATE_DEMAND(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 102 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_LOCATION_UPDATE_DEMAND, U_LOCATION_UPDATE_DEMAND_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-LOCATION-UPDATE-DEMAND");


  return offset;
}


static const value_string tetra_T_scanning_on_off_vals[] = {
  {   0, "on" },
  {   1, "off" },
  { 0, NULL }
};


static int
dissect_tetra_T_scanning_on_off(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t U_MM_STATUS_sequence[] = {
  { &hf_tetra_status_uplink , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_scanning_on_off, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_scanning_on_off },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_MM_STATUS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 238 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_MM_STATUS, U_MM_STATUS_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-MM-STATUS");


  return offset;
}



static int
dissect_tetra_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_attach_01_sequence[] = {
  { &hf_tetra_class_of_usage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_attach_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_attach_01, T_attach_01_sequence);

  return offset;
}


static const value_string tetra_T_detach_uplike_vals[] = {
  {   0, "unknow-gssi" },
  {   1, "unvaild-cipher" },
  {   2, "user-intitial" },
  {   3, "reseverd" },
  { 0, NULL }
};


static int
dissect_tetra_T_detach_uplike(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_detach_01_sequence[] = {
  { &hf_tetra_detach_uplike , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_detach_uplike },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_detach_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_detach_01, T_detach_01_sequence);

  return offset;
}


static const value_string tetra_T_attach_detach_identifiet_01_vals[] = {
  {   0, "attach" },
  {   1, "detach" },
  { 0, NULL }
};

static const per_choice_t T_attach_detach_identifiet_01_choice[] = {
  {   0, &hf_tetra_attach_01     , ASN1_NO_EXTENSIONS     , dissect_tetra_T_attach_01 },
  {   1, &hf_tetra_detach_01     , ASN1_NO_EXTENSIONS     , dissect_tetra_T_detach_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_attach_detach_identifiet_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_attach_detach_identifiet_01, T_attach_detach_identifiet_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_gssi_extension_01_sequence[] = {
  { &hf_tetra_gssi_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_3 },
  { &hf_tetra_extension     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_gssi_extension_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_gssi_extension_01, T_gssi_extension_01_sequence);

  return offset;
}


static const value_string tetra_T_address_type_01_vals[] = {
  {   0, "gssi" },
  {   1, "gssi-extension" },
  {   2, "vgssi" },
  { 0, NULL }
};

static const per_choice_t T_address_type_01_choice[] = {
  {   0, &hf_tetra_gssi_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_3 },
  {   1, &hf_tetra_gssi_extension_01, ASN1_NO_EXTENSIONS     , dissect_tetra_T_gssi_extension_01 },
  {   2, &hf_tetra_vgssi         , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_address_type_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_address_type_01, T_address_type_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GROUP_IDENTITY_UPLINK_sequence[] = {
  { &hf_tetra_attach_detach_identifiet_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_attach_detach_identifiet_01 },
  { &hf_tetra_address_type_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_address_type_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_GROUP_IDENTITY_UPLINK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_GROUP_IDENTITY_UPLINK, GROUP_IDENTITY_UPLINK_sequence);

  return offset;
}


static const per_sequence_t T_type3_elements_02_sequence[] = {
  { &hf_tetra_type3_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_TYPE3_IDENTIFIER },
  { &hf_tetra_length        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_2047 },
  { &hf_tetra_repeat_num    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_group_identity_uplink_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_GROUP_IDENTITY_UPLINK },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type3_elements_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type3_elements_02, T_type3_elements_02_sequence);

  return offset;
}


static const value_string tetra_T_type3_02_vals[] = {
  {   0, "no-type3" },
  {   1, "type3-elements" },
  { 0, NULL }
};

static const per_choice_t T_type3_02_choice[] = {
  {   0, &hf_tetra_no_type3      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type3_elements_02, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type3_elements_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_type3_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_type3_02, T_type3_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_element_sequence[] = {
  { &hf_tetra_type3_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_type3_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_element, T_type2_element_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_07_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-element" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_07_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_element , ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_element },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_07, T_optional_elements_07_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_ATTACH_DETACH_GROUP_IDENTITY_sequence[] = {
  { &hf_tetra_group_identity_report, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_group_identity_attach_detach_mode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_optional_elements_07, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_07 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_ATTACH_DETACH_GROUP_IDENTITY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 248 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_ATTACH_DETACH_GROUP_IDENTITY, U_ATTACH_DETACH_GROUP_IDENTITY_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-ATTACH-DETACH-GROUP-IDENTITY");


  return offset;
}


static const per_sequence_t T_type3_elements_03_sequence[] = {
  { &hf_tetra_type3_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_TYPE3_IDENTIFIER },
  { &hf_tetra_length        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_2047 },
  { &hf_tetra_repeat_num    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_group_identity_uplink_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_GROUP_IDENTITY_UPLINK },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type3_elements_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type3_elements_03, T_type3_elements_03_sequence);

  return offset;
}


static const value_string tetra_T_type3_03_vals[] = {
  {   0, "no-type3" },
  {   1, "type3-elements" },
  { 0, NULL }
};

static const per_choice_t T_type3_03_choice[] = {
  {   0, &hf_tetra_no_type3      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type3_elements_03, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type3_elements_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_type3_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_type3_03, T_type3_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_element_01_sequence[] = {
  { &hf_tetra_type3_03      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_type3_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_element_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_element_01, T_type2_element_01_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_08_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-element" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_08_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_element_01, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_element_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_08, T_optional_elements_08_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_ATTACH_DETACH_GROUP_IDENTITY_ACK_sequence[] = {
  { &hf_tetra_group_identity_ack_type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_group_identity_attach_detach_mode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_optional_elements_08, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_08 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_ATTACH_DETACH_GROUP_IDENTITY_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 253 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_ATTACH_DETACH_GROUP_IDENTITY_ACK, U_ATTACH_DETACH_GROUP_IDENTITY_ACK_sequence);

		col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-ATTACH-DETACH-GROUP-IDENTITY-ACK");


  return offset;
}


static const value_string tetra_U_MM_PDU_vals[] = {
  {   0, "u-Authentication" },
  {   1, "u-Itsi-Detach" },
  {   2, "u-Location-Update-Demand" },
  {   3, "u-MM-Status" },
  {   4, "u-MM-reserved1" },
  {   5, "u-WK" },
  {   6, "u-MM-reserved3" },
  {   7, "u-Attach-Detach-Group-Identity" },
  {   8, "u-Attach-Detach-Group-Identity-Ack" },
  {   9, "u-TEI-Provide" },
  {  10, "u-MM-reserved6" },
  {  11, "u-Disabled-Status" },
  {  12, "u-MM-reserved7" },
  {  13, "u-MM-reserved8" },
  {  14, "u-MM-reserved9" },
  {  15, "u-MM-Function-Not-Support" },
  { 0, NULL }
};

static const per_choice_t U_MM_PDU_choice[] = {
  {   0, &hf_tetra_u_Authentication, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_u_Itsi_Detach , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   2, &hf_tetra_u_Location_Update_Demand, ASN1_NO_EXTENSIONS     , dissect_tetra_U_LOCATION_UPDATE_DEMAND },
  {   3, &hf_tetra_u_MM_Status   , ASN1_NO_EXTENSIONS     , dissect_tetra_U_MM_STATUS },
  {   4, &hf_tetra_u_MM_reserved1, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   5, &hf_tetra_u_WK          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   6, &hf_tetra_u_MM_reserved3, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   7, &hf_tetra_u_Attach_Detach_Group_Identity, ASN1_NO_EXTENSIONS     , dissect_tetra_U_ATTACH_DETACH_GROUP_IDENTITY },
  {   8, &hf_tetra_u_Attach_Detach_Group_Identity_Ack, ASN1_NO_EXTENSIONS     , dissect_tetra_U_ATTACH_DETACH_GROUP_IDENTITY_ACK },
  {   9, &hf_tetra_u_TEI_Provide , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  10, &hf_tetra_u_MM_reserved6, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  11, &hf_tetra_u_Disabled_Status, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  12, &hf_tetra_u_MM_reserved7, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  13, &hf_tetra_u_MM_reserved8, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  14, &hf_tetra_u_MM_reserved9, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  15, &hf_tetra_u_MM_Function_Not_Support, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_U_MM_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_U_MM_PDU, U_MM_PDU_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_simplex_duplex_selection_vals[] = {
  {   0, "simplex" },
  {   1, "duplex" },
  { 0, NULL }
};


static int
dissect_tetra_T_simplex_duplex_selection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_CIRCUIT_vals[] = {
  {   0, "speech-tch-s" },
  {   1, "unprotected-tch-7-2" },
  {   2, "low-protection-tch-4-8" },
  {   3, "low-protection-tch-4-8" },
  {   4, "low-protection-tch-4-8" },
  {   5, "high-protection-tch-2-4" },
  {   6, "high-protection-tch-2-4" },
  {   7, "high-protection-tch-2-4" },
  { 0, NULL }
};


static int
dissect_tetra_CIRCUIT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Basic_service_information_sequence[] = {
  { &hf_tetra_circuit_mode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_CIRCUIT },
  { &hf_tetra_encryption    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_communication , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_slots_or_speech, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_Basic_service_information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_Basic_service_information, Basic_service_information_sequence);

  return offset;
}


static const value_string tetra_T_basic_service_information_vals[] = {
  {   0, "none" },
  {   1, "basic-service-information" },
  { 0, NULL }
};

static const per_choice_t T_basic_service_information_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_basic_service_information, ASN1_NO_EXTENSIONS     , dissect_tetra_Basic_service_information },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_basic_service_information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_basic_service_information, T_basic_service_information_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_Proprietary_element_owner(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_tetra_BIT_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t Type1_sequence[] = {
  { &hf_tetra_proprietary_element_owner, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Proprietary_element_owner },
  { &hf_tetra_proprietary_element_owner_extension, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_Type1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_Type1, Type1_sequence);

  return offset;
}


static const per_sequence_t Type2_sequence[] = {
  { &hf_tetra_proprietary_element_owner, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Proprietary_element_owner },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_Type2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_Type2, Type2_sequence);

  return offset;
}


static const value_string tetra_T_data_01_vals[] = {
  {   0, "element1" },
  {   1, "element" },
  { 0, NULL }
};

static const per_choice_t T_data_01_choice[] = {
  {   0, &hf_tetra_element1      , ASN1_NO_EXTENSIONS     , dissect_tetra_Type1 },
  {   1, &hf_tetra_element       , ASN1_NO_EXTENSIONS     , dissect_tetra_Type2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_data_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_data_01, T_data_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Proprietary_sequence[] = {
  { &hf_tetra_data_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_data_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_Proprietary(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_Proprietary, Proprietary_sequence);

  return offset;
}


static const value_string tetra_T_prop_01_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_01, T_prop_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_06_sequence[] = {
  { &hf_tetra_basic_service_information_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_basic_service_information },
  { &hf_tetra_prop_02       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_06, T_type2_parameters_06_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_10_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_10_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_06, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_06 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_10, T_optional_elements_10_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_ALERT_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_reserved_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_simplex_duplex_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_simplex_duplex_selection },
  { &hf_tetra_optional_elements_10, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_10 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_ALERT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 187 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_ALERT, U_ALERT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-ALERT");


  return offset;
}


static const value_string tetra_T_simplex_duplex_selection_01_vals[] = {
  {   0, "simplex" },
  {   1, "duplex" },
  { 0, NULL }
};


static int
dissect_tetra_T_simplex_duplex_selection_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_basic_service_information_01_vals[] = {
  {   0, "none" },
  {   1, "basic-service-information" },
  { 0, NULL }
};

static const per_choice_t T_basic_service_information_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_basic_service_information, ASN1_NO_EXTENSIONS     , dissect_tetra_Basic_service_information },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_basic_service_information_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_basic_service_information_01, T_basic_service_information_01_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_02_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_02_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_02, T_prop_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_07_sequence[] = {
  { &hf_tetra_basic_service_information_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_basic_service_information_01 },
  { &hf_tetra_prop_03       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_07, T_type2_parameters_07_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_11_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_11_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_07, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_07 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_11, T_optional_elements_11_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_CONNECT_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_hook_method_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_simplex_duplex_selection_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_simplex_duplex_selection_01 },
  { &hf_tetra_optional_elements_11, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_11 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_CONNECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 192 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_CONNECT, U_CONNECT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-CONNECT");


  return offset;
}



static int
dissect_tetra_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}


static const value_string tetra_T_prop_05_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_05_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_05, T_prop_05_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_10_sequence[] = {
  { &hf_tetra_prop_06       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_05 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_10, T_type2_parameters_10_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_14_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_14_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_10, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_10 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_14, T_optional_elements_14_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_DISCONNECT_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_disconnect_cause, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_31 },
  { &hf_tetra_optional_elements_14, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_14 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_DISCONNECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 197 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_DISCONNECT, U_DISCONNECT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-DISCONNECT");


  return offset;
}


static const per_sequence_t U_INFO_sequence[] = {
  { &hf_tetra_call_id       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_poll_response , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_INFO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_INFO, U_INFO_sequence);

  return offset;
}


static const per_sequence_t U_RELEASE_sequence[] = {
  { &hf_tetra_call_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_disconnect_cause, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_31 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_RELEASE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 79 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_RELEASE, U_RELEASE_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-RELEASE");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_RELEASE, U_RELEASE_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-RELEASE");


  return offset;
}


static const value_string tetra_T_simple_duplex_selection_vals[] = {
  {   0, "simplex" },
  {   1, "duplex" },
  { 0, NULL }
};


static int
dissect_tetra_T_simple_duplex_selection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_called_party_ssi_extention_sequence[] = {
  { &hf_tetra_called_party_ssi, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16777215 },
  { &hf_tetra_called_party_extention, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16777215 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_called_party_ssi_extention(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_called_party_ssi_extention, T_called_party_ssi_extention_sequence);

  return offset;
}


static const value_string tetra_Calling_party_address_type_vals[] = {
  {   0, "called-party-sna" },
  {   1, "called-party-ssi" },
  {   2, "called-party-ssi-extention" },
  { 0, NULL }
};

static const per_choice_t Calling_party_address_type_choice[] = {
  {   0, &hf_tetra_called_party_sna, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_255 },
  {   1, &hf_tetra_called_party_ssi, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16777215 },
  {   2, &hf_tetra_called_party_ssi_extention, ASN1_NO_EXTENSIONS     , dissect_tetra_T_called_party_ssi_extention },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_Calling_party_address_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_Calling_party_address_type, Calling_party_address_type_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_Called_party_address_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_tetra_Calling_party_address_type(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string tetra_T_external_subscriber_number_vals[] = {
  {   0, "none" },
  {   1, "external-subscriber-number" },
  { 0, NULL }
};

static const per_choice_t T_external_subscriber_number_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_external_subscriber_number_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_31 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_external_subscriber_number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_external_subscriber_number, T_external_subscriber_number_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop, T_prop_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_05_sequence[] = {
  { &hf_tetra_external_subscriber_number, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_external_subscriber_number },
  { &hf_tetra_prop          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_05, T_type2_parameters_05_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_09_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_09_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_05, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_05 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_09, T_optional_elements_09_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_SETUP_sequence[] = {
  { &hf_tetra_area_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_hook_method_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_simple_duplex_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_simple_duplex_selection },
  { &hf_tetra_basic_service_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Basic_service_information },
  { &hf_tetra_request_transmit_send_data, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_call_priority , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_clir_control  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_called_party_address, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Called_party_address_type },
  { &hf_tetra_optional_elements_09, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_09 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_SETUP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 207 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_SETUP, U_SETUP_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-SETUP");


  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_48(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     48, 48, FALSE, NULL);

  return offset;
}


static const value_string tetra_T_called_party_type_identifier_01_vals[] = {
  {   0, "short-number-address" },
  {   1, "ssi" },
  {   2, "called-ssi-called-extension" },
  {   3, "none" },
  { 0, NULL }
};

static const per_choice_t T_called_party_type_identifier_01_choice[] = {
  {   0, &hf_tetra_short_number_address, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_255 },
  {   1, &hf_tetra_ssi           , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16777215 },
  {   2, &hf_tetra_called_ssi_called_extension, ASN1_NO_EXTENSIONS     , dissect_tetra_BIT_STRING_SIZE_48 },
  {   3, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_called_party_type_identifier_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_called_party_type_identifier_01, T_called_party_type_identifier_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_STATUS_sequence[] = {
  { &hf_tetra_area_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_called_party_type_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_called_party_type_identifier_01 },
  { &hf_tetra_pre_coded_status, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_STATUS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 212 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_STATUS, U_STATUS_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-STATUS");


  return offset;
}


static const value_string tetra_T_prop_03_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_03_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_03, T_prop_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_08_sequence[] = {
  { &hf_tetra_prop_04       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_08, T_type2_parameters_08_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_12_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_12_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_08, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_08 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_12, T_optional_elements_12_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_TX_CEASED_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_optional_elements_12, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_12 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_TX_CEASED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 232 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_TX_CEASED, U_TX_CEASED_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-TX-CEASED");


  return offset;
}


static const value_string tetra_T_prop_04_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_04_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_04, T_prop_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_09_sequence[] = {
  { &hf_tetra_prop_05       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_04 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_09, T_type2_parameters_09_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_13_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_13_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_09, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_09 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_13, T_optional_elements_13_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_TX_DEMAND_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_tx_demand_priority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_encryption_control, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_reserved_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_optional_elements_13, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_13 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_TX_DEMAND(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 227 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_TX_DEMAND, U_TX_DEMAND_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-TX-DEMAND");


  return offset;
}



static int
dissect_tetra_Other_party_address_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_tetra_Calling_party_address_type(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string tetra_T_prop_06_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_06_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_06, T_prop_06_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_11_sequence[] = {
  { &hf_tetra_prop_07       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_06 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_11, T_type2_parameters_11_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_15_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_15_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_11, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_11 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_15, T_optional_elements_15_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_CALL_RESTORE_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_request_to_transmit_send_data, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_other_party_address, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Other_party_address_type },
  { &hf_tetra_basic_service_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Basic_service_information },
  { &hf_tetra_optional_elements_15, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_15 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_CALL_RESTORE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 222 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_CALL_RESTORE, U_CALL_RESTORE_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-CALL-RESTORE");


  return offset;
}


static const value_string tetra_T_called_party_type_identifier_vals[] = {
  {   0, "sna" },
  {   1, "ssi" },
  {   2, "ssi-extension" },
  {   3, "none" },
  { 0, NULL }
};

static const per_choice_t T_called_party_type_identifier_choice[] = {
  {   0, &hf_tetra_sna           , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_255 },
  {   1, &hf_tetra_ssi           , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16777215 },
  {   2, &hf_tetra_ssi_extension , ASN1_NO_EXTENSIONS     , dissect_tetra_BIT_STRING_SIZE_48 },
  {   3, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_called_party_type_identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_called_party_type_identifier, T_called_party_type_identifier_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL);

  return offset;
}



static int
dissect_tetra_INTEGER_0_4194304(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4194304U, NULL, FALSE);

  return offset;
}


static const value_string tetra_T_short_data_type_identifier_vals[] = {
  {   0, "data-1" },
  {   1, "data-2" },
  {   2, "data-3" },
  {   3, "length-indicator-data-4" },
  { 0, NULL }
};

static const per_choice_t T_short_data_type_identifier_choice[] = {
  {   0, &hf_tetra_data_1        , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_65535 },
  {   1, &hf_tetra_data_2        , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_4 },
  {   2, &hf_tetra_data_3        , ASN1_NO_EXTENSIONS     , dissect_tetra_BIT_STRING_SIZE_64 },
  {   3, &hf_tetra_length_indicator_data_4, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_4194304 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_short_data_type_identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_short_data_type_identifier, T_short_data_type_identifier_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_SDS_DATA_sequence[] = {
  { &hf_tetra_area_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_called_party_type_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_called_party_type_identifier },
  { &hf_tetra_short_data_type_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_short_data_type_identifier },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_U_SDS_DATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 217 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_SDS_DATA, U_SDS_DATA_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-SDS-DATA");


  return offset;
}


static const value_string tetra_U_CMCE_PDU_vals[] = {
  {   0, "u-Alert" },
  {   1, "reserved1" },
  {   2, "u-Connect" },
  {   3, "reserved2" },
  {   4, "u-Disconnect" },
  {   5, "u-Info" },
  {   6, "u-Release" },
  {   7, "u-Setup" },
  {   8, "u-Status" },
  {   9, "u-Tx-Ceased" },
  {  10, "u-Tx-Demand" },
  {  11, "reserved3" },
  {  12, "reserved4" },
  {  13, "reserved5" },
  {  14, "u-Call-Restore" },
  {  15, "u-SDS-Data" },
  {  16, "u-Facility" },
  { 0, NULL }
};

static const per_choice_t U_CMCE_PDU_choice[] = {
  {   0, &hf_tetra_u_Alert       , ASN1_NO_EXTENSIONS     , dissect_tetra_U_ALERT },
  {   1, &hf_tetra_reserved1     , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   2, &hf_tetra_u_Connect     , ASN1_NO_EXTENSIONS     , dissect_tetra_U_CONNECT },
  {   3, &hf_tetra_reserved2     , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   4, &hf_tetra_u_Disconnect  , ASN1_NO_EXTENSIONS     , dissect_tetra_U_DISCONNECT },
  {   5, &hf_tetra_u_Info        , ASN1_NO_EXTENSIONS     , dissect_tetra_U_INFO },
  {   6, &hf_tetra_u_Release     , ASN1_NO_EXTENSIONS     , dissect_tetra_U_RELEASE },
  {   7, &hf_tetra_u_Setup       , ASN1_NO_EXTENSIONS     , dissect_tetra_U_SETUP },
  {   8, &hf_tetra_u_Status      , ASN1_NO_EXTENSIONS     , dissect_tetra_U_STATUS },
  {   9, &hf_tetra_u_Tx_Ceased   , ASN1_NO_EXTENSIONS     , dissect_tetra_U_TX_CEASED },
  {  10, &hf_tetra_u_Tx_Demand   , ASN1_NO_EXTENSIONS     , dissect_tetra_U_TX_DEMAND },
  {  11, &hf_tetra_reserved3     , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  12, &hf_tetra_reserved4     , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  13, &hf_tetra_reserved5     , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  14, &hf_tetra_u_Call_Restore, ASN1_NO_EXTENSIONS     , dissect_tetra_U_CALL_RESTORE },
  {  15, &hf_tetra_u_SDS_Data    , ASN1_NO_EXTENSIONS     , dissect_tetra_U_SDS_DATA },
  {  16, &hf_tetra_u_Facility    , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_U_CMCE_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_U_CMCE_PDU, U_CMCE_PDU_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_cell_number_vals[] = {
  {   0, "none" },
  {   1, "cell-number" },
  { 0, NULL }
};

static const per_choice_t T_cell_number_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_cell_number_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_65535 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_cell_number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_cell_number, T_cell_number_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_sequence[] = {
  { &hf_tetra_cell_number   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_cell_number },
  { &hf_tetra_sdu           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters, T_type2_parameters_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements, T_optional_elements_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_PREPARE_sequence[] = {
  { &hf_tetra_pdu_type_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_optional_elements, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_PREPARE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_PREPARE, U_PREPARE_sequence);

  return offset;
}


static const value_string tetra_T_mcc_vals[] = {
  {   0, "none" },
  {   1, "mcc" },
  { 0, NULL }
};

static const per_choice_t T_mcc_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_mcc           , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_1023 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_mcc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_mcc, T_mcc_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_mnc_vals[] = {
  {   0, "none" },
  {   1, "mnc" },
  { 0, NULL }
};

static const per_choice_t T_mnc_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_mnc           , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16383 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_mnc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_mnc, T_mnc_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_la_vals[] = {
  {   0, "none" },
  {   1, "la" },
  { 0, NULL }
};

static const per_choice_t T_la_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_la            , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16383 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_la(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_la, T_la_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_01_sequence[] = {
  { &hf_tetra_mcc_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_mcc },
  { &hf_tetra_mnc_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_mnc },
  { &hf_tetra_la_01         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_la },
  { &hf_tetra_sdu           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_01, T_type2_parameters_01_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_01_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_01_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_01, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_01, T_optional_elements_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_RESTORE_sequence[] = {
  { &hf_tetra_pdu_type_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_optional_elements_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_RESTORE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_RESTORE, U_RESTORE_sequence);

  return offset;
}


static const value_string tetra_UMLE_PDU_vals[] = {
  {   0, "u-prepare" },
  {   1, "umle-reserved1" },
  {   2, "umle-reserved2" },
  {   3, "umle-reserved3" },
  {   4, "u-restore" },
  {   5, "umle-reserved4" },
  {   6, "umle-reserved5" },
  {   7, "umle-reserved6" },
  { 0, NULL }
};

static const per_choice_t UMLE_PDU_choice[] = {
  {   0, &hf_tetra_u_prepare     , ASN1_NO_EXTENSIONS     , dissect_tetra_U_PREPARE },
  {   1, &hf_tetra_umle_reserved1, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   2, &hf_tetra_umle_reserved2, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   3, &hf_tetra_umle_reserved3, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   4, &hf_tetra_u_restore     , ASN1_NO_EXTENSIONS     , dissect_tetra_U_RESTORE },
  {   5, &hf_tetra_umle_reserved4, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   6, &hf_tetra_umle_reserved5, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   7, &hf_tetra_umle_reserved6, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_UMLE_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_UMLE_PDU, UMLE_PDU_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_U_MLE_PDU_vals[] = {
  {   0, "u-mle-reserved1" },
  {   1, "mm" },
  {   2, "cmce" },
  {   3, "u-mle-reserved2" },
  {   4, "sndcp" },
  {   5, "mle" },
  {   6, "tetra-management-entity-protocol" },
  {   7, "u-mle-reserved3" },
  { 0, NULL }
};

static const per_choice_t U_MLE_PDU_choice[] = {
  {   0, &hf_tetra_u_mle_reserved1, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_mm            , ASN1_NO_EXTENSIONS     , dissect_tetra_U_MM_PDU },
  {   2, &hf_tetra_cmce          , ASN1_NO_EXTENSIONS     , dissect_tetra_U_CMCE_PDU },
  {   3, &hf_tetra_u_mle_reserved2, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   4, &hf_tetra_sndcp         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   5, &hf_tetra_mle           , ASN1_NO_EXTENSIONS     , dissect_tetra_UMLE_PDU },
  {   6, &hf_tetra_tetra_management_entity_protocol, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   7, &hf_tetra_u_mle_reserved3, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_U_MLE_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_U_MLE_PDU, U_MLE_PDU_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t U_BL_ADATA_sequence[] = {
  { &hf_tetra_nr            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_ns            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_MLE_PDU },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_BL_ADATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_BL_ADATA, U_BL_ADATA_sequence);

  return offset;
}


static const per_sequence_t U_BL_DATA_sequence[] = {
  { &hf_tetra_ns            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_MLE_PDU },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_BL_DATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_BL_DATA, U_BL_DATA_sequence);

  return offset;
}


static const per_sequence_t U_BL_ACK_sequence[] = {
  { &hf_tetra_nr            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_MLE_PDU },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_BL_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_BL_ACK, U_BL_ACK_sequence);

  return offset;
}


static const per_sequence_t U_BL_ADATA_FCS_sequence[] = {
  { &hf_tetra_nr            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_ns            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_MLE_PDU },
  { &hf_tetra_fcs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_BL_ADATA_FCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_BL_ADATA_FCS, U_BL_ADATA_FCS_sequence);

  return offset;
}


static const per_sequence_t U_BL_DATA_FCS_sequence[] = {
  { &hf_tetra_ns            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_MLE_PDU },
  { &hf_tetra_fcs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_BL_DATA_FCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_BL_DATA_FCS, U_BL_DATA_FCS_sequence);

  return offset;
}


static const per_sequence_t U_MLE_PDU_FCS_sequence[] = {
  { &hf_tetra_u_mle_pdu     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_MLE_PDU },
  { &hf_tetra_fcs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_MLE_PDU_FCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_MLE_PDU_FCS, U_MLE_PDU_FCS_sequence);

  return offset;
}


static const per_sequence_t U_BL_ACK_FCS_sequence[] = {
  { &hf_tetra_nr            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_MLE_PDU },
  { &hf_tetra_fcs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_U_BL_ACK_FCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_U_BL_ACK_FCS, U_BL_ACK_FCS_sequence);

  return offset;
}


static const value_string tetra_U_LLC_PDU_vals[] = {
  {   0, "bl-adata" },
  {   1, "bl-data" },
  {   2, "bl-udata" },
  {   3, "bl-ack" },
  {   4, "bl-adata-fcs" },
  {   5, "bl-data-fcs" },
  {   6, "bl-udata-fcs" },
  {   7, "bl-ack-fcs" },
  {   8, "al-setup" },
  {   9, "al-data" },
  {  10, "al-udata" },
  {  11, "al-ack" },
  {  12, "al-reconnect" },
  {  13, "reserve1" },
  {  14, "reserve2" },
  {  15, "al-disc" },
  { 0, NULL }
};

static const per_choice_t U_LLC_PDU_choice[] = {
  {   0, &hf_tetra_bl_adata      , ASN1_NO_EXTENSIONS     , dissect_tetra_U_BL_ADATA },
  {   1, &hf_tetra_bl_data       , ASN1_NO_EXTENSIONS     , dissect_tetra_U_BL_DATA },
  {   2, &hf_tetra_bl_udata      , ASN1_NO_EXTENSIONS     , dissect_tetra_U_MLE_PDU },
  {   3, &hf_tetra_bl_ack        , ASN1_NO_EXTENSIONS     , dissect_tetra_U_BL_ACK },
  {   4, &hf_tetra_bl_adata_fcs  , ASN1_NO_EXTENSIONS     , dissect_tetra_U_BL_ADATA_FCS },
  {   5, &hf_tetra_bl_data_fcs   , ASN1_NO_EXTENSIONS     , dissect_tetra_U_BL_DATA_FCS },
  {   6, &hf_tetra_bl_udata_fcs  , ASN1_NO_EXTENSIONS     , dissect_tetra_U_MLE_PDU_FCS },
  {   7, &hf_tetra_bl_ack_fcs    , ASN1_NO_EXTENSIONS     , dissect_tetra_U_BL_ACK_FCS },
  {   8, &hf_tetra_al_setup      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   9, &hf_tetra_al_data       , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  10, &hf_tetra_al_udata      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  11, &hf_tetra_al_ack        , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  12, &hf_tetra_al_reconnect  , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  13, &hf_tetra_reserve1      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  14, &hf_tetra_reserve2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  15, &hf_tetra_al_disc       , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_U_LLC_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_U_LLC_PDU, U_LLC_PDU_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_LengthIndication_vals[] = {
  {   0, "null" },
  {   1, "reserved-1" },
  {   2, "reserved-2" },
  {   3, "bits-24" },
  {   4, "bits-32" },
  {   5, "bits-40" },
  {   6, "bits-48" },
  {   7, "bits-56" },
  {   8, "bits-64" },
  {   9, "bits-72" },
  {  10, "bits-80" },
  {  11, "bits-88" },
  {  12, "bits-96" },
  {  13, "reserved-13" },
  {  14, "reserved-14" },
  {  15, "reserved-15" },
  {  16, "reserved-16" },
  {  17, "reserved-17" },
  {  18, "reserved-18" },
  {  19, "reserved-19" },
  {  20, "reserved-20" },
  {  21, "reserved-21" },
  {  22, "reserved-22" },
  {  23, "reserved-23" },
  {  24, "reserved-24" },
  {  25, "reserved-25" },
  {  26, "reserved-26" },
  {  27, "reserved-27" },
  {  28, "reserved-28" },
  {  29, "reserved-29" },
  {  30, "reserved-30" },
  {  31, "reserved-31" },
  { 0, NULL }
};


static int
dissect_tetra_LengthIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Frag1_vals[] = {
  {   0, "not-fragmented" },
  {   1, "start-of-fragmentation" },
  { 0, NULL }
};


static int
dissect_tetra_Frag1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_SLOT_APPLY_vals[] = {
  {   0, "subslot" },
  {   1, "slot-1" },
  {   2, "slot-2" },
  {   3, "slot-3" },
  {   4, "slot-4" },
  {   5, "slot-5" },
  {   6, "slot-6" },
  {   7, "slot-8" },
  {   8, "slot-10" },
  {   9, "slot-13" },
  {  10, "slot-17" },
  {  11, "slot-24" },
  {  12, "slot-34" },
  {  13, "slot-51" },
  {  14, "slot-68" },
  {  15, "more-than-68" },
  { 0, NULL }
};


static int
dissect_tetra_SLOT_APPLY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t FRAG_sequence[] = {
  { &hf_tetra_frag          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Frag1 },
  { &hf_tetra_reservation_requirement, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_SLOT_APPLY },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_FRAG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_FRAG, FRAG_sequence);

  return offset;
}


static const value_string tetra_T_lengthIndicationOrCapacityRequest_vals[] = {
  {   0, "lengthIndication" },
  {   1, "capacityRequest" },
  { 0, NULL }
};

static const per_choice_t T_lengthIndicationOrCapacityRequest_choice[] = {
  {   0, &hf_tetra_lengthIndication, ASN1_NO_EXTENSIONS     , dissect_tetra_LengthIndication },
  {   1, &hf_tetra_capacityRequest, ASN1_NO_EXTENSIONS     , dissect_tetra_FRAG },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_lengthIndicationOrCapacityRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_lengthIndicationOrCapacityRequest, T_lengthIndicationOrCapacityRequest_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ComplexSDU_sequence[] = {
  { &hf_tetra_lengthIndicationOrCapacityRequest, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_lengthIndicationOrCapacityRequest },
  { &hf_tetra_tm_sdu_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_U_LLC_PDU },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_ComplexSDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_ComplexSDU, ComplexSDU_sequence);

  return offset;
}


static const value_string tetra_T_data_vals[] = {
  {   0, "sdu1" },
  {   1, "sdu2" },
  { 0, NULL }
};

static const per_choice_t T_data_choice[] = {
  {   0, &hf_tetra_sdu1          , ASN1_NO_EXTENSIONS     , dissect_tetra_U_LLC_PDU },
  {   1, &hf_tetra_sdu2          , ASN1_NO_EXTENSIONS     , dissect_tetra_ComplexSDU },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_data, T_data_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MAC_ACCESS_sequence[] = {
  { &hf_tetra_pdu_type_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_fill_bit_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Fill_Bit_Indication },
  { &hf_tetra_encrypted_flag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Encrypted_Flag },
  { &hf_tetra_address       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Address },
  { &hf_tetra_data          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_data },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_ACCESS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_ACCESS, MAC_ACCESS_sequence);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_264(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     264, 264, FALSE, NULL);

  return offset;
}


static const per_sequence_t MAC_FRAG_sequence[] = {
  { &hf_tetra_pdu_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_sub_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_fill_bit_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Fill_Bit_Indication },
  { &hf_tetra_tm_sdu_02     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING_SIZE_264 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_FRAG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_FRAG, MAC_FRAG_sequence);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_120(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     120, 120, FALSE, NULL);

  return offset;
}


static const per_sequence_t MAC_FRAG120_sequence[] = {
  { &hf_tetra_pdu_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_sub_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_fill_bit_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Fill_Bit_Indication },
  { &hf_tetra_tm_sdu_03     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING_SIZE_120 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_FRAG120(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_FRAG120, MAC_FRAG120_sequence);

  return offset;
}


static const value_string tetra_LengthIndOrReservationReq_vals[] = {
  {   0, "reserved-0" },
  {   1, "reserved-1" },
  {   2, "bits-16" },
  {   3, "bits-24" },
  {   4, "bits-32" },
  {   5, "bits-40" },
  {   6, "bits-48" },
  {   7, "bits-56" },
  {   8, "bits-64" },
  {   9, "bits-72" },
  {  10, "bits-80" },
  {  11, "bits-88" },
  {  12, "bits-96" },
  {  13, "bits-104" },
  {  14, "bits-112" },
  {  15, "bits-120" },
  {  16, "bits-128" },
  {  17, "bits-136" },
  {  18, "bits-144" },
  {  19, "bits-152" },
  {  20, "bits-160" },
  {  21, "bits-168" },
  {  22, "bits-176" },
  {  23, "bits-184" },
  {  24, "bits-192" },
  {  25, "bits-200" },
  {  26, "bits-208" },
  {  27, "bits-216" },
  {  28, "bits-224" },
  {  29, "bits-232" },
  {  30, "bits-240" },
  {  31, "bits-248" },
  {  32, "bits-256" },
  {  33, "bits-264" },
  {  34, "bits-272" },
  {  35, "reserved-35" },
  {  36, "reserved-36" },
  {  37, "reserved-37" },
  {  38, "reserved-38" },
  {  39, "reserved-39" },
  {  40, "reserved-40" },
  {  41, "reserved-41" },
  {  42, "reserved-42" },
  {  43, "reserved-43" },
  {  44, "reserved-44" },
  {  45, "reserved-45" },
  {  46, "reserved-46" },
  {  47, "reserved-47" },
  {  48, "subslot" },
  {  49, "slot-1" },
  {  50, "slot-2" },
  {  51, "slot-3" },
  {  52, "slot-4" },
  {  53, "slot-5" },
  {  54, "slot-6" },
  {  55, "slot-8" },
  {  56, "slot-10" },
  {  57, "slot-13" },
  {  58, "slot-17" },
  {  59, "slot-24" },
  {  60, "slot-34" },
  {  61, "slot-51" },
  {  62, "slot-68" },
  {  63, "more-than-68" },
  { 0, NULL }
};


static int
dissect_tetra_LengthIndOrReservationReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_258(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     258, 258, FALSE, NULL);

  return offset;
}


static const per_sequence_t MAC_END_UPLINK_sequence[] = {
  { &hf_tetra_pdu_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_sub_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_fill_bit_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Fill_Bit_Indication },
  { &hf_tetra_lengthInd_ReservationReq, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_LengthIndOrReservationReq },
  { &hf_tetra_tm_sdu_04     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING_SIZE_258 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_END_UPLINK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_END_UPLINK, MAC_END_UPLINK_sequence);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_114(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     114, 114, FALSE, NULL);

  return offset;
}


static const per_sequence_t MAC_END_UP114_sequence[] = {
  { &hf_tetra_pdu_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_pdu_subtype   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_fill_bit_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Fill_Bit_Indication },
  { &hf_tetra_lengthInd_ReservationReq, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_LengthIndOrReservationReq },
  { &hf_tetra_tm_sdu_05     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING_SIZE_114 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_END_UP114(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_END_UP114, MAC_END_UP114_sequence);

  return offset;
}


static const value_string tetra_LengthIndMacHu_vals[] = {
  {   0, "reserved-0" },
  {   1, "bits-8" },
  {   2, "bits-16" },
  {   3, "bits-24" },
  {   4, "bits-32" },
  {   5, "bits-40" },
  {   6, "bits-48" },
  {   7, "bits-56" },
  {   8, "bits-64" },
  {   9, "bits-72" },
  {  10, "bits-80" },
  {  11, "bits-88" },
  {  12, "bits-96" },
  {  13, "reserved-13" },
  {  14, "reserved-14" },
  {  15, "reserved-15" },
  { 0, NULL }
};


static int
dissect_tetra_LengthIndMacHu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_lengthInd_ReservationReq_vals[] = {
  {   0, "lengthInd" },
  {   1, "reservation-requirement" },
  { 0, NULL }
};

static const per_choice_t T_lengthInd_ReservationReq_choice[] = {
  {   0, &hf_tetra_lengthInd     , ASN1_NO_EXTENSIONS     , dissect_tetra_LengthIndMacHu },
  {   1, &hf_tetra_reservation_requirement, ASN1_NO_EXTENSIONS     , dissect_tetra_SLOT_APPLY },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_lengthInd_ReservationReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_lengthInd_ReservationReq, T_lengthInd_ReservationReq_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_85(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     85, 85, FALSE, NULL);

  return offset;
}


static const per_sequence_t MAC_END_HU_sequence[] = {
  { &hf_tetra_pdu_type_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_fill_bit_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Fill_Bit_Indication },
  { &hf_tetra_lengthInd_ReservationReq_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_lengthInd_ReservationReq },
  { &hf_tetra_tm_sdu_06     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING_SIZE_85 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_END_HU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_END_HU, MAC_END_HU_sequence);

  return offset;
}


static const value_string tetra_Position_Of_Grant_vals[] = {
  {   0, "on-current" },
  {   1, "on-allocated" },
  { 0, NULL }
};


static int
dissect_tetra_Position_Of_Grant(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_LengthIndicationMacEndDl_vals[] = {
  {   0, "reserved-0" },
  {   1, "reserved-1" },
  {   2, "bits-16" },
  {   3, "bits-24" },
  {   4, "bits-32" },
  {   5, "bits-40" },
  {   6, "bits-48" },
  {   7, "bits-56" },
  {   8, "bits-64" },
  {   9, "bits-72" },
  {  10, "bits-80" },
  {  11, "bits-88" },
  {  12, "bits-96" },
  {  13, "bits-104" },
  {  14, "bits-112" },
  {  15, "bits-120" },
  {  16, "bits-128" },
  {  17, "bits-136" },
  {  18, "bits-144" },
  {  19, "bits-152" },
  {  20, "bits-160" },
  {  21, "bits-168" },
  {  22, "bits-176" },
  {  23, "bits-184" },
  {  24, "bits-192" },
  {  25, "bits-200" },
  {  26, "bits-208" },
  {  27, "bits-216" },
  {  28, "bits-224" },
  {  29, "bits-232" },
  {  30, "bits-240" },
  {  31, "bits-248" },
  {  32, "bits-256" },
  {  33, "bits-264" },
  {  34, "bits-272" },
  {  35, "reserved-35" },
  {  36, "reserved-36" },
  {  37, "reserved-37" },
  {  38, "reserved-38" },
  {  39, "reserved-39" },
  {  40, "reserved-40" },
  {  41, "reserved-41" },
  {  42, "reserved-42" },
  {  43, "reserved-43" },
  {  44, "reserved-44" },
  {  45, "reserved-45" },
  {  46, "reserved-46" },
  {  47, "reserved-47" },
  {  48, "reserved-48" },
  {  49, "reserved-49" },
  {  50, "reserved-50" },
  {  51, "reserved-51" },
  {  52, "reserved-52" },
  {  53, "reserved-53" },
  {  54, "reserved-54" },
  {  55, "reserved-55" },
  {  56, "reserved-56" },
  {  57, "reserved-57" },
  {  58, "reserved-58" },
  {  59, "reserved-59" },
  {  60, "reserved-60" },
  {  61, "reserved-61" },
  {  62, "reserved-62" },
  {  63, "reserved-63" },
  { 0, NULL }
};


static int
dissect_tetra_LengthIndicationMacEndDl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Capacity_Allocation_vals[] = {
  {   0, "first-subslot" },
  {   1, "slot-allocated-1" },
  {   2, "slot-allocated-2" },
  {   3, "slot-allocated-3" },
  {   4, "slot-allocated-4" },
  {   5, "slot-allocated-5" },
  {   6, "slot-allocated-6" },
  {   7, "slot-allocated-8" },
  {   8, "slot-allocated-10" },
  {   9, "slot-allocated-13" },
  {  10, "slot-allocated-17" },
  {  11, "slot-allocated-24" },
  {  12, "slot-allocated-34" },
  {  13, "lot-allocated-51" },
  {  14, "slot-allocated-68" },
  {  15, "second-subslot" },
  { 0, NULL }
};


static int
dissect_tetra_Capacity_Allocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Granting_delay_vals[] = {
  {   0, "capacity-allocation-at-next-opportunity" },
  {   1, "number-of-opportunities-delay" },
  {   2, "number-of-opportunities-delay" },
  {   3, "number-of-opportunities-delay" },
  {   4, "number-of-opportunities-delay" },
  {   5, "number-of-opportunities-delay" },
  {   6, "number-of-opportunities-delay" },
  {   7, "number-of-opportunities-delay" },
  {   8, "number-of-opportunities-delay" },
  {   9, "number-of-opportunities-delay" },
  {  10, "number-of-opportunities-delay" },
  {  11, "number-of-opportunities-delay" },
  {  12, "number-of-opportunities-delay" },
  {  13, "number-of-opportunities-delay" },
  {  14, "allocation-starts-at-frame-18" },
  {  15, "wait" },
  { 0, NULL }
};


static int
dissect_tetra_Granting_delay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t SlotGranting_sequence[] = {
  { &hf_tetra_capacity_allocation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Capacity_Allocation },
  { &hf_tetra_granting_delay, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Granting_delay },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_SlotGranting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_SlotGranting, SlotGranting_sequence);

  return offset;
}


static const value_string tetra_T_slot_granting_vals[] = {
  {   0, "none" },
  {   1, "slot-granting-param" },
  { 0, NULL }
};

static const per_choice_t T_slot_granting_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_slot_granting_param, ASN1_NO_EXTENSIONS     , dissect_tetra_SlotGranting },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_slot_granting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_slot_granting, T_slot_granting_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_allocation_type_vals[] = {
  {   0, "replace" },
  {   1, "add" },
  {   2, "quit" },
  {   3, "reserved" },
  { 0, NULL }
};


static int
dissect_tetra_T_allocation_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Timeslot_Assigned_vals[] = {
  {   0, "go-to-control-channel" },
  {   1, "timeslot-4" },
  {   2, "timeslot-bit-map" },
  {   3, "timeslot-bit-map" },
  {   4, "timeslot-bit-map" },
  {   5, "timeslot-bit-map" },
  {   6, "timeslot-bit-map" },
  {   7, "timeslot-bit-map" },
  {   8, "timeslot-bit-map" },
  {   9, "timeslot-bit-map" },
  {  10, "timeslot-bit-map" },
  {  11, "timeslot-bit-map" },
  {  12, "timeslot-bit-map" },
  {  13, "timeslot-bit-map" },
  {  14, "timeslot-bit-map" },
  {  15, "all-four-timeslots" },
  { 0, NULL }
};


static int
dissect_tetra_Timeslot_Assigned(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_up_down_assigned_vals[] = {
  {   0, "reserve" },
  {   1, "downlink-only" },
  {   2, "uplink-only" },
  {   3, "uplink-downlink" },
  { 0, NULL }
};


static int
dissect_tetra_T_up_down_assigned(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_CLCH_permission_vals[] = {
  {   0, "no-permission" },
  {   1, "permission" },
  { 0, NULL }
};


static int
dissect_tetra_CLCH_permission(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_Cell_change_flag_vals[] = {
  {   0, "no-change" },
  {   1, "change" },
  { 0, NULL }
};


static int
dissect_tetra_Cell_change_flag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_reverse_operation_vals[] = {
  {   0, "normal" },
  {   1, "reverse" },
  { 0, NULL }
};


static int
dissect_tetra_T_reverse_operation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Extended_carrier_flag_sequence[] = {
  { &hf_tetra_frequency_band, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_offset_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_duplex_spacing, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_reverse_operation_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_reverse_operation },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_Extended_carrier_flag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_Extended_carrier_flag, Extended_carrier_flag_sequence);

  return offset;
}


static const value_string tetra_T_extend_carrier_flag_vals[] = {
  {   0, "none" },
  {   1, "extended" },
  { 0, NULL }
};

static const per_choice_t T_extend_carrier_flag_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_extended      , ASN1_NO_EXTENSIONS     , dissect_tetra_Extended_carrier_flag },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_extend_carrier_flag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_extend_carrier_flag, T_extend_carrier_flag_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_Monitoring_pattern_vals[] = {
  {   0, "no" },
  {   1, "one" },
  {   2, "two" },
  {   3, "three" },
  { 0, NULL }
};


static int
dissect_tetra_Monitoring_pattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_monitoring_pattern_vals[] = {
  {   0, "one" },
  {   1, "none1" },
  {   2, "none2" },
  {   3, "none3" },
  { 0, NULL }
};

static const per_choice_t T_monitoring_pattern_choice[] = {
  {   0, &hf_tetra_one           , ASN1_NO_EXTENSIONS     , dissect_tetra_Monitoring_pattern },
  {   1, &hf_tetra_none1         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   2, &hf_tetra_none2         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   3, &hf_tetra_none3         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_monitoring_pattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_monitoring_pattern, T_monitoring_pattern_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ChannelAllocation_sequence[] = {
  { &hf_tetra_allocation_type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_allocation_type },
  { &hf_tetra_timeslot_assigned, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Timeslot_Assigned },
  { &hf_tetra_up_down_assigned, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_up_down_assigned },
  { &hf_tetra_clch_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_CLCH_permission },
  { &hf_tetra_cell_change   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Cell_change_flag },
  { &hf_tetra_carrier_number, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_4095 },
  { &hf_tetra_extend_carrier_flag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_extend_carrier_flag },
  { &hf_tetra_monitoring_pattern, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_monitoring_pattern },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_ChannelAllocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_ChannelAllocation, ChannelAllocation_sequence);

  return offset;
}


static const value_string tetra_T_channel_allocation_vals[] = {
  {   0, "none" },
  {   1, "channel-allocation-element" },
  { 0, NULL }
};

static const per_choice_t T_channel_allocation_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_channel_allocation_element, ASN1_NO_EXTENSIONS     , dissect_tetra_ChannelAllocation },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_channel_allocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_channel_allocation, T_channel_allocation_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     255, 255, FALSE, NULL);

  return offset;
}


static const per_sequence_t MAC_END_DOWNLINK_sequence[] = {
  { &hf_tetra_pdu_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_sub_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_fill_bit_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Fill_Bit_Indication },
  { &hf_tetra_position_of_grant, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Position_Of_Grant },
  { &hf_tetra_lengthIndication_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_LengthIndicationMacEndDl },
  { &hf_tetra_slot_granting , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_slot_granting },
  { &hf_tetra_channel_allocation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_channel_allocation },
  { &hf_tetra_tm_sdu_07     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING_SIZE_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_END_DOWNLINK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_END_DOWNLINK, MAC_END_DOWNLINK_sequence);

  return offset;
}


static const value_string tetra_T_slot_granting_01_vals[] = {
  {   0, "none" },
  {   1, "slot-granting-param" },
  { 0, NULL }
};

static const per_choice_t T_slot_granting_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_slot_granting_param, ASN1_NO_EXTENSIONS     , dissect_tetra_SlotGranting },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_slot_granting_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_slot_granting_01, T_slot_granting_01_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_channel_allocation_01_vals[] = {
  {   0, "none" },
  {   1, "channel-allocation-element" },
  { 0, NULL }
};

static const per_choice_t T_channel_allocation_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_channel_allocation_element, ASN1_NO_EXTENSIONS     , dissect_tetra_ChannelAllocation },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_channel_allocation_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_channel_allocation_01, T_channel_allocation_01_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_111(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     111, 111, FALSE, NULL);

  return offset;
}


static const per_sequence_t MAC_END_DOWN111_sequence[] = {
  { &hf_tetra_pdu_type_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_fill_bit_ind  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_position_of_grant_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_lengthIndication_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_LengthIndicationMacEndDl },
  { &hf_tetra_slot_granting_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_slot_granting_01 },
  { &hf_tetra_channel_allocation_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_channel_allocation_01 },
  { &hf_tetra_tm_sdu_08     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING_SIZE_111 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_END_DOWN111(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_END_DOWN111, MAC_END_DOWN111_sequence);

  return offset;
}


static const value_string tetra_T_access_ack_vals[] = {
  {   0, "undefined" },
  {   1, "random-access-acknowledged" },
  { 0, NULL }
};


static int
dissect_tetra_T_access_ack(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_LengthIndicationMacResource_vals[] = {
  {   0, "reserved-0" },
  {   1, "reserved-1" },
  {   2, "null-pdu" },
  {   3, "reserved" },
  {   4, "bits-32" },
  {   5, "bits-40" },
  {   6, "bits-48" },
  {   7, "bits-56" },
  {   8, "bits-64" },
  {   9, "bits-72" },
  {  10, "bits-80" },
  {  11, "bits-88" },
  {  12, "bits-96" },
  {  13, "bits-104" },
  {  14, "bits-112" },
  {  15, "bits-120" },
  {  16, "bits-128" },
  {  17, "bits-136" },
  {  18, "bits-144" },
  {  19, "bits-152" },
  {  20, "bits-160" },
  {  21, "bits-168" },
  {  22, "bits-176" },
  {  23, "bits-184" },
  {  24, "bits-192" },
  {  25, "bits-200" },
  {  26, "bits-208" },
  {  27, "bits-216" },
  {  28, "bits-224" },
  {  29, "bits-232" },
  {  30, "bits-240" },
  {  31, "bits-248" },
  {  32, "bits-256" },
  {  33, "bits-264" },
  {  34, "bits-272" },
  {  35, "reserved-35" },
  {  36, "reserved-36" },
  {  37, "reserved-37" },
  {  38, "reserved-38" },
  {  39, "reserved-39" },
  {  40, "reserved-40" },
  {  41, "reserved-41" },
  {  42, "reserved-42" },
  {  43, "reserved-43" },
  {  44, "reserved-44" },
  {  45, "reserved-45" },
  {  46, "reserved-46" },
  {  47, "reserved-47" },
  {  48, "reserved-48" },
  {  49, "reserved-49" },
  {  50, "reserved-50" },
  {  51, "reserved-51" },
  {  52, "reserved-52" },
  {  53, "reserved-53" },
  {  54, "reserved-54" },
  {  55, "reserved-55" },
  {  56, "reserved-56" },
  {  57, "reserved-57" },
  {  58, "reserved-58" },
  {  59, "reserved-59" },
  {  60, "reserved-60" },
  {  61, "reserved-61" },
  {  62, "second-halfslot-stolen" },
  {  63, "start-frag" },
  { 0, NULL }
};


static int
dissect_tetra_LengthIndicationMacResource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_PowerControl_vals[] = {
  {   0, "no-change" },
  {   1, "increase-1" },
  {   2, "increase-2" },
  {   3, "increase-3" },
  {   4, "increase-4" },
  {   5, "increase-5" },
  {   6, "increase-6" },
  {   7, "maximum-xceeded" },
  {   8, "revert-open-loop-control" },
  {   9, "decrease-1" },
  {  10, "decrease-2" },
  {  11, "decrease-3" },
  {  12, "decrease-4" },
  {  13, "decrease-5" },
  {  14, "decrease-6" },
  {  15, "radio-uplink-failure" },
  { 0, NULL }
};


static int
dissect_tetra_PowerControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_power_control_vals[] = {
  {   0, "none" },
  {   1, "powerParameters" },
  { 0, NULL }
};

static const per_choice_t T_power_control_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_powerParameters, ASN1_NO_EXTENSIONS     , dissect_tetra_PowerControl },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_power_control(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_power_control, T_power_control_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_slot_granting_02_vals[] = {
  {   0, "none" },
  {   1, "slot-granting-param" },
  { 0, NULL }
};

static const per_choice_t T_slot_granting_02_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_slot_granting_param, ASN1_NO_EXTENSIONS     , dissect_tetra_SlotGranting },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_slot_granting_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_slot_granting_02, T_slot_granting_02_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_channel_allocation_02_vals[] = {
  {   0, "none" },
  {   1, "channel-allocation-element" },
  { 0, NULL }
};

static const per_choice_t T_channel_allocation_02_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_channel_allocation_element, ASN1_NO_EXTENSIONS     , dissect_tetra_ChannelAllocation },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_channel_allocation_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_channel_allocation_02, T_channel_allocation_02_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_ssi_vals[] = {
  {   0, "none" },
  {   1, "ssi" },
  { 0, NULL }
};

static const per_choice_t T_ssi_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_ssi_03        , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_ssi(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_ssi, T_ssi_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_address_extension_vals[] = {
  {   0, "none" },
  {   1, "address-extension" },
  { 0, NULL }
};

static const per_choice_t T_address_extension_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_address_extension_01, ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_address_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_address_extension, T_address_extension_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}


static const value_string tetra_T_suscriber_class_vals[] = {
  {   0, "none" },
  {   1, "suscriber-class" },
  { 0, NULL }
};

static const per_choice_t T_suscriber_class_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_suscriber_class_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_32767 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_suscriber_class(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_suscriber_class, T_suscriber_class_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_energy_saving_mode_vals[] = {
  {   0, "none" },
  {   1, "energy-saving-mode" },
  { 0, NULL }
};

static const per_choice_t T_energy_saving_mode_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_energy_saving_mode_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_7 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_energy_saving_mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_energy_saving_mode, T_energy_saving_mode_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_scch_info_vals[] = {
  {   0, "none" },
  {   1, "scch-info" },
  { 0, NULL }
};

static const per_choice_t T_scch_info_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_scch_info_01  , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16383 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_scch_info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_scch_info, T_scch_info_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_new_ra_vals[] = {
  {   0, "none" },
  {   1, "new-ra" },
  { 0, NULL }
};

static const per_choice_t T_new_ra_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_new_ra_01     , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_new_ra(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_new_ra, T_new_ra_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_group_identity_location_accept_vals[] = {
  {   0, "none" },
  {   1, "group-identity-location-accept" },
  { 0, NULL }
};

static const per_choice_t T_group_identity_location_accept_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_group_identity_location_accept_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_group_identity_location_accept(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_group_identity_location_accept, T_group_identity_location_accept_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_group_predefined_lifetime_vals[] = {
  {   0, "none" },
  {   1, "group-predefined-lifetime" },
  { 0, NULL }
};

static const per_choice_t T_group_predefined_lifetime_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_group_predefined_lifetime_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_group_predefined_lifetime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_group_predefined_lifetime, T_group_predefined_lifetime_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_group_identity_downlink_vals[] = {
  {   0, "none" },
  {   1, "group-identity-downlink" },
  { 0, NULL }
};

static const per_choice_t T_group_identity_downlink_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_group_identity_downlink_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_15 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_group_identity_downlink(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_group_identity_downlink, T_group_identity_downlink_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_proprietary_vals[] = {
  {   0, "none" },
  {   1, "proprietary" },
  { 0, NULL }
};

static const per_choice_t T_proprietary_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_proprietary_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_7 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_proprietary(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_proprietary, T_proprietary_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type3_elements_sequence[] = {
  { &hf_tetra_type2_existance, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_type3_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_TYPE3_IDENTIFIER },
  { &hf_tetra_new_ra        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_new_ra },
  { &hf_tetra_group_identity_location_accept, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_group_identity_location_accept },
  { &hf_tetra_group_predefined_lifetime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_group_predefined_lifetime },
  { &hf_tetra_group_identity_downlink, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_group_identity_downlink },
  { &hf_tetra_proprietary   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_proprietary },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type3_elements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type3_elements, T_type3_elements_sequence);

  return offset;
}


static const value_string tetra_T_type3_vals[] = {
  {   0, "no-type3" },
  {   1, "type3-elements" },
  { 0, NULL }
};

static const per_choice_t T_type3_choice[] = {
  {   0, &hf_tetra_no_type3      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type3_elements, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type3_elements },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_type3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_type3, T_type3_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_03_sequence[] = {
  { &hf_tetra_ssi_02        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_ssi },
  { &hf_tetra_address_extension, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_address_extension },
  { &hf_tetra_suscriber_class, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_suscriber_class },
  { &hf_tetra_energy_saving_mode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_energy_saving_mode },
  { &hf_tetra_scch_info     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_scch_info },
  { &hf_tetra_type3         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_type3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_03, T_type2_parameters_03_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_05_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_05_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_03, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_05, T_optional_elements_05_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_LOCATION_UPDATE_ACCEPT_sequence[] = {
  { &hf_tetra_location_update_type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_UPDATE_TYPE },
  { &hf_tetra_optional_elements_05, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_05 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_LOCATION_UPDATE_ACCEPT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 108 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_LOCATION_UPDATE_ACCEPT, D_LOCATION_UPDATE_ACCEPT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-LOCATION-UPDATE-ACCEPT");


  return offset;
}


static const per_sequence_t D_LOCATION_UPDATE_REJECT_sequence[] = {
  { &hf_tetra_location_update_type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_UPDATE_TYPE },
  { &hf_tetra_reject_cause  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_31 },
  { &hf_tetra_cipher_control, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_LOCATION_UPDATE_REJECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 258 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_LOCATION_UPDATE_REJECT, D_LOCATION_UPDATE_REJECT_sequence);

		col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-LOCATION-UPDATE-REJECT");


  return offset;
}


static const per_sequence_t T_attach_sequence[] = {
  { &hf_tetra_lifetime      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_class_of_usage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_attach(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_attach, T_attach_sequence);

  return offset;
}


static const value_string tetra_T_detach_downlike_vals[] = {
  {   0, "unknow-gssi" },
  {   1, "temporary-detachment1" },
  {   2, "temporary-detachment2" },
  {   3, "permanent-detachment" },
  { 0, NULL }
};


static int
dissect_tetra_T_detach_downlike(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_detach_sequence[] = {
  { &hf_tetra_detach_downlike, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_detach_downlike },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_detach(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_detach, T_detach_sequence);

  return offset;
}


static const value_string tetra_T_attach_detach_identifiet_vals[] = {
  {   0, "attach" },
  {   1, "detach" },
  { 0, NULL }
};

static const per_choice_t T_attach_detach_identifiet_choice[] = {
  {   0, &hf_tetra_attach        , ASN1_NO_EXTENSIONS     , dissect_tetra_T_attach },
  {   1, &hf_tetra_detach        , ASN1_NO_EXTENSIONS     , dissect_tetra_T_detach },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_attach_detach_identifiet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_attach_detach_identifiet, T_attach_detach_identifiet_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_gssi_extension_sequence[] = {
  { &hf_tetra_gssi_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_3 },
  { &hf_tetra_extension     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_gssi_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_gssi_extension, T_gssi_extension_sequence);

  return offset;
}


static const value_string tetra_T_address_type_vals[] = {
  {   0, "gssi" },
  {   1, "gssi-extension" },
  {   2, "vgssi" },
  { 0, NULL }
};

static const per_choice_t T_address_type_choice[] = {
  {   0, &hf_tetra_gssi_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_3 },
  {   1, &hf_tetra_gssi_extension, ASN1_NO_EXTENSIONS     , dissect_tetra_T_gssi_extension },
  {   2, &hf_tetra_vgssi         , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_address_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_address_type, T_address_type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GROUP_IDENTITY_DOWNLINK_sequence[] = {
  { &hf_tetra_attach_detach_identifiet, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_attach_detach_identifiet },
  { &hf_tetra_address_type  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_address_type },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_GROUP_IDENTITY_DOWNLINK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_GROUP_IDENTITY_DOWNLINK, GROUP_IDENTITY_DOWNLINK_sequence);

  return offset;
}


static const per_sequence_t T_type3_elements_04_sequence[] = {
  { &hf_tetra_type3_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_TYPE3_IDENTIFIER },
  { &hf_tetra_length        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_2047 },
  { &hf_tetra_repeat_num    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_group_identity_downlink_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_GROUP_IDENTITY_DOWNLINK },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type3_elements_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type3_elements_04, T_type3_elements_04_sequence);

  return offset;
}


static const value_string tetra_T_type3_04_vals[] = {
  {   0, "no-type3" },
  {   1, "type3-elements" },
  { 0, NULL }
};

static const per_choice_t T_type3_04_choice[] = {
  {   0, &hf_tetra_no_type3      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type3_elements_04, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type3_elements_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_type3_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_type3_04, T_type3_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_element_02_sequence[] = {
  { &hf_tetra_type3_04      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_type3_04 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_element_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_element_02, T_type2_element_02_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_24_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-element" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_24_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_element_02, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_element_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_24, T_optional_elements_24_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_ATTACH_DETACH_GROUP_IDENTITY_sequence[] = {
  { &hf_tetra_group_identity_report, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_group_identity_ack_request, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_group_identity_attach_detach_mode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_optional_elements_24, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_24 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_ATTACH_DETACH_GROUP_IDENTITY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 263 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_ATTACH_DETACH_GROUP_IDENTITY, D_ATTACH_DETACH_GROUP_IDENTITY_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-ATTACH-DETACH-GROUP-IDENTITY");


  return offset;
}


static const per_sequence_t T_type3_elements_05_sequence[] = {
  { &hf_tetra_type3_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_TYPE3_IDENTIFIER },
  { &hf_tetra_length        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_2047 },
  { &hf_tetra_repeat_num    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_group_identity_downlink_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_GROUP_IDENTITY_DOWNLINK },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type3_elements_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type3_elements_05, T_type3_elements_05_sequence);

  return offset;
}


static const value_string tetra_T_type3_05_vals[] = {
  {   0, "no-type3" },
  {   1, "type3-elements" },
  { 0, NULL }
};

static const per_choice_t T_type3_05_choice[] = {
  {   0, &hf_tetra_no_type3      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type3_elements_05, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type3_elements_05 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_type3_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_type3_05, T_type3_05_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_element_03_sequence[] = {
  { &hf_tetra_type3_05      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_type3_05 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_element_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_element_03, T_type2_element_03_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_25_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-element" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_25_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_element_03, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_element_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_25, T_optional_elements_25_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_ATTACH_DETACH_GROUP_IDENTITY_ACK_sequence[] = {
  { &hf_tetra_group_identity_attach_detach_accept, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_reserved_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_optional_elements_25, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_25 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_ATTACH_DETACH_GROUP_IDENTITY_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 268 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_ATTACH_DETACH_GROUP_IDENTITY_ACK, D_ATTACH_DETACH_GROUP_IDENTITY_ACK_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-ATTACH-DETACH-GROUP-IDENTITY-ACK");


  return offset;
}


static const per_sequence_t D_MM_STATUS_sequence[] = {
  { &hf_tetra_status_downlink, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_MM_STATUS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 243 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_MM_STATUS, D_MM_STATUS_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "U-MM-STATUS");


  return offset;
}


static const value_string tetra_D_MM_PDU_vals[] = {
  {   0, "d-Otar" },
  {   1, "d-Authentication" },
  {   2, "d-Authentication-Reject" },
  {   3, "d-Disable" },
  {   4, "d-Enable" },
  {   5, "d-Location-Update-Accept" },
  {   6, "d-Location-Update-Command" },
  {   7, "d-Location-Update-Reject" },
  {   8, "d-MM-reserved2" },
  {   9, "d-Location-Update-Proceeding" },
  {  10, "d-Attach-Detach-Group-Identity" },
  {  11, "d-Attach-Detach-Group-Identity-Ack" },
  {  12, "d-MM-Status" },
  {  13, "d-MM-reserved5" },
  {  14, "d-MM-reserved6" },
  {  15, "d-MM-Function-Not-Support" },
  { 0, NULL }
};

static const per_choice_t D_MM_PDU_choice[] = {
  {   0, &hf_tetra_d_Otar        , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_d_Authentication, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   2, &hf_tetra_d_Authentication_Reject, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   3, &hf_tetra_d_Disable     , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   4, &hf_tetra_d_Enable      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   5, &hf_tetra_d_Location_Update_Accept, ASN1_NO_EXTENSIONS     , dissect_tetra_D_LOCATION_UPDATE_ACCEPT },
  {   6, &hf_tetra_d_Location_Update_Command, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   7, &hf_tetra_d_Location_Update_Reject, ASN1_NO_EXTENSIONS     , dissect_tetra_D_LOCATION_UPDATE_REJECT },
  {   8, &hf_tetra_d_MM_reserved2, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   9, &hf_tetra_d_Location_Update_Proceeding, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  10, &hf_tetra_d_Attach_Detach_Group_Identity, ASN1_NO_EXTENSIONS     , dissect_tetra_D_ATTACH_DETACH_GROUP_IDENTITY },
  {  11, &hf_tetra_d_Attach_Detach_Group_Identity_Ack, ASN1_NO_EXTENSIONS     , dissect_tetra_D_ATTACH_DETACH_GROUP_IDENTITY_ACK },
  {  12, &hf_tetra_d_MM_Status   , ASN1_NO_EXTENSIONS     , dissect_tetra_D_MM_STATUS },
  {  13, &hf_tetra_d_MM_reserved5, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  14, &hf_tetra_d_MM_reserved6, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  15, &hf_tetra_d_MM_Function_Not_Support, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_D_MM_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_D_MM_PDU, D_MM_PDU_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_simplex_duplex_selection_03_vals[] = {
  {   0, "simplex" },
  {   1, "duplex" },
  { 0, NULL }
};


static int
dissect_tetra_T_simplex_duplex_selection_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_basic_service_infomation_vals[] = {
  {   0, "none" },
  {   1, "basic-service-infomation" },
  { 0, NULL }
};

static const per_choice_t T_basic_service_infomation_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_basic_service_infomation_01, ASN1_NO_EXTENSIONS     , dissect_tetra_Basic_service_information },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_basic_service_infomation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_basic_service_infomation, T_basic_service_infomation_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_notification_indicator_01_vals[] = {
  {   0, "none" },
  {   1, "notification-indicator" },
  { 0, NULL }
};

static const per_choice_t T_notification_indicator_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_notification_indicator_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_63 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_notification_indicator_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_notification_indicator_01, T_notification_indicator_01_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_09_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_09_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_09, T_prop_09_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_14_sequence[] = {
  { &hf_tetra_basic_service_infomation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_basic_service_infomation },
  { &hf_tetra_notification_indicator_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_notification_indicator_01 },
  { &hf_tetra_prop_10       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_09 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_14, T_type2_parameters_14_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_18_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_18_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_14, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_14 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_18, T_optional_elements_18_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_ALERT_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_call_time_out_setup_phase, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_reserved_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_simplex_duplex_selection_04, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_simplex_duplex_selection_03 },
  { &hf_tetra_call_queued   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_optional_elements_18, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_18 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_ALERT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 139 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_ALERT, D_ALERT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-ALERT");


  return offset;
}


static const value_string tetra_T_basic_service_information_02_vals[] = {
  {   0, "none" },
  {   1, "basic-service-information" },
  { 0, NULL }
};

static const per_choice_t T_basic_service_information_02_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_basic_service_information, ASN1_NO_EXTENSIONS     , dissect_tetra_Basic_service_information },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_basic_service_information_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_basic_service_information_02, T_basic_service_information_02_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_call_status_vals[] = {
  {   0, "none" },
  {   1, "call-status" },
  { 0, NULL }
};

static const per_choice_t T_call_status_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_call_status_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_7 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_call_status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_call_status, T_call_status_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_notification_indicator_vals[] = {
  {   0, "none" },
  {   1, "notification-indicator" },
  { 0, NULL }
};

static const per_choice_t T_notification_indicator_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_notification_indicator_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_63 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_notification_indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_notification_indicator, T_notification_indicator_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_08_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_08_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_08, T_prop_08_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_13_sequence[] = {
  { &hf_tetra_basic_service_information_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_basic_service_information_02 },
  { &hf_tetra_call_status   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_call_status },
  { &hf_tetra_notification_indicator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_notification_indicator },
  { &hf_tetra_prop_09       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_08 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_13, T_type2_parameters_13_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_17_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_17_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_13, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_13 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_17, T_optional_elements_17_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_CALL_PROCEEDING_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_call_time_out_setup_phase, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_hook_method_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_simplex_duplex_selection_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_optional_elements_17, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_17 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_CALL_PROCEEDING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 91 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_CALL_PROCEEDING, D_CALL_PROCEEDING_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-CALL-PROCEEDING");


  return offset;
}


static const value_string tetra_T_simplex_duplex_selection_04_vals[] = {
  {   0, "simplex" },
  {   1, "duplex" },
  { 0, NULL }
};


static int
dissect_tetra_T_simplex_duplex_selection_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_call_priority_vals[] = {
  {   0, "none" },
  {   1, "call-priority" },
  { 0, NULL }
};

static const per_choice_t T_call_priority_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_call_priority_02, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_31 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_call_priority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_call_priority, T_call_priority_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_basic_service_information_03_vals[] = {
  {   0, "none" },
  {   1, "basic-service-information" },
  { 0, NULL }
};

static const per_choice_t T_basic_service_information_03_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_basic_service_information, ASN1_NO_EXTENSIONS     , dissect_tetra_Basic_service_information },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_basic_service_information_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_basic_service_information_03, T_basic_service_information_03_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_temporary_address_vals[] = {
  {   0, "none" },
  {   1, "temporary-address" },
  { 0, NULL }
};

static const per_choice_t T_temporary_address_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_temporary_address_01, ASN1_NO_EXTENSIONS     , dissect_tetra_Calling_party_address_type },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_temporary_address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_temporary_address, T_temporary_address_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_notification_indicator_02_vals[] = {
  {   0, "none" },
  {   1, "notification-indicator" },
  { 0, NULL }
};

static const per_choice_t T_notification_indicator_02_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_notification_indicator_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_63 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_notification_indicator_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_notification_indicator_02, T_notification_indicator_02_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_10_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_10_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_10, T_prop_10_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_15_sequence[] = {
  { &hf_tetra_call_priority_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_call_priority },
  { &hf_tetra_basic_service_information_04, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_basic_service_information_03 },
  { &hf_tetra_temporary_address, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_temporary_address },
  { &hf_tetra_notification_indicator_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_notification_indicator_02 },
  { &hf_tetra_prop_11       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_15, T_type2_parameters_15_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_19_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_19_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_15, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_15 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_19, T_optional_elements_19_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_CONNECT_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_call_time_out_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_31 },
  { &hf_tetra_hook_method_selection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BOOLEAN },
  { &hf_tetra_simplex_duplex_selection_05, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_simplex_duplex_selection_04 },
  { &hf_tetra_transmission_grant, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_transmission_request_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_call_ownership, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_optional_elements_19, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_19 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_CONNECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 114 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_CONNECT, D_CONNECT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-CONNECT");


  return offset;
}


static const value_string tetra_T_notification_indicator_03_vals[] = {
  {   0, "none" },
  {   1, "notification-indicator" },
  { 0, NULL }
};

static const per_choice_t T_notification_indicator_03_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_notification_indicator_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_63 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_notification_indicator_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_notification_indicator_03, T_notification_indicator_03_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_11_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_11_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_11, T_prop_11_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_16_sequence[] = {
  { &hf_tetra_notification_indicator_04, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_notification_indicator_03 },
  { &hf_tetra_prop_12       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_11 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_16, T_type2_parameters_16_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_20_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_20_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_16, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_20, T_optional_elements_20_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_CONNECT_ACK_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_call_time_out , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_transmission_grant, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_transmission_request_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_optional_elements_20, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_20 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_CONNECT_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 124 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_CONNECT_ACK, D_CONNECT_ACK_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-CONNECT-ACK");


  return offset;
}


static const per_sequence_t D_DISCONNECT_sequence[] = {
  { &hf_tetra_call_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_disconnect_cause, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_31 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_DISCONNECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 134 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_DISCONNECT, D_DISCONNECT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-DISCONNECT");


  return offset;
}


static const per_sequence_t D_INFO_sequence[] = {
  { &hf_tetra_call_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_reset_call_time_out_timer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_poll_request  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_INFO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 129 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_INFO, D_INFO_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-INFO");


  return offset;
}


static const value_string tetra_T_notification_indicator_04_vals[] = {
  {   0, "none" },
  {   1, "notification-indicator" },
  { 0, NULL }
};

static const per_choice_t T_notification_indicator_04_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_notification_indicator_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_63 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_notification_indicator_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_notification_indicator_04, T_notification_indicator_04_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_12_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_12_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_12, T_prop_12_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_17_sequence[] = {
  { &hf_tetra_notification_indicator_05, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_notification_indicator_04 },
  { &hf_tetra_prop_13       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_12 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_17, T_type2_parameters_17_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_21_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_21_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_17, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_17 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_21, T_optional_elements_21_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_RELEASE_sequence[] = {
  { &hf_tetra_call_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_disconnect_cause, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_31 },
  { &hf_tetra_optional_elements_21, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_21 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_RELEASE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 84 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_RELEASE, D_RELEASE_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-RELEASE");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_RELEASE, D_RELEASE_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-RELEASE");


  return offset;
}


static const value_string tetra_T_simplex_duplex_selection_02_vals[] = {
  {   0, "simplex" },
  {   1, "duplex" },
  { 0, NULL }
};


static int
dissect_tetra_T_simplex_duplex_selection_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string tetra_T_calling_party_address_vals[] = {
  {   0, "none" },
  {   1, "calling-party-address" },
  { 0, NULL }
};

static const per_choice_t T_calling_party_address_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_calling_party_address_01, ASN1_NO_EXTENSIONS     , dissect_tetra_Calling_party_address_type },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_calling_party_address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_calling_party_address, T_calling_party_address_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_external_subscriber_number_01_vals[] = {
  {   0, "none" },
  {   1, "external-subscriber-number" },
  { 0, NULL }
};

static const per_choice_t T_external_subscriber_number_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_external_subscriber_number_03, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_15 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_external_subscriber_number_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_external_subscriber_number_01, T_external_subscriber_number_01_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_07_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_07_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_07, T_prop_07_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_12_sequence[] = {
  { &hf_tetra_calling_party_address, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_calling_party_address },
  { &hf_tetra_external_subscriber_number_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_external_subscriber_number_01 },
  { &hf_tetra_prop_08       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_07 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_12, T_type2_parameters_12_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_16_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_16_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_12, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_12 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_16, T_optional_elements_16_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_SETUP_sequence[] = {
  { &hf_tetra_call_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_call_time_out , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_hook_method_selection_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_simplex_duplex_selection_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_simplex_duplex_selection_02 },
  { &hf_tetra_basic_service_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Basic_service_information },
  { &hf_tetra_transmission_grant, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_transmission_request_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_call_priority , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_optional_elements_16, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_16 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_SETUP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 96 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_SETUP, D_SETUP_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-SETUP");


  return offset;
}



static int
dissect_tetra_OCTET_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, FALSE, NULL);

  return offset;
}


static const value_string tetra_T_calling_party_type_identifier_01_vals[] = {
  {   0, "none1" },
  {   1, "calling-party-address-SSI" },
  {   2, "ssi-extension" },
  {   3, "none2" },
  { 0, NULL }
};

static const per_choice_t T_calling_party_type_identifier_01_choice[] = {
  {   0, &hf_tetra_none1         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_calling_party_address_SSI, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16777215 },
  {   2, &hf_tetra_ssi_extension_01, ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_6 },
  {   3, &hf_tetra_none2         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_calling_party_type_identifier_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_calling_party_type_identifier_01, T_calling_party_type_identifier_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_STATUS_sequence[] = {
  { &hf_tetra_calling_party_type_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_calling_party_type_identifier_01 },
  { &hf_tetra_pre_coded_status, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_STATUS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 150 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_STATUS, D_STATUS_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-STATUS");


  return offset;
}


static const value_string tetra_T_notification_indicator_06_vals[] = {
  {   0, "none" },
  {   1, "notification-indicator" },
  { 0, NULL }
};

static const per_choice_t T_notification_indicator_06_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_notification_indicator_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_63 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_notification_indicator_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_notification_indicator_06, T_notification_indicator_06_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_14_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_14_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_14, T_prop_14_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_19_sequence[] = {
  { &hf_tetra_notification_indicator_07, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_notification_indicator_06 },
  { &hf_tetra_prop_15       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_14 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_19, T_type2_parameters_19_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_23_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_23_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_19, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_19 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_23, T_optional_elements_23_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_TX_CEASED_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_transmission_request_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_optional_elements_23, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_23 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_TX_CEASED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 144 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_TX_CEASED, D_TX_CEASED_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-TX-CEASED");


  return offset;
}


static const per_sequence_t D_TX_CONTINUE_sequence[] = {
  { &hf_tetra_call_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_continue      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_transmission_request_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_TX_CONTINUE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 155 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_TX_CONTINUE, D_TX_CONTINUE_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-TX-CONTINUE");


  return offset;
}


static const per_sequence_t D_TX_GRANTED_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_transmission_grant, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_transmission_request_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_encryption_control, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_reserved_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_TX_GRANTED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 160 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_TX_GRANTED, D_TX_GRANTED_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-TX-GRANTED");



  return offset;
}


static const per_sequence_t D_TX_WAIT_sequence[] = {
  { &hf_tetra_call_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16383 },
  { &hf_tetra_transmission_request_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_TX_WAIT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 166 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_TX_WAIT, D_TX_WAIT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-TX-WAIT");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_TX_WAIT, D_TX_WAIT_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-TX-WAIT");


  return offset;
}


static const value_string tetra_T_new_call_identifier_vals[] = {
  {   0, "none" },
  {   1, "new-call-identifier" },
  { 0, NULL }
};

static const per_choice_t T_new_call_identifier_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_new_call_identifier_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_1023 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_new_call_identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_new_call_identifier, T_new_call_identifier_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_call_time_out_vals[] = {
  {   0, "none" },
  {   1, "call-time-out" },
  { 0, NULL }
};

static const per_choice_t T_call_time_out_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_call_time_out_03, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_7 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_call_time_out(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_call_time_out, T_call_time_out_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_call_status_01_vals[] = {
  {   0, "none" },
  {   1, "call-status" },
  { 0, NULL }
};

static const per_choice_t T_call_status_01_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_call_status_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_7 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_call_status_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_call_status_01, T_call_status_01_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_simplex_duplex_selection_05_vals[] = {
  {   0, "simplex" },
  {   1, "duplex" },
  { 0, NULL }
};


static int
dissect_tetra_T_simplex_duplex_selection_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Modify_type_sequence[] = {
  { &hf_tetra_simplex_duplex_selection_06, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_simplex_duplex_selection_05 },
  { &hf_tetra_basic_service_information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Basic_service_information },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_Modify_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_Modify_type, Modify_type_sequence);

  return offset;
}


static const value_string tetra_T_modify_vals[] = {
  {   0, "none" },
  {   1, "modify" },
  { 0, NULL }
};

static const per_choice_t T_modify_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_modify_01     , ASN1_NO_EXTENSIONS     , dissect_tetra_Modify_type },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_modify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_modify, T_modify_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_notification_indicator_05_vals[] = {
  {   0, "none" },
  {   1, "notification-indicator" },
  { 0, NULL }
};

static const per_choice_t T_notification_indicator_05_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_notification_indicator_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_63 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_notification_indicator_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_notification_indicator_05, T_notification_indicator_05_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_prop_13_vals[] = {
  {   0, "none" },
  {   1, "prop" },
  { 0, NULL }
};

static const per_choice_t T_prop_13_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_prop_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_Proprietary },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_prop_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_prop_13, T_prop_13_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_18_sequence[] = {
  { &hf_tetra_new_call_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_new_call_identifier },
  { &hf_tetra_call_time_out_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_call_time_out },
  { &hf_tetra_call_status_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_call_status_01 },
  { &hf_tetra_modify        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_modify },
  { &hf_tetra_notification_indicator_06, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_notification_indicator_05 },
  { &hf_tetra_prop_14       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_prop_13 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_18, T_type2_parameters_18_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_22_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_22_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_18, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_18 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_22(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_22, T_optional_elements_22_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_CALL_RESTORE_sequence[] = {
  { &hf_tetra_call_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_transmission_grant, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_transmission_request_permission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_reset_call_time_out, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_optional_elements_22, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_22 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_CALL_RESTORE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 171 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_CALL_RESTORE, D_CALL_RESTORE_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-CALL-RESTORE");


  return offset;
}


static const value_string tetra_T_calling_party_type_identifier_vals[] = {
  {   0, "none1" },
  {   1, "ssi" },
  {   2, "ssi-extension" },
  {   3, "none2" },
  { 0, NULL }
};

static const per_choice_t T_calling_party_type_identifier_choice[] = {
  {   0, &hf_tetra_none1         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_ssi           , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_16777215 },
  {   2, &hf_tetra_ssi_extension_01, ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_6 },
  {   3, &hf_tetra_none2         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_calling_party_type_identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_calling_party_type_identifier, T_calling_party_type_identifier_choice,
                                 NULL);

  return offset;
}



static int
dissect_tetra_OCTET_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

  return offset;
}


static const value_string tetra_T_short_data_type_identifier_01_vals[] = {
  {   0, "data-1" },
  {   1, "data-2" },
  {   2, "data-3" },
  {   3, "length-indicator-data-4" },
  { 0, NULL }
};

static const per_choice_t T_short_data_type_identifier_01_choice[] = {
  {   0, &hf_tetra_data_1        , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_65535 },
  {   1, &hf_tetra_data_2        , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_4 },
  {   2, &hf_tetra_data_3_01     , ASN1_NO_EXTENSIONS     , dissect_tetra_OCTET_STRING_SIZE_8 },
  {   3, &hf_tetra_length_indicator_data_4, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_4194304 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_short_data_type_identifier_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_short_data_type_identifier_01, T_short_data_type_identifier_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_SDS_DATA_sequence[] = {
  { &hf_tetra_calling_party_type_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_calling_party_type_identifier },
  { &hf_tetra_short_data_type_identifier_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_short_data_type_identifier_01 },
  { NULL, 0, 0, NULL }
};

int
dissect_tetra_D_SDS_DATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 176 "../../asn1/tetra/tetra.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_SDS_DATA, D_SDS_DATA_sequence);

	col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "D-SDS-DATA");


  return offset;
}


static const value_string tetra_D_CMCE_PDU_vals[] = {
  {   0, "d-Alert" },
  {   1, "d-Call-Proceeding" },
  {   2, "d-Connect" },
  {   3, "d-Connect-Ack" },
  {   4, "d-Disconnect" },
  {   5, "d-Info" },
  {   6, "d-Release" },
  {   7, "d-Setup" },
  {   8, "d-Status" },
  {   9, "d-Tx-Ceased" },
  {  10, "d-Tx-Continue" },
  {  11, "d-Tx-Granted" },
  {  12, "d-Tx-Wait" },
  {  13, "d-Tx-Interrupt" },
  {  14, "d-Call-Restore" },
  {  15, "d-SDS-Data" },
  {  16, "d-Facility" },
  { 0, NULL }
};

static const per_choice_t D_CMCE_PDU_choice[] = {
  {   0, &hf_tetra_d_Alert       , ASN1_NO_EXTENSIONS     , dissect_tetra_D_ALERT },
  {   1, &hf_tetra_d_Call_Proceeding, ASN1_NO_EXTENSIONS     , dissect_tetra_D_CALL_PROCEEDING },
  {   2, &hf_tetra_d_Connect     , ASN1_NO_EXTENSIONS     , dissect_tetra_D_CONNECT },
  {   3, &hf_tetra_d_Connect_Ack , ASN1_NO_EXTENSIONS     , dissect_tetra_D_CONNECT_ACK },
  {   4, &hf_tetra_d_Disconnect  , ASN1_NO_EXTENSIONS     , dissect_tetra_D_DISCONNECT },
  {   5, &hf_tetra_d_Info        , ASN1_NO_EXTENSIONS     , dissect_tetra_D_INFO },
  {   6, &hf_tetra_d_Release     , ASN1_NO_EXTENSIONS     , dissect_tetra_D_RELEASE },
  {   7, &hf_tetra_d_Setup       , ASN1_NO_EXTENSIONS     , dissect_tetra_D_SETUP },
  {   8, &hf_tetra_d_Status      , ASN1_NO_EXTENSIONS     , dissect_tetra_D_STATUS },
  {   9, &hf_tetra_d_Tx_Ceased   , ASN1_NO_EXTENSIONS     , dissect_tetra_D_TX_CEASED },
  {  10, &hf_tetra_d_Tx_Continue , ASN1_NO_EXTENSIONS     , dissect_tetra_D_TX_CONTINUE },
  {  11, &hf_tetra_d_Tx_Granted  , ASN1_NO_EXTENSIONS     , dissect_tetra_D_TX_GRANTED },
  {  12, &hf_tetra_d_Tx_Wait     , ASN1_NO_EXTENSIONS     , dissect_tetra_D_TX_WAIT },
  {  13, &hf_tetra_d_Tx_Interrupt, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  14, &hf_tetra_d_Call_Restore, ASN1_NO_EXTENSIONS     , dissect_tetra_D_CALL_RESTORE },
  {  15, &hf_tetra_d_SDS_Data    , ASN1_NO_EXTENSIONS     , dissect_tetra_D_SDS_DATA },
  {  16, &hf_tetra_d_Facility    , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_D_CMCE_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_D_CMCE_PDU, D_CMCE_PDU_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_optional_elements_02_vals[] = {
  {   0, "no-type2" },
  {   1, "sdu" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_02_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_sdu           , ASN1_NO_EXTENSIONS     , dissect_tetra_BIT_STRING },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_02, T_optional_elements_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_NEW_CELL_sequence[] = {
  { &hf_tetra_pdu_type_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_channel_command_valid, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_optional_elements_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_NEW_CELL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_NEW_CELL, D_NEW_CELL_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_03_vals[] = {
  {   0, "no-type2" },
  {   1, "sdu" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_03_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_sdu           , ASN1_NO_EXTENSIONS     , dissect_tetra_BIT_STRING },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_03, T_optional_elements_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_PREPARE_FAIL_sequence[] = {
  { &hf_tetra_pdu_type_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_fail_cause    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_optional_elements_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_PREPARE_FAIL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_PREPARE_FAIL, D_PREPARE_FAIL_sequence);

  return offset;
}



static int
dissect_tetra_T_network_time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_tetra_T_reserved(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t TETRA_NETWORK_TIME_sequence[] = {
  { &hf_tetra_network_time  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_network_time },
  { &hf_tetra_local_time_offset_sign, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_local_time_offset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_year          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_reserved_04   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_reserved },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_TETRA_NETWORK_TIME(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_TETRA_NETWORK_TIME, TETRA_NETWORK_TIME_sequence);

  return offset;
}


static const value_string tetra_T_tetra_network_time_vals[] = {
  {   0, "none" },
  {   1, "tetra-network-time" },
  { 0, NULL }
};

static const per_choice_t T_tetra_network_time_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_tetra_network_time_01, ASN1_NO_EXTENSIONS     , dissect_tetra_TETRA_NETWORK_TIME },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_tetra_network_time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_tetra_network_time, T_tetra_network_time_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_T_number_of_neighbour_cells_vals[] = {
  {   0, "none" },
  {   1, "number-of-neighbour-cells" },
  { 0, NULL }
};

static const per_choice_t T_number_of_neighbour_cells_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_number_of_neighbour_cells_01, ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_7 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_number_of_neighbour_cells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_number_of_neighbour_cells, T_number_of_neighbour_cells_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_parameters_02_sequence[] = {
  { &hf_tetra_tetra_network_time, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_tetra_network_time },
  { &hf_tetra_number_of_neighbour_cells, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_number_of_neighbour_cells },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_T_type2_parameters_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_T_type2_parameters_02, T_type2_parameters_02_sequence);

  return offset;
}


static const value_string tetra_T_optional_elements_04_vals[] = {
  {   0, "no-type2" },
  {   1, "type2-parameters" },
  { 0, NULL }
};

static const per_choice_t T_optional_elements_04_choice[] = {
  {   0, &hf_tetra_no_type2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_type2_parameters_02, ASN1_NO_EXTENSIONS     , dissect_tetra_T_type2_parameters_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_elements_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_elements_04, T_optional_elements_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_NWRK_BRDADCAST_sequence[] = {
  { &hf_tetra_pdu_type_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_cell_re_select_parameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_65535 },
  { &hf_tetra_cell_service_level, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_optional_elements_04, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_elements_04 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_NWRK_BRDADCAST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_NWRK_BRDADCAST, D_NWRK_BRDADCAST_sequence);

  return offset;
}


static const per_sequence_t D_RESTORE_ACK_sequence[] = {
  { &hf_tetra_pdu_type_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_sdu           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_RESTORE_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_RESTORE_ACK, D_RESTORE_ACK_sequence);

  return offset;
}


static const per_sequence_t D_RESTORE_FAIL_sequence[] = {
  { &hf_tetra_pdu_type_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_fail_cause    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_RESTORE_FAIL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_RESTORE_FAIL, D_RESTORE_FAIL_sequence);

  return offset;
}


static const value_string tetra_DMLE_PDU_vals[] = {
  {   0, "d-new-cell" },
  {   1, "d-prepare-fail" },
  {   2, "d-nwrk-broadcast" },
  {   3, "dmle-reserved1" },
  {   4, "d-restore-ack" },
  {   5, "d-restore-fail" },
  {   6, "dmle-reserved2" },
  {   7, "dmle-reserved3" },
  { 0, NULL }
};

static const per_choice_t DMLE_PDU_choice[] = {
  {   0, &hf_tetra_d_new_cell    , ASN1_NO_EXTENSIONS     , dissect_tetra_D_NEW_CELL },
  {   1, &hf_tetra_d_prepare_fail, ASN1_NO_EXTENSIONS     , dissect_tetra_D_PREPARE_FAIL },
  {   2, &hf_tetra_d_nwrk_broadcast, ASN1_NO_EXTENSIONS     , dissect_tetra_D_NWRK_BRDADCAST },
  {   3, &hf_tetra_dmle_reserved1, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   4, &hf_tetra_d_restore_ack , ASN1_NO_EXTENSIONS     , dissect_tetra_D_RESTORE_ACK },
  {   5, &hf_tetra_d_restore_fail, ASN1_NO_EXTENSIONS     , dissect_tetra_D_RESTORE_FAIL },
  {   6, &hf_tetra_dmle_reserved2, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   7, &hf_tetra_dmle_reserved3, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_DMLE_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_DMLE_PDU, DMLE_PDU_choice,
                                 NULL);

  return offset;
}


static const value_string tetra_D_MLE_PDU_vals[] = {
  {   0, "u-mle-reserved1" },
  {   1, "mm" },
  {   2, "cmce" },
  {   3, "u-mle-reserved2" },
  {   4, "sndcp" },
  {   5, "mle" },
  {   6, "tetra-management-entity-protocol" },
  {   7, "u-mle-reserved3" },
  { 0, NULL }
};

static const per_choice_t D_MLE_PDU_choice[] = {
  {   0, &hf_tetra_u_mle_reserved1, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_mm_01         , ASN1_NO_EXTENSIONS     , dissect_tetra_D_MM_PDU },
  {   2, &hf_tetra_cmce_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_D_CMCE_PDU },
  {   3, &hf_tetra_u_mle_reserved2, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   4, &hf_tetra_sndcp         , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   5, &hf_tetra_mle_01        , ASN1_NO_EXTENSIONS     , dissect_tetra_DMLE_PDU },
  {   6, &hf_tetra_tetra_management_entity_protocol, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   7, &hf_tetra_u_mle_reserved3, ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_D_MLE_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_D_MLE_PDU, D_MLE_PDU_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t D_BL_ADATA_sequence[] = {
  { &hf_tetra_nr            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_ns            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_D_MLE_PDU },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_BL_ADATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_BL_ADATA, D_BL_ADATA_sequence);

  return offset;
}


static const per_sequence_t D_BL_DATA_sequence[] = {
  { &hf_tetra_ns            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_D_MLE_PDU },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_BL_DATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_BL_DATA, D_BL_DATA_sequence);

  return offset;
}


static const per_sequence_t D_BL_ACK_sequence[] = {
  { &hf_tetra_nr            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_D_MLE_PDU },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_BL_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_BL_ACK, D_BL_ACK_sequence);

  return offset;
}


static const per_sequence_t D_BL_ADATA_FCS_sequence[] = {
  { &hf_tetra_nr            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_ns            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_D_MLE_PDU },
  { &hf_tetra_fcs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_BL_ADATA_FCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_BL_ADATA_FCS, D_BL_ADATA_FCS_sequence);

  return offset;
}


static const per_sequence_t D_BL_DATA_FCS_sequence[] = {
  { &hf_tetra_ns            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_D_MLE_PDU },
  { &hf_tetra_fcs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_BL_DATA_FCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_BL_DATA_FCS, D_BL_DATA_FCS_sequence);

  return offset;
}


static const per_sequence_t D_MLE_PDU_FCS_sequence[] = {
  { &hf_tetra_d_mle_pdu     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_D_MLE_PDU },
  { &hf_tetra_fcs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_MLE_PDU_FCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_MLE_PDU_FCS, D_MLE_PDU_FCS_sequence);

  return offset;
}


static const per_sequence_t D_BL_ACK_FCS_sequence[] = {
  { &hf_tetra_nr            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_tl_sdu_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_D_MLE_PDU },
  { &hf_tetra_fcs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_D_BL_ACK_FCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_D_BL_ACK_FCS, D_BL_ACK_FCS_sequence);

  return offset;
}


static const value_string tetra_D_LLC_PDU_vals[] = {
  {   0, "bl-adata" },
  {   1, "bl-data" },
  {   2, "bl-udata" },
  {   3, "bl-ack" },
  {   4, "bl-adata-fcs" },
  {   5, "bl-data-fcs" },
  {   6, "bl-udata-fcs" },
  {   7, "bl-ack-fcs" },
  {   8, "al-setup" },
  {   9, "al-data" },
  {  10, "al-udata" },
  {  11, "al-ack" },
  {  12, "al-reconnect" },
  {  13, "reserve1" },
  {  14, "reserve2" },
  {  15, "al-disc" },
  { 0, NULL }
};

static const per_choice_t D_LLC_PDU_choice[] = {
  {   0, &hf_tetra_bl_adata_01   , ASN1_NO_EXTENSIONS     , dissect_tetra_D_BL_ADATA },
  {   1, &hf_tetra_bl_data_01    , ASN1_NO_EXTENSIONS     , dissect_tetra_D_BL_DATA },
  {   2, &hf_tetra_bl_udata_01   , ASN1_NO_EXTENSIONS     , dissect_tetra_D_MLE_PDU },
  {   3, &hf_tetra_bl_ack_01     , ASN1_NO_EXTENSIONS     , dissect_tetra_D_BL_ACK },
  {   4, &hf_tetra_bl_adata_fcs_01, ASN1_NO_EXTENSIONS     , dissect_tetra_D_BL_ADATA_FCS },
  {   5, &hf_tetra_bl_data_fcs_01, ASN1_NO_EXTENSIONS     , dissect_tetra_D_BL_DATA_FCS },
  {   6, &hf_tetra_bl_udata_fcs_01, ASN1_NO_EXTENSIONS     , dissect_tetra_D_MLE_PDU_FCS },
  {   7, &hf_tetra_bl_ack_fcs_01 , ASN1_NO_EXTENSIONS     , dissect_tetra_D_BL_ACK_FCS },
  {   8, &hf_tetra_al_setup      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   9, &hf_tetra_al_data       , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  10, &hf_tetra_al_udata      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  11, &hf_tetra_al_ack        , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  12, &hf_tetra_al_reconnect  , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  13, &hf_tetra_reserve1      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  14, &hf_tetra_reserve2      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {  15, &hf_tetra_al_disc       , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_D_LLC_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_D_LLC_PDU, D_LLC_PDU_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t OTHER_DATA_sequence[] = {
  { &hf_tetra_power_control , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_power_control },
  { &hf_tetra_slot_granting_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_slot_granting_02 },
  { &hf_tetra_channel_allocation_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_channel_allocation_02 },
  { &hf_tetra_tm_sdu_09     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_D_LLC_PDU },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_OTHER_DATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_OTHER_DATA, OTHER_DATA_sequence);

  return offset;
}


static const per_sequence_t SSI_NEED_sequence[] = {
  { &hf_tetra_ssi           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16777215 },
  { &hf_tetra_other         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OTHER_DATA },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_SSI_NEED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_SSI_NEED, SSI_NEED_sequence);

  return offset;
}


static const per_sequence_t EVENT_NEED_sequence[] = {
  { &hf_tetra_eventlabel    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_other         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OTHER_DATA },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_EVENT_NEED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_EVENT_NEED, EVENT_NEED_sequence);

  return offset;
}


static const per_sequence_t USSI_NEED_sequence[] = {
  { &hf_tetra_ussi          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16777215 },
  { &hf_tetra_other         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OTHER_DATA },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_USSI_NEED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_USSI_NEED, USSI_NEED_sequence);

  return offset;
}


static const per_sequence_t SMI_NEED_sequence[] = {
  { &hf_tetra_smi           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16777215 },
  { &hf_tetra_other         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OTHER_DATA },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_SMI_NEED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_SMI_NEED, SMI_NEED_sequence);

  return offset;
}


static const per_sequence_t SSI_EVENT_NEED_sequence[] = {
  { &hf_tetra_ssi           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16777215 },
  { &hf_tetra_ventlabel     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1023 },
  { &hf_tetra_other         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OTHER_DATA },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_SSI_EVENT_NEED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_SSI_EVENT_NEED, SSI_EVENT_NEED_sequence);

  return offset;
}


static const per_sequence_t SSI_USAGE_NEED_sequence[] = {
  { &hf_tetra_ssi           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_16777215 },
  { &hf_tetra_usage_maker   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_63 },
  { &hf_tetra_other         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OTHER_DATA },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_SSI_USAGE_NEED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_SSI_USAGE_NEED, SSI_USAGE_NEED_sequence);

  return offset;
}



static int
dissect_tetra_BIT_STRING_SIZE_34(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     34, 34, FALSE, NULL);

  return offset;
}


static const per_sequence_t SMI_EVENT_NEED_sequence[] = {
  { &hf_tetra_smi_eventlabel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_BIT_STRING_SIZE_34 },
  { &hf_tetra_other         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_OTHER_DATA },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_SMI_EVENT_NEED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_SMI_EVENT_NEED, SMI_EVENT_NEED_sequence);

  return offset;
}


static const value_string tetra_AddressMacResource_vals[] = {
  {   0, "null-pdu" },
  {   1, "ssi" },
  {   2, "eventLabel" },
  {   3, "ussi" },
  {   4, "smi" },
  {   5, "ssi-eventLabel" },
  {   6, "ssi-usage-maker" },
  {   7, "smi-eventLabel" },
  { 0, NULL }
};

static const per_choice_t AddressMacResource_choice[] = {
  {   0, &hf_tetra_null_pdu      , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_ssi_01        , ASN1_NO_EXTENSIONS     , dissect_tetra_SSI_NEED },
  {   2, &hf_tetra_eventLabel_01 , ASN1_NO_EXTENSIONS     , dissect_tetra_EVENT_NEED },
  {   3, &hf_tetra_ussi_01       , ASN1_NO_EXTENSIONS     , dissect_tetra_USSI_NEED },
  {   4, &hf_tetra_smi_01        , ASN1_NO_EXTENSIONS     , dissect_tetra_SMI_NEED },
  {   5, &hf_tetra_ssi_eventLabel, ASN1_NO_EXTENSIONS     , dissect_tetra_SSI_EVENT_NEED },
  {   6, &hf_tetra_ssi_usage_maker, ASN1_NO_EXTENSIONS     , dissect_tetra_SSI_USAGE_NEED },
  {   7, &hf_tetra_smi_eventLabel, ASN1_NO_EXTENSIONS     , dissect_tetra_SMI_EVENT_NEED },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_AddressMacResource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_AddressMacResource, AddressMacResource_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MAC_RESOURCE_sequence[] = {
  { &hf_tetra_pdu_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_fill_bit_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Fill_Bit_Indication },
  { &hf_tetra_position_of_grant, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_Position_Of_Grant },
  { &hf_tetra_encryption_mode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_access_ack    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_access_ack },
  { &hf_tetra_lengthIndication_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_LengthIndicationMacResource },
  { &hf_tetra_address_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_AddressMacResource },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_RESOURCE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_RESOURCE, MAC_RESOURCE_sequence);

  return offset;
}



static int
dissect_tetra_INTEGER_0_33554431(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 33554431U, NULL, FALSE);

  return offset;
}


static const value_string tetra_T_optional_field_vals[] = {
  {   0, "none" },
  {   1, "class-bitmap" },
  {   2, "gssi" },
  {   3, "reserved" },
  { 0, NULL }
};

static const per_choice_t T_optional_field_choice[] = {
  {   0, &hf_tetra_none          , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  {   1, &hf_tetra_class_bitmap  , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_65535 },
  {   2, &hf_tetra_gssi          , ASN1_NO_EXTENSIONS     , dissect_tetra_INTEGER_0_33554431 },
  {   3, &hf_tetra_reserved_03   , ASN1_NO_EXTENSIONS     , dissect_tetra_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_tetra_T_optional_field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_tetra_T_optional_field, T_optional_field_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MAC_ACCESS_DEFINE_sequence[] = {
  { &hf_tetra_pdu_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_broadcast_type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_broadcast_channel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_access_code   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_3 },
  { &hf_tetra_imm_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_wt_01         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_nu_01         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_frame_len_factor_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_1 },
  { &hf_tetra_timeslot_pointer_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_15 },
  { &hf_tetra_min_priority  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { &hf_tetra_optional_field, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_T_optional_field },
  { &hf_tetra_filler_bits   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tetra_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_tetra_MAC_ACCESS_DEFINE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_tetra_MAC_ACCESS_DEFINE, MAC_ACCESS_DEFINE_sequence);

  return offset;
}

/*--- PDUs ---*/

static void dissect_AACH_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_AACH(tvb, 0, &asn1_ctx, tree, hf_tetra_AACH_PDU);
}
static void dissect_BSCH_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_BSCH(tvb, 0, &asn1_ctx, tree, hf_tetra_BSCH_PDU);
}
static void dissect_BNCH_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_BNCH(tvb, 0, &asn1_ctx, tree, hf_tetra_BNCH_PDU);
}
static void dissect_MAC_ACCESS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_ACCESS(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_ACCESS_PDU);
}
static void dissect_MAC_FRAG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_FRAG(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_FRAG_PDU);
}
static void dissect_MAC_FRAG120_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_FRAG120(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_FRAG120_PDU);
}
static void dissect_MAC_END_UPLINK_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_END_UPLINK(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_END_UPLINK_PDU);
}
static void dissect_MAC_END_UP114_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_END_UP114(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_END_UP114_PDU);
}
static void dissect_MAC_END_HU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_END_HU(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_END_HU_PDU);
}
static void dissect_MAC_END_DOWNLINK_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_END_DOWNLINK(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_END_DOWNLINK_PDU);
}
static void dissect_MAC_END_DOWN111_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_END_DOWN111(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_END_DOWN111_PDU);
}
static void dissect_MAC_RESOURCE_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_RESOURCE(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_RESOURCE_PDU);
}
static void dissect_MAC_ACCESS_DEFINE_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_tetra_MAC_ACCESS_DEFINE(tvb, 0, &asn1_ctx, tree, hf_tetra_MAC_ACCESS_DEFINE_PDU);
}


/*--- End of included file: packet-tetra-fn.c ---*/
#line 98 "../../asn1/tetra/packet-tetra-template.c"

static const value_string channeltypenames[] = {
	{ 0, "Reserved" },
	{ 1, "AACH" },
	{ 2, "SCH/F" },
	{ 3, "SCH/HD" },
	{ 4, "Unknown" },
	{ 5, "BSCH" },
	{ 6, "BNCH" },
	{ 7, "TCH/F" },
	{ 8, "TCH/H" },
	{ 9, "TCH4.8"},
	{ 10, "TCH7.2"},
	{ 11, "STCH"},
	{ 0, NULL }
};

static const value_string recvchanneltypenames[] = {
	{ 0, "Reserved" },
	{ 1, "AACH" },
	{ 2, "SCH/F" },
	{ 3, "SCH/HD" },
	{ 4, "Unknown" },
	{ 5, "BSCH" },
	{ 6, "BNCH" },
	{ 7, "TCH/F" },
	{ 8, "TCH/H" },
	{ 9, "TCH4.8"},
	{ 10, "TCH7.2"},
	{ 11, "STCH"},
	{ 15, "SCH/HU"},
	{ 0, NULL }
};

/* Get the length of received pdu */
static gint get_rx_pdu_length(guint32 channel_type)
{
	gint len = 0;

	switch(channel_type) {
	case TETRA_CHAN_AACH:
		len = 14;
		break;
	case TETRA_CHAN_SCH_F:
		len = 268;
		break;
	case TETRA_CHAN_SCH_D:
		len = 124; ;
		break;
	case TETRA_CHAN_BSCH:
		len = 60;
		break;
	case TETRA_CHAN_BNCH:
		len = 124;
		break;
	case TETRA_CHAN_TCH_F:
		len = 274;
		break;
	case TETRA_CHAN_TCH_H:
		len = 137;
		break;
	case TETRA_CHAN_TCH_2_4:
		len = 144;
		break;
	case TETRA_CHAN_TCH_4_8:
		len = 288;
		break;
	case TETRA_CHAN_STCH:
		len = 124;
		break;
	case TETRA_CHAN_SCH_HU:
		len = 92;
		break;
	default:
		len = 0;
		break;
	}

	return len;
}

/* Get the length of transmitted pdu */
static gint get_tx_pdu_length(guint32 channel_type)
{
	gint len = 0;

	switch(channel_type) {
	case TETRA_CHAN_AACH:
		len = 14;
		break;
	case TETRA_CHAN_SCH_F:
		len = 268;
		break;
	case TETRA_CHAN_SCH_D:
		len = 124;
		break;
	case TETRA_CHAN_BSCH:
		len = 60;
		break;
	case TETRA_CHAN_BNCH:
		len = 124;
		break;
	case TETRA_CHAN_TCH_F:
		len = 274;
		break;
	case TETRA_CHAN_TCH_H:
		len = 137;
		break;
	case TETRA_CHAN_TCH_2_4:
		len = 144;
		break;
	case TETRA_CHAN_TCH_4_8:
		len = 288;
		break;
	case TETRA_CHAN_STCH:
		len = 124;
		break;
	}

	return len;
}

void tetra_dissect_pdu(int channel_type, int dir, tvbuff_t *pdu, proto_tree *tree, packet_info *pinfo)
{
	proto_item *tetra_sub_item;
	proto_tree *tetra_sub_tree;
	guint8 p;

	tetra_sub_item = proto_tree_add_item(tree, hf_tetra_pdu,
					     pdu, 0, tvb_length(pdu), ENC_NA);

	tetra_sub_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);

	switch(channel_type) {
	case TETRA_CHAN_AACH:
		dissect_AACH_PDU(pdu, pinfo, tetra_sub_tree );
		break;
	case TETRA_CHAN_SCH_F:
		p = tvb_get_guint8(pdu, 0);
		switch(p >> 6) {
		case 0:
			dissect_MAC_RESOURCE_PDU(pdu, pinfo, tetra_sub_tree );
			break;
		case 1: /* MAC-FRAG or MAC-END */
			if((p >> 5) == 3) {
				if (dir == TETRA_DOWNLINK)
					dissect_MAC_END_DOWNLINK_PDU(pdu, pinfo, tetra_sub_tree );
				else
					dissect_MAC_END_UPLINK_PDU(pdu, pinfo, tetra_sub_tree);

			} else
				dissect_MAC_FRAG_PDU(pdu, pinfo, tetra_sub_tree );
			break;
		case 2:
			dissect_MAC_ACCESS_DEFINE_PDU(pdu, pinfo, tetra_sub_tree );
			break;
		}
		break;
	case TETRA_CHAN_SCH_D:
		p = tvb_get_guint8(pdu, 0);
		switch(p >> 6) {
		case 0:
			dissect_MAC_RESOURCE_PDU(pdu, pinfo, tetra_sub_tree );
			break;
		case 1: /* MAC-FRAG or MAC-END */
			if((p >> 5) == 3)
				dissect_MAC_END_DOWN111_PDU(pdu, pinfo, tetra_sub_tree );
			else
				dissect_MAC_FRAG120_PDU(pdu, pinfo, tetra_sub_tree );
		break;
		case 2:
			dissect_MAC_ACCESS_DEFINE_PDU(pdu, pinfo, tetra_sub_tree );
			break;
		}
		break;
	case TETRA_CHAN_SCH_HU:
		p = tvb_get_guint8(pdu, 0);
		switch(p >> 7) {
		case 0: /* MAC-ACCESS */
			dissect_MAC_ACCESS_PDU(pdu, pinfo, tetra_sub_tree);
			break;
		case 1: /* MAC-END-HU */
			dissect_MAC_END_HU_PDU(pdu, pinfo, tetra_sub_tree);
			break;
		}
		break;
	case TETRA_CHAN_BSCH:
		dissect_BSCH_PDU(pdu, pinfo, tetra_sub_tree );
		break;
	case TETRA_CHAN_BNCH:
		dissect_BNCH_PDU(pdu, pinfo, tetra_sub_tree );
		break;
	case TETRA_CHAN_STCH:
		p = tvb_get_guint8(pdu, 0);
		switch(p >> 6) {
		case 0:
			dissect_MAC_RESOURCE_PDU(pdu, pinfo, tetra_sub_tree );
			break;
		case 1: /* MAC-FRAG or MAC-END */
			if((p >> 5) == 3) {
				if (dir == TETRA_DOWNLINK)
					dissect_MAC_END_DOWN111_PDU(pdu, pinfo, tetra_sub_tree );
				else
					dissect_MAC_END_UP114_PDU(pdu, pinfo, tetra_sub_tree);
			} else
				dissect_MAC_FRAG120_PDU(pdu, pinfo, tetra_sub_tree );
			break;
		case 2:
			dissect_MAC_ACCESS_DEFINE_PDU(pdu, pinfo, tetra_sub_tree );
			break;
		}
		break;
	}
}

static void dissect_tetra_UNITDATA_IND(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tetra_tree, int offset)
{
	guint32 rxreg = 0;
	guint32 channels = 0, i;
	guint32 channel_type;
	gint pdu_offset = 0;
	proto_item *tetra_sub_item;
	proto_tree *tetra_header_tree = NULL;
	tvbuff_t *payload_tvb;

	/* Length */
	rxreg = tvb_get_letohl(tvb, offset);
	tetra_sub_item = proto_tree_add_uint(tetra_tree, hf_tetra_len0, tvb, offset, 4, rxreg);

	/* RvSteR */
	offset += 4;
	rxreg = tvb_get_letohl(tvb, offset);
	tetra_sub_item = proto_tree_add_uint(tetra_tree, hf_tetra_rvstr, tvb, offset, 4, rxreg);

	/* Logical channels */
	channels = rxreg & 0x3;
	tetra_sub_item = proto_tree_add_uint( tetra_tree, hf_tetra_channels, tvb, offset, 4, channels );
	tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);

	pdu_offset = offset + 4;
	for(i = 0; i < channels; i++) {
		gint hf_channel[] = {
		    hf_tetra_rxchannel1,
		    hf_tetra_rxchannel2,
		    hf_tetra_rxchannel3
		};
		gint byte_len, bits_len, remaining_bits;

		/* Channel type */
		channel_type = (rxreg >> ((i + 1) * 4) ) & 0xf;
		proto_tree_add_uint( tetra_header_tree, hf_channel[i], tvb, offset, 4, channel_type);

		/* CRC */
		proto_tree_add_boolean( tetra_header_tree, hf_tetra_crc, tvb, offset, 4, !(rxreg >> (i + 2) & 0x01));

		/* PDU */
		bits_len = get_rx_pdu_length(channel_type);
		byte_len = bits_len >> 3;
		remaining_bits = bits_len % 8;
		if ((remaining_bits)!=0)
			byte_len++;

		payload_tvb = tvb_new_subset(tvb, pdu_offset, byte_len, byte_len);
		tetra_dissect_pdu(channel_type, TETRA_UPLINK, payload_tvb, tetra_header_tree, pinfo);

		if ((remaining_bits)!=0)
			byte_len--;
		pdu_offset += byte_len;
	}
}

void dissect_tetra_UNITDATA_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tetra_tree, int offset)
{
	guint32 txreg = 0;
	guint32 channels = 0, i;
	guint32 channel_type;
	gint pdu_offset = 0;
	proto_item *tetra_sub_item = NULL;
	proto_tree *tetra_header_tree = NULL;
	tvbuff_t *payload_tvb;

	/* TxR */
	txreg = tvb_get_letohl(tvb, offset);
	tetra_sub_item = proto_tree_add_uint(tetra_tree, hf_tetra_txreg, tvb, offset, 4, txreg);

	/* Logical channels */
	channels = (txreg & 0x3) + 1;
	tetra_sub_item = proto_tree_add_uint( tetra_tree, hf_tetra_channels, tvb, offset, 4, channels );
	tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);
	txreg >>= 2;
	/* Skip 0000B */
	if(channels == 2)
		txreg >>= 4;

	pdu_offset = offset + 4;
	for(i = 0; i < channels; i++) {
		gint hf_channel[] = {hf_tetra_channel1, hf_tetra_channel2, hf_tetra_channel3};
		gint byte_len, bits_len, remaining_bits;

		channel_type = txreg & 0xf;
		proto_tree_add_uint( tetra_header_tree, hf_channel[i], tvb, offset, 4, channel_type);
		txreg >>= 4;
		/* PDU */
		bits_len = get_tx_pdu_length(channel_type);
		byte_len = bits_len >> 3;
		remaining_bits = bits_len % 8;
		if ((remaining_bits)!=0)
				byte_len++;

		payload_tvb = tvb_new_subset(tvb, pdu_offset, byte_len, byte_len);
		tetra_dissect_pdu(channel_type, TETRA_DOWNLINK, payload_tvb, tetra_header_tree, pinfo);
		pdu_offset += byte_len;
	}
}

static void
dissect_tetra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_item *tetra_item = NULL;
	proto_item *tetra_sub_item = NULL;
	proto_tree *tetra_tree = NULL;
	proto_tree *tetra_header_tree = NULL;
	guint16 type = 0;
	guint16 carriernumber = -1;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_tetra);
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	/*
	 * This is not a good way of dissecting packets.  The tvb length should
	 * be sanity checked so we aren't going past the actual size of the buffer.
	 */
	type = tvb_get_guint8(tvb, 0);

	if(include_carrier_number) {
		carriernumber = tvb_get_guint8(tvb, 1);
		carriernumber |= 0xff00;
	}


	switch(type) {
	case 1:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-REQ, Carrier: %d",
					pinfo->srcport, pinfo->destport, carriernumber);
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-REQ",
					pinfo->srcport, pinfo->destport);
		break;
	case 2:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-IND, Carrier: %d",
					pinfo->srcport, pinfo->destport, carriernumber);
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-IND",
					pinfo->srcport, pinfo->destport);
		break;
	case 3:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d MAC-Timer, Carrier: %d",
					pinfo->srcport, pinfo->destport, carriernumber);
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d MAC-Timer",
					pinfo->srcport, pinfo->destport);
		break;
	case 127:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-IND Done, Carrier: %d",
					pinfo->srcport, pinfo->destport, carriernumber);
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-IND Done",
					pinfo->srcport, pinfo->destport);
		break;
	case 128:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-REQ Done, Carrier: %d",
					pinfo->srcport, pinfo->destport, carriernumber);
	  else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-REQ Done",
					pinfo->srcport, pinfo->destport);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d Unknown command: %d",
				pinfo->srcport, pinfo->destport, type);
		break;
	}

	if (tree) { /* we are being asked for details */
		guint32 offset = 0;
		guint32 txtimer = 0;
		guint32 tslot = 0;

		tetra_item = proto_tree_add_item(tree, proto_tetra, tvb, 0, -1, ENC_NA);
		tetra_tree = proto_item_add_subtree(tetra_item, ett_tetra);
		tetra_header_tree = proto_item_add_subtree(tetra_item, ett_tetra);

		offset ++;

		/* Carrier number */
		if(include_carrier_number) {
			tetra_sub_item = proto_tree_add_uint(tetra_tree, hf_tetra_carriernumber, tvb, offset, 1, carriernumber);
			offset ++;
		}

		/* Registers */
		tetra_sub_item = proto_tree_add_item( tetra_tree, hf_tetra_header, tvb, offset, -1, ENC_NA );
		tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);

		/* Timer */
		txtimer = tvb_get_letohl(tvb, offset);
		tetra_sub_item = proto_tree_add_item(tetra_header_tree, hf_tetra_timer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		tslot = ((txtimer & 0x7800) >> 11);
		if(tslot==4)
			tslot = 3;
		if(tslot==8)
			tslot = 4;
		proto_item_append_text(tetra_sub_item, " (Multiple frame: %d, Frame: %d, Slot: %d)",
													txtimer & 0x3F, (txtimer & 0x7c0) >> 6,
													tslot);

		offset += 4;

		switch(type) {
		case 1: /* tetra-UNITDATA-REQ */
		case 128: /* tetra-UNITDATA-REQ Done */
			dissect_tetra_UNITDATA_REQ(tvb, pinfo, tetra_header_tree, offset);
			break;
		case 2: /* tetra-UNITDATA-IND */
		case 127: /* tetra-UNITDATA-IND Done */
			dissect_tetra_UNITDATA_IND(tvb, pinfo, tetra_header_tree, offset);
			break;
		case 3: /* MAC-Timer */
			break;
		default:
			break;
		}
	}
}

void proto_reg_handoff_tetra(void)
{
	static gboolean initialized=FALSE;

	if (!initialized) {
		data_handle = find_dissector("data");
		tetra_handle = create_dissector_handle(dissect_tetra, proto_tetra);
		dissector_add_uint("udp.port", global_tetra_port, tetra_handle);
	}

}


void proto_register_tetra (void)
{
	module_t *per_module;

	/*
	 * A header field is something you can search/filter on.
	 *
	 * We create a structure to register our fields. It consists of an
	 * array of hf_register_info structures, each of which are of the format
	 * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	 */
	static hf_register_info hf[] = {
		{ &hf_tetra,
		{ "Data", "tetra.data", FT_NONE, BASE_NONE, NULL, 0x0,
		"tetra PDU", HFILL }},
		{ &hf_tetra_header,
		{ "Registers", "tetra.header", FT_NONE, BASE_NONE, NULL, 0x0,
		 "TETRA Registers", HFILL }},
		{ &hf_tetra_channels,
		{ "Logical Channels", "tetra.channels", FT_UINT8, BASE_DEC, NULL, 0x0,
		"The amount of logical channels", HFILL }},
		{ &hf_tetra_channel1,
		{ "Channel 1", "tetra.txchannel1", FT_UINT8, BASE_DEC, VALS(channeltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_channel2,
		{ "Channel 2", "tetra.txchannel2", FT_UINT8, BASE_DEC, VALS(channeltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_channel3,
		{ "Channel 3", "tetra.txchannel3", FT_UINT8, BASE_DEC, VALS(channeltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_txreg,
		{ "TxR", "tetra.txreg", FT_UINT16, BASE_HEX, NULL, 0x0,
		 "TX Register", HFILL }},
		{ &hf_tetra_rvstr,
		{ "RvSteR", "tetra.rvster", FT_UINT16, BASE_HEX, NULL, 0x0,
		 "Receive Status Register", HFILL }},
		{ &hf_tetra_carriernumber,
		{ "Carrier Number", "tetra.carrier", FT_UINT16, BASE_HEX, NULL, 0x0,
		 NULL, HFILL }},
		{ &hf_tetra_rxchannel1,
		{ "Channel 1", "tetra.rxchannel1", FT_UINT8, BASE_DEC, VALS(recvchanneltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_rxchannel2,
		{ "Channel 2", "tetra.rxchannel2", FT_UINT8, BASE_DEC, VALS(recvchanneltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_rxchannel3,
		{ "Channel 3", "tetra.rxchannel3", FT_UINT8, BASE_DEC, VALS(recvchanneltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_timer,
		{ "Timer", "tetra.timer", FT_UINT16, BASE_HEX, NULL, 0x0,
		 "Timer Register", HFILL }},
		{ &hf_tetra_crc,
		{ "CRC", "tetra.crc", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
		 "CRC result", HFILL }},
		{ &hf_tetra_len0,
		{ "Length", "tetra.len0", FT_UINT16, BASE_DEC, NULL, 0x0,
		 "Length of the PDU", HFILL }},
		{ &hf_tetra_pdu,
		{ "PDU", "tetra.pdu", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }} ,


/*--- Included file: packet-tetra-hfarr.c ---*/
#line 1 "../../asn1/tetra/packet-tetra-hfarr.c"
    { &hf_tetra_AACH_PDU,
      { "AACH", "tetra.AACH",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_BSCH_PDU,
      { "BSCH", "tetra.BSCH",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_BNCH_PDU,
      { "BNCH", "tetra.BNCH",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_ACCESS_PDU,
      { "MAC-ACCESS", "tetra.MAC_ACCESS",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_FRAG_PDU,
      { "MAC-FRAG", "tetra.MAC_FRAG",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_FRAG120_PDU,
      { "MAC-FRAG120", "tetra.MAC_FRAG120",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_END_UPLINK_PDU,
      { "MAC-END-UPLINK", "tetra.MAC_END_UPLINK",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_END_UP114_PDU,
      { "MAC-END-UP114", "tetra.MAC_END_UP114",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_END_HU_PDU,
      { "MAC-END-HU", "tetra.MAC_END_HU",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_END_DOWNLINK_PDU,
      { "MAC-END-DOWNLINK", "tetra.MAC_END_DOWNLINK",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_END_DOWN111_PDU,
      { "MAC-END-DOWN111", "tetra.MAC_END_DOWN111",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_RESOURCE_PDU,
      { "MAC-RESOURCE", "tetra.MAC_RESOURCE",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_MAC_ACCESS_DEFINE_PDU,
      { "MAC-ACCESS-DEFINE", "tetra.MAC_ACCESS_DEFINE",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_function,
      { "function", "tetra.function",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_field1,
      { "field1", "tetra.field1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_field2,
      { "field2", "tetra.field2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_system_code,
      { "system-code", "tetra.system_code",
        FT_UINT32, BASE_DEC, VALS(tetra_System_Code_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_colour_code,
      { "colour-code", "tetra.colour_code",
        FT_UINT32, BASE_DEC, VALS(tetra_Colour_Code_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_timeslot_number,
      { "timeslot-number", "tetra.timeslot_number",
        FT_UINT32, BASE_DEC, VALS(tetra_Timeslot_Number_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_frame_number,
      { "frame-number", "tetra.frame_number",
        FT_UINT32, BASE_DEC, VALS(tetra_Frame_Number_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_multiple_frame_number,
      { "multiple-frame-number", "tetra.multiple_frame_number",
        FT_UINT32, BASE_DEC, VALS(tetra_Multiple_Frame_Number_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_sharing_mod,
      { "sharing-mod", "tetra.sharing_mod",
        FT_UINT32, BASE_DEC, VALS(tetra_Sharing_Mod_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_ts_reserved_frames,
      { "ts-reserved-frames", "tetra.ts_reserved_frames",
        FT_UINT32, BASE_DEC, VALS(tetra_TS_Reserved_Frames_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_u_plane_dtx,
      { "u-plane-dtx", "tetra.u_plane_dtx",
        FT_UINT32, BASE_DEC, VALS(tetra_U_Plane_DTX_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_frame_18_extension,
      { "frame-18-extension", "tetra.frame_18_extension",
        FT_UINT32, BASE_DEC, VALS(tetra_Frame_18_Extension_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_reserved,
      { "reserved", "tetra.reserved",
        FT_UINT32, BASE_DEC, VALS(tetra_Reserved_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_tm_sdu,
      { "tm-sdu", "tetra.tm_sdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "MLE_Sync", HFILL }},
    { &hf_tetra_mcc,
      { "mcc", "tetra.mcc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_tetra_mnc,
      { "mnc", "tetra.mnc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_tetra_neighbour_cell_broadcast,
      { "neighbour-cell-broadcast", "tetra.neighbour_cell_broadcast",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_cell_service_level,
      { "cell-service-level", "tetra.cell_service_level",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_late_entry_information,
      { "late-entry-information", "tetra.late_entry_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_pdu_type,
      { "pdu-type", "tetra.pdu_type",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_broadcast_type,
      { "broadcast-type", "tetra.broadcast_type",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_main_carrier,
      { "main-carrier", "tetra.main_carrier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_tetra_frequency_band,
      { "frequency-band", "tetra.frequency_band",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_offset,
      { "offset", "tetra.offset",
        FT_UINT32, BASE_DEC, VALS(tetra_Offset_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_duplex_spacing,
      { "duplex-spacing", "tetra.duplex_spacing",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_reverse_operation,
      { "reverse-operation", "tetra.reverse_operation",
        FT_UINT32, BASE_DEC, VALS(tetra_Reverse_Operation_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_sencond_ctl_carrier,
      { "sencond-ctl-carrier", "tetra.sencond_ctl_carrier",
        FT_UINT32, BASE_DEC, VALS(tetra_Sencond_Ctl_Carrier_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_ms_txpwr_max_cell,
      { "ms-txpwr-max-cell", "tetra.ms_txpwr_max_cell",
        FT_UINT32, BASE_DEC, VALS(tetra_MS_TXPWR_MAX_CELL_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_rxlev_access_min,
      { "rxlev-access-min", "tetra.rxlev_access_min",
        FT_UINT32, BASE_DEC, VALS(tetra_RXLEV_ACCESS_MIN_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_access_parameter,
      { "access-parameter", "tetra.access_parameter",
        FT_UINT32, BASE_DEC, VALS(tetra_ACCESS_PARAMETER_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_radio_downlink_timeout,
      { "radio-downlink-timeout", "tetra.radio_downlink_timeout",
        FT_UINT32, BASE_DEC, VALS(tetra_RADIO_DOWNLINK_TIMEOUT_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_hyperframe_or_cck,
      { "hyperframe-or-cck", "tetra.hyperframe_or_cck",
        FT_UINT32, BASE_DEC, VALS(tetra_T_hyperframe_or_cck_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_hyperframe,
      { "hyperframe", "tetra.hyperframe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_tetra_cckid,
      { "cckid", "tetra.cckid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_tetra_optional_params,
      { "optional-params", "tetra.optional_params",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_params_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_even_multiframe,
      { "even-multiframe", "tetra.even_multiframe",
        FT_NONE, BASE_NONE, NULL, 0,
        "TS_COMMON_FRAMES", HFILL }},
    { &hf_tetra_odd_multiframe,
      { "odd-multiframe", "tetra.odd_multiframe",
        FT_NONE, BASE_NONE, NULL, 0,
        "TS_COMMON_FRAMES", HFILL }},
    { &hf_tetra_access_a_code,
      { "access-a-code", "tetra.access_a_code",
        FT_NONE, BASE_NONE, NULL, 0,
        "Default_Code_A", HFILL }},
    { &hf_tetra_extend_service,
      { "extend-service", "tetra.extend_service",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extended_Services_Broadcast", HFILL }},
    { &hf_tetra_la,
      { "la", "tetra.la",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_tetra_subscriber_class,
      { "subscriber-class", "tetra.subscriber_class",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_tetra_registriation,
      { "registriation", "tetra.registriation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_de_registration,
      { "de-registration", "tetra.de_registration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_priority_cell,
      { "priority-cell", "tetra.priority_cell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_minimum_mode_service,
      { "minimum-mode-service", "tetra.minimum_mode_service",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_migration,
      { "migration", "tetra.migration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_system_wide_service,
      { "system-wide-service", "tetra.system_wide_service",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_tetra_voice_service,
      { "tetra-voice-service", "tetra.tetra_voice_service",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_circuit_mode_data_service,
      { "circuit-mode-data-service", "tetra.circuit_mode_data_service",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_reserved_01,
      { "reserved", "tetra.reserved",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_sndcp_service,
      { "sndcp-service", "tetra.sndcp_service",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_air_interface_encryption,
      { "air-interface-encryption", "tetra.air_interface_encryption",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_advanced_link_support,
      { "advanced-link-support", "tetra.advanced_link_support",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_frame1,
      { "frame1", "tetra.frame1",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame2,
      { "frame2", "tetra.frame2",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame3,
      { "frame3", "tetra.frame3",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame4,
      { "frame4", "tetra.frame4",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame5,
      { "frame5", "tetra.frame5",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame6,
      { "frame6", "tetra.frame6",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame7,
      { "frame7", "tetra.frame7",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame8,
      { "frame8", "tetra.frame8",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame9,
      { "frame9", "tetra.frame9",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame10,
      { "frame10", "tetra.frame10",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame11,
      { "frame11", "tetra.frame11",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame12,
      { "frame12", "tetra.frame12",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame13,
      { "frame13", "tetra.frame13",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame14,
      { "frame14", "tetra.frame14",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame15,
      { "frame15", "tetra.frame15",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame16,
      { "frame16", "tetra.frame16",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame17,
      { "frame17", "tetra.frame17",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_frame18,
      { "frame18", "tetra.frame18",
        FT_UINT32, BASE_DEC, VALS(tetra_FRAME_vals), 0,
        "FRAME", HFILL }},
    { &hf_tetra_imm,
      { "imm", "tetra.imm",
        FT_UINT32, BASE_DEC, VALS(tetra_IMM_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_wt,
      { "wt", "tetra.wt",
        FT_UINT32, BASE_DEC, VALS(tetra_WT_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_nu,
      { "nu", "tetra.nu",
        FT_UINT32, BASE_DEC, VALS(tetra_NU_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_frame_len_factor,
      { "frame-len-factor", "tetra.frame_len_factor",
        FT_UINT32, BASE_DEC, VALS(tetra_Frame_Len_Factor_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_timeslot_pointer,
      { "timeslot-pointer", "tetra.timeslot_pointer",
        FT_UINT32, BASE_DEC, VALS(tetra_Timeslot_Pointer_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_min_pdu_priority,
      { "min-pdu-priority", "tetra.min_pdu_priority",
        FT_UINT32, BASE_DEC, VALS(tetra_Min_Pdu_Priority_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_security_information,
      { "security-information", "tetra.security_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_tetra_sds_tl_addressing_method,
      { "sds-tl-addressing-method", "tetra.sds_tl_addressing_method",
        FT_UINT32, BASE_DEC, VALS(tetra_SDS_TL_Addressing_Method_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_gck_supported,
      { "gck-supported", "tetra.gck_supported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_section,
      { "section", "tetra.section",
        FT_UINT32, BASE_DEC, VALS(tetra_T_section_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_present_1,
      { "present-1", "tetra.present_1",
        FT_NONE, BASE_NONE, NULL, 0,
        "PRESENT1", HFILL }},
    { &hf_tetra_present_2,
      { "present-2", "tetra.present_2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_tetra_present_3,
      { "present-3", "tetra.present_3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_tetra_present_4,
      { "present-4", "tetra.present_4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_tetra_data_priority_supported,
      { "data-priority-supported", "tetra.data_priority_supported",
        FT_UINT32, BASE_DEC, VALS(tetra_Data_Priority_Supported_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_reserved_02,
      { "reserved", "tetra.reserved",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_section_2_information,
      { "section-2-information", "tetra.section_2_information",
        FT_UINT32, BASE_DEC, VALS(tetra_Section_Information_vals), 0,
        "Section_Information", HFILL }},
    { &hf_tetra_section_3_information,
      { "section-3-information", "tetra.section_3_information",
        FT_UINT32, BASE_DEC, VALS(tetra_Section_Information_vals), 0,
        "Section_Information", HFILL }},
    { &hf_tetra_section_4_information,
      { "section-4-information", "tetra.section_4_information",
        FT_UINT32, BASE_DEC, VALS(tetra_Section_Information_vals), 0,
        "Section_Information", HFILL }},
    { &hf_tetra_pdu_type_01,
      { "pdu-type", "tetra.pdu_type",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_fill_bit_indication,
      { "fill-bit-indication", "tetra.fill_bit_indication",
        FT_UINT32, BASE_DEC, VALS(tetra_Fill_Bit_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_encrypted_flag,
      { "encrypted-flag", "tetra.encrypted_flag",
        FT_UINT32, BASE_DEC, VALS(tetra_Encrypted_Flag_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_address,
      { "address", "tetra.address",
        FT_UINT32, BASE_DEC, VALS(tetra_Address_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_data,
      { "data", "tetra.data",
        FT_UINT32, BASE_DEC, VALS(tetra_T_data_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_sdu1,
      { "sdu1", "tetra.sdu1",
        FT_UINT32, BASE_DEC, VALS(tetra_U_LLC_PDU_vals), 0,
        "U_LLC_PDU", HFILL }},
    { &hf_tetra_sdu2,
      { "sdu2", "tetra.sdu2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ComplexSDU", HFILL }},
    { &hf_tetra_ssi,
      { "ssi", "tetra.ssi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_tetra_eventLabel,
      { "eventLabel", "tetra.eventLabel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_tetra_ussi,
      { "ussi", "tetra.ussi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_tetra_smi,
      { "smi", "tetra.smi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_tetra_bl_adata,
      { "bl-adata", "tetra.bl_adata",
        FT_NONE, BASE_NONE, NULL, 0,
        "U_BL_ADATA", HFILL }},
    { &hf_tetra_bl_data,
      { "bl-data", "tetra.bl_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "U_BL_DATA", HFILL }},
    { &hf_tetra_bl_udata,
      { "bl-udata", "tetra.bl_udata",
        FT_UINT32, BASE_DEC, VALS(tetra_U_MLE_PDU_vals), 0,
        "U_MLE_PDU", HFILL }},
    { &hf_tetra_bl_ack,
      { "bl-ack", "tetra.bl_ack",
        FT_NONE, BASE_NONE, NULL, 0,
        "U_BL_ACK", HFILL }},
    { &hf_tetra_bl_adata_fcs,
      { "bl-adata-fcs", "tetra.bl_adata_fcs",
        FT_NONE, BASE_NONE, NULL, 0,
        "U_BL_ADATA_FCS", HFILL }},
    { &hf_tetra_bl_data_fcs,
      { "bl-data-fcs", "tetra.bl_data_fcs",
        FT_NONE, BASE_NONE, NULL, 0,
        "U_BL_DATA_FCS", HFILL }},
    { &hf_tetra_bl_udata_fcs,
      { "bl-udata-fcs", "tetra.bl_udata_fcs",
        FT_NONE, BASE_NONE, NULL, 0,
        "U_MLE_PDU_FCS", HFILL }},
    { &hf_tetra_bl_ack_fcs,
      { "bl-ack-fcs", "tetra.bl_ack_fcs",
        FT_NONE, BASE_NONE, NULL, 0,
        "U_BL_ACK_FCS", HFILL }},
    { &hf_tetra_al_setup,
      { "al-setup", "tetra.al_setup",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_al_data,
      { "al-data", "tetra.al_data",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_al_udata,
      { "al-udata", "tetra.al_udata",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_al_ack,
      { "al-ack", "tetra.al_ack",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_al_reconnect,
      { "al-reconnect", "tetra.al_reconnect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_reserve1,
      { "reserve1", "tetra.reserve1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_reserve2,
      { "reserve2", "tetra.reserve2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_al_disc,
      { "al-disc", "tetra.al_disc",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_nr,
      { "nr", "tetra.nr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_tl_sdu,
      { "tl-sdu", "tetra.tl_sdu",
        FT_UINT32, BASE_DEC, VALS(tetra_U_MLE_PDU_vals), 0,
        "U_MLE_PDU", HFILL }},
    { &hf_tetra_fcs,
      { "fcs", "tetra.fcs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_tetra_u_mle_pdu,
      { "u-mle-pdu", "tetra.u_mle_pdu",
        FT_UINT32, BASE_DEC, VALS(tetra_U_MLE_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_ns,
      { "ns", "tetra.ns",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_u_mle_reserved1,
      { "u-mle-reserved1", "tetra.u_mle_reserved1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_mm,
      { "mm", "tetra.mm",
        FT_UINT32, BASE_DEC, VALS(tetra_U_MM_PDU_vals), 0,
        "U_MM_PDU", HFILL }},
    { &hf_tetra_cmce,
      { "cmce", "tetra.cmce",
        FT_UINT32, BASE_DEC, VALS(tetra_U_CMCE_PDU_vals), 0,
        "U_CMCE_PDU", HFILL }},
    { &hf_tetra_u_mle_reserved2,
      { "u-mle-reserved2", "tetra.u_mle_reserved2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_sndcp,
      { "sndcp", "tetra.sndcp",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_mle,
      { "mle", "tetra.mle",
        FT_UINT32, BASE_DEC, VALS(tetra_UMLE_PDU_vals), 0,
        "UMLE_PDU", HFILL }},
    { &hf_tetra_tetra_management_entity_protocol,
      { "tetra-management-entity-protocol", "tetra.tetra_management_entity_protocol",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_mle_reserved3,
      { "u-mle-reserved3", "tetra.u_mle_reserved3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_lengthIndicationOrCapacityRequest,
      { "lengthIndicationOrCapacityRequest", "tetra.lengthIndicationOrCapacityRequest",
        FT_UINT32, BASE_DEC, VALS(tetra_T_lengthIndicationOrCapacityRequest_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_lengthIndication,
      { "lengthIndication", "tetra.lengthIndication",
        FT_UINT32, BASE_DEC, VALS(tetra_LengthIndication_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_capacityRequest,
      { "capacityRequest", "tetra.capacityRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "FRAG", HFILL }},
    { &hf_tetra_tm_sdu_01,
      { "tm-sdu", "tetra.tm_sdu",
        FT_UINT32, BASE_DEC, VALS(tetra_U_LLC_PDU_vals), 0,
        "U_LLC_PDU", HFILL }},
    { &hf_tetra_frag,
      { "frag", "tetra.frag",
        FT_UINT32, BASE_DEC, VALS(tetra_Frag1_vals), 0,
        "Frag1", HFILL }},
    { &hf_tetra_reservation_requirement,
      { "reservation-requirement", "tetra.reservation_requirement",
        FT_UINT32, BASE_DEC, VALS(tetra_SLOT_APPLY_vals), 0,
        "SLOT_APPLY", HFILL }},
    { &hf_tetra_sub_type,
      { "sub-type", "tetra.sub_type",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_tm_sdu_02,
      { "tm-sdu", "tetra.tm_sdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_264", HFILL }},
    { &hf_tetra_tm_sdu_03,
      { "tm-sdu", "tetra.tm_sdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_120", HFILL }},
    { &hf_tetra_lengthInd_ReservationReq,
      { "lengthInd-ReservationReq", "tetra.lengthInd_ReservationReq",
        FT_UINT32, BASE_DEC, VALS(tetra_LengthIndOrReservationReq_vals), 0,
        "LengthIndOrReservationReq", HFILL }},
    { &hf_tetra_tm_sdu_04,
      { "tm-sdu", "tetra.tm_sdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_258", HFILL }},
    { &hf_tetra_pdu_subtype,
      { "pdu-subtype", "tetra.pdu_subtype",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_tm_sdu_05,
      { "tm-sdu", "tetra.tm_sdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_114", HFILL }},
    { &hf_tetra_lengthInd_ReservationReq_01,
      { "lengthInd-ReservationReq", "tetra.lengthInd_ReservationReq",
        FT_UINT32, BASE_DEC, VALS(tetra_T_lengthInd_ReservationReq_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_lengthInd,
      { "lengthInd", "tetra.lengthInd",
        FT_UINT32, BASE_DEC, VALS(tetra_LengthIndMacHu_vals), 0,
        "LengthIndMacHu", HFILL }},
    { &hf_tetra_tm_sdu_06,
      { "tm-sdu", "tetra.tm_sdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_85", HFILL }},
    { &hf_tetra_position_of_grant,
      { "position-of-grant", "tetra.position_of_grant",
        FT_UINT32, BASE_DEC, VALS(tetra_Position_Of_Grant_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_lengthIndication_01,
      { "lengthIndication", "tetra.lengthIndication",
        FT_UINT32, BASE_DEC, VALS(tetra_LengthIndicationMacEndDl_vals), 0,
        "LengthIndicationMacEndDl", HFILL }},
    { &hf_tetra_slot_granting,
      { "slot-granting", "tetra.slot_granting",
        FT_UINT32, BASE_DEC, VALS(tetra_T_slot_granting_vals), 0,
        "T_slot_granting", HFILL }},
    { &hf_tetra_none,
      { "none", "tetra.none",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_slot_granting_param,
      { "slot-granting-param", "tetra.slot_granting_param",
        FT_NONE, BASE_NONE, NULL, 0,
        "SlotGranting", HFILL }},
    { &hf_tetra_channel_allocation,
      { "channel-allocation", "tetra.channel_allocation",
        FT_UINT32, BASE_DEC, VALS(tetra_T_channel_allocation_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_channel_allocation_element,
      { "channel-allocation-element", "tetra.channel_allocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChannelAllocation", HFILL }},
    { &hf_tetra_tm_sdu_07,
      { "tm-sdu", "tetra.tm_sdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_255", HFILL }},
    { &hf_tetra_capacity_allocation,
      { "capacity-allocation", "tetra.capacity_allocation",
        FT_UINT32, BASE_DEC, VALS(tetra_Capacity_Allocation_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_granting_delay,
      { "granting-delay", "tetra.granting_delay",
        FT_UINT32, BASE_DEC, VALS(tetra_Granting_delay_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_allocation_type,
      { "allocation-type", "tetra.allocation_type",
        FT_UINT32, BASE_DEC, VALS(tetra_T_allocation_type_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_timeslot_assigned,
      { "timeslot-assigned", "tetra.timeslot_assigned",
        FT_UINT32, BASE_DEC, VALS(tetra_Timeslot_Assigned_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_up_down_assigned,
      { "up-down-assigned", "tetra.up_down_assigned",
        FT_UINT32, BASE_DEC, VALS(tetra_T_up_down_assigned_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_clch_permission,
      { "clch-permission", "tetra.clch_permission",
        FT_UINT32, BASE_DEC, VALS(tetra_CLCH_permission_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_cell_change,
      { "cell-change", "tetra.cell_change",
        FT_UINT32, BASE_DEC, VALS(tetra_Cell_change_flag_vals), 0,
        "Cell_change_flag", HFILL }},
    { &hf_tetra_carrier_number,
      { "carrier-number", "tetra.carrier_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_tetra_extend_carrier_flag,
      { "extend-carrier-flag", "tetra.extend_carrier_flag",
        FT_UINT32, BASE_DEC, VALS(tetra_T_extend_carrier_flag_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_extended,
      { "extended", "tetra.extended",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extended_carrier_flag", HFILL }},
    { &hf_tetra_monitoring_pattern,
      { "monitoring-pattern", "tetra.monitoring_pattern",
        FT_UINT32, BASE_DEC, VALS(tetra_T_monitoring_pattern_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_one,
      { "one", "tetra.one",
        FT_UINT32, BASE_DEC, VALS(tetra_Monitoring_pattern_vals), 0,
        "Monitoring_pattern", HFILL }},
    { &hf_tetra_none1,
      { "none1", "tetra.none1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_none2,
      { "none2", "tetra.none2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_none3,
      { "none3", "tetra.none3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_offset_01,
      { "offset", "tetra.offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_reverse_operation_01,
      { "reverse-operation", "tetra.reverse_operation",
        FT_UINT32, BASE_DEC, VALS(tetra_T_reverse_operation_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_pdu_type_02,
      { "pdu-type", "tetra.pdu_type",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_fill_bit_ind,
      { "fill-bit-ind", "tetra.fill_bit_ind",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_position_of_grant_01,
      { "position-of-grant", "tetra.position_of_grant",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_slot_granting_01,
      { "slot-granting", "tetra.slot_granting",
        FT_UINT32, BASE_DEC, VALS(tetra_T_slot_granting_01_vals), 0,
        "T_slot_granting_01", HFILL }},
    { &hf_tetra_channel_allocation_01,
      { "channel-allocation", "tetra.channel_allocation",
        FT_UINT32, BASE_DEC, VALS(tetra_T_channel_allocation_01_vals), 0,
        "T_channel_allocation_01", HFILL }},
    { &hf_tetra_tm_sdu_08,
      { "tm-sdu", "tetra.tm_sdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_111", HFILL }},
    { &hf_tetra_encryption_mode,
      { "encryption-mode", "tetra.encryption_mode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_access_ack,
      { "access-ack", "tetra.access_ack",
        FT_UINT32, BASE_DEC, VALS(tetra_T_access_ack_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_lengthIndication_02,
      { "lengthIndication", "tetra.lengthIndication",
        FT_UINT32, BASE_DEC, VALS(tetra_LengthIndicationMacResource_vals), 0,
        "LengthIndicationMacResource", HFILL }},
    { &hf_tetra_address_01,
      { "address", "tetra.address",
        FT_UINT32, BASE_DEC, VALS(tetra_AddressMacResource_vals), 0,
        "AddressMacResource", HFILL }},
    { &hf_tetra_power_control,
      { "power-control", "tetra.power_control",
        FT_UINT32, BASE_DEC, VALS(tetra_T_power_control_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_powerParameters,
      { "powerParameters", "tetra.powerParameters",
        FT_UINT32, BASE_DEC, VALS(tetra_PowerControl_vals), 0,
        "PowerControl", HFILL }},
    { &hf_tetra_slot_granting_02,
      { "slot-granting", "tetra.slot_granting",
        FT_UINT32, BASE_DEC, VALS(tetra_T_slot_granting_02_vals), 0,
        "T_slot_granting_02", HFILL }},
    { &hf_tetra_channel_allocation_02,
      { "channel-allocation", "tetra.channel_allocation",
        FT_UINT32, BASE_DEC, VALS(tetra_T_channel_allocation_02_vals), 0,
        "T_channel_allocation_02", HFILL }},
    { &hf_tetra_tm_sdu_09,
      { "tm-sdu", "tetra.tm_sdu",
        FT_UINT32, BASE_DEC, VALS(tetra_D_LLC_PDU_vals), 0,
        "D_LLC_PDU", HFILL }},
    { &hf_tetra_null_pdu,
      { "null-pdu", "tetra.null_pdu",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_ssi_01,
      { "ssi", "tetra.ssi",
        FT_NONE, BASE_NONE, NULL, 0,
        "SSI_NEED", HFILL }},
    { &hf_tetra_eventLabel_01,
      { "eventLabel", "tetra.eventLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        "EVENT_NEED", HFILL }},
    { &hf_tetra_ussi_01,
      { "ussi", "tetra.ussi",
        FT_NONE, BASE_NONE, NULL, 0,
        "USSI_NEED", HFILL }},
    { &hf_tetra_smi_01,
      { "smi", "tetra.smi",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMI_NEED", HFILL }},
    { &hf_tetra_ssi_eventLabel,
      { "ssi-eventLabel", "tetra.ssi_eventLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        "SSI_EVENT_NEED", HFILL }},
    { &hf_tetra_ssi_usage_maker,
      { "ssi-usage-maker", "tetra.ssi_usage_maker",
        FT_NONE, BASE_NONE, NULL, 0,
        "SSI_USAGE_NEED", HFILL }},
    { &hf_tetra_smi_eventLabel,
      { "smi-eventLabel", "tetra.smi_eventLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMI_EVENT_NEED", HFILL }},
    { &hf_tetra_other,
      { "other", "tetra.other",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTHER_DATA", HFILL }},
    { &hf_tetra_eventlabel,
      { "eventlabel", "tetra.eventlabel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_tetra_ventlabel,
      { "ventlabel", "tetra.ventlabel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_tetra_usage_maker,
      { "usage-maker", "tetra.usage_maker",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_smi_eventlabel,
      { "smi-eventlabel", "tetra.smi_eventlabel",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_tetra_broadcast_channel,
      { "broadcast-channel", "tetra.broadcast_channel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_access_code,
      { "access-code", "tetra.access_code",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_imm_01,
      { "imm", "tetra.imm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_wt_01,
      { "wt", "tetra.wt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_nu_01,
      { "nu", "tetra.nu",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_frame_len_factor_01,
      { "frame-len-factor", "tetra.frame_len_factor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_timeslot_pointer_01,
      { "timeslot-pointer", "tetra.timeslot_pointer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_min_priority,
      { "min-priority", "tetra.min_priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_optional_field,
      { "optional-field", "tetra.optional_field",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_field_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_class_bitmap,
      { "class-bitmap", "tetra.class_bitmap",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_tetra_gssi,
      { "gssi", "tetra.gssi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_33554431", HFILL }},
    { &hf_tetra_reserved_03,
      { "reserved", "tetra.reserved",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_filler_bits,
      { "filler-bits", "tetra.filler_bits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_bl_adata_01,
      { "bl-adata", "tetra.bl_adata",
        FT_NONE, BASE_NONE, NULL, 0,
        "D_BL_ADATA", HFILL }},
    { &hf_tetra_bl_data_01,
      { "bl-data", "tetra.bl_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "D_BL_DATA", HFILL }},
    { &hf_tetra_bl_udata_01,
      { "bl-udata", "tetra.bl_udata",
        FT_UINT32, BASE_DEC, VALS(tetra_D_MLE_PDU_vals), 0,
        "D_MLE_PDU", HFILL }},
    { &hf_tetra_bl_ack_01,
      { "bl-ack", "tetra.bl_ack",
        FT_NONE, BASE_NONE, NULL, 0,
        "D_BL_ACK", HFILL }},
    { &hf_tetra_bl_adata_fcs_01,
      { "bl-adata-fcs", "tetra.bl_adata_fcs",
        FT_NONE, BASE_NONE, NULL, 0,
        "D_BL_ADATA_FCS", HFILL }},
    { &hf_tetra_bl_data_fcs_01,
      { "bl-data-fcs", "tetra.bl_data_fcs",
        FT_NONE, BASE_NONE, NULL, 0,
        "D_BL_DATA_FCS", HFILL }},
    { &hf_tetra_bl_udata_fcs_01,
      { "bl-udata-fcs", "tetra.bl_udata_fcs",
        FT_NONE, BASE_NONE, NULL, 0,
        "D_MLE_PDU_FCS", HFILL }},
    { &hf_tetra_bl_ack_fcs_01,
      { "bl-ack-fcs", "tetra.bl_ack_fcs",
        FT_NONE, BASE_NONE, NULL, 0,
        "D_BL_ACK_FCS", HFILL }},
    { &hf_tetra_tl_sdu_01,
      { "tl-sdu", "tetra.tl_sdu",
        FT_UINT32, BASE_DEC, VALS(tetra_D_MLE_PDU_vals), 0,
        "D_MLE_PDU", HFILL }},
    { &hf_tetra_d_mle_pdu,
      { "d-mle-pdu", "tetra.d_mle_pdu",
        FT_UINT32, BASE_DEC, VALS(tetra_D_MLE_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_mm_01,
      { "mm", "tetra.mm",
        FT_UINT32, BASE_DEC, VALS(tetra_D_MM_PDU_vals), 0,
        "D_MM_PDU", HFILL }},
    { &hf_tetra_cmce_01,
      { "cmce", "tetra.cmce",
        FT_UINT32, BASE_DEC, VALS(tetra_D_CMCE_PDU_vals), 0,
        "D_CMCE_PDU", HFILL }},
    { &hf_tetra_mle_01,
      { "mle", "tetra.mle",
        FT_UINT32, BASE_DEC, VALS(tetra_DMLE_PDU_vals), 0,
        "DMLE_PDU", HFILL }},
    { &hf_tetra_u_prepare,
      { "u-prepare", "tetra.u_prepare",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_umle_reserved1,
      { "umle-reserved1", "tetra.umle_reserved1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_umle_reserved2,
      { "umle-reserved2", "tetra.umle_reserved2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_umle_reserved3,
      { "umle-reserved3", "tetra.umle_reserved3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_restore,
      { "u-restore", "tetra.u_restore",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_umle_reserved4,
      { "umle-reserved4", "tetra.umle_reserved4",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_umle_reserved5,
      { "umle-reserved5", "tetra.umle_reserved5",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_umle_reserved6,
      { "umle-reserved6", "tetra.umle_reserved6",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_new_cell,
      { "d-new-cell", "tetra.d_new_cell",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_prepare_fail,
      { "d-prepare-fail", "tetra.d_prepare_fail",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_nwrk_broadcast,
      { "d-nwrk-broadcast", "tetra.d_nwrk_broadcast",
        FT_NONE, BASE_NONE, NULL, 0,
        "D_NWRK_BRDADCAST", HFILL }},
    { &hf_tetra_dmle_reserved1,
      { "dmle-reserved1", "tetra.dmle_reserved1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_restore_ack,
      { "d-restore-ack", "tetra.d_restore_ack",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_restore_fail,
      { "d-restore-fail", "tetra.d_restore_fail",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_dmle_reserved2,
      { "dmle-reserved2", "tetra.dmle_reserved2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_dmle_reserved3,
      { "dmle-reserved3", "tetra.dmle_reserved3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_optional_elements,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_no_type2,
      { "no-type2", "tetra.no_type2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_type2_parameters,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_cell_number,
      { "cell-number", "tetra.cell_number",
        FT_UINT32, BASE_DEC, VALS(tetra_T_cell_number_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_cell_number_01,
      { "cell-number", "tetra.cell_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_tetra_sdu,
      { "sdu", "tetra.sdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_tetra_optional_elements_01,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_01_vals), 0,
        "T_optional_elements_01", HFILL }},
    { &hf_tetra_type2_parameters_01,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_01", HFILL }},
    { &hf_tetra_mcc_01,
      { "mcc", "tetra.mcc",
        FT_UINT32, BASE_DEC, VALS(tetra_T_mcc_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_mnc_01,
      { "mnc", "tetra.mnc",
        FT_UINT32, BASE_DEC, VALS(tetra_T_mnc_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_la_01,
      { "la", "tetra.la",
        FT_UINT32, BASE_DEC, VALS(tetra_T_la_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_channel_command_valid,
      { "channel-command-valid", "tetra.channel_command_valid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_optional_elements_02,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_02_vals), 0,
        "T_optional_elements_02", HFILL }},
    { &hf_tetra_fail_cause,
      { "fail-cause", "tetra.fail_cause",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_optional_elements_03,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_03_vals), 0,
        "T_optional_elements_03", HFILL }},
    { &hf_tetra_cell_re_select_parameters,
      { "cell-re-select-parameters", "tetra.cell_re_select_parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_tetra_optional_elements_04,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_04_vals), 0,
        "T_optional_elements_04", HFILL }},
    { &hf_tetra_type2_parameters_02,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_02", HFILL }},
    { &hf_tetra_tetra_network_time,
      { "tetra-network-time", "tetra.tetra_network_time",
        FT_UINT32, BASE_DEC, VALS(tetra_T_tetra_network_time_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_tetra_network_time_01,
      { "tetra-network-time", "tetra.tetra_network_time",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_number_of_neighbour_cells,
      { "number-of-neighbour-cells", "tetra.number_of_neighbour_cells",
        FT_UINT32, BASE_DEC, VALS(tetra_T_number_of_neighbour_cells_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_number_of_neighbour_cells_01,
      { "number-of-neighbour-cells", "tetra.number_of_neighbour_cells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_network_time,
      { "network-time", "tetra.network_time",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_local_time_offset_sign,
      { "local-time-offset-sign", "tetra.local_time_offset_sign",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_local_time_offset,
      { "local-time-offset", "tetra.local_time_offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_year,
      { "year", "tetra.year",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_reserved_04,
      { "reserved", "tetra.reserved",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Authentication,
      { "u-Authentication", "tetra.u_Authentication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Itsi_Detach,
      { "u-Itsi-Detach", "tetra.u_Itsi_Detach",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Location_Update_Demand,
      { "u-Location-Update-Demand", "tetra.u_Location_Update_Demand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_MM_Status,
      { "u-MM-Status", "tetra.u_MM_Status",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_MM_reserved1,
      { "u-MM-reserved1", "tetra.u_MM_reserved1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_WK,
      { "u-WK", "tetra.u_WK",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_MM_reserved3,
      { "u-MM-reserved3", "tetra.u_MM_reserved3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Attach_Detach_Group_Identity,
      { "u-Attach-Detach-Group-Identity", "tetra.u_Attach_Detach_Group_Identity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Attach_Detach_Group_Identity_Ack,
      { "u-Attach-Detach-Group-Identity-Ack", "tetra.u_Attach_Detach_Group_Identity_Ack",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_TEI_Provide,
      { "u-TEI-Provide", "tetra.u_TEI_Provide",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_MM_reserved6,
      { "u-MM-reserved6", "tetra.u_MM_reserved6",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Disabled_Status,
      { "u-Disabled-Status", "tetra.u_Disabled_Status",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_MM_reserved7,
      { "u-MM-reserved7", "tetra.u_MM_reserved7",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_MM_reserved8,
      { "u-MM-reserved8", "tetra.u_MM_reserved8",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_MM_reserved9,
      { "u-MM-reserved9", "tetra.u_MM_reserved9",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_MM_Function_Not_Support,
      { "u-MM-Function-Not-Support", "tetra.u_MM_Function_Not_Support",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Otar,
      { "d-Otar", "tetra.d_Otar",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Authentication,
      { "d-Authentication", "tetra.d_Authentication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Authentication_Reject,
      { "d-Authentication-Reject", "tetra.d_Authentication_Reject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Disable,
      { "d-Disable", "tetra.d_Disable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Enable,
      { "d-Enable", "tetra.d_Enable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Location_Update_Accept,
      { "d-Location-Update-Accept", "tetra.d_Location_Update_Accept",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Location_Update_Command,
      { "d-Location-Update-Command", "tetra.d_Location_Update_Command",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Location_Update_Reject,
      { "d-Location-Update-Reject", "tetra.d_Location_Update_Reject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_MM_reserved2,
      { "d-MM-reserved2", "tetra.d_MM_reserved2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Location_Update_Proceeding,
      { "d-Location-Update-Proceeding", "tetra.d_Location_Update_Proceeding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Attach_Detach_Group_Identity,
      { "d-Attach-Detach-Group-Identity", "tetra.d_Attach_Detach_Group_Identity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Attach_Detach_Group_Identity_Ack,
      { "d-Attach-Detach-Group-Identity-Ack", "tetra.d_Attach_Detach_Group_Identity_Ack",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_MM_Status,
      { "d-MM-Status", "tetra.d_MM_Status",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_MM_reserved5,
      { "d-MM-reserved5", "tetra.d_MM_reserved5",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_MM_reserved6,
      { "d-MM-reserved6", "tetra.d_MM_reserved6",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_MM_Function_Not_Support,
      { "d-MM-Function-Not-Support", "tetra.d_MM_Function_Not_Support",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_attach_detach_identifiet,
      { "attach-detach-identifiet", "tetra.attach_detach_identifiet",
        FT_UINT32, BASE_DEC, VALS(tetra_T_attach_detach_identifiet_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_attach,
      { "attach", "tetra.attach",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_lifetime,
      { "lifetime", "tetra.lifetime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_class_of_usage,
      { "class-of-usage", "tetra.class_of_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_detach,
      { "detach", "tetra.detach",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_detach_downlike,
      { "detach-downlike", "tetra.detach_downlike",
        FT_UINT32, BASE_DEC, VALS(tetra_T_detach_downlike_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_address_type,
      { "address-type", "tetra.address_type",
        FT_UINT32, BASE_DEC, VALS(tetra_T_address_type_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_gssi_01,
      { "gssi", "tetra.gssi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_tetra_gssi_extension,
      { "gssi-extension", "tetra.gssi_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_extension,
      { "extension", "tetra.extension",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_tetra_vgssi,
      { "vgssi", "tetra.vgssi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_tetra_attach_detach_identifiet_01,
      { "attach-detach-identifiet", "tetra.attach_detach_identifiet",
        FT_UINT32, BASE_DEC, VALS(tetra_T_attach_detach_identifiet_01_vals), 0,
        "T_attach_detach_identifiet_01", HFILL }},
    { &hf_tetra_attach_01,
      { "attach", "tetra.attach",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_attach_01", HFILL }},
    { &hf_tetra_detach_01,
      { "detach", "tetra.detach",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_detach_01", HFILL }},
    { &hf_tetra_detach_uplike,
      { "detach-uplike", "tetra.detach_uplike",
        FT_UINT32, BASE_DEC, VALS(tetra_T_detach_uplike_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_address_type_01,
      { "address-type", "tetra.address_type",
        FT_UINT32, BASE_DEC, VALS(tetra_T_address_type_01_vals), 0,
        "T_address_type_01", HFILL }},
    { &hf_tetra_gssi_extension_01,
      { "gssi-extension", "tetra.gssi_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_gssi_extension_01", HFILL }},
    { &hf_tetra_location_update_type,
      { "location-update-type", "tetra.location_update_type",
        FT_UINT32, BASE_DEC, VALS(tetra_UPDATE_TYPE_vals), 0,
        "UPDATE_TYPE", HFILL }},
    { &hf_tetra_optional_elements_05,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_05_vals), 0,
        "T_optional_elements_05", HFILL }},
    { &hf_tetra_type2_parameters_03,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_03", HFILL }},
    { &hf_tetra_ssi_02,
      { "ssi", "tetra.ssi",
        FT_UINT32, BASE_DEC, VALS(tetra_T_ssi_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_ssi_03,
      { "ssi", "tetra.ssi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_tetra_address_extension,
      { "address-extension", "tetra.address_extension",
        FT_UINT32, BASE_DEC, VALS(tetra_T_address_extension_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_address_extension_01,
      { "address-extension", "tetra.address_extension",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_tetra_suscriber_class,
      { "suscriber-class", "tetra.suscriber_class",
        FT_UINT32, BASE_DEC, VALS(tetra_T_suscriber_class_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_suscriber_class_01,
      { "suscriber-class", "tetra.suscriber_class",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_tetra_energy_saving_mode,
      { "energy-saving-mode", "tetra.energy_saving_mode",
        FT_UINT32, BASE_DEC, VALS(tetra_T_energy_saving_mode_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_energy_saving_mode_01,
      { "energy-saving-mode", "tetra.energy_saving_mode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_scch_info,
      { "scch-info", "tetra.scch_info",
        FT_UINT32, BASE_DEC, VALS(tetra_T_scch_info_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_scch_info_01,
      { "scch-info", "tetra.scch_info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_tetra_type3,
      { "type3", "tetra.type3",
        FT_UINT32, BASE_DEC, VALS(tetra_T_type3_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_no_type3,
      { "no-type3", "tetra.no_type3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_type3_elements,
      { "type3-elements", "tetra.type3_elements",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_type2_existance,
      { "type2-existance", "tetra.type2_existance",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_type3_identifier,
      { "type3-identifier", "tetra.type3_identifier",
        FT_UINT32, BASE_DEC, VALS(tetra_TYPE3_IDENTIFIER_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_new_ra,
      { "new-ra", "tetra.new_ra",
        FT_UINT32, BASE_DEC, VALS(tetra_T_new_ra_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_new_ra_01,
      { "new-ra", "tetra.new_ra",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_group_identity_location_accept,
      { "group-identity-location-accept", "tetra.group_identity_location_accept",
        FT_UINT32, BASE_DEC, VALS(tetra_T_group_identity_location_accept_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_group_identity_location_accept_01,
      { "group-identity-location-accept", "tetra.group_identity_location_accept",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_group_predefined_lifetime,
      { "group-predefined-lifetime", "tetra.group_predefined_lifetime",
        FT_UINT32, BASE_DEC, VALS(tetra_T_group_predefined_lifetime_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_group_predefined_lifetime_01,
      { "group-predefined-lifetime", "tetra.group_predefined_lifetime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_group_identity_downlink,
      { "group-identity-downlink", "tetra.group_identity_downlink",
        FT_UINT32, BASE_DEC, VALS(tetra_T_group_identity_downlink_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_group_identity_downlink_01,
      { "group-identity-downlink", "tetra.group_identity_downlink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_proprietary,
      { "proprietary", "tetra.proprietary",
        FT_UINT32, BASE_DEC, VALS(tetra_T_proprietary_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_proprietary_01,
      { "proprietary", "tetra.proprietary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_reject_cause,
      { "reject-cause", "tetra.reject_cause",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_tetra_cipher_control,
      { "cipher-control", "tetra.cipher_control",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_status_uplink,
      { "status-uplink", "tetra.status_uplink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_scanning_on_off,
      { "scanning-on-off", "tetra.scanning_on_off",
        FT_UINT32, BASE_DEC, VALS(tetra_T_scanning_on_off_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_status_downlink,
      { "status-downlink", "tetra.status_downlink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_u_Alert,
      { "u-Alert", "tetra.u_Alert",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_reserved1,
      { "reserved1", "tetra.reserved1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Connect,
      { "u-Connect", "tetra.u_Connect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_reserved2,
      { "reserved2", "tetra.reserved2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Disconnect,
      { "u-Disconnect", "tetra.u_Disconnect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Info,
      { "u-Info", "tetra.u_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Release,
      { "u-Release", "tetra.u_Release",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Setup,
      { "u-Setup", "tetra.u_Setup",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Status,
      { "u-Status", "tetra.u_Status",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Tx_Ceased,
      { "u-Tx-Ceased", "tetra.u_Tx_Ceased",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Tx_Demand,
      { "u-Tx-Demand", "tetra.u_Tx_Demand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_reserved3,
      { "reserved3", "tetra.reserved3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_reserved4,
      { "reserved4", "tetra.reserved4",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_reserved5,
      { "reserved5", "tetra.reserved5",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Call_Restore,
      { "u-Call-Restore", "tetra.u_Call_Restore",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_SDS_Data,
      { "u-SDS-Data", "tetra.u_SDS_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_u_Facility,
      { "u-Facility", "tetra.u_Facility",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_call_identifier,
      { "call-identifier", "tetra.call_identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_tetra_disconnect_cause,
      { "disconnect-cause", "tetra.disconnect_cause",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_tetra_area_selection,
      { "area-selection", "tetra.area_selection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_called_party_type_identifier,
      { "called-party-type-identifier", "tetra.called_party_type_identifier",
        FT_UINT32, BASE_DEC, VALS(tetra_T_called_party_type_identifier_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_sna,
      { "sna", "tetra.sna",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_tetra_ssi_extension,
      { "ssi-extension", "tetra.ssi_extension",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_48", HFILL }},
    { &hf_tetra_short_data_type_identifier,
      { "short-data-type-identifier", "tetra.short_data_type_identifier",
        FT_UINT32, BASE_DEC, VALS(tetra_T_short_data_type_identifier_vals), 0,
        "T_short_data_type_identifier", HFILL }},
    { &hf_tetra_data_1,
      { "data-1", "tetra.data_1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_tetra_data_2,
      { "data-2", "tetra.data_2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_tetra_data_3,
      { "data-3", "tetra.data_3",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_tetra_length_indicator_data_4,
      { "length-indicator-data-4", "tetra.length_indicator_data_4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4194304", HFILL }},
    { &hf_tetra_called_party_type_identifier_01,
      { "called-party-type-identifier", "tetra.called_party_type_identifier",
        FT_UINT32, BASE_DEC, VALS(tetra_T_called_party_type_identifier_01_vals), 0,
        "T_called_party_type_identifier_01", HFILL }},
    { &hf_tetra_short_number_address,
      { "short-number-address", "tetra.short_number_address",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_tetra_called_ssi_called_extension,
      { "called-ssi-called-extension", "tetra.called_ssi_called_extension",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_48", HFILL }},
    { &hf_tetra_pre_coded_status,
      { "pre-coded-status", "tetra.pre_coded_status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_tetra_call_id,
      { "call-id", "tetra.call_id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_tetra_poll_response,
      { "poll-response", "tetra.poll_response",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_d_Alert,
      { "d-Alert", "tetra.d_Alert",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Call_Proceeding,
      { "d-Call-Proceeding", "tetra.d_Call_Proceeding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Connect,
      { "d-Connect", "tetra.d_Connect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Connect_Ack,
      { "d-Connect-Ack", "tetra.d_Connect_Ack",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Disconnect,
      { "d-Disconnect", "tetra.d_Disconnect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Info,
      { "d-Info", "tetra.d_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Release,
      { "d-Release", "tetra.d_Release",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Setup,
      { "d-Setup", "tetra.d_Setup",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Status,
      { "d-Status", "tetra.d_Status",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Tx_Ceased,
      { "d-Tx-Ceased", "tetra.d_Tx_Ceased",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Tx_Continue,
      { "d-Tx-Continue", "tetra.d_Tx_Continue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Tx_Granted,
      { "d-Tx-Granted", "tetra.d_Tx_Granted",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Tx_Wait,
      { "d-Tx-Wait", "tetra.d_Tx_Wait",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Tx_Interrupt,
      { "d-Tx-Interrupt", "tetra.d_Tx_Interrupt",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Call_Restore,
      { "d-Call-Restore", "tetra.d_Call_Restore",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_SDS_Data,
      { "d-SDS-Data", "tetra.d_SDS_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_d_Facility,
      { "d-Facility", "tetra.d_Facility",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_calling_party_type_identifier,
      { "calling-party-type-identifier", "tetra.calling_party_type_identifier",
        FT_UINT32, BASE_DEC, VALS(tetra_T_calling_party_type_identifier_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_ssi_extension_01,
      { "ssi-extension", "tetra.ssi_extension",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_tetra_short_data_type_identifier_01,
      { "short-data-type-identifier", "tetra.short_data_type_identifier",
        FT_UINT32, BASE_DEC, VALS(tetra_T_short_data_type_identifier_01_vals), 0,
        "T_short_data_type_identifier_01", HFILL }},
    { &hf_tetra_data_3_01,
      { "data-3", "tetra.data_3",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_tetra_calling_party_type_identifier_01,
      { "calling-party-type-identifier", "tetra.calling_party_type_identifier",
        FT_UINT32, BASE_DEC, VALS(tetra_T_calling_party_type_identifier_01_vals), 0,
        "T_calling_party_type_identifier_01", HFILL }},
    { &hf_tetra_calling_party_address_SSI,
      { "calling-party-address-SSI", "tetra.calling_party_address_SSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_tetra_reset_call_time_out_timer,
      { "reset-call-time-out-timer", "tetra.reset_call_time_out_timer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_poll_request,
      { "poll-request", "tetra.poll_request",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_transmission_request_permission,
      { "transmission-request-permission", "tetra.transmission_request_permission",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_continue,
      { "continue", "tetra.continue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_request_to_append_LA,
      { "request-to-append-LA", "tetra.request_to_append_LA",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_cipher_control_01,
      { "cipher-control", "tetra.cipher_control",
        FT_UINT32, BASE_DEC, VALS(tetra_T_cipher_control_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_no_cipher,
      { "no-cipher", "tetra.no_cipher",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_ciphering_parameters,
      { "ciphering-parameters", "tetra.ciphering_parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_tetra_class_of_MS,
      { "class-of-MS", "tetra.class_of_MS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_tetra_optional_elements_06,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_06_vals), 0,
        "T_optional_elements_06", HFILL }},
    { &hf_tetra_type2_parameters_04,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_04", HFILL }},
    { &hf_tetra_energy_saving_mode_02,
      { "energy-saving-mode", "tetra.energy_saving_mode",
        FT_UINT32, BASE_DEC, VALS(tetra_T_energy_saving_mode_01_vals), 0,
        "T_energy_saving_mode_01", HFILL }},
    { &hf_tetra_la_information,
      { "la-information", "tetra.la_information",
        FT_UINT32, BASE_DEC, VALS(tetra_T_la_information_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_la_information_01,
      { "la-information", "tetra.la_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_tetra_ssi_04,
      { "ssi", "tetra.ssi",
        FT_UINT32, BASE_DEC, VALS(tetra_T_ssi_01_vals), 0,
        "T_ssi_01", HFILL }},
    { &hf_tetra_address_extension_02,
      { "address-extension", "tetra.address_extension",
        FT_UINT32, BASE_DEC, VALS(tetra_T_address_extension_01_vals), 0,
        "T_address_extension_01", HFILL }},
    { &hf_tetra_type3_01,
      { "type3", "tetra.type3",
        FT_UINT32, BASE_DEC, VALS(tetra_T_type3_01_vals), 0,
        "T_type3_01", HFILL }},
    { &hf_tetra_type3_elements_01,
      { "type3-elements", "tetra.type3_elements",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type3_elements_01", HFILL }},
    { &hf_tetra_group_identity_location_demand,
      { "group-identity-location-demand", "tetra.group_identity_location_demand",
        FT_UINT32, BASE_DEC, VALS(tetra_T_group_identity_location_demand_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_group_identity_location_demand_01,
      { "group-identity-location-demand", "tetra.group_identity_location_demand",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_group_report_response,
      { "group-report-response", "tetra.group_report_response",
        FT_UINT32, BASE_DEC, VALS(tetra_T_group_report_response_vals), 0,
        "T_group_report_response", HFILL }},
    { &hf_tetra_group_report_response_01,
      { "group-report-response", "tetra.group_report_response",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_group_identity_uplink,
      { "group-identity-uplink", "tetra.group_identity_uplink",
        FT_UINT32, BASE_DEC, VALS(tetra_T_group_identity_uplink_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_group_identity_uplink_01,
      { "group-identity-uplink", "tetra.group_identity_uplink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_proprietary_02,
      { "proprietary", "tetra.proprietary",
        FT_UINT32, BASE_DEC, VALS(tetra_T_proprietary_01_vals), 0,
        "T_proprietary_01", HFILL }},
    { &hf_tetra_group_identity_report,
      { "group-identity-report", "tetra.group_identity_report",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_group_identity_attach_detach_mode,
      { "group-identity-attach-detach-mode", "tetra.group_identity_attach_detach_mode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_optional_elements_07,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_07_vals), 0,
        "T_optional_elements_07", HFILL }},
    { &hf_tetra_type2_element,
      { "type2-element", "tetra.type2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_type3_02,
      { "type3", "tetra.type3",
        FT_UINT32, BASE_DEC, VALS(tetra_T_type3_02_vals), 0,
        "T_type3_02", HFILL }},
    { &hf_tetra_type3_elements_02,
      { "type3-elements", "tetra.type3_elements",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type3_elements_02", HFILL }},
    { &hf_tetra_length,
      { "length", "tetra.length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_tetra_repeat_num,
      { "repeat-num", "tetra.repeat_num",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_group_identity_uplink_02,
      { "group-identity-uplink", "tetra.group_identity_uplink",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_group_identity_ack_type,
      { "group-identity-ack-type", "tetra.group_identity_ack_type",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_optional_elements_08,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_08_vals), 0,
        "T_optional_elements_08", HFILL }},
    { &hf_tetra_type2_element_01,
      { "type2-element", "tetra.type2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_element_01", HFILL }},
    { &hf_tetra_type3_03,
      { "type3", "tetra.type3",
        FT_UINT32, BASE_DEC, VALS(tetra_T_type3_03_vals), 0,
        "T_type3_03", HFILL }},
    { &hf_tetra_type3_elements_03,
      { "type3-elements", "tetra.type3_elements",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type3_elements_03", HFILL }},
    { &hf_tetra_hook_method_selection,
      { "hook-method-selection", "tetra.hook_method_selection",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_simple_duplex_selection,
      { "simple-duplex-selection", "tetra.simple_duplex_selection",
        FT_UINT32, BASE_DEC, VALS(tetra_T_simple_duplex_selection_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_basic_service_information,
      { "basic-service-information", "tetra.basic_service_information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_request_transmit_send_data,
      { "request-transmit-send-data", "tetra.request_transmit_send_data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_call_priority,
      { "call-priority", "tetra.call_priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_clir_control,
      { "clir-control", "tetra.clir_control",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_called_party_address,
      { "called-party-address", "tetra.called_party_address",
        FT_UINT32, BASE_DEC, VALS(tetra_Calling_party_address_type_vals), 0,
        "Called_party_address_type", HFILL }},
    { &hf_tetra_optional_elements_09,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_09_vals), 0,
        "T_optional_elements_09", HFILL }},
    { &hf_tetra_type2_parameters_05,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_05", HFILL }},
    { &hf_tetra_external_subscriber_number,
      { "external-subscriber-number", "tetra.external_subscriber_number",
        FT_UINT32, BASE_DEC, VALS(tetra_T_external_subscriber_number_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_external_subscriber_number_01,
      { "external-subscriber-number", "tetra.external_subscriber_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_tetra_prop,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_prop_01,
      { "prop", "tetra.prop",
        FT_NONE, BASE_NONE, NULL, 0,
        "Proprietary", HFILL }},
    { &hf_tetra_circuit_mode,
      { "circuit-mode", "tetra.circuit_mode",
        FT_UINT32, BASE_DEC, VALS(tetra_CIRCUIT_vals), 0,
        "CIRCUIT", HFILL }},
    { &hf_tetra_encryption,
      { "encryption", "tetra.encryption",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_communication,
      { "communication", "tetra.communication",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_slots_or_speech,
      { "slots-or-speech", "tetra.slots_or_speech",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_call_identifier_01,
      { "call-identifier", "tetra.call_identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_tetra_simplex_duplex_selection,
      { "simplex-duplex-selection", "tetra.simplex_duplex_selection",
        FT_UINT32, BASE_DEC, VALS(tetra_T_simplex_duplex_selection_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_optional_elements_10,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_10_vals), 0,
        "T_optional_elements_10", HFILL }},
    { &hf_tetra_type2_parameters_06,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_06", HFILL }},
    { &hf_tetra_basic_service_information_01,
      { "basic-service-information", "tetra.basic_service_information",
        FT_UINT32, BASE_DEC, VALS(tetra_T_basic_service_information_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_prop_02,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_01_vals), 0,
        "T_prop_01", HFILL }},
    { &hf_tetra_simplex_duplex_selection_01,
      { "simplex-duplex-selection", "tetra.simplex_duplex_selection",
        FT_UINT32, BASE_DEC, VALS(tetra_T_simplex_duplex_selection_01_vals), 0,
        "T_simplex_duplex_selection_01", HFILL }},
    { &hf_tetra_optional_elements_11,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_11_vals), 0,
        "T_optional_elements_11", HFILL }},
    { &hf_tetra_type2_parameters_07,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_07", HFILL }},
    { &hf_tetra_basic_service_information_02,
      { "basic-service-information", "tetra.basic_service_information",
        FT_UINT32, BASE_DEC, VALS(tetra_T_basic_service_information_01_vals), 0,
        "T_basic_service_information_01", HFILL }},
    { &hf_tetra_prop_03,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_02_vals), 0,
        "T_prop_02", HFILL }},
    { &hf_tetra_optional_elements_12,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_12_vals), 0,
        "T_optional_elements_12", HFILL }},
    { &hf_tetra_type2_parameters_08,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_08", HFILL }},
    { &hf_tetra_prop_04,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_03_vals), 0,
        "T_prop_03", HFILL }},
    { &hf_tetra_tx_demand_priority,
      { "tx-demand-priority", "tetra.tx_demand_priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_encryption_control,
      { "encryption-control", "tetra.encryption_control",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_optional_elements_13,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_13_vals), 0,
        "T_optional_elements_13", HFILL }},
    { &hf_tetra_type2_parameters_09,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_09", HFILL }},
    { &hf_tetra_prop_05,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_04_vals), 0,
        "T_prop_04", HFILL }},
    { &hf_tetra_optional_elements_14,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_14_vals), 0,
        "T_optional_elements_14", HFILL }},
    { &hf_tetra_type2_parameters_10,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_10", HFILL }},
    { &hf_tetra_prop_06,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_05_vals), 0,
        "T_prop_05", HFILL }},
    { &hf_tetra_request_to_transmit_send_data,
      { "request-to-transmit-send-data", "tetra.request_to_transmit_send_data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_other_party_address,
      { "other-party-address", "tetra.other_party_address",
        FT_UINT32, BASE_DEC, VALS(tetra_Calling_party_address_type_vals), 0,
        "Other_party_address_type", HFILL }},
    { &hf_tetra_optional_elements_15,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_15_vals), 0,
        "T_optional_elements_15", HFILL }},
    { &hf_tetra_type2_parameters_11,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_11", HFILL }},
    { &hf_tetra_prop_07,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_06_vals), 0,
        "T_prop_06", HFILL }},
    { &hf_tetra_call_time_out,
      { "call-time-out", "tetra.call_time_out",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_hook_method_selection_01,
      { "hook-method-selection", "tetra.hook_method_selection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_simplex_duplex_selection_02,
      { "simplex-duplex-selection", "tetra.simplex_duplex_selection",
        FT_UINT32, BASE_DEC, VALS(tetra_T_simplex_duplex_selection_02_vals), 0,
        "T_simplex_duplex_selection_02", HFILL }},
    { &hf_tetra_transmission_grant,
      { "transmission-grant", "tetra.transmission_grant",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_tetra_optional_elements_16,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_16_vals), 0,
        "T_optional_elements_16", HFILL }},
    { &hf_tetra_type2_parameters_12,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_12", HFILL }},
    { &hf_tetra_calling_party_address,
      { "calling-party-address", "tetra.calling_party_address",
        FT_UINT32, BASE_DEC, VALS(tetra_T_calling_party_address_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_calling_party_address_01,
      { "calling-party-address", "tetra.calling_party_address",
        FT_UINT32, BASE_DEC, VALS(tetra_Calling_party_address_type_vals), 0,
        "Calling_party_address_type", HFILL }},
    { &hf_tetra_external_subscriber_number_02,
      { "external-subscriber-number", "tetra.external_subscriber_number",
        FT_UINT32, BASE_DEC, VALS(tetra_T_external_subscriber_number_01_vals), 0,
        "T_external_subscriber_number_01", HFILL }},
    { &hf_tetra_external_subscriber_number_03,
      { "external-subscriber-number", "tetra.external_subscriber_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_tetra_prop_08,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_07_vals), 0,
        "T_prop_07", HFILL }},
    { &hf_tetra_call_time_out_setup_phase,
      { "call-time-out-setup-phase", "tetra.call_time_out_setup_phase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_simplex_duplex_selection_03,
      { "simplex-duplex-selection", "tetra.simplex_duplex_selection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_optional_elements_17,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_17_vals), 0,
        "T_optional_elements_17", HFILL }},
    { &hf_tetra_type2_parameters_13,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_13", HFILL }},
    { &hf_tetra_basic_service_information_03,
      { "basic-service-information", "tetra.basic_service_information",
        FT_UINT32, BASE_DEC, VALS(tetra_T_basic_service_information_02_vals), 0,
        "T_basic_service_information_02", HFILL }},
    { &hf_tetra_call_status,
      { "call-status", "tetra.call_status",
        FT_UINT32, BASE_DEC, VALS(tetra_T_call_status_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_call_status_01,
      { "call-status", "tetra.call_status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_notification_indicator,
      { "notification-indicator", "tetra.notification_indicator",
        FT_UINT32, BASE_DEC, VALS(tetra_T_notification_indicator_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_notification_indicator_01,
      { "notification-indicator", "tetra.notification_indicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_tetra_prop_09,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_08_vals), 0,
        "T_prop_08", HFILL }},
    { &hf_tetra_simplex_duplex_selection_04,
      { "simplex-duplex-selection", "tetra.simplex_duplex_selection",
        FT_UINT32, BASE_DEC, VALS(tetra_T_simplex_duplex_selection_03_vals), 0,
        "T_simplex_duplex_selection_03", HFILL }},
    { &hf_tetra_call_queued,
      { "call-queued", "tetra.call_queued",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_optional_elements_18,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_18_vals), 0,
        "T_optional_elements_18", HFILL }},
    { &hf_tetra_type2_parameters_14,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_14", HFILL }},
    { &hf_tetra_basic_service_infomation,
      { "basic-service-infomation", "tetra.basic_service_infomation",
        FT_UINT32, BASE_DEC, VALS(tetra_T_basic_service_infomation_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_basic_service_infomation_01,
      { "basic-service-infomation", "tetra.basic_service_infomation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Basic_service_information", HFILL }},
    { &hf_tetra_notification_indicator_02,
      { "notification-indicator", "tetra.notification_indicator",
        FT_UINT32, BASE_DEC, VALS(tetra_T_notification_indicator_01_vals), 0,
        "T_notification_indicator_01", HFILL }},
    { &hf_tetra_prop_10,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_09_vals), 0,
        "T_prop_09", HFILL }},
    { &hf_tetra_call_time_out_01,
      { "call-time-out", "tetra.call_time_out",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_tetra_simplex_duplex_selection_05,
      { "simplex-duplex-selection", "tetra.simplex_duplex_selection",
        FT_UINT32, BASE_DEC, VALS(tetra_T_simplex_duplex_selection_04_vals), 0,
        "T_simplex_duplex_selection_04", HFILL }},
    { &hf_tetra_call_ownership,
      { "call-ownership", "tetra.call_ownership",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_optional_elements_19,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_19_vals), 0,
        "T_optional_elements_19", HFILL }},
    { &hf_tetra_type2_parameters_15,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_15", HFILL }},
    { &hf_tetra_call_priority_01,
      { "call-priority", "tetra.call_priority",
        FT_UINT32, BASE_DEC, VALS(tetra_T_call_priority_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_call_priority_02,
      { "call-priority", "tetra.call_priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_tetra_basic_service_information_04,
      { "basic-service-information", "tetra.basic_service_information",
        FT_UINT32, BASE_DEC, VALS(tetra_T_basic_service_information_03_vals), 0,
        "T_basic_service_information_03", HFILL }},
    { &hf_tetra_temporary_address,
      { "temporary-address", "tetra.temporary_address",
        FT_UINT32, BASE_DEC, VALS(tetra_T_temporary_address_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_temporary_address_01,
      { "temporary-address", "tetra.temporary_address",
        FT_UINT32, BASE_DEC, VALS(tetra_Calling_party_address_type_vals), 0,
        "Calling_party_address_type", HFILL }},
    { &hf_tetra_notification_indicator_03,
      { "notification-indicator", "tetra.notification_indicator",
        FT_UINT32, BASE_DEC, VALS(tetra_T_notification_indicator_02_vals), 0,
        "T_notification_indicator_02", HFILL }},
    { &hf_tetra_prop_11,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_10_vals), 0,
        "T_prop_10", HFILL }},
    { &hf_tetra_optional_elements_20,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_20_vals), 0,
        "T_optional_elements_20", HFILL }},
    { &hf_tetra_type2_parameters_16,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_16", HFILL }},
    { &hf_tetra_notification_indicator_04,
      { "notification-indicator", "tetra.notification_indicator",
        FT_UINT32, BASE_DEC, VALS(tetra_T_notification_indicator_03_vals), 0,
        "T_notification_indicator_03", HFILL }},
    { &hf_tetra_prop_12,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_11_vals), 0,
        "T_prop_11", HFILL }},
    { &hf_tetra_optional_elements_21,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_21_vals), 0,
        "T_optional_elements_21", HFILL }},
    { &hf_tetra_type2_parameters_17,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_17", HFILL }},
    { &hf_tetra_notification_indicator_05,
      { "notification-indicator", "tetra.notification_indicator",
        FT_UINT32, BASE_DEC, VALS(tetra_T_notification_indicator_04_vals), 0,
        "T_notification_indicator_04", HFILL }},
    { &hf_tetra_prop_13,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_12_vals), 0,
        "T_prop_12", HFILL }},
    { &hf_tetra_reset_call_time_out,
      { "reset-call-time-out", "tetra.reset_call_time_out",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_tetra_optional_elements_22,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_22_vals), 0,
        "T_optional_elements_22", HFILL }},
    { &hf_tetra_type2_parameters_18,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_18", HFILL }},
    { &hf_tetra_new_call_identifier,
      { "new-call-identifier", "tetra.new_call_identifier",
        FT_UINT32, BASE_DEC, VALS(tetra_T_new_call_identifier_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_new_call_identifier_01,
      { "new-call-identifier", "tetra.new_call_identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_tetra_call_time_out_02,
      { "call-time-out", "tetra.call_time_out",
        FT_UINT32, BASE_DEC, VALS(tetra_T_call_time_out_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_call_time_out_03,
      { "call-time-out", "tetra.call_time_out",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_tetra_call_status_02,
      { "call-status", "tetra.call_status",
        FT_UINT32, BASE_DEC, VALS(tetra_T_call_status_01_vals), 0,
        "T_call_status_01", HFILL }},
    { &hf_tetra_modify,
      { "modify", "tetra.modify",
        FT_UINT32, BASE_DEC, VALS(tetra_T_modify_vals), 0,
        NULL, HFILL }},
    { &hf_tetra_modify_01,
      { "modify", "tetra.modify",
        FT_NONE, BASE_NONE, NULL, 0,
        "Modify_type", HFILL }},
    { &hf_tetra_notification_indicator_06,
      { "notification-indicator", "tetra.notification_indicator",
        FT_UINT32, BASE_DEC, VALS(tetra_T_notification_indicator_05_vals), 0,
        "T_notification_indicator_05", HFILL }},
    { &hf_tetra_prop_14,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_13_vals), 0,
        "T_prop_13", HFILL }},
    { &hf_tetra_optional_elements_23,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_23_vals), 0,
        "T_optional_elements_23", HFILL }},
    { &hf_tetra_type2_parameters_19,
      { "type2-parameters", "tetra.type2_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_parameters_19", HFILL }},
    { &hf_tetra_notification_indicator_07,
      { "notification-indicator", "tetra.notification_indicator",
        FT_UINT32, BASE_DEC, VALS(tetra_T_notification_indicator_06_vals), 0,
        "T_notification_indicator_06", HFILL }},
    { &hf_tetra_prop_15,
      { "prop", "tetra.prop",
        FT_UINT32, BASE_DEC, VALS(tetra_T_prop_14_vals), 0,
        "T_prop_14", HFILL }},
    { &hf_tetra_group_identity_ack_request,
      { "group-identity-ack-request", "tetra.group_identity_ack_request",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_optional_elements_24,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_24_vals), 0,
        "T_optional_elements_24", HFILL }},
    { &hf_tetra_type2_element_02,
      { "type2-element", "tetra.type2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_element_02", HFILL }},
    { &hf_tetra_type3_04,
      { "type3", "tetra.type3",
        FT_UINT32, BASE_DEC, VALS(tetra_T_type3_04_vals), 0,
        "T_type3_04", HFILL }},
    { &hf_tetra_type3_elements_04,
      { "type3-elements", "tetra.type3_elements",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type3_elements_04", HFILL }},
    { &hf_tetra_group_identity_downlink_02,
      { "group-identity-downlink", "tetra.group_identity_downlink",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_group_identity_attach_detach_accept,
      { "group-identity-attach-detach-accept", "tetra.group_identity_attach_detach_accept",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tetra_optional_elements_25,
      { "optional-elements", "tetra.optional_elements",
        FT_UINT32, BASE_DEC, VALS(tetra_T_optional_elements_25_vals), 0,
        "T_optional_elements_25", HFILL }},
    { &hf_tetra_type2_element_03,
      { "type2-element", "tetra.type2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type2_element_03", HFILL }},
    { &hf_tetra_type3_05,
      { "type3", "tetra.type3",
        FT_UINT32, BASE_DEC, VALS(tetra_T_type3_05_vals), 0,
        "T_type3_05", HFILL }},
    { &hf_tetra_type3_elements_05,
      { "type3-elements", "tetra.type3_elements",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_type3_elements_05", HFILL }},
    { &hf_tetra_called_party_sna,
      { "called-party-sna", "tetra.called_party_sna",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_tetra_called_party_ssi,
      { "called-party-ssi", "tetra.called_party_ssi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_tetra_called_party_ssi_extention,
      { "called-party-ssi-extention", "tetra.called_party_ssi_extention",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_called_party_extention,
      { "called-party-extention", "tetra.called_party_extention",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_tetra_data_01,
      { "data", "tetra.data",
        FT_UINT32, BASE_DEC, VALS(tetra_T_data_01_vals), 0,
        "T_data_01", HFILL }},
    { &hf_tetra_element1,
      { "element1", "tetra.element1",
        FT_NONE, BASE_NONE, NULL, 0,
        "Type1", HFILL }},
    { &hf_tetra_element,
      { "element", "tetra.element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Type2", HFILL }},
    { &hf_tetra_proprietary_element_owner,
      { "proprietary-element-owner", "tetra.proprietary_element_owner",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tetra_proprietary_element_owner_extension,
      { "proprietary-element-owner-extension", "tetra.proprietary_element_owner_extension",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_tetra_simplex_duplex_selection_06,
      { "simplex-duplex-selection", "tetra.simplex_duplex_selection",
        FT_UINT32, BASE_DEC, VALS(tetra_T_simplex_duplex_selection_05_vals), 0,
        "T_simplex_duplex_selection_05", HFILL }},

/*--- End of included file: packet-tetra-hfarr.c ---*/
#line 614 "../../asn1/tetra/packet-tetra-template.c"
 	};

	/* List of subtrees */
  	static gint *ett[] = {
		&ett_tetra,
		&ett_tetra_header,
		&ett_tetra_length,
		&ett_tetra_txreg,
		&ett_tetra_text,

/*--- Included file: packet-tetra-ettarr.c ---*/
#line 1 "../../asn1/tetra/packet-tetra-ettarr.c"
    &ett_tetra_AACH,
    &ett_tetra_BSCH,
    &ett_tetra_MLE_Sync,
    &ett_tetra_BNCH,
    &ett_tetra_T_hyperframe_or_cck,
    &ett_tetra_T_optional_params,
    &ett_tetra_TS_COMMON_FRAMES,
    &ett_tetra_Default_Code_A,
    &ett_tetra_Extended_Services_Broadcast,
    &ett_tetra_T_section,
    &ett_tetra_PRESENT1,
    &ett_tetra_MAC_ACCESS,
    &ett_tetra_T_data,
    &ett_tetra_Address,
    &ett_tetra_U_LLC_PDU,
    &ett_tetra_U_BL_ACK_FCS,
    &ett_tetra_U_MLE_PDU_FCS,
    &ett_tetra_U_BL_DATA_FCS,
    &ett_tetra_U_BL_ADATA_FCS,
    &ett_tetra_U_MLE_PDU,
    &ett_tetra_ComplexSDU,
    &ett_tetra_T_lengthIndicationOrCapacityRequest,
    &ett_tetra_FRAG,
    &ett_tetra_MAC_FRAG,
    &ett_tetra_MAC_FRAG120,
    &ett_tetra_MAC_END_UPLINK,
    &ett_tetra_MAC_END_UP114,
    &ett_tetra_MAC_END_HU,
    &ett_tetra_T_lengthInd_ReservationReq,
    &ett_tetra_MAC_END_DOWNLINK,
    &ett_tetra_T_slot_granting,
    &ett_tetra_T_channel_allocation,
    &ett_tetra_SlotGranting,
    &ett_tetra_ChannelAllocation,
    &ett_tetra_T_extend_carrier_flag,
    &ett_tetra_T_monitoring_pattern,
    &ett_tetra_Extended_carrier_flag,
    &ett_tetra_MAC_END_DOWN111,
    &ett_tetra_T_slot_granting_01,
    &ett_tetra_T_channel_allocation_01,
    &ett_tetra_MAC_RESOURCE,
    &ett_tetra_OTHER_DATA,
    &ett_tetra_T_power_control,
    &ett_tetra_T_slot_granting_02,
    &ett_tetra_T_channel_allocation_02,
    &ett_tetra_AddressMacResource,
    &ett_tetra_SSI_NEED,
    &ett_tetra_EVENT_NEED,
    &ett_tetra_USSI_NEED,
    &ett_tetra_SMI_NEED,
    &ett_tetra_SSI_EVENT_NEED,
    &ett_tetra_SSI_USAGE_NEED,
    &ett_tetra_SMI_EVENT_NEED,
    &ett_tetra_MAC_ACCESS_DEFINE,
    &ett_tetra_T_optional_field,
    &ett_tetra_D_LLC_PDU,
    &ett_tetra_D_BL_ACK_FCS,
    &ett_tetra_D_MLE_PDU_FCS,
    &ett_tetra_D_BL_ADATA_FCS,
    &ett_tetra_D_BL_DATA_FCS,
    &ett_tetra_U_BL_ACK,
    &ett_tetra_D_BL_ACK,
    &ett_tetra_U_BL_DATA,
    &ett_tetra_D_BL_DATA,
    &ett_tetra_U_BL_ADATA,
    &ett_tetra_D_BL_ADATA,
    &ett_tetra_D_MLE_PDU,
    &ett_tetra_UMLE_PDU,
    &ett_tetra_DMLE_PDU,
    &ett_tetra_U_PREPARE,
    &ett_tetra_T_optional_elements,
    &ett_tetra_T_type2_parameters,
    &ett_tetra_T_cell_number,
    &ett_tetra_U_RESTORE,
    &ett_tetra_T_optional_elements_01,
    &ett_tetra_T_type2_parameters_01,
    &ett_tetra_T_mcc,
    &ett_tetra_T_mnc,
    &ett_tetra_T_la,
    &ett_tetra_D_NEW_CELL,
    &ett_tetra_T_optional_elements_02,
    &ett_tetra_D_PREPARE_FAIL,
    &ett_tetra_T_optional_elements_03,
    &ett_tetra_D_NWRK_BRDADCAST,
    &ett_tetra_T_optional_elements_04,
    &ett_tetra_T_type2_parameters_02,
    &ett_tetra_T_tetra_network_time,
    &ett_tetra_T_number_of_neighbour_cells,
    &ett_tetra_TETRA_NETWORK_TIME,
    &ett_tetra_D_RESTORE_ACK,
    &ett_tetra_D_RESTORE_FAIL,
    &ett_tetra_U_MM_PDU,
    &ett_tetra_D_MM_PDU,
    &ett_tetra_GROUP_IDENTITY_DOWNLINK,
    &ett_tetra_T_attach_detach_identifiet,
    &ett_tetra_T_attach,
    &ett_tetra_T_detach,
    &ett_tetra_T_address_type,
    &ett_tetra_T_gssi_extension,
    &ett_tetra_GROUP_IDENTITY_UPLINK,
    &ett_tetra_T_attach_detach_identifiet_01,
    &ett_tetra_T_attach_01,
    &ett_tetra_T_detach_01,
    &ett_tetra_T_address_type_01,
    &ett_tetra_T_gssi_extension_01,
    &ett_tetra_D_LOCATION_UPDATE_ACCEPT,
    &ett_tetra_T_optional_elements_05,
    &ett_tetra_T_type2_parameters_03,
    &ett_tetra_T_ssi,
    &ett_tetra_T_address_extension,
    &ett_tetra_T_suscriber_class,
    &ett_tetra_T_energy_saving_mode,
    &ett_tetra_T_scch_info,
    &ett_tetra_T_type3,
    &ett_tetra_T_type3_elements,
    &ett_tetra_T_new_ra,
    &ett_tetra_T_group_identity_location_accept,
    &ett_tetra_T_group_predefined_lifetime,
    &ett_tetra_T_group_identity_downlink,
    &ett_tetra_T_proprietary,
    &ett_tetra_D_LOCATION_UPDATE_REJECT,
    &ett_tetra_U_MM_STATUS,
    &ett_tetra_D_MM_STATUS,
    &ett_tetra_U_CMCE_PDU,
    &ett_tetra_U_RELEASE,
    &ett_tetra_U_SDS_DATA,
    &ett_tetra_T_called_party_type_identifier,
    &ett_tetra_T_short_data_type_identifier,
    &ett_tetra_U_STATUS,
    &ett_tetra_T_called_party_type_identifier_01,
    &ett_tetra_U_INFO,
    &ett_tetra_D_CMCE_PDU,
    &ett_tetra_D_SDS_DATA,
    &ett_tetra_T_calling_party_type_identifier,
    &ett_tetra_T_short_data_type_identifier_01,
    &ett_tetra_D_STATUS,
    &ett_tetra_T_calling_party_type_identifier_01,
    &ett_tetra_D_DISCONNECT,
    &ett_tetra_D_INFO,
    &ett_tetra_D_TX_WAIT,
    &ett_tetra_D_TX_CONTINUE,
    &ett_tetra_U_LOCATION_UPDATE_DEMAND,
    &ett_tetra_T_cipher_control,
    &ett_tetra_T_optional_elements_06,
    &ett_tetra_T_type2_parameters_04,
    &ett_tetra_T_energy_saving_mode_01,
    &ett_tetra_T_la_information,
    &ett_tetra_T_ssi_01,
    &ett_tetra_T_address_extension_01,
    &ett_tetra_T_type3_01,
    &ett_tetra_T_type3_elements_01,
    &ett_tetra_T_group_identity_location_demand,
    &ett_tetra_T_group_report_response,
    &ett_tetra_T_group_identity_uplink,
    &ett_tetra_T_proprietary_01,
    &ett_tetra_U_ATTACH_DETACH_GROUP_IDENTITY,
    &ett_tetra_T_optional_elements_07,
    &ett_tetra_T_type2_element,
    &ett_tetra_T_type3_02,
    &ett_tetra_T_type3_elements_02,
    &ett_tetra_U_ATTACH_DETACH_GROUP_IDENTITY_ACK,
    &ett_tetra_T_optional_elements_08,
    &ett_tetra_T_type2_element_01,
    &ett_tetra_T_type3_03,
    &ett_tetra_T_type3_elements_03,
    &ett_tetra_U_SETUP,
    &ett_tetra_T_optional_elements_09,
    &ett_tetra_T_type2_parameters_05,
    &ett_tetra_T_external_subscriber_number,
    &ett_tetra_T_prop,
    &ett_tetra_Basic_service_information,
    &ett_tetra_U_ALERT,
    &ett_tetra_T_optional_elements_10,
    &ett_tetra_T_type2_parameters_06,
    &ett_tetra_T_basic_service_information,
    &ett_tetra_T_prop_01,
    &ett_tetra_U_CONNECT,
    &ett_tetra_T_optional_elements_11,
    &ett_tetra_T_type2_parameters_07,
    &ett_tetra_T_basic_service_information_01,
    &ett_tetra_T_prop_02,
    &ett_tetra_U_TX_CEASED,
    &ett_tetra_T_optional_elements_12,
    &ett_tetra_T_type2_parameters_08,
    &ett_tetra_T_prop_03,
    &ett_tetra_U_TX_DEMAND,
    &ett_tetra_T_optional_elements_13,
    &ett_tetra_T_type2_parameters_09,
    &ett_tetra_T_prop_04,
    &ett_tetra_U_DISCONNECT,
    &ett_tetra_T_optional_elements_14,
    &ett_tetra_T_type2_parameters_10,
    &ett_tetra_T_prop_05,
    &ett_tetra_U_CALL_RESTORE,
    &ett_tetra_T_optional_elements_15,
    &ett_tetra_T_type2_parameters_11,
    &ett_tetra_T_prop_06,
    &ett_tetra_D_SETUP,
    &ett_tetra_T_optional_elements_16,
    &ett_tetra_T_type2_parameters_12,
    &ett_tetra_T_calling_party_address,
    &ett_tetra_T_external_subscriber_number_01,
    &ett_tetra_T_prop_07,
    &ett_tetra_D_CALL_PROCEEDING,
    &ett_tetra_T_optional_elements_17,
    &ett_tetra_T_type2_parameters_13,
    &ett_tetra_T_basic_service_information_02,
    &ett_tetra_T_call_status,
    &ett_tetra_T_notification_indicator,
    &ett_tetra_T_prop_08,
    &ett_tetra_D_ALERT,
    &ett_tetra_T_optional_elements_18,
    &ett_tetra_T_type2_parameters_14,
    &ett_tetra_T_basic_service_infomation,
    &ett_tetra_T_notification_indicator_01,
    &ett_tetra_T_prop_09,
    &ett_tetra_D_CONNECT,
    &ett_tetra_T_optional_elements_19,
    &ett_tetra_T_type2_parameters_15,
    &ett_tetra_T_call_priority,
    &ett_tetra_T_basic_service_information_03,
    &ett_tetra_T_temporary_address,
    &ett_tetra_T_notification_indicator_02,
    &ett_tetra_T_prop_10,
    &ett_tetra_D_CONNECT_ACK,
    &ett_tetra_T_optional_elements_20,
    &ett_tetra_T_type2_parameters_16,
    &ett_tetra_T_notification_indicator_03,
    &ett_tetra_T_prop_11,
    &ett_tetra_D_RELEASE,
    &ett_tetra_T_optional_elements_21,
    &ett_tetra_T_type2_parameters_17,
    &ett_tetra_T_notification_indicator_04,
    &ett_tetra_T_prop_12,
    &ett_tetra_D_CALL_RESTORE,
    &ett_tetra_T_optional_elements_22,
    &ett_tetra_T_type2_parameters_18,
    &ett_tetra_T_new_call_identifier,
    &ett_tetra_T_call_time_out,
    &ett_tetra_T_call_status_01,
    &ett_tetra_T_modify,
    &ett_tetra_T_notification_indicator_05,
    &ett_tetra_T_prop_13,
    &ett_tetra_D_TX_CEASED,
    &ett_tetra_T_optional_elements_23,
    &ett_tetra_T_type2_parameters_19,
    &ett_tetra_T_notification_indicator_06,
    &ett_tetra_T_prop_14,
    &ett_tetra_D_TX_GRANTED,
    &ett_tetra_D_ATTACH_DETACH_GROUP_IDENTITY,
    &ett_tetra_T_optional_elements_24,
    &ett_tetra_T_type2_element_02,
    &ett_tetra_T_type3_04,
    &ett_tetra_T_type3_elements_04,
    &ett_tetra_D_ATTACH_DETACH_GROUP_IDENTITY_ACK,
    &ett_tetra_T_optional_elements_25,
    &ett_tetra_T_type2_element_03,
    &ett_tetra_T_type3_05,
    &ett_tetra_T_type3_elements_05,
    &ett_tetra_Calling_party_address_type,
    &ett_tetra_T_called_party_ssi_extention,
    &ett_tetra_Proprietary,
    &ett_tetra_T_data_01,
    &ett_tetra_Type1,
    &ett_tetra_Type2,
    &ett_tetra_Modify_type,

/*--- End of included file: packet-tetra-ettarr.c ---*/
#line 624 "../../asn1/tetra/packet-tetra-template.c"
	};

	/* execute protocol initialization only once */
  	if (proto_tetra != -1)
		return;

	proto_tetra = proto_register_protocol("TETRA Protocol", "tetra", "tetra");
	proto_register_field_array (proto_tetra, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	register_dissector("tetra", dissect_tetra, proto_tetra);

	per_module = prefs_register_protocol(proto_tetra, NULL);
	prefs_register_bool_preference(per_module, "include_carrier_number",
			"The data include carrier numbers",
			"Whether the captured data include carrier number",
			&include_carrier_number);
}
