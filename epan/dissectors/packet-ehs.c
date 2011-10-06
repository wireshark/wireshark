/* packet-ehs.c
 * Routines for "Enhanced HSC System" (EHS) dissection
 * Copyright 2000, Scott Hovis scott.hovis@ums.msfc.nasa.gov
 * Enhanced 2008, Matt Dunkle Matthew.L.Dunkle@nasa.gov
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.com>
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

#include <stdlib.h>

#include <glib.h>
#include <epan/packet.h>


/* Initialize the protocol and registered fields */
static int proto_ehs = -1;

static int hf_ehs_ph_version = -1;
static int hf_ehs_ph_project = -1;
static int hf_ehs_ph_support_mode = -1;
static int hf_ehs_ph_data_mode = -1;
static int hf_ehs_ph_mission = -1;
static int hf_ehs_ph_protocol = -1;

static int hf_ehs_ph_year = -1;            /* numeric year as years since 1900 */
static int hf_ehs_ph_jday = -1;            /* julian day of year */
static int hf_ehs_ph_hour = -1;
static int hf_ehs_ph_minute = -1;
static int hf_ehs_ph_second = -1;
static int hf_ehs_ph_tenths = -1;

static int hf_ehs_ph_new_data_flag = -1;   /* indicates the time has changed */
static int hf_ehs_ph_pad1 = -1;
static int hf_ehs_ph_hold_flag = -1;       /* indicates a hold condition */
static int hf_ehs_ph_sign_flag = -1;       /* indicates pre-mission, i.e. countdown, time */

static int hf_ehs_ph_pad2 = -1;
static int hf_ehs_ph_pad3 = -1;
static int hf_ehs_ph_pad4 = -1;

static int hf_ehs_ph_hosc_packet_size = -1;

/* generic ehs secondary header values */
static int hf_ehs_sh_version = -1;
static int hf_ehs_sh_data_status_bit_5 = -1;
static int hf_ehs_sh_data_status_bit_4 = -1;
static int hf_ehs_sh_data_status_bit_3 = -1;
static int hf_ehs_sh_data_status_bit_2 = -1;
static int hf_ehs_sh_data_status_bit_1 = -1;
static int hf_ehs_sh_data_status_bit_0 = -1;

/* other common remappings of the data status bits specific to certain secondary ehs header values */
static int hf_ehs_sh_parent_stream_error = -1;      /* data status bit 3 */
static int hf_ehs_sh_vcdu_sequence_error = -1;      /* data status bit 2 */
static int hf_ehs_sh_packet_sequence_error = -1;    /* data status bit 1 */

/* common ehs secondary header values */
static int hf_ehs_sh_vcdu_sequence_number = -1;
static int hf_ehs_sh_data_stream_id = -1;
static int hf_ehs_sh_pdss_reserved_1 = -1;
static int hf_ehs_sh_pdss_reserved_2 = -1;
static int hf_ehs_sh_pdss_reserved_3 = -1;
static int hf_ehs_sh_gse_pkt_id = -1;
static int hf_ehs_sh_payload_vs_core_id = -1;
static int hf_ehs_sh_apid = -1;
static int hf_ehs_sh_virtual_channel = -1;
static int hf_ehs_sh_pdss_reserved_sync = -1;

/* tdm ehs secondary header values */
static int hf_ehs_sh_tdm_secondary_header_length = -1;

static int hf_ehs_sh_tdm_extra_data_packet = -1;
static int hf_ehs_sh_tdm_backup_stream_id_number = -1;
static int hf_ehs_sh_tdm_end_of_data_flag = -1;
static int hf_ehs_sh_tdm_parent_frame_error = -1;
static int hf_ehs_sh_tdm_checksum_error = -1;
static int hf_ehs_sh_tdm_fixed_value_error = -1;

static int hf_ehs_sh_tdm_minor_frame_counter_error = -1;
static int hf_ehs_sh_tdm_format_id_error = -1;
static int hf_ehs_sh_tdm_bit_slip_error = -1;
static int hf_ehs_sh_tdm_sync_error = -1;
static int hf_ehs_sh_tdm_aoslos_flag = -1;
static int hf_ehs_sh_tdm_override_errors_flag = -1;
static int hf_ehs_sh_tdm_data_status = -1;

static int hf_ehs_sh_tdm_idq = -1;
static int hf_ehs_sh_tdm_cdq = -1;
static int hf_ehs_sh_tdm_adq = -1;
static int hf_ehs_sh_tdm_data_dq = -1;
static int hf_ehs_sh_tdm_unused = -1;
static int hf_ehs_sh_tdm_format_id = -1;

static int hf_ehs_sh_tdm_major_frame_packet_index = -1;
static int hf_ehs_sh_tdm_numpkts_per_major_frame = -1;
static int hf_ehs_sh_tdm_num_minor_frames_per_packet = -1;

static int hf_ehs_sh_tdm_cntmet_present = -1;
static int hf_ehs_sh_tdm_obt_present = -1;
static int hf_ehs_sh_tdm_major_frame_status_present = -1;
static int hf_ehs_sh_tdm_reserved = -1;

static int hf_ehs_sh_tdm_cnt_year = -1;            /* numeric year as years since 1900 */
static int hf_ehs_sh_tdm_cnt_jday = -1;            /* julian day of year */
static int hf_ehs_sh_tdm_cnt_hour = -1;
static int hf_ehs_sh_tdm_cnt_minute = -1;
static int hf_ehs_sh_tdm_cnt_second = -1;
static int hf_ehs_sh_tdm_cnt_tenths = -1;

static int hf_ehs_sh_tdm_obt_year = -1;            /* numeric year as years since 1900 */
static int hf_ehs_sh_tdm_obt_jday = -1;            /* julian day of year */
static int hf_ehs_sh_tdm_obt_hour = -1;
static int hf_ehs_sh_tdm_obt_minute = -1;
static int hf_ehs_sh_tdm_obt_second = -1;
static int hf_ehs_sh_tdm_obt_tenths = -1;

static int hf_ehs_sh_tdm_obt_delta_time_flag = -1;
static int hf_ehs_sh_tdm_obt_computed_flag = -1;
static int hf_ehs_sh_tdm_obt_not_retrieved_flag = -1;
static int hf_ehs_sh_tdm_obt_reserved = -1;
static int hf_ehs_sh_tdm_obt_source_apid = -1;

static int hf_ehs_sh_tdm_num_major_frame_status_words = -1;

static int hf_ehs_sh_tdm_mjfs_reserved = -1;
static int hf_ehs_sh_tdm_mjfs_parent_frame_error = -1;
static int hf_ehs_sh_tdm_mjfs_checksum_error = -1;
static int hf_ehs_sh_tdm_mjfs_fixed_value_error = -1;

static int hf_ehs_sh_tdm_mnfs_parent_frame_error = -1;
static int hf_ehs_sh_tdm_mnfs_data_not_available = -1;
static int hf_ehs_sh_tdm_mnfs_checksum_error = -1;
static int hf_ehs_sh_tdm_mnfs_fixed_value_error = -1;
static int hf_ehs_sh_tdm_mnfs_counter_error = -1;
static int hf_ehs_sh_tdm_mnfs_format_id_error = -1;
static int hf_ehs_sh_tdm_mnfs_bit_slip_error = -1;
static int hf_ehs_sh_tdm_mnfs_sync_error = -1;

/* pseudo ehs secondary header values */
static int hf_ehs_sh_pseudo_unused = -1;
static int hf_ehs_sh_pseudo_workstation_id = -1;
static int hf_ehs_sh_pseudo_user_id = -1;
static int hf_ehs_sh_pseudo_comp_id = -1;

/* data zone values for well known protocol AOS/LOS */
static int hf_ehs_dz_aoslos_indicator = -1;

/* data zone values for well known protocol UDSM */
static int hf_ehs_dz_udsm_ccsds_vs_bpdu = -1;
static int hf_ehs_dz_udsm_unused1 = -1;

static int hf_ehs_dz_udsm_unused2 = -1;

static int hf_ehs_dz_udsm_unused3 = -1;
static int hf_ehs_dz_udsm_gse_pkt_id = -1;
static int hf_ehs_dz_udsm_payload_vs_core = -1;
static int hf_ehs_dz_udsm_apid = -1;

static int hf_ehs_dz_udsm_start_time_year = -1;
static int hf_ehs_dz_udsm_start_time_jday = -1;
static int hf_ehs_dz_udsm_start_time_hour = -1;
static int hf_ehs_dz_udsm_start_time_minute = -1;
static int hf_ehs_dz_udsm_start_time_second = -1;

static int hf_ehs_dz_udsm_stop_time_year = -1;
static int hf_ehs_dz_udsm_stop_time_jday = -1;
static int hf_ehs_dz_udsm_stop_time_hour = -1;
static int hf_ehs_dz_udsm_stop_time_minute = -1;
static int hf_ehs_dz_udsm_stop_time_second = -1;

static int hf_ehs_dz_udsm_unused4 = -1;

static int hf_ehs_dz_udsm_num_pkts_xmtd = -1;

static int hf_ehs_dz_udsm_num_vcdu_seqerrs = -1;

static int hf_ehs_dz_udsm_num_pkt_seqerrs = -1;

static int hf_ehs_dz_udsm_num_pktlen_errors = -1;

static int hf_ehs_dz_udsm_event = -1;

static int hf_ehs_dz_udsm_num_pkts_xmtd_rollover = -1;


/* handle to ccsds packet dissector */
static dissector_handle_t ccsds_handle;

/* Initialize the subtree pointers */
static gint ett_ehs = -1;
static gint ett_ehs_primary_header = -1;
static gint ett_ehs_secondary_header = -1;
static gint ett_ehs_data_zone = -1;

/* EHS protocol types */
typedef enum EHS_Protocol_Type
{
  EHS_PROTOCOL__ALL_PROTOCOLS,
  EHS_PROTOCOL__TDM_TELEMETRY,
  EHS_PROTOCOL__NASCOM_TELEMETRY,
  EHS_PROTOCOL__PSEUDO_TELEMETRY,
  EHS_PROTOCOL__TDS_DATA,
  EHS_PROTOCOL__TEST_DATA,
  EHS_PROTOCOL__GSE_DATA,
  EHS_PROTOCOL__CUSTOM_DATA,
  EHS_PROTOCOL__HDRS_DQ,
  EHS_PROTOCOL__CSS,
  EHS_PROTOCOL__AOS_LOS,
  EHS_PROTOCOL__PDSS_PAYLOAD_CCSDS_PACKET,
  EHS_PROTOCOL__PDSS_CORE_CCSDS_PACKET,
  EHS_PROTOCOL__PDSS_PAYLOAD_BPDU,
  EHS_PROTOCOL__PDSS_UDSM,
  EHS_PROTOCOL__PDSS_RPSM,
  NUMBER_PROTOCOLS = 15
} EHS_Protocol_Type_t;


/* some basic sizing parameters */
enum
{
  IP_HEADER_LENGTH = 48,
  CCSDS_PRIMARY_HEADER_LENGTH = 6,
  CCSDS_SECONDARY_HEADER_LENGTH = 10,
  EHS_PRIMARY_HEADER_SIZE = 16,
  EHS_SECONDARY_HEADER_SIZE = 12
};

/* determine if a ccsds primary header indicates a secondary exists */
#define HDR_SECHDR	0x0800


static const value_string ehs_primary_header_project[] =
{
  { 0, "All" },
  { 1, "STS" },
  { 2, "SL" },
  { 3, "ISS" },
  { 4, "AXAF" },
  { 0, NULL }
};

static const value_string ehs_primary_header_support_mode[] =
{
  { 0, "All" },
  { 1, "Flight" },
  { 2, "Test" },
  { 3, "Sim" },
  { 4, "Validation" },
  { 5, "Development" },
  { 6, "Training" },
  { 7, "Offline" },
  { 0, NULL }
};

static const value_string ehs_primary_header_data_mode[] =
{
  { 0,  "Unused" },
  { 1,  "Realtime" },
  { 2,  "Dump1" },
  { 3,  "Dump2" },
  { 4,  "Dump3" },
  { 5,  "Playback1" },
  { 6,  "Playback2" },
  { 7,  "Playback3" },
  { 8,  "Playback4" },
  { 9,  "Playback5" },
  { 10, "Playback6" },
  { 11, "Playback7" },
  { 12, "Playback8" },
  { 13, "Playback9" },
  { 14, "Playback10" },
  { 15, "Playback11" },
  { 16, "Mode Independent" },
  { 0, NULL }
};

static const value_string ehs_primary_header_protocol[] =
{
  { 0,  "All" },
  { 1,  "TDM" },
  { 2,  "NASCOM" },
  { 3,  "PSEUDO" },
  { 4,  "Time" },
  { 5,  "Test" },
  { 6,  "GSE" },
  { 7,  "Custom_Data" },
  { 8,  "HDRS_DQ" },
  { 9,  "CSS" },
  { 10, "AOS_LOS" },
  { 11, "PDSS_PAYLOAD_CCSDS" },
  { 12, "PDSS_CORE_CCSDS" },
  { 13, "PDSS_PAYLOAD_BPDU" },
  { 14, "PDSS_UDSM" },
  { 15, "PDSS_RPSM" },
  { 0, NULL }
};

static const value_string ehs_secondary_header_data_stream_id[] =
{
  { 0, "CCSDS" },
  { 1, "BPDU" },
  { 0, NULL }
};

static const value_string ehs_secondary_header_payload_vs_core_id[] =
{
  { 0, "Core" },
  { 1, "Payload" },
  { 0, NULL }
};

static const value_string ehs_secondary_header_tdm_backup_stream_id[] =
{
  { 0, "Stream A / KMTS-A" },
  { 1, "Stream B / KMTS-B" },
  { 2, "SKR" },
  { 0, NULL }
};

static const value_string ehs_secondary_header_tdm_end_of_data_flag[] =
{
  { 0, "OK" },
  { 1, "Loss of Clock" },
  { 2, "Watchdog Timeout" },
  { 3, "Loss of Sync" },
  { 0, NULL }
};

static const true_false_string ehs_tfs_secondary_header_tdm_aoslos_flag =
{
   "AOS" ,
   "LOS"
};

static const value_string ehs_secondary_header_tdm_data_status[] =
{
  { 0, "OK" },
  { 1, "Suspect" },
  { 2, "DQ Failed" },
  { 3, "No Data" },
  { 0, NULL }
};

static const value_string ehs_data_zone_aoslos_indicator[] =
{
  { 0, "S-band LOS" },
  { 1, "S-band AOS" },
  { 2, "Ku-band LOS" },
  { 3, "Ku-band AOS" },
  { 0, NULL }
};

static const value_string ehs_data_zone_udsm_ccsds_vs_bpdu[] =
{
  { 0, "CCSDS" },
  { 1, "BPDU" },
  { 0, NULL }
};

static const value_string ehs_data_zone_udsm_payload_vs_core[] =
{
  { 0, "Core" },
  { 1, "Payload" },
  { 0, NULL }
};

static const value_string ehs_data_zone_udsm_event[] =
{
  { 0, "Undefined" },
  { 1, "Actual LOS" },
  { 2, "Scheduled End of Data" },
  { 3, "Operator Requested" },
  { 0, NULL }
};


/* function to return EHS secondary header size according to protocol.
 * the buffer pointer tvb should be pointing to the packets ehs primary
 * header, and the offset should be set to the start of the ehs secondary
 * header on input.
 */
static int ehs_secondary_header_size ( int protocol, tvbuff_t* tvb, int offset )
{
  /* for most protocols the ehs secondary header is a standard size */
  int size = EHS_SECONDARY_HEADER_SIZE;

  switch ( protocol )
  {
  case EHS_PROTOCOL__TDM_TELEMETRY:
    /* the TDM secondary header size is variable.  it's value is actually
     * contained in the first two bytes of the secondary header itself.
     */
    size = tvb_get_ntohs ( tvb, offset );
    break;

  case EHS_PROTOCOL__NASCOM_TELEMETRY:
    break;

  case EHS_PROTOCOL__PSEUDO_TELEMETRY:
    size = 8;
    break;

  case EHS_PROTOCOL__TDS_DATA:
    break;

  case EHS_PROTOCOL__TEST_DATA:
    break;

  case EHS_PROTOCOL__GSE_DATA:
    size = 16;
    break;

  case EHS_PROTOCOL__CUSTOM_DATA:
    break;

  case EHS_PROTOCOL__HDRS_DQ:
    break;

  case EHS_PROTOCOL__CSS:
    break;

  case EHS_PROTOCOL__AOS_LOS:
    break;

  case EHS_PROTOCOL__PDSS_PAYLOAD_CCSDS_PACKET:
    break;

  case EHS_PROTOCOL__PDSS_CORE_CCSDS_PACKET:
    break;

  case EHS_PROTOCOL__PDSS_PAYLOAD_BPDU:
    break;

  case EHS_PROTOCOL__PDSS_UDSM:
    break;

  case EHS_PROTOCOL__PDSS_RPSM:
    break;

  default:
    break;
  }

  return size;

}


/* common EHS secondary header dissector */
static void common_secondary_header_dissector ( proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_vcdu_sequence_number, tvb, *offset, 3, ENC_BIG_ENDIAN );
  *offset += 3;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_stream_id, tvb, *offset, 1, ENC_BIG_ENDIAN );
  /* proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_pdss_reserved_1, tvb, *offset, 1, ENC_BIG_ENDIAN ); */
  ++(*offset);

  /* proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_pdss_reserved_2, tvb, *offset, 1, ENC_BIG_ENDIAN ); */
  ++(*offset);

  /* proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_pdss_reserved_3, tvb, *offset, 2, ENC_BIG_ENDIAN ); */
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_gse_pkt_id, tvb, *offset, 2, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_payload_vs_core_id, tvb, *offset, 2, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_apid, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_virtual_channel, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_pdss_reserved_sync, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

}


/* AOS/LOS EHS secondary header dissector */
static void aoslos_secondary_header_dissector ( proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_version, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_5, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_4, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_3, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_2, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_1, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_0, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  common_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
}


/* payload ccsds secondary header dissector */
static void payload_ccsds_secondary_header_dissector ( proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_version, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_5, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_4, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_3, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_vcdu_sequence_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_packet_sequence_error, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_0, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  common_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
}


/* core ccsds secondary header dissector */
static void core_ccsds_secondary_header_dissector ( proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_version, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_5, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_4, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_parent_stream_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_vcdu_sequence_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_packet_sequence_error, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_0, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  common_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
}


/* payload bpdu secondary header dissector */
static void payload_bpdu_secondary_header_dissector ( proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_version, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_5, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_4, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_3, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_vcdu_sequence_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_1, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_0, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  common_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
}


/* udsm secondary header dissector */
static void udsm_secondary_header_dissector ( proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_version, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_5, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_4, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_3, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_2, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_1, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_data_status_bit_0, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  common_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
}


/* tdm secondary header dissector */
static void tdm_secondary_header_dissector ( proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  int j;
  int num_major_frames = 0;
  int num_minor_frames = 0;
  int cntmet_present = 0;
  int obt_present = 0;
  int mjfs_present = 0;

  int year, jday, hour, minute, second, tenths;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_secondary_header_length, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_extra_data_packet, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_backup_stream_id_number, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_end_of_data_flag, tvb, *offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_parent_frame_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_checksum_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_fixed_value_error, tvb, *offset, 1, FALSE );
  ++(*offset);

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_minor_frame_counter_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_format_id_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_bit_slip_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_sync_error, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_aoslos_flag, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_override_errors_flag, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_data_status, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_idq, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_cdq, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_adq, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_data_dq, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  /* proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_unused, tvb, *offset, 2, ENC_BIG_ENDIAN ); */
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_format_id, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_major_frame_packet_index, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_numpkts_per_major_frame, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  num_minor_frames = 1 + tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_num_minor_frames_per_packet, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  cntmet_present = tvb_get_guint8 ( tvb, *offset ) & 0x80;
  obt_present = tvb_get_guint8 ( tvb, *offset ) & 0x40;
  mjfs_present = tvb_get_guint8 ( tvb, *offset ) & 0x20;
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_cntmet_present, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_present, tvb, *offset, 1, FALSE );
  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_major_frame_status_present, tvb, *offset, 1, FALSE );
  /* proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_reserved, tvb, *offset, 1, ENC_BIG_ENDIAN ); */
  ++(*offset);

  if ( cntmet_present )
  {
    year = tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_cnt_year, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    jday = tvb_get_ntohs ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_cnt_jday, tvb, *offset, 2, ENC_BIG_ENDIAN );
    *offset += 2;

    hour = tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_cnt_hour, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    minute = tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_cnt_minute, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    second = tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_cnt_second, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    tenths = tvb_get_guint8 ( tvb, *offset ) >> 4;
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_cnt_tenths, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    /* format a more readable time */
    proto_tree_add_text ( ehs_secondary_header_tree, tvb, *offset-7, 7,
      "%04d/%03d:%02d:%02d:%02d.%1d = CNT/MET Time", year + 1900, jday, hour, minute, second, tenths );
  }


  if ( obt_present )
  {
    year = tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_year, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    jday = tvb_get_ntohs ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_jday, tvb, *offset, 2, ENC_BIG_ENDIAN );
    *offset += 2;

    hour = tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_hour, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    minute = tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_minute, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    second = tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_second, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    tenths = tvb_get_guint8 ( tvb, *offset ) >> 4;
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_tenths, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    /* format a more readable time */
    proto_tree_add_text ( ehs_secondary_header_tree, tvb, *offset-7, 7,
       "%04d/%03d:%02d:%02d:%02d.%1d = OBT Time", year + 1900, jday, hour, minute, second, tenths );

    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_delta_time_flag, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_computed_flag, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_not_retrieved_flag, tvb, *offset, 1, FALSE );
    /* proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_reserved, tvb, *offset, 1, FALSE ); */
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_obt_source_apid, tvb, *offset, 1, ENC_BIG_ENDIAN );
  }

  if ( mjfs_present )
  {
    proto_tree_add_text ( ehs_secondary_header_tree, tvb, *offset, 0, " " );

    num_major_frames = 1 + tvb_get_guint8 ( tvb, *offset );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_num_major_frame_status_words, tvb, *offset, 1, ENC_BIG_ENDIAN );
    ++(*offset);

    for ( j=0; j < num_major_frames; ++j )
    {
      proto_tree_add_text ( ehs_secondary_header_tree, tvb, *offset, 1, "Major Frame Status Byte# %d", j );
      /* proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mjfs_reserved, tvb, *offset, 1, ENC_BIG_ENDIAN ); */
      proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mjfs_parent_frame_error, tvb, *offset, 1, FALSE );
      proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mjfs_checksum_error, tvb, *offset, 1, FALSE );
      proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mjfs_fixed_value_error, tvb, *offset, 1, FALSE );
      ++(*offset);
    }
  }

  proto_tree_add_text ( ehs_secondary_header_tree, tvb, *offset, 0, " " );

  for ( j=0; j < num_minor_frames; ++j )
  {
    proto_tree_add_text ( ehs_secondary_header_tree, tvb, *offset, 1, "Minor Frame Status Byte# %d", j );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mnfs_parent_frame_error, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mnfs_data_not_available, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mnfs_checksum_error, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mnfs_fixed_value_error, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mnfs_counter_error, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mnfs_format_id_error, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mnfs_bit_slip_error, tvb, *offset, 1, FALSE );
    proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_tdm_mnfs_sync_error, tvb, *offset, 1, FALSE );
    ++(*offset);
  }

}


/* pseudo secondary header dissector */
static void pseudo_secondary_header_dissector ( proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  /* proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_pseudo_unused, tvb, *offset, 2, ENC_BIG_ENDIAN ); */
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_pseudo_workstation_id, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_pseudo_user_id, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_secondary_header_tree, hf_ehs_sh_pseudo_comp_id, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

}




/* EHS secondary header dissector */
static void ehs_secondary_header_dissector ( int protocol, proto_tree* ehs_secondary_header_tree, tvbuff_t* tvb, int* offset )
{
  /* the ehs secondary header structure is potentially different for each and every
   * protocol type, including it's size.  we support certain protocols but not all.
   * for those protocols which are not supported we simply increment the offset
   * and return.  support for these other protocols can easily be added at a later
   * time if and when it becomes necessary to do so.  but for right now, we're only
   * going to dissect those protocols that we work with on a regular basis in pdss.
   */
  switch ( protocol )
  {
  case EHS_PROTOCOL__TDM_TELEMETRY:
    tdm_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
    break;

  case EHS_PROTOCOL__NASCOM_TELEMETRY:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;

  case EHS_PROTOCOL__PSEUDO_TELEMETRY:
    pseudo_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
    break;

  case EHS_PROTOCOL__TDS_DATA:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;

  case EHS_PROTOCOL__TEST_DATA:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;

  case EHS_PROTOCOL__GSE_DATA:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;

  case EHS_PROTOCOL__CUSTOM_DATA:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;

  case EHS_PROTOCOL__HDRS_DQ:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;

  case EHS_PROTOCOL__CSS:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;

  case EHS_PROTOCOL__AOS_LOS:
    aoslos_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
    break;

  case EHS_PROTOCOL__PDSS_PAYLOAD_CCSDS_PACKET:
    payload_ccsds_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
    break;

  case EHS_PROTOCOL__PDSS_CORE_CCSDS_PACKET:
    core_ccsds_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
    break;

  case EHS_PROTOCOL__PDSS_PAYLOAD_BPDU:
    payload_bpdu_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
    break;

  case EHS_PROTOCOL__PDSS_UDSM:
    udsm_secondary_header_dissector ( ehs_secondary_header_tree, tvb, offset );
    break;

  case EHS_PROTOCOL__PDSS_RPSM:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;

  default:
    *offset += ehs_secondary_header_size ( protocol, tvb, *offset );
    break;
  }
}


/* AOS/LOS data zone dissector */
static void aoslos_data_zone_dissector ( proto_tree* ehs_tree, tvbuff_t* tvb, int* offset, packet_info* pinfo )
{
  proto_item *ehs_data_zone;
  proto_tree *ehs_data_zone_tree;

  /* create the data zone tree */
  ehs_data_zone = proto_tree_add_text ( ehs_tree, tvb, *offset, pinfo->iplen - IP_HEADER_LENGTH - *offset, "AOS/LOS Data Zone" );
  ehs_data_zone_tree = proto_item_add_subtree ( ehs_data_zone, ett_ehs_data_zone );

  /* since the aos/los EHS packet data zone is well known, format it for display as well
   *
   * The AOS/LOS packet data zone is only 2 bytes in
   * length and only 2 bits in the first byte are
   * meaningful -- Ku band or S band and AOS or LOS
   * 
   * 7-2 - unused
   * 1-0 - band + AOS/LOS indicator
   *
   * bit 1 - 0=sband 1=kuband
   * bit 0 - 0=LOS 1=AOS
   *
   * 0 00 - sband LOS
   * 1 01 - sband AOS
   * 2 10 - kuband LOS
   * 3 11 - kuband AOS
   */
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_aoslos_indicator, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);
}


/* UDSM data zone dissector */
static void udsm_data_zone_dissector ( proto_tree* ehs_tree, tvbuff_t* tvb, int* offset, packet_info* pinfo )
{
  proto_item *ehs_data_zone;
  proto_tree *ehs_data_zone_tree;

  int year, jday, hour, minute, second;

  /* create the data zone tree */
  ehs_data_zone = proto_tree_add_text ( ehs_tree, tvb, *offset, pinfo->iplen - IP_HEADER_LENGTH - *offset, "UDSM Data Zone" );
  ehs_data_zone_tree = proto_item_add_subtree ( ehs_data_zone, ett_ehs_data_zone );

  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_ccsds_vs_bpdu, tvb, *offset, 1, ENC_BIG_ENDIAN );
  /* proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_unused1, tvb, *offset, 1, ENC_BIG_ENDIAN ); */
  ++(*offset);

  /* proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_unused2, tvb, *offset, 1, ENC_BIG_ENDIAN ); */
  ++(*offset);

  /* proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_unused3, tvb, *offset, 2, ENC_BIG_ENDIAN ); */
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_gse_pkt_id, tvb, *offset, 2, FALSE );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_payload_vs_core, tvb, *offset, 2, ENC_BIG_ENDIAN );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_apid, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  year = tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_start_time_year, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  jday = tvb_get_ntohs ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_start_time_jday, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  hour = tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_start_time_hour, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  minute = tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_start_time_minute, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  second = tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_start_time_second, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  /* format a more readable time */
  proto_tree_add_text ( ehs_data_zone_tree, tvb, *offset-7, 7,
    "%04d/%03d:%02d:%02d:%02d = UDSM Start Time", year + 1900, jday, hour, minute, second );

  year = tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_stop_time_year, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  jday = tvb_get_ntohs ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_stop_time_jday, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  hour = tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_stop_time_hour, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  minute = tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_stop_time_minute, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  second = tvb_get_guint8 ( tvb, *offset );
  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_stop_time_second, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  /* format a more readable time */
  proto_tree_add_text ( ehs_data_zone_tree, tvb, *offset-7, 7,
    "%04d/%03d:%02d:%02d:%02d = UDSM Stop Time", year + 1900, jday, hour, minute, second );

  /* proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_unused4, tvb, *offset, 2, ENC_BIG_ENDIAN ); */
  *offset += 2;

  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_num_pkts_xmtd, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_num_vcdu_seqerrs, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_num_pkt_seqerrs, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_num_pktlen_errors, tvb, *offset, 2, ENC_BIG_ENDIAN );
  *offset += 2;

  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_event, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

  proto_tree_add_item ( ehs_data_zone_tree, hf_ehs_dz_udsm_num_pkts_xmtd_rollover, tvb, *offset, 1, ENC_BIG_ENDIAN );
  ++(*offset);

}


/* data zone dissector */
static void ehs_data_zone_dissector ( int protocol, proto_tree* ehs_tree, tvbuff_t* tvb, int* offset, packet_info* pinfo )
{
  /* the data zone of certain protocols such as AOS/LOS and UDSM is well known.
   */
  switch ( protocol )
  {
  case EHS_PROTOCOL__TDM_TELEMETRY:
    break;

  case EHS_PROTOCOL__NASCOM_TELEMETRY:
    break;

  case EHS_PROTOCOL__PSEUDO_TELEMETRY:
    break;

  case EHS_PROTOCOL__TDS_DATA:
    break;

  case EHS_PROTOCOL__TEST_DATA:
    break;

  case EHS_PROTOCOL__GSE_DATA:
    break;

  case EHS_PROTOCOL__CUSTOM_DATA:
    break;

  case EHS_PROTOCOL__HDRS_DQ:
    break;

  case EHS_PROTOCOL__CSS:
    break;

  case EHS_PROTOCOL__AOS_LOS:
    aoslos_data_zone_dissector ( ehs_tree, tvb, offset, pinfo );
    break;

  case EHS_PROTOCOL__PDSS_PAYLOAD_CCSDS_PACKET:
    break;

  case EHS_PROTOCOL__PDSS_CORE_CCSDS_PACKET:
    break;

  case EHS_PROTOCOL__PDSS_PAYLOAD_BPDU:
    break;

  case EHS_PROTOCOL__PDSS_UDSM:
    udsm_data_zone_dissector ( ehs_tree, tvb, offset, pinfo );
    break;

  case EHS_PROTOCOL__PDSS_RPSM:
    break;

  default:
    break;
  }
}


/* Code to actually dissect the packets */
static void
dissect_ehs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        int offset = 0;
	guint16 first_word;

        tvbuff_t *new_tvb;

        proto_item *ehs_packet;
        proto_tree *ehs_tree;

        proto_item *ehs_primary_header;
        proto_tree *ehs_primary_header_tree;

        proto_item *ehs_secondary_header;
        proto_tree *ehs_secondary_header_tree;

        int protocol;
        int year, jday, hour, minute, second, tenths;

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "EHS");
        col_set_str(pinfo->cinfo, COL_INFO, "EHS");

        ehs_packet = proto_tree_add_item ( tree, proto_ehs, tvb, 0, -1, FALSE );
        ehs_tree = proto_item_add_subtree ( ehs_packet, ett_ehs );

        /* build the ehs primary header tree */
        ehs_primary_header = proto_tree_add_text ( ehs_tree, tvb, offset, EHS_PRIMARY_HEADER_SIZE, "Primary EHS Header" );
        ehs_primary_header_tree = proto_item_add_subtree ( ehs_primary_header, ett_ehs_primary_header );

        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_version, tvb, offset, 1, ENC_BIG_ENDIAN );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_project, tvb, offset, 1, ENC_BIG_ENDIAN );
        ++offset;

        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_support_mode, tvb, offset, 1, ENC_BIG_ENDIAN );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_data_mode, tvb, offset, 1, ENC_BIG_ENDIAN );
        ++offset;

        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_mission, tvb, offset, 1, ENC_BIG_ENDIAN );
        ++offset;

        /* save protocol for use later on */
        protocol = tvb_get_guint8 ( tvb, offset );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_protocol, tvb, offset, 1, ENC_BIG_ENDIAN );
        ++offset;

        year = tvb_get_guint8 ( tvb, offset );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_year, tvb, offset, 1, ENC_BIG_ENDIAN );
        ++offset;

        jday = tvb_get_ntohs ( tvb, offset );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_jday, tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;

        hour = tvb_get_guint8 ( tvb, offset );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_hour, tvb, offset, 1, ENC_BIG_ENDIAN );
        ++offset;

        minute = tvb_get_guint8 ( tvb, offset );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_minute, tvb, offset, 1, ENC_BIG_ENDIAN );
        ++offset;

        second = tvb_get_guint8 ( tvb, offset );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_second, tvb, offset, 1, ENC_BIG_ENDIAN );
        ++offset;

        tenths = tvb_get_guint8 ( tvb, offset ) >> 4;
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_tenths, tvb, offset, 1, ENC_BIG_ENDIAN );

        /* format a more readable ground receipt time string */
        proto_tree_add_text ( ehs_primary_header_tree, tvb, offset-7, 7,
          "%04d/%03d:%02d:%02d:%02d.%1d = EHS Ground Receipt Time", year + 1900, jday, hour, minute, second, tenths );

        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_new_data_flag, tvb, offset, 1, FALSE );
        /* proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_pad1, tvb, offset, 1, ENC_BIG_ENDIAN ); */
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_hold_flag, tvb, offset, 1, FALSE );
        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_sign_flag, tvb, offset, 1, FALSE );
        ++offset;

        /* proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_pad2, tvb, offset, 1, ENC_BIG_ENDIAN ); */
        ++offset;
        /* proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_pad3, tvb, offset, 1, ENC_BIG_ENDIAN ); */
        ++offset;
        /* proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_pad4, tvb, offset, 1, ENC_BIG_ENDIAN ); */
        ++offset;

        proto_tree_add_item ( ehs_primary_header_tree, hf_ehs_ph_hosc_packet_size, tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;

        /* build the ehs secondary header tree */
        ehs_secondary_header = proto_tree_add_text ( ehs_tree, tvb, offset,
          ehs_secondary_header_size ( protocol, tvb, offset ), "Secondary EHS Header" );
        ehs_secondary_header_tree = proto_item_add_subtree ( ehs_secondary_header, ett_ehs_secondary_header );

        /* since each protocol can have a different ehs secondary header structure, we will offload
         * this processing to lower levels of code so we don't have to insert all of that complexity
         * directly inline here, which would no doubt make this difficult to read at best.
         */
        ehs_secondary_header_dissector ( protocol, ehs_secondary_header_tree, tvb, &offset );

        /* for ccsds protocol types pass the remaining packet off to the ccsds packet dissector */
        switch ( protocol )
        {
        case EHS_PROTOCOL__TDM_TELEMETRY:
        case EHS_PROTOCOL__PSEUDO_TELEMETRY:
        case EHS_PROTOCOL__AOS_LOS:
        case EHS_PROTOCOL__PDSS_PAYLOAD_CCSDS_PACKET:
        case EHS_PROTOCOL__PDSS_CORE_CCSDS_PACKET:
        case EHS_PROTOCOL__PDSS_UDSM:
                new_tvb = tvb_new_subset_remaining ( tvb, offset);
                call_dissector ( ccsds_handle, new_tvb, pinfo, ehs_tree );

                /* bump the offset to the data zone area */
	        first_word = tvb_get_ntohs ( tvb, offset );

                offset += CCSDS_PRIMARY_HEADER_LENGTH;
	        if ( first_word & HDR_SECHDR ) offset += CCSDS_SECONDARY_HEADER_LENGTH;
                break;


        default:
                break;
        }

        /* build the ehs data zone tree for well known protocols such as AOS/LOS and UDSM */
        ehs_data_zone_dissector ( protocol, ehs_tree, tvb, &offset, pinfo );

}


/* Register the protocol with Wireshark
 * this format is require because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_ehs(void)
{
        /* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] =
        {
                /* primary ehs header */
		{ &hf_ehs_ph_version,
			{ "Version", "ehs.version",
			FT_UINT8, BASE_DEC, NULL, 0xf0,
			NULL, HFILL }
		},
		{ &hf_ehs_ph_project,
			{ "Project", "ehs.project",
			FT_UINT8, BASE_DEC, VALS(ehs_primary_header_project), 0x0f,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_support_mode,
			{ "Support Mode", "ehs.support_mode",
			FT_UINT8, BASE_DEC, VALS(ehs_primary_header_support_mode), 0xf0,
			NULL, HFILL }
		},
		{ &hf_ehs_ph_data_mode,
			{ "Data Mode", "ehs.data_mode",
			FT_UINT8, BASE_DEC, VALS(ehs_primary_header_data_mode), 0x0f,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_mission,
			{ "Mission", "ehs.mission",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_protocol,
			{ "Protocol", "ehs.protocol",
			FT_UINT8, BASE_DEC, VALS(ehs_primary_header_protocol), 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_year,
			{ "Years since 1900", "ehs.year",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_jday,
			{ "Julian Day of Year", "ehs.jday",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_hour,
			{ "Hour", "ehs.hour",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_minute,
			{ "Minute", "ehs.minute",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_second,
			{ "Second", "ehs.second",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_tenths,
			{ "Tenths", "ehs.tenths",
			FT_UINT8, BASE_DEC, NULL, 0xf0,
			NULL, HFILL }
		},
		{ &hf_ehs_ph_new_data_flag,
			{ "New Data Flag", "ehs.new_data_flag",
			FT_BOOLEAN, 8, NULL, 0x08,
			NULL, HFILL }
		},
		{ &hf_ehs_ph_pad1,
			{ "Pad1", "ehs.pad1",
			FT_UINT8, BASE_DEC, NULL, 0x04,
			NULL, HFILL }
		},
		{ &hf_ehs_ph_hold_flag,
			{ "Hold Flag", "ehs.hold_flag",
			FT_BOOLEAN, 8, NULL, 0x02,
			NULL, HFILL }
		},
		{ &hf_ehs_ph_sign_flag,
			{ "Sign Flag (1->CDT)", "ehs.sign_flag",
			FT_UINT8, BASE_DEC, NULL, 0x01,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_pad2,
			{ "Pad2", "ehs.pad2",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_pad3,
			{ "Pad3", "ehs.pad3",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_pad4,
			{ "Pad4", "ehs.pad4",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_ph_hosc_packet_size,
			{ "HOSC Packet Size", "ehs.hosc_packet_size",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},


                /* secondary ehs header */
		{ &hf_ehs_sh_version,
			{ "Version", "ehs2.version",
			FT_UINT8, BASE_DEC, NULL, 0xc0,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_data_status_bit_5,
			{ "Data Status Bit 5", "ehs2.data_status_bit_5",
			FT_UINT8, BASE_DEC, NULL, 0x20,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_data_status_bit_4,
			{ "Data Status Bit 4", "ehs2.data_status_bit_4",
			FT_UINT8, BASE_DEC, NULL, 0x10,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_data_status_bit_3,
			{ "Data Status Bit 3", "ehs2.data_status_bit_3",
			FT_UINT8, BASE_DEC, NULL, 0x08,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_data_status_bit_2,
			{ "Data Status Bit 2", "ehs2.data_status_bit_2",
			FT_UINT8, BASE_DEC, NULL, 0x04,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_data_status_bit_1,
			{ "Data Status Bit 1", "ehs2.data_status_bit_1",
			FT_UINT8, BASE_DEC, NULL, 0x02,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_data_status_bit_0,
			{ "Data Status Bit 0", "ehs2.data_status_bit_0",
			FT_UINT8, BASE_DEC, NULL, 0x01,
			NULL, HFILL }
		},


                /* other common remappings of the data status bits specific to certain secondary ehs header values */
		{ &hf_ehs_sh_parent_stream_error,
			{ "Parent Stream Error", "ehs2.parent_stream_error",
			FT_BOOLEAN, 8, NULL, 0x08,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_vcdu_sequence_error,
			{ "VCDU Sequence Error", "ehs2.vcdu_sequence_error",
			FT_BOOLEAN, 8, NULL, 0x04,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_packet_sequence_error,
			{ "Packet Sequence Error", "ehs2.packet_sequence_error",
			FT_UINT8, BASE_DEC, NULL, 0x02,
			NULL, HFILL }
		},


                /* common ehs secondary header values */
		{ &hf_ehs_sh_vcdu_sequence_number,
			{ "VCDU Sequence Number", "ehs2.vcdu_seqno",
			FT_UINT24, BASE_DEC, NULL, 0xffffff,
			NULL, HFILL }
		},

		{ &hf_ehs_sh_data_stream_id,
			{ "Data Stream ID", "ehs2.data_stream_id",
			FT_UINT8, BASE_DEC, VALS(ehs_secondary_header_data_stream_id), 0x80,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_pdss_reserved_1,
			{ "Pdss Reserved 1", "ehs2.pdss_reserved_1",
			FT_UINT8, BASE_DEC, NULL, 0x7f,
			NULL, HFILL }
		},

		{ &hf_ehs_sh_pdss_reserved_2,
			{ "Pdss Reserved 2", "ehs2.pdss_reserved_2",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

		{ &hf_ehs_sh_pdss_reserved_3,
			{ "Pdss Reserved 3", "ehs2.pdss_reserved_3",
			FT_UINT16, BASE_DEC, NULL, 0xe000,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_gse_pkt_id,
			{ "GSE Packet ID (1=GSE)", "ehs2.gse_pkt_id",
			FT_UINT16, BASE_DEC, NULL, 0x1000,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_payload_vs_core_id,
			{ "Payload vs Core ID", "ehs2.payload_vs_core_id",
			FT_UINT16, BASE_DEC, VALS(ehs_secondary_header_payload_vs_core_id), 0x0800,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_apid,
			{ "APID", "ehs2.apid",
			FT_UINT16, BASE_DEC, NULL, 0x07ff,
			NULL, HFILL }
		},

		{ &hf_ehs_sh_virtual_channel,
			{ "Virtual Channel", "ehs2.vcid",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_pdss_reserved_sync,
			{ "Pdss Reserved Sync", "ehs2.sync",
			FT_UINT16, BASE_HEX, NULL, 0xffff,
			NULL, HFILL }
		},


                /* tdm ehs secondary header values */
                { &hf_ehs_sh_tdm_secondary_header_length,
			{ "Secondary Header Length", "ehs2.tdm_secondary_header_length",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_extra_data_packet,
			{ "Extra Data Packet", "ehs2.tdm_extra_data_packet",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_backup_stream_id_number,
			{ "Backup Stream ID Number", "ehs2.tdm_backup_stream_id_number",
			FT_UINT8, BASE_DEC, VALS(ehs_secondary_header_tdm_backup_stream_id), 0x60,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_end_of_data_flag,
			{ "End of Data Flag", "ehs2tdm_end_of_data_flag.tdm_end_of_data_flag",
			FT_UINT8, BASE_DEC, VALS(ehs_secondary_header_tdm_end_of_data_flag), 0x18,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_parent_frame_error,
			{ "Parent Frame Error", "ehs2.tdm_parent_frame_error",
			FT_BOOLEAN, 8, NULL, 0x04,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_checksum_error,
			{ "Checksum Error", "ehs2.tdm_checksum_error",
			FT_BOOLEAN, 8, NULL, 0x02,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_fixed_value_error,
			{ "Fixed Value Error", "ehs2.tdm_fixed_value_error",
			FT_BOOLEAN, 8, NULL, 0x01,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_minor_frame_counter_error,
			{ "Minor Frame Counter Error", "ehs2.tdm_minor_frame_counter_error",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_format_id_error,
			{ "Format ID Error", "ehs2.tdm_format_id_error",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_bit_slip_error,
			{ "Bit Slip Error", "ehs2.tdm_bit_slip_error",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_sync_error,
			{ "Sync Error", "ehs2.tdm_sync_error",
			FT_BOOLEAN, 8, NULL, 0x10,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_aoslos_flag,
			{ "AOS/LOS Flag", "ehs2.tdm_aoslos_flag",
                          FT_BOOLEAN, 8, TFS(&ehs_tfs_secondary_header_tdm_aoslos_flag), 0x08,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_override_errors_flag,
			{ "Override Errors", "ehs2.tdm_override_errors_flag",
			FT_BOOLEAN, 8, NULL, 0x04,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_data_status,
			{ "Data Status", "ehs2.tdm_data_status",
			FT_UINT8, BASE_DEC, VALS(ehs_secondary_header_tdm_data_status), 0x03,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_idq,
			{ "IDQ", "ehs2.tdm_idq",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_cdq,
			{ "CDQ", "ehs2.tdm_cdq",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_adq,
			{ "ADQ", "ehs2.tdm_adq",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_data_dq,
			{ "Data DQ", "ehs2.tdm_data_dq",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_unused,
			{ "Unused", "ehs2.tdm_unused",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_format_id,
			{ "Format ID", "ehs2.tdm_format_id",
			FT_UINT16, BASE_HEX, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_major_frame_packet_index,
			{ "Major Frame Packet Index", "ehs2.tdm_major_frame_packet_index",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_numpkts_per_major_frame,
			{ "Num Packets per Major Frame", "ehs2.tdm_numpkts_per_major_frame",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_num_minor_frames_per_packet,
			{ "Num Minor Frames per Packet", "ehs2.tdm_num_minor_frame_per_packet",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_cntmet_present,
			{ "CNT or MET Present", "ehs2.tdm_cntmet_present",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_present,
			{ "OBT Present", "ehs2.tdm_obt_present",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_major_frame_status_present,
			{ "Major Frame Status Present", "ehs2.tdm_major_frame_status_present",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_reserved,
			{ "Reserved", "ehs2.tdm_reserved",
			FT_UINT8, BASE_DEC, NULL, 0x1f,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_cnt_year,
			{ "CNT Years since 1900", "ehs2.tdm_cnt_year",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_cnt_jday,
			{ "CNT Julian Day of Year", "ehs2.tdm_cnt_jday",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_cnt_hour,
			{ "CNT Hour", "ehs2.tdm_cnt_hour",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_cnt_minute,
			{ "CNT Minute", "ehs2.tdm_cnt_minute",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_cnt_second,
			{ "CNT Second", "ehs2.tdm_cnt_second",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_cnt_tenths,
			{ "CNT Tenths", "ehs2.tdm_cnt_tenths",
			FT_UINT8, BASE_DEC, NULL, 0xf0,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_obt_year,
			{ "OBT Years since 1900", "ehs2.tdm_cnt_year",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_jday,
			{ "OBT Julian Day of Year", "ehs2.tdm_cnt_jday",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_hour,
			{ "OBT Hour", "ehs2.tdm_cnt_hour",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_minute,
			{ "OBT Minute", "ehs2.tdm_cnt_minute",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_second,
			{ "OBT Second", "ehs2.tdm_cnt_second",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_tenths,
			{ "OBT Tenths", "ehs2.tdm_cnt_tenths",
			FT_UINT8, BASE_DEC, NULL, 0xf0,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_obt_delta_time_flag,
			{ "OBT is Delta Time Instead of GMT", "ehs2.tdm_obt_delta_time_flag",
			FT_BOOLEAN, 16, NULL, 0x8000,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_computed_flag,
			{ "OBT Computed", "ehs2.tdm_obt_computed_flag",
			FT_BOOLEAN, 16, NULL, 0x4000,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_not_retrieved_flag,
			{ "OBT Not Retrieved", "ehs2.tdm_obt_not_retrieved_flag",
			FT_BOOLEAN, 16, NULL, 0x2000,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_reserved,
			{ "OBT Reserved", "ehs2.tdm_obt_reserved",
			FT_BOOLEAN, 16, NULL, 0x1800,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_obt_source_apid,
			{ "OBT Source APID", "ehs2.tdm_obt_source_apid",
			FT_UINT16, BASE_DEC, NULL, 0x07ff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_num_major_frame_status_words,
			{ "Number of Major Frame Status Words", "ehs2.tdm_num_major_frame_status_words",
			FT_UINT8, BASE_DEC, NULL, 0x0ff,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_mjfs_reserved,
			{ "Reserved", "ehs2.tdm_mjfs_reserved",
			FT_UINT8, BASE_DEC, NULL, 0xf8,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mjfs_parent_frame_error,
			{ "Parent Frame Error", "ehs2.tdm_mjfs_parent_frame_error",
			FT_BOOLEAN, 8, NULL, 0x04,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mjfs_checksum_error,
			{ "Checksum Error", "ehs2.tdm_mjfs_checksum_error",
			FT_BOOLEAN, 8, NULL, 0x02,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mjfs_fixed_value_error,
			{ "Fixed Value Error", "ehs2.tdm_mjfs_fixed_value_error",
			FT_BOOLEAN, 8, NULL, 0x01,
			NULL, HFILL }
		},

                { &hf_ehs_sh_tdm_mnfs_parent_frame_error,
			{ "Parent Frame Error", "ehs2.tdm_mnfs_parent_frame_error",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mnfs_data_not_available,
			{ "Data Not Available", "ehs2.tdm_mnfs_data_not_available",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mnfs_checksum_error,
			{ "Checksum Error", "ehs2.tdm_mnfs_checksum_error",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mnfs_fixed_value_error,
			{ "Fixed Value Error", "ehs2.tdm_mnfs_fixed_value_error",
			FT_BOOLEAN, 8, NULL, 0x10,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mnfs_counter_error,
			{ "Counter Error", "ehs2.tdm_mnfs_counter_error",
			FT_BOOLEAN, 8, NULL, 0x08,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mnfs_format_id_error,
			{ "Format ID Error", "ehs2.tdm_mnfs_format_id_error",
			FT_BOOLEAN, 8, NULL, 0x04,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mnfs_bit_slip_error,
			{ "Bit Slip Error", "ehs2.tdm_mnfs_bit_slip_error",
			FT_BOOLEAN, 8, NULL, 0x02,
			NULL, HFILL }
		},
                { &hf_ehs_sh_tdm_mnfs_sync_error,
			{ "Sync Error", "ehs2.tdm_mnfs_sync_error",
			FT_BOOLEAN, 8, NULL, 0x01,
			NULL, HFILL }
		},


                /* pseudo secondary header */
		{ &hf_ehs_sh_pseudo_unused,
			{ "Unused", "ehs2.pseudo_unused",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_pseudo_workstation_id,
			{ "Workstation ID", "ehs2.pseudo_workstation_id",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_pseudo_user_id,
			{ "User ID", "ehs2.pseudo_user_id",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},
		{ &hf_ehs_sh_pseudo_comp_id,
			{ "Comp ID", "ehs2.pseudo_comp_id",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},


                /* aos/los protocol data zone */
		{ &hf_ehs_dz_aoslos_indicator,
			{ "AOS/LOS Indicator", "dz.aoslos_indicator",
			FT_UINT8, BASE_DEC, VALS(ehs_data_zone_aoslos_indicator), 0x03,
			NULL, HFILL }
		},


                /* udsm protocol data zone */
                { &hf_ehs_dz_udsm_ccsds_vs_bpdu,
			{ "CCSDS vs BPDU", "dz.udsm_ccsds_vs_bpdu",
			FT_UINT8, BASE_DEC, VALS(ehs_data_zone_udsm_ccsds_vs_bpdu), 0x80,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_unused1,
			{ "Unused 1", "dz.udsm_unused1",
			FT_UINT8, BASE_DEC, NULL, 0x7f,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_unused2,
			{ "Unused 2", "dz.udsm_unused2",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_unused3,
			{ "Unused 3", "dz.udsm_unused3",
			FT_UINT16, BASE_DEC, NULL, 0xe000,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_gse_pkt_id,
			{ "GSE Pkt ID", "dz.udsm_gse_pkt_id",
			FT_BOOLEAN, 16, NULL, 0x1000,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_payload_vs_core,
			{ "Payload vs Core", "dz.udsm_payload_vs_core",
			FT_UINT16, BASE_DEC, VALS(ehs_data_zone_udsm_payload_vs_core), 0x0800,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_apid,
			{ "APID", "dz.udsm_apid",
			FT_UINT16, BASE_DEC, NULL, 0x07ff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_start_time_year,
			{ "Start Time Years since 1900", "dz.udsm_start_time_year",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_start_time_jday,
			{ "Start Time Julian Day", "dz.udsm_start_time_jday",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_start_time_hour,
			{ "Start Time Hour", "dz.udsm_start_time_hour",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_start_time_minute,
			{ "Start Time Minute", "dz.udsm_start_time_minute",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_start_time_second,
			{ "Start Time Second", "dz.udsm_start_time_second",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_stop_time_year,
			{ "Stop Time Years since 1900", "dz.udsm_stop_time_year",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_stop_time_jday,
			{ "Stop Time Julian Day", "dz.udsm_stop_time_jday",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_stop_time_hour,
			{ "Stop Time Hour", "dz.udsm_stop_time_hour",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_stop_time_minute,
			{ "Stop Time Minute", "dz.udsm_stop_time_minute",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
                { &hf_ehs_dz_udsm_stop_time_second,
			{ "Stop Time Second", "dz.udsm_stop_time_second",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_unused4,
			{ "Unused 4", "dz.udsm_unused4",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_num_pkts_xmtd,
			{ "Num Pkts Transmitted", "dz.udsm_num_pkts_xmtd",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_num_vcdu_seqerrs,
			{ "Num VCDU Sequence Errors", "dz.udsm_num_vcdu_seqerrs",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_num_pkt_seqerrs,
			{ "Num Packet Sequence Errors", "dz.udsm_num_pkt_seqerrs",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_num_pktlen_errors,
			{ "Num Pkt Length Errors", "dz.udsm_num_pktlen_errors",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_event,
			{ "UDSM Event Code", "dz.udsm_event",
			FT_UINT8, BASE_DEC, VALS(ehs_data_zone_udsm_event), 0xff,
			NULL, HFILL }
		},

                { &hf_ehs_dz_udsm_num_pkts_xmtd_rollover,
			{ "Num Pkts Transmitted Rollover Counter", "dz.udsm_num_pkts_xmtd_rollover",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},

	};

        /* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ehs,
		&ett_ehs_primary_header,
		&ett_ehs_secondary_header,
		&ett_ehs_data_zone
	};

        /* Register the protocol name and description */
	proto_ehs = proto_register_protocol("EHS", "EHS", "ehs");

        /* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ehs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* XX: Does this dissector need to be publicly registered ?? */
	register_dissector ( "ehs", dissect_ehs, proto_ehs );

}


/* If this dissector uses sub-dissector registration add a registration routine.
 * This format is required because a script is used to find these routines and
 * create the code that calls these routines.
 */
void
proto_reg_handoff_ehs(void)
{
	dissector_add_handle ( "udp.port", find_dissector("ehs") ); /* for 'decode as' */
	ccsds_handle = find_dissector ( "ccsds" );
}

