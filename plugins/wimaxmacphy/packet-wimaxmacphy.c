/* packet-wimaxmacphy.c
 * Routines for wimaxmacphy (WiMAX MAX PHY over Ethernet) packet dissection
 * Copyright 2008, Mobile Metrics - http://mobilemetrics.net/
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
#include "packet-wimaxmacphy.h"

/* Initialize the protocol and registered fields */

static int proto_wimaxmacphy                                         = -1;
static int hf_wimaxmacphy_hdr_phy_entity_id                          = -1;
static int hf_wimaxmacphy_hdr_message_segmentation                   = -1;
static int hf_wimaxmacphy_hdr_message_type                           = -1;
static int hf_wimaxmacphy_unknown                                    = -1;
static int hf_wimaxmacphy_prim_length_of_txvector                    = -1;
static int hf_wimaxmacphy_prim_length_of_rxvector                    = -1;
static int hf_wimaxmacphy_prim_status                                = -1;
static int hf_wimaxmacphy_prim_txstart_indication_status             = -1;
static int hf_wimaxmacphy_prim_reserved1                             = -1;
static int hf_wimaxmacphy_prim_reserved2                             = -1;
static int hf_wimaxmacphy_prim_reserved3                             = -1;
static int hf_wimaxmacphy_prim_reserved4                             = -1;
static int hf_wimaxmacphy_prim_reserved5                             = -1;
static int hf_wimaxmacphy_prim_next_frame_number                     = -1;
static int hf_wimaxmacphy_prim_extended_frame_number                 = -1;
static int hf_wimaxmacphy_prim_current_frame_number_lsn              = -1;
static int hf_wimaxmacphy_prim_initial_frame_number                  = -1;
static int hf_wimaxmacphy_prim_dl_zone_number                        = -1;
static int hf_wimaxmacphy_prim_sub_burst_burst_split_point           = -1;
static int hf_wimaxmacphy_prim_dl_sub_burst_burst_number             = -1;
static int hf_wimaxmacphy_prim_phy_sdu                               = -1;
static int hf_wimaxmacphy_prim_phy_request                           = -1;
static int hf_wimaxmacphy_prim_requested_aas_calibration_zone_size   = -1;
static int hf_wimaxmacphy_prim_requested_aas_calibration_zone_alloc  = -1;
static int hf_wimaxmacphy_prim_number_of_consecutive_frames_with_aas = -1;
static int hf_wimaxmacphy_prim_frame_number                          = -1;
static int hf_wimaxmacphy_prim_issid                                 = -1;
static int hf_wimaxmacphy_prim_integrity                             = -1;
static int hf_wimaxmacphy_prim_number_of_bytes_received              = -1;
static int hf_wimaxmacphy_prim_rssi_per_subcarrier_level             = -1;
static int hf_wimaxmacphy_prim_cinr                                  = -1;
static int hf_wimaxmacphy_prim_power_offset                          = -1;
static int hf_wimaxmacphy_prim_current_frame_number_msn              = -1;
static int hf_wimaxmacphy_prim_acid_for_harq_data_bursts             = -1;
static int hf_wimaxmacphy_prim_indication_type                       = -1;
static int hf_wimaxmacphy_prim_zone_permutation_type                 = -1;
static int hf_wimaxmacphy_prim_update_aas_handle_in_mac              = -1;
static int hf_wimaxmacphy_prim_aas_handle                            = -1;
static int hf_wimaxmacphy_prim_time_deviation                        = -1;
static int hf_wimaxmacphy_prim_frequency_deviation                   = -1;
static int hf_wimaxmacphy_prim_phy_aas_report_present                = -1;
static int hf_wimaxmacphy_prim_number_of_affected_ss                 = -1;
static int hf_wimaxmacphy_prim_zonexid                               = -1;
static int hf_wimaxmacphy_prim_cdma_code                             = -1;
static int hf_wimaxmacphy_prim_cdma_symbol                           = -1;
static int hf_wimaxmacphy_prim_cdma_subchannel                       = -1;
static int hf_wimaxmacphy_prim_harq_ack_issid                        = -1;
static int hf_wimaxmacphy_prim_harq_ack_acid                         = -1;
static int hf_wimaxmacphy_prim_harq_ack_reserved1                    = -1;
static int hf_wimaxmacphy_prim_harq_ack_ack_valid                    = -1;
static int hf_wimaxmacphy_prim_harq_ack_unnamed                      = -1;
static int hf_wimaxmacphy_prim_harq_ack_reserved2                    = -1;
static int hf_wimaxmacphy_prim_fast_issid                            = -1;
static int hf_wimaxmacphy_prim_fast_cqich_id                         = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding             = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding_bit0        = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding_bit1        = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding_bit2        = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding_bit3        = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding_bit4        = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding_bit5        = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding_bit6        = -1;
static int hf_wimaxmacphy_prim_fast_feedback_type_coding_bit7        = -1;
static int hf_wimaxmacphy_prim_fast_feedback_valid                   = -1;
static int hf_wimaxmacphy_prim_fast_feedback_sub_type                = -1;
static int hf_wimaxmacphy_prim_fast_reserved                         = -1;
static int hf_wimaxmacphy_prim_fast_feedback_value                   = -1;
static int hf_wimaxmacphy_subframe_subframe_type                     = -1;
static int hf_wimaxmacphy_subframe_frame_number                      = -1;
static int hf_wimaxmacphy_subframe_downlink_reserved1                = -1;
static int hf_wimaxmacphy_subframe_phy_sap_version_number            = -1;
static int hf_wimaxmacphy_subframe_downlink_reserved2                = -1;
static int hf_wimaxmacphy_subframe_allocation_start_time             = -1;
static int hf_wimaxmacphy_number_of_zone_descriptors                 = -1;
static int hf_wimaxmacphy_zone_padding                               = -1;
static int hf_wimaxmacphy_dl_zone_type                               = -1;
static int hf_wimaxmacphy_ul_zone_type                               = -1;
static int hf_wimaxmacphy_zone_number                                = -1;
static int hf_wimaxmacphy_zone_start_symbol_offset                   = -1;
static int hf_wimaxmacphy_zone_end_symbol_offset                     = -1;
static int hf_wimaxmacphy_dl_zone_permutation_type                   = -1;
static int hf_wimaxmacphy_ul_zone_permutation_type                   = -1;
static int hf_wimaxmacphy_dl_zone_use_all_subchannels_indicator      = -1;
static int hf_wimaxmacphy_ul_zone_use_all_subchannels_indicator      = -1;
static int hf_wimaxmacphy_ul_zone_disable_pusc_subchannel_rotation   = -1;
static int hf_wimaxmacphy_zone_dl_perm_base                          = -1;
static int hf_wimaxmacphy_zone_ul_perm_base                          = -1;
static int hf_wimaxmacphy_zone_prbs_id                               = -1;
static int hf_wimaxmacphy_zone_agc_range_extension                   = -1;
static int hf_wimaxmacphy_zone_dedicated_pilots                      = -1;
static int hf_wimaxmacphy_zone_reserved                              = -1;
static int hf_wimaxmacphy_zone_stc_type                              = -1;
static int hf_wimaxmacphy_zone_matrix_indicator                      = -1;
static int hf_wimaxmacphy_zone_midamble_presence                     = -1;
static int hf_wimaxmacphy_zone_midamble_boosting                     = -1;
static int hf_wimaxmacphy_zone_preamble_configuration                = -1;
static int hf_wimaxmacphy_zone_sdma_supported_indication             = -1;
static int hf_wimaxmacphy_zone_preamble_type                         = -1;
static int hf_wimaxmacphy_dl_zone_aas_reserved                       = -1;
static int hf_wimaxmacphy_ul_zone_aas_reserved                       = -1;
static int hf_wimaxmacphy_number_of_burst_descriptors                = -1;
static int hf_wimaxmacphy_burst_padding                              = -1;
static int hf_wimaxmacphy_dl_burst_type                              = -1;
static int hf_wimaxmacphy_ul_burst_type                              = -1;
static int hf_wimaxmacphy_burst_type_extension                       = -1;
static int hf_wimaxmacphy_burst_number                               = -1;
static int hf_wimaxmacphy_burst_modulation_fec_code_type             = -1;
static int hf_wimaxmacphy_burst_data_length                          = -1;
static int hf_wimaxmacphy_burst_ofdma_symbol_offset                  = -1;
static int hf_wimaxmacphy_burst_subchannel_offset                    = -1;
static int hf_wimaxmacphy_burst_boosting                             = -1;
static int hf_wimaxmacphy_burst_reserved                             = -1;
static int hf_wimaxmacphy_burst_repetition_coding_indication         = -1;
static int hf_wimaxmacphy_burst_issid                                = -1;
static int hf_wimaxmacphy_burst_aas_handle                           = -1;
static int hf_wimaxmacphy_dl_burst_map_number_of_slots               = -1;
static int hf_wimaxmacphy_dl_burst_map_reserved                      = -1;
static int hf_wimaxmacphy_dl_burst_normal_number_of_symbols          = -1;
static int hf_wimaxmacphy_dl_burst_normal_number_of_subchannels      = -1;
static int hf_wimaxmacphy_dl_burst_normal_aas_handle                 = -1;
static int hf_wimaxmacphy_ul_burst_normal_number_of_slots            = -1;
static int hf_wimaxmacphy_ul_burst_normal_reserved                   = -1;
static int hf_wimaxmacphy_burst_papr_number_of_symbols               = -1;
static int hf_wimaxmacphy_burst_papr_number_of_subchannels           = -1;
static int hf_wimaxmacphy_burst_papr_reserved                        = -1;
static int hf_wimaxmacphy_ul_burst_papr_unnamed                      = -1;
static int hf_wimaxmacphy_ul_burst_harq_ack_number_of_symbols        = -1;
static int hf_wimaxmacphy_ul_burst_harq_ack_number_of_subchannels    = -1;
static int hf_wimaxmacphy_ul_burst_harq_ack_reserved                 = -1;
static int hf_wimaxmacphy_ul_burst_fast_number_of_symbols            = -1;
static int hf_wimaxmacphy_ul_burst_fast_number_of_subchannels        = -1;
static int hf_wimaxmacphy_ul_burst_fast_reserved                     = -1;
static int hf_wimaxmacphy_ul_burst_initial_number_of_symbols         = -1;
static int hf_wimaxmacphy_ul_burst_initial_number_of_subchannels     = -1;
static int hf_wimaxmacphy_ul_burst_initial_ranging_method            = -1;
static int hf_wimaxmacphy_ul_burst_initial_reserved1                 = -1;
static int hf_wimaxmacphy_ul_burst_initial_zone_xid                  = -1;
static int hf_wimaxmacphy_ul_burst_initial_reserved2                 = -1;
static int hf_wimaxmacphy_ul_burst_periodic_number_of_symbols        = -1;
static int hf_wimaxmacphy_ul_burst_periodic_number_of_subchannels    = -1;
static int hf_wimaxmacphy_ul_burst_periodic_ranging_method           = -1;
static int hf_wimaxmacphy_ul_burst_periodic_reserved1                = -1;
static int hf_wimaxmacphy_ul_burst_periodic_zone_xid                 = -1;
static int hf_wimaxmacphy_ul_burst_periodic_reserved2                = -1;
static int hf_wimaxmacphy_ul_burst_sounding_number_of_symbols        = -1;
static int hf_wimaxmacphy_ul_burst_sounding_number_of_subchannels    = -1;
static int hf_wimaxmacphy_ul_burst_sounding_type                     = -1;
static int hf_wimaxmacphy_ul_burst_sounding_separability_type        = -1;
static int hf_wimaxmacphy_ul_burst_sounding_max_cyclic_shift_indx    = -1;
static int hf_wimaxmacphy_ul_burst_sounding_decimation_value         = -1;
static int hf_wimaxmacphy_ul_burst_sounding_decimation_offset_rand   = -1;
static int hf_wimaxmacphy_ul_burst_sounding_reserved                 = -1;
static int hf_wimaxmacphy_ul_burst_noise_number_of_symbols           = -1;
static int hf_wimaxmacphy_ul_burst_noise_number_of_subchannels       = -1;
static int hf_wimaxmacphy_ul_burst_noise_reserved                    = -1;
static int hf_wimaxmacphy_burst_opt_aas_preamble_modifier_type       = -1;
static int hf_wimaxmacphy_burst_opt_aas_preamble_shift_index         = -1;
static int hf_wimaxmacphy_burst_opt_aas_reserved                     = -1;
static int hf_wimaxmacphy_burst_opt_mimo_matrix_indicator            = -1;
static int hf_wimaxmacphy_burst_opt_mimo_layer_index                 = -1;
static int hf_wimaxmacphy_dl_burst_opt_mimo_reserved                 = -1;
static int hf_wimaxmacphy_ul_burst_opt_mimo_matrix_indicator         = -1;
static int hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns           = -1;
static int hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit0      = -1;
static int hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit1      = -1;
static int hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit2      = -1;
static int hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit3      = -1;
static int hf_wimaxmacphy_ul_burst_opt_mimo_collaborative            = -1;
static int hf_wimaxmacphy_ul_burst_opt_mimo_antenna_unnamed          = -1;
static int hf_wimaxmacphy_number_of_sub_burst_descriptors            = -1;
static int hf_wimaxmacphy_sub_burst_padding                          = -1;
static int hf_wimaxmacphy_dl_sub_burst_type                          = -1;
static int hf_wimaxmacphy_ul_sub_burst_type                          = -1;
static int hf_wimaxmacphy_sub_burst_number                           = -1;
static int hf_wimaxmacphy_sub_burst_symbol_offset                    = -1;
static int hf_wimaxmacphy_sub_burst_subchannel_offset                = -1;
static int hf_wimaxmacphy_sub_burst_number_of_slots                  = -1;
static int hf_wimaxmacphy_sub_burst_reserved1                        = -1;
static int hf_wimaxmacphy_sub_burst_reserved2                        = -1;
static int hf_wimaxmacphy_sub_burst_modulation_fec_code_type         = -1;
static int hf_wimaxmacphy_sub_burst_issid                            = -1;
static int hf_wimaxmacphy_sub_burst_aas_handle                       = -1;
static int hf_wimaxmacphy_sub_burst_boosting                         = -1;
static int hf_wimaxmacphy_sub_burst_repetition_coding_indication     = -1;
static int hf_wimaxmacphy_sub_burst_data_length                      = -1;
static int hf_wimaxmacphy_sub_burst_harq_chase_harq_channel_id       = -1;
static int hf_wimaxmacphy_sub_burst_harq_chase_harq_sequence_number  = -1;
static int hf_wimaxmacphy_sub_burst_harq_chase_flush_unnamed         = -1;
static int hf_wimaxmacphy_sub_burst_harq_chase_reserved              = -1;
static int hf_wimaxmacphy_sub_burst_mimo_chase_harq_channel_id       = -1;
static int hf_wimaxmacphy_sub_burst_mimo_chase_harq_sequence_number  = -1;
static int hf_wimaxmacphy_sub_burst_mimo_chase_flush_unnamed         = -1;
static int hf_wimaxmacphy_sub_burst_mimo_chase_layer_index           = -1;
static int hf_wimaxmacphy_ul_sub_burst_ctype                         = -1;
static int hf_wimaxmacphy_ul_sub_burst_mini_subchannel_index         = -1;
static int hf_wimaxmacphy_ul_sub_burst_mini_reserved                 = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding          = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit0     = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit1     = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit2     = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit3     = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit4     = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit5     = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit6     = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit7     = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_reserved1            = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_sub_type             = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_cqich_id             = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_reserved2            = -1;
static int hf_wimaxmacphy_ul_sub_burst_feedback_slot_offset          = -1;
static int hf_wimaxmacphy_ul_sub_burst_harq_ack_acid                 = -1;
static int hf_wimaxmacphy_ul_sub_burst_harq_ack_reserved             = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_symbol_index         = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_power_assignment     = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_power_boost          = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_allocation_mode      = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_start_freq_band      = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_num_freq_bands       = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_band_bit_map         = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_cyclic_time_shift    = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_decimation_offset    = -1;
static int hf_wimaxmacphy_ul_sub_burst_sounding_reserved             = -1;
static int hf_wimaxmacphy_ul_sub_burst_mimo_chase_matrix             = -1;

/* Initialize the subtree pointers */
static gint ett_wimaxmacphy                                          = -1;
static gint ett_wimaxmacphy_primitive                                = -1;
static gint ett_wimaxmacphy_prim_harq_ack                            = -1;
static gint ett_wimaxmacphy_prim_fast_feedback                       = -1;
static gint ett_wimaxmacphy_prim_fast_feedback_type_coding           = -1;
static gint ett_wimaxmacphy_dl_zone_descriptor                       = -1;
static gint ett_wimaxmacphy_dl_zone_stc                              = -1;
static gint ett_wimaxmacphy_dl_zone_aas                              = -1;
static gint ett_wimaxmacphy_dl_burst_descriptor                      = -1;
static gint ett_wimaxmacphy_dl_burst_map                             = -1;
static gint ett_wimaxmacphy_dl_burst_normal                          = -1;
static gint ett_wimaxmacphy_dl_burst_papr                            = -1;
static gint ett_wimaxmacphy_dl_sub_burst_descriptor                  = -1;
static gint ett_wimaxmacphy_dl_sub_burst_harq_chase                  = -1;
static gint ett_wimaxmacphy_dl_sub_burst_mimo_chase                  = -1;
static gint ett_wimaxmacphy_dl_burst_opt_aas                         = -1;
static gint ett_wimaxmacphy_dl_burst_opt_mimo                        = -1;
static gint ett_wimaxmacphy_ul_zone_descriptor                       = -1;
static gint ett_wimaxmacphy_ul_zone_aas                              = -1;
static gint ett_wimaxmacphy_ul_burst_descriptor                      = -1;
static gint ett_wimaxmacphy_ul_burst_harq_ack                        = -1;
static gint ett_wimaxmacphy_ul_burst_fast_feedback                   = -1;
static gint ett_wimaxmacphy_ul_burst_initial_ranging                 = -1;
static gint ett_wimaxmacphy_ul_burst_periodic_ranging                = -1;
static gint ett_wimaxmacphy_ul_burst_papr_safety_zone                = -1;
static gint ett_wimaxmacphy_ul_burst_sounding_zone                   = -1;
static gint ett_wimaxmacphy_ul_burst_noise_floor                     = -1;
static gint ett_wimaxmacphy_ul_burst_normal_data                     = -1;
static gint ett_wimaxmacphy_ul_burst_opt_aas                         = -1;
static gint ett_wimaxmacphy_ul_burst_opt_mimo                        = -1;
static gint ett_wimaxmacphy_ul_sub_burst_descriptor                  = -1;
static gint ett_wimaxmacphy_ul_pilot_patterns                        = -1;
static gint ett_wimaxmacphy_ul_feedback_type_coding                  = -1;
static gint ett_wimaxmacphy_ul_sub_burst_mini_subchannel             = -1;
static gint ett_wimaxmacphy_ul_sub_burst_fast_feedback               = -1;
static gint ett_wimaxmacphy_ul_sub_burst_harq_ack                    = -1;
static gint ett_wimaxmacphy_ul_sub_burst_sounding_signal             = -1;
static gint ett_wimaxmacphy_ul_sub_burst_harq_chase                  = -1;
static gint ett_wimaxmacphy_ul_sub_burst_mimo_chase                  = -1;
static gint ett_wimaxmacphy_ul_sub_burst_sub_allocation_specific     = -1;

static expert_field ei_wimaxmacphy_unknown = EI_INIT;

/* Preferences */
static guint wimaxmacphy_udp_port = 0;


/* PHY SAP message header size */
#define WIMAXMACPHY_HEADER_SIZE 2

#define WIMAXMACPHY_BIT(n) (1 << (n))

#define WIMAXMACPHY_PHY_TXSTART_REQUEST         1
#define WIMAXMACPHY_PHY_TXSTART_CONFIRMATION    2
#define WIMAXMACPHY_PHY_TXSTART_INDICATION      3
#define WIMAXMACPHY_PHY_TXSDU_REQUEST           4
#define WIMAXMACPHY_PHY_TXSDU_CONFIRMATION      5
#define WIMAXMACPHY_PHY_TXEND_INDICATION        6
#define WIMAXMACPHY_PHY_RXSTART_REQUEST         7
#define WIMAXMACPHY_PHY_RXSTART_CONFIRMATION    8
#define WIMAXMACPHY_PHY_RXSTART_INDICATION      9
#define WIMAXMACPHY_PHY_RXSDU_INDICATION       10
#define WIMAXMACPHY_PHY_RXEND_INDICATION       11
#define WIMAXMACPHY_PHY_RXCDMA_INDICATION      15

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_message_segmentation_vals[] =
{
    { 0x00, "Middle segment of the message segment sequence"},
    { 0x01, "Last segment of the message segment sequence"},
    { 0x02, "First segment of the message segment sequence"},
    { 0x03, "The entire message is contained in this segment"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_message_type_vals[] =
{
    {  0,  "Reserved"},
    {  1,  "PHY_TXSTART.request"},
    {  2,  "PHY_TXSTART.confirmation"},
    {  3,  "PHY_TXSTART.indication"},
    {  4,  "PHY_TXSDU.request"},
    {  5,  "PHY_TXSDU.confirmation"},
    {  6,  "PHY_TXEND.indication"},
    {  7,  "PHY_RXSTART.request"},
    {  8,  "PHY_RXSTART.confirmation"},
    {  9,  "PHY_RXSTART.indication"},
    { 10,  "PHY_RXSDU.indication"},
    { 11,  "PHY_RXEND.indication"},
    { 12,  "Reserved (OFDM)"},
    { 13,  "Reserved (OFDM)"},
    { 14,  "Reserved (OFDM)"},
    { 15,  "PHY_RXCDMA.indication"},
    { 16,  "Reserved (OFDMA SS)"},
    { 17,  "Reserved (OFDMA SS)"},
    { 0,    NULL}
};
#if 0 /* XXX: 'tshark -G values' gives warning on Windows' */
static value_string_ext wimaxmacphy_message_type_vals_ext = VALUE_STRING_EXT_INIT(wimaxmacphy_message_type_vals);
#endif

/* ------------------------------------------------------------------------- */
/* error code field coding, for all but TXSTART.indication
 */
static const value_string wimaxmacphy_prim_status_vals[]=
{
    { 0, "Success"},
    { 1, "Primitive is not supported"},
    { 2, "FEC code type is not supported"},
    { 3, "Overrun"},
    { 4, "Underrun"},
    { 5, "Transport Media Error"},
    { 6, "TX data size do not match TXVECTOR"},
    { 7, "Invalid RX/TX VECTOR format"},
    { 0, NULL}
};

/* ---------------------------------------------------------------------------
 *  error code field coding, TXSTART.indication specific, delta is description
 *  for value 1
 */

static const value_string wimaxmacphy_prim_txstart_indication_status_vals[]=
{
    { 0, "Success"},
    { 1, "Restart flag"},
    { 2, "FEC code type is not supported"},
    { 3, "Overrun"},
    { 4, "Underrun"},
    { 5, "Transport Media Error"},
    { 6, "TX data size do not match TXVECTOR"},
    { 7, "Invalid RX/TX VECTOR format"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

#if 0
static const value_string wimaxmacphy_prim_sub_burst_burst_split_point_vals[]=
{
    { 0x00, "all 10 bits for burst number"},
    { 0x01, "1 bit sub-burst and 9 bits burst number"},
    { 0x02, "2 bit sub-burst and 8 bits burst number"},
    { 0x03, "3 bit sub-burst and 7 bits burst number"},
    { 0x04, "4 bit sub-burst and 6 bits burst number"},
    { 0x05, "5 bit sub-burst and 5 bits burst number"},
    { 0x06, "6 bit sub-burst and 4 bits burst number"},
    { 0x07, "7 bit sub-burst and 3 bits burst number"},
    { 0,    NULL}
};
#endif

/* ------------------------------------------------------------------------- */

#if 0
static const value_string wimaxmacphy_prim_phy_request_vals[]=
{
    { 0x0, "LW 1 not present"},
    { 0x1, "AAS calibration request present in LW 1"},
    { 0,    NULL}
};
#endif

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_prim_integrity_vals[]=
{
    { 0, "valid data"},
    { 1, "invalid data"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_prim_indication_type_vals[]=
{
    { 0, "Data burst"},
    { 1, "HARQ ACK channel"},
    { 2, "Fast Feedback Channel"},
    { 3, "HARQ data burst"},
    { 4, "MIMO data burst"},
    { 5, "MIMO HARQ data burst"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_prim_zone_permutation_type_vals[]=
{
    { 0x0, "PUSC"},
    { 0x1, "Optional PUSC"},
    { 0x2, "AMC - 1 x 6"},
    { 0x3, "AMC - 2 x 3"},
    { 0x4, "AMC - 3 x 2"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_prim_phy_aas_report_present_vals[]=
{
    { 0x0, " not present (only LW 0 is significant)"},
    { 0x1, "AAS info aged out report present"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_prim_harq_ack_ack_valid_vals[]=
{
    { 0, "valid data"},
    { 1, "invalid data"},
    { 0, NULL}
};

static const true_false_string set_notset = {
    "Set",
    "Not set"
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_prim_harq_ack_unnamed_vals[]=
{
    { 0, "ACK"},
    { 1, "NAK"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_prim_fast_feedback_valid_vals[]=
{
    { 0, "valid data"},
    { 1, "invalid data"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_prim_fast_feedback_sub_type_vals[]=
{
    { 0, "CQI (CINR) measurement"},
    { 1, "Control feedback"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_subframe_type_vals[]=
{
    { 1, "Downlink Subframe"},
    { 2, "Uplink Subframe"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_dl_zone_type_vals[]=
{
    { 0x20, "Normal Zone Parameters"},
    { 0x21, "STC Zone Parameters"},
    { 0x22, "AAS Zone Parameters"},
    { 0x23, "Common Sync Symbol Parameters"},
    { 0x24, "AAS Calibration Zone"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_zone_type_vals[]=
{
    { 0x20, "Normal Zone Parameters"},
    { 0x21, "Reserved"},
    { 0x22, "AAS Zone Parameters"},
    { 0x23, "Reserved"},
    { 0x24, "Reserved"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_dl_zone_permutation_type_vals[]=
{
    { 0x00, "PUSC"},
    { 0x01, "FUSC"},
    { 0x02, "Optional FUSC"},
    { 0x03, "AMC - 1 x 6"},
    { 0x04, "AMC - 2 x 3"},
    { 0x05, "AMC - 3 x 2"},
    { 0x06, "TUSC1"},
    { 0x07, "TUSC2"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_zone_permutation_type_vals[]=
{
    { 0x00, "PUSC"},
    { 0x01, "FUSC"},
    { 0x02, "Optional FUSC"},
    { 0x03, "AMC - 1 x 6"},
    { 0x04, "AMC - 2 x 3"},
    { 0x05, "AMC - 3 x 2"},
    { 0x06, "Reserved"},
    { 0x07, "Reserved"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_zone_use_all_subchannels_indicator_vals[]=
{
    { 0, "use only subchannels specified in PHY configuration register"},
    { 1, "use all subchannels"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_ul_zone_disable_pusc_subchannel_rotation_vals[]=
{
    { 0, "rotation enabled"},
    { 1, "rotation disabled"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_zone_dedicated_pilots_vals[]=
{
    { 0, "pilots are broadcast"},
    { 1, "pilots are dedicated"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_zone_agc_range_extension_vals[]=
{
    { 0, "default range"},
    { 1, "range to cover SS very close to BS"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_zone_stc_type_vals[]=
{
    { 0x00, "STC using 2 antennas"},
    { 0x01, "STC using 3 antennas"},
    { 0x02, "STC using 4 antennas"},
    { 0x03, "FHDC using 2 antennas"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_matrix_indicator_vals[]=
{
    { 0x00, "Matrix A"},
    { 0x01, "Matrix B"},
    { 0x02, "Matrix C"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_zone_midamble_presence_vals[]=
{
    { 0, "not present"},
    { 1, "present"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_zone_midamble_boosting_vals[]=
{
    { 0, "no boosting"},
    { 1, "boosting"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_zone_preamble_configuration_vals[]=
{
    { 0x00, "0 symbols (preambles not supported)"},
    { 0x01, "1 symbol"},
    { 0x02, "2 symbols"},
    { 0x03, "3 symbols"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_zone_sdma_supported_indication_vals[]=
{
    { 0, "SDMA not supported"},
    { 1, "SDMA supported"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_zone_preamble_type_vals[]=
{
    { 0, "frequency shifted preamble"},
    { 1, "time shifted preamble"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_dl_burst_type_vals[]=
{
    { 0x40, "Map Data Burst"},
    { 0x41, "Normal Data Burst"},
    { 0x42, "Control Command"},
    { 0x43, "PAPR Allocation"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_burst_type_vals[]=
{
    { 0x40, "HARQ ACK Channel allocation"},
    { 0x41, "Fast Feedback Channel allocation"},
    { 0x42, "Initial Ranging/Handover Ranging region"},
    { 0x43, "Periodic Ranging/Bandwidth Request region"},
    { 0x44, "PAPR/Safety Zone allocation"},
    { 0x45, "Sounding Zone allocation"},
    { 0x46, "Noise Floor Calculation allocation"},
    { 0x47, "Normal Data burst"},
    { 0x48, "Control Command"},
    { 0x49, "Reserved"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_burst_type_extension_vals[]=
{
    { 0x00, "no extended data:"},
    { 0x01, "AAS v1"},
    { 0x02, "MIMO v1"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_modulation_fec_code_type_vals[]=
{
    {  0, "QPSK (CC) 1/2"},
    {  1, "QPSK (CC) 3/4"},
    {  2, "16-QAM (CC) 1/2"},
    {  3, "16-QAM (CC) 3/4"},
    {  4, "64-QAM (CC) 1/2"},
    {  5, "64-QAM (CC) 2/3"},
    {  6, "64-QAM (CC) 3/4"},
    {  7, "QPSK (BTC) 1/2"},
    {  8, "QPSK (BTC) 3/4"},
    {  9, "16-QAM (BTC) 3/5"},
    { 10, "16-QAM (BTC) 4/5"},
    { 11, "64-QAM (BTC) 5/8"},
    { 12, "64-QAM (BTC) 4/5"},
    { 13, "QPSK (CTC) 1/2"},
    { 14, "Reserved"},
    { 15, "QPSK (CTC) 3/4"},
    { 16, "16-QAM (CTC) 1/2"},
    { 17, "16-QAM (CTC) 3/4"},
    { 18, "64-QAM (CTC) 1/2"},
    { 19, "64-QAM (CTC) 2/3"},
    { 20, "64-QAM (CTC) 3/4"},
    { 21, "64-QAM (CTC) 5/6"},
    { 22, "QPSK (ZT CC) 1/2"},
    { 23, "QPSK (ZT CC) 3/4"},
    { 24, "16-QAM (ZT CC) 1/2"},
    { 25, "16-QAM (ZT CC) 3/4"},
    { 26, "64-QAM (ZT CC) 1/2"},
    { 27, "64-QAM (ZT CC) 2/3"},
    { 28, "64-QAM (ZT CC) 3/4"},
    { 29, "QPSK (LDPC) 1/2"},
    { 30, "QPSK (LDPC) 2/3 A code"},
    { 31, "QPSK (LDPC) 3/4 A code"},
    { 32, "16-QAM (LDPC) 1/2"},
    { 33, "16-QAM (LDPC) 2/3 A code"},
    { 34, "16-QAM (LDPC) 3/4 A code"},
    { 35, "64-QAM (LDPC) 1/2"},
    { 36, "64-QAM (LDPC) 2/3 A code"},
    { 37, "64-QAM (LDPC) 3/4 A code"},
    { 38, "QPSK (LDPC) 2/3 B code"},
    { 39, "QPSK (LDPC) 3/4 B code"},
    { 40, "16-QAM (LDPC) 2/3 B code"},
    { 41, "16-QAM (LDPC) 3/4 B code"},
    { 42, "64-QAM (LDPC) 2/3 B code"},
    { 43, "64-QAM (LDPC) 3/4 B code"},
    { 44, "QPSK (CC with optional interleaver) 1/2"},
    { 45, "QPSK (CC with optional interleaver) 3/4"},
    { 46, "16-QAM (CC with optional interleaver) 1/2"},
    { 47, "16-QAM (CC with optional interleaver) 3/4"},
    { 48, "64-QAM (CC with optional interleaver) 2/3"},
    { 49, "64-QAM (CC with optional interleaver) 3/4"},
    { 50, "QPSK (LDPC) 5/6"},
    { 51, "16-QAM(LDPC) 5/6"},
    { 52, "64-QAM(LDPC) 5/6"},
    { 0,  NULL}
};
#if 0 /* XXX: 'tshark -G values' gives warning on Windows' */
static value_string_ext wimaxmacphy_modulation_fec_code_type_vals_ext =
    VALUE_STRING_EXT_INIT(wimaxmacphy_modulation_fec_code_type_vals);
#endif

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_burst_boosting_vals[]=
{
    { 0x00, "normal"},
    { 0x01, "+6dB"},
    { 0x02, "-6dB"},
    { 0x03, "+9dB"},
    { 0x04, "+3dB"},
    { 0x05, "-3dB"},
    { 0x06, "-9 dB"},
    { 0x07, "-12 dB"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_burst_repetition_coding_indication_vals[]=
{
    { 0x00, "No repetition coding"},
    { 0x01, "Repetition coding of 2"},
    { 0x02, "Repetition coding of 4"},
    { 0x03, "Repetition coding of 6"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_dl_sub_burst_type_vals[]=
{
    { 0x60, "No HARQ"},
    { 0x61, "HARQ Chase Combining"},
    { 0x62, "HARQ IR-CTC"},
    { 0x63, "HARQ IR-CC"},
    { 0x64, "MIMO Chase Combining"},
    { 0x65, "MIMO IR-CTC"},
    { 0x66, "MIMO IR-CC"},
    { 0x67, "MIMO-STC"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_sub_burst_type_vals[]=
{
    { 0x60, "No HARQ"},
    { 0x61, "HARQ Chase Combining"},
    { 0x62, "HARQ IR-CTC"},
    { 0x63, "HARQ IR-CC"},
    { 0x64, "MIMO Chase Combining"},
    { 0x65, "MIMO IR-CTC"},
    { 0x66, "MIMO IR-CC"},
    { 0x67, "MIMO-STC"},
    { 0x68, "Mini-subchannel"},
    { 0x69, "Fast Feedback channel"},
    { 0x6A, "HARQ ACK subchannel"},
    { 0x6B, "Sounding signal"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_sub_burst_flush_unnamed_vals[]=
{
    { 0x00, "no flush action"},
    { 0x02, "flush request to PHY for the ISSID/ACID"},
    { 0x03, "flush request to PHY for the given ISSID"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_burst_papr_unnamed_vals[]=
{
    { 0, "UL PAPR reduction"},
    { 1, "UL Safety zone"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_burst_ranging_method_vals[]=
{
    { 0, "ranging over 2 symbols"},
    { 1, "ranging over 4 symbols"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_burst_sounding_type_vals[]=
{
    { 0, "Type A"},
    { 1, "Type B"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_ul_burst_sounding_separability_type_vals[]=
{
    { 0, "all subcarriers"},
    { 1, "decimated subcarriers in a band"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_ul_burst_sounding_max_cyclic_shift_indx_vals[]=
{
    { 0x00, "P=4"},
    { 0x01, "P=8;"},
    { 0x02, "P=16"},
    { 0x03, "P=32"},
    { 0x04, "P=9"},
    { 0x05, "P=18"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_ul_burst_sounding_decimation_offset_rand_vals[]=
{
    { 0, "no randomization"},
    { 1, "randomization"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_ul_burst_opt_mimo_matrix_indicator_vals[]=
{
    { 0x00, "Matrix A (STTD)"},
    { 0x01, "Matrix B (SM)"},
    { 0x02, "Reserved"},
    { 0x03, "Reserved"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_burst_opt_mimo_collaborative_vals[]=
{
    { 0, "non-collaborative"},
    { 1, "collaborative"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_burst_opt_mimo_antenna_unnamed_vals[]=
{
    { 0, "Single TX antenna SS"},
    { 1, "Dual TX antenna SS"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_sub_burst_ctype_vals[]=
{
    { 0x00, "2 mini-subchannels adjacent tiles"},
    { 0x01, "2 mini subchannels interleaved tiles"},
    { 0x02, "3 mini subchannels"},
    { 0x03, "6 mini subchannels"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

#if 0
static const value_string wimaxmacphy_ul_sub_burst_feedback_sub_type_vals[]=
{
    { 0, "CQI (CINR) measurement"},
    { 1, "Control feedback"},
    { 0, NULL}
};
#endif

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_ul_sub_burst_sounding_power_assignment_vals[]=
{
    { 0x00, "Equal power"},
    { 0x01, "Reserved"},
    { 0x02, "Interference dependent. Per subcarrier power limit."},
    { 0x03, "Interference dependent. Total power limit."},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_sub_burst_sounding_power_boost_vals[]=
{
    { 0, "no boost"},
    { 1, "boost"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxmacphy_ul_sub_burst_sounding_allocation_mode_vals[]=
{
    { 0, "Normal"},
    { 1, "Band AMC"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxmacphy_ul_sub_burst_mimo_chase_matrix_vals[]=
{
    { 0, "Matrix A"},
    { 1, "Matrix B"},
    { 0,    NULL}
};

static gint dissect_wimaxmacphy_dl_sub_burst_descriptor(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint       start_offset = offset;
    guint8      sub_burst_type;
    proto_tree *subtree;

    sub_burst_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_dl_sub_burst_type,                      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_number,                       tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_symbol_offset,                tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_subchannel_offset,            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_number_of_slots,              tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_reserved1,                    tvb, offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_reserved2,                    tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_modulation_fec_code_type,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_issid,                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_aas_handle,                   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_boosting,                     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_repetition_coding_indication, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_data_length,                  tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* sub-burst-specific parts */
    switch (sub_burst_type)
    {
    case 0x61:  /* HARQ chase combining */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_sub_burst_harq_chase, NULL, "HARQ Chase Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_harq_chase_harq_channel_id,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_harq_chase_harq_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_harq_chase_flush_unnamed,        tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_harq_chase_reserved,             tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case 0x64:  /* MIMO chase combining */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_sub_burst_mimo_chase, NULL, "MIMO Chase Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_mimo_chase_harq_channel_id,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_mimo_chase_harq_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_mimo_chase_flush_unnamed,        tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_mimo_chase_layer_index,          tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    default:
        /* do nothing */
        break;
    }

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_dl_burst_descriptor(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint       start_offset = offset;
    guint8      burst_type, burst_type_extension, sub_burst_descriptor_count, sub_burst;
    proto_item *item;
    proto_tree *subtree, *opt_tree;

    burst_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_dl_burst_type,                      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    burst_type_extension = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_burst_type_extension,               tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_number,                       tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_modulation_fec_code_type,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_data_length,                  tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_ofdma_symbol_offset,          tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_subchannel_offset,            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_boosting,                     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_repetition_coding_indication, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* burst-specific parts */
    switch (burst_type)
    {
    case 0x40:  /* map */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_burst_map, NULL, "MAP Data Burst Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_dl_burst_map_number_of_slots,          tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_dl_burst_map_reserved,                 tvb, offset, 2, ENC_NA);
        offset += 2;
        break;

    case 0x41:  /* normal */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_burst_normal, NULL, "Normal Data Burst Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_dl_burst_normal_number_of_symbols,     tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_dl_burst_normal_number_of_subchannels, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_dl_burst_normal_aas_handle,            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* extensions */
        switch (burst_type_extension)
        {
        case 0x01:  /* AAS v1 */

            opt_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_burst_opt_aas, NULL, "Optional AAS Specific");

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_aas_preamble_modifier_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_aas_preamble_shift_index,   tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_aas_reserved,               tvb, offset, 2, ENC_NA);
            offset += 2;

            /* ??? Algorithm specific Information (per Burst Type extension) */
            break;

        case 0x02:  /* MIMO v1 */

            opt_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_burst_opt_mimo, NULL, "Optional MIMO Specific");

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_mimo_matrix_indicator,      tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_mimo_layer_index,           tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_dl_burst_opt_mimo_reserved,           tvb, offset, 2, ENC_NA);
            offset += 2;


            /* ??? Algorithm specific Information (per Burst Type extension) */
            break;

        default:
            /* do nothing */
            break;
        }

        break;

    case 0x43:  /* PAPR */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_burst_papr, NULL, "PAPR Allocation Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_burst_papr_number_of_symbols,     tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_burst_papr_number_of_subchannels, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_burst_papr_reserved,              tvb, offset, 2, ENC_NA);
        offset += 2;
        break;

    default:
        /* do nothing */
        break;
    }

    /* sub-burst portion */
    sub_burst_descriptor_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_number_of_sub_burst_descriptors, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_padding,               tvb, offset, 3, ENC_NA);
    offset += 3;

    /* sub-burst descriptors */
    for (sub_burst = 0; sub_burst < sub_burst_descriptor_count; ++sub_burst)
    {
        proto_tree *sub_burst_descriptor_tree;
        guint       sub_burst_descriptor_length;

        sub_burst_descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
                 ett_wimaxmacphy_dl_sub_burst_descriptor, &item, "Sub-Burst Descriptor %u", sub_burst);

        sub_burst_descriptor_length = dissect_wimaxmacphy_dl_sub_burst_descriptor(tvb, offset,
            pinfo, sub_burst_descriptor_tree);

        proto_item_set_len(item, sub_burst_descriptor_length);
        offset += sub_burst_descriptor_length;
    }

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_dl_zone_descriptor(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint       start_offset = offset;
    guint8      zone_type, burst_descriptor_count, burst;
    proto_item *item;
    proto_tree *subtree;

    zone_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_dl_zone_type,                          tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_number,                           tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_start_symbol_offset,              tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_end_symbol_offset,                tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_dl_zone_permutation_type,              tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_dl_zone_use_all_subchannels_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_dl_perm_base,                     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_prbs_id,                          tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_dedicated_pilots,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_reserved,                         tvb, offset, 3, ENC_NA);
    offset += 3;

    /* zone-specific parts */
    switch (zone_type)
    {
    case 0x21:  /* STC */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_zone_stc, NULL, "STC Zone Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_stc_type,                  tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_matrix_indicator,          tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_midamble_presence,         tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_midamble_boosting,         tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case 0x22:  /* AAS */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_dl_zone_aas, NULL, "AAS Zone Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_preamble_configuration,    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_sdma_supported_indication, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_dl_zone_aas_reserved,           tvb, offset, 2, ENC_NA);
        offset += 2;

        /* ??? Algorithm Specific Information (per Zone Type) */
        break;

    default:
        /* do nothing */
        break;
    }

    /* burst portion */
    burst_descriptor_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_number_of_burst_descriptors, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_padding,               tvb, offset, 3, ENC_NA);
    offset += 3;

    /* burst descriptors */
    for (burst = 0; burst < burst_descriptor_count; ++burst)
    {
        proto_tree *burst_descriptor_tree;
        guint       burst_descriptor_length;

        /* note: we'll adjust the length later */
        burst_descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
            ett_wimaxmacphy_dl_burst_descriptor, &item, "Burst Descriptor %u", burst);

        burst_descriptor_length = dissect_wimaxmacphy_dl_burst_descriptor(
            tvb, offset, pinfo, burst_descriptor_tree);

        proto_item_set_len(item, burst_descriptor_length);

        offset += burst_descriptor_length;
    }

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_dl_subframe_descriptor(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint  start_offset = offset;
    guint8 zone_descriptor_count;
    guint8 zone;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_subframe_type,          tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_frame_number,           tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_downlink_reserved1,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_phy_sap_version_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_downlink_reserved2,     tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* zone portion */
    zone_descriptor_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_number_of_zone_descriptors,      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_number_of_zone_descriptors,      tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* zone descriptors */
    for (zone = 0; zone < zone_descriptor_count; ++zone)
    {
        proto_item *item;
        proto_tree *zone_descriptor_tree;
        guint zone_descriptor_length;

        zone_descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_wimaxmacphy_dl_zone_descriptor, &item, "Zone Descriptor %u", zone);

        zone_descriptor_length = dissect_wimaxmacphy_dl_zone_descriptor(
            tvb, offset, pinfo, zone_descriptor_tree);

        proto_item_set_len(item, zone_descriptor_length);

        offset += zone_descriptor_length;
    }

    return offset - start_offset;
}

static gint dissect_wimaxmacphy_ul_sub_burst_sub_allocation_specific_part(tvbuff_t *tvb, guint offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 sub_burst_type)
{
    guint       start_offset = offset;
    proto_item *item, *opt_item;
    proto_tree *subtree, *opt_tree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_wimaxmacphy_ul_sub_burst_sub_allocation_specific, &item, "Sub-Allocation Specific");

    proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_symbol_offset,                tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_subchannel_offset,            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_number_of_slots,              tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_data_length,                  tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_repetition_coding_indication, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_modulation_fec_code_type,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(subtree, hf_wimaxmacphy_sub_burst_reserved1,                    tvb, offset, 2, ENC_NA);
    offset += 2;

    /* HARQ chase and MIMO chase specific parts */
    switch (sub_burst_type)
    {
    case 0x61:  /* HARQ chase combining */

        opt_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_sub_burst_harq_chase, &opt_item, "HARQ Chase Specific");

        proto_tree_add_item(opt_tree, hf_wimaxmacphy_sub_burst_harq_chase_harq_channel_id,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(opt_tree, hf_wimaxmacphy_sub_burst_harq_chase_harq_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(opt_tree, hf_wimaxmacphy_sub_burst_harq_chase_flush_unnamed,        tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(opt_tree, hf_wimaxmacphy_sub_burst_harq_chase_reserved,             tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case 0x64:  /* MIMO chase combining */

        opt_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_sub_burst_mimo_chase, NULL, "MIMO Chase Specific");

        proto_tree_add_item(opt_tree, hf_wimaxmacphy_sub_burst_mimo_chase_harq_channel_id,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(opt_tree, hf_wimaxmacphy_sub_burst_mimo_chase_harq_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(opt_tree, hf_wimaxmacphy_sub_burst_mimo_chase_flush_unnamed,        tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(opt_tree, hf_wimaxmacphy_ul_sub_burst_mimo_chase_matrix,            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    default:
        /* do nothing */
        break;
    }

    proto_item_set_len(item, offset - start_offset);

    return offset - start_offset;
}

static gint dissect_wimaxmacphy_ul_sub_burst_descriptor(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint8      sub_burst_type;
    proto_item *feedback_item;
    proto_tree *subtree, *feedback_tree;
    guint       start_offset = offset;

    sub_burst_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_ul_sub_burst_type,    tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_number,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_issid,      tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_aas_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_reserved1,  tvb, offset, 2, ENC_NA);
    offset += 2;

    /* sub-burst-specific parts */
    switch (sub_burst_type)
    {
    case 0x68:  /* mini-subchannel */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_sub_burst_mini_subchannel, NULL, "Mini-Subchannel Allocation Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_ctype,                 tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_mini_subchannel_index, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_mini_reserved,         tvb, offset, 2, ENC_NA);
        offset += 2;
        break;

    case 0x69:  /* fast feedback */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_sub_burst_fast_feedback, NULL, "Fast Feedback Allocation Specific");

        feedback_item = proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding, tvb, offset, 1, ENC_BIG_ENDIAN);
        feedback_tree = proto_item_add_subtree(feedback_item, ett_wimaxmacphy_ul_feedback_type_coding);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit0, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit1, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit2, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit3, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit4, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit5, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit6, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit7, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_feedback_reserved1,   tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_feedback_sub_type,    tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_feedback_cqich_id,    tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_feedback_reserved2,   tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_feedback_slot_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case 0x6a:  /* HARQ ACK */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_sub_burst_harq_ack, NULL, "HARQ ACK Subchannel Allocation Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_harq_ack_acid,     tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_harq_ack_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case 0x6b: /* sounding signal */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 11, ett_wimaxmacphy_ul_sub_burst_sounding_signal, NULL, "Sounding Signal Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_symbol_index,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_power_assignment,  tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_power_boost,       tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_allocation_mode,   tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_start_freq_band,   tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_num_freq_bands,    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_band_bit_map,      tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_cyclic_time_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_decimation_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_sub_burst_sounding_reserved,          tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    default:
        offset += dissect_wimaxmacphy_ul_sub_burst_sub_allocation_specific_part(
            tvb, offset, pinfo, tree, sub_burst_type);
        break;
    }

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_ul_burst_descriptor(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint8      burst_type, burst_type_extension;
    guint8      sub_burst_descriptor_count, sub_burst;
    proto_item *item, *pilot_patterns_item;
    proto_tree *subtree, *opt_tree, *pilot_patterns_tree;
    guint       start_offset = offset;

    burst_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_ul_burst_type,                      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    burst_type_extension = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_burst_type_extension,               tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_number,                       tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_modulation_fec_code_type,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_data_length,                  tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_ofdma_symbol_offset,          tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_subchannel_offset,            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_reserved,                     tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_repetition_coding_indication, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_issid,                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_aas_handle,                   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* burst-specific parts */
    switch (burst_type)
    {
    case 0x40:  /* HARQ ACK channel */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_burst_harq_ack, NULL, "HARQ ACK Channel Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_harq_ack_number_of_symbols,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_harq_ack_number_of_subchannels,  tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_harq_ack_reserved,               tvb, offset, 2, ENC_NA);
        offset += 2;
        break;

    case 0x41:  /* fast feedback channel */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_burst_fast_feedback, NULL, "Fast Feedback Channel Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_fast_number_of_symbols,          tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_fast_number_of_subchannels,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_fast_reserved,                   tvb, offset, 2, ENC_NA);
        offset += 2;
        break;

    case 0x42:  /* initial ranging/handover ranging */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_wimaxmacphy_ul_burst_initial_ranging, NULL, "Initial Ranging/Handover Ranging Allocation Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_initial_number_of_symbols,       tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_initial_number_of_subchannels,   tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_initial_ranging_method,          tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_initial_reserved1,               tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_initial_zone_xid,                tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_initial_reserved2,               tvb, offset, 2, ENC_NA);
        offset += 2;
        break;

    case 0x43:  /* periodic ranging/bandwidth request */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_wimaxmacphy_ul_burst_periodic_ranging, NULL, "Periodic Ranging/Bandwidth Request Allocation Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_periodic_number_of_symbols,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_periodic_number_of_subchannels,  tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_periodic_ranging_method,         tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_periodic_reserved1,              tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_periodic_zone_xid,               tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_periodic_reserved2,              tvb, offset, 2, ENC_NA);
        offset += 2;
        break;

    case 0x44:  /* PAPR/safety zone */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_burst_papr_safety_zone, NULL, "PAPR/Safety Zone Channel Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_burst_papr_number_of_symbols,             tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_burst_papr_number_of_subchannels,         tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_papr_unnamed,                    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_burst_papr_reserved,                      tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case 0x45:  /* sounding zone */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_wimaxmacphy_ul_burst_sounding_zone, NULL, "Sounding Zone Allocation Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_sounding_number_of_symbols,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_sounding_number_of_subchannels,  tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_sounding_type,                   tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_sounding_separability_type,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_sounding_max_cyclic_shift_indx,  tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_sounding_decimation_value,       tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_sounding_decimation_offset_rand, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_sounding_reserved,               tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case 0x46:  /* noise floor calculation */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_burst_noise_floor, NULL, "Noise Floor Calculation Allocation Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_noise_number_of_symbols,         tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_noise_number_of_subchannels,     tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_noise_reserved,                  tvb, offset, 2, ENC_NA);
        offset += 2;
        break;

    case 0x47:  /* normal data */

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_burst_normal_data, NULL, "Normal Data Burst Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_normal_number_of_slots,          tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_burst_normal_reserved,                 tvb, offset, 2, ENC_NA);
        offset += 2;

        /* extensions */
        switch (burst_type_extension)
        {
        case 0x01:  /* AAS v1 */

            opt_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_burst_opt_aas, NULL, "Optional AAS Specific");

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_aas_preamble_modifier_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_aas_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_aas_preamble_shift_index, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            /* ??? Algorithm specific Information (per Burst Type extension) */
            break;

        case 0x02:  /* MIMO v1 */

            opt_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_burst_opt_mimo, NULL, "Optional MIMO Specific");

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_ul_burst_opt_mimo_matrix_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            /* optional MIMO-specific - pilot patterns */
            pilot_patterns_item = proto_tree_add_item(opt_tree, hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns, tvb, offset, 1, ENC_BIG_ENDIAN);
            pilot_patterns_tree = proto_item_add_subtree(pilot_patterns_item, ett_wimaxmacphy_ul_pilot_patterns);
            proto_tree_add_item(pilot_patterns_tree, hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit0, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pilot_patterns_tree, hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit1, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pilot_patterns_tree, hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit2, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pilot_patterns_tree, hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit3, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_ul_burst_opt_mimo_collaborative,   tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_tree, hf_wimaxmacphy_ul_burst_opt_mimo_antenna_unnamed, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(opt_tree, hf_wimaxmacphy_burst_opt_mimo_layer_index,        tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            /* ??? Algorithm specific Information (per Burst Type extension) */
            break;

        default:
            /* do nothing */
            break;
        }

        break;

    default:
        /* do nothing */
        break;
    }

    /* sub-burst portion */
    sub_burst_descriptor_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_number_of_sub_burst_descriptors, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_sub_burst_padding,               tvb, offset, 3, ENC_NA);
    offset += 3;

    /* sub-burst descriptors */
    for (sub_burst = 0; sub_burst < sub_burst_descriptor_count; ++sub_burst)
    {
        proto_tree *sub_burst_descriptor_tree;
        guint       sub_burst_descriptor_length;

        sub_burst_descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_wimaxmacphy_ul_sub_burst_descriptor, &item, "Sub-Burst Descriptor %u", sub_burst);

        sub_burst_descriptor_length = dissect_wimaxmacphy_ul_sub_burst_descriptor(tvb, offset,
                pinfo, sub_burst_descriptor_tree);

        proto_item_set_len(item, sub_burst_descriptor_length);

        offset += sub_burst_descriptor_length;
    }

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_ul_zone_descriptor(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint       start_offset = offset;
    guint8      zone_type, burst_descriptor_count, burst;
    proto_item *item;

    zone_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_ul_zone_type,                             tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_number,                              tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_start_symbol_offset,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_end_symbol_offset,                   tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_ul_zone_permutation_type,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_ul_zone_use_all_subchannels_indicator,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_ul_zone_disable_pusc_subchannel_rotation, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_ul_perm_base,                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_agc_range_extension,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* zone-specific parts */
    switch (zone_type)
    {
    case 0x22:  /* AAS */
    {
        proto_tree *subtree;

        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_ul_zone_aas, NULL, "AAS Zone Specific");

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_preamble_configuration,    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_preamble_type,             tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_zone_sdma_supported_indication, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_ul_zone_aas_reserved,           tvb, offset, 1, ENC_NA);
        offset += 1;

        /* ??? Algorithm Specific Information (per Zone Type) */
        break;
    }
    default:
        /* do nothing */
        break;
    }

    /* burst portion */
    burst_descriptor_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_number_of_burst_descriptors, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_burst_padding,               tvb, offset, 3, ENC_NA);
    offset += 3;

    /* burst descriptors */
    for (burst = 0; burst < burst_descriptor_count; ++burst)
    {
        proto_tree *burst_descriptor_tree;
        guint burst_descriptor_length;

        burst_descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_wimaxmacphy_ul_burst_descriptor, &item, "Burst Descriptor %u", burst);

        burst_descriptor_length = dissect_wimaxmacphy_ul_burst_descriptor(
            tvb, offset, pinfo, burst_descriptor_tree);
        proto_item_set_len(item, burst_descriptor_length);

        offset += burst_descriptor_length;
    }

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_ul_subframe_descriptor(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint  start_offset = offset;
    guint8 zone_descriptor_count;
    guint8 zone;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_subframe_type,          tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_frame_number,           tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_downlink_reserved1,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_phy_sap_version_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_subframe_allocation_start_time,  tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    zone_descriptor_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_number_of_zone_descriptors,      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_zone_padding,                    tvb, offset, 3, ENC_NA);
    offset += 3;

    /* -----------------------------------------------------------------------
     * zone descriptors
     * -----------------------------------------------------------------------
     */

    for (zone = 0; zone < zone_descriptor_count; ++zone)
    {
        proto_item *item;
        proto_tree *zone_descriptor_tree;
        guint zone_descriptor_length;

        zone_descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_wimaxmacphy_ul_zone_descriptor, &item, "Zone Descriptor %u", zone);

        zone_descriptor_length = dissect_wimaxmacphy_ul_zone_descriptor(
            tvb, offset, pinfo, zone_descriptor_tree);

        proto_item_set_len(item, zone_descriptor_length);
        offset += zone_descriptor_length;
    }

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_phy_txstart_request(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 txvector_length;
    guint   subframe_descriptor_length;

    txvector_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_length_of_txvector, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    subframe_descriptor_length = dissect_wimaxmacphy_dl_subframe_descriptor(
        tvb, offset, pinfo, tree);

    offset += subframe_descriptor_length;

    if (subframe_descriptor_length < txvector_length)
        proto_tree_add_item(tree, hf_wimaxmacphy_unknown, tvb, offset, txvector_length - subframe_descriptor_length, ENC_NA);

    return txvector_length + 2;
}

static guint dissect_wimaxmacphy_phy_txstart_confirmation(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_status,            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved2,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_next_frame_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* offset += 1; */

    return 2;
}

static guint dissect_wimaxmacphy_phy_txstart_indication(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_txstart_indication_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_extended_frame_number,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_current_frame_number_lsn,  tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved1,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_initial_frame_number,      tvb, offset, 3, ENC_BIG_ENDIAN);
    /* offset += 3; */

    return 6;
}

static guint dissect_wimaxmacphy_phy_txsdu_request(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint length;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_dl_zone_number,              tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_sub_burst_burst_split_point, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_dl_sub_burst_burst_number,   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    length = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_phy_sdu,                     tvb, offset, length, ENC_NA);

    return length + 2;
}

static guint dissect_wimaxmacphy_phy_txsdu_confirmation(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_dl_zone_number,              tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_sub_burst_burst_split_point, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_dl_sub_burst_burst_number,   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved5,                   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_status,                      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved2,                   tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_next_frame_number,           tvb, offset, 1, ENC_BIG_ENDIAN);
    /* offset += 1; */

    return 6;
}

static guint dissect_wimaxmacphy_phy_txend_indication(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_status,                                tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_phy_request,                           tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_current_frame_number_lsn,              tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_requested_aas_calibration_zone_size,   tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_requested_aas_calibration_zone_alloc,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_number_of_consecutive_frames_with_aas, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved5,                             tvb, offset, 2, ENC_BIG_ENDIAN);
    /* offset += 2; */

    return 6;
}

static guint dissect_wimaxmacphy_phy_rxstart_request(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 rxvector_length;
    guint   subframe_descriptor_length;

    rxvector_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_length_of_rxvector, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    subframe_descriptor_length = dissect_wimaxmacphy_ul_subframe_descriptor(
        tvb, offset, pinfo, tree);

    offset += subframe_descriptor_length;

    /* check for unprocessed bytes */
    if (subframe_descriptor_length < rxvector_length)
        proto_tree_add_item(tree, hf_wimaxmacphy_unknown, tvb, offset, rxvector_length - subframe_descriptor_length, ENC_NA);

    return rxvector_length + 2;
}

static guint dissect_wimaxmacphy_phy_rxstart_confirmation(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_status,       tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved2,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_frame_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* offset += 1; */

    return 2;
}

static guint dissect_wimaxmacphy_phy_rxstart_indication(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_status,                   tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved2,                tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_current_frame_number_lsn, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* offset += 1; */

    return 2;
}

static guint dissect_wimaxmacphy_phy_rxsdu_indication(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint8      indication_type;
    proto_item *feedback_item;
    proto_tree *subtree, *feedback_tree;
    guint       length, start_offset = offset;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_issid,                     tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_integrity,                 tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_number_of_bytes_received,  tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_rssi_per_subcarrier_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_cinr,                      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved1,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_power_offset,              tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_current_frame_number_msn,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_acid_for_harq_data_bursts, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    indication_type = (tvb_get_guint8(tvb, offset) >> 4) & 0x0F;
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_indication_type,           tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_zone_permutation_type,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_update_aas_handle_in_mac,  tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_aas_handle,                tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_time_deviation,            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_frequency_deviation,       tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    switch (indication_type)
    {
    case 0:  /* data burst */
    {
        length = tvb_reported_length_remaining(tvb, offset);
        proto_tree_add_item(tree, hf_wimaxmacphy_prim_phy_sdu, tvb, offset, length, ENC_NA);
        offset += length;
        break;
    }
    case 1:  /* HARQ ACK */
    {
        subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_wimaxmacphy_prim_harq_ack, NULL, "HARQ ACK channel data format");

        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_harq_ack_issid,     tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_harq_ack_acid,      tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_harq_ack_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_harq_ack_ack_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_harq_ack_unnamed,   tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_harq_ack_reserved2, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
    }
    case 2:  /* fast feedback */
    {
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_wimaxmacphy_prim_harq_ack, NULL, "Fast Feedback channel data format");

        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_fast_issid,                                tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_fast_cqich_id,                             tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        feedback_item = proto_tree_add_item(subtree, hf_wimaxmacphy_prim_fast_feedback_type_coding, tvb, offset, 1, ENC_BIG_ENDIAN);
        feedback_tree = proto_item_add_subtree(feedback_item, ett_wimaxmacphy_prim_fast_feedback_type_coding);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_prim_fast_feedback_type_coding_bit0,      tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_prim_fast_feedback_type_coding_bit1,      tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_prim_fast_feedback_type_coding_bit2,      tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_prim_fast_feedback_type_coding_bit3,      tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_prim_fast_feedback_type_coding_bit4,      tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_prim_fast_feedback_type_coding_bit5,      tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_prim_fast_feedback_type_coding_bit6,      tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feedback_tree, hf_wimaxmacphy_prim_fast_feedback_type_coding_bit7,      tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_fast_feedback_valid,                       tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_fast_feedback_sub_type,                    tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_fast_reserved,                             tvb, offset, 2, ENC_NA);
        offset += 2;

        proto_tree_add_item(subtree, hf_wimaxmacphy_prim_fast_feedback_value,                       tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
    }
    default:
        break;
    }

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_phy_rxend_indication(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint start_offset = offset;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_status,                   tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_phy_aas_report_present,   tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_current_frame_number_lsn, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_number_of_affected_ss,    tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved1,                tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    do
    {
        /* list of ISSIDs (at least one required) */
        proto_tree_add_item(tree, hf_wimaxmacphy_prim_issid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    while (tvb_reported_length_remaining(tvb, offset));

    return offset - start_offset;
}

static guint dissect_wimaxmacphy_phy_rxcdma_indication(tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint start_offset = offset;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_zonexid,                   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_cdma_code,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_cdma_symbol,               tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved1,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_cdma_subchannel,           tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_rssi_per_subcarrier_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_cinr,                      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved3,                 tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_power_offset,              tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_current_frame_number_msn,  tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wimaxmacphy_prim_reserved4,                 tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_aas_handle,                tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_time_deviation,            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_wimaxmacphy_prim_frequency_deviation,       tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset - start_offset;
}

static int
dissect_wimaxmacphy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_tree *wimaxmacphy_tree, *primitive_tree;
    proto_item *item;

    guint  offset = 0;
    guint8 message_type;

    /* Ensure minimum size */
    if (tvb_reported_length(tvb) < WIMAXMACPHY_HEADER_SIZE)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "wimaxmacphy");
    col_clear(pinfo->cinfo, COL_INFO);

    item = proto_tree_add_item(tree, proto_wimaxmacphy, tvb, 0, -1, ENC_NA);
    wimaxmacphy_tree = proto_item_add_subtree(item, ett_wimaxmacphy);

    proto_tree_add_item(wimaxmacphy_tree, hf_wimaxmacphy_hdr_phy_entity_id,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(wimaxmacphy_tree, hf_wimaxmacphy_hdr_message_segmentation,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    message_type = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_item(wimaxmacphy_tree, hf_wimaxmacphy_hdr_message_type,
                               tvb, offset, 1, ENC_BIG_ENDIAN);

    primitive_tree = proto_item_add_subtree(item, ett_wimaxmacphy_primitive);
#if 0
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(message_type, &wimaxmacphy_message_type_vals_ext, "Unknown"));
#endif
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_type, wimaxmacphy_message_type_vals, "Unknown"));
    offset += 1;

    switch(message_type)
    {
    case WIMAXMACPHY_PHY_TXSTART_REQUEST:
        offset += dissect_wimaxmacphy_phy_txstart_request(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_TXSTART_CONFIRMATION:
        offset += dissect_wimaxmacphy_phy_txstart_confirmation(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_TXSTART_INDICATION:
        offset += dissect_wimaxmacphy_phy_txstart_indication(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_TXSDU_REQUEST:
        offset += dissect_wimaxmacphy_phy_txsdu_request(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_TXSDU_CONFIRMATION:
        offset += dissect_wimaxmacphy_phy_txsdu_confirmation(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_TXEND_INDICATION:
        offset += dissect_wimaxmacphy_phy_txend_indication(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_RXSTART_REQUEST:
        offset += dissect_wimaxmacphy_phy_rxstart_request(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_RXSTART_CONFIRMATION:
        offset += dissect_wimaxmacphy_phy_rxstart_confirmation(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_RXSTART_INDICATION:
        offset += dissect_wimaxmacphy_phy_rxstart_indication(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_RXSDU_INDICATION:
        offset += dissect_wimaxmacphy_phy_rxsdu_indication(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_RXEND_INDICATION:
        offset += dissect_wimaxmacphy_phy_rxend_indication(
            tvb, offset, pinfo, primitive_tree);
        break;
    case WIMAXMACPHY_PHY_RXCDMA_INDICATION:
        offset += dissect_wimaxmacphy_phy_rxcdma_indication(
            tvb, offset, pinfo, primitive_tree);
        break;
    default:
        proto_tree_add_item(primitive_tree, hf_wimaxmacphy_unknown,
                            tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_reported_length_remaining(tvb, offset);
        break;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        /* Incorporate any "extra" bytes */
        item = proto_tree_add_item(wimaxmacphy_tree, hf_wimaxmacphy_unknown,
                                   tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);

        expert_add_info(pinfo, item, &ei_wimaxmacphy_unknown);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_wimaxmacphy(void)
{
    module_t *wimaxmacphy_module;

    static hf_register_info hf[] = {
            {
                &hf_wimaxmacphy_hdr_phy_entity_id,
                {
                    "PHY entity ID",
                    "wimaxmacphy.hdr_phy_entity_id",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0xfc,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_hdr_message_segmentation,
                {
                    "Message Segmentation",
                    "wimaxmacphy.hdr_message_segmentation",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_message_segmentation_vals),
                    0x03,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_hdr_message_type,
                {
                    "Message Type",
                    "wimaxmacphy.hdr_message_type",
                    FT_UINT8,
#if 0
                    BASE_HEX | BASE_EXT_STRING,
                    &wimaxmacphy_message_type_vals_ext,
#endif
                    BASE_HEX,
                    VALS(wimaxmacphy_message_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_unknown,
                {
                    "Unknown(!)",
                    "wimaxmacphy.unknown_primitive",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_length_of_txvector,
                {
                    "Length of TXVECTOR",
                    "wimaxmacphy.prim_length_of_txvector",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_length_of_rxvector,
                {
                    "Length of RXVECTOR",
                    "wimaxmacphy.prim_length_of_rxvector",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_status,
                {
                    "Status",
                    "wimaxmacphy.prim_status",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_prim_status_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_txstart_indication_status,
                {
                    "Status",
                    "wimaxmacphy.prim_status",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_prim_txstart_indication_status_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_reserved1,
                {
                    "Reserved",
                    "wimaxmacphy.prim_reserved1",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_reserved2,
                {
                    "Reserved",
                    "wimaxmacphy.prim_reserved2",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0xF0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_reserved3,
                {
                    "Reserved",
                    "wimaxmacphy.prim_reserved3",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_reserved4,
                {
                    "Reserved",
                    "wimaxmacphy.prim_reserved4",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0FFF,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_reserved5,
                {
                    "Reserved",
                    "wimaxmacphy.prim_reserved5",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_next_frame_number,
                {
                    "Next Frame Number (lsb)",
                    "wimaxmacphy.prim_next_frame_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_extended_frame_number,
                {
                    "Extended frame number",
                    "wimaxmacphy.prim_extended_frame_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_current_frame_number_lsn,
                {
                    "Current Frame Number (lsb)",
                    "wimaxmacphy.prim_current_frame_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0f,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_initial_frame_number,
                {
                    "Initial Frame Number (from PHY)",
                    "wimaxmacphy.prim_initial_frame_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_dl_zone_number,
                {
                    "DL zone number",
                    "wimaxmacphy.prim_dl_zone_number",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0xe000,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_sub_burst_burst_split_point,
                {
                    "Sub-burst/burst split point",
                    "wimaxmacphy.prim_sub_burst_burst_split_point",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x1c00,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_dl_sub_burst_burst_number,
                {
                    "DL sub-burst/burst number in this zone",
                    "wimaxmacphy.prim_dl_sub_burst_burst_number",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x03ff,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_phy_sdu,
                {
                    "PHY SDU",
                    "wimaxmacphy.prim_phy_sdu",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_phy_request,
                {
                    "PHY request (LW 1)",
                    "wimaxmacphy.prim_phy_request",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_requested_aas_calibration_zone_size,
                {
                    "Requested AAS Calibration Zone size",
                    "wimaxmacphy.prim_requested_aas_calibration_zone_size",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_requested_aas_calibration_zone_alloc,
                {
                    "Requested AAS Calibration Zone allocation deadline",
                    "wimaxmacphy.prim_requested_aas_calibration_zone_alloc",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_number_of_consecutive_frames_with_aas,
                {
                    "Number of consecutive frames with AAS Calibration Zone"
                    " allocation",
                    "wimaxmacphy.prim_number_of_consecutive_frames_with_aas",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0f,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_frame_number,
                {
                    "Frame Number (lsb)",
                    "wimaxmacphy.prim_frame_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0f,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_issid,
                {
                    "ISSID",
                    "wimaxmacphy.prim_issid",
                    FT_INT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_integrity,
                {
                    "Integrity",
                    "wimaxmacphy.prim_integrity",
                    FT_UINT32,
                    BASE_DEC,
                    VALS(wimaxmacphy_prim_integrity_vals),
                    0x80000000,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_number_of_bytes_received,
                {
                    "Number of bytes received",
                    "wimaxmacphy.prim_number_of_bytes_received",
                    FT_UINT32,
                    BASE_DEC,
                    NULL,
                    0x7fffffff,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_rssi_per_subcarrier_level,
                {
                    "RSSI per subcarrier level",
                    "wimaxmacphy.prim_rssi_per_subcarrier_level",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_cinr,
                {
                    "CINR",
                    "wimaxmacphy.prim_cinr",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_power_offset,
                {
                    "Power Offset",
                    "wimaxmacphy.prim_power_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_current_frame_number_msn,
                {
                    "Current Frame Number (lsb)",
                    "wimaxmacphy.prim_current_frame_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_acid_for_harq_data_bursts,
                {
                    "ACID for HARQ data bursts",
                    "wimaxmacphy.prim_acid_for_harq_data_bursts",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0f,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_indication_type,
                {
                    "Indication Type",
                    "wimaxmacphy.prim_indication_type",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_prim_indication_type_vals),
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_zone_permutation_type,
                {
                    "Zone Permutation Type",
                    "wimaxmacphy.prim_zone_permutation_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_prim_zone_permutation_type_vals),
                    0x0e,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_update_aas_handle_in_mac,
                {
                    "Update AAS handle in MAC",
                    "wimaxmacphy.prim_update_aas_handle_in_mac",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_aas_handle,
                {
                    "AAS Handle",
                    "wimaxmacphy.prim_aas_handle",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_time_deviation,
                {
                    "Time deviation in units of 1/Fs",
                    "wimaxmacphy.prim_time_deviation",
                    FT_INT32,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_frequency_deviation,
                {
                    "Frequency deviation in Hz",
                    "wimaxmacphy.prim_frequency_deviation",
                    FT_INT32,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_harq_ack_issid,
                {
                    "ISSID",
                    "wimaxmacphy.prim_harq_ack_issid",
                    FT_INT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_harq_ack_acid,
                {
                    "ACID",
                    "wimaxmacphy.prim_harq_ack_acid",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_harq_ack_reserved1,
                {
                    "Reserved",
                    "wimaxmacphy.prim_harq_ack_reserved1",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x0c,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_harq_ack_ack_valid,
                {
                    "ACK Valid",
                    "wimaxmacphy.prim_harq_ack_ack_valid",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_prim_harq_ack_ack_valid_vals),
                    0x2,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_harq_ack_unnamed,
                {
                    "Unnamed",
                    "wimaxmacphy.prim_harq_ack_unnamed",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_prim_harq_ack_unnamed_vals),
                    0x1,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_harq_ack_reserved2,
                {
                    "Reserved",
                    "wimaxmacphy.prim_harq_ack_reserved2",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_issid,
                {
                    "ISSID",
                    "wimaxmacphy.prim_fast_issid",
                    FT_INT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_cqich_id,
                {
                    "CQICH_ID",
                    "wimaxmacphy.prim_fast_cqich_id",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding,
                {
                    "Feedback type coding",
                    "wimaxmacphy.prim_fast_type_coding",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding_bit0,
                {
                    "3 bit-MIMO Fast-feedback",
                    "wimaxmacphy.prim_fast_type_coding.bit0",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x01,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding_bit1,
                {
                    "Enhanced FAST_FEEDBACK",
                    "wimaxmacphy.prim_fast_type_coding.bit1",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x02,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding_bit2,
                {
                    "Reserved",
                    "wimaxmacphy.prim_fast_type_coding.bit2",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x04,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding_bit3,
                {
                    "Reserved",
                    "wimaxmacphy.prim_fast_type_coding.bit3",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x08,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding_bit4,
                {
                    "UEP fast-feedback",
                    "wimaxmacphy.prim_fast_type_coding.bit4",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x10,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding_bit5,
                {
                    "A measurement report performed on the last DL burst",
                    "wimaxmacphy.prim_fast_type_coding.bit5",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x20,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding_bit6,
                {
                    "Primary/Secondary FAST_FEEDBACK",
                    "wimaxmacphy.prim_fast_type_coding.bit6",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x40,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_type_coding_bit7,
                {
                    "DIUC-CQI Fast-feedback",
                    "wimaxmacphy.prim_fast_type_coding.bit7",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x80,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_valid,
                {
                    "Feedback Valid",
                    "wimaxmacphy.prim_fast_feedback_valid",
                    FT_UINT16,
                    BASE_DEC,
                    VALS(wimaxmacphy_prim_fast_feedback_valid_vals),
                    0x8000,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_sub_type,
                {
                    "Feedback sub-type",
                    "wimaxmacphy.prim_fast_feedback_sub_type",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(
                        wimaxmacphy_prim_fast_feedback_sub_type_vals),
                    0x7000,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.prim_fast_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_fast_feedback_value,
                {
                    "Feedback value",
                    "wimaxmacphy.prim_fast_feedback_value",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_phy_aas_report_present,
                {
                    "PHY AAS report present",
                    "wimaxmacphy.prim_phy_aas_report_present",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_prim_phy_aas_report_present_vals),
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_number_of_affected_ss,
                {
                    "Number of affected SS",
                    "wimaxmacphy.prim_number_of_affected_ss",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_zonexid,
                {
                    "ZoneXID",
                    "wimaxmacphy.prim_zonexid",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_cdma_code,
                {
                    "CDMA code",
                    "wimaxmacphy.prim_cdma_code",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_cdma_symbol,
                {
                    "CDMA symbol",
                    "wimaxmacphy.prim_cdma_symbol",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_prim_cdma_subchannel,
                {
                    "CDMA subchannel",
                    "wimaxmacphy.prim_cdma_subchannel",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_subframe_subframe_type,
                {
                    "Subframe Type",
                    "wimaxmacphy.subframe_subframe_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_subframe_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_subframe_frame_number,
                {
                    "Frame Number",
                    "wimaxmacphy.subframe_frame_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_subframe_downlink_reserved1,
                {
                    "Reserved",
                    "wimaxmacphy.subframe_downlink_reserved1",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_subframe_phy_sap_version_number,
                {
                    "PHY SAP version number",
                    "wimaxmacphy.subframe_phy_sap_version_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_subframe_downlink_reserved2,
                {
                    "Downlink reserved",
                    "wimaxmacphy.subframe_downlink_reserved2",
                    FT_UINT32,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_subframe_allocation_start_time,
                {
                    "Allocation start time",
                    "wimaxmacphy.subframe_allocation_start_time",
                    FT_UINT32,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_number_of_zone_descriptors,
                {
                    "Number of Zone Descriptors",
                    "wimaxmacphy.number_of_zone_descriptors",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_padding,
                {
                    "Padding",
                    "wimaxmacphy.zone_padding",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_zone_type,
                {
                    "Zone Type",
                    "wimaxmacphy.zone_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_dl_zone_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_zone_type,
                {
                    "Zone Type",
                    "wimaxmacphy.zone_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_ul_zone_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_number,
                {
                    "Zone Number",
                    "wimaxmacphy.zone_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_start_symbol_offset,
                {
                    "Start Symbol Offset",
                    "wimaxmacphy.zone_start_symbol_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_end_symbol_offset,
                {
                    "End Symbol Offset",
                    "wimaxmacphy.zone_end_symbol_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_zone_permutation_type,
                {
                    "Permutation Type",
                    "wimaxmacphy.zone_permutation_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_dl_zone_permutation_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_zone_permutation_type,
                {
                    "Permutation Type",
                    "wimaxmacphy.zone_permutation_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_ul_zone_permutation_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_zone_use_all_subchannels_indicator,
                {
                    "Use all subchannels indicator",
                    "wimaxmacphy.zone_use_all_subchannels_indicator",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_zone_use_all_subchannels_indicator_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_zone_use_all_subchannels_indicator,
                {
                    "Use all subchannels indicator",
                    "wimaxmacphy.zone_use_all_subchannels_indicator",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_zone_use_all_subchannels_indicator_vals),
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_zone_disable_pusc_subchannel_rotation,
                {
                    "Disable PUSC subchannel rotation",
                    "wimaxmacphy.zone_disable_pusc_subchannel_rotation",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(
                    wimaxmacphy_ul_zone_disable_pusc_subchannel_rotation_vals),
                    0x0f,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_dl_perm_base,
                {
                    "DL_PermBase",
                    "wimaxmacphy.zone_dl_perm_base",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_ul_perm_base,
                {
                    "UL_PermBase",
                    "wimaxmacphy.zone_ul_perm_base",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_prbs_id,
                {
                    "PRBS_ID",
                    "wimaxmacphy.zone_prbs_id",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_dedicated_pilots,
                {
                    "Dedicated pilots",
                    "wimaxmacphy.zone_dedicated_pilots",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_zone_dedicated_pilots_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_agc_range_extension,
                {
                    "Rx AGC range extension",
                    "wimaxmacphy.zone_agc_range_extension",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_zone_agc_range_extension_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.zone_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_stc_type,
                {
                    "STC type",
                    "wimaxmacphy.zone_stc_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_zone_stc_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_matrix_indicator,
                {
                    "Matrix Indicator",
                    "wimaxmacphy.zone_matrix_indicator",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_matrix_indicator_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_midamble_presence,
                {
                    "Midamble presence",
                    "wimaxmacphy.zone_midamble_presence",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_zone_midamble_presence_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_midamble_boosting,
                {
                    "Midamble boosting",
                    "wimaxmacphy.zone_midamble_boosting",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_zone_midamble_boosting_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_preamble_configuration,
                {
                    "Preamble configuration",
                    "wimaxmacphy.zone_preamble_configuration",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_zone_preamble_configuration_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_sdma_supported_indication,
                {
                    "SDMA supported indication",
                    "wimaxmacphy.zone_sdma_supported_indication",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_zone_sdma_supported_indication_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_zone_preamble_type,
                {
                    "Preamble type",
                    "wimaxmacphy.zone_preamble_type",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_zone_preamble_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_zone_aas_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.zone_aas_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_zone_aas_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.zone_aas_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_number_of_burst_descriptors,
                {
                    "Number of Burst Descriptors",
                    "wimaxmacphy.number_of_burst_descriptors",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_padding,
                {
                    "Padding",
                    "wimaxmacphy.burst_padding",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_burst_type,
                {
                    "Burst Type",
                    "wimaxmacphy.burst_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_dl_burst_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_type,
                {
                    "Burst Type",
                    "wimaxmacphy.dl_burst_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_ul_burst_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_type_extension,
                {
                    "Burst Type extension",
                    "wimaxmacphy.burst_type_extension",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_burst_type_extension_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_number,
                {
                    "Burst Number",
                    "wimaxmacphy.burst_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_modulation_fec_code_type,
                {
                    "Modulation/FEC Code Type",
                    "wimaxmacphy.burst_modulation_fec_code_type",
                    FT_UINT8,
#if 0
                    BASE_DEC | BASE_EXT_STRING,
                    &wimaxmacphy_modulation_fec_code_type_vals_ext,
#endif
                    BASE_DEC,
                    VALS(wimaxmacphy_modulation_fec_code_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_data_length,
                {
                    "Burst Data Length",
                    "wimaxmacphy.burst_data_length",
                    FT_UINT32,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_ofdma_symbol_offset,
                {
                    "OFDMA Symbol offset",
                    "wimaxmacphy.burst_ofdma_symbol_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_subchannel_offset,
                {
                    "Subchannel offset",
                    "wimaxmacphy.burst_subchannel_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_boosting,
                {
                    "Boosting",
                    "wimaxmacphy.burst_boosting",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_burst_boosting_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_repetition_coding_indication,
                {
                    "Repetition coding indication",
                    "wimaxmacphy.burst_repetition_coding_indication",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_burst_repetition_coding_indication_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_issid,
                {
                    "ISSID",
                    "wimaxmacphy.burst_issid",
                    FT_INT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_aas_handle,
                {
                    "AAS Handle",
                    "wimaxmacphy.burst_aas_handle",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_burst_map_number_of_slots,
                {
                    "Number of slots (duration) after repetition code is"
                    " applied",
                    "wimaxmacphy.burst_map_number_of_slots",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_burst_map_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_map_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_burst_normal_number_of_symbols,
                {
                    "Number of Symbols",
                    "wimaxmacphy.burst_normal_number_of_symbols",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_burst_normal_number_of_subchannels,
                {
                    "Number of Subchannels",
                    "wimaxmacphy.burst_normal_number_of_subchannels",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_burst_normal_aas_handle,
                {
                    "AAS Handle",
                    "wimaxmacphy.burst_normal_aas_handle",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_normal_number_of_slots,
                {
                    "Number of slots",
                    "wimaxmacphy.burst_normal_number_of_slots",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_normal_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_normal_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_papr_number_of_symbols,
                {
                    "Number of Symbols",
                    "wimaxmacphy.burst_papr_number_of_symbols",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_papr_number_of_subchannels,
                {
                    "Number of Subchannels",
                    "wimaxmacphy.burst_papr_number_of_subchannels",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_papr_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_papr_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_papr_unnamed,
                {
                    "Unnamed",
                    "wimaxmacphy.burst_papr_unnamed",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_burst_papr_unnamed_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_harq_ack_number_of_symbols,
                {
                    "Number of Symbols",
                    "wimaxmacphy.burst_harq_ack_number_of_symbols",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_harq_ack_number_of_subchannels,
                {
                    "Number of Subchannels",
                    "wimaxmacphy.burst_harq_ack_number_of_subchannels",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_harq_ack_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_harq_ack_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_fast_number_of_symbols,
                {
                    "Number of Symbols",
                    "wimaxmacphy.burst_fast_number_of_symbols",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_fast_number_of_subchannels,
                {
                    "Number of Subchannels",
                    "wimaxmacphy.burst_fast_number_of_subchannels",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_fast_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_fast_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_initial_number_of_symbols,
                {
                    "Number of Symbols",
                    "wimaxmacphy.burst_initial_number_of_symbols",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_initial_number_of_subchannels,
                {
                    "Number of Subchannels",
                    "wimaxmacphy.burst_initial_number_of_subchannels",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_initial_ranging_method,
                {
                    "Ranging method",
                    "wimaxmacphy.burst_initial_ranging_method",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_burst_ranging_method_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_initial_reserved1,
                {
                    "Reserved",
                    "wimaxmacphy.burst_initial_reserved1",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_initial_zone_xid,
                {
                    "Zone XID",
                    "wimaxmacphy.burst_initial_zone_xid",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_initial_reserved2,
                {
                    "Reserved",
                    "wimaxmacphy.burst_initial_reserved2",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_periodic_number_of_symbols,
                {
                    "Number of Symbols",
                    "wimaxmacphy.burst_periodic_number_of_symbols",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_periodic_number_of_subchannels,
                {
                    "Number of Subchannels",
                    "wimaxmacphy.burst_periodic_number_of_subchannels",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_periodic_ranging_method,
                {
                    "Ranging method",
                    "wimaxmacphy.burst_periodic_ranging_method",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_burst_ranging_method_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_periodic_reserved1,
                {
                    "Reserved",
                    "wimaxmacphy.burst_periodic_reserved1",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_periodic_zone_xid,
                {
                    "Zone XID",
                    "wimaxmacphy.burst_periodic_zone_xid",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_periodic_reserved2,
                {
                    "Reserved",
                    "wimaxmacphy.burst_periodic_reserved2",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_noise_number_of_symbols,
                {
                    "Number of Symbols",
                    "wimaxmacphy.burst_noise_number_of_symbols",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_noise_number_of_subchannels,
                {
                    "Number of Subchannels",
                    "wimaxmacphy.burst_noise_number_of_subchannels",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_noise_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_noise_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_sounding_number_of_symbols,
                {
                    "Number of Symbols",
                    "wimaxmacphy.burst_sounding_number_of_symbols",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_sounding_number_of_subchannels,
                {
                    "Number of Subchannels",
                    "wimaxmacphy.burst_sounding_number_of_subchannels",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_sounding_type,
                {
                    "Sounding type",
                    "wimaxmacphy.burst_sounding_type",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_burst_sounding_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_sounding_separability_type,
                {
                    "Separability type",
                    "wimaxmacphy.burst_sounding_separability_type",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_burst_sounding_separability_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_sounding_max_cyclic_shift_indx,
                {
                    "Max Cyclic Shift Indx",
                    "wimaxmacphy.burst_sounding_max_cyclic_shift_indx",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(
                     wimaxmacphy_ul_burst_sounding_max_cyclic_shift_indx_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_sounding_decimation_value,
                {
                    "Decimation value",
                    "wimaxmacphy.burst_sounding_decimation_value",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_sounding_decimation_offset_rand,
                {
                    "Decimation offset randomization",
                    "wimaxmacphy.burst_sounding_decimation_offset_rand",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(
                    wimaxmacphy_ul_burst_sounding_decimation_offset_rand_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_sounding_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_sounding_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_opt_aas_preamble_modifier_type,
                {
                    "Preamble Modifier Type",
                    "wimaxmacphy.burst_opt_aas_preamble_modifier_type",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_opt_aas_preamble_shift_index,
                {
                    "Preamble Shift index",
                    "wimaxmacphy.burst_opt_aas_preamble_shift_index",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_opt_aas_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_opt_aas_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_opt_mimo_matrix_indicator,
                {
                    "Matrix indicator",
                    "wimaxmacphy.burst_opt_mimo_matrix_indicator",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_matrix_indicator_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_burst_opt_mimo_layer_index,
                {
                    "Layer index",
                    "wimaxmacphy.burst_opt_mimo_layer_index",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_burst_opt_mimo_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.burst_opt_mimo_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_opt_mimo_matrix_indicator,
                {
                    "Matrix indicator (dual antenna SS)",
                    "wimaxmacphy.burst_opt_mimo_matrix_indicator",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_ul_burst_opt_mimo_matrix_indicator_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns,
                {
                    "Pilot patterns",
                    "wimaxmacphy.burst_opt_mimo_pilot_patterns",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit0,
                {
                    "Pattern A",
                    "wimaxmacphy.burst_opt_mimo_pilot_patterns.A",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x01,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit1,
                {
                    "Pattern B",
                    "wimaxmacphy.burst_opt_mimo_pilot_patterns.B",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x02,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit2,
                {
                    "Pattern C",
                    "wimaxmacphy.burst_opt_mimo_pilot_patterns.C",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x04,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_opt_mimo_pilot_patterns_bit3,
                {
                    "Pattern D",
                    "wimaxmacphy.burst_opt_mimo_pilot_patterns.D",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x08,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_opt_mimo_collaborative,
                {
                    "Collaborative MIMO control",
                    "wimaxmacphy.burst_opt_mimo_collaborative",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_burst_opt_mimo_collaborative_vals),
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_burst_opt_mimo_antenna_unnamed,
                {
                    "Antenna(?)",
                    "wimaxmacphy.burst_opt_mimo_antenna_unnamed",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_burst_opt_mimo_antenna_unnamed_vals),
                    0x0f,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_number_of_sub_burst_descriptors,
                {
                    "Number of Sub-Burst Descriptors",
                    "wimaxmacphy.number_of_sub_burst_descriptors",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_padding,
                {
                    "Padding",
                    "wimaxmacphy.sub_burst_padding",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_dl_sub_burst_type,
                {
                    "Sub-Burst Type",
                    "wimaxmacphy.sub_burst_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_dl_sub_burst_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_type,
                {
                    "Sub-Burst Type",
                    "wimaxmacphy.sub_burst_type",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_ul_sub_burst_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_number,
                {
                    "Sub-Burst number",
                    "wimaxmacphy.sub_burst_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_symbol_offset,
                {
                    "Symbol Offset",
                    "wimaxmacphy.sub_burst_symbol_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_subchannel_offset,
                {
                    "Subchannel Offset",
                    "wimaxmacphy.sub_burst_subchannel_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_number_of_slots,
                {
                    "Number of slots in this sub-burst",
                    "wimaxmacphy.sub_burst_number_of_slots",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_reserved1,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_reserved1",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_reserved2,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_reserved2",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_modulation_fec_code_type,
                {
                    "Modulation/FEC Code Type",
                    "wimaxmacphy.sub_burst_modulation_fec_code_type",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_modulation_fec_code_type_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_issid,
                {
                    "ISSID",
                    "wimaxmacphy.sub_burst_issid",
                    FT_INT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_aas_handle,
                {
                    "AAS Handle",
                    "wimaxmacphy.sub_burst_aas_handle",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_boosting,
                {
                    "Boosting",
                    "wimaxmacphy.sub_burst_boosting",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_burst_boosting_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_repetition_coding_indication,
                {
                    "Repetition coding indication",
                    "wimaxmacphy.sub_burst_repetition_coding_indication",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_burst_repetition_coding_indication_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_data_length,
                {
                    "Sub-Burst Data Length",
                    "wimaxmacphy.sub_burst_data_length",
                    FT_UINT32,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_harq_chase_harq_channel_id,
                {
                    "HARQ channeld id (ACID)",
                    "wimaxmacphy.sub_burst_harq_chase_harq_channel_id",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_harq_chase_harq_sequence_number,
                {
                    "HARQ sequence number (AI_SN)",
                    "wimaxmacphy.sub_burst_harq_chase_harq_sequence_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_harq_chase_flush_unnamed,
                {
                    "Flush(?)",
                    "wimaxmacphy.sub_burst_harq_chase_flush_unnamed",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_sub_burst_flush_unnamed_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_harq_chase_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_harq_chase_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_mimo_chase_harq_channel_id,
                {
                    "HARQ channel id (ACID)",
                    "wimaxmacphy.sub_burst_mimo_chase_harq_channel_id",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_mimo_chase_harq_sequence_number,
                {
                    "HARQ sequence number (AI_SN)",
                    "wimaxmacphy.sub_burst_mimo_chase_harq_sequence_number",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_mimo_chase_flush_unnamed,
                {
                    "Flush(?)",
                    "wimaxmacphy.sub_burst_mimo_chase_flush_unnamed",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_sub_burst_flush_unnamed_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_sub_burst_mimo_chase_layer_index,
                {
                    "Layer index",
                    "wimaxmacphy.sub_burst_mimo_chase_layer_index",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_ctype,
                {
                    "CType",
                    "wimaxmacphy.sub_burst_ctype",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxmacphy_ul_sub_burst_ctype_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_mini_subchannel_index,
                {
                    "Mini-subchannel Index",
                    "wimaxmacphy.sub_burst_mini_subchannel_index",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_mini_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_mini_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding,
                {
                    "Feedback type coding",
                    "wimaxmacphy.sub_burst_feedback_type_coding",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit0,
                {
                    "3 bit-MIMO Fast-feedback",
                    "wimaxmacphy.sub_burst_feedback_type_coding.bit0",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x01,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit1,
                {
                    "Enhanced FAST_FEEDBACK",
                    "wimaxmacphy.sub_burst_feedback_type_coding.bit1",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x02,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit2,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_feedback_type_coding.bit2",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x04,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit3,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_feedback_type_coding.bit3",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x08,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit4,
                {
                    "UEP fast-feedback",
                    "wimaxmacphy.sub_burst_feedback_type_coding.bit4",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x10,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit5,
                {
                    "A measurement report performed on the last DL burst",
                    "wimaxmacphy.sub_burst_feedback_type_coding.bit5",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x20,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit6,
                {
                    "Primary/Secondary FAST_FEEDBACK",
                    "wimaxmacphy.sub_burst_feedback_type_coding.bit6",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x40,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_type_coding_bit7,
                {
                    "DIUC-CQI Fast-feedback",
                    "wimaxmacphy.sub_burst_feedback_type_coding.bit7",
                    FT_BOOLEAN,
                    8,
                    TFS(&set_notset),
                    0x80,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_reserved1,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_feedback_reserved1",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x8000,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_sub_type,
                {
                    "Feedback sub-type",
                    "wimaxmacphy.sub_burst_feedback_sub_type",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x7000,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_cqich_id,
                {
                    "CQICH_ID",
                    "wimaxmacphy.sub_burst_feedback_cqich_id",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0fff,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_reserved2,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_feedback_reserved2",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0xc0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_feedback_slot_offset,
                {
                    "Slot offset",
                    "wimaxmacphy.sub_burst_feedback_slot_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x3f,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_harq_ack_acid,
                {
                    "ACID",
                    "wimaxmacphy.sub_burst_harq_ack_acid",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0xf0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_harq_ack_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_harq_ack_reserved",
                    FT_UINT32,
                    BASE_HEX,
                    NULL,
                    0x0fff,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_symbol_index,
                {
                    "Sounding symbol index within Sounding zone",
                    "wimaxmacphy.sub_burst_sounding_symbol_index",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_power_assignment,
                {
                    "Power assignment method",
                    "wimaxmacphy.sub_burst_sounding_power_assignment_method",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(
                      wimaxmacphy_ul_sub_burst_sounding_power_assignment_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_power_boost,
                {
                    "Power boost",
                    "wimaxmacphy.",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_sub_burst_sounding_power_boost_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_allocation_mode,
                {
                    "Allocation mode",
                    "wimaxmacphy.sub_burst_sounding_allocation_mode",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(
                       wimaxmacphy_ul_sub_burst_sounding_allocation_mode_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_start_freq_band,
                {
                    "Start frequency band",
                    "wimaxmacphy.sub_burst_sounding_start_freq_band",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_num_freq_bands,
                {
                    "Number of frequency bands",
                    "wimaxmacphy.ub_burst_sounding_num_freq_bands",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_band_bit_map,
                {
                    "Band bit map",
                    "wimaxmacphy.sub_burst_sounding_band_bit_map",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_cyclic_time_shift,
                {
                    "Cyclic time shift index",
                    "wimaxmacphy.sub_burst_sounding_cyclic_time_shift_index",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_decimation_offset,
                {
                    "Decimation offset",
                    "wimaxmacphy.sub_burst_sounding_decimation_offset",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_sounding_reserved,
                {
                    "Reserved",
                    "wimaxmacphy.sub_burst_sounding_reserved",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxmacphy_ul_sub_burst_mimo_chase_matrix,
                {
                    "Matrix (dual antenna SS)",
                    "wimaxmacphy.sub_burst_mimo_chase_matrix",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxmacphy_ul_sub_burst_mimo_chase_matrix_vals),
                    0x0,
                    NULL,
                    HFILL
                }
            }
        };

        /* Protocol subtree array */
    static gint *ett[] = {
        &ett_wimaxmacphy,
        &ett_wimaxmacphy_primitive,
        &ett_wimaxmacphy_prim_harq_ack,
        &ett_wimaxmacphy_prim_fast_feedback,
        &ett_wimaxmacphy_prim_fast_feedback_type_coding,
        &ett_wimaxmacphy_dl_zone_descriptor,
        &ett_wimaxmacphy_dl_zone_stc,
        &ett_wimaxmacphy_dl_zone_aas,
        &ett_wimaxmacphy_dl_burst_descriptor,
        &ett_wimaxmacphy_dl_burst_map,
        &ett_wimaxmacphy_dl_burst_normal,
        &ett_wimaxmacphy_dl_burst_papr,
        &ett_wimaxmacphy_dl_burst_opt_aas,
        &ett_wimaxmacphy_dl_burst_opt_mimo,
        &ett_wimaxmacphy_dl_sub_burst_descriptor,
        &ett_wimaxmacphy_dl_sub_burst_harq_chase,
        &ett_wimaxmacphy_dl_sub_burst_mimo_chase,
        &ett_wimaxmacphy_ul_zone_descriptor,
        &ett_wimaxmacphy_ul_zone_aas,
        &ett_wimaxmacphy_ul_burst_descriptor,
        &ett_wimaxmacphy_ul_burst_harq_ack,
        &ett_wimaxmacphy_ul_burst_fast_feedback,
        &ett_wimaxmacphy_ul_burst_initial_ranging,
        &ett_wimaxmacphy_ul_burst_periodic_ranging,
        &ett_wimaxmacphy_ul_burst_papr_safety_zone,
        &ett_wimaxmacphy_ul_burst_sounding_zone,
        &ett_wimaxmacphy_ul_burst_noise_floor,
        &ett_wimaxmacphy_ul_burst_normal_data,
        &ett_wimaxmacphy_ul_burst_opt_aas,
        &ett_wimaxmacphy_ul_burst_opt_mimo,
        &ett_wimaxmacphy_ul_sub_burst_descriptor,
        &ett_wimaxmacphy_ul_sub_burst_mini_subchannel,
        &ett_wimaxmacphy_ul_sub_burst_fast_feedback,
        &ett_wimaxmacphy_ul_sub_burst_harq_ack,
        &ett_wimaxmacphy_ul_sub_burst_sounding_signal,
        &ett_wimaxmacphy_ul_sub_burst_harq_chase,
        &ett_wimaxmacphy_ul_sub_burst_mimo_chase,
        &ett_wimaxmacphy_ul_pilot_patterns,
        &ett_wimaxmacphy_ul_feedback_type_coding,
        &ett_wimaxmacphy_ul_sub_burst_sub_allocation_specific
    };

    static ei_register_info ei[] = {
        { &ei_wimaxmacphy_unknown, { "wimaxmacphy.unexpected_bytes", PI_MALFORMED, PI_ERROR, "Unexpected bytes", EXPFILL }},
    };

    expert_module_t* expert_wimaxmacphy;

    /* Register the protocol name and description */
    proto_wimaxmacphy = proto_register_protocol(
        "WiMAX MAC-PHY over Ethernet",
        "WiMAX MAC-PHY",
        "wimaxmacphy");

    /* Required function calls to register the header fields and subtrees
     * used */
    proto_register_field_array(proto_wimaxmacphy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_wimaxmacphy = expert_register_protocol(proto_wimaxmacphy);
    expert_register_field_array(expert_wimaxmacphy, ei, array_length(ei));

    /* Register preferences module (See Section 2.6 for more on
     * preferences) */
    wimaxmacphy_module = prefs_register_protocol(
        proto_wimaxmacphy,
        proto_reg_handoff_wimaxmacphy);

    prefs_register_uint_preference(
        wimaxmacphy_module, "udp.port",
        "WiMAX MAX PHY UDP Port",
        "WiMAX MAX PHY UDP port",
        10,
        &wimaxmacphy_udp_port);

}

void
proto_reg_handoff_wimaxmacphy(void)
{
    static guint              old_wimaxmacphy_udp_port = 0;
    static gboolean           inited                   = FALSE;
    static dissector_handle_t wimaxmacphy_handle;

    if (!inited) {
        wimaxmacphy_handle = create_dissector_handle(dissect_wimaxmacphy, proto_wimaxmacphy);
        dissector_add_for_decode_as("udp.port", wimaxmacphy_handle);
        inited = TRUE;
    }

    /* Register UDP port for dissection */
    if (old_wimaxmacphy_udp_port != 0 && old_wimaxmacphy_udp_port != wimaxmacphy_udp_port) {
        dissector_delete_uint("udp.port", old_wimaxmacphy_udp_port, wimaxmacphy_handle);
    }

    if (wimaxmacphy_udp_port != 0 && old_wimaxmacphy_udp_port != wimaxmacphy_udp_port) {
        dissector_add_uint("udp.port", wimaxmacphy_udp_port, wimaxmacphy_handle);
    }
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
