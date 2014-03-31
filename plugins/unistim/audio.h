/* audio.h
  * header field declarations, value_string definitions and true_false_string
  * definitions for audio manager messages
  * Copyright 2007 Don Newton <dnewton@cypresscom.net>
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

#ifndef UNISTIM_AUDIO_H
#define UNISTIM_AUDIO_H

static int hf_audio_mgr_attr=-1;
static int hf_audio_mgr_opts=-1;
static int hf_audio_mgr_alert=-1;
static int hf_audio_mgr_adj_rx_vol=-1;
static int hf_audio_mgr_def_rx_vol=-1;
static int hf_audio_mgr_handset=-1;
static int hf_audio_mgr_headset=-1;
static int hf_audio_default_rx_vol_id=-1;

static int hf_audio_mgr_opt_max_vol=-1;
static int hf_audio_mgr_opt_adj_vol=-1;
static int hf_audio_mgr_opt_aa_rx_vol_rpt=-1;
static int hf_audio_mgr_opt_hs_on_air=-1;
static int hf_audio_mgr_opt_hd_on_air=-1;
static int hf_audio_mgr_opt_noise_squelch=-1;

static int hf_audio_mgr_mute=-1;
static int hf_audio_mgr_tx_rx=-1;
static int hf_audio_mgr_stream_id=-1;

static int hf_audio_mgr_transducer_based_tone_id=-1;
static int hf_audio_mgr_attenuated=-1;
static int hf_audio_mgr_warbler_select=-1;
static int hf_audio_mgr_transducer_routing=-1;
static int hf_audio_mgr_tone_vol_range=-1;
static int hf_audio_mgr_cadence_select=-1;
static int hf_audio_special_tone=-1;
static int hf_audio_tone_level=-1;
static int hf_audio_visual_tones=-1;

static int hf_audio_stream_based_tone_id=-1;
static int hf_audio_stream_based_tone_rx_tx=-1;
static int hf_audio_stream_based_tone_mute=-1;
static int hf_audio_stream_id=-1;
static int hf_audio_stream_based_volume=-1;

static int hf_audio_apb_number=-1;
static int hf_audio_apb_op_code=-1;
static int hf_audio_apb_param_len=-1;
static int hf_audio_apb_data=-1;
static int hf_audio_vocoder_id=-1;
static int hf_audio_vocoder_param=-1;
static int hf_audio_vocoder_entity=-1;
static int hf_audio_vocoder_annexa=-1;
static int hf_audio_vocoder_annexb=-1;
static int hf_audio_sample_rate=-1;
static int hf_audio_rtp_type=-1;
static int hf_audio_bytes_per_frame=-1;

static int hf_audio_rx_stream_id=-1;
static int hf_audio_tx_stream_id=-1;
static int hf_rx_vocoder_type=-1;
static int hf_tx_vocoder_type=-1;
static int hf_frames_per_packet=-1;
static int hf_audio_tos=-1;
static int hf_audio_precedence=-1;
static int hf_audio_frf_11=-1;
static int hf_rtcp_bucket_id=-1;
static int hf_audio_lcl_rtp_port=-1;
static int hf_audio_lcl_rtcp_port=-1;
static int hf_audio_far_rtp_port=-1;
static int hf_audio_far_rtcp_port=-1;
static int hf_audio_far_ip_add=-1;
static int hf_audio_rtcp_bucket_id=-1;
static int hf_audio_clear_bucket=-1;

static int hf_audio_transducer_pair=-1;
static int hf_audio_rx_enable=-1;
static int hf_audio_tx_enable=-1;
static int hf_audio_sidetone_disable=-1;
static int hf_audio_destruct_additive=-1;
static int hf_audio_dont_force_active=-1;
static int hf_audio_source_descr=-1;
static int hf_audio_sdes_rtcp_bucket=-1;
static int hf_audio_desired_jitter=-1;
static int hf_audio_high_water_mark=-1;
static int hf_audio_early_packet_resync_thresh=-1;
static int hf_audio_late_packet_resync_thresh=-1;
static int hf_audio_resolve_phone_port=-1;
static int hf_audio_far_end_echo_port=-1;
static int hf_audio_far_end_ip_address=-1;
static int hf_audio_nat_port=-1;
static int hf_audio_nat_ip_address=-1;
static int hf_audio_direction_code=-1;
static int hf_audio_hf_support=-1;
static int hf_audio_opt_rpt_max=-1;
static int hf_audio_opt_rpt_adj_vol=-1;
static int hf_audio_opt_rpt_auto_adj_vol=-1;
static int hf_audio_opt_rpt_hs_on_air=-1;
static int hf_audio_opt_rpt_hd_on_air=-1;
static int hf_audio_opt_rpt_noise_squelch=-1;
static int hf_audio_rx_vol_apb_rpt=-1;
static int hf_audio_rx_vol_vol_up=-1;
static int hf_audio_rx_vol_vol_floor=-1;
static int hf_audio_rx_vol_vol_ceiling=-1;
static int hf_audio_current_adj_vol_id=-1;
static int hf_audio_current_rx_level=-1;
static int hf_audio_current_rx_range=-1;
static int hf_audio_cadence_select=-1;
static int hf_audio_warbler_select=-1;
static int hf_audio_open_stream_rpt=-1;
static int hf_audio_sdes_rpt_source_desc=-1;
static int hf_audio_sdes_rpt_buk_id=-1;
static int hf_audio_phone_port=-1;
static int hf_audio_phone_ip=-1;

static int hf_audio_phone_add_len=-1;
static int hf_audio_nat_listen_port=-1;
static int hf_audio_nat_ip=-1;
static int hf_audio_nat_add_len=-1;
static int hf_audio_stream_direction_code=-1;
static int hf_audio_stream_state=-1;
static int hf_audio_transducer_list_length=-1;


static const value_string audio_switch_msgs[]={
 {0x00,"Query Audio Manager"},
 {0x01,"Query Supervisor Headset Status"},
 {0x02,"Audio Manager Options"},
 {0x04,"Mute/Unmute"},
 {0x10,"Transducer Based Tone On"},
 {0x11,"Transducer Based Tone Off"},
 {0x12,"Alerting Tone Configuration"},
 {0x13,"Special Tone Configuration"},
 {0x14,"Paging Tone Configuration"},
 {0x15,"Alerting Tone Cadence Download"},
 {0x17,"Paging Tone Cadence Download"},
 {0x18,"Transducer Based Tone Volume Level"},
 {0x1a,"Visual Transducer Based Tone Enable"},
 {0x1b,"Stream Based Tone On"},
 {0x1c,"Stream Based Tone Off"},
 {0x1d,"Stream Based Tone Frequency Component List Download"},
 {0x1e,"Stream Based Tone Cadence Download"},
 {0x20,"Select Adjustable Rx Volume"},
 {0x21,"Set APB's Rx Volume Level"},
 {0x22,"Change Adjustable Rx Volume (quieter)"},
 {0x23,"Change Adjustable Rx Volume (louder)"},
 {0x24,"Adjust Default Rx Volume (quieter)"},
 {0x25,"Adjust Default Rx Volume (louder)"},
 {0x28,"APB Download"},
 {0x30,"Open Audio Stream"},
 {0x31,"Close Audio Stream"},
 {0x32,"Connect Transducer"},
 {0x34,"Filter Block Download"},
 {0x37,"Query RTCP Statistics"},
 {0x38,"Configure Vocoder Parameters"},
 {0x39,"Query RTCP Bucket's SDES Information"},
 {0x3a,"Jitter Buffer Parameters Configuration"},
 {0x3b,"Resolve Port Mapping"},
 {0x3c,"Port Mapping Discovery"},
 {0x3d,"Query Audio Stream Status"},
 {0xff,"Reserved"},
 {0,NULL}
};
static const value_string audio_phone_msgs[]={
 {0x00,"Handset Connected"},
 {0x01,"Handset Disconnected"},
 {0x02,"Headset Connected"},
 {0x03,"Headset Disconnected"},
 {0x04,"Supervisor Headset Connected"},
 {0x05,"Supervisor Headset Disconnected"},
 {0x07,"Audio Manager Attributes Info"},
 {0x08,"Audio Manager Options Report"},
 {0x09,"Adjustable Rx Volume Report"},
 {0x0a,"Adjustable Rx Volume Information"},
 {0x0b,"APB's Default Rx Volume Value"},
 {0x0c,"Alerting Tone Select"},
 {0x0e,"RTCP Statistics Report"},
 {0x0f,"Open Audio Stream Report"},
 {0x10,"RTCP Bucket SDES Information Report"},
 {0x11,"Port Mapping Discovery"},
 {0x12,"Resolve Port Mapping"},
 {0x13,"Audio Stream Status Report"},
 {0x14,"Query APB Response"},
 {0xff,"Reserved"},
 {0,NULL}
};


static const true_false_string stream_states={
 "Stream in use.",
 "Stream not in use."
};

static const value_string stream_direction_codes[]={
 {0x00,"Invalid"},
 {0x01,"Command contains information about an Rx Audio stream"},
 {0x02,"Command contains information about a Tx Audio stream"},
 {0x03,"Invalid"},
 {0,NULL}
};



static const value_string source_descipts[]={
 {0x00,"Information Not Available"},
 {0x01,"Canonical End-Point Identifier associated with the IT"},
 {0x02,"Name used to describe the IT e.g. Homer Does IT "},
 {0x03,"E-mail address associated with the IT"},
 {0x04,"Phone number of the IT"},
 {0x05,"Geographic location of the IT"},
 {0x06,"IT software version"},
 {0x07,"Notice/Status information"},
 {0,NULL}
};

static const value_string stream_result[]={
 {0x00,"Stream opened successfully"},
 {0x01,"Operation failed: Invalid Stream ID"},
 {0x02,"Operation failed: Unsupported Vocoder"},
 {0x03,"Operation failed: Stream already in use"},
 {0x04,"Operation failed: Local port already in use"},
 {0x05,"Operation failed: No streams specified"},
 {0x06,"Operation failed: Audio packet size too large based on frames per packets"},
 {0x07,"Operation failed: Invalid Frames Per Packet value"},
 {0x08,"Operation failed: Invalid Bucket ID"},
 {0x09,"Operation failed: RTP and RTCP ports Identical"},
 {0x0a,"Operation failed: Inconsistent Parameters on full duplex promotion"},
 {0x0b,"Operation failed: No Empty Vocoder Bins"},
 {0x0c,"Operation failed: Vocoders Not Identical"},
 {0,NULL}
};


static const value_string volume_rpt_apbs[]={
 {0x01,"Audio Param Bank 1"},
 {0x02,"Audio Param Bank 2"},
 {0x03,"Audio Param Bank 3"},
 {0x04,"Audio Param Bank 4"},
 {0x05,"Audio Param Bank 5"},
 {0x06,"Audio Param Bank 6"},
 {0x07,"Audio Param Bank 7"},
 {0x08,"Audio Param Bank 8"},
 {0x09,"Audio Param Bank 9"},
 {0x0a,"Audio Param Bank 10"},
 {0x0b,"Audio Param Bank 11"},
 {0x0c,"Audio Param Bank 12"},
 {0x0d,"Audio Param Bank 13"},
 {0x0e,"Audio Param Bank 14"},
 {0x0f,"Audio Param Bank 15"},
 {0x10,"Special Tones"},
 {0x11,"Paging Tones"},
 {0,NULL}
};
static const true_false_string opt_rpt_adjust_volume={
 "Volume level adjustments are performed locally in the IT",
 "Volume level adjustments are not performed locally in the IT"
};
static const true_false_string opt_rpt_automatic_adjustable_rx_volume_report={
 "Adjustable Rx volume reports sent to the NI when volume keys are pressed",
 "Adjustable Rx volume reports not sent to the NI when volume keys are pressed"
};
static const true_false_string opt_rpt_enable_max_tone_vol={
 "Maximum tone volume is set equal to the physical maximum",
 "Maximum tone volume is one level lower than physical maximum"
};
static const true_false_string opt_rpths_on_air_feature={
 "Single tone frequency sent to HS port while call in progress",
 "Single tone frequency NOT sent to HS port while call in progress"
};
static const true_false_string opt_rpt_hd_on_air_feature={
 "Single tone frequency sent to HD port while call in progress",
 "Single tone frequency NOT sent to HD port while call in progress"
};
static const true_false_string opt_rpt_noise_sqlch_disable={
 "Automatic noise squelching enabled",
 "Automatic noise squelching disabled"
};

static const value_string direction_codes[]={
 {0x00,"Invalid"},
 {0x01,"Rx Audio stream is queried"},
 {0x02,"Tx Audio stream is queried"},
 {0x03,"Rx and Tx Audio streams are queried"},
 {0,NULL}
};

static const value_string source_descriptions[]={
 {0x01,"Canonical End-Point Identifier associated with the Phone"},
 {0x02,"Name used to describe the Phone e.g. Homer Does Phone"},
 {0x03,"E-mail address associated with the Phone"},
 {0x04,"Phone number of the Phone"},
 {0x05,"Geographic location of the Phone"},
 {0x06,"Phone software version"},
 {0x07,"Notice/Status information"},
 {0,NULL}
};

static const true_false_string dont_force_active={
 "The APB specified will NOT be the active one",
 "The APB specified will be the active one"
};


static const true_false_string destruct_additive={
 "This will not affect the connections that were established prior",
 "All transducers that were connected prior will be disconnected"
};



static const value_string transducer_pairs[]={
 {0x00,"Handset"},
 {0x01,"Headset"},
 {0x02,"Handsfree Speaker/Microphone"},
 {0x3F,"All Transducer Pairs"},
 {0,NULL}
};

static const value_string types_of_service[]={
 {0x08,"Minimize Delay"},
 {0x04,"Maximize Throughput"},
 {0x02,"Maximize Reliability"},
 {0x01,"Minimize Monetary Cost"},
 {0x00,"Normal Service"},
 {0,NULL}
};
static const value_string precedences[]={
 {0x00,"Routine"},
 {0x01,"Priority"},
 {0x02,"Immediate"},
 {0x03,"Flash"},
 {0x04,"Flash Override"},
 {0x05,"Critical"},
 {0x06,"Internetwork Control"},
 {0x07,"Network Control"},
 {0,NULL}
};
static const value_string sample_rates[]={
 {0x00,"8 kbit/sec"},
 {0x01,"16 kbit/sec"},
 {0x02,"44.1 kbit/sec"},
 {0,NULL}
};

static const value_string config_param_entities[]={
 {0x01,"Configuration Parameter in byte only affects the encoder"},
 {0x02,"Configuration Parameter in byte only affects decoder"},
 {0x03," Configuration Parameter in byte affects the whole vocoder"},
 {0,NULL}
};
static const value_string vocoder_config_params[]={
 {0x00,"Turn Off Voice Activity Detection"},
 {0x01,"Turn On Voice Activity Detection"},
 {0x02,"Turn Off Bad Frame Interpolation Algorithm"},
 {0x03,"Turn On Bad Frame Interpolation Algorithm"},
 {0x04,"Disable Post Filter"},
 {0x05,"Enable Post Filter"},
 {0x06,"Disable High Pass Filter"},
 {0x07,"Enable High Pass Filter"},
 {0x08,"G.723 6.3kbps Working Rate "},
 {0x09,"G.723 5.3kbps Working Rate "},
 {0x0A,"G.729 Annexes Selection "},
 {0x0B,"Set the sampling Rate of the vocoder "},
 {0x0C,"Set RTP Payload Type "},
 {0x20,"Set number of bytes per frame "},
 {0,NULL}
};
static const value_string vocoder_ids[]={
 {0x00,"G.711, Mu-Law"},
 {0x04,"G.723"},
 {0x08,"G.711, A-Law"},
 {0x0A,"16-bit Linear"},
 {0x12,"G.729"},
 {0x60,"8-bit Linear"},
 {0x61,"G.711, Mu-Law with PLP"},
 {0x62,"G.711, A-Law with PLP"},
 {0,NULL}
};


static const value_string apb_op_codes[]={
 {0x00,"Enable Return To Default Option"},
 {0x01,"Disable Return To Default Option"},
 {0x02,"Enable Automatic Gain Control Option"},
 {0x03,"Disable Automatic Gain Control Option"},
 {0x04,"Select APB for Volume Control Option"},
 {0x05,"Deselect APB for Volume Control Option"},
 {0x06,"Enable Listener Sidetone Option"},
 {0x07,"Disable Listener Sidetone Option"},
 {0x08,"Enable Acoustic Echo Canceller (AEC) Option"},
 {0x09,"Disable Acoustic Echo Canceller (AEC) Option"},
 {0x10,"Enable Hearing Impaired (HIP) Option"},
 {0x11,"Disable Hearing Impaired (HIP) Option"},
 {0x0A,"Enable Rx Squelch Option"},
 {0x0B,"Disable Rx Squelch Option"},
 {0x0C,"Enable Rx Compressor Option"},
 {0x0D,"Disable Rx Compressor Option"},
 {0x0E,"Enable Tx Echo Squelch Option"},
 {0x0F,"Disable Tx Echo Squelch Option"},
 {0x40,"Query Audio Parameters"},
 {0x41,"Step Size setting"},
 {0x42,"Maximum Volume setting"},
 {0x43,"Minimum Volume setting"},
 {0x44,"Rx CODEC Gain Value"},
 {0x45,"Tx CODEC Gain Value"},
 {0x46,"Rx DSP Gain Value"},
 {0x47,"Tx DSP Gain Value"},
 {0x48,"Sidetone Gain Value"},
 {0x49,"Switched Loss Depth"},
 {0x4A,"Length of AEC"},
 {0x4B,"MCS_NOISE_THR"},
 {0x4C,"LineDelayLength"},
 {0x4D,"MaxReturnLossTG"},
 {0x4E,"SWL_AEC_OFF"},
 {0x4F,"NormDelta"},
 {0x50,"TxLevelCompHD"},
 {0x51,"TxRL_BOOT"},
 {0x52,"NoiseWaitCounter" },
 {0x53,"Whole APS" },
 {0x54,"Change Default Volume setting"},
 {0x55,"Change Current Volume setting"},
 {0x56,"Sampling Rate setting"},
 {0x57,"The filter(s) to be used when the HIP is enabled"},
 {0x58,"The threshold that should be used when AGC is enabled"},
 {0x59,"The threshold that should be used when Listener Sidetone (LST) is enabled"},
 {0,NULL}
};
static const true_false_string stream_based_tone_rx_tx_yn={
 "Stream ID specified in last byte is in the tx direction",
 "Stream ID specified in last byte is in the rx direction"
};
static const true_false_string stream_based_tone_mute_yn={
 "Stream Based Tone will replace Stream Data",
 "Stream Based tone will be summed with Stream Data"
};
static const value_string stream_based_tone_vals[]={
 {0x00,"Dial Tone F1=0x0B33 - 350 Hz F2=0x0E14 - 440 Hz F3=0x00 - not present F4=0x00 - not present"},
 {0x01,"Recall Dial Tone F1=0x0B33 - 350 Hz F2=0x0E14 - 440 Hz F3=0x00 - not present F4=0x00 - not present"},
 {0x02,"Line Busy F1 = 0x0F5C - 480 Hz F2 = 0x13D7 - 620 Hz F3 = 0x00 - not present F4 = 0x00 - not present"},
 {0x03,"Reorder F1 = 0x0F5C - 480 Hz F2 = 0x13D7 - 620 Hz F3 = 0x00 - not present F4 = 0x00 - not present"},
 {0x04,"Audible Ringing F1=0x0E14 - 440 Hz F2=0x0F5C - 480 Hz F3=0x00 - not present F4=0x00 - not present"},
 {0x05,"Receiver Off Hook (ROH) F1=0x2CCC-1400 Hz F2=0x4851-2260 Hz F3=0x4E66-2450 Hz F4=0x5333 - 2600 Hz"},
 {0x06,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x07,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x08,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x09,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x0a,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x0b,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x0c,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x0d,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x0e,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0x0f,"No Tone F1=0x00-0 Hz F2=0x00-0 Hz F3=0x00-0 Hz F4=0x00-0 Hz 0x00 C1=0x00 C2=0x00 C3=0x0 c4=0x0"},
 {0,NULL}
};
static const value_string stream_base_vol_level[]={
 {0x6F,"C1=0xFF00 C2=0x00 C3=0x00 c4=0x00 Steady on.  -13 dBmO per frequency."},
 {0x6F,"C1=0x0505 C2=0x0505 C3=0x0505 c4=0xFF00 3 burst(0.1 sec on,0.1 sec off),Then steady on.-13 dBmO per frequency."},
 {0x60,"C1=0x1919 C2=0x00 C3=0x00 c4=0x00 0.5 sec on, 0.5 sec off, repeating.  -24 dBmO per frequency."},
 {0x67,"C1=0x64C8 C2=0x00 C3=0x00 c4=0x00 2 sec on, 4 sec off, repeating.  -19 dBmO per frequency."},
 {0x80,"C1=0xFF00 C2=0x00 C3=0x00 c4=0x00 0.1 sec on, 0.1 sec off, repeating.  +3 to -6 dBmO/frequency."},
 {0,NULL}
};
static const value_string special_tones_vals[]={
 {0x01,"250Hz"},
 {0x02,"333Hz"},
 {0x04,"500Hz"},
 {0x08,"667Hz"},
 {0x10,"1000Hz"},
 {0,NULL}
};


static const value_string transducer_routing_vals[]={
 {0x00,"Handset Speaker"},
 {0x01,"Headset Speaker"},
 {0x02,"Handsfree Speaker"},
 {0,NULL}
};
static const value_string cadence_select_vals[]={
 {0x00,"cadence 0 (2 secs on, 4 secs off, cyclic)"},
 {0x01,"cadence 1 (0.5 secs on, 0.3 secs off, 1.2 secs on, 4 secs off, cyclic)"},
 {0x02,"cadence 2 (0.7 secs on, 0.5 secs off, 0.7 secs on, 4 secs off, cyclic)"},
 {0x03,"cadence 3 (0.5 secs on then off, one-shot)"},
 {0x04,"cadence 4 (test cadence)"},
 {0x05,"cadence 5 (test cadence)"},
 {0x06," cadence 6 (test cadence)"},
 {0x07,"downloadable alerter tone cadence"},
 {0,NULL}
};

static const true_false_string audio_mgr_mute_val={
 "Following Stream will be Muted",
 "Following Stream will be UnMuted"
};
static const true_false_string audio_mgr_tx_rx_val={
 "Next Byte specifies an RX Stream ID",
 "Next Byte specifies an TX Stream ID"
};

static const true_false_string audio_opts_enable_max_tone_vol={
 "Maximum tone volume is set equal to the physical maximum",
 "Maximum tone volume is one level lower than physical maximum"
};
static const true_false_string audio_opts_adjust_volume={
 "Volume level adjustments are performed locally in the phone",
 "Volume level adjustments are not performed locally in the phone"
};
static const true_false_string audio_opts_automatic_adjustable={
 "Adjustable Rx volume reports sent to the switch when volume keys are pressed",
 "Adjustable Rx volume reports not sent to the switch when volume keys are pressed Rx Volume Report"
};
static const true_false_string audio_opts_hs_on_air_feature={
 "Single tone frequency sent to Handset port while call in progress",
 "Single tone frequency NOT sent to Handset (HS) port while call in progress"
};
static const true_false_string audio_opts_hd_on_air_feature={
 "Single tone frequency sent to Headset (HD) port while call in progress",
 "Single tone frequency NOT sent to Headset (HD) port while call in progress"
};
static const true_false_string noise_sqlch_disable={
 "Automatic noise squelching enabled",
 "Automatic noise squelching disabled"
};

static const value_string default_rx_vol_id[]={
 {0x00,"none"},
 {0x01,"Audio Param Bank 1"},
 {0x02,"Audio Param Bank 2"},
 {0x03,"Audio Param Bank 3"},
 {0x04,"Audio Param Bank 4"},
 {0x05,"Audio Param Bank 5"},
 {0x06,"Audio Param Bank 6"},
 {0x07,"Audio Param Bank 7"},
 {0x08,"Audio Param Bank 8"},
 {0x09,"Audio Param Bank 9"},
 {0x0a,"Audio Param Bank a"},
 {0x0b,"Audio Param Bank b"},
 {0x0c,"Audio Param Bank c"},
 {0x0d,"Audio Param Bank d"},
 {0x0e,"Audio Param Bank e"},
 {0x0f,"Audio Param Bank f"},
 {0x10,"Alerting"},
 {0x11,"Special Tones"},
 {0x12,"Paging Tones"},
 {0,NULL}
};

static const value_string trans_base_tone_ids[]={
 {0x00,"Alerting"},
 {0x01,"Special Tones"},
 {0x02,"Paging Tones"},
 {0,NULL}
};
#endif
