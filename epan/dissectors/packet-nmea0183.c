/* packet-nmea0183.c
 * Routines for NMEA 0183 protocol dissection
 * Copyright 2024 Casper Meijn <casper@meijn.net>
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
#include <wsutil/strtoi.h>


/*
 * null-terminated sentence prefix string "UdPbC"
 */
#define UDPBC "UdPbC"
#define RRUDP "RrUdP"
#define RAUDP "RaUdp"
#define RPUDP "RpUdP"
#define NMEA0183_CRLF 0x0d0a

static int hf_nmea0183_talker_id;
static int hf_nmea0183_sentence_id;
static int hf_nmea0183_unknown_field;
static int hf_nmea0183_checksum;
static int hf_nmea0183_checksum_calculated;

static int hf_nmea0183_dpt_depth;
static int hf_nmea0183_dpt_offset;
static int hf_nmea0183_dpt_max_range;

static int hf_nmea0183_hdt_heading;
static int hf_nmea0183_hdt_unit;

static int hf_nmea0183_aam_arr_circle_radius;
static int hf_nmea0183_aam_arr_circle_status;
static int hf_nmea0183_aam_perp_status;
static int hf_nmea0183_aam_units_radius;
static int hf_nmea0183_aam_waypoint;

static int hf_nmea0183_abk_ack_type;
static int hf_nmea0183_abk_ais_channel;
static int hf_nmea0183_abk_mmsi;
static int hf_nmea0183_abk_msg_id;
static int hf_nmea0183_abk_msg_seq;

static int hf_nmea0183_aca_chan_a;
static int hf_nmea0183_aca_chan_a_bw;
static int hf_nmea0183_aca_chan_b;
static int hf_nmea0183_aca_chan_b_bw;
static int hf_nmea0183_aca_info_src;
static int hf_nmea0183_aca_inuse;
static int hf_nmea0183_aca_inuse_change;
static int hf_nmea0183_aca_ne_clat;
static int hf_nmea0183_aca_ne_clong;
static int hf_nmea0183_aca_power;
static int hf_nmea0183_aca_seq_num;
static int hf_nmea0183_aca_sw_clat;
static int hf_nmea0183_aca_sw_clong;
static int hf_nmea0183_aca_txrx_mode;
static int hf_nmea0183_aca_zone_size;

static int hf_nmea0183_ack_alarm_id;

static int hf_nmea0183_acs_day;
static int hf_nmea0183_acs_mmsi;
static int hf_nmea0183_acs_month;
static int hf_nmea0183_acs_seq_num;
static int hf_nmea0183_acs_utc;
static int hf_nmea0183_acs_year;

static int hf_nmea0183_air_mmsi_is1;
static int hf_nmea0183_air_mmsi_is2;
static int hf_nmea0183_air_msg2_req;
static int hf_nmea0183_air_msg2_sub;
static int hf_nmea0183_air_msg_req;
static int hf_nmea0183_air_msg_req_is2;
static int hf_nmea0183_air_msg_sub;
static int hf_nmea0183_air_msg_sub_is2;

static int hf_nmea0183_akd_alarm_type;
static int hf_nmea0183_akd_inst_num_orig;
static int hf_nmea0183_akd_inst_num_send;
static int hf_nmea0183_akd_subsys_indicator_orig;
static int hf_nmea0183_akd_sybsys_indicator_send;
static int hf_nmea0183_akd_sys_indicator_orig;
static int hf_nmea0183_akd_sys_indicator_send;
static int hf_nmea0183_akd_utc;

static int hf_nmea0183_ala_alarm_ack_state;
static int hf_nmea0183_ala_alarm_cond;
static int hf_nmea0183_ala_alarm_text;
static int hf_nmea0183_ala_alarm_type;
static int hf_nmea0183_ala_inst_num;
static int hf_nmea0183_ala_subsys_indicator;
static int hf_nmea0183_ala_sys_indicator;
static int hf_nmea0183_ala_time;

static int hf_nmea0183_alm_af0_clock_param;
static int hf_nmea0183_alm_af1_clock_param;
static int hf_nmea0183_alm_alm_ref_time;
static int hf_nmea0183_alm_arg_perigee;
static int hf_nmea0183_alm_eccent;
static int hf_nmea0183_alm_gps_week;
static int hf_nmea0183_alm_incl_angle;
static int hf_nmea0183_alm_long_asc_node;
static int hf_nmea0183_alm_mean_anomaly;
static int hf_nmea0183_alm_rate_right_asc;
static int hf_nmea0183_alm_root_sm_axis;
static int hf_nmea0183_alm_sat_prn;
static int hf_nmea0183_alm_sent_num;
static int hf_nmea0183_alm_sent_tot;
static int hf_nmea0183_alm_sv_health;

static int hf_nmea0183_alr_time;
static int hf_nmea0183_alr_time_hour;
static int hf_nmea0183_alr_time_minute;
static int hf_nmea0183_alr_time_second;
static int hf_nmea0183_alr_alarm_id;
static int hf_nmea0183_alr_alarm_cond;
static int hf_nmea0183_alr_alarm_ack_st;
static int hf_nmea0183_alr_alarm_desc_txt;

static int hf_nmea0183_apb_arr_circle_status;
static int hf_nmea0183_apb_bearing_origin;
static int hf_nmea0183_apb_bearing_present;
static int hf_nmea0183_apb_cycle_lock_warning;
static int hf_nmea0183_apb_dir_steer;
static int hf_nmea0183_apb_heading_steer;
static int hf_nmea0183_apb_mag_xte;
static int hf_nmea0183_apb_mode;
static int hf_nmea0183_apb_perp_status;
static int hf_nmea0183_apb_waypoint_id;
static int hf_nmea0183_apb_xte_units;

static int hf_nmea0183_bec_bearing_mag;
static int hf_nmea0183_bec_bearing_true;
static int hf_nmea0183_bec_distance;
static int hf_nmea0183_bec_latitude;
static int hf_nmea0183_bec_longitude;
static int hf_nmea0183_bec_utc;
static int hf_nmea0183_bec_waypoint;

static int hf_nmea0183_bod_bearing_mag;
static int hf_nmea0183_bod_bearing_true;
static int hf_nmea0183_bod_dest_waypoint;
static int hf_nmea0183_bod_orig_waypoint;

static int hf_nmea0183_bwc_bearing_mag;
static int hf_nmea0183_bwc_bearing_true;
static int hf_nmea0183_bwc_distance;
static int hf_nmea0183_bwc_latitude;
static int hf_nmea0183_bwc_longitude;
static int hf_nmea0183_bwc_mode;
static int hf_nmea0183_bwc_utc;
static int hf_nmea0183_bwc_waypoint;

static int hf_nmea0183_bwr_bearing_mag;
static int hf_nmea0183_bwr_bearing_true;
static int hf_nmea0183_bwr_distance;
static int hf_nmea0183_bwr_latitude;
static int hf_nmea0183_bwr_longitude;
static int hf_nmea0183_bwr_mode;
static int hf_nmea0183_bwr_utc;
static int hf_nmea0183_bwr_waypoint;

static int hf_nmea0183_bww_bearing_mag;
static int hf_nmea0183_bww_bearing_true;
static int hf_nmea0183_bww_from_waypoint;
static int hf_nmea0183_bww_to_waypoint;

static int hf_nmea0183_cbr_hr_chan_a;
static int hf_nmea0183_cbr_hr_chan_b;
static int hf_nmea0183_cbr_interv_chan_a;
static int hf_nmea0183_cbr_interv_chan_b;
static int hf_nmea0183_cbr_min_chan_a;
static int hf_nmea0183_cbr_min_chan_b;
static int hf_nmea0183_cbr_mmsi;
static int hf_nmea0183_cbr_msd_id_index;
static int hf_nmea0183_cbr_msg_id;
static int hf_nmea0183_cbr_setup;
static int hf_nmea0183_cbr_slot_chan_a;
static int hf_nmea0183_cbr_slot_chan_b;
static int hf_nmea0183_cbr_status;

static int hf_nmea0183_cur_data_set;
static int hf_nmea0183_cur_depth;
static int hf_nmea0183_cur_direction;
static int hf_nmea0183_cur_direction_ref;
static int hf_nmea0183_cur_heading;
static int hf_nmea0183_cur_heading_ref;
static int hf_nmea0183_cur_layer;
static int hf_nmea0183_cur_ref_layer;
static int hf_nmea0183_cur_speed;
static int hf_nmea0183_cur_speed_ref;
static int hf_nmea0183_cur_validity;

static int hf_nmea0183_dbt_fathoms;
static int hf_nmea0183_dbt_feet;
static int hf_nmea0183_dbt_meters;

static int hf_nmea0183_dcn_data_basis;
static int hf_nmea0183_dcn_dc_id;
static int hf_nmea0183_dcn_glop;
static int hf_nmea0183_dcn_gnav;
static int hf_nmea0183_dcn_gstatus;
static int hf_nmea0183_dcn_gz_id;
static int hf_nmea0183_dcn_plop;
static int hf_nmea0183_dcn_pnav;
static int hf_nmea0183_dcn_pos_uncertainty;
static int hf_nmea0183_dcn_pstatus;
static int hf_nmea0183_dcn_pz_id;
static int hf_nmea0183_dcn_rlop;
static int hf_nmea0183_dcn_rnav;
static int hf_nmea0183_dcn_rstatus;
static int hf_nmea0183_dcn_rz_id;

static int hf_nmea0183_ddc_brightness;
static int hf_nmea0183_ddc_dimming;
static int hf_nmea0183_ddc_palette;
static int hf_nmea0183_ddc_status;

static int hf_nmea0183_dor_door_num;
static int hf_nmea0183_dor_time;
static int hf_nmea0183_dor_first_indic;
static int hf_nmea0183_dor_msg_type;
static int hf_nmea0183_dor_open_count;
static int hf_nmea0183_dor_second_indic;
static int hf_nmea0183_dor_setting;
static int hf_nmea0183_dor_status;
static int hf_nmea0183_dor_system_type;
static int hf_nmea0183_dor_text;

static int hf_nmea0183_dsc_ack;
static int hf_nmea0183_dsc_address;
static int hf_nmea0183_dsc_category;
static int hf_nmea0183_dsc_comm_type;
static int hf_nmea0183_dsc_expansion;
static int hf_nmea0183_dsc_first_tcmd;
static int hf_nmea0183_dsc_format;
static int hf_nmea0183_dsc_mmsi;
static int hf_nmea0183_dsc_nature_distress;
static int hf_nmea0183_dsc_position;
static int hf_nmea0183_dsc_time;

static int hf_nmea0183_dse_code;
static int hf_nmea0183_dse_data;
static int hf_nmea0183_dse_flag;
static int hf_nmea0183_dse_mmsi;
static int hf_nmea0183_dse_sentence_number;
static int hf_nmea0183_dse_total_sentences;

static int hf_nmea0183_dsi_course;
static int hf_nmea0183_dsi_expansion;
static int hf_nmea0183_dsi_geo_area;
static int hf_nmea0183_dsi_info;
static int hf_nmea0183_dsi_mmsi;
static int hf_nmea0183_dsi_sentence_number;
static int hf_nmea0183_dsi_symbol;
static int hf_nmea0183_dsi_total_sentences;
static int hf_nmea0183_dsi_type;

static int hf_nmea0183_dsr_expansion;
static int hf_nmea0183_dsr_info;
static int hf_nmea0183_dsr_mmsi;
static int hf_nmea0183_dsr_sentence_number;
static int hf_nmea0183_dsr_symbol;
static int hf_nmea0183_dsr_total_sentences;

static int hf_nmea0183_dtm_alt_offset;
static int hf_nmea0183_dtm_datum;
static int hf_nmea0183_dtm_datum_subdiv;
static int hf_nmea0183_dtm_lat_offset;
static int hf_nmea0183_dtm_lon_offset;
static int hf_nmea0183_dtm_ref_datum;

static int hf_nmea0183_etl_msg_type;
static int hf_nmea0183_etl_num_eng_shaft;
static int hf_nmea0183_etl_opind;
static int hf_nmea0183_etl_posind_engine;
static int hf_nmea0183_etl_posind_sub;
static int hf_nmea0183_etl_time;

static int hf_nmea0183_fsi_mode;
static int hf_nmea0183_fsi_power;
static int hf_nmea0183_fsi_recv_freq;
static int hf_nmea0183_fsi_xmit_freq;

static int hf_nmea0183_gbs_alt_err;
static int hf_nmea0183_gbs_est_bias;
static int hf_nmea0183_gbs_lat_err;
static int hf_nmea0183_gbs_long_err;
static int hf_nmea0183_gbs_prob_miss;
static int hf_nmea0183_gbs_sat_id;
static int hf_nmea0183_gbs_sat_type;
static int hf_nmea0183_gbs_std_dev;
static int hf_nmea0183_gbs_utc;

static int hf_nmea0183_gga_time;
static int hf_nmea0183_gga_time_hour;
static int hf_nmea0183_gga_time_minute;
static int hf_nmea0183_gga_time_second;
static int hf_nmea0183_gga_latitude;
static int hf_nmea0183_gga_latitude_degree;
static int hf_nmea0183_gga_latitude_minute;
static int hf_nmea0183_gga_latitude_direction;
static int hf_nmea0183_gga_longitude;
static int hf_nmea0183_gga_longitude_degree;
static int hf_nmea0183_gga_longitude_minute;
static int hf_nmea0183_gga_longitude_direction;
static int hf_nmea0183_gga_quality;
static int hf_nmea0183_gga_number_satellites;
static int hf_nmea0183_gga_horizontal_dilution;
static int hf_nmea0183_gga_altitude;
static int hf_nmea0183_gga_altitude_unit;
static int hf_nmea0183_gga_geoidal_separation;
static int hf_nmea0183_gga_geoidal_separation_unit;
static int hf_nmea0183_gga_age_dgps;
static int hf_nmea0183_gga_dgps_station;

static int hf_nmea0183_glc_gri;
static int hf_nmea0183_glc_master_toa;
static int hf_nmea0183_glc_sig_status;
static int hf_nmea0183_glc_td1;
static int hf_nmea0183_glc_td2;
static int hf_nmea0183_glc_td3;
static int hf_nmea0183_glc_td4;
static int hf_nmea0183_glc_td5;

static int hf_nmea0183_gll_latitude;
static int hf_nmea0183_gll_latitude_degree;
static int hf_nmea0183_gll_latitude_minute;
static int hf_nmea0183_gll_latitude_direction;
static int hf_nmea0183_gll_longitude;
static int hf_nmea0183_gll_longitude_degree;
static int hf_nmea0183_gll_longitude_minute;
static int hf_nmea0183_gll_longitude_direction;
static int hf_nmea0183_gll_time;
static int hf_nmea0183_gll_time_hour;
static int hf_nmea0183_gll_time_minute;
static int hf_nmea0183_gll_time_second;
static int hf_nmea0183_gll_status;
static int hf_nmea0183_gll_mode;

static int hf_nmea0183_gmp_ant_alt;
static int hf_nmea0183_gmp_data_age;
static int hf_nmea0183_gmp_diff_ref_id;
static int hf_nmea0183_gmp_geoid_sep;
static int hf_nmea0183_gmp_hdop;
static int hf_nmea0183_gmp_mode_glonass;
static int hf_nmea0183_gmp_mode_gps;
static int hf_nmea0183_gmp_mode_other;
static int hf_nmea0183_gmp_mode_string;
static int hf_nmea0183_gmp_projection;
static int hf_nmea0183_gmp_tot_sats;
static int hf_nmea0183_gmp_utc;
static int hf_nmea0183_gmp_x_comp;
static int hf_nmea0183_gmp_y_comp;
static int hf_nmea0183_gmp_zone;

static int hf_nmea0183_gns_ant_alt;
static int hf_nmea0183_gns_data_age;
static int hf_nmea0183_gns_diff_ref_id;
static int hf_nmea0183_gns_geoid_sep;
static int hf_nmea0183_gns_hdop;
static int hf_nmea0183_gns_latitude;
static int hf_nmea0183_gns_longitude;
static int hf_nmea0183_gns_mode_glonass;
static int hf_nmea0183_gns_mode_gps;
static int hf_nmea0183_gns_mode_other;
static int hf_nmea0183_gns_mode_string;
static int hf_nmea0183_gns_tot_sats;
static int hf_nmea0183_gns_utc;

static int hf_nmea0183_grs_mode;
static int hf_nmea0183_grs_range_resid;
static int hf_nmea0183_grs_utc;

static int hf_nmea0183_gsa_fix_mode;
static int hf_nmea0183_gsa_hdop;
static int hf_nmea0183_gsa_op_mode;
static int hf_nmea0183_gsa_pdop;
static int hf_nmea0183_gsa_sat_id;
static int hf_nmea0183_gsa_sat_type;
static int hf_nmea0183_gsa_vdop;

static int hf_nmea0183_gst_time;
static int hf_nmea0183_gst_time_hour;
static int hf_nmea0183_gst_time_minute;
static int hf_nmea0183_gst_time_second;
static int hf_nmea0183_gst_rms_total_sd;
static int hf_nmea0183_gst_ellipse_major_sd;
static int hf_nmea0183_gst_ellipse_minor_sd;
static int hf_nmea0183_gst_ellipse_orientation;
static int hf_nmea0183_gst_latitude_sd;
static int hf_nmea0183_gst_longitude_sd;
static int hf_nmea0183_gst_altitude_sd;

static int hf_nmea0183_gsv_azimuth;
static int hf_nmea0183_gsv_elevation;
static int hf_nmea0183_gsv_sat_id;
static int hf_nmea0183_gsv_sat_type;
static int hf_nmea0183_gsv_sats_in_view;
static int hf_nmea0183_gsv_sentence_number;
static int hf_nmea0183_gsv_snr;
static int hf_nmea0183_gsv_total_sentences;

static int hf_nmea0183_hbt_interval;
static int hf_nmea0183_hbt_sent_id;
static int hf_nmea0183_hbt_status;

static int hf_nmea0183_hdg_mag_dev;
static int hf_nmea0183_hdg_mag_sensor;
static int hf_nmea0183_hdg_mag_var;

static int hf_nmea0183_hmr_dev_s1;
static int hf_nmea0183_hmr_dev_s2;
static int hf_nmea0183_hmr_difflim_setting;
static int hf_nmea0183_hmr_heading_s1;
static int hf_nmea0183_hmr_heading_s2;
static int hf_nmea0183_hmr_heading_sdiff;
static int hf_nmea0183_hmr_hr_s1;
static int hf_nmea0183_hmr_hr_s2;
static int hf_nmea0183_hmr_s1_type;
static int hf_nmea0183_hmr_s2_type;
static int hf_nmea0183_hmr_status_s1;
static int hf_nmea0183_hmr_status_s2;
static int hf_nmea0183_hmr_variation;
static int hf_nmea0183_hmr_warning_flag;

static int hf_nmea0183_hms_heading_s1;
static int hf_nmea0183_hms_heading_s2;
static int hf_nmea0183_hms_max_diff;

static int hf_nmea0183_hsc_heading_magnetic;
static int hf_nmea0183_hsc_heading_true;

static int hf_nmea0183_htc_cmd_offhead_lim;
static int hf_nmea0183_htc_cmd_offtrack;
static int hf_nmea0183_htc_cmd_radius;
static int hf_nmea0183_htc_cmd_rate;
static int hf_nmea0183_htc_cmd_rudder_angle;
static int hf_nmea0183_htc_cmd_rudder_dir;
static int hf_nmea0183_htc_cmd_rudder_lim;
static int hf_nmea0183_htc_cmd_steer;
static int hf_nmea0183_htc_cmd_track;
static int hf_nmea0183_htc_heading_ref;
static int hf_nmea0183_htc_override;
static int hf_nmea0183_htc_steering_mode;
static int hf_nmea0183_htc_turn_mode;

static int hf_nmea0183_htd_cmd_offhead_lim;
static int hf_nmea0183_htd_cmd_offtrack;
static int hf_nmea0183_htd_cmd_radius;
static int hf_nmea0183_htd_cmd_rate;
static int hf_nmea0183_htd_cmd_rudder_angle;
static int hf_nmea0183_htd_cmd_rudder_dir;
static int hf_nmea0183_htd_cmd_rudder_lim;
static int hf_nmea0183_htd_cmd_steer;
static int hf_nmea0183_htd_cmd_track;
static int hf_nmea0183_htd_heading_ref;
static int hf_nmea0183_htd_offhdng_status;
static int hf_nmea0183_htd_offtrack_status;
static int hf_nmea0183_htd_override;
static int hf_nmea0183_htd_rudder_status;
static int hf_nmea0183_htd_steering_mode;
static int hf_nmea0183_htd_turn_mode;
static int hf_nmea0183_htd_vessel_heading;

static int hf_nmea0183_lcd_gri;
static int hf_nmea0183_lcd_master_ecd;
static int hf_nmea0183_lcd_master_snr;
static int hf_nmea0183_lcd_s1_ecd;
static int hf_nmea0183_lcd_s1_snr;
static int hf_nmea0183_lcd_s2_ecd;
static int hf_nmea0183_lcd_s2_snr;
static int hf_nmea0183_lcd_s3_ecd;
static int hf_nmea0183_lcd_s3_snr;
static int hf_nmea0183_lcd_s4_ecd;
static int hf_nmea0183_lcd_s4_snr;
static int hf_nmea0183_lcd_s5_ecd;
static int hf_nmea0183_lcd_s5_snr;

static int hf_nmea0183_loranc_blink_snr_warning;

static int hf_nmea0183_lr1_callsign;
static int hf_nmea0183_lr1_imo_num;
static int hf_nmea0183_lr1_req_mmsi;
static int hf_nmea0183_lr1_resp_mmsi;
static int hf_nmea0183_lr1_seqnum;
static int hf_nmea0183_lr1_shipname;

static int hf_nmea0183_lr2_course_ground;
static int hf_nmea0183_lr2_date;
static int hf_nmea0183_lr2_latitude;
static int hf_nmea0183_lr2_longitude;
static int hf_nmea0183_lr2_resp_mmsi;
static int hf_nmea0183_lr2_seqnum;
static int hf_nmea0183_lr2_speed_ground;
static int hf_nmea0183_lr2_utc;

static int hf_nmea0183_lr3_destination;
static int hf_nmea0183_lr3_draught;
static int hf_nmea0183_lr3_eta_date;
static int hf_nmea0183_lr3_eta_time;
static int hf_nmea0183_lr3_persons;
static int hf_nmea0183_lr3_resp_mmsi;
static int hf_nmea0183_lr3_seqnum;
static int hf_nmea0183_lr3_ship_breadth;
static int hf_nmea0183_lr3_ship_cargo;
static int hf_nmea0183_lr3_ship_length;
static int hf_nmea0183_lr3_ship_type;

static int hf_nmea0183_lrf_function_rep;
static int hf_nmea0183_lrf_function_rep_val;
static int hf_nmea0183_lrf_function_req;
static int hf_nmea0183_lrf_function_req_val;
static int hf_nmea0183_lrf_mmsi;
static int hf_nmea0183_lrf_name;
static int hf_nmea0183_lrf_seqnum;

static int hf_nmea0183_lri_control;
static int hf_nmea0183_lri_dest_mmsi;
static int hf_nmea0183_lri_latitude_ne;
static int hf_nmea0183_lri_latitude_sw;
static int hf_nmea0183_lri_longitude_ne;
static int hf_nmea0183_lri_longitude_sw;
static int hf_nmea0183_lri_req_mmsi;
static int hf_nmea0183_lri_seqnum;

static int hf_nmea0183_mla_12lsb_corr_t_scale;
static int hf_nmea0183_mla_16msb_corr_t_scale;
static int hf_nmea0183_mla_calday_count;
static int hf_nmea0183_mla_corr_circling;
static int hf_nmea0183_mla_corr_incl_angle;
static int hf_nmea0183_mla_eccentricity;
static int hf_nmea0183_mla_long_asc_node;
static int hf_nmea0183_mla_perigee;
static int hf_nmea0183_mla_roc_circling;
static int hf_nmea0183_mla_sat_health;
static int hf_nmea0183_mla_sat_id;
static int hf_nmea0183_mla_sentence_number;
static int hf_nmea0183_mla_t_asc_node;
static int hf_nmea0183_mla_t_scale_shift;
static int hf_nmea0183_mla_total_sentences;

static int hf_nmea0183_msk_am_bitrate;
static int hf_nmea0183_msk_am_freq;
static int hf_nmea0183_msk_beacon_bitrate;
static int hf_nmea0183_msk_beacon_freq;
static int hf_nmea0183_msk_channel;
static int hf_nmea0183_msk_interval;

static int hf_nmea0183_mss_beacon_bitrate;
static int hf_nmea0183_mss_beacon_freq;
static int hf_nmea0183_mss_channel;
static int hf_nmea0183_mss_sig_str;
static int hf_nmea0183_mss_snr;

static int hf_nmea0183_mtw_temp;

static int hf_nmea0183_mwd_direction_mag;
static int hf_nmea0183_mwd_direction_true;
static int hf_nmea0183_mwd_speed_knots;
static int hf_nmea0183_mwd_speed_ms;

static int hf_nmea0183_mwv_reference;
static int hf_nmea0183_mwv_speed_units;
static int hf_nmea0183_mwv_status;
static int hf_nmea0183_mwv_wind_angle;
static int hf_nmea0183_mwv_wind_speed;

static int hf_nmea0183_osd_course_ref;
static int hf_nmea0183_osd_course_true;
static int hf_nmea0183_osd_drift;
static int hf_nmea0183_osd_heading_status;
static int hf_nmea0183_osd_heading_true;
static int hf_nmea0183_osd_set_true;
static int hf_nmea0183_osd_speed;
static int hf_nmea0183_osd_speed_ref;
static int hf_nmea0183_osd_speed_units;

static int hf_nmea0183_rma_course;
static int hf_nmea0183_rma_latitude;
static int hf_nmea0183_rma_longitude;
static int hf_nmea0183_rma_mag_var;
static int hf_nmea0183_rma_mode;
static int hf_nmea0183_rma_speed;
static int hf_nmea0183_rma_status;
static int hf_nmea0183_rma_time_diff_a;
static int hf_nmea0183_rma_time_diff_b;

static int hf_nmea0183_rmb_arrival_status;
static int hf_nmea0183_rmb_bearing_dest;
static int hf_nmea0183_rmb_data_status;
static int hf_nmea0183_rmb_dest_id;
static int hf_nmea0183_rmb_dest_velocity;
static int hf_nmea0183_rmb_dest_wp_latitude;
static int hf_nmea0183_rmb_dest_wp_longitude;
static int hf_nmea0183_rmb_mode;
static int hf_nmea0183_rmb_orig_id;
static int hf_nmea0183_rmb_range_dest;
static int hf_nmea0183_rmb_steer;
static int hf_nmea0183_rmb_xte;

static int hf_nmea0183_rmc_course;
static int hf_nmea0183_rmc_date;
static int hf_nmea0183_rmc_latitude;
static int hf_nmea0183_rmc_longitude;
static int hf_nmea0183_rmc_magnetic;
static int hf_nmea0183_rmc_mode;
static int hf_nmea0183_rmc_speed;
static int hf_nmea0183_rmc_status;
static int hf_nmea0183_rmc_utc;

static int hf_nmea0183_rot_rate_of_turn;
static int hf_nmea0183_rot_valid;

static int hf_nmea0183_rpm_number;
static int hf_nmea0183_rpm_pitch;
static int hf_nmea0183_rpm_source;
static int hf_nmea0183_rpm_speed;
static int hf_nmea0183_rpm_status;

static int hf_nmea0183_rsa_pt_sensor;
static int hf_nmea0183_rsa_pt_status;
static int hf_nmea0183_rsa_sb_sensor;
static int hf_nmea0183_rsa_sb_status;

static int hf_nmea0183_rsd_cursor_bearing;
static int hf_nmea0183_rsd_cursor_range;
static int hf_nmea0183_rsd_display;
static int hf_nmea0183_rsd_ebl1;
static int hf_nmea0183_rsd_ebl2;
static int hf_nmea0183_rsd_orig2_range;
static int hf_nmea0183_rsd_orig_bearing;
static int hf_nmea0183_rsd_orig_range;
static int hf_nmea0183_rsd_scale;
static int hf_nmea0183_rsd_units;
static int hf_nmea0183_rsd_vrm1;
static int hf_nmea0183_rsd_vrm2;

static int hf_nmea0183_rte_route;
static int hf_nmea0183_rte_sentence_mode;
static int hf_nmea0183_rte_sentence_number;
static int hf_nmea0183_rte_total_sentences;
static int hf_nmea0183_rte_waypoint;

static int hf_nmea0183_sfi_frequency;
static int hf_nmea0183_sfi_mode;
static int hf_nmea0183_sfi_sentence_number;
static int hf_nmea0183_sfi_total_sentences;

static int hf_nmea0183_ssd_callsign;
static int hf_nmea0183_ssd_dte_flag;
static int hf_nmea0183_ssd_name;
static int hf_nmea0183_ssd_ref_a;
static int hf_nmea0183_ssd_ref_b;
static int hf_nmea0183_ssd_ref_c;
static int hf_nmea0183_ssd_ref_d;
static int hf_nmea0183_ssd_source;

static int hf_nmea0183_stn_talker;

static int hf_nmea0183_tlb_label;
static int hf_nmea0183_tlb_target;

static int hf_nmea0183_tll_ref_tgt;
static int hf_nmea0183_tll_tgt_latitude;
static int hf_nmea0183_tll_tgt_longitude;
static int hf_nmea0183_tll_tgt_name;
static int hf_nmea0183_tll_utc;
static int hf_nmea0183_tll_tgt_num;
static int hf_nmea0183_tll_tgt_status;

static int hf_nmea0183_ttm_acq_type;
static int hf_nmea0183_ttm_bearing;
static int hf_nmea0183_ttm_dist_pt_approach;
static int hf_nmea0183_ttm_ref_tgt;
static int hf_nmea0183_ttm_tgt_course;
static int hf_nmea0183_ttm_tgt_dist;
static int hf_nmea0183_ttm_tgt_name;
static int hf_nmea0183_ttm_tgt_num;
static int hf_nmea0183_ttm_tgt_speed;
static int hf_nmea0183_ttm_tgt_status;
static int hf_nmea0183_ttm_time_cpa;
static int hf_nmea0183_ttm_units;
static int hf_nmea0183_ttm_utc;

static int hf_nmea0183_tut_sentence_num;
static int hf_nmea0183_tut_seq_msg;
static int hf_nmea0183_tut_src_id;
static int hf_nmea0183_tut_text;
static int hf_nmea0183_tut_total_sentences;
static int hf_nmea0183_tut_trans_code;

static int hf_nmea0183_txt_num;
static int hf_nmea0183_txt_sent_num;
static int hf_nmea0183_txt_id;
static int hf_nmea0183_txt_msg;

static int hf_nmea0183_vbw_water_speed_longitudinal;
static int hf_nmea0183_vbw_water_speed_transverse;
static int hf_nmea0183_vbw_water_speed_valid;
static int hf_nmea0183_vbw_ground_speed_longitudinal;
static int hf_nmea0183_vbw_ground_speed_transverse;
static int hf_nmea0183_vbw_ground_speed_valid;
static int hf_nmea0183_vbw_stern_water_speed;
static int hf_nmea0183_vbw_stern_water_speed_valid;
static int hf_nmea0183_vbw_stern_ground_speed;
static int hf_nmea0183_vbw_stern_ground_speed_valid;

static int hf_nmea0183_vdr_heading_magnetic;
static int hf_nmea0183_vdr_heading_true;
static int hf_nmea0183_vdr_speed;

static int hf_nmea0183_vhw_true_heading;
static int hf_nmea0183_vhw_true_heading_unit;
static int hf_nmea0183_vhw_magnetic_heading;
static int hf_nmea0183_vhw_magnetic_heading_unit;
static int hf_nmea0183_vhw_water_speed_knot;
static int hf_nmea0183_vhw_water_speed_knot_unit;
static int hf_nmea0183_vhw_water_speed_kilometer;
static int hf_nmea0183_vhw_water_speed_kilometer_unit;

static int hf_nmea0183_vlw_cumulative_water;
static int hf_nmea0183_vlw_cumulative_water_unit;
static int hf_nmea0183_vlw_trip_water;
static int hf_nmea0183_vlw_trip_water_unit;
static int hf_nmea0183_vlw_cumulative_ground;
static int hf_nmea0183_vlw_cumulative_ground_unit;
static int hf_nmea0183_vlw_trip_ground;
static int hf_nmea0183_vlw_trip_ground_unit;

static int hf_nmea0183_vpw_speed_knots;
static int hf_nmea0183_vpw_speed_ms;

static int hf_nmea0183_vsd_app_flags;
static int hf_nmea0183_vsd_day_arrival;
static int hf_nmea0183_vsd_destination;
static int hf_nmea0183_vsd_max_draught;
static int hf_nmea0183_vsd_month_arrival;
static int hf_nmea0183_vsd_nav_status;
static int hf_nmea0183_vsd_persons;
static int hf_nmea0183_vsd_ship_cargo;
static int hf_nmea0183_vsd_utc_arrival;

static int hf_nmea0183_vtg_true_course;
static int hf_nmea0183_vtg_true_course_unit;
static int hf_nmea0183_vtg_magnetic_course;
static int hf_nmea0183_vtg_magnetic_course_unit;
static int hf_nmea0183_vtg_ground_speed_knot;
static int hf_nmea0183_vtg_ground_speed_knot_unit;
static int hf_nmea0183_vtg_ground_speed_kilometer;
static int hf_nmea0183_vtg_ground_speed_kilometer_unit;
static int hf_nmea0183_vtg_mode;

static int hf_nmea0183_wcv_mode;
static int hf_nmea0183_wcv_velocity;
static int hf_nmea0183_wcv_waypoint;

static int hf_nmea0183_wnc_dist_km;
static int hf_nmea0183_wnc_dist_nm;
static int hf_nmea0183_wnc_from_id;
static int hf_nmea0183_wnc_to_id;

static int hf_nmea0183_wpl_latitude;
static int hf_nmea0183_wpl_longitude;
static int hf_nmea0183_wpl_waypoint;

static int hf_nmea0183_xdr_data;
static int hf_nmea0183_xdr_id;
static int hf_nmea0183_xdr_type;
static int hf_nmea0183_xdr_units;

static int hf_nmea0183_xte_blinksnr_status;
static int hf_nmea0183_xte_cycle_status;
static int hf_nmea0183_xte_magnitude;
static int hf_nmea0183_xte_direction;
static int hf_nmea0183_xte_mode;

static int hf_nmea0183_xtr_direction;
static int hf_nmea0183_xtr_magnitude;

static int hf_nmea0183_zda_time;
static int hf_nmea0183_zda_time_hour;
static int hf_nmea0183_zda_time_minute;
static int hf_nmea0183_zda_time_second;
static int hf_nmea0183_zda_date_day;
static int hf_nmea0183_zda_date_month;
static int hf_nmea0183_zda_date_year;
static int hf_nmea0183_zda_local_zone_hour;
static int hf_nmea0183_zda_local_zone_minute;

static int hf_nmea0183_zdl_dist;
static int hf_nmea0183_zdl_time;
static int hf_nmea0183_zdl_type;

static int hf_nmea0183_zfo_elapsed;
static int hf_nmea0183_zfo_origin;
static int hf_nmea0183_zfo_utc;

static int hf_nmea0183_ztg_dest;
static int hf_nmea0183_ztg_time_left;
static int hf_nmea0183_ztg_utc;

static int hf_nmea0183_sentence_prefix;
static int hf_nmea0183_tag_block;
static int hf_nmea0183_bin_version;
static int hf_nmea0183_bin_srcid;
static int hf_nmea0183_bin_dstid;
static int hf_nmea0183_bin_mtype;
static int hf_nmea0183_bin_blockid;
static int hf_nmea0183_bin_seqnum;
static int hf_nmea0183_bin_max_seqnum;
static int hf_nmea0183_bin_data;
static int hf_nmea0183_bin_file_descriptor;
static int hf_nmea0183_bin_file_descriptor_len;
static int hf_nmea0183_bin_file_length;
static int hf_nmea0183_bin_stat_of_acquisition;
static int hf_nmea0183_bin_device;
static int hf_nmea0183_bin_channel;
static int hf_nmea0183_bin_type_len;
static int hf_nmea0183_bin_data_type;
static int hf_nmea0183_bin_status_and_info;

static int ett_nmea0183;
static int ett_nmea0183_checksum;
static int ett_nmea0183_sentence;
static int ett_nmea0183_zda_time;
static int ett_nmea0183_alr_time;
static int ett_nmea0183_gga_time;
static int ett_nmea0183_gga_latitude;
static int ett_nmea0183_gga_longitude;
static int ett_nmea0183_gll_time;
static int ett_nmea0183_gll_latitude;
static int ett_nmea0183_gll_longitude;
static int ett_nmea0183_gst_time;
static int ett_nmea0183_tag_block;
static int ett_nmea0183_fd;
static int ett_nmea0183_legacy_satellite_info;

static expert_field ei_nmea0183_invalid_first_character;
static expert_field ei_nmea0183_missing_checksum_character;
static expert_field ei_nmea0183_invalid_end_of_line;
static expert_field ei_nmea0183_checksum_incorrect;
static expert_field ei_nmea0183_sentence_too_long;
static expert_field ei_nmea0183_field_time_too_short;
static expert_field ei_nmea0183_field_latitude_too_short;
static expert_field ei_nmea0183_field_longitude_too_short;
static expert_field ei_nmea0183_field_missing;
static expert_field ei_nmea0183_field_uint_invalid;
static expert_field ei_nmea0183_sat_prn_invalid;
static expert_field ei_nmea0183_gga_altitude_unit_incorrect;
static expert_field ei_nmea0183_gga_geoidal_separation_unit_incorrect;
static expert_field ei_nmea0183_hdt_unit_incorrect;
static expert_field ei_nmea0183_vhw_true_heading_unit_incorrect;
static expert_field ei_nmea0183_vhw_magnetic_heading_unit_incorrect;
static expert_field ei_nmea0183_vhw_water_speed_knot_unit_incorrect;
static expert_field ei_nmea0183_vhw_water_speed_kilometer_unit_incorrect;
static expert_field ei_nmea0183_vlw_cumulative_water_unit_incorrect;
static expert_field ei_nmea0183_vlw_trip_water_unit_incorrect;
static expert_field ei_nmea0183_vlw_cumulative_ground_unit_incorrect;
static expert_field ei_nmea0183_vlw_trip_ground_unit_incorrect;
static expert_field ei_nmea0183_vtg_true_course_unit_incorrect;
static expert_field ei_nmea0183_vtg_magnetic_course_unit_incorrect;
static expert_field ei_nmea0183_vtg_ground_speed_knot_unit_incorrect;
static expert_field ei_nmea0183_vtg_ground_speed_kilometer_unit_incorrect;
static expert_field ei_nmea0183_legacy_nonstandard;
static expert_field ei_nmea0183_legacy_empty_response;

static int proto_nmea0183;
static int proto_nmea0183_bin;

static dissector_handle_t nmea0183_handle;

// List of known Talker IDs (Source: NMEA Revealed by Eric S. Raymond, https://gpsd.gitlab.io/gpsd/NMEA.html, retrieved 2023-01-26)
static const string_string known_talker_ids[] = {
    {"AB", "Independent AIS Base Station"},
    {"AD", "Dependent AIS Base Station"},
    {"AG", "Autopilot - General"},
    {"AI", "Mobile AIS Station"},
    {"AN", "AIS Aid to Navigation"},
    {"AP", "Autopilot - Magnetic"},
    {"AR", "AIS Receiving Station"},
    {"AT", "AIS Transmitting Station"},
    {"AX", "AIS Simplex Repeater"},
    {"BD", "BeiDou (China)"},
    {"BI", "Bilge System"},
    {"BN", "Bridge navigational watch alarm system"},
    {"BS", "Base AIS Station"},
    {"CA", "Central Alarm"},
    {"CC", "Computer - Programmed Calculator (obsolete)"},
    {"CD", "Communications - Digital Selective Calling (DSC)"},
    {"CM", "Computer - Memory Data (obsolete)"},
    {"CR", "Communications - Data Receiver"},
    {"CS", "Communications - Satellite"},
    {"CT", "Communications - Radio-Telephone (MF/HF)"},
    {"CV", "Communications - Radio-Telephone (VHF)"},
    {"CX", "Communications - Scanning Receiver"},
    {"DE", "DECCA Navigation (obsolete)"},
    {"DF", "Direction Finder"},
    {"DM", "Velocity Sensor, Speed Log, Water, Magnetic"},
    {"DP", "Dynamiv Position"},
    {"DU", "Duplex repeater station"},
    {"EC", "Electronic Chart System (ECS)"},
    {"EI", "Electronic Chart Display & Information System (ECDIS)"},
    {"EP", "Emergency Position Indicating Beacon (EPIRB)"},
    {"ER", "Engine Room Monitoring Systems"},
    {"FD", "Fire Door"},
    {"FE", "Fire Extinguisher System"},
    {"FR", "Fire Detection System"},
    {"FS", "Fire Sprinkler"},
    {"GA", "Galileo Positioning System"},
    {"GB", "BeiDou (China)"},
    {"GI", "NavIC, IRNSS (India)"},
    {"GL", "GLONASS, according to IEIC 61162-1"},
    {"GN", "Combination of multiple satellite systems (NMEA 1083)"},
    {"GP", "Global Positioning System receiver"},
    {"GQ", "QZSS regional GPS augmentation system (Japan)"},
    {"HC", "Heading - Magnetic Compass"},
    {"HD", "Hull Door"},
    {"HE", "Heading - North Seeking Gyro"},
    {"HF", "Heading - Fluxgate"},
    {"HN", "Heading - Non North Seeking Gyro"},
    {"HS", "Hull Stress"},
    {"II", "Integrated Instrumentation"},
    {"IN", "Integrated Navigation"},
    {"JA", "Alarm and Monitoring"},
    {"JB", "Water Monitoring"},
    {"JC", "Power Management"},
    {"JD", "Propulsion Control"},
    {"JE", "Engine Control"},
    {"JF", "Propulsion Boiler"},
    {"JG", "Aux Boiler"},
    {"JH", "Engine Governor"},
    {"LA", "Loran A (obsolete)"},
    {"LC", "Loran C (obsolete)"},
    {"MP", "Microwave Positioning System (obsolete)"},
    {"MX", "Multiplexer"},
    {"NL", "Navigation light controller"},
    {"NV", "Night Vision"},
    {"OM", "OMEGA Navigation System (obsolete)"},
    {"OS", "Distress Alarm System (obsolete)"},
    {"P ", "Vendor specific"},
    {"QZ", "QZSS regional GPS augmentation system (Japan)"},
    {"RA", "RADAR and/or ARPA"},
    {"RB", "Record Book"},
    {"RC", "Propulsion Machinery including Remote Control"},
    {"RI", "Rudder Angle Indicator"},
    {"SA", "Physical Shore AUS Station"},
    {"SC", "Steering Control System/Device"},
    {"SD", "Depth Sounder"},
    {"SG", "Steering Gear"},
    {"SN", "Electronic Positioning System, other/general"},
    {"SS", "Scanning Sounder"},
    {"ST", "Skytraq debug output"},
    {"TC", "Track Control"},
    {"TI", "Turn Rate Indicator"},
    {"TR", "TRANSIT Navigation System"},
    {"U0", "User Configured 0"},
    {"U1", "User Configured 1"},
    {"U2", "User Configured 2"},
    {"U3", "User Configured 3"},
    {"U4", "User Configured 4"},
    {"U5", "User Configured 5"},
    {"U6", "User Configured 6"},
    {"U7", "User Configured 7"},
    {"U8", "User Configured 8"},
    {"U9", "User Configured 9"},
    {"UP", "Microprocessor controller"},
    {"VA", "VHF Data Exchange System (VDES), ASM"},
    {"VD", "Velocity Sensor, Doppler, other/general"},
    {"VM", "Velocity Sensor, Speed Log, Water, Magnetic"},
    {"VR", "Voyage Data recorder"},
    {"VS", "VHF Data Exchange System (VDES), Satellite"},
    {"VT", "VHF Data Exchange System (VDES), Terrestrial"},
    {"VW", "Velocity Sensor, Speed Log, Water, Mechanical"},
    {"WD", "Watertight Door"},
    {"WI", "Weather Instruments"},
    {"WL", "Water Level"},
    {"YC", "Transducer - Temperature (obsolete)"},
    {"YD", "Transducer - Displacement, Angular or Linear (obsolete)"},
    {"YF", "Transducer - Frequency (obsolete)"},
    {"YL", "Transducer - Level (obsolete)"},
    {"YP", "Transducer - Pressure (obsolete)"},
    {"YR", "Transducer - Flow Rate (obsolete)"},
    {"YT", "Transducer - Tachometer (obsolete)"},
    {"YV", "Transducer - Volume (obsolete)"},
    {"YX", "Transducer"},
    {"ZA", "Timekeeper - Atomic Clock"},
    {"ZC", "Timekeeper - Chronometer"},
    {"ZQ", "Timekeeper - Quartz"},
    {"ZV", "Timekeeper - Radio Update, WWV or WWVH"},
    {NULL, NULL}};

// List of known Sentence IDs (Source: NMEA Revealed by Eric S. Raymond, https://gpsd.gitlab.io/gpsd/NMEA.html, retrieved 2023-01-26)
static const string_string known_sentence_ids[] = {
    {"AAM", "Waypoint Arrival Alarm"},
    {"ABK", "UAIS Addressed and Binary Broadcast Acknowledgement"},
    {"ACA", "UAIS Regional Channel Assignment Message"},
    {"ACF", "General AtoN Station Configuration Command"},
    {"ACG", "Extended General AtoN Station Configuration Command"},
    {"ACK", "Alarm Acknowledgement"},
    {"ACM", "Preparation and Initiation of an AIS Base Station Addressed Channel Management Message (Message 22)"},
    {"ACS", "UAIS Channel Management Information Source"},
    {"ADS", "Automatic Device Status"},
    {"AFB", "AtoN Forced Broadcast Command"},
    {"AGA", "Preparation and Initiation of an AIS Base Station Broadcast of a Group Assignment Message (Message 23)"},
    {"AID", "AtoN Identification Configuration Command"},
    {"AIR", "UAIS Interrogation Request"},
    {"AKD", "Acknowledge Detail Alarm Condition"},
    {"ALA", "Set Detail Alarm Condition"},
    {"ALM", "GPS Almanac Data"},
    {"ALR", "Set Alarm State"},
    {"ARC", "Alert Command Refused"},
    {"APA", "Autopilot Sentence A"},
    {"APB", "Autopilot Sentence B"},
    {"ASD", "Autopilot System Data"},
    {"ASN", "Preparation and Initiation of an AIS Base Station Broadcast of Assignment VDL (Message 16)"},
    {"BBM", "AIS Broadcast BinaryMessage"},
    {"BCG", "Base Station Configuration, General Command"},
    {"BCL", "Base Station Configuration, Location Command"},
    {"BEC", "Bearing & Distance to Waypoint - Dead Reckoning"},
    {"BER", "Bearing & Distance to Waypoint, Dead Reckoning, Rhumb Line"},
    {"BOD", "Bearing - Waypoint to Waypoint"},
    {"BPI", "Bearing & Distance to Point of Interest"},
    {"BWC", "Bearing & Distance to Waypoint - Great Circle"},
    {"BWR", "Bearing and Distance to Waypoint - Rhumb Line"},
    {"BWW", "Bearing - Waypoint to Waypoint"},
    {"CBR", "Configure Broadcast Rates for AIS AtoN Station Message Command"},
    {"CEK", "Configure Encryption Key Command"},
    {"COP", "Configure the Operational Period, Command"},
    {"CPC", "Configure Parameter-Code for UNIX Time Parameter (c)"},
    {"CPD", "Configure Parameter-Code for Destination-Identification Parameter (d)"},
    {"CPG", "Configure Parameter-Code for the Sentence-Grouping Parameter (g)"},
    {"CPN", "Configure Parameter-Code for the Line-Count Parameter (n)"},
    {"CPR", "Configure Parameter-Code for Relative Time Parameter (r)"},
    {"CPS", "Configure Parameter-Code for the Source-Identification Parameter (s)"},
    {"CPT", "Configure Parameter-Code for General Alphanumeric String Parameter (t)"},
    {"CUR", "Water Current Layer"},
    {"DBK", "Echosounder - Depth Below Keel"},
    {"DBS", "Echosounder - Depth Below Surface"},
    {"DBT", "Echosounder - Depth Below Transducer"},
    {"DCN", "DECCA Position"},
    {"DCR", "Device Capability Report"},
    {"DDC", "Display Dimming Control"},
    {"DLM", "Data Link Management Slot Allocations for Base Station"},
    {"DOR", "Door Status Detection"},
    {"DPT", "Depth of Water"},
    {"DRU", "Dual Doppler Auxiliary Data"},
    {"DSC", "Digital Selective Calling Information"},
    {"DSE", "Extended DSC"},
    {"DSI", "DSC Transponder Initiate"},
    {"DSR", "DSC Transponder Response"},
    {"DTM", "Datum Reference"},
    {"ECB", "Configure Broadcast Rates for Base Station Messages with Epoch Planning Support"},
    {"ETL", "Engine Telegraph Operation Status"},
    {"EVE", "General Event Message"},
    {"FIR", "Fire Detection"},
    {"FSI", "Frequency Set Information"},
    {"FSR", "Frame Summary of AIS Reception"},
    {"GAL", "Galileo Almanac Data"},
    {"GBS", "GPS Satellite Fault Detection"},
    {"GDA", "Dead Reckoning Positions"},
    {"GEN", "Generic Binary/Status Information"},
    {"GFA", "GNSS Fix Accuracy and Integrity"},
    {"GGA", "Global Positioning System Fix Data"},
    {"GLA", "Loran-C Positions"},
    {"GLC", "Geographic Position, Loran-C"},
    {"GLL", "Geographic Position - Latitude/Longitude"},
    {"GMP", "GNSS Map Projection Fix Data"},
    {"GNS", "GNSS Fix data"},
    {"GOA", "OMEGA Positions"},
    {"GRS", "GNSS Range Residuals"},
    {"GSA", "GNSS DOP and Active Satellites"},
    {"GST", "GNSS Pseudorange Noise Statistics"},
    {"GSV", "GNSS Satellites in View"},
    {"GTD", "Geographic Location in Time Differences"},
    {"GXA", "TRANSIT Position"},
    {"HBT", "Heartbeat Supervision Report"},
    {"HCC", "Compass Heading"},
    {"HCD", "Heading and Deviation"},
    {"HDG", "Heading - Deviation & Variation"},
    {"HDM", "Heading - Magnetic"},
    {"HDT", "Heading - True"},
    {"HFB", "Trawl Headrope to Footrope and Bottom"},
    {"HMR", "Heading, Monitor Receive"},
    {"HMS", "Heading, Monitor Set"},
    {"HSC", "Heading Steering Command"},
    {"HSS", "Hull Stress Surveillance Systems"},
    {"HTC", "Heading/Track Control Command"},
    {"HTD", "Heading/Track Control Data"},
    {"HVD", "Magnetic Variation, Automatic"},
    {"HVM", "Magnetic Variation, Manually Set"},
    {"IMA", "Vessel Identification"},
    {"ITS", "Trawl Door Spread 2 Distance"},
    {"LCD", "Loran-C Signal Data"},
    {"LR1", "UAIS Long-range Reply Sentence 1"},
    {"LR2", "UAIS Long-range Reply Sentence 2"},
    {"LR3", "UAIS Long-range Reply Sentence 3"},
    {"LRF", "UAIS Long-Range Function"},
    {"LRI", "UAIS Long-Range Interrogation"},
    {"LTI", "UAIS Long-Range Interrogation"},
    {"MDA", "Meteorological Composite"},
    {"MEB", "Message Input for Broadcast, Command"},
    {"MHU", "Humidity"},
    {"MLA", "GLONASS Almanac Data"},
    {"MMB", "Barometer"},
    {"MSK", "Control for a Beacon Receiver"},
    {"MSS", "Beacon Receiver Status"},
    {"MTA", "Air Temperature"},
    {"MTW", "Mean Temperature of Water"},
    {"MWD", "Wind Direction & Speed"},
    {"MWH", "Wave Height"},
    {"MWS", "Wind & Sea State"},
    {"MWV", "Wind Speed and Angle"},
    {"NAK", "Negative Acknowledgement"},
    {"NRM", "NAVTEX Receiver Mask"},
    {"NRX", "NAVTEX Received Message"},
    {"ODC", "Echosounder - ODEC DPT Format"},
    {"OLN", "Omega Lane Numbers"},
    {"OLW", "Omega Lane Width"},
    {"OMP", "Omega Position"},
    {"OSD", "Own Ship Data"},
    {"OZN", "Omega Zone Number"},
    {"POS", "Device Position and Ship Dimensions Report or Configuration Command"},
    {"PRC", "Propulsion Remote Control Status"},
    {"R00", "Waypoints in active route"},
    {"RLM", "Return Link Message"},
    {"RMA", "Recommended Minimum Specific Loran-C Data"},
    {"RMB", "Recommended Minimum Navigation Information"},
    {"RMC", "Recommended Minimum Specific GNSS Data"},
    {"RNN", "Routes"},
    {"ROO", "Waypoints in Active Route"},
    {"ROR", "Rudder Order Status"},
    {"ROT", "Rate Of Turn"},
    {"RPM", "Revolutions"},
    {"RSA", "Rudder Sensor Angle"},
    {"RSD", "RADAR System Data"},
    {"RST", "Equipment Reset Command"},
    {"RTE", "Routes"},
    {"SBK", "Loran-C Blink Status"},
    {"SCD", "Loran-C ECDs"},
    {"SCY", "Loran-C Cycle Lock Status"},
    {"SDB", "Loran-C Signal Strength"},
    {"SFI", "Scanning Frequency Information"},
    {"SGD", "Position Accuracy Estimate"},
    {"SGR", "Loran-C Chain Identifier"},
    {"SID", "Set an Equipment's Identification, Command"},
    {"SIU", "Loran-C Stations in Use"},
    {"SLC", "Loran-C Status"},
    {"SNC", "Navigation Calculation Basis"},
    {"SNU", "Loran-C SNR Status"},
    {"SPO", "Select AIS Device's Processing and Output"},
    {"SPS", "Loran-C Predicted Signal Strength"},
    {"SSD", "UAIS Ship Static Data"},
    {"SSF", "Position Correction Offset"},
    {"STC", "Time Constant"},
    {"STN", "Multiple Data ID"},
    {"STR", "Tracking Reference"},
    {"SYS", "Hybrid System Configuration"},
    {"TBR", "TAG Block Report"},
    {"TBS", "TAG Block Listener Source-Identification Configuration Command"},
    {"TDS", "Trawl Door Spread Distance"},
    {"TEC", "TRANSIT Satellite Error Code & Doppler Count"},
    {"TEP", "TRANSIT Satellite Predicted Elevation"},
    {"TFI", "Trawl Filling Indicator"},
    {"TFR", "Transmit Feedback Report"},
    {"TGA", "TRANSIT Satellite Antenna & Geoidal Heights"},
    {"THS", "True Heading and Status"},
    {"TIF", "TRANSIT Satellite Initial Flag"},
    {"TLB", "Target Label"},
    {"TLL", "Target Latitude and Longitude"},
    {"TPC", "Trawl Position Cartesian Coordinates"},
    {"TPR", "Trawl Position Relative Vessel"},
    {"TPT", "Trawl Position True"},
    {"TRC", "Thruster Control Data"},
    {"TRD", "Thruster Response Data"},
    {"TRF", "TRANSIT Fix Data"},
    {"TRP", "TRANSIT Satellite Predicted Direction of Rise"},
    {"TRS", "TRANSIT Satellite Operating Status"},
    {"TSA", "Transmit Slot Assignment"},
    {"TSP", "Transmit Slot Prohibit"},
    {"TSR", "Transmit Slot Prohibit - Status Report"},
    {"TTD", "Tracked Target Data"},
    {"TTM", "Tracked Target Message"},
    {"TUT", "Transmission of Multi-Language Text"},
    {"TXT", "Text Transmission"},
    {"UID", "User Identification Code Transmission"},
    {"VBW", "Dual Ground/Water Speed"},
    {"VCD", "Current at Selected Depth"},
    {"VDR", "Set and Drift"},
    {"VER", "Version"},
    {"VHW", "Water Speed and Heading"},
    {"VLW", "Distance Traveled through Water"},
    {"VPE", "Speed, Dead Reckoned Parallel to True Wind"},
    {"VPW", "Speed, Measured Parallel to Wind"},
    {"VSD", "UAIS Voyage Static Data"},
    {"VSI", "VDL Signal Information"},
    {"VTA", "Actual Track"},
    {"VTG", "Track made good and Ground speed"},
    {"VTI", "Intended Track"},
    {"VWE", "Wind Track Efficiency"},
    {"VWR", "Relative Wind Speed and Angle"},
    {"VWT", "True Wind Speed and Angle"},
    {"WAT", "Water Level Detection"},
    {"WCV", "Waypoint Closure Velocity"},
    {"WDC", "Distance to Waypoint - Great Circle"},
    {"WDR", "Distance to Waypoint - Rhumb Line"},
    {"WFM", "Route Following Mode"},
    {"WNC", "Distance - Waypoint to Waypoint"},
    {"WNR", "Waypoint-to-Waypoint Distance, Rhumb Line"},
    {"WPL", "Waypoint Location"},
    {"XDR", "Transducer Measurement"},
    {"XTE", "Cross-Track Error, Measured"},
    {"XTR", "Cross Track Error - Dead Reckoning"},
    {"YWP", "Water Propagation Speed"},
    {"YWS", "Water Profile"},
    {"ZAA", "Time, Elapsed/Estimated"},
    {"ZCD", "Timer"},
    {"ZDA", "Time & Date - UTC, day, month, year and local time zone"},
    {"ZDL", "Time and Distance to Variable Point"},
    {"ZEV", "Event Timer"},
    {"ZFO", "UTC & Time from origin Waypoint"},
    {"ZLZ", "Time of Day"},
    {"ZTG", "UTC & Time to Destination Waypoint"},
    {"ZZU", "Time, UTC"},
    {NULL, NULL}};

/* Proprietary Manufacturer Mnemonic Coder lookup table */
/* https://web.nmea.org/External/WCPages/WCWebContent/webcontentpage.aspx?ContentID=364 */
static const string_string manufacturer_vals[] = {
    {"3SN", "3-S Navigation"},
    {"AAB", "ASM Selective Addressed Message (Reserved for Future Use)"},
    {"AAR", "Asian American Resources"},
    {"ABB", "ASM Broadcast Message (Reserved for Future Use)"},
    {"ACE", "Auto-Comm Engineering Corporation"},
    {"ACR", "ACR Electronics, Inc."},
    {"ACS", "Arco Solar Inc."},
    {"ACT", "Advanced Control Technology"},
    {"ADI", "Aditel"},
    {"ADM", "ASM VHF Data-Link Message (Reserved for Future Use)"},
    {"ADN", "AD Navigation"},
    {"ADO", "ASM VHF Data-Link Own-Vessel Report (Reserved for Future Use"},
    {"AGB", "ASM Geographical Multicast Message (Reserved for Future Use"},
    {"AGI", "Airguide Instrument Co."},
    {"AGL", "Alert Group List (Reserved for Future Use)"},
    {"AHA", "Autohelm of America"},
    {"AIP", "AIPHONE Corporation"},
    {"ALD", "Alden Electronics, Inc."},
    {"AMB", "Ambarella, Inc. "},
    {"AMC", "AllTek Marine Electronics Corp."},
    {"AMI", "Advanced Marine Instrumentation, Ltd."},
    {"AMK", "ASM Addressed and Broadcast Message Acknowledgement (Reserved for Future Use)"},
    {"AMM", "Aquametro Oil & Marine"},
    {"AMR", "AMR Systems"},
    {"AMT", "Airmar Technology Corporation"},
    {"AND", "Andrew Corporation"},
    {"ANI", "Autonautic Instrumental Sl. (Spain)"},
    {"ANS", "Antenna Specialists"},
    {"ANX", "Analytyx Electronic Systems"},
    {"ANZ", "Anschutz of America"},
    {"AOB", "Aerobytes, Ltd."},
    {"APC", "Apelco Electronics & Navigation"},
    {"APN", "American Pioneer, Inc."},
    {"APO", "Automated Procedure Options (Reserved for Future Use)"},
    {"APW", "Pharos Marine Automatic Power"},
    {"APX", "Amperex, Inc."},
    {"AQC", "Aqua-Chem, Inc."},
    {"AQD", "AquaDynamics, Inc."},
    {"AQM", "Aqua Meter Instrument Corp."},
    {"ARL", "Active Research, Ltd."},
    {"ART", "Arlt Technologies, GmbH (Germany)"},
    {"ARV", "Arvento Mobile Systems"},
    {"ASH", "Ashtech"},
    {"ASP", "American Solar Power"},
    {"ATC", "Advanced C Technology, Ltd."},
    {"ATE", "Aetna Engineering"},
    {"ATM", "Atlantic Marketing Company"},
    {"ATR", "Airtron"},
    {"ATV", "Activation, Inc."},
    {"AUC", "Automated Procedure Control (Reserved for Future Use)"},
    {"AUP", "Automated Procedure Query (Reserved for Future Use)"},
    {"AUS", "Automated Procedure Status (Reserved for Future Use)"},
    {"AVN", "Advanced Navigation, Inc."},
    {"AWA", "Awa New Zealand, Ltd."},
    {"AXN", "Axiom Navigation, Inc."},
    {"BBG", "BBG, Inc."},
    {"BBL", "BBL Industries, Inc."},
    {"BBR", "BBR and Associates"},
    {"BDV", "Brisson Development, Inc."},
    {"BEC", "Boat Electric Corporation"},
    {"BFA", "Blueflow Americas"},
    {"BGG", "Bodensee Gravitymeter Geo-Systems (BGS)"},
    {"BGS", "Barringer Geoservice"},
    {"BGT", "Brookes and Gatehouse, Inc."},
    {"BHE", "BH Electronics"},
    {"BHR", "Bahr Technologies, Inc."},
    {"BLB", "Bay Laboratories"},
    {"BMC", "BMC"},
    {"BME", "Bartel Marine Electronics"},
    {"BMS", "Becker Marine Systems"},
    {"BMT", "Aventics GmbH (formerly Bosch Rexroth AG Marine Technique) (Germany)"},
    {"BNI", "Neil Brown Instrument Systems"},
    {"BNS", "Bowditch Navigation Systems"},
    {"BRM", "Mel Barr Company"},
    {"BRO", "Broadgate, Ltd."},
    {"BRY", "Byrd Industries"},
    {"BTH", "Benthos, Inc."},
    {"BTK", "Baltek Corporation"},
    {"BTS", "Boat Sentry, Inc."},
    {"BVE", "BV Engineering"},
    {"BXA", "Bendix-Avalex, Inc."},
    {"CAI", "Cambridge Aero Instruments"},
    {"CAT", "Catel"},
    {"CBN", "Cybernet Marine Products"},
    {"CCA", "Copal Corporation of America"},
    {"CCC", "Coastel Communications Company"},
    {"CCL", "Coastal Climate Company"},
    {"CCM", "Coastal Communications"},
    {"CDC", "Cordic Company"},
    {"CDI", "Chetco Digital Instruments"},
    {"CDL", "Teledyne CDL (CDLTD), Inc."},
    {"CDS", "Central Dimming Set (Reserved for Future Use)"},
    {"CEC", "Ceco Communications, Inc."},
    {"CEI", "Cambridge Engineering, Inc."},
    {"CFS", "Carlisle and Finch Company"},
    {"CHI", "Charles Industries, Ltd."},
    {"CIN", "Canadian Automotive Instruments"},
    {"CKM", "Cinkel Marine Electronics"},
    {"CLR", "Colorlight AB"},
    {"CMA", "Soc Nouvelle D'equip Calvados"},
    {"CMC", "Coe Manufacturing Company"},
    {"CME", "Cushman Electronics, Inc."},
    {"CML", "CML Microsystems PLC"},
    {"CMN", "ComNav Marine, Ltd."},
    {"CMP", "C-MAP, s.r.l. (Italy)"},
    {"CMS", "Coastal Marine Sales Company"},
    {"CMV", "Coursemaster USA, Inc."},
    {"CNI", "Continental Instruments"},
    {"CNS", "CNS Systems AB (Sweden)"},
    {"CNV", "Coastal Navigator"},
    {"CNX", "Cynex Manufacturing Company"},
    {"CPL", "Computrol, Inc."},
    {"CPN", "CompuNav"},
    {"CPS", "Columbus Positioning, Ltd."},
    {"CPT", "CPT, Inc."},
    {"CRE", "Crystal Electronics, Ltd."},
    {"CRO", "The Caro Group"},
    {"CRY", "Crystek Crystals Corporation"},
    {"CSI", "Communication Systems International"},
    {"CSM", "COMSAT Maritime Services"},
    {"CSR", "CSR Stockholm"},
    {"CSS", "CNS, Inc."},
    {"CST", "CAST, Inc."},
    {"CSV", "Combined Services"},
    {"CTA", "Current Alternatives"},
    {"CTB", "Cetec Benmar"},
    {"CTC", "Cell-Tech Communications"},
    {"CTE", "Castle Electronics"},
    {"CTL", "C-Tech, Ltd."},
    {"CTS", "C-Tech Systems"},
    {"CUL", "Cyclic Procedure List (Reserved for Future Use)"},
    {"CUS", "Customware"},
    {"CWD", "Cubic Western Data"},
    {"CWF", "Hamilton Jet"},
    {"CWV", "Celwave RF, Inc."},
    {"CYL", "Cyclic Procedure List (Reserved for Future Use)"},
    {"CYZ", "CYZ, Inc."},
    {"DAN", "Danelec Marine A/S (Denmark)"},
    {"DAS", "Dassault Sercel Navigation-Positioning"},
    {"DBM", "Deep Blue Marine"},
    {"DCC", "Dolphin Components Corporation"},
    {"DEB", "Debeg GmbH (Germany)"},
    {"DEC", "Decca Division, Litton Marine Systems BV"},
    {"DFI", "Defender Industries, Inc."},
    {"DGC", "Digicourse, Inc."},
    {"DGY", "Digital Yacht, Ltd."},
    {"DGP", "Digpilot A/S (Norway)"},
    {"DME", "Delorme"},
    {"DMI", "Datamarine International"},
    {"DNS", "Dornier System"},
    {"DNT", "Del Norte Technology, Inc."},
    {"DOI", "Digital Oceans, Inc."},
    {"DPC", "Data Panel Corporation"},
    {"DPS", "Danaplus, Inc."},
    {"DRL", "RL Drake Company"},
    {"DSC", "Dynascan Corporation"},
    {"DTN", "Dytechna, Ltd."},
    {"DYN", "Dynamote Corporation"},
    {"DYT", "Dytek Laboratories, Inc."},
    {"EAN", "EuroAvionics Navigation Systems GmbH (Germany)"},
    {"EBC", "Emergency Beacon Corporation"},
    {"ECI", "Enhanced Selective Calling Information (Reserved for Future Use)"},
    {"ECR", "Escort, Inc."},
    {"ECT", "Echotec, Inc."},
    {"EDO", "EDO Corporation, Electroacoustics Division"},
    {"EEL", "Electronica Eutimio Sl. (Spain)"},
    {"EEV", "EEV, Inc."},
    {"EFC", "Efcom Communication Systems"},
    {"EKC", "Eastman Kodak"},
    {"ELA", "Wartsila Elac Nautik GmbH (Germany)"},
    {"ELD", "Electronic Devices, Inc."},
    {"ELM", "ELMAN, s.r.l. (Italy)"},
    {"EMC", "Electric Motion Company"},
    {"EMK", "E-Marine Company, Ltd."},
    {"EMR", "EMRI A/S (Denmark)"},
    {"EMS", "Electro Marine Systems, Inc."},
    {"ENA", "Energy Analysts, Inc."},
    {"ENC", "Encron, Inc."},
    {"EPM", "EPSCO Marine"},
    {"EPT", "Eastprint, Inc."},
    {"ERC", "The Ericsson Corporation"},
    {"ERD", "eRide, Inc."},
    {"ESA", "European Space Agency"},
    {"ESC", "Electronics Emporium Division of ESC Products"},
    {"ESY", "E-Systems ECI Division"},
    {"FDN", "FluiDyne"},
    {"FEC", "Furuno Electric Company"},
    {"FHE", "Fish Hawk Electronics"},
    {"FJN", "Jon Fluke Company"},
    {"FLA", "Flarm Technology GmbH (Germany)"},
    {"FLO", "Floscan, Inc."},
    {"FMM", "First Mate Marine Autopilots"},
    {"FMS", "Fugro Seastar A/S (MarineStar)"},
    {"FNT", "Franklin Net and Twine, Ltd."},
    {"FRC", "The Fredericks Company"},
    {"FSS", "Frequency Selection (Reserved for Future Use)"},
    {"FST", "Fastrax OY (Switzerland)"},
    {"FTG", "Thomas G Faria Corporation"},
    {"FTT", "FT-TEC"},
    {"FUG", "Fugro Intersite BV (Netherlands)"},
    {"FUJ", "Fujitsu Ten Corporation of America"},
    {"FUR", "Furuno USA, Inc."},
    {"FWG", "Forschungsbereich Wasserchall and Geophysik WTD 71 (German Armed Forces Research Institute) (Germany)"},
    {"GAM", "GRE America, Inc."},
    {"GCA", "Gulf Cellular Associates"},
    {"GDC", "GNSS Differential Correction (Reserved for Future Use)"},
    {"GEC", "GEC Plessey Semiconductors"},
    {"GES", "Geostar Corporation"},
    {"GFC", "Graphic Controls Corporation"},
    {"GFV", "GFV Marine, Ltd."},
    {"GIL", "Gill Instruments Limited"},
    {"GIS", "Galax Integrated Systems"},
    {"GNV", "Geonav International"},
    {"GPI", "Global Positioning Instrument Corporation"},
    {"GPP", "GEO++ GmbH (Germany)"},
    {"GPR", "Global Positioning System Joint Program Office (Rockwell Collins)"},
    {"GRF", "Grafinta (Spain)"},
    {"GRM", "Garmin Corporation"},
    {"GSC", "Gold Star Company, Ltd."},
    {"GTI", "Genesis Technology International, Ltd."},
    {"GTO", "GRO Electronics"},
    {"GVE", "Guest Corporation"},
    {"GVT", "Great Valley Technology"},
    {"HAI", "Hydragraphic Associates, Ltd."},
    {"HAL", "HAL Communications Corporation"},
    {"HAR", "Harris Corporation"},
    {"HHS", "Hydel Hellas Skaltsaris, Ltd. (Shanghai)"},
    {"HIG", "Hy-Gain"},
    {"HIL", "Philips Navigation A/S (Denmark)"},
    {"HIT", "Hi-Tec"},
    {"HMS", "Hyde Marine Systems, Inc."},
    {"HOM", "Hoppe Marine GmbH (Germany)"},
    {"HPK", "Hewlett-Packard"},
    {"HRC", "Harco Manufacturing Company"},
    {"HRM", "[Unnamed]"},
    {"HRT", "Hart Systems, Inc."},
    {"HTI", "Heart Interface, Inc."},
    {"HUL", "Hull Electronics Company"},
    {"HWM", "Honeywell Marine Systems"},
    {"IBM", "IBM Microelectronics"},
    {"ICO", "Icom of America, Inc."},
    {"ICG", "Initiative Computing USA, Inc. / Initiative Computing AG"},
    {"IDS", "ICAN Marine (Canada)"},
    {"IFD", "International Fishing Devices"},
    {"IFI", "Instruments for Industry"},
    {"ILS", "Ideal Teknoloji Bilisim Cozumleri A/S (Turkey)"},
    {"IME", "Imperial Marine Equipment"},
    {"IMI", "International Marine Instruments"},
    {"IMM", "ITT Mackay Marine"},
    {"IMP", "Impulse Manufacturing, Inc."},
    {"IMR", "Ideal Technologies, Inc."},
    {"IMT", "International Marketing and Trading, Inc."},
    {"INM", "Inmar Electronics and Sales"},
    {"INT", "Intech, Inc."},
    {"IRT", "Intera Technologies, Ltd."},
    {"IST", "Innerspace Technology, Inc."},
    {"ITM", "Intermarine Electronics, Inc."},
    {"ITR", "Itera, Ltd."},
    {"IWW", "Inland Waterways (Germany)"},
    {"IXB", "iXblue"},
    {"JAN", "Jan Crystals"},
    {"JAS", "Jasco Research, Ltd."},
    {"JFR", "Ray Jefferson"},
    {"JLD", "Jargoon Limited"},
    {"JMT", "Japan Marine Telecommunications"},
    {"JPI", "JP Instruments"},
    {"JRC", "Japan Radio Company, Ltd."},
    {"JRI", "J-R Industries, Inc."},
    {"JTC", "J-Tech Associates, Inc."},
    {"JTR", "Jotron Radiosearch, Ltd."},
    {"KBE", "KB Electronics, Ltd."},
    {"KBM", "Kennebec Marine Company"},
    {"KEL", "Knudsen Engineering, Ltd."},
    {"KHU", "Kelvin Hughes, Ltd."},
    {"KLA", "Klein Associates, Inc."},
    {"KME", "Kyushu Matsushita Electric"},
    {"KML", "Kongsberg Mesotech, Ltd. (Canada)"},
    {"KMO", "Kongsberg Maritime A/S (Norway)"},
    {"KMR", "King Marine Radio Corporation"},
    {"KMS", "Kongsberg Maritime Subsea (Norway)"},
    {"KNC", "Kongsberg Norcontrols (Norway)"},
    {"KNG", "King Radio Corporation"},
    {"KOD", "Koden Electronics Company, Ltd."},
    {"KRA", "EDV Krajka (Germany)"},
    {"KRP", "Krupp International, Inc."},
    {"KST", "Kongsberg Seatex A/S (Norway)"},
    {"KVH", "KVH Company"},
    {"KYI", "Kyocera International, Inc."},
    {"L3A", "L3 Communications Recorders Division"},
    {"LAT", "Latitude Corporation"},
    {"L3I", "L-3 Interstate Electronics Corporation"},
    {"LCI", "Lasercraft, Inc."},
    {"LEC", "Lorain Electronics Corporation"},
    {"LEI", "Leica Geosystems Pty, Ltd."},
    {"LIT", "Litton Laser Systems"},
    {"LMM", "Lamarche Manufacturing Company"},
    {"LRD", "Lorad"},
    {"LSE", "Littlemore Scientific (ELSEC) Engineering"},
    {"LSP", "Laser Plot, Inc."},
    {"LST", "Lite Systems Engineering"},
    {"LTH", "Lars Thrane A/S (Denmark)"},
    {"LTF", "Littlefuse, Inc."},
    {"LTI", "Laser Technology, Inc."},
    {"LWR", "Lowrance Electronics Corporation"},
    {"MCA", "Canadian Marconi Company"},
    {"MCI", "Matsushita Communications (Japan)"},
    {"MCL", "Micrologic, Inc."},
    {"MDL", "Medallion Instruments, Inc."},
    {"MDS", "Marine Data Systems"},
    {"MEC", "Marine Engine Center, Inc."},
    {"MEG", "Maritec Engineering GmbH (Germany)"},
    {"MES", "Marine Electronics Services, Inc."},
    {"MEW", "Matsushita Electric Works (Japan)"},
    {"MFR", "Modern Products, Ltd."},
    {"MFW", "Frank W. Murphy Manufacturing"},
    {"MGN", "Magellen Systems Corporation"},
    {"MGS", "MG Electronic Sales Corporation"},
    {"MIE", "Mieco, Inc."},
    {"MIK", "Mikrolab GmbH (Germany)"},
    {"MIR", "Miros A/S (Norway)"},
    {"MIM", "Marconi International Marine"},
    {"MLE", "Martha Lake Electronics"},
    {"MLN", "Matlin Company"},
    {"MLP", "Marlin Products"},
    {"MLT", "Miller Technologies"},
    {"MMB", "Marsh-McBirney, Inc."},
    {"MME", "Marks Marine Engineering"},
    {"MMI", "Microwave Monolithics"},
    {"MMM", "Madman Marine"},
    {"MMP", "Metal Marine Pilot, Inc."},
    {"MMS", "Mars Marine Systems"},
    {"MMT", "Micro Modular Technologies"},
    {"MNI", "Micro-Now Instrument Company"},
    {"MNT", "Marine Technology"},
    {"MNX", "Marinex"},
    {"MOT", "Motorola Communications & Electronics"},
    {"MPI", "Megapulse, Inc."},
    {"MPN", "Memphis Net and Twine Company, Inc."},
    {"MQS", "Marquis Industries, Inc."},
    {"MRC", "Marinecomp, Inc."},
    {"MRE", "Morad Electronics Corporation"},
    {"MRP", "Mooring Products of New England"},
    {"MRR", "II Morrow, Inc."},
    {"MRS", "Marine Radio Service"},
    {"MSB", "Mitsubishi Electric Company, Ltd."},
    {"MSE", "Master Electronics"},
    {"MSF", "Microsoft Corporation"},
    {"MSM", "Master Mariner, Inc."},
    {"MST", "Mesotech Systems, Ltd."},
    {"MTA", "Marine Technical Associates"},
    {"MTD", "Maritel Data Services"},
    {"MTG", "Marine Technical Assistance Group"},
    {"MTI", "Mobile Telesystems, Inc."},
    {"MTK", "Martech, Inc."},
    {"MTL", "Marine Technologies, LLC"},
    {"MTR", "The MITRE Corporation"},
    {"MTS", "Mets, Inc."},
    {"MUR", "Murata Erie North America"},
    {"MVX", "Magnavox Advanced Products and Systems Company"},
    {"MXS", "Maxsea International"},
    {"MXX", "Maxxima Marine"},
    {"MYS", "Marine Electronics Company (South Korea)"},
    {"NAG", "Noris Automation GmbH (Germany)"},
    {"NAT", "Nautech, Ltd."},
    {"NAU", "Nauticast (a.k.a. Nauticall)"},
    {"NAV", "Navtec, Inc."},
    {"NCG", "Navcert, GmbH (Germany)"},
    {"NCT", "Navcom Technology, Inc."},
    {"NEC", "NEC Corporation"},
    {"NEF", "New England Fishing Gear"},
    {"NGC", "Northrop Grumman Maritime Systems"},
    {"NGS", "Navigation Sciences, Inc."},
    {"NIX", "L-3 Nautronix"},
    {"NLS", "Navigation Light Status (Reserved for Future Use)"},
    {"NMR", "Newmar"},
    {"NMX", "Nanometrics"},
    {"NOM", "Nav-Com, Inc."},
    {"NOR", "Nortech Surveys (Canada)"},
    {"NOS", "Northern Solutions A/S (Norway)"},
    {"NOV", "NovAtel Communications, Ltd."},
    {"NSI", "Noregon Systems, Inc."},
    {"NSL", "Navitron Systems, Ltd."},
    {"NSM", "Northstar Marine"},
    {"NTI", "Northstar Technologies, Inc."},
    {"NTK", "Novatech Designs, Ltd."},
    {"NTS", "Navtech Systems"},
    {"NUT", "Nautitech Pty, Ltd."},
    {"NVC", "Navico"},
    {"NVG", "NVS Technologies AG (Switzerland)"},
    {"NVL", "Navelec Marine Systems Sl. (Spain)"},
    {"NVO", "Navionics, s.p.a. (Italy)"},
    {"NVS", "Navstar"},
    {"NVT", "Novariant, Inc."},
    {"NWC", "Naval Warfare Center"},
    {"OAR", "On-Line Applications Research (OAR) Corporation"},
    {"OBS", "Observator Instruments"},
    {"OCC", "Occupation Control (Reserved for Future Use)"},
    {"ODE", "Ocean Data Equipment Corporation"},
    {"ODN", "Odin Electronics, Inc."},
    {"OHB", "OHB Systems"},
    {"OIN", "Ocean Instruments, Inc."},
    {"OKI", "Oki Electric Industry Company, Ltd."},
    {"OLY", "Navstard, Ltd. (Polytechnic Electronics)"},
    {"OMN", "Omnetics Corporation"},
    {"OMT", "Omnitech A/S (Norway)"},
    {"ONI", "Omskiy Nauchno Issledovatelskiy Institut Priborostroeniya (Russia)"},
    {"ORB", "Orbcomm"},
    {"ORE", "Ocean Research"},
    {"OSG", "Ocean Signal, Ltd."},
    {"OSI", "OSI Maritime Systems (was Offshore Systems International)"},
    {"OSL", "OSI Maritime Systems (was Offshore Systems, Ltd.)"},
    {"OSS", "Ocean Solution Systems"},
    {"OTK", "Ocean Technology"},
    {"PCE", "Pace"},
    {"PCM", "P-Sea Marine Systems"},
    {"PDC", "Pan Delta Controls, Ltd."},
    {"PDM", "Prodelco Marine Systems"},
    {"PLA", "Plath C Division of Litton Industries"},
    {"PLI", "Pilot Instruments"},
    {"PMI", "Pernicka Marine Instruments"},
    {"PMP", "Pacific Marine Products"},
    {"PNI", "PNI Sensors, Inc."},
    {"PNL", "Points North, Ltd."},
    {"POM", "POMS Engineering"},
    {"PPL", "Pamarine Private, Ltd."},
    {"PRK", "Perko, Inc."},
    {"PSM", "Pearce-Simpson, Inc."},
    {"PST", "Pointstar A/S (Denmark)"},
    {"PTC", "Petro-Com"},
    {"PTG", "PTI/Guest"},
    {"PTH", "Pathcom, Inc."},
    {"PVS", "Planevision Systems"},
    {"QNQ", "QinetiQ (United Kingdom)"},
    {"QRC", "QinetiQ (United Kingdom)"},
    {"QWE", "Qwerty Elektronik AB (Sweden)"},
    {"QZM", "[Unnamed]"},
    {"Q2N", "QQN Navigation ABS"},
    {"RAC", "Racal Marine, Inc."},
    {"RAE", "RCA Astro-Electronics"},
    {"RAF", "Robins Air Force (USAF)"},
    {"RAK", "Rockson Automation Kiel"},
    {"RAY", "Raytheon Marine Company"},
    {"RCA", "RCA Service Company"},
    {"RCH", "Roach Engineering"},
    {"RCI", "Rochester Instruments, Inc."},
    {"RCQ", "QinetiQ (United Kingdom)"},
    {"RDC", "U.S. Coast Guard Research & Development Center"},
    {"RDI", "Radar Devices"},
    {"RDM", "Ray-Dar Manufacturing Company"},
    {"REC", "Ross Engineering Company"},
    {"RFP", "Rolfite Products, Inc."},
    {"RGC", "RCA Global Communications"},
    {"RGL", "Riegl Laser Measurement Systems"},
    {"RGY", "Regency Electronics, Inc."},
    {"RHO", "Rhotheta Elektronik GmbH (Germany)"},
    {"RHM", "RH Marine"},
    {"RLK", "Reelektronika NL (Netherlands)"},
    {"RME", "Racal Marine Electronics"},
    {"RMR", "RCA Missile and Radar"},
    {"RSL", "Ross Laboratories, Inc."},
    {"RSM", "Robertson-Shipmate USA"},
    {"RTH", "Parthus"},
    {"RTN", "Robertson Tritech Nyaskaien (Norway)"},
    {"RWC", "Rockwell Collins"},
    {"RWI", "Rockwell International"},
    {"SAA", "Satronika Sl. (Spain)"},
    {"SAB", "VDE Satellite Selective Addressed Binary and Safety Related Message (Reserved for Future Use)"},
    {"SAE", "STN Atlas Elektronik GmbH (Germany)"},
    {"SAF", "Safemine"},
    {"SAI", "SAIT, Inc."},
    {"SAJ", "SAJ Instrument AB (Finland)"},
    {"SAM", "SAM Electronics GmbH (Germany)"},
    {"SAL", "Consilium Marine AB (Sweden)"},
    {"SAP", "Systems Engineering & Assessment, Ltd."},
    {"SAT", "Satloc"},
    {"SBB", "VDE Satellite Broadcast Binary Message (Reserved for Future Use)"},
    {"SBG", "SBG Systems"},
    {"SBR", "Sea-Bird Electronics, Inc."},
    {"SCL", "Sokkia Company, Ltd."},
    {"SCM", "Scandinavian Microsystems A/S (Norway)"},
    {"SCO", "Simoco Telecommunications, Ltd."},
    {"SCR", "Signalcrafters, Inc."},
    {"SDM", "VDE Satellite VHF Data-Link Message (Reserved for Future Use)"},
    {"SDN", "Sapien Design"},
    {"SDO", "VDE Satellite VHF Data-Link Own-Vessel Report (Reserved for Future Use)"},
    {"SEA", "Sea, Inc."},
    {"SEC", "Sercel Electronics of Canada"},
    {"SEE", "Seetrac (a.k.a. Global Marine Tracking)"},
    {"SEL", "Selection Report (Reserved for Future Use)"},
    {"SEM", "Semtech, Ltd."},
    {"SEP", "Steel and Engine Products"},
    {"SER", "Sercel France"},
    {"SFN", "Seafarer Navigation International"},
    {"SGB", "VDE Satellite Geographical Addressed Binary and Safety Message (Reserved for Future Use)"},
    {"SGC", "SGC, Inc."},
    {"SGN", "Signav"},
    {"SHI", "Shine Micro, Inc."},
    {"SIG", "Signet, Inc."},
    {"SIM", "Simrad, Inc."},
    {"SKA", "Skantek Corporation"},
    {"SKP", "Skipper Electronics A/S (Norway)"},
    {"SLI", "Starlink, Inc."},
    {"SLM", "Steering Location Mode (Reserved for Future Use)"},
    {"SMC", "Solis Marine Consultants"},
    {"SMD", "ShipModul Customware (Netherlands)"},
    {"SME", "Shakespeare Marine Electronics"},
    {"SMF", "Seattle Marine and Fishing Supply Company"},
    {"SMI", "Sperry Marine, Inc."},
    {"SMK", "VDE Satellite Addressed and Broadcast Message Acknowledgement (Reserved for Future Use)"},
    {"SML", "Simerl Instruments"},
    {"SMT", "SRT Marine Technology, Ltd. (United Kingdom)"},
    {"SMV", "SafetyNet Message Vessel (Reserved for Future Use)"},
    {"SNP", "Science Applications International Corporation"},
    {"SNV", "STARNAV Corporation (Canada)"},
    {"SNY", "Sony Corporation - Mobile Electronics"},
    {"SOM", "Sound Marine Electronics"},
    {"SON", "Sonardyne International, Ltd. (United Kingdom)"},
    {"SOV", "Sell Overseas America"},
    {"SPL", "Spelmar"},
    {"SPT", "Sound Powered Telephone"},
    {"SRC", "Stellar Research Group"},
    {"SRD", "SRD Labs"},
    {"SRF", "SIRF Technology, Inc."},
    {"SRP", "System Function ID Resolution Protocol (Reserved for Future Use)"},
    {"SRS", "Scientific Radio Systems, Inc."},
    {"SRT", "Standard Radio and Telefon AB (Sweden)"},
    {"SRV", "(Reserved for Future Use)"},
    {"SSA", "(Reserved for Future Use)"},
    {"SSC", "Swedish Space Corporation"},
    {"SSD", "Saab AB, Security & Defense Solutions, Command and Control Systems Division (Sweden)"},
    {"SSE", "Seven Star Electronics"},
    {"SSI", "Sea Scout Industries"},
    {"SSN", "Septentrio"},
    {"STC", "Standard Communications"},
    {"STI", "Sea-Temp Instrument Corporation"},
    {"STK", "Seatechnik, Ltd. (a.k.a. Trelleborg Marine Systems) (United Kingdom)"},
    {"STL", "Streamline Technology, Ltd."},
    {"STM", "SI-TEX Marine Electronics"},
    {"STO", "Stowe Marine Electronics"},
    {"STT", "Saab TransponderTech AB (Sweden)"},
    {"SVY", "Savoy Electronics"},
    {"SWI", "Swoffer Marine Instruments"},
    {"SWT", "Swift Navigation, Inc."},
    {"SYE", "Samyung ENC Company, Ltd. (South Korea)"},
    {"SYN", "Synergy Systems, LLC"},
    {"TAB", "VDE Terrestrial Selective Addressed Binary and Safety Related Message (Reserved for Future Use)"},
    {"TBB", "Thompson Brothers Boat Manufacturing"},
    {"TBM", "VDE Terrestrial Broadcast Binary Message (Reserved for Future Use)"},
    {"TCN", "Trade Commission of Norway"},
    {"TDI", "Teledyne RD Instruments, Inc."},
    {"TDL", "Tideland Signal"},
    {"TDM", "VDE Terrestrial VHF Data-Link Message (Reserved for Future Use)"},
    {"TDO", "VDE Terrestrial VHF Data-Link Own-Vessel Report (Reserved for Future Use)"},
    {"TEL", "Plessey Tellumat (South Africa)"},
    {"TES", "Thales Electronic Systems GmbH (Germany)"},
    {"TGB", "VDE Terrestrial Geographical Addressed Binary and Safety Message (Reserved for Future Use)"},
    {"THR", "Thrane and Thrane A/A (Denmark)"},
    {"TKI", "Tokyo Keiki, Inc. (Japan)"},
    {"TLS", "Telesystems"},
    {"TMK", "VDE Terrestrial Addressed and Broadcast Message Acknowledgement (Reserved for Future Use)"},
    {"TMS", "Trelleborg Marine Systems"},
    {"TMT", "Tamtech, Ltd."},
    {"TNL", "Trimble Navigation, Inc."},
    {"TOP", "Topcon Positioning Systems, Inc."},
    {"TPL", "Totem Plus, Ltd."},
    {"TRC", "Tracor, Inc."},
    {"TRS", "Travroute Software"},
    {"TSG", "(Reserved for Future Use)"},
    {"TSI", "Techsonic Industries, Inc."},
    {"TSS", "Teledyne TSS, Ltd. (United Kingdom)"},
    {"TTK", "Talon Technology Corporation"},
    {"TTS", "Transtector Systems, Inc."},
    {"TYC", "Vincotech GmbH (formerly Tyco Electronics) (Germany)"},
    {"TWC", "Transworld Communications"},
    {"TWS", "Telit Location Solutions, a Division of Telit Wireless Solutions"},
    {"TXI", "Texas Instruments, Inc."},
    {"UBX", "u-blox AG (Switzerland)"},
    {"UCG", "United States Coast Guard"},
    {"UEL", "Ultra Electronics, Ltd."},
    {"UME", "UMEC"},
    {"UNF", "Uniforce Electronics Company"},
    {"UNI", "Uniden Corporation of America"},
    {"UNP", "Unipas, Inc."},
    {"URS", "UrsaNav, Inc."},
    {"VAN", "Vanner, Inc."},
    {"VAR", "Varian Eimac Associates"},
    {"VBC", "Docking Speed Log (Reserved for Future Use)"},
    {"VCM", "Videocom"},
    {"VDB", "Bertold Vandenbergh"},
    {"VEA", "Vard Electro A/S (Norway)"},
    {"VEC", "Vectron International"},
    {"VEX", "Vexilar"},
    {"VIS", "Vessel Information Systems"},
    {"VMR", "Vast Marketing Corporation"},
    {"VSP", "Vesper Marine"},
    {"VXS", "Vertex Standard"},
    {"WAL", "Walport USA"},
    {"WBE", "Wamblee, s.r.l. (Italy)"},
    {"WBG", "Westberg Manufacturing"},
    {"WBR", "Wesbar Corporation"},
    {"WEC", "Westinghouse Electric Corporation"},
    {"WEI", "Weidmueller Interface GmbH (Germany)"},
    {"WCI", "Wi-Sys Communications"},
    {"WDC", "Weatherdock Corporation"},
    {"WHA", "W-H Autopilots, Inc."},
    {"WMM", "Wait Manufacturing and Marine Sales Company"},
    {"WMR", "Wesmar Electronics"},
    {"WNG", "Winegard Company"},
    {"WOE", "Woosung Engineering Company, Ltd. (South Korea)"},
    {"WSE", "Wilson Electronics Corporation"},
    {"WST", "West Electronics, Ltd."},
    {"WTC", "Watercom"},
    {"XEL", "3XEL Electronics and Navigation Systems, s.r.l. (Italy)"},
    {"YAS", "Yaesu Electronics (Japan)"},
    {"YDK", "Yokogawa Denshikiki Company, Ltd. (Japan)"},
    {"YSH", "Standard Horizon Yaesu"},
    {"ZNS", "Zinnos, Inc. (South Korea)"},
    {NULL, NULL}};

// List of GPS Quality Indicator (Source: NMEA Revealed by Eric S. Raymond, https://gpsd.gitlab.io/gpsd/NMEA.html, retrieved 2023-01-26)
static const string_string known_gps_quality_indicators[] = {
    {"0", "Fix not available"},
    {"1", "GPS fix"},
    {"2", "Differential GPS fix"},
    {"3", "PPS fix"},
    {"4", "Real Time Kinematic"},
    {"5", "Float Real Time Kinematic"},
    {"6", "Estimated (dead reckoning)"},
    {"7", "Manual input mode"},
    {"8", "Simulation mode"},
    {NULL, NULL}};

// List of status indicators (Source: NMEA Revealed by Eric S. Raymond, https://gpsd.gitlab.io/gpsd/NMEA.html, retrieved 2024-04-19)
static const string_string known_status_indicators[] = {
    {"A", "Valid/Active"},
    {"V", "Invalid/Void"},
    {NULL, NULL}};

// List of FAA Mode Indicator (Source: NMEA Revealed by Eric S. Raymond, https://gpsd.gitlab.io/gpsd/NMEA.html, retrieved 2024-04-19)
static const string_string known_faa_mode_indicators[] = {
    {"A", "Autonomous mode"},
    {"C", "Quectel Querk, Caution"},
    {"D", "Differential Mode"},
    {"E", "Estimated (dead-reckoning) mode"},
    {"F", "RTK Float mode"},
    {"M", "Manual Input Mode"},
    {"N", "Data Not Valid"},
    {"P", "Precise"},
    {"R", "RTK Integer mode"},
    {"S", "Simulated Mode"},
    {"U", "Quectel Querk, Unsafe"},
    {NULL, NULL}};

static const value_string abk_ack_type[] = {
    {'0', "Message (6 or 12) successfully received by addressed AIS unit"},
    {'1', "Message (6 or 12) was broadcast, but no acknowledgement by addressed AIS unit"},
    {'2', "Message could not be broadcast (i.e., quantity of encapsulated data exceeds five slots)"},
    {'3', "Requested broadcast of message (8, 14, or 15) has been successfully completed"},
    {'4', "Late reception of a message 7 or 13 acknowledgement that was addressed to this AIS unit (own-ship) and referenced a valid transaction"},
    {0, NULL}};

static const value_string abk_channel[] = {
    {'A', "Channel A"},
    {'B', "Channel B"},
    {0, NULL}};

static const value_string aca_chbw[] = {
    {'0', "Bandwidth specified by channel number (see ITU-R M.1084, Annex 4)"},
    {'1', "Bandwidth is 12.5 kHz"},
    {0, NULL}};

static const value_string aca_in_use[] = {
    {'0', "Not in use"},
    {'1', "In use"},
    {0, NULL}};

static const value_string aca_info_src[] = {
    {'A', "ITU-R M.1371 Message 22:  Channel Management addressed message"},
    {'B', "ITU-R M.1371 Message 22:  Channel Management broadcast geographical area message"},
    {'C', "IEC 61162-1 AIS Channel Assignment sentence"},
    {'D', "DSC Channel 70 Telecommand"},
    {'M', "Operator Manual Input"},
    {0, NULL}};

static const value_string aca_power[] = {
    {'0', "High Power"},
    {'1', "Low Power"},
    {0, NULL}};

static const value_string aca_txrx_control[] = {
    {'0', "Transmit on Channels A and B, Receive on Channels A and B"},
    {'1', "Transmit on Channel A, Receive on Channels A and B"},
    {'2', "Transmit on Channel B, Receive on Channels A and B"},
    {'3', "Do not transmit, Receive on Channels A and B"},
    {'4', "Do not transmit, Receive on Channel A"},
    {'5', "Do not transmit, Receive on Channel B"},
    {0, NULL}};

static const value_string alarm_ack_state_vals[] = {
    {'A', "Acknowledged"},
    {'V', "Not Acknowledged"},
    {'B', "Broadcast (Acknowledgement not applicable)"},
    {'H', "Harbour Mode"},
    {'O', "Override"},
    {0, NULL}};

static const value_string alarm_cond_state_vals[] = {
    {'N', "Normal State"},
    {'H', "Alarm State: Threshold Exceeded"},
    {'J', "Alarm State: Extreme Threshold Exceeded"},
    {'L', "Alarm State: Low Threshold Exceeded"},
    {'K', "Alarm State: Extreme Low Threshold Exceeded (i.e., not reached)"},
    {'X', "Other"},
    {0, NULL}};

static const value_string arrival_circle_status[] = {
    {'A', "Arrival circle entered"},
    {'V', "Arrival circle not entered"},
    {0, NULL}};

static const value_string auto_manual_vals[] = {
    {'M', "Manual"},
    {'A', "Automatic"},
    {0, NULL}};

static const value_string control_flag_vals[] = {
    {'0', "AIS unit responds if AIS unit is within geographic rectangle provided and AIS unit hasn't responded to requesting MMSI within last 24 hours and MMSI destination field is NULL"},
    {'1', "AIS unit responds if AIS unit is within geographic rectangle provided"},
    {0, NULL}};

static const value_string course_ref_vals[] = {
    {'B', "Bottom tracking log"},
    {'M', "Manually entered"},
    {'W', "Water referenced"},
    {'R', "Radar tracking (of fixed target)"},
    {'P', "Positioning system ground reference"},
    {0, NULL}};

static const value_string data_status[] = {
    {'A', "Data valid"},
    {'V', "Data not valid"},
    {0, NULL}};

static const string_string datum_vals[] = {
    {"W84", "WGS84"},
    {"W72", "WGS72"},
    {"S85", "SGS85"},
    {"P90", "PE90"},
    {"999", "User Defined"},
    {NULL, NULL}
};

static const value_string dcn_data_basis[] = {
    {'1', "Normal pattern"},
    {'2', "Lane identification pattern"},
    {'3', "Lane identification transmissions"},
    {0, NULL}};

static const value_string dimming_palette_preset_vals[] = {
    {'D', "Daytime"},
    {'K', "Dusk"},
    {'N', "Nighttime"},
    {'O', "Backlighting Off"},
    {0, NULL}};

static const value_string direction_reference[] = {
    {'T', "True"},
    {'R', "Relative"},
    {0, NULL}};

static const value_string display_rotation_vals[] = {
    {'C', "Course-up, course-over-ground up, degrees True"},
    {'H', "Head-up, ship's heading (centerline) 0 degrees up"},
    {'N', "North-up, True North is 0 degrees up"},
    {0, NULL}};

static const value_string dma_setup_vals[] = {
    {'0', "FATDMA"},
    {'1', "RATDMA"},
    {'2', "CSTDMA"},
    {0, NULL}};

static const string_string door_mon_sys_type_vals[] = {
    {"WT", "Watertight Door"},
    {"WS", "Semi-watertight Door (splash-tight)"},
    {"FD", "Fire Door"},
    {"HD", "Hull (shell) Door"},
    {"OT", "Other"},
    {NULL, NULL}};

static const value_string door_status_vals[] = {
    {'O', "Open"},
    {'C', "Closed"},
    {'S', "Secured"},
    {'F', "Free status (for watertight door)"},
    {'X', "Fault (door status unknown)"},
    {0, NULL}};

static const value_string dor_msg_type_vals[] = {
    {'S', "Status for section"},
    {'E', "Status for single door"},
    {'F', "Fault in system"},
    {0, NULL}};

static const value_string dsc_ack_vals[] = {
    {'R', "Acknowledgement Request"},
    {'B', "Acknowledgement"},
    {'S', "Neither (end of sequence)"},
    {0, NULL}};

static const value_string dse_flag_vals[] = {
    {'Q', "Query"},
    {'R', "Reply"},
    {'A', "Automatic"},
    {0, NULL}};

static const value_string dte_indicator_vals[] = {
    {'0', "Keyboard and display are a standard configuration, and communication is supported"},
    {'1', "Keyboard and display are either unknown or unable to support communication"},
    {0, NULL}};

static const value_string equipment_status_vals[] = {
    {'A', "Normal operation"},
    {'V', "Not normal operation"},
    {0, NULL}};

static const value_string etl_message_type_vals[] = {
    {'O', "Order"},
    {'A', "Answer-back"},
    {0, NULL}};

static const value_string fsi_mode_vals[] = {
    {'d', "F3E/G3E simplex, telephone"},
    {'e', "F3E/G3E duplex, telephone"},
    {'m', "J3E, telephone"},
    {'o', "H3E, telephone"},
    {'q', "F1B/J2B FEC NBDP, Telex/teleprinter"},
    {'s', "F1B/J2B ARQ NBDP, Telex/teleprinter"},
    {'t', "F1B/J2B receive only, teleprinter/DSC"},
    {'w', "F1B/J2B, teleprinter/DSC"},
    {'x', "A1A Morse, tape recorder"},
    {'{', "A1A Morse, Morse key/head set"},
    {'|', "F1C/F2C/F3C, FAX-machine"},
    {0, NULL}};

static const value_string fsi_power_vals[] = {
    {'0', "Standby"},
    {'1', "Lowest"},
    {'9', "Highest"},
    {0, NULL}};

static const value_string glc_sig_status[] = {
    {'B', "Blink warning"},
    {'C', "Cycle warning"},
    {'S', "SNR warning"},
    {'A', "Valid"},
    {0, NULL}};

static const value_string grs_mode_vals[] = {
    {'0', "Residuals were used to calculate the position given in the matching GGA/GNS sentence"},
    {'1', "Residuals were recomputed after the GGA/GNS position was computed"},
    {0, NULL}};

static const value_string gsa_fix_mode[] = {
    {'1', "Fix not available"},
    {'2', "2D"},
    {'3', "3D"},
    {0, NULL}};

static const value_string gsa_op_mode[] = {
    {'M', "Manual, forced to operate in 2D or 3D mode"},
    {'A', "Automatic, allowed to automatically switch 2D/3D"},
    {0, NULL}};

static const value_string heading_monitor_sensor_type[] = {
    {'T', "True"},
    {'M', "Magnetic"},
    {0, NULL}};

static const value_string heading_monitor_sensor_vals[] = {
    {'A', "Data valid"},
    {'V', "Data not valid"},
    {0, NULL}};

static const value_string heading_reference[] = {
    {'T', "True"},
    {'M', "Magnetic"},
    {0, NULL}};

static const value_string indicators_for_engine_telegraph[] = {
    {0, "Stop Engine"},
    {1, "[AH] Dead Slow"},
    {2, "[AH] Slow"},
    {3, "[AH] Half"},
    {4, "[AH] Full"},
    {5, "[AH] Navigation Full"},
    {11, "[AS] Dead Slow"},
    {12, "[AS] Slow"},
    {13, "[AS] Half"},
    {14, "[AS] Full"},
    {15, "[AS] Crash Astern"},
    {0, NULL}};

static const value_string indicators_for_sub_telegraph[] = {
    {20, "S/B (Stand-by Engine)"},
    {30, "F/A (Full Away - Navigation Full"},
    {40, "F/E (Finish with Engine)"},
    {0, NULL}};

static const value_string loranc_blink_snr_warning_vals[] = {
    {'A', "Data valid"},
    {'V', "Loran-C Blink, SNR, or General warning"},
    {0, NULL}};

static const value_string loranc_cycle_lock_warning_vals[] = {
    {'A', "Data valid or not used"},
    {'V', "Loran-C Cycle Lock warning"},
    {0, NULL}};

static const value_string lrf_func_rep_vals[] = {
    {'2', "Information available and provided in the following LR1, LR2, or LR3 sentence"},
    {'3', "Information not available from the IAS unit"},
    {'4', "Information is available but not provided (i.e., restricted access determined by ship's master)"},
    {0, NULL}};

static const value_string lrf_func_req_vals[] = {
    {'A', "Ship's: name, call sign, and IMO number"},
    {'B', "Date and time of message composition"},
    {'C', "Position"},
    {'E', "Course over ground"},
    {'F', "Speed over ground"},
    {'I', "Destination and Estimated Time of Arrival (ETA)"},
    {'O', "Draught"},
    {'P', "Ship / Cargo"},
    {'U', "Ship's: length, breadth, type"},
    {'W', "Persons on board"},
    {0, NULL}};

static const value_string mode_indicator[] = {
    {'A', "Autonomous mode"},
    {'D', "Differential mode"},
    {'E', "Estimated (dead reckoning) mode"},
    {'M', "Manual input mode"},
    {'S', "Simulator mode"},
    {'N', "Data not valid"},
    {0, NULL}};

static const value_string mwv_reference[] = {
    {'R', "Relative"},
    {'T', "Theoretical"},
    {0, NULL}};

/* Navigational Status per ITU-R M.1371 Message 1, Navigational Status parameter */
static const string_string nav_status_vals[] = {
    {"0", "Under way using engine"},
    {"1", "At anchor"},
    {"2", "Not under command"},
    {"3", "Restricted maneuverability"},
    {"4", "Constrained by draught"},
    {"5", "Moored"},
    {"6", "Aground"},
    {"7", "Engaged in fishing"},
    {"8", "Under way sailing"},
    {"9", "Reserved for High Speed Craft (HSC)"},
    {"10", "Reserved for Wing in Ground (WIG)"},
    {"11", "Reserved for Future Use"},
    {"12", "Reserved for Future Use"},
    {"13", "Reserved for Future Use"},
    {"14", "Reserved for Future Use"},
    {"15", "Default"},
    {NULL, NULL}};

static const value_string navigation_data_status[] = {
    {'A', "Data valid"},
    {'V', "Navigation receiver warning"},
    {0, NULL}};

static const value_string oplocation_indicator_vals[] = {
    {'B', "Bridge"},
    {'P', "Port Wing"},
    {'S', "Starboard Wing"},
    {'C', "Engine Control Room"},
    {'E', "Engine Side / Local"},
    {'W', "Wing (port or starboard not specified)"},
    {0, NULL}};

static const value_string override_vals[] = {
    {'A', "In use"},
    {'V', "Not in use"},
    {0, NULL}};

static const value_string perpendicular_pass_status[] = {
    {'A', "Perpendicular passed at waypoint"},
    {'V', "Perpendicular not passed"},
    {0, NULL}};

static const value_string point_type_vals[] = {
    {'C', "Collision"},
    {'T', "Turning point"},
    {'R', "Reference (general)"},
    {'W', "Wheelover"},
    {0, NULL}};

static const value_string r_oh_ot_status[] = {
    {'A', "Within limits"},
    {'V', "Limit reached or exceeded"},
    {0, NULL}};

static const value_string ref_target_vals[] = {
    {'R', "Target is a reference to determine own-ship position/velocity"},
    {0, NULL}};

static const value_string revolutions_number_vals[] = {
    {'0', "Single or on centerline"},
    {'1', "Starboard"},
    {'2', "Port"},
    {0, NULL}};

static const value_string revolutions_source_vals[] = {
    {'S', "Shaft"},
    {'E', "Engine"},
    {0, NULL}};

static const value_string rma_data_status[] = {
    {'A', "Data valid"},
    {'V', "Blink, Cycle, or SNR warning"},
    {0, NULL}};

static const value_string rudder_dir_vals[] = {
    {'L', "Port"},
    {'R', "Starboard"},
    {0, NULL}};

static const range_string sat_prn_type[] = {
    {1, 32, "GPS satellite"},
    {33, 64, "WAAS/SBAS satellite"},
    {65, 88, "GLONASS satellite"},
    {89, 96, "GLONASS on-orbit spare"},
    {193, 197, "QZSS satellite"},
    {0, 0, NULL}};

static const value_string satellite_mode_vals[] = {
    {'N', "No fix.  Satellite system not used in position fix, or fix not valid"},
    {'A', "Autonomous.  Satellite system used in non-differential mode in position fix"},
    {'D', "Differential.  Satellite system used in differential mode in position fix"},
    {'P', "Precise.  Satellite system used in precision mode"},
    {'R', "Real Time Kinematic (RTK).  Satellite system used in RTK mode with fixed integers"},
    {'F', "Float RTK.  Satellite system used in RTK mode with floating integers"},
    {'E', "Estimated (dead reckoning) mode"},
    {'M', "Manual input mode"},
    {'S', "Simulator mode"},
    {0, NULL}};

static const value_string sentence_mode_vals[] = {
    {'c', "Complete route, all waypoints"},
    {'w', "Working route, 1st listed waypoint is 'FROM', 2nd is 'TO', remaining are the route"},
    {0, NULL}};

static const value_string sentence_status_vals[] = {
    {'R', "Sentence is a status report of current settings (use for a reply to a query)"},
    {'C', "Sentence is a configuration command to change settings"},
    {0, NULL}};

static const value_string sfi_operation_mode_vals[] = {
    {'d', "F3E/G3E simplex, telephone"},
    {'e', "F3E/G3E duplex, telephone"},
    {'m', "J3E, telephone"},
    {'o', "H3E, telephone"},
    {'q', "F1B/J2B FEC NBDP, telex/teleprinter"},
    {'s', "F1B/J2B ARQ NBDP, telex/teleprinter"},
    {'t', "F1B/J2B receive only, teleprinter/DSC"},
    {'w', "F1B/J2B, teleprinter/DSC"},
    {'x', "A1A Morse, tape recorder"},
    {'{', "A1A Morse, Morse key/head set"},
    {'|', "F1C/F2C/F3C, FAX-machine"},
    {'\0', "No information"},
    {0, NULL}};

static const value_string speed_reference[] = {
    {'B', "Bottom track"},
    {'W', "Water track"},
    {'P', "Positioning System"},
    {0, NULL}};

static const value_string speed_unit_vals[] = {
    {'K', "Kilometers/hour"},
    {'M', "Meters/sec"},
    {'N', "Knots"},
    {'S', "Statute Miles/hour"},
    {0, NULL}};

static const value_string steer_direction[] = {
    {'L', "Left"},
    {'R', "Right"},
    {0, NULL}};

static const value_string steering_mode_vals[] = {
    {'M', "Manual steering.  The main steering system is in use"},
    {'S', "Standalone (heading control).  System works as a standalone heading controller"},
    {'H', "Heading control.  Input of commanded heading to steer is from external device"},
    {'T', "Track control.  System works as track controller by correcting course received in fielded 'Commanded Track'"},
    {'R', "Rudder control.  Input of commanded rudder angle and direction from external device"},
    {0, NULL}};

/* IEC 61126-1 Ed. 4 Annex D Subsystem Tables */
static const string_string subsystem_equipment_vals[] = {
    {"AL", "Group Alarm System"},
    {"AR", "Air"},
    {"BD", "Boiler Drum"},
    {"BL", "Boiler"},
    {"BN", "Burner"},
    {"CA", "Compressed Air"},
    {"CB", "Combustion"},
    {"CD", "Condensate"},
    {"CH", "Chemical Cargo System"},
    {"CL", "Control System (Actuator or Drive Unit for Steering Signal)"},
    {"CM", "Cooling Medium"},
    {"CN", "Combustion"},
    {"CO", "Condensate"},
    {"EG", "Engine"},
    {"EH", "Exhaust Gas"},
    {"EP", "Electric Power Generator Plant"},
    {"FO", "[System=AM] Fuel Oil System / [System=GT/PB/AB/AD/AG] Fuel Oil"},
    {"FV", "Fuel Valve Coolant"},
    {"FW", "Feed Water"},
    /* Duplicate character mapping from the table
    {"FW", "Cylinder Fresh Water Cooling"},*/
    {"HT", "Heat Detection Type"},
    {"LC", "Lubricating Oil Cooling System"},
    {"LG", "LPG/LNG Cargo System"},
    {"LO", "Lubricating/Lubrication Oil"},
    {"MN", "Monitoring System"},
    {"MS", "Propulsion Machinery Space"},
    {"OL", "Inert Gas System"},
    {"OT", "Others"},
    {"PA", "Propulsion Motor - AC"},
    {"PC", "Propulsion Control"},
    {"PD", "Propulsion Motor - DC"},
    {"PG", "Propulsion Generator"},
    {"PS", "[System=DE] Piston Cooling / [System=EP] Propulsion SCR"},
    {"PU", "Power Unit"},
    {"PW", "Power"},
    {"RC", "Remote Control System"},
    {"RM", "High-Voltage Rotating Machine"},
    {"RT", "Rotor"},
    {"SA", "[System=AG/GT] Starting / [System=DE] Scavenge Air"},
    {"SC", "Seawater Cooling"},
    {"SM", "[System=FR] Smoke Detection Type / [System=AB/PB/ST] Steam"},
    {"SP", "System Power Source"},
    {"ST", "[System=AM] Stern Tube Lub. Oil / [System=AD] Starting Medium / [System=AT] Steam"},
    {"SW", "Seawater"},
    {"TB", "Turbine"},
    {"TC", "Turbo-Charger"},
    {NULL, NULL}};

/* IEC 61126-1 Ed. 4 Annex D System Tables */
static const string_string system_equipment_vals[] = {
    {"AB", "Auxiliary Boiler"},
    {"AD", "Auxiliary Diesel Engine"},
    {"AG", "Auxiliary Gas Turbine"},
    {"AM", "Auxiliary Machinery"},
    {"AT", "Auxiliary Turbine"},
    {"CG", "Cargo Control Plant"},
    {"DE", "Diesel Plant"},
    {"EP", "Electric Propulsion Plant"},
    {"FD", "Fire Door Controller"},
    {"FR", "Fire Detection System"},
    {"GT", "Gas Turbine Plant"},
    {"HD", "Hull (shell) Door Controller"},
    {"OT", "Other's System"},
    {"PB", "Propulsion Boiler"},
    {"PC", "Propulsion Control"},
    {"SG", "Steering Gear"},
    {"ST", "Steam Turbines Plant"},
    {"WD", "Watertight Door Controller"},
    {NULL, NULL}};

static const value_string target_acq_vals[] = {
    {'A', "Auto"},
    {'M', "Manual"},
    {'R', "Reported"},
    {0, NULL}};

static const value_string tgt_status_vals[] = {
    {'L', "Lost, tracked target has been lost"},
    {'Q', "Query, target in the process of acquisition"},
    {'T', "Tracking"},
    {0, NULL}};

static const value_string transducer_type_vals[] = {
    {'C', "Temperature"},
    {'A', "Angular displacement"},
    {'D', "Linear displacement"},
    {'F', "Frequency"},
    {'N', "Force"},
    {'P', "Pressure"},
    {'R', "Flow rate"},
    {'T', "Tachometer"},
    {'H', "Humidity"},
    {'V', "Volume"},
    {'G', "Generic"},
    {'I', "Current"},
    {'U', "Voltage"},
    {'S', "Switch or valve"},
    {'L', "Salinity"},
    {0, NULL}};

static const value_string transducer_unit_vals[] = {
    {'C', "Degrees Celsius"},
    {'D', "Degrees"},
    {'H', "Hertz"},
    {'N', "Newton"},
    {'B', "Bars"},
    {'P', "Pascal (Pressure) or Percent (Humidity)"},
    {'l', "Liters/second"},
    {'R', "RPM"},
    {'M', "Cubic meters"},
    {'A', "Amperes"},
    {'V', "Volts"},
    {'S', "ppt"},
    {0, NULL}};

static const value_string turning_mode_vals[] = {
    {'R', "Radius controlled"},
    {'T', "Turn rate controlled"},
    {'N', "Turn is not controlled"},
    {0, NULL}};

static const value_string warning_flag_vals[] = {
    {'A', "Difference within set limit"},
    {'V', "Difference exceeds set limit"},
    {0, NULL}};

static const value_string watertight_switch_setting_vals[] = {
    {'O', "Harbor mode (allowed open)"},
    {'C', "Sea mode (ordered closed)"},
    {0, NULL}};

static const value_string xte_unit_vals[] = {
    {'K', "Kilometers"},
    {'M', "Meters"},
    {'N', "Nautical miles"},
    {'S', "Statute miles"},
    {0, NULL}};

static uint8_t calculate_checksum(tvbuff_t *tvb, const int start, const int length)
{
    uint8_t checksum = 0;
    for (int i = start; i < start + length; i++)
    {
        checksum ^= tvb_get_uint8(tvb, i);
    }
    return checksum;
}

static char *
decode_time(wmem_allocator_t *scope, const char *value)
{
    size_t length = strlen(value);

    if (length < 4)
    {
        return wmem_strdup(scope, value);
    }
    return wmem_strdup_printf(scope, "%.2s:%.2s:%s",
                              value, value + 2, value + 4);
}

static char *
decode_date(wmem_allocator_t *scope, const char *value)
{
    static const char *months[] = {
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
        "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"
    };
    unsigned month;
    unsigned year;

    if (strlen(value) < 6)
    {
        return wmem_strdup(scope, value);
    }
    month = (unsigned)(value[2] - '0') * 10 + (unsigned)(value[3] - '0');
    if (month < 1 || month > G_N_ELEMENTS(months))
    {
        return wmem_strdup(scope, value);
    }
    year = (unsigned)(value[4] - '0') * 10 + (unsigned)(value[5] - '0');
    return wmem_strdup_printf(scope, "%.2s %s %s%.2s",
                              value, months[month - 1],
                              year >= 70 ? "19" : "20", value + 4);
}

static bool
decode_latlong(const char *latlong, const char *direction, float *result)
{
    if (latlong == NULL || latlong[0] == '\0' ||
        direction == NULL || direction[0] == '\0')
    {
        return false;
    }

    double raw = g_ascii_strtod(latlong, NULL);
    double degrees = (int)(raw / 100.0);
    double coordinate = degrees + (raw - degrees * 100.0) / 60.0;

    if (direction[0] == 'S' || direction[0] == 'W')
    {
        coordinate = -coordinate;
    }
    *result = (float)coordinate;
    return true;
}

static char *
field_binding(wmem_allocator_t *scope, const char *value, const char *label)
{
    return wmem_strdup_printf(scope, "%s %.1s", value, label);
}

/* Find first occurrence of a field separator in tvbuff, starting at offset. Searches
 * to end of tvbuff.
 * Returns the offset of the found separator.
 * If separator is not found, return the offset of end of tvbuff.
 * If offset is out of bounds, return the offset of end of tvbuff.
 **/
static unsigned
tvb_find_end_of_nmea0183_field(tvbuff_t *tvb, const unsigned offset)
{
    if (tvb_captured_length_remaining(tvb, offset) == 0)
    {
        return tvb_captured_length(tvb);
    }

    unsigned end_of_field_offset;
    if (!tvb_find_uint8_remaining(tvb, offset, ',', &end_of_field_offset))
    {
        return tvb_captured_length(tvb);
    }
    return end_of_field_offset;
}

/* Add a zero length item which indicates an expected but missing field */
static proto_item *
proto_tree_add_missing_field(proto_tree *tree, packet_info *pinfo, int hf, tvbuff_t *tvb,
                             const int offset)
{
    proto_item *ti = NULL;
    ti = proto_tree_add_item(tree, hf, tvb, offset, 0, ENC_ASCII);
    proto_item_append_text(ti, "[missing]");
    expert_add_info(pinfo, ti, &ei_nmea0183_field_missing);
    return ti;
}

/* Dissect a time field. The field is split into a tree with hour, minute and second elements.
 * Returns length including separator
 **/
static int
dissect_nmea0183_field_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                            int hf_time, int hf_hour, int hf_minute, int hf_second, int ett_time)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf_time, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    ti = proto_tree_add_item(tree, hf_time, tvb, offset, end_of_field_offset - offset, ENC_ASCII);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, ": [empty]");
    }
    else if (end_of_field_offset - offset >= 6)
    {
        const uint8_t *hour = NULL;
        const uint8_t *minute = NULL;
        const uint8_t *second = NULL;
        proto_tree *time_subtree = proto_item_add_subtree(ti, ett_time);

        proto_tree_add_item_ret_string(time_subtree, hf_hour,
                                       tvb, offset, 2, ENC_ASCII,
                                       pinfo->pool, &hour);

        proto_tree_add_item_ret_string(time_subtree, hf_minute,
                                       tvb, offset + 2, 2, ENC_ASCII,
                                       pinfo->pool, &minute);

        proto_tree_add_item_ret_string(time_subtree, hf_second,
                                       tvb, offset + 4, end_of_field_offset - offset - 4,
                                       ENC_ASCII, pinfo->pool, &second);

        proto_item_append_text(ti, ": %s:%s:%s", hour, minute, second);
    }
    else
    {
        expert_add_info(pinfo, ti, &ei_nmea0183_field_time_too_short);
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a single field containing a dimensionless value. Returns length including separator */
static int
dissect_nmea0183_field(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf, const char *suffix, const string_string *str_str)
{
    const uint8_t *field_str = NULL;

    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    ti = proto_tree_add_item_ret_string(tree, hf, tvb, offset, end_of_field_offset - offset, ENC_ASCII, pinfo->pool, &field_str);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, "[empty]");
    }
    else if (suffix != NULL)
    {
        proto_item_append_text(ti, " %s", suffix);
    }
    if ((str_str)&&(field_str)) {
        proto_item_append_text(ti, " - %s", str_to_str_wmem(pinfo->pool, (const char *)field_str, str_str, " "));
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a latitude/longitude direction field.
 * Returns length including separator
 **/
static int
dissect_nmea0183_field_latlong_direction(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int offset, int hf,
                                         wmem_allocator_t *scope, const uint8_t **retval)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    proto_item *ti = proto_tree_add_item_ret_string(tree, hf,
                                                    tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                                    scope, retval);
    if (end_of_field_offset - offset == 0)
    {
        if (retval == NULL)
        {
            proto_item_append_text(ti, "[empty]");
        }
        else
        {
            proto_item_append_text(ti, "[missing]");
            expert_add_info(pinfo, ti, &ei_nmea0183_field_missing);
        }
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a latitude field + direction field. The fields are split into a tree with degree, minute and direction elements.
 * Returns length including separator
 **/
static int
dissect_nmea0183_field_latitude(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                int hf_latitude, int hf_degree, int hf_minute, int hf_direction, int ett_latitude)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf_latitude, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    ti = proto_tree_add_item(tree, hf_latitude, tvb, offset, end_of_field_offset - offset, ENC_ASCII);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, ": [empty]");

        end_of_field_offset += dissect_nmea0183_field_latlong_direction(tvb, pinfo, tree, end_of_field_offset + 1, hf_direction, NULL, NULL);
    }
    else if (end_of_field_offset - offset >= 4)
    {
        const uint8_t *degree = NULL;
        const uint8_t *minute = NULL;
        const uint8_t *direction = NULL;
        proto_tree *latitude_subtree = proto_item_add_subtree(ti, ett_latitude);

        proto_tree_add_item_ret_string(latitude_subtree, hf_degree,
                                       tvb, offset, 2,
                                       ENC_ASCII, pinfo->pool, &degree);

        proto_tree_add_item_ret_string(latitude_subtree, hf_minute,
                                       tvb, offset + 2, end_of_field_offset - offset - 2,
                                       ENC_ASCII, pinfo->pool, &minute);

        end_of_field_offset += dissect_nmea0183_field_latlong_direction(tvb, pinfo, latitude_subtree, end_of_field_offset + 1, hf_direction, pinfo->pool, &direction);

        proto_item_append_text(ti, ": %s° %s' %s", degree, minute, direction);
    }
    else
    {
        expert_add_info(pinfo, ti, &ei_nmea0183_field_latitude_too_short);

        end_of_field_offset += dissect_nmea0183_field_latlong_direction(tvb, pinfo, tree, end_of_field_offset + 1, hf_direction, NULL, NULL);
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a longitude field + direction field. The fields are split into a tree with degree, minute and direction elements.
 * Returns length including separator
 **/
static int
dissect_nmea0183_field_longitude(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                 int hf_longitude, int hf_degree, int hf_minute, int hf_direction, int ett_latitude)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf_longitude, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    ti = proto_tree_add_item(tree, hf_longitude, tvb, offset, end_of_field_offset - offset, ENC_ASCII);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, ": [empty]");

        end_of_field_offset += dissect_nmea0183_field_latlong_direction(tvb, pinfo, tree, end_of_field_offset + 1, hf_direction, NULL, NULL);
    }
    else if (end_of_field_offset - offset >= 5)
    {
        const uint8_t *degree = NULL;
        const uint8_t *minute = NULL;
        const uint8_t *direction = NULL;
        proto_tree *longitude_subtree = proto_item_add_subtree(ti, ett_latitude);

        proto_tree_add_item_ret_string(longitude_subtree, hf_degree,
                                       tvb, offset, 3,
                                       ENC_ASCII, pinfo->pool, &degree);

        proto_tree_add_item_ret_string(longitude_subtree, hf_minute,
                                       tvb, offset + 3, end_of_field_offset - offset - 3,
                                       ENC_ASCII, pinfo->pool, &minute);

        end_of_field_offset += dissect_nmea0183_field_latlong_direction(tvb, pinfo, longitude_subtree, end_of_field_offset + 1, hf_direction, pinfo->pool, &direction);

        proto_item_append_text(ti, ": %s° %s' %s", degree, minute, direction);
    }
    else
    {
        expert_add_info(pinfo, ti, &ei_nmea0183_field_longitude_too_short);

        end_of_field_offset += dissect_nmea0183_field_latlong_direction(tvb, pinfo, tree, end_of_field_offset + 1, hf_direction, NULL, NULL);
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a required gps quality field. Returns length including separator */
static int
dissect_nmea0183_field_gps_quality(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    const char *quality = NULL;
    ti = proto_tree_add_item_ret_string(tree, hf,
                                        tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                        pinfo->pool, (const uint8_t**)&quality);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, "[missing]");
        expert_add_info(pinfo, ti, &ei_nmea0183_field_missing);
    }
    else
    {
        proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, quality, known_gps_quality_indicators, "Unknown quality"));
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a single field containing a fixed text.
    The text of the field must match the `expected_text` or expert info `invalid_ei` is
    added to the field. An empty field is allowed. Returns length including separator */
static int
dissect_nmea0183_field_fixed_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf,
                                  const char *expected_text, expert_field *invalid_ei)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    const char *text = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    ti = proto_tree_add_item_ret_string(tree, hf,
                                        tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                        pinfo->pool, (const uint8_t**)&text);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, "[empty]");
    }
    else if (g_ascii_strcasecmp(text, expected_text) != 0)
    {
        expert_add_info(pinfo, ti, invalid_ei);
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a optional FAA mode indicator field. Returns length including separator */
static int
dissect_nmea0183_field_faa_mode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    const char *mode = NULL;
    ti = proto_tree_add_item_ret_string(tree, hf,
                                        tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                        pinfo->pool, (const uint8_t**)&mode);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, "[empty]");
    }
    else
    {
        proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, mode, known_faa_mode_indicators, "Unknown FAA mode"));
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a optional A/V status field. Returns length including separator */
static int
dissect_nmea0183_field_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    const char *mode = NULL;
    ti = proto_tree_add_item_ret_string(tree, hf,
                                        tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                        pinfo->pool, (const uint8_t**)&mode);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, "[empty]");
    }
    else
    {
        proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, mode, known_status_indicators, "Unknown status"));
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a ALR sentence. */
/*
 * $--ALR,hhmmss.ss,xxx,A,A,c--c*hh<CR><LF>
*/
static const string_string alarm_condition_str[] = {
    {"A", "Threshold exceeded"},
    {"V", "Threshold not exceeded"},
    { NULL, NULL},
};

static const string_string alarm_ack_state_str[] = {
    {"A", "Acknowledged"},
    {"V", "Unacknowledged"},
    { NULL, NULL},
};

static int
dissect_nmea0183_sentence_alr(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    unsigned offset = 0;

    proto_tree* subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
        ett_nmea0183_sentence, NULL, "ALR sentence - Set Alarm State");

    /* hhmmss.ss */
    offset += dissect_nmea0183_field_time(tvb, pinfo, subtree, offset, hf_nmea0183_alr_time,
        hf_nmea0183_alr_time_hour, hf_nmea0183_alr_time_minute,
        hf_nmea0183_alr_time_second, ett_nmea0183_alr_time);
    /* xxx Unique alarm number (identifier) at alarm source */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alr_alarm_id, NULL, NULL);
    /* Alarm condition (A = threshold exceeded, V = not exceeded)  */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alr_alarm_cond, NULL, alarm_condition_str);
    /* Alarm’s acknowledge state, A= acknowledged, V= unacknowledged*/
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alr_alarm_ack_st, NULL, alarm_ack_state_str);
    /* c--c Alarm’s description text*/
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alr_alarm_desc_txt, NULL, NULL);

    return tvb_captured_length(tvb);
}

/* Dissect a DPT sentence. */
static int
dissect_nmea0183_sentence_dpt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
        NULL, "DPT sentence - Depth of Water");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dpt_depth, "meter", NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dpt_offset, "meter", NULL);

    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dpt_max_range, "meter", NULL);

    return tvb_captured_length(tvb);
}

/* Dissect a GGA sentence. The time, latitude and longitude fields is split into individual parts. */
static int
dissect_nmea0183_sentence_gga(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GGA sentence - Global Positioning System Fix");

    offset += dissect_nmea0183_field_time(tvb, pinfo, subtree, offset, hf_nmea0183_gga_time,
                                          hf_nmea0183_gga_time_hour, hf_nmea0183_gga_time_minute,
                                          hf_nmea0183_gga_time_second, ett_nmea0183_gga_time);

    offset += dissect_nmea0183_field_latitude(tvb, pinfo, subtree, offset, hf_nmea0183_gga_latitude,
                                              hf_nmea0183_gga_latitude_degree, hf_nmea0183_gga_latitude_minute,
                                              hf_nmea0183_gga_latitude_direction, ett_nmea0183_gga_latitude);

    offset += dissect_nmea0183_field_longitude(tvb, pinfo, subtree, offset, hf_nmea0183_gga_longitude,
                                               hf_nmea0183_gga_longitude_degree, hf_nmea0183_gga_longitude_minute,
                                               hf_nmea0183_gga_longitude_direction, ett_nmea0183_gga_longitude);

    offset += dissect_nmea0183_field_gps_quality(tvb, pinfo, subtree, offset, hf_nmea0183_gga_quality);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_number_satellites, NULL, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_horizontal_dilution, "meter", NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_altitude, "meter", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_gga_altitude_unit,
                                                "M", &ei_nmea0183_gga_altitude_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_geoidal_separation, "meter", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_gga_geoidal_separation_unit,
                                                "M", &ei_nmea0183_gga_geoidal_separation_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_age_dgps, "second", NULL);

    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_dgps_station, NULL, NULL);

    return tvb_captured_length(tvb);
}

/* Dissect a GLL sentence. The latitude, longitude and time fields is split into individual parts. */
static int
dissect_nmea0183_sentence_gll(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GLL sentence - Geographic Position");

    offset += dissect_nmea0183_field_latitude(tvb, pinfo, subtree, offset, hf_nmea0183_gll_latitude,
                                              hf_nmea0183_gll_latitude_degree, hf_nmea0183_gll_latitude_minute,
                                              hf_nmea0183_gll_latitude_direction, ett_nmea0183_gll_latitude);

    offset += dissect_nmea0183_field_longitude(tvb, pinfo, subtree, offset, hf_nmea0183_gll_longitude,
                                               hf_nmea0183_gll_longitude_degree, hf_nmea0183_gll_longitude_minute,
                                               hf_nmea0183_gll_longitude_direction, ett_nmea0183_gll_longitude);

    offset += dissect_nmea0183_field_time(tvb, pinfo, subtree, offset, hf_nmea0183_gll_time,
                                          hf_nmea0183_gll_time_hour, hf_nmea0183_gll_time_minute,
                                          hf_nmea0183_gll_time_second, ett_nmea0183_gll_time);

    offset += dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_gll_status);

    dissect_nmea0183_field_faa_mode(tvb, pinfo, subtree, offset, hf_nmea0183_gll_mode);

    return tvb_captured_length(tvb);
}

/* Dissect a GST sentence. The time field is split into individual parts. */
static int
dissect_nmea0183_sentence_gst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GST sentence - GPS Pseudorange Noise Statistics");

    offset += dissect_nmea0183_field_time(tvb, pinfo, subtree, offset, hf_nmea0183_gst_time,
                                          hf_nmea0183_gst_time_hour, hf_nmea0183_gst_time_minute,
                                          hf_nmea0183_gst_time_second, ett_nmea0183_gst_time);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_rms_total_sd, NULL, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_ellipse_major_sd, "meter", NULL);
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_ellipse_minor_sd, "meter", NULL);
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_ellipse_orientation, "degree (true north)", NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_latitude_sd, "meter", NULL);
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_longitude_sd, "meter", NULL);
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_altitude_sd, "meter", NULL);

    return tvb_captured_length(tvb);
}

/* Dissect a HDT sentence. */
static int
dissect_nmea0183_sentence_hdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "HDT sentence - True Heading");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hdt_heading, "degree", NULL);

    dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_hdt_unit,
                                      "T", &ei_nmea0183_hdt_unit_incorrect);

    return tvb_captured_length(tvb);
}

/* Dissect a ROT sentence. */
static int
dissect_nmea0183_sentence_rot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ROT sentence - Rate Of Turn");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rot_rate_of_turn, "degree per minute", NULL);

    dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_rot_valid);

    return tvb_captured_length(tvb);
}

/* Dissect a TXT sentence */
static int
dissect_nmea0183_sentence_txt(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    unsigned offset = 0;

    proto_tree* subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
        ett_nmea0183_sentence, NULL, "TXT sentence - Text Transmission");

    /* Total number of sentences, 01 to 99  */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_txt_num, NULL, NULL);
    /* Sentence number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_txt_sent_num, NULL, NULL);
    /* Text identifier */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_txt_id, NULL, NULL);
    /* Text message */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_txt_msg, NULL, NULL);

    return tvb_captured_length(tvb);
}


/* Dissect a VHW sentence. */
static int
dissect_nmea0183_sentence_vhw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "VHW sentence - Water speed and heading");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_true_heading, "degree", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_true_heading_unit,
                                                "T", &ei_nmea0183_vhw_true_heading_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_magnetic_heading, "degree", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_magnetic_heading_unit,
                                                "M", &ei_nmea0183_vhw_magnetic_heading_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_water_speed_knot, "knot", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_water_speed_knot_unit,
                                                "N", &ei_nmea0183_vhw_water_speed_knot_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_water_speed_kilometer, "kilometer per hour", NULL);

    dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_water_speed_kilometer_unit,
                                      "K", &ei_nmea0183_vhw_water_speed_kilometer_unit_incorrect);

    return tvb_captured_length(tvb);
}

/* Dissect a VBW sentence. */
static int
dissect_nmea0183_sentence_vbw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "VBW sentence - Dual Ground/Water Speed");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_water_speed_longitudinal, "knot", NULL);
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_water_speed_transverse, "knot", NULL);
    offset += dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_water_speed_valid);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_ground_speed_longitudinal, "knot", NULL);
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_ground_speed_transverse, "knot", NULL);
    offset += dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_ground_speed_valid);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_stern_water_speed, "knot", NULL);
    offset += dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_stern_water_speed_valid);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_stern_ground_speed, "knot", NULL);
    dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_stern_ground_speed_valid);

    return tvb_captured_length(tvb);
}

/* Dissect a VLW sentence. */
static int
dissect_nmea0183_sentence_vlw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "VLW sentence - Distance Traveled through Water");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_cumulative_water, "nautical miles", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_cumulative_water_unit,
                                                "N", &ei_nmea0183_vlw_cumulative_water_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_trip_water, "nautical miles", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_trip_water_unit,
                                                "N", &ei_nmea0183_vlw_trip_water_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_cumulative_ground, "nautical miles", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_cumulative_ground_unit,
                                                "N", &ei_nmea0183_vlw_cumulative_ground_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_trip_ground, "nautical miles", NULL);

    dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_trip_ground_unit,
                                      "N", &ei_nmea0183_vlw_trip_ground_unit_incorrect);

    return tvb_captured_length(tvb);
}

/* Dissect a VTG sentence. */
static int
dissect_nmea0183_sentence_vtg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "VTG sentence - Track made good and Ground speed");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_true_course, "degree", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_true_course_unit,
                                                "T", &ei_nmea0183_vtg_true_course_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_magnetic_course, "degree", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_magnetic_course_unit,
                                                "M", &ei_nmea0183_vtg_magnetic_course_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_ground_speed_knot, "knot", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_ground_speed_knot_unit,
                                                "N", &ei_nmea0183_vtg_ground_speed_knot_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_ground_speed_kilometer, "kilometer per hour", NULL);

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_ground_speed_kilometer_unit,
                                                "K", &ei_nmea0183_vtg_ground_speed_kilometer_unit_incorrect);

    dissect_nmea0183_field_faa_mode(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_mode);

    return tvb_captured_length(tvb);
}

/* Dissect a ZDA (Time & Date) sentence. The time field is split into individual parts. */
static int
dissect_nmea0183_sentence_zda(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ZDA sentence - Time & Date");

    offset += dissect_nmea0183_field_time(tvb, pinfo, subtree, offset, hf_nmea0183_zda_time,
                                          hf_nmea0183_zda_time_hour, hf_nmea0183_zda_time_minute,
                                          hf_nmea0183_zda_time_second, ett_nmea0183_zda_time);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_date_day, NULL, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_date_month, NULL, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_date_year, NULL, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_local_zone_hour, NULL, NULL);

    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_local_zone_minute, NULL, NULL);

    return tvb_captured_length(tvb);
}


/* Dissect a single character or numeric field. Returns length including separator. */
static int
dissect_nmea0183_field_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    proto_item *ti = proto_tree_add_item(tree, hf, tvb, offset, end_of_field_offset - offset, ENC_BIG_ENDIAN);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, "[empty]");
    }
    return end_of_field_offset - offset + 1;
}

/* Skip a field which is represented by an adjacent value or has no registered field. */
static int
dissect_nmea0183_field_skip(tvbuff_t *tvb, int offset)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        return 0;
    }

    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    return end_of_field_offset - offset + 1;
}

/* Return the current field as a packet-scoped string without advancing the offset. */
static const char *
nmea0183_field_value(tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        return "";
    }

    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    return (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset,
                                             end_of_field_offset - offset, ENC_ASCII);
}

/* Dissect a string field and optionally return its item. */
static int
dissect_nmea0183_field_ret_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                int hf, proto_item **item)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_item *ti = proto_tree_add_missing_field(tree, pinfo, hf, tvb,
                                                       tvb_captured_length(tvb));
        if (item != NULL)
        {
            *item = ti;
        }
        return 0;
    }

    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    proto_item *ti = proto_tree_add_item(tree, hf, tvb, offset,
                                         end_of_field_offset - offset, ENC_ASCII);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, "[empty]");
    }
    if (item != NULL)
    {
        *item = ti;
    }
    return end_of_field_offset - offset + 1;
}

/* Dissect a long-range response field and flag an empty requested value. */
static int
dissect_nmea0183_field_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                int hf, const char *description, bool decode_time_value)
{
    const char *value;
    proto_item *ti;
    int length;

    if (offset > (int)tvb_captured_length(tvb))
    {
        ti = proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        value = "";
        length = 0;
    }
    else
    {
        int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
        length = end_of_field_offset - offset;
        value = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII);
        if (decode_time_value)
        {
            ti = proto_tree_add_string(tree, hf, tvb, offset, length,
                                       decode_time(pinfo->pool, value));
        }
        else
        {
            ti = proto_tree_add_string(tree, hf, tvb, offset, length, value);
        }
    }

    if (value[0] == '\0')
    {
        expert_add_info_format(pinfo, ti, &ei_nmea0183_legacy_empty_response,
                               "Empty Response Message (unavailable/not provided) - %s",
                               description);
    }
    return length + 1;
}

/* Dissect a time field and display it in a readable form. Returns length including separator. */
static int
dissect_nmea0183_field_decoded_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    const char *value = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset,
                                                         end_of_field_offset - offset, ENC_ASCII);
    proto_tree_add_string(tree, hf, tvb, offset, end_of_field_offset - offset,
                          decode_time(pinfo->pool, value));
    return end_of_field_offset - offset + 1;
}

/* Dissect a date field and display it in a readable form. Returns length including separator. */
static int
dissect_nmea0183_field_decoded_date(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    const char *value = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset,
                                                         end_of_field_offset - offset, ENC_ASCII);
    proto_tree_add_string(tree, hf, tvb, offset, end_of_field_offset - offset,
                          decode_date(pinfo->pool, value));
    return end_of_field_offset - offset + 1;
}

/* Dissect a latitude or longitude value and its direction field. */
static int
dissect_nmea0183_field_latlong(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    int value_end = tvb_find_end_of_nmea0183_field(tvb, offset);
    int direction_offset = MIN(value_end + 1, (int)tvb_captured_length(tvb));
    int direction_end = tvb_find_end_of_nmea0183_field(tvb, direction_offset);
    const char *value = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset,
                                                         value_end - offset, ENC_ASCII);
    const char *direction = (const char *)tvb_get_string_enc(pinfo->pool, tvb, direction_offset,
                                                             direction_end - direction_offset, ENC_ASCII);
    float coordinate;

    if (decode_latlong(value, direction, &coordinate))
    {
        proto_tree_add_float(tree, hf, tvb, offset, direction_end - offset, coordinate);
    }
    return direction_end - offset + 1;
}

/* Dissect a value and its following unit field as one displayed value. */
static int
dissect_nmea0183_field_with_unit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    int value_end = tvb_find_end_of_nmea0183_field(tvb, offset);
    int unit_offset = MIN(value_end + 1, (int)tvb_captured_length(tvb));
    int unit_end = tvb_find_end_of_nmea0183_field(tvb, unit_offset);
    const char *value = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset,
                                                         value_end - offset, ENC_ASCII);
    const char *unit = (const char *)tvb_get_string_enc(pinfo->pool, tvb, unit_offset,
                                                        unit_end - unit_offset, ENC_ASCII);

    proto_tree_add_string(tree, hf, tvb, offset, value_end - offset,
                          field_binding(pinfo->pool, value, unit));
    return unit_end - offset + 1;
}

/* Dissect an ASCII integer field. Returns length including separator. */
static int
dissect_nmea0183_field_uint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
    uint32_t uint_value;
    proto_item *ti;

    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    int length = end_of_field_offset - offset;
    const char *value = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset,
                                                         length, ENC_ASCII);

    if (length == 0)
    {
        ti = proto_tree_add_uint(tree, hf, tvb, offset, length, 0);
        expert_add_info(pinfo, ti, &ei_nmea0183_field_missing);
    }
    else if (!ws_strtou32(value, NULL, &uint_value))
    {
        ti = proto_tree_add_uint(tree, hf, tvb, offset, length, uint_value);
        expert_add_info_format(pinfo, ti, &ei_nmea0183_field_uint_invalid,
                               "Invalid unsigned integer: %s", value);
    }
    else
    {
        proto_tree_add_uint(tree, hf, tvb, offset, length, uint_value);
    }

    return length + 1;
}

/* Add a satellite-system classification by parsing an ASCII PRN as a decimal number. */
static proto_item *
dissect_nmea0183_satellite_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                int offset, int length, int hf, const char *value)
{
    uint32_t prn;
    proto_item *ti;

    if (value[0] == '\0')
    {
        return NULL;
    }

    if (!ws_strtou32(value, NULL, &prn) || prn > UINT16_MAX)
    {
        ti = proto_tree_add_uint(tree, hf, tvb, offset, length, prn);
        expert_add_info_format(pinfo, ti, &ei_nmea0183_sat_prn_invalid,
                               "Invalid satellite PRN: %s", value);
        return ti;
    }

    return proto_tree_add_uint(tree, hf, tvb, offset, length, prn);
}

static int
dissect_nmea0183_sentence_aam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "AAM sentence - Waypoint Arrival Alarm");
    /* Arrival Circle Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aam_arr_circle_status);

    /* Perpendicular Pass Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aam_perp_status);

    /* Arrival Circle Radius */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_aam_arr_circle_radius, NULL, NULL);

    /* Units of Radius (NM) */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aam_units_radius);

    /* Waypoint ID */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_aam_waypoint, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_abk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ABK sentence - UAIS Addressed and Binary Broadcast Acknowledgement");
    /* MMSI of the Addressed AIS Unit */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_abk_mmsi, NULL, NULL);

    /* AIS Channel of Reception (either A or B) */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_abk_ais_channel);

    /* ITU-R M.1371 Message ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_abk_msg_id, NULL, NULL);

    /* Message Sequence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_abk_msg_seq, NULL, NULL);

    /* Type of Acknowledgement */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_abk_ack_type);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_aca(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ACA sentence - UAIS Regional Channel Assignment Message");

    /* Sequence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_aca_seq_num, NULL, NULL);

    /* Region Northeast Corner Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_aca_ne_clat);

    /* Region Northeast Corner Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_aca_ne_clong);

    /* Region Southwest Corner Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_aca_sw_clat);

    /* Region Southwest Corner Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_aca_sw_clong);

    /* Transition Zone Size (1 to 8 nm) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_aca_zone_size, NULL, NULL);

    /* Channel A */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_aca_chan_a, NULL, NULL);

    /* Channel A Bandwidth */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aca_chan_a_bw);

    /* Channel B */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_aca_chan_b, NULL, NULL);

    /* Channel B Bandwidth */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aca_chan_b_bw);

    /* Tx/Rx Mode Control */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aca_txrx_mode);

    /* Power Level Control */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aca_power);

    /* Information Source */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aca_info_src);

    /* In-use Flag */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_aca_inuse);

    /* Time of "in-use" Change */
    dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_aca_inuse_change);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ACK sentence - Alarm Acknowledgement");
    /* Unique Alarm Number (Identifier) at Alarm Source */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ack_alarm_id, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_acs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ACS sentence - Arco Solar Inc.");

    /* Sequence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_acs_seq_num, NULL, NULL);

    /* MMSI of Originator */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_acs_mmsi, NULL, NULL);

    /* UTC of Receipt of Channel Management Information */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_acs_utc);

    /* Day, 01 to 31 (UTC) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_acs_day, NULL, NULL);

    /* Month, 01 to 12 (UTC) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_acs_month, NULL, NULL);

    /* Year (UTC) */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_acs_year, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_air(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "AIR sentence - UAIS Interrogation Request");
    /* MMSI of Interrogated Station #1 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_air_mmsi_is1, NULL, NULL);

    /* ITU-R M.1371 Message #1 Requested from Station #1 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_air_msg_req, NULL, NULL);

    /* Message #1 Sub-Section from Station #1 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_air_msg_sub, NULL, NULL);

    /* ITU-R M.1371 Message #2 Requested from Station #1 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_air_msg2_req, NULL, NULL);

    /* Message #2 Sub-Section from Station #1 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_air_msg2_sub, NULL, NULL);

    /* MMSI of Interrogated Station #2 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_air_mmsi_is2, NULL, NULL);

    /* ITU-R M.1371 Message #1 Requested from Station #2 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_air_msg_req_is2, NULL, NULL);

    /* Message #1 Sub-Section from Station #2 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_air_msg_sub_is2, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_akd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *value;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "AKD sentence - Acknowledge Detail Alarm Condition");

    /* UTC of Time Acknowledgement */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        /* May be NULL */
        proto_tree_add_string(subtree, hf_nmea0183_akd_utc, tvb, offset, 0, "Time omitted");
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset,
                                                       hf_nmea0183_akd_utc);
    }

    /* System Indicator of Original Alarm Source */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_akd_sys_indicator_orig, NULL,
                                      system_equipment_vals);

    /* Subsystem Equipment Indicator of Original Alarm Source */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_akd_subsys_indicator_orig, NULL,
                                      subsystem_equipment_vals);

    /* Instance number of Equipment Unit/Item */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_akd_inst_num_orig, NULL, NULL);

    /* Type of Alarm */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_akd_alarm_type, NULL, NULL);

    /* System Indicator of the System Sending the Acknowledgement */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        /* May be NULL - this is a table lookup so if it's not there we'll skip past it */
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_akd_sys_indicator_send, NULL,
                                          system_equipment_vals);
    }

    /* Subsystem Indicator of the System Sending the Acknowledgement */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        /* May be NULL - this is a table lookup so if it's not there we'll skip past it */
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_akd_sybsys_indicator_send, NULL,
                                          subsystem_equipment_vals);
    }

    /* Instance of Equipment/Unit/Item Sending the Acknowledgement */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] != '\0')
    {
        dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_akd_inst_num_send, NULL, NULL);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_ala(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ALA sentence - Set Detail Alarm Condition");

    /* Event Time */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_ala_time);

    /* System Indicator */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_ala_sys_indicator, NULL,
                                      system_equipment_vals);

    /* Subsystem Indicator */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_ala_subsys_indicator, NULL,
                                      subsystem_equipment_vals);

    /* Instance Number of Equipment/Unit/Item */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ala_inst_num, NULL, NULL);

    /* Type of Alarm */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ala_alarm_type, NULL, NULL);

    /* Alarm's Condition */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ala_alarm_cond);

    /* Alarm's Acknowledged State */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ala_alarm_ack_state);

    /* Alarm's Description Text */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ala_alarm_text, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_alm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ALM sentence - GPS Almanac Data");
    /* Total Number of Sentences */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_sent_tot, NULL, NULL);

    /* Sentence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_sent_num, NULL, NULL);

    /* Satellite PRN Number, 01 to 32 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_sat_prn, NULL, NULL);

    /* GPS Week Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_gps_week, NULL, NULL);

    /* SV Health, Bits 17-24 of Each Almanac Page */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_sv_health, NULL, NULL);

    /* All the following fields require the scaling factors and units table */

    /* e, Eccentricity */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_eccent, NULL, NULL);

    /* t(oa), Almanac Reference Time */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_alm_ref_time, NULL, NULL);

    /* (sigma), Inclination Angle */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_incl_angle, NULL, NULL);

    /* OMEGADOT, Rate of Right Ascension */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_rate_right_asc, NULL, NULL);

    /* root(A), Root of Semi-Major Axis */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_root_sm_axis, NULL, NULL);

    /* OMEGA, Argument of Perigee */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_arg_perigee, NULL, NULL);

    /* (OMEGA)(o), Longitude of Ascension Node */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_long_asc_node, NULL, NULL);

    /* M(o), Mean Anomaly */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_mean_anomaly, NULL, NULL);

    /* a(f0), Clock Parameter */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_af0_clock_param, NULL, NULL);

    /* a(f1), clock Parameter */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_alm_af1_clock_param, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_apb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *value;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "APB sentence - Autopilot Sentence B");

    /* Data Valid or Loran-C Blink or SNR Warning */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_loranc_blink_snr_warning);

    /* Data Valid or not used / Loran-C Cycle Lock Warning Flag */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_apb_cycle_lock_warning);

    /* Magnitude of XTE (cross-track-error) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_apb_mag_xte, NULL, NULL);

    /* Direction to Steer, L/R */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_apb_dir_steer);

    /* XTE units, nautical miles */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_apb_xte_units);

    /* Status: A = arrival cricle entered */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_apb_arr_circle_status);

    /* Status: A = perpendicular passed at waypoint */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_apb_perp_status);

    /* Bearing Origin to Destination, M/T */
    offset += dissect_nmea0183_field_with_unit(tvb, pinfo, subtree, offset, hf_nmea0183_apb_bearing_origin);

    /* Destination Waypoint ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_apb_waypoint_id, NULL, NULL);

    /* Bearing, Present Position to Destination, Magnetic or True */
    offset += dissect_nmea0183_field_with_unit(tvb, pinfo, subtree, offset, hf_nmea0183_apb_bearing_present);

    /* Heading-to-steer to Destination Waypoint, Magnetic or True */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        proto_tree_add_string(subtree, hf_nmea0183_apb_heading_steer, tvb, offset, 0,
                              "Data unavailable");
        offset += dissect_nmea0183_field_skip(tvb, offset);
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field_with_unit(tvb, pinfo, subtree, offset,
                                                    hf_nmea0183_apb_heading_steer);
    }

    /* Mode Indicator */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_apb_mode);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_bec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "BEC sentence - Boat Electric Corporation");

    /* UTC of Observation */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_bec_utc);

    /* Waypoint Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_bec_latitude);

    /* Waypoint Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_bec_longitude);

    /* Bearing, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bec_bearing_true, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Bearing, degrees Magnetic */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bec_bearing_mag, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Distance (nm) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bec_distance, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Waypoint ID */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bec_waypoint, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_bod(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "BOD sentence - Bearing - Waypoint to Waypoint");
    /* Bearing, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bod_bearing_true, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Bearing, degrees Magnetic */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bod_bearing_mag, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Destination Waypoint ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bod_dest_waypoint, NULL, NULL);

    /* Origin Waypoint ID */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bod_orig_waypoint, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_bwc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "BWC sentence - Bearing & Distance to Waypoint - Great Circle");

    /* UTC of Observation */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_bwc_utc);

    /* Waypoint Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_bwc_latitude);

    /* Waypoint Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_bwc_longitude);

    /* Bearing, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bwc_bearing_true, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Bearing, degrees Magnetic */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bwc_bearing_mag, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Distance (nm) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bwc_distance, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Waypoint ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bwc_waypoint, NULL, NULL);

    /* Mode Indicator */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_bwc_mode);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_bwr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "BWR sentence - Bearing and Distance to Waypoint - Rhumb Line");

    /* UTC of Observation */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_bwr_utc);

    /* Waypoint Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_bwr_latitude);

    /* Waypoint Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_bwr_longitude);

    /* Bearing, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bwr_bearing_true, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Bearing, degrees Magnetic */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bwr_bearing_mag, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Distance (nm) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bwr_distance, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Waypoint ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bwr_waypoint, NULL, NULL);

    /* Mode Indicator */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_bwr_mode);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_bww(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "BWW sentence - Bearing - Waypoint to Waypoint");
    /* Bearing, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bww_bearing_true, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Bearing, degrees Magnetic */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bww_bearing_mag, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* TO Waypoint ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bww_to_waypoint, NULL, NULL);

    /* FROM Waypoint ID */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_bww_from_waypoint, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_cbr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "CBR sentence - Configure Broadcast Rates for AIS AtoN Station Message Command");
    /* MMSI */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_mmsi, NULL, NULL);

    /* Message ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_msg_id, NULL, NULL);

    /* Message ID Index */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_msd_id_index, NULL, NULL);

    /* Start UTC Hour, Channel A */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_hr_chan_a, NULL, NULL);

    /* Start UTC Minute, Channel A */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_min_chan_a, NULL, NULL);

    /* Start Slot, Channel A */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_slot_chan_a, NULL, NULL);

    /* Slot Interval, Channel A */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_interv_chan_a, NULL, NULL);

    /* FATDMA or RATDMA/CSTDMA Setup */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_setup);

    /* Start UTC Hour, Channel B */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_hr_chan_b, NULL, NULL);

    /* Start UTC Minute, Channel B */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_min_chan_b, NULL, NULL);

    /* Start Slot, Channel B */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_slot_chan_b, NULL, NULL);

    /* Slot Interval, Channel B */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_interv_chan_b, NULL, NULL);

    /* Sentence Status Flag */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_cbr_status);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_cur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "CUR sentence - Water Current Layer");
    /* Validity of the Data */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_cur_validity);

    /* Data Set Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cur_data_set, NULL, NULL);

    /* Layer Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cur_layer, NULL, NULL);

    /* Current Depth in meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cur_depth, NULL, NULL);

    /* Current Direction in degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cur_direction, NULL, NULL);

    /* Direction Reference in use (True/Relative) */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_cur_direction_ref);

    /* Current Speed in knots */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cur_speed, NULL, NULL);

    /* Reference Layer Depth in meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cur_ref_layer, NULL, NULL);

    /* Heading */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_cur_heading, NULL, NULL);

    /* Heading Reference in use (True/Magnetic) */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_cur_heading_ref);

    /* Speed Reference */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_cur_speed_ref);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_dbt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DBT sentence - Echosounder - Depth Below Transducer");

    /* Water Depth (feet) */
    offset += dissect_nmea0183_field_with_unit(tvb, pinfo, subtree, offset, hf_nmea0183_dbt_feet);

    /* Water Depth (meters) */
    offset += dissect_nmea0183_field_with_unit(tvb, pinfo, subtree, offset, hf_nmea0183_dbt_meters);

    /* Water Depth (fathoms) */
    dissect_nmea0183_field_with_unit(tvb, pinfo, subtree, offset, hf_nmea0183_dbt_fathoms);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_dcn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DCN sentence - DECCA Position");
    /* Decca Chain Identifier */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_dc_id, NULL, NULL);

    /* Red Zone Identifier, Number-Letter */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_rz_id, NULL, NULL);

    /* Red Line of Position (LOP) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_rlop, NULL, NULL);

    /* Status: Red-Master Line */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_rstatus);

    /* Green Zone Identifier, Number-Letter */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_gz_id, NULL, NULL);

    /* Green LOP */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_glop, NULL, NULL);

    /* Status: Green-Master Line */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_gstatus);

    /* Purple Zone Identifier, Number-Letter */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_pz_id, NULL, NULL);

    /* Purple LOP */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_plop, NULL, NULL);

    /* Status: Purple-Master Line */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_pstatus);

    /* Red-line Navigation Use */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_rnav);

    /* Green-line Navigation Use */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_gnav);

    /* Purple-line Navigation Use */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_pnav);

    /* Position Uncertainty (nm) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_pos_uncertainty, NULL, NULL);

    /* Fix Data Basis */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dcn_data_basis);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_ddc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DDC sentence - Display Dimming Control");
    /* Display Dimming Preset */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ddc_dimming);

    /* Brightness Percentage (00 to 99) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ddc_brightness, NULL, NULL);

    /* Color Palette */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ddc_palette);

    /* Sentence Status Flag */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ddc_status);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_dor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *message_type;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DOR sentence - Door Status Detection");

    /* Message Type */
    message_type = nmea0183_field_value(tvb, pinfo, offset);
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dor_msg_type);

    /* Event Time (UTC) - may be NULL */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset,
                                                   hf_nmea0183_dor_time);

    /* Type of Door Monitoring System */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_dor_system_type, NULL,
                                      door_mon_sys_type_vals);

    /* First Division Indicator */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_dor_first_indic, NULL, NULL);

    /* Second Division Indicator */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_dor_second_indic, NULL, NULL);

    /* If Message Type is 'S' then it represents number of open or faulty doors.
     * If Message Type is 'E' then it represents the door number.
     * If Message Type is 'F' then this field is NULL so just continue */
    if (strcmp(message_type, "S") == 0)
    {
        /* Count of Open/Faulty Doors */
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_dor_open_count, NULL, NULL);
    }
    else if (strcmp(message_type, "E") == 0)
    {
        /* Door Number */
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_dor_door_num, NULL, NULL);
    }
    else
    {
        /* Message Type is "F" so this field is NULL so offset and continue */
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }

    /* Door Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dor_status);

    /* Watertight Door Switch Setting */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dor_setting);

    /* Message Description Text */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dor_text, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_dsc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DSC sentence - Dynascan Corporation");
    /* Format Specifier */
    /* TODO: Set up ITU-R M.493 Table 3 and map to two least-significant bits */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_format, NULL, NULL);

    /* Address (i.e., MMSI for the station to be called or
     * the MMSI of the calling station in a received call */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_address, NULL, NULL);

    /* Category */
    /* TODO: Set up ITU-R M.493 Table 3 and map to two least-significant bits */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_category, NULL, NULL);

    /* Nature of Distress or First Telecommand */
    /* TODO: Set up ITU-R M.493 Table 3 and map to two least-significant bits */
    /* Nature of Distress is used here ONLY for distress calls */
    /* TODO: Probably ought to use an if/else statement with two separate fields here */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_first_tcmd, NULL, NULL);

    /* Type of Communication or Second Telecommand */
    /* TODO: Set up ITU-R M.493 Table 3 and map to two least-significant bits */
    /* Type of Communication is used here ONLY for:
     * (1) Distress
     * (2) Distress Acknowledgement
     * (3) Distress Relay
     * (4) Distress Relay Acknowledgement */
    /* TODO: Probably ought to use an if/else statement with two separate fields here */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_comm_type, NULL, NULL);

    /* Position or Channel/Frequency */
    /* TODO: Set up ITU-R M.493 Paragraph 8.1.2 table for Position Message */
    /* TODO: Set up ITU-R M.493 Table 13 for Channel/Frequency Message */
    /* TODO: Probably ought to use an if/else statement with two separate fields here */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_position, NULL, NULL);

    /* Time or Telephone Number */
    /* Time is HHMM format and in UTC */
    /* Telephone Number is 16 digits max., odd/even information inserted by DSC equipment */
    /* TODO: Probably ought to use an if/else statement with two separate fields here */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_time, NULL, NULL);

    /* MMSI of Ship in Distress */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_mmsi, NULL, NULL);

    /* Nature of Distress */
    /* TODO: Set up ITU-R M.493 Table 3 and map to two least-significant bits */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_nature_distress, NULL, NULL);

    /* Acknowledgement */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_ack);

    /* Expansion Indicator */
    /* TODO: Write code to account for expanded messages when this is set to 'E' */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsc_expansion, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_dse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DSE sentence - Extended DSC");
    /* Total Number of Sentences */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dse_total_sentences, NULL, NULL);

    /* Sentence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dse_sentence_number, NULL, NULL);

    /* Query/Reply Flag */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_dse_flag);

    /* Vessel MMSI */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dse_mmsi, NULL, NULL);

    /* TODO: This is a loop - can be a lot of "Data sets" comprised of a code field and data field */
    /* Code Field */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dse_code, NULL, NULL);

    /* Data Field */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dse_data, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_dsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DSI sentence - DSC Transponder Initiate");
    /* Total Number of Sentences */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_total_sentences, NULL, NULL);

    /* Sentence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_sentence_number, NULL, NULL);

    /* Vessel MMSI */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_mmsi, NULL, NULL);

    /* Vessel Course, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_course, NULL, NULL);

    /* Vessel Type */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_type, NULL, NULL);

    /* Geographic Area, 0.01 minutes */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_geo_area, NULL, NULL);

    /* TODO: The next two fields are part of a 1-to-n loop of "Command Sets" */
    /* Symbol Field */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_symbol, NULL, NULL);

    /* Information Field */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_info, NULL, NULL);

    /* TODO:  Account for expanded messages when this is set to 'E' */
    /* Expansion Indicator */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsi_expansion, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_dsr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DSR sentence - DSC Transponder Response");
    /* Total Number of Sentences */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsr_total_sentences, NULL, NULL);

    /* Sentence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsr_sentence_number, NULL, NULL);

    /* Vessel MMSI */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsr_mmsi, NULL, NULL);

    /* TODO: The next two fields are part of a 1-to-n loop of "Command Sets" */
    /* Symbol Field */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsr_symbol, NULL, NULL);

    /* Information Field */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsr_info, NULL, NULL);

    /* TODO:  Account for expanded messages when this is set to 'E' */
    /* Expansion Indicator */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dsr_expansion, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_dtm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *datum_code;
    const char *value;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "DTM sentence - Datum Reference");

    /* Datum Code */
    value = nmea0183_field_value(tvb, pinfo, offset);
    datum_code = try_str_to_str(value, datum_vals);
    proto_tree_add_string(subtree, hf_nmea0183_dtm_datum, tvb, offset, (int)strlen(value),
                          datum_code ? datum_code : "Unknown Datum/Unavailable");
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Datum Subdivision Code */
    /* TODO: Create table from IHO Publication S-60 Appendices B and C, perhaps in a separate file due to size */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        proto_tree_add_string(subtree, hf_nmea0183_dtm_datum_subdiv, tvb, offset, 0,
                              "Data unavailable");
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_dtm_datum_subdiv, NULL, NULL);
    }

    /* Latitude Offset in minutes */
    /* TODO: Write an offset decode function for latitude and longitude offsets */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_dtm_lat_offset, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Longitude Offset in minutes */
    /* TODO: Write an offset decode function for latitude and longitude offsets */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_dtm_lon_offset, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Altitude Offset in meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dtm_alt_offset, NULL, NULL);

    /* Reference Datum Code */
    value = nmea0183_field_value(tvb, pinfo, offset);
    datum_code = try_str_to_str(value, datum_vals);
    proto_tree_add_string(subtree, hf_nmea0183_dtm_ref_datum, tvb, offset, (int)strlen(value),
                          datum_code ? datum_code : "Unknown Datum/Unavailable");

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_etl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ETL sentence - Engine Telegraph Operation Status");

    /* Event Time */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_etl_time);

    /* Message Type */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_etl_msg_type);

    /* Position Indicator of Engine Telegraph */
    offset += dissect_nmea0183_field_uint(tvb, pinfo, subtree, offset, hf_nmea0183_etl_posind_engine);

    /* Position Indicator of Sub Telegraph */
    offset += dissect_nmea0183_field_uint(tvb, pinfo, subtree, offset, hf_nmea0183_etl_posind_sub);

    /* Operating Location Indicator */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_etl_opind);

    /* Number of Engine or Propeller Shafts */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_etl_num_eng_shaft, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_fsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "FSI sentence - Frequency Set Information");
    /* Transmit Frequency (100 Hz Increments) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_fsi_xmit_freq, NULL, NULL);

    /* Receive Frequency (100 Hz Increments) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_fsi_recv_freq, NULL, NULL);

    /* Mode of Operation */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_fsi_mode);

    /* Power Level */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_fsi_power);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_gbs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *value;
    int length;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GBS sentence - GPS Satellite Fault Detection");

    /* UTC of Position */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_gbs_utc);

    /* Expected Error in Latitude */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gbs_lat_err, NULL, NULL);

    /* Expected Error in Longitude */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gbs_long_err, NULL, NULL);

    /* Expected Error in Altitude */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gbs_alt_err, NULL, NULL);

    /* ID Number of Most Likely Failed Satellite */
    value = nmea0183_field_value(tvb, pinfo, offset);
    length = (int)strlen(value);
    if (length == 0)
    {
        proto_tree_add_string(subtree, hf_nmea0183_gbs_sat_id, tvb, offset, 0,
                              "Satellite ID unavailable");
    }
    else
    {
        proto_tree_add_string(subtree, hf_nmea0183_gbs_sat_id, tvb, offset, length, value);
        dissect_nmea0183_satellite_type(tvb, pinfo, subtree, offset, length,
                                        hf_nmea0183_gbs_sat_type, value);
    }
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Probability of Missed Detection for Most Likely Failed Satellite */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        proto_tree_add_string(subtree, hf_nmea0183_gbs_prob_miss, tvb, offset, 0,
                              "Data not available");
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_gbs_prob_miss, NULL, NULL);
    }

    /* Estimate of Bias in meters on Most Likely Failed Satellite */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        proto_tree_add_string(subtree, hf_nmea0183_gbs_est_bias, tvb, offset, 0,
                              "Data not available");
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_gbs_est_bias, NULL, NULL);
    }

    /* Standard Deviation of Bias Estimate */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        proto_tree_add_string(subtree, hf_nmea0183_gbs_std_dev, tvb, offset, 0,
                              "Data not available");
    }
    else
    {
        dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gbs_std_dev, NULL, NULL);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_glc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GLC sentence - Geographic Position, Loran-C");
    /* GRI, tens of microseconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_glc_gri, NULL, NULL);

    /* Master TOA, microseconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_glc_master_toa, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Time Difference #1, microseconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_glc_td1, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Time Difference #2, microseconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_glc_td2, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Time Difference #3, microseconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_glc_td3, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Time Difference #4, microseconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_glc_td4, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Time Difference #5, microseconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_glc_td5, NULL, NULL);

    /* Signal Status */
    proto_tree_add_item(subtree, hf_nmea0183_glc_sig_status, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_gmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *mode;
    int mode_offset;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GMP sentence - GNSS Map Projection Fix Data");

    /* UTC of Position */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_utc);

    /* Map Projection Identification */
    /* TODO: Convert three-character values to strings:
     * UTM = Universal Transverse Mercator | LOC = Local Coordinate System */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_projection, NULL, NULL);

    /* Map Zone */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_zone, NULL, NULL);

    /* X (Northern) component of grid (or local) coordinates */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_x_comp, NULL, NULL);

    /* Y (Eastern) component of grid (or local) coordinates */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_y_comp, NULL, NULL);

    /* Mode Indicator */
    mode_offset = offset;
    mode = nmea0183_field_value(tvb, pinfo, offset);
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_mode_string, NULL, NULL);

    /* This is a variable length string that uses a table lookup for each character.
     * The first character indicates use of GPS satellites.
     * The second character indicates use of GLONASS satellites.
     * The third to nth character indicates new satellite systems not-yet-incorporated */
    for (int i = 0; mode[i] != '\0'; i++)
    {
        /* GPS Mode Indicator */
        if (i == 0)
        {
            proto_tree_add_item(subtree, hf_nmea0183_gmp_mode_gps, tvb,
                                mode_offset + i, 1, ENC_BIG_ENDIAN);
        }
        /* GLONASS Mode Indicator */
        else if (i == 1)
        {
            proto_tree_add_item(subtree, hf_nmea0183_gmp_mode_glonass, tvb,
                                mode_offset + i, 1, ENC_BIG_ENDIAN);
        }
        /* Other Satellite System Mode Indicators (1 to n) */
        else
        {
            proto_tree_add_item(subtree, hf_nmea0183_gmp_mode_other, tvb,
                                mode_offset + i, 1, ENC_BIG_ENDIAN);
        }
    }
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Total Number of Satellites in use, 00-99 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_tot_sats, NULL, NULL);

    /* Horizontal Dilution of Precision */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_hdop, NULL, NULL);

    /* Antenna Altitude in meters, re: mean-sea-level (geoid) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_ant_alt, NULL, NULL);

    /* Geoidal Separation in meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_geoid_sep, NULL, NULL);

    /* Age of Differential Data */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_data_age, NULL, NULL);

    /* Differential Reference Station ID */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gmp_diff_ref_id, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_gns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *mode;
    const char *value;
    int mode_offset;
    proto_item *pi;
    proto_tree *pt;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GNS sentence - GNSS Fix data");

    /* UTC of Position */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_gns_utc);

    /* Latitude */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        /* Skip this field and the next since we don't have anything to report */
        offset += dissect_nmea0183_field_skip(tvb, offset);
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset,
                                                  hf_nmea0183_gns_latitude);
    }

    /* Longitude */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        /* Skip this field and the next since we don't have anything to report */
        offset += dissect_nmea0183_field_skip(tvb, offset);
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset,
                                                  hf_nmea0183_gns_longitude);
    }

    /* Mode Indicator */
    mode_offset = offset;
    mode = nmea0183_field_value(tvb, pinfo, offset);
    if (mode[0] == '\0')
    {
        /* Skip this field since we have nothing to report */
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field_ret_item(tvb, pinfo, subtree, offset,
                                                   hf_nmea0183_gns_mode_string, &pi);
        pt = proto_item_add_subtree(pi, ett_nmea0183_legacy_satellite_info);
        /* This is a variable length string that uses a table lookup for each character.
         * The first character indicates use of GPS satellites.
         * The second character indicates use of GLONASS satellites.
         * The third to nth character indicates new satellite systems not-yet-incorporated */
        for (int i = 0; mode[i] != '\0'; i++)
        {
            /* GPS Mode Indicator */
            if (i == 0)
            {
                proto_tree_add_item(pt, hf_nmea0183_gns_mode_gps, tvb,
                                    mode_offset + i, 1, ENC_BIG_ENDIAN);
            }
            /* GLONASS Mode Indicator */
            else if (i == 1)
            {
                proto_tree_add_item(pt, hf_nmea0183_gns_mode_glonass, tvb,
                                    mode_offset + i, 1, ENC_BIG_ENDIAN);
            }
            /* Other Satellite System Mode Indicators (1 to n) */
            else
            {
                proto_tree_add_item(pt, hf_nmea0183_gns_mode_other, tvb,
                                    mode_offset + i, 1, ENC_BIG_ENDIAN);
            }
        }
    }

    /* Total Number of Satellites in use, 00-99 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gns_tot_sats, NULL, NULL);

    /* Horizontal DOP */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gns_hdop, NULL, NULL);

    /* Antenna Altitude in meters (re: mean-sea-level - geoid) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gns_ant_alt, NULL, NULL);

    /* Geoidal Separation in meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gns_geoid_sep, NULL, NULL);

    /* Age of Differential Data */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        proto_tree_add_string(subtree, hf_nmea0183_gns_data_age, tvb, offset, 0,
                              "DGPS is not used");
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_gns_data_age, NULL, NULL);
    }

    /* Differential Reference Station ID */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        proto_tree_add_string(subtree, hf_nmea0183_gns_diff_ref_id, tvb, offset, 0, "[None]");
    }
    else
    {
        dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gns_diff_ref_id, NULL, NULL);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_grs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GRS sentence - GNSS Range Residuals");
    /* UTC decoded_time of associated GGA/GNS fix */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_grs_utc);

    /* Mode (residuals) */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_grs_mode);

    /* Can be multiple range residuals */
    while (tvb_captured_length_remaining(tvb, offset) > 0)
    {
        /* Range Residuals */
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_grs_range_resid, NULL, NULL);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_gsa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *value;
    int length;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GSA sentence - GNSS DOP and Active Satellites");

    /* Operational Mode - Manual or Automatic */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_gsa_op_mode);

    /* Fix Mode */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_gsa_fix_mode);

    /* 12x Satellite IDs */
    for (int i = 0; i < 12; i++)
    {
        /* Satellite ID */
        value = nmea0183_field_value(tvb, pinfo, offset);
        length = (int)strlen(value);
        if (length == 0)
        {
            proto_tree_add_string(subtree, hf_nmea0183_gsa_sat_id, tvb, offset, 0,
                                  "[No Satellite]");
        }
        else
        {
            proto_tree_add_string(subtree, hf_nmea0183_gsa_sat_id, tvb, offset, length, value);
            dissect_nmea0183_satellite_type(tvb, pinfo, subtree, offset, length,
                                            hf_nmea0183_gsa_sat_type, value);
        }
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }

    /* Position DOP */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gsa_pdop, NULL, NULL);

    /* Horizontal DOP */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gsa_hdop, NULL, NULL);

    /* Vertical DOP */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gsa_vdop, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_gsv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *value;
    int length;
    int satellite_offset;
    proto_item *pi;
    proto_tree *pt;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "GSV sentence - GNSS Satellites in View");

    /* Total Number of Sentences, 1 to 9 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gsv_total_sentences, NULL, NULL);

    /* Sentence Number, 1 to 9 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gsv_sentence_number, NULL, NULL);

    /* Total Number of Satellites in View */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gsv_sats_in_view, NULL, NULL);

    /* Variable number of "Satellite ID-Elevation-Azimuth-SNR" string sets (from 1 to 4) */
    for (int i = 0; i < 4 && tvb_captured_length_remaining(tvb, offset) > 0; i++)
    {
        /* Satellite ID Number (use PRN numbers) */
        satellite_offset = offset;
        value = nmea0183_field_value(tvb, pinfo, offset);
        offset += dissect_nmea0183_field_ret_item(tvb, pinfo, subtree, offset,
                                                   hf_nmea0183_gsv_sat_id, &pi);
        pt = proto_item_add_subtree(pi, ett_nmea0183_legacy_satellite_info);

        /* Satellite type based on the numeric PRN range. */
        length = (int)strlen(value);
        dissect_nmea0183_satellite_type(tvb, pinfo, pt, satellite_offset, length,
                                        hf_nmea0183_gsv_sat_type, value);

        /* Elevation, degrees, 90deg maximum */
        offset += dissect_nmea0183_field(tvb, pinfo, pt, offset,
                                          hf_nmea0183_gsv_elevation, NULL, NULL);

        /* Azimuth, degrees True, 00 to 359 */
        offset += dissect_nmea0183_field(tvb, pinfo, pt, offset,
                                          hf_nmea0183_gsv_azimuth, NULL, NULL);

        /* SNR (C/No) 00-99 dB-Hz, null when not tracking */
        value = nmea0183_field_value(tvb, pinfo, offset);
        if (value[0] == '\0')
        {
            proto_tree_add_string(pt, hf_nmea0183_gsv_snr, tvb, offset, 0, "Not tracking");
            offset += dissect_nmea0183_field_skip(tvb, offset);
        }
        else
        {
            offset += dissect_nmea0183_field(tvb, pinfo, pt, offset,
                                              hf_nmea0183_gsv_snr, NULL, NULL);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_hbt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *value;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "HBT sentence - Heartbeat Supervision Report");
    /* Configured Repeat Interval */
    value = nmea0183_field_value(tvb, pinfo, offset);
    if (value[0] == '\0')
    {
        /* NULL in response to a query */
        proto_tree_add_string(subtree, hf_nmea0183_hbt_interval, tvb, offset, 0,
                              "NULL for query");
        offset += dissect_nmea0183_field_skip(tvb, offset);
    }
    else
    {
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_hbt_interval, NULL, NULL);
    }

    /* Equipment Status (Normal/Abnormal) */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_hbt_status);

    /* Sequential Sentence Identifier */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hbt_sent_id, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_hdg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "HDG sentence - Heading - Deviation & Variation");
    /* Magnetic Sensor Heading, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hdg_mag_sensor, NULL, NULL);

    /* Magnetic Deviation, degrees E/W */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hdg_mag_dev, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Magnetic Variation, degrees E/W */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hdg_mag_var, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_hmr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "HMR sentence - Heading, Monitor Receive");
    /* Heading Sensor #1 ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_heading_s1, NULL, NULL);

    /* Heading Sensor #2 ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_heading_s2, NULL, NULL);

    /* Difference Limit Setting, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_difflim_setting, NULL, NULL);

    /* Actual Heading Sensor Difference, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_heading_sdiff, NULL, NULL);

    /* Warning Flag */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_warning_flag);

    /* Heading Reading, Sensor #1, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_hr_s1, NULL, NULL);

    /* Status, Sensor #1 */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_status_s1);

    /* Sensor #1 Type */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_s1_type);

    /* Deviation, Sensor #1, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_dev_s1, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Heading Reading, Sensor #2, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_hr_s2, NULL, NULL);

    /* Status, Sensor #2 */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_status_s2);

    /* Sensor #2 Type */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_s2_type);

    /* Deviation, Sensor #2, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_dev_s2, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Variation, degrees */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hmr_variation, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_hms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "HMS sentence - Hyde Marine Systems, Inc.");
    /* Heading, Sensor #1 ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hms_heading_s1, NULL, NULL);

    /* Heading, Sensor #2 ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hms_heading_s2, NULL, NULL);

    /* Maximum Difference (allowed between sensors), degrees */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hms_max_diff, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_hsc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "HSC sentence - Heading Steering Command");
    /* Commanded Heading, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hsc_heading_true, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Commanded Heading, degrees Magnetic */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hsc_heading_magnetic, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_htc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "HTC sentence - Heading/Track Control Command");
    /* Override */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htc_override);

    /* Commanded rudder angle, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_rudder_angle, NULL, NULL);

    /* Commanded rudder direction, L/R=port/starboard */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_rudder_dir);

    /* Selected Steering Mode */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htc_steering_mode);

    /* Turn Mode */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htc_turn_mode);

    /* Commanded Rudder Limit, degrees (unsigned) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_rudder_lim, NULL, NULL);

    /* Commanded Off-heading Limit, degrees (unsigned) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_offhead_lim, NULL, NULL);

    /* Commanded Radius of Turn for Heading Changes, n. miles */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_radius, NULL, NULL);

    /* Commanded Rate of Turn for Heading Changes, deg./minute */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_rate, NULL, NULL);

    /* Commanded Heading-to-Steer, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_steer, NULL, NULL);

    /* Commanded Off-Track Limit, n. miles (unsigned) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_offtrack, NULL, NULL);

    /* Commanded Track, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htc_cmd_track, NULL, NULL);

    /* Heading Reference in Use, T/M */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htc_heading_ref);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_htd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "HTD sentence - Heading/Track Control Data");
    /* Override */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htd_override);

    /* Commanded rudder angle, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_rudder_angle, NULL, NULL);

    /* Commanded rudder direction, L/R=port/starboard */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_rudder_dir);

    /* Selected Steering Mode */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htd_steering_mode);

    /* Turn Mode */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htd_turn_mode);

    /* Commanded Rudder Limit, degrees (unsigned) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_rudder_lim, NULL, NULL);

    /* Commanded Off-heading Limit, degrees (unsigned) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_offhead_lim, NULL, NULL);

    /* Commanded Radius of Turn for Heading Changes, n. miles */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_radius, NULL, NULL);

    /* Commanded Rate of Turn for Heading Changes, deg./minute */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_rate, NULL, NULL);

    /* Commanded Heading-to-Steer, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_steer, NULL, NULL);

    /* Commanded Off-Track Limit, n. miles (unsigned) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_offtrack, NULL, NULL);

    /* Commanded Track, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_cmd_track, NULL, NULL);

    /* Heading Reference in Use, T/M */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htd_heading_ref);

    /* Rudder Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htd_rudder_status);

    /* Off-heading Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htd_offhdng_status);

    /* Off-Track Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_htd_offtrack_status);

    /* Vessel Heading, degrees */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_htd_vessel_heading, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_lcd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "LCD sentence - Loran-C Signal Data");
    /* GRI, tens of microseconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_gri, NULL, NULL);

    /* Master - SNR */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_master_snr, NULL, NULL);

    /* Master - Pulse Shape (ECD) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_master_ecd, NULL, NULL);

    /* Secondary 1 - SNR */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s1_snr, NULL, NULL);

    /* Secondary 1 - Pulse Shape (ECD) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s1_ecd, NULL, NULL);

    /* Secondary 2 - SNR */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s2_snr, NULL, NULL);

    /* Secondary 2 - Pulse Shape (ECD) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s2_ecd, NULL, NULL);

    /* Secondary 3 - SNR */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s3_snr, NULL, NULL);

    /* Secondary 3 - Pulse Shape (ECD) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s3_ecd, NULL, NULL);

    /* Secondary 4 - SNR */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s4_snr, NULL, NULL);

    /* Secondary 4 - Pulse Shape (ECD) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s4_ecd, NULL, NULL);

    /* Secondary 5 - SNR */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s5_snr, NULL, NULL);

    /* Secondary 5 - Pulse Shape (ECD) */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lcd_s5_ecd, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_lrf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *value;
    int field_offset;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "LRF sentence - UAIS Long-Range Function");
    /* Sequence Number, 0 to 9 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lrf_seqnum, NULL, NULL);

    /* MMSI of Requestor */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lrf_mmsi, NULL, NULL);

    /* Name of Requestor */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lrf_name, NULL, NULL);

    /* Function Request, 1 to 26 characters */
    field_offset = offset;
    value = nmea0183_field_value(tvb, pinfo, offset);
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lrf_function_req, NULL, NULL);

    /* This is a variable length string that uses a table lookup for each character. */
    for (int i = 0; value[i] != '\0'; i++)
    {
        /* Add each function request by looking it up and resolving it. */
        proto_tree_add_item(subtree, hf_nmea0183_lrf_function_req_val, tvb,
                            field_offset + i, 1, ENC_BIG_ENDIAN);
    }
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Function Reply Status */
    field_offset = offset;
    value = nmea0183_field_value(tvb, pinfo, offset);
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lrf_function_rep, NULL, NULL);

    /* This is a variable length string that uses a table lookup for each character. */
    for (int i = 0; value[i] != '\0'; i++)
    {
        /* Add each function reply by looking it up and resolving it. */
        proto_tree_add_item(subtree, hf_nmea0183_lrf_function_rep_val, tvb,
                            field_offset + i, 1, ENC_BIG_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_lri(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "LRI sentence - UAIS Long-Range Interrogation");
    /* Sequence Number, 0 to 9 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lri_seqnum, NULL, NULL);

    /* Control Flag */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset,
                                           hf_nmea0183_lri_control);

    /* MMSI of Requestor */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lri_req_mmsi, NULL, NULL);

    /* MMSI of Destination */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lri_dest_mmsi, NULL, NULL);

    /* NE Corner Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_lri_latitude_ne);

    /* NE Corner Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_lri_longitude_ne);

    /* SW Corner Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_lri_latitude_sw);

    /* SW Corner Longitude */
    dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset,
                                    hf_nmea0183_lri_longitude_sw);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_lr1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "LR1 sentence - UAIS Long-range Reply Sentence 1");
    /* Sequence Number, 0 to 9 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr1_seqnum, NULL, NULL);

    /* MMSI of Responder */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr1_resp_mmsi, NULL, NULL);

    /* MMSI of Requestor */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr1_req_mmsi, NULL, NULL);

    /* Ship's Name */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr1_shipname, "Ship's Name", false);

    /* Call Sign */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr1_callsign, NULL, NULL);

    /* IMO Number */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr1_imo_num, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_lr2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "LR2 sentence - UAIS Long-range Reply Sentence 2");

    /* Sequence Number, 0 to 9 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr2_seqnum, NULL, NULL);

    /* MMSI of Responder */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr2_resp_mmsi, NULL, NULL);

    /* Date (ddmmyyyy) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr2_date, NULL, NULL);

    /* UTC of Position */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_lr2_utc);

    /* Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_lr2_latitude);

    /* Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_lr2_longitude);

    /* Course over ground, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr2_course_ground, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Speed over ground, knots */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_lr2_speed_ground, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_lr3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "LR3 sentence - UAIS Long-range Reply Sentence 3");

    /* Sequence Number, 0 to 9 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_lr3_seqnum, NULL, NULL);

    /* MMSI of Responder */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_lr3_resp_mmsi, NULL, NULL);

    /* Voyage Destination, 1 to 20 characters */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr3_destination,
                                               "Voyage Destination", false);

    /* ETA Date (ddmmyyyy) */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr3_eta_date,
                                               "ETA Date (ddmmyyyy)", false);

    /* ETA Time */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr3_eta_time,
                                               "ETA Time (hhmmss.ss)", true);

    /* Draught */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr3_draught,
                                               "Draught", false);

    /* Ship's Cargo */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr3_ship_cargo,
                                               "Ship's Cargo", false);

    /* Ship's Length */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr3_ship_length,
                                               "Ship's Length", false);

    /* Ship's Breadth */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr3_ship_breadth,
                                               "Ship's Breadth", false);

    /* Ship Type */
    offset += dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                               hf_nmea0183_lr3_ship_type,
                                               "Ship Type", false);

    /* Persons, 0 to 8191, 8191 means greater than or equal to 8191 people */
    dissect_nmea0183_field_response(tvb, pinfo, subtree, offset,
                                     hf_nmea0183_lr3_persons,
                                     "Personnel Aboard", false);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_mla(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "MLA sentence - GLONASS Almanac Data");
    /* Total Number of Sentences */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_total_sentences, NULL, NULL);

    /* Sentence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_sentence_number, NULL, NULL);

    /* Satellite ID (satellite slot) number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_sat_id, NULL, NULL);

    /* NA, calendar day count within the four year period beginning with the previous leap year */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_calday_count, NULL, NULL);

    /* CnA and HnA, generalized health of the satellite and carrier frequency number respectively */
    /* TODO:  This is a 2-character hexadecimal bitmask (ref: GLONASS ICD, 1995) and should
     * probably be two separate fields once the bitmask is understood. */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_sat_health, NULL, NULL);

    /* e, Eccentricity */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_eccentricity, NULL, NULL);

    /* DOT, rate of change of the draconitic circling decoded_time */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_roc_circling, NULL, NULL);

    /* Argument of Perigee */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_perigee, NULL, NULL);

    /* 16 MSB of system decoded_time scale correction */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_16msb_corr_t_scale, NULL, NULL);

    /* Correction to the average value of the draconitic circling decoded_time */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_corr_circling, NULL, NULL);

    /* Time of the Ascension Node, Almanac Reference Time */
    /* TODO:  This is a 2-character hexadecimal bitmask (ref: GLONASS ICD, 1995, Section 4.5, Table 4.3)
     * and should probably be two separate fields once the bitmask is understood. */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_t_asc_node, NULL, NULL);

    /* Greenwich Longitude of the Ascension Node */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_long_asc_node, NULL, NULL);

    /* Correction to the average value of the inclination angle */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_corr_incl_angle, NULL, NULL);

    /* 12 LSB of system decoded_time scale correction */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_12lsb_corr_t_scale, NULL, NULL);

    /* Course Value of the Time Scale Shift */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mla_t_scale_shift, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_msk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "MSK sentence - Control for a Beacon Receiver");
    /* Beacon Frequency, 283.5 - 325.0 kHz */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_msk_beacon_freq, NULL, NULL);

    /* Auto/Manual Frequency */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_msk_am_freq);

    /* Beacon Bit Rate (25, 50, 100, or 200) bits per second */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_msk_beacon_bitrate, NULL, NULL);

    /* Auto/Manual Bit Rate */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_msk_am_bitrate);

    /* Interval for sending MSS status, seconds */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_msk_interval, NULL, NULL);

    /* Channel Number */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_msk_channel, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_mss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "MSS sentence - Beacon Receiver Status");
    /* Signal Strength (SS), dB re: 1 uV/m */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mss_sig_str, NULL, NULL);

    /* Signal-to-Noise Ratio (SNR), dB */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mss_snr, NULL, NULL);

    /* Beacon Frequency, 283.5-325.0 kHz */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mss_beacon_freq, NULL, NULL);

    /* Beacon bit rate (25, 50, 100, or 200) bits per second */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mss_beacon_bitrate, NULL, NULL);

    /* Channel Number */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mss_channel, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_mtw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "MTW sentence - Mean Temperature of Water");

    /* Temperature (in Celsius) */
    dissect_nmea0183_field_with_unit(tvb, pinfo, subtree, offset, hf_nmea0183_mtw_temp);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_mwd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "MWD sentence - Wind Direction & Speed");
    /* Wind Direction, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mwd_direction_true, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Wind Direction, degrees Magnetic */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mwd_direction_mag, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Wind Speed, knots */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mwd_speed_knots, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Wind Speed, meters/second */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mwd_speed_ms, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_mwv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "MWV sentence - Wind Speed and Angle");
    /* Wind Angle, 0 to 359 degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mwv_wind_angle, NULL, NULL);

    /* Reference, R = Relative and T = Theoretical */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_mwv_reference);

    /* Wind Speed */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_mwv_wind_speed, NULL, NULL);

    /* Wind speed units, K/M/N/S */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_mwv_speed_units);

    /* Data Status */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_mwv_status);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_osd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "OSD sentence - Own Ship Data");
    /* Heading, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_osd_heading_true, NULL, NULL);

    /* Heading Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_osd_heading_status);

    /* Vessel Course, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_osd_course_true, NULL, NULL);

    /* Course Reference */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_osd_course_ref);

    /* Vessel Speed */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_osd_speed, NULL, NULL);

    /* Speed Reference */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_osd_speed_ref);

    /* Vessel Set, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_osd_set_true, NULL, NULL);

    /* Vessel Drift (speed) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_osd_drift, NULL, NULL);

    /* Speed Units (K/N/S) */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_osd_speed_units);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_rma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "RMA sentence - Recommended Minimum Specific Loran-C Data");

    /* Data Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rma_status);

    /* Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_rma_latitude);

    /* Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_rma_longitude);

    /* Time Difference A (microseconds) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rma_time_diff_a, NULL, NULL);

    /* Time Difference B (microseconds) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rma_time_diff_b, NULL, NULL);

    /* Speed over Ground, knots */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rma_speed, NULL, NULL);

    /* Course over Ground, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rma_course, NULL, NULL);

    /* Magnetic Variation, degrees E/W */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rma_mag_var, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Mode Indicator */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rma_mode);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_rmb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "RMB sentence - Recommended Minimum Navigation Information");

    /* Data Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_data_status);

    /* Cross Track Error (XTE) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_xte, NULL, NULL);

    /* Direction to Steer */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_steer);

    /* Origin Waypoint ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_orig_id, NULL, NULL);

    /* Destination Waypoint ID */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_dest_id, NULL, NULL);

    /* Destination Waypoint Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_dest_wp_latitude);

    /* Destination Waypoint Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_dest_wp_longitude);

    /* Range to Destination, nautical miles */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_range_dest, NULL, NULL);

    /* Bearing to Destination, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_bearing_dest, NULL, NULL);

    /* Destination Closing Velocity, knots */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_dest_velocity, NULL, NULL);

    /* Arrival Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_arrival_status);

    /* Mode Indicator */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rmb_mode);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_rmc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;
    const char *direction;
    const char *value;
    int length;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "RMC sentence - Recommended Minimum Specific GNSS Data");

    /* UTC of Position Fix */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_rmc_utc);

    /* Data Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rmc_status);

    /* Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_rmc_latitude);

    /* Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_rmc_longitude);

    /* Speed over ground (knots) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rmc_speed, NULL, NULL);

    /* Course Over Ground (degrees true) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rmc_course, NULL, NULL);

    /* Date: ddmmyy */
    offset += dissect_nmea0183_field_decoded_date(tvb, pinfo, subtree, offset, hf_nmea0183_rmc_date);

    /* Magnetic Variation, degrees E/W */
    value = nmea0183_field_value(tvb, pinfo, offset);
    length = (int)strlen(value);
    if (length == 0)
    {
        /* Sometimes this field is empty. */
        proto_tree_add_string(subtree, hf_nmea0183_rmc_magnetic, tvb, offset, 0,
                              "Data temporarily unavailable");
        offset += dissect_nmea0183_field_skip(tvb, offset);

        direction = nmea0183_field_value(tvb, pinfo, offset);
        if (direction[0] == '\0' || strcmp(direction, "E") == 0 ||
            strcmp(direction, "W") == 0)
        {
            offset += dissect_nmea0183_field_skip(tvb, offset);
        }
        else
        {
            /* The magnetic variation direction field was omitted. */
            expert_add_info(pinfo, tree, &ei_nmea0183_legacy_nonstandard);
        }
    }
    else
    {
        /* Easterly variation subtracts from True course / Westerly adds to True course */
        int magnetic_offset = offset;

        offset += dissect_nmea0183_field_skip(tvb, offset);
        direction = nmea0183_field_value(tvb, pinfo, offset);
        if (strcmp(direction, "E") == 0)
        {
            proto_tree_add_string_format_value(subtree, hf_nmea0183_rmc_magnetic, tvb,
                                               magnetic_offset, length, value,
                                               "%s E (subtract from True Course)", value);
            offset += dissect_nmea0183_field_skip(tvb, offset);
        }
        else if (strcmp(direction, "W") == 0)
        {
            proto_tree_add_string_format_value(subtree, hf_nmea0183_rmc_magnetic, tvb,
                                               magnetic_offset, length, value,
                                               "%s W (add to True Course)", value);
            offset += dissect_nmea0183_field_skip(tvb, offset);
        }
        else
        {
            proto_tree_add_string(subtree, hf_nmea0183_rmc_magnetic, tvb,
                                  magnetic_offset, length, value);
            expert_add_info(pinfo, tree, &ei_nmea0183_legacy_nonstandard);
        }
    }

    /* Mode Indicator */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rmc_mode);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_rpm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "RPM sentence - Revolutions");
    /* Source, shaft/engine */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rpm_source);

    /* Engine or Shaft Number, numbered from centerline */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rpm_number);

    /* Speed, rev/min where negative numbers represent counter-clockwise */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rpm_speed, NULL, NULL);

    /* Propeller Pitch, % of max */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rpm_pitch, NULL, NULL);

    /* Data Status */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rpm_status);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_rsa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "RSA sentence - Rudder Sensor Angle");
    /* Starboard (or single) Rudder Sensor */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsa_sb_sensor, NULL, NULL);

    /* Starboard sensor status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rsa_sb_status);

    /* Port Rudder Sensor */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsa_pt_sensor, NULL, NULL);

    /* Port sensor status */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rsa_pt_status);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_rsd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "RSD sentence - RADAR System Data");
    /* Origin 1 range, from own ship */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_orig_range, NULL, NULL);

    /* Origin 1 bearing, degrees from 0 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_orig_bearing, NULL, NULL);

    /* Variable Range Marker 1 (VRM1), range */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_vrm1, NULL, NULL);

    /* Bearing Line 1 (EBL1), degrees from 0 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_ebl1, NULL, NULL);

    /* Origin 2 range */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_orig2_range, NULL, NULL);

    /* VRM2, range */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_vrm2, NULL, NULL);
    /* EBL2, degrees */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_ebl2, NULL, NULL);

    /* Cursor range, from own ship */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_cursor_range, NULL, NULL);

    /* Cursor bearing, degrees clockwise from 0 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_cursor_bearing, NULL, NULL);

    /* Range scale in use */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_scale, NULL, NULL);

    /* Range units */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_units);

    /* Display Rotation */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rsd_display);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_rte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "RTE sentence - Routes");
    /* Total number of sentences being transmitted */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rte_total_sentences, NULL, NULL);

    /* Sentence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rte_sentence_number, NULL, NULL);

    /* Sentence Mode */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_rte_sentence_mode);

    /* Route Identifier */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rte_route, NULL, NULL);

    /* There can be 1 to n waypoint identifiers so we loop through them all */
    while (tvb_captured_length_remaining(tvb, offset) > 0)
    {
        /* Waypoint identifier */
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_rte_waypoint, NULL, NULL);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_sfi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "SFI sentence - Scanning Frequency Information");
    /* Total number of sentences being transmitted */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_sfi_total_sentences, NULL, NULL);

    /* Sentence Number */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_sfi_sentence_number, NULL, NULL);

    /* There can be up to 6 of these freq+mode pairs */
    for (int i = 0; i < 6 && tvb_captured_length_remaining(tvb, offset) > 0; i++)
    {
        /* Frequency or ITU Channel (100 Hz increments) */
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_sfi_frequency, NULL, NULL);

        /* Mode of Operation */
        if (tvb_captured_length_remaining(tvb, offset) > 0)
        {
            offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset,
                                                   hf_nmea0183_sfi_mode);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_ssd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "SSD sentence - Saab AB, Security & Defense Solutions, Command and Control Systems Division (Sweden)");
    /* Ship's Callsign */
    /* Note: Callsign of "@@@@@@@" means unavailable */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ssd_callsign, NULL, NULL);

    /* Ship's Name */
    /* Note: Ship's name of "@@@@@@@@@@@@@@@@@@@@" means unavailable */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ssd_name, NULL, NULL);

    /* Pos. ref. point distance, "A," from bow 3, 0 to 511 meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ssd_ref_a, NULL, NULL);

    /* Pos. ref. point distance, "B," from stern 3, 0 to 511 Meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ssd_ref_b, NULL, NULL);

    /* Pos. ref. point distance, "C," from port beam 3, 0 to 63 Meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ssd_ref_c, NULL, NULL);

    /* Pos. ref. point distance, "D," from starboard beam 3, 0 to 63 Meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ssd_ref_d, NULL, NULL);

    /* DTE Indicator Flag */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ssd_dte_flag);

    /* Source Identifier */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ssd_source, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_stn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "STN sentence - Multiple Data ID");
    /* Talker ID Number (00-99) */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_stn_talker, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_tlb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "TLB sentence - Target Label");
    /* There can be 1 to n of these target + label pairs */
    while (tvb_captured_length_remaining(tvb, offset) > 0)
    {
        /* Target number 'n' reported by the device */
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_tlb_target, NULL, NULL);

        /* Label assigned to target 'n' */
        if (tvb_captured_length_remaining(tvb, offset) > 0)
        {
            offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                              hf_nmea0183_tlb_label, NULL, NULL);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_tll(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "TLL sentence - Target Latitude and Longitude");

    /* Target Number, 00-99 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_tll_tgt_num, NULL, NULL);

    /* Target Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_tll_tgt_latitude);

    /* Target Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_tll_tgt_longitude);

    /* Target Name */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_tll_tgt_name, NULL, NULL);

    /* UTC of Data */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_tll_utc);

    /* Target Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_tll_tgt_status);

    /* Reference Target */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_tll_ref_tgt);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_ttm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "TTM sentence - Tracked Target Message");

    /* Target Number, 00 to 99 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_tgt_num, NULL, NULL);

    /* Target Distance, from own ship */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_tgt_dist, NULL, NULL);

    /* Bearing from own ship, degrees true/relative */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_bearing, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Target Speed */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_tgt_speed, NULL, NULL);

    /* Target Course, degrees true/relative */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_tgt_course, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Distance of closest-point-of-approach */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_dist_pt_approach, NULL, NULL);

    /* Time to CPA, minutes ("-" = increasing decoded_time) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_time_cpa, NULL, NULL);

    /* Speed/Distance Units */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_units);

    /* Target Name */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_tgt_name, NULL, NULL);

    /* Target Status */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_tgt_status);

    /* Reference Target */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_ref_tgt);

    /* UTC of Data */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_utc);

    /* Type of Acquisition */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_ttm_acq_type);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_tut(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "TUT sentence - Transmission of Multi-Language Text");
    /* Source Identifier */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_tut_src_id, NULL, NULL);

    /* Total number of sentences, 00 - FF */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_tut_total_sentences, NULL, NULL);

    /* Sentence Number, 00 to FF */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_tut_sentence_num, NULL, NULL);

    /* Sequential Message Identifier, 0 to 9 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_tut_seq_msg, NULL, NULL);

    /* Translation Code for Text Body */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_tut_trans_code, NULL, NULL);

    /* Text Body */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_tut_text, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_vdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "VDR sentence - Set and Drift");
    /* Direction, degrees True */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vdr_heading_true, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Direction, degrees Magnetic */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vdr_heading_magnetic, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Current Speed, knots */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vdr_speed, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_vpw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "VPW sentence - Speed, Measured Parallel to Wind");
    /* "-" means downwind for either of the following two fields */

    /* Speed, knots */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vpw_speed_knots, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Speed, meters/second */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vpw_speed_ms, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_vsd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "VSD sentence - UAIS Voyage Static Data");

    /* Type of Ship and Cargo Category, 0-255 */
    /* TODO: These are defined under Message 5 of ITU-R M.1371.  NULL field means "unchanged". */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vsd_ship_cargo, NULL, NULL);

    /* Maximum Present Static Draught, 0-25.5 meters */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vsd_max_draught, NULL, NULL);

    /* Persons on-board, 0-8191 where a value of 8191 implies greater than or equal to 8191 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vsd_persons, NULL, NULL);

    /* Destination */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vsd_destination, NULL, NULL);

    /* Estimated UTC of arrival at Destination */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_vsd_utc_arrival);

    /* Estimated Day of Arrival at Destination, 00 to 31 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vsd_day_arrival, NULL, NULL);

    /* Estimated Month of Arrival at Destination, 00 to 12 */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vsd_month_arrival, NULL, NULL);

    /* Navigational Status */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                      hf_nmea0183_vsd_nav_status, NULL,
                                      nav_status_vals);

    /* Regional Application Flags - set by Regional Authority (i.e., no table lookup) */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vsd_app_flags, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_wcv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "WCV sentence - Waypoint Closure Velocity");
    /* Velocity component, knots */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_wcv_velocity, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Waypoint identifier */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_wcv_waypoint, NULL, NULL);

    /* Mode Indicator */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_wcv_mode);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_wnc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "WNC sentence - Distance - Waypoint to Waypoint");
    /* Distance (nm) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_wnc_dist_nm, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* Distance (km) */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_wnc_dist_km, NULL, NULL);
    offset += dissect_nmea0183_field_skip(tvb, offset);

    /* 'TO' Waypoint Identifier */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_wnc_to_id, NULL, NULL);

    /* 'FROM' Waypoint Identifier */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_wnc_from_id, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_wpl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "WPL sentence - Waypoint Location");

    /* Waypoint Latitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_wpl_latitude);

    /* Waypoint Longitude */
    offset += dissect_nmea0183_field_latlong(tvb, pinfo, subtree, offset, hf_nmea0183_wpl_longitude);

    /* Waypoint identifer */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_wpl_waypoint, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_xdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "XDR sentence - Transducer Measurement");
    /* This can be from 1 to n transducer messages */
    while (tvb_captured_length_remaining(tvb, offset) > 0)
    {
        /* Transducer Type */
        offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_xdr_type);

        /* Transducer Data */
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_xdr_data, NULL, NULL);

        /* Transducer Units of Measure */
        offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_xdr_units);

        /* Transducer ID */
        offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset,
                                          hf_nmea0183_xdr_id, NULL, NULL);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_xte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "XTE sentence - Cross-Track Error, Measured");
    /* Data Status - Loran-C Blink or SNR Warning */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_xte_blinksnr_status);

    /* Data Status - Loran-C Cycle Lock Warning Flag */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_xte_cycle_status);

    /* Magnitude of XTE */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_xte_magnitude, NULL, NULL);

    /* Direction to Steer (L/R) */
    offset += dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_xte_direction);

    /* Mode Indicator */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_xte_mode);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_xtr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "XTR sentence - Cross Track Error - Dead Reckoning");
    /* Magnitude of XTE */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_xtr_magnitude, NULL, NULL);

    /* Direction to Steer (L/R) */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_xtr_direction, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_zdl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ZDL sentence - Time and Distance to Variable Point");

    /* Time to point, hh = 00 to 99 hours */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_zdl_time);

    /* Distance to point, nautical miles */
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zdl_dist, NULL, NULL);

    /* Type of Point (table lookup) */
    dissect_nmea0183_field_item(tvb, pinfo, subtree, offset, hf_nmea0183_zdl_type);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_zfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ZFO sentence - UTC & Time from origin Waypoint");

    /* UTC of Observation */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_zfo_utc);

    /* Elapsed Time, hh = 00 to 99 */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_zfo_elapsed);

    /* Origin Waypoint ID */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zfo_origin, NULL, NULL);

    return tvb_captured_length(tvb);
}

static int
dissect_nmea0183_sentence_ztg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "ZTG sentence - UTC & Time to Destination Waypoint");

    /* UTC of Observation */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_ztg_utc);

    /* Time-to-go, hh = 00 to 99 */
    offset += dissect_nmea0183_field_decoded_time(tvb, pinfo, subtree, offset, hf_nmea0183_ztg_time_left);

    /* Destination Waypoint ID */
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_ztg_dest, NULL, NULL);

    return tvb_captured_length(tvb);
}

 /* Dissect a sentence where the sentence id is unknown. Each field is shown as an generic field. */
static int
dissect_nmea0183_sentence_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    unsigned offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nmea0183_sentence,
                                                 NULL, "Unknown sentence");

    /* In an unknown sentence, the name of each field is unknown. Find all field by splitting at a comma. */
    while (tvb_captured_length_remaining(tvb, offset) > 0)
    {
        int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
        proto_item *ti = proto_tree_add_item(subtree, hf_nmea0183_unknown_field,
                                             tvb, offset, end_of_field_offset - offset, ENC_ASCII);
        if (end_of_field_offset - offset == 0)
        {
            proto_item_append_text(ti, "[empty]");
        }
        offset = end_of_field_offset + 1;
    }
    return tvb_captured_length(tvb);
}


/* <tag block 1>,<tagblock2>, … <tagblock n>*<tagblocks CS> */
//static void
//dissect_nmea0183_tag_block(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
//{
//    unsigned offset = 0, chk_sum_off, comma_off;
//
//    if (!tvb_find_uint8_remaining(tvb, offset, '*', &chk_sum_off)) {
//        /* No checksum ??*/
//        return;
//    }
//    while (offset < chk_sum_off) {
//        if (!tvb_find_uint8_remaining(tvb, offset, ',', &comma_off)) {
//
//        }
//
//    }
//
//}
static unsigned
dissect_nmea0183_tag_blocks(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, unsigned offset) {

    unsigned start_offset;
    unsigned end_offset;

    while (tvb_get_uint8(tvb, offset) == '\\') {
        start_offset = offset;
        offset++;
        if (!tvb_find_uint8_remaining(tvb, offset, '\\', &end_offset)) {
            // Add expert info
            return tvb_captured_length(tvb);
        }
        proto_tree_add_item(tree, hf_nmea0183_tag_block, tvb, start_offset, (end_offset - start_offset) + 1, ENC_ASCII);
        //proto_tree* tree = proto_item_add_subtree(ti, ett_nmea0183_tag_block);
        offset = end_offset + 1;
    }
    return offset;
}

static int
dissect_nmea0183_msg(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_item* ti;
    unsigned offset = 0,start_offset;
    unsigned start_checksum_offset = 0;
    const char* talker_id = NULL;
    const char* sentence_id = NULL;
    const char* checksum = NULL;
    uint8_t start_delimiter;

    /* Start delimiter */
    start_delimiter = tvb_get_uint8(tvb, offset);
    if ((start_delimiter != '$') && (start_delimiter != '!'))
    {
        expert_add_info(pinfo, tree, &ei_nmea0183_invalid_first_character);
    }

    offset += 1;
    start_offset = offset;
    /* Talker id */
    ti = proto_tree_add_item_ret_string(tree, hf_nmea0183_talker_id,
                                        tvb, offset, 2, ENC_ASCII,
                                        pinfo->pool, (const uint8_t**)&talker_id);

    proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, talker_id, known_talker_ids, "Unknown talker ID"));

    col_append_fstr(pinfo->cinfo, COL_INFO, "Talker %s", str_to_str_wmem(pinfo->pool, talker_id, known_talker_ids, "Unknown talker ID"));

    offset += 2;

    /* Sentence id */
    ti = proto_tree_add_item_ret_string(tree, hf_nmea0183_sentence_id,
                                        tvb, offset, 3, ENC_ASCII,
                                        pinfo->pool, (const uint8_t**)&sentence_id);

    proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, sentence_id, known_sentence_ids, "Unknown sentence ID"));

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Sentence %s", str_to_str_wmem(pinfo->pool, sentence_id, known_sentence_ids, "Unknown sentence ID"));

    offset += 3;

    /* Start of checksum */
    if (!tvb_find_uint8_remaining(tvb, offset, '*', &start_checksum_offset))
    {
        expert_add_info(pinfo, tree, &ei_nmea0183_missing_checksum_character);
        return tvb_captured_length(tvb);
    }

    /* Data */
    offset += 1;
    tvbuff_t *data_tvb = tvb_new_subset_length(tvb, offset, start_checksum_offset - offset);
    if (g_ascii_strcasecmp(sentence_id, "AAM") == 0)
    {
        offset += dissect_nmea0183_sentence_aam(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ABK") == 0)
    {
        offset += dissect_nmea0183_sentence_abk(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ACA") == 0)
    {
        offset += dissect_nmea0183_sentence_aca(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ACK") == 0)
    {
        offset += dissect_nmea0183_sentence_ack(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ACS") == 0)
    {
        offset += dissect_nmea0183_sentence_acs(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "AIR") == 0)
    {
        offset += dissect_nmea0183_sentence_air(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "AKD") == 0)
    {
        offset += dissect_nmea0183_sentence_akd(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ALA") == 0)
    {
        offset += dissect_nmea0183_sentence_ala(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ALM") == 0)
    {
        offset += dissect_nmea0183_sentence_alm(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ALR") == 0)
    {
        offset += dissect_nmea0183_sentence_alr(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "APB") == 0)
    {
        offset += dissect_nmea0183_sentence_apb(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "BEC") == 0)
    {
        offset += dissect_nmea0183_sentence_bec(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "BOD") == 0)
    {
        offset += dissect_nmea0183_sentence_bod(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "BWC") == 0)
    {
        offset += dissect_nmea0183_sentence_bwc(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "BWR") == 0)
    {
        offset += dissect_nmea0183_sentence_bwr(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "BWW") == 0)
    {
        offset += dissect_nmea0183_sentence_bww(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "CBR") == 0)
    {
        offset += dissect_nmea0183_sentence_cbr(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "CUR") == 0)
    {
        offset += dissect_nmea0183_sentence_cur(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DBT") == 0)
    {
        offset += dissect_nmea0183_sentence_dbt(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DCN") == 0)
    {
        offset += dissect_nmea0183_sentence_dcn(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DDC") == 0)
    {
        offset += dissect_nmea0183_sentence_ddc(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DOR") == 0)
    {
        offset += dissect_nmea0183_sentence_dor(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DPT") == 0)
    {
        offset += dissect_nmea0183_sentence_dpt(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DSC") == 0)
    {
        offset += dissect_nmea0183_sentence_dsc(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DSE") == 0)
    {
        offset += dissect_nmea0183_sentence_dse(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DSI") == 0)
    {
        offset += dissect_nmea0183_sentence_dsi(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DSR") == 0)
    {
        offset += dissect_nmea0183_sentence_dsr(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "DTM") == 0)
    {
        offset += dissect_nmea0183_sentence_dtm(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ETL") == 0)
    {
        offset += dissect_nmea0183_sentence_etl(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "FSI") == 0)
    {
        offset += dissect_nmea0183_sentence_fsi(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GBS") == 0)
    {
        offset += dissect_nmea0183_sentence_gbs(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GGA") == 0)
    {
        offset += dissect_nmea0183_sentence_gga(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GLC") == 0)
    {
        offset += dissect_nmea0183_sentence_glc(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GLL") == 0)
    {
        offset += dissect_nmea0183_sentence_gll(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GMP") == 0)
    {
        offset += dissect_nmea0183_sentence_gmp(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GNS") == 0)
    {
        offset += dissect_nmea0183_sentence_gns(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GRS") == 0)
    {
        offset += dissect_nmea0183_sentence_grs(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GSA") == 0)
    {
        offset += dissect_nmea0183_sentence_gsa(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GST") == 0)
    {
        offset += dissect_nmea0183_sentence_gst(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GSV") == 0)
    {
        offset += dissect_nmea0183_sentence_gsv(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HBT") == 0)
    {
        offset += dissect_nmea0183_sentence_hbt(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HDG") == 0)
    {
        offset += dissect_nmea0183_sentence_hdg(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HDT") == 0)
    {
        offset += dissect_nmea0183_sentence_hdt(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HMR") == 0)
    {
        offset += dissect_nmea0183_sentence_hmr(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HMS") == 0)
    {
        offset += dissect_nmea0183_sentence_hms(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HSC") == 0)
    {
        offset += dissect_nmea0183_sentence_hsc(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HTC") == 0)
    {
        offset += dissect_nmea0183_sentence_htc(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HTD") == 0)
    {
        offset += dissect_nmea0183_sentence_htd(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "LCD") == 0)
    {
        offset += dissect_nmea0183_sentence_lcd(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "LR1") == 0)
    {
        offset += dissect_nmea0183_sentence_lr1(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "LR2") == 0)
    {
        offset += dissect_nmea0183_sentence_lr2(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "LR3") == 0)
    {
        offset += dissect_nmea0183_sentence_lr3(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "LRF") == 0)
    {
        offset += dissect_nmea0183_sentence_lrf(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "LRI") == 0)
    {
        offset += dissect_nmea0183_sentence_lri(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "MLA") == 0)
    {
        offset += dissect_nmea0183_sentence_mla(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "MSK") == 0)
    {
        offset += dissect_nmea0183_sentence_msk(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "MSS") == 0)
    {
        offset += dissect_nmea0183_sentence_mss(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "MTW") == 0)
    {
        offset += dissect_nmea0183_sentence_mtw(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "MWD") == 0)
    {
        offset += dissect_nmea0183_sentence_mwd(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "MWV") == 0)
    {
        offset += dissect_nmea0183_sentence_mwv(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "OSD") == 0)
    {
        offset += dissect_nmea0183_sentence_osd(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "RMA") == 0)
    {
        offset += dissect_nmea0183_sentence_rma(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "RMB") == 0)
    {
        offset += dissect_nmea0183_sentence_rmb(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "RMC") == 0)
    {
        offset += dissect_nmea0183_sentence_rmc(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ROT") == 0)
    {
        offset += dissect_nmea0183_sentence_rot(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "RPM") == 0)
    {
        offset += dissect_nmea0183_sentence_rpm(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "RSA") == 0)
    {
        offset += dissect_nmea0183_sentence_rsa(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "RSD") == 0)
    {
        offset += dissect_nmea0183_sentence_rsd(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "RTE") == 0)
    {
        offset += dissect_nmea0183_sentence_rte(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "SFI") == 0)
    {
        offset += dissect_nmea0183_sentence_sfi(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "SSD") == 0)
    {
        offset += dissect_nmea0183_sentence_ssd(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "STN") == 0)
    {
        offset += dissect_nmea0183_sentence_stn(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "TLB") == 0)
    {
        offset += dissect_nmea0183_sentence_tlb(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "TLL") == 0)
    {
        offset += dissect_nmea0183_sentence_tll(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "TTM") == 0)
    {
        offset += dissect_nmea0183_sentence_ttm(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "TUT") == 0)
    {
        offset += dissect_nmea0183_sentence_tut(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "TXT") == 0)
    {
        offset += dissect_nmea0183_sentence_txt(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VBW") == 0)
    {
        offset += dissect_nmea0183_sentence_vbw(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VDR") == 0)
    {
        offset += dissect_nmea0183_sentence_vdr(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VHW") == 0)
    {
        offset += dissect_nmea0183_sentence_vhw(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VLW") == 0)
    {
        offset += dissect_nmea0183_sentence_vlw(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VPW") == 0)
    {
        offset += dissect_nmea0183_sentence_vpw(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VSD") == 0)
    {
        offset += dissect_nmea0183_sentence_vsd(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VTG") == 0)
    {
        offset += dissect_nmea0183_sentence_vtg(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "WCV") == 0)
    {
        offset += dissect_nmea0183_sentence_wcv(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "WNC") == 0)
    {
        offset += dissect_nmea0183_sentence_wnc(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "WPL") == 0)
    {
        offset += dissect_nmea0183_sentence_wpl(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "XDR") == 0)
    {
        offset += dissect_nmea0183_sentence_xdr(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "XTE") == 0)
    {
        offset += dissect_nmea0183_sentence_xte(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "XTR") == 0)
    {
        offset += dissect_nmea0183_sentence_xtr(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ZDA") == 0)
    {
        offset += dissect_nmea0183_sentence_zda(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ZDL") == 0)
    {
        offset += dissect_nmea0183_sentence_zdl(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ZFO") == 0)
    {
        offset += dissect_nmea0183_sentence_zfo(data_tvb, pinfo, tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ZTG") == 0)
    {
        offset += dissect_nmea0183_sentence_ztg(data_tvb, pinfo, tree);
    }
    else
    {
        offset += dissect_nmea0183_sentence_unknown(data_tvb, pinfo, tree);
    }

    /* Checksum */
    offset += 1;
    ti = proto_tree_add_item_ret_string(tree, hf_nmea0183_checksum,
                                        tvb, offset, 2, ENC_ASCII,
                                        pinfo->pool, (const uint8_t**)&checksum);

    uint8_t received_checksum = (uint8_t)strtol(checksum, NULL, 16);
    uint8_t calculated_checksum;

    //calculated_checksum  = calculate_checksum(tvb, 1, offset - 2);
    calculated_checksum = calculate_checksum(tvb, start_offset, (offset - start_offset-1));

    if (received_checksum == calculated_checksum)
    {
        proto_item_append_text(ti, " [correct]");
    }
    else
    {
        proto_item_append_text(ti, " [INCORRECT]");
        expert_add_info(pinfo, ti, &ei_nmea0183_checksum_incorrect);
    }

    // Calculated checksum highlights 2 bytes, which is the ascii hex value of a 1 byte checksum
    proto_item *checksum_tree = proto_item_add_subtree(ti, ett_nmea0183_checksum);
    ti = proto_tree_add_uint(checksum_tree, hf_nmea0183_checksum_calculated,
                             tvb, offset, 2, calculated_checksum);

    proto_item_set_generated(ti);

    offset += 2;

    /* End of line */
    if (tvb_captured_length_remaining(tvb, offset) < 2 ||
        tvb_get_uint8(tvb, offset) != '\r' ||
        tvb_get_uint8(tvb, offset + 1) != '\n')
    {
        expert_add_info(pinfo, tree, &ei_nmea0183_invalid_end_of_line);
    }
    offset += 2;

    /* Check sentence length */
    if (offset > 82)
    {
        expert_add_info(pinfo, tree, &ei_nmea0183_sentence_too_long);
    }

    return tvb_captured_length(tvb);
}

static const value_string nmea0183_bin_mtype_vals[] = {
        { 1, "Data"},
        { 2, "Query"},
        { 3, "Ack"},
        { 0, NULL },
};

static int
dissect_nmea0183_bin(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* ti;
    proto_tree* nmea0183_tree, *fd_tree;
    uint32_t mtype, seqnum, file_descriptor_len, type_len;

    unsigned offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NMEA 0183 Binary");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_nmea0183_bin, tvb, 0, -1, ENC_NA);
    nmea0183_tree = proto_item_add_subtree(ti, ett_nmea0183);

    proto_tree_add_item(nmea0183_tree, hf_nmea0183_sentence_prefix, tvb, offset, 6, ENC_ASCII);
    offset += 6;
    proto_tree_add_item(nmea0183_tree, hf_nmea0183_bin_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(nmea0183_tree, hf_nmea0183_bin_srcid, tvb, offset, 6, ENC_ASCII);
    offset += 6;
    proto_tree_add_item(nmea0183_tree, hf_nmea0183_bin_dstid, tvb, offset, 6, ENC_ASCII);
    offset += 6;
    proto_tree_add_item_ret_uint(nmea0183_tree, hf_nmea0183_bin_mtype, tvb, offset, 2, ENC_BIG_ENDIAN, &mtype);
    offset += 2;
    proto_tree_add_item(nmea0183_tree, hf_nmea0183_bin_blockid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(nmea0183_tree, hf_nmea0183_bin_seqnum, tvb, offset, 4, ENC_BIG_ENDIAN, &seqnum);
    offset += 4;
    proto_tree_add_item(nmea0183_tree, hf_nmea0183_bin_max_seqnum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (offset < tvb_reported_length(tvb)) {
        if ((mtype == 1) && (seqnum == 1)) {
            /* binary file descriptor*/
            ti = proto_tree_add_item(nmea0183_tree, hf_nmea0183_bin_file_descriptor, tvb, offset, -1, ENC_ASCII);
            fd_tree = proto_item_add_subtree(ti, ett_nmea0183_fd);
            proto_tree_add_item_ret_uint(fd_tree, hf_nmea0183_bin_file_descriptor_len, tvb, offset, 4, ENC_BIG_ENDIAN, &file_descriptor_len);
            proto_item_set_len(ti, file_descriptor_len);
            offset += 4;
            proto_tree_add_item(fd_tree, hf_nmea0183_bin_file_length, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(fd_tree, hf_nmea0183_bin_stat_of_acquisition, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(fd_tree, hf_nmea0183_bin_device, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(fd_tree, hf_nmea0183_bin_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item_ret_uint(fd_tree, hf_nmea0183_bin_type_len, tvb, offset, 1, ENC_BIG_ENDIAN, &type_len);
            offset++;
            proto_tree_add_item(fd_tree, hf_nmea0183_bin_data_type, tvb, offset, type_len, ENC_ASCII);
            offset += type_len;
            proto_tree_add_item(fd_tree, hf_nmea0183_bin_status_and_info, tvb, offset, file_descriptor_len - type_len - 13, ENC_ASCII);
            offset += file_descriptor_len - type_len - 13;
        }
        proto_tree_add_item(nmea0183_tree, hf_nmea0183_bin_data, tvb, offset, -1, ENC_NA);
    }


    return tvb_reported_length(tvb);
}

static int
dissect_nmea0183(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    proto_item* ti;
    proto_tree* nmea0183_tree = NULL;
    unsigned offset = 0;
    unsigned end_offset;
    bool first_msg = true;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NMEA 0183");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Find end of nmea message */
    if (tvb_find_uint16_remaining(tvb, 0, NMEA0183_CRLF, &end_offset)) {
        /* Add CRLF */
        end_offset += 2;
    } else {
        end_offset = tvb_reported_length(tvb);
    }

    /* UdPbC\<tag block 1>,<tagblock2>, … <tagblock n>*<tagblocks CS>\<NMEA message>*/
    if (tvb_strneql(tvb, 0, UDPBC, strlen(UDPBC)) == 0) {
        if (first_msg == true) {
            ti = proto_tree_add_item(tree, proto_nmea0183, tvb, 0, end_offset, ENC_NA);
            nmea0183_tree = proto_item_add_subtree(ti, ett_nmea0183);
        }
        proto_tree_add_item(nmea0183_tree, hf_nmea0183_sentence_prefix, tvb, offset, 6, ENC_ASCII);
        offset += 6;
        while (tvb_reported_length_remaining(tvb, offset)) {
            if (first_msg != true) {
                if (tvb_find_uint16_remaining(tvb, offset, NMEA0183_CRLF, &end_offset)) {
                    /* Add CRLF */
                    end_offset += 2;
                } else {
                    end_offset = tvb_reported_length(tvb);
                }

                ti = proto_tree_add_item(tree, proto_nmea0183, tvb, offset, end_offset, ENC_NA);
                nmea0183_tree = proto_item_add_subtree(ti, ett_nmea0183);
            }
            offset = dissect_nmea0183_tag_blocks(tvb, pinfo, nmea0183_tree, offset);
            tvbuff_t* msg_tvb = tvb_new_subset_length(tvb, offset, end_offset - offset);
            dissect_nmea0183_msg(msg_tvb, pinfo, nmea0183_tree);
            offset += (end_offset - offset);
            first_msg = false;
        }
        return offset;
    } else if (tvb_strneql(tvb, 0, RRUDP, strlen(RRUDP)) == 0) {
        /* Binary nmea0183 */
        offset = dissect_nmea0183_bin(tvb, pinfo, tree, data);
        return offset;
    } else if (tvb_strneql(tvb, 0, RAUDP, strlen(RAUDP)) == 0) {
        /* Binary nmea0183 */
        offset = dissect_nmea0183_bin(tvb, pinfo, tree, data);
        return offset;
    } else if (tvb_strneql(tvb, 0, RPUDP, strlen(RPUDP)) == 0) {
        /* Binary nmea0183 */
        offset = dissect_nmea0183_bin(tvb, pinfo, tree, data);
        return offset;
    }

    ti = proto_tree_add_item(tree, proto_nmea0183, tvb, 0, end_offset, ENC_NA);
    nmea0183_tree = proto_item_add_subtree(ti, ett_nmea0183);

    tvbuff_t *msg_tvb = tvb_new_subset_length(tvb, offset, end_offset - offset);
    offset = dissect_nmea0183_msg(msg_tvb, pinfo, nmea0183_tree);

    return offset;
}

/* Try to detect NMEA 0183 heuristically */
static bool dissect_nmea0183_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    char *sent_type;
    const char *talker, *t_val, *p_val, *m_val, *manuf;

    /* Have to have at least 11 bytes:
     * 1-byte sentence type character ('!' or '$')
     * 2-byte TALKER lookup value
     * 2-byte TALKER (for Query sentences) or 3-byte FORMATTER
     * variable number of bytes for delimiters and data fields (minimum would be a single ',' byte)
     * '*' delimeter byte, 2-bytes for checksum, and 2-bytes for EOM "\r\n" */
    if(tvb_reported_length(tvb) < 11 || tvb_captured_length(tvb) < 5){
        return false;
    }
    /* See if we have a UDP brodcast message */
    if (tvb_strneql(tvb, 0, UDPBC, strlen(UDPBC)) == 0) {
        return (dissect_nmea0183(tvb, pinfo, tree, data) != 0);
    }
    if (tvb_strneql(tvb, 0, RRUDP, strlen(RRUDP)) == 0) {
        return (dissect_nmea0183_bin(tvb, pinfo, tree, data) != 0);
    }
    if (tvb_strneql(tvb, 0, RAUDP, strlen(RAUDP)) == 0) {
        return (dissect_nmea0183_bin(tvb, pinfo, tree, data) != 0);
    }
    if (tvb_strneql(tvb, 0, RPUDP, strlen(RPUDP)) == 0) {
        return (dissect_nmea0183_bin(tvb, pinfo, tree, data) != 0);
    }
    /* Grab the first byte and check the first character */
    sent_type = (char*)tvb_get_string_enc(pinfo->pool, tvb, 0, 1, ENC_ASCII);

    /* Sentence type character ('!' or '$') */
    if( (sent_type[0] != '!') && (sent_type[0] != '$') ){
        return false;
    }

    /* We either have a 'P' and corresponding manufacturer 3-byte value OR
     * we have a non-proprietary 2-byte TALKER field */
    //TODO: Implement encapsulation and proprietary message parsing

    /* Do a lookup for the 2-byte TALKER field */
    t_val = (char*)tvb_get_string_enc(pinfo->pool, tvb, 1, 2, ENC_ASCII);
    talker = try_str_to_str(t_val, known_talker_ids);

    /* Do a lookup for the 3-byte manufacturer if the 2nd byte in the PDU is 'P' */
    p_val = (char*)tvb_get_string_enc(pinfo->pool, tvb, 1, 1, ENC_ASCII);
    m_val = (char*)tvb_get_string_enc(pinfo->pool, tvb, 2, 3, ENC_ASCII);
    manuf = try_str_to_str(m_val, manufacturer_vals);

    /* If one of the two conditions are true then try to dissect NMEA 0183 */
    if( ((p_val[0] == 'P') && (manuf != NULL)) ||
        (talker != NULL) ){
        /* Looks like NMEA 0183 so let's give it a try */
        return (dissect_nmea0183(tvb, pinfo, tree, data) != 0);
    }
    /* If neither conditions are met then we return false */
    else{
        return false;
    }
}

void proto_register_nmea0183(void)
{
    expert_module_t *expert_nmea0183;

    static hf_register_info hf[] = {
        {&hf_nmea0183_talker_id,
         {"Talker ID", "nmea0183.talker",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_sentence_id,
         {"Sentence ID", "nmea0183.sentence",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_unknown_field,
         {"Field", "nmea0183.unknown_field",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 Unknown field", HFILL}},
        {&hf_nmea0183_checksum,
         {"Checksum", "nmea0183.checksum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_checksum_calculated,
         {"Calculated checksum", "nmea0183.checksum_calculated",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aam_arr_circle_radius,
         {"Arrival Circle Radius", "nmea0183.aam.circle_radius",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aam_arr_circle_status,
         {"Arrival Circle Status", "nmea0183.aam.arrival_status",
          FT_CHAR, BASE_NONE,
          VALS(arrival_circle_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aam_perp_status,
         {"Perpendicular Pass Status", "nmea0183.aam.perp_status",
          FT_CHAR, BASE_NONE,
          VALS(perpendicular_pass_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aam_units_radius,
         {"Units of Radius (nm)", "nmea0183.aam.units",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aam_waypoint,
         {"Waypoint ID", "nmea0183.aam.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_abk_ack_type,
         {"Type of Acknowledgement", "nmea0183.abk.ack_type",
          FT_CHAR, BASE_NONE,
          VALS(abk_ack_type), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_abk_ais_channel,
         {"AIS Channel of Reception", "nmea0183.abk.channel",
          FT_CHAR, BASE_NONE,
          VALS(abk_channel), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_abk_mmsi,
         {"MMSI of Addressed AIS Unit", "nmea0183.abk.mmsi",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_abk_msg_id,
         {"ITU-R M.1371 Message ID", "nmea0183.abk.msg_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_abk_msg_seq,
         {"Message Sequence Number", "nmea0183.abk.msg_seq",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_chan_a,
         {"Channel A", "nmea0183.aca.chan_a",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_chan_a_bw,
         {"Channel A Bandwidth", "nmea0183.aca.chan_a_bw",
          FT_CHAR, BASE_NONE,
          VALS(aca_chbw), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_chan_b,
         {"Channel B", "nmea0183.aca.chan_b",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_chan_b_bw,
         {"Channel B Bandwidth", "nmea0183.aca.chan_b_bw",
          FT_CHAR, BASE_NONE,
          VALS(aca_chbw), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_info_src,
         {"Information Source", "nmea0183.aca.info_src",
          FT_CHAR, BASE_NONE,
          VALS(aca_info_src), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_inuse,
         {"'In-use' Flag", "nmea0183.aca.inuse",
          FT_CHAR, BASE_NONE,
          VALS(aca_in_use), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_inuse_change,
         {"Time of 'in-use' Change (UTC)", "nmea0183.aca.inuse_change",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_ne_clat,
         {"Northeast Corner Latitude", "nmea0183.aca.ne_clatitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_ne_clong,
         {"Northeast Corner Longitude", "nmea0183.aca.ne_clongitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_power,
         {"Power Level Control", "nmea0183.aca.power",
          FT_CHAR, BASE_NONE,
          VALS(aca_power), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_seq_num,
         {"Sequence Number", "nmea0183.aca.seq_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_sw_clat,
         {"Southwest Corner Latitude", "nmea0183.aca.sw_clatitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_sw_clong,
         {"Southwest Corner Longitude", "nmea0183.aca.sw_clongitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_txrx_mode,
         {"Tx/Rx Mode Control", "nmea0183.aca.txrx_mode",
          FT_CHAR, BASE_NONE,
          VALS(aca_txrx_control), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_aca_zone_size,
         {"Transition Zone Size (nm)", "nmea0183.aca.zonesize",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ack_alarm_id,
         {"Unique Alarm Number at Alarm Source", "nmea0183.acs.id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_acs_day,
         {"Day (01 to 31) (UTC)", "nmea0183.acs.day",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_acs_mmsi,
         {"MMSI of Originator", "nmea0183.acs.mmsi",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_acs_month,
         {"Month (01 to 12) (UTC)", "nmea0183.acs.month",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_acs_seq_num,
         {"Sequence Number", "nmea0183.acs.seq_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_acs_utc,
         {"UTC of Receipt of Channel Management Information", "nmea0183.acs.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_acs_year,
         {"Year (UTC)", "nmea0183.acs.year",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_air_mmsi_is1,
         {"MMSI of Interrogated Station #1", "nmea0183.air.mmsi1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_air_mmsi_is2,
         {"MMSI of Interrogated Station #2", "nmea0183.air.mmsi2",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_air_msg2_req,
         {"ITU-R M.1371 Message #2 Requested from Station #1", "nmea0183.air.msg2_req_is1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_air_msg2_sub,
         {"Message #2 Sub-Section", "nmea0183.air.msg2_sub_is1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_air_msg_req,
         {"ITU-R M.1371 Message #1 Requested from Station #1", "nmea0183.air.msg_req_is1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_air_msg_req_is2,
         {"ITU-R M.1371 Message Requested from Station #2", "nmea0183.air.msg_req_is2",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_air_msg_sub,
         {"Message #1 Sub-Section", "nmea0183.air.msg_sub_is1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_air_msg_sub_is2,
         {"Message Sub-Section - Station #2", "nmea0183.air.msg_sub_is2",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_akd_alarm_type,
         {"Type of Alarm", "nmea0183.akd.alarm_type",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_akd_inst_num_orig,
         {"Instance Number of Equipment/Unit/Item (Original)", "nmea0183.akd.inst_num_orig",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_akd_inst_num_send,
         {"Instance Number of Equipment/Unit/Item (Sending)", "nmea0183.akd.inst_num_send",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_akd_subsys_indicator_orig,
         {"Subsystem Indicator of Original Alarm Source", "nmea0183.akd.ss_indic_orig",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_akd_sybsys_indicator_send,
         {"Subsystem Indicator of System Sending Acknowledgement", "nmea0183.akd.ss_indic_send",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_akd_sys_indicator_orig,
         {"System Indicator of Original Alarm Source", "nmea0183.akd.s_indic_orig",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_akd_sys_indicator_send,
         {"System Indicator of System Sending Acknowledgement", "nmea0183.akd.s_indic_send",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_akd_utc,
         {"Time of Acknowledgement (UTC)", "nmea0183.akd.time",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ala_alarm_ack_state,
         {"Alarm's Acknowledged State", "nmea0183.ala.alarm_state",
          FT_CHAR, BASE_NONE,
          VALS(alarm_ack_state_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ala_alarm_cond,
         {"Alarm Condition", "nmea0183.ala.alarm_cond",
          FT_CHAR, BASE_NONE,
          VALS(alarm_cond_state_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ala_alarm_text,
         {"Alarm's Description Text", "nmea0183.ala.alarm_text",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ala_alarm_type,
         {"Type of Alarm", "nmea0183.ala.alarm_type",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ala_inst_num,
         {"Instance Number of Equipment/Unit/Item", "nmea0183.ala.inst_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ala_subsys_indicator,
         {"Subsystem Indicator of Alarm Source", "nmea0183.ala.ss_indic",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ala_sys_indicator,
         {"System Indicator of Alarm Source", "nmea0183.ala.s_indic",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ala_time,
         {"Event Time (UTC)", "nmea0183.ala.time",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_af0_clock_param,
         {"a(f0), Clock Parameter", "nmea0183.alm.af0_clock",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_af1_clock_param,
         {"a(f1), Clock Parameter", "nmea0183.alm.af1_clock",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_alm_ref_time,
         {"t(oa), Almanac Reference Time", "nmea0183.alm.ref_time",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_arg_perigee,
         {"OMEGA, Argument of Perigee", "nmea0183.alm.perigee",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_eccent,
         {"e, Eccentricity", "nmea0183.alm.eccentricity",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_gps_week,
         {"GPS Week Number", "nmea0183.alm.gps_week",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_incl_angle,
         {"(sigma)(i), Inclination Angle", "nmea0183.alm.inc_angle",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_long_asc_node,
         {"(OMEGA)(o), Longitude of Ascending Node", "nmea0183.alm.long_asn_node",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_mean_anomaly,
         {"M(o), Mean Anomaly", "nmea0183.alm.anomaly",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_rate_right_asc,
         {"OMEGADOT, Rate of Right Ascension", "nmea0183.alm.rate_right_asc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_root_sm_axis,
         {"root(A), Root of Semi-Major Axis", "nmea0183.alm.axis",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_sat_prn,
         {"Satellite PRN Number", "nmea0183.alm.satprn",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_sent_num,
         {"Sentence Number", "nmea0183.alm.sentence_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_sent_tot,
         {"Total Number of Sentences", "nmea0183.alm.num_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alm_sv_health,
         {"SV Health", "nmea0183.alm.sv_health",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alr_alarm_ack_st,
         {"Alarm’s acknowledge state", "nmea0183.alr_alarm_ack_st",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alr_alarm_cond,
         {"Alarm condition", "nmea0183.alr_alarm_cond",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alr_alarm_desc_txt,
         {"Alarm’s description text", "nmea0183.alr_alarm_desc_txt",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alr_alarm_id,
         {"Alarm id", "nmea0183.alr_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alr_time,
         {"UTC Time of alarm condition change", "nmea0183.alr_time",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alr_time_hour,
         {"Hour", "nmea0183.alr_time_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alr_time_minute,
         {"Minute", "nmea0183.alr_time_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_alr_time_second,
         {"Second", "nmea0183.alr_time_second",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_arr_circle_status,
         {"Arrival Circle Status", "nmea0183.apb.arrival_status",
          FT_CHAR, BASE_NONE,
          VALS(arrival_circle_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_bearing_origin,
         {"Bearing Origin to Destination", "nmea0183.apb.bearing_origin",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_bearing_present,
         {"Bearing, Present position to Destination", "nmea0183.apb.bearing_present",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_cycle_lock_warning,
         {"Data Status (Loran-C Cycle Lock)", "nmea0183.apb.cycle_warning",
          FT_CHAR, BASE_NONE,
          VALS(loranc_cycle_lock_warning_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_dir_steer,
         {"Direction to Steer", "nmea0183.apb.steer",
          FT_CHAR, BASE_NONE,
          VALS(steer_direction), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_heading_steer,
         {"Heading-to-Steer to Destination Waypoint", "nmea0183.apb.steer_heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_mag_xte,
         {"Magnitude of Cross-Track-Error (XTE)", "nmea0183.apb.mag_xte",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_mode,
         {"Mode Indicator", "nmea0183.apb.mode",
          FT_CHAR, BASE_NONE,
          VALS(mode_indicator), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_perp_status,
         {"Perpendicular Pass Status", "nmea0183.apb.perp_status",
          FT_CHAR, BASE_NONE,
          VALS(perpendicular_pass_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_waypoint_id,
         {"Waypoint ID", "nmea0183.apb.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_apb_xte_units,
         {"XTE units", "nmea0183.apb.xte_units",
          FT_CHAR, BASE_NONE,
          VALS(xte_unit_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bec_bearing_mag,
         {"Bearing (degrees Magnetic)", "nmea0183.bec.bearing_mag",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bec_bearing_true,
         {"Bearing (degrees True)", "nmea0183.bec.bearing_true",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bec_distance,
         {"Distance (nm)", "nmea0183.bec.distance",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bec_latitude,
         {"Waypoint Latitude", "nmea0183.bec.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bec_longitude,
         {"Waypoint Longitude", "nmea0183.bec.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bec_utc,
         {"UTC of Observation", "nmea0183.bec.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bec_waypoint,
         {"Waypoint ID", "nmea0183.bec.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        { &hf_nmea0183_bin_blockid,
         { "Blockid", "nmea0183.bin.blockid",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_channel,
         { "Channel", "nmea0183.bin.channel",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_data,
         { "Data", "nmea0183.bin.data",
          FT_BYTES, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_data_type,
         { "Data type", "nmea0183.bin.data_type",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_device,
         { "Device", "nmea0183.bin.device",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_dstid,
         { "Destination Id", "nmea0183.bin.dst_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_file_descriptor,
         { "File descriptor", "nmea0183.bin.file_descriptor",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_file_descriptor_len,
         { "File descriptor length", "nmea0183.bin.fd_len",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_file_length,
         { "File length", "nmea0183.bin.file_len",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_max_seqnum,
         { "Max Sequence number", "nmea0183.bin.maxseqnum",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_mtype,
         { "Mtype", "nmea0183.bin.mtype",
          FT_UINT16, BASE_DEC,
          VALS(nmea0183_bin_mtype_vals), 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_seqnum,
         { "Sequence number", "nmea0183.bin.seqnum",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_srcid,
         { "Source Id", "nmea0183.bin.src_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL }},
        { &hf_nmea0183_bin_stat_of_acquisition,
         { "Status of acquisition", "nmea0183.bin.stat_of_acquisition",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_status_and_info,
         { "Status and information text", "nmea0183.bin.status_and_info",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_type_len,
         { "Type length", "nmea0183.bin.type_len",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL } },
        { &hf_nmea0183_bin_version,
         { "Version", "nmea0183.bin.version",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL }},
        {&hf_nmea0183_bod_bearing_mag,
         {"Bearing (degrees Magnetic)", "nmea0183.bod.bearing_mag",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bod_bearing_true,
         {"Bearing (degrees True)", "nmea0183.bod.bearing_true",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bod_dest_waypoint,
         {"Destination Waypoint ID", "nmea0183.bod.waypoint_dest",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bod_orig_waypoint,
         {"Origin Waypoint ID", "nmea0183.bod.waypoint_orig",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwc_bearing_mag,
         {"Bearing (degrees Magnetic)", "nmea0183.bwc.bearing_mag",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwc_bearing_true,
         {"Bearing (degrees True)", "nmea0183.bwc.bearing_true",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwc_distance,
         {"Distance (nm)", "nmea0183.bwc.distance",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwc_latitude,
         {"Waypoint Latitude", "nmea0183.bwc.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwc_longitude,
         {"Waypoint Longitude", "nmea0183.bwc.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwc_mode,
         {"Mode Indicator", "nmea0183.bwc.mode",
          FT_CHAR, BASE_NONE,
          VALS(mode_indicator), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwc_utc,
         {"UTC of Observation", "nmea0183.bwc.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwc_waypoint,
         {"Waypoint ID", "nmea0183.bwc.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwr_bearing_mag,
         {"Bearing (degrees Magnetic)", "nmea0183.bwr.bearing_mag",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwr_bearing_true,
         {"Bearing (degrees True)", "nmea0183.bwr.bearing_true",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwr_distance,
         {"Distance (nm)", "nmea0183.bwr.distance",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwr_latitude,
         {"Waypoint Latitude", "nmea0183.bwr.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwr_longitude,
         {"Waypoint Longitude", "nmea0183.bwr.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwr_mode,
         {"Mode Indicator", "nmea0183.bwr.mode",
          FT_CHAR, BASE_NONE,
          VALS(mode_indicator), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwr_utc,
         {"UTC of Observation", "nmea0183.bwr.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bwr_waypoint,
         {"Waypoint ID", "nmea0183.bwr.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bww_bearing_mag,
         {"Bearing (degrees Magnetic)", "nmea0183.bww.bearing_mag",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bww_bearing_true,
         {"Bearing (degrees True)", "nmea0183.bww.bearing_true",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bww_from_waypoint,
         {"FROM Waypoint ID", "nmea0183.bww.waypoint_from",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_bww_to_waypoint,
         {"TO Waypoint ID", "nmea0183.bww.waypoint_to",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_hr_chan_a,
         {"Start Hour (UTC), Channel A", "nmea0183.cbr.chan_a_hr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_hr_chan_b,
         {"Start Hour (UTC), Channel B", "nmea0183.cbr.chan_b_hr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_interv_chan_a,
         {"Slot Interval, Channel A", "nmea0183.cbr.chan_a_interval",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_interv_chan_b,
         {"Slot Interval, Channel B", "nmea0183.cbr.chan_b_interval",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_min_chan_a,
         {"Start Minute (UTC), Channel A", "nmea0183.cbr.chan_a_min",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_min_chan_b,
         {"Start Minute (UTC), Channel B", "nmea0183.cbr.chan_b_min",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_mmsi,
         {"MMSI", "nmea0183.cbr.mmsi",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_msd_id_index,
         {"Message ID Index", "nmea0183.cbr.msg_id_index",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_msg_id,
         {"Message ID", "nmea0183.cbr.msg_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_setup,
         {"FATDMA or RATDMA/CSTDMA Setup", "nmea0183.cbr.setup",
          FT_CHAR, BASE_NONE,
          VALS(dma_setup_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_slot_chan_a,
         {"Start Slot, Channel A", "nmea0183.cbr.chan_a_slot",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_slot_chan_b,
         {"Start Slot, Channel B", "nmea0183.cbr.chan_b_slot",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cbr_status,
         {"Sentence Status Flag", "nmea0183.cbr.status",
          FT_CHAR, BASE_NONE,
          VALS(sentence_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_data_set,
         {"Data Set Number (0 to 9)", "nmea0183.cur.dataset_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_depth,
         {"Current Depth (m)", "nmea0183.cur.depth",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_direction,
         {"Current Direction (degrees)", "nmea0183.cur.direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_direction_ref,
         {"Direction Reference in use", "nmea0183.cur.direction_ref",
          FT_CHAR, BASE_NONE,
          VALS(direction_reference), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_heading,
         {"Heading", "nmea0183.cur.heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_heading_ref,
         {"Heading Reference in use", "nmea0183.cur.heading_ref",
          FT_CHAR, BASE_NONE,
          VALS(heading_reference), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_layer,
         {"Layer Number", "nmea0183.cur.layer",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_ref_layer,
         {"Reference Layer Depth (m)", "nmea0183.cur.ref_layer",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_speed,
         {"Current Speed (knots)", "nmea0183.cur.speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_speed_ref,
         {"Speed Reference", "nmea0183.cur.speed_ref",
          FT_CHAR, BASE_NONE,
          VALS(speed_reference), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_cur_validity,
         {"Validity of the Data", "nmea0183.cur.validity",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dbt_fathoms,
         {"Water depth (fathoms)", "nmea0183.dbt.fathoms",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dbt_feet,
         {"Water depth (feet)", "nmea0183.dbt.feet",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dbt_meters,
         {"Water depth (meters)", "nmea0183.dbt.meters",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_data_basis,
         {"Fix Data Basis", "nmea0183.dcn.basis",
          FT_CHAR, BASE_NONE,
          VALS(dcn_data_basis), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_dc_id,
         {"Decca Chain Identifier", "nmea0183.dcn.dcid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_glop,
         {"Green Line of Position (LOP)", "nmea0183.dcn.glop",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_gnav,
         {"Green-line Navigation Use", "nmea0183.dcn.gnav",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_gstatus,
         {"Status: Green-Master Line", "nmea0183.dcn.gstatus",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_gz_id,
         {"Green Zone Identifier", "nmea0183.dcn.gzid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_plop,
         {"Purple Line of Position (LOP)", "nmea0183.dcn.plop",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_pnav,
         {"Purple-line Navigation Use", "nmea0183.dcn.pnav",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_pos_uncertainty,
         {"Position Uncertainty (nm)", "nmea0183.dcn.pos_uncertainty",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_pstatus,
         {"Status: Purple-Master Line", "nmea0183.dcn.pstatus",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_pz_id,
         {"Purple Zone Identifier", "nmea0183.dcn.pzid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_rlop,
         {"Red Line of Position (LOP)", "nmea0183.dcn.rlop",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_rnav,
         {"Red-line Navigation Use", "nmea0183.dcn.rnav",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_rstatus,
         {"Status: Red-Master Line", "nmea0183.dcn.rstatus",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dcn_rz_id,
         {"Red Zone Identifier", "nmea0183.dcn.rzid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ddc_brightness,
         {"Brightness Percentage", "nmea0183.ddc.brightness",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ddc_dimming,
         {"Display Dimming Preset", "nmea0183.ddc.dimming",
          FT_CHAR, BASE_NONE,
          VALS(dimming_palette_preset_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ddc_palette,
         {"Color Palette", "nmea0183.ddc.palette",
          FT_CHAR, BASE_NONE,
          VALS(dimming_palette_preset_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ddc_status,
         {"Sentence Status Flag", "nmea0183.ddc.status",
          FT_CHAR, BASE_NONE,
          VALS(sentence_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_door_num,
         {"Door Number", "nmea0183.dor.number",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_first_indic,
         {"First Division Indicator", "nmea0183.dor.indicator_1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_msg_type,
         {"Message Type", "nmea0183.dor.msg_type",
          FT_CHAR, BASE_NONE,
          VALS(dor_msg_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_open_count,
         {"Open and/or Faulty Door Count", "nmea0183.dor.open_count",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_second_indic,
         {"Second Division Indicator", "nmea0183.dor.indicator_2",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_setting,
         {"Watertight Door Switch Setting", "nmea0183.dor.setting",
          FT_CHAR, BASE_NONE,
          VALS(watertight_switch_setting_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_status,
         {"Door Status", "nmea0183.dor.status",
          FT_CHAR, BASE_NONE,
          VALS(door_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_system_type,
         {"Type of Door Monitoring System", "nmea0183.dor.sys_type",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_text,
         {"Message Description Text", "nmea0183.dor.text",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dor_time,
         {"Event Time (UTC)", "nmea0183.dor.time",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
          {&hf_nmea0183_dpt_depth,
         {"Water depth", "nmea0183.dpt_depth",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 DPT Water depth relative to transducer", HFILL}},
        {&hf_nmea0183_dpt_max_range,
         {"Maximum range", "nmea0183.dpt_max_range",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 DPT Maximum range scale in use (NMEA 3.0 and above)", HFILL}},
        {&hf_nmea0183_dpt_offset,
         {"Offset", "nmea0183.dpt_offset",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 DPT Offset from transducer, positive means distance from transducer to water line, negative means distance from transducer to keel", HFILL}},
        {&hf_nmea0183_dsc_ack,
         {"Acknowledgement", "nmea0183.dsc.ack",
          FT_CHAR, BASE_NONE,
          VALS(dsc_ack_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_address,
         {"Address", "nmea0183.dsc.address",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_category,
         {"Category", "nmea0183.dsc.category",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_comm_type,
         {"Type of Communication", "nmea0183.dsc.comm_type",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_expansion,
         {"Expansion Indicator", "nmea0183.dsc.expansion",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_first_tcmd,
         {"First Telecommand", "nmea0183.dsc.first_tcmd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_format,
         {"Format Specifier", "nmea0183.dsc.format",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_mmsi,
         {"MMSI of Ship in Distress", "nmea0183.dsc.mmsi",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_nature_distress,
         {"Nature of Distress", "nmea0183.dsc.distress",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_position,
         {"Position", "nmea0183.dsc.position",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsc_time,
         {"Time (UTC)", "nmea0183.dsc.time",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dse_code,
         {"Code", "nmea0183.dse.code",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dse_data,
         {"Data", "nmea0183.dse.data",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dse_flag,
         {"Query/Reply Flag", "nmea0183.dse.flag",
          FT_CHAR, BASE_NONE,
          VALS(dse_flag_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dse_mmsi,
         {"Vessel MMSI", "nmea0183.dse.mmsi",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dse_sentence_number,
         {"Sentence Number", "nmea0183.dse.sentence_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dse_total_sentences,
         {"Total Number of Sentences", "nmea0183.dse.tot_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_course,
         {"Vessel Course (degrees True)", "nmea0183.dsi.course",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_expansion,
         {"Expansion Indicator", "nmea0183.dsi.expansion",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_geo_area,
         {"Geographic Area (0.01 minutes)", "nmea0183.dsi.geo",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_info,
         {"Information", "nmea0183.dsi.info",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_mmsi,
         {"Vessel MMSI", "nmea0183.dsi.mmsi",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_sentence_number,
         {"Sentence Number", "nmea0183.dsi.sentence_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_symbol,
         {"Symbol", "nmea0183.dsi.symbol",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_total_sentences,
         {"Total Number of Sentences", "nmea0183.dsi.tot_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsi_type,
         {"Vessel Type", "nmea0183.dsi.type",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsr_expansion,
         {"Expansion Indicator", "nmea0183.dsr.expansion",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsr_info,
         {"Information", "nmea0183.dsr.info",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsr_mmsi,
         {"Vessel MMSI", "nmea0183.dsr.mmsi",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsr_sentence_number,
         {"Sentence Number", "nmea0183.dsr.sentence_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsr_symbol,
         {"Symbol", "nmea0183.dsr.symbol",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dsr_total_sentences,
         {"Total Number of Sentences", "nmea0183.dsr.tot_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dtm_alt_offset,
         {"Altitude Offset (m)", "nmea0183.dtm.alt_offset",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dtm_datum,
         {"Datum Code", "nmea0183.dtm.datum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dtm_datum_subdiv,
         {"Datum Subdivision Code", "nmea0183.dtm.datum_sub",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dtm_lat_offset,
         {"Latitude Offset (minutes)", "nmea0183.dtm.lat_offset",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dtm_lon_offset,
         {"Longitude Offset (minutes)", "nmea0183.dtm.lon_offset",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_dtm_ref_datum,
         {"Reference Datum Code", "nmea0183.dtm.ref_datum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_etl_msg_type,
         {"Message Type", "nmea0183.etl.msg_type",
          FT_CHAR, BASE_NONE,
          VALS(etl_message_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_etl_num_eng_shaft,
         {"Number of Engine or Propeller Shaft", "nmea0183.etl.engshaft_num",
          FT_CHAR, BASE_NONE,
          VALS(revolutions_number_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_etl_opind,
         {"Operating Location Indicator", "nmea0183.etl.posind_op",
          FT_CHAR, BASE_NONE,
          VALS(oplocation_indicator_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_etl_posind_engine,
         {"Position Indicator of Engine Telegraph", "nmea0183.etl.posind_eng",
          FT_UINT16, BASE_DEC,
          VALS(indicators_for_engine_telegraph), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_etl_posind_sub,
         {"Position Indication of Sub Telegraph", "nmea0183.etl.posind_sub",
          FT_UINT16, BASE_DEC,
          VALS(indicators_for_sub_telegraph), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_etl_time,
         {"Event Time (UTC)", "nmea0183.etl.time",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_fsi_mode,
         {"Mode of Operation", "nmea0183.fsi.mode",
          FT_CHAR, BASE_NONE,
          VALS(fsi_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_fsi_power,
         {"Reference Datum Code", "nmea0183.fsi.power",
          FT_CHAR, BASE_NONE,
          VALS(fsi_power_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_fsi_recv_freq,
         {"Receive Frequency (100Hz Increments)", "nmea0183.fsi.recv_freq",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_fsi_xmit_freq,
         {"Transmit Frequency (100Hz Increments)", "nmea0183.fsi.xmit_freq",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_alt_err,
         {"Expected Error in Altitude (m)", "nmea0183.gbs.alt_err",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_est_bias,
         {"Estimate of Bias (m) on Most Likely Failed Satellite", "nmea0183.gbs.est_bias",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_lat_err,
         {"Expected Error in Latitude (m)", "nmea0183.gbs.lat_err",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_long_err,
         {"Expected Error in Longitude (m)", "nmea0183.gbs.long_err",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_prob_miss,
         {"Prob. of Missed Detection for Most Likely Failed Satellite", "nmea0183.gbs.prob_miss",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_sat_id,
         {"ID Number of Most Likely Failed Satellite (PRN No.)", "nmea0183.gbs.sat_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_sat_type,
         {"Satellite Type", "nmea0183.gbs.sat_type",
          FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
          RVALS(sat_prn_type), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_std_dev,
         {"Standard Deviation of Bias Estimate", "nmea0183.gbs.std_dev",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gbs_utc,
         {"UTC time of the GGA or GNS fix", "nmea0183.gbs.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_age_dgps,
         {"Age of differential GPS", "nmea0183.gga_age_dgps",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_altitude,
         {"Altitude", "nmea0183.gga_altitude",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Antenna Altitude above mean-sea-level", HFILL}},
        {&hf_nmea0183_gga_altitude_unit,
         {"Altitude unit", "nmea0183.gga_altitude_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Units of antenna altitude", HFILL}},
        {&hf_nmea0183_gga_dgps_station,
         {"Differential GPS station id", "nmea0183.gga_dgps_station",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Differential reference station ID", HFILL}},
        {&hf_nmea0183_gga_geoidal_separation,
         {"Geoidal separation", "nmea0183.gga_geoidal_separation",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Geoidal separation, the difference between the WGS-84 earth ellipsoid and mean-sea-level", HFILL}},
        {&hf_nmea0183_gga_geoidal_separation_unit,
         {"Geoidal separation unit", "nmea0183.gga_geoidal_separation_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Units of geoidal separation, meters", HFILL}},
        {&hf_nmea0183_gga_horizontal_dilution,
         {"Horizontal Dilution", "nmea0183.gga_horizontal_dilution",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Horizontal Dilution of precision", HFILL}},
        {&hf_nmea0183_gga_latitude,
         {"Latitude", "nmea0183.gga_latitude",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_latitude_degree,
         {"Degree", "nmea0183.gga_latitude_degree",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_latitude_direction,
         {"Direction", "nmea0183.gga_latitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_latitude_minute,
         {"Minute", "nmea0183.gga_latitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_longitude,
         {"Longitude", "nmea0183.gga_longitude",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_longitude_degree,
         {"Degree", "nmea0183.gga_longitude_degree",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_longitude_direction,
         {"Direction", "nmea0183.gga_longitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_longitude_minute,
         {"Minute", "nmea0183.gga_longitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_number_satellites,
         {"Number of satellites", "nmea0183.gga_number_satellites",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Number of satellites in use", HFILL}},
        {&hf_nmea0183_gga_quality,
         {"Quality indicator", "nmea0183.gga_quality",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_time,
         {"UTC Time of position", "nmea0183.gga_time",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_time_hour,
         {"Hour", "nmea0183.gga_time_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_time_minute,
         {"Minute", "nmea0183.gga_time_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_time_second,
         {"Second", "nmea0183.gga_time_second",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_glc_gri,
         {"Loran-C GRI (tens of microseconds)", "nmea0183.glc.gri",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_glc_master_toa,
         {"Master TOA (microseconds)", "nmea0183.glc.master",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_glc_sig_status,
         {"Signal Status", "nmea0183.glc.status",
          FT_CHAR, BASE_NONE,
          VALS(glc_sig_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_glc_td1,
         {"Time Difference #1 (microseconds)", "nmea0183.glc.td1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_glc_td2,
         {"Time Difference #2 (microseconds)", "nmea0183.glc.td2",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_glc_td3,
         {"Time Difference #3 (microseconds)", "nmea0183.glc.td3",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_glc_td4,
         {"Time Difference #4 (microseconds)", "nmea0183.glc.td4",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_glc_td5,
         {"Time Difference #5 (microseconds)", "nmea0183.glc.td5",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_latitude,
         {"Latitude", "nmea0183.gll_latitude",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_latitude_degree,
         {"Degree", "nmea0183.gll_latitude_degree",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_latitude_direction,
         {"Direction", "nmea0183.gll_latitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_latitude_minute,
         {"Minute", "nmea0183.gll_latitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_longitude,
         {"Longitude", "nmea0183.gll_longitude",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_longitude_degree,
         {"Degree", "nmea0183.gll_longitude_degree",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_longitude_direction,
         {"Direction", "nmea0183.gll_longitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_longitude_minute,
         {"Minute", "nmea0183.gll_longitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_mode,
         {"FAA mode", "nmea0183.gll_mode",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL FAA mode indicator (NMEA 2.3 and later)", HFILL}},
        {&hf_nmea0183_gll_status,
         {"Status", "nmea0183.gll_status",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_time,
         {"UTC Time of position", "nmea0183.gll_time",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_time_hour,
         {"Hour", "nmea0183.gll_time_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_time_minute,
         {"Minute", "nmea0183.gll_time_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_time_second,
         {"Second", "nmea0183.gll_time_second",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_ant_alt,
         {"Antenna Altitude (m) - MSL (geoid)", "nmea0183.gmp.ant_alt",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_data_age,
         {"Age of Differential Data", "nmea0183.gmp.data_age",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_diff_ref_id,
         {"Differential Reference Station ID", "nmea0183.gmp.diff_ref_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_geoid_sep,
         {"Geoidal Separation (m)", "nmea0183.gmp.geoid_sep",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_hdop,
         {"Horizontal Dilution of Precision (DOP)", "nmea0183.gmp.hdop",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_mode_glonass,
         {"GLONASS Mode Indicator", "nmea0183.gmp.mode_glonass",
          FT_CHAR, BASE_NONE,
          VALS(satellite_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_mode_gps,
         {"GPS Mode Indicator", "nmea0183.gmp.mode_gps",
          FT_CHAR, BASE_NONE,
          VALS(satellite_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_mode_other,
         {"Other Satellite System Mode Indicator", "nmea0183.gmp.mode_other",
          FT_CHAR, BASE_NONE,
          VALS(satellite_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_mode_string,
         {"Mode Indicator String", "nmea0183.gmp.mode_string",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_projection,
         {"Map Projection Identification", "nmea0183.gmp.projection",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_tot_sats,
         {"Total Number of Satellites in use (00-99)", "nmea0183.gmp.tot_sats",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_utc,
         {"UTC of Position", "nmea0183.gmp.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_x_comp,
         {"X (Northern) Component of Grid (or local) Coordinates", "nmea0183.gmp.x_comp",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_y_comp,
         {"Y (Eastern) Component of Grid (or local) Coordinates", "nmea0183.gmp.y_comp",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gmp_zone,
         {"Map Zone", "nmea0183.gmp.zone",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_ant_alt,
         {"Antenna Altitude (m) - MSL (geoid)", "nmea0183.gns.ant_alt",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_data_age,
         {"Age of Differential Data", "nmea0183.gns.data_age",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_diff_ref_id,
         {"Differential Reference Station ID", "nmea0183.gns.diff_ref_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_geoid_sep,
         {"Geoidal Separation (m)", "nmea0183.gns.geoid_sep",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_hdop,
         {"Horizontal Dilution of Precision (DOP)", "nmea0183.gns.hdop",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_latitude,
         {"Latitude", "nmea0183.gns.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_longitude,
         {"Longitude", "nmea0183.gns.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_mode_glonass,
         {"GLONASS Mode Indicator", "nmea0183.gns.mode_glonass",
          FT_CHAR, BASE_NONE,
          VALS(satellite_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_mode_gps,
         {"GPS Mode Indicator", "nmea0183.gns.mode_gps",
          FT_CHAR, BASE_NONE,
          VALS(satellite_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_mode_other,
         {"Other Satellite System Mode Indicator", "nmea0183.gns.mode_other",
          FT_CHAR, BASE_NONE,
          VALS(satellite_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_mode_string,
         {"Mode Indicator String", "nmea0183.gns.mode_string",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_tot_sats,
         {"Total Number of Satellites in use (00-99)", "nmea0183.gns.tot_sats",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gns_utc,
         {"UTC of Position", "nmea0183.gns.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_grs_mode,
         {"Mode (Residuals)", "nmea0183.grs.mode",
          FT_CHAR, BASE_NONE,
          VALS(grs_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_grs_range_resid,
         {"Range Residual (m)", "nmea0183.grs.residual",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_grs_utc,
         {"UTC time of the associated GGA/GNS fix", "nmea0183.grs.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsa_fix_mode,
         {"Fix Mode", "nmea0183.gsa.fixmode",
          FT_CHAR, BASE_NONE,
          VALS(gsa_fix_mode), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsa_hdop,
         {"Horizontal Dilution of Precision (HDOP)", "nmea0183.gsa.hdop",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsa_op_mode,
         {"Operation Mode", "nmea0183.gsa.opmode",
          FT_CHAR, BASE_NONE,
          VALS(gsa_op_mode), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsa_pdop,
         {"Position Dilution of Precision (PDOP)", "nmea0183.gsa.pdop",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsa_sat_id,
         {"Satellite ID", "nmea0183.gsa.sat_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsa_sat_type,
         {"Satellite Type", "nmea0183.gsa.sat_type",
          FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
          RVALS(sat_prn_type), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsa_vdop,
         {"Vertical Dilution of Precision (VDOP)", "nmea0183.gsa.vdop",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_altitude_sd,
         {"Standard deviation of altitude error", "nmea0183.gst_sd_altitude",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_ellipse_major_sd,
         {"Standard deviation of semi-major axis of error", "nmea0183.gst_ellipse_major_sd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_ellipse_minor_sd,
         {"Standard deviation of semi-minor axis of error ellipse", "nmea0183.gst_ellipse_minor_sd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_ellipse_orientation,
         {"Orientation of semi-major axis of error ellipse", "nmea0183.gst_ellipse_orientation",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GST Orientation of semi-major axis of error ellipse (true north degrees)", HFILL}},
        {&hf_nmea0183_gst_latitude_sd,
         {"Standard deviation of latitude error", "nmea0183.gst_sd_latitude",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_longitude_sd,
         {"Standard deviation of longitude error", "nmea0183.gst_sd_longitude",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_rms_total_sd,
         {"Total RMS standard deviation", "nmea0183.gst_sd_rms_total",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GST Total RMS standard deviation of ranges inputs to the navigation solution", HFILL}},
        {&hf_nmea0183_gst_time,
         {"UTC Time of position", "nmea0183.gst_time",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_time_hour,
         {"Hour", "nmea0183.gst_time_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_time_minute,
         {"Minute", "nmea0183.gst_time_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gst_time_second,
         {"Second", "nmea0183.gst_time_second",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsv_azimuth,
         {"Azimuth (degrees True)", "nmea0183.gsv.azimuth",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsv_elevation,
         {"Elevation (degrees, 90 max)", "nmea0183.gsv.elevation",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsv_sat_id,
         {"Satellite ID", "nmea0183.gsv.sat_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsv_sat_type,
         {"Satellite Type", "nmea0183.gsv.sat_type",
          FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
          RVALS(sat_prn_type), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsv_sats_in_view,
         {"Total Number of Satellites in View", "nmea0183.gsv.tot_sats",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsv_sentence_number,
         {"Sentence Number (1 to 9)", "nmea0183.gsv.sentence_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsv_snr,
         {"SNR (C/No) (db-Hz)", "nmea0183.gsv.snr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gsv_total_sentences,
         {"Total Number of Sentences (1 to 9)", "nmea0183.gsv.tot_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hbt_interval,
         {"Configured Repeat Interval", "nmea0183.hbt.interval",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hbt_sent_id,
         {"Sequential Sentence Identifier", "nmea0183.hbt.sent_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hbt_status,
         {"Equipment Status", "nmea0183.hbt.status",
          FT_CHAR, BASE_NONE,
          VALS(equipment_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hdg_mag_dev,
         {"Magnetic Deviation (degrees E/W)", "nmea0183.hdg.deviation",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hdg_mag_sensor,
         {"Magnetic Sensor Heading (degrees)", "nmea0183.hdg.sensor",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hdg_mag_var,
         {"Magnetic Variation (degrees E/W)", "nmea0183.hdg.variation",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hdt_heading,
         {"True heading", "nmea0183.hdt_heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hdt_unit,
         {"Heading unit", "nmea0183.hdt_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 HDT Heading unit, must be T", HFILL}},
        {&hf_nmea0183_hmr_dev_s1,
         {"Deviation, Sensor 1 (degrees)", "nmea0183.hmr.s1_dev",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_dev_s2,
         {"Deviation, Sensor 2 (degrees)", "nmea0183.hmr.s2_dev",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_difflim_setting,
         {"Difference Limit Setting (degrees)", "nmea0183.hmr.difflim",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_heading_s1,
         {"Heading Sensor 1 ID", "nmea0183.hmr.s1_heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_heading_s2,
         {"Heading Sensor 2 ID", "nmea0183.hmr.s2_heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_heading_sdiff,
         {"Actual Heading Sensor Difference (degrees)", "nmea0183.hmr.sensor_diff",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_hr_s1,
         {"Heading Reading, Sensor 1 (degrees)", "nmea0183.hmr.s1_hr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_hr_s2,
         {"Heading Reading, Sensor 2 (degrees)", "nmea0183.hmr.s2_hr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_s1_type,
         {"Sensor 1 Type", "nmea0183.hmr.s1_stype",
          FT_CHAR, BASE_NONE,
          VALS(heading_monitor_sensor_type), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_s2_type,
         {"Sensor 2 Type", "nmea0183.hmr.s2_stype",
          FT_CHAR, BASE_NONE,
          VALS(heading_monitor_sensor_type), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_status_s1,
         {"Status, Sensor 1", "nmea0183.hmr.s1_status",
          FT_CHAR, BASE_NONE,
          VALS(heading_monitor_sensor_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_status_s2,
         {"Status, Sensor 2", "nmea0183.hmr.s2_status",
          FT_CHAR, BASE_NONE,
          VALS(heading_monitor_sensor_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_variation,
         {"Variation (degrees)", "nmea0183.hmr.variation",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hmr_warning_flag,
         {"Override", "nmea0183.hmr.warning",
          FT_CHAR, BASE_NONE,
          VALS(warning_flag_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hms_heading_s1,
         {"Heading Sensor 1 ID", "nmea0183.hms.heading_s1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hms_heading_s2,
         {"Heading Sensor 2 ID", "nmea0183.hms.heading_s2",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hms_max_diff,
         {"Maximum Difference (degrees)", "nmea0183.hms.max_diff",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hsc_heading_magnetic,
         {"Commanded Heading (degrees Magnetic)", "nmea0183.hsc.heading_mag",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_hsc_heading_true,
         {"Commanded Heading (degrees True)", "nmea0183.hsc.heading_true",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_offhead_lim,
         {"Commanded Off-heading Limit (degrees)", "nmea0183.htc.offhead_lim",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_offtrack,
         {"Commanded Off-Track Limit (nm)", "nmea0183.htc.offtrack",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_radius,
         {"Commanded Radius of Turn for Heading Changes (nm)", "nmea0183.htc.radius",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_rate,
         {"Commanded Rate of Turn for Heading Changes (deg./min.)", "nmea0183.htc.rate",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_rudder_angle,
         {"Commanded Rudder Angle (degrees)", "nmea0183.htc.rudder_angle",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_rudder_dir,
         {"Commanded Rudder Direction", "nmea0183.htc.rudder_dir",
          FT_CHAR, BASE_NONE,
          VALS(rudder_dir_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_rudder_lim,
         {"Commanded Rudder Limit (degrees)", "nmea0183.htc.rudder_lim",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_steer,
         {"Commanded Heading-to-Steer (degrees)", "nmea0183.htc.steer",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_cmd_track,
         {"Commanded Track (degrees)", "nmea0183.htc.track",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_heading_ref,
         {"Heading Reference in use", "nmea0183.htc.heading_ref",
          FT_CHAR, BASE_NONE,
          VALS(heading_reference), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_override,
         {"Override", "nmea0183.htc.override",
          FT_CHAR, BASE_NONE,
          VALS(override_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_steering_mode,
         {"Selected Steering Mode", "nmea0183.htc.steering_mode",
          FT_CHAR, BASE_NONE,
          VALS(steering_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htc_turn_mode,
         {"Turn Mode", "nmea0183.htc.turn_mode",
          FT_CHAR, BASE_NONE,
          VALS(turning_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_offhead_lim,
         {"Commanded Off-heading Limit (degrees)", "nmea0183.htd.offhead_lim",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_offtrack,
         {"Commanded Off-Track Limit (nm)", "nmea0183.htd.offtrack",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_radius,
         {"Commanded Radius of Turn for Heading Changes (nm)", "nmea0183.htd.radius",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_rate,
         {"Commanded Rate of Turn for Heading Changes (deg./min.)", "nmea0183.htd.rate",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_rudder_angle,
         {"Commanded Rudder Angle (degrees)", "nmea0183.htd.rudder_angle",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_rudder_dir,
         {"Commanded Rudder Direction", "nmea0183.htd.rudder_dir",
          FT_CHAR, BASE_NONE,
          VALS(rudder_dir_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_rudder_lim,
         {"Commanded Rudder Limit (degrees)", "nmea0183.htd.rudder_lim",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_steer,
         {"Commanded Heading-to-Steer (degrees)", "nmea0183.htd.steer",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_cmd_track,
         {"Commanded Track (degrees)", "nmea0183.htd.track",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_heading_ref,
         {"Heading Reference in use", "nmea0183.htd.heading_ref",
          FT_CHAR, BASE_NONE,
          VALS(heading_reference), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_offhdng_status,
         {"Off-heading Status", "nmea0183.htd.offheading_status",
          FT_CHAR, BASE_NONE,
          VALS(r_oh_ot_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_offtrack_status,
         {"Off-track Status", "nmea0183.htd.offtrack_status",
          FT_CHAR, BASE_NONE,
          VALS(r_oh_ot_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_override,
         {"Override", "nmea0183.htd.override",
          FT_CHAR, BASE_NONE,
          VALS(override_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_rudder_status,
         {"Rudder Status", "nmea0183.htd.rudder_status",
          FT_CHAR, BASE_NONE,
          VALS(r_oh_ot_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_steering_mode,
         {"Selected Steering Mode", "nmea0183.htd.steering_mode",
          FT_CHAR, BASE_NONE,
          VALS(steering_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_turn_mode,
         {"Turn Mode", "nmea0183.htd.turn_mode",
          FT_CHAR, BASE_NONE,
          VALS(turning_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_htd_vessel_heading,
         {"Vessel Heading (degrees)", "nmea0183.htd.vessel_heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_gri,
         {"GRI (tens of microseconds)", "nmea0183.lcd.gri",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_master_ecd,
         {"Master Pulse Shape (ECD)", "nmea0183.lcd.master_ecd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_master_snr,
         {"Master Signal-to-Noise Ratio (SNR)", "nmea0183.lcd.master_snr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s1_ecd,
         {"Secondary 1 ECD", "nmea0183.lcd.s1_ecd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s1_snr,
         {"Secondary 1 SNR", "nmea0183.lcd.s1_snr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s2_ecd,
         {"Secondary 2 ECD", "nmea0183.lcd.s2_ecd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s2_snr,
         {"Secondary 2 SNR", "nmea0183.lcd.s2_snr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s3_ecd,
         {"Secondary 3 ECD", "nmea0183.lcd.s3_ecd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s3_snr,
         {"Secondary 3 SNR", "nmea0183.lcd.s3_snr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s4_ecd,
         {"Secondary 4 ECD", "nmea0183.lcd.s4_ecd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s4_snr,
         {"Secondary 4 SNR", "nmea0183.lcd.s4_snr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s5_ecd,
         {"Secondary 5 ECD", "nmea0183.lcd.s5_ecd",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lcd_s5_snr,
         {"Secondary 5 SNR", "nmea0183.lcd.s5_snr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_loranc_blink_snr_warning,
         {"Data Status (Loran-C Blink / SNR)", "nmea0183.apb.gen_warning",
          FT_CHAR, BASE_NONE,
          VALS(loranc_blink_snr_warning_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr1_callsign,
         {"Call Sign", "nmea0183.lr1.callsign",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr1_imo_num,
         {"IMO Number", "nmea0183.lr1.imo_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr1_req_mmsi,
         {"MMSI of Requestor", "nmea0183.lr1.mmsi_req",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr1_resp_mmsi,
         {"MMSI of Responder", "nmea0183.lr1.mmsi_resp",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr1_seqnum,
         {"Sequence Number (0 to 9)", "nmea0183.lr1.seqnum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr1_shipname,
         {"Ship's Name", "nmea0183.lr1.shipname",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr2_course_ground,
         {"Course Over Ground (degrees True)", "nmea0183.lr2.course",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr2_date,
         {"Date (ddmmyyyy)", "nmea0183.lr2.date",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr2_latitude,
         {"Latitude", "nmea0183.lr2.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr2_longitude,
         {"Longitude", "nmea0183.lr2.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr2_resp_mmsi,
         {"MMSI of Responder", "nmea0183.lr2.mmsi_resp",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr2_seqnum,
         {"Sequence Number (0 to 9)", "nmea0183.lr2.seqnum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr2_speed_ground,
         {"Speed Over Ground (knots)", "nmea0183.lr2.speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr2_utc,
         {"UTC of Position", "nmea0183.lr2.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_destination,
         {"Voyage Destination", "nmea0183.lr3.destination",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_draught,
         {"Draught", "nmea0183.lr3.draught",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_eta_date,
         {"ETA Date (ddmmyy)", "nmea0183.lr3.eta_date",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_eta_time,
         {"ETA Time", "nmea0183.lr3.eta_time",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_persons,
         {"Persons (8191 implies >= 8191)", "nmea0183.lr3.persons",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_resp_mmsi,
         {"MMSI of Responder", "nmea0183.lr3.mmsi_resp",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_seqnum,
         {"Sequence Number (0 to 9)", "nmea0183.lr3.seqnum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_ship_breadth,
         {"Ship Breadth", "nmea0183.lr3.breadth",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_ship_cargo,
         {"Ship/Cargo", "nmea0183.lr3.cargo",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_ship_length,
         {"Ship Length", "nmea0183.lr3.length",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lr3_ship_type,
         {"Ship Type", "nmea0183.lr3.type",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lrf_function_rep,
         {"Function Reply Status String", "nmea0183.lr2.function_rep_string",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lrf_function_rep_val,
         {"Function Reply Status", "nmea0183.lr2.function_rep",
          FT_CHAR, BASE_NONE,
          VALS(lrf_func_rep_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lrf_function_req,
         {"Function Request String", "nmea0183.lr2.function_req_string",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lrf_function_req_val,
         {"Function Request", "nmea0183.lr2.function_req",
          FT_CHAR, BASE_NONE,
          VALS(lrf_func_req_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lrf_mmsi,
         {"MMSI of Requestor", "nmea0183.lrf.mmsi",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lrf_name,
         {"Name of Requestor", "nmea0183.lr2.name",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lrf_seqnum,
         {"Sequence Number (0 to 9)", "nmea0183.lrf.seqnum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lri_control,
         {"Control Flag", "nmea0183.lri.control",
          FT_CHAR, BASE_NONE,
          VALS(control_flag_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lri_dest_mmsi,
         {"MMSI of Destination", "nmea0183.lri.mmsi_dest",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lri_latitude_ne,
         {"Latitude (NE corner)", "nmea0183.lri.latitude_ne",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lri_latitude_sw,
         {"Latitude (SW corner)", "nmea0183.lri.latitude_sw",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lri_longitude_ne,
         {"Longitude (NE corner)", "nmea0183.lri.longitude_ne",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lri_longitude_sw,
         {"Longitude (SW corner)", "nmea0183.lri.longitude_sw",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lri_req_mmsi,
         {"MMSI of Requestor", "nmea0183.lri.mmsi_req",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_lri_seqnum,
         {"Sequence Number (0 to 9)", "nmea0183.lri.seqnum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_12lsb_corr_t_scale,
         {"12 LSB of System Time Scale Correction", "nmea0183.mla.12lsb",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_16msb_corr_t_scale,
         {"16 MSB of System Time Scale Correction", "nmea0183.mla.16msb",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_calday_count,
         {"Calendar Day Count", "nmea0183.mla.calday_count",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_corr_circling,
         {"Correction to the Avg. Value of Draconitic Circling Time", "nmea0183.mla.corr_circling",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_corr_incl_angle,
         {"Correction to the Avg. Value of the Inclination Angle", "nmea0183.mla.inc_angle",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_eccentricity,
         {"Eccentricity", "nmea0183.mla.eccentricity",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_long_asc_node,
         {"Greenwich Longitude of the Ascension Node", "nmea0183.mla.long_asc_node",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_perigee,
         {"Argument of Perigee", "nmea0183.mla.perigee",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_roc_circling,
         {"Rate of Change of Draconitic Circling Time", "nmea0183.mla.roc_circling",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_sat_health,
         {"Satellite Health & Carrier Frequency", "nmea0183.mla.sat_carrier",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_sat_id,
         {"Satellite ID (satellite slot)", "nmea0183.mla.sat_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_sentence_number,
         {"Sentence Number", "nmea0183.mla.sentence_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_t_asc_node,
         {"Time of the Ascension Node & Almanac Reference Time", "nmea0183.mla.asc_node",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_t_scale_shift,
         {"Course Value of the Time Scale Shift", "nmea0183.mla.scale_shift",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mla_total_sentences,
         {"Total Number of Sentences", "nmea0183.mla.tot_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_msk_am_bitrate,
         {"Auto/Manual Bit Rate", "nmea0183.msk.am_bitrate",
          FT_CHAR, BASE_NONE,
          VALS(auto_manual_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_msk_am_freq,
         {"Auto/Manual Frequency", "nmea0183.msk.am_freq",
          FT_CHAR, BASE_NONE,
          VALS(auto_manual_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_msk_beacon_bitrate,
         {"Beacon Bit Rate (bps)", "nmea0183.msk.beacon_bitrate",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_msk_beacon_freq,
         {"Beacon Frequency (kHz)", "nmea0183.msk.beacon_freq",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_msk_channel,
         {"Channel Number", "nmea0183.msk.channel",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_msk_interval,
         {"Interval for sending MSS status (seconds)", "nmea0183.msk.interval",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mss_beacon_bitrate,
         {"Beacon Bit Rate (bps)", "nmea0183.mss.bitrate",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mss_beacon_freq,
         {"Beacon Frequency (kHz)", "nmea0183.mss.beacon_freq",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mss_channel,
         {"Channel Number", "nmea0183.mss.channel",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mss_sig_str,
         {"Signal Strength (dB) (re: 1 uV/m)", "nmea0183.mss.sig_strength",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mss_snr,
         {"Signal-to-Noise Ratio (SNR) (dB)", "nmea0183.mss.snr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mtw_temp,
         {"Water Temperature", "nmea0183.mtw.temp",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwd_direction_mag,
         {"Wind Direction (degrees Magnetic)", "nmea0183.mwd.dir_mag",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwd_direction_true,
         {"Wind Direction (degrees True)", "nmea0183.mwd.dir_true",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwd_speed_knots,
         {"Wind Speed (knots)", "nmea0183.mwd.speed_kts",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwd_speed_ms,
         {"Wind Speed (meters/second)", "nmea0183.mwd.speed_ms",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwv_reference,
         {"Reference", "nmea0183.mwv.reference",
          FT_CHAR, BASE_NONE,
          VALS(mwv_reference), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwv_speed_units,
         {"Wind Speed Units", "nmea0183.mwv.units",
          FT_CHAR, BASE_NONE,
          VALS(speed_unit_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwv_status,
         {"Data Status", "nmea0183.mwv.status",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwv_wind_angle,
         {"Wind Angle (0 to 359 deg)", "nmea0183.mwv.angle",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_mwv_wind_speed,
         {"Wind Speed", "nmea0183.mwv.speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_course_ref,
         {"Course Reference", "nmea0183.osd.course_ref",
          FT_CHAR, BASE_NONE,
          VALS(course_ref_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_course_true,
         {"Vessel Course (degrees True)", "nmea0183.osd.course",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_drift,
         {"Vessel Drift (speed)", "nmea0183.osd.drift",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_heading_status,
         {"Heading Status", "nmea0183.osd.heading_status",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_heading_true,
         {"Heading (degrees True)", "nmea0183.osd.heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_set_true,
         {"Vessel Set (degrees True)", "nmea0183.osd.set",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_speed,
         {"Vessel Speed (degrees True)", "nmea0183.osd.speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_speed_ref,
         {"Speed Reference", "nmea0183.osd.speed_ref",
          FT_CHAR, BASE_NONE,
          VALS(course_ref_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_osd_speed_units,
         {"Speed Units", "nmea0183.osd.speed_units",
          FT_CHAR, BASE_NONE,
          VALS(speed_unit_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_course,
         {"Course Over Ground (degrees True)", "nmea0183.rma.course",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_latitude,
         {"Latitude", "nmea0183.rma.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_longitude,
         {"Longitude", "nmea0183.rma.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_mag_var,
         {"Magnetic Variation (degrees)", "nmea0183.rma.mag_var",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_mode,
         {"Mode Indicator", "nmea0183.rma.mode",
          FT_CHAR, BASE_NONE,
          VALS(mode_indicator), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_speed,
         {"Speed Over Ground (knots)", "nmea0183.rma.speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_status,
         {"Status", "nmea0183.rma.status",
          FT_CHAR, BASE_NONE,
          VALS(rma_data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_time_diff_a,
         {"Time Difference A (microseconds)", "nmea0183.rma.td_a",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rma_time_diff_b,
         {"Time Difference B (microseconds)", "nmea0183.rma.td_b",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_arrival_status,
         {"Arrival Status", "nmea0183.rmb.arrival_status",
          FT_CHAR, BASE_NONE,
          VALS(arrival_circle_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_bearing_dest,
         {"Bearing to Destination (degrees True)", "nmea0183.rmb.bearing",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_data_status,
         {"Data Status", "nmea0183.rmb.data_status",
          FT_CHAR, BASE_NONE,
          VALS(navigation_data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_dest_id,
         {"Destination Waypoint ID", "nmea0183.rmb.dest_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_dest_velocity,
         {"Destination Closing Velocity", "nmea0183.rmb.velocity",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_dest_wp_latitude,
         {"Latitude", "nmea0183.rmb.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_dest_wp_longitude,
         {"Longitude", "nmea0183.rmb.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_mode,
         {"Mode Indicator", "nmea0183.rmb.mode",
          FT_CHAR, BASE_NONE,
          VALS(mode_indicator), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_orig_id,
         {"Origin Waypoint ID", "nmea0183.rmb.orig_id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_range_dest,
         {"Range to Destination (nm)", "nmea0183.rmb.range",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_steer,
         {"Direction to Steer", "nmea0183.rmb.steer",
          FT_CHAR, BASE_NONE,
          VALS(steer_direction), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmb_xte,
         {"Cross Track Error (XTE) (nm)", "nmea0183.rmb.xte",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_course,
         {"Course over ground (degrees True)", "nmea0183.rmc.course",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_date,
         {"Date (ddmmyy)", "nmea0183.rmc.date",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_latitude,
         {"Latitude", "nmea0183.rmc.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_longitude,
         {"Longitude", "nmea0183.rmc.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_magnetic,
         {"Magnetic Variation", "nmea0183.rmc.magnetic",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_mode,
         {"Mode Indicator", "nmea0183.rmc.mode",
          FT_CHAR, BASE_NONE,
          VALS(mode_indicator), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_speed,
         {"Speed over ground (knots)", "nmea0183.rmc.speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_status,
         {"Status", "nmea0183.rmc.status",
          FT_CHAR, BASE_NONE,
          VALS(navigation_data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rmc_utc,
         {"UTC of Position", "nmea0183.rmc.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rot_rate_of_turn,
         {"Rate of turn", "nmea0183.rot_rate_of_turn",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ROT Rate Of Turn, degrees per minute, negative value means bow turns to port", HFILL}},
        {&hf_nmea0183_rot_valid,
         {"Validity", "nmea0183.rot_valid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ROT Status, A means data is valid", HFILL}},
        {&hf_nmea0183_rpm_number,
         {"Engine or Shaft Number (from centerline)", "nmea0183.rpm.number",
          FT_CHAR, BASE_NONE,
          VALS(revolutions_number_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rpm_pitch,
         {"Propeller Pitch (% of max)", "nmea0183.rpm.pitch",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rpm_source,
         {"Source", "nmea0183.rpm.source",
          FT_CHAR, BASE_NONE,
          VALS(revolutions_source_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rpm_speed,
         {"Speed (rev/min)", "nmea0183.rpm.speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rpm_status,
         {"Data Status", "nmea0183.rpm.status",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsa_pt_sensor,
         {"Port Rudder Sensor", "nmea0183.rsa.pt",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsa_pt_status,
         {"Data Status", "nmea0183.rsa.pt_status",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsa_sb_sensor,
         {"Starboard (or single) Rudder Sensor", "nmea0183.rsa.sb",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsa_sb_status,
         {"Data Status", "nmea0183.rsa.sb_status",
          FT_CHAR, BASE_NONE,
          VALS(data_status), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_cursor_bearing,
         {"Cursor Bearing (degrees clockwise from 0)", "nmea0183.rsd.curs_scale",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_cursor_range,
         {"Cursor Range, from own ship", "nmea0183.rsd.curs_range",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_display,
         {"Display Rotation", "nmea0183.rsd.display",
          FT_CHAR, BASE_NONE,
          VALS(display_rotation_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_ebl1,
         {"Bearing Line 1 (EBL1) (degrees from 0)", "nmea0183.rsd.ebl1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_ebl2,
         {"EBL2 (degrees)", "nmea0183.rsd.ebl2",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_orig2_range,
         {"Origin 2 Bearing (degrees from 0)", "nmea0183.rsd.orig2_range",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_orig_bearing,
         {"Origin 1 Bearing (degrees from 0)", "nmea0183.rsd.orig_bearing",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_orig_range,
         {"Origin 1 Range, from own ship", "nmea0183.rsd.orig_range",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_scale,
         {"Range Scale in use", "nmea0183.rsd.scale",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_units,
         {"Range Units", "nmea0183.rsd.units",
          FT_CHAR, BASE_NONE,
          VALS(speed_unit_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_vrm1,
         {"Variable Range Marker 1 (VRM1)", "nmea0183.rsd.vrm1",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rsd_vrm2,
         {"VRM2", "nmea0183.rsd.vrm2",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rte_route,
         {"Route Identifier", "nmea0183.rte.route",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rte_sentence_mode,
         {"Sentence Mode", "nmea0183.rte.mode",
          FT_CHAR, BASE_NONE,
          VALS(sentence_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rte_sentence_number,
         {"Sentence Number", "nmea0183.rte.sent_number",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rte_total_sentences,
         {"Total Number of Sentences", "nmea0183.rte.num_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_rte_waypoint,
         {"Waypoint Identifier", "nmea0183.rte.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        { &hf_nmea0183_sentence_prefix,
         { "Sentence prefix", "nmea0183.sentence_prefix",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL }},
        {&hf_nmea0183_sfi_frequency,
         {"Frequency/ITU Channel (100 Hz increments)", "nmea0183.sfi.freq",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_sfi_mode,
         {"Mode of Operation", "nmea0183.sfi.mode",
          FT_CHAR, BASE_NONE,
          VALS(sfi_operation_mode_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_sfi_sentence_number,
         {"Sentence Number", "nmea0183.sfi.sent_number",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_sfi_total_sentences,
         {"Total Number of Sentences", "nmea0183.sfi.num_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ssd_callsign,
         {"Ship's Call Sign", "nmea0183.ssd.callsign",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ssd_dte_flag,
         {"DTE Indicator Flag", "nmea0183.ssd.dte",
          FT_CHAR, BASE_NONE,
          VALS(dte_indicator_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ssd_name,
         {"Ship's Name", "nmea0183.ssd.name",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ssd_ref_a,
         {"Pos. Ref. Point distance 'A' (from bow)", "nmea0183.ssd.ref_a",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ssd_ref_b,
         {"Pos. Ref. Point distance 'B' (from stern)", "nmea0183.ssd.ref_b",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ssd_ref_c,
         {"Pos. Ref. Point distance 'C' (from port beam)", "nmea0183.ssd.ref_c",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ssd_ref_d,
         {"Pos. Ref. Point distance 'D' (from starboard beam)", "nmea0183.ssd.ref_d",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ssd_source,
         {"Talker ID Number", "nmea0183.ssd.source",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_stn_talker,
         {"Talker ID Number", "nmea0183.stn.talker",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        { &hf_nmea0183_tag_block,
         { "Tag block", "nmea0183.tag_block",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL }},
        {&hf_nmea0183_tlb_label,
         {"Label Assigned to Target", "nmea0183.tlb.label",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tlb_target,
         {"Target Number", "nmea0183.tlb.tgt_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tll_ref_tgt,
         {"Reference Target", "nmea0183.tll.ref",
          FT_CHAR, BASE_NONE,
          VALS(ref_target_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tll_tgt_latitude,
         {"Target Latitude", "nmea0183.tll.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tll_tgt_longitude,
         {"Target Longitude", "nmea0183.tll.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tll_tgt_name,
         {"Target Name", "nmea0183.tll.tgt_name",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tll_utc,
         {"UTC of Data","nmea0183.tll.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tll_tgt_num,
         {"Target Number", "nmea0183.tll.tgt_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tll_tgt_status,
         {"Target Status", "nmea0183.tll.status",
          FT_CHAR, BASE_NONE,
          VALS(tgt_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_acq_type,
         {"Type of Acquisition", "nmea0183.ttm.acq",
          FT_CHAR, BASE_NONE,
          VALS(target_acq_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_bearing,
         {"Target Number", "nmea0183.ttm.bearing",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_dist_pt_approach,
         {"Target Number", "nmea0183.ttm.dist_approach",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_ref_tgt,
         {"Reference Target", "nmea0183.ttm.ref",
          FT_CHAR, BASE_NONE,
          VALS(ref_target_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_tgt_course,
         {"Target Number", "nmea0183.ttm.tgt_course",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_tgt_dist,
         {"Target Number", "nmea0183.ttm.tgt_dist",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_tgt_name,
         {"Target Name", "nmea0183.ttm.tgt_name",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_tgt_num,
         {"Target Number", "nmea0183.ttm.tgt_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_tgt_speed,
         {"Target Number", "nmea0183.ttm.tgt_speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_tgt_status,
         {"Target Status", "nmea0183.ttm.status",
          FT_CHAR, BASE_NONE,
          VALS(tgt_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_time_cpa,
         {"Target Number", "nmea0183.ttm.cpa",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_units,
         {"Speed/Distance Units", "nmea0183.ttm.units",
          FT_CHAR, BASE_NONE,
          VALS(speed_unit_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ttm_utc,
         {"UTC of Data", "nmea0183.ttm.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tut_sentence_num,
         {"Sentence Number", "nmea0183.tut.sent_number",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tut_seq_msg,
         {"Sequential Message Identifier", "nmea0183.tut.seq_msg",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tut_src_id,
         {"Source Identifier", "nmea0183.tut.source",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tut_text,
         {"Text Body", "nmea0183.tut.text",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tut_total_sentences,
         {"Total Number of Sentences", "nmea0183.tut.tot_sentences",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_tut_trans_code,
         {"Translation Code for Text Body", "nmea0183.tut.trans_code",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        { &hf_nmea0183_txt_id,
         {"Text identifier", "nmea0183.txt.id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL} },
        { &hf_nmea0183_txt_msg,
         {"Text message", "nmea0183.txt.msg",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL} },
        { &hf_nmea0183_txt_num,
         {"Total number of sentences", "nmea0183.txt.num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL} },
        { &hf_nmea0183_txt_sent_num,
         {"Sentence number", "nmea0183.txt.sent_num",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL} },
        {&hf_nmea0183_vbw_ground_speed_longitudinal,
         {"Longitudinal ground speed", "nmea0183.vbw_ground_speed_longitudinal",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Longitudinal ground speed, negative value means astern, knots", HFILL}},
        {&hf_nmea0183_vbw_ground_speed_transverse,
         {"Transverse ground speed", "nmea0183.vbw_ground_speed_transverse",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Transverse ground speed, negative value means port, knots", HFILL}},
        {&hf_nmea0183_vbw_ground_speed_valid,
         {"Ground speed validity", "nmea0183.vbw_ground_speed_valid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Ground speed status, A means data is valid", HFILL}},
        {&hf_nmea0183_vbw_stern_ground_speed,
         {"Stern ground speed", "nmea0183.vbw_stern_ground_speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Stern traverse ground ground speed, negative value means port, knots", HFILL}},
        {&hf_nmea0183_vbw_stern_ground_speed_valid,
         {"Stern ground speed validity", "nmea0183.vbw_stern_ground_speed_valid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Stern traverse ground speed status, A means data is valid", HFILL}},
        {&hf_nmea0183_vbw_stern_water_speed,
         {"Stern water speed", "nmea0183.vbw_stern_water_speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Stern traverse water ground speed, negative value means port, knots", HFILL}},
        {&hf_nmea0183_vbw_stern_water_speed_valid,
         {"Stern water speed validity", "nmea0183.vbw_stern_water_speed_valid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Stern traverse water speed status, A means data is valid", HFILL}},
        {&hf_nmea0183_vbw_water_speed_longitudinal,
         {"Longitudinal water speed", "nmea0183.vbw_water_speed_longitudinal",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Longitudinal water speed, negative value means astern, knots", HFILL}},
        {&hf_nmea0183_vbw_water_speed_transverse,
         {"Transverse water speed", "nmea0183.vbw_water_speed_transverse",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Transverse water speed, negative value means port, knots", HFILL}},
        {&hf_nmea0183_vbw_water_speed_valid,
         {"Water speed validity", "nmea0183.vbw_water_speed_valid",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VBW Water speed status, A means data is valid", HFILL}},
        {&hf_nmea0183_vdr_heading_magnetic,
         {"Direction (degrees Magnetic)", "nmea0183.vdr.magnetic",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vdr_heading_true,
         {"Direction (degrees True)", "nmea0183.vdr.true",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vdr_speed,
         {"Current Speed (knots)", "nmea0183.vdr.speed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vhw_magnetic_heading,
         {"Magnetic heading", "nmea0183.vhw_magnetic_heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vhw_magnetic_heading_unit,
         {"Heading unit", "nmea0183.vhw_magnetic_heading_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VHW Heading unit, must be M", HFILL}},
        {&hf_nmea0183_vhw_true_heading,
         {"True heading", "nmea0183.vhw_true_heading",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vhw_true_heading_unit,
         {"Heading unit", "nmea0183.vhw_true_heading_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VHW Heading unit, must be T", HFILL}},
        {&hf_nmea0183_vhw_water_speed_kilometer,
         {"Water speed", "nmea0183.vhw_water_speed_kilometer",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vhw_water_speed_kilometer_unit,
         {"Speed unit", "nmea0183.vhw_water_speed_kilometer_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VHW Water speed unit, must be K", HFILL}},
        {&hf_nmea0183_vhw_water_speed_knot,
         {"Water speed", "nmea0183.vhw_water_speed_knot",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vhw_water_speed_knot_unit,
         {"Speed unit", "nmea0183.vhw_water_speed_knot_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VHW Water speed unit, must be N", HFILL}},
        {&hf_nmea0183_vlw_cumulative_ground,
         {"Cumulative ground distance", "nmea0183.vlw_hf_nmea0183_vlw_cumulative_ground",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VLW Total cumulative ground distance, nautical miles (NMEA 3 and above)", HFILL}},
        {&hf_nmea0183_vlw_cumulative_ground_unit,
         {"Distance unit", "nmea0183.vlw_cumulative_ground_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VLW Distance unit, must be N", HFILL}},
        {&hf_nmea0183_vlw_cumulative_water,
         {"Cumulative water distance", "nmea0183.vlw_hf_nmea0183_vlw_cumulative_water",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VLW Total cumulative water distance, nautical miles", HFILL}},
        {&hf_nmea0183_vlw_cumulative_water_unit,
         {"Distance unit", "nmea0183.vlw_cumulative_water_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VLW Distance unit, must be N", HFILL}},
        {&hf_nmea0183_vlw_trip_ground,
         {"Trip ground distance", "nmea0183.vlw_hf_nmea0183_vlw_trip_ground",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VLW Ground distance since Reset, nautical miles (NMEA 3 and above)", HFILL}},
        {&hf_nmea0183_vlw_trip_ground_unit,
         {"Distance unit", "nmea0183.vlw_trip_ground_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VLW Distance unit, must be N", HFILL}},
        {&hf_nmea0183_vlw_trip_water,
         {"Trip water distance", "nmea0183.vlw_hf_nmea0183_vlw_trip_water",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VLW Water distance since Reset, nautical miles", HFILL}},
        {&hf_nmea0183_vlw_trip_water_unit,
         {"Distance unit", "nmea0183.vlw_trip_water_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VLW Distance unit, must be N", HFILL}},
        {&hf_nmea0183_vpw_speed_knots,
         {"Speed (knots)", "nmea0183.vpw.knots",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vpw_speed_ms,
         {"Speed (meters/second)", "nmea0183.vpw.ms",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_app_flags,
         {"Regional Application Flags", "nmea0183.vsd.app_flags",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_day_arrival,
         {"Estimated Day of Arrival at Destination", "nmea0183.vsd.arrival_day",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_destination,
         {"Destination", "nmea0183.vsd.dest",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_max_draught,
         {"Maximum Present Static Draught (m)", "nmea0183.vsd.draft",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_month_arrival,
         {"Estimated Month of Arrival at Destination", "nmea0183.vsd.arrival_month",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_nav_status,
         {"Navigational Status", "nmea0183.vsd.nav_status",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_persons,
         {"Persons On-board", "nmea0183.vsd.persons",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_ship_cargo,
         {"Type of Ship & Cargo Category", "nmea0183.vsd.ship_cargo",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vsd_utc_arrival,
         {"Estimated UTC of Arrival at Destination", "nmea0183.vsd.arrival_utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vtg_ground_speed_kilometer,
         {"Speed over ground", "nmea0183.vtg_ground_speed_kilometer",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vtg_ground_speed_kilometer_unit,
         {"Speed unit", "nmea0183.vtg_ground_speed_kilometer_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VTG Ground speed unit, must be K", HFILL}},
        {&hf_nmea0183_vtg_ground_speed_knot,
         {"Speed over ground", "nmea0183.vtg_ground_speed_knot",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vtg_ground_speed_knot_unit,
         {"Speed unit", "nmea0183.vtg_ground_speed_knot_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VTG Ground speed unit, must be N", HFILL}},
        {&hf_nmea0183_vtg_magnetic_course,
         {"Magnetic course over ground", "nmea0183.vtg_magnetic_course",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vtg_magnetic_course_unit,
         {"Course unit", "nmea0183.vtg_magnetic_course_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VTG Course unit, must be M", HFILL}},
        {&hf_nmea0183_vtg_mode,
         {"FAA mode", "nmea0183.vtg_mode",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VTG FAA mode indicator (NMEA 2.3 and later)", HFILL}},
        {&hf_nmea0183_vtg_true_course,
         {"True course over ground", "nmea0183.vtg_true_course",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_vtg_true_course_unit,
         {"Course unit", "nmea0183.vtg_true_course_unit",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VTG Course unit, must be T", HFILL}},
        {&hf_nmea0183_wcv_mode,
         {"Mode Indicator", "nmea0183.wcv.mode",
          FT_CHAR, BASE_NONE,
          VALS(mode_indicator), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wcv_velocity,
         {"Velocity (knots)", "nmea0183.wcv.velocity",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wcv_waypoint,
         {"Waypoint Identifier", "nmea0183.wcv.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wnc_dist_km,
         {"Distance (km)", "nmea0183.wnc.dist_km",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wnc_dist_nm,
         {"Distance (nm)", "nmea0183.wnc.dist_nm",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wnc_from_id,
         {"'FROM' Waypoint ID", "nmea0183.wnc.from_waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wnc_to_id,
         {"'TO' Waypoint ID", "nmea0183.wnc.to_waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wpl_latitude,
         {"Waypoint Latitude", "nmea0183.wpl.latitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wpl_longitude,
         {"Waypoint Longitude", "nmea0183.wpl.longitude",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_wpl_waypoint,
         {"Waypoint Identifier", "nmea0183.wpl.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xdr_data,
         {"Measurement Data", "nmea0183.xdr.data",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xdr_id,
         {"Transducer ID", "nmea0183.xdr.id",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xdr_type,
         {"Transducer Type", "nmea0183.xdr.type",
          FT_CHAR, BASE_NONE,
          VALS(transducer_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xdr_units,
         {"Units of Measure", "nmea0183.xdr.units",
          FT_CHAR, BASE_NONE,
          VALS(transducer_unit_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xte_blinksnr_status,
         {"Data Status - Loran-C Blink/SNR Warning", "nmea0183.xte.blinksnr",
          FT_CHAR, BASE_NONE,
          VALS(loranc_blink_snr_warning_vals), 0x0,
          NULL, HFILL}},
          {&hf_nmea0183_xte_cycle_status,
         {"Data Status - Loran-C Cycle Lock Warning", "nmea0183.xte.cycle_lock",
          FT_CHAR, BASE_NONE,
          VALS(loranc_cycle_lock_warning_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xte_magnitude,
         {"Magnitude of Cross-Track-Error (XTE)", "nmea0183.xte.magnitude",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xte_direction,
         {"Direction to Steer (nm)", "nmea0183.xte.steer",
          FT_CHAR, BASE_NONE,
          VALS(steer_direction), 0x0,
          NULL, HFILL}},
          {&hf_nmea0183_xte_mode,
         {"Mode Indicator", "nmea0183.xte.mode",
          FT_CHAR, BASE_NONE,
          VALS(mode_indicator), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xtr_direction,
         {"Direction to Steer (nm)", "nmea0183.xtr.steer",
          FT_CHAR, BASE_NONE,
          VALS(steer_direction), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_xtr_magnitude,
         {"Magnitude of Cross-Track-Error (XTE)", "nmea0183.xtr.magnitude",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zda_date_day,
         {"Day", "nmea0183.zda_date_day",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zda_date_month,
         {"Month", "nmea0183.zda_date_month",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zda_date_year,
         {"Year", "nmea0183.zda_date_year",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zda_local_zone_hour,
         {"Local zone hour", "nmea0183.zda_local_zone_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        { &hf_nmea0183_zda_local_zone_minute,
         {"Local zone minute", "nmea0183.zda_local_zone_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zda_time,
         {"UTC Time", "nmea0183.zda_time",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zda_time_hour,
         {"Hour", "nmea0183.zda_time_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zda_time_minute,
         {"Minute", "nmea0183.zda_time_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zda_time_second,
         {"Second", "nmea0183.zda_time_second",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zdl_dist,
         {"Distance to point (nm)", "nmea0183.zdl.dist",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zdl_time,
         {"Time to point (hours)", "nmea0183.zdl.time",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zdl_type,
         {"Type of Point", "nmea0183.zdl.type",
          FT_CHAR, BASE_NONE,
          VALS(point_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zfo_elapsed,
         {"Elapsed Time (hours)", "nmea0183.zfo.elapsed",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zfo_origin,
         {"Origin Waypoint ID", "nmea0183.zfo.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_zfo_utc,
         {"UTC of Observation", "nmea0183.zfo.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ztg_dest,
         {"Destination Waypoint ID", "nmea0183.ztg.waypoint",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ztg_time_left,
         {"Time-to-go (hours)", "nmea0183.ztg.time_left",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_ztg_utc,
         {"UTC of Observation", "nmea0183.ztg.utc",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}}
};

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_nmea0183,
        &ett_nmea0183_checksum,
        &ett_nmea0183_sentence,
        &ett_nmea0183_zda_time,
        &ett_nmea0183_alr_time,
        &ett_nmea0183_gga_time,
        &ett_nmea0183_gga_latitude,
        &ett_nmea0183_gga_longitude,
        &ett_nmea0183_gll_time,
        &ett_nmea0183_gll_latitude,
        &ett_nmea0183_gll_longitude,
        &ett_nmea0183_gst_time,
        &ett_nmea0183_tag_block,
        &ett_nmea0183_fd,
        &ett_nmea0183_legacy_satellite_info
    };

    static ei_register_info ei[] = {
        {&ei_nmea0183_invalid_first_character,
         {"nmea0183.invalid_first_character", PI_PROTOCOL, PI_WARN,
          "First character should be '$'", EXPFILL}},
        {&ei_nmea0183_missing_checksum_character,
         {"nmea0183.missing_checksum_character", PI_MALFORMED, PI_ERROR,
          "Missing begin of checksum character '*'", EXPFILL}},
        {&ei_nmea0183_invalid_end_of_line,
         {"nmea0183.invalid_end_of_line", PI_PROTOCOL, PI_WARN,
          "Sentence should end with <CR><LF>", EXPFILL}},
        {&ei_nmea0183_checksum_incorrect,
         {"nmea0183.checksum_incorrect", PI_CHECKSUM, PI_WARN,
          "Incorrect checksum", EXPFILL}},
        {&ei_nmea0183_sentence_too_long,
         {"nmea0183.sentence_too_long", PI_PROTOCOL, PI_WARN,
          "Sentence is too long. Maximum is 82 bytes including $ and <CR><LF>", EXPFILL}},
        {&ei_nmea0183_field_time_too_short,
         {"nmea0183.field_time_too_short", PI_PROTOCOL, PI_WARN,
          "Field containing time is too short. Field should be at least 6 characters", EXPFILL}},
        {&ei_nmea0183_field_latitude_too_short,
         {"nmea0183.field_latitude_too_short", PI_PROTOCOL, PI_WARN,
          "Field containing latitude is too short. Field should be at least 4 characters", EXPFILL}},
        {&ei_nmea0183_field_longitude_too_short,
         {"nmea0183.field_longitude_too_short", PI_PROTOCOL, PI_WARN,
          "Field containing longitude is too short. Field should be at least 5 characters", EXPFILL}},
        {&ei_nmea0183_field_missing,
         {"nmea0183.field_missing", PI_PROTOCOL, PI_WARN,
          "Field expected, but not found", EXPFILL}},
        {&ei_nmea0183_field_uint_invalid,
         {"nmea0183.field_uint_invalid", PI_PROTOCOL, PI_WARN,
          "Invalid unsigned integer", EXPFILL}},
        {&ei_nmea0183_sat_prn_invalid,
         {"nmea0183.sat_prn_invalid", PI_PROTOCOL, PI_WARN,
          "Invalid satellite PRN", EXPFILL}},
        {&ei_nmea0183_gga_altitude_unit_incorrect,
         {"nmea0183.gga_altitude_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect altitude unit (should be 'M')", EXPFILL}},
        {&ei_nmea0183_gga_geoidal_separation_unit_incorrect,
         {"nmea0183.gga_geoidal_separation_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect geoidal separation unit (should be 'M')", EXPFILL}},
        {&ei_nmea0183_hdt_unit_incorrect,
         {"nmea0183.hdt_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect heading unit (should be 'T')", EXPFILL}},
        {&ei_nmea0183_vhw_true_heading_unit_incorrect,
         {"nmea0183.vhw_true_heading_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect heading unit (should be 'T')", EXPFILL}},
        {&ei_nmea0183_vhw_magnetic_heading_unit_incorrect,
         {"nmea0183.vhw_magnetic_heading_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect heading unit (should be 'M')", EXPFILL}},
        {&ei_nmea0183_vhw_water_speed_knot_unit_incorrect,
         {"nmea0183.vhw_water_speed_knot_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect speed unit (should be 'N')", EXPFILL}},
        {&ei_nmea0183_vhw_water_speed_kilometer_unit_incorrect,
         {"nmea0183.vhw_water_speed_kilometer_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect speed unit (should be 'K')", EXPFILL}},
        {&ei_nmea0183_vlw_cumulative_water_unit_incorrect,
         {"nmea0183.vlw_cumulative_water_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect distance unit (should be 'N')", EXPFILL}},
        {&ei_nmea0183_vlw_trip_water_unit_incorrect,
         {"nmea0183.vlw_trip_water_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect distance unit (should be 'N')", EXPFILL}},
        {&ei_nmea0183_vlw_cumulative_ground_unit_incorrect,
         {"nmea0183.vlw_cumulative_ground_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect distance unit (should be 'N')", EXPFILL}},
        {&ei_nmea0183_vlw_trip_ground_unit_incorrect,
         {"nmea0183.vlw_trip_ground_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect distance unit (should be 'N')", EXPFILL}},
        {&ei_nmea0183_vtg_true_course_unit_incorrect,
         {"nmea0183.vtg_true_course_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect course unit (should be 'T')", EXPFILL}},
        {&ei_nmea0183_vtg_magnetic_course_unit_incorrect,
         {"nmea0183.vtg_magnetic_course_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect course unit (should be 'M')", EXPFILL}},
        {&ei_nmea0183_vtg_ground_speed_knot_unit_incorrect,
         {"nmea0183.vtg_ground_speed_knot_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect speed unit (should be 'N')", EXPFILL}},
        {&ei_nmea0183_vtg_ground_speed_kilometer_unit_incorrect,
         {"nmea0183.vtg_ground_speed_kilometer_unit_incorrect", PI_PROTOCOL, PI_WARN,
          "Incorrect speed unit (should be 'K')", EXPFILL}},
        {&ei_nmea0183_legacy_nonstandard,
         {"nmea0183.legacy.nonstandard", PI_PROTOCOL, PI_WARN,
          "Non-standard field value", EXPFILL}},
        {&ei_nmea0183_legacy_empty_response,
         {"nmea0183.legacy.empty_response", PI_RESPONSE_CODE, PI_WARN,
          "Empty response", EXPFILL}}};

    proto_nmea0183 = proto_register_protocol("NMEA 0183 protocol", "NMEA 0183", "nmea0183");
    proto_nmea0183_bin = proto_register_protocol("NMEA 0183 binary protocol", "NMEA 0183 BIN", "nmea0183_bin");

    proto_register_field_array(proto_nmea0183, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_nmea0183 = expert_register_protocol(proto_nmea0183);
    expert_register_field_array(expert_nmea0183, ei, array_length(ei));

    nmea0183_handle = register_dissector("nmea0183", dissect_nmea0183, proto_nmea0183);
}

void proto_reg_handoff_nmea0183(void)
{
    /* Register the UDP PDU NMEA0183 handle for heuristic dissection */
    heur_dissector_add("udp", dissect_nmea0183_heur, "NMEA0183 over UDP",
                       "nmea0183_udp", proto_nmea0183, HEURISTIC_DISABLE);
    dissector_add_for_decode_as_with_preference("udp.port", nmea0183_handle);
}
