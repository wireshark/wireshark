/* packet-stanag4607.c
 * Routines for STANAG 4607 dissection
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <math.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include <wiretap/stanag4607.h>

void proto_register_stanag4607(void);
void proto_reg_handoff_stanag4607(void);

static int proto_stanag4607;

static int hf_4607_version;
static int hf_4607_version_edition;
static int hf_4607_version_version;
static int hf_4607_packet_size;
static int hf_4607_nationality;
static int hf_4607_sec_class;
static int hf_4607_sec_system;
static int hf_4607_sec_code;
static int hf_4607_exercise_indicator;
static int hf_4607_platform_id;
static int hf_4607_mission_id;
static int hf_4607_job_id;

static int hf_4607_segment_type;
static int hf_4607_segment_size;

/* Mission Segment */
static int hf_4607_mission_plan;
static int hf_4607_mission_flight_plan;
static int hf_4607_mission_platform;
static int hf_4607_mission_platform_config;
static int hf_4607_mission_time_year;
static int hf_4607_mission_time_month;
static int hf_4607_mission_time_day;

/* Dwell Segment */
static int hf_4607_dwell_mask;
static int hf_4607_dwell_mask_7_7;
static int hf_4607_dwell_mask_7_6;
static int hf_4607_dwell_mask_7_5;
static int hf_4607_dwell_mask_7_4;
static int hf_4607_dwell_mask_7_3;
static int hf_4607_dwell_mask_7_2;
static int hf_4607_dwell_mask_7_1;
static int hf_4607_dwell_mask_7_0;
static int hf_4607_dwell_mask_6_7;
static int hf_4607_dwell_mask_6_6;
static int hf_4607_dwell_mask_6_5;
static int hf_4607_dwell_mask_6_4;
static int hf_4607_dwell_mask_6_3;
static int hf_4607_dwell_mask_6_2;
static int hf_4607_dwell_mask_6_1;
static int hf_4607_dwell_mask_6_0;
static int hf_4607_dwell_mask_5_7;
static int hf_4607_dwell_mask_5_6;
static int hf_4607_dwell_mask_5_5;
static int hf_4607_dwell_mask_5_4;
static int hf_4607_dwell_mask_5_3;
static int hf_4607_dwell_mask_5_2;
static int hf_4607_dwell_mask_5_1;
static int hf_4607_dwell_mask_5_0;
static int hf_4607_dwell_mask_4_7;
static int hf_4607_dwell_mask_4_6;
static int hf_4607_dwell_mask_4_5;
static int hf_4607_dwell_mask_4_4;
static int hf_4607_dwell_mask_4_3;
static int hf_4607_dwell_mask_4_2;
static int hf_4607_dwell_mask_4_1;
static int hf_4607_dwell_mask_4_0;
static int hf_4607_dwell_mask_3_7;
static int hf_4607_dwell_mask_3_6;
static int hf_4607_dwell_mask_3_5;
static int hf_4607_dwell_mask_3_4;
static int hf_4607_dwell_mask_3_3;
static int hf_4607_dwell_mask_3_2;
static int hf_4607_dwell_mask_3_1;
static int hf_4607_dwell_mask_3_0;
static int hf_4607_dwell_mask_2_7;
static int hf_4607_dwell_mask_2_6;
static int hf_4607_dwell_mask_2_5;
static int hf_4607_dwell_mask_2_4;
static int hf_4607_dwell_mask_2_3;
static int hf_4607_dwell_mask_2_2;
static int hf_4607_dwell_mask_2_1;
static int hf_4607_dwell_mask_2_0;
static int hf_4607_dwell_mask_spare;

static int hf_4607_dwell_revisit_index;
static int hf_4607_dwell_dwell_index;
static int hf_4607_dwell_last_dwell;
static int hf_4607_dwell_count;
static int hf_4607_dwell_time;
static int hf_4607_dwell_sensor_lat;
static int hf_4607_dwell_sensor_lon;
static int hf_4607_dwell_sensor_alt;
static int hf_4607_dwell_scale_lat;
static int hf_4607_dwell_scale_lon;
static int hf_4607_dwell_unc_along;
static int hf_4607_dwell_unc_cross;
static int hf_4607_dwell_unc_alt;
static int hf_4607_dwell_track;
static int hf_4607_dwell_speed;
static int hf_4607_dwell_vert_velocity;
static int hf_4607_dwell_track_unc;
static int hf_4607_dwell_speed_unc;
static int hf_4607_dwell_vv_unc;

static int hf_4607_dwell_plat_heading;
static int hf_4607_dwell_plat_pitch;
static int hf_4607_dwell_plat_roll;
static int hf_4607_dwell_da_lat;
static int hf_4607_dwell_da_lon;
static int hf_4607_dwell_da_range;
static int hf_4607_dwell_da_angle;
static int hf_4607_dwell_sensor_heading;
static int hf_4607_dwell_sensor_pitch;
static int hf_4607_dwell_sensor_roll;
static int hf_4607_dwell_mdv;

/* Target Report */
static int hf_4607_dwell_report_index;
static int hf_4607_dwell_report_lat;
static int hf_4607_dwell_report_lon;
static int hf_4607_dwell_report_delta_lat;
static int hf_4607_dwell_report_delta_lon;
static int hf_4607_dwell_report_height;
static int hf_4607_dwell_report_radial;
static int hf_4607_dwell_report_wrap;
static int hf_4607_dwell_report_snr;
static int hf_4607_dwell_report_class;
static int hf_4607_dwell_report_prob;
static int hf_4607_dwell_report_unc_slant;
static int hf_4607_dwell_report_unc_cross;
static int hf_4607_dwell_report_unc_height;
static int hf_4607_dwell_report_unc_radial;
static int hf_4607_dwell_report_tag_app;
static int hf_4607_dwell_report_tag_entity;
static int hf_4607_dwell_report_section;

/* Job Definition Segment */
static int hf_4607_jobdef_job_id;
static int hf_4607_jobdef_sensor_type;
static int hf_4607_jobdef_sensor_model;
static int hf_4607_jobdef_filter;
static int hf_4607_jobdef_priority;
static int hf_4607_jobdef_ba_lat_a;
static int hf_4607_jobdef_ba_lon_a;
static int hf_4607_jobdef_ba_lat_b;
static int hf_4607_jobdef_ba_lon_b;
static int hf_4607_jobdef_ba_lat_c;
static int hf_4607_jobdef_ba_lon_c;
static int hf_4607_jobdef_ba_lat_d;
static int hf_4607_jobdef_ba_lon_d;
static int hf_4607_jobdef_radar_mode;
static int hf_4607_jobdef_revisit_interval;
static int hf_4607_jobdef_unc_along;
static int hf_4607_jobdef_unc_cross;
static int hf_4607_jobdef_unc_alt;
static int hf_4607_jobdef_unc_heading;
static int hf_4607_jobdef_unc_speed;
static int hf_4607_jobdef_sense_slant;
static int hf_4607_jobdef_sense_cross;
static int hf_4607_jobdef_sense_vlos;
static int hf_4607_jobdef_sense_mdv;
static int hf_4607_jobdef_sense_prob;
static int hf_4607_jobdef_sense_alarm;
static int hf_4607_jobdef_terrain_model;
static int hf_4607_jobdef_geoid_model;

/* Platform Location Segment */
static int hf_4607_platloc_time;
static int hf_4607_platloc_latitude;
static int hf_4607_platloc_longitude;
static int hf_4607_platloc_altitude;
static int hf_4607_platloc_track;
static int hf_4607_platloc_speed;
static int hf_4607_platloc_vertical_velocity;

/* Subtree pointers */
static int ett_4607_hdr;
static int ett_4607_seg;
static int ett_4607_rpt;
static int ett_4607_mask;
static int ett_4607_ver;

/* Error pointers */
static expert_field ei_bad_length;
static expert_field ei_too_short;
static expert_field ei_bad_packet_size;
static expert_field ei_job_id_zero;

static dissector_handle_t stanag4607_handle;


static const value_string stanag4607_class_vals[] = {
	{   1, "TOP SECRET" },
	{   2, "SECRET" },
	{   3, "CONFIDENTIAL" },
	{   4, "RESTRICTED" },
	{   5, "UNCLASSIFIED" },
	{ 0, NULL }
};

static const value_string stanag4607_security_codes_vals[] = {
	{ 0x0000, "NONE (NO-STATEMENT VALUE)" },
	{ 0x0001, "EU (Releasable To European Commission)" },
	{ 0x0002, "EUFOR (Releasable To European Union Force)" },
	{ 0x0004, "ISAF (Releasable To International Security Assistance Force)" },
	{ 0x0008, "KFOR (Releasable To Kosovo Force)" },
	{ 0x0010, "NATO RESPONSE FORCE (Releaseable to NRF)" },
	{ 0x0020, "NMI (Releasable To NATO Mission Iraq)" },
	{ 0x0040, "PFP (Releasable To Partnership for Peace)" },
	{ 0x0080, "RESOLUTE SUPPORT (Releasable To RS)" },
	{ 0x0100, "THE PUBLIC (Releasable To The Public)" },
	{ 0x0200, "UNDEFINED. FOR FUTURE USE" },
	{ 0x0400, "UNDEFINED. FOR FUTURE USE" },
	{ 0x0800, "UNDEFINED. FOR FUTURE USE" },
	{ 0x1000, "UNDEFINED. FOR FUTURE USE" },
	{ 0x2000, "UNDEFINED. FOR FUTURE USE" },
	{ 0x4000, "UNDEFINED. FOR FUTURE USE" },
	{ 0x8000, "UNDEFINED. FOR FUTURE USE" },
	{ 0, NULL }
};

static const value_string stanag4607_exind_vals[] = {
	{   0, "Operation, Real Data" },
	{   1, "Operation, Simulated Data" },
	{   2, "Operation, Synthesized Data" },
	{   128, "Exercise, Real Data" },
	{   129, "Exercise, Simulated Data" },
	{   130, "Exercise, Synthesized Data" },
	{ 0, NULL }
};

#define MISSION_SEGMENT 1
#define DWELL_SEGMENT 2
#define JOB_DEFINITION_SEGMENT 5
#define PLATFORM_LOCATION_SEGMENT 13

static const value_string stanag4607_segment_vals[] = {
	{   1, "Mission Segment" },
	{   2, "Dwell Segment" },
	{   3, "HRR Segment" },
	{   5, "Job Definition Segment" },
	{   6, "Free Text Segment" },
	{   7, "Low Reflectivity Index Segment" },
	{   8, "Group Segment" },
	{   9, "Attached Target Segment" },
	{  10, "Test and Status Segment" },
	{  11, "System-Specific Segment" },
	{  12, "Processing History Segment" },
	{  13, "Platform Location Segment" },
	{  101, "Job Request Segment" },
	{  102, "Job Acknowledgment Segment" },
	{ 0, NULL }
};

static const value_string stanag4607_sensor_vals[] = {
	{   0, "Unidentified" },
	{   1, "Other" },
	{   2, "HiSAR" },
	{   3, "ASTOR" },
	{   4, "Rotary Wing Radar" },
	{   5, "Global Hawk Sensor" },
	{   6, "HORIZON" },
	{   7, "APY-3" },
	{   8, "APY-6" },
	{   9, "APY-8 (Lynx I)" },
	{  10, "RADARSAT2" },
	{  11, "ASARS-2A" },
	{  12, "TESAR" },
	{  13, "MP-RTIP" },
	{  14, "APG-77" },
	{  15, "APG-79" },
	{  16, "APG-81" },
	{  17, "APY-6v1" },
	{  18, "SPY-I (Lynx II)" },
	{  19, "SIDM" },
	{  20, "LIMIT" },
	{  21, "TCAR (AGS A321)" },
	{  22, "LSRS Sensor" },
	{  23, "UGS Single Sensor" },
	{  24, "UGS Cluster Sensor" },
	{  25, "IMASTER GMTI" },
	{  26, "AN/ZPY-1 (STARLite)" },
	{  27, "VADER" },
	{  255, "No Statement" },
	{ 0, NULL }
};

static const value_string stanag4607_radar_mode_vals[] = {
	{   0, "Unspecified Mode" },
	{   1, "MTI (Moving Target Indicator)" },
	{   2, "HRR (High Range Resolution)" },
	{   3, "UHRR (Ultra High Range Resolution)" },
	{   4, "HUR (High Update Rate)" },
	{   5, "FTI" },
	/* TODO: and many many more ... */
	{ 0, NULL }
};

static const value_string stanag4607_terrain_vals[] = {
	{   0, "None Specified" },
	{   1, "DTED0 (Digital Terrain Elevation Data, Level 0)" },
	{   2, "DTED1 (Digital Terrain Elevation Data, Level 1)" },
	{   3, "DTED2 (Digital Terrain Elevation Data, Level 2)" },
	{   4, "DTED3 (Digital Terrain Elevation Data, Level 3)" },
	{   5, "DTED4 (Digital Terrain Elevation Data, Level 4)" },
	{   6, "DTED5 (Digital Terrain Elevation Data, Level 5)" },
	{   7, "SRTM1 (Shuttle Radar Topography Mission, Level 1)" },
	{   8, "SRTM2 (Shuttle Radar Topography Mission, Level 2)" },
	{   9, "DGM50 M745 (Digitales Gelandemodell 1:50 000)" },
	{   10, "DGM250 (Digitales Gelandemodell 1:250 000)" },
	{   11, "ITHD (Interferometric Terrain Data Height)" },
	{   12, "STHD (Stereometric Terrain Data Height)" },
	{   13, "SEDRIS (SEDRIS Reference Model ISO/IEC 18026)" },
	{ 0, NULL }
};

static const value_string stanag4607_geoid_vals[] = {
	{   0, "None Specified" },
	{   1, "EGM96 (Earth Gravitational Model, Version 1996)" },
	{   2, "GEO96 (Geoid Gravitational Model, Version 1996)" },
	{   3, "Flat Earth" },
	{ 0, NULL }
};

static const value_string stanag4607_target_vals[] = {
	{   0, "No Information, Live Target" },
	{   1, "Tracked Vehicle, Live Target" },
	{   2, "Wheeled Vehicle, Live Target" },
	{   3, "Rotary Wing Aircraft, Live Target" },
	{   4, "Fixed Wing Aircraft, Live Target" },
	{   5, "Stationary Rotator, Live Target" },
	{   6, "Maritime, Live Target" },
	{   7, "Beacon, Live Target" },
	{   8, "Amphibious, Live Target" },
	{   9, "Person, Live Target" },
	{   10, "Vehicle, Live Target" },
	{   11, "Animal, Live Target" },
	{   12, "Large Multiple-Return, Live Land Target" },
	{   13, "Large Multiple-Return, Live Maritime Target" },

	{   126, "Other, Live Target" },
	{   127, "Unknown, Live Target" },
	{   128, "No Information, Simulated Target" },
	{   129, "Tracked Vehicle, Simulated Target" },
	{   130, "Wheeled Vehicle, Simulated Target" },
	{   131, "Rotary Wing Aircraft, Simulated Target" },
	{   132, "Fixed Wing Aircraft, Simulated Target" },
	{   133, "Stationary Rotator, Simulated Target" },
	{   134, "Maritime, Simulated Target" },
	{   135, "Beacon, Simulated Target" },
	{   136, "Amphibious, Simulated Target" },
	{   137, "Person, Simulated Target" },
	{   138, "Vehicle, Simulated Target" },
	{   139, "Animal, Simulated Target" },
	{   140, "Large Multiple-Return, Simulated Land Target" },
	{   141, "Large Multiple-Return, Simulated Maritime Target" },

	{   143, "Tagging Device" },

	{   254, "Other, Simulated Target" },
	{   255, "Unknown, Simulated Target" },
	{ 0, NULL }
};

static const value_string stanag4607_platform_vals[] = {
	{   0, "Unidentified" },
	{   1, "ACS" },
	{   2, "ARL-M" },
	{   3, "Sentinel" },
	{   4, "Rotary Wing Radar" },
	{   5, "Global Hawk-Navy" },
	{   6, "HORIZON" },
	{   7, "E-8C (Joint STARS)" },
	{   8, "P-3C" },
	{   9, "Predator" },
	{  10, "RADARSAT2" },
	{  11, "U-2" },
	{  12, "E-10" },
	{  13, "UGS - Single" },
	{  14, "UGS - Cluster" },
	{  15, "Ground Based" },
	{  16, "UAV-Army" },
	{  17, "UAV-Marines" },
	{  18, "UAV-Navy" },
	{  19, "UAV-Air Force" },
	{  20, "Global Hawk-Air Force" },
	{  21, "Global Hawk-Australia" },
	{  22, "Global Hawk-Germany" },
	{  23, "Paul Revere" },
	{  24, "Mariner UAV" },
	{  25, "BAC-111" },
	{  26, "Coyote" },
	{  27, "King Air" },
	{  28, "LIMIT" },
	{  29, "NRL NP-3B" },
	{  30, "SOSTAR-X" },
	{  31, "WatchKeeper" },
	{  32, "Alliance Ground Surveillance (AGS) (A321)" },
	{  33, "Stryker" },
	{  34, "AGS (HALE UAV)" },
	{  35, "SIDM" },
	{  36, "MQ-9 Reaper" },
	{  37, "Warrior A" },
	{  38, "Warrior" },
	{  39, "Twin Otter" },
	{  40, "LEMV" },
	{  41, "P8A Poseidon" },
	{  42, "A160" },
	{  43, "MQ-1C Gray Eagle" },
	{  44, "RQ-7C Shadow" },
	{  45, "PGSS" },
	{  46, "PTDS" },
	{  47, "LRAS 3" },
	{  48, "RAID Tower" },
	{  49, "Heron" },
	{  50, "Scan Eagle" },
	{  51, "Fire Scout" },
	{  52, "F35 Joint Strike Fighter" },
	{  53, "F-61 Sea King (SKASac)" },
	{  54, "Lynx Wildcat" },
	{  55, "Merlin" },
	{  56, "SDT (Système de Drone Tactique)" },
	{  255, "Other" },
	{  0, NULL }
};

static void
prt_sa32(char *buff, uint32_t val)
{
	double deg, min, sec;
	double x = (double) ((int32_t) val);
	x /= (double) (1UL<<30);
	x *= 45.0;
	deg = floor(x);
	min = floor(60.0 * (x - deg));
	sec = 60.0 * (60.0 * (x - deg) - min);
	/* checkAPI.pl doesn't like the unicode degree symbol, I don't know what to do... */
	snprintf(buff, ITEM_LABEL_LENGTH, "%.8f degrees (%.0f %.0f\' %.2f\")", x, deg, min, sec);
}

static void
prt_ba32(char *buff, uint32_t val)
{
	double deg, min, sec;
	double x = (double) val;
	x /= (double) (1UL<<30);
	x *= 90.0;
	deg = floor(x);
	min = floor(60.0 * (x - deg));
	sec = 60.0 * (60.0 * (x - deg) - min);
	/* checkAPI.pl doesn't like the unicode degree symbol, I don't know what to do... */
	snprintf(buff, ITEM_LABEL_LENGTH, "%.8f degrees (%.0f %.0f\' %.2f\")", x, deg, min, sec);
}

static void
prt_sa16(char *buff, uint32_t val)
{
	double x = (double) ((int32_t) val);
	x /= (double) (1<<14);
	x *= 90.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.3f degrees", x);
}

static void
prt_ba16(char *buff, uint32_t val)
{
	double x = (double) val;
	x /= (double) (1<<14);
	x *= 90.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.3f degrees", x);
}

static void
prt_ba16_none(char *buff, uint32_t val)
{
	double x = (double) val;
	x /= (double) (1<<14);
	x *= 90.0;
	if (val <= 65536)
		snprintf(buff, ITEM_LABEL_LENGTH, "No Statement");
	else
		snprintf(buff, ITEM_LABEL_LENGTH, "%.3f degrees", x);
}

static void
prt_kilo(char *buff, uint32_t val)
{
	double x = (double) ((int32_t) val);
	x /= 128.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.2f kilometers", x);
}

static void
prt_meters(char *buff, uint32_t val)
{
	double x = (double) ((int32_t) val);
	snprintf(buff, ITEM_LABEL_LENGTH, "%.0f meters", x);
}

static void
prt_decimeters(char *buff, uint32_t val)
{
	double x = (double) ((int32_t) val);
	x /= 10.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.1f meters", x);
}

static void
prt_centimeters(char *buff, uint32_t val)
{
	double x = (double) ((int32_t) val);
	x /= 100.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.2f meters", x);
}

static void
prt_speed(char *buff, uint32_t val)
{
	double x = (double) val;
	x /= 1000.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.3f meters/second", x);
}

static void
prt_speed_centi(char *buff, uint32_t val)
{
	double x = (double) ((int32_t) val);
	x /= 100.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.2f meters/second", x);
}

static void
prt_speed_deci(char *buff, uint32_t val)
{
	/* Usually 8-bit, signed */
	double x = (double) ((int32_t) val);
	x /= 10.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.1f meters/second", x);
}

static void
prt_millisec(char *buff, uint32_t val)
{
	double x = (double) val;
	x /= 1000.0;
	snprintf(buff, ITEM_LABEL_LENGTH, "%.3f seconds", x);
}

static void
prt_none8(char *buff, uint32_t val)
{
	if (0xff == val)
		snprintf(buff, ITEM_LABEL_LENGTH, "No Statement");
	else
		snprintf(buff, ITEM_LABEL_LENGTH, "%d", val);
}

static void
prt_none16(char *buff, uint32_t val)
{
	if (0xffff == val)
		snprintf(buff, ITEM_LABEL_LENGTH, "No Statement");
	else
		snprintf(buff, ITEM_LABEL_LENGTH, "%d", val);
}


static int
dissect_mission(tvbuff_t *tvb, proto_tree *seg_tree, int offset)
{
	proto_tree_add_item(seg_tree, hf_4607_mission_plan, tvb, offset, 12, ENC_ASCII);
	offset += 12;
	proto_tree_add_item(seg_tree, hf_4607_mission_flight_plan, tvb, offset, 12, ENC_ASCII);
	offset += 12;
	proto_tree_add_item(seg_tree, hf_4607_mission_platform, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_mission_platform_config, tvb, offset, 10, ENC_ASCII);
	offset += 10;
	proto_tree_add_item(seg_tree, hf_4607_mission_time_year, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_mission_time_month, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_mission_time_day, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	return offset;
}

/* Dwell Segment Existence Mask */
/* The Dxx fields are NOT bit locations! They are the field numbers
 * as specified in Table 2-4 Dwell Segment.  These field numbers DO NOT
 * count bit locations in the existence mask (even though they come
 * close to this).  The m and n values of the m*8+n offset below are
 * given in Figure 2-1 titled "Dwell Segment Existence Mask Mapping."
 */
#define SET(MASK,OFF) (((MASK)>>(OFF)) & INT64_C(1))
#define D2      7*8+7
#define D3      7*8+6
#define D4      7*8+5
#define D5      7*8+4
#define D6      7*8+3
#define D7      7*8+2
#define D8      7*8+1
#define D9      7*8+0
#define D10     6*8+7
#define D11     6*8+6
#define D12     6*8+5
#define D13     6*8+4
#define D14     6*8+3
#define D15     6*8+2
#define D16     6*8+1
#define D17     6*8+0
#define D18     5*8+7
#define D19     5*8+6
#define D20     5*8+5
#define D21     5*8+4
#define D22     5*8+3
#define D23     5*8+2
#define D24     5*8+1
#define D25     5*8+0
#define D26     4*8+7
#define D27     4*8+6
#define D28     4*8+5
#define D29     4*8+4
#define D30     4*8+3
#define D31     4*8+2
#define D32_1   4*8+1
#define D32_2   4*8+0
#define D32_3   3*8+7
#define D32_4   3*8+6
#define D32_5   3*8+5
#define D32_6   3*8+4
#define D32_7   3*8+3
#define D32_8   3*8+2
#define D32_9   3*8+1
#define D32_10  3*8+0
#define D32_11  2*8+7
#define D32_12  2*8+6
#define D32_13  2*8+5
#define D32_14  2*8+4
#define D32_15  2*8+3
#define D32_16  2*8+2
#define D32_17  2*8+1
#define D32_18  2*8+0

/* Target Report */
static int
dissect_target(tvbuff_t *tvb, proto_tree *seg_tree, int offset, uint64_t mask)
{
	proto_item *rpt_item = NULL;
	proto_tree *rpt_tree = seg_tree;

	if (SET(mask, D32_1)) {
		rpt_item = proto_tree_add_item(rpt_tree, hf_4607_dwell_report_index, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		rpt_tree = proto_item_add_subtree(rpt_item, ett_4607_rpt);
	}

	if (SET(mask, D32_2)) {
		rpt_item = proto_tree_add_item(rpt_tree, hf_4607_dwell_report_lat, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (SET(mask, D32_3)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_lon, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (SET(mask, D32_4)) {
		rpt_item = proto_tree_add_item(rpt_tree, hf_4607_dwell_report_delta_lat, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D32_5)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_delta_lon, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	/* If the report index wasn't set, then no subtree yet */
	if (rpt_item && rpt_tree == seg_tree) {
		rpt_tree = proto_item_add_subtree(rpt_item, ett_4607_rpt);
	}
	if (SET(mask, D32_6)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_height, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D32_7)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_radial, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D32_8)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_wrap, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D32_9)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_snr, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (SET(mask, D32_10)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_class, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (SET(mask, D32_11)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_prob, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (SET(mask, D32_12)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_unc_slant, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D32_13)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_unc_cross, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D32_14)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_unc_height, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (SET(mask, D32_15)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_unc_radial, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D32_16)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_tag_app, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (SET(mask, D32_17)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_tag_entity, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (SET(mask, D32_18)) {
		proto_tree_add_item(rpt_tree, hf_4607_dwell_report_section, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}

	return offset;
}

/* Dwell Segment */
static int
dissect_dwell(tvbuff_t *tvb, proto_tree *seg_tree, int offset)
{
	uint64_t mask;
	uint32_t count;

	mask = tvb_get_ntoh64(tvb, offset);

	static int* const mask_bits[] = {
            &hf_4607_dwell_mask_7_7,
			&hf_4607_dwell_mask_7_6,
			&hf_4607_dwell_mask_7_5,
			&hf_4607_dwell_mask_7_4,
			&hf_4607_dwell_mask_7_3,
			&hf_4607_dwell_mask_7_2,
			&hf_4607_dwell_mask_7_1,
			&hf_4607_dwell_mask_7_0,
			&hf_4607_dwell_mask_6_7,
			&hf_4607_dwell_mask_6_6,
			&hf_4607_dwell_mask_6_5,
			&hf_4607_dwell_mask_6_4,
			&hf_4607_dwell_mask_6_3,
			&hf_4607_dwell_mask_6_2,
			&hf_4607_dwell_mask_6_1,
			&hf_4607_dwell_mask_6_0,
			&hf_4607_dwell_mask_5_7,
			&hf_4607_dwell_mask_5_6,
			&hf_4607_dwell_mask_5_5,
			&hf_4607_dwell_mask_5_4,
			&hf_4607_dwell_mask_5_3,
			&hf_4607_dwell_mask_5_2,
			&hf_4607_dwell_mask_5_1,
			&hf_4607_dwell_mask_5_0,
			&hf_4607_dwell_mask_4_7,
			&hf_4607_dwell_mask_4_6,
			&hf_4607_dwell_mask_4_5,
			&hf_4607_dwell_mask_4_4,
			&hf_4607_dwell_mask_4_3,
			&hf_4607_dwell_mask_4_2,
			&hf_4607_dwell_mask_4_1,
			&hf_4607_dwell_mask_4_0,
			&hf_4607_dwell_mask_3_7,
			&hf_4607_dwell_mask_3_6,
			&hf_4607_dwell_mask_3_5,
			&hf_4607_dwell_mask_3_4,
			&hf_4607_dwell_mask_3_3,
			&hf_4607_dwell_mask_3_2,
			&hf_4607_dwell_mask_3_1,
			&hf_4607_dwell_mask_3_0,
			&hf_4607_dwell_mask_2_7,
			&hf_4607_dwell_mask_2_6,
			&hf_4607_dwell_mask_2_5,
			&hf_4607_dwell_mask_2_4,
			&hf_4607_dwell_mask_2_3,
			&hf_4607_dwell_mask_2_2,
			&hf_4607_dwell_mask_2_1,
			&hf_4607_dwell_mask_2_0,
			&hf_4607_dwell_mask_spare,
            NULL
        };
	proto_tree_add_bitmask(seg_tree, tvb, offset, hf_4607_dwell_mask, ett_4607_mask, mask_bits, ENC_BIG_ENDIAN);
	offset += 8;

	/* Mandatory fields, existence mask irrelevant */
	proto_tree_add_item(seg_tree, hf_4607_dwell_revisit_index, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(seg_tree, hf_4607_dwell_dwell_index, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(seg_tree, hf_4607_dwell_last_dwell, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* count of target reports */
	count = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(seg_tree, hf_4607_dwell_count, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(seg_tree, hf_4607_dwell_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(seg_tree, hf_4607_dwell_sensor_lat, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(seg_tree, hf_4607_dwell_sensor_lon, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(seg_tree, hf_4607_dwell_sensor_alt, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Optional or conditional fields, in accordance to presence mask */
	if (SET(mask, D10)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_scale_lat, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (SET(mask, D11)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_scale_lon, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (SET(mask, D12)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_unc_along, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (SET(mask, D13)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_unc_cross, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (SET(mask, D14)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_unc_alt, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D15)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_track, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D16)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (SET(mask, D17)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_vert_velocity, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (SET(mask, D18)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_track_unc, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (SET(mask, D19)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_speed_unc, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D20)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_vv_unc, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D21)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_plat_heading, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D22)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_plat_pitch, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D23)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_plat_roll, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	/* Dwell Area */
	/* Mandatory fields, existence mask irrelevant */
	proto_tree_add_item(seg_tree, hf_4607_dwell_da_lat, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(seg_tree, hf_4607_dwell_da_lon, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(seg_tree, hf_4607_dwell_da_range, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(seg_tree, hf_4607_dwell_da_angle, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Optional or conditional fields, in accordance to presence mask */
	if (SET(mask, D28)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_sensor_heading, tvb, offset, 2, ENC_BIG_ENDIAN);
	}
	if (SET(mask, D29)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_sensor_pitch, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D30)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_sensor_roll, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (SET(mask, D31)) {
		proto_tree_add_item(seg_tree, hf_4607_dwell_mdv, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}

	while (count--) {
		offset = dissect_target(tvb, seg_tree, offset, mask);
	}

	return offset;
}

/* Job Definition */
static int
dissect_jobdef(tvbuff_t *tvb, proto_tree *seg_tree, int offset)
{
	proto_tree_add_item(seg_tree, hf_4607_jobdef_job_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_sensor_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_sensor_model, tvb, offset, 6, ENC_ASCII);
	offset += 6;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_filter, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_ba_lat_a, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_ba_lon_a, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_ba_lat_b, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_ba_lon_b, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_ba_lat_c, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_ba_lon_c, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_ba_lat_d, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_ba_lon_d, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_radar_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_revisit_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_unc_along, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_unc_cross, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_unc_alt, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_unc_heading, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_unc_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_sense_slant, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_sense_cross, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_sense_vlos, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_sense_mdv, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_sense_prob, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_sense_alarm, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_terrain_model, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(seg_tree, hf_4607_jobdef_geoid_model, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	return offset;
}

static int
dissect_platform_location(tvbuff_t *tvb, proto_tree *seg_tree, int offset)
{
	proto_tree_add_item(seg_tree, hf_4607_platloc_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_platloc_latitude, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_platloc_longitude, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_platloc_altitude, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_platloc_track, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(seg_tree, hf_4607_platloc_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(seg_tree, hf_4607_platloc_vertical_velocity, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	return offset;
}

/* 32 == packet header, 5 == segment type and length */
#define STANAG4607_MIN_LENGTH (32+5)

#define MINIMUM_SEGMENT_SIZE 14
#define MISSION_SEGMENT_SIZE 44
#define JOB_DEFINITION_SEGMENT_SIZE 73
#define PLATFORM_LOCATION_SEGMENT_SIZE 28

/* Provide a basic sanity check on segment sizes; the fixed-length
 * ones should be what they claim to be.
 */
#define CHK_SIZE(SEG_TYPE) \
	if (SEG_TYPE##_SIZE != seg_size) { \
		col_append_str(pinfo->cinfo, COL_INFO, ", Error: Invalid segment size "); \
		expert_add_info(pinfo, pi, &ei_bad_length); \
	}

static int
dissect_stanag4607(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	uint32_t offset = 0;
	int8_t first_segment;

	uint32_t pkt_size = 0, job_id;
	proto_item *ti, *seg_type, *pver, *pedition;
	proto_tree *hdr_tree, *seg_tree, *ver_tree;
	uint8_t seg_id = 0;

	/* Basic length check */
	if (tvb_captured_length(tvb) < STANAG4607_MIN_LENGTH)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "S4607");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Put type of first segment in the info column */
	first_segment = tvb_get_uint8(tvb, 32);
	col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str(first_segment, stanag4607_segment_vals, "Unknown (0x%02x)"));

	/* Put the timestamp, if available in the time column */
	if (PLATFORM_LOCATION_SEGMENT == first_segment) {
		uint32_t millisecs;
		nstime_t ts;
		millisecs = tvb_get_ntohl(tvb, 37);
		ts.secs = millisecs / 1000;
		ts.nsecs = (int)((millisecs - 1000 * ts.secs) * 1000000);
		col_set_time(pinfo->cinfo, COL_REL_TIME, &ts, "s4607.ploc.time");
	}

	/* The generic packet header */
	ti = proto_tree_add_item(tree, proto_stanag4607, tvb, 0, -1, ENC_NA);
	hdr_tree = proto_item_add_subtree(ti, ett_4607_hdr);

	/* Version is in format mn (ASCII) where m reflects edition and n version

	   m="4" equates to A, m="5" equates to B, and so on
	   n is the direct alphanumeric representation

	   Note: STANAG 4607 has numbers up to 3 (Edition 3 Rev. 0 => "30").
	   This changed with the transition to AEDP-4607.
	*/
	pver = proto_tree_add_item(hdr_tree, hf_4607_version, tvb, 0, 2, ENC_ASCII);
	ver_tree = proto_item_add_subtree(pver, ett_4607_ver);
	pedition = proto_tree_add_item(ver_tree, hf_4607_version_edition, tvb, 0, 1, ENC_ASCII);
	uint8_t edition = tvb_get_uint8(tvb, 0);
	if(edition >= 48 && edition <= 51) {
		/* ASCII char 48-51 (0-3) */
		proto_item_append_text(pedition, " (STANAG 4607 Edition %c)", edition);
	} else if(edition >= 52 && edition <= 57) {
		/* ASCII char 52-57 (0-9) -> ASCII table offset 13 -> 52 (4) + 13 = 65 (A) */
		proto_item_append_text(pedition, " (AEDP-4607 Edition %c)", edition + 13);
	}
	proto_tree_add_item(ver_tree, hf_4607_version_version, tvb, 1, 1, ENC_ASCII);

	ti = proto_tree_add_item(hdr_tree, hf_4607_packet_size, tvb, 2, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(hdr_tree, hf_4607_nationality, tvb, 6, 2, ENC_ASCII);
	proto_tree_add_item(hdr_tree, hf_4607_sec_class, tvb, 8, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(hdr_tree, hf_4607_sec_system, tvb, 9, 2, ENC_ASCII);
	proto_tree_add_item(hdr_tree, hf_4607_sec_code, tvb, 11, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(hdr_tree, hf_4607_exercise_indicator, tvb, 13, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(hdr_tree, hf_4607_platform_id, tvb, 14, 10, ENC_ASCII);
	proto_tree_add_item(hdr_tree, hf_4607_mission_id, tvb, 24, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(hdr_tree, hf_4607_job_id, tvb, 28, 4, ENC_BIG_ENDIAN);
	job_id = tvb_get_uint32(tvb, 28, ENC_BIG_ENDIAN);
	offset = 32;

	pkt_size = tvb_get_ntohl(tvb, 2);

	/* Ruh ro. These should be equal... */
	if (tvb_reported_length(tvb) != pkt_size) {
		expert_add_info(pinfo, ti, &ei_bad_packet_size);
		pkt_size = tvb_reported_length(tvb);
	}

	/* Loop over all segments in the packet */
	while (offset < pkt_size) {
		uint32_t seg_size = 0;
		uint32_t saved_offset = offset;

		proto_item * pi;
		/* Segment header */
		seg_type = proto_tree_add_item(hdr_tree, hf_4607_segment_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		seg_id = tvb_get_uint8(tvb, offset);
		offset += 1;

		seg_tree = proto_item_add_subtree(seg_type, ett_4607_seg);
		pi = proto_tree_add_item(seg_tree, hf_4607_segment_size, tvb, offset, 4, ENC_BIG_ENDIAN);
		seg_size = tvb_get_ntohl(tvb, offset);
		offset += 4;
		if (seg_size < MINIMUM_SEGMENT_SIZE) {
			seg_size = MINIMUM_SEGMENT_SIZE;
			col_append_str(pinfo->cinfo, COL_INFO, ", Error: Invalid segment size ");
			expert_add_info(pinfo, pi, &ei_too_short);
		}

		switch (seg_id) {
			case MISSION_SEGMENT:
				CHK_SIZE(MISSION_SEGMENT);
				offset = dissect_mission(tvb, seg_tree, offset);
				break;
			case DWELL_SEGMENT:
				if(job_id == 0)
					proto_tree_add_expert(seg_tree, pinfo, &ei_job_id_zero, tvb, 0, 0);
				offset = dissect_dwell(tvb, seg_tree, offset);
				break;
			case JOB_DEFINITION_SEGMENT:
				CHK_SIZE(JOB_DEFINITION_SEGMENT);
				offset = dissect_jobdef(tvb, seg_tree, offset);
				break;
			case PLATFORM_LOCATION_SEGMENT:
				CHK_SIZE(PLATFORM_LOCATION_SEGMENT);
				offset = dissect_platform_location(tvb, seg_tree, offset);
				break;
			default:
				offset += seg_size - 5;
				break;
		}

		if (offset < saved_offset) {
			/* overflow */
			break;
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_stanag4607(void)
{
	static hf_register_info hf[] = {
		/* ========================================== */
		/* Packet header */
		{ &hf_4607_version,
			{ "Version ID", "s4607.version",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_version_edition,
			{ "Edition", "s4607.version.edition",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_version_version,
			{ "Version", "s4607.version.version",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_packet_size,
			{ "Packet Size", "s4607.size",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_nationality,
			{ "Nationality", "s4607.nationality",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_sec_class,
			{ "Security Classification", "s4607.sec.class",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_class_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_sec_system,
			{ "Security System", "s4607.sec.system",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_sec_code,
			{ "Security Codes", "s4607.sec.codes",
			FT_UINT16, BASE_HEX,
			VALS(stanag4607_security_codes_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_exercise_indicator,
			{ "Exercise Indicator", "s4607.exind",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_exind_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_platform_id,
			{ "Platform ID", "s4607.platform",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_mission_id,
			{ "Mission ID", "s4607.mission",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_job_id,
			{ "Job ID", "s4607.job",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		/* ========================================== */
		/* Segment header */
		{ &hf_4607_segment_type,
			{ "Segment Type", "s4607.seg.type",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_segment_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_segment_size,
			{ "Segment Size", "s4607.seg.size",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		/* ========================================== */
		/* Dwell Segment */
		{ &hf_4607_dwell_mask,
			{ "Existence Mask", "s4607.dwell.mask",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_7_7,
			{ "Revisit Index (D2)", "s4607.dwell.mask.d2",
			FT_BOOLEAN, 64,
			NULL, 0x8000000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_7_6,
			{ "Dwell Index (D3)", "s4607.dwell.mask.d3",
			FT_BOOLEAN, 64,
			NULL, 0x4000000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_7_5,
			{ "Last Dwell of Revisit (D4)", "s4607.dwell.mask.d4",
			FT_BOOLEAN, 64,
			NULL, 0x2000000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_7_4,
			{ "Target Report Count (D5)", "s4607.dwell.mask.d5",
			FT_BOOLEAN, 64,
			NULL, 0x1000000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_7_3,
			{ "Dwell Time (D6)", "s4607.dwell.mask.d6",
			FT_BOOLEAN, 64,
			NULL, 0x0800000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_7_2,
			{ "Sensor Position (Latitude) (D7)", "s4607.dwell.mask.d7",
			FT_BOOLEAN, 64,
			NULL, 0x0400000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_7_1,
			{ "Sensor Position (Longitude) (D8)", "s4607.dwell.mask.d8",
			FT_BOOLEAN, 64,
			NULL, 0x0200000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_7_0,
			{ "Sensor Position (Altitude) (D9)", "s4607.dwell.mask.d9",
			FT_BOOLEAN, 64,
			NULL, 0x0100000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_6_7,
			{ "Scale Factor (Latitude Scale) (D10)", "s4607.dwell.mask.d10",
			FT_BOOLEAN, 64,
			NULL, 0x0080000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_6_6,
			{ "Scale Factor (Longitude Scale) (D11)", "s4607.dwell.mask.d11",
			FT_BOOLEAN, 64,
			NULL, 0x0040000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_6_5,
			{ "Sensor Position Uncertainty (Along Track) (D12)", "s4607.dwell.mask.d12",
			FT_BOOLEAN, 64,
			NULL, 0x0020000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_6_4,
			{ "Sensor Position Uncertainty (Cross-Track) (D13)", "s4607.dwell.mask.d13",
			FT_BOOLEAN, 64,
			NULL, 0x0010000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_6_3,
			{ "Sensor Position Uncertainty (Altitude) (D14)", "s4607.dwell.mask.d14",
			FT_BOOLEAN, 64,
			NULL, 0x0008000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_6_2,
			{ "Sensor Track (D15)", "s4607.dwell.mask.d15",
			FT_BOOLEAN, 64,
			NULL, 0x0004000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_6_1,
			{ "Sensor Speed (D16)", "s4607.dwell.mask.d16",
			FT_BOOLEAN, 64,
			NULL, 0x0002000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_6_0,
			{ "Sensor Vertical Velocity (D17)", "s4607.dwell.mask.d17",
			FT_BOOLEAN, 64,
			NULL, 0x0001000000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_5_7,
			{ "Sensor Track Uncertainty (D18)", "s4607.dwell.mask.d18",
			FT_BOOLEAN, 64,
			NULL, 0x0000800000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_5_6,
			{ "Sensor Speed Uncertainty (D19)", "s4607.dwell.mask.d19",
			FT_BOOLEAN, 64,
			NULL, 0x0000400000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_5_5,
			{ "Sensor Vertical Velocity Uncertainty (D20)", "s4607.dwell.mask.d20",
			FT_BOOLEAN, 64,
			NULL, 0x0000200000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_5_4,
			{ "Platform Orientation (Heading) (D21)", "s4607.dwell.mask.d21",
			FT_BOOLEAN, 64,
			NULL, 0x0000100000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_5_3,
			{ "Platform Orientation (Pitch) (D22)", "s4607.dwell.mask.d22",
			FT_BOOLEAN, 64,
			NULL, 0x0000080000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_5_2,
			{ "Platform Orientation (Roll) (D23)", "s4607.dwell.mask.d23",
			FT_BOOLEAN, 64,
			NULL, 0x0000040000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_5_1,
			{ "Dwell Area (Center Latitude) (D24)", "s4607.dwell.mask.d24",
			FT_BOOLEAN, 64,
			NULL, 0x0000020000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_5_0,
			{ "Dwell Area (Center Longitude) (D25)", "s4607.dwell.mask.d25",
			FT_BOOLEAN, 64,
			NULL, 0x0000010000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_4_7,
			{ "Dwell Area (Range Half Extent) (D26)", "s4607.dwell.mask.d26",
			FT_BOOLEAN, 64,
			NULL, 0x0000008000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_4_6,
			{ "Dwell Area (Dwell Angle Half Extent) (D27)", "s4607.dwell.mask.d27",
			FT_BOOLEAN, 64,
			NULL, 0x0000004000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_4_5,
			{ "Sensor Orientation (Heading) (D28)", "s4607.dwell.mask.d28",
			FT_BOOLEAN, 64,
			NULL, 0x0000002000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_4_4,
			{ "Sensor Orientation (Pitch) (D29)", "s4607.dwell.mask.d29",
			FT_BOOLEAN, 64,
			NULL, 0x0000001000000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_4_3,
			{ "Sensor Orientation (Roll) (D30)", "s4607.dwell.mask.d30",
			FT_BOOLEAN, 64,
			NULL, 0x0000000800000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_4_2,
			{ "Minimum Detectable Velocity, MDV (D31)", "s4607.dwell.mask.d31",
			FT_BOOLEAN, 64,
			NULL, 0x0000000400000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_4_1,
			{ "MTI Report Index (D32.1)", "s4607.dwell.mask.d32_1",
			FT_BOOLEAN, 64,
			NULL, 0x0000000200000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_4_0,
			{ "Target Location (Hi-Res Latitude) (D32.2)", "s4607.dwell.mask.d32_2",
			FT_BOOLEAN, 64,
			NULL, 0x0000000100000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_3_7,
			{ "Target Location (Hi-Res Longitude) (D32.3)", "s4607.dwell.mask.d32_3",
			FT_BOOLEAN, 64,
			NULL, 0x0000000080000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_3_6,
			{ "Target Location (Delta Latitude) (D32.4)", "s4607.dwell.mask.d32_4",
			FT_BOOLEAN, 64,
			NULL, 0x0000000040000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_3_5,
			{ "Target Location (Delta Longitude) (D32.5)", "s4607.dwell.mask.d32_5",
			FT_BOOLEAN, 64,
			NULL, 0x0000000020000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_3_4,
			{ "Target Location (Geodetic Height) (D32.6)", "s4607.dwell.mask.d32_6",
			FT_BOOLEAN, 64,
			NULL, 0x0000000010000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_3_3,
			{ "Target Velocity Line-of-Sight Component (D32.7)", "s4607.dwell.mask.d32_7",
			FT_BOOLEAN, 64,
			NULL, 0x0000000008000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_3_2,
			{ "Target Wrap Velocity (D32.8)", "s4607.dwell.mask.d32_8",
			FT_BOOLEAN, 64,
			NULL, 0x0000000004000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_3_1,
			{ "Target SNR (D32.9)", "s4607.dwell.mask.d32_9",
			FT_BOOLEAN, 64,
			NULL, 0x0000000002000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_3_0,
			{ "Target Classification (D32.10)", "s4607.dwell.mask.d32_10",
			FT_BOOLEAN, 64,
			NULL, 0x0000000001000000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_2_7,
			{ "Target Class. Probability (D32.11)", "s4607.dwell.mask.d32_11",
			FT_BOOLEAN, 64,
			NULL, 0x0000000000800000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_2_6,
			{ "Target Measurement Uncertainty (Slant Range) (D32.12)", "s4607.dwell.mask.d32_12",
			FT_BOOLEAN, 64,
			NULL, 0x0000000000400000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_2_5,
			{ "Target Measurement Uncertainty (Cross Range) (D32.13)", "s4607.dwell.mask.d32_13",
			FT_BOOLEAN, 64,
			NULL, 0x0000000000200000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_2_4,
			{ "Target Measurement Uncertainty (Height) (D32.14)", "s4607.dwell.mask.d32_14",
			FT_BOOLEAN, 64,
			NULL, 0x0000000000100000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_2_3,
			{ "Target Measurement Uncertainty (Target Radial Velocity) (D32.15)", "s4607.dwell.mask.d32_15",
			FT_BOOLEAN, 64,
			NULL, 0x0000000000080000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_2_2,
			{ "Truth Tag (Application) (D32.16)", "s4607.dwell.mask.d32_16",
			FT_BOOLEAN, 64,
			NULL, 0x0000000000040000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_2_1,
			{ "Truth Tag (Entity) (D32.17)", "s4607.dwell.mask.d32_17",
			FT_BOOLEAN, 64,
			NULL, 0x0000000000020000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_2_0,
			{ "Target Radar Cross Section (D32.18)", "s4607.dwell.mask.d32_18",
			FT_BOOLEAN, 64,
			NULL, 0x0000000000010000,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mask_spare,
			{ "Spare", "s4607.dwell.mask.spare",
			FT_UINT64, BASE_HEX,
			NULL, 0x000000000000FFFF,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_revisit_index,
			{ "Revisit Index", "s4607.dwell.revisit",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_dwell_index,
			{ "Dwell Index", "s4607.dwell.dwell",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_last_dwell,
			{ "Last Dwell of Revisit", "s4607.dwell.last",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_count,
			{ "Target Report Count", "s4607.dwell.count",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_time,
			{ "Dwell Time", "s4607.dwell.time",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_millisec), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_sensor_lat,
			{ "Sensor Position Latitude", "s4607.dwell.sensor.lat",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_sensor_lon,
			{ "Sensor Position Longitude", "s4607.dwell.sensor.lon",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_sensor_alt,
			{ "Sensor Position Altitude", "s4607.dwell.sensor.alt",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_centimeters), 0x0,
			NULL, HFILL }
		},
		/* D10 */
		{ &hf_4607_dwell_scale_lat,
			{ "Scale Factor, Latitude", "s4607.dwell.scale.lat",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_scale_lon,
			{ "Scale Factor, Longitude", "s4607.dwell.scale.lon",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},

		/* D12 */
		{ &hf_4607_dwell_unc_along,
			{ "Sensor Position Uncertainty Along Track", "s4607.dwell.unc.along",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_centimeters), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_unc_cross,
			{ "Sensor Position Uncertainty Cross Track", "s4607.dwell.unc.cross",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_centimeters), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_unc_alt,
			{ "Sensor Position Uncertainty Altitude", "s4607.dwell.unc.alt",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_centimeters), 0x0,
			NULL, HFILL }
		},

		/* D15 */
		{ &hf_4607_dwell_track,
			{ "Sensor Track", "s4607.dwell.track",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_ba16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_speed,
			{ "Sensor Speed", "s4607.dwell.speed",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_speed), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_vert_velocity,
			{ "Sensor Vertical Velocity", "s4607.dwell.vvel",
			FT_INT8, BASE_CUSTOM,
			CF_FUNC(prt_speed_deci), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_track_unc,
			{ "Sensor Track Uncertainty", "s4607.dwell.track.unc",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_speed_unc,
			{ "Sensor Speed Uncertainty", "s4607.dwell.speed.unc",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_speed), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_vv_unc,
			{ "Sensor Vertical Velocity Uncertainty", "s4607.dwell.vvel.unc",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_speed_centi), 0x0,
			NULL, HFILL }
		},

		/* D21 */
		{ &hf_4607_dwell_plat_heading,
			{ "Platform Orientation Heading", "s4607.dwell.plat.heading",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_ba16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_plat_pitch,
			{ "Platform Orientation Pitch", "s4607.dwell.plat.pitch",
			FT_INT16, BASE_CUSTOM,
			CF_FUNC(prt_sa16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_plat_roll,
			{ "Platform Orientation Roll (Bank Angle)", "s4607.dwell.plat.roll",
			FT_INT16, BASE_CUSTOM,
			CF_FUNC(prt_sa16), 0x0,
			NULL, HFILL }
		},

		/* D24 */
		{ &hf_4607_dwell_da_lat,
			{ "Dwell Area Center Latitude", "s4607.dwell.da.lat",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_da_lon,
			{ "Dwell Area Center Longitude", "s4607.dwell.da.lon",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_da_range,
			{ "Dwell Area Range Half Extent", "s4607.dwell.da.range",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_kilo), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_da_angle,
			{ "Dwell Area Dwell Angle Half Extent", "s4607.dwell.da.angle",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_ba16), 0x0,
			NULL, HFILL }
		},

		/* D28 */
		{ &hf_4607_dwell_sensor_heading,
			{ "Sensor Orientation Heading", "s4607.dwell.sensor.heading",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_ba16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_sensor_pitch,
			{ "Sensor Orientation Pitch", "s4607.dwell.sensor.pitch",
			FT_INT16, BASE_CUSTOM,
			CF_FUNC(prt_sa16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_sensor_roll,
			{ "Sensor Orientation Roll (Bank Angle)", "s4607.dwell.sensor.roll",
			FT_INT16, BASE_CUSTOM,
			CF_FUNC(prt_sa16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_mdv,
			{ "Minimum Detectable Velocity (MDV)", "s4607.dwell.mdv",
			FT_UINT8, BASE_CUSTOM,
			CF_FUNC(prt_speed_deci), 0x0,
			NULL, HFILL }
		},

		/* ========================================== */
		/* Target Report */
		{ &hf_4607_dwell_report_index,
			{ "MTI Report Index", "s4607.dwell.rpt.idx",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		/* D32.2 */
		{ &hf_4607_dwell_report_lat,
			{ "Target Location Hi-Res Latitude", "s4607.dwell.rpt.lat",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_lon,
			{ "Target Location Hi-Res Longitude", "s4607.dwell.rpt.lon",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},

		/* D32.4 */
		{ &hf_4607_dwell_report_delta_lat,
			{ "Target Location Delta Latitude", "s4607.dwell.rpt.delta.lat",
			FT_INT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_delta_lon,
			{ "Target Location Delta Longitude", "s4607.dwell.rpt.delta.lon",
			FT_INT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		/* D32.6 */
		{ &hf_4607_dwell_report_height,
			{ "Target Location Geodetic Height", "s4607.dwell.rpt.height",
			FT_INT16, BASE_CUSTOM,
			CF_FUNC(prt_meters), 0x0,
			NULL, HFILL }
		},

		/* D32.7 */
		{ &hf_4607_dwell_report_radial,
			{ "Target Velocity Line of Sight Component", "s4607.dwell.rpt.radial",
			FT_INT16, BASE_CUSTOM,
			CF_FUNC(prt_speed_centi), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_wrap,
			{ "Target Wrap Velocity", "s4607.dwell.rpt.wrap",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_speed_centi), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_snr,
			{ "Target SNR", "s4607.dwell.rpt.snr",
			FT_INT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_class,
			{ "Target Classification", "s4607.dwell.rpt.class",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_target_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_prob,
			{ "Target Class Probability", "s4607.dwell.rpt.prob",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		/* D32.12 */
		{ &hf_4607_dwell_report_unc_slant,
			{ "Target Measurement Uncertainty Slant Range", "s4607.dwell.rpt.unc.slant",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_centimeters), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_unc_cross,
			{ "Target Measurement Uncertainty Cross Range", "s4607.dwell.rpt.unc.cross",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_decimeters), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_unc_height,
			{ "Target Measurement Uncertainty Height", "s4607.dwell.rpt.unc.height",
			FT_UINT8, BASE_CUSTOM,
			CF_FUNC(prt_meters), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_unc_radial,
			{ "Target Measurement Uncertainty Radial Velocity", "s4607.dwell.rpt.unc.radial",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_speed_centi), 0x0,
			NULL, HFILL }
		},

		/* D32.16 */
		{ &hf_4607_dwell_report_tag_app,
			{ "Truth Tag Application", "s4607.dwell.rpt.tag.app",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_tag_entity,
			{ "Truth Tag Entity", "s4607.dwell.rpt.tag.entity",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_dwell_report_section,
			{ "Radar Cross Section", "s4607.dwell.rpt.section",
			FT_INT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},


		/* ========================================== */
		/* Job Definition Segment */
		{ &hf_4607_jobdef_job_id,
			{ "Job ID", "s4607.job.id",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_sensor_type,
			{ "Sensor Type", "s4607.job.type",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_sensor_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_sensor_model,
			{ "Sensor Model", "s4607.job.model",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_filter,
			{ "Target Filtering Flag", "s4607.job.filter",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_priority,
			{ "Radar Priority", "s4607.job.priority",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_4607_jobdef_ba_lat_a,
			{ "Bounding Area Point A Latitude", "s4607.job.ba.lat.a",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_ba_lon_a,
			{ "Bounding Area Point A Longitude", "s4607.job.ba.lon.a",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},

		{ &hf_4607_jobdef_ba_lat_b,
			{ "Bounding Area Point B Latitude", "s4607.job.ba.lat.b",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_ba_lon_b,
			{ "Bounding Area Point B Longitude", "s4607.job.ba.lon.b",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_ba_lat_c,
			{ "Bounding Area Point C Latitude", "s4607.job.ba.lat.c",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_ba_lon_c,
			{ "Bounding Area Point C Longitude", "s4607.job.ba.lon.c",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_ba_lat_d,
			{ "Bounding Area Point D Latitude", "s4607.job.ba.lat.d",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_ba_lon_d,
			{ "Bounding Area Point D Longitude", "s4607.job.ba.lon.d",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},

		{ &hf_4607_jobdef_radar_mode,
			{ "Radar Mode", "s4607.job.mode",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_radar_mode_vals), 0x0,
			NULL, HFILL }
		},

		{ &hf_4607_jobdef_revisit_interval,
			{ "Nominal Revisit Interval", "s4607.job.revisit",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_unc_along,
			{ "Nominal Sensor Position Uncertainty Along Track", "s4607.job.unc.track",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_none16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_unc_cross,
			{ "Nominal Sensor Position Uncertainty Cross Track", "s4607.job.unc.cross",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_none16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_unc_alt,
			{ "Nominal Sensor Position Uncertainty Altitude", "s4607.job.unc.alt",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_none16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_unc_heading,
			{ "Nominal Sensor Position Uncertainty Track Heading", "s4607.job.unc.heading",
			FT_UINT8, BASE_CUSTOM,
			CF_FUNC(prt_none8), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_unc_speed,
			{ "Nominal Sensor Position Uncertainty Speed", "s4607.job.unc.speed",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_none16), 0x0,
			NULL, HFILL }
		},

		{ &hf_4607_jobdef_sense_slant,
			{ "Nominal Sensor Slant Range Standard Deviation", "s4607.job.sense.slant",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_none16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_sense_cross,
			{ "Nominal Sensor Cross Range Standard Deviation", "s4607.job.sense.cross",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_ba16_none), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_sense_vlos,
			{ "Nominal Sensor Velocity Line-Of-Sight Std. Dev", "s4607.job.sense.vlos",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_none16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_sense_mdv,
			{ "Nominal Sensor Minimum Detectable Velocity (MDV)", "s4607.job.sense.mdv",
			FT_UINT8, BASE_CUSTOM,
			CF_FUNC(prt_none8), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_sense_prob,
			{ "Nominal Sensor Detection Probability", "s4607.job.sense.prob",
			FT_UINT8, BASE_CUSTOM,
			CF_FUNC(prt_none8), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_sense_alarm,
			{ "Nominal Sensor False Alarm Density", "s4607.job.sense.alarm",
			FT_UINT8, BASE_CUSTOM,
			CF_FUNC(prt_none8), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_terrain_model,
			{ "Terrain Elevation Model Used", "s4607.job.terrain",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_terrain_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_jobdef_geoid_model,
			{ "Geoid Model Used", "s4607.job.geoid",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_geoid_vals), 0x0,
			NULL, HFILL }
		},


		/* ========================================== */
		/* Mission segment */
		{ &hf_4607_mission_plan,
			{ "Mission Plan", "s4607.mission.plan",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_mission_flight_plan,
			{ "Mission Flight Plan", "s4607.mission.flight",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_mission_platform,
			{ "Mission Platform Type", "s4607.mission.platform",
			FT_UINT8, BASE_DEC,
			VALS(stanag4607_platform_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_mission_platform_config,
			{ "Mission Platform Configuration", "s4607.mission.config",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_mission_time_year,
			{ "Mission Reference Time Year", "s4607.mission.year",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_mission_time_month,
			{ "Mission Reference Time Month", "s4607.mission.month",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_mission_time_day,
			{ "Mission Reference Time Day", "s4607.mission.day",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		/* ========================================== */
		{ &hf_4607_platloc_time,
			{ "Platform Location Time", "s4607.ploc.time",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_millisec), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_platloc_latitude,
			{ "Platform Position Latitude", "s4607.ploc.lat",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_sa32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_platloc_longitude,
			{ "Platform Position Longitude", "s4607.ploc.lon",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_ba32), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_platloc_altitude,
			{ "Platform Position Altitude", "s4607.ploc.alt",
			FT_INT32, BASE_CUSTOM,
			CF_FUNC(prt_centimeters), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_platloc_track,
			{ "Platform Track", "s4607.ploc.track",
			FT_UINT16, BASE_CUSTOM,
			CF_FUNC(prt_ba16), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_platloc_speed,
			{ "Platform Speed", "s4607.ploc.speed",
			FT_UINT32, BASE_CUSTOM,
			CF_FUNC(prt_speed), 0x0,
			NULL, HFILL }
		},
		{ &hf_4607_platloc_vertical_velocity,
			{ "Platform Vertical Velocity", "s4607.ploc.velocity",
			FT_INT8, BASE_CUSTOM,
			CF_FUNC(prt_speed_deci), 0x0,
			NULL, HFILL }
		},

	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_4607_hdr,
		&ett_4607_seg,
		&ett_4607_rpt,
		&ett_4607_mask,
		&ett_4607_ver,
	};

	static ei_register_info ei[] = {
		{ &ei_too_short,
			{ "s4607.segment_too_short", PI_MALFORMED, PI_ERROR,
			  "Segment size too small", EXPFILL }},
		{ &ei_bad_length,
			{ "s4607.segment_bad_length", PI_MALFORMED, PI_ERROR,
			  "Bad segment size", EXPFILL }},
		{ &ei_bad_packet_size,
			{ "s4607.bad_packet_size", PI_MALFORMED, PI_ERROR,
			  "Bad packet size field", EXPFILL }},
		{ &ei_job_id_zero,
			{ "s4607.job_id_zero", PI_MALFORMED, PI_WARN,
			  "Segment present without valid Job ID", EXPFILL }}
	};

	expert_module_t* expert_4607;

	proto_stanag4607 = proto_register_protocol (
	    "STANAG 4607 (GMTI Format)", /* name       */
	    "STANAG 4607",      /* short name */
	    "s4607"       /* abbrev     */
	);

	proto_register_field_array(proto_stanag4607, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_4607 = expert_register_protocol(proto_stanag4607);
	expert_register_field_array(expert_4607, ei, array_length(ei));

	stanag4607_handle = register_dissector("stanag4607", dissect_stanag4607, proto_stanag4607);
	/* prefs_register_protocol(proto_stanag4607, proto_reg_handoff_stanag4607); */
}

void
proto_reg_handoff_stanag4607(void)
{
	dissector_add_for_decode_as("tcp.port", stanag4607_handle);
	dissector_add_for_decode_as("udp.port", stanag4607_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_STANAG_4607, stanag4607_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
