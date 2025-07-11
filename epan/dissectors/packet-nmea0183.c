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

static int hf_nmea0183_rot_rate_of_turn;
static int hf_nmea0183_rot_valid;

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

static int hf_nmea0183_vtg_true_course;
static int hf_nmea0183_vtg_true_course_unit;
static int hf_nmea0183_vtg_magnetic_course;
static int hf_nmea0183_vtg_magnetic_course_unit;
static int hf_nmea0183_vtg_ground_speed_knot;
static int hf_nmea0183_vtg_ground_speed_knot_unit;
static int hf_nmea0183_vtg_ground_speed_kilometer;
static int hf_nmea0183_vtg_ground_speed_kilometer_unit;
static int hf_nmea0183_vtg_mode;

static int hf_nmea0183_zda_time;
static int hf_nmea0183_zda_time_hour;
static int hf_nmea0183_zda_time_minute;
static int hf_nmea0183_zda_time_second;
static int hf_nmea0183_zda_date_day;
static int hf_nmea0183_zda_date_month;
static int hf_nmea0183_zda_date_year;
static int hf_nmea0183_zda_local_zone_hour;
static int hf_nmea0183_zda_local_zone_minute;

static int ett_nmea0183;
static int ett_nmea0183_checksum;
static int ett_nmea0183_sentence;
static int ett_nmea0183_zda_time;
static int ett_nmea0183_gga_time;
static int ett_nmea0183_gga_latitude;
static int ett_nmea0183_gga_longitude;
static int ett_nmea0183_gll_time;
static int ett_nmea0183_gll_latitude;
static int ett_nmea0183_gll_longitude;
static int ett_nmea0183_gst_time;

static expert_field ei_nmea0183_invalid_first_character;
static expert_field ei_nmea0183_missing_checksum_character;
static expert_field ei_nmea0183_invalid_end_of_line;
static expert_field ei_nmea0183_checksum_incorrect;
static expert_field ei_nmea0183_sentence_too_long;
static expert_field ei_nmea0183_field_time_too_short;
static expert_field ei_nmea0183_field_latitude_too_short;
static expert_field ei_nmea0183_field_longitude_too_short;
static expert_field ei_nmea0183_field_missing;
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

static int proto_nmea0183;

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
    {"APA", "Autopilot Sentence A"},
    {"APB", "Autopilot Sentence B"},
    {"ASD", "Autopilot System Data"},
    {"ASN", "Preparation and Initiation of an AIS Base Station Broadcast of Assignment VDL (Message 16)"},
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
    {"SPO", "Select AIS Device's Processing and Output"},
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

static uint8_t calculate_checksum(tvbuff_t *tvb, const int start, const int length)
{
    uint8_t checksum = 0;
    for (int i = start; i < start + length; i++)
    {
        checksum ^= tvb_get_uint8(tvb, i);
    }
    return checksum;
}

/* Find first occurrence of a field separator in tvbuff, starting at offset. Searches
 * to end of tvbuff.
 * Returns the offset of the found separator.
 * If separator is not found, return the offset of end of tvbuff.
 * If offset is out of bounds, return the offset of end of tvbuff.
 **/
static int
tvb_find_end_of_nmea0183_field(tvbuff_t *tvb, const int offset)
{
    if (tvb_captured_length_remaining(tvb, offset) == 0)
    {
        return tvb_captured_length(tvb);
    }

    int end_of_field_offset = tvb_find_uint8(tvb, offset, -1, ',');
    if (end_of_field_offset == -1)
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
dissect_nmea0183_field(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf, const char *suffix)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    ti = proto_tree_add_item(tree, hf, tvb, offset, end_of_field_offset - offset, ENC_ASCII);
    if (end_of_field_offset - offset == 0)
    {
        proto_item_append_text(ti, "[empty]");
    }
    else if (suffix != NULL)
    {
        proto_item_append_text(ti, " %s", suffix);
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
        proto_item_append_text(ti, "[empty]");

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
        proto_item_append_text(ti, "[empty]");

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
    const uint8_t *quality = NULL;
    ti = proto_tree_add_item_ret_string(tree, hf,
                                        tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                        pinfo->pool, &quality);
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
                                  const uint8_t *expected_text, expert_field *invalid_ei)
{
    if (offset > (int)tvb_captured_length(tvb))
    {
        proto_tree_add_missing_field(tree, pinfo, hf, tvb, tvb_captured_length(tvb));
        return 0;
    }

    proto_item *ti = NULL;
    const uint8_t *text = NULL;
    int end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
    ti = proto_tree_add_item_ret_string(tree, hf,
                                        tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                        pinfo->pool, &text);
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
    const uint8_t *mode = NULL;
    ti = proto_tree_add_item_ret_string(tree, hf,
                                        tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                        pinfo->pool, &mode);
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
    const uint8_t *mode = NULL;
    ti = proto_tree_add_item_ret_string(tree, hf,
                                        tvb, offset, end_of_field_offset - offset, ENC_ASCII,
                                        pinfo->pool, &mode);
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

/* Dissect a DPT sentence. */
static int
dissect_nmea0183_sentence_dpt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence, NULL, "DPT sentence - Depth of Water");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dpt_depth, "meter");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dpt_offset, "meter");

    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_dpt_max_range, "meter");

    return tvb_captured_length(tvb);
}

/* Dissect a GGA sentence. The time, latitude and longitude fields is split into individual parts. */
static int
dissect_nmea0183_sentence_gga(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
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

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_number_satellites, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_horizontal_dilution, "meter");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_altitude, "meter");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_gga_altitude_unit,
                                                "M", &ei_nmea0183_gga_altitude_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_geoidal_separation, "meter");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_gga_geoidal_separation_unit,
                                                "M", &ei_nmea0183_gga_geoidal_separation_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_age_dgps, "second");

    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gga_dgps_station, NULL);

    return tvb_captured_length(tvb);
}

/* Dissect a GLL sentence. The latitude, longitude and time fields is split into individual parts. */
static int
dissect_nmea0183_sentence_gll(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
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
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "GST sentence - GPS Pseudorange Noise Statistics");

    offset += dissect_nmea0183_field_time(tvb, pinfo, subtree, offset, hf_nmea0183_gst_time,
                                          hf_nmea0183_gst_time_hour, hf_nmea0183_gst_time_minute,
                                          hf_nmea0183_gst_time_second, ett_nmea0183_gst_time);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_rms_total_sd, "");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_ellipse_major_sd, "meter");
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_ellipse_minor_sd, "meter");
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_ellipse_orientation, "degree (true north)");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_latitude_sd, "meter");
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_longitude_sd, "meter");
    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_gst_altitude_sd, "meter");

    return tvb_captured_length(tvb);
}

/* Dissect a HDT sentence. */
static int
dissect_nmea0183_sentence_hdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "HDT sentence - True Heading");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_hdt_heading, "degree");

    dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_hdt_unit,
                                      "T", &ei_nmea0183_hdt_unit_incorrect);

    return tvb_captured_length(tvb);
}

/* Dissect a ROT sentence. */
static int
dissect_nmea0183_sentence_rot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "ROT sentence - Rate Of Turn");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rot_rate_of_turn, "degree per minute");

    dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_rot_valid);

    return tvb_captured_length(tvb);
}

/* Dissect a VHW sentence. */
static int
dissect_nmea0183_sentence_vhw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "VHW sentence - Water speed and heading");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_true_heading, "degree");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_true_heading_unit,
                                                "T", &ei_nmea0183_vhw_true_heading_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_magnetic_heading, "degree");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_magnetic_heading_unit,
                                                "M", &ei_nmea0183_vhw_magnetic_heading_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_water_speed_knot, "knot");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_water_speed_knot_unit,
                                                "N", &ei_nmea0183_vhw_water_speed_knot_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_water_speed_kilometer, "kilometer per hour");

    dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vhw_water_speed_kilometer_unit,
                                      "K", &ei_nmea0183_vhw_water_speed_kilometer_unit_incorrect);

    return tvb_captured_length(tvb);
}

/* Dissect a VBW sentence. */
static int
dissect_nmea0183_sentence_vbw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "VBW sentence - Dual Ground/Water Speed");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_water_speed_longitudinal, "knot");
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_water_speed_transverse, "knot");
    offset += dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_water_speed_valid);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_ground_speed_longitudinal, "knot");
    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_ground_speed_transverse, "knot");
    offset += dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_ground_speed_valid);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_stern_water_speed, "knot");
    offset += dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_stern_water_speed_valid);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_stern_ground_speed, "knot");
    dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_vbw_stern_ground_speed_valid);

    return tvb_captured_length(tvb);
}

/* Dissect a VLW sentence. */
static int
dissect_nmea0183_sentence_vlw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "VLW sentence - Distance Traveled through Water");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_cumulative_water, "nautical miles");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_cumulative_water_unit,
                                                "N", &ei_nmea0183_vlw_cumulative_water_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_trip_water, "nautical miles");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_trip_water_unit,
                                                "N", &ei_nmea0183_vlw_trip_water_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_cumulative_ground, "nautical miles");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_cumulative_ground_unit,
                                                "N", &ei_nmea0183_vlw_cumulative_ground_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_trip_ground, "nautical miles");

    dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vlw_trip_ground_unit,
                                      "N", &ei_nmea0183_vlw_trip_ground_unit_incorrect);

    return tvb_captured_length(tvb);
}

/* Dissect a VTG sentence. */
static int
dissect_nmea0183_sentence_vtg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "VTG sentence - Track made good and Ground speed");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_true_course, "degree");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_true_course_unit,
                                                "T", &ei_nmea0183_vtg_true_course_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_magnetic_course, "degree");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_magnetic_course_unit,
                                                "M", &ei_nmea0183_vtg_magnetic_course_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_ground_speed_knot, "knot");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_ground_speed_knot_unit,
                                                "N", &ei_nmea0183_vtg_ground_speed_knot_unit_incorrect);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_ground_speed_kilometer, "kilometer per hour");

    offset += dissect_nmea0183_field_fixed_text(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_ground_speed_kilometer_unit,
                                                "K", &ei_nmea0183_vtg_ground_speed_kilometer_unit_incorrect);

    dissect_nmea0183_field_faa_mode(tvb, pinfo, subtree, offset, hf_nmea0183_vtg_mode);

    return tvb_captured_length(tvb);
}

/* Dissect a ZDA (Time & Date) sentence. The time field is split into individual parts. */
static int
dissect_nmea0183_sentence_zda(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "ZDA sentence - Time & Date");

    offset += dissect_nmea0183_field_time(tvb, pinfo, subtree, offset, hf_nmea0183_zda_time,
                                          hf_nmea0183_zda_time_hour, hf_nmea0183_zda_time_minute,
                                          hf_nmea0183_zda_time_second, ett_nmea0183_zda_time);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_date_day, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_date_month, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_date_year, NULL);

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_local_zone_hour, NULL);

    dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_zda_local_zone_minute, NULL);

    return tvb_captured_length(tvb);
}

/* Dissect a sentence where the sentence id is unknown. Each field is shown as an generic field. */
static int
dissect_nmea0183_sentence_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
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

static int
dissect_nmea0183(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    int start_checksum_offset = 0;
    const uint8_t *talker_id = NULL;
    const uint8_t *sentence_id = NULL;
    const uint8_t *checksum = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NMEA 0183");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_nmea0183, tvb, 0, -1, ENC_NA);
    proto_tree *nmea0183_tree = proto_item_add_subtree(ti, ett_nmea0183);

    /* Start delimiter */
    if (tvb_get_uint8(tvb, offset) != '$')
    {
        expert_add_info(pinfo, nmea0183_tree, &ei_nmea0183_invalid_first_character);
    }
    offset += 1;

    /* Talker id */
    ti = proto_tree_add_item_ret_string(nmea0183_tree, hf_nmea0183_talker_id,
                                        tvb, offset, 2, ENC_ASCII,
                                        pinfo->pool, &talker_id);

    proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, talker_id, known_talker_ids, "Unknown talker ID"));

    col_append_fstr(pinfo->cinfo, COL_INFO, "Talker %s", talker_id);

    offset += 2;

    /* Sentence id */
    ti = proto_tree_add_item_ret_string(nmea0183_tree, hf_nmea0183_sentence_id,
                                        tvb, offset, 3, ENC_ASCII,
                                        pinfo->pool, &sentence_id);

    proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, sentence_id, known_sentence_ids, "Unknown sentence ID"));

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Sentence %s", sentence_id);

    offset += 3;

    /* Start of checksum */
    start_checksum_offset = tvb_find_uint8(tvb, offset, -1, '*');
    if (start_checksum_offset == -1)
    {
        expert_add_info(pinfo, nmea0183_tree, &ei_nmea0183_missing_checksum_character);
        return tvb_captured_length(tvb);
    }

    /* Data */
    offset += 1;
    tvbuff_t *data_tvb = tvb_new_subset_length(tvb, offset, start_checksum_offset - offset);
    if (g_ascii_strcasecmp(sentence_id, "DPT") == 0)
    {
        offset += dissect_nmea0183_sentence_dpt(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GGA") == 0)
    {
        offset += dissect_nmea0183_sentence_gga(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GLL") == 0)
    {
        offset += dissect_nmea0183_sentence_gll(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "GST") == 0)
    {
        offset += dissect_nmea0183_sentence_gst(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "HDT") == 0)
    {
        offset += dissect_nmea0183_sentence_hdt(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ROT") == 0)
    {
        offset += dissect_nmea0183_sentence_rot(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VBW") == 0)
    {
        offset += dissect_nmea0183_sentence_vbw(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VHW") == 0)
    {
        offset += dissect_nmea0183_sentence_vhw(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VLW") == 0)
    {
        offset += dissect_nmea0183_sentence_vlw(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "VTG") == 0)
    {
        offset += dissect_nmea0183_sentence_vtg(data_tvb, pinfo, nmea0183_tree);
    }
    else if (g_ascii_strcasecmp(sentence_id, "ZDA") == 0)
    {
        offset += dissect_nmea0183_sentence_zda(data_tvb, pinfo, nmea0183_tree);
    }
    else
    {
        offset += dissect_nmea0183_sentence_unknown(data_tvb, pinfo, nmea0183_tree);
    }

    /* Checksum */
    offset += 1;
    ti = proto_tree_add_item_ret_string(nmea0183_tree, hf_nmea0183_checksum,
                                        tvb, offset, 2, ENC_ASCII,
                                        pinfo->pool, &checksum);

    uint8_t received_checksum = (uint8_t)strtol(checksum, NULL, 16);
    uint8_t calculated_checksum = calculate_checksum(tvb, 1, offset - 2);
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
        expert_add_info(pinfo, nmea0183_tree, &ei_nmea0183_invalid_end_of_line);
    }
    offset += 2;

    /* Check sentence length */
    if (offset > 82)
    {
        expert_add_info(pinfo, nmea0183_tree, &ei_nmea0183_sentence_too_long);
    }

    return tvb_captured_length(tvb);
}

/* Try to detect NMEA 0183 heuristically */
static bool dissect_nmea0183_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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
    /* Grab the first byte and check the first character */
    sent_type = tvb_get_string_enc(pinfo->pool, tvb, 0, 1, ENC_ASCII);

    /* Sentence type character ('!' or '$') */
    if( (sent_type[0] != '!') && (sent_type[0] != '$') ){
        return false;
    }

    /* We either have a 'P' and corresponding manufacturer 3-byte value OR
     * we have a non-proprietary 2-byte TALKER field */
    //TODO: Implement encapsulation and proprietary message parsing

    /* Do a lookup for the 2-byte TALKER field */
    t_val = tvb_get_string_enc(pinfo->pool, tvb, 1, 2, ENC_ASCII);
    talker = try_str_to_str(t_val, known_talker_ids);

    /* Do a lookup for the 3-byte manufacturer if the 2nd byte in the PDU is 'P' */
    p_val = tvb_get_string_enc(pinfo->pool, tvb, 1, 1, ENC_ASCII);
    m_val = tvb_get_string_enc(pinfo->pool, tvb, 2, 3, ENC_ASCII);
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
        {&hf_nmea0183_dpt_depth,
         {"Water depth", "nmea0183.dpt_depth",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 DPT Water depth relative to transducer", HFILL}},
        {&hf_nmea0183_dpt_offset,
         {"Offset", "nmea0183.dpt_offset",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 DPT Offset from transducer, positive means distance from transducer to water line, negative means distance from transducer to keel", HFILL}},
        {&hf_nmea0183_dpt_max_range,
         {"Maximum range", "nmea0183.dpt_max_range",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 DPT Maximum range scale in use (NMEA 3.0 and above)", HFILL}},
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
        {&hf_nmea0183_gga_latitude_minute,
         {"Minute", "nmea0183.gga_latitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_latitude_direction,
         {"Direction", "nmea0183.gga_latitude_direction",
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
        {&hf_nmea0183_gga_longitude_minute,
         {"Minute", "nmea0183.gga_longitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_longitude_direction,
         {"Direction", "nmea0183.gga_longitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_quality,
         {"Quality indicator", "nmea0183.gga_quality",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_number_satellites,
         {"Number of satellites", "nmea0183.gga_number_satellites",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Number of satellites in use", HFILL}},
        {&hf_nmea0183_gga_horizontal_dilution,
         {"Horizontal Dilution", "nmea0183.gga_horizontal_dilution",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Horizontal Dilution of precision", HFILL}},
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
        {&hf_nmea0183_gga_age_dgps,
         {"Age of differential GPS", "nmea0183.gga_age_dgps",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gga_dgps_station,
         {"Differential GPS station id", "nmea0183.gga_dgps_station",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Differential reference station ID", HFILL}},
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
        {&hf_nmea0183_gll_latitude_minute,
         {"Minute", "nmea0183.gll_latitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_latitude_direction,
         {"Direction", "nmea0183.gll_latitude_direction",
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
        {&hf_nmea0183_gll_longitude_minute,
         {"Minute", "nmea0183.gll_longitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_longitude_direction,
         {"Direction", "nmea0183.gll_longitude_direction",
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
        {&hf_nmea0183_gll_status,
         {"Status", "nmea0183.gll_status",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nmea0183_gll_mode,
         {"FAA mode", "nmea0183.gll_mode",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL FAA mode indicator (NMEA 2.3 and later)", HFILL}},
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
        {&hf_nmea0183_gst_rms_total_sd,
         {"Total RMS standard deviation", "nmea0183.gst_sd_rms_total",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GST Total RMS standard deviation of ranges inputs to the navigation solution", HFILL}},
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
        {&hf_nmea0183_gst_altitude_sd,
         {"Standard deviation of altitude error", "nmea0183.gst_sd_altitude",
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
        {&hf_nmea0183_vtg_mode,
         {"FAA mode", "nmea0183.vtg_mode",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 VTG FAA mode indicator (NMEA 2.3 and later)", HFILL}},
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
        {&hf_nmea0183_zda_local_zone_minute,
         {"Local zone minute", "nmea0183.zda_local_zone_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}}};

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_nmea0183,
        &ett_nmea0183_checksum,
        &ett_nmea0183_sentence,
        &ett_nmea0183_zda_time,
        &ett_nmea0183_gga_time,
        &ett_nmea0183_gga_latitude,
        &ett_nmea0183_gga_longitude,
        &ett_nmea0183_gll_time,
        &ett_nmea0183_gll_latitude,
        &ett_nmea0183_gll_longitude,
        &ett_nmea0183_gst_time};

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
          "Incorrect speed unit (should be 'K')", EXPFILL}}};

    proto_nmea0183 = proto_register_protocol("NMEA 0183 protocol", "NMEA 0183", "nmea0183");

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
