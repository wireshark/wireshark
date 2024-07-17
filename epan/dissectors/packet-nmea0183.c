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

static int hf_nmea0183_rot_rate_of_turn;
static int hf_nmea0183_rot_valid;

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

static int proto_nmea0183;

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
    {"CA", "Central Alarm"},
    {"CC", "Computer - Programmed Calculator (obsolete)"},
    {"CD", "Communications - Digital Selective Calling (DSC)"},
    {"CM", "Computer - Memory Data (obsolete)"},
    {"CR", "Data Receiver"},
    {"CS", "Communications - Satellite"},
    {"CT", "Communications - Radio-Telephone (MF/HF)"},
    {"CV", "Communications - Radio-Telephone (VHF)"},
    {"CX", "Communications - Scanning Receiver"},
    {"DE", "DECCA Navigation (obsolete)"},
    {"DF", "Direction Finder"},
    {"DM", "Velocity Sensor, Speed Log, Water, Magnetic"},
    {"DP", "Dynamiv Position"},
    {"DU", "Duplex repeater station"},
    {"EC", "Electronic Chart Display & Information System (ECDIS)"},
    {"EP", "Emergency Position Indicating Beacon (EPIRB)"},
    {"ER", "Engine Room Monitoring Systems"},
    {"FD", "Fire Door"},
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
    {"OM", "OMEGA Navigation System (obsolete)"},
    {"OS", "Distress Alarm System (obsolete)"},
    {"P ", "Vendor specific"},
    {"QZ", "QZSS regional GPS augmentation system (Japan)"},
    {"RA", "RADAR and/or ARPA"},
    {"RB", "Record Book"},
    {"RC", "Propulsion Machinery"},
    {"RI", "Rudder Angle Indicator"},
    {"SA", "Physical Shore AUS Station"},
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
    {"ACK", "Alarm Acknowledgement"},
    {"ADS", "Automatic Device Status"},
    {"AKD", "Acknowledge Detail Alarm Condition"},
    {"ALA", "Set Detail Alarm Condition"},
    {"ALM", "GPS Almanac Data"},
    {"APA", "Autopilot Sentence A"},
    {"APB", "Autopilot Sentence B"},
    {"ASD", "Autopilot System Data"},
    {"BEC", "Bearing & Distance to Waypoint - Dead Reckoning"},
    {"BER", "Bearing & Distance to Waypoint, Dead Reckoning, Rhumb Line"},
    {"BOD", "Bearing - Waypoint to Waypoint"},
    {"BPI", "Bearing & Distance to Point of Interest"},
    {"BWC", "Bearing & Distance to Waypoint - Great Circle"},
    {"BWR", "Bearing and Distance to Waypoint - Rhumb Line"},
    {"BWW", "Bearing - Waypoint to Waypoint"},
    {"CEK", "Configure Encryption Key Command"},
    {"COP", "Configure the Operational Period, Command"},
    {"CUR", "Water Current Layer"},
    {"DBK", "Depth Below Keel"},
    {"DBS", "Depth Below Surface"},
    {"DBT", "Depth below transducer"},
    {"DCN", "DECCA Position"},
    {"DCR", "Device Capability Report"},
    {"DDC", "Display Dimming Control"},
    {"DOR", "Door Status Detection"},
    {"DPT", "Depth of Water"},
    {"DRU", "Dual Doppler Auxiliary Data"},
    {"DSC", "Digital Selective Calling Information"},
    {"DSE", "Extended DSC"},
    {"DSI", "DSC Transponder Initiate"},
    {"DSR", "DSC Transponder Response"},
    {"DTM", "Datum Reference"},
    {"ETL", "Engine Telegraph Operation Status"},
    {"EVE", "General Event Message"},
    {"FIR", "Fire Detection"},
    {"FSI", "Frequency Set Information"},
    {"GBS", "GPS Satellite Fault Detection"},
    {"GDA", "Dead Reckoning Positions"},
    {"GGA", "Global Positioning System Fix Data"},
    {"GLa", "Loran-C Positions"},
    {"GLC", "Geographic Position, Loran-C"},
    {"GLL", "Geographic Position - Latitude/Longitude"},
    {"GNS", "Fix data"},
    {"GOA", "OMEGA Positions"},
    {"GRS", "GPS Range Residuals"},
    {"GSA", "GPS DOP and active satellites"},
    {"GST", "GPS Pseudorange Noise Statistics"},
    {"GSV", "Satellites in view"},
    {"GTD", "Geographic Location in Time Differences"},
    {"GXA", "TRANSIT Position"},
    {"HCC", "Compass Heading"},
    {"HCD", "Heading and Deviation"},
    {"HDG", "Heading - Deviation & Variation"},
    {"HDM", "Heading - Magnetic"},
    {"HDT", "Heading - True"},
    {"HFB", "Trawl Headrope to Footrope and Bottom"},
    {"HSC", "Heading Steering Command"},
    {"HVD", "Magnetic Variation, Automatic"},
    {"HVM", "Magnetic Variation, Manually Set"},
    {"IMA", "Vessel Identification"},
    {"ITS", "Trawl Door Spread 2 Distance"},
    {"LCD", "Loran-C Signal Data"},
    {"MDA", "Meteorological Composite"},
    {"MHU", "Humidity"},
    {"MMB", "Barometer"},
    {"MSK", "Control for a Beacon Receiver"},
    {"MSS", "Beacon Receiver Status"},
    {"MTA", "Air Temperature"},
    {"MTW", "Mean Temperature of Water"},
    {"MWD", "Wind Direction & Speed"},
    {"MWH", "Wave Height"},
    {"MWS", "Wind & Sea State"},
    {"MWV", "Wind Speed and Angle"},
    {"OLN", "Omega Lane Numbers"},
    {"OLW", "Omega Lane Width"},
    {"OMP", "Omega Position"},
    {"OSD", "Own Ship Data"},
    {"OZN", "Omega Zone Number"},
    {"R00", "Waypoints in active route"},
    {"RLM", "Return Link Message"},
    {"RMA", "Recommended Minimum Navigation Information"},
    {"RMB", "Recommended Minimum Navigation Information"},
    {"RMC", "Recommended Minimum Navigation Information"},
    {"Rnn", "Routes"},
    {"ROT", "Rate Of Turn"},
    {"RPM", "Revolutions"},
    {"RSA", "Rudder Sensor Angle"},
    {"RSD", "RADAR System Data"},
    {"RTE", "Routes"},
    {"SBK", "Loran-C Blink Status"},
    {"SCD", "Loran-C ECDs"},
    {"SCY", "Loran-C Cycle Lock Status"},
    {"SDB", "Loran-C Signal Strength"},
    {"SFI", "Scanning Frequency Information"},
    {"SGD", "Position Accuracy Estimate"},
    {"SGR", "Loran-C Chain Identifier"},
    {"SIU", "Loran-C Stations in Use"},
    {"SLC", "Loran-C Status"},
    {"SNC", "Navigation Calculation Basis"},
    {"SNU", "Loran-C SNR Status"},
    {"SPS", "Loran-C Predicted Signal Strength"},
    {"SSF", "Position Correction Offset"},
    {"STC", "Time Constant"},
    {"STN", "Multiple Data ID"},
    {"STR", "Tracking Reference"},
    {"SYS", "Hybrid System Configuration"},
    {"TDS", "Trawl Door Spread Distance"},
    {"TEC", "TRANSIT Satellite Error Code & Doppler Count"},
    {"TEP", "TRANSIT Satellite Predicted Elevation"},
    {"TFI", "Trawl Filling Indicator"},
    {"TGA", "TRANSIT Satellite Antenna & Geoidal Heights"},
    {"TIF", "TRANSIT Satellite Initial Flag"},
    {"TLB", "Target Label"},
    {"TLL", "Target Latitude and Longitude"},
    {"TPC", "Trawl Position Cartesian Coordinates"},
    {"TPR", "Trawl Position Relative Vessel"},
    {"TPT", "Trawl Position True"},
    {"TRF", "TRANSIT Fix Data"},
    {"TRP", "TRANSIT Satellite Predicted Direction of Rise"},
    {"TRS", "TRANSIT Satellite Operating Status"},
    {"TTM", "Tracked Target Message"},
    {"VBW", "Dual Ground/Water Speed"},
    {"VCD", "Current at Selected Depth"},
    {"VDR", "Set and Drift"},
    {"VHW", "Water speed and heading"},
    {"VLW", "Distance Traveled through Water"},
    {"VPE", "Speed, Dead Reckoned Parallel to True Wind"},
    {"VPW", "Speed - Measured Parallel to Wind"},
    {"VTA", "Actual Track"},
    {"VTG", "Track made good and Ground speed"},
    {"VTI", "Intended Track"},
    {"VWE", "Wind Track Efficiency"},
    {"VWR", "Relative Wind Speed and Angle"},
    {"VWT", "True Wind Speed and Angle"},
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

    int end_of_field_offset = tvb_find_guint8(tvb, offset, -1, ',');
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
        proto_item_append_text(ti, " (%s)", str_to_str(quality, known_gps_quality_indicators, "Unknown quality"));
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
        proto_item_append_text(ti, " (%s)", str_to_str(mode, known_faa_mode_indicators, "Unknown FAA mode"));
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
        proto_item_append_text(ti, " (%s)", str_to_str(mode, known_status_indicators, "Unknown status"));
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

/* Dissect a ROT sentence. */
static int
dissect_nmea0183_sentence_rot(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    int offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "ROT sentence - Rate Of Turn");

    offset += dissect_nmea0183_field(tvb, pinfo, subtree, offset, hf_nmea0183_rot_rate_of_turn, "degree per minute");

    dissect_nmea0183_field_status(tvb, pinfo, subtree, offset, hf_nmea0183_rot_valid);

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

    proto_item_append_text(ti, " (%s)", str_to_str(talker_id, known_talker_ids, "Unknown talker ID"));

    col_append_fstr(pinfo->cinfo, COL_INFO, "Talker %s", talker_id);

    offset += 2;

    /* Sentence id */
    ti = proto_tree_add_item_ret_string(nmea0183_tree, hf_nmea0183_sentence_id,
                                        tvb, offset, 3, ENC_ASCII,
                                        pinfo->pool, &sentence_id);

    proto_item_append_text(ti, " (%s)", str_to_str(sentence_id, known_sentence_ids, "Unknown sentence ID"));

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Sentence %s", sentence_id);

    offset += 3;

    /* Start of checksum */
    start_checksum_offset = tvb_find_guint8(tvb, offset, -1, '*');
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
    else if (g_ascii_strcasecmp(sentence_id, "ROT") == 0)
    {
        offset += dissect_nmea0183_sentence_rot(data_tvb, pinfo, nmea0183_tree);
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

void proto_register_nmea0183(void)
{
    expert_module_t *expert_nmea0183;

    static hf_register_info hf[] = {
        {&hf_nmea0183_talker_id,
         {"Talker ID", "nmea0183.talker",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 Talker ID", HFILL}},
        {&hf_nmea0183_sentence_id,
         {"Sentence ID", "nmea0183.sentence",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 Sentence ID", HFILL}},
        {&hf_nmea0183_unknown_field,
         {"Field", "nmea0183.unknown_field",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 Unknown field", HFILL}},
        {&hf_nmea0183_checksum,
         {"Checksum", "nmea0183.checksum",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 Checksum", HFILL}},
        {&hf_nmea0183_checksum_calculated,
         {"Calculated checksum", "nmea0183.checksum_calculated",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          "NMEA 0183 Calculated checksum", HFILL}},
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
          "NMEA 0183 GGA UTC Time field", HFILL}},
        {&hf_nmea0183_gga_time_hour,
         {"Hour", "nmea0183.gga_time_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA UTC hour", HFILL}},
        {&hf_nmea0183_gga_time_minute,
         {"Minute", "nmea0183.gga_time_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA UTC minute", HFILL}},
        {&hf_nmea0183_gga_time_second,
         {"Second", "nmea0183.gga_time_second",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA UTC second", HFILL}},
        {&hf_nmea0183_gga_latitude,
         {"Latitude", "nmea0183.gga_latitude",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Latitude field", HFILL}},
        {&hf_nmea0183_gga_latitude_degree,
         {"Degree", "nmea0183.gga_latitude_degree",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Latitude Degree", HFILL}},
        {&hf_nmea0183_gga_latitude_minute,
         {"Minute", "nmea0183.gga_latitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Latitude Minute", HFILL}},
        {&hf_nmea0183_gga_latitude_direction,
         {"Direction", "nmea0183.gga_latitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Latitude Direction", HFILL}},
        {&hf_nmea0183_gga_longitude,
         {"Longitude", "nmea0183.gga_longitude",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Longitude field", HFILL}},
        {&hf_nmea0183_gga_longitude_degree,
         {"Degree", "nmea0183.gga_longitude_degree",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Longitude Degree", HFILL}},
        {&hf_nmea0183_gga_longitude_minute,
         {"Minute", "nmea0183.gga_longitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Longitude Minute", HFILL}},
        {&hf_nmea0183_gga_longitude_direction,
         {"Direction", "nmea0183.gga_longitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Longitude Direction", HFILL}},
        {&hf_nmea0183_gga_quality,
         {"Quality indicator", "nmea0183.gga_quality",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Quality indicator", HFILL}},
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
          "NMEA 0183 GGA Age of differential GPS data in seconds", HFILL}},
        {&hf_nmea0183_gga_dgps_station,
         {"Differential GPS station id", "nmea0183.gga_dgps_station",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GGA Differential reference station ID", HFILL}},
        {&hf_nmea0183_gll_latitude,
         {"Latitude", "nmea0183.gll_latitude",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Latitude field", HFILL}},
        {&hf_nmea0183_gll_latitude_degree,
         {"Degree", "nmea0183.gll_latitude_degree",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Latitude Degree", HFILL}},
        {&hf_nmea0183_gll_latitude_minute,
         {"Minute", "nmea0183.gll_latitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Latitude Minute", HFILL}},
        {&hf_nmea0183_gll_latitude_direction,
         {"Direction", "nmea0183.gll_latitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Latitude Direction", HFILL}},
        {&hf_nmea0183_gll_longitude,
         {"Longitude", "nmea0183.gll_longitude",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Longitude field", HFILL}},
        {&hf_nmea0183_gll_longitude_degree,
         {"Degree", "nmea0183.gll_longitude_degree",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Longitude Degree", HFILL}},
        {&hf_nmea0183_gll_longitude_minute,
         {"Minute", "nmea0183.gll_longitude_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Longitude Minute", HFILL}},
        {&hf_nmea0183_gll_longitude_direction,
         {"Direction", "nmea0183.gll_longitude_direction",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Longitude Direction", HFILL}},
        {&hf_nmea0183_gll_time,
         {"UTC Time of position", "nmea0183.gll_time",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL UTC Time field", HFILL}},
        {&hf_nmea0183_gll_time_hour,
         {"Hour", "nmea0183.gll_time_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL UTC hour", HFILL}},
        {&hf_nmea0183_gll_time_minute,
         {"Minute", "nmea0183.gll_time_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL UTC minute", HFILL}},
        {&hf_nmea0183_gll_time_second,
         {"Second", "nmea0183.gll_time_second",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL UTC second", HFILL}},
        {&hf_nmea0183_gll_status,
         {"Status", "nmea0183.gll_status",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL Status", HFILL}},
        {&hf_nmea0183_gll_mode,
         {"FAA mode", "nmea0183.gll_mode",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 GLL FAA mode indicator (NMEA 2.3 and later)", HFILL}},
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
        {&hf_nmea0183_zda_time,
         {"UTC Time", "nmea0183.zda_time",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA UTC Time field", HFILL}},
        {&hf_nmea0183_zda_time_hour,
         {"Hour", "nmea0183.zda_time_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA UTC hour", HFILL}},
        {&hf_nmea0183_zda_time_minute,
         {"Minute", "nmea0183.zda_time_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA UTC minute", HFILL}},
        {&hf_nmea0183_zda_time_second,
         {"Second", "nmea0183.zda_time_second",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA UTC second", HFILL}},
        {&hf_nmea0183_zda_date_day,
         {"Day", "nmea0183.zda_date_day",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA Day field", HFILL}},
        {&hf_nmea0183_zda_date_month,
         {"Month", "nmea0183.zda_date_month",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA Month field", HFILL}},
        {&hf_nmea0183_zda_date_year,
         {"Year", "nmea0183.zda_date_year",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA Year field", HFILL}},
        {&hf_nmea0183_zda_local_zone_hour,
         {"Local zone hour", "nmea0183.zda_local_zone_hour",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA Local zone hour field", HFILL}},
        {&hf_nmea0183_zda_local_zone_minute,
         {"Local zone minute", "nmea0183.zda_local_zone_minute",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "NMEA 0183 ZDA Local zone minute field", HFILL}}};

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
        &ett_nmea0183_gll_longitude};

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
          "Incorrect geoidal separation unit (should be 'M')", EXPFILL}}};

    proto_nmea0183 = proto_register_protocol("NMEA 0183 protocol", "NMEA 0183", "nmea0183");

    proto_register_field_array(proto_nmea0183, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_nmea0183 = expert_register_protocol(proto_nmea0183);
    expert_register_field_array(expert_nmea0183, ei, array_length(ei));
}

void proto_reg_handoff_nmea0183(void)
{
    static dissector_handle_t nmea0183_handle;

    nmea0183_handle = create_dissector_handle(dissect_nmea0183, proto_nmea0183);
    dissector_add_for_decode_as_with_preference("udp.port", nmea0183_handle);
}
