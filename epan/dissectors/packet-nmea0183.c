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

static int ett_nmea0183;
static int ett_nmea0183_checksum;
static int ett_nmea0183_sentence;

static expert_field ei_nmea0183_invalid_first_character;
static expert_field ei_nmea0183_missing_checksum_character;
static expert_field ei_nmea0183_invalid_end_of_line;
static expert_field ei_nmea0183_checksum_incorrect;
static expert_field ei_nmea0183_sentence_too_long;

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
    {"TRS", "TRANSIT Satellite Operating Statu"},
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

static uint8_t calculate_checksum(tvbuff_t *tvb, const gint start, const gint length)
{
    uint8_t checksum = 0;
    for (gint i = start; i < start + length; i++)
    {
        checksum ^= tvb_get_guint8(tvb, i);
    }
    return checksum;
}

/* Find first occurrence of a field separator in tvbuff, starting at offset. Searches
 * to end of tvbuff.
 * Returns the offset of the found separator, or offset of end of tvbuff if not found. */
static gint
tvb_find_end_of_nmea0183_field(tvbuff_t *tvb, const gint offset)
{
    gint end_of_field_offset = tvb_find_guint8(tvb, offset, -1, ',');
    if (end_of_field_offset == -1)
    {
        return tvb_captured_length(tvb);
    }
    return end_of_field_offset;
}

/* Dissect a sentence where the sentence id is unknown. Each field is shown as an generic field. */
static int
dissect_nmea0183_sentence(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset = 0;

    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset,
                                                 tvb_captured_length(tvb), ett_nmea0183_sentence,
                                                 NULL, "Unknown sentence");

    /* In an unknown sentence, the name of each field is unknown. Find all field by splitting at a comma. */
    while (tvb_captured_length_remaining(tvb, offset) > 0)
    {
        gint end_of_field_offset = tvb_find_end_of_nmea0183_field(tvb, offset);
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
    gint offset = 0;
    gint start_checksum_offset = 0;
    const guint8 *talker_id = NULL;
    const guint8 *sentence_id = NULL;
    const guint8 *checksum = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NMEA 0183");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_nmea0183, tvb, 0, -1, ENC_NA);
    proto_tree *nmea0183_tree = proto_item_add_subtree(ti, ett_nmea0183);

    /* Start delimiter */
    if (tvb_get_guint8(tvb, offset) != '$')
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
    offset += dissect_nmea0183_sentence(data_tvb, pinfo, nmea0183_tree);

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

    proto_item *checksum_tree = proto_item_add_subtree(ti, ett_nmea0183_checksum);
    ti = proto_tree_add_uint(checksum_tree, hf_nmea0183_checksum_calculated,
                             tvb, offset, 2, calculated_checksum);
    proto_item_set_generated(ti);

    offset += 2;

    /* End of line */
    if (tvb_get_guint8(tvb, offset) != '\r' || tvb_get_guint8(tvb, offset + 1) != '\n')
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
          "NMEA 0183 Calculated checksum", HFILL}}};

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_nmea0183,
        &ett_nmea0183_checksum,
        &ett_nmea0183_sentence};

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
          "Sentence is too long. Maximum is 82 bytes including $ and <CR><LF>", EXPFILL}}};

    proto_nmea0183 = proto_register_protocol(
        "NMEA 0183 protocol", /* name        */
        "NMEA 0183",          /* short name  */
        "nmea0183"            /* filter_name */
    );

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
