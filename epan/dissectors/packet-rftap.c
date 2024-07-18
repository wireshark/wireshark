/*
 *  packet-rftap.c
 *  Decode packets with a RFtap header
 *  Copyright 2016, Jonathan Brucker <jonathan.brucke@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The RFtap header is a simple meta-data header designed to provide
 * RF (Radio Frequency) meta-data about frames, such as:
 * - Accurate signal and noise power
 * - Accurate timing and phase information
 * - Accurate carrier and Doppler frequencies, and more.
 * The RFtap protocol can be used to encapsulate any type of frame.
 *
 * Official specification:
 * https://rftap.github.io
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_rftap(void);
void proto_register_rftap(void);

/* protocols */
static int proto_rftap;

/* rftap fixed fields */
static int hf_rftap_fixed_header;
static int hf_rftap_magic;
static int hf_rftap_len;    /* length in bytes */
static int hf_rftap_flags;

/* rftap flags bit-field (16 bits) */
static int hf_rftap_present_dlt;
static int hf_rftap_present_freq;
static int hf_rftap_present_nomfreq;
static int hf_rftap_present_freqofs;
static int hf_rftap_power_is_in_dbm;
static int hf_rftap_present_signal_power;
static int hf_rftap_present_noise_power;
static int hf_rftap_present_snr;
static int hf_rftap_present_signal_quality;
static int hf_rftap_time_is_unix_time;
static int hf_rftap_present_time;
static int hf_rftap_present_duration;
static int hf_rftap_present_location;
static int hf_rftap_present_reserved_field_13;
static int hf_rftap_present_reserved_field_14;
static int hf_rftap_present_reserved_field_15;

/* rftap optional fields */
static int hf_rftap_dlt;
static int hf_rftap_freq;
static int hf_rftap_nomfreq;
static int hf_rftap_freqofs;
static int hf_rftap_signal_power;
static int hf_rftap_noise_power;
static int hf_rftap_snr;
static int hf_rftap_signal_quality;
static int hf_rftap_time_int;
static int hf_rftap_time_frac;
static int hf_rftap_time;
static int hf_rftap_duration;
static int hf_rftap_latitude;
static int hf_rftap_longitude;
static int hf_rftap_altitude;

/* rftap tag IDs >= 16 */
static int hf_rftap_subdissector_name;

/* subtree pointers */
static int ett_rftap;
static int ett_rftap_fixed_header;
static int ett_rftap_flags;

static dissector_handle_t pcap_pktdata_handle;

#define RFTAP_MAGIC 0x61744652UL  /* "RFta" */

enum rftap_tag_id {
    RFTAP_TAG_DLT = 0,
    RFTAP_TAG_FREQ = 1,
    RFTAP_TAG_NOM_FREQ = 2,
    RFTAP_TAG_FREQ_OFS = 3,
    RFTAP_TAG_POWER_IS_IN_DBM = 4,
    RFTAP_TAG_SIGNAL_POWER = 5,
    RFTAP_TAG_NOISE_POWER = 6,
    RFTAP_TAG_SNR = 7,
    RFTAP_TAG_SIGNAL_QUALITY = 8,
    RFTAP_TAG_TIME_IS_UNIX_TIME = 9,
    RFTAP_TAG_TIME = 10,
    RFTAP_TAG_DURATION = 11,
    RFTAP_TAG_LOCATION = 12,
    RFTAP_TAG_RESERVED_13 = 13,
    RFTAP_TAG_RESERVED_14 = 14,
    RFTAP_TAG_RESERVED_15 = 15,
    RFTAP_TAG_DISSECTOR_NAME = 16
};

/* This is the header as it is used by rftap-generating software.
 * It is not used by the wireshark dissector and provided for reference only.
struct rftap_hdr {
    le32 magic;  // "RFta"
    le16 len32;  // sizeof(rftap_hdr) / sizeof(le32)
    le16 flags;  // bitfield indicating presence of parameters
    le32 data[];
} __attribute__((packed));
 */

/* dissect the rftap header part of the packet
 * returns Data Link Type (dlt) and subdissector name
 */
static void
dissect_rftap_header(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t *dlt, const uint8_t **subdissector_name)
{
    proto_item *ti_header;
    proto_tree *header_tree;
    int32_t offset;
    int32_t len;
    uint64_t flags;
    uint32_t flag_bit;
    uint32_t tag_id;
    int32_t tag_len;
    uint32_t tag_flags;
    double double_val;
    float   float_val;
    char    *power_units;

    static int * const flag_fields[] = {
        &hf_rftap_present_dlt,
        &hf_rftap_present_freq,
        &hf_rftap_present_nomfreq,
        &hf_rftap_present_freqofs,
        &hf_rftap_power_is_in_dbm,
        &hf_rftap_present_signal_power,
        &hf_rftap_present_noise_power,
        &hf_rftap_present_snr,
        &hf_rftap_present_signal_quality,
        &hf_rftap_time_is_unix_time,
        &hf_rftap_present_time,
        &hf_rftap_present_duration,
        &hf_rftap_present_location,
        &hf_rftap_present_reserved_field_13,
        &hf_rftap_present_reserved_field_14,
        &hf_rftap_present_reserved_field_15,
        NULL
    };

    *dlt = 0xffffffff;
    *subdissector_name = NULL;

    /* rftap fixed header sub-tree */

    ti_header = proto_tree_add_item(tree, hf_rftap_fixed_header, tvb, 0, 8, ENC_NA);
    header_tree = proto_item_add_subtree(ti_header, ett_rftap_fixed_header);

    proto_tree_add_item(header_tree, hf_rftap_magic, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    len = 4 * (int32_t) tvb_get_letohs(tvb, 4);  /* convert to length in bytes */
    proto_tree_add_uint(header_tree, hf_rftap_len, tvb, 4, 2, len);  /* show length in bytes */
    proto_tree_add_bitmask_ret_uint64(header_tree, tvb, 6, hf_rftap_flags,
        ett_rftap_flags, flag_fields, ENC_LITTLE_ENDIAN, &flags);

    /* rftap parameter fields */

    power_units = (flags & (1 << RFTAP_TAG_POWER_IS_IN_DBM)) ? "dBm" : "dB";

    offset = 8;
    flag_bit = 1;
    for (tag_id = 0; tag_id < 16; tag_id++, flag_bit<<=1) {

        if (!(flags & flag_bit))
            continue;  /* parameter is not present, skip */

        switch (tag_id) {
        case RFTAP_TAG_DLT:
            proto_tree_add_item_ret_uint(tree, hf_rftap_dlt, tvb, offset, 4, ENC_LITTLE_ENDIAN, dlt);
            offset += 4;
            break;
        case RFTAP_TAG_FREQ:
            proto_tree_add_item(tree, hf_rftap_freq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case RFTAP_TAG_NOM_FREQ:
            proto_tree_add_item(tree, hf_rftap_nomfreq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case RFTAP_TAG_FREQ_OFS:
            proto_tree_add_item(tree, hf_rftap_freqofs, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case RFTAP_TAG_POWER_IS_IN_DBM:
            /* do nothing, it's already decoded in flags bit-field */
            break;
        case RFTAP_TAG_SIGNAL_POWER:
            float_val = tvb_get_letohieee_float(tvb, offset);
            proto_tree_add_float_format_value(tree, hf_rftap_signal_power, tvb, offset, 4, float_val, "%.2f %s", float_val, power_units);
            offset += 4;
            break;
        case RFTAP_TAG_NOISE_POWER:
            float_val = tvb_get_letohieee_float(tvb, offset);
            proto_tree_add_float_format_value(tree, hf_rftap_noise_power, tvb, offset, 4, float_val, "%.2f %s", float_val, power_units);
            offset += 4;
            break;
        case RFTAP_TAG_SNR:
            float_val = tvb_get_letohieee_float(tvb, offset);
            proto_tree_add_float_format_value(tree, hf_rftap_snr, tvb, offset, 4, float_val, "%.2f dB", float_val);
            offset += 4;
            break;
        case RFTAP_TAG_SIGNAL_QUALITY:
            proto_tree_add_item(tree, hf_rftap_signal_quality, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case RFTAP_TAG_TIME_IS_UNIX_TIME:
            /* do nothing, it's already decoded in flags bit-field */
            break;
        case RFTAP_TAG_TIME:
            double_val = tvb_get_letohieee_double(tvb, offset);
            proto_tree_add_double_format_value(tree, hf_rftap_time_int, tvb, offset, 8, double_val, "%.0f seconds", double_val);
            double_val = tvb_get_letohieee_double(tvb, offset + 8);
            proto_tree_add_double_format_value(tree, hf_rftap_time_frac, tvb, offset+8, 8, double_val, "%.9f seconds", double_val);
            /* compute combined time: (not accurate, error is > 300 nanoseconds) */
            double_val += tvb_get_letohieee_double(tvb, offset);
            proto_tree_add_double_format_value(tree, hf_rftap_time, tvb, offset, 16, double_val, "%.6f seconds", double_val);
            offset += 16;
            break;
        case RFTAP_TAG_DURATION:
            proto_tree_add_item(tree, hf_rftap_duration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case RFTAP_TAG_LOCATION:
            proto_tree_add_item(tree, hf_rftap_latitude, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_rftap_longitude, tvb, offset+8, 8, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_rftap_altitude, tvb, offset+16, 8, ENC_LITTLE_ENDIAN);
            offset += 24;
            break;
        default:
            return;  /* we've hit a parameter we can't decode, abort */
        }
    }

    if (offset >= len)
        return;  /* there are no tagged parameters to decode, goodbye */

    /* rftap tagged parameter fields */

    tag_id = tvb_get_letohs(tvb, offset);
    tag_len = tvb_get_uint8(tvb, offset+2);
    tag_flags = tvb_get_uint8(tvb, offset+3);

    if ((tag_id != RFTAP_TAG_DISSECTOR_NAME) || (tag_len == 0) || (tag_len == 255) || (tag_flags != 255))
        return;  /* we've hit a tagged parameter we can't decode, abort */

    proto_tree_add_item_ret_string(tree, hf_rftap_subdissector_name, tvb,
        offset+4, tag_len, ENC_ASCII, pinfo->pool, subdissector_name);
}

/* Main entry point to dissect the packets.
 *
 * Each packet consists of two parts:
 * - The rftap header, containing all the RF metadata.
 * - The encapsulated data packet, decoded by a sub-dissector.
 */
static int
dissect_rftap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *rftap_tree;

    tvbuff_t   *rftap_tvb;  /* the first part of the packet */
    tvbuff_t   *subdissector_tvb;  /* the second part of the packet */

    int32_t     rftap_len;  /* length in bytes */
    dissector_handle_t subdissector_handle;
    uint32_t    subdissector_dlt;
    const uint8_t *subdissector_name;

    /* heuristics */

    if (tvb_captured_length(tvb) < 8)  /* 4 magic + 2 len + 2 flags = 8 bytes */
        return 0;

    if (tvb_get_letohl(tvb, 0) != RFTAP_MAGIC)
        return 0;

    /* column info */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RFTAP");
    col_clear(pinfo->cinfo, COL_INFO);
    clear_address(&pinfo->src);
    clear_address(&pinfo->dst);

    /* dissect part 1: rftap header */

    rftap_len = 4 * (int32_t) tvb_get_letohs(tvb, 4);
    rftap_tvb = tvb_new_subset_length_caplen(tvb, 0, rftap_len, rftap_len);

    ti = proto_tree_add_protocol_format(tree, proto_rftap, rftap_tvb, 0, -1,
        "RFtap Protocol (%d bytes)", rftap_len);
    rftap_tree = proto_item_add_subtree(ti, ett_rftap);

    dissect_rftap_header(rftap_tvb, rftap_tree, pinfo, &subdissector_dlt, &subdissector_name);

    /* dissect part 2: data packet */

    subdissector_tvb = tvb_new_subset_remaining(tvb, rftap_len);

    /* try using data link type (DLT) */
    if (subdissector_dlt != 0xffffffff) {
        call_dissector_with_data(pcap_pktdata_handle, subdissector_tvb, pinfo, tree, &subdissector_dlt);
        return tvb_captured_length(tvb);
    }

    /* try using dissector name */
    if (subdissector_name) {
        subdissector_handle = find_dissector(subdissector_name);
        if (subdissector_handle) {
            call_dissector_with_data(subdissector_handle, subdissector_tvb, pinfo, tree, NULL);
            return tvb_captured_length(tvb);
        }
    }

    /* fallback using plain data dissector */
    call_data_dissector(subdissector_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

static bool
dissect_rftap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_rftap(tvb, pinfo, tree, data) != 0;
}

/* Register the protocol with Wireshark. */
void
proto_register_rftap(void)
{
    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_rftap,
        &ett_rftap_fixed_header,
        &ett_rftap_flags
    };

    /* Setup list of header fields */
    static hf_register_info hf[] = {

        /* rftap fixed header */

        { &hf_rftap_fixed_header, {
            "RFtap Fixed header",
            "rftap.fixedheader",
            FT_NONE, BASE_NONE, NULL, 0,
            "RFtap Fixed 8-byte Header", HFILL }},

        { &hf_rftap_magic, {
            "Magic",
            "rftap.magic",
            FT_UINT32, BASE_HEX, NULL, 0,
            "RFtap signature: wikipedia.org/wiki/File_format#Magic_number", HFILL }},
        { &hf_rftap_len, {
            "Length",
            "rftap.len",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Length (in bytes) of entire rftap header, including tagged (optional) parameters", HFILL }},
        { &hf_rftap_flags, {
            "Flags",
            "rftap.flags",
            FT_UINT16, BASE_HEX, NULL, 0,
            "RFtap flags", HFILL }},

        /* flags bit-field */

        {&hf_rftap_present_dlt, {
            "DLT Present",
            "rftap.present.dlt",
            FT_BOOLEAN, 16, NULL, 0x0001,
            "Specifies if the DLT (Data Link Type) field is present", HFILL }},
        {&hf_rftap_present_freq, {
            "Frequency Present",
            "rftap.present.freq",
            FT_BOOLEAN, 16, NULL, 0x0002,
            "Specifies if the Frequency field is present", HFILL }},
        {&hf_rftap_present_nomfreq, {
            "Nominal Frequency Present",
            "rftap.present.nomfreq",
            FT_BOOLEAN, 16, NULL, 0x0004,
            "Specifies if the Nominal Frequency field is present", HFILL }},
        {&hf_rftap_present_freqofs, {
            "Frequency Offset Present",
            "rftap.present.freqofs",
            FT_BOOLEAN, 16, NULL, 0x0008,
            "Specifies if the Frequency Offset field is present", HFILL }},
        {&hf_rftap_power_is_in_dbm, {
            "Power is in dBm Units",
            "rftap.isdbm",
            FT_BOOLEAN, 16, NULL, 0x0010,
            "Specifies if the Power is specified in dBm units", HFILL }},
        {&hf_rftap_present_signal_power, {
            "Signal Power Present",
            "rftap.present.power",
            FT_BOOLEAN, 16, NULL, 0x0020,
            "Specifies if the Signal Power field is present", HFILL }},
        {&hf_rftap_present_noise_power, {
            "Noise Power Present",
            "rftap.present.noise",
            FT_BOOLEAN, 16, NULL, 0x0040,
            "Specifies if the Noise Power field is present", HFILL }},
        {&hf_rftap_present_snr, {
            "SNR Present",
            "rftap.present.snr",
            FT_BOOLEAN, 16, NULL, 0x0080,
            "Specifies if the SNR field is present", HFILL }},
        {&hf_rftap_present_signal_quality, {
            "Signal Quality Present",
            "rftap.present.qual",
            FT_BOOLEAN, 16, NULL, 0x0100,
            "Specifies if the Signal Quality field is present", HFILL }},
        {&hf_rftap_time_is_unix_time, {
            "Time standard is Unix Time",
            "rftap.isunixtime",
            FT_BOOLEAN, 16, NULL, 0x0200,
            "Specifies if the time standard is Unix Time: wikipedia.org/wiki/Unix_time", HFILL }},
        {&hf_rftap_present_time, {
            "Time Present",
            "rftap.present.time",
            FT_BOOLEAN, 16, NULL, 0x0400,
            "Specifies if the Time field is present", HFILL }},
        {&hf_rftap_present_duration, {
            "Duration Present",
            "rftap.present.duration",
            FT_BOOLEAN, 16, NULL, 0x0800,
            "Specifies if the Duration field is present", HFILL }},
        {&hf_rftap_present_location, {
            "Location Present",
            "rftap.present.location",
            FT_BOOLEAN, 16, NULL, 0x1000,
            "Specifies if the Location field is present", HFILL }},
        {&hf_rftap_present_reserved_field_13, {
            "Reserved Field 13 Present",
            "rftap.present.field13",
            FT_BOOLEAN, 16, NULL, 0x2000,
            "Specifies if the Reserved Field 13 is present", HFILL }},
        {&hf_rftap_present_reserved_field_14, {
            "Reserved Field 14 Present",
            "rftap.present.field14",
            FT_BOOLEAN, 16, NULL, 0x4000,
            "Specifies if the Reserved Field 14 is present", HFILL }},
        {&hf_rftap_present_reserved_field_15, {
            "Reserved Field 15 Present",
            "rftap.present.field15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            "Specifies if the Reserved Field 15 is present", HFILL }},

        /* rftap parameters */

        { &hf_rftap_dlt, {
            "Data Link Type (DLT)",
            "rftap.dlt",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Data Link Type (DLT) of the encapsulated packet: www.tcpdump.org/linktypes.html", HFILL }},
        { &hf_rftap_freq, {
            "Frequency",
            "rftap.freq",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_hz, 0,
            "Actual (measured) carrier frequency, in Hertz (not necessarily center frequency)", HFILL }},
        { &hf_rftap_nomfreq, {
            "Nominal Frequency",
            "rftap.nomfreq",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_hz, 0,
            "Nominal carrier frequency, in Hertz (the ideal frequency, ignoring freq errors)", HFILL }},
        { &hf_rftap_freqofs, {
            "Frequency Offset",
            "rftap.freqofs",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_hz, 0,
            "Carrier frequency offset, in Hertz: wikipedia.org/wiki/Carrier_frequency_offset", HFILL }},
        { &hf_rftap_signal_power, {
            "Signal Power",
            "rftap.power",
            FT_FLOAT, BASE_NONE, NULL, 0,
            "Signal power, in dB or dBm units: wikipedia.org/wiki/DBm", HFILL }},
        { &hf_rftap_noise_power, {
            "Noise Power",
            "rftap.noise",
            FT_FLOAT, BASE_NONE, NULL, 0,
            "Noise power, in dB or dBm units: wikipedia.org/wiki/DBm", HFILL }},
        { &hf_rftap_snr, {
            "SNR",
            "rftap.snr",
            FT_FLOAT, BASE_NONE, NULL, 0,
            "Signal to Noise ratio (decibel units): wikipedia.org/wiki/Signal-to-noise_ratio", HFILL }},
        { &hf_rftap_signal_quality, {
            "Signal Quality",
            "rftap.qual",
            FT_FLOAT, BASE_NONE, NULL, 0,
            "Signal quality, arbitrary units from 0.0 (worst) to 1.0 (best)", HFILL }},
        { &hf_rftap_time_int, {
            "Time (integer part)",
            "rftap.timeint",
            FT_DOUBLE, BASE_NONE, NULL, 0,
            "The integer part of event time, in seconds, since epoch: wikipedia.org/wiki/Epoch_(reference_date)", HFILL }},
        { &hf_rftap_time_frac, {
            "Time (fractional part)",
            "rftap.timefrac",
            FT_DOUBLE, BASE_NONE, NULL, 0,
            "The fractional part of event time, in seconds, since epoch: wikipedia.org/wiki/Epoch_(reference_date)", HFILL }},
        { &hf_rftap_time, {
            "Time",
            "rftap.time",
            FT_DOUBLE, BASE_NONE, NULL, 0,
            "The event time, in seconds, since epoch: wikipedia.org/wiki/Epoch_(reference_date)", HFILL }},
        { &hf_rftap_duration, {
            "Duration",
            "rftap.duration",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_second_seconds, 0,
            "The duration of the event (packet), in seconds", HFILL }},
        { &hf_rftap_latitude, {
            "Latitude",
            "rftap.lat",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_degree_degrees, 0,
            "Latitude of receiver (-90..90 degrees), using WGS 84 datum: wikipedia.org/wiki/World_Geodetic_System", HFILL }},
        { &hf_rftap_longitude, {
            "Longitude",
            "rftap.lon",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_degree_degrees, 0,
            "Longitude of receiver (-180..180 degrees), using WGS 84 datum: wikipedia.org/wiki/World_Geodetic_System", HFILL }},
        { &hf_rftap_altitude, {
            "Altitude",
            "rftap.alt",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_meter_meters, 0,
            "Altitude of receiver, in meters, using WGS 84 datum: wikipedia.org/wiki/World_Geodetic_System", HFILL }},

        /* rftap tagged parameters */

        { &hf_rftap_subdissector_name, {
            "Dissector Name",
            "rftap.dissector",
            FT_STRING, BASE_NONE, NULL, 0,
            "Name of sub-dissector used for packet data (alternative to DLT field)", HFILL }}
    };

    /* Register the protocol name and description */
    proto_rftap = proto_register_protocol("RFtap Protocol", "RFtap", "rftap");

    /* Register the header fields and subtrees */
    proto_register_field_array(proto_rftap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("rftap", dissect_rftap, proto_rftap);
}


/* Protocol registration routine. This function is also called by
 * Wireshark's preferences manager whenever "Apply" or "OK" are pressed.
 */
void
proto_reg_handoff_rftap(void)
{
    pcap_pktdata_handle = find_dissector_add_dependency("pcap_pktdata", proto_rftap);
    heur_dissector_add("udp", dissect_rftap_heur, "RFtap over UDP", "rftap", proto_rftap, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
