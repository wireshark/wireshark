/* packet-wsa.c
 * Routines for IEEE 1609.3 WAVE Service Advertisement (WSA) dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: IEEE Std 1609.3-2020, clause 8.2 (WSA) and Annex J (WAVE extension
 * elements). The WSA is carried as IEEE 1609.2 data under PSID 0x87 and is
 * encoded with unaligned PER (UPER). This dissector walks the UPER bit
 * stream directly; it is not generated from the IEEE ASN.1 modules.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>

#include "packet-ieee1609dot2.h"

void proto_register_wsa(void);
void proto_reg_handoff_wsa(void);

static dissector_handle_t wsa_handle;

static int proto_wsa;

static int hf_wsa_version;
static int hf_wsa_hdr_ext_present;
static int hf_wsa_svc_present;
static int hf_wsa_chan_present;
static int hf_wsa_wra_present;
static int hf_wsa_id;
static int hf_wsa_content_count;

static int hf_wsa_ext_count;
static int hf_wsa_ext_id;
static int hf_wsa_ext_len;
static int hf_wsa_ext_data;

static int hf_wsa_svc_count;
static int hf_wsa_svc_psid;
static int hf_wsa_svc_chan_index;
static int hf_wsa_svc_reserved;
static int hf_wsa_svc_ext_present;

static int hf_wsa_chan_count;
static int hf_wsa_chan_op_class;
static int hf_wsa_chan_number;
static int hf_wsa_chan_tx_power;
static int hf_wsa_chan_adaptable;
static int hf_wsa_chan_data_rate;
static int hf_wsa_chan_reserved;
static int hf_wsa_chan_ext_present;

static int hf_wsa_wra_lifetime;
static int hf_wsa_wra_prefix;
static int hf_wsa_wra_prefix_len;
static int hf_wsa_wra_gateway;
static int hf_wsa_wra_dns;

/* Extension element values */
static int hf_wsa_latitude;
static int hf_wsa_longitude;
static int hf_wsa_elevation;
static int hf_wsa_advertiser_id;
static int hf_wsa_psc;
static int hf_wsa_ipv6;
static int hf_wsa_port;
static int hf_wsa_mac;
static int hf_wsa_channel_number;
static int hf_wsa_data_rate;
static int hf_wsa_tx_power;
static int hf_wsa_repeat_rate;
static int hf_wsa_rcpi_threshold;
static int hf_wsa_count_threshold;
static int hf_wsa_count_threshold_interval;
static int hf_wsa_channel_access;
static int hf_wsa_protocol_type;
static int hf_wsa_app_data;
static int hf_wsa_edca_aci;
static int hf_wsa_edca_acm;
static int hf_wsa_edca_aifsn;
static int hf_wsa_edca_ecw_max;
static int hf_wsa_edca_ecw_min;
static int hf_wsa_edca_txop;

static int ett_wsa;
static int ett_wsa_hdr;
static int ett_wsa_exts;
static int ett_wsa_ext;
static int ett_wsa_svcs;
static int ett_wsa_svc;
static int ett_wsa_chans;
static int ett_wsa_chan;
static int ett_wsa_wra;
static int ett_wsa_edca;

static expert_field ei_wsa_version;
static expert_field ei_wsa_fragmented;
static expert_field ei_wsa_lat_range;
static expert_field ei_wsa_lon_range;
static expert_field ei_wsa_fill_nonzero;
static expert_field ei_wsa_chan_index;
static expert_field ei_wsa_trailing;
static expert_field ei_wsa_psid_ext;

#define WSA_VERSION 3

/* Latitude / longitude bounds in units of 0.1 microdegree */
#define LAT_MIN      (-900000000)
#define LAT_UNAVAIL  900000001
#define LON_MIN      (-1799999999)
#define LON_UNAVAIL  1800000001
#define ELEV_MIN     (-4096)

/* WAVE extension element IDs used in a WSA */
#define EXT_TX_POWER          4
#define EXT_2D_LOCATION       5
#define EXT_3D_LOCATION       6
#define EXT_ADVERTISER_ID     7
#define EXT_PSC               8
#define EXT_IPV6_ADDRESS      9
#define EXT_SERVICE_PORT     10
#define EXT_PROVIDER_MAC     11
#define EXT_EDCA_PARAMS      12
#define EXT_SECONDARY_DNS    13
#define EXT_GATEWAY_MAC      14
#define EXT_CHANNEL_NUMBER   15
#define EXT_DATA_RATE        16
#define EXT_REPEAT_RATE      17
#define EXT_RCPI_THRESHOLD   19
#define EXT_COUNT_THRESHOLD  20
#define EXT_CHANNEL_ACCESS   21
#define EXT_COUNT_THRES_INT  22
#define EXT_CHANNEL_LOAD     23
#define EXT_PROTOCOL_TYPE    24
#define EXT_TIME_CONFIDENCE  25
#define EXT_SA_SIGNER        26
#define EXT_EXT_CHAN_INFOS   84
#define EXT_APPLICATION_DATA 85

static const value_string wsa_ext_id_vals[] = {
    { EXT_TX_POWER,         "Transmit Power Used" },
    { EXT_2D_LOCATION,      "2D Location" },
    { EXT_3D_LOCATION,      "3D Location" },
    { EXT_ADVERTISER_ID,    "Advertiser Identifier" },
    { EXT_PSC,              "Provider Service Context" },
    { EXT_IPV6_ADDRESS,     "IPv6 Address" },
    { EXT_SERVICE_PORT,     "Service Port" },
    { EXT_PROVIDER_MAC,     "Provider MAC Address" },
    { EXT_EDCA_PARAMS,      "EDCA Parameter Set" },
    { EXT_SECONDARY_DNS,    "Secondary DNS" },
    { EXT_GATEWAY_MAC,      "Gateway MAC Address" },
    { EXT_CHANNEL_NUMBER,   "Channel Number" },
    { EXT_DATA_RATE,        "Data Rate" },
    { EXT_REPEAT_RATE,      "Repeat Rate" },
    { EXT_RCPI_THRESHOLD,   "RCPI Threshold" },
    { EXT_COUNT_THRESHOLD,  "WSA Count Threshold" },
    { EXT_CHANNEL_ACCESS,   "Channel Access" },
    { EXT_COUNT_THRES_INT,  "WSA Count Threshold Interval" },
    { EXT_CHANNEL_LOAD,     "Channel Load" },
    { EXT_PROTOCOL_TYPE,    "Protocol Type" },
    { EXT_TIME_CONFIDENCE,  "Compact Time Confidence" },
    { EXT_SA_SIGNER,        "Asserted By SA Signer" },
    { EXT_EXT_CHAN_INFOS,   "Extended Channel Infos" },
    { EXT_APPLICATION_DATA, "Application Data" },
    { 0, NULL }
};

static const value_string wsa_channel_access_vals[] = {
    { 0, "Continuous" },
    { 1, "Alternating, time slot 0" },
    { 2, "Alternating, time slot 1" },
    { 0, NULL }
};

static const value_string wsa_edca_aci_vals[] = {
    { 0, "AC_BE" },
    { 1, "AC_BK" },
    { 2, "AC_VI" },
    { 3, "AC_VO" },
    { 0, NULL }
};

/** Formats a latitude in 0.1 microdegree units as degrees. */
static void
wsa_fmt_lat(char *s, uint32_t v)
{
    int32_t lat = (int32_t)v;
    if (lat == LAT_UNAVAIL)
        snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", lat);
    else
        snprintf(s, ITEM_LABEL_LENGTH, "%.7f\xC2\xB0 (%d)", lat / 1e7, lat);
}

/** Formats a longitude in 0.1 microdegree units as degrees. */
static void
wsa_fmt_lon(char *s, uint32_t v)
{
    int32_t lon = (int32_t)v;
    if (lon == LON_UNAVAIL)
        snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", lon);
    else
        snprintf(s, ITEM_LABEL_LENGTH, "%.7f\xC2\xB0 (%d)", lon / 1e7, lon);
}

/** Formats an elevation in decimeters as meters. */
static void
wsa_fmt_elev(char *s, uint32_t v)
{
    int32_t elev = (int32_t)v;
    snprintf(s, ITEM_LABEL_LENGTH, "%.1f m (%d)", elev / 10.0, elev);
}

/** Formats a data rate in units of 500 kb/s. */
static void
wsa_fmt_rate(char *s, uint32_t v)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%u.%u Mb/s (%u)", v / 2, (v % 2) * 5, v);
}

/** First byte and byte span covering @p nbits bits starting at @p bo. */
#define BO_START(bo)        ((int)((bo) >> 3))
#define BO_SPAN(bo, nbits)  ((int)((((bo) + (nbits) + 7) >> 3) - ((bo) >> 3)))

/**
 * Reads an @p nbits wide unsigned field at *@p bo, adds it to @p tree as
 * @p hf (an unsigned or boolean field) and advances *@p bo.
 */
static uint32_t
wsa_add_bits(proto_tree *tree, int hf, tvbuff_t *tvb, unsigned *bo, unsigned nbits)
{
    uint32_t v = tvb_get_bits32(tvb, *bo, nbits, ENC_BIG_ENDIAN);
    proto_tree_add_uint(tree, hf, tvb, BO_START(*bo), BO_SPAN(*bo, nbits), v);
    *bo += nbits;
    return v;
}

/** Reads a 1-bit flag at *@p bo, adds it as boolean @p hf and advances *@p bo. */
static bool
wsa_add_flag(proto_tree *tree, int hf, tvbuff_t *tvb, unsigned *bo)
{
    bool v = tvb_get_bits8(tvb, *bo, 1) != 0;
    proto_tree_add_boolean(tree, hf, tvb, BO_START(*bo), 1, v);
    *bo += 1;
    return v;
}

/**
 * Reads an @p nbits wide constrained integer whose lower bound is @p lb
 * (UPER stores value - lb), adds it as signed field @p hf, advances *@p bo.
 */
static int32_t
wsa_add_int(proto_tree *tree, int hf, tvbuff_t *tvb, unsigned *bo, unsigned nbits,
            int64_t lb, proto_item **item)
{
    int32_t v = (int32_t)((int64_t)tvb_get_bits32(tvb, *bo, nbits, ENC_BIG_ENDIAN) + lb);
    proto_item *pi = proto_tree_add_int(tree, hf, tvb, BO_START(*bo), BO_SPAN(*bo, nbits), v);
    if (item)
        *item = pi;
    *bo += nbits;
    return v;
}

/**
 * Reads a UPER length determinant (unconstrained; 1 or 2 octets) at *@p bo.
 * Adds it as @p hf when @p hf > 0. Returns false on a fragmented length.
 */
static bool
wsa_length(proto_tree *tree, packet_info *pinfo, int hf, tvbuff_t *tvb, unsigned *bo,
           uint32_t *len)
{
    uint8_t b = tvb_get_bits8(tvb, *bo, 8);
    unsigned nbits;

    if ((b & 0x80) == 0) {
        *len = b;
        nbits = 8;
    } else if ((b & 0xC0) == 0x80) {
        *len = tvb_get_bits16(tvb, *bo, 16, ENC_BIG_ENDIAN) & 0x3FFF;
        nbits = 16;
    } else {
        proto_tree_add_expert(tree, pinfo, &ei_wsa_fragmented, tvb, BO_START(*bo), 1);
        return false;
    }
    if (hf > 0)
        proto_tree_add_uint(tree, hf, tvb, BO_START(*bo), BO_SPAN(*bo, nbits), *len);
    *bo += nbits;
    return true;
}

/**
 * Reads a VarLengthNumber (the p-encoded PSID / protocol type, 1-4 octets)
 * at *@p bo, adds it as @p hf and advances *@p bo. Returns the value.
 */
static uint32_t
wsa_var_length_number(proto_tree *tree, packet_info *pinfo, int hf, tvbuff_t *tvb, unsigned *bo)
{
    unsigned start = *bo;
    unsigned nbits;
    uint32_t val;

    if (tvb_get_bits8(tvb, start, 1) == 0) {
        val = tvb_get_bits8(tvb, start + 1, 7);
        nbits = 8;
    } else if (tvb_get_bits8(tvb, start + 1, 1) == 0) {
        val = 0x80 + tvb_get_bits16(tvb, start + 2, 14, ENC_BIG_ENDIAN);
        nbits = 16;
    } else if (tvb_get_bits8(tvb, start + 2, 1) == 0) {
        val = 0x4080 + tvb_get_bits32(tvb, start + 3, 21, ENC_BIG_ENDIAN);
        nbits = 24;
    } else if (tvb_get_bits8(tvb, start + 3, 1) == 0) {
        val = 0x204080 + tvb_get_bits32(tvb, start + 4, 28, ENC_BIG_ENDIAN);
        nbits = 32;
    } else {
        /* Beyond the 4-octet range: not used by any registered PSID */
        proto_tree_add_expert(tree, pinfo, &ei_wsa_psid_ext, tvb, BO_START(start), 1);
        THROW(ReportedBoundsError);
    }

    proto_tree_add_uint_format_value(tree, hf, tvb, BO_START(start), BO_SPAN(start, nbits), val,
            "%s (0x%x, p-encoded 0x%0*x)",
            val64_to_str_const(val, ieee1609dot2_Psid_vals, "Unknown"), val,
            nbits / 4, tvb_get_bits32(tvb, start, nbits, ENC_BIG_ENDIAN));
    *bo += nbits;
    return val;
}

/** Decodes a 2D/3D location extension value (octet aligned in @p tvb). */
static void
dissect_wsa_location(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool with_elev)
{
    unsigned bo = 0;
    proto_item *pi;
    int32_t v;

    /* Latitude is preceded by one fill bit that must be zero */
    if (tvb_get_bits8(tvb, bo, 1) != 0)
        proto_tree_add_expert(tree, pinfo, &ei_wsa_fill_nonzero, tvb, 0, 1);
    bo += 1;
    v = wsa_add_int(tree, hf_wsa_latitude, tvb, &bo, 31, LAT_MIN, &pi);
    if (v > LAT_UNAVAIL)
        expert_add_info(pinfo, pi, &ei_wsa_lat_range);
    v = wsa_add_int(tree, hf_wsa_longitude, tvb, &bo, 32, LON_MIN, &pi);
    if (v > LON_UNAVAIL)
        expert_add_info(pinfo, pi, &ei_wsa_lon_range);
    if (with_elev)
        wsa_add_int(tree, hf_wsa_elevation, tvb, &bo, 16, ELEV_MIN, NULL);
}

/** Decodes an EDCA Parameter Set extension value: four AC records. */
static void
dissect_wsa_edca(tvbuff_t *tvb, proto_tree *tree)
{
    unsigned bo = 0;

    for (int i = 0; i < 4; i++) {
        uint8_t aci = tvb_get_bits8(tvb, bo + 1, 2);
        proto_tree *rt = proto_tree_add_subtree_format(tree, tvb, BO_START(bo), 4, ett_wsa_edca,
                NULL, "EDCA Parameter Record: %s", val_to_str_const(aci, wsa_edca_aci_vals, "?"));
        bo += 1;    /* reserved */
        wsa_add_bits(rt, hf_wsa_edca_aci, tvb, &bo, 2);
        wsa_add_bits(rt, hf_wsa_edca_acm, tvb, &bo, 1);
        wsa_add_bits(rt, hf_wsa_edca_aifsn, tvb, &bo, 4);
        wsa_add_bits(rt, hf_wsa_edca_ecw_max, tvb, &bo, 4);
        wsa_add_bits(rt, hf_wsa_edca_ecw_min, tvb, &bo, 4);
        wsa_add_bits(rt, hf_wsa_edca_txop, tvb, &bo, 16);
    }
}

/**
 * Decodes one extension element value. @p tvb holds exactly the value's
 * octets (re-aligned), so every decoder starts at bit 0.
 */
static void
dissect_wsa_ext_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t id,
                      proto_item *ext_item)
{
    unsigned bo = 0;
    uint32_t len;

    switch (id) {
    case EXT_2D_LOCATION:
    case EXT_3D_LOCATION:
        dissect_wsa_location(tvb, pinfo, tree, id == EXT_3D_LOCATION);
        break;
    case EXT_ADVERTISER_ID:
        if (wsa_length(tree, pinfo, -1, tvb, &bo, &len)) {
            proto_tree_add_item(tree, hf_wsa_advertiser_id, tvb, BO_START(bo), len, ENC_UTF_8);
            proto_item_append_text(ext_item, ": %s",
                    tvb_format_text(pinfo->pool, tvb, BO_START(bo), len));
        }
        break;
    case EXT_PSC:
        /* Three fill bits, then a 5-bit length and the context octets */
        if (tvb_get_bits8(tvb, 0, 3) != 0)
            proto_tree_add_expert(tree, pinfo, &ei_wsa_fill_nonzero, tvb, 0, 1);
        len = tvb_get_bits8(tvb, 3, 5);
        proto_tree_add_item(tree, hf_wsa_psc, tvb, 1, len, ENC_ASCII);
        proto_item_append_text(ext_item, ": \"%s\"", tvb_format_text(pinfo->pool, tvb, 1, len));
        break;
    case EXT_IPV6_ADDRESS:
    case EXT_SECONDARY_DNS:
        proto_tree_add_item(tree, hf_wsa_ipv6, tvb, 0, 16, ENC_NA);
        break;
    case EXT_SERVICE_PORT:
        proto_tree_add_item(tree, hf_wsa_port, tvb, 0, 2, ENC_BIG_ENDIAN);
        break;
    case EXT_PROVIDER_MAC:
    case EXT_GATEWAY_MAC:
        proto_tree_add_item(tree, hf_wsa_mac, tvb, 0, 6, ENC_NA);
        break;
    case EXT_EDCA_PARAMS:
        dissect_wsa_edca(tvb, tree);
        break;
    case EXT_CHANNEL_NUMBER:
        proto_tree_add_item(tree, hf_wsa_channel_number, tvb, 0, 1, ENC_NA);
        break;
    case EXT_DATA_RATE:
        proto_tree_add_item(tree, hf_wsa_data_rate, tvb, 0, 1, ENC_NA);
        break;
    case EXT_TX_POWER:
        wsa_add_int(tree, hf_wsa_tx_power, tvb, &bo, 8, -128, NULL);
        break;
    case EXT_REPEAT_RATE:
        proto_tree_add_item(tree, hf_wsa_repeat_rate, tvb, 0, 1, ENC_NA);
        break;
    case EXT_RCPI_THRESHOLD:
        proto_tree_add_item(tree, hf_wsa_rcpi_threshold, tvb, 0, 1, ENC_NA);
        break;
    case EXT_COUNT_THRESHOLD:
        proto_tree_add_item(tree, hf_wsa_count_threshold, tvb, 0, 1, ENC_NA);
        break;
    case EXT_COUNT_THRES_INT:
        proto_tree_add_item(tree, hf_wsa_count_threshold_interval, tvb, 0, 1, ENC_NA);
        break;
    case EXT_CHANNEL_ACCESS:
        proto_tree_add_item(tree, hf_wsa_channel_access, tvb, 0, 1, ENC_NA);
        proto_item_append_text(ext_item, ": %s",
                val_to_str_const(tvb_get_uint8(tvb, 0), wsa_channel_access_vals, "Unknown"));
        break;
    case EXT_PROTOCOL_TYPE:
        wsa_var_length_number(tree, pinfo, hf_wsa_protocol_type, tvb, &bo);
        break;
    case EXT_SA_SIGNER:
        break;      /* NULL: presence is the information */
    case EXT_APPLICATION_DATA:
        if (wsa_length(tree, pinfo, -1, tvb, &bo, &len))
            proto_tree_add_item(tree, hf_wsa_app_data, tvb, BO_START(bo), len, ENC_NA);
        break;
    default:
        proto_tree_add_item(tree, hf_wsa_ext_data, tvb, 0, -1, ENC_NA);
        break;
    }
}

/**
 * Decodes a SEQUENCE OF extension elements at *@p bo into a "@p label"
 * subtree and advances *@p bo. Returns false if the list can't be walked.
 */
static bool
dissect_wsa_extensions(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *bo,
                       const char *label)
{
    unsigned start = *bo;
    proto_item *list_item;
    proto_tree *list_tree = proto_tree_add_subtree(tree, tvb, BO_START(start), -1, ett_wsa_exts,
                                                   &list_item, label);
    uint32_t count;

    if (!wsa_length(list_tree, pinfo, hf_wsa_ext_count, tvb, bo, &count))
        return false;

    for (uint32_t i = 0; i < count; i++) {
        unsigned ext_start = *bo;
        uint8_t id = tvb_get_bits8(tvb, *bo, 8);
        proto_item *ext_item;
        proto_tree *ext_tree = proto_tree_add_subtree(list_tree, tvb, BO_START(ext_start), -1,
                ett_wsa_ext, &ext_item, val_to_str(pinfo->pool, id, wsa_ext_id_vals, "Extension %u"));
        uint32_t len;

        wsa_add_bits(ext_tree, hf_wsa_ext_id, tvb, bo, 8);
        if (!wsa_length(ext_tree, pinfo, hf_wsa_ext_len, tvb, bo, &len))
            return false;
        if (len > 0) {
            tvbuff_t *val_tvb = tvb_new_octet_aligned(tvb, *bo, len * 8);
            add_new_data_source(pinfo, val_tvb, "WSA extension value");
            dissect_wsa_ext_value(val_tvb, pinfo, ext_tree, id, ext_item);
        }
        *bo += len * 8;
        proto_item_set_len(ext_item, BO_SPAN(ext_start, *bo - ext_start));
    }
    proto_item_set_len(list_item, BO_SPAN(start, *bo - start));
    return true;
}

/** Most Service Info channel indexes kept for checking against the Channel Info count. */
#define WSA_MAX_CHECKED_SVCS 32

/** Channel index items of decoded services, checked once the channel count is known. */
typedef struct {
    proto_item *item[WSA_MAX_CHECKED_SVCS];
    uint8_t chan_index[WSA_MAX_CHECKED_SVCS];
    unsigned n;
} wsa_chan_refs_t;

/** Decodes the Service Info segment at *@p bo, recording channel indexes in @p refs. */
static bool
dissect_wsa_service_infos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *bo,
                          wsa_chan_refs_t *refs)
{
    unsigned start = *bo;
    proto_item *list_item;
    proto_tree *list_tree = proto_tree_add_subtree(tree, tvb, BO_START(start), -1, ett_wsa_svcs,
                                                   &list_item, "Service Info Segment");
    uint32_t count;

    if (!wsa_length(list_tree, pinfo, hf_wsa_svc_count, tvb, bo, &count))
        return false;

    for (uint32_t i = 0; i < count; i++) {
        unsigned svc_start = *bo;
        proto_item *svc_item, *pi;
        proto_tree *svc_tree = proto_tree_add_subtree_format(list_tree, tvb, BO_START(svc_start), -1,
                ett_wsa_svc, &svc_item, "Service Info %u", i + 1);
        uint32_t psid, chan_index;

        psid = wsa_var_length_number(svc_tree, pinfo, hf_wsa_svc_psid, tvb, bo);
        proto_item_append_text(svc_item, ": PSID 0x%x", psid);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s0x%x", i ? ", " : " PSID ", psid);

        chan_index = tvb_get_bits8(tvb, *bo, 5);
        pi = proto_tree_add_uint(svc_tree, hf_wsa_svc_chan_index, tvb, BO_START(*bo),
                                 BO_SPAN(*bo, 5), chan_index);
        if (refs->n < WSA_MAX_CHECKED_SVCS) {
            refs->item[refs->n] = pi;
            refs->chan_index[refs->n++] = (uint8_t)chan_index;
        }
        *bo += 5;
        wsa_add_bits(svc_tree, hf_wsa_svc_reserved, tvb, bo, 2);
        if (wsa_add_flag(svc_tree, hf_wsa_svc_ext_present, tvb, bo)) {
            if (!dissect_wsa_extensions(tvb, pinfo, svc_tree, bo, "Service Info Extensions"))
                return false;
        }
        proto_item_set_len(svc_item, BO_SPAN(svc_start, *bo - svc_start));
    }
    proto_item_set_len(list_item, BO_SPAN(start, *bo - start));
    return true;
}

/** Decodes the Channel Info segment at *@p bo; stores the instance count in *@p count. */
static bool
dissect_wsa_channel_infos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *bo,
                          uint32_t *count_out)
{
    unsigned start = *bo;
    proto_item *list_item;
    proto_tree *list_tree = proto_tree_add_subtree(tree, tvb, BO_START(start), -1, ett_wsa_chans,
                                                   &list_item, "Channel Info Segment");
    uint32_t count;

    if (!wsa_length(list_tree, pinfo, hf_wsa_chan_count, tvb, bo, &count))
        return false;
    *count_out = count;

    for (uint32_t i = 0; i < count; i++) {
        unsigned ch_start = *bo;
        proto_item *ch_item;
        proto_tree *ch_tree = proto_tree_add_subtree_format(list_tree, tvb, BO_START(ch_start), -1,
                ett_wsa_chan, &ch_item, "Channel Info %u", i + 1);
        uint32_t channel;

        wsa_add_bits(ch_tree, hf_wsa_chan_op_class, tvb, bo, 8);
        channel = wsa_add_bits(ch_tree, hf_wsa_chan_number, tvb, bo, 8);
        wsa_add_int(ch_tree, hf_wsa_chan_tx_power, tvb, bo, 8, -128, NULL);
        wsa_add_flag(ch_tree, hf_wsa_chan_adaptable, tvb, bo);
        wsa_add_bits(ch_tree, hf_wsa_chan_data_rate, tvb, bo, 7);
        wsa_add_bits(ch_tree, hf_wsa_chan_reserved, tvb, bo, 7);
        proto_item_append_text(ch_item, ": channel %u", channel);
        if (wsa_add_flag(ch_tree, hf_wsa_chan_ext_present, tvb, bo)) {
            if (!dissect_wsa_extensions(tvb, pinfo, ch_tree, bo, "Channel Info Extensions"))
                return false;
        }
        proto_item_set_len(ch_item, BO_SPAN(ch_start, *bo - ch_start));
    }
    proto_item_set_len(list_item, BO_SPAN(start, *bo - start));
    return true;
}

/** Decodes the WAVE Routing Advertisement at *@p bo. */
static bool
dissect_wsa_routing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *bo)
{
    unsigned start = *bo;
    proto_item *wra_item;
    proto_tree *wra_tree = proto_tree_add_subtree(tree, tvb, BO_START(start), -1, ett_wsa_wra,
                                                  &wra_item, "WAVE Routing Advertisement");
    int fields[] = { hf_wsa_wra_prefix, hf_wsa_wra_gateway, hf_wsa_wra_dns };
    bool ok;

    wsa_add_bits(wra_tree, hf_wsa_wra_lifetime, tvb, bo, 16);
    for (unsigned f = 0; f < array_length(fields); f++) {
        tvbuff_t *addr = tvb_new_octet_aligned(tvb, *bo, 128);
        proto_tree_add_item(wra_tree, fields[f], addr, 0, 16, ENC_NA);
        *bo += 128;
        if (f == 0)
            wsa_add_bits(wra_tree, hf_wsa_wra_prefix_len, tvb, bo, 8);
    }
    ok = dissect_wsa_extensions(tvb, pinfo, wra_tree, bo, "Routing Advertisement Extensions");
    proto_item_set_len(wra_item, BO_SPAN(start, *bo - start));
    return ok;
}

static int
dissect_wsa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *wsa_tree, *hdr_tree;
    unsigned bo = 0;
    uint32_t version, wsa_id, content_count, num_chans = 0;
    bool has_ext, has_svc, has_chan, has_wra;
    bool ok = true;
    wsa_chan_refs_t refs = { .n = 0 };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WSA");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_wsa, tvb, 0, -1, ENC_NA);
    wsa_tree = proto_item_add_subtree(ti, ett_wsa);

    hdr_tree = proto_tree_add_subtree(wsa_tree, tvb, 0, 2, ett_wsa_hdr, NULL, "WSA Header");
    version = wsa_add_bits(hdr_tree, hf_wsa_version, tvb, &bo, 4);
    if (version != WSA_VERSION) {
        proto_tree_add_expert_format(hdr_tree, pinfo, &ei_wsa_version, tvb, 0, 1,
                "Unsupported WSA version %u (expected %u)", version, WSA_VERSION);
        col_add_fstr(pinfo->cinfo, COL_INFO, "WSA version %u (unsupported)", version);
        return tvb_captured_length(tvb);
    }
    has_ext  = wsa_add_flag(hdr_tree, hf_wsa_hdr_ext_present, tvb, &bo);
    has_svc  = wsa_add_flag(hdr_tree, hf_wsa_svc_present, tvb, &bo);
    has_chan = wsa_add_flag(hdr_tree, hf_wsa_chan_present, tvb, &bo);
    has_wra  = wsa_add_flag(hdr_tree, hf_wsa_wra_present, tvb, &bo);
    wsa_id = wsa_add_bits(hdr_tree, hf_wsa_id, tvb, &bo, 4);
    content_count = wsa_add_bits(hdr_tree, hf_wsa_content_count, tvb, &bo, 4);

    col_add_fstr(pinfo->cinfo, COL_INFO, "WAVE Service Advertisement id=%u count=%u",
                 wsa_id, content_count);
    proto_item_append_text(ti, ", ID %u, Content Count %u", wsa_id, content_count);

    if (has_ext)
        ok = dissect_wsa_extensions(tvb, pinfo, wsa_tree, &bo, "WSA Header Extensions");

    if (ok && has_svc)
        ok = dissect_wsa_service_infos(tvb, pinfo, wsa_tree, &bo, &refs);

    if (ok && has_chan)
        ok = dissect_wsa_channel_infos(tvb, pinfo, wsa_tree, &bo, &num_chans);

    /* A service's channel index (1-based) must name a Channel Info instance */
    if (ok) {
        for (unsigned i = 0; i < refs.n; i++) {
            if (refs.chan_index[i] > num_chans)
                expert_add_info(pinfo, refs.item[i], &ei_wsa_chan_index);
        }
    }

    if (ok && has_wra)
        ok = dissect_wsa_routing(tvb, pinfo, wsa_tree, &bo);

    /* Only zero padding up to the next octet boundary may remain */
    if (ok && BO_SPAN(0, bo) < (int)tvb_reported_length(tvb))
        proto_tree_add_expert_remaining(wsa_tree, pinfo, &ei_wsa_trailing, tvb, BO_SPAN(0, bo));

    return tvb_captured_length(tvb);
}

void
proto_register_wsa(void)
{
    static hf_register_info hf[] = {
        { &hf_wsa_version,
          { "WSA Version", "wsa.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_hdr_ext_present,
          { "Header Extensions Present", "wsa.hdr_ext_present", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_svc_present,
          { "Service Info Present", "wsa.service_info_present", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_chan_present,
          { "Channel Info Present", "wsa.channel_info_present", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_wra_present,
          { "Routing Advertisement Present", "wsa.wra_present", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_id,
          { "WSA Identifier", "wsa.id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_content_count,
          { "Content Count", "wsa.content_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_wsa_ext_count,
          { "Extension Count", "wsa.ext.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_ext_id,
          { "Extension ID", "wsa.ext.id", FT_UINT8, BASE_DEC, VALS(wsa_ext_id_vals), 0x0,
            NULL, HFILL }},
        { &hf_wsa_ext_len,
          { "Extension Length", "wsa.ext.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_ext_data,
          { "Extension Data", "wsa.ext.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_wsa_svc_count,
          { "Service Info Count", "wsa.service.count", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_svc_psid,
          { "PSID", "wsa.service.psid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_svc_chan_index,
          { "Channel Index", "wsa.service.channel_index", FT_UINT8, BASE_DEC, NULL, 0x0,
            "1-based index into the Channel Info segment; 0 = not used", HFILL }},
        { &hf_wsa_svc_reserved,
          { "Reserved", "wsa.service.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_svc_ext_present,
          { "Extensions Present", "wsa.service.ext_present", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsa_chan_count,
          { "Channel Info Count", "wsa.channel.count", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_chan_op_class,
          { "Operating Class", "wsa.channel.operating_class", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_chan_number,
          { "Channel Number", "wsa.channel.number", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_chan_tx_power,
          { "Transmit Power Level", "wsa.channel.tx_power", FT_INT8, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_dbm), 0x0, NULL, HFILL }},
        { &hf_wsa_chan_adaptable,
          { "Adaptable", "wsa.channel.adaptable", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Data rate is a lower bound rather than a fixed rate", HFILL }},
        { &hf_wsa_chan_data_rate,
          { "Data Rate", "wsa.channel.data_rate", FT_UINT8, BASE_CUSTOM,
            CF_FUNC(wsa_fmt_rate), 0x0, NULL, HFILL }},
        { &hf_wsa_chan_reserved,
          { "Reserved Options", "wsa.channel.reserved", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_chan_ext_present,
          { "Extensions Present", "wsa.channel.ext_present", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsa_wra_lifetime,
          { "Router Lifetime", "wsa.wra.lifetime", FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_second_seconds), 0x0, NULL, HFILL }},
        { &hf_wsa_wra_prefix,
          { "IP Prefix", "wsa.wra.prefix", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_wra_prefix_len,
          { "Prefix Length", "wsa.wra.prefix_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_wra_gateway,
          { "Default Gateway", "wsa.wra.gateway", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_wra_dns,
          { "Primary DNS", "wsa.wra.dns", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_wsa_latitude,
          { "Latitude", "wsa.latitude", FT_INT32, BASE_CUSTOM, CF_FUNC(wsa_fmt_lat), 0x0,
            NULL, HFILL }},
        { &hf_wsa_longitude,
          { "Longitude", "wsa.longitude", FT_INT32, BASE_CUSTOM, CF_FUNC(wsa_fmt_lon), 0x0,
            NULL, HFILL }},
        { &hf_wsa_elevation,
          { "Elevation", "wsa.elevation", FT_INT32, BASE_CUSTOM, CF_FUNC(wsa_fmt_elev), 0x0,
            NULL, HFILL }},
        { &hf_wsa_advertiser_id,
          { "Advertiser Identifier", "wsa.advertiser_id", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_psc,
          { "Provider Service Context", "wsa.psc", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_ipv6,
          { "IPv6 Address", "wsa.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_port,
          { "Service Port", "wsa.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_mac,
          { "MAC Address", "wsa.mac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_channel_number,
          { "Channel Number", "wsa.ext.channel_number", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_data_rate,
          { "Data Rate", "wsa.ext.data_rate", FT_UINT8, BASE_CUSTOM, CF_FUNC(wsa_fmt_rate),
            0x0, NULL, HFILL }},
        { &hf_wsa_tx_power,
          { "Transmit Power Used", "wsa.ext.tx_power", FT_INT8, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_dbm), 0x0, NULL, HFILL }},
        { &hf_wsa_repeat_rate,
          { "Repeat Rate", "wsa.repeat_rate", FT_UINT8, BASE_DEC, NULL, 0x0,
            "WSAs transmitted per 5 seconds", HFILL }},
        { &hf_wsa_rcpi_threshold,
          { "RCPI Threshold", "wsa.rcpi_threshold", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_count_threshold,
          { "WSA Count Threshold", "wsa.count_threshold", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_count_threshold_interval,
          { "WSA Count Threshold Interval", "wsa.count_threshold_interval", FT_UINT8,
            BASE_DEC, NULL, 0x0, "In units of 100 ms", HFILL }},
        { &hf_wsa_channel_access,
          { "Channel Access", "wsa.channel_access", FT_UINT8, BASE_DEC,
            VALS(wsa_channel_access_vals), 0x0, NULL, HFILL }},
        { &hf_wsa_protocol_type,
          { "Protocol Type", "wsa.protocol_type", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_wsa_app_data,
          { "Application Data", "wsa.app_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_edca_aci,
          { "ACI", "wsa.edca.aci", FT_UINT8, BASE_DEC, VALS(wsa_edca_aci_vals), 0x0,
            NULL, HFILL }},
        { &hf_wsa_edca_acm,
          { "ACM", "wsa.edca.acm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_edca_aifsn,
          { "AIFSN", "wsa.edca.aifsn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_edca_ecw_max,
          { "ECWmax", "wsa.edca.ecw_max", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_edca_ecw_min,
          { "ECWmin", "wsa.edca.ecw_min", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_wsa_edca_txop,
          { "TXOP Limit", "wsa.edca.txop", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_wsa,
        &ett_wsa_hdr,
        &ett_wsa_exts,
        &ett_wsa_ext,
        &ett_wsa_svcs,
        &ett_wsa_svc,
        &ett_wsa_chans,
        &ett_wsa_chan,
        &ett_wsa_wra,
        &ett_wsa_edca,
    };

    static ei_register_info ei[] = {
        { &ei_wsa_version,
          { "wsa.version.unsupported", PI_PROTOCOL, PI_WARN, "Unsupported WSA version", EXPFILL }},
        { &ei_wsa_fragmented,
          { "wsa.length.fragmented", PI_MALFORMED, PI_ERROR,
            "Fragmented UPER length determinant not supported", EXPFILL }},
        { &ei_wsa_lat_range,
          { "wsa.latitude.range", PI_PROTOCOL, PI_WARN, "Latitude out of range", EXPFILL }},
        { &ei_wsa_lon_range,
          { "wsa.longitude.range", PI_PROTOCOL, PI_WARN, "Longitude out of range", EXPFILL }},
        { &ei_wsa_fill_nonzero,
          { "wsa.fill.nonzero", PI_PROTOCOL, PI_WARN, "Fill bits are not zero", EXPFILL }},
        { &ei_wsa_chan_index,
          { "wsa.service.channel_index.range", PI_PROTOCOL, PI_WARN,
            "Channel index refers to a Channel Info instance that is not present", EXPFILL }},
        { &ei_wsa_trailing,
          { "wsa.trailing", PI_MALFORMED, PI_WARN, "Trailing data after the WSA", EXPFILL }},
        { &ei_wsa_psid_ext,
          { "wsa.psid.extended", PI_PROTOCOL, PI_WARN,
            "PSID beyond the 4-octet range is not supported", EXPFILL }},
    };

    expert_module_t *expert_wsa;

    proto_wsa = proto_register_protocol("IEEE 1609.3 WAVE Service Advertisement", "WSA", "wsa");
    proto_register_field_array(proto_wsa, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_wsa = expert_register_protocol(proto_wsa);
    expert_register_field_array(expert_wsa, ei, array_length(ei));

    wsa_handle = register_dissector("wsa", dissect_wsa, proto_wsa);
}

void
proto_reg_handoff_wsa(void)
{
    dissector_add_uint("ieee1609dot2.psid", psid_wave_service_advertisement, wsa_handle);
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
