/* packet-lda-neo-trailer.c
 * Routines for LDA Neo Device trailer dissection
 * Vladimir Arustamov <vladimir@ldatech.com>
 *
 * Copyright 2025 LDA Technologies https://ldatech.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wireshark.h>

#include <epan/packet.h>
#include <epan/expert.h>

/**
 * Ethernet Trailer Format
 * ======================================================================================
 *
 * | Offset | Size (bytes) | Description                                               |
 * |--------|--------------|-----------------------------------------------------------|
 * |   0    |      1       | Record signature: ASCII character "L" (0x4C)              |
 * |--------|--------------|-----------------------------------------------------------|
 * |   1    |      2       | 16-bit little-endian (LSB first) per-port sequence number.|
 * |        |              | Reset to 0 on FPGA reset and increases monotonically for  |
 * |        |              | each packet. Gaps may indicate dropped packets.           |
 * |--------|--------------|-----------------------------------------------------------|
 * |   3    |      1       | Bit 0: Ethernet FCS validity indicator                    |
 * |        |              |        0: valid, 1: invalid                               |
 * |        |              | NOTE: Port must be configured with KEEPRXCRC=1            |
 * |        |              | Bits 7-1: Configured device ID (default 0)                |
 * |--------|--------------|-----------------------------------------------------------|
 * |   4    |      1       | Bit 0: PCS code 33/78 indicator (10G/25G only)            |
 * |        |              |        1 = PCS code 0x33 received, always 0 for 40G       |
 * |        |              | Bit 1: Reserved                                           |
 * |        |              | Bits 7-2: PCS code position in 64-bit word (0-63)         |
 * |--------|--------------|-----------------------------------------------------------|
 * |   5    |      1       | Bits 5-0: Port ID                                         |
 * |        |              |          1-48: 10G/25G ports                              |
 * |        |              |          49-52: 40G port VLAN 49                          |
 * |        |              |          53-56: 40G VLAN 50                               |
 * |        |              | Bits 7-6: Port speed (0: 10G, 1: 25G, 2: 40G)             |
 * |--------|--------------|-----------------------------------------------------------|
 * |   6    |      10      | 80-bit little-endian (LSB first) timestamp in             |
 * |        |              | picoseconds since EPOCH                                   |
 * ======================================================================================
 */

/* Parameters common to 40G port range and lane  */
#define LDA_NEO_TRAILER_40G_PORT_ID_MIN 49
#define LDA_NEO_TRAILER_40G_PORT_ID_MAX 56
#define LDA_NEO_TRAILER_40G_PORT_LANE_COUNT 4

/* Parameters common mask */
#define LDA_NEO_TRAILER_MASK_DEFAULT 0x0
#define LDA_NEO_TRAILER_MASK_CRC_INVALID 0x80
#define LDA_NEO_TRAILER_MASK_DEVICE_ID 0x7F
#define LDA_NEO_TRAILER_MASK_PCS_CODE 0x01
#define LDA_NEO_TRAILER_MASK_PCS_CODE_POS 0xFC
#define LDA_NEO_TRAILER_MASK_PORT_ID 0x3F
#define LDA_NEO_TRAILER_MASK_PORT_SPEED 0xC0

/* Parameters common offset */
#define LDA_NEO_TRAILER_SIG_OFFSET 0
#define LDA_NEO_TRAILER_SEQNUM_OFFSET 1
#define LDA_NEO_TRAILER_DEVID_OFFSET 3
#define LDA_NEO_TRAILER_PCS_CODE_OFFSET 4
#define LDA_NEO_TRAILER_PORTID_OFFSET 5
#define LDA_NEO_TRAILER_PICOSEC_OFFSET 6

/* Parameters common data length */
#define LDA_NEO_TRAILER_DATA_LENGTH 16
#define LDA_NEO_TRAILER_SIG_LENGTH_V2 (LDA_NEO_TRAILER_SEQNUM_OFFSET - LDA_NEO_TRAILER_SIG_OFFSET)
#define LDA_NEO_TRAILER_SEQNUM_LENGTH (LDA_NEO_TRAILER_DEVID_OFFSET - LDA_NEO_TRAILER_SEQNUM_OFFSET)
#define LDA_NEO_TRAILER_DEVID_LENGTH (LDA_NEO_TRAILER_PCS_CODE_OFFSET - LDA_NEO_TRAILER_DEVID_OFFSET)
#define LDA_NEO_TRAILER_PCS_CODE_LENGTH (LDA_NEO_TRAILER_PORTID_OFFSET - LDA_NEO_TRAILER_PCS_CODE_OFFSET)
#define LDA_NEO_TRAILER_PORTID_LENGTH (LDA_NEO_TRAILER_PICOSEC_OFFSET - LDA_NEO_TRAILER_PORTID_OFFSET)
#define LDA_NEO_TRAILER_PICOSEC_LENGTH (LDA_NEO_TRAILER_DATA_LENGTH - LDA_NEO_TRAILER_PICOSEC_OFFSET)

#define SECONDS_IN_MONTH 2592000 /* Representation month to second */

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_lda_neo_trailer(void);
void proto_register_lda_neo_trailer(void);

/* Initialization signature */
static const uint8_t ldasig = 0x4c; /* Hex value 'L' */

/* Dissector registration */
static int proto_lda_neo_trailer;

/* Header field register ids */
static int hf_lda_neo_trailer_sig;
static int hf_lda_neo_trailer_seq_num;
static int hf_lda_neo_trailer_crc_invalid;
static int hf_lda_neo_trailer_dev_id;
static int hf_lda_neo_trailer_pcs_code;
static int hf_lda_neo_trailer_pcs_code_pos;
static int hf_lda_neo_trailer_port_id;
static int hf_lda_neo_trailer_port_preamble_lane;
static int hf_lda_neo_trailer_port_speed;
static int hf_lda_neo_trailer_timestamp;
#if defined(_M_X64) && (_MSC_VER >= 1920) || defined(__SIZEOF_INT128__)
static int hf_lda_neo_trailer_picosec;
static int hf_lda_neo_trailer_nanosec;
static int hf_lda_neo_trailer_datetime;
#endif

/* Header field register ids for unexpected parameters */
static expert_field ei_lda_neo_trailer_invalid;
static expert_field ei_lda_neo_trailer_port_id_invalid;
static expert_field ei_lda_neo_trailer_pcs_code_invalid;
static expert_field ei_lda_neo_trailer_port_speed_invalid;
static expert_field ei_lda_neo_trailer_cant_handle_picoseconds;

/* Speed configuration */
static const value_string port_speed_str[] = {
    {0, "10G"},
    {1, "25G"},
    {2, "40G"},
    {0, NULL}
};

static dissector_handle_t lda_neo_trailer_handle;

static int ett_lda_neo_trailer;
static int ett_lda_neo_trailer_pcs_code;
static int ett_lda_neo_trailer_port;
static int ett_lda_neo_trailer_port_id;
static int ett_lda_neo_trailer_timestamp;

/* Timestamp representation from epoch */
typedef struct _timestamp_data {
    uint16_t picosec;
    uint64_t nanosec;
} timestamp_data;

/* Timestamp analyzing indicator */
static bool pref_timestamp_validation = true;

/*
 * Extract timestamp data from buffer
 */
#if defined(_M_X64) && (_MSC_VER >= 1920)
static bool
extract_nstime(tvbuff_t *tvb, int32_t offset, timestamp_data* data)
{
   uint32_t i;
   uint8_t picosec_buf[LDA_NEO_TRAILER_PICOSEC_LENGTH];
   int64_t nanosec;
   uint64_t picosec_counter_high;
   uint64_t picosec_counter_low;
   int64_t remainder = 0;

   /* Fill 10 byte timestamp buffer */
   tvb_memcpy(tvb, picosec_buf, offset, LDA_NEO_TRAILER_PICOSEC_LENGTH);
   picosec_counter_high = picosec_buf[0];
   picosec_counter_low = 0;

   /* Extract picosec from buffer */
   for (i = 1; i < sizeof(picosec_buf); ++i) {
      if (i < 2) {
         picosec_counter_high = (picosec_counter_high << 8) | picosec_buf[i];
      } else {
         picosec_counter_low = (picosec_counter_low << 8) | picosec_buf[i];
      }
   }

   /* Sanity check the data to make sure the result will fit into a 64-bit integer */
   if (picosec_counter_high >= 500) {
     return false;
   }

   /* Calculate picosec and nanosec */
   nanosec = _div128(picosec_counter_high, picosec_counter_low, 1000, &remainder);

   data->picosec = (uint16_t)remainder;
   data->nanosec = nanosec;
   return true;
}
#elif defined(__SIZEOF_INT128__)
static bool
extract_nstime(tvbuff_t *tvb, int32_t offset, timestamp_data* data)
{
   uint8_t picosec_buf[LDA_NEO_TRAILER_PICOSEC_LENGTH];
   uint32_t i;

   /* Fill 10 byte timestamp buffer */
   tvb_memcpy(tvb, picosec_buf, offset, LDA_NEO_TRAILER_PICOSEC_LENGTH);
   unsigned __int128 picosec_counter;
   picosec_counter = picosec_buf[0];

   /* Extract picosec from buffer */
   for (i = 1; i < sizeof(picosec_buf); ++i) {
      picosec_counter = (picosec_counter << 8) | picosec_buf[i];
   }

   /* Calculate picosec and nanosec */
   data->picosec = (uint16_t)(picosec_counter % 1000);
   data->nanosec = picosec_counter / 1000;
   return true;
}
#else
static bool
extract_nstime(tvbuff_t *tvb _U_, int32_t offset _U_, timestamp_data* data)
{
    data->picosec = 0;
    data->nanosec = 0;
    return true;
}
#endif

static int
dissect_lda_neo_trailer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint8_t signature;
    uint8_t speed;
    uint32_t port;
    uint32_t pcs_code;
    int32_t extra_trailer_bytes;
    uint32_t ts_sec;
    uint32_t ts_nsec;
    int32_t offset;
    bool invalid = false;
    uint8_t lane = 0;

    proto_item *ti_root;
    proto_tree *lda_neo_trailer_tree;

    timestamp_data timestamp;
    nstime_t ts;

    /* Check do we have enough data */
    extra_trailer_bytes = tvb_captured_length(tvb) - LDA_NEO_TRAILER_DATA_LENGTH;
    if (extra_trailer_bytes < 0) {
        return 0;
    }

    /* Find the LDA Neo Device trailer signature in the extra trailer bytes */
    for (offset = 0; offset <= extra_trailer_bytes; ++offset) {
        signature = tvb_get_uint8(tvb, offset);
        if (signature != ldasig) {
            continue;
        }

        /* Extract timestamp segments */
        if (!extract_nstime(tvb, offset + LDA_NEO_TRAILER_DATA_LENGTH - LDA_NEO_TRAILER_PICOSEC_LENGTH, &timestamp)) {
            continue;
        }
        ts_sec = (uint32_t)(timestamp.nanosec / 1000000000);
        ts_nsec = timestamp.nanosec % 1000000000;
        ts = (nstime_t)NSTIME_INIT_SECS_NSECS(ts_sec, ts_nsec);

        /* Validate timestamp */
        if (pref_timestamp_validation) {
            nstime_t delta;
            nstime_delta(&delta, &pinfo->abs_ts, &ts);
            if (labs((long)(delta.secs)) > SECONDS_IN_MONTH) {
                continue;
            }
        }

        break;
    }
    if (offset > extra_trailer_bytes) {
        /* No valid LDA Neo Device trailer signature found */
        return 0;
    }

    /* Construct LDA Neo Device trailer tree */
    ti_root = proto_tree_add_item(tree, proto_lda_neo_trailer, tvb, offset, LDA_NEO_TRAILER_DATA_LENGTH, ENC_NA);
    lda_neo_trailer_tree = proto_item_add_subtree(ti_root, ett_lda_neo_trailer);

    /* Construct LDA Neo Device trailer signature */
    proto_tree_add_item(lda_neo_trailer_tree, hf_lda_neo_trailer_sig, tvb, offset, LDA_NEO_TRAILER_SIG_LENGTH_V2, ENC_ASCII);
    offset += LDA_NEO_TRAILER_SIG_LENGTH_V2;

    /* Construct LDA Neo Device trailer sequence number */
    proto_tree_add_item(lda_neo_trailer_tree, hf_lda_neo_trailer_seq_num, tvb, offset, LDA_NEO_TRAILER_SEQNUM_LENGTH,
            ENC_BIG_ENDIAN);
    offset += LDA_NEO_TRAILER_SEQNUM_LENGTH;

    /* Construct LDA Neo Device trailer CRC validation flag */
    proto_tree_add_item(lda_neo_trailer_tree, hf_lda_neo_trailer_crc_invalid, tvb, offset, LDA_NEO_TRAILER_DEVID_LENGTH,
            ENC_LITTLE_ENDIAN);

    /* Construct LDA Neo Device trailer device ID */
    proto_tree_add_item(lda_neo_trailer_tree, hf_lda_neo_trailer_dev_id, tvb, offset, LDA_NEO_TRAILER_DEVID_LENGTH,
            ENC_LITTLE_ENDIAN);
    offset += LDA_NEO_TRAILER_DEVID_LENGTH;

    /* Construct LDA Neo Device trailer PCS code tree and fields */
    proto_tree *pcs_tree = proto_tree_add_subtree(lda_neo_trailer_tree, tvb, offset, LDA_NEO_TRAILER_PCS_CODE_LENGTH,
            ett_lda_neo_trailer_pcs_code, &ti_root, "PCS");
    pcs_code = tvb_get_uint8(tvb, offset) & LDA_NEO_TRAILER_MASK_PCS_CODE;
    port = tvb_get_uint8(tvb, offset + LDA_NEO_TRAILER_PCS_CODE_LENGTH) & LDA_NEO_TRAILER_MASK_PORT_ID;

    /* PCS Code always 0 for 40G. */
    if (pcs_code == true && port >= LDA_NEO_TRAILER_40G_PORT_ID_MIN && port <= LDA_NEO_TRAILER_40G_PORT_ID_MAX) {
        invalid = true;
        proto_tree_add_expert(pcs_tree, pinfo, &ei_lda_neo_trailer_pcs_code_invalid, tvb,
                LDA_NEO_TRAILER_PCS_CODE_OFFSET, LDA_NEO_TRAILER_PCS_CODE_LENGTH);
    } else {
        proto_tree_add_item(pcs_tree, hf_lda_neo_trailer_pcs_code, tvb, offset, LDA_NEO_TRAILER_PCS_CODE_LENGTH,
                ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(pcs_tree, hf_lda_neo_trailer_pcs_code_pos, tvb, offset, LDA_NEO_TRAILER_PCS_CODE_LENGTH,
            ENC_LITTLE_ENDIAN);
    offset += LDA_NEO_TRAILER_PCS_CODE_LENGTH;

    /* Construct LDA Neo Device trailer port tree and fields */
    proto_tree *port_tree = proto_tree_add_subtree(lda_neo_trailer_tree, tvb, offset, LDA_NEO_TRAILER_PORTID_LENGTH,
            ett_lda_neo_trailer_port, &ti_root, "Port");
    proto_item *port_id_item = proto_tree_add_item(port_tree, hf_lda_neo_trailer_port_id, tvb, offset,
            LDA_NEO_TRAILER_PORTID_LENGTH, ENC_LITTLE_ENDIAN);
    if (port <= LDA_NEO_TRAILER_40G_PORT_ID_MAX) {
        if (port > LDA_NEO_TRAILER_40G_PORT_ID_MIN) {
            lane = (port - LDA_NEO_TRAILER_40G_PORT_ID_MIN) % LDA_NEO_TRAILER_40G_PORT_LANE_COUNT;

            proto_tree *port_id_tree = proto_item_add_subtree(port_id_item, ett_lda_neo_trailer_port_id);
            proto_tree_add_uint(port_id_tree, hf_lda_neo_trailer_port_preamble_lane, tvb, offset,
                    LDA_NEO_TRAILER_PORTID_LENGTH, lane);
        }
    } else {
        invalid = true;
        proto_tree_add_expert(lda_neo_trailer_tree, pinfo, &ei_lda_neo_trailer_port_id_invalid, tvb,
                LDA_NEO_TRAILER_PORTID_OFFSET, LDA_NEO_TRAILER_PORTID_LENGTH);
    }

    speed = (tvb_get_uint8(tvb, offset) & LDA_NEO_TRAILER_MASK_PORT_SPEED) >> 6;

    /* Validate speed with port_speed_str */
    if (speed < 3) {
        /* Construct LDA Neo Device trailer speed */
        proto_tree_add_item(port_tree, hf_lda_neo_trailer_port_speed, tvb, offset,
                LDA_NEO_TRAILER_PORTID_LENGTH, ENC_LITTLE_ENDIAN);
    } else {
        invalid = true;
        proto_tree_add_expert(port_tree, pinfo, &ei_lda_neo_trailer_port_speed_invalid, tvb,
                offset, LDA_NEO_TRAILER_PORTID_LENGTH);
    }

    if (invalid) {
        expert_add_info(pinfo, ti_root, &ei_lda_neo_trailer_invalid);
    }

    offset += LDA_NEO_TRAILER_PORTID_LENGTH;

    /* Construct LDA Neo Device trailer timestamp */
    //proto_tree *ts_tree = proto_tree_add_subtree(lda_neo_trailer_tree, tvb, offset, LDA_NEO_TRAILER_PICOSEC_LENGTH,
    //        ett_lda_neo_trailer_timestamp, &ti_root, "Timestamp");
    proto_item *ts_item = proto_tree_add_item(lda_neo_trailer_tree, hf_lda_neo_trailer_timestamp, tvb, offset,
            LDA_NEO_TRAILER_PICOSEC_LENGTH, ENC_NA);
    proto_tree *ts_tree = proto_item_add_subtree(ts_item, ett_lda_neo_trailer_timestamp);

#if defined(_M_X64) && (_MSC_VER >= 1920) || defined(__SIZEOF_INT128__)
    proto_tree_add_uint64(ts_tree, hf_lda_neo_trailer_nanosec, tvb, offset, LDA_NEO_TRAILER_PICOSEC_LENGTH,
            timestamp.nanosec);
    proto_tree_add_uint(ts_tree, hf_lda_neo_trailer_picosec, tvb, offset, LDA_NEO_TRAILER_PICOSEC_LENGTH,
            timestamp.picosec);
    proto_tree_add_time(ts_tree, hf_lda_neo_trailer_datetime, tvb, offset, LDA_NEO_TRAILER_PICOSEC_LENGTH, &ts);
#else
    proto_tree_add_expert(ts_tree, pinfo, &ei_lda_neo_trailer_cant_handle_picoseconds, tvb,
            offset, LDA_NEO_TRAILER_PORTID_LENGTH);
#endif

    return offset + LDA_NEO_TRAILER_PICOSEC_LENGTH;
}

static bool
dissect_lda_neo_trailer_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_lda_neo_trailer(tvb, pinfo, tree, data) > 0;
}

/*
 * Register the LDA Neo Device trailer protocol
 */
void
proto_register_lda_neo_trailer(void)
{
    module_t        *lda_neo_trailer_module;
    expert_module_t *expert_lda_neo_trailer;

    /* Setup list of header fields */
    static hf_register_info hf[] = {
        {
            &hf_lda_neo_trailer_sig,
            {"Signature", "lda_neo_trailer.signature", FT_STRING, BASE_NONE, NULL, LDA_NEO_TRAILER_MASK_DEFAULT,
                NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_seq_num,
            {"Sequence Number", "lda_neo_trailer.seqnum", FT_UINT16, BASE_DEC, NULL, LDA_NEO_TRAILER_MASK_DEFAULT,
                NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_crc_invalid,
            {"CRC Invalid", "lda_neo_trailer.crc_invalid", FT_BOOLEAN, 8, NULL, LDA_NEO_TRAILER_MASK_CRC_INVALID,
                NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_dev_id,
            {"Device ID", "lda_neo_trailer.devid", FT_UINT8, BASE_DEC, NULL, LDA_NEO_TRAILER_MASK_DEVICE_ID, NULL,
                HFILL}
        },
        {
            &hf_lda_neo_trailer_pcs_code,
            {"PCS Code 33", "lda_neo_trailer.pcscode33", FT_BOOLEAN, 8, NULL, LDA_NEO_TRAILER_MASK_PCS_CODE,
                NULL, HFILL}
        },

        {
            &hf_lda_neo_trailer_pcs_code_pos,
            {"PCS Position", "lda_neo_trailer.pcscode_position", FT_UINT8, BASE_DEC, NULL,
                LDA_NEO_TRAILER_MASK_PCS_CODE_POS, NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_port_id,
            {"Port ID", "lda_neo_trailer.portid", FT_UINT8, BASE_DEC, NULL, LDA_NEO_TRAILER_MASK_PORT_ID, NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_port_preamble_lane,
            {"40G preamble Lane", "lda_neo_trailer.preamble_lane", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_port_speed,
            {"Port speed", "lda_neo_trailer.portspeed", FT_UINT8, BASE_DEC, VALS(port_speed_str),
                LDA_NEO_TRAILER_MASK_PORT_SPEED, NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_timestamp,
            {"Timestamp", "lda_neo_trailer.timestamp", FT_BYTES, BASE_NONE, NULL, LDA_NEO_TRAILER_MASK_DEFAULT, NULL,
                HFILL}
        },

#if defined(_M_X64) && (_MSC_VER >= 1920) || defined(__SIZEOF_INT128__)
        {
            &hf_lda_neo_trailer_nanosec,
            {"Nanosec", "lda_neo_trailer.timestamp.nanosec", FT_UINT64, BASE_DEC, NULL, LDA_NEO_TRAILER_MASK_DEFAULT,
                NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_picosec,
            {"Picosec", "lda_neo_trailer.timestamp.picosec", FT_UINT16, BASE_DEC, NULL, LDA_NEO_TRAILER_MASK_DEFAULT,
                NULL, HFILL}
        },
        {
            &hf_lda_neo_trailer_datetime,
            {"Date time", "lda_neo_trailer.timestamp.datetime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
                LDA_NEO_TRAILER_MASK_DEFAULT, NULL, HFILL}
        },
#endif
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        {
            &ei_lda_neo_trailer_invalid,
            {"lda_neo_trailer.invalid", PI_MALFORMED, PI_ERROR, "Invalid Packet", EXPFILL}
        },
        {
            &ei_lda_neo_trailer_pcs_code_invalid,
            {"lda_neo_trailer.pcscode33_invalid", PI_MALFORMED, PI_ERROR, "PCS Code 33 invalid", EXPFILL}
        },
        {
            &ei_lda_neo_trailer_port_speed_invalid,
            {"lda_neo_trailer.portspeed_invalid", PI_MALFORMED, PI_ERROR, "Port speed invalid", EXPFILL}
        },
        {
            &ei_lda_neo_trailer_port_id_invalid,
            {"lda_neo_trailer.portid_invalid", PI_MALFORMED, PI_ERROR, "Invalid port ID", EXPFILL}
        },
        {
            &ei_lda_neo_trailer_cant_handle_picoseconds,
            {"lda_neo_trailer.cant_handle_picoseconds", PI_UNDECODED, PI_WARN, "Wireshark doesn't handle picosecond time stamps on this platform", EXPFILL}
        }
    };
    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_lda_neo_trailer,
        &ett_lda_neo_trailer_pcs_code,
        &ett_lda_neo_trailer_port,
        &ett_lda_neo_trailer_port_id,
        &ett_lda_neo_trailer_timestamp
    };

    /* Register the protocol name and description */
    proto_lda_neo_trailer = proto_register_protocol("LDA Neo Device trailer", "LDA_NEO_TRAILER", "lda_neo_trailer");

    /* Register the header fields and subtrees */
    proto_register_field_array(proto_lda_neo_trailer, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_lda_neo_trailer = expert_register_protocol(proto_lda_neo_trailer);
    expert_register_field_array(expert_lda_neo_trailer, ei, array_length(ei));

    lda_neo_trailer_handle = register_dissector("lda_neo_trailer", dissect_lda_neo_trailer, proto_lda_neo_trailer);

    lda_neo_trailer_module = prefs_register_protocol(proto_lda_neo_trailer, NULL);
    prefs_register_bool_preference(lda_neo_trailer_module, "timestamp", "Enable time validation",
            "The trailer detection includes additional validation through time verification,"
            " which provides extra accuracy.",
            &pref_timestamp_validation);
}

/* The registration lda_neo_trailer routine */
void
proto_reg_handoff_lda_neo_trailer(void)
{
    /* add session dissector to atn dissector list dissector list */
    heur_dissector_add(
        "eth.trailer",
        dissect_lda_neo_trailer_heur,
        "LDA Neo Device trailer",
        "lda_neo_trailer",
        proto_lda_neo_trailer,
        HEURISTIC_ENABLE
    );
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
