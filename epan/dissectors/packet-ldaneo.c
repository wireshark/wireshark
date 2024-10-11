/* packet-ldaneo.c
 * Routines for LDANeo Device trailer dissection
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
#define LDANEO_40G_PORT_ID_MIN 49
#define LDANEO_40G_PORT_ID_MAX 56
#define LDANEO_40G_PORT_LANE_COUNT 4

/* Parameters common mask */
#define LDANEO_MASK_DEFAULT 0x0
#define LDANEO_MASK_CRC_INVALID 0x80
#define LDANEO_MASK_DEVICE_ID 0x7F
#define LDANEO_MASK_PCS_CODE 0x01
#define LDANEO_MASK_PCS_CODE_POS 0xFC
#define LDANEO_MASK_PORT_ID 0x3F
#define LDANEO_MASK_PORT_SPEED 0xC0

/* Parameters common offset */
#define LDANEO_SIG_OFFSET 0
#define LDANEO_SEQNUM_OFFSET 1
#define LDANEO_DEVID_OFFSET 3
#define LDANEO_PCS_CODE_OFFSET 4
#define LDANEO_PORTID_OFFSET 5
#define LDANEO_PICOSEC_OFFSET 6

/* Parameters common data length */
#define LDANEO_DATA_LENGTH 16
#define LDANEO_SIG_LENGTH_V2 (LDANEO_SEQNUM_OFFSET - LDANEO_SIG_OFFSET)
#define LDANEO_SEQNUM_LENGTH (LDANEO_DEVID_OFFSET - LDANEO_SEQNUM_OFFSET)
#define LDANEO_DEVID_LENGTH (LDANEO_PCS_CODE_OFFSET - LDANEO_DEVID_OFFSET)
#define LDANEO_PCS_CODE_LENGTH (LDANEO_PORTID_OFFSET - LDANEO_PCS_CODE_OFFSET)
#define LDANEO_PORTID_LENGTH (LDANEO_PICOSEC_OFFSET - LDANEO_PORTID_OFFSET)
#define LDANEO_PICOSEC_LENGTH (LDANEO_DATA_LENGTH - LDANEO_PICOSEC_OFFSET)

#define SECONDS_IN_MONTH 2592000 /* Representation month to second */

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_ldaneo(void);
void proto_register_ldaneo(void);

/* Initialization signature */
static const uint8_t ldasig = 0x4c; /* Hex value 'L' */

/* Dissector registration */
static int proto_ldaneo;

/* Header field register ids */
static int hf_ldaneo_sig;
static int hf_ldaneo_seq_num;
static int hf_ldaneo_crc_invalid;
static int hf_ldaneo_dev_id;
static int hf_ldaneo_pcs_code;
static int hf_ldaneo_pcs_code_pos;
static int hf_ldaneo_port_id;
static int hf_ldaneo_port_preamble_lane;
static int hf_ldaneo_port_speed;
static int hf_ldaneo_timestamp;
#if defined(_M_X64) && (_MSC_VER >= 1920) || defined(__SIZEOF_INT128__)
static int hf_ldaneo_picosec;
static int hf_ldaneo_nanosec;
static int hf_ldaneo_datetime;
#endif

/* Header field register ids for unexpected parameters */
static expert_field ei_ldaneo_invalid;
static expert_field ei_ldaneo_port_id_invalid;
static expert_field ei_ldaneo_pcs_code_invalid;
static expert_field ei_ldaneo_port_speed_invalid;

/* Speed configuration */
static const value_string port_speed_str[] = {
    {0, "10G"},
    {1, "25G"},
    {2, "40G"},
    {0, NULL}
};

static dissector_handle_t ldaneo_handle;

static int ett_ldaneo;
static int ett_ldaneo_pcs_code;
static int ett_ldaneo_port;
static int ett_ldaneo_port_id;
static int ett_ldaneo_timestamp;

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
static timestamp_data
extract_nstime(tvbuff_t *tvb, int32_t offset)
{
   uint32_t i;
   uint8_t picosec_buf[LDANEO_PICOSEC_LENGTH];
   uint64_t nanosec;
   uint64_t picosec_counter_high;
   uint64_t picosec_counter_low;
   int64_t remainder = 0;

   /* Fill 10 byte timestamp buffer */
   tvb_memcpy(tvb, picosec_buf, offset, LDANEO_PICOSEC_LENGTH);
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

   /* Calculate picosec and nanosec */
   nanosec = _div128(picosec_counter_high, picosec_counter_low, 1000, &remainder);

   timestamp_data result = {(uint16_t)remainder, nanosec};
   return result;
}
#elif defined(__SIZEOF_INT128__)
static timestamp_data
extract_nstime(tvbuff_t *tvb, int32_t offset)
{
   uint8_t picosec_buf[LDANEO_PICOSEC_LENGTH];
   uint16_t picosec;
   uint32_t i;
   uint64_t nanosec;

   /* Fill 10 byte timestamp buffer */
   tvb_memcpy(tvb, picosec_buf, offset, LDANEO_PICOSEC_LENGTH);
   unsigned __int128 picosec_counter;
   picosec_counter = picosec_buf[0];

   /* Extract picosec from buffer */
   for (i = 1; i < sizeof(picosec_buf); ++i) {
      picosec_counter = (picosec_counter << 8) | picosec_buf[i];
   }

   /* Calculate picosec and nanosec */
   picosec = picosec_counter % 1000;
   nanosec = picosec_counter / 1000;

   timestamp_data result = {picosec, nanosec};
   return result;
}
#else
static timestamp_data
extract_nstime(tvbuff_t *, int )
{
   timestamp_data result = {0, 0};
   return result;
}
#endif

static int
dissect_ldaneo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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
    proto_tree *ldaneo_tree;

    timestamp_data timestamp;
    nstime_t ts;

    /* Check do we have enough data */
    extra_trailer_bytes = tvb_captured_length(tvb) - LDANEO_DATA_LENGTH;
    if (extra_trailer_bytes < 0) {
        return 0;
    }

    /* Find the LDANeo signature in the extra trailer bytes */
    for (offset = 0; offset <= extra_trailer_bytes; ++offset) {
        signature = tvb_get_uint8(tvb, offset);
        if (signature != ldasig) {
            continue;
        }

        /* Extract timestamp segments */
        timestamp = extract_nstime(tvb, offset + LDANEO_DATA_LENGTH - LDANEO_PICOSEC_LENGTH);
        ts_sec = (uint32_t)(timestamp.nanosec / 1000000000);
        ts_nsec = timestamp.nanosec % 1000000000;
        ts = (nstime_t)NSTIME_INIT_SECS_NSECS(ts_sec, ts_nsec);

        /* Validate timestamp */
        if (pref_timestamp_validation) {
            nstime_t delta;
            nstime_delta(&delta, &pinfo->abs_ts, &ts);
            if (labs(delta.secs) > SECONDS_IN_MONTH) {
                continue;
            }
        }

        break;
    }
    if (offset > extra_trailer_bytes) {
        /* No valid LDANeo signature found */
        return 0;
    }

    /* Construct LDANeo tree */
    ti_root = proto_tree_add_item(tree, proto_ldaneo, tvb, offset, LDANEO_DATA_LENGTH, ENC_NA);
    ldaneo_tree = proto_item_add_subtree(ti_root, ett_ldaneo);

    /* Construct LDANeo signature */
    proto_tree_add_item(ldaneo_tree, hf_ldaneo_sig, tvb, offset, LDANEO_SIG_LENGTH_V2, ENC_ASCII);
    offset += LDANEO_SIG_LENGTH_V2;

    /* Construct LDANeo sequence number */
    proto_tree_add_item(ldaneo_tree, hf_ldaneo_seq_num, tvb, offset, LDANEO_SEQNUM_LENGTH,
            ENC_BIG_ENDIAN);
    offset += LDANEO_SEQNUM_LENGTH;

    /* Construct LDANeo CRC validation flag */
    proto_tree_add_item(ldaneo_tree, hf_ldaneo_crc_invalid, tvb, offset, LDANEO_DEVID_LENGTH,
            ENC_LITTLE_ENDIAN);

    /* Construct LDANeo device ID */
    proto_tree_add_item(ldaneo_tree, hf_ldaneo_dev_id, tvb, offset, LDANEO_DEVID_LENGTH,
            ENC_LITTLE_ENDIAN);
    offset += LDANEO_DEVID_LENGTH;

    /* Construct LDANeo PCS code tree and fields */
    proto_tree *pcs_tree = proto_tree_add_subtree(ldaneo_tree, tvb, offset, LDANEO_PCS_CODE_LENGTH,
            ett_ldaneo_pcs_code, &ti_root, "PCS");
    pcs_code = tvb_get_uint8(tvb, offset) & LDANEO_MASK_PCS_CODE;
    port = tvb_get_uint8(tvb, offset + LDANEO_PCS_CODE_LENGTH) & LDANEO_MASK_PORT_ID;

    /* PCS Code always 0 for 40G. */
    if (pcs_code == true && port >= LDANEO_40G_PORT_ID_MIN && port <= LDANEO_40G_PORT_ID_MAX) {
        invalid = true;
        proto_tree_add_expert(pcs_tree, pinfo, &ei_ldaneo_pcs_code_invalid, tvb,
                LDANEO_PCS_CODE_OFFSET, LDANEO_PCS_CODE_LENGTH);
    } else {
        proto_tree_add_item(pcs_tree, hf_ldaneo_pcs_code, tvb, offset, LDANEO_PCS_CODE_LENGTH,
                ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(pcs_tree, hf_ldaneo_pcs_code_pos, tvb, offset, LDANEO_PCS_CODE_LENGTH,
            ENC_LITTLE_ENDIAN);
    offset += LDANEO_PCS_CODE_LENGTH;

    /* Construct LDANeo port tree and fields */
    proto_tree *port_tree = proto_tree_add_subtree(ldaneo_tree, tvb, offset, LDANEO_PORTID_LENGTH,
            ett_ldaneo_port, &ti_root, "Port");
    proto_item *port_id_item = proto_tree_add_item(port_tree, hf_ldaneo_port_id, tvb, offset,
            LDANEO_PORTID_LENGTH, ENC_LITTLE_ENDIAN);
    if (port <= LDANEO_40G_PORT_ID_MAX) {
        if (port > LDANEO_40G_PORT_ID_MIN) {
            lane = (port - LDANEO_40G_PORT_ID_MIN) % LDANEO_40G_PORT_LANE_COUNT;

            proto_tree *port_id_tree = proto_item_add_subtree(port_id_item, ett_ldaneo_port_id);
            proto_tree_add_uint(port_id_tree, hf_ldaneo_port_preamble_lane, tvb, offset,
                    LDANEO_PORTID_LENGTH, lane);
        }
    } else {
        invalid = true;
        proto_tree_add_expert(ldaneo_tree, pinfo, &ei_ldaneo_port_id_invalid, tvb,
                LDANEO_PORTID_OFFSET, LDANEO_PORTID_LENGTH);
    }

    speed = (tvb_get_uint8(tvb, offset) & LDANEO_MASK_PORT_SPEED) >> 6;

    /* Validate speed with port_speed_str */
    if (speed < 3) {
        /* Construct LDANeo speed */
        proto_tree_add_item(port_tree, hf_ldaneo_port_speed, tvb, offset,
                LDANEO_PORTID_LENGTH, ENC_LITTLE_ENDIAN);
    } else {
        invalid = true;
        proto_tree_add_expert(port_tree, pinfo, &ei_ldaneo_port_speed_invalid, tvb,
                offset, LDANEO_PORTID_LENGTH);
    }

    if (invalid) {
        expert_add_info(pinfo, ti_root, &ei_ldaneo_invalid);
    }

    offset += LDANEO_PORTID_LENGTH;

    /* Construct LDANeo timestamp */
    //proto_tree *ts_tree = proto_tree_add_subtree(ldaneo_tree, tvb, offset, LDANEO_PICOSEC_LENGTH,
    //        ett_ldaneo_timestamp, &ti_root, "Timestamp");
    proto_item *ts_item = proto_tree_add_item(ldaneo_tree, hf_ldaneo_timestamp, tvb, offset,
            LDANEO_PICOSEC_LENGTH, ENC_NA);
    proto_tree *ts_tree = proto_item_add_subtree(ts_item, ett_ldaneo_timestamp);

#if defined(_M_X64) && (_MSC_VER >= 1920) || defined(__SIZEOF_INT128__)
    proto_tree_add_uint64(ts_tree, hf_ldaneo_nanosec, tvb, offset, LDANEO_PICOSEC_LENGTH,
            timestamp.nanosec);
    proto_tree_add_uint(ts_tree, hf_ldaneo_picosec, tvb, offset, LDANEO_PICOSEC_LENGTH,
            timestamp.picosec);
    proto_tree_add_time(ts_tree, hf_ldaneo_datetime, tvb, offset, LDANEO_PICOSEC_LENGTH, &ts);
#endif

    return offset + LDANEO_PICOSEC_LENGTH;
}

static bool
dissect_ldaneo_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_ldaneo(tvb, pinfo, tree, data) > 0;
}

/*
 * Register the LDANeo protocol
 */
void
proto_register_ldaneo(void)
{
    module_t        *ldaneo_module;
    expert_module_t *expert_ldaneo;

    /* Setup list of header fields */
    static hf_register_info hf[] = {
        {
            &hf_ldaneo_sig,
            {"Signature", "ldaneo.signature", FT_STRING, BASE_NONE, NULL, LDANEO_MASK_DEFAULT,
                NULL, HFILL}
        },
        {
            &hf_ldaneo_seq_num,
            {"Sequence Number", "ldaneo.seqnum", FT_UINT16, BASE_DEC, NULL, LDANEO_MASK_DEFAULT,
                NULL, HFILL}
        },
        {
            &hf_ldaneo_crc_invalid,
            {"CRC Invalid", "ldaneo.crc_invalid", FT_BOOLEAN, 8, NULL, LDANEO_MASK_CRC_INVALID,
                NULL, HFILL}
        },
        {
            &hf_ldaneo_dev_id,
            {"Device ID", "ldaneo.devid", FT_UINT8, BASE_DEC, NULL, LDANEO_MASK_DEVICE_ID, NULL,
                HFILL}
        },
        {
            &hf_ldaneo_pcs_code,
            {"PCS Code 33", "ldaneo.pcscode33", FT_BOOLEAN, 8, NULL, LDANEO_MASK_PCS_CODE,
                NULL, HFILL}
        },

        {
            &hf_ldaneo_pcs_code_pos,
            {"PCS Position", "ldaneo.pcscode_position", FT_UINT8, BASE_DEC, NULL,
                LDANEO_MASK_PCS_CODE_POS, NULL, HFILL}
        },
        {
            &hf_ldaneo_port_id,
            {"Port ID", "ldaneo.portid", FT_UINT8, BASE_DEC, NULL, LDANEO_MASK_PORT_ID, NULL, HFILL}
        },
        {
            &hf_ldaneo_port_preamble_lane,
            {"40G preamble Lane", "ldaneo.preamble_lane", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
        },
        {
            &hf_ldaneo_port_speed,
            {"Port speed", "ldaneo.portspeed", FT_UINT8, BASE_DEC, VALS(port_speed_str),
                LDANEO_MASK_PORT_SPEED, NULL, HFILL}
        },
        {
            &hf_ldaneo_timestamp,
            {"Timestamp", "ldaneo.timestamp", FT_BYTES, BASE_NONE, NULL, LDANEO_MASK_DEFAULT, NULL,
                HFILL}
        },

#if defined(_M_X64) && (_MSC_VER >= 1920) || defined(__SIZEOF_INT128__)
        {
            &hf_ldaneo_nanosec,
            {"Nanosec", "ldaneo.timestamp.nanosec", FT_UINT64, BASE_DEC, NULL, LDANEO_MASK_DEFAULT,
                NULL, HFILL}
        },
        {
            &hf_ldaneo_picosec,
            {"Picosec", "ldaneo.timestamp.picosec", FT_UINT16, BASE_DEC, NULL, LDANEO_MASK_DEFAULT,
                NULL, HFILL}
        },
        {
            &hf_ldaneo_datetime,
            {"Date time", "ldaneo.timestamp.datetime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
                LDANEO_MASK_DEFAULT, NULL, HFILL}
        },
#endif
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        {
            &ei_ldaneo_invalid,
            {"ldaneo.invalid", PI_MALFORMED, PI_ERROR, "Invalid Packet", EXPFILL}
        },
        {
            &ei_ldaneo_pcs_code_invalid,
            {"ldaneo.pcscode33_invalid", PI_MALFORMED, PI_ERROR, "PCS Code 33 invalid", EXPFILL}
        },
        {
            &ei_ldaneo_port_speed_invalid,
            {"ldaneo.portspeed_invalid", PI_MALFORMED, PI_ERROR, "Port speed invalid", EXPFILL}
        },
        {
            &ei_ldaneo_port_id_invalid,
            {"ldaneo.portid_invalid", PI_MALFORMED, PI_ERROR, "Invalid port ID", EXPFILL}
        }
    };
    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_ldaneo,
        &ett_ldaneo_pcs_code,
        &ett_ldaneo_port,
        &ett_ldaneo_port_id,
        &ett_ldaneo_timestamp
    };

    /* Register the protocol name and description */
    proto_ldaneo = proto_register_protocol(
            "LDANeo Device trailer",
            "LDANeo",
            "ldaneo"
    );

    /* Register the header fields and subtrees */
    proto_register_field_array(proto_ldaneo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_ldaneo = expert_register_protocol(proto_ldaneo);
    expert_register_field_array(expert_ldaneo, ei, array_length(ei));

    ldaneo_handle = register_dissector("ldaneo", dissect_ldaneo, proto_ldaneo);

    ldaneo_module = prefs_register_protocol(proto_ldaneo, NULL);
    prefs_register_bool_preference(ldaneo_module, "timestamp", "Enable time validation",
            "The trailer detection includes additional validation through time verification,"
            " which provides extra accuracy.",
            &pref_timestamp_validation);
}

/* The registration ldaneo routine */
void
proto_reg_handoff_ldaneo(void)
{
    /* add session dissector to atn dissector list dissector list */
    heur_dissector_add(
        "eth.trailer",
        dissect_ldaneo_heur,
        "LDANeo Device trailer",
        "ldaneo",
        proto_ldaneo,
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
