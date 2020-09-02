/* packet-tecmp.c
 * Technically Enhanced Capture Module Protocol (TECMP) dissector.
 * By <lars.voelker@technica-engineering.de>
 * Copyright 2019-2020 Dr. Lars Voelker
 * Copyright 2020      Ayoub Kaanich
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * This is a dissector for the Technically Enhanced Capture Module Protocol (TECMP).
  * A new automotive protocol to carry data from a so called Capture Module (CM),
  * which is somewhat similar to active network tap, towards a logger or PC to
  * record or analyze the captured data.
  * Capture Modules capture data of LIN, CAN, FlexRay, Ethernet, RS232, or other sources.
  */

#include <config.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/proto_data.h>
#include <packet-socketcan.h>
#include <packet-flexray.h>

void proto_register_tecmp(void);
void proto_reg_handoff_tecmp(void);
void proto_register_tecmp_payload(void);
void proto_reg_handoff_tecmp_payload(void);

static int proto_tecmp = -1;
static int proto_tecmp_payload = -1;
static dissector_handle_t eth_handle;
static int proto_vlan;

static dissector_table_t can_subdissector_table;
static dissector_table_t fr_subdissector_table;

/* Header fields */
/* TECMP */
static int hf_tecmp_cm_id = -1;
static int hf_tecmp_counter = -1;
static int hf_tecmp_version = -1;
static int hf_tecmp_msgtype = -1;
static int hf_tecmp_data_type = -1;
static int hf_tecmp_res = -1;

static int hf_tecmp_cmflags = -1;
static int hf_tecmp_cmflags_eos = -1;
static int hf_tecmp_cmflags_sos = -1;
static int hf_tecmp_cmflags_spy = -1;
static int hf_tecmp_cmflags_multi_frame = -1;
static int hf_tecmp_cmflags_cm_overflow = -1;

/* TECMP Payload */
static int hf_tecmp_payload_channelid = -1;
static int hf_tecmp_payload_timestamp = -1;
static int hf_tecmp_payload_timestamp_ns = -1;
static int hf_tecmp_payload_timestamp_async = -1;
static int hf_tecmp_payload_length = -1;
static int hf_tecmp_payload_data = -1;
static int hf_tecmp_payload_data_length = -1;
static int hf_tecmp_payload_data_payload = -1;
static int hf_tecmp_payload_data_payload_ascii = -1;

/* TECMP Payload flags */
/* Generic */
static int hf_tecmp_payload_data_flags = -1;
static int hf_tecmp_payload_data_flags_crc = -1;
static int hf_tecmp_payload_data_flags_tx = -1;
static int hf_tecmp_payload_data_flags_overflow = -1;

/* LIN */
static int hf_tecmp_payload_data_flags_no_resp = -1;
static int hf_tecmp_payload_data_flags_parity = -1;
static int hf_tecmp_payload_data_flags_coll = -1;

/* CAN and CAN-FD DATA */
static int hf_tecmp_payload_data_flags_ack = -1;
static int hf_tecmp_payload_data_flags_rtr = -1;  /* CAN DATA only */
static int hf_tecmp_payload_data_flags_esi = -1;  /* CAN-FD DATA only */
static int hf_tecmp_payload_data_flags_ide = -1;
static int hf_tecmp_payload_data_flags_err = -1;
static int hf_tecmp_payload_data_flags_brs = -1;  /* CAN-FD DATA only */

/* FlexRay */
static int hf_tecmp_payload_data_flags_nf = -1;
static int hf_tecmp_payload_data_flags_sf = -1;
static int hf_tecmp_payload_data_flags_sync = -1;
static int hf_tecmp_payload_data_flags_wus = -1;
static int hf_tecmp_payload_data_flags_ppi = -1;

/* UART/RS232 ASCII*/
static int hf_tecmp_payload_data_flags_dl = -1;
static int hf_tecmp_payload_data_flags_parity_error = -1;

/* Analog */
static int hf_tecmp_payload_data_flags_sample_time = -1;
static int hf_tecmp_payload_data_flags_factor = -1;
static int hf_tecmp_payload_data_flags_unit = -1;
static int hf_tecmp_payload_data_flags_threshold_u = -1;
static int hf_tecmp_payload_data_flags_threshold_o = -1;

/* TECMP Payload Fields*/
/* LIN */
static int hf_tecmp_payload_data_id_field_8bit = -1;
static int hf_tecmp_payload_data_checksum_8bit = -1;

/* CAN DATA / CAN-FD DATA */
static int hf_tecmp_payload_data_id_field_32bit = -1;
static int hf_tecmp_payload_data_id_type = -1;
static int hf_tecmp_payload_data_id_11 = -1;
static int hf_tecmp_payload_data_id_29 = -1;

/* FlexRay DATA */
static int hf_tecmp_payload_data_cycle = -1;
static int hf_tecmp_payload_data_frame_id = -1;

/* Analog */
static int hf_tecmp_payload_data_analog_value = -1;

/* TECMP Status Messsages */
/* Status Capture Module */
static int hf_tecmp_payload_status_vendor_id = -1;
static int hf_tecmp_payload_status_cm_version = -1;
static int hf_tecmp_payload_status_cm_type = -1;
static int hf_tecmp_payload_status_res = -1;
static int hf_tecmp_payload_status_length_vendor_data = -1;
static int hf_tecmp_payload_status_id = -1;
static int hf_tecmp_payload_status_sn = -1;
static int hf_tecmp_payload_status_vendor_data = -1;

/* Status Bus */
static int hf_tecmp_payload_status_bus_data = -1;
static int hf_tecmp_payload_status_bus_data_entry = -1;
static int hf_tecmp_payload_status_bus_channelid = -1;
static int hf_tecmp_payload_status_bus_total = -1;
static int hf_tecmp_payload_status_bus_errors = -1;

/* Status Capture Module Vendor Data Technica Engineering */
static int hf_tecmp_payload_status_cm_vendor_technica_res = -1;
static int hf_tecmp_payload_status_cm_vendor_technica_sw = -1;
static int hf_tecmp_payload_status_cm_vendor_technica_hw = -1;
static int hf_tecmp_payload_status_cm_vendor_technica_buffer_fill_level = -1;
static int hf_tecmp_payload_status_cm_vendor_technica_buffer_overflow = -1;
static int hf_tecmp_payload_status_cm_vendor_technica_buffer_size = -1;
static int hf_tecmp_payload_status_cm_vendor_technica_lifecycle = -1;
static int hf_tecmp_payload_status_cm_vendor_technica_voltage = -1;
static int hf_tecmp_payload_status_cm_vendor_technica_temperature = -1;

/* Status Bus Vendor Data Technica Engineering */
static int hf_tecmp_payload_status_bus_vendor_technica_link_status = -1;
static int hf_tecmp_payload_status_bus_vendor_technica_link_quality = -1;
static int hf_tecmp_payload_status_bus_vendor_technica_linkup_time = -1;

/* Status Configuration Data Technica Engineering */
static int hf_tecmp_payload_status_cfg_vendor_technica_version = -1;
static int hf_tecmp_payload_status_cfg_vendor_technica_reserved = -1;
static int hf_tecmp_payload_status_cfg_vendor_technica_msg_id = -1;
static int hf_tecmp_payload_status_cfg_vendor_technica_total_length = -1;
static int hf_tecmp_payload_status_cfg_vendor_technica_total_num_seg = -1;
static int hf_tecmp_payload_status_cfg_vendor_technica_segment_num = -1;
static int hf_tecmp_payload_status_cfg_vendor_technica_segment_length = -1;
static int hf_tecmp_payload_status_cfg_vendor_technica_segment_data = -1;

/* TECMP Control Message */
static int hf_tecmp_payload_ctrl_msg_cm_id = -1;
static int hf_tecmp_payload_ctrl_msg_id = -1;

/* protocol tree items */
static gint ett_tecmp = -1;
static gint ett_tecmp_cm_flags = -1;

static gint ett_tecmp_payload = -1;
static gint ett_tecmp_payload_data = -1;
static gint ett_tecmp_payload_timestamp = -1;
static gint ett_tecmp_payload_dataflags = -1;
static gint ett_tecmp_payload_data_id = -1;
static gint ett_tecmp_status_bus_data = -1;
static gint ett_tecmp_status_bus_data_entry = -1;
static gint ett_tecmp_status_cm_vendor_data = -1;
static gint ett_tecmp_status_bus_vendor_data = -1;


/*** expert info items ***/
static expert_field ef_tecmp_payload_length_mismatch = EI_INIT;

/* TECMP Type Names */

#define TECMP_MSG_TYPE_CTRL_MSG            0x00
#define TECMP_MSG_TYPE_STATUS_CM           0x01
#define TECMP_MSG_TYPE_STATUS_BUS          0x02
#define TECMP_MSG_TYPE_LOG_STREAM          0x03
#define TECMP_MSG_TYPE_CFG_CM              0x04
#define TECMP_MSG_TYPE_REPLAY_DATA         0x0A

/* TECMP Type Names */
/* Updated by ID Registry */
static const value_string msg_type_names[] = {
    {TECMP_MSG_TYPE_CTRL_MSG,              "Control Message"},
    {TECMP_MSG_TYPE_STATUS_CM,             "Status Capture Module"},
    {TECMP_MSG_TYPE_STATUS_BUS,            "Status Bus"},
    {TECMP_MSG_TYPE_LOG_STREAM,            "Logging Stream"},
    {TECMP_MSG_TYPE_CFG_CM,                "Status Configuration"},
    {TECMP_MSG_TYPE_REPLAY_DATA,           "Replay Data"},
    {0, NULL}
};

/* TECMP Message Type Names */
/* Updated by ID Registry */
#define TECMP_DATA_TYPE_NONE               0x0000
#define TECMP_DATA_TYPE_CAN_RAW            0x0001
#define TECMP_DATA_TYPE_CAN_DATA           0x0002
#define TECMP_DATA_TYPE_CAN_FD_DATA        0x0003
#define TECMP_DATA_TYPE_LIN                0x0004
#define TECMP_DATA_TYPE_FR_RAW             0x0007
#define TECMP_DATA_TYPE_FR_DATA            0x0008
#define TECMP_DATA_TYPE_GPIO               0x000A
#define TECMP_DATA_TYPE_RS232_ASCII        0x0010
#define TECMP_DATA_TYPE_RS232_RAW          0x0011
#define TECMP_DATA_TYPE_RS232_SLA          0x0012
#define TECMP_DATA_TYPE_ANALOG             0x0020
#define TECMP_DATA_TYPE_ANALOG_SLA         0x0021
#define TECMP_DATA_TYPE_ETH                0x0080
#define TECMP_DATA_TYPE_XCP_DATA           0x00A0
#define TECMP_DATA_TYPE_MIPI_CSI2_V        0x0101
#define TECMP_DATA_TYPE_MIPI_CSI2_L        0x0102
#define TECMP_DATA_TYPE_SPI                0x0103
#define TECMP_DATA_TYPE_I2C_7BIT           0x0104
#define TECMP_DATA_TYPE_TAPI               0x0200
#define TECMP_DATA_TYPE_TAPI_INIT_STATE    0x0201
#define TECMP_DATA_TYPE_TAPI_CORE_DUMP     0x0202
#define TECMP_DATA_TYPE_R                  0x0400
#define TECMP_DATA_TYPE_TECMP_RAW          0xA000
#define TECMP_DATA_TYPE_PRE_LABEL          0xB000

static const value_string tecmp_msgtype_names[] = {
    {TECMP_DATA_TYPE_NONE,                 "None (Undefined)"},
    {TECMP_DATA_TYPE_CAN_RAW,              "CAN(-FD) Raw"},
    {TECMP_DATA_TYPE_CAN_DATA,             "CAN Data"},
    {TECMP_DATA_TYPE_CAN_FD_DATA,          "CAN-FD Data"},
    {TECMP_DATA_TYPE_LIN,                  "LIN"},
    {TECMP_DATA_TYPE_FR_RAW,               "Flexray Raw"},
    {TECMP_DATA_TYPE_FR_DATA,              "Flexray Data"},
    {TECMP_DATA_TYPE_GPIO,                 "GPIO"},
    {TECMP_DATA_TYPE_RS232_ASCII,          "UART/RS232_ASCII"},
    {TECMP_DATA_TYPE_RS232_RAW,            "UART/RS232_RAW"},
    {TECMP_DATA_TYPE_RS232_SLA,            "UART/RS232_SLA"},
    {TECMP_DATA_TYPE_ANALOG,               "Analog"},
    {TECMP_DATA_TYPE_ANALOG_SLA,           "Analog_SLA"},
    {TECMP_DATA_TYPE_ETH,                  "Ethernet II"},
    {TECMP_DATA_TYPE_XCP_DATA,             "XCP-Data"},
    {TECMP_DATA_TYPE_MIPI_CSI2_V,          "MIPI-CSI2 V"},
    {TECMP_DATA_TYPE_MIPI_CSI2_L,          "MIPI-CSI2 L"},
    {TECMP_DATA_TYPE_SPI,                  "SPI"},
    {TECMP_DATA_TYPE_I2C_7BIT,             "I2C 7 Bit"},
    {TECMP_DATA_TYPE_TAPI,                 "TAPI"},
    {TECMP_DATA_TYPE_TAPI_INIT_STATE,      "TAPI Initial State"},
    {TECMP_DATA_TYPE_TAPI_CORE_DUMP,       "TAPI Core Dump"},
    {TECMP_DATA_TYPE_R,                    "R"},
    {TECMP_DATA_TYPE_TECMP_RAW,            "TECMP_Raw"},
    {TECMP_DATA_TYPE_PRE_LABEL,            "PreLabel"},
    {0, NULL}
};

/* Vendor IDs */
/* Updated by ID Registry */
#define TECMP_VENDOR_ID_TECHNICA           0x0c
static const value_string tecmp_vendor_ids[] = {
    {TECMP_VENDOR_ID_TECHNICA,             "Technica Engineering"},
    {0, NULL}
};

/* Capture Module IDs */
/* Can be overwritten/extended by config */
static const value_string tecmp_cm_id_prefixes[] = {
    {0x0030, "CM LIN Combo"},
    {0x0040, "CM CAN Combo"},
    {0x0060, "CM 100 High"},
    {0x0080, "CM Eth Combo"},
    {0x0090, "CM 1000 High"},
    {0, NULL}
};

/* Capture Module Types */
/* Updated by ID Registry */
static const value_string tecmp_cm_types[] = {
    {0x02, "CM LIN Combo"},
    {0x04, "CM CAN Combo"},
    {0x06, "CM 100 High"},
    {0x08, "CM Eth Combo"},
    {0x0a, "CM 1000 High"},
    {0x10, "Sensor specific"},
    {0x20, "Logger"},
    {0, NULL}
};

/* Control Message IDs */
/* Updated by ID Registry */
static const value_string tecmp_ctrl_msg_ids[] = {
    {0x0002, "Logger Ready"},
    {0x0004, "Shutdown Level 1"},
    {0x0005, "Shutdown Level 2"},
    {0x0006, "Shutdown"},
    {0x0010, "Config Mode On"},
    {0x0011, "Logging Mode On"},
    {0x0020, "Trigger 1"},
    {0x0021, "Trigger 2"},
    {0, NULL}
};

static const true_false_string tfs_tecmp_payload_timestamp_async_type = {
    "Not synchronized",
    "Synchronized or Master"
};

static const true_false_string tfs_tecmp_technica_bufferoverflow = {
    "Buffer Overflow occurred",
    "No Buffer Overflow occurred"
};

static const true_false_string tfs_tecmp_payload_data_id_type = {
    "29bit CAN Identifier",
    "11bit CAN Identifier"
};

static const value_string tecmp_payload_rs232_uart_dl_types[] = {
    {0x2, "RS232 with 7 bit"},
    {0x3, "RS232 with 8 bit"},
    {0, NULL}
};

static const value_string tecmp_payload_analog_sample_time_types[] = {
    {0x0, "Comparator Mode"},
    {0x1, "2500 ms"},
    {0x2, "1000 ms"},
    {0x3, "500 ms"},
    {0x4, "250 ms"},
    {0x5, "100 ms"},
    {0x6, "50 ms"},
    {0x7, "25 ms"},
    {0x8, "10 ms"},
    {0x9, "5 ms"},
    {0xa, "2.5 ms"},
    {0xb, "1 ms"},
    {0xc, "0.5 ms"},
    {0xd, "0.25 ms"},
    {0xe, "0.1 ms"},
    {0xf, "0.05 ms"},
    {0, NULL}
};

static const value_string tecmp_payload_analog_factor_types[] = {
    {0x0, "0.1"},
    {0x1, "0.01"},
    {0x2, "0.001"},
    {0x3, "0.0001"},
    {0, NULL}
};

static const value_string tecmp_payload_analog_unit_types[] = {
    {0x0, "V"},
    {0x1, "A"},
    {0x2, "undefined value"},
    {0x3, "undefined value"},
    {0, NULL}
};

static const value_string tecmp_bus_status_link_status[] = {
    {0x0, "Down"},
    {0x1, "Up"},
    {0, NULL}
};

static const value_string tecmp_bus_status_link_quality[] = {
    {0x0, "Unacceptable or Down (0/5)"},
    {0x1, "Poor (1/5)"},
    {0x2, "Marginal (2/5)"},
    {0x3, "Good (3/5)"},
    {0x4, "Very good (4/5)"},
    {0x5, "Excellent (5/5)"},
    {0, NULL}
};

#define DATA_FLAG_CAN_ACK 0x0001
#define DATA_FLAG_CAN_RTR 0x0002
#define DATA_FLAG_CAN_ESI 0x0002
#define DATA_FLAG_CAN_IDE 0x0004
#define DATA_FLAG_CAN_ERR 0x0008
#define DATA_FLAG_CAN_BRS 0x0010

/********* UATs *********/

typedef struct _generic_one_id_string {
    guint   id;
    gchar  *name;
} generic_one_id_string_t;

static void
tecmp_free_key(gpointer key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
simple_free(gpointer data) {
    /* we need to free because of the g_strdup in post_update*/
    g_free(data);
}

/* ID -> Name */
static void *
copy_generic_one_id_string_cb(void* n, const void* o, size_t size _U_) {
    generic_one_id_string_t* new_rec = (generic_one_id_string_t*)n;
    const generic_one_id_string_t* old_rec = (const generic_one_id_string_t*)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->id = old_rec->id;
    return new_rec;
}

static gboolean
update_generic_one_identifier_16bit(void *r, char **err) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;

    if (rec->id > 0xffff) {
        *err = g_strdup_printf("We currently only support 16 bit identifiers (ID: %i  Name: %s)", rec->id, rec->name);
        return FALSE;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return FALSE;
    }

    return TRUE;
}

static void
free_generic_one_id_string_cb(void*r) {
    generic_one_id_string_t* rec = (generic_one_id_string_t*)r;
    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static void
post_update_one_id_string_template_cb(generic_one_id_string_t *data, guint data_num, GHashTable *ht) {
    guint   i;
    int    *key = NULL;

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int);
        *key = data[i].id;

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}

static char*
ht_lookup_name(GHashTable* ht, unsigned int identifier) {
    char           *tmp = NULL;
    unsigned int   *id = NULL;

    if (ht == NULL) {
        return NULL;
    }

    id = wmem_new(wmem_epan_scope(), unsigned int);
    *id = (unsigned int)identifier;
    tmp = (char *)g_hash_table_lookup(ht, id);
    wmem_free(wmem_epan_scope(), id);

    return tmp;
}

/*** UAT TECMP_CM_IDs ***/
#define DATAFILE_TECMP_CM_IDS "TECMP_capture_module_identifiers"

static GHashTable *data_tecmp_cms = NULL;
static generic_one_id_string_t* tecmp_cms = NULL;
static guint tecmp_cms_num = 0;

UAT_DEC_CB_DEF(tecmp_cms, id, generic_one_id_string_t)
UAT_CSTRING_CB_DEF(tecmp_cms, name, generic_one_id_string_t)

static void
post_update_tecmp_cms_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_tecmp_cms) {
        g_hash_table_destroy(data_tecmp_cms);
        data_tecmp_cms = NULL;
    }

    /* create new hash table */
    data_tecmp_cms = g_hash_table_new_full(g_int_hash, g_int_equal, &tecmp_free_key, &simple_free);
    post_update_one_id_string_template_cb(tecmp_cms, tecmp_cms_num, data_tecmp_cms);
}

static void
add_cm_id_text(proto_item *ti, guint16 cm_id) {
    const gchar *descr = ht_lookup_name(data_tecmp_cms, cm_id);

    if (descr != NULL) {
        proto_item_append_text(ti, " (%s)", descr);
    } else {
        /* try to pick a default */
        descr = val_to_str((cm_id & 0xfff0), tecmp_cm_id_prefixes, "Unknown/Unconfigured CM");

        if (descr != NULL) {
            if ((cm_id & 0x000f) == 0) {
                proto_item_append_text(ti, " (%s %d (Default))", descr, (cm_id & 0x000f));
            } else {
                proto_item_append_text(ti, " (%s %d)", descr, (cm_id & 0x000f));
            }
        }
    }
}

static gboolean
tecmp_entry_header_present(tvbuff_t *tvb, guint offset) {
    guint32 chan_id = 0;
    guint64 tstamp  = 0;
    guint16 length  = 0;

    chan_id = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    tstamp  = tvb_get_guint64(tvb, offset + 4, ENC_BIG_ENDIAN);
    length  = tvb_get_guint16(tvb, offset + 12, ENC_BIG_ENDIAN);

    if (chan_id == 0 && tstamp == 0 && length == 0) {
        /* 0 is not valid and therefore we assume padding. */
        return FALSE;
    }
    return TRUE;
}

static guint
dissect_tecmp_entry_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset_orig, guint16 msg_type,
                           gboolean first, guint16 *dataflags) {
    proto_item *ti;
    proto_tree *subtree = NULL;
    guint offset = offset_orig;

    nstime_t timestamp;
    guint64 ns = 0;
    gboolean async = FALSE;

    static int * const dataflags_generic[] = {
        &hf_tecmp_payload_data_flags_crc,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_overflow,
        NULL
    };

    static int * const dataflags_lin[] = {
        &hf_tecmp_payload_data_flags_no_resp,
        &hf_tecmp_payload_data_flags_parity,
        &hf_tecmp_payload_data_flags_coll,
        NULL
    };

    static int * const dataflags_can_data[] = {
        &hf_tecmp_payload_data_flags_ack,
        &hf_tecmp_payload_data_flags_rtr,
        &hf_tecmp_payload_data_flags_ide,
        &hf_tecmp_payload_data_flags_err,
        &hf_tecmp_payload_data_flags_crc,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_overflow,
        NULL
    };

    static int * const dataflags_can_fd_data[] = {
        &hf_tecmp_payload_data_flags_ack,
        &hf_tecmp_payload_data_flags_esi,
        &hf_tecmp_payload_data_flags_ide,
        &hf_tecmp_payload_data_flags_err,
        &hf_tecmp_payload_data_flags_brs,
        &hf_tecmp_payload_data_flags_crc,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_overflow,
        NULL
    };

    static int * const dataflags_flexray_data[] = {
        &hf_tecmp_payload_data_flags_nf,
        &hf_tecmp_payload_data_flags_sf,
        &hf_tecmp_payload_data_flags_sync,
        &hf_tecmp_payload_data_flags_wus,
        &hf_tecmp_payload_data_flags_ppi,
        &hf_tecmp_payload_data_flags_crc,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_overflow,
        NULL
    };

    static int * const dataflags_rs232_uart_ascii[] = {
        &hf_tecmp_payload_data_flags_dl,
        &hf_tecmp_payload_data_flags_parity_error,
        NULL
    };

    static int * const dataflags_analog[] = {
        &hf_tecmp_payload_data_flags_sample_time,
        &hf_tecmp_payload_data_flags_factor,
        &hf_tecmp_payload_data_flags_unit,
        &hf_tecmp_payload_data_flags_threshold_u,
        &hf_tecmp_payload_data_flags_threshold_o,
        NULL
    };

    /* Can't use col_append_sep_str because we already set something before. */
    if (!first) {
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
    }
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(msg_type, tecmp_msgtype_names, "Unknown (%d)"));

    proto_tree_add_item(tree, hf_tecmp_payload_channelid, tvb, offset, 4, ENC_BIG_ENDIAN);

    ns = tvb_get_guint64(tvb, offset + 4, ENC_BIG_ENDIAN) & 0x7fffffffffffffff;

    timestamp.secs = (time_t)(ns / 1000000000);
    timestamp.nsecs = (int)(ns % 1000000000);
    ti = proto_tree_add_time(tree, hf_tecmp_payload_timestamp, tvb, offset + 4, 8, &timestamp);
    subtree = proto_item_add_subtree(ti, ett_tecmp_payload_timestamp);
    proto_tree_add_item_ret_boolean(subtree, hf_tecmp_payload_timestamp_async, tvb, offset + 4, 1,ENC_BIG_ENDIAN,
                                    &async);
    if (async) {
        proto_item_append_text(ti, " (not synchronized)");
    } else {
        proto_item_append_text(ti, " (synchronized or master)");
    }
    ti = proto_tree_add_uint64(tree, hf_tecmp_payload_timestamp_ns, tvb, offset + 4, 8, ns);
    PROTO_ITEM_SET_HIDDEN(ti);

    proto_tree_add_item(tree, hf_tecmp_payload_length, tvb, offset+12, 2, ENC_BIG_ENDIAN);
    offset += 14;

    if (dataflags != NULL) {
        *dataflags = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    }

    switch (msg_type) {
    case TECMP_DATA_TYPE_LIN:
        proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags,
                               dataflags_lin, ENC_BIG_ENDIAN);
        break;

    case TECMP_DATA_TYPE_CAN_DATA:
        proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags,
                               dataflags_can_data, ENC_BIG_ENDIAN);
        break;

    case TECMP_DATA_TYPE_CAN_FD_DATA:
        proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags,
                               dataflags_can_fd_data, ENC_BIG_ENDIAN);
        break;

    case TECMP_DATA_TYPE_FR_DATA:
        proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags,
                               dataflags_flexray_data, ENC_BIG_ENDIAN);
        break;

    case TECMP_DATA_TYPE_RS232_ASCII:
        proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags,
                               dataflags_rs232_uart_ascii, ENC_BIG_ENDIAN);
        break;

    case TECMP_DATA_TYPE_ANALOG:
        proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags,
                               dataflags_analog, ENC_BIG_ENDIAN);
        break;

    case TECMP_DATA_TYPE_ETH:
    default:
        proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags,
                               dataflags_generic, ENC_BIG_ENDIAN);
    }
    offset += 2;

    return offset - offset_orig;
}

static void
dissect_tecmp_status_config_vendor_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *ti_root,
                                        guint8 vendor_id) {
    proto_tree *tree = NULL;
    gint offset = 0;
    guint data_length = 0;

    proto_item_append_text(ti_root, " (%s)", val_to_str(vendor_id, tecmp_vendor_ids, "(Unknown Vendor: %d)"));
    tree = proto_item_add_subtree(ti_root, ett_tecmp_status_bus_vendor_data);

    switch (vendor_id) {
    case TECMP_VENDOR_ID_TECHNICA:
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_version, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_reserved, tvb, offset + 1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_msg_id, tvb, offset + 2, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_total_length, tvb, offset + 4, 4,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_total_num_seg, tvb, offset + 8, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_segment_num, tvb, offset + 10, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(tree, hf_tecmp_payload_status_cfg_vendor_technica_segment_length, tvb,
                                     offset + 12, 2, ENC_BIG_ENDIAN, &data_length);
        offset += 14;
        if (tvb_captured_length_remaining(tvb, offset) >= (gint)data_length) {
            proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_segment_data, tvb, offset,
                                data_length, ENC_NA);
        } else {
            proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_segment_data, tvb, offset,
                                tvb_captured_length_remaining(tvb, offset), ENC_NA);
        }

        break;
    }
}

static void
dissect_tecmp_status_bus_vendor_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *ti_root,
                                     guint8 vendor_id) {
    proto_tree *tree = NULL;
    proto_item *ti = NULL;
    gint offset = 0;
    gint bytes_remaining = 0;
    guint tmp = 0;

    proto_item_append_text(ti_root, " (%s)", val_to_str(vendor_id, tecmp_vendor_ids, "(Unknown Vendor: %d)"));
    tree = proto_item_add_subtree(ti_root, ett_tecmp_status_bus_vendor_data);

    switch (vendor_id) {
    case TECMP_VENDOR_ID_TECHNICA:
        bytes_remaining = tvb_captured_length_remaining(tvb, offset);

        if (bytes_remaining >= 1) {
            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_link_status, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        if (bytes_remaining >= 2) {
            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_link_quality, tvb, offset, 1,
                                ENC_NA);
            offset += 1;
        }
        if (bytes_remaining >= 4) {
            ti = proto_tree_add_item_ret_uint(tree, hf_tecmp_payload_status_bus_vendor_technica_linkup_time, tvb,
                                              offset, 2, ENC_NA, &tmp);
            if (tmp==0) {
                proto_item_append_text(ti, " %s", "(no linkup detected yet)");
            } else if (tmp == 0xffff) {
                proto_item_append_text(ti, " %s", "(no linkup detected and timeout occurred)");
            }
        }
        break;
    }
}

static void
dissect_tecmp_status_cm_vendor_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *ti_root, guint8 vendor_id) {
    proto_tree *tree = NULL;
    proto_item *ti = NULL;
    gint offset = 0;
    guint tmp = 0;

    proto_item_append_text(ti_root, " (%s)", val_to_str(vendor_id, tecmp_vendor_ids, "(Unknown Vendor: %d)"));
    tree = proto_item_add_subtree(ti_root, ett_tecmp_status_cm_vendor_data);

    switch (vendor_id) {
    case TECMP_VENDOR_ID_TECHNICA:
        proto_tree_add_item(tree, hf_tecmp_payload_status_cm_vendor_technica_res, tvb, offset, 1, ENC_NA);
        offset += 1;
        tmp = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_string_format(tree, hf_tecmp_payload_status_cm_vendor_technica_sw, tvb, offset, 3, NULL,
                                     "Software Version: v.%d.%d.%d",
                                     (tmp&0x00ff0000)>>16, (tmp&0x0000ff00)>>8, tmp&0x000000ff);
        offset += 3;

        tmp = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_string_format(tree, hf_tecmp_payload_status_cm_vendor_technica_hw, tvb, offset, 3, NULL,
                                     "Hardware Version: v.%d.%d",
                                     (tmp & 0x0000ff00) >> 8, tmp & 0x000000ff);
        offset += 2;

        ti = proto_tree_add_item(tree, hf_tecmp_payload_status_cm_vendor_technica_buffer_fill_level, tvb, offset, 1,
                                 ENC_NA);
        proto_item_append_text(ti, "%s", "%");
        offset += 1;

        proto_tree_add_item(tree, hf_tecmp_payload_status_cm_vendor_technica_buffer_overflow, tvb, offset, 1, ENC_NA);
        offset += 1;

        tmp = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format_value(tree, hf_tecmp_payload_status_cm_vendor_technica_buffer_size, tvb, offset,
                                         4, tmp * 128, "%d MB", tmp * 128);
        offset += 4;

        ti = proto_tree_add_item(tree, hf_tecmp_payload_status_cm_vendor_technica_lifecycle, tvb, offset, 8,
                                 ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " %s", "ns");
        offset += 8;

        tmp = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_string_format(tree, hf_tecmp_payload_status_cm_vendor_technica_voltage, tvb, offset, 2, NULL,
                                     "Voltage: %d.%d V", (tmp & 0x0000ff00) >> 8, tmp & 0x000000ff);
        offset += 2;

        ti = proto_tree_add_item(tree, hf_tecmp_payload_status_cm_vendor_technica_temperature, tvb, offset, 1, ENC_NA);
        proto_item_append_text(ti, " %s", "Degrees Celsius");

        break;
    }
}

static int
dissect_tecmp_control_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset_orig, guint16 msg_type,
                          guint tecmp_msg_type _U_) {
    proto_item *ti = NULL;
    proto_tree *tecmp_tree = NULL;
    guint16 length = 0;
    guint offset = offset_orig;
    guint cm_id = 0;

    if (tvb_captured_length_remaining(tvb, offset) >= (16 + 4)) {
        length = tvb_get_guint16(tvb, offset + 12, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(tree, proto_tecmp_payload, tvb, offset, (gint)length + 16, ENC_NA);
        proto_item_append_text(ti, " Control Message");
        tecmp_tree = proto_item_add_subtree(ti, ett_tecmp_payload);

        offset += dissect_tecmp_entry_header(tvb, pinfo, tecmp_tree, offset, msg_type, TRUE, NULL);

        col_set_str(pinfo->cinfo, COL_INFO, "TECMP Control Message");

        ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_ctrl_msg_cm_id, tvb, offset, 2, ENC_BIG_ENDIAN,
                                          &cm_id);
        add_cm_id_text(ti, (guint16)cm_id);
        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_id, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return offset - offset_orig;
}

static int
dissect_tecmp_status_cm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset_orig, guint16 msg_type,
                        guint tecmp_msg_type) {
    proto_item *ti = NULL;
    proto_item *ti_tecmp_payload = NULL;
    proto_item *ti_tecmp_vendor_data = NULL;
    proto_item *ti_tecmp_bus = NULL;
    proto_tree *tecmp_tree = NULL;
    proto_tree *tecmp_tree_bus = NULL;
    tvbuff_t *sub_tvb = NULL;
    guint16 length = 0;
    guint16 vendor_data_len = 0;
    guint vendor_id = 0;
    guint offset = offset_orig;
    guint i = 0;
    guint tmp = 0;

    if (tvb_captured_length_remaining(tvb, offset) >= 12) {
        length = tvb_get_guint16(tvb, offset + 12, ENC_BIG_ENDIAN);
        ti_tecmp_payload = proto_tree_add_item(tree, proto_tecmp_payload, tvb, offset, (gint)length + 16, ENC_NA);
        tecmp_tree = proto_item_add_subtree(ti_tecmp_payload, ett_tecmp_payload);

        offset += dissect_tecmp_entry_header(tvb, pinfo, tecmp_tree, offset, msg_type, TRUE, NULL);

        proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_status_vendor_id, tvb, offset, 1, ENC_NA,
                                     &vendor_id);
        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_cm_version, tvb, offset + 1, 1, ENC_NA);
        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_cm_type, tvb, offset + 2, 1, ENC_NA);
        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_res, tvb, offset + 3, 1, ENC_NA);
        offset += 4;

        proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_status_length_vendor_data, tvb, offset, 2,
                                     ENC_BIG_ENDIAN, &tmp);
        vendor_data_len = (guint16)tmp;
        ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_status_id, tvb, offset + 2, 2, ENC_BIG_ENDIAN,
                                          &tmp);
        add_cm_id_text(ti, (guint16)tmp);
        offset += 4;

        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_sn, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        switch (tecmp_msg_type) {
        case TECMP_MSG_TYPE_STATUS_CM:
            col_set_str(pinfo->cinfo, COL_INFO, "TECMP Status Capture Module");
            proto_item_append_text(ti_tecmp_payload, " Status Capture Module");

            if (vendor_data_len > 0) {
                sub_tvb = tvb_new_subset_length_caplen(tvb, offset, (gint)vendor_data_len, (gint)vendor_data_len);
                ti_tecmp_vendor_data = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_vendor_data, tvb,
                                                           offset, (gint)vendor_data_len, ENC_NA);

                dissect_tecmp_status_cm_vendor_data(sub_tvb, pinfo, ti_tecmp_vendor_data, (guint8)vendor_id);
                offset += vendor_data_len;
            }
            break;

        case TECMP_MSG_TYPE_STATUS_BUS:
            col_set_str(pinfo->cinfo, COL_INFO, "TECMP Status Bus");
            proto_item_append_text(ti_tecmp_payload, " Status Bus");

            /* bytes left - entry header (16 bytes) */
            length = length - (guint16)(offset - offset_orig - 16);

            ti_tecmp_bus = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_bus_data, tvb, offset, length,
                                               ENC_NA);
            tecmp_tree = proto_item_add_subtree(ti_tecmp_bus, ett_tecmp_status_bus_data);
            i = 1; /* we start the numbering of the entries with 1. */
            while (length >= (12 + vendor_data_len)) {
                ti_tecmp_bus = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_bus_data_entry, tvb, offset,
                                                   12 + vendor_data_len, ENC_NA);
                proto_item_append_text(ti_tecmp_bus, " %d", i);
                tecmp_tree_bus = proto_item_add_subtree(ti_tecmp_bus, ett_tecmp_status_bus_data_entry);

                proto_tree_add_item_ret_uint(tecmp_tree_bus, hf_tecmp_payload_status_bus_channelid, tvb, offset, 4,
                                             ENC_NA, &tmp);
                proto_item_append_text(ti_tecmp_bus, ": (Channel ID: 0x%08x)", tmp);
                proto_tree_add_item(tecmp_tree_bus, hf_tecmp_payload_status_bus_total, tvb, offset + 4, 4, ENC_NA);
                proto_tree_add_item(tecmp_tree_bus, hf_tecmp_payload_status_bus_errors, tvb, offset + 8, 4, ENC_NA);
                offset += 12;

                if (vendor_data_len > 0) {
                    sub_tvb = tvb_new_subset_length_caplen(tvb, offset, (gint)vendor_data_len, (gint)vendor_data_len);
                    ti_tecmp_vendor_data = proto_tree_add_item(tecmp_tree_bus, hf_tecmp_payload_status_vendor_data,
                                                               tvb, offset, (gint)vendor_data_len, ENC_NA);

                    dissect_tecmp_status_bus_vendor_data(sub_tvb, pinfo, ti_tecmp_vendor_data, (guint8)vendor_id);
                    offset += vendor_data_len;
                }

                i++;
                length -= (12 + vendor_data_len);
            }
            break;

        case TECMP_MSG_TYPE_CFG_CM:
            col_set_str(pinfo->cinfo, COL_INFO, "TECMP Status Configuration");
            proto_item_append_text(ti_tecmp_payload, " Status Configuration");

            if (vendor_data_len > 0) {
                sub_tvb = tvb_new_subset_length_caplen(tvb, offset, (gint)vendor_data_len, (gint)vendor_data_len);
                ti_tecmp_vendor_data = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_vendor_data, tvb,
                                                           offset, (gint)vendor_data_len, ENC_NA);

                dissect_tecmp_status_config_vendor_data(sub_tvb, pinfo, ti_tecmp_vendor_data, (guint8)vendor_id);
                offset += vendor_data_len;
            }
            break;

        default:
            proto_item_append_text(ti_tecmp_payload, " Status Capture Module");
        }

    } else {
        return tvb_captured_length_remaining(tvb, offset);
    }

    return offset - offset_orig;
}

static int
dissect_tecmp_log_or_replay_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset_orig,
                                   guint16 msg_type, guint tecmp_msg_type _U_) {
    proto_item *ti = NULL;
    proto_item *ti_tecmp = NULL;
    proto_tree *tecmp_tree = NULL;
    guint16 length = 0;
    guint32 length2 = 0;
    guint offset = offset_orig;
    guint offset2 = 0;
    guint16 dataflags = 0;
    guint32 tmp = 0;
    tvbuff_t *sub_tvb;
    tvbuff_t *payload_tvb;
    gboolean first = TRUE;

    struct can_info can_info;
    flexray_identifier fr_info;

    static int * const tecmp_payload_id_flags_can_11[] = {
        &hf_tecmp_payload_data_id_type,
        &hf_tecmp_payload_data_id_11,
        NULL
    };

    static int * const tecmp_payload_id_flags_can_29[] = {
        &hf_tecmp_payload_data_id_type,
        &hf_tecmp_payload_data_id_29,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_INFO, "TECMP Payload: ");

    while (tvb_captured_length_remaining(tvb, offset) >= 16) {

        if (!tecmp_entry_header_present(tvb, offset)) {
            /* header not valid, we leave */
            break;
        }

        length = tvb_get_guint16(tvb, offset+12, ENC_BIG_ENDIAN);
        ti_tecmp = proto_tree_add_item(tree, proto_tecmp_payload, tvb, offset, (gint)length + 16, ENC_NA);
        proto_item_append_text(ti_tecmp, " (%s)", val_to_str(msg_type, tecmp_msgtype_names, "Unknown (%d)"));
        tecmp_tree = proto_item_add_subtree(ti_tecmp, ett_tecmp_payload);

        offset += dissect_tecmp_entry_header(tvb, pinfo, tecmp_tree, offset, msg_type, first, &dataflags);

        first = FALSE;

        if (length > 0) {
            sub_tvb = tvb_new_subset_length_caplen(tvb, offset, (gint)length, (gint)length);
            offset2 = 0;

            switch (msg_type) {
            case TECMP_DATA_TYPE_LIN:
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_id_field_8bit, sub_tvb, offset2, 1, ENC_NA);
                ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_length, sub_tvb, offset2 + 1, 1,
                                                  ENC_NA, &length2);
                offset2 += 2;

                if (length2 > 0 && tvb_captured_length_remaining(sub_tvb, offset2) < (gint)(length2 + 1)) {
                    expert_add_info(pinfo, ti, &ef_tecmp_payload_length_mismatch);
                    length2 = MAX(0, MIN((gint)length2, tvb_captured_length_remaining(sub_tvb, offset2) - 1));
                }

                if (length2 > 0) {
                    proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_payload, sub_tvb, offset2, (gint)length2,
                                        ENC_NA);
                    offset2 += (gint)length2;
                    proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_checksum_8bit, sub_tvb, offset2, 1, ENC_NA);
                }

                break;

            case TECMP_DATA_TYPE_CAN_DATA:
            case TECMP_DATA_TYPE_CAN_FD_DATA:
                tmp = tvb_get_guint32(sub_tvb, offset2, ENC_BIG_ENDIAN);
                if ((tmp & 0x80000000) == 0x80000000) {
                    proto_tree_add_bitmask_with_flags(tecmp_tree, sub_tvb, offset2, hf_tecmp_payload_data_id_field_32bit,
                        ett_tecmp_payload_data_id, tecmp_payload_id_flags_can_29, ENC_BIG_ENDIAN, BMT_NO_APPEND);
                } else {
                    proto_tree_add_bitmask_with_flags(tecmp_tree, sub_tvb, offset2, hf_tecmp_payload_data_id_field_32bit,
                        ett_tecmp_payload_data_id, tecmp_payload_id_flags_can_11, ENC_BIG_ENDIAN, BMT_NO_APPEND);
                }
                ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_length, sub_tvb, offset2 + 4, 1, ENC_NA,
                                                  &length2);
                offset2 += 5;

                if (tvb_captured_length_remaining(sub_tvb, offset2) < (gint)length2) {
                    expert_add_info(pinfo, ti, &ef_tecmp_payload_length_mismatch);
                    length2 = MAX(0, MIN((gint)length2, tvb_captured_length_remaining(sub_tvb, offset2)));
                }

                if (length2 > 0) {
                    payload_tvb = tvb_new_subset_length(sub_tvb, offset2, tvb_captured_length_remaining(sub_tvb, offset2));

                    can_info.fd = (msg_type == TECMP_DATA_TYPE_CAN_FD_DATA);
                    can_info.len = tvb_captured_length_remaining(sub_tvb, offset2);

                    /* luckely TECMP and SocketCAN share the first bit as indicator for 11 vs 29bit Identifiers */
                    can_info.id = tmp;

                    if ((dataflags & DATA_FLAG_CAN_RTR) == DATA_FLAG_CAN_RTR) {
                        can_info.id |= CAN_RTR_FLAG;
                    }

                    if ((dataflags & DATA_FLAG_CAN_ERR) == DATA_FLAG_CAN_ERR) {
                        can_info.id |= CAN_ERR_FLAG;
                    }

                    if (!dissector_try_payload_new(can_subdissector_table, payload_tvb, pinfo, tree, TRUE, &can_info))
                    {
                        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_payload, payload_tvb, 0, (gint)length2, ENC_NA);
                    }
                }
                break;

            case TECMP_DATA_TYPE_FR_DATA:
                /* we assume "channel A" since we cannot know */
                fr_info.ch = 0;

                proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_cycle, sub_tvb, offset2, 1, ENC_NA, &tmp);
                fr_info.cc = (guint8)tmp;

                proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_frame_id, sub_tvb, offset2 + 1, 2, ENC_NA, &tmp);
                fr_info.id = (guint16)tmp;

                ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_length, sub_tvb, offset2 + 3, 1, ENC_NA,
                                                  &length2);
                offset2 += 4;

                if (tvb_captured_length_remaining(sub_tvb, offset2) < (gint)length2) {
                    expert_add_info(pinfo, ti, &ef_tecmp_payload_length_mismatch);
                    length2 = MAX(0, MIN((gint)length2, tvb_captured_length_remaining(sub_tvb, offset2)));
                }

                if (length2 > 0) {
                    payload_tvb = tvb_new_subset_length(sub_tvb, offset2, tvb_captured_length_remaining(sub_tvb, offset2));

                    if (!dissector_try_payload_new(fr_subdissector_table, payload_tvb, pinfo, tree, TRUE, &fr_info))
                    {
                        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_payload, payload_tvb, 0, (gint)length2, ENC_NA);
                    }
                }
                break;

            case TECMP_DATA_TYPE_RS232_ASCII:
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_payload_ascii, sub_tvb, offset2, length, ENC_ASCII|ENC_NA);
                break;

            case TECMP_DATA_TYPE_ANALOG:
                ti_tecmp = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data, sub_tvb, offset2, length, ENC_NA);
                tecmp_tree = proto_item_add_subtree(ti_tecmp, ett_tecmp_payload_data);
                tmp = offset2 + length;
                while (offset2 + 2 <= tmp) {
                    proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_analog_value, sub_tvb, offset2, 2, ENC_NA);
                    offset2 += 2;
                }
                break;

            case TECMP_DATA_TYPE_ETH:
                /* resetting VLAN count since this is another embedded Ethernet packet. */
                p_set_proto_depth(pinfo, proto_vlan, 0);
                call_dissector(eth_handle, sub_tvb, pinfo, tecmp_tree);
                break;

            default:
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data, sub_tvb, 0, length, ENC_NA);
            }

            offset += length;
        }
    }

    return offset - offset_orig;
}

static int
dissect_tecmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *ti = NULL;
    proto_item *ti_root = NULL;
    proto_tree *tecmp_tree = NULL;
    guint offset = 0;
    guint tecmp_type = 0;
    guint tecmp_msg_type = 0;
    guint cm_id = 0;

    static int * const tecmp_cm_flags[] = {
        &hf_tecmp_cmflags_eos,
        &hf_tecmp_cmflags_sos,
        &hf_tecmp_cmflags_spy,
        &hf_tecmp_cmflags_multi_frame,
        &hf_tecmp_cmflags_cm_overflow,
        NULL
    };

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TECMP");
    ti_root = proto_tree_add_item(tree, proto_tecmp, tvb, 0, -1, ENC_NA);
    tecmp_tree = proto_item_add_subtree(ti_root, ett_tecmp);

    if (!proto_field_is_referenced(tree, proto_tecmp)) {
        tecmp_tree = NULL;
    }

    ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_cm_id, tvb, offset, 2, ENC_BIG_ENDIAN, &cm_id);
    add_cm_id_text(ti, (guint16)cm_id);
    offset += 2;

    proto_tree_add_item(tecmp_tree, hf_tecmp_counter, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tecmp_tree, hf_tecmp_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_msgtype, tvb, offset, 1, ENC_NA, &tecmp_type);
    offset += 1;

    proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_data_type, tvb, offset, 2, ENC_BIG_ENDIAN, &tecmp_msg_type);
    offset += 2;

    proto_tree_add_item(tecmp_tree, hf_tecmp_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(tecmp_tree, tvb, offset, hf_tecmp_cmflags, ett_tecmp_cm_flags, tecmp_cm_flags,
                           ENC_BIG_ENDIAN);
    offset += 2;

    switch (tecmp_type) {
    case TECMP_MSG_TYPE_CTRL_MSG:
        offset += dissect_tecmp_control_msg(tvb, pinfo, tree, offset, (guint16)tecmp_msg_type, (guint8)tecmp_type);
        break;

    case TECMP_MSG_TYPE_STATUS_BUS:
    case TECMP_MSG_TYPE_CFG_CM:
    case TECMP_MSG_TYPE_STATUS_CM:
        offset += dissect_tecmp_status_cm(tvb, pinfo, tree, offset, (guint16)tecmp_msg_type, (guint8)tecmp_type);
        break;

    case TECMP_MSG_TYPE_LOG_STREAM:
    case TECMP_MSG_TYPE_REPLAY_DATA:
        offset += dissect_tecmp_log_or_replay_stream(tvb, pinfo, tree, offset, (guint16)tecmp_msg_type, (guint8)tecmp_type);
        break;

    }

    proto_item_set_end(ti_root, tvb, offset);
    return offset;
}

void
proto_register_tecmp_payload(void) {
    expert_module_t *expert_module_tecmp_payload;

    static hf_register_info hf[] = {
        { &hf_tecmp_payload_channelid,
            { "Channel ID", "tecmp.payload.channel_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_timestamp,
            { "Timestamp", "tecmp.payload.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_timestamp_async,
            { "Timestamp Synchronisation Status", "tecmp.payload.timestamp_synch_status",
            FT_BOOLEAN, 8, TFS(&tfs_tecmp_payload_timestamp_async_type), 0x80, NULL, HFILL }},
        { &hf_tecmp_payload_timestamp_ns,
            { "Timestamp ns", "tecmp.payload.timestamp_ns",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_length,
            { "Length", "tecmp.payload.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data,
            { "Data", "tecmp.payload.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_id_field_8bit,
            { "ID", "tecmp.payload.data.lin_id",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_checksum_8bit,
            { "Checksum", "tecmp.payload.data.checksum",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_id_field_32bit,
            { "ID Field", "tecmp.payload.data.can_id_field",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_id_type,
            { "CAN ID Type", "tecmp.payload.data.can_id_type",
            FT_BOOLEAN, 32, TFS(&tfs_tecmp_payload_data_id_type), 0x80000000, NULL, HFILL }},
        { &hf_tecmp_payload_data_id_11,
            { "ID (11bit)", "tecmp.payload.data.can_id_11",
            FT_UINT32, BASE_HEX, NULL, 0x7FF, NULL, HFILL }},
        { &hf_tecmp_payload_data_id_29,
            { "ID (29bit)", "tecmp.payload.data.can_id_29",
            FT_UINT32, BASE_HEX, NULL, 0x1FFFFFFF, NULL, HFILL }},

        { &hf_tecmp_payload_data_cycle,
            { "Cycle", "tecmp.payload.data.cycle",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_frame_id,
            { "Frame ID", "tecmp.payload.data.frame_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_length,
            { "Payload Length", "tecmp.payload.data.payload_length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_payload,
            { "Payload", "tecmp.payload.data.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_payload_ascii,
            { "Payload", "tecmp.payload.data.payload_ascii",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_flags,
            { "Data Flags", "tecmp.payload.data_flags",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_crc,
            { "CRC Error", "tecmp.payload.data_flags.crc_error",
            FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_tx,
            { "TX (sent by Capture Module)", "tecmp.payload.data_flags.tx",
            FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_overflow,
            { "Overflow (lost data)", "tecmp.payload.data_flags.Overflow",
            FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},

        /* Control Message */
        { &hf_tecmp_payload_ctrl_msg_cm_id,
            { "Capture Module ID", "tecmp.payload.ctrl_msg.cm_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_ctrl_msg_id,
            { "Control Message ID", "tecmp.payload.ctrl_msg.id",
            FT_UINT16, BASE_HEX, VALS(tecmp_ctrl_msg_ids), 0x0, NULL, HFILL }},

        /* Status Capture Module / Status Bus / Status Configuration */
        { &hf_tecmp_payload_status_vendor_id,
            { "Vendor ID", "tecmp.payload.status.vendor_id",
            FT_UINT8, BASE_HEX, VALS(tecmp_vendor_ids), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_version,
            { "Capture Module Version", "tecmp.payload.status.cm_version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_type,
            { "Capture Module Type", "tecmp.payload.status.cm_type",
            FT_UINT8, BASE_HEX, VALS(tecmp_cm_types), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_res,
            { "Reserved", "tecmp.payload.status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_length_vendor_data,
            { "Length of Vendor Data", "tecmp.payload.status.vdata_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_id,
            { "Capture Module ID", "tecmp.payload.status.cm_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_sn,
            { "Serial Number", "tecmp.payload.status.sn",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_vendor_data,
            { "Vendor Data", "tecmp.payload.status.vendor_data",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_data,
            { "Bus Data", "tecmp.payload.status.bus_data",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_data_entry,
            { "Bus Data Entry", "tecmp.payload.status.bus_data_entry",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_channelid,
            { "Channel ID", "tecmp.payload.status.bus.channelid",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_total,
            { "Messages Total", "tecmp.payload.status.bus.total",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_errors,
            { "Errors Total", "tecmp.payload.status.bus.errors",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Status Capture Module Vendor Data */
        { &hf_tecmp_payload_status_cm_vendor_technica_res,
            { "Reserved", "tecmp.payload.status_cm.vendor_technica.res",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_vendor_technica_sw,
            { "Software Version", "tecmp.payload.status_cm.vendor_technica.sw_version",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_vendor_technica_hw,
            { "Hardware Version", "tecmp.payload.status_cm.vendor_technica.hw_version",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_vendor_technica_buffer_fill_level,
            { "Buffer Fill Level", "tecmp.payload.status_cm.vendor_technica.buffer_fill_level",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_vendor_technica_buffer_overflow,
            { "Buffer Overflow", "tecmp.payload.status_cm.vendor_technica.buffer_overflow",
            FT_BOOLEAN, BASE_DEC, TFS(&tfs_tecmp_technica_bufferoverflow), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_vendor_technica_buffer_size,
            { "Buffer Size", "tecmp.payload.status_cm.vendor_technica.buffer_size",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_vendor_technica_lifecycle,
            { "Lifecycle", "tecmp.payload.status_cm.vendor_technica.lifecycle",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_vendor_technica_voltage,
            { "Voltage", "tecmp.payload.status_cm.vendor_technica.voltage",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cm_vendor_technica_temperature,
            { "Temperature", "tecmp.payload.status_cm.vendor_technica.temperature",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Status Bus Vendor Data */
        { &hf_tecmp_payload_status_bus_vendor_technica_link_status,
            { "Link Status", "tecmp.payload.status.bus.vendor_technica.link_status",
            FT_UINT8, BASE_DEC, VALS(tecmp_bus_status_link_status), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_vendor_technica_link_quality,
            { "Link Quality", "tecmp.payload.status.bus.vendor_technica.link_quality",
            FT_UINT8, BASE_DEC, VALS(tecmp_bus_status_link_quality), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_vendor_technica_linkup_time,
            { "Linkup Time", "tecmp.payload.status.bus.vendor_technica.linkup_time",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Status Bus Vendor Data */
        { &hf_tecmp_payload_status_cfg_vendor_technica_version,
            { "Version", "tecmp.payload.status.config.vendor_technica.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_reserved,
            { "Reserved", "tecmp.payload.status.config.vendor_technica.res",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_msg_id,
            { "Message ID", "tecmp.payload.status.config.vendor_technica.message_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_total_length,
            { "Total Length", "tecmp.payload.status.config.vendor_technica.total_length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_total_num_seg,
            { "Total Number of Segments", "tecmp.payload.status.config.vendor_technica.total_number_segments",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_segment_num,
            { "Segment Number", "tecmp.payload.status.config.vendor_technica.segment_number",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_segment_length,
            { "Segment Length", "tecmp.payload.status.config.vendor_technica.segment_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_segment_data,
            { "Segment Data", "tecmp.payload.status.config.vendor_technica.segment_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* LIN */
        { &hf_tecmp_payload_data_flags_coll,
            { "Collision", "tecmp.payload.data_flags.collision",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_parity,
            { "Parity Error", "tecmp.payload.data_flags.parity_error",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_no_resp,
            { "No Slave Response", "tecmp.payload.data_flags.no_resp",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }},

        /* CAN DATA, CAN-FD Data */
        { &hf_tecmp_payload_data_flags_ack,
            { "Ack'ed", "tecmp.payload.data_flags.ack",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_ACK, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_rtr,
            { "Remote Frame", "tecmp.payload.data_flags.rtr",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_RTR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_esi,
            { "Error Node Active", "tecmp.payload.data_flags.esi",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_ESI, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_ide,
            { "Extended CAN-ID", "tecmp.payload.data_flags.ext_can_id",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_IDE, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_err,
            { "Frame Error", "tecmp.payload.data_flags.frame_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_brs,
            { "Bit Rate Switch", "tecmp.payload.data_flags.bit_rate_switch",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_BRS, NULL, HFILL } },

        /* FlexRay Data */
        { &hf_tecmp_payload_data_flags_nf,
            { "Null Frame", "tecmp.payload.data_flags.null_frame",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_sf,
            { "Startup Frame", "tecmp.payload.data_flags.startup_frame",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_sync,
            { "Sync Frame", "tecmp.payload.data_flags.sync_frame",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_wus,
            { "Wakeup Symbol", "tecmp.payload.data_flags.wakeup_symbol",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_ppi,
            { "Payload Preamble Indicator", "tecmp.payload.data_flags.payload_preamble_indicator",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL }},

        /* UART/RS232 ASCII */
        { &hf_tecmp_payload_data_flags_dl,
            { "DL", "tecmp.payload.data_flags.dl",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_rs232_uart_dl_types), 0x000e, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_parity_error,
            { "Parity Error", "tecmp.payload.data_flags.parity_error",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},

        /* Analog  */
        { &hf_tecmp_payload_data_flags_sample_time,
            { "Sample Time", "tecmp.payload.data_flags.sample_time",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_analog_sample_time_types), 0x7800, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_factor,
            { "Factor", "tecmp.payload.data_flags.factor",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_analog_factor_types), 0x0180, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_unit,
            { "Unit", "tecmp.payload.data_flags.unit",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_analog_unit_types), 0x000c, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_threshold_u,
            { "Threshold Undershot", "tecmp.payload.data_flags.threshold_undershot",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_threshold_o,
            { "Threshold Exceeded", "tecmp.payload.data_flags.threshold_exceeded",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_tecmp_payload_data_analog_value,
            { "Analog Value", "tecmp.payload.data.analog_value",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_tecmp_payload,
        &ett_tecmp_payload_data,
        &ett_tecmp_payload_timestamp,
        &ett_tecmp_payload_dataflags,
        &ett_tecmp_payload_data_id,
        &ett_tecmp_status_cm_vendor_data,
        &ett_tecmp_status_bus_data,
        &ett_tecmp_status_bus_data_entry,
        &ett_tecmp_status_bus_vendor_data,
    };

    static ei_register_info ei[] = {
         { &ef_tecmp_payload_length_mismatch, { "tecmp.payload.payload_length_mismatch",
           PI_PROTOCOL, PI_WARN, "Payload Length and the length of Payload present in packet do not match!", EXPFILL } },
    };

    proto_tecmp_payload = proto_register_protocol("Technically Enhanced Capture Module Protocol Payload",
        "TECMP Payload", "tecmp.payload");
    proto_register_field_array(proto_tecmp_payload, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_tecmp_payload = expert_register_protocol(proto_tecmp_payload);
    expert_register_field_array(expert_module_tecmp_payload, ei, array_length(ei));
}

void
proto_reg_handoff_tecmp_payload(void) {
    eth_handle = find_dissector("eth_maybefcs");
    proto_vlan = proto_get_id_by_filter_name("vlan");
}

void
proto_register_tecmp(void) {
    module_t *tecmp_module = NULL;
    uat_t *tecmp_cmid_uat = NULL;

    static hf_register_info hf[] = {
        { &hf_tecmp_cm_id,
            { "Capture Module ID", "tecmp.cm_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_counter,
            { "Counter", "tecmp.counter",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_version,
            { "Version", "tecmp.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_msgtype,
            { "Message Type", "tecmp.message_type",
            FT_UINT8, BASE_HEX, VALS(msg_type_names), 0x0, NULL, HFILL }},
        { &hf_tecmp_data_type,
            { "Data Type", "tecmp.data_type",
            FT_UINT16, BASE_HEX, VALS(tecmp_msgtype_names), 0x0, NULL, HFILL }},
        { &hf_tecmp_res,
            { "Reserved", "tecmp.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_cmflags,
            { "CM Flags", "tecmp.cm_flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_cmflags_eos,
            { "End of Segment", "tecmp.cm_flags.eos",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_tecmp_cmflags_sos,
            { "Start of Segment", "tecmp.cm_flags.sos",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_tecmp_cmflags_spy,
            { "Spy", "tecmp.cm_flags.spy",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }},
        { &hf_tecmp_cmflags_multi_frame,
            { "Multi Frame", "tecmp.cm_flags.multi_frame",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }},
        { &hf_tecmp_cmflags_cm_overflow,
            { "Capture Module Overflow", "tecmp.cm_flags.cm_overflow",
            FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_tecmp,
        &ett_tecmp_cm_flags,
    };

    /* UATs for user_data fields */
    static uat_field_t tecmp_cm_id_uat_fields[] = {
        UAT_FLD_DEC(tecmp_cms, id, "ID", "ID of the Capture Module (decimal uint16)"),
        UAT_FLD_CSTRING(tecmp_cms, name, "Capture Module Name", "Name of the Capture Module (string)"),
        UAT_END_FIELDS
    };

    proto_tecmp = proto_register_protocol("Technically Enhanced Capture Module Protocol", "TECMP", "tecmp");
    proto_register_field_array(proto_tecmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    tecmp_module = prefs_register_protocol(proto_tecmp, &proto_reg_handoff_tecmp);

    /* UATs */
    tecmp_cmid_uat = uat_new("TECMP Capture Modules",
        sizeof(generic_one_id_string_t),        /* record size           */
        DATAFILE_TECMP_CM_IDS,                  /* filename              */
        TRUE,                                   /* from profile          */
        (void**)&tecmp_cms,                     /* data_ptr              */
        &tecmp_cms_num,                         /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_generic_one_id_string_cb,          /* copy callback         */
        update_generic_one_identifier_16bit,    /* update callback       */
        free_generic_one_id_string_cb,          /* free callback         */
        post_update_tecmp_cms_cb,               /* post update callback  */
        NULL,                                   /* reset callback        */
        tecmp_cm_id_uat_fields                  /* UAT field definitions */
    );

    prefs_register_uat_preference(tecmp_module, "_udf_tecmp_cms", "Capture Modules",
        "A table to define names of Capture Modules, which override default names.", tecmp_cmid_uat);
}

void
proto_reg_handoff_tecmp(void) {
    dissector_handle_t tecmp_handle;

    tecmp_handle = create_dissector_handle(dissect_tecmp, proto_tecmp);
    dissector_add_uint("ethertype", ETHERTYPE_TECMP, tecmp_handle);

    can_subdissector_table = find_dissector_table("can.subdissector");
    fr_subdissector_table  = find_dissector_table("flexray.subdissector");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
