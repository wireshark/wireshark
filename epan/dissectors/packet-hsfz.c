/* packet-hsfz.c
 * HSFZ Dissector
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2013-2019 BMW Group, Dr. Lars Voelker
 * Copyright 2020-2023 Technica Engineering, Dr. Lars Voelker
 * Copyright 2023-2023 BMW Group, Hermann Leinsle
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include <config.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include "packet-tcp.h"
#include "packet-udp.h"
#include "packet-hsfz.h"


#define HSFZ_HDR_LEN        6

#define HSFZ_NAME           "HSFZ"
#define HSFZ_NAME_LONG      "High Speed Fahrzeugzugang"
#define HSFZ_NAME_FILTER    "hsfz"


dissector_handle_t hsfz_handle_tcp;
dissector_handle_t hsfz_handle_udp;
dissector_handle_t uds_handle;

void proto_register_hsfz(void);
void proto_reg_handoff_hsfz(void);

static int proto_hsfz;

/*** header fields ***/
static int hf_hsfz_length;
static int hf_hsfz_ctrlword;
static int hf_hsfz_source_address;
static int hf_hsfz_target_address;
static int hf_hsfz_address;
static int hf_hsfz_ident_string;
static int hf_hsfz_data;

/*** protocol tree items ***/
static int ett_hsfz;

/* Control Words */
#define	HSFZ_CTRLWORD_DIAGNOSTIC_REQ_RES        0x0001
#define	HSFZ_CTRLWORD_ACKNOWLEDGE_TRANSFER      0x0002
#define HSFZ_CTRLWORD_TERMINAL15                0x0010
#define HSFZ_CTRLWORD_VEHICLE_IDENT_DATA        0x0011
#define HSFZ_CTRLWORD_ALIVE_CHECK               0x0012
#define	HSFZ_CTRLWORD_STATUS_DATA_INQUIRY       0x0013
#define	HSFZ_CTRLWORD_INCORRECT_TESTER_ADDRESS  0x0040
#define HSFZ_CTRLWORD_INCORRECT_CONTROL_WORD    0x0041
#define HSFZ_CTRLWORD_INCORRECT_FORMAT          0x0042
#define HSFZ_CTRLWORD_INCORRECT_DEST_ADDRESS    0x0043
#define HSFZ_CTRLWORD_MESSAGE_TOO_LARGE         0x0044
#define HSFZ_CTRLWORD_DIAG_APP_NOT_READY        0x0045
#define HSFZ_CTRLWORD_OUT_OF_MEMORY             0x00FF

static const value_string hsfz_ctrlwords[] = {
    {HSFZ_CTRLWORD_DIAGNOSTIC_REQ_RES,          "Request or Response"},
    {HSFZ_CTRLWORD_ACKNOWLEDGE_TRANSFER,        "Acknowledgment"},
    {HSFZ_CTRLWORD_TERMINAL15,                  "Terminal 15 Control Message"},
    {HSFZ_CTRLWORD_VEHICLE_IDENT_DATA,          "Vehicle Identification Data"},
    {HSFZ_CTRLWORD_ALIVE_CHECK,                 "Alive check"},
    {HSFZ_CTRLWORD_STATUS_DATA_INQUIRY,         "Status data inquiry"},
    {HSFZ_CTRLWORD_INCORRECT_TESTER_ADDRESS,    "Incorrect tester address"},
    {HSFZ_CTRLWORD_INCORRECT_CONTROL_WORD,      "Incorrect control word"},
    {HSFZ_CTRLWORD_INCORRECT_FORMAT,            "Incorrect format"},
    {HSFZ_CTRLWORD_INCORRECT_DEST_ADDRESS,      "Incorrect destination address"},
    {HSFZ_CTRLWORD_MESSAGE_TOO_LARGE,           "Message too large"},
    {HSFZ_CTRLWORD_DIAG_APP_NOT_READY,          "Diagnostic application not ready"},
    {HSFZ_CTRLWORD_OUT_OF_MEMORY,               "Out of memory"},
    {0, NULL}
};


/**********************************
 ********* Configuration **********
 **********************************/
typedef struct _udf_one_id_string {
    unsigned	id;
    char*	name;
} udf_one_id_string_t;

/*** Hash Tables for lookup data ***/
static GHashTable *ht_diag_addr;

static bool hsfz_check_header;
static bool hsfz_show_uds_in_ack;

static udf_one_id_string_t *udf_diag_addr;
static unsigned udf_diag_addr_num;

static void *
udf_copy_one_id_string_cb(void* n, const void* o, size_t size _U_) {
    udf_one_id_string_t *new_rec = (udf_one_id_string_t*)n;
    const udf_one_id_string_t *old_rec = (const udf_one_id_string_t*)o;

    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }

    new_rec->id = old_rec->id;
    return new_rec;
}

static void
udf_free_one_id_string_cb(void *r)   {
    udf_one_id_string_t *rec = (udf_one_id_string_t*)r;
    if (rec->name) g_free(rec->name);
}

static void
udf_free_one_id_string_data(void *data _U_)  {
    /* nothing to free here since we did not malloc data in udf_post_update_one_id_string_template_cb */
}

static bool
udf_update_diag_addr_cb(void *r, char **err) {
    udf_one_id_string_t *rec = (udf_one_id_string_t *)r;

    if (rec->id > 0xff) {
        *err = g_strdup_printf("HSFZ only supports 8 bit diagnostic addresses (diag_addr: %i  name: %s)", rec->id, rec->name);
        return (*err == NULL);
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup_printf("ECU Name cannot be empty");
        return (*err == NULL);
    }

    *err = NULL;
    return (*err == NULL);
}

UAT_HEX_CB_DEF(udf_diag_addr, id, udf_one_id_string_t)
UAT_CSTRING_CB_DEF(udf_diag_addr, name, udf_one_id_string_t)

static void
udf_free_key(void *key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
udf_post_update_one_id_string_template_cb(udf_one_id_string_t *udf_data, unsigned udf_data_num, GHashTable *ht) {
    unsigned i;
    int *key = NULL;
    int tmp;

    if (udf_data_num>0) {
        for (i = 0; i < udf_data_num; i++) {
            key = wmem_new(wmem_epan_scope(), int);
            tmp = udf_data[i].id;
            *key = tmp;

            g_hash_table_insert(ht, key, udf_data[i].name);
        }
    }
}

static void
udf_post_update_diag_addr_cb(void) {
    if (ht_diag_addr) {
        g_hash_table_destroy(ht_diag_addr);
        ht_diag_addr = NULL;
    }

    ht_diag_addr = g_hash_table_new_full(g_int_hash, g_int_equal, &udf_free_key, &udf_free_one_id_string_data);
    udf_post_update_one_id_string_template_cb(udf_diag_addr, udf_diag_addr_num, ht_diag_addr);
}

static char*
get_name_from_ht_diag_addr(unsigned identifier) {
    unsigned key = identifier;

    if (ht_diag_addr == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(ht_diag_addr, &key);
}


/**********************************
 ****** The dissector itself ******
 **********************************/

static uint8_t
dissect_hsfz_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int hf_specific_address) {
    proto_item *ti;
    uint32_t tmp;
    char *name;

    ti = proto_tree_add_item_ret_uint(tree, hf_specific_address, tvb, offset, 1, ENC_NA, &tmp);
    name = get_name_from_ht_diag_addr((unsigned)tmp);
    if (name != NULL) {
        proto_item_append_text(ti, " (%s)", name);
    }

    ti = proto_tree_add_item(tree, hf_hsfz_address, tvb, offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(ti);

    return (uint8_t)tmp;
}

static int
dissect_hsfz_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *ti_root;

    uint32_t offset = 0;
    uint32_t real_length = 0;

    uint8_t source_addr;
    uint8_t target_addr;

    if (tvb_captured_length_remaining(tvb, 0) < HSFZ_HDR_LEN) {
        return 0;
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, HSFZ_NAME);

    uint32_t hsfz_length = tvb_get_ntohl(tvb, 0);
    uint16_t hsfz_ctrlword = tvb_get_ntohs(tvb, 4);
    const char *ctrlword_description = val_to_str(hsfz_ctrlword, hsfz_ctrlwords, "Unknown 0x%04x");

    const char *col_string = col_get_text(pinfo->cinfo, COL_INFO);
    if (col_string!=NULL && g_str_has_prefix(col_string, (char *)&"HSFZ\0")) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " / %s %s", HSFZ_NAME, ctrlword_description);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", HSFZ_NAME, ctrlword_description);
    }

    if (hsfz_ctrlword == HSFZ_CTRLWORD_DIAGNOSTIC_REQ_RES || (hsfz_ctrlword == HSFZ_CTRLWORD_ACKNOWLEDGE_TRANSFER && hsfz_show_uds_in_ack)) {
        real_length = HSFZ_HDR_LEN + 2;
    } else {
        real_length = HSFZ_HDR_LEN + hsfz_length;
    }

    ti_root = proto_tree_add_item(tree, proto_hsfz, tvb, 0, real_length, ENC_NA);
    proto_item_append_text(ti_root, ", Length: %i, Control Word: 0x%04x (%s)", hsfz_length, hsfz_ctrlword, ctrlword_description);
    proto_tree *hsfz_tree = proto_item_add_subtree(ti_root, ett_hsfz);

    proto_tree_add_item(hsfz_tree, hf_hsfz_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(hsfz_tree, hf_hsfz_ctrlword, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    switch (hsfz_ctrlword) {
    case HSFZ_CTRLWORD_DIAGNOSTIC_REQ_RES:
    case HSFZ_CTRLWORD_ACKNOWLEDGE_TRANSFER:
        source_addr = dissect_hsfz_address(tvb, pinfo, hsfz_tree, offset, hf_hsfz_source_address);
        offset += 1;

        target_addr = dissect_hsfz_address(tvb, pinfo, hsfz_tree, offset, hf_hsfz_target_address);
        offset += 1;

        if ( (hsfz_ctrlword != HSFZ_CTRLWORD_ACKNOWLEDGE_TRANSFER || hsfz_show_uds_in_ack) && uds_handle != 0) {
            hsfz_info_t hsfz_info;
            hsfz_info.source_address = source_addr;
            hsfz_info.target_address = target_addr;

            tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset, hsfz_length - 2);
            call_dissector_with_data(uds_handle, subtvb, pinfo, tree, &hsfz_info);
        } else {
            proto_tree_add_item(hsfz_tree, hf_hsfz_data, tvb, offset, hsfz_length - 2, ENC_NA);
        }
        break;

    case HSFZ_CTRLWORD_VEHICLE_IDENT_DATA:
        if (hsfz_length > 0) {
            const uint8_t *ident_data;
            proto_tree_add_item_ret_string(hsfz_tree, hf_hsfz_ident_string, tvb, offset, hsfz_length, ENC_ASCII, pinfo->pool, &ident_data);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", ident_data);
        }
        break;

    case HSFZ_CTRLWORD_INCORRECT_DEST_ADDRESS:
    case HSFZ_CTRLWORD_OUT_OF_MEMORY:
        if (hsfz_ctrlword == HSFZ_CTRLWORD_INCORRECT_DEST_ADDRESS || hsfz_length >= 2) {
            dissect_hsfz_address(tvb, pinfo, hsfz_tree, offset, hf_hsfz_source_address);
            offset += 1;

            dissect_hsfz_address(tvb, pinfo, hsfz_tree, offset, hf_hsfz_target_address);
        }
        break;

    default:
        if (hsfz_length > 0) {
            proto_tree_add_item(hsfz_tree, hf_hsfz_data, tvb, offset, hsfz_length, ENC_NA);
        }
        break;
    }

    return HSFZ_HDR_LEN + hsfz_length;
}

static unsigned
get_hsfz_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void* data _U_) {
    /* The length [uint32] does not include the header itself */
    uint32_t length = tvb_get_ntohl(tvb, offset);
    uint16_t ctrlwd = tvb_get_ntohs(tvb, offset + 4);

    /* if heuristic check active: */
    if (hsfz_check_header && (length > 0x000fffff || ctrlwd > 0x00ff )) {
        return 1;
    }

    return HSFZ_HDR_LEN + length;
}

static int
dissect_hsfz_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tcp_dissect_pdus(tvb, pinfo, tree, true, HSFZ_HDR_LEN, get_hsfz_message_len, dissect_hsfz_message, NULL);
    return tvb_captured_length(tvb);
}

static int
dissect_hsfz_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return udp_dissect_pdus(tvb, pinfo, tree, HSFZ_HDR_LEN, NULL, get_hsfz_message_len, dissect_hsfz_message, NULL);
}

void proto_register_hsfz(void) {
    module_t *hsfz_module;
    uat_t* udf_diag_addr_uat;

    /* data fields */
    static hf_register_info hf[] = {
    { &hf_hsfz_length,
        { "Length", "hsfz.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_hsfz_ctrlword,
        { "Control Word", "hsfz.ctrlword", FT_UINT16, BASE_HEX, VALS(hsfz_ctrlwords), 0x0, NULL, HFILL }},
    { &hf_hsfz_source_address,
        { "Source Address", "hsfz.sourceaddr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_hsfz_target_address,
        { "Target Address", "hsfz.targetaddr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_hsfz_address,
        { "Address", "hsfz.address", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_hsfz_ident_string,
        { "Identification String", "hsfz.identification_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_hsfz_data,
        { "Data", "hsfz.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    /* entries in the protocol tree */
    static int *ett[] = {
        &ett_hsfz,
    };

    /* UATs for user_data fields */
    static uat_field_t diag_addr_uat_fields[] = {
        UAT_FLD_HEX(udf_diag_addr, id, "Diagnostic Address", "Diagnostic Address of ECU (hex without leading 0x)"),
        UAT_FLD_CSTRING(udf_diag_addr, name, "ECU Name", "Name of ECU (string)"),
        UAT_END_FIELDS
    };

    proto_hsfz = proto_register_protocol(HSFZ_NAME_LONG, HSFZ_NAME, HSFZ_NAME_FILTER);
    proto_register_field_array(proto_hsfz, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    hsfz_module = prefs_register_protocol(proto_hsfz, NULL);

    prefs_register_bool_preference(hsfz_module, "header_check_heuristic", "Find start of HSFZ header by checking validity",
        "Should the HSFZ dissector check if a HSFZ header for validity (length and control word)?", &hsfz_check_header);

    prefs_register_bool_preference(hsfz_module, "show_uds_in_ack", "Show UDS in HSFZ Ack",
        "Should the shortened UDS in the HSFZ be dissected?", &hsfz_show_uds_in_ack);

    udf_diag_addr_uat = uat_new("Diagnostic Addresses",
        sizeof(udf_one_id_string_t),            /* record size           */
        "HSFZ_diagnostics_addresses",           /* filename              */
        true,                                   /* from_profile          */
        (void**)&udf_diag_addr,                 /* data_ptr              */
        &udf_diag_addr_num,                     /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* specifies addresses   */
        NULL,                                   /* help                  */
        udf_copy_one_id_string_cb,              /* copy callback         */
        udf_update_diag_addr_cb,                /* update callback       */
        udf_free_one_id_string_cb,              /* free callback         */
        udf_post_update_diag_addr_cb,           /* post update callback  */
        NULL,                                   /* reset callback        */
        diag_addr_uat_fields                    /* UAT field definitions */
    );

    prefs_register_uat_preference(hsfz_module, "_udf_diag_addr", "Diagnostic Addresses",
        "A table to define names for diagnostic addresses", udf_diag_addr_uat);
}

void proto_reg_handoff_hsfz(void) {
    hsfz_handle_tcp = register_dissector("hsfz_over_tcp", dissect_hsfz_tcp, proto_hsfz);
    hsfz_handle_udp = register_dissector("hsfz_over_udp", dissect_hsfz_udp, proto_hsfz);

    dissector_add_uint_range_with_preference("tcp.port", "", hsfz_handle_tcp);
    dissector_add_uint_range_with_preference("udp.port", "", hsfz_handle_udp);

    uds_handle = find_dissector("uds_over_hsfz");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
