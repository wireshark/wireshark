/* packet-bluetooth.c
 * Routines for the Bluetooth
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Dissector for Bluetooth High Speed over wireless
 * Copyright 2012 intel Corp.
 * Written by Andrei Emeltchenko at intel dot com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/to_str.h>
#include <epan/conversation_table.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/unit_strings.h>
#include <epan/uuid_types.h>
#include <wiretap/wtap.h>
#include "packet-llc.h"
#include <epan/oui.h>

#include <wsutil/str_util.h>

#include "packet-bluetooth.h"

static dissector_handle_t bluetooth_handle;
static dissector_handle_t bluetooth_bthci_handle;
static dissector_handle_t bluetooth_btmon_handle;
static dissector_handle_t bluetooth_usb_handle;

int proto_bluetooth;

static int hf_bluetooth_src;
static int hf_bluetooth_dst;
static int hf_bluetooth_addr;
static int hf_bluetooth_src_str;
static int hf_bluetooth_dst_str;
static int hf_bluetooth_addr_str;

static int hf_llc_bluetooth_pid;

static int ett_bluetooth;

static dissector_handle_t btle_handle;
static dissector_handle_t hci_usb_handle;

static dissector_table_t bluetooth_table;
static dissector_table_t hci_vendor_table;
dissector_table_t        bluetooth_uuid_table;

static wmem_tree_t *chandle_sessions;
static wmem_tree_t *chandle_to_bdaddr;
static wmem_tree_t *chandle_to_mode;
static wmem_tree_t *shandle_to_chandle;
static wmem_tree_t *bdaddr_to_name;
static wmem_tree_t *bdaddr_to_role;
static wmem_tree_t *localhost_name;
static wmem_tree_t *localhost_bdaddr;
static wmem_tree_t *hci_vendors;
static wmem_tree_t *cs_configurations;

static int bluetooth_uuid_id;

static int bluetooth_tap;
int bluetooth_device_tap;
int bluetooth_hci_summary_tap;

// UAT structure
typedef struct _bt_uuid_uat_t {
    char *uuid;
    char *label;
    bool long_attr;
} bt_uuid_uat_t;
static bt_uuid_uat_t* bt_uuids;
static unsigned num_bt_uuids;

static bluetooth_uuid_t get_bluetooth_uuid_from_str(const char *str);

const value_string bluetooth_address_type_vals[] = {
    { 0x00,  "Public" },
    { 0x01,  "Random" },
    { 0, NULL }
};

/*
 * BLUETOOTH SPECIFICATION Version 4.0 [Vol 5] defines that
 * before transmission, the PAL shall remove the HCI header,
 * add LLC and SNAP headers and insert an 802.11 MAC header.
 * Protocol identifier are described in Table 5.2.
 */

#define AMP_U_L2CAP             0x0001
#define AMP_C_ACTIVITY_REPORT   0x0002
#define AMP_C_SECURITY_FRAME    0x0003
#define AMP_C_LINK_SUP_REQUEST  0x0004
#define AMP_C_LINK_SUP_REPLY    0x0005

static const value_string bluetooth_pid_vals[] = {
    { AMP_U_L2CAP,            "AMP_U L2CAP ACL data" },
    { AMP_C_ACTIVITY_REPORT,  "AMP-C Activity Report" },
    { AMP_C_SECURITY_FRAME,   "AMP-C Security frames" },
    { AMP_C_LINK_SUP_REQUEST, "AMP-C Link supervision request" },
    { AMP_C_LINK_SUP_REPLY,   "AMP-C Link supervision reply" },
    { 0,    NULL }
};

uint32_t bluetooth_max_disconnect_in_frame = UINT32_MAX;


void proto_register_bluetooth(void);
void proto_reg_handoff_bluetooth(void);

/* UAT routines */
static bool
bt_uuids_update_cb(void *r, char **err)
{
    bt_uuid_uat_t *rec = (bt_uuid_uat_t *)r;
    bluetooth_uuid_t uuid;

    if (rec->uuid == NULL) {
        *err = g_strdup("UUID can't be empty");
        return false;
    }
    g_strstrip(rec->uuid);
    if (rec->uuid[0] == 0) {
        *err = g_strdup("UUID can't be empty");
        return false;
    }

    uuid = get_bluetooth_uuid_from_str(rec->uuid);
    if (uuid.size == 0) {
        *err = g_strdup("UUID must be 16, 32, or 128-bit, with the latter formatted as XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX");
        return false;
    }
    /* print_numeric_bluetooth_uuid uses bytes_to_hexstr, which uses
     * lowercase hex digits. */
    rec->uuid = ascii_strdown_inplace(rec->uuid);

    if (rec->label == NULL) {
        *err = g_strdup("UUID Name can't be empty");
        return false;
    }
    g_strstrip(rec->label);
    if (rec->label[0] == 0) {
        *err = g_strdup("UUID Name can't be empty");
        return false;
    }

    *err = NULL;
    return true;
}

static void *
bt_uuids_copy_cb(void* n, const void* o, size_t siz _U_)
{
    bt_uuid_uat_t* new_rec = (bt_uuid_uat_t*)n;
    const bt_uuid_uat_t* old_rec = (const bt_uuid_uat_t*)o;

    new_rec->uuid = g_strdup(old_rec->uuid);
    new_rec->label = g_strdup(old_rec->label);
    new_rec->long_attr = old_rec->long_attr;

    return new_rec;
}

static void
bt_uuids_free_cb(void*r)
{
    bt_uuid_uat_t* rec = (bt_uuid_uat_t*)r;

    bluetooth_uuid_t uuid = get_bluetooth_uuid_from_str(rec->uuid);
    uuid_type_remove_if_present(bluetooth_uuid_id, &uuid);
    g_free(rec->uuid);
    g_free(rec->label);
}

static void
bt_uuids_post_update_cb(void)
{
    if (num_bt_uuids) {
        for (unsigned i = 0; i < num_bt_uuids; i++) {
            bluetooth_uuid_t uuid = get_bluetooth_uuid_from_str(bt_uuids[i].uuid);
            bluetooth_uuid_t* uuid_copy = wmem_memdup(wmem_epan_scope(), &uuid, sizeof(uuid));
            uuid_type_insert(bluetooth_uuid_id, uuid_copy, &bt_uuids[i]);
        }
    }
}

static void
bt_uuids_reset_cb(void)
{
}

UAT_CSTRING_CB_DEF(bt_uuids, uuid, bt_uuid_uat_t)
UAT_CSTRING_CB_DEF(bt_uuids, label, bt_uuid_uat_t)
UAT_BOOL_CB_DEF(bt_uuids, long_attr, bt_uuid_uat_t)

static unsigned
bluetooth_uuid_hash(const void* uuid)
{
    const bluetooth_uuid_t* bt_uuid = (const bluetooth_uuid_t*)uuid;
    return wmem_strong_hash(bt_uuid->data, bt_uuid->size);
}

static gboolean
bluetooth_uuid_equal(const void* u1, const void* u2)
{
    const bluetooth_uuid_t *bt_u1 = (const bluetooth_uuid_t*)u1,
                           *bt_u2 = (const bluetooth_uuid_t*)u2;
    if (bt_u1->bt_uuid != bt_u2->bt_uuid)
        return false;

    if (bt_u1->size != bt_u2->size)
        return false;

    return (memcmp(bt_u1->data, bt_u2->data, bt_u1->size) == 0);
}

static const char*
bluetooth_uuid_to_str(void* uuid, wmem_allocator_t* scope)
{
    return print_numeric_bluetooth_uuid(scope, (const bluetooth_uuid_t*)uuid);
}

void bluetooth_add_custom_uuid(const char *uuid_str, const char *label, bool long_attr)
{
    bluetooth_uuid_t uuid = get_bluetooth_uuid_from_str(uuid_str);
    if (uuid.size > 0)
    {
        //Now that the UUID is valid, add it to the table
        bluetooth_uuid_t* uuid_copy = wmem_memdup(wmem_epan_scope(), &uuid, sizeof(uuid));
        bt_uuid_uat_t* custom_uuid = wmem_new(wmem_epan_scope(), bt_uuid_uat_t);

        custom_uuid->uuid = wmem_strdup(wmem_epan_scope(), uuid_str);
        custom_uuid->label = wmem_strdup(wmem_epan_scope(), label);
        custom_uuid->long_attr = long_attr;

        uuid_type_insert(bluetooth_uuid_id, uuid_copy, custom_uuid);
    }
}

bool bluetooth_get_custom_uuid_long_attr(const bluetooth_uuid_t *uuid)
{
    bt_uuid_uat_t* custom_uuid = (bt_uuid_uat_t*)uuid_type_lookup(bluetooth_uuid_id, (void*)uuid);
    if (custom_uuid) {
        return custom_uuid->long_attr;
    }
    return false;
}

const char* bluetooth_get_custom_uuid_description(const bluetooth_uuid_t *uuid)
{
    bt_uuid_uat_t* custom_uuid = (bt_uuid_uat_t*)uuid_type_lookup(bluetooth_uuid_id, (void*)uuid);
    if (custom_uuid) {
        return custom_uuid->label;
    }
    return NULL;
}

/* Decode As routines */
static void bluetooth_uuid_prompt(packet_info *pinfo, char* result)
{
    char *value_data;

    value_data = (char *) p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID);
    if (value_data)
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "BT Service UUID %s as", (char *) value_data);
    else
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown BT Service UUID");
}

static void *bluetooth_uuid_value(packet_info *pinfo)
{
    char *value_data;

    value_data = (char *) p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID);

    if (value_data)
        return (void *) value_data;

    return NULL;
}

int
dissect_bd_addr(int hf_bd_addr, packet_info *pinfo, proto_tree *tree,
        tvbuff_t *tvb, int offset, bool is_local_bd_addr,
        uint32_t interface_id, uint32_t adapter_id, uint8_t *bdaddr)
{
    uint8_t bd_addr[6];

    bd_addr[5] = tvb_get_uint8(tvb, offset);
    bd_addr[4] = tvb_get_uint8(tvb, offset + 1);
    bd_addr[3] = tvb_get_uint8(tvb, offset + 2);
    bd_addr[2] = tvb_get_uint8(tvb, offset + 3);
    bd_addr[1] = tvb_get_uint8(tvb, offset + 4);
    bd_addr[0] = tvb_get_uint8(tvb, offset + 5);

    proto_tree_add_ether(tree, hf_bd_addr, tvb, offset, 6, bd_addr);
    offset += 6;

    if (have_tap_listener(bluetooth_device_tap)) {
        bluetooth_device_tap_t  *tap_device;

        tap_device = wmem_new(pinfo->pool, bluetooth_device_tap_t);
        tap_device->interface_id = interface_id;
        tap_device->adapter_id   = adapter_id;
        memcpy(tap_device->bd_addr, bd_addr, 6);
        tap_device->has_bd_addr = true;
        tap_device->is_local = is_local_bd_addr;
        tap_device->type = BLUETOOTH_DEVICE_BD_ADDR;
        tap_queue_packet(bluetooth_device_tap, pinfo, tap_device);
    }

    if (bdaddr)
        memcpy(bdaddr, bd_addr, 6);

    return offset;
}

void bluetooth_unit_0p625_ms(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%g ms (%u slots)", 0.625 * value, value);
}

void bluetooth_unit_1p25_ms(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%g ms (%u slot-pairs)", 1.25 * value, value);
}

void bluetooth_unit_0p01_sec(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%g sec (%u)", 0.01 * value, value);
}

void bluetooth_unit_0p125_ms(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%g ms (%u)", 0.125 * value, value);
}

const value_string bluetooth_procedure_count_special[] = {
    {0x0, "Infinite, Continue until disabled"},
    {0, NULL}
};

const value_string bluetooth_not_supported_0x00_special[] = {
    {0x0, "Not Supported"},
    {0, NULL}
};

const value_string bluetooth_not_used_0xff_special[] = {
    {0xff, "Not used"},
    {0, NULL}
};

const true_false_string tfs_rtt_accuracy = {
    "10 ns",
    "150 ns"
};

void
save_local_device_name_from_eir_ad(tvbuff_t *tvb, int offset, packet_info *pinfo,
        uint8_t size, bluetooth_data_t *bluetooth_data)
{
    int                     i = 0;
    uint8_t                 length;
    wmem_tree_key_t         key[4];
    uint32_t                k_interface_id;
    uint32_t                k_adapter_id;
    uint32_t                k_frame_number;
    char                    *name;
    localhost_name_entry_t  *localhost_name_entry;

    if (!(!pinfo->fd->visited && bluetooth_data)) return;

    while (i < size) {
        length = tvb_get_uint8(tvb, offset + i);
        if (length == 0) break;

        switch(tvb_get_uint8(tvb, offset + i + 1)) {
        case 0x08: /* Device Name, shortened */
        case 0x09: /* Device Name, full */
            name = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + i + 2, length - 1, ENC_ASCII);

            k_interface_id = bluetooth_data->interface_id;
            k_adapter_id = bluetooth_data->adapter_id;
            k_frame_number = pinfo->num;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_frame_number;
            key[3].length = 0;
            key[3].key    = NULL;

            localhost_name_entry = (localhost_name_entry_t *) wmem_new(wmem_file_scope(), localhost_name_entry_t);
            localhost_name_entry->interface_id = k_interface_id;
            localhost_name_entry->adapter_id = k_adapter_id;
            localhost_name_entry->name = wmem_strdup(wmem_file_scope(), name);

            wmem_tree_insert32_array(bluetooth_data->localhost_name, key, localhost_name_entry);

            break;
        }

        i += length + 1;
    }
}


static const char* bluetooth_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_ADDRESS) {
        if (conv->src_address.type == AT_ETHER)
            return "bluetooth.src";
        else if (conv->src_address.type == AT_STRINGZ)
            return "bluetooth.src_str";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (conv->dst_address.type == AT_ETHER)
            return "bluetooth.dst";
        else if (conv->dst_address.type == AT_STRINGZ)
            return "bluetooth.dst_str";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (conv->src_address.type == AT_ETHER && conv->dst_address.type == AT_ETHER)
            return "bluetooth.addr";
        else if (conv->src_address.type == AT_STRINGZ && conv->dst_address.type == AT_STRINGZ)
            return "bluetooth.addr_str";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t bluetooth_ct_dissector_info = {&bluetooth_conv_get_filter_type};


static const char* bluetooth_endpoint_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
    if (filter == CONV_FT_ANY_ADDRESS) {
        if (endpoint->myaddress.type == AT_ETHER)
            return "bluetooth.addr";
        else if (endpoint->myaddress.type == AT_STRINGZ)
            return "bluetooth.addr_str";
    }

    return CONV_FILTER_INVALID;
}

static et_dissector_info_t  bluetooth_et_dissector_info = {&bluetooth_endpoint_get_filter_type};


static tap_packet_status
bluetooth_conversation_packet(void *pct, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;
    add_conversation_table_data(hash, &pinfo->dl_src, &pinfo->dl_dst, 0, 0, 1,
            pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts,
            &bluetooth_ct_dissector_info, CONVERSATION_NONE);

    return TAP_PACKET_REDRAW;
}


static tap_packet_status
bluetooth_endpoint_packet(void *pit, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

    add_endpoint_table_data(hash, &pinfo->dl_src, 0, true,  1, pinfo->fd->pkt_len, &bluetooth_et_dissector_info, ENDPOINT_NONE);
    add_endpoint_table_data(hash, &pinfo->dl_dst, 0, false, 1, pinfo->fd->pkt_len, &bluetooth_et_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static conversation_t *
get_conversation(packet_info *pinfo,
                     address *src_addr, address *dst_addr,
                     uint32_t src_endpoint, uint32_t dst_endpoint)
{
    conversation_t *conversation;

    conversation = find_conversation(pinfo->num,
                               src_addr, dst_addr,
                               CONVERSATION_BLUETOOTH,
                               src_endpoint, dst_endpoint, 0);
    if (conversation) {
        return conversation;
    }

    conversation = conversation_new(pinfo->num,
                           src_addr, dst_addr,
                           CONVERSATION_BLUETOOTH,
                           src_endpoint, dst_endpoint, 0);
    return conversation;
}

static bluetooth_uuid_t
get_bluetooth_uuid_from_str(const char *str)
{
    bluetooth_uuid_t  uuid;
    char digits[3];
    const char *p = str;

    memset(&uuid, 0, sizeof(uuid));

    ws_return_val_if(!str, uuid);

    static const char fmt[] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";
    const size_t fmtchars = sizeof(fmt) - 1;

    size_t size = strlen(str);
    if (size != 4 && size != 8 && size != fmtchars) {
        return uuid;
    }

    for (size_t i = 0; i < size; i++) {
        if (fmt[i] == 'X') {
            if (!g_ascii_isxdigit(str[i]))
                return uuid;
        } else {
            if (str[i] != fmt[i])
                return uuid;
        }
    }

    if (size == 4) {
        size = 2;
    } else if (size == 8) {
        size = 4;
    } else if (size == fmtchars) {
        size = 16;
    } else {
        ws_assert_not_reached();
    }

    for (size_t i = 0; i < size; i++) {
        if (*p == '-') ++p;
        digits[0] = *(p++);
        digits[1] = *(p++);
        digits[2] = '\0';
        uuid.data[i] = (uint8_t)strtoul(digits, NULL, 16);
    }

    if (size == 4) {
        if (uuid.data[0] == 0x00 && uuid.data[1] == 0x00) {
            uuid.data[0] = uuid.data[2];
            uuid.data[1] = uuid.data[3];
            size = 2;
        }
    } else if (size == 16) {
        if (uuid.data[0] == 0x00 && uuid.data[1] == 0x00 &&
            uuid.data[4]  == 0x00 && uuid.data[5]  == 0x00 && uuid.data[6]  == 0x10 &&
            uuid.data[7]  == 0x00 && uuid.data[8]  == 0x80 && uuid.data[9]  == 0x00 &&
            uuid.data[10] == 0x00 && uuid.data[11] == 0x80 && uuid.data[12] == 0x5F &&
            uuid.data[13] == 0x9B && uuid.data[14] == 0x34 && uuid.data[15] == 0xFB) {

            uuid.data[0] = uuid.data[2];
            uuid.data[1] = uuid.data[3];
            size = 2;
        }
    }

    if (size == 2) {
        uuid.bt_uuid = uuid.data[1] | uuid.data[0] << 8;
    }
    uuid.size = (uint8_t)size;
    return uuid;
}

bluetooth_uuid_t
get_bluetooth_uuid(tvbuff_t *tvb, int offset, int size)
{
    bluetooth_uuid_t  uuid;

    memset(&uuid, 0, sizeof(uuid));

    if (size != 2 && size != 4 && size != 16) {
        return uuid;
    }

    if (size == 2) {
        uuid.data[0] = tvb_get_uint8(tvb, offset + 1);
        uuid.data[1] = tvb_get_uint8(tvb, offset);

        uuid.bt_uuid = uuid.data[1] | uuid.data[0] << 8;
    } else if (size == 4) {
        uuid.data[0] = tvb_get_uint8(tvb, offset + 3);
        uuid.data[1] = tvb_get_uint8(tvb, offset + 2);
        uuid.data[2] = tvb_get_uint8(tvb, offset + 1);
        uuid.data[3] = tvb_get_uint8(tvb, offset);

        if (uuid.data[0] == 0x00 && uuid.data[1] == 0x00) {
            uuid.bt_uuid = uuid.data[3] | uuid.data[2] << 8;
            size = 2;
        }
    } else {
        uuid.data[0] = tvb_get_uint8(tvb, offset + 15);
        uuid.data[1] = tvb_get_uint8(tvb, offset + 14);
        uuid.data[2] = tvb_get_uint8(tvb, offset + 13);
        uuid.data[3] = tvb_get_uint8(tvb, offset + 12);
        uuid.data[4] = tvb_get_uint8(tvb, offset + 11);
        uuid.data[5] = tvb_get_uint8(tvb, offset + 10);
        uuid.data[6] = tvb_get_uint8(tvb, offset + 9);
        uuid.data[7] = tvb_get_uint8(tvb, offset + 8);
        uuid.data[8] = tvb_get_uint8(tvb, offset + 7);
        uuid.data[9] = tvb_get_uint8(tvb, offset + 6);
        uuid.data[10] = tvb_get_uint8(tvb, offset + 5);
        uuid.data[11] = tvb_get_uint8(tvb, offset + 4);
        uuid.data[12] = tvb_get_uint8(tvb, offset + 3);
        uuid.data[13] = tvb_get_uint8(tvb, offset + 2);
        uuid.data[14] = tvb_get_uint8(tvb, offset + 1);
        uuid.data[15] = tvb_get_uint8(tvb, offset);

        if (uuid.data[0] == 0x00 && uuid.data[1] == 0x00 &&
            uuid.data[4]  == 0x00 && uuid.data[5]  == 0x00 && uuid.data[6]  == 0x10 &&
            uuid.data[7]  == 0x00 && uuid.data[8]  == 0x80 && uuid.data[9]  == 0x00 &&
            uuid.data[10] == 0x00 && uuid.data[11] == 0x80 && uuid.data[12] == 0x5F &&
            uuid.data[13] == 0x9B && uuid.data[14] == 0x34 && uuid.data[15] == 0xFB) {
            uuid.bt_uuid = uuid.data[3] | uuid.data[2] << 8;
            size = 2;
        }
    }

    uuid.size = size;
    return uuid;
}

/* Extract a UUID stored in big-endian order within a tvb. */
bluetooth_uuid_t
get_bluetooth_uuid_be(tvbuff_t *tvb, int offset, int size)
{
    bluetooth_uuid_t uuid;

    memset(&uuid, 0, sizeof(uuid));

    if (size != 2 && size != 4 && size != 16) {
        return uuid;
    }

    tvb_memcpy(tvb, uuid.data, offset, size);

    if (size == 2) {
        /* [0x11, 0x01] in tvb -> 0x1101 */
        uuid.bt_uuid = (uuid.data[0] << 8) | uuid.data[1];
    }
    else if (size == 4) {
        /* Check if the 32-bit UUID can be collapsed to 16-bit */
        if (uuid.data[0] == 0x00 && uuid.data[1] == 0x00) {
            uuid.bt_uuid = (uuid.data[2] << 8) | uuid.data[3];
            size = 2;
        }
    }
    else {
        /* Check if the 128-bit UUID can be collapsed to 16-bit */
        if (uuid.data[0]  == 0x00 && uuid.data[1]  == 0x00 &&
            uuid.data[4]  == 0x00 && uuid.data[5]  == 0x00 && uuid.data[6]  == 0x10 &&
            uuid.data[7]  == 0x00 && uuid.data[8]  == 0x80 && uuid.data[9]  == 0x00 &&
            uuid.data[10] == 0x00 && uuid.data[11] == 0x80 && uuid.data[12] == 0x5F &&
            uuid.data[13] == 0x9B && uuid.data[14] == 0x34 && uuid.data[15] == 0xFB) {

            uuid.bt_uuid = (uuid.data[2] << 8) | uuid.data[3];
            size = 2;
        }
    }

    uuid.size = size;
    return uuid;
}


const char *
print_numeric_bluetooth_uuid(wmem_allocator_t *pool, const bluetooth_uuid_t *uuid)
{
    if (!(uuid && uuid->size > 0))
        return NULL;

    if (uuid->size == 2) {
        return wmem_strdup_printf(pool, "%04x", uuid->bt_uuid);
    }
    else if (uuid->size != 16) {
        return bytes_to_str(pool, uuid->data, uuid->size);
    }

    char *text;

    text = (char *) wmem_alloc(pool, 38);
    bytes_to_hexstr(&text[0], uuid->data, 4);
    text[8] = '-';
    bytes_to_hexstr(&text[9], uuid->data + 4, 2);
    text[13] = '-';
    bytes_to_hexstr(&text[14], uuid->data + 4 + 2 * 1, 2);
    text[18] = '-';
    bytes_to_hexstr(&text[19], uuid->data + 4 + 2 * 2, 2);
    text[23] = '-';
    bytes_to_hexstr(&text[24], uuid->data + 4 + 2 * 3, 6);
    text[36] = '\0';

    return text;
}

const char *
try_print_bluetooth_uuid(const bluetooth_uuid_t *uuid)
{
    const char *description = NULL;

    if (uuid->bt_uuid) {
        const char *name;

        /*
         * Known UUID?
         */
        name = try_val_to_str_ext(uuid->bt_uuid, &bluetooth_uuid_vals_ext);
        if (name != NULL) {
            /*
             * Yes.  This string is part of the value_string_ext table,
             * so we don't have to make a copy.
             */
            return name;
        }

        /*
         * No - fall through to try looking it up.
         */
    }

    description = bluetooth_get_custom_uuid_description(uuid);

    return description;
}

const char *
print_bluetooth_uuid(const bluetooth_uuid_t *uuid)
{
    const char *description = try_print_bluetooth_uuid(uuid);

    if (description == NULL) {
        description = "Unknown";
    }

    return description;
}


bluetooth_data_t *
dissect_bluetooth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item        *main_item;
    proto_tree        *main_tree;
    proto_item        *sub_item;
    bluetooth_data_t  *bluetooth_data;
    address           *src;
    address           *dst;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bluetooth");
    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    default:
        col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
        break;
    }

    pinfo->ptype = PT_BLUETOOTH;
    get_conversation(pinfo, &pinfo->dl_src, &pinfo->dl_dst, pinfo->srcport, pinfo->destport);

    main_item = proto_tree_add_item(tree, proto_bluetooth, tvb, 0, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bluetooth);

    bluetooth_data = (bluetooth_data_t *) wmem_new(pinfo->pool, bluetooth_data_t);
    if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
        bluetooth_data->interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    else
        bluetooth_data->interface_id = HCI_INTERFACE_DEFAULT;
    bluetooth_data->adapter_id = HCI_ADAPTER_DEFAULT;
    bluetooth_data->adapter_disconnect_in_frame  = &bluetooth_max_disconnect_in_frame;
    bluetooth_data->chandle_sessions             = chandle_sessions;
    bluetooth_data->chandle_to_bdaddr            = chandle_to_bdaddr;
    bluetooth_data->chandle_to_mode              = chandle_to_mode;
    bluetooth_data->shandle_to_chandle           = shandle_to_chandle;
    bluetooth_data->bdaddr_to_name               = bdaddr_to_name;
    bluetooth_data->bdaddr_to_role               = bdaddr_to_role;
    bluetooth_data->localhost_bdaddr             = localhost_bdaddr;
    bluetooth_data->localhost_name               = localhost_name;
    bluetooth_data->hci_vendors                  = hci_vendors;
    bluetooth_data->cs_configurations            = cs_configurations;

    if (have_tap_listener(bluetooth_tap)) {
        bluetooth_tap_data_t  *bluetooth_tap_data;

        bluetooth_tap_data                = wmem_new(pinfo->pool, bluetooth_tap_data_t);
        bluetooth_tap_data->interface_id  = bluetooth_data->interface_id;
        bluetooth_tap_data->adapter_id    = bluetooth_data->adapter_id;

        tap_queue_packet(bluetooth_tap, pinfo, bluetooth_tap_data);
    }

    src = (address *) p_get_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC);
    dst = (address *) p_get_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST);

    if (src && src->type == AT_STRINGZ) {
        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_addr_str, tvb, 0, 0, (const char *) src->data);
        proto_item_set_hidden(sub_item);

        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_src_str, tvb, 0, 0, (const char *) src->data);
        proto_item_set_generated(sub_item);
    } else if (src && src->type == AT_ETHER) {
        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_addr, tvb, 0, 0, (const uint8_t *) src->data);
        proto_item_set_hidden(sub_item);

        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_src, tvb, 0, 0, (const uint8_t *) src->data);
        proto_item_set_generated(sub_item);
    }

    if (dst && dst->type == AT_STRINGZ) {
        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_addr_str, tvb, 0, 0, (const char *) dst->data);
        proto_item_set_hidden(sub_item);

        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_dst_str, tvb, 0, 0, (const char *) dst->data);
        proto_item_set_generated(sub_item);
    } else if (dst && dst->type == AT_ETHER) {
        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_addr, tvb, 0, 0, (const uint8_t *) dst->data);
        proto_item_set_hidden(sub_item);

        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_dst, tvb, 0, 0, (const uint8_t *) dst->data);
        proto_item_set_generated(sub_item);
    }

    return bluetooth_data;
}

/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_H4, WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR,
 * WTAP_ENCAP_PACKETLOGGER. WTAP_ENCAP_BLUETOOTH_LE_LL,
 * WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR, and WTAP_ENCAP_BLUETOOTH_BREDR_BB.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static int
dissect_bluetooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * There is no pseudo-header, or there's just a p2p pseudo-header.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_NONE;
    bluetooth_data->previous_protocol_data.none = NULL;

    if (!dissector_try_uint_with_data(bluetooth_table, pinfo->rec->rec_header.packet_header.pkt_encap, tvb, pinfo, tree, true, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}


/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_HCI.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static int
dissect_bluetooth_bthci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a struct bthci_phdr.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_BTHCI;
    bluetooth_data->previous_protocol_data.bthci = (struct bthci_phdr *)data;

    if (!dissector_try_uint_with_data(bluetooth_table, pinfo->rec->rec_header.packet_header.pkt_encap, tvb, pinfo, tree, true, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static int
dissect_bluetooth_btmon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a struct btmon_phdr.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_BTMON;
    bluetooth_data->previous_protocol_data.btmon = (struct btmon_phdr *)data;

    if (!dissector_try_uint_with_data(bluetooth_table, pinfo->rec->rec_header.packet_header.pkt_encap, tvb, pinfo, tree, true, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/*
 * Register this in various USB dissector tables.
 */
static int
dissect_bluetooth_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    /* A crafted Exported PDU file can name this without the URB info */
    if (data == NULL)
        return 0;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a urb_info_t.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_URB_INFO;
    bluetooth_data->previous_protocol_data.urb = (urb_info_t *)data;

    return call_dissector_with_data(hci_usb_handle, tvb, pinfo, tree, bluetooth_data);
}

/*
 * Register this by name; it's called from the Ubertooth dissector.
 */
static int
dissect_bluetooth_ubertooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a ubertooth_data_t.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_UBERTOOTH_DATA;
    bluetooth_data->previous_protocol_data.ubertooth_data = (ubertooth_data_t *)data;

    call_dissector(btle_handle, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void
proto_register_bluetooth(void)
{
    static hf_register_info hf[] = {
        { &hf_bluetooth_src,
            { "Source",                              "bluetooth.src",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_dst,
            { "Destination",                         "bluetooth.dst",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_addr,
            { "Source or Destination",               "bluetooth.addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_src_str,
            { "Source",                              "bluetooth.src_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_dst_str,
            { "Destination",                         "bluetooth.dst_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_addr_str,
            { "Source or Destination",               "bluetooth.addr_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info oui_hf[] = {
        { &hf_llc_bluetooth_pid,
            { "PID",    "llc.bluetooth_pid",
            FT_UINT16, BASE_HEX, VALS(bluetooth_pid_vals), 0x0,
            "Protocol ID", HFILL }
        }
    };

    static int *ett[] = {
        &ett_bluetooth,
    };

    // UAT
    module_t *bluetooth_module;
    uat_t* bluetooth_uuids_uat;
    static uat_field_t bluetooth_uuids_uat_fields[] = {
        UAT_FLD_CSTRING(bt_uuids, uuid, "UUID", "UUID"),
        UAT_FLD_CSTRING(bt_uuids, label, "UUID Name", "Readable label"),
        UAT_FLD_BOOL(bt_uuids, long_attr, "Long Attribute", "A Long Attribute that may be sent in multiple BT ATT PDUs"),
        UAT_END_FIELDS
    };

    /* Decode As handling */
    static build_valid_func bluetooth_uuid_da_build_value[1] = {bluetooth_uuid_value};
    static decode_as_value_t bluetooth_uuid_da_values = {bluetooth_uuid_prompt, 1, bluetooth_uuid_da_build_value};
    static decode_as_t bluetooth_uuid_da = {"bluetooth", "bluetooth.uuid", 1, 0, &bluetooth_uuid_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL, NULL, NULL };


    proto_bluetooth = proto_register_protocol("Bluetooth", "Bluetooth", "bluetooth");

    register_dissector("bluetooth_ubertooth", dissect_bluetooth_ubertooth, proto_bluetooth);

    proto_register_field_array(proto_bluetooth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bluetooth_table = register_dissector_table("bluetooth.encap",
            "Bluetooth Encapsulation", proto_bluetooth, FT_UINT32, BASE_HEX);

    chandle_sessions         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_bdaddr        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_mode          = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    shandle_to_chandle       = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bdaddr_to_name           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bdaddr_to_role           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    localhost_bdaddr         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    localhost_name           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    hci_vendors              = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    cs_configurations        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    hci_vendor_table = register_dissector_table("bluetooth.vendor", "HCI Vendor", proto_bluetooth, FT_UINT16, BASE_HEX);
    bluetooth_uuid_id = uuid_type_dissector_register("bluetooth", bluetooth_uuid_hash, bluetooth_uuid_equal, bluetooth_uuid_to_str);

    bluetooth_tap = register_tap("bluetooth");
    bluetooth_device_tap = register_tap("bluetooth.device");
    bluetooth_hci_summary_tap = register_tap("bluetooth.hci_summary");

    bluetooth_uuid_table = register_dissector_table("bluetooth.uuid", "BT Service UUID", proto_bluetooth, FT_STRING, STRING_CASE_SENSITIVE);
    llc_add_oui(OUI_BLUETOOTH, "llc.bluetooth_pid", "LLC Bluetooth OUI PID", oui_hf, proto_bluetooth);

    register_conversation_table(proto_bluetooth, true, bluetooth_conversation_packet, bluetooth_endpoint_packet);

    register_decode_as(&bluetooth_uuid_da);

    bluetooth_module = prefs_register_protocol(proto_bluetooth, NULL);
    bluetooth_uuids_uat = uat_new("Custom Bluetooth UUIDs",
                                  sizeof(bt_uuid_uat_t),
                                  "bluetooth_uuids",
                                  true,
                                  &bt_uuids,
                                  &num_bt_uuids,
                                  UAT_AFFECTS_DISSECTION,
                                  NULL,
                                  bt_uuids_copy_cb,
                                  bt_uuids_update_cb,
                                  bt_uuids_free_cb,
                                  bt_uuids_post_update_cb,
                                  bt_uuids_reset_cb,
                                  bluetooth_uuids_uat_fields);

    static const char* bt_uuids_uat_defaults_[] = {
      NULL, NULL, "FALSE" };
    uat_set_default_values(bluetooth_uuids_uat, bt_uuids_uat_defaults_);

    prefs_register_uat_preference(bluetooth_module, "uuids",
                                  "Custom Bluetooth UUID names",
                                  "Assign readable names to custom UUIDs",
                                  bluetooth_uuids_uat);

    bluetooth_handle = register_dissector("bluetooth", dissect_bluetooth, proto_bluetooth);
    bluetooth_bthci_handle = register_dissector("bluetooth.bthci", dissect_bluetooth_bthci, proto_bluetooth);
    bluetooth_btmon_handle = register_dissector("bluetooth.btmon", dissect_bluetooth_btmon, proto_bluetooth);
    bluetooth_usb_handle = register_dissector("bluetooth.usb", dissect_bluetooth_usb, proto_bluetooth);

    register_external_value_string_ext("bluetooth_company_id_vals_ext", &bluetooth_company_id_vals_ext);
    register_external_value_string_ext("bluetooth_uuid_vals_ext", &bluetooth_uuid_vals_ext);
}

void
proto_reg_handoff_bluetooth(void)
{
    dissector_handle_t eapol_handle;
    dissector_handle_t btl2cap_handle;

    btle_handle = find_dissector_add_dependency("btle", proto_bluetooth);
    hci_usb_handle = find_dissector_add_dependency("hci_usb", proto_bluetooth);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_HCI,           bluetooth_bthci_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4,            bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR,  bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR, bluetooth_btmon_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_PACKETLOGGER,            bluetooth_handle);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL,           bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR, bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_BREDR_BB,        bluetooth_handle);

    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x1131 << 16) | 0x1001, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x050d << 16) | 0x0081, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x2198, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x04bf << 16) | 0x0320, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x13d3 << 16) | 0x3375, bluetooth_usb_handle);

    dissector_add_uint("usb.protocol", 0xE00101, bluetooth_usb_handle);
    dissector_add_uint("usb.protocol", 0xE00104, bluetooth_usb_handle);

    dissector_add_for_decode_as("usb.device", bluetooth_usb_handle);

    bluetooth_add_custom_uuid("00000001-0000-1000-8000-0002EE000002", "SyncML Server", false);
    bluetooth_add_custom_uuid("00000002-0000-1000-8000-0002EE000002", "SyncML Client", false);
    bluetooth_add_custom_uuid("7905F431-B5CE-4E99-A40F-4B1E122D00D0", "Apple Notification Center Service", false);

    eapol_handle = find_dissector("eapol");
    btl2cap_handle = find_dissector("btl2cap");

    dissector_add_uint("llc.bluetooth_pid", AMP_C_SECURITY_FRAME, eapol_handle);
    dissector_add_uint("llc.bluetooth_pid", AMP_U_L2CAP, btl2cap_handle);

/* TODO: Add UUID128 version of UUID16; UUID32? UUID16? */
}


/* Most of the following Apple continuity code has bas been ported from
 * https://github.com/furiousMAC/continuity/tree/master
 * Authored by Sam Teplov, gigaryte, phrj, Emilqn Stanchev and XenoKovah
 */

static int proto_btad_apple_continuity;

static int hf_btad_apple_type;
static int hf_btad_apple_length;
static int hf_btad_apple_data;
static int hf_btad_apple_nearbyinfo_os;
static int hf_btad_apple_ibeacon_uuid128;
static int hf_btad_apple_ibeacon_major;
static int hf_btad_apple_ibeacon_minor;
static int hf_btad_apple_ibeacon_measured_power;
static int hf_btad_apple_airprint_addrtype;
static int hf_btad_apple_airprint_resourcepathtype;
static int hf_btad_apple_airprint_securitytype;
static int hf_btad_apple_airprint_qidport;
static int hf_btad_apple_airprint_ipaddr;
static int hf_btad_apple_airprint_power;
static int hf_btad_apple_airdrop_prefix;
static int hf_btad_apple_airdrop_version;
static int hf_btad_apple_airdrop_appleid;
static int hf_btad_apple_airdrop_phone;
static int hf_btad_apple_airdrop_email;
static int hf_btad_apple_airdrop_email2;
static int hf_btad_apple_airdrop_suffix;
static int hf_btad_apple_homekit_status;
static int hf_btad_apple_homekit_deviceid;
static int hf_btad_apple_homekit_category;
static int hf_btad_apple_homekit_globalstatenum;
static int hf_btad_apple_homekit_confignum;
static int hf_btad_apple_homekit_compver;
static int hf_btad_apple_airpods_prefix;
static int hf_btad_apple_airpods_devicemodel;
static int hf_btad_apple_airpods_status;
static int hf_btad_apple_airpods_leftbattery;
static int hf_btad_apple_airpods_rightbattery;
static int hf_btad_apple_airpods_leftcharging;
static int hf_btad_apple_airpods_rightcharging;
static int hf_btad_apple_airpods_casecharging;
static int hf_btad_apple_airpods_casebattery;
static int hf_btad_apple_airpods_opencount;
static int hf_btad_apple_airpods_devicecolor;
static int hf_btad_apple_airpods_suffix;
static int hf_btad_apple_airpods_encdata;
static int hf_btad_apple_airpods_battery_status;
static int hf_btad_apple_airpods_charging_status;
static int hf_btad_apple_airpods_casebattery_status;
static int hf_btad_apple_airpods_battery_charging_status;
static int hf_btad_apple_siri_perphash;
static int hf_btad_apple_siri_snr;
static int hf_btad_apple_siri_confidence;
static int hf_btad_apple_siri_deviceclass;
static int hf_btad_apple_siri_randbyte;
static int hf_btad_apple_airplay_flags;
static int hf_btad_apple_airplay_seed;
static int hf_btad_apple_airplay_ip;
static int hf_btad_apple_airplay_data;
static int hf_btad_apple_magicswitch_data;
static int hf_btad_apple_magicswitch_confidence;
static int hf_btad_apple_handoff_copy;
static int hf_btad_apple_handoff_seqnum;
static int hf_btad_apple_handoff_authtag;
static int hf_btad_apple_handoff_encdata;
static int hf_btad_apple_tethtgt_icloudid;
static int hf_btad_apple_tethsrc_version;
static int hf_btad_apple_tethsrc_flags;
static int hf_btad_apple_tethsrc_battery;
static int hf_btad_apple_tethsrc_celltype;
static int hf_btad_apple_tethsrc_cellbars;
static int hf_btad_apple_nearbyaction_flags;
static int hf_btad_apple_nearbyaction_flags_authtag;
static int hf_btad_apple_nearbyaction_type;
static int hf_btad_apple_nearbyaction_auth;
static int hf_btad_apple_nearbyaction_setup_device_class;
static int hf_btad_apple_nearbyaction_setup_device_model;
static int hf_btad_apple_nearbyaction_setup_device_color;
static int hf_btad_apple_nearbyaction_setup_msg_version;
static int hf_btad_apple_nearbyaction_wifijoin_ssid;
static int hf_btad_apple_nearbyaction_wifijoin_appleid;
static int hf_btad_apple_nearbyaction_wifijoin_phonenumber;
static int hf_btad_apple_nearbyaction_wifijoin_email;
static int hf_btad_apple_nearbyaction_data;
static int hf_btad_apple_nearbyinfo_statusflags;
static int hf_btad_apple_nearbyinfo_airdrop_status;
static int hf_btad_apple_nearbyinfo_unk_flag;
static int hf_btad_apple_nearbyinfo_unk_flag2;
static int hf_btad_apple_nearbyinfo_primary_device;
static int hf_btad_apple_nearbyinfo_action_code;
static int hf_btad_apple_nearbyinfo_dataflags;
static int hf_btad_apple_nearbyinfo_autounlock_enabled;
static int hf_btad_apple_nearbyinfo_autounlock_watch;
static int hf_btad_apple_nearbyinfo_watch_locked;
static int hf_btad_apple_nearbyinfo_authtag_present;
static int hf_btad_apple_nearbyinfo_unk_flag3;
static int hf_btad_apple_nearbyinfo_wifi_status;
static int hf_btad_apple_nearbyinfo_authtag_fourbyte= -1;
static int hf_btad_apple_nearbyinfo_airpod_conn;
static int hf_btad_apple_nearbyinfo_auth;
static int hf_btad_apple_nearbyinfo_postauth;
static int hf_btad_apple_findmy_status;
static int hf_btad_apple_findmy_publickey;
static int hf_btad_apple_findmy_publickeybits;
static int hf_btad_apple_findmy_hint;
static int hf_btad_apple_findmy_data;
static int hf_btad_apple_findmy_publickeyxcoord;

static int ett_btad_apple;
static int ett_btad_apple_airpods;
static int ett_btad_apple_airpods_battery;
static int ett_btad_apple_airpods_charging;
static int ett_btad_apple_nearbyinfo_status;
static int ett_btad_apple_nearbyinfo_data;

static dissector_handle_t btad_apple_continuity;
static dissector_handle_t btad_apple_ibeacon;

void proto_register_btad_apple_continuity(void);
void proto_reg_handoff_btad_apple_continuity(void);

#define BTAD_APPLE_OBSERVED_IPHONE     0x0001
#define BTAD_APPLE_IBEACON             0x0002
#define BTAD_APPLE_AIRPRINT            0x0003
#define BTAD_APPLE_AIRDROP             0x0005
#define BTAD_APPLE_HOMEKIT             0x0006
#define BTAD_APPLE_AIRPODS             0x0007
#define BTAD_APPLE_SIRI                0x0008
#define BTAD_APPLE_AIRPLAY_TARGET      0x0009
#define BTAD_APPLE_AIRPLAY_SOURCE      0x000a
#define BTAD_APPLE_MAGIC_SWITCH        0x000b
#define BTAD_APPLE_HANDOFF             0x000c
#define BTAD_APPLE_TETHERING_TARGET    0x000d
#define BTAD_APPLE_TETHERING_SOURCE    0x000e
#define BTAD_APPLE_NEARBY_ACTION       0x000f
#define BTAD_APPLE_NEARBY_INFO         0x0010
#define BTAD_APPLE_FIND_MY             0x0012

static const value_string btad_apple_type_values[] = {
    { BTAD_APPLE_OBSERVED_IPHONE,    "Observed on iPhone" },
    { BTAD_APPLE_IBEACON,            "iBeacon" },
    { BTAD_APPLE_AIRPRINT,           "AirPrint" },
    { BTAD_APPLE_AIRDROP,            "AirDrop" },
    { BTAD_APPLE_HOMEKIT,            "HomeKit" },
    { BTAD_APPLE_AIRPODS,            "AirPods" },
    { BTAD_APPLE_SIRI,               "Hey Siri" },
    { BTAD_APPLE_AIRPLAY_TARGET,     "AirPlay Target" },
    { BTAD_APPLE_AIRPLAY_SOURCE,     "AirPlay Source" },
    { BTAD_APPLE_MAGIC_SWITCH,       "Magic Switch" },
    { BTAD_APPLE_HANDOFF,            "Handoff" },
    { BTAD_APPLE_TETHERING_TARGET,   "Tethering Target" },
    { BTAD_APPLE_TETHERING_SOURCE,   "Tethering Source" },
    { BTAD_APPLE_NEARBY_ACTION,      "Nearby Action" },
    { BTAD_APPLE_NEARBY_INFO,        "Nearby Info" },
    { BTAD_APPLE_FIND_MY,            "Find My Message" },
    { 0,    NULL }
};

static const value_string btad_apple_homekit_category_vals[] = {
    { 0x0000, "Unknown" },
    { 0x0100, "Other" },
    { 0x0200, "Bridge" },
    { 0x0300, "Fan" },
    { 0x0400, "Garage Door Opener" },
    { 0x0500, "Lightbulb" },
    { 0x0600, "Door Lock" },
    { 0x0700, "Outlet" },
    { 0x0800, "Switch" },
    { 0x0900, "Thermostat" },
    { 0x0A00, "Sensor" },
    { 0x0B00, "Security System" },
    { 0x0C00, "Door" },
    { 0x0D00, "Window" },
    { 0x0E00, "Window Covering" },
    { 0x0F00, "Programmable Switch" },
    { 0x1000, "Range Extender" },
    { 0x1100, "IP Camera" },
    { 0x1200, "Video Doorbell" },
    { 0x1300, "Air Purifier" },
    { 0x1400, "Heater" },
    { 0x1500, "Air Conditioner" },
    { 0x1600, "Humidifier" },
    { 0x1700, "Dehumidifier" },
    { 0x1C00, "Sprinklers" },
    { 0x1D00, "Faucets" },
    { 0x1E00, "Shower Systems" },
    { 0, NULL}
};

static const value_string btad_apple_airpods_device_vals[] = {
    { 0x0220, "AirPods 1" },
    { 0x0f20, "AirPods 2" },
    { 0x0e20, "AirPods Pro" },
    { 0x0320, "Powerbeats3" },
    { 0x0520, "BeatsX" },
    { 0x0620, "Beats Solo 3" },
    { 0, NULL}
};

static const value_string btad_apple_airpods_status_vals[] = {
    { 0x2b, "Both AirPods in ear" },
    { 0x0b, "Both AirPods in ear" },
    { 0x01, "AirPods: Both out of case, not in ear" },
    { 0x21, "Both taken out of ears, Pause Audio" },
    { 0x02, "Right in ear, Left in case" },
    { 0x22, "Left in ear, Right in case" },
    { 0x75, "Case: Both AirPods in case" },
    { 0x55, "Case: Both AirPods in case" },
    { 0x03, "AirPods: Right in ear, Left out of case" },
    { 0x23, "AirPods: Left in ear, Right out of case" },
    { 0x33, "AirPods: Left in ear, Right in case" },
    { 0x53, "Case: Left in ear, Right in case" },
    { 0x13, "AirPods: Right in ear, Left in case" },
    { 0x73, "Case: Right in ear, Left in case" },
    { 0x11, "AirPods: Right out of case, Left in case" },
    { 0x71, "Case: Right out of case, Left in case" },
    { 0x31, "AirPods: Left out of case, Right in case" },
    { 0x51, "Case: Left out of case, Right in case" },
    { 0, NULL}
};

static const value_string btad_apple_airpods_color_vals[] = {
    { 0x00, "White" },
    { 0x01, "Black" },
    { 0x02, "Red" },
    { 0x03, "Blue" },
    { 0x04, "Pink" },
    { 0x05, "Gray" },
    { 0x06, "Silver" },
    { 0x07, "Gold" },
    { 0x08, "Rose Gold" },
    { 0x09, "Space Gray" },
    { 0x0A, "Dark Blue" },
    { 0x0B, "Light Blue" },
    { 0x0C, "Yellow" },
    { 0, NULL}
};

static const value_string btad_apple_siri_device_vals[] = {
    { 0x0002, "iPhone" },
    { 0x0003, "iPad" },
    { 0x0007, "HomePod" },
    { 0x0009, "MacBook" },
    { 0x000A, "Watch" },
    { 0, NULL}
};

static const value_string btad_apple_wrist_confidence_vals[] = {
    { 0x03, "Not on Wrist" },
    { 0x1F, "Wrist detection disabled" },
    { 0x3F, "On Wrist" },
    { 0, NULL}
};

static const value_string btad_apple_cellular_type_vals[] = {
    { 0x0, "4G (GSM)" },
    { 0x1, "1xRTT" },
    { 0x2, "GPRS" },
    { 0x3, "EDGE" },
    { 0x4, "3G (EV-DO)" },
    { 0x5, "3G" },
    { 0x6, "4G" },
    { 0x7, "LTE" },
    { 0, NULL }
};

static const value_string btad_apple_nearbyaction_type_vals[] = {
    { 0x01, "Apple TV Tap-To-Setup" },
    { 0x04, "Mobile Backup" },
    { 0x05, "Watch Setup" },
    { 0x06, "Apple TV Pair" },
    { 0x07, "Internet Relay" },
    { 0x08, "Wi-Fi Password" },
    { 0x09, "iOS Setup" },
    { 0x0A, "Repair" },
    { 0x0B, "Speaker Setup" },
    { 0x0C, "Apple Pay" },
    { 0x0D, "Whole Home Audio Setup" },
    { 0x0E, "Developer Tools Pairing Request" },
    { 0x0F, "Answered Call" },
    { 0x10, "Ended Call" },
    { 0x11, "DD Ping" },
    { 0x12, "DD Pong" },
    { 0x13, "Remote Auto Fill" },
    { 0x14, "Companion Link Prox" },
    { 0x15, "Remote Management" },
    { 0x16, "Remote Auto Fill Pong" },
    { 0x17, "Remote Display" },
    { 0, NULL }
};

static const value_string btad_apple_device_class_vals[] = {
    { 0x2,  "iPhone" },
    { 0x4,  "iPod" },
    { 0x6,  "iPad" },
    { 0x8,  "Audio accessory (HomePod)" },
    { 0xA,  "Mac" },
    { 0xC,  "AppleTV" },
    { 0xE,  "Watch" },
    { 0,    NULL }
};

static const value_string btad_apple_device_model_vals[] = {
    { 0x0, "5, 6, 7, 8, SE (2nd Gen)" },
    { 0x1, "D22 (X, XS, XSMax)" },
    { 0x2, "SE (1st Gen)" },
    { 0x3, "JEXX" },
    { 0, NULL }
};

static const value_string btad_apple_device_color_vals[] = {
    { 0x00, "Unknown" },
    { 0x01, "Black" },
    { 0x02, "White" },
    { 0x03, "Red" },
    { 0x04, "Silver" },
    { 0x05, "Pink" },
    { 0x06, "Blue" },
    { 0x07, "Yellow" },
    { 0x08, "Gold" },
    { 0x09, "Sparrow" },
    { 0, NULL }
};

static const value_string btad_apple_action_vals[] = {
    {  0, "Activity Level Unknown" },
    {  1, "Activity Reporting Disabled (Recently Updated/iPhone Setup)" },
    {  2, "Apple iOS 13.6 Bug" },
    {  3, "Locked Phone" },
    {  4, "Apple iOS 13.6 Bug" },
    {  5, "Audio is Playing with Screen off" }, /* Never Observed */
    {  6, "Apple iOS 13.6 Bug" },
    {  7, "Transition to Inactive User or from Locked Screen" },
    {  8, "Apple iOS 13.6 Bug" },
    {  9, "Screen is on and Video is playing" }, /* Never Observed */
    { 10, "Locked Phone; Push Notifications to Watch" },
    { 11, "Active User" },
    { 12, "Apple iOS 13.6 Bug" },
    { 13, "User is Driving a Vehicle (CarPlay)"},
    { 14, "Phone/FaceTime Call" },
    { 15, "Apple iOS 13.6 Bug" },
    { 16, "Apple iOS 13.6 Bug" },
    { 0, NULL }
};

static const value_string btad_apple_findmy_status_vals[] = {
    { 0x00, "Owner did not connect within key rotation period (15 min.)" },
    { 0xe4, "Owner connected within key rotation period, Battery Critically Low" },
    { 0xa4, "Owner connected within key rotation period, Battery Low" },
    { 0x64, "Owner connected within key rotation period, Battery Medium" },
    { 0x24, "Owner connected within key rotation period, Battery Full" },
    { 0, NULL}
};

static const value_string btad_apple_findmy_publickeybits_vals[] = {
    { 0x00, "bits 6 & 7 not set in public key" },
    { 0x01, "bit 6 set in public key" },
    { 0x02, "bit 7 set in public key" },
    { 0x03, "bits 6 & 7 set in public key" },
    { 0, NULL}
};

static int
dissect_btad_apple_continuity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree       *main_tree, *airpods_tree;
    proto_item       *main_item, *airpods_item, *os_item;
    int               offset = 0;
    uint32_t          type, length;
    uint32_t          handoff_nearby_flag = 0;
    uint32_t          nearbyaction_type_val;
    uint8_t           nearby_action_flags_check;
    uint8_t           nearby_os_val, auth_tag_present, four_byte_authtag;
    uint32_t          apple_os_flag = 0, os_set = 0, ios_13_flag = 0;
    bluetooth_eir_ad_apple_data_t *apple_data;
    address          *src;
    char             *publicKeyStr;
    uint32_t          pubKeyBits;
    uint8_t           pubKey[28];


    main_item = proto_tree_add_item(tree, proto_btad_apple_continuity, tvb, offset, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btad_apple);

    apple_data = (bluetooth_eir_ad_apple_data_t *) p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_EIR_AD_APPLE);
    if (apple_data) {
        apple_os_flag = apple_data->apple_os_flag;
        ios_13_flag = apple_data->ios_13_flag;
    }

    if(apple_os_flag == 0x06 && os_set == 0){ /* if MacOS and OS not set yet */
        /* changed to 0,0 so it doesn't tie to byte */
        os_item = proto_tree_add_string(main_tree, hf_btad_apple_nearbyinfo_os, tvb, 0, 0, "macOS");
        os_set = 1;
        PROTO_ITEM_SET_GENERATED(os_item);
    }
    else if(ios_13_flag == 1 && os_set == 0){ /* if iOS13 and OS not set yet */
        os_item = proto_tree_add_string(main_tree, hf_btad_apple_nearbyinfo_os, tvb, offset, 0, "iOS >=13");
        os_set = 1;
        PROTO_ITEM_SET_GENERATED(os_item);
    }
    else {
        os_item = proto_tree_add_string(main_tree, hf_btad_apple_nearbyinfo_os, tvb, offset, 0, "unknown");
        PROTO_ITEM_SET_GENERATED(os_item);
    }

    proto_tree_add_item_ret_uint(main_tree, hf_btad_apple_type, tvb, offset, 1, ENC_NA, &type);
    offset += 1;

    proto_tree_add_item_ret_uint(main_tree, hf_btad_apple_length, tvb, offset, 1, ENC_NA, &length);
    offset += 1;

    switch(type) {
        case BTAD_APPLE_IBEACON:
            proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_uuid128, tvb, offset, 16, ENC_BIG_ENDIAN);
            offset += 16;
            proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_major, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_minor, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_measured_power, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case BTAD_APPLE_AIRPRINT:
            if (length == 22) {
                proto_tree_add_item(main_tree, hf_btad_apple_airprint_addrtype, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airprint_resourcepathtype, tvb, offset , 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airprint_securitytype, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airprint_qidport, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_airprint_ipaddr, tvb, offset, 16, ENC_NA);
                offset += 16;
                proto_tree_add_item(main_tree, hf_btad_apple_airprint_power, tvb, offset, 1, ENC_NA);
                offset += 1;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_AIRDROP:
            if (length == 18) {
                proto_tree_add_item(main_tree, hf_btad_apple_airdrop_prefix, tvb, offset, 8, ENC_NA);
                offset += 8;
                proto_tree_add_item(main_tree, hf_btad_apple_airdrop_version, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airdrop_appleid, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_airdrop_phone, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_airdrop_email, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_airdrop_email2, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_airdrop_suffix, tvb, offset, 1, ENC_NA);
                offset += 1;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_HOMEKIT:
            if (length == 13) {
                proto_tree_add_item(main_tree, hf_btad_apple_homekit_status, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_homekit_deviceid, tvb, offset, 6, ENC_NA);
                offset += 6;
                proto_tree_add_item(main_tree, hf_btad_apple_homekit_category, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_homekit_globalstatenum, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_homekit_confignum, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_homekit_compver, tvb, offset, 1, ENC_NA);
                offset += 1;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_AIRPODS:
            if (length == 25) {
                proto_tree_add_item(main_tree, hf_btad_apple_airpods_prefix, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airpods_devicemodel, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_airpods_status, tvb, offset, 1, ENC_NA);
                offset += 1;

                airpods_item = proto_tree_add_item(main_tree, hf_btad_apple_airpods_battery_charging_status, tvb, offset, 2, ENC_NA);
                airpods_tree = proto_item_add_subtree(airpods_item, ett_btad_apple_airpods);

                static int * const battery_flags[] = {
                    &hf_btad_apple_airpods_rightbattery,
                    &hf_btad_apple_airpods_leftbattery,
                    NULL
                };
                proto_tree_add_bitmask(airpods_tree, tvb, offset, hf_btad_apple_airpods_battery_status, ett_btad_apple_airpods_battery, battery_flags, ENC_NA);
                offset += 1;

                static int * const charging_flags[] = {
                    &hf_btad_apple_airpods_casecharging,
                    &hf_btad_apple_airpods_rightcharging,
                    &hf_btad_apple_airpods_leftcharging,
                    &hf_btad_apple_airpods_casebattery,
                    NULL
                };
                proto_tree_add_bitmask(airpods_tree, tvb, offset, hf_btad_apple_airpods_charging_status, ett_btad_apple_airpods_charging, charging_flags, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_btad_apple_airpods_opencount, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airpods_devicecolor, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airpods_suffix, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airpods_encdata, tvb, offset, 16, ENC_NA);
                offset += 16;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_SIRI:
            if (length == 8) {
                proto_tree_add_item(main_tree, hf_btad_apple_siri_perphash, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_siri_snr, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_siri_confidence, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_siri_deviceclass, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_siri_randbyte, tvb, offset, 2, ENC_NA);
                offset += 2;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_AIRPLAY_TARGET:
            if (length == 6) {
                proto_tree_add_item(main_tree, hf_btad_apple_airplay_flags, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airplay_seed, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_airplay_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_AIRPLAY_SOURCE:
            if (length == 1) {
                proto_tree_add_item(main_tree, hf_btad_apple_airplay_data, tvb, offset, 1 , ENC_NA);
                offset += 1;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_MAGIC_SWITCH:
            if (length == 3) {
                proto_tree_add_item(main_tree, hf_btad_apple_magicswitch_data, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_magicswitch_confidence, tvb, offset, 1, ENC_NA);
                offset += 1;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_HANDOFF:
            //handoff_nearby_flag = 1; //flag to fix bug w/ iOS 13 being labeled as iOS 12 when nearby & handoff in same frame
            proto_tree_add_item(main_tree, hf_btad_apple_handoff_copy, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(main_tree, hf_btad_apple_handoff_seqnum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(main_tree, hf_btad_apple_handoff_authtag, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(main_tree, hf_btad_apple_handoff_encdata, tvb, offset, length - 4, ENC_NA);
            offset += length - 4;
            break;
        case BTAD_APPLE_TETHERING_TARGET:
            proto_tree_add_item(main_tree, hf_btad_apple_tethtgt_icloudid, tvb, offset, length, ENC_NA);
            offset += length;
            break;
        case BTAD_APPLE_TETHERING_SOURCE:
            if (length == 6) {
                proto_tree_add_item(main_tree, hf_btad_apple_tethsrc_version, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_tethsrc_flags, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_tethsrc_battery, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(main_tree, hf_btad_apple_tethsrc_celltype, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(main_tree, hf_btad_apple_tethsrc_cellbars, tvb, offset, 1, ENC_NA);
                offset += 1;
            } else {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_NEARBY_ACTION:
            if(length != 2){
                nearby_action_flags_check = tvb_get_uint8(tvb, offset) & 0x80;
                proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_flags, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_flags_authtag, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item_ret_uint(main_tree, hf_btad_apple_nearbyaction_type, tvb, offset, 1, ENC_NA, &nearbyaction_type_val);
                offset += 1;
                if(nearby_action_flags_check == 0x80){
                    proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_auth, tvb, offset, 3, ENC_NA);
                    offset += 3;
                    length -= 3;
                }
                switch(nearbyaction_type_val){
                    case 8: /* Wi-Fi Password */
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_wifijoin_appleid, tvb, offset, 3, ENC_NA);
                        offset += 3;
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_wifijoin_phonenumber, tvb, offset, 3, ENC_NA);
                        offset += 3;
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_wifijoin_email, tvb, offset, 3, ENC_NA);
                        offset += 3;
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_wifijoin_ssid, tvb, offset + 9, 3, ENC_NA);
                        offset += 3;
                        break;
                    case 9: /* iOS Setup */
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_setup_device_class, tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_setup_device_model, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_setup_device_color, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_setup_msg_version, tvb, offset, 1, ENC_NA);
                        offset += 2;
                        if(nearby_action_flags_check == 0x80){
                            length -= 3;
                        }
                        if((length - 5) != 0){
                            offset += 1;
                        }
                        break;
                    default:
                        proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_data, tvb, offset, length - 2, ENC_NA);
                        offset += length - 2;
                        break;
                }
            }
            else{
                proto_tree_add_item(main_tree, hf_btad_apple_nearbyaction_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
            break;
        case BTAD_APPLE_NEARBY_INFO:
            {
            static int * const status_flags[] = {
                // Only seen on newer phones (iPhone 11)
                &hf_btad_apple_nearbyinfo_unk_flag,
                &hf_btad_apple_nearbyinfo_airdrop_status,
                // Only seen on newer phones (iPhone 11)
                &hf_btad_apple_nearbyinfo_unk_flag2,
                // This could be:
                //     Face recognition capability (turning face recognition on/off does not toggle bit)
                //     This could be not having no home button (not tested on  iPhone X/XR/XS, only iPhone 11
                &hf_btad_apple_nearbyinfo_primary_device,
                &hf_btad_apple_nearbyinfo_action_code,
                NULL
            };
            proto_tree_add_bitmask(main_tree, tvb, offset, hf_btad_apple_nearbyinfo_statusflags, ett_btad_apple_nearbyinfo_status, status_flags, ENC_NA);
            offset += 1;
            length -= 1;

            static int * const data_flags[] = {
                &hf_btad_apple_nearbyinfo_autounlock_enabled,
                &hf_btad_apple_nearbyinfo_autounlock_watch,
                &hf_btad_apple_nearbyinfo_watch_locked,
                &hf_btad_apple_nearbyinfo_authtag_present,
                &hf_btad_apple_nearbyinfo_unk_flag3,
                &hf_btad_apple_nearbyinfo_wifi_status,
                &hf_btad_apple_nearbyinfo_authtag_fourbyte,
                &hf_btad_apple_nearbyinfo_airpod_conn,
                NULL
            };
            proto_tree_add_bitmask(main_tree, tvb, offset, hf_btad_apple_nearbyinfo_dataflags, ett_btad_apple_nearbyinfo_data, data_flags, ENC_NA);
            // When screen on and airpods connected -> 1
            // When screen on and airpods disconnected -> 0
            // When screen off and airpods connected -> 0
            // When screen off and airpods disconnected -> 0

            nearby_os_val = tvb_get_uint8(tvb, offset) & 0x0f;
            auth_tag_present = tvb_get_uint8(tvb, offset) & 0x10;
            four_byte_authtag = tvb_get_uint8(tvb, offset) & 0x02;

            if(os_set == 0){ //if OS not set yet (IE. not iOS13 based off Tx Power or MacOS)
              if(auth_tag_present == 0){ //iOS 10 probably
                proto_item_set_text(os_item, "iOS 10.x");
                offset += length;
                break;
              }
              else{ // there is auth tag
                if(nearby_os_val == 0x00){ //iOS 11 (has auth tag but byte is always 0)
                  proto_item_set_text(os_item, "iOS 11.x");
                  if(four_byte_authtag){
                  proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_auth, tvb, offset + 1, 4, ENC_NA);
                    offset += 5;
                    length -= 5;
                  }
                  else{
                  proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_auth, tvb, offset + 1, 3, ENC_NA);
                    offset += 4;
                    length -= 4;
                  }
                  if(length){
                    proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_postauth, tvb, offset, length, ENC_NA);
                  }
                offset += length;
                break;
                }
                else{ //else its iOS 12 b/c iOS 13 has Tx power
                  //only set as iOS 12.x if nearby frame ONLY. If Handoff + Nearby in same frame, leave blank
                  if(handoff_nearby_flag == 0){
                    proto_item_set_text(os_item, "iOS 12.x");
                  }
                if(length > 1){
                    if(four_byte_authtag){
                    proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_auth, tvb, offset + 1, 4, ENC_NA);
                      offset += 5;
                      length -= 5;
                    }
                    else{
                    proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_auth, tvb, offset + 1, 3, ENC_NA);
                      offset += 4;
                      length -= 4;
                    }
                    if(length){
                      proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_postauth, tvb, offset, length, ENC_NA);
                    }
                }
                offset += length;
                break;
                }
              }
            }
            else{ //iOS 13 or MacOS already set, just need wifi status and auth tag
              //get wifi status always
              if((length > 1) && (auth_tag_present == 0x10)){
                if(four_byte_authtag){
                proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_auth, tvb, offset + 1, 4, ENC_NA);
                  offset += 5;
                  length -= 5;
                }
                else{
                proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_auth, tvb, offset + 1, 3, ENC_NA);
                  offset += 4;
                  length -= 4;
                }
                if(length){
                  proto_tree_add_item(main_tree, hf_btad_apple_nearbyinfo_postauth, tvb, offset, length, ENC_NA);
                }
              }
              offset += length;
              break;
            }
            }
        case BTAD_APPLE_FIND_MY:
            if(length == 25){
                src = (address *) p_get_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC);
                publicKeyStr = (char *) wmem_alloc(pinfo->pool, 57);
                for(int i = 0; i < 6; i++){
                    pubKey[i] = *(unsigned char *)(((char *)(src->data))+i);
                }
                proto_tree_add_item(main_tree, hf_btad_apple_findmy_status, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(main_tree, hf_btad_apple_findmy_publickey, tvb, offset+1, 22, ENC_NA);
                proto_tree_add_item_ret_uint(main_tree, hf_btad_apple_findmy_publickeybits, tvb, offset + 23, 1, ENC_NA, &pubKeyBits);
                proto_tree_add_item(main_tree, hf_btad_apple_findmy_hint, tvb, offset + 24, 1, ENC_NA);
                pubKey[0] = ((((unsigned char)pubKeyBits) & 0x03) << 0x06) | (pubKey[0] & 0x3f);
                for(int i = 6; i < 28; i++){
                    pubKey[i] = (unsigned char) tvb_get_uint8(tvb, (offset+1+(i-6)));
                }
                for(int i = 0; i < 28; i++){
                    snprintf((publicKeyStr+(i*2)), 3, "%02x", ((unsigned char) pubKey[i]));
                }
                proto_tree_add_string(main_tree, hf_btad_apple_findmy_publickeyxcoord, tvb, 0, 0, publicKeyStr);
            }
            else if(length == 2){
                proto_tree_add_item(main_tree, hf_btad_apple_findmy_status, tvb, offset, 1, ENC_NA);
                proto_tree_add_item_ret_uint(main_tree, hf_btad_apple_findmy_publickeybits, tvb, offset + 1, 1, ENC_NA, &pubKeyBits);

            }
            else {
                proto_tree_add_item(main_tree, hf_btad_apple_findmy_data, tvb, offset, length, ENC_NA);
            }
            offset += length;
            break;
        default:
            if (length > 0) {
                proto_tree_add_item(main_tree, hf_btad_apple_data, tvb, offset, length, ENC_NA);
                offset += length;
            }
    }

    return offset;
}

void
proto_register_btad_apple_continuity(void)
{
    static hf_register_info hf[] = {
        {&hf_btad_apple_type,
            {"Type",                             "bluetooth.apple.type",
            FT_UINT8, BASE_HEX, VALS(btad_apple_type_values), 0x0,
            NULL, HFILL}
        },
        {&hf_btad_apple_length,
            {"Length",                           "bluetooth.apple.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btad_apple_data,
            {"Data",                             "bluetooth.apple.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_btad_apple_nearbyinfo_os,
          { "OS",                                "bluetooth.apple.nearbyinfo.os",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_btad_apple_ibeacon_uuid128,
            {"UUID",                             "bluetooth.apple.ibeacon.uuid128",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_btad_apple_ibeacon_major,
          { "Major",                             "bluetooth.apple.ibeacon.major",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_ibeacon_minor,
          { "Minor",                             "bluetooth.apple.ibeacon.minor",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_ibeacon_measured_power,
          { "Measured Power",                    "bluetooth.apple.ibeacon.measured_power",
            FT_INT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_dbm), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airprint_addrtype,
          { "AirPrint Address Type", "bluetooth.apple.airprint.addrtype",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airprint_resourcepathtype,
          { "AirPrint Resource Path Type", "bluetooth.apple.airprint.resourcepathtype",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airprint_securitytype,
          { "AirPrint Security Type", "bluetooth.apple.airprint.securitytype",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airprint_qidport,
          { "AirPrint QID or TCP Port", "bluetooth.apple.airprint.qidport",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airprint_ipaddr,
          { "IP Address", "bluetooth.apple.airprint.ipaddr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airprint_power,
          { "Measured Power", "bluetooth.apple.airprint.power",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airdrop_prefix,
          { "AirDrop Prefix", "bluetooth.apple.airdrop.prefix",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airdrop_version,
          { "AirDrop Version", "bluetooth.apple.airdrop.version",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airdrop_appleid,
          { "First 2 Bytes SHA256(Apple ID)", "bluetooth.apple.airdrop.appleid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airdrop_phone,
          { "First 2 Bytes SHA256(Phone Number)", "bluetooth.apple.airdrop.phone",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airdrop_email,
          { "First 2 Bytes SHA256(Email)", "bluetooth.apple.airdrop.email",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airdrop_email2,
          { "First 2 Bytes SHA256(Email 2)", "bluetooth.apple.airdrop.email2",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airdrop_suffix,
          { "AirDrop Suffix", "bluetooth.apple.airdrop.suffix",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_homekit_status,
          { "Status Flags", "bluetooth.apple.homekit.status",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_homekit_deviceid,
          { "Device ID", "bluetooth.apple.homekit.deviceid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_homekit_category,
          { "Category", "bluetooth.apple.homekit.category",
            FT_UINT16, BASE_HEX, VALS(btad_apple_homekit_category_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_homekit_globalstatenum,
          { "Global State Number", "bluetooth.apple.homekit.globalstatenum",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_homekit_confignum,
          { "Configuration Number", "bluetooth.apple.homekit.confignum",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_homekit_compver,
          { "Compatible Version", "bluetooth.apple.homekit.compver",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_prefix,
          { "AirPods Prefix", "bluetooth.apple.airpods.prefix",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_devicemodel,
          { "AirPods Device Model", "bluetooth.apple.airpods.devicemodel",
            FT_UINT16, BASE_HEX, VALS(btad_apple_airpods_device_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_status,
          { "AirPods Status", "bluetooth.apple.airpods.status",
            FT_UINT8, BASE_HEX, VALS(btad_apple_airpods_status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_leftbattery,
          { "Left AirPod Battery (x10%)", "bluetooth.apple.airpods.leftbattery",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_rightbattery,
          { "Right AirPod Battery (x10%)", "bluetooth.apple.airpods.rightbattery",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_casecharging,
          { "AirPods Case Charging", "bluetooth.apple.airpods.casecharging",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_rightcharging,
          { "Right AirPod Charging", "bluetooth.apple.airpods.rightcharging",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_leftcharging,
          { "Left AirPod Charging", "bluetooth.apple.airpods.leftcharging",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_casebattery,
          { "AirPod Case Battery (x10%)", "bluetooth.apple.airpods.casebattery",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_opencount,
          { "AirPods Open Count", "bluetooth.apple.airpods.opencount",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_devicecolor,
          { "AirPods Device Color", "bluetooth.apple.airpods.devicecolor",
            FT_UINT8, BASE_HEX, VALS(btad_apple_airpods_color_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_suffix,
          { "AirPods Suffix", "bluetooth.apple.airpods.suffix",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_encdata,
          { "AirPods Encrypted Data", "bluetooth.apple.airpods.encdata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_battery_status,
          { "AirPods L/R Battery Level", "bluetooth.apple.airpods.batterystatus",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_charging_status,
          { "AirPods Charging Status", "bluetooth.apple.airpods.charingstatus",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_casebattery_status,
          { "AirPods Case Battery Level", "bluetooth.apple.airpods.casebatterystatus",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btad_apple_airpods_battery_charging_status,
          { "AirPods Battery Levels & Charging Status", "bluetooth.apple.airpods.batterychargingstatus",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btad_apple_siri_perphash,
          { "Perceptual Hash", "bluetooth.apple.siri.perphash",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_siri_snr,
          { "Signal-to-Noise Ratio", "bluetooth.apple.siri.snr",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_siri_confidence,
          { "Confidence Level", "bluetooth.apple.siri.confidence",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_siri_deviceclass,
          { "Device Class", "bluetooth.apple.siri.deviceclass",
            FT_UINT16, BASE_HEX, VALS(btad_apple_siri_device_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_siri_randbyte,
          { "Random Byte", "bluetooth.apple.siri.randbyte",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airplay_flags,
          { "AirPlay Flags", "bluetooth.apple.airplay.flags",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airplay_seed,
          { "AirPlay Seed", "bluetooth.apple.airplay.seed",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airplay_ip,
          { "AirPlay IPv4 Address", "bluetooth.apple.airplay.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_airplay_data,
          { "AirPlay Source Data", "bluetooth.apple.airplay.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_magicswitch_data,
          { "Data", "bluetooth.apple.magicswitch.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_magicswitch_confidence,
          { "Confidence on Wrist", "bluetooth.apple.magicswitch.confidence",
            FT_UINT8, BASE_HEX, VALS(btad_apple_wrist_confidence_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_handoff_copy,
          { "Copy/Cut Performed", "bluetooth.apple.handoff.copy",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x0f,
            NULL, HFILL }
        },
        { &hf_btad_apple_handoff_seqnum,
          { "IV (Sequence Number)", "bluetooth.apple.handoff.seqnum",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_handoff_authtag,
          { "AES-GCM Auth Tag", "bluetooth.apple.handoff.authtag",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_handoff_encdata,
          { "Encrypted Handoff Data", "bluetooth.apple.handoff.encdata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_tethtgt_icloudid,
          { "iCloud ID", "bluetooth.apple.tethtgt.icloudid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_tethsrc_version,
          { "Version", "bluetooth.apple.tethsrc.version",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_tethsrc_flags,
          { "Flags", "bluetooth.apple.tethsrc.flags",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_tethsrc_battery,
          { "Battery Life (%)", "bluetooth.apple.tethsrc.battery",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_tethsrc_celltype,
          { "Cellular Connection Type", "bluetooth.apple.tethsrc.celltype",
            FT_UINT16, BASE_DEC, VALS(btad_apple_cellular_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_tethsrc_cellbars,
          { "Cell Service Quality (Bars)", "bluetooth.apple.tethsrc.cellbars",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_flags,
          { "Nearby Action Flags", "bluetooth.apple.nearbyaction.flags",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_flags_authtag,
          { "Auth Tag Flag", "bluetooth.apple.nearbyaction.flags.authtag",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x80,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_type,
          { "Nearby Action Type", "bluetooth.apple.nearbyaction.type",
            FT_UINT8, BASE_HEX, VALS(btad_apple_nearbyaction_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_auth,
          { "Auth Tag", "bluetooth.apple.nearbyaction.auth",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_wifijoin_ssid,
          { "First 3 Bytes SHA256(SSID)", "bluetooth.apple.nearbyaction.wifijoin.ssid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_wifijoin_appleid,
          { "First 3 Bytes SHA256(Apple ID)", "bluetooth.apple.nearbyaction.wifijoin.appleid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_wifijoin_phonenumber,
          { "First 3 Bytes SHA256(Phone Number)", "bluetooth.apple.nearbyaction.wifijoin.phonenumber",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_wifijoin_email,
          { "First 3 Bytes SHA256(Email)", "bluetooth.apple.nearbyaction.wifijoin.email",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_setup_device_class,
          { "Device Class", "bluetooth.apple.nearbyaction.setup.device_class",
            FT_UINT8, BASE_HEX, VALS(btad_apple_device_class_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_setup_device_model,
          { "iPhone Model", "bluetooth.apple.nearbyaction.setup.device_model",
            FT_UINT8, BASE_HEX, VALS(btad_apple_device_model_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_setup_device_color,
          { "Device Color", "bluetooth.apple.nearbyaction.setup.device_color",
            FT_UINT8, BASE_HEX, VALS(btad_apple_device_color_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_setup_msg_version,
          { "Message Version", "bluetooth.apple.nearbyaction.setup.msg_ver",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyaction_data,
          { "Unknown Data", "bluetooth.apple.nearbyaction_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_statusflags,
          { "Nearby Info Status Flags", "bluetooth.apple.nearbyinfo.statusflags",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_primary_device,
          { "Primary Device", "bluetooth.apple.nearbyinfo.primary_device",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_unk_flag2,
          { "Unknown Flag", "bluetooth.apple.nearbyinfo.unk.flag2",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x20,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_airdrop_status,
          { "AirDrop Receiving Status", "bluetooth.apple.nearbyinfo.airdrop_status",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x40,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_unk_flag,
          { "Unknown Flag", "bluetooth.apple.nearbyinfo.unk.flag",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_action_code,
          { "Action Code", "bluetooth.apple.nearbyinfo.action_code",
            FT_UINT8, BASE_DEC, VALS(btad_apple_action_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_dataflags,
          { "Nearby Info Data Flags", "bluetooth.apple.nearbyinfo.dataflags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_authtag_present,
          { "Auth Tag Present", "bluetooth.apple.nearbyinfo.authtag_present",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_watch_locked,
          { "Watch Locked", "bluetooth.apple.nearbyinfo.watch_locked",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_autounlock_watch,
          { "Auto Unlock Watch", "bluetooth.apple.nearbyinfo.autounlock_watch",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_autounlock_enabled,
          { "Auto Unlock Enabled", "bluetooth.apple.nearbyinfo.autounlock_enabled",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        /* unk_flag2 may be iPhone/Mac vs IoT device */
        /* Have only seen 0x00 from Apple TV */
        { &hf_btad_apple_nearbyinfo_unk_flag3,
          { "Unknown Flag", "bluetooth.apple.nearbyinfo.unk.flag3",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x08,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_wifi_status,
          { "WiFi Status", "bluetooth.apple.nearbyinfo.wifi_status",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x04,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_authtag_fourbyte,
          { "Four Byte Auth Tag", "bluetooth.apple.nearbyinfo.authtag.fourbyte",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_airpod_conn,
          { "AirPod Connection Status", "bluetooth.apple.nearbyinfo.airpod.connection",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_auth,
          { "Auth Tag", "bluetooth.apple.nearbyinfo.auth",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_nearbyinfo_postauth,
          { "Post Auth Tag Data", "bluetooth.apple.nearbyinfo.postauth",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_findmy_status,
          { "FindMy Status", "bluetooth.apple.findmy.status",
            FT_UINT8, BASE_HEX, VALS(btad_apple_findmy_status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_findmy_publickey,
          { "Bytes 6-27 of Public Key", "bluetooth.apple.findmy.publickey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_findmy_publickeybits,
          { "Public Key Bits", "bluetooth.apple.findmy.publickey.bits",
            FT_UINT8, BASE_HEX, VALS(btad_apple_findmy_publickeybits_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_btad_apple_findmy_hint,
          { "Byte 5 of BT_ADDR of Primary Key", "bluetooth.apple.findmy.hint",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_findmy_publickeyxcoord,
          { "Public Key X Coordinate", "bluetooth.apple.findmy.publickey.xcord",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_findmy_data,
          { "Data", "bluetooth.apple.findmy.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_btad_apple,
        &ett_btad_apple_airpods,
        &ett_btad_apple_airpods_battery,
        &ett_btad_apple_airpods_charging,
        &ett_btad_apple_nearbyinfo_status,
        &ett_btad_apple_nearbyinfo_data,
    };

    proto_btad_apple_continuity = proto_register_protocol("Apple BLE Continuity", "apple_continuity", "apple_continuity");
    proto_register_field_array(proto_btad_apple_continuity, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btad_apple_continuity = register_dissector("bluetooth.apple", dissect_btad_apple_continuity, proto_btad_apple_continuity);
    btad_apple_ibeacon = register_dissector("bluetooth.apple.ibeacon", dissect_btad_apple_continuity, proto_btad_apple_continuity);
}


void
proto_reg_handoff_btad_apple_continuity(void)
{
    dissector_add_uint("btcommon.eir_ad.manufacturer_company_id", 0x004c, btad_apple_continuity);
}


static int proto_btad_alt_beacon;

static int hf_btad_alt_beacon_code;
static int hf_btad_alt_beacon_id;
static int hf_btad_alt_beacon_reference_rssi;
static int hf_btad_alt_beacon_manufacturer_data;

static int ett_btad_alt_beacon;

static dissector_handle_t btad_alt_beacon;

void proto_register_btad_alt_beacon(void);
void proto_reg_handoff_btad_alt_beacon(void);


static int
dissect_btad_alt_beacon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree       *main_tree;
    proto_item       *main_item;
    int               offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_alt_beacon, tvb, offset, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btad_alt_beacon);

    proto_tree_add_item(main_tree, hf_btad_alt_beacon_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(main_tree, hf_btad_alt_beacon_id, tvb, offset, 20, ENC_NA);
    offset += 20;

    proto_tree_add_item(main_tree, hf_btad_alt_beacon_reference_rssi, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(main_tree, hf_btad_alt_beacon_manufacturer_data, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

void
proto_register_btad_alt_beacon(void)
{
    static hf_register_info hf[] = {
        { &hf_btad_alt_beacon_code,
          { "Code",                              "bluetooth.alt_beacon.code",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_btad_alt_beacon_id,
            {"ID",                               "bluetooth.alt_beacon.id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_btad_alt_beacon_reference_rssi,
          { "Reference RSSI",                    "bluetooth.alt_beacon.reference_rssi",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_alt_beacon_manufacturer_data,
          { "Manufacturer Data",                 "bluetooth.alt_beacon.manufacturer_data",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_btad_alt_beacon,
    };

    proto_btad_alt_beacon = proto_register_protocol("AltBeacon", "AltBeacon", "alt_beacon");
    proto_register_field_array(proto_btad_alt_beacon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btad_alt_beacon = register_dissector("bluetooth.alt_beacon", dissect_btad_alt_beacon, proto_btad_alt_beacon);
}

void
proto_reg_handoff_btad_alt_beacon(void)
{
    dissector_add_for_decode_as("btcommon.eir_ad.manufacturer_company_id", btad_alt_beacon);
}

static int proto_btad_gaen;

static int hf_btad_gaen_rpi128;
static int hf_btad_gaen_aemd32;

static int ett_btad_gaen;

static dissector_handle_t btad_gaen;

void proto_register_btad_gaen(void);
void proto_reg_handoff_btad_gaen(void);

static int
dissect_btad_gaen(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree       *main_tree;
    proto_item       *main_item;
    int              offset = 0;

    /* The "Service Data" blob of data has the following format for GAEN:
    1 byte: length (0x17)
    1 byte: Type (0x16)
    2 bytes: Identifier (should be 0xFD6F again)
    16 bytes: Rolling Proximity Identifier
    4 bytes: Associated Encrypted Metadata (Encrypted in AES-CTR mode)
    1 byte: Version
    1 byte: Power level
    2 bytes: Reserved for future use.

    We want to skip everything before the last 20 bytes, because it'll be handled by other parts of the BTLE dissector. */
    if (tvb_reported_length(tvb) < 20)
        return 0;
    offset = tvb_reported_length(tvb) - 20;

    main_item = proto_tree_add_item(tree, proto_btad_gaen, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btad_gaen);

    proto_tree_add_item(main_tree, hf_btad_gaen_rpi128, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(main_tree, hf_btad_gaen_aemd32, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

void
proto_register_btad_gaen(void)
{
    static hf_register_info hf[] = {
        { &hf_btad_gaen_rpi128,
    { "Rolling Proximity Identifier",    "bluetooth.gaen.rpi",
    FT_BYTES, BASE_NONE, NULL, 0x0,
    NULL, HFILL }
        },
    { &hf_btad_gaen_aemd32,
    { "Associated Encrypted Metadata",   "bluetooth.gaen.aemd",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    }
    };

    static int *ett[] = {
        &ett_btad_gaen,
    };

    proto_btad_gaen = proto_register_protocol("Google/Apple Exposure Notification", "Google/Apple Exposure Notification", "bluetooth.gaen");
    proto_register_field_array(proto_btad_gaen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btad_gaen = register_dissector("bluetooth.gaen", dissect_btad_gaen, proto_btad_gaen);
}

void
proto_reg_handoff_btad_gaen(void)
{
    dissector_add_string("btcommon.eir_ad.entry.uuid", "fd6f", btad_gaen);
}

static int proto_btad_matter;

#define MATTER_OPCODE_COMMISSIONABLE    0x00
#define MATTER_OPCODE_NETWORK_RECOVERY  0x01

static int hf_btad_matter_opcode;
static int hf_btad_matter_version_u8;
static int hf_btad_matter_version_u16;
static int hf_btad_matter_discriminator;
static int hf_btad_matter_vendor_id;
static int hf_btad_matter_product_id;
static int hf_btad_matter_recovery_id;
static int hf_btad_matter_flags;
static int hf_btad_matter_flags_additional_data;
static int hf_btad_matter_flags_ext_announcement;

static int ett_btad_matter;
static int ett_btad_matter_flags;

static dissector_handle_t btad_matter;

void proto_register_btad_matter(void);
void proto_reg_handoff_btad_matter(void);

static int
dissect_btad_matter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    unsigned offset = 0;
    proto_tree *main_item = proto_tree_add_item(tree, proto_btad_matter, tvb, offset, -1, ENC_NA);
    proto_tree *main_tree = proto_item_add_subtree(main_item, ett_btad_matter);

    unsigned int opcode;
    proto_tree_add_item_ret_uint(main_tree, hf_btad_matter_opcode, tvb, offset, 1, ENC_NA, &opcode);
    offset += 1;

    switch (opcode) {
    case MATTER_OPCODE_COMMISSIONABLE:
        proto_tree_add_item(main_tree, hf_btad_matter_version_u16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(main_tree, hf_btad_matter_discriminator, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(main_tree, hf_btad_matter_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(main_tree, hf_btad_matter_product_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;
    case MATTER_OPCODE_NETWORK_RECOVERY:
        proto_tree_add_item(main_tree, hf_btad_matter_version_u8, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(main_tree, hf_btad_matter_recovery_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
    default:
        return offset;
    }

    static int * const flags[] = {
        &hf_btad_matter_flags_additional_data,
        &hf_btad_matter_flags_ext_announcement,
        NULL
    };

    proto_tree_add_bitmask(main_tree, tvb, offset, hf_btad_matter_flags, ett_btad_matter_flags, flags, ENC_NA);
    offset += 1;

    return offset;
}

void
proto_register_btad_matter(void)
{
    static const value_string opcode_vals[] = {
        { MATTER_OPCODE_COMMISSIONABLE, "Commissionable" },
        { MATTER_OPCODE_NETWORK_RECOVERY, "Network Recovery" },
        { 0, NULL }
    };

    static hf_register_info hf[] = {
        { &hf_btad_matter_opcode,
          { "Opcode", "bluetooth.matter.opcode",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL }
        },
        {&hf_btad_matter_version_u8,
          {"Advertisement Version", "bluetooth.matter.version",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL}
        },
        {&hf_btad_matter_version_u16,
          {"Advertisement Version", "bluetooth.matter.version",
            FT_UINT16, BASE_DEC, NULL, 0xF000,
            NULL, HFILL}
        },
        { &hf_btad_matter_discriminator,
          { "Discriminator", "bluetooth.matter.discriminator",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            "A 12-bit value used in the Setup Code", HFILL }
        },
        { &hf_btad_matter_vendor_id,
          { "Vendor ID", "bluetooth.matter.vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "A 16-bit value identifying the device manufacturer", HFILL }
        },
        { &hf_btad_matter_product_id,
          { "Product ID", "bluetooth.matter.product_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "A 16-bit value identifying the product", HFILL }
        },
        { &hf_btad_matter_recovery_id,
          { "Recovery ID", "bluetooth.matter.recovery_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            "A 64-bit recovery ID", HFILL }
        },
        { &hf_btad_matter_flags,
          { "Flags", "bluetooth.matter.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_matter_flags_additional_data,
          { "Additional Data", "bluetooth.matter.flags.additional_data",
            FT_BOOLEAN, 8, NULL, 0x01,
            "Set if the device provides the optional C3 GATT characteristic", HFILL }
        },
        { &hf_btad_matter_flags_ext_announcement,
          { "Extended Announcement", "bluetooth.matter.flags.ext_announcement",
            FT_BOOLEAN, 8, NULL, 0x02,
            "Set while the device is in the Extended Announcement period", HFILL }
        },
    };

    static int *ett[] = {
        &ett_btad_matter,
        &ett_btad_matter_flags,
    };

    proto_btad_matter = proto_register_protocol("Matter Advertising Data", "Matter Advertising Data", "bluetooth.matter");
    proto_register_field_array(proto_btad_matter, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btad_matter = register_dissector("bluetooth.matter", dissect_btad_matter, proto_btad_matter);
}

void
proto_reg_handoff_btad_matter(void)
{
    dissector_add_string("btcommon.eir_ad.entry.uuid", "fff6", btad_matter);
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
