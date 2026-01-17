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

static int proto_btad_apple_ibeacon;

static int hf_btad_apple_ibeacon_type;
static int hf_btad_apple_ibeacon_length;
static int hf_btad_apple_ibeacon_uuid128;
static int hf_btad_apple_ibeacon_major;
static int hf_btad_apple_ibeacon_minor;
static int hf_btad_apple_ibeacon_measured_power;

static int ett_btad_apple_ibeacon;

static dissector_handle_t btad_apple_ibeacon;

void proto_register_btad_apple_ibeacon(void);
void proto_reg_handoff_btad_apple_ibeacon(void);


static int
dissect_btad_apple_ibeacon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree       *main_tree;
    proto_item       *main_item;
    int               offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_apple_ibeacon, tvb, offset, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btad_apple_ibeacon);

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_uuid128, tvb, offset, 16, ENC_BIG_ENDIAN);
    offset += 16;

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_major, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_minor, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_measured_power, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

void
proto_register_btad_apple_ibeacon(void)
{
    static hf_register_info hf[] = {
        {&hf_btad_apple_ibeacon_type,
            {"Type",                             "bluetooth.apple.ibeacon.type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btad_apple_ibeacon_length,
            {"Length",                           "bluetooth.apple.ibeacon.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
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
        }
    };

    static int *ett[] = {
        &ett_btad_apple_ibeacon,
    };

    proto_btad_apple_ibeacon = proto_register_protocol("Apple iBeacon", "iBeacon", "ibeacon");
    proto_register_field_array(proto_btad_apple_ibeacon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btad_apple_ibeacon = register_dissector("bluetooth.apple.ibeacon", dissect_btad_apple_ibeacon, proto_btad_apple_ibeacon);
}


void
proto_reg_handoff_btad_apple_ibeacon(void)
{
    dissector_add_for_decode_as("btcommon.eir_ad.manufacturer_company_id", btad_apple_ibeacon);
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
    offset = tvb_captured_length(tvb) - 20;

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

static int hf_btad_matter_opcode;
static int hf_btad_matter_version;
static int hf_btad_matter_discriminator;
static int hf_btad_matter_vendor_id;
static int hf_btad_matter_product_id;
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
    /* We are interested only in the last 8 bytes (Service Data Payload) */
    int offset = tvb_captured_length(tvb) - 8;

    proto_tree *main_item = proto_tree_add_item(tree, proto_btad_matter, tvb, offset, -1, ENC_NA);
    proto_tree *main_tree = proto_item_add_subtree(main_item, ett_btad_matter);

    proto_tree_add_item(main_tree, hf_btad_matter_opcode, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(main_tree, hf_btad_matter_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(main_tree, hf_btad_matter_discriminator, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(main_tree, hf_btad_matter_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(main_tree, hf_btad_matter_product_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

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
        { 0x00, "Commissionable" },
        { 0, NULL }
    };

    static hf_register_info hf[] = {
        { &hf_btad_matter_opcode,
          { "Opcode", "bluetooth.matter.opcode",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL }
        },
        {&hf_btad_matter_version,
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
