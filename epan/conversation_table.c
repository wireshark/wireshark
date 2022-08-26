/* conversations_table.c
 * conversations_table   2003 Ronnie Sahlberg
 * Helper routines common to all endpoint conversations tap.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include "proto.h"
#include "packet_info.h"
#include "conversation_table.h"
#include "addr_resolv.h"
#include "address_types.h"

#include "stat_tap_ui.h"

struct register_ct {
    gboolean hide_ports;       /* hide TCP / UDP port columns */
    int proto_id;              /* protocol id (0-indexed) */
    tap_packet_cb conv_func;        /* function to be called for new incoming packets for conversations */
    tap_packet_cb endpoint_func;    /* function to be called for new incoming packets for endpoints */
    conv_gui_init_cb conv_gui_init; /* GUI specific function to initialize conversation */
    endpoint_gui_init_cb endpoint_gui_init; /* GUI specific function to initialize endpoint */
};

gboolean get_conversation_hide_ports(register_ct_t* ct)
{
    return ct->hide_ports;
}

int get_conversation_proto_id(register_ct_t* ct)
{
    if (!ct) {
        return -1;
    }
    return ct->proto_id;
}

tap_packet_cb get_conversation_packet_func(register_ct_t* ct)
{
    return ct->conv_func;
}

tap_packet_cb get_endpoint_packet_func(register_ct_t* ct)
{
    return ct->endpoint_func;
}

/* For backwards source and binary compatibility */
tap_packet_cb get_hostlist_packet_func(register_ct_t* ct)
{
    return get_endpoint_packet_func(ct);
}

static wmem_tree_t *registered_ct_tables = NULL;

void
dissector_conversation_init(const char *opt_arg, void* userdata)
{
    register_ct_t *table = (register_ct_t*)userdata;
    GString *cmd_str = g_string_new("conv,");
    const char *filter=NULL;

    g_string_append(cmd_str, proto_get_protocol_filter_name(table->proto_id));
    if(!strncmp(opt_arg, cmd_str->str, cmd_str->len)){
        if (opt_arg[cmd_str->len] == ',') {
            filter = opt_arg + cmd_str->len + 1;
        }
    }
    g_string_free(cmd_str, TRUE);

    if (table->conv_gui_init)
        table->conv_gui_init(table, filter);
}

void
dissector_endpoint_init(const char *opt_arg, void* userdata)
{
    register_ct_t *table = (register_ct_t*)userdata;
    GString *cmd_str = g_string_new("");
    const char *filter=NULL;

    g_string_printf(cmd_str, "%s,%s", ENDPOINT_TAP_PREFIX, proto_get_protocol_filter_name(table->proto_id));
    if(!strncmp(opt_arg, cmd_str->str, cmd_str->len)){
        if (opt_arg[cmd_str->len] == ',') {
            filter = opt_arg + cmd_str->len + 1;
        }
    } else {
        filter=NULL;
    }

    g_string_free(cmd_str, TRUE);

    if (table->endpoint_gui_init)
        table->endpoint_gui_init(table, filter);
}

/* For backwards source and binary compatibility */
void
dissector_hostlist_init(const char *opt_arg, void* userdata)
{
    dissector_endpoint_init(opt_arg, userdata);
}

/** get conversation from protocol ID
 *
 * @param proto_id protocol ID
 * @return tap function handler of conversation
 */
register_ct_t* get_conversation_by_proto_id(int proto_id)
{
    return (register_ct_t*)wmem_tree_lookup_string(registered_ct_tables, proto_get_protocol_short_name(find_protocol_by_id(proto_id)), 0);
}

void
register_conversation_table(const int proto_id, gboolean hide_ports, tap_packet_cb conv_packet_func, tap_packet_cb endpoint_packet_func)
{
    register_ct_t *table;

    table = wmem_new(wmem_epan_scope(), register_ct_t);

    table->hide_ports    = hide_ports;
    table->proto_id      = proto_id;
    table->conv_func     = conv_packet_func;
    table->endpoint_func = endpoint_packet_func;
    table->conv_gui_init = NULL;
    table->endpoint_gui_init = NULL;

    if (registered_ct_tables == NULL)
        registered_ct_tables = wmem_tree_new(wmem_epan_scope());

    wmem_tree_insert_string(registered_ct_tables, proto_get_protocol_short_name(find_protocol_by_id(proto_id)), table, 0);
}

/* Set GUI fields for register_ct list */
static gboolean
set_conv_gui_data(const void *key _U_, void *value, void *userdata)
{
    GString *conv_cmd_str = g_string_new("conv,");
    stat_tap_ui ui_info;
    register_ct_t *table = (register_ct_t*)value;

    table->conv_gui_init = (conv_gui_init_cb)userdata;

    g_string_append(conv_cmd_str, proto_get_protocol_filter_name(table->proto_id));
    ui_info.group = REGISTER_STAT_GROUP_CONVERSATION_LIST;
    ui_info.title = NULL;   /* construct this from the protocol info? */
    ui_info.cli_string = g_string_free(conv_cmd_str, FALSE);
    ui_info.tap_init_cb = dissector_conversation_init;
    ui_info.nparams = 0;
    ui_info.params = NULL;
    register_stat_tap_ui(&ui_info, table);
    g_free((char*)ui_info.cli_string);
    return FALSE;
}

void conversation_table_set_gui_info(conv_gui_init_cb init_cb)
{
    wmem_tree_foreach(registered_ct_tables, set_conv_gui_data, (void*)init_cb);
}

static gboolean
set_endpoint_gui_data(const void *key _U_, void *value, void *userdata)
{
    stat_tap_ui ui_info;
    register_ct_t *table = (register_ct_t*)value;

    table->endpoint_gui_init = (endpoint_gui_init_cb)userdata;

    ui_info.group = REGISTER_STAT_GROUP_ENDPOINT_LIST;
    ui_info.title = NULL;   /* construct this from the protocol info? */
    ui_info.cli_string = ws_strdup_printf("%s,%s", ENDPOINT_TAP_PREFIX, proto_get_protocol_filter_name(table->proto_id));
    ui_info.tap_init_cb = dissector_endpoint_init;
    ui_info.nparams = 0;
    ui_info.params = NULL;
    register_stat_tap_ui(&ui_info, table);
    g_free((char*)ui_info.cli_string);
    return FALSE;
}

void endpoint_table_set_gui_info(endpoint_gui_init_cb init_cb)
{
    wmem_tree_foreach(registered_ct_tables, set_endpoint_gui_data, (void*)init_cb);
}

/* For backwards source and binary compatibility */
void hostlist_table_set_gui_info(endpoint_gui_init_cb init_cb)
{
    endpoint_table_set_gui_info(init_cb);
}

void conversation_table_iterate_tables(wmem_foreach_func func, void* user_data)
{
    wmem_tree_foreach(registered_ct_tables, func, user_data);
}

guint conversation_table_get_num(void)
{
    return wmem_tree_count(registered_ct_tables);
}

/** Compute the hash value for two given address/port pairs.
 * (Parameter type is gconstpointer for GHashTable compatibility.)
 *
 * @param v Conversation Key. MUST point to a conv_key_t struct.
 * @return Computed key hash.
 */
static guint
conversation_hash(gconstpointer v)
{
    const conv_key_t *key = (const conv_key_t *)v;
    guint hash_val;

    hash_val = 0;
    hash_val = add_address_to_hash(hash_val, &key->addr1);
    hash_val += key->port1;
    hash_val = add_address_to_hash(hash_val, &key->addr2);
    hash_val += key->port2;
    hash_val ^= key->conv_id;

    return hash_val;
}

/** Compare two conversation keys for an exact match.
 * (Parameter types are gconstpointer for GHashTable compatibility.)
 *
 * @param key1 First conversation. MUST point to a conv_key_t struct.
 * @param key2 Second conversation. MUST point to a conv_key_t struct.
 * @return TRUE if conversations are equal, FALSE otherwise.
 */
static gboolean
conversation_equal(gconstpointer key1, gconstpointer key2)
{
    const conv_key_t *ck1 = (const conv_key_t *)key1;
    const conv_key_t *ck2 = (const conv_key_t *)key2;

    if (ck1->conv_id == ck2->conv_id)
    {
        if (ck1->port1 == ck2->port1 &&
            ck1->port2 == ck2->port2 &&
            addresses_equal(&ck1->addr1, &ck2->addr1) &&
            addresses_equal(&ck1->addr2, &ck2->addr2)) {
            return TRUE;
        }

        if (ck1->port2 == ck2->port1 &&
            ck1->port1 == ck2->port2 &&
            addresses_equal(&ck1->addr2, &ck2->addr1) &&
            addresses_equal(&ck1->addr1, &ck2->addr2)) {
            return TRUE;
        }
    }

    /*
     * The addresses, ports, or conversation IDs don't match.
     */
    return FALSE;
}

void
reset_conversation_table_data(conv_hash_t *ch)
{
    if (!ch) {
        return;
    }

    if (ch->conv_array != NULL) {
        guint i;
        for(i = 0; i < ch->conv_array->len; i++){
            conv_item_t *conv = &g_array_index(ch->conv_array, conv_item_t, i);
            free_address(&conv->src_address);
            free_address(&conv->dst_address);
        }

        g_array_free(ch->conv_array, TRUE);
    }

    if (ch->hashtable != NULL) {
        g_hash_table_destroy(ch->hashtable);
    }

    ch->conv_array=NULL;
    ch->hashtable=NULL;
}

void reset_endpoint_table_data(conv_hash_t *ch)
{
    if (!ch) {
        return;
    }

    if (ch->conv_array != NULL) {
        guint i;
        for(i = 0; i < ch->conv_array->len; i++){
            endpoint_item_t *endpoint = &g_array_index(ch->conv_array, endpoint_item_t, i);
            free_address(&endpoint->myaddress);
        }

        g_array_free(ch->conv_array, TRUE);
    }

    if (ch->hashtable != NULL) {
        g_hash_table_destroy(ch->hashtable);
    }

    ch->conv_array=NULL;
    ch->hashtable=NULL;
}

/* For backwards source and binary compatibility */
void reset_hostlist_table_data(conv_hash_t *ch)
{
    reset_endpoint_table_data(ch);
}

char *get_conversation_address(wmem_allocator_t *allocator, address *addr, gboolean resolve_names)
{
    if (resolve_names) {
        return address_to_display(allocator, addr);
    } else {
        return address_to_str(allocator, addr);
    }
}

char *get_conversation_port(wmem_allocator_t *allocator, guint32 port, conversation_type ctype, gboolean resolve_names)
{

    if(!resolve_names) ctype = CONVERSATION_NONE;

    switch(ctype) {
    case(CONVERSATION_TCP):
        return tcp_port_to_display(allocator, port);
    case(CONVERSATION_UDP):
        return udp_port_to_display(allocator, port);
    case(CONVERSATION_SCTP):
        return sctp_port_to_display(allocator, port);
    case(CONVERSATION_DCCP):
        return dccp_port_to_display(allocator, port);
    default:
        return wmem_strdup_printf(allocator, "%d", port);
    }
}

char *get_endpoint_port(wmem_allocator_t *allocator, endpoint_item_t *item, gboolean resolve_names)
{
    endpoint_type etype = item->etype;

    if(!resolve_names) etype = ENDPOINT_NONE;

    switch(etype) {
    case(ENDPOINT_TCP):
        return tcp_port_to_display(allocator, item->port);
    case(ENDPOINT_UDP):
        return udp_port_to_display(allocator, item->port);
    case(ENDPOINT_SCTP):
        return sctp_port_to_display(allocator, item->port);
    case(ENDPOINT_DCCP):
        return dccp_port_to_display(allocator, item->port);
    default:
        return wmem_strdup_printf(allocator, "%d", item->port);
    }
}

/* given an address (to distinguish between ipv4 and ipv6 for tcp/udp),
   a endpoint_type and a name_type (FN_...)
   return a string for the filter name.

   Some addresses, like AT_ETHER may actually be any of multiple types
   of protocols,   either ethernet, tokenring, fddi, wlan etc so we must be
   more specific there;  that's why we need specific_addr_type.
*/
static const char *
conversation_get_filter_name(conv_item_t *conv_item, conv_filter_type_e filter_type)
{

    if ((conv_item == NULL) || (conv_item->dissector_info == NULL) || (conv_item->dissector_info->get_filter_type == NULL)) {
        return CONV_FILTER_INVALID;
    }

    return conv_item->dissector_info->get_filter_type(conv_item, filter_type);
}

static const char *
endpoint_get_filter_name(endpoint_item_t *endpoint, conv_filter_type_e filter_type)
{

    if ((endpoint == NULL) || (endpoint->dissector_info == NULL) || (endpoint->dissector_info->get_filter_type == NULL)) {
        return CONV_FILTER_INVALID;
    }

    return endpoint->dissector_info->get_filter_type(endpoint, filter_type);
}

/* Convert a port number into a string or NULL */
static char *
ct_port_to_str(conversation_type ctype, guint32 port)
{
    switch(ctype){
    case CONVERSATION_TCP:
    case CONVERSATION_UDP:
    case CONVERSATION_SCTP:
    case CONVERSATION_NCP:
        return ws_strdup_printf("%d", port);
    default:
        break;
    }
    return NULL;
}

static int usb_address_type = -1;

char *get_conversation_filter(conv_item_t *conv_item, conv_direction_e direction)
{
    char *sport, *dport, *src_addr, *dst_addr;
    char *str;

    /* XXX - Hack until we find something better */
    if (usb_address_type == -1)
        usb_address_type = address_type_get_by_name("AT_USB");

    sport = ct_port_to_str(conv_item->ctype, conv_item->src_port);
    dport = ct_port_to_str(conv_item->ctype, conv_item->dst_port);
    src_addr = address_to_str(NULL, &conv_item->src_address);
    dst_addr = address_to_str(NULL, &conv_item->dst_address);

    if (conv_item->src_address.type == AT_STRINGZ || conv_item->src_address.type == usb_address_type) {
        char *new_addr;

        new_addr = wmem_strdup_printf(NULL, "\"%s\"", src_addr);
        wmem_free(NULL, src_addr);
        src_addr = new_addr;
    }
    if (conv_item->dst_address.type == AT_STRINGZ || conv_item->dst_address.type == usb_address_type) {
        char *new_addr;

        new_addr = wmem_strdup_printf(NULL, "\"%s\"", dst_addr);
        wmem_free(NULL, dst_addr);
        dst_addr = new_addr;
    }

    switch(direction){
    case CONV_DIR_A_TO_FROM_B:
        /* A <-> B */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              src_addr,
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              dst_addr,
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_TO_B:
        /* A --> B */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              src_addr,
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              dst_addr,
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_FROM_B:
        /* A <-- B */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              src_addr,
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              dst_addr,
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_TO_FROM_ANY:
        /* A <-> ANY */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              src_addr,
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_A_TO_ANY:
        /* A --> ANY */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              src_addr,
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_A_FROM_ANY:
        /* A <-- ANY */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              src_addr,
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_ANY_TO_FROM_B:
        /* ANY <-> B */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              dst_addr,
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_ANY_FROM_B:
        /* ANY <-- B */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              dst_addr,
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_ANY_TO_B:
        /* ANY --> B */
        str = wmem_strdup_printf(NULL, "%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              dst_addr,
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    default:
        str = wmem_strdup(NULL, "INVALID");
        break;
    }
    g_free(sport);
    g_free(dport);
    wmem_free(NULL, src_addr);
    wmem_free(NULL, dst_addr);
    return str;
}

char *get_endpoint_filter(endpoint_item_t *endpoint_item)
{
    char *sport, *src_addr;
    char *str;

    /* XXX - Hack until we find something better */
    if (usb_address_type == -1)
        usb_address_type = address_type_get_by_name("AT_USB");

    switch(endpoint_item->etype){
    case ENDPOINT_TCP:
    case ENDPOINT_UDP:
    case ENDPOINT_SCTP:
    case ENDPOINT_NCP:
        sport = ws_strdup_printf("%d", endpoint_item->port);
        break;
    default:
        sport = NULL;
        break;
    }
    src_addr = address_to_str(NULL, &endpoint_item->myaddress);
    if (endpoint_item->myaddress.type == AT_STRINGZ || endpoint_item->myaddress.type == usb_address_type) {
        char *new_addr;

        new_addr = wmem_strdup_printf(NULL, "\"%s\"", src_addr);
        wmem_free(NULL, src_addr);
        src_addr = new_addr;
    }

    str = ws_strdup_printf("%s==%s%s%s%s%s",
                          endpoint_get_filter_name(endpoint_item, CONV_FT_ANY_ADDRESS),
                          src_addr,
                          sport?" && ":"",
                          sport?endpoint_get_filter_name(endpoint_item, CONV_FT_ANY_PORT):"",
                          sport?"==":"",
                          sport?sport:"");

    g_free(sport);
    wmem_free(NULL, src_addr);
    return str;
}

/* For backwards source and binary compatibility */
char *get_hostlist_filter(endpoint_item_t *endpoint_item)
{
    return get_endpoint_filter(endpoint_item);
}

void
add_conversation_table_data(conv_hash_t *ch, const address *src, const address *dst, guint32 src_port, guint32 dst_port, int num_frames, int num_bytes,
        nstime_t *ts, nstime_t *abs_ts, ct_dissector_info_t *ct_info, conversation_type ctype)
{
    add_conversation_table_data_with_conv_id(ch, src, dst, src_port, dst_port, CONV_ID_UNSET, num_frames, num_bytes, ts, abs_ts, ct_info, ctype);
}

void
add_conversation_table_data_with_conv_id(
    conv_hash_t *ch,
    const address *src,
    const address *dst,
    guint32 src_port,
    guint32 dst_port,
    conv_id_t conv_id,
    int num_frames,
    int num_bytes,
    nstime_t *ts,
    nstime_t *abs_ts,
    ct_dissector_info_t *ct_info,
    conversation_type ctype)
{
    conv_item_t *conv_item = NULL;
    gboolean is_fwd_direction = FALSE; /* direction of any conversation found */

    /* if we don't have any entries at all yet */
    if (ch->conv_array == NULL) {
        ch->conv_array = g_array_sized_new(FALSE, FALSE, sizeof(conv_item_t), 10000);

        ch->hashtable = g_hash_table_new_full(conversation_hash,
                                              conversation_equal, /* key_equal_func */
                                              g_free,             /* key_destroy_func */
                                              NULL);              /* value_destroy_func */

    } else { /* try to find it among the existing known conversations */
        /* first, check in the fwd conversations */
        conv_key_t existing_key;
        gpointer conversation_idx_hash_val;

        existing_key.addr1 = *src;
        existing_key.addr2 = *dst;
        existing_key.port1 = src_port;
        existing_key.port2 = dst_port;
        existing_key.conv_id = conv_id;
        if (g_hash_table_lookup_extended(ch->hashtable, &existing_key, NULL, &conversation_idx_hash_val)) {
            conv_item = &g_array_index(ch->conv_array, conv_item_t, GPOINTER_TO_UINT(conversation_idx_hash_val));
        }
        if (conv_item == NULL) {
            /* then, check in the rev conversations if not found in 'fwd' */
            existing_key.addr1 = *dst;
            existing_key.addr2 = *src;
            existing_key.port1 = dst_port;
            existing_key.port2 = src_port;
            if (g_hash_table_lookup_extended(ch->hashtable, &existing_key, NULL, &conversation_idx_hash_val)) {
                conv_item = &g_array_index(ch->conv_array, conv_item_t, GPOINTER_TO_UINT(conversation_idx_hash_val));
            }
        } else {
            /* a conversation was found in this same fwd direction */
            is_fwd_direction = TRUE;
        }
    }

    /* if we still don't know what conversation this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if (conv_item == NULL) {
        conv_key_t *new_key;
        conv_item_t new_conv_item;
        unsigned int conversation_idx;

        copy_address(&new_conv_item.src_address, src);
        copy_address(&new_conv_item.dst_address, dst);
        new_conv_item.dissector_info = ct_info;
        new_conv_item.ctype = ctype;
        new_conv_item.src_port = src_port;
        new_conv_item.dst_port = dst_port;
        new_conv_item.conv_id = conv_id;
        new_conv_item.rx_frames = 0;
        new_conv_item.tx_frames = 0;
        new_conv_item.rx_bytes = 0;
        new_conv_item.tx_bytes = 0;
        new_conv_item.rx_frames_total = 0;
        new_conv_item.tx_frames_total = 0;
        new_conv_item.rx_bytes_total = 0;
        new_conv_item.tx_bytes_total = 0;

        if (ts) {
            memcpy(&new_conv_item.start_time, ts, sizeof(new_conv_item.start_time));
            memcpy(&new_conv_item.stop_time, ts, sizeof(new_conv_item.stop_time));
            memcpy(&new_conv_item.start_abs_time, abs_ts, sizeof(new_conv_item.start_abs_time));
        } else {
            nstime_set_unset(&new_conv_item.start_abs_time);
            nstime_set_unset(&new_conv_item.start_time);
            nstime_set_unset(&new_conv_item.stop_time);
        }
        g_array_append_val(ch->conv_array, new_conv_item);
        conversation_idx = ch->conv_array->len - 1;
        conv_item = &g_array_index(ch->conv_array, conv_item_t, conversation_idx);

        /* ct->conversations address is not a constant but src/dst_address.data are */
        new_key = g_new(conv_key_t, 1);
        set_address(&new_key->addr1, conv_item->src_address.type, conv_item->src_address.len, conv_item->src_address.data);
        set_address(&new_key->addr2, conv_item->dst_address.type, conv_item->dst_address.len, conv_item->dst_address.data);
        new_key->port1 = src_port;
        new_key->port2 = dst_port;
        new_key->conv_id = conv_id;
        g_hash_table_insert(ch->hashtable, new_key, GUINT_TO_POINTER(conversation_idx));

        /* update the conversation struct */
        conv_item->tx_frames_total += num_frames;
        conv_item->tx_bytes_total += num_bytes;
        conv_item->filtered = TRUE;
        if (! (ch->flags & TL_DISPLAY_FILTER_IGNORED)) {
            conv_item->tx_frames += num_frames;
            conv_item->tx_bytes += num_bytes;
            conv_item->filtered = FALSE;
        }
    } else {
        /*
         * update an existing conversation
         * update the conversation struct
         */
        if (is_fwd_direction) {
            conv_item->tx_frames_total += num_frames;
            conv_item->tx_bytes_total += num_bytes;
        } else {
            conv_item->rx_frames_total += num_frames;
            conv_item->rx_bytes_total += num_bytes;
        }
        if (! (ch->flags & TL_DISPLAY_FILTER_IGNORED)) {
            if( is_fwd_direction ){
                conv_item->tx_frames += num_frames;
                conv_item->tx_bytes += num_bytes;
            } else {
                conv_item->rx_frames += num_frames;
                conv_item->rx_bytes += num_bytes;
            }
            conv_item->filtered = FALSE;
        }
    }

    if (ts) {
        if (nstime_cmp(ts, &conv_item->stop_time) > 0) {
            memcpy(&conv_item->stop_time, ts, sizeof(conv_item->stop_time));
        } else if (nstime_cmp(ts, &conv_item->start_time) < 0) {
            memcpy(&conv_item->start_time, ts, sizeof(conv_item->start_time));
            memcpy(&conv_item->start_abs_time, abs_ts, sizeof(conv_item->start_abs_time));
        }
    }
}

/*
 * Compute the hash value for a given address/port pair if the match
 * is to be exact.
 */
static guint
endpoint_hash(gconstpointer v)
{
    const endpoint_key_t *key = (const endpoint_key_t *)v;
    guint hash_val;

    hash_val = 0;
    hash_val = add_address_to_hash(hash_val, &key->myaddress);
    hash_val += key->port;
    return hash_val;
}

/*
 * Compare two endpoint keys for an exact match.
 */
static gint
endpoint_match(gconstpointer v, gconstpointer w)
{
    const endpoint_key_t *v1 = (const endpoint_key_t *)v;
    const endpoint_key_t *v2 = (const endpoint_key_t *)w;

    if (v1->port == v2->port &&
        addresses_equal(&v1->myaddress, &v2->myaddress)) {
        return 1;
    }
    /*
     * The addresses or the ports don't match.
     */
    return 0;
}

void
add_endpoint_table_data(conv_hash_t *ch, const address *addr, guint32 port, gboolean sender, int num_frames, int num_bytes, et_dissector_info_t *et_info, endpoint_type etype)
{
    endpoint_item_t *endpoint_item = NULL;

    /* XXX should be optimized to allocate n extra entries at a time
       instead of just one */
    /* if we don't have any entries at all yet */
    if(ch->conv_array==NULL){
        ch->conv_array=g_array_sized_new(FALSE, FALSE, sizeof(endpoint_item_t), 10000);
        ch->hashtable = g_hash_table_new_full(endpoint_hash,
                                              endpoint_match, /* key_equal_func */
                                              g_free,     /* key_destroy_func */
                                              NULL);      /* value_destroy_func */
    }
    else {
        /* try to find it among the existing known conversations */
        endpoint_key_t existing_key;
        gpointer endpoint_idx_hash_val;

        copy_address_shallow(&existing_key.myaddress, addr);
        existing_key.port = port;

        if (g_hash_table_lookup_extended(ch->hashtable, &existing_key, NULL, &endpoint_idx_hash_val)) {
            endpoint_item = &g_array_index(ch->conv_array, endpoint_item_t, GPOINTER_TO_UINT(endpoint_idx_hash_val));
        }
    }

    /* if we still don't know what endpoint this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if(endpoint_item==NULL){
        endpoint_key_t *new_key;
        endpoint_item_t new_endpoint_item;
        unsigned int endpoint_idx;

        copy_address(&new_endpoint_item.myaddress, addr);
        new_endpoint_item.dissector_info = et_info;
        new_endpoint_item.etype=etype;
        new_endpoint_item.port=port;
        new_endpoint_item.rx_frames=0;
        new_endpoint_item.tx_frames=0;
        new_endpoint_item.rx_bytes=0;
        new_endpoint_item.tx_bytes=0;
        new_endpoint_item.rx_frames_total=0;
        new_endpoint_item.tx_frames_total=0;
        new_endpoint_item.rx_bytes_total=0;
        new_endpoint_item.tx_bytes_total=0;
        new_endpoint_item.modified = TRUE;
        new_endpoint_item.filtered = TRUE;

        g_array_append_val(ch->conv_array, new_endpoint_item);
        endpoint_idx = ch->conv_array->len - 1;
        endpoint_item = &g_array_index(ch->conv_array, endpoint_item_t, endpoint_idx);

        /* hl->hosts address is not a constant but address.data is */
        new_key = g_new(endpoint_key_t,1);
        set_address(&new_key->myaddress, endpoint_item->myaddress.type, endpoint_item->myaddress.len, endpoint_item->myaddress.data);
        new_key->port = port;
        g_hash_table_insert(ch->hashtable, new_key, GUINT_TO_POINTER(endpoint_idx));
    }

    /* if this is a new endpoint we need to initialize the struct */
    endpoint_item->modified = TRUE;

    /* update the endpoint struct */
    if (! (ch->flags & TL_DISPLAY_FILTER_IGNORED)) {
        if( sender ){
            endpoint_item->tx_frames+=num_frames;
            endpoint_item->tx_bytes+=num_bytes;
        } else {
            endpoint_item->rx_frames+=num_frames;
            endpoint_item->rx_bytes+=num_bytes;
        }
        endpoint_item->filtered = FALSE;
    }
    /* update the endpoint struct for total values */
    if( sender ){
        endpoint_item->tx_frames_total+=num_frames;
        endpoint_item->tx_bytes_total+=num_bytes;
    } else {
        endpoint_item->rx_frames_total+=num_frames;
        endpoint_item->rx_bytes_total+=num_bytes;
    }
}

/* For backwards source and binary compatibility */
void
add_hostlist_table_data(conv_hash_t *ch, const address *addr, guint32 port, gboolean sender, int num_frames, int num_bytes, et_dissector_info_t *et_info, endpoint_type etype)
{
    add_endpoint_table_data(ch, addr, port, sender, num_frames, num_bytes, et_info, etype);
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
