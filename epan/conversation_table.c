/* conversations_table.c
 * conversations_table   2003 Ronnie Sahlberg
 * Helper routines common to all endpoint conversations tap.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
    tap_packet_cb conv_func;   /* function to be called for new incoming packets for conversation*/
    tap_packet_cb host_func;   /* function to be called for new incoming packets for hostlist */
    conv_gui_init_cb conv_gui_init; /* GUI specific function to initialize conversation */
    host_gui_init_cb host_gui_init; /* GUI specific function to initialize hostlist */
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

tap_packet_cb get_hostlist_packet_func(register_ct_t* ct)
{
    return ct->host_func;
}

static GSList *registered_ct_tables = NULL;

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
dissector_hostlist_init(const char *opt_arg, void* userdata)
{
    register_ct_t *table = (register_ct_t*)userdata;
    GString *cmd_str = g_string_new("");
    const char *filter=NULL;

    g_string_printf(cmd_str, "%s,%s,", HOSTLIST_TAP_PREFIX, proto_get_protocol_filter_name(table->proto_id));
    if(!strncmp(opt_arg, cmd_str->str, cmd_str->len)){
        if (opt_arg[cmd_str->len] == ',') {
            filter = opt_arg + cmd_str->len + 1;
        }
    } else {
        filter=NULL;
    }

    g_string_free(cmd_str, TRUE);

    if (table->host_gui_init)
        table->host_gui_init(table, filter);
}
/** get conversation from protocol ID
 *
 * @param proto_id protocol ID
 * @return tap function handler of conversation
 */
register_ct_t* get_conversation_by_proto_id(int proto_id)
{
    GSList *ct;
    register_ct_t *table;

    for(ct = registered_ct_tables; ct != NULL; ct = g_slist_next(ct)){
        table = (register_ct_t*)ct->data;
        if ((table) && (table->proto_id == proto_id))
            return table;
    }

    return NULL;
}

static gint
insert_sorted_by_table_name(gconstpointer aparam, gconstpointer bparam)
{
    const register_ct_t *a = (const register_ct_t *)aparam;
    const register_ct_t *b = (const register_ct_t *)bparam;

    return g_ascii_strcasecmp(proto_get_protocol_short_name(find_protocol_by_id(a->proto_id)), proto_get_protocol_short_name(find_protocol_by_id(b->proto_id)));
}

void
register_conversation_table(const int proto_id, gboolean hide_ports, tap_packet_cb conv_packet_func, tap_packet_cb hostlist_func)
{
    register_ct_t *table;

    table = g_new(register_ct_t,1);

    table->hide_ports    = hide_ports;
    table->proto_id      = proto_id;
    table->conv_func     = conv_packet_func;
    table->host_func     = hostlist_func;
    table->conv_gui_init = NULL;
    table->host_gui_init = NULL;

    registered_ct_tables = g_slist_insert_sorted(registered_ct_tables, table, insert_sorted_by_table_name);
}

/* Set GUI fields for register_ct list */
static void
set_conv_gui_data(gpointer data, gpointer user_data)
{
    GString *conv_cmd_str = g_string_new("conv,");
    stat_tap_ui ui_info;
    register_ct_t *table = (register_ct_t*)data;

    table->conv_gui_init = (conv_gui_init_cb)user_data;

    g_string_append(conv_cmd_str, proto_get_protocol_filter_name(table->proto_id));
    ui_info.group = REGISTER_STAT_GROUP_CONVERSATION_LIST;
    ui_info.title = NULL;   /* construct this from the protocol info? */
    ui_info.cli_string = g_string_free(conv_cmd_str, FALSE);
    ui_info.tap_init_cb = dissector_conversation_init;
    ui_info.nparams = 0;
    ui_info.params = NULL;
    register_stat_tap_ui(&ui_info, table);
}

void conversation_table_set_gui_info(conv_gui_init_cb init_cb)
{
    g_slist_foreach(registered_ct_tables, set_conv_gui_data, (gpointer)init_cb);
}

static void
set_host_gui_data(gpointer data, gpointer user_data)
{
    GString *host_cmd_str = g_string_new("");
    stat_tap_ui ui_info;
    register_ct_t *table = (register_ct_t*)data;

    table->host_gui_init = (host_gui_init_cb)user_data;

    g_string_printf(host_cmd_str, "%s,%s", HOSTLIST_TAP_PREFIX, proto_get_protocol_filter_name(table->proto_id));
    ui_info.group = REGISTER_STAT_GROUP_ENDPOINT_LIST;
    ui_info.title = NULL;   /* construct this from the protocol info? */
    ui_info.cli_string = g_string_free(host_cmd_str, FALSE);
    ui_info.tap_init_cb = dissector_hostlist_init;
    ui_info.nparams = 0;
    ui_info.params = NULL;
    register_stat_tap_ui(&ui_info, table);
}

void hostlist_table_set_gui_info(host_gui_init_cb init_cb)
{
    g_slist_foreach(registered_ct_tables, set_host_gui_data, (gpointer)init_cb);
}

void conversation_table_iterate_tables(GFunc func, gpointer user_data)
{
    g_slist_foreach(registered_ct_tables, func, user_data);
}

guint conversation_table_get_num(void)
{
    return g_slist_length(registered_ct_tables);
}


register_ct_t *get_conversation_table_by_num(guint table_num)
{
    return (register_ct_t *) g_slist_nth_data(registered_ct_tables, table_num);
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

void reset_hostlist_table_data(conv_hash_t *ch)
{
    if (!ch) {
        return;
    }

    if (ch->conv_array != NULL) {
        guint i;
        for(i = 0; i < ch->conv_array->len; i++){
            hostlist_talker_t *host = &g_array_index(ch->conv_array, hostlist_talker_t, i);
            free_address(&host->myaddress);
        }

        g_array_free(ch->conv_array, TRUE);
    }

    if (ch->hashtable != NULL) {
        g_hash_table_destroy(ch->hashtable);
    }

    ch->conv_array=NULL;
    ch->hashtable=NULL;
}

char *get_conversation_address(wmem_allocator_t *allocator, address *addr, gboolean resolve_names)
{
    if (resolve_names) {
        return address_to_display(allocator, addr);
    } else {
        return address_to_str(allocator, addr);
    }
}

char *get_conversation_port(wmem_allocator_t *allocator, guint32 port, port_type ptype, gboolean resolve_names)
{

    if(!resolve_names) ptype = PT_NONE;

    switch(ptype) {
    case(PT_TCP):
        return tcp_port_to_display(allocator, port);
    case(PT_UDP):
        return udp_port_to_display(allocator, port);
    case(PT_SCTP):
        return sctp_port_to_display(allocator, port);
    default:
        return wmem_strdup_printf(allocator, "%d", port);
    }
}

/* given an address (to distinguish between ipv4 and ipv6 for tcp/udp),
   a port_type and a name_type (FN_...)
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
hostlist_get_filter_name(hostlist_talker_t *host, conv_filter_type_e filter_type)
{

    if ((host == NULL) || (host->dissector_info == NULL) || (host->dissector_info->get_filter_type == NULL)) {
        return CONV_FILTER_INVALID;
    }

    return host->dissector_info->get_filter_type(host, filter_type);
}

/* Convert a port number into a string or NULL */
static char *
ct_port_to_str(port_type ptype, guint32 port)
{
    switch(ptype){
    case PT_TCP:
    case PT_UDP:
    case PT_SCTP:
    case PT_NCP:
        return g_strdup_printf("%d", port);
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

    sport = ct_port_to_str(conv_item->ptype, conv_item->src_port);
    dport = ct_port_to_str(conv_item->ptype, conv_item->dst_port);
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

char *get_hostlist_filter(hostlist_talker_t *host)
{
    char *sport, *src_addr;
    char *str;

    /* XXX - Hack until we find something better */
    if (usb_address_type == -1)
        usb_address_type = address_type_get_by_name("AT_USB");

    sport = ct_port_to_str(host->ptype, host->port);
    src_addr = address_to_str(NULL, &host->myaddress);
    if (host->myaddress.type == AT_STRINGZ || host->myaddress.type == usb_address_type) {
        char *new_addr;

        new_addr = wmem_strdup_printf(NULL, "\"%s\"", src_addr);
        wmem_free(NULL, src_addr);
        src_addr = new_addr;
    }

    str = g_strdup_printf("%s==%s%s%s%s%s",
                          hostlist_get_filter_name(host, CONV_FT_ANY_ADDRESS),
                          src_addr,
                          sport?" && ":"",
                          sport?hostlist_get_filter_name(host, CONV_FT_ANY_PORT):"",
                          sport?"==":"",
                          sport?sport:"");

    g_free(sport);
    wmem_free(NULL, src_addr);
    return str;
}

void
add_conversation_table_data(conv_hash_t *ch, const address *src, const address *dst, guint32 src_port, guint32 dst_port, int num_frames, int num_bytes,
        nstime_t *ts, nstime_t *abs_ts, ct_dissector_info_t *ct_info, port_type ptype)
{
    add_conversation_table_data_with_conv_id(ch, src, dst, src_port, dst_port, CONV_ID_UNSET, num_frames, num_bytes, ts, abs_ts, ct_info, ptype);
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
    port_type ptype)
{
    const address *addr1, *addr2;
    guint32 port1, port2;
    conv_item_t *conv_item = NULL;
    unsigned int conversation_idx = 0;

    if (src_port > dst_port) {
        addr1 = src;
        addr2 = dst;
        port1 = src_port;
        port2 = dst_port;
    } else if (src_port < dst_port) {
        addr2 = src;
        addr1 = dst;
        port2 = src_port;
        port1 = dst_port;
    } else if (cmp_address(src, dst) < 0) {
        addr1 = src;
        addr2 = dst;
        port1 = src_port;
        port2 = dst_port;
    } else {
        addr2 = src;
        addr1 = dst;
        port2 = src_port;
        port1 = dst_port;
    }

    /* if we don't have any entries at all yet */
    if (ch->conv_array == NULL) {
        ch->conv_array = g_array_sized_new(FALSE, FALSE, sizeof(conv_item_t), 10000);

        ch->hashtable = g_hash_table_new_full(conversation_hash,
                                              conversation_equal, /* key_equal_func */
                                              g_free,             /* key_destroy_func */
                                              NULL);              /* value_destroy_func */

    } else {
        /* try to find it among the existing known conversations */
        conv_key_t existing_key;
        gpointer conversation_idx_hash_val;

        existing_key.addr1 = *addr1;
        existing_key.addr2 = *addr2;
        existing_key.port1 = port1;
        existing_key.port2 = port2;
        existing_key.conv_id = conv_id;
        if (g_hash_table_lookup_extended(ch->hashtable, &existing_key, NULL, &conversation_idx_hash_val)) {
            conv_item = &g_array_index(ch->conv_array, conv_item_t, GPOINTER_TO_UINT(conversation_idx_hash_val));
        }
    }

    /* if we still don't know what conversation this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if (conv_item == NULL) {
        conv_key_t *new_key;
        conv_item_t new_conv_item;

        copy_address(&new_conv_item.src_address, addr1);
        copy_address(&new_conv_item.dst_address, addr2);
        new_conv_item.dissector_info = ct_info;
        new_conv_item.ptype = ptype;
        new_conv_item.src_port = port1;
        new_conv_item.dst_port = port2;
        new_conv_item.conv_id = conv_id;
        new_conv_item.rx_frames = 0;
        new_conv_item.tx_frames = 0;
        new_conv_item.rx_bytes = 0;
        new_conv_item.tx_bytes = 0;
        new_conv_item.modified = TRUE;

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
        new_key->port1 = port1;
        new_key->port2 = port2;
        new_key->conv_id = conv_id;
        g_hash_table_insert(ch->hashtable, new_key, GUINT_TO_POINTER(conversation_idx));
    }

    /* update the conversation struct */
    conv_item->modified = TRUE;
    if ( (!cmp_address(src, addr1)) && (!cmp_address(dst, addr2)) && (src_port==port1) && (dst_port==port2) ) {
        conv_item->tx_frames += num_frames;
        conv_item->tx_bytes += num_bytes;
    } else {
        conv_item->rx_frames += num_frames;
        conv_item->rx_bytes += num_bytes;
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
 * Compute the hash value for a given address/port pairs if the match
 * is to be exact.
 */
static guint
host_hash(gconstpointer v)
{
    const host_key_t *key = (const host_key_t *)v;
    guint hash_val;

    hash_val = 0;
    hash_val = add_address_to_hash(hash_val, &key->myaddress);
    hash_val += key->port;
    return hash_val;
}

/*
 * Compare two host keys for an exact match.
 */
static gint
host_match(gconstpointer v, gconstpointer w)
{
    const host_key_t *v1 = (const host_key_t *)v;
    const host_key_t *v2 = (const host_key_t *)w;

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
add_hostlist_table_data(conv_hash_t *ch, const address *addr, guint32 port, gboolean sender, int num_frames, int num_bytes, hostlist_dissector_info_t *host_info, port_type port_type_val)
{
    hostlist_talker_t *talker=NULL;
    int talker_idx=0;

    /* XXX should be optimized to allocate n extra entries at a time
       instead of just one */
    /* if we don't have any entries at all yet */
    if(ch->conv_array==NULL){
        ch->conv_array=g_array_sized_new(FALSE, FALSE, sizeof(hostlist_talker_t), 10000);
        ch->hashtable = g_hash_table_new_full(host_hash,
                                              host_match, /* key_equal_func */
                                              g_free,     /* key_destroy_func */
                                              NULL);      /* value_destroy_func */
    }
    else {
        /* try to find it among the existing known conversations */
        host_key_t existing_key;
        gpointer talker_idx_hash_val;

        copy_address_shallow(&existing_key.myaddress, addr);
        existing_key.port = port;

        if (g_hash_table_lookup_extended(ch->hashtable, &existing_key, NULL, &talker_idx_hash_val)) {
            talker = &g_array_index(ch->conv_array, hostlist_talker_t, GPOINTER_TO_UINT(talker_idx_hash_val));
        }
    }

    /* if we still don't know what talker this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if(talker==NULL){
        host_key_t *new_key;
        hostlist_talker_t host;

        copy_address(&host.myaddress, addr);
        host.dissector_info = host_info;
        host.ptype=port_type_val;
        host.port=port;
        host.rx_frames=0;
        host.tx_frames=0;
        host.rx_bytes=0;
        host.tx_bytes=0;
        host.modified = TRUE;

        g_array_append_val(ch->conv_array, host);
        talker_idx= ch->conv_array->len - 1;
        talker=&g_array_index(ch->conv_array, hostlist_talker_t, talker_idx);

        /* hl->hosts address is not a constant but address.data is */
        new_key = g_new(host_key_t,1);
        set_address(&new_key->myaddress, talker->myaddress.type, talker->myaddress.len, talker->myaddress.data);
        new_key->port = port;
        g_hash_table_insert(ch->hashtable, new_key, GUINT_TO_POINTER(talker_idx));
    }

    /* if this is a new talker we need to initialize the struct */
    talker->modified = TRUE;

    /* update the talker struct */
    if( sender ){
        talker->tx_frames+=num_frames;
        talker->tx_bytes+=num_bytes;
    } else {
        talker->rx_frames+=num_frames;
        talker->rx_bytes+=num_bytes;
    }
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
