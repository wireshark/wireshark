/* conversation_hash.c
 * Copied from gtk/conversations_table.c   2003 Ronnie Sahlberg
 * Helper routines common to all conversations taps.
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

#include <glib.h>

#include <epan/address.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>
#include <epan/to_str.h>

#include "conversation_hash.h"
#include "utf8_entities.h"

const char *column_titles[CONV_NUM_COLUMNS] = {
    "Address A",
    "Port A",
    "Address B",
    "Port B",
    "Packets",
    "Bytes",
    "Packets A " UTF8_RIGHTWARDS_ARROW " B",
    "Bytes A " UTF8_RIGHTWARDS_ARROW " B",
    "Packets B " UTF8_RIGHTWARDS_ARROW " A",
    "Bytes B " UTF8_RIGHTWARDS_ARROW " A",
    "Rel Start",
    "Duration",
    "bps A " UTF8_RIGHTWARDS_ARROW " B",
    "bps B " UTF8_RIGHTWARDS_ARROW " A"
};

const char *conn_a_title = "Connection A";
const char *conn_b_title = "Connection B";

/*
 * Compute the hash value for two given address/port pairs if the match
 * is to be exact.
 */
guint
conversation_hash(gconstpointer key)
{
    const conv_key_t *ck = (const conv_key_t *)key;
    guint hash_val;

    hash_val = 0;
    ADD_ADDRESS_TO_HASH(hash_val, &ck->addr1);
    hash_val += ck->port1;
    ADD_ADDRESS_TO_HASH(hash_val, &ck->addr2);
    hash_val += ck->port2;
    hash_val ^= ck->conv_id;

    return hash_val;
}

/*
 * Compare two conversation keys for an exact match.
 */
gboolean
conversation_equal(gconstpointer key1, gconstpointer key2)
{
    const conv_key_t *ck1 = (const conv_key_t *)key1;
    const conv_key_t *ck2 = (const conv_key_t *)key2;

    if (ck1->conv_id == ck2->conv_id)
    {
        if (ck1->port1 == ck2->port1 &&
            ck1->port2 == ck2->port2 &&
            ADDRESSES_EQUAL(&ck1->addr1, &ck2->addr1) &&
            ADDRESSES_EQUAL(&ck1->addr2, &ck2->addr2)) {
            return TRUE;
        }

        if (ck1->port2 == ck2->port1 &&
            ck1->port1 == ck2->port2 &&
            ADDRESSES_EQUAL(&ck1->addr2, &ck2->addr1) &&
            ADDRESSES_EQUAL(&ck1->addr1, &ck2->addr2)) {
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
            g_free((gpointer)conv->src_address.data);
            g_free((gpointer)conv->dst_address.data);
        }

        g_array_free(ch->conv_array, TRUE);
    }

    if (ch->hashtable != NULL) {
        g_hash_table_destroy(ch->hashtable);
    }

    ch->conv_array=NULL;
    ch->hashtable=NULL;
}

void
add_conversation_table_data(conv_hash_t *ch, const address *src, const address *dst, guint32 src_port, guint32 dst_port, int num_frames, int num_bytes, nstime_t *ts, conversation_type_e conv_type, port_type ptype)
{
    add_conversation_table_data_with_conv_id(ch, src, dst, src_port, dst_port, CONV_ID_UNSET, num_frames, num_bytes, ts, conv_type, ptype);
}

void
add_conversation_table_data_with_conv_id(conv_hash_t *ch,
    const address *src,
    const address *dst,
    guint32 src_port,
    guint32 dst_port,
    conv_id_t conv_id,
    int num_frames,
    int num_bytes,
    nstime_t *ts,
    conversation_type_e conv_type,
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
    } else if (CMP_ADDRESS(src, dst) < 0) {
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

    /* if we dont have any entries at all yet */
    if (ch->conv_array == NULL) {
        ch->conv_array = g_array_sized_new(FALSE, FALSE, sizeof(conv_item_t), 10000);

        ch->hashtable = g_hash_table_new_full(conversation_hash,
                                              conversation_equal, /* key_equal_func */
                                              g_free,             /* key_destroy_func */
                                              NULL);              /* value_destroy_func */

    } else {
        /* try to find it among the existing known conversations */
        conv_key_t existing_key;

        existing_key.addr1 = *addr1;
        existing_key.addr2 = *addr2;
        existing_key.port1 = port1;
        existing_key.port2 = port2;
        existing_key.conv_id = conv_id;
        if (g_hash_table_lookup_extended(ch->hashtable, &existing_key, NULL, (gpointer *) &conversation_idx)) {
            conv_item = &g_array_index(ch->conv_array, conv_item_t, conversation_idx);
        }
    }

    /* if we still dont know what conversation this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if (conv_item == NULL) {
        conv_key_t *new_key;
        conv_item_t new_conv_item;

        COPY_ADDRESS(&new_conv_item.src_address, addr1);
        COPY_ADDRESS(&new_conv_item.dst_address, addr2);
        new_conv_item.conv_type = conv_type;
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
        } else {
            nstime_set_unset(&new_conv_item.start_time);
            nstime_set_unset(&new_conv_item.stop_time);
        }
        g_array_append_val(ch->conv_array, new_conv_item);
        conversation_idx = ch->conv_array->len - 1;
        conv_item = &g_array_index(ch->conv_array, conv_item_t, conversation_idx);

        /* ct->conversations address is not a constant but src/dst_address.data are */
        new_key = g_new(conv_key_t, 1);
        SET_ADDRESS(&new_key->addr1, conv_item->src_address.type, conv_item->src_address.len, conv_item->src_address.data);
        SET_ADDRESS(&new_key->addr2, conv_item->dst_address.type, conv_item->dst_address.len, conv_item->dst_address.data);
        new_key->port1 = port1;
        new_key->port2 = port2;
        new_key->conv_id = conv_id;
        g_hash_table_insert(ch->hashtable, new_key, GUINT_TO_POINTER(conversation_idx));
    }

    /* update the conversation struct */
    conv_item->modified = TRUE;
    if ( (!CMP_ADDRESS(src, addr1)) && (!CMP_ADDRESS(dst, addr2)) && (src_port==port1) && (dst_port==port2) ) {
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
        }
    }
}

const char *conversation_title(conversation_type_e conv_type)
{
    switch (conv_type) {
    case CONV_TYPE_ETHERNET:
        return "Ethernet";
    case CONV_TYPE_FIBRE_CHANNEL:
        return "Fibre Channel";
    case CONV_TYPE_FDDI:
        return "FDDI";
    case CONV_TYPE_IPV4:
        return "IPv4";
    case CONV_TYPE_IPV6:
        return "IPv6";
    case CONV_TYPE_IPX:
        return "IPX";
    case CONV_TYPE_JXTA:
        return "JXTA";
    case CONV_TYPE_NCP:
        return "NCP";
    case CONV_TYPE_RSVP:
        return "RSVP";
    case CONV_TYPE_SCTP:
        return "SCTP";
    case CONV_TYPE_TCP:
        return "TCP";
    case CONV_TYPE_TOKEN_RING:
        return "Token Ring";
    case CONV_TYPE_UDP:
        return "UDP";
    case CONV_TYPE_USB:
        return "USB";
    case CONV_TYPE_WLAN:
        return "WLAN";
    default:
        return "Unknown";
    }
}

conversation_type_e conversation_title_to_type(const char *title)
{
    int i;

    for (i = CONV_TYPE_ETHERNET; i < N_CONV_TYPES; i++) {
        conversation_type_e ct = (conversation_type_e) i;
        if (strcmp(title, conversation_title(ct)) == 0) {
            return ct;
        }
    }
    // Sensible default?
    return CONV_TYPE_TCP;
}

const char *conversation_tap_name(conversation_type_e conv_type)
{
    switch (conv_type) {
    case CONV_TYPE_ETHERNET:
        return "eth";
    case CONV_TYPE_FIBRE_CHANNEL:
        return "fc";
    case CONV_TYPE_FDDI:
        return "fddi";
    case CONV_TYPE_IPV4:
        return "ip";
    case CONV_TYPE_IPV6:
        return "ipv6";
    case CONV_TYPE_IPX:
        return "ipx";
    case CONV_TYPE_JXTA:
        return "jxta";
    case CONV_TYPE_NCP:
        return "ncp_hdr";
    case CONV_TYPE_RSVP:
        return "rsvp";
    case CONV_TYPE_SCTP:
        return "sctp";
    case CONV_TYPE_TCP:
        return "tcp";
    case CONV_TYPE_TOKEN_RING:
        return "tr";
    case CONV_TYPE_UDP:
        return "udp";
    case CONV_TYPE_USB:
        return "usb";
    case CONV_TYPE_WLAN:
        return "wlan";
    default:
        return "INVALID TAP NAME";
    }
}

gboolean conversation_hide_ports(conversation_type_e conv_type)
{
    switch (conv_type) {
    case CONV_TYPE_NCP:
    case CONV_TYPE_SCTP:
    case CONV_TYPE_TCP:
    case CONV_TYPE_UDP:
        return FALSE;
    default:
        return TRUE;
    }
}

const char *get_conversation_address(address *addr, gboolean resolve_names)
{
    if (resolve_names) {
        return ep_address_to_display(addr);
    } else {
        return ep_address_to_str(addr);
    }
}

const char *get_conversation_port(guint32 port, port_type ptype, gboolean resolve_names)
{

    if(!resolve_names) ptype = PT_NONE;

    switch(ptype) {
    case(PT_TCP):
        return ep_tcp_port_to_display(port);
    case(PT_UDP):
        return ep_udp_port_to_display(port);
    case(PT_SCTP):
        return ep_sctp_port_to_display(port);
    default:
        return ep_strdup_printf("%d", port);
    }
}

typedef enum {
    CONV_FT_SRC_ADDRESS,
    CONV_FT_DST_ADDRESS,
    CONV_FT_ANY_ADDRESS,
    CONV_FT_SRC_PORT,
    CONV_FT_DST_PORT,
    CONV_FT_ANY_PORT
} conv_filter_type_e;

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

    if (!conv_item) {
        return "INVALID";
    }

    switch(filter_type){
    case CONV_FT_SRC_ADDRESS:
        switch(conv_item->src_address.type){
        case AT_ETHER:
            switch(conv_item->conv_type){
            case CONV_TYPE_ETHERNET:
                return "eth.src";
            case CONV_TYPE_WLAN:
                return "wlan.sa";
            case CONV_TYPE_FDDI:
                return "fddi.src";
            case CONV_TYPE_TOKEN_RING:
                return "tr.src";
            default:
                break;
            }
            break;
        case AT_IPv4:
            return "ip.src";
        case AT_IPv6:
            return "ipv6.src";
        case AT_IPX:
            return "ipx.src";
        case AT_FC:
            return "fc.s_id";
        case AT_URI:
            switch(conv_item->conv_type){
            case CONV_TYPE_JXTA:
                return "jxta.message.src";
            default:
                break;
            }
            break;
        case AT_USB:
            return "usb.sa";
        default:
            break;
        }
        break;
    case CONV_FT_DST_ADDRESS:
        switch(conv_item->dst_address.type){
        case AT_ETHER:
            switch(conv_item->conv_type){
            case CONV_TYPE_ETHERNET:
                return "eth.dst";
            case CONV_TYPE_WLAN:
                return "wlan.da";
            case CONV_TYPE_FDDI:
                return "fddi.dst";
            case CONV_TYPE_TOKEN_RING:
                return "tr.dst";
            default:
                break;
            }
            break;
        case AT_IPv4:
            return "ip.dst";
        case AT_IPv6:
            return "ipv6.dst";
        case AT_IPX:
            return "ipx.dst";
        case AT_FC:
            return "fc.d_id";
        case AT_URI:
            switch(conv_item->conv_type){
            case CONV_TYPE_JXTA:
                return "jxta.message.dst";
            default:
                break;
            }
            break;
        case AT_USB:
            return "usb.da";
        default:
            break;
        }
        break;
    case CONV_FT_ANY_ADDRESS:
        switch(conv_item->src_address.type){
        case AT_ETHER:
            switch(conv_item->conv_type){
            case CONV_TYPE_ETHERNET:
                return "eth.addr";
            case CONV_TYPE_WLAN:
                return "wlan.addr";
            case CONV_TYPE_FDDI:
                return "fddi.addr";
            case CONV_TYPE_TOKEN_RING:
                return "tr.addr";
            default:
                break;
            }
            break;
        case AT_IPv4:
            return "ip.addr";
        case AT_IPv6:
            return "ipv6.addr";
        case AT_IPX:
            return "ipx.addr";
        case AT_FC:
            return "fc.id";
        case AT_URI:
            switch(conv_item->conv_type){
            case CONV_TYPE_JXTA:
                return "jxta.message.address";
            default:
                break;
            }
            break;
        case AT_USB:
            return "usb.addr";
        default:
            break;
        }
        break;
    case CONV_FT_SRC_PORT:
        switch(conv_item->ptype){
        case PT_TCP:
            return "tcp.srcport";
        case PT_UDP:
            return "udp.srcport";
        case PT_SCTP:
            return "sctp.srcport";
        case PT_NCP:
            return "ncp.connection";
        default:
            break;
        }
        break;
    case CONV_FT_DST_PORT:
        switch(conv_item->ptype){
        case PT_TCP:
            return "tcp.dstport";
        case PT_UDP:
            return "udp.dstport";
        case PT_SCTP:
            return "sctp.dstport";
        case PT_NCP:
            return "ncp.connection";
        default:
            break;
        }
        break;
    case CONV_FT_ANY_PORT:
        switch(conv_item->ptype){
        case PT_TCP:
            return "tcp.port";
        case PT_UDP:
            return "udp.port";
        case PT_SCTP:
            return "sctp.port";
        case PT_NCP:
            return "ncp.connection";
        default:
            break;
        }
        break;
    }

    return "INVALID";
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


const char *get_conversation_filter(conv_item_t *conv_item, conv_direction_e direction)
{
    char *sport, *dport;
    const char *str = "INVALID";

    sport = ct_port_to_str(conv_item->ptype, conv_item->src_port);
    dport = ct_port_to_str(conv_item->ptype, conv_item->dst_port);

    switch(direction){
    case CONV_DIR_A_TO_FROM_B:
        /* A <-> B */
        str = ep_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_TO_B:
        /* A --> B */
        str = ep_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_FROM_B:
        /* A <-- B */
        str = ep_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_TO_FROM_ANY:
        /* A <-> ANY */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_A_TO_ANY:
        /* A --> ANY */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_A_FROM_ANY:
        /* A <-- ANY */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_ANY_TO_FROM_B:
        /* ANY <-> B */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_ANY_FROM_B:
        /* ANY <-- B */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_ANY_TO_B:
        /* ANY --> B */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    default:
        break;
    }
    g_free(sport);
    g_free(dport);
    return str;
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
