/* packet-lbmc.c
 * Routines for LBMC Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
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
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/wmem/wmem.h>
#include <epan/to_str.h>
#include "packet-lbm.h"
#include "packet-lbttcp.h"


void proto_register_lbmc(void);
void proto_reg_handoff_lbmc(void);

/*----------------------------------------------------------------------------*/
/* Stream management.                                                         */
/*----------------------------------------------------------------------------*/

/* Instance stream structures. */
struct lbm_istream_entry_t_stct;
typedef struct lbm_istream_entry_t_stct lbm_istream_entry_t;
struct lbm_istream_substream_entry_t_stct;
typedef struct lbm_istream_substream_entry_t_stct lbm_istream_substream_entry_t;

struct lbm_istream_substream_entry_t_stct
{
    address src_addr;
    guint16 src_port;
    address dst_addr;
    guint16 dst_port;
    guint32 lbm_stream_id;
    lbm_istream_entry_t * parent;
    guint32 substream_id;
    guint32 first_frame;
    guint32 last_frame;
    guint32 messages;
    guint32 bytes;
};

struct lbm_istream_entry_t_stct
{
    guint8 ctxinst_1[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
    guint8 ctxinst_2[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
    guint64 channel;
    guint32 next_substream_id;
    guint32 first_frame;
    guint32 last_frame;
    guint32 messages;
    guint32 bytes;
    wmem_tree_t * substream_list;
};

/* Domain stream structures */
struct lbm_dstream_entry_t_stct;
typedef struct lbm_dstream_entry_t_stct lbm_dstream_entry_t;
struct lbm_dstream_substream_entry_t_stct;
typedef struct lbm_dstream_substream_entry_t_stct lbm_dstream_substream_entry_t;

struct lbm_dstream_substream_entry_t_stct
{
    address src_addr;
    guint16 src_port;
    address dst_addr;
    guint16 dst_port;
    guint32 lbm_stream_id;
    lbm_dstream_entry_t * parent;
    guint32 substream_id;
    guint32 first_frame;
    guint32 last_frame;
    guint32 messages;
    guint32 bytes;
};

struct lbm_dstream_entry_t_stct
{
    guint32 domain_1;
    address addr_1;
    guint32 domain_2;
    address addr_2;
    guint16 port_1;
    guint16 port_2;
    guint64 channel;
    guint32 next_substream_id;
    guint32 first_frame;
    guint32 last_frame;
    guint32 messages;
    guint32 bytes;
    wmem_tree_t * substream_list;
};

/* Instance stream variables */
#define LBM_ISTREAM_STREAM_KEY_ELEMENT_COUNT         4
#define LBM_ISTREAM_STREAM_KEY_ELEMENT_CTXINST1_HIGH 0
#define LBM_ISTREAM_STREAM_KEY_ELEMENT_CTXINST1_LOW  1
#define LBM_ISTREAM_STREAM_KEY_ELEMENT_CTXINST2_HIGH 2
#define LBM_ISTREAM_STREAM_KEY_ELEMENT_CTXINST2_LOW  3

#define LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_COUNT         5
#define LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_SRC_ADDR      0
#define LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_SRC_PORT      1
#define LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_DST_ADDR      2
#define LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_DST_PORT      3
#define LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_LBM_STREAM_ID 4

static wmem_tree_t * instance_stream_table = NULL;

/* Domain stream variables */
#define LBM_DSTREAM_STREAM_KEY_ELEMENT_COUNT    6
#define LBM_DSTREAM_STREAM_KEY_ELEMENT_DOMAIN_1 0
#define LBM_DSTREAM_STREAM_KEY_ELEMENT_ADDR_1   1
#define LBM_DSTREAM_STREAM_KEY_ELEMENT_DOMAIN_2 2
#define LBM_DSTREAM_STREAM_KEY_ELEMENT_ADDR_2   3
#define LBM_DSTREAM_STREAM_KEY_ELEMENT_PORT_1   4
#define LBM_DSTREAM_STREAM_KEY_ELEMENT_PORT_2   5

#define LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_COUNT         5
#define LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_SRC_ADDR      0
#define LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_SRC_PORT      1
#define LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_DST_ADDR      2
#define LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_DST_PORT      3
#define LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_LBM_STREAM_ID 4

static wmem_tree_t * domain_stream_table = NULL;

static void lbm_stream_init(void)
{
    instance_stream_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    domain_stream_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

static void lbm_istream_stream_build_key(guint32 * key_value, wmem_tree_key_t * key, const lbm_istream_entry_t * stream)
{
    guint32 val;

    /* Note: ctxinst_1 and ctxinst_2 are 8-byte blocks, not guaranteed to be aligned. So we memcpy them 4 bytes
       at a time to an intermediate variable, to prevent any alignment issues with assigning to a 32-bit unsigned int
       on certain platforms.
    */
    memcpy((void *) &val, (void *) stream->ctxinst_1, sizeof(guint32));
    key_value[LBM_ISTREAM_STREAM_KEY_ELEMENT_CTXINST1_HIGH] = val;
    memcpy((void *) &val, (void *) (stream->ctxinst_1 + sizeof(guint32)), sizeof(guint32));
    key_value[LBM_ISTREAM_STREAM_KEY_ELEMENT_CTXINST1_LOW] = val;
    memcpy((void *) &val, (void *) stream->ctxinst_2, sizeof(guint32));
    key_value[LBM_ISTREAM_STREAM_KEY_ELEMENT_CTXINST2_HIGH] = val;
    memcpy((void *) &val, (void *) (stream->ctxinst_2 + sizeof(guint32)), sizeof(guint32));
    key_value[LBM_ISTREAM_STREAM_KEY_ELEMENT_CTXINST2_LOW] = val;
    key[0].length = LBM_ISTREAM_STREAM_KEY_ELEMENT_COUNT;
    key[0].key = key_value;
    key[1].length = 0;
    key[1].key = NULL;
}

static void lbm_stream_order_istream_key(lbm_istream_entry_t * stream)
{
    guint8 ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];

    if (memcmp((void *)stream->ctxinst_1, (void *)stream->ctxinst_2, LBM_CONTEXT_INSTANCE_BLOCK_SZ) > 0)
    {
        memcpy((void *)ctxinst, (void *)stream->ctxinst_1, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
        memcpy((void *)stream->ctxinst_1, (void *)stream->ctxinst_2, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
        memcpy((void *)stream->ctxinst_2, (void *)ctxinst, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
    }
}

static lbm_istream_entry_t * lbm_stream_istream_find(const guint8 * instance1, const guint8 * instance2)
{
    lbm_istream_entry_t key;
    lbm_istream_entry_t * entry = NULL;
    guint32 keyval[LBM_ISTREAM_STREAM_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    memset((void *)&key, 0, sizeof(lbm_istream_entry_t));
    memcpy((void *)key.ctxinst_1, (void *)instance1, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
    memcpy((void *)key.ctxinst_2, (void *)instance2, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
    lbm_stream_order_istream_key(&key);
    lbm_istream_stream_build_key(keyval, tkey, &key);
    entry = (lbm_istream_entry_t *) wmem_tree_lookup32_array(instance_stream_table, tkey);
    return (entry);
}

static lbm_istream_entry_t * lbm_stream_istream_add(const guint8 * instance1, const guint8 * instance2)
{
    lbm_istream_entry_t * entry;
    guint32 keyval[LBM_ISTREAM_STREAM_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    entry = lbm_stream_istream_find(instance1, instance2);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbm_istream_entry_t);
    memcpy((void *)entry->ctxinst_1, (void *)instance1, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
    memcpy((void *)entry->ctxinst_2, (void *)instance2, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
    lbm_stream_order_istream_key(entry);
    entry->channel = lbm_channel_assign(LBM_CHANNEL_STREAM_TCP);
    entry->next_substream_id = 1;
    entry->first_frame = ~((guint32)0);
    entry->last_frame = 0;
    entry->messages = 0;
    entry->bytes = 0;
    entry->substream_list = wmem_tree_new(wmem_file_scope());
    lbm_istream_stream_build_key(keyval, tkey, entry);
    wmem_tree_insert32_array(instance_stream_table, tkey, (void *) entry);
    return (entry);
}

static void lbm_istream_substream_build_key(guint32 * key_value, wmem_tree_key_t * key, const lbm_istream_substream_entry_t * substream)
{
    guint32 val;

    /* Note: for the time being we only support IPv4 addresses (currently enforced in the dissectors), so
       assume it's an IPv4 address. memcpy to an intermediate value (don't know for sure the address.data field
       has any particular alignment) to prevent any alignment issues with assigning to a 32-bit unsigned int
       on certain platforms.
    */
    memcpy((void *) &val, (void *) substream->src_addr.data, sizeof(guint32));
    key_value[LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_SRC_ADDR] = val;
    key_value[LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_SRC_PORT] = (guint32) substream->src_port;
    memcpy((void *) &val, (void *) substream->dst_addr.data, sizeof(guint32));
    key_value[LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_DST_ADDR] = val;
    key_value[LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_DST_PORT] = (guint32) substream->dst_port;
    key_value[LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_LBM_STREAM_ID] = substream->lbm_stream_id;
    key[0].length = LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_COUNT;
    key[0].key = key_value;
    key[1].length = 0;
    key[1].key = NULL;
}

static lbm_istream_substream_entry_t * lbm_stream_istream_substream_find(lbm_istream_entry_t * stream, const address * src_addr, guint16 src_port, const address * dst_addr, guint16 dst_port, guint32 stream_id)
{
    lbm_istream_substream_entry_t key;
    lbm_istream_substream_entry_t * entry = NULL;
    guint32 keyval[LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    memset((void *)&key, 0, sizeof(lbm_istream_substream_entry_t));
    COPY_ADDRESS_SHALLOW(&(key.src_addr), src_addr);
    key.src_port = src_port;
    COPY_ADDRESS_SHALLOW(&(key.dst_addr), dst_addr);
    key.dst_port = dst_port;
    key.lbm_stream_id = stream_id;
    lbm_istream_substream_build_key(keyval, tkey, &key);
    entry = (lbm_istream_substream_entry_t *) wmem_tree_lookup32_array(stream->substream_list, tkey);
    return (entry);
}

static lbm_istream_substream_entry_t * lbm_stream_istream_substream_add(lbm_istream_entry_t * stream, const address * src_addr, guint16 src_port, const address * dst_addr, guint16 dst_port, guint32 stream_id)
{
    lbm_istream_substream_entry_t * entry;
    guint32 keyval[LBM_ISTREAM_SUBSTREAM_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    entry = lbm_stream_istream_substream_find(stream, src_addr, src_port, dst_addr, dst_port, stream_id);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbm_istream_substream_entry_t);
    SE_COPY_ADDRESS(&(entry->src_addr), src_addr);
    entry->src_port = src_port;
    SE_COPY_ADDRESS(&(entry->dst_addr), dst_addr);
    entry->dst_port = dst_port;
    entry->lbm_stream_id = stream_id;
    entry->parent = stream;
    entry->substream_id = stream->next_substream_id++;
    entry->first_frame = ~((guint32)0);
    entry->last_frame = 0;
    entry->messages = 0;
    entry->bytes = 0;
    lbm_istream_substream_build_key(keyval, tkey, entry);
    wmem_tree_insert32_array(stream->substream_list, tkey, (void *) entry);
    return (entry);
}

static void lbm_stream_istream_substream_update(lbm_istream_substream_entry_t * substream, guint16 length, guint32 frame)
{
    substream->messages++;
    substream->parent->messages++;
    substream->bytes += (guint32)length;
    substream->parent->bytes += (guint32)length;
    if (frame < substream->first_frame)
    {
        substream->first_frame = frame;
    }
    if (frame < substream->parent->first_frame)
    {
        substream->parent->first_frame = frame;
    }
    if (frame > substream->last_frame)
    {
        substream->last_frame = frame;
    }
    if (frame > substream->parent->last_frame)
    {
        substream->parent->last_frame = frame;
    }
}

static void lbm_dstream_stream_build_key(guint32 * key_value, wmem_tree_key_t * key, const lbm_dstream_entry_t * stream)
{
    guint32 val;

    /* Note: for the time being we only support IPv4 addresses (currently enforced in the dissectors), so
       assume it's an IPv4 address. memcpy to an intermediate value (don't know for sure the address.data field
       has any particular alignment) to prevent any alignment issues with assigning to a 32-bit unsigned int
       on certain platforms.
    */
    key_value[LBM_DSTREAM_STREAM_KEY_ELEMENT_DOMAIN_1] = stream->domain_1;
    memcpy((void *) &val, (void *) (stream->addr_1.data), sizeof(guint32));
    key_value[LBM_DSTREAM_STREAM_KEY_ELEMENT_ADDR_1] = val;
    key_value[LBM_DSTREAM_STREAM_KEY_ELEMENT_DOMAIN_2] = stream->domain_2;
    memcpy((void *) &val, (void *) (stream->addr_2.data), sizeof(guint32));
    key_value[LBM_DSTREAM_STREAM_KEY_ELEMENT_ADDR_2] = val;
    key_value[LBM_DSTREAM_STREAM_KEY_ELEMENT_PORT_1] = (guint32) stream->port_1;
    key_value[LBM_DSTREAM_STREAM_KEY_ELEMENT_PORT_2] = (guint32) stream->port_2;
    key[0].length = LBM_DSTREAM_STREAM_KEY_ELEMENT_COUNT;
    key[0].key = key_value;
    key[1].length = 0;
    key[1].key = NULL;
}

static void lbm_stream_order_dstream_key(lbm_dstream_entry_t * stream)
{
    gboolean swap_items = FALSE;
    address addr;
    guint32 domain;
    guint16 port;

    if (stream->domain_1 > stream->domain_2)
    {
        swap_items = TRUE;
    }
    else if (stream->domain_1 == stream->domain_2)
    {
        int compare;

        compare = CMP_ADDRESS(&(stream->addr_1), &(stream->addr_2));
        if (compare > 0)
        {
            swap_items = TRUE;
        }
        else if (compare == 0)
        {
            if (stream->port_1 > stream->port_2)
            {
                swap_items = TRUE;
            }
        }
    }
    if (swap_items)
    {
        domain = stream->domain_1;
        COPY_ADDRESS_SHALLOW(&addr, &(stream->addr_1));
        port = stream->port_1;

        stream->domain_1 = stream->domain_2;
        COPY_ADDRESS_SHALLOW(&(stream->addr_1), &(stream->addr_2));
        stream->port_1 = stream->port_2;

        stream->domain_2 = domain;
        COPY_ADDRESS_SHALLOW(&(stream->addr_2), &addr);
        stream->port_2 = port;
    }
}

static lbm_dstream_entry_t * lbm_stream_dstream_find(const lbm_uim_stream_destination_t * endpoint_a, const lbm_uim_stream_destination_t * endpoint_b)
{
    lbm_dstream_entry_t key;
    lbm_dstream_entry_t * entry = NULL;
    guint32 keyval[LBM_DSTREAM_STREAM_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    key.domain_1 = endpoint_a->domain;
    COPY_ADDRESS_SHALLOW(&(key.addr_1), &(endpoint_a->addr));
    key.port_1 = endpoint_a->port;
    key.domain_2 = endpoint_b->domain;
    COPY_ADDRESS_SHALLOW(&(key.addr_2), &(endpoint_b->addr));
    key.port_2 = endpoint_b->port;
    lbm_stream_order_dstream_key(&key);
    lbm_dstream_stream_build_key(keyval, tkey, &key);
    entry = (lbm_dstream_entry_t *) wmem_tree_lookup32_array(domain_stream_table, tkey);
    return (entry);
}

static lbm_dstream_entry_t * lbm_stream_dstream_add(const lbm_uim_stream_destination_t * endpoint_a, const lbm_uim_stream_destination_t * endpoint_b)
{
    lbm_dstream_entry_t * entry;
    guint32 keyval[LBM_DSTREAM_STREAM_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    entry = lbm_stream_dstream_find(endpoint_a, endpoint_b);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbm_dstream_entry_t);
    entry->domain_1 = endpoint_a->domain;
    SE_COPY_ADDRESS(&(entry->addr_1), &(endpoint_a->addr));
    entry->port_1 = endpoint_a->port;
    entry->domain_2 = endpoint_b->domain;
    SE_COPY_ADDRESS(&(entry->addr_2), &(endpoint_b->addr));
    entry->port_2 = endpoint_b->port;
    lbm_stream_order_dstream_key(entry);
    entry->channel = lbm_channel_assign(LBM_CHANNEL_STREAM_TCP);
    entry->next_substream_id = 1;
    entry->first_frame = ~((guint32)0);
    entry->last_frame = 0;
    entry->messages = 0;
    entry->bytes = 0;
    entry->substream_list = wmem_tree_new(wmem_file_scope());
    lbm_dstream_stream_build_key(keyval, tkey, entry);
    wmem_tree_insert32_array(domain_stream_table, tkey, (void *) entry);
    return (entry);
}

static void lbm_dstream_substream_build_key(guint32 * key_value, wmem_tree_key_t * key, const lbm_dstream_substream_entry_t * substream)
{
    guint32 val;

    /* Note: for the time being we only support IPv4 addresses (currently enforced in the dissectors), so
       assume it's an IPv4 address. memcpy to an intermediate value (don't know for sure the address.data field
       has any particular alignment) to prevent any alignment issues with assigning to a 32-bit unsigned int
       on certain platforms.
    */
    memcpy((void *) &val, (void *) substream->src_addr.data, sizeof(guint32));
    key_value[LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_SRC_ADDR] = val;
    key_value[LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_SRC_PORT] = (guint32) substream->src_port;
    memcpy((void *) &val, (void *) substream->dst_addr.data, sizeof(guint32));
    key_value[LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_DST_ADDR] = val;
    key_value[LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_DST_PORT] = (guint32) substream->dst_port;
    key_value[LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_LBM_STREAM_ID] = substream->lbm_stream_id;
    key[0].length = LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_COUNT;
    key[0].key = key_value;
    key[1].length = 0;
    key[1].key = NULL;
}

static lbm_dstream_substream_entry_t * lbm_stream_dstream_substream_find(lbm_dstream_entry_t * stream, const address * src_addr, guint16 src_port, const address * dst_addr, guint16 dst_port, guint32 stream_id)
{
    lbm_dstream_substream_entry_t key;
    lbm_dstream_substream_entry_t * entry = NULL;
    guint32 keyval[LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    memset((void *)&key, 0, sizeof(lbm_dstream_substream_entry_t));
    COPY_ADDRESS_SHALLOW(&(key.src_addr), src_addr);
    key.src_port = src_port;
    COPY_ADDRESS_SHALLOW(&(key.dst_addr), dst_addr);
    key.dst_port = dst_port;
    key.lbm_stream_id = stream_id;
    lbm_dstream_substream_build_key(keyval, tkey, &key);
    entry = (lbm_dstream_substream_entry_t *) wmem_tree_lookup32_array(stream->substream_list, tkey);
    return (entry);
}

static lbm_dstream_substream_entry_t * lbm_stream_dstream_substream_add(lbm_dstream_entry_t * stream, const address * src_addr, guint16 src_port, const address * dst_addr, guint16 dst_port, guint32 stream_id)
{
    lbm_dstream_substream_entry_t * entry;
    guint32 keyval[LBM_DSTREAM_SUBSTREAM_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    entry = lbm_stream_dstream_substream_find(stream, src_addr, src_port, dst_addr, dst_port, stream_id);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbm_dstream_substream_entry_t);
    SE_COPY_ADDRESS(&(entry->src_addr), src_addr);
    entry->src_port = src_port;
    SE_COPY_ADDRESS(&(entry->dst_addr), dst_addr);
    entry->dst_port = dst_port;
    entry->lbm_stream_id = stream_id;
    entry->parent = stream;
    entry->substream_id = stream->next_substream_id++;
    entry->first_frame = ~((guint32)0);
    entry->last_frame = 0;
    entry->messages = 0;
    entry->bytes = 0;
    lbm_dstream_substream_build_key(keyval, tkey, entry);
    wmem_tree_insert32_array(stream->substream_list, tkey, (void *) entry);
    return (entry);
}

static void lbm_stream_dstream_substream_update(lbm_dstream_substream_entry_t * substream, guint16 length, guint32 frame)
{
    substream->messages++;
    substream->parent->messages++;
    substream->bytes += (guint32)length;
    substream->parent->bytes += (guint32)length;
    if (frame < substream->first_frame)
    {
        substream->first_frame = frame;
    }
    if (frame < substream->parent->first_frame)
    {
        substream->parent->first_frame = frame;
    }
    if (frame > substream->last_frame)
    {
        substream->last_frame = frame;
    }
    if (frame > substream->parent->last_frame)
    {
        substream->parent->last_frame = frame;
    }
}

/*----------------------------------------------------------------------------*/
/* Packet layouts.                                                            */
/*----------------------------------------------------------------------------*/

/* LBMC header */
typedef struct
{
    lbm_uint8_t ver_type;
    lbm_uint8_t next_hdr;
    lbm_uint16_t msglen;
    lbm_uint32_t tidx;
    lbm_uint32_t sqn;
} lbmc_hdr_t;
#define O_LBMC_HDR_T_VER_TYPE OFFSETOF(lbmc_hdr_t, ver_type)
#define L_LBMC_HDR_T_VER_TYPE SIZEOF(lbmc_hdr_t, ver_type)
#define O_LBMC_HDR_T_NEXT_HDR OFFSETOF(lbmc_hdr_t, next_hdr)
#define L_LBMC_HDR_T_NEXT_HDR SIZEOF(lbmc_hdr_t, next_hdr)
#define O_LBMC_HDR_T_MSGLEN OFFSETOF(lbmc_hdr_t, msglen)
#define L_LBMC_HDR_T_MSGLEN SIZEOF(lbmc_hdr_t, msglen)
#define O_LBMC_HDR_T_TIDX OFFSETOF(lbmc_hdr_t, tidx)
#define L_LBMC_HDR_T_TIDX SIZEOF(lbmc_hdr_t, tidx)
#define O_LBMC_HDR_T_SQN OFFSETOF(lbmc_hdr_t, sqn)
#define L_LBMC_HDR_T_SQN SIZEOF(lbmc_hdr_t, sqn)
#define L_LBMC_HDR_T (gint) sizeof(lbmc_hdr_t)

/* LBMC control header */
typedef struct
{
    lbm_uint8_t ver_type;
    lbm_uint8_t next_hdr;
    lbm_uint16_t msglen;
} lbmc_cntl_hdr_t;
#define O_LBMC_CNTL_HDR_T_VER_TYPE OFFSETOF(lbmc_cntl_hdr_t, ver_type)
#define L_LBMC_CNTL_HDR_T_VER_TYPE SIZEOF(lbmc_cntl_hdr_t, ver_type)
#define O_LBMC_CNTL_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_hdr_t, next_hdr)
#define L_LBMC_CNTL_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_hdr_t, next_hdr)
#define O_LBMC_CNTL_HDR_T_MSGLEN OFFSETOF(lbmc_cntl_hdr_t, msglen)
#define L_LBMC_CNTL_HDR_T_MSGLEN SIZEOF(lbmc_cntl_hdr_t, msglen)
#define L_LBMC_CNTL_HDR_T (gint) sizeof(lbmc_cntl_hdr_t)

#define LBMC_HDR_VER_TYPE_VER_MASK 0xF0
#define LBMC_HDR_VER_TYPE_TYPE_MASK 0x0F

/* Minimal LBMC header */
typedef struct
{
    lbm_uint8_t ver_type;
    lbm_uint8_t next_hdr;
    lbm_uint16_t msglen;
} lbmc_minimal_hdr_t;
#define O_LBMC_MINIMAL_HDR_T_VER_TYPE OFFSETOF(lbmc_minimal_hdr_t, ver_type)
#define L_LBMC_MINIMAL_HDR_T_VER_TYPE SIZEOF(lbmc_minimal_hdr_t, ver_type)
#define O_LBMC_MINIMAL_HDR_T_NEXT_HDR OFFSETOF(lbmc_minimal_hdr_t, next_hdr)
#define L_LBMC_MINIMAL_HDR_T_NEXT_HDR SIZEOF(lbmc_minimal_hdr_t, next_hdr)
#define O_LBMC_MINIMAL_HDR_T_MSGLEN OFFSETOF(lbmc_minimal_hdr_t, msglen)
#define L_LBMC_MINIMAL_HDR_T_MSGLEN SIZEOF(lbmc_minimal_hdr_t, msglen)
#define L_LBMC_MINIMAL_HDR_T (gint) sizeof(lbmc_minimal_hdr_t)

#define LBMC_HDR_VER(x) (x >> 4)
#define LBMC_HDR_TYPE(x) (x & 0xF)

/* LBMC basic header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t res;
} lbmc_basic_hdr_t;
#define O_LBMC_BASIC_HDR_T_NEXT_HDR OFFSETOF(lbmc_basic_hdr_t, next_hdr)
#define L_LBMC_BASIC_HDR_T_NEXT_HDR SIZEOF(lbmc_basic_hdr_t, next_hdr)
#define O_LBMC_BASIC_HDR_T_HDR_LEN OFFSETOF(lbmc_basic_hdr_t, hdr_len)
#define L_LBMC_BASIC_HDR_T_HDR_LEN SIZEOF(lbmc_basic_hdr_t, hdr_len)
#define O_LBMC_BASIC_HDR_T_RES OFFSETOF(lbmc_basic_hdr_t, res)
#define L_LBMC_BASIC_HDR_T_RES SIZEOF(lbmc_basic_hdr_t, res)
#define L_LBMC_BASIC_HDR_T (gint) sizeof(lbmc_basic_hdr_t)

/* LBMC fragment header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t first_sqn;
    lbm_uint32_t offset;
    lbm_uint32_t len;
} lbmc_frag_hdr_t;
#define O_LBMC_FRAG_HDR_T_NEXT_HDR OFFSETOF(lbmc_frag_hdr_t, next_hdr)
#define L_LBMC_FRAG_HDR_T_NEXT_HDR SIZEOF(lbmc_frag_hdr_t, next_hdr)
#define O_LBMC_FRAG_HDR_T_HDR_LEN OFFSETOF(lbmc_frag_hdr_t, hdr_len)
#define L_LBMC_FRAG_HDR_T_HDR_LEN SIZEOF(lbmc_frag_hdr_t, hdr_len)
#define O_LBMC_FRAG_HDR_T_FLAGS OFFSETOF(lbmc_frag_hdr_t, flags)
#define L_LBMC_FRAG_HDR_T_FLAGS SIZEOF(lbmc_frag_hdr_t, flags)
#define O_LBMC_FRAG_HDR_T_FIRST_SQN OFFSETOF(lbmc_frag_hdr_t, first_sqn)
#define L_LBMC_FRAG_HDR_T_FIRST_SQN SIZEOF(lbmc_frag_hdr_t, first_sqn)
#define O_LBMC_FRAG_HDR_T_OFFSET OFFSETOF(lbmc_frag_hdr_t, offset)
#define L_LBMC_FRAG_HDR_T_OFFSET SIZEOF(lbmc_frag_hdr_t, offset)
#define O_LBMC_FRAG_HDR_T_LEN OFFSETOF(lbmc_frag_hdr_t, len)
#define L_LBMC_FRAG_HDR_T_LEN SIZEOF(lbmc_frag_hdr_t, len)
#define L_LBMC_FRAG_HDR_T (gint) sizeof(lbmc_frag_hdr_t)

/* LBMC batch header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
} lbmc_batch_hdr_t;
#define O_LBMC_BATCH_HDR_T_NEXT_HDR OFFSETOF(lbmc_batch_hdr_t, next_hdr)
#define L_LBMC_BATCH_HDR_T_NEXT_HDR SIZEOF(lbmc_batch_hdr_t, next_hdr)
#define O_LBMC_BATCH_HDR_T_HDR_LEN OFFSETOF(lbmc_batch_hdr_t, hdr_len)
#define L_LBMC_BATCH_HDR_T_HDR_LEN SIZEOF(lbmc_batch_hdr_t, hdr_len)
#define O_LBMC_BATCH_HDR_T_FLAGS OFFSETOF(lbmc_batch_hdr_t, flags)
#define L_LBMC_BATCH_HDR_T_FLAGS SIZEOF(lbmc_batch_hdr_t, flags)
#define L_LBMC_BATCH_HDR_T (gint) sizeof(lbmc_batch_hdr_t)

/* LBMC TCP request header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t res;
    lbm_uint8_t transport;
    lbm_uint32_t qidx;
    lbm_uint16_t port;
    lbm_uint16_t reserved;
    lbm_uint32_t ipaddr;
} lbmc_tcp_request_hdr_t;
#define O_LBMC_TCP_REQUEST_HDR_T_NEXT_HDR OFFSETOF(lbmc_tcp_request_hdr_t, next_hdr)
#define L_LBMC_TCP_REQUEST_HDR_T_NEXT_HDR SIZEOF(lbmc_tcp_request_hdr_t, next_hdr)
#define O_LBMC_TCP_REQUEST_HDR_T_HDR_LEN OFFSETOF(lbmc_tcp_request_hdr_t, hdr_len)
#define L_LBMC_TCP_REQUEST_HDR_T_HDR_LEN SIZEOF(lbmc_tcp_request_hdr_t, hdr_len)
#define O_LBMC_TCP_REQUEST_HDR_T_FLAGS OFFSETOF(lbmc_tcp_request_hdr_t, res)
#define L_LBMC_TCP_REQUEST_HDR_T_FLAGS SIZEOF(lbmc_tcp_request_hdr_t, res)
#define O_LBMC_TCP_REQUEST_HDR_T_TRANSPORT OFFSETOF(lbmc_tcp_request_hdr_t, transport)
#define L_LBMC_TCP_REQUEST_HDR_T_TRANSPORT SIZEOF(lbmc_tcp_request_hdr_t, transport)
#define O_LBMC_TCP_REQUEST_HDR_T_QIDX OFFSETOF(lbmc_tcp_request_hdr_t, qidx)
#define L_LBMC_TCP_REQUEST_HDR_T_QIDX SIZEOF(lbmc_tcp_request_hdr_t, qidx)
#define O_LBMC_TCP_REQUEST_HDR_T_PORT OFFSETOF(lbmc_tcp_request_hdr_t, port)
#define L_LBMC_TCP_REQUEST_HDR_T_PORT SIZEOF(lbmc_tcp_request_hdr_t, port)
#define O_LBMC_TCP_REQUEST_HDR_T_RESERVED OFFSETOF(lbmc_tcp_request_hdr_t, reserved)
#define L_LBMC_TCP_REQUEST_HDR_T_RESERVED SIZEOF(lbmc_tcp_request_hdr_t, reserved)
#define O_LBMC_TCP_REQUEST_HDR_T_IPADDR OFFSETOF(lbmc_tcp_request_hdr_t, ipaddr)
#define L_LBMC_TCP_REQUEST_HDR_T_IPADDR SIZEOF(lbmc_tcp_request_hdr_t, ipaddr)
#define L_LBMC_TCP_REQUEST_HDR_T (gint) sizeof(lbmc_tcp_request_hdr_t)

/* LBMC topicname header (an extension to lbmc_basic_hdr_t) */
#define O_LBMC_TOPICNAME_HDR_T_NEXT_HDR OFFSETOF(lbmc_basic_hdr_t, next_hdr)
#define L_LBMC_TOPICNAME_HDR_T_NEXT_HDR SIZEOF(lbmc_basic_hdr_t, next_hdr)
#define O_LBMC_TOPICNAME_HDR_T_HDR_LEN OFFSETOF(lbmc_basic_hdr_t, hdr_len)
#define L_LBMC_TOPICNAME_HDR_T_HDR_LEN SIZEOF(lbmc_basic_hdr_t, hdr_len)
#define O_LBMC_TOPICNAME_HDR_T_FLAGS OFFSETOF(lbmc_basic_hdr_t, res)
#define L_LBMC_TOPICNAME_HDR_T_FLAGS SIZEOF(lbmc_basic_hdr_t, res)
#define O_LBMC_TOPICNAME_HDR_T_TOPIC (OFFSETOF(lbmc_basic_hdr_t, res) + SIZEOF(lbmc_basic_hdr_t, res))

/* LBMC appheader header. */
#define O_LBMC_APPHDR_HDR_T_NEXT_HDR OFFSETOF(lbmc_basic_hdr_t, next_hdr)
#define L_LBMC_APPHDR_HDR_T_NEXT_HDR SIZEOF(lbmc_basic_hdr_t, next_hdr)
#define O_LBMC_APPHDR_HDR_T_HDR_LEN OFFSETOF(lbmc_basic_hdr_t, hdr_len)
#define L_LBMC_APPHDR_HDR_T_HDR_LEN SIZEOF(lbmc_basic_hdr_t, hdr_len)
#define O_LBMC_APPHDR_HDR_T_CODE OFFSETOF(lbmc_basic_hdr_t, res)
#define L_LBMC_APPHDR_HDR_T_CODE SIZEOF(lbmc_basic_hdr_t, res)
#define O_LBMC_APPHDR_HDR_T_DATA (OFFSETOF(lbmc_basic_hdr_t, res) + SIZEOF(lbmc_basic_hdr_t, res))

#define LBMC_APPHDR_CODE_MASK 0x7fff

/* LBMC appheader chain element */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t res;
} lbmc_apphdr_chain_element_t;
#define O_LBMC_APPHDR_CHAIN_ELEMENT_T_NEXT_HDR OFFSETOF(lbmc_apphdr_chain_element_t, next_hdr)
#define L_LBMC_APPHDR_CHAIN_ELEMENT_T_NEXT_HDR SIZEOF(lbmc_apphdr_chain_element_t, next_hdr)
#define O_LBMC_APPHDR_CHAIN_ELEMENT_T_HDR_LEN OFFSETOF(lbmc_apphdr_chain_element_t, hdr_len)
#define L_LBMC_APPHDR_CHAIN_ELEMENT_T_HDR_LEN SIZEOF(lbmc_apphdr_chain_element_t, hdr_len)
#define O_LBMC_APPHDR_CHAIN_ELEMENT_T_RES OFFSETOF(lbmc_apphdr_chain_element_t, res)
#define L_LBMC_APPHDR_CHAIN_ELEMENT_T_RES SIZEOF(lbmc_apphdr_chain_element_t, res)
#define L_LBMC_APPHDR_CHAIN_ELEMENT_T_MIN (gint) sizeof(lbmc_apphdr_chain_element_t)

/* LBMC appheader chain message properties element */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t res;
    lbm_uint32_t len;
} lbmc_apphdr_chain_msgprop_element_t;
#define O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_NEXT_HDR OFFSETOF(lbmc_apphdr_chain_msgprop_element_t, next_hdr)
#define L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_NEXT_HDR SIZEOF(lbmc_apphdr_chain_msgprop_element_t, next_hdr)
#define O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_HDR_LEN OFFSETOF(lbmc_apphdr_chain_msgprop_element_t, hdr_len)
#define L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_HDR_LEN SIZEOF(lbmc_apphdr_chain_msgprop_element_t, hdr_len)
#define O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_RES OFFSETOF(lbmc_apphdr_chain_msgprop_element_t, res)
#define L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_RES SIZEOF(lbmc_apphdr_chain_msgprop_element_t, res)
#define O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_LEN OFFSETOF(lbmc_apphdr_chain_msgprop_element_t, len)
#define L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_LEN SIZEOF(lbmc_apphdr_chain_msgprop_element_t, len)
#define L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T (gint) sizeof(lbmc_apphdr_chain_msgprop_element_t)

/* LBMC appheader chain header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t res;
    lbm_uint8_t first_chain_hdr;
} lbmc_apphdr_chain_hdr_t;
#define O_LBMC_APPHDR_CHAIN_HDR_T_NEXT_HDR OFFSETOF(lbmc_apphdr_chain_hdr_t, next_hdr)
#define L_LBMC_APPHDR_CHAIN_HDR_T_NEXT_HDR SIZEOF(lbmc_apphdr_chain_hdr_t, next_hdr)
#define O_LBMC_APPHDR_CHAIN_HDR_T_HDR_LEN OFFSETOF(lbmc_apphdr_chain_hdr_t, hdr_len)
#define L_LBMC_APPHDR_CHAIN_HDR_T_HDR_LEN SIZEOF(lbmc_apphdr_chain_hdr_t, hdr_len)
#define O_LBMC_APPHDR_CHAIN_HDR_T_RES OFFSETOF(lbmc_apphdr_chain_hdr_t, res)
#define L_LBMC_APPHDR_CHAIN_HDR_T_RES SIZEOF(lbmc_apphdr_chain_hdr_t, res)
#define O_LBMC_APPHDR_CHAIN_HDR_T_FIRST_CHAIN_HDR OFFSETOF(lbmc_apphdr_chain_hdr_t, first_chain_hdr)
#define L_LBMC_APPHDR_CHAIN_HDR_T_FIRST_CHAIN_HDR SIZEOF(lbmc_apphdr_chain_hdr_t, first_chain_hdr)
#define L_LBMC_APPHDR_CHAIN_HDR_T (gint) sizeof(lbmc_apphdr_chain_hdr_t)

/* LBMC UMQ Message ID header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint8_t msgid_regid[8];
    lbm_uint8_t msgid_stamp[8];
} lbmc_umq_msgid_hdr_t;
#define O_LBMC_UMQ_MSGID_HDR_T_NEXT_HDR OFFSETOF(lbmc_umq_msgid_hdr_t, next_hdr)
#define L_LBMC_UMQ_MSGID_HDR_T_NEXT_HDR SIZEOF(lbmc_umq_msgid_hdr_t, next_hdr)
#define O_LBMC_UMQ_MSGID_HDR_T_HDR_LEN OFFSETOF(lbmc_umq_msgid_hdr_t, hdr_len)
#define L_LBMC_UMQ_MSGID_HDR_T_HDR_LEN SIZEOF(lbmc_umq_msgid_hdr_t, hdr_len)
#define O_LBMC_UMQ_MSGID_HDR_T_FLAGS OFFSETOF(lbmc_umq_msgid_hdr_t, flags)
#define L_LBMC_UMQ_MSGID_HDR_T_FLAGS SIZEOF(lbmc_umq_msgid_hdr_t, flags)
#define O_LBMC_UMQ_MSGID_HDR_T_MSGID_REGID OFFSETOF(lbmc_umq_msgid_hdr_t, msgid_regid)
#define L_LBMC_UMQ_MSGID_HDR_T_MSGID_REGID SIZEOF(lbmc_umq_msgid_hdr_t, msgid_regid)
#define O_LBMC_UMQ_MSGID_HDR_T_MSGID_STAMP OFFSETOF(lbmc_umq_msgid_hdr_t, msgid_stamp)
#define L_LBMC_UMQ_MSGID_HDR_T_MSGID_STAMP SIZEOF(lbmc_umq_msgid_hdr_t, msgid_stamp)
#define L_LBMC_UMQ_MSGID_HDR_T (gint) sizeof(lbmc_umq_msgid_hdr_t)

/* LBMC UMQ SQD receive header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t queue_id;
    lbm_uint32_t queue_ver;
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_umq_sqd_rcv_hdr_t;
#define O_LBMC_UMQ_SQD_RCV_HDR_T_NEXT_HDR OFFSETOF(lbmc_umq_sqd_rcv_hdr_t, next_hdr)
#define L_LBMC_UMQ_SQD_RCV_HDR_T_NEXT_HDR SIZEOF(lbmc_umq_sqd_rcv_hdr_t, next_hdr)
#define O_LBMC_UMQ_SQD_RCV_HDR_T_HDR_LEN OFFSETOF(lbmc_umq_sqd_rcv_hdr_t, hdr_len)
#define L_LBMC_UMQ_SQD_RCV_HDR_T_HDR_LEN SIZEOF(lbmc_umq_sqd_rcv_hdr_t, hdr_len)
#define O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS OFFSETOF(lbmc_umq_sqd_rcv_hdr_t, flags)
#define L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS SIZEOF(lbmc_umq_sqd_rcv_hdr_t, flags)
#define O_LBMC_UMQ_SQD_RCV_HDR_T_QUEUE_ID OFFSETOF(lbmc_umq_sqd_rcv_hdr_t, queue_id)
#define L_LBMC_UMQ_SQD_RCV_HDR_T_QUEUE_ID SIZEOF(lbmc_umq_sqd_rcv_hdr_t, queue_id)
#define O_LBMC_UMQ_SQD_RCV_HDR_T_QUEUE_VER OFFSETOF(lbmc_umq_sqd_rcv_hdr_t, queue_ver)
#define L_LBMC_UMQ_SQD_RCV_HDR_T_QUEUE_VER SIZEOF(lbmc_umq_sqd_rcv_hdr_t, queue_ver)
#define O_LBMC_UMQ_SQD_RCV_HDR_T_RCR_IDX OFFSETOF(lbmc_umq_sqd_rcv_hdr_t, rcr_idx)
#define L_LBMC_UMQ_SQD_RCV_HDR_T_RCR_IDX SIZEOF(lbmc_umq_sqd_rcv_hdr_t, rcr_idx)
#define O_LBMC_UMQ_SQD_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_umq_sqd_rcv_hdr_t, assign_id)
#define L_LBMC_UMQ_SQD_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_umq_sqd_rcv_hdr_t, assign_id)
#define L_LBMC_UMQ_SQD_RCV_HDR_T (gint) sizeof(lbmc_umq_sqd_rcv_hdr_t)

/* LBMC UMQ resubmission header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t rcr_idx;
    lbm_uint32_t resp_ip;
    lbm_uint16_t resp_port;
    lbm_uint16_t appset_idx;
} lbmc_umq_resub_hdr_t;
#define O_LBMC_UMQ_RESUB_HDR_T_NEXT_HDR OFFSETOF(lbmc_umq_resub_hdr_t, next_hdr)
#define L_LBMC_UMQ_RESUB_HDR_T_NEXT_HDR SIZEOF(lbmc_umq_resub_hdr_t, next_hdr)
#define O_LBMC_UMQ_RESUB_HDR_T_HDR_LEN OFFSETOF(lbmc_umq_resub_hdr_t, hdr_len)
#define L_LBMC_UMQ_RESUB_HDR_T_HDR_LEN SIZEOF(lbmc_umq_resub_hdr_t, hdr_len)
#define O_LBMC_UMQ_RESUB_HDR_T_FLAGS OFFSETOF(lbmc_umq_resub_hdr_t, flags)
#define L_LBMC_UMQ_RESUB_HDR_T_FLAGS SIZEOF(lbmc_umq_resub_hdr_t, flags)
#define O_LBMC_UMQ_RESUB_HDR_T_RCR_IDX OFFSETOF(lbmc_umq_resub_hdr_t, rcr_idx)
#define L_LBMC_UMQ_RESUB_HDR_T_RCR_IDX SIZEOF(lbmc_umq_resub_hdr_t, rcr_idx)
#define O_LBMC_UMQ_RESUB_HDR_T_RESP_IP OFFSETOF(lbmc_umq_resub_hdr_t, resp_ip)
#define L_LBMC_UMQ_RESUB_HDR_T_RESP_IP SIZEOF(lbmc_umq_resub_hdr_t, resp_ip)
#define O_LBMC_UMQ_RESUB_HDR_T_RESP_PORT OFFSETOF(lbmc_umq_resub_hdr_t, resp_port)
#define L_LBMC_UMQ_RESUB_HDR_T_RESP_PORT SIZEOF(lbmc_umq_resub_hdr_t, resp_port)
#define O_LBMC_UMQ_RESUB_HDR_T_APPSET_IDX OFFSETOF(lbmc_umq_resub_hdr_t, appset_idx)
#define L_LBMC_UMQ_RESUB_HDR_T_APPSET_IDX SIZEOF(lbmc_umq_resub_hdr_t, appset_idx)
#define L_LBMC_UMQ_RESUB_HDR_T (gint) sizeof(lbmc_umq_resub_hdr_t)

/* LBMC originating transport ID header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint8_t otid[LBM_OTID_BLOCK_SZ];
} lbmc_otid_hdr_t;
#define O_LBMC_OTID_HDR_T_NEXT_HDR OFFSETOF(lbmc_otid_hdr_t, next_hdr)
#define L_LBMC_OTID_HDR_T_NEXT_HDR SIZEOF(lbmc_otid_hdr_t, next_hdr)
#define O_LBMC_OTID_HDR_T_HDR_LEN OFFSETOF(lbmc_otid_hdr_t, hdr_len)
#define L_LBMC_OTID_HDR_T_HDR_LEN SIZEOF(lbmc_otid_hdr_t, hdr_len)
#define O_LBMC_OTID_HDR_T_FLAGS OFFSETOF(lbmc_otid_hdr_t, flags)
#define L_LBMC_OTID_HDR_T_FLAGS SIZEOF(lbmc_otid_hdr_t, flags)
#define O_LBMC_OTID_HDR_T_OTID OFFSETOF(lbmc_otid_hdr_t, otid)
#define L_LBMC_OTID_HDR_T_OTID SIZEOF(lbmc_otid_hdr_t, otid)
#define L_LBMC_OTID_HDR_T (gint) sizeof(lbmc_otid_hdr_t)

/* LBMC context instance header(s) */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint8_t ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbmc_ctxinst_hdr_t;
#define O_LBMC_CTXINST_HDR_T_NEXT_HDR OFFSETOF(lbmc_ctxinst_hdr_t, next_hdr)
#define L_LBMC_CTXINST_HDR_T_NEXT_HDR SIZEOF(lbmc_ctxinst_hdr_t, next_hdr)
#define O_LBMC_CTXINST_HDR_T_HDR_LEN OFFSETOF(lbmc_ctxinst_hdr_t, hdr_len)
#define L_LBMC_CTXINST_HDR_T_HDR_LEN SIZEOF(lbmc_ctxinst_hdr_t, hdr_len)
#define O_LBMC_CTXINST_HDR_T_FLAGS OFFSETOF(lbmc_ctxinst_hdr_t, flags)
#define L_LBMC_CTXINST_HDR_T_FLAGS SIZEOF(lbmc_ctxinst_hdr_t, flags)
#define O_LBMC_CTXINST_HDR_T_CTXINST OFFSETOF(lbmc_ctxinst_hdr_t, ctxinst)
#define L_LBMC_CTXINST_HDR_T_CTXINST SIZEOF(lbmc_ctxinst_hdr_t, ctxinst)
#define L_LBMC_CTXINST_HDR_T (gint) sizeof(lbmc_ctxinst_hdr_t)

/* LBMC source index header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    char srcidx[8];
} lbmc_srcidx_hdr_t;
#define O_LBMC_SRCIDX_HDR_T_NEXT_HDR OFFSETOF(lbmc_srcidx_hdr_t, next_hdr)
#define L_LBMC_SRCIDX_HDR_T_NEXT_HDR SIZEOF(lbmc_srcidx_hdr_t, next_hdr)
#define O_LBMC_SRCIDX_HDR_T_HDR_LEN OFFSETOF(lbmc_srcidx_hdr_t, hdr_len)
#define L_LBMC_SRCIDX_HDR_T_HDR_LEN SIZEOF(lbmc_srcidx_hdr_t, hdr_len)
#define O_LBMC_SRCIDX_HDR_T_FLAGS OFFSETOF(lbmc_srcidx_hdr_t, flags)
#define L_LBMC_SRCIDX_HDR_T_FLAGS SIZEOF(lbmc_srcidx_hdr_t, flags)
#define O_LBMC_SRCIDX_HDR_T_SRCIDX OFFSETOF(lbmc_srcidx_hdr_t, srcidx)
#define L_LBMC_SRCIDX_HDR_T_SRCIDX SIZEOF(lbmc_srcidx_hdr_t, srcidx)
#define L_LBMC_SRCIDX_HDR_T (gint) sizeof(lbmc_srcidx_hdr_t)

/* LBMC UMQ ULB message header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t queue_id;
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t num_ras;
} lbmc_umq_ulb_msg_hdr_t;
#define O_LBMC_UMQ_ULB_MSG_HDR_T_NEXT_HDR OFFSETOF(lbmc_umq_ulb_msg_hdr_t, next_hdr)
#define L_LBMC_UMQ_ULB_MSG_HDR_T_NEXT_HDR SIZEOF(lbmc_umq_ulb_msg_hdr_t, next_hdr)
#define O_LBMC_UMQ_ULB_MSG_HDR_T_HDR_LEN OFFSETOF(lbmc_umq_ulb_msg_hdr_t, hdr_len)
#define L_LBMC_UMQ_ULB_MSG_HDR_T_HDR_LEN SIZEOF(lbmc_umq_ulb_msg_hdr_t, hdr_len)
#define O_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS OFFSETOF(lbmc_umq_ulb_msg_hdr_t, flags)
#define L_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS SIZEOF(lbmc_umq_ulb_msg_hdr_t, flags)
#define O_LBMC_UMQ_ULB_MSG_HDR_T_QUEUE_ID OFFSETOF(lbmc_umq_ulb_msg_hdr_t, queue_id)
#define L_LBMC_UMQ_ULB_MSG_HDR_T_QUEUE_ID SIZEOF(lbmc_umq_ulb_msg_hdr_t, queue_id)
#define O_LBMC_UMQ_ULB_MSG_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_umq_ulb_msg_hdr_t, ulb_src_id)
#define L_LBMC_UMQ_ULB_MSG_HDR_T_ULB_SRC_ID SIZEOF(lbmc_umq_ulb_msg_hdr_t, ulb_src_id)
#define O_LBMC_UMQ_ULB_MSG_HDR_T_ASSIGN_ID OFFSETOF(lbmc_umq_ulb_msg_hdr_t, assign_id)
#define L_LBMC_UMQ_ULB_MSG_HDR_T_ASSIGN_ID SIZEOF(lbmc_umq_ulb_msg_hdr_t, assign_id)
#define O_LBMC_UMQ_ULB_MSG_HDR_T_APPSET_IDX OFFSETOF(lbmc_umq_ulb_msg_hdr_t, appset_idx)
#define L_LBMC_UMQ_ULB_MSG_HDR_T_APPSET_IDX SIZEOF(lbmc_umq_ulb_msg_hdr_t, appset_idx)
#define O_LBMC_UMQ_ULB_MSG_HDR_T_NUM_RAS OFFSETOF(lbmc_umq_ulb_msg_hdr_t, num_ras)
#define L_LBMC_UMQ_ULB_MSG_HDR_T_NUM_RAS SIZEOF(lbmc_umq_ulb_msg_hdr_t, num_ras)
#define L_LBMC_UMQ_ULB_MSG_HDR_T (gint) sizeof(lbmc_umq_ulb_msg_hdr_t)

/* LBMC control source-side filtering initialization header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t transport;
    lbm_uint32_t transport_idx;
    lbm_uint32_t client_idx;
    lbm_uint16_t ssf_port;
    lbm_uint16_t res;
    lbm_uint32_t ssf_ip;
} lbmc_cntl_ssf_init_hdr_t;
#define O_LBMC_CNTL_SSF_INIT_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ssf_init_hdr_t, next_hdr)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ssf_init_hdr_t, next_hdr)
#define O_LBMC_CNTL_SSF_INIT_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ssf_init_hdr_t, hdr_len)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ssf_init_hdr_t, hdr_len)
#define O_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ssf_init_hdr_t, flags)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS SIZEOF(lbmc_cntl_ssf_init_hdr_t, flags)
#define O_LBMC_CNTL_SSF_INIT_HDR_T_TRANSPORT OFFSETOF(lbmc_cntl_ssf_init_hdr_t, transport)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_TRANSPORT SIZEOF(lbmc_cntl_ssf_init_hdr_t, transport)
#define O_LBMC_CNTL_SSF_INIT_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_ssf_init_hdr_t, transport_idx)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_ssf_init_hdr_t, transport_idx)
#define O_LBMC_CNTL_SSF_INIT_HDR_T_CLIENT_IDX OFFSETOF(lbmc_cntl_ssf_init_hdr_t, client_idx)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_CLIENT_IDX SIZEOF(lbmc_cntl_ssf_init_hdr_t, client_idx)
#define O_LBMC_CNTL_SSF_INIT_HDR_T_SSF_PORT OFFSETOF(lbmc_cntl_ssf_init_hdr_t, ssf_port)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_SSF_PORT SIZEOF(lbmc_cntl_ssf_init_hdr_t, ssf_port)
#define O_LBMC_CNTL_SSF_INIT_HDR_T_RES OFFSETOF(lbmc_cntl_ssf_init_hdr_t, res)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_RES SIZEOF(lbmc_cntl_ssf_init_hdr_t, res)
#define O_LBMC_CNTL_SSF_INIT_HDR_T_SSF_IP OFFSETOF(lbmc_cntl_ssf_init_hdr_t, ssf_ip)
#define L_LBMC_CNTL_SSF_INIT_HDR_T_SSF_IP SIZEOF(lbmc_cntl_ssf_init_hdr_t, ssf_ip)
#define L_LBMC_CNTL_SSF_INIT_HDR_T (gint) sizeof(lbmc_cntl_ssf_init_hdr_t)

/* LBMC control source-side filtering control request header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t res;
    lbm_uint8_t mode;
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
    lbm_uint32_t client_idx;
} lbmc_cntl_ssf_creq_hdr_t;
#define O_LBMC_CNTL_SSF_CREQ_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ssf_creq_hdr_t, next_hdr)
#define L_LBMC_CNTL_SSF_CREQ_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ssf_creq_hdr_t, next_hdr)
#define O_LBMC_CNTL_SSF_CREQ_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ssf_creq_hdr_t, hdr_len)
#define L_LBMC_CNTL_SSF_CREQ_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ssf_creq_hdr_t, hdr_len)
#define O_LBMC_CNTL_SSF_CREQ_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ssf_creq_hdr_t, res)
#define L_LBMC_CNTL_SSF_CREQ_HDR_T_FLAGS SIZEOF(lbmc_cntl_ssf_creq_hdr_t, res)
#define O_LBMC_CNTL_SSF_CREQ_HDR_T_MODE OFFSETOF(lbmc_cntl_ssf_creq_hdr_t, mode)
#define L_LBMC_CNTL_SSF_CREQ_HDR_T_MODE SIZEOF(lbmc_cntl_ssf_creq_hdr_t, mode)
#define O_LBMC_CNTL_SSF_CREQ_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_ssf_creq_hdr_t, transport_idx)
#define L_LBMC_CNTL_SSF_CREQ_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_ssf_creq_hdr_t, transport_idx)
#define O_LBMC_CNTL_SSF_CREQ_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_ssf_creq_hdr_t, topic_idx)
#define L_LBMC_CNTL_SSF_CREQ_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_ssf_creq_hdr_t, topic_idx)
#define O_LBMC_CNTL_SSF_CREQ_HDR_T_CLIENT_IDX OFFSETOF(lbmc_cntl_ssf_creq_hdr_t, client_idx)
#define L_LBMC_CNTL_SSF_CREQ_HDR_T_CLIENT_IDX SIZEOF(lbmc_cntl_ssf_creq_hdr_t, client_idx)
#define L_LBMC_CNTL_SSF_CREQ_HDR_T (gint) sizeof(lbmc_cntl_ssf_creq_hdr_t)

/* LBMC control UME presistent registration header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t marker;
    lbm_uint32_t reg_id;
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
    lbm_uint32_t src_reg_id;
    lbm_uint16_t resp_port;
    lbm_uint16_t res2;
    lbm_uint32_t resp_ip;
} lbmc_cntl_ume_preg_hdr_t;
#define O_LBMC_CNTL_UME_PREG_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_preg_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_PREG_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_preg_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_PREG_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_preg_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_PREG_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_preg_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_PREG_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_preg_hdr_t, flags)
#define L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_preg_hdr_t, flags)
#define O_LBMC_CNTL_UME_PREG_HDR_T_MARKER OFFSETOF(lbmc_cntl_ume_preg_hdr_t, marker)
#define L_LBMC_CNTL_UME_PREG_HDR_T_MARKER SIZEOF(lbmc_cntl_ume_preg_hdr_t, marker)
#define O_LBMC_CNTL_UME_PREG_HDR_T_REG_ID OFFSETOF(lbmc_cntl_ume_preg_hdr_t, reg_id)
#define L_LBMC_CNTL_UME_PREG_HDR_T_REG_ID SIZEOF(lbmc_cntl_ume_preg_hdr_t, reg_id)
#define O_LBMC_CNTL_UME_PREG_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_ume_preg_hdr_t, transport_idx)
#define L_LBMC_CNTL_UME_PREG_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_ume_preg_hdr_t, transport_idx)
#define O_LBMC_CNTL_UME_PREG_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_ume_preg_hdr_t, topic_idx)
#define L_LBMC_CNTL_UME_PREG_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_ume_preg_hdr_t, topic_idx)
#define O_LBMC_CNTL_UME_PREG_HDR_T_SRC_REG_ID OFFSETOF(lbmc_cntl_ume_preg_hdr_t, src_reg_id)
#define L_LBMC_CNTL_UME_PREG_HDR_T_SRC_REG_ID SIZEOF(lbmc_cntl_ume_preg_hdr_t, src_reg_id)
#define O_LBMC_CNTL_UME_PREG_HDR_T_RESP_PORT OFFSETOF(lbmc_cntl_ume_preg_hdr_t, resp_port)
#define L_LBMC_CNTL_UME_PREG_HDR_T_RESP_PORT SIZEOF(lbmc_cntl_ume_preg_hdr_t, resp_port)
#define O_LBMC_CNTL_UME_PREG_HDR_T_RES2 OFFSETOF(lbmc_cntl_ume_preg_hdr_t, res2)
#define L_LBMC_CNTL_UME_PREG_HDR_T_RES2 SIZEOF(lbmc_cntl_ume_preg_hdr_t, res2)
#define O_LBMC_CNTL_UME_PREG_HDR_T_RESP_IP OFFSETOF(lbmc_cntl_ume_preg_hdr_t, resp_ip)
#define L_LBMC_CNTL_UME_PREG_HDR_T_RESP_IP SIZEOF(lbmc_cntl_ume_preg_hdr_t, resp_ip)
#define L_LBMC_CNTL_UME_PREG_HDR_T (gint) sizeof(lbmc_cntl_ume_preg_hdr_t)

#define LBMC_CNTL_UME_PREG_MARKER(x) (x & 0x7F)
#define LBMC_CNTL_UME_PREG_MARKER_MASK 0x7F

/* LBMC control UME persistent registration response header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t code;
    lbm_uint8_t marker;
    lbm_uint32_t reg_id;
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
    lbm_uint32_t low_seqnum;
    lbm_uint32_t high_seqnum;
} lbmc_cntl_ume_preg_resp_hdr_t;
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, code)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, code)
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, marker)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, marker)
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_REG_ID OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, reg_id)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_REG_ID SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, reg_id)
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, transport_idx)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, transport_idx)
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, topic_idx)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, topic_idx)
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_LOW_SEQNUM OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, low_seqnum)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_LOW_SEQNUM SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, low_seqnum)
#define O_LBMC_CNTL_UME_PREG_RESP_HDR_T_HIGH_SEQNUM OFFSETOF(lbmc_cntl_ume_preg_resp_hdr_t, high_seqnum)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T_HIGH_SEQNUM SIZEOF(lbmc_cntl_ume_preg_resp_hdr_t, high_seqnum)
#define L_LBMC_CNTL_UME_PREG_RESP_HDR_T (gint) sizeof(lbmc_cntl_ume_preg_resp_hdr_t)

#define LBMC_CNTL_UME_PREG_RESP_CODE(x) (x & 0x0F)
#define LBMC_CNTL_UME_PREG_RESP_CODE_MASK 0x0F

/* LBMC control UME acknowledgement header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t type;
    lbm_uint32_t transport_idx;
    lbm_uint32_t id_2;
    lbm_uint32_t rcv_reg_id;
    lbm_uint32_t seqnum;
} lbmc_cntl_ume_ack_hdr_t;
#define O_LBMC_CNTL_UME_ACK_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_ack_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_ACK_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_ack_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_ACK_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_ack_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_ACK_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_ack_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_ACK_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_ack_hdr_t, flags)
#define L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_ack_hdr_t, flags)
#define O_LBMC_CNTL_UME_ACK_HDR_T_TYPE OFFSETOF(lbmc_cntl_ume_ack_hdr_t, type)
#define L_LBMC_CNTL_UME_ACK_HDR_T_TYPE SIZEOF(lbmc_cntl_ume_ack_hdr_t, type)
#define O_LBMC_CNTL_UME_ACK_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_ume_ack_hdr_t, transport_idx)
#define L_LBMC_CNTL_UME_ACK_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_ume_ack_hdr_t, transport_idx)
#define O_LBMC_CNTL_UME_ACK_HDR_T_ID_2 OFFSETOF(lbmc_cntl_ume_ack_hdr_t, id_2)
#define L_LBMC_CNTL_UME_ACK_HDR_T_ID_2 SIZEOF(lbmc_cntl_ume_ack_hdr_t, id_2)
#define O_LBMC_CNTL_UME_ACK_HDR_T_RCV_REG_ID OFFSETOF(lbmc_cntl_ume_ack_hdr_t, rcv_reg_id)
#define L_LBMC_CNTL_UME_ACK_HDR_T_RCV_REG_ID SIZEOF(lbmc_cntl_ume_ack_hdr_t, rcv_reg_id)
#define O_LBMC_CNTL_UME_ACK_HDR_T_SEQNUM OFFSETOF(lbmc_cntl_ume_ack_hdr_t, seqnum)
#define L_LBMC_CNTL_UME_ACK_HDR_T_SEQNUM SIZEOF(lbmc_cntl_ume_ack_hdr_t, seqnum)
#define L_LBMC_CNTL_UME_ACK_HDR_T (gint) sizeof(lbmc_cntl_ume_ack_hdr_t)

/* LBMC control UME ranged acknowledgement header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t first_seqnum;
    lbm_uint32_t last_seqnum;
} lbmc_cntl_ume_ranged_ack_hdr_t;
#define O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_ranged_ack_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_ranged_ack_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_ranged_ack_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_ranged_ack_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_ranged_ack_hdr_t, flags)
#define L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_ranged_ack_hdr_t, flags)
#define O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FIRST_SEQNUM OFFSETOF(lbmc_cntl_ume_ranged_ack_hdr_t, first_seqnum)
#define L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FIRST_SEQNUM SIZEOF(lbmc_cntl_ume_ranged_ack_hdr_t, first_seqnum)
#define O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_LAST_SEQNUM OFFSETOF(lbmc_cntl_ume_ranged_ack_hdr_t, last_seqnum)
#define L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_LAST_SEQNUM SIZEOF(lbmc_cntl_ume_ranged_ack_hdr_t, last_seqnum)
#define L_LBMC_CNTL_UME_RANGED_ACK_HDR_T (gint) sizeof(lbmc_cntl_ume_ranged_ack_hdr_t)

/* LBMC control UME acknowledgement ID header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t id;
} lbmc_cntl_ume_ack_id_hdr_t;
#define O_LBMC_CNTL_UME_ACK_ID_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_ack_id_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_ACK_ID_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_ack_id_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_ACK_ID_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_ack_id_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_ACK_ID_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_ack_id_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_ACK_ID_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_ack_id_hdr_t, flags)
#define L_LBMC_CNTL_UME_ACK_ID_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_ack_id_hdr_t, flags)
#define O_LBMC_CNTL_UME_ACK_ID_HDR_T_ID OFFSETOF(lbmc_cntl_ume_ack_id_hdr_t, id)
#define L_LBMC_CNTL_UME_ACK_ID_HDR_T_ID SIZEOF(lbmc_cntl_ume_ack_id_hdr_t, id)
#define L_LBMC_CNTL_UME_ACK_ID_HDR_T (gint) sizeof(lbmc_cntl_ume_ack_id_hdr_t)

/* LBMC control UME retransmision request header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t request_idx;
    lbm_uint32_t transport_idx;
    lbm_uint32_t id_2;
    lbm_uint32_t seqnum;
    lbm_uint16_t rx_port;
    lbm_uint16_t res;
    lbm_uint32_t rx_ip;
} lbmc_cntl_ume_rxreq_hdr_t;
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, flags)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, flags)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_REQUEST_IDX OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, request_idx)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_REQUEST_IDX SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, request_idx)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, transport_idx)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, transport_idx)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_ID_2 OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, id_2)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_ID_2 SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, id_2)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_SEQNUM OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, seqnum)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_SEQNUM SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, seqnum)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_RX_PORT OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, rx_port)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_RX_PORT SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, rx_port)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_RES OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, res)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_RES SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, res)
#define O_LBMC_CNTL_UME_RXREQ_HDR_T_RX_IP OFFSETOF(lbmc_cntl_ume_rxreq_hdr_t, rx_ip)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T_RX_IP SIZEOF(lbmc_cntl_ume_rxreq_hdr_t, rx_ip)
#define L_LBMC_CNTL_UME_RXREQ_HDR_T (gint) sizeof(lbmc_cntl_ume_rxreq_hdr_t)

/* LBMC control late join initiation request */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t request_idx;
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
    lbm_uint32_t req_ip;
    lbm_uint16_t req_port;
    lbm_uint16_t res;
    lbm_uint32_t tx_low_sqn;
    lbm_uint32_t rx_req_max;
    lbm_uint32_t rx_req_outstanding_max;
} lbmc_cntl_lji_req_hdr_t;
#define O_LBMC_CNTL_LJI_REQ_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_lji_req_hdr_t, next_hdr)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_lji_req_hdr_t, next_hdr)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_lji_req_hdr_t, hdr_len)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_lji_req_hdr_t, hdr_len)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS OFFSETOF(lbmc_cntl_lji_req_hdr_t, flags)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS SIZEOF(lbmc_cntl_lji_req_hdr_t, flags)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_REQUEST_IDX OFFSETOF(lbmc_cntl_lji_req_hdr_t, request_idx)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_REQUEST_IDX SIZEOF(lbmc_cntl_lji_req_hdr_t, request_idx)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_lji_req_hdr_t, transport_idx)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_lji_req_hdr_t, transport_idx)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_lji_req_hdr_t, topic_idx)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_lji_req_hdr_t, topic_idx)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_REQ_IP OFFSETOF(lbmc_cntl_lji_req_hdr_t, req_ip)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_REQ_IP SIZEOF(lbmc_cntl_lji_req_hdr_t, req_ip)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_REQ_PORT OFFSETOF(lbmc_cntl_lji_req_hdr_t, req_port)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_REQ_PORT SIZEOF(lbmc_cntl_lji_req_hdr_t, req_port)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_RES OFFSETOF(lbmc_cntl_lji_req_hdr_t, res)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_RES SIZEOF(lbmc_cntl_lji_req_hdr_t, res)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_TX_LOW_SQN OFFSETOF(lbmc_cntl_lji_req_hdr_t, tx_low_sqn)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_TX_LOW_SQN SIZEOF(lbmc_cntl_lji_req_hdr_t, tx_low_sqn)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_RX_REQ_MAX OFFSETOF(lbmc_cntl_lji_req_hdr_t, rx_req_max)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_RX_REQ_MAX SIZEOF(lbmc_cntl_lji_req_hdr_t, rx_req_max)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_RX_REQ_OUTSTANDING_MAX OFFSETOF(lbmc_cntl_lji_req_hdr_t, rx_req_outstanding_max)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_RX_REQ_OUTSTANDING_MAX SIZEOF(lbmc_cntl_lji_req_hdr_t, rx_req_outstanding_max)
#define O_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS OFFSETOF(lbmc_cntl_lji_req_hdr_t, flags)
#define L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS SIZEOF(lbmc_cntl_lji_req_hdr_t, flags)
#define L_LBMC_CNTL_LJI_REQ_HDR_T (gint) sizeof(lbmc_cntl_lji_req_hdr_t)

/* LBMC control UME keepalive header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t type;
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
    lbm_uint32_t reg_id;
} lbmc_cntl_ume_keepalive_hdr_t;
#define O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_keepalive_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_keepalive_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_keepalive_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_keepalive_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_keepalive_hdr_t, flags)
#define L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_keepalive_hdr_t, flags)
#define O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TYPE OFFSETOF(lbmc_cntl_ume_keepalive_hdr_t, type)
#define L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TYPE SIZEOF(lbmc_cntl_ume_keepalive_hdr_t, type)
#define O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_ume_keepalive_hdr_t, transport_idx)
#define L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_ume_keepalive_hdr_t, transport_idx)
#define O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_ume_keepalive_hdr_t, topic_idx)
#define L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_ume_keepalive_hdr_t, topic_idx)
#define O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_REG_ID OFFSETOF(lbmc_cntl_ume_keepalive_hdr_t, reg_id)
#define L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_REG_ID SIZEOF(lbmc_cntl_ume_keepalive_hdr_t, reg_id)
#define L_LBMC_CNTL_UME_KEEPALIVE_HDR_T (gint) sizeof(lbmc_cntl_ume_keepalive_hdr_t)

/* LBMC control UME store ID header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t store_id;
} lbmc_cntl_ume_storeid_hdr_t;
#define O_LBMC_CNTL_UME_STOREID_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_storeid_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_STOREID_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_storeid_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_STOREID_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_storeid_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_STOREID_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_storeid_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID OFFSETOF(lbmc_cntl_ume_storeid_hdr_t, store_id)
#define L_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID SIZEOF(lbmc_cntl_ume_storeid_hdr_t, store_id)
#define L_LBMC_CNTL_UME_STOREID_HDR_T (gint) sizeof(lbmc_cntl_ume_storeid_hdr_t)

#define LBMC_CNTL_UME_STOREID_STOREID(x) (x & 0x7FFF)
#define LBMC_CNTL_UME_STOREID_STOREID_MASK 0x7FFF

/* LBMC control UME capability header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
} lbmc_cntl_ume_capability_hdr_t;
#define O_LBMC_CNTL_UME_CAPABILITY_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_capability_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_CAPABILITY_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_capability_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_CAPABILITY_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_capability_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_CAPABILITY_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_capability_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_capability_hdr_t, flags)
#define L_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_capability_hdr_t, flags)
#define L_LBMC_CNTL_UME_CAPABILITY_HDR_T (gint) sizeof(lbmc_cntl_ume_capability_hdr_t)

/* LBMC control UME Proxy Source header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
} lbmc_cntl_ume_proxy_src_hdr_t;
#define O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_proxy_src_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_proxy_src_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_proxy_src_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_proxy_src_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_proxy_src_hdr_t, flags)
#define L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_proxy_src_hdr_t, flags)
#define L_LBMC_CNTL_UME_PROXY_SRC_HDR_T (gint) sizeof(lbmc_cntl_ume_proxy_src_hdr_t)

/* LBMC control UME Store header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t grp_idx;
    lbm_uint16_t store_tcp_port;
    lbm_uint16_t store_idx;
    lbm_uint32_t store_ip_addr;
    lbm_uint32_t src_reg_id;
} lbmc_cntl_ume_store_hdr_t;
#define O_LBMC_CNTL_UME_STORE_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_store_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_STORE_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_store_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_STORE_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_store_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_STORE_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_store_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_STORE_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_store_hdr_t, flags)
#define L_LBMC_CNTL_UME_STORE_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_store_hdr_t, flags)
#define O_LBMC_CNTL_UME_STORE_HDR_T_GRP_IDX OFFSETOF(lbmc_cntl_ume_store_hdr_t, grp_idx)
#define L_LBMC_CNTL_UME_STORE_HDR_T_GRP_IDX SIZEOF(lbmc_cntl_ume_store_hdr_t, grp_idx)
#define O_LBMC_CNTL_UME_STORE_HDR_T_STORE_TCP_PORT OFFSETOF(lbmc_cntl_ume_store_hdr_t, store_tcp_port)
#define L_LBMC_CNTL_UME_STORE_HDR_T_STORE_TCP_PORT SIZEOF(lbmc_cntl_ume_store_hdr_t, store_tcp_port)
#define O_LBMC_CNTL_UME_STORE_HDR_T_STORE_IDX OFFSETOF(lbmc_cntl_ume_store_hdr_t, store_idx)
#define L_LBMC_CNTL_UME_STORE_HDR_T_STORE_IDX SIZEOF(lbmc_cntl_ume_store_hdr_t, store_idx)
#define O_LBMC_CNTL_UME_STORE_HDR_T_STORE_IP_ADDR OFFSETOF(lbmc_cntl_ume_store_hdr_t, store_ip_addr)
#define L_LBMC_CNTL_UME_STORE_HDR_T_STORE_IP_ADDR SIZEOF(lbmc_cntl_ume_store_hdr_t, store_ip_addr)
#define O_LBMC_CNTL_UME_STORE_HDR_T_SRC_REG_ID OFFSETOF(lbmc_cntl_ume_store_hdr_t, src_reg_id)
#define L_LBMC_CNTL_UME_STORE_HDR_T_SRC_REG_ID SIZEOF(lbmc_cntl_ume_store_hdr_t, src_reg_id)
#define L_LBMC_CNTL_UME_STORE_HDR_T (gint) sizeof(lbmc_cntl_ume_store_hdr_t)

/* LBMC control UME Store Extended header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t grp_idx;
    lbm_uint16_t store_tcp_port;
    lbm_uint16_t store_idx;
    lbm_uint32_t store_ip_addr;
    lbm_uint32_t src_reg_id;
    lbm_uint32_t domain_id;
    lbm_uint32_t version;
} lbmc_cntl_ume_store_ext_hdr_t;
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, flags)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, flags)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_GRP_IDX OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, grp_idx)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_GRP_IDX SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, grp_idx)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_TCP_PORT OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, store_tcp_port)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_TCP_PORT SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, store_tcp_port)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_IDX OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, store_idx)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_IDX SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, store_idx)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_IP_ADDR OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, store_ip_addr)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_IP_ADDR SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, store_ip_addr)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_SRC_REG_ID OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, src_reg_id)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_SRC_REG_ID SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, src_reg_id)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_DOMAIN_ID OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, domain_id)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_DOMAIN_ID SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, domain_id)
#define O_LBMC_CNTL_UME_STORE_EXT_HDR_T_VERSION OFFSETOF(lbmc_cntl_ume_store_ext_hdr_t, version)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T_VERSION SIZEOF(lbmc_cntl_ume_store_ext_hdr_t, version)
#define L_LBMC_CNTL_UME_STORE_EXT_HDR_T (gint) sizeof(lbmc_cntl_ume_store_ext_hdr_t)

/* LBMC control UME Late Join info header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t low_seqnum;
    lbm_uint32_t high_seqnum;
    lbm_uint32_t qidx;
} lbmc_cntl_ume_lj_info_hdr_t;
#define O_LBMC_CNTL_UME_LJ_INFO_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_lj_info_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_LJ_INFO_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_lj_info_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_LJ_INFO_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_lj_info_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_LJ_INFO_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_lj_info_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_LJ_INFO_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_lj_info_hdr_t, flags)
#define L_LBMC_CNTL_UME_LJ_INFO_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_lj_info_hdr_t, flags)
#define O_LBMC_CNTL_UME_LJ_INFO_HDR_T_LOW_SEQNUM OFFSETOF(lbmc_cntl_ume_lj_info_hdr_t, low_seqnum)
#define L_LBMC_CNTL_UME_LJ_INFO_HDR_T_LOW_SEQNUM SIZEOF(lbmc_cntl_ume_lj_info_hdr_t, low_seqnum)
#define O_LBMC_CNTL_UME_LJ_INFO_HDR_T_HIGH_SEQNUM OFFSETOF(lbmc_cntl_ume_lj_info_hdr_t, high_seqnum)
#define L_LBMC_CNTL_UME_LJ_INFO_HDR_T_HIGH_SEQNUM SIZEOF(lbmc_cntl_ume_lj_info_hdr_t, high_seqnum)
#define O_LBMC_CNTL_UME_LJ_INFO_HDR_T_QIDX OFFSETOF(lbmc_cntl_ume_lj_info_hdr_t, qidx)
#define L_LBMC_CNTL_UME_LJ_INFO_HDR_T_QIDX SIZEOF(lbmc_cntl_ume_lj_info_hdr_t, qidx)
#define L_LBMC_CNTL_UME_LJ_INFO_HDR_T (gint) sizeof(lbmc_cntl_ume_lj_info_hdr_t)

/* LBMC control UME Store Group header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t grp_idx;
    lbm_uint16_t grp_sz;
    lbm_uint16_t res1;
} lbmc_cntl_ume_store_group_hdr_t;
#define O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_store_group_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_store_group_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_store_group_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_store_group_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_store_group_hdr_t, flags)
#define L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_store_group_hdr_t, flags)
#define O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_GRP_IDX OFFSETOF(lbmc_cntl_ume_store_group_hdr_t, grp_idx)
#define L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_GRP_IDX SIZEOF(lbmc_cntl_ume_store_group_hdr_t, grp_idx)
#define O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_GRP_SZ OFFSETOF(lbmc_cntl_ume_store_group_hdr_t, grp_sz)
#define L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_GRP_SZ SIZEOF(lbmc_cntl_ume_store_group_hdr_t, grp_sz)
#define O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_RES1 OFFSETOF(lbmc_cntl_ume_store_group_hdr_t, res1)
#define L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_RES1 SIZEOF(lbmc_cntl_ume_store_group_hdr_t, res1)
#define L_LBMC_CNTL_UME_STORE_GROUP_HDR_T (gint) sizeof(lbmc_cntl_ume_store_group_hdr_t)

/* LBMC control TSNI header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t num_recs;
} lbmc_cntl_tsni_hdr_t;
#define O_LBMC_CNTL_TSNI_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_tsni_hdr_t, next_hdr)
#define L_LBMC_CNTL_TSNI_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_tsni_hdr_t, next_hdr)
#define O_LBMC_CNTL_TSNI_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_tsni_hdr_t, hdr_len)
#define L_LBMC_CNTL_TSNI_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_tsni_hdr_t, hdr_len)
#define O_LBMC_CNTL_TSNI_HDR_T_NUM_RECS OFFSETOF(lbmc_cntl_tsni_hdr_t, num_recs)
#define L_LBMC_CNTL_TSNI_HDR_T_NUM_RECS SIZEOF(lbmc_cntl_tsni_hdr_t, num_recs)
#define L_LBMC_CNTL_TSNI_HDR_T (gint) sizeof(lbmc_cntl_tsni_hdr_t)

#define LBMC_CNTL_TSNI_NUM_RECS_MASK 0x7fff

typedef struct
{
    lbm_uint32_t tidx;
    lbm_uint32_t sqn;
} lbmc_cntl_tsni_rec_hdr_t;
#define O_LBMC_CNTL_TSNI_REC_HDR_T_TIDX OFFSETOF(lbmc_cntl_tsni_rec_hdr_t, tidx)
#define L_LBMC_CNTL_TSNI_REC_HDR_T_TIDX SIZEOF(lbmc_cntl_tsni_rec_hdr_t, tidx)
#define O_LBMC_CNTL_TSNI_REC_HDR_T_SQN OFFSETOF(lbmc_cntl_tsni_rec_hdr_t, sqn)
#define L_LBMC_CNTL_TSNI_REC_HDR_T_SQN SIZEOF(lbmc_cntl_tsni_rec_hdr_t, sqn)
#define L_LBMC_CNTL_TSNI_REC_HDR_T (gint) sizeof(lbmc_cntl_tsni_rec_hdr_t)

/* LBMC control UMQ registration header(s) */
typedef struct
{
    lbm_uint16_t port;
    lbm_uint16_t reserved;
    lbm_uint32_t ip;
    lbm_uint32_t capabilities;
} lbmc_cntl_umq_reg_ctx_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_CTX_HDR_T_PORT OFFSETOF(lbmc_cntl_umq_reg_ctx_hdr_t, port)
#define L_LBMC_CNTL_UMQ_REG_CTX_HDR_T_PORT SIZEOF(lbmc_cntl_umq_reg_ctx_hdr_t, port)
#define O_LBMC_CNTL_UMQ_REG_CTX_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_reg_ctx_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_CTX_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_reg_ctx_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_REG_CTX_HDR_T_IP OFFSETOF(lbmc_cntl_umq_reg_ctx_hdr_t, ip)
#define L_LBMC_CNTL_UMQ_REG_CTX_HDR_T_IP SIZEOF(lbmc_cntl_umq_reg_ctx_hdr_t, ip)
#define O_LBMC_CNTL_UMQ_REG_CTX_HDR_T_CAPABILITIES OFFSETOF(lbmc_cntl_umq_reg_ctx_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_CTX_HDR_T_CAPABILITIES SIZEOF(lbmc_cntl_umq_reg_ctx_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_CTX_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_ctx_hdr_t)

typedef struct
{
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
} lbmc_cntl_umq_reg_src_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_SRC_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_umq_reg_src_hdr_t, transport_idx)
#define L_LBMC_CNTL_UMQ_REG_SRC_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_umq_reg_src_hdr_t, transport_idx)
#define O_LBMC_CNTL_UMQ_REG_SRC_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_umq_reg_src_hdr_t, topic_idx)
#define L_LBMC_CNTL_UMQ_REG_SRC_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_umq_reg_src_hdr_t, topic_idx)
#define L_LBMC_CNTL_UMQ_REG_SRC_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_src_hdr_t)

typedef struct
{
    lbm_uint32_t assign_id;
    lbm_uint32_t rcv_type_id;
    lbm_uint32_t last_topic_rcr_tsp;
} lbmc_cntl_umq_reg_rcv_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_reg_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_REG_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_reg_rcv_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_REG_RCV_HDR_T_RCV_TYPE_ID OFFSETOF(lbmc_cntl_umq_reg_rcv_hdr_t, rcv_type_id)
#define L_LBMC_CNTL_UMQ_REG_RCV_HDR_T_RCV_TYPE_ID SIZEOF(lbmc_cntl_umq_reg_rcv_hdr_t, rcv_type_id)
#define O_LBMC_CNTL_UMQ_REG_RCV_HDR_T_LAST_TOPIC_RCR_TSP OFFSETOF(lbmc_cntl_umq_reg_rcv_hdr_t, last_topic_rcr_tsp)
#define L_LBMC_CNTL_UMQ_REG_RCV_HDR_T_LAST_TOPIC_RCR_TSP SIZEOF(lbmc_cntl_umq_reg_rcv_hdr_t, last_topic_rcr_tsp)
#define L_LBMC_CNTL_UMQ_REG_RCV_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_rcv_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_rcv_dereg_hdr_t;
#define O_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_rcv_dereg_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_rcv_dereg_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rcv_dereg_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rcv_dereg_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T (gint) sizeof(lbmc_cntl_umq_rcv_dereg_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint32_t rcv_type_id;
    lbm_uint16_t port;
    lbm_uint16_t reserved;
    lbm_uint32_t ip;
    lbm_uint32_t capabilities;
} lbmc_cntl_umq_reg_ulb_rcv_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_RCV_TYPE_ID OFFSETOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, rcv_type_id)
#define L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_RCV_TYPE_ID SIZEOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, rcv_type_id)
#define O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_PORT OFFSETOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, port)
#define L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_PORT SIZEOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, port)
#define O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_IP OFFSETOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, ip)
#define L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_IP SIZEOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, ip)
#define O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_CAPABILITIES OFFSETOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_CAPABILITIES SIZEOF(lbmc_cntl_umq_reg_ulb_rcv_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_ulb_rcv_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_ulb_rcv_dereg_hdr_t;
#define O_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_ulb_rcv_dereg_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_ulb_rcv_dereg_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ulb_rcv_dereg_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ulb_rcv_dereg_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T (gint) sizeof(lbmc_cntl_umq_ulb_rcv_dereg_hdr_t)

typedef struct
{
    lbm_uint32_t assign_id;
    lbm_uint32_t rcv_type_id;
    lbm_uint32_t last_topic_rcr_tsp;
} lbmc_cntl_umq_reg_observer_rcv_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_reg_observer_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_reg_observer_rcv_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_RCV_TYPE_ID OFFSETOF(lbmc_cntl_umq_reg_observer_rcv_hdr_t, rcv_type_id)
#define L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_RCV_TYPE_ID SIZEOF(lbmc_cntl_umq_reg_observer_rcv_hdr_t, rcv_type_id)
#define O_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_LAST_TOPIC_RCR_TSP OFFSETOF(lbmc_cntl_umq_reg_observer_rcv_hdr_t, last_topic_rcr_tsp)
#define L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_LAST_TOPIC_RCR_TSP SIZEOF(lbmc_cntl_umq_reg_observer_rcv_hdr_t, last_topic_rcr_tsp)
#define L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_observer_rcv_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_observer_rcv_dereg_hdr_t;
#define O_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_observer_rcv_dereg_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_observer_rcv_dereg_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_observer_rcv_dereg_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_observer_rcv_dereg_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T (gint) sizeof(lbmc_cntl_umq_observer_rcv_dereg_hdr_t)

typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t reg_type;
    lbm_uint32_t queue_id;
    lbm_uint16_t cmd_id;
    lbm_uint16_t inst_idx;
    lbm_uint8_t regid[8];
} lbmc_cntl_umq_reg_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_reg_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_REG_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_reg_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_REG_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_reg_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_REG_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_reg_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_reg_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_reg_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_REG_HDR_T_REG_TYPE OFFSETOF(lbmc_cntl_umq_reg_hdr_t, reg_type)
#define L_LBMC_CNTL_UMQ_REG_HDR_T_REG_TYPE SIZEOF(lbmc_cntl_umq_reg_hdr_t, reg_type)
#define O_LBMC_CNTL_UMQ_REG_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_reg_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_REG_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_reg_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_REG_HDR_T_CMD_ID OFFSETOF(lbmc_cntl_umq_reg_hdr_t, cmd_id)
#define L_LBMC_CNTL_UMQ_REG_HDR_T_CMD_ID SIZEOF(lbmc_cntl_umq_reg_hdr_t, cmd_id)
#define O_LBMC_CNTL_UMQ_REG_HDR_T_INST_IDX OFFSETOF(lbmc_cntl_umq_reg_hdr_t, inst_idx)
#define L_LBMC_CNTL_UMQ_REG_HDR_T_INST_IDX SIZEOF(lbmc_cntl_umq_reg_hdr_t, inst_idx)
#define O_LBMC_CNTL_UMQ_REG_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_reg_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_REG_HDR_T_REGID SIZEOF(lbmc_cntl_umq_reg_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_REG_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_hdr_t)

/* LBMC control UMQ registration response header(s) */
typedef struct
{
    lbm_uint32_t capabilities;
} lbmc_cntl_umq_reg_resp_ctx_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RESP_CTX_HDR_T_CAPABILITIES OFFSETOF(lbmc_cntl_umq_reg_resp_ctx_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_RESP_CTX_HDR_T_CAPABILITIES SIZEOF(lbmc_cntl_umq_reg_resp_ctx_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_RESP_CTX_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_resp_ctx_hdr_t)

typedef struct
{
    lbm_uint32_t capabilities;
    lbm_uint16_t reserved;
    lbm_uint16_t flags;
    lbm_uint8_t stamp[8];
} lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_CAPABILITIES OFFSETOF(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_CAPABILITIES SIZEOF(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t, capabilities)
#define O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_STAMP OFFSETOF(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t, stamp)
#define L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_STAMP SIZEOF(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t, stamp)
#define L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t)

typedef struct
{
    lbm_uint16_t reserved;
    lbm_uint16_t code;
} lbmc_cntl_umq_reg_resp_err_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_reg_resp_err_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_reg_resp_err_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T_CODE OFFSETOF(lbmc_cntl_umq_reg_resp_err_hdr_t, code)
#define L_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T_CODE SIZEOF(lbmc_cntl_umq_reg_resp_err_hdr_t, code)
#define L_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_resp_err_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
} lbmc_cntl_umq_reg_resp_src_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RESP_SRC_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_reg_resp_src_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_REG_RESP_SRC_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_reg_resp_src_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_REG_RESP_SRC_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_resp_src_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_reg_resp_rcv_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_reg_resp_rcv_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_reg_resp_rcv_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_reg_resp_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_reg_resp_rcv_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_reg_resp_rcv_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_reg_resp_rcv_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_reg_resp_rcv_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_reg_resp_rcv_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_resp_rcv_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_rcv_dereg_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_rcv_dereg_resp_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_rcv_dereg_resp_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rcv_dereg_resp_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rcv_dereg_resp_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_rcv_dereg_resp_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
    lbm_uint32_t capabilities;
} lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_CAPABILITIES OFFSETOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_CAPABILITIES SIZEOF(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t, capabilities)
#define L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_ulb_rcv_dereg_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_ulb_rcv_dereg_resp_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_ulb_rcv_dereg_resp_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ulb_rcv_dereg_resp_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ulb_rcv_dereg_resp_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_ulb_rcv_dereg_resp_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_observer_rcv_dereg_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_observer_rcv_dereg_resp_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_observer_rcv_dereg_resp_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_observer_rcv_dereg_resp_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_observer_rcv_dereg_resp_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_observer_rcv_dereg_resp_hdr_t)

typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t resp_type;
    lbm_uint32_t queue_id;
    lbm_uint16_t cmd_id;
    lbm_uint16_t inst_idx;
    lbm_uint8_t regid[8];
} lbmc_cntl_umq_reg_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_reg_resp_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_reg_resp_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_reg_resp_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_reg_resp_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_reg_resp_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_reg_resp_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESP_TYPE OFFSETOF(lbmc_cntl_umq_reg_resp_hdr_t, resp_type)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESP_TYPE SIZEOF(lbmc_cntl_umq_reg_resp_hdr_t, resp_type)
#define O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_reg_resp_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_reg_resp_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_CMD_ID OFFSETOF(lbmc_cntl_umq_reg_resp_hdr_t, cmd_id)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_CMD_ID SIZEOF(lbmc_cntl_umq_reg_resp_hdr_t, cmd_id)
#define O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_INST_IDX OFFSETOF(lbmc_cntl_umq_reg_resp_hdr_t, inst_idx)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_INST_IDX SIZEOF(lbmc_cntl_umq_reg_resp_hdr_t, inst_idx)
#define O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESPID OFFSETOF(lbmc_cntl_umq_reg_resp_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESPID SIZEOF(lbmc_cntl_umq_reg_resp_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_REG_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_reg_resp_hdr_t)

/* LBMC control UMQ ACK header(s) */
typedef struct
{
    lbm_uint8_t regid[8];
    lbm_uint8_t stamp[8];
} lbmc_cntl_umq_ack_msgid_hdr_t;
#define O_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_ack_msgid_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T_REGID SIZEOF(lbmc_cntl_umq_ack_msgid_hdr_t, regid)
#define O_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T_STAMP OFFSETOF(lbmc_cntl_umq_ack_msgid_hdr_t, stamp)
#define L_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T_STAMP SIZEOF(lbmc_cntl_umq_ack_msgid_hdr_t, stamp)
#define L_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T (gint) sizeof(lbmc_cntl_umq_ack_msgid_hdr_t)

typedef struct
{
    lbm_uint32_t queue_id;
    lbm_uint16_t inst_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_ack_stable_hdr_t;
#define O_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_ack_stable_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_ack_stable_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_INST_IDX OFFSETOF(lbmc_cntl_umq_ack_stable_hdr_t, inst_idx)
#define L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_INST_IDX SIZEOF(lbmc_cntl_umq_ack_stable_hdr_t, inst_idx)
#define O_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ack_stable_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ack_stable_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T (gint) sizeof(lbmc_cntl_umq_ack_stable_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_ack_cr_hdr_t;
#define O_LBMC_CNTL_UMQ_ACK_CR_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_ack_cr_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_ACK_CR_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_ack_cr_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_ACK_CR_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ack_cr_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ACK_CR_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ack_cr_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_ACK_CR_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_ack_cr_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_ACK_CR_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_ack_cr_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_ACK_CR_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ack_cr_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ACK_CR_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ack_cr_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ACK_CR_HDR_T (gint) sizeof(lbmc_cntl_umq_ack_cr_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_ack_ulb_cr_hdr_t;
#define O_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_ack_ulb_cr_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_ack_ulb_cr_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ack_ulb_cr_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ack_ulb_cr_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_ack_ulb_cr_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_ack_ulb_cr_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ack_ulb_cr_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ack_ulb_cr_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T (gint) sizeof(lbmc_cntl_umq_ack_ulb_cr_hdr_t)

typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t msgs;
    lbm_uint8_t ack_type;
} lbmc_cntl_umq_ack_hdr_t;
#define O_LBMC_CNTL_UMQ_ACK_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_ack_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_ACK_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_ack_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_ACK_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_ack_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_ACK_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_ack_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS OFFSETOF(lbmc_cntl_umq_ack_hdr_t, msgs)
#define L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS SIZEOF(lbmc_cntl_umq_ack_hdr_t, msgs)
#define O_LBMC_CNTL_UMQ_ACK_HDR_T_ACK_TYPE OFFSETOF(lbmc_cntl_umq_ack_hdr_t, ack_type)
#define L_LBMC_CNTL_UMQ_ACK_HDR_T_ACK_TYPE SIZEOF(lbmc_cntl_umq_ack_hdr_t, ack_type)
#define L_LBMC_CNTL_UMQ_ACK_HDR_T (gint) sizeof(lbmc_cntl_umq_ack_hdr_t)

/* UMQ control receiver control record header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t queue_id;
    lbm_uint32_t rcr_idx;
    lbm_uint8_t msgid_regid[8];
    lbm_uint8_t msgid_stamp[8];
    lbm_uint32_t topic_tsp;
    lbm_uint32_t q_tsp;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t num_ras;
    lbm_uint32_t queue_ver;
} lbmc_cntl_umq_rcr_hdr_t;
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_rcr_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_rcr_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_rcr_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_rcr_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_rcr_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_MSGID_REGID OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, msgid_regid)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_MSGID_REGID SIZEOF(lbmc_cntl_umq_rcr_hdr_t, msgid_regid)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_MSGID_STAMP OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_MSGID_STAMP SIZEOF(lbmc_cntl_umq_rcr_hdr_t, msgid_stamp)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_TOPIC_TSP OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, topic_tsp)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_TOPIC_TSP SIZEOF(lbmc_cntl_umq_rcr_hdr_t, topic_tsp)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_Q_TSP OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, q_tsp)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_Q_TSP SIZEOF(lbmc_cntl_umq_rcr_hdr_t, q_tsp)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rcr_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_rcr_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_NUM_RAS OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, num_ras)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_NUM_RAS SIZEOF(lbmc_cntl_umq_rcr_hdr_t, num_ras)
#define O_LBMC_CNTL_UMQ_RCR_HDR_T_QUEUE_VER OFFSETOF(lbmc_cntl_umq_rcr_hdr_t, queue_ver)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T_QUEUE_VER SIZEOF(lbmc_cntl_umq_rcr_hdr_t, queue_ver)
#define L_LBMC_CNTL_UMQ_RCR_HDR_T (gint) sizeof(lbmc_cntl_umq_rcr_hdr_t)

/* LBMC control UMQ keepalive header(s) */
typedef struct
{
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
} lbmc_cntl_umq_ka_src_hdr_t;
#define O_LBMC_CNTL_UMQ_KA_SRC_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_umq_ka_src_hdr_t, transport_idx)
#define L_LBMC_CNTL_UMQ_KA_SRC_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_umq_ka_src_hdr_t, transport_idx)
#define O_LBMC_CNTL_UMQ_KA_SRC_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_umq_ka_src_hdr_t, topic_idx)
#define L_LBMC_CNTL_UMQ_KA_SRC_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_umq_ka_src_hdr_t, topic_idx)
#define L_LBMC_CNTL_UMQ_KA_SRC_HDR_T (gint) sizeof(lbmc_cntl_umq_ka_src_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_ka_rcv_hdr_t;
#define O_LBMC_CNTL_UMQ_KA_RCV_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_ka_rcv_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_KA_RCV_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_ka_rcv_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_KA_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ka_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_KA_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ka_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_KA_RCV_HDR_T (gint) sizeof(lbmc_cntl_umq_ka_rcv_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_ka_ulb_rcv_hdr_t;
#define O_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_ka_ulb_rcv_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_ka_ulb_rcv_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ka_ulb_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ka_ulb_rcv_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T (gint) sizeof(lbmc_cntl_umq_ka_ulb_rcv_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t)

typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t ka_type;
    lbm_uint32_t queue_id;
    lbm_uint8_t regid[8];
    lbm_uint16_t inst_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_ka_hdr_t;
#define O_LBMC_CNTL_UMQ_KA_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_ka_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_KA_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_ka_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_KA_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_ka_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_KA_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_ka_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_ka_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_ka_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_KA_HDR_T_KA_TYPE OFFSETOF(lbmc_cntl_umq_ka_hdr_t, ka_type)
#define L_LBMC_CNTL_UMQ_KA_HDR_T_KA_TYPE SIZEOF(lbmc_cntl_umq_ka_hdr_t, ka_type)
#define O_LBMC_CNTL_UMQ_KA_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_ka_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_KA_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_ka_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_KA_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_ka_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_KA_HDR_T_REGID SIZEOF(lbmc_cntl_umq_ka_hdr_t, regid)
#define O_LBMC_CNTL_UMQ_KA_HDR_T_INST_IDX OFFSETOF(lbmc_cntl_umq_ka_hdr_t, inst_idx)
#define L_LBMC_CNTL_UMQ_KA_HDR_T_INST_IDX SIZEOF(lbmc_cntl_umq_ka_hdr_t, inst_idx)
#define O_LBMC_CNTL_UMQ_KA_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ka_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_KA_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ka_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_KA_HDR_T (gint) sizeof(lbmc_cntl_umq_ka_hdr_t)

/* LBMC control UMQ retransmission request header(s) */
typedef struct
{
    lbm_uint8_t regid[8];
} lbmc_cntl_umq_rxreq_regid_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_REGID_RESP_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_rxreq_regid_resp_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_RXREQ_REGID_RESP_HDR_T_REGID SIZEOF(lbmc_cntl_umq_rxreq_regid_resp_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_RXREQ_REGID_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_regid_resp_hdr_t)

typedef struct
{
    lbm_uint32_t ip;
    lbm_uint16_t port;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_rxreq_addr_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_IP OFFSETOF(lbmc_cntl_umq_rxreq_addr_resp_hdr_t, ip)
#define L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_IP SIZEOF(lbmc_cntl_umq_rxreq_addr_resp_hdr_t, ip)
#define O_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_PORT OFFSETOF(lbmc_cntl_umq_rxreq_addr_resp_hdr_t, port)
#define L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_PORT SIZEOF(lbmc_cntl_umq_rxreq_addr_resp_hdr_t, port)
#define O_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_rxreq_addr_resp_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_rxreq_addr_resp_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_addr_resp_hdr_t)

typedef struct
{
    lbm_uint32_t assign_id;
    lbm_uint8_t msgid_regid[8];
    lbm_uint8_t msgid_stamp[8];
} lbmc_cntl_umq_rxreq_mr_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rxreq_mr_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rxreq_mr_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_MSGID_REGID OFFSETOF(lbmc_cntl_umq_rxreq_mr_hdr_t, msgid_regid)
#define L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_MSGID_REGID SIZEOF(lbmc_cntl_umq_rxreq_mr_hdr_t, msgid_regid)
#define O_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_MSGID_STAMP OFFSETOF(lbmc_cntl_umq_rxreq_mr_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_MSGID_STAMP SIZEOF(lbmc_cntl_umq_rxreq_mr_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_mr_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
    lbm_uint8_t msgid_regid[8];
    lbm_uint8_t msgid_stamp[8];
} lbmc_cntl_umq_rxreq_ulb_mr_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_MSGID_REGID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, msgid_regid)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_MSGID_REGID SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, msgid_regid)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_MSGID_STAMP OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_MSGID_STAMP SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_ulb_mr_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint8_t msgid_regid[8];
    lbm_uint8_t msgid_stamp[8];
} lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_MSGID_REGID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t, msgid_regid)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_MSGID_REGID SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t, msgid_regid)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_MSGID_STAMP OFFSETOF(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_MSGID_STAMP SIZEOF(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t)

typedef struct
{
    lbm_uint32_t tsp;
} lbmc_cntl_umq_rxreq_qrcrr_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_QRCRR_HDR_T_TSP OFFSETOF(lbmc_cntl_umq_rxreq_qrcrr_hdr_t, tsp)
#define L_LBMC_CNTL_UMQ_RXREQ_QRCRR_HDR_T_TSP SIZEOF(lbmc_cntl_umq_rxreq_qrcrr_hdr_t, tsp)
#define L_LBMC_CNTL_UMQ_RXREQ_QRCRR_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_qrcrr_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t tsp;
} lbmc_cntl_umq_rxreq_trcrr_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_rxreq_trcrr_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_rxreq_trcrr_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T_TSP OFFSETOF(lbmc_cntl_umq_rxreq_trcrr_hdr_t, tsp)
#define L_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T_TSP SIZEOF(lbmc_cntl_umq_rxreq_trcrr_hdr_t, tsp)
#define L_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_trcrr_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint32_t tsp;
} lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_TSP OFFSETOF(lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t, tsp)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_TSP SIZEOF(lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t, tsp)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t)

typedef struct
{
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t assign_id;
    lbm_uint32_t tsp;
} lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_TSP OFFSETOF(lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t, tsp)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_TSP SIZEOF(lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t, tsp)
#define L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t)

typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t rxreq_type;
} lbmc_cntl_umq_rxreq_hdr_t;
#define O_LBMC_CNTL_UMQ_RXREQ_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_rxreq_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_RXREQ_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_rxreq_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_RXREQ_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_rxreq_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_RXREQ_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_rxreq_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_rxreq_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_rxreq_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_RXREQ_HDR_T_RXREQ_TYPE OFFSETOF(lbmc_cntl_umq_rxreq_hdr_t, rxreq_type)
#define L_LBMC_CNTL_UMQ_RXREQ_HDR_T_RXREQ_TYPE SIZEOF(lbmc_cntl_umq_rxreq_hdr_t, rxreq_type)
#define L_LBMC_CNTL_UMQ_RXREQ_HDR_T (gint) sizeof(lbmc_cntl_umq_rxreq_hdr_t)

/* LBMC control UMQ queue management header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
} lbmc_cntl_umq_qmgmt_hdr_t;
#define O_LBMC_CNTL_UMQ_QMGMT_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_qmgmt_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_QMGMT_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_qmgmt_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_QMGMT_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_qmgmt_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_QMGMT_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_qmgmt_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_QMGMT_HDR_T (gint) sizeof(lbmc_cntl_umq_qmgmt_hdr_t)

/* LBMC control UMQ resubmission request header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint8_t msgid_regid[8];
    lbm_uint8_t msgid_stamp[8];
    lbm_uint32_t rcr_idx;
    lbm_uint32_t resp_ip;
    lbm_uint16_t resp_port;
    lbm_uint16_t appset_idx;
} lbmc_cntl_umq_resub_req_hdr_t;
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_MSGID_REGID OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, msgid_regid)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_MSGID_REGID SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, msgid_regid)
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_MSGID_STAMP OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_MSGID_STAMP SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, msgid_stamp)
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RESP_IP OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, resp_ip)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RESP_IP SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, resp_ip)
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RESP_PORT OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, resp_port)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RESP_PORT SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, resp_port)
#define O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_resub_req_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_resub_req_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T (gint) sizeof(lbmc_cntl_umq_resub_req_hdr_t)

/* LBMC control UMQ resubmission response header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t code;
    lbm_uint8_t msgid_regid[8];
    lbm_uint8_t msgid_stamp[8];
    lbm_uint32_t rcr_idx;
    lbm_uint16_t reserved;
    lbm_uint16_t appset_idx;
} lbmc_cntl_umq_resub_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_CODE OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, code)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_CODE SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, code)
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_MSGID_REGID OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, msgid_regid)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_MSGID_REGID SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, msgid_regid)
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_MSGID_STAMP OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_MSGID_STAMP SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, msgid_stamp)
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_resub_resp_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_resub_resp_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_resub_resp_hdr_t)

/* LBMC control topic interest header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t domain_id;
} lbmc_cntl_topic_interest_hdr_t;
#define O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_topic_interest_hdr_t, next_hdr)
#define L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_topic_interest_hdr_t, next_hdr)
#define O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_topic_interest_hdr_t, hdr_len)
#define L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_topic_interest_hdr_t, hdr_len)
#define O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS OFFSETOF(lbmc_cntl_topic_interest_hdr_t, flags)
#define L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS SIZEOF(lbmc_cntl_topic_interest_hdr_t, flags)
#define O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_DOMAIN_ID OFFSETOF(lbmc_cntl_topic_interest_hdr_t, domain_id)
#define L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_DOMAIN_ID SIZEOF(lbmc_cntl_topic_interest_hdr_t, domain_id)
#define L_LBMC_CNTL_TOPIC_INTEREST_HDR_T (gint) sizeof(lbmc_cntl_topic_interest_hdr_t)

/* LBMC control pattern interest header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t type;
    lbm_uint32_t domain_id;
    lbm_uint8_t index[8];
} lbmc_cntl_pattern_interest_hdr_t;
#define O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_pattern_interest_hdr_t, next_hdr)
#define L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_pattern_interest_hdr_t, next_hdr)
#define O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_pattern_interest_hdr_t, hdr_len)
#define L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_pattern_interest_hdr_t, hdr_len)
#define O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS OFFSETOF(lbmc_cntl_pattern_interest_hdr_t, flags)
#define L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS SIZEOF(lbmc_cntl_pattern_interest_hdr_t, flags)
#define O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_TYPE OFFSETOF(lbmc_cntl_pattern_interest_hdr_t, type)
#define L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_TYPE SIZEOF(lbmc_cntl_pattern_interest_hdr_t, type)
#define O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_DOMAIN_ID OFFSETOF(lbmc_cntl_pattern_interest_hdr_t, domain_id)
#define L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_DOMAIN_ID SIZEOF(lbmc_cntl_pattern_interest_hdr_t, domain_id)
#define O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_INDEX OFFSETOF(lbmc_cntl_pattern_interest_hdr_t, index)
#define L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_INDEX SIZEOF(lbmc_cntl_pattern_interest_hdr_t, index)
#define L_LBMC_CNTL_PATTERN_INTEREST_HDR_T (gint) sizeof(lbmc_cntl_pattern_interest_hdr_t)

/* LBMC control advertisement header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t hop_count;
    lbm_uint32_t ad_flags;
    lbm_uint32_t cost;
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
    lbm_uint32_t low_seqno;
    lbm_uint32_t high_seqno;
    lbm_uint32_t domain_id;
    lbm_uint8_t pat_idx[8];
    lbm_uint8_t ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbmc_cntl_advertisement_hdr_t;
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_advertisement_hdr_t, next_hdr)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_advertisement_hdr_t, next_hdr)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_advertisement_hdr_t, hdr_len)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_advertisement_hdr_t, hdr_len)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS OFFSETOF(lbmc_cntl_advertisement_hdr_t, flags)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS SIZEOF(lbmc_cntl_advertisement_hdr_t, flags)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_HOP_COUNT OFFSETOF(lbmc_cntl_advertisement_hdr_t, hop_count)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_HOP_COUNT SIZEOF(lbmc_cntl_advertisement_hdr_t, hop_count)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS OFFSETOF(lbmc_cntl_advertisement_hdr_t, ad_flags)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS SIZEOF(lbmc_cntl_advertisement_hdr_t, ad_flags)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_COST OFFSETOF(lbmc_cntl_advertisement_hdr_t, cost)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_COST SIZEOF(lbmc_cntl_advertisement_hdr_t, cost)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_advertisement_hdr_t, transport_idx)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_advertisement_hdr_t, transport_idx)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_advertisement_hdr_t, topic_idx)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_advertisement_hdr_t, topic_idx)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_LOW_SEQNO OFFSETOF(lbmc_cntl_advertisement_hdr_t, low_seqno)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_LOW_SEQNO SIZEOF(lbmc_cntl_advertisement_hdr_t, low_seqno)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_HIGH_SEQNO OFFSETOF(lbmc_cntl_advertisement_hdr_t, high_seqno)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_HIGH_SEQNO SIZEOF(lbmc_cntl_advertisement_hdr_t, high_seqno)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_DOMAIN_ID OFFSETOF(lbmc_cntl_advertisement_hdr_t, domain_id)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_DOMAIN_ID SIZEOF(lbmc_cntl_advertisement_hdr_t, domain_id)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_PAT_IDX OFFSETOF(lbmc_cntl_advertisement_hdr_t, pat_idx)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_PAT_IDX SIZEOF(lbmc_cntl_advertisement_hdr_t, pat_idx)
#define O_LBMC_CNTL_ADVERTISEMENT_HDR_T_CTXINST OFFSETOF(lbmc_cntl_advertisement_hdr_t, ctxinst)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T_CTXINST SIZEOF(lbmc_cntl_advertisement_hdr_t, ctxinst)
#define L_LBMC_CNTL_ADVERTISEMENT_HDR_T (gint) sizeof(lbmc_cntl_advertisement_hdr_t)

/* LBMC control UME storename header. */
#define O_LBMC_UME_STORENAME_HDR_T_NEXT_HDR OFFSETOF(lbmc_basic_hdr_t, next_hdr)
#define L_LBMC_UME_STORENAME_HDR_T_NEXT_HDR SIZEOF(lbmc_basic_hdr_t, next_hdr)
#define O_LBMC_UME_STORENAME_HDR_T_HDR_LEN OFFSETOF(lbmc_basic_hdr_t, hdr_len)
#define L_LBMC_UME_STORENAME_HDR_T_HDR_LEN SIZEOF(lbmc_basic_hdr_t, hdr_len)
#define O_LBMC_UME_STORENAME_HDR_T_FLAGS OFFSETOF(lbmc_basic_hdr_t, res)
#define L_LBMC_UME_STORENAME_HDR_T_FLAGS SIZEOF(lbmc_basic_hdr_t, res)
#define O_LBMC_UME_STORENAME_HDR_T_STORE (OFFSETOF(lbmc_basic_hdr_t, res) + SIZEOF(lbmc_basic_hdr_t, res))

/* UMQ control ULB receiver control record header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t queue_id;
    lbm_uint32_t ulb_src_id;
    lbm_uint8_t msgid_regid[8];
    lbm_uint8_t msgid_stamp[8];
    lbm_uint32_t topic_tsp;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t num_ras;
} lbmc_cntl_umq_ulb_rcr_hdr_t;
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_ULB_SRC_ID OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, ulb_src_id)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_ULB_SRC_ID SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, ulb_src_id)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_MSGID_REGID OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, msgid_regid)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_MSGID_REGID SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, msgid_regid)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_MSGID_STAMP OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, msgid_stamp)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_MSGID_STAMP SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, msgid_stamp)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_TOPIC_TSP OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, topic_tsp)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_TOPIC_TSP SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, topic_tsp)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_NUM_RAS OFFSETOF(lbmc_cntl_umq_ulb_rcr_hdr_t, num_ras)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_NUM_RAS SIZEOF(lbmc_cntl_umq_ulb_rcr_hdr_t, num_ras)
#define L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T (gint) sizeof(lbmc_cntl_umq_ulb_rcr_hdr_t)

/* LBMC control UMQ load factor header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t type;
    lbm_uint16_t num_srcs;
    lbm_uint16_t lf;
} lbmc_cntl_umq_lf_hdr_t;
#define O_LBMC_CNTL_UMQ_LF_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_lf_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_LF_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_lf_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_LF_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_lf_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_LF_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_lf_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_LF_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_lf_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_LF_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_lf_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_LF_HDR_T_TYPE OFFSETOF(lbmc_cntl_umq_lf_hdr_t, type)
#define L_LBMC_CNTL_UMQ_LF_HDR_T_TYPE SIZEOF(lbmc_cntl_umq_lf_hdr_t, type)
#define O_LBMC_CNTL_UMQ_LF_HDR_T_NUM_SRCS OFFSETOF(lbmc_cntl_umq_lf_hdr_t, num_srcs)
#define L_LBMC_CNTL_UMQ_LF_HDR_T_NUM_SRCS SIZEOF(lbmc_cntl_umq_lf_hdr_t, num_srcs)
#define O_LBMC_CNTL_UMQ_LF_HDR_T_LF OFFSETOF(lbmc_cntl_umq_lf_hdr_t, lf)
#define L_LBMC_CNTL_UMQ_LF_HDR_T_LF SIZEOF(lbmc_cntl_umq_lf_hdr_t, lf)
#define L_LBMC_CNTL_UMQ_LF_HDR_T (gint) sizeof(lbmc_cntl_umq_lf_hdr_t)

/* LBMC control context information header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint8_t reserved;
    lbm_uint8_t hop_count;
    lbm_uint16_t port;
    lbm_uint32_t addr;
    lbm_uint32_t domain_id;
    lbm_uint8_t ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbmc_cntl_ctxinfo_hdr_t;
#define O_LBMC_CNTL_CTXINFO_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, next_hdr)
#define L_LBMC_CNTL_CTXINFO_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ctxinfo_hdr_t, next_hdr)
#define O_LBMC_CNTL_CTXINFO_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, hdr_len)
#define L_LBMC_CNTL_CTXINFO_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ctxinfo_hdr_t, hdr_len)
#define O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, flags)
#define L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS SIZEOF(lbmc_cntl_ctxinfo_hdr_t, flags)
#define O_LBMC_CNTL_CTXINFO_HDR_T_RESERVED OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, reserved)
#define L_LBMC_CNTL_CTXINFO_HDR_T_RESERVED SIZEOF(lbmc_cntl_ctxinfo_hdr_t, reserved)
#define O_LBMC_CNTL_CTXINFO_HDR_T_HOP_COUNT OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, hop_count)
#define L_LBMC_CNTL_CTXINFO_HDR_T_HOP_COUNT SIZEOF(lbmc_cntl_ctxinfo_hdr_t, hop_count)
#define O_LBMC_CNTL_CTXINFO_HDR_T_PORT OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, port)
#define L_LBMC_CNTL_CTXINFO_HDR_T_PORT SIZEOF(lbmc_cntl_ctxinfo_hdr_t, port)
#define O_LBMC_CNTL_CTXINFO_HDR_T_ADDR OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, addr)
#define L_LBMC_CNTL_CTXINFO_HDR_T_ADDR SIZEOF(lbmc_cntl_ctxinfo_hdr_t, addr)
#define O_LBMC_CNTL_CTXINFO_HDR_T_DOMAIN_ID OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, domain_id)
#define L_LBMC_CNTL_CTXINFO_HDR_T_DOMAIN_ID SIZEOF(lbmc_cntl_ctxinfo_hdr_t, domain_id)
#define O_LBMC_CNTL_CTXINFO_HDR_T_CTXINST OFFSETOF(lbmc_cntl_ctxinfo_hdr_t, ctxinst)
#define L_LBMC_CNTL_CTXINFO_HDR_T_CTXINST SIZEOF(lbmc_cntl_ctxinfo_hdr_t, ctxinst)
#define L_LBMC_CNTL_CTXINFO_HDR_T (gint) sizeof(lbmc_cntl_ctxinfo_hdr_t)

/* LBMC control UME proxy source election header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t source_ip;
    lbm_uint32_t store_ip;
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
    lbm_uint16_t source_port;
    lbm_uint16_t store_port;
    lbm_uint8_t source_ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
    lbm_uint8_t store_ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbmc_cntl_ume_pser_hdr_t;
#define O_LBMC_CNTL_UME_PSER_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_pser_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_PSER_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_pser_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_PSER_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_pser_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_PSER_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_pser_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_PSER_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_pser_hdr_t, flags)
#define L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_pser_hdr_t, flags)
#define O_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_IP OFFSETOF(lbmc_cntl_ume_pser_hdr_t, source_ip)
#define L_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_IP SIZEOF(lbmc_cntl_ume_pser_hdr_t, source_ip)
#define O_LBMC_CNTL_UME_PSER_HDR_T_STORE_IP OFFSETOF(lbmc_cntl_ume_pser_hdr_t, store_ip)
#define L_LBMC_CNTL_UME_PSER_HDR_T_STORE_IP SIZEOF(lbmc_cntl_ume_pser_hdr_t, store_ip)
#define O_LBMC_CNTL_UME_PSER_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_ume_pser_hdr_t, transport_idx)
#define L_LBMC_CNTL_UME_PSER_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_ume_pser_hdr_t, transport_idx)
#define O_LBMC_CNTL_UME_PSER_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_ume_pser_hdr_t, topic_idx)
#define L_LBMC_CNTL_UME_PSER_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_ume_pser_hdr_t, topic_idx)
#define O_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_PORT OFFSETOF(lbmc_cntl_ume_pser_hdr_t, source_port)
#define L_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_PORT SIZEOF(lbmc_cntl_ume_pser_hdr_t, source_port)
#define O_LBMC_CNTL_UME_PSER_HDR_T_STORE_PORT OFFSETOF(lbmc_cntl_ume_pser_hdr_t, store_port)
#define L_LBMC_CNTL_UME_PSER_HDR_T_STORE_PORT SIZEOF(lbmc_cntl_ume_pser_hdr_t, store_port)
#define O_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_CTXINST OFFSETOF(lbmc_cntl_ume_pser_hdr_t, source_ctxinst)
#define L_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_CTXINST SIZEOF(lbmc_cntl_ume_pser_hdr_t, source_ctxinst)
#define O_LBMC_CNTL_UME_PSER_HDR_T_STORE_CTXINST OFFSETOF(lbmc_cntl_ume_pser_hdr_t, store_ctxinst)
#define L_LBMC_CNTL_UME_PSER_HDR_T_STORE_CTXINST SIZEOF(lbmc_cntl_ume_pser_hdr_t, store_ctxinst)
#define L_LBMC_CNTL_UME_PSER_HDR_T (gint) sizeof(lbmc_cntl_ume_pser_hdr_t)

/* LBMC domain header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t domain;
} lbmc_domain_hdr_t;
#define O_LBMC_DOMAIN_HDR_T_NEXT_HDR OFFSETOF(lbmc_domain_hdr_t, next_hdr)
#define L_LBMC_DOMAIN_HDR_T_NEXT_HDR SIZEOF(lbmc_domain_hdr_t, next_hdr)
#define O_LBMC_DOMAIN_HDR_T_HDR_LEN OFFSETOF(lbmc_domain_hdr_t, hdr_len)
#define L_LBMC_DOMAIN_HDR_T_HDR_LEN SIZEOF(lbmc_domain_hdr_t, hdr_len)
#define O_LBMC_DOMAIN_HDR_T_FLAGS OFFSETOF(lbmc_domain_hdr_t, flags)
#define L_LBMC_DOMAIN_HDR_T_FLAGS SIZEOF(lbmc_domain_hdr_t, flags)
#define O_LBMC_DOMAIN_HDR_T_DOMAIN OFFSETOF(lbmc_domain_hdr_t, domain)
#define L_LBMC_DOMAIN_HDR_T_DOMAIN SIZEOF(lbmc_domain_hdr_t, domain)
#define L_LBMC_DOMAIN_HDR_T (gint) sizeof(lbmc_domain_hdr_t)

/* LBMC control TNWG capabilities header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t capabilities1;
    lbm_uint32_t capabilities2;
    lbm_uint32_t capabilities3;
    lbm_uint32_t capabilities4;
} lbmc_cntl_tnwg_capabilities_hdr_t;

#define O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_tnwg_capabilities_hdr_t, next_hdr)
#define L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_tnwg_capabilities_hdr_t, next_hdr)
#define O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_tnwg_capabilities_hdr_t, hdr_len)
#define L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_tnwg_capabilities_hdr_t, hdr_len)
#define O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS OFFSETOF(lbmc_cntl_tnwg_capabilities_hdr_t, flags)
#define L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS SIZEOF(lbmc_cntl_tnwg_capabilities_hdr_t, flags)
#define O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1 OFFSETOF(lbmc_cntl_tnwg_capabilities_hdr_t, capabilities1)
#define L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1 SIZEOF(lbmc_cntl_tnwg_capabilities_hdr_t, capabilities1)
#define O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES2 OFFSETOF(lbmc_cntl_tnwg_capabilities_hdr_t, capabilities2)
#define L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES2 SIZEOF(lbmc_cntl_tnwg_capabilities_hdr_t, capabilities2)
#define O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3 OFFSETOF(lbmc_cntl_tnwg_capabilities_hdr_t, capabilities3)
#define L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3 SIZEOF(lbmc_cntl_tnwg_capabilities_hdr_t, capabilities3)
#define O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES4 OFFSETOF(lbmc_cntl_tnwg_capabilities_hdr_t, capabilities4)
#define L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES4 SIZEOF(lbmc_cntl_tnwg_capabilities_hdr_t, capabilities4)
#define L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T (gint) sizeof(lbmc_cntl_tnwg_capabilities_hdr_t)

/* LBMC pattern index header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    char patidx[8];
} lbmc_patidx_hdr_t;
#define O_LBMC_PATIDX_HDR_T_NEXT_HDR OFFSETOF(lbmc_patidx_hdr_t, next_hdr)
#define L_LBMC_PATIDX_HDR_T_NEXT_HDR SIZEOF(lbmc_patidx_hdr_t, next_hdr)
#define O_LBMC_PATIDX_HDR_T_HDR_LEN OFFSETOF(lbmc_patidx_hdr_t, hdr_len)
#define L_LBMC_PATIDX_HDR_T_HDR_LEN SIZEOF(lbmc_patidx_hdr_t, hdr_len)
#define O_LBMC_PATIDX_HDR_T_FLAGS OFFSETOF(lbmc_patidx_hdr_t, flags)
#define L_LBMC_PATIDX_HDR_T_FLAGS SIZEOF(lbmc_patidx_hdr_t, flags)
#define O_LBMC_PATIDX_HDR_T_PATIDX OFFSETOF(lbmc_patidx_hdr_t, patidx)
#define L_LBMC_PATIDX_HDR_T_PATIDX SIZEOF(lbmc_patidx_hdr_t, patidx)
#define L_LBMC_PATIDX_HDR_T (gint) sizeof(lbmc_patidx_hdr_t)

/* LBMC control UME client lifetime header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t activity_tmo;
    lbm_uint32_t lifetime;
    lbm_uint32_t ttl;
} lbmc_cntl_ume_client_lifetime_hdr_t;
#define O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_client_lifetime_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_client_lifetime_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_client_lifetime_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_client_lifetime_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_client_lifetime_hdr_t, flags)
#define L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_client_lifetime_hdr_t, flags)
#define O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_ACTIVITY_TMO OFFSETOF(lbmc_cntl_ume_client_lifetime_hdr_t, activity_tmo)
#define L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_ACTIVITY_TMO SIZEOF(lbmc_cntl_ume_client_lifetime_hdr_t, activity_tmo)
#define O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_LIFETIME OFFSETOF(lbmc_cntl_ume_client_lifetime_hdr_t, lifetime)
#define L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_LIFETIME SIZEOF(lbmc_cntl_ume_client_lifetime_hdr_t, lifetime)
#define O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_TTL OFFSETOF(lbmc_cntl_ume_client_lifetime_hdr_t, ttl)
#define L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_TTL SIZEOF(lbmc_cntl_ume_client_lifetime_hdr_t, ttl)
#define L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T (gint) sizeof(lbmc_cntl_ume_client_lifetime_hdr_t)

/* LBMC control UME session ID header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint8_t sid[8];
} lbmc_cntl_ume_sid_hdr_t;
#define O_LBMC_CNTL_UME_SID_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_sid_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_SID_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_sid_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_SID_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_sid_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_SID_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_sid_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_SID_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_sid_hdr_t, flags)
#define L_LBMC_CNTL_UME_SID_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_sid_hdr_t, flags)
#define O_LBMC_CNTL_UME_SID_HDR_T_SID OFFSETOF(lbmc_cntl_ume_sid_hdr_t, sid)
#define L_LBMC_CNTL_UME_SID_HDR_T_SID SIZEOF(lbmc_cntl_ume_sid_hdr_t, sid)
#define L_LBMC_CNTL_UME_SID_HDR_T (gint) sizeof(lbmc_cntl_ume_sid_hdr_t)

/* LBMC control UMQ index command header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t cmd_type;
    lbm_uint32_t queue_id;
    lbm_uint16_t cmd_id;
    lbm_uint16_t inst_idx;
    lbm_uint8_t regid[8];
} lbmc_cntl_umq_idx_cmd_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_idx_cmd_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_idx_cmd_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_idx_cmd_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_idx_cmd_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_idx_cmd_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_idx_cmd_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_TYPE OFFSETOF(lbmc_cntl_umq_idx_cmd_hdr_t, cmd_type)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_TYPE SIZEOF(lbmc_cntl_umq_idx_cmd_hdr_t, cmd_type)
#define O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_idx_cmd_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_hdr_t, cmd_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_ID SIZEOF(lbmc_cntl_umq_idx_cmd_hdr_t, cmd_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_INST_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_hdr_t, inst_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_INST_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_hdr_t, inst_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_idx_cmd_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_REGID SIZEOF(lbmc_cntl_umq_idx_cmd_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_rcv_stop_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_rcv_stop_idx_assign_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_rcv_stop_idx_assign_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rcv_stop_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rcv_stop_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_rcv_stop_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_rcv_start_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_rcv_start_idx_assign_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_rcv_start_idx_assign_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rcv_start_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rcv_start_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_rcv_start_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint32_t flags;
    lbm_uint8_t index_len;
    lbm_uint8_t reserved[3];
} lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX_LEN OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, index_len)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX_LEN SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, index_len)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED + L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_SRC_ID OFFSETOF(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t, src_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_SRC_ID SIZEOF(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t, src_id)
#define O_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_SRC_ID OFFSETOF(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t, src_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_SRC_ID SIZEOF(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t, src_id)
#define O_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t src_id;
    lbm_uint32_t assign_id;
    lbm_uint32_t flags;
    lbm_uint16_t appset_idx;
    lbm_uint8_t index_len;
    lbm_uint8_t reserved[1];
} lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_SRC_ID OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, src_id)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_SRC_ID SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, src_id)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX_LEN OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, index_len)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX_LEN SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, index_len)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED + L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint32_t flags;
    lbm_uint8_t index_len;
    lbm_uint8_t reserved[3];
} lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, index_len)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, index_len)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED + L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED
#define L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t src_id;
    lbm_uint32_t assign_id;
    lbm_uint32_t flags;
    lbm_uint16_t appset_idx;
    lbm_uint8_t index_len;
    lbm_uint8_t reserved[1];
} lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_SRC_ID OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, src_id)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_SRC_ID SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, src_id)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, index_len)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, index_len)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED + L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED
#define L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t)

/* LBMC control UMQ index command response header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t resp_type;
    lbm_uint32_t queue_id;
    lbm_uint16_t cmd_id;
    lbm_uint16_t inst_idx;
    lbm_uint8_t regid[8];
} lbmc_cntl_umq_idx_cmd_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_RESP_TYPE OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, resp_type)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_RESP_TYPE SIZEOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, resp_type)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_CMD_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, cmd_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_CMD_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, cmd_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_INST_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, inst_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_INST_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, inst_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_REGID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_hdr_t)

typedef struct
{
    lbm_uint16_t reserved;
    lbm_uint16_t code;
} lbmc_cntl_umq_idx_cmd_resp_err_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_err_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_resp_err_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T_CODE OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_err_hdr_t, code)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T_CODE SIZEOF(lbmc_cntl_umq_idx_cmd_resp_err_hdr_t, code)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_err_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_idx_cmd_resp_rcv_stop_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_stop_idx_assign_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_stop_idx_assign_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_stop_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_stop_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_rcv_stop_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_SRC_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t, src_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_SRC_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t, src_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_SRC_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t, src_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_SRC_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t, src_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t src_id;
    lbm_uint32_t assign_id;
    lbm_uint16_t appset_idx;
    lbm_uint16_t reserved;
} lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_SRC_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t, src_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_SRC_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t, src_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint32_t flags;
    lbm_uint16_t appset_idx;
    lbm_uint8_t index_len;
    lbm_uint8_t reserved[1];
} lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, index_len)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, index_len)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED + L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t)

typedef struct
{
    lbm_uint32_t src_id;
    lbm_uint32_t assign_id;
    lbm_uint32_t flags;
    lbm_uint16_t appset_idx;
    lbm_uint8_t index_len;
    lbm_uint8_t reserved[1];
} lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t;
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_SRC_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, src_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_SRC_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, src_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, index_len)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, index_len)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED + L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED
#define L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T (gint) sizeof(lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t)

/* LBMC originating domain header (same as lbmc_domain_hdr_t) */
#define O_LBMC_ODOMAIN_HDR_T_NEXT_HDR OFFSETOF(lbmc_domain_hdr_t, next_hdr)
#define L_LBMC_ODOMAIN_HDR_T_NEXT_HDR SIZEOF(lbmc_domain_hdr_t, next_hdr)
#define O_LBMC_ODOMAIN_HDR_T_HDR_LEN OFFSETOF(lbmc_domain_hdr_t, hdr_len)
#define L_LBMC_ODOMAIN_HDR_T_HDR_LEN SIZEOF(lbmc_domain_hdr_t, hdr_len)
#define O_LBMC_ODOMAIN_HDR_T_FLAGS OFFSETOF(lbmc_domain_hdr_t, flags)
#define L_LBMC_ODOMAIN_HDR_T_FLAGS SIZEOF(lbmc_domain_hdr_t, flags)
#define O_LBMC_ODOMAIN_HDR_T_ODOMAIN OFFSETOF(lbmc_domain_hdr_t, domain)
#define L_LBMC_ODOMAIN_HDR_T_ODOMAIN SIZEOF(lbmc_domain_hdr_t, domain)
#define L_LBMC_ODOMAIN_HDR_T (gint) sizeof(lbmc_domain_hdr_t)

/* LBMC stream header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t stream_id;
    lbm_uint32_t sqn;
    lbm_uint8_t ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbmc_stream_hdr_t;
#define O_LBMC_STREAM_HDR_T_NEXT_HDR OFFSETOF(lbmc_stream_hdr_t, next_hdr)
#define L_LBMC_STREAM_HDR_T_NEXT_HDR SIZEOF(lbmc_stream_hdr_t, next_hdr)
#define O_LBMC_STREAM_HDR_T_HDR_LEN OFFSETOF(lbmc_stream_hdr_t, hdr_len)
#define L_LBMC_STREAM_HDR_T_HDR_LEN SIZEOF(lbmc_stream_hdr_t, hdr_len)
#define O_LBMC_STREAM_HDR_T_FLAGS OFFSETOF(lbmc_stream_hdr_t, flags)
#define L_LBMC_STREAM_HDR_T_FLAGS SIZEOF(lbmc_stream_hdr_t, flags)
#define O_LBMC_STREAM_HDR_T_STREAM_ID OFFSETOF(lbmc_stream_hdr_t, stream_id)
#define L_LBMC_STREAM_HDR_T_STREAM_ID SIZEOF(lbmc_stream_hdr_t, stream_id)
#define O_LBMC_STREAM_HDR_T_SQN OFFSETOF(lbmc_stream_hdr_t, sqn)
#define L_LBMC_STREAM_HDR_T_SQN SIZEOF(lbmc_stream_hdr_t, sqn)
#define O_LBMC_STREAM_HDR_T_CTXINST OFFSETOF(lbmc_stream_hdr_t, ctxinst)
#define L_LBMC_STREAM_HDR_T_CTXINST SIZEOF(lbmc_stream_hdr_t, ctxinst)
#define L_LBMC_STREAM_HDR_T (gint) sizeof(lbmc_stream_hdr_t)

/* LBMC control topic multi-domain interest header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint16_t domain_count;
    lbm_uint16_t res1;
} lbmc_cntl_topic_md_interest_hdr_t;
#define O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_topic_md_interest_hdr_t, next_hdr)
#define L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_topic_md_interest_hdr_t, next_hdr)
#define O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_topic_md_interest_hdr_t, hdr_len)
#define L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_topic_md_interest_hdr_t, hdr_len)
#define O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS OFFSETOF(lbmc_cntl_topic_md_interest_hdr_t, flags)
#define L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS SIZEOF(lbmc_cntl_topic_md_interest_hdr_t, flags)
#define O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_DOMAIN_COUNT OFFSETOF(lbmc_cntl_topic_md_interest_hdr_t, domain_count)
#define L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_DOMAIN_COUNT SIZEOF(lbmc_cntl_topic_md_interest_hdr_t, domain_count)
#define O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_RES1 OFFSETOF(lbmc_cntl_topic_md_interest_hdr_t, res1)
#define L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_RES1 SIZEOF(lbmc_cntl_topic_md_interest_hdr_t, res1)
#define L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T (gint) sizeof(lbmc_cntl_topic_md_interest_hdr_t)

/* LBMC control pattern multi-domain interest header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t type;
    lbm_uint16_t domain_count;
    lbm_uint16_t res1;
    lbm_uint8_t index[8];
} lbmc_cntl_pattern_md_interest_hdr_t;
#define O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_pattern_md_interest_hdr_t, next_hdr)
#define L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_pattern_md_interest_hdr_t, next_hdr)
#define O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_pattern_md_interest_hdr_t, hdr_len)
#define L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_pattern_md_interest_hdr_t, hdr_len)
#define O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS OFFSETOF(lbmc_cntl_pattern_md_interest_hdr_t, flags)
#define L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS SIZEOF(lbmc_cntl_pattern_md_interest_hdr_t, flags)
#define O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_TYPE OFFSETOF(lbmc_cntl_pattern_md_interest_hdr_t, type)
#define L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_TYPE SIZEOF(lbmc_cntl_pattern_md_interest_hdr_t, type)
#define O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_DOMAIN_COUNT OFFSETOF(lbmc_cntl_pattern_md_interest_hdr_t, domain_count)
#define L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_DOMAIN_COUNT SIZEOF(lbmc_cntl_pattern_md_interest_hdr_t, domain_count)
#define O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_RES1 OFFSETOF(lbmc_cntl_pattern_md_interest_hdr_t, res1)
#define L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_RES1 SIZEOF(lbmc_cntl_pattern_md_interest_hdr_t, res1)
#define O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_INDEX OFFSETOF(lbmc_cntl_pattern_md_interest_hdr_t, index)
#define L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_INDEX SIZEOF(lbmc_cntl_pattern_md_interest_hdr_t, index)
#define L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T (gint) sizeof(lbmc_cntl_pattern_md_interest_hdr_t)

/* LBMC control TNWG keepalive header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t index;
    lbm_uint8_t ts_seconds[8];
    lbm_uint32_t ts_microseconds;
    lbm_uint32_t reserved_1;
    lbm_uint8_t reserved_2[8];
    lbm_uint8_t reserved_3[8];
    lbm_uint8_t reserved_4[8];
    lbm_uint8_t reserved_5[8];
    lbm_uint8_t reserved_6[8];
} lbmc_cntl_tnwg_ka_hdr_t;
#define O_LBMC_CNTL_TNWG_KA_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, next_hdr)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, next_hdr)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, hdr_len)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, hdr_len)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, flags)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, flags)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_INDEX OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, index)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_INDEX SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, index)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_TS_SECONDS OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, ts_seconds)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_TS_SECONDS SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, ts_seconds)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_TS_MICROSECONDS OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, ts_microseconds)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_TS_MICROSECONDS SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, ts_microseconds)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_1 OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_1)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_1 SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_1)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_2 OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_2)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_2 SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_2)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_3 OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_3)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_3 SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_3)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_4 OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_4)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_4 SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_4)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_5 OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_5)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_5 SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_5)
#define O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_6 OFFSETOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_6)
#define L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_6 SIZEOF(lbmc_cntl_tnwg_ka_hdr_t, reserved_6)
#define L_LBMC_CNTL_TNWG_KA_HDR_T (gint) sizeof(lbmc_cntl_tnwg_ka_hdr_t)

/* LBMC control UME receiver keepalive header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t rcv_regid;
    lbm_uint64_t session_id;
    lbm_uint8_t ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbmc_cntl_ume_receiver_keepalive_hdr_t;
#define O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, flags)
#define L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, flags)
#define O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_RCV_REGID OFFSETOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, rcv_regid)
#define L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_RCV_REGID SIZEOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, rcv_regid)
#define O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_SESSION_ID OFFSETOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, session_id)
#define L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_SESSION_ID SIZEOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, session_id)
#define O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_CTXINST OFFSETOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, ctxinst)
#define L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_CTXINST SIZEOF(lbmc_cntl_ume_receiver_keepalive_hdr_t, ctxinst)
#define L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T (gint) sizeof(lbmc_cntl_ume_receiver_keepalive_hdr_t)

/* LBMC control UMQ command header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t cmd_type;
    lbm_uint32_t queue_id;
    lbm_uint16_t cmd_id;
    lbm_uint16_t inst_idx;
    lbm_uint8_t regid[8];
} lbmc_cntl_umq_cmd_hdr_t;
#define O_LBMC_CNTL_UMQ_CMD_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_cmd_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_cmd_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_CMD_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_cmd_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_cmd_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_CMD_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_cmd_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_cmd_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_TYPE OFFSETOF(lbmc_cntl_umq_cmd_hdr_t, cmd_type)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_TYPE SIZEOF(lbmc_cntl_umq_cmd_hdr_t, cmd_type)
#define O_LBMC_CNTL_UMQ_CMD_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_cmd_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_cmd_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_ID OFFSETOF(lbmc_cntl_umq_cmd_hdr_t, cmd_id)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_ID SIZEOF(lbmc_cntl_umq_cmd_hdr_t, cmd_id)
#define O_LBMC_CNTL_UMQ_CMD_HDR_T_INST_IDX OFFSETOF(lbmc_cntl_umq_cmd_hdr_t, inst_idx)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T_INST_IDX SIZEOF(lbmc_cntl_umq_cmd_hdr_t, inst_idx)
#define O_LBMC_CNTL_UMQ_CMD_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_cmd_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T_REGID SIZEOF(lbmc_cntl_umq_cmd_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_CMD_HDR_T (gint) sizeof(lbmc_cntl_umq_cmd_hdr_t)

typedef struct
{
    lbm_uint8_t serial_num[8];
} lbmc_cntl_umq_ctx_queue_topic_list_hdr_t;
#define O_LBMC_CNTL_UMQ_CTX_QUEUE_TOPIC_LIST_HDR_T_SERIAL_NUM OFFSETOF(lbmc_cntl_umq_ctx_queue_topic_list_hdr_t, serial_num)
#define L_LBMC_CNTL_UMQ_CTX_QUEUE_TOPIC_LIST_HDR_T_SERIAL_NUM SIZEOF(lbmc_cntl_umq_ctx_queue_topic_list_hdr_t, serial_num)
#define L_LBMC_CNTL_UMQ_CTX_QUEUE_TOPIC_LIST_HDR_T (gint) sizeof(lbmc_cntl_umq_ctx_queue_topic_list_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
    lbm_uint16_t info_only;
    lbm_uint8_t num_msgids;
    lbm_uint8_t flags;
} lbmc_cntl_umq_rcv_msg_retrieve_hdr_t;
#define O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, assign_id)
#define O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_INFO_ONLY OFFSETOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, info_only)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_INFO_ONLY SIZEOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, info_only)
#define O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGIDS OFFSETOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, num_msgids)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGIDS SIZEOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, num_msgids)
#define O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T (gint) sizeof(lbmc_cntl_umq_rcv_msg_retrieve_hdr_t)

typedef struct
{
    lbm_uint8_t regid[8];
    lbm_uint8_t stamp[8];
} lbmc_cntl_umq_rcv_msg_retrieve_entry_hdr_t;
#define O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_rcv_msg_retrieve_entry_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T_REGID SIZEOF(lbmc_cntl_umq_rcv_msg_retrieve_entry_hdr_t, regid)
#define O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STAMP OFFSETOF(lbmc_cntl_umq_rcv_msg_retrieve_entry_hdr_t, stamp)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STAMP SIZEOF(lbmc_cntl_umq_rcv_msg_retrieve_entry_hdr_t, stamp)
#define L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T (gint) sizeof(lbmc_cntl_umq_rcv_msg_retrieve_entry_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_rcv_msg_list_hdr_t;
#define O_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_rcv_msg_list_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_rcv_msg_list_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_rcv_msg_list_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_rcv_msg_list_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T (gint) sizeof(lbmc_cntl_umq_rcv_msg_list_hdr_t)

/* LBMC control UMQ command response header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t resp_type;
    lbm_uint32_t queue_id;
    lbm_uint16_t cmd_id;
    lbm_uint16_t inst_idx;
    lbm_uint8_t regid[8];
} lbmc_cntl_umq_cmd_resp_hdr_t;
#define O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_cmd_resp_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_cmd_resp_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_cmd_resp_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_cmd_resp_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_cmd_resp_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_cmd_resp_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_RESP_TYPE OFFSETOF(lbmc_cntl_umq_cmd_resp_hdr_t, resp_type)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_RESP_TYPE SIZEOF(lbmc_cntl_umq_cmd_resp_hdr_t, resp_type)
#define O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_QUEUE_ID OFFSETOF(lbmc_cntl_umq_cmd_resp_hdr_t, queue_id)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_QUEUE_ID SIZEOF(lbmc_cntl_umq_cmd_resp_hdr_t, queue_id)
#define O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_CMD_ID OFFSETOF(lbmc_cntl_umq_cmd_resp_hdr_t, cmd_id)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_CMD_ID SIZEOF(lbmc_cntl_umq_cmd_resp_hdr_t, cmd_id)
#define O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_INST_IDX OFFSETOF(lbmc_cntl_umq_cmd_resp_hdr_t, inst_idx)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_INST_IDX SIZEOF(lbmc_cntl_umq_cmd_resp_hdr_t, inst_idx)
#define O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_REGID OFFSETOF(lbmc_cntl_umq_cmd_resp_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_REGID SIZEOF(lbmc_cntl_umq_cmd_resp_hdr_t, regid)
#define L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T (gint) sizeof(lbmc_cntl_umq_cmd_resp_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t;
#define O_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T (gint) sizeof(lbmc_cntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t)

typedef struct
{
    lbm_uint8_t num_msgs;
    lbm_uint8_t flags;
    lbm_uint16_t reserved;
} lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t;
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGS OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, num_msgs)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGS SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, num_msgs)
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_FLAGS OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, flags)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_FLAGS SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, flags)
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_RESERVED OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, reserved)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_RESERVED SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t, reserved)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T (gint) sizeof(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t)

typedef struct
{
    lbm_uint8_t regid[8];
    lbm_uint8_t stamp[8];
    lbm_uint32_t assign_id;
    lbm_uint16_t num_ras;
    lbm_uint8_t status;
    lbm_uint8_t reserved;
} lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t;
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_REGID OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, regid)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_REGID SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, regid)
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STAMP OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, stamp)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STAMP SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, stamp)
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_ASSIGN_ID OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, assign_id)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_ASSIGN_ID SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, assign_id)
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_NUM_RAS OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, num_ras)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_NUM_RAS SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, num_ras)
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STATUS OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, status)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STATUS SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, status)
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_RESERVED OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, reserved)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_RESERVED SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t, reserved)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T (gint) sizeof(lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint32_t assign_id;
} lbmc_cntl_umq_cmd_resp_rcv_msg_list_hdr_t;
#define O_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_cmd_resp_rcv_msg_list_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_cmd_resp_rcv_msg_list_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_ASSIGN_ID OFFSETOF(lbmc_cntl_umq_cmd_resp_rcv_msg_list_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_ASSIGN_ID SIZEOF(lbmc_cntl_umq_cmd_resp_rcv_msg_list_hdr_t, assign_id)
#define L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T (gint) sizeof(lbmc_cntl_umq_cmd_resp_rcv_msg_list_hdr_t)

typedef struct
{
    lbm_uint8_t num_msgs[8];
} lbmc_xcntl_umq_cmd_resp_rcv_msg_list_hdr_t;
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_NUM_MSGS OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_list_hdr_t, num_msgs)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_NUM_MSGS SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_list_hdr_t, num_msgs)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T (gint) sizeof(lbmc_xcntl_umq_cmd_resp_rcv_msg_list_hdr_t)

typedef struct
{
    lbm_uint8_t regid[8];
    lbm_uint8_t stamp[8];
} lbmc_xcntl_umq_cmd_resp_rcv_msg_list_msg_entry_hdr_t;
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T_REGID OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_list_msg_entry_hdr_t, regid)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T_REGID SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_list_msg_entry_hdr_t, regid)
#define O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T_STAMP OFFSETOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_list_msg_entry_hdr_t, stamp)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T_STAMP SIZEOF(lbmc_xcntl_umq_cmd_resp_rcv_msg_list_msg_entry_hdr_t, stamp)
#define L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T (gint) sizeof(lbmc_xcntl_umq_cmd_resp_rcv_msg_list_msg_entry_hdr_t)

typedef struct
{
    lbm_uint32_t num_topics;
} lbmc_cntl_umq_cmd_resp_ctx_topic_list_hdr_t;
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_HDR_T_NUM_TOPICS OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_hdr_t, num_topics)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_HDR_T_NUM_TOPICS SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_hdr_t, num_topics)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_HDR_T (gint) sizeof(lbmc_cntl_umq_cmd_resp_ctx_topic_list_hdr_t)

typedef struct
{
    lbm_uint16_t num_receiver_type_ids;
    lbm_uint16_t appset_idx;
    lbm_uint8_t appset_name_len;
    lbm_uint8_t reserved[3];
} lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t;
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_NUM_RECEIVER_TYPE_IDS OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t, num_receiver_type_ids)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_NUM_RECEIVER_TYPE_IDS SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t, num_receiver_type_ids)
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_IDX OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t, appset_idx)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_IDX SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t, appset_idx)
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_NAME_LEN OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t, appset_name_len)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_NAME_LEN SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t, appset_name_len)
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T (gint) sizeof(lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t)

typedef struct
{
    lbm_uint32_t rcr_idx;
    lbm_uint16_t num_appsets;
    lbm_uint8_t topic_len;
    lbm_uint8_t reserved;
} lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t;
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_RCR_IDX OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t, rcr_idx)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_RCR_IDX SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t, rcr_idx)
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_NUM_APPSETS OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t, num_appsets)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_NUM_APPSETS SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t, num_appsets)
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_TOPIC_LEN OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t, topic_len)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_TOPIC_LEN SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t, topic_len)
#define O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T (gint) sizeof(lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t)

typedef struct
{
    lbm_uint16_t reserved;
    lbm_uint16_t code;
} lbmc_cntl_umq_cmd_resp_err_hdr_t;
#define O_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T_RESERVED OFFSETOF(lbmc_cntl_umq_cmd_resp_err_hdr_t, reserved)
#define L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T_RESERVED SIZEOF(lbmc_cntl_umq_cmd_resp_err_hdr_t, reserved)
#define O_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T_CODE OFFSETOF(lbmc_cntl_umq_cmd_resp_err_hdr_t, code)
#define L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T_CODE SIZEOF(lbmc_cntl_umq_cmd_resp_err_hdr_t, code)
#define L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T (gint) sizeof(lbmc_cntl_umq_cmd_resp_err_hdr_t)

/* LBMC control source registration information request header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t transport_idx;
    lbm_uint32_t topic_idx;
} lbmc_cntl_sri_req_hdr_t;
#define O_LBMC_CNTL_SRI_REQ_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_sri_req_hdr_t, next_hdr)
#define L_LBMC_CNTL_SRI_REQ_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_sri_req_hdr_t, next_hdr)
#define O_LBMC_CNTL_SRI_REQ_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_sri_req_hdr_t, hdr_len)
#define L_LBMC_CNTL_SRI_REQ_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_sri_req_hdr_t, hdr_len)
#define O_LBMC_CNTL_SRI_REQ_HDR_T_FLAGS OFFSETOF(lbmc_cntl_sri_req_hdr_t, flags)
#define L_LBMC_CNTL_SRI_REQ_HDR_T_FLAGS SIZEOF(lbmc_cntl_sri_req_hdr_t, flags)
#define O_LBMC_CNTL_SRI_REQ_HDR_T_TRANSPORT_IDX OFFSETOF(lbmc_cntl_sri_req_hdr_t, transport_idx)
#define L_LBMC_CNTL_SRI_REQ_HDR_T_TRANSPORT_IDX SIZEOF(lbmc_cntl_sri_req_hdr_t, transport_idx)
#define O_LBMC_CNTL_SRI_REQ_HDR_T_TOPIC_IDX OFFSETOF(lbmc_cntl_sri_req_hdr_t, topic_idx)
#define L_LBMC_CNTL_SRI_REQ_HDR_T_TOPIC_IDX SIZEOF(lbmc_cntl_sri_req_hdr_t, topic_idx)
#define L_LBMC_CNTL_SRI_REQ_HDR_T (gint) sizeof(lbmc_cntl_sri_req_hdr_t)

/* LBMC control UME store domain header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t domain;
} lbmc_cntl_ume_store_domain_hdr_t;
#define O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_store_domain_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_store_domain_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_store_domain_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_store_domain_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_store_domain_hdr_t, flags)
#define L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_store_domain_hdr_t, flags)
#define O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_DOMAIN OFFSETOF(lbmc_cntl_ume_store_domain_hdr_t, domain)
#define L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_DOMAIN SIZEOF(lbmc_cntl_ume_store_domain_hdr_t, domain)
#define L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T (gint) sizeof(lbmc_cntl_ume_store_domain_hdr_t)

/* LBMC control source registration information header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t version;
    lbm_uint32_t low_sqn;
    lbm_uint32_t high_sqn;
} lbmc_cntl_sri_hdr_t;
#define O_LBMC_CNTL_SRI_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_sri_hdr_t, next_hdr)
#define L_LBMC_CNTL_SRI_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_sri_hdr_t, next_hdr)
#define O_LBMC_CNTL_SRI_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_sri_hdr_t, hdr_len)
#define L_LBMC_CNTL_SRI_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_sri_hdr_t, hdr_len)
#define O_LBMC_CNTL_SRI_HDR_T_FLAGS OFFSETOF(lbmc_cntl_sri_hdr_t, flags)
#define L_LBMC_CNTL_SRI_HDR_T_FLAGS SIZEOF(lbmc_cntl_sri_hdr_t, flags)
#define O_LBMC_CNTL_SRI_HDR_T_VERSION OFFSETOF(lbmc_cntl_sri_hdr_t, version)
#define L_LBMC_CNTL_SRI_HDR_T_VERSION SIZEOF(lbmc_cntl_sri_hdr_t, version)
#define O_LBMC_CNTL_SRI_HDR_T_LOW_SQN OFFSETOF(lbmc_cntl_sri_hdr_t, low_sqn)
#define L_LBMC_CNTL_SRI_HDR_T_LOW_SQN SIZEOF(lbmc_cntl_sri_hdr_t, low_sqn)
#define O_LBMC_CNTL_SRI_HDR_T_HIGH_SQN OFFSETOF(lbmc_cntl_sri_hdr_t, high_sqn)
#define L_LBMC_CNTL_SRI_HDR_T_HIGH_SQN SIZEOF(lbmc_cntl_sri_hdr_t, high_sqn)
#define L_LBMC_CNTL_SRI_HDR_T (gint) sizeof(lbmc_cntl_sri_hdr_t)

/* LBMC control route information header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t gateway_version;
    lbm_uint32_t configuration_signature;
    lbm_uint8_t node_id[8];
    lbm_uint32_t topology;
    lbm_uint16_t vers;
    lbm_uint16_t sqn;
    lbm_uint8_t ttl;
    lbm_uint8_t reserved1;
    lbm_uint16_t reserved2;
} lbmc_cntl_route_info_hdr_t;
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_route_info_hdr_t, next_hdr)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_route_info_hdr_t, next_hdr)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_route_info_hdr_t, hdr_len)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_route_info_hdr_t, hdr_len)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_FLAGS OFFSETOF(lbmc_cntl_route_info_hdr_t, flags)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_FLAGS SIZEOF(lbmc_cntl_route_info_hdr_t, flags)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_GATEWAY_VERSION OFFSETOF(lbmc_cntl_route_info_hdr_t, gateway_version)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_GATEWAY_VERSION SIZEOF(lbmc_cntl_route_info_hdr_t, gateway_version)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_CONFIGURATION_SIGNATURE OFFSETOF(lbmc_cntl_route_info_hdr_t, configuration_signature)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_CONFIGURATION_SIGNATURE SIZEOF(lbmc_cntl_route_info_hdr_t, configuration_signature)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_NODE_ID OFFSETOF(lbmc_cntl_route_info_hdr_t, node_id)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_NODE_ID SIZEOF(lbmc_cntl_route_info_hdr_t, node_id)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_TOPOLOGY OFFSETOF(lbmc_cntl_route_info_hdr_t, topology)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_TOPOLOGY SIZEOF(lbmc_cntl_route_info_hdr_t, topology)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_VERS OFFSETOF(lbmc_cntl_route_info_hdr_t, vers)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_VERS SIZEOF(lbmc_cntl_route_info_hdr_t, vers)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_SQN OFFSETOF(lbmc_cntl_route_info_hdr_t, sqn)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_SQN SIZEOF(lbmc_cntl_route_info_hdr_t, sqn)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_TTL OFFSETOF(lbmc_cntl_route_info_hdr_t, ttl)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_TTL SIZEOF(lbmc_cntl_route_info_hdr_t, ttl)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_RESERVED1 OFFSETOF(lbmc_cntl_route_info_hdr_t, reserved1)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_RESERVED1 SIZEOF(lbmc_cntl_route_info_hdr_t, reserved1)
#define O_LBMC_CNTL_ROUTE_INFO_HDR_T_RESERVED2 OFFSETOF(lbmc_cntl_route_info_hdr_t, reserved2)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T_RESERVED2 SIZEOF(lbmc_cntl_route_info_hdr_t, reserved2)
#define L_LBMC_CNTL_ROUTE_INFO_HDR_T (gint) sizeof(lbmc_cntl_route_info_hdr_t)

/* LBMC control route information neighbor header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint8_t node_id[8];
    lbm_uint32_t ingress_cost;
    lbm_uint32_t egress_cost;
} lbmc_cntl_route_info_neighbor_hdr_t;
#define O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_route_info_neighbor_hdr_t, next_hdr)
#define L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_route_info_neighbor_hdr_t, next_hdr)
#define O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_route_info_neighbor_hdr_t, hdr_len)
#define L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_route_info_neighbor_hdr_t, hdr_len)
#define O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_FLAGS OFFSETOF(lbmc_cntl_route_info_neighbor_hdr_t, flags)
#define L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_FLAGS SIZEOF(lbmc_cntl_route_info_neighbor_hdr_t, flags)
#define O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_NODE_ID OFFSETOF(lbmc_cntl_route_info_neighbor_hdr_t, node_id)
#define L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_NODE_ID SIZEOF(lbmc_cntl_route_info_neighbor_hdr_t, node_id)
#define O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_INGRESS_COST OFFSETOF(lbmc_cntl_route_info_neighbor_hdr_t, ingress_cost)
#define L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_INGRESS_COST SIZEOF(lbmc_cntl_route_info_neighbor_hdr_t, ingress_cost)
#define O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_EGRESS_COST OFFSETOF(lbmc_cntl_route_info_neighbor_hdr_t, egress_cost)
#define L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_EGRESS_COST SIZEOF(lbmc_cntl_route_info_neighbor_hdr_t, egress_cost)
#define L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T (gint) sizeof(lbmc_cntl_route_info_neighbor_hdr_t)

/* LBMC control gateway name header. */
#define O_LBMC_CNTL_GATEWAY_NAME_HDR_T_NEXT_HDR OFFSETOF(lbmc_basic_hdr_t, next_hdr)
#define L_LBMC_CNTL_GATEWAY_NAME_HDR_T_NEXT_HDR SIZEOF(lbmc_basic_hdr_t, next_hdr)
#define O_LBMC_CNTL_GATEWAY_NAME_HDR_T_HDR_LEN OFFSETOF(lbmc_basic_hdr_t, hdr_len)
#define L_LBMC_CNTL_GATEWAY_NAME_HDR_T_HDR_LEN SIZEOF(lbmc_basic_hdr_t, hdr_len)
#define O_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS OFFSETOF(lbmc_basic_hdr_t, res)
#define L_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS SIZEOF(lbmc_basic_hdr_t, res)
#define O_LBMC_CNTL_GATEWAY_NAME_HDR_T_NAME (OFFSETOF(lbmc_basic_hdr_t, res) + SIZEOF(lbmc_basic_hdr_t, res))

/* LBMC control generic authentication header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t opid;
} lbmc_cntl_auth_generic_hdr_t;
#define O_LBMC_CNTL_AUTH_GENERIC_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_auth_generic_hdr_t, next_hdr)
#define L_LBMC_CNTL_AUTH_GENERIC_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_auth_generic_hdr_t, next_hdr)
#define O_LBMC_CNTL_AUTH_GENERIC_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_auth_generic_hdr_t, hdr_len)
#define L_LBMC_CNTL_AUTH_GENERIC_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_auth_generic_hdr_t, hdr_len)
#define O_LBMC_CNTL_AUTH_GENERIC_HDR_T_FLAGS OFFSETOF(lbmc_cntl_auth_generic_hdr_t, flags)
#define L_LBMC_CNTL_AUTH_GENERIC_HDR_T_FLAGS SIZEOF(lbmc_cntl_auth_generic_hdr_t, flags)
#define O_LBMC_CNTL_AUTH_GENERIC_HDR_T_OPID OFFSETOF(lbmc_cntl_auth_generic_hdr_t, opid)
#define L_LBMC_CNTL_AUTH_GENERIC_HDR_T_OPID SIZEOF(lbmc_cntl_auth_generic_hdr_t, opid)
#define L_LBMC_CNTL_AUTH_GENERIC_HDR_T (gint) sizeof(lbmc_cntl_auth_generic_hdr_t)

/* LBMC control authentication request header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t opid;
    lbm_uint8_t user_len;
} lbmc_cntl_auth_request_hdr_t;
#define O_LBMC_CNTL_AUTH_REQUEST_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_auth_request_hdr_t, next_hdr)
#define L_LBMC_CNTL_AUTH_REQUEST_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_auth_request_hdr_t, next_hdr)
#define O_LBMC_CNTL_AUTH_REQUEST_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_auth_request_hdr_t, hdr_len)
#define L_LBMC_CNTL_AUTH_REQUEST_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_auth_request_hdr_t, hdr_len)
#define O_LBMC_CNTL_AUTH_REQUEST_HDR_T_FLAGS OFFSETOF(lbmc_cntl_auth_request_hdr_t, flags)
#define L_LBMC_CNTL_AUTH_REQUEST_HDR_T_FLAGS SIZEOF(lbmc_cntl_auth_request_hdr_t, flags)
#define O_LBMC_CNTL_AUTH_REQUEST_HDR_T_OPID OFFSETOF(lbmc_cntl_auth_request_hdr_t, opid)
#define L_LBMC_CNTL_AUTH_REQUEST_HDR_T_OPID SIZEOF(lbmc_cntl_auth_request_hdr_t, opid)
#define O_LBMC_CNTL_AUTH_REQUEST_HDR_T_USER_LEN OFFSETOF(lbmc_cntl_auth_request_hdr_t, user_len)
#define L_LBMC_CNTL_AUTH_REQUEST_HDR_T_USER_LEN SIZEOF(lbmc_cntl_auth_request_hdr_t, user_len)
#define L_LBMC_CNTL_AUTH_REQUEST_HDR_T (gint) sizeof(lbmc_cntl_auth_request_hdr_t)

/* LBMC control authentication challenge header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t opid;
    lbm_uint8_t mod_len;
    lbm_uint8_t gen_len;
    lbm_uint8_t salt_len;
    lbm_uint8_t pubkey_len;
} lbmc_cntl_auth_challenge_hdr_t;
#define O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_auth_challenge_hdr_t, next_hdr)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_auth_challenge_hdr_t, next_hdr)
#define O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_auth_challenge_hdr_t, hdr_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_auth_challenge_hdr_t, hdr_len)
#define O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_FLAGS OFFSETOF(lbmc_cntl_auth_challenge_hdr_t, flags)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_FLAGS SIZEOF(lbmc_cntl_auth_challenge_hdr_t, flags)
#define O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_OPID OFFSETOF(lbmc_cntl_auth_challenge_hdr_t, opid)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_OPID SIZEOF(lbmc_cntl_auth_challenge_hdr_t, opid)
#define O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_MOD_LEN OFFSETOF(lbmc_cntl_auth_challenge_hdr_t, mod_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_MOD_LEN SIZEOF(lbmc_cntl_auth_challenge_hdr_t, mod_len)
#define O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_GEN_LEN OFFSETOF(lbmc_cntl_auth_challenge_hdr_t, gen_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_GEN_LEN SIZEOF(lbmc_cntl_auth_challenge_hdr_t, gen_len)
#define O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_SALT_LEN OFFSETOF(lbmc_cntl_auth_challenge_hdr_t, salt_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_SALT_LEN SIZEOF(lbmc_cntl_auth_challenge_hdr_t, salt_len)
#define O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_PUBKEY_LEN OFFSETOF(lbmc_cntl_auth_challenge_hdr_t, pubkey_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_PUBKEY_LEN SIZEOF(lbmc_cntl_auth_challenge_hdr_t, pubkey_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T (gint) sizeof(lbmc_cntl_auth_challenge_hdr_t)

/* LBMC control authentication challenge response header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t opid;
    lbm_uint8_t pubkey_len;
    lbm_uint8_t evidence_len;
} lbmc_cntl_auth_challenge_rsp_hdr_t;
#define O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_auth_challenge_rsp_hdr_t, next_hdr)
#define L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_auth_challenge_rsp_hdr_t, next_hdr)
#define O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_auth_challenge_rsp_hdr_t, hdr_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_auth_challenge_rsp_hdr_t, hdr_len)
#define O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_FLAGS OFFSETOF(lbmc_cntl_auth_challenge_rsp_hdr_t, flags)
#define L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_FLAGS SIZEOF(lbmc_cntl_auth_challenge_rsp_hdr_t, flags)
#define O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_OPID OFFSETOF(lbmc_cntl_auth_challenge_rsp_hdr_t, opid)
#define L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_OPID SIZEOF(lbmc_cntl_auth_challenge_rsp_hdr_t, opid)
#define O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_PUBKEY_LEN OFFSETOF(lbmc_cntl_auth_challenge_rsp_hdr_t, pubkey_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_PUBKEY_LEN SIZEOF(lbmc_cntl_auth_challenge_rsp_hdr_t, pubkey_len)
#define O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_EVIDENCE_LEN OFFSETOF(lbmc_cntl_auth_challenge_rsp_hdr_t, evidence_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_EVIDENCE_LEN SIZEOF(lbmc_cntl_auth_challenge_rsp_hdr_t, evidence_len)
#define L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T (gint) sizeof(lbmc_cntl_auth_challenge_rsp_hdr_t)

/* LBMC control authentication result header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t opid;
    lbm_uint8_t result;
} lbmc_cntl_auth_result_hdr_t;
#define O_LBMC_CNTL_AUTH_RESULT_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_auth_result_hdr_t, next_hdr)
#define L_LBMC_CNTL_AUTH_RESULT_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_auth_result_hdr_t, next_hdr)
#define O_LBMC_CNTL_AUTH_RESULT_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_auth_result_hdr_t, hdr_len)
#define L_LBMC_CNTL_AUTH_RESULT_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_auth_result_hdr_t, hdr_len)
#define O_LBMC_CNTL_AUTH_RESULT_HDR_T_FLAGS OFFSETOF(lbmc_cntl_auth_result_hdr_t, flags)
#define L_LBMC_CNTL_AUTH_RESULT_HDR_T_FLAGS SIZEOF(lbmc_cntl_auth_result_hdr_t, flags)
#define O_LBMC_CNTL_AUTH_RESULT_HDR_T_OPID OFFSETOF(lbmc_cntl_auth_result_hdr_t, opid)
#define L_LBMC_CNTL_AUTH_RESULT_HDR_T_OPID SIZEOF(lbmc_cntl_auth_result_hdr_t, opid)
#define O_LBMC_CNTL_AUTH_RESULT_HDR_T_RESULT OFFSETOF(lbmc_cntl_auth_result_hdr_t, result)
#define L_LBMC_CNTL_AUTH_RESULT_HDR_T_RESULT SIZEOF(lbmc_cntl_auth_result_hdr_t, result)
#define L_LBMC_CNTL_AUTH_RESULT_HDR_T (gint) sizeof(lbmc_cntl_auth_result_hdr_t)

/* LBMC control HMAC header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t padding;
    lbm_uint8_t data[LBM_HMAC_BLOCK_SZ];
} lbmc_cntl_hmac_hdr_t;
#define O_LBMC_CNTL_HMAC_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_hmac_hdr_t, next_hdr)
#define L_LBMC_CNTL_HMAC_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_hmac_hdr_t, next_hdr)
#define O_LBMC_CNTL_HMAC_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_hmac_hdr_t, hdr_len)
#define L_LBMC_CNTL_HMAC_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_hmac_hdr_t, hdr_len)
#define O_LBMC_CNTL_HMAC_HDR_T_FLAGS OFFSETOF(lbmc_cntl_hmac_hdr_t, flags)
#define L_LBMC_CNTL_HMAC_HDR_T_FLAGS SIZEOF(lbmc_cntl_hmac_hdr_t, flags)
#define O_LBMC_CNTL_HMAC_HDR_T_PADDING OFFSETOF(lbmc_cntl_hmac_hdr_t, padding)
#define L_LBMC_CNTL_HMAC_HDR_T_PADDING SIZEOF(lbmc_cntl_hmac_hdr_t, padding)
#define O_LBMC_CNTL_HMAC_HDR_T_DATA OFFSETOF(lbmc_cntl_hmac_hdr_t, data)
#define L_LBMC_CNTL_HMAC_HDR_T_DATA SIZEOF(lbmc_cntl_hmac_hdr_t, data)
#define L_LBMC_CNTL_HMAC_HDR_T (gint) sizeof(lbmc_cntl_hmac_hdr_t)

/* LBMC control UMQ session ID header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t key;
    lbm_uint8_t sid[8];
} lbmc_cntl_umq_sid_hdr_t;
#define O_LBMC_CNTL_UMQ_SID_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_umq_sid_hdr_t, next_hdr)
#define L_LBMC_CNTL_UMQ_SID_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_umq_sid_hdr_t, next_hdr)
#define O_LBMC_CNTL_UMQ_SID_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_umq_sid_hdr_t, hdr_len)
#define L_LBMC_CNTL_UMQ_SID_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_umq_sid_hdr_t, hdr_len)
#define O_LBMC_CNTL_UMQ_SID_HDR_T_FLAGS OFFSETOF(lbmc_cntl_umq_sid_hdr_t, flags)
#define L_LBMC_CNTL_UMQ_SID_HDR_T_FLAGS SIZEOF(lbmc_cntl_umq_sid_hdr_t, flags)
#define O_LBMC_CNTL_UMQ_SID_HDR_T_KEY OFFSETOF(lbmc_cntl_umq_sid_hdr_t, key)
#define L_LBMC_CNTL_UMQ_SID_HDR_T_KEY SIZEOF(lbmc_cntl_umq_sid_hdr_t, key)
#define O_LBMC_CNTL_UMQ_SID_HDR_T_SID OFFSETOF(lbmc_cntl_umq_sid_hdr_t, sid)
#define L_LBMC_CNTL_UMQ_SID_HDR_T_SID SIZEOF(lbmc_cntl_umq_sid_hdr_t, sid)
#define L_LBMC_CNTL_UMQ_SID_HDR_T (gint) sizeof(lbmc_cntl_umq_sid_hdr_t)

/* LBMC destination header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t domain_id;
    lbm_uint32_t ipaddr;
    lbm_uint16_t port;
    lbm_uint16_t hops_taken;
    lbm_uint32_t orig_domain_id;
    lbm_uint32_t orig_ipaddr;
    lbm_uint16_t orig_port;
    lbm_uint16_t reserved;
} lbmc_destination_hdr_t;
#define O_LBMC_DESTINATION_HDR_T_NEXT_HDR OFFSETOF(lbmc_destination_hdr_t, next_hdr)
#define L_LBMC_DESTINATION_HDR_T_NEXT_HDR SIZEOF(lbmc_destination_hdr_t, next_hdr)
#define O_LBMC_DESTINATION_HDR_T_HDR_LEN OFFSETOF(lbmc_destination_hdr_t, hdr_len)
#define L_LBMC_DESTINATION_HDR_T_HDR_LEN SIZEOF(lbmc_destination_hdr_t, hdr_len)
#define O_LBMC_DESTINATION_HDR_T_FLAGS OFFSETOF(lbmc_destination_hdr_t, flags)
#define L_LBMC_DESTINATION_HDR_T_FLAGS SIZEOF(lbmc_destination_hdr_t, flags)
#define O_LBMC_DESTINATION_HDR_T_DOMAIN_ID OFFSETOF(lbmc_destination_hdr_t, domain_id)
#define L_LBMC_DESTINATION_HDR_T_DOMAIN_ID SIZEOF(lbmc_destination_hdr_t, domain_id)
#define O_LBMC_DESTINATION_HDR_T_IPADDR OFFSETOF(lbmc_destination_hdr_t, ipaddr)
#define L_LBMC_DESTINATION_HDR_T_IPADDR SIZEOF(lbmc_destination_hdr_t, ipaddr)
#define O_LBMC_DESTINATION_HDR_T_PORT OFFSETOF(lbmc_destination_hdr_t, port)
#define L_LBMC_DESTINATION_HDR_T_PORT SIZEOF(lbmc_destination_hdr_t, port)
#define O_LBMC_DESTINATION_HDR_T_HOPS_TAKEN OFFSETOF(lbmc_destination_hdr_t, hops_taken)
#define L_LBMC_DESTINATION_HDR_T_HOPS_TAKEN SIZEOF(lbmc_destination_hdr_t, hops_taken)
#define O_LBMC_DESTINATION_HDR_T_ORIG_DOMAIN_ID OFFSETOF(lbmc_destination_hdr_t, orig_domain_id)
#define L_LBMC_DESTINATION_HDR_T_ORIG_DOMAIN_ID SIZEOF(lbmc_destination_hdr_t, orig_domain_id)
#define O_LBMC_DESTINATION_HDR_T_ORIG_IPADDR OFFSETOF(lbmc_destination_hdr_t, orig_ipaddr)
#define L_LBMC_DESTINATION_HDR_T_ORIG_IPADDR SIZEOF(lbmc_destination_hdr_t, orig_ipaddr)
#define O_LBMC_DESTINATION_HDR_T_ORIG_PORT OFFSETOF(lbmc_destination_hdr_t, orig_port)
#define L_LBMC_DESTINATION_HDR_T_ORIG_PORT SIZEOF(lbmc_destination_hdr_t, orig_port)
#define O_LBMC_DESTINATION_HDR_T_RESERVED OFFSETOF(lbmc_destination_hdr_t, reserved)
#define L_LBMC_DESTINATION_HDR_T_RESERVED SIZEOF(lbmc_destination_hdr_t, reserved)
#define L_LBMC_DESTINATION_HDR_T (gint) sizeof(lbmc_destination_hdr_t)

/* LBMC topic index header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t tidx;
} lbmc_topic_idx_hdr_t;
#define O_LBMC_TOPIC_IDX_HDR_T_NEXT_HDR OFFSETOF(lbmc_topic_idx_hdr_t, next_hdr)
#define L_LBMC_TOPIC_IDX_HDR_T_NEXT_HDR SIZEOF(lbmc_topic_idx_hdr_t, next_hdr)
#define O_LBMC_TOPIC_IDX_HDR_T_HDR_LEN OFFSETOF(lbmc_topic_idx_hdr_t, hdr_len)
#define L_LBMC_TOPIC_IDX_HDR_T_HDR_LEN SIZEOF(lbmc_topic_idx_hdr_t, hdr_len)
#define O_LBMC_TOPIC_IDX_HDR_T_FLAGS OFFSETOF(lbmc_topic_idx_hdr_t, flags)
#define L_LBMC_TOPIC_IDX_HDR_T_FLAGS SIZEOF(lbmc_topic_idx_hdr_t, flags)
#define O_LBMC_TOPIC_IDX_HDR_T_TIDX OFFSETOF(lbmc_topic_idx_hdr_t, tidx)
#define L_LBMC_TOPIC_IDX_HDR_T_TIDX SIZEOF(lbmc_topic_idx_hdr_t, tidx)
#define L_LBMC_TOPIC_IDX_HDR_T (gint) sizeof(lbmc_topic_idx_hdr_t)

/* LBMC control topic source header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t domain_id;
} lbmc_cntl_topic_source_hdr_t;
#define O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_topic_source_hdr_t, next_hdr)
#define L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_topic_source_hdr_t, next_hdr)
#define O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_topic_source_hdr_t, hdr_len)
#define L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_topic_source_hdr_t, hdr_len)
#define O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS OFFSETOF(lbmc_cntl_topic_source_hdr_t, flags)
#define L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS SIZEOF(lbmc_cntl_topic_source_hdr_t, flags)
#define O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_DOMAIN_ID OFFSETOF(lbmc_cntl_topic_source_hdr_t, domain_id)
#define L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_DOMAIN_ID SIZEOF(lbmc_cntl_topic_source_hdr_t, domain_id)
#define L_LBMC_CNTL_TOPIC_SOURCE_HDR_T (gint) sizeof(lbmc_cntl_topic_source_hdr_t)

/* LBMC control topic source extended functionality header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t src_ip;
    lbm_uint16_t src_port;
    lbm_uint16_t unused;
    lbm_uint32_t functionality_flags;
} lbmc_cntl_topic_source_exfunc_hdr_t;
#define O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_topic_source_exfunc_hdr_t, next_hdr)
#define L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_topic_source_exfunc_hdr_t, next_hdr)
#define O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_topic_source_exfunc_hdr_t, hdr_len)
#define L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_topic_source_exfunc_hdr_t, hdr_len)
#define O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FLAGS OFFSETOF(lbmc_cntl_topic_source_exfunc_hdr_t, flags)
#define L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FLAGS SIZEOF(lbmc_cntl_topic_source_exfunc_hdr_t, flags)
#define O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_SRC_IP OFFSETOF(lbmc_cntl_topic_source_exfunc_hdr_t, src_ip)
#define L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_SRC_IP SIZEOF(lbmc_cntl_topic_source_exfunc_hdr_t, src_ip)
#define O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_SRC_PORT OFFSETOF(lbmc_cntl_topic_source_exfunc_hdr_t, src_port)
#define L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_SRC_PORT SIZEOF(lbmc_cntl_topic_source_exfunc_hdr_t, src_port)
#define O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_UNUSED OFFSETOF(lbmc_cntl_topic_source_exfunc_hdr_t, unused)
#define L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_UNUSED SIZEOF(lbmc_cntl_topic_source_exfunc_hdr_t, unused)
#define O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS OFFSETOF(lbmc_cntl_topic_source_exfunc_hdr_t, functionality_flags)
#define L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS SIZEOF(lbmc_cntl_topic_source_exfunc_hdr_t, functionality_flags)
#define L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T (gint) sizeof(lbmc_cntl_topic_source_exfunc_hdr_t)

/* LBM control UME proxy source election token header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t store_index;
    lbm_uint32_t token;
} lbmc_cntl_ume_psrc_election_token_hdr_t;
#define O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_ume_psrc_election_token_hdr_t, next_hdr)
#define L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_ume_psrc_election_token_hdr_t, next_hdr)
#define O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_ume_psrc_election_token_hdr_t, hdr_len)
#define L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_ume_psrc_election_token_hdr_t, hdr_len)
#define O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_FLAGS OFFSETOF(lbmc_cntl_ume_psrc_election_token_hdr_t, flags)
#define L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_FLAGS SIZEOF(lbmc_cntl_ume_psrc_election_token_hdr_t, flags)
#define O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_STORE_INDEX OFFSETOF(lbmc_cntl_ume_psrc_election_token_hdr_t, store_index)
#define L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_STORE_INDEX SIZEOF(lbmc_cntl_ume_psrc_election_token_hdr_t, store_index)
#define O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_TOKEN OFFSETOF(lbmc_cntl_ume_psrc_election_token_hdr_t, token)
#define L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_TOKEN SIZEOF(lbmc_cntl_ume_psrc_election_token_hdr_t, token)
#define L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T (gint) sizeof(lbmc_cntl_ume_psrc_election_token_hdr_t)

/* LBM control TCP session ID header. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t flags;
    lbm_uint32_t sid;
} lbmc_cntl_tcp_sid_hdr_t;
#define O_LBMC_CNTL_TCP_SID_HDR_T_NEXT_HDR OFFSETOF(lbmc_cntl_tcp_sid_hdr_t, next_hdr)
#define L_LBMC_CNTL_TCP_SID_HDR_T_NEXT_HDR SIZEOF(lbmc_cntl_tcp_sid_hdr_t, next_hdr)
#define O_LBMC_CNTL_TCP_SID_HDR_T_HDR_LEN OFFSETOF(lbmc_cntl_tcp_sid_hdr_t, hdr_len)
#define L_LBMC_CNTL_TCP_SID_HDR_T_HDR_LEN SIZEOF(lbmc_cntl_tcp_sid_hdr_t, hdr_len)
#define O_LBMC_CNTL_TCP_SID_HDR_T_FLAGS OFFSETOF(lbmc_cntl_tcp_sid_hdr_t, flags)
#define L_LBMC_CNTL_TCP_SID_HDR_T_FLAGS SIZEOF(lbmc_cntl_tcp_sid_hdr_t, flags)
#define O_LBMC_CNTL_TCP_SID_HDR_T_SID OFFSETOF(lbmc_cntl_tcp_sid_hdr_t, sid)
#define L_LBMC_CNTL_TCP_SID_HDR_T_SID SIZEOF(lbmc_cntl_tcp_sid_hdr_t, sid)
#define L_LBMC_CNTL_TCP_SID_HDR_T (gint) sizeof(lbmc_cntl_tcp_sid_hdr_t)

/* LBMC extended configuration option. */
typedef struct
{
    lbm_uint8_t scope;
    lbm_uint8_t parent;
} lbmc_extopt_cfgopt_hdr_t;
#define O_LBMC_EXTOPT_CFGOPT_HDR_T_SCOPE OFFSETOF(lbmc_extopt_cfgopt_hdr_t, scope)
#define L_LBMC_EXTOPT_CFGOPT_HDR_T_SCOPE SIZEOF(lbmc_extopt_cfgopt_hdr_t, scope)
#define O_LBMC_EXTOPT_CFGOPT_HDR_T_PARENT OFFSETOF(lbmc_extopt_cfgopt_hdr_t, scope)
#define L_LBMC_EXTOPT_CFGOPT_HDR_T_PARENT SIZEOF(lbmc_extopt_cfgopt_hdr_t, scope)
#define L_LBMC_EXTOPT_CFGOPT_HDR_T (gint) sizeof(lbmc_extopt_cfgopt_hdr_t)

/* LBMC extended option. */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint8_t flags;
    lbm_uint8_t id;
    lbm_uint16_t subtype;
    lbm_uint16_t fragment_offset;
} lbmc_extopt_hdr_t;
#define O_LBMC_EXTOPT_HDR_T_NEXT_HDR OFFSETOF(lbmc_extopt_hdr_t, next_hdr)
#define L_LBMC_EXTOPT_HDR_T_NEXT_HDR SIZEOF(lbmc_extopt_hdr_t, next_hdr)
#define O_LBMC_EXTOPT_HDR_T_HDR_LEN OFFSETOF(lbmc_extopt_hdr_t, hdr_len)
#define L_LBMC_EXTOPT_HDR_T_HDR_LEN SIZEOF(lbmc_extopt_hdr_t, hdr_len)
#define O_LBMC_EXTOPT_HDR_T_FLAGS OFFSETOF(lbmc_extopt_hdr_t, flags)
#define L_LBMC_EXTOPT_HDR_T_FLAGS SIZEOF(lbmc_extopt_hdr_t, flags)
#define O_LBMC_EXTOPT_HDR_T_ID OFFSETOF(lbmc_extopt_hdr_t, id)
#define L_LBMC_EXTOPT_HDR_T_ID SIZEOF(lbmc_extopt_hdr_t, id)
#define O_LBMC_EXTOPT_HDR_T_SUBTYPE OFFSETOF(lbmc_extopt_hdr_t, subtype)
#define L_LBMC_EXTOPT_HDR_T_SUBTYPE SIZEOF(lbmc_extopt_hdr_t, subtype)
#define O_LBMC_EXTOPT_HDR_T_FRAGMENT_OFFSET OFFSETOF(lbmc_extopt_hdr_t, fragment_offset)
#define L_LBMC_EXTOPT_HDR_T_FRAGMENT_OFFSET SIZEOF(lbmc_extopt_hdr_t, fragment_offset)
#define L_LBMC_EXTOPT_HDR_T (gint) sizeof(lbmc_extopt_hdr_t)

/* LBMC message properties. */
typedef struct
{
    lbm_uint32_t key_offset;
    lbm_uint32_t value_offset;
    lbm_uint32_t hash;
    lbm_uint32_t type;
} lbm_msg_properties_hdr_t;
#define O_LBM_MSG_PROPERTIES_HDR_T_KEY_OFFSET OFFSETOF(lbm_msg_properties_hdr_t, key_offset)
#define L_LBM_MSG_PROPERTIES_HDR_T_KEY_OFFSET SIZEOF(lbm_msg_properties_hdr_t, key_offset)
#define O_LBM_MSG_PROPERTIES_HDR_T_VALUE_OFFSET OFFSETOF(lbm_msg_properties_hdr_t, value_offset)
#define L_LBM_MSG_PROPERTIES_HDR_T_VALUE_OFFSET SIZEOF(lbm_msg_properties_hdr_t, value_offset)
#define O_LBM_MSG_PROPERTIES_HDR_T_HASH OFFSETOF(lbm_msg_properties_hdr_t, hash)
#define L_LBM_MSG_PROPERTIES_HDR_T_HASH SIZEOF(lbm_msg_properties_hdr_t, hash)
#define O_LBM_MSG_PROPERTIES_HDR_T_TYPE OFFSETOF(lbm_msg_properties_hdr_t, type)
#define L_LBM_MSG_PROPERTIES_HDR_T_TYPE SIZEOF(lbm_msg_properties_hdr_t, type)
#define L_LBM_MSG_PROPERTIES_HDR_T (gint) sizeof(lbm_msg_properties_hdr_t)

typedef struct
{
    lbm_uint32_t magic;
    lbm_uint16_t num_fields;
    lbm_uint8_t vertype;
    lbm_uint8_t res;
} lbm_msg_properties_data_t;
#define O_LBM_MSG_PROPERTIES_DATA_T_MAGIC OFFSETOF(lbm_msg_properties_data_t, magic)
#define L_LBM_MSG_PROPERTIES_DATA_T_MAGIC SIZEOF(lbm_msg_properties_data_t, magic)
#define O_LBM_MSG_PROPERTIES_DATA_T_NUM_FIELDS OFFSETOF(lbm_msg_properties_data_t, num_fields)
#define L_LBM_MSG_PROPERTIES_DATA_T_NUM_FIELDS SIZEOF(lbm_msg_properties_data_t, num_fields)
#define O_LBM_MSG_PROPERTIES_DATA_T_VERTYPE OFFSETOF(lbm_msg_properties_data_t, vertype)
#define L_LBM_MSG_PROPERTIES_DATA_T_VERTYPE SIZEOF(lbm_msg_properties_data_t, vertype)
#define O_LBM_MSG_PROPERTIES_DATA_T_RES OFFSETOF(lbm_msg_properties_data_t, res)
#define L_LBM_MSG_PROPERTIES_DATA_T_RES SIZEOF(lbm_msg_properties_data_t, res)
#define L_LBM_MSG_PROPERTIES_DATA_T (gint) sizeof(lbm_msg_properties_data_t)

/* Unhandled header. */
#define O_LBMC_UNHANDLED_HDR_T_NEXT_HDR OFFSETOF(lbmc_basic_hdr_t, next_hdr)
#define L_LBMC_UNHANDLED_HDR_T_NEXT_HDR SIZEOF(lbmc_basic_hdr_t, next_hdr)
#define O_LBMC_UNHANDLED_HDR_T_HDR_LEN OFFSETOF(lbmc_basic_hdr_t, hdr_len)
#define L_LBMC_UNHANDLED_HDR_T_HDR_LEN SIZEOF(lbmc_basic_hdr_t, hdr_len)

/* End of LBMC header definitions. */

#define LBMC_VERSION 0x0

#define LBMC_TYPE_MESSAGE 0x00
#define LBMC_TYPE_EOT 0x01
#define LBMC_TYPE_PRORX 0x02
#define LBMC_TYPE_CONTROL 0x08
#define LBMC_TYPE_RETRANS 0x0A

#define LBMC_NHDR_DATA 0x00
#define LBMC_NHDR_FRAG 0x01
#define LBMC_NHDR_BATCH 0x02
#define LBMC_NHDR_TGIDX 0x03
#define LBMC_NHDR_REQUEST 0x04
#define LBMC_NHDR_TOPICNAME 0x05
#define LBMC_NHDR_APPHDR 0x06
#define LBMC_NHDR_APPHDR_CHAIN 0x07
#define LBMC_NHDR_UMQ_MSGID 0x08
#define LBMC_NHDR_UMQ_SQD_RCV 0x09
#define LBMC_NHDR_UMQ_RESUB 0x0A
#define LBMC_NHDR_OTID 0x0B
#define LBMC_NHDR_CTXINSTD 0x0C
#define LBMC_NHDR_CTXINSTR 0x0D
#define LBMC_NHDR_SRCIDX 0x0E
#define LBMC_NHDR_UMQ_ULB_MSG 0x0F
#define LBMC_NHDR_SSF_INIT 0x10
#define LBMC_NHDR_SSF_CREQ 0x11
#define LBMC_NHDR_UME_PREG 0x12
#define LBMC_NHDR_UME_PREG_RESP 0x13
#define LBMC_NHDR_UME_ACK 0x14
#define LBMC_NHDR_UME_RXREQ 0x15
#define LBMC_NHDR_UME_KEEPALIVE 0x16
#define LBMC_NHDR_UME_STOREID 0x17
#define LBMC_NHDR_UME_RANGED_ACK 0x18
#define LBMC_NHDR_UME_ACK_ID 0x19
#define LBMC_NHDR_UME_CAPABILITY 0x1A
#define LBMC_NHDR_UME_PROXY_SRC 0x1B
#define LBMC_NHDR_UME_STORE_GROUP 0x1C
#define LBMC_NHDR_UME_STORE_INFO 0x1D
#define LBMC_NHDR_UME_LJ_INFO 0x1E
#define LBMC_NHDR_TSNI 0x20
#define LBMC_NHDR_UMQ_REG 0x30
#define LBMC_NHDR_UMQ_REG_RESP 0x31
#define LBMC_NHDR_UMQ_ACK 0x32
#define LBMC_NHDR_UMQ_RCR 0x33
#define LBMC_NHDR_UMQ_KA 0x34
#define LBMC_NHDR_UMQ_RXREQ 0x35
#define LBMC_NHDR_UMQ_QMGMT 0x36
#define LBMC_NHDR_UMQ_RESUB_REQ 0x37
#define LBMC_NHDR_UMQ_RESUB_RESP 0x38
#define LBMC_NHDR_TOPIC_INTEREST 0x39
#define LBMC_NHDR_PATTERN_INTEREST 0x3A
#define LBMC_NHDR_ADVERTISEMENT 0x3B
#define LBMC_NHDR_UME_CTXINSTS 0x3C
#define LBMC_NHDR_UME_STORENAME 0x3D
#define LBMC_NHDR_UMQ_ULB_RCR 0x3E
#define LBMC_NHDR_UMQ_LF 0x3F
#define LBMC_NHDR_CTXINFO 0x40
#define LBMC_NHDR_UME_PSER 0x41
#define LBMC_NHDR_CTXINST 0x42
#define LBMC_NHDR_DOMAIN 0x43
#define LBMC_NHDR_TNWG_CAPABILITIES 0x44
#define LBMC_NHDR_PATIDX 0x45
#define LBMC_NHDR_UME_CLIENT_LIFETIME 0x46
#define LBMC_NHDR_UME_SID 0x47
#define LBMC_NHDR_UMQ_IDX_CMD 0x48
#define LBMC_NHDR_UMQ_IDX_CMD_RESP 0x49
#define LBMC_NHDR_ODOMAIN 0x4a
#define LBMC_NHDR_STREAM 0x4b
#define LBMC_NHDR_TOPIC_MD_INTEREST 0x4c
#define LBMC_NHDR_PATTERN_MD_INTEREST 0x4d
#define LBMC_NHDR_LJI_REQ 0x4e
#define LBMC_NHDR_TNWG_KA 0x4f
#define LBMC_NHDR_UME_RCV_KEEPALIVE 0x50
#define LBMC_NHDR_UMQ_CMD 0x51
#define LBMC_NHDR_UMQ_CMD_RESP 0x52
#define LBMC_NHDR_SRI_REQ 0x53
#define LBMC_NHDR_UME_STORE_DOMAIN 0x54
#define LBMC_NHDR_SRI 0x55
#define LBMC_NHDR_ROUTE_INFO 0x56
#define LBMC_NHDR_ROUTE_INFO_NEIGHBOR 0x57
#define LBMC_NHDR_GATEWAY_NAME 0x58
#define LBMC_NHDR_AUTHENTICATION 0x60
#define LBMC_NHDR_HMAC  0x62
#define LBMC_NHDR_UMQ_SID 0x63
#define LBMC_NHDR_DESTINATION 0x64
#define LBMC_NHDR_TOPIC_IDX 0x65
#define LBMC_NHDR_TOPIC_SOURCE 0x67
#define LBMC_NHDR_TOPIC_SOURCE_EXFUNC 0x68
#define LBMC_NHDR_UME_STORE_INFO_EXT 0x69
#define LBMC_NHDR_UME_PSRC_ELECTION_TOKEN 0x6A
#define LBMC_NHDR_TCP_SID 0x6B

#define LBMC_NHDR_EXTOPT 0xFE

#define LBMC_NHDR_NONE 0xFF

#define LBMC_OPT_IGNORE 0x8000
#define LBMC_OPT_IGNORE_CHAR 0x80
#define LBMC_BATCH_START 0x0002
#define LBMC_BATCH_END 0x0001

#define LBMC_CNTL_SSF_INIT_DEFAULT_INC 0x40
#define LBMC_CNTL_SSF_INIT_DEFAULT_EXC 0x20

#define LBMC_CNTL_SSF_CREQ_MODE_INCLUDE 0x00
#define LBMC_CNTL_SSF_CREQ_MODE_EXCLUDE 0x01

#define LBMC_REQUEST_TRANSPORT_TCP 0x00
#define LBMC_CNTL_SSF_INIT_TRANSPORT_TCP 0x00

#define LBMC_UME_PREG_S_FLAG 0x80
#define LBMC_UME_PREG_F_FLAG 0x40
#define LBMC_UME_PREG_P_FLAG 0x20
#define LBMC_UME_PREG_W_FLAG 0x10
#define LBMC_UME_PREG_D_FLAG 0x08
#define LBMC_UME_PREG_MARKER_PRI 0x01
#define LBMC_UME_PREG_MARKER_SEC 0x02
#define LBMC_UME_PREG_MARKER_TER 0x03
#define LBMC_UME_PREG_RESP_O_FLAG 0x40
#define LBMC_UME_PREG_RESP_E_FLAG 0x20
#define LBMC_UME_PREG_RESP_S_FLAG 0x80
#define LBMC_UME_PREG_RESP_W_FLAG 0x02
#define LBMC_UME_PREG_RESP_D_FLAG 0x01
#define LBMC_UME_PREG_RESP_ERRCODE_ENOERROR 0x00
#define LBMC_UME_PREG_RESP_ERRCODE_ENOPATTERN 0x01
#define LBMC_UME_PREG_RESP_ERRCODE_ESRCREGID 0x02
#define LBMC_UME_PREG_RESP_ERRCODE_EREGID 0x03
#define LBMC_UME_PREG_RESP_ERRCODE_ETOPICNAME 0x04
#define LBMC_UME_PREG_RESP_ERRCODE_EACTIVE 0x05
#define LBMC_UME_PREG_RESP_ERRCODE_ECONFIG 0x06
#define LBMC_UME_PREG_RESP_CODE_NOACKS_FLAG 0x10
#define LBMC_UME_PREG_RESP_CODE_NOCACHE_FLAG 0x10
#define LBMC_UME_ACK_O_FLAG 0x40
#define LBMC_UME_ACK_F_FLAG 0x20
#define LBMC_UME_ACK_U_FLAG 0x10
#define LBMC_UME_ACK_E_FLAG 0x08
#define LBMC_UME_ACK_TYPE_CDELV 0x00
#define LBMC_UME_ACK_TYPE_STABLE 0x01
#define LBMC_UME_KEEPALIVE_R_FLAG 0x40
#define LBMC_UME_KEEPALIVE_T_FLAG 0x20
#define LBMC_UME_KEEPALIVE_TYPE_SRC 0x2
#define LBMC_UME_KEEPALIVE_TYPE_RCV 0x1
#define LBMC_UME_KEEPALIVE_TYPE_STORE 0x0
#define LBMC_UME_STOREID_MAX_STOREID 0x7FFF
#define LBMC_UME_CAPABILITY_QC_FLAG 0x4000
#define LBMC_UME_CAPABILITY_CLIENT_LIFETIME_FLAG 0x2000
#define LBMC_UME_PROXY_SRC_E_FLAG 0x4000
#define LBMC_UME_PROXY_SRC_C_FLAG 0x2000
#define LBMC_UME_RXREQ_T_FLAG 0x4000
#define LBMC_LJI_REQ_L_FLAG 0x0001
#define LBMC_LJI_REQ_M_FLAG 0x0002
#define LBMC_LJI_REQ_O_FLAG 0x0004
#define LBMC_SRI_A_FLAG 0x0001
#define LBMC_SRI_INITIAL_SQN_KNOWN_FLAG 0x0002
#define LBMC_UMQ_REG_CTX_TYPE 0x1
#define LBMC_UMQ_REG_SRC_TYPE 0x2
#define LBMC_UMQ_REG_RCV_TYPE 0x3
#define LBMC_UMQ_REG_RCV_DEREG_TYPE 0x4
#define LBMC_UMQ_REG_ULB_RCV_TYPE 0x5
#define LBMC_UMQ_REG_ULB_RCV_DEREG_TYPE 0x6
#define LBMC_UMQ_REG_OBSERVER_RCV_TYPE 0x7
#define LBMC_UMQ_REG_OBSERVER_RCV_DEREG_TYPE 0x8
#define LBMC_UMQ_REG_R_FLAG 0x40
#define LBMC_UMQ_REG_T_FLAG 0x20
#define LBMC_UMQ_REG_I_FLAG 0x10
#define LBMC_UMQ_REG_MSG_SEL_FLAG 0x08
#define LBMC_UMQ_REG_RESP_CTX_TYPE 0x1
#define LBMC_UMQ_REG_RESP_SRC_TYPE 0x2
#define LBMC_UMQ_REG_RESP_RCV_TYPE 0x3
#define LBMC_UMQ_REG_RESP_RCV_DEREG_TYPE 0x4
#define LBMC_UMQ_REG_RESP_ULB_RCV_TYPE 0x5
#define LBMC_UMQ_REG_RESP_ULB_RCV_DEREG_TYPE 0x6
#define LBMC_UMQ_REG_RESP_OBSERVER_RCV_TYPE 0x7
#define LBMC_UMQ_REG_RESP_OBSERVER_RCV_DEREG_TYPE 0x8
#define LBMC_UMQ_REG_RESP_CTX_EX_TYPE 0x9
#define LBMC_UMQ_REG_RESP_ERR_TYPE 0xFF
#define LBMC_UMQ_REG_RESP_R_FLAG 0x40
#define LBMC_UMQ_REG_RESP_ERR_L_FLAG 0x20
#define LBMC_UMQ_REG_RESP_SRC_S_FLAG 0x20
#define LBMC_UMQ_REG_RESP_SRC_D_FLAG 0x10
#define LBMC_UMQ_REG_RESP_CTX_EX_FLAG_FIRSTMSG 0x1

#define LBMC_UMQ_ACK_STABLE_TYPE 0x1
#define LBMC_UMQ_ACK_CR_TYPE 0x2
#define LBMC_UMQ_ACK_ULB_CR_TYPE 0x3
#define LBMC_UMQ_ACK_T_FLAG 0x40
#define LBMC_UMQ_ACK_D_FLAG 0x20
#define LBMC_UMQ_ACK_NUMIDS_MASK 0x0F
#define LBMC_UMQ_RCR_BOI_FLAG 0x100
#define LBMC_UMQ_RCR_R_FLAG 0x4000
#define LBMC_UMQ_RCR_D_FLAG 0x2000
#define LBMC_UMQ_RCR_S_FLAG 0x1000
#define LBMC_UMQ_RCR_EOI_FLAG 0x200
#define LBMC_UMQ_RCR_BOI_FLAG 0x100
#define LBMC_UMQ_ULB_RCR_R_FLAG 0x4000
#define LBMC_UMQ_ULB_RCR_D_FLAG 0x2000
#define LBMC_UMQ_ULB_RCR_EOI_FLAG 0x200
#define LBMC_UMQ_ULB_RCR_BOI_FLAG 0x100
#define LBMC_UMQ_SQD_RCV_R_FLAG 0x4000
#define LBMC_UMQ_SQD_RCV_S_FLAG 0x2000
#define LBMC_UMQ_SQD_RCV_RE_FLAG 0x800
#define LBMC_UMQ_SQD_RCV_EOI_FLAG 0x200
#define LBMC_UMQ_SQD_RCV_BOI_FLAG 0x100
#define LBMC_UMQ_RESUB_Q_FLAG 0x4000
#define LBMC_UMQ_ULB_MSG_A_FLAG 0x4000
#define LBMC_UMQ_ULB_MSG_R_FLAG 0x2000
#define LBMC_UMQ_KA_CTX_TYPE 0x00
#define LBMC_UMQ_KA_SRC_TYPE 0x01
#define LBMC_UMQ_KA_RCV_TYPE 0x02
#define LBMC_UMQ_KA_ULB_RCV_TYPE 0x03
#define LBMC_UMQ_KA_CTX_RESP_TYPE 0x10
#define LBMC_UMQ_KA_SRC_RESP_TYPE 0x11
#define LBMC_UMQ_KA_RCV_RESP_TYPE 0x12
#define LBMC_UMQ_KA_ULB_RCV_RESP_TYPE 0x13
#define LBMC_UMQ_KA_R_FLAG 0x40
#define LBMC_UMQ_RXREQ_MR_TYPE 0x1
#define LBMC_UMQ_RXREQ_QRCRR_TYPE 0x2
#define LBMC_UMQ_RXREQ_TRCRR_TYPE 0x3
#define LBMC_UMQ_RXREQ_ULB_MR_TYPE 0x4
#define LBMC_UMQ_RXREQ_ULB_TRCRR_TYPE 0x5
#define LBMC_UMQ_RXREQ_ULB_MR_ABORT_TYPE 0x6
#define LBMC_UMQ_RXREQ_ULB_TRCRR_ABORT_TYPE 0x7
#define LBMC_UMQ_RXREQ_R_FLAG 0x40
#define LBMC_UMQ_RESUB_RESP_ENQUEUED_CODE 0x1
#define LBMC_UMQ_RESUB_RESP_CONSUMED_CODE 0x2
#define LBMC_UMQ_RESUB_RESP_OUTSTANDING_CODE 0x3
#define LBMC_UMQ_RESUB_RESP_RESUBALLOWED_CODE 0x4
#define LBMC_UMQ_RESUB_RESP_RESUBDONE_CODE 0x5
#define LBMC_UMQ_LF_SRC_TYPE 0x01
#define LBMC_UMQ_LF_RCV_TYPE 0x02
#define LBMC_UMQ_LF_U_FLAG 0x40
#define LBMC_UMQ_IDX_CMD_RCV_STOP_IDX_ASSIGN_TYPE 0x1
#define LBMC_UMQ_IDX_CMD_RCV_START_IDX_ASSIGN_TYPE 0x2
#define LBMC_UMQ_IDX_CMD_ULB_RCV_STOP_IDX_ASSIGN_TYPE 0x3
#define LBMC_UMQ_IDX_CMD_ULB_RCV_START_IDX_ASSIGN_TYPE 0x4
#define LBMC_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_TYPE 0x5
#define LBMC_UMQ_IDX_CMD_ULB_RCV_RELEASE_IDX_ASSIGN_TYPE 0x6
#define LBMC_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_TYPE 0x7
#define LBMC_UMQ_IDX_CMD_ULB_RCV_RESERVE_IDX_ASSIGN_TYPE 0x8
#define LBMC_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_TYPE 0x1
#define LBMC_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_TYPE 0x2
#define LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_TYPE 0x3
#define LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_TYPE 0x4
#define LBMC_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_TYPE 0x5
#define LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_TYPE 0x6
#define LBMC_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_TYPE 0x7
#define LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_TYPE 0x8

#define UMQUEUE_CTX_REG_EDUPREGID 0x1
#define UMQUEUE_SRC_REG_EREGID 0x2
#define UMQUEUE_SRC_REG_ENOPATTERN 0x3
#define UMQUEUE_SRC_REG_ENOTOPICNAME 0x4
#define UMQUEUE_RCV_REG_ENOTOPICNAME 0x5
#define UMQUEUE_RCV_REG_EREGID 0x6
#define UMQUEUE_RCV_REG_ENOPATTERN 0x7
#define UMQUEUE_RCV_REG_EASSIGNIDINUSE 0x8
#define UMQUEUE_RCV_REG_ERCVTYPEID 0x9
#define UMQUEUE_RCV_REG_EINVAL 0xa
#define UMQUEUE_REG_EAUTHFAIL 0x10

#define UMQUEUE_RCV_IDX_CMD_EREGID 0x1
#define UMQUEUE_RCV_IDX_CMD_EIDXNOTASSIGNED 0x2
#define UMQUEUE_RCV_IDX_CMD_EIDXINELIGIBLE 0x3
#define UMQUEUE_RCV_IDX_CMD_EIDXINUSE 0x4
#define UMQUEUE_RCV_IDX_CMD_EIDXALREADYASSIGNED 0x5
#define UMQUEUE_RCV_IDX_CMD_EAUTHFAIL 0x10
#define LBM_UMQ_ULB_RCV_IDX_CMD_EIDXNOTASSIGNED 0xA
#define LBM_UMQ_ULB_RCV_IDX_CMD_EIDXINELIGIBLE 0xB
#define LBM_UMQ_ULB_RCV_IDX_CMD_EIDXINUSE 0xC
#define LBM_UMQ_ULB_RCV_IDX_CMD_EIDXALREADYASSIGNED 0xD

#define LBMC_UMQ_IDX_CMD_RESP_ERR_TYPE 0xFF
#define LBMC_UMQ_IDX_CMD_RESP_ERR_L_FLAG 0x20
#define LBM_UMQ_INDEX_FLAG_NUMERIC 0x1

#define LBMC_TOPIC_INTEREST_CANCEL_FLAG 0x4000
#define LBMC_TOPIC_INTEREST_REFRESH_FLAG 0x2000
#define LBMC_PATTERN_INTEREST_CANCEL_FLAG 0x40
#define LBMC_PATTERN_INTEREST_REFRESH_FLAG 0x20
#define LBMC_ADVERTISEMENT_EOS_FLAG 0x40
#define LBMC_ADVERTISEMENT_PATTERN_FLAG 0x20
#define LBMC_ADVERTISEMENT_CHANGE_FLAG 0x10
#define LBMC_ADVERTISEMENT_CTXINST_FLAG 0x08
#define LBMC_TOPIC_SOURCE_EOS_FLAG 0x4000
#define LBMC_ADVERTISEMENT_AD_LJ_FLAG 0x80000000
#define LBMC_ADVERTISEMENT_AD_UME_FLAG 0x40000000
#define LBMC_ADVERTISEMENT_AD_ACKTOSRC_FLAG 0x20000000
#define LBMC_ADVERTISEMENT_AD_QUEUE_FLAG 0x10000000
#define LBMC_ADVERTISEMENT_AD_ULB_FLAG 0x08000000
#define LBMC_CTXINFO_QUERY_FLAG   0x4000
#define LBMC_CTXINFO_ADDR_FLAG    0x2000
#define LBMC_CTXINFO_CTXINST_FLAG 0x1000
#define LBMC_CTXINFO_NAME_FLAG    0x0800
#define LBMC_CTXINFO_TNWGSRC_FLAG 0x0400
#define LBMC_CTXINFO_TNWGRCV_FLAG 0x0200
#define LBMC_CTXINFO_PROXY_FLAG   0x0100
#define LBMC_UME_PSER_SOURCE_CTXINST_FLAG 0x4000
#define LBMC_UME_PSER_STORE_CTXINST_FLAG 0x2000
#define LBMC_UME_PSER_REELECT_FLAG 0x1000
#define LBMC_DOMAIN_ACTIVE_FLAG 0x4000
#define LBMC_CNTL_TNWG_CAPABILITIES_VERSION_MASK 0x7fff
#define LBMC_CNTL_TNWG_CAPABILITIES1_UME_FLAG 0x80000000
#define LBMC_CNTL_TNWG_CAPABILITIES1_UMQ_FLAG 0x40000000
#define LBMC_CNTL_TNWG_CAPABILITIES3_PCRE_FLAG 0x80000000
#define LBMC_CNTL_TNWG_CAPABILITIES3_REGEX_FLAG 0x40000000

#define LBM_CHAIN_ELEM_CHANNEL_NUMBER 0x1
#define LBM_CHAIN_ELEM_HF_SQN 0x2
#define LBM_CHAIN_ELEM_GW_INFO 0x3
#define LBM_CHAIN_ELEM_APPHDR 0x4
#define LBM_CHAIN_ELEM_USER_DATA 0x5
#define LBM_CHAIN_ELEM_PROPERTIES_LENGTH 0x6
#define LBM_CHAIN_ELEM_NONE 0xff

#define LBMC_CNTL_TNWG_KA_Q_FLAG 0x4000
#define LBMC_CNTL_TNWG_KA_R_FLAG 0x2000

#define LBMC_UMQ_CMD_TYPE_TOPIC_LIST 1
#define LBMC_UMQ_CMD_TYPE_RCV_MSG_RETRIEVE 2
#define LBMC_UMQ_CMD_TYPE_RCV_MSG_LIST 3

#define LBMC_UMQ_CMD_RESP_TYPE_CTX_TOPIC_LIST 1
#define LBMC_UMQ_CMD_RESP_TYPE_RCV_MSG_RETRIEVE 2
#define LBMC_UMQ_CMD_RESP_TYPE_RCV_MSG_LIST 3
#define LBMC_UMQ_CMD_RESP_TYPE_ERROR 4

#define AUTH_OP_REQ 0x01
#define AUTH_OP_CHALLENGE 0x02
#define AUTH_OP_CHALLENGE_RSP 0x03
#define AUTH_OP_RESULT 0x04

#define LBMC_UMQ_CMD_RESP_ERROR_AUTHFAIL 0x11
#define LBMC_UMQ_CMD_RESP_ERROR_NOHMAC 0x12
#define LBMC_UMQ_CMD_RESP_ERROR_NOAUTHOR 0x13

#define LBMC_EXTOPT_FLAG_IGNORE 0x80
#define LBMC_EXTOPT_FLAG_IGNORE_SUBTYPE 0x40
#define LBMC_EXTOPT_FLAG_MORE_FRAGMENT 0x20

#define LBMC_EXT_NHDR_CFGOPT 0x0100
#define LBMC_EXT_NHDR_MSGSEL 0x0101

#define LBM_MSG_PROPERTIES_HDR_VER(vt) ((vt & 0xF0) >> 4)
#define LBM_MSG_PROPERTIES_HDR_TYPE(vt) (vt & 0xF)
#define LBM_MSG_PROPERTIES_HDR_VER_MASK 0xF0
#define LBM_MSG_PROPERTIES_HDR_TYPE_MASK 0x0F

#define LBM_MSG_PROPERTIES_VER 0x0

#define LBM_MSG_PROPERTIES_TYPE_NORMAL 0x0

#define LBM_MSG_PROPERTIES_MAGIC 0xABACDABA
#define LBM_MSG_PROPERTIES_ANTIMAGIC 0xBADAACAB

#define LBM_MSG_PROPERTY_NONE 0x0
#define LBM_MSG_PROPERTY_BOOLEAN 0x1
#define LBM_MSG_PROPERTY_BYTE 0x2
#define LBM_MSG_PROPERTY_SHORT 0x3
#define LBM_MSG_PROPERTY_INT 0x4
#define LBM_MSG_PROPERTY_LONG 0x5
#define LBM_MSG_PROPERTY_FLOAT 0x6
#define LBM_MSG_PROPERTY_DOUBLE 0x7
#define LBM_MSG_PROPERTY_STRING 0x8

#define LBM_UMQ_QUEUE_MSG_STATUS_UNKNOWN 0
#define LBM_UMQ_QUEUE_MSG_STATUS_UNASSIGNED 1
#define LBM_UMQ_QUEUE_MSG_STATUS_ASSIGNED 2
#define LBM_UMQ_QUEUE_MSG_STATUS_REASSIGNING 3
#define LBM_UMQ_QUEUE_MSG_STATUS_CONSUMED 4
#define LBM_UMQ_QUEUE_MSG_STATUS_COMPLETE 5

#define LBMC_CNTL_CONFIG_OPT_SCOPE_SOURCE 0x1
#define LBMC_CNTL_CONFIG_OPT_SCOPE_RECEIVER 0x2
#define LBMC_CNTL_CONFIG_OPT_SCOPE_CONTEXT 0x3
#define LBMC_CNTL_CONFIG_OPT_SCOPE_WILDCARD_RECEIVER 0x4
#define LBMC_CNTL_CONFIG_OPT_SCOPE_EVENT_QUEUE 0x5
#define LBMC_CNTL_CONFIG_OPT_SCOPE_CONNECTION_FACTORY 0x6
#define LBMC_CNTL_CONFIG_OPT_SCOPE_DESTINATION 0x7
#define LBMC_CNTL_CONFIG_OPT_SCOPE_HFX 0x8

/*----------------------------------------------------------------------------*/
/* Value translation tables.                                                  */
/*----------------------------------------------------------------------------*/

static const value_string lbmc_message_type[] =
{
    { LBMC_TYPE_MESSAGE, "Message" },
    { LBMC_TYPE_PRORX, "Proactive Retransmission" },
    { LBMC_TYPE_RETRANS, "Retransmission" },
    { LBMC_TYPE_CONTROL, "Control" },
    { LBMC_TYPE_EOT, "EOT" },
    { 0x0, NULL }
};

static const value_string lbmc_next_header[] =
{
    { LBMC_NHDR_DATA, "Data" },
    { LBMC_NHDR_FRAG, "Fragment" },
    { LBMC_NHDR_BATCH, "Batch" },
    { LBMC_NHDR_TGIDX, "Unknown" },
    { LBMC_NHDR_REQUEST, "Request" },
    { LBMC_NHDR_TOPICNAME, "Topic name" },
    { LBMC_NHDR_APPHDR, "Application header" },
    { LBMC_NHDR_APPHDR_CHAIN, "Application header chain" },
    { LBMC_NHDR_UMQ_MSGID, "UMQ message ID" },
    { LBMC_NHDR_UMQ_SQD_RCV, "UMQ SQD rcv" },
    { LBMC_NHDR_UMQ_RESUB, "UMQ resub" },
    { LBMC_NHDR_OTID, "OTID" },
    { LBMC_NHDR_CTXINSTD, "Context instance destination" },
    { LBMC_NHDR_CTXINSTR, "Context instance return" },
    { LBMC_NHDR_SRCIDX, "Source index" },
    { LBMC_NHDR_UMQ_ULB_MSG, "UMQ ULB Message" },
    { LBMC_NHDR_SSF_INIT, "Source-side filtering init" },
    { LBMC_NHDR_SSF_CREQ, "Source-side filtering control request" },
    { LBMC_NHDR_UME_PREG, "UME persistent registration" },
    { LBMC_NHDR_UME_PREG_RESP, "UME persistent registration response" },
    { LBMC_NHDR_UME_ACK, "UME acknowledgement" },
    { LBMC_NHDR_UME_RXREQ, "UME retransmission request" },
    { LBMC_NHDR_UME_KEEPALIVE, "UME keepalive" },
    { LBMC_NHDR_UME_STOREID, "UME store ID" },
    { LBMC_NHDR_UME_RANGED_ACK, "UME ranged ACK" },
    { LBMC_NHDR_UME_ACK_ID, "UME ACK" },
    { LBMC_NHDR_UME_CAPABILITY, "UME capability" },
    { LBMC_NHDR_UME_PROXY_SRC, "Proxy source" },
    { LBMC_NHDR_UME_STORE_GROUP, "Store group" },
    { LBMC_NHDR_UME_STORE_INFO, "Store info" },
    { LBMC_NHDR_UME_LJ_INFO, "UME late-join info" },
    { LBMC_NHDR_TSNI, "Topic sequence info" },
    { LBMC_NHDR_UMQ_REG, "UMQ registration" },
    { LBMC_NHDR_UMQ_REG_RESP, "UMQ registration response" },
    { LBMC_NHDR_UMQ_ACK, "UMQ ACK" },
    { LBMC_NHDR_UMQ_RCR, "UMQ receiver control record" },
    { LBMC_NHDR_UMQ_KA, "UMQ keepalive" },
    { LBMC_NHDR_UMQ_RXREQ, "UME retransmission request" },
    { LBMC_NHDR_UMQ_QMGMT, "UMQ queue management" },
    { LBMC_NHDR_UMQ_RESUB_REQ, "UMQ resubmission request" },
    { LBMC_NHDR_UMQ_RESUB_RESP, "UMQ resubmission response" },
    { LBMC_NHDR_TOPIC_INTEREST, "Topic interest" },
    { LBMC_NHDR_PATTERN_INTEREST, "Pattern interest" },
    { LBMC_NHDR_ADVERTISEMENT, "Advertisement" },
    { LBMC_NHDR_UME_CTXINSTS, "Store context instance" },
    { LBMC_NHDR_UME_STORENAME, "Store name" },
    { LBMC_NHDR_UMQ_ULB_RCR, "UMQ ULB RCR" },
    { LBMC_NHDR_UMQ_LF, "UMQ load factor" },
    { LBMC_NHDR_CTXINFO, "Context information" },
    { LBMC_NHDR_UME_PSER, "UME proxy source election" },
    { LBMC_NHDR_CTXINST, "Context instance" },
    { LBMC_NHDR_DOMAIN, "Domain" },
    { LBMC_NHDR_TNWG_CAPABILITIES, "TNWG Capabilities" },
    { LBMC_NHDR_PATIDX, "Pattern index" },
    { LBMC_NHDR_UME_CLIENT_LIFETIME, "UME client lifetime" },
    { LBMC_NHDR_UME_SID, "UME session ID" },
    { LBMC_NHDR_UMQ_IDX_CMD, "UMQ index command" },
    { LBMC_NHDR_UMQ_IDX_CMD_RESP, "UMQ index command response" },
    { LBMC_NHDR_ODOMAIN, "Originating Domain" },
    { LBMC_NHDR_STREAM, "Stream" },
    { LBMC_NHDR_TOPIC_MD_INTEREST, "Topic multi-domain interest" },
    { LBMC_NHDR_PATTERN_MD_INTEREST, "Pattern multi-domain interest" },
    { LBMC_NHDR_LJI_REQ, "Late Join information request" },
    { LBMC_NHDR_TNWG_KA, "Gateway peer keepalive" },
    { LBMC_NHDR_UME_RCV_KEEPALIVE, "UME receiver keepalive" },
    { LBMC_NHDR_UMQ_CMD, "UMQ command" },
    { LBMC_NHDR_UMQ_CMD_RESP, "UMQ command response" },
    { LBMC_NHDR_SRI_REQ, "Source registration information request" },
    { LBMC_NHDR_UME_STORE_DOMAIN, "Store domain" },
    { LBMC_NHDR_SRI, "Source registration information" },
    { LBMC_NHDR_ROUTE_INFO, "Route information" },
    { LBMC_NHDR_ROUTE_INFO_NEIGHBOR, "Route information neighbor" },
    { LBMC_NHDR_GATEWAY_NAME, "Gateway name" },
    { LBMC_NHDR_AUTHENTICATION, "Authentication" },
    { LBMC_NHDR_HMAC, "HMAC" },
    { LBMC_NHDR_UMQ_SID, "UMQ session ID" },
    { LBMC_NHDR_DESTINATION, "Destination" },
    { LBMC_NHDR_TOPIC_IDX, "Topic index" },
    { LBMC_NHDR_TOPIC_SOURCE, "Topic source" },
    { LBMC_NHDR_TOPIC_SOURCE_EXFUNC, "Topic source extended functionality" },
    { LBMC_NHDR_EXTOPT, "Extended option" },
    { LBMC_NHDR_UME_STORE_INFO_EXT, "Store extended information" },
    { LBMC_NHDR_UME_PSRC_ELECTION_TOKEN, "Proxy source election token" },
    { LBMC_NHDR_NONE, "None" },
    { LBMC_NHDR_TCP_SID, "TCP session ID" },
    { 0x0, NULL }
};

static const value_string lbmc_req_transport_type[] =
{
    { LBMC_REQUEST_TRANSPORT_TCP, "TCP" },
    { 0x0, NULL }
};

static const value_string lbmc_ssf_transport_type[] =
{
    { LBMC_CNTL_SSF_INIT_TRANSPORT_TCP, "TCP" },
    { 0x0, NULL }
};

static const value_string lbmc_ssf_creq_mode[] =
{
    { LBMC_CNTL_SSF_CREQ_MODE_INCLUDE, "Include" },
    { LBMC_CNTL_SSF_CREQ_MODE_EXCLUDE, "Exclude" },
    { 0x0, NULL }
};

static const value_string lbmc_ume_preg_resp_error_code[] =
{
    { LBMC_UME_PREG_RESP_ERRCODE_ENOERROR, "No error" },
    { LBMC_UME_PREG_RESP_ERRCODE_ENOPATTERN, "Store has no matching pattern" },
    { LBMC_UME_PREG_RESP_ERRCODE_ESRCREGID, "Source RegID not found" },
    { LBMC_UME_PREG_RESP_ERRCODE_EREGID, "RegID is in use by a receiver" },
    { LBMC_UME_PREG_RESP_ERRCODE_ETOPICNAME,  "Topic name does not match previous registration" },
    { LBMC_UME_PREG_RESP_ERRCODE_EACTIVE, "RegID is in use by a different source" },
    { LBMC_UME_PREG_RESP_ERRCODE_ECONFIG, "Source and store configuration values are incompatible" },
    { 0x0, NULL }
};

static const value_string lbmc_ume_ack_type[] =
{
    { LBMC_UME_ACK_TYPE_CDELV, "CDELV" },
    { LBMC_UME_ACK_TYPE_STABLE, "Stable" },
    { 0x0, NULL }
};

static const value_string lbmc_ume_ka_type[] =
{
    { LBMC_UME_KEEPALIVE_TYPE_SRC, "Source" },
    { LBMC_UME_KEEPALIVE_TYPE_RCV, "Receiver" },
    { LBMC_UME_KEEPALIVE_TYPE_STORE, "Store" },
    { 0x0, NULL }
};

static const true_false_string lbmc_ume_s_flag =
{
    "Source registration",
    "Receiver registration"
};

static const true_false_string lbmc_ume_f_flag =
{
    "Do not forward ACKs",
    "Forward ACKs"
};

static const true_false_string lbmc_ume_o_flag =
{
    "Old/returning client",
    "New client"
};

static const true_false_string lbmc_ume_error_flag =
{
    "Error (see code)",
    "No error"
};

static const true_false_string lbmc_ume_n_flag =
{
    "No cache (store) or no ACKs (receiver)",
    "Cache (store) or ACKs (receiver)"
};

static const true_false_string lbmc_ume_r_flag =
{
    "Store requests a response",
    "No response requested"
};

static const true_false_string lbmc_ume_t_flag =
{
    "Store has not seen a TIR for the topic",
    "Store has seen a TIR for the topic"
};

static const value_string lbmc_apphdr_chain_type[] =
{
    { LBM_CHAIN_ELEM_CHANNEL_NUMBER, "Channel" },
    { LBM_CHAIN_ELEM_HF_SQN, "Hot failover sequence number" },
    { LBM_CHAIN_ELEM_GW_INFO, "Gateway info" },
    { LBM_CHAIN_ELEM_APPHDR, "Non-chained apphdr" },
    { LBM_CHAIN_ELEM_USER_DATA, "User data" },
    { LBM_CHAIN_ELEM_PROPERTIES_LENGTH, "Message properties length" },
    { LBM_CHAIN_ELEM_NONE, "None" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_reg_type[] =
{
    { LBMC_UMQ_REG_CTX_TYPE, "Context" },
    { LBMC_UMQ_REG_SRC_TYPE, "Source" },
    { LBMC_UMQ_REG_RCV_TYPE, "Receiver" },
    { LBMC_UMQ_REG_RCV_DEREG_TYPE, "Receiver deregistration" },
    { LBMC_UMQ_REG_ULB_RCV_TYPE, "ULB Receiver" },
    { LBMC_UMQ_REG_ULB_RCV_DEREG_TYPE, "ULB Receiver deregistration" },
    { LBMC_UMQ_REG_OBSERVER_RCV_TYPE, "Observer receiver registration" },
    { LBMC_UMQ_REG_OBSERVER_RCV_DEREG_TYPE, "Observer receiver deregistration" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_reg_response_type[] =
{
    { LBMC_UMQ_REG_RESP_CTX_TYPE, "Context" },
    { LBMC_UMQ_REG_RESP_SRC_TYPE, "Source" },
    { LBMC_UMQ_REG_RESP_RCV_TYPE, "Receiver" },
    { LBMC_UMQ_REG_RESP_RCV_DEREG_TYPE, "Receiver deregistration" },
    { LBMC_UMQ_REG_RESP_ERR_TYPE, "Error" },
    { LBMC_UMQ_REG_RESP_ULB_RCV_TYPE, "ULB Receiver" },
    { LBMC_UMQ_REG_RESP_ULB_RCV_DEREG_TYPE, "ULB Receiver deregistration" },
    { LBMC_UMQ_REG_RESP_OBSERVER_RCV_TYPE, "Observer receiver registration" },
    { LBMC_UMQ_REG_RESP_OBSERVER_RCV_DEREG_TYPE, "Observer receiver deregistration" },
    { LBMC_UMQ_REG_RESP_CTX_EX_TYPE, "Extended context registration" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_reg_response_error_code[] =
{
    { UMQUEUE_CTX_REG_EDUPREGID, "Registration ID in use by different IP/port (ctx)" },
    { UMQUEUE_SRC_REG_EREGID, "Registration ID not found (src)" },
    { UMQUEUE_SRC_REG_ENOPATTERN, "Topic not specified in queue configuration (src)" },
    { UMQUEUE_SRC_REG_ENOTOPICNAME, "No topic name (src)" },
    { UMQUEUE_RCV_REG_ENOTOPICNAME, "No topic name (rcv)" },
    { UMQUEUE_RCV_REG_EREGID, "Registration ID not found (rcv)" },
    { UMQUEUE_RCV_REG_ENOPATTERN, "Topic not specified in queue configuration (rcv)"},
    { UMQUEUE_RCV_REG_EASSIGNIDINUSE, "Assignment ID already in use (rcv)" },
    { UMQUEUE_RCV_REG_ERCVTYPEID, "Invalid receiver-type ID (rcv)" },
    { UMQUEUE_RCV_REG_EINVAL, "Invalid value (rcv)" },
    { UMQUEUE_REG_EAUTHFAIL, "Authorization failure" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_idx_cmd_response_error_code[] =
{
    { UMQUEUE_RCV_IDX_CMD_EREGID, "Receiver/list not found" },
    { UMQUEUE_RCV_IDX_CMD_EIDXNOTASSIGNED, "Index not assigned" },
    { UMQUEUE_RCV_IDX_CMD_EIDXINELIGIBLE, "Receiver ineligible for index" },
    { UMQUEUE_RCV_IDX_CMD_EIDXINUSE, "Index assigned to another receiver" },
    { UMQUEUE_RCV_IDX_CMD_EIDXALREADYASSIGNED, "Index already assigned to this receiver" },
    { UMQUEUE_RCV_IDX_CMD_EAUTHFAIL, "Authorization failure" },
    { LBM_UMQ_ULB_RCV_IDX_CMD_EIDXNOTASSIGNED, "Index not assigned" },
    { LBM_UMQ_ULB_RCV_IDX_CMD_EIDXINELIGIBLE, "Receiver ineligible for index" },
    { LBM_UMQ_ULB_RCV_IDX_CMD_EIDXINUSE, "Indes already assigned or unavailable" },
    { LBM_UMQ_ULB_RCV_IDX_CMD_EIDXALREADYASSIGNED, "Index already assigned to this receiver" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_ack_type[] =
{
    { LBMC_UMQ_ACK_STABLE_TYPE, "Stable" },
    { LBMC_UMQ_ACK_CR_TYPE, "CR" },
    { LBMC_UMQ_ACK_ULB_CR_TYPE, "ULB CR" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_ka_type[] =
{
    { LBMC_UMQ_KA_CTX_TYPE, "Context" },
    { LBMC_UMQ_KA_SRC_TYPE, "Source" },
    { LBMC_UMQ_KA_RCV_TYPE, "Receiver" },
    { LBMC_UMQ_KA_ULB_RCV_TYPE, "ULB Receiver" },
    { LBMC_UMQ_KA_CTX_RESP_TYPE, "Context response" },
    { LBMC_UMQ_KA_SRC_RESP_TYPE, "Source response" },
    { LBMC_UMQ_KA_RCV_RESP_TYPE, "Receiver response" },
    { LBMC_UMQ_KA_ULB_RCV_RESP_TYPE, "ULB Receiver response" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_rxreq_type[] =
{
    { LBMC_UMQ_RXREQ_MR_TYPE, "MR" },
    { LBMC_UMQ_RXREQ_QRCRR_TYPE, "QRCRR" },
    { LBMC_UMQ_RXREQ_TRCRR_TYPE, "TRCRR" },
    { LBMC_UMQ_RXREQ_ULB_MR_TYPE, "ULB MR" },
    { LBMC_UMQ_RXREQ_ULB_MR_ABORT_TYPE, "ULB MR Abort" },
    { LBMC_UMQ_RXREQ_ULB_TRCRR_TYPE, "ULB TRCRR" },
    { LBMC_UMQ_RXREQ_ULB_TRCRR_ABORT_TYPE, "ULB TRCRR Abort" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_resub_response_code[] =
{
    { LBMC_UMQ_RESUB_RESP_ENQUEUED_CODE, "Enqueued" },
    { LBMC_UMQ_RESUB_RESP_CONSUMED_CODE, "Consumed" },
    { LBMC_UMQ_RESUB_RESP_OUTSTANDING_CODE, "Outstanding" },
    { LBMC_UMQ_RESUB_RESP_RESUBALLOWED_CODE, "Resubmission allowed" },
    { LBMC_UMQ_RESUB_RESP_RESUBDONE_CODE, "Resubmission done" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_lf_type[] =
{
    { LBMC_UMQ_LF_SRC_TYPE, "Source" },
    { LBMC_UMQ_LF_RCV_TYPE, "Receiver" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_index_cmd_type[] =
{
    { LBMC_UMQ_IDX_CMD_RCV_STOP_IDX_ASSIGN_TYPE, "Stop receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RCV_START_IDX_ASSIGN_TYPE, "Start receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_ULB_RCV_STOP_IDX_ASSIGN_TYPE, "Stop ULB receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_ULB_RCV_START_IDX_ASSIGN_TYPE, "Start ULB receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_TYPE, "Release receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_ULB_RCV_RELEASE_IDX_ASSIGN_TYPE, "Release ULB receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_TYPE, "Reserve receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_ULB_RCV_RESERVE_IDX_ASSIGN_TYPE, "Reserve ULB receiver index assignment" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_index_cmd_response_type[] =
{
    { LBMC_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_TYPE, "Stop receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_TYPE, "Start receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_TYPE, "Stop ULB receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_TYPE, "Start ULB receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_TYPE, "Release receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_TYPE, "Release ULB receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_TYPE, "Reserve receiver index assignment" },
    { LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_TYPE, "Reserve ULB receiver index assignment" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_cmd_type[] =
{
    { LBMC_UMQ_CMD_TYPE_TOPIC_LIST, "Topic list" },
    { LBMC_UMQ_CMD_TYPE_RCV_MSG_RETRIEVE, "Retrieve message" },
    { LBMC_UMQ_CMD_TYPE_RCV_MSG_LIST, "List message" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_cmd_response_type[] =
{
    { LBMC_UMQ_CMD_RESP_TYPE_CTX_TOPIC_LIST, "Topic list" },
    { LBMC_UMQ_CMD_RESP_TYPE_RCV_MSG_RETRIEVE, "Retrieve message" },
    { LBMC_UMQ_CMD_RESP_TYPE_RCV_MSG_LIST, "List message" },
    { LBMC_UMQ_CMD_RESP_TYPE_ERROR, "Error" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_cmd_response_error_code[] =
{
    { LBMC_UMQ_CMD_RESP_ERROR_AUTHFAIL, "Authentication failed" },
    { LBMC_UMQ_CMD_RESP_ERROR_NOHMAC, "HMAC failed" },
    { LBMC_UMQ_CMD_RESP_ERROR_NOAUTHOR, "Not authorized" },
    { 0x0, NULL }
};

static const value_string lbmc_auth_operation_id_type[] =
{
    { AUTH_OP_REQ, "Request" },
    { AUTH_OP_CHALLENGE, "Challenge" },
    { AUTH_OP_CHALLENGE_RSP, "Challenge response" },
    { AUTH_OP_RESULT, "Result" },
    { 0x0, NULL }
};

static const value_string lbmc_extopt_subtype[] =
{
    { LBMC_EXT_NHDR_CFGOPT, "Configuration option" },
    { LBMC_EXT_NHDR_MSGSEL, "Message selector" },
    { 0x0, NULL }
};

static const value_string lbm_msg_prop_header_type[] =
{
    { LBM_MSG_PROPERTIES_TYPE_NORMAL, "Normal" },
    { 0x0, NULL }
};

static const value_string lbm_msg_prop_magic_type[] =
{
    { LBM_MSG_PROPERTIES_MAGIC, "MAGIC" },
    { LBM_MSG_PROPERTIES_ANTIMAGIC, "ANTI-MAGIC" },
    { 0x0, NULL }
};

static const value_string lbm_msg_prop_field_type[] =
{
    { LBM_MSG_PROPERTY_NONE, "None" },
    { LBM_MSG_PROPERTY_BOOLEAN, "Boolean" },
    { LBM_MSG_PROPERTY_BYTE, "Byte" },
    { LBM_MSG_PROPERTY_SHORT, "Short" },
    { LBM_MSG_PROPERTY_INT, "Integer" },
    { LBM_MSG_PROPERTY_LONG, "Long" },
    { LBM_MSG_PROPERTY_FLOAT, "Float" },
    { LBM_MSG_PROPERTY_DOUBLE, "Double" },
    { LBM_MSG_PROPERTY_STRING, "String" },
    { 0x0, NULL }
};

static const value_string lbmc_umq_msg_status_code[] =
{
    { LBM_UMQ_QUEUE_MSG_STATUS_UNKNOWN, "Unknown" },
    { LBM_UMQ_QUEUE_MSG_STATUS_UNASSIGNED, "Unassigned" },
    { LBM_UMQ_QUEUE_MSG_STATUS_ASSIGNED, "Assigned" },
    { LBM_UMQ_QUEUE_MSG_STATUS_REASSIGNING, "Reassigning" },
    { LBM_UMQ_QUEUE_MSG_STATUS_CONSUMED, "Consumed" },
    { LBM_UMQ_QUEUE_MSG_STATUS_COMPLETE, "Complete" },
    { 0x0, NULL }
};

static const value_string lbmc_extopt_config_option_scope[] =
{
    { LBMC_CNTL_CONFIG_OPT_SCOPE_SOURCE, "Source" },
    { LBMC_CNTL_CONFIG_OPT_SCOPE_RECEIVER, "Receiver" },
    { LBMC_CNTL_CONFIG_OPT_SCOPE_CONTEXT, "Context" },
    { LBMC_CNTL_CONFIG_OPT_SCOPE_WILDCARD_RECEIVER, "Wildcard receiver" },
    { LBMC_CNTL_CONFIG_OPT_SCOPE_EVENT_QUEUE, "Event queue" },
    { LBMC_CNTL_CONFIG_OPT_SCOPE_CONNECTION_FACTORY, "Connection factory" },
    { LBMC_CNTL_CONFIG_OPT_SCOPE_DESTINATION, "Destination" },
    { LBMC_CNTL_CONFIG_OPT_SCOPE_HFX, "HFX" },
    { 0x0, NULL }
};

static const true_false_string lbmc_umq_r_flag =
{
    "Queue requests a response",
    "No response requested"
};

/*----------------------------------------------------------------------------*/
/* Preferences.                                                               */
/*----------------------------------------------------------------------------*/

static gboolean lbmc_use_heuristic_subdissectors = TRUE;
static gboolean lbmc_reassemble_fragments = FALSE;
static gboolean lbmc_dissect_lbmpdm = FALSE;
static heur_dissector_list_t lbmc_heuristic_subdissector_list;
static dissector_handle_t lbmc_data_dissector_handle;

/*----------------------------------------------------------------------------*/
/* Handles of all types.                                                      */
/*----------------------------------------------------------------------------*/

static int proto_lbmc = -1;
static int tnw_protocol_handle = -1;
static int lbmc_uim_tap_handle = -1;
static int lbmc_stream_tap_handle = -1;
static int hf_lbmc_tag = -1;
static int hf_lbmc_topic = -1;
static int hf_lbmc_ver_type = -1;
static int hf_lbmc_ver_type_version = -1;
static int hf_lbmc_ver_type_type = -1;
static int hf_lbmc_next_hdr = -1;
static int hf_lbmc_msglen = -1;
static int hf_lbmc_tidx = -1;
static int hf_lbmc_sqn = -1;
static int hf_lbmc_frag = -1;
static int hf_lbmc_frag_next_hdr = -1;
static int hf_lbmc_frag_hdr_len = -1;
static int hf_lbmc_frag_flags = -1;
static int hf_lbmc_frag_flags_ignore = -1;
static int hf_lbmc_frag_first_sqn = -1;
static int hf_lbmc_frag_offset = -1;
static int hf_lbmc_frag_len = -1;
static int hf_lbmc_batch = -1;
static int hf_lbmc_batch_next_hdr = -1;
static int hf_lbmc_batch_hdr_len = -1;
static int hf_lbmc_batch_flags = -1;
static int hf_lbmc_batch_flags_ignore = -1;
static int hf_lbmc_batch_flags_batch_start = -1;
static int hf_lbmc_batch_flags_batch_end = -1;
static int hf_lbmc_tcp_request = -1;
static int hf_lbmc_tcp_request_next_hdr = -1;
static int hf_lbmc_tcp_request_hdr_len = -1;
static int hf_lbmc_tcp_request_flags = -1;
static int hf_lbmc_tcp_request_flags_ignore = -1;
static int hf_lbmc_tcp_request_transport = -1;
static int hf_lbmc_tcp_request_qidx = -1;
static int hf_lbmc_tcp_request_port = -1;
static int hf_lbmc_tcp_request_reserved = -1;
static int hf_lbmc_tcp_request_ipaddr = -1;
static int hf_lbmc_topicname = -1;
static int hf_lbmc_topicname_next_hdr = -1;
static int hf_lbmc_topicname_hdr_len = -1;
static int hf_lbmc_topicname_flags = -1;
static int hf_lbmc_topicname_flags_ignore = -1;
static int hf_lbmc_topicname_topicname = -1;
static int hf_lbmc_apphdr = -1;
static int hf_lbmc_apphdr_next_hdr = -1;
static int hf_lbmc_apphdr_hdr_len = -1;
static int hf_lbmc_apphdr_code = -1;
static int hf_lbmc_apphdr_code_ignore = -1;
static int hf_lbmc_apphdr_code_code = -1;
static int hf_lbmc_apphdr_data = -1;
static int hf_lbmc_apphdr_chain = -1;
static int hf_lbmc_apphdr_chain_next_hdr = -1;
static int hf_lbmc_apphdr_chain_hdr_len = -1;
static int hf_lbmc_apphdr_chain_res = -1;
static int hf_lbmc_apphdr_chain_first_chain_hdr = -1;
static int hf_lbmc_apphdr_chain_element = -1;
static int hf_lbmc_apphdr_chain_element_next_hdr = -1;
static int hf_lbmc_apphdr_chain_element_hdr_len = -1;
static int hf_lbmc_apphdr_chain_element_res = -1;
static int hf_lbmc_apphdr_chain_element_data = -1;
static int hf_lbmc_apphdr_chain_msgprop = -1;
static int hf_lbmc_apphdr_chain_msgprop_next_hdr = -1;
static int hf_lbmc_apphdr_chain_msgprop_hdr_len = -1;
static int hf_lbmc_apphdr_chain_msgprop_res = -1;
static int hf_lbmc_apphdr_chain_msgprop_len = -1;
static int hf_lbmc_umq_msgid = -1;
static int hf_lbmc_umq_msgid_next_hdr = -1;
static int hf_lbmc_umq_msgid_hdr_len = -1;
static int hf_lbmc_umq_msgid_flags = -1;
static int hf_lbmc_umq_msgid_flags_ignore = -1;
static int hf_lbmc_umq_msgid_msgid_regid = -1;
static int hf_lbmc_umq_msgid_msgid_stamp = -1;
static int hf_lbmc_umq_sqd_rcv = -1;
static int hf_lbmc_umq_sqd_rcv_next_hdr = -1;
static int hf_lbmc_umq_sqd_rcv_hdr_len = -1;
static int hf_lbmc_umq_sqd_rcv_flags = -1;
static int hf_lbmc_umq_sqd_rcv_flags_ignore = -1;
static int hf_lbmc_umq_sqd_rcv_flags_r_flag = -1;
static int hf_lbmc_umq_sqd_rcv_flags_s_flag = -1;
static int hf_lbmc_umq_sqd_rcv_flags_re_flag = -1;
static int hf_lbmc_umq_sqd_rcv_flags_eoi_flag = -1;
static int hf_lbmc_umq_sqd_rcv_flags_boi_flag = -1;
static int hf_lbmc_umq_sqd_rcv_queue_id = -1;
static int hf_lbmc_umq_sqd_rcv_queue_ver = -1;
static int hf_lbmc_umq_sqd_rcv_rcr_idx = -1;
static int hf_lbmc_umq_sqd_rcv_assign_id = -1;
static int hf_lbmc_umq_resub = -1;
static int hf_lbmc_umq_resub_next_hdr = -1;
static int hf_lbmc_umq_resub_hdr_len = -1;
static int hf_lbmc_umq_resub_flags = -1;
static int hf_lbmc_umq_resub_flags_ignore = -1;
static int hf_lbmc_umq_resub_flags_q_flag = -1;
static int hf_lbmc_umq_resub_rcr_idx = -1;
static int hf_lbmc_umq_resub_resp_ip = -1;
static int hf_lbmc_umq_resub_resp_port = -1;
static int hf_lbmc_umq_resub_appset_idx = -1;
static int hf_lbmc_otid = -1;
static int hf_lbmc_otid_next_hdr = -1;
static int hf_lbmc_otid_hdr_len = -1;
static int hf_lbmc_otid_flags = -1;
static int hf_lbmc_otid_flags_ignore = -1;
static int hf_lbmc_otid_otid = -1;
static int hf_lbmc_ctxinst = -1;
static int hf_lbmc_ctxinst_next_hdr = -1;
static int hf_lbmc_ctxinst_hdr_len = -1;
static int hf_lbmc_ctxinst_flags = -1;
static int hf_lbmc_ctxinst_flags_ignore = -1;
static int hf_lbmc_ctxinst_ctxinst = -1;
static int hf_lbmc_ctxinstd = -1;
static int hf_lbmc_ctxinstr = -1;
static int hf_lbmc_srcidx = -1;
static int hf_lbmc_srcidx_next_hdr = -1;
static int hf_lbmc_srcidx_hdr_len = -1;
static int hf_lbmc_srcidx_flags = -1;
static int hf_lbmc_srcidx_flags_ignore = -1;
static int hf_lbmc_srcidx_srcidx = -1;
static int hf_lbmc_umq_ulb_msg = -1;
static int hf_lbmc_umq_ulb_msg_next_hdr = -1;
static int hf_lbmc_umq_ulb_msg_hdr_len = -1;
static int hf_lbmc_umq_ulb_msg_flags = -1;
static int hf_lbmc_umq_ulb_msg_flags_ignore = -1;
static int hf_lbmc_umq_ulb_msg_flags_a_flag = -1;
static int hf_lbmc_umq_ulb_msg_flags_r_flag = -1;
static int hf_lbmc_umq_ulb_msg_queue_id = -1;
static int hf_lbmc_umq_ulb_msg_ulb_src_id = -1;
static int hf_lbmc_umq_ulb_msg_assign_id = -1;
static int hf_lbmc_umq_ulb_msg_appset_idx = -1;
static int hf_lbmc_umq_ulb_msg_num_ras = -1;
static int hf_lbmc_ssf_init = -1;
static int hf_lbmc_ssf_init_next_hdr = -1;
static int hf_lbmc_ssf_init_hdr_len = -1;
static int hf_lbmc_ssf_init_transport = -1;
static int hf_lbmc_ssf_init_flags = -1;
static int hf_lbmc_ssf_init_flags_ignore = -1;
static int hf_lbmc_ssf_init_flags_default_inclusions = -1;
static int hf_lbmc_ssf_init_flags_default_exclusions = -1;
static int hf_lbmc_ssf_init_transport_idx = -1;
static int hf_lbmc_ssf_init_client_idx = -1;
static int hf_lbmc_ssf_init_ssf_port = -1;
static int hf_lbmc_ssf_init_res = -1;
static int hf_lbmc_ssf_init_ssf_ip = -1;
static int hf_lbmc_ssf_creq = -1;
static int hf_lbmc_ssf_creq_next_hdr = -1;
static int hf_lbmc_ssf_creq_hdr_len = -1;
static int hf_lbmc_ssf_creq_flags = -1;
static int hf_lbmc_ssf_creq_flags_ignore = -1;
static int hf_lbmc_ssf_creq_mode = -1;
static int hf_lbmc_ssf_creq_transport_idx = -1;
static int hf_lbmc_ssf_creq_topic_idx = -1;
static int hf_lbmc_ssf_creq_client_idx = -1;
static int hf_lbmc_ume_preg = -1;
static int hf_lbmc_ume_preg_next_hdr = -1;
static int hf_lbmc_ume_preg_hdr_len = -1;
static int hf_lbmc_ume_preg_flags = -1;
static int hf_lbmc_ume_preg_flags_ignore = -1;
static int hf_lbmc_ume_preg_flags_f_flag = -1;
static int hf_lbmc_ume_preg_flags_p_flag = -1;
static int hf_lbmc_ume_preg_flags_w_flag = -1;
static int hf_lbmc_ume_preg_flags_d_flag = -1;
static int hf_lbmc_ume_preg_marker = -1;
static int hf_lbmc_ume_preg_marker_s_flag = -1;
static int hf_lbmc_ume_preg_marker_marker = -1;
static int hf_lbmc_ume_preg_reg_id = -1;
static int hf_lbmc_ume_preg_transport_idx = -1;
static int hf_lbmc_ume_preg_topic_idx = -1;
static int hf_lbmc_ume_preg_src_reg_id = -1;
static int hf_lbmc_ume_preg_resp_port = -1;
static int hf_lbmc_ume_preg_res2 = -1;
static int hf_lbmc_ume_preg_resp_ip = -1;
static int hf_lbmc_ume_preg_resp = -1;
static int hf_lbmc_ume_preg_resp_next_hdr = -1;
static int hf_lbmc_ume_preg_resp_hdr_len = -1;
static int hf_lbmc_ume_preg_resp_code = -1;
static int hf_lbmc_ume_preg_resp_code_ignore = -1;
static int hf_lbmc_ume_preg_resp_code_e_flag = -1;
static int hf_lbmc_ume_preg_resp_code_o_flag = -1;
static int hf_lbmc_ume_preg_resp_code_n_flag = -1;
static int hf_lbmc_ume_preg_resp_code_w_flag = -1;
static int hf_lbmc_ume_preg_resp_code_d_flag = -1;
static int hf_lbmc_ume_preg_resp_code_code = -1;
static int hf_lbmc_ume_preg_resp_marker = -1;
static int hf_lbmc_ume_preg_resp_marker_s_flag = -1;
static int hf_lbmc_ume_preg_resp_marker_marker = -1;
static int hf_lbmc_ume_preg_resp_reg_id = -1;
static int hf_lbmc_ume_preg_resp_transport_idx = -1;
static int hf_lbmc_ume_preg_resp_topic_idx = -1;
static int hf_lbmc_ume_preg_resp_low_seqnum = -1;
static int hf_lbmc_ume_preg_resp_high_seqnum = -1;
static int hf_lbmc_ume_ack = -1;
static int hf_lbmc_ume_ack_next_hdr = -1;
static int hf_lbmc_ume_ack_hdr_len = -1;
static int hf_lbmc_ume_ack_flags = -1;
static int hf_lbmc_ume_ack_flags_ignore = -1;
static int hf_lbmc_ume_ack_flags_o_flag = -1;
static int hf_lbmc_ume_ack_flags_f_flag = -1;
static int hf_lbmc_ume_ack_flags_u_flag = -1;
static int hf_lbmc_ume_ack_flags_e_flag = -1;
static int hf_lbmc_ume_ack_type = -1;
static int hf_lbmc_ume_ack_transport_idx = -1;
static int hf_lbmc_ume_ack_id_2 = -1;
static int hf_lbmc_ume_ack_rcv_reg_id = -1;
static int hf_lbmc_ume_ack_seqnum = -1;
static int hf_lbmc_ume_rxreq = -1;
static int hf_lbmc_ume_rxreq_next_hdr = -1;
static int hf_lbmc_ume_rxreq_hdr_len = -1;
static int hf_lbmc_ume_rxreq_flags = -1;
static int hf_lbmc_ume_rxreq_flags_ignore = -1;
static int hf_lbmc_ume_rxreq_flags_tsni_req = -1;
static int hf_lbmc_ume_rxreq_request_idx = -1;
static int hf_lbmc_ume_rxreq_transport_idx = -1;
static int hf_lbmc_ume_rxreq_id_2 = -1;
static int hf_lbmc_ume_rxreq_seqnum = -1;
static int hf_lbmc_ume_rxreq_rx_port = -1;
static int hf_lbmc_ume_rxreq_res = -1;
static int hf_lbmc_ume_rxreq_rx_ip = -1;
static int hf_lbmc_ume_keepalive = -1;
static int hf_lbmc_ume_keepalive_next_hdr = -1;
static int hf_lbmc_ume_keepalive_hdr_len = -1;
static int hf_lbmc_ume_keepalive_flags = -1;
static int hf_lbmc_ume_keepalive_flags_ignore = -1;
static int hf_lbmc_ume_keepalive_flags_r_flag = -1;
static int hf_lbmc_ume_keepalive_flags_t_flag = -1;
static int hf_lbmc_ume_keepalive_type = -1;
static int hf_lbmc_ume_keepalive_transport_idx = -1;
static int hf_lbmc_ume_keepalive_topic_idx = -1;
static int hf_lbmc_ume_keepalive_reg_id = -1;
static int hf_lbmc_ume_storeid = -1;
static int hf_lbmc_ume_storeid_next_hdr = -1;
static int hf_lbmc_ume_storeid_hdr_len = -1;
static int hf_lbmc_ume_storeid_store_id = -1;
static int hf_lbmc_ume_storeid_store_id_ignore = -1;
static int hf_lbmc_ume_storeid_store_id_store_id = -1;
static int hf_lbmc_ume_ranged_ack = -1;
static int hf_lbmc_ume_ranged_ack_next_hdr = -1;
static int hf_lbmc_ume_ranged_ack_hdr_len = -1;
static int hf_lbmc_ume_ranged_ack_flags = -1;
static int hf_lbmc_ume_ranged_ack_flags_ignore = -1;
static int hf_lbmc_ume_ranged_ack_first_seqnum = -1;
static int hf_lbmc_ume_ranged_ack_last_seqnum = -1;
static int hf_lbmc_ume_ack_id = -1;
static int hf_lbmc_ume_ack_id_next_hdr = -1;
static int hf_lbmc_ume_ack_id_hdr_len = -1;
static int hf_lbmc_ume_ack_id_flags = -1;
static int hf_lbmc_ume_ack_id_flags_ignore = -1;
static int hf_lbmc_ume_ack_id_id = -1;
static int hf_lbmc_ume_capability = -1;
static int hf_lbmc_ume_capability_next_hdr = -1;
static int hf_lbmc_ume_capability_hdr_len = -1;
static int hf_lbmc_ume_capability_flags = -1;
static int hf_lbmc_ume_capability_flags_ignore = -1;
static int hf_lbmc_ume_capability_flags_qc_flag = -1;
static int hf_lbmc_ume_capability_flags_client_lifetime_flag = -1;
static int hf_lbmc_ume_proxy_src = -1;
static int hf_lbmc_ume_proxy_src_next_hdr = -1;
static int hf_lbmc_ume_proxy_src_hdr_len = -1;
static int hf_lbmc_ume_proxy_src_flags = -1;
static int hf_lbmc_ume_proxy_src_flags_ignore = -1;
static int hf_lbmc_ume_proxy_src_flags_enable = -1;
static int hf_lbmc_ume_proxy_src_flags_compatibility = -1;
static int hf_lbmc_ume_store_group = -1;
static int hf_lbmc_ume_store_group_next_hdr = -1;
static int hf_lbmc_ume_store_group_hdr_len = -1;
static int hf_lbmc_ume_store_group_flags = -1;
static int hf_lbmc_ume_store_group_flags_ignore = -1;
static int hf_lbmc_ume_store_group_grp_idx = -1;
static int hf_lbmc_ume_store_group_grp_sz = -1;
static int hf_lbmc_ume_store_group_res1 = -1;
static int hf_lbmc_ume_store = -1;
static int hf_lbmc_ume_store_next_hdr = -1;
static int hf_lbmc_ume_store_hdr_len = -1;
static int hf_lbmc_ume_store_flags = -1;
static int hf_lbmc_ume_store_flags_ignore = -1;
static int hf_lbmc_ume_store_grp_idx = -1;
static int hf_lbmc_ume_store_store_tcp_port = -1;
static int hf_lbmc_ume_store_store_idx = -1;
static int hf_lbmc_ume_store_store_ip_addr = -1;
static int hf_lbmc_ume_store_src_reg_id = -1;
static int hf_lbmc_ume_lj_info = -1;
static int hf_lbmc_ume_lj_info_next_hdr = -1;
static int hf_lbmc_ume_lj_info_hdr_len = -1;
static int hf_lbmc_ume_lj_info_flags = -1;
static int hf_lbmc_ume_lj_info_flags_ignore = -1;
static int hf_lbmc_ume_lj_info_low_seqnum = -1;
static int hf_lbmc_ume_lj_info_high_seqnum = -1;
static int hf_lbmc_ume_lj_info_qidx = -1;
static int hf_lbmc_tsni = -1;
static int hf_lbmc_tsni_next_hdr = -1;
static int hf_lbmc_tsni_hdr_len = -1;
static int hf_lbmc_tsni_num_recs = -1;
static int hf_lbmc_tsni_num_recs_ignore = -1;
static int hf_lbmc_tsni_num_recs_num_recs = -1;
static int hf_lbmc_tsni_rec = -1;
static int hf_lbmc_tsni_rec_tidx = -1;
static int hf_lbmc_tsni_rec_sqn = -1;
static int hf_lbmc_umq_reg = -1;
static int hf_lbmc_umq_reg_next_hdr = -1;
static int hf_lbmc_umq_reg_hdr_len = -1;
static int hf_lbmc_umq_reg_flags = -1;
static int hf_lbmc_umq_reg_flags_ignore = -1;
static int hf_lbmc_umq_reg_flags_r_flag = -1;
static int hf_lbmc_umq_reg_flags_t_flag = -1;
static int hf_lbmc_umq_reg_flags_i_flag = -1;
static int hf_lbmc_umq_reg_flags_msg_sel_flag = -1;
static int hf_lbmc_umq_reg_reg_type = -1;
static int hf_lbmc_umq_reg_queue_id = -1;
static int hf_lbmc_umq_reg_cmd_id = -1;
static int hf_lbmc_umq_reg_inst_idx = -1;
static int hf_lbmc_umq_reg_regid = -1;
static int hf_lbmc_umq_reg_reg_ctx = -1;
static int hf_lbmc_umq_reg_reg_ctx_port = -1;
static int hf_lbmc_umq_reg_reg_ctx_reserved = -1;
static int hf_lbmc_umq_reg_reg_ctx_ip = -1;
static int hf_lbmc_umq_reg_reg_ctx_capabilities = -1;
static int hf_lbmc_umq_reg_reg_src = -1;
static int hf_lbmc_umq_reg_reg_src_transport_idx = -1;
static int hf_lbmc_umq_reg_reg_src_topic_idx = -1;
static int hf_lbmc_umq_reg_reg_rcv = -1;
static int hf_lbmc_umq_reg_reg_rcv_assign_id = -1;
static int hf_lbmc_umq_reg_reg_rcv_rcv_type_id = -1;
static int hf_lbmc_umq_reg_reg_rcv_last_topic_rcr_tsp = -1;
static int hf_lbmc_umq_reg_rcv_dereg = -1;
static int hf_lbmc_umq_reg_rcv_dereg_rcr_idx = -1;
static int hf_lbmc_umq_reg_rcv_dereg_assign_id = -1;
static int hf_lbmc_umq_reg_reg_ulb_rcv = -1;
static int hf_lbmc_umq_reg_reg_ulb_rcv_ulb_src_id = -1;
static int hf_lbmc_umq_reg_reg_ulb_rcv_assign_id = -1;
static int hf_lbmc_umq_reg_reg_ulb_rcv_rcv_type_id = -1;
static int hf_lbmc_umq_reg_reg_ulb_rcv_port = -1;
static int hf_lbmc_umq_reg_reg_ulb_rcv_reserved = -1;
static int hf_lbmc_umq_reg_reg_ulb_rcv_ip = -1;
static int hf_lbmc_umq_reg_reg_ulb_rcv_capabilities = -1;
static int hf_lbmc_umq_reg_ulb_rcv_dereg = -1;
static int hf_lbmc_umq_reg_ulb_rcv_dereg_ulb_src_id = -1;
static int hf_lbmc_umq_reg_ulb_rcv_dereg_assign_id = -1;
static int hf_lbmc_umq_reg_reg_observer_rcv = -1;
static int hf_lbmc_umq_reg_reg_observer_rcv_assign_id = -1;
static int hf_lbmc_umq_reg_reg_observer_rcv_rcv_type_id = -1;
static int hf_lbmc_umq_reg_reg_observer_rcv_last_topic_rcr_tsp = -1;
static int hf_lbmc_umq_reg_observer_rcv_dereg = -1;
static int hf_lbmc_umq_reg_observer_rcv_dereg_rcr_idx = -1;
static int hf_lbmc_umq_reg_observer_rcv_dereg_assign_id = -1;
static int hf_lbmc_umq_reg_resp = -1;
static int hf_lbmc_umq_reg_resp_next_hdr = -1;
static int hf_lbmc_umq_reg_resp_hdr_len = -1;
static int hf_lbmc_umq_reg_resp_flags = -1;
static int hf_lbmc_umq_reg_resp_flags_ignore = -1;
static int hf_lbmc_umq_reg_resp_flags_r_flag = -1;
static int hf_lbmc_umq_reg_resp_flags_l_flag = -1;
static int hf_lbmc_umq_reg_resp_flags_src_s_flag = -1;
static int hf_lbmc_umq_reg_resp_flags_src_d_flag = -1;
static int hf_lbmc_umq_reg_resp_resp_type = -1;
static int hf_lbmc_umq_reg_resp_queue_id = -1;
static int hf_lbmc_umq_reg_resp_cmd_id = -1;
static int hf_lbmc_umq_reg_resp_inst_idx = -1;
static int hf_lbmc_umq_reg_resp_regid = -1;
static int hf_lbmc_umq_reg_resp_reg_ctx = -1;
static int hf_lbmc_umq_reg_resp_reg_ctx_capabilities = -1;
static int hf_lbmc_umq_reg_resp_reg_ctx_ex = -1;
static int hf_lbmc_umq_reg_resp_reg_ctx_ex_capabilities = -1;
static int hf_lbmc_umq_reg_resp_reg_ctx_ex_reserved = -1;
static int hf_lbmc_umq_reg_resp_reg_ctx_ex_flags = -1;
static int hf_lbmc_umq_reg_resp_reg_ctx_ex_flags_firstmsg = -1;
static int hf_lbmc_umq_reg_resp_reg_ctx_ex_stamp = -1;
static int hf_lbmc_umq_reg_resp_err = -1;
static int hf_lbmc_umq_reg_resp_err_reserved = -1;
static int hf_lbmc_umq_reg_resp_err_code = -1;
static int hf_lbmc_umq_reg_resp_reg_src = -1;
static int hf_lbmc_umq_reg_resp_reg_src_rcr_idx = -1;
static int hf_lbmc_umq_reg_resp_reg_rcv = -1;
static int hf_lbmc_umq_reg_resp_reg_rcv_rcr_idx = -1;
static int hf_lbmc_umq_reg_resp_reg_rcv_assign_id = -1;
static int hf_lbmc_umq_reg_resp_reg_rcv_appset_idx = -1;
static int hf_lbmc_umq_reg_resp_reg_rcv_reserved = -1;
static int hf_lbmc_umq_reg_resp_rcv_dereg = -1;
static int hf_lbmc_umq_reg_resp_rcv_dereg_rcr_idx = -1;
static int hf_lbmc_umq_reg_resp_rcv_dereg_assign_id = -1;
static int hf_lbmc_umq_reg_resp_reg_ulb_rcv = -1;
static int hf_lbmc_umq_reg_resp_reg_ulb_rcv_ulb_src_id = -1;
static int hf_lbmc_umq_reg_resp_reg_ulb_rcv_assign_id = -1;
static int hf_lbmc_umq_reg_resp_reg_ulb_rcv_appset_idx = -1;
static int hf_lbmc_umq_reg_resp_reg_ulb_rcv_reserved = -1;
static int hf_lbmc_umq_reg_resp_reg_ulb_rcv_capabilities = -1;
static int hf_lbmc_umq_reg_resp_ulb_rcv_dereg = -1;
static int hf_lbmc_umq_reg_resp_ulb_rcv_dereg_ulb_src_id = -1;
static int hf_lbmc_umq_reg_resp_ulb_rcv_dereg_assign_id = -1;
static int hf_lbmc_umq_reg_resp_reg_observer_rcv = -1;
static int hf_lbmc_umq_reg_resp_reg_observer_rcv_rcr_idx = -1;
static int hf_lbmc_umq_reg_resp_reg_observer_rcv_assign_id = -1;
static int hf_lbmc_umq_reg_resp_reg_observer_rcv_appset_idx = -1;
static int hf_lbmc_umq_reg_resp_reg_observer_rcv_reserved = -1;
static int hf_lbmc_umq_reg_resp_observer_rcv_dereg = -1;
static int hf_lbmc_umq_reg_resp_observer_rcv_dereg_rcr_idx = -1;
static int hf_lbmc_umq_reg_resp_observer_rcv_dereg_assign_id = -1;
static int hf_lbmc_umq_ack = -1;
static int hf_lbmc_umq_ack_next_hdr = -1;
static int hf_lbmc_umq_ack_hdr_len = -1;
static int hf_lbmc_umq_ack_msgs = -1;
static int hf_lbmc_umq_ack_msgs_ignore = -1;
static int hf_lbmc_umq_ack_msgs_t_flag = -1;
static int hf_lbmc_umq_ack_msgs_d_flag = -1;
static int hf_lbmc_umq_ack_msgs_numids = -1;
static int hf_lbmc_umq_ack_ack_type = -1;
static int hf_lbmc_umq_ack_msgid = -1;
static int hf_lbmc_umq_ack_msgid_regid = -1;
static int hf_lbmc_umq_ack_msgid_stamp = -1;
static int hf_lbmc_umq_ack_stable = -1;
static int hf_lbmc_umq_ack_stable_queue_id = -1;
static int hf_lbmc_umq_ack_stable_inst_idx = -1;
static int hf_lbmc_umq_ack_stable_reserved = -1;
static int hf_lbmc_umq_ack_cr = -1;
static int hf_lbmc_umq_ack_cr_rcr_idx = -1;
static int hf_lbmc_umq_ack_cr_assign_id = -1;
static int hf_lbmc_umq_ack_cr_appset_idx = -1;
static int hf_lbmc_umq_ack_cr_reserved = -1;
static int hf_lbmc_umq_ack_ulb_cr = -1;
static int hf_lbmc_umq_ack_ulb_cr_ulb_src_id = -1;
static int hf_lbmc_umq_ack_ulb_cr_assign_id = -1;
static int hf_lbmc_umq_ack_ulb_cr_appset_idx = -1;
static int hf_lbmc_umq_ack_ulb_cr_reserved = -1;
static int hf_lbmc_umq_rcr = -1;
static int hf_lbmc_umq_rcr_next_hdr = -1;
static int hf_lbmc_umq_rcr_hdr_len = -1;
static int hf_lbmc_umq_rcr_flags = -1;
static int hf_lbmc_umq_rcr_flags_ignore = -1;
static int hf_lbmc_umq_rcr_flags_r_flag = -1;
static int hf_lbmc_umq_rcr_flags_d_flag = -1;
static int hf_lbmc_umq_rcr_flags_s_flag = -1;
static int hf_lbmc_umq_rcr_flags_eoi_flag = -1;
static int hf_lbmc_umq_rcr_flags_boi_flag = -1;
static int hf_lbmc_umq_rcr_queue_id = -1;
static int hf_lbmc_umq_rcr_rcr_idx = -1;
static int hf_lbmc_umq_rcr_msgid_regid = -1;
static int hf_lbmc_umq_rcr_msgid_stamp = -1;
static int hf_lbmc_umq_rcr_topic_tsp = -1;
static int hf_lbmc_umq_rcr_q_tsp = -1;
static int hf_lbmc_umq_rcr_assign_id = -1;
static int hf_lbmc_umq_rcr_appset_idx = -1;
static int hf_lbmc_umq_rcr_num_ras = -1;
static int hf_lbmc_umq_rcr_queue_ver = -1;
static int hf_lbmc_cntl_umq_ka = -1;
static int hf_lbmc_cntl_umq_ka_next_hdr = -1;
static int hf_lbmc_cntl_umq_ka_hdr_len = -1;
static int hf_lbmc_cntl_umq_ka_flags = -1;
static int hf_lbmc_cntl_umq_ka_flags_ignore = -1;
static int hf_lbmc_cntl_umq_ka_flags_r_flag = -1;
static int hf_lbmc_cntl_umq_ka_ka_type = -1;
static int hf_lbmc_cntl_umq_ka_queue_id = -1;
static int hf_lbmc_cntl_umq_ka_regid = -1;
static int hf_lbmc_cntl_umq_ka_inst_idx = -1;
static int hf_lbmc_cntl_umq_ka_reserved = -1;
static int hf_lbmc_umq_ka_src = -1;
static int hf_lbmc_umq_ka_src_transport_idx = -1;
static int hf_lbmc_umq_ka_src_topic_idx = -1;
static int hf_lbmc_umq_ka_rcv = -1;
static int hf_lbmc_umq_ka_rcv_rcr_idx = -1;
static int hf_lbmc_umq_ka_rcv_assign_id = -1;
static int hf_lbmc_umq_ka_ulb_rcv = -1;
static int hf_lbmc_umq_ka_ulb_rcv_ulb_src_id = -1;
static int hf_lbmc_umq_ka_ulb_rcv_assign_id = -1;
static int hf_lbmc_umq_ka_ulb_rcv_resp = -1;
static int hf_lbmc_umq_ka_ulb_rcv_resp_ulb_src_id = -1;
static int hf_lbmc_umq_ka_ulb_rcv_resp_assign_id = -1;
static int hf_lbmc_umq_ka_ulb_rcv_resp_appset_idx = -1;
static int hf_lbmc_umq_ka_ulb_rcv_resp_reserved = -1;
static int hf_lbmc_umq_rxreq = -1;
static int hf_lbmc_umq_rxreq_next_hdr = -1;
static int hf_lbmc_umq_rxreq_hdr_len = -1;
static int hf_lbmc_umq_rxreq_flags = -1;
static int hf_lbmc_umq_rxreq_flags_ignore = -1;
static int hf_lbmc_umq_rxreq_flags_r_flag = -1;
static int hf_lbmc_umq_rxreq_rxreq_type = -1;
static int hf_lbmc_umq_rxreq_regid_resp = -1;
static int hf_lbmc_umq_rxreq_regid_resp_regid = -1;
static int hf_lbmc_umq_rxreq_addr_resp = -1;
static int hf_lbmc_umq_rxreq_addr_resp_ip = -1;
static int hf_lbmc_umq_rxreq_addr_resp_port = -1;
static int hf_lbmc_umq_rxreq_addr_resp_reserved = -1;
static int hf_lbmc_umq_rxreq_mr = -1;
static int hf_lbmc_umq_rxreq_mr_assign_id = -1;
static int hf_lbmc_umq_rxreq_mr_msgid_regid = -1;
static int hf_lbmc_umq_rxreq_mr_msgid_stamp = -1;
static int hf_lbmc_umq_rxreq_ulb_mr = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_ulb_src_id = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_assign_id = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_appset_idx = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_reserved = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_msgid_regid = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_msgid_stamp = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_abort = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_abort_ulb_src_id = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_abort_assign_id = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_abort_msgid_regid = -1;
static int hf_lbmc_umq_rxreq_ulb_mr_abort_msgid_stamp = -1;
static int hf_lbmc_umq_rxreq_qrcrr = -1;
static int hf_lbmc_umq_rxreq_qrcrr_tsp = -1;
static int hf_lbmc_umq_rxreq_trcrr = -1;
static int hf_lbmc_umq_rxreq_trcrr_rcr_idx = -1;
static int hf_lbmc_umq_rxreq_trcrr_tsp = -1;
static int hf_lbmc_umq_rxreq_ulb_trcrr = -1;
static int hf_lbmc_umq_rxreq_ulb_trcrr_ulb_src_id = -1;
static int hf_lbmc_umq_rxreq_ulb_trcrr_assign_id = -1;
static int hf_lbmc_umq_rxreq_ulb_trcrr_tsp = -1;
static int hf_lbmc_umq_rxreq_ulb_trcrr_abort = -1;
static int hf_lbmc_umq_rxreq_ulb_trcrr_abort_ulb_src_id = -1;
static int hf_lbmc_umq_rxreq_ulb_trcrr_abort_assign_id = -1;
static int hf_lbmc_umq_rxreq_ulb_trcrr_abort_tsp = -1;
static int hf_lbmc_umq_qmgmt = -1;
static int hf_lbmc_umq_qmgmt_next_hdr = -1;
static int hf_lbmc_umq_qmgmt_hdr_len = -1;
static int hf_lbmc_umq_resub_req = -1;
static int hf_lbmc_umq_resub_req_next_hdr = -1;
static int hf_lbmc_umq_resub_req_hdr_len = -1;
static int hf_lbmc_umq_resub_req_flags = -1;
static int hf_lbmc_umq_resub_req_flags_ignore = -1;
static int hf_lbmc_umq_resub_req_msgid_regid = -1;
static int hf_lbmc_umq_resub_req_msgid_stamp = -1;
static int hf_lbmc_umq_resub_req_rcr_idx = -1;
static int hf_lbmc_umq_resub_req_resp_ip = -1;
static int hf_lbmc_umq_resub_req_resp_port = -1;
static int hf_lbmc_umq_resub_req_appset_idx = -1;
static int hf_lbmc_umq_resub_resp = -1;
static int hf_lbmc_umq_resub_resp_next_hdr = -1;
static int hf_lbmc_umq_resub_resp_hdr_len = -1;
static int hf_lbmc_umq_resub_resp_flags = -1;
static int hf_lbmc_umq_resub_resp_flags_ignore = -1;
static int hf_lbmc_umq_resub_resp_code = -1;
static int hf_lbmc_umq_resub_resp_msgid_regid = -1;
static int hf_lbmc_umq_resub_resp_msgid_stamp = -1;
static int hf_lbmc_umq_resub_resp_rcr_idx = -1;
static int hf_lbmc_umq_resub_resp_reserved = -1;
static int hf_lbmc_umq_resub_resp_appset_idx = -1;
static int hf_lbmc_topic_interest = -1;
static int hf_lbmc_topic_interest_next_hdr = -1;
static int hf_lbmc_topic_interest_hdr_len = -1;
static int hf_lbmc_topic_interest_flags = -1;
static int hf_lbmc_topic_interest_flags_ignore = -1;
static int hf_lbmc_topic_interest_flags_cancel = -1;
static int hf_lbmc_topic_interest_flags_refresh = -1;
static int hf_lbmc_topic_interest_domain_id = -1;
static int hf_lbmc_pattern_interest = -1;
static int hf_lbmc_pattern_interest_next_hdr = -1;
static int hf_lbmc_pattern_interest_hdr_len = -1;
static int hf_lbmc_pattern_interest_flags = -1;
static int hf_lbmc_pattern_interest_flags_ignore = -1;
static int hf_lbmc_pattern_interest_flags_cancel = -1;
static int hf_lbmc_pattern_interest_flags_refresh = -1;
static int hf_lbmc_pattern_interest_type = -1;
static int hf_lbmc_pattern_interest_domain_id = -1;
static int hf_lbmc_pattern_interest_index = -1;
static int hf_lbmc_advertisement = -1;
static int hf_lbmc_advertisement_next_hdr = -1;
static int hf_lbmc_advertisement_hdr_len = -1;
static int hf_lbmc_advertisement_flags = -1;
static int hf_lbmc_advertisement_flags_ignore = -1;
static int hf_lbmc_advertisement_flags_eos = -1;
static int hf_lbmc_advertisement_flags_pattern = -1;
static int hf_lbmc_advertisement_flags_change = -1;
static int hf_lbmc_advertisement_flags_ctxinst = -1;
static int hf_lbmc_advertisement_hop_count = -1;
static int hf_lbmc_advertisement_ad_flags = -1;
static int hf_lbmc_advertisement_ad_flags_lj = -1;
static int hf_lbmc_advertisement_ad_flags_ume = -1;
static int hf_lbmc_advertisement_ad_flags_acktosrc = -1;
static int hf_lbmc_advertisement_ad_flags_queue = -1;
static int hf_lbmc_advertisement_ad_flags_ulb = -1;
static int hf_lbmc_advertisement_cost = -1;
static int hf_lbmc_advertisement_transport_idx = -1;
static int hf_lbmc_advertisement_topic_idx = -1;
static int hf_lbmc_advertisement_low_seqno = -1;
static int hf_lbmc_advertisement_high_seqno = -1;
static int hf_lbmc_advertisement_domain_id = -1;
static int hf_lbmc_advertisement_pat_idx = -1;
static int hf_lbmc_advertisement_ctxinst = -1;
static int hf_lbmc_ume_storename = -1;
static int hf_lbmc_ume_storename_next_hdr = -1;
static int hf_lbmc_ume_storename_hdr_len = -1;
static int hf_lbmc_ume_storename_flags = -1;
static int hf_lbmc_ume_storename_flags_ignore = -1;
static int hf_lbmc_ume_storename_store = -1;
static int hf_lbmc_umq_ulb_rcr = -1;
static int hf_lbmc_umq_ulb_rcr_next_hdr = -1;
static int hf_lbmc_umq_ulb_rcr_hdr_len = -1;
static int hf_lbmc_umq_ulb_rcr_flags = -1;
static int hf_lbmc_umq_ulb_rcr_flags_ignore = -1;
static int hf_lbmc_umq_ulb_rcr_flags_r_flag = -1;
static int hf_lbmc_umq_ulb_rcr_flags_d_flag = -1;
static int hf_lbmc_umq_ulb_rcr_flags_eoi_flag = -1;
static int hf_lbmc_umq_ulb_rcr_flags_boi_flag = -1;
static int hf_lbmc_umq_ulb_rcr_queue_id = -1;
static int hf_lbmc_umq_ulb_rcr_ulb_src_id = -1;
static int hf_lbmc_umq_ulb_rcr_msgid_regid = -1;
static int hf_lbmc_umq_ulb_rcr_msgid_stamp = -1;
static int hf_lbmc_umq_ulb_rcr_topic_tsp = -1;
static int hf_lbmc_umq_ulb_rcr_assign_id = -1;
static int hf_lbmc_umq_ulb_rcr_appset_idx = -1;
static int hf_lbmc_umq_ulb_rcr_num_ras = -1;
static int hf_lbmc_umq_lf = -1;
static int hf_lbmc_umq_lf_next_hdr = -1;
static int hf_lbmc_umq_lf_hdr_len = -1;
static int hf_lbmc_umq_lf_flags = -1;
static int hf_lbmc_umq_lf_flags_ignore = -1;
static int hf_lbmc_umq_lf_type = -1;
static int hf_lbmc_umq_lf_num_srcs = -1;
static int hf_lbmc_umq_lf_lf = -1;
static int hf_lbmc_ctxinfo = -1;
static int hf_lbmc_ctxinfo_next_hdr = -1;
static int hf_lbmc_ctxinfo_hdr_len = -1;
static int hf_lbmc_ctxinfo_flags = -1;
static int hf_lbmc_ctxinfo_flags_ignore = -1;
static int hf_lbmc_ctxinfo_flags_query = -1;
static int hf_lbmc_ctxinfo_flags_addr = -1;
static int hf_lbmc_ctxinfo_flags_ctxinst = -1;
static int hf_lbmc_ctxinfo_flags_name = -1;
static int hf_lbmc_ctxinfo_flags_tnwgsrc = -1;
static int hf_lbmc_ctxinfo_flags_tnwgrcv = -1;
static int hf_lbmc_ctxinfo_flags_proxy = -1;
static int hf_lbmc_ctxinfo_reserved = -1;
static int hf_lbmc_ctxinfo_hop_count = -1;
static int hf_lbmc_ctxinfo_port = -1;
static int hf_lbmc_ctxinfo_addr = -1;
static int hf_lbmc_ctxinfo_domain_id = -1;
static int hf_lbmc_ctxinfo_ctxinst = -1;
static int hf_lbmc_ctxinfo_name = -1;
static int hf_lbmc_ume_pser = -1;
static int hf_lbmc_ume_pser_next_hdr = -1;
static int hf_lbmc_ume_pser_hdr_len = -1;
static int hf_lbmc_ume_pser_flags = -1;
static int hf_lbmc_ume_pser_flags_ignore = -1;
static int hf_lbmc_ume_pser_flags_source_ctxinst = -1;
static int hf_lbmc_ume_pser_flags_store_ctxinst = -1;
static int hf_lbmc_ume_pser_flags_reelect = -1;
static int hf_lbmc_ume_pser_source_ip = -1;
static int hf_lbmc_ume_pser_store_ip = -1;
static int hf_lbmc_ume_pser_transport_idx = -1;
static int hf_lbmc_ume_pser_topic_idx = -1;
static int hf_lbmc_ume_pser_source_port = -1;
static int hf_lbmc_ume_pser_store_port = -1;
static int hf_lbmc_ume_pser_source_ctxinst = -1;
static int hf_lbmc_ume_pser_store_ctxinst = -1;
static int hf_lbmc_domain = -1;
static int hf_lbmc_domain_next_hdr = -1;
static int hf_lbmc_domain_hdr_len = -1;
static int hf_lbmc_domain_flags = -1;
static int hf_lbmc_domain_flags_ignore = -1;
static int hf_lbmc_domain_flags_active = -1;
static int hf_lbmc_domain_domain = -1;
static int hf_lbmc_tnwg_capabilities = -1;
static int hf_lbmc_tnwg_capabilities_next_hdr = -1;
static int hf_lbmc_tnwg_capabilities_hdr_len = -1;
static int hf_lbmc_tnwg_capabilities_flags = -1;
static int hf_lbmc_tnwg_capabilities_flags_ignore = -1;
static int hf_lbmc_tnwg_capabilities_flags_version = -1;
static int hf_lbmc_tnwg_capabilities_capabilities1 = -1;
static int hf_lbmc_tnwg_capabilities_capabilities1_ume = -1;
static int hf_lbmc_tnwg_capabilities_capabilities1_umq = -1;
static int hf_lbmc_tnwg_capabilities_capabilities2 = -1;
static int hf_lbmc_tnwg_capabilities_capabilities3 = -1;
static int hf_lbmc_tnwg_capabilities_capabilities3_pcre = -1;
static int hf_lbmc_tnwg_capabilities_capabilities3_regex = -1;
static int hf_lbmc_tnwg_capabilities_capabilities4 = -1;
static int hf_lbmc_patidx = -1;
static int hf_lbmc_patidx_next_hdr = -1;
static int hf_lbmc_patidx_hdr_len = -1;
static int hf_lbmc_patidx_flags = -1;
static int hf_lbmc_patidx_flags_ignore = -1;
static int hf_lbmc_patidx_patidx = -1;
static int hf_lbmc_ume_client_lifetime = -1;
static int hf_lbmc_ume_client_lifetime_next_hdr = -1;
static int hf_lbmc_ume_client_lifetime_hdr_len = -1;
static int hf_lbmc_ume_client_lifetime_flags = -1;
static int hf_lbmc_ume_client_lifetime_flags_ignore = -1;
static int hf_lbmc_ume_client_lifetime_activity_tmo = -1;
static int hf_lbmc_ume_client_lifetime_lifetime = -1;
static int hf_lbmc_ume_client_lifetime_ttl = -1;
static int hf_lbmc_ume_sid = -1;
static int hf_lbmc_ume_sid_next_hdr = -1;
static int hf_lbmc_ume_sid_hdr_len = -1;
static int hf_lbmc_ume_sid_flags = -1;
static int hf_lbmc_ume_sid_flags_ignore = -1;
static int hf_lbmc_ume_sid_sid = -1;
static int hf_lbmc_umq_idx_cmd = -1;
static int hf_lbmc_umq_idx_cmd_next_hdr = -1;
static int hf_lbmc_umq_idx_cmd_hdr_len = -1;
static int hf_lbmc_umq_idx_cmd_flags = -1;
static int hf_lbmc_umq_idx_cmd_flags_ignore = -1;
static int hf_lbmc_umq_idx_cmd_cmd_type = -1;
static int hf_lbmc_umq_idx_cmd_queue_id = -1;
static int hf_lbmc_umq_idx_cmd_cmd_id = -1;
static int hf_lbmc_umq_idx_cmd_inst_idx = -1;
static int hf_lbmc_umq_idx_cmd_regid = -1;
static int hf_lbmc_umq_idx_cmd_stop_assign = -1;
static int hf_lbmc_umq_idx_cmd_stop_assign_rcr_idx = -1;
static int hf_lbmc_umq_idx_cmd_stop_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_start_assign = -1;
static int hf_lbmc_umq_idx_cmd_start_assign_rcr_idx = -1;
static int hf_lbmc_umq_idx_cmd_start_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_release_assign = -1;
static int hf_lbmc_umq_idx_cmd_release_assign_rcr_idx = -1;
static int hf_lbmc_umq_idx_cmd_release_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_release_assign_flags = -1;
static int hf_lbmc_umq_idx_cmd_release_assign_flags_numeric = -1;
static int hf_lbmc_umq_idx_cmd_release_assign_index_len = -1;
static int hf_lbmc_umq_idx_cmd_release_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_release_assign_numeric_index = -1;
static int hf_lbmc_umq_idx_cmd_release_assign_string_index = -1;
static int hf_lbmc_umq_idx_cmd_ulb_stop_assign = -1;
static int hf_lbmc_umq_idx_cmd_ulb_stop_assign_src_id = -1;
static int hf_lbmc_umq_idx_cmd_ulb_stop_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_ulb_stop_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_ulb_stop_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_ulb_start_assign = -1;
static int hf_lbmc_umq_idx_cmd_ulb_start_assign_src_id = -1;
static int hf_lbmc_umq_idx_cmd_ulb_start_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_ulb_start_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_ulb_start_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_src_id = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_flags = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_flags_numeric = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_index_len = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_numeric_index = -1;
static int hf_lbmc_umq_idx_cmd_ulb_release_assign_string_index = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign_rcr_idx = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign_flags = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign_flags_numeric = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign_index_len = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign_numeric_index = -1;
static int hf_lbmc_umq_idx_cmd_reserve_assign_string_index = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_src_id = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_flags = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_flags_numeric = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_index_len = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_numeric_index = -1;
static int hf_lbmc_umq_idx_cmd_ulb_reserve_assign_string_index = -1;
static int hf_lbmc_umq_idx_cmd_resp = -1;
static int hf_lbmc_umq_idx_cmd_resp_next_hdr = -1;
static int hf_lbmc_umq_idx_cmd_resp_hdr_len = -1;
static int hf_lbmc_umq_idx_cmd_resp_flags = -1;
static int hf_lbmc_umq_idx_cmd_resp_flags_ignore = -1;
static int hf_lbmc_umq_idx_cmd_resp_flags_ulb = -1;
static int hf_lbmc_umq_idx_cmd_resp_resp_type = -1;
static int hf_lbmc_umq_idx_cmd_resp_queue_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_cmd_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_inst_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_regid = -1;
static int hf_lbmc_umq_idx_cmd_resp_err = -1;
static int hf_lbmc_umq_idx_cmd_resp_err_reserved = -1;
static int hf_lbmc_umq_idx_cmd_resp_err_code = -1;
static int hf_lbmc_umq_idx_cmd_resp_err_error_string = -1;
static int hf_lbmc_umq_idx_cmd_resp_stop_assign = -1;
static int hf_lbmc_umq_idx_cmd_resp_stop_assign_rcr_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_stop_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_start_assign = -1;
static int hf_lbmc_umq_idx_cmd_resp_start_assign_rcr_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_start_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_start_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_start_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_resp_release_assign = -1;
static int hf_lbmc_umq_idx_cmd_resp_release_assign_rcr_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_release_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_release_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_release_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_src_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_start_assign = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_src_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_release_assign = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_src_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_rcr_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_flags = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_flags_numeric = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_index_len = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_numeric_index = -1;
static int hf_lbmc_umq_idx_cmd_resp_reserve_assign_string_index = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_src_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_assign_id = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags_numeric = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_appset_idx = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_index_len = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_reserved = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_numeric_index = -1;
static int hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_string_index = -1;
static int hf_lbmc_odomain = -1;
static int hf_lbmc_odomain_next_hdr = -1;
static int hf_lbmc_odomain_hdr_len = -1;
static int hf_lbmc_odomain_flags = -1;
static int hf_lbmc_odomain_flags_ignore = -1;
static int hf_lbmc_odomain_domain = -1;
static int hf_lbmc_stream = -1;
static int hf_lbmc_stream_next_hdr = -1;
static int hf_lbmc_stream_hdr_len = -1;
static int hf_lbmc_stream_flags = -1;
static int hf_lbmc_stream_flags_ignore = -1;
static int hf_lbmc_stream_stream_id = -1;
static int hf_lbmc_stream_sqn = -1;
static int hf_lbmc_stream_ctxinst = -1;
static int hf_lbmc_topic_md_interest = -1;
static int hf_lbmc_topic_md_interest_next_hdr = -1;
static int hf_lbmc_topic_md_interest_hdr_len = -1;
static int hf_lbmc_topic_md_interest_flags = -1;
static int hf_lbmc_topic_md_interest_flags_ignore = -1;
static int hf_lbmc_topic_md_interest_flags_cancel = -1;
static int hf_lbmc_topic_md_interest_flags_refresh = -1;
static int hf_lbmc_topic_md_interest_domain_count = -1;
static int hf_lbmc_topic_md_interest_res1 = -1;
static int hf_lbmc_topic_md_interest_domain_id = -1;
static int hf_lbmc_pattern_md_interest = -1;
static int hf_lbmc_pattern_md_interest_next_hdr = -1;
static int hf_lbmc_pattern_md_interest_hdr_len = -1;
static int hf_lbmc_pattern_md_interest_flags = -1;
static int hf_lbmc_pattern_md_interest_flags_ignore = -1;
static int hf_lbmc_pattern_md_interest_flags_cancel = -1;
static int hf_lbmc_pattern_md_interest_flags_refresh = -1;
static int hf_lbmc_pattern_md_interest_type = -1;
static int hf_lbmc_pattern_md_interest_domain_count = -1;
static int hf_lbmc_pattern_md_interest_res1 = -1;
static int hf_lbmc_pattern_md_interest_index = -1;
static int hf_lbmc_pattern_md_interest_domain_id = -1;
static int hf_lbmc_lji_req = -1;
static int hf_lbmc_lji_req_next_hdr = -1;
static int hf_lbmc_lji_req_hdr_len = -1;
static int hf_lbmc_lji_req_flags = -1;
static int hf_lbmc_lji_req_flags_ignore = -1;
static int hf_lbmc_lji_req_flags_l_flag = -1;
static int hf_lbmc_lji_req_flags_m_flag = -1;
static int hf_lbmc_lji_req_flags_o_flag = -1;
static int hf_lbmc_lji_req_request_idx = -1;
static int hf_lbmc_lji_req_transport_idx = -1;
static int hf_lbmc_lji_req_topic_idx = -1;
static int hf_lbmc_lji_req_req_ip = -1;
static int hf_lbmc_lji_req_req_port = -1;
static int hf_lbmc_lji_req_res = -1;
static int hf_lbmc_lji_req_tx_low_sqn = -1;
static int hf_lbmc_lji_req_rx_req_max = -1;
static int hf_lbmc_lji_req_rx_req_outstanding_max = -1;
static int hf_lbmc_tnwg_ka = -1;
static int hf_lbmc_tnwg_ka_next_hdr = -1;
static int hf_lbmc_tnwg_ka_hdr_len = -1;
static int hf_lbmc_tnwg_ka_flags = -1;
static int hf_lbmc_tnwg_ka_flags_ignore = -1;
static int hf_lbmc_tnwg_ka_flags_q_flag = -1;
static int hf_lbmc_tnwg_ka_flags_r_flag = -1;
static int hf_lbmc_tnwg_ka_index = -1;
static int hf_lbmc_tnwg_ka_ts_seconds = -1;
static int hf_lbmc_tnwg_ka_ts_microseconds = -1;
static int hf_lbmc_tnwg_ka_reserved_1 = -1;
static int hf_lbmc_tnwg_ka_reserved_2 = -1;
static int hf_lbmc_tnwg_ka_reserved_3 = -1;
static int hf_lbmc_tnwg_ka_reserved_4 = -1;
static int hf_lbmc_tnwg_ka_reserved_5 = -1;
static int hf_lbmc_tnwg_ka_reserved_6 = -1;
static int hf_lbmc_ume_receiver_keepalive = -1;
static int hf_lbmc_ume_receiver_keepalive_next_hdr = -1;
static int hf_lbmc_ume_receiver_keepalive_hdr_len = -1;
static int hf_lbmc_ume_receiver_keepalive_flags = -1;
static int hf_lbmc_ume_receiver_keepalive_flags_ignore = -1;
static int hf_lbmc_ume_receiver_keepalive_rcv_regid = -1;
static int hf_lbmc_ume_receiver_keepalive_session_id = -1;
static int hf_lbmc_ume_receiver_keepalive_ctxinst = -1;
static int hf_lbmc_umq_cmd = -1;
static int hf_lbmc_umq_cmd_next_hdr = -1;
static int hf_lbmc_umq_cmd_hdr_len = -1;
static int hf_lbmc_umq_cmd_flags = -1;
static int hf_lbmc_umq_cmd_flags_ignore = -1;
static int hf_lbmc_umq_cmd_cmd_type = -1;
static int hf_lbmc_umq_cmd_queue_id = -1;
static int hf_lbmc_umq_cmd_cmd_id = -1;
static int hf_lbmc_umq_cmd_inst_idx = -1;
static int hf_lbmc_umq_cmd_regid = -1;
static int hf_lbmc_umq_cmd_topic_list = -1;
static int hf_lbmc_umq_cmd_topic_list_serial_num = -1;
static int hf_lbmc_umq_cmd_msg_retrieve = -1;
static int hf_lbmc_umq_cmd_msg_retrieve_rcr_idx = -1;
static int hf_lbmc_umq_cmd_msg_retrieve_assign_id = -1;
static int hf_lbmc_umq_cmd_msg_retrieve_info_only = -1;
static int hf_lbmc_umq_cmd_msg_retrieve_num_msgids = -1;
static int hf_lbmc_umq_cmd_msg_retrieve_flags = -1;
static int hf_lbmc_umq_cmd_msg_retrieve_entry = -1;
static int hf_lbmc_umq_cmd_msg_retrieve_entry_regid = -1;
static int hf_lbmc_umq_cmd_msg_retrieve_entry_stamp = -1;
static int hf_lbmc_umq_cmd_msg_list = -1;
static int hf_lbmc_umq_cmd_msg_list_rcr_idx = -1;
static int hf_lbmc_umq_cmd_msg_list_assign_id = -1;
static int hf_lbmc_umq_cmd_resp = -1;
static int hf_lbmc_umq_cmd_resp_next_hdr = -1;
static int hf_lbmc_umq_cmd_resp_hdr_len = -1;
static int hf_lbmc_umq_cmd_resp_flags = -1;
static int hf_lbmc_umq_cmd_resp_flags_ignore = -1;
static int hf_lbmc_umq_cmd_resp_resp_type = -1;
static int hf_lbmc_umq_cmd_resp_queue_id = -1;
static int hf_lbmc_umq_cmd_resp_cmd_id = -1;
static int hf_lbmc_umq_cmd_resp_inst_idx = -1;
static int hf_lbmc_umq_cmd_resp_regid = -1;
static int hf_lbmc_umq_cmd_resp_msg_retrieve = -1;
static int hf_lbmc_umq_cmd_resp_msg_retrieve_rcr_idx = -1;
static int hf_lbmc_umq_cmd_resp_msg_retrieve_assign_id = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_num_msgs = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_flags = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_reserved = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_regid = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_stamp = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_assign_id = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_num_ras = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_status = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_reserved = -1;
static int hf_lbmc_umq_cmd_resp_msg_list = -1;
static int hf_lbmc_umq_cmd_resp_msg_list_rcr_idx = -1;
static int hf_lbmc_umq_cmd_resp_msg_list_assign_id = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_list = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_list_num_msgs = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_list_entry = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_list_entry_regid = -1;
static int hf_lbmc_umq_cmd_resp_xmsg_list_entry_stamp = -1;
static int hf_lbmc_umq_cmd_resp_topic_list = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_num_topics = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_rcr_idx = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_num_appsets = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_topic_len = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_reserved = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_topic = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_num_receiver_type_ids = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_appset_idx = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_appset_name_len = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_reserved = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_name = -1;
static int hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_receiver_type_id = -1;
static int hf_lbmc_umq_cmd_resp_err = -1;
static int hf_lbmc_umq_cmd_resp_err_reserved = -1;
static int hf_lbmc_umq_cmd_resp_err_code = -1;
static int hf_lbmc_umq_cmd_resp_err_errmsg = -1;
static int hf_lbmc_sri_req = -1;
static int hf_lbmc_sri_req_next_hdr = -1;
static int hf_lbmc_sri_req_hdr_len = -1;
static int hf_lbmc_sri_req_flags = -1;
static int hf_lbmc_sri_req_flags_ignore = -1;
static int hf_lbmc_sri_req_transport_idx = -1;
static int hf_lbmc_sri_req_topic_idx = -1;
static int hf_lbmc_ume_store_domain = -1;
static int hf_lbmc_ume_store_domain_next_hdr = -1;
static int hf_lbmc_ume_store_domain_hdr_len = -1;
static int hf_lbmc_ume_store_domain_flags = -1;
static int hf_lbmc_ume_store_domain_flags_ignore = -1;
static int hf_lbmc_ume_store_domain_domain = -1;
static int hf_lbmc_sri = -1;
static int hf_lbmc_sri_next_hdr = -1;
static int hf_lbmc_sri_hdr_len = -1;
static int hf_lbmc_sri_flags = -1;
static int hf_lbmc_sri_flags_ignore = -1;
static int hf_lbmc_sri_flags_acktosrc = -1;
static int hf_lbmc_sri_flags_initial_sqn_known = -1;
static int hf_lbmc_sri_version = -1;
static int hf_lbmc_sri_low_sqn = -1;
static int hf_lbmc_sri_high_sqn = -1;
static int hf_lbmc_route_info = -1;
static int hf_lbmc_route_info_next_hdr = -1;
static int hf_lbmc_route_info_hdr_len = -1;
static int hf_lbmc_route_info_flags = -1;
static int hf_lbmc_route_info_flags_ignore = -1;
static int hf_lbmc_route_info_gateway_version = -1;
static int hf_lbmc_route_info_configuration_signature = -1;
static int hf_lbmc_route_info_node_id = -1;
static int hf_lbmc_route_info_topology = -1;
static int hf_lbmc_route_info_vers = -1;
static int hf_lbmc_route_info_sqn = -1;
static int hf_lbmc_route_info_ttl = -1;
static int hf_lbmc_route_info_reserved1 = -1;
static int hf_lbmc_route_info_reserved2 = -1;
static int hf_lbmc_route_info_neighbor = -1;
static int hf_lbmc_route_info_neighbor_next_hdr = -1;
static int hf_lbmc_route_info_neighbor_hdr_len = -1;
static int hf_lbmc_route_info_neighbor_flags = -1;
static int hf_lbmc_route_info_neighbor_flags_ignore = -1;
static int hf_lbmc_route_info_neighbor_node_id = -1;
static int hf_lbmc_route_info_neighbor_ingress_cost = -1;
static int hf_lbmc_route_info_neighbor_egress_cost = -1;
static int hf_lbmc_gateway_name = -1;
static int hf_lbmc_gateway_name_next_hdr = -1;
static int hf_lbmc_gateway_name_hdr_len = -1;
static int hf_lbmc_gateway_name_flags = -1;
static int hf_lbmc_gateway_name_flags_ignore = -1;
static int hf_lbmc_gateway_name_gateway_name = -1;
static int hf_lbmc_auth_request = -1;
static int hf_lbmc_auth_request_next_hdr = -1;
static int hf_lbmc_auth_request_hdr_len = -1;
static int hf_lbmc_auth_request_flags = -1;
static int hf_lbmc_auth_request_flags_ignore = -1;
static int hf_lbmc_auth_request_opid = -1;
static int hf_lbmc_auth_request_user_len = -1;
static int hf_lbmc_auth_request_user_name = -1;
static int hf_lbmc_auth_challenge = -1;
static int hf_lbmc_auth_challenge_next_hdr = -1;
static int hf_lbmc_auth_challenge_hdr_len = -1;
static int hf_lbmc_auth_challenge_flags = -1;
static int hf_lbmc_auth_challenge_flags_ignore = -1;
static int hf_lbmc_auth_challenge_opid = -1;
static int hf_lbmc_auth_challenge_mod_len = -1;
static int hf_lbmc_auth_challenge_gen_len = -1;
static int hf_lbmc_auth_challenge_salt_len = -1;
static int hf_lbmc_auth_challenge_pubkey_len = -1;
static int hf_lbmc_auth_challenge_mod = -1;
static int hf_lbmc_auth_challenge_gen = -1;
static int hf_lbmc_auth_challenge_salt = -1;
static int hf_lbmc_auth_challenge_pubkey = -1;
static int hf_lbmc_auth_challenge_rsp = -1;
static int hf_lbmc_auth_challenge_rsp_next_hdr = -1;
static int hf_lbmc_auth_challenge_rsp_hdr_len = -1;
static int hf_lbmc_auth_challenge_rsp_flags = -1;
static int hf_lbmc_auth_challenge_rsp_flags_ignore = -1;
static int hf_lbmc_auth_challenge_rsp_opid = -1;
static int hf_lbmc_auth_challenge_rsp_pubkey_len = -1;
static int hf_lbmc_auth_challenge_rsp_evidence_len = -1;
static int hf_lbmc_auth_challenge_rsp_pubkey = -1;
static int hf_lbmc_auth_challenge_rsp_evidence = -1;
static int hf_lbmc_auth_result = -1;
static int hf_lbmc_auth_result_next_hdr = -1;
static int hf_lbmc_auth_result_hdr_len = -1;
static int hf_lbmc_auth_result_flags = -1;
static int hf_lbmc_auth_result_flags_ignore = -1;
static int hf_lbmc_auth_result_opid = -1;
static int hf_lbmc_auth_result_result = -1;
static int hf_lbmc_auth_unknown = -1;
static int hf_lbmc_auth_unknown_next_hdr = -1;
static int hf_lbmc_auth_unknown_hdr_len = -1;
static int hf_lbmc_auth_unknown_flags = -1;
static int hf_lbmc_auth_unknown_opid = -1;
static int hf_lbmc_auth_unknown_data = -1;
static int hf_lbmc_hmac = -1;
static int hf_lbmc_hmac_next_hdr = -1;
static int hf_lbmc_hmac_hdr_len = -1;
static int hf_lbmc_hmac_flags = -1;
static int hf_lbmc_hmac_flags_ignore = -1;
static int hf_lbmc_hmac_padding = -1;
static int hf_lbmc_hmac_data = -1;
static int hf_lbmc_umq_sid = -1;
static int hf_lbmc_umq_sid_next_hdr = -1;
static int hf_lbmc_umq_sid_hdr_len = -1;
static int hf_lbmc_umq_sid_flags = -1;
static int hf_lbmc_umq_sid_flags_ignore = -1;
static int hf_lbmc_umq_sid_key = -1;
static int hf_lbmc_umq_sid_sid = -1;
static int hf_lbmc_destination = -1;
static int hf_lbmc_destination_next_hdr = -1;
static int hf_lbmc_destination_hdr_len = -1;
static int hf_lbmc_destination_flags = -1;
static int hf_lbmc_destination_flags_ignore = -1;
static int hf_lbmc_destination_domain_id = -1;
static int hf_lbmc_destination_ipaddr = -1;
static int hf_lbmc_destination_port = -1;
static int hf_lbmc_destination_hops_taken = -1;
static int hf_lbmc_destination_orig_domain_id = -1;
static int hf_lbmc_destination_orig_ipaddr = -1;
static int hf_lbmc_destination_orig_port = -1;
static int hf_lbmc_destination_reserved = -1;
static int hf_lbmc_topic_idx = -1;
static int hf_lbmc_topic_idx_next_hdr = -1;
static int hf_lbmc_topic_idx_hdr_len = -1;
static int hf_lbmc_topic_idx_flags = -1;
static int hf_lbmc_topic_idx_flags_ignore = -1;
static int hf_lbmc_topic_idx_tidx = -1;
static int hf_lbmc_topic_source = -1;
static int hf_lbmc_topic_source_next_hdr = -1;
static int hf_lbmc_topic_source_hdr_len = -1;
static int hf_lbmc_topic_source_flags = -1;
static int hf_lbmc_topic_source_flags_ignore = -1;
static int hf_lbmc_topic_source_flags_eos = -1;
static int hf_lbmc_topic_source_domain_id = -1;
static int hf_lbmc_topic_source_exfunc = -1;
static int hf_lbmc_topic_source_exfunc_next_hdr = -1;
static int hf_lbmc_topic_source_exfunc_hdr_len = -1;
static int hf_lbmc_topic_source_exfunc_flags = -1;
static int hf_lbmc_topic_source_exfunc_flags_ignore = -1;
static int hf_lbmc_topic_source_exfunc_src_ip = -1;
static int hf_lbmc_topic_source_exfunc_src_port = -1;
static int hf_lbmc_topic_source_exfunc_unused = -1;
static int hf_lbmc_topic_source_exfunc_functionality_flags = -1;
static int hf_lbmc_topic_source_exfunc_functionality_flags_ulb = -1;
static int hf_lbmc_topic_source_exfunc_functionality_flags_umq = -1;
static int hf_lbmc_topic_source_exfunc_functionality_flags_ume = -1;
static int hf_lbmc_topic_source_exfunc_functionality_flags_lj = -1;
static int hf_lbmc_ume_store_ext = -1;
static int hf_lbmc_ume_store_ext_next_hdr = -1;
static int hf_lbmc_ume_store_ext_hdr_len = -1;
static int hf_lbmc_ume_store_ext_flags = -1;
static int hf_lbmc_ume_store_ext_flags_ignore = -1;
static int hf_lbmc_ume_store_ext_grp_idx = -1;
static int hf_lbmc_ume_store_ext_store_tcp_port = -1;
static int hf_lbmc_ume_store_ext_store_idx = -1;
static int hf_lbmc_ume_store_ext_store_ip_addr = -1;
static int hf_lbmc_ume_store_ext_src_reg_id = -1;
static int hf_lbmc_ume_store_ext_domain_id = -1;
static int hf_lbmc_ume_store_ext_version = -1;
static int hf_lbmc_ume_psrc_election_token = -1;
static int hf_lbmc_ume_psrc_election_token_next_hdr = -1;
static int hf_lbmc_ume_psrc_election_token_hdr_len = -1;
static int hf_lbmc_ume_psrc_election_token_flags = -1;
static int hf_lbmc_ume_psrc_election_token_flags_ignore = -1;
static int hf_lbmc_ume_psrc_election_token_store_index = -1;
static int hf_lbmc_ume_psrc_election_token_token = -1;
static int hf_lbmc_tcp_sid = -1;
static int hf_lbmc_tcp_sid_next_hdr = -1;
static int hf_lbmc_tcp_sid_hdr_len = -1;
static int hf_lbmc_tcp_sid_flags = -1;
static int hf_lbmc_tcp_sid_flags_ignore = -1;
static int hf_lbmc_tcp_sid_sid = -1;
static int hf_lbmc_extopt = -1;
static int hf_lbmc_extopt_next_hdr = -1;
static int hf_lbmc_extopt_hdr_len = -1;
static int hf_lbmc_extopt_flags = -1;
static int hf_lbmc_extopt_flags_ignore = -1;
static int hf_lbmc_extopt_flags_ignore_subtype = -1;
static int hf_lbmc_extopt_flags_more_fragments = -1;
static int hf_lbmc_extopt_id = -1;
static int hf_lbmc_extopt_subtype = -1;
static int hf_lbmc_extopt_fragment_offset = -1;
static int hf_lbmc_extopt_data = -1;
static int hf_lbmc_extopt_cfgopt = -1;
static int hf_lbmc_extopt_cfgopt_scope = -1;
static int hf_lbmc_extopt_cfgopt_parent = -1;
static int hf_lbmc_extopt_cfgopt_name = -1;
static int hf_lbmc_extopt_cfgopt_value = -1;
static int hf_lbmc_extopt_msgsel = -1;
static int hf_lbmc_extopt_reassembled_data = -1;
static int hf_lbmc_extopt_reassembled_data_subtype = -1;
static int hf_lbmc_extopt_reassembled_data_len = -1;
static int hf_lbmc_extopt_reassembled_data_data = -1;
static int hf_lbmc_extopt_reassembled_data_msgsel = -1;
static int hf_lbm_msg_properties = -1;
static int hf_lbm_msg_properties_data = -1;
static int hf_lbm_msg_properties_data_magic = -1;
static int hf_lbm_msg_properties_data_num_fields = -1;
static int hf_lbm_msg_properties_data_vertype = -1;
static int hf_lbm_msg_properties_data_vertype_version = -1;
static int hf_lbm_msg_properties_data_vertype_type = -1;
static int hf_lbm_msg_properties_data_res = -1;
static int hf_lbm_msg_properties_hdr = -1;
static int hf_lbm_msg_properties_hdr_key_offset = -1;
static int hf_lbm_msg_properties_hdr_value_offset = -1;
static int hf_lbm_msg_properties_hdr_hash = -1;
static int hf_lbm_msg_properties_hdr_type = -1;
static int hf_lbm_msg_properties_hdr_key = -1;
static int hf_lbm_msg_properties_hdr_boolean_value = -1;
static int hf_lbm_msg_properties_hdr_byte_value = -1;
static int hf_lbm_msg_properties_hdr_short_value = -1;
static int hf_lbm_msg_properties_hdr_int_value = -1;
static int hf_lbm_msg_properties_hdr_float_value = -1;
static int hf_lbm_msg_properties_hdr_long_value = -1;
static int hf_lbm_msg_properties_hdr_double_value = -1;
static int hf_lbm_msg_properties_hdr_string_value = -1;
static int hf_lbm_msg_properties_hdr_unknown_value = -1;
static int hf_lbmc_unhandled = -1;
static int hf_lbmc_unhandled_next_hdr = -1;
static int hf_lbmc_unhandled_hdr_len = -1;
static int hf_lbmc_unhandled_data = -1;
static int hf_lbm_stream = -1;
static int hf_lbm_stream_stream_id = -1;
static int hf_lbm_stream_substream_id = -1;
static int hf_lbmc_reassembly = -1;
static int hf_lbmc_reassembly_fragment = -1;
static int hf_reassembly_frame = -1;

/* Protocol trees */
static gint ett_lbmc = -1;
static gint ett_lbmc_ver_type = -1;
static gint ett_lbmc_frag = -1;
static gint ett_lbmc_frag_flags = -1;
static gint ett_lbmc_batch = -1;
static gint ett_lbmc_batch_flags = -1;
static gint ett_lbmc_tcp_request = -1;
static gint ett_lbmc_tcp_request_flags = -1;
static gint ett_lbmc_topicname = -1;
static gint ett_lbmc_topicname_flags = -1;
static gint ett_lbmc_apphdr = -1;
static gint ett_lbmc_apphdr_code = -1;
static gint ett_lbmc_apphdr_chain = -1;
static gint ett_lbmc_apphdr_chain_element = -1;
static gint ett_lbmc_apphdr_chain_msgprop = -1;
static gint ett_lbmc_umq_msgid = -1;
static gint ett_lbmc_umq_msgid_flags = -1;
static gint ett_lbmc_umq_sqd_rcv = -1;
static gint ett_lbmc_umq_sqd_rcv_flags = -1;
static gint ett_lbmc_umq_resub = -1;
static gint ett_lbmc_umq_resub_flags = -1;
static gint ett_lbmc_otid = -1;
static gint ett_lbmc_otid_flags = -1;
static gint ett_lbmc_ctxinst = -1;
static gint ett_lbmc_ctxinst_flags = -1;
static gint ett_lbmc_ctxinstd = -1;
static gint ett_lbmc_ctxinstr = -1;
static gint ett_lbmc_srcidx = -1;
static gint ett_lbmc_srcidx_flags = -1;
static gint ett_lbmc_umq_ulb_msg = -1;
static gint ett_lbmc_umq_ulb_msg_flags = -1;
static gint ett_lbmc_ssf_init = -1;
static gint ett_lbmc_ssf_init_flags = -1;
static gint ett_lbmc_ssf_creq = -1;
static gint ett_lbmc_ssf_creq_flags = -1;
static gint ett_lbmc_ume_preg = -1;
static gint ett_lbmc_ume_preg_flags = -1;
static gint ett_lbmc_ume_preg_marker = -1;
static gint ett_lbmc_ume_preg_resp = -1;
static gint ett_lbmc_ume_preg_resp_code = -1;
static gint ett_lbmc_ume_preg_resp_marker = -1;
static gint ett_lbmc_ume_ack = -1;
static gint ett_lbmc_ume_ack_flags = -1;
static gint ett_lbmc_ume_rxreq = -1;
static gint ett_lbmc_ume_rxreq_flags = -1;
static gint ett_lbmc_ume_keepalive = -1;
static gint ett_lbmc_ume_keepalive_flags = -1;
static gint ett_lbmc_ume_storeid = -1;
static gint ett_lbmc_ume_storeid_store_id = -1;
static gint ett_lbmc_ume_ranged_ack = -1;
static gint ett_lbmc_ume_ranged_ack_flags = -1;
static gint ett_lbmc_ume_ack_id = -1;
static gint ett_lbmc_ume_ack_id_flags = -1;
static gint ett_lbmc_ume_capability = -1;
static gint ett_lbmc_ume_capability_flags = -1;
static gint ett_lbmc_ume_proxy_src = -1;
static gint ett_lbmc_ume_proxy_src_flags = -1;
static gint ett_lbmc_ume_store_group = -1;
static gint ett_lbmc_ume_store_group_flags = -1;
static gint ett_lbmc_ume_store = -1;
static gint ett_lbmc_ume_store_flags = -1;
static gint ett_lbmc_ume_lj_info = -1;
static gint ett_lbmc_ume_lj_info_flags = -1;
static gint ett_lbmc_tsni = -1;
static gint ett_lbmc_tsni_num_recs = -1;
static gint ett_lbmc_tsni_rec = -1;
static gint ett_lbmc_umq_reg = -1;
static gint ett_lbmc_umq_reg_flags = -1;
static gint ett_lbmc_umq_reg_reg_ctx = -1;
static gint ett_lbmc_umq_reg_reg_src = -1;
static gint ett_lbmc_umq_reg_reg_rcv = -1;
static gint ett_lbmc_umq_reg_rcv_dereg = -1;
static gint ett_lbmc_umq_reg_reg_ulb_rcv = -1;
static gint ett_lbmc_umq_reg_ulb_rcv_dereg = -1;
static gint ett_lbmc_umq_reg_reg_observer_rcv = -1;
static gint ett_lbmc_umq_reg_observer_rcv_dereg = -1;
static gint ett_lbmc_umq_reg_resp = -1;
static gint ett_lbmc_umq_reg_resp_flags = -1;
static gint ett_lbmc_umq_reg_resp_reg_ctx = -1;
static gint ett_lbmc_umq_reg_resp_reg_ctx_ex = -1;
static gint ett_lbmc_umq_reg_resp_reg_ctx_ex_flags = -1;
static gint ett_lbmc_umq_reg_resp_err = -1;
static gint ett_lbmc_umq_reg_resp_reg_src = -1;
static gint ett_lbmc_umq_reg_resp_reg_rcv = -1;
static gint ett_lbmc_umq_reg_resp_rcv_dereg = -1;
static gint ett_lbmc_umq_reg_resp_reg_ulb_rcv = -1;
static gint ett_lbmc_umq_reg_resp_ulb_rcv_dereg = -1;
static gint ett_lbmc_umq_reg_resp_reg_observer_rcv = -1;
static gint ett_lbmc_umq_reg_resp_observer_rcv_dereg = -1;
static gint ett_lbmc_umq_ack = -1;
static gint ett_lbmc_umq_ack_msgs = -1;
static gint ett_lbmc_umq_ack_msgid = -1;
static gint ett_lbmc_umq_ack_stable = -1;
static gint ett_lbmc_umq_ack_cr = -1;
static gint ett_lbmc_umq_ack_ulb_cr = -1;
static gint ett_lbmc_umq_rcr = -1;
static gint ett_lbmc_umq_rcr_flags = -1;
static gint ett_lbmc_umq_ka = -1;
static gint ett_lbmc_umq_ka_flags = -1;
static gint ett_lbmc_umq_ka_src = -1;
static gint ett_lbmc_umq_ka_rcv = -1;
static gint ett_lbmc_umq_ka_ulb_rcv = -1;
static gint ett_lbmc_umq_ka_ulb_rcv_resp = -1;
static gint ett_lbmc_umq_rxreq = -1;
static gint ett_lbmc_umq_rxreq_flags = -1;
static gint ett_lbmc_umq_rxreq_regid_resp = -1;
static gint ett_lbmc_umq_rxreq_addr_resp = -1;
static gint ett_lbmc_umq_rxreq_mr = -1;
static gint ett_lbmc_umq_rxreq_ulb_mr = -1;
static gint ett_lbmc_umq_rxreq_ulb_mr_abort = -1;
static gint ett_lbmc_umq_rxreq_qrcrr = -1;
static gint ett_lbmc_umq_rxreq_trcrr = -1;
static gint ett_lbmc_umq_rxreq_ulb_trcrr = -1;
static gint ett_lbmc_umq_rxreq_ulb_trcrr_abort = -1;
static gint ett_lbmc_umq_qmgmt = -1;
static gint ett_lbmc_umq_resub_req = -1;
static gint ett_lbmc_umq_resub_req_flags = -1;
static gint ett_lbmc_umq_resub_resp = -1;
static gint ett_lbmc_umq_resub_resp_flags = -1;
static gint ett_lbmc_topic_interest = -1;
static gint ett_lbmc_topic_interest_flags = -1;
static gint ett_lbmc_pattern_interest = -1;
static gint ett_lbmc_pattern_interest_flags = -1;
static gint ett_lbmc_advertisement = -1;
static gint ett_lbmc_advertisement_flags = -1;
static gint ett_lbmc_advertisement_ad_flags = -1;
static gint ett_lbmc_ume_storename = -1;
static gint ett_lbmc_ume_storename_flags = -1;
static gint ett_lbmc_umq_ulb_rcr = -1;
static gint ett_lbmc_umq_ulb_rcr_flags = -1;
static gint ett_lbmc_umq_lf = -1;
static gint ett_lbmc_umq_lf_flags = -1;
static gint ett_lbmc_ctxinfo = -1;
static gint ett_lbmc_ctxinfo_flags = -1;
static gint ett_lbmc_ume_pser = -1;
static gint ett_lbmc_ume_pser_flags = -1;
static gint ett_lbmc_domain = -1;
static gint ett_lbmc_domain_flags = -1;
static gint ett_lbmc_tnwg_capabilities = -1;
static gint ett_lbmc_tnwg_capabilities_flags = -1;
static gint ett_lbmc_tnwg_capabilities_capabilities1 = -1;
static gint ett_lbmc_tnwg_capabilities_capabilities3 = -1;
static gint ett_lbmc_patidx = -1;
static gint ett_lbmc_patidx_flags = -1;
static gint ett_lbmc_ume_client_lifetime = -1;
static gint ett_lbmc_ume_client_lifetime_flags = -1;
static gint ett_lbmc_ume_sid = -1;
static gint ett_lbmc_ume_sid_flags = -1;
static gint ett_lbmc_umq_idx_cmd = -1;
static gint ett_lbmc_umq_idx_cmd_flags = -1;
static gint ett_lbmc_umq_idx_cmd_stop_assign = -1;
static gint ett_lbmc_umq_idx_cmd_start_assign = -1;
static gint ett_lbmc_umq_idx_cmd_release_assign = -1;
static gint ett_lbmc_umq_idx_cmd_release_assign_flags = -1;
static gint ett_lbmc_umq_idx_cmd_ulb_stop_assign = -1;
static gint ett_lbmc_umq_idx_cmd_ulb_start_assign = -1;
static gint ett_lbmc_umq_idx_cmd_ulb_release_assign = -1;
static gint ett_lbmc_umq_idx_cmd_ulb_release_assign_flags = -1;
static gint ett_lbmc_umq_idx_cmd_reserve_assign = -1;
static gint ett_lbmc_umq_idx_cmd_reserve_assign_flags = -1;
static gint ett_lbmc_umq_idx_cmd_ulb_reserve_assign = -1;
static gint ett_lbmc_umq_idx_cmd_ulb_reserve_assign_flags = -1;
static gint ett_lbmc_umq_idx_cmd_resp = -1;
static gint ett_lbmc_umq_idx_cmd_resp_flags = -1;
static gint ett_lbmc_umq_idx_cmd_resp_err = -1;
static gint ett_lbmc_umq_idx_cmd_resp_stop_assign = -1;
static gint ett_lbmc_umq_idx_cmd_resp_start_assign = -1;
static gint ett_lbmc_umq_idx_cmd_resp_release_assign = -1;
static gint ett_lbmc_umq_idx_cmd_resp_ulb_stop_assign = -1;
static gint ett_lbmc_umq_idx_cmd_resp_ulb_start_assign = -1;
static gint ett_lbmc_umq_idx_cmd_resp_ulb_release_assign = -1;
static gint ett_lbmc_umq_idx_cmd_resp_reserve_assign = -1;
static gint ett_lbmc_umq_idx_cmd_resp_reserve_assign_flags = -1;
static gint ett_lbmc_umq_idx_cmd_resp_ulb_reserve_assign = -1;
static gint ett_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags = -1;
static gint ett_lbmc_odomain = -1;
static gint ett_lbmc_odomain_flags = -1;
static gint ett_lbmc_stream = -1;
static gint ett_lbmc_stream_flags = -1;
static gint ett_lbmc_topic_md_interest = -1;
static gint ett_lbmc_topic_md_interest_flags = -1;
static gint ett_lbmc_pattern_md_interest = -1;
static gint ett_lbmc_pattern_md_interest_flags = -1;
static gint ett_lbmc_lji_req = -1;
static gint ett_lbmc_lji_req_flags = -1;
static gint ett_lbmc_tnwg_ka = -1;
static gint ett_lbmc_tnwg_ka_flags = -1;
static gint ett_lbmc_ume_receiver_keepalive = -1;
static gint ett_lbmc_ume_receiver_keepalive_flags = -1;
static gint ett_lbmc_umq_cmd = -1;
static gint ett_lbmc_umq_cmd_flags = -1;
static gint ett_lbmc_umq_cmd_topic_list = -1;
static gint ett_lbmc_umq_cmd_msg_retrieve = -1;
static gint ett_lbmc_umq_cmd_msg_retrieve_entry = -1;
static gint ett_lbmc_umq_cmd_msg_list = -1;
static gint ett_lbmc_umq_cmd_resp = -1;
static gint ett_lbmc_umq_cmd_resp_flags = -1;
static gint ett_lbmc_umq_cmd_resp_msg_retrieve = -1;
static gint ett_lbmc_umq_cmd_resp_xmsg_retrieve = -1;
static gint ett_lbmc_umq_cmd_resp_xmsg_retrieve_entry = -1;
static gint ett_lbmc_umq_cmd_resp_msg_list = -1;
static gint ett_lbmc_umq_cmd_resp_xmsg_list = -1;
static gint ett_lbmc_umq_cmd_resp_xmsg_list_entry = -1;
static gint ett_lbmc_umq_cmd_resp_topic_list = -1;
static gint ett_lbmc_umq_cmd_resp_topic_list_topic_entry = -1;
static gint ett_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry = -1;
static gint ett_lbmc_umq_cmd_resp_err = -1;
static gint ett_lbmc_sri_req = -1;
static gint ett_lbmc_sri_req_flags = -1;
static gint ett_lbmc_ume_store_domain = -1;
static gint ett_lbmc_ume_store_domain_flags = -1;
static gint ett_lbmc_sri = -1;
static gint ett_lbmc_sri_flags = -1;
static gint ett_lbmc_route_info = -1;
static gint ett_lbmc_route_info_flags = -1;
static gint ett_lbmc_route_info_neighbor = -1;
static gint ett_lbmc_route_info_neighbor_flags = -1;
static gint ett_lbmc_gateway_name = -1;
static gint ett_lbmc_gateway_name_flags = -1;
static gint ett_lbmc_auth_request = -1;
static gint ett_lbmc_auth_request_flags = -1;
static gint ett_lbmc_auth_challenge = -1;
static gint ett_lbmc_auth_challenge_flags = -1;
static gint ett_lbmc_auth_challenge_rsp = -1;
static gint ett_lbmc_auth_challenge_rsp_flags = -1;
static gint ett_lbmc_auth_result = -1;
static gint ett_lbmc_auth_result_flags = -1;
static gint ett_lbmc_auth_unknown = -1;
static gint ett_lbmc_hmac = -1;
static gint ett_lbmc_hmac_flags = -1;
static gint ett_lbmc_umq_sid = -1;
static gint ett_lbmc_umq_sid_flags = -1;
static gint ett_lbmc_destination = -1;
static gint ett_lbmc_destination_flags = -1;
static gint ett_lbmc_topic_idx = -1;
static gint ett_lbmc_topic_idx_flags = -1;
static gint ett_lbmc_topic_source = -1;
static gint ett_lbmc_topic_source_flags = -1;
static gint ett_lbmc_topic_source_exfunc = -1;
static gint ett_lbmc_topic_source_exfunc_flags = -1;
static gint ett_lbmc_topic_source_exfunc_functionality_flags = -1;
static gint ett_lbmc_ume_store_ext = -1;
static gint ett_lbmc_ume_store_ext_flags = -1;
static gint ett_lbmc_ume_psrc_election_token = -1;
static gint ett_lbmc_ume_psrc_election_token_flags = -1;
static gint ett_lbmc_tcp_sid = -1;
static gint ett_lbmc_tcp_sid_flags = -1;
static gint ett_lbmc_extopt = -1;
static gint ett_lbmc_extopt_flags = -1;
static gint ett_lbmc_extopt_cfgopt = -1;
static gint ett_lbmc_extopt_reassembled_data = -1;
static gint ett_lbmc_extopt_reassembled_data_cfgopt = -1;
static gint ett_lbm_msg_properties = -1;
static gint ett_lbm_msg_properties_data = -1;
static gint ett_lbm_msg_properties_data_vertype = -1;
static gint ett_lbm_msg_properties_hdr = -1;
static gint ett_lbmc_unhandled_hdr = -1;
static gint ett_lbm_stream = -1;
static gint ett_lbmc_reassembly = -1;
static gint ett_unknown = -1;
static gint ett_msg_data = -1;
static gint ett_msgprop_data = -1;

/* Expert info handles */
static expert_field ei_lbmc_analysis_length_incorrect = EI_INIT;
static expert_field ei_lbmc_analysis_zero_length = EI_INIT;
static expert_field ei_lbmc_analysis_tsni = EI_INIT;
static expert_field ei_lbmc_analysis_invalid_value = EI_INIT;
static expert_field ei_lbmc_analysis_no_reassembly = EI_INIT;
static expert_field ei_lbmc_analysis_invalid_offset = EI_INIT;
static expert_field ei_lbmc_analysis_missing_reassembly_frame = EI_INIT;
static expert_field ei_lbmc_analysis_invalid_fragment = EI_INIT;

/* Extended option reassembly structures. */
#define LBMC_EXTOPT_REASSEMBLED_DATA_MAX_LEN 65536
typedef struct
{
    gboolean reassembly_in_progress;
    guint16 subtype;
    int len;
    gchar data[LBMC_EXTOPT_REASSEMBLED_DATA_MAX_LEN];
} lbmc_extopt_reassembled_data_t;

/* Stream structures. */
typedef struct
{
    gboolean set;
    guint32 stream_id;
    guint32 sqn;
    gchar ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbmc_stream_info_t;

typedef struct
{
    gboolean set;
    gchar ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbmc_ctxinst_info_t;

typedef struct
{
    gboolean set;
    lbm_uim_stream_destination_t endpoint_a;
    lbm_uim_stream_destination_t endpoint_b;
} lbmc_destination_info_t;

/* TCP session ID structures. */
typedef struct
{
    gboolean set;
    guint32 session_id;
} lbmc_tcp_sid_info_t;

/*----------------------------------------------------------------------------*/
/* Message reassembly.                                                        */
/*----------------------------------------------------------------------------*/
#define LBMC_MESSAGE_KEY_ELEMENT_COUNT        5
#define LBMC_MESSAGE_KEY_ELEMENT_CHANNEL_HIGH 0
#define LBMC_MESSAGE_KEY_ELEMENT_CHANNEL_LOW  1
#define LBMC_MESSAGE_KEY_ELEMENT_ADDR         2
#define LBMC_MESSAGE_KEY_ELEMENT_PORT         3
#define LBMC_MESSAGE_KEY_ELEMENT_FIRST_SQN    4

static wmem_tree_t * lbmc_message_table = NULL;

typedef struct
{
    int fragment_found;
    guint32 first_sqn;
    guint32 offset;
    guint32 len;
} lbmc_fragment_info_t;

struct lbmc_fragment_entry_t_stct;
typedef struct lbmc_fragment_entry_t_stct lbmc_fragment_entry_t;
struct lbmc_fragment_entry_t_stct
{
    lbmc_fragment_entry_t * prev;
    lbmc_fragment_entry_t * next;
    guint32 fragment_start;
    guint32 fragment_len;
    guint32 frame;
    int frame_offset;
    gchar * data;
};

typedef struct
{
    guint64 channel;
    address addr;
    guint16 port;
    guint32 first_sqn;
    guint32 fragment_count;
    guint32 total_len;
    guint32 accumulated_len;
    guint32 msgprop_len;
    gboolean data_is_umq_cmd_resp;
    lbmc_fragment_entry_t * entry;
    guint32 reassembled_frame;
    tvbuff_t * reassembled_data;
    tvbuff_t * data;
    tvbuff_t * msgprop;
} lbmc_message_entry_t;

static void lbmc_message_build_key(guint32 * key_value, wmem_tree_key_t * key, const lbmc_message_entry_t * message)
{
    guint32 val;

    key_value[LBMC_MESSAGE_KEY_ELEMENT_CHANNEL_HIGH] = (guint32) ((message->channel >> 32) & 0xffffffff);
    key_value[LBMC_MESSAGE_KEY_ELEMENT_CHANNEL_LOW] = (guint32) ((message->channel & 0xffffffff) >> 32);
    memcpy((void *) &val, (void *) message->addr.data, sizeof(guint32));
    key_value[LBMC_MESSAGE_KEY_ELEMENT_ADDR] = val;
    key_value[LBMC_MESSAGE_KEY_ELEMENT_PORT] = (guint32) message->port;
    key_value[LBMC_MESSAGE_KEY_ELEMENT_FIRST_SQN] = message->first_sqn;
    key[0].length = LBMC_MESSAGE_KEY_ELEMENT_COUNT;
    key[0].key = key_value;
    key[1].length = 0;
    key[1].key = NULL;
}

static lbmc_message_entry_t * lbmc_message_find(guint64 channel, const address * dest_address, guint16 port, lbmc_fragment_info_t * info)
{
    lbmc_message_entry_t key;
    lbmc_message_entry_t * entry = NULL;
    guint32 keyval[LBMC_MESSAGE_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    memset((void *)&key, 0, sizeof(lbmc_message_entry_t));
    key.channel = channel;
    COPY_ADDRESS_SHALLOW(&(key.addr), dest_address);
    key.port = port;
    key.first_sqn = info->first_sqn;
    lbmc_message_build_key(keyval, tkey, &key);
    entry = (lbmc_message_entry_t *) wmem_tree_lookup32_array(lbmc_message_table, tkey);
    return (entry);
}

static lbmc_message_entry_t * lbmc_message_create(guint64 channel, const address * dest_address, guint16 port, lbmc_fragment_info_t * info, guint32 msgprop_length)
{
    lbmc_message_entry_t * entry = NULL;
    guint32 keyval[LBMC_MESSAGE_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    entry = lbmc_message_find(channel, dest_address, port, info);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbmc_message_entry_t);
    entry->channel = channel;
    SE_COPY_ADDRESS(&(entry->addr), dest_address);
    entry->port = port;
    entry->first_sqn = info->first_sqn;
    entry->fragment_count = 0;
    entry->total_len = info->len;
    entry->accumulated_len = 0;
    entry->msgprop_len = msgprop_length;
    entry->data_is_umq_cmd_resp = FALSE;
    entry->entry = NULL;
    entry->reassembled_frame = 0;
    entry->reassembled_data = NULL;
    entry->data = NULL;
    entry->msgprop = NULL;
    lbmc_message_build_key(keyval, tkey, entry);
    wmem_tree_insert32_array(lbmc_message_table, tkey, (void *) entry);
    return (entry);
}

static void lbmc_message_add_fragment(lbmc_message_entry_t * message, tvbuff_t * tvb, int data_offset, lbmc_fragment_info_t * info, guint32 frame)
{
    lbmc_fragment_entry_t * frag = NULL;
    lbmc_fragment_entry_t * cur = NULL;

    if ((tvb == NULL) || (info == NULL) || (message == NULL))
    {
        return;
    }
    if (message->entry == NULL)
    {
        frag = wmem_new(wmem_file_scope(), lbmc_fragment_entry_t);
        if (frag == NULL)
        {
            return;
        }
        frag->prev = NULL;
        frag->next = NULL;
        message->entry = frag;
    }
    else
    {
        cur = message->entry;
        while (cur != NULL)
        {
            if (info->offset == cur->fragment_start)
            {
                /* Already have this fragment */
                return;
            }
            if (info->offset < cur->fragment_start)
            {
                /* Fragment goes after cur->prev */
                cur = cur->prev;
                break;
            }
            if (cur->next == NULL)
            {
                /* Fragment goes after cur */
                break;
            }
            cur = cur->next;
        }
        frag = wmem_new(wmem_file_scope(), lbmc_fragment_entry_t);
        if (frag == NULL)
        {
            return;
        }
        if (cur == NULL)
        {
            frag->prev = NULL;
            frag->next = message->entry;
            message->entry->prev = frag;
            message->entry = frag;
        }
        else
        {
            frag->prev = cur;
            frag->next = cur->next;
            cur->next = frag;
            if (frag->next != NULL)
            {
                frag->next->prev = frag;
            }
        }
    }
    frag->fragment_start = info->offset;
    frag->fragment_len = tvb_reported_length_remaining(tvb, data_offset);
    frag->data = (gchar *) tvb_memdup(wmem_file_scope(), tvb, data_offset, frag->fragment_len);
    frag->frame = frame;
    frag->frame_offset = data_offset;
    message->accumulated_len += frag->fragment_len;
    message->fragment_count++;
}

/*----------------------------------------------------------------------------*/
/* Message table/reassembly functions.                                        */
/*----------------------------------------------------------------------------*/
static void lbmc_init_extopt_reassembled_data(lbmc_extopt_reassembled_data_t * reassembly)
{
    reassembly->reassembly_in_progress = FALSE;
    reassembly->subtype = 0;
    reassembly->len = 0;
    memset((void *)&(reassembly->data), 0, sizeof(reassembly->data));
}

/*----------------------------------------------------------------------------*/
/* Dissection functions.                                                      */
/*----------------------------------------------------------------------------*/
static int dissect_nhdr_frag(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmc_fragment_info_t * frag_info)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_frag, tvb, offset, L_LBMC_FRAG_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_frag);
    proto_tree_add_item(subtree, hf_lbmc_frag_next_hdr, tvb, offset + O_LBMC_FRAG_HDR_T_NEXT_HDR, L_LBMC_FRAG_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_frag_hdr_len, tvb, offset + O_LBMC_FRAG_HDR_T_HDR_LEN, L_LBMC_FRAG_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_FRAG_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_frag_flags, tvb, offset + O_LBMC_FRAG_HDR_T_FLAGS, L_LBMC_FRAG_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_frag);
    proto_tree_add_item(flags_tree, hf_lbmc_frag_flags_ignore, tvb, offset + O_LBMC_FRAG_HDR_T_FLAGS, L_LBMC_FRAG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_frag_first_sqn, tvb, offset + O_LBMC_FRAG_HDR_T_FIRST_SQN, L_LBMC_FRAG_HDR_T_FIRST_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_frag_offset, tvb, offset + O_LBMC_FRAG_HDR_T_OFFSET, L_LBMC_FRAG_HDR_T_OFFSET, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_frag_len, tvb, offset + O_LBMC_FRAG_HDR_T_LEN, L_LBMC_FRAG_HDR_T_LEN, ENC_BIG_ENDIAN);
    if (frag_info != NULL)
    {
        frag_info->fragment_found = 1;
        frag_info->first_sqn = tvb_get_ntohl(tvb, offset + O_LBMC_FRAG_HDR_T_FIRST_SQN);
        frag_info->offset = tvb_get_ntohl(tvb, offset + O_LBMC_FRAG_HDR_T_OFFSET);
        frag_info->len = tvb_get_ntohl(tvb, offset + O_LBMC_FRAG_HDR_T_LEN);
    }
    return (L_LBMC_FRAG_HDR_T);
}

static int dissect_nhdr_batch(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_batch, tvb, offset, L_LBMC_BATCH_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_batch);
    proto_tree_add_item(subtree, hf_lbmc_batch_next_hdr, tvb, offset + O_LBMC_BATCH_HDR_T_NEXT_HDR, L_LBMC_BATCH_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_batch_hdr_len, tvb, offset + O_LBMC_BATCH_HDR_T_HDR_LEN, L_LBMC_BATCH_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_BATCH_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_batch_flags, tvb, offset + O_LBMC_BATCH_HDR_T_FLAGS, L_LBMC_BATCH_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_batch_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_batch_flags_ignore, tvb, offset + O_LBMC_BATCH_HDR_T_FLAGS, L_LBMC_BATCH_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_batch_flags_batch_start, tvb, offset + O_LBMC_BATCH_HDR_T_FLAGS, L_LBMC_BATCH_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_batch_flags_batch_end, tvb, offset + O_LBMC_BATCH_HDR_T_FLAGS, L_LBMC_BATCH_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    return (L_LBMC_BATCH_HDR_T);
}

static int dissect_nhdr_request(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_tcp_request, tvb, offset, L_LBMC_TCP_REQUEST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_tcp_request);
    proto_tree_add_item(subtree, hf_lbmc_tcp_request_next_hdr, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_NEXT_HDR, L_LBMC_TCP_REQUEST_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tcp_request_hdr_len, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_HDR_LEN, L_LBMC_TCP_REQUEST_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_tcp_request_flags, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_FLAGS, L_LBMC_TCP_REQUEST_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_tcp_request_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_tcp_request_flags_ignore, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_FLAGS, L_LBMC_TCP_REQUEST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tcp_request_transport, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_TRANSPORT, L_LBMC_TCP_REQUEST_HDR_T_TRANSPORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tcp_request_qidx, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_QIDX, L_LBMC_TCP_REQUEST_HDR_T_QIDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tcp_request_port, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_PORT, L_LBMC_TCP_REQUEST_HDR_T_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tcp_request_reserved, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_RESERVED, L_LBMC_TCP_REQUEST_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tcp_request_ipaddr, tvb, offset + O_LBMC_TCP_REQUEST_HDR_T_IPADDR, L_LBMC_TCP_REQUEST_HDR_T_IPADDR, ENC_BIG_ENDIAN);
    return (L_LBMC_TCP_REQUEST_HDR_T);
}

static int dissect_nhdr_topicname(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;
    int len_dissected = 0;
    int namelen = 0;
    proto_item * hdrlen_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_TOPICNAME_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_topicname, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_topicname);
    proto_tree_add_item(subtree, hf_lbmc_topicname_next_hdr, tvb, offset + O_LBMC_TOPICNAME_HDR_T_NEXT_HDR, L_LBMC_TOPICNAME_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_topicname_hdr_len, tvb, offset + O_LBMC_TOPICNAME_HDR_T_HDR_LEN, L_LBMC_TOPICNAME_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_TOPICNAME_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_topicname_flags, tvb, offset + O_LBMC_TOPICNAME_HDR_T_FLAGS, L_LBMC_TOPICNAME_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_topicname_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_topicname_flags_ignore, tvb, offset + O_LBMC_TOPICNAME_HDR_T_FLAGS, L_LBMC_TOPICNAME_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_BASIC_HDR_T;
    namelen = (int) hdrlen - len_dissected;
    if (namelen > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_topicname_topicname, tvb, offset + O_LBMC_TOPICNAME_HDR_T_FLAGS + L_LBMC_TOPICNAME_HDR_T_FLAGS, namelen, ENC_ASCII | ENC_NA);
        len_dissected += namelen;
    }
    else
    {
        expert_add_info(pinfo, hdrlen_item, &ei_lbmc_analysis_length_incorrect);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_apphdr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * code_item = NULL;
    proto_tree * code_tree = NULL;
    guint16 code = 0;
    int len_dissected = 0;
    int datalen = 0;
    proto_item * hdrlen_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_APPHDR_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_apphdr, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_apphdr);
    proto_tree_add_item(subtree, hf_lbmc_apphdr_next_hdr, tvb, offset + O_LBMC_APPHDR_HDR_T_NEXT_HDR, L_LBMC_APPHDR_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_apphdr_hdr_len, tvb, offset + O_LBMC_APPHDR_HDR_T_HDR_LEN, L_LBMC_APPHDR_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    code = tvb_get_ntohs(tvb, offset + O_LBMC_APPHDR_HDR_T_CODE);
    code_item = proto_tree_add_none_format(subtree, hf_lbmc_apphdr_code, tvb, offset + O_LBMC_APPHDR_HDR_T_CODE, L_LBMC_APPHDR_HDR_T_CODE, "Code: 0x%04x", code);
    code_tree = proto_item_add_subtree(code_item, ett_lbmc_apphdr_code);
    proto_tree_add_item(code_tree, hf_lbmc_apphdr_code_ignore, tvb, offset + O_LBMC_APPHDR_HDR_T_CODE, L_LBMC_APPHDR_HDR_T_CODE, ENC_BIG_ENDIAN);
    proto_tree_add_item(code_tree, hf_lbmc_apphdr_code_code, tvb, offset + O_LBMC_APPHDR_HDR_T_CODE, L_LBMC_APPHDR_HDR_T_CODE, ENC_BIG_ENDIAN);
    len_dissected = O_LBMC_APPHDR_HDR_T_CODE + L_LBMC_APPHDR_HDR_T_CODE;
    datalen = (int) hdrlen - len_dissected;
    if (datalen > 0)
    {
        proto_tree_add_none_format(subtree, hf_lbmc_apphdr_data, tvb, O_LBMC_APPHDR_HDR_T_CODE + L_LBMC_APPHDR_HDR_T_CODE, datalen, "Data (%u bytes)", datalen);
        len_dissected += datalen;
    }
    else
    {
        expert_add_info(pinfo, hdrlen_item, &ei_lbmc_analysis_length_incorrect);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_apphdr_chain_element(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, guint8 element)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * hdrlen_item;
    int datalen = 0;
    int len_dissected = 0;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_APPHDR_CHAIN_ELEMENT_T_HDR_LEN);
    subtree_item = proto_tree_add_none_format(tree, hf_lbmc_apphdr_chain_element, tvb, offset, (gint)hdrlen, "%s element", val_to_str(element, lbmc_apphdr_chain_type, "Unknown (0x%02x)"));
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_apphdr_chain_element);
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_element_next_hdr, tvb, offset + O_LBMC_APPHDR_CHAIN_ELEMENT_T_NEXT_HDR, L_LBMC_APPHDR_CHAIN_ELEMENT_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_element_hdr_len, tvb, offset + O_LBMC_APPHDR_CHAIN_ELEMENT_T_HDR_LEN, L_LBMC_APPHDR_CHAIN_ELEMENT_T_HDR_LEN, ENC_BIG_ENDIAN);
    if (hdrlen == 0)
    {
        expert_add_info_format(pinfo, hdrlen_item, &ei_lbmc_analysis_zero_length, "Element header length is zero");
        return ((int)hdrlen);
    }
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_element_res, tvb, offset + O_LBMC_APPHDR_CHAIN_ELEMENT_T_RES, L_LBMC_APPHDR_CHAIN_ELEMENT_T_RES, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_APPHDR_CHAIN_ELEMENT_T_MIN;
    datalen = (int) hdrlen - len_dissected;
    if (datalen > 0)
    {
        proto_tree_add_none_format(subtree, hf_lbmc_apphdr_chain_element_data, tvb, offset + O_LBMC_APPHDR_CHAIN_ELEMENT_T_RES + L_LBMC_APPHDR_CHAIN_ELEMENT_T_RES, datalen, "Data (%u bytes)", datalen);
        len_dissected += datalen;
    }
    else
    {
        expert_add_info(pinfo, hdrlen_item, &ei_lbmc_analysis_length_incorrect);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_apphdr_chain_msgprop_element(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, guint8 element, guint32 * msg_prop_len)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    guint32 datalen;
    int len_dissected = 0;
    proto_item * hdrlen_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_HDR_LEN);
    subtree_item = proto_tree_add_none_format(tree, hf_lbmc_apphdr_chain_msgprop, tvb, offset, (gint)hdrlen, "%s element", val_to_str(element, lbmc_apphdr_chain_type, "Unknown (0x%02x)"));
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_apphdr_chain_msgprop);
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_msgprop_next_hdr, tvb, offset + O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_NEXT_HDR, L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_msgprop_hdr_len, tvb, offset + O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_HDR_LEN, L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_HDR_LEN, ENC_BIG_ENDIAN);
    if (hdrlen == 0)
    {
        expert_add_info_format(pinfo, hdrlen_item, &ei_lbmc_analysis_zero_length, "Element header length is zero");
        return ((int)hdrlen);
    }
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_msgprop_res, tvb, offset + O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_RES, L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_RES, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_msgprop_len, tvb, offset + O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_LEN, L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_LEN, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T;
    datalen = tvb_get_ntohl(tvb, offset + O_LBMC_APPHDR_CHAIN_MSGPROP_ELEMENT_T_LEN);
    if (msg_prop_len != NULL)
    {
        *msg_prop_len += datalen;
    }
    len_dissected += datalen;
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_apphdr_chain(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, guint32 * msg_prop_len)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    guint8 datalen = 0;
    int elem_offset = 0;
    int elem_len = 0;
    guint8 elem = 0;
    int len_dissected = 0;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_APPHDR_CHAIN_HDR_T_HDR_LEN);
    datalen = hdrlen - L_LBMC_APPHDR_CHAIN_HDR_T;
    subtree_item = proto_tree_add_item(tree, hf_lbmc_apphdr_chain, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_apphdr_chain);
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_next_hdr, tvb, offset + O_LBMC_APPHDR_CHAIN_HDR_T_NEXT_HDR, L_LBMC_APPHDR_CHAIN_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_hdr_len, tvb, offset + O_LBMC_APPHDR_CHAIN_HDR_T_HDR_LEN, L_LBMC_APPHDR_CHAIN_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_res, tvb, offset + O_LBMC_APPHDR_CHAIN_HDR_T_RES, L_LBMC_APPHDR_CHAIN_HDR_T_RES, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_apphdr_chain_first_chain_hdr, tvb, offset + O_LBMC_APPHDR_CHAIN_HDR_T_FIRST_CHAIN_HDR, L_LBMC_APPHDR_CHAIN_HDR_T_FIRST_CHAIN_HDR, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_APPHDR_CHAIN_HDR_T;
    elem_offset = offset + L_LBMC_APPHDR_CHAIN_HDR_T;
    elem = tvb_get_guint8(tvb, offset + O_LBMC_APPHDR_CHAIN_HDR_T_FIRST_CHAIN_HDR);
    while (datalen > 0)
    {
        switch (elem)
        {
            case LBM_CHAIN_ELEM_PROPERTIES_LENGTH:
                elem_len = dissect_nhdr_apphdr_chain_msgprop_element(tvb, elem_offset, pinfo, subtree, elem, msg_prop_len);
                break;
            default:
                elem_len = dissect_nhdr_apphdr_chain_element(tvb, elem_offset, pinfo, subtree, elem);
                break;
        }
        if (elem_len == 0)
        {
            return (len_dissected);
        }
        elem_offset += elem_len;
        datalen -= elem_len;
        len_dissected += elem_len;
        if (datalen >= L_LBMC_APPHDR_CHAIN_ELEMENT_T_MIN)
        {
            elem = tvb_get_guint8(tvb, elem_offset + O_LBMC_APPHDR_CHAIN_ELEMENT_T_NEXT_HDR);
        }
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_msgid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_msgid, tvb, offset, L_LBMC_UMQ_MSGID_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_msgid);
    proto_tree_add_item(subtree, hf_lbmc_umq_msgid_next_hdr, tvb, offset + O_LBMC_UMQ_MSGID_HDR_T_NEXT_HDR, L_LBMC_UMQ_MSGID_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_msgid_hdr_len, tvb, offset + O_LBMC_UMQ_MSGID_HDR_T_HDR_LEN, L_LBMC_UMQ_MSGID_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_UMQ_MSGID_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_msgid_flags, tvb, offset + O_LBMC_UMQ_MSGID_HDR_T_FLAGS, L_LBMC_UMQ_MSGID_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_msgid_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_msgid_flags_ignore, tvb, offset + O_LBMC_UMQ_MSGID_HDR_T_FLAGS, L_LBMC_UMQ_MSGID_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_msgid_msgid_regid, tvb, offset + O_LBMC_UMQ_MSGID_HDR_T_MSGID_REGID, L_LBMC_UMQ_MSGID_HDR_T_MSGID_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_msgid_msgid_stamp, tvb, offset + O_LBMC_UMQ_MSGID_HDR_T_MSGID_STAMP, L_LBMC_UMQ_MSGID_HDR_T_MSGID_STAMP, ENC_BIG_ENDIAN);
    return (L_LBMC_UMQ_MSGID_HDR_T);
}

static int dissect_nhdr_umq_sqd_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, gboolean * data_is_response)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_sqd_rcv, tvb, offset, L_LBMC_UMQ_SQD_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_sqd_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_sqd_rcv_next_hdr, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_NEXT_HDR, L_LBMC_UMQ_SQD_RCV_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_sqd_rcv_hdr_len, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_HDR_LEN, L_LBMC_UMQ_SQD_RCV_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_sqd_rcv_flags, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_sqd_rcv_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_sqd_rcv_flags_ignore, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_sqd_rcv_flags_r_flag, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_sqd_rcv_flags_s_flag, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_sqd_rcv_flags_re_flag, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_sqd_rcv_flags_eoi_flag, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_sqd_rcv_flags_boi_flag, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_sqd_rcv_queue_id, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_QUEUE_ID, L_LBMC_UMQ_SQD_RCV_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_sqd_rcv_queue_ver, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_QUEUE_VER, L_LBMC_UMQ_SQD_RCV_HDR_T_QUEUE_VER, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_sqd_rcv_rcr_idx, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_RCR_IDX, L_LBMC_UMQ_SQD_RCV_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_sqd_rcv_assign_id, tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_ASSIGN_ID, L_LBMC_UMQ_SQD_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    if (data_is_response != NULL)
    {
        guint32 rcr_index;

        rcr_index = tvb_get_ntohl(tvb, offset + O_LBMC_UMQ_SQD_RCV_HDR_T_RCR_IDX);
        if (rcr_index == 0)
        {
            *data_is_response = TRUE;
        }
        else
        {
            *data_is_response = FALSE;
        }
    }
    return (L_LBMC_UMQ_SQD_RCV_HDR_T);
}

static int dissect_nhdr_umq_resub(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_resub, tvb, offset, L_LBMC_UMQ_RESUB_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_resub);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_next_hdr, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_NEXT_HDR, L_LBMC_UMQ_RESUB_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_hdr_len, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_HDR_LEN, L_LBMC_UMQ_RESUB_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_resub_flags, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_FLAGS, L_LBMC_UMQ_RESUB_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_resub_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_resub_flags_ignore, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_FLAGS, L_LBMC_UMQ_RESUB_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_resub_flags_q_flag, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_FLAGS, L_LBMC_UMQ_RESUB_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_rcr_idx, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_RCR_IDX, L_LBMC_UMQ_RESUB_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_ip, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_RESP_IP, L_LBMC_UMQ_RESUB_HDR_T_RESP_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_port, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_RESP_PORT, L_LBMC_UMQ_RESUB_HDR_T_RESP_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_appset_idx, tvb, offset + O_LBMC_UMQ_RESUB_HDR_T_APPSET_IDX, L_LBMC_UMQ_RESUB_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    return (L_LBMC_UMQ_RESUB_HDR_T);
}

static int dissect_nhdr_otid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_otid, tvb, offset, L_LBMC_OTID_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_otid);
    proto_tree_add_item(subtree, hf_lbmc_otid_next_hdr, tvb, offset + O_LBMC_OTID_HDR_T_NEXT_HDR, L_LBMC_OTID_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_otid_hdr_len, tvb, offset + O_LBMC_OTID_HDR_T_HDR_LEN, L_LBMC_OTID_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_OTID_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_otid_flags, tvb, offset + O_LBMC_OTID_HDR_T_FLAGS, L_LBMC_OTID_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_otid_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_otid_flags_ignore, tvb, offset + O_LBMC_OTID_HDR_T_FLAGS, L_LBMC_OTID_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_otid_otid, tvb, offset + O_LBMC_OTID_HDR_T_OTID, L_LBMC_OTID_HDR_T_OTID, ENC_NA);
    return (L_LBMC_OTID_HDR_T);
}

static void dissect_ctxinst(tvbuff_t * tvb, int offset, proto_tree * tree, lbmc_ctxinst_info_t * info)
{
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    proto_tree_add_item(tree, hf_lbmc_ctxinst_next_hdr, tvb, offset + O_LBMC_CTXINST_HDR_T_NEXT_HDR, L_LBMC_CTXINST_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_lbmc_ctxinst_hdr_len, tvb, offset + O_LBMC_CTXINST_HDR_T_HDR_LEN, L_LBMC_CTXINST_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CTXINST_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(tree, hf_lbmc_ctxinst_flags, tvb, offset + O_LBMC_CTXINST_HDR_T_FLAGS, L_LBMC_CTXINST_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ctxinst_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinst_flags_ignore, tvb, offset + O_LBMC_CTXINST_HDR_T_FLAGS, L_LBMC_CTXINST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_lbmc_ctxinst_ctxinst, tvb, offset + O_LBMC_CTXINST_HDR_T_CTXINST, L_LBMC_CTXINST_HDR_T_CTXINST, ENC_NA);
    if (info != NULL)
    {
        info->set = TRUE;
        tvb_memcpy(tvb, (void *)&(info->ctxinst), offset + O_LBMC_CTXINST_HDR_T_CTXINST, L_LBMC_CTXINST_HDR_T_CTXINST);
    }
}

static int dissect_nhdr_ctxinstd(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmc_ctxinst_info_t * info)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ctxinstd, tvb, offset, L_LBMC_CTXINST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ctxinstd);
    dissect_ctxinst(tvb, offset, subtree, info);
    return (L_LBMC_CTXINST_HDR_T);
}

static int dissect_nhdr_ctxinstr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmc_ctxinst_info_t * info)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ctxinstr, tvb, offset, L_LBMC_CTXINST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ctxinstr);
    dissect_ctxinst(tvb, offset, subtree, info);
    return (L_LBMC_CTXINST_HDR_T);
}

static int dissect_nhdr_ctxinst(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmc_ctxinst_info_t * info)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ctxinst, tvb, offset, L_LBMC_CTXINST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ctxinst);
    dissect_ctxinst(tvb, offset, subtree, info);
    return (L_LBMC_CTXINST_HDR_T);
}

static int dissect_nhdr_srcidx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_srcidx, tvb, offset, L_LBMC_SRCIDX_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_srcidx);
    proto_tree_add_item(subtree, hf_lbmc_srcidx_next_hdr, tvb, offset + O_LBMC_SRCIDX_HDR_T_NEXT_HDR, L_LBMC_SRCIDX_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_srcidx_hdr_len, tvb, offset + O_LBMC_SRCIDX_HDR_T_HDR_LEN, L_LBMC_SRCIDX_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_SRCIDX_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_srcidx_flags, tvb, offset + O_LBMC_SRCIDX_HDR_T_FLAGS, L_LBMC_SRCIDX_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_srcidx_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_srcidx_flags_ignore, tvb, offset + O_LBMC_SRCIDX_HDR_T_FLAGS, L_LBMC_SRCIDX_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_srcidx_srcidx, tvb, offset + O_LBMC_SRCIDX_HDR_T_SRCIDX, L_LBMC_SRCIDX_HDR_T_SRCIDX, ENC_BIG_ENDIAN);
    return (L_LBMC_SRCIDX_HDR_T);
}

static int dissect_nhdr_umq_ulb_msg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ulb_msg, tvb, offset, L_LBMC_UMQ_ULB_MSG_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ulb_msg);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_msg_next_hdr, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_NEXT_HDR, L_LBMC_UMQ_ULB_MSG_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_msg_hdr_len, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_HDR_LEN, L_LBMC_UMQ_ULB_MSG_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_ulb_msg_flags, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS, L_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_ulb_msg);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_ulb_msg_flags_ignore, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS, L_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_ulb_msg_flags_a_flag, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS, L_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_ulb_msg_flags_r_flag, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS, L_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_msg_queue_id, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_QUEUE_ID, L_LBMC_UMQ_ULB_MSG_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_msg_ulb_src_id, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_ULB_SRC_ID, L_LBMC_UMQ_ULB_MSG_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_msg_assign_id, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_ASSIGN_ID, L_LBMC_UMQ_ULB_MSG_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_msg_appset_idx, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_APPSET_IDX, L_LBMC_UMQ_ULB_MSG_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_msg_num_ras, tvb, offset + O_LBMC_UMQ_ULB_MSG_HDR_T_NUM_RAS, L_LBMC_UMQ_ULB_MSG_HDR_T_NUM_RAS, ENC_BIG_ENDIAN);
    return (L_LBMC_UMQ_ULB_MSG_HDR_T);
}

static int dissect_nhdr_ssf_init(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ssf_init, tvb, offset, L_LBMC_CNTL_SSF_INIT_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ssf_init);
    proto_tree_add_item(subtree, hf_lbmc_ssf_init_next_hdr, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_NEXT_HDR, L_LBMC_CNTL_SSF_INIT_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_init_hdr_len, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_HDR_LEN, L_LBMC_CNTL_SSF_INIT_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ssf_init_flags, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS, L_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ssf_init);
    proto_tree_add_item(flags_tree, hf_lbmc_ssf_init_flags_ignore, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS, L_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ssf_init_flags_default_exclusions, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS, L_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ssf_init_flags_default_inclusions, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS, L_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_init_transport, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_TRANSPORT, L_LBMC_CNTL_SSF_INIT_HDR_T_TRANSPORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_init_transport_idx, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_SSF_INIT_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_init_client_idx, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_CLIENT_IDX, L_LBMC_CNTL_SSF_INIT_HDR_T_CLIENT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_init_ssf_port, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_SSF_PORT, L_LBMC_CNTL_SSF_INIT_HDR_T_SSF_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_init_res, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_RES, L_LBMC_CNTL_SSF_INIT_HDR_T_RES, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_init_ssf_ip, tvb, offset + O_LBMC_CNTL_SSF_INIT_HDR_T_SSF_IP, L_LBMC_CNTL_SSF_INIT_HDR_T_SSF_IP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_SSF_INIT_HDR_T);
}

static int dissect_nhdr_ssf_creq(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ssf_creq, tvb, offset, L_LBMC_CNTL_SSF_CREQ_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ssf_creq);
    proto_tree_add_item(subtree, hf_lbmc_ssf_creq_next_hdr, tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_NEXT_HDR, L_LBMC_CNTL_SSF_CREQ_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_creq_hdr_len, tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_HDR_LEN, L_LBMC_CNTL_SSF_CREQ_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ssf_creq_flags, tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_FLAGS, L_LBMC_CNTL_SSF_CREQ_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ssf_creq);
    proto_tree_add_item(flags_tree, hf_lbmc_ssf_creq_flags_ignore, tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_FLAGS, L_LBMC_CNTL_SSF_CREQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_creq_mode, tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_MODE, L_LBMC_CNTL_SSF_CREQ_HDR_T_MODE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_creq_transport_idx, tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_SSF_CREQ_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_creq_topic_idx, tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_TOPIC_IDX, L_LBMC_CNTL_SSF_CREQ_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ssf_creq_client_idx, tvb, offset + O_LBMC_CNTL_SSF_CREQ_HDR_T_CLIENT_IDX, L_LBMC_CNTL_SSF_CREQ_HDR_T_CLIENT_IDX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_SSF_CREQ_HDR_T);
}

static int dissect_nhdr_ume_preg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    proto_item * marker_item = NULL;
    proto_tree * marker_tree = NULL;
    guint8 flags = 0;
    guint8 marker = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_preg, tvb, offset, L_LBMC_CNTL_UME_PREG_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_preg);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_next_hdr, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_PREG_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_hdr_len, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_PREG_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_preg_flags, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_preg_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_preg_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_preg_flags_f_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_preg_flags_p_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_preg_flags_w_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_preg_flags_d_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    marker = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_MARKER);
    marker_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_preg_marker, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_MARKER, L_LBMC_CNTL_UME_PREG_HDR_T_MARKER, "Marker: 0x%02x", marker);
    marker_tree = proto_item_add_subtree(marker_item, ett_lbmc_ume_preg_marker);
    proto_tree_add_item(marker_tree, hf_lbmc_ume_preg_marker_s_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_MARKER, L_LBMC_CNTL_UME_PREG_HDR_T_MARKER, ENC_BIG_ENDIAN);
    proto_tree_add_item(marker_tree, hf_lbmc_ume_preg_marker_marker, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_MARKER, L_LBMC_CNTL_UME_PREG_HDR_T_MARKER, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_reg_id, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_REG_ID, L_LBMC_CNTL_UME_PREG_HDR_T_REG_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_transport_idx, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_UME_PREG_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_topic_idx, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_TOPIC_IDX, L_LBMC_CNTL_UME_PREG_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_src_reg_id, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_SRC_REG_ID, L_LBMC_CNTL_UME_PREG_HDR_T_SRC_REG_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_port, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_RESP_PORT, L_LBMC_CNTL_UME_PREG_HDR_T_RESP_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_res2, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_RES2, L_LBMC_CNTL_UME_PREG_HDR_T_RES2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_ip, tvb, offset + O_LBMC_CNTL_UME_PREG_HDR_T_RESP_IP, L_LBMC_CNTL_UME_PREG_HDR_T_RESP_IP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_PREG_HDR_T);
}

static int dissect_nhdr_ume_preg_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * code_item = NULL;
    proto_tree * code_tree = NULL;
    proto_item * marker_item = NULL;
    proto_tree * marker_tree = NULL;
    guint8 code = 0;
    guint8 marker = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_preg_resp, tvb, offset, L_LBMC_CNTL_UME_PREG_RESP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_preg_resp);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_next_hdr, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_hdr_len, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    code = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE);
    code_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_preg_resp_code, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, "Code: 0x%02x", code);
    code_tree = proto_item_add_subtree(code_item, ett_lbmc_ume_preg_resp_code);
    proto_tree_add_item(code_tree, hf_lbmc_ume_preg_resp_code_ignore, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, ENC_BIG_ENDIAN);
    proto_tree_add_item(code_tree, hf_lbmc_ume_preg_resp_code_o_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, ENC_BIG_ENDIAN);
    proto_tree_add_item(code_tree, hf_lbmc_ume_preg_resp_code_e_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, ENC_BIG_ENDIAN);
    if ((code & LBMC_UME_PREG_RESP_E_FLAG) == 0)
    {
        proto_tree_add_item(code_tree, hf_lbmc_ume_preg_resp_code_n_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, ENC_BIG_ENDIAN);
        proto_tree_add_item(code_tree, hf_lbmc_ume_preg_resp_code_w_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, ENC_BIG_ENDIAN);
        proto_tree_add_item(code_tree, hf_lbmc_ume_preg_resp_code_d_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, ENC_BIG_ENDIAN);
    }
    else
    {
        proto_tree_add_item(code_tree, hf_lbmc_ume_preg_resp_code_code, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE, ENC_BIG_ENDIAN);
    }
    marker = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER);
    marker_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_preg_resp_marker, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER, "Marker: 0x%02x", marker);
    marker_tree = proto_item_add_subtree(marker_item, ett_lbmc_ume_preg_resp_marker);
    proto_tree_add_item(marker_tree, hf_lbmc_ume_preg_resp_marker_s_flag, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER, ENC_BIG_ENDIAN);
    proto_tree_add_item(marker_tree, hf_lbmc_ume_preg_resp_marker_marker, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_reg_id, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_REG_ID, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_REG_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_transport_idx, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_topic_idx, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_TOPIC_IDX, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_low_seqnum, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_LOW_SEQNUM, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_LOW_SEQNUM, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_preg_resp_high_seqnum, tvb, offset + O_LBMC_CNTL_UME_PREG_RESP_HDR_T_HIGH_SEQNUM, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_HIGH_SEQNUM, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_PREG_RESP_HDR_T);
}

static int dissect_nhdr_ume_ack(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_ack, tvb, offset, L_LBMC_CNTL_UME_ACK_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_ack);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_next_hdr, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_ACK_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_hdr_len, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_ACK_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_ack_flags, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_ack_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_ack_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_ack_flags_o_flag, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_ack_flags_f_flag, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_ack_flags_u_flag, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_ack_flags_e_flag, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_type, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_TYPE, L_LBMC_CNTL_UME_ACK_HDR_T_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_transport_idx, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_UME_ACK_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_id_2, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_ID_2, L_LBMC_CNTL_UME_ACK_HDR_T_ID_2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_rcv_reg_id, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_RCV_REG_ID, L_LBMC_CNTL_UME_ACK_HDR_T_RCV_REG_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_seqnum, tvb, offset + O_LBMC_CNTL_UME_ACK_HDR_T_SEQNUM, L_LBMC_CNTL_UME_ACK_HDR_T_SEQNUM, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_ACK_HDR_T);
}

static int dissect_nhdr_ume_rxreq(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_rxreq, tvb, offset, L_LBMC_CNTL_UME_RXREQ_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_rxreq);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_next_hdr, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_RXREQ_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_hdr_len, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_RXREQ_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_rxreq_flags, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS, L_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_rxreq_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_rxreq_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS, L_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_rxreq_flags_tsni_req, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS, L_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_request_idx, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_REQUEST_IDX, L_LBMC_CNTL_UME_RXREQ_HDR_T_REQUEST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_transport_idx, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_UME_RXREQ_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_id_2, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_ID_2, L_LBMC_CNTL_UME_RXREQ_HDR_T_ID_2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_seqnum, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_SEQNUM, L_LBMC_CNTL_UME_RXREQ_HDR_T_SEQNUM, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_rx_port, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_RX_PORT, L_LBMC_CNTL_UME_RXREQ_HDR_T_RX_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_res, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_RES, L_LBMC_CNTL_UME_RXREQ_HDR_T_RES, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_rxreq_rx_ip, tvb, offset + O_LBMC_CNTL_UME_RXREQ_HDR_T_RX_IP, L_LBMC_CNTL_UME_RXREQ_HDR_T_RX_IP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_RXREQ_HDR_T);
}

static int dissect_nhdr_ume_keepalive(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_keepalive, tvb, offset, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_keepalive);
    proto_tree_add_item(subtree, hf_lbmc_ume_keepalive_next_hdr, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_keepalive_hdr_len, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_keepalive_flags, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_keepalive_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_keepalive_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_keepalive_flags_r_flag, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_keepalive_flags_t_flag, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_keepalive_type, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TYPE, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_keepalive_transport_idx, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_keepalive_topic_idx, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TOPIC_IDX, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_keepalive_reg_id, tvb, offset + O_LBMC_CNTL_UME_KEEPALIVE_HDR_T_REG_ID, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_REG_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_KEEPALIVE_HDR_T);
}

static int dissect_nhdr_ume_storeid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * storeid_item = NULL;
    proto_tree * storeid_tree = NULL;
    guint16 store_id = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_storeid, tvb, offset, L_LBMC_CNTL_UME_STOREID_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_storeid);
    proto_tree_add_item(subtree, hf_lbmc_ume_storeid_next_hdr, tvb, offset + O_LBMC_CNTL_UME_STOREID_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_STOREID_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_storeid_hdr_len, tvb, offset + O_LBMC_CNTL_UME_STOREID_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_STOREID_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    store_id = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID);
    storeid_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_storeid_store_id, tvb, offset + O_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID, L_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID, "Store ID: 0x%04x", store_id);
    storeid_tree = proto_item_add_subtree(storeid_item, ett_lbmc_ume_storeid_store_id);
    proto_tree_add_item(storeid_tree, hf_lbmc_ume_storeid_store_id_ignore, tvb, offset + O_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID, L_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(storeid_tree, hf_lbmc_ume_storeid_store_id_store_id, tvb, offset + O_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID, L_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_STOREID_HDR_T);
}

static int dissect_nhdr_ume_ranged_ack(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_ranged_ack, tvb, offset, L_LBMC_CNTL_UME_RANGED_ACK_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_ranged_ack);
    proto_tree_add_item(subtree, hf_lbmc_ume_ranged_ack_next_hdr, tvb, offset + O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ranged_ack_hdr_len, tvb, offset + O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_ranged_ack_flags, tvb, offset + O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FLAGS, L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_ranged_ack_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_ranged_ack_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FLAGS, L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ranged_ack_first_seqnum, tvb, offset + O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FIRST_SEQNUM, L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FIRST_SEQNUM, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ranged_ack_last_seqnum, tvb, offset + O_LBMC_CNTL_UME_RANGED_ACK_HDR_T_LAST_SEQNUM, L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_LAST_SEQNUM, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_RANGED_ACK_HDR_T);
}

static int dissect_nhdr_ume_ack_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_ack_id, tvb, offset, L_LBMC_CNTL_UME_ACK_ID_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_ack_id);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_id_next_hdr, tvb, offset + O_LBMC_CNTL_UME_ACK_ID_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_ACK_ID_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_id_hdr_len, tvb, offset + O_LBMC_CNTL_UME_ACK_ID_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_ACK_ID_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_ACK_ID_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_ack_id_flags, tvb, offset + O_LBMC_CNTL_UME_ACK_ID_HDR_T_FLAGS, L_LBMC_CNTL_UME_ACK_ID_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_ack_id_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_ack_id_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_ACK_ID_HDR_T_FLAGS, L_LBMC_CNTL_UME_ACK_ID_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_ack_id_id, tvb, offset + O_LBMC_CNTL_UME_ACK_ID_HDR_T_ID, L_LBMC_CNTL_UME_ACK_ID_HDR_T_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_ACK_ID_HDR_T);
}

static int dissect_nhdr_ume_capability(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_capability, tvb, offset, L_LBMC_CNTL_UME_CAPABILITY_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_capability);
    proto_tree_add_item(subtree, hf_lbmc_ume_capability_next_hdr, tvb, offset + O_LBMC_CNTL_UME_CAPABILITY_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_capability_hdr_len, tvb, offset + O_LBMC_CNTL_UME_CAPABILITY_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_capability_flags, tvb, offset + O_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_capability_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_capability_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_capability_flags_qc_flag, tvb, offset + O_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_capability_flags_client_lifetime_flag, tvb, offset + O_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_CAPABILITY_HDR_T);
}

static int dissect_nhdr_ume_proxy_src(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_proxy_src, tvb, offset, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_proxy_src);
    proto_tree_add_item(subtree, hf_lbmc_ume_proxy_src_next_hdr, tvb, offset + O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_proxy_src_hdr_len, tvb, offset + O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_proxy_src_flags, tvb, offset + O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_proxy_src_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_proxy_src_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_proxy_src_flags_enable, tvb, offset + O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_proxy_src_flags_compatibility, tvb, offset + O_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_PROXY_SRC_HDR_T);
}

static int dissect_nhdr_ume_store_group(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_store_group, tvb, offset, L_LBMC_CNTL_UME_STORE_GROUP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_store_group);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_group_next_hdr, tvb, offset + O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_group_hdr_len, tvb, offset + O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_store_group_flags, tvb, offset + O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_FLAGS, L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_store_group_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_store_group_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_FLAGS, L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_group_grp_idx, tvb, offset + O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_GRP_IDX, L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_GRP_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_group_grp_sz, tvb, offset + O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_GRP_SZ, L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_GRP_SZ, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_group_res1, tvb, offset + O_LBMC_CNTL_UME_STORE_GROUP_HDR_T_RES1, L_LBMC_CNTL_UME_STORE_GROUP_HDR_T_RES1, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_STORE_GROUP_HDR_T);
}

static int dissect_nhdr_ume_store(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_store, tvb, offset, L_LBMC_CNTL_UME_STORE_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_store);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_next_hdr, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_STORE_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_hdr_len, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_STORE_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_store_flags, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_FLAGS, L_LBMC_CNTL_UME_STORE_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_store_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_store_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_FLAGS, L_LBMC_CNTL_UME_STORE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_grp_idx, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_GRP_IDX, L_LBMC_CNTL_UME_STORE_HDR_T_GRP_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_store_tcp_port, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_STORE_TCP_PORT, L_LBMC_CNTL_UME_STORE_HDR_T_STORE_TCP_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_store_idx, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_STORE_IDX, L_LBMC_CNTL_UME_STORE_HDR_T_STORE_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_store_ip_addr, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_STORE_IP_ADDR, L_LBMC_CNTL_UME_STORE_HDR_T_STORE_IP_ADDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_src_reg_id, tvb, offset + O_LBMC_CNTL_UME_STORE_HDR_T_SRC_REG_ID, L_LBMC_CNTL_UME_STORE_HDR_T_SRC_REG_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_STORE_HDR_T);
}

static int dissect_nhdr_ume_lj_info(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_lj_info, tvb, offset, L_LBMC_CNTL_UME_LJ_INFO_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_lj_info);
    proto_tree_add_item(subtree, hf_lbmc_ume_lj_info_next_hdr, tvb, offset + O_LBMC_CNTL_UME_LJ_INFO_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_LJ_INFO_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_lj_info_hdr_len, tvb, offset + O_LBMC_CNTL_UME_LJ_INFO_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_LJ_INFO_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_LJ_INFO_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_lj_info_flags, tvb, offset + O_LBMC_CNTL_UME_LJ_INFO_HDR_T_FLAGS, L_LBMC_CNTL_UME_LJ_INFO_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_lj_info_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_lj_info_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_LJ_INFO_HDR_T_FLAGS, L_LBMC_CNTL_UME_LJ_INFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_lj_info_low_seqnum, tvb, offset + O_LBMC_CNTL_UME_LJ_INFO_HDR_T_LOW_SEQNUM, L_LBMC_CNTL_UME_LJ_INFO_HDR_T_LOW_SEQNUM, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_lj_info_high_seqnum, tvb, offset + O_LBMC_CNTL_UME_LJ_INFO_HDR_T_HIGH_SEQNUM, L_LBMC_CNTL_UME_LJ_INFO_HDR_T_HIGH_SEQNUM, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_lj_info_qidx, tvb, offset + O_LBMC_CNTL_UME_LJ_INFO_HDR_T_QIDX, L_LBMC_CNTL_UME_LJ_INFO_HDR_T_QIDX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_LJ_INFO_HDR_T);
}

static int dissect_nhdr_tsni_rec(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * sqn_item = NULL;
    guint32 sqn = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_tsni_rec, tvb, offset, L_LBMC_CNTL_TSNI_REC_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_tsni_rec);
    proto_tree_add_item(subtree, hf_lbmc_tsni_rec_tidx, tvb, offset + O_LBMC_CNTL_TSNI_REC_HDR_T_TIDX, L_LBMC_CNTL_TSNI_REC_HDR_T_TIDX, ENC_BIG_ENDIAN);
    sqn_item = proto_tree_add_item(subtree, hf_lbmc_tsni_rec_sqn, tvb, offset + O_LBMC_CNTL_TSNI_REC_HDR_T_SQN, L_LBMC_CNTL_TSNI_REC_HDR_T_SQN, ENC_BIG_ENDIAN);
    sqn = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_TSNI_REC_HDR_T_SQN);
    expert_add_info_format(pinfo, sqn_item, &ei_lbmc_analysis_tsni, "TSNI Sqn 0x%08x", sqn);
    return (L_LBMC_CNTL_TSNI_REC_HDR_T);
}

static int dissect_nhdr_tsni(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    guint8 hdrlen_remaining;
    int rec_offset = 0;
    proto_item * num_recs_subtree_item = NULL;
    proto_tree * num_recs_subtree = NULL;
    int len_dissected = 0;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_TSNI_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_tsni, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_tsni);
    proto_tree_add_item(subtree, hf_lbmc_tsni_next_hdr, tvb, offset + O_LBMC_CNTL_TSNI_HDR_T_NEXT_HDR, L_LBMC_CNTL_TSNI_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tsni_hdr_len, tvb, offset + O_LBMC_CNTL_TSNI_HDR_T_HDR_LEN, L_LBMC_CNTL_TSNI_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    num_recs_subtree_item = proto_tree_add_item(subtree, hf_lbmc_tsni_num_recs, tvb, offset + O_LBMC_CNTL_TSNI_HDR_T_NUM_RECS, L_LBMC_CNTL_TSNI_HDR_T_NUM_RECS, ENC_NA);
    num_recs_subtree = proto_item_add_subtree(num_recs_subtree_item, ett_lbmc_tsni_num_recs);
    proto_tree_add_item(num_recs_subtree, hf_lbmc_tsni_num_recs_ignore, tvb, offset + O_LBMC_CNTL_TSNI_HDR_T_NUM_RECS, L_LBMC_CNTL_TSNI_HDR_T_NUM_RECS, ENC_BIG_ENDIAN);
    proto_tree_add_item(num_recs_subtree, hf_lbmc_tsni_num_recs_num_recs, tvb, offset + O_LBMC_CNTL_TSNI_HDR_T_NUM_RECS, L_LBMC_CNTL_TSNI_HDR_T_NUM_RECS, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_TSNI_HDR_T;
    hdrlen_remaining = hdrlen - L_LBMC_CNTL_TSNI_HDR_T;
    rec_offset = L_LBMC_CNTL_TSNI_HDR_T;
    while (hdrlen_remaining >= L_LBMC_CNTL_TSNI_REC_HDR_T)
    {
        int reclen;

        reclen = dissect_nhdr_tsni_rec(tvb, offset + rec_offset, pinfo, subtree);
        hdrlen_remaining -= reclen;
        rec_offset += reclen;
        len_dissected += reclen;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_reg_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_reg_ctx, tvb, offset, L_LBMC_CNTL_UMQ_REG_CTX_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_reg_ctx);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ctx_port, tvb, offset + O_LBMC_CNTL_UMQ_REG_CTX_HDR_T_PORT, L_LBMC_CNTL_UMQ_REG_CTX_HDR_T_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ctx_reserved, tvb, offset + O_LBMC_CNTL_UMQ_REG_CTX_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_REG_CTX_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ctx_ip, tvb, offset + O_LBMC_CNTL_UMQ_REG_CTX_HDR_T_IP, L_LBMC_CNTL_UMQ_REG_CTX_HDR_T_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ctx_capabilities, tvb, offset + O_LBMC_CNTL_UMQ_REG_CTX_HDR_T_CAPABILITIES, L_LBMC_CNTL_UMQ_REG_CTX_HDR_T_CAPABILITIES, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_CTX_HDR_T);
}

static int dissect_nhdr_umq_reg_src(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_reg_src, tvb, offset, L_LBMC_CNTL_UMQ_REG_SRC_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_reg_src);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_src_transport_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_SRC_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_UMQ_REG_SRC_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_src_topic_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_SRC_HDR_T_TOPIC_IDX, L_LBMC_CNTL_UMQ_REG_SRC_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_SRC_HDR_T);
}

static int dissect_nhdr_umq_reg_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_reg_rcv, tvb, offset, L_LBMC_CNTL_UMQ_REG_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_reg_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_rcv_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_RCV_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_REG_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_rcv_rcv_type_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_RCV_HDR_T_RCV_TYPE_ID, L_LBMC_CNTL_UMQ_REG_RCV_HDR_T_RCV_TYPE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_rcv_last_topic_rcr_tsp, tvb, offset + O_LBMC_CNTL_UMQ_REG_RCV_HDR_T_LAST_TOPIC_RCR_TSP, L_LBMC_CNTL_UMQ_REG_RCV_HDR_T_LAST_TOPIC_RCR_TSP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_RCV_HDR_T);
}

static int dissect_nhdr_umq_rcv_dereg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_rcv_dereg, tvb, offset, L_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_rcv_dereg);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_rcv_dereg_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_rcv_dereg_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RCV_DEREG_HDR_T);
}

static int dissect_nhdr_umq_reg_ulb_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_reg_ulb_rcv, tvb, offset, L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_reg_ulb_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ulb_rcv_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ulb_rcv_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ulb_rcv_rcv_type_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_RCV_TYPE_ID, L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_RCV_TYPE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ulb_rcv_port, tvb, offset + O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_PORT, L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ulb_rcv_reserved, tvb, offset + O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ulb_rcv_ip, tvb, offset + O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_IP, L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_ulb_rcv_capabilities, tvb, offset + O_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_CAPABILITIES, L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T_CAPABILITIES, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_ULB_RCV_HDR_T);
}

static int dissect_nhdr_umq_ulb_rcv_dereg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_ulb_rcv_dereg, tvb, offset, L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_ulb_rcv_dereg);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_ulb_rcv_dereg_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_ulb_rcv_dereg_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_HDR_T);
}

static int dissect_nhdr_umq_reg_observer_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_reg_observer_rcv, tvb, offset, L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_reg_observer_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_observer_rcv_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_observer_rcv_rcv_type_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_RCV_TYPE_ID, L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_RCV_TYPE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_observer_rcv_last_topic_rcr_tsp, tvb, offset + O_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_LAST_TOPIC_RCR_TSP, L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T_LAST_TOPIC_RCR_TSP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_OBSERVER_RCV_HDR_T);
}

static int dissect_nhdr_umq_observer_rcv_dereg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_observer_rcv_dereg, tvb, offset, L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_observer_rcv_dereg);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_observer_rcv_dereg_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_observer_rcv_dereg_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_HDR_T);
}

static int dissect_nhdr_umq_reg(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    guint8 reg_type = 0;
    int len_dissected = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags;
    int len = 0;
    proto_item * reg_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_REG_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_REG_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_reg_flags, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_reg_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_flags_r_flag, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_flags_t_flag, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_flags_i_flag, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_flags_msg_sel_flag, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    reg_type_item = proto_tree_add_item(subtree, hf_lbmc_umq_reg_reg_type, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_REG_TYPE, L_LBMC_CNTL_UMQ_REG_HDR_T_REG_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_REG_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_cmd_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_CMD_ID, L_LBMC_CNTL_UMQ_REG_HDR_T_CMD_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_inst_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_INST_IDX, L_LBMC_CNTL_UMQ_REG_HDR_T_INST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_regid, tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_REGID, L_LBMC_CNTL_UMQ_REG_HDR_T_REGID, ENC_BIG_ENDIAN);

    len_dissected = L_LBMC_CNTL_UMQ_REG_HDR_T;
    reg_type = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_REG_HDR_T_REG_TYPE);
    switch (reg_type)
    {
        case LBMC_UMQ_REG_CTX_TYPE:
            len = dissect_nhdr_umq_reg_ctx(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_SRC_TYPE:
            len = dissect_nhdr_umq_reg_src(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RCV_TYPE:
            len = dissect_nhdr_umq_reg_rcv(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RCV_DEREG_TYPE:
            len = dissect_nhdr_umq_rcv_dereg(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_ULB_RCV_TYPE:
            len = dissect_nhdr_umq_reg_ulb_rcv(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_ULB_RCV_DEREG_TYPE:
            len = dissect_nhdr_umq_ulb_rcv_dereg(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_OBSERVER_RCV_TYPE:
            len = dissect_nhdr_umq_reg_observer_rcv(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_OBSERVER_RCV_DEREG_TYPE:
            len = dissect_nhdr_umq_observer_rcv_dereg(tvb, offset + len_dissected, pinfo, subtree);
            break;
        default:
            expert_add_info_format(pinfo, reg_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ REG type 0x%02x", reg_type);
            len = 0;
            break;
    }
    len_dissected += len;
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_reg_resp_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_reg_ctx, tvb, offset, L_LBMC_CNTL_UMQ_REG_RESP_CTX_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_reg_ctx);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ctx_capabilities, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_CTX_HDR_T_CAPABILITIES, L_LBMC_CNTL_UMQ_REG_RESP_CTX_HDR_T_CAPABILITIES, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_RESP_CTX_HDR_T);
}

static int dissect_nhdr_umq_reg_resp_ctx_ex(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_reg_ctx_ex, tvb, offset, L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_reg_ctx_ex);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ctx_ex_capabilities, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_CAPABILITIES, L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_CAPABILITIES, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ctx_ex_reserved, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_reg_resp_reg_ctx_ex_flags, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_reg_resp_reg_ctx_ex_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_resp_reg_ctx_ex_flags_firstmsg, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ctx_ex_stamp, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_STAMP, L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_STAMP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T);
}

static int dissect_nhdr_umq_reg_resp_err(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_err, tvb, offset, L_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_err);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_err_reserved, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_err_code, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T_CODE, L_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T_CODE, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_RESP_ERR_HDR_T);
}

static int dissect_nhdr_umq_reg_resp_src(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_reg_src, tvb, offset, L_LBMC_CNTL_UMQ_REG_RESP_SRC_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_reg_src);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_src_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_SRC_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_REG_RESP_SRC_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_RESP_SRC_HDR_T);
}

static int dissect_nhdr_umq_reg_resp_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_reg_rcv, tvb, offset, L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_reg_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_rcv_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_rcv_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_rcv_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_rcv_reserved, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_RESP_RCV_HDR_T);
}

static int dissect_nhdr_umq_rcv_dereg_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_rcv_dereg, tvb, offset, L_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_rcv_dereg);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_rcv_dereg_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_rcv_dereg_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RCV_DEREG_RESP_HDR_T);
}

static int dissect_nhdr_umq_reg_resp_ulb_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_reg_ulb_rcv, tvb, offset, L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_reg_ulb_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ulb_rcv_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ulb_rcv_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ulb_rcv_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ulb_rcv_reserved, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_ulb_rcv_capabilities, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_CAPABILITIES, L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T_CAPABILITIES, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_RESP_ULB_RCV_HDR_T);
}

static int dissect_nhdr_umq_ulb_rcv_dereg_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_ulb_rcv_dereg, tvb, offset, L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_ulb_rcv_dereg);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_ulb_rcv_dereg_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_ulb_rcv_dereg_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_ULB_RCV_DEREG_RESP_HDR_T);
}

static int dissect_nhdr_umq_reg_resp_observer_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_reg_observer_rcv, tvb, offset, L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_reg_observer_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_observer_rcv_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_observer_rcv_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_observer_rcv_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_reg_observer_rcv_reserved, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_REG_RESP_OBSERVER_RCV_HDR_T);
}

static int dissect_nhdr_umq_observer_rcv_dereg_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp_observer_rcv_dereg, tvb, offset, L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp_observer_rcv_dereg);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_observer_rcv_dereg_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_observer_rcv_dereg_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_OBSERVER_RCV_DEREG_RESP_HDR_T);
}

static int dissect_nhdr_umq_reg_resp(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    guint8 resp_type = 0;
    int len_dissected = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags;
    int len = 0;
    proto_item * resp_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_HDR_LEN);
    resp_type = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESP_TYPE);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_reg_resp, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_reg_resp);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_reg_resp_flags, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_reg_resp_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_resp_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_resp_flags_r_flag, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    switch (resp_type)
    {
        case LBMC_UMQ_REG_RESP_CTX_TYPE:
            break;
        case LBMC_UMQ_REG_RESP_CTX_EX_TYPE:
            break;
        case LBMC_UMQ_REG_RESP_ERR_TYPE:
            proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_resp_flags_l_flag, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            break;
        case LBMC_UMQ_REG_RESP_SRC_TYPE:
            proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_resp_flags_src_s_flag, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            proto_tree_add_item(flags_tree, hf_lbmc_umq_reg_resp_flags_src_d_flag, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            break;
        case LBMC_UMQ_REG_RESP_RCV_TYPE:
            break;
        case LBMC_UMQ_REG_RESP_OBSERVER_RCV_TYPE:
            break;
        case LBMC_UMQ_REG_RESP_RCV_DEREG_TYPE:
            break;
        case LBMC_UMQ_REG_RESP_OBSERVER_RCV_DEREG_TYPE:
            break;
        case LBMC_UMQ_REG_RESP_ULB_RCV_TYPE:
            break;
        case LBMC_UMQ_REG_RESP_ULB_RCV_DEREG_TYPE:
            break;
        default:
            break;
    }
    resp_type_item = proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_resp_type, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESP_TYPE, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESP_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_cmd_id, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_CMD_ID, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_CMD_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_inst_idx, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_INST_IDX, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_INST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_reg_resp_regid, tvb, offset + O_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESPID, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_REG_RESPID, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_REG_RESP_HDR_T;
    switch (resp_type)
    {
        case LBMC_UMQ_REG_RESP_CTX_TYPE:
            len = dissect_nhdr_umq_reg_resp_ctx(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_CTX_EX_TYPE:
            len = dissect_nhdr_umq_reg_resp_ctx_ex(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_ERR_TYPE:
            len = dissect_nhdr_umq_reg_resp_err(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_SRC_TYPE:
            len = dissect_nhdr_umq_reg_resp_src(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_RCV_TYPE:
            len = dissect_nhdr_umq_reg_resp_rcv(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_RCV_DEREG_TYPE:
            len = dissect_nhdr_umq_rcv_dereg_resp(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_ULB_RCV_TYPE:
            len = dissect_nhdr_umq_reg_resp_ulb_rcv(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_ULB_RCV_DEREG_TYPE:
            len = dissect_nhdr_umq_ulb_rcv_dereg_resp(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_OBSERVER_RCV_TYPE:
            len = dissect_nhdr_umq_reg_resp_observer_rcv(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_REG_RESP_OBSERVER_RCV_DEREG_TYPE:
            len = dissect_nhdr_umq_observer_rcv_dereg_resp(tvb, offset + len_dissected, pinfo, subtree);
            break;
        default:
            expert_add_info_format(pinfo, resp_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ REG RESP type 0x%02x", resp_type);
            len = 0;
            break;
    }
    len_dissected += len;
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_ack_msgid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ack_msgid, tvb, offset, L_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ack_msgid);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_msgid_regid, tvb, offset + O_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T_REGID, L_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_msgid_stamp, tvb, offset + O_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T_STAMP, L_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T_STAMP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_ACK_MSGID_HDR_T);
}

static int dissect_nhdr_umq_ack_stable(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ack_stable, tvb, offset, L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ack_stable);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_stable_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_stable_inst_idx, tvb, offset + O_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_INST_IDX, L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_INST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_stable_reserved, tvb, offset + O_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_ACK_STABLE_HDR_T);
}

static int dissect_nhdr_umq_ack_cr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ack_cr, tvb, offset, L_LBMC_CNTL_UMQ_ACK_CR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ack_cr);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_cr_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_ACK_CR_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_ACK_CR_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_cr_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ACK_CR_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ACK_CR_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_cr_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_ACK_CR_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_ACK_CR_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_cr_reserved, tvb, offset + O_LBMC_CNTL_UMQ_ACK_CR_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_ACK_CR_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_ACK_CR_HDR_T);
}

static int dissect_nhdr_umq_ack_ulb_cr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ack_ulb_cr, tvb, offset, L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ack_ulb_cr);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_ulb_cr_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_ulb_cr_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_ulb_cr_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_ulb_cr_reserved, tvb, offset + O_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_ACK_ULB_CR_HDR_T);
}

static int dissect_nhdr_umq_ack(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    guint8 ack_type = 0;
    guint8 num_ids = 0;
    guint8 idx;
    int len_dissected = 0;
    proto_item * msgs_item = NULL;
    proto_tree * msgs_tree = NULL;
    guint8 msgs;
    int len;
    int packet_len = 0;
    proto_item * ack_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ack, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ack);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_ACK_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ack_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_ACK_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    msgs = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS);
    msgs_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_ack_msgs, tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, "Messages: 0x%02x", msgs);
    msgs_tree = proto_item_add_subtree(msgs_item, ett_lbmc_umq_ack_msgs);
    proto_tree_add_item(msgs_tree, hf_lbmc_umq_ack_msgs_ignore, tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(msgs_tree, hf_lbmc_umq_ack_msgs_t_flag, tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(msgs_tree, hf_lbmc_umq_ack_msgs_d_flag, tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(msgs_tree, hf_lbmc_umq_ack_msgs_numids, tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS, ENC_BIG_ENDIAN);
    ack_type_item = proto_tree_add_item(subtree, hf_lbmc_umq_ack_ack_type, tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_ACK_TYPE, L_LBMC_CNTL_UMQ_ACK_HDR_T_ACK_TYPE, ENC_BIG_ENDIAN);
    packet_len = tvb_reported_length_remaining(tvb, offset);
    len_dissected = L_LBMC_CNTL_UMQ_ACK_HDR_T;
    num_ids = msgs & LBMC_UMQ_ACK_NUMIDS_MASK;
    for (idx = 0; (idx < num_ids) && (len_dissected < packet_len); idx++)
    {
        len = dissect_nhdr_umq_ack_msgid(tvb, offset + len_dissected, pinfo, subtree);
        len_dissected += len;
    }
    ack_type = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_ACK_HDR_T_ACK_TYPE);
    switch (ack_type)
    {
        case LBMC_UMQ_ACK_STABLE_TYPE:
            len = dissect_nhdr_umq_ack_stable(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_ACK_CR_TYPE:
            len = dissect_nhdr_umq_ack_cr(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_ACK_ULB_CR_TYPE:
            len = dissect_nhdr_umq_ack_ulb_cr(tvb, offset + len_dissected, pinfo, subtree);
            break;
        default:
            expert_add_info_format(pinfo, ack_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ ACK type 0x%02x", ack_type);
            len = 0;
            break;
    }
    len_dissected += len;
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_rcr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint16 flags;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rcr, tvb, offset, L_LBMC_CNTL_UMQ_RCR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rcr);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_RCR_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_RCR_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_rcr_flags, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_rcr_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_rcr_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_rcr_flags_r_flag, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_rcr_flags_d_flag, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_rcr_flags_s_flag, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_rcr_flags_eoi_flag, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_rcr_flags_boi_flag, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_RCR_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RCR_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_msgid_regid, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_MSGID_REGID, L_LBMC_CNTL_UMQ_RCR_HDR_T_MSGID_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_msgid_stamp, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_MSGID_STAMP, L_LBMC_CNTL_UMQ_RCR_HDR_T_MSGID_STAMP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_topic_tsp, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_TOPIC_TSP, L_LBMC_CNTL_UMQ_RCR_HDR_T_TOPIC_TSP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_q_tsp, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_Q_TSP, L_LBMC_CNTL_UMQ_RCR_HDR_T_Q_TSP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RCR_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_RCR_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_num_ras, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_NUM_RAS, L_LBMC_CNTL_UMQ_RCR_HDR_T_NUM_RAS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rcr_queue_ver, tvb, offset + O_LBMC_CNTL_UMQ_RCR_HDR_T_QUEUE_VER, L_LBMC_CNTL_UMQ_RCR_HDR_T_QUEUE_VER, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RCR_HDR_T);
}

static int dissect_nhdr_umq_ka_src(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ka_src, tvb, offset, L_LBMC_CNTL_UMQ_KA_SRC_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ka_src);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_src_transport_idx, tvb, offset + O_LBMC_CNTL_UMQ_KA_SRC_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_UMQ_KA_SRC_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_src_topic_idx, tvb, offset + O_LBMC_CNTL_UMQ_KA_SRC_HDR_T_TOPIC_IDX, L_LBMC_CNTL_UMQ_KA_SRC_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_KA_SRC_HDR_T);
}

static int dissect_nhdr_umq_ka_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ka_rcv, tvb, offset, L_LBMC_CNTL_UMQ_KA_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ka_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_rcv_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_KA_RCV_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_KA_RCV_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_rcv_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_KA_RCV_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_KA_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_KA_RCV_HDR_T);
}

static int dissect_nhdr_umq_ka_ulb_rcv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ka_ulb_rcv, tvb, offset, L_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ka_ulb_rcv);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_ulb_rcv_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_ulb_rcv_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_KA_ULB_RCV_HDR_T);
}

static int dissect_nhdr_umq_ka_ulb_rcv_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ka_ulb_rcv_resp, tvb, offset, L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ka_ulb_rcv_resp);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_ulb_rcv_resp_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_ulb_rcv_resp_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_ulb_rcv_resp_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ka_ulb_rcv_resp_reserved, tvb, offset + O_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_KA_ULB_RCV_RESP_HDR_T);
}

static int dissect_nhdr_umq_ka(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    guint8 flags;
    guint8 type;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    int len_dissected = 0;
    int len;
    proto_item * ka_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_cntl_umq_ka, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ka);
    proto_tree_add_item(subtree, hf_lbmc_cntl_umq_ka_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_KA_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_cntl_umq_ka_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_KA_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_cntl_umq_ka_flags, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_ka_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_cntl_umq_ka_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_cntl_umq_ka_flags_r_flag, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    ka_type_item = proto_tree_add_item(subtree, hf_lbmc_cntl_umq_ka_ka_type, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_KA_TYPE, L_LBMC_CNTL_UMQ_KA_HDR_T_KA_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_cntl_umq_ka_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_KA_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_cntl_umq_ka_regid, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_REGID, L_LBMC_CNTL_UMQ_KA_HDR_T_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_cntl_umq_ka_inst_idx, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_INST_IDX, L_LBMC_CNTL_UMQ_KA_HDR_T_INST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_cntl_umq_ka_reserved, tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_KA_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_KA_HDR_T;
    type = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_KA_HDR_T_KA_TYPE);
    switch (type)
    {
        case LBMC_UMQ_KA_SRC_TYPE:
        case LBMC_UMQ_KA_SRC_RESP_TYPE:
            len = dissect_nhdr_umq_ka_src(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_KA_RCV_TYPE:
        case LBMC_UMQ_KA_RCV_RESP_TYPE:
            len = dissect_nhdr_umq_ka_rcv(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_KA_ULB_RCV_TYPE:
            len = dissect_nhdr_umq_ka_ulb_rcv(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_KA_ULB_RCV_RESP_TYPE:
            len = dissect_nhdr_umq_ka_ulb_rcv_resp(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_KA_CTX_TYPE:
        case LBMC_UMQ_KA_CTX_RESP_TYPE:
            len = 0;
            break;
        default:
            expert_add_info_format(pinfo, ka_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ KA type 0x%02x", type);
            len = 0;
            break;
    }
    len_dissected += len;
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_rxreq_regid_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_regid_resp, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_REGID_RESP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_regid_resp);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_regid_resp_regid, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_REGID_RESP_HDR_T_REGID, L_LBMC_CNTL_UMQ_RXREQ_REGID_RESP_HDR_T_REGID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_REGID_RESP_HDR_T);
}

static int dissect_nhdr_umq_rxreq_addr_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_addr_resp, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_addr_resp);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_addr_resp_ip, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_IP, L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_addr_resp_port, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_PORT, L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_addr_resp_reserved, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_ADDR_RESP_HDR_T);
}

static int dissect_nhdr_umq_rxreq_mr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_mr, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_mr);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_mr_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_mr_msgid_regid, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_MSGID_REGID, L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_MSGID_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_mr_msgid_stamp, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_MSGID_STAMP, L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T_MSGID_STAMP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_MR_HDR_T);
}

static int dissect_nhdr_umq_rxreq_ulb_mr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_ulb_mr, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_ulb_mr);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_reserved, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_msgid_regid, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_MSGID_REGID, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_MSGID_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_msgid_stamp, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_MSGID_STAMP, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T_MSGID_STAMP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_HDR_T);
}

static int dissect_nhdr_umq_rxreq_ulb_mr_abort(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_ulb_mr_abort, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_ulb_mr_abort);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_abort_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_abort_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_abort_msgid_regid, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_MSGID_REGID, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_MSGID_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_mr_abort_msgid_stamp, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_MSGID_STAMP, L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T_MSGID_STAMP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_ULB_MR_ABORT_HDR_T);
}

static int dissect_nhdr_umq_rxreq_qrcrr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_qrcrr, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_QRCRR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_qrcrr);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_qrcrr_tsp, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_QRCRR_HDR_T_TSP, L_LBMC_CNTL_UMQ_RXREQ_QRCRR_HDR_T_TSP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_QRCRR_HDR_T);
}

static int dissect_nhdr_umq_rxreq_trcrr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_trcrr, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_trcrr);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_trcrr_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_trcrr_tsp, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T_TSP, L_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T_TSP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_TRCRR_HDR_T);
}

static int dissect_nhdr_umq_rxreq_ulb_trcrr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_ulb_trcrr, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_ulb_trcrr);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_trcrr_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_trcrr_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_trcrr_tsp, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_TSP, L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T_TSP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_HDR_T);
}

static int dissect_nhdr_umq_rxreq_ulb_trcrr_abort(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq_ulb_trcrr_abort, tvb, offset, L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq_ulb_trcrr_abort);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_trcrr_abort_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_trcrr_abort_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_ulb_trcrr_abort_tsp, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_TSP, L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T_TSP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RXREQ_ULB_TRCRR_ABORT_HDR_T);
}

static int dissect_nhdr_umq_rxreq(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    guint8 flags;
    guint8 type;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    int len_dissected = 0;
    int len = 0;
    proto_item * rxreq_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_rxreq, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_rxreq);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_RXREQ_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_RXREQ_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_rxreq_flags, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_rxreq_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_rxreq_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_rxreq_flags_r_flag, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    rxreq_type_item = proto_tree_add_item(subtree, hf_lbmc_umq_rxreq_rxreq_type, tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_RXREQ_TYPE, L_LBMC_CNTL_UMQ_RXREQ_HDR_T_RXREQ_TYPE, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_RXREQ_HDR_T;
    if ((flags & LBMC_UMQ_RXREQ_R_FLAG) != 0)
    {
        len = dissect_nhdr_umq_rxreq_regid_resp(tvb, offset + len_dissected, pinfo, subtree);
    }
    else
    {
        len = dissect_nhdr_umq_rxreq_addr_resp(tvb, offset + len_dissected, pinfo, subtree);
    }
    len_dissected += len;
    type = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_RXREQ_HDR_T_RXREQ_TYPE);
    switch (type)
    {
        case LBMC_UMQ_RXREQ_MR_TYPE:
            len = dissect_nhdr_umq_rxreq_mr(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_RXREQ_ULB_MR_TYPE:
            len = dissect_nhdr_umq_rxreq_ulb_mr(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_RXREQ_ULB_MR_ABORT_TYPE:
            len = dissect_nhdr_umq_rxreq_ulb_mr_abort(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_RXREQ_QRCRR_TYPE:
            len = dissect_nhdr_umq_rxreq_qrcrr(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_RXREQ_TRCRR_TYPE:
            len = dissect_nhdr_umq_rxreq_trcrr(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_RXREQ_ULB_TRCRR_TYPE:
            len = dissect_nhdr_umq_rxreq_ulb_trcrr(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_RXREQ_ULB_TRCRR_ABORT_TYPE:
            len = dissect_nhdr_umq_rxreq_ulb_trcrr_abort(tvb, offset + len_dissected, pinfo, subtree);
            break;
        default:
            expert_add_info_format(pinfo, rxreq_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ RXREQ type 0x%02x", type);
            len = 0;
            break;
    }
    len_dissected += len;
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_qmgmt(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    int len_dissected = 0;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_QMGMT_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_qmgmt, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_qmgmt);
    proto_tree_add_item(subtree, hf_lbmc_umq_qmgmt_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_QMGMT_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_QMGMT_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_qmgmt_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_QMGMT_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_QMGMT_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    len_dissected = lbmr_dissect_umq_qmgmt(tvb, (offset + L_LBMC_CNTL_UMQ_QMGMT_HDR_T) - 2, pinfo, subtree);
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_resub_req(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint16 flags;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_resub_req, tvb, offset, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_resub_req);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_req_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_req_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_resub_req_flags, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_resub_req_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_resub_req_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_req_msgid_regid, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_MSGID_REGID, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_MSGID_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_req_msgid_stamp, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_MSGID_STAMP, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_MSGID_STAMP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_req_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_req_resp_ip, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RESP_IP, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RESP_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_req_resp_port, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RESP_PORT, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_RESP_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_req_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T);
}

static int dissect_nhdr_umq_resub_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 flags;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_resub_resp, tvb, offset, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_resub_resp);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_resub_resp_flags, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_resub_resp_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_resub_resp_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_code, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_CODE, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_CODE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_msgid_regid, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_MSGID_REGID, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_MSGID_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_msgid_stamp, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_MSGID_STAMP, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_MSGID_STAMP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_reserved, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_resub_resp_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T);
}

static int dissect_nhdr_topic_interest(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_topic_interest, tvb, offset, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_topic_interest);
    proto_tree_add_item(subtree, hf_lbmc_topic_interest_next_hdr, tvb, offset + O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_NEXT_HDR, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_interest_hdr_len, tvb, offset + O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_HDR_LEN, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_topic_interest_flags, tvb, offset + O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_topic_interest_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_interest_flags_ignore, tvb, offset + O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_interest_flags_cancel, tvb, offset + O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_interest_flags_refresh, tvb, offset + O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_interest_domain_id, tvb, offset + O_LBMC_CNTL_TOPIC_INTEREST_HDR_T_DOMAIN_ID, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_TOPIC_INTEREST_HDR_T);
}

static int dissect_nhdr_pattern_interest(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_pattern_interest, tvb, offset, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_pattern_interest);
    proto_tree_add_item(subtree, hf_lbmc_pattern_interest_next_hdr, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_NEXT_HDR, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_interest_hdr_len, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_HDR_LEN, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_pattern_interest_flags, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_pattern_interest_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_pattern_interest_flags_ignore, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_pattern_interest_flags_cancel, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_pattern_interest_flags_refresh, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_interest_type, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_TYPE, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_interest_domain_id, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_DOMAIN_ID, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_interest_index, tvb, offset + O_LBMC_CNTL_PATTERN_INTEREST_HDR_T_INDEX, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_INDEX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_PATTERN_INTEREST_HDR_T);
}

static int dissect_nhdr_advertisement(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    proto_item * ad_flags_item = NULL;
    proto_tree * ad_flags_tree = NULL;
    guint8 flags = 0;
    guint32 ad_flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_advertisement, tvb, offset, L_LBMC_CNTL_ADVERTISEMENT_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_advertisement);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_next_hdr, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_NEXT_HDR, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_hdr_len, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_HDR_LEN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_advertisement_flags, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_advertisement_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_advertisement_flags_ignore, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_advertisement_flags_eos, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_advertisement_flags_pattern, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_advertisement_flags_change, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_advertisement_flags_ctxinst, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    ad_flags = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS);
    ad_flags_item = proto_tree_add_none_format(subtree, hf_lbmc_advertisement_ad_flags, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, "Ad Flags: 0x%08x", ad_flags);
    ad_flags_tree = proto_item_add_subtree(ad_flags_item, ett_lbmc_advertisement_ad_flags);
    proto_tree_add_item(ad_flags_tree, hf_lbmc_advertisement_ad_flags_lj, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(ad_flags_tree, hf_lbmc_advertisement_ad_flags_ume, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(ad_flags_tree, hf_lbmc_advertisement_ad_flags_acktosrc, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(ad_flags_tree, hf_lbmc_advertisement_ad_flags_queue, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(ad_flags_tree, hf_lbmc_advertisement_ad_flags_ulb, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_hop_count, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_HOP_COUNT, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_HOP_COUNT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_cost, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_COST, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_COST, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_transport_idx, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_topic_idx, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_TOPIC_IDX, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_low_seqno, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_LOW_SEQNO, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_LOW_SEQNO, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_high_seqno, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_HIGH_SEQNO, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_HIGH_SEQNO, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_domain_id, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_DOMAIN_ID, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_pat_idx, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_PAT_IDX, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_PAT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_advertisement_ctxinst, tvb, offset + O_LBMC_CNTL_ADVERTISEMENT_HDR_T_CTXINST, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_CTXINST, ENC_NA);
    return (L_LBMC_CNTL_ADVERTISEMENT_HDR_T);
}

static int dissect_nhdr_storename(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;
    int len_dissected = 0;
    int namelen = 0;
    proto_item * hdrlen_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_UME_STORENAME_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_storename, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_storename);
    proto_tree_add_item(subtree, hf_lbmc_ume_storename_next_hdr, tvb, offset + O_LBMC_UME_STORENAME_HDR_T_NEXT_HDR, L_LBMC_UME_STORENAME_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_ume_storename_hdr_len, tvb, offset + O_LBMC_UME_STORENAME_HDR_T_HDR_LEN, L_LBMC_UME_STORENAME_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_UME_STORENAME_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_storename_flags, tvb, offset + O_LBMC_UME_STORENAME_HDR_T_FLAGS, L_LBMC_UME_STORENAME_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_storename_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_storename_flags_ignore, tvb, offset + O_LBMC_UME_STORENAME_HDR_T_FLAGS, L_LBMC_UME_STORENAME_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_BASIC_HDR_T;
    namelen = (int) hdrlen - len_dissected;
    if (namelen > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_ume_storename_store, tvb, offset + O_LBMC_UME_STORENAME_HDR_T_FLAGS + L_LBMC_UME_STORENAME_HDR_T_FLAGS, namelen, ENC_ASCII | ENC_NA);
        len_dissected += namelen;
    }
    else
    {
        expert_add_info(pinfo, hdrlen_item, &ei_lbmc_analysis_length_incorrect);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_ulb_rcr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint16 flags;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_ulb_rcr, tvb, offset, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_ulb_rcr);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_ulb_rcr_flags, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_ulb_rcr_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_ulb_rcr_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_ulb_rcr_flags_r_flag, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_ulb_rcr_flags_d_flag, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_ulb_rcr_flags_eoi_flag, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_ulb_rcr_flags_boi_flag, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_ulb_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_ULB_SRC_ID, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_msgid_regid, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_MSGID_REGID, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_MSGID_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_msgid_stamp, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_MSGID_STAMP, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_MSGID_STAMP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_topic_tsp, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_TOPIC_TSP, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_TOPIC_TSP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_ulb_rcr_num_ras, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_NUM_RAS, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_NUM_RAS, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T);
}

static int dissect_nhdr_umq_lf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 flags;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_lf, tvb, offset, L_LBMC_CNTL_UMQ_LF_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_lf);
    proto_tree_add_item(subtree, hf_lbmc_umq_lf_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_LF_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_LF_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_lf_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_LF_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_LF_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_LF_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_lf_flags, tvb, offset + O_LBMC_CNTL_UMQ_LF_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_LF_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_lf_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_lf_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_LF_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_LF_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_lf_type, tvb, offset + O_LBMC_CNTL_UMQ_LF_HDR_T_TYPE, L_LBMC_CNTL_UMQ_LF_HDR_T_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_lf_num_srcs, tvb, offset + O_LBMC_CNTL_UMQ_LF_HDR_T_NUM_SRCS, L_LBMC_CNTL_UMQ_LF_HDR_T_NUM_SRCS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_lf_lf, tvb, offset + O_LBMC_CNTL_UMQ_LF_HDR_T_LF, L_LBMC_CNTL_UMQ_LF_HDR_T_LF, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_LF_HDR_T);
}

static int dissect_nhdr_ctxinfo(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;
    wmem_strbuf_t * flagbuf;
    const char * sep = "";
    int len_dissected = 0;
    proto_item * hdrlen_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_ctxinfo, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ctxinfo);
    proto_tree_add_item(subtree, hf_lbmc_ctxinfo_next_hdr, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_NEXT_HDR, L_LBMC_CNTL_CTXINFO_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_ctxinfo_hdr_len, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_HDR_LEN, L_LBMC_CNTL_CTXINFO_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS);
    flagbuf = wmem_strbuf_new_label(wmem_packet_scope());
    if ((flags & LBMC_CTXINFO_PROXY_FLAG) != 0)
    {
        wmem_strbuf_append(flagbuf, sep);
        wmem_strbuf_append(flagbuf, "Proxy");
        sep = ", ";
    }
    if ((flags & LBMC_CTXINFO_TNWGRCV_FLAG) != 0)
    {
        wmem_strbuf_append(flagbuf, sep);
        wmem_strbuf_append(flagbuf, "GW Rcv");
        sep = ", ";
    }
    if ((flags & LBMC_CTXINFO_TNWGSRC_FLAG) != 0)
    {
        wmem_strbuf_append(flagbuf, sep);
        wmem_strbuf_append(flagbuf, "GW Src");
        sep = ", ";
    }
    if ((flags & LBMC_CTXINFO_NAME_FLAG) != 0)
    {
        wmem_strbuf_append(flagbuf, sep);
        wmem_strbuf_append(flagbuf, "Name");
        sep = ", ";
    }
    if ((flags & LBMC_CTXINFO_CTXINST_FLAG) != 0)
    {
        wmem_strbuf_append(flagbuf, sep);
        wmem_strbuf_append(flagbuf, "CtxInst");
        sep = ", ";
    }
    if ((flags & LBMC_CTXINFO_ADDR_FLAG) != 0)
    {
        wmem_strbuf_append(flagbuf, sep);
        wmem_strbuf_append(flagbuf, "IP");
        sep = ", ";
    }
    if ((flags & LBMC_CTXINFO_QUERY_FLAG) != 0)
    {
        wmem_strbuf_append(flagbuf, sep);
        wmem_strbuf_append(flagbuf, "Query");
    }
    if (flags != LBMC_OPT_IGNORE)
    {
        flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ctxinfo_flags, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, "Flags: 0x%04x (%s)", flags, (char *)wmem_strbuf_get_str(flagbuf));
    }
    else
    {
        flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ctxinfo_flags, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    }
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ctxinfo_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinfo_flags_ignore, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinfo_flags_query, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinfo_flags_addr, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinfo_flags_ctxinst, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinfo_flags_name, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinfo_flags_tnwgsrc, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinfo_flags_tnwgrcv, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ctxinfo_flags_proxy, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ctxinfo_reserved, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_RESERVED, L_LBMC_CNTL_CTXINFO_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ctxinfo_hop_count, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_HOP_COUNT, L_LBMC_CNTL_CTXINFO_HDR_T_HOP_COUNT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ctxinfo_port, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_PORT, L_LBMC_CNTL_CTXINFO_HDR_T_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ctxinfo_addr, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_ADDR, L_LBMC_CNTL_CTXINFO_HDR_T_ADDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ctxinfo_domain_id, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_DOMAIN_ID, L_LBMC_CNTL_CTXINFO_HDR_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ctxinfo_ctxinst, tvb, offset + O_LBMC_CNTL_CTXINFO_HDR_T_CTXINST, L_LBMC_CNTL_CTXINFO_HDR_T_CTXINST, ENC_NA);
    len_dissected = L_LBMC_CNTL_CTXINFO_HDR_T;
    if ((flags & LBMC_CTXINFO_NAME_FLAG) != 0)
    {
        int namelen = (int) hdrlen - len_dissected;
        if (namelen > 0)
        {
            proto_tree_add_item(subtree, hf_lbmc_ctxinfo_name, tvb, offset + L_LBMC_CNTL_CTXINFO_HDR_T, hdrlen - L_LBMC_CNTL_CTXINFO_HDR_T, ENC_ASCII | ENC_NA);
            len_dissected += namelen;
        }
        else
        {
            expert_add_info(pinfo, hdrlen_item, &ei_lbmc_analysis_length_incorrect);
        }
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_ume_pser(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_pser, tvb, offset, L_LBMC_CNTL_UME_PSER_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_pser);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_next_hdr, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_PSER_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_hdr_len, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_PSER_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_pser_flags, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_pser_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_pser_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_pser_flags_source_ctxinst, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_pser_flags_store_ctxinst, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_pser_flags_reelect, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_source_ip, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_IP, L_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_store_ip, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_STORE_IP, L_LBMC_CNTL_UME_PSER_HDR_T_STORE_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_transport_idx, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_UME_PSER_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_topic_idx, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_TOPIC_IDX, L_LBMC_CNTL_UME_PSER_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_source_port, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_PORT, L_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_store_port, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_STORE_PORT, L_LBMC_CNTL_UME_PSER_HDR_T_STORE_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_source_ctxinst, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_CTXINST, L_LBMC_CNTL_UME_PSER_HDR_T_SOURCE_CTXINST, ENC_NA);
    proto_tree_add_item(subtree, hf_lbmc_ume_pser_store_ctxinst, tvb, offset + O_LBMC_CNTL_UME_PSER_HDR_T_STORE_CTXINST, L_LBMC_CNTL_UME_PSER_HDR_T_STORE_CTXINST, ENC_NA);
    return (L_LBMC_CNTL_UME_PSER_HDR_T);
}

static int dissect_nhdr_domain(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_domain, tvb, offset, L_LBMC_DOMAIN_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_domain);
    proto_tree_add_item(subtree, hf_lbmc_domain_next_hdr, tvb, offset + O_LBMC_DOMAIN_HDR_T_NEXT_HDR, L_LBMC_DOMAIN_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_domain_hdr_len, tvb, offset + O_LBMC_DOMAIN_HDR_T_HDR_LEN, L_LBMC_DOMAIN_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_DOMAIN_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_domain_flags, tvb, offset + O_LBMC_DOMAIN_HDR_T_FLAGS, L_LBMC_DOMAIN_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_domain_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_domain_flags_ignore, tvb, offset + O_LBMC_DOMAIN_HDR_T_FLAGS, L_LBMC_DOMAIN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_domain_flags_active, tvb, offset + O_LBMC_DOMAIN_HDR_T_FLAGS, L_LBMC_DOMAIN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_domain_domain, tvb, offset + O_LBMC_DOMAIN_HDR_T_DOMAIN, L_LBMC_DOMAIN_HDR_T_DOMAIN, ENC_BIG_ENDIAN);
    return (L_LBMC_DOMAIN_HDR_T);
}

static int dissect_nhdr_tnwg_capabilities(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;
    proto_item * cap1_item = NULL;
    proto_tree * cap1_tree = NULL;
    guint32 cap1 = 0;
    proto_item * cap3_item = NULL;
    proto_tree * cap3_tree = NULL;
    guint32 cap3 = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_tnwg_capabilities, tvb, offset, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_tnwg_capabilities);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_capabilities_next_hdr, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_NEXT_HDR, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_capabilities_hdr_len, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_HDR_LEN, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_tnwg_capabilities_flags, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_tnwg_capabilities_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_tnwg_capabilities_flags_ignore, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_tnwg_capabilities_flags_version, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    cap1 = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1);
    cap1_item = proto_tree_add_none_format(subtree, hf_lbmc_tnwg_capabilities_capabilities1, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1, "Capabilities1: 0x%08x", cap1);
    cap1_tree = proto_item_add_subtree(cap1_item, ett_lbmc_tnwg_capabilities_capabilities1);
    proto_tree_add_item(cap1_tree, hf_lbmc_tnwg_capabilities_capabilities1_ume, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap1_tree, hf_lbmc_tnwg_capabilities_capabilities1_umq, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_capabilities_capabilities2, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES2, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES2, ENC_BIG_ENDIAN);
    cap3 = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3);
    cap3_item = proto_tree_add_none_format(subtree, hf_lbmc_tnwg_capabilities_capabilities3, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3, "Capabilities3: 0x%08x", cap3);
    cap3_tree = proto_item_add_subtree(cap3_item, ett_lbmc_tnwg_capabilities_capabilities3);
    proto_tree_add_item(cap3_tree, hf_lbmc_tnwg_capabilities_capabilities3_pcre, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap3_tree, hf_lbmc_tnwg_capabilities_capabilities3_regex, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_capabilities_capabilities4, tvb, offset + O_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES4, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES4, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T);
}

static int dissect_nhdr_patidx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_patidx, tvb, offset, L_LBMC_PATIDX_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_patidx);
    proto_tree_add_item(subtree, hf_lbmc_patidx_next_hdr, tvb, offset + O_LBMC_PATIDX_HDR_T_NEXT_HDR, L_LBMC_PATIDX_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_patidx_hdr_len, tvb, offset + O_LBMC_PATIDX_HDR_T_HDR_LEN, L_LBMC_PATIDX_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_PATIDX_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_patidx_flags, tvb, offset + O_LBMC_PATIDX_HDR_T_FLAGS, L_LBMC_PATIDX_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_patidx_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_patidx_flags_ignore, tvb, offset + O_LBMC_PATIDX_HDR_T_FLAGS, L_LBMC_PATIDX_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_patidx_patidx, tvb, offset + O_LBMC_PATIDX_HDR_T_PATIDX, L_LBMC_PATIDX_HDR_T_PATIDX, ENC_BIG_ENDIAN);
    return (L_LBMC_PATIDX_HDR_T);
}

static int dissect_nhdr_ume_client_lifetime(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_client_lifetime, tvb, offset, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_client_lifetime);
    proto_tree_add_item(subtree, hf_lbmc_ume_client_lifetime_next_hdr, tvb, offset + O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_client_lifetime_hdr_len, tvb, offset + O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_client_lifetime_flags, tvb, offset + O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_FLAGS, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_client_lifetime_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_client_lifetime_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_FLAGS, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_client_lifetime_activity_tmo, tvb, offset + O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_ACTIVITY_TMO, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_ACTIVITY_TMO, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_client_lifetime_lifetime, tvb, offset + O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_LIFETIME, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_LIFETIME, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_client_lifetime_ttl, tvb, offset + O_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_TTL, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_TTL, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T);
}

static int dissect_nhdr_ume_sid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_sid, tvb, offset, L_LBMC_CNTL_UME_SID_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_sid);
    proto_tree_add_item(subtree, hf_lbmc_ume_sid_next_hdr, tvb, offset + O_LBMC_CNTL_UME_SID_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_SID_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_sid_hdr_len, tvb, offset + O_LBMC_CNTL_UME_SID_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_SID_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_SID_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_sid_flags, tvb, offset + O_LBMC_CNTL_UME_SID_HDR_T_FLAGS, L_LBMC_CNTL_UME_SID_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_sid_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_sid_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_SID_HDR_T_FLAGS, L_LBMC_CNTL_UME_SID_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_sid_sid, tvb, offset + O_LBMC_CNTL_UME_SID_HDR_T_SID, L_LBMC_CNTL_UME_SID_HDR_T_SID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_SID_HDR_T);
}

static int dissect_nhdr_umq_idx_cmd(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;
    guint8 cmd_type = 0;
    proto_item * opt_subtree_item = NULL;
    proto_tree * opt_subtree = NULL;
    guint32 opt_flags = 0;
    proto_item * opt_flags_item = NULL;
    proto_tree * opt_flags_tree = NULL;
    guint8 index_len = 0;
    int opt_len = 0;
    int len_dissected = 0;
    proto_item * cmd_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_idx_cmd, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_idx_cmd);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_idx_cmd_flags, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_idx_cmd_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_idx_cmd_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    cmd_type = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_TYPE);
    cmd_type_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_cmd_type, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_TYPE, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_cmd_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_ID, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_CMD_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_inst_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_INST_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_INST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_regid, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_REGID, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_REGID, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T;
    offset += L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T;
    switch (cmd_type)
    {
        case LBMC_UMQ_IDX_CMD_RCV_STOP_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_stop_assign, tvb, offset, L_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_stop_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_stop_assign_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_stop_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_RCV_STOP_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_RCV_START_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_start_assign, tvb, offset, L_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_start_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_start_assign_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_start_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_RCV_START_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_ULB_RCV_STOP_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_ulb_stop_assign, tvb, offset, L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_ulb_stop_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_stop_assign_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_SRC_ID, L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_SRC_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_stop_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_stop_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_stop_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_RESERVED, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_ULB_RCV_STOP_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_ULB_RCV_START_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_ulb_start_assign, tvb, offset, L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_ulb_start_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_start_assign_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_SRC_ID, L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_SRC_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_start_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_start_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_start_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T_RESERVED, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_ULB_RCV_START_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_release_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T + index_len, ENC_NA);
            index_len = opt_len - L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T;
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_release_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_release_assign_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_release_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            opt_flags = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS);
            opt_flags_item = proto_tree_add_none_format(opt_subtree, hf_lbmc_umq_idx_cmd_release_assign_flags, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS, "Flags: 0x%08x", opt_flags);
            opt_flags_tree = proto_item_add_subtree(opt_flags_item, ett_lbmc_umq_idx_cmd_release_assign_flags);
            proto_tree_add_item(opt_flags_tree, hf_lbmc_umq_idx_cmd_release_assign_flags_numeric, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_release_assign_index_len, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX_LEN, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_release_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED, ENC_NA);
            if ((opt_flags & LBM_UMQ_INDEX_FLAG_NUMERIC) != 0)
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_release_assign_numeric_index, tvb, offset + L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_release_assign_string_index, tvb, offset + L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_ASCII|ENC_NA);
            }
            len_dissected += L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T + index_len;
            break;
        case LBMC_UMQ_IDX_CMD_ULB_RCV_RELEASE_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign, tvb, offset, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T + index_len, ENC_NA);
            index_len = opt_len - L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T;
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_ulb_release_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_SRC_ID, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_SRC_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            opt_flags = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS);
            opt_flags_item = proto_tree_add_none_format(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign_flags, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS, "Flags: 0x%08x", opt_flags);
            opt_flags_tree = proto_item_add_subtree(opt_flags_item, ett_lbmc_umq_idx_cmd_ulb_release_assign_flags);
            proto_tree_add_item(opt_flags_tree, hf_lbmc_umq_idx_cmd_ulb_release_assign_flags_numeric, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign_index_len, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX_LEN, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_INDEX_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED, ENC_NA);
            if ((opt_flags & LBM_UMQ_INDEX_FLAG_NUMERIC) != 0)
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign_numeric_index, tvb, offset + L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_release_assign_string_index, tvb, offset + L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_ASCII|ENC_NA);
            }
            len_dissected += L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T + index_len;
            break;
        case LBMC_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_reserve_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T + index_len, ENC_NA);
            index_len = opt_len - L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T;
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_reserve_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_reserve_assign_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_reserve_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            opt_flags = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS);
            opt_flags_item = proto_tree_add_none_format(opt_subtree, hf_lbmc_umq_idx_cmd_reserve_assign_flags, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, "Flags: 0x%08x", opt_flags);
            opt_flags_tree = proto_item_add_subtree(opt_flags_item, ett_lbmc_umq_idx_cmd_reserve_assign_flags);
            proto_tree_add_item(opt_flags_tree, hf_lbmc_umq_idx_cmd_reserve_assign_flags_numeric, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_reserve_assign_index_len, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_reserve_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED, ENC_NA);
            if ((opt_flags & LBM_UMQ_INDEX_FLAG_NUMERIC) != 0)
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_reserve_assign_numeric_index, tvb, offset + L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_reserve_assign_string_index, tvb, offset + L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_ASCII|ENC_NA);
            }
            len_dissected += L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T + index_len;
            break;
        case LBMC_UMQ_IDX_CMD_ULB_RCV_RESERVE_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign, tvb, offset, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T + index_len, ENC_NA);
            index_len = opt_len - L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T;
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_ulb_reserve_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_SRC_ID, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_SRC_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            opt_flags = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS);
            opt_flags_item = proto_tree_add_none_format(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_flags, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, "Flags: 0x%08x", opt_flags);
            opt_flags_tree = proto_item_add_subtree(opt_flags_item, ett_lbmc_umq_idx_cmd_ulb_reserve_assign_flags);
            proto_tree_add_item(opt_flags_tree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_flags_numeric, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_index_len, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED, ENC_NA);
            if ((opt_flags & LBM_UMQ_INDEX_FLAG_NUMERIC) != 0)
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_numeric_index, tvb, offset + L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_ulb_reserve_assign_string_index, tvb, offset + L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_ASCII|ENC_NA);
            }
            len_dissected += L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T + index_len;
            break;
        default:
            expert_add_info_format(pinfo, cmd_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ IDX CMD type 0x%02x", cmd_type);
            break;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_idx_cmd_resp(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;
    guint8 resp_type = 0;
    proto_item * opt_subtree_item = NULL;
    proto_tree * opt_subtree = NULL;
    int string_len = 0;
    int len_dissected = 0;
    guint32 opt_flags = 0;
    proto_item * opt_flags_item = NULL;
    proto_tree * opt_flags_tree = NULL;
    guint8 index_len = 0;
    proto_item * resp_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_idx_cmd_resp, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_idx_cmd_resp);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_idx_cmd_resp_flags, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_idx_cmd_resp_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_idx_cmd_resp_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_idx_cmd_resp_flags_ulb, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    resp_type = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_RESP_TYPE);
    resp_type_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_resp_type, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_RESP_TYPE, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_RESP_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_cmd_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_CMD_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_CMD_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_inst_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_INST_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_INST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_regid, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_REGID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_REGID, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T;
    offset += L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T;
    switch (resp_type)
    {
        case LBMC_UMQ_IDX_CMD_RESP_ERR_TYPE:
            string_len = hdrlen - (L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T + L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T);
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_err, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T + string_len, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_err);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_err_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T_RESERVED, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_err_code, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T_CODE, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T_CODE, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_err_error_string, tvb, offset + L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T, string_len, ENC_ASCII|ENC_NA);
            len_dissected += (L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ERR_HDR_T + string_len);
            break;
        case LBMC_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_stop_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_stop_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_stop_assign_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_stop_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_STOP_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_start_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_start_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_start_assign_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_start_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_start_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_start_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T_RESERVED, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_START_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_ulb_stop_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_src_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_SRC_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_SRC_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T_RESERVED, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_STOP_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_ulb_start_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_ulb_start_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_src_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_SRC_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_SRC_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T_RESERVED, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_START_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_release_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_release_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_release_assign_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_release_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_release_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_release_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RELEASE_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_TYPE:
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_ulb_release_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_ulb_release_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_src_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_SRC_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_SRC_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T_RESERVED, ENC_BIG_ENDIAN);
            len_dissected += L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RELEASE_IDX_ASSIGN_HDR_T;
            break;
        case LBMC_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_TYPE:
            index_len = hdrlen - (L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T + L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T);
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign, tvb, offset, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T + index_len, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_reserve_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            opt_flags = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS);
            opt_flags_item = proto_tree_add_none_format(opt_subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_flags, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, "Flags: 0x%08x", opt_flags);
            opt_flags_tree = proto_item_add_subtree(opt_flags_item, ett_lbmc_umq_idx_cmd_resp_reserve_assign_flags);
            proto_tree_add_item(opt_flags_tree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_flags_numeric, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_index_len, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED, ENC_NA);
            if ((opt_flags & LBM_UMQ_INDEX_FLAG_NUMERIC) != 0)
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_numeric_index, tvb, offset + L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_reserve_assign_string_index, tvb, offset + L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_ASCII|ENC_NA);
            }
            len_dissected += (L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T + index_len);
            break;
        case LBMC_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_TYPE:
            index_len = hdrlen - (L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T + L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T);
            opt_subtree_item = proto_tree_add_item(subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign, tvb, offset, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T + index_len, ENC_NA);
            opt_subtree = proto_item_add_subtree(opt_subtree_item, ett_lbmc_umq_idx_cmd_resp_ulb_reserve_assign);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_src_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_SRC_ID, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_SRC_ID, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
            opt_flags = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS);
            opt_flags_item = proto_tree_add_none_format(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, "Flags: 0x%08x", opt_flags);
            opt_flags_tree = proto_item_add_subtree(opt_flags_item, ett_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags);
            proto_tree_add_item(opt_flags_tree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags_numeric, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_index_len, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_INDEX_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_reserved, tvb, offset + O_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_RESERVED, ENC_NA);
            if ((opt_flags & LBM_UMQ_INDEX_FLAG_NUMERIC) != 0)
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_numeric_index, tvb, offset + L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_item(opt_subtree, hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_string_index, tvb, offset + L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T, (gint)index_len, ENC_ASCII|ENC_NA);
            }
            len_dissected += (L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T + index_len);
            break;
        default:
            expert_add_info_format(pinfo, resp_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ IDX CMD RESP type 0x%02x", resp_type);
            break;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_odomain(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_odomain, tvb, offset, L_LBMC_ODOMAIN_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_odomain);
    proto_tree_add_item(subtree, hf_lbmc_odomain_next_hdr, tvb, offset + O_LBMC_ODOMAIN_HDR_T_NEXT_HDR, L_LBMC_ODOMAIN_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_odomain_hdr_len, tvb, offset + O_LBMC_ODOMAIN_HDR_T_HDR_LEN, L_LBMC_ODOMAIN_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_ODOMAIN_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_odomain_flags, tvb, offset + O_LBMC_ODOMAIN_HDR_T_FLAGS, L_LBMC_ODOMAIN_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_odomain_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_odomain_flags_ignore, tvb, offset + O_LBMC_ODOMAIN_HDR_T_FLAGS, L_LBMC_ODOMAIN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_odomain_domain, tvb, offset + O_LBMC_ODOMAIN_HDR_T_ODOMAIN, L_LBMC_ODOMAIN_HDR_T_ODOMAIN, ENC_BIG_ENDIAN);
    return (L_LBMC_ODOMAIN_HDR_T);
}

static int dissect_nhdr_stream(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmc_stream_info_t * info)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_stream, tvb, offset, L_LBMC_STREAM_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_stream);
    proto_tree_add_item(subtree, hf_lbmc_stream_next_hdr, tvb, offset + O_LBMC_STREAM_HDR_T_NEXT_HDR, L_LBMC_STREAM_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_stream_hdr_len, tvb, offset + O_LBMC_STREAM_HDR_T_HDR_LEN, L_LBMC_STREAM_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_STREAM_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_stream_flags, tvb, offset + O_LBMC_STREAM_HDR_T_FLAGS, L_LBMC_STREAM_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_stream_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_stream_flags_ignore, tvb, offset + O_LBMC_STREAM_HDR_T_FLAGS, L_LBMC_STREAM_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_stream_stream_id, tvb, offset + O_LBMC_STREAM_HDR_T_STREAM_ID, L_LBMC_STREAM_HDR_T_STREAM_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_stream_sqn, tvb, offset + O_LBMC_STREAM_HDR_T_SQN, L_LBMC_STREAM_HDR_T_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_stream_ctxinst, tvb, offset + O_LBMC_STREAM_HDR_T_CTXINST, L_LBMC_STREAM_HDR_T_CTXINST, ENC_NA);
    if (info != NULL)
    {
        info->set = TRUE;
        info->stream_id = tvb_get_ntohl(tvb, offset + O_LBMC_STREAM_HDR_T_STREAM_ID);
        info->sqn = tvb_get_ntohl(tvb, offset + O_LBMC_STREAM_HDR_T_SQN);
        tvb_memcpy(tvb, (void *)&(info->ctxinst), offset + O_LBMC_STREAM_HDR_T_CTXINST, L_LBMC_STREAM_HDR_T_CTXINST);
    }
    return (L_LBMC_STREAM_HDR_T);
}

static int dissect_nhdr_topic_md_interest(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;
    guint16 dom_count = 0;
    int idx = 0;
    int len_dissected = 0;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_topic_md_interest, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_topic_md_interest);
    proto_tree_add_item(subtree, hf_lbmc_topic_md_interest_next_hdr, tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_NEXT_HDR, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_md_interest_hdr_len, tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_HDR_LEN, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_topic_md_interest_flags, tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_topic_md_interest_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_md_interest_flags_ignore, tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_md_interest_flags_cancel, tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_md_interest_flags_refresh, tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_md_interest_domain_count, tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_DOMAIN_COUNT, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_DOMAIN_COUNT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_md_interest_res1, tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_RES1, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_RES1, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T;
    dom_count = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_DOMAIN_COUNT);
    offset += L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T;
    for (idx = 0; idx < dom_count; ++idx)
    {
        proto_tree_add_item(subtree, hf_lbmc_topic_md_interest_domain_id, tvb, offset, (gint)sizeof(lbm_uint32_t), ENC_BIG_ENDIAN);
        offset += (int)sizeof(lbm_uint32_t);
        len_dissected += (int)sizeof(lbm_uint32_t);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_pattern_md_interest(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;
    guint16 dom_count = 0;
    int idx = 0;
    int len_dissected = 0;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_pattern_md_interest, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_pattern_md_interest);
    proto_tree_add_item(subtree, hf_lbmc_pattern_md_interest_next_hdr, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_NEXT_HDR, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_md_interest_hdr_len, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_HDR_LEN, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_pattern_md_interest_flags, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_pattern_md_interest_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_pattern_md_interest_flags_ignore, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_pattern_md_interest_flags_cancel, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_pattern_md_interest_flags_refresh, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_md_interest_type, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_TYPE, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_md_interest_domain_count, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_DOMAIN_COUNT, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_DOMAIN_COUNT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_md_interest_res1, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_RES1, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_RES1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_pattern_md_interest_index, tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_INDEX, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_INDEX, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T;
    dom_count = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_DOMAIN_COUNT);
    offset += L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T;
    for (idx = 0; idx < dom_count; ++idx)
    {
        proto_tree_add_item(subtree, hf_lbmc_pattern_md_interest_domain_id, tvb, offset, (gint)sizeof(lbm_uint32_t), ENC_BIG_ENDIAN);
        offset += (int)sizeof(lbm_uint32_t);
        len_dissected += (int)sizeof(lbm_uint32_t);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_lji_req(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_lji_req, tvb, offset, L_LBMC_CNTL_LJI_REQ_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_lji_req);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_next_hdr, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_NEXT_HDR, L_LBMC_CNTL_LJI_REQ_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_hdr_len, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_HDR_LEN, L_LBMC_CNTL_LJI_REQ_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_lji_req_flags, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_lji_req_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_lji_req_flags_ignore, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_lji_req_flags_l_flag, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_lji_req_flags_m_flag, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_lji_req_flags_o_flag, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_request_idx, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_REQUEST_IDX, L_LBMC_CNTL_LJI_REQ_HDR_T_REQUEST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_transport_idx, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_LJI_REQ_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_topic_idx, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_TOPIC_IDX, L_LBMC_CNTL_LJI_REQ_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_req_ip, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_REQ_IP, L_LBMC_CNTL_LJI_REQ_HDR_T_REQ_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_req_port, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_REQ_PORT, L_LBMC_CNTL_LJI_REQ_HDR_T_REQ_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_res, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_RES, L_LBMC_CNTL_LJI_REQ_HDR_T_RES, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_tx_low_sqn, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_TX_LOW_SQN, L_LBMC_CNTL_LJI_REQ_HDR_T_TX_LOW_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_rx_req_max, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_RX_REQ_MAX, L_LBMC_CNTL_LJI_REQ_HDR_T_RX_REQ_MAX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_lji_req_rx_req_outstanding_max, tvb, offset + O_LBMC_CNTL_LJI_REQ_HDR_T_RX_REQ_OUTSTANDING_MAX, L_LBMC_CNTL_LJI_REQ_HDR_T_RX_REQ_OUTSTANDING_MAX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_LJI_REQ_HDR_T);
}

static int dissect_nhdr_tnwg_ka(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_tnwg_ka, tvb, offset, L_LBMC_CNTL_TNWG_KA_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_tnwg_ka);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_next_hdr, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_NEXT_HDR, L_LBMC_CNTL_TNWG_KA_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_hdr_len, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_HDR_LEN, L_LBMC_CNTL_TNWG_KA_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_tnwg_ka_flags, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS, L_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_tnwg_ka_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_tnwg_ka_flags_ignore, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS, L_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_tnwg_ka_flags_q_flag, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS, L_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_tnwg_ka_flags_r_flag, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS, L_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_index, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_INDEX, L_LBMC_CNTL_TNWG_KA_HDR_T_INDEX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_ts_seconds, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_TS_SECONDS, L_LBMC_CNTL_TNWG_KA_HDR_T_TS_SECONDS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_ts_microseconds, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_TS_MICROSECONDS, L_LBMC_CNTL_TNWG_KA_HDR_T_TS_MICROSECONDS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_reserved_1, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_1, L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_reserved_2, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_2, L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_reserved_3, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_3, L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_3, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_reserved_4, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_4, L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_reserved_5, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_5, L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_5, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tnwg_ka_reserved_6, tvb, offset + O_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_6, L_LBMC_CNTL_TNWG_KA_HDR_T_RESERVED_6, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_TNWG_KA_HDR_T);
}

static int dissect_nhdr_ume_receiver_keepalive(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_receiver_keepalive, tvb, offset, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_receiver_keepalive);
    proto_tree_add_item(subtree, hf_lbmc_ume_receiver_keepalive_next_hdr, tvb, offset + O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_receiver_keepalive_hdr_len, tvb, offset + O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_receiver_keepalive_flags, tvb, offset + O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_FLAGS, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_receiver_keepalive_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_receiver_keepalive_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_FLAGS, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_receiver_keepalive_rcv_regid, tvb, offset + O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_RCV_REGID, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_RCV_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_receiver_keepalive_session_id, tvb, offset + O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_SESSION_ID, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_SESSION_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_receiver_keepalive_ctxinst, tvb, offset + O_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_CTXINST, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_CTXINST, ENC_NA);
    return (L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T);
}

static int dissect_nhdr_umq_ctx_queue_topic_list(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_topic_list, tvb, offset, L_LBMC_CNTL_UMQ_CTX_QUEUE_TOPIC_LIST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_topic_list);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_topic_list_serial_num, tvb, offset + O_LBMC_CNTL_UMQ_CTX_QUEUE_TOPIC_LIST_HDR_T_SERIAL_NUM, L_LBMC_CNTL_UMQ_CTX_QUEUE_TOPIC_LIST_HDR_T_SERIAL_NUM, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_CTX_QUEUE_TOPIC_LIST_HDR_T);
}

static int dissect_nhdr_umq_rcv_msg_retrieve_entry(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_msg_retrieve_entry, tvb, offset, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_msg_retrieve_entry);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_retrieve_entry_regid, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T_REGID, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T_REGID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_retrieve_entry_stamp, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STAMP, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STAMP, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_ENTRY_HDR_T);
}

static int dissect_nhdr_umq_rcv_msg_retrieve(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int len = 0;
    int dissected_len = 0;
    guint8 num_msgids;
    guint8 idx;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_msg_retrieve, tvb, offset, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_msg_retrieve);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_retrieve_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_retrieve_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_retrieve_info_only, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_INFO_ONLY, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_INFO_ONLY, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_retrieve_num_msgids, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGIDS, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGIDS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_retrieve_flags, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_FLAGS, ENC_BIG_ENDIAN);

    dissected_len = L_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T;
    num_msgids = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGIDS);
    for (idx = 0; idx < num_msgids; ++idx)
    {
        len = dissect_nhdr_umq_rcv_msg_retrieve_entry(tvb, offset + dissected_len, pinfo, subtree);
        dissected_len += len;
    }
    proto_item_set_len(subtree_item, dissected_len);
    return (dissected_len);
}

static int dissect_nhdr_umq_rcv_msg_list(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_msg_list, tvb, offset, L_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_msg_list);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_list_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_msg_list_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_RCV_MSG_LIST_HDR_T);
}

static int dissect_nhdr_umq_cmd(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;
    int len_dissected = 0;
    guint8 cmd_type = 0;
    proto_item * cmd_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_CMD_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_CMD_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_cmd_flags, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_CMD_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_cmd_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_cmd_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_CMD_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    cmd_type_item = proto_tree_add_item(subtree, hf_lbmc_umq_cmd_cmd_type, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_TYPE, L_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_CMD_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_cmd_id, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_ID, L_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_inst_idx, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_INST_IDX, L_LBMC_CNTL_UMQ_CMD_HDR_T_INST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_regid, tvb, offset + O_LBMC_CNTL_UMQ_CMD_HDR_T_REGID, L_LBMC_CNTL_UMQ_CMD_HDR_T_REGID, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_CMD_HDR_T;
    cmd_type = tvb_get_guint8(tvb, O_LBMC_CNTL_UMQ_CMD_HDR_T_CMD_TYPE);
    switch (cmd_type)
    {
        case LBMC_UMQ_CMD_TYPE_TOPIC_LIST:
            len_dissected += dissect_nhdr_umq_ctx_queue_topic_list(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_CMD_TYPE_RCV_MSG_RETRIEVE:
            len_dissected += dissect_nhdr_umq_rcv_msg_retrieve(tvb, offset + len_dissected, pinfo, subtree);
            break;
        case LBMC_UMQ_CMD_TYPE_RCV_MSG_LIST:
            len_dissected += dissect_nhdr_umq_rcv_msg_list(tvb, offset + len_dissected, pinfo, subtree);
            break;
        default:
            expert_add_info_format(pinfo, cmd_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ CMD cmd_type 0x%02x", cmd_type);
            break;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_cmd_resp_rcv_msg_retrieve(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp_msg_retrieve, tvb, offset, L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp_msg_retrieve);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_msg_retrieve_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_msg_retrieve_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T);
}

static int dissect_nhdr_umq_cmd_resp_rcv_xmsg_retrieve(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int len_dissected;
    int num_msgs;
    int entry_offset;
    proto_item * entry_item = NULL;
    proto_tree * entry_tree = NULL;
    int idx;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp_xmsg_retrieve, tvb, offset, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp_xmsg_retrieve);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_num_msgs, tvb, offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGS, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_flags, tvb, offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_FLAGS, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_reserved, tvb, offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_RESERVED, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T;
    entry_offset = offset + len_dissected;
    num_msgs = (int)tvb_get_guint8(tvb, offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_HDR_T_NUM_MSGS);
    for (idx = 0; idx < num_msgs; ++idx)
    {
        entry_item = proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry, tvb, entry_offset, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T, ENC_NA);
        entry_tree = proto_item_add_subtree(entry_item, ett_lbmc_umq_cmd_resp_xmsg_retrieve_entry);
        proto_tree_add_item(entry_tree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_regid, tvb, entry_offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_REGID, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_REGID, ENC_BIG_ENDIAN);
        proto_tree_add_item(entry_tree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_stamp, tvb, entry_offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STAMP, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STAMP, ENC_BIG_ENDIAN);
        proto_tree_add_item(entry_tree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_assign_id, tvb, entry_offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_ASSIGN_ID, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
        proto_tree_add_item(entry_tree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_num_ras, tvb, entry_offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_NUM_RAS, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_NUM_RAS, ENC_BIG_ENDIAN);
        proto_tree_add_item(entry_tree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_status, tvb, entry_offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STATUS, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_STATUS, ENC_BIG_ENDIAN);
        proto_tree_add_item(entry_tree, hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_reserved, tvb, entry_offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_RESERVED, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T_RESERVED, ENC_BIG_ENDIAN);
        entry_offset += L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T;
        len_dissected += L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_RETRIEVE_ENTRY_HDR_T;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_cmd_resp_rcv_msg_list(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp_msg_list, tvb, offset, L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp_msg_list);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_msg_list_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_msg_list_assign_id, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_ASSIGN_ID, L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_ASSIGN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T);
}

static int dissect_nhdr_umq_cmd_resp_rcv_xmsg_list(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int len_dissected = 0;
    guint64 num_msgs = 0;
    int entry_offset = 0;
    proto_item * entry_item = NULL;
    proto_tree * entry_tree = NULL;
    guint64 idx;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp_xmsg_list, tvb, offset, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp_xmsg_list);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_xmsg_list_num_msgs, tvb, offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_NUM_MSGS, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_NUM_MSGS, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T;
    entry_offset = offset + len_dissected;
    num_msgs = tvb_get_ntoh64(tvb, offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_HDR_T_NUM_MSGS);
    for (idx = 0; idx < num_msgs; ++idx)
    {
        entry_item = proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_xmsg_list_entry, tvb, entry_offset, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T, ENC_NA);
        entry_tree = proto_item_add_subtree(entry_item, ett_lbmc_umq_cmd_resp_xmsg_list_entry);
        proto_tree_add_item(entry_tree, hf_lbmc_umq_cmd_resp_xmsg_list_entry_regid, tvb, entry_offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T_REGID, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T_REGID, ENC_BIG_ENDIAN);
        proto_tree_add_item(entry_tree, hf_lbmc_umq_cmd_resp_xmsg_list_entry_stamp, tvb, entry_offset + O_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T_STAMP, L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T_STAMP, ENC_BIG_ENDIAN);
        entry_offset += L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T;
        len_dissected += L_LBMC_XCNTL_UMQ_CMD_RESP_RCV_MSG_LIST_MSG_ENTRY_HDR_T;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_cmd_resp_ctx_topic_list_appset_entry(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int len_dissected = 0;
    guint8 appset_name_len;
    guint16 num_receiver_type_ids;
    guint16 idx;
    int receiver_type_id_offset;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry, tvb, offset, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_num_receiver_type_ids, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_NUM_RECEIVER_TYPE_IDS, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_NUM_RECEIVER_TYPE_IDS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_appset_idx, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_IDX, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_appset_name_len, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_NAME_LEN, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_NAME_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_reserved, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_RESERVED, ENC_NA);
    len_dissected = L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T;
    appset_name_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_APPSET_NAME_LEN);
    len_dissected += (int)appset_name_len;
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_name, tvb, offset + L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T, (int)appset_name_len, ENC_ASCII|ENC_NA);
    num_receiver_type_ids = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_APPSET_ENTRY_HDR_T_NUM_RECEIVER_TYPE_IDS);
    if (num_receiver_type_ids > 0)
    {
        receiver_type_id_offset = offset + len_dissected;
        for (idx = 0; idx < num_receiver_type_ids; ++idx)
        {
            proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_receiver_type_id, tvb, receiver_type_id_offset, sizeof(lbm_uint32_t), ENC_BIG_ENDIAN);
            len_dissected += (int)sizeof(lbm_uint32_t);
            receiver_type_id_offset += (int)sizeof(lbm_uint32_t);
        }
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_cmd_resp_ctx_topic_list_topic_entry(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int len_dissected = 0;
    guint8 topic_len;
    guint16 num_appsets;
    guint16 idx;
    int appset_offset;
    int len;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry, tvb, offset, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp_topic_list_topic_entry);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_rcr_idx, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_RCR_IDX, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_RCR_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_num_appsets, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_NUM_APPSETS, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_NUM_APPSETS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_topic_len, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_TOPIC_LEN, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_TOPIC_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_reserved, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T;
    topic_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_TOPIC_LEN);
    len_dissected += (int)topic_len;
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_topic_entry_topic, tvb, offset + L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T, (int)topic_len, ENC_ASCII|ENC_NA);
    num_appsets = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_TOPIC_ENTRY_HDR_T_NUM_APPSETS);
    if (num_appsets > 0)
    {
        appset_offset = offset + len_dissected;
        for (idx = 0; idx < num_appsets; ++idx)
        {
            len = dissect_nhdr_umq_cmd_resp_ctx_topic_list_appset_entry(tvb, appset_offset, pinfo, subtree);
            appset_offset += len;
            len_dissected += len;
        }
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_cmd_resp_ctx_topic_list(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int len_dissected = 0;
    int len;
    guint32 num_topics;
    guint32 idx;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp_topic_list, tvb, offset, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp_topic_list);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_topic_list_num_topics, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_HDR_T_NUM_TOPICS, L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_HDR_T_NUM_TOPICS, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_HDR_T;
    num_topics = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_CTX_TOPIC_LIST_HDR_T_NUM_TOPICS);
    for (idx = 0; idx < num_topics; ++idx)
    {
        len = dissect_nhdr_umq_cmd_resp_ctx_topic_list_topic_entry(tvb, offset + len_dissected, pinfo, subtree);
        len_dissected += len;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_cmd_resp_err(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int len_dissected = 0;
    int errmsg_len;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp_err, tvb, offset, L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp_err);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_err_reserved, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T_RESERVED, L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_err_code, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T_CODE, L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T_CODE, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T;
    errmsg_len = tvb_reported_length_remaining(tvb, offset + L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_err_errmsg, tvb, offset + L_LBMC_CNTL_UMQ_CMD_RESP_ERR_HDR_T, errmsg_len, ENC_ASCII|ENC_NA);
    len_dissected += errmsg_len;
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_umq_cmd_resp(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, gboolean data_msg)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;
    int len_dissected = 0;
    int len;
    guint8 resp_type;
    proto_item * resp_type_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_cmd_resp, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_cmd_resp);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_cmd_resp_flags, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_cmd_resp_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_cmd_resp_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    resp_type_item = proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_resp_type, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_RESP_TYPE, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_RESP_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_queue_id, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_QUEUE_ID, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_QUEUE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_cmd_id, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_CMD_ID, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_CMD_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_inst_idx, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_INST_IDX, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_INST_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_cmd_resp_regid, tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_REGID, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_REGID, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T;
    resp_type = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_RESP_TYPE);
    if (tvb_length_remaining(tvb, offset + L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T) > 0)
    {
        switch (resp_type)
        {
            case LBMC_UMQ_CMD_RESP_TYPE_CTX_TOPIC_LIST:
                len = dissect_nhdr_umq_cmd_resp_ctx_topic_list(tvb, len_dissected, pinfo, subtree);
                break;
            case LBMC_UMQ_CMD_RESP_TYPE_RCV_MSG_RETRIEVE:
                if (data_msg)
                {
                    len = dissect_nhdr_umq_cmd_resp_rcv_xmsg_retrieve(tvb, len_dissected, pinfo, subtree);
                }
                else
                {
                    len = dissect_nhdr_umq_cmd_resp_rcv_msg_retrieve(tvb, len_dissected, pinfo, subtree);
                }
                break;
            case LBMC_UMQ_CMD_RESP_TYPE_RCV_MSG_LIST:
                if (data_msg)
                {
                    len = dissect_nhdr_umq_cmd_resp_rcv_xmsg_list(tvb, len_dissected, pinfo, subtree);
                }
                else
                {
                    len = dissect_nhdr_umq_cmd_resp_rcv_msg_list(tvb, len_dissected, pinfo, subtree);
                }
                break;
            case LBMC_UMQ_CMD_RESP_TYPE_ERROR:
                len = dissect_nhdr_umq_cmd_resp_err(tvb, len_dissected, pinfo, subtree);
                break;
            default:
                expert_add_info_format(pinfo, resp_type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC UMQ CMD_RESP cmd_type 0x%02x", resp_type);
                len = 0;
                break;
        }
    }
    else
    {
        len = 0;
    }
    len_dissected += len;
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_sri_req(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_sri_req, tvb, offset, L_LBMC_CNTL_SRI_REQ_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_sri_req);
    proto_tree_add_item(subtree, hf_lbmc_sri_req_next_hdr, tvb, offset + O_LBMC_CNTL_SRI_REQ_HDR_T_NEXT_HDR, L_LBMC_CNTL_SRI_REQ_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_sri_req_hdr_len, tvb, offset + O_LBMC_CNTL_SRI_REQ_HDR_T_HDR_LEN, L_LBMC_CNTL_SRI_REQ_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_SRI_REQ_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_sri_req_flags, tvb, offset + O_LBMC_CNTL_SRI_REQ_HDR_T_FLAGS, L_LBMC_CNTL_SRI_REQ_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_sri_req_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_sri_req_flags_ignore, tvb, offset + O_LBMC_CNTL_SRI_REQ_HDR_T_FLAGS, L_LBMC_CNTL_SRI_REQ_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_sri_req_transport_idx, tvb, offset + O_LBMC_CNTL_SRI_REQ_HDR_T_TRANSPORT_IDX, L_LBMC_CNTL_SRI_REQ_HDR_T_TRANSPORT_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_sri_req_topic_idx, tvb, offset + O_LBMC_CNTL_SRI_REQ_HDR_T_TOPIC_IDX, L_LBMC_CNTL_SRI_REQ_HDR_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_SRI_REQ_HDR_T);
}

static int dissect_nhdr_ume_store_domain(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_store_domain, tvb, offset, L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_store_domain);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_domain_next_hdr, tvb, offset + O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_domain_hdr_len, tvb, offset + O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_store_domain_flags, tvb, offset + O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_FLAGS, L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_store_domain_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_store_domain_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_FLAGS, L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_domain_domain, tvb, offset + O_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_DOMAIN, L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_DOMAIN, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T);
}

static int dissect_nhdr_sri(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_sri, tvb, offset, L_LBMC_CNTL_SRI_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_sri);
    proto_tree_add_item(subtree, hf_lbmc_sri_next_hdr, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_NEXT_HDR, L_LBMC_CNTL_SRI_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_sri_hdr_len, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_HDR_LEN, L_LBMC_CNTL_SRI_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_SRI_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_sri_flags, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_FLAGS, L_LBMC_CNTL_SRI_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_sri_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_sri_flags_ignore, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_FLAGS, L_LBMC_CNTL_SRI_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_sri_flags_acktosrc, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_FLAGS, L_LBMC_CNTL_SRI_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_sri_flags_initial_sqn_known, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_FLAGS, L_LBMC_CNTL_SRI_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_sri_version, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_VERSION, L_LBMC_CNTL_SRI_HDR_T_VERSION, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_sri_low_sqn, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_LOW_SQN, L_LBMC_CNTL_SRI_HDR_T_LOW_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_sri_high_sqn, tvb, offset + O_LBMC_CNTL_SRI_HDR_T_HIGH_SQN, L_LBMC_CNTL_SRI_HDR_T_HIGH_SQN, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_SRI_HDR_T);
}

static int dissect_nhdr_route_info(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_route_info, tvb, offset, L_LBMC_CNTL_ROUTE_INFO_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_route_info);
    proto_tree_add_item(subtree, hf_lbmc_route_info_next_hdr, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_NEXT_HDR, L_LBMC_CNTL_ROUTE_INFO_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_hdr_len, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_HDR_LEN, L_LBMC_CNTL_ROUTE_INFO_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_route_info_flags, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_FLAGS, L_LBMC_CNTL_ROUTE_INFO_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_route_info_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_route_info_flags_ignore, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_FLAGS, L_LBMC_CNTL_ROUTE_INFO_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_gateway_version, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_GATEWAY_VERSION, L_LBMC_CNTL_ROUTE_INFO_HDR_T_GATEWAY_VERSION, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_configuration_signature, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_CONFIGURATION_SIGNATURE, L_LBMC_CNTL_ROUTE_INFO_HDR_T_CONFIGURATION_SIGNATURE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_node_id, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_NODE_ID, L_LBMC_CNTL_ROUTE_INFO_HDR_T_NODE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_topology, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_TOPOLOGY, L_LBMC_CNTL_ROUTE_INFO_HDR_T_TOPOLOGY, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_vers, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_VERS, L_LBMC_CNTL_ROUTE_INFO_HDR_T_VERS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_sqn, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_SQN, L_LBMC_CNTL_ROUTE_INFO_HDR_T_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_ttl, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_TTL, L_LBMC_CNTL_ROUTE_INFO_HDR_T_TTL, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_reserved1, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_RESERVED1, L_LBMC_CNTL_ROUTE_INFO_HDR_T_RESERVED1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_reserved2, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_HDR_T_RESERVED2, L_LBMC_CNTL_ROUTE_INFO_HDR_T_RESERVED2, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_ROUTE_INFO_HDR_T);
}

static int dissect_nhdr_route_info_neighbor(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_route_info_neighbor, tvb, offset, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_route_info_neighbor);
    proto_tree_add_item(subtree, hf_lbmc_route_info_neighbor_next_hdr, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_NEXT_HDR, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_neighbor_hdr_len, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_HDR_LEN, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_route_info_neighbor_flags, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_FLAGS, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_route_info_neighbor_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_route_info_neighbor_flags_ignore, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_FLAGS, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_neighbor_node_id, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_NODE_ID, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_NODE_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_neighbor_ingress_cost, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_INGRESS_COST, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_INGRESS_COST, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_route_info_neighbor_egress_cost, tvb, offset + O_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_EGRESS_COST, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_EGRESS_COST, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T);
}

static int dissect_nhdr_gateway_name(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;
    int len_dissected = 0;
    int namelen = 0;
    proto_item * hdrlen_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_GATEWAY_NAME_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_gateway_name, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_gateway_name);
    proto_tree_add_item(subtree, hf_lbmc_gateway_name_next_hdr, tvb, offset + O_LBMC_CNTL_GATEWAY_NAME_HDR_T_NEXT_HDR, L_LBMC_CNTL_GATEWAY_NAME_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_gateway_name_hdr_len, tvb, offset + O_LBMC_CNTL_GATEWAY_NAME_HDR_T_HDR_LEN, L_LBMC_CNTL_GATEWAY_NAME_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_gateway_name_flags, tvb, offset + O_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS, L_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_gateway_name_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_gateway_name_flags_ignore, tvb, offset + O_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS, L_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_BASIC_HDR_T;
    namelen = (int) hdrlen - len_dissected;
    if (namelen > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_gateway_name_gateway_name, tvb, offset + O_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS + L_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS, namelen, ENC_ASCII | ENC_NA);
        len_dissected += namelen;
    }
    else
    {
        expert_add_info(pinfo, hdrlen_item, &ei_lbmc_analysis_length_incorrect);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_auth_request(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;
    int len_dissected = 0;
    guint8 user_len;
    int data_offset;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_auth_request, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_auth_request);
    proto_tree_add_item(subtree, hf_lbmc_auth_request_next_hdr, tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_NEXT_HDR, L_LBMC_CNTL_AUTH_REQUEST_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_request_hdr_len, tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_HDR_LEN, L_LBMC_CNTL_AUTH_REQUEST_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_auth_request_flags, tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_REQUEST_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_auth_request_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_auth_request_flags_ignore, tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_REQUEST_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_request_opid, tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_OPID, L_LBMC_CNTL_AUTH_REQUEST_HDR_T_OPID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_request_user_len, tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_USER_LEN, L_LBMC_CNTL_AUTH_REQUEST_HDR_T_USER_LEN, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_AUTH_REQUEST_HDR_T;
    data_offset = offset + len_dissected;
    user_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_REQUEST_HDR_T_USER_LEN);
    if (user_len > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_auth_request_user_name, tvb, data_offset, (int)user_len, ENC_ASCII|ENC_NA);
        len_dissected += (int)user_len;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_auth_challenge(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;
    int len_dissected = 0;
    guint8 mod_len;
    guint8 gen_len;
    guint8 salt_len;
    guint8 pubkey_len;
    int data_offset;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_auth_challenge, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_auth_challenge);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_next_hdr, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_NEXT_HDR, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_hdr_len, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_HDR_LEN, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_auth_challenge_flags, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_auth_challenge_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_auth_challenge_flags_ignore, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_opid, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_OPID, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_OPID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_mod_len, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_MOD_LEN, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_MOD_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_gen_len, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_GEN_LEN, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_GEN_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_salt_len, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_SALT_LEN, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_SALT_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_pubkey_len, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_PUBKEY_LEN, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_PUBKEY_LEN, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T;
    data_offset = offset + len_dissected;
    mod_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_MOD_LEN);
    if (mod_len > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_auth_challenge_mod, tvb, data_offset, (int)mod_len, ENC_NA);
        len_dissected += (int)mod_len;
        data_offset += (int)mod_len;
    }
    gen_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_GEN_LEN);
    if (gen_len > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_auth_challenge_gen, tvb, data_offset, (int)gen_len, ENC_NA);
        len_dissected += (int)gen_len;
        data_offset += (int)gen_len;
    }
    salt_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_SALT_LEN);
    if (salt_len > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_auth_challenge_salt, tvb, data_offset, (int)salt_len, ENC_NA);
        len_dissected += (int)salt_len;
        data_offset += (int)salt_len;
    }
    pubkey_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_PUBKEY_LEN);
    if (pubkey_len > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_auth_challenge_pubkey, tvb, data_offset, (int)pubkey_len, ENC_NA);
        len_dissected += (int)pubkey_len;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_auth_challenge_rsp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;
    int len_dissected = 0;
    guint8 pubkey_len;
    guint8 evidence_len;
    int data_offset;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_auth_challenge_rsp, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_auth_challenge_rsp);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_rsp_next_hdr, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_NEXT_HDR, L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_rsp_hdr_len, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_HDR_LEN, L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_auth_challenge_rsp_flags, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_auth_challenge_rsp_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_auth_challenge_rsp_flags_ignore, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_rsp_opid, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_OPID, L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_OPID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_rsp_pubkey_len, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_PUBKEY_LEN, L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_PUBKEY_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_challenge_rsp_evidence_len, tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_EVIDENCE_LEN, L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_EVIDENCE_LEN, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T;
    data_offset = offset + len_dissected;
    pubkey_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_PUBKEY_LEN);
    if (pubkey_len > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_auth_challenge_rsp_pubkey, tvb, data_offset, (int)pubkey_len, ENC_NA);
        len_dissected += (int)pubkey_len;
        data_offset += (int)pubkey_len;
    }
    evidence_len = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_EVIDENCE_LEN);
    if (evidence_len > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_auth_challenge_rsp_evidence, tvb, data_offset, (int)evidence_len, ENC_NA);
        len_dissected += (int)evidence_len;
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_auth_result(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_auth_result, tvb, offset, L_LBMC_CNTL_AUTH_RESULT_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_auth_result);
    proto_tree_add_item(subtree, hf_lbmc_auth_result_next_hdr, tvb, offset + O_LBMC_CNTL_AUTH_RESULT_HDR_T_NEXT_HDR, L_LBMC_CNTL_AUTH_RESULT_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_result_hdr_len, tvb, offset + O_LBMC_CNTL_AUTH_RESULT_HDR_T_HDR_LEN, L_LBMC_CNTL_AUTH_RESULT_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_RESULT_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_auth_result_flags, tvb, offset + O_LBMC_CNTL_AUTH_RESULT_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_RESULT_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_auth_result_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_auth_result_flags_ignore, tvb, offset + O_LBMC_CNTL_AUTH_RESULT_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_RESULT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_result_opid, tvb, offset + O_LBMC_CNTL_AUTH_RESULT_HDR_T_OPID, L_LBMC_CNTL_AUTH_RESULT_HDR_T_OPID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_result_result, tvb, offset + O_LBMC_CNTL_AUTH_RESULT_HDR_T_RESULT, L_LBMC_CNTL_AUTH_RESULT_HDR_T_RESULT, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_AUTH_RESULT_HDR_T);
}

static int dissect_nhdr_auth_unknown(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * opid_item = NULL;
    guint8 opid;
    int len_dissected = 0;
    int datalen = 0;
    proto_item * hdrlen_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_GENERIC_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_auth_unknown, tvb, offset, (int) hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_auth_unknown);
    proto_tree_add_item(subtree, hf_lbmc_auth_unknown_next_hdr, tvb, offset + O_LBMC_CNTL_AUTH_GENERIC_HDR_T_NEXT_HDR, L_LBMC_CNTL_AUTH_GENERIC_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_auth_unknown_hdr_len, tvb, offset + O_LBMC_CNTL_AUTH_GENERIC_HDR_T_HDR_LEN, L_LBMC_CNTL_AUTH_GENERIC_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_auth_unknown_flags, tvb, offset + O_LBMC_CNTL_AUTH_GENERIC_HDR_T_FLAGS, L_LBMC_CNTL_AUTH_GENERIC_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    opid_item = proto_tree_add_item(subtree, hf_lbmc_auth_unknown_opid, tvb, offset + O_LBMC_CNTL_AUTH_GENERIC_HDR_T_OPID, L_LBMC_CNTL_AUTH_GENERIC_HDR_T_OPID, ENC_BIG_ENDIAN);
    opid = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_AUTH_GENERIC_HDR_T_OPID);
    expert_add_info_format(pinfo, opid_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC AUTH OPID 0x%02x", opid);
    len_dissected = L_LBMC_CNTL_AUTH_GENERIC_HDR_T;
    datalen = (int) hdrlen - len_dissected;
    if (datalen > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_auth_unknown_data, tvb, offset + L_LBMC_CNTL_AUTH_GENERIC_HDR_T, datalen, ENC_NA);
        len_dissected += datalen;
    }
    else
    {
        expert_add_info(pinfo, hdrlen_item, &ei_lbmc_analysis_length_incorrect);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_hmac(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_hmac, tvb, offset, L_LBMC_CNTL_HMAC_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_hmac);
    proto_tree_add_item(subtree, hf_lbmc_hmac_next_hdr, tvb, offset + O_LBMC_CNTL_HMAC_HDR_T_NEXT_HDR, L_LBMC_CNTL_HMAC_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_hmac_hdr_len, tvb, offset + O_LBMC_CNTL_HMAC_HDR_T_HDR_LEN, L_LBMC_CNTL_HMAC_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_HMAC_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_hmac_flags, tvb, offset + O_LBMC_CNTL_HMAC_HDR_T_FLAGS, L_LBMC_CNTL_HMAC_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_hmac_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_hmac_flags_ignore, tvb, offset + O_LBMC_CNTL_HMAC_HDR_T_FLAGS, L_LBMC_CNTL_HMAC_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_hmac_padding, tvb, offset + O_LBMC_CNTL_HMAC_HDR_T_PADDING, L_LBMC_CNTL_HMAC_HDR_T_PADDING, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_hmac_data, tvb, offset + O_LBMC_CNTL_HMAC_HDR_T_DATA, L_LBMC_CNTL_HMAC_HDR_T_DATA, ENC_NA);
    return (L_LBMC_CNTL_HMAC_HDR_T);
}

static int dissect_nhdr_umq_sid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_umq_sid, tvb, offset, L_LBMC_CNTL_UMQ_SID_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_umq_sid);
    proto_tree_add_item(subtree, hf_lbmc_umq_sid_next_hdr, tvb, offset + O_LBMC_CNTL_UMQ_SID_HDR_T_NEXT_HDR, L_LBMC_CNTL_UMQ_SID_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_sid_hdr_len, tvb, offset + O_LBMC_CNTL_UMQ_SID_HDR_T_HDR_LEN, L_LBMC_CNTL_UMQ_SID_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_CNTL_UMQ_SID_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_umq_sid_flags, tvb, offset + O_LBMC_CNTL_UMQ_SID_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_SID_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_umq_sid_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_umq_sid_flags_ignore, tvb, offset + O_LBMC_CNTL_UMQ_SID_HDR_T_FLAGS, L_LBMC_CNTL_UMQ_SID_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_sid_key, tvb, offset + O_LBMC_CNTL_UMQ_SID_HDR_T_KEY, L_LBMC_CNTL_UMQ_SID_HDR_T_KEY, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_umq_sid_sid, tvb, offset + O_LBMC_CNTL_UMQ_SID_HDR_T_SID, L_LBMC_CNTL_UMQ_SID_HDR_T_SID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UMQ_SID_HDR_T);
}

static int dissect_nhdr_destination(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmc_destination_info_t * info)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_destination, tvb, offset, L_LBMC_DESTINATION_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_destination);
    proto_tree_add_item(subtree, hf_lbmc_destination_next_hdr, tvb, offset + O_LBMC_DESTINATION_HDR_T_NEXT_HDR, L_LBMC_DESTINATION_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_hdr_len, tvb, offset + O_LBMC_DESTINATION_HDR_T_HDR_LEN, L_LBMC_DESTINATION_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_DESTINATION_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_destination_flags, tvb, offset + O_LBMC_DESTINATION_HDR_T_FLAGS, L_LBMC_DESTINATION_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_destination_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_destination_flags_ignore, tvb, offset + O_LBMC_DESTINATION_HDR_T_FLAGS, L_LBMC_DESTINATION_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_domain_id, tvb, offset + O_LBMC_DESTINATION_HDR_T_DOMAIN_ID, L_LBMC_DESTINATION_HDR_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_ipaddr, tvb, offset + O_LBMC_DESTINATION_HDR_T_IPADDR, L_LBMC_DESTINATION_HDR_T_IPADDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_port, tvb, offset + O_LBMC_DESTINATION_HDR_T_PORT, L_LBMC_DESTINATION_HDR_T_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_hops_taken, tvb, offset + O_LBMC_DESTINATION_HDR_T_HOPS_TAKEN, L_LBMC_DESTINATION_HDR_T_HOPS_TAKEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_orig_domain_id, tvb, offset + O_LBMC_DESTINATION_HDR_T_ORIG_DOMAIN_ID, L_LBMC_DESTINATION_HDR_T_ORIG_DOMAIN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_orig_ipaddr, tvb, offset + O_LBMC_DESTINATION_HDR_T_ORIG_IPADDR, L_LBMC_DESTINATION_HDR_T_ORIG_IPADDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_orig_port, tvb, offset + O_LBMC_DESTINATION_HDR_T_ORIG_PORT, L_LBMC_DESTINATION_HDR_T_ORIG_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_destination_reserved, tvb, offset + O_LBMC_DESTINATION_HDR_T_RESERVED, L_LBMC_DESTINATION_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    if (info != NULL)
    {
        info->set = TRUE;
        info->endpoint_a.domain = tvb_get_ntohl(tvb, offset + O_LBMC_DESTINATION_HDR_T_DOMAIN_ID);
        TVB_SET_ADDRESS(&(info->endpoint_a.addr), AT_IPv4, tvb, offset + O_LBMC_DESTINATION_HDR_T_IPADDR, L_LBMC_DESTINATION_HDR_T_IPADDR);
        info->endpoint_a.port = tvb_get_ntohs(tvb, offset + O_LBMC_DESTINATION_HDR_T_PORT);
        info->endpoint_b.domain = tvb_get_ntohl(tvb, offset + O_LBMC_DESTINATION_HDR_T_ORIG_DOMAIN_ID);
        TVB_SET_ADDRESS(&(info->endpoint_b.addr), AT_IPv4, tvb, offset + O_LBMC_DESTINATION_HDR_T_ORIG_IPADDR, L_LBMC_DESTINATION_HDR_T_ORIG_IPADDR);
        info->endpoint_b.port = tvb_get_ntohs(tvb, offset + O_LBMC_DESTINATION_HDR_T_ORIG_PORT);
    }
    return (L_LBMC_DESTINATION_HDR_T);
}

static int dissect_nhdr_topic_idx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint8 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_topic_idx, tvb, offset, L_LBMC_TOPIC_IDX_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_topic_idx);
    proto_tree_add_item(subtree, hf_lbmc_topic_idx_next_hdr, tvb, offset + O_LBMC_TOPIC_IDX_HDR_T_NEXT_HDR, L_LBMC_TOPIC_IDX_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_idx_hdr_len, tvb, offset + O_LBMC_TOPIC_IDX_HDR_T_HDR_LEN, L_LBMC_TOPIC_IDX_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_TOPIC_IDX_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_topic_idx_flags, tvb, offset + O_LBMC_TOPIC_IDX_HDR_T_FLAGS, L_LBMC_TOPIC_IDX_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_topic_idx_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_idx_flags_ignore, tvb, offset + O_LBMC_TOPIC_IDX_HDR_T_FLAGS, L_LBMC_TOPIC_IDX_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_idx_tidx, tvb, offset + O_LBMC_TOPIC_IDX_HDR_T_TIDX, L_LBMC_TOPIC_IDX_HDR_T_TIDX, ENC_BIG_ENDIAN);
    return (L_LBMC_TOPIC_IDX_HDR_T);
}

static int dissect_nhdr_topic_source(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_topic_source, tvb, offset, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_topic_source);
    proto_tree_add_item(subtree, hf_lbmc_topic_source_next_hdr, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_NEXT_HDR, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_source_hdr_len, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_HDR_LEN, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_topic_source_flags, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_topic_source_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_source_flags_ignore, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_source_flags_eos, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_source_domain_id, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_HDR_T_DOMAIN_ID, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_TOPIC_SOURCE_HDR_T);
}

static int dissect_nhdr_topic_source_exfunc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;
    proto_item * functionality_flags_item = NULL;
    proto_tree * functionality_flags_tree = NULL;
    guint32 functionality_flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_topic_source_exfunc, tvb, offset, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_topic_source_exfunc);
    proto_tree_add_item(subtree, hf_lbmc_topic_source_exfunc_next_hdr, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_NEXT_HDR, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_source_exfunc_hdr_len, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_HDR_LEN, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_topic_source_exfunc_flags, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_topic_source_exfunc_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_topic_source_exfunc_flags_ignore, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_source_exfunc_src_ip, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_SRC_IP, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_SRC_IP, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_source_exfunc_src_port, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_SRC_PORT, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_SRC_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_topic_source_exfunc_unused, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_UNUSED, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_UNUSED, ENC_BIG_ENDIAN);
    functionality_flags = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS);
    functionality_flags_item = proto_tree_add_none_format(subtree, hf_lbmc_topic_source_exfunc_functionality_flags, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, "Flags: 0x%08x", functionality_flags);
    functionality_flags_tree = proto_item_add_subtree(functionality_flags_item, ett_lbmc_topic_source_exfunc_functionality_flags);
    proto_tree_add_item(functionality_flags_tree, hf_lbmc_topic_source_exfunc_functionality_flags_lj, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(functionality_flags_tree, hf_lbmc_topic_source_exfunc_functionality_flags_ume, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(functionality_flags_tree, hf_lbmc_topic_source_exfunc_functionality_flags_umq, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(functionality_flags_tree, hf_lbmc_topic_source_exfunc_functionality_flags_ulb, tvb, offset + O_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T);
}

static int dissect_nhdr_ume_store_ext(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_store_ext, tvb, offset, L_LBMC_CNTL_UME_STORE_EXT_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_store_ext);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_next_hdr, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_hdr_len, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_store_ext_flags, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_FLAGS, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_store_ext_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_store_ext_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_FLAGS, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_grp_idx, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_GRP_IDX, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_GRP_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_store_tcp_port, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_TCP_PORT, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_TCP_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_store_idx, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_IDX, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_IDX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_store_ip_addr, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_IP_ADDR, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_STORE_IP_ADDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_src_reg_id, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_SRC_REG_ID, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_SRC_REG_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_domain_id, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_DOMAIN_ID, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_store_ext_version, tvb, offset + O_LBMC_CNTL_UME_STORE_EXT_HDR_T_VERSION, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_VERSION, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_STORE_EXT_HDR_T);
}

static int dissect_nhdr_ume_psrc_election_token(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_ume_psrc_election_token, tvb, offset, L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_ume_psrc_election_token);
    proto_tree_add_item(subtree, hf_lbmc_ume_psrc_election_token_next_hdr, tvb, offset + O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_NEXT_HDR, L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_psrc_election_token_hdr_len, tvb, offset + O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_HDR_LEN, L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_ume_psrc_election_token_flags, tvb, offset + O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_FLAGS, L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_ume_psrc_election_token_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_ume_psrc_election_token_flags_ignore, tvb, offset + O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_FLAGS, L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_psrc_election_token_store_index, tvb, offset + O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_STORE_INDEX, L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_STORE_INDEX, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_ume_psrc_election_token_token, tvb, offset + O_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_TOKEN, L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_TOKEN, ENC_BIG_ENDIAN);
    return (L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T);
}

static int dissect_nhdr_tcp_sid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmc_tcp_sid_info_t * info)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    guint16 flags = 0;

    subtree_item = proto_tree_add_item(tree, hf_lbmc_tcp_sid, tvb, offset, L_LBMC_CNTL_TCP_SID_HDR_T, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_tcp_sid);
    proto_tree_add_item(subtree, hf_lbmc_tcp_sid_next_hdr, tvb, offset + O_LBMC_CNTL_TCP_SID_HDR_T_NEXT_HDR, L_LBMC_CNTL_TCP_SID_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tcp_sid_hdr_len, tvb, offset + O_LBMC_CNTL_TCP_SID_HDR_T_HDR_LEN, L_LBMC_CNTL_TCP_SID_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset + O_LBMC_CNTL_TCP_SID_HDR_T_FLAGS);
    flags_item = proto_tree_add_none_format(subtree, hf_lbmc_tcp_sid_flags, tvb, offset + O_LBMC_CNTL_TCP_SID_HDR_T_FLAGS, L_LBMC_CNTL_TCP_SID_HDR_T_FLAGS, "Flags: 0x%04x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_tcp_sid_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_tcp_sid_flags_ignore, tvb, offset + O_LBMC_CNTL_TCP_SID_HDR_T_FLAGS, L_LBMC_CNTL_TCP_SID_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_tcp_sid_sid, tvb, offset + O_LBMC_CNTL_TCP_SID_HDR_T_SID, L_LBMC_CNTL_TCP_SID_HDR_T_SID, ENC_BIG_ENDIAN);
    if (info != NULL)
    {
        info->set = TRUE;
        info->session_id = tvb_get_ntohl(tvb, offset + O_LBMC_CNTL_TCP_SID_HDR_T_SID);
    }
    return (L_LBMC_CNTL_TCP_SID_HDR_T);
}

static int dissect_nhdr_extopt_cfgopt(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    /*
        Returns number of bytes dissected (>=0), or -1 if an error occurs. In either case, *bytes_dissected
        will contain the number of bytes successfully dissected.
    */
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int curr_offset = offset;
    int len_dissected = 0;

    while (tvb_reported_length_remaining(tvb, curr_offset) > L_LBMC_EXTOPT_CFGOPT_HDR_T)
    {
        int name_offset = 0;
        int name_len = 0;
        int value_offset = 0;
        int value_len = 0;
        int optlen = L_LBMC_EXTOPT_CFGOPT_HDR_T;

        name_offset = curr_offset + L_LBMC_EXTOPT_CFGOPT_HDR_T;
        name_len = tvb_strsize(tvb, name_offset);
        optlen += name_len;
        value_offset = name_offset + name_len;
        value_len = tvb_strsize(tvb, value_offset);
        optlen += value_len;
        subtree_item = proto_tree_add_item(tree, hf_lbmc_extopt_cfgopt, tvb, curr_offset, optlen, ENC_NA);
        subtree = proto_item_add_subtree(subtree_item, ett_lbmc_extopt_cfgopt);
        proto_tree_add_item(subtree, hf_lbmc_extopt_cfgopt_scope, tvb, curr_offset + O_LBMC_EXTOPT_CFGOPT_HDR_T_SCOPE, L_LBMC_EXTOPT_CFGOPT_HDR_T_SCOPE, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_lbmc_extopt_cfgopt_parent, tvb, curr_offset + O_LBMC_EXTOPT_CFGOPT_HDR_T_PARENT, L_LBMC_EXTOPT_CFGOPT_HDR_T_PARENT, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_lbmc_extopt_cfgopt_name, tvb, name_offset, name_len, ENC_ASCII|ENC_NA);
        proto_tree_add_item(subtree, hf_lbmc_extopt_cfgopt_value, tvb, value_offset, value_len, ENC_ASCII|ENC_NA);
        curr_offset += optlen;
        len_dissected += optlen;
    }
    return (len_dissected);
}

static int dissect_nhdr_extopt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, lbmc_extopt_reassembled_data_t * reassembly)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    proto_item * flags_item = NULL;
    proto_tree * flags_tree = NULL;
    proto_item * ritem = NULL;
    proto_tree * rtree = NULL;
    guint8 flags = 0;
    int len_dissected = 0;
    int data_len = 0;
    guint16 subtype;
    guint16 fragment_offset;
    int data_offset;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_EXTOPT_HDR_T_HDR_LEN);
    flags = tvb_get_guint8(tvb, offset + O_LBMC_EXTOPT_HDR_T_FLAGS);
    subtype = tvb_get_ntohs(tvb, offset + O_LBMC_EXTOPT_HDR_T_SUBTYPE);
    fragment_offset = tvb_get_ntohs(tvb, offset + O_LBMC_EXTOPT_HDR_T_FRAGMENT_OFFSET);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_extopt, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_extopt);
    proto_tree_add_item(subtree, hf_lbmc_extopt_next_hdr, tvb, offset + O_LBMC_EXTOPT_HDR_T_NEXT_HDR, L_LBMC_EXTOPT_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_extopt_hdr_len, tvb, offset + O_LBMC_EXTOPT_HDR_T_HDR_LEN, L_LBMC_EXTOPT_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    flags_item = proto_tree_add_none_format(subtree,
        hf_lbmc_extopt_flags, tvb, offset + O_LBMC_EXTOPT_HDR_T_FLAGS, L_LBMC_EXTOPT_HDR_T_FLAGS, "Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbmc_extopt_flags);
    proto_tree_add_item(flags_tree, hf_lbmc_extopt_flags_ignore, tvb, offset + O_LBMC_EXTOPT_HDR_T_FLAGS, L_LBMC_EXTOPT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_extopt_flags_ignore_subtype, tvb, offset + O_LBMC_EXTOPT_HDR_T_FLAGS, L_LBMC_EXTOPT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbmc_extopt_flags_more_fragments, tvb, offset + O_LBMC_EXTOPT_HDR_T_FLAGS, L_LBMC_EXTOPT_HDR_T_FLAGS, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_extopt_id, tvb, offset + O_LBMC_EXTOPT_HDR_T_ID, L_LBMC_EXTOPT_HDR_T_ID, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_extopt_subtype, tvb, offset + O_LBMC_EXTOPT_HDR_T_SUBTYPE, L_LBMC_EXTOPT_HDR_T_SUBTYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lbmc_extopt_fragment_offset, tvb, offset + O_LBMC_EXTOPT_HDR_T_FRAGMENT_OFFSET, L_LBMC_EXTOPT_HDR_T_FRAGMENT_OFFSET, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_EXTOPT_HDR_T;
    data_len = (int)hdrlen - len_dissected;
    data_offset = offset + len_dissected;
    len_dissected += data_len;
    if ((flags & LBMC_EXTOPT_FLAG_MORE_FRAGMENT) == 0)
    {
        /* No more fragments. Do we have a reassembly already started? */
        if (reassembly->reassembly_in_progress)
        {
            tvbuff_t * reassembly_tvb;
            gchar * buf;
            proto_item * pi = NULL;

            tvb_memcpy(tvb, reassembly->data + fragment_offset, data_offset, data_len);
            reassembly->len += data_len;
            buf = (gchar *) wmem_memdup(wmem_file_scope(), reassembly->data, reassembly->len);
            reassembly_tvb = tvb_new_real_data(buf, reassembly->len, reassembly->len);
            add_new_data_source(pinfo, reassembly_tvb, "Reassembled EXTOPT fragment data");
            proto_tree_add_item(subtree, hf_lbmc_extopt_data, tvb, data_offset, data_len, ENC_NA);
            ritem = proto_tree_add_item(tree, hf_lbmc_extopt_reassembled_data, reassembly_tvb, 0, reassembly->len, ENC_NA);
            rtree = proto_item_add_subtree(ritem, ett_lbmc_extopt_reassembled_data);
            pi = proto_tree_add_uint(rtree, hf_lbmc_extopt_reassembled_data_subtype, reassembly_tvb, 0, 0, reassembly->subtype);
            PROTO_ITEM_SET_GENERATED(pi);
            pi = proto_tree_add_uint(rtree, hf_lbmc_extopt_reassembled_data_len, reassembly_tvb, 0, 0, (guint32)reassembly->len);
            PROTO_ITEM_SET_GENERATED(pi);
            switch (reassembly->subtype)
            {
                case LBMC_EXT_NHDR_MSGSEL:
                    proto_tree_add_item(rtree, hf_lbmc_extopt_reassembled_data_msgsel, reassembly_tvb, 0, reassembly->len, ENC_ASCII|ENC_NA);
                    break;
                case LBMC_EXT_NHDR_CFGOPT:
                    len_dissected += dissect_nhdr_extopt_cfgopt(reassembly_tvb, 0, pinfo, rtree);
                    break;
                default:
                    proto_tree_add_item(rtree, hf_lbmc_extopt_reassembled_data_data, reassembly_tvb, 0, reassembly->len, ENC_NA);
                    break;
            }
            lbmc_init_extopt_reassembled_data(reassembly);
        }
        else
        {
            switch (subtype)
            {
                case LBMC_EXT_NHDR_MSGSEL:
                    proto_tree_add_item(subtree, hf_lbmc_extopt_msgsel, tvb, data_offset, data_len, ENC_ASCII|ENC_NA);
                    break;
                case LBMC_EXT_NHDR_CFGOPT:
                    len_dissected += dissect_nhdr_extopt_cfgopt(tvb, data_offset, pinfo, subtree);
                    break;
                default:
                    proto_tree_add_item(subtree, hf_lbmc_extopt_data, tvb, data_offset, data_len, ENC_NA);
                    break;
            }
        }
    }
    else
    {
        /* Self-contained extended option. */
        if (reassembly->reassembly_in_progress)
        {
            tvb_memcpy(tvb, reassembly->data + fragment_offset, data_offset, data_len);
            reassembly->len += data_len;
            proto_tree_add_item(subtree, hf_lbmc_extopt_data, tvb, offset + len_dissected, data_len, ENC_NA);
        }
        else
        {
            reassembly->reassembly_in_progress = TRUE;
            reassembly->subtype = subtype;
            reassembly->len = 0;
            if (fragment_offset != 0)
            {
                expert_add_info_format(pinfo, NULL, &ei_lbmc_analysis_no_reassembly, "LBMC EXTOPT: reassembly not in progress but fragment_offset not zero (%" G_GUINT16_FORMAT ")", fragment_offset);
            }
            else
            {
                tvb_memcpy(tvb, reassembly->data + fragment_offset, data_offset, data_len);
                reassembly->len += data_len;
            }
            proto_tree_add_item(subtree, hf_lbmc_extopt_data, tvb, data_offset, data_len, ENC_NA);
        }
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_nhdr_unhandled(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 next_hdr)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 hdrlen = 0;
    int len_dissected = 0;
    int datalen = 0;
    proto_item * hdrlen_item = NULL;

    hdrlen = tvb_get_guint8(tvb, offset + O_LBMC_BASIC_HDR_T_HDR_LEN);
    subtree_item = proto_tree_add_item(tree, hf_lbmc_unhandled, tvb, offset, (gint)hdrlen, ENC_NA);
    subtree = proto_item_add_subtree(subtree_item, ett_lbmc_unhandled_hdr);
    expert_add_info_format(pinfo, subtree_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC header type 0x%02x", next_hdr);
    proto_tree_add_item(subtree, hf_lbmc_unhandled_next_hdr, tvb, offset + O_LBMC_UNHANDLED_HDR_T_NEXT_HDR, L_LBMC_UNHANDLED_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    hdrlen_item = proto_tree_add_item(subtree, hf_lbmc_unhandled_hdr_len, tvb, offset + O_LBMC_UNHANDLED_HDR_T_HDR_LEN, L_LBMC_UNHANDLED_HDR_T_HDR_LEN, ENC_BIG_ENDIAN);
    len_dissected = L_LBMC_UNHANDLED_HDR_T_NEXT_HDR + L_LBMC_UNHANDLED_HDR_T_HDR_LEN;
    datalen = (int) hdrlen - len_dissected;
    if (datalen > 0)
    {
        proto_tree_add_item(subtree, hf_lbmc_unhandled_data, tvb, offset + O_LBMC_UNHANDLED_HDR_T_HDR_LEN + L_LBMC_UNHANDLED_HDR_T_HDR_LEN, datalen, ENC_NA);
        len_dissected += datalen;
    }
    else
    {
        expert_add_info(pinfo, hdrlen_item, &ei_lbmc_analysis_length_incorrect);
    }
    proto_item_set_len(subtree_item, len_dissected);
    return (len_dissected);
}

static int dissect_msg_properties(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * data_item = NULL;
    proto_tree * data_tree = NULL;
    proto_item * field_item = NULL;
    proto_tree * field_tree = NULL;
    proto_item * vertype_item = NULL;
    proto_tree * vertype_tree = NULL;
    guint32 magic;
    guint32 * magic_ptr = NULL;
    char magic_char[4];
    guint16 num_fields;
    guint16 idx;
    guint encoding;
    int field_offset;
    int data_length;
    proto_item * magic_item = NULL;

    tvb_memcpy(tvb, (void *)magic_char, offset + O_LBM_MSG_PROPERTIES_DATA_T_MAGIC, 4);
    magic_ptr = (guint32 *)magic_char;
    magic = *magic_ptr;
    encoding = ENC_LITTLE_ENDIAN;
    if (magic == LBM_MSG_PROPERTIES_MAGIC)
    {
        encoding = ENC_LITTLE_ENDIAN;
    }
    else if (magic == LBM_MSG_PROPERTIES_ANTIMAGIC)
    {
        encoding = ENC_BIG_ENDIAN;
    }
    else
    {
        magic = 0xffffffff;
    }
    data_length = tvb_reported_length_remaining(tvb, offset);
    subtree_item = proto_tree_add_item(tree, hf_lbm_msg_properties, tvb, offset, data_length, encoding);
    subtree = proto_item_add_subtree(subtree_item, ett_lbm_msg_properties);
    data_item = proto_tree_add_item(subtree, hf_lbm_msg_properties_data, tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_MAGIC, L_LBM_MSG_PROPERTIES_DATA_T, encoding);
    data_tree = proto_item_add_subtree(data_item, ett_lbm_msg_properties_data);
    magic_item = proto_tree_add_item(data_tree, hf_lbm_msg_properties_data_magic, tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_MAGIC, L_LBM_MSG_PROPERTIES_DATA_T_MAGIC, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_lbm_msg_properties_data_num_fields, tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_NUM_FIELDS, L_LBM_MSG_PROPERTIES_DATA_T_NUM_FIELDS, encoding);
    vertype_item = proto_tree_add_item(data_tree, hf_lbm_msg_properties_data_vertype, tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_VERTYPE, L_LBM_MSG_PROPERTIES_DATA_T_VERTYPE, encoding);
    vertype_tree = proto_item_add_subtree(vertype_item, ett_lbm_msg_properties_data_vertype);
    proto_tree_add_item(vertype_tree, hf_lbm_msg_properties_data_vertype_version, tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_VERTYPE, L_LBM_MSG_PROPERTIES_DATA_T_VERTYPE, encoding);
    proto_tree_add_item(vertype_tree, hf_lbm_msg_properties_data_vertype_type, tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_VERTYPE, L_LBM_MSG_PROPERTIES_DATA_T_VERTYPE, encoding);
    proto_tree_add_item(data_tree, hf_lbm_msg_properties_data_res, tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_RES, L_LBM_MSG_PROPERTIES_DATA_T_RES, encoding);
    if ((magic != LBM_MSG_PROPERTIES_MAGIC) && (magic != LBM_MSG_PROPERTIES_ANTIMAGIC))
    {
        expert_add_info_format(pinfo, magic_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC Message Properties MAGIC value");
        return (L_LBM_MSG_PROPERTIES_DATA_T);
    }
    if (encoding == ENC_LITTLE_ENDIAN)
    {
        num_fields = tvb_get_letohs(tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_NUM_FIELDS);
    }
    else
    {
        num_fields = tvb_get_ntohs(tvb, offset + O_LBM_MSG_PROPERTIES_DATA_T_NUM_FIELDS);
    }
    field_offset = offset + L_LBM_MSG_PROPERTIES_DATA_T;
    for (idx = 0; idx < num_fields; ++idx)
    {
        guint32 key_offset;
        guint32 value_offset;
        guint32 type;
        int actual_key_offset;
        int actual_value_offset;
        int key_len;
        int value_len;
        proto_item * type_item = NULL;

        if (encoding == ENC_LITTLE_ENDIAN)
        {
            key_offset = tvb_get_letohl(tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_KEY_OFFSET);
            value_offset = tvb_get_letohl(tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_VALUE_OFFSET);
            type = tvb_get_letohl(tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_TYPE);
        }
        else
        {
            key_offset = tvb_get_ntohl(tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_KEY_OFFSET);
            value_offset = tvb_get_ntohl(tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_VALUE_OFFSET);
            type = tvb_get_ntohl(tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_TYPE);
        }
        actual_key_offset = (int) key_offset;
        actual_value_offset = (int) value_offset;
        field_item = proto_tree_add_item(subtree, hf_lbm_msg_properties_hdr, tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_KEY_OFFSET, L_LBM_MSG_PROPERTIES_HDR_T, encoding);
        field_tree = proto_item_add_subtree(field_item, ett_lbm_msg_properties_hdr);
        proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_key_offset, tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_KEY_OFFSET, L_LBM_MSG_PROPERTIES_HDR_T_KEY_OFFSET, encoding);
        proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_value_offset, tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_VALUE_OFFSET, L_LBM_MSG_PROPERTIES_HDR_T_VALUE_OFFSET, encoding);
        proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_hash, tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_HASH, L_LBM_MSG_PROPERTIES_HDR_T_HASH, encoding);
        type_item = proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_type, tvb, field_offset + O_LBM_MSG_PROPERTIES_HDR_T_TYPE, L_LBM_MSG_PROPERTIES_HDR_T_TYPE, encoding);
        switch (type)
        {
            case LBM_MSG_PROPERTY_BOOLEAN:
            case LBM_MSG_PROPERTY_BYTE:
                value_len = 1;
                break;
            case LBM_MSG_PROPERTY_SHORT:
                value_len = 2;
                break;
            case LBM_MSG_PROPERTY_INT:
            case LBM_MSG_PROPERTY_FLOAT:
                value_len = 4;
                break;
            case LBM_MSG_PROPERTY_LONG:
            case LBM_MSG_PROPERTY_DOUBLE:
                value_len = 8;
                break;
            case LBM_MSG_PROPERTY_STRING:
                value_len = (int)tvb_strsize(tvb, actual_value_offset);
                break;
            default:
                expert_add_info_format(pinfo, type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC Message Properties type 0x%08x", type);
                value_len = 4;
                break;
        }
        key_len = (int)tvb_strsize(tvb, actual_key_offset);
        proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_key, tvb, offset + actual_key_offset, key_len, encoding);
        switch (type)
        {
            case LBM_MSG_PROPERTY_BOOLEAN:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_boolean_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
            case LBM_MSG_PROPERTY_BYTE:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_byte_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
            case LBM_MSG_PROPERTY_SHORT:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_short_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
            case LBM_MSG_PROPERTY_INT:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_int_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
            case LBM_MSG_PROPERTY_FLOAT:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_float_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
            case LBM_MSG_PROPERTY_LONG:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_long_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
            case LBM_MSG_PROPERTY_DOUBLE:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_double_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
            case LBM_MSG_PROPERTY_STRING:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_string_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
            default:
                proto_tree_add_item(field_tree, hf_lbm_msg_properties_hdr_unknown_value, tvb, offset + actual_value_offset, value_len, encoding);
                break;
        }
        field_offset += L_LBM_MSG_PROPERTIES_HDR_T;
    }
    return (data_length);
}

/*----------------------------------------------------------------------------*/
/* Miscellaneous functions.                                                   */
/*----------------------------------------------------------------------------*/
static const gchar * lbmc_determine_msg_type(const guint8 * header_array)
{
    if (header_array[LBMC_NHDR_SSF_INIT] != 0)
    {
        return ((gchar *)"SSF-INIT");
    }
    else if (header_array[LBMC_NHDR_SSF_CREQ] != 0)
    {
        return ((gchar *)"SSF-CREQ");
    }
    else if (header_array[LBMC_NHDR_UME_PREG] != 0)
    {
        return ((gchar *)"PREG");
    }
    else if (header_array[LBMC_NHDR_UME_PREG_RESP] != 0)
    {
        return ((gchar *)"PREG-RESP");
    }
    else if (header_array[LBMC_NHDR_UME_ACK] != 0)
    {
        return ((gchar *)"ACK");
    }
    else if (header_array[LBMC_NHDR_UME_RXREQ] != 0)
    {
        return ((gchar *)"RXREQ");
    }
    else if (header_array[LBMC_NHDR_UME_KEEPALIVE] != 0)
    {
        return ((gchar *)"UME-KA");
    }
    else if (header_array[LBMC_NHDR_UME_CAPABILITY] != 0)
    {
        return ((gchar *)"UME-CAP");
    }
    else if (header_array[LBMC_NHDR_TSNI] != 0)
    {
        return ((gchar *)"TSNI");
    }
    else if (header_array[LBMC_NHDR_UMQ_REG] != 0)
    {
        return ((gchar *)"UMQ-REG");
    }
    else if (header_array[LBMC_NHDR_UMQ_REG_RESP] != 0)
    {
        return ((gchar *)"UMQ-REG-RSP");
    }
    else if (header_array[LBMC_NHDR_UMQ_ACK] != 0)
    {
        return ((gchar *)"UMQ-ACK");
    }
    else if (header_array[LBMC_NHDR_UMQ_KA] != 0)
    {
        return ((gchar *)"UMQ-KA");
    }
    else if (header_array[LBMC_NHDR_UMQ_RCR] != 0)
    {
        return ((gchar *)"UMQ-RCR");
    }
    else if (header_array[LBMC_NHDR_UMQ_RXREQ] != 0)
    {
        return ((gchar *)"UMQ-RXREQ");
    }
    else if (header_array[LBMC_NHDR_UMQ_QMGMT] != 0)
    {
        return ((gchar *)"UMQ-QMGMT");
    }
    else if (header_array[LBMC_NHDR_UME_LJ_INFO] != 0)
    {
        return ((gchar *)"LJINFO");
    }
    else if (header_array[LBMC_NHDR_UMQ_RESUB_REQ] != 0)
    {
        return ((gchar *)"UMQ-RESUB-REQ");
    }
    else if (header_array[LBMC_NHDR_UMQ_RESUB_RESP] != 0)
    {
        return ((gchar *)"UMQ-RESUB-RESP");
    }
    else if (header_array[LBMC_NHDR_TOPIC_INTEREST] != 0)
    {
        return ((gchar *)"TOPIC-INT");
    }
    else if (header_array[LBMC_NHDR_PATTERN_INTEREST] != 0)
    {
        return ((gchar *)"PAT-INT");
    }
    else if (header_array[LBMC_NHDR_ADVERTISEMENT] != 0)
    {
        return ((gchar *)"AD");
    }
    else if (header_array[LBMC_NHDR_UMQ_ULB_RCR] != 0)
    {
        return ((gchar *)"UMQ-ULB-RCR");
    }
    else if (header_array[LBMC_NHDR_UMQ_LF] != 0)
    {
        return ((gchar *)"UMQ-LF");
    }
    else if (header_array[LBMC_NHDR_CTXINFO] != 0)
    {
        return ((gchar *)"CTXINFO");
    }
    else if (header_array[LBMC_NHDR_UME_PSER] != 0)
    {
        return ((gchar *)"PSER");
    }
    else if (header_array[LBMC_NHDR_DOMAIN] != 0)
    {
        return ((gchar *)"DOMAIN");
    }
    else if (header_array[LBMC_NHDR_TNWG_CAPABILITIES] != 0)
    {
        return ((gchar *)"TNWG_CAP");
    }
    else if (header_array[LBMC_NHDR_PATIDX] != 0)
    {
        return ((gchar *)"PATIDX");
    }
    else if (header_array[LBMC_NHDR_UMQ_IDX_CMD] != 0)
    {
        return ((gchar *)"UMQ-IDX-CMD");
    }
    else if (header_array[LBMC_NHDR_UMQ_IDX_CMD_RESP] != 0)
    {
        return ((gchar *)"UMQ-IDX-CMD-RESP");
    }
    else if (header_array[LBMC_NHDR_TOPIC_MD_INTEREST] != 0)
    {
        return ((gchar *)"TOPIC-MD-INT");
    }
    else if (header_array[LBMC_NHDR_PATTERN_MD_INTEREST] != 0)
    {
        return ((gchar *)"PAT-MD-INT");
    }
    else if (header_array[LBMC_NHDR_LJI_REQ] != 0)
    {
        return ((gchar *)"LJI-REQ");
    }
    else if (header_array[LBMC_NHDR_TNWG_KA] != 0)
    {
        return ((gchar *)"TNWG-KA");
    }
    else if (header_array[LBMC_NHDR_AUTHENTICATION] != 0)
    {
        return ((gchar *)"AUTH");
    }
    else if (header_array[LBMC_NHDR_UME_RCV_KEEPALIVE] != 0)
    {
        return ((gchar *)"UME-RCV-KA");
    }
    else if (header_array[LBMC_NHDR_UMQ_CMD] != 0)
    {
        return ((gchar *)"UMQ-CMD");
    }
    else if (header_array[LBMC_NHDR_UMQ_CMD_RESP] != 0)
    {
        return ((gchar *)"UMQ-CMD-RESP");
    }
    else if (header_array[LBMC_NHDR_EXTOPT] != 0)
    {
        return ((gchar *)"EXTOPT");
    }
    else if (header_array[LBMC_NHDR_HMAC] != 0)
    {
        return ((gchar *)"HMAC");
    }
    else if (header_array[LBMC_NHDR_SRI_REQ] != 0)
    {
        return ((gchar *)"SRI-REQ");
    }
    else if (header_array[LBMC_NHDR_SRI] != 0)
    {
        return ((gchar *)"SRI");
    }
    else if (header_array[LBMC_NHDR_UME_PSRC_ELECTION_TOKEN] != 0)
    {
        return ((gchar *)"PSRC-ETOK");
    }
    else if (header_array[LBMC_NHDR_TOPIC_SOURCE_EXFUNC] != 0)
    {
        return ((gchar *)"TOPIC-SRC-EX");
    }
    else if (header_array[LBMC_NHDR_ROUTE_INFO] != 0)
    {
        return ((gchar *)"RTE-INFO");
    }
    else if (header_array[LBMC_NHDR_TCP_SID] != 0)
    {
        return ((gchar *)"TCP-SID");
    }
    return (NULL);
}

static lbm_uim_stream_info_t * lbmc_dup_stream_info(const lbm_uim_stream_info_t * info)
{
    /* Returns a packet-scoped copy. */
    lbm_uim_stream_info_t * ptr = NULL;

    ptr = wmem_new(wmem_packet_scope(), lbm_uim_stream_info_t);
    ptr->channel = info->channel;
    ptr->sqn = info->sqn;
    ptr->endpoint_a.type = info->endpoint_a.type;
    if (ptr->endpoint_a.type == lbm_uim_instance_stream)
    {
        memcpy((void *)ptr->endpoint_a.stream_info.ctxinst.ctxinst, (void *)info->endpoint_a.stream_info.ctxinst.ctxinst, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
    }
    else
    {
        ptr->endpoint_a.stream_info.dest = info->endpoint_a.stream_info.dest;
    }
    ptr->endpoint_b.type = info->endpoint_b.type;
    if (ptr->endpoint_b.type == lbm_uim_instance_stream)
    {
        memcpy((void *)ptr->endpoint_b.stream_info.ctxinst.ctxinst, (void *)info->endpoint_b.stream_info.ctxinst.ctxinst, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
    }
    else
    {
        ptr->endpoint_b.stream_info.dest = info->endpoint_b.stream_info.dest;
    }
    ptr->description = wmem_strdup(wmem_packet_scope(), info->description);
    return (ptr);
}

gboolean lbmc_test_lbmc_header(tvbuff_t * tvb, int offset)
{
    guint8 type;
    guint8 version;
    guint8 ver_type;
    guint8 next_header;
    guint16 msglen;

    if (tvb_reported_length_remaining(tvb, offset) < (O_LBMC_HDR_T_MSGLEN + L_LBMC_HDR_T_MSGLEN))
    {
        return (FALSE);
    }
    ver_type = tvb_get_guint8(tvb, offset + O_LBMC_HDR_T_VER_TYPE);
    version = LBMC_HDR_VER(ver_type);
    type = LBMC_HDR_TYPE(ver_type);
    if (version != LBMC_VERSION)
    {
        return (FALSE);
    }
    switch (type)
    {
        case LBMC_TYPE_MESSAGE:
        case LBMC_TYPE_PRORX:
        case LBMC_TYPE_EOT:
        case LBMC_TYPE_CONTROL:
        case LBMC_TYPE_RETRANS:
            break;
        default:
            return (FALSE);
    }
    next_header = tvb_get_guint8(tvb, offset + O_LBMC_HDR_T_NEXT_HDR);
    switch (next_header)
    {
        case LBMC_NHDR_DATA:
        case LBMC_NHDR_FRAG:
        case LBMC_NHDR_BATCH:
        case LBMC_NHDR_TGIDX:
        case LBMC_NHDR_REQUEST:
        case LBMC_NHDR_TOPICNAME:
        case LBMC_NHDR_APPHDR:
        case LBMC_NHDR_APPHDR_CHAIN:
        case LBMC_NHDR_UMQ_MSGID:
        case LBMC_NHDR_UMQ_SQD_RCV:
        case LBMC_NHDR_UMQ_RESUB:
        case LBMC_NHDR_OTID:
        case LBMC_NHDR_CTXINSTD:
        case LBMC_NHDR_CTXINSTR:
        case LBMC_NHDR_SRCIDX:
        case LBMC_NHDR_UMQ_ULB_MSG:
        case LBMC_NHDR_SSF_INIT:
        case LBMC_NHDR_SSF_CREQ:
        case LBMC_NHDR_UME_PREG:
        case LBMC_NHDR_UME_PREG_RESP:
        case LBMC_NHDR_UME_ACK:
        case LBMC_NHDR_UME_RXREQ:
        case LBMC_NHDR_UME_KEEPALIVE:
        case LBMC_NHDR_UME_STOREID:
        case LBMC_NHDR_UME_RANGED_ACK:
        case LBMC_NHDR_UME_ACK_ID:
        case LBMC_NHDR_UME_CAPABILITY:
        case LBMC_NHDR_UME_PROXY_SRC:
        case LBMC_NHDR_UME_STORE_GROUP:
        case LBMC_NHDR_UME_STORE_INFO:
        case LBMC_NHDR_UME_LJ_INFO:
        case LBMC_NHDR_TSNI:
        case LBMC_NHDR_UMQ_REG:
        case LBMC_NHDR_UMQ_REG_RESP:
        case LBMC_NHDR_UMQ_ACK:
        case LBMC_NHDR_UMQ_RCR:
        case LBMC_NHDR_UMQ_KA:
        case LBMC_NHDR_UMQ_RXREQ:
        case LBMC_NHDR_UMQ_QMGMT:
        case LBMC_NHDR_UMQ_RESUB_REQ:
        case LBMC_NHDR_UMQ_RESUB_RESP:
        case LBMC_NHDR_TOPIC_INTEREST:
        case LBMC_NHDR_PATTERN_INTEREST:
        case LBMC_NHDR_ADVERTISEMENT:
        case LBMC_NHDR_UME_CTXINSTS:
        case LBMC_NHDR_UME_STORENAME:
        case LBMC_NHDR_UMQ_ULB_RCR:
        case LBMC_NHDR_UMQ_LF:
        case LBMC_NHDR_CTXINFO:
        case LBMC_NHDR_UME_PSER:
        case LBMC_NHDR_CTXINST:
        case LBMC_NHDR_DOMAIN:
        case LBMC_NHDR_TNWG_CAPABILITIES:
        case LBMC_NHDR_PATIDX:
        case LBMC_NHDR_UME_CLIENT_LIFETIME:
        case LBMC_NHDR_UME_SID:
        case LBMC_NHDR_UMQ_IDX_CMD:
        case LBMC_NHDR_UMQ_IDX_CMD_RESP:
        case LBMC_NHDR_ODOMAIN:
        case LBMC_NHDR_STREAM:
        case LBMC_NHDR_TOPIC_MD_INTEREST:
        case LBMC_NHDR_PATTERN_MD_INTEREST:
        case LBMC_NHDR_LJI_REQ:
        case LBMC_NHDR_TNWG_KA:
        case LBMC_NHDR_UME_RCV_KEEPALIVE:
        case LBMC_NHDR_UMQ_CMD:
        case LBMC_NHDR_UMQ_CMD_RESP:
        case LBMC_NHDR_SRI_REQ:
        case LBMC_NHDR_UME_STORE_DOMAIN:
        case LBMC_NHDR_SRI:
        case LBMC_NHDR_ROUTE_INFO:
        case LBMC_NHDR_ROUTE_INFO_NEIGHBOR:
        case LBMC_NHDR_GATEWAY_NAME:
        case LBMC_NHDR_AUTHENTICATION:
        case LBMC_NHDR_HMAC:
        case LBMC_NHDR_UMQ_SID:
        case LBMC_NHDR_DESTINATION:
        case LBMC_NHDR_TOPIC_IDX:
        case LBMC_NHDR_TOPIC_SOURCE:
        case LBMC_NHDR_TOPIC_SOURCE_EXFUNC:
        case LBMC_NHDR_UME_STORE_INFO_EXT:
        case LBMC_NHDR_UME_PSRC_ELECTION_TOKEN:
        case LBMC_NHDR_TCP_SID:
        case LBMC_NHDR_EXTOPT:
            break;
        default:
            return (FALSE);
    }
    msglen = tvb_get_ntohs(tvb, offset + O_LBMC_HDR_T_MSGLEN);
    if (msglen == 0)
    {
        return (FALSE);
    }
    return (TRUE);
}

int lbmc_dissect_lbmc_packet(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, const char * tag_name, guint64 channel)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    guint8 type;
    guint8 version;
    guint8 ver_type;
    guint8 next_hdr;
    guint16 msglen = 0;
    int pkt_offset = 0;
    lbmc_basic_hdr_t bhdr;
    tvbuff_t * lbmc_tvb = NULL;
    int tvb_lbmc_offset = offset;
    const char * topic_name = NULL;
    guint32 topic_index = 0;
    int len_dissected = 0;
    int lbmc_hdr_len;
    proto_item * ver_type_item = NULL;
    proto_tree * ver_type_tree = NULL;
    guint32 msgprop_len = 0;
    lbmc_fragment_info_t frag_info;
    lbmc_extopt_reassembled_data_t reassembly;
    gboolean data_is_umq_cmd_resp;
    gboolean packet_is_data;
    lbmc_stream_info_t stream_info;
    lbmc_ctxinst_info_t ctxinstd_info;
    lbmc_ctxinst_info_t ctxinstr_info;
    lbmc_destination_info_t destination_info;
    lbm_istream_entry_t * inst_stream;
    lbm_istream_substream_entry_t * inst_substream;
    lbm_dstream_entry_t * dom_stream;
    lbm_dstream_substream_entry_t * dom_substream;
    proto_item * last_initial_item = NULL;
    guint8 found_header[256];
    lbm_uim_stream_info_t uim_stream_info;
    lbm_uim_stream_info_t * puim_stream_info = NULL;
    lbmc_tcp_sid_info_t tcp_sid_info;
    gboolean has_source_index;
    address tcp_addr;
    guint16 tcp_port = 0;
    guint64 actual_channel = channel;
    gboolean tcp_address_valid = FALSE;

    while (tvb_reported_length_remaining(tvb, tvb_lbmc_offset) >= L_LBMC_MINIMAL_HDR_T)
    {
        proto_item * type_item = NULL;

        /* Get the version and type. */
        ver_type = tvb_get_guint8(tvb, tvb_lbmc_offset + O_LBMC_HDR_T_VER_TYPE);
        version = LBMC_HDR_VER(ver_type);
        type = LBMC_HDR_TYPE(ver_type);
        /* Get the message length. */
        msglen = tvb_get_ntohs(tvb, tvb_lbmc_offset + O_LBMC_MINIMAL_HDR_T_MSGLEN);
        if (msglen == 0)
        {
            expert_add_info_format(pinfo, NULL, &ei_lbmc_analysis_zero_length, "LBMC packet header length is zero");
            return (len_dissected);
        }
        /* Create a new tvb for just this LBMC message. */
        lbmc_tvb = tvb_new_subset_length(tvb, tvb_lbmc_offset, (gint)msglen);
        if ((type == LBMC_TYPE_MESSAGE) || (type == LBMC_TYPE_RETRANS) || (type == LBMC_TYPE_PRORX))
        {
            topic_index = tvb_get_ntohl(lbmc_tvb, O_LBMC_HDR_T_TIDX);
            if (lbm_channel_is_transport(channel) && lbm_channel_is_known(channel))
            {
                topic_name = lbm_topic_find(channel, topic_index);
            }
            lbmc_hdr_len = L_LBMC_HDR_T;
        }
        else
        {
            lbmc_hdr_len = L_LBMC_CNTL_HDR_T;
        }

        if (topic_name == NULL)
        {
            if (tag_name == NULL)
            {
                subtree_item = proto_tree_add_protocol_format(tree, proto_lbmc, lbmc_tvb, 0, tvb_reported_length_remaining(tvb, 0), "LBMC Protocol");
            }
            else
            {
                subtree_item = proto_tree_add_protocol_format(tree, proto_lbmc, lbmc_tvb, 0, tvb_reported_length_remaining(tvb, 0), "LBMC Protocol (Tag: %s)", tag_name);
            }
        }
        else
        {
            if (tag_name == NULL)
            {
                subtree_item = proto_tree_add_protocol_format(tree, proto_lbmc, lbmc_tvb, 0, tvb_reported_length_remaining(tvb, 0), "LBMC Protocol for topic [%s]", topic_name);
            }
            else
            {
                subtree_item = proto_tree_add_protocol_format(tree, proto_lbmc, lbmc_tvb, 0, tvb_reported_length_remaining(tvb, 0), "LBMC Protocol (Tag: %s) for topic [%s]", tag_name, topic_name);
            }
        }
        subtree = proto_item_add_subtree(subtree_item, ett_lbmc);
        if (tag_name != NULL)
        {
            proto_item * pi = NULL;

            pi = proto_tree_add_string(subtree, hf_lbmc_tag, tvb, 0, 0, tag_name);
            PROTO_ITEM_SET_GENERATED(pi);
        }
        if (topic_name != NULL)
        {
            proto_item * pi = NULL;

            pi = proto_tree_add_string(subtree, hf_lbmc_topic, tvb, 0, 0, topic_name);
            PROTO_ITEM_SET_GENERATED(pi);
        }
        ver_type_item = proto_tree_add_none_format(subtree,
            hf_lbmc_ver_type,
            lbmc_tvb,
            O_LBMC_HDR_T_VER_TYPE,
            L_LBMC_HDR_T_VER_TYPE,
            "Version/Type: 0x%02x (Version:%u, Type:%s)",
            ver_type,
            version,
            val_to_str(type, lbmc_message_type, "Unknown (0x%02x)"));
        ver_type_tree = proto_item_add_subtree(ver_type_item, ett_lbmc_ver_type);
        proto_tree_add_item(ver_type_tree, hf_lbmc_ver_type_version, lbmc_tvb, O_LBMC_HDR_T_VER_TYPE, L_LBMC_HDR_T_VER_TYPE, ENC_BIG_ENDIAN);
        type_item = proto_tree_add_item(ver_type_tree, hf_lbmc_ver_type_type, lbmc_tvb, O_LBMC_HDR_T_VER_TYPE, L_LBMC_HDR_T_VER_TYPE, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_lbmc_next_hdr, lbmc_tvb, O_LBMC_HDR_T_NEXT_HDR, L_LBMC_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
        last_initial_item = proto_tree_add_item(subtree, hf_lbmc_msglen, lbmc_tvb, O_LBMC_HDR_T_MSGLEN, L_LBMC_HDR_T_MSGLEN, ENC_BIG_ENDIAN);
        len_dissected += (L_LBMC_HDR_T_VER_TYPE + L_LBMC_HDR_T_NEXT_HDR + L_LBMC_HDR_T_MSGLEN);
        switch (type)
        {
            case LBMC_TYPE_EOT:
            case LBMC_TYPE_CONTROL:
                packet_is_data = FALSE;
                break;
            case LBMC_TYPE_MESSAGE:
            case LBMC_TYPE_RETRANS:
            case LBMC_TYPE_PRORX:
                packet_is_data = TRUE;
                break;
            default:
                expert_add_info_format(pinfo, type_item, &ei_lbmc_analysis_invalid_value, "Invalid LBMC type 0x%02x", type);
                tvb_lbmc_offset += msglen;
                len_dissected += (msglen - (L_LBMC_HDR_T_VER_TYPE + L_LBMC_HDR_T_NEXT_HDR + L_LBMC_HDR_T_MSGLEN));
                continue;
                break;
        }
        next_hdr = tvb_get_guint8(lbmc_tvb, O_LBMC_HDR_T_NEXT_HDR);
        pkt_offset = lbmc_hdr_len;
        if ((type == LBMC_TYPE_MESSAGE) || (type == LBMC_TYPE_RETRANS) || (type == LBMC_TYPE_PRORX))
        {
            proto_tree_add_item(subtree, hf_lbmc_tidx, lbmc_tvb, O_LBMC_HDR_T_TIDX, L_LBMC_HDR_T_TIDX, ENC_BIG_ENDIAN);
            last_initial_item = proto_tree_add_item(subtree, hf_lbmc_sqn, lbmc_tvb, O_LBMC_HDR_T_SQN, L_LBMC_HDR_T_SQN, ENC_BIG_ENDIAN);
        }
        frag_info.fragment_found = 0;
        frag_info.first_sqn = 0;
        frag_info.offset = 0;
        frag_info.len = 0;
        msgprop_len = 0;
        lbmc_init_extopt_reassembled_data(&reassembly);
        data_is_umq_cmd_resp = FALSE;
        stream_info.set = FALSE;
        ctxinstd_info.set = FALSE;
        ctxinstr_info.set = FALSE;
        destination_info.set = FALSE;
        inst_stream = NULL;
        inst_substream = NULL;
        dom_stream = NULL;
        dom_substream = NULL;
        memset((void *)found_header, 0, sizeof(found_header));
        puim_stream_info = NULL;
        tcp_sid_info.set = FALSE;
        has_source_index = FALSE;

        while ((tvb_reported_length_remaining(lbmc_tvb, pkt_offset) >= L_LBMC_BASIC_HDR_T) && (next_hdr != LBMC_NHDR_DATA) && (next_hdr != LBMC_NHDR_NONE))
        {
            tvbuff_t * hdr_tvb = NULL;
            int dissected_hdr_len;
            guint8 opid;

            bhdr.next_hdr = tvb_get_guint8(lbmc_tvb, pkt_offset + O_LBMC_BASIC_HDR_T_NEXT_HDR);
            bhdr.hdr_len = tvb_get_guint8(lbmc_tvb, pkt_offset + O_LBMC_BASIC_HDR_T_HDR_LEN);
            if (bhdr.hdr_len == 0)
            {
                expert_add_info_format(pinfo, NULL, &ei_lbmc_analysis_zero_length, "LBMC header length is zero");
                return (len_dissected);
            }
            hdr_tvb = tvb_new_subset_length(lbmc_tvb, pkt_offset, (gint)bhdr.hdr_len);
            found_header[next_hdr] = 1;
            switch (next_hdr)
            {
                case LBMC_NHDR_FRAG:
                    dissected_hdr_len = dissect_nhdr_frag(hdr_tvb, 0, pinfo, subtree, &frag_info);
                    break;
                case LBMC_NHDR_BATCH:
                    dissected_hdr_len = dissect_nhdr_batch(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TGIDX:
                    /* Not implemented */
                    dissected_hdr_len = dissect_nhdr_unhandled(hdr_tvb, 0, pinfo, subtree, next_hdr);
                    break;
                case LBMC_NHDR_REQUEST:
                    dissected_hdr_len = dissect_nhdr_request(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TOPICNAME:
                    dissected_hdr_len = dissect_nhdr_topicname(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_APPHDR:
                    dissected_hdr_len = dissect_nhdr_apphdr(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_APPHDR_CHAIN:
                    dissected_hdr_len = dissect_nhdr_apphdr_chain(hdr_tvb, 0, pinfo, subtree, &msgprop_len);
                    break;
                case LBMC_NHDR_UMQ_MSGID:
                    dissected_hdr_len = dissect_nhdr_umq_msgid(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_SQD_RCV:
                    dissected_hdr_len = dissect_nhdr_umq_sqd_rcv(hdr_tvb, 0, pinfo, subtree, &data_is_umq_cmd_resp);
                    break;
                case LBMC_NHDR_UMQ_RESUB:
                    dissected_hdr_len = dissect_nhdr_umq_resub(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_OTID:
                    dissected_hdr_len = dissect_nhdr_otid(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_CTXINSTD:
                    dissected_hdr_len = dissect_nhdr_ctxinstd(hdr_tvb, 0, pinfo, subtree, &ctxinstd_info);
                    break;
                case LBMC_NHDR_CTXINSTR:
                    dissected_hdr_len = dissect_nhdr_ctxinstr(hdr_tvb, 0, pinfo, subtree, &ctxinstr_info);
                    break;
                case LBMC_NHDR_SRCIDX:
                    dissected_hdr_len = dissect_nhdr_srcidx(hdr_tvb, 0, pinfo, subtree);
                    has_source_index = TRUE;
                    break;
                case LBMC_NHDR_UMQ_ULB_MSG:
                    dissected_hdr_len = dissect_nhdr_umq_ulb_msg(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_SSF_INIT:
                    dissected_hdr_len = dissect_nhdr_ssf_init(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_SSF_CREQ:
                    dissected_hdr_len = dissect_nhdr_ssf_creq(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_PREG:
                    dissected_hdr_len = dissect_nhdr_ume_preg(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_PREG_RESP:
                    dissected_hdr_len = dissect_nhdr_ume_preg_resp(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_ACK:
                    dissected_hdr_len = dissect_nhdr_ume_ack(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_RXREQ:
                    dissected_hdr_len = dissect_nhdr_ume_rxreq(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_KEEPALIVE:
                    dissected_hdr_len = dissect_nhdr_ume_keepalive(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_STOREID:
                    dissected_hdr_len = dissect_nhdr_ume_storeid(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_RANGED_ACK:
                    dissected_hdr_len = dissect_nhdr_ume_ranged_ack(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_ACK_ID:
                    dissected_hdr_len = dissect_nhdr_ume_ack_id(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_CAPABILITY:
                    dissected_hdr_len = dissect_nhdr_ume_capability(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_PROXY_SRC:
                    dissected_hdr_len = dissect_nhdr_ume_proxy_src(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_STORE_GROUP:
                    dissected_hdr_len = dissect_nhdr_ume_store_group(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_STORE_INFO:
                    dissected_hdr_len = dissect_nhdr_ume_store(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_LJ_INFO:
                    dissected_hdr_len = dissect_nhdr_ume_lj_info(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TSNI:
                    dissected_hdr_len = dissect_nhdr_tsni(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_REG:
                    dissected_hdr_len = dissect_nhdr_umq_reg(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_REG_RESP:
                    dissected_hdr_len = dissect_nhdr_umq_reg_resp(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_ACK:
                    dissected_hdr_len = dissect_nhdr_umq_ack(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_RCR:
                    dissected_hdr_len = dissect_nhdr_umq_rcr(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_KA:
                    dissected_hdr_len = dissect_nhdr_umq_ka(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_RXREQ:
                    dissected_hdr_len = dissect_nhdr_umq_rxreq(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_QMGMT:
                    dissected_hdr_len = dissect_nhdr_umq_qmgmt(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_RESUB_REQ:
                    dissected_hdr_len = dissect_nhdr_umq_resub_req(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_RESUB_RESP:
                    dissected_hdr_len = dissect_nhdr_umq_resub_resp(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TOPIC_INTEREST:
                    dissected_hdr_len = dissect_nhdr_topic_interest(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_PATTERN_INTEREST:
                    dissected_hdr_len = dissect_nhdr_pattern_interest(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_ADVERTISEMENT:
                    dissected_hdr_len = dissect_nhdr_advertisement(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_CTXINSTS:
                    dissected_hdr_len = dissect_nhdr_ctxinst(hdr_tvb, 0, pinfo, subtree, NULL);
                    break;
                case LBMC_NHDR_UME_STORENAME:
                    dissected_hdr_len = dissect_nhdr_storename(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_ULB_RCR:
                    dissected_hdr_len = dissect_nhdr_umq_ulb_rcr(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_LF:
                    dissected_hdr_len = dissect_nhdr_umq_lf(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_CTXINFO:
                    dissected_hdr_len = dissect_nhdr_ctxinfo(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_PSER:
                    dissected_hdr_len = dissect_nhdr_ume_pser(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_CTXINST:
                    dissected_hdr_len = dissect_nhdr_ctxinst(hdr_tvb, 0, pinfo, subtree, NULL);
                    break;
                case LBMC_NHDR_DOMAIN:
                    dissected_hdr_len = dissect_nhdr_domain(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TNWG_CAPABILITIES:
                    dissected_hdr_len = dissect_nhdr_tnwg_capabilities(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_PATIDX:
                    dissected_hdr_len = dissect_nhdr_patidx(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_CLIENT_LIFETIME:
                    dissected_hdr_len = dissect_nhdr_ume_client_lifetime(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_SID:
                    dissected_hdr_len = dissect_nhdr_ume_sid(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_IDX_CMD:
                    dissected_hdr_len = dissect_nhdr_umq_idx_cmd(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_IDX_CMD_RESP:
                    dissected_hdr_len = dissect_nhdr_umq_idx_cmd_resp(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_ODOMAIN:
                    dissected_hdr_len = dissect_nhdr_odomain(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_STREAM:
                    dissected_hdr_len = dissect_nhdr_stream(hdr_tvb, 0, pinfo, subtree, &stream_info);
                    break;
                case LBMC_NHDR_TOPIC_MD_INTEREST:
                    dissected_hdr_len = dissect_nhdr_topic_md_interest(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_PATTERN_MD_INTEREST:
                    dissected_hdr_len = dissect_nhdr_pattern_md_interest(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_LJI_REQ:
                    dissected_hdr_len = dissect_nhdr_lji_req(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TNWG_KA:
                    dissected_hdr_len = dissect_nhdr_tnwg_ka(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_RCV_KEEPALIVE:
                    dissected_hdr_len = dissect_nhdr_ume_receiver_keepalive(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_CMD:
                    dissected_hdr_len = dissect_nhdr_umq_cmd(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_CMD_RESP:
                    dissected_hdr_len = dissect_nhdr_umq_cmd_resp(hdr_tvb, 0, pinfo, subtree, packet_is_data);
                    break;
                case LBMC_NHDR_SRI_REQ:
                    dissected_hdr_len = dissect_nhdr_sri_req(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_STORE_DOMAIN:
                    dissected_hdr_len = dissect_nhdr_ume_store_domain(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_SRI:
                    dissected_hdr_len = dissect_nhdr_sri(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_ROUTE_INFO:
                    dissected_hdr_len = dissect_nhdr_route_info(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_ROUTE_INFO_NEIGHBOR:
                    dissected_hdr_len = dissect_nhdr_route_info_neighbor(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_GATEWAY_NAME:
                    dissected_hdr_len = dissect_nhdr_gateway_name(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_AUTHENTICATION:
                    opid = tvb_get_guint8(hdr_tvb, O_LBMC_CNTL_AUTH_GENERIC_HDR_T_OPID);
                    switch (opid)
                    {
                        case AUTH_OP_REQ:
                            dissected_hdr_len = dissect_nhdr_auth_request(hdr_tvb, 0, pinfo, subtree);
                            break;
                        case AUTH_OP_CHALLENGE:
                            dissected_hdr_len = dissect_nhdr_auth_challenge(hdr_tvb, 0, pinfo, subtree);
                            break;
                        case AUTH_OP_CHALLENGE_RSP:
                            dissected_hdr_len = dissect_nhdr_auth_challenge_rsp(hdr_tvb, 0, pinfo, subtree);
                            break;
                        case AUTH_OP_RESULT:
                            dissected_hdr_len = dissect_nhdr_auth_result(hdr_tvb, 0, pinfo, subtree);
                            break;
                        default:
                            dissected_hdr_len = dissect_nhdr_auth_unknown(hdr_tvb, 0, pinfo, subtree);
                            break;
                    }
                    break;
                case LBMC_NHDR_HMAC:
                    dissected_hdr_len = dissect_nhdr_hmac(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UMQ_SID:
                    dissected_hdr_len = dissect_nhdr_umq_sid(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_DESTINATION:
                    dissected_hdr_len = dissect_nhdr_destination(hdr_tvb, 0, pinfo, subtree, &destination_info);
                    break;
                case LBMC_NHDR_TOPIC_IDX:
                    dissected_hdr_len = dissect_nhdr_topic_idx(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TOPIC_SOURCE:
                    dissected_hdr_len = dissect_nhdr_topic_source(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TOPIC_SOURCE_EXFUNC:
                    dissected_hdr_len = dissect_nhdr_topic_source_exfunc(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_STORE_INFO_EXT:
                    dissected_hdr_len = dissect_nhdr_ume_store_ext(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_UME_PSRC_ELECTION_TOKEN:
                    dissected_hdr_len = dissect_nhdr_ume_psrc_election_token(hdr_tvb, 0, pinfo, subtree);
                    break;
                case LBMC_NHDR_TCP_SID:
                    dissected_hdr_len = dissect_nhdr_tcp_sid(hdr_tvb, 0, pinfo, subtree, &tcp_sid_info);
                    break;
                case LBMC_NHDR_EXTOPT:
                    dissected_hdr_len = dissect_nhdr_extopt(hdr_tvb, 0, pinfo, subtree, &reassembly);
                    break;
                    /* Headers that are not implemented. */
                case LBMC_NHDR_NONE:
                default:
                    dissected_hdr_len = dissect_nhdr_unhandled(hdr_tvb, 0, pinfo, subtree, next_hdr);
                    break;
            }
            len_dissected += dissected_hdr_len;
            next_hdr = bhdr.next_hdr;
            pkt_offset += bhdr.hdr_len;
        }
        /* If transport is TCP and we got a TCP SID header, process it. */
        tcp_address_valid = TRUE;
        if (lbm_channel_is_unknown_transport_source_lbttcp(channel))
        {
            COPY_ADDRESS_SHALLOW(&tcp_addr, &(pinfo->src));
            tcp_port = (guint16)pinfo->srcport;
        }
        else if (lbm_channel_is_unknown_transport_client_lbttcp(channel))
        {
            COPY_ADDRESS_SHALLOW(&tcp_addr, &(pinfo->dst));
            tcp_port = (guint16)pinfo->destport;
        }
        else
        {
            tcp_address_valid = FALSE;
        }
        /* Note: it *is* possible for a TCP SID to appear in an LBTTCP non-transport (UIM) message. */
        if ((pinfo->fd->flags.visited == 0) && (tcp_sid_info.set) && lbm_channel_is_unknown_transport_lbttcp(channel) && tcp_address_valid)
        {
            lbttcp_transport_sid_add(&tcp_addr, tcp_port, pinfo->fd->num, tcp_sid_info.session_id);
        }
        /* Try to determine the TCP transport channel. */
        if (lbm_channel_type(channel) == LBM_CHANNEL_TRANSPORT_LBTTCP)
        {
            if (lbm_channel_is_known(channel))
            {
                if (topic_name != NULL)
                {
                    topic_name = lbm_topic_find(channel, topic_index);
                }
            }
            else
            {
                guint32 tcp_session_id = 0;

                if (lbttcp_transport_sid_find(&tcp_addr, tcp_port, pinfo->fd->num, &tcp_session_id))
                {
                    lbttcp_transport_t * tcp_transport = NULL;

                    tcp_transport = lbttcp_transport_find(&tcp_addr, tcp_port, tcp_session_id, pinfo->fd->num);
                    if (tcp_transport != NULL)
                    {
                        actual_channel = tcp_transport->channel;
                        topic_name = lbm_topic_find(actual_channel, topic_index);
                    }
                }
            }
            if (topic_name != NULL)
            {
                if (tag_name == NULL)
                {
                    proto_item_set_text(subtree_item, "LBMC Protocol for topic [%s]", topic_name);
                }
                else
                {
                    proto_item_set_text(subtree_item, "LBMC Protocol (Tag: %s) for topic [%s]", tag_name, topic_name);
                }
            }
        }

        /* If TCP, handle stream info. */
        if (pinfo->ptype == PT_TCP)
        {
            if (stream_info.set && ctxinstd_info.set && !destination_info.set)
            {
                inst_stream = lbm_stream_istream_find(stream_info.ctxinst, ctxinstd_info.ctxinst);
                if (inst_stream == NULL)
                {
                    inst_stream = lbm_stream_istream_add(stream_info.ctxinst, ctxinstd_info.ctxinst);
                }
                if (inst_stream != NULL)
                {
                    inst_substream = lbm_stream_istream_substream_find(inst_stream, &(pinfo->src), pinfo->srcport, &(pinfo->dst), pinfo->destport, stream_info.stream_id);
                    if (inst_substream == NULL)
                    {
                        inst_substream = lbm_stream_istream_substream_add(inst_stream, &(pinfo->src), pinfo->srcport, &(pinfo->dst), pinfo->destport, stream_info.stream_id);
                    }
                    if (inst_substream != NULL)
                    {
                        proto_item * stream_item = NULL;
                        proto_tree * stream_tree = NULL;
                        proto_item * pi = NULL;
                        lbm_uim_stream_tap_info_t * stream_tap_info = NULL;

                        lbm_stream_istream_substream_update(inst_substream, msglen, pinfo->fd->num);
                        stream_item = proto_tree_add_item(subtree, hf_lbm_stream, tvb, 0, 0, ENC_NA);
                        PROTO_ITEM_SET_GENERATED(stream_item);
                        stream_tree = proto_item_add_subtree(stream_item, ett_lbm_stream);
                        pi = proto_tree_add_uint64(stream_tree, hf_lbm_stream_stream_id, tvb, 0, 0, inst_stream->channel);
                        PROTO_ITEM_SET_GENERATED(pi);
                        pi = proto_tree_add_uint(stream_tree, hf_lbm_stream_substream_id, tvb, 0, 0, inst_substream->substream_id);
                        PROTO_ITEM_SET_GENERATED(pi);
                        proto_tree_move_item(subtree, last_initial_item, stream_item);

                        stream_tap_info = wmem_new0(wmem_packet_scope(), lbm_uim_stream_tap_info_t);
                        stream_tap_info->channel = inst_stream->channel;
                        stream_tap_info->substream_id = inst_substream->substream_id;
                        stream_tap_info->bytes = msglen;
                        stream_tap_info->endpoint_a.type = lbm_uim_instance_stream;
                        memcpy((void *) stream_tap_info->endpoint_a.stream_info.ctxinst.ctxinst, (void *)stream_info.ctxinst, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
                        stream_tap_info->endpoint_b.type = lbm_uim_instance_stream;
                        memcpy((void *) stream_tap_info->endpoint_b.stream_info.ctxinst.ctxinst, (void *)ctxinstd_info.ctxinst, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
                        tap_queue_packet(lbmc_stream_tap_handle, pinfo, (void *) stream_tap_info);
                    }
                    uim_stream_info.channel = inst_stream->channel;
                    uim_stream_info.sqn = stream_info.sqn;
                    uim_stream_info.endpoint_a.type = lbm_uim_instance_stream;
                    memcpy((void *)uim_stream_info.endpoint_a.stream_info.ctxinst.ctxinst, (void *)stream_info.ctxinst, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
                    uim_stream_info.endpoint_b.type = lbm_uim_instance_stream;
                    memcpy((void *)uim_stream_info.endpoint_b.stream_info.ctxinst.ctxinst, (void *)ctxinstd_info.ctxinst, LBM_CONTEXT_INSTANCE_BLOCK_SZ);
                    puim_stream_info = &uim_stream_info;
                }
            }
            else if (stream_info.set && destination_info.set)
            {
                dom_stream = lbm_stream_dstream_find(&(destination_info.endpoint_a), &(destination_info.endpoint_b));
                if (dom_stream == NULL)
                {
                    dom_stream = lbm_stream_dstream_add(&(destination_info.endpoint_a), &(destination_info.endpoint_b));
                }
                if (dom_stream != NULL)
                {
                    dom_substream = lbm_stream_dstream_substream_find(dom_stream, &(pinfo->src), pinfo->srcport, &(pinfo->dst), pinfo->destport, stream_info.stream_id);
                    if (dom_substream == NULL)
                    {
                        dom_substream = lbm_stream_dstream_substream_add(dom_stream, &(pinfo->src), pinfo->srcport, &(pinfo->dst), pinfo->destport, stream_info.stream_id);
                    }
                    if (dom_substream != NULL)
                    {
                        proto_item * stream_item = NULL;
                        proto_tree * stream_tree = NULL;
                        proto_item * pi = NULL;
                        lbm_uim_stream_tap_info_t * stream_tap_info = NULL;

                        lbm_stream_dstream_substream_update(dom_substream, msglen, pinfo->fd->num);
                        stream_item = proto_tree_add_item(subtree, hf_lbm_stream, tvb, 0, 0, ENC_NA);
                        PROTO_ITEM_SET_GENERATED(stream_item);
                        stream_tree = proto_item_add_subtree(stream_item, ett_lbm_stream);
                        pi = proto_tree_add_uint64(stream_tree, hf_lbm_stream_stream_id, tvb, 0, 0, dom_stream->channel);
                        PROTO_ITEM_SET_GENERATED(pi);
                        pi = proto_tree_add_uint(stream_tree, hf_lbm_stream_substream_id, tvb, 0, 0, dom_substream->substream_id);
                        PROTO_ITEM_SET_GENERATED(pi);
                        proto_tree_move_item(subtree, last_initial_item, stream_item);

                        stream_tap_info = wmem_new0(wmem_packet_scope(), lbm_uim_stream_tap_info_t);
                        stream_tap_info->channel = dom_stream->channel;
                        stream_tap_info->substream_id = dom_substream->substream_id;
                        stream_tap_info->bytes = msglen;
                        stream_tap_info->endpoint_a.type = lbm_uim_domain_stream;
                        stream_tap_info->endpoint_a.stream_info.dest = destination_info.endpoint_a;
                        stream_tap_info->endpoint_b.type = lbm_uim_domain_stream;
                        stream_tap_info->endpoint_b.stream_info.dest = destination_info.endpoint_b;
                        tap_queue_packet(lbmc_stream_tap_handle, pinfo, (void *) stream_tap_info);
                    }
                    uim_stream_info.channel = dom_stream->channel;
                    uim_stream_info.sqn = stream_info.sqn;
                    uim_stream_info.endpoint_a.type = lbm_uim_domain_stream;
                    uim_stream_info.endpoint_a.stream_info.dest = destination_info.endpoint_a;
                    uim_stream_info.endpoint_b.type = lbm_uim_domain_stream;
                    uim_stream_info.endpoint_b.stream_info.dest = destination_info.endpoint_b;
                    puim_stream_info = &uim_stream_info;
                }
            }
        }
        if (next_hdr == LBMC_NHDR_DATA)
        {
            int actual_data_len = 0;
            int msgprop_offset = 0;
            tvbuff_t * data_tvb = NULL;
            tvbuff_t * msgprop_tvb = NULL;
            gboolean msg_complete = TRUE;
            gboolean msg_reassembled = FALSE;
            lbmc_message_entry_t * msg = NULL;
            gboolean dissector_found = FALSE;
            heur_dtbl_entry_t *hdtbl_entry;


            if (frag_info.fragment_found == 0)
            {
                /* No fragment info */
                if (msgprop_len > 0)
                {
                    /* Has message properties */
                    actual_data_len = tvb_reported_length_remaining(lbmc_tvb, pkt_offset) - msgprop_len;
                    msgprop_offset = pkt_offset + actual_data_len;
                    data_tvb = tvb_new_subset_length(lbmc_tvb, pkt_offset, actual_data_len);
                    msgprop_tvb = tvb_new_subset_length(lbmc_tvb, msgprop_offset, msgprop_len);
                }
                else
                {
                    data_tvb = tvb_new_subset_remaining(lbmc_tvb, pkt_offset);
                    msgprop_tvb = NULL;
                }
                msg_complete = TRUE;
                msg_reassembled = FALSE;
            }
            else
            {
                /* Fragment info is present */
                if (!lbmc_reassemble_fragments)
                {
                    /* But don't reassemble them */
                    actual_data_len = tvb_reported_length_remaining(lbmc_tvb, pkt_offset);
                    data_tvb = tvb_new_subset_length(lbmc_tvb, pkt_offset, actual_data_len);
                    msgprop_tvb = NULL;
                    msg_complete = TRUE;
                }
                else
                {
                    /* Fragment info is present and we should reassemble */
                    guint32 port;

                    port = (guint32)pinfo->destport;
                    msg = lbmc_message_find(actual_channel, &(pinfo->dst), port, &frag_info);
                    if (msg == NULL)
                    {
                        msg = lbmc_message_create(actual_channel, &(pinfo->dst), port, &frag_info, msgprop_len);
                    }
                    if (msg != NULL)
                    {
                        /* Check fragment against message */
                        int frag_len = tvb_reported_length_remaining(lbmc_tvb, pkt_offset);
                        if ((frag_info.offset + (guint32) frag_len) > msg->total_len)
                        {
                            /* Indicate a malformed packet */
                            expert_add_info_format(pinfo, NULL, &ei_lbmc_analysis_invalid_fragment,
                                "Invalid fragment for message (msglen=%" G_GUINT32_FORMAT ", frag offset=%" G_GUINT32_FORMAT ", frag len=%d",
                                msg->total_len, frag_info.offset, frag_len);
                        }
                        else
                        {
                            (void)lbmc_message_add_fragment(msg, lbmc_tvb, pkt_offset, &frag_info, pinfo->fd->num);
                            if (data_is_umq_cmd_resp)
                            {
                                msg->data_is_umq_cmd_resp = TRUE;
                            }
                            if ((msg->total_len == msg->accumulated_len) && (msg->reassembled_frame == 0))
                            {
                                /* Store the frame number in which the message will be reassembled */
                                msg->reassembled_frame = pinfo->fd->num;
                                data_tvb = tvb_new_subset_remaining(lbmc_tvb, pkt_offset);
                                msgprop_tvb = NULL;
                                msg_reassembled = TRUE;
                                msg_complete = TRUE;
                            }
                            else
                            {
                                /* This is not the last fragment of the message. */
                                data_tvb = tvb_new_subset_remaining(lbmc_tvb, pkt_offset);
                                msgprop_tvb = NULL;
                                msg_reassembled = TRUE;
                                msg_complete = FALSE;
                            }
                        }
                    }
                }
            }

            /* Note:
                - Data to be dissected is in data_tvb
                - Message properties to be dissected is in msgprop_tvb
            */
            /* For reassembled messages, show the frame or reassembly information. */
            if (msg_reassembled)
            {
                if (msg->reassembled_frame == pinfo->fd->num)
                {
                    proto_tree * frag_tree = NULL;
                    proto_item * frag_item = NULL;
                    proto_item * pi = NULL;
                    gboolean first_item = TRUE;
                    lbmc_fragment_entry_t * cur = NULL;
                    gchar * buf = NULL;

                    /* Create a new real data tvb of the reassembled data. */
                    buf = (gchar *)wmem_alloc(wmem_file_scope(), (size_t)msg->total_len);
                    cur = msg->entry;
                    while (cur != NULL)
                    {
                        memcpy(buf + cur->fragment_start, cur->data, cur->fragment_len);
                        cur = cur->next;
                    }
                    msg->reassembled_data = tvb_new_real_data(buf, msg->total_len, msg->total_len);
                    msg_complete = TRUE;
                    /* Create separate data and msgprop tvbs */
                    msg->data = tvb_new_subset_length(msg->reassembled_data, 0, msg->total_len - msg->msgprop_len);
                    if (msg->msgprop_len > 0)
                    {
                        msg->msgprop = tvb_new_subset_length(msg->reassembled_data, msg->total_len - msg->msgprop_len, msg->msgprop_len);
                    }
                    add_new_data_source(pinfo, msg->reassembled_data, "Reassembled Data");
                    if (msg->data == NULL)
                    {
                        msg->data = tvb_new_subset_length(msg->reassembled_data, 0, msg->total_len - msg->msgprop_len);
                    }
                    if (msg->msgprop == NULL)
                    {
                        if (msg->msgprop_len > 0)
                        {
                            msg->msgprop = tvb_new_subset_length(msg->reassembled_data, msg->total_len - msg->msgprop_len, msg->msgprop_len);
                        }
                    }
                    data_tvb = msg->data;
                    msgprop_tvb = msg->msgprop;
                    data_is_umq_cmd_resp = msg->data_is_umq_cmd_resp;

                    frag_item = proto_tree_add_none_format(subtree,
                        hf_lbmc_reassembly,
                        data_tvb,
                        0,
                        tvb_reported_length_remaining(data_tvb, 0),
                        "%" G_GUINT32_FORMAT " Reassembled Fragments (%" G_GUINT32_FORMAT " bytes):",
                        msg->fragment_count,
                        msg->total_len);
                    frag_tree = proto_item_add_subtree(frag_item, ett_lbmc_reassembly);
                    cur = msg->entry;
                    first_item = TRUE;
                    while (cur != NULL)
                    {
                        pi = proto_tree_add_uint_format_value(frag_tree,
                            hf_lbmc_reassembly_fragment,
                            msg->reassembled_data,
                            cur->fragment_start,
                            cur->fragment_len,
                            cur->frame,
                            "Frame: %" G_GUINT32_FORMAT ", payload: %" G_GUINT32_FORMAT "-%" G_GUINT32_FORMAT " (%" G_GUINT32_FORMAT " bytes)",
                            cur->frame,
                            cur->fragment_start,
                            (cur->fragment_start + cur->fragment_len) - 1,
                            cur->fragment_len);
                        PROTO_ITEM_SET_GENERATED(pi);
                        if (first_item)
                        {
                            proto_item_append_text(frag_item, " #%" G_GUINT32_FORMAT "(%" G_GUINT32_FORMAT ")", cur->frame, cur->fragment_len);
                        }
                        else
                        {
                            proto_item_append_text(frag_item, ", #%" G_GUINT32_FORMAT "(%" G_GUINT32_FORMAT ")", cur->frame, cur->fragment_len);
                        }
                        first_item = FALSE;
                        cur = cur->next;
                    }
                    PROTO_ITEM_SET_GENERATED(frag_item);
                }
                else
                {
                    proto_item * pi = NULL;

                    if (msg->reassembled_frame == 0)
                    {
                        expert_add_info(pinfo, NULL, &ei_lbmc_analysis_missing_reassembly_frame);
                        pi = proto_tree_add_text(subtree, data_tvb, 0, tvb_reported_length_remaining(data_tvb, 0),
                            "Message not reassembled - reassembly data missing from capture");
                    }
                    else
                    {
                        pi = proto_tree_add_uint(subtree, hf_reassembly_frame, data_tvb, 0, tvb_reported_length_remaining(data_tvb, 0), msg->reassembled_frame);
                    }
                    PROTO_ITEM_SET_GENERATED(pi);
                }
            }

            if (data_is_umq_cmd_resp && msg_complete)
            {
                (void)dissect_nhdr_umq_cmd_resp(data_tvb, 0, pinfo, subtree, TRUE);
                col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "UMQ-CMD-RESP");
            }
            else
            {
                if ((!lbm_channel_is_transport(channel)) && (!has_source_index))
                {
                    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "RX-DATA");
                }
                else
                {
                    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "DATA");
                }
                if (lbmc_use_heuristic_subdissectors)
                {
                    dissector_found = dissector_try_heuristic(lbmc_heuristic_subdissector_list, data_tvb, pinfo, subtree, &hdtbl_entry, NULL);
                }
                if (!dissector_found)
                {
                    if (lbmc_dissect_lbmpdm)
                    {
                        int encoding;
                        int pdmlen;

                        dissector_found = lbmpdm_verify_payload(data_tvb, 0, &encoding, &pdmlen);
                    }
                    if (dissector_found)
                    {
                        lbmpdm_dissect_lbmpdm_payload(data_tvb, 0, pinfo, subtree, actual_channel);
                    }
                    else
                    {
                        call_dissector(lbmc_data_dissector_handle, data_tvb, pinfo, subtree);
                    }
                }
            }
            if (msgprop_tvb != NULL)
            {
                dissect_msg_properties(msgprop_tvb, 0, pinfo, subtree);
            }
            if (msg_complete)
            {
                if (puim_stream_info != NULL)
                {
                    lbm_uim_stream_info_t * msg_info;

                    if ((!lbm_channel_is_transport(actual_channel)) && (!has_source_index))
                    {
                        puim_stream_info->description = "RX-DATA";
                    }
                    else
                    {
                        puim_stream_info->description = "DATA";
                    }
                    /* The dup is needed since there may be multiple stream infos per packet. */
                    msg_info = lbmc_dup_stream_info(puim_stream_info);
                    tap_queue_packet(lbmc_uim_tap_handle, pinfo, (void *)msg_info);
                }
            }
            len_dissected += tvb_reported_length_remaining(lbmc_tvb, pkt_offset);
        }
        else
        {
            const gchar * msg_type = NULL;
            msg_type = lbmc_determine_msg_type(found_header);

            if (msg_type != NULL)
            {
                col_append_sep_str(pinfo->cinfo, COL_INFO, " ", msg_type);
                if (puim_stream_info != NULL)
                {
                    lbm_uim_stream_info_t * msg_info;

                    puim_stream_info->description = msg_type;
                    /* The dup is needed since there may be multiple stream infos per packet. */
                    msg_info = lbmc_dup_stream_info(puim_stream_info);
                    tap_queue_packet(lbmc_uim_tap_handle, pinfo, (void *)msg_info);
                }
            }
        }
        tvb_lbmc_offset += msglen;
    }
    return (len_dissected);
}

int lbmc_get_minimum_length(void)
{
    return (O_LBMC_HDR_T_MSGLEN + L_LBMC_HDR_T_MSGLEN);
}

guint16 lbmc_get_message_length(tvbuff_t * tvb, int offset)
{
    return (tvb_get_ntohs(tvb, offset + O_LBMC_HDR_T_MSGLEN));
}

/* Register all the bits needed with the filtering engine */
void proto_register_lbmc(void)
{
    static hf_register_info hf[] =
    {
        { &hf_lbmc_tag,
            { "Tag", "lbmc.tag", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic,
            { "Topic", "lbmc.topic", FT_STRING, BASE_NONE, NULL, 0x0, "Topic string", HFILL } },
        { &hf_lbmc_ver_type,
            { "Version/Type", "lbmc.ver_type", FT_NONE, BASE_NONE, NULL, 0x0, "Version/Type information", HFILL } },
        { &hf_lbmc_ver_type_version,
            { "Version", "lbmc.ver_type.version", FT_UINT8, BASE_DEC, NULL, LBMC_HDR_VER_TYPE_VER_MASK, "LBMC protocol version", HFILL } },
        { &hf_lbmc_ver_type_type,
            { "Type", "lbmc.ver_type.type", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_message_type), LBMC_HDR_VER_TYPE_TYPE_MASK, "LBMC packet type", HFILL } },
        { &hf_lbmc_next_hdr,
            { "Next Header", "lbmc.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_msglen,
            { "Message Length", "lbmc.msglen", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tidx,
            { "Topic Index", "lbmc.tidx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sqn,
            { "Sequence Number", "lbmc.sqn", FT_UINT32, BASE_DEC, NULL, 0x0, "Topic sequence number", HFILL } },
        { &hf_lbmc_frag,
            { "Fragment", "lbmc.frag", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_frag_next_hdr,
            { "Next Header", "lbmc.frag.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_frag_hdr_len,
            { "Header Length", "lbmc.frag.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_frag_flags,
            { "Flags", "lbmc.frag.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_frag_flags_ignore,
            { "Ignore", "lbmc.frag.flags.ignore", FT_BOOLEAN, L_LBMC_FRAG_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_frag_first_sqn,
            { "First Sequence Number", "lbmc.frag.first_sqn", FT_UINT32, BASE_DEC, NULL, 0x0, "First sqn of fragment for this message", HFILL } },
        { &hf_lbmc_frag_offset,
            { "Offset", "lbmc.frag.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "Offset of this fragment within message", HFILL } },
        { &hf_lbmc_frag_len,
            { "Length", "lbmc.frag.len", FT_UINT32, BASE_DEC, NULL, 0x0, "Total length of message", HFILL } },
        { &hf_lbmc_batch,
            { "Batch", "lbmc.batch", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_batch_next_hdr,
            { "Next Header", "lbmc.batch.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_batch_hdr_len,
            { "Header Length", "lbmc.batch.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_batch_flags,
            { "Flags", "lbmc.batch.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_batch_flags_ignore,
            { "Ignore", "lbmc.batch.flags.ignore", FT_BOOLEAN, L_LBMC_BATCH_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_batch_flags_batch_start,
            { "Batch Start", "lbmc.batch.flags.batch_start", FT_BOOLEAN, L_LBMC_BATCH_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_BATCH_START, "If set, indicates the start of an explicit batch", HFILL } },
        { &hf_lbmc_batch_flags_batch_end,
            { "Batch End", "lbmc.batch.flags.batch_end", FT_BOOLEAN, L_LBMC_BATCH_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_BATCH_END, "If set, indicate the end of an explicit batch", HFILL } },
        { &hf_lbmc_tcp_request,
            { "Request", "lbmc.tcp_request", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_request_next_hdr,
            { "Next Header", "lbmc.tcp_request.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_request_hdr_len,
            { "Header Length", "lbmc.tcp_request.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_request_flags,
            { "Flags", "lbmc.tcp_request.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_request_flags_ignore,
            { "Ignore", "lbmc.tcp_request_flags.ignore", FT_BOOLEAN, L_LBMC_TCP_REQUEST_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_tcp_request_transport,
            { "Transport", "lbmc.tcp_request.transport", FT_UINT8, BASE_HEX, VALS(lbmc_req_transport_type), 0x0, "Transport type", HFILL } },
        { &hf_lbmc_tcp_request_qidx,
            { "Request Index", "lbmc.tcp_request.qidx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_request_port,
            { "Port", "lbmc.tcp_request.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_request_reserved,
            { "Reserved", "lbmc.tcp_request.reserved", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_request_ipaddr,
            { "Requester IP Address", "lbmc.tcp_request.ipaddr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topicname,
            { "Topicname", "lbmc.topicname", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topicname_next_hdr,
            { "Next Header", "lbmc.topicname.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_topicname_hdr_len,
            { "Header Length", "lbmc.topicname.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topicname_flags,
            { "Flags", "lbmc.topicname.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topicname_flags_ignore,
            { "Ignore", "lbmc.topicname.flags.ignore", FT_BOOLEAN, L_LBMC_TOPICNAME_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_topicname_topicname,
            { "Topic", "lbmc.topicname.topic", FT_STRING, BASE_NONE, NULL, 0x0, "Topic name", HFILL } },
        { &hf_lbmc_apphdr,
            { "AppHeader", "lbmc.apphdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_next_hdr,
            { "Next Header", "lbmc.apphdr.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_hdr_len,
            { "Header Length", "lbmc.apphdr.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_code,
            { "Code", "lbmc.apphdr.code", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_code_ignore,
            { "Ignore", "lbmc.apphdr.code.ignore", FT_BOOLEAN, L_LBMC_APPHDR_HDR_T_CODE * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_apphdr_code_code,
            { "Application Code", "lbmc.apphdr.code.code", FT_UINT16, BASE_DEC_HEX, NULL, LBMC_APPHDR_CODE_MASK, "Application header code", HFILL } },
        { &hf_lbmc_apphdr_data,
            { "Data", "lbmc.apphdr.data", FT_NONE, BASE_NONE, NULL, 0x0, "Application header data", HFILL } },
        { &hf_lbmc_apphdr_chain,
            { "AppHeader Chain", "lbmc.apphdr_chain", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_next_hdr,
            { "Next Header", "lbmc.apphdr_chain.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_hdr_len,
            { "Header Length", "lbmc.apphdr_chain.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_res,
            { "Reserved", "lbmc.apphdr_chain.res", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_first_chain_hdr,
            { "First chain hdr", "lbmc.apphdr_chain.first_chain_hdr", FT_UINT8, BASE_HEX_DEC, VALS(lbmc_apphdr_chain_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_element,
            { "AppHeader Chain Element", "lbmc.apphdr_chain.element", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_element_next_hdr,
            { "Next Header", "lbmc.apphdr_chain.element.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_apphdr_chain_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_element_hdr_len,
            { "Header Length", "lbmc.apphdr_chain.element.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_element_res,
            { "Reserved", "lbmc.apphdr_chain.element.res", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_element_data,
            { "Data", "lbmc.apphdr_chain.element.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_msgprop,
            { "AppHeader Chain Message Properties Element", "lbmc.apphdr_chain.msgprop", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_msgprop_next_hdr,
            { "Next Header", "lbmc.apphdr_chain.msgprop.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_apphdr_chain_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_msgprop_hdr_len,
            { "Header Length", "lbmc.apphdr_chain.msgprop.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_msgprop_res,
            { "Reserved", "lbmc.apphdr_chain.msgprop.res", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_apphdr_chain_msgprop_len,
            { "Properties Length", "lbmc.apphdr_chain.msgprop.proplen", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_msgid,
            { "UMQ MessageID", "lbmc.umq_msgid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_msgid_next_hdr,
            { "Next Header", "lbmc.umq_msgid.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_msgid_hdr_len,
            { "Header Length", "lbmc.umq_msgid.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_msgid_flags,
            { "Flags", "lbmc.umq_msgid.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_msgid_flags_ignore,
            { "Ignore", "lbmc.umq_msgid.flags.ignore", FT_BOOLEAN, L_LBMC_UMQ_MSGID_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_umq_msgid_msgid_regid,
            { "Message ID RegID", "lbmc.umq_msgid.msgid_regid", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, "Message ID registration ID", HFILL } },
        { &hf_lbmc_umq_msgid_msgid_stamp,
            { "MessageID Stamp", "lbmc.umq_msgid.msgid_stamp", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, "Message ID stamp", HFILL } },
        { &hf_lbmc_umq_sqd_rcv,
            { "UMQ SQD Receiver", "lbmc.umq_sqd_rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_next_hdr,
            { "Next Header", "lbmc.umq_sqd_rcv.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_hdr_len,
            { "Header Length", "lbmc.umq_sqd_rcv.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_flags,
            { "Flags", "lbmc.umq_sqd_rcv.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_flags_ignore,
            { "Ignore", "lbmc.umq_sqd_rcv.flags.ignore", FT_BOOLEAN, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_flags_r_flag,
            { "Reassign", "lbmc.umq_sqd_rcv.flags.r_flag", FT_BOOLEAN, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_SQD_RCV_R_FLAG, "Set if this is a reassignment", HFILL } },
        { &hf_lbmc_umq_sqd_rcv_flags_s_flag,
            { "Resubmit", "lbmc.umq_sqd_rcv.flags.s_flag", FT_BOOLEAN, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_SQD_RCV_S_FLAG, "Set if this is a resubmission", HFILL } },
        { &hf_lbmc_umq_sqd_rcv_flags_re_flag,
            { "Redelivered", "lbmc.umq_sqd_rcv.flags.re_flag", FT_BOOLEAN, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_SQD_RCV_RE_FLAG, "Set if this is a redelivery", HFILL } },
        { &hf_lbmc_umq_sqd_rcv_flags_eoi_flag,
            { "End of Index", "lbmc.umq_sqd_rcv.flags.eoi_flag", FT_BOOLEAN, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_SQD_RCV_BOI_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_flags_boi_flag,
            { "Beginning of Index", "lbmc.umq_sqd_rcv.flags.boi_flag", FT_BOOLEAN, L_LBMC_UMQ_SQD_RCV_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_SQD_RCV_EOI_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_queue_id,
            { "Queue ID", "lbmc.umq_sqd_rcv.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_queue_ver,
            { "Queue Version", "lbmc.umq_sqd_rcv.queue_ver", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_rcr_idx,
            { "RCR Index", "lbmc.umq_sqd_rcv.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sqd_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_sqd_rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub,
            { "UMQ Resubmission", "lbmc.umq_resub", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_next_hdr,
            { "Next Header", "lbmc.umq_resub.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_hdr_len,
            { "Header Length", "lbmc.umq_resub.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_flags,
            { "Flags", "lbmc.umq_resub.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_flags_ignore,
            { "Ignore", "lbmc.umq_resub.flags.ignore", FT_BOOLEAN, L_LBMC_UMQ_RESUB_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_umq_resub_flags_q_flag,
            { "Queue", "lbmc.umq_resub.flags.q_flag", FT_BOOLEAN, L_LBMC_UMQ_RESUB_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_RESUB_Q_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_resub_rcr_idx,
            { "RCR Index", "lbmc.umq_resub.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Receiver control record index", HFILL } },
        { &hf_lbmc_umq_resub_resp_ip,
            { "Response IP Address", "lbmc.umq_resub.resp_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_port,
            { "Response Port", "lbmc.umq_resub.resp_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_appset_idx,
            { "AppSet Index", "lbmc.umq_resub.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_otid,
            { "OTID", "lbmc.otid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_otid_next_hdr,
            { "Next Header", "lbmc.otid.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_otid_hdr_len,
            { "Header Length", "lbmc.otid.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_otid_flags,
            { "Flags", "lbmc.otid.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_otid_flags_ignore,
            { "Ignore", "lbmc.otid.flags.ignore", FT_BOOLEAN, L_LBMC_OTID_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_otid_otid,
            { "OTID", "lbmc.otid.otid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinst,
            { "Context Instance", "lbmc.ctxinst", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinst_next_hdr,
            { "Next Header", "lbmc.ctxinst.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinst_hdr_len,
            { "Header Length", "lbmc.ctxinst.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinst_flags,
            { "Flags", "lbmc.ctxinst.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinst_flags_ignore,
            { "Ignore", "lbmc.ctxinst_flags.ignore", FT_BOOLEAN, L_LBMC_CTXINST_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ctxinst_ctxinst,
            { "Context Instance", "lbmc.ctxinst.ctxinst", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinstd,
            { "Context Instance Destination", "lbmc.ctxinstd", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinstr,
            { "Context Instance Return", "lbmc.ctxinstr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_srcidx,
            { "Source Index", "lbmc.srcidx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_srcidx_next_hdr,
            { "Next Header", "lbmc.srcidx.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_srcidx_hdr_len,
            { "Header Length", "lbmc.srcidx.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_srcidx_flags,
            { "Flags", "lbmc.srcidx.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_srcidx_flags_ignore,
            { "Ignore", "lbmc.srcidx.flags.ignore", FT_BOOLEAN, L_LBMC_SRCIDX_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_srcidx_srcidx,
            { "Source Index", "lbmc.srcidx.srcidx", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg,
            { "UMQ ULB Message", "lbmc.umq_ulb_msg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_next_hdr,
            { "Next Header", "lbmc.umq_ulb_msg.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_hdr_len,
            { "Header Length", "lbmc.umq_ulb_msg.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_flags,
            { "Flags", "lbmc.umq_ulb_msg.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_flags_ignore,
            { "Ignore", "lbmc.umq_ulb_msg.flags.ignore", FT_BOOLEAN, L_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_flags_a_flag,
            { "Assigned", "lbmc.umq_ulb_msg.flags.a", FT_BOOLEAN, L_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_ULB_MSG_A_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_flags_r_flag,
            { "Reassigned", "lbmc.umq_ulb_msg.flags.r", FT_BOOLEAN, L_LBMC_UMQ_ULB_MSG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_ULB_MSG_R_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_queue_id,
            { "Queue ID", "lbmc.umq_ulb_msg.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_ulb_msg.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_assign_id,
            { "Assignment ID", "lbmc.umq_ulb_msg.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_appset_idx,
            { "AppSet Index", "lbmc.umq_ulb_msg.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_msg_num_ras,
            { "Number of RAs", "lbmc.umq_ulb_msg.num_ras", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "Number of reassignments", HFILL } },
        { &hf_lbmc_ssf_init,
            { "SSF Init", "lbmc.ssf_init", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_next_hdr,
            { "Next Header", "lbmc.ssf_init.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_hdr_len,
            { "Header Length", "lbmc.ssf_init.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_transport,
            { "Transport", "lbmc.ssf_init.transport", FT_UINT8, BASE_DEC, VALS(lbmc_ssf_transport_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_flags,
            { "Flags", "lbmc.ssf_init.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_flags_ignore,
            { "Ignore", "lbmc.ssf_init.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_ssf_init_flags_default_inclusions,
            { "Default Inclusions", "lbmc.ssf_init.flags.default_inclusions", FT_BOOLEAN, L_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CNTL_SSF_INIT_DEFAULT_INC, NULL, HFILL } },
        { &hf_lbmc_ssf_init_flags_default_exclusions,
            { "Default Exclusions", "lbmc.ssf_init.flags.default_exclusions", FT_BOOLEAN, L_LBMC_CNTL_SSF_INIT_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CNTL_SSF_INIT_DEFAULT_EXC, NULL, HFILL } },
        { &hf_lbmc_ssf_init_transport_idx,
            { "Transport Index", "lbmc.ssf_init.transport_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_client_idx,
            { "Client Index", "lbmc.ssf_init.client_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_ssf_port,
            { "SSF Port", "lbmc.ssf_init.ssf_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_res,
            { "Reserved", "lbmc.ssf_init.res", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_init_ssf_ip,
            { "SSF IP Address", "lbmc.ssf_init.ssf_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_creq,
            { "SSF CReq", "lbmc.ssf_creq", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_creq_next_hdr,
            { "Next Header", "lbmc.ssf_creq.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_creq_hdr_len,
            { "Header Length", "lbmc.ssf_creq.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_creq_flags,
            { "Flags", "lbmc.ssf_creq.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_creq_flags_ignore,
            { "Ignore", "lbmc.ssf_creq.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_SSF_CREQ_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_ssf_creq_mode,
            { "Mode", "lbmc.ssf_creq.mode", FT_UINT8, BASE_HEX, VALS(lbmc_ssf_creq_mode), 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_creq_transport_idx,
            { "Transport Index", "lbmc.ssf_creq.transport_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_creq_topic_idx,
            { "Topic Index", "lbmc.ssf_creq.topic_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ssf_creq_client_idx,
            { "Client Index", "lbmc.ssf_creq.client_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg,
            { "UME PReg", "lbmc.ume_preg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_next_hdr,
            { "Next Header", "lbmc.ume_preg.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_hdr_len,
            { "Header Length", "lbmc.ume_preg.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_flags,
            { "Flags", "lbmc.ume_preg.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_flags_ignore,
            { "Ignore", "lbmc.ume_preg.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_ume_preg_flags_f_flag,
            { "Do Not Forward ACKs", "lbmc.ume_preg.flags.f_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS * 8, TFS(&lbmc_ume_f_flag), LBMC_UME_PREG_F_FLAG, "Set if ACKs are to be forwarded", HFILL } },
        { &hf_lbmc_ume_preg_flags_p_flag,
            { "Proxy Source", "lbmc.ume_preg.flags.p_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_PREG_P_FLAG, "Set if this source is a proxy source", HFILL } },
        { &hf_lbmc_ume_preg_flags_w_flag,
            { "Receiver Paced Persistence", "lbmc.ume_preg.flags.w_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_PREG_W_FLAG, "Set if receiver paced persistence is used", HFILL } },
        { &hf_lbmc_ume_preg_flags_d_flag,
            { "Deregister", "lbmc.ume_preg.flags.d_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_PREG_D_FLAG, "Set if this is a de-registration", HFILL } },
        { &hf_lbmc_ume_preg_marker,
            { "Marker", "lbmc.ume_preg.marker", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_marker_s_flag,
            { "Source Registration", "lbmc.ume_preg.marker.s_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_HDR_T_MARKER * 8, TFS(&lbmc_ume_s_flag), LBMC_UME_PREG_S_FLAG, "Set if this is a source registration", HFILL } },
        { &hf_lbmc_ume_preg_marker_marker,
            { "Marker", "lbmc.ume_preg.marker.marker", FT_UINT8, BASE_DEC_HEX, NULL, LBMC_CNTL_UME_PREG_MARKER_MASK, NULL, HFILL } },
        { &hf_lbmc_ume_preg_reg_id,
            { "Registration ID", "lbmc.ume_preg.reg_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_transport_idx,
            { "Transport Index", "lbmc.ume_preg.transport_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_topic_idx,
            { "Topic Index", "lbmc.ume_preg.topic_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_src_reg_id,
            { "Source Registration ID", "lbmc.ume_preg.src_reg_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_port,
            { "Response Port", "lbmc.ume_preg.resp_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_res2,
            { "Reserved2", "lbmc.ume_preg.res2", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_ip,
            { "Response IP Address", "lbmc.ume_preg.resp_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp,
            { "UME PReg Resp", "lbmc.ume_preg_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_next_hdr,
            { "Next Header", "lbmc.ume_preg_resp.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_hdr_len,
            { "Header Length", "lbmc.ume_preg_resp.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_code,
            { "Code", "lbmc.ume_preg_resp.code", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_code_ignore,
            { "Ignore", "lbmc.ume_preg_resp.code.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_code_e_flag,
            { "Error Indicator", "lbmc.ume_preg_resp.code.e_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE * 8, TFS(&lbmc_ume_error_flag), LBMC_UME_PREG_RESP_E_FLAG, "Set if an error occurred", HFILL } },
        { &hf_lbmc_ume_preg_resp_code_o_flag,
            { "Old Client", "lbmc.ume_preg_resp.code.o_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE * 8, TFS(&lbmc_ume_o_flag), LBMC_UME_PREG_RESP_O_FLAG, "Set if an old client was detected", HFILL } },
        { &hf_lbmc_ume_preg_resp_code_n_flag,
            { "No ACKs/No Cache", "lbmc.ume_preg_resp.code.n_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE * 8, TFS(&lbmc_ume_n_flag), LBMC_UME_PREG_RESP_CODE_NOACKS_FLAG, "Set if not ACKing or not caching", HFILL } },
        { &hf_lbmc_ume_preg_resp_code_w_flag,
            { "Receiver Paced Persistence", "lbmc.ume_preg_resp.code.w_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE * 8, TFS(&tfs_set_notset), LBMC_UME_PREG_RESP_W_FLAG, "Set if receiver paced persistence", HFILL } },
        { &hf_lbmc_ume_preg_resp_code_d_flag,
            { "Deregister", "lbmc.ume_preg_resp.code.d_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_CODE * 8, TFS(&tfs_set_notset), LBMC_UME_PREG_RESP_D_FLAG, "Set if deregistration", HFILL } },
        { &hf_lbmc_ume_preg_resp_code_code,
            { "Error Code", "lbmc.ume_preg_resp.code.code", FT_UINT8, BASE_HEX, VALS(lbmc_ume_preg_resp_error_code), LBMC_CNTL_UME_PREG_RESP_CODE_MASK, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_marker,
            { "Marker", "lbmc.ume_preg_resp.marker", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_marker_s_flag,
            { "Source Registration", "lbmc.ume_preg_resp.marker.s_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_PREG_RESP_HDR_T_MARKER * 8, TFS(&lbmc_ume_s_flag), LBMC_UME_PREG_S_FLAG, "Set if source registration", HFILL } },
        { &hf_lbmc_ume_preg_resp_marker_marker,
            { "Marker", "lbmc.ume_preg_resp.marker.marker", FT_UINT8, BASE_DEC_HEX, NULL, LBMC_CNTL_UME_PREG_MARKER_MASK, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_reg_id,
            { "Registration ID", "lbmc.ume_preg_resp.reg_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_transport_idx,
            { "Transport Index", "lbmc.ume_preg_resp.transport_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_topic_idx,
            { "Topic Index", "lbmc.ume_preg_resp.topic_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_low_seqnum,
            { "Low Sequence Number", "lbmc.ume_preg_resp.low_seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_preg_resp_high_seqnum,
            { "High Sequence Number", "lbmc.ume_preg_resp.high_seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack,
            { "UME ACK", "lbmc.ume_ack", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_next_hdr,
            { "Next Header", "lbmc.ume_ack.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_hdr_len,
            { "Header Length", "lbmc.ume_ack.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_flags,
            { "Flags", "lbmc.ume_ack.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_flags_ignore,
            { "Ignore", "lbmc.ume_ack.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_ume_ack_flags_o_flag,
            { "Receiver Arrival-Order Delivery", "lbmc.ume_ack.flags.o_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_ACK_O_FLAG, "Set if receiver specified  arrival-order delivery", HFILL } },
        { &hf_lbmc_ume_ack_flags_f_flag,
            { "Do Not Forward ACKs", "lbmc.ume_ack.flags.f_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS * 8, TFS(&lbmc_ume_f_flag), LBMC_UME_ACK_F_FLAG, NULL, HFILL } },
        { &hf_lbmc_ume_ack_flags_u_flag,
            { "User-Specified Receiver Registration ID", "lbmc.ume_ack.flags.u_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_ACK_U_FLAG, "Set if receiver registration ID was set by the user", HFILL } },
        { &hf_lbmc_ume_ack_flags_e_flag,
            { "Explicit ACK", "lbmc.ume_ack.flags.e_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_ACK_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_ACK_E_FLAG, "Set if an explicit ACK", HFILL } },
        { &hf_lbmc_ume_ack_type,
            { "Type", "lbmc.ume_ack.type", FT_UINT8, BASE_HEX, VALS(lbmc_ume_ack_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_transport_idx,
            { "Transport Index", "lbmc.ume_ack.transport_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_id_2,
            { "Topic Index/Registration ID", "lbmc.ume_ack.id_2", FT_UINT32, BASE_DEC, NULL, 0x0, "Topic index (from store) or Registration ID (from receiver)", HFILL } },
        { &hf_lbmc_ume_ack_rcv_reg_id,
            { "Receiver Registration ID", "lbmc.ume_ack.rcv_reg_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_seqnum,
            { "Sequence Number", "lbmc.ume_ack.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq,
            { "UME RX Request", "lbmc.ume_rxreq", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_next_hdr,
            { "Next Header", "lbmc.ume_rxreq.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_hdr_len,
            { "Header Length", "lbmc.ume_rxreq.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_flags,
            { "Flags", "lbmc.ume_rxreq.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_flags_ignore,
            { "Ignore", "lbmc.ume_rxreq.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_flags_tsni_req,
            { "TSNI Request", "lbmc.ume_rxreq.flags.t", FT_BOOLEAN, L_LBMC_CNTL_UME_RXREQ_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_RXREQ_T_FLAG, "Set if TSNI request", HFILL } },
        { &hf_lbmc_ume_rxreq_request_idx,
            { "Request Index", "lbmc.ume_rxreq.request_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_transport_idx,
            { "Transport Index", "lbmc.ume_rxreq.transport_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_id_2,
            { "Topic Index/Registration ID", "lbmc.ume_rxreq.id_2", FT_UINT32, BASE_DEC, NULL, 0x0, "Topic index (from store) or Registration ID (from receiver)", HFILL } },
        { &hf_lbmc_ume_rxreq_seqnum,
            { "Sequence Number", "lbmc.ume_rxreq.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_rx_port,
            { "Retransmission Port", "lbmc.ume_rxreq.rx_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_res,
            { "Reserved", "lbmc.ume_rxreq.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_rxreq_rx_ip,
            { "Retransmission IP Address", "lbmc.ume_rxreq.rx_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive,
            { "UME Keepalive", "lbmc.ume_keepalive", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive_next_hdr,
            { "Next Header", "lbmc.ume_keepalive.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive_hdr_len,
            { "Header Length", "lbmc.ume_keepalive.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive_flags,
            { "Flags", "lbmc.ume_keepalive.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive_flags_ignore,
            { "Ignore", "lbmc.ume_keepalive.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive_flags_r_flag,
            { "Response Requested", "lbmc.ume_keepalive.flags.r_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS * 8, TFS(&lbmc_ume_r_flag), LBMC_UME_KEEPALIVE_R_FLAG, "Set if response requested", HFILL } },
        { &hf_lbmc_ume_keepalive_flags_t_flag,
            { "No TIR Seen", "lbmc.ume_keepalive.flags.t_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_KEEPALIVE_HDR_T_FLAGS * 8, TFS(&lbmc_ume_t_flag), LBMC_UME_KEEPALIVE_T_FLAG, "Set if no TIR seen", HFILL } },
        { &hf_lbmc_ume_keepalive_type,
            { "Type", "lbmc.ume_keepalive.type", FT_UINT8, BASE_HEX, VALS(lbmc_ume_ka_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive_transport_idx,
            { "Transport Index", "lbmc.ume_keepalive.transport_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive_topic_idx,
            { "Topic Index", "lbmc.ume_keepalive.topic_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_keepalive_reg_id,
            { "Registration ID", "lbmc.ume_keepalive.reg_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storeid,
            { "UME Store ID", "lbmc.ume_storeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storeid_next_hdr,
            { "Next Header", "lbmc.ume_storeid.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storeid_hdr_len,
            { "Header Length", "lbmc.ume_storeid.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storeid_store_id,
            { "Store ID", "lbmc.ume_storeid.storeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storeid_store_id_ignore,
            { "Ignore", "lbmc.ume_storeid.storeid.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_STOREID_HDR_T_STORE_ID * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_storeid_store_id_store_id,
            { "Store ID", "lbmc.ume_storeid.storeid.store_id", FT_UINT16, BASE_DEC_HEX, NULL, LBMC_CNTL_UME_STOREID_STOREID_MASK, NULL, HFILL } },
        { &hf_lbmc_ume_ranged_ack,
            { "UME Ranged ACK", "lbmc.ume_ranged_ack", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ranged_ack_next_hdr,
            { "Next Header", "lbmc.ume_ranged_ack.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ranged_ack_hdr_len,
            { "Header Length", "lbmc.ume_ranged_ack.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ranged_ack_flags,
            { "Flags", "lbmc.ume_ranged_ack.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ranged_ack_flags_ignore,
            { "Ignore", "lbmc.ume_ranged_ack.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_RANGED_ACK_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_ranged_ack_first_seqnum,
            { "First Sequence Number", "lbmc.ume_ranged_ack.first_seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ranged_ack_last_seqnum,
            { "Last Sequence Number", "lbmc.ume_ranged_ack.last_seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_id,
            { "UME ACK ID", "lbmc.ume_ack_id", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_id_next_hdr,
            { "Next Header", "lbmc.ume_ack_id.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_id_hdr_len,
            { "Header Length", "lbmc.ume_ack_id.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_id_flags,
            { "Flags", "lbmc.ume_ack_id.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_ack_id_flags_ignore,
            { "Ignore", "lbmc.ume_ack_id.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_ACK_ID_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_ack_id_id,
            { "Acknowledgement ID", "lbmc.ume_ack_id.id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_capability,
            { "UME Capability", "lbmc.ume_capability", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_capability_next_hdr,
            { "Next Header", "lbmc.ume_capability.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_capability_hdr_len,
            { "Header Length", "lbmc.ume_capability.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_capability_flags,
            { "Flags", "lbmc.ume_capability.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_capability_flags_ignore,
            { "Ignore", "lbmc.ume_capability.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_capability_flags_qc_flag,
            { "Quorum/Consensus Capabilities", "lbmc.ume_capability.flags.qc_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_CAPABILITY_QC_FLAG, "Set if quorum/consensus supported", HFILL } },
        { &hf_lbmc_ume_capability_flags_client_lifetime_flag,
            { "Client Lifetime Capabilities", "lbmc.ume_capability.flags.client_lifetime_flag", FT_BOOLEAN, L_LBMC_CNTL_UME_CAPABILITY_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_CAPABILITY_CLIENT_LIFETIME_FLAG, "Set if client lifetime enabled", HFILL } },
        { &hf_lbmc_ume_proxy_src,
            { "UME Proxy Source", "lbmc.ume_proxy_src", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_proxy_src_next_hdr,
            { "Next Header", "lbmc.ume_proxy_src.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_proxy_src_hdr_len,
            { "Header Length", "lbmc.ume_proxy_src.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_proxy_src_flags,
            { "Flags", "lbmc.ume_proxy_src.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_proxy_src_flags_ignore,
            { "Ignore", "lbmc.ume_proxy_src.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_proxy_src_flags_enable,
            { "Enable Proxy Source", "lbmc.ume_proxy_src.flags.enable", FT_BOOLEAN, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_PROXY_SRC_E_FLAG, "Set if proxy source is enabled", HFILL } },
        { &hf_lbmc_ume_proxy_src_flags_compatibility,
            { "Enable Pre-6.0 Compatibility", "lbmc.ume_proxy_src.flags.compatibility", FT_BOOLEAN, L_LBMC_CNTL_UME_PROXY_SRC_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_PROXY_SRC_C_FLAG, "Set if pre-6.0 compatibility for created proxy source is enabled", HFILL } },
        { &hf_lbmc_ume_store_group,
            { "UME Store Group", "lbmc.ume_store_group", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_group_next_hdr,
            { "Next Header", "lbmc.ume_store_group.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_group_hdr_len,
            { "Header Length", "lbmc.ume_store_group.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_group_flags,
            { "Flags", "lbmc.ume_store_group.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_group_flags_ignore,
            { "Ignore", "lbmc.ume_store_group.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_STORE_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_store_group_grp_idx,
            { "Group Index", "lbmc.ume_store_group.grp_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_group_grp_sz,
            { "Group Size", "lbmc.ume_store_group.grp_sz", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_group_res1,
            { "Reserved", "lbmc.ume_store_group.res1", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store,
            { "UME Store", "lbmc.ume_store", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_next_hdr,
            { "Next Header", "lbmc.ume_store.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_hdr_len,
            { "Header Length", "lbmc.ume_store.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_flags,
            { "Flags", "lbmc.ume_store.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_flags_ignore,
            { "Ignore", "lbmc.ume_store.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_STORE_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_store_grp_idx,
            { "Group Index", "lbmc.ume_store.grp_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_store_tcp_port,
            { "Store TCP Port", "lbmc.ume_store.store_tcp_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_store_idx,
            { "Store Index", "lbmc.ume_store.store_idx", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_store_ip_addr,
            { "Store IP Address", "lbmc.ume_store.store_ip_addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_src_reg_id,
            { "Source RegID", "lbmc.ume_store.src_reg_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_lj_info,
            { "UME Late Join", "lbmc.ume_lj_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_lj_info_next_hdr,
            { "Next Header", "lbmc.ume_lj_info.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_lj_info_hdr_len,
            { "Header Length", "lbmc.ume_lj_info.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_lj_info_flags,
            { "Flags", "lbmc.ume_lj_info.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_lj_info_flags_ignore,
            { "Ignore", "lbmc.ume_lj_info.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_LJ_INFO_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_lj_info_low_seqnum,
            { "Low sequence", "lbmc.ume_lj_info.low_seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_lj_info_high_seqnum,
            { "High sequence", "lbmc.ume_lj_info.high_seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_lj_info_qidx,
            { "Request index", "lbmc.ume_lj_info.qidx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tsni,
            { "TSNI", "lbmc.tsni", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tsni_next_hdr,
            { "Next Header", "lbmc.tsni.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_tsni_hdr_len,
            { "Header Length", "lbmc.tsni.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tsni_num_recs,
            { "Num Recs", "lbmc.tsni.num_recs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tsni_num_recs_ignore,
            { "Ignore", "lbmc.tsni.num_recs.ignore", FT_BOOLEAN, L_LBMC_CNTL_TSNI_HDR_T_NUM_RECS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_tsni_num_recs_num_recs,
            { "Num Recs", "lbmc.tsni.num_recs.num_recs", FT_UINT16, BASE_DEC_HEX, NULL, LBMC_CNTL_TSNI_NUM_RECS_MASK, NULL, HFILL } },
        { &hf_lbmc_tsni_rec,
            { "TSNIs", "lbmc.tsni.tsni_rec", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tsni_rec_tidx,
            { "Topic Index", "lbmc.tsni.tsni_rec.tidx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tsni_rec_sqn,
            { "Sequence Number", "lbmc.tsni.tsni_rec.sqn", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg,
            { "UMQ Registration", "lbmc.umq_reg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_next_hdr,
            { "Next Header", "lbmc.umq_reg.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_hdr_len,
            { "Header Length", "lbmc.umq_reg.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_flags,
            { "Flags", "lbmc.umq_reg.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_flags_ignore,
            { "Ignore", "lbmc.umq_reg.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_reg_flags_r_flag,
            { "R Flag", "lbmc.umq_reg.flags.r_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_R_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_reg_flags_t_flag,
            { "TSP Present", "lbmc.umq_reg.flags.t_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_T_FLAG, "Sst if TSP is present", HFILL } },
        { &hf_lbmc_umq_reg_flags_i_flag,
            { "Index Assign Eligible", "lbmc.umq_reg.flags.i_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_I_FLAG, "Set if index assign eligible", HFILL } },
        { &hf_lbmc_umq_reg_flags_msg_sel_flag,
            { "Message Selector", "lbmc.umq_reg.flags.msg_sel_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_MSG_SEL_FLAG, "Set if message selector present", HFILL } },
        { &hf_lbmc_umq_reg_reg_type,
            { "Registration Type", "lbmc.umq_reg.reg_type", FT_UINT8, BASE_DEC, VALS(lbmc_umq_reg_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_queue_id,
            { "Queue ID", "lbmc.umq_reg.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_cmd_id,
            { "Command ID", "lbmc.umq_reg.cmd_id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_inst_idx,
            { "Instance Index", "lbmc.umq_reg.inst_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_regid,
            { "Registration ID", "lbmc.umq_reg.regid", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ctx,
            { "Context Registration", "lbmc.umq_reg.reg_ctx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ctx_port,
            { "Port", "lbmc.umq_reg.reg_ctx.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ctx_reserved,
            { "Reserved", "lbmc.umq_reg.reg_ctx.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ctx_ip,
            { "IP Address", "lbmc.umq_reg.reg_ctx.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ctx_capabilities,
            { "Capabilities", "lbmc.umq_reg.reg_ctx.capabilities", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_src,
            { "Source Registration", "lbmc.umq_reg.reg_src", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_src_transport_idx,
            { "Transport Index", "lbmc.umq_reg.reg_src.transport_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_src_topic_idx,
            { "Topic Index", "lbmc.umq_reg.reg_src.topic_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_rcv,
            { "Receiver Registration", "lbmc.umq_reg.reg_rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_reg.reg_rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_rcv_rcv_type_id,
            { "Receiver Type ID", "lbmc.umq_reg.reg_rcv.rcv_type_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_rcv_last_topic_rcr_tsp,
            { "Last Topic RCR TSP", "lbmc.umq_reg.reg_rcv.last_topic_rcr_tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_rcv_dereg,
            { "Receiver deregistration", "lbmc.umq_reg.rcv_dereg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_rcv_dereg_rcr_idx,
            { "RCR Index", "lbmc.umq_reg.rcv_dereg.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_rcv_dereg_assign_id,
            { "Assignment ID", "lbmc.umq_reg.rcv_dereg.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ulb_rcv,
            { "ULB Receiver registration", "lbmc.umq_reg.reg_ulb_rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ulb_rcv_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_reg.reg_ulb_rcv.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ulb_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_reg.reg_ulb_rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ulb_rcv_rcv_type_id,
            { "Receiver Type ID", "lbmc.umq_reg.reg_ulb_rcv.rcv_type_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ulb_rcv_port,
            { "Port", "lbmc.umq_reg.reg_ulb_rcv.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ulb_rcv_reserved,
            { "Reserved", "lbmc.umq_reg.reg_ulb_rcv.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ulb_rcv_ip,
            { "IP Address", "lbmc.umq_reg.reg_ulb_rcv.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_ulb_rcv_capabilities,
            { "Capabilities", "lbmc.umq_reg.reg_ulb_rcv.capabilities", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_ulb_rcv_dereg,
            { "ULB Receiver Deregistration", "lbmc.umq_reg.ulb_rcv_dereg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_ulb_rcv_dereg_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_reg.ulb_rcv_dereg.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_ulb_rcv_dereg_assign_id,
            { "Assignment ID", "lbmc.umq_reg.ulb_rcv_dereg.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_observer_rcv,
            { "Observer Receiver Registration", "lbmc.umq_reg.reg_observer_rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_observer_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_reg.reg_observer_rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_observer_rcv_rcv_type_id,
            { "Receiver Type ID", "lbmc.umq_reg.reg_observer_rcv.rcv_type_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_reg_observer_rcv_last_topic_rcr_tsp,
            { "Last Topic RCR TSP", "lbmc.umq_reg.reg_observer_rcv.last_topic_rcr_tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_observer_rcv_dereg,
            { "Observer Receiver Deregistration", "lbmc.umq_reg.observer_rcv_dereg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_observer_rcv_dereg_rcr_idx,
            { "RCR Index", "lbmc.umq_reg.observer_rcv_dereg.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_observer_rcv_dereg_assign_id,
            { "Assignment ID", "lbmc.umq_reg.observer_rcv_dereg.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp,
            { "UMQ Registration Response", "lbmc.umq_reg_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_next_hdr,
            { "Next Header", "lbmc.umq_reg_resp.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_hdr_len,
            { "Header Length", "lbmc.umq_reg_resp.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_flags,
            { "Flags", "lbmc.umq_reg_resp.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_flags_ignore,
            { "Ignore", "lbmc.umq_reg_resp.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_flags_r_flag,
            { "R Flag", "lbmc.umq_reg_resp.flags.r", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_RESP_R_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_flags_l_flag,
            { "ULB Error", "lbmc.umq_reg_resp.flags.l", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_RESP_ERR_L_FLAG, "Set if ULB error occurred", HFILL } },
        { &hf_lbmc_umq_reg_resp_flags_src_s_flag,
            { "Source Dissemination", "lbmc.umq_reg_resp.flags.src_s", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_RESP_SRC_S_FLAG, "Set if source dissemination model", HFILL } },
        { &hf_lbmc_umq_reg_resp_flags_src_d_flag,
            { "RCR Index Present", "lbmc.umq_reg_resp.flags.src_d", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_RESP_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_RESP_SRC_D_FLAG, "Set if RCR index present", HFILL } },
        { &hf_lbmc_umq_reg_resp_resp_type,
            { "Registration Response Type", "lbmc.umq_reg_resp.resp_type", FT_UINT8, BASE_DEC, VALS(lbmc_umq_reg_response_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_queue_id,
            { "Queue ID", "lbmc.umq_reg_resp.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_cmd_id,
            { "Command ID", "lbmc.umq_reg_resp.cmd_id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_inst_idx,
            { "Instance Index", "lbmc.umq_reg_resp.inst_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_regid,
            { "Registration ID", "lbmc.umq_reg_resp.regid", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ctx,
            { "Context Registration Response", "lbmc.umq_reg_resp.reg_ctx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ctx_capabilities,
            { "Capabilities", "lbmc.umq_reg_resp.reg_ctx.capabilities", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ctx_ex,
            { "Extended Context Registration Response", "lbmc.umq_reg_resp.reg_ctx_ex", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ctx_ex_capabilities,
            { "Capabilities", "lbmc.umq_reg_resp.reg_ctx_ex.capabilities", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ctx_ex_reserved,
            { "Reserved", "lbmc.umq_reg_resp.reg_ctx_ex.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ctx_ex_flags,
            { "Flags", "lbmc.umq_reg_resp.reg_ctx_ex.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ctx_ex_flags_firstmsg,
            { "First Message", "lbmc.umq_reg_resp.reg_ctx_ex.flags.firstmsg", FT_BOOLEAN, L_LBMC_CNTL_UMQ_REG_RESP_CTX_EX_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_REG_RESP_CTX_EX_FLAG_FIRSTMSG, "Set if first message", HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ctx_ex_stamp,
            { "Stamp", "lbmc.umq_reg_resp.reg_ctx_ex.stamp", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_err,
            { "Registration Error Response", "lbmc.umq_reg_resp.err", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_err_reserved,
            { "Reserved", "lbmc.umq_reg_resp.err.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_err_code,
            { "Code", "lbmc.umq_reg_resp.err.code", FT_UINT16, BASE_HEX_DEC, VALS(lbmc_umq_reg_response_error_code), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_src,
            { "Source Registration Response", "lbmc.umq_reg_resp.reg_src", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_src_rcr_idx,
            { "RCR Index", "lbmc.umq_reg_resp.reg_src.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_rcv,
            { "Receiver Registration Response", "lbmc.umq_reg_resp.reg_rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_rcv_rcr_idx,
            { "RCR Index", "lbmc.umq_reg_resp.reg_rcv.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_reg_resp.reg_rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_rcv_appset_idx,
            { "Application Set Index", "lbmc.umq_reg_resp.reg_rcv.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_rcv_reserved,
            { "Reserved", "lbmc.umq_reg_resp.reg_rcv.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_rcv_dereg,
            { "Receiver Deregistration Response", "lbmc.umq_reg_resp.rcv_dereg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_rcv_dereg_rcr_idx,
            { "RCR Index", "lbmc.umq_reg_resp.rcv_dereg.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_rcv_dereg_assign_id,
            { "Assignment ID", "lbmc.umq_reg_resp.rcv_dereg.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ulb_rcv,
            { "ULB Receiver Registration Response", "lbmc.umq_reg_resp.reg_ulb_rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ulb_rcv_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_reg_resp.reg_ulb_rcv.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ulb_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_reg_resp.reg_ulb_rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ulb_rcv_appset_idx,
            { "Application Set Index", "lbmc.umq_reg_resp.reg_ulb_rcv.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ulb_rcv_reserved,
            { "Reserved", "lbmc.umq_reg_resp.reg_ulb_rcv.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_ulb_rcv_capabilities,
            { "Capabilities", "lbmc.umq_reg_resp.reg_ulb_rcv.capabilities", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_ulb_rcv_dereg,
            { "ULB Receiver Deregistration Response", "lbmc.umq_reg_resp.ulb_rcv_dereg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_ulb_rcv_dereg_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_reg_resp.ulb_rcv_dereg.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_ulb_rcv_dereg_assign_id,
            { "Assignment ID", "lbmc.umq_reg_resp.ulb_rcv_dereg.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_observer_rcv,
            { "Observer Receiver Registration Response", "lbmc.umq_reg_resp.reg_observer_rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_observer_rcv_rcr_idx,
            { "RCR Index", "lbmc.umq_reg_resp.reg_observer_rcv.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_observer_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_reg_resp.reg_observer_rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_observer_rcv_appset_idx,
            { "Application Set Index", "lbmc.umq_reg_resp.reg_observer_rcv.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_reg_observer_rcv_reserved,
            { "Reserved", "lbmc.umq_reg_resp.reg_observer_rcv.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_observer_rcv_dereg,
            { "Observer Receiver Deregistration Response", "lbmc.umq_reg_resp.observer_rcv_dereg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_observer_rcv_dereg_rcr_idx,
            { "RCR Index", "lbmc.umq_reg_resp.observer_rcv_dereg.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_reg_resp_observer_rcv_dereg_assign_id,
            { "Assignment ID", "lbmc.umq_reg_resp.observer_rcv_dereg.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack,
            { "UMQ ACK", "lbmc.umq_ack", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_next_hdr,
            { "Next Header", "lbmc.umq_ack.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_hdr_len,
            { "Header Length", "lbmc.umq_ack.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_msgs,
            { "Msgs", "lbmc.umq_ack.msgs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_msgs_ignore,
            { "Ignore", "lbmc.umq_ack.msgs.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_ack_msgs_t_flag,
            { "T Flag", "lbmc.umq_ack.msgs.t_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_ACK_T_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_ack_msgs_d_flag,
            { "D Flag", "lbmc.umq_ack.msgs.d_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ACK_HDR_T_MSGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_ACK_D_FLAG, NULL, HFILL } },
        { &hf_lbmc_umq_ack_msgs_numids,
            { "Number of Message IDs", "lbmc.umq_ack.msgs.num_ids", FT_UINT8, BASE_DEC_HEX, NULL, LBMC_UMQ_ACK_NUMIDS_MASK, NULL, HFILL } },
        { &hf_lbmc_umq_ack_ack_type,
            { "ACK Type", "lbmc.umq_ack.ack_type", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_umq_ack_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_msgid,
            { "Message ID", "lbmc.umq_ack.msgid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_msgid_regid,
            { "Registration ID", "lbmc.umq_ack.msgid.regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_msgid_stamp,
            { "Stamp", "lbmc.umq_ack.msgid.stamp", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_stable,
            { "Stable", "lbmc.umq_ack.stable", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_stable_queue_id,
            { "Queue ID", "lbmc.umq_ack.stable.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_stable_inst_idx,
            { "Instance Index", "lbmc.umq_ack.stable.inst_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_stable_reserved,
            { "Reserved", "lbmc.umq_ack.stable.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_cr,
            { "Consumption Report", "lbmc.umq_ack.cr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_cr_rcr_idx,
            { "RCR Index", "lbmc.umq_ack.cr.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_cr_assign_id,
            { "Assignment ID", "lbmc.umq_ack.cr.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_cr_appset_idx,
            { "Application Set Index", "lbmc.umq_ack.cr.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_cr_reserved,
            { "Reserved", "lbmc.umq_ack.cr.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_ulb_cr,
            { "ULB Consumption Report", "lbmc.umq_ack.ulb_cr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_ulb_cr_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_ack.ulb_cr.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_ulb_cr_assign_id,
            { "Assignment ID", "lbmc.umq_ack.ulb_cr.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_ulb_cr_appset_idx,
            { "Application Set Index", "lbmc.umq_ack.ulb_cr.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ack_ulb_cr_reserved,
            { "Reserved", "lbmc.umq_ack.ulb_cr.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr,
            { "UMQ Receiver Control Record", "lbmc.umq_rcr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_next_hdr,
            { "Next Header", "lbmc.umq_rcr.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_hdr_len,
            { "Header Length", "lbmc.umq_rcr.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_flags,
            { "Flags", "lbmc.umq_rcr.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_flags_ignore,
            { "Ignore", "lbmc.umq_rcr.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_flags_r_flag,
            { "Reassign", "lbmc.umq_rcr.flags.r_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_RCR_R_FLAG, "Set if reassignment", HFILL } },
        { &hf_lbmc_umq_rcr_flags_d_flag,
            { "Receiver Deregister", "lbmc.umq_rcr.flags.d_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_RCR_D_FLAG, "Set if receiver deregistration", HFILL } },
        { &hf_lbmc_umq_rcr_flags_s_flag,
            { "Resubmit", "lbmc.umq_rcr.flags.s_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_RCR_S_FLAG, "Set if resubmission", HFILL } },
        { &hf_lbmc_umq_rcr_flags_eoi_flag,
            { "End of Index", "lbmc.umq_rcr.flags.eoi_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_RCR_EOI_FLAG, "Set if end of index", HFILL } },
        { &hf_lbmc_umq_rcr_flags_boi_flag,
            { "Beginning of Index", "lbmc.umq_rcr.flags.boi_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_RCR_BOI_FLAG, "Set if beginning of index", HFILL } },
        { &hf_lbmc_umq_rcr_queue_id,
            { "Queue ID", "lbmc.umq_rcr.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_rcr_idx,
            { "RCR Index", "lbmc.umq_rcr.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_msgid_regid,
            { "Message ID Registration ID", "lbmc.umq_rcr.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_msgid_stamp,
            { "Message ID Stamp", "lbmc.umq_rcr.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_topic_tsp,
            { "Topic TSP", "lbmc.umq_rcr.topic_tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_q_tsp,
            { "Queue TSP", "lbmc.umq_rcr.q_tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_assign_id,
            { "Assignment ID", "lbmc.umq_rcr.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_appset_idx,
            { "Application Set Index", "lbmc.umq_rcr.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_num_ras,
            { "Number of Reassigns", "lbmc.umq_rcr.num_ras", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rcr_queue_ver,
            { "Queue Version", "lbmc.umq_rcr.queue_ver", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka,
            { "UMQ Keepalive", "lbmc.umq_ka", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_next_hdr,
            { "Next Header", "lbmc.umq_ka.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_hdr_len,
            { "Header Length", "lbmc.umq_ka.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_flags,
            { "Flags", "lbmc.umq_ka.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_flags_ignore,
            { "Ignore", "lbmc.umq_ka.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_flags_r_flag,
            { "Response Requested", "lbmc.umq_ka.flags.r", FT_BOOLEAN, L_LBMC_CNTL_UMQ_KA_HDR_T_FLAGS * 8, TFS(&lbmc_umq_r_flag), LBMC_UMQ_KA_R_FLAG, "Set if response requested", HFILL } },
        { &hf_lbmc_cntl_umq_ka_ka_type,
            { "Keepalive Type", "lbmc.umq_ka.ka_type", FT_UINT8, BASE_HEX_DEC, VALS(lbmc_umq_ka_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_queue_id,
            { "Queue ID", "lbmc.umq_ka.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_regid,
            { "Registration ID", "lbmc.umq_ka.regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_inst_idx,
            { "Instance Index", "lbmc.umq_ka.inst_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_cntl_umq_ka_reserved,
            { "Reserved", "lbmc.umq_ka.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_src,
            { "Source", "lbmc.umq_ka.src", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_src_transport_idx,
            { "Transport Index", "lbmc.umq_ka.src.transport_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_src_topic_idx,
            { "Topic Index", "lbmc.umq_ka.src.topic_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_rcv,
            { "Receiver", "lbmc.umq_ka.rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_rcv_rcr_idx,
            { "RCR Index", "lbmc.umq_ka.rcv.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_ka.rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_ulb_rcv,
            { "ULB Receiver", "lbmc.umq_ka.ulb_rcv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_ulb_rcv_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_ka.ulb_rcv.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_ulb_rcv_assign_id,
            { "Assignment ID", "lbmc.umq_ka.ulb_rcv.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_ulb_rcv_resp,
            { "ULB Receiver Response", "lbmc.umq_ka.ulb_rcv_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_ulb_rcv_resp_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_ka.ulb_rcv_resp.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_ulb_rcv_resp_assign_id,
            { "Assignment ID", "lbmc.umq_ka.ulb_rcv_resp.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_ulb_rcv_resp_appset_idx,
            { "Application Set Index", "lbmc.umq_ka.ulb_rcv_resp.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ka_ulb_rcv_resp_reserved,
            { "Reserved", "lbmc.umq_ka.ulb_rcv_resp.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq,
            { "UMQ Retransmission Request", "lbmc.umq_rxreq", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_next_hdr,
            { "Next Header", "lbmc.umq_rxreq.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_hdr_len,
            { "Header Length", "lbmc.umq_rxreq.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_flags,
            { "Flags", "lbmc.umq_rxreq.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_flags_ignore,
            { "Ignore", "lbmc.umq_rxreq.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_flags_r_flag,
            { "RegID Present", "lbmc.umq_rxreq.flags.r", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RXREQ_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_RXREQ_R_FLAG, "Set if registration ID is present", HFILL } },
        { &hf_lbmc_umq_rxreq_rxreq_type,
            { "Retransmission Request Type", "lbmc.umq_rxreq.rxreq_type", FT_UINT8, BASE_HEX_DEC, VALS(lbmc_umq_rxreq_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_regid_resp,
            { "RegID Response", "lbmc.umq_rxreq.regid_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_regid_resp_regid,
            { "Registration ID", "lbmc.umq_rxreq.regid_resp.regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_addr_resp,
            { "Address Response", "lbmc.umq_rxreq.addr_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_addr_resp_ip,
            { "IP Address", "lbmc.umq_rxreq.addr_resp.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_addr_resp_port,
            { "Port", "lbmc.umq_rxreq.addr_resp.port", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_addr_resp_reserved,
            { "Reserved", "lbmc.umq_rxreq.addr_resp.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_mr,
            { "Message Request", "lbmc.umq_rxreq.mr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_mr_assign_id,
            { "Assignment ID", "lbmc.umq_rxreq.mr.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_mr_msgid_regid,
            { "Message ID Registration ID", "lbmc.umq_rxreq.mr.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_mr_msgid_stamp,
            { "Message ID Stamp", "lbmc.umq_rxreq.mr.msgid_stamp", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr,
            { "ULB MR", "lbmc.umq_rxreq.ulb_mr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_rxreq.ulb_mr.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_assign_id,
            { "Assignment ID", "lbmc.umq_rxreq.ulb_mr.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_appset_idx,
            { "Application Set Index", "lbmc.umq_rxreq.ulb_mr.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_reserved,
            { "Reserved", "lbmc.umq_rxreq.ulb_mr.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_msgid_regid,
            { "Message ID Registration ID", "lbmc.umq_rxreq.ulb_mr.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_msgid_stamp,
            { "Message ID Stamp", "lbmc.umq_rxreq.ulb_mr.msgid_stamp", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_abort,
            { "ULB MR Abort", "lbmc.umq_rxreq.ulb_mr_abort", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_abort_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_rxreq.ulb_mr_abort.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_abort_assign_id,
            { "Assignment ID", "lbmc.umq_rxreq.ulb_mr_abort.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_abort_msgid_regid,
            { "Message ID Registration ID", "lbmc.umq_rxreq.ulb_mr_abort.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_mr_abort_msgid_stamp,
            { "Message ID Stamp", "lbmc.umq_rxreq.ulb_mr_abort.msgid_stamp", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_qrcrr,
            { "Queue RCR Request", "lbmc.umq_rxreq.qrrcr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_qrcrr_tsp,
            { "TSP", "lbmc.umq_rxreq.qrrcr.tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_trcrr,
            { "Topic RCR Request", "lbmc.umq_rxreq.trcrr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_trcrr_rcr_idx,
            { "RCR Index", "lbmc.umq_rxreq.trcrr.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_trcrr_tsp,
            { "TSP", "lbmc.umq_rxreq.trcrr.tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_trcrr,
            { "ULB Topic RCR Request", "lbmc.umq_rxreq.ulb_trcrr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_trcrr_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_rxreq.ulb_trcrr.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_trcrr_assign_id,
            { "Assignment ID", "lbmc.umq_rxreq.ulb_trcrr.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_trcrr_tsp,
            { "TSP", "lbmc.umq_rxreq.ulb_trcrr.tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_trcrr_abort,
            { "ULB TRCRR Abort", "lbmc.umq_rxreq.ulb_trcrr_abort", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_trcrr_abort_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_rxreq.ulb_trcrr_abort.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_trcrr_abort_assign_id,
            { "Assignment ID", "lbmc.umq_rxreq.ulb_trcrr_abort.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_rxreq_ulb_trcrr_abort_tsp,
            { "TSP", "lbmc.umq_rxreq.ulb_trcrr_abort.tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_qmgmt,
            { "Queue Management", "lbmc.umq_qmgmt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_qmgmt_next_hdr,
            { "Next Header", "lbmc.umq_qmgmt.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_qmgmt_hdr_len,
            { "Header Length", "lbmc.umq_qmgmt.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req,
            { "UMQ Resubmission Request", "lbmc.umq_resub_req", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_next_hdr,
            { "Next Header", "lbmc.umq_resub_req.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_hdr_len,
            { "Header Length", "lbmc.umq_resub_req.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_flags,
            { "Flags", "lbmc.umq_resub_req.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_flags_ignore,
            { "Ignore", "lbmc.umq_resub_req.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RESUB_REQ_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_msgid_regid,
            { "Message ID Registration ID", "lbmc.umq_resub_req.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_msgid_stamp,
            { "Message ID Stamp", "lbmc.umq_resub_req.msgid_stamp", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_rcr_idx,
            { "RCR Index", "lbmc.umq_resub_req.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_resp_ip,
            { "Response IP Address", "lbmc.umq_resub_req.resp_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_resp_port,
            { "Response Port", "lbmc.umq_resub_req.resp_port", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_req_appset_idx,
            { "Application Set Index", "lbmc.umq_resub_req.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp,
            { "UMQ Resubmission Response", "lbmc.umq_resub_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_next_hdr,
            { "Next Header", "lbmc.umq_resub_resp.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_hdr_len,
            { "Header Length", "lbmc.umq_resub_resp.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_flags,
            { "Flags", "lbmc.umq_resub_resp.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_flags_ignore,
            { "Ignore", "lbmc.umq_resub_resp.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_RESUB_RESP_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_code,
            { "Code", "lbmc.umq_resub_resp.code", FT_UINT8, BASE_HEX_DEC, VALS(lbmc_umq_resub_response_code), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_msgid_regid,
            { "Message ID Registration ID", "lbmc.umq_resub_resp.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_msgid_stamp,
            { "Message ID Stamp", "lbmc.umq_resub_resp.msgid_stamp", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_rcr_idx,
            { "RCR Index", "lbmc.umq_resub_resp.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_reserved,
            { "Reserved", "lbmc.umq_resub_resp.resp_ip", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_resub_resp_appset_idx,
            { "Application Set Index", "lbmc.umq_resub_resp.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_interest,
            { "Topic Interest", "lbmc.topic_interest", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_interest_next_hdr,
            { "Next Header", "lbmc.topic_interest.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_interest_hdr_len,
            { "Header Length", "lbmc.topic_interest.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_interest_flags,
            { "Flags", "lbmc.topic_interest.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_interest_flags_ignore,
            { "Ignore", "lbmc.topic_interest.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_topic_interest_flags_cancel,
            { "Cancel", "lbmc.topic_interest.flags.cancel", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_TOPIC_INTEREST_CANCEL_FLAG, "Set if cancelling interest", HFILL } },
        { &hf_lbmc_topic_interest_flags_refresh,
            { "Refresh", "lbmc.topic_interest.flags.refresh", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_INTEREST_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_TOPIC_INTEREST_REFRESH_FLAG, "Set if refreshing interest", HFILL } },
        { &hf_lbmc_topic_interest_domain_id,
            { "Domain ID", "lbmc.topic_interest.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_interest,
            { "Pattern Interest", "lbmc.pattern_interest", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_interest_next_hdr,
            { "Next Header", "lbmc.pattern_interest.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_interest_hdr_len,
            { "Header Length", "lbmc.pattern_interest.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_interest_flags,
            { "Flags", "lbmc.pattern_interest.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_interest_flags_ignore,
            { "Ignore", "lbmc.pattern_interest.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_pattern_interest_flags_cancel,
            { "Cancel", "lbmc.pattern_interest.flags.cancel", FT_BOOLEAN, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_PATTERN_INTEREST_CANCEL_FLAG, "Set if cancelling interest", HFILL } },
        { &hf_lbmc_pattern_interest_flags_refresh,
            { "Refresh", "lbmc.pattern_interest.flags.refresh", FT_BOOLEAN, L_LBMC_CNTL_PATTERN_INTEREST_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_PATTERN_INTEREST_REFRESH_FLAG, "Set if refreshing interest", HFILL } },
        { &hf_lbmc_pattern_interest_type,
            { "Type", "lbmc.pattern_interest.type", FT_UINT8, BASE_DEC_HEX, VALS(lbm_wildcard_pattern_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_interest_domain_id,
            { "Domain ID", "lbmc.pattern_interest.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_interest_index,
            { "Index", "lbmc.pattern_interest.index", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement,
            { "Advertisement", "lbmc.advertisement", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_next_hdr,
            { "Next Header", "lbmc.advertisement.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_hdr_len,
            { "Header Length", "lbmc.advertisement.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_flags,
            { "Flags", "lbmc.advertisement.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_flags_ignore,
            { "Ignore", "lbmc.advertisement.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_advertisement_flags_eos,
            { "EOS", "lbmc.advertisement.flags.eos", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_EOS_FLAG, "Set if source EOS is being advertised", HFILL } },
        { &hf_lbmc_advertisement_flags_pattern,
            { "Pattern", "lbmc.advertisement.flags.pattern", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_PATTERN_FLAG, "Set if the topic being advertised matched a pattern", HFILL } },
        { &hf_lbmc_advertisement_flags_change,
            { "Change", "lbmc.advertisement.flags.change", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_CHANGE_FLAG, "Set if the advertisement indicates a change", HFILL } },
        { &hf_lbmc_advertisement_flags_ctxinst,
            { "Context Instance", "lbmc.advertisement.flags.ctxinst", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_CTXINST_FLAG, NULL, HFILL } },
        { &hf_lbmc_advertisement_hop_count,
            { "Hop Count", "lbmc.advertisement.hop_count", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_ad_flags,
            { "Ad Flags", "lbmc.advertisement.ad_flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_ad_flags_lj,
            { "Late Join", "lbmc.advertisement.ad_flags.lj", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_AD_LJ_FLAG, "Set if source provides late join", HFILL } },
        { &hf_lbmc_advertisement_ad_flags_ume,
            { "UME", "lbmc.advertisement.ad_flags.ume", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_AD_UME_FLAG, "Set if a UME source", HFILL } },
        { &hf_lbmc_advertisement_ad_flags_acktosrc,
            { "ACK To Source", "lbmc.advertisement.ad_flags.acktosrc", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_AD_ACKTOSRC_FLAG, "Set if ACKs are sent to source", HFILL } },
        { &hf_lbmc_advertisement_ad_flags_queue,
            { "Queue", "lbmc.advertisement.ad_flags.queue", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_AD_QUEUE_FLAG, "Set if a queue", HFILL } },
        { &hf_lbmc_advertisement_ad_flags_ulb,
            { "ULB", "lbmc.advertisement.ad_flags.ulb", FT_BOOLEAN, L_LBMC_CNTL_ADVERTISEMENT_HDR_T_AD_FLAGS * 8, TFS(&tfs_set_notset), LBMC_ADVERTISEMENT_AD_ULB_FLAG, "Set if a ULB source", HFILL } },
        { &hf_lbmc_advertisement_cost,
            { "Cost", "lbmc.advertisement.cost", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_transport_idx,
            { "Transport Index", "lbmc.advertisement.transport_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_topic_idx,
            { "Topic Index", "lbmc.advertisement.topic_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_low_seqno,
            { "Low Sequence Number", "lbmc.advertisement.low_seqno", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_high_seqno,
            { "High Sequence Number", "lbmc.advertisement.high_seqno", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_domain_id,
            { "Domain ID", "lbmc.advertisement.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_pat_idx,
            { "Pattern Index", "lbmc.advertisement.pat_idx", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_advertisement_ctxinst,
            { "Context Instance", "lbmc.advertisement.ctxinst", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storename,
            { "Store Name", "lbmc.ume_storename", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storename_next_hdr,
            { "Next Header", "lbmc.ume_storename.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storename_hdr_len,
            { "Header Length", "lbmc.ume_storename.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storename_flags,
            { "Flags", "lbmc.ume_storename.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_storename_flags_ignore,
            { "Ignore", "lbmc.ume_storename.flags.ignore", FT_BOOLEAN, L_LBMC_UME_STORENAME_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_storename_store,
            { "Store Name", "lbmc.ume_storename.store", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr,
            { "UMQ ULB Receiver Control Record", "lbmc.umq_ulb_rcr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_next_hdr,
            { "Next Header", "lbmc.umq_ulb_rcr.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_hdr_len,
            { "Header Length", "lbmc.umq_ulb_rcr.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_flags,
            { "Flags", "lbmc.umq_ulb_rcr.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_flags_ignore,
            { "Ignore", "lbmc.umq_ulb_rcr.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_flags_r_flag,
            { "Reassign", "lbmc.umq_ulb_rcr.flags.r_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_ULB_RCR_R_FLAG, "Reassign", HFILL } },
        { &hf_lbmc_umq_ulb_rcr_flags_d_flag,
            { "Receiver Deregister", "lbmc.umq_ulb_rcr.flags.d_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_ULB_RCR_D_FLAG, "Receiver deregister", HFILL } },
        { &hf_lbmc_umq_ulb_rcr_flags_eoi_flag,
            { "End of Index", "lbmc.umq_ulb_rcr.flags.eoi_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_ULB_RCR_EOI_FLAG, "End of index", HFILL } },
        { &hf_lbmc_umq_ulb_rcr_flags_boi_flag,
            { "Beginning of Index", "lbmc.umq_ulb_rcr.flags.boi_flag", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ULB_RCR_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_ULB_RCR_BOI_FLAG, "Beginning of index", HFILL } },
        { &hf_lbmc_umq_ulb_rcr_queue_id,
            { "Queue ID", "lbmc.umq_ulb_rcr.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_ulb_src_id,
            { "ULB Source ID", "lbmc.umq_ulb_rcr.ulb_src_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_msgid_regid,
            { "Message ID Registration ID", "lbmc.umq_ulb_rcr.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_msgid_stamp,
            { "Message ID Stamp", "lbmc.umq_ulb_rcr.msgid_regid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_topic_tsp,
            { "Topic TSP", "lbmc.umq_ulb_rcr.topic_tsp", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_assign_id,
            { "Assignment ID", "lbmc.umq_ulb_rcr.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_appset_idx,
            { "Application Set Index", "lbmc.umq_ulb_rcr.appset_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_ulb_rcr_num_ras,
            { "Number of RAs", "lbmc.umq_ulb_rcr.num_ras", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_lf,
            { "UMQ Load Factor", "lbmc.umq_lf", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_lf_next_hdr,
            { "Next Header", "lbmc.umq_lf.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_lf_hdr_len,
            { "Header Length", "lbmc.umq_lf.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_lf_flags,
            { "Flags", "lbmc.umq_lf.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_lf_flags_ignore,
            { "Ignore", "lbmc.umq_lf.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_LF_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_lf_type,
            { "Type", "lbmc.umq_lf.type", FT_UINT8, BASE_HEX_DEC, VALS(lbmc_umq_lf_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_lf_num_srcs,
            { "Number of Sources", "lbmc.umq_lf.resp_ip", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_lf_lf,
            { "Load Factor", "lbmc.umq_lf.lf", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo,
            { "Context Information", "lbmc.ctxinfo", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_next_hdr,
            { "Next Header", "lbmc.ctxinfo.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_hdr_len,
            { "Header Length", "lbmc.ctxinfo.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags,
            { "Flags", "lbmc.ctxinfo.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags_ignore,
            { "Ignore", "lbmc.ctxinfo.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags_query,
            { "Query", "lbmc.ctxinfo.flags.query", FT_BOOLEAN, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CTXINFO_QUERY_FLAG, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags_addr,
            { "Address", "lbmc.ctxinfo.flags.addr", FT_BOOLEAN, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CTXINFO_ADDR_FLAG, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags_ctxinst,
            { "Context Instance", "lbmc.ctxinfo.flags.ctxinst", FT_BOOLEAN, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CTXINFO_CTXINST_FLAG, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags_name,
            { "Name", "lbmc.ctxinfo.flags.name", FT_BOOLEAN, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CTXINFO_NAME_FLAG, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags_tnwgsrc,
            { "Gateway Source", "lbmc.ctxinfo.flags.tnwgsrc", FT_BOOLEAN, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CTXINFO_TNWGSRC_FLAG, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags_tnwgrcv,
            { "Gateway Receive", "lbmc.ctxinfo.flags.tnwgrcv", FT_BOOLEAN, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CTXINFO_TNWGRCV_FLAG, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_flags_proxy,
            { "Proxy", "lbmc.ctxinfo.flags.proxy", FT_BOOLEAN, L_LBMC_CNTL_CTXINFO_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CTXINFO_PROXY_FLAG, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_reserved,
            { "Reserved", "lbmc.ctxinfo.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_hop_count,
            { "Hop Count", "lbmc.ctxinfo.hop_count", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_port,
            { "Port", "lbmc.ctxinfo.port", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_addr,
            { "Address", "lbmc.ctxinfo.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_domain_id,
            { "Domain ID", "lbmc.ctxinfo.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_ctxinst,
            { "Context Instance", "lbmc.ctxinfo.ctxinst", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ctxinfo_name,
            { "Name", "lbmc.ctxinfo.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser,
            { "UME Proxy Source Election Record", "lbmc.ume_pser", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_next_hdr,
            { "Next Header", "lbmc.ume_pser.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_hdr_len,
            { "Header Length", "lbmc.ume_pser.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_flags,
            { "Flags", "lbmc.ume_pser.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_flags_ignore,
            { "Ignore", "lbmc.ume_pser.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_pser_flags_source_ctxinst,
            { "Source Context Instance", "lbmc.ume_pser.flags.source_ctxinst", FT_BOOLEAN, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_PSER_SOURCE_CTXINST_FLAG, NULL, HFILL } },
        { &hf_lbmc_ume_pser_flags_store_ctxinst,
            { "Store Context Instance", "lbmc.ume_pser.flags.store_ctxinst", FT_BOOLEAN, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_PSER_STORE_CTXINST_FLAG, NULL, HFILL } },
        { &hf_lbmc_ume_pser_flags_reelect,
            { "Reelection", "lbmc.ume_pser.flags.reelect", FT_BOOLEAN, L_LBMC_CNTL_UME_PSER_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UME_PSER_REELECT_FLAG, NULL, HFILL } },
        { &hf_lbmc_ume_pser_source_ip,
            { "Source Address", "lbmc.ume_pser.source_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_store_ip,
            { "Store Address", "lbmc.ume_pser.store_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_transport_idx,
            { "Transport Index", "lbmc.ume_pser.transport_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_topic_idx,
            { "Topic Index", "lbmc.ume_pser.topic_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_source_port,
            { "Source Port", "lbmc.ume_pser.source_port", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_store_port,
            { "Store Port", "lbmc.ume_pser.store_port", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_source_ctxinst,
            { "Source Context Instance", "lbmc.ume_pser.source_ctxinst", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_pser_store_ctxinst,
            { "Store Context Instance", "lbmc.ume_pser.store_ctxinst", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_domain,
            { "Domain", "lbmc.domain", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_domain_next_hdr,
            { "Next Header", "lbmc.domain.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_domain_hdr_len,
            { "Header Length", "lbmc.domain.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_domain_flags,
            { "Flags", "lbmc.domain.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_domain_flags_ignore,
            { "Ignore", "lbmc.domain.flags.ignore", FT_BOOLEAN, L_LBMC_DOMAIN_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_domain_flags_active,
            { "Active", "lbmc.domain.flags.active", FT_BOOLEAN, L_LBMC_DOMAIN_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_DOMAIN_ACTIVE_FLAG, NULL, HFILL } },
        { &hf_lbmc_domain_domain,
            { "Domain ID", "lbmc.domain.domain", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities,
            { "TNWG Capabilities", "lbmc.tnwg_capabilities", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_next_hdr,
            { "Next Header", "lbmc.tnwg_capabilities.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_hdr_len,
            { "Header Length", "lbmc.tnwg_capabilities.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_flags,
            { "Flags", "lbmc.tnwg_capabilities.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_flags_ignore,
            { "Ignore", "lbmc.tnwg_capabilities.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_flags_version,
            { "Version", "lbmc.tnwg_capabilities.flags.version", FT_UINT16, BASE_DEC, NULL, LBMC_CNTL_TNWG_CAPABILITIES_VERSION_MASK, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_capabilities1,
            { "Capabilities1", "lbmc.tnwg_capabilities.capabilities1", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_capabilities1_ume,
            { "UME", "lbmc.tnwg_capabilities.capabilities1.ume", FT_BOOLEAN, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1 * 8, TFS(&tfs_set_notset), LBMC_CNTL_TNWG_CAPABILITIES1_UME_FLAG, "Set if UME is supported", HFILL } },
        { &hf_lbmc_tnwg_capabilities_capabilities1_umq,
            { "UMQ", "lbmc.tnwg_capabilities.capabilities1.umq", FT_BOOLEAN, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES1 * 8, TFS(&tfs_set_notset), LBMC_CNTL_TNWG_CAPABILITIES1_UMQ_FLAG, "Set if UMQ is supported", HFILL } },
        { &hf_lbmc_tnwg_capabilities_capabilities2,
            { "Capabilities2", "lbmc.tnwg_capabilities.capabilities2", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_capabilities3,
            { "Capabilities3", "lbmc.tnwg_capabilities.capabilities3", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_capabilities_capabilities3_pcre,
            { "PCRE", "lbmc.tnwg_capabilities.capabilities3.pcre", FT_BOOLEAN, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3 * 8, TFS(&tfs_set_notset), LBMC_CNTL_TNWG_CAPABILITIES3_PCRE_FLAG, "Set if PCRE patterns are supported", HFILL } },
        { &hf_lbmc_tnwg_capabilities_capabilities3_regex,
            { "Regex", "lbmc.tnwg_capabilities.capabilities3.regex", FT_BOOLEAN, L_LBMC_CNTL_TNWG_CAPABILITIES_HDR_T_CAPABILITIES3 * 8, TFS(&tfs_set_notset), LBMC_CNTL_TNWG_CAPABILITIES3_REGEX_FLAG, "Set if Regex patters are supported", HFILL } },
        { &hf_lbmc_tnwg_capabilities_capabilities4,
            { "Capabilities4", "lbmc.tnwg_capabilities.capabilities4", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_patidx,
            { "Pattern Index", "lbmc.patidx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_patidx_next_hdr,
            { "Next Header", "lbmc.patidx.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_patidx_hdr_len,
            { "Header Length", "lbmc.patidx.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_patidx_flags,
            { "Flags", "lbmc.patidx.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_patidx_flags_ignore,
            { "Ignore", "lbmc.patidx.flags.ignore", FT_BOOLEAN, L_LBMC_PATIDX_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_patidx_patidx,
            { "Source Index", "lbmc.patidx.patidx", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_client_lifetime,
            { "UME Client Lifetime", "lbmc.ume_client_lifetime", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_client_lifetime_next_hdr,
            { "Next Header", "lbmc.ume_client_lifetime.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_client_lifetime_hdr_len,
            { "Header Length", "lbmc.ume_client_lifetime.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_client_lifetime_flags,
            { "Flags", "lbmc.ume_client_lifetime.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_client_lifetime_flags_ignore,
            { "Ignore", "lbmc.ume_client_lifetime.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_CLIENT_LIFETIME_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_client_lifetime_activity_tmo,
            { "Activity Timeout", "lbmc.ume_client_lifetime.activity_tmo", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_client_lifetime_lifetime,
            { "Lifetime", "lbmc.ume_client_lifetime.lifetime", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_client_lifetime_ttl,
            { "Time to Live", "lbmc.ume_client_lifetime.ttl", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_sid,
            { "UME Session ID", "lbmc.ume_sid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_sid_next_hdr,
            { "Next Header", "lbmc.ume_sid.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_sid_hdr_len,
            { "Header Length", "lbmc.ume_sid.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_sid_flags,
            { "Flags", "lbmc.ume_sid.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_sid_flags_ignore,
            { "Ignore", "lbmc.ume_sid.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_SID_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_sid_sid,
            { "Session ID", "lbmc.ume_sid.sid", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd,
            { "UMQ Index Command", "lbmc.umq_idx_cmd", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_next_hdr,
            { "Next Header", "lbmc.umq_idx_cmd.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_hdr_len,
            { "Header Length", "lbmc.umq_idx_cmd.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_flags,
            { "Flags", "lbmc.umq_idx_cmd.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_flags_ignore,
            { "Ignore", "lbmc.umq_idx_cmd.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_IDX_CMD_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_cmd_type,
            { "Command Type", "lbmc.umq_idx_cmd.cmd_type", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_umq_index_cmd_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_queue_id,
            { "Queue ID", "lbmc.umq_idx_cmd.queue_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_cmd_id,
            { "Command ID", "lbmc.umq_idx_cmd.cmd_id", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_inst_idx,
            { "Instance Index", "lbmc.umq_idx_cmd.inst_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_regid,
            { "RegID", "lbmc.umq_idx_cmd.regid", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_stop_assign,
            { "Stop Assign", "lbmc.umq_idx_cmd.stop_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_stop_assign_rcr_idx,
            { "RCR Index", "lbmc.umq_idx_cmd.stop_assign.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_stop_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd.stop_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_start_assign,
            { "Start Assign", "lbmc.umq_idx_cmd.start_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_start_assign_rcr_idx,
            { "RCR Index", "lbmc.umq_idx_cmd.start_assign.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_start_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd.start_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign,
            { "Release Assign", "lbmc.umq_idx_cmd.release_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign_rcr_idx,
            { "RCR Index", "lbmc.umq_idx_cmd.release_assign.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd.release_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign_flags,
            { "Flags", "lbmc.umq_idx_cmd.release_assign.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign_flags_numeric,
            { "Numeric", "lbmc.umq_idx_cmd.release_assign.flags.numeric", FT_BOOLEAN, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBM_UMQ_INDEX_FLAG_NUMERIC, "Set if index is numeric", HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign_index_len,
            { "Index Length", "lbmc.umq_idx_cmd.release_assign.index_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd.release_assign.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign_numeric_index,
            { "Index", "lbmc.umq_idx_cmd.release_assign.numeric_index", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_release_assign_string_index,
            { "Index", "lbmc.umq_idx_cmd.release_assign.string_index", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_stop_assign,
            { "ULB Stop Assign", "lbmc.umq_idx_cmd.ulb_stop_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_stop_assign_src_id,
            { "Source ID", "lbmc.umq_idx_cmd.ulb_stop_assign.src_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_stop_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd.ulb_stop_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_stop_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd.ulb_stop_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_stop_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd.ulb_stop_assign.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_start_assign,
            { "ULB Start Assign", "lbmc.umq_idx_cmd.ulb_start_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_start_assign_src_id,
            { "Source ID", "lbmc.umq_idx_cmd.ulb_start_assign.src_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_start_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd.ulb_start_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_start_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd.ulb_start_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_start_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd.ulb_start_assign.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign,
            { "ULB Release Assign", "lbmc.umq_idx_cmd.ulb_release_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_src_id,
            { "Source ID", "lbmc.umq_idx_cmd.ulb_release_assign.src_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd.ulb_release_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_flags,
            { "Flags", "lbmc.umq_idx_cmd.ulb_release_assign.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_flags_numeric,
            { "Numeric", "lbmc.umq_idx_cmd.ulb_release_assign.flags.numeric", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RELEASE_IDX_ASSIGN_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBM_UMQ_INDEX_FLAG_NUMERIC, "Set if index is numeric", HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd.ulb_release_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_index_len,
            { "Index Length", "lbmc.umq_idx_cmd.ulb_release_assign.index_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd.ulb_release_assign.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_numeric_index,
            { "Index", "lbmc.umq_idx_cmd.ulb_release_assign.numeric_index", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_release_assign_string_index,
            { "Index", "lbmc.umq_idx_cmd.ulb_release_assign.string_index", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign,
            { "Reserve Assign", "lbmc.umq_idx_cmd.reserve_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign_rcr_idx,
            { "RCR Index", "lbmc.umq_idx_cmd.reserve_assign.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd.reserve_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign_flags,
            { "Flags", "lbmc.umq_idx_cmd.reserve_assign.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign_flags_numeric,
            { "Numeric", "lbmc.umq_idx_cmd.reserve_assign.flags.numeric", FT_BOOLEAN, L_LBMC_CNTL_UMQ_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBM_UMQ_INDEX_FLAG_NUMERIC, "Set if index is numeric", HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign_index_len,
            { "Index Length", "lbmc.umq_idx_cmd.reserve_assign.index_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd.reserve_assign.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign_numeric_index,
            { "Index", "lbmc.umq_idx_cmd.reserve_assign.numeric_index", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_reserve_assign_string_index,
            { "Index", "lbmc.umq_idx_cmd.reserve_assign.string_index", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign,
            { "ULB Reserve Assign", "lbmc.umq_idx_cmd.ulb_reserve_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_src_id,
            { "Source ID", "lbmc.umq_idx_cmd.ulb_reserve_assign.src_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd.ulb_reserve_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_flags,
            { "Flags", "lbmc.umq_idx_cmd.ulb_reserve_assign.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_flags_numeric,
            { "Numeric", "lbmc.umq_idx_cmd.ulb_reserve_assign.flags.numeric", FT_BOOLEAN, L_LBMC_CNTL_UMQ_ULB_IDX_CMD_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBM_UMQ_INDEX_FLAG_NUMERIC, "Set if index is numeric", HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd.ulb_reserve_assign.index_len", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_index_len,
            { "Index Length", "lbmc.umq_idx_cmd.ulb_reserve_assign.index_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd.ulb_reserve_assign.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_numeric_index,
            { "Index", "lbmc.umq_idx_cmd.ulb_reserve_assign.numeric_index", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_ulb_reserve_assign_string_index,
            { "Index", "lbmc.umq_idx_cmd.ulb_reserve_assign.string_index", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp,
            { "UMQ Index Command Response", "lbmc.umq_idx_cmd_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_next_hdr,
            { "Next Header", "lbmc.umq_idx_cmd_resp.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_hdr_len,
            { "Header Length", "lbmc.umq_idx_cmd_resp.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_flags,
            { "Flags", "lbmc.umq_idx_cmd_resp.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_flags_ignore,
            { "Ignore", "lbmc.umq_idx_cmd_resp.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_flags_ulb,
            { "ULB", "lbmc.umq_idx_cmd_resp.flags.ulb", FT_BOOLEAN, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_UMQ_IDX_CMD_RESP_ERR_L_FLAG, "Set if ULB", HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_resp_type,
            { "Response Type", "lbmc.umq_idx_cmd_resp.resp_type", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_umq_index_cmd_response_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_queue_id,
            { "Queue ID", "lbmc.umq_idx_cmd_resp.queue_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_cmd_id,
            { "Command ID", "lbmc.umq_idx_cmd_resp.cmd_id", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_inst_idx,
            { "Instance Index", "lbmc.umq_idx_cmd_resp.inst_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_regid,
            { "RegID", "lbmc.umq_idx_cmd_resp.regid", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_err,
            { "Error", "lbmc.umq_idx_cmd_resp.err", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_err_reserved,
            { "Reserved", "lbmc.umq_idx_cmd_resp.err.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_err_code,
            { "Code", "lbmc.umq_idx_cmd_resp.err.code", FT_UINT16, BASE_DEC_HEX, VALS(lbmc_umq_idx_cmd_response_error_code), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_err_error_string,
            { "Error String", "lbmc.umq_idx_cmd_resp.err.error_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_stop_assign,
            { "Stop Assign", "lbmc.umq_idx_cmd_resp.stop_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_stop_assign_rcr_idx,
            { "RCR Index", "lbmc.umq_idx_cmd_resp.stop_assign.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_stop_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd_resp.stop_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_start_assign,
            { "Start Assign", "lbmc.umq_idx_cmd_resp.start_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_start_assign_rcr_idx,
            { "RCR Index", "lbmc.umq_idx_cmd_resp.start_assign.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_start_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd_resp.start_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_start_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd_resp.start_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_start_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd_resp.start_assign.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_release_assign,
            { "Release Assign", "lbmc.umq_idx_cmd_resp.release_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_release_assign_rcr_idx,
            { "RCR Index", "lbmc.umq_idx_cmd_resp.release_assign.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_release_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd_resp.release_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_release_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd_resp.release_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_release_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd_resp.release_assign.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign,
            { "ULB Stop Assign", "lbmc.umq_idx_cmd_resp.ulb_stop_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_src_id,
            { "Source ID", "lbmc.umq_idx_cmd_resp.ulb_stop_assign.src_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd_resp.ulb_stop_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd_resp.ulb_stop_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_stop_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd_resp.ulb_stop_assign.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_start_assign,
            { "ULB Start Assign", "lbmc.umq_idx_cmd_resp.ulb_start_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_src_id,
            { "Source ID", "lbmc.umq_idx_cmd_resp.ulb_start_assign.src_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd_resp.ulb_start_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd_resp.ulb_start_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_start_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd_resp.ulb_start_assign.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_release_assign,
            { "ULB Release Assign", "lbmc.umq_idx_cmd_resp.ulb_release_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_src_id,
            { "Source ID", "lbmc.umq_idx_cmd_resp.ulb_release_assign.src_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd_resp.ulb_release_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_appset_idx,
            { "Application Set Index", "lbmc.umq_idx_cmd_resp.ulb_release_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_release_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd_resp.ulb_release_assign.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign,
            { "Reserve Assign", "lbmc.umq_idx_cmd_resp.reserve_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_rcr_idx,
            { "RCR Index", "lbmc.umq_idx_cmd_resp.reserve_assign.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd_resp.reserve_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_flags,
            { "Flags", "lbmc.umq_idx_cmd_resp.reserve_assign.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_flags_numeric,
            { "Numeric", "lbmc.umq_idx_cmd_resp.reserve_assign.flags.numeric", FT_BOOLEAN, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBM_UMQ_INDEX_FLAG_NUMERIC, "Set if index is numeric", HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_appset_idx,
            { "AppSet Index", "lbmc.umq_idx_cmd_resp.reserve_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_index_len,
            { "Index Length", "lbmc.umq_idx_cmd_resp.reserve_assign.index_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd_resp.reserve_assign.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_numeric_index,
            { "Index", "lbmc.umq_idx_cmd_resp.reserve_assign.numeric_index", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_reserve_assign_string_index,
            { "Index", "lbmc.umq_idx_cmd_resp.reserve_assign.string_index", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign,
            { "ULB Reserve Assign", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_src_id,
            { "Source ID", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.src_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_assign_id,
            { "Assignment ID", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags,
            { "Flags", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags_numeric,
            { "Numeric", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.flags.numeric", FT_BOOLEAN, L_LBMC_CNTL_UMQ_IDX_CMD_RESP_ULB_RCV_RESERVE_IDX_ASSIGN_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBM_UMQ_INDEX_FLAG_NUMERIC, "Set if index is numeric", HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_appset_idx,
            { "AppSet Index", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_index_len,
            { "Index Length", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.index_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_reserved,
            { "Reserved", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_numeric_index,
            { "Index", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.numeric_index", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_string_index,
            { "Index", "lbmc.umq_idx_cmd_resp.ulb_reserve_assign.string_index", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_odomain,
            { "Originating Domain", "lbmc.odomain", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_odomain_next_hdr,
            { "Next Header", "lbmc.odomain.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_odomain_hdr_len,
            { "Header Length", "lbmc.odomain.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_odomain_flags,
            { "Flags", "lbmc.odomain.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_odomain_flags_ignore,
            { "Ignore", "lbmc.odomain.flags.ignore", FT_BOOLEAN, L_LBMC_ODOMAIN_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_odomain_domain,
            { "Domain ID", "lbmc.odomain.domain", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_stream,
            { "Stream", "lbmc.stream", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_stream_next_hdr,
            { "Next Header", "lbmc.stream.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_stream_hdr_len,
            { "Header Length", "lbmc.stream.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_stream_flags,
            { "Flags", "lbmc.stream.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_stream_flags_ignore,
            { "Ignore", "lbmc.stream.flags.ignore", FT_BOOLEAN, L_LBMC_STREAM_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_stream_stream_id,
            { "Stream ID", "lbmc.stream.stream_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_stream_sqn,
            { "Sequence Number", "lbmc.stream.sqn", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_stream_ctxinst,
            { "Context Instance", "lbmc.stream.ctxinst", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_md_interest,
            { "Topic Multi-Domain Interest", "lbmc.topic_md_interest", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_md_interest_next_hdr,
            { "Next Header", "lbmc.topic_md_interest.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_md_interest_hdr_len,
            { "Header Length", "lbmc.topic_md_interest.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_md_interest_flags,
            { "Flags", "lbmc.topic_md_interest.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_md_interest_flags_ignore,
            { "Ignore", "lbmc.topic_md_interest.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_topic_md_interest_flags_cancel,
            { "Cancel", "lbmc.topic_md_interest.flags.cancel", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_TOPIC_INTEREST_CANCEL_FLAG, "Set if cancelling interest", HFILL } },
        { &hf_lbmc_topic_md_interest_flags_refresh,
            { "Refresh", "lbmc.topic_md_interest.flags.refresh", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_MD_INTEREST_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_TOPIC_INTEREST_REFRESH_FLAG, "Set if refreshing interest", HFILL } },
        { &hf_lbmc_topic_md_interest_domain_count,
            { "Domain Count", "lbmc.topic_md_interest.domain_count", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_md_interest_res1,
            { "Reserved", "lbmc.topic_md_interest.res1", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_md_interest_domain_id,
            { "Domain ID", "lbmc.topic_md_interest.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest,
            { "Pattern Multi-Domain Interest", "lbmc.pattern_md_interest", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_next_hdr,
            { "Next Header", "lbmc.pattern_md_interest.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_hdr_len,
            { "Header Length", "lbmc.pattern_md_interest.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_flags,
            { "Flags", "lbmc.pattern_md_interest.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_flags_ignore,
            { "Ignore", "lbmc.pattern_md_interest.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_flags_cancel,
            { "Cancel", "lbmc.pattern_md_interest.flags.cancel", FT_BOOLEAN, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_PATTERN_INTEREST_CANCEL_FLAG, "Set if cancelling interest", HFILL } },
        { &hf_lbmc_pattern_md_interest_flags_refresh,
            { "Refresh", "lbmc.pattern_md_interest.flags.refresh", FT_BOOLEAN, L_LBMC_CNTL_PATTERN_MD_INTEREST_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_PATTERN_INTEREST_REFRESH_FLAG, "Set if refreshing interest", HFILL } },
        { &hf_lbmc_pattern_md_interest_type,
            { "Type", "lbmc.pattern_md_interest.type", FT_UINT8, BASE_DEC_HEX, VALS(lbm_wildcard_pattern_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_domain_count,
            { "Domain Count", "lbmc.pattern_md_interest.domain_count", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_res1,
            { "Reserved", "lbmc.pattern_md_interest.res1", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_index,
            { "Index", "lbmc.pattern_md_interest.index", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_pattern_md_interest_domain_id,
            { "Domain ID", "lbmc.pattern_md_interest.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req,
            { "Late Join Information Request", "lbmc.lji_req", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_next_hdr,
            { "Next Header", "lbmc.lji_req.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_hdr_len,
            { "Header Length", "lbmc.lji_req.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_flags,
            { "Flags", "lbmc.lji_req.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_flags_ignore,
            { "Ignore", "lbmc.lji_req.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_lji_req_flags_l_flag,
            { "Low SQN Present", "lbmc.lji_req.flags.l_flag", FT_BOOLEAN, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_LJI_REQ_L_FLAG, "Set if low SQN present", HFILL } },
        { &hf_lbmc_lji_req_flags_m_flag,
            { "RX Request Max Present", "lbmc.lji_req.flags.m_flag", FT_BOOLEAN, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_LJI_REQ_M_FLAG, "Set if RX request max present", HFILL } },
        { &hf_lbmc_lji_req_flags_o_flag,
            { "RX Request Outstanding Max Present", "lbmc.lji_req.flags.o_flag", FT_BOOLEAN, L_LBMC_CNTL_LJI_REQ_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_LJI_REQ_O_FLAG, "Set if outstanding RX request max present", HFILL } },
        { &hf_lbmc_lji_req_request_idx,
            { "Request Index", "lbmc.lji_req.request_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_transport_idx,
            { "Transport Index", "lbmc.lji_req.transport_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_topic_idx,
            { "Topic Index", "lbmc.lji_req.topic_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_req_ip,
            { "Request IP", "lbmc.lji_req.req_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_req_port,
            { "Request Port", "lbmc.lji_req.req_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_res,
            { "Reserved", "lbmc.lji_req.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_tx_low_sqn,
            { "Transmitted Low SQN", "lbmc.lji_req.tx_low_sqn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_rx_req_max,
            { "Maximum RX Requests", "lbmc.lji_req.rx_req_max", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_lji_req_rx_req_outstanding_max,
            { "Maximum Outstanding RX Requests", "lbmc.lji_req.rx_req_outstanding_max", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka,
            { "TNWG Keepalive", "lbmc.tnwg_ka", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_next_hdr,
            { "Next Header", "lbmc.tnwg_ka.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_hdr_len,
            { "Header Length", "lbmc.tnwg_ka.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_flags,
            { "Flags", "lbmc.tnwg_ka.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_flags_ignore,
            { "Ignore", "lbmc.tnwg_ka.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_flags_q_flag,
            { "Query", "lbmc.tnwg_ka.flags.q_flag", FT_BOOLEAN, L_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CNTL_TNWG_KA_Q_FLAG, "Set if a keepalive query", HFILL } },
        { &hf_lbmc_tnwg_ka_flags_r_flag,
            { "Response", "lbmc.tnwg_ka.flags.r_flag", FT_BOOLEAN, L_LBMC_CNTL_TNWG_KA_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_CNTL_TNWG_KA_R_FLAG, "Set if a keepalive response", HFILL } },
        { &hf_lbmc_tnwg_ka_index,
            { "Index", "lbmc.tnwg_ka.index", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_ts_seconds,
            { "TS Seconds", "lbmc.tnwg_ka.ts_seconds", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_ts_microseconds,
            { "TS Microseconds", "lbmc.tnwg_ka.ts_microseconds", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_reserved_1,
            { "Reserved 1", "lbmc.tnwg_ka.reserved_1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_reserved_2,
            { "Reserved 2", "lbmc.tnwg_ka.reserved_2", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_reserved_3,
            { "Reserved 3", "lbmc.tnwg_ka.reserved_3", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_reserved_4,
            { "Reserved 4", "lbmc.tnwg_ka.reserved_4", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_reserved_5,
            { "Reserved 5", "lbmc.tnwg_ka.reserved_5", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tnwg_ka_reserved_6,
            { "Reserved 6", "lbmc.tnwg_ka.reserved_6", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_receiver_keepalive,
            { "UME Receiver Keepalive", "lbmc.ume_receiver_keepalive", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_receiver_keepalive_next_hdr,
            { "Next Header", "lbmc.ume_receiver_keepalive.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_receiver_keepalive_hdr_len,
            { "Header Length", "lbmc.ume_receiver_keepalive.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_receiver_keepalive_flags,
            { "Flags", "lbmc.ume_receiver_keepalive.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_receiver_keepalive_flags_ignore,
            { "Ignore", "lbmc.ume_receiver_keepalive.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_RECEIVER_KEEPALIVE_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_receiver_keepalive_rcv_regid,
            { "Receiver RegID", "lbmc.ume_receiver_keepalive.rcv_regid", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_receiver_keepalive_session_id,
            { "Session ID", "lbmc.ume_receiver_keepalive.session_id", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_receiver_keepalive_ctxinst,
            { "Context Instance", "lbmc.ume_receiver_keepalive.ctxinst", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd,
            { "UMQ Command", "lbmc.umq_cmd", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_next_hdr,
            { "Next Header", "lbmc.umq_cmd.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_hdr_len,
            { "Header Length", "lbmc.umq_cmd.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_flags,
            { "Flags", "lbmc.umq_cmd.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_flags_ignore,
            { "Ignore", "lbmc.umq_cmd.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_CMD_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_cmd_type,
            { "Command", "lbmc.umq_cmd.cmd_type", FT_UINT8, BASE_DEC, VALS(lbmc_umq_cmd_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_queue_id,
            { "Queue ID", "lbmc.umq_cmd.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_cmd_id,
            { "Command ID", "lbmc.umq_cmd.cmd_id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_inst_idx,
            { "Instance index", "lbmc.umq_cmd.inst_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_regid,
            { "Reg ID", "lbmc.umq_cmd.regid", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_topic_list,
            { "Topic List", "lbmc.umq_cmd.topic_list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_topic_list_serial_num,
            { "Serial number", "lbmc.umq_cmd.topic_list.serial_num", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve,
            { "Message Retrieve", "lbmc.umq_cmd.msg_retrieve", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve_rcr_idx,
            { "RCR Index", "lbmc.umq_cmd.msg_retrieve.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve_assign_id,
            { "Assignment ID", "lbmc.umq_cmd.msg_retrieve.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve_info_only,
            { "Info Only", "lbmc.umq_cmd.msg_retrieve.info_only", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve_num_msgids,
            { "Number of Message IDs", "lbmc.umq_cmd.msg_retrieve.num_msgids", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve_flags,
            { "Flags", "lbmc.umq_cmd.msg_retrieve.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve_entry,
            { "Message Retrieve Entry", "lbmc.umq_cmd.msg_retrieve.entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve_entry_regid,
            { "Reg ID", "lbmc.umq_cmd.msg_retrieve.entry.regid", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_retrieve_entry_stamp,
            { "Stamp", "lbmc.umq_cmd.msg_retrieve.entry.stamp", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_list,
            { "Message List", "lbmc.umq_cmd.msg_list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_list_rcr_idx,
            { "RCR Index", "lbmc.umq_cmd.msg_list.rcr_idx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_msg_list_assign_id,
            { "Assign ID", "lbmc.umq_cmd.msg_list.assign_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp,
            { "UMQ Command Response", "lbmc.umq_cmd_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_next_hdr,
            { "Next Header", "lbmc.umq_cmd_resp.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_hdr_len,
            { "Header Length", "lbmc.umq_cmd_resp.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_flags,
            { "Flags", "lbmc.umq_cmd_resp.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_flags_ignore,
            { "Ignore", "lbmc.umq_cmd_resp.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_CMD_RESP_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_resp_type,
            { "Response", "lbmc.umq_cmd_resp.resp_type", FT_UINT8, BASE_DEC, VALS(lbmc_umq_cmd_response_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_queue_id,
            { "Queue ID", "lbmc.umq_cmd_resp.queue_id", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_cmd_id,
            { "Command ID", "lbmc.umq_cmd_resp.cmd_id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_inst_idx,
            { "Instance index", "lbmc.umq_cmd_resp.inst_idx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_regid,
            { "Reg ID", "lbmc.umq_cmd_resp.regid", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_msg_retrieve,
            { "Message Retrieve", "lbmc.umq_cmd_resp.msg_retrieve", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_msg_retrieve_rcr_idx,
            { "RCR Index", "lbmc.umq_cmd_resp.msg_retrieve.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_msg_retrieve_assign_id,
            { "Assignment ID", "lbmc.umq_cmd_resp.msg_retrieve.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve,
            { "Message Retrieve", "lbmc.umq_cmd_resp.xmsg_retrieve", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_num_msgs,
            { "Number of Messages", "lbmc.umq_cmd_resp.xmsg_retrieve.num_msgs", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_flags,
            { "Flags", "lbmc.umq_cmd_resp.xmsg_retrieve.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_reserved,
            { "Reserved", "lbmc.umq_cmd_resp.xmsg_retrieve.reserved", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry,
            { "Message", "lbmc.umq_cmd_resp.xmsg_retrieve.entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_regid,
            { "Reg ID", "lbmc.umq_cmd_resp.xmsg_retrieve.entry.regid", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_stamp,
            { "Stamp", "lbmc.umq_cmd_resp.xmsg_retrieve.entry.stamp", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_assign_id,
            { "Assignment ID", "lbmc.umq_cmd_resp.xmsg_retrieve.entry.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_num_ras,
            { "Number of Reassignments", "lbmc.umq_cmd_resp.xmsg_retrieve.entry.num_ras", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_status,
            { "Status", "lbmc.umq_cmd_resp.xmsg_retrieve.entry.status", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_umq_msg_status_code), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_retrieve_entry_reserved,
            { "Reserved", "lbmc.umq_cmd_resp.xmsg_retrieve.entry.reserved", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_msg_list,
            { "Message List", "lbmc.umq_cmd_resp.msg_list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_msg_list_rcr_idx,
            { "RCR Index", "lbmc.umq_cmd_resp.msg_list.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_msg_list_assign_id,
            { "Assignment ID", "lbmc.umq_cmd_resp.msg_list.assign_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_list,
            { "Message List", "lbmc.umq_cmd_resp.xmsg_list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_list_num_msgs,
            { "Number of Messages", "lbmc.umq_cmd_resp.xmsg_list.num_msgs", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_list_entry,
            { "Message", "lbmc.umq_cmd_resp.xmsg_list.entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_list_entry_regid,
            { "Reg ID", "lbmc.umq_cmd_resp.xmsg_list.entry.regid", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_xmsg_list_entry_stamp,
            { "Stamp", "lbmc.umq_cmd_resp.xmsg_list.entry.stamp", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list,
            { "Topic List", "lbmc.umq_cmd_resp.topic_list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_num_topics,
            { "Number of Topics", "lbmc.umq_cmd_resp.topic_list.num_topics", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry,
            { "Topic List Entry", "lbmc.umq_cmd_resp.topic_list.topic_entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_rcr_idx,
            { "RCR Index", "lbmc.umq_cmd_resp.topic_list.topic_entry.rcr_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_num_appsets,
            { "Number of AppSets", "lbmc.umq_cmd_resp.topic_list.topic_entry.num_appsets", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_topic_len,
            { "Topic Length", "lbmc.umq_cmd_resp.topic_list.topic_entry.topic_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_reserved,
            { "Reserved", "lbmc.umq_cmd_resp.topic_list.topic_entry.reserved", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_topic,
            { "Topic", "lbmc.umq_cmd_resp.topic_list.topic_entry.topic", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry,
            { "Appset Entry", "lbmc.umq_cmd_resp.topic_list.topic_entry.appset_entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_num_receiver_type_ids,
            { "Number of Receiver Type IDs", "lbmc.umq_cmd_resp.topic_list.topic_entry.appset_entry.num_receiver_type_ids", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_appset_idx,
            { "AppSet Index", "lbmc.umq_cmd_resp.topic_list.topic_entry.appset_entry.appset_idx", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_appset_name_len,
            { "AppSet Name Length", "lbmc.umq_cmd_resp.topic_list.topic_entry.appset_entry.appset_name_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_reserved,
            { "Reserved", "lbmc.umq_cmd_resp.topic_list.topic_entry.appset_entry.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_name,
            { "AppSet Name", "lbmc.umq_cmd_resp.topic_list.topic_entry.appset_entry.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry_receiver_type_id,
            { "Receiver Type ID", "lbmc.umq_cmd_resp.topic_list.topic_entry.appset_entry.receiver_type_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_err,
            { "Error", "lbmc.umq_cmd_resp.error", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_err_reserved,
            { "Reserved", "lbmc.umq_cmd_resp.error.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_err_code,
            { "Code", "lbmc.umq_cmd_resp.error.code", FT_UINT16, BASE_DEC_HEX, VALS(lbmc_umq_cmd_response_error_code), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_cmd_resp_err_errmsg,
            { "Error Message", "lbmc.umq_cmd_resp.error.errmsg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_req,
            { "Source Registration Information Request", "lbmc.sri_req", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_req_next_hdr,
            { "Next Header", "lbmc.sri_req.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_req_hdr_len,
            { "Header Length", "lbmc.sri_req.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_req_flags,
            { "Flags", "lbmc.sri_req.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_req_flags_ignore,
            { "Ignore", "lbmc.sri_req.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_SRI_REQ_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_sri_req_transport_idx,
            { "Transport Index", "lbmc.sri_req.transport_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_req_topic_idx,
            { "Topic Index", "lbmc.sri_req.topic_idx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_domain,
            { "UME Store Domain", "lbmc.ume_store_domain", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_domain_next_hdr,
            { "Next Header", "lbmc.ume_store_domain.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_domain_hdr_len,
            { "Header Length", "lbmc.ume_store_domain.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_domain_flags,
            { "Flags", "lbmc.ume_store_domain.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_domain_flags_ignore,
            { "Ignore", "lbmc.ume_store_domain.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_STORE_DOMAIN_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_store_domain_domain,
            { "Domain ID", "lbmc.ume_store_domain.domain", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri,
            { "Source Registration Information", "lbmc.sri", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_next_hdr,
            { "Next Header", "lbmc.sri.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_hdr_len,
            { "Header Length", "lbmc.sri.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_flags,
            { "Flags", "lbmc.sri.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_flags_ignore,
            { "Ignore", "lbmc.sri.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_SRI_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_sri_flags_acktosrc,
            { "ACK to Source", "lbmc.sri.flags.acktosrc", FT_BOOLEAN, L_LBMC_CNTL_SRI_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_SRI_A_FLAG, "If set ACKs are sent to source", HFILL } },
        { &hf_lbmc_sri_flags_initial_sqn_known,
            { "Initial SQN Known", "lbmc.sri.flags.initial_sqn_known", FT_BOOLEAN, L_LBMC_CNTL_SRI_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_SRI_INITIAL_SQN_KNOWN_FLAG, "If set, initial SQN is known", HFILL } },
        { &hf_lbmc_sri_version,
            { "Version", "lbmc.sri.version", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_low_sqn,
            { "Low Sequence Number", "lbmc.sri.low_sqn", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_sri_high_sqn,
            { "High Sequence Number", "lbmc.sri.high_sqn", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info,
            { "Route Information", "lbmc.route_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_next_hdr,
            { "Next Header", "lbmc.route_info.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_hdr_len,
            { "Header Length", "lbmc.route_info.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_flags,
            { "Flags", "lbmc.route_info.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_flags_ignore,
            { "Ignore", "lbmc.route_info.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_ROUTE_INFO_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_route_info_gateway_version,
            { "Gateway Version", "lbmc.route_info.gateway_version", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_configuration_signature,
            { "Configuration Signature", "lbmc.route_info.configuration_signature", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_node_id,
            { "Node ID", "lbmc.route_info.node_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_topology,
            { "Topology", "lbmc.route_info.topology", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_vers,
            { "Version", "lbmc.route_info.vers", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_sqn,
            { "SQN", "lbmc.route_info.sqn", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_ttl,
            { "TTL", "lbmc.route_info.ttl", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_reserved1,
            { "Reserved1", "lbmc.route_info.reserved1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_reserved2,
            { "Reserved2", "lbmc.route_info.reserved2", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_neighbor,
            { "Route Information Neighbor", "lbmc.route_info_neighbor", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_neighbor_next_hdr,
            { "Next Header", "lbmc.route_info_neighbor.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_neighbor_hdr_len,
            { "Header Length", "lbmc.route_info_neighbor.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_neighbor_flags,
            { "Flags", "lbmc.route_info_neighbor.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_neighbor_flags_ignore,
            { "Ignore", "lbmc.route_info_neighbor.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_ROUTE_INFO_NEIGHBOR_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_route_info_neighbor_node_id,
            { "Node ID", "lbmc.route_info_neighbor.node_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_neighbor_ingress_cost,
            { "Ingress Cost", "lbmc.route_info_neighbor.ingress_cost", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_route_info_neighbor_egress_cost,
            { "Egress Cost", "lbmc.route_info_neighbor.egress_cost", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_gateway_name,
            { "Gateway Name", "lbmc.gateway_name", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_gateway_name_next_hdr,
            { "Next Header", "lbmc.gateway_name.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_gateway_name_hdr_len,
            { "Header Length", "lbmc.gateway_name.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_gateway_name_flags,
            { "Flags", "lbmc.gateway_name.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_gateway_name_flags_ignore,
            { "Ignore", "lbmc.gateway_name.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_GATEWAY_NAME_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_gateway_name_gateway_name,
            { "Gateway Name", "lbmc.gateway_name.gateway_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_request,
            { "Authentication Request", "lbmc.auth_request", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_request_next_hdr,
            { "Next Header", "lbmc.auth_request.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_request_hdr_len,
            { "Header Length", "lbmc.auth_request.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_request_flags,
            { "Flags", "lbmc.auth_request.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_request_flags_ignore,
            { "Ignore", "lbmc.auth_request.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_AUTH_REQUEST_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_auth_request_opid,
            { "Operation ID", "lbmc.auth_request.opid", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_auth_operation_id_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_request_user_len,
            { "User Length", "lbmc.auth_request.user_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_request_user_name,
            { "User Name", "lbmc.auth_request.user_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge,
            { "Authentication Challenge", "lbmc.auth_challenge", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_next_hdr,
            { "Next Header", "lbmc.auth_challenge.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_hdr_len,
            { "Header Length", "lbmc.auth_challenge.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_flags,
            { "Flags", "lbmc.auth_challenge.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_flags_ignore,
            { "Ignore", "lbmc.auth_challenge.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_AUTH_CHALLENGE_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_opid,
            { "Operation ID", "lbmc.auth_challenge.opid", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_auth_operation_id_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_mod_len,
            { "Mod Length", "lbmc.auth_challenge.mod_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_gen_len,
            { "Gen Length", "lbmc.auth_challenge.gen_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_salt_len,
            { "Salt Length", "lbmc.auth_challenge.salt_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_pubkey_len,
            { "Pubkey Length", "lbmc.auth_challenge.pubkey_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_mod,
            { "Mod", "lbmc.auth_challenge.mod", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_gen,
            { "Gen", "lbmc.auth_challenge.gen", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_salt,
            { "Salt", "lbmc.auth_challenge.salt", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_pubkey,
            { "Pubkey", "lbmc.auth_challenge.pubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp,
            { "Authentication Challenge Response", "lbmc.auth_challenge_rsp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_next_hdr,
            { "Next Header", "lbmc.auth_challenge_rsp.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_hdr_len,
            { "Header Length", "lbmc.auth_challenge_rsp.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_flags,
            { "Flags", "lbmc.auth_challenge_rsp.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_flags_ignore,
            { "Ignore", "lbmc.auth_challenge_rsp.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_AUTH_CHALLENGE_RSP_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_opid,
            { "Operation ID", "lbmc.auth_challenge_rsp.opid", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_auth_operation_id_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_pubkey_len,
            { "Pubkey Length", "lbmc.auth_challenge_rsp.pubkey_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_evidence_len,
            { "Evidence Length", "lbmc.auth_challenge_rsp.evidence_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_pubkey,
            { "Pubkey", "lbmc.auth_challenge_rsp.pubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_challenge_rsp_evidence,
            { "Evidence", "lbmc.auth_challenge_rsp.evidence", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_result,
            { "Authentication Result", "lbmc.auth_result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_result_next_hdr,
            { "Next Header", "lbmc.auth_result.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_result_hdr_len,
            { "Header Length", "lbmc.auth_result.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_result_flags,
            { "Flags", "lbmc.auth_result.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_result_flags_ignore,
            { "Ignore", "lbmc.auth_result.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_AUTH_RESULT_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_auth_result_opid,
            { "Operation ID", "lbmc.auth_result.opid", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_auth_operation_id_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_result_result,
            { "Result", "lbmc.auth_result.result", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_unknown,
            { "Unknown Authentication Header", "lbmc.auth_unknown", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_unknown_next_hdr,
            { "Next Header", "lbmc.auth_unknown.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_unknown_hdr_len,
            { "Header Length", "lbmc.auth_unknown.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_unknown_flags,
            { "Flags", "lbmc.auth_unknown.flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_unknown_opid,
            { "Operation ID", "lbmc.auth_unknown.opid", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_auth_operation_id_type), 0x0, NULL, HFILL } },
        { &hf_lbmc_auth_unknown_data,
            { "Data", "lbmc.auth_unknown.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_hmac,
            { "HMAC", "lbmc.hmac", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_hmac_next_hdr,
            { "Next Header", "lbmc.hmac.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_hmac_hdr_len,
            { "Header Length", "lbmc.hmac.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_hmac_flags,
            { "Flags", "lbmc.hmac.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_hmac_flags_ignore,
            { "Ignore", "lbmc.hmac.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_HMAC_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_hmac_padding,
            { "Padding", "lbmc.hmac.padding", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_hmac_data,
            { "Data", "lbmc.hmac.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sid,
            { "UMQ Session ID", "lbmc.umq_sid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sid_next_hdr,
            { "Next Header", "lbmc.umq_sid.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sid_hdr_len,
            { "Header Length", "lbmc.umq_sid.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sid_flags,
            { "Flags", "lbmc.umq_sid.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sid_flags_ignore,
            { "Ignore", "lbmc.umq_sid.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UMQ_SID_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE_CHAR, NULL, HFILL } },
        { &hf_lbmc_umq_sid_key,
            { "Key", "lbmc.umq_sid.key", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_umq_sid_sid,
            { "SID", "lbmc.umq_sid.sid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination,
            { "Destination", "lbmc.destination", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_next_hdr,
            { "Next Header", "lbmc.destination.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_hdr_len,
            { "Header Length", "lbmc.destination.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_flags,
            { "Flags", "lbmc.destination.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_flags_ignore,
            { "Ignore", "lbmc.destination.flags.ignore", FT_BOOLEAN, L_LBMC_DESTINATION_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_destination_domain_id,
            { "Domain ID", "lbmc.destination.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_ipaddr,
            { "IP Address", "lbmc.destination.ipaddr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_port,
            { "Port", "lbmc.destination.port", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_hops_taken,
            { "Hops Taken", "lbmc.destination.hops_taken", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_orig_domain_id,
            { "Originating Domain ID", "lbmc.destination.orig_domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_orig_ipaddr,
            { "Originating IP Address", "lbmc.destination.orig_ipaddr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_orig_port,
            { "Originating Port", "lbmc.destination.orig_port", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_destination_reserved,
            { "Reserved", "lbmc.destination.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_idx,
            { "Topic Index", "lbmc.topic_idx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_idx_next_hdr,
            { "Next Header", "lbmc.topic_idx.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_idx_hdr_len,
            { "Header Length", "lbmc.topic_idx.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_idx_flags,
            { "Flags", "lbmc.topic_idx.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_idx_flags_ignore,
            { "Ignore", "lbmc.topic_idx.flags.ignore", FT_BOOLEAN, L_LBMC_TOPIC_IDX_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_topic_idx_tidx,
            { "Topic Index", "lbmc.topic_idx.tidx", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source,
            { "Topic Source", "lbmc.topic_source", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_next_hdr,
            { "Next Header", "lbmc.topic_source.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_hdr_len,
            { "Header Length", "lbmc.topic_source.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_flags,
            { "Flags", "lbmc.topic_source.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_flags_ignore,
            { "Ignore", "lbmc.topic_source.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_topic_source_flags_eos,
            { "End of Stream", "lbmc.topic_source.flags.eos", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_SOURCE_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_TOPIC_SOURCE_EOS_FLAG, NULL, HFILL } },
        { &hf_lbmc_topic_source_domain_id,
            { "Domain ID", "lbmc.topic_source.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc,
            { "Topic Source Extended Functionality", "lbmc.topic_source_exfunc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_next_hdr,
            { "Next Header", "lbmc.topic_source_exfunc.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_hdr_len,
            { "Header Length", "lbmc.topic_source_exfunc.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_flags,
            { "Flags", "lbmc.topic_source_exfunc.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_flags_ignore,
            { "Ignore", "lbmc.topic_source_exfunc.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_src_ip,
            { "Source Address", "lbmc.topic_source_exfunc.src_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_src_port,
            { "Source Port", "lbmc.topic_source_exfunc.src_port", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_unused,
            { "Unused", "lbmc.topic_source_exfunc.unused", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_functionality_flags,
            { "Functionality Flags", "lbmc.topic_source_exfunc.functionality_flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_functionality_flags_ulb,
            { "ULB", "lbmc.topic_source_exfunc.functionality_flags.ulb", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS * 8, TFS(&tfs_capable_not_capable), LBM_TOPIC_OPT_EXFUNC_FFLAG_ULB, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_functionality_flags_umq,
            { "UMQ", "lbmc.topic_source_exfunc.functionality_flags.umq", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS * 8, TFS(&tfs_capable_not_capable), LBM_TOPIC_OPT_EXFUNC_FFLAG_UMQ, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_functionality_flags_ume,
            { "UME", "lbmc.topic_source_exfunc.functionality_flags.ume", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS * 8, TFS(&tfs_capable_not_capable), LBM_TOPIC_OPT_EXFUNC_FFLAG_UME, NULL, HFILL } },
        { &hf_lbmc_topic_source_exfunc_functionality_flags_lj,
            { "Late Join", "lbmc.topic_source_exfunc.functionality_flags.lj", FT_BOOLEAN, L_LBMC_CNTL_TOPIC_SOURCE_EXFUNC_HDR_T_FUNCTIONALITY_FLAGS * 8, TFS(&tfs_capable_not_capable), LBM_TOPIC_OPT_EXFUNC_FFLAG_LJ, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext,
            { "UME Store Extended", "lbmc.ume_store_ext", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_next_hdr,
            { "Next Header", "lbmc.ume_store_ext.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_hdr_len,
            { "Header Length", "lbmc.ume_store_ext.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_flags,
            { "Flags", "lbmc.ume_store_ext.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_flags_ignore,
            { "Ignore", "lbmc.ume_store_ext.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_STORE_EXT_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_grp_idx,
            { "Group Index", "lbmc.ume_store_ext.grp_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_store_tcp_port,
            { "Store TCP Port", "lbmc.ume_store_ext.store_tcp_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_store_idx,
            { "Store Index", "lbmc.ume_store_ext.store_idx", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_store_ip_addr,
            { "Store IP Address", "lbmc.ume_store_ext.store_ip_addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_src_reg_id,
            { "Source RegID", "lbmc.ume_store_ext.src_reg_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_domain_id,
            { "Domain ID", "lbmc.ume_store_ext.domain_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_store_ext_version,
            { "Version", "lbmc.ume_store_ext.version", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_psrc_election_token,
            { "UME Proxy Source Election Token", "lbmc.ume_psrc_election_token", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_psrc_election_token_next_hdr,
            { "Next Header", "lbmc.ume_psrc_election_token.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_psrc_election_token_hdr_len,
            { "Header Length", "lbmc.ume_psrc_election_token.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_psrc_election_token_flags,
            { "Flags", "lbmc.ume_psrc_election_token.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_psrc_election_token_flags_ignore,
            { "Ignore", "lbmc.ume_psrc_election_token.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_UME_PSRC_ELECTION_TOKEN_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_ume_psrc_election_token_store_index,
            { "Store Index", "lbmc.ume_psrc_election_token.store_index", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_ume_psrc_election_token_token,
            { "Token", "lbmc.ume_psrc_election_token.token", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_sid,
            { "TCP Session ID", "lbmc.tcp_sid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_sid_next_hdr,
            { "Next Header", "lbmc.tcp_sid.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_sid_hdr_len,
            { "Header Length", "lbmc.tcp_sid.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_sid_flags,
            { "Flags", "lbmc.tcp_sid.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_tcp_sid_flags_ignore,
            { "Ignore", "lbmc.tcp_sid.flags.ignore", FT_BOOLEAN, L_LBMC_CNTL_TCP_SID_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbmc_tcp_sid_sid,
            { "Session ID", "lbmc.tcp_sid.sid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt,
            { "Extended Option", "lbmc.extopt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_next_hdr,
            { "Next Header", "lbmc.extopt.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_hdr_len,
            { "Header Length", "lbmc.extopt.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_flags,
            { "Flags", "lbmc.extopt.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_flags_ignore,
            { "Ignore", "lbmc.extopt.flags.ignore", FT_BOOLEAN, L_LBMC_EXTOPT_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_EXTOPT_FLAG_IGNORE, NULL, HFILL } },
        { &hf_lbmc_extopt_flags_ignore_subtype,
            { "Ignore Subtype", "lbmc.extopt.flags.ignore_subtype", FT_BOOLEAN, L_LBMC_EXTOPT_HDR_T_FLAGS * 8, TFS(&lbm_ignore_flag), LBMC_EXTOPT_FLAG_IGNORE_SUBTYPE, NULL, HFILL } },
        { &hf_lbmc_extopt_flags_more_fragments,
            { "More Fragments", "lbmc.extopt.flags.more_fragments", FT_BOOLEAN, L_LBMC_EXTOPT_HDR_T_FLAGS * 8, TFS(&tfs_set_notset), LBMC_EXTOPT_FLAG_MORE_FRAGMENT, "Set if there are more fragments", HFILL } },
        { &hf_lbmc_extopt_id,
            { "ID", "lbmc.extopt.id", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_subtype,
            { "Subtype", "lbmc.extopt.subtype", FT_UINT16, BASE_DEC_HEX, VALS(lbmc_extopt_subtype), 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_fragment_offset,
            { "Fragment offset", "lbmc.extopt.fragment_offset", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_data,
            { "Data", "lbmc.extopt.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_cfgopt,
            { "Configuration Option", "lbmc.extopt.cfgopt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_cfgopt_scope,
            { "Scope", "lbmc.extopt.cfgopt.scope", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_extopt_config_option_scope), 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_cfgopt_parent,
            { "Parent", "lbmc.extopt.cfgopt.parent", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_cfgopt_name,
            { "Name", "lbmc.extopt.cfgopt.name", FT_STRING, FT_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_cfgopt_value,
            { "Value", "lbmc.extopt.cfgopt.value", FT_STRING, FT_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_msgsel,
            { "Message Selector", "lbmc.extopt.msgsel", FT_STRING, FT_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_reassembled_data,
            { "EXTOPT Reassembled Data", "lbmc.extopt.reassembled_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_reassembled_data_subtype,
            { "Subtype", "lbmc.extopt.reassembled_data.subtype", FT_UINT16, BASE_DEC_HEX, VALS(lbmc_extopt_subtype), 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_reassembled_data_len,
            { "Length", "lbmc.extopt.reassembled_data.length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_reassembled_data_data,
            { "Data", "lbmc.extopt.reassembled_data.data", FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_extopt_reassembled_data_msgsel,
            { "Message Selector", "lbmc.extopt.reassembled_data.msgsel", FT_STRING, FT_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties,
            { "Message Properties", "lbmc.lbm_msg_properties", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_data,
            { "Message Properties Data", "lbmc.lbm_msg_properties.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_data_magic,
            { "Magic", "lbmc.lbm_msg_properties.data.magic", FT_UINT32, BASE_HEX, VALS(lbm_msg_prop_magic_type), 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_data_num_fields,
            { "Number of Fields", "lbmc.lbm_msg_properties.data.num_fields", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_data_vertype,
            { "Version/Type", "lbmc.lbm_msg_properties.data.vertype", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_data_vertype_version,
            { "Version", "lbmc.lbm_msg_properties.data.vertype.version", FT_UINT8, BASE_DEC, NULL, LBM_MSG_PROPERTIES_HDR_VER_MASK, NULL, HFILL } },
        { &hf_lbm_msg_properties_data_vertype_type,
            { "Type", "lbmc.lbm_msg_properties.data.vertype.type", FT_UINT8, BASE_DEC_HEX, VALS(lbm_msg_prop_header_type), LBM_MSG_PROPERTIES_HDR_VER_MASK, NULL, HFILL } },
        { &hf_lbm_msg_properties_data_res,
            { "Reserved", "lbmc.lbm_msg_properties.data.res", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr,
            { "Message Properties", "lbmc.lbm_msg_properties.hdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_key_offset,
            { "Key offset", "lbmc.lbm_msg_properties.hdr.key_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_value_offset,
            { "Value offset", "lbmc.lbm_msg_properties.hdr.value_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_hash,
            { "Hash", "lbmc.lbm_msg_properties.hdr.hash", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_type,
            { "Type", "lbmc.lbm_msg_properties.hdr.type", FT_UINT32, BASE_DEC_HEX, VALS(lbm_msg_prop_field_type), 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_key,
            { "Key", "lbmc.lbm_msg_properties.hdr.key", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_boolean_value,
            { "Boolean Value", "lbmc.lbm_msg_properties.hdr.boolean_value", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_byte_value,
            { "Byte Value", "lbmc.lbm_msg_properties.hdr.byte_value", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_short_value,
            { "Short Value", "lbmc.lbm_msg_properties.hdr.short_value", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_int_value,
            { "Int Value", "lbmc.lbm_msg_properties.hdr.int_value", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_float_value,
            { "Float Value", "lbmc.lbm_msg_properties.hdr.float_value", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_long_value,
            { "Long Value", "lbmc.lbm_msg_properties.hdr.long_value", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_double_value,
            { "Double Value", "lbmc.lbm_msg_properties.hdr.double_value", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_string_value,
            { "String Value", "lbmc.lbm_msg_properties.hdr.string_value", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_msg_properties_hdr_unknown_value,
            { "Unknown Value", "lbmc.lbm_msg_properties.hdr.unknown_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_unhandled,
            { "Unhandled", "lbmc.unhandled", FT_NONE, BASE_NONE, NULL, 0x0, "Unrecognized/unhandled header", HFILL } },
        { &hf_lbmc_unhandled_next_hdr,
            { "Next Header", "lbmc.unhandled.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmc_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmc_unhandled_hdr_len,
            { "Header Length", "lbmc.unhandled.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_unhandled_data,
            { "Data", "lbmc.unhandled.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_stream,
            { "LBM Stream", "lbmc.lbm_stream", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_stream_stream_id,
            { "Stream ID", "lbmc.lbm_stream.stream_id", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbm_stream_substream_id,
            { "Substream ID", "lbmc.lbm_stream.substream_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_reassembly,
            { "Reassembled Fragments", "lbmc.reassembly", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmc_reassembly_fragment,
            { "Fragment", "lbmc.reassembly.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_reassembly_frame,
            { "Reassembled message in frame", "lbmc.reassembly_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "Frame in which reassembled message appears", HFILL } },
    };

    static gint * ett[] =
    {
        &ett_lbmc,
        &ett_lbmc_ver_type,
        &ett_lbmc_frag,
        &ett_lbmc_frag_flags,
        &ett_lbmc_batch,
        &ett_lbmc_batch_flags,
        &ett_lbmc_tcp_request,
        &ett_lbmc_tcp_request_flags,
        &ett_lbmc_topicname,
        &ett_lbmc_topicname_flags,
        &ett_lbmc_apphdr,
        &ett_lbmc_apphdr_code,
        &ett_lbmc_apphdr_chain,
        &ett_lbmc_apphdr_chain_element,
        &ett_lbmc_apphdr_chain_msgprop,
        &ett_lbmc_umq_msgid,
        &ett_lbmc_umq_msgid_flags,
        &ett_lbmc_umq_sqd_rcv,
        &ett_lbmc_umq_sqd_rcv_flags,
        &ett_lbmc_umq_resub,
        &ett_lbmc_umq_resub_flags,
        &ett_lbmc_otid,
        &ett_lbmc_otid_flags,
        &ett_lbmc_ctxinst,
        &ett_lbmc_ctxinst_flags,
        &ett_lbmc_ctxinstd,
        &ett_lbmc_ctxinstr,
        &ett_lbmc_srcidx,
        &ett_lbmc_srcidx_flags,
        &ett_lbmc_umq_ulb_msg,
        &ett_lbmc_umq_ulb_msg_flags,
        &ett_lbmc_ssf_init,
        &ett_lbmc_ssf_init_flags,
        &ett_lbmc_ssf_creq,
        &ett_lbmc_ssf_creq_flags,
        &ett_lbmc_ume_preg,
        &ett_lbmc_ume_preg_flags,
        &ett_lbmc_ume_preg_marker,
        &ett_lbmc_ume_preg_resp,
        &ett_lbmc_ume_preg_resp_code,
        &ett_lbmc_ume_preg_resp_marker,
        &ett_lbmc_ume_ack,
        &ett_lbmc_ume_ack_flags,
        &ett_lbmc_ume_rxreq,
        &ett_lbmc_ume_rxreq_flags,
        &ett_lbmc_ume_keepalive,
        &ett_lbmc_ume_keepalive_flags,
        &ett_lbmc_ume_storeid,
        &ett_lbmc_ume_storeid_store_id,
        &ett_lbmc_ume_ranged_ack,
        &ett_lbmc_ume_ranged_ack_flags,
        &ett_lbmc_ume_ack_id,
        &ett_lbmc_ume_ack_id_flags,
        &ett_lbmc_ume_capability,
        &ett_lbmc_ume_capability_flags,
        &ett_lbmc_ume_proxy_src,
        &ett_lbmc_ume_proxy_src_flags,
        &ett_lbmc_ume_store_group,
        &ett_lbmc_ume_store_group_flags,
        &ett_lbmc_ume_store,
        &ett_lbmc_ume_store_flags,
        &ett_lbmc_ume_lj_info,
        &ett_lbmc_ume_lj_info_flags,
        &ett_lbmc_tsni,
        &ett_lbmc_tsni_num_recs,
        &ett_lbmc_tsni_rec,
        &ett_lbmc_umq_reg,
        &ett_lbmc_umq_reg_flags,
        &ett_lbmc_umq_reg_reg_ctx,
        &ett_lbmc_umq_reg_reg_src,
        &ett_lbmc_umq_reg_reg_rcv,
        &ett_lbmc_umq_reg_rcv_dereg,
        &ett_lbmc_umq_reg_reg_ulb_rcv,
        &ett_lbmc_umq_reg_ulb_rcv_dereg,
        &ett_lbmc_umq_reg_reg_observer_rcv,
        &ett_lbmc_umq_reg_observer_rcv_dereg,
        &ett_lbmc_umq_reg_resp,
        &ett_lbmc_umq_reg_resp_flags,
        &ett_lbmc_umq_reg_resp_reg_ctx,
        &ett_lbmc_umq_reg_resp_reg_ctx_ex,
        &ett_lbmc_umq_reg_resp_reg_ctx_ex_flags,
        &ett_lbmc_umq_reg_resp_err,
        &ett_lbmc_umq_reg_resp_reg_src,
        &ett_lbmc_umq_reg_resp_reg_rcv,
        &ett_lbmc_umq_reg_resp_rcv_dereg,
        &ett_lbmc_umq_reg_resp_reg_ulb_rcv,
        &ett_lbmc_umq_reg_resp_ulb_rcv_dereg,
        &ett_lbmc_umq_reg_resp_reg_observer_rcv,
        &ett_lbmc_umq_reg_resp_observer_rcv_dereg,
        &ett_lbmc_umq_ack,
        &ett_lbmc_umq_ack_msgs,
        &ett_lbmc_umq_ack_msgid,
        &ett_lbmc_umq_ack_stable,
        &ett_lbmc_umq_ack_cr,
        &ett_lbmc_umq_ack_ulb_cr,
        &ett_lbmc_umq_rcr,
        &ett_lbmc_umq_rcr_flags,
        &ett_lbmc_umq_ka,
        &ett_lbmc_umq_ka_flags,
        &ett_lbmc_umq_ka_src,
        &ett_lbmc_umq_ka_rcv,
        &ett_lbmc_umq_ka_ulb_rcv,
        &ett_lbmc_umq_ka_ulb_rcv_resp,
        &ett_lbmc_umq_rxreq,
        &ett_lbmc_umq_rxreq_flags,
        &ett_lbmc_umq_rxreq_regid_resp,
        &ett_lbmc_umq_rxreq_addr_resp,
        &ett_lbmc_umq_rxreq_mr,
        &ett_lbmc_umq_rxreq_ulb_mr,
        &ett_lbmc_umq_rxreq_ulb_mr_abort,
        &ett_lbmc_umq_rxreq_qrcrr,
        &ett_lbmc_umq_rxreq_trcrr,
        &ett_lbmc_umq_rxreq_ulb_trcrr,
        &ett_lbmc_umq_rxreq_ulb_trcrr_abort,
        &ett_lbmc_umq_qmgmt,
        &ett_lbmc_umq_resub_req,
        &ett_lbmc_umq_resub_req_flags,
        &ett_lbmc_umq_resub_resp,
        &ett_lbmc_umq_resub_resp_flags,
        &ett_lbmc_topic_interest,
        &ett_lbmc_topic_interest_flags,
        &ett_lbmc_pattern_interest,
        &ett_lbmc_pattern_interest_flags,
        &ett_lbmc_advertisement,
        &ett_lbmc_advertisement_flags,
        &ett_lbmc_advertisement_ad_flags,
        &ett_lbmc_ume_storename,
        &ett_lbmc_ume_storename_flags,
        &ett_lbmc_umq_ulb_rcr,
        &ett_lbmc_umq_ulb_rcr_flags,
        &ett_lbmc_umq_lf,
        &ett_lbmc_umq_lf_flags,
        &ett_lbmc_ctxinfo,
        &ett_lbmc_ctxinfo_flags,
        &ett_lbmc_ume_pser,
        &ett_lbmc_ume_pser_flags,
        &ett_lbmc_domain,
        &ett_lbmc_domain_flags,
        &ett_lbmc_tnwg_capabilities,
        &ett_lbmc_tnwg_capabilities_flags,
        &ett_lbmc_tnwg_capabilities_capabilities1,
        &ett_lbmc_tnwg_capabilities_capabilities3,
        &ett_lbmc_patidx,
        &ett_lbmc_patidx_flags,
        &ett_lbmc_ume_client_lifetime,
        &ett_lbmc_ume_client_lifetime_flags,
        &ett_lbmc_ume_sid,
        &ett_lbmc_ume_sid_flags,
        &ett_lbmc_umq_idx_cmd,
        &ett_lbmc_umq_idx_cmd_flags,
        &ett_lbmc_umq_idx_cmd_stop_assign,
        &ett_lbmc_umq_idx_cmd_start_assign,
        &ett_lbmc_umq_idx_cmd_release_assign,
        &ett_lbmc_umq_idx_cmd_release_assign_flags,
        &ett_lbmc_umq_idx_cmd_ulb_stop_assign,
        &ett_lbmc_umq_idx_cmd_ulb_start_assign,
        &ett_lbmc_umq_idx_cmd_ulb_release_assign,
        &ett_lbmc_umq_idx_cmd_ulb_release_assign_flags,
        &ett_lbmc_umq_idx_cmd_reserve_assign,
        &ett_lbmc_umq_idx_cmd_reserve_assign_flags,
        &ett_lbmc_umq_idx_cmd_ulb_reserve_assign,
        &ett_lbmc_umq_idx_cmd_ulb_reserve_assign_flags,
        &ett_lbmc_umq_idx_cmd_resp,
        &ett_lbmc_umq_idx_cmd_resp_flags,
        &ett_lbmc_umq_idx_cmd_resp_err,
        &ett_lbmc_umq_idx_cmd_resp_stop_assign,
        &ett_lbmc_umq_idx_cmd_resp_start_assign,
        &ett_lbmc_umq_idx_cmd_resp_release_assign,
        &ett_lbmc_umq_idx_cmd_resp_ulb_stop_assign,
        &ett_lbmc_umq_idx_cmd_resp_ulb_start_assign,
        &ett_lbmc_umq_idx_cmd_resp_ulb_release_assign,
        &ett_lbmc_umq_idx_cmd_resp_reserve_assign,
        &ett_lbmc_umq_idx_cmd_resp_reserve_assign_flags,
        &ett_lbmc_umq_idx_cmd_resp_ulb_reserve_assign,
        &ett_lbmc_umq_idx_cmd_resp_ulb_reserve_assign_flags,
        &ett_lbmc_odomain,
        &ett_lbmc_odomain_flags,
        &ett_lbmc_stream,
        &ett_lbmc_stream_flags,
        &ett_lbmc_topic_md_interest,
        &ett_lbmc_topic_md_interest_flags,
        &ett_lbmc_pattern_md_interest,
        &ett_lbmc_pattern_md_interest_flags,
        &ett_lbmc_lji_req,
        &ett_lbmc_lji_req_flags,
        &ett_lbmc_tnwg_ka,
        &ett_lbmc_tnwg_ka_flags,
        &ett_lbmc_ume_receiver_keepalive,
        &ett_lbmc_ume_receiver_keepalive_flags,
        &ett_lbmc_umq_cmd,
        &ett_lbmc_umq_cmd_flags,
        &ett_lbmc_umq_cmd_topic_list,
        &ett_lbmc_umq_cmd_msg_retrieve,
        &ett_lbmc_umq_cmd_msg_retrieve_entry,
        &ett_lbmc_umq_cmd_msg_list,
        &ett_lbmc_umq_cmd_resp,
        &ett_lbmc_umq_cmd_resp_flags,
        &ett_lbmc_umq_cmd_resp_msg_retrieve,
        &ett_lbmc_umq_cmd_resp_xmsg_retrieve,
        &ett_lbmc_umq_cmd_resp_xmsg_retrieve_entry,
        &ett_lbmc_umq_cmd_resp_msg_list,
        &ett_lbmc_umq_cmd_resp_xmsg_list,
        &ett_lbmc_umq_cmd_resp_xmsg_list_entry,
        &ett_lbmc_umq_cmd_resp_topic_list,
        &ett_lbmc_umq_cmd_resp_topic_list_topic_entry,
        &ett_lbmc_umq_cmd_resp_topic_list_topic_entry_appset_entry,
        &ett_lbmc_umq_cmd_resp_err,
        &ett_lbmc_sri_req,
        &ett_lbmc_sri_req_flags,
        &ett_lbmc_ume_store_domain,
        &ett_lbmc_ume_store_domain_flags,
        &ett_lbmc_sri,
        &ett_lbmc_sri_flags,
        &ett_lbmc_route_info,
        &ett_lbmc_route_info_flags,
        &ett_lbmc_route_info_neighbor,
        &ett_lbmc_route_info_neighbor_flags,
        &ett_lbmc_gateway_name,
        &ett_lbmc_gateway_name_flags,
        &ett_lbmc_auth_request,
        &ett_lbmc_auth_request_flags,
        &ett_lbmc_auth_challenge,
        &ett_lbmc_auth_challenge_flags,
        &ett_lbmc_auth_challenge_rsp,
        &ett_lbmc_auth_challenge_rsp_flags,
        &ett_lbmc_auth_result,
        &ett_lbmc_auth_result_flags,
        &ett_lbmc_auth_unknown,
        &ett_lbmc_hmac,
        &ett_lbmc_hmac_flags,
        &ett_lbmc_umq_sid,
        &ett_lbmc_umq_sid_flags,
        &ett_lbmc_destination,
        &ett_lbmc_destination_flags,
        &ett_lbmc_topic_idx,
        &ett_lbmc_topic_idx_flags,
        &ett_lbmc_topic_source,
        &ett_lbmc_topic_source_flags,
        &ett_lbmc_topic_source_exfunc,
        &ett_lbmc_topic_source_exfunc_flags,
        &ett_lbmc_topic_source_exfunc_functionality_flags,
        &ett_lbmc_ume_store_ext,
        &ett_lbmc_ume_store_ext_flags,
        &ett_lbmc_ume_psrc_election_token,
        &ett_lbmc_ume_psrc_election_token_flags,
        &ett_lbmc_tcp_sid,
        &ett_lbmc_tcp_sid_flags,
        &ett_lbmc_extopt,
        &ett_lbmc_extopt_flags,
        &ett_lbmc_extopt_cfgopt,
        &ett_lbmc_extopt_reassembled_data,
        &ett_lbmc_extopt_reassembled_data_cfgopt,
        &ett_lbm_msg_properties,
        &ett_lbm_msg_properties_data,
        &ett_lbm_msg_properties_data_vertype,
        &ett_lbm_msg_properties_hdr,
        &ett_lbmc_unhandled_hdr,
        &ett_lbm_stream,
        &ett_lbmc_reassembly,
        &ett_unknown,
        &ett_msg_data,
        &ett_msgprop_data
    };
    static ei_register_info ei[] =
    {
        { &ei_lbmc_analysis_length_incorrect, { "lbmc.analysis.length_incorrect", PI_PROTOCOL, PI_ERROR, "Header length incorrect", EXPFILL } },
        { &ei_lbmc_analysis_zero_length, { "lbmc.analysis.zero_length", PI_MALFORMED, PI_ERROR, "Length dissected is zero", EXPFILL } },
        { &ei_lbmc_analysis_tsni, { "lbmc.analysis.tsni", PI_SEQUENCE, PI_NOTE, "TSNI Sqn", EXPFILL } },
        { &ei_lbmc_analysis_invalid_value, { "lbmc.analysis.invalid_value", PI_MALFORMED, PI_ERROR, "Invalid value", EXPFILL } },
        { &ei_lbmc_analysis_no_reassembly, { "lbmc.analysis.no_reassembly", PI_PROTOCOL, PI_ERROR, "Reassembly not in progress but fragment_offset not zero", EXPFILL } },
        { &ei_lbmc_analysis_invalid_offset, { "lbmc.analysis.invalid_offset", PI_MALFORMED, PI_ERROR, "Message property offset exceeds data length", EXPFILL } },
        { &ei_lbmc_analysis_missing_reassembly_frame, { "lbmc.analysis.missing_reassembly_frame", PI_UNDECODED, PI_WARN, "Reassembly frame not found - perhaps missing packets?", EXPFILL } },
        { &ei_lbmc_analysis_invalid_fragment, { "lbmc.analysis.invalid_fragment", PI_MALFORMED, PI_ERROR, "Invalid fragment", EXPFILL } },
    };
    module_t * lbmc_module = NULL;
    expert_module_t * expert_lbmc;

    tnw_protocol_handle = proto_register_protocol("29West Protocol", "29West", "29west");
    proto_lbmc = proto_register_protocol("LBMC Protocol", "LBMC", "lbmc");

    proto_register_field_array(proto_lbmc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lbmc = expert_register_protocol(proto_lbmc);
    expert_register_field_array(expert_lbmc, ei, array_length(ei));

    register_heur_dissector_list("29westdata", &lbmc_heuristic_subdissector_list);

    prefs_register_protocol(tnw_protocol_handle, NULL);
    lbmc_module = prefs_register_protocol_subtree("29West", proto_lbmc, proto_reg_handoff_lbmc);
    prefs_register_bool_preference(lbmc_module,
        "use_heuristic_subdissectors",
        "Use heuristic sub-dissectors",
        "Use a registered heuristic sub-dissector to decode the data payload",
        &lbmc_use_heuristic_subdissectors);
    prefs_register_bool_preference(lbmc_module,
        "reassemble_fragments",
        "Reassemble fragmented data",
        "Reassemble data message fragments",
        &lbmc_reassemble_fragments);
    prefs_register_bool_preference(lbmc_module,
        "dissect_lbmpdm",
        "Dissect LBMPDM payload",
        "Recognize and dissect payloads containing LBMPDM messages (requires reassembly to be enabled)",
        &lbmc_dissect_lbmpdm);
    lbm_stream_init();
    lbmc_message_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

/* The registration hand-off routine */
void proto_reg_handoff_lbmc(void)
{
    lbmc_data_dissector_handle = find_dissector("data");
    lbmc_uim_tap_handle = register_tap("lbm_uim");
    lbmc_stream_tap_handle = register_tap("lbm_stream");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
