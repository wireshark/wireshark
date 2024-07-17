/* packet-lbm.c
 * Routines for LBM Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include "packet-lbm.h"

void proto_register_lbm(void);

/*----------------------------------------------------------------------------*/
/* Value translation tables.                                                  */
/*----------------------------------------------------------------------------*/

const true_false_string lbm_ignore_flag =
{
    "May be ignored",
    "Must be processed"
};

#define LBM_WILDCARD_PATTERN_TYPE_PCRE 1
#define LBM_WILDCARD_PATTERN_TYPE_REGEX 2

const value_string lbm_wildcard_pattern_type[] =
{
    { LBM_WILDCARD_PATTERN_TYPE_PCRE, "Perl Compatible Regular Expression (PCRE)" },
    { LBM_WILDCARD_PATTERN_TYPE_REGEX, "POSIX Extended Regular Expression (REGEX)" },
    { 0x0, NULL }
};

const value_string lbm_wildcard_pattern_type_short[] =
{
    { LBM_WILDCARD_PATTERN_TYPE_PCRE, "PCRE" },
    { LBM_WILDCARD_PATTERN_TYPE_REGEX, "REGEX" },
    { 0x0, NULL }
};

/* Initialization function, called whenever Wireshark loads a new capture, etc. */
static void lbm_init(void)
{
    lbm_channel_reset();
}

/* Register all the bits needed with the filtering engine */
void proto_register_lbm(void)
{
    register_init_routine(lbm_init);
}

/*----------------------------------------------------------------------------*/
/* Channel interface.                                                         */
/*----------------------------------------------------------------------------*/
/*
  lbm_next_channel_value is a counter (akin to tcp_stream_count in packet-tcp.c) used to assign a unique index to an LBM communication
  stream or transport session. The actual channel value consists of:
  - The lower 52 bits of the counter, shifted left 12 bits
  - A 4-bit source/client classification (for unicast channels), shifted left 8 bits
  - An 8-bit channel type

   6                                                                                                     1 1     0 0             0
   3                                                                                                     2 1     8 7             0
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                    Counter                                                            |  S/C  |     Type      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  The counter wraps at 0x000ffffffffffffe, and is reset to 1 whenever Wireshark invokes any init routines registered via
  register_init_routine() (the call to lbm_channel_reset() is in packet-lbm.c).

  Special values are used as placeholders to indicate an as-yet-unknown transport or stream TCP channel.
*/

static uint64_t lbm_next_channel_value = 1;

#define LBM_CHANNEL_TYPE_MASK UINT64_C(0x00000000000000ff)
#define LBM_CHANNEL_VALUE_LIMIT_MASK UINT64_C(0x000ffffffffffffff)
#define LBM_CHANNEL_MAX_VALUE UINT64_C(0x000ffffffffffffe)

#define LBM_CHANNEL_VALUE_UNKNOWN UINT64_C(0xfffffffffffff000)
#define LBM_CHANNEL_VALUE_UNKNOWN_SOURCE UINT64_C(0xfffffffffffff100)
#define LBM_CHANNEL_VALUE_UNKNOWN_CLIENT UINT64_C(0xfffffffffffff200)
#define LBM_CHANNEL_UNKNOWN_TRANSPORT_SOURCE_LBTTCP (LBM_CHANNEL_VALUE_UNKNOWN_SOURCE | LBM_CHANNEL_TRANSPORT_LBTTCP)
#define LBM_CHANNEL_UNKNOWN_TRANSPORT_CLIENT_LBTTCP (LBM_CHANNEL_VALUE_UNKNOWN_CLIENT | LBM_CHANNEL_TRANSPORT_LBTTCP)
#define LBM_CHANNEL_UNKNOWN_STREAM_TCP (LBM_CHANNEL_VALUE_UNKNOWN | LBM_CHANNEL_STREAM_TCP)

#define LBM_CHANNEL_TYPE(ch) ((uint8_t)(ch & LBM_CHANNEL_TYPE_MASK))

void lbm_channel_reset(void)
{
    lbm_next_channel_value = 1;
}

uint64_t lbm_channel_assign(uint8_t channel_type)
{
    uint64_t ch;
    uint64_t ch_counter = lbm_next_channel_value++;

    if (lbm_next_channel_value == LBM_CHANNEL_MAX_VALUE)
    {
        lbm_next_channel_value = 1;
    }
    ch = ((uint64_t)((ch_counter & LBM_CHANNEL_VALUE_LIMIT_MASK) << LBM_CHANNEL_VALUE_SHIFT_COUNT)) | channel_type;
    return (ch);
}

bool lbm_channel_is_transport(uint64_t channel)
{
    uint8_t ch_type;

    ch_type = LBM_CHANNEL_TYPE(channel);
    switch (ch_type)
    {
        case LBM_CHANNEL_TRANSPORT_LBTTCP:
        case LBM_CHANNEL_TRANSPORT_LBTRU:
        case LBM_CHANNEL_TRANSPORT_LBTRM:
        case LBM_CHANNEL_TRANSPORT_LBTIPC:
        case LBM_CHANNEL_TRANSPORT_LBTRDMA:
        case LBM_CHANNEL_TRANSPORT_LBTSMX:
            return true;
        default:
            break;
    }
    return false;
}

uint8_t lbm_channel_type(uint64_t channel)
{
    uint8_t ch_type;

    ch_type = LBM_CHANNEL_TYPE(channel);
    return (ch_type);
}

uint64_t lbm_channel_assign_unknown_transport_source_lbttcp(void)
{
    return (LBM_CHANNEL_UNKNOWN_TRANSPORT_SOURCE_LBTTCP);
}

uint64_t lbm_channel_assign_unknown_transport_client_lbttcp(void)
{
    return (LBM_CHANNEL_UNKNOWN_TRANSPORT_CLIENT_LBTTCP);
}

uint64_t lbm_channel_assign_unknown_stream_tcp(void)
{
    return (LBM_CHANNEL_UNKNOWN_STREAM_TCP);
}

bool lbm_channel_is_unknown_transport_lbttcp(uint64_t channel)
{
    return (lbm_channel_is_unknown_transport_source_lbttcp(channel) || lbm_channel_is_unknown_transport_client_lbttcp(channel));
}

bool lbm_channel_is_unknown_transport_source_lbttcp(uint64_t channel)
{
    if (channel == LBM_CHANNEL_UNKNOWN_TRANSPORT_SOURCE_LBTTCP)
    {
        return true;
    }
    return false;
}

bool lbm_channel_is_unknown_transport_client_lbttcp(uint64_t channel)
{
    if (channel == LBM_CHANNEL_UNKNOWN_TRANSPORT_CLIENT_LBTTCP)
    {
        return true;
    }
    return false;
}

bool lbm_channel_is_unknown_stream_tcp(uint64_t channel)
{
    if (channel == LBM_CHANNEL_UNKNOWN_STREAM_TCP)
    {
        return true;
    }
    return false;
}

bool lbm_channel_is_known(uint64_t channel)
{
    return (!lbm_channel_is_unknown_transport_lbttcp(channel) && !lbm_channel_is_unknown_stream_tcp(channel));
}

/*----------------------------------------------------------------------------*/
/* Frame/SQN interface.                                                       */
/*----------------------------------------------------------------------------*/
lbm_transport_frame_t * lbm_transport_frame_add(wmem_tree_t * list, uint8_t type, uint32_t frame, uint32_t sqn, bool retransmission)
{
    lbm_transport_frame_t * frame_entry = NULL;

    /* Locate the frame. */
    frame_entry = (lbm_transport_frame_t *) wmem_tree_lookup32(list, frame);
    if (frame_entry != NULL)
    {
        return (frame_entry);
    }
    frame_entry = wmem_new(wmem_file_scope(), lbm_transport_frame_t);
    frame_entry->frame = frame;
    frame_entry->type = type;
    frame_entry->sqn = sqn;
    frame_entry->previous_frame = 0;
    frame_entry->previous_type_frame = 0;
    frame_entry->next_frame = 0;
    frame_entry->next_type_frame = 0;
    frame_entry->retransmission = retransmission;
    frame_entry->sqn_gap = 0;
    frame_entry->ooo_gap = 0;
    frame_entry->duplicate = false;
    wmem_tree_insert32(list, frame, (void *) frame_entry);
    return (frame_entry);
}

lbm_transport_sqn_t * lbm_transport_sqn_add(wmem_tree_t * list, lbm_transport_frame_t * frame)
{
    lbm_transport_sqn_t * sqn_entry = NULL;
    lbm_transport_sqn_frame_t * frame_entry = NULL;

    /* Locate the SQN. */
    sqn_entry = (lbm_transport_sqn_t *) wmem_tree_lookup32(list, frame->sqn);
    if (sqn_entry == NULL)
    {
        sqn_entry = wmem_new(wmem_file_scope(), lbm_transport_sqn_t);
        sqn_entry->sqn = frame->sqn;
        sqn_entry->frame_count = 0;
        sqn_entry->frame = wmem_tree_new(wmem_file_scope());
        wmem_tree_insert32(list, frame->sqn, (void *) sqn_entry);
    }
    /* Add this frame to the list of frames this SQN appears in. */
    frame_entry = wmem_new(wmem_file_scope(), lbm_transport_sqn_frame_t);
    frame_entry->frame = frame->frame;
    frame_entry->retransmission = frame->retransmission;
    wmem_tree_insert32(sqn_entry->frame, frame->frame, (void *) frame_entry);
    sqn_entry->frame_count++;
    return (sqn_entry);
}

/*----------------------------------------------------------------------------*/
/* Topic interface.                                                           */
/*----------------------------------------------------------------------------*/
static wmem_tree_t * lbm_topic_table;

#define LBM_TOPIC_KEY_ELEMENT_COUNT 3
#define LBM_TOPIC_KEY_ELEMENT_CHANNEL_HIGH 0
#define LBM_TOPIC_KEY_ELEMENT_CHANNEL_LOW 1
#define LBM_TOPIC_KEY_ELEMENT_TOPIC_INDEX 2

struct lbm_topic_t_stct;
typedef struct lbm_topic_t_stct lbm_topic_t;

typedef struct
{
    uint64_t channel;
    uint32_t topic_idx;
    lbm_topic_t * topic;
} lbm_topic_key_t;

struct lbm_topic_t_stct
{
    lbm_topic_key_t key;
    char * topic;
};

void lbm_topic_init(void)
{
    lbm_topic_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

static void lbm_topic_build_key(uint32_t * key_value, wmem_tree_key_t * key, uint64_t channel, uint32_t topic_index)
{
    key_value[LBM_TOPIC_KEY_ELEMENT_CHANNEL_HIGH] = (uint32_t) ((channel >> 32) & 0xffffffff);
    key_value[LBM_TOPIC_KEY_ELEMENT_CHANNEL_LOW] = (uint32_t) (channel & 0xffffffff);
    key_value[LBM_TOPIC_KEY_ELEMENT_TOPIC_INDEX] = topic_index;
    key[0].length = LBM_TOPIC_KEY_ELEMENT_COUNT;
    key[0].key = key_value;
    key[1].length = 0;
    key[1].key = NULL;
}

static lbm_topic_t * lbm_topic_locate(uint64_t channel, uint32_t topic_index)
{
    lbm_topic_t * entry = NULL;
    uint32_t keyval[LBM_TOPIC_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    lbm_topic_build_key(keyval, tkey, channel, topic_index);
    entry = (lbm_topic_t *) wmem_tree_lookup32_array(lbm_topic_table, tkey);
    return (entry);
}

const char * lbm_topic_find(uint64_t channel, uint32_t topic_index)
{
    lbm_topic_t * entry = NULL;
    const char * topic = NULL;

    entry = lbm_topic_locate(channel, topic_index);
    if (entry != NULL)
    {
        topic = entry->topic;
    }
    return (topic);
}

void lbm_topic_add(uint64_t channel, uint32_t topic_index, const char * name)
{
    lbm_topic_t * entry;
    uint32_t keyval[LBM_TOPIC_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    entry = lbm_topic_locate(channel, topic_index);
    if (entry != NULL)
    {
        return;
    }
    entry = wmem_new(wmem_file_scope(), lbm_topic_t);
    entry->key.channel = channel;
    entry->key.topic_idx = topic_index;
    entry->key.topic = entry;
    entry->topic = wmem_strdup(wmem_file_scope(), name);
    lbm_topic_build_key(keyval, tkey, channel, topic_index);
    wmem_tree_insert32_array(lbm_topic_table, tkey, (void *) entry);
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
