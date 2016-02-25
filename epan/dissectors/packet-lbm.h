/* packet-lbm.h
 * Definitions for LBM packet dissection
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

#ifndef PACKET_LBM_H_INCLUDED
#define PACKET_LBM_H_INCLUDED

/* A list of the taps etc. made available by these dissectors:
   Taps:
     lbm_stream
       - A packet is queued for each UIM (unicast immediate message) LBMC message (or fragment)
       - The data associated with each tap entry is described by lbm_uim_stream_tap_info_t
       - A single packet may generate multiple tap entries (in the case that a single packet
         contains multiple LBMC messages)
       - An LBMC message that spans multiple packets will cause a single entry to be queued,
         corresponding to the last packet spanned
     lbm_uim
       - A packet is queued for each complete (possibly reassembled) UIM message
       - The data associated with each tap entry is described by lbm_uim_stream_info_t
       - A single packet may generate multiple tap entries (in the case that a single packet
         contains multiple complete UIM messages)
       - An complete UIM message that spans multiple packets will cause a single entry to be queued,
         corresponding to the last packet spanned
     lbm_lbmr_topic_advertisement
       - A packet is queued for each LBMR topic advertisement (TIR)
       - The data associated with each tap entry is described by lbm_lbmr_topic_advertisement_tap_info_t
       - A single LBMR message (which may span multiple IP frames, reassembled into a single UDP packet)
         may generate multiple tap entries (in the case that a single LBMR message contains multiple topic
         advertisements)
     lbm_lbmr_topic_query
       - A packet is queued for each LBMR topic query (TQR)
       - The data associated with each tap entry is described by lbm_lbmr_topic_query_tap_info_t
       - A single LBMR message (which may span multiple IP frames, reassembled into a single UDP packet)
         may generate multiple tap entries (in the case that a single LBMR message contains multiple topic
         queries)
     lbm_lbmr_pattern_query
       - A packet is queued for each LBMR pattern query (TQR specifying a pattern)
       - The data associated with each tap entry is described by lbm_lbmr_pattern_query_tap_info_t
       - A single LBMR message (which may span multiple IP frames, reassembled into a single UDP packet)
         may generate multiple tap entries (in the case that a single LBMR message contains multiple pattern
         queries)
     lbm_lbmr_queue_advertisement
       - A packet is queued for each LBMR queue advertisement (QIR)
       - The data associated with each tap entry is described by lbm_lbmr_queue_advertisement_tap_info_t
       - A single LBMR message (which may span multiple IP frames, reassembled into a single UDP packet)
         may generate multiple tap entries (in the case that a single LBMR message contains multiple queue
         advertisements)
     lbm_lbmr_queue_query
       - A packet is queued for each LBMR queue query (QQR)
       - The data associated with each tap entry is described by lbm_lbmr_queue_query_tap_info_t
       - A single LBMR message (which may span multiple IP frames, reassembled into a single UDP packet)
         may generate multiple tap entries (in the case that a single LBMR message contains multiple queue
         queries)
     lbm_lbtrm
       - A packet is queued for each LBTRM transport message
       - The data associated with each tap entry is described by lbm_lbtrm_tap_info_t
       - A single LBTRM transport message (which may span multiple IP frames, reassembled into a single UDP
         packet) will generate a single tap entry
     lbm_lbtru
       - A packet is queued for each LBTRU transport message
       - The data associated with each tap entry is described by lbm_lbtru_tap_info_t
       - A single LBTRU transport message (which may span multiple IP frames, reassembled into a single UDP
         packet) will generate a single tap entry
   Heuristic subdissector tables:
     lbm_msg_payload
       - If the LBMC preference "Use heuristic sub-dissectors" is enabled, the dissector will call any dissector
         registered in this table via heur_dissector_add(). This allows a customer plugin to dissect the
         actual payload of their messages.
*/

#if defined(__FreeBSD__)
#include <sys/types.h>
#include <netinet/in.h>
#endif
#include <stddef.h>

#include <wsutil/inet_aton.h>

typedef guint8 lbm_uint8_t;
typedef guint16 lbm_uint16_t;
typedef guint32 lbm_uint32_t;
typedef guint64 lbm_uint64_t;
#define SIZEOF(TYPE, MEMBER) (gint)(sizeof(((TYPE *)0)->MEMBER))
#define OFFSETOF(TYPE, MEMBER) (gint)(offsetof(TYPE, MEMBER))
#define STRINGIZE(a) #a
#define MAKESTRING(a) STRINGIZE(a)
#define LBM_OTID_BLOCK_SZ 32
#define LBM_CONTEXT_INSTANCE_BLOCK_SZ 8
#define LBM_HMAC_BLOCK_SZ 20

/* UAT macros for IPV4 fields. */
#define UAT_IPV4_CB_DEF(basename,field_name,rec_t) \
    static gboolean basename ## _ ## field_name ## _chk_cb(void * u1 _U_, const char * strptr, unsigned len _U_, const void * u2 _U_, const void * u3 _U_, char ** err) \
    { \
        struct in_addr addr; \
        if (inet_aton(strptr, &addr) == 0) \
        { \
            *err = g_strdup("invalid address"); \
            return (FALSE); \
        } \
        return (TRUE); \
    } \
    static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) \
    { \
        struct in_addr addr; \
        char* new_buf = g_strndup(buf,len); \
        g_free((((rec_t*)rec)->field_name)); \
        (((rec_t*)rec)->field_name) = new_buf; \
        inet_aton(new_buf, &addr); \
        (((rec_t*)rec)->field_name ## _val_h) = g_ntohl(addr.s_addr); \
    } \
    static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) \
    {\
        if (((rec_t*)rec)->field_name ) \
        { \
            *out_ptr = g_strdup((((rec_t*)rec)->field_name)); \
            *out_len = (unsigned)strlen((((rec_t*)rec)->field_name)); \
        } \
        else \
        { \
            *out_ptr = g_strdup(""); \
            *out_len = 0; \
        } \
    }

#define UAT_FLD_IPV4(basename,field_name,title,desc) \
        {#field_name, title, PT_TXTMOD_STRING,{basename ## _ ## field_name ## _chk_cb,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/* UAT macros for IPV4 Multicast fields. */
#define UAT_IPV4_MC_CB_DEF(basename,field_name,rec_t) \
    static gboolean basename ## _ ## field_name ## _chk_cb(void * u1 _U_, const char * strptr, unsigned len _U_, const void * u2 _U_, const void * u3 _U_, char ** err) \
    { \
        struct in_addr addr; \
        if (inet_aton(strptr, &addr) == 0) \
        { \
            *err = g_strdup("invalid address"); \
            return (FALSE); \
        } \
        if (!IN_MULTICAST(g_ntohl(addr.s_addr)) && (g_ntohl(addr.s_addr) != 0)) \
        { \
            *err = g_strdup("invalid multicast address"); \
            return (FALSE); \
        } \
        return (TRUE); \
    } \
    static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) \
    { \
        struct in_addr addr; \
        char* new_buf = g_strndup(buf,len); \
        g_free((((rec_t*)rec)->field_name)); \
        (((rec_t*)rec)->field_name) = new_buf; \
        inet_aton(new_buf, &addr); \
        (((rec_t*)rec)->field_name ## _val_h) = g_ntohl(addr.s_addr); \
    } \
    static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) \
    {\
        if (((rec_t*)rec)->field_name ) \
        { \
            *out_ptr = g_strdup((((rec_t*)rec)->field_name)); \
            *out_len = (unsigned)strlen((((rec_t*)rec)->field_name)); \
        } \
        else \
        { \
            *out_ptr = g_strdup(""); \
            *out_len = 0; \
        } \
    }

#define UAT_FLD_IPV4_MC(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{basename ## _ ## field_name ## _chk_cb,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

typedef struct
{
    guint32 domain;
    address addr;
    guint16 port;
} lbm_uim_stream_destination_t;

typedef struct
{
    guint8 ctxinst[LBM_CONTEXT_INSTANCE_BLOCK_SZ];
} lbm_uim_stream_ctxinst_t;

typedef enum
{
    lbm_uim_instance_stream,
    lbm_uim_domain_stream
} lbm_uim_stream_type_t;

typedef struct
{
    lbm_uim_stream_type_t type;
    union
    {
        lbm_uim_stream_destination_t dest;
        lbm_uim_stream_ctxinst_t ctxinst;
    } stream_info;
} lbm_uim_stream_endpoint_t;

typedef struct
{
    guint64 channel;
    guint32 sqn;
    lbm_uim_stream_endpoint_t endpoint_a;
    lbm_uim_stream_endpoint_t endpoint_b;
    const gchar * description;
} lbm_uim_stream_info_t;

typedef struct
{
    guint64 channel;
    guint32 substream_id;
    guint32 bytes;
    lbm_uim_stream_endpoint_t endpoint_a;
    lbm_uim_stream_endpoint_t endpoint_b;
} lbm_uim_stream_tap_info_t;

typedef struct
{
    gchar * transport;
    guint8 type;
    gboolean retransmission;
    guint32 sqn;
    guint8 ncf_reason;
    guint16 num_sqns;
    guint32 * sqns;
} lbm_lbtrm_tap_info_t;

typedef struct
{
    gchar * transport;
    guint8 type;
    gboolean retransmission;
    guint32 sqn;
    guint8 ncf_reason;
    guint16 num_sqns;
    guint16 creq_type;
    guint16 rst_type;
    guint32 * sqns;
} lbm_lbtru_tap_info_t;

typedef struct
{
    guint16 size;
    guint8 topic_length;
    guint8 source_length;
    guint32 topic_index;
    char topic[256];
    char source[256];
} lbm_lbmr_topic_advertisement_tap_info_t;

typedef struct
{
    guint16 size;
    guint8 topic_length;
    char topic[256];
} lbm_lbmr_topic_query_tap_info_t;

typedef struct
{
    guint16 size;
    guint8 type;
    guint8 pattern_length;
    char pattern[256];
} lbm_lbmr_pattern_query_tap_info_t;

#define LBMR_WILDCARD_PATTERN_TYPE_PCRE 1
#define LBMR_WILDCARD_PATTERN_TYPE_REGEX 2

typedef struct
{
    guint16 size;
    guint16 port;
    guint8 queue_length;
    guint8 topic_length;
    char queue[256];
    char topic[256];
} lbm_lbmr_queue_advertisement_tap_info_t;

typedef struct
{
    guint16 size;
    guint8 queue_length;
    char queue[256];
} lbm_lbmr_queue_query_tap_info_t;

#define LBM_TOPIC_OPT_EXFUNC_FFLAG_LJ  0x00000001
#define LBM_TOPIC_OPT_EXFUNC_FFLAG_UME 0x00000002
#define LBM_TOPIC_OPT_EXFUNC_FFLAG_UMQ 0x00000004
#define LBM_TOPIC_OPT_EXFUNC_FFLAG_ULB 0x00000008

/* LBT-RM packet types */
#define LBTRM_PACKET_TYPE_DATA 0x00
#define LBTRM_PACKET_TYPE_SM 0x02
#define LBTRM_PACKET_TYPE_NAK 0x03
#define LBTRM_PACKET_TYPE_NCF 0x04

/* LBT-RM NCF reason types */
#define LBTRM_NCF_REASON_NO_RETRY 0x0
#define LBTRM_NCF_REASON_IGNORED 0x1
#define LBTRM_NCF_REASON_RX_DELAY 0x2
#define LBTRM_NCF_REASON_SHED 0x3

/* LBT-RU packet types */
#define LBTRU_PACKET_TYPE_DATA 0x00
#define LBTRU_PACKET_TYPE_SM 0x02
#define LBTRU_PACKET_TYPE_NAK 0x03
#define LBTRU_PACKET_TYPE_NCF 0x04
#define LBTRU_PACKET_TYPE_ACK 0x05
#define LBTRU_PACKET_TYPE_CREQ 0x06
#define LBTRU_PACKET_TYPE_RST 0x07

/* LBT-RU NCF reason types */
#define LBTRU_NCF_REASON_NO_RETRY 0x0
#define LBTRU_NCF_REASON_IGNORED 0x1
#define LBTRU_NCF_REASON_RX_DELAY 0x2
#define LBTRU_NCF_REASON_SHED 0x3

/* LBT-RU CREQ types */
#define LBTRU_CREQ_REQUEST_SYN 0x0

/* LBT-RU RST reasons */
#define LBTRU_RST_REASON_DEFAULT 0x0

gboolean lbmc_test_lbmc_header(tvbuff_t * tvb, int offset);
int lbmc_dissect_lbmc_packet(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, const char * tag_name, guint64 channel);
int lbmc_get_minimum_length(void);
guint16 lbmc_get_message_length(tvbuff_t * tvb, int offset);
gboolean lbmpdm_verify_payload(tvbuff_t * tvb, int offset, int * encoding, int * length);
int lbmpdm_dissect_lbmpdm_payload(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, guint64 channel);
int lbmpdm_get_minimum_length(void);
int lbmr_dissect_umq_qmgmt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);

extern const true_false_string lbm_ignore_flag;
extern const value_string lbm_wildcard_pattern_type[];
extern const value_string lbm_wildcard_pattern_type_short[];

/*----------------------------------------------------------------------------*/
/* Channel interface.                                                         */
/*----------------------------------------------------------------------------*/
#define LBM_CHANNEL_NO_CHANNEL (~((guint64) 0))

#define LBM_CHANNEL_TRANSPORT_LBTTCP 0x00
#define LBM_CHANNEL_TRANSPORT_LBTRU 0x01
#define LBM_CHANNEL_TRANSPORT_LBTRM 0x02
#define LBM_CHANNEL_TRANSPORT_LBTIPC 0x03
#define LBM_CHANNEL_TRANSPORT_LBTRDMA 0x04
#define LBM_CHANNEL_TRANSPORT_LBTSMX  0x05
#define LBM_CHANNEL_STREAM_TCP 0x10
#define LBM_CHANNEL_TCP 0x20

#define LBM_CHANNEL_VALUE_MASK G_GUINT64_CONSTANT(0xfffffffffffff000)
#define LBM_CHANNEL_VALUE_SHIFT_COUNT 12

void lbm_channel_reset(void);
guint64 lbm_channel_assign(guint8 channel_type);
gboolean lbm_channel_is_transport(guint64 channel);
guint8 lbm_channel_type(guint64 channel);
guint64 lbm_channel_assign_unknown_transport_source_lbttcp(void);
guint64 lbm_channel_assign_unknown_transport_client_lbttcp(void);
guint64 lbm_channel_assign_unknown_stream_tcp(void);
gboolean lbm_channel_is_unknown_transport_lbttcp(guint64 channel);
gboolean lbm_channel_is_unknown_transport_source_lbttcp(guint64 channel);
gboolean lbm_channel_is_unknown_transport_client_lbttcp(guint64 channel);
gboolean lbm_channel_is_unknown_stream_tcp(guint64 channel);
gboolean lbm_channel_is_known(guint64 channel);

#define LBM_CHANNEL_ID(ch) ((ch & LBM_CHANNEL_VALUE_MASK) >> LBM_CHANNEL_VALUE_SHIFT_COUNT)

/*----------------------------------------------------------------------------*/
/* Frame/SQN interface.                                                       */
/*----------------------------------------------------------------------------*/
typedef struct
{
    guint32 frame;
    guint8 type;
    guint32 sqn;
    guint32 previous_frame;
    guint32 previous_type_frame;
    guint32 next_frame;
    guint32 next_type_frame;
    gboolean retransmission;
    guint32 sqn_gap;
    guint32 ooo_gap;
    gboolean duplicate;
} lbm_transport_frame_t;

typedef struct
{
    guint32 frame;
    gboolean retransmission;
} lbm_transport_sqn_frame_t;

typedef struct
{
    guint32 sqn;
    guint32 frame_count;
    wmem_tree_t * frame;  /* List of lbm_transport_sqn_frame_t */
} lbm_transport_sqn_t;

lbm_transport_frame_t * lbm_transport_frame_add(wmem_tree_t * list, guint8 type, guint32 frame, guint32 sqn, gboolean retransmission);
lbm_transport_sqn_t * lbm_transport_sqn_add(wmem_tree_t * list, lbm_transport_frame_t * frame);

/*----------------------------------------------------------------------------*/
/* Topic interface.                                                           */
/*----------------------------------------------------------------------------*/
void lbm_topic_init(void);
const char * lbm_topic_find(guint64 channel, guint32 topic_index);
void lbm_topic_add(guint64 channel, guint32 topic_index, const char * name);

#endif

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
