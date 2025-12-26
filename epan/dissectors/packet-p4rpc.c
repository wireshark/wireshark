/*
 * packet-p4rpc.c
 *
 * A Perforce P4RPC protocol packet dissector for Wireshark
 * Mark Wittenberg <mwittenberg@perforce.com>, <markw-perforce@wittenberg.us>
 * Copyright 2012-2022 Mark Wittenberg
 * Copyright 2023-2025 Perforce Software Inc.
 * Updates 2023-2024 by Tim Brazil and Jason Gibson
 *
 * It supports P4RPC over TLS as well as over TCP.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * NB: C99 supports // comments, so I'm using them
 */

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

// for TLS
#include <epan/tvbuff.h>
#include <epan/dissectors/packet-tls.h>

// for expert info
#include <epan/expert.h>

#include <ws_symbol_export.h>
#include <wsutil/plugins.h>
#include <wsutil/str_util.h>
#include <epan/proto.h>

// for prefs
#include <wsutil/report_message.h>

#include "config.h"

/*
 * To decrypt TLS, don't set both ports to the same value;
 * that might prevent TLS from decrypting the packets
 * before P4RPC tries to dissect them.
 * Set the TLS port to the server port number;
 * TLS will automatically decrypt TLS packets
 * if the TCP port is not equal to the TLS port.
 * After decryption, if a packet's src or dst port
 * matches the "tls.port" then P4RPC will decrypt
 * the packet.
 *
 * These values are just the initial default value;
 * users can change the defaults via
 *     Preferences -> Protocols -> P4RPC
 * and changing either the TCP or TLS ports
 * in the "TCP port" or "TLS port" text fields.
 *
 * P4RPC preferences can be more easily reached by right-clicking
 * on a P4RPC packet (if there is one) and choosing
 *      Protocol Preferences -> P4RPC -> Open P4RPC Preferences
 *
 * Users can also right-click on an individual packet
 * and choose "Decode As..." but the same rules apply.
 *
 * If you don't care about supporting TLS then
 * set the TCP port to the desired port and set
 * the TLS port to anything else.
 */
#define P4RPC_TCP_PORT 1666     // Not IANA registered
#define P4RPC_TLS_PORT 1667     // Not IANA registered

/*
 * checksum(length)     1
 * length               4
 *
 * Every message starts with a header
 * and must contain at least one message.
 * The smallest message has:
 * - (1) empty name string + NUL terminator byte
 * - (4) val len = 0
 * - (1) trailing NUL byte
 * ie, 6 bytes.
 */
#define MSG_HEADER_LEN 5
#define MSG_MIN_PARAM_LEN 6
#define MSG_MIN_LEN (MSG_HEADER_LEN + MSG_MIN_PARAM_LEN)
#define MSG_MAX_LEN 0x1FFFFFFF

// for expert message
#define MSG_MIN_LEN_STR "11"
#define MSG_MAX_LEN_STR "536870911"

// Normally set by Wireshark builds
#ifndef VERSION
# define VERSION        "1.0.5"
#endif

/*
 * holds the total number of messages and pdus
 * in a reassembled packet
 */
typedef struct pdu_info {
    unsigned int num_msgs;
    unsigned int num_pdus;
} pdu_info;

static dissector_handle_t p4rpc_handle;

// for tls
static dissector_handle_t p4rpc_tls_handle;

/*
* If it is false then the parameters will be decoded
* only as a "name=value" string.
*
* If prefs_varval_tree is true then the name=val parameters
* in each message will be decoded as a tree (in addition
* to as a "name=value" string), with separate child nodes
* for each of the name, value length, and value.
*
* This options can be set in the P4RPC preferences dialog in
*     Preferences -> Protocols -> P4RPC
* in the "Show message parameters as a tree" checkbox.
*/
typedef struct {
    unsigned int prev_tcp_port;
    unsigned int cur_tcp_port;
    unsigned int prev_tls_port;
    unsigned int cur_tls_port;
    bool prev_heur_enable;
    bool cur_heur_enable;
    bool prefer_tls; // enable TLS
    bool varval_tree; // enable displaying var=val as a tree
    bool hide_nul; // hide the terminating NUL of a variable
} p4prefs_t;

/*
 * Our global preferences
 */
static p4prefs_t p4prefs = {
    P4RPC_TCP_PORT, // prev tcp port
    P4RPC_TCP_PORT, // cur tcp port
    P4RPC_TLS_PORT, // prev tls port
    P4RPC_TLS_PORT, // cur tls port
    true, // prev heur enable
    true, // cur heur enable
    true, // prefer_tls
    true, // varval_tree
    true, // hide_nul
};

static int proto_p4rpc;         // main tree proto
static int ett_p4rpc;           // first registered subtree proto
static int ett_argtree;         // second registered subtree proto
static int ett_haverec;         // third registered subtree proto

// header indices
static int hf_p4rpc_checksum_len;
static int hf_p4rpc_len;
static int hf_p4rpc_varbytes;

// name=value subtree indices
static int hf_p4rpc_varname;
static int hf_p4rpc_varvallen;
static int hf_p4rpc_varval;
static int hf_p4rpc_have_client_path;
static int hf_p4rpc_have_depot_path;
static int hf_p4rpc_have_file_rev;
static int hf_p4rpc_have_file_type;
static int hf_p4rpc_have_file_datetime;
static int hf_p4rpc_func; // func value
static int hf_p4rpc_handle; // handle value
static int hf_p4rpc_action; // action value
static int hf_p4rpc_confirm; // confirm value
static int hf_p4rpc_num_msgs; // num mgs in packet
static int hf_p4rpc_nul; // NUL terminator byte after param value

// expert fields (for packet warnings, errors, etc)
static expert_field ei_p4rpc_msg_short;
static expert_field ei_p4rpc_msg_len_cksum;
static expert_field ei_p4rpc_msg_len;
static expert_field ei_p4rpc_msg_val_len;
static expert_field ei_p4rpc_msg_val_nul;

void proto_register_p4rpc(void);
void proto_reg_handoff_p4rpc(void);

// used for calculating the checksum of the message length field
static uint8_t
calc_checksum( uint32_t val )
{
    return ( (val & 0xFF) ^ ((val >> 8) & 0xFF) ^ ((val >> 16) & 0xFF) ^ ((val >> 24) & 0xFF) );
}

/*
 * dissect a single P4RPC message (request or response)
 *
 * Format of a P4RPC message:
 *      offset  len (always LE)         description
 *      ------  ---------------         -----------
 *      0       1 byte                  len XOR [see calc_checksum()]
 *      1       4 bytes                 len (uint32_t)
 *      5       N parameters
 *      Each param:
 *      *       M bytes                 ASCIIZ param name
 *              1 byte                  NUL byte (the Z in ASCIIZ)
 *              4 bytes                 length of the data (uint32_t)
 *              data_len bytes          data (value)
 *              1 byte                  NUL
 */
static uint32_t
dissect_one_p4rpc_message( tvbuff_t *tvb, uint32_t offset, uint32_t *seqno _U_,
    packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    uint32_t msg_start = offset;

    // add an item to the parent tree and attach a subtree to it
    proto_item *ti = proto_tree_add_item( tree, proto_p4rpc, tvb, 0, -1, ENC_NA );
    proto_item *ti_tree = proto_item_add_subtree( ti, ett_p4rpc );

    // we need at least MSG_HEADER_LEN bytes to find the message length
    if ( !tvb_bytes_exist(tvb, offset, MSG_HEADER_LEN) ) {
        proto_tree_add_expert_format(ti_tree, pinfo, &ei_p4rpc_msg_short, tvb,
            0, MSG_HEADER_LEN,
            "Invalid message: Fewer than %d bytes available", MSG_HEADER_LEN );
    }

    // add the checksum of the length field as an item to our subtree
    uint8_t cksum_of_len = tvb_get_uint8( tvb, offset );
    proto_tree_add_item( ti_tree, hf_p4rpc_checksum_len, tvb, offset, 1, ENC_NA );
    offset++;

    // add the length field as an item to our subtree
    uint32_t msg_len = tvb_get_letohl( tvb, offset );
    proto_tree_add_item( ti_tree, hf_p4rpc_len, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN );
    offset += sizeof(uint32_t);

    // warn if the length checksum doesn't match the actual checksum
    if( cksum_of_len != calc_checksum(msg_len) ) {
        proto_tree_add_expert_format( ti_tree, pinfo, &ei_p4rpc_msg_len_cksum, tvb, 0, MSG_HEADER_LEN,
            "checksum mismatch: expected 0x%0X, got 0x%0X for length %d (0x%0X)",
            cksum_of_len, calc_checksum(msg_len), msg_len, msg_len );
    }

    // warn if the message length is out of bounds
    if ( msg_len < MSG_MIN_LEN || msg_len > MSG_MAX_LEN ) {
        proto_tree_add_expert_format( ti_tree, pinfo, &ei_p4rpc_msg_len, tvb, 1, sizeof(uint32_t),
            "Message length %d (0x%0X) not in range [%d, %d]", msg_len, msg_len,
            MSG_MIN_LEN, MSG_MAX_LEN );
    }

    // there's something wrong if msg len exceeds the captured data
    uint32_t tvb_len = tvb_captured_length( tvb );
    if( msg_len > tvb_len - MSG_HEADER_LEN ) {
        proto_tree_add_expert_format( ti_tree, pinfo, &ei_p4rpc_msg_len, tvb, 1, sizeof(uint32_t),
            "Message length %d (0x%0X) exceeds tvb length (%d)",
            msg_len, msg_len, tvb_len - MSG_HEADER_LEN );

        // don't try to dissect past the end of the captured data
        msg_len = tvb_len - MSG_HEADER_LEN;
    }

    // process each param {name, value}
    while( offset - msg_start < msg_len )
    {
        // the offset to the start of the name of the parameter
        uint32_t name_offset = offset;
        uint32_t name_len;

        // get the param name
        const uint8_t *varname = tvb_get_stringz_enc( pinfo->pool, tvb, offset, &name_len, ENC_UTF_8 );
        offset += name_len; // NB: name_len counts the NUL terminator byte

        uint32_t vallen_offset = offset; // the offset to the start of the value length

        // get the param value length
        uint32_t vallen = tvb_get_letohl( tvb, offset );
        offset += sizeof(uint32_t);

        // get the param value
        uint32_t val_offset = offset; // the offset to the start of the value
        uint8_t *varval = tvb_get_string_enc( pinfo->pool, tvb, offset, vallen, ENC_UTF_8 );
        int32_t tot_var_len = name_len + vallen + sizeof(uint32_t);

        // get the (expected) NUL byte
        uint32_t nul_offset = offset + vallen;
        uint8_t zero = tvb_get_uint8( tvb, nul_offset );

#define ARGBUF_SZ       128
        // make our "var=val" string
        char *argbuf = wmem_alloc( pinfo->pool, ARGBUF_SZ );
        int bytes_written;
        /* Pass in bufsz-1 to save space for closing bracket. */
        bytes_written = snprintf( argbuf, ARGBUF_SZ-1, "%s = {%s",
            (*varname ? varname : (const uint8_t *)"<none>"), varval );
        /* Returns number of bytes that would have been written (not including
         * the null terminator) if not for the  buffer size limit. */
        if (bytes_written > ARGBUF_SZ - 2) { // Possibly truncated
            ws_utf8_truncate( argbuf, ARGBUF_SZ-2 ); // ensure no partial char at the end
        }
        g_strlcat( argbuf, "}", ARGBUF_SZ ); // close our bracket

        // used to check if a value length goes past the end of the message
        uint32_t bytes_left = msg_len - (offset - msg_start) + MSG_HEADER_LEN;

        // is our "var=val" item a tree or just text?
        if( p4prefs.varval_tree )
        {
            // add a new item item to our subtree and attach a new "var=value" sub-subtree to it
            proto_item *ti_arg = proto_tree_add_item( ti_tree, proto_p4rpc, tvb, name_offset, tot_var_len, ENC_NA );
            proto_item *arg_tree = proto_item_add_subtree( ti_arg, ett_argtree );
            proto_item_set_text( arg_tree, "%s", argbuf );

            // add the param name to our sub-subtree
            proto_tree_add_item( arg_tree, hf_p4rpc_varname, tvb, name_offset, name_len, ENC_UTF_8 );

            // add the length of the param value to our sub-subtree
            proto_tree_add_item( arg_tree, hf_p4rpc_varvallen, tvb, vallen_offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN );

            // add the param value to our sub-subtree
            proto_item *vv_rec = proto_tree_add_item( arg_tree, hf_p4rpc_varval, tvb, val_offset, vallen, ENC_NA );

            /*
             * Special handling for the "haveRec" parameter
             * because it's a compound structure.
             */
            if( strcmp((char *)varname, "haveRec") == 0 ) {
                uint32_t cur_offset = val_offset;

                /*
                 * Format of the haveRec field:
                 *
                 * struct haveRec {
                 *     char clientPath[];
                 *     char depotPath[];
                 *     uint32_t rev;
                 *     uint32_t type;
                 *     uint32_t date; // sometimes a uint64_t
                 * };
                 */

                // add a new item item to our sub-subtree and attach a new "value" sub-subtree to it
                proto_item *have_tree = proto_item_add_subtree( vv_rec, ett_haverec );

                // add the client path to our sub-sub-subtree
                uint32_t client_len;
                tvb_get_stringz_enc( pinfo->pool, tvb, cur_offset, &client_len, ENC_UTF_8 );
                proto_tree_add_item( have_tree, hf_p4rpc_have_client_path, tvb, cur_offset, client_len, ENC_UTF_8 );
                cur_offset += client_len;

                // add the depot path to our sub-sub-subtree
                uint32_t depot_len;
                tvb_get_stringz_enc( pinfo->pool, tvb, cur_offset, &depot_len, ENC_UTF_8 );
                proto_tree_add_item( have_tree, hf_p4rpc_have_depot_path, tvb, cur_offset, depot_len, ENC_UTF_8 );
                cur_offset += depot_len;

                // add the file rev number to our sub-sub-subtree
                proto_tree_add_item( have_tree, hf_p4rpc_have_file_rev, tvb, cur_offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN );
                cur_offset += sizeof(uint32_t);

                // add the file type to our sub-sub-subtree
                proto_tree_add_item( have_tree, hf_p4rpc_have_file_type, tvb, cur_offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN );
                cur_offset += sizeof(uint32_t);

                /*
                 * Add the file datetime to our sub-sub-subtree.
                 * If there are 8 bytes remaining before the NUL terminator
                 * then all 8 are the 64-bit datetime.
                 * Otherwise the next 4 bytes are the 32-bit datetime.
                 */
                uint32_t datetime_len = (cur_offset + sizeof(uint64_t) < nul_offset )
                                      ? sizeof(uint64_t)
                                      : sizeof(uint32_t);
                proto_tree_add_item( have_tree, hf_p4rpc_have_file_datetime,
                    tvb, cur_offset, datetime_len, ENC_LITTLE_ENDIAN );
            }

            // decode the nul terminator
            proto_item *nul_item =
                proto_tree_add_item( arg_tree, hf_p4rpc_nul, tvb, nul_offset, 1, ENC_NA );
            if( p4prefs.hide_nul )
                proto_item_set_hidden( nul_item );

            if( zero )
            {
                // add a new subtree to the value field for the expert info
                proto_item *expert_tree = proto_item_add_subtree( arg_tree, ett_argtree );
                proto_tree_add_expert_format( expert_tree, pinfo, &ei_p4rpc_msg_val_nul,
                    tvb, nul_offset, 1,
                    "Terminating NUL byte is 0x%0X instead of 0x0",
                    zero );
            }

            // does the value go past the end of the message?
            if( vallen > bytes_left )
            {
                proto_tree_add_expert_format( arg_tree, pinfo, &ei_p4rpc_msg_val_len,
                tvb, vallen_offset, sizeof(uint32_t),
                "Invalid value: length %d > %d bytes remaining in message",
                vallen, bytes_left );

                // don't try to read past the end
                vallen = bytes_left;
            }
        } else {
            // add "name=value" to be a leaf item to our subtree
            proto_tree_add_bytes_format( ti_tree, hf_p4rpc_varbytes, tvb,
                name_offset, tot_var_len, NULL, "%s", argbuf );

            // add the param name to our sub-subtree
            proto_tree_add_item( ti_tree, hf_p4rpc_varname, tvb, name_offset, name_len, ENC_UTF_8 );

            // add the length of the param value to our sub-subtree
            proto_tree_add_item( ti_tree, hf_p4rpc_varvallen, tvb, vallen_offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN );

            // add the param value to our sub-subtree
            proto_tree_add_item( ti_tree, hf_p4rpc_varval, tvb, val_offset, vallen, ENC_NA );

            // decode the nul terminator
            proto_item *nul_item =
                proto_tree_add_item( ti_tree, hf_p4rpc_nul, tvb, nul_offset, 1, ENC_NA );
            if( p4prefs.hide_nul )
                proto_item_set_hidden( nul_item );

            // report incorrect NUL terminator
            if( zero )
            {
                proto_tree_add_expert_format( ti_tree, pinfo, &ei_p4rpc_msg_val_nul,
                    tvb, offset+vallen, 1,
                    "Invalid terminating NUL byte is 0x%0X instead of 0x0",
                    zero );
            }

            // does the value go past the end of the message?
            if( vallen > bytes_left )
            {
                proto_tree_add_expert_format( ti_tree, pinfo, &ei_p4rpc_msg_val_len,
                    tvb, vallen_offset, sizeof(uint32_t),
                    "Invalid value: var \"%s\" length %d > %d bytes remaining in message",
                    varname, vallen, bytes_left );

                // don't try to read past the end
                vallen = bytes_left;
            }

        } // var=val subtree

        /*
         * special "alias" handling for "func" and "handle" params, etc.
         */

        if( strcmp((char *)varname, "func") == 0 )
        {
            // add the "func" name to the subtree (not sub-subtree) text
            proto_item_append_text( ti_tree, " : [%s] [len=%d]",
                varval, offset+vallen+1 );

            /*
             * Special case "func" and "handle" for convenience,
             * so that a filter can be written as:
             *  p4rpc.func == "sync"
             * rather than as:
             *  p4rpc.var.name == "func" && p4rpc.var.val == "sync"
             *
             * Allow filtering by the value of the "func" param.
             * Don't show it because the "func" is already shown.
             */
            proto_item *func_item = proto_tree_add_item(
                ti_tree, hf_p4rpc_func, tvb, val_offset, vallen, ENC_UTF_8);
            proto_item_set_hidden( func_item );

        }

        if( strcmp((char *)varname, "handle") == 0 )
        {
            /*
             * Special case "func" and "handle" for convenience,
             * so that a filter can be written as:
             *  p4rpc.handle == "sync"
             * rather than as:
             *  p4rpc.var.name == "handle" && p4rpc.var.val == "sync"
             * Allow filtering by the value of the "handle" param.
             * Don't show it because the "handle" is already shown.
             */
            proto_item *handle_item = proto_tree_add_item(
                ti_tree, hf_p4rpc_handle, tvb, val_offset, vallen, ENC_UTF_8 );
            proto_item_set_hidden( handle_item );
        }

        if( strcmp((char *)varname, "action") == 0 )
        {
            proto_item *handle_item = proto_tree_add_item(
                ti_tree, hf_p4rpc_action, tvb, val_offset, vallen, ENC_UTF_8 );
            proto_item_set_hidden( handle_item );
        }

        if( strcmp((char *)varname, "confirm") == 0 )
        {
            proto_item *handle_item = proto_tree_add_item(
                ti_tree, hf_p4rpc_confirm, tvb, val_offset, vallen, ENC_UTF_8 );
            proto_item_set_hidden( handle_item );
        }

        offset += vallen + 1;   // + 1 for the NUL data terminator
    }

    return offset;
}

/*
 * This method dissects a fully reassembled PDU
 * - it will contain one complete P4RPC message
 */
static int
dissect_p4rpc_pdu( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data )
{
    uint32_t offset = 0;
    uint32_t tvb_len = tvb_captured_length( tvb );
    uint32_t seqno = 0xFFFF;
    pdu_info *info = (pdu_info *) data;

    ++info->num_pdus; // we get called once per pdu

    col_set_str( pinfo->cinfo, COL_PROTOCOL, "P4RPC" );

    /*
     * Process every message in this PDU
     * (but a PDU is exactly on message
     * so we pass through the loop exactly once).
     */
    while( offset < tvb_len )
    {
        offset = dissect_one_p4rpc_message( tvb, offset, &seqno, pinfo, tree, data );
        ++info->num_msgs; // we processed another message
    }

    return offset;
}

/*
 * determine PDU length of protocol p4rpc
 */
static unsigned int
get_p4rpc_pdu_len( packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_ )
{
    return tvb_get_letohl(tvb, offset+1) + MSG_HEADER_LEN;
}

/*
 * The main dissecting routine:
 * - A P4RPC Protocol Data Unit (PDU) consists of one P4RPC message.
 * - A single (large) PDU may be split into multiple packets.
 *   In this case Wireshark will dissect all but the last
 *   of the component packets as TCP, adding "[TCP PDU reassembled in NN]"
 *   to the INFO field of each packet (where NN is the number of the final
 *   packet in the PDU), and dissect the final packet of the PDU
 *   as the concatenation of all of the component packets.
 *
 * - "data" is a pointer to a pdu_info that is a count
 *   of the numbers of messages and PDUs that have been dissected.
 *   Because there is exactly one message in a PDU, these counts
 *   are always equal, but if we ever allow bundling multiple
 *   messages in a PDU then the counts can differ.
 *   I don't expect this will ever happen but it's cheap
 *   to count each of them, so USE_NUM_PDUS and SHOW_NUM_PDUS
 *   default to undefined.
 */
static int
dissect_p4rpc( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    pdu_info    info = { 0, 0 };

    // reassemble TCP packets and call dissect_p4rpc_pdu on each pdu
    tcp_dissect_pdus( tvb, pinfo, tree, true, MSG_HEADER_LEN,
                     get_p4rpc_pdu_len, dissect_p4rpc_pdu, &info );

    /*
     * Add [msgs=NN] to the INFO of the packet tree where NN
     * is the number of messages in the packet
     * (or [msgs=NN, pdus=NN] if we're showing PDUs as well).
     */
#define NUMBUF_SZ 48
    char *info_buf = wmem_alloc( pinfo->pool, NUMBUF_SZ ); /* big enough */

    snprintf( info_buf, NUMBUF_SZ-1, " [msgs=%d]", info.num_msgs );

    col_append_str( pinfo->cinfo, COL_INFO, info_buf );

    /*
     * Similar to "func" and "hidden", allow filtering by number
     * of messages in a packet.
     * Hidden because we already show it in COL_INFO.
     */
    proto_item *num_msgs_item = proto_tree_add_uint(
        tree, hf_p4rpc_num_msgs, tvb, 0, 0, info.num_msgs );
    proto_item_set_hidden( num_msgs_item );

    return tvb_captured_length( tvb );
}

/*
 * Called to dissect a decrypted tvb, so just call
 * our p4rpc dissector.
 */
static int
dissect_tls_p4rpc( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data )
{
    return dissect_p4rpc( tvb, pinfo, tree, data );
}

/*
 * Return true if this is a P4RPC packet
 * else return false so that another dissector can try.
 * - if the checksum matches and length is reasonable
 *   then assume that it is but that's not very definitive.
 * Don't enable USE_DEBUG unless you want to see a lot of error messages,
 * because non-P4RPC packets are very likely going to emit one.
 */
static bool
p4rpc_check_heur( packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_ )
{
    uint8_t cksum_of_len = 0;
    uint32_t msg_len = 0;

    // if we don't have at least our header, it isn't P4RPC
    if( !tvb_bytes_exist(tvb, offset, MSG_HEADER_LEN) ) {
        return false;
    }

    // fetch the checksum from the tvb
    cksum_of_len = tvb_get_uint8(tvb, offset);

    // not P4RPC if the message is too small or too big
    msg_len = tvb_get_letohl(tvb, offset+1);

    if( msg_len < MSG_MIN_LEN || msg_len > MSG_MAX_LEN)  {
        return false;
    }

    // not P4RPC if the message length exceeds the captured data
    uint32_t tvb_len = tvb_captured_length( tvb );
    if( msg_len > tvb_len - MSG_HEADER_LEN ) {
        return false;
    }

    // not P4RPC if the checksum is wrong
    if( cksum_of_len != calc_checksum(msg_len) ) {
        return false;
    }

    return true;
}

/*
 * Check to see if this packet is P4RPC and dissect it if so,
 * else return false and let another dissector try.
 */
static bool
dissect_p4rpc_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data )
{
    if( !p4rpc_check_heur(pinfo, tvb, 0, data) )
        return false;

    /*
     * Assume that this is a P4RPC packet and set p4rpc as the dissector
     * for the rest of the packets in this conversion.
     */
    conversation_t *conversation = find_or_create_conversation( pinfo );
    if( conversation )
        conversation_set_dissector( conversation, p4rpc_handle );

    // go ahead and dissect it
    int rslt = dissect_p4rpc( tvb, pinfo, tree, NULL );

    return rslt > 0 ? true : false;
}

/*
 * proto_reg_handoff_p4rpc() calls this with isInit == true
 * - set up initially, ignoring the p4prefs.pref_* members
 * prefs_cb() calls this with isInit == false
 * - change only the ports that have changes
 */
static void
p4rpc_setup_ports( bool isInit )
{
    bool tcp_port_changed = p4prefs.cur_tcp_port != p4prefs.prev_tcp_port;
    bool tls_port_changed = p4prefs.cur_tls_port != p4prefs.prev_tls_port;
    bool heur_changed = p4prefs.cur_heur_enable != p4prefs.prev_heur_enable;

    /*
     * Claim tcp.port for P4RPC if:
     * - we don't prefer TLS, and
     *   we're initializing or the tls port has changes
     */
    if( !p4prefs.prefer_tls && (isInit || tcp_port_changed) )
    {
        if( !isInit )
            dissector_delete_uint( "tcp.port", p4prefs.prev_tcp_port, p4rpc_handle );
        dissector_add_uint( "tcp.port", p4prefs.cur_tcp_port, p4rpc_handle );
    }

    /*
     * Allow P4RPC to grab our TLS port (after decryption) by default
     * - if we prefer TLS, and
     *   we're initializing or the tls port has changes
     */
    if( p4prefs.prefer_tls && (isInit || tls_port_changed) )
    {
        if( !isInit )
            dissector_delete_uint( "tls.port", p4prefs.prev_tls_port, p4rpc_handle );
        dissector_add_uint( "tls.port", p4prefs.cur_tls_port, p4rpc_handle );
    }

    /*
     * Add or delete our TCP heuristic packet finder if TLS is lower priority.
     */
    if( isInit || heur_changed )
    {
        /*
         * We don't delete the heuristic dissector during initialization
         * because none could have been registered already.
         *
         * After initialization it's still possible that no heuristic
         * dissector has registered.
         * Rather than track whether or not one has already been registered
         * we always delete it, because heur_dissector_delete() is a no-op
         * if the dissector isn't registered.
         */
        if( !isInit )
            heur_dissector_delete( "tcp", dissect_p4rpc_heur, proto_p4rpc );

        if( p4prefs.cur_heur_enable )
        {
            heur_dissector_add( "tcp", dissect_p4rpc_heur, "P4RPC over TCP", "p4rpc_tcp", proto_p4rpc, HEURISTIC_ENABLE );
        }
    }

    /*
     * remember our current settings
     */

    if( tcp_port_changed )
        p4prefs.prev_tcp_port = p4prefs.cur_tcp_port;

    if( tls_port_changed )
        p4prefs.prev_tls_port = p4prefs.cur_tls_port;

    if( heur_changed )
        p4prefs.prev_heur_enable = p4prefs.cur_heur_enable;
}

/*
 * Called after the user has changed preferences.
 * We validate the settings, alert the user if appropriate,
 * and apply those that have changed.
 */
static void
prefs_cb(void)
{
    /*
     * Warn against making both ports the same
     * because the P4RPC dissector may take
     * precedence over the TLS dissector
     */
    if( p4prefs.prefer_tls && (p4prefs.cur_tcp_port == p4prefs.cur_tls_port) )
    {
        report_warning( "You have set both the P4RPC TCP and TLS ports to %d.\n"
            "If this prevents Wireshark from decoding both the TLS and"
            " the P4RPC layers then set the TLS port to the server port"
            " and set the TCP port to any other port.\n"
            "\nDisabling \"Decrypt TLS before P4RPC\" might help if TLS"
            " grabs the port first and blocks P4RPC from decoding packets.",
            p4prefs.cur_tcp_port );
    }

    p4rpc_setup_ports( false );
}

/*
 * Define our preferences pane and hook in our callback routine (above).
 */
static void
register_prefs(void)
{
    // register our callback func
    module_t *prefs_mod = prefs_register_protocol( proto_p4rpc, prefs_cb );

    // tcp.port
    prefs_register_uint_preference( prefs_mod, "tcp.port",
        "TCP port",
        "Default P4RPC-over-TCP port.",
        10, // decimal
        &p4prefs.cur_tcp_port );

    // tls.port
    prefs_register_uint_preference( prefs_mod, "tls.port",
        "TLS port",
        "Default P4RPC-over-TLS port (should not be same as \"TCP port\" if \"TLS priority\" is disabled).",
        10, // decimal
        &p4prefs.cur_tls_port );

    // tls preference
    prefs_register_bool_preference( prefs_mod, "prefer_tls",
        "Decrypt TLS before P4RPC",
        "Always decrypt packets before P4RPC tries to dissect them.\n\n"
        "- Enabled: If traffic is TLS then then it will be decrypted and then decoded as P4RPC.\n"
        "- Disabled: Traffic on \"TCP port\" will not be decrypted even if it is TLS.\n"
        "\nRelevant only when \"TCP port\" is the same as \"TLS port\", "
        "but normally should be enabled.",
        &p4prefs.prefer_tls );

    // tcp heuristics preference
    prefs_register_bool_preference( prefs_mod, "tcp_heur",
        "Enable P4RPC/TCP heuristic detection",
        "Enable heuristic detection of P4RPC over TCP.\n"
        "\nTry to guess at P4RPC packets on ports other than \"TCP port\".\n"
        "\nEnable this if you frequently dissect P4RPC traffic on different ports,"
        " so that you won't need to use \"Decode As...\" often.\n"
        "\nP4RPC over TLS is always auto-detected when \"Decrypt TLS before P4RPC\" is enabled,"
        " whether or not this option is enabled.",
        &p4prefs.cur_heur_enable );

    // var=val tree preference
    prefs_register_bool_preference( prefs_mod, "message_params_as_tree",
        "Show message parameters as a \"var=value\" tree",
        "Show message parameters as a \"var=value\" subtree with \"var\", "
        " \"length\", and \"val\" children.\n"
        "\nIt is recommended to enable this.",
        &p4prefs.varval_tree );

    // hide_nul preference
    prefs_register_bool_preference( prefs_mod, "hide_nul",
        "Don't add the NUL byte of var=val params into the protocol tree",
        "If set, don't add a subtree item for the ending NUL byte of a message parameter",
        &p4prefs.hide_nul );

    /*
     * Not real preferences, just some static text to display.
     * Added a dummy one to separate the version string a little.
     */
    prefs_register_static_text_preference( prefs_mod, "", "", "" );
    prefs_register_static_text_preference( prefs_mod, "version",
        "P4RPC dissector version: " VERSION,
        VERSION ); // this last arg doesn't seem to get displayed
}

/*
 * Register P4RPC dissector with its tree items and filter variables.
 */
void
proto_register_p4rpc(void)
{
    static hf_register_info hf[] = {
        {
            &hf_p4rpc_checksum_len,
            {
                "message cksum of len",
                "p4rpc.cksum.len",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                "checksum of p4rpc.msg.len (XOR of the 4 length bytes)",
                HFILL
            }
        },
        {
            &hf_p4rpc_len,
            {
                "message len",
                "p4rpc.msg.len",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "Total number of bytes in this message",
                HFILL
            }
        },
        {
            // comprises p4rpc.var.name, p4rpc.var.val.len, p4rpc.var.val
            &hf_p4rpc_varbytes,
            {
                "param name=val", // placeholder
                "p4rpc.var.name.val",
                FT_STRINGZTRUNC, // or FT_BYTES
                BASE_NONE,
                NULL,
                0x0,
                "Combined var name and value",
                HFILL
            },
        },
        {
            &hf_p4rpc_nul, // p_id (int)
            {                       // hfinfo (header_field_info)
                "param NUL terminator", // name (const char *)
                "p4rpc.var.nul",        // abbrev (const char *)
                FT_UINT8,               // type (enum ftenum)
                BASE_HEX,               // display (int)
                NULL,                   // strings (const void *)
                0x0,                    // bitmask (uint64_t)
                "Parameter value NUL terminator byte", // blurb (const char *)
                HFILL
            }
        },
        {
            &hf_p4rpc_func,
            {
                "param func",
                "p4rpc.func",
                FT_STRINGZ,
                BASE_NONE,
                NULL,
                0x0,
                "Name of the requested function [required]",
                HFILL
            }
        },
        {
            &hf_p4rpc_handle, // p_id (int)
            {                       // hfinfo (header_field_info)
                "param handle",         // name (const char *)
                "p4rpc.handle",         // abbrev (const char *)
                FT_STRINGZ,             // type (enum ftenum)
                BASE_NONE,              // display (int)
                NULL,                   // strings (const void *)
                0x0,                    // bitmask (uint64_t)
                "Name of response function [optional]", // blurb (const char *)
                HFILL
            }
        },
        {
            &hf_p4rpc_action, // p_id (int)
            {                       // hfinfo (header_field_info)
                "param action",         // name (const char *)
                "p4rpc.action",         // abbrev (const char *)
                FT_STRINGZ,             // type (enum ftenum)
                BASE_NONE,              // display (int)
                NULL,                   // strings (const void *)
                0x0,                    // bitmask (uint64_t)
                "Name of action function [optional]", // blurb (const char *)
                HFILL
            }
        },
        {
            &hf_p4rpc_confirm, // p_id (int)
            {                       // hfinfo (header_field_info)
                "param confirm",        // name (const char *)
                "p4rpc.confirm",        // abbrev (const char *)
                FT_STRINGZ,             // type (enum ftenum)
                BASE_NONE,              // display (int)
                NULL,                   // strings (const void *)
                0x0,                    // bitmask (uint64_t)
                "Name of confirm function [optional]", // blurb (const char *)
                HFILL
            }
        },
        {
            &hf_p4rpc_num_msgs, // p_id (int)
            {                       // hfinfo (header_field_info)
                "number of messages",   // name (const char *)
                "p4rpc.num.msgs",       // abbrev (const char *)
                FT_UINT32,              // type (enum ftenum)
                BASE_DEC,               // display (int)
                NULL,                   // strings (const void *)
                0x0,                    // bitmask (uint64_t)
                "Number of messages in this (reassembled) packet", // blurb (const char *)
                HFILL
            }
        }
    };

    // name=value subtree
    static hf_register_info nv[] = {
        {
            &hf_p4rpc_varname,
            {
                "param name",
                "p4rpc.var.name",
                FT_STRINGZ,
                BASE_NONE,
                NULL,
                0x0,
                "Name of this parameter",
                HFILL
            }
        },
        {
            &hf_p4rpc_varvallen,
            {
                "param value len",
                "p4rpc.var.val.len",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "Length of the value of this parameter",
                HFILL
            }
        },
        {
            &hf_p4rpc_varval,
            {
                "param value",
                "p4rpc.var.val",
                FT_STRINGZTRUNC, // really FT_BYTES, but starts with a FT_STRINGZ
                BASE_NONE,
                NULL,
                0x0,
                "Value of this parameter",
                HFILL
            }
        },
    };

    // haveRec subtree
    static hf_register_info hr[] = {
        {
            &hf_p4rpc_have_client_path,
            {
                "client path",
                "p4rpc.have.client.path",
                FT_STRINGZ,
                BASE_NONE,
                NULL,
                0x0,
                "Value of this parameter",
                HFILL
            }
        },
        {
            &hf_p4rpc_have_depot_path,
            {
                "depot path",
                "p4rpc.have.depot.path",
                FT_STRINGZ,
                BASE_NONE,
                NULL,
                0x0,
                "Value of this parameter",
                HFILL
            }
        },
        {
            &hf_p4rpc_have_file_rev,
            {
                "file rev",
                "p4rpc.have.file.rev",
                FT_INT32,
                BASE_DEC,
                NULL,
                0x0,
                "Value of this parameter",
                HFILL
            }
        },
        {
            &hf_p4rpc_have_file_type,
            {
                "file type",
                "p4rpc.have.file.type",
                FT_INT32,
                BASE_DEC,
                NULL,
                0x0,
                "Value of this parameter",
                HFILL
            }
        },
        {
            &hf_p4rpc_have_file_datetime,
            {
                "file datetime",
                "p4rpc.have.file.datetime",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_LOCAL,
                NULL,
                0x0,
                "Value of this parameter",
                HFILL
            }
        }
    };

    /*
     * Register our expert info variables
     * (message warnings, errors, corruption, etc)
     */
    expert_module_t *expert_p4rpc = NULL;

    static ei_register_info ei[] = {
        {
            &ei_p4rpc_msg_short,
            {
                "p4rpc.msg.short",
                PI_MALFORMED,
                PI_ERROR,
                "available data < 5 bytes",
                EXPFILL
            }
        },
        {
            &ei_p4rpc_msg_len_cksum,
            {
                "p4rpc.msg.len_cksum",
                PI_CHECKSUM,
                PI_WARN,
                "message length checksum mismatch",
                EXPFILL
            }
        },
        {
            &ei_p4rpc_msg_len,
            {
                "p4rpc.msg.msglen",
                PI_MALFORMED,
                PI_ERROR,
                "message length < " MSG_MIN_LEN_STR " or > " MSG_MAX_LEN_STR,
                EXPFILL
            }
        },
        {
            &ei_p4rpc_msg_val_len,
            {
                "p4rpc.msg.val.len",
                PI_MALFORMED,
                PI_ERROR,
                "value length extends past end of message",
                EXPFILL
            }
        },
        {
            &ei_p4rpc_msg_val_nul,
            {
                "p4rpc.msg.val.nul",
                PI_MALFORMED,
                PI_WARN,
                "expected NUL terminator is not zero",
                EXPFILL
            }
        }
    };

    // Setup protocol subtree array
    static int *ett[] = {
        &ett_p4rpc
    };

    // Setup protocol subtree name=value array
    static int *ett_name_value[] = {
        &ett_argtree
    };

    // Setup protocol subtree haveRec value array
    static int *ett_haverec_value[] = {
        &ett_haverec
    };

    // Finally, register our protocol
    proto_p4rpc = proto_register_protocol (
        "P4RPC (Perforce Protocol)", // protocol long name
        "P4RPC",          // protocol short name
        "p4rpc"           // protocol filter_name
    );

    // register our variables
    proto_register_field_array( proto_p4rpc, hf, array_length(hf) );
    proto_register_subtree_array( ett, array_length(ett) );

    // register more variables
    proto_register_field_array( proto_p4rpc, nv, array_length(nv) );
    proto_register_subtree_array( ett_name_value, array_length(ett_name_value) );

    // register haverec variables
    proto_register_field_array( proto_p4rpc, hr, array_length(hr) );
    proto_register_subtree_array( ett_haverec_value, array_length(ett_haverec_value) );

    // register expert variables
    expert_p4rpc = expert_register_protocol( proto_p4rpc );
    expert_register_field_array( expert_p4rpc, ei, array_length(ei) );

    // register P4RPC as a TCP dissector
    p4rpc_handle = register_dissector_with_description(
        "p4rpc",           // dissector name
        "P4RPC",           // dissector description
        dissect_p4rpc,     // dissector function
        proto_p4rpc        // protocol being dissected
    );

    /*
     * register P4RPC as a TLS dissector
     *
     * We probably could just register dissect_p4rpc
     * as the TLS dissector as well.
     */
    p4rpc_tls_handle = register_dissector_with_description(
        "p4rpc.tls",       // dissector name
        "P4RPC over TLS",  // dissector description
        dissect_tls_p4rpc, // dissector function
        proto_p4rpc        // protocol being dissected
    );

    register_prefs();
} // proto_register_p4rpc

/*
 * Associate our dissector with ports.
 */
void
proto_reg_handoff_p4rpc(void)
{
    /*
     * Allow "Decode As" with any TCP packet.
     * - need to do it only once
     */
    dissector_add_for_decode_as( "tcp.port", p4rpc_handle );

    /*
     * Allow "Decode As" with any packet on our TLS port.
     * - need to do it only once
     */
    dissector_add_for_decode_as( "tls.port", p4rpc_handle );

    // all the setup that needs to be redone when prefs are changed
    p4rpc_setup_ports( true );
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
