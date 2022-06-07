/* packet-jxta.c
 *
 * Routines for JXTA packet dissection
 * JXTA specification from https://jxta-spec.dev.java.net (now at https://github.com/chaupal/jxta-spec ?)
 *
 * Copyright 2004-08, Mike Duigou <bondolo@dev.java.net>
 *
 * Heavily based on packet-jabber.c, which in turn is heavily based on
 * on packet-acap.c, which in turn is heavily based on
 * packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * Copied from packet-pop.c, packet-jabber.c, packet-udp.c, packet-http.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN "jxta"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/address_types.h>
#include <epan/expert.h>
#include <wsutil/str_util.h>

#include "packet-jxta.h"
#include "packet-http.h"

void proto_register_jxta(void);
void proto_reg_handoff_jxta(void);

static const gchar JXTA_UDP_SIG[] = { 'J', 'X', 'T', 'A' };
static const gchar JXTA_MSG_SIG[] = { 'j', 'x', 'm', 'g' };
static const gchar JXTA_MSGELEM_SIG[] = { 'j', 'x', 'e', 'l' };

static const gchar JXTA_WELCOME_MSG_SIG[] = { 'J', 'X', 'T', 'A', 'H', 'E', 'L', 'L', 'O', ' ' };

static const gchar* JXTA_WELCOME_MSG_VERSION_1_1 = "1.1";
static const gchar* JXTA_WELCOME_MSG_VERSION_3_0 = "3.0";

static const int JXTA_MSG_VERSION_1 = 0;
static const int JXTA_MSG_VERSION_2 = 1;

static const int JXTAMSG1_ELMFLAG_TYPE = 1 << 0;
static const int JXTAMSG1_ELMFLAG_ENCODING = 1 << 1;
static const int JXTAMSG1_ELMFLAG_SIGNATURE = 1 << 2;

static const int JXTAMSG2_ELMFLAG_UINT64_LENS = 1 << 0;
static const int JXTAMSG2_ELMFLAG_NAME_LITERAL = 1 << 1;
static const int JXTAMSG2_ELMFLAG_TYPE = 1 << 2;
static const int JXTAMSG2_ELMFLAG_SIGNATURE = 1 << 3;
static const int JXTAMSG2_ELMFLAG_ENCODINGS = 1 << 4;

static int proto_jxta = -1;
static int proto_message_jxta = -1;
static int jxta_tap = -1;

static dissector_table_t media_type_dissector_table = NULL;
static dissector_handle_t media_handle = NULL;
static dissector_handle_t stream_jxta_handle = NULL;
static dissector_handle_t tls_handle = NULL;

static int hf_uri_addr = -1;
static int hf_uri_src = -1;
static int hf_uri_dst = -1;
static int hf_jxta_udp = -1;
static int hf_jxta_udpsig = -1;
static int hf_jxta_welcome = -1;
static int hf_jxta_welcome_initiator = -1;
static int hf_jxta_welcome_sig = -1;
static int hf_jxta_welcome_destAddr = -1;
static int hf_jxta_welcome_pubAddr = -1;
static int hf_jxta_welcome_peerid = -1;
static int hf_jxta_welcome_noProp = -1;
static int hf_jxta_welcome_msgVers = -1;
static int hf_jxta_welcome_variable = -1;
static int hf_jxta_welcome_version = -1;
static int hf_jxta_framing = -1;
static int hf_jxta_framing_header = -1;
static int hf_jxta_framing_header_name = -1;
static int hf_jxta_framing_header_value_length = -1;
static int hf_jxta_framing_header_value = -1;
static int hf_jxta_message_address = -1;
static int hf_jxta_message_src = -1;
static int hf_jxta_message_dst = -1;
static int hf_jxta_message_sig = -1;
static int hf_jxta_message_version = -1;
static int hf_jxta_message_flags = -1;
static int hf_jxta_message_flag_utf16be = -1;
static int hf_jxta_message_flag_ucs32be = -1;
static int hf_jxta_message_names_count = -1;
static int hf_jxta_message_names_name = -1;
static int hf_jxta_message_element_count = -1;
static int hf_jxta_element = -1;
static int hf_jxta_element_sig = -1;
static int hf_jxta_element1_namespaceid = -1;
static int hf_jxta_element2_namespaceid = -1;
static int hf_jxta_element2_nameid = -1;
static int hf_jxta_element2_mimeid = -1;
static int hf_jxta_element2_encodingid = -1;
static int hf_jxta_element_flags = -1;
static int hf_jxta_element1_flag_hasType = -1;
static int hf_jxta_element1_flag_hasEncoding = -1;
static int hf_jxta_element1_flag_hasSignature = -1;
static int hf_jxta_element2_flag_64bitlens = -1;
static int hf_jxta_element2_flag_nameLiteral = -1;
static int hf_jxta_element2_flag_hasType = -1;
static int hf_jxta_element2_flag_hasSignature = -1;
static int hf_jxta_element2_flag_hasEncoding = -1;
static int hf_jxta_element2_flag_sigOfEncoded = -1;
static int hf_jxta_element_name = -1;
static int hf_jxta_element_type = -1;
static int hf_jxta_element_encoding = -1;
static int hf_jxta_element_content_len = -1;
static int hf_jxta_element_content_len64 = -1;
/* static int hf_jxta_element_content = -1; */

/**
*    JXTA Protocol subtree handles
**/
static gint ett_jxta = -1;
static gint ett_jxta_welcome = -1;
static gint ett_jxta_udp = -1;
static gint ett_jxta_framing = -1;
static gint ett_jxta_framing_header = -1;
static gint ett_jxta_msg = -1;
static gint ett_jxta_msg_flags = -1;
static gint ett_jxta_elem = -1;
static gint ett_jxta_elem_1_flags = -1;
static gint ett_jxta_elem_2_flags = -1;

static expert_field ei_media_too_short = EI_INIT;

static int uri_address_type = -1;

/**
*   global preferences
**/
static gboolean gDESEGMENT = TRUE;
static gboolean gMSG_MEDIA = TRUE;

static dissector_handle_t jxta_udp_handle;

/**
*   Stream Conversation data
**/
struct jxta_stream_conversation_data {
    port_type tpt_ptype;

    address initiator_tpt_address;
    guint32 initiator_tpt_port;
    guint32 initiator_welcome_frame;
    address initiator_address;

    address receiver_tpt_address;
    guint32 receiver_tpt_port;
    guint32 receiver_welcome_frame;
    address receiver_address;
};

typedef struct jxta_stream_conversation_data jxta_stream_conversation_data;

static const char* jxta_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == uri_address_type))
        return "jxta.message.src";

    if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == uri_address_type))
        return "jxta.message.dst";

    if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == uri_address_type))
        return "jxta.message.address";

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t jxta_ct_dissector_info = {&jxta_conv_get_filter_type};

static tap_packet_status
jxta_conversation_packet(void *pct, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *vip)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    const jxta_tap_header *jxtahdr = (const jxta_tap_header *) vip;

    add_conversation_table_data(hash, &jxtahdr->src_address, &jxtahdr->dest_address,
        0, 0, 1, jxtahdr->size, NULL, NULL, &jxta_ct_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static const char* jxta_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_ANY_ADDRESS) && (host->myaddress.type == uri_address_type))
        return "jxta.message.address";

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t jxta_host_dissector_info = {&jxta_host_get_filter_type};

static tap_packet_status
jxta_hostlist_packet(void *pit, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *vip)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    const jxta_tap_header *jxtahdr = (const jxta_tap_header *)vip;

    /* Take two "add" passes per packet, adding for each direction, ensures that all
    packets are counted properly (even if address is sending to itself)
    XXX - this could probably be done more efficiently inside hostlist_table */
    add_hostlist_table_data(hash, &jxtahdr->src_address, 0, TRUE, 1, jxtahdr->size, &jxta_host_dissector_info, ENDPOINT_NONE);
    add_hostlist_table_data(hash, &jxtahdr->dest_address, 0, FALSE, 1, jxtahdr->size, &jxta_host_dissector_info, ENDPOINT_NONE);
    return TAP_PACKET_REDRAW;
}

static int uri_to_str(const address* addr, gchar *buf, int buf_len)
{
    int copy_len = addr->len < (buf_len - 1) ? addr->len : (buf_len - 1);
    memcpy(buf, addr->data, copy_len );
    buf[copy_len] = '\0';
    return copy_len+1;
}

static int uri_str_len(const address* addr)
{
    return addr->len+1;
}

static const char* uri_col_filter_str(const address* addr _U_, gboolean is_src)
{
    if (is_src)
        return "uri.src";

    return "uri.dst";
}

/**
*   Prototypes
**/
static int dissect_jxta_udp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data);
static int dissect_jxta_stream(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data);
static jxta_stream_conversation_data *get_tpt_conversation(packet_info * pinfo);
static conversation_t *get_peer_conversation(packet_info * pinfo, jxta_stream_conversation_data* tpt_conv_data, gboolean create);

static int dissect_jxta_welcome(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, address * found_addr, gboolean initiator);
static int dissect_jxta_message_framing(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint64 * content_length,
                                        gchar ** content_type);
static int dissect_jxta_message(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data);
static int dissect_jxta_message_element_1(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint ns_count,
                                        const gchar ** namespaces);
static int dissect_jxta_message_element_2(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint ns_count,
                                        const gchar ** namespaces);
static int dissect_media( const gchar* fullmediatype, tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);

/**
*   Heuristically dissect a tvbuff containing a JXTA UDP Message
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return TRUE if the tvb contained JXTA data which was dissected otherwise FALSE
**/
static gboolean dissect_jxta_UDP_heur(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */
    int save_desegment_offset;
    guint32 save_desegment_len;
    int ret;

    if (tvb_strneql(tvb, 0, JXTA_UDP_SIG, sizeof (JXTA_UDP_SIG)) != 0) {
        /* Not a JXTA UDP packet (or not enough bytes to check for the sig) */
        return FALSE;
    }

    save_desegment_offset = pinfo->desegment_offset;
    save_desegment_len = pinfo->desegment_len;
    ret = dissect_jxta_udp(tvb, pinfo, tree, NULL);

    /* ws_message( "%d Heuristic UDP Dissection : %d", pinfo->num, ret ); */

    if (ret < 0) {
        /*
         * UDP is not a packet stream protocol, so the UDP dissector
         * should not, and will not, do the sort of dissection help
         * that the TCP dissector will.  If JXTA messages don't
         * start and end on UDP packet boundaries, the JXTA dissector
         * will have to do its own byte stream reassembly.
         */
        pinfo->desegment_offset = save_desegment_offset;
        pinfo->desegment_len = save_desegment_len;
        return FALSE;
    } else if (ret == 0) {
        /*
         * A clear rejection.
         */
        pinfo->desegment_offset = save_desegment_offset;
        pinfo->desegment_len = save_desegment_len;
        return FALSE;
    } else {
        /*
         * A clear acceptance.
         */
        return TRUE;
    }
}

/**
*   Heuristically dissect a tvbuff containing a JXTA TCP Stream
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return TRUE if the tvb contained JXTA data which was dissected otherwise FALSE
**/
static gboolean dissect_jxta_TCP_heur(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
    /* This is a heuristic dissector, which means we get all the TCP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */
    int save_desegment_offset;
    guint32 save_desegment_len;
    int ret;

    save_desegment_offset = pinfo->desegment_offset;
    save_desegment_len = pinfo->desegment_len;
    ret = dissect_jxta_stream(tvb, pinfo, tree, NULL);

    /* ws_message( "%d Heuristic TCP Dissection : %d", pinfo->num, ret ); */

    if (ret < 0) {
        /*
         * A heuristic dissector for a TCP-based protocol can reject
         * a packet, or it can request that more data be provided.
         * It must not attempt to do both, as the notion of doing both
         * is nonsensical - if the packet isn't considered a packet
         * for the dissector's protocol, that dissector won't be
         * dissecting it no matter *how* much more data is added.
         *
         * Therefore, we treat a negative return from
         * dissect_jxta_stream() as a rejection.
         *
         * If that's not desired - i.e., if we should keep trying to get
         * more data, in the hopes that we'll eventually be able to
         * determine whether the packet is a JXTA packet or not - we
         * should, in this case, leave pinfo->desegment_offset and
         * pinfo->desegment_len alone, and return TRUE, *NOT* FALSE.
         */
        pinfo->desegment_offset = save_desegment_offset;
        pinfo->desegment_len = save_desegment_len;
        return FALSE;
    } else if (ret == 0) {
        /*
         * A clear rejection.
         */
        pinfo->desegment_offset = save_desegment_offset;
        pinfo->desegment_len = save_desegment_len;
        return FALSE;
    } else {
        /*
         * A clear acceptance.
         */
        return TRUE;
    }
}

/**
*   Heuristically dissect a tvbuff containing a JXTA SCTP Stream
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return TRUE if the tvb contained JXTA data which was dissected otherwise FALSE
**/
static gboolean dissect_jxta_SCTP_heur(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
    /* This is a heuristic dissector, which means we get all the SCTP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */
    int save_desegment_offset;
    guint32 save_desegment_len;
    int ret;

    save_desegment_offset = pinfo->desegment_offset;
    save_desegment_len = pinfo->desegment_len;
    ret = dissect_jxta_stream(tvb, pinfo, tree, NULL);

    /* ws_message( "%d Heuristic SCTP Dissection : %d", pinfo->num, ret ); */

    if (ret < 0) {
        /*
         * SCTP is not a byte stream protocol, so the SCTP dissector
         * should not, and will not, do the sort of dissection help
         * that the SCTP dissector will.  If JXTA messages don't
         * start and end on SCTP packet boundaries, the JXTA dissector
         * will have to do its own byte stream reassembly.
         *
         * The SCTP dissector currently won't do reassembly.  If that
         * causes a problem for the JXTA dissector, the correct fix
         * is to implement reassembly in the SCTP dissector, so *all*
         * dissectors for protocols running atop SCTP can benefit from
         * it.
         */
        pinfo->desegment_offset = save_desegment_offset;
        pinfo->desegment_len = save_desegment_len;
        return FALSE;
    } else if (ret == 0) {
        /*
         * A clear rejection.
         */
        pinfo->desegment_offset = save_desegment_offset;
        pinfo->desegment_len = save_desegment_len;
        return FALSE;
    } else {
        /*
         * A clear acceptance.
         */
        return TRUE;
    }
}

/**
*   Dissect a tvbuff containing a JXTA UDP header, JXTA Message framing and a JXTA Message
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return Number of bytes from the tvbuff_t which were processed, 0 (zero) if
*           the packet was not recognized as a JXTA packet and negative if the
*           dissector needs more bytes in order to process a PDU.
**/
static int dissect_jxta_udp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
    guint offset = 0;
    guint available;
    gint needed = 0;

    conversation_t *conversation = find_or_create_conversation(pinfo);

    conversation_set_dissector(conversation, jxta_udp_handle);

    while (TRUE) {
        tvbuff_t *jxta_message_framing_tvb;
        gint processed = 0;
        guint64 content_length = -1;
        gchar *content_type = NULL;

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(JXTA_UDP_SIG)) {
            needed = (gint) (sizeof(JXTA_UDP_SIG) - available);
            break;
        }

        if (tvb_memeql(tvb, offset, JXTA_UDP_SIG, sizeof(JXTA_UDP_SIG)) != 0) {
            /* not ours */
            return 0;
        }

        offset += (int)sizeof(JXTA_UDP_SIG);

        jxta_message_framing_tvb = tvb_new_subset_remaining(tvb, offset);
        processed = dissect_jxta_message_framing(jxta_message_framing_tvb, pinfo, NULL, &content_length, &content_type);

        if ((0 == processed) || (NULL == content_type) || (content_length <= 0) || (content_length > UINT_MAX)) {
            /** Buffer did not begin with valid framing headers */
            return 0;
        }

        if (processed < 0) {
            needed = -processed;
            break;
        }

        offset += processed;

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < content_length) {
            needed = (gint) (content_length - available);
            break;
        }

        offset += (guint) content_length;

        break;
    }

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        /* ws_message( "UDP requesting %d more bytes", needed ); */
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "JXTA");

    guint tree_offset = 0;
    proto_item *jxta_tree_item =
        proto_tree_add_protocol_format(tree, proto_jxta, tvb, tree_offset, -1, "JXTA" );
    proto_tree *jxta_tree = proto_item_add_subtree(jxta_tree_item, ett_jxta);
    proto_item *jxta_udp_tree_item =
        proto_tree_add_none_format(jxta_tree, hf_jxta_udp, tvb, tree_offset, -1, "JXTA UDP Message");
    proto_tree *jxta_udp_tree = proto_item_add_subtree(jxta_udp_tree_item, ett_jxta_udp);
    tvbuff_t *jxta_message_framing_tvb;
    guint64 content_length = -1;
    gchar *content_type = NULL;
    tvbuff_t *jxta_message_tvb;

    proto_tree_add_item(jxta_udp_tree, hf_jxta_udpsig, tvb, tree_offset, (int)sizeof(JXTA_UDP_SIG), ENC_ASCII);
    tree_offset += (int)sizeof(JXTA_UDP_SIG);

    jxta_message_framing_tvb = tvb_new_subset_remaining(tvb, tree_offset);

    tree_offset += dissect_jxta_message_framing(jxta_message_framing_tvb, pinfo, jxta_tree, &content_length, &content_type);

    jxta_message_tvb = tvb_new_subset_length(tvb, tree_offset, (gint) content_length);

    tree_offset += dissect_media(content_type, jxta_message_tvb, pinfo, tree);

    proto_item_set_end(jxta_udp_tree_item, tvb, tree_offset);

    // offset is based on reported lengths. tree_offset is based on captured lengths via dissect_media.
    // Comment this out for now in favor of dissect_media's expert warning.
    // DISSECTOR_ASSERT(tree_offset == offset);

    return offset;
}

/**
*   Dissect a tvbuff containing JXTA stream PDUs. This commonly includes
*   connections over TCP sockets.
*
*   <p/>The stream (in both directions) will consist of a JXTA Welcome Message
*   followed by an indeterminate number of JXTA Message Framing Headers and
*   JXTA Messages.
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return Number of bytes from the tvbuff_t which were processed, 0 (zero) if
*           the packet was not recognized as a JXTA packet and negative if the
*           dissector needs more bytes in order to process a PDU.
**/
static int dissect_jxta_stream(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
    guint offset = 0;
    guint available = tvb_reported_length_remaining(tvb, offset);
    gint processed = 0;
    gint needed = 0;
    jxta_stream_conversation_data *tpt_conv_data = NULL;
    proto_item *jxta_tree_item = NULL;
    proto_tree *jxta_tree = NULL;

    /* ws_message("Dissecting%s : %d", (NULL != tree) ? " for display" : "", pinfo->num ); */

    if (available < sizeof(JXTA_WELCOME_MSG_SIG)) {
        needed = (gint) (sizeof(JXTA_WELCOME_MSG_SIG) - available);
        goto Common_Exit;
    }

    if (0 == tvb_memeql(tvb, 0, JXTA_WELCOME_MSG_SIG, sizeof(JXTA_WELCOME_MSG_SIG))) {
        /* The beginning of a JXTA stream connection */
        address *welcome_addr;
        gboolean initiator = FALSE;

        tpt_conv_data = get_tpt_conversation(pinfo);

        if (0 == tpt_conv_data->initiator_welcome_frame) {
            /* The initiator welcome frame */
            tpt_conv_data->tpt_ptype = pinfo->ptype;
            tpt_conv_data->initiator_welcome_frame = pinfo->num;
            copy_address_wmem(wmem_file_scope(), &tpt_conv_data->initiator_tpt_address, &pinfo->src);
            tpt_conv_data->initiator_tpt_port = pinfo->srcport;

            welcome_addr = &tpt_conv_data->initiator_address;
            initiator = TRUE;
        } else {
            if (tpt_conv_data->initiator_welcome_frame >= pinfo->num) {
                /* what we saw previously was the receiver welcome message */
                tpt_conv_data->receiver_welcome_frame = tpt_conv_data->initiator_welcome_frame;
                tpt_conv_data->receiver_tpt_address = tpt_conv_data->initiator_tpt_address;
                tpt_conv_data->receiver_tpt_port = tpt_conv_data->initiator_tpt_port;
                tpt_conv_data->receiver_address = tpt_conv_data->initiator_address;
                tpt_conv_data->initiator_welcome_frame = pinfo->num;
                copy_address_wmem(wmem_file_scope(), &tpt_conv_data->initiator_tpt_address, &pinfo->src);
                tpt_conv_data->initiator_tpt_port = pinfo->srcport;

                welcome_addr = &tpt_conv_data->initiator_address;
                initiator = TRUE;
            } else {
                /* The receiver welcome frame */
                tpt_conv_data->tpt_ptype = pinfo->ptype;
                tpt_conv_data->receiver_welcome_frame = pinfo->num;
                copy_address_wmem(wmem_file_scope(), &tpt_conv_data->receiver_tpt_address, &pinfo->src);
                tpt_conv_data->receiver_tpt_port = pinfo->srcport;

                welcome_addr = &tpt_conv_data->receiver_address;
                initiator = FALSE;
            }
        }

        processed = dissect_jxta_welcome(tvb, pinfo, NULL, welcome_addr, initiator);

        if( processed < 0 ) {
            needed = -processed;
            goto Common_Exit;
        }

        /* redo, this time creating the display tree. */
        jxta_tree_item = proto_tree_add_protocol_format(tree, proto_jxta, tvb, offset, -1, "JXTA" );
        jxta_tree = proto_item_add_subtree(jxta_tree_item, ett_jxta);

        processed = dissect_jxta_welcome(tvb, pinfo, jxta_tree, welcome_addr, initiator);
    } else {
        /* Somewhere in the middle of a JXTA stream connection */
        gint64 content_length = G_GINT64_CONSTANT(-1);
        gchar *content_type = NULL;
        gint headers_len = dissect_jxta_message_framing(tvb, pinfo, NULL, (guint64*) &content_length, &content_type);

        if ((0 == headers_len) || (NULL == content_type) || (content_length <= 0) || (content_length > UINT_MAX)) {
            /** Buffer did not begin with valid framing headers */
            return 0;
        }

        /* ws_message("%d Tpt %s:%d -> %s:%d tvb len=%d\n\t%s %d", pinfo->num,
                  address_to_str(pinfo->pool, &pinfo->src), pinfo->srcport,
                  address_to_str(pinfo->pool, &pinfo->dst), pinfo->destport,
                  tvb_reported_length_remaining(tvb, 0),
                  content_type ? content_type : "[unknown content type]", (gint) content_length); */

        if (headers_len < 0) {
            /* negative headers_len means we need more bytes */
            needed = -headers_len;
            goto Common_Exit;
        }

        available = tvb_reported_length_remaining(tvb, offset + headers_len);
        if (available >= content_length) {
            tvbuff_t *jxta_message_tvb = tvb_new_subset_length(tvb, offset + headers_len, (gint) content_length);
            conversation_t *peer_conversation = NULL;

            jxta_tree_item = proto_tree_add_protocol_format(tree, proto_jxta, tvb, offset, -1, "JXTA" );
            jxta_tree = proto_item_add_subtree(jxta_tree_item, ett_jxta);

            /* Redo header processing, this time populating the tree. */
            headers_len = dissect_jxta_message_framing(tvb, pinfo, jxta_tree, &content_length, &content_type);

            tpt_conv_data = get_tpt_conversation(pinfo);
            peer_conversation = get_peer_conversation(pinfo, tpt_conv_data, TRUE);

            /* Use our source and destination addresses if we have them */
            if (NULL != peer_conversation) {
                /* ws_message("%d Tpt %s:%d -> %s:%d", pinfo->num,
                          address_to_str(pinfo->pool, &tpt_conv_data->initiator_tpt_address), tpt_conv_data->initiator_tpt_port,
                          address_to_str(pinfo->pool, &tpt_conv_data->receiver_tpt_address), tpt_conv_data->receiver_tpt_port); */

                if (addresses_equal(&pinfo->src, &tpt_conv_data->initiator_tpt_address)
                    && tpt_conv_data->initiator_tpt_port == pinfo->srcport) {
                    /* ws_message("%d From initiator : %s -> %s ", pinfo->num,
                              address_to_str(pinfo->pool, &tpt_conv_data->initiator_address),
                              address_to_str(pinfo->pool, &tpt_conv_data->receiver_address)); */
                    copy_address_shallow(&pinfo->src, &tpt_conv_data->initiator_address);
                    pinfo->srcport = 0;
                    copy_address_shallow(&pinfo->dst, &tpt_conv_data->receiver_address);
                    pinfo->destport = 0;
                    pinfo->ptype = PT_NONE;
                } else if (addresses_equal(&pinfo->src, &tpt_conv_data->receiver_tpt_address) &&
                           tpt_conv_data->receiver_tpt_port == pinfo->srcport) {
                    /* ws_message("%d From receiver : %s -> %s ", pinfo->num,
                              address_to_str(pinfo->pool, &tpt_conv_data->receiver_address),
                              address_to_str(pinfo->pool, &tpt_conv_data->initiator_address)); */
                    copy_address_shallow(&pinfo->src, &tpt_conv_data->receiver_address);
                    pinfo->srcport = 0;
                    copy_address_shallow(&pinfo->dst, &tpt_conv_data->initiator_address);
                    pinfo->destport = 0;
                    pinfo->ptype = PT_NONE;
                } else {
                    /* ws_message("%d Nothing matches %s:%d -> %s:%d", pinfo->num,
                              address_to_str(pinfo->pool, &pinfo->src), pinfo->srcport,
                              address_to_str(pinfo->pool, &pinfo->dst), pinfo->destport); */
                }
            }

            processed = headers_len;

            processed += dissect_media(content_type, jxta_message_tvb, pinfo, tree);
        } else {
            /* we need more bytes before we can process message body. */
            needed = (gint) ((guint) content_length - available);
            goto Common_Exit;
        }
    }

    offset += processed;

Common_Exit:
    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        /* ws_message( "Stream requesting %d more bytes", needed ); */
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = needed;
        return -needed;
    }

    return offset;
}

/**
*   Find or possibly create a transport conversation object for the connection
*   which is associated with the packet info.
*
*   @param pinfo  The packet info from the underlying transport.
**/
static jxta_stream_conversation_data *get_tpt_conversation(packet_info * pinfo)
{
    conversation_t *tpt_conversation = find_or_create_conversation(pinfo);
    jxta_stream_conversation_data *tpt_conv_data;

    conversation_set_dissector(tpt_conversation, stream_jxta_handle);

    tpt_conv_data = (jxta_stream_conversation_data *) conversation_get_proto_data(tpt_conversation, proto_jxta);

    if (NULL == tpt_conv_data) {
        tpt_conv_data = wmem_new(wmem_file_scope(), jxta_stream_conversation_data);
        tpt_conv_data->tpt_ptype = pinfo->ptype;

        copy_address_wmem(wmem_file_scope(), &tpt_conv_data->initiator_tpt_address, &pinfo->src);
        tpt_conv_data->initiator_tpt_port = pinfo->srcport;
        tpt_conv_data->initiator_welcome_frame = 0;
        clear_address(&tpt_conv_data->initiator_address);

        copy_address_wmem(wmem_file_scope(), &tpt_conv_data->receiver_tpt_address, &pinfo->dst);
        tpt_conv_data->receiver_tpt_port = pinfo->destport;
        tpt_conv_data->receiver_welcome_frame = 0;
        clear_address(&tpt_conv_data->receiver_address);

        conversation_add_proto_data(tpt_conversation, proto_jxta, tpt_conv_data);
    }

    return tpt_conv_data;
}

/**
*   Find or possibly create a peer conversation object for the connection
*   which is associated with the packet info.
*
*   @param tpt_conv_data  The transport conversation from which we will locate the peer conversation.
*   @param create If TRUE then create a new conversation object if necessary.
**/
static conversation_t *get_peer_conversation(packet_info * pinfo, jxta_stream_conversation_data* tpt_conv_data, gboolean create)
{
    conversation_t * peer_conversation = NULL;

    if ((AT_NONE != tpt_conv_data->initiator_address.type) && (AT_NONE != tpt_conv_data->receiver_address.type)) {
        peer_conversation = find_conversation(pinfo->num, &tpt_conv_data->initiator_address, &tpt_conv_data->receiver_address,
                                               ENDPOINT_NONE, 0, 0, NO_PORT_B);

        if (create && (NULL == peer_conversation)) {
            peer_conversation = conversation_new(pinfo->num, &tpt_conv_data->initiator_address,
                                                  &tpt_conv_data->receiver_address, ENDPOINT_NONE, 0, 0, NO_PORT2);
            conversation_set_dissector(peer_conversation, stream_jxta_handle);
        }

    }

    return peer_conversation;
}

/**
*   Dissect a tvbuff containing a JXTA Welcome Message
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @param  found_addr The address found in the welcome message.
*   @param  initiator If TRUE then we believe this welcome message to be the initiator's.
*   @return Number of bytes from the tvbuff_t which were processed, 0 (zero) if
*           the packet was not recognized as a JXTA packet and negative if the
*           dissector needs more bytes in order to process a PDU.
**/
static int dissect_jxta_welcome(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, address * found_addr, gboolean initiator)
{
    guint offset = 0;
    gint afterwelcome;
    gint first_linelen;
    guint available = tvb_reported_length_remaining(tvb, offset);
    gchar **tokens = NULL;

    if (available < sizeof(JXTA_WELCOME_MSG_SIG)) {
        return (gint) (available - sizeof(JXTA_WELCOME_MSG_SIG));
    }

    if (0 != tvb_memeql(tvb, 0, JXTA_WELCOME_MSG_SIG, sizeof(JXTA_WELCOME_MSG_SIG))) {
        /* not ours! */
        return 0;
    }

    first_linelen = tvb_find_line_end(tvb, offset, -1, &afterwelcome, gDESEGMENT && pinfo->can_desegment);

    if (-1 == first_linelen) {
        if (available > 4096) {
            /* it's too far too be reasonable */
            return 0;
        } else {
            /* ask for more bytes */
            return -DESEGMENT_ONE_MORE_SEGMENT;
        }
    }

    /* Dissect the Welcome Message */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "JXTA");

    col_set_str(pinfo->cinfo, COL_INFO, "Welcome");

    {
        gchar *welcomeline = tvb_get_string_enc(pinfo->pool, tvb, offset, first_linelen, ENC_ASCII);
        gchar **current_token;
        guint token_offset = offset;
        proto_item *jxta_welcome_tree_item = NULL;
        proto_tree *jxta_welcome_tree = NULL;

        tokens = wmem_strsplit(pinfo->pool, welcomeline, " ", 255);
        current_token = tokens;

        if (tree) {
            jxta_welcome_tree_item =
                proto_tree_add_none_format(tree, hf_jxta_welcome, tvb, offset, afterwelcome,
                                           "JXTA Connection Welcome Message, %s", welcomeline);
            jxta_welcome_tree = proto_item_add_subtree(jxta_welcome_tree_item, ett_jxta_welcome);
        }

        if (jxta_welcome_tree) {
            proto_item *jxta_welcome_initiator_item =
                proto_tree_add_boolean(jxta_welcome_tree, hf_jxta_welcome_initiator, tvb, 0, 0, initiator);
            proto_item_set_generated(jxta_welcome_initiator_item);
        }

        if (NULL != *current_token) {
            proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_sig, tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII);

            token_offset += (guint) strlen(*current_token) + 1;
            current_token++;
        } else {
            /* invalid welcome message */
            afterwelcome = 0;
            goto Common_Exit;
        }

        if (NULL != *current_token) {
            if (jxta_welcome_tree) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_destAddr, tvb, token_offset, (gint) strlen(*current_token),
                                    ENC_ASCII);
            }

            token_offset += (guint) strlen(*current_token) + 1;
            current_token++;
        } else {
            /* invalid welcome message */
            afterwelcome = 0;
            goto Common_Exit;
        }

        if (NULL != *current_token) {
            if (jxta_welcome_tree) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_pubAddr, tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII);
            }

            token_offset += (guint) strlen(*current_token) + 1;
            current_token++;
        } else {
            /* invalid welcome message */
            afterwelcome = 0;
            goto Common_Exit;
        }

        if (NULL != *current_token) {
            if (jxta_welcome_tree) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_peerid, tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII);
            }

            col_append_str(pinfo->cinfo, COL_INFO, (initiator ? " -> " : " <- ") );
            col_append_str(pinfo->cinfo, COL_INFO, *current_token);

            if (NULL != found_addr) {
                set_address(found_addr, uri_address_type, (int)strlen(*current_token) + 1, wmem_strdup(wmem_file_scope(), *current_token));
            }

            token_offset += (guint) strlen(*current_token) + 1;
            current_token++;
        } else {
            /* invalid welcome message */
            afterwelcome = 0;
            goto Common_Exit;
        }

        if (NULL != *current_token) {
            int variable_tokens = 0;
            gchar **variable_token = current_token;

            while(NULL != *variable_token) {
                variable_tokens++;
                variable_token++;
            }

            if( variable_tokens < 1 ) {
              /* invalid welcome message */
              afterwelcome = 0;
              goto Common_Exit;
            }

            if( (2 == variable_tokens) && (0 == strcmp(JXTA_WELCOME_MSG_VERSION_1_1, current_token[variable_tokens -1])) ) {
                  if (jxta_welcome_tree) {
                      proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_noProp, tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII);
                  }

                  token_offset += (guint) strlen(*current_token) + 1;
                  current_token++;

                  if (jxta_welcome_tree) {
                      proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_version, tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII);
                  }
            } else if( (3 == variable_tokens) && (0 == strcmp(JXTA_WELCOME_MSG_VERSION_3_0, current_token[variable_tokens -1])) ) {
                  if (jxta_welcome_tree) {
                      proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_noProp, tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII);
                  }

                  token_offset += (guint) strlen(*current_token) + 1;
                  current_token++;

                  if (jxta_welcome_tree) {
                      proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_msgVers, tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII);
                  }

                  token_offset += (guint) strlen(*current_token) + 1;
                  current_token++;

                  if (jxta_welcome_tree) {
                      proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_version, tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII);
                  }
            } else {
                /* Unrecognized Welcome Version */
                int each_variable_token;

                for( each_variable_token = 0; each_variable_token < variable_tokens; each_variable_token++ ) {
                  if (jxta_welcome_tree) {
                      jxta_welcome_tree_item = proto_tree_add_item(jxta_welcome_tree,
                        (each_variable_token < (variable_tokens -1) ? hf_jxta_welcome_variable : hf_jxta_welcome_version),
                        tvb, token_offset, (gint) strlen(*current_token), ENC_ASCII|ENC_NA);

                        proto_item_append_text(jxta_welcome_tree_item, " (UNRECOGNIZED)");
                  }

                  token_offset += (guint) strlen(*current_token) + 1;
                  current_token++;
                }
            }
        } else {
            /* invalid welcome message */
            afterwelcome = 0;
            goto Common_Exit;
        }
    }

Common_Exit:
    col_set_writable(pinfo->cinfo, -1, FALSE);

    return afterwelcome;
}

/**
*   Dissect a tvbuff containing JXTA Message framing.
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @param  content_length Pointer to a buffer for storing the value of the
*           "content-length" header or NULL.
*   @param  content_type Pointer-to-a-pointer for a new buffer for storing the
*           value of the "content_type-length" header or NULL.
*   @return Number of bytes from the tvbuff_t which were processed, 0 (zero) if
*           the packet was not recognized as a JXTA packet and negative if the
*           dissector needs more bytes in order to process a PDU.
**/
static int dissect_jxta_message_framing(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint64 * content_length,
                                        gchar ** content_type)
{
    guint offset = 0;
    guint available;
    gint needed = 0;

    /*
     *   First go around. Make sure all of the bytes are there.
     */
    do {
        guint8 headername_len;
        guint8 headername_offset;
        guint16 headervalue_len;
        guint16 headervalue_offset;

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 1) {
            needed = 1;
            break;
        } else {
            headername_len = tvb_get_guint8(tvb, offset);
            offset++;
            headername_offset = offset;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < headername_len) {
                needed = (gint) (headername_len - available);
                break;
            }

            if (0 == headername_len) {
                break;
            }
            offset += headername_len;
        }

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 2) {
            needed = (gint) (2 - available);
            break;
        } else {
            headervalue_len = tvb_get_ntohs(tvb, offset);
            offset += 2;
            headervalue_offset = offset;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < headervalue_len) {
                needed = (gint) (headervalue_len - available);
                break;
            }

            offset += headervalue_len;
        }

        if (content_type && (sizeof("content-type") - 1) == headername_len) {
            if (0 == tvb_strncaseeql(tvb, headername_offset, "content-type", sizeof("content-type") - 1)) {
                *content_type = tvb_get_string_enc(pinfo->pool, tvb, headervalue_offset, headervalue_len, ENC_ASCII);
            }
        }


        if (content_length && (sizeof(guint64) == headervalue_len) && ((sizeof("content-length") - 1) == headername_len)) {
            if (0 == tvb_strncaseeql(tvb, headername_offset, "content-length", sizeof("content-length") - 1)) {
                *content_length = tvb_get_ntoh64(tvb, headervalue_offset);
            }
        }
    } while (TRUE);

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        /* ws_message( "Framing requesting %d more bytes", needed ); */
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    /*
     *   Second (optional pass) Now that we are sure that all the bytes are there we update the protocol tree.
     */
    if (tree) {
        guint tree_offset = 0;
        proto_item *framing_tree_item;
        proto_tree *framing_tree;

        framing_tree_item =
            proto_tree_add_none_format(tree, hf_jxta_framing, tvb, tree_offset, -1, "JXTA Message Framing Headers");
        framing_tree = proto_item_add_subtree(framing_tree_item, ett_jxta_framing);

        /* parse framing headers */
        do {
            guint8 headernamelen = tvb_get_guint8(tvb, tree_offset);
            proto_item *framing_header_tree_item =
                proto_tree_add_item(framing_tree, hf_jxta_framing_header, tvb, tree_offset, -1, ENC_NA);
            proto_tree *framing_header_tree = proto_item_add_subtree(framing_header_tree_item, ett_jxta_framing_header);

            /*
             *   Put header name into the protocol tree
             */
            proto_tree_add_item(framing_header_tree, hf_jxta_framing_header_name, tvb, tree_offset, (int)sizeof(gint8), ENC_ASCII|ENC_BIG_ENDIAN);

            /*
             *   Append header name into the header protocol item. It's a nice hint so you don't have to reveal all headers.
             */
            if (headernamelen > 0) {
                proto_item_append_text(framing_header_tree_item, " \"%s\"",
                                       tvb_format_text(pinfo->pool, tvb, tree_offset + 1, headernamelen));
            }

            tree_offset += 1 + headernamelen;

            if (headernamelen > 0) {
                guint16 headervaluelen = tvb_get_ntohs(tvb, tree_offset);

                if (tree) {
                    proto_tree_add_uint(framing_header_tree, hf_jxta_framing_header_value_length, tvb, tree_offset,
                                        2, headervaluelen);

                    /** TODO bondolo Add specific handling for known header types */

                    /*
                     * Put header value into protocol tree.
                     */
                    proto_tree_add_item(framing_header_tree, hf_jxta_framing_header_value, tvb, tree_offset + 2,
                                        headervaluelen, ENC_NA);
                }

                tree_offset += 2 + headervaluelen;
            }

            proto_item_set_end(framing_header_tree_item, tvb, tree_offset);

            if (0 == headernamelen) {
                break;
            }
        } while (TRUE);

        proto_item_set_end(framing_tree_item, tvb, tree_offset);

        DISSECTOR_ASSERT(offset == tree_offset);
    }

    /* return how many bytes we used up. */
    return offset;
}

/**
*   Dissect a tvbuff containing one or more JXTA Messages.
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return Number of bytes from the tvbuff_t which were processed, 0 (zero) if
*           the packet was not recognized as a JXTA packet and negative if the
*           dissector needs more bytes in order to process a PDU.
**/
static int dissect_jxta_message(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
    gint complete_messages = 0;
    guint offset = 0;
    guint tree_offset = 0;
    guint available;
    gint needed = 0;
    wmem_strbuf_t* src_addr;
    wmem_strbuf_t* dst_addr;

    while (TRUE) {
        guint8 message_version;
        guint message_start_offset = offset;

        /* First pass. Make sure all of the bytes we need are available */
        available = tvb_reported_length_remaining(tvb, offset);

        if((0 == available) && (0 != complete_messages)) {
            /* We have discovered all of the complete messages in the tvbuff. */
            break;
        }

        if (available < sizeof(JXTA_MSG_SIG)) {
            needed = (gint) (sizeof(JXTA_MSG_SIG) - available);
            break;
        }

        if (tvb_memeql(tvb, offset, JXTA_MSG_SIG, sizeof(JXTA_MSG_SIG)) != 0) {
            /* It is not one of ours */
            return 0;
        }

        offset += (int)sizeof(JXTA_MSG_SIG);

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 1) {
            needed = 1;
            break;
        } else {
            message_version = tvb_get_guint8(tvb, offset);

            offset++;

            if ((JXTA_MSG_VERSION_1 != message_version) && (JXTA_MSG_VERSION_2 != message_version)) {
                /* Sort of a lie, we say that we don't recognize it at all. */
                return 0;
            }
        }

        /* Read the flags (Version 2 and later) */
        if(message_version > 0) {
            available = tvb_reported_length_remaining(tvb, offset);
            if (available < 1) {
                needed = 1;
                break;
            } else {
                offset++;
            }
        }

        /* Read names table */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 2) {
            needed = (gint) (2 - available);
            break;
        } else {
            guint16 msg_names_count = tvb_get_ntohs(tvb, offset);
            guint each_name;

            offset += 2;

            for (each_name = 0; each_name < msg_names_count; each_name++) {
                guint16 name_len;

                available = tvb_reported_length_remaining(tvb, offset);
                if (available < sizeof(name_len)) {
                    needed = (gint) (sizeof(name_len) - available);
                    break;
                }

                name_len = tvb_get_ntohs(tvb, offset);

                available = tvb_reported_length_remaining(tvb, offset + (int)sizeof(name_len));
                if (available < name_len) {
                    needed = (gint) (name_len - available);
                    break;
                }

                offset += (int)sizeof(name_len) + name_len;
            }
        }

        /* parse element count */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 2) {
            needed = (gint) (2 - available);
            break;
        } else {
            guint16 elem_count = tvb_get_ntohs(tvb, offset);
            guint each_elem;

            offset += 2;

            /* parse elements */
            for (each_elem = 0; each_elem < elem_count; each_elem++) {
                tvbuff_t *jxta_message_element_tvb = tvb_new_subset_remaining(tvb, offset);
                int processed;

                if (JXTA_MSG_VERSION_1 == message_version) {
                    processed = dissect_jxta_message_element_1(jxta_message_element_tvb, pinfo, NULL, 0, NULL);
                } else { /* JXTA_MSG_VERSION_2 */
                    processed = dissect_jxta_message_element_2(jxta_message_element_tvb, pinfo, NULL, 0, NULL);
                }

                if (processed < 0) {
                    needed = -processed;
                    break;
                }

                if (0 == processed) {
                    /* XXX bondolo Not really clear what we should do! */
                    /* eapache: based on reading the code, I believe this can occur
                     * when the message_version is valid but the JXTA_MSGELEM_SIG
                     * (some sort of magic number?) is not. This almost
                     * certainly indicates a corrupt packet, so this should
                     * probably be expert info, not a ws_warning. Pending confirmation
                     * just comment it out since a ws_warning is definitely the
                     * wrong thing to do.
                     * ws_warning( "Failure processing message element #%d of %d of frame %d", each_elem, elem_count, pinfo->num );
                     */
                    return 0;
                }

                offset += processed;
            }
        }

        if ((uri_address_type == pinfo->src.type) && (uri_address_type == pinfo->dst.type)) {
            jxta_tap_header *tap_header = wmem_new(wmem_file_scope(), jxta_tap_header);

            copy_address_shallow(&tap_header->src_address, &pinfo->src);
            copy_address_shallow(&tap_header->dest_address, &pinfo->dst);
            tap_header->size = offset - message_start_offset ;

            tap_queue_packet(jxta_tap, pinfo, tap_header);
        }

        complete_messages++;

        /* ws_message( "%d Scanned message #%d: ", pinfo->num, complete_messages ); */
    }

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        /* ws_message("Frame %d: Message requesting %d more bytes", pinfo->num, needed); */
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    src_addr = wmem_strbuf_new_label(pinfo->pool);
    wmem_strbuf_append(src_addr, address_to_str(pinfo->pool, &pinfo->src));
    dst_addr = wmem_strbuf_new_label(pinfo->pool);
    wmem_strbuf_append(dst_addr, address_to_str(pinfo->pool, &pinfo->dst));

    /* append the port if appropriate */
    if (PT_NONE != pinfo->ptype) {
        wmem_strbuf_append_printf(src_addr, ":%d", pinfo->srcport);
        wmem_strbuf_append_printf(dst_addr, ":%d", pinfo->destport);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "JXTA");

    if( complete_messages > 1 ) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%d Messages, %s -> %s", complete_messages,
                     wmem_strbuf_get_str(src_addr), wmem_strbuf_get_str(dst_addr));
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Message, %s -> %s",
                     wmem_strbuf_get_str(src_addr), wmem_strbuf_get_str(dst_addr));
    }

    col_set_writable(pinfo->cinfo, -1, FALSE);

    while( tree && (complete_messages > 0) ) {
        proto_item *jxta_msg_tree_item = NULL;
        proto_tree *jxta_msg_tree = NULL;
        guint8 message_version;
        const gchar **names_table = NULL;
        guint16 msg_names_count;
        guint each_name;
        guint16 elem_count;
        guint each_elem;
        proto_item *tree_item;

        jxta_msg_tree_item = proto_tree_add_protocol_format(tree, proto_message_jxta, tvb, tree_offset, -1,
                                                            "JXTA Message, %s -> %s", wmem_strbuf_get_str(src_addr),
                                                            wmem_strbuf_get_str(dst_addr));

        jxta_msg_tree = proto_item_add_subtree(jxta_msg_tree_item, ett_jxta_msg);

        proto_tree_add_item(jxta_msg_tree, hf_jxta_message_sig, tvb, tree_offset, (int)sizeof(JXTA_MSG_SIG), ENC_ASCII);
        tree_offset += (int)sizeof(JXTA_MSG_SIG);

        tree_item = proto_tree_add_string(jxta_msg_tree, hf_jxta_message_src, tvb, 0, 0, wmem_strbuf_get_str(src_addr));
        proto_item_set_generated(tree_item);

        tree_item = proto_tree_add_string(jxta_msg_tree, hf_jxta_message_address, tvb, 0, 0, wmem_strbuf_get_str(src_addr));
        proto_item_set_hidden(tree_item);
        proto_item_set_generated(tree_item);

        if(uri_address_type == pinfo->src.type) {
            tree_item = proto_tree_add_string(jxta_msg_tree, hf_uri_src, tvb, 0, 0, wmem_strbuf_get_str(src_addr));
            proto_item_set_hidden(tree_item);
            proto_item_set_generated(tree_item);
            tree_item = proto_tree_add_string(jxta_msg_tree, hf_uri_addr, tvb, 0, 0, wmem_strbuf_get_str(src_addr));
            proto_item_set_hidden(tree_item);
            proto_item_set_generated(tree_item);
        }

        tree_item = proto_tree_add_string(jxta_msg_tree, hf_jxta_message_dst, tvb, 0, 0, wmem_strbuf_get_str(dst_addr));
        proto_item_set_generated(tree_item);

        tree_item = proto_tree_add_string(jxta_msg_tree, hf_jxta_message_address, tvb, 0, 0, wmem_strbuf_get_str(dst_addr));
        proto_item_set_hidden(tree_item);
        proto_item_set_generated(tree_item);

        if(uri_address_type == pinfo->dst.type) {
            tree_item = proto_tree_add_string(jxta_msg_tree, hf_uri_dst, tvb, 0, 0, wmem_strbuf_get_str(dst_addr));
            proto_item_set_hidden(tree_item);
            proto_item_set_generated(tree_item);
            tree_item = proto_tree_add_string(jxta_msg_tree, hf_uri_addr, tvb, 0, 0, wmem_strbuf_get_str(dst_addr));
            proto_item_set_hidden(tree_item);
            proto_item_set_generated(tree_item);
        }

        message_version = tvb_get_guint8(tvb, tree_offset);
        proto_tree_add_uint(jxta_msg_tree, hf_jxta_message_version, tvb, tree_offset, 1, message_version);
        tree_offset += 1;

        if( message_version > 0 ) {
            static int * const flags[] = {
                &hf_jxta_message_flag_utf16be,
                &hf_jxta_message_flag_ucs32be,
                NULL
            };

            proto_tree_add_bitmask(jxta_msg_tree, tvb, tree_offset, hf_jxta_message_flags, ett_jxta_msg_flags, flags, ENC_NA);
            tree_offset += 1;
        }

        msg_names_count = tvb_get_ntohs(tvb, tree_offset);
        proto_tree_add_uint(jxta_msg_tree, hf_jxta_message_names_count, tvb, tree_offset, 2, msg_names_count);
        tree_offset += 2;

        names_table = (const gchar **)wmem_alloc(pinfo->pool, (msg_names_count + 2) * sizeof(const gchar *));
        names_table[0] = "";
        names_table[1] = "jxta";

        /* parse names */
        for (each_name = 0; each_name < msg_names_count; each_name++) {
            guint16 name_len = tvb_get_ntohs(tvb, tree_offset);

            names_table[2 + each_name] = tvb_get_string_enc(pinfo->pool, tvb, tree_offset + 2, name_len, ENC_ASCII);
            proto_tree_add_item(jxta_msg_tree, hf_jxta_message_names_name, tvb, tree_offset, 2, ENC_ASCII|ENC_BIG_ENDIAN);
            tree_offset += 2 + name_len;
        }

        /* parse element count */
        elem_count = tvb_get_ntohs(tvb, tree_offset);
        proto_tree_add_item(jxta_msg_tree, hf_jxta_message_element_count, tvb, tree_offset, 2, ENC_BIG_ENDIAN);
        tree_offset += 2;

        /* FIXME bondolo Element count 0 (Process elements until FIN) should be supported. */

        /* parse elements */
        for (each_elem = 0; each_elem < elem_count; each_elem++) {
            tvbuff_t *jxta_message_element_tvb = tvb_new_subset_remaining(tvb, tree_offset);

            if(JXTA_MSG_VERSION_1 == message_version) {
                tree_offset +=
                    dissect_jxta_message_element_1(jxta_message_element_tvb, pinfo, jxta_msg_tree, msg_names_count + 2, names_table);
            } else if(JXTA_MSG_VERSION_2 == message_version) {
                tree_offset +=
                    dissect_jxta_message_element_2(jxta_message_element_tvb, pinfo, jxta_msg_tree, msg_names_count + 2, names_table);
            } else {
                /* Sort of a lie, we say that we don't recognize it at all. */
                return 0;
            }
       }

       proto_item_set_end(jxta_msg_tree_item, tvb, tree_offset);

       complete_messages--;
    }

    if( tree ) {
        /* ws_message( "%d tvb offset : %d  tree offset : %d", pinfo->num, offset, tree_offset ); */
        DISSECTOR_ASSERT(tree_offset == offset);
    }

    return offset;
}

/**
*   Dissect a tvbuff containing a JXTA Message Element (Version 1).
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return Number of bytes from the tvbuff_t which were processed, 0 (zero) if
*           the packet was not recognized as a JXTA packet and negative if the
*           dissector needs more bytes in order to process a PDU.
**/
static int dissect_jxta_message_element_1(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint ns_count,
                                        const gchar ** names_table)
{
    guint offset = 0;
    guint available;
    gint needed = 0;
    guint8 flags;

    /* First pass. Make sure all of the bytes we need are available */

    while (TRUE) {
        /* signature field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(JXTA_MSGELEM_SIG)) {
            needed = (gint) (sizeof(JXTA_MSGELEM_SIG) - available);
        }

        if (tvb_memeql(tvb, offset, JXTA_MSGELEM_SIG, sizeof(JXTA_MSGELEM_SIG)) != 0) {
            /* It is not one of ours */
            return 0;
        }

        offset += (int)sizeof(JXTA_MSGELEM_SIG);

        /* namespace id field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 1) {
            needed = 1;
            break;
        }

        offset++;

        /* flags field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 1) {
            needed = 1;
            break;
        } else {
            flags = tvb_get_guint8(tvb, offset);
            offset++;
        }

        /* name field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 2) {
            needed = (gint) (2 - available);
            break;
        } else {
            guint16 name_len = tvb_get_ntohs(tvb, offset);
            offset += 2;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < name_len) {
                needed = (gint) (name_len - available);
                break;
            }

            offset += name_len;
        }

        /* type field */
        if ((flags & JXTAMSG1_ELMFLAG_TYPE) != 0) {
            guint16 type_len;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < 2) {
                needed = (gint) (2 - available);
                break;
            }

            type_len = tvb_get_ntohs(tvb, offset);
            offset += 2;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < type_len) {
                needed = (gint) (type_len - available);
                break;
            }

            offset += type_len;
        }

        /* encoding field */
        if ((flags & JXTAMSG1_ELMFLAG_ENCODING) != 0) {
            guint16 encoding_len;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < 2) {
                needed = (gint) (2 - available);
                break;
            }

            encoding_len = tvb_get_ntohs(tvb, offset);
            offset += 2;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < encoding_len) {
                needed = (gint) (encoding_len - available);
                break;
            }

            offset += encoding_len;
        }

        /* content field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 2) {
            needed = (gint) (2 - available);
            break;
        } else {
            guint32 content_len = tvb_get_ntohl(tvb, offset);
            offset += 4;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < content_len) {
                needed = (gint) (content_len - available);
                break;
            }

            offset += content_len;
        }

        /* signature element field */
        if ((flags & JXTAMSG1_ELMFLAG_SIGNATURE) != 0) {
            tvbuff_t *jxta_signature_element_tvb;
            int processed;

            jxta_signature_element_tvb = tvb_new_subset_remaining(tvb, offset);

            processed = dissect_jxta_message_element_1(jxta_signature_element_tvb, pinfo, NULL, 0, NULL);

            if (processed == 0) {
                return offset;
            }

            if (processed < 0) {
                needed = -processed;
                break;
            }

            offset += processed;
        }

        break;
    }

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        /* ws_message( "Element1 requesting %d more bytes", needed ); */
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    /* Second pass : build the proto tree */
    guint tree_offset = 0;
    proto_item *jxta_elem_tree_item = proto_tree_add_item(tree, hf_jxta_element, tvb, tree_offset, -1, ENC_NA);
    proto_tree *jxta_elem_tree = proto_item_add_subtree(jxta_elem_tree_item, ett_jxta_elem);
    guint8 namespaceID;
    proto_item *namespace_ti;
    guint16 name_len;
    guint32 content_len;
    gchar *mediatype = NULL;
    tvbuff_t *element_content_tvb;
    static int * const element_flags[] = {
        &hf_jxta_element1_flag_hasType,
        &hf_jxta_element1_flag_hasEncoding,
        &hf_jxta_element1_flag_hasSignature,
        NULL
    };

    proto_tree_add_item(jxta_elem_tree, hf_jxta_element_sig, tvb, tree_offset, (int)sizeof(JXTA_MSGELEM_SIG), ENC_ASCII);
    tree_offset += (int)sizeof(JXTA_MSGELEM_SIG);

    namespaceID = tvb_get_guint8(tvb, tree_offset);
    namespace_ti =
        proto_tree_add_uint(jxta_elem_tree, hf_jxta_element1_namespaceid, tvb, tree_offset, 1, namespaceID);
    if (namespaceID < ns_count) {
        proto_item_append_text(namespace_ti, " (%s)", names_table[namespaceID]);
    } else {
        proto_item_append_text(namespace_ti, " * BAD *");
    }
    tree_offset += 1;

    flags = tvb_get_guint8(tvb, tree_offset);
    proto_tree_add_bitmask(jxta_elem_tree, tvb, tree_offset, hf_jxta_element_flags, ett_jxta_elem_1_flags, element_flags, ENC_NA);
    tree_offset += 1;

    name_len = tvb_get_ntohs(tvb, tree_offset);
    proto_item_append_text(jxta_elem_tree_item, " \"%s\"", tvb_format_text(pinfo->pool, tvb, tree_offset + 2, name_len));
    proto_tree_add_item(jxta_elem_tree, hf_jxta_element_name, tvb, tree_offset, 2, ENC_ASCII|ENC_BIG_ENDIAN);
    tree_offset += 2 + name_len;

    /* process type */
    if ((flags & JXTAMSG1_ELMFLAG_TYPE) != 0) {
        guint16 type_len = tvb_get_ntohs(tvb, tree_offset);
        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_type, tvb, tree_offset, 2, ENC_ASCII|ENC_BIG_ENDIAN);
        tree_offset += 2;

        mediatype = tvb_get_string_enc(pinfo->pool, tvb, tree_offset, type_len, ENC_ASCII);

        tree_offset += type_len;
    }

    /* process encoding */
    if ((flags & JXTAMSG1_ELMFLAG_ENCODING) != 0) {
        guint16 encoding_len = tvb_get_ntohs(tvb, tree_offset);
        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_encoding, tvb, tree_offset, 2, ENC_ASCII|ENC_BIG_ENDIAN);
        tree_offset += 2 + encoding_len;
    }

    /* content */
    content_len = tvb_get_ntohl(tvb, tree_offset);
    proto_tree_add_item(jxta_elem_tree, hf_jxta_element_content_len, tvb, tree_offset, 4, ENC_BIG_ENDIAN);
    tree_offset += 4;

    element_content_tvb = tvb_new_subset_length(tvb, tree_offset, content_len);

    tree_offset += dissect_media(mediatype, element_content_tvb, pinfo, jxta_elem_tree);

    /* process the signature element */
    if ((flags & JXTAMSG1_ELMFLAG_SIGNATURE) != 0) {
        tvbuff_t *jxta_message_element_tvb = tvb_new_subset_remaining(tvb, tree_offset);

        tree_offset += dissect_jxta_message_element_1(jxta_message_element_tvb, pinfo, jxta_elem_tree, ns_count, names_table);
    }

    proto_item_set_end(jxta_elem_tree_item, tvb, tree_offset);

    // offset is based on reported lengths. tree_offset is based on captured lengths via dissect_media.
    // Comment this out for now in favor of dissect_media's expert warning.
    // DISSECTOR_ASSERT(tree_offset == offset);

    return offset;
}

/**
*   Dissect a tvbuff containing a JXTA Message Element (Version 2).
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @param  names_count The number of elements in the names table.
*   @param  names_table The table of names.
*   @return Number of bytes from the tvbuff_t which were processed, 0 (zero) if
*           the packet was not recognized as a JXTA packet and negative if the
*           dissector needs more bytes in order to process a PDU.
**/
static int dissect_jxta_message_element_2(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint names_count,
                                        const gchar ** names_table)
{
    guint offset = 0;
    guint available;
    gint needed = 0;
    guint8 flags;

    /* First pass. Make sure all of the bytes we need are available */

    while (TRUE) {
        /* signature field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(JXTA_MSGELEM_SIG)) {
            needed = (gint) (sizeof(JXTA_MSGELEM_SIG) - available);
        }

        if (tvb_memeql(tvb, offset, JXTA_MSGELEM_SIG, sizeof(JXTA_MSGELEM_SIG)) != 0) {
            /* It is not one of ours */
            return 0;
        }

        offset += (int)sizeof(JXTA_MSGELEM_SIG);

        /* flags field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 1) {
            needed = 1;
            break;
        } else {
            flags = tvb_get_guint8(tvb, offset);
            offset++;
        }

        /* namespace id field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < 2) {
            needed = (gint) (2 - available);
            break;
        }

        offset += 2;

        /* name field */
        if ((flags & JXTAMSG2_ELMFLAG_NAME_LITERAL) == 0) {
            available = tvb_reported_length_remaining(tvb, offset);
            if (available < 2) {
                needed = (gint) (2 - available);
                break;
            }

            offset += 2;
        } else {
            /* literal name field */
            available = tvb_reported_length_remaining(tvb, offset);
            if (available < 2) {
                needed = (gint) (2 - available);
                break;
            } else {
                guint16 name_len = tvb_get_ntohs(tvb, offset);
                offset += 2;

                available = tvb_reported_length_remaining(tvb, offset);
                if (available < name_len) {
                    needed = (gint) (name_len - available);
                    break;
                }

                offset += name_len;
            }
        }

        /* type field */
        if ((flags & JXTAMSG2_ELMFLAG_TYPE) != 0) {
            available = tvb_reported_length_remaining(tvb, offset);
            if (available < 2) {
                needed = (gint) (2 - available);
                break;
            }

            offset += 2;
        }

        /* encoding field */
        if ((flags & JXTAMSG2_ELMFLAG_ENCODINGS) != 0) {
            available = tvb_reported_length_remaining(tvb, offset);
            if (available < 2) {
                needed = (gint) (2 - available);
                break;
            }

            offset += 2;
        }


        /* content field */
        if ((flags & JXTAMSG2_ELMFLAG_UINT64_LENS) != 0) {
            available = tvb_reported_length_remaining(tvb, offset);
            if (available < sizeof(guint64)) {
                needed = (gint) (sizeof(guint64) - available);
                break;
            } else {
                guint64 content_len = tvb_get_ntoh64(tvb, offset);
                offset += (int)sizeof(guint64);

                available = tvb_reported_length_remaining(tvb, offset);
                if (available < content_len) {
                    needed = (gint) (content_len - available);
                    break;
                }

                offset += (guint) content_len;
            }
        } else {
            available = tvb_reported_length_remaining(tvb, offset);
            if (available < 4) {
                needed = (gint) (4 - available);
                break;
            } else {
                guint64 content_len = tvb_get_ntohl(tvb, offset);
                offset += 4;

                available = tvb_reported_length_remaining(tvb, offset);
                if (available < content_len) {
                    needed = (gint) (content_len - available);
                    break;
                }

                offset += (guint) content_len;
            }
        }

        /* signature element field */
        if ((flags & JXTAMSG2_ELMFLAG_SIGNATURE) != 0) {
            tvbuff_t *jxta_signature_element_tvb;
            int processed;

            jxta_signature_element_tvb = tvb_new_subset_remaining(tvb, offset);

            processed = dissect_jxta_message_element_2(jxta_signature_element_tvb, pinfo, NULL, 0, NULL);

            if (processed == 0) {
                return offset;
            }

            if (processed < 0) {
                needed = -processed;
                break;
            }

            offset += processed;
        }

        break;
    }

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        /* ws_message( "Element2 requesting %d more bytes", needed ); */
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    /* Second (optional) pass : build the proto tree */
    guint tree_offset = 0;
    proto_item *jxta_elem_tree_item = proto_tree_add_item(tree, hf_jxta_element, tvb, tree_offset, -1, ENC_NA);
    proto_tree *jxta_elem_tree = proto_item_add_subtree(jxta_elem_tree_item, ett_jxta_elem);
    guint16 namespaceID;
    proto_item *namespace_ti;
    guint16 nameID;
    proto_item *name_ti;
    guint64 content_len;
    const gchar *mediatype = NULL;
    tvbuff_t *element_content_tvb;
    static int * const element_flags[] = {
        &hf_jxta_element2_flag_64bitlens,
        &hf_jxta_element2_flag_nameLiteral,
        &hf_jxta_element2_flag_hasType,
        &hf_jxta_element2_flag_hasSignature,
        &hf_jxta_element2_flag_hasEncoding,
        &hf_jxta_element2_flag_sigOfEncoded,
        NULL
    };

    proto_tree_add_item(jxta_elem_tree, hf_jxta_element_sig, tvb, tree_offset, (int)sizeof(JXTA_MSGELEM_SIG), ENC_ASCII);
    tree_offset += (int)sizeof(JXTA_MSGELEM_SIG);

    flags = tvb_get_guint8(tvb, tree_offset);
    proto_tree_add_bitmask(jxta_elem_tree, tvb, tree_offset, hf_jxta_element_flags, ett_jxta_elem_2_flags, element_flags, ENC_NA);
    tree_offset += 1;

    /* Namespace */
    namespaceID = tvb_get_ntohs(tvb, tree_offset);
    namespace_ti =
        proto_tree_add_uint(jxta_elem_tree, hf_jxta_element2_namespaceid, tvb, tree_offset, 2, namespaceID);
    if (namespaceID < names_count) {
        proto_item_append_text(namespace_ti, " (%s)", names_table[namespaceID]);
    } else {
        proto_item_append_text(namespace_ti, " * BAD *");
    }
    tree_offset += 2;

    /* Name */
    if ((flags & JXTAMSG2_ELMFLAG_NAME_LITERAL) == 0) {
        nameID = tvb_get_ntohs(tvb, tree_offset);
        name_ti =
            proto_tree_add_uint(jxta_elem_tree, hf_jxta_element2_nameid, tvb, tree_offset, 2, nameID);
        if (nameID < names_count) {
            proto_item_append_text(name_ti, " (%s)", names_table[nameID]);
        } else {
            proto_item_append_text(name_ti, " * BAD *");
        }
        tree_offset += 2;
    } else {
        /* literal name */
        guint16 name_len = tvb_get_ntohs(tvb, tree_offset);
        proto_item_append_text(jxta_elem_tree_item, " \"%s\"", tvb_format_text(pinfo->pool, tvb, tree_offset + 2, name_len));
        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_name, tvb, tree_offset, 2, ENC_ASCII|ENC_BIG_ENDIAN);
        tree_offset += 2 + name_len;
    }

    /* process type */
    if ((flags & JXTAMSG2_ELMFLAG_TYPE) != 0) {
        guint16 mimeID = tvb_get_ntohs(tvb, tree_offset);
        proto_item *mime_ti =
            proto_tree_add_uint(jxta_elem_tree, hf_jxta_element2_mimeid, tvb, tree_offset, 2, mimeID);

        if (mimeID < names_count) {
            proto_item_append_text(mime_ti, " (%s)", names_table[mimeID]);
            mediatype = wmem_strdup( pinfo->pool, names_table[mimeID] );
        } else {
            proto_item_append_text(mime_ti, " * BAD *");
        }

        tree_offset += 2;
    } else {
        mediatype = "application/octet-stream";
    }

    /* process encoding */
    if ((flags & JXTAMSG2_ELMFLAG_ENCODINGS) != 0) {
        guint16 encodingID = tvb_get_ntohs(tvb, tree_offset);
        proto_item *encoding_ti =
            proto_tree_add_uint(jxta_elem_tree, hf_jxta_element2_encodingid, tvb, tree_offset, 2, encodingID);

        if (encodingID < names_count) {
            proto_item_append_text(encoding_ti, " (%s)", names_table[encodingID]);
        } else {
            proto_item_append_text(encoding_ti, " * BAD *");
        }

        tree_offset += 2;
    }


    if ((flags & JXTAMSG2_ELMFLAG_UINT64_LENS) != 0) {
        content_len = tvb_get_ntoh64(tvb, tree_offset);
        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_content_len64, tvb, tree_offset, 8, ENC_BIG_ENDIAN);
        tree_offset += 8;
    } else {
        content_len = tvb_get_ntohl(tvb, tree_offset);
        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_content_len, tvb, tree_offset, 4, ENC_BIG_ENDIAN);
        tree_offset += 4;
    }

    /* content */
    element_content_tvb = tvb_new_subset_length(tvb, tree_offset, (gint)content_len);

    tree_offset += dissect_media(mediatype, element_content_tvb, pinfo, jxta_elem_tree);

    /* process the signature element */
    if ((flags & JXTAMSG2_ELMFLAG_SIGNATURE) != 0) {
        tvbuff_t *jxta_message_element_tvb = tvb_new_subset_remaining(tvb, tree_offset);

        tree_offset += dissect_jxta_message_element_1(jxta_message_element_tvb, pinfo, jxta_elem_tree, names_count, names_table);
    }

    proto_item_set_end(jxta_elem_tree_item, tvb, tree_offset);

    // offset is based on reported lengths. tree_offset is based on captured lengths via dissect_media.
    // Comment this out for now in favor of dissect_media's expert warning.
    // DISSECTOR_ASSERT(tree_offset == offset);

    return offset;
}

/**
*   Dissect a tvbuff containing arbitrary typed data.
*
*   <p/>We provide special handling for type media types :
*   <dl>
*       <dt>application/x-jxta-tls-block</dt>
*       <dd>We hand this data off to SSL to dissect.</dd>
*       <dt>application/gzip</dt>
*       <dd>We decompress the data and then dissect the contents as <tt>text/xml;charset="UTF-8"</tt></dd>
*   </dl>
*
*   @param  fullmediatype The full media type of the buffer to dissect including params
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return Number of bytes from the tvbuff_t which were processed, 0 (zero) if
*           the packet was not recognized and negative if the dissector needs
*           more bytes in order to process a PDU.
**/
static int dissect_media( const gchar* fullmediatype, tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {
    int dissected = 0;

    if (fullmediatype) {
        gchar *mediatype = wmem_strdup(pinfo->pool, fullmediatype);
        gchar *parms_at = strchr(mediatype, ';');
        const char *save_match_string = pinfo->match_string;
        http_message_info_t message_info = { HTTP_OTHERS, NULL, NULL, NULL };

        /* Based upon what is done in packet-media.c we set up type and params */
        if (NULL != parms_at) {
            message_info.media_str = wmem_strdup( pinfo->pool, parms_at + 1 );
            *parms_at = '\0';
        }

        /* Set the version that goes to packet-media.c before converting case */
        pinfo->match_string = wmem_strdup(pinfo->pool, mediatype);

        /* force to lower case */
        ascii_strdown_inplace(mediatype);

        if (0 == strcmp("application/x-jxta-tls-block", mediatype)) {
            /* If we recognize it as a TLS packet then we shuffle it off to tls dissector. */
            if (NULL != tls_handle) {
                dissected = call_dissector(tls_handle, tvb, pinfo, tree);
            }
        } else if (0 == strcmp("application/gzip", mediatype)) {
            tvbuff_t *uncomp_tvb = tvb_child_uncompress(tvb, tvb, 0, tvb_captured_length(tvb));

            if( NULL != uncomp_tvb ) {
                add_new_data_source(pinfo, uncomp_tvb, "Uncompressed Element Content");

                /* XXX bondolo 20060201 Force XML for uncompressed data. */
                dissected = dissect_media("text/xml;charset=\"UTF-8\"", uncomp_tvb, pinfo, tree);

                if( dissected > 0 ) {
                    /* report back the uncompressed length. */
                    dissected = tvb_captured_length(tvb);
                }
            }
        } else {
            dissected = dissector_try_string(media_type_dissector_table, mediatype, tvb, pinfo, tree, &message_info) ? tvb_captured_length(tvb) : 0;

            if( dissected != (int) tvb_captured_length(tvb) ) {
                /* ws_message( "%s : %d expected, %d dissected", mediatype, tvb_captured_length(tvb), dissected ); */
            }
        }

        if (0 == dissected) {
            dissected = call_dissector_with_data(media_handle, tvb, pinfo, tree, &message_info);
        }

        pinfo->match_string = save_match_string;
    }

    if(0 == dissected) {
        /* display it as raw data */
        dissected = call_data_dissector(tvb, pinfo, tree);
    }

    if (dissected < (int) tvb_reported_length(tvb)) {
        proto_item *item = proto_tree_add_expert(tree, pinfo, &ei_media_too_short, tvb, 0, dissected);
        proto_item_set_generated(item);
    }
    return dissected;
}

/**
*    Register jxta protocol and jxta message protocol, header fields, subtree types, preferences.
**/
void proto_register_jxta(void)
{
    module_t *jxta_module;
    expert_module_t *expert_jxta;

    /** our header fields */
    static hf_register_info hf[] = {
        {&hf_uri_addr,
         {"Address", "jxta.uri.addr", FT_STRING, BASE_NONE, NULL, 0x0,
          "URI Address (source or destination)", HFILL}
         },
        {&hf_uri_src,
         {"Source", "jxta.uri.src", FT_STRING, BASE_NONE, NULL, 0x0,
          "URI Source", HFILL}
         },
        {&hf_uri_dst,
         {"Destination", "jxta.uri.dst", FT_STRING, BASE_NONE, NULL, 0x0,
          "URI Destination", HFILL}
         },
        {&hf_jxta_udp,
         {"JXTA UDP", "jxta.udp", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
         },
        {&hf_jxta_udpsig,
         {"Signature", "jxta.udpsig", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA UDP Signature", HFILL}
         },
        {&hf_jxta_welcome,
         {"Welcome", "jxta.welcome", FT_NONE, BASE_NONE, NULL, 0x00,
          "JXTA Connection Welcome Message", HFILL}
         },
        {&hf_jxta_welcome_initiator,
         {"Initiator", "jxta.welcome.initiator", FT_BOOLEAN, BASE_NONE, NULL, 0x00,
          "JXTA Connection Welcome Message Initiator", HFILL}
         },
        {&hf_jxta_welcome_sig,
         {"Signature", "jxta.welcome.signature", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Connection Welcome Message Signature", HFILL}
         },
        {&hf_jxta_welcome_destAddr,
         {"Destination Address", "jxta.welcome.destAddr", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Connection Welcome Message Destination Address", HFILL}
         },
        {&hf_jxta_welcome_pubAddr,
         {"Public Address", "jxta.welcome.pubAddr", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Connection Welcome Message Public Address", HFILL}
         },
        {&hf_jxta_welcome_peerid,
         {"PeerID", "jxta.welcome.peerid", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Connection Welcome Message PeerID", HFILL}
         },
        {&hf_jxta_welcome_noProp,
         {"No Propagate Flag", "jxta.welcome.noPropFlag", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Connection Welcome Message No Propagate Flag", HFILL}
         },
        {&hf_jxta_welcome_msgVers,
         {"Preferred Message Version", "jxta.welcome.msgVersion", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Connection Welcome Message Preferred Message Version", HFILL}
         },
        {&hf_jxta_welcome_variable,
         {"Variable Parameter", "jxta.welcome.variable", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Connection Welcome Message Variable Parameter", HFILL}
         },
        {&hf_jxta_welcome_version,
         {"Version", "jxta.welcome.version", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Connection Welcome Message Version", HFILL}
         },
        {&hf_jxta_framing,
         {"Framing", "jxta.framing", FT_NONE, BASE_NONE, NULL, 0x0,
          "JXTA Message Framing", HFILL}
         },
        {&hf_jxta_framing_header,
         {"Header", "jxta.framing.header", FT_NONE, BASE_NONE, NULL, 0x0,
          "JXTA Message Framing Header", HFILL}
         },
        {&hf_jxta_framing_header_name,
         {"Name", "jxta.framing.header.name", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Framing Header Name", HFILL}
         },
        {&hf_jxta_framing_header_value_length,
         {"Value Length", "jxta.framing.header.valuelen", FT_UINT16, BASE_DEC, NULL, 0x0,
          "JXTA Message Framing Header Value Length", HFILL}
         },
        {&hf_jxta_framing_header_value,
         {"Value", "jxta.framing.header.value", FT_BYTES, BASE_NONE, NULL, 0x0,
          "JXTA Message Framing Header Value", HFILL}
         },
        {&hf_jxta_message_address,
         {"Address", "jxta.message.address", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Address (source or destination)", HFILL}
         },
        {&hf_jxta_message_src,
         {"Source", "jxta.message.source", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Source", HFILL}
         },
        {&hf_jxta_message_dst,
         {"Destination", "jxta.message.destination", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Destination", HFILL}
         },
        {&hf_jxta_message_sig,
         {"Signature", "jxta.message.signature", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Signature", HFILL}
         },
        {&hf_jxta_message_version,
         {"Version", "jxta.message.version", FT_UINT8, BASE_DEC, NULL, 0x0,
          "JXTA Message Version", HFILL}
         },
        {&hf_jxta_message_flags,
         {"Flags", "jxta.message.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
          "JXTA Message Flags", HFILL}
         },
        {&hf_jxta_message_flag_utf16be,
         {"UTF16BE", "jxta.message.flags.UTF-16BE", FT_BOOLEAN, 2, TFS(&tfs_set_notset), 0x01,
          "JXTA Message Element Flag -- UTF16-BE Strings", HFILL}
         },
        {&hf_jxta_message_flag_ucs32be,
         {"UCS32BE", "jxta.message.flags.UCS32BE", FT_BOOLEAN, 2, TFS(&tfs_set_notset), 0x02,
          "JXTA Message Flag -- UCS32-BE Strings", HFILL}
         },
        {&hf_jxta_message_names_count,
         {"Names Count", "jxta.message.names", FT_UINT16, BASE_DEC, NULL, 0x0,
          "JXTA Message Names Table", HFILL}
         },
        {&hf_jxta_message_names_name,
         {"Names Table Name", "jxta.message.names.name", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Names Table Name", HFILL}
         },
        {&hf_jxta_message_element_count,
         {"Element Count", "jxta.message.elements", FT_UINT16, BASE_DEC, NULL, 0x0,
          "JXTA Message Element Count", HFILL}
         },
        {&hf_jxta_element,
         {"JXTA Message Element", "jxta.message.element", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
         },
        {&hf_jxta_element_sig,
         {"Signature", "jxta.message.element.signature", FT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Element Signature", HFILL}
         },
        {&hf_jxta_element1_namespaceid,
         {"Namespace ID", "jxta.message.element.namespaceid", FT_UINT8, BASE_DEC, NULL, 0x0,
          "JXTA Message Element Namespace ID", HFILL}
         },
        {&hf_jxta_element2_namespaceid,
         {"Namespace ID", "jxta.message.element.namespaceid", FT_UINT16, BASE_DEC, NULL, 0x0,
          "JXTA Message Element Namespace ID", HFILL}
         },
        {&hf_jxta_element_flags,
         {"Flags", "jxta.message.element.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
          "JXTA Message Element Flags", HFILL}
         },
        {&hf_jxta_element1_flag_hasType,
         {"hasType", "jxta.message.element.flags.hasType", FT_BOOLEAN, 3, TFS(&tfs_set_notset), 0x01,
          "JXTA Message Element Flag -- hasType", HFILL}
         },
        {&hf_jxta_element1_flag_hasEncoding,
         {"hasEncoding", "jxta.message.element.flags.hasEncoding", FT_BOOLEAN, 3, TFS(&tfs_set_notset), 0x02,
          "JXTA Message Element Flag -- hasEncoding", HFILL}
         },
        {&hf_jxta_element1_flag_hasSignature,
         {"hasSignature", "jxta.message.element.flags.hasSignature", FT_BOOLEAN, 3, TFS(&tfs_set_notset), 0x04,
          "JXTA Message Element Flag -- hasSignature", HFILL}
         },
        {&hf_jxta_element2_flag_64bitlens,
         {"uint64Lens", "jxta.message.element.flags.uint64Lens", FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x01,
          "JXTA Message Element Flag -- uint64Lens", HFILL}
         },
        {&hf_jxta_element2_flag_nameLiteral,
         {"nameLiteral", "jxta.message.element.flags.nameLiteral", FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x02,
          "JXTA Message Element Flag -- nameLiteral", HFILL}
         },
        {&hf_jxta_element2_flag_hasType,
         {"hasEncoding", "jxta.message.element.flags.hasType", FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x04,
          "JXTA Message Element Flag -- hasType", HFILL}
         },
        {&hf_jxta_element2_flag_hasSignature,
         {"hasSignature", "jxta.message.element.flags.hasSignature", FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x08,
          "JXTA Message Element Flag -- hasSignature", HFILL}
         },
        {&hf_jxta_element2_flag_hasEncoding,
         {"hasSignature", "jxta.message.element.flags.hasEncoding", FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x10,
          "JXTA Message Element Flag -- hasEncoding", HFILL}
         },
        {&hf_jxta_element2_flag_sigOfEncoded,
         {"sigOfEncoded", "jxta.message.element.flags.sigOfEncoded", FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x20,
          "JXTA Message Element Flag -- sigOfEncoded", HFILL}
         },
        {&hf_jxta_element2_nameid,
         {"Name ID", "jxta.message.element.nameid", FT_UINT16, BASE_DEC, NULL, 0x0,
          "JXTA Message Element Name ID", HFILL}
         },
        {&hf_jxta_element_name,
         {"Element Name", "jxta.message.element.name", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Element Name", HFILL}
         },
        {&hf_jxta_element2_mimeid,
         {"MIME ID", "jxta.message.element.mimeid", FT_UINT16, BASE_DEC, NULL, 0x0,
          "JXTA Message Element MIME ID", HFILL}
         },
        {&hf_jxta_element2_encodingid,
         {"Encoding ID", "jxta.message.element.encodingid", FT_UINT16, BASE_DEC, NULL, 0x0,
          "JXTA Message Element Encoding ID", HFILL}
         },
        {&hf_jxta_element_type,
         {"Element Type", "jxta.message.element.type", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Element Name", HFILL}
         },
        {&hf_jxta_element_encoding,
         {"Element Type", "jxta.message.element.encoding", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "JXTA Message Element Encoding", HFILL}
         },
        {&hf_jxta_element_content_len,
         {"Element Content Length", "jxta.message.element.content.length", FT_UINT32, BASE_DEC, NULL, 0x0,
          "JXTA Message Element Content Length", HFILL}
         },
        {&hf_jxta_element_content_len64,
         {"Element Content Length", "jxta.message.element.content.length64", FT_UINT64, BASE_DEC, NULL, 0x0,
          "JXTA Message Element Content Length", HFILL}
         },
#if 0
        {&hf_jxta_element_content,
         {"Element Content", "jxta.message.element.content", FT_BYTES, BASE_NONE, NULL, 0x0,
          "JXTA Message Element Content", HFILL}
         },
#endif
    };

  static ei_register_info ei[] = {
     { &ei_media_too_short, { "jxta.media_too_short", PI_PROTOCOL, PI_WARN, "Media length less than expected", EXPFILL }},
  };

    /**
    *   JXTA Protocol subtree array
    **/
    static gint *ett[] = {
        &ett_jxta,
        &ett_jxta_welcome,
        &ett_jxta_udp,
        &ett_jxta_framing,
        &ett_jxta_framing_header,
        &ett_jxta_msg,
        &ett_jxta_msg_flags,
        &ett_jxta_elem,
        &ett_jxta_elem_1_flags,
        &ett_jxta_elem_2_flags
    };

    proto_jxta = proto_register_protocol("JXTA P2P", "JXTA", "jxta");

    jxta_tap = register_tap("jxta");

    proto_message_jxta = proto_register_protocol("JXTA Message", "JXTA Message", "jxta.message");

    jxta_udp_handle = register_dissector("jxta.udp", dissect_jxta_udp, proto_jxta);
    stream_jxta_handle = register_dissector("jxta.stream", dissect_jxta_stream, proto_jxta);

    /* Register header fields */
    proto_register_field_array(proto_jxta, hf, array_length(hf));

    /* Register JXTA Sub-tree */
    proto_register_subtree_array(ett, array_length(ett));

  expert_jxta = expert_register_protocol(proto_jxta);
  expert_register_field_array(expert_jxta, ei, array_length(ei));

    uri_address_type = address_type_dissector_register("AT_URI", "URI/URL/URN", uri_to_str, uri_str_len, NULL, uri_col_filter_str, NULL, NULL, NULL);

    /* Register preferences */
    /* register re-init routine */
    jxta_module = prefs_register_protocol(proto_jxta, proto_reg_handoff_jxta);

    prefs_register_bool_preference(jxta_module, "msg.mediatype", "Register binary JXTA Message as a media type",
                                   "Enable to have correctly typed MIME media dissected as JXTA Messages.", &gMSG_MEDIA);

    prefs_register_bool_preference(jxta_module, "desegment",
                                   "Reassemble JXTA messages spanning multiple UDP/TCP/SCTP segments",
                                   "Whether the JXTA dissector should reassemble messages spanning multiple UDP/TCP/SCTP segments."
                                   " To use this option you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings "
                                   " and enable \"Reassemble fragmented IP datagrams\" in the IP protocol settings.",
                                   &gDESEGMENT);

    prefs_register_obsolete_preference(jxta_module, "udp.heuristic");
    prefs_register_obsolete_preference(jxta_module, "tcp.heuristic");
    prefs_register_obsolete_preference(jxta_module, "sctp.heuristic");

    register_conversation_table(proto_jxta, TRUE, jxta_conversation_packet, jxta_hostlist_packet);
}


/**
*   Update registrations in response to preferences changes.
**/
void proto_reg_handoff_jxta(void)
{
    static gboolean init_done = FALSE;
    static dissector_handle_t message_jxta_handle;

    static gboolean msg_media_register_done = FALSE;

    if(!init_done) {
        message_jxta_handle = create_dissector_handle(dissect_jxta_message, proto_message_jxta);

        media_type_dissector_table = find_dissector_table("media_type");
        tls_handle = find_dissector_add_dependency("tls", proto_jxta);

        media_handle = find_dissector_add_dependency("media", proto_jxta);

        init_done = TRUE;
        }

    if( gMSG_MEDIA ) {
        if( !msg_media_register_done ) {
            /* ws_message( "Registering JXTA Message media type" ); */
            dissector_add_string("media_type", "application/x-jxta-msg", message_jxta_handle);
            msg_media_register_done = TRUE;
            }
    } else {
        if( msg_media_register_done ) {
            /* ws_message( "Deregistering JXTA Message media type" ); */
            dissector_delete_string("media_type", "application/x-jxta-msg", message_jxta_handle);
            msg_media_register_done = FALSE;
            }
    }

    /* ws_message( "Registering UDP Heuristic dissector" ); */
    heur_dissector_add("udp", dissect_jxta_UDP_heur, "JXTA over UDP", "jxta_udp", proto_jxta, HEURISTIC_ENABLE);

    /* ws_message( "Registering TCP Heuristic dissector" ); */
    heur_dissector_add("tcp", dissect_jxta_TCP_heur, "JXTA over TCP", "jxta_tcp", proto_jxta, HEURISTIC_ENABLE);

    /* ws_message( "Registering SCTP Heuristic dissector" ); */
    heur_dissector_add("sctp", dissect_jxta_SCTP_heur, "JXTA over SCTP", "jxta_sctp", proto_jxta, HEURISTIC_ENABLE);
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
