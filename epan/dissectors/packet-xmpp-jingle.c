/* xmpp-jingle.c
 * Wireshark's XMPP dissector.
 *
 * urn:xmpp:jingle:1
 * urn:xmpp:jingle:apps:rtp:1
 * urn:xmpp:jingle:apps:rtp:errors:1
 * urn:xmpp:jingle:apps:rtp:info:1
 * urn:xmpp:jingle:apps:rtp:rtp-hdrext:0
 * urn:xmpp:jingle:apps:rtp:izrtp:1
 *
 * urn:xmpp:jingle:transports:ice-udp:1
 * urn:xmpp:jingle:transports:raw-udp:1
 * urn:xmpp:jingle:transports:s5b:1
 * urn:xmpp:jingle:transports:ibb:1
 *
 * http://jabber.org/protocol/jinglenodes
 * http://jabber.org/protocol/jinglenodes#channel
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-xmpp.h"
#include "packet-xmpp-jingle.h"
#include "packet-xmpp-conference.h"
#include "packet-xmpp-gtalk.h"
#include "packet-xmpp-other.h"

static void xmpp_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_content_description_rtp(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_desc_rtp_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_desc_rtp_payload_param(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_desc_rtp_enc(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_desc_rtp_enc_zrtp_hash(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_desc_rtp_enc_crypto(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_desc_rtp_bandwidth(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_desc_rtp_hdrext(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_trans_ice(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_ice_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_trans_ice_remote_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_rtp_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jinglenodes_relay_stun_tracker(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_raw(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_raw_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_cont_trans_s5b(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_s5b_candidate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_s5b_activated(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_s5b_cand_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_s5b_cand_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_s5b_proxy_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_jingle_cont_trans_ibb(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

static void xmpp_jingle_file_transfer_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_file_transfer_offer(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_file_transfer_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_file_transfer_request(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_file_transfer_received(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_file_transfer_abort(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_jingle_file_transfer_checksum(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);

/*XEP-0166: Jingle urn:xmpp:jingle:1*/
void
xmpp_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *jingle_item;
    proto_tree *jingle_tree;

    static const char *rtp_info_msgs[] = {"active", "hold", "mute", "ringing", "unhold", "unmute"};

    static const char *action_enums[] = {"content-accept","content-add", "content-modify",
        "content-modify", "content-remove", "description-info", "security-info",
        "session-accept", "session-info", "session-initiate", "session-terminate",
        "transport-accept", "transport-info", "transport-reject", "transport-replace"
    };

    xmpp_array_t *action_array = xmpp_ep_init_array_t(pinfo->pool, action_enums,array_length(action_enums));
    xmpp_array_t *rtp_info_array = xmpp_ep_init_array_t(pinfo->pool, rtp_info_msgs, array_length(rtp_info_msgs));

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, true, false, NULL, NULL},
        {"action", &hf_xmpp_jingle_action, true, true, xmpp_val_enum_list, action_array},
        {"sid", &hf_xmpp_jingle_sid, true, false, NULL, NULL},
        {"initiator", &hf_xmpp_jingle_initiator, false, false, NULL, NULL},
        {"responder", &hf_xmpp_jingle_responder, false, false, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "content", xmpp_jingle_content, MANY},
        {NAME, "reason", xmpp_jingle_reason, MANY},
        {NAMES, rtp_info_array, xmpp_jingle_rtp_info, ONE},
        {NAME, "conference-info", xmpp_conferece_info_advert, ONE}
    };

     xmpp_attr_t *action = xmpp_get_attr(element,"action");
     col_append_fstr(pinfo->cinfo, COL_INFO, "JINGLE(%s) ", action?action->value:"");


    jingle_item = proto_tree_add_item(tree, hf_xmpp_jingle, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    jingle_tree = proto_item_add_subtree(jingle_item, ett_xmpp_jingle);

    xmpp_display_attrs(jingle_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(jingle_item, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *content_item;
    proto_tree *content_tree;

    static const char *creator_enums[] = {"initiator","responder"};
    xmpp_array_t *creator_enums_array = xmpp_ep_init_array_t(pinfo->pool, creator_enums,array_length(creator_enums));

    xmpp_attr_info attrs_info[] = {
        {"creator", &hf_xmpp_jingle_content_creator, true, false, xmpp_val_enum_list, creator_enums_array},
        {"name", &hf_xmpp_jingle_content_name, true, true, NULL, NULL},
        {"disposition", &hf_xmpp_jingle_content_disposition, false, false, NULL, NULL},
        {"senders", &hf_xmpp_jingle_content_senders, false, false, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME_AND_ATTR, xmpp_name_attr_struct(pinfo->pool, "description", "xmlns", "urn:xmpp:jingle:apps:rtp:1"), xmpp_jingle_content_description_rtp, MANY},
        {NAME_AND_ATTR, xmpp_name_attr_struct(pinfo->pool, "description", "xmlns", "urn:xmpp:jingle:apps:file-transfer:3"), xmpp_jingle_file_transfer_desc, MANY},
        {NAME_AND_ATTR,  xmpp_name_attr_struct(pinfo->pool, "transport", "xmlns", "urn:xmpp:jingle:transports:ice-udp:1"), xmpp_jingle_cont_trans_ice, MANY},
        {NAME_AND_ATTR,  xmpp_name_attr_struct(pinfo->pool, "transport", "xmlns", "urn:xmpp:jingle:transports:raw-udp:1"), xmpp_jingle_cont_trans_raw, MANY},
        {NAME_AND_ATTR,  xmpp_name_attr_struct(pinfo->pool, "transport", "xmlns", "urn:xmpp:jingle:transports:s5b:1"), xmpp_jingle_cont_trans_s5b, MANY},
        {NAME_AND_ATTR,  xmpp_name_attr_struct(pinfo->pool, "transport", "xmlns", "urn:xmpp:jingle:transports:ibb:1"), xmpp_jingle_cont_trans_ibb, MANY},
        {NAME_AND_ATTR,  xmpp_name_attr_struct(pinfo->pool, "transport", "xmlns", "http://www.google.com/transport/p2p"), xmpp_gtalk_transport_p2p, MANY},
        {NAME_AND_ATTR,  xmpp_name_attr_struct(pinfo->pool, "received", "xmlns", "urn:xmpp:jingle:apps:file-transfer:3"), xmpp_jingle_file_transfer_received, MANY},
        {NAME_AND_ATTR,  xmpp_name_attr_struct(pinfo->pool, "abort", "xmlns", "urn:xmpp:jingle:apps:file-transfer:3"), xmpp_jingle_file_transfer_abort, MANY},
        {NAME_AND_ATTR,  xmpp_name_attr_struct(pinfo->pool, "checksum", "xmlns", "urn:xmpp:jingle:apps:file-transfer:3"), xmpp_jingle_file_transfer_checksum, MANY},
        {NAME_AND_ATTR, xmpp_name_attr_struct(pinfo->pool, "inputevt", "xmlns","http://jitsi.org/protocol/inputevt"), xmpp_jitsi_inputevt, ONE},
    };

    content_item = proto_tree_add_item(tree, hf_xmpp_jingle_content, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    content_tree = proto_item_add_subtree(content_item, ett_xmpp_jingle_content);

    xmpp_display_attrs(content_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(content_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *reason_item;
    proto_tree *reason_tree;

    xmpp_attr_info attrs_info[] = {
        {"condition", &hf_xmpp_jingle_reason_condition, true, true, NULL, NULL},
        {"sid", NULL, false, true, NULL, NULL},
        {"rtp-error", NULL, false, true, NULL, NULL},
        {"text", &hf_xmpp_jingle_reason_text, false, false, NULL, NULL}
   };

    xmpp_element_t *condition; /*1?*/
    xmpp_element_t *text; /*0-1*/
    xmpp_element_t *rtp_error;

    static const char *reason_names[] = { "success", "busy", "failed-application", "cancel", "connectivity-error",
        "decline", "expired", "failed-transport", "general-error", "gone", "incompatible-parameters",
        "media-error", "security-error", "timeout", "unsupported-applications", "unsupported-transports"};

    static const char *rtp_error_names[] = {"crypto-required", "invalid-crypto"};

    reason_item = proto_tree_add_item(tree, hf_xmpp_jingle_reason, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    reason_tree = proto_item_add_subtree(reason_item, ett_xmpp_jingle_reason);


    /*Looks for reason description. "alternative-session" may contain "sid" element
     Elements are changed into attribute*/
    if((condition = xmpp_steal_element_by_names(element, reason_names, array_length(reason_names)))!=NULL)
    {
        xmpp_attr_t *fake_cond = xmpp_ep_init_attr_t(pinfo->pool, condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, (void *)"condition", fake_cond);

    } else if((condition = xmpp_steal_element_by_name(element, "alternative-session"))!=NULL)
    {
        xmpp_attr_t *fake_cond,*fake_alter_sid;
        xmpp_element_t *sid;

        fake_cond = xmpp_ep_init_attr_t(pinfo->pool, condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, (void *)"condition", fake_cond);


        if((sid = xmpp_steal_element_by_name(condition, "sid"))!=NULL)
        {
            fake_alter_sid = xmpp_ep_init_attr_t(pinfo->pool, sid->name, sid->offset, sid->length);
            g_hash_table_insert(element->attrs, (void *)"sid", fake_alter_sid);
        }
    }

    if((rtp_error = xmpp_steal_element_by_names(element, rtp_error_names, array_length(rtp_error_names)))!=NULL)
    {
        xmpp_attr_t *fake_rtp_error = xmpp_ep_init_attr_t(pinfo->pool, rtp_error->name, rtp_error->offset, rtp_error->length);
        g_hash_table_insert(element->attrs, (void *)"rtp-error", fake_rtp_error);
    }

    if((text = xmpp_steal_element_by_name(element, "text"))!=NULL)
    {
        xmpp_attr_t *fake_text = xmpp_ep_init_attr_t(pinfo->pool, text->data?text->data->value:"", text->offset, text->length);
        g_hash_table_insert(element->attrs, (void *)"text", fake_text);
    }

    xmpp_display_attrs(reason_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(reason_tree, tvb, pinfo, element);
}

/*XEP-0167: Jingle RTP Sessions urn:xmpp:jingle:apps:rtp:1*/
static void
xmpp_jingle_content_description_rtp(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL},
        {"media", &hf_xmpp_jingle_content_description_media, true, true, NULL, NULL},
        {"ssrc", &hf_xmpp_jingle_content_description_ssrc , false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "payload-type", xmpp_jingle_cont_desc_rtp_payload, MANY},
        {NAME, "bandwidth", xmpp_jingle_cont_desc_rtp_bandwidth, ONE},
        {NAME, "encryption", xmpp_jingle_cont_desc_rtp_enc, ONE},
        {NAME, "rtp-hdrext", xmpp_jingle_cont_desc_rtp_hdrext, MANY},
        {NAME, "zrtp-hash", xmpp_jingle_cont_desc_rtp_enc_zrtp_hash, MANY}/*IMHO it shouldn't appear in description*/

    };

    desc_item = proto_tree_add_item(tree, hf_xmpp_jingle_content_description, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_jingle_content_description);

    xmpp_display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(desc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_desc_rtp_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *payload_item;
    proto_tree *payload_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, false, NULL, NULL},
        {"id", &hf_xmpp_jingle_cont_desc_payload_id, true, true, NULL, NULL},
        {"channels", &hf_xmpp_jingle_cont_desc_payload_channels, false, false, NULL, NULL},
        {"clockrate", &hf_xmpp_jingle_cont_desc_payload_clockrate, false, false, NULL, NULL},
        {"maxptime", &hf_xmpp_jingle_cont_desc_payload_maxptime, false, false, NULL, NULL},
        {"name", &hf_xmpp_jingle_cont_desc_payload_name, false, true, NULL, NULL},
        {"ptime", &hf_xmpp_jingle_cont_desc_payload_ptime, false, false, NULL, NULL}
    };

    xmpp_elem_info elems_info [] =
    {
        {NAME, "parameter", xmpp_jingle_cont_desc_rtp_payload_param, MANY}
    };

    payload_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_payload, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    payload_tree = proto_item_add_subtree(payload_item, ett_xmpp_jingle_cont_desc_payload);

    xmpp_display_attrs(payload_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(payload_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_desc_rtp_payload_param(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element)
{
    proto_item *param_item;
    proto_tree *param_tree;

    proto_item *parent_item;
    xmpp_attr_t *name, *value;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, false, NULL, NULL},
        {"name", &hf_xmpp_jingle_cont_desc_payload_param_name, true, true, NULL, NULL},
        {"value", &hf_xmpp_jingle_cont_desc_payload_param_value, true, true, NULL, NULL}
    };

    name = xmpp_get_attr(element, "name");
    value = xmpp_get_attr(element, "value");

    if(name && value)
    {
        char *parent_item_label;

        parent_item = proto_tree_get_parent(tree);

        parent_item_label = proto_item_get_text(pinfo->pool, parent_item);

        if(parent_item_label)
        {
            parent_item_label[strlen(parent_item_label)-1]= '\0';
            proto_item_set_text(parent_item, "%s param(\"%s\")=%s]", parent_item_label ,name->value, value->value);
        }
    }

    param_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_payload_param, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    param_tree = proto_item_add_subtree(param_item, ett_xmpp_jingle_cont_desc_payload_param);

    xmpp_display_attrs(param_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(param_tree, tvb, pinfo, element);

}

static void
xmpp_jingle_cont_desc_rtp_enc(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element)
{
    proto_item *enc_item;
    proto_tree *enc_tree;

    xmpp_elem_info elems_info [] = {
        {NAME, "zrtp-hash", xmpp_jingle_cont_desc_rtp_enc_zrtp_hash, MANY},
        {NAME, "crypto", xmpp_jingle_cont_desc_rtp_enc_crypto, MANY}
    };

    enc_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_enc, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    enc_tree = proto_item_add_subtree(enc_item, ett_xmpp_jingle_cont_desc_enc);

    xmpp_display_attrs(enc_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(enc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

/*urn:xmpp:jingle:apps:rtp:zrtp:1*/
static void
xmpp_jingle_cont_desc_rtp_enc_zrtp_hash(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element)
{
    proto_item *zrtp_hash_item;
    proto_tree *zrtp_hash_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, false, NULL, NULL},
        {"version", NULL, true, true,NULL,NULL},
        {"hash", NULL, true, false, NULL, NULL}
    };

    zrtp_hash_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_enc_zrtp_hash, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    zrtp_hash_tree = proto_item_add_subtree(zrtp_hash_item, ett_xmpp_jingle_cont_desc_enc_zrtp_hash);

    if(element->data)
    {
        xmpp_attr_t *fake_hash = xmpp_ep_init_attr_t(pinfo->pool, element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, (void *)"hash", fake_hash);
    }

    xmpp_display_attrs(zrtp_hash_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(zrtp_hash_tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_desc_rtp_enc_crypto(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element)
{
    proto_item *crypto_item;
    proto_tree *crypto_tree;

    xmpp_attr_info attrs_info[] = {
        {"crypto-suite", NULL, true, true, NULL, NULL},
        {"key-params", NULL, true, false,NULL,NULL},
        {"session-params", NULL, false, true, NULL, NULL},
        {"tag", NULL, true, false, NULL, NULL}
    };

    crypto_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_enc_crypto, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    crypto_tree = proto_item_add_subtree(crypto_item, ett_xmpp_jingle_cont_desc_enc_crypto);


    xmpp_display_attrs(crypto_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(crypto_tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_desc_rtp_bandwidth(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element)
{
    proto_item *bandwidth_item;
    proto_tree *bandwidth_tree;

    xmpp_attr_info attrs_info[] = {
        {"type", NULL, true, true, NULL, NULL},
        {"value", NULL, true, true, NULL, NULL}
    };

    bandwidth_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_bandwidth, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    bandwidth_tree = proto_item_add_subtree(bandwidth_item, ett_xmpp_jingle_cont_desc_bandwidth);

    if(element->data)
    {
        xmpp_attr_t *fake_value = xmpp_ep_init_attr_t(pinfo->pool, element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, (void *)"value", fake_value);
    }

    xmpp_display_attrs(bandwidth_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(bandwidth_tree, tvb, pinfo, element);
}

/*urn:xmpp:jingle:apps:rtp:rtp-hdrext:0*/
static void
xmpp_jingle_cont_desc_rtp_hdrext(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, xmpp_element_t* element)
{
    proto_item *rtp_hdr_item;
    proto_tree *rtp_hdr_tree;

    static const char *senders[] = {"both", "initiator", "responder"};
    xmpp_array_t *senders_enums = xmpp_ep_init_array_t(pinfo->pool, senders, 3);

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, false, NULL, NULL},
        {"id", NULL, true, false, NULL, NULL},
        {"uri", NULL, true, true, NULL, NULL},
        {"senders", NULL, false, true, xmpp_val_enum_list, senders_enums},
        {"parameter", NULL, false, true, NULL, NULL}
    };

    xmpp_element_t *parameter;

    rtp_hdr_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_rtp_hdr, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    rtp_hdr_tree = proto_item_add_subtree(rtp_hdr_item, ett_xmpp_jingle_cont_desc_rtp_hdr);

    if((parameter = xmpp_steal_element_by_name(element, "parameter"))!=NULL)
    {
        xmpp_attr_t *name = xmpp_get_attr(element, "name");
        xmpp_attr_t *fake_attr = xmpp_ep_init_attr_t(pinfo->pool, name?name->value:"", parameter->offset, parameter->length);
        g_hash_table_insert(element->attrs, (void *)"parameter", fake_attr);
    }

    xmpp_display_attrs(rtp_hdr_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(rtp_hdr_tree, tvb, pinfo, element);
}

/*urn:xmpp:jingle:apps:rtp:info:1*/
static void
xmpp_jingle_rtp_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *rtp_info_item;
    proto_tree *rtp_info_tree;

    static const char *creator[] = {"initiator","responder"};
    xmpp_array_t *creator_enums = xmpp_ep_init_array_t(pinfo->pool, creator, array_length(creator));

    xmpp_attr_info mute_attrs_info[] = {
        {"creator", NULL, true, true, xmpp_val_enum_list, creator_enums},
        {"name", NULL, true, true, NULL, NULL}
    };

    rtp_info_item = proto_tree_add_string(tree, hf_xmpp_jingle_rtp_info, tvb, element->offset, element->length, element->name);
    rtp_info_tree = proto_item_add_subtree(rtp_info_item, ett_xmpp_jingle_rtp_info);

    if(strcmp("mute", element->name) == 0 || strcmp("unmute", element->name) == 0)
        xmpp_display_attrs(rtp_info_tree, element, pinfo, tvb, mute_attrs_info, array_length(mute_attrs_info));

    xmpp_unknown(rtp_info_tree, tvb, pinfo, element);
}

/*XEP-0176: Jingle ICE-UDP Transport Method urn:xmpp:jingle:transports:ice-udp:1*/
static void
xmpp_jingle_cont_trans_ice(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, true, NULL, NULL},
        {"pwd", &hf_xmpp_jingle_cont_trans_pwd, false, false, NULL, NULL},
        {"ufrag", &hf_xmpp_jingle_cont_trans_ufrag, false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "candidate", xmpp_jingle_cont_trans_ice_candidate, MANY},
        {NAME, "remote-candidate", xmpp_jingle_cont_trans_ice_remote_candidate, ONE}
    };

    trans_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_jingle_cont_trans);

    xmpp_display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(trans_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_trans_ice_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    static const char *type_enums[] = {"host", "prflx", "relay", "srflx"};
    xmpp_array_t *type_enums_array = xmpp_ep_init_array_t(pinfo->pool, type_enums,array_length(type_enums));

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, false, NULL, NULL},
        {"component", NULL, true, false, NULL, NULL},
        {"foundation", NULL, true, false, NULL, NULL},
        {"generation", NULL, true, false, NULL, NULL},
        {"id", NULL, false, false, NULL, NULL}, /*in schemas id is marked as required, but in jitsi logs it doesn't appear*/
        {"ip", NULL, true, true, NULL, NULL},
        {"network", NULL, true, false, NULL, NULL},
        {"port", NULL, true, false, NULL, NULL},
        {"priority", NULL, true, true, NULL, NULL},
        {"protocol", NULL, true, true, NULL, NULL},
        {"rel-addr", NULL, false, false, NULL, NULL},
        {"rel-port", NULL, false, false, NULL, NULL},
        {"type", NULL, true, true, xmpp_val_enum_list, type_enums_array}
    };

    cand_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_cand, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_jingle_cont_trans_cand);

    xmpp_display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(cand_tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_trans_ice_remote_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *remote_cand_item;
    proto_tree *remote_cand_tree;

    xmpp_attr_info attrs_info[] = {
        {"component", NULL, true, false, NULL, NULL},
        {"ip", NULL, true, false, NULL, NULL},
        {"port", NULL, true, false, NULL, NULL}
    };

    remote_cand_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_rem_cand, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    remote_cand_tree = proto_item_add_subtree(remote_cand_item, ett_xmpp_jingle_cont_trans_rem_cand);

    xmpp_display_attrs(remote_cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(remote_cand_tree, tvb, pinfo, element);
}

/*XEP-0177: Jingle Raw UDP Transport Method urn:xmpp:jingle:transports:raw-udp:1*/
static void
xmpp_jingle_cont_trans_raw(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "candidate", xmpp_jingle_cont_trans_raw_candidate, MANY}
    };

    trans_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_jingle_cont_trans);

    xmpp_display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(trans_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_trans_raw_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    static const char *type_enums[] = {"host", "prflx", "relay", "srflx"};
    xmpp_array_t *type_enums_array = xmpp_ep_init_array_t(pinfo->pool, type_enums,array_length(type_enums));

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, false, NULL, NULL},
        {"component", NULL, true, false, NULL, NULL},
        {"generation", NULL, true, false, NULL, NULL},
        {"id", NULL, true, false, NULL, NULL},
        {"ip", NULL, true, true, NULL, NULL},
        {"port", NULL, true, true, NULL, NULL},
        {"type", NULL, true, true, xmpp_val_enum_list, type_enums_array}
    };

    cand_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_cand, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_jingle_cont_trans_cand);

    xmpp_display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(cand_tree, element, pinfo, tvb, NULL, 0);
}

/*XEP-0260: Jingle SOCKS5 Bytestreams Transport Method urn:xmpp:jingle:transports:s5b:1*/
static void
xmpp_jingle_cont_trans_s5b(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, true, NULL, NULL},
        {"mode", NULL, false, true, NULL, NULL},
        {"sid", NULL, false, true, NULL, NULL},
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "candidate", xmpp_jingle_cont_trans_s5b_candidate, MANY},
        {NAME, "activated", xmpp_jingle_cont_trans_s5b_activated, ONE},
        {NAME, "candidate-used", xmpp_jingle_cont_trans_s5b_cand_used, ONE},
        {NAME, "candidate-error", xmpp_jingle_cont_trans_s5b_cand_error, ONE},
        {NAME, "proxy-error", xmpp_jingle_cont_trans_s5b_proxy_error, ONE},
    };

    trans_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_jingle_cont_trans);

    xmpp_display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(trans_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_trans_s5b_candidate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    static const char * type_enums[] = {"assisted", "direct", "proxy", "tunnel"};
    xmpp_array_t *type_enums_array = xmpp_ep_init_array_t(pinfo->pool, type_enums, array_length(type_enums));

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, false, NULL, NULL},
        {"cid", NULL, true, true, NULL, NULL},
        {"jid", NULL, true, true, NULL, NULL},
        {"port", NULL, false, true, NULL, NULL},
        {"priority", NULL, true, true, NULL, NULL},
        {"type", NULL, true, true, xmpp_val_enum_list, type_enums_array}
    };

    cand_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_cand, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_jingle_cont_trans_cand);

    xmpp_display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(cand_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_jingle_cont_trans_s5b_activated(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *activated_item;
    xmpp_attr_t *cid = xmpp_get_attr(element, "cid");

    activated_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_activated, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    proto_item_append_text(activated_item, " [cid=\"%s\"]",cid?cid->value:"");

    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_trans_s5b_cand_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *cand_used_item;
    xmpp_attr_t *cid = xmpp_get_attr(element, "cid");

    cand_used_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_candidate_used, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    proto_item_append_text(cand_used_item, " [cid=\"%s\"]",cid?cid->value:"");

    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_trans_s5b_cand_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_candidate_error, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_trans_s5b_proxy_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_proxy_error, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    xmpp_unknown(tree, tvb, pinfo, element);
}

/*XEP-0261: Jingle In-Band Bytestreams Transport Method urn:xmpp:jingle:transports:ibb:1*/
static void
xmpp_jingle_cont_trans_ibb(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element) {
    proto_item *trans_item;
    proto_tree *trans_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, true, NULL, NULL},
        {"block-size", NULL, true, true, NULL, NULL},
        {"sid", NULL, true, true, NULL, NULL},
        {"stanza", NULL, false, true, NULL, NULL}
    };

    trans_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_jingle_cont_trans);

    xmpp_display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(trans_tree, element, pinfo, tvb, NULL, 0);
}

/*XEP-0234: Jingle File Transfer urn:xmpp:jingle:apps:file-transfer:3*/
static void
xmpp_jingle_file_transfer_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "offer", xmpp_jingle_file_transfer_offer, ONE},
        {NAME, "request", xmpp_jingle_file_transfer_request, ONE}
    };

    desc_item = proto_tree_add_item(tree, hf_xmpp_jingle_content_description, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_jingle_content_description);

    xmpp_display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(desc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_offer(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *offer_item;
    proto_tree *offer_tree;

    xmpp_elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    offer_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_offer, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    offer_tree = proto_item_add_subtree(offer_item, ett_xmpp_jingle_file_transfer_offer);

    xmpp_display_attrs(offer_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(offer_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_request(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *request_item;
    proto_tree *request_tree;

    xmpp_elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    request_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_request, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    request_tree = proto_item_add_subtree(request_item, ett_xmpp_jingle_file_transfer_request);

    xmpp_display_attrs(request_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(request_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_received(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *received_item;
    proto_tree *received_tree;

    xmpp_elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    received_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_received, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    received_tree = proto_item_add_subtree(received_item, ett_xmpp_jingle_file_transfer_received);

    xmpp_display_attrs(received_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(received_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_abort(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *abort_item;
    proto_tree *abort_tree;

    xmpp_elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    abort_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_abort, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    abort_tree = proto_item_add_subtree(abort_item, ett_xmpp_jingle_file_transfer_abort);

    xmpp_display_attrs(abort_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(abort_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_checksum(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *checksum_item;
    proto_tree *checksum_tree;

    xmpp_elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    checksum_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_checksum, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    checksum_tree = proto_item_add_subtree(checksum_item, ett_xmpp_jingle_file_transfer_checksum);

    xmpp_display_attrs(checksum_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(checksum_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *file_tree;

    xmpp_attr_info attrs_info[] = {
        {"name", NULL, false, true, NULL, NULL},
        {"size", NULL, false, true, NULL, NULL},
        {"date", NULL, false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "hashes", xmpp_hashes, ONE}
    };

    file_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_jingle_file_transfer_file, NULL, "FILE");

    xmpp_change_elem_to_attrib(pinfo->pool, "name", "name", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "size", "size", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "date", "date", element, xmpp_transform_func_cdata);

    xmpp_display_attrs(file_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(file_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

/*XEP-0278: Jingle Relay Nodes http://jabber.org/protocol/jinglenodes*/
void
xmpp_jinglenodes_services(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *services_item;
    proto_tree *services_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "relay", xmpp_jinglenodes_relay_stun_tracker, ONE},
        {NAME, "tracker", xmpp_jinglenodes_relay_stun_tracker, ONE},
        {NAME, "stun", xmpp_jinglenodes_relay_stun_tracker, ONE},
    };

    col_append_str(pinfo->cinfo, COL_INFO, "SERVICES ");

    services_item = proto_tree_add_item(tree, hf_xmpp_services, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    services_tree = proto_item_add_subtree(services_item, ett_xmpp_services);

    xmpp_display_attrs(services_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(services_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jinglenodes_relay_stun_tracker(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree *relay_tree;

    xmpp_attr_info attrs_info[] = {
        {"address", NULL, true, true, NULL, NULL},
        {"port", NULL, false, true, NULL, NULL},
        {"policy", NULL, true, true, NULL, NULL},
        {"protocol", NULL, true, true, NULL, NULL},
    };

    relay_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_services_relay, NULL, element->name);

    xmpp_display_attrs(relay_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(relay_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_jinglenodes_channel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *channel_item;
    proto_tree *channel_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, true, false, NULL, NULL},
        {"id", NULL, false, false, NULL, NULL},
        {"host", NULL, false, true, NULL, NULL},
        {"localport", NULL, false, true, NULL, NULL},
        {"remoteport", NULL, false, true, NULL, NULL},
        {"protocol", NULL, true, true, NULL, NULL},
        {"maxkbps", NULL, false, false, NULL, NULL},
        {"expire", NULL, false, false, NULL, NULL},
    };

    channel_item = proto_tree_add_item(tree, hf_xmpp_channel, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    channel_tree = proto_item_add_subtree(channel_item, ett_xmpp_channel);

    xmpp_display_attrs(channel_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(channel_tree, element, pinfo, tvb, NULL, 0);
}
/*
* Editor modelines - https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
