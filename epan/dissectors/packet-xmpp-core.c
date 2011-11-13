/* xmpp-core.c
 * Wireshark's XMPP dissector.
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#include <epan/dissectors/packet-xml.h>

#include <packet-xmpp-utils.h>
#include <packet-xmpp.h>
#include <packet-xmpp-core.h>
#include <packet-xmpp-jingle.h>
#include <packet-xmpp-other.h>
#include <packet-xmpp-gtalk.h>
#include <packet-xmpp-conference.h>

#include <epan/strutil.h>

#include "epan/tvbparse.h"


void xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet);
void xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, xmpp_element_t *packet, gint hf, gint ett, const char *col_info);

void xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet);

static void xmpp_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_error_text(proto_tree *tree, tvbuff_t *tvb, xmpp_element_t *element);

void xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet);
static void xmpp_presence_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

void xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet);
static void xmpp_message_thread(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_message_body(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_message_subject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

void xmpp_failure(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet);
static void xmpp_failure_text(proto_tree *tree, tvbuff_t *tvb, xmpp_element_t *element);

static void xmpp_features_mechanisms(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet);

void
xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *xmpp_iq_item;
    proto_tree *xmpp_iq_tree;

    xmpp_attr_t *attr_id, *attr_type;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_id, TRUE, TRUE, NULL, NULL},
        {"type", hf_xmpp_type, TRUE, TRUE, NULL, NULL},
        {"from", hf_xmpp_from, FALSE, TRUE, NULL, NULL},
        {"to", hf_xmpp_to, FALSE, TRUE, NULL, NULL},
        {"xml:lang", -1, FALSE, FALSE, NULL, NULL}
    };

    conversation_t *conversation = NULL;
    xmpp_conv_info_t *xmpp_info = NULL;
    xmpp_transaction_t *reqresp_trans = NULL;

    xmpp_elem_info elems_info [] = {
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns","http://jabber.org/protocol/disco#items"), xmpp_disco_items_query, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns", "jabber:iq:roster"), xmpp_roster_query, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns", "http://jabber.org/protocol/disco#info"), xmpp_disco_info_query, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns", "http://jabber.org/protocol/bytestreams"), xmpp_bytestreams_query, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns", "http://jabber.org/protocol/muc#owner"), xmpp_muc_owner_query, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns", "http://jabber.org/protocol/muc#admin"), xmpp_muc_admin_query, ONE},
        {NAME, "bind", xmpp_iq_bind, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("session", "xmlns", "urn:ietf:params:xml:ns:xmpp-session"), xmpp_session, ONE},
        {NAME, "vCard", xmpp_vcard, ONE},
        {NAME, "jingle", xmpp_jingle, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("services", "xmlns", "http://jabber.org/protocol/jinglenodes"), xmpp_jinglenodes_services, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("channel", "xmlns", "http://jabber.org/protocol/jinglenodes#channel"), xmpp_jinglenodes_channel, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("open", "xmlns", "http://jabber.org/protocol/ibb"), xmpp_ibb_open, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("close", "xmlns", "http://jabber.org/protocol/ibb"), xmpp_ibb_close, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("data", "xmlns", "http://jabber.org/protocol/ibb"), xmpp_ibb_data, ONE},
        {NAME, "si", xmpp_si, ONE},
        {NAME, "error", xmpp_error, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("session", "xmlns", "http://www.google.com/session"), xmpp_gtalk_session, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns","google:jingleinfo"), xmpp_gtalk_jingleinfo_query, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("usersetting", "xmlns","google:setting"), xmpp_gtalk_usersetting, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns","jabber:iq:last"), xmpp_last_query, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns","jabber:iq:version"), xmpp_version_query, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns","google:mail:notify"), xmpp_gtalk_mail_query, ONE},
        {NAME, "mailbox", xmpp_gtalk_mail_mailbox, ONE},
        {NAME, "new-mail", xmpp_gtalk_mail_new_mail, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns","google:shared-status"), xmpp_gtalk_status_query, ONE},
        {NAME, "conference-info", xmpp_conference_info, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("ping", "xmlns","urn:xmpp:ping"), xmpp_ping, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("inputevt", "xmlns","http://jitsi.org/protocol/inputevt"), xmpp_jitsi_inputevt, ONE},
    };

    attr_id = xmpp_get_attr(packet, "id");
    attr_type = xmpp_get_attr(packet, "type");

    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    xmpp_iq_item = proto_tree_add_item(tree, hf_xmpp_iq, tvb, packet->offset, packet->length, ENC_LITTLE_ENDIAN);
    xmpp_iq_tree = proto_item_add_subtree(xmpp_iq_item,ett_xmpp_iq);

    xmpp_display_attrs(xmpp_iq_tree, packet, pinfo, tvb, attrs_info,  array_length(attrs_info));


    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "IQ(%s) ", attr_type?attr_type->value:"");

    xmpp_display_elems(xmpp_iq_tree, packet, pinfo, tvb, elems_info, array_length(elems_info));

    /*displays generated info such as req/resp tracking, jingle sid
     * in each packet related to specified jingle session and IBB sid in packet related to it*/
    if(xmpp_info && attr_id)
    {
        gchar *jingle_sid, *ibb_sid, *gtalk_sid;

        jingle_sid = se_tree_lookup_string(xmpp_info->jingle_sessions, attr_id->value, EMEM_TREE_STRING_NOCASE);

        if (jingle_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_jingle_session, tvb, 0, 0, jingle_sid);
            PROTO_ITEM_SET_GENERATED(it);
        }

        ibb_sid = se_tree_lookup_string(xmpp_info->ibb_sessions, attr_id->value, EMEM_TREE_STRING_NOCASE);

        if (ibb_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_ibb, tvb, 0, 0, ibb_sid);
            PROTO_ITEM_SET_GENERATED(it);
        }

        gtalk_sid = se_tree_lookup_string(xmpp_info->gtalk_sessions, attr_id->value, EMEM_TREE_STRING_NOCASE);

        if (gtalk_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_gtalk, tvb, 0, 0, gtalk_sid);
            PROTO_ITEM_SET_GENERATED(it);
        }

        reqresp_trans = se_tree_lookup_string(xmpp_info->req_resp, attr_id->value, EMEM_TREE_STRING_NOCASE);
        /*displays request/response field in each iq packet*/
        if (reqresp_trans) {

            if (reqresp_trans->req_frame == pinfo->fd->num) {
                if (reqresp_trans->resp_frame) {
                    proto_item *it = proto_tree_add_uint(tree, hf_xmpp_response_in, tvb, 0, 0, reqresp_trans->resp_frame);
                    PROTO_ITEM_SET_GENERATED(it);
                } else
                {
                    expert_add_info_format(pinfo, xmpp_iq_item , PI_PROTOCOL, PI_CHAT, "Packet without response");
                }

            } else {
                if (reqresp_trans->req_frame) {
                    proto_item *it = proto_tree_add_uint(tree, hf_xmpp_response_to, tvb, 0, 0, reqresp_trans->req_frame);
                    PROTO_ITEM_SET_GENERATED(it);
                } else
                {
                    expert_add_info_format(pinfo, xmpp_iq_item , PI_PROTOCOL, PI_CHAT, "Packet without response");
                }
            }
        }
    }


}


static void
xmpp_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *error_item;
    proto_tree *error_tree;

    xmpp_element_t *text_element, *cond_element;

    xmpp_attr_info attrs_info[] = {
        {"type", hf_xmpp_error_type, TRUE, TRUE, NULL, NULL},
        {"code", hf_xmpp_error_code, FALSE, TRUE, NULL, NULL},
        {"condition", hf_xmpp_error_condition, TRUE, TRUE, NULL, NULL} /*TODO: validate list to the condition element*/
    };

    gchar *error_info;

    xmpp_attr_t *fake_condition = NULL;

    error_info = ep_strdup("Stanza error");

    error_item = proto_tree_add_item(tree, hf_xmpp_error, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    error_tree = proto_item_add_subtree(error_item, ett_xmpp_query_item);

    cond_element = xmpp_steal_element_by_attr(element, "xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    if(cond_element)
    {
        fake_condition = xmpp_ep_init_attr_t(cond_element->name, cond_element->offset, cond_element->length);
        g_hash_table_insert(element->attrs,"condition", fake_condition);

        error_info = ep_strdup_printf("%s: %s;", error_info, cond_element->name);
    }


    xmpp_display_attrs(error_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((text_element = xmpp_steal_element_by_name(element, "text")) != NULL)
    {
        xmpp_error_text(error_tree, tvb, text_element);

        error_info = ep_strdup_printf("%s Text: %s", error_info, text_element->data?text_element->data->value:"");
    }

    expert_add_info_format(pinfo, error_item, PI_RESPONSE_CODE, PI_CHAT,"%s", error_info);

    xmpp_unknown(error_tree, tvb, pinfo, element);
}

static void
xmpp_error_text(proto_tree *tree, tvbuff_t *tvb, xmpp_element_t *element)
{
    proto_tree_add_string(tree, hf_xmpp_error_text, tvb, element->offset, element->length, element->data?element->data->value:"");
}


void
xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *presence_item;
    proto_tree *presence_tree;

    const gchar *type_enums[] = {"error", "probe", "subscribe", "subscribed",
        "unavailable", "unsubscribe", "unsubscribed"};
    xmpp_array_t *type_array = xmpp_ep_init_array_t(type_enums, array_length(type_enums));

    const gchar *show_enums[] = {"away", "chat", "dnd", "xa"};
    xmpp_array_t *show_array = xmpp_ep_init_array_t(show_enums, array_length(show_enums));

    xmpp_attr_info attrs_info[] = {
        {"from", hf_xmpp_from, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_id, FALSE, TRUE, NULL, NULL},
        {"to", hf_xmpp_to, FALSE, FALSE, NULL, NULL},
        {"type", hf_xmpp_type, FALSE, TRUE, xmpp_val_enum_list, type_array},
        {"xml:lang",-1, FALSE, FALSE, NULL,NULL},
        {"show", hf_xmpp_presence_show, FALSE, TRUE, xmpp_val_enum_list, show_array},
        {"priority", -1, FALSE, FALSE, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "status", xmpp_presence_status, MANY},
        {NAME_AND_ATTR, xmpp_name_attr_struct("c","xmlns","http://jabber.org/protocol/caps"), xmpp_presence_caps, ONE},
        {NAME, "delay", xmpp_delay, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("x","xmlns", "jabber:x:delay"), xmpp_delay, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("x","xmlns", "vcard-temp:x:update"), xmpp_vcard_x_update, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("x","xmlns","http://jabber.org/protocol/muc"), xmpp_muc_x, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("x","xmlns","http://jabber.org/protocol/muc#user"), xmpp_muc_user_x, ONE},
        {NAME, "error", xmpp_error, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("query", "xmlns","jabber:iq:last"), xmpp_last_query, ONE}
    };


    xmpp_element_t *show, *priority;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "PRESENCE ");

    presence_item = proto_tree_add_item(tree, hf_xmpp_presence, tvb, packet->offset, packet->length, ENC_BIG_ENDIAN);
    presence_tree = proto_item_add_subtree(presence_item, ett_xmpp_presence);

    if((show = xmpp_steal_element_by_name(packet, "show"))!=NULL)
    {
        xmpp_attr_t *fake_show = xmpp_ep_init_attr_t(show->data?show->data->value:"",show->offset, show->length);
        g_hash_table_insert(packet->attrs, "show", fake_show);
    }

    if((priority = xmpp_steal_element_by_name(packet, "priority"))!=NULL)
    {
        xmpp_attr_t *fake_priority = xmpp_ep_init_attr_t(priority->data?priority->data->value:"",priority->offset, priority->length);
        g_hash_table_insert(packet->attrs, "priority", fake_priority);
    }
    xmpp_display_attrs(presence_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(presence_tree, packet, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_presence_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *status_item;
    proto_tree *status_tree;

    xmpp_attr_info attrs_info[] = {
        {"xml:lang", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    xmpp_attr_t *fake_value;

    status_item = proto_tree_add_item(tree, hf_xmpp_presence_status, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    status_tree = proto_item_add_subtree(status_item, ett_xmpp_presence_status);

    if(element->data)
        fake_value = xmpp_ep_init_attr_t(element->data->value, element->offset, element->length);
    else
        fake_value = xmpp_ep_init_attr_t("(empty)", element->offset, element->length);


    g_hash_table_insert(element->attrs, "value", fake_value);

    xmpp_display_attrs(status_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(status_tree, tvb, pinfo, element);
}


void
xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *message_item;
    proto_tree *message_tree;

    const gchar *type_enums[] = {"chat", "error", "groupchat", "headline", "normal"};
    xmpp_array_t *type_array = xmpp_ep_init_array_t(type_enums, array_length(type_enums));

    xmpp_attr_info attrs_info[] = {
        {"from", hf_xmpp_from, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_id, FALSE, TRUE, NULL, NULL},
        {"to", hf_xmpp_to, FALSE, FALSE, NULL, NULL},
        {"type", hf_xmpp_type, FALSE, TRUE, xmpp_val_enum_list, type_array},
        {"xml:lang",-1, FALSE, FALSE, NULL,NULL},
        {"chatstate", hf_xmpp_message_chatstate, FALSE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME_AND_ATTR, xmpp_name_attr_struct("data", "xmlns", "http://jabber.org/protocol/ibb"), xmpp_ibb_data, ONE},
        {NAME, "thread", xmpp_message_thread, ONE},
        {NAME, "body", xmpp_message_body, MANY},
        {NAME, "subject", xmpp_message_subject, MANY},
        {NAME, "delay", xmpp_delay, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("x","xmlns","jabber:x:event"), xmpp_x_event, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("x","xmlns","http://jabber.org/protocol/muc#user"), xmpp_muc_user_x, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("x","xmlns","google:nosave"), xmpp_gtalk_nosave_x, ONE},
        {NAME, "error", xmpp_error, ONE}
    };

    xmpp_element_t *chatstate;

    xmpp_attr_t *id = NULL;

    conversation_t *conversation = NULL;
    xmpp_conv_info_t *xmpp_info = NULL;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "MESSAGE ");

    id = xmpp_get_attr(packet, "id");

    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    message_item = proto_tree_add_item(tree, hf_xmpp_message, tvb, packet->offset, packet->length, ENC_BIG_ENDIAN);
    message_tree = proto_item_add_subtree(message_item, ett_xmpp_message);

    if((chatstate = xmpp_steal_element_by_attr(packet, "xmlns", "http://jabber.org/protocol/chatstates"))!=NULL)
    {
        xmpp_attr_t *fake_chatstate_attr = xmpp_ep_init_attr_t(chatstate->name, chatstate->offset, chatstate->length);
        g_hash_table_insert(packet->attrs, "chatstate", fake_chatstate_attr);
    }

    xmpp_display_attrs(message_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(message_tree, packet, pinfo, tvb, elems_info, array_length(elems_info));

    /*Displays data about IBB session*/
    if(xmpp_info && id)
    {
        gchar *ibb_sid;

        ibb_sid = se_tree_lookup_string(xmpp_info->ibb_sessions, id->value, EMEM_TREE_STRING_NOCASE);

        if (ibb_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_ibb, tvb, 0, 0, ibb_sid);
            PROTO_ITEM_SET_GENERATED(it);
        }

    }
}

static void
xmpp_message_body(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *body_item;
    proto_tree *body_tree;

    xmpp_attr_info attrs_info[] = {
        {"xml:lang", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    xmpp_attr_t *fake_data_attr;

    body_item = proto_tree_add_item(tree, hf_xmpp_message_body, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    body_tree = proto_item_add_subtree(body_item, ett_xmpp_message_body);

    fake_data_attr = xmpp_ep_init_attr_t(element->data?element->data->value:"", element->offset, element->length);
    g_hash_table_insert(element->attrs, "value", fake_data_attr);


    xmpp_display_attrs(body_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(body_tree, tvb, pinfo, element);
}

static void
xmpp_message_subject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element) {
    proto_item *subject_item;
    proto_tree *subject_tree;

    xmpp_attr_info attrs_info[] = {
        {"xml:lang", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, FALSE, NULL, NULL}
    };

    xmpp_attr_t *fake_data_attr;

    subject_item = proto_tree_add_item(tree, hf_xmpp_message_subject, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    subject_tree = proto_item_add_subtree(subject_item, ett_xmpp_message_subject);

    fake_data_attr = xmpp_ep_init_attr_t(element->data?element->data->value:"", element->offset, element->length);
    g_hash_table_insert(element->attrs, "value", fake_data_attr);


    xmpp_display_attrs(subject_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(subject_tree, tvb, pinfo, element);
}

static void
xmpp_message_thread(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *thread_item;
    proto_tree *thread_tree;

    xmpp_attr_info attrs_info[] = {
        {"parent", hf_xmpp_message_thread_parent, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    xmpp_attr_t *fake_value;

    thread_item = proto_tree_add_item(tree, hf_xmpp_message_thread, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    thread_tree = proto_item_add_subtree(thread_item, ett_xmpp_message_thread);

    fake_value = xmpp_ep_init_attr_t(element->data?element->data->value:"", element->offset, element->length);
    g_hash_table_insert(element->attrs, "value", fake_value);


    xmpp_display_attrs(thread_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(thread_tree, tvb, pinfo, element);
}

void
xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *auth_item;
    proto_tree *auth_tree;

    xmpp_attr_info_ext attrs_info[]={
        {"urn:ietf:params:xml:ns:xmpp-sasl", {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}},
        {"urn:ietf:params:xml:ns:xmpp-sasl", {"mechanism", -1, TRUE, TRUE, NULL, NULL}},
        {"http://www.google.com/talk/protocol/auth", {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}},
        {"http://www.google.com/talk/protocol/auth", {"client-uses-full-bind-result", -1, TRUE, TRUE, NULL, NULL}},
    };

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "AUTH");

    auth_item = proto_tree_add_item(tree, hf_xmpp_auth, tvb, packet->offset, packet->length, ENC_BIG_ENDIAN);
    auth_tree = proto_item_add_subtree(auth_item, ett_xmpp_auth);

    xmpp_display_attrs_ext(auth_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_cdata(auth_tree, tvb, packet, -1);

    xmpp_unknown(auth_tree, tvb, pinfo, packet);
}

void
xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, xmpp_element_t *packet, gint hf, gint ett,  const char *col_info)
{
    proto_item *item;
    proto_tree *subtree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, col_info);

    item = proto_tree_add_item(tree, hf, tvb, packet->offset, packet->length, ENC_BIG_ENDIAN);
    subtree = proto_item_add_subtree(item, ett);

    xmpp_display_attrs(subtree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_cdata(subtree, tvb, packet, -1);

    xmpp_unknown(subtree, tvb, pinfo, packet);
}

void
xmpp_failure(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *fail_item;
    proto_tree *fail_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"condition", -1, FALSE, TRUE, NULL, NULL}
    };

    const gchar *fail_names[] = {"aborted","account-disabled", "credentials-expired",
        "encryption-required", "incorrect-encoding", "invalid-authzid", "invalid-mechanism",
        "malformed-request", "mechanism-too-weak", "not-authorized", "temporary-auth-failure",
        "transition-needed"
    };

    xmpp_element_t *fail_condition, *text;

    col_add_fstr(pinfo->cinfo, COL_INFO, "FAILURE ");

    fail_item = proto_tree_add_item(tree, hf_xmpp_failure, tvb, packet->offset, packet->length, ENC_BIG_ENDIAN);
    fail_tree = proto_item_add_subtree(fail_item, ett_xmpp_failure);

    if((fail_condition = xmpp_steal_element_by_names(packet, fail_names, array_length(fail_names)))!=NULL)
    {
        xmpp_attr_t *fake_cond = xmpp_ep_init_attr_t(fail_condition->name, fail_condition->offset, fail_condition->length);
        g_hash_table_insert(packet->attrs, "condition", fake_cond);
    }

    if((text = xmpp_steal_element_by_name(packet, "text"))!=NULL)
    {
        xmpp_failure_text(fail_tree, tvb, text);
    }

    xmpp_display_attrs(fail_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(fail_tree, tvb, pinfo, packet);
}

static void
xmpp_failure_text(proto_tree *tree, tvbuff_t *tvb, xmpp_element_t *element)
{
    xmpp_attr_t *lang = xmpp_get_attr(element,"xml:lang");

    proto_tree_add_text(tree, tvb, element->offset, element->length, "TEXT%s: %s",
            lang?ep_strdup_printf("(%s)",lang->value):"",
            element->data?element->data->value:"");
}

void
xmpp_xml_header(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, xmpp_element_t *packet)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "XML ");
    proto_tree_add_text(tree, tvb, packet->offset, packet->length, "XML HEADER VER. %s","1.0");
}

void
xmpp_stream(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *stream_item;
    proto_tree *stream_tree;

    xmpp_attr_info_ext attrs_info [] = {
        {"http://etherx.jabber.org/streams",{"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL}},
        {"http://etherx.jabber.org/streams",{"version", -1, FALSE, TRUE, NULL, NULL}},
        {"http://etherx.jabber.org/streams",{"from",-1, FALSE, TRUE, NULL, NULL}},
        {"http://etherx.jabber.org/streams",{"to",-1, FALSE, TRUE, NULL, NULL}},
        {"http://etherx.jabber.org/streams",{"id",-1, FALSE, TRUE, NULL, NULL}},
        {"http://etherx.jabber.org/streams",{"xml:lang",-1, FALSE, TRUE, NULL, NULL}},
        {"jabber:client",{"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL}},

    };

    col_add_fstr(pinfo->cinfo, COL_INFO, "STREAM ");

    stream_item = proto_tree_add_item(tree, hf_xmpp_stream, tvb, packet->offset, packet->length, ENC_BIG_ENDIAN);
    stream_tree = proto_item_add_subtree(stream_item, ett_xmpp_stream);

    xmpp_display_attrs_ext(stream_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(stream_tree, packet, pinfo, tvb, NULL, 0);
}

/*returns TRUE if stream end occurs*/
gboolean
xmpp_stream_close(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo)
{
    tvbparse_t* tt;
    tvbparse_elem_t* elem;
    tvbparse_wanted_t* want_ignore = tvbparse_chars(1,1,0," \t\r\n",NULL,NULL,NULL);
    tvbparse_wanted_t* want_name = tvbparse_chars(2,1,0,"abcdefghijklmnopqrstuvwxyz.-_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",NULL,NULL,NULL);
    tvbparse_wanted_t* want_stream_end_with_ns = tvbparse_set_seq(3, NULL, NULL, NULL,
                                                               want_name,
                                                               tvbparse_char(4, ":", NULL, NULL, NULL),
                                                               want_name,
                                                               NULL);

    tvbparse_wanted_t* want_stream_end = tvbparse_set_oneof(5, NULL, NULL, NULL,
                                                               want_stream_end_with_ns,
                                                               want_name,
                                                               NULL);

    tvbparse_wanted_t* want_stream_end_tag = tvbparse_set_seq(6, NULL, NULL, NULL,
                                                               tvbparse_string(-1,"</",NULL,NULL,NULL),
                                                               want_stream_end,
                                                               tvbparse_char(-1,">",NULL,NULL,NULL),
                                                               NULL);
    tt = tvbparse_init(tvb,0,-1,NULL,want_ignore);

    if((elem = tvbparse_get(tt,want_stream_end_tag))!=NULL)
    {
        proto_tree_add_text(tree, tvb, elem->offset, elem->len, "STREAM END");
        col_add_fstr(pinfo->cinfo, COL_INFO, "STREAM END");

        return TRUE;
    }
    return FALSE;
}

void
xmpp_features(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *features_item;
    proto_tree *features_tree;

    xmpp_elem_info elems_info [] = {
        {NAME, "mechanisms", xmpp_features_mechanisms, MANY}
    };

    features_item = proto_tree_add_item(tree, hf_xmpp_features, tvb, packet->offset, packet->length,
        ENC_BIG_ENDIAN);
    features_tree = proto_item_add_subtree(features_item, ett_xmpp_features);

    col_add_fstr(pinfo->cinfo, COL_INFO, "FEATURES ");

    xmpp_display_attrs(features_tree, packet, pinfo, tvb, NULL, 0);
    xmpp_display_elems(features_tree, packet, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_features_mechanisms(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *mechanisms_item;
    proto_tree *mechanisms_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "mechanism", xmpp_simple_cdata_elem, MANY},
    };

    mechanisms_item = proto_tree_add_text(tree, tvb, packet->offset, packet->length, "MECHANISMS");
    mechanisms_tree = proto_item_add_subtree(mechanisms_item, ett_xmpp_features_mechanisms);

    xmpp_display_attrs(mechanisms_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(mechanisms_tree, packet, pinfo, tvb, elems_info, array_length(elems_info));
}

void
xmpp_starttls(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *tls_item;
    proto_tree *tls_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
    };

    col_add_fstr(pinfo->cinfo, COL_INFO, "STARTTLS ");

    tls_item = proto_tree_add_item(tree, hf_xmpp_starttls, tvb, packet->offset, packet->length, ENC_BIG_ENDIAN);
    tls_tree = proto_item_add_subtree(tls_item, ett_xmpp_starttls);

    xmpp_display_attrs(tls_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(tls_tree, packet, pinfo, tvb, NULL, 0);
}

void
xmpp_proceed(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *packet)
{
    proto_item *proceed_item;
    proto_tree *proceed_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
    };

    col_add_fstr(pinfo->cinfo, COL_INFO, "PROCEED ");

    proceed_item = proto_tree_add_item(tree, hf_xmpp_proceed, tvb, packet->offset, packet->length, ENC_BIG_ENDIAN);
    proceed_tree = proto_item_add_subtree(proceed_item, ett_xmpp_proceed);

    xmpp_display_attrs(proceed_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(proceed_tree, packet, pinfo, tvb, NULL, 0);
}
/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
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
