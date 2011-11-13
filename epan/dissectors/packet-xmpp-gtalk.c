/* xmpp-gtalk.c
 * Wireshark's XMPP dissector.
 *
 * GTalk extensions.
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

#include <epan/dissectors/packet-xml.h>

#include <packet-xmpp.h>
#include <packet-xmpp-utils.h>
#include <packet-xmpp-gtalk.h>
#include <packet-xmpp-conference.h>


static void xmpp_gtalk_session_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_session_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_session_cand(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_session_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_jingleinfo_stun(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_jingleinfo_server(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_jingleinfo_relay(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_jingleinfo_relay_serv(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_nosave_item(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_mail_mail_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_mail_senders(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_mail_sender(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_mail_snippet(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_status_status_list(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_transport_p2p_cand(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);

void
xmpp_gtalk_session(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *session_item;
    proto_tree *session_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"type", hf_xmpp_gtalk_session_type, TRUE, TRUE, NULL, NULL},
        {"initiator", -1, FALSE, TRUE, NULL, NULL},
        {"id", -1, TRUE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME,"description", xmpp_gtalk_session_desc, ONE},
        {NAME, "candidate", xmpp_gtalk_session_cand, MANY},
        {NAME, "reason", xmpp_gtalk_session_reason, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct("transport", "xmlns", "http://www.google.com/transport/p2p"), xmpp_gtalk_transport_p2p, ONE},
        {NAME, "conference-info", xmpp_conferece_info_advert, ONE}
    };

    xmpp_attr_t *attr_type = xmpp_get_attr(element, "type");

    col_append_fstr(pinfo->cinfo, COL_INFO, "GTALK-SESSION(%s) ", attr_type?attr_type->value:"");

    session_item = proto_tree_add_item(tree, hf_xmpp_gtalk_session, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    session_tree = proto_item_add_subtree(session_item, ett_xmpp_gtalk_session);

    xmpp_display_attrs(session_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(session_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_session_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"xml:lang", -1, FALSE, FALSE, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "payload-type", xmpp_gtalk_session_desc_payload, MANY}
    };

    desc_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "DESCRIPTION");
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_gtalk_session_desc);

    xmpp_display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(desc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_session_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *payload_item;
    proto_tree *payload_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL},
        {"id", -1, FALSE, TRUE, NULL, NULL},
        {"name", -1, FALSE, TRUE, NULL, NULL},
        {"channels", -1, FALSE, FALSE, NULL, NULL},
        {"clockrate", -1, FALSE, FALSE, NULL, NULL},
        {"bitrate", -1, FALSE, FALSE, NULL, NULL},
        {"width", -1, FALSE, FALSE, NULL, NULL},
        {"height", -1, FALSE, FALSE, NULL, NULL},
        {"framerate", -1, FALSE, FALSE, NULL, NULL},
    };

    payload_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "PAYLOAD-TYPE");
    payload_tree = proto_item_add_subtree(payload_item, ett_xmpp_gtalk_session_desc_payload);

    xmpp_display_attrs(payload_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(payload_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_session_cand(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    xmpp_attr_info attrs_info[] = {
        {"name", -1, TRUE, TRUE, NULL, NULL},
        {"address", -1, TRUE, FALSE, NULL, NULL},
        {"port", -1, TRUE, FALSE, NULL, NULL},
        {"preference", -1, TRUE, FALSE, NULL, NULL},
        {"type", -1, TRUE, TRUE, NULL, NULL},
        {"protocol", -1, TRUE, TRUE, NULL, NULL},
        {"network", -1, TRUE, FALSE, NULL, NULL},
        {"username", -1, TRUE, FALSE, NULL, NULL},
        {"password", -1, TRUE, FALSE, NULL, NULL},
        {"generation", -1, TRUE, FALSE, NULL, NULL},
        {"foundation", -1, FALSE, FALSE, NULL, NULL},
        {"component", -1, FALSE, FALSE, NULL, NULL}
    };

    cand_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "CANDIDATE");
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_gtalk_session_cand);

    xmpp_display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(cand_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_session_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *reason_item;
    proto_tree *reason_tree;

    xmpp_attr_info attrs_info[] = {
        {"condition", -1, TRUE, TRUE, NULL, NULL},
        {"text", -1, FALSE, FALSE, NULL, NULL}
   };

    xmpp_element_t *condition;
    xmpp_element_t *text;

    const gchar *reason_names[] = { "success", "busy", "cancel"};

    reason_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "REASON");
    reason_tree = proto_item_add_subtree(reason_item, ett_xmpp_gtalk_session_reason);


    /*Looks for reason description.*/
    if((condition = xmpp_steal_element_by_names(element, reason_names, array_length(reason_names)))!=NULL)
    {
        xmpp_attr_t *fake_cond = xmpp_ep_init_attr_t(condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, "condition", fake_cond);

    }

    if((text = xmpp_steal_element_by_name(element, "text"))!=NULL)
    {
        xmpp_attr_t *fake_text = xmpp_ep_init_attr_t(text->data?text->data->value:"", text->offset, text->length);
        g_hash_table_insert(element->attrs, "text", fake_text);
    }

    xmpp_display_attrs(reason_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(reason_tree, tvb, pinfo, element);
}

void
xmpp_gtalk_jingleinfo_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "stun", xmpp_gtalk_jingleinfo_stun, ONE},
        {NAME, "relay", xmpp_gtalk_jingleinfo_relay, ONE}
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(google:jingleinfo) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_jingleinfo_stun(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *stun_item;
    proto_tree *stun_tree;

    xmpp_elem_info elems_info [] = {
        {NAME, "server", xmpp_gtalk_jingleinfo_server, MANY},
    };

    stun_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "STUN");
    stun_tree = proto_item_add_subtree(stun_item, ett_xmpp_gtalk_jingleinfo_stun);

    xmpp_display_attrs(stun_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(stun_tree, element, pinfo, tvb, elems_info, array_length(elems_info));

}

static void
xmpp_gtalk_jingleinfo_server(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *serv_item;
    proto_tree *serv_tree;

    xmpp_attr_info attrs_info[] = {
        {"host", -1, TRUE, TRUE, NULL, NULL},
        {"udp", -1, TRUE, TRUE, NULL, NULL}
    };

    serv_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "SERVER");
    serv_tree = proto_item_add_subtree(serv_item, ett_xmpp_gtalk_jingleinfo_server);

    xmpp_display_attrs(serv_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(serv_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_jingleinfo_relay(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *relay_item;
    proto_tree *relay_tree;

    xmpp_attr_info attrs_info[] = {
        {"token", -1, FALSE, FALSE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "server", xmpp_gtalk_jingleinfo_relay_serv, ONE}
    };

    xmpp_element_t *token;

    relay_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "RELAY");
    relay_tree = proto_item_add_subtree(relay_item, ett_xmpp_gtalk_jingleinfo_relay);

    if((token  = xmpp_steal_element_by_name(element, "token"))!=NULL)
    {
        xmpp_attr_t *fake_token = xmpp_ep_init_attr_t(token->data?token->data->value:"", token->offset, token->length);
        g_hash_table_insert(element->attrs, "token", fake_token);
    }

    xmpp_display_attrs(relay_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(relay_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_jingleinfo_relay_serv(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *serv_item;
    proto_tree *serv_tree;

    xmpp_attr_info attrs_info[] = {
        {"host", -1, TRUE, TRUE, NULL, NULL},
        {"udp", -1, FALSE, TRUE, NULL, NULL},
        {"tcp", -1, FALSE, TRUE, NULL, NULL},
        {"tcpssl", -1, FALSE, TRUE, NULL, NULL}
    };

    serv_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "SERVER");
    serv_tree = proto_item_add_subtree(serv_item, ett_xmpp_gtalk_jingleinfo_relay_serv);

    xmpp_display_attrs(serv_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(serv_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_gtalk_usersetting(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *sett_item;
    proto_tree *sett_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    guint i;

    sett_item = proto_tree_add_item(tree, hf_xmpp_gtalk_setting, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    sett_tree = proto_item_add_subtree(sett_item, ett_xmpp_gtalk_setting);

    xmpp_display_attrs(sett_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    for(i = 0; i < g_list_length(element->elements); i++)
    {
        GList *elem_l = g_list_nth(element->elements,i);
        xmpp_element_t *elem = elem_l?elem_l->data:NULL;

        if(elem)
        {
            xmpp_attr_t *val = xmpp_get_attr(elem,"value");
            proto_tree_add_text(sett_tree, tvb, elem->offset, elem->length, "%s [%s]",elem->name,val?val->value:"");
        }
    }
}

void
xmpp_gtalk_nosave_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element) {
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "item", xmpp_gtalk_nosave_item, MANY},
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(google:nosave) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_nosave_item(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL,NULL},
        {"jid", -1, TRUE, TRUE, NULL, NULL},
        {"source", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    item_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "ITEM");
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_query_item);

    xmpp_display_attrs(item_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(item_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_gtalk_nosave_x(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"value", -1, FALSE, TRUE, NULL, NULL}
    };

    x_item = proto_tree_add_item(tree, hf_xmpp_gtalk_nosave_x, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_gtalk_nosave_x);

    xmpp_display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(x_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_gtalk_mail_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"newer-than-time", -1, FALSE, TRUE, NULL, NULL},
        {"newer-than-tid", -1, FALSE, TRUE, NULL, NULL},
        {"q", -1, FALSE, TRUE, NULL, NULL}
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(google:mail:notify) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_gtalk_mail_mailbox(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *mail_item;
    proto_tree *mail_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL},
        {"result-time", -1, FALSE, TRUE, NULL, NULL},
        {"total-matched", -1, FALSE, TRUE, NULL, NULL},
        {"total-estimate", -1, FALSE, TRUE, NULL, NULL},
        {"url", -1, FALSE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME,"mail-thread-info", xmpp_gtalk_mail_mail_info, MANY}
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "MAILBOX ");

    mail_item = proto_tree_add_item(tree, hf_xmpp_gtalk_mail_mailbox, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    mail_tree = proto_item_add_subtree(mail_item, ett_xmpp_gtalk_mail_mailbox);

    xmpp_display_attrs(mail_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(mail_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_mail_mail_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *mail_info_item;
    proto_tree *mail_info_tree;

    xmpp_attr_info attrs_info [] = {
        {"tid", -1, FALSE, FALSE, NULL, NULL},
        {"participation", -1, FALSE, FALSE, NULL, NULL},
        {"messages", -1, FALSE, TRUE, NULL, NULL},
        {"date", -1, FALSE, TRUE, NULL, NULL},
        {"url", -1, FALSE, FALSE, NULL, NULL},
        {"labels", -1, FALSE, FALSE, NULL, NULL},
        {"subject", -1, FALSE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "senders", xmpp_gtalk_mail_senders, ONE},
        {NAME, "snippet", xmpp_gtalk_mail_snippet, ONE}/*or MANY?*/
    };

    xmpp_element_t *labels, *subject;

    mail_info_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "MAIL-THREAD-INFO");
    mail_info_tree = proto_item_add_subtree(mail_info_item,ett_xmpp_gtalk_mail_mail_info);

    if((labels = xmpp_steal_element_by_name(element,"labels"))!=NULL)
    {
        xmpp_attr_t *fake_labels = xmpp_ep_init_attr_t(labels->data?labels->data->value:"",labels->offset, labels->length);
        g_hash_table_insert(element->attrs, "labels", fake_labels);
    }
    if((subject = xmpp_steal_element_by_name(element,"subject"))!=NULL)
    {
        xmpp_attr_t *fake_subject = xmpp_ep_init_attr_t(subject->data?subject->data->value:"",subject->offset, subject->length);
        g_hash_table_insert(element->attrs, "subject", fake_subject);
    }

    xmpp_display_attrs(mail_info_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(mail_info_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}


static void
xmpp_gtalk_mail_senders(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *senders_item;
    proto_tree *senders_tree;

    xmpp_elem_info elems_info [] = {
        {NAME, "sender", xmpp_gtalk_mail_sender, MANY}
    };

    senders_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "SENDERS");
    senders_tree = proto_item_add_subtree(senders_item, ett_xmpp_gtalk_mail_senders);

    xmpp_display_attrs(senders_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(senders_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_mail_sender(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *sender_item;
    proto_tree *sender_tree;

    xmpp_attr_info attrs_info [] = {
        {"name", -1, FALSE, TRUE, NULL, NULL},
        {"address", -1, FALSE, TRUE, NULL, NULL},
        {"originator", -1, FALSE, TRUE, NULL, NULL},
        {"unread", -1, FALSE, TRUE, NULL, NULL}
    };

    sender_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "SENDER");
    sender_tree = proto_item_add_subtree(sender_item, ett_xmpp_gtalk_mail_sender);

    xmpp_display_attrs(sender_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(sender_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_mail_snippet(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree_add_text(tree, tvb, element->offset, element->length, "SNIPPET: %s",element->data?element->data->value:"");
    xmpp_unknown(tree, tvb, pinfo, element);
}

void
xmpp_gtalk_mail_new_mail(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    col_append_fstr(pinfo->cinfo, COL_INFO, "NEW-MAIL ");
    proto_tree_add_item(tree, hf_xmpp_gtalk_mail_new_mail, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    xmpp_unknown(tree, tvb, pinfo, element);
}


void
xmpp_gtalk_status_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"version", -1, FALSE, TRUE, NULL, NULL},
        {"status-max", -1, FALSE, FALSE, NULL, NULL},
        {"status-list-max", -1, FALSE, FALSE, NULL, NULL},
        {"status-list-contents-max", -1, FALSE, FALSE, NULL, NULL},
        {"status-min-ver", -1, FALSE, TRUE, NULL, NULL},
        {"show", -1, FALSE, TRUE, NULL, NULL},
        {"status", -1, FALSE, TRUE, NULL, NULL},
        {"invisible", -1, FALSE, TRUE, NULL, NULL},
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "status-list", xmpp_gtalk_status_status_list, MANY}
    };

    xmpp_element_t *status, *show, *invisible;

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(google:shared-status) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    if((status = xmpp_steal_element_by_name(element,"status"))!=NULL)
    {
        xmpp_attr_t *fake_status = xmpp_ep_init_attr_t(status->data?status->data->value:"",status->offset, status->length);
        g_hash_table_insert(element->attrs, "status", fake_status);
    }

    if((show = xmpp_steal_element_by_name(element,"show"))!=NULL)
    {
        xmpp_attr_t *fake_show = xmpp_ep_init_attr_t(show->data?show->data->value:"",show->offset, show->length);
        g_hash_table_insert(element->attrs, "show", fake_show);
    }

    if((invisible = xmpp_steal_element_by_name(element,"invisible"))!=NULL)
    {
        xmpp_attr_t *value = xmpp_get_attr(invisible, "value");
        xmpp_attr_t *fake_invisible = xmpp_ep_init_attr_t(value?value->value:"",invisible->offset, invisible->length);
        g_hash_table_insert(element->attrs, "invisible", fake_invisible);
    }

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_status_status_list(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *list_item;
    proto_tree *list_tree;

    xmpp_attr_info attrs_info [] = {
        {"show", -1, TRUE, TRUE, NULL, NULL}
    };

    xmpp_element_t *status;

    list_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "STATUS LIST");
    list_tree = proto_item_add_subtree(list_item, ett_xmpp_gtalk_status_status_list);

    while((status = xmpp_steal_element_by_name(element, "status"))!=NULL)
    {
        proto_tree_add_text(list_tree, tvb, status->offset, status->length, "STATUS: %s",status->data?status->data->value:"");
    }

    xmpp_display_attrs(list_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(list_tree, element, pinfo, tvb, NULL, 0);
}

/*http://www.google.com/transport/p2p*/
void
xmpp_gtalk_transport_p2p(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "candidate", xmpp_gtalk_transport_p2p_cand, MANY}
    };

    trans_item = proto_tree_add_item(tree, hf_xmpp_gtalk_transport_p2p, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_gtalk_transport_p2p);

    xmpp_display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_display_elems(trans_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_transport_p2p_cand(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element) {
    proto_item *cand_item;
    proto_tree *cand_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"name", -1, FALSE, TRUE, NULL, NULL},
        {"generation", -1, FALSE, FALSE, NULL, NULL},
        {"network", -1, FALSE, FALSE, NULL, NULL},
        {"component", -1, FALSE, FALSE, NULL, NULL},
        {"type", -1, FALSE, FALSE, NULL, NULL},
        {"protocol", -1, FALSE, TRUE, NULL, NULL},
        {"preference", -1, FALSE, FALSE, NULL, NULL},
        {"password", -1, FALSE, FALSE, NULL, NULL},
        {"username", -1, FALSE, FALSE, NULL, NULL},
        {"port", -1, FALSE, TRUE, NULL, NULL},
        {"address", -1, FALSE, TRUE, NULL, NULL}
    };

    cand_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "CANDIDATE");
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_gtalk_transport_p2p_cand);

    xmpp_display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(cand_tree, element, pinfo, tvb, NULL, 0);

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
