/* xmpp-gtalk.c
 * Wireshark's XMPP dissector.
 *
 * GTalk extensions.
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
#include "packet-xmpp-gtalk.h"
#include "packet-xmpp-conference.h"


static void xmpp_gtalk_session_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_session_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_session_cand(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_session_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_jingleinfo_stun(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_jingleinfo_server(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_jingleinfo_relay(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_gtalk_jingleinfo_relay_serv(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
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
        {"xmlns", &hf_xmpp_xmlns, true, false, NULL, NULL},
        {"type", &hf_xmpp_gtalk_session_type, true, true, NULL, NULL},
        {"initiator", NULL, false, true, NULL, NULL},
        {"id", NULL, true, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME,"description", xmpp_gtalk_session_desc, ONE},
        {NAME, "candidate", xmpp_gtalk_session_cand, MANY},
        {NAME, "reason", xmpp_gtalk_session_reason, ONE},
        {NAME_AND_ATTR, xmpp_name_attr_struct(pinfo->pool, "transport", "xmlns", "http://www.google.com/transport/p2p"), xmpp_gtalk_transport_p2p, ONE},
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
    proto_tree *desc_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL},
        {"xml:lang", NULL, false, false, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "payload-type", xmpp_gtalk_session_desc_payload, MANY}
    };

    desc_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_session_desc, NULL, "DESCRIPTION");

    xmpp_display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(desc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_session_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *payload_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, true, NULL, NULL},
        {"id", NULL, false, true, NULL, NULL},
        {"name", NULL, false, true, NULL, NULL},
        {"channels", NULL, false, false, NULL, NULL},
        {"clockrate", NULL, false, false, NULL, NULL},
        {"bitrate", NULL, false, false, NULL, NULL},
        {"width", NULL, false, false, NULL, NULL},
        {"height", NULL, false, false, NULL, NULL},
        {"framerate", NULL, false, false, NULL, NULL},
    };

    payload_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_session_desc_payload, NULL, "PAYLOAD-TYPE");

    xmpp_display_attrs(payload_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(payload_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_session_cand(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *cand_tree;

    xmpp_attr_info attrs_info[] = {
        {"name", NULL, true, true, NULL, NULL},
        {"address", NULL, true, false, NULL, NULL},
        {"port", NULL, true, false, NULL, NULL},
        {"preference", NULL, true, false, NULL, NULL},
        {"type", NULL, true, true, NULL, NULL},
        {"protocol", NULL, true, true, NULL, NULL},
        {"network", NULL, true, false, NULL, NULL},
        {"username", NULL, true, false, NULL, NULL},
        {"password", NULL, true, false, NULL, NULL},
        {"generation", NULL, true, false, NULL, NULL},
        {"foundation", NULL, false, false, NULL, NULL},
        {"component", NULL, false, false, NULL, NULL}
    };

    cand_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_session_cand, NULL, "CANDIDATE");

    xmpp_display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(cand_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_session_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *reason_tree;

    xmpp_attr_info attrs_info[] = {
        {"condition", NULL, true, true, NULL, NULL},
        {"text", NULL, false, false, NULL, NULL}
   };

    xmpp_element_t *condition;
    xmpp_element_t *text;

    static const char *reason_names[] = { "success", "busy", "cancel"};

    reason_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_session_reason, NULL, "REASON");


    /*Looks for reason description.*/
    if((condition = xmpp_steal_element_by_names(element, reason_names, array_length(reason_names)))!=NULL)
    {
        xmpp_attr_t *fake_cond = xmpp_ep_init_attr_t(pinfo->pool, condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, (void *)"condition", fake_cond);

    }

    if((text = xmpp_steal_element_by_name(element, "text"))!=NULL)
    {
        xmpp_attr_t *fake_text = xmpp_ep_init_attr_t(pinfo->pool, text->data?text->data->value:"", text->offset, text->length);
        g_hash_table_insert(element->attrs, (void *)"text", fake_text);
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
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "stun", xmpp_gtalk_jingleinfo_stun, ONE},
        {NAME, "relay", xmpp_gtalk_jingleinfo_relay, ONE}
    };

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(google:jingleinfo) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_jingleinfo_stun(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *stun_tree;

    xmpp_elem_info elems_info [] = {
        {NAME, "server", xmpp_gtalk_jingleinfo_server, MANY},
    };

    stun_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_jingleinfo_stun, NULL, "STUN");

    xmpp_display_attrs(stun_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(stun_tree, element, pinfo, tvb, elems_info, array_length(elems_info));

}

static void
xmpp_gtalk_jingleinfo_server(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *serv_tree;

    xmpp_attr_info attrs_info[] = {
        {"host", NULL, true, true, NULL, NULL},
        {"udp", NULL, true, true, NULL, NULL}
    };

    serv_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_jingleinfo_server, NULL, "SERVER");

    xmpp_display_attrs(serv_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(serv_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_jingleinfo_relay(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *relay_tree;

    xmpp_attr_info attrs_info[] = {
        {"token", NULL, false, false, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "server", xmpp_gtalk_jingleinfo_relay_serv, ONE}
    };

    xmpp_element_t *token;

    relay_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_jingleinfo_relay, NULL, "RELAY");

    if((token  = xmpp_steal_element_by_name(element, "token"))!=NULL)
    {
        xmpp_attr_t *fake_token = xmpp_ep_init_attr_t(pinfo->pool, token->data?token->data->value:"", token->offset, token->length);
        g_hash_table_insert(element->attrs, (void *)"token", fake_token);
    }

    xmpp_display_attrs(relay_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(relay_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_jingleinfo_relay_serv(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *serv_tree;

    xmpp_attr_info attrs_info[] = {
        {"host", NULL, true, true, NULL, NULL},
        {"udp", NULL, false, true, NULL, NULL},
        {"tcp", NULL, false, true, NULL, NULL},
        {"tcpssl", NULL, false, true, NULL, NULL}
    };

    serv_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_jingleinfo_relay_serv, NULL, "SERVER");

    xmpp_display_attrs(serv_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(serv_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_gtalk_usersetting(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *sett_item;
    proto_tree *sett_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL}
    };

    unsigned i;

    sett_item = proto_tree_add_item(tree, hf_xmpp_gtalk_setting, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    sett_tree = proto_item_add_subtree(sett_item, ett_xmpp_gtalk_setting);

    xmpp_display_attrs(sett_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    for(i = 0; i < g_list_length(element->elements); i++)
    {
        GList *elem_l = g_list_nth(element->elements,i);
        xmpp_element_t *elem = (xmpp_element_t *)(elem_l?elem_l->data:NULL);

        if(elem)
        {
            xmpp_attr_t *val = xmpp_get_attr(elem,"value");
            proto_tree_add_string_format(sett_tree, hf_xmpp_gtalk_setting_element, tvb, elem->offset, elem->length, val?val->value:"",
                            "%s [%s]",elem->name,val?val->value:"");
        }
    }
}

void
xmpp_gtalk_nosave_x(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL},
        {"value", NULL, false, true, NULL, NULL}
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
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL},
        {"newer-than-time", NULL, false, true, NULL, NULL},
        {"newer-than-tid", NULL, false, true, NULL, NULL},
        {"q", NULL, false, true, NULL, NULL}
    };

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(google:mail:notify) ");

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
        {"xmlns", &hf_xmpp_xmlns, false, true, NULL, NULL},
        {"result-time", NULL, false, true, NULL, NULL},
        {"total-matched", NULL, false, true, NULL, NULL},
        {"total-estimate", NULL, false, true, NULL, NULL},
        {"url", NULL, false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME,"mail-thread-info", xmpp_gtalk_mail_mail_info, MANY}
    };

    col_append_str(pinfo->cinfo, COL_INFO, "MAILBOX ");

    mail_item = proto_tree_add_item(tree, hf_xmpp_gtalk_mail_mailbox, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    mail_tree = proto_item_add_subtree(mail_item, ett_xmpp_gtalk_mail_mailbox);

    xmpp_display_attrs(mail_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(mail_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_mail_mail_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *mail_info_tree;

    xmpp_attr_info attrs_info [] = {
        {"tid", NULL, false, false, NULL, NULL},
        {"participation", NULL, false, false, NULL, NULL},
        {"messages", NULL, false, true, NULL, NULL},
        {"date", NULL, false, true, NULL, NULL},
        {"url", NULL, false, false, NULL, NULL},
        {"labels", NULL, false, false, NULL, NULL},
        {"subject", NULL, false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "senders", xmpp_gtalk_mail_senders, ONE},
        {NAME, "snippet", xmpp_gtalk_mail_snippet, ONE}/*or MANY?*/
    };

    xmpp_element_t *labels, *subject;

    mail_info_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_mail_mail_info, NULL, "MAIL-THREAD-INFO");

    if((labels = xmpp_steal_element_by_name(element,"labels"))!=NULL)
    {
        xmpp_attr_t *fake_labels = xmpp_ep_init_attr_t(pinfo->pool, labels->data?labels->data->value:"",labels->offset, labels->length);
        g_hash_table_insert(element->attrs, (void *)"labels", fake_labels);
    }
    if((subject = xmpp_steal_element_by_name(element,"subject"))!=NULL)
    {
        xmpp_attr_t *fake_subject = xmpp_ep_init_attr_t(pinfo->pool, subject->data?subject->data->value:"",subject->offset, subject->length);
        g_hash_table_insert(element->attrs, (void *)"subject", fake_subject);
    }

    xmpp_display_attrs(mail_info_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(mail_info_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}


static void
xmpp_gtalk_mail_senders(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *senders_tree;

    xmpp_elem_info elems_info [] = {
        {NAME, "sender", xmpp_gtalk_mail_sender, MANY}
    };

    senders_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_mail_senders, NULL, "SENDERS");

    xmpp_display_attrs(senders_tree, element, pinfo, tvb, NULL, 0);
    xmpp_display_elems(senders_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_mail_sender(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *sender_tree;

    xmpp_attr_info attrs_info [] = {
        {"name", NULL, false, true, NULL, NULL},
        {"address", NULL, false, true, NULL, NULL},
        {"originator", NULL, false, true, NULL, NULL},
        {"unread", NULL, false, true, NULL, NULL}
    };

    sender_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_mail_sender, NULL, "SENDER");

    xmpp_display_attrs(sender_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(sender_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_mail_snippet(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree_add_string(tree, hf_xmpp_gtalk_mail_snippet, tvb, element->offset, element->length, element->data?element->data->value:"");
    xmpp_unknown(tree, tvb, pinfo, element);
}

void
xmpp_gtalk_mail_new_mail(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    col_append_str(pinfo->cinfo, COL_INFO, "NEW-MAIL ");
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
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL},
        {"version", NULL, false, true, NULL, NULL},
        {"status-max", NULL, false, false, NULL, NULL},
        {"status-list-max", NULL, false, false, NULL, NULL},
        {"status-list-contents-max", NULL, false, false, NULL, NULL},
        {"status-min-ver", NULL, false, true, NULL, NULL},
        {"show", NULL, false, true, NULL, NULL},
        {"status", NULL, false, true, NULL, NULL},
        {"invisible", NULL, false, true, NULL, NULL},
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "status-list", xmpp_gtalk_status_status_list, MANY}
    };

    xmpp_element_t *status, *show, *invisible;

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(google:shared-status) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    if((status = xmpp_steal_element_by_name(element,"status"))!=NULL)
    {
        xmpp_attr_t *fake_status = xmpp_ep_init_attr_t(pinfo->pool, status->data?status->data->value:"",status->offset, status->length);
        g_hash_table_insert(element->attrs, (void *)"status", fake_status);
    }

    if((show = xmpp_steal_element_by_name(element,"show"))!=NULL)
    {
        xmpp_attr_t *fake_show = xmpp_ep_init_attr_t(pinfo->pool, show->data?show->data->value:"",show->offset, show->length);
        g_hash_table_insert(element->attrs, (void *)"show", fake_show);
    }

    if((invisible = xmpp_steal_element_by_name(element,"invisible"))!=NULL)
    {
        xmpp_attr_t *value = xmpp_get_attr(invisible, "value");
        xmpp_attr_t *fake_invisible = xmpp_ep_init_attr_t(pinfo->pool, value?value->value:"",invisible->offset, invisible->length);
        g_hash_table_insert(element->attrs, (void *)"invisible", fake_invisible);
    }

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_status_status_list(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_tree *list_tree;

    xmpp_attr_info attrs_info [] = {
        {"show", NULL, true, true, NULL, NULL}
    };

    xmpp_element_t *status;

    list_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_status_status_list, NULL, "STATUS LIST");

    while((status = xmpp_steal_element_by_name(element, "status"))!=NULL)
    {
        proto_tree_add_string(list_tree, hf_xmpp_gtalk_status_status_list, tvb, status->offset, status->length, status->data?status->data->value:"");
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
        {"xmlns", &hf_xmpp_xmlns, false, true, NULL, NULL}
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
    proto_tree *cand_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, false, false, NULL, NULL},
        {"name", NULL, false, true, NULL, NULL},
        {"generation", NULL, false, false, NULL, NULL},
        {"network", NULL, false, false, NULL, NULL},
        {"component", NULL, false, false, NULL, NULL},
        {"type", NULL, false, false, NULL, NULL},
        {"protocol", NULL, false, true, NULL, NULL},
        {"preference", NULL, false, false, NULL, NULL},
        {"password", NULL, false, false, NULL, NULL},
        {"username", NULL, false, false, NULL, NULL},
        {"port", NULL, false, true, NULL, NULL},
        {"address", NULL, false, true, NULL, NULL}
    };

    cand_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_gtalk_transport_p2p_cand, NULL, "CANDIDATE");

    xmpp_display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(cand_tree, element, pinfo, tvb, NULL, 0);

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
