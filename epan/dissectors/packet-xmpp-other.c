/* xmpp-other.c
 * Wireshark's XMPP dissector.
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
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

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/wmem/wmem.h>

#include <epan/dissectors/packet-xml.h>

#include <packet-xmpp-utils.h>
#include <packet-xmpp.h>
#include <packet-xmpp-other.h>

static void xmpp_disco_items_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element);

static void xmpp_roster_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element);

static void xmpp_disco_info_identity(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element);
static void xmpp_disco_info_feature(proto_tree *tree, tvbuff_t *tvb, xmpp_element_t *element);

static void xmpp_bytestreams_streamhost(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_bytestreams_streamhost_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_bytestreams_activate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_bytestreams_udpsuccess(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

static void xmpp_si_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_si_file_range(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);

static void xmpp_x_data_field(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_x_data_field_option(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_x_data_field_value(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
static void xmpp_x_data_instr(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);

static void xmpp_muc_history(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

static void xmpp_muc_user_item(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_muc_user_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_muc_user_invite(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

static void xmpp_hashes_hash(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

static void xmpp_jitsi_inputevt_rmt_ctrl(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

void
xmpp_iq_bind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *bind_item;
    proto_tree *bind_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"resource", &hf_xmpp_iq_bind_resource, FALSE, TRUE, NULL, NULL},
        {"jid", &hf_xmpp_iq_bind_jid, FALSE, TRUE, NULL, NULL}
    };

    col_append_str(pinfo->cinfo, COL_INFO, "BIND ");

    bind_item = proto_tree_add_item(tree, hf_xmpp_iq_bind, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    bind_tree = proto_item_add_subtree(bind_item, ett_xmpp_iq_bind);

    xmpp_change_elem_to_attrib("resource", "resource", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib("jid", "jid", element, xmpp_transform_func_cdata);

    xmpp_display_attrs(bind_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(bind_tree, tvb, pinfo, element);
}

void
xmpp_session(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *session_item;
    proto_tree *session_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    session_item = proto_tree_add_item(tree, hf_xmpp_iq_session, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    session_tree = proto_item_add_subtree(session_item, ett_xmpp_iq_session);

    col_append_str(pinfo->cinfo, COL_INFO, "SESSION ");

    xmpp_display_attrs(session_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(session_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_vcard(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *vcard_item;
    proto_tree *vcard_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"value", NULL, FALSE, FALSE, NULL, NULL}
    };

    xmpp_element_t *cdata;

    col_append_str(pinfo->cinfo, COL_INFO, "VCARD ");

    vcard_item = proto_tree_add_item(tree, hf_xmpp_vcard, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    vcard_tree = proto_item_add_subtree(vcard_item, ett_xmpp_vcard);

    cdata = xmpp_get_first_element(element);

    if(cdata)
    {
        xmpp_attr_t *fake_cdata;
        fake_cdata = xmpp_ep_init_attr_t(xmpp_element_to_string(tvb, cdata), cdata->offset, cdata->length);
        g_hash_table_insert(element->attrs,(gpointer)"value", fake_cdata);

    }
    xmpp_display_attrs(vcard_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

}

void
xmpp_vcard_x_update(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"photo", NULL, FALSE, FALSE, NULL, NULL}
    };

    xmpp_element_t *photo;

    x_item = proto_tree_add_item(tree, hf_xmpp_vcard_x_update, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_vcard_x_update);

    if((photo = xmpp_steal_element_by_name(element, "photo"))!=NULL)
    {
        xmpp_attr_t *fake_photo = xmpp_ep_init_attr_t(photo->data?photo->data->value:"", photo->offset, photo->length);
        g_hash_table_insert(element->attrs, (gpointer)"photo", fake_photo);
    }

    xmpp_display_attrs(x_tree, element,pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

void
xmpp_disco_items_query(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"node", &hf_xmpp_query_node, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *item;

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(disco#items) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((item = xmpp_steal_element_by_name(element, "item")) != NULL)
    {
        xmpp_disco_items_item(query_tree, tvb, pinfo, item);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_disco_items_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    xmpp_attr_info attrs_info[] = {
        {"jid", &hf_xmpp_query_item_jid, TRUE, TRUE, NULL, NULL},
        {"name", &hf_xmpp_query_item_name, FALSE, TRUE, NULL, NULL},
        {"node", &hf_xmpp_query_item_node, FALSE, TRUE, NULL, NULL}
    };

    item_item = proto_tree_add_item(tree, hf_xmpp_query_item, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_query_item);

    xmpp_display_attrs(item_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(item_tree, tvb, pinfo, element);
}

void
xmpp_roster_query(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"ver", NULL, FALSE, TRUE, NULL, NULL},
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "item", xmpp_roster_item, MANY},
    };

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(jabber:iq:roster) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_roster_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    static const gchar *ask_enums[] = {"subscribe"};
    static const gchar *subscription_enums[] = {"both", "from", "none", "remove", "to"};

    xmpp_array_t *ask_enums_array = xmpp_ep_init_array_t(ask_enums,array_length(ask_enums));
    xmpp_array_t *subscription_array = xmpp_ep_init_array_t(subscription_enums,array_length(subscription_enums));

    xmpp_attr_info attrs_info[] = {
        {"jid", &hf_xmpp_query_item_jid, TRUE, TRUE, NULL, NULL},
        {"name", &hf_xmpp_query_item_name, FALSE, TRUE, NULL, NULL},
        {"ask", &hf_xmpp_query_item_ask, FALSE, TRUE, xmpp_val_enum_list, ask_enums_array},
        {"approved", &hf_xmpp_query_item_approved, FALSE, TRUE, NULL, NULL},
        {"subscription", &hf_xmpp_query_item_subscription, FALSE, TRUE, xmpp_val_enum_list, subscription_array},
    };

    xmpp_element_t *group;

    item_item = proto_tree_add_item(tree, hf_xmpp_query_item, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_query_item);

    xmpp_display_attrs(item_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((group = xmpp_steal_element_by_name(element,"group"))!=NULL)
    {
        proto_tree_add_string(item_tree, hf_xmpp_query_item_group, tvb, group->offset, group->length, xmpp_elem_cdata(group));
    }

    xmpp_unknown(item_tree, tvb, pinfo, element);
}

void
xmpp_disco_info_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"node", &hf_xmpp_query_node, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *identity, *feature, *x_data;

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(disco#info) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));


    while((identity = xmpp_steal_element_by_name(element, "identity")) != NULL)
    {
        xmpp_disco_info_identity(query_tree, tvb, pinfo, identity);
    }

    while((feature = xmpp_steal_element_by_name(element, "feature")) != NULL)
    {
        xmpp_disco_info_feature(query_tree, tvb, feature);
    }

    if((x_data = xmpp_steal_element_by_name_and_attr(element, "x", "xmlns", "jabber:x:data")) != NULL)
    {
        xmpp_x_data(query_tree, tvb, pinfo, x_data);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_disco_info_identity(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element)
{
    proto_item *identity_item;
    proto_tree *identity_tree;

    xmpp_attr_info attrs_info[] = {
        {"category", &hf_xmpp_query_identity_category, TRUE, TRUE, NULL, NULL},
        {"name", &hf_xmpp_query_identity_name, FALSE, TRUE, NULL, NULL},
        {"type", &hf_xmpp_query_identity_type, TRUE, TRUE, NULL, NULL}
    };

    identity_item = proto_tree_add_item(tree, hf_xmpp_query_identity, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    identity_tree = proto_item_add_subtree(identity_item, ett_xmpp_query_identity);

    xmpp_display_attrs(identity_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(identity_tree, tvb, pinfo, element);

}

static void
xmpp_disco_info_feature(proto_tree *tree, tvbuff_t *tvb, xmpp_element_t *element)
{

    xmpp_attr_t *var = xmpp_get_attr(element, "var");

    if(var)
    {
        proto_tree_add_string_format(tree, hf_xmpp_query_feature, tvb, var->offset, var->length, var->value, "FEATURE [%s]", var->value);
    }
}

void
xmpp_bytestreams_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    static const gchar *mode_enums[] = {"tcp", "udp"};
    xmpp_array_t *mode_array = xmpp_ep_init_array_t(mode_enums, array_length(mode_enums));

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"sid", NULL, FALSE, TRUE, NULL, NULL},
        {"mode", NULL, FALSE, TRUE, xmpp_val_enum_list, mode_array},
        {"dstaddr", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *streamhost, *streamhost_used, *activate, *udpsuccess;

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(bytestreams) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));


    while((streamhost = xmpp_steal_element_by_name(element, "streamhost")) != NULL)
    {
        xmpp_bytestreams_streamhost(query_tree, tvb, pinfo, streamhost);
    }

    if((streamhost_used = xmpp_steal_element_by_name(element, "streamhost-used")) != NULL)
    {
        xmpp_bytestreams_streamhost_used(query_tree, tvb, pinfo, streamhost_used);
    }

    if((activate = xmpp_steal_element_by_name(element, "activate")) != NULL)
    {
        xmpp_bytestreams_activate(query_tree, tvb, pinfo, activate);
    }

    if((udpsuccess = xmpp_steal_element_by_name(element, "udpsuccess")) != NULL)
    {
        xmpp_bytestreams_udpsuccess(query_tree, tvb, pinfo, udpsuccess);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_streamhost(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *sh_item;
    proto_tree *sh_tree;

    xmpp_attr_info attrs_info[] = {
        {"jid", NULL, TRUE, TRUE, NULL, NULL},
        {"host", NULL, TRUE, TRUE, NULL, NULL},
        {"port", NULL, FALSE, TRUE, NULL, NULL}
    };

    sh_item = proto_tree_add_item(tree, hf_xmpp_query_streamhost, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    sh_tree = proto_item_add_subtree(sh_item, ett_xmpp_query_streamhost);

    xmpp_display_attrs(sh_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(sh_tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_streamhost_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *shu_item;
    proto_tree *shu_tree;

    xmpp_attr_info attrs_info[] = {
        {"jid", NULL, TRUE, TRUE, NULL, NULL}
    };

    shu_item = proto_tree_add_item(tree, hf_xmpp_query_streamhost_used, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    shu_tree = proto_item_add_subtree(shu_item, ett_xmpp_query_streamhost_used);

    xmpp_display_attrs(shu_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(shu_tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_activate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree_add_string(tree, hf_xmpp_query_activate, tvb, element->offset, element->length, xmpp_elem_cdata(element));
    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_udpsuccess(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *udps_item;
    proto_tree *udps_tree;

    xmpp_attr_info attrs_info[] = {
        {"dstaddr", NULL, TRUE, TRUE, NULL, NULL}
    };

    udps_item = proto_tree_add_item(tree, hf_xmpp_query_udpsuccess, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    udps_tree =proto_item_add_subtree(udps_item, ett_xmpp_query_udpsuccess);

    xmpp_display_attrs(udps_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(udps_tree, tvb, pinfo, element);
}



/*SI File Transfer*/
void
xmpp_si(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *si_item;
    proto_tree *si_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"id", NULL, FALSE, FALSE, NULL, NULL},
        {"mime-type", NULL, FALSE, TRUE, NULL, NULL},
        {"profile", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *file, *feature_neg;

    col_append_str(pinfo->cinfo, COL_INFO, "SI ");

    si_item = proto_tree_add_item(tree, hf_xmpp_si, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    si_tree = proto_item_add_subtree(si_item, ett_xmpp_si);

    xmpp_display_attrs(si_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((file = xmpp_steal_element_by_name(element, "file"))!=NULL)
    {
        xmpp_si_file(si_tree, tvb, pinfo, file);
    }

    while((feature_neg = xmpp_steal_element_by_name(element, "feature"))!=NULL)
    {
        xmpp_feature_neg(si_tree, tvb, pinfo, feature_neg);
    }



    xmpp_unknown(si_tree, tvb, pinfo, element);
}

static void
xmpp_si_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *file_item;
    proto_tree *file_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"name", NULL, TRUE, TRUE, NULL, NULL},
        {"size", NULL, TRUE, TRUE, NULL, NULL},
        {"date", NULL, FALSE, FALSE, NULL, NULL},
        {"hash", NULL, FALSE, FALSE, NULL, NULL},
        {"desc", NULL, FALSE, FALSE, NULL, NULL}
    };

    xmpp_element_t *desc, *range;

    file_item = proto_tree_add_item(tree, hf_xmpp_si_file, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    file_tree = proto_item_add_subtree(file_item, ett_xmpp_si_file);

    if((desc = xmpp_steal_element_by_name(element, "desc"))!=NULL)
    {
         xmpp_attr_t *fake_desc = xmpp_ep_init_attr_t(desc->data?desc->data->value:"", desc->offset, desc->length);
         g_hash_table_insert(element->attrs, (gpointer)"desc", fake_desc);
    }

    if((range = xmpp_steal_element_by_name(element, "range"))!=NULL)
    {
        xmpp_si_file_range(file_tree, tvb, pinfo, range);
    }

    xmpp_display_attrs(file_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(file_tree, tvb, pinfo, element);
}

static void
xmpp_si_file_range(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *range_item;
    proto_tree *range_tree;

    xmpp_attr_info attrs_info[] = {
        {"offset", NULL, FALSE, TRUE, NULL, NULL},
        {"length", NULL, FALSE, TRUE, NULL, NULL}
    };

    range_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "RANGE: ");
    range_tree = proto_item_add_subtree(range_item, ett_xmpp_si_file_range);

    xmpp_display_attrs(range_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(range_tree, tvb, pinfo, element);

}

/*Feature Negotiation*/
void
xmpp_feature_neg(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *feature_item;
    proto_tree *feature_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    xmpp_element_t *x_data;

    feature_item = proto_tree_add_item(tree, hf_xmpp_iq_feature_neg, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    feature_tree = proto_item_add_subtree(feature_item, ett_xmpp_iq_feature_neg);

    xmpp_display_attrs(feature_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((x_data = xmpp_steal_element_by_name_and_attr(element, "x", "xmlns", "jabber:x:data"))!=NULL)
    {
        xmpp_x_data(feature_tree, tvb, pinfo, x_data);
    }

    xmpp_unknown(feature_tree, tvb, pinfo, element);
}


/*jabber:x:data*/
void
xmpp_x_data(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    static const gchar *type_enums[] = {"cancel", "form", "result", "submit"};
    xmpp_array_t *type_array = xmpp_ep_init_array_t(type_enums, array_length(type_enums));

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"type", NULL, TRUE, TRUE, xmpp_val_enum_list, type_array},
        {"TITLE", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "instructions", xmpp_x_data_instr, MANY},
        {NAME, "field", xmpp_x_data_field, MANY},
    };
    /*TODO reported, item*/

    x_item = proto_tree_add_item(tree, hf_xmpp_x_data, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_x_data);

    xmpp_change_elem_to_attrib("title", "TITLE", element, xmpp_transform_func_cdata);

    xmpp_display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(x_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_x_data_field(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *field_item;
    proto_tree *field_tree;

    static const gchar *type_enums[] = {"boolean", "fixed", "hidden", "jid-multi",
        "jid-single", "list-multi", "list-single", "text-multi", "text-single",
        "text-private"
    };
    xmpp_array_t *type_array = xmpp_ep_init_array_t(type_enums, array_length(type_enums));

    xmpp_attr_info attrs_info[] = {
        {"label", NULL, FALSE, TRUE, NULL, NULL},
        {"type", NULL, FALSE, TRUE, xmpp_val_enum_list, type_array},
        {"var", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t /**desc, *required,*/ *value, *option;

    field_item = proto_tree_add_item(tree, hf_xmpp_x_data_field, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    field_tree = proto_item_add_subtree(field_item, ett_xmpp_x_data_field);

    xmpp_display_attrs(field_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((option = xmpp_steal_element_by_name(element, "option"))!=NULL)
    {
        xmpp_x_data_field_option(field_tree, tvb, pinfo, option);
    }

    while((value = xmpp_steal_element_by_name(element, "value"))!=NULL)
    {
        xmpp_x_data_field_value(field_tree, tvb, pinfo, value);
    }

    xmpp_unknown(field_item, tvb, pinfo, element);

}

static void
xmpp_x_data_field_option(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *option_item;
    proto_tree *option_tree;

    xmpp_attr_info attrs_info[] = {
        {"label", NULL, FALSE, TRUE, NULL, NULL},
        {"value", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *value;

    option_item = proto_tree_add_item(tree, hf_xmpp_x_data_field_value, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    option_tree = proto_item_add_subtree(option_item, ett_xmpp_x_data_field_value);

    if((value = xmpp_steal_element_by_name(element, "value"))!=NULL)
    {
        xmpp_attr_t *fake_value = xmpp_ep_init_attr_t(value->data?value->data->value:"",value->offset, value->length);
        g_hash_table_insert(element->attrs, (gpointer)"value", fake_value);
    }

    xmpp_display_attrs(option_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(option_tree, tvb, pinfo, element);
}

static void
xmpp_x_data_field_value(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element)
{
    proto_item *value_item;
    proto_tree *value_tree;

    xmpp_attr_info attrs_info[] = {
        {"label", NULL, FALSE, TRUE, NULL, NULL},
        {"value", NULL, TRUE, TRUE, NULL, NULL}
    };
    xmpp_attr_t *fake_value;

    value_item = proto_tree_add_item(tree, hf_xmpp_x_data_field_value, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    value_tree = proto_item_add_subtree(value_item, ett_xmpp_x_data_field_value);



   fake_value = xmpp_ep_init_attr_t(element->data?element->data->value:"",element->offset, element->length);
   g_hash_table_insert(element->attrs, (gpointer)"value", fake_value);


    xmpp_display_attrs(value_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(value_tree, tvb, pinfo, element);
}

static void
xmpp_x_data_instr(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo _U_, xmpp_element_t* element)
{
    proto_tree_add_text(tree, tvb, element->offset, element->length, "INSTRUCTIONS: %s",xmpp_elem_cdata(element));
}

/*In-Band Bytestreams*/
void
xmpp_ibb_open(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *open_item;
    proto_tree *open_tree;

    static const gchar *stanza_enums[] = {"iq", "message"};
    xmpp_array_t *stanza_array = xmpp_ep_init_array_t(stanza_enums, array_length(stanza_enums));

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"sid", NULL, TRUE, TRUE, NULL, NULL},
        {"block-size", NULL, TRUE, TRUE, NULL, NULL},
        {"stanza", NULL, FALSE, TRUE, xmpp_val_enum_list, stanza_array}
    };

    col_append_str(pinfo->cinfo, COL_INFO, "IBB-OPEN ");

    open_item = proto_tree_add_item(tree, hf_xmpp_ibb_open, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    open_tree = proto_item_add_subtree(open_item, ett_xmpp_ibb_open);

    xmpp_display_attrs(open_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(open_tree, tvb, pinfo, element);
}

void
xmpp_ibb_close(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *close_item;
    proto_tree *close_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"sid", NULL, TRUE, TRUE, NULL, NULL}
    };

    col_append_str(pinfo->cinfo, COL_INFO, "IBB-CLOSE ");

    close_item = proto_tree_add_item(tree, hf_xmpp_ibb_close, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    close_tree = proto_item_add_subtree(close_item, ett_xmpp_ibb_close);

    xmpp_display_attrs(close_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(close_tree, tvb, pinfo, element);
}

void
xmpp_ibb_data(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *data_item;
    proto_tree *data_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"sid", NULL, TRUE, TRUE, NULL, NULL},
        {"seq", NULL, TRUE, TRUE, NULL, NULL},
        {"value", NULL, FALSE, FALSE, NULL, NULL}
    };

    col_append_str(pinfo->cinfo, COL_INFO, "IBB-DATA ");

    data_item = proto_tree_add_item(tree, hf_xmpp_ibb_data, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    data_tree = proto_item_add_subtree(data_item, ett_xmpp_ibb_data);

    if(element->data)
    {
        xmpp_attr_t *fake_data = xmpp_ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, (gpointer)"value", fake_data);
    }

    xmpp_display_attrs(data_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(data_tree, tvb, pinfo, element);
}


/*Delayed Delivery urn:xmpp:delay and jabber:x:delay*/
void
xmpp_delay(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *delay_item;
    proto_tree *delay_tree;

    xmpp_attr_info attrs_info[]={
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"from", NULL, FALSE, TRUE, NULL, NULL},
        {"stamp", NULL, TRUE, TRUE, NULL, NULL},
        {"value", NULL, FALSE, TRUE, NULL, NULL}
    };

    delay_item = proto_tree_add_item(tree, hf_xmpp_delay, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    delay_tree = proto_item_add_subtree(delay_item, ett_xmpp_delay);

    if(element->data)
    {
        xmpp_attr_t *fake_value = xmpp_ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, (gpointer)"value", fake_value);
    }

    xmpp_display_attrs(delay_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(delay_tree, tvb, pinfo, element);
}

/*Entity Capabilities http://jabber.org/protocol/caps*/
void
xmpp_presence_caps(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *caps_item;
    proto_tree *caps_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"ext", NULL, FALSE, FALSE, NULL, NULL},
        {"hash", NULL, TRUE, TRUE, NULL, NULL},
        {"node", NULL, TRUE, TRUE, NULL, NULL},
        {"ver", NULL, TRUE, FALSE, NULL, NULL}
    };

    caps_item = proto_tree_add_item(tree, hf_xmpp_presence_caps, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    caps_tree = proto_item_add_subtree(caps_item, ett_xmpp_presence_caps);

    xmpp_display_attrs(caps_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(caps_tree, tvb, pinfo, element);
}

/*Message Events jabber:x:event*/
void
xmpp_x_event(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"condition", &hf_xmpp_x_event_condition, TRUE, TRUE, NULL, NULL},
        {"id", NULL, FALSE, TRUE, NULL, NULL}
    };

    static const gchar *cond_names[] = {"offline", "delivered", "displayed", "composing"};

    xmpp_attr_t *fake_cond;

    xmpp_element_t *cond, *id;

    gchar *cond_value = wmem_strdup(wmem_packet_scope(), "");

    x_item =  proto_tree_add_item(tree, hf_xmpp_x_event, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_x_event);

    if((id = xmpp_steal_element_by_name(element, "id"))!=NULL)
    {
        xmpp_attr_t *fake_id = xmpp_ep_init_attr_t(id->data?id->data->value:"", id->offset, id->length);
        g_hash_table_insert(element->attrs, (gpointer)"id", fake_id);
    }

    while((cond = xmpp_steal_element_by_names(element, cond_names, array_length(cond_names))) != NULL)
    {
        if(strcmp(cond_value,"") != 0)
            cond_value = wmem_strdup_printf(wmem_packet_scope(), "%s/%s",cond_value, cond->name);
        else
            cond_value = wmem_strdup(wmem_packet_scope(), cond->name);
    }

    fake_cond = xmpp_ep_init_attr_t(cond_value, element->offset, element->length);
    g_hash_table_insert(element->attrs, (gpointer)"condition", fake_cond);


    xmpp_display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

/*Multi-User Chat http://jabber.org/protocol/muc*/
void
xmpp_muc_x(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    xmpp_attr_info attrs_info [] ={
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"password", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *pass, *hist;

    x_item = proto_tree_add_item(tree, hf_xmpp_muc_x, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_muc_x);

    if((pass = xmpp_steal_element_by_name(element, "password"))!=NULL)
    {
        xmpp_attr_t *fake_pass = xmpp_ep_init_attr_t(pass->data?pass->data->value:"",pass->offset, pass->length);
        g_hash_table_insert(element->attrs, (gpointer)"password", fake_pass);
    }

    xmpp_display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    if((hist = xmpp_steal_element_by_name(element, "history"))!=NULL)
    {
        xmpp_muc_history(x_tree, tvb, pinfo, hist);
    }

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

static void
xmpp_muc_history(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *hist_item;
    proto_tree *hist_tree;

    xmpp_attr_info attrs_info[] = {
        {"maxchars", NULL, FALSE, TRUE, NULL, NULL},
        {"maxstanzas", NULL, FALSE, TRUE, NULL, NULL},
        {"seconds", NULL, FALSE, TRUE, NULL, NULL},
        {"since", NULL, FALSE, TRUE, NULL, NULL}
    };

    hist_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "HISTORY: ");
    hist_tree = proto_item_add_subtree(hist_item, ett_xmpp_muc_hist);

    xmpp_display_attrs(hist_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(hist_tree, tvb, pinfo, element);
}

/*Multi-User Chat http://jabber.org/protocol/muc#user*/
void
xmpp_muc_user_x(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"password", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *item, *status, *invite, *password;
    /*TODO decline destroy*/

    x_item = proto_tree_add_item(tree, hf_xmpp_muc_user_x, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_muc_user_x);

    if((password = xmpp_steal_element_by_name(element, "password"))!=NULL)
    {
        xmpp_attr_t *fake_pass = xmpp_ep_init_attr_t(password->data?password->data->value:"",password->offset, password->length);
        g_hash_table_insert(element->attrs, (gpointer)"password", fake_pass);
    }

    xmpp_display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((item = xmpp_steal_element_by_name(element, "item"))!=NULL)
    {
        xmpp_muc_user_item(x_tree, tvb, pinfo, item);
    }

    while((status = xmpp_steal_element_by_name(element, "status"))!=NULL)
    {
        xmpp_muc_user_status(x_tree, tvb, pinfo, status);
    }

    while((invite = xmpp_steal_element_by_name(element, "invite"))!=NULL)
    {
        xmpp_muc_user_invite(x_tree, tvb, pinfo, invite);
    }

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

static void
xmpp_muc_user_item(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    static const gchar *affiliation_enums[] = {"admin", "member", "none", "outcast", "owner"};
    xmpp_array_t  *affil_array = xmpp_ep_init_array_t(affiliation_enums, array_length(affiliation_enums));

    static const gchar *role_enums[] = {"none", "moderator", "participant", "visitor"};
    xmpp_array_t *role_array = xmpp_ep_init_array_t(role_enums, array_length(role_enums));

    xmpp_attr_info attrs_info [] ={
        {"affiliation", NULL, FALSE, TRUE, xmpp_val_enum_list, affil_array},
        {"jid", NULL, FALSE, TRUE, NULL, NULL},
        {"nick", NULL, FALSE, TRUE, NULL, NULL},
        {"role", NULL, FALSE, TRUE, xmpp_val_enum_list, role_array},
        {"reason", NULL, FALSE, TRUE, NULL, NULL},
        {"actor_jid", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *reason, *actor;
    /*TODO continue - it's not clear to me, in schema it's marked as empty, but in examples it has CDATA*/

    item_item = proto_tree_add_item(tree, hf_xmpp_muc_user_item, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_muc_user_item);

    if((reason = xmpp_steal_element_by_name(element, "reason"))!=NULL)
    {
        xmpp_attr_t *fake_reason = xmpp_ep_init_attr_t(reason->data?reason->data->value:"",reason->offset, reason->length);
        g_hash_table_insert(element->attrs,(gpointer)"reason",fake_reason);
    }

    if((actor = xmpp_steal_element_by_name(element, "actor"))!=NULL)
    {
        xmpp_attr_t *jid = xmpp_get_attr(actor, "jid");
        xmpp_attr_t *fake_actor_jid = xmpp_ep_init_attr_t(jid?jid->value:"",actor->offset, actor->length);
        g_hash_table_insert(element->attrs, (gpointer)"actor_jid", fake_actor_jid);
    }

    xmpp_display_attrs(item_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(item_tree, tvb, pinfo, element);
}

static void
xmpp_muc_user_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    xmpp_attr_t *code = xmpp_get_attr(element, "code");
    proto_tree_add_text(tree, tvb, element->offset, element->length, "STATUS [code=\"%s\"]",code?code->value:"");

    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_muc_user_invite(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *invite_item;
    proto_tree *invite_tree;

    xmpp_attr_info attrs_info[] = {
        {"from", NULL, FALSE, TRUE, NULL, NULL},
        {"to", NULL, FALSE, TRUE, NULL, NULL},
        {"reason", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *reason;

    invite_item = proto_tree_add_item(tree, hf_xmpp_muc_user_invite, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    invite_tree = proto_item_add_subtree(invite_item, ett_xmpp_muc_user_invite);

    if((reason = xmpp_steal_element_by_name(element, "reason"))!=NULL)
    {
        xmpp_attr_t *fake_reason = xmpp_ep_init_attr_t(reason->data?reason->data->value:"",reason->offset, reason->length);
        g_hash_table_insert(element->attrs, (gpointer)"reason", fake_reason);
    }

    xmpp_display_attrs(invite_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(invite_tree, tvb, pinfo, element);
}

/*Multi-User Chat http://jabber.org/protocol/muc#owner*/
void
xmpp_muc_owner_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    xmpp_element_t *x_data;
    /*TODO destroy*/

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(muc#owner) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    if((x_data = xmpp_steal_element_by_name_and_attr(element, "x", "xmlns", "jabber:x:data"))!=NULL)
    {
        xmpp_x_data(query_tree, tvb, pinfo, x_data);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);

}

/*Multi-User Chat http://jabber.org/protocol/muc#admin*/
void
xmpp_muc_admin_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    xmpp_element_t *item;

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(muc#admin) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((item = xmpp_steal_element_by_name(element, "item"))!=NULL)
    {
        /*from muc#user, because it is the same except continue element*/
        xmpp_muc_user_item(query_tree, tvb, pinfo, item);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

/*Last Activity jabber:iq:last*/
void
xmpp_last_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"seconds", NULL, FALSE, TRUE, NULL, NULL},
        {"value", NULL, FALSE, TRUE, NULL, NULL}
    };

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(jabber:iq:last) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    if(element->data)
    {
        xmpp_attr_t *fake_data = xmpp_ep_init_attr_t(element->data->value, element->data->offset, element->data->length);
        g_hash_table_insert(element->attrs, (gpointer)"value", fake_data);
    }

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, NULL, 0);
}

/*XEP-0092: Software Version jabber:iq:version*/
void
xmpp_version_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"name", NULL, FALSE, TRUE, NULL, NULL},
        {"version", NULL, FALSE, TRUE, NULL, NULL},
        {"os", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_element_t *name, *version, *os;

    col_append_str(pinfo->cinfo, COL_INFO, "QUERY(jabber:iq:version) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    if((name = xmpp_steal_element_by_name(element,"name"))!=NULL)
    {
        xmpp_attr_t *fake_name = xmpp_ep_init_attr_t(name->data?name->data->value:"", name->offset, name->length);
        g_hash_table_insert(element->attrs, (gpointer)"name", fake_name);
    }

    if((version = xmpp_steal_element_by_name(element,"version"))!=NULL)
    {
        xmpp_attr_t *fake_version = xmpp_ep_init_attr_t(version->data?version->data->value:"", version->offset, version->length);
        g_hash_table_insert(element->attrs, (gpointer)"version", fake_version);
    }

    if((os = xmpp_steal_element_by_name(element,"os"))!=NULL)
    {
        xmpp_attr_t *fake_os = xmpp_ep_init_attr_t(os->data?os->data->value:"", os->offset, os->length);
        g_hash_table_insert(element->attrs, (gpointer)"os", fake_os);
    }

    xmpp_display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(query_tree, element, pinfo, tvb, NULL, 0);
}
/*XEP-0199: XMPP Ping*/
void
xmpp_ping(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *ping_item;
    proto_tree *ping_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
    };

    col_append_str(pinfo->cinfo, COL_INFO, "PING ");

    ping_item = proto_tree_add_item(tree, hf_xmpp_ping, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    ping_tree = proto_item_add_subtree(ping_item, ett_xmpp_ping);

    xmpp_display_attrs(ping_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(ping_tree, element, pinfo, tvb, NULL, 0);
}

/*XEP-0300: Use of Cryptographic Hash Functions in XMPP urn:xmpp:hashes:0*/
void
xmpp_hashes(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element) {
    proto_item *hashes_item;
    proto_tree *hashes_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
    };
    xmpp_elem_info elems_info[] = {
        {NAME, "hash", xmpp_hashes_hash, MANY}
    };

    hashes_item = proto_tree_add_item(tree, hf_xmpp_hashes, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    hashes_tree = proto_item_add_subtree(hashes_item, ett_xmpp_hashes);

    xmpp_display_attrs(hashes_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(hashes_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_hashes_hash(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *hash_item;
    proto_tree *hash_tree;

    xmpp_attr_info attrs_info[] = {
        {"algo", NULL, TRUE, TRUE, NULL, NULL},
        {"value", NULL, TRUE, TRUE, NULL, NULL}
    };

    xmpp_attr_t *fake_cdata = xmpp_ep_init_attr_t(xmpp_elem_cdata(element), element->offset, element->length);
    g_hash_table_insert(element->attrs, (gpointer)"value", fake_cdata);

    hash_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "HASH");
    hash_tree = proto_item_add_subtree(hash_item, ett_xmpp_hashes_hash);

    xmpp_display_attrs(hash_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(hash_tree, element, pinfo, tvb, NULL, 0);
}

/*http://jitsi.org/protocol/inputevt*/
void
xmpp_jitsi_inputevt(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *inputevt_item;
    proto_tree *inputevt_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"action", NULL, FALSE, TRUE, NULL, NULL}
    };

    xmpp_elem_info elems_info[] = {
        {NAME, "remote-control", xmpp_jitsi_inputevt_rmt_ctrl, MANY}
    };

    inputevt_item = proto_tree_add_item(tree, hf_xmpp_jitsi_inputevt, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    inputevt_tree = proto_item_add_subtree(inputevt_item, ett_xmpp_jitsi_inputevt);

    xmpp_display_attrs(inputevt_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(inputevt_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jitsi_inputevt_rmt_ctrl(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *rmt_ctrl_item;
    proto_tree *rmt_ctrl_tree;

    xmpp_attr_info attrs_info[] = {
        {"xmlns", &hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"action", NULL, TRUE, TRUE, NULL, NULL},
        {"x", NULL, FALSE, TRUE, NULL, NULL},
        {"y", NULL, FALSE, TRUE, NULL, NULL},
        {"btns", NULL, FALSE, TRUE, NULL, NULL},
        {"keycode", NULL, FALSE, TRUE, NULL, NULL},
    };

    xmpp_element_t *action;
    static const gchar *action_names[] = {"mouse-move", "mouse-press", "mouse-release", "key-press", "key-release"};

    if((action = xmpp_steal_element_by_names(element, action_names, array_length(action_names)))!=NULL)
    {
        xmpp_attr_t *fake_action = xmpp_ep_init_attr_t(action->name, action->offset, action->length);
        g_hash_table_insert(element->attrs,(gpointer)"action", fake_action);

        if(strcmp(action->name,"mouse-move") == 0)
        {
            xmpp_attr_t *x = xmpp_get_attr(action,"x");
            xmpp_attr_t *y = xmpp_get_attr(action,"y");

            if(x)
                g_hash_table_insert(element->attrs,(gpointer)"x",x);
            if(y)
                g_hash_table_insert(element->attrs,(gpointer)"y",y);
        } else if(strcmp(action->name,"mouse-press") == 0 || strcmp(action->name,"mouse-release") == 0)
        {
            xmpp_attr_t *btns = xmpp_get_attr(action,"btns");

            if(btns)
                g_hash_table_insert(element->attrs,(gpointer)"btns",btns);
        } else if(strcmp(action->name,"key-press") == 0 || strcmp(action->name,"key-release") == 0)
        {
            xmpp_attr_t *keycode = xmpp_get_attr(action,"keycode");

            if(keycode)
                g_hash_table_insert(element->attrs,(gpointer)"keycode",keycode);
        }

    }

    rmt_ctrl_item = proto_tree_add_item(tree, hf_xmpp_jitsi_inputevt_rmt_ctrl, tvb, element->offset, element->length, ENC_BIG_ENDIAN);
    rmt_ctrl_tree = proto_item_add_subtree(rmt_ctrl_item, ett_xmpp_jitsi_inputevt_rmt_ctrl);

    xmpp_display_attrs(rmt_ctrl_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(rmt_ctrl_tree, element, pinfo, tvb, NULL, 0);
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
