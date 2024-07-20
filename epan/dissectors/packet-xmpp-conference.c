/* xmpp-conference.c
 * Wireshark's XMPP dissector.
 *
 * XEP-0298: Delivering Conference Information to Jingle Participants (Coin)
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
#include "packet-xmpp-conference.h"


static void xmpp_conf_desc(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_conf_state(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_conf_users(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_conf_user(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_conf_endpoint(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
static void xmpp_conf_media(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

void
xmpp_conferece_info_advert(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *cinfo_item;
    proto_tree *cinfo_tree;

    xmpp_attr_info attrs_info [] = {
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL},
        {"isfocus", NULL, true, true, NULL, NULL}
    };

    cinfo_item = proto_tree_add_item(tree, hf_xmpp_conf_info, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    cinfo_tree = proto_item_add_subtree(cinfo_item, ett_xmpp_conf_info);

    xmpp_display_attrs(cinfo_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(cinfo_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_conference_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_item *cinfo_item;
    proto_tree *cinfo_tree;

    static const char *state_enums[] = {"full", "partial", "deleted"};
    xmpp_array_t *state_array = xmpp_ep_init_array_t(pinfo->pool, state_enums, array_length(state_enums));

    xmpp_attr_info attrs_info [] = {
        {"xmlns", &hf_xmpp_xmlns, true, true, NULL, NULL},
        {"entity", NULL, true, true, NULL, NULL},
        {"state", NULL, false, true, xmpp_val_enum_list, state_array},
        {"version", NULL, false, true, NULL, NULL},
        {"sid", &hf_xmpp_conf_info_sid, false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "conference-description", xmpp_conf_desc, ONE},
        {NAME, "conference-state", xmpp_conf_state, ONE},
        /*{NAME, "host-info", xmpp_conf_host_info, ONE},*/
        {NAME, "users", xmpp_conf_users, ONE},
        /*{NAME, "sidebars-by-ref", xmpp_conf_sidebars_by_ref, ONE},*/
        /*{NAME, "sidebars-by-val", xmpp_conf_sidebars_by_val, ONE},*/
    };

    col_append_str(pinfo->cinfo, COL_INFO, "CONFERENC-INFO ");

    cinfo_item = proto_tree_add_item(tree, hf_xmpp_conf_info, tvb, element->offset, element->length,
        ENC_BIG_ENDIAN);
    cinfo_tree = proto_item_add_subtree(cinfo_item, ett_xmpp_conf_info);

    xmpp_display_attrs(cinfo_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(cinfo_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_conf_desc(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree *desc_tree;

    xmpp_attr_info attrs_info [] = {
        {"subject", NULL, false, true, NULL, NULL},
        {"display-text", NULL, false, false, NULL, NULL},
        {"free-text", NULL, false, false, NULL, NULL},
        {"max-user-count", NULL, false, false, NULL, NULL},
    };

/*
    xmpp_elem_info elems_info [] = {
        {NAME, "keywords", xmpp_conf_desc_keywords, ONE},
        {NAME, "conf-uris", xmpp_conf_desc_conf_uris, ONE},
        {NAME, "service-uris", xmpp_conf_desc_serv_uris, ONE},
        {NAME, "available-media", xmpp_conf_desc_avil_media, ONE},
    };
*/

    desc_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_conf_desc, NULL, "CONFERENCE DESCRIPTION");

    xmpp_change_elem_to_attrib(pinfo->pool, "subject", "subject", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "display-text", "display-text", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "free-text", "free-text", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "maximum-user-count", "max-user-count", element, xmpp_transform_func_cdata);

    xmpp_display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(desc_tree, element, pinfo, tvb, NULL,0);
}

static void
xmpp_conf_state(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree *state_tree;

    xmpp_attr_info attrs_info [] = {
        {"user-count", NULL, false, true, NULL, NULL},
        {"active", NULL, false, true, NULL, NULL},
        {"locked", NULL, false, true, NULL, NULL}
    };

    state_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length,
                                        ett_xmpp_conf_state, NULL, "CONFERENCE STATE");

    xmpp_change_elem_to_attrib(pinfo->pool, "user-count", "user-count", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "active", "active", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "locked", "locked", element, xmpp_transform_func_cdata);

    xmpp_display_attrs(state_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(state_tree, element, pinfo, tvb, NULL,0);

}

static void
xmpp_conf_users(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree *users_tree;

    xmpp_attr_info attrs_info [] = {
        {"state", NULL, false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        {NAME, "user", xmpp_conf_user, MANY}
    };

    users_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_conf_users, NULL, "USERS");

    xmpp_display_attrs(users_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(users_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}
static void
xmpp_conf_user(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree *user_tree;

    xmpp_attr_info attrs_info [] = {
        {"entity", NULL, false, true, NULL, NULL},
        {"state", NULL, false, true, NULL, NULL},
        {"display-text", NULL, false, true, NULL, NULL},
        {"cascaded-focus", NULL, false, true, NULL, NULL}
    };

    xmpp_elem_info elems_info [] = {
        /*{NAME, "associated-aors", xmpp_conf_assoc_aors, ONE},*/
        /*{NAME, "roles", xmpp_conf_roles, ONE},*/
        /*{NAME, "languages", xmpp_conf_langs, ONE},*/
        {NAME, "endpoint", xmpp_conf_endpoint, MANY},
    };

    user_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_conf_user, NULL, "USERS");

    xmpp_change_elem_to_attrib(pinfo->pool, "display-text", "display-text", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "cascaded-focus", "cascaded-focus", element, xmpp_transform_func_cdata);

    xmpp_display_attrs(user_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(user_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_conf_endpoint(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree *endpoint_tree;

    xmpp_attr_info attrs_info [] = {
        {"entity", NULL, false, true, NULL, NULL},
        {"state", NULL, false, true, NULL, NULL},
        {"display-text", NULL, false, true, NULL, NULL},
        {"status", NULL, false, true, NULL, NULL},
        {"joining-method", NULL, false, true, NULL, NULL},
        {"disconnection-method", NULL, false, true, NULL, NULL},
    };

    xmpp_elem_info elems_info [] = {
        /*{NAME,"referred",...,ONE},*/
        /*{NAME,"joining-info",...,ONE},*/
        /*{NAME,"disconnection-info",...,ONE},*/
        {NAME,"media", xmpp_conf_media, ONE},
        /*{NAME,"call-info",...,ONE},*/

    };

    endpoint_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_conf_endpoint, NULL, "ENDPOINT");

    xmpp_change_elem_to_attrib(pinfo->pool, "display-text", "display-text", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "status", "status", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "joining-method", "joining-method", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "disconnection-method", "disconnection-method", element, xmpp_transform_func_cdata);


    xmpp_display_attrs(endpoint_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(endpoint_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_conf_media(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    proto_tree *media_tree;

    xmpp_attr_info attrs_info[] = {
        {"id", NULL, true, true, NULL, NULL},
        {"display-text", NULL, false, true, NULL, NULL},
        {"type", NULL, false, true, NULL, NULL},
        {"label", NULL, false, true, NULL, NULL},
        {"src-id", NULL, false, true, NULL, NULL},
        {"status", NULL, false, true, NULL, NULL},
    };

    media_tree = proto_tree_add_subtree(tree, tvb, element->offset, element->length, ett_xmpp_conf_media, NULL, "MEDIA");

    xmpp_change_elem_to_attrib(pinfo->pool, "display-text", "display-text", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "type", "type", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "label", "label", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "src-id", "src-id", element, xmpp_transform_func_cdata);
    xmpp_change_elem_to_attrib(pinfo->pool, "status", "status", element, xmpp_transform_func_cdata);

    xmpp_display_attrs(media_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_display_elems(media_tree, element, pinfo, tvb, NULL, 0);
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
