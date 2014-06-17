/* xmpp-utils.c
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tvbparse.h>
#include <epan/strutil.h>

#include <epan/dissectors/packet-xml.h>

#include <packet-xmpp.h>
#include <packet-xmpp-core.h>
#include <packet-xmpp-utils.h>


void
xmpp_iq_reqresp_track(packet_info *pinfo, xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    xmpp_transaction_t *xmpp_trans = NULL;

    xmpp_attr_t *attr_id;
    char *id;

    attr_id = xmpp_get_attr(packet, "id");

    if (!attr_id) {
        return;
    }

    id = wmem_strdup(wmem_packet_scope(), attr_id->value);

    if (!pinfo->fd->flags.visited) {
        xmpp_trans = (xmpp_transaction_t *)wmem_tree_lookup_string(xmpp_info->req_resp, id, WMEM_TREE_STRING_NOCASE);
        if (xmpp_trans) {
            xmpp_trans->resp_frame = pinfo->fd->num;

        } else {
            char *se_id = wmem_strdup(wmem_file_scope(), id);

            xmpp_trans = wmem_new(wmem_file_scope(), xmpp_transaction_t);
            xmpp_trans->req_frame = pinfo->fd->num;
            xmpp_trans->resp_frame = 0;

            wmem_tree_insert_string(xmpp_info->req_resp, se_id, (void *) xmpp_trans, WMEM_TREE_STRING_NOCASE);

        }

    } else {
        wmem_tree_lookup_string(xmpp_info->req_resp, id, WMEM_TREE_STRING_NOCASE);
    }
}

void
xmpp_jingle_session_track(packet_info *pinfo, xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    xmpp_element_t *jingle_packet;
    GList *jingle_packet_l;

    jingle_packet_l = xmpp_find_element_by_name(packet,"jingle");
    jingle_packet = (xmpp_element_t *)(jingle_packet_l?jingle_packet_l->data:NULL);

    if (jingle_packet && !pinfo->fd->flags.visited) {
        xmpp_attr_t *attr_id;
        xmpp_attr_t *attr_sid;

        char *se_id;
        char *se_sid;


        attr_id = xmpp_get_attr(packet, "id");
        if (!attr_id) {
            return;
        }

        attr_sid = xmpp_get_attr(jingle_packet, "sid");
        if (!attr_sid) {
            return;
        }

        se_id = wmem_strdup(wmem_file_scope(), attr_id->value);
        se_sid = wmem_strdup(wmem_file_scope(), attr_sid->value);

        wmem_tree_insert_string(xmpp_info->jingle_sessions, se_id, (void*) se_sid, WMEM_TREE_STRING_NOCASE);
    }
}

void
xmpp_gtalk_session_track(packet_info *pinfo, xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    xmpp_element_t *gtalk_packet;
    GList *gtalk_packet_l;

    gtalk_packet_l = xmpp_find_element_by_name(packet,"session");
    gtalk_packet = (xmpp_element_t *)(gtalk_packet_l?gtalk_packet_l->data:NULL);


    if (gtalk_packet && !pinfo->fd->flags.visited) {
        xmpp_attr_t *attr_id;
        xmpp_attr_t *attr_sid;

        char *se_id;
        char *se_sid;

        xmpp_attr_t *xmlns = xmpp_get_attr(gtalk_packet, "xmlns");
        if(xmlns && strcmp(xmlns->value,"http://www.google.com/session") != 0)
            return;

        attr_id = xmpp_get_attr(packet, "id");
        if (!attr_id) {
            return;
        }

        attr_sid = xmpp_get_attr(gtalk_packet, "id");
        if (!attr_sid) {
            return;
        }

        se_id = wmem_strdup(wmem_file_scope(), attr_id->value);
        se_sid = wmem_strdup(wmem_file_scope(), attr_sid->value);

        wmem_tree_insert_string(xmpp_info->gtalk_sessions, se_id, (void*) se_sid, WMEM_TREE_STRING_NOCASE);
    }
}

void
xmpp_ibb_session_track(packet_info *pinfo, xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    xmpp_element_t *ibb_packet = NULL;
    GList *ibb_packet_l;

    if(strcmp(packet->name, "message") == 0)
    {
        ibb_packet_l = xmpp_find_element_by_name(packet,"data");
        ibb_packet = (xmpp_element_t *)(ibb_packet_l?ibb_packet_l->data:NULL);

    } else if(strcmp(packet->name, "iq") == 0)
    {
        ibb_packet_l = xmpp_find_element_by_name(packet,"open");

        if(!ibb_packet_l)
            ibb_packet_l = xmpp_find_element_by_name(packet,"close");
         if(!ibb_packet_l)
            ibb_packet_l = xmpp_find_element_by_name(packet,"data");

        ibb_packet = (xmpp_element_t *)(ibb_packet_l?ibb_packet_l->data:NULL);
    }

    if (ibb_packet && !pinfo->fd->flags.visited) {
        xmpp_attr_t *attr_id;
        xmpp_attr_t *attr_sid;

        char *se_id;
        char *se_sid;


        attr_id = xmpp_get_attr(packet, "id");
        attr_sid = xmpp_get_attr(ibb_packet, "sid");
        if(attr_id && attr_sid)
        {
            se_id = wmem_strdup(wmem_file_scope(), attr_id->value);
            se_sid = wmem_strdup(wmem_file_scope(), attr_sid->value);
            wmem_tree_insert_string(xmpp_info->ibb_sessions, se_id, (void*) se_sid, WMEM_TREE_STRING_NOCASE);
        }
    }
}

static void
xmpp_unknown_items(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element, guint level)
{
    GList *childs = element->elements;

    DISSECTOR_ASSERT( level < ETT_UNKNOWN_LEN );

    xmpp_unknown_attrs(tree, tvb, pinfo, element, TRUE);

    if(element->data)
    {
        proto_tree_add_text(tree, tvb, element->data->offset, element->data->length, "CDATA: %s",element->data->value);
    }

    while(childs)
    {
        xmpp_element_t *child = (xmpp_element_t *)childs->data;
        proto_item *child_item = proto_tree_add_text(tree, tvb, child->offset, child->length, "%s", xmpp_ep_string_upcase(child->name));
        proto_tree *child_tree = proto_item_add_subtree(child_item, ett_unknown[level]);

        if(child->default_ns_abbrev)
            proto_item_append_text(child_item, "(%s)", child->default_ns_abbrev);

        xmpp_unknown_items(child_tree, tvb, pinfo, child, level +1);

        childs = childs->next;
    }
}

void
xmpp_unknown(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element)
{
    GList *childs = element->elements;

    /*element has unrecognized elements*/
    while(childs)
    {
        xmpp_element_t *child = (xmpp_element_t *)childs->data;
        if(!child->was_read)
        {
            proto_item *unknown_item;
            proto_tree *unknown_tree;

            unknown_item = proto_tree_add_string_format(tree,
                    hf_xmpp_unknown, tvb, child->offset, child->length, child->name,
                    "%s", xmpp_ep_string_upcase(child->name));

            unknown_tree = proto_item_add_subtree(unknown_item, ett_unknown[0]);

            /*Add COL_INFO only if root element is IQ*/
            if(strcmp(element->name,"iq")==0)
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", xmpp_ep_string_upcase(child->name));

            if(child->default_ns_abbrev)
                proto_item_append_text(unknown_item,"(%s)",child->default_ns_abbrev);

            xmpp_unknown_items(unknown_tree, tvb, pinfo, child, 1);
            proto_item_append_text(unknown_item, " [UNKNOWN]");
            expert_add_info_format(pinfo, unknown_item, &ei_xmpp_unknown_element, "Unknown element: %s", child->name);
        }
        childs = childs->next;
    }
}

void
xmpp_unknown_attrs(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, xmpp_element_t *element, gboolean displ_short_list)
{
    proto_item *item = proto_tree_get_parent(tree);

    GList *keys = g_hash_table_get_keys(element->attrs);
    GList *values = g_hash_table_get_values(element->attrs);

    GList *keys_head = keys, *values_head = values;

    gboolean short_list_started = FALSE;

    while(keys && values)
    {
        xmpp_attr_t *attr = (xmpp_attr_t*) values->data;
        if (!attr->was_read) {
            if (displ_short_list) {
                if (!short_list_started)
                    proto_item_append_text(item, " [");
                else
                    proto_item_append_text(item, " ");
                proto_item_append_text(item, "%s=\"%s\"", (gchar*) keys->data, attr->value);

                short_list_started = TRUE;
            }

            /*If unknown element has xmlns attrib then header field hf_xmpp_xmlns is added to the tree.
             In other case only text.*/
            if (strcmp((const char *)keys->data, "xmlns") == 0)
                proto_tree_add_string(tree, hf_xmpp_xmlns, tvb, attr->offset, attr->length, attr->value);
            else {
                /*xmlns may looks like xmlns:abbrev="sth"*/
                gchar* xmlns_needle = epan_strcasestr((const char *)keys->data, "xmlns:");
                if (xmlns_needle && xmlns_needle == keys->data) {
                    proto_tree_add_string_format(tree, hf_xmpp_xmlns, tvb, attr->offset, attr->length, attr->value,"%s: %s", (gchar*)keys->data, attr->value);
                } else {
                    proto_item* unknown_attr_item;
                    unknown_attr_item = proto_tree_add_string_format(tree,
                            hf_xmpp_unknown_attr, tvb, attr->offset, attr->length,
                            attr->name, "%s: %s", attr->name, attr->value);
                    proto_item_append_text(unknown_attr_item, " [UNKNOWN ATTR]");
                    expert_add_info_format(pinfo, unknown_attr_item, &ei_xmpp_unknown_attribute, "Unknown attribute %s", attr->name);
                }
            }
        }
        keys = keys->next;
        values = values->next;
    }

    if(short_list_started && displ_short_list)
        proto_item_append_text(item, "]");

    g_list_free(keys_head);
    g_list_free(values_head);
}

void
xmpp_cdata(proto_tree *tree, tvbuff_t *tvb, xmpp_element_t *element, gint hf)
{
    if(element->data)
{
        if (hf == -1) {
            proto_tree_add_text(tree, tvb, element->data->offset, element->data->length, "CDATA: %s", element->data->value);
        } else {
            proto_tree_add_string(tree, hf, tvb, element->data->offset, element->data->length, element->data->value);
        }
    } else
    {
        if (hf == -1) {
            proto_tree_add_text(tree, tvb, 0, 0, "CDATA: (empty)");
        } else {
            proto_tree_add_string(tree, hf, tvb, 0, 0, "");
        }
    }
}

/* displays element that looks like <element_name>element_value</element_name>
 * ELEMENT_NAME: element_value as TEXT(proto_tree_add_text) int PROTO_TREE
 */
void
xmpp_simple_cdata_elem(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, xmpp_element_t *element)
{
    proto_tree_add_text(tree, tvb, element->offset, element->length, "%s: %s", xmpp_ep_string_upcase(element->name), xmpp_elem_cdata(element));
}

xmpp_array_t*
xmpp_ep_init_array_t(const gchar** array, gint len)
{
    xmpp_array_t *result;

    result = wmem_new(wmem_packet_scope(), xmpp_array_t);
    result->data = (gpointer) array;
    result->length = len;

    return result;
}

xmpp_attr_t*
xmpp_ep_init_attr_t(const gchar *value, gint offset, gint length)
{
    xmpp_attr_t *result;
    result = wmem_new(wmem_packet_scope(), xmpp_attr_t);
    result->value = value;
    result->offset = offset;
    result->length = length;
    result->name = NULL;

    return result;
}

gchar*
xmpp_ep_string_upcase(const gchar* string)
{
    gint len = (int)strlen(string);
    gint i;
    gchar* result = (gchar *)wmem_alloc0(wmem_packet_scope(), len+1);
    for(i=0; i<len; i++)
    {
        result[i] = string[i];

        if(string[i]>='a' && string[i]<='z')
            result[i]-='a'-'A';

    }
    return result;
}

gint
xmpp_element_t_cmp(gconstpointer a, gconstpointer b)
{
    gint result = strcmp(((const xmpp_element_t*)a)->name,((const xmpp_element_t*)b)->name);

    if(result == 0 && ((const xmpp_element_t*)a)->was_read)
        result = -1;

    return result;
}

GList*
xmpp_find_element_by_name(xmpp_element_t *packet,const gchar *name)
{
    GList *found_elements;
    xmpp_element_t *search_element;

    /*create fake element only with name*/
    search_element = wmem_new(wmem_packet_scope(), xmpp_element_t);
    search_element->name = wmem_strdup(wmem_packet_scope(), name);

    found_elements = g_list_find_custom(packet->elements, search_element, xmpp_element_t_cmp);

    if(found_elements)
        return found_elements;
    else
        return NULL;
}


/* steal_*
 * function searches element in packet and sets it as read.
 * if element doesn't exist, NULL is returned.
 * If element is set as read, it is invisible for these functions.*/
xmpp_element_t*
xmpp_steal_element_by_name(xmpp_element_t *packet,const gchar *name)
{
    GList *element_l;
    xmpp_element_t *element = NULL;

    element_l = xmpp_find_element_by_name(packet, name);

    if(element_l)
    {
        element = (xmpp_element_t *)element_l->data;
        element->was_read = TRUE;
    }

    return element;

}

xmpp_element_t*
xmpp_steal_element_by_names(xmpp_element_t *packet, const gchar **names, gint names_len)
{
    gint i;
    xmpp_element_t *el = NULL;

    for(i = 0; i<names_len; i++)
    {
        if((el = xmpp_steal_element_by_name(packet, names[i])))
            break;
    }

    return el;
}

xmpp_element_t*
xmpp_steal_element_by_attr(xmpp_element_t *packet, const gchar *attr_name, const gchar *attr_value)
{
    GList *childs = packet->elements;
    xmpp_element_t *result = NULL;

    while (childs) {
        xmpp_element_t *child_elem = (xmpp_element_t *)childs->data;
        xmpp_attr_t *attr = xmpp_get_attr(child_elem, attr_name);

        if(attr)
            attr->was_read = FALSE;

        if (!child_elem->was_read && attr && strcmp(attr->value, attr_value) == 0) {

            result = (xmpp_element_t *)childs->data;

            result->was_read = TRUE;

            break;
        } else
            childs = childs->next;
    }

    return result;
}

xmpp_element_t*
xmpp_steal_element_by_name_and_attr(xmpp_element_t *packet, const gchar *name, const gchar *attr_name, const gchar *attr_value)
{
    GList *childs = packet->elements;
    xmpp_element_t *result = NULL;

    while (childs) {
        xmpp_element_t *child_elem = (xmpp_element_t *)childs->data;
        xmpp_attr_t *attr = xmpp_get_attr(child_elem, attr_name);

        if(attr)
            attr->was_read = FALSE;

        if (!child_elem->was_read && attr && strcmp(child_elem->name, name) == 0 && strcmp(attr->value, attr_value) == 0) {

            result = (xmpp_element_t *)childs->data;

            result->was_read = TRUE;

            break;
        } else
            childs = childs->next;
    }
    return result;
}

xmpp_element_t*
xmpp_get_first_element(xmpp_element_t *packet)
{
    if(packet->elements && packet->elements->data)
        return (xmpp_element_t *)packet->elements->data;
    else
        return NULL;
}

/*
Function converts xml_frame_t structure to xmpp_element_t (simpler representation)
*/
xmpp_element_t*
xmpp_xml_frame_to_element_t(xml_frame_t *xml_frame, xmpp_element_t *parent, tvbuff_t *tvb)
{
    xml_frame_t *child;
    xmpp_element_t *node = wmem_new0(wmem_packet_scope(), xmpp_element_t);

    tvbparse_t* tt;
    tvbparse_elem_t* elem;

    node->attrs = g_hash_table_new(g_str_hash, g_str_equal);
    node->elements = NULL;
    node->data = NULL;
    node->was_read = FALSE;
    node->default_ns_abbrev = NULL;

    node->name = wmem_strdup(wmem_packet_scope(), xml_frame->name_orig_case);
    node->offset = 0;
    node->length = 0;

    node->namespaces = g_hash_table_new(g_str_hash, g_str_equal);
    if(parent)
    {
        xmpp_copy_hash_table(parent->namespaces, node->namespaces);
    } else
    {
        g_hash_table_insert(node->namespaces, (gpointer)"", (gpointer)"jabber:client");
    }

    if(xml_frame->item != NULL)
    {
        node->length = xml_frame->item->finfo->length;
    }

    node->offset = xml_frame->start_offset;

    tt = tvbparse_init(tvb,node->offset,-1,NULL,want_ignore);

    if((elem = tvbparse_get(tt,want_stream_end_with_ns))!=NULL)
    {
        node->default_ns_abbrev = tvb_get_string_enc(wmem_packet_scope(), elem->sub->tvb, elem->sub->offset, elem->sub->len, ENC_ASCII);
    }

    child = xml_frame->first_child;

    while(child)
    {
        if(child->type != XML_FRAME_TAG)
        {
            if(child->type == XML_FRAME_ATTRIB)
            {
                gint l;
                gchar *value = NULL;
                gchar *xmlns_needle = NULL;

                xmpp_attr_t *attr = wmem_new(wmem_packet_scope(), xmpp_attr_t);
                attr->length = 0;
                attr->offset = 0;
                attr->was_read = FALSE;

                if (child->value != NULL) {
                    l = tvb_reported_length(child->value);
                    value = (gchar *)wmem_alloc0(wmem_packet_scope(), l + 1);
                    tvb_memcpy(child->value, value, 0, l);
                }

                if(child->item)
                {
                    attr->length = child->item->finfo->length;
                }

                attr->offset = child->start_offset;
                attr->value = value;
                attr->name = wmem_strdup(wmem_packet_scope(), child->name_orig_case);

                g_hash_table_insert(node->attrs,(gpointer)attr->name,(gpointer)attr);

                /*checking that attr->name looks like xmlns:ns*/
                xmlns_needle = epan_strcasestr(attr->name, "xmlns");

                if(xmlns_needle == attr->name)
                {
                    if(attr->name[5] == ':' && strlen(attr->name) > 6)
                    {
                        g_hash_table_insert(node->namespaces, (gpointer)wmem_strdup(wmem_packet_scope(), &attr->name[6]), (gpointer)wmem_strdup(wmem_packet_scope(), attr->value));
                    } else if(attr->name[5] == '\0')
                    {
                        g_hash_table_insert(node->namespaces, (gpointer)"", (gpointer)wmem_strdup(wmem_packet_scope(), attr->value));
                    }
                }


            }
            else if( child->type == XML_FRAME_CDATA)
            {
                xmpp_data_t *data = NULL;
                gint l;
                gchar* value = NULL;

                data =  wmem_new(wmem_packet_scope(), xmpp_data_t);
                data->length = 0;
                data->offset = 0;

                if (child->value != NULL) {
                    l = tvb_reported_length(child->value);
                    value = (gchar *)wmem_alloc0(wmem_packet_scope(), l + 1);
                    tvb_memcpy(child->value, value, 0, l);
                }

                data->value = value;

                if(child->item)
                {
                    data->length = child->item->finfo->length;
                }
                data->offset = child->start_offset;
                node->data = data;
            }
        } else
        {
            node->elements = g_list_append(node->elements,(gpointer)xmpp_xml_frame_to_element_t(child, node,tvb));
        }

        child = child->next_sibling;
    }
    return node;
}

void
xmpp_element_t_tree_free(xmpp_element_t *root)
{
    GList *childs = root->elements;

    g_hash_table_destroy(root->attrs);
    g_hash_table_destroy(root->namespaces);

    while(childs)
    {
        xmpp_element_t *child = (xmpp_element_t *)childs->data;

        xmpp_element_t_tree_free(child);
        childs = childs->next;
    }
    g_list_free(root->elements);
}

/*Function recognize attribute names if they looks like xmlns:ns*/
static gboolean
attr_find_pred(gpointer key, gpointer value _U_, gpointer user_data)
{
    gchar *attr_name = (gchar*) user_data;

    if( strcmp(attr_name, "xmlns") == 0 )
    {
        gchar *first_occur = epan_strcasestr((const char *)key, "xmlns:");
        if(first_occur && first_occur == key)
            return TRUE;
        else
            return FALSE;
    }
    return FALSE;
}

/*Functions returns element's attibute by name and set as read*/
xmpp_attr_t*
xmpp_get_attr(xmpp_element_t *element, const gchar* attr_name)
{
    xmpp_attr_t *result = (xmpp_attr_t *)g_hash_table_lookup(element->attrs, attr_name);

    if(!result)
    {
        result = (xmpp_attr_t *)g_hash_table_find(element->attrs, attr_find_pred, (gpointer)attr_name);
    }

    if(result)
        result->was_read = TRUE;

    return result;
}

/*Functions returns element's attibute by name and namespace abbrev*/
static xmpp_attr_t*
xmpp_get_attr_ext(xmpp_element_t *element, const gchar* attr_name, const gchar* ns_abbrev)
{
    gchar* search_phrase;
    xmpp_attr_t *result;

    if(strcmp(ns_abbrev,"")==0)
        search_phrase = wmem_strdup(wmem_packet_scope(), attr_name);
    else if(strcmp(attr_name, "xmlns") == 0)
        search_phrase = wmem_strdup_printf(wmem_packet_scope(), "%s:%s",attr_name, ns_abbrev);
    else
        search_phrase = wmem_strdup_printf(wmem_packet_scope(), "%s:%s", ns_abbrev, attr_name);

    result = (xmpp_attr_t *)g_hash_table_lookup(element->attrs, search_phrase);

    if(!result)
    {
        result = (xmpp_attr_t *)g_hash_table_find(element->attrs, attr_find_pred, (gpointer)attr_name);
    }

    if(result)
        result->was_read = TRUE;

    return result;
}



gchar*
xmpp_element_to_string(tvbuff_t *tvb, xmpp_element_t *element)
{
    gchar *buff = NULL;

    if(tvb_offset_exists(tvb, element->offset+element->length-1))
    {
        buff = tvb_get_string_enc(wmem_packet_scope(), tvb, element->offset, element->length, ENC_ASCII);
    }
    return buff;
}

gchar*
xmpp_attr_to_string(tvbuff_t *tvb, xmpp_attr_t *attr)
{
    gchar *buff = NULL;

    if(tvb_offset_exists(tvb, attr->offset + attr->length-1))
    {
        buff = tvb_get_string_enc(wmem_packet_scope(), tvb, attr->offset, attr->length, ENC_ASCII);
    }
    return buff;
}

static void
children_foreach_hide_func(proto_node *node, gpointer data)
{
    int *i = (int *)data;
    if((*i) == 0)
        PROTO_ITEM_SET_HIDDEN(node);
    (*i)++;
}

static void
children_foreach_show_func(proto_node *node, gpointer data)
{
    int *i = (int *)data;
    if((*i) == 0)
        PROTO_ITEM_SET_VISIBLE(node);
    (*i)++;
}

void
xmpp_proto_tree_hide_first_child(proto_tree *tree)
{
    int i = 0;
    proto_tree_children_foreach(tree, children_foreach_hide_func, &i);
}

void
xmpp_proto_tree_show_first_child(proto_tree *tree)
{
    int i = 0;
    proto_tree_children_foreach(tree, children_foreach_show_func, &i);
}

gchar*
proto_item_get_text(proto_item *item)
{
    field_info *fi = NULL;
    gchar *result;

    if(item == NULL)
        return NULL;

    fi = PITEM_FINFO(item);

    if(fi==NULL)
        return NULL;

    if (fi->rep == NULL)
        return NULL;


    result = wmem_strdup(wmem_packet_scope(), fi->rep->representation);
    return result;
}


void
xmpp_display_attrs(proto_tree *tree, xmpp_element_t *element, packet_info *pinfo, tvbuff_t *tvb, const xmpp_attr_info *attrs, guint n)
{
    proto_item *item = proto_tree_get_parent(tree);
    xmpp_attr_t *attr;
    guint i;
    gboolean short_list_started = FALSE;

    if(element->default_ns_abbrev)
        proto_item_append_text(item, "(%s)",element->default_ns_abbrev);

    proto_item_append_text(item," [");
    for(i = 0; i < n && attrs!=NULL; i++)
    {
        attr = xmpp_get_attr(element, attrs[i].name);
        if(attr)
        {
            if(attrs[i].phf != NULL)
            {
                if(attr->name)
                    proto_tree_add_string_format(tree, *attrs[i].phf, tvb, attr->offset, attr->length, attr->value,"%s: %s", attr->name, attr->value);
                else
                    proto_tree_add_string(tree, *attrs[i].phf, tvb, attr->offset, attr->length, attr->value);
            }
            else
            {
                proto_tree_add_text(tree, tvb, attr->offset, attr->length, "%s: %s", attr->name?attr->name:attrs[i].name, attr->value);
            }

            if(attrs[i].in_short_list)
            {
                if(short_list_started)
                {
                    proto_item_append_text(item," ");
                }
                proto_item_append_text(item,"%s=\"%s\"",attr->name?attr->name:attrs[i].name, attr->value);
                short_list_started = TRUE;
            }

        } else if(attrs[i].is_required)
        {
            expert_add_info_format(pinfo, item, &ei_xmpp_required_attribute, "Required attribute \"%s\" doesn't appear in \"%s\".", attrs[i].name, element->name);
        }

        if(attrs[i].val_func)
        {
            if(attr)
                attrs[i].val_func(pinfo, item, attrs[i].name, attr->value, attrs[i].data);
            else
                attrs[i].val_func(pinfo, item, attrs[i].name, NULL, attrs[i].data);
        }
    }
    proto_item_append_text(item,"]");

    /*displays attributes that weren't recognized*/
    xmpp_unknown_attrs(tree, tvb, pinfo, element, FALSE);
}

void
xmpp_display_attrs_ext(proto_tree *tree, xmpp_element_t *element, packet_info *pinfo, tvbuff_t *tvb, const xmpp_attr_info_ext *attrs, guint n)
{
    proto_item *item = proto_tree_get_parent(tree);
    xmpp_attr_t *attr;
    guint i;
    gboolean short_list_started = FALSE;

    GList *ns_abbrevs_head, *ns_abbrevs = g_hash_table_get_keys(element->namespaces);
    GList *ns_fullnames_head, *ns_fullnames = g_hash_table_get_values(element->namespaces);
    ns_abbrevs_head = ns_abbrevs;
    ns_fullnames_head = ns_fullnames;

    if(element->default_ns_abbrev)
        proto_item_append_text(item, "(%s)",element->default_ns_abbrev);

    proto_item_append_text(item," [");
    while(ns_abbrevs && ns_fullnames)
    {
        for (i = 0; i < n && attrs != NULL; i++) {
            if(strcmp((const char *)(ns_fullnames->data), attrs[i].ns) == 0)
            {
                attr = xmpp_get_attr_ext(element, attrs[i].info.name, (const gchar *)(ns_abbrevs->data));
                if(!attr && element->default_ns_abbrev && strcmp((const char *)ns_abbrevs->data, element->default_ns_abbrev)==0)
                    attr = xmpp_get_attr_ext(element, attrs[i].info.name, "");

                if (attr) {
                    if (attrs[i].info.phf != NULL) {
                        if (attr->name)
                            proto_tree_add_string_format(tree, *attrs[i].info.phf, tvb, attr->offset, attr->length, attr->value, "%s: %s", attr->name, attr->value);
                        else
                            proto_tree_add_string(tree, *attrs[i].info.phf, tvb, attr->offset, attr->length, attr->value);
                    } else {
                        proto_tree_add_text(tree, tvb, attr->offset, attr->length, "%s: %s", attr->name ? attr->name : attrs[i].info.name, attr->value);
                    }

                    if (attrs[i].info.in_short_list) {
                        if (short_list_started) {
                            proto_item_append_text(item, " ");
                        }
                        proto_item_append_text(item, "%s=\"%s\"", attr->name ? attr->name : attrs[i].info.name, attr->value);
                        short_list_started = TRUE;
                    }

                } else if (attrs[i].info.is_required) {
                    expert_add_info_format(pinfo, item, &ei_xmpp_required_attribute, "Required attribute \"%s\" doesn't appear in \"%s\".", attrs[i].info.name, element->name);
                }

                if (attrs[i].info.val_func) {
                    if (attr)
                        attrs[i].info.val_func(pinfo, item, attrs[i].info.name, attr->value, attrs[i].info.data);
                    else
                        attrs[i].info.val_func(pinfo, item, attrs[i].info.name, NULL, attrs[i].info.data);
                }
            }
        }
        ns_abbrevs = ns_abbrevs->next;
        ns_fullnames = ns_fullnames->next;
    }
    proto_item_append_text(item,"]");

    /*displays attributes that weren't recognized*/
    xmpp_unknown_attrs(tree, tvb, pinfo, element, FALSE);

    g_list_free(ns_abbrevs_head);
    g_list_free(ns_fullnames_head);
}

typedef struct _name_attr_t
{
    const gchar *name;
    const gchar *attr_name;
    const gchar *attr_value;
} name_attr_t;

/*
returns pointer to the struct that contains 3 strings(element name, attribute name, attribute value)
*/
gpointer
xmpp_name_attr_struct(const gchar *name, const gchar *attr_name, const gchar *attr_value)
{
    name_attr_t *result;

    result =  wmem_new(wmem_packet_scope(), name_attr_t);
    result->name = name;
    result->attr_name = attr_name;
    result->attr_value = attr_value;
    return result;
}

void
xmpp_display_elems(proto_tree *tree, xmpp_element_t *parent, packet_info *pinfo, tvbuff_t *tvb, xmpp_elem_info *elems, guint n)
{
    guint i;

    for(i = 0; i < n && elems!=NULL; i++)
    {
        xmpp_element_t *elem = NULL;

        if(elems[i].type == NAME_AND_ATTR)
        {
            gboolean loop = TRUE;

            name_attr_t *a = (name_attr_t *)(elems[i].data);

            while(loop && (elem = xmpp_steal_element_by_name_and_attr(parent, a->name, a->attr_name, a->attr_value))!=NULL)
            {
                elems[i].elem_func(tree, tvb, pinfo, elem);
                if(elems[i].occurrence == ONE)
                    loop = FALSE;
            }
        } else if(elems[i].type == NAME)
        {
            gboolean loop = TRUE;
            const gchar *name = (const gchar *)(elems[i].data);

            while(loop && (elem = xmpp_steal_element_by_name(parent, name))!=NULL)
            {
                elems[i].elem_func(tree, tvb, pinfo, elem);
                if(elems[i].occurrence == ONE)
                    loop = FALSE;
            }
        }
        else if(elems[i].type == ATTR)
        {
            gboolean loop = TRUE;
            name_attr_t *attr = (name_attr_t *)(elems[i].data);

            while(loop && (elem = xmpp_steal_element_by_attr(parent, attr->attr_name, attr->attr_value))!=NULL)
            {
                elems[i].elem_func(tree, tvb, pinfo, elem);
                if(elems[i].occurrence == ONE)
                    loop = FALSE;
            }

        } else if(elems[i].type == NAMES)
        {
            gboolean loop = TRUE;
            const xmpp_array_t *names = (const xmpp_array_t *)(elems[i].data);

            while(loop && (elem =  xmpp_steal_element_by_names(parent, (const gchar**)names->data, names->length))!=NULL)
            {
                elems[i].elem_func(tree, tvb, pinfo, elem);
                if(elems[i].occurrence == ONE)
                    loop = FALSE;
            }
        }
    }

    xmpp_unknown(tree, tvb, pinfo, parent);
}

/*
function checks that variable value is in array ((xmpp_array_t)data)->data
*/
void
xmpp_val_enum_list(packet_info *pinfo, proto_item *item, const gchar *name, const gchar *value, gconstpointer data)
{
    const xmpp_array_t *enums_array = (const xmpp_array_t *)data;

    gint i;
    gboolean value_in_enums = FALSE;

    gchar **enums =  (char**)enums_array->data;

    if (value != NULL) {
        for (i = 0; i < enums_array->length; i++) {
            if (strcmp(value, enums[i]) == 0) {
                value_in_enums = TRUE;
                break;
            }
        }
        if (!value_in_enums) {
            expert_add_info_format(pinfo, item, &ei_xmpp_field_unexpected_value, "Field \"%s\" has unexpected value \"%s\"", name, value);
        }
    }
}


void
xmpp_change_elem_to_attrib(const gchar *elem_name, const gchar *attr_name, xmpp_element_t *parent, xmpp_attr_t* (*transform_func)(xmpp_element_t *element))
{
    xmpp_element_t *element = NULL;
    xmpp_attr_t *fake_attr = NULL;

    element = xmpp_steal_element_by_name(parent, elem_name);
    if(element)
        fake_attr = transform_func(element);

    if(fake_attr)
        g_hash_table_insert(parent->attrs, (gpointer)attr_name, fake_attr);
}

xmpp_attr_t*
xmpp_transform_func_cdata(xmpp_element_t *elem)
{
    xmpp_attr_t *result = xmpp_ep_init_attr_t(elem->data?elem->data->value:"", elem->offset, elem->length);
    return result;
}

static void
xmpp_copy_hash_table_func(gpointer key, gpointer value, gpointer user_data)
{
    GHashTable *dst = (GHashTable *)user_data;
    g_hash_table_insert(dst, key, value);
}

void xmpp_copy_hash_table(GHashTable *src, GHashTable *dst)
{
    g_hash_table_foreach(src, xmpp_copy_hash_table_func, dst);
}

#if 0
static void
printf_hash_table_func(gpointer key, gpointer value, gpointer user_data _U_)
{
    printf("'%s' '%s'\n", (gchar*)key, (gchar*)value);
}

void
printf_elements(xmpp_element_t *root)
{
    GList *elems = root->elements;

    printf("%s\n", root->name);
    g_hash_table_foreach(root->namespaces, printf_hash_table_func, NULL);
    while(elems)
    {
        printf_elements(elems->data);
        elems = elems->next;
    }
}
#endif

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
