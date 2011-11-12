/* xmpp-utils.h
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

#ifndef XMPP_UTILS_H
#define XMPP_UTILS_H

#define FI_RESET_FLAG(fi, flag) \
    do { \
      if (fi) \
        (fi)->flags = (fi)->flags & !(flag); \
    } while(0)

#define PROTO_ITEM_SET_VISIBLE(proto_item)       \
  do { \
    if (proto_item) \
      FI_RESET_FLAG(PITEM_FINFO(proto_item), FI_HIDDEN); \
  } while(0)

#define elem_cdata(elem) \
elem->data?elem->data->value:""

typedef struct _array_t
{
    gpointer data;
    gint length;
} array_t;

typedef struct _attr_t{
    gchar *value;
    gchar *name;
    gint offset;
    gint length;

    gboolean was_read;
} attr_t;

typedef struct _data_t{
    gchar *value;

    gint offset;
    gint length;
} data_t;

typedef struct _element_t{
    gchar* name;
    
    /*abbreviation that apprears before tag name (<nos:x .../>)
     if abbrev doesn't appear then NULL*/
    gchar* default_ns_abbrev;
    /*pair of namespace abbrev and namespace*/
    GHashTable *namespaces;

    GHashTable *attrs;
    GList *elements;
    data_t *data;

    gint offset;
    gint length;

    gboolean was_read;
} element_t;

/*informations about attributes that are displayed in proto tree*/
typedef struct _attr_info{
    gchar *name;
    gint hf;
    gboolean is_required;
    gboolean in_short_list;

    /*function validates this attribute
    it may impose other restrictions (e.g. validating atribut's name, ...)*/
    void (*val_func)(packet_info *pinfo, proto_item *item, gchar *name, gchar *value, gpointer data);
    gpointer data;
} attr_info;

typedef struct _attr_info_ext{
    gchar* ns;
    attr_info info;
} attr_info_ext;

typedef enum _elem_info_type{
    NAME,
    ATTR,
    NAME_AND_ATTR,
    NAMES
} elem_info_type;

typedef enum _elem_info_occurrence
{
    ONE,MANY
} elem_info_occurrence;

/*informations about elements that are displayed in proto tree*/
typedef struct _elem_info{
    elem_info_type type;
    gpointer data;
    /*function that displays element in tree*/
    void (*elem_func)(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
    elem_info_occurrence occurrence;
} elem_info;

typedef struct _xmpp_conv_info_t {
    emem_tree_t *req_resp;
    emem_tree_t *jingle_sessions;
    emem_tree_t *ibb_sessions;
    emem_tree_t *gtalk_sessions;
} xmpp_conv_info_t;

/** Struct conatins frame numbers (request frame(IQ set/get) and
 * response frame(IQ result/error)).
 */
typedef struct _xmpp_reqresp_transaction_t {
    guint32 req_frame;
    guint32 resp_frame;
} xmpp_transaction_t;

/** Function that is responsibe for request/response tracking in IQ packets.
 * Each IQ set/get packet should have the response in other IQ result/error packet.
 * Both packet should have the same id attribute. Function saves in emem_tree pairs of
 * packet id and struct xmpp_transaction_t.
 */
extern void xmpp_iq_reqresp_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);

/** Function that is responsibe for jingle session tracking in IQ packets.
 * Function saves in emem_tree pairs of packet's id and Jingle session's id.
 */
extern void xmpp_jingle_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);

/** Function that is responsibe for ibb(in band bytestreams) session tracking in IQ packets.
 * Function saves in emem_tree pairs of packet's id and In-Band Bytestreams session's id.
 */
extern void xmpp_ibb_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);

/** Function that is responsibe for GTalk session(voice/video) tracking in IQ packets.
 * Function saves in emem_tree pairs of packet's id and GTalk session's id.
 */
extern void xmpp_gtalk_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);

/** Function detects unrecognized elements and displays them in tree.
 * It uses ett_unknown to display packets. ett_unknown has const size described by
 * ETT_UNKNOWN_LEN in packet-xmpp.h 
 */
extern void xmpp_unknown(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

extern void xmpp_unknown_attrs(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element, gboolean displ_short_list);

/** Displays CDATA from element in tree. You can use your own header field hf or
 * pass -1. If you pass -1 then CDATA will be display as text(proto_tree_add_text):
 * ELEMENT_NAME: CDATA
 * ELEMENT_NAME = element->name, if element is empty CDATA = "(empty)"
 */
extern void xmpp_cdata(proto_tree *tree, tvbuff_t *tvb, element_t *element, gint hf);

/** Function is similar to xmpp_cdata. But it display items only as a text and it is
 * compatibile with function display_elems
 */
extern void xmpp_simple_cdata_elem(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

/** Converts xml_frame_t struct to element_t. Should be call with parent==NULL.
 */
extern element_t* xml_frame_to_element_t(xml_frame_t *xml_frame, element_t *parent, tvbuff_t *tvb);

/** Frees all GLib structs in element_t struct. Should be call only for root element.
 * It works recursively.
 */
extern void element_t_tree_free(element_t *root);

/** Allocs ephemeral memory for array_t struct.*/
extern array_t* ep_init_array_t(const gchar** array, gint len);

/*Allocs ephemeral memory for attr_t struct*/
extern attr_t* ep_init_attr_t(gchar *value, gint offset, gint length);

/*Allocs ephemeral memory for upcased string*/
extern gchar* ep_string_upcase(const gchar* string);

/*Compares 2 element_t struct by names. Returns value is similar to the returned by strcmp*/
extern gint element_t_cmp(gconstpointer a, gconstpointer b);

/*Searches child element in parent element by name. GList element is returned.*/
extern GList* find_element_by_name(element_t *packet,const gchar *name);

/** steal_*
 * Functions searches and marks as read found elements.
 * If element is set as read, it is invisible for these functions.*/
 
extern element_t* steal_element_by_name(element_t *packet, const gchar *name);
extern element_t* steal_element_by_names(element_t *packet, const gchar **names, gint names_len);
extern element_t* steal_element_by_attr(element_t *packet, const gchar *attr_name, const gchar *attr_value);
extern element_t* steal_element_by_name_and_attr(element_t *packet, const gchar *name, const gchar *attr_name, const gchar *attr_value);

/*Returns first child in element*/
extern element_t* get_first_element(element_t *packet);

/*Converts element to string. Returns memory allocated as ephemeral.*/
extern gchar* element_to_string(tvbuff_t *tvb, element_t *element);

/*Converts attribute to string. Returns memory allocated as ephemeral.*/
extern gchar* attr_to_string(tvbuff_t *tvb, attr_t *attr);

/* Returns attribute by name and set as read. If attrib is set as read, it may be found
 * one more time, but it is invisible for function xmpp_unknown_attrib*/
extern attr_t* get_attr(element_t *element, const gchar* attr_name);

/*Function hides first element in tree.*/
extern void proto_tree_hide_first_child(proto_tree *tree);

/*Function shows first element in tree.*/
extern void proto_tree_show_first_child(proto_tree *tree);

/*Function returns item as text. Memory is allocated as ephemeral.*/
extern gchar* proto_item_get_text(proto_item *item);

/*Function returns struct that contains 3 strings. It is used to build attr_info struct.*/
extern gpointer name_attr_struct(gchar *name, gchar *attr_name, gchar *attr_value);

/** Function displays attributes from element in way described in attrs.
 * Elements that doesn't exist in attrs are displayed as text.
 * In ATTR_INFO struct you can define several things:
 * - is_in_short_list - attribute should be displayed in short list e.g. ELEMENT_NAME [ATTR1='value' ATTR2='value']
 * - is_required - attribute is required. If attribute doesn't appear then EXPERT INFO will be displayed
 * - val_func - validate function
 * - data - data passes to the val_func
 */
extern void display_attrs(proto_tree *tree, element_t *element, packet_info *pinfo, tvbuff_t *tvb, attr_info *attrs, guint n);

/** Function does the same as shown above. It takes attrs(ATTR_INFO_EXT) argument
 * that contains ATTR_INFO struct and string with namespace. It is used when packet
 * contains several namespaces and each attribute belongs to particular namespace.
 * E.g.
 * <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'
 *  mechanism='PLAIN'
 *  xmlns:ga='http://www.google.com/talk/protocol/auth'
 *  ga:client-uses-full-bind-result='true'>
 * </auth>
 */
extern void display_attrs_ext(proto_tree *tree, element_t *element, packet_info *pinfo, tvbuff_t *tvb, attr_info_ext *attrs, guint n);

/** Displays elements from parent element in a way described in elems(ELEM_INFO).
 * ELEM_INFO describes how to find particular element and what action should be done
 * for this element.
 * Function calls xmpp_unknown.
 */
extern void display_elems(proto_tree *tree, element_t *parent, packet_info *pinfo, tvbuff_t *tvb, elem_info *elems, guint n);

/* Validates attribute value. Takes string array(gchar**) in parameter data.
 * Is used in ATTR_INFO struct.
 */
extern void val_enum_list(packet_info *pinfo, proto_item *item, gchar *name, gchar *value, gpointer data);

/** Function changes element to attribute. It searches element by name in parent element,
 * next it create attribute using transform_func and inserts it to parent attributes hash table
 * using attr_name as key.
 */
extern void change_elem_to_attrib(const gchar *elem_name, const gchar *attr_name, element_t *parent, attr_t* (*transform_func)(element_t *element));

/** transform_func that creates attribute with element's cdata as value
 */
extern attr_t* transform_func_cdata(element_t *elem);

/*Copys keys and values from one hash table to another.
 Hash tables must be initialized.*/
extern void copy_hash_table(GHashTable *src, GHashTable *dst);

#endif /* XMPP_UTILS_H */
