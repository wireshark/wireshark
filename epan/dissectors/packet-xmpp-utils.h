/* xmpp-utils.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef XMPP_UTILS_H
#define XMPP_UTILS_H

#include "ws_symbol_export.h"
#include "tvbuff.h"
#include "dissectors/packet-xml.h"
#include <epan/wmem_scopes.h>

#define xmpp_elem_cdata(elem) \
elem->data?elem->data->value:""

typedef struct _xmpp_array_t
{
    void *data;
    int length;
} xmpp_array_t;

typedef struct _xmpp_attr_t{
    const char *value;
    const char *name;
    int offset;
    int length;

    bool was_read;
} xmpp_attr_t;

typedef struct _xmpp_data_t{
    char *value;

    int offset;
    int length;
} xmpp_data_t;

typedef struct _xmpp_element_t{
    char* name;

    /*abbreviation that apprears before tag name (<nos:x .../>)
     if abbrev doesn't appear then NULL*/
    char* default_ns_abbrev;
    /*pair of namespace abbrev and namespace*/
    GHashTable *namespaces;

    GHashTable *attrs;
    GList *elements;
    xmpp_data_t *data;

    int offset;
    int length;

    bool was_read;
} xmpp_element_t;

/*informations about attributes that are displayed in proto tree*/
typedef struct _xmpp_attr_info{
    const char *name;
    const int *phf;
    bool is_required;
    bool in_short_list;

    /*function validates this attribute
    it may impose other restrictions (e.g. validating atribut's name, ...)*/
    void (*val_func)(packet_info *pinfo, proto_item *item, const char *name, const char *value, const void *data);
    void *data;
} xmpp_attr_info;

typedef struct _xmpp_attr_info_ext{
    const char* ns;
    xmpp_attr_info info;
} xmpp_attr_info_ext;

typedef enum _xmpp_elem_info_type{
    NAME,
    ATTR,
    NAME_AND_ATTR,
    NAMES
} xmpp_elem_info_type;

typedef enum _xmpp_elem_info_occurrence
{
    ONE,MANY
} xmpp_elem_info_occurrence;

/*informations about elements that are displayed in proto tree*/
typedef struct _xmpp_elem_info{
    xmpp_elem_info_type type;
    const void *data;
    /*function that displays element in tree*/
    void (*elem_func)(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
    xmpp_elem_info_occurrence occurrence;
} xmpp_elem_info;

typedef struct _xmpp_conv_info_t {
    wmem_tree_t *req_resp;
    wmem_tree_t *jingle_sessions;
    wmem_tree_t *ibb_sessions;
    wmem_tree_t *gtalk_sessions;
    uint32_t     ssl_start;
} xmpp_conv_info_t;

/** Struct conatins frame numbers (request frame(IQ set/get) and
 * response frame(IQ result/error)).
 */
typedef struct _xmpp_reqresp_transaction_t {
    uint32_t req_frame;
    uint32_t resp_frame;
} xmpp_transaction_t;

/** Function that is responsibe for request/response tracking in IQ packets.
 * Each IQ set/get packet should have the response in other IQ result/error packet.
 * Both packet should have the same id attribute. Function saves in wmem_tree pairs of
 * packet id and struct xmpp_transaction_t.
 */
extern void xmpp_iq_reqresp_track(packet_info *pinfo, xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info);

/** Function that is responsibe for jingle session tracking in IQ packets.
 * Function saves in wmem_tree pairs of packet's id and Jingle session's id.
 */
extern void xmpp_jingle_session_track(packet_info *pinfo, xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info);

/** Function that is responsibe for ibb(in band bytestreams) session tracking in IQ packets.
 * Function saves in wmem_tree pairs of packet's id and In-Band Bytestreams session's id.
 */
extern void xmpp_ibb_session_track(packet_info *pinfo, xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info);

/** Function that is responsibe for GTalk session(voice/video) tracking in IQ packets.
 * Function saves in wmem_tree pairs of packet's id and GTalk session's id.
 */
extern void xmpp_gtalk_session_track(packet_info *pinfo, xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info);

/** Function detects unrecognized elements and displays them in tree.
 * It uses ett_unknown to display packets. ett_unknown has const size described by
 * ETT_UNKNOWN_LEN in packet-xmpp.h
 */
extern void xmpp_unknown(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

/** Displays CDATA from element in tree. You can use your own header field hf or
 * pass -1. If you pass -1 then CDATA will be display as text:
 * ELEMENT_NAME: CDATA
 * ELEMENT_NAME = element->name, if element is empty CDATA = "(empty)"
 */
extern void xmpp_cdata(proto_tree *tree, tvbuff_t *tvb, xmpp_element_t *element, int hf);

/** Function is similar to xmpp_cdata. But it display items only as a text and it is
 * compatibile with function display_elems
 */
extern void xmpp_simple_cdata_elem(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

/** Converts xml_frame_t struct to xmpp_element_t. Should be call with parent==NULL.
 */
extern xmpp_element_t* xmpp_xml_frame_to_element_t(packet_info *pinfo, xml_frame_t *xml_frame, xmpp_element_t *parent, tvbuff_t *tvb);

/** Frees all GLib structs in xmpp_element_t struct. Should be call only for root element.
 * It works recursively.
 */
extern void xmpp_element_t_tree_free(xmpp_element_t *root);

/** Allocs ephemeral memory for xmpp_array_t struct.*/
extern xmpp_array_t* xmpp_ep_init_array_t(wmem_allocator_t *pool, const char** array, int len);

/*Allocs ephemeral memory for xmpp_attr_t struct*/
extern xmpp_attr_t* xmpp_ep_init_attr_t(wmem_allocator_t *pool, const char *value, int offset, int length);

/** steal_*
 * Functions searches and marks as read found elements.
 * If element is set as read, it is invisible for these functions.*/

extern xmpp_element_t* xmpp_steal_element_by_name(xmpp_element_t *packet, const char *name);
extern xmpp_element_t* xmpp_steal_element_by_names(xmpp_element_t *packet, const char **names, int names_len);
extern xmpp_element_t* xmpp_steal_element_by_attr(xmpp_element_t *packet, const char *attr_name, const char *attr_value);
extern xmpp_element_t* xmpp_steal_element_by_name_and_attr(xmpp_element_t *packet, const char *name, const char *attr_name, const char *attr_value);

/*Returns first child in element*/
extern xmpp_element_t* xmpp_get_first_element(xmpp_element_t *packet);

/*Converts element to string. Returns memory allocated from the given pool.*/
extern char* xmpp_element_to_string(wmem_allocator_t *pool, tvbuff_t *tvb, xmpp_element_t *element);

/* Returns attribute by name and set as read. If attrib is set as read, it may be found
 * one more time, but it is invisible for function xmpp_unknown_attrib*/
extern xmpp_attr_t* xmpp_get_attr(xmpp_element_t *element, const char* attr_name);

/*Function hides first element in tree.*/
extern void xmpp_proto_tree_hide_first_child(proto_tree *tree);

/*Function shows first element in tree.*/
extern void xmpp_proto_tree_show_first_child(proto_tree *tree);

/*Function returns item as text. Memory is allocated from the given pool.*/
extern char* proto_item_get_text(wmem_allocator_t *pool, proto_item *item);

/*Function returns struct that contains 3 strings. It is used to build xmpp_attr_info struct.*/
extern void *xmpp_name_attr_struct(wmem_allocator_t *pool, const char *name, const char *attr_name, const char *attr_value);

/** Function displays attributes from element in way described in attrs.
 * Elements that doesn't exist in attrs are displayed as text.
 * In XMPP_ATTR_INFO struct you can define several things:
 * - is_in_short_list - attribute should be displayed in short list e.g. ELEMENT_NAME [ATTR1='value' ATTR2='value']
 * - is_required - attribute is required. If attribute doesn't appear then EXPERT INFO will be displayed
 * - val_func - validate function
 * - data - data passes to the val_func
 */
extern void xmpp_display_attrs(proto_tree *tree, xmpp_element_t *element, packet_info *pinfo, tvbuff_t *tvb, const xmpp_attr_info *attrs, unsigned n);

/** Function does the same as shown above. It takes attrs(XMPP_ATTR_INFO_EXT) argument
 * that contains XMPP_ATTR_INFO struct and string with namespace. It is used when packet
 * contains several namespaces and each attribute belongs to particular namespace.
 * E.g.
 * @code
 * <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'
 *  mechanism='PLAIN'
 *  xmlns:ga='http://www.google.com/talk/protocol/auth'
 *  ga:client-uses-full-bind-result='true'>
 * </auth>
 * @endcode
 */
extern void xmpp_display_attrs_ext(proto_tree *tree, xmpp_element_t *element, packet_info *pinfo, tvbuff_t *tvb, const xmpp_attr_info_ext *attrs, unsigned n);

/** Displays elements from parent element in a way described in elems(XMPP_ELEM_INFO).
 * XMPP_ELEM_INFO describes how to find particular element and what action should be done
 * for this element.
 * Function calls xmpp_unknown.
 */
extern void xmpp_display_elems(proto_tree *tree, xmpp_element_t *parent, packet_info *pinfo, tvbuff_t *tvb, xmpp_elem_info *elems, unsigned n);

/* Validates attribute value. Takes string array(char**) in parameter data.
 * Is used in XMPP_ATTR_INFO struct.
 */
extern void xmpp_val_enum_list(packet_info *pinfo, proto_item *item, const char *name, const char *value, const void *data);

/** Function changes element to attribute. It searches element by name in parent element,
 * next it create attribute using transform_func and inserts it to parent attributes hash table
 * using attr_name as key.
 */
extern void xmpp_change_elem_to_attrib(wmem_allocator_t *pool, const char *elem_name, const char *attr_name, xmpp_element_t *parent, xmpp_attr_t* (*transform_func)(wmem_allocator_t *pool, xmpp_element_t *element));

/** transform_func that creates attribute with element's cdata as value
 */
extern xmpp_attr_t* xmpp_transform_func_cdata(wmem_allocator_t *pool, xmpp_element_t *elem);

#endif /* XMPP_UTILS_H */
