/* packet-xml.h
 * wireshark's xml dissector .
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_XML_H__
#define __PACKET_XML_H__

#include "ws_symbol_export.h"

typedef struct _xml_ns_t {
    /* the name of this namespace */
    char* name;

    /* its fully qualified name */
    const char* fqn;

    /* the contents of the whole element from <> to </> */
    int hf_tag;

    /* chunks of cdata from <> to </> excluding sub tags */
    int hf_cdata;

    /* the subtree for its sub items  */
    int ett;

    wmem_map_t* attributes;
    /*  key:   the attribute name
        value: hf_id of what's between quotes */

    /* the namespace's namespaces */
    wmem_map_t* elements;
    /*	key:   the element name
        value: the child namespace */

    GPtrArray* element_names;
    /* imported directly from the parser and used while building the namespace */

} xml_ns_t;

#define XML_FRAME_ROOT  0
#define XML_FRAME_TAG   1
#define XML_FRAME_XMPLI 2
#define XML_FRAME_DTD_DOCTYPE 3
#define XML_FRAME_ATTRIB 4
#define XML_FRAME_CDATA 5

typedef struct _xml_frame_t {
    int type;
    struct _xml_frame_t* parent;
    struct _xml_frame_t* first_child;
    struct _xml_frame_t* last_child;
    struct _xml_frame_t* prev_sibling;
    struct _xml_frame_t* next_sibling;
    const char *name;
    const char *name_orig_case;
    tvbuff_t *value;
    proto_tree* tree;
    proto_item* item;
    proto_item* last_item;
    xml_ns_t* ns;
    int start_offset;
    int length;
    packet_info* pinfo;
    wmem_map_t *decryption_keys;
} xml_frame_t;

WS_DLL_PUBLIC
xml_frame_t *xml_get_tag(xml_frame_t *frame, const char *name);
WS_DLL_PUBLIC
xml_frame_t *xml_get_attrib(xml_frame_t *frame, const char *name);
WS_DLL_PUBLIC
xml_frame_t *xml_get_cdata(xml_frame_t *frame);

#endif /* __PACKET_XML_H__ */

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
