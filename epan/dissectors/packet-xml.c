/* packet-xml.c
 * wireshark's xml dissector .
 *
 * (C) 2005, Luis E. Garcia Ontanon.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/tvbparse.h>
#include <epan/dtd.h>
#include <epan/proto_data.h>
#include <wsutil/filesystem.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/garrayfix.h>
#include <wsutil/str_util.h>
#include <wsutil/report_message.h>

#include "packet-xml.h"
#include "packet-acdr.h"

void proto_register_xml(void);
void proto_reg_handoff_xml(void);

struct _attr_reg_data {
    wmem_array_t *hf;
    const gchar *basename;
};


static gint ett_dtd = -1;
static gint ett_xmpli = -1;

static int hf_unknowwn_attrib = -1;
static int hf_comment = -1;
static int hf_xmlpi = -1;
static int hf_dtd_tag = -1;
static int hf_doctype = -1;
static int hf_cdatasection = -1;

static expert_field ei_xml_closing_unopened_tag = EI_INIT;
static expert_field ei_xml_closing_unopened_xmpli_tag = EI_INIT;
static expert_field ei_xml_unrecognized_text = EI_INIT;

/* dissector handles */
static dissector_handle_t xml_handle;

/* parser definitions */
static tvbparse_wanted_t *want;
static tvbparse_wanted_t *want_ignore;
static tvbparse_wanted_t *want_heur;

static wmem_map_t *xmpli_names;
static wmem_map_t *media_types;

static xml_ns_t xml_ns     = {"xml",     "/", -1, -1, -1, NULL, NULL, NULL};
static xml_ns_t unknown_ns = {"unknown", "?", -1, -1, -1, NULL, NULL, NULL};
static xml_ns_t *root_ns;

static gboolean pref_heuristic_unicode    = FALSE;


#define XML_CDATA       -1000
#define XML_SCOPED_NAME -1001


static wmem_array_t *hf_arr;
static GArray *ett_arr;

static const gchar *default_media_types[] = {
    "text/xml",
    "text/vnd.wap.wml",
    "text/vnd.wap.si",
    "text/vnd.wap.sl",
    "text/vnd.wap.co",
    "text/vnd.wap.emn",
    "application/3gpp-ims+xml",
    "application/atom+xml",
    "application/auth-policy+xml",
    "application/ccmp+xml",
    "application/conference-info+xml",          /*RFC4575*/
    "application/cpim-pidf+xml",
    "application/cpl+xml",
    "application/dds-web+xml",
    "application/im-iscomposing+xml",           /*RFC3994*/
    "application/load-control+xml",             /*RFC7200*/
    "application/mathml+xml",
    "application/media_control+xml",
    "application/note+xml",
    "application/pidf+xml",
    "application/pidf-diff+xml",
    "application/poc-settings+xml",
    "application/rdf+xml",
    "application/reginfo+xml",
    "application/resource-lists+xml",
    "application/rlmi+xml",
    "application/rls-services+xml",
    "application/rss+xml",
    "application/rs-metadata+xml",
    "application/smil",
    "application/simple-filter+xml",
    "application/simple-message-summary+xml",   /*RFC3842*/
    "application/simservs+xml",
    "application/soap+xml",
    "application/vnd.etsi.aoc+xml",
    "application/vnd.etsi.cug+xml",
    "application/vnd.etsi.iptvcommand+xml",
    "application/vnd.etsi.iptvdiscovery+xml",
    "application/vnd.etsi.iptvprofile+xml",
    "application/vnd.etsi.iptvsad-bc+xml",
    "application/vnd.etsi.iptvsad-cod+xml",
    "application/vnd.etsi.iptvsad-npvr+xml",
    "application/vnd.etsi.iptvservice+xml",
    "application/vnd.etsi.iptvsync+xml",
    "application/vnd.etsi.iptvueprofile+xml",
    "application/vnd.etsi.mcid+xml",
    "application/vnd.etsi.overload-control-policy-dataset+xml",
    "application/vnd.etsi.pstn+xml",
    "application/vnd.etsi.sci+xml",
    "application/vnd.etsi.simservs+xml",
    "application/vnd.etsi.tsl+xml",
    "application/vnd.oma.xdm-apd+xml",
    "application/vnd.oma.fnl+xml",
    "application/vnd.oma.access-permissions-list+xml",
    "application/vnd.oma.alias-principals-list+xml",
    "application/upp-directory+xml",            /*OMA-ERELD-XDM-V2_2_1-20170124-A*/
    "application/vnd.oma.xdm-hi+xml",
    "application/vnd.oma.xdm-rhi+xml",
    "application/vnd.oma.xdm-prefs+xml",
    "application/vnd.oma.xdcp+xml",
    "application/vnd.oma.bcast.associated-procedure-parameter+xml",
    "application/vnd.oma.bcast.drm-trigger+xml",
    "application/vnd.oma.bcast.imd+xml",
    "application/vnd.oma.bcast.notification+xml",
    "application/vnd.oma.bcast.sgdd+xml",
    "application/vnd.oma.bcast.smartcard-trigger+xml",
    "application/vnd.oma.bcast.sprov+xml",
    "application/vnd.oma.cab-address-book+xml",
    "application/vnd.oma.cab-feature-handler+xml",
    "application/vnd.oma.cab-pcc+xml",
    "application/vnd.oma.cab-subs-invite+xml",
    "application/vnd.oma.cab-user-prefs+xml",
    "application/vnd.oma.dd2+xml",
    "application/vnd.oma.drm.risd+xml",
    "application/vnd.oma.group-usage-list+xml",
    "application/vnd.oma.pal+xml",
    "application/vnd.oma.poc.detailed-progress-report+xml",
    "application/vnd.oma.poc.final-report+xml",
    "application/vnd.oma.poc.groups+xml",
    "application/vnd.oma.poc.invocation-descriptor+xml",
    "application/vnd.oma.poc.optimized-progress-report+xml",
    "application/vnd.oma.scidm.messages+xml",
    "application/vnd.oma.suppnot+xml",          /*OMA-ERELD-Presence_SIMPLE-V2_0-20120710-A*/
    "application/vnd.oma.xcap-directory+xml",
    "application/vnd.omads-email+xml",
    "application/vnd.omads-file+xml",
    "application/vnd.omads-folder+xml",
    "application/vnd.3gpp.access-transfer-events+xml",
    "application/vnd.3gpp.bsf+xml",
    "application/vnd.3gpp.comm-div-info+xml",   /*3GPP TS 24.504  version 8.19.0*/
    "application/vnd.3gpp.cw+xml",
    "application/vnd.3gpp.iut+xml",             /*3GPP TS 24.337*/
    "application/vnc.3gpp.iut-config+xml",      /*3GPP TS 24.337*/
    "application/vnd.3gpp.mid-call+xml",
    "application/vnd.3gpp-prose-pc3ch+xml",
    "application/vnd.3gpp-prose+xml",
    "application/vnd.3gpp.replication+xml",     /*3GPP TS 24.337*/
    "application/vnd.3gpp.sms+xml",
    "application/vnd.3gpp.srvcc-info+xml",
    "application/vnd.3gpp.srvcc-ext+xml",
    "application/vnd.3gpp.state-and-event-info+xml",
    "application/vnd.3gpp.ussd+xml",
    "application/vnd.3gpp2.bcmcsinfo+xml",
    "application/vnd.wv.csp+xml",
    "application/vnd.wv.csp.xml",
    "application/watcherinfo+xml",
    "application/xcap-att+xml",
    "application/xcap-caps+xml",
    "application/xcap-diff+xml",
    "application/xcap-el+xml",
    "application/xcap-error+xml",
    "application/xcap-ns+xml",
    "application/xml",
    "application/xml-dtd",
    "application/xpidf+xml",
    "application/xslt+xml",
    "application/x-crd+xml",
    "application/x-wms-logconnectstats",
    "application/x-wms-logplaystats",
    "application/x-wms-sendevent",
    "image/svg+xml",
    "message/imdn+xml",                         /*RFC5438*/
};

static void insert_xml_frame(xml_frame_t *parent, xml_frame_t *new_child)
{
    new_child->first_child  = NULL;
    new_child->last_child   = NULL;

    new_child->parent       = parent;
    new_child->next_sibling = NULL;
    new_child->prev_sibling = NULL;
    if (parent == NULL) return;  /* root */

    if (parent->first_child == NULL) {  /* the 1st child */
        parent->first_child = new_child;
    } else {  /* following children */
        parent->last_child->next_sibling = new_child;
        new_child->prev_sibling = parent->last_child;
    }
    parent->last_child = new_child;
}

static int
dissect_xml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbparse_t       *tt;
    static GPtrArray *stack;
    xml_frame_t      *current_frame;
    const char       *colinfo_str;
    tvbuff_t         *decoded;
    guint16           try_bom;
    int               start_offset   = 0;

    if (stack != NULL)
        g_ptr_array_free(stack, TRUE);

    stack = g_ptr_array_new();
    current_frame                 = wmem_new(wmem_packet_scope(), xml_frame_t);
    current_frame->type           = XML_FRAME_ROOT;
    current_frame->name           = NULL;
    current_frame->name_orig_case = NULL;
    current_frame->value          = NULL;
    current_frame->pinfo          = pinfo;
    insert_xml_frame(NULL, current_frame);
    g_ptr_array_add(stack, current_frame);

    /* Detect and act on possible byte-order mark (BOM) */
    try_bom = tvb_get_ntohs(tvb, start_offset);
    if (try_bom == 0xFEFF) {
        /* UTF-16BE */
        const guint8 *data_str = tvb_get_string_enc(pinfo->pool, tvb, 0, tvb_captured_length(tvb), ENC_UTF_16|ENC_BIG_ENDIAN);
        size_t l = strlen(data_str);
        decoded = tvb_new_child_real_data(tvb, data_str, (guint)l, (gint)l);
        add_new_data_source(pinfo, decoded, "Decoded UTF-16BE text");
    }
    else if(try_bom == 0xFFFE) {
        /* UTF-16LE (or possibly UTF-32LE, but Wireshark doesn't support UTF-32) */
        const guint8 *data_str = tvb_get_string_enc(pinfo->pool, tvb, 0, tvb_captured_length(tvb), ENC_UTF_16|ENC_LITTLE_ENDIAN);
        size_t l = strlen(data_str);
        decoded = tvb_new_child_real_data(tvb, data_str, (guint)l, (gint)l);
        add_new_data_source(pinfo, decoded, "Decoded UTF-16LE text");
    }
    /* Could also test if try_bom is 0xnn00 or 0x00nn to guess endianness if we wanted */
    else if(tvb_get_ntoh24(tvb, start_offset) == 0xEFBBBF) {
        /* UTF-8 BOM; just skip over it */
        decoded = tvb;
        start_offset += 3;
    }
    else {
        /* Assume it's UTF-8 */
        decoded = tvb;
    }

    tt = tvbparse_init(decoded, start_offset, -1, stack, want_ignore);
    current_frame->start_offset = 0;
    current_frame->length = tvb_captured_length(decoded) - start_offset;

    root_ns = NULL;

    if (pinfo->match_string)
        root_ns = (xml_ns_t *)wmem_map_lookup(media_types, pinfo->match_string);

    if (! root_ns ) {
        root_ns = &xml_ns;
        colinfo_str = "/XML";
    } else {
        char *colinfo_str_buf;
        colinfo_str_buf = wmem_strconcat(wmem_packet_scope(), "/", root_ns->name, NULL);
        ascii_strup_inplace(colinfo_str_buf);
        colinfo_str = colinfo_str_buf;
    }

    col_append_str(pinfo->cinfo, COL_PROTOCOL, colinfo_str);

    current_frame->ns = root_ns;

    current_frame->item = proto_tree_add_item(tree, current_frame->ns->hf_tag, decoded, start_offset, -1, ENC_UTF_8|ENC_NA);
    current_frame->tree = proto_item_add_subtree(current_frame->item, current_frame->ns->ett);
    current_frame->last_item = current_frame->item;

    while(tvbparse_get(tt, want)) ;

    /* Save XML structure in case it is useful for the caller (only XMPP for now) */
    p_add_proto_data(pinfo->pool, pinfo, xml_ns.hf_tag, 0, current_frame);

    return tvb_captured_length(tvb);
}

static gboolean dissect_xml_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvbparse_peek(tvbparse_init(tvb, 0, -1, NULL, want_ignore), want_heur)) {
        dissect_xml(tvb, pinfo, tree, data);
        return TRUE;
    } else if (pref_heuristic_unicode) {
        const guint8 *data_str;
        tvbuff_t     *unicode_tvb;
        guint16       try_bom;
        /* XXX - UCS-2, or UTF-16? */
        gint          enc = ENC_UCS_2|ENC_LITTLE_ENDIAN;
        size_t        l;

        try_bom = tvb_get_ntohs(tvb, 0);
        if (try_bom == 0xFEFF) {
            enc = ENC_UTF_16|ENC_BIG_ENDIAN;
        }
        else if(try_bom == 0xFFFE) {
            enc = ENC_UTF_16|ENC_LITTLE_ENDIAN;
        }

        data_str    = tvb_get_string_enc(pinfo->pool, tvb, 0, tvb_captured_length(tvb), enc);
        l           = strlen(data_str);
        unicode_tvb = tvb_new_child_real_data(tvb, data_str, (guint)l, (gint)l);
        if (tvbparse_peek(tvbparse_init(unicode_tvb, 0, -1, NULL, want_ignore), want_heur)) {
            add_new_data_source(pinfo, unicode_tvb, "UTF8");
            dissect_xml(unicode_tvb, pinfo, tree, data);
            return TRUE;
        }
    }
    return FALSE;
}

xml_frame_t *xml_get_tag(xml_frame_t *frame, const gchar *name)
{
    xml_frame_t *tag = NULL;

    xml_frame_t *xml_item = frame->first_child;
    while (xml_item) {
        if (xml_item->type == XML_FRAME_TAG) {
            if (!name) {  /* get the 1st tag */
                tag = xml_item;
                break;
            } else if (xml_item->name_orig_case && !strcmp(xml_item->name_orig_case, name)) {
                tag = xml_item;
                break;
            }
        }
        xml_item = xml_item->next_sibling;
    }

    return tag;
}

xml_frame_t *xml_get_attrib(xml_frame_t *frame, const gchar *name)
{
    xml_frame_t *attr = NULL;

    xml_frame_t *xml_item = frame->first_child;
    while (xml_item) {
        if ((xml_item->type == XML_FRAME_ATTRIB) &&
            xml_item->name_orig_case && !strcmp(xml_item->name_orig_case, name)) {
            attr = xml_item;
            break;
        }
        xml_item = xml_item->next_sibling;
    }

    return attr;
}

xml_frame_t *xml_get_cdata(xml_frame_t *frame)
{
    xml_frame_t *cdata = NULL;

    xml_frame_t *xml_item = frame->first_child;
    while (xml_item) {
        if (xml_item->type == XML_FRAME_CDATA) {
            cdata = xml_item;
            break;
        }
        xml_item = xml_item->next_sibling;
    }

    return cdata;
}

static void after_token(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);
    int          hfid;
    gboolean     is_cdata      = FALSE;
    proto_item  *pi;
    xml_frame_t *new_frame;

    if (tok->id == XML_CDATA) {
        hfid = current_frame->ns ? current_frame->ns->hf_cdata : xml_ns.hf_cdata;
        is_cdata = TRUE;
    } else if ( tok->id > 0) {
        hfid = tok->id;
    } else {
        hfid = xml_ns.hf_cdata;
    }

    pi = proto_tree_add_item(current_frame->tree, hfid, tok->tvb, tok->offset, tok->len, ENC_UTF_8|ENC_NA);

    proto_item_set_text(pi, "%s",
                        tvb_format_text(tok->tvb, tok->offset, tok->len));

    if (is_cdata) {
        new_frame                 = wmem_new(wmem_packet_scope(), xml_frame_t);
        new_frame->type           = XML_FRAME_CDATA;
        new_frame->name           = NULL;
        new_frame->name_orig_case = NULL;
        new_frame->value          = tvb_new_subset_length(tok->tvb, tok->offset, tok->len);
        insert_xml_frame(current_frame, new_frame);
        new_frame->item           = pi;
        new_frame->last_item      = pi;
        new_frame->tree           = NULL;
        new_frame->start_offset   = tok->offset;
        new_frame->length         = tok->len;
        new_frame->ns             = NULL;
        new_frame->pinfo          = current_frame->pinfo;
    }
}

static void before_xmpli(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray       *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t     *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);
    proto_item      *pi;
    proto_tree      *pt;
    tvbparse_elem_t *name_tok      = tok->sub->next;
    gchar           *name          = tvb_get_string_enc(wmem_packet_scope(), name_tok->tvb, name_tok->offset, name_tok->len, ENC_ASCII);
    xml_ns_t        *ns            = (xml_ns_t *)wmem_map_lookup(xmpli_names, name);
    xml_frame_t     *new_frame;

    int  hf_tag;
    gint ett;

    ascii_strdown_inplace(name);
    if (!ns) {
        hf_tag = hf_xmlpi;
        ett = ett_xmpli;
    } else {
        hf_tag = ns->hf_tag;
        ett = ns->ett;
    }

    pi = proto_tree_add_item(current_frame->tree, hf_tag, tok->tvb, tok->offset, tok->len, ENC_UTF_8|ENC_NA);

    proto_item_set_text(pi, "%s", tvb_format_text(tok->tvb, tok->offset, (name_tok->offset - tok->offset) + name_tok->len));

    pt = proto_item_add_subtree(pi, ett);

    new_frame                 = wmem_new(wmem_packet_scope(), xml_frame_t);
    new_frame->type           = XML_FRAME_XMPLI;
    new_frame->name           = name;
    new_frame->name_orig_case = name;
    new_frame->value          = NULL;
    insert_xml_frame(current_frame, new_frame);
    new_frame->item           = pi;
    new_frame->last_item      = pi;
    new_frame->tree           = pt;
    new_frame->start_offset   = tok->offset;
    new_frame->length         = tok->len;
    new_frame->ns             = ns;
    new_frame->pinfo          = current_frame->pinfo;

    g_ptr_array_add(stack, new_frame);

}

static void after_xmlpi(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);

    proto_tree_add_format_text(current_frame->tree, tok->tvb, tok->offset, tok->len);

    if (stack->len > 1) {
        g_ptr_array_remove_index_fast(stack, stack->len - 1);
    } else {
        proto_tree_add_expert(current_frame->tree, current_frame->pinfo, &ei_xml_closing_unopened_xmpli_tag,
            tok->tvb, tok->offset, tok->len);
    }
}

static void before_tag(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray       *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t     *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);
    tvbparse_elem_t *name_tok      = tok->sub->next;
    gchar           *root_name;
    gchar           *name          = NULL, *name_orig_case = NULL;
    xml_ns_t        *ns;
    xml_frame_t     *new_frame;
    proto_item      *pi;
    proto_tree      *pt;

    if (name_tok->sub->id == XML_SCOPED_NAME) {
        tvbparse_elem_t *root_tok = name_tok->sub->sub;
        tvbparse_elem_t *leaf_tok = name_tok->sub->sub->next->next;
        xml_ns_t        *nameroot_ns;

        root_name      = (gchar *)tvb_get_string_enc(wmem_packet_scope(), root_tok->tvb, root_tok->offset, root_tok->len, ENC_ASCII);
        name           = (gchar *)tvb_get_string_enc(wmem_packet_scope(), leaf_tok->tvb, leaf_tok->offset, leaf_tok->len, ENC_ASCII);
        name_orig_case = name;

        nameroot_ns = (xml_ns_t *)wmem_map_lookup(xml_ns.elements, root_name);

        if(nameroot_ns) {
            ns = (xml_ns_t *)wmem_map_lookup(nameroot_ns->elements, name);
            if (!ns) {
                ns = &unknown_ns;
            }
        } else {
            ns = &unknown_ns;
        }

    } else {
        name = tvb_get_string_enc(wmem_packet_scope(), name_tok->tvb, name_tok->offset, name_tok->len, ENC_ASCII);
        name_orig_case = wmem_strdup(wmem_packet_scope(), name);
        ascii_strdown_inplace(name);

        if(current_frame->ns) {
            ns = (xml_ns_t *)wmem_map_lookup(current_frame->ns->elements, name);

            if (!ns) {
                if (! ( ns = (xml_ns_t *)wmem_map_lookup(root_ns->elements, name) ) ) {
                    ns = &unknown_ns;
                }
            }
        } else {
            ns = &unknown_ns;
        }
    }

    pi = proto_tree_add_item(current_frame->tree, ns->hf_tag, tok->tvb, tok->offset, tok->len, ENC_UTF_8|ENC_NA);
    proto_item_set_text(pi, "%s", tvb_format_text(tok->tvb,
                                                  tok->offset,
                                                  (name_tok->offset - tok->offset) + name_tok->len));

    pt = proto_item_add_subtree(pi, ns->ett);

    new_frame = wmem_new(wmem_packet_scope(), xml_frame_t);
    new_frame->type           = XML_FRAME_TAG;
    new_frame->name           = name;
    new_frame->name_orig_case = name_orig_case;
    new_frame->value          = NULL;
    insert_xml_frame(current_frame, new_frame);
    new_frame->item           = pi;
    new_frame->last_item      = pi;
    new_frame->tree           = pt;
    new_frame->start_offset   = tok->offset;
    new_frame->length         = tok->len;
    new_frame->ns             = ns;
    new_frame->pinfo          = current_frame->pinfo;

    g_ptr_array_add(stack, new_frame);

}

static void after_open_tag(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok _U_)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);

    proto_item_append_text(current_frame->last_item, ">");
}

static void after_closed_tag(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);

    proto_item_append_text(current_frame->last_item, "/>");

    if (stack->len > 1) {
        g_ptr_array_remove_index_fast(stack, stack->len - 1);
    } else {
        proto_tree_add_expert(current_frame->tree, current_frame->pinfo, &ei_xml_closing_unopened_tag,
                              tok->tvb, tok->offset, tok->len);
    }
}

static void after_untag(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);

    proto_item_set_len(current_frame->item, (tok->offset - current_frame->start_offset) + tok->len);
    current_frame->length = (tok->offset - current_frame->start_offset) + tok->len;

    proto_tree_add_format_text(current_frame->tree, tok->tvb, tok->offset, tok->len);

    if (stack->len > 1) {
        g_ptr_array_remove_index_fast(stack, stack->len - 1);
    } else {
        proto_tree_add_expert(current_frame->tree, current_frame->pinfo, &ei_xml_closing_unopened_tag,
            tok->tvb, tok->offset, tok->len);
    }
}

static void before_dtd_doctype(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray       *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t     *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);
    xml_frame_t     *new_frame;
    tvbparse_elem_t *name_tok      = tok->sub->next->next->next->sub->sub;
    proto_tree      *dtd_item      = proto_tree_add_item(current_frame->tree, hf_doctype,
                                                         name_tok->tvb, name_tok->offset,
                                                         name_tok->len, ENC_ASCII|ENC_NA);

    proto_item_set_text(dtd_item, "%s", tvb_format_text(tok->tvb, tok->offset, tok->len));

    new_frame = wmem_new(wmem_packet_scope(), xml_frame_t);
    new_frame->type           = XML_FRAME_DTD_DOCTYPE;
    new_frame->name           = (gchar *)tvb_get_string_enc(wmem_packet_scope(), name_tok->tvb,
                                                                  name_tok->offset,
                                                                  name_tok->len, ENC_ASCII);
    new_frame->name_orig_case = new_frame->name;
    new_frame->value          = NULL;
    insert_xml_frame(current_frame, new_frame);
    new_frame->item           = dtd_item;
    new_frame->last_item      = dtd_item;
    new_frame->tree           = proto_item_add_subtree(dtd_item, ett_dtd);
    new_frame->start_offset   = tok->offset;
    new_frame->length         = tok->len;
    new_frame->ns             = NULL;
    new_frame->pinfo          = current_frame->pinfo;

    g_ptr_array_add(stack, new_frame);
}

static void pop_stack(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok _U_)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);

    if (stack->len > 1) {
        g_ptr_array_remove_index_fast(stack, stack->len - 1);
    } else {
        proto_tree_add_expert(current_frame->tree, current_frame->pinfo, &ei_xml_closing_unopened_tag,
            tok->tvb, tok->offset, tok->len);
    }
}

static void after_dtd_close(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);

    proto_tree_add_format_text(current_frame->tree, tok->tvb, tok->offset, tok->len);
    if (stack->len > 1) {
        g_ptr_array_remove_index_fast(stack, stack->len - 1);
    } else {
        proto_tree_add_expert(current_frame->tree, current_frame->pinfo, &ei_xml_closing_unopened_tag,
            tok->tvb, tok->offset, tok->len);
    }
}

static void get_attrib_value(void *tvbparse_data _U_, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    tok->data = tok->sub;
}

static void after_attrib(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray       *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t     *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);
    gchar           *name, *name_orig_case;
    tvbparse_elem_t *value;
    tvbparse_elem_t *value_part    = (tvbparse_elem_t *)tok->sub->next->next->data;
    int             *hfidp;
    int              hfid;
    proto_item      *pi;
    xml_frame_t     *new_frame;

    name           = tvb_get_string_enc(wmem_packet_scope(), tok->sub->tvb, tok->sub->offset, tok->sub->len, ENC_ASCII);
    name_orig_case = wmem_strdup(wmem_packet_scope(), name);
    ascii_strdown_inplace(name);

    if(current_frame->ns && (hfidp = (int *)wmem_map_lookup(current_frame->ns->attributes, name) )) {
        hfid  = *hfidp;
        value = value_part;
    } else {
        hfid  = hf_unknowwn_attrib;
        value = tok;
    }

    pi = proto_tree_add_item(current_frame->tree, hfid, value->tvb, value->offset, value->len, ENC_UTF_8|ENC_NA);
    proto_item_set_text(pi, "%s", tvb_format_text(tok->tvb, tok->offset, tok->len));

    current_frame->last_item = pi;

    new_frame = wmem_new(wmem_packet_scope(), xml_frame_t);
    new_frame->type           = XML_FRAME_ATTRIB;
    new_frame->name           = name;
    new_frame->name_orig_case = name_orig_case;
    new_frame->value          = tvb_new_subset_length(value_part->tvb, value_part->offset,
                           value_part->len);
    insert_xml_frame(current_frame, new_frame);
    new_frame->item           = pi;
    new_frame->last_item      = pi;
    new_frame->tree           = NULL;
    new_frame->start_offset   = tok->offset;
    new_frame->length         = tok->len;
    new_frame->ns             = NULL;
    new_frame->pinfo          = current_frame->pinfo;

}

static void unrecognized_token(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok _U_)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);

    proto_tree_add_expert(current_frame->tree, current_frame->pinfo, &ei_xml_unrecognized_text,
                    tok->tvb, tok->offset, tok->len);

}



static void init_xml_parser(void)
{
    tvbparse_wanted_t *want_name =
        tvbparse_chars(-1, 1, 0,
                   "abcdefghijklmnopqrstuvwxyz.-_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                   NULL, NULL, NULL);
    tvbparse_wanted_t *want_attr_name =
        tvbparse_chars(-1, 1, 0,
                   "abcdefghijklmnopqrstuvwxyz.-_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:",
                   NULL, NULL, NULL);

    tvbparse_wanted_t *want_scoped_name = tvbparse_set_seq(XML_SCOPED_NAME, NULL, NULL, NULL,
                                   want_name,
                                   tvbparse_char(-1, ":", NULL, NULL, NULL),
                                   want_name,
                                   NULL);

    tvbparse_wanted_t *want_tag_name = tvbparse_set_oneof(0, NULL, NULL, NULL,
                                  want_scoped_name,
                                  want_name,
                                  NULL);

    tvbparse_wanted_t *want_attrib_value = tvbparse_set_oneof(0, NULL, NULL, get_attrib_value,
                                  tvbparse_quoted(-1, NULL, NULL, tvbparse_shrink_token_cb, '\"', '\\'),
                                  tvbparse_quoted(-1, NULL, NULL, tvbparse_shrink_token_cb, '\'', '\\'),
                                  tvbparse_chars(-1, 1, 0, "0123456789", NULL, NULL, NULL),
                                  want_name,
                                  NULL);

    tvbparse_wanted_t *want_attributes = tvbparse_one_or_more(-1, NULL, NULL, NULL,
                                  tvbparse_set_seq(-1, NULL, NULL, after_attrib,
                                           want_attr_name,
                                           tvbparse_char(-1, "=", NULL, NULL, NULL),
                                           want_attrib_value,
                                           NULL));

    tvbparse_wanted_t *want_stoptag = tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                 tvbparse_char(-1, ">", NULL, NULL, after_open_tag),
                                 tvbparse_string(-1, "/>", NULL, NULL, after_closed_tag),
                                 NULL);

    tvbparse_wanted_t *want_stopxmlpi = tvbparse_string(-1, "?>", NULL, NULL, after_xmlpi);

    tvbparse_wanted_t *want_comment = tvbparse_set_seq(hf_comment, NULL, NULL, after_token,
                               tvbparse_string(-1, "<!--", NULL, NULL, NULL),
                               tvbparse_until(-1, NULL, NULL, NULL,
                                      tvbparse_string(-1, "-->", NULL, NULL, NULL),
                                      TP_UNTIL_INCLUDE),
                               NULL);

    tvbparse_wanted_t *want_cdatasection = tvbparse_set_seq(hf_cdatasection, NULL, NULL, after_token,
                               tvbparse_string(-1, "<![CDATA[", NULL, NULL, NULL),
                               tvbparse_until(-1, NULL, NULL, NULL,
                                       tvbparse_string(-1, "]]>", NULL, NULL, NULL),
                                       TP_UNTIL_INCLUDE),
                                NULL);

    tvbparse_wanted_t *want_xmlpi = tvbparse_set_seq(hf_xmlpi, NULL, before_xmpli, NULL,
                             tvbparse_string(-1, "<?", NULL, NULL, NULL),
                             want_name,
                             tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                        want_stopxmlpi,
                                        tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                 want_attributes,
                                                 want_stopxmlpi,
                                                 NULL),
                                        NULL),
                             NULL);

    tvbparse_wanted_t *want_closing_tag = tvbparse_set_seq(0, NULL, NULL, after_untag,
                                   tvbparse_char(-1, "<", NULL, NULL, NULL),
                                   tvbparse_char(-1, "/", NULL, NULL, NULL),
                                   want_tag_name,
                                   tvbparse_char(-1, ">", NULL, NULL, NULL),
                                   NULL);

    tvbparse_wanted_t *want_doctype_start = tvbparse_set_seq(-1, NULL, before_dtd_doctype, NULL,
                                 tvbparse_char(-1, "<", NULL, NULL, NULL),
                                 tvbparse_char(-1, "!", NULL, NULL, NULL),
                                 tvbparse_casestring(-1, "DOCTYPE", NULL, NULL, NULL),
                                 tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                            tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                     want_name,
                                                     tvbparse_char(-1, "[", NULL, NULL, NULL),
                                                     NULL),
                                            tvbparse_set_seq(-1, NULL, NULL, pop_stack,
                                                     want_name,
                                                     tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                                            tvbparse_casestring(-1, "PUBLIC", NULL, NULL, NULL),
                                                            tvbparse_casestring(-1, "SYSTEM", NULL, NULL, NULL),
                                                            NULL),
                                                     tvbparse_until(-1, NULL, NULL, NULL,
                                                            tvbparse_char(-1, ">", NULL, NULL, NULL),
                                                            TP_UNTIL_INCLUDE),
                                                     NULL),
                                            NULL),
                                 NULL);

    tvbparse_wanted_t *want_dtd_tag = tvbparse_set_seq(hf_dtd_tag, NULL, NULL, after_token,
                               tvbparse_char(-1, "<", NULL, NULL, NULL),
                               tvbparse_char(-1, "!", NULL, NULL, NULL),
                               tvbparse_until(-1, NULL, NULL, NULL,
                                      tvbparse_char(-1, ">", NULL, NULL, NULL),
                                      TP_UNTIL_INCLUDE),
                               NULL);

    tvbparse_wanted_t *want_tag = tvbparse_set_seq(-1, NULL, before_tag, NULL,
                               tvbparse_char(-1, "<", NULL, NULL, NULL),
                               want_tag_name,
                               tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                      tvbparse_set_seq(-1, NULL, NULL, NULL,
                                               want_attributes,
                                               want_stoptag,
                                               NULL),
                                      want_stoptag,
                                      NULL),
                               NULL);

    tvbparse_wanted_t *want_dtd_close = tvbparse_set_seq(-1, NULL, NULL, after_dtd_close,
                                 tvbparse_char(-1, "]", NULL, NULL, NULL),
                                 tvbparse_char(-1, ">", NULL, NULL, NULL),
                                 NULL);

    want_ignore = tvbparse_chars(-1, 1, 0, " \t\r\n", NULL, NULL, NULL);


    want = tvbparse_set_oneof(-1, NULL, NULL, NULL,
                  want_comment,
                  want_cdatasection,
                  want_xmlpi,
                  want_closing_tag,
                  want_doctype_start,
                  want_dtd_close,
                  want_dtd_tag,
                  want_tag,
                  tvbparse_not_chars(XML_CDATA, 1, 0, "<", NULL, NULL, after_token),
                  tvbparse_not_chars(-1, 1, 0, " \t\r\n", NULL, NULL, unrecognized_token),
                  NULL);

    want_heur = tvbparse_set_oneof(-1, NULL, NULL, NULL,
                       want_comment,
                       want_cdatasection,
                       want_xmlpi,
                       want_doctype_start,
                       want_dtd_tag,
                       want_tag,
                       NULL);

}


static xml_ns_t *xml_new_namespace(wmem_map_t *hash, const gchar *name, ...)
{
    xml_ns_t *ns = wmem_new(wmem_epan_scope(), xml_ns_t);
    va_list   ap;
    gchar    *attr_name;

    ns->name       = wmem_strdup(wmem_epan_scope(), name);
    ns->hf_tag     = -1;
    ns->hf_cdata   = -1;
    ns->ett        = -1;
    ns->attributes = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    ns->elements   = NULL;

    va_start(ap, name);

    while(( attr_name = va_arg(ap, gchar *) )) {
        int *hfp = wmem_new(wmem_epan_scope(), int);
        *hfp = -1;
        wmem_map_insert(ns->attributes, wmem_strdup(wmem_epan_scope(), attr_name), hfp);
    };

    va_end(ap);

    wmem_map_insert(hash, ns->name, ns);

    return ns;
}


static void add_xml_field(wmem_array_t *hfs, int *p_id, const gchar *name, const gchar *fqn)
{
    hf_register_info hfri;

    hfri.p_id          = p_id;
    hfri.hfinfo.name           = name;
    hfri.hfinfo.abbrev         = fqn;
    hfri.hfinfo.type           = FT_STRING;
    hfri.hfinfo.display        = BASE_NONE;
    hfri.hfinfo.strings        = NULL;
    hfri.hfinfo.bitmask        = 0x0;
    hfri.hfinfo.blurb          = NULL;
    HFILL_INIT(hfri);

    wmem_array_append_one(hfs, hfri);
}

static void add_xml_attribute_names(gpointer k, gpointer v, gpointer p)
{
    struct _attr_reg_data *d = (struct _attr_reg_data *)p;
    const gchar *basename = wmem_strconcat(wmem_epan_scope(), d->basename, ".", (gchar *)k, NULL);

    add_xml_field(d->hf, (int*) v, (gchar *)k, basename);
}


static void add_xmlpi_namespace(gpointer k _U_, gpointer v, gpointer p)
{
    xml_ns_t *ns       = (xml_ns_t *)v;
    const gchar *basename = wmem_strconcat(wmem_epan_scope(), (gchar *)p, ".", ns->name, NULL);
    gint     *ett_p    = &(ns->ett);
    struct _attr_reg_data d;

    add_xml_field(hf_arr, &(ns->hf_tag), basename, basename);

    g_array_append_val(ett_arr, ett_p);

    d.basename = basename;
    d.hf = hf_arr;

    wmem_map_foreach(ns->attributes, add_xml_attribute_names, &d);

}

static void destroy_dtd_data(dtd_build_data_t *dtd_data)
{
    g_free(dtd_data->proto_name);
    g_free(dtd_data->media_type);
    g_free(dtd_data->description);
    g_free(dtd_data->proto_root);

    g_string_free(dtd_data->error, TRUE);

    while(dtd_data->elements->len) {
        dtd_named_list_t *nl = (dtd_named_list_t *)g_ptr_array_remove_index_fast(dtd_data->elements, 0);
        g_ptr_array_free(nl->list, TRUE);
        g_free(nl->name);
        g_free(nl);
    }

    g_ptr_array_free(dtd_data->elements, TRUE);

    while(dtd_data->attributes->len) {
        dtd_named_list_t *nl = (dtd_named_list_t *)g_ptr_array_remove_index_fast(dtd_data->attributes, 0);
        g_ptr_array_free(nl->list, TRUE);
        g_free(nl->name);
        g_free(nl);
    }

    g_ptr_array_free(dtd_data->attributes, TRUE);

    g_free(dtd_data);
}

static void copy_attrib_item(gpointer k, gpointer v _U_, gpointer p)
{
    gchar      *key   = (gchar *)wmem_strdup(wmem_epan_scope(), (const gchar *)k);
    int        *value = wmem_new(wmem_epan_scope(), int);
    wmem_map_t *dst   = (wmem_map_t *)p;

    *value = -1;
    wmem_map_insert(dst, key, value);

}

static wmem_map_t *copy_attributes_hash(wmem_map_t *src)
{
    wmem_map_t *dst = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    wmem_map_foreach(src, copy_attrib_item, dst);

    return dst;
}

static xml_ns_t *duplicate_element(xml_ns_t *orig)
{
    xml_ns_t *new_item = wmem_new(wmem_epan_scope(), xml_ns_t);
    guint     i;

    new_item->name          = wmem_strdup(wmem_epan_scope(), orig->name);
    new_item->hf_tag        = -1;
    new_item->hf_cdata      = -1;
    new_item->ett           = -1;
    new_item->attributes    = copy_attributes_hash(orig->attributes);
    new_item->elements      = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    new_item->element_names = g_ptr_array_new();

    for(i=0; i < orig->element_names->len; i++) {
        g_ptr_array_add(new_item->element_names,
                           g_ptr_array_index(orig->element_names, i));
    }

    return new_item;
}

static gchar *fully_qualified_name(GPtrArray *hier, gchar *name, gchar *proto_name)
{
    guint    i;
    wmem_strbuf_t *s = wmem_strbuf_new(wmem_epan_scope(), proto_name);

    wmem_strbuf_append(s, ".");

    for (i = 1; i < hier->len; i++) {
        wmem_strbuf_append_printf(s, "%s.", (gchar *)g_ptr_array_index(hier, i));
    }

    wmem_strbuf_append(s, name);

    return wmem_strbuf_finalize(s);;
}


static xml_ns_t *make_xml_hier(gchar      *elem_name,
                               xml_ns_t   *root,
                               wmem_map_t *elements,
                               GPtrArray  *hier,
                               GString    *error,
                               wmem_array_t *hfs,
                               GArray     *etts,
                               char       *proto_name)
{
    xml_ns_t *fresh;
    xml_ns_t *orig;
    gchar    *fqn;
    gint     *ett_p;
    gboolean  recurred = FALSE;
    guint     i;
    struct _attr_reg_data  d;

    if ( g_str_equal(elem_name, root->name) ) {
        return NULL;
    }

    if (! ( orig = (xml_ns_t *)wmem_map_lookup(elements, elem_name) )) {
        g_string_append_printf(error, "element '%s' is not defined\n", elem_name);
        return NULL;
    }

    for (i = 0; i < hier->len; i++) {
        if( (elem_name) && (strcmp(elem_name, (gchar *) g_ptr_array_index(hier, i) ) == 0 )) {
            recurred = TRUE;
        }
    }

    if (recurred) {
        return NULL;
    }

    fqn = fully_qualified_name(hier, elem_name, proto_name);

    fresh = duplicate_element(orig);
    fresh->fqn = fqn;

    add_xml_field(hfs, &(fresh->hf_tag), wmem_strdup(wmem_epan_scope(), elem_name), fqn);
    add_xml_field(hfs, &(fresh->hf_cdata), wmem_strdup(wmem_epan_scope(), elem_name), fqn);

    ett_p = &fresh->ett;
    g_array_append_val(etts, ett_p);

    d.basename = fqn;
    d.hf = hfs;

    wmem_map_foreach(fresh->attributes, add_xml_attribute_names, &d);

    while(fresh->element_names->len) {
        gchar *child_name = (gchar *)g_ptr_array_remove_index(fresh->element_names, 0);
        xml_ns_t *child_element = NULL;

        g_ptr_array_add(hier, elem_name);
        child_element = make_xml_hier(child_name, root, elements, hier, error, hfs, etts, proto_name);
        g_ptr_array_remove_index_fast(hier, hier->len - 1);

        if (child_element) {
            wmem_map_insert(fresh->elements, child_element->name, child_element);
        }
    }

    g_ptr_array_free(fresh->element_names, TRUE);
    fresh->element_names = NULL;
    return fresh;
}

static void free_elements(gpointer k _U_, gpointer v, gpointer p _U_)
{
    xml_ns_t *e = (xml_ns_t *)v;

    while (e->element_names->len) {
        g_free(g_ptr_array_remove_index(e->element_names, 0));
    }

    g_ptr_array_free(e->element_names, TRUE);
}

static void register_dtd(dtd_build_data_t *dtd_data, GString *errors)
{
    wmem_map_t *elements      = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    gchar      *root_name     = NULL;
    xml_ns_t   *root_element  = NULL;
    wmem_array_t *hfs;
    GArray     *etts;
    GPtrArray  *hier;
    gchar      *curr_name;
    GPtrArray  *element_names = g_ptr_array_new();

    /* we first populate elements with the those coming from the parser */
    while(dtd_data->elements->len) {
        dtd_named_list_t *nl      = (dtd_named_list_t *)g_ptr_array_remove_index(dtd_data->elements, 0);
        xml_ns_t         *element = wmem_new(wmem_epan_scope(), xml_ns_t);

        /* we will use the first element found as root in case no other one was given. */
        if (root_name == NULL)
            root_name = wmem_strdup(wmem_epan_scope(), nl->name);

        element->name          = wmem_strdup(wmem_epan_scope(), nl->name);
        element->element_names = nl->list;
        element->hf_tag        = -1;
        element->hf_cdata      = -1;
        element->ett           = -1;
        element->attributes    = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        element->elements      = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

        if( wmem_map_lookup(elements, element->name) ) {
            g_string_append_printf(errors, "element %s defined more than once\n", element->name);
            free_elements(NULL, element, NULL);
        } else {
            wmem_map_insert(elements, element->name, element);
            g_ptr_array_add(element_names, wmem_strdup(wmem_epan_scope(), element->name));
        }

        g_free(nl->name);
        g_free(nl);
    }

    /* then we add the attributes to its relative elements */
    while(dtd_data->attributes->len) {
        dtd_named_list_t *nl      = (dtd_named_list_t *)g_ptr_array_remove_index(dtd_data->attributes, 0);
        xml_ns_t         *element = (xml_ns_t *)wmem_map_lookup(elements, nl->name);

        if (element) {
            while(nl->list->len) {
                gchar *name = (gchar *)g_ptr_array_remove_index(nl->list, 0);
                int   *id_p = wmem_new(wmem_epan_scope(), int);

                *id_p = -1;
                wmem_map_insert(element->attributes, wmem_strdup(wmem_epan_scope(), name), id_p);
                g_free(name);            }
        }
        else {
            g_string_append_printf(errors, "element %s is not defined\n", nl->name);
        }

        g_free(nl->name);
        g_ptr_array_free(nl->list, TRUE);
        g_free(nl);
    }

    /* if a proto_root is defined in the dtd we'll use that as root */
    if( dtd_data->proto_root ) {
        wmem_free(wmem_epan_scope(), root_name);
        root_name = wmem_strdup(wmem_epan_scope(), dtd_data->proto_root);
    }

    /* we use a stack with the names to avoid recurring infinitelly */
    hier = g_ptr_array_new();

    /*
     * if a proto name was given in the dtd the dtd will be used as a protocol
     * or else the dtd will be loaded as a branch of the xml namespace
     */
    if( ! dtd_data->proto_name ) {
        hfs  = hf_arr;
        etts = ett_arr;
        g_ptr_array_add(hier, wmem_strdup(wmem_epan_scope(), "xml"));
    } else {
        /*
         * if we were given a proto_name the namespace will be registered
         * as an independent protocol with its own hf and ett arrays.
         */
        hfs  = wmem_array_new(wmem_epan_scope(), sizeof(hf_register_info));
        etts = g_array_new(FALSE, FALSE, sizeof(gint *));
    }

    /* the root element of the dtd's namespace */
    root_element = wmem_new(wmem_epan_scope(), xml_ns_t);
    root_element->name          = wmem_strdup(wmem_epan_scope(), root_name);
    root_element->fqn           = dtd_data->proto_name ? wmem_strdup(wmem_epan_scope(), dtd_data->proto_name) : root_element->name;
    root_element->hf_tag        = -1;
    root_element->hf_cdata      = -1;
    root_element->ett           = -1;
    root_element->elements      = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    root_element->element_names = element_names;

    /*
     * we can either create a namespace as a flat namespace
     * in which all the elements are at the root level
     * or we can create a recursive namespace
     */
    if (dtd_data->recursion) {
        xml_ns_t *orig_root;

        make_xml_hier(root_name, root_element, elements, hier, errors, hfs, etts, dtd_data->proto_name);

        wmem_map_insert(root_element->elements, (gpointer)root_element->name, root_element);

        orig_root = (xml_ns_t *)wmem_map_lookup(elements, root_name);

        /* if the root element was defined copy its attrlist to the child */
        if(orig_root) {
            struct _attr_reg_data d;

            d.basename = dtd_data->proto_name;
            d.hf = hfs;

            root_element->attributes = copy_attributes_hash(orig_root->attributes);
            wmem_map_foreach(root_element->attributes, add_xml_attribute_names, &d);
        } else {
            root_element->attributes = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        }

        /* we then create all the sub hierarchies to catch the recurred cases */
        g_ptr_array_add(hier, root_name);

        while(root_element->element_names->len) {
            curr_name = (gchar *)g_ptr_array_remove_index(root_element->element_names, 0);

            if( ! wmem_map_lookup(root_element->elements, curr_name) ) {
                xml_ns_t *fresh = make_xml_hier(curr_name, root_element, elements, hier, errors,
                                              hfs, etts, dtd_data->proto_name);
                wmem_map_insert(root_element->elements, (gpointer)fresh->name, fresh);
            }
        }

    } else {
        /* a flat namespace */
        g_ptr_array_add(hier, root_name);

        root_element->attributes = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

        while(root_element->element_names->len) {
            xml_ns_t *fresh;
            gint *ett_p;
            struct _attr_reg_data d;

            curr_name = (gchar *)g_ptr_array_remove_index(root_element->element_names, 0);
            fresh       = duplicate_element((xml_ns_t *)wmem_map_lookup(elements, curr_name));
            fresh->fqn  = fully_qualified_name(hier, curr_name, root_name);

            add_xml_field(hfs, &(fresh->hf_tag), curr_name, fresh->fqn);
            add_xml_field(hfs, &(fresh->hf_cdata), curr_name, fresh->fqn);

            d.basename = fresh->fqn;
            d.hf = hfs;

            wmem_map_foreach(fresh->attributes, add_xml_attribute_names, &d);

            ett_p = &fresh->ett;
            g_array_append_val(etts, ett_p);

            g_ptr_array_free(fresh->element_names, TRUE);

            wmem_map_insert(root_element->elements, (gpointer)fresh->name, fresh);
        }
    }

    g_ptr_array_free(element_names, TRUE);

    g_ptr_array_free(hier, TRUE);

    /*
     * if we were given a proto_name the namespace will be registered
     * as an independent protocol.
     */
    if( dtd_data->proto_name ) {
        gint *ett_p;
        gchar *full_name, *short_name;

        if (dtd_data->description) {
            full_name = wmem_strdup(wmem_epan_scope(), dtd_data->description);
        } else {
            full_name = wmem_strdup(wmem_epan_scope(), root_name);
        }
        short_name = wmem_strdup(wmem_epan_scope(), dtd_data->proto_name);

        ett_p = &root_element->ett;
        g_array_append_val(etts, ett_p);

        add_xml_field(hfs, &root_element->hf_cdata, root_element->name, root_element->fqn);

        root_element->hf_tag = proto_register_protocol(full_name, short_name, short_name);
        proto_register_field_array(root_element->hf_tag, (hf_register_info*)wmem_array_get_raw(hfs), wmem_array_get_count(hfs));
        proto_register_subtree_array((gint **)g_array_data(etts), etts->len);

        if (dtd_data->media_type) {
            gchar* media_type = wmem_strdup(wmem_epan_scope(), dtd_data->media_type);
            wmem_map_insert(media_types, media_type, root_element);
        }

        g_array_free(etts, TRUE);
    }

    wmem_map_insert(xml_ns.elements, root_element->name, root_element);
    wmem_map_foreach(elements, free_elements, NULL);

    destroy_dtd_data(dtd_data);
    wmem_free(wmem_epan_scope(), root_name);
}

#  define DIRECTORY_T GDir
#  define FILE_T gchar
#  define OPENDIR_OP(name) g_dir_open(name, 0, dummy)
#  define DIRGETNEXT_OP(dir) g_dir_read_name(dir)
#  define GETFNAME_OP(file) (file);
#  define CLOSEDIR_OP(dir) g_dir_close(dir)

static void init_xml_names(void)
{
    guint         i;
    DIRECTORY_T  *dir;
    const FILE_T *file;
    const gchar  *filename;
    gchar        *dirname;

    GError **dummy = wmem_new(wmem_epan_scope(), GError *);
    *dummy = NULL;

    xmpli_names = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    media_types = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    unknown_ns.elements = xml_ns.elements = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    unknown_ns.attributes = xml_ns.attributes = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    xml_new_namespace(xmpli_names, "xml", "version", "encoding", "standalone", NULL);

    dirname = get_persconffile_path("dtds", FALSE);

    if (test_for_directory(dirname) != EISDIR) {
        /* Although dir isn't a directory it may still use memory */
        g_free(dirname);
        dirname = get_datafile_path("dtds");
    }

    if (test_for_directory(dirname) == EISDIR) {
        if ((dir = OPENDIR_OP(dirname)) != NULL) {
            GString *errors = g_string_new("");

            while ((file = DIRGETNEXT_OP(dir)) != NULL) {
                guint namelen;
                filename = GETFNAME_OP(file);

                namelen = (int)strlen(filename);
                if ( namelen > 4 && ( g_ascii_strcasecmp(filename+(namelen-4), ".dtd")  == 0 ) ) {
                    GString *preparsed;
                    dtd_build_data_t *dtd_data;

                    g_string_truncate(errors, 0);
                    preparsed = dtd_preparse(dirname, filename, errors);

                    if (errors->len) {
                        report_failure("Dtd Preparser in file %s%c%s: %s",
                                       dirname, G_DIR_SEPARATOR, filename, errors->str);
                        continue;
                    }

                    dtd_data = dtd_parse(preparsed);

                    g_string_free(preparsed, TRUE);

                    if (dtd_data->error->len) {
                        report_failure("Dtd Parser in file %s%c%s: %s",
                                       dirname, G_DIR_SEPARATOR, filename, dtd_data->error->str);
                        destroy_dtd_data(dtd_data);
                        continue;
                    }

                    register_dtd(dtd_data, errors);

                    if (errors->len) {
                        report_failure("Dtd Registration in file: %s%c%s: %s",
                                       dirname, G_DIR_SEPARATOR, filename, errors->str);
                        continue;
                    }
                }
            }
            g_string_free(errors, TRUE);

            CLOSEDIR_OP(dir);
        }
    }

    g_free(dirname);

    for(i=0;i<array_length(default_media_types);i++) {
        if( ! wmem_map_lookup(media_types, default_media_types[i]) ) {
            wmem_map_insert(media_types, (gpointer)default_media_types[i], &xml_ns);
        }
    }

    wmem_map_foreach(xmpli_names, add_xmlpi_namespace, (gpointer)"xml.xmlpi");

    wmem_free(wmem_epan_scope(), dummy);
}

void
proto_register_xml(void)
{
    static gint *ett_base[] = {
        &unknown_ns.ett,
        &xml_ns.ett,
        &ett_dtd,
        &ett_xmpli
    };

    static hf_register_info hf_base[] = {
        { &hf_xmlpi,
          {"XMLPI", "xml.xmlpi",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_cdatasection,
          {"CDATASection", "xml.cdatasection",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_comment,
          {"Comment", "xml.comment",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_unknowwn_attrib,
          {"Attribute", "xml.attribute",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_doctype,
          {"Doctype", "xml.doctype",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_dtd_tag,
          {"DTD Tag", "xml.dtdtag",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &unknown_ns.hf_cdata,
          {"CDATA", "xml.cdata",
           FT_STRING, BASE_NONE, NULL, 0, NULL,
           HFILL }
        },
        { &unknown_ns.hf_tag,
          {"Tag", "xml.tag",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &xml_ns.hf_cdata,
          {"Unknown", "xml.unknown",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_xml_closing_unopened_tag, { "xml.closing_unopened_tag", PI_MALFORMED, PI_ERROR, "Closing an unopened tag", EXPFILL }},
        { &ei_xml_closing_unopened_xmpli_tag, { "xml.closing_unopened_xmpli_tag", PI_MALFORMED, PI_ERROR, "Closing an unopened xmpli tag", EXPFILL }},
        { &ei_xml_unrecognized_text, { "xml.unrecognized_text", PI_PROTOCOL, PI_WARN, "Unrecognized text", EXPFILL }},
    };

    module_t *xml_module;
    expert_module_t* expert_xml;

    hf_arr  = wmem_array_new(wmem_epan_scope(), sizeof(hf_register_info));
    ett_arr = g_array_new(FALSE, FALSE, sizeof(gint *));

    wmem_array_append(hf_arr, hf_base, array_length(hf_base));
    g_array_append_vals(ett_arr, ett_base, array_length(ett_base));

    init_xml_names();

    xml_ns.hf_tag = proto_register_protocol("eXtensible Markup Language", "XML", xml_ns.name);

    proto_register_field_array(xml_ns.hf_tag, (hf_register_info*)wmem_array_get_raw(hf_arr), wmem_array_get_count(hf_arr));
    proto_register_subtree_array((gint **)g_array_data(ett_arr), ett_arr->len);
    expert_xml = expert_register_protocol(xml_ns.hf_tag);
    expert_register_field_array(expert_xml, ei, array_length(ei));

    xml_module = prefs_register_protocol(xml_ns.hf_tag, NULL);
    prefs_register_obsolete_preference(xml_module, "heuristic");
    prefs_register_obsolete_preference(xml_module, "heuristic_tcp");
    prefs_register_obsolete_preference(xml_module, "heuristic_udp");
    /* XXX - UCS-2, or UTF-16? */
    prefs_register_bool_preference(xml_module, "heuristic_unicode", "Use Unicode in heuristics",
                                   "Try to recognize XML encoded in Unicode (UCS-2BE)",
                                   &pref_heuristic_unicode);

    g_array_free(ett_arr, TRUE);

    xml_handle = register_dissector("xml", dissect_xml, xml_ns.hf_tag);

    init_xml_parser();
}

static void
add_dissector_media(gpointer k, gpointer v _U_, gpointer p _U_)
{
    dissector_add_string("media_type", (gchar *)k, xml_handle);
}

void
proto_reg_handoff_xml(void)
{
    wmem_map_foreach(media_types, add_dissector_media, NULL);
    dissector_add_uint_range_with_preference("tcp.port", "", xml_handle);

    heur_dissector_add("http",  dissect_xml_heur, "XML in HTTP", "xml_http", xml_ns.hf_tag, HEURISTIC_DISABLE);
    heur_dissector_add("sip",   dissect_xml_heur, "XML in SIP", "xml_sip", xml_ns.hf_tag, HEURISTIC_DISABLE);
    heur_dissector_add("media", dissect_xml_heur, "XML in media", "xml_media", xml_ns.hf_tag, HEURISTIC_DISABLE);
    heur_dissector_add("tcp", dissect_xml_heur, "XML over TCP", "xml_tcp", xml_ns.hf_tag, HEURISTIC_DISABLE);
    heur_dissector_add("udp", dissect_xml_heur, "XML over UDP", "xml_udp", xml_ns.hf_tag, HEURISTIC_DISABLE);

    heur_dissector_add("wtap_file", dissect_xml_heur, "XML file", "xml_wtap", xml_ns.hf_tag, HEURISTIC_ENABLE);

    dissector_add_uint("acdr.tls_application", TLS_APP_XML, xml_handle);
}

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
