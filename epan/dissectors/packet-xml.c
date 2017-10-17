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
#include <epan/iana_charsets.h>
#include <epan/asn1.h>
#include <wsutil/str_util.h>
#include <wsutil/report_message.h>
#include <wsutil/wsgcrypt.h>
#include "packet-kerberos.h"
#include "read_keytab_file.h"

#include "packet-xml.h"
#include "packet-acdr.h"

void proto_register_xml(void);
void proto_reg_handoff_xml(void);

struct _attr_reg_data {
    wmem_array_t *hf;
    const char *basename;
};


static int ett_dtd;
static int ett_xmpli;

static int hf_unknowwn_attrib;
static int hf_comment;
static int hf_xmlpi;
static int hf_dtd_tag;
static int hf_doctype;
static int hf_cdatasection;

static expert_field ei_xml_closing_unopened_tag;
static expert_field ei_xml_closing_unopened_xmpli_tag;
static expert_field ei_xml_unrecognized_text;

/* dissector handles */
static dissector_handle_t xml_handle;
static dissector_handle_t gssapi_handle;

/* Port 3702 is IANA-registered for Web Service Discovery, which uses
 * SOAP-over-UDP to send XML */
#define XML_UDP_PORT_RANGE "3702"

/* parser definitions */
static tvbparse_wanted_t *want;
static tvbparse_wanted_t *want_ignore;
static tvbparse_wanted_t *want_heur;

static wmem_map_t *xmpli_names;
static wmem_map_t *media_types;

static xml_ns_t xml_ns     = {"xml",     "/", -1, -1, -1, NULL, NULL, NULL};
static xml_ns_t unknown_ns = {"unknown", "?", -1, -1, -1, NULL, NULL, NULL};
static xml_ns_t *root_ns;

static bool pref_heuristic_unicode;
static int pref_default_encoding = IANA_CS_UTF_8;


#define XML_CDATA       -1000
#define XML_SCOPED_NAME -1001


static wmem_array_t *hf_arr;
static GArray *ett_arr;
static GRegex* encoding_pattern;

static const char *default_media_types[] = {
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
    "application/vnd.3gpp.mcptt-info+xml",                 /*3GPP TS 24.379 version 17.6.0*/
    "application/vnd.3gpp.mcptt-mbms-usage-info+xml",      /*3GPP TS 24.379 version 17.6.0*/
    "application/vnd.3gpp.mcptt-location-info+xml",        /*3GPP TS 24.379 version 17.6.0*/
    "application/vnd.3gpp.mcptt-affiliation-command+xml",  /*3GPP TS 24.379 version 17.6.0*/
    "application/vnd.3gpp.mcptt-floor-request+xml",        /*3GPP TS 24.379 version 17.6.0*/
    "application/vnd.3gpp.mcptt-signed+xml",               /*3GPP TS 24.379 version 17.6.0*/
    "application/vnd.3gpp.mcptt-regroup+xml",              /*3GPP TS 24.379 version 17.6.0*/
    "application/vnd.3gpp.mcdata-info+xml",                /*3GPP TS 24.282 version 17.6.2*/
    "application/vnd.3gpp.mcdata-mbms-usage-info+xml",     /*3GPP TS 24.282 version 17.6.2*/
    "application/vnd.3gpp.mcdata-location-info+xml",       /*3GPP TS 24.282 version 17.6.2*/
    "application/vnd.3gpp.mcdata-affiliation-command+xml", /*3GPP TS 24.282 version 17.6.2*/
    "application/vnd.3gpp.mcdata-regroup+xml",             /*3GPP TS 24.282 version 17.6.2*/
    "application/vnd.3gpp.mcvideo-info+xml",               /*3GPP TS 24.281 version 17.6.0*/
    "application/vnd.3gpp.mcvideo-mbms-usage-info+xml",    /*3GPP TS 24.281 version 17.6.0*/
    "application/vnd.3gpp.mcvideo-location-info+xml",      /*3GPP TS 24.281 version 17.6.0*/
    "application/vnd.3gpp.mcvideo-affiliation-command+xml",/*3GPP TS 24.281 version 17.6.0*/
    "application/vnd.3gpp.transmission-request+xml",       /*3GPP TS 24.281 version 17.6.0*/
    "application/vnd.3gpp.mcptt-ue-init-config+xml",       /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcptt-ue-config+xml",            /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcptt-user-profile+xml",         /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcptt-service-config+xml",       /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcdata-service-config+xml",      /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcvideo-service-config+xml",     /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcvideo-ue-config+xml",          /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcvideo-user-profile+xml",       /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcdata-ue-config+xml",           /*3GPP TS 24.484 version 17.5.0*/
    "application/vnd.3gpp.mcdata-user-profile+xml",        /*3GPP TS 24.484 version 17.5.0*/
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

/* Try to get the 'encoding' attribute from XML declaration, and convert it to
 * Wireshark character encoding.
 */
static unsigned
get_char_encoding(tvbuff_t* tvb, packet_info* pinfo, char** ret_encoding_name) {
    uint32_t iana_charset_id;
    unsigned ws_encoding_id;
    char* encoding_str;
    GMatchInfo* match_info;
    const char* xmldecl = (char*)tvb_get_string_enc(pinfo->pool, tvb, 0,
        MIN(100, tvb_captured_length(tvb)), ENC_UTF_8);

    g_regex_match(encoding_pattern, xmldecl, 0, &match_info);
    if (g_match_info_matches(match_info)) {
        char* match_ret = g_match_info_fetch(match_info, 1);
        encoding_str = ascii_strup_inplace(wmem_strdup(pinfo->pool, match_ret));
        g_free(match_ret);
        /* Get the iana charset enum number by the name of the charset. */
        iana_charset_id = str_to_val(encoding_str,
            VALUE_STRING_EXT_VS_P(&mibenum_vals_character_sets_ext), IANA_CS_US_ASCII);
    } else {
        /* Use default encoding preference if this xml does not contains 'encoding' attribute. */
        iana_charset_id = pref_default_encoding;
        encoding_str = val_to_str_ext_wmem(pinfo->pool, iana_charset_id,
            &mibenum_vals_character_sets_ext, "UNKNOWN");
    }
    g_match_info_free(match_info);

    ws_encoding_id = mibenum_charset_to_encoding((unsigned)iana_charset_id);

    /* UTF-8 compatible with ASCII */
    if (ws_encoding_id == (ENC_NA | ENC_ASCII)) {
        ws_encoding_id = ENC_UTF_8;
        *ret_encoding_name = wmem_strdup(pinfo->pool, "UTF-8");
    } else {
        *ret_encoding_name = encoding_str;
    }

    return ws_encoding_id;
}

static int
dissect_xml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbparse_t       *tt;
    static GPtrArray *stack;
    xml_frame_t      *current_frame;
    const char       *colinfo_str;
    tvbuff_t         *decoded;
    uint16_t          try_bom;

    if (stack != NULL)
        g_ptr_array_free(stack, true);

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
    try_bom = tvb_get_ntohs(tvb, 0);
    if (try_bom == 0xFEFF) {
        /* UTF-16BE */
        const uint8_t *data_str = tvb_get_string_enc(pinfo->pool, tvb, 0, tvb_captured_length(tvb), ENC_UTF_16|ENC_BIG_ENDIAN);
        size_t l = strlen(data_str);
        decoded = tvb_new_child_real_data(tvb, data_str, (unsigned)l, (int)l);
        add_new_data_source(pinfo, decoded, "Decoded UTF-16BE text");
    }
    else if(try_bom == 0xFFFE) {
        /* UTF-16LE (or possibly UTF-32LE, but Wireshark doesn't support UTF-32) */
        const uint8_t *data_str = tvb_get_string_enc(pinfo->pool, tvb, 0, tvb_captured_length(tvb), ENC_UTF_16|ENC_LITTLE_ENDIAN);
        size_t l = strlen(data_str);
        decoded = tvb_new_child_real_data(tvb, data_str, (unsigned)l, (int)l);
        add_new_data_source(pinfo, decoded, "Decoded UTF-16LE text");
    }
    /* Could also test if try_bom is 0xnn00 or 0x00nn to guess endianness if we wanted */
    else {
        /* Get character encoding according to XML declaration or preference. */
        char* encoding_name;
        unsigned encoding = get_char_encoding(tvb, pinfo, &encoding_name);

        /* Encoding string with encoding, either with or without BOM */
        const uint8_t *data_str = tvb_get_string_enc(pinfo->pool, tvb, 0, tvb_captured_length(tvb), encoding);
        size_t l = strlen(data_str);
        decoded = tvb_new_child_real_data(tvb, data_str, (unsigned)l, (int)l);
        add_new_data_source(pinfo, decoded, wmem_strdup_printf(pinfo->pool, "Decoded %s text", encoding_name));
    }

    tt = tvbparse_init(pinfo->pool, decoded, 0, -1, stack, want_ignore);
    current_frame->start_offset = 0;
    current_frame->length = tvb_captured_length(decoded);

    current_frame->decryption_keys = wmem_map_new(wmem_packet_scope(), g_str_hash, g_str_equal);

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

    current_frame->item = proto_tree_add_item(tree, current_frame->ns->hf_tag, decoded, 0, -1, ENC_UTF_8|ENC_NA);
    current_frame->tree = proto_item_add_subtree(current_frame->item, current_frame->ns->ett);
    current_frame->last_item = current_frame->item;

    while(tvbparse_get(tt, want)) ;

    /* Save XML structure in case it is useful for the caller */
    p_add_proto_data(pinfo->pool, pinfo, xml_ns.hf_tag, 0, current_frame);

    return tvb_captured_length(tvb);
}

static bool dissect_xml_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvbparse_peek(tvbparse_init(pinfo->pool, tvb, 0, -1, NULL, want_ignore), want_heur)) {
        dissect_xml(tvb, pinfo, tree, data);
        return true;
    } else if (pref_heuristic_unicode) {
        const uint8_t *data_str;
        tvbuff_t     *unicode_tvb;
        uint16_t      try_bom;
        /* XXX - UCS-2, or UTF-16? */
        int           enc = ENC_UCS_2|ENC_LITTLE_ENDIAN;
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
        unicode_tvb = tvb_new_child_real_data(tvb, data_str, (unsigned)l, (int)l);
        if (tvbparse_peek(tvbparse_init(pinfo->pool, unicode_tvb, 0, -1, NULL, want_ignore), want_heur)) {
            add_new_data_source(pinfo, unicode_tvb, "UTF8");
            dissect_xml(unicode_tvb, pinfo, tree, data);
            return true;
        }
    }
    return false;
}

xml_frame_t *xml_get_tag(xml_frame_t *frame, const char *name)
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

xml_frame_t *xml_get_attrib(xml_frame_t *frame, const char *name)
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
    bool         is_cdata      = false;
    proto_item  *pi;
    xml_frame_t *new_frame     = NULL;
    char        *text          = NULL;

    if (tok->id == XML_CDATA) {
        hfid = current_frame->ns ? current_frame->ns->hf_cdata : xml_ns.hf_cdata;
        is_cdata = true;
    } else if ( tok->id > 0) {
        hfid = tok->id;
    } else {
        hfid = xml_ns.hf_cdata;
    }

    pi = proto_tree_add_item(current_frame->tree, hfid, tok->tvb, tok->offset, tok->len, ENC_UTF_8|ENC_NA);

    text = tvb_format_text(wmem_packet_scope(), tok->tvb, tok->offset, tok->len);
    proto_item_set_text(pi, "%s", text);

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

    if (new_frame != NULL &&
        current_frame != NULL &&
        current_frame->name_orig_case != NULL &&
        strcmp(current_frame->name_orig_case, "BinarySecurityToken") == 0)
    {
        xml_frame_t *value_type   = NULL;

        value_type = xml_get_attrib(current_frame, "ValueType");
        if (value_type != NULL) {
            const char *s = "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ";
            size_t l = strlen(s);
            int c;
            c = tvb_strneql(value_type->value, 0, s, l);
            if (c == 0) {
                tvbuff_t *ssp_tvb = base64_to_tvb(new_frame->value, text);
                add_new_data_source(current_frame->pinfo, ssp_tvb, "GSSAPI Data");
                call_dissector(gssapi_handle, ssp_tvb,
                               current_frame->pinfo, current_frame->tree);
            }
        }
    }
}

static void before_xmpli(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray       *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t     *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);
    proto_item      *pi;
    proto_tree      *pt;
    tvbparse_elem_t *name_tok      = tok->sub->next;
    char            *name          = tvb_get_string_enc(wmem_packet_scope(), name_tok->tvb, name_tok->offset, name_tok->len, ENC_ASCII);
    xml_ns_t        *ns            = (xml_ns_t *)wmem_map_lookup(xmpli_names, name);
    xml_frame_t     *new_frame;

    int  hf_tag;
    int ett;

    ascii_strdown_inplace(name);
    if (!ns) {
        hf_tag = hf_xmlpi;
        ett = ett_xmpli;
    } else {
        hf_tag = ns->hf_tag;
        ett = ns->ett;
    }

    pi = proto_tree_add_item(current_frame->tree, hf_tag, tok->tvb, tok->offset, tok->len, ENC_UTF_8|ENC_NA);

    proto_item_set_text(pi, "%s", tvb_format_text(wmem_packet_scope(), tok->tvb, tok->offset, (name_tok->offset - tok->offset) + name_tok->len));

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
    char            *root_name;
    char            *name          = NULL, *name_orig_case = NULL;
    xml_ns_t        *ns;
    xml_frame_t     *new_frame;
    proto_item      *pi;
    proto_tree      *pt;

    if (name_tok->sub->id == XML_SCOPED_NAME) {
        tvbparse_elem_t *root_tok = name_tok->sub->sub;
        tvbparse_elem_t *leaf_tok = name_tok->sub->sub->next->next;
        xml_ns_t        *nameroot_ns;

        root_name      = (char *)tvb_get_string_enc(wmem_packet_scope(), root_tok->tvb, root_tok->offset, root_tok->len, ENC_ASCII);
        name           = (char *)tvb_get_string_enc(wmem_packet_scope(), leaf_tok->tvb, leaf_tok->offset, leaf_tok->len, ENC_ASCII);
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
    proto_item_set_text(pi, "%s", tvb_format_text(wmem_packet_scope(), tok->tvb,
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

#ifdef HAVE_KERBEROS
struct decryption_key {
        char *id;
        size_t key_length;
        uint8_t key[HASH_SHA1_LENGTH];
};

static void P_SHA1(const uint8_t *Secret, size_t Secret_len,
                   const uint8_t *Seed, size_t Seed_len,
                   uint8_t Result[HASH_SHA1_LENGTH])
{
    gcry_md_hd_t hd = NULL;
    uint8_t *digest = NULL;

    /*
     * https://social.microsoft.com/Forums/en-US/c485d98b-6e0b-49e7-ab34-8ecf8d694d31/signing-soap-message-request-via-adfs?forum=crmdevelopment#6cee9fa8-dc24-4524-a5a2-c3d17e05d50e
     */
    gcry_md_open(&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(hd, Secret, Secret_len);
    gcry_md_write(hd, Seed, Seed_len);
    digest = gcry_md_read(hd, GCRY_MD_SHA1);
    memcpy(Result, digest, HASH_SHA1_LENGTH);

    gcry_md_close(hd);
}
#endif /* HAVE_KERBEROS */

static void after_untag(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray   *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);
#ifdef HAVE_KERBEROS
    xml_frame_t *top_frame = (xml_frame_t *)g_ptr_array_index(stack, 0);
#endif /* HAVE_KERBEROS */

    proto_item_set_len(current_frame->item, (tok->offset - current_frame->start_offset) + tok->len);
    current_frame->length = (tok->offset - current_frame->start_offset) + tok->len;

    proto_tree_add_format_text(current_frame->tree, tok->tvb, tok->offset, tok->len);

    if (stack->len > 1) {
        g_ptr_array_remove_index_fast(stack, stack->len - 1);
    } else {
        proto_tree_add_expert(current_frame->tree, current_frame->pinfo, &ei_xml_closing_unopened_tag,
            tok->tvb, tok->offset, tok->len);
    }

#ifdef HAVE_KERBEROS
    if (current_frame->name_orig_case == NULL) {
        return;
    }

    if (strcmp(current_frame->name_orig_case, "DerivedKeyToken") == 0) {
        xml_frame_t *id_frame = xml_get_attrib(current_frame, "u:Id");
        xml_frame_t *nonce_frame = xml_get_tag(current_frame, "Nonce");
        xml_frame_t *nonce_cdata = NULL;
        tvbuff_t *nonce_tvb = NULL;
        enc_key_t *ek = NULL;
        uint8_t seed[64];
        size_t seed_length = 16; // TODO
        const size_t key_length = 16; //TODO

        if (id_frame != NULL && nonce_frame != NULL) {
            nonce_cdata = xml_get_cdata(nonce_frame);
        }
        if (nonce_cdata != NULL) {
            char *text = tvb_format_text(wmem_packet_scope(), nonce_cdata->value, 0,
                                         tvb_reported_length(nonce_cdata->value));
            nonce_tvb = base64_to_tvb(nonce_cdata->value, text);
        }
        if (nonce_tvb != NULL) {
            seed_length = tvb_reported_length(nonce_tvb);
            seed_length = MIN(seed_length, sizeof(seed));
            tvb_memcpy(nonce_tvb, seed, 0, seed_length);

            if (krb_decrypt) {
                read_keytab_file_from_preferences();
            }

            for (ek=enc_key_list;ek;ek=ek->next) {
                if (ek->fd_num == (int)current_frame->pinfo->num) {
                    break;
                }
            }
        }
        if (ek != NULL) {
            struct decryption_key *key;
            char *id_str;

            id_str = tvb_format_text(wmem_packet_scope(),
                                     id_frame->value, 0,
                                     tvb_reported_length(id_frame->value));

            key = wmem_new0(wmem_packet_scope(), struct decryption_key);
            key->id = wmem_strdup_printf(wmem_packet_scope(), "#%s", id_str);
            P_SHA1(ek->keyvalue, ek->keylength, seed, seed_length, key->key);
            key->key_length = key_length;

            wmem_map_insert(top_frame->decryption_keys, key->id, key);
        }
    }
    if (strcmp(current_frame->name_orig_case, "CipherValue") == 0) {
        xml_frame_t *encrypted_frame = current_frame->parent->parent;
        xml_frame_t *key_info_frame = NULL;
        xml_frame_t *token_frame = NULL;
        xml_frame_t *reference_frame = NULL;
        xml_frame_t *uri_frame = NULL;
        const struct decryption_key *key = NULL;
        xml_frame_t *cdata_frame = NULL;
        tvbuff_t *crypt_tvb = NULL;
        tvbuff_t *plain_tvb = NULL;

        key_info_frame = xml_get_tag(encrypted_frame, "KeyInfo");
        if (key_info_frame != NULL) {
            token_frame = xml_get_tag(key_info_frame, "SecurityTokenReference");
        }
        if (token_frame != NULL) {
            reference_frame = xml_get_tag(token_frame, "Reference");
        }
        if (reference_frame != NULL) {
            uri_frame = xml_get_attrib(reference_frame, "URI");
        }

        if (uri_frame != NULL) {
            char *key_id = tvb_format_text(wmem_packet_scope(), uri_frame->value, 0,
                                           tvb_reported_length(uri_frame->value));

            key = (const struct decryption_key *)wmem_map_lookup(top_frame->decryption_keys, key_id);
        }
        if (key != NULL) {
            cdata_frame = xml_get_cdata(current_frame);
        }
        if (cdata_frame != NULL) {
            char *text = tvb_format_text(wmem_packet_scope(), cdata_frame->value, 0,
                                         tvb_reported_length(cdata_frame->value));
            crypt_tvb = base64_to_tvb(cdata_frame->value, text);
        }
        if (crypt_tvb != NULL) {
            gcry_cipher_hd_t cipher_hd = NULL;
            uint8_t *data = NULL;
            unsigned data_length = tvb_reported_length(crypt_tvb);

            data = (uint8_t *)tvb_memdup(wmem_packet_scope(),
                                         crypt_tvb, 0, data_length);

            /* Open the cipher. */
            gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);

            gcry_cipher_setkey(cipher_hd, key->key, key->key_length);
            gcry_cipher_encrypt(cipher_hd, data, data_length, NULL, 0);
            gcry_cipher_close(cipher_hd);

            plain_tvb = tvb_new_child_real_data(crypt_tvb, data,
                                                data_length, data_length);
            add_new_data_source(current_frame->pinfo, plain_tvb, "Decrypted Data");
        }
    }
#endif /* HAVE_KERBEROS */
}

static void before_dtd_doctype(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok)
{
    GPtrArray       *stack         = (GPtrArray *)tvbparse_data;
    xml_frame_t     *current_frame = (xml_frame_t *)g_ptr_array_index(stack, stack->len - 1);
    xml_frame_t     *new_frame;
    tvbparse_elem_t *name_tok      = tok->sub->next->next->next->sub->sub;
    proto_tree      *dtd_item      = proto_tree_add_item(current_frame->tree, hf_doctype,
                                                         name_tok->tvb, name_tok->offset,
                                                         name_tok->len, ENC_ASCII);

    proto_item_set_text(dtd_item, "%s", tvb_format_text(wmem_packet_scope(), tok->tvb, tok->offset, tok->len));

    new_frame = wmem_new(wmem_packet_scope(), xml_frame_t);
    new_frame->type           = XML_FRAME_DTD_DOCTYPE;
    new_frame->name           = (char *)tvb_get_string_enc(wmem_packet_scope(), name_tok->tvb,
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
    char            *name, *name_orig_case;
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
    proto_item_set_text(pi, "%s", tvb_format_text(wmem_packet_scope(), tok->tvb, tok->offset, tok->len));

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


static xml_ns_t *xml_new_namespace(wmem_map_t *hash, const char *name, ...)
{
    xml_ns_t *ns = wmem_new(wmem_epan_scope(), xml_ns_t);
    va_list   ap;
    char     *attr_name;

    ns->name       = wmem_strdup(wmem_epan_scope(), name);
    ns->hf_tag     = -1;
    ns->hf_cdata   = -1;
    ns->ett        = -1;
    ns->attributes = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    ns->elements   = NULL;

    va_start(ap, name);

    while(( attr_name = va_arg(ap, char *) )) {
        int *hfp = wmem_new(wmem_epan_scope(), int);
        *hfp = -1;
        wmem_map_insert(ns->attributes, wmem_strdup(wmem_epan_scope(), attr_name), hfp);
    };

    va_end(ap);

    wmem_map_insert(hash, ns->name, ns);

    return ns;
}


static void add_xml_field(wmem_array_t *hfs, int *p_id, const char *name, const char *fqn)
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

static void add_xml_attribute_names(void *k, void *v, void *p)
{
    struct _attr_reg_data *d = (struct _attr_reg_data *)p;
    const char *basename = wmem_strconcat(wmem_epan_scope(), d->basename, ".", (char *)k, NULL);

    add_xml_field(d->hf, (int*) v, (char *)k, basename);
}


static void add_xmlpi_namespace(void *k _U_, void *v, void *p)
{
    xml_ns_t *ns       = (xml_ns_t *)v;
    const char *basename = wmem_strconcat(wmem_epan_scope(), (char *)p, ".", ns->name, NULL);
    int      *ett_p    = &(ns->ett);
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

    g_string_free(dtd_data->error, true);

    while(dtd_data->elements->len) {
        dtd_named_list_t *nl = (dtd_named_list_t *)g_ptr_array_remove_index_fast(dtd_data->elements, 0);
        g_ptr_array_free(nl->list, true);
        g_free(nl->name);
        g_free(nl);
    }

    g_ptr_array_free(dtd_data->elements, true);

    while(dtd_data->attributes->len) {
        dtd_named_list_t *nl = (dtd_named_list_t *)g_ptr_array_remove_index_fast(dtd_data->attributes, 0);
        g_ptr_array_free(nl->list, true);
        g_free(nl->name);
        g_free(nl);
    }

    g_ptr_array_free(dtd_data->attributes, true);

    g_free(dtd_data);
}

static void copy_attrib_item(void *k, void *v _U_, void *p)
{
    char       *key   = (char *)wmem_strdup(wmem_epan_scope(), (const char *)k);
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
    unsigned  i;

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

static char *fully_qualified_name(GPtrArray *hier, char *name, char *proto_name)
{
    unsigned i;
    wmem_strbuf_t *s = wmem_strbuf_new(wmem_epan_scope(), proto_name);

    wmem_strbuf_append(s, ".");

    for (i = 1; i < hier->len; i++) {
        wmem_strbuf_append_printf(s, "%s.", (char *)g_ptr_array_index(hier, i));
    }

    wmem_strbuf_append(s, name);

    return wmem_strbuf_finalize(s);
}


// NOLINTNEXTLINE(misc-no-recursion)
static xml_ns_t *make_xml_hier(char       *elem_name,
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
    char     *fqn;
    int      *ett_p;
    bool      recurred = false;
    unsigned  i;
    struct _attr_reg_data  d;

    if ( g_str_equal(elem_name, root->name) ) {
        return NULL;
    }

    if (! ( orig = (xml_ns_t *)wmem_map_lookup(elements, elem_name) )) {
        g_string_append_printf(error, "element '%s' is not defined\n", elem_name);
        return NULL;
    }

    if (hier->len >= prefs.gui_max_tree_depth) {
        g_string_append_printf(error, "hierarchy too deep: %u\n", hier->len);
        return NULL;
    }

    for (i = 0; i < hier->len; i++) {
        if( (elem_name) && (strcmp(elem_name, (char *) g_ptr_array_index(hier, i) ) == 0 )) {
            recurred = true;
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
        char *child_name = (char *)g_ptr_array_remove_index(fresh->element_names, 0);
        xml_ns_t *child_element = NULL;

        g_ptr_array_add(hier, elem_name);
        child_element = make_xml_hier(child_name, root, elements, hier, error, hfs, etts, proto_name);
        g_ptr_array_remove_index_fast(hier, hier->len - 1);

        if (child_element) {
            wmem_map_insert(fresh->elements, child_element->name, child_element);
        }
    }

    g_ptr_array_free(fresh->element_names, true);
    fresh->element_names = NULL;
    return fresh;
}

static void free_elements(void *k _U_, void *v, void *p _U_)
{
    xml_ns_t *e = (xml_ns_t *)v;

    while (e->element_names->len) {
        g_free(g_ptr_array_remove_index(e->element_names, 0));
    }

    g_ptr_array_free(e->element_names, true);
}

static void register_dtd(dtd_build_data_t *dtd_data, GString *errors)
{
    wmem_map_t *elements      = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    char       *root_name     = NULL;
    xml_ns_t   *root_element  = NULL;
    wmem_array_t *hfs;
    GArray     *etts;
    GPtrArray  *hier;
    char       *curr_name;
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
                char *name = (char *)g_ptr_array_remove_index(nl->list, 0);
                int   *id_p = wmem_new(wmem_epan_scope(), int);

                *id_p = -1;
                wmem_map_insert(element->attributes, wmem_strdup(wmem_epan_scope(), name), id_p);
                g_free(name);            }
        }
        else {
            g_string_append_printf(errors, "element %s is not defined\n", nl->name);
        }

        g_free(nl->name);
        g_ptr_array_free(nl->list, true);
        g_free(nl);
    }

    /* if a proto_root is defined in the dtd we'll use that as root */
    if( dtd_data->proto_root ) {
        wmem_free(wmem_epan_scope(), root_name);
        root_name = wmem_strdup(wmem_epan_scope(), dtd_data->proto_root);
    }

    /* we use a stack with the names to avoid recurring infinitely */
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
        etts = g_array_new(false, false, sizeof(int *));
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

        wmem_map_insert(root_element->elements, (void *)root_element->name, root_element);

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
            curr_name = (char *)g_ptr_array_remove_index(root_element->element_names, 0);

            if( ! wmem_map_lookup(root_element->elements, curr_name) ) {
                xml_ns_t *fresh = make_xml_hier(curr_name, root_element, elements, hier, errors,
                                              hfs, etts, dtd_data->proto_name);
                wmem_map_insert(root_element->elements, (void *)fresh->name, fresh);
            }
        }

    } else {
        /* a flat namespace */
        g_ptr_array_add(hier, root_name);

        root_element->attributes = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

        while(root_element->element_names->len) {
            xml_ns_t *fresh;
            int *ett_p;
            struct _attr_reg_data d;

            curr_name = (char *)g_ptr_array_remove_index(root_element->element_names, 0);
            fresh       = duplicate_element((xml_ns_t *)wmem_map_lookup(elements, curr_name));
            fresh->fqn  = fully_qualified_name(hier, curr_name, root_name);

            add_xml_field(hfs, &(fresh->hf_tag), curr_name, fresh->fqn);
            add_xml_field(hfs, &(fresh->hf_cdata), curr_name, fresh->fqn);

            d.basename = fresh->fqn;
            d.hf = hfs;

            wmem_map_foreach(fresh->attributes, add_xml_attribute_names, &d);

            ett_p = &fresh->ett;
            g_array_append_val(etts, ett_p);

            g_ptr_array_free(fresh->element_names, true);

            wmem_map_insert(root_element->elements, (void *)fresh->name, fresh);
        }
    }

    g_ptr_array_free(element_names, true);

    g_ptr_array_free(hier, true);

    /*
     * if we were given a proto_name the namespace will be registered
     * as an independent protocol.
     */
    if( dtd_data->proto_name ) {
        int *ett_p;
        char *full_name, *short_name;

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
        proto_register_subtree_array((int **)etts->data, etts->len);

        if (dtd_data->media_type) {
            char* media_type = wmem_strdup(wmem_epan_scope(), dtd_data->media_type);
            wmem_map_insert(media_types, media_type, root_element);
        }

        g_array_free(etts, true);
    }

    wmem_map_insert(xml_ns.elements, root_element->name, root_element);
    wmem_map_foreach(elements, free_elements, NULL);

    destroy_dtd_data(dtd_data);
    wmem_free(wmem_epan_scope(), root_name);
}

#  define DIRECTORY_T GDir
#  define FILE_T char
#  define OPENDIR_OP(name) g_dir_open(name, 0, dummy)
#  define DIRGETNEXT_OP(dir) g_dir_read_name(dir)
#  define GETFNAME_OP(file) (file);
#  define CLOSEDIR_OP(dir) g_dir_close(dir)

static void init_xml_names(void)
{
    unsigned      i;
    DIRECTORY_T  *dir;
    const FILE_T *file;
    const char   *filename;
    char         *dirname;

    GError **dummy = wmem_new(wmem_epan_scope(), GError *);
    *dummy = NULL;

    xmpli_names = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    media_types = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    unknown_ns.elements = xml_ns.elements = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    unknown_ns.attributes = xml_ns.attributes = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    xml_new_namespace(xmpli_names, "xml", "version", "encoding", "standalone", NULL);

    dirname = get_persconffile_path("dtds", false);

    if (test_for_directory(dirname) != EISDIR) {
        /* Although dir isn't a directory it may still use memory */
        g_free(dirname);
        dirname = get_datafile_path("dtds");
    }

    if (test_for_directory(dirname) == EISDIR) {
        if ((dir = OPENDIR_OP(dirname)) != NULL) {
            GString *errors = g_string_new("");

            while ((file = DIRGETNEXT_OP(dir)) != NULL) {
                unsigned namelen;
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

                    g_string_free(preparsed, true);

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
            g_string_free(errors, true);

            CLOSEDIR_OP(dir);
        }
    }

    g_free(dirname);

    for(i=0;i<array_length(default_media_types);i++) {
        if( ! wmem_map_lookup(media_types, default_media_types[i]) ) {
            wmem_map_insert(media_types, (void *)default_media_types[i], &xml_ns);
        }
    }

    wmem_map_foreach(xmpli_names, add_xmlpi_namespace, (void *)"xml.xmlpi");

    wmem_free(wmem_epan_scope(), dummy);
}

static void
xml_init_protocol(void)
{
    // The longest encoding at https://www.iana.org/assignments/character-sets/character-sets.xml
    // is 45 characters (Extended_UNIX_Code_Packed_Format_for_Japanese).
    encoding_pattern = g_regex_new("^\\s*<[?]xml\\s+version\\s*=\\s*[\"']\\s*(?U:.+)\\s*[\"']\\s+encoding\\s*=\\s*[\"']\\s*((?U).{1,50})\\s*[\"']", G_REGEX_CASELESS, 0, 0);
}

static void
xml_cleanup_protocol(void) {
    g_regex_unref(encoding_pattern);
}

void
proto_register_xml(void)
{
    static int *ett_base[] = {
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
    ett_arr = g_array_new(false, false, sizeof(int *));

    wmem_array_append(hf_arr, hf_base, array_length(hf_base));
    g_array_append_vals(ett_arr, ett_base, array_length(ett_base));

    init_xml_names();

    xml_ns.hf_tag = proto_register_protocol("eXtensible Markup Language", "XML", xml_ns.name);

    proto_register_field_array(xml_ns.hf_tag, (hf_register_info*)wmem_array_get_raw(hf_arr), wmem_array_get_count(hf_arr));
    proto_register_subtree_array((int **)ett_arr->data, ett_arr->len);
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

    prefs_register_enum_preference(xml_module, "default_encoding", "Default character encoding",
                                   "Use this charset if the 'encoding' attribute of XML declaration is missing."
                                   "Unsupported encoding will be replaced by the default UTF-8.",
                                   &pref_default_encoding, ws_supported_mibenum_vals_character_sets_ev_array, false);

    g_array_free(ett_arr, true);

    register_init_routine(&xml_init_protocol);
    register_cleanup_routine(&xml_cleanup_protocol);

    xml_handle = register_dissector("xml", dissect_xml, xml_ns.hf_tag);

    init_xml_parser();
}

static void
add_dissector_media(void *k, void *v _U_, void *p _U_)
{
    dissector_add_string("media_type", (char *)k, xml_handle);
}

void
proto_reg_handoff_xml(void)
{
    wmem_map_foreach(media_types, add_dissector_media, NULL);
    dissector_add_uint_range_with_preference("tcp.port", "", xml_handle);
    dissector_add_uint_range_with_preference("udp.port", XML_UDP_PORT_RANGE, xml_handle);

    gssapi_handle = find_dissector_add_dependency("gssapi", xml_ns.hf_tag);

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
