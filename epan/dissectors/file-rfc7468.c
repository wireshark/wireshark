/* file-rfc7468.c
 * Routines for dissection of files in the format specified by RFC 7468.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_rfc7468(void);
void proto_reg_handoff_rfc7468(void);

static int proto_rfc7468 = -1;

static gint ett_rfc7468 = -1;
static gint ett_rfc7468_preeb = -1;
static gint ett_rfc7468_data = -1;
static gint ett_rfc7468_posteb = -1;

static int hf_rfc7468_preeb_label = -1;
static int hf_rfc7468_ber_data = -1;
static int hf_rfc7468_posteb_label = -1;

static dissector_handle_t ber_handle = NULL;

static dissector_table_t rfc7468_label_table;

static gboolean
line_is_eb(const guchar *line, int linelen, const char *prefix,
           size_t prefixlen, const guchar **labelpp, int *labellenp)
{
    static const char suffix[] = "-----";
#define suffixlen (sizeof suffix - 1)
    const guchar *labelp;
    int labellen;

    /*
     * Is this line an encapulation boundary of the type specified by the
     * prefix?
     *
     * First, it must be big enough to include the prefix at the beginning
     * and the suffix at the end.
     */
    if ((size_t)linelen < prefixlen + suffixlen) {
        /*
         * No - it's too short.
         */
        return FALSE;
    }

    /*
     * It is, but it must begin with the prefix.
     */
    if (memcmp(line, prefix, prefixlen) != 0) {
        /*
         * No - it doesn't begin with the prefix.
         */
        return FALSE;
    }

    /*
     * It does, but it must also end with the suffix.
     */
    if (memcmp(line + linelen - suffixlen, suffix, suffixlen) != 0) {
        /*
         * No - it doesn't end with the suffix.
         */
        return FALSE;
    }

    /*
     * It begins with the prefix and ends with the suffix.  Check
     * the label, if there is one.
     */
    labelp = line + prefixlen;
    labellen = (int)(linelen - (prefixlen + suffixlen));
    *labelpp = labelp;
    *labellenp = labellen;
    if (labellen == 0) {
        /* The label is empty. */
        return TRUE;
    }

    /*
     * The first character of the label must be 0x21-0x2C or 0x2E-0x7F,
     * i.e., printable ASCII other than SP or '-'.
     */
    if (*labelp == ' ' || *labelp == '-')
        return FALSE;
    labelp++;
    labellen--;

    /*
     * The rest of the characters must be printable ASCII.
     */
    for (int i = 0; i < labellen; i++, labelp++) {
        if (*labelp < 0x20 || *labelp > 0x7E) {
            /* Not printable ASCII. */
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean
line_is_blank(const guchar *line, int linelen)
{
    const guchar *p;

    p = line;
    for (int i = 0; i < linelen; i++, p++) {
        if (*p != ' ' && *p != '\t') {
            /* Not space or tab */
            return FALSE;
        }
    }
    return TRUE;
}

static const char preeb_prefix[] = "-----BEGIN ";
#define preeb_prefix_len (sizeof preeb_prefix - 1)
static const char posteb_prefix[] = "-----END ";
#define posteb_prefix_len (sizeof posteb_prefix - 1)

static gint
dissect_rfc7468(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset;
    int linelen;
    int next_offset;
    const guchar *line;
    const guchar *labelp;
    int labellen;
    char *label;
    proto_tree *rfc7468_tree, *preeb_tree, *posteb_tree;
    proto_item *rfc7468_item, *ti;

    offset = 0;
    rfc7468_item = proto_tree_add_item(tree, proto_rfc7468, tvb, offset, -1, ENC_NA);
    rfc7468_tree = proto_item_add_subtree(rfc7468_item, ett_rfc7468);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "rfc7468");

    /*
     * First, process the text lines prior to the pre-encapsulation
     * boundary; they're explanatory text lines.
     */
    for (;;) {
        linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        if (linelen == -1) {
            /* No complete line was found.  Nothing more to do. */
            return tvb_captured_length(tvb);
        }

        /*
         * Get a buffer that refers to the line.
         *
         * Note that "tvb_find_line_end()" will return a value that
         * is not longer than what's in the buffer, so the
         * "tvb_get_ptr()" call won't throw an exception.
         */
        line = tvb_get_ptr(tvb, offset, linelen);

        /*
         * Is this line a pre-encapulation boundary?
         */
        if (line_is_eb(line, linelen, preeb_prefix, sizeof preeb_prefix - 1,
                       &labelp, &labellen)) {
            /*
             * Yes - we're finished with the explanatory text lines.
             */
            break;
        }

        /*
         * Add this line to the dissection.
         */
        proto_tree_add_format_text(rfc7468_tree, tvb, offset, next_offset - offset);

        /*
         * Step to the next line.
         */
        offset = next_offset;
    }

    /*
     * This line is the pre-encapsulation boundary.
     * Put it into the protocol tree, and create a subtree under it.
     */
    ti = proto_tree_add_format_text(rfc7468_tree, tvb, offset, next_offset - offset);
    preeb_tree = proto_item_add_subtree(ti, ett_rfc7468_preeb);

    /*
     * Extract the label, and put it in that subtree.
     */
    label = wmem_strndup(wmem_packet_scope(), labelp, labellen);
    proto_tree_add_item(preeb_tree, hf_rfc7468_preeb_label, tvb,
                        offset + (int)preeb_prefix_len, labellen,  ENC_ASCII|ENC_NA);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Label: %s", label);

    /*
     * Step to the next line.
     */
    offset = next_offset;

    /*
     * Skip over any blank lines before the base64 information.
     */
    for (;;) {
        linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        if (linelen == -1) {
            /* No complete line was found.  We're done. */
            return tvb_captured_length(tvb);
        }

        /*
         * Get a buffer that refers to the line.
         *
         * Note that "tvb_find_line_end()" will return a value that
         * is not longer than what's in the buffer, so the
         * "tvb_get_ptr()" call won't throw an exception.
         */
        line = tvb_get_ptr(tvb, offset, linelen);

        /*
         * Is the line entirely blank (space or tab)?
         */
        if (!line_is_blank(line, linelen)) {
            /*
             * No.
             */
            break;
        }

        /*
         * Add this line to the dissection.
         */
        proto_tree_add_format_text(rfc7468_tree, tvb, offset, next_offset - offset);

        /*
         * Step to the next line.
         */
        offset = next_offset;
    }

    /*
     * OK, this should be base64-encoded binary data.
     */
    guint8 *databuf = NULL;
    gsize databufsize = 0;
    gint base64_state = 0;
    guint base64_save = 0;
    guint datasize = 0;
    for (;;) {
        linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        if (linelen == -1) {
            /*
             * No complete line was found.  Nothing more to do.
             */
            return tvb_captured_length(tvb);
        }

        /*
         * Get a buffer that refers to the line.
         *
         * Note that "tvb_find_line_end()" will return a value that
         * is not longer than what's in the buffer, so the
         * "tvb_get_ptr()" call won't throw an exception.
         */
        line = tvb_get_ptr(tvb, offset, linelen);

        /*
         * Is this line a post-encapulation boundary?
         */
        if (line_is_eb(line, linelen, posteb_prefix, sizeof posteb_prefix - 1,
                       &labelp, &labellen)) {
            /*
             * Yes - we're done with the base64 data.
             */
            break;
        }

        /*
         * Add this line to the dissection.
         */
        proto_tree_add_format_text(rfc7468_tree, tvb, offset, next_offset - offset);

        /*
         * Decode it and add that to the buffer.
         * First, grow the buffer as needed.
         */
        databufsize += (linelen / 4) * 3 + 3;
        databuf = (guint8 *)wmem_realloc(pinfo->pool, databuf, databufsize);

        /*
         * Now decode into it.
         */
        guint decodesize = (guint)g_base64_decode_step(line, linelen,
                                                       &databuf[datasize],
                                                       &base64_state,
                                                       &base64_save);
        datasize += decodesize;

        /*
         * Step to the next line.
         */
        offset = next_offset;
    }

    /*
     * Make a tvbuff for the data, and put it into the protocol tree,
     * if we have any.
     */
    if (datasize != 0) {
        tvbuff_t *data_tvb;

        data_tvb = tvb_new_child_real_data(tvb, databuf, datasize, datasize);
        add_new_data_source(pinfo, data_tvb, "Base64-encoded data");

        /*
         * Try to decode it based on the label.
         */
        if (dissector_try_string(rfc7468_label_table, label, data_tvb, pinfo,
                                 tree, NULL) == 0) {
            proto_tree *data_tree;

            /*
             * No known dissector; decode it as BER.
             */
            ti = proto_tree_add_item(tree, hf_rfc7468_ber_data, data_tvb, 0, -1, ENC_NA);
            data_tree = proto_item_add_subtree(ti, ett_rfc7468_data);
            call_dissector(ber_handle, data_tvb, pinfo, data_tree);
        }
    }

    /*
     * This line is the post-encapsulation boundary.
     * Put it into the protocol tree, and create a subtree under it.
     */
    ti = proto_tree_add_format_text(rfc7468_tree, tvb, offset, next_offset - offset);
    posteb_tree = proto_item_add_subtree(ti, ett_rfc7468_posteb);

    /*
     * Extract the label, and put it in that subtree.
     */
    proto_tree_add_item(posteb_tree, hf_rfc7468_posteb_label, tvb,
                        offset + (int)posteb_prefix_len, labellen,  ENC_ASCII|ENC_NA);

    return tvb_captured_length(tvb);
}

//
// Arbitrary value - we don't want to read all of a huge non-RFC 7468 file
// only to find no pre-encapsulation boundary.
//
#define MAX_EXPLANATORY_TEXT_LINES     20

static gboolean
dissect_rfc7468_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset;
    int linelen;
    int next_offset;
    const guchar *line;
    const guchar *labelp;
    int labellen;
    gboolean found = FALSE;

    /*
     * Look for a pre-encapsulation boundary.
     * Process up to MAX_EXPLANATORY_TEXT_LINES worth of lines that don't
     * look like pre-encapsulation boundaries.
     */
    offset = 0;
    for (unsigned int i = 0; i < MAX_EXPLANATORY_TEXT_LINES; i++) {
        linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        if (linelen == -1) {
            /*
             * No complete line was found; we ran out of file data
             * and didn't find a pre-encapsulation boundary, so this
             * isn't an RFC 7468 file.
             */
            break;
        }

        /*
         * Get a buffer that refers to the line.
         *
         * Note that "tvb_find_line_end()" will return a value that
         * is not longer than what's in the buffer, so the
         * "tvb_get_ptr()" call won't throw an exception.
         */
        line = tvb_get_ptr(tvb, offset, linelen);

        /*
         * Is this line a pre-encapulation boundary?
         */
        if (line_is_eb(line, linelen, preeb_prefix, sizeof preeb_prefix - 1,
                       &labelp, &labellen)) {
            /*
             * Yes - we're done looking.
             */
            found = TRUE;
            break;
        }

        /*
         * Step to the next line.
         */
        offset = next_offset;
    }

    /*
     * Did we find a pre-encapsulation boundary?
     */
    if (!found)
        return FALSE; /* no */

    /*
     * OK, it's an RFC 7468 file.  Dissect it.
     */
    dissect_rfc7468(tvb, pinfo, tree, data);
    return TRUE;
}

void
proto_register_rfc7468(void)
{
    static hf_register_info hf[] = {
        { &hf_rfc7468_preeb_label,
            { "Pre-encapsulation boundary label", "rfc7468.preeb_label", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_rfc7468_ber_data,
            { "BER data", "rfc7468.ber_data", FT_NONE, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_rfc7468_posteb_label,
            { "Post-encapsulation boundary label", "rfc7468.posteb_label", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_rfc7468,
        &ett_rfc7468_preeb,
        &ett_rfc7468_data,
        &ett_rfc7468_posteb
    };

    proto_rfc7468 = proto_register_protocol("RFC 7468 file format", "rfc7468", "rfc7468");

    proto_register_field_array(proto_rfc7468, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    rfc7468_label_table = register_dissector_table("rfc7468.preeb_label", "FFF",
                                                   proto_rfc7468, FT_STRING,
                                                   TRUE);
}

void
proto_reg_handoff_rfc7468(void)
{
    dissector_handle_t rfc7468_handle;

    heur_dissector_add("wtap_file", dissect_rfc7468_heur, "RFC 7468 file", "rfc7468_wtap", proto_rfc7468, HEURISTIC_ENABLE);
    rfc7468_handle = create_dissector_handle(dissect_rfc7468, proto_rfc7468);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_RFC7468, rfc7468_handle);

    ber_handle = find_dissector("ber");
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
