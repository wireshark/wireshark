/* packet-multipart.c
 * Routines for multipart media encapsulation dissection
 * Copyright 2004, Anders Broman.
 * Copyright 2004, Olivier Biot.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References for "media-type multipart/mixed :
 * https://www.iana.org/assignments/media-types/index.html
 * https://tools.ietf.org/html/rfc2045
 * https://tools.ietf.org/html/rfc2046
 * https://tools.ietf.org/html/rfc2047
 * https://tools.ietf.org/html/rfc2048
 * https://tools.ietf.org/html/rfc2049
 *
 * Part of the code is modeled from the SIP and HTTP dissectors
 *
 * General format of a MIME multipart document:
 *      [ preamble line-end ]
 *      dash-boundary transport-padding line-end
 *      body-part
 *      *encapsulation
 *      close-delimiter transport-padding
 *      [ line-end epilogue ]
 *
 * Where:
 *      dash-boundary     := "--" boundary
 *      encapsulation     := delimiter transport-padding line-end body-part
 *      delimiter         := line-end body-part
 *      close-delimiter   := delimiter "--"
 *      body-part         := MIME-part-headers [ line-end *OCTET ]
 *      transport-padding := *LWSP-char
 *
 * Note that line-end is often a LF instead of a CRLF.
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/media_params.h>
#include <epan/prefs.h>
#include <wsutil/str_util.h>
#include "packet-imf.h"

#include "packet-gssapi.h"
#include "packet-media-type.h"

void proto_register_multipart(void);
void proto_reg_handoff_multipart(void);

/* Dissector table for media requiring special attention in multipart
 * encapsulation. */
static dissector_table_t multipart_media_subdissector_table;

/* Initialize the protocol and registered fields */
static int proto_multipart;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_multipart_trailer;
static int hf_multipart_boundary;
static int hf_multipart_first_boundary;
static int hf_multipart_last_boundary;
static int hf_multipart_preamble;

/* Initialize the subtree pointers */
static int ett_multipart;
static int ett_multipart_main;
static int ett_multipart_body;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_multipart_no_required_parameter;
static expert_field ei_multipart_decryption_not_possible;

/* Not sure that compact_name exists for multipart, but choose to keep
 * the structure from SIP dissector, all the content- is also from SIP */


typedef struct {
        const char *name;
        const char *compact_name;
} multipart_header_t;

static const multipart_header_t multipart_headers[] = {
    { "Unknown-header", NULL },     /* Pad so that the real headers start at index 1 */
    { "Content-Description", NULL },
    { "Content-Disposition", NULL },
    { "Content-Encoding", "e" },
    { "Content-Id", NULL },
    { "Content-Language", NULL },
    { "Content-Length", "l" },
    { "Content-Transfer-Encoding", NULL },
    { "Content-Type", "c" },
    { "OriginalContent", NULL }
};

#define POS_CONTENT_DESCRIPTION         1
#define POS_CONTENT_DISPOSITION         2
#define POS_CONTENT_ENCODING            3
#define POS_CONTENT_ID                  4
#define POS_CONTENT_LANGUAGE            5
#define POS_CONTENT_LENGTH              6
#define POS_CONTENT_TRANSFER_ENCODING   7
#define POS_CONTENT_TYPE                8
#define POS_ORIGINALCONTENT             9

/* Initialize the header fields */
static int hf_multipart_type;
static int hf_multipart_part;
static int hf_multipart_sec_token_len;
static int hf_header_array[array_length(multipart_headers)];

/* Define media_type/Content type table */
static dissector_table_t media_type_dissector_table;

/* Data and media dissector handles */
static dissector_handle_t multipart_handle;
static dissector_handle_t media_handle;
static dissector_handle_t gssapi_handle;

/* Determines if bodies with no media type dissector should be displayed
 * as raw text, may cause problems with images sound etc
 * TODO improve to check for different content types ?
 */
static bool display_unknown_body_as_text;
static bool remove_base64_encoding;
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
static bool uncompress_data = true;
#endif

typedef struct {
    const char *type; /* Type of multipart */
    char *boundary; /* Boundary string (enclosing quotes removed if any) */
    unsigned boundary_length; /* Length of the boundary string */
    char *protocol; /* Protocol string if encrypted multipart (enclosing quotes removed if any) */
    unsigned protocol_length; /* Length of the protocol string  */
    char *orig_content_type; /* Content-Type of original message */
    char *orig_parameters; /* Parameters for Content-Type of original message */
} multipart_info_t;



static int
find_first_boundary(tvbuff_t *tvb, int start, const uint8_t *boundary,
        int boundary_len, int *boundary_line_len, bool *last_boundary);
static int
find_next_boundary(tvbuff_t *tvb, int start, const uint8_t *boundary,
        int boundary_len, int *boundary_line_len, bool *last_boundary);
static int
process_preamble(proto_tree *tree, tvbuff_t *tvb, multipart_info_t *m_info,
        bool *last_boundary);
static int
process_body_part(proto_tree *tree, tvbuff_t *tvb,
        media_content_info_t *input_content_info, multipart_info_t *m_info,
        packet_info *pinfo, int start, int idx,
        bool *last_boundary);
static int
is_known_multipart_header(const char *header_str, unsigned len);


/* Return a tvb that contains the binary representation of a base64
   string */

static tvbuff_t *
base64_decode(packet_info *pinfo, tvbuff_t *b64_tvb, char *name)
{
    char *data;
    tvbuff_t *tvb;
    data = tvb_get_string_enc(pinfo->pool, b64_tvb, 0, tvb_reported_length(b64_tvb), ENC_ASCII);

    tvb = base64_to_tvb(b64_tvb, data);
    add_new_data_source(pinfo, tvb, name);

    return tvb;
}

/*
 * Unfold and clean up a MIME-like header, and process LWS as follows:
 *      o Preserves LWS in quoted text
 *      o Remove LWS before and after a separator
 *      o Remove trailing LWS
 *      o Replace other LWS with a single space
 * Set value to the start of the value
 * Return the cleaned-up RFC2822 header (buffer must be freed).
 */
static char *
unfold_and_compact_mime_header(wmem_allocator_t *pool, const char *lines, int *first_colon_offset)
{
    const char *p = lines;
    char c;
    char *ret, *q;
    char sep_seen = 0; /* Did we see a separator ":;," */
    char lws = false; /* Did we see LWS (incl. folding) */
    int colon = -1;

    if (! lines) return NULL;

    c = *p;
    ret = (char *)wmem_alloc(pool, strlen(lines) + 1);
    q = ret;

    while (c) {
        if (c == ':') {
            lws = false; /* Prevent leading LWS from showing up */
            if (colon == -1) {/* First colon */
                colon = (int) (q - ret);
            }
            *(q++) = sep_seen = c;
            p++;
        } else if (c == ';' || c == ',' || c == '=') {
            lws = false; /* Prevent leading LWS from showing up */
            *(q++) = sep_seen = c;
            p++;
        } else if (c == ' ' || c == '\t') {
            lws = true;
            p++;
        } else if (c == '\n') {
            lws = false; /* Skip trailing LWS */
            if ((c = *(p+1))) {
                if (c == ' ' || c == '\t') { /* Header unfolding */
                    lws = true;
                    p += 2;
                } else {
                    *q = c = 0; /* Stop */
                }
            }
        } else if (c == '\r') {
            lws = false;
            if ((c = *(p+1))) {
                if (c == '\n') {
                    if ((c = *(p+2))) {
                        if (c == ' ' || c == '\t') { /* Header unfolding */
                            lws = true;
                            p += 3;
                        } else {
                            *q = c = 0; /* Stop */
                        }
                    }
                } else if (c == ' ' || c == '\t') { /* Header unfolding */
                    lws = true;
                    p += 2;
                } else {
                    *q = c = 0; /* Stop */
                }
            }
        } else if (c == '"') { /* Start of quoted-string */
            lws = false;
            *(q++) = c;
            while (c) {
                c = *(q++) = *(++p);
                if (c == '\\') {
                    /* First part of a quoted-pair; copy the other part,
                       without checking if it's a quote */
                    c = *(q++) = *(++p);
                } else {
                    if (c == '"') {
                        p++; /* Skip closing quote */
                        break;
                    }
                }
            }
            /* if already zero terminated now, rewind one char to avoid an "off by one" */
            if(c == 0) {
                q--;
            }
        } else { /* Regular character */
            if (sep_seen) {
                sep_seen = 0;
            } else {
                if (lws) {
                    *(q++) = ' ';
                }
            }
            lws = false;
            *(q++) = c;
            p++; /* OK */
        }

        if (c) {
            c = *p;
        }
    }
    *q = 0;

    *first_colon_offset = colon;
    return (ret);
}

/* Retrieve the media information from pinfo->private_data,
 * and compute the boundary string and its length.
 * Return a pointer to a filled-in multipart_info_t, or NULL on failure.
 *
 * Boundary delimiters must not appear within the encapsulated material,
 * and must be no longer than 70 characters, not counting the two
 * leading hyphens. (quote from rfc2046)
 */
static multipart_info_t *
get_multipart_info(packet_info *pinfo, media_content_info_t *content_info)
{
    char *start_boundary, *start_protocol = NULL;
    multipart_info_t *m_info = NULL;
    const char *type = pinfo->match_string;
    char *parameters;
    int dummy;

    /*
     * We need both a content type AND parameters
     * for multipart dissection.
     */
    if (type == NULL) {
        return NULL;
    }
    if (content_info == NULL) {
        return NULL;
    }
    if (content_info->media_str == NULL) {
        return NULL;
    }

    /* Clean up the parameters */
    parameters = unfold_and_compact_mime_header(pinfo->pool, content_info->media_str, &dummy);

    start_boundary = ws_find_media_type_parameter(pinfo->pool, parameters, "boundary");
    if (!start_boundary) {
        return NULL;
    }

    if (strncmp(type, "multipart/encrypted", sizeof("multipart/encrypted") - 1) == 0) {
        start_protocol = ws_find_media_type_parameter(pinfo->pool, parameters, "protocol");
        if (!start_protocol) {
            return NULL;
        }
    }

    /*
     * There is a value for the boundary string
     */
    m_info = wmem_new(pinfo->pool, multipart_info_t);
    m_info->type = type;
    m_info->boundary = start_boundary;
    m_info->boundary_length = (unsigned)strlen(start_boundary);
    if(start_protocol) {
        m_info->protocol = start_protocol;
        m_info->protocol_length = (unsigned)strlen(start_protocol);
    } else {
        m_info->protocol = NULL;
        m_info->protocol_length = -1;
    }
    m_info->orig_content_type = NULL;
    m_info->orig_parameters = NULL;

    return m_info;
}

/*
 * The first boundary does not implicitly contain the leading
 * line-end sequence.
 *
 * Return the offset to the 1st byte of the boundary delimiter line.
 * Set boundary_line_len to the length of the entire boundary delimiter.
 * Set last_boundary to true if we've seen the last-boundary delimiter.
 */
static int
find_first_boundary(tvbuff_t *tvb, int start, const uint8_t *boundary,
        int boundary_len, int *boundary_line_len, bool *last_boundary)
{
    int offset = start, next_offset, line_len, boundary_start;

    while (tvb_offset_exists(tvb, offset + 2 + boundary_len)) {
        boundary_start = offset;
        if (((tvb_strneql(tvb, offset, (const uint8_t *)"--", 2) == 0)
                    && (tvb_strneql(tvb, offset + 2, boundary,  boundary_len) == 0)))
        {
            /* Boundary string; now check if last */
            if ((tvb_reported_length_remaining(tvb, offset + 2 + boundary_len + 2) >= 0)
                    && (tvb_strneql(tvb, offset + 2 + boundary_len,
                            (const uint8_t *)"--", 2) == 0)) {
                *last_boundary = true;
            } else {
                *last_boundary = false;
            }
            /* Look for line end of the boundary line */
            line_len =  tvb_find_line_end(tvb, offset, -1, &offset, false);
            if (line_len == -1) {
                *boundary_line_len = -1;
            } else {
                *boundary_line_len = offset - boundary_start;
            }
            return boundary_start;
        }
        line_len =  tvb_find_line_end(tvb, offset, -1, &next_offset, false);
        if (line_len == -1) {
            return -1;
        }
        offset = next_offset;
    }

    return -1;
}

/*
 * Unless the first boundary, subsequent boundaries include a line-end sequence
 * before the dashed boundary string.
 *
 * Return the offset to the 1st byte of the boundary delimiter line.
 * Set boundary_line_len to the length of the entire boundary delimiter.
 * Set last_boundary to true if we've seen the last-boundary delimiter.
 */
static int
find_next_boundary(tvbuff_t *tvb, int start, const uint8_t *boundary,
        int boundary_len, int *boundary_line_len, bool *last_boundary)
{
    int offset = start, next_offset, line_len, boundary_start;

    while (tvb_offset_exists(tvb, offset + 2 + boundary_len)) {
        line_len =  tvb_find_line_end(tvb, offset, -1, &next_offset, false);
        if (line_len == -1) {
            return -1;
        }
        boundary_start = offset + line_len;
        if (((tvb_strneql(tvb, next_offset, (const uint8_t *)"--", 2) == 0)
                    && (tvb_strneql(tvb, next_offset + 2, boundary, boundary_len) == 0)))
        {
            /* Boundary string; now check if last */
            if ((tvb_reported_length_remaining(tvb, next_offset + 2 + boundary_len + 2) >= 0)
                    && (tvb_strneql(tvb, next_offset + 2 + boundary_len,
                            (const uint8_t *)"--", 2) == 0)) {
                *last_boundary = true;
            } else {
                *last_boundary = false;
            }
            /* Look for line end of the boundary line */
            line_len =  tvb_find_line_end(tvb, next_offset, -1, &offset, false);
            if (line_len == -1) {
                *boundary_line_len = -1;
            } else {
                *boundary_line_len = offset - boundary_start;
            }
            return boundary_start;
        /* check if last before CRLF; some ignore the standard, so there is no CRLF before the boundary */
        } else if ((tvb_strneql(tvb, boundary_start - 2, (const uint8_t *)"--", 2) == 0)
                    && (tvb_strneql(tvb, boundary_start - (2 + boundary_len), boundary, boundary_len) == 0)
                    && (tvb_strneql(tvb, boundary_start - (2 + boundary_len + 2),
                            (const uint8_t *)"--", 2) == 0)) {
            boundary_start -= 2 + boundary_len + 2;
            *boundary_line_len = next_offset - boundary_start;
            *last_boundary = true;
            return boundary_start;
        }
        offset = next_offset;
    }

    return -1;
}

/*
 * Process the multipart preamble:
 *      [ preamble line-end ] dashed-boundary transport-padding line-end
 *
 * Return the offset to the start of the first body-part.
 */
static int
process_preamble(proto_tree *tree, tvbuff_t *tvb, multipart_info_t *m_info,
        bool *last_boundary)
{
    int boundary_start, boundary_line_len;

    const uint8_t *boundary = (uint8_t *)m_info->boundary;
    int boundary_len = m_info->boundary_length;

    boundary_start = find_first_boundary(tvb, 0, boundary, boundary_len,
            &boundary_line_len, last_boundary);
    if (boundary_start == 0) {
       proto_tree_add_item(tree, hf_multipart_first_boundary, tvb, boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
        return boundary_start + boundary_line_len;
    } else if (boundary_start > 0) {
        if (boundary_line_len > 0) {
            int body_part_start = boundary_start + boundary_line_len;
            proto_tree_add_item(tree, hf_multipart_preamble, tvb, 0, boundary_start, ENC_NA);
            proto_tree_add_item(tree, hf_multipart_first_boundary, tvb, boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
            return body_part_start;
        }
    }
    return -1;
}

static void
dissect_kerberos_encrypted_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gssapi_encrypt_info_t* encrypt)
{
    tvbuff_t *kerberos_tvb;
    int offset = 0, len;
    uint8_t *data;

    proto_tree_add_item(tree, hf_multipart_sec_token_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    len = tvb_reported_length_remaining(tvb, offset);

    DISSECTOR_ASSERT(tvb_bytes_exist(tvb, offset, len));

    data = (uint8_t *)tvb_memdup(pinfo->pool, tvb, offset, len);
    kerberos_tvb = tvb_new_child_real_data(tvb, data, len, len);

    add_new_data_source(pinfo, kerberos_tvb, "Kerberos Data");
    call_dissector_with_data(gssapi_handle, kerberos_tvb, pinfo, tree, encrypt);
}

/*
 * Process a multipart body-part:
 *      MIME-part-headers [ line-end *OCTET ]
 *      line-end dashed-boundary transport-padding line-end
 *
 * If applicable, call a media subdissector.
 *
 * Return the offset to the start of the next body-part.
 */
static int
process_body_part(proto_tree *tree, tvbuff_t *tvb,
        media_content_info_t *input_content_info, multipart_info_t *m_info,
        packet_info *pinfo, int start, int idx,
        bool *last_boundary)
{
    proto_tree *subtree;
    proto_item *ti;
    int offset = start, next_offset = 0;
    media_content_info_t content_info = { input_content_info->type, NULL, NULL, NULL };
    int body_start, boundary_start, boundary_line_len;

    char *content_type_str = NULL;
    char *content_trans_encoding_str = NULL;
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    char *content_encoding_str = NULL;
#endif
    char *filename = NULL;
    char *mimetypename = NULL;
    bool last_field = false;
    bool is_raw_data = false;

    const uint8_t *boundary = (uint8_t *)m_info->boundary;
    int boundary_len = m_info->boundary_length;

    ti = proto_tree_add_item(tree, hf_multipart_part, tvb, start, 0, ENC_ASCII);
    subtree = proto_item_add_subtree(ti, ett_multipart_body);

    /* find the next boundary to find the end of this body part */
    boundary_start = find_next_boundary(tvb, offset, boundary, boundary_len,
            &boundary_line_len, last_boundary);

    if (boundary_start <= 0) {
        return -1;
    }

    /*
     * Process the MIME-part-headers
     */

    while (!last_field)
    {
        int colon_offset;
        char *hdr_str;
        char *header_str;

        /* Look for the end of the header (denoted by cr)
         * 3:d argument to imf_find_field_end() maxlen; must be last offset in the tvb.
         */
        next_offset = imf_find_field_end(tvb, offset, tvb_reported_length_remaining(tvb, offset)+offset, &last_field);
        /* the following should never happen */
        /* If cr not found, won't have advanced - get out to avoid infinite loop! */
        /*
        if (next_offset == offset) {
            break;
        }
        */
        if (last_field && (next_offset+2) <= boundary_start) {
            /* Add the extra CRLF of the last field */
            next_offset += 2;
        } else if((next_offset-2) == boundary_start) {
            /* if CRLF is the start of next boundary it belongs to the boundary and not the field,
               so it's the last field without CRLF */
            last_field = true;
            next_offset -= 2;
        } else if (next_offset > boundary_start) {
            /* if there is no CRLF between last field and next boundary - trim it! */
            next_offset = boundary_start;
        }

        hdr_str = tvb_get_string_enc(pinfo->pool, tvb, offset, next_offset - offset, ENC_ASCII);

        colon_offset = 0;
        header_str = unfold_and_compact_mime_header(pinfo->pool, hdr_str, &colon_offset);
        if (colon_offset <= 0) {
            /* if there is no colon it's no header, so break and add complete line to the body */
            next_offset = offset;
            break;
        } else {
            int hf_index;

            hf_index = is_known_multipart_header(header_str, colon_offset);

            if (hf_index == -1) {
                if(isprint_string(header_str)) {
                    proto_tree_add_format_text(subtree, tvb, offset, next_offset - offset);
                } else {
                    /* if the header name is unknown and not printable, break and add complete line to the body */
                    next_offset = offset;
                    break;
                }
            } else {
                char *value_str = wmem_strdup(pinfo->pool, header_str + colon_offset + 1);

                proto_tree_add_string_format(subtree,
                      hf_header_array[hf_index], tvb,
                      offset, next_offset - offset,
                      (const char *)value_str, "%s",
                      tvb_format_text(pinfo->pool, tvb, offset, next_offset - offset));

                switch (hf_index) {
                    case POS_ORIGINALCONTENT:
                        {
                            char *semicolonp;
                            /* The Content-Type starts at colon_offset + 1 or after the type parameter */
                            char* type_str = ws_find_media_type_parameter(pinfo->pool, value_str, "type");
                            if(type_str != NULL) {
                                value_str = type_str;
                            }

                            semicolonp = strchr(value_str, ';');

                            if (semicolonp != NULL) {
                                *semicolonp = '\0';
                                m_info->orig_parameters = wmem_strdup(pinfo->pool,
                                                             semicolonp + 1);
                            }

                            m_info->orig_content_type = wmem_ascii_strdown(pinfo->pool, value_str, -1);
                        }
                        break;
                    case POS_CONTENT_TYPE:
                        {
                            /* The Content-Type starts at colon_offset + 1 */
                            char *semicolonp = strchr(value_str, ';');

                            if (semicolonp != NULL) {
                                *semicolonp = '\0';
                                content_info.media_str = wmem_strdup(pinfo->pool, semicolonp + 1);
                            } else {
                                content_info.media_str = NULL;
                            }

                            content_type_str = wmem_ascii_strdown(pinfo->pool, value_str, -1);

                            /* Show content-type in root 'part' label */
                            proto_item_append_text(ti, " (%s)", content_type_str);

                            /* find the "name" parameter in case we don't find a content disposition "filename" */
                            mimetypename = ws_find_media_type_parameter(pinfo->pool, content_info.media_str, "name");

                            if(strncmp(content_type_str, "application/octet-stream",
                                    sizeof("application/octet-stream")-1) == 0) {
                                is_raw_data = true;
                            }

                            /* there are only 2 body parts possible and each part has specific content types */
                            if(m_info->protocol && idx == 0
                                && (is_raw_data || g_ascii_strncasecmp(content_type_str, m_info->protocol,
                                                        strlen(m_info->protocol)) != 0))
                            {
                                return -1;
                            }
                        }
                        break;
                    case POS_CONTENT_ENCODING:
                        {
                            /* The Content-Encoding starts at colon_offset + 1 */
                            char *crp = strchr(value_str, '\r');

                            if (crp != NULL) {
                                *crp = '\0';
                            }
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
                            content_encoding_str = wmem_ascii_strdown(pinfo->pool, value_str, -1);
#endif
                        }
                        break;
                    case POS_CONTENT_TRANSFER_ENCODING:
                        {
                            /* The Content-Transferring starts at colon_offset + 1 */
                            char *crp = strchr(value_str, '\r');

                            if (crp != NULL) {
                                *crp = '\0';
                            }

                            content_trans_encoding_str = wmem_ascii_strdown(pinfo->pool, value_str, -1);
                        }
                        break;
                    case POS_CONTENT_DISPOSITION:
                        {
                            /* find the "filename" parameter */
                            filename = ws_find_media_type_parameter(pinfo->pool, value_str, "filename");
                        }
                        break;
                    case POS_CONTENT_ID:
                        content_info.content_id = wmem_strdup(pinfo->pool, value_str);
                        break;
                    default:
                        break;
                }
            }
        }
        offset = next_offset;
    }

    body_start = next_offset;

    /*
     * Process the body
     */

    {
        int body_len = boundary_start - body_start;
        tvbuff_t *tmp_tvb = tvb_new_subset_length(tvb, body_start, body_len);
        /*
         * If multipart subtype is encrypted the protcol string was set.
         *
         * See MS-WSMV section 2.2.9.1.2.1 "HTTP Headers":
         *
         *  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/b79927c2-96be-4801-aa68-180db95593f9
         *
         * There are only 2 body parts possible, and each part has specific
         * content types.
         */
        if(m_info->protocol && idx == 1 && is_raw_data)
        {
            gssapi_encrypt_info_t  encrypt;

            memset(&encrypt, 0, sizeof(encrypt));
            encrypt.decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;

            dissect_kerberos_encrypted_message(tmp_tvb, pinfo, subtree, &encrypt);

            if(encrypt.gssapi_decrypted_tvb){
                    tmp_tvb = encrypt.gssapi_decrypted_tvb;
                    is_raw_data = false;
                    content_type_str = m_info->orig_content_type;
                    content_info.media_str = m_info->orig_parameters;
            } else if(encrypt.gssapi_encrypted_tvb) {
                    tmp_tvb = encrypt.gssapi_encrypted_tvb;
                    proto_tree_add_expert(tree, pinfo, &ei_multipart_decryption_not_possible, tmp_tvb, 0, -1);
            }
        }

        if (!is_raw_data &&
            content_type_str) {

            /*
             * subdissection
             */
            bool dissected;

            /*
             * Try and remove any content transfer encoding so that each sub-dissector
             * doesn't have to do it itself
             *
             */

            if(content_trans_encoding_str && remove_base64_encoding) {

                if(!g_ascii_strncasecmp(content_trans_encoding_str, "base64", 6))
                    tmp_tvb = base64_decode(pinfo, tmp_tvb, filename ? filename : (mimetypename ? mimetypename : content_type_str));

            }

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
            if(content_encoding_str && uncompress_data) {

                if(g_ascii_strncasecmp(content_encoding_str,"gzip",4) == 0 ||
                   g_ascii_strncasecmp(content_encoding_str,"deflate",7) == 0 ||
                   g_ascii_strncasecmp(content_encoding_str,"x-gzip",6) == 0 ||
                   g_ascii_strncasecmp(content_encoding_str,"x-deflate",9) == 0){
                   /* The body is gzip:ed */
                    tvbuff_t *uncompress_tvb = tvb_child_uncompress_zlib(tmp_tvb, tmp_tvb, 0, body_len);
                    if (uncompress_tvb) {
                        tmp_tvb = uncompress_tvb;
                        add_new_data_source(pinfo, tmp_tvb, "gunzipped data");
                    }
                }
            }
#endif

            /*
             * First try the dedicated multipart dissector table
             */
            dissected = dissector_try_string(multipart_media_subdissector_table,
                        content_type_str, tmp_tvb, pinfo, subtree, &content_info);
            if (! dissected) {
                /*
                 * Fall back to the default media dissector table
                 */
                dissected = dissector_try_string(media_type_dissector_table,
                        content_type_str, tmp_tvb, pinfo, subtree, &content_info);
            }
            if (! dissected) {
                const char *save_match_string = pinfo->match_string;
                pinfo->match_string = content_type_str;
                call_dissector_with_data(media_handle, tmp_tvb, pinfo, subtree, &content_info);
                pinfo->match_string = save_match_string;
            }
            content_info.media_str = NULL; /* Shares same memory as content_type_str */
        } else {
            call_data_dissector(tmp_tvb, pinfo, subtree);
        }
        proto_item_set_len(ti, boundary_start - start);
        if (*last_boundary == true) {
           proto_tree_add_item(tree, hf_multipart_last_boundary, tvb, boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
        } else {
           proto_tree_add_item(tree, hf_multipart_boundary, tvb, boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
        }

        return boundary_start + boundary_line_len;
    }
}

/*
 * Call this method to actually dissect the multipart body.
 * NOTE - Only do so if a boundary string has been found!
 */
static int dissect_multipart(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree *subtree;
    proto_item *ti;
    proto_item *type_ti;
    media_content_info_t *content_info = (media_content_info_t *)data;
    multipart_info_t *m_info = get_multipart_info(pinfo, content_info);
    int header_start = 0;
    int body_index = 0;
    bool last_boundary = false;

    if (m_info == NULL) {
        /*
         * We can't get the required multipart information
         */
        proto_tree_add_expert(tree, pinfo, &ei_multipart_no_required_parameter, tvb, 0, -1);
        call_data_dissector(tvb, pinfo, tree);
        return tvb_reported_length(tvb);
    }

    /* Add stuff to the protocol tree */
    ti = proto_tree_add_item(tree, proto_multipart,
          tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_multipart);
    proto_item_append_text(ti, ", Type: %s, Boundary: \"%s\"",
          m_info->type, m_info->boundary);

    /* Show multi-part type as a generated field */
    type_ti = proto_tree_add_string(subtree, hf_multipart_type,
          tvb, 0, 0, pinfo->match_string);
    proto_item_set_generated(type_ti);

    /*
     * Make no entries in Protocol column and Info column on summary display,
     * but stop sub-dissectors from clearing entered text in summary display.
     */
    col_set_fence(pinfo->cinfo, COL_INFO);

    /*
     * Process the multipart preamble
     */
    header_start = process_preamble(subtree, tvb, m_info, &last_boundary);
    if (header_start == -1) {
        call_data_dissector(tvb, pinfo, subtree);
        return tvb_reported_length(tvb);
    }
    /*
     * Process the encapsulated bodies
     */
    while (last_boundary == false) {
        header_start = process_body_part(subtree, tvb, content_info, m_info,
                pinfo, header_start, body_index++, &last_boundary);
        if (header_start == -1) {
            return tvb_reported_length(tvb);
        }
    }
    /*
     * Process the multipart trailer
     */
    if (tvb_reported_length_remaining(tvb, header_start) > 0) {
       proto_tree_add_item(subtree, hf_multipart_trailer, tvb, header_start, -1, ENC_NA);
    }

    return tvb_reported_length(tvb);
}

/* Returns index of method in multipart_headers */
static int
is_known_multipart_header(const char *header_str, unsigned len)
{
    unsigned i;

    for (i = 1; i < array_length(multipart_headers); i++) {
        if (len == strlen(multipart_headers[i].name) &&
            g_ascii_strncasecmp(header_str, multipart_headers[i].name, len) == 0)
            return i;
        if (multipart_headers[i].compact_name != NULL &&
            len == strlen(multipart_headers[i].compact_name) &&
            g_ascii_strncasecmp(header_str, multipart_headers[i].compact_name, len) == 0)
            return i;
    }

    return -1;
}

/*
 * Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */

void
proto_register_multipart(void)
{

/* Setup list of header fields  See Section 1.6.1 for details */
    static hf_register_info hf[] = {
        { &hf_multipart_type,
          {   "Type",
              "mime_multipart.type",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "MIME multipart encapsulation type", HFILL
          }
        },
        { &hf_multipart_part,
          {   "Encapsulated multipart part",
              "mime_multipart.part",
              FT_STRING, BASE_NONE, NULL, 0x00,
              NULL, HFILL
          }
        },
        { &hf_multipart_sec_token_len,
          {   "Length of security token",
              "mime_multipart.header.sectoken-length",
              FT_UINT32, BASE_DEC, NULL, 0x00,
              "Length of the Kerberos BLOB which follows this token", HFILL
          }
        },
        { &hf_header_array[POS_CONTENT_DESCRIPTION],
          {   "Content-Description",
              "mime_multipart.header.content-description",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "Content-Description Header", HFILL
          }
        },
        { &hf_header_array[POS_CONTENT_DISPOSITION],
          {   "Content-Disposition",
              "mime_multipart.header.content-disposition",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "RFC 2183: Content-Disposition Header", HFILL
          }
        },
        { &hf_header_array[POS_CONTENT_ENCODING],
          {   "Content-Encoding",
              "mime_multipart.header.content-encoding",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "Content-Encoding Header", HFILL
          }
        },
        { &hf_header_array[POS_CONTENT_ID],
          {   "Content-Id",
              "mime_multipart.header.content-id",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "RFC 2045: Content-Id Header", HFILL
          }
        },
        { &hf_header_array[POS_CONTENT_LANGUAGE],
          {   "Content-Language",
              "mime_multipart.header.content-language",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "Content-Language Header", HFILL
          }
        },
        { &hf_header_array[POS_CONTENT_LENGTH],
          {   "Content-Length",
              "mime_multipart.header.content-length",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Content-Length Header", HFILL
          }
        },
        { &hf_header_array[POS_CONTENT_TRANSFER_ENCODING],
          {   "Content-Transfer-Encoding",
              "mime_multipart.header.content-transfer-encoding",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "RFC 2045: Content-Transfer-Encoding Header", HFILL
          }
        },
        { &hf_header_array[POS_CONTENT_TYPE],
          {   "Content-Type",
              "mime_multipart.header.content-type",
              FT_STRING, BASE_NONE,NULL,0x0,
              "Content-Type Header", HFILL
          }
        },
        { &hf_header_array[POS_ORIGINALCONTENT],
          {   "OriginalContent",
              "mime_multipart.header.originalcontent",
              FT_STRING, BASE_NONE,NULL,0x0,
              "Original Content-Type Header", HFILL
          }
        },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_multipart_first_boundary, { "First boundary", "mime_multipart.first_boundary", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_multipart_preamble, { "Preamble", "mime_multipart.preamble", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_multipart_last_boundary, { "Last boundary", "mime_multipart.last_boundary", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_multipart_boundary, { "Boundary", "mime_multipart.boundary", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_multipart_trailer, { "Trailer", "mime_multipart.trailer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    };

    /*
     * Preferences
     */
    module_t *multipart_module;
    expert_module_t* expert_multipart;


    /*
     * Setup protocol subtree array
     */
    static int *ett[] = {
        &ett_multipart,
        &ett_multipart_main,
        &ett_multipart_body,
    };

    static ei_register_info ei[] = {
        { &ei_multipart_no_required_parameter, { "mime_multipart.no_required_parameter", PI_PROTOCOL, PI_ERROR, "The multipart dissector could not find a required parameter.", EXPFILL }},
        { &ei_multipart_decryption_not_possible, { "mime_multipart.decryption_not_possible", PI_UNDECODED, PI_WARN, "The multipart dissector could not decrypt the message.", EXPFILL }},
    };

    /*
     * Register the protocol name and description
     */
    proto_multipart = proto_register_protocol("MIME Multipart Media Encapsulation", "MIME multipart", "mime_multipart");

    /*
     * Required function calls to register
     * the header fields and subtrees used.
     */
    proto_register_field_array(proto_multipart, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_multipart = expert_register_protocol(proto_multipart);
    expert_register_field_array(expert_multipart, ei, array_length(ei));

    multipart_module = prefs_register_protocol(proto_multipart, NULL);

    prefs_register_bool_preference(multipart_module,
                                   "display_unknown_body_as_text",
                                   "Display bodies without media type as text",
                                   "Display multipart bodies with no media type dissector"
                                   " as raw text (may cause problems with binary data).",
                                   &display_unknown_body_as_text);

    prefs_register_bool_preference(multipart_module,
                                   "remove_base64_encoding",
                                   "Remove base64 encoding from bodies",
                                   "Remove any base64 content-transfer encoding from bodies. "
                                   "This supports export of the body and its further dissection.",
                                   &remove_base64_encoding);

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    prefs_register_bool_preference(multipart_module,
                                   "uncompress_data",
                                   "Uncompress parts which are compressed",
                                   "Uncompress parts which are compressed. GZIP for example. "
                                   "This supports export of the body and its further dissection.",
                                   &uncompress_data);
#endif

    /*
     * Dissectors requiring different behavior in cases where the media
     * is contained in a multipart entity should register their multipart
     * dissector in the dissector table below, which is similar to the
     * "media_type" dissector table defined in the HTTP dissector code.
     */
    multipart_media_subdissector_table = register_dissector_table(
        "multipart_media_type",
        "Internet media type (for multipart processing)",
        proto_multipart, FT_STRING, STRING_CASE_INSENSITIVE);

    /*
     * Handle for multipart dissection
     */
    multipart_handle = register_dissector("mime_multipart",
            dissect_multipart, proto_multipart);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_multipart(void)
{
    /*
     * When we cannot display the data, call the data dissector.
     * When there is no dissector for the given media, call the media dissector.
     */
    media_handle = find_dissector_add_dependency("media", proto_multipart);
    gssapi_handle = find_dissector_add_dependency("gssapi", proto_multipart);

    /*
     * Get the content type and Internet media type table
     */
    media_type_dissector_table = find_dissector_table("media_type");

    dissector_add_string("media_type",
            "multipart/mixed", multipart_handle);
    dissector_add_string("media_type",
            "multipart/related", multipart_handle);
    dissector_add_string("media_type",
            "multipart/alternative", multipart_handle);
    dissector_add_string("media_type",
            "multipart/form-data", multipart_handle);
    dissector_add_string("media_type",
            "multipart/report", multipart_handle);
    dissector_add_string("media_type",
            "multipart/signed", multipart_handle);
    dissector_add_string("media_type",
            "multipart/encrypted", multipart_handle);

    /*
     * Supply an entry to use for unknown multipart subtype.
     * See RFC 2046, section 5.1.3
     */
    dissector_add_string("media_type",
            "multipart/", multipart_handle);
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
