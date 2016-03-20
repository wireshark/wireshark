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
 *
 * References for "media-type multipart/mixed :
 * http://www.iana.org/assignments/media-types/index.html
 * http://www.ietf.org/rfc/rfc2045.txt?number=2045
 * http://www.rfc-editor.org/rfc/rfc2046.txt
 * http://www.rfc-editor.org/rfc/rfc2047.txt
 * http://www.rfc-editor.org/rfc/rfc2048.txt
 * http://www.rfc-editor.org/rfc/rfc2049.txt
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
#include <epan/prefs.h>
#include <wsutil/str_util.h>
#include "packet-imf.h"

#include "packet-dcerpc.h"
#include "packet-gssapi.h"

void proto_register_multipart(void);
void proto_reg_handoff_multipart(void);

/* Dissector table for media requiring special attention in multipart
 * encapsulation. */
static dissector_table_t multipart_media_subdissector_table;

/* Initialize the protocol and registered fields */
static int proto_multipart = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_multipart_trailer = -1;
static int hf_multipart_boundary = -1;
static int hf_multipart_first_boundary = -1;
static int hf_multipart_last_boundary = -1;
static int hf_multipart_preamble = -1;

/* Initialize the subtree pointers */
static gint ett_multipart = -1;
static gint ett_multipart_main = -1;
static gint ett_multipart_body = -1;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_multipart_no_required_parameter = EI_INIT;
static expert_field ei_multipart_decryption_not_possible = EI_INIT;

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
static gint hf_multipart_type = -1;
static gint hf_multipart_part = -1;
static gint hf_multipart_sec_token_len = -1;

static gint hf_header_array[] = {
    -1, /* "Unknown-header" - Pad so that the real headers start at index 1 */
    -1, /* "Content-Description" */
    -1, /* "Content-Disposition" */
    -1, /* "Content-Encoding" */
    -1, /* "Content-Id" */
    -1, /* "Content-Language" */
    -1, /* "Content-Length" */
    -1, /* "Content-Transfer-Encoding" */
    -1, /* "Content-Type" */
    -1, /* "OriginalContent" */
};

/* Define media_type/Content type table */
static dissector_table_t media_type_dissector_table;

/* Data and media dissector handles */
static dissector_handle_t media_handle;
static dissector_handle_t gssapi_handle;

/* Determines if bodies with no media type dissector should be displayed
 * as raw text, may cause problems with images sound etc
 * TODO improve to check for different content types ?
 */
static gboolean display_unknown_body_as_text = FALSE;
static gboolean remove_base64_encoding = FALSE;


typedef struct {
    const char *type; /* Type of multipart */
    char *boundary; /* Boundary string (enclosing quotes removed if any) */
    guint boundary_length; /* Length of the boundary string */
    char *protocol; /* Protocol string if encrypted multipart (enclosing quotes removed if any) */
    guint protocol_length; /* Length of the protocol string  */
    char *orig_content_type; /* Content-Type of original message */
    char *orig_parameters; /* Parameters for Content-Type of original message */
} multipart_info_t;



static gint
find_first_boundary(tvbuff_t *tvb, gint start, const guint8 *boundary,
        gint boundary_len, gint *boundary_line_len, gboolean *last_boundary);
static gint
find_next_boundary(tvbuff_t *tvb, gint start, const guint8 *boundary,
        gint boundary_len, gint *boundary_line_len, gboolean *last_boundary);
static gint
process_preamble(proto_tree *tree, tvbuff_t *tvb, multipart_info_t *m_info,
        gboolean *last_boundary);
static gint
process_body_part(proto_tree *tree, tvbuff_t *tvb, multipart_info_t *m_info,
        packet_info *pinfo, gint start, gint idx,
        gboolean *last_boundary);
static gint
is_known_multipart_header(const char *header_str, guint len);
static gint
index_of_char(const char *str, const char c);


/* Return a tvb that contains the binary representation of a base64
   string */

static tvbuff_t *
base64_decode(packet_info *pinfo, tvbuff_t *b64_tvb, char *name)
{
    char *data;
    tvbuff_t *tvb;
    data = tvb_get_string_enc(wmem_packet_scope(), b64_tvb, 0, tvb_reported_length(b64_tvb), ENC_ASCII);

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
unfold_and_compact_mime_header(const char *lines, gint *first_colon_offset)
{
    const char *p = lines;
    char c;
    char *ret, *q;
    char sep_seen = 0; /* Did we see a separator ":;," */
    char lws = FALSE; /* Did we see LWS (incl. folding) */
    gint colon = -1;

    if (! lines) return NULL;

    c = *p;
    ret = (char *)wmem_alloc(wmem_packet_scope(), strlen(lines) + 1);
    q = ret;

    while (c) {
        if (c == ':') {
            lws = FALSE; /* Prevent leading LWS from showing up */
            if (colon == -1) {/* First colon */
                colon = (gint) (q - ret);
            }
            *(q++) = sep_seen = c;
            p++;
        } else if (c == ';' || c == ',' || c == '=') {
            lws = FALSE; /* Prevent leading LWS from showing up */
            *(q++) = sep_seen = c;
            p++;
        } else if (c == ' ' || c == '\t') {
            lws = TRUE;
            p++;
        } else if (c == '\n') {
            lws = FALSE; /* Skip trailing LWS */
            if ((c = *(p+1))) {
                if (c == ' ' || c == '\t') { /* Header unfolding */
                    lws = TRUE;
                    p += 2;
                } else {
                    *q = c = 0; /* Stop */
                }
            }
        } else if (c == '\r') {
            lws = FALSE;
            if ((c = *(p+1))) {
                if (c == '\n') {
                    if ((c = *(p+2))) {
                        if (c == ' ' || c == '\t') { /* Header unfolding */
                            lws = TRUE;
                            p += 3;
                        } else {
                            *q = c = 0; /* Stop */
                        }
                    }
                } else if (c == ' ' || c == '\t') { /* Header unfolding */
                    lws = TRUE;
                    p += 2;
                } else {
                    *q = c = 0; /* Stop */
                }
            }
        } else if (c == '"') { /* Start of quoted-string */
            lws = FALSE;
            *(q++) = c;
            while (c) {
                c = *(q++) = *(++p);
                if (c == '"') {
                    p++; /* Skip closing quote */
                    break;
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
            lws = FALSE;
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

/* Return the index of a given char in the given string,
 * or -1 if not found.
 */
static gint
index_of_char(const char *str, const char c)
{
    gint len = 0;
    const char *p = str;

    while (*p && *p != c) {
        p++;
        len++;
    }

    if (*p)
        return len;
    return -1;
}

static char *find_parameter(char *parameters, const char *key, int *retlen)
{
    char *start, *p;
    int   keylen = 0;
    int   len = 0;

    if(!parameters || !*parameters || !key || strlen(key) == 0)
        /* we won't be able to find anything */
        return NULL;

    keylen = (int) strlen(key);
    p = parameters;

    while (*p) {

        while ((*p) && g_ascii_isspace(*p))
            p++; /* Skip white space */

        if (g_ascii_strncasecmp(p, key, keylen) == 0)
            break;
        /* Skip to next parameter */
        p = strchr(p, ';');
        if (p == NULL)
        {
            return NULL;
        }
        p++; /* Skip semicolon */

    }
    if (*p == 0x0)
        return NULL;  /* key wasn't found */

    start = p + keylen;
    if (start[0] == 0) {
        return NULL;
    }

    /*
     * Process the parameter value
     */
    if (start[0] == '"') {
        /*
         * Parameter value is a quoted-string
         */
        start++; /* Skip the quote */
        len = index_of_char(start, '"');
        if (len < 0) {
            /*
             * No closing quote
             */
            return NULL;
        }
    } else {
        /*
         * Look for end of boundary
         */
        p = start;
        while (*p) {
            if (*p == ';' || g_ascii_isspace(*p))
                break;
            p++;
            len++;
        }
    }

    if(retlen)
        (*retlen) = len;

    return start;
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
get_multipart_info(packet_info *pinfo, const char *str)
{
    const char *start_boundary, *start_protocol = NULL;
    int len_boundary = 0, len_protocol = 0;
    multipart_info_t *m_info = NULL;
    const char *type = pinfo->match_string;
    char *parameters;
    gint dummy;

    if ((type == NULL) || (str == NULL)) {
        /*
         * We need both a content type AND parameters
         * for multipart dissection.
         */
        return NULL;
    }

    /* Clean up the parameters */
    parameters = unfold_and_compact_mime_header(str, &dummy);

    start_boundary = find_parameter(parameters, "boundary=", &len_boundary);

    if(!start_boundary) {
        return NULL;
    }
    if(strncmp(type, "multipart/encrypted", sizeof("multipart/encrypted")-1) == 0) {
        start_protocol = find_parameter(parameters, "protocol=", &len_protocol);
        if(!start_protocol) {
            return NULL;
        }
    }

    /*
     * There is a value for the boundary string
     */
    m_info = (multipart_info_t *)g_malloc(sizeof(multipart_info_t));
    m_info->type = type;
    m_info->boundary = g_strndup(start_boundary, len_boundary);
    m_info->boundary_length = len_boundary;
    if(start_protocol) {
        m_info->protocol = g_strndup(start_protocol, len_protocol);
        m_info->protocol_length = len_protocol;
    } else {
        m_info->protocol = NULL;
        m_info->protocol_length = -1;
    }
    m_info->orig_content_type = NULL;
    m_info->orig_parameters = NULL;

    return m_info;
}

static void
cleanup_multipart_info(void *data)
{
    multipart_info_t *m_info = (multipart_info_t *)data;
    if (m_info) {
        if (m_info->protocol) {
            g_free(m_info->protocol);
        }
        g_free(m_info->boundary);
        g_free(m_info);
    }
}

/*
 * The first boundary does not implicitly contain the leading
 * line-end sequence.
 *
 * Return the offset to the 1st byte of the boundary delimiter line.
 * Set boundary_line_len to the length of the entire boundary delimiter.
 * Set last_boundary to TRUE if we've seen the last-boundary delimiter.
 */
static gint
find_first_boundary(tvbuff_t *tvb, gint start, const guint8 *boundary,
        gint boundary_len, gint *boundary_line_len, gboolean *last_boundary)
{
    gint offset = start, next_offset, line_len, boundary_start;

    while (tvb_offset_exists(tvb, offset + 2 + boundary_len)) {
        boundary_start = offset;
        if (((tvb_strneql(tvb, offset, (const guint8 *)"--", 2) == 0)
                    && (tvb_strneql(tvb, offset + 2, boundary,  boundary_len) == 0)))
        {
            /* Boundary string; now check if last */
            if ((tvb_reported_length_remaining(tvb, offset + 2 + boundary_len + 2) >= 0)
                    && (tvb_strneql(tvb, offset + 2 + boundary_len,
                            (const guint8 *)"--", 2) == 0)) {
                *last_boundary = TRUE;
            } else {
                *last_boundary = FALSE;
            }
            /* Look for line end of the boundary line */
            line_len =  tvb_find_line_end(tvb, offset, -1, &offset, FALSE);
            if (line_len == -1) {
                *boundary_line_len = -1;
            } else {
                *boundary_line_len = offset - boundary_start;
            }
            return boundary_start;
        }
        line_len =  tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
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
 * Set last_boundary to TRUE if we've seen the last-boundary delimiter.
 */
static gint
find_next_boundary(tvbuff_t *tvb, gint start, const guint8 *boundary,
        gint boundary_len, gint *boundary_line_len, gboolean *last_boundary)
{
    gint offset = start, next_offset, line_len, boundary_start;

    while (tvb_offset_exists(tvb, offset + 2 + boundary_len)) {
        line_len =  tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        if (line_len == -1) {
            return -1;
        }
        boundary_start = offset + line_len;
        if (((tvb_strneql(tvb, next_offset, (const guint8 *)"--", 2) == 0)
                    && (tvb_strneql(tvb, next_offset + 2, boundary, boundary_len) == 0)))
        {
            /* Boundary string; now check if last */
            if ((tvb_reported_length_remaining(tvb, next_offset + 2 + boundary_len + 2) >= 0)
                    && (tvb_strneql(tvb, next_offset + 2 + boundary_len,
                            (const guint8 *)"--", 2) == 0)) {
                *last_boundary = TRUE;
            } else {
                *last_boundary = FALSE;
            }
            /* Look for line end of the boundary line */
            line_len =  tvb_find_line_end(tvb, next_offset, -1, &offset, FALSE);
            if (line_len == -1) {
                *boundary_line_len = -1;
            } else {
                *boundary_line_len = offset - boundary_start;
            }
            return boundary_start;
        /* check if last before CRLF; some ignore the standard, so there is no CRLF before the boundary */
        } else if ((tvb_strneql(tvb, boundary_start - 2, (const guint8 *)"--", 2) == 0)
                    && (tvb_strneql(tvb, boundary_start - (2 + boundary_len), boundary, boundary_len) == 0)
                    && (tvb_strneql(tvb, boundary_start - (2 + boundary_len + 2),
                            (const guint8 *)"--", 2) == 0)) {
            boundary_start -= 2 + boundary_len + 2;
            *boundary_line_len = next_offset - boundary_start;
            *last_boundary = TRUE;
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
static gint
process_preamble(proto_tree *tree, tvbuff_t *tvb, multipart_info_t *m_info,
        gboolean *last_boundary)
{
    gint boundary_start, boundary_line_len;

    const guint8 *boundary = (guint8 *)m_info->boundary;
    gint boundary_len = m_info->boundary_length;

    boundary_start = find_first_boundary(tvb, 0, boundary, boundary_len,
            &boundary_line_len, last_boundary);
    if (boundary_start == 0) {
       proto_tree_add_item(tree, hf_multipart_first_boundary, tvb, boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
        return boundary_start + boundary_line_len;
    } else if (boundary_start > 0) {
        if (boundary_line_len > 0) {
            gint body_part_start = boundary_start + boundary_line_len;

            if (boundary_start > 0) {
               proto_tree_add_item(tree, hf_multipart_preamble, tvb, 0, boundary_start, ENC_NA);
            }
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
    gint offset = 0, len;
    guint8 *data;

    proto_tree_add_item(tree, hf_multipart_sec_token_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    len = tvb_reported_length_remaining(tvb, offset);

    DISSECTOR_ASSERT(tvb_bytes_exist(tvb, offset, len));

    data = (guint8 *) g_malloc(len);
    tvb_memcpy(tvb, data, offset, len);
    kerberos_tvb = tvb_new_child_real_data(tvb, data, len, len);
    tvb_set_free_cb(kerberos_tvb, g_free);

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
static gint
process_body_part(proto_tree *tree, tvbuff_t *tvb, multipart_info_t *m_info,
        packet_info *pinfo, gint start, gint idx,
        gboolean *last_boundary)
{
    proto_tree *subtree;
    proto_item *ti;
    gint offset = start, next_offset = 0;
    char *parameters = NULL;
    gint body_start, boundary_start, boundary_line_len;

    gchar *content_type_str = NULL;
    gchar *content_encoding_str = NULL;
    char *filename = NULL;
    char *mimetypename = NULL;
    int  len = 0;
    gboolean last_field = FALSE;
    gboolean is_raw_data = FALSE;

    const guint8 *boundary = (guint8 *)m_info->boundary;
    gint boundary_len = m_info->boundary_length;

    ti = proto_tree_add_item(tree, hf_multipart_part, tvb, start, 0, ENC_ASCII|ENC_NA);
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
        gint colon_offset;
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
            last_field = TRUE;
            next_offset -= 2;
        } else if (next_offset > boundary_start) {
            /* if there is no CRLF between last field and next boundary - trim it! */
            next_offset = boundary_start;
        }

        hdr_str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, next_offset - offset, ENC_ASCII);

        header_str = unfold_and_compact_mime_header(hdr_str, &colon_offset);
        if (colon_offset <= 0) {
            /* if there is no colon it's no header, so break and add complete line to the body */
            next_offset = offset;
            break;
        } else {
            gint hf_index;

            /* Split header name from header value */
            header_str[colon_offset] = '\0';
            hf_index = is_known_multipart_header(header_str, colon_offset);

            if (hf_index == -1) {
                if(isprint_string(hdr_str)) {
                    proto_tree_add_format_text(subtree, tvb, offset, next_offset - offset);
                } else {
                    /* if the header name is unkown and not printable, break and add complete line to the body */
                    next_offset = offset;
                    break;
                }
            } else {
                char *value_str = header_str + colon_offset + 1;

                proto_tree_add_string_format(subtree,
                      hf_header_array[hf_index], tvb,
                      offset, next_offset - offset,
                      (const char *)value_str, "%s",
                      tvb_format_text(tvb, offset, next_offset - offset));

                switch (hf_index) {
                    case POS_ORIGINALCONTENT:
                        {
                            gint semicolon_offset;
                            /* The Content-Type starts at colon_offset + 1 or after the type parameter */
                            char* type_str = find_parameter(value_str, "type=", NULL);
                            if(type_str != NULL) {
                                value_str = type_str;
                            }

                            semicolon_offset = index_of_char(
                                    value_str, ';');

                            if (semicolon_offset > 0) {
                                value_str[semicolon_offset] = '\0';
                                m_info->orig_parameters = wmem_strdup(wmem_packet_scope(),
                                                            value_str + semicolon_offset + 1);
                            }

                            m_info->orig_content_type = wmem_ascii_strdown(wmem_packet_scope(), value_str, -1);
                        }
                        break;
                    case POS_CONTENT_TYPE:
                        {
                            /* The Content-Type starts at colon_offset + 1 */
                            gint semicolon_offset = index_of_char(
                                    value_str, ';');

                            if (semicolon_offset > 0) {
                                value_str[semicolon_offset] = '\0';
                                parameters = wmem_strdup(wmem_packet_scope(), value_str + semicolon_offset + 1);
                            } else {
                                parameters = NULL;
                            }

                            content_type_str = wmem_ascii_strdown(wmem_packet_scope(), value_str, -1);

                            /* Show content-type in root 'part' label */
                            proto_item_append_text(ti, " (%s)", content_type_str);

                            /* find the "name" parameter in case we don't find a content disposition "filename" */
                            if((mimetypename = find_parameter(parameters, "name=", &len)) != NULL) {
                              mimetypename = g_strndup(mimetypename, len);
                            }

                            if(strncmp(content_type_str, "application/octet-stream",
                                    sizeof("application/octet-stream")-1) == 0) {
                                is_raw_data = TRUE;
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
                        case POS_CONTENT_TRANSFER_ENCODING:
                        {
                            /* The Content-Transferring starts at colon_offset + 1 */
                            gint cr_offset = index_of_char(value_str, '\r');

                            if (cr_offset > 0) {
                                value_str[cr_offset] = '\0';
                            }

                            content_encoding_str = wmem_ascii_strdown(wmem_packet_scope(), value_str, -1);
                        }
                        break;
                        case POS_CONTENT_DISPOSITION:
                            {
                            /* find the "filename" parameter */
                            if((filename = find_parameter(value_str, "filename=", &len)) != NULL) {
                                filename = g_strndup(filename, len);
                            }
                        }
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
        gint body_len = boundary_start - body_start;
        tvbuff_t *tmp_tvb = tvb_new_subset_length(tvb, body_start, body_len);
        /* if multipart subtype is encrypted the protcol string was set */
        /* see: https://msdn.microsoft.com/en-us/library/cc251581.aspx */
        /* there are only 2 body parts possible and each part has specific content types */
        if(m_info->protocol && idx == 1 && is_raw_data)
        {
            gssapi_encrypt_info_t  encrypt;

            memset(&encrypt, 0, sizeof(encrypt));
            encrypt.decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;

            dissect_kerberos_encrypted_message(tmp_tvb, pinfo, subtree, &encrypt);

            if(encrypt.gssapi_decrypted_tvb){
                    tmp_tvb = encrypt.gssapi_decrypted_tvb;
                    is_raw_data = FALSE;
                    content_type_str = m_info->orig_content_type;
                    parameters = m_info->orig_parameters;
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
            gboolean dissected;

            /*
             * Try and remove any content transfer encoding so that each sub-dissector
             * doesn't have to do it itself
             *
             */

            if(content_encoding_str && remove_base64_encoding) {

                if(!g_ascii_strncasecmp(content_encoding_str, "base64", 6))
                    tmp_tvb = base64_decode(pinfo, tmp_tvb, filename ? filename : (mimetypename ? mimetypename : content_type_str));

            }

            /*
             * First try the dedicated multipart dissector table
             */
            dissected = dissector_try_string(multipart_media_subdissector_table,
                        content_type_str, tmp_tvb, pinfo, subtree, parameters);
            if (! dissected) {
                /*
                 * Fall back to the default media dissector table
                 */
                dissected = dissector_try_string(media_type_dissector_table,
                        content_type_str, tmp_tvb, pinfo, subtree, parameters);
            }
            if (! dissected) {
                const char *save_match_string = pinfo->match_string;
                pinfo->match_string = content_type_str;
                call_dissector_with_data(media_handle, tmp_tvb, pinfo, subtree, parameters);
                pinfo->match_string = save_match_string;
            }
            parameters = NULL; /* Shares same memory as content_type_str */
        } else {
            call_data_dissector(tmp_tvb, pinfo, subtree);
        }
        proto_item_set_len(ti, boundary_start - start);
        if (*last_boundary == TRUE) {
           proto_tree_add_item(tree, hf_multipart_last_boundary, tvb, boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
        } else {
           proto_tree_add_item(tree, hf_multipart_boundary, tvb, boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
        }

        g_free(filename);
        g_free(mimetypename);

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
    multipart_info_t *m_info = get_multipart_info(pinfo, (const char*)data);
    gint header_start = 0;
    gint body_index = 0;
    gboolean last_boundary = FALSE;

    if (m_info == NULL) {
        /*
         * We can't get the required multipart information
         */
        proto_tree_add_expert(tree, pinfo, &ei_multipart_no_required_parameter, tvb, 0, -1);
        call_data_dissector(tvb, pinfo, tree);
        return tvb_reported_length(tvb);
    }
    /* Clean up the memory if an exception is thrown */
    /* CLEANUP_PUSH(cleanup_multipart_info, m_info); */

    /* Add stuff to the protocol tree */
    ti = proto_tree_add_item(tree, proto_multipart,
          tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_multipart);
    proto_item_append_text(ti, ", Type: %s, Boundary: \"%s\"",
          m_info->type, m_info->boundary);

    /* Show multi-part type as a generated field */
    type_ti = proto_tree_add_string(subtree, hf_multipart_type,
          tvb, 0, 0, pinfo->match_string);
    PROTO_ITEM_SET_GENERATED(type_ti);

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
        /* Clean up the dynamically allocated memory */
        cleanup_multipart_info(m_info);
        return tvb_reported_length(tvb);
    }
    /*
     * Process the encapsulated bodies
     */
    while (last_boundary == FALSE) {
        header_start = process_body_part(subtree, tvb, m_info,
                pinfo, header_start, body_index++, &last_boundary);
        if (header_start == -1) {
            /* Clean up the dynamically allocated memory */
            cleanup_multipart_info(m_info);
            return tvb_reported_length(tvb);
        }
    }
    /*
     * Process the multipart trailer
     */
    if (tvb_reported_length_remaining(tvb, header_start) > 0) {
       proto_tree_add_item(subtree, hf_multipart_trailer, tvb, header_start, -1, ENC_NA);
    }
    /* Clean up the dynamically allocated memory */
    cleanup_multipart_info(m_info);
    return tvb_reported_length(tvb);
}

/* Returns index of method in multipart_headers */
static gint
is_known_multipart_header(const char *header_str, guint len)
{
    guint i;

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
    static gint *ett[] = {
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
    proto_multipart = proto_register_protocol(
        "MIME Multipart Media Encapsulation",
        "MIME multipart",
        "mime_multipart");

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

    /*
     * Dissectors requiring different behavior in cases where the media
     * is contained in a multipart entity should register their multipart
     * dissector in the dissector table below, which is similar to the
     * "media_type" dissector table defined in the HTTP dissector code.
     */
    multipart_media_subdissector_table = register_dissector_table(
        "multipart_media_type",
        "Internet media type (for multipart processing)",
        proto_multipart, FT_STRING, BASE_NONE, DISSECTOR_TABLE_NOT_ALLOW_DUPLICATE);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_multipart(void)
{
    dissector_handle_t multipart_handle;

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

    /*
     * Handle for multipart dissection
     */
    multipart_handle = create_dissector_handle(
            dissect_multipart, proto_multipart);

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
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
