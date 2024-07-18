/* packet-pgsql.c
 * Routines for PostgreSQL v3 protocol dissection.
 * <http://www.postgresql.org/docs/current/static/protocol.html>
 * Copyright 2004 Abhijit Menon-Sen <ams@oryx.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-gssapi.h"
#include "packet-tls-utils.h"
#include "packet-tcp.h"

void proto_register_pgsql(void);
void proto_reg_handoff_pgsql(void);

static dissector_handle_t pgsql_handle;
static dissector_handle_t pgsql_gssapi_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t gssapi_handle;
static dissector_handle_t ntlmssp_handle;

static int proto_pgsql;
static int hf_frontend;
static int hf_type;
static int hf_length;
static int hf_version_major;
static int hf_version_minor;
static int hf_request_code;
static int hf_supported_minor_version;
static int hf_number_nonsupported_options;
static int hf_nonsupported_option;
static int hf_parameter_name;
static int hf_parameter_value;
static int hf_query;
static int hf_authtype;
static int hf_passwd;
static int hf_salt;
static int hf_gssapi_sspi_data;
static int hf_sasl_auth_mech;
static int hf_sasl_auth_data;
static int hf_sasl_auth_data_length;
static int hf_statement;
static int hf_portal;
static int hf_return;
static int hf_tag;
static int hf_status;
static int hf_copydata;
static int hf_error;
static int hf_pid;
static int hf_key;
static int hf_condition;
static int hf_text;
static int hf_tableoid;
static int hf_typeoid;
static int hf_oid;
static int hf_format;
static int hf_field_count;
static int hf_val_name;
static int hf_val_idx;
static int hf_val_length;
static int hf_val_data;
static int hf_val_mod;
static int hf_severity;
static int hf_code;
static int hf_message;
static int hf_detail;
static int hf_hint;
static int hf_position;
static int hf_internal_position;
static int hf_internal_query;
static int hf_where;
static int hf_schema_name;
static int hf_table_name;
static int hf_column_name;
static int hf_type_name;
static int hf_constraint_name;
static int hf_file;
static int hf_line;
static int hf_routine;
static int hf_ssl_response;
static int hf_gssenc_response;
static int hf_gssapi_encrypted_payload;

static int ett_pgsql;
static int ett_values;

#define PGSQL_PORT 5432
static bool pgsql_desegment = true;
static bool first_message = true;

typedef enum {
  /* Reserve 0 (== GPOINTER_TO_UINT(NULL)) for no PGSQL detected */
  PGSQL_AUTH_STATE_NONE = 1,           /* No authentication seen or used */
  PGSQL_AUTH_SASL_REQUESTED,           /* Server sends SASL auth request with supported SASL mechanisms*/
  PGSQL_AUTH_SASL_CONTINUE,            /* Server and/or client send further SASL challenge-response messages */
  PGSQL_AUTH_GSSAPI_SSPI_DATA,         /* GSSAPI/SSPI in use */
  PGSQL_AUTH_SSL_REQUESTED,            /* Client sends SSL encryption request */
  PGSQL_AUTH_GSSENC_REQUESTED,         /* Client sends GSSAPI encryption request */
} pgsql_auth_state_t;

typedef struct pgsql_conn_data {
    wmem_tree_t *state_tree;   /* Tree of encryption and auth state changes */
    uint32_t     server_port;
} pgsql_conn_data_t;

static const value_string fe_messages[] = {
    { 'p', "Authentication message" },
    { 'Q', "Simple query" },
    { 'P', "Parse" },
    { 'B', "Bind" },
    { 'E', "Execute" },
    { 'D', "Describe" },
    { 'C', "Close" },
    { 'H', "Flush" },
    { 'S', "Sync" },
    { 'F', "Function call" },
    { 'd', "Copy data" },
    { 'c', "Copy completion" },
    { 'f', "Copy failure" },
    { 'X', "Termination" },
    { 0, NULL }
};

static const value_string be_messages[] = {
    { 'R', "Authentication request" },
    { 'K', "Backend key data" },
    { 'S', "Parameter status" },
    { '1', "Parse completion" },
    { '2', "Bind completion" },
    { '3', "Close completion" },
    { 'C', "Command completion" },
    { 't', "Parameter description" },
    { 'T', "Row description" },
    { 'D', "Data row" },
    { 'I', "Empty query" },
    { 'n', "No data" },
    { 'E', "Error" },
    { 'N', "Notice" },
    { 's', "Portal suspended" },
    { 'Z', "Ready for query" },
    { 'A', "Notification" },
    { 'V', "Function call response" },
    { 'G', "CopyIn response" },
    { 'H', "CopyOut response" },
    { 'd', "Copy data" },
    { 'c', "Copy completion" },
    { 'v', "Negotiate protocol version" },
    { 0, NULL }
};

#define PGSQL_AUTH_TYPE_SUCCESS 0
#define PGSQL_AUTH_TYPE_KERBEROS4 1
#define PGSQL_AUTH_TYPE_KERBEROS5 2
#define PGSQL_AUTH_TYPE_PLAINTEXT 3
#define PGSQL_AUTH_TYPE_CRYPT 4
#define PGSQL_AUTH_TYPE_MD5 5
#define PGSQL_AUTH_TYPE_SCM 6
#define PGSQL_AUTH_TYPE_GSSAPI 7
#define PGSQL_AUTH_TYPE_GSSAPI_SSPI_CONTINUE 8
#define PGSQL_AUTH_TYPE_SSPI 9
#define PGSQL_AUTH_TYPE_SASL 10
#define PGSQL_AUTH_TYPE_SASL_CONTINUE 11
#define PGSQL_AUTH_TYPE_SASL_COMPLETE 12

static const value_string auth_types[] = {
    { PGSQL_AUTH_TYPE_SUCCESS              , "Success" },
    { PGSQL_AUTH_TYPE_KERBEROS4            , "Kerberos V4" },
    { PGSQL_AUTH_TYPE_KERBEROS5            , "Kerberos V5" },
    { PGSQL_AUTH_TYPE_PLAINTEXT            , "Plaintext password" },
    { PGSQL_AUTH_TYPE_CRYPT                , "crypt()ed password" },
    { PGSQL_AUTH_TYPE_MD5                  , "MD5 password" },
    { PGSQL_AUTH_TYPE_SCM                  , "SCM credentials" },
    { PGSQL_AUTH_TYPE_GSSAPI               , "GSSAPI" },
    { PGSQL_AUTH_TYPE_GSSAPI_SSPI_CONTINUE , "GSSAPI/SSPI continue" },
    { PGSQL_AUTH_TYPE_SSPI                 , "SSPI" },
    { PGSQL_AUTH_TYPE_SASL                 , "SASL" },
    { PGSQL_AUTH_TYPE_SASL_CONTINUE        , "SASL continue" },
    { PGSQL_AUTH_TYPE_SASL_COMPLETE        , "SASL complete" },
    { 0, NULL }
};

static const value_string status_vals[] = {
    { 'I', "Idle" },
    { 'T', "In a transaction" },
    { 'E', "In a failed transaction" },
    { 0, NULL }
};

static const value_string format_vals[] = {
    { 0, "Text" },
    { 1, "Binary" },
    { 0, NULL }
};

#define PGSQL_CANCELREQUEST 80877102
#define PGSQL_SSLREQUEST    80877103
#define PGSQL_GSSENCREQUEST 80877104

static const value_string request_code_vals[] = {
    { PGSQL_CANCELREQUEST, "CancelRequest" },
    { PGSQL_SSLREQUEST,    "SSLRequest" },
    { PGSQL_GSSENCREQUEST, "GSSENCRequest" },
    { 0, NULL }
};

static const value_string ssl_response_vals[] = {
    { 'N', "Unwilling to perform SSL" },
    { 'S', "Willing to perform SSL" },
    { 0, NULL }
};

static const value_string gssenc_response_vals[] = {
    { 'G', "Willing to perform GSSAPI encryption" },
    { 'N', "Unwilling to perform GSSAPI encryption" },
    { 0, NULL }
};

static void dissect_pgsql_fe_msg(unsigned char type, unsigned length, tvbuff_t *tvb,
                                 int n, proto_tree *tree, packet_info *pinfo,
                                 pgsql_conn_data_t *conv_data)
{
    unsigned char c;
    int i, siz;
    char *s;
    proto_tree *shrub;
    int32_t data_length;
    pgsql_auth_state_t   state;
    tvbuff_t *next_tvb;
    dissector_handle_t payload_handle;

    switch (type) {
    /* Password, SASL or GSSAPI Response, depending on context */
    case 'p':
        state = GPOINTER_TO_UINT(wmem_tree_lookup32_le(conv_data->state_tree, pinfo->num));
        switch(state) {

            case PGSQL_AUTH_SASL_REQUESTED:
                /* SASLInitResponse */
                siz = tvb_strsize(tvb, n);
                proto_tree_add_item(tree, hf_sasl_auth_mech, tvb, n, siz, ENC_ASCII);
                n += siz;
                proto_tree_add_item_ret_int(tree, hf_sasl_auth_data_length, tvb, n, 4, ENC_BIG_ENDIAN, &data_length);
                n += 4;
                if (data_length) {
                    proto_tree_add_item(tree, hf_sasl_auth_data, tvb, n, data_length, ENC_NA);
                }
                break;

            case PGSQL_AUTH_SASL_CONTINUE:
                proto_tree_add_item(tree, hf_sasl_auth_data, tvb, n, length-4, ENC_NA);
                break;

            case PGSQL_AUTH_GSSAPI_SSPI_DATA:
                next_tvb = tvb_new_subset_length(tvb, n, length - 4);
                /* https://www.postgresql.org/docs/current/sspi-auth.html
                 * "PostgreSQL will use SSPI in negotiate mode, which will use
                 * Kerberos when possible and automatically fall back to NTLM
                 * in other cases... When using Kerberos authentication, SSPI
                 * works the same way GSSAPI does."
                 * Assume this means the Kerberos mode for SSPI works like
                 * GSSAPI, and not, say, SPNEGO the way TDS does. (Need
                 * a sample.)
                 */
                if (tvb_strneql(next_tvb, 0, "NTLMSSP", 7) == 0) {
                    payload_handle = ntlmssp_handle;
                } else {
                    payload_handle = gssapi_handle;
                }
                n = call_dissector_only(payload_handle, next_tvb, pinfo, tree, NULL);
                if ((length = tvb_reported_length_remaining(next_tvb, n))) {
                    proto_tree_add_item(tree, hf_gssapi_sspi_data, next_tvb, n, length, ENC_NA);
                }
                break;

            default:
                siz = tvb_strsize(tvb, n);
                proto_tree_add_item(tree, hf_passwd, tvb, n, siz, ENC_ASCII);
                break;
        }
        break;

    /* Simple query */
    case 'Q':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_query, tvb, n, siz, ENC_ASCII);
        break;

    /* Parse */
    case 'P':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_statement, tvb, n, siz, ENC_ASCII);
        n += siz;

        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_query, tvb, n, siz, ENC_ASCII);
        n += siz;

        i = tvb_get_ntohs(tvb, n);
        shrub = proto_tree_add_subtree_format(tree, tvb, n, 2, ett_values, NULL, "Parameters: %d", i);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_typeoid, tvb, n, 4, ENC_BIG_ENDIAN);
            n += 4;
        }
        break;

    /* Bind */
    case 'B':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_portal, tvb, n, siz, ENC_ASCII);
        n += siz;

        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_statement, tvb, n, siz, ENC_ASCII);
        n += siz;

        i = tvb_get_ntohs(tvb, n);
        shrub = proto_tree_add_subtree_format(tree, tvb, n, 2, ett_values, NULL, "Parameter formats: %d", i);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
        }

        i = tvb_get_ntohs(tvb, n);
        shrub = proto_tree_add_subtree_format(tree, tvb, n, 2, ett_values, NULL, "Parameter values: %d", i);
        n += 2;
        while (i-- > 0) {
            siz = tvb_get_ntohl(tvb, n);
            proto_tree_add_int(shrub, hf_val_length, tvb, n, 4, siz);
            n += 4;
            if (siz > 0) {
                proto_tree_add_item(shrub, hf_val_data, tvb, n, siz, ENC_NA);
                n += siz;
            }
        }

        i = tvb_get_ntohs(tvb, n);
        shrub = proto_tree_add_subtree_format(tree, tvb, n, 2, ett_values, NULL, "Result formats: %d", i);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
        }
        break;

    /* Execute */
    case 'E':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_portal, tvb, n, siz, ENC_ASCII);
        n += siz;

        i = tvb_get_ntohl(tvb, n);
        if (i == 0)
            proto_tree_add_uint_format_value(tree, hf_return, tvb, n, 4, i, "all rows");
        else
            proto_tree_add_uint_format_value(tree, hf_return, tvb, n, 4, i, "%d rows", i);
        break;

    /* Describe, Close */
    case 'D':
    case 'C':
        c = tvb_get_uint8(tvb, n);
        if (c == 'P')
            i = hf_portal;
        else
            i = hf_statement;

        n += 1;
        s = tvb_get_stringz_enc(pinfo->pool, tvb, n, &siz, ENC_ASCII);
        proto_tree_add_string(tree, i, tvb, n, siz, s);
        break;

    /* Messages without a type identifier */
    case '\0':
        i = tvb_get_ntohl(tvb, n);
        n += 4;
        length -= n;
        switch (i) {
        /* Startup message */
        case 196608:
            proto_tree_add_item(tree, hf_version_major, tvb, n-4, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_version_minor, tvb, n-2, 2, ENC_BIG_ENDIAN);
            while ((signed)length > 0) {
                siz = tvb_strsize(tvb, n);
                length -= siz;
                if ((signed)length <= 0) {
                    break;
                }
                proto_tree_add_item(tree, hf_parameter_name,  tvb, n,       siz, ENC_ASCII);
                i = tvb_strsize(tvb, n+siz);
                proto_tree_add_item(tree, hf_parameter_value, tvb, n + siz, i,   ENC_ASCII);
                length -= i;

                n += siz+i;
                if (length == 1 && tvb_get_uint8(tvb, n) == 0)
                    break;
            }
            break;

        case PGSQL_SSLREQUEST:
            proto_tree_add_item(tree, hf_request_code, tvb, n-4, 4, ENC_BIG_ENDIAN);
            /* Next reply will be a single byte. */
            wmem_tree_insert32(conv_data->state_tree, pinfo->num, GUINT_TO_POINTER(PGSQL_AUTH_SSL_REQUESTED));
            break;

        case PGSQL_GSSENCREQUEST:
            proto_tree_add_item(tree, hf_request_code, tvb, n-4, 4, ENC_BIG_ENDIAN);
            /* Next reply will be a single byte. */
            wmem_tree_insert32(conv_data->state_tree, pinfo->num, GUINT_TO_POINTER(PGSQL_AUTH_GSSENC_REQUESTED));
            break;

        case PGSQL_CANCELREQUEST:
            proto_tree_add_item(tree, hf_request_code, tvb, n-4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_pid, tvb, n,   4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_key, tvb, n+4, 4, ENC_BIG_ENDIAN);
            break;
        }
        break;

    /* Copy data */
    case 'd':
        proto_tree_add_item(tree, hf_copydata, tvb, n, length-n+1, ENC_NA);
        break;

    /* Copy failure */
    case 'f':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_error, tvb, n, siz, ENC_ASCII);
        break;

    /* Function call */
    case 'F':
        proto_tree_add_item(tree, hf_oid, tvb, n, 4, ENC_BIG_ENDIAN);
        n += 4;

        i = tvb_get_ntohs(tvb, n);
        shrub = proto_tree_add_subtree_format(tree, tvb, n, 2, ett_values, NULL, "Parameter formats: %d", i);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
        }

        i = tvb_get_ntohs(tvb, n);
        shrub = proto_tree_add_subtree_format(tree, tvb, n, 2, ett_values, NULL, "Parameter values: %d", i);
        n += 2;
        while (i-- > 0) {
            siz = tvb_get_ntohl(tvb, n);
            proto_tree_add_item(shrub, hf_val_length, tvb, n, 4, ENC_BIG_ENDIAN);
            n += 4;
            if (siz > 0) {
                proto_tree_add_item(shrub, hf_val_data, tvb, n, siz, ENC_NA);
                n += siz;
            }
        }

        proto_tree_add_item(tree, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
        break;
    }
}


static void dissect_pgsql_be_msg(unsigned char type, unsigned length, tvbuff_t *tvb,
                                 int n, proto_tree *tree, packet_info *pinfo,
                                 pgsql_conn_data_t *conv_data)
{
    unsigned char c;
    int i, siz;
    char *s, *t;
    int32_t num_nonsupported_options;
    proto_item *ti;
    proto_tree *shrub;
    uint32_t auth_type;

    switch (type) {
    /* Authentication request */
    case 'R':
        proto_tree_add_item_ret_uint(tree, hf_authtype, tvb, n, 4, ENC_BIG_ENDIAN, &auth_type);
        switch (auth_type) {
        case PGSQL_AUTH_TYPE_CRYPT:
        case PGSQL_AUTH_TYPE_MD5:
            n += 4;
            siz = (auth_type == PGSQL_AUTH_TYPE_CRYPT ? 2 : 4);
            proto_tree_add_item(tree, hf_salt, tvb, n, siz, ENC_NA);
            break;
        case PGSQL_AUTH_TYPE_GSSAPI_SSPI_CONTINUE:
            proto_tree_add_item(tree, hf_gssapi_sspi_data, tvb, n, length-8, ENC_NA);
            /* FALLTHROUGH */
        case PGSQL_AUTH_TYPE_GSSAPI:
        case PGSQL_AUTH_TYPE_SSPI:
            wmem_tree_insert32(conv_data->state_tree, pinfo->num, GUINT_TO_POINTER(PGSQL_AUTH_GSSAPI_SSPI_DATA));
            break;
        case PGSQL_AUTH_TYPE_SASL:
            wmem_tree_insert32(conv_data->state_tree, pinfo->num, GUINT_TO_POINTER(PGSQL_AUTH_SASL_REQUESTED));
            n += 4;
            while ((unsigned)n < length) {
                siz = tvb_strsize(tvb, n);
                proto_tree_add_item(tree, hf_sasl_auth_mech, tvb, n, siz, ENC_ASCII);
                n += siz;
            }
            break;
        case PGSQL_AUTH_TYPE_SASL_CONTINUE:
        case PGSQL_AUTH_TYPE_SASL_COMPLETE:
            wmem_tree_insert32(conv_data->state_tree, pinfo->num, GUINT_TO_POINTER(PGSQL_AUTH_SASL_CONTINUE));
            n += 4;
            if ((unsigned)n < length) {
                proto_tree_add_item(tree, hf_sasl_auth_data, tvb, n, length-8, ENC_NA);
            }
            break;
        }
        break;

    /* Key data */
    case 'K':
        proto_tree_add_item(tree, hf_pid, tvb, n,   4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_key, tvb, n+4, 4, ENC_BIG_ENDIAN);
        break;

    /* Parameter status */
    case 'S':
        s = tvb_get_stringz_enc(pinfo->pool, tvb, n, &siz, ENC_ASCII);
        proto_tree_add_string(tree, hf_parameter_name, tvb, n, siz, s);
        n += siz;
        t = tvb_get_stringz_enc(pinfo->pool, tvb, n, &i, ENC_ASCII);
        proto_tree_add_string(tree, hf_parameter_value, tvb, n, i, t);
        break;

    /* Parameter description */
    case 't':
        i = tvb_get_ntohs(tvb, n);
        shrub = proto_tree_add_subtree_format(tree, tvb, n, 2, ett_values, NULL, "Parameters: %d", i);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_typeoid, tvb, n, 4, ENC_BIG_ENDIAN);
            n += 4;
        }
        break;

    /* Row description */
    case 'T':
        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_item(tree, hf_field_count, tvb, n, 2, ENC_BIG_ENDIAN);
        shrub = proto_item_add_subtree(ti, ett_values);
        n += 2;
        while (i-- > 0) {
            proto_tree *twig;
            siz = tvb_strsize(tvb, n);
            ti = proto_tree_add_item(shrub, hf_val_name, tvb, n, siz, ENC_ASCII);
            twig = proto_item_add_subtree(ti, ett_values);
            n += siz;
            proto_tree_add_item(twig, hf_tableoid, tvb, n, 4, ENC_BIG_ENDIAN);
            n += 4;
            proto_tree_add_item(twig, hf_val_idx, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
            proto_tree_add_item(twig, hf_typeoid, tvb, n, 4, ENC_BIG_ENDIAN);
            n += 4;
            proto_tree_add_item(twig, hf_val_length, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
            proto_tree_add_item(twig, hf_val_mod, tvb, n, 4, ENC_BIG_ENDIAN);
            n += 4;
            proto_tree_add_item(twig, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
        }
        break;

    /* Data row */
    case 'D':
        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_item(tree, hf_field_count, tvb, n, 2, ENC_BIG_ENDIAN);
        shrub = proto_item_add_subtree(ti, ett_values);
        n += 2;
        while (i-- > 0) {
            siz = tvb_get_ntohl(tvb, n);
            proto_tree_add_int(shrub, hf_val_length, tvb, n, 4, siz);
            n += 4;
            if (siz > 0) {
                proto_tree_add_item(shrub, hf_val_data, tvb, n, siz, ENC_NA);
                n += siz;
            }
        }
        break;

    /* Command completion */
    case 'C':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_tag, tvb, n, siz, ENC_ASCII);
        break;

    /* Ready */
    case 'Z':
        proto_tree_add_item(tree, hf_status, tvb, n, 1, ENC_BIG_ENDIAN);
        break;

    /* Error, Notice */
    case 'E':
    case 'N':
        length -= 4;
        while ((signed)length > 0) {
            c = tvb_get_uint8(tvb, n);
            if (c == '\0')
                break;
            --length;
            s = tvb_get_stringz_enc(pinfo->pool, tvb, n+1, &siz, ENC_ASCII);
            i = hf_text;
            switch (c) {
            case 'S': i = hf_severity;          break;
            case 'C': i = hf_code;              break;
            case 'M': i = hf_message;           break;
            case 'D': i = hf_detail;            break;
            case 'H': i = hf_hint;              break;
            case 'P': i = hf_position;          break;
            case 'p': i = hf_internal_position; break;
            case 'q': i = hf_internal_query;    break;
            case 'W': i = hf_where;             break;
            case 's': i = hf_schema_name;       break;
            case 't': i = hf_table_name;        break;
            case 'c': i = hf_column_name;       break;
            case 'd': i = hf_type_name;         break;
            case 'n': i = hf_constraint_name;   break;
            case 'F': i = hf_file;              break;
            case 'L': i = hf_line;              break;
            case 'R': i = hf_routine;           break;
            }
            proto_tree_add_string(tree, i, tvb, n, siz+1, s);
            length -= siz+1;
            n += siz+1;
        }
        break;

    /* NOTICE response */
    case 'A':
        proto_tree_add_item(tree, hf_pid, tvb, n, 4, ENC_BIG_ENDIAN);
        n += 4;
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_condition, tvb, n, siz, ENC_ASCII);
        n += siz;
        siz = tvb_strsize(tvb, n);
        if (siz > 1)
            proto_tree_add_item(tree, hf_text, tvb, n, siz, ENC_ASCII);
        break;

    /* Copy in/out */
    case 'G':
    case 'H':
        proto_tree_add_item(tree, hf_format, tvb, n, 1, ENC_BIG_ENDIAN);
        n += 1;
        i = tvb_get_ntohs(tvb, n);
        shrub = proto_tree_add_subtree_format(tree, tvb, n, 2, ett_values, NULL, "Columns: %d", i);
        n += 2;
        while (i-- > 2) {
            proto_tree_add_item(shrub, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
        }
        break;

    /* Copy data */
    case 'd':
        proto_tree_add_item(tree, hf_copydata, tvb, n, length-n+1, ENC_NA);
        break;

    /* Function call response */
    case 'V':
        siz = tvb_get_ntohl(tvb, n);
        proto_tree_add_int(tree, hf_val_length, tvb, n, 4, siz);
        if (siz > 0)
            proto_tree_add_item(tree, hf_val_data, tvb, n+4, siz, ENC_NA);
        break;

    /* Negotiate Protocol Version */
    case 'v':
        proto_tree_add_item(tree, hf_supported_minor_version, tvb, n, 4, ENC_BIG_ENDIAN);
        n += 4;
        proto_tree_add_item_ret_int(tree, hf_number_nonsupported_options, tvb, n, 4, ENC_BIG_ENDIAN, &num_nonsupported_options);
        n += 4;
        while (num_nonsupported_options > 0) {
            siz = tvb_strsize(tvb, n);
            proto_tree_add_item(tree, hf_nonsupported_option, tvb, n, siz, ENC_ASCII);
            n += siz;
            num_nonsupported_options--;
        }
        break;
    }
}

/* This function is called by tcp_dissect_pdus() to find the size of the
   message starting at tvb[offset]. */
static unsigned
pgsql_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    int n = 0;
    unsigned char type;
    unsigned length;

    /* The length is either the four bytes after the type, or, if the
       type is 0, the first four bytes. */
    type = tvb_get_uint8(tvb, offset);
    if (type != '\0')
        n = 1;
    length = tvb_get_ntohl(tvb, offset+n);
    return length+n;
}

/* This function is called by tcp_dissect_pdus() to find the size of the
   wrapped GSS-API message starting at tvb[offset] whe. */
static unsigned
pgsql_gssapi_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    /* The length of the GSS-API message is the first four bytes, and does
     * not include the 4 byte length (the gss_wrap). */
    return tvb_get_ntohl(tvb, offset) + 4;
}


/* This function is responsible for dissecting a single message. */

static int
dissect_pgsql_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti, *hidden_item;
    proto_tree *ptree;
    conversation_t      *conversation;
    pgsql_conn_data_t   *conn_data;
    pgsql_auth_state_t   state;

    int n;
    unsigned char type;
    const char *typestr;
    unsigned length;
    bool fe;

    conversation = find_or_create_conversation(pinfo);
    conn_data = (pgsql_conn_data_t *)conversation_get_proto_data(conversation, proto_pgsql);
    if (!conn_data) {
        conn_data = wmem_new(wmem_file_scope(), pgsql_conn_data_t);
        conn_data->state_tree = wmem_tree_new(wmem_file_scope());
        conn_data->server_port = pinfo->match_uint;
        wmem_tree_insert32(conn_data->state_tree, pinfo->num, GUINT_TO_POINTER(PGSQL_AUTH_STATE_NONE));
        conversation_add_proto_data(conversation, proto_pgsql, conn_data);
    }

    fe = (conn_data->server_port == pinfo->destport);

    n = 0;
    type = tvb_get_uint8(tvb, 0);
    if (type != '\0')
        n += 1;
    length = tvb_get_ntohl(tvb, n);

    /* This is like specifying VALS(messages) for hf_type, which we can't do
       directly because of messages without type bytes, and because the type
       interpretation depends on fe. */
    if (fe) {
        /* There are a few frontend messages that have no leading type byte.
           We identify them by the fact that the first byte of their length
           must be zero, and that the next four bytes are a unique tag. */
        if (type == '\0') {
            unsigned tag = tvb_get_ntohl(tvb, 4);

            if (length == 16 && tag == PGSQL_CANCELREQUEST)
                typestr = "Cancel request";
            else if (length == 8 && tag == PGSQL_SSLREQUEST)
                typestr = "SSL request";
            else if (length == 8 && tag == PGSQL_GSSENCREQUEST)
                typestr = "GSS encrypt request";
            else if (tag == 196608)
                typestr = "Startup message";
            else
                typestr = "Unknown";
        } else if (type == 'p') {
            state = GPOINTER_TO_UINT(wmem_tree_lookup32_le(conn_data->state_tree, pinfo->num));
            switch (state) {
                case PGSQL_AUTH_SASL_REQUESTED:
                    typestr = "SASLInitialResponse message";
                    break;
                case PGSQL_AUTH_SASL_CONTINUE:
                    typestr = "SASLResponse message";
                    break;
                case PGSQL_AUTH_GSSAPI_SSPI_DATA:
                    typestr = "GSSResponse message";
                    break;
                default:
                    typestr = "Password message";
                    break;
            }
        } else
            typestr = val_to_str_const(type, fe_messages, "Unknown");
    }
    else {
        typestr = val_to_str_const(type, be_messages, "Unknown");
    }

    /* This is a terrible hack. It makes the "Info" column reflect
        the contents of every message in a TCP packet. Could it be
        done any better? */
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s%c",
                    ( first_message ? "" : "/" ), g_ascii_isprint(type) ? type : '?');
    first_message = false;

    {
        ti = proto_tree_add_item(tree, proto_pgsql, tvb, 0, -1, ENC_NA);
        ptree = proto_item_add_subtree(ti, ett_pgsql);

        n = 1;
        if (type == '\0')
            n = 0;
        proto_tree_add_string(ptree, hf_type, tvb, 0, n, typestr);
        proto_tree_add_item(ptree, hf_length, tvb, n, 4, ENC_BIG_ENDIAN);
        hidden_item = proto_tree_add_boolean(ptree, hf_frontend, tvb, 0, 0, fe);
        proto_item_set_hidden(hidden_item);
        n += 4;

        if (fe)
            dissect_pgsql_fe_msg(type, length, tvb, n, ptree, pinfo, conn_data);
        else
            dissect_pgsql_be_msg(type, length, tvb, n, ptree, pinfo, conn_data);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_pgsql_gssapi_wrap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *ptree;

    conversation_t      *conversation;
    pgsql_conn_data_t   *conn_data;

    conversation = find_or_create_conversation(pinfo);
    conn_data = (pgsql_conn_data_t *)conversation_get_proto_data(conversation, proto_pgsql);

    if (!conn_data) {
        /* This shouldn't happen. */
        conn_data = wmem_new0(wmem_file_scope(), pgsql_conn_data_t);
        conn_data->state_tree = wmem_tree_new(wmem_file_scope());
        conn_data->server_port = pinfo->match_uint;
        wmem_tree_insert32(conn_data->state_tree, pinfo->num, GUINT_TO_POINTER(PGSQL_AUTH_GSSAPI_SSPI_DATA));
        conversation_add_proto_data(conversation, proto_pgsql, conn_data);
    }

    bool fe = (pinfo->destport == conn_data->server_port);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PGSQL");
    col_set_str(pinfo->cinfo, COL_INFO,
                    fe ? ">" : "<");

    ti = proto_tree_add_item(tree, proto_pgsql, tvb, 0, -1, ENC_NA);
    ptree = proto_item_add_subtree(ti, ett_pgsql);

    proto_tree_add_string(ptree, hf_type, tvb, 0, 0, "GSS-API encrypted message");
    proto_tree_add_item(ptree, hf_length, tvb, 0, 4, ENC_BIG_ENDIAN);

    gssapi_encrypt_info_t encrypt;
    memset(&encrypt, 0, sizeof(encrypt));
    encrypt.decrypt_gssapi_tvb = DECRYPT_GSSAPI_NORMAL;

    int ver_len;
    tvbuff_t *gssapi_tvb = tvb_new_subset_remaining(tvb, 4);

    ver_len = call_dissector_with_data(gssapi_handle, gssapi_tvb, pinfo, ptree, &encrypt);
    if (ver_len == 0) {
        /* GSS-API couldn't do anything with it. */
        return tvb_captured_length(tvb);
    }
    if (encrypt.gssapi_data_encrypted) {
        if (encrypt.gssapi_decrypted_tvb) {
            tvbuff_t *decr_tvb = encrypt.gssapi_decrypted_tvb;
            add_new_data_source(pinfo, encrypt.gssapi_decrypted_tvb, "Decrypted GSS-API");
            dissect_pgsql_msg(decr_tvb, pinfo, ptree, data);
        } else {
            /* Encrypted but couldn't be decrypted. */
            proto_tree_add_item(ptree, hf_gssapi_encrypted_payload, gssapi_tvb, ver_len, -1, ENC_NA);
        }
    } else {
        /* No encrypted (sealed) payload. If any bytes are left, that is
         * signed-only payload. */
        tvbuff_t *plain_tvb;
        if (encrypt.gssapi_decrypted_tvb) {
            plain_tvb = encrypt.gssapi_decrypted_tvb;
        } else {
            plain_tvb = tvb_new_subset_remaining(gssapi_tvb, ver_len);
        }
        if (tvb_reported_length(plain_tvb)) {
            dissect_pgsql_msg(plain_tvb, pinfo, ptree, data);
        }
    }
    return tvb_captured_length(tvb);
}

static int
dissect_pgsql_gssapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, pgsql_desegment, 4,
                     pgsql_gssapi_length, dissect_pgsql_gssapi_wrap, data);
    return tvb_captured_length(tvb);
}

/* This function is called once per TCP packet. It sets COL_PROTOCOL and
 * identifies FE/BE messages by adding a ">" or "<" to COL_INFO. Then it
 * arranges for each message to be dissected individually. */

static int
dissect_pgsql(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item          *ti;
    proto_tree          *ptree;
    conversation_t      *conversation;
    pgsql_conn_data_t   *conn_data;
    pgsql_auth_state_t   state;

    first_message = true;

    conversation = find_or_create_conversation(pinfo);
    conn_data = (pgsql_conn_data_t *)conversation_get_proto_data(conversation, proto_pgsql);

    if (!tvb_ascii_isprint(tvb, 0, 1) && tvb_get_uint8(tvb, 0) != '\0') {
        /* Doesn't look like the start of a PostgreSQL packet. Have we
         * seen Postgres yet?
         */
        if (!conn_data || wmem_tree_lookup32_le(conn_data->state_tree, pinfo->num) == NULL) {
            /* No. Reject. This might be PostgreSQL over TLS and we missed
             * the start of the transaction. The TLS dissector should get
             * a chance.
             */
            return 0;
        }
        /* Was there segmentation, and we lost a packet or were out of
         * order without out of order processing, or we couldn't do
         * desegmentation of a segment because of a bad checksum?
         * XXX: Should we call this Continuation Data if this happens,
         * so we don't send it to tcp_dissect_pdus()?
         */
    }

    bool fe = (pinfo->match_uint == pinfo->destport);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PGSQL");
    col_set_str(pinfo->cinfo, COL_INFO,
                    fe ? ">" : "<");

    if (conn_data && !fe) {
        state = GPOINTER_TO_UINT(wmem_tree_lookup32_le(conn_data->state_tree, pinfo->num));
        if (state == PGSQL_AUTH_SSL_REQUESTED) {
            /* Response to SSLRequest. */
            wmem_tree_insert32(conn_data->state_tree, pinfo->num + 1, GUINT_TO_POINTER(PGSQL_AUTH_STATE_NONE));
            ti = proto_tree_add_item(tree, proto_pgsql, tvb, 0, -1, ENC_NA);
            ptree = proto_item_add_subtree(ti, ett_pgsql);
            proto_tree_add_string(ptree, hf_type, tvb, 0, 0, "SSL response");
            proto_tree_add_item(ptree, hf_ssl_response, tvb, 0, 1, ENC_NA);
            switch (tvb_get_uint8(tvb, 0)) {
            case 'S':   /* Willing to perform SSL */
                /* Next packet will start using SSL. */
                ssl_starttls_ack(tls_handle, pinfo, pgsql_handle);
                break;
            case 'E':   /* ErrorResponse when server does not support SSL. */
                /* Process normally. */
                tcp_dissect_pdus(tvb, pinfo, tree, pgsql_desegment, 5,
                                 pgsql_length, dissect_pgsql_msg, data);
                break;
            case 'N':   /* Unwilling to perform SSL */
            default:    /* Unexpected response. */
                /* TODO: maybe add expert info here? */
                break;
            }
            /* XXX: If it's anything other than 'E', a length of more
             * than one character is unexpected and should possibly have
             * an expert info (possible MitM:
             * https://www.postgresql.org/support/security/CVE-2021-23222/ )
             */
            return tvb_captured_length(tvb);
        } else if (state == PGSQL_AUTH_GSSENC_REQUESTED) {
            /* Response to GSSENCRequest. */
            wmem_tree_insert32(conn_data->state_tree, pinfo->num + 1, GUINT_TO_POINTER(PGSQL_AUTH_STATE_NONE));
            ti = proto_tree_add_item(tree, proto_pgsql, tvb, 0, -1, ENC_NA);
            ptree = proto_item_add_subtree(ti, ett_pgsql);
            proto_tree_add_string(ptree, hf_type, tvb, 0, 0, "GSS encrypt response");
            proto_tree_add_item(ptree, hf_gssenc_response, tvb, 0, 1, ENC_NA);
            switch (tvb_get_uint8(tvb, 0)) {
            case 'E':   /* ErrorResponse; server does not support GSSAPI. */
                /* Process normally. */
                tcp_dissect_pdus(tvb, pinfo, tree, pgsql_desegment, 5,
                                 pgsql_length, dissect_pgsql_msg, data);
                break;
            case 'G':   /* Willing to perform GSSAPI Enc */
                wmem_tree_insert32(conn_data->state_tree, pinfo->num + 1, GUINT_TO_POINTER(PGSQL_AUTH_GSSAPI_SSPI_DATA));
                conversation_set_dissector_from_frame_number(conversation, pinfo->num + 1, pgsql_gssapi_handle);
                break;
            case 'N':   /* Unwilling to perform GSSAPI Enc */
            default:    /* Unexpected response. */
                /* TODO: maybe add expert info here? */
                break;
            }
            return tvb_captured_length(tvb);
        }
    }

    tcp_dissect_pdus(tvb, pinfo, tree, pgsql_desegment, 5,
                     pgsql_length, dissect_pgsql_msg, data);
    return tvb_captured_length(tvb);
}

void
proto_register_pgsql(void)
{
    static hf_register_info hf[] = {
        { &hf_frontend,
          { "Frontend", "pgsql.frontend", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True for messages from the frontend, false otherwise.",
            HFILL }
        },
        { &hf_type,
          { "Type", "pgsql.type", FT_STRING, BASE_NONE, NULL, 0,
            "A one-byte message type identifier.", HFILL }
        },
        { &hf_length,
          { "Length", "pgsql.length", FT_UINT32, BASE_DEC, NULL, 0,
            "The length of the message (not including the type).",
            HFILL }
        },
        { &hf_version_major,
          { "Protocol major version", "pgsql.version_major", FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_version_minor,
          { "Protocol minor version", "pgsql.version_minor", FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_request_code,
          { "Request code", "pgsql.request_code", FT_UINT32, BASE_DEC,
            VALS(request_code_vals), 0, NULL, HFILL }
        },
        { &hf_supported_minor_version,
          { "Supported minor version", "pgsql.version_supported_minor", FT_UINT32, BASE_DEC, NULL, 0,
            "Newest minor protocol version supported by the server for the major protocol version requested by the client.", HFILL }
        },
        { &hf_number_nonsupported_options,
          { "Number nonsupported options", "pgsql.number_nonsupported_options", FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nonsupported_option,
          { "Nonsupported option", "pgsql.nonsupported_option", FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_parameter_name,
          { "Parameter name", "pgsql.parameter_name", FT_STRINGZ,
            BASE_NONE, NULL, 0, "The name of a database parameter.",
            HFILL }
        },
        { &hf_parameter_value,
          { "Parameter value", "pgsql.parameter_value", FT_STRINGZ,
            BASE_NONE, NULL, 0, "The value of a database parameter.",
            HFILL }
        },
        { &hf_query,
          { "Query", "pgsql.query", FT_STRINGZ, BASE_NONE, NULL, 0,
            "A query string.", HFILL }
        },
        { &hf_passwd,
          { "Password", "pgsql.password", FT_STRINGZ, BASE_NONE, NULL, 0,
            "A password.", HFILL }
        },
        { &hf_authtype,
          { "Authentication type", "pgsql.authtype", FT_UINT32, BASE_DEC,
            VALS(auth_types), 0,
            "The type of authentication requested by the backend.", HFILL }
        },
        { &hf_salt,
          { "Salt value", "pgsql.salt", FT_BYTES, BASE_NONE, NULL, 0,
            "The salt to use while encrypting a password.", HFILL }
        },
        { &hf_gssapi_sspi_data,
          { "GSSAPI or SSPI authentication data", "pgsql.auth.gssapi_sspi.data", FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sasl_auth_mech,
          { "SASL authentication mechanism", "pgsql.auth.sasl.mech", FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sasl_auth_data_length,
          { "SASL authentication data length", "pgsql.auth.sasl.data.length", FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sasl_auth_data,
          { "SASL authentication data", "pgsql.auth.sasl.data", FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_statement,
          { "Statement", "pgsql.statement", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The name of a prepared statement.", HFILL }
        },
        { &hf_portal,
          { "Portal", "pgsql.portal", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The name of a portal.", HFILL }
        },
        { &hf_return,
          { "Returns", "pgsql.returns", FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_tag,
          { "Tag", "pgsql.tag", FT_STRINGZ, BASE_NONE, NULL, 0,
            "A completion tag.", HFILL }
        },
        { &hf_status,
          { "Status", "pgsql.status", FT_UINT8, BASE_DEC, VALS(status_vals),
            0, "The transaction status of the backend.", HFILL }
        },
        { &hf_copydata,
          { "Copy data", "pgsql.copydata", FT_BYTES, BASE_NONE, NULL, 0,
            "Data sent following a Copy-in or Copy-out response.", HFILL }
        },
        { &hf_error,
          { "Error", "pgsql.error", FT_STRINGZ, BASE_NONE, NULL, 0,
            "An error message.", HFILL }
        },
        { &hf_pid,
          { "PID", "pgsql.pid", FT_UINT32, BASE_DEC, NULL, 0,
            "The process ID of a backend.", HFILL }
        },
        { &hf_key,
          { "Key", "pgsql.key", FT_UINT32, BASE_DEC, NULL, 0,
            "The secret key used by a particular backend.", HFILL }
        },
        { &hf_condition,
          { "Condition", "pgsql.condition", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The name of a NOTIFY condition.", HFILL }
        },
        { &hf_text,
          { "Text", "pgsql.text", FT_STRINGZ, BASE_NONE, NULL, 0,
            "Text from the backend.", HFILL }
        },
        { &hf_tableoid,
          { "Table OID", "pgsql.oid.table", FT_UINT32, BASE_DEC, NULL, 0,
            "The object identifier of a table.", HFILL }
        },
        { &hf_typeoid,
          { "Type OID", "pgsql.oid.type", FT_UINT32, BASE_DEC, NULL, 0,
            "The object identifier of a type.", HFILL }
        },
        { &hf_oid,
          { "OID", "pgsql.oid", FT_UINT32, BASE_DEC, NULL, 0,
            "An object identifier.", HFILL }
        },
        { &hf_format,
          { "Format", "pgsql.format", FT_UINT16, BASE_DEC, VALS(format_vals),
            0, "A format specifier.", HFILL }
        },
        { &hf_field_count,
          { "Field count", "pgsql.field.count", FT_UINT16, BASE_DEC, NULL, 0,
            "The number of fields within a row.", HFILL }
        },
        { &hf_val_name,
          { "Column name", "pgsql.col.name", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The name of a column.", HFILL }
        },
        { &hf_val_idx,
          { "Column index", "pgsql.col.index", FT_UINT32, BASE_DEC, NULL, 0,
            "The position of a column within a row.", HFILL }
        },
        { &hf_val_length,
          { "Column length", "pgsql.val.length", FT_INT32, BASE_DEC, NULL, 0,
            "The length of a parameter value, in bytes. -1 means NULL.",
            HFILL }
        },
        { &hf_val_data,
          { "Data", "pgsql.val.data", FT_BYTES, BASE_NONE, NULL, 0,
            "Parameter data.", HFILL }
        },
        { &hf_val_mod,
          { "Type modifier", "pgsql.col.typemod", FT_INT32, BASE_DEC, NULL, 0,
            "The type modifier for a column.", HFILL }
        },
        { &hf_severity,
          { "Severity", "pgsql.severity", FT_STRINGZ, BASE_NONE, NULL, 0,
            "Message severity.", HFILL }
        },
        { &hf_code,
          { "Code", "pgsql.code", FT_STRINGZ, BASE_NONE, NULL, 0,
            "SQLState code.", HFILL }
        },
        { &hf_message,
          { "Message", "pgsql.message", FT_STRINGZ, BASE_NONE, NULL, 0,
            "Error message.", HFILL }
        },
        { &hf_detail,
          { "Detail", "pgsql.detail", FT_STRINGZ, BASE_NONE, NULL, 0,
            "Detailed error message.", HFILL }
        },
        { &hf_hint,
          { "Hint", "pgsql.hint", FT_STRINGZ, BASE_NONE, NULL, 0,
            "A suggestion to resolve an error.", HFILL }
        },
        { &hf_position,
          { "Position", "pgsql.position", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The index of the error within the query string.", HFILL }
        },
        { &hf_internal_position,
          { "Position (Internal)", "pgsql.internal_position", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The index of the error within the internally-generated query string.", HFILL }
        },
        { &hf_internal_query,
          { "Query (Internal)", "pgsql.internal_query", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The internally-generated query string", HFILL }
        },
        { &hf_where,
          { "Context", "pgsql.where", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The context in which an error occurred.", HFILL }
        },
        { &hf_schema_name,
          { "Schema", "pgsql.schema_name", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The schema with which an error is associated.", HFILL }
        },
        { &hf_table_name,
          { "Table", "pgsql.table_name", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The table with which an error is associated.", HFILL }
        },
        { &hf_column_name,
          { "Column", "pgsql.column_name", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The column with which an error is associated.", HFILL }
        },
        { &hf_type_name,
          { "Type", "pgsql.type_name", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The date type with which an error is associated.", HFILL }
        },
        { &hf_constraint_name,
          { "Constraint", "pgsql.constraint_name", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The constraint with which an error is associated.", HFILL }
        },
        { &hf_file,
          { "File", "pgsql.file", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The source-code file where an error was reported.", HFILL }
        },
        { &hf_line,
          { "Line", "pgsql.line", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The line number on which an error was reported.", HFILL }
        },
        { &hf_routine,
          { "Routine", "pgsql.routine", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The routine that reported an error.", HFILL }
        },
        { &hf_ssl_response,
          { "SSL Response", "pgsql.ssl_response", FT_CHAR, BASE_HEX,
            VALS(ssl_response_vals), 0, NULL, HFILL }
        },
        { &hf_gssenc_response,
          { "GSSAPI Encrypt Response", "pgsql.gssenc_response", FT_CHAR,
            BASE_HEX, VALS(gssenc_response_vals), 0, NULL, HFILL }
        },
        { &hf_gssapi_encrypted_payload,
          { "GSS-API encrypted payload", "pgsql.gssapi.encrypted_payload", FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_pgsql,
        &ett_values
    };

    proto_pgsql = proto_register_protocol("PostgreSQL", "PGSQL", "pgsql");
    pgsql_handle = register_dissector("pgsql", dissect_pgsql, proto_pgsql);
    proto_register_field_array(proto_pgsql, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Unfortunately there's no way to set up a GSS-API conversation
     * instructing the GSS-API dissector to use our wrap handle; that
     * only works for protocols that have an OID and that begin the
     * GSS-API conversation by sending that OID.
     */
    pgsql_gssapi_handle = register_dissector("pgsql.gssapi", dissect_pgsql_gssapi, proto_pgsql);
}

void
proto_reg_handoff_pgsql(void)
{
    dissector_add_uint_with_preference("tcp.port", PGSQL_PORT, pgsql_handle);

    tls_handle = find_dissector_add_dependency("tls", proto_pgsql);
    gssapi_handle = find_dissector_add_dependency("gssapi", proto_pgsql);
    ntlmssp_handle = find_dissector_add_dependency("ntlmssp", proto_pgsql);
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
