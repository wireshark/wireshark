/* packet-pgsql.c
 * Routines for PostgreSQL v3 protocol dissection.
 * <http://www.postgresql.org/docs/current/static/protocol.html>
 * Copyright 2004 Abhijit Menon-Sen <ams@oryx.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

#include "packet-tcp.h"


static int proto_pgsql = -1;
static int hf_frontend = -1;
static int hf_type = -1;
static int hf_length = -1;
static int hf_parameter_name = -1;
static int hf_parameter_value = -1;
static int hf_query = -1;
static int hf_authtype = -1;
static int hf_passwd = -1;
static int hf_salt = -1;
static int hf_statement = -1;
static int hf_portal = -1;
static int hf_tag = -1;
static int hf_status = -1;
static int hf_copydata = -1;
static int hf_error = -1;
static int hf_pid = -1;
static int hf_key = -1;
static int hf_condition = -1;
static int hf_text = -1;
static int hf_tableoid = -1;
static int hf_typeoid = -1;
static int hf_oid = -1;
static int hf_format = -1;
static int hf_field_count = -1;
static int hf_val_name = -1;
static int hf_val_idx = -1;
static int hf_val_length = -1;
static int hf_val_data = -1;
static int hf_val_mod = -1;
static int hf_severity = -1;
static int hf_code = -1;
static int hf_message = -1;
static int hf_detail = -1;
static int hf_hint = -1;
static int hf_position = -1;
static int hf_where = -1;
static int hf_file = -1;
static int hf_line = -1;
static int hf_routine = -1;

static gint ett_pgsql = -1;
static gint ett_values = -1;

static guint pgsql_port = 5432;
static gboolean pgsql_desegment = TRUE;
static gboolean first_message = TRUE;

static void dissect_pgsql_fe_msg(guchar, guint, tvbuff_t *, gint, proto_tree *);
static void dissect_pgsql_be_msg(guchar, guint, tvbuff_t *, gint, proto_tree *);
static void dissect_pgsql_msg(tvbuff_t *, packet_info *, proto_tree *);
static void dissect_pgsql(tvbuff_t *, packet_info *, proto_tree *);
static guint pgsql_length(packet_info *, tvbuff_t *, int);

static const value_string fe_messages[] = {
    { 'p', "Password message" },
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
    { 0, NULL }
};


static const value_string auth_types[] = {
    { 0, "Success" },
    { 1, "Kerberos V4" },
    { 2, "Kerberos V5" },
    { 3, "Plaintext password" },
    { 4, "crypt()ed password" },
    { 5, "MD5 password" },
    { 6, "SCM credentials" },
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

/* This function is called once per TCP packet. It sets COL_PROTOCOL and
 * identifies FE/BE messages by adding a ">" or "<" to COL_INFO. Then it
 * arranges for each message to be dissected individually. */

static void
dissect_pgsql(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* conversation_t *cv; */

    first_message = TRUE;

    /* We don't use conversation data yet, but... */
    /* cv = find_or_create_conversation(pinfo); */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PGSQL");
    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO,
                    (pinfo->match_uint == pinfo->destport) ?
                     ">" : "<");

    tcp_dissect_pdus(tvb, pinfo, tree, pgsql_desegment, 5,
                     pgsql_length, dissect_pgsql_msg);
}


/* This function is called by tcp_dissect_pdus() to find the size of the
   message starting at tvb[offset]. */

static guint
pgsql_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    gint n = 0;
    guchar type;
    guint length;

    /* The length is either the four bytes after the type, or, if the
       type is 0, the first four bytes. */
    type = tvb_get_guint8(tvb, offset);
    if (type != '\0')
        n = 1;
    length = tvb_get_ntohl(tvb, offset+n);
    return length+n;
}


/* This function is responsible for dissecting a single message. */

static void
dissect_pgsql_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti, *hidden_item;
    proto_tree *ptree;

    gint n;
    guchar type;
    const char *typestr;
    guint length;
    gboolean info = check_col(pinfo->cinfo, COL_INFO);
    gboolean fe = (pinfo->match_uint == pinfo->destport);

    n = 0;
    type = tvb_get_guint8(tvb, 0);
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
            guint tag = tvb_get_ntohl(tvb, 4);

            if (length == 16 && tag == 80877102)
                typestr = "Cancel request";
            else if (length == 8 && tag == 80877103)
                typestr = "SSL request";
            else if (tag == 196608)
                typestr = "Startup message";
            else
                typestr = "Unknown";
        } else
            typestr = val_to_str_const(type, fe_messages, "Unknown");
    }
    else {
        typestr = val_to_str_const(type, be_messages, "Unknown");
    }

    if (info) {
        /* This is a terrible hack. It makes the "Info" column reflect
           the contents of every message in a TCP packet. Could it be
           done any better? */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%c",
                        ( first_message ? "" : "/" ), type);
        first_message = FALSE;
    }

    if (tree) {
        ti = proto_tree_add_item(tree, proto_pgsql, tvb, 0, -1, ENC_NA);
        ptree = proto_item_add_subtree(ti, ett_pgsql);

        n = 1;
        if (type == '\0')
            n = 0;
        proto_tree_add_text(ptree, tvb, 0, n, "Type: %s", typestr);
        hidden_item = proto_tree_add_item(ptree, hf_type, tvb, 0, n, ENC_ASCII|ENC_NA);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_item(ptree, hf_length, tvb, n, 4, ENC_BIG_ENDIAN);
        hidden_item = proto_tree_add_boolean(ptree, hf_frontend, tvb, 0, 0, fe);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        n += 4;

        if (fe)
            dissect_pgsql_fe_msg(type, length, tvb, n, ptree);
        else
            dissect_pgsql_be_msg(type, length, tvb, n, ptree);
    }
}


static void dissect_pgsql_fe_msg(guchar type, guint length, tvbuff_t *tvb,
                                 gint n, proto_tree *tree)
{
    guchar c;
    gint i, siz;
    char *s;
    proto_item *ti, *hidden_item;
    proto_tree *shrub;

    switch (type) {
    /* Password */
    case 'p':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_passwd, tvb, n, siz, ENC_ASCII|ENC_NA);
        break;

    /* Simple query */
    case 'Q':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_query, tvb, n, siz, ENC_ASCII|ENC_NA);
        break;

    /* Parse */
    case 'P':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_statement, tvb, n, siz, ENC_ASCII|ENC_NA);
        n += siz;

        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_query, tvb, n, siz, ENC_ASCII|ENC_NA);
        n += siz;

        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_text(tree, tvb, n, 2, "Parameters: %d", i);
        shrub = proto_item_add_subtree(ti, ett_values);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_typeoid, tvb, n, 4, ENC_BIG_ENDIAN);
            n += 4;
        }
        break;

    /* Bind */
    case 'B':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_portal, tvb, n, siz, ENC_ASCII|ENC_NA);
        n += siz;

        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_statement, tvb, n, siz, ENC_ASCII|ENC_NA);
        n += siz;

        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_text(tree, tvb, n, 2, "Parameter formats: %d", i);
        shrub = proto_item_add_subtree(ti, ett_values);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
        }

        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_text(tree, tvb, n, 2, "Parameter values: %d", i);
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

        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_text(tree, tvb, n, 2, "Result formats: %d", i);
        shrub = proto_item_add_subtree(ti, ett_values);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
        }
        break;

    /* Execute */
    case 'E':
        siz = tvb_strsize(tvb, n);
        proto_tree_add_item(tree, hf_portal, tvb, n, siz, ENC_ASCII|ENC_NA);
        n += siz;

        ti = proto_tree_add_text(tree, tvb, n, 4, "Returns: ");
        i = tvb_get_ntohl(tvb, n);
        if (i == 0)
            proto_item_append_text(ti, "all");
        else
            proto_item_append_text(ti, "%d", i);
        proto_item_append_text(ti, " rows");
        break;

    /* Describe, Close */
    case 'D':
    case 'C':
        c = tvb_get_guint8(tvb, n);
        if (c == 'P')
            i = hf_portal;
        else
            i = hf_statement;

        if (i != 0) {
            n += 1;
            s = tvb_get_ephemeral_stringz(tvb, n, &siz);
            hidden_item = proto_tree_add_string(tree, i, tvb, n, siz, s);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            proto_tree_add_text(
                tree, tvb, n-1, siz, "%s: %s",
                (c == 'P' ? "Portal" : "Statement"), s
            );
        }
        break;

    /* Messages without a type identifier */
    case '\0':
        i = tvb_get_ntohl(tvb, n);
        n += 4;
        length -= n;
        switch (i) {
        /* Startup message */
        case 196608:
            while ((signed)length > 0) {
                siz = tvb_strsize(tvb, n);
                length -= siz;
                if ((signed)length <= 0) {
                    break;
                }
                proto_tree_add_item(tree, hf_parameter_name,  tvb, n,       siz, ENC_ASCII|ENC_NA);
                i = tvb_strsize(tvb, n+siz);
                proto_tree_add_item(tree, hf_parameter_value, tvb, n + siz, i,   ENC_ASCII|ENC_NA);
                length -= i;

                n += siz+i;
                if (length == 1 && tvb_get_guint8(tvb, n) == 0)
                    break;
            }
            break;

        /* SSL request */
        case 80877103:
            /* There's nothing to parse here, but what do we do if the
               SSL negotiation succeeds? */
            break;

        /* Cancellation request */
        case 80877102:
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
        proto_tree_add_item(tree, hf_error, tvb, n, siz, ENC_ASCII|ENC_NA);
        break;

    /* Function call */
    case 'F':
        proto_tree_add_item(tree, hf_oid, tvb, n, 4, ENC_BIG_ENDIAN);
        n += 4;

        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_text(tree, tvb, n, 2, "Parameter formats: %d", i);
        shrub = proto_item_add_subtree(ti, ett_values);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(shrub, hf_format, tvb, n, 2, ENC_BIG_ENDIAN);
            n += 2;
        }

        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_text(tree, tvb, n, 2, "Parameter values: %d", i);
        shrub = proto_item_add_subtree(ti, ett_values);
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


static void dissect_pgsql_be_msg(guchar type, guint length, tvbuff_t *tvb,
                                 gint n, proto_tree *tree)
{
    guchar c;
    gint i, siz;
    char *s, *t;
    proto_item *ti, *hidden_item;
    proto_tree *shrub;

    switch (type) {
    /* Authentication request */
    case 'R':
        proto_tree_add_item(tree, hf_authtype, tvb, n, 4, ENC_BIG_ENDIAN);
        i = tvb_get_ntohl(tvb, n);
        if (i == 4 || i == 5) {
            /* i -= (6-i); :-) */
            n += 4;
            siz = (i == 4 ? 2 : 4);
            proto_tree_add_item(tree, hf_salt, tvb, n, siz, ENC_NA);
        }
        break;

    /* Key data */
    case 'K':
        proto_tree_add_item(tree, hf_pid, tvb, n,   4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_key, tvb, n+4, 4, ENC_BIG_ENDIAN);
        break;

    /* Parameter status */
    case 'S':
        s = tvb_get_ephemeral_stringz(tvb, n, &siz);
        hidden_item = proto_tree_add_string(tree, hf_parameter_name, tvb, n, siz, s);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        n += siz;
        t = tvb_get_ephemeral_stringz(tvb, n, &i);
        hidden_item = proto_tree_add_string(tree, hf_parameter_value, tvb, n, i, t);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_text(tree, tvb, n-siz, siz+i, "%s: %s", s, t);
        break;

    /* Parameter description */
    case 't':
        i = tvb_get_ntohs(tvb, n);
        proto_tree_add_text(tree, tvb, n, 2, "Parameters: %d", i);
        n += 2;
        while (i-- > 0) {
            proto_tree_add_item(tree, hf_typeoid, tvb, n, 4, ENC_BIG_ENDIAN);
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
            ti = proto_tree_add_item(shrub, hf_val_name, tvb, n, siz, ENC_ASCII|ENC_NA);
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
        proto_tree_add_item(tree, hf_tag, tvb, n, siz, ENC_ASCII|ENC_NA);
        break;

    /* Ready */
    case 'Z':
        proto_tree_add_item(tree, hf_status, tvb, n, 1, ENC_NA);
        break;

    /* Error, Notice */
    case 'E':
    case 'N':
        length -= 4;
        while ((signed)length > 0) {
            c = tvb_get_guint8(tvb, n);
            if (c == '\0')
                break;
            s = tvb_get_ephemeral_stringz(tvb, n+1, &siz);
            i = hf_text;
            switch (c) {
            case 'S': i = hf_severity; break;
            case 'C': i = hf_code;     break;
            case 'M': i = hf_message;  break;
            case 'D': i = hf_detail;   break;
            case 'H': i = hf_hint;     break;
            case 'P': i = hf_position; break;
            case 'W': i = hf_where;    break;
            case 'F': i = hf_file;     break;
            case 'L': i = hf_line;     break;
            case 'R': i = hf_routine;  break;
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
        proto_tree_add_item(tree, hf_condition, tvb, n, siz, ENC_ASCII|ENC_NA);
        n += siz;
        siz = tvb_strsize(tvb, n);
        if (siz > 1)
            proto_tree_add_item(tree, hf_text, tvb, n, siz, ENC_ASCII|ENC_NA);
        break;

    /* Copy in/out */
    case 'G':
    case 'H':
        proto_tree_add_item(tree, hf_format, tvb, n, 1, ENC_BIG_ENDIAN);
        n += 1;
        i = tvb_get_ntohs(tvb, n);
        ti = proto_tree_add_text(tree, tvb, n, 2, "Columns: %d", i);
        shrub = proto_item_add_subtree(ti, ett_values);
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
    }
}

void
proto_reg_handoff_pgsql(void);

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
          { "Authentication type", "pgsql.authtype", FT_INT32, BASE_DEC,
            VALS(auth_types), 0,
            "The type of authentication requested by the backend.", HFILL }
        },
        { &hf_salt,
          { "Salt value", "pgsql.salt", FT_BYTES, BASE_NONE, NULL, 0,
            "The salt to use while encrypting a password.", HFILL }
        },
        { &hf_statement,
          { "Statement", "pgsql.statement", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The name of a prepared statement.", HFILL }
        },
        { &hf_portal,
          { "Portal", "pgsql.portal", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The name of a portal.", HFILL }
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
        { &hf_where,
          { "Context", "pgsql.where", FT_STRINGZ, BASE_NONE, NULL, 0,
            "The context in which an error occurred.", HFILL }
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
        }
    };

    static gint *ett[] = {
        &ett_pgsql,
        &ett_values
    };

    module_t *mod_pgsql;

    proto_pgsql = proto_register_protocol("PostgreSQL", "PGSQL", "pgsql");
    proto_register_field_array(proto_pgsql, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    mod_pgsql = prefs_register_protocol(proto_pgsql, proto_reg_handoff_pgsql);
    prefs_register_uint_preference(
        mod_pgsql, "tcp.port", "PGSQL TCP port", "Set the port for PGSQL "
        "messages (if different from the default of 5432)", 10, &pgsql_port
    );
}

void
proto_reg_handoff_pgsql(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t pgsql_handle;
    static guint saved_pgsql_port;

    if (!initialized) {
        pgsql_handle = create_dissector_handle(dissect_pgsql, proto_pgsql);
        initialized = TRUE;
    } else {
        dissector_delete_uint("tcp.port", saved_pgsql_port, pgsql_handle);
    }

    dissector_add_uint("tcp.port", pgsql_port, pgsql_handle);
    saved_pgsql_port = pgsql_port;
}


