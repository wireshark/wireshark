/* packet-elcom.c
 * Routines for elcom packet dissection
 * Copyright 2008, 2011 juha.takala@iki.fi (Juha Takala)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-imap.c
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
 *
 * I found the protocol specification at
 *  http://www.sintef.no/upload/Energiforskning/Energisystemer/ELCOM%2090.pdf
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

#define TCP_PORT_ELCOM        5997

/* Application level: */
#define A_CONRQ        0x04
#define A_CONRS        0x05

/* Presentation level: */
#define P_CONRQ        0x00
#define P_CONRS        0x10
#define P_RELRQ        0x20
#define P_RELRS        0x30
#define P_DATRQ        0x80

#define TC_REQ         0x40
#define TC_RSP         0x41

#define LOWADR_LEN 17
#define SUFFIX_LEN  2
#define TOTAL_LEN (LOWADR_LEN + SUFFIX_LEN + 2)

#define ELCOM_UNKNOWN_ENDIAN 0
#define ELCOM_LITTLE_ENDIAN  1
#define ELCOM_BIG_ENDIAN     2

static int proto_elcom = -1;
static int hf_elcom_response = -1;
static int hf_elcom_request = -1;

static int hf_elcom_length = -1;
static int hf_elcom_type = -1;

static int hf_elcom_initiator = -1;
static int hf_elcom_initiator_endian = -1;
static int hf_elcom_initiator_ip = -1;
static int hf_elcom_initiator_port = -1;
static int hf_elcom_initiator_suff = -1;

static int hf_elcom_responder = -1;
static int hf_elcom_responder_endian = -1;
static int hf_elcom_responder_ip = -1;
static int hf_elcom_responder_port = -1;
static int hf_elcom_responder_suff = -1;

static int hf_elcom_userdata = -1;
static int hf_elcom_userdata_length = -1;
static int hf_elcom_userdata_pduid = -1;
static int hf_elcom_userdata_version = -1;
static int hf_elcom_userdata_result = -1;
static int hf_elcom_userdata_restmark = -1;
static int hf_elcom_userdata_cf = -1;

static int hf_elcom_datarequest = -1;
static int hf_elcom_datarequest_grouptype = -1;
static int hf_elcom_datarequest_result = -1;
static int hf_elcom_datarequest_groupnumber = -1;
static int hf_elcom_datarequest_grouppriority = -1;
static int hf_elcom_datarequest_groupsize = -1;
static int hf_elcom_datarequest_groupindex1 = -1;
static int hf_elcom_datarequest_groupindex2 = -1;
static int hf_elcom_datarequest_oid = -1;

static int hf_elcom_release_reason = -1;
static int hf_elcom_release_result = -1;

static int hf_elcom_strangeleftover = -1;

static gint ett_elcom = -1;
static gint ett_elcom_initiator = -1;
static gint ett_elcom_responder = -1;
static gint ett_elcom_userdata = -1;
static gint ett_elcom_datarequest = -1;

static gboolean elcom_show_hex = TRUE;

static const value_string endian_vals[] = {
        {0x0002, "Big"},
        {0x0200, "Little"},
        {0, NULL }
};

static const value_string suffix_vals[] = {
        {'A', "Control"},
        {'B', "Unsolicited"},
        {'C', "Periodic"},
        {'D', "Requested, scheduling"},
        {'E', "Requested, present/archived"},
        {'G', "Supervisory"},
        {'F', "Test"},
        {0, NULL }
};

static const value_string userdata_pduid_vals[] = {
        {0x04, "Connect Request"},
        {0x05, "Connect Response"},
        {0, NULL }
};

static const value_string userdata_version_vals[] = {
        {0x00, "Class 0, v0"},
        {0x01, "Class 1, v0"},
        {0x02, "Class 2, v0"},
        {0x12, "Class 2, v1"},
        {0x13, "Class 3, v1"},
        {0, NULL }
};

static const value_string userdata_result_vals[] = {
        {0x00, "OK"},
        {0, NULL }
};

static const value_string datarequest_grouptype_vals[] = {
        {TC_REQ, "Test Connection Request"},
        {TC_RSP, "Test Connection Response"},
        {0, NULL }
};

static const value_string datarequest_result_vals[] = {
        {0x00, "OK"},
        {0, NULL }
};

static const value_string type_vals[] = {
        {P_CONRQ, "Connect Request"},
        {P_CONRS, "Connect Response"},
        {P_RELRQ, "Release Request"},
        {P_RELRS, "Release Response"},
        {P_DATRQ, "Data Request"},
        {0, NULL }
};

static gint
dissect_lower_address(proto_item *ti_arg, gint ett_arg,
                      tvbuff_t *tvb, gint arg_offset,
                      int hf_endian, int hf_ip, int hf_port, int hf_suff)
{
        gint        offset = arg_offset;
        guint8      len1, len2;
        guint8     *suffix;
        proto_tree *tree;
        proto_item *ti;

        tree = proto_item_add_subtree(ti_arg, ett_arg);

        /*
         * Coding of address:
         * ELCOM-90 TRA3825.02 User Element conventions, p. 5-2 and Appendix G
         */
        len1 = tvb_get_guint8(tvb, offset);
        if (tvb_length_remaining(tvb, offset+len1+1) <= 0)
                return offset;
        len2 = tvb_get_guint8(tvb, offset+len1+1);
        if (tvb_length_remaining(tvb, offset+len1+len2+2) <= 0)
                return offset;
        if ((len1 != LOWADR_LEN) || (len2 != SUFFIX_LEN)) {
                proto_item_append_text(tree, " Invalid structure");
                return offset;
        }


        /* Show pre stuff */
        if (0x82 != tvb_get_guint8(tvb, offset+1)) {
                proto_item_append_text(tree, " Not IPV4 address");
                return offset;
        }
        offset += 2;


        /* endian */
        proto_tree_add_item(tree, hf_endian, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* port */
        proto_tree_add_item(tree, hf_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* ip-addr */
        proto_tree_add_item(tree, hf_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        offset += 8;                /* skip the zero bytes */

        /* SUFFIX */
        suffix = tvb_get_string(tvb, offset+1, len2);
        ti = proto_tree_add_item(tree, hf_suff, tvb, offset, 1, TRUE);
        offset += len2+1;

        if (!(suffix[0] == 'A' || suffix[0] == 'B')) {
                g_free(suffix);
                proto_item_append_text(ti, " (invalid)");
                return offset;
        }

        proto_item_append_text(ti, " (%s)", val_to_str(suffix[1], suffix_vals, "<<-- WHAT?") );

        g_free(suffix);
        return offset;
}

static gint
dissect_userdata(proto_item *ti_arg, gint ett_arg, tvbuff_t *tvb, gint arg_offset)
{
        gint        offset = arg_offset;
        guint8      flen, lenbytes;
        guint8      year, month, day, hour, min, sec;
        guint16     msec;
        proto_tree *tree;
        proto_item *ti;

        tree = proto_item_add_subtree(ti_arg, ett_arg);

        /* length of User Data, should be 1 byte field ... */
        flen     = tvb_get_guint8(tvb, offset);
        lenbytes = 1;

        /* ... but sometimes it seems to be 2 bytes; try to be clever */
        if (flen == 0) {
                flen = tvb_get_guint8(tvb, offset+1);
                lenbytes = 2;
        }
        if (flen == 0 || flen > 79) /* invalid */
                return offset;

        ti = proto_tree_add_item(tree, hf_elcom_userdata_length, tvb, offset, lenbytes, ENC_BIG_ENDIAN);
        offset += lenbytes;
        if (lenbytes == 2) {
                proto_item_append_text(ti, " (2 bytes, should be 1 byte)");
        }

        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        proto_tree_add_item(tree, hf_elcom_userdata_pduid, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        proto_tree_add_item(tree, hf_elcom_userdata_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;


        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        proto_tree_add_item(tree, hf_elcom_userdata_result, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* show the rest */
        /*        tree2 = proto_tree_add_text(tree, tvb, offset, -1, "User Data"); */

        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;
        ti = proto_tree_add_item(tree, hf_elcom_userdata_restmark, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " <-- '0' = no restart etc.");
        offset +=1;

        if (tvb_length_remaining(tvb, offset+8) <= 0)
                return offset;
        year  = tvb_get_guint8(tvb, offset);
        month = tvb_get_guint8(tvb, offset+1);
        day   = tvb_get_guint8(tvb, offset+2);
        hour  = tvb_get_guint8(tvb, offset+3);
        min   = tvb_get_guint8(tvb, offset+4);
        sec   = tvb_get_guint8(tvb, offset+5);
        msec  = tvb_get_ntohs(tvb, offset+6);

        proto_tree_add_none_format(tree, hf_elcom_userdata_cf, tvb, offset, 8,
                                   "Control Field: %4d-%02d-%02d %02d:%02d:%02d.%d",
                                   year+1900, month, day, hour, min, sec, msec);

        offset += 12;
        if (tvb_length_remaining(tvb, offset+12) > 0) {
                proto_item_append_text(ti, " Security info: ");
        }
        /* security info field, if present */
        while (tvb_length_remaining(tvb, offset) > 0) {
                proto_item_append_text(ti, elcom_show_hex ? " %02x" : " %03o",
                                       tvb_get_guint8(tvb, offset));
                offset++;
        }

        return offset;
}

static gint
dissect_datarequest(proto_item *ti_arg, gint ett_arg, tvbuff_t *tvb, gint arg_offset)
{
        gint        offset = arg_offset;
        guint8      gtype, oidlen;
        proto_tree *tree, *tree2;
        proto_item *ti;

        tree = proto_item_add_subtree(ti_arg, ett_arg);
        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        gtype = tvb_get_guint8(tvb, offset);
        ti = proto_tree_add_item(tree, hf_elcom_datarequest_grouptype,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        switch (gtype) {

        case TC_REQ:
                /* No more data for this type, suppress the error message */
                break;

        case TC_RSP:

                proto_tree_add_uint(tree, hf_elcom_datarequest_result,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                break;

        default:
                proto_item_append_text(ti, " <<--- meaning WHAT?");
                return offset;
        }
        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        proto_tree_add_item(tree, hf_elcom_datarequest_groupnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        proto_tree_add_item(tree, hf_elcom_datarequest_grouppriority, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        proto_tree_add_item(tree, hf_elcom_datarequest_groupsize, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        proto_tree_add_item(tree, hf_elcom_datarequest_groupindex1, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        proto_tree_add_uint(tree, hf_elcom_datarequest_groupindex2, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        while (1) {
                oidlen = tvb_get_guint8(tvb, offset);
                if (oidlen == 0) /* normal termination */
                        break;
                if (tvb_length_remaining(tvb, offset+oidlen+1) <= 0)
                        return offset;
                proto_tree_add_item(tree, hf_elcom_datarequest_oid, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
                offset += oidlen+1;
        }
        offset += 1;             /* the loop exited at the 0 length byte */
        if (tvb_length_remaining(tvb, offset) <= 0)
                return offset;

        /* show the rest */
        tree2 = proto_tree_add_text(tree, tvb, offset, -1, "leftover =");
        while (tvb_length_remaining(tvb, offset) > 0) {
                proto_item_append_text(tree2, elcom_show_hex ? " %02x" : " %03o",
                                       tvb_get_guint8(tvb, offset));
                offset++;
        }

        return offset;
}

/* XXX: Are all the tests against tvb_length() really the right way to handle invalid fields ?
 *      It seems to me that invalid fields should just add an expert item
 *        or cause a "Malformed" exception.
 */
static void
dissect_elcom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gboolean    is_request, length_ok;
        proto_tree *elcom_tree;
        proto_item *ti, *hidden_item;
        gint        offset = 0;
        guint       elcom_len;
        guint8      elcom_msg_type;
        guint8     *suffix;

        /* Check that there's enough data */
        if (tvb_length(tvb) < 3)
                return;

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ELCOM");
        col_clear(pinfo->cinfo, COL_INFO);

        is_request = (pinfo->match_port == pinfo->destport);
        elcom_len  = tvb_get_ntohs(tvb, 0);
        length_ok  = (tvb_reported_length(tvb) == (elcom_len+2));
        if (check_col(pinfo->cinfo, COL_INFO)) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s Len=%d%s",
                             is_request ? "Request" : "Response",
                             elcom_len,
                             length_ok ? "" : " (incorrect)");

                elcom_msg_type = tvb_get_guint8(tvb, 2);
                switch (elcom_msg_type) {
                case P_CONRQ:
                case P_CONRS:

                        /* starting after elcom_len and elcom_msg_type,
                           initiator + responder + userdata fields must be there */
                        if (tvb_length_remaining(tvb, 3+TOTAL_LEN+TOTAL_LEN+3) < 0) return;
                        /* check also that those field lengths are valid */
                        if (tvb_get_guint8(tvb, 3)  != LOWADR_LEN) return;
                        if (tvb_get_guint8(tvb, 3+1+LOWADR_LEN) != SUFFIX_LEN) return;
                        if (tvb_get_guint8(tvb, 3+TOTAL_LEN) != LOWADR_LEN) return;
                        if (tvb_get_guint8(tvb, 3+1+TOTAL_LEN+LOWADR_LEN) != SUFFIX_LEN) return;

                        /* finally believe that there is valid suffix */
                        suffix = tvb_get_string(tvb, 3+2+LOWADR_LEN, 2);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " %s Connect", suffix);
                        g_free(suffix);
                        break;

                case P_RELRQ:
                case P_RELRS:
                        col_append_str(pinfo->cinfo, COL_INFO, " Release");
                        break;

                case P_DATRQ:
                        col_append_str(pinfo->cinfo, COL_INFO, " Data");
                        break;
                }

                switch (elcom_msg_type) {
                case P_CONRQ:
                case P_RELRQ:
                        col_append_str(pinfo->cinfo, COL_INFO, " Request");
                        break;

                case P_CONRS:
                case P_RELRS:
                        col_append_str(pinfo->cinfo, COL_INFO, " Response");
                        break;
                }
        }

        if (!tree)
                return;

        ti = proto_tree_add_item(tree, proto_elcom, tvb, offset, -1, ENC_NA);
        elcom_tree = proto_item_add_subtree(ti, ett_elcom);

        hidden_item = proto_tree_add_boolean(elcom_tree,
                                             is_request ? hf_elcom_request : hf_elcom_response,
                                             tvb, 0, 0, TRUE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        /* 2 first bytes are the frame length */
        offset = 0;
        ti = proto_tree_add_item(elcom_tree, hf_elcom_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset = +2;
        if (! length_ok) {
                proto_item_append_text(ti, " (incorrect)");
        }

        elcom_msg_type = tvb_get_guint8(tvb, offset);
        ti = proto_tree_add_item(elcom_tree, hf_elcom_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(elcom_tree, " ( %s)", val_to_str(elcom_msg_type, type_vals, "Unknown %d"));

        offset++;
        if (tvb_length_remaining(tvb, offset) <= 0)
                return;

        switch (elcom_msg_type) {
        case P_CONRQ:
        case P_CONRS:
                /*
                 * Connection request/release assiciated PDU's,
                 * /ELCOM-90 P Protocol spec/ p. 85...
                 */

                /* We need the length here, hardcode the LOWADR_LEN = 21 */
                ti = proto_tree_add_item(elcom_tree, hf_elcom_initiator, tvb, offset, TOTAL_LEN, ENC_BIG_ENDIAN);
                offset = dissect_lower_address(ti, ett_elcom_initiator, tvb, offset,
                                               hf_elcom_initiator_endian,
                                               hf_elcom_initiator_ip,
                                               hf_elcom_initiator_port,
                                               hf_elcom_initiator_suff);
                if (tvb_length_remaining(tvb, offset) <= 0)
                        return;

                ti = proto_tree_add_item(elcom_tree, hf_elcom_responder, tvb, offset, TOTAL_LEN, ENC_BIG_ENDIAN);
                offset = dissect_lower_address(ti, ett_elcom_responder, tvb, offset,
                                               hf_elcom_responder_endian,
                                               hf_elcom_responder_ip,
                                               hf_elcom_responder_port,
                                               hf_elcom_responder_suff);
                if (tvb_length_remaining(tvb, offset) <= 0)
                        return;

                /* Rest of the payload is USER-DATA, 0..82 bytes */
                ti = proto_tree_add_item(elcom_tree, hf_elcom_userdata, tvb, offset, -1, ENC_NA);
                offset = dissect_userdata(ti, ett_elcom_userdata, tvb, offset);

                break;

        case P_RELRQ:

                proto_tree_add_item(elcom_tree, hf_elcom_release_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                break;
        case P_RELRS:

                proto_tree_add_item(elcom_tree, hf_elcom_release_result, tvb, offset, 1, ENC_BIG_ENDIAN);

                offset += 1;

                break;

        case P_DATRQ:
                ti = proto_tree_add_item(elcom_tree, hf_elcom_datarequest, tvb, offset, -1, ENC_NA);
                offset = dissect_datarequest(ti, ett_elcom_datarequest, tvb, offset);
                break;

        default:
                proto_item_append_text(ti, " <<--- meaning WHAT??");
                break;
        }


        if (tvb_length_remaining(tvb, offset) <= 0)
                return;

        /* We should not get here, but if we do, show what is left over: */
        ti = proto_tree_add_item(elcom_tree, hf_elcom_strangeleftover, tvb, offset, -1, ENC_NA);
        while (tvb_length_remaining(tvb, offset) > 0) {
                proto_item_append_text(ti, elcom_show_hex ? " %02x" : " %03o",
                                       tvb_get_guint8(tvb, offset));
                offset++;
        }
}

void
proto_register_elcom(void)
{
        /* Setup list of header fields  See Section 1.6.1 for details*/
        static hf_register_info hf[] = {
                { &hf_elcom_response,
                  { "Response",        "elcom.response",
                    FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_request,
                  { "Request",        "elcom.request",
                    FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_length,
                  { "Length",        "elcom.length",
                    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_type,
                  { "Type",        "elcom.type",
                    FT_UINT8, BASE_HEX, VALS(type_vals), 0, NULL, HFILL }
                },

                { &hf_elcom_initiator,
                  { "Initiator",        "elcom.initiator",
                    FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_initiator_endian,
                  { "Endian",        "elcom.initiator.endian",
                    FT_UINT16, BASE_HEX, VALS(endian_vals), 0, NULL, HFILL }
                },

                { &hf_elcom_initiator_ip,
                  { "IP",        "elcom.initiator.ip",
                    FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_initiator_port,
                  { "Port",        "elcom.initiator.port",
                    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_initiator_suff,
                  { "Suffix",        "elcom.initiator.suffix",
                    FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_responder,
                  { "Responder",        "elcom.responder",
                    FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_responder_endian,
                  { "Endian",        "elcom.responder.endian",
                    FT_UINT16, BASE_HEX, VALS(endian_vals), 0, NULL, HFILL }
                },

                { &hf_elcom_responder_ip,
                  { "IP",        "elcom.responder.ip",
                    FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_responder_port,
                  { "Port",        "elcom.responder.port",
                    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_responder_suff,
                  { "Suffix",        "elcom.responder.suffix",
                    FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_userdata,
                  { "User Data",        "elcom.userdata",
                    FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_userdata_length,
                  { "Length",        "elcom.userdata.length",
                    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_userdata_pduid,
                  { "PDU-ID",        "elcom.userdata.pduid",
                    FT_UINT8, BASE_DEC, VALS(userdata_pduid_vals), 0, NULL, HFILL }
                },

                { &hf_elcom_userdata_version,
                  { "Version",        "elcom.userdata.version",
                    FT_UINT8, BASE_DEC, VALS(userdata_version_vals), 0, NULL, HFILL }
                },

                { &hf_elcom_userdata_result,
                  { "Result",        "elcom.userdata.result",
                    FT_UINT8, BASE_DEC, VALS(userdata_result_vals), 0, NULL, HFILL }
                },

                { &hf_elcom_userdata_restmark,
                  { "Restart marking",        "elcom.userdata.response.restartcode",
                    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_userdata_cf,
                  { "Control Field",        "elcom.userdata.response.controlfield",
                    FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_release_reason,
                  { "Reason",        "elcom.release.reason",
                    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_release_result,
                  { "Result",        "elcom.release.result",
                    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest,
                  { "Data Request",        "elcom.datarequest",
                    FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest_grouptype,
                  { "Group Type",        "elcom.datarequest.grouptype",
                    FT_UINT8, BASE_DEC, VALS(datarequest_grouptype_vals), 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest_result,
                  { "Result",        "elcom.datarequest.result",
                    FT_UINT8, BASE_DEC, VALS(datarequest_result_vals), 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest_groupnumber,
                  { "Group Number",        "elcom.datarequest.groupnumber",
                    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest_grouppriority,
                  { "Group Priority",        "elcom.datarequest.grouppriority",
                    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest_groupsize,
                  { "Group Size",        "elcom.datarequest.groupsize",
                    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest_groupindex1,
                  { "Group Index1",        "elcom.datarequest.groupindex1",
                    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest_groupindex2,
                  { "Group Index2",        "elcom.datarequest.groupindex2",
                    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
                },

                { &hf_elcom_datarequest_oid,
                  { "Obkect Name",        "elcom.datarequest.oid",
                    FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
                },
                { &hf_elcom_strangeleftover,
                  { "Strange Leftover",        "elcom.leftover",
                    FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
                }
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_elcom,
                &ett_elcom_initiator,
                &ett_elcom_responder,
                &ett_elcom_userdata,
                &ett_elcom_datarequest
        };

        /* Register the protocol name and description */
        proto_elcom = proto_register_protocol (
                                               "ELCOM Communication Protocol",
                                               "ELCOM",
                                               "elcom"
                                               );

        /* Required function calls to register the header fields and subtrees used */
        proto_register_field_array(proto_elcom, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_elcom(void)
{
        dissector_handle_t elcom_handle;

        elcom_handle = create_dissector_handle(dissect_elcom, proto_elcom);
        dissector_add_uint("tcp.port", TCP_PORT_ELCOM, elcom_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
