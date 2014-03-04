/* packet-irc.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

/*
 * Routines for IRC packet dissection
 *
 * See
 *
 *  http://www.irchelp.org/irchelp/rfc/
 *
 * and the RFCs and other documents it mentions, such as RFC 1459, RFCs
 * 2810, 2811, 2812, and 2813,
 *
 *  http://www.irchelp.org/irchelp/rfc/ctcpspec.html
 *
 * and
 *
 *  http://www.invlogic.com/irc/ctcp.html
 */

#include "config.h"

#include <glib.h>
#include <ctype.h>
#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_irc(void);
void proto_reg_handoff_irc(void);

static int proto_irc = -1;
static int hf_irc_request = -1;
static int hf_irc_request_prefix = -1;
static int hf_irc_request_command = -1;
static int hf_irc_request_command_param = -1;
static int hf_irc_request_trailer = -1;
static int hf_irc_response = -1;
static int hf_irc_response_prefix = -1;
static int hf_irc_response_command = -1;
static int hf_irc_response_num_command = -1;
static int hf_irc_response_command_param = -1;
static int hf_irc_response_trailer = -1;
static int hf_irc_ctcp = -1;

static gint ett_irc = -1;
static gint ett_irc_request = -1;
static gint ett_irc_request_command = -1;
static gint ett_irc_response = -1;
static gint ett_irc_response_command = -1;

static expert_field ei_irc_missing_end_delimiter = EI_INIT;
static expert_field ei_irc_numeric_request_command = EI_INIT;
static expert_field ei_irc_response_command = EI_INIT;
static expert_field ei_irc_prefix_missing_ending_space = EI_INIT;
static expert_field ei_irc_request_command = EI_INIT;
static expert_field ei_irc_tag_data_invalid = EI_INIT;

/* This must be a null-terminated string */
static const guint8 TAG_DELIMITER[] = {0x01, 0x00};


#define TCP_PORT_IRC            6667
#define TCP_PORT_DIRCPROXY      57000
    /* good candidate for dynamic port specification */

static void
dissect_irc_tag_data(proto_tree *tree, proto_item *item, tvbuff_t *tvb, int offset, int datalen, packet_info *pinfo, guint8* command)
{
    guchar found_start_needle = 0,
           found_end_needle   = 0;
    gint   tag_start_offset, tag_end_offset;

    tag_start_offset = tvb_pbrk_guint8(tvb, offset, datalen, TAG_DELIMITER, &found_start_needle);
    if (tag_start_offset == -1)
    {
        /* no tag data */
        return;
    }

    tag_end_offset = tvb_pbrk_guint8(tvb, offset, datalen-offset, TAG_DELIMITER, &found_end_needle);
    if (tag_end_offset == -1)
    {
        expert_add_info(pinfo, item, &ei_irc_missing_end_delimiter);
        return;
    }

    if ((strcmp(command, "NOTICE") != 0) &&
       (strcmp(command, "PRIVMSG") != 0))
    {
        expert_add_info(pinfo, item, &ei_irc_tag_data_invalid);
    }

    /* Placeholder to call CTCP dissector, strip out delimiter */
    proto_tree_add_item(tree, hf_irc_ctcp, tvb, offset+1, datalen-2, ENC_ASCII|ENC_NA);
}

static void
dissect_irc_request(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int linelen)
{
    proto_tree *request_tree, *command_tree = NULL;
    proto_item *request_item, *command_item;
    int         start_offset                = offset;
    int         end_offset                  = start_offset+linelen;
    gint        eop_offset                  = -1,
                eoc_offset                  = -1,
                eocp_offset,
                tag_start_offset, tag_end_offset;
    guint8*     str_command;
    guchar      found_needle                = 0,
                found_tag_needle            = 0;
    gboolean    first_command_param         = TRUE;

    request_item = proto_tree_add_item(tree, hf_irc_request, tvb, offset, linelen, ENC_ASCII|ENC_NA);
    if (linelen <= 0)
        return;

    request_tree = proto_item_add_subtree(request_item, ett_irc_request );

    /* Check if message has a prefix */
    if (tvb_get_guint8(tvb, offset) == ':')
    {
        /* find the end of the prefix */
        eop_offset = tvb_pbrk_guint8(tvb, offset+1, linelen-1, " ", &found_needle);
        if (eop_offset == -1)
        {
            expert_add_info(pinfo, request_item, &ei_irc_prefix_missing_ending_space);
            return;
        }

        proto_tree_add_item(request_tree, hf_irc_request_prefix, tvb, offset+1, eop_offset-offset-1, ENC_ASCII|ENC_NA);
        found_needle = 0;
        offset = eop_offset+1;
    }

    /* clear out any whitespace before command */
    while(offset < end_offset && tvb_get_guint8(tvb, offset) == ' ')
    {
        offset++;
    }
    if (offset == end_offset)
    {
        expert_add_info(pinfo, request_item, &ei_irc_request_command);
        return;
    }

    eoc_offset = tvb_pbrk_guint8(tvb, offset, end_offset-offset, " ", &found_needle);
    if (eoc_offset == -1)
    {
        proto_tree_add_item(request_tree, hf_irc_request_command, tvb, offset, end_offset-offset, ENC_ASCII|ENC_NA);
        col_append_fstr( pinfo->cinfo, COL_INFO, " (%s)",
              tvb_get_string_enc(wmem_packet_scope(), tvb, offset, end_offset-offset, ENC_ASCII|ENC_NA));

        /* Warn if there is a "numeric" command */
        if ((end_offset-offset == 3) &&
            (isdigit(tvb_get_guint8(tvb, offset))) &&
            (isdigit(tvb_get_guint8(tvb, offset+1))) &&
            (isdigit(tvb_get_guint8(tvb, offset+2))))
        {
            expert_add_info(pinfo, request_item, &ei_irc_numeric_request_command);
        }
        return;
    }

    proto_tree_add_item(request_tree, hf_irc_request_command, tvb, offset, eoc_offset-offset, ENC_ASCII|ENC_NA);
    str_command = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, eoc_offset-offset, ENC_ASCII|ENC_NA);
    col_append_fstr( pinfo->cinfo, COL_INFO, " (%s)", str_command);

    /* Warn if there is a "numeric" command */
    if ((eoc_offset-offset == 3) &&
       (isdigit(tvb_get_guint8(tvb, offset))) &&
       (isdigit(tvb_get_guint8(tvb, offset+1))) &&
       (isdigit(tvb_get_guint8(tvb, offset+2))))
    {
        expert_add_info(pinfo, request_item, &ei_irc_numeric_request_command);
    }

    found_needle = 0;
    offset = eoc_offset+1;

    /* clear out any whitespace before command parameter */
    while(offset < end_offset && tvb_get_guint8(tvb, offset) == ' ')
    {
        offset++;
    }
    if (offset == end_offset)
    {
        /* No command parameters */
        return;
    }

    /* Check if message has a trailer */
    if (tvb_get_guint8(tvb, offset) == ':')
    {
        proto_tree_add_item(request_tree, hf_irc_request_trailer, tvb, offset+1, end_offset-offset-1, ENC_ASCII|ENC_NA);
        dissect_irc_tag_data(request_tree, request_item, tvb, offset+1, end_offset-offset-1, pinfo, str_command);
        return;
    }

    while(offset < end_offset)
    {
        eocp_offset = tvb_pbrk_guint8(tvb, offset, end_offset-offset, " ", &found_needle);
        tag_start_offset = tvb_pbrk_guint8(tvb, offset, end_offset-offset, TAG_DELIMITER, &found_tag_needle);

        /* Create subtree when the first parameter is found */
        if (first_command_param)
        {
            command_item = proto_tree_add_text(request_tree, tvb, offset, end_offset-offset, "Command parameters");
            command_tree = proto_item_add_subtree(command_item, ett_irc_request_command );
            first_command_param = FALSE;
        }

        if (((eocp_offset == -1) && (tag_start_offset == -1)) ||
            ((eocp_offset != -1) && (tag_start_offset == -1)) ||
            (eocp_offset < tag_start_offset))
        {
            /* regular message should be dissected */

            found_needle = 0;
            if (eocp_offset == -1)
            {
                proto_tree_add_item(command_tree, hf_irc_request_command_param, tvb, offset, end_offset-offset, ENC_ASCII|ENC_NA);
                return;
            }

            proto_tree_add_item(command_tree, hf_irc_request_command_param, tvb, offset, eocp_offset-offset, ENC_ASCII|ENC_NA);
            offset = eocp_offset+1;

            /* clear out any whitespace before next command parameter */
            while(offset < end_offset && tvb_get_guint8(tvb, offset) == ' ')
            {
                offset++;
            }
            if (offset == end_offset)
            {
                break;
            }

            /* Check if message has a trailer */
            if (tvb_get_guint8(tvb, offset) == ':')
            {
                proto_tree_add_item(request_tree, hf_irc_request_trailer, tvb, offset+1, end_offset-offset-1, ENC_ASCII|ENC_NA);
                dissect_irc_tag_data(request_tree, request_item, tvb, offset+1, end_offset-offset-1, pinfo, str_command);
                return;
            }
        }
        else if (((eocp_offset == -1) && (tag_start_offset != -1)) ||
               (eocp_offset > tag_start_offset))
        {
            /* tag data dissected */

            found_tag_needle = 0;
            tag_end_offset = tvb_pbrk_guint8(tvb, tag_start_offset+1, end_offset-tag_start_offset-1, TAG_DELIMITER, &found_tag_needle);
            if (tag_end_offset == -1)
            {
                expert_add_info(pinfo, request_item, &ei_irc_missing_end_delimiter);
                return;
            }

            dissect_irc_tag_data(request_tree, request_item, tvb, tag_start_offset, tag_end_offset-tag_start_offset, pinfo, str_command);
            offset = tag_end_offset+1;
        }
    }
}

static void
dissect_irc_response(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int linelen)
{
    proto_tree *response_tree, *command_tree = NULL;
    proto_item *response_item, *command_item, *hidden_item;
    int         start_offset                 = offset;
    int         end_offset                   = start_offset+linelen;
    gint        eop_offset                   = -1,
                eoc_offset                   = -1,
                eocp_offset,
                tag_start_offset, tag_end_offset;
    guint8*     str_command;
    guint16     num_command;
    guchar      found_needle                 = 0,
                found_tag_needle             = 0;
    gboolean    first_command_param          = TRUE;

    response_item = proto_tree_add_item(tree, hf_irc_response, tvb, offset, linelen, ENC_ASCII|ENC_NA);
    if (linelen <= 0)
        return;

    response_tree = proto_item_add_subtree(response_item, ett_irc_response );

    /* Check if message has a prefix */
    if (tvb_get_guint8(tvb, offset) == ':')
    {
        /* find the end of the prefix */
        eop_offset = tvb_pbrk_guint8(tvb, offset+1, linelen-1, " ", &found_needle);
        if (eop_offset == -1)
        {
            expert_add_info(pinfo, response_item, &ei_irc_prefix_missing_ending_space);
            return;
        }

        proto_tree_add_item(response_tree, hf_irc_response_prefix, tvb, offset+1, eop_offset-offset-1, ENC_ASCII|ENC_NA);
        found_needle = 0;
        offset = eop_offset+1;
    }

    /* clear out any whitespace before command */
    while(offset < end_offset && tvb_get_guint8(tvb, offset) == ' ')
    {
        offset++;
    }
    if (offset == end_offset)
    {
        expert_add_info(pinfo, response_item, &ei_irc_response_command);
        return;
    }

    eoc_offset = tvb_pbrk_guint8(tvb, offset, end_offset-offset, " ", &found_needle);
    if (eoc_offset == -1)
    {
        proto_tree_add_item(response_tree, hf_irc_response_command, tvb, offset, end_offset-offset, ENC_ASCII|ENC_NA);
        col_append_fstr( pinfo->cinfo, COL_INFO, " (%s)",
              tvb_get_string_enc(wmem_packet_scope(), tvb, offset, end_offset-offset, ENC_ASCII|ENC_NA));

        /* if response command is numeric, allow it to be filtered as an integer */
        if ((end_offset-offset == 3) &&
            (isdigit(tvb_get_guint8(tvb, offset))) &&
            (isdigit(tvb_get_guint8(tvb, offset+1))) &&
            (isdigit(tvb_get_guint8(tvb, offset+2))))
        {
            num_command = ((tvb_get_guint8(tvb, offset)-0x30)*100) + ((tvb_get_guint8(tvb, offset+1)-0x30)*10) + (tvb_get_guint8(tvb, offset+2)-0x30);
            hidden_item = proto_tree_add_uint(response_tree, hf_irc_response_num_command, tvb, offset, end_offset-offset, num_command);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        return;
    }

    proto_tree_add_item(response_tree, hf_irc_response_command, tvb, offset, eoc_offset-offset, ENC_ASCII|ENC_NA);
    str_command = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, eoc_offset-offset, ENC_ASCII|ENC_NA);
    col_append_fstr( pinfo->cinfo, COL_INFO, " (%s)", str_command);

    /* if response command is numeric, allow it to be filtered as an integer */
    if ((eoc_offset-offset == 3) &&
       (isdigit(tvb_get_guint8(tvb, offset))) &&
       (isdigit(tvb_get_guint8(tvb, offset+1))) &&
       (isdigit(tvb_get_guint8(tvb, offset+2))))
    {
        num_command = ((tvb_get_guint8(tvb, offset)-0x30)*100) + ((tvb_get_guint8(tvb, offset+1)-0x30)*10) + (tvb_get_guint8(tvb, offset+2)-0x30);
        hidden_item = proto_tree_add_uint(response_tree, hf_irc_response_num_command, tvb, offset, eoc_offset-offset, num_command);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
    }

    found_needle = 0;
    offset = eoc_offset+1;

    /* clear out any whitespace before command parameter */
    while(offset < end_offset && tvb_get_guint8(tvb, offset) == ' ')
    {
        offset++;
    }
    if (offset == end_offset)
    {
        /* No command parameters */
        return;
    }

    /* Check if message has a trailer */
    if (tvb_get_guint8(tvb, offset) == ':')
    {
        proto_tree_add_item(response_tree, hf_irc_response_trailer, tvb, offset+1, end_offset-offset-1, ENC_ASCII|ENC_NA);
        dissect_irc_tag_data(response_tree, response_item, tvb, offset+1, end_offset-offset-1, pinfo, str_command);
        return;
    }

    while(offset < end_offset)
    {
        eocp_offset = tvb_pbrk_guint8(tvb, offset, end_offset-offset, " ", &found_needle);
        tag_start_offset = tvb_pbrk_guint8(tvb, offset, end_offset-offset, TAG_DELIMITER, &found_tag_needle);

        /* Create subtree when the first parameter is found */
        if (first_command_param)
        {
            command_item = proto_tree_add_text(response_tree, tvb, offset, end_offset-offset, "Command parameters");
            command_tree = proto_item_add_subtree(command_item, ett_irc_response_command );
            first_command_param = FALSE;
        }

        if ((tag_start_offset == -1) || (eocp_offset < tag_start_offset))
        {
            /* regular message should be dissected */

            found_needle = 0;
            if (eocp_offset == -1)
            {
                proto_tree_add_item(command_tree, hf_irc_response_command_param, tvb, offset, end_offset-offset, ENC_ASCII|ENC_NA);
                return;
            }

            proto_tree_add_item(command_tree, hf_irc_response_command_param, tvb, offset, eocp_offset-offset, ENC_ASCII|ENC_NA);
            offset = eocp_offset+1;

            /* clear out any whitespace before next command parameter */
            while(offset < end_offset && tvb_get_guint8(tvb, offset) == ' ')
            {
                offset++;
            }
            if (offset == end_offset)
            {
                break;
            }

            /* Check if message has a trailer */
            if (tvb_get_guint8(tvb, offset) == ':')
            {
                proto_tree_add_item(response_tree, hf_irc_response_trailer, tvb, offset+1, end_offset-offset-1, ENC_ASCII|ENC_NA);
                dissect_irc_tag_data(response_tree, response_item, tvb, offset+1, end_offset-offset-1, pinfo, str_command);
                return;
            }
        }
        else if ((eocp_offset == -1) || (eocp_offset > tag_start_offset))
        {
            /* tag data dissected */

            found_tag_needle = 0;
            tag_end_offset = tvb_pbrk_guint8(tvb, tag_start_offset+1, end_offset-tag_start_offset-1, TAG_DELIMITER, &found_tag_needle);
            if (tag_end_offset == -1)
            {
                expert_add_info(pinfo, response_item, &ei_irc_missing_end_delimiter);
                return;
            }

            dissect_irc_tag_data(response_tree, response_item, tvb, tag_start_offset, tag_end_offset-tag_start_offset, pinfo, str_command);
            offset = tag_end_offset+1;
        }
    }
}

static void
dissect_irc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *irc_tree, *ti;
    gint        offset = 0;
    gint        next_offset;
    int         linelen;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IRC");

    col_set_str(pinfo->cinfo, COL_INFO,
        (pinfo->match_uint == pinfo->destport) ? "Request" : "Response");

    ti = proto_tree_add_item(tree, proto_irc, tvb, 0, -1, ENC_NA);
    irc_tree = proto_item_add_subtree(ti, ett_irc);

    /*
     * Process the packet data, a line at a time.
     */
    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        /*
         * Find the end of the line.
         */
        linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        if (next_offset == offset) {
            /*
             * XXX - we really want the "show data a
             * line at a time" loops in various
             * dissectors to do reassembly and to
             * throw an exception if there's no
             * line ending in the current packet
             * and we're not doing reassembly.
             */
            break;
        }

        if (linelen != 0)
        {
            if (pinfo->match_uint == pinfo->destport)
            {
                dissect_irc_request(irc_tree, tvb, pinfo, offset, linelen);
            }
            else
            {
                dissect_irc_response(irc_tree, tvb, pinfo, offset, linelen);
            }
        }
        offset = next_offset;
    }
}

void
proto_register_irc(void)
{
    static hf_register_info hf[] = {
        { &hf_irc_response, { "Response", "irc.response", FT_STRING, STR_ASCII,
          NULL, 0x0, "Line of response message", HFILL }},

        { &hf_irc_request, { "Request", "irc.request", FT_STRING, STR_ASCII,
          NULL, 0x0, "Line of request message", HFILL }},

        { &hf_irc_request_prefix, { "Prefix", "irc.request.prefix", FT_STRING, STR_ASCII,
          NULL, 0x0, "Request prefix", HFILL }},

        { &hf_irc_request_command, { "Command", "irc.request.command", FT_STRING, STR_ASCII,
          NULL, 0x0, "Request command", HFILL }},

        { &hf_irc_request_command_param, { "Parameter", "irc.request.command_parameter", FT_STRING, STR_ASCII,
          NULL, 0x0, "Request command parameter", HFILL }},

        { &hf_irc_request_trailer, { "Trailer", "irc.request.trailer", FT_STRING, STR_ASCII,
          NULL, 0x0, "Request trailer", HFILL }},

        { &hf_irc_response_prefix, { "Prefix", "irc.response.prefix", FT_STRING, STR_ASCII,
          NULL, 0x0, "Response prefix", HFILL }},

        { &hf_irc_response_command, { "Command", "irc.response.command", FT_STRING, STR_ASCII,
          NULL, 0x0, "Response command", HFILL }},

        { &hf_irc_response_num_command, { "Command", "irc.response.num_command", FT_UINT16, BASE_DEC,
          NULL, 0x0, "Response (numeric) command", HFILL }},

        { &hf_irc_response_command_param, { "Parameter", "irc.response.command_parameter", FT_STRING, STR_ASCII,
          NULL, 0x0, "Response command parameter", HFILL }},

        { &hf_irc_response_trailer, { "Trailer", "irc.response.trailer", FT_STRING, STR_ASCII,
          NULL, 0x0, "Response trailer", HFILL }},

        { &hf_irc_ctcp, { "CTCP Data", "irc.ctcp", FT_STRING, STR_ASCII,
          NULL, 0x0, "Placeholder to dissect CTCP data", HFILL }}
    };

    static gint *ett[] = {
        &ett_irc,
        &ett_irc_request,
        &ett_irc_request_command,
        &ett_irc_response,
        &ett_irc_response_command
    };

    static ei_register_info ei[] = {
        { &ei_irc_missing_end_delimiter, { "irc.missing_end_delimiter", PI_MALFORMED, PI_ERROR, "Missing ending tag delimiter (0x01)", EXPFILL }},
        { &ei_irc_tag_data_invalid, { "irc.tag_data_invalid", PI_PROTOCOL, PI_WARN, "Tag data outside of NOTICE or PRIVMSG command", EXPFILL }},
        { &ei_irc_prefix_missing_ending_space, { "irc.prefix_missing_ending_space", PI_MALFORMED, PI_ERROR, "Prefix missing ending <space>", EXPFILL }},
        { &ei_irc_request_command, { "irc.request.command.missing", PI_MALFORMED, PI_ERROR, "Request has no command", EXPFILL }},
        { &ei_irc_numeric_request_command, { "irc.request.command.numeric", PI_PROTOCOL, PI_WARN, "Numeric command not allowed in request", EXPFILL }},
        { &ei_irc_response_command, { "irc.response.command.missing", PI_MALFORMED, PI_ERROR, "Response has no command", EXPFILL }},
    };

    expert_module_t* expert_irc;

    proto_irc = proto_register_protocol("Internet Relay Chat", "IRC", "irc");
    proto_register_field_array(proto_irc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_irc = expert_register_protocol(proto_irc);
    expert_register_field_array(expert_irc, ei, array_length(ei));
}

void
proto_reg_handoff_irc(void)
{
    dissector_handle_t irc_handle;

    irc_handle = create_dissector_handle(dissect_irc, proto_irc);
    dissector_add_uint("tcp.port", TCP_PORT_IRC, irc_handle);
    dissector_add_uint("tcp.port", TCP_PORT_DIRCPROXY, irc_handle);
}
