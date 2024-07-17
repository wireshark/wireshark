/* packet-irc.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 * For CTCP, see :
 *  http://www.irchelp.org/irchelp/rfc/ctcpspec.html
 *  http://web.archive.org/web/20031203073050/http://www.invlogic.com/irc/ctcp.html
 *  https://www.ietf.org/archive/id/draft-oakley-irc-ctcp-02.txt
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_irc(void);
void proto_reg_handoff_irc(void);

static int proto_irc;
static int proto_irc_ctcp;
static int hf_irc_request;
static int hf_irc_request_prefix;
static int hf_irc_request_command;
static int hf_irc_request_command_param;
static int hf_irc_request_trailer;
static int hf_irc_response;
static int hf_irc_response_prefix;
static int hf_irc_response_command;
static int hf_irc_response_num_command;
static int hf_irc_response_command_param;
static int hf_irc_response_trailer;
static int hf_irc_ctcp;
static int hf_irc_ctcp_command;
static int hf_irc_ctcp_params;

static int ett_irc;
static int ett_irc_request;
static int ett_irc_request_command;
static int ett_irc_response;
static int ett_irc_response_command;

static expert_field ei_irc_missing_end_delimiter;
static expert_field ei_irc_numeric_request_command;
static expert_field ei_irc_response_command;
static expert_field ei_irc_prefix_missing_ending_space;
static expert_field ei_irc_request_command;
static expert_field ei_irc_tag_data_invalid;

/* This must be a null-terminated string */
static const uint8_t TAG_DELIMITER[] = {0x01, 0x00};
/* patterns used for tvb_ws_mempbrk_pattern_guint8 */
static ws_mempbrk_pattern pbrk_tag_delimiter;

static dissector_handle_t ctcp_handle;

#define TCP_PORT_RANGE          "6667,57000" /* Not IANA registered */

static int
dissect_irc_ctcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree   *ctcp_tree;
    proto_item   *ti;
    const uint8_t *str_command, *str_params;
    int          space_offset = -1;

    ti = proto_tree_add_item(tree, hf_irc_ctcp, tvb, 0, -1, ENC_ASCII|ENC_NA);
    ctcp_tree = proto_item_add_subtree(ti, ett_irc);

    space_offset = tvb_find_guint8(tvb, 1, -1, ' ');
    if (space_offset == -1) {
        proto_tree_add_item_ret_string(ctcp_tree, hf_irc_ctcp_command, tvb, 0, tvb_reported_length(tvb), ENC_ASCII|ENC_NA, pinfo->pool, &str_command);
    }
    else {
        proto_tree_add_item_ret_string(ctcp_tree, hf_irc_ctcp_command, tvb, 0, space_offset, ENC_ASCII|ENC_NA, pinfo->pool, &str_command);
        proto_tree_add_item_ret_string(ctcp_tree, hf_irc_ctcp_params, tvb, space_offset+1, tvb_reported_length(tvb)-space_offset-1, ENC_ASCII|ENC_NA, pinfo->pool, &str_params);
    }

    return tvb_captured_length(tvb);
}

static void
dissect_irc_tag_data(proto_tree *tree, proto_item *item, tvbuff_t *tvb, int offset, int datalen, packet_info *pinfo, const uint8_t* command)
{
    unsigned char found_start_needle = 0,
           found_end_needle   = 0;
    int    tag_start_offset, tag_end_offset;
    tvbuff_t *next_tvb;

    tag_start_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, datalen, &pbrk_tag_delimiter, &found_start_needle);
    if (tag_start_offset == -1)
    {
        /* no tag data */
        return;
    }

    tag_end_offset = tvb_ws_mempbrk_pattern_guint8(tvb, tag_start_offset+1, datalen, &pbrk_tag_delimiter, &found_end_needle);
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
    if(tree) {
        next_tvb = tvb_new_subset_length(tvb, tag_start_offset+1, datalen-2 );
        dissect_irc_ctcp(next_tvb, pinfo, tree, NULL);
    }
}

static void
dissect_irc_request(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int linelen)
{
    proto_tree   *request_tree, *command_tree = NULL;
    proto_item   *request_item;
    int           start_offset                = offset;
    int           end_offset                  = start_offset+linelen;
    int           eop_offset                  = -1,
                  eoc_offset                  = -1,
                  eocp_offset,
                  tag_start_offset, tag_end_offset;
    const uint8_t *str_command;
    unsigned char found_tag_needle            = 0;
    bool          first_command_param         = true;

    request_item = proto_tree_add_item(tree, hf_irc_request, tvb, offset, linelen, ENC_ASCII);
    if (linelen <= 0)
        return;

    request_tree = proto_item_add_subtree(request_item, ett_irc_request );

    /* Check if message has a prefix */
    if (tvb_get_uint8(tvb, offset) == ':')
    {
        /* find the end of the prefix */
        eop_offset = tvb_find_guint8(tvb, offset+1, linelen-1, ' ');
        if (eop_offset == -1)
        {
            expert_add_info(pinfo, request_item, &ei_irc_prefix_missing_ending_space);
            return;
        }

        proto_tree_add_item(request_tree, hf_irc_request_prefix, tvb, offset+1, eop_offset-offset-1, ENC_ASCII);
        offset = eop_offset+1;
    }

    /* clear out any whitespace before command */
    while(offset < end_offset && tvb_get_uint8(tvb, offset) == ' ')
    {
        offset++;
    }
    if (offset == end_offset)
    {
        expert_add_info(pinfo, request_item, &ei_irc_request_command);
        return;
    }

    eoc_offset = tvb_find_guint8(tvb, offset, end_offset-offset, ' ');
    if (eoc_offset == -1)
    {
        const uint8_t* col_str;
        proto_tree_add_item_ret_string(request_tree, hf_irc_request_command, tvb, offset, end_offset-offset, ENC_ASCII|ENC_NA, pinfo->pool, &col_str);
        col_append_fstr( pinfo->cinfo, COL_INFO, " (%s)", col_str);

        /* Warn if there is a "numeric" command */
        if ((end_offset-offset == 3) &&
            (g_ascii_isdigit(tvb_get_uint8(tvb, offset))) &&
            (g_ascii_isdigit(tvb_get_uint8(tvb, offset+1))) &&
            (g_ascii_isdigit(tvb_get_uint8(tvb, offset+2))))
        {
            expert_add_info(pinfo, request_item, &ei_irc_numeric_request_command);
        }
        return;
    }

    proto_tree_add_item_ret_string(request_tree, hf_irc_request_command, tvb, offset, eoc_offset-offset, ENC_ASCII|ENC_NA, pinfo->pool, &str_command);
    col_append_fstr( pinfo->cinfo, COL_INFO, " (%s)", str_command);

    /* Warn if there is a "numeric" command */
    if ((eoc_offset-offset == 3) &&
       (g_ascii_isdigit(tvb_get_uint8(tvb, offset))) &&
       (g_ascii_isdigit(tvb_get_uint8(tvb, offset+1))) &&
       (g_ascii_isdigit(tvb_get_uint8(tvb, offset+2))))
    {
        expert_add_info(pinfo, request_item, &ei_irc_numeric_request_command);
    }

    offset = eoc_offset+1;

    /* clear out any whitespace before command parameter */
    while(offset < end_offset && tvb_get_uint8(tvb, offset) == ' ')
    {
        offset++;
    }
    if (offset == end_offset)
    {
        /* No command parameters */
        return;
    }

    /* Check if message has a trailer */
    if (tvb_get_uint8(tvb, offset) == ':')
    {
        proto_tree_add_item(request_tree, hf_irc_request_trailer, tvb, offset+1, end_offset-offset-1, ENC_ASCII);
        dissect_irc_tag_data(request_tree, request_item, tvb, offset+1, end_offset-offset-1, pinfo, str_command);
        return;
    }

    while(offset < end_offset)
    {
        eocp_offset = tvb_find_guint8(tvb, offset, end_offset-offset, ' ');
        tag_start_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, end_offset-offset, &pbrk_tag_delimiter, &found_tag_needle);

        /* Create subtree when the first parameter is found */
        if (first_command_param)
        {
            command_tree = proto_tree_add_subtree(request_tree, tvb, offset, end_offset-offset,
                                             ett_irc_request_command, NULL, "Command parameters");
            first_command_param = false;
        }

        if (((eocp_offset == -1) && (tag_start_offset == -1)) ||
            ((eocp_offset != -1) && (tag_start_offset == -1)) ||
            (eocp_offset < tag_start_offset))
        {
            /* regular message should be dissected */

            if (eocp_offset == -1)
            {
                proto_tree_add_item(command_tree, hf_irc_request_command_param, tvb, offset, end_offset-offset, ENC_ASCII);
                return;
            }

            proto_tree_add_item(command_tree, hf_irc_request_command_param, tvb, offset, eocp_offset-offset, ENC_ASCII);
            offset = eocp_offset+1;

            /* clear out any whitespace before next command parameter */
            while(offset < end_offset && tvb_get_uint8(tvb, offset) == ' ')
            {
                offset++;
            }
            if (offset == end_offset)
            {
                break;
            }

            /* Check if message has a trailer */
            if (tvb_get_uint8(tvb, offset) == ':')
            {
                proto_tree_add_item(request_tree, hf_irc_request_trailer, tvb, offset+1, end_offset-offset-1, ENC_ASCII);
                dissect_irc_tag_data(request_tree, request_item, tvb, offset+1, end_offset-offset-1, pinfo, str_command);
                return;
            }
        }
        else if (((eocp_offset == -1) && (tag_start_offset != -1)) ||
               (eocp_offset > tag_start_offset))
        {
            /* tag data dissected */

            found_tag_needle = 0;
            tag_end_offset = tvb_ws_mempbrk_pattern_guint8(tvb, tag_start_offset+1, end_offset-tag_start_offset-1, &pbrk_tag_delimiter, &found_tag_needle);
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
    proto_tree   *response_tree, *command_tree = NULL;
    proto_item   *response_item, *hidden_item;
    int           start_offset                 = offset;
    int           end_offset                   = start_offset+linelen;
    int           eop_offset                   = -1,
                  eoc_offset                   = -1,
                  eocp_offset,
                  tag_start_offset, tag_end_offset;
    const uint8_t* str_command;
    uint16_t      num_command;
    unsigned char found_tag_needle             = 0;
    bool          first_command_param          = true;

    response_item = proto_tree_add_item(tree, hf_irc_response, tvb, offset, linelen, ENC_ASCII);
    if (linelen <= 0)
        return;

    response_tree = proto_item_add_subtree(response_item, ett_irc_response );

    /* Check if message has a prefix */
    if (tvb_get_uint8(tvb, offset) == ':')
    {
        /* find the end of the prefix */
        eop_offset = tvb_find_guint8(tvb, offset+1, linelen-1, ' ');
        if (eop_offset == -1)
        {
            expert_add_info(pinfo, response_item, &ei_irc_prefix_missing_ending_space);
            return;
        }

        proto_tree_add_item(response_tree, hf_irc_response_prefix, tvb, offset+1, eop_offset-offset-1, ENC_ASCII);
        offset = eop_offset+1;
    }

    /* clear out any whitespace before command */
    while(offset < end_offset && tvb_get_uint8(tvb, offset) == ' ')
    {
        offset++;
    }
    if (offset == end_offset)
    {
        expert_add_info(pinfo, response_item, &ei_irc_response_command);
        return;
    }

    eoc_offset = tvb_find_guint8(tvb, offset, end_offset-offset, ' ');
    if (eoc_offset == -1)
    {
        const uint8_t* col_str;
        proto_tree_add_item_ret_string(response_tree, hf_irc_response_command, tvb, offset, end_offset-offset, ENC_ASCII|ENC_NA, pinfo->pool, &col_str);
        col_append_fstr( pinfo->cinfo, COL_INFO, " (%s)", col_str);

        /* if response command is numeric, allow it to be filtered as an integer */
        if ((end_offset-offset == 3) &&
            (g_ascii_isdigit(tvb_get_uint8(tvb, offset))) &&
            (g_ascii_isdigit(tvb_get_uint8(tvb, offset+1))) &&
            (g_ascii_isdigit(tvb_get_uint8(tvb, offset+2))))
        {
            num_command = ((tvb_get_uint8(tvb, offset)-0x30)*100) + ((tvb_get_uint8(tvb, offset+1)-0x30)*10) + (tvb_get_uint8(tvb, offset+2)-0x30);
            hidden_item = proto_tree_add_uint(response_tree, hf_irc_response_num_command, tvb, offset, end_offset-offset, num_command);
            proto_item_set_hidden(hidden_item);
        }
        return;
    }

    proto_tree_add_item_ret_string(response_tree, hf_irc_response_command, tvb, offset, eoc_offset-offset, ENC_ASCII|ENC_NA, pinfo->pool, &str_command);
    col_append_fstr( pinfo->cinfo, COL_INFO, " (%s)", str_command);

    /* if response command is numeric, allow it to be filtered as an integer */
    if ((eoc_offset-offset == 3) &&
       (g_ascii_isdigit(tvb_get_uint8(tvb, offset))) &&
       (g_ascii_isdigit(tvb_get_uint8(tvb, offset+1))) &&
       (g_ascii_isdigit(tvb_get_uint8(tvb, offset+2))))
    {
        num_command = ((tvb_get_uint8(tvb, offset)-0x30)*100) + ((tvb_get_uint8(tvb, offset+1)-0x30)*10) + (tvb_get_uint8(tvb, offset+2)-0x30);
        hidden_item = proto_tree_add_uint(response_tree, hf_irc_response_num_command, tvb, offset, eoc_offset-offset, num_command);
        proto_item_set_hidden(hidden_item);
    }

    offset = eoc_offset+1;

    /* clear out any whitespace before command parameter */
    while(offset < end_offset && tvb_get_uint8(tvb, offset) == ' ')
    {
        offset++;
    }
    if (offset == end_offset)
    {
        /* No command parameters */
        return;
    }

    /* Check if message has a trailer */
    if (tvb_get_uint8(tvb, offset) == ':')
    {
        proto_tree_add_item(response_tree, hf_irc_response_trailer, tvb, offset+1, end_offset-offset-1, ENC_ASCII);
        dissect_irc_tag_data(response_tree, response_item, tvb, offset+1, end_offset-offset-1, pinfo, str_command);
        return;
    }

    while(offset < end_offset)
    {
        eocp_offset = tvb_find_guint8(tvb, offset, end_offset-offset, ' ');
        tag_start_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, end_offset-offset, &pbrk_tag_delimiter, &found_tag_needle);

        /* Create subtree when the first parameter is found */
        if (first_command_param)
        {
            command_tree = proto_tree_add_subtree(response_tree, tvb, offset, end_offset-offset,
                                        ett_irc_response_command , NULL, "Command parameters");
            first_command_param = false;
        }

        if ((tag_start_offset == -1) || (eocp_offset < tag_start_offset))
        {
            /* regular message should be dissected */

            if (eocp_offset == -1)
            {
                proto_tree_add_item(command_tree, hf_irc_response_command_param, tvb, offset, end_offset-offset, ENC_ASCII);
                return;
            }

            proto_tree_add_item(command_tree, hf_irc_response_command_param, tvb, offset, eocp_offset-offset, ENC_ASCII);
            offset = eocp_offset+1;

            /* clear out any whitespace before next command parameter */
            while(offset < end_offset && tvb_get_uint8(tvb, offset) == ' ')
            {
                offset++;
            }
            if (offset == end_offset)
            {
                break;
            }

            /* Check if message has a trailer */
            if (tvb_get_uint8(tvb, offset) == ':')
            {
                proto_tree_add_item(response_tree, hf_irc_response_trailer, tvb, offset+1, end_offset-offset-1, ENC_ASCII);
                dissect_irc_tag_data(response_tree, response_item, tvb, offset+1, end_offset-offset-1, pinfo, str_command);
                return;
            }
        }
        else if ((eocp_offset == -1) || (eocp_offset > tag_start_offset))
        {
            /* tag data dissected */

            found_tag_needle = 0;
            tag_end_offset = tvb_ws_mempbrk_pattern_guint8(tvb, tag_start_offset+1, end_offset-tag_start_offset-1, &pbrk_tag_delimiter, &found_tag_needle);
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

static int
dissect_irc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *irc_tree, *ti;
    int         offset = 0;
    int         next_offset;
    int         linelen;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IRC");

    col_set_str(pinfo->cinfo, COL_INFO,
        (pinfo->match_uint == pinfo->destport) ? "Request" : "Response");

    ti = proto_tree_add_item(tree, proto_irc, tvb, 0, -1, ENC_NA);
    irc_tree = proto_item_add_subtree(ti, ett_irc);

    /*
     * Process the packet data, a line at a time.
     */
    while (tvb_offset_exists(tvb, offset))
    {
        /*
         * Find the end of the line.
         */
        linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
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
    return tvb_captured_length(tvb);
}

void
proto_register_irc(void)
{
    static hf_register_info hf[] = {
        { &hf_irc_response, { "Response", "irc.response", FT_STRING, BASE_NONE,
          NULL, 0x0, "Line of response message", HFILL }},

        { &hf_irc_request, { "Request", "irc.request", FT_STRING, BASE_NONE,
          NULL, 0x0, "Line of request message", HFILL }},

        { &hf_irc_request_prefix, { "Prefix", "irc.request.prefix", FT_STRING, BASE_NONE,
          NULL, 0x0, "Request prefix", HFILL }},

        { &hf_irc_request_command, { "Command", "irc.request.command", FT_STRING, BASE_NONE,
          NULL, 0x0, "Request command", HFILL }},

        { &hf_irc_request_command_param, { "Parameter", "irc.request.command_parameter", FT_STRING, BASE_NONE,
          NULL, 0x0, "Request command parameter", HFILL }},

        { &hf_irc_request_trailer, { "Trailer", "irc.request.trailer", FT_STRING, BASE_NONE,
          NULL, 0x0, "Request trailer", HFILL }},

        { &hf_irc_response_prefix, { "Prefix", "irc.response.prefix", FT_STRING, BASE_NONE,
          NULL, 0x0, "Response prefix", HFILL }},

        { &hf_irc_response_command, { "Command", "irc.response.command", FT_STRING, BASE_NONE,
          NULL, 0x0, "Response command", HFILL }},

        { &hf_irc_response_num_command, { "Command", "irc.response.num_command", FT_UINT16, BASE_DEC,
          NULL, 0x0, "Response (numeric) command", HFILL }},

        { &hf_irc_response_command_param, { "Parameter", "irc.response.command_parameter", FT_STRING, BASE_NONE,
          NULL, 0x0, "Response command parameter", HFILL }},

        { &hf_irc_response_trailer, { "Trailer", "irc.response.trailer", FT_STRING, BASE_NONE,
          NULL, 0x0, "Response trailer", HFILL }},

        { &hf_irc_ctcp, { "CTCP", "irc.ctcp", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

        { &hf_irc_ctcp_command, { "Command", "irc.ctcp.command", FT_STRING, BASE_NONE,
          NULL, 0x0, "CTCP command", HFILL }},

        { &hf_irc_ctcp_params, { "Parameters", "irc.ctcp.parameters", FT_STRING, BASE_NONE,
          NULL, 0x0, "CTCP parameters", HFILL }},
    };

    static int *ett[] = {
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
    register_dissector("irc", dissect_irc, proto_irc);
    proto_register_field_array(proto_irc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_irc = expert_register_protocol(proto_irc);
    expert_register_field_array(expert_irc, ei, array_length(ei));

    /* subdissector code */
    proto_irc_ctcp = proto_register_protocol_in_name_only("Client To Client Protocol", "CTCP", "irc.ctcp", proto_irc, FT_PROTOCOL);

    /* compile patterns */
    ws_mempbrk_compile(&pbrk_tag_delimiter, TAG_DELIMITER);
}

void
proto_reg_handoff_irc(void)
{
    dissector_add_uint_range_with_preference("tcp.port", TCP_PORT_RANGE, find_dissector("irc"));

    ctcp_handle = create_dissector_handle(dissect_irc_ctcp, proto_irc_ctcp);
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
