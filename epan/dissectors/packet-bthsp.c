/* packet-bthsp.c
 * Routines for Bluetooth Headset Profile (HSP)
 *
 * Copyright 2013, Michal Labedzki for Tieto Corporation
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

#include <ctype.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#include "packet-btrfcomm.h"
#include "packet-btsdp.h"

static int proto_bthsp = -1;

static int hf_command                                                      = -1;
static int hf_parameters                                                   = -1;
static int hf_command_in                                                   = -1;
static int hf_unsolicited                                                  = -1;
static int hf_role                                                         = -1;
static int hf_at_cmd                                                       = -1;
static int hf_at_cmd_type                                                  = -1;
static int hf_at_command_line_prefix                                       = -1;
static int hf_at_ignored                                                   = -1;
static int hf_parameter                                                    = -1;
static int hf_unknown_parameter                                            = -1;
static int hf_data                                                         = -1;
static int hf_fragment                                                     = -1;
static int hf_fragmented                                                   = -1;
static int hf_vgs                                                          = -1;
static int hf_vgm                                                          = -1;
static int hf_ckpd                                                         = -1;

static expert_field ei_non_mandatory_command                          = EI_INIT;
static expert_field ei_invalid_usage                                  = EI_INIT;
static expert_field ei_unknown_parameter                              = EI_INIT;
static expert_field ei_vgm_gain                                       = EI_INIT;
static expert_field ei_vgs_gain                                       = EI_INIT;
static expert_field ei_ckpd                                           = EI_INIT;

static gint ett_bthsp            = -1;
static gint ett_bthsp_command    = -1;
static gint ett_bthsp_parameters = -1;

static dissector_handle_t bthsp_handle;

static wmem_tree_t *fragments = NULL;

#define ROLE_UNKNOWN  0
#define ROLE_AG       1
#define ROLE_HS       2

#define TYPE_UNKNOWN       0x0000
#define TYPE_RESPONSE_ACK  0x0d0a
#define TYPE_RESPONSE      0x003a
#define TYPE_ACTION        0x003d
#define TYPE_ACTION_SIMPLY 0x000d
#define TYPE_READ          0x003f
#define TYPE_TEST          0x3d3f

static gint hsp_role = ROLE_UNKNOWN;

enum reassemble_state_t {
    REASSEMBLE_FRAGMENT,
    REASSEMBLE_PARTIALLY,
    REASSEMBLE_DONE
};

typedef struct _fragment_t {
    guint32                  interface_id;
    guint32                  adapter_id;
    guint32                  chandle;
    guint32                  dlci;
    guint32                  role;

    guint                    index;
    guint                    length;
    guint8                  *data;
    struct _fragment_t      *previous_fragment;

    guint                    reassemble_start_offset;
    guint                    reassemble_end_offset;
    enum reassemble_state_t  reassemble_state;
} fragment_t;

typedef struct _at_cmd_t {
    const guint8 *name;
    const guint8 *long_name;

    gboolean (*check_command)(gint role, guint16 type);
    gboolean (*dissect_parameter)(tvbuff_t *tvb, packet_info *pinfo,
            proto_tree *tree, gint offset, gint role, guint16 type,
            guint8 *parameter_stream, guint parameter_number,
            gint parameter_length, void **data);
} at_cmd_t;

static const value_string role_vals[] = {
    { ROLE_UNKNOWN,   "Unknown" },
    { ROLE_AG,        "AG - Audio Gate" },
    { ROLE_HS,        "HS - Headset" },
    { 0, NULL }
};

static const value_string at_cmd_type_vals[] = {
    { 0x0d,   "Action Command" },
    { 0x3a,   "Response" },
    { 0x3d,   "Action Command" },
    { 0x3f,   "Read Command" },
    { 0x0d0a, "Response" },
    { 0x3d3f, "Test Command" },
    { 0, NULL }
};

static const enum_val_t pref_hsp_role[] = {
    { "off",     "Off",                    ROLE_UNKNOWN },
    { "ag",      "Sent is AG, Rcvd is HS", ROLE_AG },
    { "hs",      "Sent is HS, Rcvd is AG", ROLE_HS },
    { NULL, NULL, 0 }
};

void proto_register_bthsp(void);
void proto_reg_handoff_bthsp(void);

static guint32 get_uint_parameter(guint8 *parameter_stream, gint parameter_length)
{
    guint32      value;
    guint8      *val;

    val = (guint8 *) wmem_alloc(wmem_packet_scope(), parameter_length + 1);
    memcpy(val, parameter_stream, parameter_length);
    val[parameter_length] = '\0';
    value = (guint32) g_ascii_strtoull(val, NULL, 10);

    return value;
}

static gboolean check_vgs(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_vgm(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_ckpd(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;

    return FALSE;
}

static gboolean check_only_ag_role(gint role, guint16 type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE_ACK) return TRUE;

    return FALSE;
}

static gint
dissect_vgs_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!check_vgs(role, type)) return FALSE;

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_vgs, tvb, offset, parameter_length, value);
    proto_item_append_text(pitem, "/15");

    if (value > 15) {
        expert_add_info(pinfo, pitem, &ei_vgs_gain);
    }

    return TRUE;
}

static gint
dissect_vgm_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!check_vgm(role, type)) return FALSE;

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_vgm, tvb, offset, parameter_length, value);
    proto_item_append_text(pitem, "/15");

    if (value > 15) {
        expert_add_info(pinfo, pitem, &ei_vgm_gain);
    }

    return TRUE;
}

static gint
dissect_ckpd_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!check_ckpd(role, type)) return FALSE;


    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_ckpd, tvb, offset, parameter_length, value);

    if (value != 200) {
        expert_add_info(pinfo, pitem, &ei_ckpd);
    }

    return TRUE;
}

static gint
dissect_no_parameter(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_,
        gint offset _U_, gint role _U_, guint16 type _U_, guint8 *parameter_stream _U_,
        guint parameter_number _U_, gint parameter_length _U_, void **data _U_)
{
    return FALSE;
}

static const at_cmd_t at_cmds[] = {
    { "+VGS",       "Gain of Speaker",                          check_vgs,  dissect_vgs_parameter  },
    { "+VGM",       "Gain of Microphone",                       check_vgm,  dissect_vgm_parameter  },
    { "+CKPD",      "Control Keypad",                           check_ckpd, dissect_ckpd_parameter },
    { "ERROR",      "ERROR",                                    check_only_ag_role, dissect_no_parameter },
    { "RING",       "Incomming Call Indication",                check_only_ag_role, dissect_no_parameter },
    { "OK",         "OK",                                       check_only_ag_role, dissect_no_parameter },
    { NULL, NULL, NULL, NULL }
};


static gint
dissect_at_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, guint32 role, gint command_number)
{
    proto_item      *pitem;
    proto_tree      *command_item;
    proto_item      *command_tree;
    proto_tree      *parameters_item = NULL;
    proto_item      *parameters_tree = NULL;
    guint8          *col_str = NULL;
    guint8          *at_stream;
    guint8          *at_command = NULL;
    gint             i_char = 0;
    guint            i_char_fix = 0;
    gint             length;
    const at_cmd_t  *i_at_cmd;
    gint             parameter_length;
    guint            parameter_number = 0;
    gint             first_parameter_offset = offset;
    gint             last_parameter_offset  = offset;
    guint16          type = TYPE_UNKNOWN;
    guint32          brackets;
    gboolean         quotation;
    gboolean         next;
    void            *data;

    length = tvb_length_remaining(tvb, offset);
    if (length <= 0)
        return tvb_length(tvb);

    if (!command_number) {
        proto_tree_add_item(tree, hf_data, tvb, offset, length, ENC_NA | ENC_ASCII);
        col_str = (guint8 *) wmem_alloc(wmem_packet_scope(), length + 1);
        tvb_memcpy(tvb, col_str, offset, length);
        col_str[length] = '\0';
    }

    at_stream = (guint8 *) wmem_alloc(wmem_packet_scope(), length + 1);
    tvb_memcpy(tvb, at_stream, offset, length);
    at_stream[length] = '\0';
    while (at_stream[i_char]) {
        at_stream[i_char] = toupper(at_stream[i_char]);
        if (!command_number) {
            col_str[i_char] = toupper(col_str[i_char]);
            if (!g_ascii_isgraph(col_str[i_char])) col_str[i_char] = ' ';
        }
        i_char += 1;
    }

    command_item = proto_tree_add_none_format(tree, hf_command, tvb,
            offset, 0, "Command %u", command_number);
    command_tree = proto_item_add_subtree(command_item, ett_bthsp_command);

    if (!command_number) col_append_fstr(pinfo->cinfo, COL_INFO, "%s", col_str);

    if (role == ROLE_HS) {
        if (command_number) {
            at_command = at_stream;
            i_char = 0;
        } else {
            at_command = g_strstr_len(at_stream, length, "AT");

            if (at_command) {
                i_char = (guint) (at_command - at_stream);

                if (i_char) {
                    proto_tree_add_item(command_tree, hf_at_ignored, tvb, offset,
                        i_char, ENC_NA | ENC_ASCII);
                    offset += i_char;
                }

                proto_tree_add_item(command_tree, hf_at_command_line_prefix,
                        tvb, offset, 2, ENC_NA | ENC_ASCII);
                offset += 2;
                i_char += 2;
                at_command = at_stream;

                at_command += i_char;
                length -= i_char;
                i_char_fix += i_char;
                i_char = 0;
            }
        }
    } else {
        at_command = at_stream;
        i_char = 0;
        while (i_char <= length &&
                (at_command[i_char] == '\r' || at_command[i_char] == '\n' ||
                at_command[i_char] == ' ' || at_command[i_char] == '\t')) {
            /* ignore white characters */
            i_char += 1;
        }

        offset += i_char;
        at_command += i_char;
        length -= i_char;
        i_char_fix += i_char;
        i_char = 0;
    }

    if (at_command) {

        while (i_char < length &&
                        (at_command[i_char] != '\r' && at_command[i_char] != '=' &&
                        at_command[i_char] != ';' && at_command[i_char] != '?' &&
                        at_command[i_char] != ':')) {
            i_char += 1;
        }

        i_at_cmd = at_cmds;
        if (at_command[0] == '\r') {
            pitem = proto_tree_add_item(command_tree, hf_at_cmd, tvb, offset - 2,
                    2, ENC_NA | ENC_ASCII);
            i_at_cmd = NULL;
        } else {
            pitem = NULL;
            while (i_at_cmd->name) {
                if (g_str_has_prefix(&at_command[0], i_at_cmd->name)) {
                    pitem = proto_tree_add_item(command_tree, hf_at_cmd, tvb, offset,
                            (gint) strlen(i_at_cmd->name), ENC_NA | ENC_ASCII);
                    proto_item_append_text(pitem, " (%s)", i_at_cmd->long_name);
                    break;
                }
                i_at_cmd += 1;
            }

            if (!pitem) {
                pitem = proto_tree_add_item(command_tree, hf_at_cmd, tvb, offset,
                        i_char, ENC_NA | ENC_ASCII);
            }
        }


        if (i_at_cmd && i_at_cmd->name == NULL) {
            char *name;

            name = (char *) wmem_alloc(wmem_packet_scope(), i_char + 2);
            g_strlcpy(name, at_command, i_char + 1);
            name[i_char + 1] = '\0';
            proto_item_append_text(command_item, ": %s (Unknown)", name);
            proto_item_append_text(pitem, " (Unknown - Non-Standard HSP Command)");
            expert_add_info(pinfo, pitem, &ei_non_mandatory_command);
        } else if (i_at_cmd == NULL) {
            proto_item_append_text(command_item, ": AT");
        } else {
            proto_item_append_text(command_item, ": %s", i_at_cmd->name);
        }

        offset += i_char;

        if (i_at_cmd && g_strcmp0(i_at_cmd->name, "D")) {
            if (length >= 2 && at_command[i_char] == '=' && at_command[i_char + 1] == '?') {
                type = at_command[i_char] << 8 | at_command[i_char + 1];
                proto_tree_add_uint(command_tree, hf_at_cmd_type, tvb, offset, 2, type);
                offset += 2;
                i_char += 2;
            } else if (role == ROLE_AG && length >= 2 && at_command[i_char] == '\r' && at_command[i_char + 1] == '\n') {
                type = at_command[i_char] << 8 | at_command[i_char + 1];
                proto_tree_add_uint(command_tree, hf_at_cmd_type, tvb, offset, 2, type);
                offset += 2;
                i_char += 2;
            } else if (length >= 1 && (at_command[i_char] == '=' ||
                        at_command[i_char] == '\r' ||
                        at_command[i_char] == ':' ||
                        at_command[i_char] == '?')) {
                type = at_command[i_char];
                proto_tree_add_uint(command_tree, hf_at_cmd_type, tvb, offset, 1, type);
                offset += 1;
                i_char += 1;
            }
        }

        if (i_at_cmd && i_at_cmd->check_command && !i_at_cmd->check_command(role, type)) {
            expert_add_info(pinfo, command_item, &ei_invalid_usage);
        }

        parameters_item = proto_tree_add_none_format(command_tree, hf_parameters, tvb,
                offset, 0, "Parameters");
        parameters_tree = proto_item_add_subtree(parameters_item, ett_bthsp_parameters);

        data = NULL;

        while (i_char < length) {

            while (at_command[i_char] == ' ' || at_command[i_char]  == '\t') {
                offset += 1;
                i_char += 1;
            }

            parameter_length = 0;
            brackets = 0;
            quotation = FALSE;
            next = FALSE;

            if (at_command[i_char + parameter_length] != '\r') {
                while (i_char + parameter_length < length &&
                        at_command[i_char + parameter_length] != '\r') {

                    if (at_command[i_char + parameter_length] == ';') {
                        next = TRUE;
                        break;
                    }

                    if (at_command[i_char + parameter_length] == '"') {
                        quotation = quotation ? FALSE : TRUE;
                    }

                    if (quotation == TRUE) {
                        parameter_length += 1;
                        continue;
                    }

                    if (at_command[i_char + parameter_length] == '(') {
                        brackets += 1;
                    }
                    if (at_command[i_char + parameter_length] == ')') {
                        brackets -= 1;
                    }

                    if (brackets == 0 && at_command[i_char + parameter_length] == ',') {
                        break;
                    }

                    parameter_length += 1;
                }

/* TODO: Save bthsp.at_cmd, bthsp.at_cmd.type, frame_time  and frame_num here in

                if (role == ROLE_HS && pinfo->fd->flags.visited == 0) {

    at_cmd_db = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    interface_id
    adapter_id
    chandle
    dlci

    frame_number
-------------------
    at_command
    at_type
    frame_num
    frame_time
    status
    first_response_in (if 0 - no response)


            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_dlci         = dlci;
            k_frame_number = pinfo->fd->num;


            key[0].length = 1;
            key[0].key = &k_interface_id;
            key[1].length = 1;
            key[1].key = &k_adapter_id;
            key[2].length = 1;
            key[2].key = &k_chandle;
            key[3].length = 1;
            key[3].key = &k_dlci;
            key[4].length = 1;
            key[4].key = &k_frame_number;
            key[5].length = 0;
            key[5].key = NULL;

            cmd = wmem_new(wmem_file_scope(), at_cmd_entry_t);
            cmd->interface_id = interface_id;
            cmd->adapter_id   = adapter_id;
            cmd->chandle      = chandle;
            cmd->dlci         = dlci;

            cmd->frame_number = pinfo->fd->num;
            cmd->status = STATUS_NO_RESPONSE;
            cmd->time = pinfo->fd->abs_ts;
            cmd->at_command
            cmd->at_type
            cmd->first_response_in = 0;

            wmem_tree_insert32_array(at_cmd_db, key, cmd);
    }

*/

                first_parameter_offset = offset;
                if (type == TYPE_ACTION || type == TYPE_RESPONSE) {
                    if (i_at_cmd && (i_at_cmd->dissect_parameter != NULL &&
                            !i_at_cmd->dissect_parameter(tvb, pinfo, parameters_tree, offset, role,
                            type, &at_command[i_char], parameter_number, parameter_length, &data) )) {
                        pitem = proto_tree_add_item(parameters_tree,
                                hf_unknown_parameter, tvb, offset,
                                parameter_length, ENC_NA | ENC_ASCII);
                        expert_add_info(pinfo, pitem, &ei_unknown_parameter);
                    } else if (i_at_cmd && i_at_cmd->dissect_parameter == NULL) {
                        proto_tree_add_item(parameters_tree, hf_parameter, tvb, offset,
                                parameter_length, ENC_NA | ENC_ASCII);
                    }
                }
            }

            if (type != TYPE_ACTION_SIMPLY && type != TYPE_RESPONSE_ACK && type != TYPE_TEST && type != TYPE_READ)
                parameter_number += 1;
            i_char += parameter_length;
            offset += parameter_length;
            last_parameter_offset = offset;

            if (role == ROLE_AG &&
                    i_char + 1 <= length &&
                    at_command[i_char] == '\r' &&
                    at_command[i_char + 1] == '\n') {
                offset += 2;
                i_char += 2;
                break;
            } else if (at_command[i_char] == ',' ||
                        at_command[i_char] == '\r' ||
                        at_command[i_char] == ';') {
                    i_char += 1;
                    offset += 1;
            }

            if (next) break;
        }

        i_char += i_char_fix;
        proto_item_set_len(command_item, i_char);
    } else {
        length = tvb_length_remaining(tvb, offset);
        if (length < 0)
            length = 0;
        proto_item_set_len(command_item, length);
        offset += length;
    }

    if (parameter_number > 0 && last_parameter_offset - first_parameter_offset > 0)
        proto_item_set_len(parameters_item, last_parameter_offset - first_parameter_offset);
    else
        proto_item_append_text(parameters_item, ": No");

    if (role == ROLE_AG) {
        guint command_frame_number = 0;

        if (command_frame_number) {
            pitem = proto_tree_add_uint(command_tree, hf_command_in, tvb, offset,
                    0, command_frame_number);
            PROTO_ITEM_SET_GENERATED(pitem);
        } else {
            pitem = proto_tree_add_item(command_tree, hf_unsolicited, tvb, offset, 0, ENC_NA);
            PROTO_ITEM_SET_GENERATED(pitem);
        }
    }

    return offset;
}

static gint
dissect_bthsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *main_item;
    proto_tree       *main_tree;
    proto_item       *pitem;
    gint              offset = 0;
    guint32           role = ROLE_UNKNOWN;
    wmem_tree_key_t   key[10];
    guint32           k_interface_id;
    guint32           k_adapter_id;
    guint32           k_chandle;
    guint32           k_dlci;
    guint32           k_role;
    guint32           k_frame_number;
    guint32           interface_id;
    guint32           adapter_id;
    guint32           chandle;
    guint32           dlci;
    fragment_t       *fragment;
    fragment_t       *previous_fragment;
    fragment_t       *i_fragment;
    btrfcomm_data_t  *rfcomm_data;
    guint8           *at_stream;
    gint              length;
    gint              command_number;
    gint              i_length;
    tvbuff_t         *reassembled_tvb = NULL;
    guint             reassemble_start_offset = 0;
    guint             reassemble_end_offset   = 0;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    rfcomm_data = (btrfcomm_data_t *) data;

    main_item = proto_tree_add_item(tree, proto_bthsp, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bthsp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HSP");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ", pinfo->p2p_dir);
            break;
    }

    interface_id = rfcomm_data->interface_id;
    adapter_id   = rfcomm_data->adapter_id;
    chandle      = rfcomm_data->chandle;
    dlci         = rfcomm_data->dlci;

    if ((hsp_role == ROLE_AG && pinfo->p2p_dir == P2P_DIR_SENT) ||
            (hsp_role == ROLE_HS && pinfo->p2p_dir == P2P_DIR_RECV)) {
        role = ROLE_AG;
    } else if (hsp_role != ROLE_UNKNOWN) {
        role = ROLE_HS;
    }

    if (role == ROLE_UNKNOWN) {
        guint32          k_sdp_psm;
        guint32          k_direction;
        guint32          k_bd_addr_oui;
        guint32          k_bd_addr_id;
        guint32          k_service_type;
        guint32          k_service_channel;
        service_info_t  *service_info;

        k_interface_id    = rfcomm_data->interface_id;
        k_adapter_id      = rfcomm_data->adapter_id;
        k_sdp_psm         = SDP_PSM_DEFAULT;
        k_direction       = (rfcomm_data->is_local_psm) ? P2P_DIR_SENT : P2P_DIR_RECV;
        if (k_direction == P2P_DIR_RECV) {
            k_bd_addr_oui     = rfcomm_data->remote_bd_addr_oui;
            k_bd_addr_id      = rfcomm_data->remote_bd_addr_id;
        } else {
            k_bd_addr_oui     = 0;
            k_bd_addr_id      = 0;
        }
        k_service_type    = BTSDP_RFCOMM_PROTOCOL_UUID;
        k_service_channel = rfcomm_data->dlci >> 1;
        k_frame_number    = pinfo->fd->num;

        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_sdp_psm;
        key[3].length = 1;
        key[3].key = &k_direction;
        key[4].length = 1;
        key[4].key = &k_bd_addr_oui;
        key[5].length = 1;
        key[5].key = &k_bd_addr_id;
        key[6].length = 1;
        key[6].key = &k_service_type;
        key[7].length = 1;
        key[7].key = &k_service_channel;
        key[8].length = 1;
        key[8].key = &k_frame_number;
        key[9].length = 0;
        key[9].key = NULL;

        service_info = btsdp_get_service_info(key);
        if (service_info && service_info->interface_id == rfcomm_data->interface_id &&
                service_info->adapter_id == rfcomm_data->adapter_id &&
                service_info->sdp_psm == SDP_PSM_DEFAULT &&
                ((service_info->direction == P2P_DIR_RECV &&
                service_info->bd_addr_oui == rfcomm_data->remote_bd_addr_oui &&
                service_info->bd_addr_id == rfcomm_data->remote_bd_addr_id) ||
                (service_info->direction != P2P_DIR_RECV &&
                service_info->bd_addr_oui == 0 &&
                service_info->bd_addr_id == 0)) &&
                service_info->type == BTSDP_RFCOMM_PROTOCOL_UUID &&
                service_info->channel == (rfcomm_data->dlci >> 1)) {
            if ((service_info->uuid.bt_uuid == BTSDP_HSP_GW_SERVICE_UUID && service_info->direction == P2P_DIR_RECV && pinfo->p2p_dir == P2P_DIR_SENT) ||
                (service_info->uuid.bt_uuid == BTSDP_HSP_GW_SERVICE_UUID && service_info->direction == P2P_DIR_SENT && pinfo->p2p_dir == P2P_DIR_RECV) ||
                ((service_info->uuid.bt_uuid == BTSDP_HSP_SERVICE_UUID || service_info->uuid.bt_uuid == BTSDP_HSP_HS_SERVICE_UUID) && service_info->direction == P2P_DIR_RECV && pinfo->p2p_dir == P2P_DIR_RECV) ||
                ((service_info->uuid.bt_uuid == BTSDP_HSP_SERVICE_UUID || service_info->uuid.bt_uuid == BTSDP_HSP_HS_SERVICE_UUID) && service_info->direction == P2P_DIR_SENT && pinfo->p2p_dir == P2P_DIR_SENT)) {
                role = ROLE_HS;
            } else {
                role = ROLE_AG;
            }
        }
    }

    pitem = proto_tree_add_uint(main_tree, hf_role, tvb, 0, 0, role);
    PROTO_ITEM_SET_GENERATED(pitem);

    if (role == ROLE_UNKNOWN) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Data: %s",
                tvb_format_text(tvb, 0, tvb_length(tvb)));
        proto_tree_add_item(main_tree, hf_data, tvb, 0, -1, ENC_NA | ENC_ASCII);
        return tvb_length(tvb);
    }

    /* save fragments */
    if (!pinfo->fd->flags.visited) {
        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_dlci         = dlci;
        k_role         = role;
        k_frame_number = pinfo->fd->num - 1;

        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_chandle;
        key[3].length = 1;
        key[3].key = &k_dlci;
        key[4].length = 1;
        key[4].key = &k_role;
        key[5].length = 1;
        key[5].key = &k_frame_number;
        key[6].length = 0;
        key[6].key = NULL;

        previous_fragment = (fragment_t *) wmem_tree_lookup32_array_le(fragments, key);
        if (!(previous_fragment && previous_fragment->interface_id == interface_id &&
                previous_fragment->adapter_id == adapter_id &&
                previous_fragment->chandle == chandle &&
                previous_fragment->dlci == dlci &&
                previous_fragment->role == role &&
                previous_fragment->reassemble_state != REASSEMBLE_DONE)) {
            previous_fragment = NULL;
        }

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_dlci         = dlci;
        k_role         = role;
        k_frame_number = pinfo->fd->num;

        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_chandle;
        key[3].length = 1;
        key[3].key = &k_dlci;
        key[4].length = 1;
        key[4].key = &k_role;
        key[5].length = 1;
        key[5].key = &k_frame_number;
        key[6].length = 0;
        key[6].key = NULL;

        fragment = wmem_new(wmem_file_scope(), fragment_t);
        fragment->interface_id      = interface_id;
        fragment->adapter_id        = adapter_id;
        fragment->chandle           = chandle;
        fragment->dlci              = dlci;
        fragment->role              = role;
        fragment->index             = previous_fragment ? previous_fragment->index + previous_fragment->length : 0;
        fragment->reassemble_state  = REASSEMBLE_FRAGMENT;
        fragment->length            = tvb_length(tvb);
        fragment->data              = (guint8 *) wmem_alloc(wmem_file_scope(), fragment->length);
        fragment->previous_fragment = previous_fragment;
        tvb_memcpy(tvb, fragment->data, offset, fragment->length);

        wmem_tree_insert32_array(fragments, key, fragment);

        /* Detect reassemble end character: \r for HS or \n for AG */
        length = tvb_length(tvb);
        at_stream = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, length, ENC_ASCII);

        reassemble_start_offset = 0;

        for (i_length = 0; i_length < length; i_length += 1) {
            if (!((role == ROLE_HS && at_stream[i_length] == '\r') ||
                    (role == ROLE_AG && at_stream[i_length] == '\n'))) {
                continue;
            }

            if (role == ROLE_HS && at_stream[i_length] == '\r') {
                reassemble_start_offset = i_length + 1;
                if (reassemble_end_offset == 0) reassemble_end_offset = i_length + 1;
            }

            if (role == ROLE_AG && at_stream[i_length] == '\n') {
                reassemble_start_offset = i_length + 1;
            }

            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_dlci         = dlci;
            k_role         = role;
            k_frame_number = pinfo->fd->num;

            key[0].length = 1;
            key[0].key = &k_interface_id;
            key[1].length = 1;
            key[1].key = &k_adapter_id;
            key[2].length = 1;
            key[2].key = &k_chandle;
            key[3].length = 1;
            key[3].key = &k_dlci;
            key[4].length = 1;
            key[4].key = &k_role;
            key[5].length = 1;
            key[5].key = &k_frame_number;
            key[6].length = 0;
            key[6].key = NULL;

            fragment = (fragment_t *) wmem_tree_lookup32_array_le(fragments, key);
            if (fragment && fragment->interface_id == interface_id &&
                    fragment->adapter_id == adapter_id &&
                    fragment->chandle == chandle &&
                    fragment->dlci == dlci &&
                    fragment->role == role) {
                i_fragment = fragment;
                while (i_fragment && i_fragment->index > 0) {
                    i_fragment = i_fragment->previous_fragment;
                }

                if (i_length + 1 == length &&
                        role == ROLE_HS &&
                        at_stream[i_length] == '\r') {
                    fragment->reassemble_state = REASSEMBLE_DONE;
                } else if (i_length + 1 == length &&
                        role == ROLE_AG &&
                        i_length >= 4 &&
                        at_stream[i_length] == '\n' &&
                        at_stream[i_length - 1] == '\r' &&
                        at_stream[0] == '\r' &&
                        at_stream[1] == '\n') {
                    fragment->reassemble_state = REASSEMBLE_DONE;
                } else if (i_length + 1 == length &&
                        role == ROLE_AG &&
                        i_length >= 2 &&
                        at_stream[i_length] == '\n' &&
                        at_stream[i_length - 1] == '\r' &&
                        i_fragment &&
                        i_fragment->reassemble_state == REASSEMBLE_FRAGMENT &&
                        i_fragment->length >= 2 &&
                        i_fragment->data[0] == '\r' &&
                        i_fragment->data[1] == '\n') {
                    fragment->reassemble_state = REASSEMBLE_DONE;
                } else if (role == ROLE_HS) {
                    fragment->reassemble_state = REASSEMBLE_PARTIALLY;
                }
                fragment->reassemble_start_offset = reassemble_start_offset;
                fragment->reassemble_end_offset = reassemble_end_offset;
            }
        }
    }

    /* recover reassembled payload */
    k_interface_id = interface_id;
    k_adapter_id   = adapter_id;
    k_chandle      = chandle;
    k_dlci         = dlci;
    k_role         = role;
    k_frame_number = pinfo->fd->num;

    key[0].length = 1;
    key[0].key = &k_interface_id;
    key[1].length = 1;
    key[1].key = &k_adapter_id;
    key[2].length = 1;
    key[2].key = &k_chandle;
    key[3].length = 1;
    key[3].key = &k_dlci;
    key[4].length = 1;
    key[4].key = &k_role;
    key[5].length = 1;
    key[5].key = &k_frame_number;
    key[6].length = 0;
    key[6].key = NULL;

    fragment = (fragment_t *) wmem_tree_lookup32_array_le(fragments, key);
    if (fragment && fragment->interface_id == interface_id &&
            fragment->adapter_id == adapter_id &&
            fragment->chandle == chandle &&
            fragment->dlci == dlci &&
            fragment->role == role &&
            fragment->reassemble_state != REASSEMBLE_FRAGMENT) {
        guint8    *at_data;
        guint      i_data_offset;

        i_data_offset = fragment->index + fragment->length;
        at_data = (guint8 *) wmem_alloc(pinfo->pool, fragment->index + fragment->length);

        i_fragment = fragment;

        if (i_fragment && i_fragment->reassemble_state == REASSEMBLE_PARTIALLY) {
                i_data_offset -= i_fragment->reassemble_end_offset;
                memcpy(at_data + i_data_offset, i_fragment->data, i_fragment->reassemble_end_offset);

            i_fragment = i_fragment->previous_fragment;
        }

        if (i_fragment) {
            while (i_fragment && i_fragment->index > 0) {
                i_data_offset -= i_fragment->length;
                memcpy(at_data + i_data_offset, i_fragment->data, i_fragment->length);
                i_fragment = i_fragment->previous_fragment;
            }

            if (i_fragment && i_fragment->reassemble_state == REASSEMBLE_PARTIALLY) {
                i_data_offset -= (i_fragment->length - i_fragment->reassemble_start_offset);
                memcpy(at_data + i_data_offset, i_fragment->data + i_fragment->reassemble_start_offset,
                        i_fragment->length - i_fragment->reassemble_start_offset);
            } else if (i_fragment) {
                i_data_offset -= i_fragment->length;
                memcpy(at_data + i_data_offset, i_fragment->data, i_fragment->length);
            }
        }

        if (fragment->index > 0 && fragment->length > 0) {
            proto_tree_add_item(main_tree, hf_fragment, tvb, offset,
                                tvb_length_remaining(tvb, offset), ENC_ASCII | ENC_NA);
            reassembled_tvb = tvb_new_child_real_data(tvb, at_data,
                    fragment->index + fragment->length, fragment->index + fragment->length);
            add_new_data_source(pinfo, reassembled_tvb, "Reassembled HSP");
        }

        command_number = 0;
        if (reassembled_tvb) {
            guint reassembled_offset = 0;

            while (tvb_length(reassembled_tvb) > reassembled_offset) {
                reassembled_offset = dissect_at_command(reassembled_tvb,
                        pinfo, main_tree, reassembled_offset, role, command_number);
                command_number += 1;
            }
        } else {
            while (tvb_length(tvb) > (guint) offset) {
                offset = dissect_at_command(tvb, pinfo, main_tree, offset, role, command_number);
                command_number += 1;
            }
        }
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Fragment: %s",
                tvb_format_text_wsp(tvb, offset, tvb_length_remaining(tvb, offset)));
        pitem = proto_tree_add_item(main_tree, hf_fragmented, tvb, 0, 0, ENC_NA);
        PROTO_ITEM_SET_GENERATED(pitem);
        proto_tree_add_item(main_tree, hf_fragment, tvb, offset,
                tvb_length_remaining(tvb, offset), ENC_ASCII | ENC_NA);
    }

    return offset;
}

void
proto_register_bthsp(void)
{
    module_t         *module;
    expert_module_t  *expert_bthsp;

    static hf_register_info hf[] = {
        { &hf_command,
           { "Command",                          "bthsp.command",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_parameters,
           { "Parameters",                       "bthsp.parameters",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_command_in,
           { "Command frame number in",          "bthsp.command_in",
           FT_FRAMENUM, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_unsolicited,
           { "Unsolicited",                      "bthsp.unsolicited",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_data,
           { "AT Stream",                        "bthsp.data",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_fragment,
           { "Fragment",                         "bthsp.fragment",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_fragmented,
           { "Fragmented",                       "bthsp.fragmented",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_ignored,
           { "Ignored",                          "bthsp.ignored",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_cmd,
           { "Command",                          "bthsp.at_cmd",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_cmd_type,
           { "Type",                             "bthsp.at_cmd.type",
           FT_UINT16, BASE_HEX, VALS(at_cmd_type_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_command_line_prefix,
           { "Command Line Prefix",              "bthsp.command_line_prefix",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_parameter,
           { "Parameter",                        "bthsp.parameter",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_unknown_parameter,
           { "Unknown Parameter",                "bthsp.unknown_parameter",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_role,
           { "Role",                             "bthsp.role",
           FT_UINT8, BASE_DEC, VALS(role_vals), 0,
           NULL, HFILL}
        },
        { &hf_vgs,
           { "Gain",                             "bthsp.vgs",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_vgm,
           { "Gain",                             "bthsp.vgm",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_ckpd,
           { "Key",                             "bthsp.ckpd",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        }
    };

    static ei_register_info ei[] = {
        { &ei_non_mandatory_command, { "bthsp.expert.non_mandatory_command", PI_PROTOCOL, PI_NOTE, "Non-mandatory command in HSP", EXPFILL }},
        { &ei_invalid_usage,         { "bthsp.expert.invalid_usage", PI_PROTOCOL, PI_WARN, "Non mandatory type or command in this role", EXPFILL }},
        { &ei_unknown_parameter,     { "bthsp.expert.unknown_parameter", PI_PROTOCOL, PI_WARN, "Unknown parameter", EXPFILL }},
        { &ei_vgm_gain,              { "bthsp.expert.vgm", PI_PROTOCOL, PI_WARN, "Gain of microphone exceeds range 0-15", EXPFILL }},
        { &ei_vgs_gain,              { "bthsp.expert.vgs", PI_PROTOCOL, PI_WARN, "Gain of speaker exceeds range 0-15", EXPFILL }},
        { &ei_ckpd,              { "bthsp.expert.ckpd", PI_PROTOCOL, PI_WARN, "Only key 200 is covered in HSP", EXPFILL }}    };

    static gint *ett[] = {
        &ett_bthsp,
        &ett_bthsp_command,
        &ett_bthsp_parameters
    };

    fragments = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_bthsp = proto_register_protocol("Bluetooth HSP Profile", "BT HSP", "bthsp");
    bthsp_handle = new_register_dissector("bthsp", dissect_bthsp, proto_bthsp);

    proto_register_field_array(proto_bthsp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_bthsp, NULL);
    prefs_register_static_text_preference(module, "hsp.version",
            "Bluetooth Profile HSP version: 1.2",
            "Version of profile supported by this dissector.");

    prefs_register_enum_preference(module, "hsp.hsp_role",
            "Force treat packets as AG or HS role",
            "Force treat packets as AG or HS role",
            &hsp_role, pref_hsp_role, TRUE);

    expert_bthsp = expert_register_protocol(proto_bthsp);
    expert_register_field_array(expert_bthsp, ei, array_length(ei));
}

void
proto_reg_handoff_bthsp(void)
{
    dissector_add_uint("btrfcomm.service", BTSDP_HSP_SERVICE_UUID, bthsp_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_HSP_HS_SERVICE_UUID, bthsp_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_HSP_GW_SERVICE_UUID, bthsp_handle);
    dissector_add_for_decode_as("btrfcomm.channel", bthsp_handle);
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
