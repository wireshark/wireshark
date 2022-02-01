/* packet-tpncp.c
 * Routines for Audiocodes TrunkPack Network Control Protocol (TPNCP) dissection
 *
 * Copyright (c) 2007 by Valery Sigalov <valery.sigalov@audiocodes.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.com>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*---------------------------------------------------------------------------*/

#define WS_LOG_DOMAIN "TPNCP"
#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>
#include <wsutil/strtoi.h>
#include <epan/wmem_scopes.h>
#include "packet-acdr.h"
#include "packet-tcp.h"

/*---------------------------------------------------------------------------*/

#define BASE_TPNCP_PORT 2424
#define HA_PORT_TPNCP_TRUNKPACK 2442
#define TCP_PORT_TPNCP_TRUNKPACK BASE_TPNCP_PORT
#define UDP_PORT_TPNCP_TRUNKPACK BASE_TPNCP_PORT
#define TCP_PORT_TPNCP_HOST BASE_TPNCP_PORT
#define UDP_PORT_TPNCP_HOST BASE_TPNCP_PORT

#define MAX_TPNCP_DB_ENTRY_LEN 3000

#define MAX_TPNCP_DB_SIZE 5000
#define MAX_ENUMS_NUM 1000
#define MAX_ENUM_ENTRIES 1000

/*---------------------------------------------------------------------------*/

void proto_register_tpncp(void);
void proto_reg_handoff_tpncp(void);

enum SpecialFieldType {
    TPNCP_NORMAL,
    TPNCP_ADDRESS_FAMILY,
    TPNCP_IP_ADDR,
    TPNCP_OPEN_CHANNEL_START,
    TPNCP_SECURITY_START,
    TPNCP_SECURITY_OFFSET,
    RTP_STATE_START,
    RTP_STATE_OFFSET,
    RTP_STATE_END,
    TPNCP_CHANNEL_CONFIGURATION
};

/* The linked list for storing information about specific data fields. */
typedef struct tpncp_data_field_info
{
    gchar *name;
    gint   descr;
    gint   ipv6_descr;
    gint   array_dim;
    enum SpecialFieldType special_type;
    guchar size;
    guchar sign;
    gint   since;
    struct tpncp_data_field_info *p_next;
} tpncp_data_field_info;

/*---------------------------------------------------------------------------
 * Desegmentation of TPNCP over TCP */
static gboolean tpncp_desegment = TRUE;

/* Database for storing information about all TPNCP events.
 * XXX: ToDo: allocate at runtime as needed*/
static tpncp_data_field_info tpncp_events_info_db[MAX_TPNCP_DB_SIZE];

/* Database for storing information about all TPNCP commands.
 * XXX: ToDo: allocate at runtime as needed*/
static tpncp_data_field_info tpncp_commands_info_db[MAX_TPNCP_DB_SIZE];

/* Global variables for bitfields representation. */
static gint bits[] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80};

/* TPNCP packet header fields. */
static gint proto_tpncp = -1;
static gint hf_tpncp_version = -1;
static gint hf_tpncp_length = -1;
static gint hf_tpncp_seq_number = -1;
static gint hf_tpncp_length_ext = -1;
static gint hf_tpncp_reserved = -1;
static gint hf_tpncp_command_id = -1;
static gint hf_tpncp_event_id = -1;
static gint hf_tpncp_cid = -1;

static expert_field ei_tpncp_unknown_data = EI_INIT;

/* TPNCP fields defining a subtree. */
static gint ett_tpncp = -1;
static gint ett_tpncp_body = -1;

static gboolean global_tpncp_load_db = FALSE;

static dissector_handle_t tpncp_handle;

/* XXX: ToDo: allocate at runtime as needed
 *      The following allocates something on the order of 2M of static memory !
 *      Also: Runtime value_string_ext arrays should be used*/
static value_string tpncp_commands_id_vals[MAX_TPNCP_DB_SIZE];
static value_string tpncp_events_id_vals[MAX_TPNCP_DB_SIZE];
static value_string tpncp_enums_id_vals[MAX_ENUMS_NUM][MAX_ENUM_ENTRIES];
static gchar *tpncp_enums_name_vals[MAX_ENUMS_NUM];

static gint hf_size = 0;
static gint hf_allocated = 0;
static hf_register_info *hf = NULL;

static gboolean db_initialized = FALSE;

/*---------------------------------------------------------------------------*/

enum AddressFamily {
    TPNCP_IPV4 = 2,
    TPNCP_IPV6 = 10,
    TPNCP_IPV6_PSOS = 28
};

static void
dissect_tpncp_data(guint data_id, packet_info *pinfo, tvbuff_t *tvb, proto_tree *ltree,
                   gint *offset, tpncp_data_field_info *data_fields_info, gint ver, guint encoding)
{
    gint8 g_char;
    guint8 g_uchar;
    gint g_str_len, counter, bitshift, bitmask;
    tpncp_data_field_info *field = NULL;
    gint bitindex = encoding == ENC_LITTLE_ENDIAN ? 7 : 0;
    enum AddressFamily address_family = TPNCP_IPV4;
    gint open_channel_start = -1, security_offset = 0, rtp_state_offset = 0;
    gint channel_b_offset = 0, rtp_tx_state_offset = 0, rtp_state_size = 0;
    const gint initial_offset = *offset;

    for (field = &data_fields_info[data_id]; field; field = field->p_next) {
        if (field->since > 0 && field->since > ver)
            continue;
        switch (field->special_type) {
        case TPNCP_OPEN_CHANNEL_START:
            open_channel_start = *offset;
            break;
        case TPNCP_SECURITY_OFFSET: {
            const guint32 sec_offset = tvb_get_guint32(tvb, *offset, encoding);
            if (sec_offset > 0 && open_channel_start >= 0)
                security_offset = open_channel_start + sec_offset;
            break;
        }
        case TPNCP_SECURITY_START:
            *offset = security_offset;
            open_channel_start = -1;
            security_offset = 0;
            break;
        case RTP_STATE_OFFSET:
            rtp_state_offset = tvb_get_gint32(tvb, *offset, encoding);
            if (rtp_state_offset > 0)
                rtp_state_offset += initial_offset + 4; /* The offset starts after CID */
            break;
        case RTP_STATE_START:
            *offset = rtp_state_offset;
            rtp_state_offset = 0;
            if (rtp_tx_state_offset == 0) {
                rtp_state_size = (tvb_reported_length_remaining(tvb, *offset) - 4) / 2;
                rtp_tx_state_offset = *offset + rtp_state_size;
            } else {
                *offset = rtp_tx_state_offset;
                rtp_tx_state_offset += rtp_state_size;
            }
            break;
        case RTP_STATE_END:
            rtp_tx_state_offset = 0;
            break;
        case TPNCP_CHANNEL_CONFIGURATION:
            if (channel_b_offset == 0) {
                gint channel_configuration_size = tvb_reported_length_remaining(tvb, *offset) / 2;
                channel_b_offset = *offset + channel_configuration_size;
            } else {
                *offset = channel_b_offset;
                channel_b_offset = 0;
            }
            break;
        case TPNCP_ADDRESS_FAMILY:
            address_family = (enum AddressFamily)tvb_get_guint32(tvb, *offset, encoding);
            // fall-through
        default:
            if (open_channel_start != -1 && security_offset > 0 && *offset >= security_offset)
                continue;
            if (rtp_state_offset > 0 && *offset >= rtp_state_offset)
                continue;
            if (rtp_tx_state_offset > 0 && *offset >= rtp_tx_state_offset)
                continue;
            if (channel_b_offset > 0 && *offset >= channel_b_offset)
                continue;
            break;
        }
        switch (field->size) {
        case 1: case 2: case 3: case 4:
        case 5: case 6: case 7: case 8:
            /* add char array */
            if ((g_str_len = field->array_dim)) {
                g_str_len = MIN(g_str_len, tvb_reported_length_remaining(tvb, *offset));
                proto_tree_add_item(ltree, field->descr, tvb, *offset, g_str_len, ENC_NA | ENC_ASCII);
                (*offset) += g_str_len;
            } else { /* add single char */
                g_uchar = tvb_get_guint8(tvb, *offset);

                /* bitfields */

                if (field->size != 8) {
                    for (counter = 0, bitmask = 0x0, bitshift = bitindex;
                         counter < field->size;
                         counter++) {
                        bitmask |= bits[bitindex]; /* Bitmask of interesting bits. */
                        bitindex += encoding == ENC_LITTLE_ENDIAN ? -1 : 1;
                    }
                    g_uchar &= bitmask;
                    g_uchar >>= bitshift;
                }
                if (field->sign || field->size != 8) {
                    proto_tree_add_uint(ltree, field->descr, tvb, *offset, 1, g_uchar);
                } else {
                    /* signed*/
                    g_char = (gint8) g_uchar;
                    proto_tree_add_int(ltree, field->descr, tvb, *offset, 1, g_char);
                }
                if (((bitindex == 0 || bitindex == 8) && encoding == ENC_BIG_ENDIAN) ||
                    ((bitindex == -1 || bitindex == 7) && encoding == ENC_LITTLE_ENDIAN)) {
                    (*offset)++;
                    bitindex = encoding == ENC_LITTLE_ENDIAN ? 7 : 0;
                }
            }
            break;
        case 16:
            proto_tree_add_item(ltree, field->descr, tvb, *offset, 2, encoding);
            (*offset) += 2;
            break;
        case 32:
            proto_tree_add_item(ltree, field->descr, tvb, *offset, 4, encoding);
            (*offset) += 4;
            break;
        case 128:
            if (field->special_type == TPNCP_IP_ADDR) {
                if (address_family == TPNCP_IPV6 || address_family == TPNCP_IPV6_PSOS)
                    proto_tree_add_item(ltree, field->ipv6_descr, tvb, *offset, 16, encoding);
                else
                    proto_tree_add_item(ltree, field->descr, tvb, *offset, 4, encoding);
                address_family = TPNCP_IPV4;
            }
            (*offset) += 16;
            break;
        default:
            break;
        }
        if (tvb_reported_length_remaining(tvb, *offset) <= 0)
            break;
    }
    if ((g_str_len = tvb_reported_length_remaining(tvb, *offset)) > 0) {
        expert_add_info_format(pinfo, ltree, &ei_tpncp_unknown_data, "TPNCP Unknown Data");
        (*offset) += g_str_len;
    }
}

/*---------------------------------------------------------------------------*/
static int
dissect_tpncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item = NULL;
    proto_tree *tpncp_tree = NULL, *event_tree, *command_tree;
    gint offset = 0, cid = -1;
    guint id;
    guint seq_number, len, ver;
    guint len_ext, reserved, encoding;
    guint32 fullLength;

    if (!db_initialized)
        return 0;

    encoding = tvb_get_ntohs(tvb, 8) == 0 ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPNCP");

    item = proto_tree_add_item(tree, proto_tpncp, tvb, 0, -1, ENC_NA);
    tpncp_tree = proto_item_add_subtree(item, ett_tpncp);

    proto_tree_add_item_ret_uint(tpncp_tree, hf_tpncp_version, tvb, 0, 2, encoding, &ver);
    proto_tree_add_item_ret_uint(tpncp_tree, hf_tpncp_length, tvb, 2, 2, encoding, &len);
    proto_tree_add_item_ret_uint(tpncp_tree, hf_tpncp_seq_number, tvb, 4, 2, encoding, &seq_number);
    proto_tree_add_item_ret_uint(tpncp_tree, hf_tpncp_length_ext, tvb, 6, 1, encoding, &len_ext);
    proto_tree_add_item_ret_uint(tpncp_tree, hf_tpncp_reserved, tvb, 7, 1, encoding, &reserved);
    fullLength = 0xffff * len_ext + len;

    id = tvb_get_guint32(tvb, 8, encoding);
    if (len > 8)
        cid = tvb_get_gint32(tvb, 12, encoding);
    if (pinfo->srcport == UDP_PORT_TPNCP_TRUNKPACK ||
        pinfo->srcport == HA_PORT_TPNCP_TRUNKPACK) {
        if (try_val_to_str(id, tpncp_events_id_vals)) {
            proto_tree_add_uint(tpncp_tree, hf_tpncp_event_id, tvb, 8, 4, id);
            if (len > 8)
                proto_tree_add_int(tpncp_tree, hf_tpncp_cid, tvb, 12, 4, cid);
            offset += 16;
            if (tpncp_events_info_db[id].size && len > 12) {
                event_tree = proto_tree_add_subtree_format(
                    tree, tvb, offset, -1, ett_tpncp_body, NULL,
                    "TPNCP Event: %s (%d)",
                    val_to_str_const(id, tpncp_events_id_vals, "Unknown"), id);
                dissect_tpncp_data(id, pinfo, tvb, event_tree, &offset, tpncp_events_info_db,
                                   ver, encoding);
            }
        }
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "EvID=%s(%d), SeqNo=%d, CID=%d, Len=%d, Ver=%d",
                     val_to_str_const(id, tpncp_events_id_vals, "Unknown"),
                     id, seq_number, cid, fullLength, ver);
    } else {
        if (try_val_to_str(id, tpncp_commands_id_vals)) {
            proto_tree_add_uint(tpncp_tree, hf_tpncp_command_id, tvb, 8, 4, id);
            offset += 12;
            if (tpncp_commands_info_db[id].size && len > 8) {
                command_tree = proto_tree_add_subtree_format(
                    tree, tvb, offset, -1, ett_tpncp_body, NULL,
                    "TPNCP Command: %s (%d)",
                    val_to_str_const(id, tpncp_commands_id_vals, "Unknown"), id);
                dissect_tpncp_data(id, pinfo, tvb, command_tree, &offset, tpncp_commands_info_db,
                                   ver, encoding);
            }
        }
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "CmdID=%s(%d), SeqNo=%d, CID=%d, Len=%d, Ver=%d",
                     val_to_str_const(id, tpncp_commands_id_vals, "Unknown"),
                     id, seq_number, cid, fullLength, ver);
    }

    return tvb_reported_length(tvb);
}

/*---------------------------------------------------------------------------*/

static guint
get_tpncp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint32 plen;

    /* Get the length of the TPNCP packet. */
    plen = tvb_get_ntohs(tvb, offset + 2) + 0xffff * tvb_get_guint8(tvb, offset + 6);

    /* Length does not include the version+length field. */
    plen += 4;

    return plen;
}

/*---------------------------------------------------------------------------*/

static int
dissect_tpncp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!db_initialized)
        return 0;

    if (pinfo->can_desegment)
        /* If desegmentation is enabled (TCP preferences) use the desegmentation API. */
        tcp_dissect_pdus(tvb, pinfo, tree, tpncp_desegment, 4, get_tpncp_pdu_len,
                         dissect_tpncp, data);
    else
        /* Otherwise use the regular dissector (might not give correct dissection). */
        dissect_tpncp(tvb, pinfo, tree, data);

    return tvb_reported_length(tvb);
}

static int
dissect_acdr_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int res = 0;
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;
    guint32 orig_port = pinfo->srcport;

    if (acdr_data == NULL)
        return 0;

    // only on version 2+ events are sent with TPNCP header that enables using tpncp parser
    if (acdr_data->version <= 1)
        return 0;

    // the TPNCP dissector uses the following statement to
    // differentiate command from event:
    // if (pinfo->srcport == UDP_PORT_TPNCP_TRUNKPACK) -> Event
    // so for proper dissection we want to imitate this behaviour
    pinfo->srcport = UDP_PORT_TPNCP_TRUNKPACK;
    res = dissect_tpncp(tvb, pinfo, tree, NULL);
    pinfo->srcport = orig_port;
    return res;
}

static int
dissect_acdr_tpncp_by_tracepoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;
    guint32 orig_port = pinfo->srcport;
    int res = 0;

    if (acdr_data == NULL)
        return 0;

    // the TPNCP dissector uses the following statement to
    // differentiate command from event:
    // if (pinfo->srcport == UDP_PORT_TPNCP_TRUNKPACK) -> Event
    // so for proper dissection we want to imitate this behaviour

    if (acdr_data->trace_point == Host2Net) // event
        pinfo->srcport = UDP_PORT_TPNCP_TRUNKPACK;
    else // Net2Host ->command
        pinfo->srcport = UDP_PORT_TPNCP_TRUNKPACK + 1;

    res = dissect_tpncp(tvb, pinfo, tree, NULL);
    pinfo->srcport = orig_port;
    return res;
}

/*---------------------------------------------------------------------------*/

static gboolean
fgetline(gchar *buffer, int size, FILE *file)
{
    if (!fgets(buffer, size, file))
        return 0;
    size_t last = strlen(buffer);
    if (buffer[last - 1] == '\n')
        buffer[last - 1] = 0;
    return 1;
}

static gint
fill_tpncp_id_vals(value_string string[], FILE *file)
{
    gint i = 0, tpncp_id = 0;
    gchar *tpncp_name, *line_in_file;

    if (file == NULL) return -1;

    line_in_file = (gchar *) g_malloc(MAX_TPNCP_DB_ENTRY_LEN);
    line_in_file[0] = 0;
    tpncp_name = (gchar *) g_malloc(MAX_TPNCP_DB_ENTRY_LEN);
    tpncp_name[0] = 0;

    while (fgetline(line_in_file, MAX_TPNCP_DB_ENTRY_LEN, file) && !feof(file)) {
        if (!strncmp(line_in_file, "#####", 5))
            break;
        if (sscanf(line_in_file, "%255s %d", tpncp_name, &tpncp_id) == 2) {
            string[i].strptr = wmem_strdup(wmem_epan_scope(), tpncp_name);
            string[i].value = (guint32) tpncp_id;
            if (i >= MAX_TPNCP_DB_SIZE - 1)
                break;
            i++;
        }
    }

    g_free(line_in_file);
    g_free(tpncp_name);

    return 0;
}

/*---------------------------------------------------------------------------*/

static gint
fill_enums_id_vals(FILE *file)
{
    gint i = 0, enum_id = 0, enum_val = 0;
    gboolean first_entry = TRUE;
    gchar *line_in_file = NULL, *enum_name = NULL, *enum_type = NULL, *enum_str = NULL;

    line_in_file = (gchar *) g_malloc(MAX_TPNCP_DB_ENTRY_LEN);
    enum_name = (gchar *) g_malloc(MAX_TPNCP_DB_ENTRY_LEN);
    enum_type = (gchar *) g_malloc(MAX_TPNCP_DB_ENTRY_LEN);
    enum_str = (gchar *) g_malloc(MAX_TPNCP_DB_ENTRY_LEN);

    *line_in_file = *enum_name = *enum_type = *enum_str = 0;
    while (fgetline(line_in_file, MAX_TPNCP_DB_ENTRY_LEN, file)) {
        if (!strncmp(line_in_file, "#####", 5))
            break;
        if (sscanf(line_in_file, "%255s %255s %d", enum_name, enum_str, &enum_id) == 3) {
            if (strcmp(enum_type, enum_name)) {
                if (!first_entry) {
                    tpncp_enums_id_vals[enum_val][i].strptr = NULL;
                    tpncp_enums_id_vals[enum_val][i].value = 0;
                    if (enum_val < (MAX_ENUMS_NUM - 2)) {
                        enum_val++; i = 0;
                    } else {
                        break;
                    }
                } else {
                    first_entry = FALSE;
                }
                tpncp_enums_name_vals[enum_val] = wmem_strdup(wmem_epan_scope(), enum_name);
                (void) g_strlcpy(enum_type, enum_name, MAX_TPNCP_DB_ENTRY_LEN);
            }
            tpncp_enums_id_vals[enum_val][i].strptr = wmem_strdup(wmem_epan_scope(), enum_str);
            tpncp_enums_id_vals[enum_val][i].value = enum_id;
            if (i < (MAX_ENUM_ENTRIES - 1)) {
                i++;
            } else {
                break;
            }
        }
    }

    tpncp_enums_name_vals[enum_val + 1] = NULL;

    g_free(line_in_file);
    g_free(enum_name);
    g_free(enum_type);
    g_free(enum_str);

    return 0;
}

/*---------------------------------------------------------------------------*/

static gint
get_enum_name_val(const gchar *enum_name)
{
    gint enum_val = 0;

    while (tpncp_enums_name_vals[enum_val]) {
        if (!strcmp(enum_name, tpncp_enums_name_vals[enum_val]))
            return enum_val;
        enum_val++;
    }

    return -1;
}

/*---------------------------------------------------------------------------*/

static gboolean add_hf(hf_register_info *hf_entr)
{
    if (hf_size >= hf_allocated) {
        void *newbuf;
        hf_allocated += 1024;
        newbuf = wmem_realloc(wmem_epan_scope(), hf, hf_allocated * sizeof (hf_register_info));
        if (!newbuf)
            return FALSE;
        hf = (hf_register_info *) newbuf;
    }
    memcpy(hf + hf_size, hf_entr, sizeof (hf_register_info));
    hf_size++;
    return TRUE;
}

static gint
init_tpncp_data_fields_info(tpncp_data_field_info *data_fields_info, FILE *file)
{
    static gboolean was_registered = FALSE;
    gchar tpncp_db_entry[MAX_TPNCP_DB_ENTRY_LEN];
    gchar entry_copy[MAX_TPNCP_DB_ENTRY_LEN];
    const gchar *name = NULL, *tmp = NULL;
    gint enum_val, data_id, current_data_id = -1, array_dim;
    guchar size;
    enum SpecialFieldType special_type;
    gboolean sign, is_address_family;
    guint idx, since, ip_addr_field;
    tpncp_data_field_info *field = NULL;
    hf_register_info hf_entr;
    gboolean* registered_struct_ids = wmem_alloc0_array(wmem_epan_scope(), gboolean, MAX_TPNCP_DB_SIZE);

    static hf_register_info hf_tpncp[] = {
        {
            &hf_tpncp_version,
            {
                "Version",
                "tpncp.version",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_tpncp_length,
            {
                "Length",
                "tpncp.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_tpncp_seq_number,
            {
                "Sequence number",
                "tpncp.seq_number",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_tpncp_length_ext,
            {
                "Length Extension",
                "tpncp.lengthextension",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_tpncp_reserved,
            {
                "Reserved",
                "tpncp.reserved",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_tpncp_command_id,
            {
                "Command ID",
                "tpncp.command_id",
                FT_UINT32,
                BASE_DEC,
                VALS(tpncp_commands_id_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_tpncp_event_id,
            {
                "Event ID",
                "tpncp.event_id",
                FT_UINT32,
                BASE_DEC,
                VALS(tpncp_events_id_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_tpncp_cid,
            {
                "Channel ID",
                "tpncp.channel_id",
                FT_INT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        }
    };

    /* Register common fields of hf_register_info structure. */
    hf_entr.hfinfo.type = FT_NONE;
    hf_entr.hfinfo.strings = NULL;
    hf_entr.hfinfo.bitmask = 0x0;
    hf_entr.hfinfo.blurb = NULL;
    HFILL_INIT(hf_entr);

    if (!was_registered) {
        void *newbuf;

        /* Register non-standard data should be done only once. */
        hf_allocated = hf_size + (int) array_length(hf_tpncp);
        newbuf = wmem_realloc(wmem_epan_scope(), hf, hf_allocated * sizeof (hf_register_info));
        if (!newbuf)
            return -1;
        hf = (hf_register_info *) newbuf;
        for (idx = 0; idx < array_length(hf_tpncp); idx++) {
            memcpy(hf + hf_size, hf_tpncp + idx, sizeof (hf_register_info));
            hf_size++;
        }
        was_registered = TRUE;
    }

    is_address_family = FALSE;
    ip_addr_field = 0;

    /* Register standard data. */
    while (fgetline(tpncp_db_entry, MAX_TPNCP_DB_ENTRY_LEN, file)) {
        special_type = TPNCP_NORMAL;
        since = 0;
        snprintf(entry_copy, MAX_TPNCP_DB_ENTRY_LEN, "%s", tpncp_db_entry);
        if (!strncmp(tpncp_db_entry, "#####", 5))
            break;

        /* Default to decimal display type */
        hf_entr.hfinfo.display = BASE_DEC;
        if ((tmp = strtok(tpncp_db_entry, " ")) == NULL) {
            report_failure(
                "ERROR! Badly formed data base entry: %s - corresponding field's registration is skipped.",
                entry_copy);
            continue;
        }
        data_id = (gint) g_ascii_strtoll(tmp, NULL, 10);
        if ((name = strtok(NULL, " ")) == NULL) {
            report_failure(
                "ERROR! Badly formed data base entry: %s - corresponding field's registration is skipped.",
                entry_copy);
            continue;
        }

        /* We happen to have a line without a name (57 0 32 0 0 primitive). Consider unnamed. */
        if (g_ascii_isdigit(*name)) {
            tmp = name;
            name = "unnamed";
        } else {
            if ((tmp = strtok(NULL, " ")) == NULL) {
                report_failure(
                    "ERROR! Badly formed data base entry: %s - corresponding field's registration is skipped.",
                    entry_copy);
                continue;
            }
        }
        if (name[0] == 'c' && !strcmp(name, "cmd_rev_lsb"))
            special_type = TPNCP_OPEN_CHANNEL_START;
        else if (name[0] == 'r' && !strcmp(name, "rtp_authentication_algorithm"))
            special_type = TPNCP_SECURITY_START;
        else if (name[0] == 's' && !strcmp(name, "security_cmd_offset"))
            special_type = TPNCP_SECURITY_OFFSET;
        else if (data_id != 1611 && name[0] == 's' && !strcmp(name, "ssrc"))
            special_type = RTP_STATE_START;
        else if (name[0] == 'r' && !strcmp(name, "rtp_tx_state_ssrc"))
            special_type = RTP_STATE_START;
        else if (name[0] == 'r' && !strcmp(name, "rtp_state_offset"))
            special_type = RTP_STATE_OFFSET;
        else if (name[0] == 's' && !strcmp(name, "state_update_time_stamp"))
            special_type = RTP_STATE_END;
        else if (data_id == 1611 && name[0] == 'c' && strstr(name, "configuration_type_updated"))
            special_type = TPNCP_CHANNEL_CONFIGURATION;
        else if ((data_id == 4 && strstr(name, "secondary_rtp_seq_num")) ||
                 (data_id == 1611 && strstr(name, "dtls_remote_fingerprint_alg"))) {
            since = 7401;
        }
        sign = !!((gboolean) g_ascii_strtoll(tmp, NULL, 10));
        if ((tmp = strtok(NULL, " ")) == NULL) {
            report_failure(
                "ERROR! Badly formed data base entry: %s - corresponding field's registration is skipped.",
                entry_copy);
            continue;
        }
        size = (guchar) g_ascii_strtoll(tmp, NULL, 10);
        if ((tmp = strtok(NULL, " ")) == NULL) {
            report_failure(
                "ERROR! Badly formed data base entry: %s - corresponding field's registration is skipped.",
                entry_copy);
            continue;
        }
        array_dim = (gint) g_ascii_strtoll(tmp, NULL, 10);
        if ((tmp = strtok(NULL, " ")) == NULL) {
            report_failure(
                "ERROR! Badly formed data base entry: %s - corresponding field's registration is skipped.",
                entry_copy);
            continue;
        }
        if (sign && g_ascii_strtoll(tmp, NULL, 10))
            special_type = TPNCP_IP_ADDR;
        if ((tmp = strtok(NULL, "\n")) == NULL) {
            report_failure(
                "ERROR! Badly formed data base entry: %s - corresponding field's registration is skipped.",
                entry_copy);
            continue;
        }

        if (ip_addr_field > 0) {
            // ip address that comes after address family has 4 fields: ip_addr_0, ip_addr_1, 2 and 3
            // On these cases, ignore 1, 2 and 3 and enlarge the field size of 0 to 128
            char *seq = (char*)name + strlen(name) - 2;
            --ip_addr_field;
            if (seq > name && *seq == '_') {
                if (seq[1] >= '1' && seq[1] <= '3')
                    continue;
                // relates to the *previous* field
                if (is_address_family) {
                    *seq = 0;
                    size = 128;
                    special_type = TPNCP_IP_ADDR;
                } else {
                    report_warning("Bad address form. Field name: %s", name);
                    ip_addr_field = 0;
                }
            }
        }

        is_address_family = FALSE;
        if (current_data_id != data_id) { /* new data */
            if (registered_struct_ids[data_id] == TRUE) {
                report_failure(
                    "ERROR! The data_id %d already registered. Cannot register two identical events/command",
                    data_id);
                continue;
            }
            registered_struct_ids[data_id] = TRUE;
            field = &data_fields_info[data_id];
            current_data_id = data_id;
        } else {
            field->p_next = wmem_new(wmem_epan_scope(), tpncp_data_field_info);
            if (!field->p_next)
                return (-1);
            field = field->p_next;
            field->p_next = NULL;
        }

        /* Register specific fields of hf_register_info struture. */
        if (strcmp(tmp, "primitive")) {
            enum_val = get_enum_name_val(tmp);
            if (enum_val == -1) {
                hf_entr.hfinfo.strings = NULL;
            } else {
                hf_entr.hfinfo.strings = VALS(tpncp_enums_id_vals[enum_val]);
                if (!strcmp(tmp, "AddressFamily")) {
                    is_address_family = TRUE;
                    ip_addr_field = 4;
                }
            }
        } else {
            hf_entr.hfinfo.strings = NULL;
        }
        field->descr = -1;
        field->ipv6_descr = -1;
        hf_entr.p_id = &field->descr;
        field->name = wmem_strdup_printf(wmem_epan_scope(), "tpncp.%s", name);
        hf_entr.hfinfo.name = field->name;
        hf_entr.hfinfo.abbrev = field->name;
        switch (size) {
        case 1: case 2: case 3: case 4:
        case 5: case 6: case 7: case 8:
            if (array_dim) {
                hf_entr.hfinfo.type = FT_STRING;
                hf_entr.hfinfo.display = BASE_NONE;
            } else {
                hf_entr.hfinfo.type = (sign) ? FT_UINT8 : FT_INT8;
            }
            break;
        case 16:
            hf_entr.hfinfo.type = (sign) ? FT_UINT16 : FT_INT16;
            break;
        case 32:
            if (special_type == TPNCP_IP_ADDR) {
                hf_entr.hfinfo.display = BASE_NONE;
                hf_entr.hfinfo.type = FT_IPv4;
            } else {
                hf_entr.hfinfo.type = (sign) ? FT_UINT32 : FT_INT32;
            }
            break;
        case 128:
            if (special_type == TPNCP_IP_ADDR) {
                hf_entr.hfinfo.display = BASE_NONE;
                hf_entr.hfinfo.type = FT_IPv4;
                if (!add_hf(&hf_entr))
                    return -1;
                hf_entr.p_id = &field->ipv6_descr;
                hf_entr.hfinfo.type = FT_IPv6;
            }
            break;
        default:
            break;
        }

        /* Register initialized hf_register_info in global database. */
        if (!add_hf(&hf_entr))
            return -1;
        field->sign = sign;
        field->size = size;
        field->array_dim = array_dim;
        field->special_type = is_address_family ? TPNCP_ADDRESS_FAMILY : special_type;
        field->since = since;
    }

    return 0;
}

/*---------------------------------------------------------------------------*/

static gint
init_tpncp_db(void)
{
    gchar tpncp_dat_file_path[MAX_TPNCP_DB_ENTRY_LEN];
    FILE *file;

    snprintf(tpncp_dat_file_path, MAX_TPNCP_DB_ENTRY_LEN,
               "%s" G_DIR_SEPARATOR_S "tpncp" G_DIR_SEPARATOR_S "tpncp.dat", get_datafile_dir());

    /* Open file with TPNCP data. */
    if ((file = ws_fopen(tpncp_dat_file_path, "r")) == NULL)
        return (-1);
    fill_tpncp_id_vals(tpncp_events_id_vals, file);
    fill_tpncp_id_vals(tpncp_commands_id_vals, file);
    fill_enums_id_vals(file);
    init_tpncp_data_fields_info(tpncp_events_info_db, file);
    init_tpncp_data_fields_info(tpncp_commands_info_db, file);

    fclose(file);
    return 0;
}

/*---------------------------------------------------------------------------*/

void
proto_reg_handoff_tpncp(void)
{
    static gboolean initialized = FALSE;

    if (proto_tpncp == -1) return;

    if (!initialized) {
        dissector_handle_t tpncp_udp_handle = create_dissector_handle(dissect_tpncp, proto_tpncp);
        dissector_handle_t tpncp_tcp_handle = create_dissector_handle(dissect_tpncp_tcp, proto_tpncp);
        dissector_add_uint_with_preference("udp.port", UDP_PORT_TPNCP_TRUNKPACK, tpncp_udp_handle);
        dissector_add_uint_with_preference("tcp.port", TCP_PORT_TPNCP_TRUNKPACK, tpncp_tcp_handle);
        dissector_add_uint("acdr.media_type", ACDR_PCIIF_COMMAND, tpncp_udp_handle);
        dissector_add_uint("acdr.media_type", ACDR_COMMAND, tpncp_udp_handle);
        dissector_add_uint("acdr.media_type", ACDR_Event, create_dissector_handle(dissect_acdr_event, -1));
        dissector_add_uint("acdr.media_type", ACDR_TPNCP,
                           create_dissector_handle(dissect_acdr_tpncp_by_tracepoint, -1));
        dissector_add_uint("acdr.tls_application", TLS_APP_TPNCP, tpncp_udp_handle);
        initialized = TRUE;
    }
    /*  If we weren't able to load the database (and thus the hf_ entries)
     *  do not attach to any ports (if we did then we'd get a "dissector bug"
     *  assertions every time a packet is handed to us and we tried to use the
     *  hf_ entry).
     */
    if (!global_tpncp_load_db)
        return;

    if (hf_allocated == 0 && init_tpncp_db() == -1) {
        report_failure("tpncp: Could not load tpncp.dat file, tpncp dissector will not work");
        return;
    }

    if (db_initialized)
        return;

    /* Rather than duplicating large quantities of code from
     * proto_register_field_array() and friends to sanitize the tpncp.dat file
     * when we read it, just catch any exceptions we get while registering and
     * take them as a hint that the file is corrupt. Then move on, so that at
     * least the rest of the protocol dissectors will still work.
     */
    TRY {
        gint idx;
        /* The function proto_register_field_array does not work with dynamic
         * arrays, so pass dynamic array elements one-by-one in the loop.
         */
        for (idx = 0; idx < hf_size; idx++)
            proto_register_field_array(proto_tpncp, &hf[idx], 1);
    }

    CATCH_ALL {
        report_failure("Corrupt tpncp.dat file, tpncp dissector will not work.");
    }

    ENDTRY;
    db_initialized = TRUE;
}

/*---------------------------------------------------------------------------*/

void
proto_register_tpncp(void)
{
    module_t *tpncp_module;
    expert_module_t* expert_tpncp;
    static gint *ett[] = {
        &ett_tpncp,
        &ett_tpncp_body
    };

    static ei_register_info ei[] = {
        { &ei_tpncp_unknown_data, { "tpncp.unknown_data", PI_UNDECODED, PI_WARN, "Unknown data", EXPFILL } },
    };

    /* this dissector reads hf entries from a database
     * a boolean preference defines whether the database is loaded or not
     * we initialize the hf array in the handoff function when we have
     * access to the preference's value */

    proto_tpncp = proto_register_protocol("AudioCodes TPNCP (TrunkPack Network Control Protocol)",
                                          "TPNCP", "tpncp");

    tpncp_handle = register_dissector("tpncp", dissect_tpncp, proto_tpncp);

    tpncp_module = prefs_register_protocol(proto_tpncp, proto_reg_handoff_tpncp);

    proto_register_subtree_array(ett, array_length(ett));

    expert_tpncp = expert_register_protocol(proto_tpncp);
    expert_register_field_array(expert_tpncp, ei, array_length(ei));

    /* See https://gitlab.com/wireshark/wireshark/-/issues/9569 for some discussion on this as well */
    prefs_register_bool_preference(tpncp_module, "load_db",
                                   "Whether to load DB or not; if DB not loaded dissector is passive",
                                   "Whether to load the Database or not; not loading the DB"
                                   " disables the protocol; Wireshark has to be restarted for the"
                                   " setting to take effect.",
                                   &global_tpncp_load_db);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
