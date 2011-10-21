/* packet-tpncp.c
 * Routines for Audiocodes TrunkPack Network Control Protocol (TPNCP) dissection
 *
 * Copyright (c) 2007 by Valery Sigalov <valery.sigalov@audiocodes.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <wsutil/file_util.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/filesystem.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/strutil.h>

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

#define BASE_TPNCP_PORT 2424
#define TCP_PORT_TPNCP_TRUNKPACK BASE_TPNCP_PORT
#define UDP_PORT_TPNCP_TRUNKPACK BASE_TPNCP_PORT
#define TCP_PORT_TPNCP_HOST BASE_TPNCP_PORT
#define UDP_PORT_TPNCP_HOST BASE_TPNCP_PORT

#define BASE_TPNCP_DATA_LEN 256
#define MAX_TPNCP_DB_ENTRY_LEN BASE_TPNCP_DATA_LEN

#define MAX_TPNCP_DB_SIZE 3000
#define MAX_ENUMS_NUM 500
#define MAX_ENUM_ENTRIES 500

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

/* The linked list for storing information about specific data fields. */
typedef struct tpncp_data_field_info
{
    gchar *tpncp_data_field_name;
    gint tpncp_data_field_descr;
    gint tpncp_data_field_sign;
    gint tpncp_data_field_size;
    gint tpncp_data_field_array_dim;
    gint tpncp_data_field_is_ip_addr;
    struct tpncp_data_field_info *p_next;
} tpncp_data_field_info;

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

/* Desegmentation of TPNCP over TCP */
static gboolean tpncp_desegment = TRUE;

/* Database for storing information about all TPNCP events. */
/* XXX: ToDo: allocate at runtime as needed */
static tpncp_data_field_info tpncp_events_info_db[MAX_TPNCP_DB_SIZE];

/* Database for storing information about all TPNCP commands. */
/* XXX: ToDo: allocate at runtime as needed */
static tpncp_data_field_info tpncp_commands_info_db[MAX_TPNCP_DB_SIZE];

/* Global variables for bitfields representation. */
static gint bits[] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80};
static gint bitindex = 0;

/* TPNCP packet header fields. */
static gint proto_tpncp = -1,
            hf_tpncp_version = -1,
            hf_tpncp_length = -1,
            hf_tpncp_seq_number = -1,
            hf_tpncp_old_event_seq_number = -1,
            hf_tpncp_reserved = -1,
            hf_tpncp_command_id = -1,
            hf_tpncp_old_command_id = -1,
            hf_tpncp_event_id = -1,
            hf_tpncp_cid = -1;

/* TPNCP fields defining a subtree. */
static gint ett_tpncp = -1,
            ett_tpncp_body = -1;

static guint global_tpncp_trunkpack_tcp_port = TCP_PORT_TPNCP_TRUNKPACK,
             global_tpncp_trunkpack_udp_port = UDP_PORT_TPNCP_TRUNKPACK,
             global_tpncp_host_tcp_port = TCP_PORT_TPNCP_HOST,
             global_tpncp_host_udp_port = UDP_PORT_TPNCP_HOST;

static guint trunkpack_tcp_port = 0,
             trunkpack_udp_port = 0,
             host_tcp_port = 0,
             host_udp_port = 0;

/* XXX: ToDo: allocate at runtime as needed */
/*      The following allocates something on the order of 2M of static memory ! */
/*      Also: Runtime value_string_ext arrays should be used                    */
static value_string tpncp_commands_id_vals[MAX_TPNCP_DB_SIZE];
static value_string tpncp_events_id_vals[MAX_TPNCP_DB_SIZE];
static value_string tpncp_enums_id_vals[MAX_ENUMS_NUM][MAX_ENUM_ENTRIES];
static gchar *tpncp_enums_name_vals[MAX_ENUMS_NUM];

static gint hf_size = 1;
static gint hf_allocated = 0;
static hf_register_info *hf = NULL;

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static void dissect_tpncp_data(gint data_id, tvbuff_t *tvb, proto_item *item,
                               gint *offset, tpncp_data_field_info *data_fields_info) {
    proto_tree *ltree = NULL;
    proto_item *pi = NULL;
    gint32 g_int;
    gint16 g_short;
    guint16 g_ushort;
    gint8 g_char;
    gchar *g_str = NULL;
    gint g_str_len, counter, bitshift, bitmask;
    tpncp_data_field_info *current_tpncp_data_field_info = NULL;

    ltree = proto_item_add_subtree(item, ett_tpncp_body);
    current_tpncp_data_field_info = &data_fields_info[data_id];

    while (current_tpncp_data_field_info) {
        switch(current_tpncp_data_field_info->tpncp_data_field_size) {
            case 1: case 2: case 3: case 4:
            case 5: case 6: case 7: case 8:
                if ((g_str_len = current_tpncp_data_field_info->tpncp_data_field_array_dim)) { /* add char array */
                    g_str_len = MIN(g_str_len, tvb_length_remaining(tvb, *offset));
                    g_str = g_malloc(g_str_len);
                    tvb_memcpy(tvb, g_str, *offset, g_str_len);
                    g_str[g_str_len-1] = '\0';
                    proto_tree_add_string(ltree, current_tpncp_data_field_info->tpncp_data_field_descr,
                                          tvb, *offset, g_str_len, g_str);
                    (*offset) += g_str_len;
                    g_free(g_str);
                }
                else { /* add single char */
                    g_char = tvb_get_guint8(tvb, *offset);
                    /* bitfields */
                    if (current_tpncp_data_field_info->tpncp_data_field_size != 8) {
                        for (counter = 0, bitmask = 0x0, bitshift = bitindex;
                             counter < current_tpncp_data_field_info->tpncp_data_field_size;
                             counter++)
                            bitmask |= bits[bitindex++]; /* Bitmask of interesting bits. */
                        g_char &= bitmask;
                        g_char >>= bitshift;
                    }
                    if (current_tpncp_data_field_info->tpncp_data_field_sign) {
                        proto_tree_add_uint(ltree, current_tpncp_data_field_info->tpncp_data_field_descr,
                                            tvb, *offset, 1, g_char);
                    }
                    else {
                        proto_tree_add_int(ltree, current_tpncp_data_field_info->tpncp_data_field_descr,
                                           tvb, *offset, 1, g_char);
                    }
                    if ((bitindex == 0) || (bitindex == 8)) {
                        (*offset)++;
                        bitindex = 0;
                    }
                }
                break;
            case 16:
                if (current_tpncp_data_field_info->tpncp_data_field_sign) {
                    g_ushort = tvb_get_ntohs(tvb, *offset);
                    proto_tree_add_uint(ltree, current_tpncp_data_field_info->tpncp_data_field_descr,
                                        tvb, *offset, 2, g_ushort);
                }
                else {
                    g_short = tvb_get_ntohs(tvb, *offset);
                    proto_tree_add_int(ltree, current_tpncp_data_field_info->tpncp_data_field_descr,
                                       tvb, *offset, 2, g_short);
                }
                (*offset) += 2;
                break;
            case 32:
                g_int = tvb_get_ntohl(tvb, *offset);
                if (current_tpncp_data_field_info->tpncp_data_field_sign) {
                    pi = proto_tree_add_uint(ltree, current_tpncp_data_field_info->tpncp_data_field_descr,
                                             tvb, *offset, 4, g_int);
                }
                else {
                    pi = proto_tree_add_int(ltree, current_tpncp_data_field_info->tpncp_data_field_descr,
                                            tvb, *offset, 4, g_int);
                }
                /* Add string representation for ip_address's field (if needed). */
                if (current_tpncp_data_field_info->tpncp_data_field_is_ip_addr) {
                    proto_item_append_text(pi, " (%s)", tvb_ip_to_str(tvb, *offset));
                }
                (*offset) += 4;
                break;
            default:
                break;
        }
        current_tpncp_data_field_info = current_tpncp_data_field_info->p_next;
        if (tvb_length_remaining(tvb, *offset) <= 0) {
            break;
        }
    }
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static void dissect_tpncp_event(gint event_id, tvbuff_t *tvb,
                                proto_item *item, gint *offset) {
    switch (event_id) {
        /* Place non-standard events here. */
        default:
            dissect_tpncp_data(event_id, tvb, item, offset, tpncp_events_info_db);
            break;
    }
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static void dissect_tpncp_command(gint command_id, tvbuff_t *tvb,
                                  proto_item *item, gint *offset) {
    switch (command_id) {
        /* Place non-standard commands here. */
        default:
            dissect_tpncp_data(command_id, tvb, item, offset, tpncp_commands_info_db);
            break;
    }
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static void dissect_tpncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    proto_item *item = NULL, *tpncp_item = NULL;
    proto_tree *tpncp_tree = NULL;
    gint offset = 0;
    guint32 id, cid = 0;
    guint16 seq_number, len, ver, reserved;
    gchar *tpncp_header;

    ver = tvb_get_ntohs(tvb, 0);
    len = tvb_get_ntohs(tvb, 2);
    seq_number = tvb_get_ntohs(tvb, 4);
    reserved = tvb_get_ntohs(tvb, 6);
    id = tvb_get_ntohl(tvb, 8);

    if (pinfo->srcport == UDP_PORT_TPNCP_TRUNKPACK) /* Event */
        cid = tvb_get_ntohl(tvb, 12 );

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPNCP");

    if (check_col(pinfo->cinfo, COL_INFO)) {
        if (pinfo->srcport == UDP_PORT_TPNCP_TRUNKPACK) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "EvID=%s(%d), SeqNo=%d, ChID=%d, Len=%d, Ver=%d",
                         val_to_str(id, tpncp_events_id_vals, "Unknown"),
                         id, seq_number, cid, len, ver);
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "CmdID=%s(%d), SeqNo=%d, Len=%d, Ver=%d",
                         val_to_str(id, tpncp_commands_id_vals, "Unknown"),
                         id, seq_number, len, ver);
        }
    }

    if (tree) {
        item = proto_tree_add_item(tree, proto_tpncp, tvb, 0, -1, ENC_NA);
        tpncp_tree = proto_item_add_subtree(item, ett_tpncp);

        proto_tree_add_uint(tpncp_tree, hf_tpncp_version, tvb, 0, 2, ver);
        proto_tree_add_uint(tpncp_tree, hf_tpncp_length, tvb, 2, 2, len);
        proto_tree_add_uint(tpncp_tree, hf_tpncp_seq_number, tvb, 4, 2, seq_number);
        proto_tree_add_uint(tpncp_tree, hf_tpncp_reserved, tvb, 6, 2, reserved);

        if (pinfo->srcport == UDP_PORT_TPNCP_TRUNKPACK) {
            if (match_strval(id, tpncp_events_id_vals)) {
                proto_tree_add_uint(tpncp_tree, hf_tpncp_event_id, tvb, 8, 4, id);
                proto_tree_add_int(tpncp_tree, hf_tpncp_cid, tvb, 12, 4, cid);
                offset += 16;
                if (tpncp_events_info_db[id].tpncp_data_field_size) {
                    tpncp_header = ep_strdup_printf("TPNCP Event: %s (%d)", val_to_str(id, tpncp_events_id_vals, "Unknown"), id);
                    tpncp_item = proto_tree_add_text(tree, tvb, offset, -1, "%s", tpncp_header);
                    dissect_tpncp_event(id, tvb, tpncp_item, &offset);
                }
            }
        }
        else {
            if (match_strval(id, tpncp_commands_id_vals)) {
                proto_tree_add_uint(tpncp_tree, hf_tpncp_command_id, tvb, 8, 4, id);
                offset += 12;
                if (tpncp_commands_info_db[id].tpncp_data_field_size) {
                    tpncp_header = ep_strdup_printf("TPNCP Command: %s (%d)", val_to_str(id, tpncp_commands_id_vals, "Unknown"), id);
                    tpncp_item = proto_tree_add_text(tree, tvb, offset, -1, "%s", tpncp_header);
                    dissect_tpncp_command(id, tvb, tpncp_item, &offset);
                }
            }
        }
    }
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static guint get_tpncp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, gint offset) {
  guint16 plen;

  /* Get the length of the DNS packet. */
  plen = tvb_get_ntohs(tvb, offset + 2);
  /* Length does not include the version+length field. */
  plen += 4;

  return plen;
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static void dissect_tpncp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    if (pinfo->can_desegment)
        /* If desegmentation is enabled (TCP preferences) use the desegmentation API. */
        tcp_dissect_pdus(tvb, pinfo, tree, tpncp_desegment, 4, get_tpncp_pdu_len, dissect_tpncp);
    else
        /* Otherwise use the regular dissector (might not give correct dissection). */
        dissect_tpncp(tvb, pinfo, tree);
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static gint fill_tpncp_id_vals(value_string string[], FILE *file) {
    gint i = 0, tpncp_id = 0;
    gchar *tpncp_name = NULL, *line_in_file = NULL;

    line_in_file = ep_alloc(MAX_TPNCP_DB_ENTRY_LEN);
    line_in_file[0] = 0;
    tpncp_name = ep_alloc(MAX_TPNCP_DB_ENTRY_LEN);
    tpncp_name[0] = 0;

    while (fgets(line_in_file, MAX_TPNCP_DB_ENTRY_LEN, file) != NULL) {
        if (!strncmp(line_in_file, "#####", 5)) {
            break;
        }
        if (sscanf(line_in_file, "%255s %d", tpncp_name, &tpncp_id) == 2) {
            string[i].strptr = g_strdup(tpncp_name);
            string[i].value = tpncp_id;
            if (i < (MAX_TPNCP_DB_SIZE-1)) {
                i++;
            }
            else {
                break;
            }
        }
    }

    return 0;
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static gint fill_enums_id_vals(FILE *file) {
    gint i = 0, enum_id = 0, enum_val = 0, first_entry = 1;
    gchar *line_in_file = NULL, *enum_name = NULL,
           *enum_type = NULL, *enum_str = NULL;

    line_in_file = ep_alloc(MAX_TPNCP_DB_ENTRY_LEN);
    line_in_file[0] = 0;
    enum_name = ep_alloc(MAX_TPNCP_DB_ENTRY_LEN);
    enum_name[0] = 0;
    enum_type = ep_alloc(MAX_TPNCP_DB_ENTRY_LEN);
    enum_type[0] = 0;
    enum_str = ep_alloc(MAX_TPNCP_DB_ENTRY_LEN);
    enum_str[0] = 0;

    while (fgets(line_in_file, MAX_TPNCP_DB_ENTRY_LEN, file) != NULL) {
        if (!strncmp(line_in_file, "#####", 5)) {
            break;
        }
        if (sscanf(line_in_file, "%255s %255s %d", enum_name, enum_str, &enum_id) == 3) {
            if (strcmp(enum_type, enum_name)) {
                if (!first_entry) {
                    tpncp_enums_id_vals[enum_val][i].strptr = NULL;
                    tpncp_enums_id_vals[enum_val][i].value = 0;
                    if (enum_val < (MAX_ENUMS_NUM-1)) {
                        enum_val++; i = 0;
                    }
                    else {
                        break;
                    }
                }
                else
                    first_entry = 0;
                tpncp_enums_name_vals[enum_val] = g_strdup(enum_name);
                g_strlcpy(enum_type, enum_name, MAX_TPNCP_DB_ENTRY_LEN);
            }
            tpncp_enums_id_vals[enum_val][i].strptr = g_strdup(enum_str);
            tpncp_enums_id_vals[enum_val][i].value = enum_id;
            if (i < (MAX_ENUM_ENTRIES-1)) {
                i++;
            }
            else {
                break;
            }
        }
    }

    return 0;
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static gint get_enum_name_val(gchar *enum_name) {
    gint enum_val = 0;

    while (tpncp_enums_name_vals[enum_val]) {
        if (!strcmp(enum_name, tpncp_enums_name_vals[enum_val]))
            return enum_val;
        enum_val++;
    }

    return -1;
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static gint init_tpncp_data_fields_info(tpncp_data_field_info *data_fields_info, FILE *file) {
    static gboolean was_registered = FALSE;
    gchar *tpncp_db_entry = NULL, *tpncp_data_field_name = NULL, *tmp = NULL;
    gint enum_val, data_id, current_data_id = -1,
         tpncp_data_field_sign, tpncp_data_field_size,
         tpncp_data_field_array_dim, tpncp_data_field_is_ip_addr;
    guint idx;
    tpncp_data_field_info *current_tpncp_data_field_info = NULL;
    hf_register_info hf_entr;

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
            &hf_tpncp_old_event_seq_number,
            {
                "Sequence number",
                "tpncp.old_event_seq_number",
                FT_UINT32,
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
                FT_UINT16,
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
            &hf_tpncp_old_command_id,
            {
                "Command ID",
                "tpncp.old_command_id",
                FT_UINT16,
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

    tpncp_db_entry = ep_alloc(MAX_TPNCP_DB_ENTRY_LEN);
    tpncp_db_entry[0] = 0;

    /* Register common fields of hf_register_info struture. */
    hf_entr.hfinfo.type           = 0;
    hf_entr.hfinfo.strings        = NULL;
    hf_entr.hfinfo.bitmask        = 0x0;
    hf_entr.hfinfo.blurb          = NULL;
    hf_entr.hfinfo.id             = 0;
    hf_entr.hfinfo.parent         = 0;
    hf_entr.hfinfo.ref_type       = HF_REF_TYPE_NONE;
    hf_entr.hfinfo.bitshift       = 0;
    hf_entr.hfinfo.same_name_next = NULL;
    hf_entr.hfinfo.same_name_prev = NULL;

    if (!was_registered) {
        /* Register non-standard data should be done only once. */
        hf_allocated = hf_size+array_length(hf_tpncp)-1;
        if ((hf = (hf_register_info *)g_realloc(hf, hf_allocated * sizeof(hf_register_info))) == NULL)
            return (-1);
        for (idx = 0; idx < array_length(hf_tpncp); idx++) {
            memcpy(hf + (hf_size - 1), hf_tpncp + idx, sizeof(hf_register_info));
            hf_size++;
        }
        was_registered = TRUE;
    }
    else
        hf_size++;
    /* Register standard data. */
    while (fgets(tpncp_db_entry, MAX_TPNCP_DB_ENTRY_LEN, file) != NULL) {
        if (!strncmp(tpncp_db_entry, "#####", 5)) {
            hf_size--;
            break;
        }

        /* Default to decimal display type */
        hf_entr.hfinfo.display = BASE_DEC;

        if ((tmp = strtok(tpncp_db_entry, " ")) == NULL)
            continue; /* Badly formed data base entry - skip corresponding field's registration. */
        data_id = atoi(tmp);
        if ((tpncp_data_field_name = strtok(NULL, " ")) == NULL)
            continue; /* Badly formed data base entry - skip corresponding field's registration. */
        if ((tmp = strtok(NULL, " ")) == NULL)
            continue; /* Badly formed data base entry - skip corresponding field's registration. */
        tpncp_data_field_sign = atoi(tmp);
        if ((tmp = strtok(NULL, " ")) == NULL)
            continue; /* Badly formed data base entry - skip corresponding field's registration. */
        tpncp_data_field_size = atoi(tmp);
        if ((tmp = strtok(NULL, " ")) == NULL)
            continue; /* Badly formed data base entry - skip corresponding field's registration. */
        tpncp_data_field_array_dim = atoi(tmp);
        if ((tmp = strtok(NULL, " ")) == NULL)
            continue; /* Badly formed data base entry - skip corresponding field's registration. */
        tpncp_data_field_is_ip_addr = atoi(tmp);
        if ((tmp = strtok(NULL, "\n")) == NULL)
            continue; /* Badly formed data base entry - skip corresponding field's registration. */

        if (current_data_id != data_id) { /* new data */
            current_tpncp_data_field_info = &data_fields_info[data_id];
            current_data_id = data_id;
        }
        else {
            if ((current_tpncp_data_field_info->p_next =
                (tpncp_data_field_info *)g_malloc0(sizeof(tpncp_data_field_info)))
                == NULL)
                return (-1);
            current_tpncp_data_field_info = current_tpncp_data_field_info->p_next;
        }
        /* Register specific fields of hf_register_info struture. */
        if (strcmp(tmp, "primitive")) {
            enum_val = get_enum_name_val(tmp);
            if (enum_val == -1) {
                hf_entr.hfinfo.strings = NULL;
            }
            else {
                hf_entr.hfinfo.strings = VALS(tpncp_enums_id_vals[enum_val]);
            }
        }
        else {
            hf_entr.hfinfo.strings = NULL;
        }
        current_tpncp_data_field_info->tpncp_data_field_descr = -1;
        hf_entr.p_id = &current_tpncp_data_field_info->tpncp_data_field_descr;
	current_tpncp_data_field_info->tpncp_data_field_name = g_strdup_printf("tpncp.%s", tpncp_data_field_name);
        hf_entr.hfinfo.name = current_tpncp_data_field_info->tpncp_data_field_name;
        hf_entr.hfinfo.abbrev = current_tpncp_data_field_info->tpncp_data_field_name;
        switch (tpncp_data_field_size) {
            case 1: case 2: case 3: case 4:
            case 5: case 6: case 7: case 8:
                if (tpncp_data_field_array_dim) {
                    hf_entr.hfinfo.type = FT_STRING;
                    hf_entr.hfinfo.display = BASE_NONE;
                }
                else
                    hf_entr.hfinfo.type = (tpncp_data_field_sign)?FT_UINT8:FT_INT8;
                break;
            case 16:
                hf_entr.hfinfo.type = (tpncp_data_field_sign)?FT_UINT16:FT_INT16;
                break;
            case 32:
                hf_entr.hfinfo.type = (tpncp_data_field_sign)?FT_UINT32:FT_INT32;
                break;
            default:
                break;
        }
        /* Register initialized hf_register_info in global database. */
        if (hf_size > hf_allocated) {
            hf_allocated += 1024;
            if ((hf = (hf_register_info *)g_realloc(hf, hf_allocated * sizeof(hf_register_info))) == NULL)
                return (-1);
        }
        memcpy(hf + hf_size - 1, &hf_entr, sizeof(hf_register_info));
        hf_size++;
        current_tpncp_data_field_info->tpncp_data_field_sign = tpncp_data_field_sign;
        current_tpncp_data_field_info->tpncp_data_field_size = tpncp_data_field_size;
        current_tpncp_data_field_info->tpncp_data_field_array_dim = tpncp_data_field_array_dim;
        current_tpncp_data_field_info->tpncp_data_field_is_ip_addr = tpncp_data_field_is_ip_addr;
    }

    return 0;
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

static gint init_tpncp_db(void) {
    gchar *tpncp_dat_file_path;
    FILE *file;

    tpncp_dat_file_path = ep_strdup_printf("%s" G_DIR_SEPARATOR_S"tpncp" G_DIR_SEPARATOR_S "tpncp.dat", get_datafile_dir());

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

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

void proto_reg_handoff_tpncp(void) {
    static gint tpncp_prefs_initialized = FALSE;
    static dissector_handle_t tpncp_udp_handle, tpncp_tcp_handle;

    /*  If we weren't able to load the database (and thus the hf_ entries)
     *  do not attach to any ports (if we did then we'd get a "dissector bug"
     *  assertions every time a packet is handed to us and we tried to use the
     *  hf_ entry).
     */
    if (proto_tpncp == -1)
	return;

    if (!tpncp_prefs_initialized) {
        tpncp_udp_handle = create_dissector_handle(dissect_tpncp, proto_tpncp);
        tpncp_tcp_handle = create_dissector_handle(dissect_tpncp_tcp, proto_tpncp);

        tpncp_prefs_initialized = TRUE;
    }
    else {
        dissector_delete_uint("tcp.port", trunkpack_tcp_port, tpncp_tcp_handle);
        dissector_delete_uint("udp.port", trunkpack_udp_port, tpncp_udp_handle);
        dissector_delete_uint("tcp.port", host_tcp_port,      tpncp_tcp_handle);
        dissector_delete_uint("udp.port", host_udp_port,      tpncp_udp_handle);
    }

    trunkpack_tcp_port = global_tpncp_trunkpack_tcp_port;
    trunkpack_udp_port = global_tpncp_trunkpack_udp_port;

    host_tcp_port = global_tpncp_host_tcp_port;
    host_udp_port = global_tpncp_host_udp_port;

    dissector_add_uint("tcp.port", global_tpncp_trunkpack_tcp_port, tpncp_tcp_handle);
    dissector_add_uint("udp.port", global_tpncp_trunkpack_udp_port, tpncp_udp_handle);
}

/*-------------------------------------------------------------------------------------------------------------------------------------------*/

void proto_register_tpncp(void) {
    gint idx;
    module_t *tpncp_module;
    static gint *ett[] = {
        &ett_tpncp,
        &ett_tpncp_body
    };

    if (init_tpncp_db() == -1)
        return;

    proto_tpncp = proto_register_protocol("AudioCodes TPNCP (TrunkPack Network Control Protocol)",
                                          "TPNCP", "tpncp");

    /*
     * The function proto_register_field_array can not work with dynamic arrays,
     * so passing dynamic array elements one-by-one in the loop.
     */
    for(idx = 0; idx < hf_size; idx++) {
        proto_register_field_array(proto_tpncp, &hf[idx], 1);
    }

    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("tpncp", dissect_tpncp, proto_tpncp);

    tpncp_module = prefs_register_protocol(proto_tpncp, proto_reg_handoff_tpncp);

    prefs_register_uint_preference(tpncp_module, "tcp.trunkpack_port",
                                   "TPNCP \"well-known\" TrunkPack TCP Port",
                                   "", 10, &global_tpncp_trunkpack_tcp_port);

    prefs_register_uint_preference(tpncp_module, "udp.trunkpack_port",
                                   "TPNCP \"well-known\" TrunkPack UDP Port",
                                   "", 10, &global_tpncp_trunkpack_udp_port);
}
