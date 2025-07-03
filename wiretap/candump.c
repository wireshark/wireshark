/* candump.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for candump log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include "candump.h"

#include <file_wrappers.h>
#include <errno.h>
#include <wsutil/exported_pdu_tlvs.h>
#include <wsutil/strtoi.h>
#include <wsutil/str_util.h>
#include <wiretap/socketcan.h>
#include <epan/dissectors/packet-socketcan.h>

/*
 * Private per-wtap_t data needed to read a file.
 */
typedef struct {
	GHashTable *interface_ids;	/* map name/description/link-layer type to interface ID */
	unsigned num_interface_ids;	/* Number of interface IDs assigned */
} candump_t;

#define CANDUMP_MAX_LINE_SIZE 4096 // J1939 logs could contain long lines

static int candump_file_type_subtype = -1;

/*
 * Hash table to map interface name to interface ID.
 */

static gboolean
destroy_if_name(void *key, void *value _U_, void *user_data _U_)
{
    char *name = (char *)key;

    g_free(name);

    return true;
}

static void
add_new_if_name(candump_t *candump, const char *name, void * *result)
{
    char *new_name;

    new_name = g_strdup(name);
    *result = GUINT_TO_POINTER(candump->num_interface_ids);
    g_hash_table_insert(candump->interface_ids, (void *)new_name, *result);
    candump->num_interface_ids++;
}

/*
 * Following 3 functions taken from gsmdecode-0.7bis, with permission:
 *
 *   https://web.archive.org/web/20091218112927/http://wiki.thc.org/gsm
 */
/*
* TODO: Find a better replacement for this
*/
static int
hex2bin(uint8_t* out, uint8_t* out_end, char* in)
{
    uint8_t* out_start = out;
    int is_low = 0;
    int c;

    while (*in != '\0')
    {
        c = ws_xton(*in);
        if (c < 0)
        {
            in++;
            continue;
        }
        if (out == out_end)
        {
            /* Too much data */
            return -1;
        }
        if (is_low == 0)
        {
            *out = c << 4;
            is_low = 1;
        }
        else {
            *out |= (c & 0x0f);
            is_low = 0;
            out++;
        }
        in++;
    }

    return (int)(out - out_start);
}

/*
 * This is written by the candump utility on Linux.
 */

static bool
candump_parse(wtap *wth, FILE_T fh, wtap_can_msg_t *msg, int64_t *offset,
              unsigned int *interface_id, int *err, char **err_info)
{
    gint64 seek_off = 0;
    char line_buffer[CANDUMP_MAX_LINE_SIZE];
    char** tokens = NULL;
    char* data_start;
    bool ext_msg;
    int secs = 0,
        nsecs = 0;
    void *result;

    while(!file_eof(fh))
    {

        seek_off = file_tell(fh);

        if (file_gets(line_buffer, CANDUMP_MAX_LINE_SIZE, fh) == NULL)
        {
            /* Error reading file, bail out */
            *err = file_error(fh, err_info);
            return false;
        }

        tokens = g_strsplit(line_buffer, " ", 3);

        if (tokens[0] == NULL)
            break;
        if (sscanf(tokens[0], "(%d.%d)", &secs, &nsecs) != 2)
            break;

        msg->ts.secs = secs;
        msg->ts.nsecs = nsecs*1000;

        if (tokens[1] == NULL)
            break;

        if (tokens[2] == NULL)
            break;
        char* id_end = strstr(tokens[2], "#");
        if (id_end == NULL)
            break;

        if (!ws_hexstrtou32(tokens[2], (const char**)&id_end, &msg->id))
            break;

        ext_msg = (msg->id > CAN_SFF_MASK);
        msg->type = ext_msg ? MSG_TYPE_EXT : MSG_TYPE_STD;

        //Skip over the (first) #
        id_end++;
        data_start = id_end;
        bool valid = false;
        switch(*id_end)
        {
        case 0:
            //Packet with no data
            valid = true;
            break;
        case '#':
        {
            char strflags[2] = {0};
            char* flag_start = id_end + 1;
            if (!g_ascii_isxdigit(*flag_start))
                break;

            strflags[0] = *flag_start;

            if (!ws_hexstrtou8(strflags, NULL, &msg->flags))
                break;
            valid = true;
            msg->type = ext_msg ? MSG_TYPE_EXT_FD : MSG_TYPE_STD_FD;

            //Skip the flags
            data_start = id_end+2;
            break;
        }
        case 'R':
        {
            char rvalue = *(id_end + 1);
            if (g_ascii_isdigit(rvalue))
            {
                msg->data.length = rvalue - '0';
            }
            else
            {
                msg->data.length = 0;
            }

            msg->type = ext_msg ? MSG_TYPE_EXT_RTR : MSG_TYPE_STD_RTR;

            //No data
            data_start = NULL;
            valid = true;
            break;
        }
        default:
            if (!g_ascii_isxdigit(*id_end) && (!g_ascii_isspace(*id_end)))
            {
                g_strfreev(tokens);
                return false;
            }
            valid = true;
            break;
        }

        if (!valid)
            break;

        //Now grab the data
        if (data_start != NULL)
            msg->data.length = hex2bin(msg->data.data, &msg->data.data[CANFD_MAX_DLEN], data_start);

	/*
	 * No errors - if we're reading a file of our own,
	 * get the interface ID.
	 *
         * The interface name is tokens[1].  Try to find the entry
         * with that name.
         */
        if (wth != NULL) {
            candump_t *candump = (candump_t *)wth->priv;

            if (!g_hash_table_lookup_extended(candump->interface_ids,
                                             (const void *)tokens[1],
                                             NULL, &result)) {
                wtap_block_t int_data;
                wtapng_if_descr_mandatory_t *int_data_mand;

                /*
                 * Not found; make a new entry.
                 */
                add_new_if_name(candump, tokens[1], &result);

                /*
                 * Now make a new IDB and add it.
                 */
                int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
                int_data_mand = (wtapng_if_descr_mandatory_t *)wtap_block_get_mandatory_data(int_data);

                int_data_mand->wtap_encap = WTAP_ENCAP_SOCKETCAN;
                int_data_mand->tsprecision = WTAP_TSPREC_USEC;
                int_data_mand->time_units_per_second = 1000000; /* Microsecond resolution */
                int_data_mand->snap_len = WTAP_MAX_PACKET_SIZE_STANDARD;	/* XXX - not known */

                wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 0x06); /* microsecond resolution */
                /* Interface statistics */
                int_data_mand->num_stat_entries = 0;
                int_data_mand->interface_statistics = NULL;

                wtap_block_set_string_option_value(int_data,
                    OPT_IDB_NAME, tokens[1], strlen(tokens[1]));
                wtap_add_idb(wth, int_data);
             }
             *interface_id = GPOINTER_TO_UINT(result);
        }

        g_strfreev(tokens);

        if (offset != NULL)
            *offset = seek_off;

        return true;
    }

    g_strfreev(tokens);
    return false;
}

static bool
candump_fill_in_rec(wtap *wth, wtap_rec *rec, wtap_can_msg_t *msg,
                    unsigned int interface_id, int *err, char **err_info)
{
    if (!wtap_socketcan_gen_packet(wth, rec, msg, "candump", err, err_info))
        return false;
    rec->presence_flags |= WTAP_HAS_INTERFACE_ID;
    rec->rec_header.packet_header.interface_id = interface_id;
    return true;
}

static bool
candump_read(wtap *wth, wtap_rec *rec, int *err, char **err_info,
             int64_t *data_offset)
{
    wtap_can_msg_t msg = {0};
    unsigned int interface_id;

    ws_debug("%s: Try reading at offset %" PRIi64 "\n", G_STRFUNC, file_tell(wth->fh));

    if (!candump_parse(wth, wth->fh, &msg, data_offset, &interface_id,
                       err, err_info))
        return false;

    ws_debug("%s: Stopped at offset %" PRIi64 "\n", G_STRFUNC, file_tell(wth->fh));

    return candump_fill_in_rec(wth, rec, &msg, interface_id, err, err_info);
}

static bool
candump_seek_read(wtap *wth , int64_t seek_off, wtap_rec *rec,
                  int *err, char **err_info)
{
    wtap_can_msg_t msg = {0};
    unsigned int interface_id;

    ws_debug("%s: Read at offset %" PRIi64 "\n", G_STRFUNC, seek_off);

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    {
        *err      = errno;
        *err_info = g_strdup(g_strerror(errno));

        return false;
    }

    if (!candump_parse(wth, wth->random_fh, &msg, NULL, &interface_id,
                       err, err_info))
        return false;

    return candump_fill_in_rec(wth, rec, &msg, interface_id, err, err_info);
}

static void
candump_close(wtap *wth)
{
    candump_t *candump = (candump_t *)wth->priv;

    g_hash_table_foreach_remove(candump->interface_ids, destroy_if_name, NULL);
    g_hash_table_destroy(candump->interface_ids);
}

wtap_open_return_val
candump_open(wtap* wth, int* err, char** err_info)
{
    wtap_can_msg_t temp_msg = {0};
    candump_t *candump;

    /*
     * We don't pass wth to candump_parse(), because we haven't yet
     * decided whether this is a candump file, and haven't set up
     * the hash table for interface names, and thus don't want it
     * trying to look up those names and adding new interfaces if
     * it doesn't find them; we do that in the read code.
     */
    if (!candump_parse(NULL, wth->fh, &temp_msg, NULL, NULL, err, err_info))
    {
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;

        *err = 0;
        *err_info = NULL;
        return WTAP_OPEN_NOT_MINE;
    }

    ws_debug("%s: This is our file\n", G_STRFUNC);

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    {
        *err = errno;
        *err_info = g_strdup(g_strerror(errno));

        return WTAP_OPEN_ERROR;
    }

    /* This is a candump file */
    wtap_set_as_socketcan(wth, candump_file_type_subtype, WTAP_TSPREC_USEC);
    wth->subtype_read = candump_read;
    wth->subtype_seek_read = candump_seek_read;
    wth->subtype_close = candump_close;
    candump = g_new(candump_t, 1);
    candump->interface_ids = g_hash_table_new(g_str_hash, g_str_equal);
    candump->num_interface_ids = 0;
    wth->priv = (void *)candump;

    return WTAP_OPEN_MINE;
}

static const struct supported_block_type candump_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info candump_info = {
    "Linux candump file", "candump", NULL, NULL,
    false, BLOCKS_SUPPORTED(candump_blocks_supported),
    NULL, NULL, NULL
};

void register_candump(void)
{
    candump_file_type_subtype = wtap_register_file_type_subtype(&candump_info);
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
