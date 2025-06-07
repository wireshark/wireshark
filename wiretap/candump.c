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

#include <wtap-int.h>
#include <file_wrappers.h>
#include <errno.h>
#include <wsutil/exported_pdu_tlvs.h>
#include <wsutil/strtoi.h>
#include <wsutil/str_util.h>
#include <wiretap/socketcan.h>
#include <epan/dissectors/packet-socketcan.h>

#define CANDUMP_MAX_LINE_SIZE 4096 // J1939 logs could contain long lines

static int candump_file_type_subtype = -1;


typedef struct {
    uint8_t    length;
    uint8_t    data[CANFD_MAX_DLEN];
} msg_data_t;

typedef struct {
    nstime_t   ts;
    uint32_t   id;
    bool       is_fd;
    uint8_t    flags;
    msg_data_t data;
} msg_t;

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
candump_gen_packet(wtap *wth, wtap_rec *rec, const msg_t *msg, int *err, char **err_info)
{
    /* Generate Exported PDU tags for the packet info */
    ws_buffer_clean(&rec->data);

    if (msg->is_fd)
    {
        canfd_frame_t canfd_frame = {0};

        /*
         * There's a maximum of CANFD_MAX_DLEN bytes in a CAN-FD frame.
         */
        if (msg->data.length > CANFD_MAX_DLEN) {
            *err = WTAP_ERR_BAD_FILE;
            if (err_info != NULL) {
	        *err_info = ws_strdup_printf("candump: File has %u-byte CAN FD packet, bigger than maximum of %u",
                                             msg->data.length, CANFD_MAX_DLEN);
            }
            return false;
        }

        canfd_frame.can_id = g_htonl(msg->id);
        canfd_frame.flags  = msg->flags | CANFD_FDF;
        canfd_frame.len    = msg->data.length;
        memcpy(canfd_frame.data, msg->data.data, msg->data.length);

        ws_buffer_append(&rec->data, (uint8_t *)&canfd_frame, sizeof(canfd_frame));
    }
    else
    {
        can_frame_t can_frame = {0};

        /*
         * There's a maximum of CAN_MAX_DLEN bytes in a CAN frame.
         */
        if (msg->data.length > CAN_MAX_DLEN) {
            *err = WTAP_ERR_BAD_FILE;
            if (err_info != NULL) {
	        *err_info = ws_strdup_printf("candump: File has %u-byte CAN packet, bigger than maximum of %u",
                                             msg->data.length, CAN_MAX_DLEN);
            }
            return false;
        }

        can_frame.can_id  = g_htonl(msg->id);
        can_frame.can_dlc = msg->data.length;
        memcpy(can_frame.data, msg->data.data, msg->data.length);

        ws_buffer_append(&rec->data, (uint8_t *)&can_frame, sizeof(can_frame));
    }

    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->block          = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;
    rec->ts             = msg->ts;
    rec->tsprec         = WTAP_TSPREC_USEC;

    rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
    rec->rec_header.packet_header.len    = (uint32_t)ws_buffer_length(&rec->data);

    return true;
}

static bool
candump_parse(FILE_T fh, msg_t* msg, int64_t* offset, int* err, char** err_info)
{
    gint64 seek_off = 0;
    char line_buffer[CANDUMP_MAX_LINE_SIZE];
    char** tokens = NULL;
    char* data_start;
    int secs = 0,
        nsecs = 0;

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

        if (sscanf(tokens[0], "(%d.%d)", &secs, &nsecs) != 2)
            break;

        msg->ts.secs = secs;
        msg->ts.nsecs = nsecs*1000;

        /* TODO: Interface name is tokens[1] */

        char* id_end = strstr(tokens[2], "#");
        if (id_end == NULL)
            break;

        if (!ws_hexstrtou32(tokens[2], (const char**)&id_end, &msg->id))
            break;

        if (msg->id > 0x7FF)
        {
            if (!(msg->id & CAN_ERR_FLAG))
                msg->id |= CAN_EFF_FLAG;
        }

        msg->is_fd = false;

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
            msg->is_fd = true;

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

            msg->id |= CAN_RTR_FLAG;

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

        g_strfreev(tokens);

        if (offset != NULL)
            *offset = seek_off;

        return true;
    }

    g_strfreev(tokens);
    return false;
}

static bool
candump_read(wtap *wth, wtap_rec *rec, int *err, char **err_info,
             int64_t *data_offset)
{
    msg_t msg = {0};

    ws_debug("%s: Try reading at offset %" PRIi64 "\n", G_STRFUNC, file_tell(wth->fh));

    if (!candump_parse(wth->fh, &msg, data_offset, err, err_info))
        return false;

    ws_debug("%s: Stopped at offset %" PRIi64 "\n", G_STRFUNC, file_tell(wth->fh));

    return candump_gen_packet(wth, rec, &msg, err, err_info);
}

static bool
candump_seek_read(wtap *wth , int64_t seek_off, wtap_rec *rec,
                  int *err, char **err_info)
{
    msg_t msg = {0};

    ws_debug("%s: Read at offset %" PRIi64 "\n", G_STRFUNC, seek_off);

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    {
        *err      = errno;
        *err_info = g_strdup(g_strerror(errno));

        return false;
    }

    if (!candump_parse(wth->random_fh, &msg, NULL, err, err_info))
        return false;

    return candump_gen_packet(wth, rec, &msg, err, err_info);
}

wtap_open_return_val
candump_open(wtap* wth, int* err, char** err_info)
{
    msg_t temp_msg = {0};
    if (!candump_parse(wth->fh, &temp_msg, NULL, err, err_info))
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

    wth->priv = NULL;
    wth->file_type_subtype = candump_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_SOCKETCAN;
    wth->file_tsprec = WTAP_TSPREC_USEC;
    wth->subtype_read = candump_read;
    wth->subtype_seek_read = candump_seek_read;

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
