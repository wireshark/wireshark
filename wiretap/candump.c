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
#include <wsutil/exported_pdu_tlvs.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include "candump_priv.h"

static bool candump_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                             int *err, char **err_info,
                             int64_t *data_offset);
static bool candump_seek_read(wtap *wth, int64_t seek_off,
                                  wtap_rec *rec, Buffer *buf,
                                  int *err, char **err_info);

static int candump_file_type_subtype = -1;

void register_candump(void);

/*
 * This is written by the candump utility on Linux.
 */

static bool
candump_gen_packet(wtap_rec *rec, Buffer *buf, const msg_t *msg, int *err,
                     char **err_info)
{
    /* Generate Exported PDU tags for the packet info */
    ws_buffer_clean(buf);

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

        ws_buffer_append(buf, (uint8_t *)&canfd_frame, sizeof(canfd_frame));
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

        ws_buffer_append(buf, (uint8_t *)&can_frame, sizeof(can_frame));
    }

    rec->rec_type       = REC_TYPE_PACKET;
    rec->block          = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;
    rec->ts             = msg->ts;
    rec->tsprec         = WTAP_TSPREC_USEC;

    rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(buf);
    rec->rec_header.packet_header.len    = (uint32_t)ws_buffer_length(buf);

    return true;
}

static bool
candump_parse(FILE_T fh, msg_t *msg, int64_t *offset, int *err, char **err_info)
{
    candump_state_t state = {0};
    bool            ok;
    int64_t         seek_off;

#ifdef CANDUMP_DEBUG
    candump_debug_printf("%s: Trying candump file decoder\n", G_STRFUNC);
#endif

    state.fh = fh;

    do
    {
        if (file_eof(fh))
            return false;

        seek_off = file_tell(fh);
#ifdef CANDUMP_DEBUG
        candump_debug_printf("%s: Starting parser at offset %" PRIi64 "\n", G_STRFUNC, seek_off);
#endif
        state.file_bytes_read = 0;
        ok = run_candump_parser(&state, err, err_info);

        /* Rewind the file to the offset we have finished parsing */
        if (file_seek(fh, seek_off + state.file_bytes_read, SEEK_SET, err) == -1)
        {
            g_free(*err_info);
            *err      = errno;
            *err_info = g_strdup(g_strerror(errno));
            return false;
        }
    }
    while (ok && !state.is_msg_valid);

    if (!ok)
        return false;

#ifdef CANDUMP_DEBUG
    candump_debug_printf("%s: Success\n", G_STRFUNC);
#endif

    if (offset)
        *offset = seek_off;

    if (msg)
        *msg = state.msg;

    return true;
}

wtap_open_return_val
candump_open(wtap *wth, int *err, char **err_info)
{
    if (!candump_parse(wth->fh, NULL, NULL, err, err_info))
    {
        g_free(*err_info);

        *err      = 0;
        *err_info = NULL;

        return WTAP_OPEN_NOT_MINE;
    }

#ifdef CANDUMP_DEBUG
    candump_debug_printf("%s: This is our file\n", G_STRFUNC);
#endif

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    {
        *err      = errno;
        *err_info = g_strdup(g_strerror(errno));

        return WTAP_OPEN_ERROR;
    }

    wth->priv              = NULL;
    wth->file_type_subtype = candump_file_type_subtype;
    wth->file_encap        = WTAP_ENCAP_SOCKETCAN;
    wth->file_tsprec       = WTAP_TSPREC_USEC;
    wth->subtype_read      = candump_read;
    wth->subtype_seek_read = candump_seek_read;

    return WTAP_OPEN_MINE;
}

static bool
candump_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, char **err_info,
             int64_t *data_offset)
{
    msg_t msg;

#ifdef CANDUMP_DEBUG
    candump_debug_printf("%s: Try reading at offset %" PRIi64 "\n", G_STRFUNC, file_tell(wth->fh));
#endif

    if (!candump_parse(wth->fh, &msg, data_offset, err, err_info))
        return false;

#ifdef CANDUMP_DEBUG
    candump_debug_printf("%s: Stopped at offset %" PRIi64 "\n", G_STRFUNC, file_tell(wth->fh));
#endif

    return candump_gen_packet(rec, buf, &msg, err, err_info);
}

static bool
candump_seek_read(wtap *wth , int64_t seek_off, wtap_rec *rec,
                  Buffer *buf, int *err, char **err_info)
{
    msg_t msg;

#ifdef CANDUMP_DEBUG
    candump_debug_printf("%s: Read at offset %" PRIi64 "\n", G_STRFUNC, seek_off);
#endif

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    {
        *err      = errno;
        *err_info = g_strdup(g_strerror(errno));

        return false;
    }

    if (!candump_parse(wth->random_fh, &msg, NULL, err, err_info))
        return false;

    return candump_gen_packet(rec, buf, &msg, err, err_info);
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
