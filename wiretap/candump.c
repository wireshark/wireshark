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
#include <wtap-int.h>
#include <file_wrappers.h>
#include <epan/exported_pdu.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include "candump.h"
#include "candump_priv.h"

static gboolean candump_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                             int *err, gchar **err_info,
                             gint64 *data_offset);
static gboolean candump_seek_read(wtap *wth, gint64 seek_off,
                                  wtap_rec *rec, Buffer *buf,
                                  int *err, gchar **err_info);

static void
candump_write_packet(wtap_rec *rec, Buffer *buf, const msg_t *msg)
{
    static const char *can_proto_name    = "can-hostendian";
    static const char *canfd_proto_name  = "canfd";
    const char        *proto_name        = msg->is_fd ? canfd_proto_name : can_proto_name;
    guint              proto_name_length = (guint)strlen(proto_name) + 1;
    guint              header_length;
    guint              packet_length;
    guint              frame_length;
    guint8            *buf_data;

    /* Adjust proto name length to be aligned on 4 byte boundary */
    proto_name_length += (proto_name_length % 4) ? (4 - (proto_name_length % 4)) : 0;

    header_length = 4 + proto_name_length + 4;
    frame_length  = msg->is_fd ? sizeof(canfd_frame_t) : sizeof(can_frame_t);
    packet_length = header_length + frame_length;

    ws_buffer_clean(buf);
    ws_buffer_assure_space(buf, packet_length);
    buf_data = ws_buffer_start_ptr(buf);

    memset(buf_data, 0, packet_length);

    buf_data[1] = EXP_PDU_TAG_PROTO_NAME;
    buf_data[3] = proto_name_length;
    memcpy(buf_data + 4, proto_name, strlen(proto_name));

    if (msg->is_fd)
    {
        canfd_frame_t canfd_frame = {0};

        canfd_frame.can_id = msg->id;
        canfd_frame.flags  = msg->flags;
        canfd_frame.len    = msg->data.length;
        memcpy(canfd_frame.data, msg->data.data, msg->data.length);

        memcpy(buf_data + header_length, (guint8 *)&canfd_frame, sizeof(canfd_frame));
    }
    else
    {
        can_frame_t can_frame = {0};

        can_frame.can_id  = msg->id;
        can_frame.can_dlc = msg->data.length;
        memcpy(can_frame.data, msg->data.data, msg->data.length);

        memcpy(buf_data + header_length, (guint8 *)&can_frame, sizeof(can_frame));
    }

    rec->rec_type       = REC_TYPE_PACKET;
    rec->presence_flags = WTAP_HAS_TS;
    rec->ts             = msg->ts;
    rec->tsprec         = WTAP_TSPREC_USEC;

    rec->rec_header.packet_header.caplen = packet_length;
    rec->rec_header.packet_header.len    = packet_length;
}

static gboolean
candump_parse(FILE_T fh, msg_t *msg, gint64 *offset, int *err, char **err_info)
{
    candump_state_t state = {0};
    gboolean        ok;
    gint64          seek_off;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Trying candump file decoder\n", G_STRFUNC);
#endif

    state.fh = fh;

    do
    {
        if (file_eof(fh))
            return FALSE;

        seek_off = file_tell(fh);
#ifdef CANDUMP_DEBUG
        ws_debug_printf("%s: Starting parser at offset %" PRIi64 "\n", G_STRFUNC, seek_off);
#endif
        state.file_bytes_read = 0;
        ok = run_candump_parser(&state, err, err_info);

        /* Rewind the file to the offset we have finished parsing */
        if (file_seek(fh, seek_off + state.file_bytes_read, SEEK_SET, err) == -1)
        {
            g_free(*err_info);
            *err      = errno;
            *err_info = g_strdup(g_strerror(errno));
            return FALSE;
        }
    }
    while (ok && !state.is_msg_valid);

    if (!ok)
        return FALSE;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Success\n", G_STRFUNC);
#endif

    if (offset)
        *offset = seek_off;

    if (msg)
        *msg = state.msg;

    return TRUE;
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
    ws_debug_printf("%s: This is our file\n", G_STRFUNC);
#endif

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    {
        *err      = errno;
        *err_info = g_strdup(g_strerror(errno));

        return WTAP_OPEN_ERROR;
    }

    wth->priv              = NULL;
    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    wth->file_encap        = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
    wth->file_tsprec       = WTAP_TSPREC_USEC;
    wth->subtype_read      = candump_read;
    wth->subtype_seek_read = candump_seek_read;

    return WTAP_OPEN_MINE;
}

static gboolean
candump_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info,
             gint64 *data_offset)
{
    msg_t msg;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Try reading at offset %" PRIi64 "\n", G_STRFUNC, file_tell(wth->fh));
#endif

    if (!candump_parse(wth->fh, &msg, data_offset, err, err_info))
        return FALSE;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Stopped at offset %" PRIi64 "\n", G_STRFUNC, file_tell(wth->fh));
#endif

    candump_write_packet(rec, buf, &msg);

    return TRUE;
}

static gboolean
candump_seek_read(wtap *wth , gint64 seek_off, wtap_rec *rec,
                  Buffer *buf, int *err, gchar **err_info)
{
    msg_t msg;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Read at offset %" PRIi64 "\n", G_STRFUNC, seek_off);
#endif

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    {
        *err      = errno;
        *err_info = g_strdup(g_strerror(errno));

        return FALSE;
    }

    if (!candump_parse(wth->random_fh, &msg, NULL, err, err_info))
        return FALSE;

    candump_write_packet(rec, buf, &msg);

    return TRUE;
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
