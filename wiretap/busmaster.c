/* busmaster.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Busmaster log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <wtap-int.h>
#include <file_wrappers.h>
#include <epan/exported_pdu.h>
#include <epan/dissectors/packet-socketcan.h>
#include "busmaster.h"
#include "busmaster_priv.h"
#include <inttypes.h>
#include <string.h>
#include <errno.h>

static void
busmaster_close(wtap *wth);

static gboolean
busmaster_read(wtap   *wth, wtap_rec *rec, Buffer *buf,
               int    *err, gchar **err_info,
               gint64 *data_offset);

static gboolean
busmaster_seek_read(wtap     *wth, gint64 seek_off,
                    wtap_rec *rec, Buffer *buf,
                    int      *err, gchar **err_info);

static gboolean
busmaster_gen_packet(wtap_rec               *rec, Buffer *buf,
                     const busmaster_priv_t *priv_entry, const msg_t *msg,
                     int                    *err, gchar **err_info)
{
    time_t secs     = 0;
    guint32  nsecs  = 0;
    gboolean has_ts = FALSE;
    gboolean is_fd  = (msg->type == MSG_TYPE_STD_FD)
        || (msg->type == MSG_TYPE_EXT_FD);
    gboolean is_eff = (msg->type == MSG_TYPE_EXT)
        || (msg->type == MSG_TYPE_EXT_RTR)
        || (msg->type == MSG_TYPE_EXT_FD);
    gboolean is_rtr = (msg->type == MSG_TYPE_STD_RTR)
        || (msg->type == MSG_TYPE_EXT_RTR);
    gboolean is_err = (msg->type == MSG_TYPE_ERR);

    static const char *const can_proto_name   = "can-hostendian";
    static const char *const canfd_proto_name = "canfd";

    const char        *proto_name  = is_fd ? canfd_proto_name : can_proto_name;
    guint              proto_name_length = (guint)strlen(proto_name) + 1;
    guint              header_length;
    guint              packet_length;
    guint              frame_length;
    guint8            *buf_data;

    /* Adjust proto name length to be aligned on 4 byte boundary */
    proto_name_length += (proto_name_length % 4) ? (4 - (proto_name_length % 4)) : 0;

    header_length = 4 + proto_name_length + 4;
    frame_length  = is_fd ? sizeof(canfd_frame_t) : sizeof(can_frame_t);
    packet_length = header_length + frame_length;

    ws_buffer_clean(buf);
    ws_buffer_assure_space(buf, packet_length);
    buf_data = ws_buffer_start_ptr(buf);

    memset(buf_data, 0, packet_length);

    buf_data[1] = EXP_PDU_TAG_PROTO_NAME;
    buf_data[3] = proto_name_length;
    memcpy(buf_data + 4, proto_name, strlen(proto_name));

    if (!priv_entry)
    {
        *err      = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("Header is missing");
        return FALSE;
    }

    if (is_fd)
    {
        canfd_frame_t canfd_frame = {0};

        canfd_frame.can_id = (msg->id & (is_eff ? CAN_EFF_MASK : CAN_SFF_MASK)) |
            (is_eff ? CAN_EFF_FLAG : 0) |
            (is_err ? CAN_ERR_FLAG : 0);
        canfd_frame.flags  = 0;
        canfd_frame.len    = msg->data.length;

        memcpy(canfd_frame.data,
               msg->data.data,
               MIN(msg->data.length, sizeof(canfd_frame.data)));

        memcpy(buf_data + header_length,
               (guint8 *)&canfd_frame,
               sizeof(canfd_frame));
    }
    else
    {
        can_frame_t can_frame = {0};

        can_frame.can_id  = (msg->id & (is_eff ? CAN_EFF_MASK : CAN_SFF_MASK)) |
            (is_rtr ? CAN_RTR_FLAG : 0) |
            (is_eff ? CAN_EFF_FLAG : 0) |
            (is_err ? CAN_ERR_FLAG : 0);
        can_frame.can_dlc = msg->data.length;

        memcpy(can_frame.data,
               msg->data.data,
               MIN(msg->data.length, sizeof(can_frame.data)));

        memcpy(buf_data + header_length,
               (guint8 *)&can_frame,
               sizeof(can_frame));
    }

    if (priv_entry->time_mode == TIME_MODE_SYSTEM)
    {
        struct tm tm;

        tm.tm_year  = priv_entry->start_date.year - 1900;
        tm.tm_mon   = priv_entry->start_date.month - 1;
        tm.tm_mday  = priv_entry->start_date.day;
        tm.tm_hour  = msg->timestamp.hours;
        tm.tm_min   = msg->timestamp.minutes;
        tm.tm_sec   = msg->timestamp.seconds;
        tm.tm_isdst = -1;

        secs   = mktime(&tm);
        nsecs  = msg->timestamp.micros * 1000u;
        has_ts = TRUE;
    }
    else if (priv_entry->time_mode == TIME_MODE_ABSOLUTE)
    {
        struct tm tm;
        guint32   micros;

        tm.tm_year  = priv_entry->start_date.year - 1900;
        tm.tm_mon   = priv_entry->start_date.month - 1;
        tm.tm_mday  = priv_entry->start_date.day;
        tm.tm_hour  = priv_entry->start_time.hours;
        tm.tm_min   = priv_entry->start_time.minutes;
        tm.tm_sec   = priv_entry->start_time.seconds;
        tm.tm_isdst = -1;

        secs = mktime(&tm);

        secs += msg->timestamp.hours * 3600;
        secs += msg->timestamp.minutes * 60;
        secs += msg->timestamp.seconds;

        micros = priv_entry->start_time.micros + msg->timestamp.micros;
        if (micros >= 1000000u)
        {
            micros -= 1000000u;
            secs   += 1;
        }

        nsecs  = micros * 1000u;
        has_ts = TRUE;
    }

    rec->rec_type       = REC_TYPE_PACKET;
    rec->presence_flags = has_ts ? WTAP_HAS_TS : 0;
    rec->ts.secs        = secs;
    rec->ts.nsecs       = nsecs;

    rec->rec_header.packet_header.caplen = packet_length;
    rec->rec_header.packet_header.len    = packet_length;

    return TRUE;
}

static log_entry_type_t
busmaster_parse(FILE_T fh, busmaster_state_t *state, int *err, char **err_info)
{
    gboolean ok;
    gint64   seek_off;

    busmaster_debug_printf("%s: Running busmaster file decoder\n", G_STRFUNC);

    state->fh = fh;

    do
    {
        if (file_eof(fh))
            return LOG_ENTRY_EOF;

        seek_off               = file_tell(fh);
        busmaster_debug_printf("%s: Starting parser at offset %" PRIi64 "\n",
                               G_STRFUNC, seek_off);
        state->file_bytes_read = 0;
        ok                     = run_busmaster_parser(state, err, err_info);

        /* Rewind the file to the offset we have finished parsing */
        busmaster_debug_printf("%s: Rewinding to offset %" PRIi64 "\n",
                               G_STRFUNC, seek_off + state->file_bytes_read);
        if (file_seek(fh, seek_off + state->file_bytes_read, SEEK_SET, err) == -1)
        {
            g_free(*err_info);
            *err      = errno;
            *err_info = g_strdup(g_strerror(errno));
            return LOG_ENTRY_ERROR;
        }
    }
    while (ok && state->entry_type == LOG_ENTRY_NONE);

    if (!ok)
        return LOG_ENTRY_ERROR;

    busmaster_debug_printf("%s: Success\n", G_STRFUNC);

    return state->entry_type;
}

wtap_open_return_val
busmaster_open(wtap *wth, int *err, char **err_info)
{
    busmaster_state_t state = {0};
    log_entry_type_t  entry;

    busmaster_debug_printf("%s: Trying to open with busmaster log reader\n",
                           G_STRFUNC);

    /* Rewind to the beginning */
    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    entry = busmaster_parse(wth->fh, &state, err, err_info);

    g_free(*err_info);
    *err_info = NULL;
    *err      = 0;

    if (entry != LOG_ENTRY_HEADER)
        return WTAP_OPEN_NOT_MINE;

    /* Rewind to the beginning, so busmaster_read may read from the very beginning */
    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    busmaster_debug_printf("%s: That's a busmaster log\n", G_STRFUNC);

    wth->priv              = NULL;
    wth->subtype_close     = busmaster_close;
    wth->subtype_read      = busmaster_read;
    wth->subtype_seek_read = busmaster_seek_read;
    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    wth->file_encap        = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
    wth->file_tsprec       = WTAP_TSPREC_USEC;

    return WTAP_OPEN_MINE;
}

static void
busmaster_close(wtap *wth)
{
    busmaster_debug_printf("%s\n", G_STRFUNC);

    g_slist_free_full((GSList *)wth->priv, g_free);
    wth->priv = NULL;
}

static busmaster_priv_t *
busmaster_find_priv_entry(void *priv, gint64 offset)
{
    GSList *list;

    for (list = (GSList *)priv; list; list = g_slist_next(list))
    {
        busmaster_priv_t *entry = (busmaster_priv_t *)list->data;

        if (((entry->file_end_offset == -1)
             && (g_slist_next(list) == NULL))
            || ((offset >= entry->file_start_offset)
                && (offset <= entry->file_end_offset)))
        {
            return entry;
        }
    }

    return NULL;
}

static gboolean
busmaster_read(wtap   *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info,
               gint64 *data_offset)
{
    log_entry_type_t   entry;
    busmaster_state_t  state;
    busmaster_priv_t  *priv_entry;
    gboolean           is_msg = FALSE;
    gboolean          is_ok = TRUE;

    while (!is_msg && is_ok)
    {
        busmaster_debug_printf("%s: offset = %" PRIi64 "\n",
                               G_STRFUNC, file_tell(wth->fh));

        if (file_eof(wth->fh))
        {
            busmaster_debug_printf("%s: End of file detected, nothing to do here\n",
                                   G_STRFUNC);
            *err      = 0;
            *err_info = NULL;
            return FALSE;
        }

        *data_offset = file_tell(wth->fh);
        priv_entry   = busmaster_find_priv_entry(wth->priv, *data_offset);

        memset(&state, 0, sizeof(state));
        if (priv_entry)
            state.header = *priv_entry;
        entry = busmaster_parse(wth->fh, &state, err, err_info);

        busmaster_debug_printf("%s: analyzing output\n", G_STRFUNC);
        switch (entry)
        {
        case LOG_ENTRY_EMPTY:
            break;
        case LOG_ENTRY_FOOTER_AND_HEADER:
        case LOG_ENTRY_FOOTER:
            priv_entry = (busmaster_priv_t *)g_slist_last((GSList *)wth->priv)->data;
            if (!priv_entry)
            {
                *err      = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("Header is missing");
                return FALSE;
            }
            priv_entry->file_end_offset  = *data_offset;
            if (entry == LOG_ENTRY_FOOTER)
                break;
            /* fall-through */
        case LOG_ENTRY_HEADER:
            if (state.header.protocol != PROTOCOL_CAN &&
                state.header.protocol != PROTOCOL_J1939)
            {
                *err      = WTAP_ERR_UNSUPPORTED;
                *err_info = g_strdup("Unsupported protocol type");
                return FALSE;
            }

            if (wth->priv)
            {
                /* Check that the previous section has a footer */
                priv_entry = (busmaster_priv_t *)g_slist_last((GSList *)wth->priv)->data;

                if (priv_entry && priv_entry->file_end_offset == -1)
                {
                    *err      = WTAP_ERR_BAD_FILE;
                    *err_info = g_strdup("Footer is missing");
                    return FALSE;
                }
            }

            /* Start a new section */
            priv_entry = g_new(busmaster_priv_t, 1);

            priv_entry[0]                 = state.header;
            priv_entry->file_start_offset = file_tell(wth->fh);
            priv_entry->file_end_offset   = -1;

            wth->priv = g_slist_append((GSList *)wth->priv, priv_entry);
            break;
        case LOG_ENTRY_MSG:
            is_msg     = TRUE;
            priv_entry = busmaster_find_priv_entry(wth->priv, *data_offset);
            is_ok      = busmaster_gen_packet(rec, buf, priv_entry, &state.msg, err, err_info);
            break;
        case LOG_ENTRY_EOF:
        case LOG_ENTRY_ERROR:
        case LOG_ENTRY_NONE:
        default:
            is_ok = FALSE;
            break;
        }
    }

    busmaster_debug_printf("%s: stopped at offset %" PRIi64 " with entry %d\n",
                           G_STRFUNC, file_tell(wth->fh), entry);

    return is_ok;
}

static gboolean
busmaster_seek_read(wtap   *wth, gint64 seek_off, wtap_rec *rec,
                    Buffer *buf, int *err, gchar **err_info)
{
    busmaster_priv_t  *priv_entry;
    busmaster_state_t  state = {0};
    log_entry_type_t   entry;

    busmaster_debug_printf("%s: offset = %" PRIi64 "\n", G_STRFUNC, seek_off);

    priv_entry = busmaster_find_priv_entry(wth->priv, seek_off);
    if (!priv_entry)
    {
        busmaster_debug_printf("%s: analyzing output\n", G_STRFUNC);
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("Malformed header");
        return FALSE;
    }

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    state.header = *priv_entry;
    entry = busmaster_parse(wth->random_fh, &state, err, err_info);

    busmaster_debug_printf("%s: analyzing output\n", G_STRFUNC);

    if (entry == LOG_ENTRY_ERROR || entry == LOG_ENTRY_NONE)
        return FALSE;

    if (entry != LOG_ENTRY_MSG)
    {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("Failed to read a frame");
        return FALSE;
    }

    return busmaster_gen_packet(rec, buf, priv_entry, &state.msg, err, err_info);
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
