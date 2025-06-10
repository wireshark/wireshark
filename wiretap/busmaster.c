/* busmaster.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Busmaster log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * See https://rbei-etas.github.io/busmaster/ for the BUSMASTER software.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "busmaster.h"

#include <socketcan.h>
#include <file_wrappers.h>
#include <epan/dissectors/packet-socketcan.h>
#include <wsutil/exported_pdu_tlvs.h>
#include "busmaster_priv.h"
#include <inttypes.h>
#include <string.h>
#include <errno.h>

static void
busmaster_close(wtap *wth);

static bool
busmaster_read(wtap   *wth, wtap_rec *rec,
               int    *err, char **err_info,
               int64_t *data_offset);

static bool
busmaster_seek_read(wtap     *wth, int64_t seek_off,
                    wtap_rec *rec,
                    int      *err, char **err_info);

static int busmaster_file_type_subtype = -1;

void register_busmaster(void);


static bool
busmaster_gen_packet(wtap* wth,
    wtap_rec* rec,
    const busmaster_priv_t* priv_entry, const msg_t* msg,
    int* err, char** err_info)
{
    wtap_can_msg_t     can_msg;
    bool has_ts = false;

    can_msg.id = msg->id;
    can_msg.type = msg->type;
    can_msg.flags = 0;     //Not used by BUSMASTER
    can_msg.data = msg->data;

    //Need to convert the timestamp
    if (priv_entry->time_mode == TIME_MODE_SYSTEM)
    {
        struct tm tm;

        tm.tm_year = priv_entry->start.d.year - 1900;
        tm.tm_mon = priv_entry->start.d.month - 1;
        tm.tm_mday = priv_entry->start.d.day;
        tm.tm_hour = msg->timestamp.hours;
        tm.tm_min = msg->timestamp.minutes;
        tm.tm_sec = msg->timestamp.seconds;
        tm.tm_isdst = -1;

        can_msg.ts.secs = mktime(&tm);
        can_msg.ts.nsecs = msg->timestamp.micros * 1000u;
        has_ts = true;
    }
    else if (priv_entry->time_mode == TIME_MODE_ABSOLUTE)
    {
        struct tm tm;
        uint32_t  micros;

        tm.tm_year = priv_entry->start.d.year - 1900;
        tm.tm_mon = priv_entry->start.d.month - 1;
        tm.tm_mday = priv_entry->start.d.day;
        tm.tm_hour = priv_entry->start.t.hours;
        tm.tm_min = priv_entry->start.t.minutes;
        tm.tm_sec = priv_entry->start.t.seconds;
        tm.tm_isdst = -1;

        can_msg.ts.secs = mktime(&tm);

        can_msg.ts.secs += msg->timestamp.hours * 3600;
        can_msg.ts.secs += msg->timestamp.minutes * 60;
        can_msg.ts.secs += msg->timestamp.seconds;

        micros = priv_entry->start.t.micros + msg->timestamp.micros;
        if (micros >= 1000000u)
        {
            micros -= 1000000u;
            can_msg.ts.secs += 1;
        }

        can_msg.ts.nsecs = micros * 1000u;
        has_ts = true;
    }
    else
    {
        can_msg.ts.secs = 0;
        can_msg.ts.nsecs = 0;
    }

    if (!wtap_socketcan_gen_packet(wth, rec, &can_msg, "busmaster", err, err_info))
        return false;

    //Packet may not have timestamp
    if (!has_ts)
        rec->presence_flags &= (~WTAP_HAS_TS);
    return true;
}

static log_entry_type_t
busmaster_parse(FILE_T fh, busmaster_state_t *state, int *err, char **err_info)
{
    bool ok;
    int64_t  seek_off;

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
    wtap_set_as_socketcan(wth, busmaster_file_type_subtype, WTAP_TSPREC_USEC);

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
busmaster_find_priv_entry(void *priv, int64_t offset)
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

static bool
busmaster_read(wtap   *wth, wtap_rec *rec, int *err, char **err_info,
               int64_t *data_offset)
{
    log_entry_type_t   entry;
    busmaster_state_t  state;
    busmaster_priv_t  *priv_entry;
    bool               is_msg = false;
    bool               is_ok = true;

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
            return false;
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
                return false;
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
                return false;
            }

            if (wth->priv)
            {
                /* Check that the previous section has a footer */
                priv_entry = (busmaster_priv_t *)g_slist_last((GSList *)wth->priv)->data;

                if (priv_entry && priv_entry->file_end_offset == -1)
                {
                    *err      = WTAP_ERR_BAD_FILE;
                    *err_info = g_strdup("Footer is missing");
                    return false;
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
            is_msg     = true;
            priv_entry = busmaster_find_priv_entry(wth->priv, *data_offset);
            is_ok  = busmaster_gen_packet(wth, rec, priv_entry, &state.msg, err, err_info);
            break;
        case LOG_ENTRY_EOF:
        case LOG_ENTRY_ERROR:
        case LOG_ENTRY_NONE:
        default:
            is_ok = false;
            break;
        }
    }

    busmaster_debug_printf("%s: stopped at offset %" PRIi64 " with entry %d\n",
                           G_STRFUNC, file_tell(wth->fh), entry);

    return is_ok;
}

static bool
busmaster_seek_read(wtap   *wth, int64_t seek_off, wtap_rec *rec,
                    int *err, char **err_info)
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
        return false;
    }

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    state.header = *priv_entry;
    entry = busmaster_parse(wth->random_fh, &state, err, err_info);

    busmaster_debug_printf("%s: analyzing output\n", G_STRFUNC);

    if (entry == LOG_ENTRY_ERROR || entry == LOG_ENTRY_NONE)
        return false;

    if (entry != LOG_ENTRY_MSG)
    {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("Failed to read a frame");
        return false;
    }

    return busmaster_gen_packet(wth, rec, priv_entry, &state.msg, err, err_info);
}

static const struct supported_block_type busmaster_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info busmaster_info = {
    "BUSMASTER log file", "busmaster", "log", NULL,
    false, BLOCKS_SUPPORTED(busmaster_blocks_supported),
    NULL, NULL, NULL
};

void register_busmaster(void)
{
    busmaster_file_type_subtype = wtap_register_file_type_subtype(&busmaster_info);
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
