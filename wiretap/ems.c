/* ems.c
 *
 * File format support for EGNOS Message Server files
 * Copyright (c) 2023 by Timo Warns <timo.warns@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include "ems.h"

#include <stdio.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/buffer.h>
#include <wsutil/nstime.h>
#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>

static bool ems_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, char
        **err_info, int64_t *data_offset);
static bool ems_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, Buffer
        *buf, int *err, char **err_info);

#define MAX_EMS_LINE_LEN 256
#define EMS_MSG_SIZE 40

typedef struct ems_msg_s {
    unsigned int prn;
    unsigned int year;
    unsigned int month;
    unsigned int day;
    unsigned int hour;
    unsigned int minute;
    unsigned int second;
    unsigned int mt;
    char sbas_msg[64];
} ems_msg_t;

static int ems_file_type_subtype = -1;

/**
 * Gets one character and returns in case of error.
 * Without error, peeks at next character and returns it.
 */
static int get_and_peek(FILE_T fh) {
    int c;

    c = file_getc(fh);

    if (c < 0) {
        return c;
    }

    return file_peekc(fh);
}

/**
 * Peeks / returns next relevant character.
 * Skips whitespace at the beginning of a line, comment lines, and empty
 * lines.
 */
static int peek_relevant_character(FILE_T fh) {
    int c;

    while (true) {
        c = file_peekc(fh);

        if (c < 0) {
            return c;
        }

        // ignore whitespace at the beginning of a line
        else if (g_ascii_isspace(c)) {
            ws_debug("ignoring whitespace at the beginning of line");
            do {
                c = get_and_peek(fh);
                if (c < 0) {
                    return c;
                }
            } while (g_ascii_isspace(c));

            continue;
        }

        // ignore comment and empty lines
        else if (c == '\r' || c == '\n' || c == '#') {
            ws_debug("ignoring comment or empty line");
            do {
                c = get_and_peek(fh);
                if (c < 0) {
                    return c;
                }
            } while (c != '\n');

            continue;
        }

        // return current character for further inspection
        else {
            return c;
        }
    }
}

/**
 * Parses EMS line to ems_msg struct.
 * Return false on error, true otherwise.
 */
static bool parse_ems_line(FILE_T fh, ems_msg_t* ems_msg) {
    char line[MAX_EMS_LINE_LEN];
    int i;

    if (!file_gets(line, array_length(line), fh)) {
        return false;
    }

    i = sscanf(line, "%03u %02u %02u %02u %02u %02u %02u %u %64c",
                &ems_msg->prn,
                &ems_msg->year,
                &ems_msg->month,
                &ems_msg->day,
                &ems_msg->hour,
                &ems_msg->minute,
                &ems_msg->second,
                &ems_msg->mt,
                ems_msg->sbas_msg);
    if (9 != i) {
        return false;
    }

    if (ems_msg->prn > 255 ||
            ems_msg->year > 255 ||
            ems_msg->month > 12 ||
            ems_msg->day > 31 ||
            ems_msg->hour > 23 ||
            ems_msg->minute > 59 ||
            ems_msg->second > 59 ||
            ems_msg->mt > 255) {
        return false;
    }

    return true;
}

wtap_open_return_val ems_open(wtap *wth, int *err, char **err_info) {
    int c;
    ems_msg_t msg;

    ws_debug("opening file");

    // skip irrelevant characters
    c = peek_relevant_character(wth->fh);
    if (c < 0) {
        if (file_eof(wth->fh)) {
            return WTAP_OPEN_NOT_MINE;
        }
        *err = file_error(wth->fh, err_info);
        return WTAP_OPEN_ERROR;
    }

    // EMS nav msg lines start with a digit (first digit of PRN).
    // Check whether current line starts with a digit.
    if (!g_ascii_isdigit(c)) {
        return WTAP_OPEN_NOT_MINE;
    }

    // Check whether the current line matches the EMS format
    if (parse_ems_line(wth->fh, &msg)) {
        /* return to the beginning of the file */
        if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
            *err = file_error(wth->fh, err_info);
            return WTAP_OPEN_ERROR;
        }

        wth->file_encap = WTAP_ENCAP_EMS;
        wth->snapshot_length = 0;
        wth->file_tsprec = WTAP_TSPREC_SEC;
        wth->subtype_read = ems_read;
        wth->subtype_seek_read = ems_seek_read;
        wth->file_type_subtype = ems_file_type_subtype;

        return WTAP_OPEN_MINE;
    }

    return WTAP_OPEN_NOT_MINE;
}

static bool ems_read_message(FILE_T fh, wtap_rec *rec, Buffer *buf,
        int *err, char **err_info) {

    int c;
    ems_msg_t msg;

    // skip irrelevant characters
    c = peek_relevant_character(fh);
    if (c < 0) {
        *err = file_error(fh, err_info);
        return false;
    }

    // parse line with EMS message
    if (parse_ems_line(fh, &msg)) {
        char ts[NSTIME_ISO8601_BUFSIZE + 1];

        ws_buffer_assure_space(buf, EMS_MSG_SIZE);

        ws_buffer_end_ptr(buf)[0] = msg.prn;
        ws_buffer_end_ptr(buf)[1] = msg.year;
        ws_buffer_end_ptr(buf)[2] = msg.month;
        ws_buffer_end_ptr(buf)[3] = msg.day;
        ws_buffer_end_ptr(buf)[4] = msg.hour;
        ws_buffer_end_ptr(buf)[5] = msg.minute;
        ws_buffer_end_ptr(buf)[6] = msg.second;
        ws_buffer_end_ptr(buf)[7] = msg.mt;

        int i;
        for (i = 0; i < 32; i++) {
            uint8_t v;
            char s[3] = {msg.sbas_msg[i*2], msg.sbas_msg[i*2+1], 0};
            if (!ws_hexstrtou8(s, NULL, &v)) {
                return false;
            }
            ws_buffer_end_ptr(buf)[8 + i] = v;
        }

        ws_buffer_increase_length(buf, EMS_MSG_SIZE);

        rec->rec_type = REC_TYPE_PACKET;
        rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
        rec->presence_flags = WTAP_HAS_TS;
        rec->rec_header.packet_header.len = EMS_MSG_SIZE;
        rec->rec_header.packet_header.caplen = EMS_MSG_SIZE;

        // use EMS timestamp as packet timestamp
        snprintf(ts, sizeof(ts), "%04u-%02u-%02uT%02u:%02u:%02uZ", msg.year
                + 2000, msg.month, msg.day, msg.hour, msg.minute, msg.second);
        iso8601_to_nstime(&rec->ts, ts, ISO8601_DATETIME);

        return true;
    }

    return false;
}

static bool ems_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, char
        **err_info, int64_t *offset) {

    *offset = file_tell(wth->fh);
    ws_debug("reading at offset %" PRId64, *offset);

    if (!ems_read_message(wth->fh, rec, buf, err, err_info)) {
        return false;
    }

    return true;
}

static bool ems_seek_read(wtap *wth, int64_t offset, wtap_rec *rec, Buffer
        *buf, int *err, char **err_info) {

    if (file_seek(wth->random_fh, offset, SEEK_SET, err) == -1) {
        *err = file_error(wth->fh, err_info);
        return false;
    }

    if (!ems_read_message(wth->random_fh, rec, buf, err, err_info)) {
        return false;
    }

    return true;
}

static const struct supported_block_type ems_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info ems_info = {
    "EGNOS Message Server File Format", "ems", "ems", "ems",
    false, BLOCKS_SUPPORTED(ems_blocks_supported),
    NULL, NULL, NULL
};

void register_ems(void)
{
    ems_file_type_subtype = wtap_register_file_type_subtype(&ems_info);

    wtap_register_backwards_compatibility_lua_name("EMS",
            ems_file_type_subtype);
}
