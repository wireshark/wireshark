/* ems.c
 *
 * File format support for EGNOS Message Server files
 * See "Multi-Band EGNOS File Format Description Document" (ESA-EGN-EPO-ICD-0031, Issue 1.4)
 *
 * Copyright (c) 2023 by Timo Warns <timo.warns@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include "ems.h"

#include <stdio.h>

#include "wtap_module.h"
#include "file_wrappers.h"

#include <wsutil/buffer.h>
#include <wsutil/nstime.h>
#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>

static bool ems_read(wtap *wth, wtap_rec *rec, int *err, char
        **err_info, int64_t *data_offset);
static bool ems_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
        int *err, char **err_info);

#define MAX_EMS_LINE_LEN 1024
#define EMS_MSG_SIZE 40

typedef char ems_line[MAX_EMS_LINE_LEN];

typedef struct ems_msg_s {
    unsigned int prn;
    unsigned int year;
    unsigned int month;
    unsigned int day;
    unsigned int hour;
    unsigned int minute;
    unsigned int second;
    unsigned int second_frac;
    char band[3];
    unsigned int nof_bits;
    unsigned int mt;
    char sbas_msg[64];
} ems_msg_t;

static int ems_file_type_subtype = -1;

/**
 * Parses an EMS line.
 * Return false on error, true otherwise.
 */
static bool parse(ems_line *line, ems_msg_t *msg) {
    int i;

    // try to parse for L1
    i = sscanf((char *)line, "%03u %02u %02u %02u %02u %02u %02u %u %64c",
                &msg->prn,
                &msg->year,
                &msg->month,
                &msg->day,
                &msg->hour,
                &msg->minute,
                &msg->second,
                &msg->mt,
                msg->sbas_msg);

    if (9 != i) {
        // L1 parsing failed, try to parse for L5 or non-standard message encoding
        i = sscanf((char *)line, "%03u %02u %02u %02u %02u %02u %02u.%06u %2s %04x %02u",
                    &msg->prn,
                    &msg->year,
                    &msg->month,
                    &msg->day,
                    &msg->hour,
                    &msg->minute,
                    &msg->second,
                    &msg->second_frac,
                    (char *)&msg->band,
                    &msg->nof_bits,
                    &msg->mt);

        if (11 != i) {
          // L5 / non-standard message parsing failed as well. So,
          // return with error.
          return false;
        }
    }

    // Do some basic validation
    // - SBAS PRNs are limited to 128, ..., 158 by the ICAO SARPS
    // - basic date & time constraints
    // - SBAS has defined MTs up to 63 only
    if (msg->prn < 120 || msg->prn > 158 ||
            msg->year > 255 ||
            msg->month > 12 ||
            msg->day > 31 ||
            msg->hour > 23 ||
            msg->minute > 59 ||
            msg->second > 59 ||
            msg->mt > 63) {
        return false;
    }

    return true;
}

wtap_open_return_val ems_open(wtap *wth, int *err, char **err_info) {
    ems_line line;
    ems_msg_t msg;

    ws_debug("opening file");

    // read complete EMS line
    if (!file_gets((char *)line, MAX_EMS_LINE_LEN, wth->fh)) {
        return WTAP_OPEN_ERROR;
    }

    // Check whether the current line can be parsed.
    if (parse(&line, &msg)) {
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

static bool ems_read_message(wtap *wth, FILE_T fh, wtap_rec *rec,
        int *err, char **err_info) {

    ems_line line;
    ems_msg_t msg = {.second_frac = 0};
    char *end;

    // get complete EMS line
    end = file_getsp((char *)line, MAX_EMS_LINE_LEN, fh);
    if (!end) {
        *err = file_error(fh, err_info);
        return false;
    }

    // Check whether the current line can be parsed.
    if (parse(&line, &msg)) {
        char ts[NSTIME_ISO8601_BUFSIZE + 1];

        ws_buffer_append(&rec->data, line, end - line);

        wtap_setup_packet_rec(rec, wth->file_encap);
        rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
        rec->presence_flags = WTAP_HAS_TS;
        rec->rec_header.packet_header.len = (uint32_t) (end - line);
        rec->rec_header.packet_header.caplen = (uint32_t) (end - line);

        // use EMS timestamp as packet timestamp
        snprintf(ts, sizeof(ts), "%04u-%02u-%02uT%02u:%02u:%02u.%06uZ",
                 msg.year + 2000, msg.month, msg.day, msg.hour, msg.minute,
                 msg.second, msg.second_frac);
        iso8601_to_nstime(&rec->ts, ts, ISO8601_DATETIME);

        return true;
    }

    return false;
}

static bool ems_read(wtap *wth, wtap_rec *rec, int *err, char **err_info,
    int64_t *offset) {

    *offset = file_tell(wth->fh);
    ws_debug("reading at offset %" PRId64, *offset);

    if (!ems_read_message(wth, wth->fh, rec, err, err_info)) {
        return false;
    }

    return true;
}

static bool ems_seek_read(wtap *wth, int64_t offset, wtap_rec *rec,
        int *err, char **err_info) {

    if (file_seek(wth->random_fh, offset, SEEK_SET, err) == -1) {
        *err = file_error(wth->random_fh, err_info);
        return false;
    }

    if (!ems_read_message(wth, wth->random_fh, rec, err, err_info)) {
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
