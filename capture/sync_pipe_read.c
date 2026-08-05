/* sync_pipe_read.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <string.h>

#include <glib.h>

#include <wsutil/file_util.h>
#include <wsutil/ws_assert.h>
#include <wsutil/pint.h>

#include <capture/sync_pipe.h>

/****************************************************************************************************************/
/* sync_pipe reading */

/* convert header values (indicator and 3-byte length) */
void
sync_pipe_convert_header(const unsigned char *header, char *indicator, unsigned *block_len) {

    /* convert header values */
    *indicator = pntohu8(&header[0]);
    *block_len = pntohu24(&header[1]);
}

/* read a number of bytes from a pipe */
/* (blocks until enough bytes read or an error occurs) */
static ssize_t
pipe_read_bytes(GIOChannel *pipe_io, char *bytes, size_t required, char **msg)
{
    GError *err = NULL;
    size_t newly;
    size_t offset = 0;

    /*
     * This should never happen, as "required" should be no greater than 2^24.
     *
     * XXX - 64-bit Haiku defines ssize_t as an signed long int but defines
     * SSIZE_MAX as a signed long long int; they're the same width, but
     * gcc warns of a type mismatch between %zd and signed long long int.
     * We cast SSIZE_MAX to (ssize_t) to squelch the warning.
     */
    if (required > SSIZE_MAX) {
        ws_debug("read from pipe %p: bytes to read %zu > %zd", pipe_io, required, (ssize_t)SSIZE_MAX);
        *msg = ws_strdup_printf("Error reading from sync pipe: bytes to read %zu > %zd", required, (ssize_t)SSIZE_MAX);
        return -1;
    }
    while(required) {
        if (g_io_channel_read_chars(pipe_io, &bytes[offset], required, &newly, &err) == G_IO_STATUS_ERROR) {
            if (err != NULL) {
                ws_debug("read from pipe %p: error(%u): %s", pipe_io, err->code, err->message);
                *msg = ws_strdup_printf("Error reading from sync pipe: %s", err->message);
                g_clear_error(&err);
            } else {
                ws_debug("read from pipe %p: unknown error", pipe_io);
                *msg = ws_strdup_printf("Error reading from sync pipe: unknown error");
            }
            return -1;
        }
        if (newly == 0) {
            /* EOF */
            ws_debug("read from pipe %p: EOF (capture closed?)", pipe_io);
            *msg = NULL;
            /*
             * offset is, at this point, known to be less than the value of
             * required passed to us, which is guaranteed to fit in an ssize_t.
             */
            return (ssize_t)offset;
        }

        required -= newly;
        offset += newly;
    }

    /*
     * offset is, at this point, known to be equal to the value of
     * required passed to us, which is guaranteed to fit in an ssize_t.
     */
    *msg = NULL;
    return (ssize_t)offset;
}

/* read a message from the sending pipe in the standard format
   (1-byte message indicator, 3-byte message length (excluding length
   and indicator field), and the rest is the message) */
ssize_t
sync_pipe_read_block(GIOChannel *pipe_io, char *indicator, unsigned len, char *msg,
                char **err_msg)
{
    unsigned required;
    ssize_t newly;
    char header[4];

    /* read header (indicator and 3-byte length) */
    newly = pipe_read_bytes(pipe_io, header, 4, err_msg);
    if(newly != 4) {
        if(newly == -1) {
            /*
             * Error; *err_msg has been set.
             */
            ws_debug("read %p got an error reading header: %s", pipe_io, *err_msg);
            return -1;
        }
        if(newly == 0) {
            /*
             * Immediate EOF; if the capture child exits normally, this
             * is an "I'm done" indication, so don't report it as an
             * error.
             */
            ws_debug("read %p got an EOF reading header", pipe_io);
            return 0;
        }
        /*
         * Short read, but not an immediate EOF.
         */
        ws_debug("read %p got premature EOF reading header: %zd", pipe_io, newly);
        *err_msg = ws_strdup_printf("Premature EOF reading from sync pipe: got only %zd bytes",
                                    newly);
        return -1;
    }

    /* convert header values */
    sync_pipe_convert_header((unsigned char*)header, indicator, &required);

    /* only indicator with no value? */
    if(required == 0) {
        ws_debug("read %p indicator: %c empty value", pipe_io, *indicator);
        return 4;
    }

    /* does the data fit into the given buffer? */
    if(required > len) {
        size_t bytes_read;
        GError *err = NULL;
        ws_debug("read %p length error, required %d > len %d, header: 0x%02x 0x%02x 0x%02x 0x%02x",
              pipe_io, required, len,
              header[0], header[1], header[2], header[3]);

        /* we have a problem here, try to read some more bytes from the pipe to debug where the problem really is */
        if (g_io_channel_read_chars(pipe_io, msg, len, &bytes_read, &err) == G_IO_STATUS_ERROR) {
            if (err != NULL) { /* error */
                ws_debug("read from pipe %p: error(%u): %s", pipe_io, err->code, err->message);
                g_clear_error(&err);
            } else {
                ws_debug("read from pipe %p: unknown error", pipe_io);
            }
        }
        *err_msg = ws_strdup_printf("Message %c from dumpcap with length %d > buffer size %d! Partial message: %s",
                                    *indicator, required, len, msg);
        return -1;
    }
    len = required;

    /* read the actual block data */
    newly = pipe_read_bytes(pipe_io, msg, required, err_msg);
    if(newly == -1) {
        /*
         * Error; *err_msg has been set.
         */
        ws_debug("read %p got an error reading block data: %s", pipe_io, *err_msg);
        return -1;
    }

    /*
     * newly is guaranteed to be >= 0 at this point, as pipe_read_bytes()
     * either returns -1 on an error, a positive value <= required on
     * a short read, or required on a non-short read.
     */
    if((size_t)newly != required) {
        *err_msg = ws_strdup_printf("Unknown message from dumpcap reading data, try to show it as a string: %s",
                                    msg);
        return -1;
    }

    /* XXX If message is "2part", the msg probably won't be sent to debug log correctly */
    ws_debug("read %p ok indicator: %c len: %u msg: %s", pipe_io, *indicator, len, msg);
    *err_msg = NULL;
    return newly + 4;
}
