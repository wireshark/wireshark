/* sync_pipe_write.c
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

#include "sync_pipe.h"

/****************************************************************************************************************/
/* sync_pipe handling */


/* write a single message header to the recipient pipe */
static ssize_t
sync_pipe_write_header(int pipe_fd, char indicator, unsigned int length)
{
    unsigned char header[1+3]; /* indicator + 3-byte len */

    ws_assert(length <= SP_MAX_MSG_LEN);

    /* write header (indicator + 3-byte len) */
    header[0] = indicator;
    header[1] = (length >> 16) & 0xFF;
    header[2] = (length >> 8) & 0xFF;
    header[3] = (length >> 0) & 0xFF;

    /* write header */
    return ws_write(pipe_fd, header, sizeof header);
}


/* Write a message, with a string body, to the recipient pipe in the
   standard format (1-byte message indicator, 3-byte message length
   (excluding length and indicator field), and the string.
   If msg is NULL, the message has only a length and indicator. */
void
sync_pipe_write_string_msg(int pipe_fd, char indicator, const char *msg)
{
    ssize_t ret;
    int len;

    /*ws_warning("write %d enter", pipe_fd);*/

    if(msg != NULL) {
        len = (int) strlen(msg) + 1;    /* including the terminating '\0'! */
    } else {
        len = 0;
    }

    /* write header (indicator + 3-byte len) */
    ret = sync_pipe_write_header(pipe_fd, indicator, len);
    if(ret == -1) {
        return;
    }

    /* write value (if we have one) */
    if(len) {
        /*ws_warning("write %d indicator: %c value len: %u msg: %s", pipe_fd, indicator, len, msg);*/
        ret = ws_write(pipe_fd, msg, len);
        if(ret == -1) {
            return;
        }
    } else {
        /*ws_warning("write %d indicator: %c no value", pipe_fd, indicator);*/
    }

    /*ws_warning("write %d leave", pipe_fd);*/
}


/* Size of buffer to hold decimal representation of
   signed/unsigned 64-bit int */
#define SP_DECISIZE 20

/* Write a message, with an unsigned integer body, to the recipient
   pipe in the standard format (1-byte message indicator, 3-byte
   message length (excluding length and indicator field), and the
   unsigned integer, as a string. */
void
sync_pipe_write_uint_msg(int pipe_fd, char indicator, unsigned int num)
{
    char count_str[SP_DECISIZE+1+1];

    snprintf(count_str, sizeof(count_str), "%u", num);
    sync_pipe_write_string_msg(pipe_fd, indicator, count_str);
}

/* Write a message, with an integer body, to the recipient pipe in the
   standard format (1-byte message indicator, 3-byte message length
   (excluding length and indicator field), and the unsigned integer,
   as a string. */
void
sync_pipe_write_int_msg(int pipe_fd, char indicator, int num)
{
    char count_str[SP_DECISIZE+1+1];

    snprintf(count_str, sizeof(count_str), "%d", num);
    sync_pipe_write_string_msg(pipe_fd, indicator, count_str);
}

/* Write a message, with a primary and secondary error message as the body,
   to the recipient pipe.  The header is an SP_ERROR_MSG header, with the
   length being the length of two string submessages; the submessages
   are the body of the message, with each submessage being a message
   with an indicator of SP_ERROR_MSG, the first message having the
   primary error message string and the second message having the secondary
   error message string. */
void
sync_pipe_write_errmsgs_to_parent(int pipe_fd, const char *error_msg,
                                  const char *secondary_error_msg)
{
    sync_pipe_write_header(pipe_fd, SP_ERROR_MSG,
                           (unsigned int) (strlen(error_msg) + 1 + 4 + strlen(secondary_error_msg) + 1 + 4));
    sync_pipe_write_string_msg(pipe_fd, SP_ERROR_MSG, error_msg);
    sync_pipe_write_string_msg(pipe_fd, SP_ERROR_MSG, secondary_error_msg);
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
