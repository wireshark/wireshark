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

#include "sync_pipe.h"

/****************************************************************************************************************/
/* sync_pipe handling */


/* write a single message header to the recipient pipe */
ssize_t
pipe_write_header(int pipe_fd, char indicator, int length)
{
    guchar header[1+3]; /* indicator + 3-byte len */


    g_assert(length <= SP_MAX_MSG_LEN);

    /* write header (indicator + 3-byte len) */
    header[0] = indicator;
    header[1] = (length >> 16) & 0xFF;
    header[2] = (length >> 8) & 0xFF;
    header[3] = (length >> 0) & 0xFF;

    /* write header */
    return ws_write(pipe_fd, header, sizeof header);
}


/* write a message to the recipient pipe in the standard format
   (3 digit message length (excluding length and indicator field),
   1 byte message indicator and the rest is the message).
   If msg is NULL, the message has only a length and indicator. */
void
pipe_write_block(int pipe_fd, char indicator, const char *msg)
{
    ssize_t ret;
    int len;

    /*g_warning("write %d enter", pipe_fd);*/

    if(msg != NULL) {
        len = (int) strlen(msg) + 1;    /* including the terminating '\0'! */
    } else {
        len = 0;
    }

    /* write header (indicator + 3-byte len) */
    ret = pipe_write_header(pipe_fd, indicator, len);
    if(ret == -1) {
        return;
    }

    /* write value (if we have one) */
    if(len) {
        /*g_warning("write %d indicator: %c value len: %u msg: %s", pipe_fd, indicator, len, msg);*/
        ret = ws_write(pipe_fd, msg, len);
        if(ret == -1) {
            return;
        }
    } else {
        /*g_warning("write %d indicator: %c no value", pipe_fd, indicator);*/
    }

    /*g_warning("write %d leave", pipe_fd);*/
}


void
sync_pipe_errmsg_to_parent(int pipe_fd, const char *error_msg,
                           const char *secondary_error_msg)
{
    /* Write a message header containing the length of the two messages followed by the primary and secondary error messagess */
    pipe_write_header(pipe_fd, SP_ERROR_MSG, (int) (strlen(error_msg) + 1 + 4 + strlen(secondary_error_msg) + 1 + 4));
    pipe_write_block(pipe_fd, SP_ERROR_MSG, error_msg);
    pipe_write_block(pipe_fd, SP_ERROR_MSG, secondary_error_msg);
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
