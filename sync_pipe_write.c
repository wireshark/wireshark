/* sync_pipe_write.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <io.h>
#endif

#include <glib.h>

#include "sync_pipe.h"
#include "log.h"

/****************************************************************************************************************/
/* sync_pipe handling */


/* write a single message header to the recipient pipe */
int
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
    return write(pipe_fd, header, sizeof header);
}


/* write a message to the recipient pipe in the standard format 
   (3 digit message length (excluding length and indicator field), 
   1 byte message indicator and the rest is the message).
   If msg is NULL, the message has only a length and indicator. */
void
pipe_write_block(int pipe_fd, char indicator, const char *msg)
{
    int ret;
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
        ret = (int) write(pipe_fd, msg, len);
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

    /* first write a "master header" with the length of the two messages plus their "slave headers" */
    pipe_write_header(pipe_fd, SP_ERROR_MSG, (int) (strlen(error_msg) + 1 + 4 + strlen(secondary_error_msg) + 1 + 4));
    pipe_write_block(pipe_fd, SP_ERROR_MSG, error_msg);
    pipe_write_block(pipe_fd, SP_ERROR_MSG, secondary_error_msg);
}
