/* sync_pipe.h
 * Low-level synchronization pipe routines for use by Wireshark/TShark
 * and dumpcap
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


/** @file
 *
 *  Low-level sync pipe interfaces.
 */

#ifndef __SYNC_PIPE_H__
#define __SYNC_PIPE_H__


/*
 * Maximum length of sync pipe message data.  Must be < 2^24, as the
 * message length is 3 bytes.
 * XXX - this must be large enough to handle a Really Big Filter
 * Expression, as the error message for an incorrect filter expression
 * is a bit larger than the filter expression.
 */
#define SP_MAX_MSG_LEN  4096


/* Size of buffer to hold decimal representation of
   signed/unsigned 64-bit int */
#define SP_DECISIZE 20

/*
 * Indications sent out on the sync pipe (from child to parent).
 * We might want to switch to something like Thrift
 * (http://thrift.apache.org/) or Protocol Buffers
 * (http://code.google.com/p/protobuf-c/) if we ever need to use more
 * complex messages.
 */
#define SP_FILE         'F'     /* the name of the recently opened file */
#define SP_ERROR_MSG    'E'     /* error message */
#define SP_BAD_FILTER   'B'     /* error message for bad capture filter */
#define SP_PACKET_COUNT 'P'     /* count of packets captured since last message */
#define SP_DROPS        'D'     /* count of packets dropped in capture */
#define SP_SUCCESS      'S'     /* success indication, no extra data */
/*
 * Win32 only: Indications sent out on the signal pipe (from parent to child)
 * (UNIX-like sends signals for this)
 */
#define SP_QUIT         'Q'     /* "gracefully" capture quit message (SIGUSR1) */

/* write a single message header to the recipient pipe */
extern ssize_t
pipe_write_header(int pipe_fd, char indicator, int length);

/* write a message to the recipient pipe in the standard format
   (3 digit message length (excluding length and indicator field),
   1 byte message indicator and the rest is the message).
   If msg is NULL, the message has only a length and indicator. */
extern void
pipe_write_block(int pipe_fd, char indicator, const char *msg);

/** the child encountered an error, notify the parent */
extern void
sync_pipe_errmsg_to_parent(int pipe_fd, const char *error_msg,
                           const char *secondary_error_msg);

/** Has the parent signalled the child to stop? */
#define SIGNAL_PIPE_CTRL_ID_NONE "none"
#ifdef _WIN32
#define SIGNAL_PIPE_FORMAT "\\\\.\\pipe\\wireshark.%s.signal"
#endif

#endif /* sync_pipe.h */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
