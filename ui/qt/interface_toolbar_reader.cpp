/* interface_toolbar_reader.cpp
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#include "interface_toolbar_reader.h"
#include "sync_pipe.h"
#include "wsutil/file_util.h"

#include <QThread>

const int header_size = 6;

// To do:
// - Add support for WIN32

void InterfaceToolbarReader::loop()
{
#ifndef _WIN32
    struct timeval timeout;
    QByteArray header;
    QByteArray payload;
    fd_set readfds;

    int fd = ws_open(control_in_.toUtf8(), O_RDONLY | O_BINARY | O_NONBLOCK, 0);
    if (fd == -1)
    {
        emit finished();
        return;
    }

    forever
    {
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        int ret = select(fd + 1, &readfds, NULL, NULL, &timeout);
        if (ret == -1)
        {
            break;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 2, 0)
        if (QThread::currentThread()->isInterruptionRequested())
        {
            break;
        }
#endif

        if (ret > 0 && FD_ISSET(fd, &readfds))
        {
            header.resize(header_size);
            if (ws_read(fd, header.data(), header_size) != header_size)
            {
                break;
            }

            unsigned char high_nibble = header[1] & 0xFF;
            unsigned char mid_nibble = header[2] & 0xFF;
            unsigned char low_nibble = header[3] & 0xFF;
            ssize_t payload_len = (ssize_t)((high_nibble << 16) + (mid_nibble << 8) + low_nibble) - 2;

            payload.resize((int)payload_len);
            if (payload_len > 0)
            {
                ssize_t total_len = 0;
                while (total_len < payload_len)
                {
                    ssize_t read_len = ws_read(fd, payload.data() + total_len, payload_len - total_len);
                    if (read_len == -1)
                    {
                        if (errno != EAGAIN)
                        {
                            break;
                        }
                    }
                    else
                    {
                        total_len += read_len;
                    }
                }
                if (total_len != payload_len)
                {
                    break;
                }
            }
            if (header[0] == SP_TOOLBAR_CTRL)
            {
                emit received(ifname_, (unsigned char)header[4], (unsigned char)header[5], payload);
            }
        }
    }

    ws_close(fd);
#endif
    emit finished();
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
