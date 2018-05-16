/* interface_toolbar_reader.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#include "interface_toolbar_reader.h"
#include "sync_pipe.h"
#include "wsutil/file_util.h"

#include <QThread>

const int header_size = 6;

#ifdef _WIN32
int InterfaceToolbarReader::async_pipe_read(void *data, int nbyte)
{
    BOOL success;
    DWORD nof_bytes_read;
    OVERLAPPED overlap;
    int bytes_read = -1;

    overlap.Pointer = 0;
    overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (overlap.hEvent == NULL)
    {
        // CreateEvent failed with error code GetLastError()
        return -1;
    }

    success = ReadFile(control_in_, data, nbyte, &nof_bytes_read, &overlap);

    if (success && nof_bytes_read != 0)
    {
        // The read operation completed successfully.
        bytes_read = nof_bytes_read;
    }
    else if (!success && GetLastError() == ERROR_IO_PENDING)
    {
        // The operation is still pending, wait for a signal.
        if (WaitForSingleObject(overlap.hEvent, INFINITE) == WAIT_OBJECT_0)
        {
            // The wait operation has completed.
            success = GetOverlappedResult(control_in_, &overlap, &nof_bytes_read, FALSE);

            if (success && nof_bytes_read != 0)
            {
                // The get result operation completed successfully.
                bytes_read = nof_bytes_read;
            }
        }
    }

    CloseHandle(overlap.hEvent);
    return bytes_read;
}
#endif

int InterfaceToolbarReader::pipe_read(char *data, int nbyte)
{
    int total_len = 0;

    while (total_len < nbyte)
    {
        char *data_ptr = data + total_len;
        int data_len = nbyte - total_len;

#ifdef _WIN32
        int read_len = async_pipe_read(data_ptr, data_len);
#else
        int read_len = (int)ws_read(fd_in_, data_ptr, data_len);
#endif
        if (read_len == -1)
        {
            if (errno != EAGAIN)
            {
                return -1;
            }
        }
        else
        {
            total_len += read_len;
        }

        if (QThread::currentThread()->isInterruptionRequested())
        {
            return -1;
        }
    }

    return total_len;
}

void InterfaceToolbarReader::loop()
{
    QByteArray header;
    QByteArray payload;

#ifndef _WIN32
    struct timeval timeout;
    fd_set readfds;
    fd_in_ = ws_open(control_in_.toUtf8(), O_RDONLY | O_BINARY | O_NONBLOCK, 0);

    if (fd_in_ == -1)
    {
        emit finished();
        return;
    }
#endif

    header.resize(header_size);

    forever
    {
#ifndef _WIN32
        FD_ZERO(&readfds);
        FD_SET(fd_in_, &readfds);

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        int ret = select(fd_in_ + 1, &readfds, NULL, NULL, &timeout);
        if (ret == -1)
        {
            break;
        }

        if (QThread::currentThread()->isInterruptionRequested())
        {
            break;
        }

        if (ret == 0 || !FD_ISSET(fd_in_, &readfds))
        {
            continue;
        }
#endif

        // Read the header from the pipe.
        if (pipe_read(header.data(), header_size) != header_size)
        {
            break;
        }

        unsigned char high_nibble = header[1] & 0xFF;
        unsigned char mid_nibble = header[2] & 0xFF;
        unsigned char low_nibble = header[3] & 0xFF;
        int payload_len = (int)((high_nibble << 16) + (mid_nibble << 8) + low_nibble) - 2;

        payload.resize(payload_len);
        // Read the payload from the pipe.
        if (pipe_read(payload.data(), payload_len) != payload_len)
        {
            break;
        }

        if (header[0] == SP_TOOLBAR_CTRL)
        {
            emit received(ifname_, (unsigned char)header[4], (unsigned char)header[5], payload);
        }
    }

#ifndef _WIN32
    ws_close(fd_in_);
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
