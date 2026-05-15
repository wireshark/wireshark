/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_TOOLBAR_READER_H
#define INTERFACE_TOOLBAR_READER_H

#include <QObject>
#include <QByteArray>

#ifdef _WIN32
#include <windows.h>
#endif

namespace Ui {
class InterfaceToolbarReader;
}

/**
 * @brief A reader thread component that listens to a control pipe for incoming messages from an interface.
 */
class InterfaceToolbarReader : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new InterfaceToolbarReader.
     * @param ifname The name of the interface being monitored.
     * @param control_in The operating-system-specific handle or path for the input control pipe.
     * @param parent The parent QObject, defaults to 0.
     */
    InterfaceToolbarReader(QString ifname, void *control_in, QObject *parent = 0) :
        QObject(parent),
        ifname_(ifname),
#ifdef _WIN32
        control_in_((HANDLE)control_in)
#else
        control_in_((char *)control_in),
        fd_in_(-1)
#endif
    {
    }

public slots:
    /**
     * @brief The main polling loop that continuously reads from the control pipe.
     */
    void loop();

signals:
    /**
     * @brief Signal emitted when a complete control message is successfully read.
     * @param ifname The name of the interface that sent the message.
     * @param num The control number.
     * @param command The command type.
     * @param payload The raw byte array payload of the message.
     */
    void received(QString ifname, int num, int command, QByteArray payload);

    /**
     * @brief Signal emitted when the reader loop finishes or terminates.
     */
    void finished();

private:
#ifdef _WIN32
    /**
     * @brief Performs an asynchronous read from a named pipe on Windows.
     * @param data Pointer to the buffer to store the read data.
     * @param nbyte The number of bytes to read.
     * @return The number of bytes successfully read, or -1 on error.
     */
    int async_pipe_read(void *data, int nbyte);
#endif

    /**
     * @brief Reads a specified number of bytes from the control pipe.
     * @param data Pointer to the buffer to store the read data.
     * @param nbyte The number of bytes to read.
     * @return The number of bytes successfully read, or -1 on error.
     */
    int pipe_read(char *data, int nbyte);

    /** The name of the interface being monitored. */
    QString ifname_;

#ifdef _WIN32
    /** The Windows handle to the named pipe. */
    HANDLE control_in_;
#else
    /** The file path to the named pipe/FIFO on POSIX systems. */
    QString control_in_;
    /** The file descriptor for the open pipe on POSIX systems. */
    int fd_in_;
#endif
};

#endif // INTERFACE_TOOLBAR_READER_H
