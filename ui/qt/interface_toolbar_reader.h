/* interface_toolbar_reader.h
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

class InterfaceToolbarReader : public QObject
{
    Q_OBJECT

public:
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
    void loop();

signals:
    void received(QString ifname, int num, int command, QByteArray payload);
    void finished();

private:
#ifdef _WIN32
    int async_pipe_read(void *data, int nbyte);
#endif
    int pipe_read(char *data, int nbyte);

    QString ifname_;
#ifdef _WIN32
    HANDLE control_in_;
#else
    QString control_in_;
    int fd_in_;
#endif
};

#endif // INTERFACE_TOOLBAR_READER_H

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
