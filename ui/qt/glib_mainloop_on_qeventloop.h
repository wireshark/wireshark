/** @file
 *
 * Copyright 2022 Tomasz Mon <desowin@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef GLIB_MAINLOOP_ON_QEVENTLOOP_H
#define GLIB_MAINLOOP_ON_QEVENTLOOP_H

#include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <glib.h>

class GLibPoller : public QThread
{
    Q_OBJECT

protected:
    explicit GLibPoller(GMainContext *context);
    ~GLibPoller();

    void run() override;

    QMutex mutex_;
    QWaitCondition dispatched_;
    GMainContext *ctx_;
    gint priority_;
    GPollFD *fds_;
    gint allocated_fds_, nfds_;

signals:
    void polled(void);

    friend class GLibMainloopOnQEventLoop;
};

class GLibMainloopOnQEventLoop : public QObject
{
    Q_OBJECT

protected:
    explicit GLibMainloopOnQEventLoop(QObject *parent);
    ~GLibMainloopOnQEventLoop();

protected slots:
    void checkAndDispatch();

public:
    static void setup(QObject *parent);

protected:
    GLibPoller poller_;
};

#endif /* GLIB_MAINLOOP_ON_QEVENTLOOP_H */
