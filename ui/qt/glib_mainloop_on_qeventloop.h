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

/**
 * @brief A background thread that polls a GLib main context.
 */
class GLibPoller : public QThread
{
    Q_OBJECT

protected:
    /**
     * @brief Constructs a new GLibPoller.
     * @param context The GLib main context to poll.
     */
    explicit GLibPoller(GMainContext *context);

    /**
     * @brief Destroys the GLibPoller.
     */
    ~GLibPoller();

    /**
     * @brief Executes the polling loop in the background thread.
     */
    void run() override;

    /** Mutex for thread synchronization. */
    QMutex mutex_;

    /** Condition variable to signal when events are dispatched. */
    QWaitCondition dispatched_;

    /** The GLib main context being polled. */
    GMainContext *ctx_;

    /** The maximum priority of the events to be dispatched. */
    int priority_;

    /** Array of file descriptors being polled. */
    GPollFD *fds_;

    /** The number of allocated file descriptors in the array. */
    int allocated_fds_;

    /** The number of active file descriptors being polled. */
    int nfds_;

signals:
    /**
     * @brief Signal emitted when the polling operation detects activity.
     */
    void polled(void);

    /** @brief Friend class allowing access to private members. */
    friend class GLibMainloopOnQEventLoop;
};

/**
 * @brief Integrates the GLib main loop with the Qt event loop.
 */
class GLibMainloopOnQEventLoop : public QObject
{
    Q_OBJECT

protected:
    /**
     * @brief Constructs a new GLibMainloopOnQEventLoop.
     * @param parent The parent QObject.
     */
    explicit GLibMainloopOnQEventLoop(QObject *parent);

    /**
     * @brief Destroys the GLibMainloopOnQEventLoop.
     */
    ~GLibMainloopOnQEventLoop();

protected slots:
    /**
     * @brief Slot triggered to check and dispatch pending GLib events on the Qt main thread.
     */
    void checkAndDispatch();

public:
    /**
     * @brief Sets up and initializes the GLib main loop integration.
     * @param parent The parent QObject to own the integration instance.
     */
    static void setup(QObject *parent);

protected:
    /** The poller thread managing the GLib context. */
    GLibPoller poller_;
};

#endif /* GLIB_MAINLOOP_ON_QEVENTLOOP_H */
