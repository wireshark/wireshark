/** @file
 *
 * Copyright 2022 Tomasz Mon <desowin@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QTimer>
#include "glib_mainloop_on_qeventloop.h"

GLibPoller::GLibPoller(GMainContext *context) :
    mutex_(), dispatched_(),
    ctx_(context), priority_(0),
    fds_(g_new(GPollFD, 1)), allocated_fds_(1), nfds_(0)
{
    g_main_context_ref(ctx_);
}

GLibPoller::~GLibPoller()
{
    g_main_context_unref(ctx_);
    g_free(fds_);
}

void GLibPoller::run()
{
    gint timeout;

    mutex_.lock();
    while (!isInterruptionRequested())
    {
        while (!g_main_context_acquire(ctx_))
        {
            /* In normal circumstances context is acquired right away */
        }
        g_main_context_prepare(ctx_, &priority_);
        while ((nfds_ = g_main_context_query(ctx_, priority_, &timeout, fds_,
                                             allocated_fds_)) > allocated_fds_)
        {
            g_free(fds_);
            fds_ = g_new(GPollFD, nfds_);
            allocated_fds_ = nfds_;
        }
        /* Blocking g_poll() call is the reason for separate polling thread */
        g_poll(fds_, nfds_, timeout);
        g_main_context_release(ctx_);

        /* Polling has finished, dispatch events (if any) in main thread so we
         * don't have to worry about concurrency issues in GLib callbacks.
         */
        emit polled();
        /* Wait for the main thread to finish dispatching before next poll */
        dispatched_.wait(&mutex_);
    }
    mutex_.unlock();
}

GLibMainloopOnQEventLoop::GLibMainloopOnQEventLoop(QObject *parent) :
    QObject(parent),
    poller_(g_main_context_default())
{
    connect(&poller_, &GLibPoller::polled,
            this, &GLibMainloopOnQEventLoop::checkAndDispatch);
    poller_.setObjectName("GLibPoller");
    poller_.start();
}

GLibMainloopOnQEventLoop::~GLibMainloopOnQEventLoop()
{
    poller_.requestInterruption();
    /* Wakeup poller thread in case it is blocked on g_poll(). Wakeup does not
     * cause any problem if poller thread is already waiting on dispatched wait
     * condition.
     */
    g_main_context_wakeup(poller_.ctx_);
    /* Wakeup poller thread without actually dispatching */
    poller_.mutex_.lock();
    poller_.dispatched_.wakeOne();
    poller_.mutex_.unlock();
    /* Poller thread will quit, wait for it to avoid warning */
    poller_.wait();
}

void GLibMainloopOnQEventLoop::checkAndDispatch()
{
    poller_.mutex_.lock();
    while (!g_main_context_acquire(poller_.ctx_))
    {
        /* In normal circumstances context is acquired right away */
    }
    if (g_main_depth() > 0)
    {
        /* This should not happen, but if it does warn about nested event loops
         * so the issue can be fixed before the harm is done. To identify root
         * cause, put breakpoint here and take backtrace when it hits. Look for
         * calls to exec() and processEvents() functions. Refactor the code so
         * it does not spin additional event loops.
         *
         * Ignoring this warning will lead to very strange and hard to debug
         * problems in the future.
         */
        qWarning("Nested GLib event loop detected");
    }
    if (g_main_context_check(poller_.ctx_, poller_.priority_,
                             poller_.fds_, poller_.nfds_))
    {
        g_main_context_dispatch(poller_.ctx_);
    }
    g_main_context_release(poller_.ctx_);
    /* Start next iteration in GLibPoller thread */
    poller_.dispatched_.wakeOne();
    poller_.mutex_.unlock();
}

void GLibMainloopOnQEventLoop::setup(QObject *parent)
{
    /* Schedule event loop action so we can check if Qt runs GLib mainloop */
    QTimer::singleShot(0, [parent]() {
        if (g_main_depth() == 0)
        {
            /* Not running inside GLib mainloop, actually setup */
            new GLibMainloopOnQEventLoop(parent);
        }
    });
}
