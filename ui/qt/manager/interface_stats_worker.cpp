/* interface_stats_worker.cpp
 *
 * Background worker that owns a dumpcap "-S" interface-statistics stream and
 * delivers periodic per-interface packet counters.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/manager/interface_stats_worker.h>

#include <glib.h>

#ifdef HAVE_LIBPCAP
#include <capture/capture_sync.h>
#endif

#include <wsutil/wslog.h>

#include <QThread>
#include <QTimer>

#ifdef HAVE_LIBPCAP
// dumpcap emits one short "name\trecv\tdrop" line per interface per report.
// Lines this long are never expected; the cap simply bounds a single read.
// Only the dumpcap pipe drain uses it, so it does not exist in no-pcap builds.
static constexpr int kMaxStatLineLen = 600;
#endif

// Built-in fallback pipe-drain/emit interval, in milliseconds. Used until the
// interval is overridden via setUpdateInterval() (e.g. from a preference).
static constexpr int kDefaultUpdateIntervalMsec = 1000;

InterfaceStatsWorker::InterfaceStatsWorker(QObject *parent) :
    QObject(parent),
    updateIntervalMsec_(kDefaultUpdateIntervalMsec),
    timer_(nullptr),
    statFd_(-1),
    forkChild_(WS_INVALID_PID),
    paused_(false)
{
    // The sampled() signal carries these across the worker/GUI thread boundary
    // via a queued connection, so they must be known to the meta-object system.
    qRegisterMetaType<InterfaceStatsSample>();
    qRegisterMetaType<InterfaceStatsSnapshot>();
}

InterfaceStatsWorker::~InterfaceStatsWorker()
{
    // The worker must be destroyed on the thread it lives on (the canonical
    // QThread::finished -> deleteLater idiom guarantees this) so that
    // closeStream() terminates the dumpcap child on the same thread that
    // spawned it. Deleting it from another thread while it is still running is
    // a bug; catch it in debug builds rather than leaking the process or
    // crashing.
    Q_ASSERT_X(thread() == QThread::currentThread(),
               "InterfaceStatsWorker",
               "must be destroyed on its own thread (use QThread::finished -> deleteLater)");
    closeStream();
}

void InterfaceStatsWorker::start()
{
    assertWorkerThread();

    paused_ = false;

    // start() doubles as a restart: drop any existing stream first.
    if (forkChild_ != WS_INVALID_PID)
        closeStream();

    if (!openStream())
        return; // openStream() has emitted failed()

    armTimer();
    emit started();
}

void InterfaceStatsWorker::stop()
{
    assertWorkerThread();

    disarmTimer();
    bool wasOpen = (forkChild_ != WS_INVALID_PID);
    closeStream();
    paused_ = false;

    if (wasOpen)
        emit stopped();
}

void InterfaceStatsWorker::setInterfaceFilter(const QStringList &interfaceNames)
{
    assertWorkerThread();
    interfaceFilter_ = interfaceNames;
}

void InterfaceStatsWorker::setUpdateInterval(int intervalMsec)
{
    assertWorkerThread();

    if (intervalMsec < 1)
        return;

    updateIntervalMsec_ = intervalMsec;
    if (timer_ && timer_->isActive())
        timer_->start(updateIntervalMsec_);
}

int InterfaceStatsWorker::updateInterval() const
{
    return updateIntervalMsec_;
}

void InterfaceStatsWorker::pause()
{
    assertWorkerThread();

    if (forkChild_ == WS_INVALID_PID)
        return; // not running; nothing to suspend

    disarmTimer();
    closeStream();
    paused_ = true;
    emit stopped();
}

void InterfaceStatsWorker::resume()
{
    assertWorkerThread();

    if (!paused_)
        return;

    paused_ = false;
    if (!openStream())
        return; // openStream() has emitted failed()

    armTimer();
    emit started();
}

void InterfaceStatsWorker::poll()
{
    assertWorkerThread();

    if (forkChild_ == WS_INVALID_PID)
        return;

    InterfaceStatsSnapshot snapshot;
    int read_result = 0;

#ifdef HAVE_LIBPCAP
    char line[kMaxStatLineLen];

    // Drain every line dumpcap has buffered this cycle. Each call returns a
    // single NUL-terminated line (>0), 0 when nothing more is available, or
    // -1 if the pipe has broken.
    while ((read_result = sync_pipe_gets_nonblock(statFd_, line, kMaxStatLineLen)) > 0) {
        g_strstrip(line);

        char **parts = g_strsplit(line, "\t", 3);
        if (parts[0] != nullptr && parts[0][0] != '\0' &&
            parts[1] != nullptr && parts[2] != nullptr) {
            QString name = QString::fromUtf8(parts[0]);
            if (interfaceFilter_.isEmpty() || interfaceFilter_.contains(name)) {
                InterfaceStatsSample sample;
                sample.receivedPackets = g_ascii_strtoull(parts[1], nullptr, 10);
                sample.droppedPackets = g_ascii_strtoull(parts[2], nullptr, 10);
                // A later report in the same drain supersedes an earlier one.
                snapshot.insert(name, sample);
            }
        }
        g_strfreev(parts);
    }
#endif // HAVE_LIBPCAP

    if (read_result < 0) {
        // The dumpcap child or pipe is gone; tear down and report.
        closeStream();
        disarmTimer();
        emit failed(tr("The interface statistics stream stopped unexpectedly."));
        return;
    }

    if (!snapshot.isEmpty())
        emit sampled(snapshot);
}

bool InterfaceStatsWorker::openStream()
{
#ifdef HAVE_LIBPCAP
    char *msg = nullptr;
    int stat_fd = -1;
    ws_process_id fork_child = WS_INVALID_PID;

    int ret = sync_interface_stats_open(&stat_fd, &fork_child,
                                        nullptr /* no -D -L; stats only */,
                                        &msg, nullptr /* no GUI update callback */);
    if (ret != 0) {
        QString err = (msg != nullptr)
                ? QString::fromUtf8(msg)
                : tr("Unable to start the interface statistics stream.");
        g_free(msg);
        emit failed(err);
        return false;
    }
    g_free(msg);

    statFd_ = stat_fd;
    forkChild_ = fork_child;
    return true;
#else
    emit failed(tr("This build has no packet capture support."));
    return false;
#endif // HAVE_LIBPCAP
}

void InterfaceStatsWorker::closeStream()
{
#ifdef HAVE_LIBPCAP
    if (forkChild_ != WS_INVALID_PID || statFd_ != -1) {
        char *msg = nullptr;
        if (sync_interface_stats_close(&statFd_, &forkChild_, &msg) == -1) {
            ws_warning("Closing interface statistics stream: %s",
                       (msg != nullptr) ? msg : "unknown error");
        }
        g_free(msg);
    }
#endif // HAVE_LIBPCAP

    statFd_ = -1;
    forkChild_ = WS_INVALID_PID;
}

void InterfaceStatsWorker::armTimer()
{
    if (timer_ == nullptr) {
        // Created here (in the worker thread) so its timer events fire here.
        timer_ = new QTimer(this);
        timer_->setTimerType(Qt::CoarseTimer);
        connect(timer_, &QTimer::timeout, this, &InterfaceStatsWorker::poll);
    }
    timer_->start(updateIntervalMsec_);
}

void InterfaceStatsWorker::disarmTimer()
{
    if (timer_ != nullptr)
        timer_->stop();
}

void InterfaceStatsWorker::assertWorkerThread() const
{
    Q_ASSERT_X(thread() == QThread::currentThread(),
               "InterfaceStatsWorker",
               "slot invoked from a foreign thread; use a queued connection");
}
