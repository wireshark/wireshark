/* interface_statistics.cpp
 *
 * Single source of truth for live per-interface capture statistics. Owns the
 * off-thread sampler, performs diffing, and retains bounded history.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI

#include <ui/qt/manager/interface_statistics.h>


#include <wsutil/wslog.h>

#include <QTimer>

// Default per-interface history cap, in entries (not time, so it stays bounded
// regardless of the sampling interval). ~1 hour at a 1 s interval; far more than
// a sparkline can display, but cheap (~14 KB/interface).
static constexpr int kDefaultHistoryCapacity = 3600;

// Fallback sampling interval, in milliseconds, mirrored down to the worker.
static constexpr int kDefaultUpdateIntervalMsec = 1000;

// Sentinel appended to a history buffer to mark an unsampled gap (e.g. while a
// capture was running). Real deltas are >= 0, so a negative value is unambiguous;
// SparkLineDelegate renders it as a line break with a dashed bridge.
static constexpr int kGapMarker = -1;

// After an unexpected worker failure (e.g. dumpcap -S exits because a monitored
// interface disappeared), wait this long before restarting the stream. Long
// enough to let the interface list settle, and it bounds the retry rate should
// the failure be persistent.
static constexpr int kRestartDelayMsec = 1000;

InterfaceStatistics::InterfaceStatistics(QObject *parent) :
    QObject(parent),
    worker_(new InterfaceStatsWorker), // no parent: it is moved to workerThread_
    historyCapacity_(kDefaultHistoryCapacity),
    updateIntervalMsec_(kDefaultUpdateIntervalMsec),
    running_(false),
    paused_(false)
{
    worker_->moveToThread(&workerThread_);

    // Destroy the worker on its own thread once the thread's loop has finished,
    // so its destructor (and closeStream()) runs on the worker thread.
    connect(&workerThread_, &QThread::finished, worker_, &QObject::deleteLater);

    // Facade -> worker. These cross the thread boundary, so the default
    // auto-connection resolves to a queued connection.
    connect(this, &InterfaceStatistics::startWorker, worker_, &InterfaceStatsWorker::start);
    connect(this, &InterfaceStatistics::stopWorker, worker_, &InterfaceStatsWorker::stop);
    connect(this, &InterfaceStatistics::pauseWorker, worker_, &InterfaceStatsWorker::pause);
    connect(this, &InterfaceStatistics::resumeWorker, worker_, &InterfaceStatsWorker::resume);
    connect(this, &InterfaceStatistics::setWorkerInterval, worker_, &InterfaceStatsWorker::setUpdateInterval);
    connect(this, &InterfaceStatistics::setWorkerFilter, worker_, &InterfaceStatsWorker::setInterfaceFilter);

    // Worker -> facade.
    connect(worker_, &InterfaceStatsWorker::sampled, this, &InterfaceStatistics::onSampled);
    connect(worker_, &InterfaceStatsWorker::failed, this, &InterfaceStatistics::onWorkerFailed);

    workerThread_.setObjectName(QStringLiteral("InterfaceStats"));
    workerThread_.start();
}

InterfaceStatistics::~InterfaceStatistics()
{
    if (workerThread_.isRunning()) {
        // Tear the dumpcap stream down synchronously on the worker thread, then
        // stop the loop; finished() triggers the worker's deleteLater.
        InterfaceStatsWorker *worker = worker_;
        QMetaObject::invokeMethod(worker, [worker]() { worker->stop(); },
                                  Qt::BlockingQueuedConnection);
        workerThread_.quit();
        workerThread_.wait();
    }
}

QList<int> InterfaceStatistics::pointsFor(const QString &interfaceName) const
{
    return receivedHistory_.value(interfaceName);
}

QList<int> InterfaceStatistics::droppedPointsFor(const QString &interfaceName) const
{
    return droppedHistory_.value(interfaceName);
}

bool InterfaceStatistics::isActive(const QString &interfaceName) const
{
    return active_.contains(interfaceName);
}

unsigned InterfaceStatistics::rate(const QString &interfaceName) const
{
    const QList<int> points = receivedHistory_.value(interfaceName);
    if (points.isEmpty() || points.constLast() < 0) // empty or a gap marker
        return 0u;
    return static_cast<unsigned>(points.constLast());
}

int InterfaceStatistics::updateInterval() const
{
    return updateIntervalMsec_;
}

int InterfaceStatistics::historyCapacity() const
{
    return historyCapacity_;
}

bool InterfaceStatistics::isRunning() const
{
    return running_;
}

void InterfaceStatistics::start()
{
    if (running_)
        return;

#ifdef HAVE_LIBPCAP
    paused_ = false;
    resetBaselines();

    emit setWorkerInterval(updateIntervalMsec_);
    emit setWorkerFilter(interfaceFilter_);

    emit startWorker();
    running_ = true;
#endif // HAVE_LIBPCAP
}

void InterfaceStatistics::stop()
{
    if (!running_)
        return;

    emit stopWorker();
    running_ = false;
    paused_ = false;
}

void InterfaceStatistics::pauseSampling()
{
    if (!running_ || paused_)
        return;

    emit pauseWorker();
    // A resumed stream spawns a fresh dumpcap whose counters restart from zero;
    // drop the baselines so the first post-resume samples don't look like a spike.
    resetBaselines();
    paused_ = true;
}

void InterfaceStatistics::resumeSampling()
{
    if (!running_ || !paused_)
        return;

    emit resumeWorker();
    paused_ = false;

    // Mark the (just-ended) capture interval as a one-slot gap in each
    // interface's history, so the sparkline shows a break with a dashed bridge
    // rather than a line drawn straight across the unsampled span. The gap is a
    // single sample wide regardless of how long the capture ran.
    bool inserted = false;
    for (auto it = receivedHistory_.begin(); it != receivedHistory_.end(); ++it) {
        QList<int> &received = it.value();
        if (received.isEmpty() || received.constLast() == kGapMarker)
            continue;
        appendCapped(received, kGapMarker);
        appendCapped(droppedHistory_[it.key()], kGapMarker);
        inserted = true;
    }
    if (inserted)
        emit statisticsUpdated();
}

void InterfaceStatistics::setUpdateInterval(int intervalMsec)
{
    if (intervalMsec < 1)
        return;

    updateIntervalMsec_ = intervalMsec;
    emit setWorkerInterval(intervalMsec);
}

void InterfaceStatistics::setInterfaceFilter(const QStringList &interfaceNames)
{
    interfaceFilter_ = interfaceNames;
    emit setWorkerFilter(interfaceNames);
}

void InterfaceStatistics::removeInterfaces(const QStringList &removedInterfaceNames)
{
    // QHash::remove() and QSet::remove() share the same shape, so a single loop
    // clears every container without the QHash/QSet iterator asymmetry.
    bool activityDidChange = false;
    for (const QString &name : removedInterfaceNames) {
        lastReceived_.remove(name);
        lastDropped_.remove(name);
        receivedHistory_.remove(name);
        droppedHistory_.remove(name);
        if (active_.remove(name))
            activityDidChange = true;
    }
    if (activityDidChange)
        emit activityChanged();
}

void InterfaceStatistics::resetActivity()
{
    // Forget the latched activity so the next samples re-mark only interfaces
    // that are still showing traffic; history and diff baselines are kept.
    if (active_.isEmpty())
        return;
    active_.clear();
    emit activityChanged();
}

void InterfaceStatistics::setHistoryCapacity(int maxEntries)
{
    if (maxEntries < 1)
        return;

    // Growing or leaving the cap unchanged cannot make any existing buffer
    // exceed it, so only a shrink needs trimming.
    const bool needsTrim = maxEntries < historyCapacity_;
    historyCapacity_ = maxEntries;
    if (!needsTrim)
        return;

    // Range-for over a QHash iterates its values; trim each buffer to the cap.
    for (QList<int> &buffer : receivedHistory_)
        trimToCapacity(buffer);
    for (QList<int> &buffer : droppedHistory_)
        trimToCapacity(buffer);
}

void InterfaceStatistics::onSampled(const InterfaceStatsSnapshot &snapshot)
{
    // Performance note (monitor): this iterates the snapshot, which holds one
    // entry per interface - a small, bounded set that does NOT grow with session
    // length, so the loop stays cheap. The only work that scales with the history
    // cap is appendCapped()'s front-trim, which shifts the QList (O(capacity))
    // once a buffer is full; that is negligible at realistic interface counts.
    // If the cap or the interface count ever grows large, switch the per-interface
    // history to a ring buffer for O(1) appends (reads would then linearize).
    // active_ only grows here (interfaces are never deactivated mid-stream), so a
    // size change means a newly-active interface and a sort-affecting event.
    const qsizetype activeBefore = active_.size();

    for (auto it = snapshot.cbegin(); it != snapshot.cend(); ++it) {
        const QString &name = it.key();
        const InterfaceStatsSample &sample = it.value();

        // Default the baseline to the current value so a first/just-reset
        // sample yields a zero delta rather than a spurious spike.
        const quint64 prevReceived = lastReceived_.value(name, sample.receivedPackets);
        const quint64 prevDropped = lastDropped_.value(name, sample.droppedPackets);

        const int receivedDelta = (sample.receivedPackets >= prevReceived)
                ? static_cast<int>(sample.receivedPackets - prevReceived) : 0;
        const int droppedDelta = (sample.droppedPackets >= prevDropped)
                ? static_cast<int>(sample.droppedPackets - prevDropped) : 0;

        lastReceived_[name] = sample.receivedPackets;
        lastDropped_[name] = sample.droppedPackets;

        appendCapped(receivedHistory_[name], receivedDelta);
        appendCapped(droppedHistory_[name], droppedDelta);

        // Mark active on observed traffic. Using the (reset-tolerant) delta, not
        // the cumulative count, is what lets resetActivity() drop a now-quiet
        // interface: after a manual refresh clears the set, a quiet interface
        // produces a zero delta and is not re-marked. The flag is otherwise held
        // across implicit rescans and pause/resume for a stable sort order.
        if (receivedDelta > 0)
            active_.insert(name);
    }

    if (active_.size() != activeBefore)
        emit activityChanged();
    emit statisticsUpdated();
}

void InterfaceStatistics::onWorkerFailed(const QString &message)
{
    ws_warning("Interface statistics worker: %s", qUtf8Printable(message));
    running_ = false;

    // dumpcap -S exits if a monitored interface disappears (unplugged/removed),
    // which would otherwise freeze the sparklines permanently. Restart the stream
    // after a short delay so a fresh dumpcap re-enumerates the current interfaces.
    // Re-check state when the timer fires: skip if a capture paused us in the
    // meantime, or if a refresh already restarted the worker.
    if (!paused_) {
        QTimer::singleShot(kRestartDelayMsec, this, [this]() {
            if (!running_ && !paused_)
                start();
        });
    }
}

void InterfaceStatistics::appendCapped(QList<int> &buffer, int value) const
{
    buffer.append(value);
    trimToCapacity(buffer);
}

void InterfaceStatistics::trimToCapacity(QList<int> &buffer) const
{
    if (buffer.size() > historyCapacity_)
        buffer.remove(0, buffer.size() - historyCapacity_);
}

void InterfaceStatistics::resetBaselines()
{
    lastReceived_.clear();
    lastDropped_.clear();
}
