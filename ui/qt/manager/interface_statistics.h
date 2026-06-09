/** @file
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

#ifndef INTERFACE_STATISTICS_H
#define INTERFACE_STATISTICS_H

#include <config.h>

#include <ui/qt/manager/interface_stats_worker.h>

#include <QHash>
#include <QList>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QThread>

/**
 * @brief GUI-thread facade that owns the interface-statistics sampler and is the
 *        single source of truth for per-interface history.
 *
 * Responsibilities:
 *  - Owns one InterfaceStatsWorker living on a dedicated QThread, with the
 *    standard finished -> deleteLater teardown.
 *  - Receives cumulative counter snapshots from the worker (queued, cross-thread)
 *    and converts them to per-interval deltas, tolerating counter resets (e.g.
 *    after a pause/resume cycle spawns a fresh dumpcap).
 *  - Keeps each interface's delta history in a fixed-capacity FIFO buffer so a
 *    long-running session stays bounded; history and the "active" flag survive
 *    interface-list rescans and are pruned only for interfaces that disappear.
 *  - Latches an interface "active" once it has shown any traffic, giving a stable
 *    activity-first sort order.
 *
 * All accessors and accumulated state are confined to the GUI thread; the only
 * cross-thread interaction is the signal/slot bridge to the worker. The facade
 * is expected to be owned by the MainWindow base class (shared by both flavors),
 * not by MainApplication.
 */
class InterfaceStatistics : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the facade and starts the worker thread (idle).
     *
     * Sampling does not begin until start() is called.
     * @param parent Optional parent QObject.
     */
    explicit InterfaceStatistics(QObject *parent = nullptr);

    /**
     * @brief Tears down the worker and its thread safely, then destroys.
     */
    ~InterfaceStatistics() override;

    /**
     * @brief Received-packet deltas for an interface, oldest to newest.
     *
     * This is the series drawn by the interface sparkline.
     * @param interfaceName The interface name.
     * @return The bounded delta history, or an empty list if unknown.
     */
    QList<int> pointsFor(const QString &interfaceName) const;

    /**
     * @brief Dropped-packet deltas for an interface, oldest to newest.
     *
     * Parallel to pointsFor(); intended for future sparkline drop annotation.
     * @param interfaceName The interface name.
     * @return The bounded drop-delta history, or an empty list if unknown.
     */
    QList<int> droppedPointsFor(const QString &interfaceName) const;

    /**
     * @brief Whether an interface is currently considered active for sorting.
     *
     * Set when a positive received-packet delta is observed, and held across
     * implicit interface-list rescans and capture pause/resume so the
     * activity-first sort order stays stable. It is re-evaluated only by
     * resetActivity() (the hook a *manual* interface refresh calls), at which
     * point an interface that has gone quiet correctly drops to inactive.
     * @param interfaceName The interface name.
     * @return true if the interface is currently considered active.
     */
    bool isActive(const QString &interfaceName) const;

    /**
     * @brief Most recent received-packet delta for an interface.
     * @param interfaceName The interface name.
     * @return The latest delta, or 0 if unknown.
     */
    unsigned rate(const QString &interfaceName) const;

    /** @brief Returns the current sampling interval, in milliseconds. */
    int updateInterval() const;

    /** @brief Returns the per-interface history capacity, in entries. */
    int historyCapacity() const;

    /** @brief Returns true between start() and stop() (sampling requested). */
    bool isRunning() const;

public slots:
    /**
     * @brief Begins sampling: opens the dumpcap statistics stream via the worker.
     *
     * A no-op if already running.
     */
    void start();

    /** @brief Stops sampling and tears down the dumpcap stream. */
    void stop();

    /**
     * @brief Temporarily suspends sampling (e.g. while a capture is active).
     *
     * Frees the dumpcap process but retains accumulated history and active
     * flags; the diff baseline is reset so resume() does not produce a spike.
     */
    void pauseSampling();

    /** @brief Resumes sampling previously suspended with pauseSampling(). */
    void resumeSampling();

    /**
     * @brief Sets the sampling interval and forwards it to the worker.
     * @param intervalMsec Interval in milliseconds; values < 1 are ignored.
     */
    void setUpdateInterval(int intervalMsec);

    /**
     * @brief Restricts which interfaces are sampled/emitted (empty = all).
     * @param interfaceNames Interface names to keep.
     */
    void setInterfaceFilter(const QStringList &interfaceNames);

    /**
     * @brief Drops all retained state for the given (vanished) interfaces.
     *
     * Called when the interface list changes; surviving interfaces keep their
     * history and active flag. Implicit/automatic rescans should call only this;
     * a manual refresh additionally calls resetActivity().
     * @param removedInterfaceNames Interface names that no longer exist.
     */
    void removeInterfaces(const QStringList &removedInterfaceNames);

    /**
     * @brief Re-evaluates interface activity, e.g. on a manual interface refresh.
     *
     * Clears the latched active set so that, on subsequent samples, only
     * interfaces still showing traffic are re-marked active; interfaces that
     * have gone quiet drop to inactive. History and diff baselines are kept.
     * Implicit/automatic rescans should NOT call this (to avoid a spurious sort
     * reshuffle); only a user-initiated refresh should.
     */
    void resetActivity();

    /**
     * @brief Sets the per-interface history capacity in entries.
     * @param maxEntries Maximum retained samples per interface; values < 1
     *        are ignored. Existing buffers are trimmed to the new cap.
     */
    void setHistoryCapacity(int maxEntries);

signals:
    /** @brief Emitted after a worker snapshot has been folded into the history. */
    void statisticsUpdated();

    /**
     * @brief Emitted when the set of active interfaces changes.
     *
     * Distinct from statisticsUpdated() (which fires every sampling cycle): this
     * fires only when activity actually changes, so consumers can re-sort by
     * activity without churning on every tick.
     */
    void activityChanged();

    /// @cond INTERNAL
    /* Bridge signals to the worker (queued across the thread boundary). */
    void startWorker();
    void stopWorker();
    void pauseWorker();
    void resumeWorker();
    void setWorkerInterval(int intervalMsec);
    void setWorkerFilter(const QStringList &interfaceNames);
    /// @endcond

private slots:
    /** @brief Folds a cumulative-counter snapshot into per-interface history. */
    void onSampled(const InterfaceStatsSnapshot &snapshot);

    /** @brief Logs a worker failure and clears the running state. */
    void onWorkerFailed(int exitCode, const QString &message);

private:
    /** @brief Appends a value to a history buffer, dropping the oldest if full. */
    void appendCapped(QList<int> &buffer, int value) const;

    /** @brief Drops the oldest entries so a buffer fits the history capacity. */
    void trimToCapacity(QList<int> &buffer) const;

    /** @brief Forgets diff baselines so the next samples start fresh. */
    void resetBaselines();

    InterfaceStatsWorker *worker_;            /**< Owned; lives on worker_thread_. */
    QThread workerThread_;                    /**< Owned worker thread. */

    QHash<QString, quint64> lastReceived_;    /**< Last cumulative recv per iface. */
    QHash<QString, quint64> lastDropped_;     /**< Last cumulative drop per iface. */
    QHash<QString, QList<int> > receivedHistory_; /**< FIFO recv-delta history. */
    QHash<QString, QList<int> > droppedHistory_;  /**< FIFO drop-delta history. */
    QSet<QString> active_;                    /**< Interfaces ever seen active. */

    QStringList interfaceFilter_;             /**< Emit/sample filter; empty = all. */
    int historyCapacity_;                     /**< Max entries per interface. */
    int updateIntervalMsec_;                  /**< Sampling interval mirror. */
    bool running_;                            /**< True between start() and stop(). */
    bool paused_;                             /**< True while suspended. */
    bool warned_no_interfaces_;               /**< True if already warned about no valid interfaces. */
};

#endif // INTERFACE_STATISTICS_H
