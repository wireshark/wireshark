/** @file
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

#ifndef INTERFACE_STATS_WORKER_H
#define INTERFACE_STATS_WORKER_H

#include <config.h>

#include <wsutil/processes.h> /* for ws_process_id */

#include <QHash>
#include <QMetaType>
#include <QObject>
#include <QString>
#include <QStringList>

class QTimer;

/**
 * @brief Cumulative packet counters for a single interface, as reported by
 *        dumpcap's statistics stream.
 *
 * Values are cumulative since the underlying dumpcap statistics process was
 * started; consumers are responsible for any diffing they require.
 */
struct InterfaceStatsSample
{
    quint64 receivedPackets = 0; /**< Cumulative packets received (ps_recv). */
    quint64 droppedPackets = 0;  /**< Cumulative packets dropped (ps_drop). */
};

/** @brief A full set of per-interface counters keyed by interface name. */
typedef QHash<QString, InterfaceStatsSample> InterfaceStatsSnapshot;

Q_DECLARE_METATYPE(InterfaceStatsSample)
Q_DECLARE_METATYPE(InterfaceStatsSnapshot)

/**
 * @brief Worker that runs a dumpcap "-S" statistics stream off the GUI thread.
 *
 * The worker is designed to be moved onto a dedicated QThread. It owns the
 * dumpcap child process and its stat pipe, drains the pipe on a timer, and
 * emits a snapshot of the latest per-interface counters. It deliberately knows
 * nothing about the interface model, views, or the global capture options: the
 * application name is supplied by the caller so the same worker serves both
 * Wireshark and Stratoshark.
 *
 * Threading contract: every public slot is meant to be invoked through the
 * worker thread's event loop (queued/auto connections or
 * QMetaObject::invokeMethod), never called directly across threads. The slots
 * assert this.
 *
 * Lifetime/teardown: the worker creates no thread of its own; an owner moves it
 * onto a dedicated QThread and is responsible for destroying it safely using
 * the standard idiom, so the destructor (and thus closeStream()) runs on the
 * worker's own thread:
 * @code
 *   worker->moveToThread(&thread);
 *   connect(&thread, &QThread::finished, worker, &QObject::deleteLater);
 *   thread.start();
 *   // teardown:
 *   QMetaObject::invokeMethod(worker, &InterfaceStatsWorker::stop,
 *                             Qt::BlockingQueuedConnection);
 *   thread.quit();
 *   thread.wait();
 * @endcode
 * The destructor asserts it is run on the worker's own thread to catch misuse.
 * This worker is not a singleton: exactly one instance is expected, owned by
 * the (single) statistics facade, never instantiated ad hoc.
 */
class InterfaceStatsWorker : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an idle worker with the default update interval.
     * @param parent Optional parent QObject. Leave null when the worker will be
     *               moved to its own thread.
     */
    explicit InterfaceStatsWorker(QObject *parent = nullptr);

    /**
     * @brief Stops the stream (if running) and destroys the worker.
     */
    ~InterfaceStatsWorker() override;

    /**
     * @brief Returns the current pipe-drain/emit interval, in milliseconds.
     *
     * Seeded from a built-in default at construction; overridable via
     * setUpdateInterval() (e.g. from a preference).
     */
    int updateInterval() const;

public slots:
    /**
     * @brief Opens the dumpcap statistics stream and begins periodic sampling.
     *
     * Re-issuing start() while already running first tears down the existing
     * stream. On failure, failed() is emitted and no sampling occurs.
     */
    void start();

    /**
     * @brief Stops sampling and tears down the dumpcap stream and process.
     *
     * Clears the running state; a subsequent start() is required to resume.
     */
    void stop();

    /**
     * @brief Restricts which interfaces appear in emitted snapshots.
     *
     * dumpcap reports counters for every interface it can open; this filter is
     * applied only to the emitted snapshot. An empty list (the default) emits
     * every reported interface.
     *
     * @param interfaceNames Interface names to keep, or empty for all.
     */
    void setInterfaceFilter(const QStringList &interfaceNames);

    /**
     * @brief Sets the pipe-drain/emit interval.
     * @param intervalMsec Interval in milliseconds; values < 1 are ignored.
     */
    void setUpdateInterval(int intervalMsec);

    /**
     * @brief Tears down the dumpcap stream but remembers the configuration.
     *
     * Used to stop sampling (and free the dumpcap process) without forgetting
     * the application name or filter, e.g. while a capture is active. resume()
     * re-opens the stream. A no-op if not currently running.
     */
    void pause();

    /**
     * @brief Re-opens the stream previously suspended with pause().
     *
     * A no-op unless the worker is paused.
     */
    void resume();

signals:
    /** @brief Emitted once the dumpcap stream has been opened successfully. */
    void started();

    /** @brief Emitted after the stream and process have been torn down. */
    void stopped();

    /**
     * @brief Emitted when the stream could not be opened or has broken.
     * @param errorMessage Human-readable description.
     */
    void failed(const QString &errorMessage);

    /**
     * @brief Emitted each cycle in which new counters were read.
     * @param snapshot Latest cumulative per-interface counters.
     */
    void sampled(const InterfaceStatsSnapshot &snapshot);

private slots:
    /** @brief Timer-driven: drain the pipe and emit a snapshot if data arrived. */
    void poll();

private:
    /**
     * @brief Spawns dumpcap "-S" and records the pipe fd and child pid.
     * @return true on success; on failure emits failed() and returns false.
     */
    bool openStream();

    /** @brief Closes the pipe and terminates the dumpcap child, if any. */
    void closeStream();

    /** @brief Lazily creates (with correct thread affinity) and starts the timer. */
    void armTimer();

    /** @brief Stops the drain timer if it is running. */
    void disarmTimer();

    /** @brief Asserts the calling thread owns this object (threading contract). */
    void assertWorkerThread() const;

    QStringList interfaceFilter_; /**< Emit filter; empty means all. */
    int updateIntervalMsec_;      /**< Drain/emit interval. */
    QTimer *timer_;               /**< Drain timer, owned, lives in worker thread. */
    int statFd_;                  /**< Stat pipe fd, or -1 when closed. */
    ws_process_id forkChild_;     /**< dumpcap pid, or WS_INVALID_PID when closed. */
    bool paused_;                 /**< True between pause() and resume(). */
};

#endif // INTERFACE_STATS_WORKER_H
