/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VOIP_CALLS_INFO_MODEL_H
#define VOIP_CALLS_INFO_MODEL_H

#include <config.h>

#include "ui/voip_calls.h"
#include <ui/qt/utils/variant_pointer.h>

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>

/**
 * @brief Table model that exposes a list of VoIP call records for display in
 *        the VoIP Calls dialog, supporting both relative and time-of-day
 *        timestamp formatting.
 */
class VoipCallsInfoModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the model with an empty call list.
     * @param parent Optional parent QObject.
     */
    VoipCallsInfoModel(QObject *parent = 0);

    /**
     * @brief Returns display or decoration data for the given cell.
     * @param index Model index of the cell to query.
     * @param role  Qt item data role.
     * @return The requested data, or an invalid QVariant if not applicable.
     */
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Returns column header labels for the VoIP calls table.
     * @param section     Column index.
     * @param orientation Qt::Horizontal for column headers.
     * @param role        Qt item data role.
     * @return Header label string, or an invalid QVariant if not applicable.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

    /**
     * @brief Returns the number of call records currently held by the model.
     * @param parent Unused; must be an invalid index for table models.
     * @return Number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns in the model.
     * @param parent Unused.
     * @return Number of columns (Column::ColumnCount).
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Controls whether timestamps are shown as time-of-day or relative times.
     * @param timeOfDay @c true to display absolute time-of-day; @c false for relative.
     */
    void setTimeOfDay(bool timeOfDay);

    /**
     * @brief Returns whether timestamps are currently shown as time-of-day values.
     * @return @c true if time-of-day display is active.
     */
    bool timeOfDay() const;

    /**
     * @brief Replaces the model's call list with the contents of @p callsinfos and
     *        notifies the view to refresh.
     * @param callsinfos GQueue of voip_calls_info_t pointers to display.
     */
    void updateCalls(GQueue *callsinfos);

    /**
     * @brief Removes all call records from the model and notifies the view.
     */
    void removeAllCalls();

    /**
     * @brief Returns the voip_calls_info_t record associated with @p index.
     * @param index Model index whose row identifies the call record.
     * @return Pointer to the voip_calls_info_t, or @c nullptr if the index is invalid.
     */
    static voip_calls_info_t *indexToCallInfo(const QModelIndex &index);

    /**
     * @brief Column indices for the VoIP calls table.
     */
    enum Column
    {
        StartTime,       /**< Timestamp of the first packet in the call. */
        StopTime,        /**< Timestamp of the last packet in the call. */
        InitialSpeaker,  /**< Address of the party that initiated the call. */
        From,            /**< Calling party address or URI. */
        To,              /**< Called party address or URI. */
        Protocol,        /**< Signalling protocol (e.g. SIP, H.323). */
        Duration,        /**< Total duration of the call. */
        Packets,         /**< Number of packets belonging to the call. */
        State,           /**< Current call state (e.g. CALL, COMPLETED). */
        Comments,        /**< Free-text comments or extra protocol info. */
        ColumnCount      /**< Sentinel value; not an actual column. */
    };

private:
    QList<void *> callinfos_;  /**< Ordered list of voip_calls_info_t pointers. */
    bool          mTimeOfDay_; /**< @c true if timestamps are shown as time-of-day. */

    /**
     * @brief Formats a timestamp for display according to the current time mode.
     * @param abs_ts Absolute (wall-clock) timestamp.
     * @param rel_ts Relative timestamp from the start of the capture.
     * @return Formatted timestamp string as a QVariant.
     */
    QVariant timeData(nstime_t *abs_ts, nstime_t *rel_ts) const;
};


/**
 * @brief Sort proxy model for VoipCallsInfoModel that provides column-aware
 *        comparisons, handling numeric and duration columns correctly.
 */
class VoipCallsInfoSortedModel : public QSortFilterProxyModel
{
public:
    /**
     * @brief Constructs the sort proxy model.
     * @param parent Optional parent QObject.
     */
    VoipCallsInfoSortedModel(QObject *parent = 0);

protected:
    /**
     * @brief Compares two rows for sorting, using type-appropriate comparisons
     *        for numeric, duration, and string columns.
     * @param source_left  Index of the left-hand item in the source model.
     * @param source_right Index of the right-hand item in the source model.
     * @return @c true if @p source_left should sort before @p source_right.
     */
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override;
};

#endif // VOIP_CALLS_INFO_MODEL_H
