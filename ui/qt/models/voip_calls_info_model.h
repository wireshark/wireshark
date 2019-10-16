/* voip_calls_info_model.h
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
#include <glib.h>

#include "ui/voip_calls.h"
#include <ui/qt/utils/variant_pointer.h>

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>

class VoipCallsInfoModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    VoipCallsInfoModel(QObject *parent = 0);
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    void setTimeOfDay(bool timeOfDay);
    bool timeOfDay() const;
    void updateCalls(GQueue *callsinfos);

    static voip_calls_info_t *indexToCallInfo(const QModelIndex &index);

    enum Column
    {
        StartTime,
        StopTime,
        InitialSpeaker,
        From,
        To,
        Protocol,
        Duration,
        Packets,
        State,
        Comments,
        ColumnCount /* not an actual column, but used to find max. cols. */
    };

private:
    QList<void *> callinfos_;
    bool mTimeOfDay_;

    QVariant timeData(nstime_t *abs_ts, nstime_t *rel_ts) const;
};

class VoipCallsInfoSortedModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    VoipCallsInfoSortedModel(QObject *parent = 0);

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
};

#endif // VOIP_CALLS_INFO_MODEL_H

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
