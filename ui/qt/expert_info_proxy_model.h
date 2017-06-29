/* expert_info_model.h
 * Data model for Expert Info tap data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef EXPERT_INFO_PROXY_MODEL_H
#define EXPERT_INFO_PROXY_MODEL_H

#include <config.h>

#include <QSortFilterProxyModel>

class ExpertPacketItem;

class ExpertInfoProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    ExpertInfoProxyModel(QObject *parent = 0);

    enum SeverityMode { Group, Packet };
    enum ExpertProxyColumn {
        colProxySeverity = 0,
        colProxySummary,
        colProxyGroup,
        colProxyProtocol,
        colProxyCount,
        colProxyLast
    };

    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    //GUI helpers
    void setSeverityMode(enum SeverityMode);
    void setSeverityFilter(int severity, bool hide);
    void setSummaryFilter(const QString &filter);

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
    bool filterAcceptItem(ExpertPacketItem& item) const;

    enum SeverityMode severityMode_;
    QList<int> hidden_severities_;

    QString textFilter_;

};

#endif // EXPERT_INFO_PROXY_MODEL_H

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
