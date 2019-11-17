/* expert_info_model.cpp
 * Data model for Expert Info tap data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/expert_info_model.h>
#include <ui/qt/models/expert_info_proxy_model.h>
#include <ui/qt/utils/color_utils.h>

ExpertInfoProxyModel::ExpertInfoProxyModel(QObject *parent) : QSortFilterProxyModel(parent),
    severityMode_(Group)
{
}

bool ExpertInfoProxyModel::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    ExpertPacketItem *left_item,
                     *right_item;
    QString leftStr, rightStr;
    bool checkPacketNumber = false;
    int compare_ret;

    if (source_left.parent().isValid() && source_right.parent().isValid()) {
        left_item = static_cast<ExpertPacketItem*>(source_left.parent().internalPointer());
        right_item = static_cast<ExpertPacketItem*>(source_right.parent().internalPointer());
    } else {
        left_item = static_cast<ExpertPacketItem*>(source_left.internalPointer());
        right_item = static_cast<ExpertPacketItem*>(source_right.internalPointer());
    }

    if ((left_item != NULL) && (right_item != NULL)) {
        switch (source_left.column())
        {
        case colProxySeverity:
            if (left_item->severity() != right_item->severity()) {
                return (left_item->severity() < right_item->severity());
            }

            checkPacketNumber = true;
            break;
        case colProxySummary:
            compare_ret = left_item->summary().compare(right_item->summary());
            if (compare_ret < 0)
                return true;
            if (compare_ret > 0)
                return false;

            checkPacketNumber = true;
            break;
        case colProxyGroup:
            if (left_item->group() != right_item->group()) {
                return (left_item->group() < right_item->group());
            }

            checkPacketNumber = true;
            break;
        case colProxyProtocol:
            compare_ret = left_item->protocol().compare(right_item->protocol());
            if (compare_ret < 0)
                return true;
            if (compare_ret > 0)
                return false;

            checkPacketNumber = true;
            break;
        case colProxyCount:
            break;
        default:
            break;
        }

        if (checkPacketNumber) {
            return (left_item->packetNum() < right_item->packetNum());
        }
    }

    // fallback to string cmp on other fields
    return QSortFilterProxyModel::lessThan(source_left, source_right);
}

QVariant ExpertInfoProxyModel::data(const QModelIndex &proxy_index, int role) const
{
    QModelIndex source_index;

    switch (role)
    {
    case Qt::BackgroundRole:
        {
        source_index = mapToSource(proxy_index);

        // only color base row
        if (!source_index.isValid() || source_index.parent().isValid())
            return QVariant();

        ExpertPacketItem* item = static_cast<ExpertPacketItem*>(source_index.internalPointer());
        if (item == NULL)
            return QVariant();

        // provide background color for groups
        switch(item->severity()) {
        case(PI_COMMENT):
            return QBrush(ColorUtils::expert_color_comment);
        case(PI_CHAT):
            return QBrush(ColorUtils::expert_color_chat);
        case(PI_NOTE):
            return QBrush(ColorUtils::expert_color_note);
        case(PI_WARN):
            return QBrush(ColorUtils::expert_color_warn);
        case(PI_ERROR):
            return QBrush(ColorUtils::expert_color_error);
        }
        }
        break;
    case Qt::ForegroundRole:
        {
        source_index = mapToSource(proxy_index);

        // only color base row
        if (!source_index.isValid() || source_index.parent().isValid())
            return QVariant();

        ExpertPacketItem* item = static_cast<ExpertPacketItem*>(source_index.internalPointer());
        if (item == NULL)
            return QVariant();

        // provide foreground color for groups
        switch(item->severity()) {
        case(PI_COMMENT):
        case(PI_CHAT):
        case(PI_NOTE):
        case(PI_WARN):
        case(PI_ERROR):
            return QBrush(ColorUtils::expert_color_foreground);
        }
        }
        break;
    case Qt::TextAlignmentRole:
        switch (proxy_index.column())
        {
        case colProxySeverity:
            //packet number should be right aligned
            if (source_index.parent().isValid())
                return Qt::AlignRight;
            break;
        case colProxyCount:
            return Qt::AlignRight;
        default:
            break;
        }
        return Qt::AlignLeft;

    case Qt::DisplayRole:
        source_index = mapToSource(proxy_index);

        switch (proxy_index.column())
        {
        case colProxySeverity:
            if (source_index.parent().isValid())
                return sourceModel()->data(source_index.sibling(source_index.row(), ExpertInfoModel::colPacket), role);

            return sourceModel()->data(source_index.sibling(source_index.row(), ExpertInfoModel::colSeverity), role);
        case colProxySummary:
            return sourceModel()->data(source_index.sibling(source_index.row(), ExpertInfoModel::colSummary), role);
        case colProxyGroup:
            return sourceModel()->data(source_index.sibling(source_index.row(), ExpertInfoModel::colGroup), role);
        case colProxyProtocol:
            return sourceModel()->data(source_index.sibling(source_index.row(), ExpertInfoModel::colProtocol), role);
        case colProxyCount:
            //only show counts for parent
            if (!source_index.parent().isValid()) {
                //because of potential filtering, count is computed manually
                unsigned int count = 0;
                ExpertPacketItem *child_item,
                                 *item = static_cast<ExpertPacketItem*>(source_index.internalPointer());
                for (int row = 0; row < item->childCount(); row++) {
                    child_item = item->child(row);
                    if (child_item == NULL)
                        continue;
                    if (filterAcceptItem(*child_item))
                        count++;
                }

                return count;
            }
        }
        break;
    }

    return QSortFilterProxyModel::data(proxy_index, role);
}

QVariant ExpertInfoProxyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {

        switch ((enum ExpertProxyColumn)section) {
        case colProxySeverity:
            if (severityMode_ == Packet)
                return tr("Packet");
            else
                return tr("Severity");
        case colProxySummary:
            return tr("Summary");
        case colProxyGroup:
            return tr("Group");
        case colProxyProtocol:
            return tr("Protocol");
        case colProxyCount:
            return tr("Count");
        default:
            break;
        }
    }
    return QVariant();
}

int ExpertInfoProxyModel::columnCount(const QModelIndex&) const
{
    return colProxyLast;
}

bool ExpertInfoProxyModel::filterAcceptItem(ExpertPacketItem& item) const
{
    if (hidden_severities_.contains(item.severity()))
        return false;

    if (!textFilter_.isEmpty()) {
        QRegExp regex(textFilter_, Qt::CaseInsensitive);

        if (item.protocol().contains(regex))
            return true;

        if (item.summary().contains(regex))
            return true;

        if (item.colInfo().contains(regex))
            return true;

        return false;
    }

    return true;
}

bool ExpertInfoProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex severityIdx = sourceModel()->index(sourceRow, ExpertInfoModel::colSeverity, sourceParent);
    ExpertPacketItem* item = static_cast<ExpertPacketItem*>(severityIdx.internalPointer());
    if (item == NULL)
        return true;

    return filterAcceptItem(*item);
}

//GUI helpers
void ExpertInfoProxyModel::setSeverityMode(enum SeverityMode mode)
{
    severityMode_ = mode;
    emit headerDataChanged(Qt::Vertical, 0, 1);
}

void ExpertInfoProxyModel::setSeverityFilter(int severity, bool hide)
{
    if (hide)
    {
        hidden_severities_ << severity;
    }
    else
    {
        hidden_severities_.removeOne(severity);
    }

    invalidateFilter();
}

void ExpertInfoProxyModel::setSummaryFilter(const QString &filter)
{
    textFilter_ = filter;
    invalidateFilter();
}


/* * Editor modelines
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
