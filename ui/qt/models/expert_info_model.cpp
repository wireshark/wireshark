/* expert_info_model.cpp
 * Data model for Expert Info tap data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "expert_info_model.h"

#include "file.h"
#include <epan/proto.h>

ExpertPacketItem::ExpertPacketItem(const expert_info_t& expert_info, column_info *cinfo, ExpertPacketItem* parent) :
    packet_num_(expert_info.packet_num),
    group_(expert_info.group),
    severity_(expert_info.severity),
    hf_id_(expert_info.hf_index),
    protocol_(expert_info.protocol),
    summary_(expert_info.summary),
    parentItem_(parent)
{
    if (cinfo) {
        info_ = col_get_text(cinfo, COL_INFO);
    }
}

ExpertPacketItem::~ExpertPacketItem()
{
    for (int row = 0; row < childItems_.count(); row++)
    {
        delete childItems_.value(row);
    }

    childItems_.clear();
}

QString ExpertPacketItem::groupKey(bool group_by_summary, int severity, int group, QString protocol, int expert_hf)
{
    QString key = QString("%1|%2|%3")
            .arg(severity)
            .arg(group)
            .arg(protocol);
    if (group_by_summary) {
        key += QString("|%1").arg(expert_hf);
    }
    return key;
}

QString ExpertPacketItem::groupKey(bool group_by_summary) {
    return groupKey(group_by_summary, severity_, group_, protocol_, hf_id_);
}

void ExpertPacketItem::appendChild(ExpertPacketItem* child, QString hash)
{
    childItems_.append(child);
    hashChild_[hash] = child;
}

ExpertPacketItem* ExpertPacketItem::child(int row)
{
    return childItems_.value(row);
}

ExpertPacketItem* ExpertPacketItem::child(QString hash)
{
    return hashChild_[hash];
}

int ExpertPacketItem::childCount() const
{
    return static_cast<int>(childItems_.count());
}

int ExpertPacketItem::row() const
{
    if (parentItem_)
        return static_cast<int>(parentItem_->childItems_.indexOf(const_cast<ExpertPacketItem*>(this)));

    return 0;
}

ExpertPacketItem* ExpertPacketItem::parentItem()
{
    return parentItem_;
}




ExpertInfoModel::ExpertInfoModel(CaptureFile& capture_file, QObject *parent) :
    QAbstractItemModel(parent),
    capture_file_(capture_file),
    group_by_summary_(true),
    root_(createRootItem())
{
}

ExpertInfoModel::~ExpertInfoModel()
{
    delete root_;
}

void ExpertInfoModel::clear()
{
    beginResetModel();

    eventCounts_.clear();
    delete root_;
    root_ = createRootItem();

    endResetModel();
}

ExpertPacketItem* ExpertInfoModel::createRootItem()
{
    static const char* rootName = "ROOT";
DIAG_OFF_CAST_AWAY_CONST
    static expert_info_t root_expert = { 0, -1, -1, -1, rootName, (gchar*)rootName, NULL };
DIAG_ON_CAST_AWAY_CONST

    return new ExpertPacketItem(root_expert, NULL, NULL);
}



int ExpertInfoModel::numEvents(enum ExpertSeverity severity)
{
    return eventCounts_[severity];
}

QModelIndex ExpertInfoModel::index(int row, int column, const QModelIndex& parent) const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    ExpertPacketItem *parent_item, *child_item;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<ExpertPacketItem*>(parent.internalPointer());

    Q_ASSERT(parent_item);
    if (group_by_summary_) {
        //don't allow group layer
        if (parent_item == root_) {
            int row_count = 0;
            ExpertPacketItem *grandchild_item;

            for (int subrow = 0; subrow < parent_item->childCount(); subrow++) {
                child_item = parent_item->child(subrow);
                //summary children are always stored in first child of group
                grandchild_item = child_item->child(0);

                if (row_count+grandchild_item->childCount() > row) {
                    return createIndex(row, column, grandchild_item->child(row-row_count));
                }
                row_count += grandchild_item->childCount();
            }

            //shouldn't happen
            return QModelIndex();
        }

        int root_level = 0;
        ExpertPacketItem *item = parent_item;
        while (item != root_)
        {
            root_level++;
            item = item->parentItem();
        }

        if (root_level == 3) {
            child_item = parent_item->child(row);
            if (child_item) {
                return createIndex(row, column, child_item);
            }
        }

    } else {
        child_item = parent_item->child(row);
        if (child_item) {
            //only allow 2 levels deep
            if (((parent_item == root_) || (parent_item->parentItem() == root_)))
                return createIndex(row, column, child_item);
        }
    }
    return QModelIndex();
}

QModelIndex ExpertInfoModel::parent(const QModelIndex& index) const
{
    if (!index.isValid())
        return QModelIndex();

    ExpertPacketItem *item = static_cast<ExpertPacketItem*>(index.internalPointer());
    ExpertPacketItem *parent_item = item->parentItem();

    if (group_by_summary_)
    {
        //don't allow group layer
        int root_level = 0;
        item = parent_item;
        while ((item != root_) && (item != NULL))
        {
            root_level++;
            item = item->parentItem();
        }

        if (root_level == 3)
            return createIndex(parent_item->row(), 0, parent_item);

    } else {
        if (parent_item == root_)
            return QModelIndex();

        return createIndex(parent_item->row(), 0, parent_item);
    }

    return QModelIndex();
}

#if 0
Qt::ItemFlags ExpertInfoModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    ExpertPacketItem* item = static_cast<ExpertPacketItem*>(index.internalPointer());
    Qt::ItemFlags flags = QAbstractTableModel::flags(index);

    //collapse???
    return flags;
}
#endif

QVariant ExpertInfoModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || (role != Qt::DisplayRole && role != Qt::ToolTipRole))
        return QVariant();

    ExpertPacketItem* item = static_cast<ExpertPacketItem*>(index.internalPointer());
    if (item == NULL)
        return QVariant();

    if (role == Qt::ToolTipRole)
    {
        QString filterName = proto_registrar_get_abbrev(item->hfId());
        return filterName;
    }
    else if (role == Qt::DisplayRole)
    {
        switch ((enum ExpertColumn)index.column()) {
        case colSeverity:
            return QString(val_to_str_const(item->severity(), expert_severity_vals, "Unknown"));
        case colSummary:
            if (index.parent().isValid())
            {
                if (item->severity() == PI_COMMENT)
                    return item->summary().simplified();
                if (group_by_summary_)
                    return item->colInfo().simplified();

                return item->summary().simplified();
            }
            else
            {
                if (group_by_summary_)
                {
                    if (item->severity() == PI_COMMENT)
                        return "Packet comments listed below.";
                    if (item->hfId() != -1) {
                        return proto_registrar_get_name(item->hfId());
                    } else {
                        return item->summary().simplified();
                    }
                }
            }
            return QVariant();
        case colGroup:
            return QString(val_to_str_const(item->group(), expert_group_vals, "Unknown"));
        case colProtocol:
            return item->protocol();
        case colCount:
            if (!index.parent().isValid())
            {
                return item->childCount();
            }
            break;
        case colPacket:
            return item->packetNum();
        case colHf:
            return item->hfId();
        default:
            break;
        }
    }

    return QVariant();
}

//GUI helpers
void ExpertInfoModel::setGroupBySummary(bool group_by_summary)
{
    beginResetModel();
    group_by_summary_ = group_by_summary;
    endResetModel();
}

int ExpertInfoModel::rowCount(const QModelIndex &parent) const
{
    ExpertPacketItem *parent_item;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<ExpertPacketItem*>(parent.internalPointer());

    if (group_by_summary_) {
        int row_count = 0;

        //don't allow group layer
        if (parent_item == root_) {
            ExpertPacketItem *child_item, *grandchild_item;

            for (int row = 0; row < parent_item->childCount(); row++) {
                child_item = parent_item->child(row);
                grandchild_item = child_item->child(0);
                row_count += grandchild_item->childCount();
            }

            return row_count;
        }

        return parent_item->childCount();

    } else {
        //only allow 2 levels deep
        if ((parent_item == root_) || (parent_item->parentItem() == root_))
            return parent_item->childCount();
    }

    return 0;
}

int ExpertInfoModel::columnCount(const QModelIndex&) const
{
    return colLast;
}

void ExpertInfoModel::addExpertInfo(const struct expert_info_s& expert_info)
{
    QString groupKey = ExpertPacketItem::groupKey(FALSE, expert_info.severity, expert_info.group, QString(expert_info.protocol), expert_info.hf_index);
    QString summaryKey = ExpertPacketItem::groupKey(TRUE, expert_info.severity, expert_info.group, QString(expert_info.protocol), expert_info.hf_index);

    ExpertPacketItem* expert_root = root_->child(groupKey);
    if (expert_root == NULL) {
        ExpertPacketItem *new_item = new ExpertPacketItem(expert_info, &(capture_file_.capFile()->cinfo), root_);

        root_->appendChild(new_item, groupKey);

        expert_root = new_item;
    }

    ExpertPacketItem *expert = new ExpertPacketItem(expert_info, &(capture_file_.capFile()->cinfo), expert_root);
    expert_root->appendChild(expert, groupKey);

    //add the summary children off of the first child of the root children
    ExpertPacketItem* summary_root = expert_root->child(0);

    //make a summary child
    ExpertPacketItem* expert_summary_root = summary_root->child(summaryKey);
    if (expert_summary_root == NULL) {
        ExpertPacketItem *new_summary = new ExpertPacketItem(expert_info, &(capture_file_.capFile()->cinfo), summary_root);

        summary_root->appendChild(new_summary, summaryKey);
        expert_summary_root = new_summary;
    }

    ExpertPacketItem *expert_summary = new ExpertPacketItem(expert_info, &(capture_file_.capFile()->cinfo), expert_summary_root);
    expert_summary_root->appendChild(expert_summary, summaryKey);
}

void ExpertInfoModel::tapReset(void *eid_ptr)
{
    ExpertInfoModel *model = static_cast<ExpertInfoModel*>(eid_ptr);
    if (!model)
        return;

    model->clear();
}

tap_packet_status ExpertInfoModel::tapPacket(void *eid_ptr, struct _packet_info *pinfo, struct epan_dissect *, const void *data, tap_flags_t)
{
    ExpertInfoModel *model = static_cast<ExpertInfoModel*>(eid_ptr);
    const expert_info_t *expert_info = (const expert_info_t *) data;
    tap_packet_status status = TAP_PACKET_DONT_REDRAW;

    if (!pinfo || !model || !expert_info)
        return TAP_PACKET_DONT_REDRAW;

    model->addExpertInfo(*expert_info);

    status = TAP_PACKET_REDRAW;

    model->eventCounts_[(enum ExpertSeverity)expert_info->severity]++;

    return status;
}

void ExpertInfoModel::tapDraw(void *eid_ptr)
{
    ExpertInfoModel *model = static_cast<ExpertInfoModel*>(eid_ptr);
    if (!model)
        return;

    model->beginResetModel();
    model->endResetModel();
}
