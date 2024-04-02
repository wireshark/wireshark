/* simple_statistics_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "simple_statistics_dialog.h"

#include "file.h"

#include "epan/stat_tap_ui.h"

#include <QTreeWidget>

#include "main_application.h"

// To do:
// - Hide rows with zero counts.

static QHash<const QString, stat_tap_table_ui *> cfg_str_to_stu_;

extern "C" {
static void
simple_stat_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    if (args_l.length() > 1) {
        QString simple_stat = QString("%1,%2").arg(args_l[0]).arg(args_l[1]);
        QString filter;
        if (args_l.length() > 2) {
            filter = QStringList(args_l.mid(2)).join(",");
        }
        mainApp->emitTapParameterSignal(simple_stat, filter, NULL);
    }
}
}

bool register_simple_stat_tables(const void *key, void *value, void*) {
    stat_tap_table_ui *stu = (stat_tap_table_ui*)value;

    cfg_str_to_stu_[stu->cli_string] = stu;
    TapParameterDialog::registerDialog(
                stu->title,
                (const char*)key,
                stu->group,
                simple_stat_init,
                SimpleStatisticsDialog::createSimpleStatisticsDialog);
    return false;
}

enum {
    simple_row_type_ = 1000
};

class SimpleStatisticsTreeWidgetItem : public QTreeWidgetItem
{
public:
    SimpleStatisticsTreeWidgetItem(QTreeWidgetItem *parent, int num_fields, const stat_tap_table_item_type *fields) :
        QTreeWidgetItem (parent, simple_row_type_),
        num_fields_(num_fields),
        fields_(fields)
    {
    }
    void draw() {
        for (int i = 0; i < num_fields_ && i < treeWidget()->columnCount(); i++) {
            switch (fields_[i].type) {
            case TABLE_ITEM_UINT:
                setText(i, QString::number(fields_[i].value.uint_value));
                break;
            case TABLE_ITEM_INT:
                setText(i, QString::number(fields_[i].value.int_value));
                break;
            case TABLE_ITEM_STRING:
                setText(i, fields_[i].value.string_value);
                break;
            case TABLE_ITEM_FLOAT:
                setText(i, QString::number(fields_[i].value.float_value, 'f', 6));
                break;
            case TABLE_ITEM_ENUM:
                setText(i, QString::number(fields_[i].value.enum_value));
                break;
            default:
                break;
            }
        }
    }
    bool operator< (const QTreeWidgetItem &other) const
    {
        int col = treeWidget()->sortColumn();
        if (other.type() != simple_row_type_ || col >= num_fields_) {
            return QTreeWidgetItem::operator< (other);
        }
        const SimpleStatisticsTreeWidgetItem *other_row = static_cast<const SimpleStatisticsTreeWidgetItem *>(&other);
        switch (fields_[col].type) {
        case TABLE_ITEM_UINT:
            return fields_[col].value.uint_value < other_row->fields_[col].value.uint_value;
        case TABLE_ITEM_INT:
            return fields_[col].value.int_value < other_row->fields_[col].value.int_value;
        case TABLE_ITEM_STRING:
            return g_strcmp0(fields_[col].value.string_value, other_row->fields_[col].value.string_value) < 0;
        case TABLE_ITEM_FLOAT:
            return fields_[col].value.float_value < other_row->fields_[col].value.float_value;
        case TABLE_ITEM_ENUM:
            return fields_[col].value.enum_value < other_row->fields_[col].value.enum_value;
        default:
            break;
        }

        return QTreeWidgetItem::operator< (other);
    }
    QList<QVariant> rowData() {
        QList<QVariant> row_data;

        for (int i = 0; i < num_fields_ && i < columnCount(); i++) {
            switch (fields_[i].type) {
            case TABLE_ITEM_UINT:
                row_data << fields_[i].value.uint_value;
                break;
            case TABLE_ITEM_INT:
                row_data << fields_[i].value.int_value;
                break;
            case TABLE_ITEM_STRING:
                row_data << fields_[i].value.string_value;
                break;
            case TABLE_ITEM_FLOAT:
                row_data << fields_[i].value.float_value;
                break;
            case TABLE_ITEM_ENUM:
                row_data << fields_[i].value.enum_value;
                break;
            default:
                break;
            }
        }

        return row_data;
    }

private:
    const int num_fields_;
    const stat_tap_table_item_type *fields_;
};

SimpleStatisticsDialog::SimpleStatisticsDialog(QWidget &parent, CaptureFile &cf, struct _stat_tap_table_ui *stu, const QString filter, int help_topic) :
    TapParameterDialog(parent, cf, help_topic),
    stu_(stu)
{
    stu->refcount++;
    setWindowSubtitle(stu_->title);
    loadGeometry(0, 0, stu_->title);

    QStringList header_labels;
    for (int col = 0; col < (int) stu_->nfields; col++) {
        header_labels << stu_->fields[col].column_name;
    }
    statsTreeWidget()->setHeaderLabels(header_labels);

    for (int col = 0; col < (int) stu_->nfields; col++) {
        if (stu_->fields[col].align == TAP_ALIGN_RIGHT) {
            statsTreeWidget()->headerItem()->setTextAlignment(col, Qt::AlignRight);
        }
    }

    setDisplayFilter(filter);
}

TapParameterDialog *SimpleStatisticsDialog::createSimpleStatisticsDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf)
{
    if (!cfg_str_to_stu_.contains(cfg_str)) {
        // XXX MessageBox?
        return NULL;
    }

    stat_tap_table_ui *stu = cfg_str_to_stu_[cfg_str];

    return new SimpleStatisticsDialog(parent, cf, stu, filter);
}

void SimpleStatisticsDialog::addMissingRows(struct _stat_data_t *stat_data)
{
    // Hierarchy:
    // - tables (GTK+ UI only supports one currently)
    //   - elements (rows?)
    //     - fields (columns?)
    // For multiple table support we might want to add them as subtrees, with
    // the top-level tree item text set to the column labels for that table.

    // Add any missing tables and rows.
    for (unsigned table_idx = 0; table_idx < stat_data->stat_tap_data->tables->len; table_idx++) {
        stat_tap_table* st_table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, table_idx);
        QTreeWidgetItem *ti = NULL;

        if ((int) table_idx >= statsTreeWidget()->topLevelItemCount()) {
            ti = new QTreeWidgetItem(statsTreeWidget());
            ti->setText(0, st_table->title);
            ti->setFirstColumnSpanned(true);
            ti->setExpanded(true);
        } else {
            ti = statsTreeWidget()->topLevelItem(table_idx);
        }
        for (unsigned element = ti->childCount(); element < st_table->num_elements; element++) {
            stat_tap_table_item_type* fields = stat_tap_get_field_data(st_table, element, 0);
            if (stu_->nfields > 0) {
                SimpleStatisticsTreeWidgetItem *ss_ti = new SimpleStatisticsTreeWidgetItem(ti, st_table->num_fields, fields);
                for (int col = 0; col < (int) stu_->nfields; col++) {
                    if (stu_->fields[col].align == TAP_ALIGN_RIGHT) {
                        ss_ti->setTextAlignment(col, Qt::AlignRight);
                    }
                }
            }
        }
    }
}

void SimpleStatisticsDialog::tapReset(void *sd_ptr)
{
    stat_data_t *sd = (stat_data_t*) sd_ptr;
    SimpleStatisticsDialog *ss_dlg = static_cast<SimpleStatisticsDialog *>(sd->user_data);
    if (!ss_dlg) return;

    reset_stat_table(sd->stat_tap_data);
    ss_dlg->statsTreeWidget()->clear();
}

void SimpleStatisticsDialog::tapDraw(void *sd_ptr)
{
    stat_data_t *sd = (stat_data_t*) sd_ptr;
    SimpleStatisticsDialog *ss_dlg = static_cast<SimpleStatisticsDialog *>(sd->user_data);
    if (!ss_dlg) return;

    ss_dlg->addMissingRows(sd);

    QTreeWidgetItemIterator it(ss_dlg->statsTreeWidget());
    while (*it) {
        if ((*it)->type() == simple_row_type_) {
            SimpleStatisticsTreeWidgetItem *ss_ti = static_cast<SimpleStatisticsTreeWidgetItem *>((*it));
            ss_ti->draw();
        }
        ++it;
    }

    for (int i = 0; i < ss_dlg->statsTreeWidget()->columnCount() - 1; i++) {
        ss_dlg->statsTreeWidget()->resizeColumnToContents(i);
    }
}

void SimpleStatisticsDialog::fillTree()
{
    stat_data_t stat_data;
    stat_data.stat_tap_data = stu_;
    stat_data.user_data = this;

    stu_->stat_tap_init_cb(stu_);

    QString display_filter = displayFilter();
    if (!registerTapListener(stu_->tap_name,
                             &stat_data,
                             display_filter.toUtf8().constData(),
                             0,
                             tapReset,
                             stu_->packet_func,
                             tapDraw)) {
        free_stat_tables(stu_);
        reject(); // XXX Stay open instead?
        return;
    }

    statsTreeWidget()->setSortingEnabled(false);

    cap_file_.retapPackets();

    // We only have one table. Move its tree items up one level.
    if (statsTreeWidget()->invisibleRootItem()->childCount() == 1) {
        statsTreeWidget()->setRootIndex(statsTreeWidget()->model()->index(0, 0));
    }

    tapDraw(&stat_data);

    statsTreeWidget()->sortItems(0, Qt::AscendingOrder);
    statsTreeWidget()->setSortingEnabled(true);

    removeTapListeners();
}

// This is how an item is represented for exporting.
QList<QVariant> SimpleStatisticsDialog::treeItemData(QTreeWidgetItem *it) const
{
    // Cast up to our type.
    SimpleStatisticsTreeWidgetItem *rit = dynamic_cast<SimpleStatisticsTreeWidgetItem*>(it);
    if (rit) {
        return rit->rowData();
    }
    else {
        return QList<QVariant>();
    }
}


SimpleStatisticsDialog::~SimpleStatisticsDialog()
{
    stu_->refcount--;
    if (stu_->refcount == 0) {
        if (stu_->tables)
            free_stat_tables(stu_);
    }
}
