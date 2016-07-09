/* service_response_time_dialog.cpp
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

#include "service_response_time_dialog.h"

#include "file.h"

#include <epan/tap.h>

#include <ui/service_response_time.h>

#include "rpc_service_response_time_dialog.h"
#include "wireshark_application.h"

#include <QTreeWidget>
#include <QTreeWidgetItemIterator>

static QHash<const QString, register_srt_t *> cfg_str_to_srt_;

extern "C" {
static void
srt_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    if (args_l.length() > 1) {
        QString srt = QString("%1,%2").arg(args_l[0]).arg(args_l[1]);
        QString filter;
        if (args_l.length() > 2) {
            filter = QStringList(args_l.mid(2)).join(",");
        }
        wsApp->emitTapParameterSignal(srt, filter, NULL);
    }
}
}

void register_service_response_tables(gpointer data, gpointer)
{
    register_srt_t *srt = (register_srt_t*)data;
    const char* short_name = proto_get_protocol_short_name(find_protocol_by_id(get_srt_proto_id(srt)));
    const char *cfg_abbr = srt_table_get_tap_string(srt);
    tpdCreator tpd_creator = ServiceResponseTimeDialog::createSrtDialog;

    /* XXX - These dissectors haven't been converted over to due to an "interactive input dialog" for their
       tap data.  Let those specific dialogs register for themselves */
    if (strcmp(short_name, "DCERPC") == 0) {
        short_name = "DCE-RPC";
        tpd_creator = RpcServiceResponseTimeDialog::createDceRpcSrtDialog;
    } else if (strcmp(short_name, "RPC") == 0) {
        short_name = "ONC-RPC";
        tpd_creator = RpcServiceResponseTimeDialog::createOncRpcSrtDialog;
    }

    cfg_str_to_srt_[cfg_abbr] = srt;
    TapParameterDialog::registerDialog(
                short_name,
                cfg_abbr,
                REGISTER_STAT_GROUP_RESPONSE_TIME,
                srt_init,
                tpd_creator);
}

enum {
    srt_table_type_ = 1000,
    srt_row_type_
};

class SrtRowTreeWidgetItem : public QTreeWidgetItem
{
public:
    SrtRowTreeWidgetItem(QTreeWidgetItem *parent, const srt_procedure_t *procedure) :
        QTreeWidgetItem (parent, srt_row_type_),
        procedure_(procedure)
    {
        setText(SRT_COLUMN_PROCEDURE, procedure_->procedure);
        setHidden(true);
    }

    void draw() {
        setText(SRT_COLUMN_INDEX, QString::number(procedure_->proc_index));
        setText(SRT_COLUMN_CALLS, QString::number(procedure_->stats.num));
        setText(SRT_COLUMN_MIN, QString::number(nstime_to_sec(&procedure_->stats.min), 'f', 6));
        setText(SRT_COLUMN_MAX, QString::number(nstime_to_sec(&procedure_->stats.max), 'f', 6));
        setText(SRT_COLUMN_AVG, QString::number(get_average(&procedure_->stats.tot, procedure_->stats.num) / 1000.0, 'f', 6));
        setText(SRT_COLUMN_SUM, QString::number(nstime_to_sec(&procedure_->stats.tot), 'f', 6));

        for (int col = 0; col < columnCount(); col++) {
            if (col == SRT_COLUMN_PROCEDURE) continue;
            setTextAlignment(col, Qt::AlignRight);
        }

        setHidden(procedure_->stats.num < 1);
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != srt_row_type_) return QTreeWidgetItem::operator< (other);
        const SrtRowTreeWidgetItem *other_row = static_cast<const SrtRowTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case SRT_COLUMN_INDEX:
            return procedure_->proc_index < other_row->procedure_->proc_index;
        case SRT_COLUMN_CALLS:
            return procedure_->stats.num < other_row->procedure_->stats.num;
        case SRT_COLUMN_MIN:
            return nstime_cmp(&procedure_->stats.min, &other_row->procedure_->stats.min) < 0;
        case SRT_COLUMN_MAX:
            return nstime_cmp(&procedure_->stats.max, &other_row->procedure_->stats.max) < 0;
        case SRT_COLUMN_AVG:
        {
            double our_avg = get_average(&procedure_->stats.tot, procedure_->stats.num);
            double other_avg = get_average(&other_row->procedure_->stats.tot, other_row->procedure_->stats.num);
            return our_avg < other_avg;
        }
        case SRT_COLUMN_SUM:
            return nstime_cmp(&procedure_->stats.tot, &other_row->procedure_->stats.tot) < 0;
        default:
            break;
        }

        return QTreeWidgetItem::operator< (other);
    }
    QList<QVariant> rowData() {
        return QList<QVariant>() << QString(procedure_->procedure) << procedure_->proc_index << procedure_->stats.num
                                 << nstime_to_sec(&procedure_->stats.min) << nstime_to_sec(&procedure_->stats.max)
                                 << get_average(&procedure_->stats.tot, procedure_->stats.num) / 1000.0
                                 << nstime_to_sec(&procedure_->stats.tot);
    }
private:
    const srt_procedure_t *procedure_;
};

class SrtTableTreeWidgetItem : public QTreeWidgetItem
{
public:
    SrtTableTreeWidgetItem(QTreeWidget *parent, const srt_stat_table *srt_table) :
        QTreeWidgetItem (parent, srt_table_type_),
        srt_table_(srt_table)
    {
        setText(0, srt_table_->name);
        setFirstColumnSpanned(true);
        setExpanded(true);

        for (int i = 0; i < srt_table_->num_procs; i++) {
            new SrtRowTreeWidgetItem(this, &srt_table_->procedures[i]);
        }
    }
    const QString columnTitle() { return srt_table_->proc_column_name; }

    QList<QVariant> rowData() {
        return QList<QVariant>() << srt_table_->name;
    }
    const QString filterField() { return srt_table_->filter_string; }

private:
    const srt_stat_table *srt_table_;
};


ServiceResponseTimeDialog::ServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, register_srt *srt, const QString filter, int help_topic) :
    TapParameterDialog(parent, cf, help_topic),
    srt_(srt)
{
    QString subtitle = QString("%1 Service Response Time Statistics")
            .arg(proto_get_protocol_short_name(find_protocol_by_id(get_srt_proto_id(srt))));
    setWindowSubtitle(subtitle);
    loadGeometry(0, 0, "ServiceResponseTimeDialog");

    // Add number of columns for this stats_tree
    QStringList header_labels;
    for (int col = 0; col < NUM_SRT_COLUMNS; col++) {
        header_labels.push_back(service_response_time_get_column_name(col));
    }
    statsTreeWidget()->setColumnCount(header_labels.count());
    statsTreeWidget()->setHeaderLabels(header_labels);

    for (int col = 0; col < statsTreeWidget()->columnCount(); col++) {
        if (col == SRT_COLUMN_PROCEDURE) continue;
        statsTreeWidget()->headerItem()->setTextAlignment(col, Qt::AlignRight);
    }

    addFilterActions();

    if (!filter.isEmpty()) {
        setDisplayFilter(filter);
    }

    connect(statsTreeWidget(), SIGNAL(itemChanged(QTreeWidgetItem*,int)),
            this, SLOT(statsTreeWidgetItemChanged()));
}

TapParameterDialog *ServiceResponseTimeDialog::createSrtDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf)
{
    if (!cfg_str_to_srt_.contains(cfg_str)) {
        // XXX MessageBox?
        return NULL;
    }

    register_srt_t *srt = cfg_str_to_srt_[cfg_str];

    return new ServiceResponseTimeDialog(parent, cf, srt, filter);
}

void ServiceResponseTimeDialog::addSrtTable(const struct _srt_stat_table *srt_table)
{
    new SrtTableTreeWidgetItem(statsTreeWidget(), srt_table);
}

void ServiceResponseTimeDialog::tapReset(void *srtd_ptr)
{
    srt_data_t *srtd = (srt_data_t*) srtd_ptr;
    ServiceResponseTimeDialog *srt_dlg = static_cast<ServiceResponseTimeDialog *>(srtd->user_data);
    if (!srt_dlg) return;

    reset_srt_table(srtd->srt_array, NULL, NULL);

    srt_dlg->statsTreeWidget()->clear();
    for (guint i = 0; i < srtd->srt_array->len; i++) {
        srt_stat_table *srt_table = g_array_index(srtd->srt_array, srt_stat_table*, i);
        srt_dlg->addSrtTable(srt_table);
    }
}

void ServiceResponseTimeDialog::tapDraw(void *srtd_ptr)
{
    srt_data_t *srtd = (srt_data_t*) srtd_ptr;
    ServiceResponseTimeDialog *srt_dlg = static_cast<ServiceResponseTimeDialog *>(srtd->user_data);
    if (!srt_dlg || !srt_dlg->statsTreeWidget()) return;

    QTreeWidgetItemIterator it(srt_dlg->statsTreeWidget());
    while (*it) {
        if ((*it)->type() == srt_row_type_) {
            SrtRowTreeWidgetItem *srtr_ti = static_cast<SrtRowTreeWidgetItem *>((*it));
            srtr_ti->draw();
        }
        ++it;
    }

    for (int i = 0; i < srt_dlg->statsTreeWidget()->columnCount() - 1; i++) {
        srt_dlg->statsTreeWidget()->resizeColumnToContents(i);
    }
}

void ServiceResponseTimeDialog::fillTree()
{
    srt_data_t srt_data;
    srt_data.srt_array = g_array_new(FALSE, TRUE, sizeof(srt_stat_table*));
    srt_data.user_data = this;

    srt_table_dissector_init(srt_, srt_data.srt_array, NULL, NULL);

    QString display_filter = displayFilter();
    if (!registerTapListener(get_srt_tap_listener_name(srt_),
                        &srt_data,
                        display_filter.toUtf8().constData(),
                        0,
                        tapReset,
                        get_srt_packet_func(srt_),
                        tapDraw)) {
        reject(); // XXX Stay open instead?
        return;
    }

    statsTreeWidget()->setSortingEnabled(false);

    cap_file_.retapPackets();

    // We only have one table. Move its tree items up one level.
    if (statsTreeWidget()->invisibleRootItem()->childCount() == 1) {
        statsTreeWidget()->setRootIndex(statsTreeWidget()->model()->index(0, 0));
    }

    tapDraw(&srt_data);

    statsTreeWidget()->sortItems(SRT_COLUMN_PROCEDURE, Qt::AscendingOrder);
    statsTreeWidget()->setSortingEnabled(true);

    removeTapListeners();

    g_array_free(srt_data.srt_array, TRUE);
}

QList<QVariant> ServiceResponseTimeDialog::treeItemData(QTreeWidgetItem *ti) const
{
    QList<QVariant> tid;
    if (ti->type() == srt_table_type_) {
        SrtTableTreeWidgetItem *srtt_ti = static_cast<SrtTableTreeWidgetItem *>(ti);
        if (srtt_ti) {
            tid << srtt_ti->rowData();
        }
    } else if (ti->type() == srt_row_type_) {
        SrtRowTreeWidgetItem *srtr_ti = static_cast<SrtRowTreeWidgetItem *>(ti);
        if (srtr_ti) {
            tid << srtr_ti->rowData();
        }
    }
    return tid;
}

const QString ServiceResponseTimeDialog::filterExpression()
{
    QString filter_expr;
    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];
        if (ti->type() == srt_row_type_) {
            SrtTableTreeWidgetItem *srtt_ti = static_cast<SrtTableTreeWidgetItem *>(ti->parent());
            g_assert(srtt_ti);
            QString field = srtt_ti->filterField();
            QString value = ti->text(SRT_COLUMN_INDEX);
            if (!field.isEmpty() && !value.isEmpty()) {
                filter_expr = QString("%1==%2").arg(srtt_ti->filterField()).arg(value);
            }
        }
    }
    return filter_expr;
}

void ServiceResponseTimeDialog::statsTreeWidgetItemChanged()
{
    QString procedure_title = service_response_time_get_column_name(SRT_COLUMN_PROCEDURE);

    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];
        SrtTableTreeWidgetItem *srtt_ti = NULL;
        if (ti->type() == srt_row_type_) {
            srtt_ti = static_cast<SrtTableTreeWidgetItem *>(ti->parent());
        } else {
            srtt_ti = static_cast<SrtTableTreeWidgetItem *>(ti);
        }
        if (srtt_ti) {
            procedure_title = srtt_ti->columnTitle();
        }
    }
    statsTreeWidget()->headerItem()->setText(SRT_COLUMN_PROCEDURE, procedure_title);
}

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
