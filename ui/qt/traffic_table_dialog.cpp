/* traffic_table_dialog.cpp
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

#include "traffic_table_dialog.h"
#include <ui_traffic_table_dialog.h>

#include <epan/addr_resolv.h>
#include <epan/prefs.h>

#include "ui/recent.h"

#include "progress_frame.h"
#include "wireshark_application.h"

#include <QCheckBox>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QDialogButtonBox>
#include <QList>
#include <QMap>
#include <QMessageBox>
#include <QPushButton>
#include <QTabWidget>
#include <QTreeWidget>
#include <QTextStream>
#include <QToolButton>

// To do:
// - Add "copy" items to the menu.

// Bugs:
// - Tabs and menu items don't always end up in the same order.
// - Columns don't resize correctly.
// - Closing the capture file clears conversation data.

TrafficTableDialog::TrafficTableDialog(QWidget &parent, CaptureFile &cf, const char *filter, const QString &table_name) :
    WiresharkDialog(parent, cf),
    ui(new Ui::TrafficTableDialog),
    cap_file_(cf),
    file_closed_(false),
    filter_(filter),
    nanosecond_timestamps_(false)
{
    ui->setupUi(this);
    loadGeometry(parent.width(), parent.height() * 3 / 4);

    ui->enabledTypesPushButton->setText(tr("%1 Types").arg(table_name));
    ui->absoluteTimeCheckBox->hide();
    setWindowSubtitle(QString("%1s").arg(table_name));

    QMenu *copy_menu = new QMenu();
    QAction *ca;
    copy_bt_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in CSV (Comma Separated Values) format."));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsCsv()));
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in the YAML data serialization format."));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsYaml()));
    copy_bt_->setMenu(copy_menu);

    ui->enabledTypesPushButton->setMenu(&traffic_type_menu_);
    ui->trafficTableTabWidget->setFocus();

    if (cf.timestampPrecision() == WTAP_TSPREC_NSEC) {
        nanosecond_timestamps_ = true;
    }

    connect(wsApp, SIGNAL(addressResolutionChanged()), this, SLOT(currentTabChanged()));
    connect(wsApp, SIGNAL(addressResolutionChanged()), this, SLOT(updateWidgets()));
    connect(ui->trafficTableTabWidget, SIGNAL(currentChanged(int)),
            this, SLOT(currentTabChanged()));
    connect(&cap_file_, SIGNAL(captureFileRetapStarted()),
            this, SLOT(retapStarted()));
    connect(&cap_file_, SIGNAL(captureFileRetapFinished()),
            this, SLOT(retapFinished()));
}

TrafficTableDialog::~TrafficTableDialog()
{
    delete ui;
}

bool TrafficTableDialog::absoluteStartTime()
{
    return absoluteTimeCheckBox()->isChecked();
}

const QList<int> TrafficTableDialog::defaultProtos() const
{
    // Reasonable defaults?
    return QList<int>() << proto_get_id_by_filter_name("eth") << proto_get_id_by_filter_name("ip")
                        << proto_get_id_by_filter_name("ipv6") << proto_get_id_by_filter_name("tcp")
                        << proto_get_id_by_filter_name("udp");
}

void TrafficTableDialog::fillTypeMenu(QList<int> &enabled_protos)
{
    for (guint i = 0; i < conversation_table_get_num(); i++) {
        int proto_id = get_conversation_proto_id(get_conversation_table_by_num(i));
        if (proto_id < 0) {
            continue;
        }
        QString title = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

        QAction *endp_action = new QAction(title, this);
        endp_action->setData(qVariantFromValue(proto_id));
        endp_action->setCheckable(true);
        endp_action->setChecked(enabled_protos.contains(proto_id));
        connect(endp_action, SIGNAL(triggered()), this, SLOT(toggleTable()));
        traffic_type_menu_.addAction(endp_action);
    }
}

void TrafficTableDialog::addProgressFrame(QObject *parent)
{
    ProgressFrame::addToButtonBox(ui->buttonBox, parent);
}

QDialogButtonBox *TrafficTableDialog::buttonBox() const
{
    return ui->buttonBox;
}

QTabWidget *TrafficTableDialog::trafficTableTabWidget() const
{
    return ui->trafficTableTabWidget;
}

QCheckBox *TrafficTableDialog::displayFilterCheckBox() const
{
    return ui->displayFilterCheckBox;
}

QCheckBox *TrafficTableDialog::nameResolutionCheckBox() const
{
    return ui->nameResolutionCheckBox;
}

QCheckBox *TrafficTableDialog::absoluteTimeCheckBox() const
{
    return ui->absoluteTimeCheckBox;
}

QPushButton *TrafficTableDialog::enabledTypesPushButton() const
{
    return ui->enabledTypesPushButton;
}

void TrafficTableDialog::currentTabChanged()
{
    bool has_resolution = false;
    TrafficTableTreeWidget *cur_tree = qobject_cast<TrafficTableTreeWidget *>(ui->trafficTableTabWidget->currentWidget());
    if (cur_tree) has_resolution = cur_tree->hasNameResolution();

    bool block = blockSignals(true);
    if (has_resolution) {
        // Don't change the actual setting.
        ui->nameResolutionCheckBox->setEnabled(true);
    } else {
        ui->nameResolutionCheckBox->setChecked(false);
        ui->nameResolutionCheckBox->setEnabled(false);
    }
    blockSignals(block);

    if (cur_tree) cur_tree->setNameResolutionEnabled(ui->nameResolutionCheckBox->isChecked());
}

void TrafficTableDialog::on_nameResolutionCheckBox_toggled(bool)
{
    QWidget *cw = ui->trafficTableTabWidget->currentWidget();
    if (cw) cw->update();
}

void TrafficTableDialog::on_displayFilterCheckBox_toggled(bool checked)
{
    if (!cap_file_.isValid()) {
        return;
    }

    QByteArray filter_utf8;
    const char *filter = NULL;
    if (checked) {
        filter = cap_file_.capFile()->dfilter;
    } else if (!filter_.isEmpty()) {
        filter_utf8 = filter_.toUtf8();
        filter = filter_utf8.constData();
    }

    for (int i = 0; i < ui->trafficTableTabWidget->count(); i++) {
        TrafficTableTreeWidget *cur_tree = qobject_cast<TrafficTableTreeWidget *>(ui->trafficTableTabWidget->widget(i));
        set_tap_dfilter(cur_tree->trafficTreeHash(), filter);
    }

    cap_file_.retapPackets();
}

void TrafficTableDialog::retapStarted()
{
    ui->displayFilterCheckBox->setEnabled(false);
}

void TrafficTableDialog::retapFinished()
{
    ui->displayFilterCheckBox->setEnabled(true);
}

void TrafficTableDialog::setTabText(QWidget *tree, const QString &text)
{
    // Could use QObject::sender as well
    int index = ui->trafficTableTabWidget->indexOf(tree);
    if (index >= 0) {
        ui->trafficTableTabWidget->setTabText(index, text);
    }
}

void TrafficTableDialog::toggleTable()
{
    QAction *ca = qobject_cast<QAction *>(QObject::sender());
    if (!ca) {
        return;
    }

    int proto_id = ca->data().value<int>();
    register_ct_t* table = get_conversation_by_proto_id(proto_id);

    bool new_table = addTrafficTable(table);
    updateWidgets();

    if (ca->isChecked()) {
        ui->trafficTableTabWidget->setCurrentWidget(proto_id_to_tree_[proto_id]);
    }

    if (new_table) {
        cap_file_.retapPackets();
    }
}

void TrafficTableDialog::updateWidgets()
{
    QWidget *cur_w = ui->trafficTableTabWidget->currentWidget();
    ui->trafficTableTabWidget->setUpdatesEnabled(false);
    ui->trafficTableTabWidget->clear();

    foreach (QAction *ca, traffic_type_menu_.actions()) {
        int proto_id = ca->data().value<int>();
        if (proto_id_to_tree_.contains(proto_id) && ca->isChecked()) {
            ui->trafficTableTabWidget->addTab(proto_id_to_tree_[proto_id],
                                              proto_id_to_tree_[proto_id]->trafficTreeTitle());
        }
    }
    ui->trafficTableTabWidget->setCurrentWidget(cur_w);
    ui->trafficTableTabWidget->setUpdatesEnabled(true);

    WiresharkDialog::updateWidgets();
}

QList<QVariant> TrafficTableDialog::curTreeRowData(int row) const
{
    TrafficTableTreeWidget *cur_tree = qobject_cast<TrafficTableTreeWidget *>(ui->trafficTableTabWidget->currentWidget());
    if (!cur_tree) {
        return QList<QVariant>();
    }

    return cur_tree->rowData(row);
}

void TrafficTableDialog::copyAsCsv()
{
    QTreeWidget *cur_tree = qobject_cast<QTreeWidget *>(ui->trafficTableTabWidget->currentWidget());
    if (!cur_tree) {
        return;
    }

    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    for (int row = -1; row < cur_tree->topLevelItemCount(); row ++) {
        QStringList rdsl;
        foreach (QVariant v, curTreeRowData(row)) {
            if (!v.isValid()) {
                rdsl << "\"\"";
            } else if ((int) v.type() == (int) QMetaType::QString) {
                rdsl << QString("\"%1\"").arg(v.toString());
            } else {
                rdsl << v.toString();
            }
        }
        stream << rdsl.join(",") << endl;
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void TrafficTableDialog::copyAsYaml()
{
    QTreeWidget *cur_tree = qobject_cast<QTreeWidget *>(ui->trafficTableTabWidget->currentWidget());
    if (!cur_tree) {
        return;
    }

    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    stream << "---" << endl;
    for (int row = -1; row < cur_tree->topLevelItemCount(); row ++) {
        stream << "-" << endl;
        foreach (QVariant v, curTreeRowData(row)) {
            stream << " - " << v.toString() << endl;
        }
    }
    wsApp->clipboard()->setText(stream.readAll());
}

TrafficTableTreeWidget::TrafficTableTreeWidget(QWidget *parent, register_ct_t *table) :
    QTreeWidget(parent),
    table_(table),
    hash_(),
    resolve_names_(false)
{
    setRootIsDecorated(false);
    sortByColumn(0, Qt::AscendingOrder);

    connect(wsApp, SIGNAL(addressResolutionChanged()), this, SLOT(updateItemsForSettingChange()));
}

TrafficTableTreeWidget::~TrafficTableTreeWidget()
{
    remove_tap_listener(&hash_);
}

QList<QVariant> TrafficTableTreeWidget::rowData(int row) const
{
    QList<QVariant> row_data;

    if (row >= topLevelItemCount()) {
        return row_data;
    }

    for (int col = 0; col < columnCount(); col++) {
        if (isColumnHidden(col)) {
            continue;
        }
        if (row < 0) {
            row_data << headerItem()->text(col);
        } else {
            TrafficTableTreeWidgetItem *ti = static_cast<TrafficTableTreeWidgetItem *>(topLevelItem(row));
            if (ti) {
                row_data << ti->colData(col, resolve_names_);
            }
        }
    }
    return row_data;
}

// True if name resolution is enabled for the table's address type, false
// otherwise.
// XXX We need a more reliable method of fetching the address type(s) for
// a table.
bool TrafficTableTreeWidget::hasNameResolution() const
{
    if (!table_) return false;

    QStringList mac_protos = QStringList() << "eth" << "tr"<< "wlan";
    QStringList net_protos = QStringList() << "ip" << "ipv6" << "jxta"
                                           << "mptcp" << "rsvp" << "sctp"
                                           << "tcp" << "udp";

    QString table_proto = proto_get_protocol_filter_name(get_conversation_proto_id(table_));

    if (mac_protos.contains(table_proto) && gbl_resolv_flags.mac_name) return true;
    if (net_protos.contains(table_proto) && gbl_resolv_flags.network_name) return true;

    return false;
}

void TrafficTableTreeWidget::setNameResolutionEnabled(bool enable)
{
    if (resolve_names_ != enable) {
        resolve_names_ = enable;
        updateItems();
    }
}

void TrafficTableTreeWidget::contextMenuEvent(QContextMenuEvent *event)
{
    bool enable = currentItem() != NULL ? true : false;

    foreach (QMenu *submenu, ctx_menu_.findChildren<QMenu*>()) {
        submenu->setEnabled(enable);
    }

    ctx_menu_.exec(event->globalPos());

}

void TrafficTableTreeWidget::updateItemsForSettingChange()
{
    updateItems();
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
