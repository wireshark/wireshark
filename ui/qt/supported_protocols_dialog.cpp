/* supported_protocols_dialog.cpp
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

// warning C4267: 'argument' : conversion from 'size_t' to 'int', possible loss of data
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4267)
#endif

#include "supported_protocols_dialog.h"
#include <ui_supported_protocols_dialog.h>

#include "config.h"

#include <algorithm>
#include <glib.h>

#include <epan/proto.h>

#include <QTreeWidgetItem>
#include <QElapsedTimer>

#include "wireshark_application.h"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

enum { name_col_, filter_col_, type_col_, descr_col_ };

SupportedProtocolsDialog::SupportedProtocolsDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::SupportedProtocolsDialog),
    field_count_(0)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 3 / 4, parent->height());
    setWindowTitle(wsApp->windowTitleString(tr("Supported Protocols")));

    // Some of our names are unreasonably long.
    int one_em = fontMetrics().height();
    ui->protoTreeWidget->setColumnWidth(name_col_, one_em * 15);
    ui->protoTreeWidget->setColumnWidth(filter_col_, one_em * 10);
    ui->protoTreeWidget->setColumnWidth(type_col_, one_em * 12);
    ui->protoTreeWidget->setColumnWidth(descr_col_, one_em * 30);

    QTimer::singleShot(0, this, SLOT(fillTree()));
}

SupportedProtocolsDialog::~SupportedProtocolsDialog()
{
    delete ui;
}

void SupportedProtocolsDialog::updateStatistics()
{
    QLocale locale = QLocale::system();
    QString hint = tr("%1 protocols, %2 fields.")
            .arg(locale.toString(ui->protoTreeWidget->topLevelItemCount()))
            .arg(locale.toString(field_count_));
    ui->hintLabel->setText(hint);
    wsApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers, 1);
}

// Nearly identical to DisplayFilterExpressionDialog::fillTree.
void SupportedProtocolsDialog::fillTree()
{
    void *proto_cookie;
    QList <QTreeWidgetItem *> proto_list;

    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
         proto_id = proto_get_next_protocol(&proto_cookie)) {
        protocol_t *protocol = find_protocol_by_id(proto_id);
        QTreeWidgetItem *proto_ti = new QTreeWidgetItem();
        proto_ti->setText(name_col_, proto_get_protocol_short_name(protocol));
        proto_ti->setText(filter_col_, proto_get_protocol_filter_name(proto_id));
        // type_col_ empty
        proto_ti->setText(descr_col_, proto_get_protocol_long_name(protocol));
        proto_ti->setData(name_col_, Qt::UserRole, proto_id);
        proto_list << proto_ti;
    }

    updateStatistics();
    ui->protoTreeWidget->invisibleRootItem()->addChildren(proto_list);
    ui->protoTreeWidget->sortByColumn(name_col_, Qt::AscendingOrder);

    foreach (QTreeWidgetItem *proto_ti, proto_list) {
        void *field_cookie;
        int proto_id = proto_ti->data(name_col_, Qt::UserRole).toInt();
        QList <QTreeWidgetItem *> field_list;
        for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL;
             hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
            if (hfinfo->same_name_prev_id != -1) continue;

            QTreeWidgetItem *field_ti = new QTreeWidgetItem();
            field_ti->setText(name_col_, hfinfo->name);
            field_ti->setText(filter_col_, hfinfo->abbrev);
            field_ti->setText(type_col_, ftype_pretty_name(hfinfo->type));
            field_ti->setText(descr_col_, hfinfo->blurb);
            field_list << field_ti;

            field_count_++;
            if (field_count_ % 10000 == 0) updateStatistics();
        }
        std::sort(field_list.begin(), field_list.end());
        proto_ti->addChildren(field_list);
    }

    updateStatistics();
    ui->protoTreeWidget->sortByColumn(name_col_, Qt::AscendingOrder);
}

// Copied from DisplayFilterExpressionDialog
void SupportedProtocolsDialog::on_searchLineEdit_textChanged(const QString &search_re)
{
    QTreeWidgetItemIterator it(ui->protoTreeWidget);
    QRegExp regex(search_re, Qt::CaseInsensitive);
    while (*it) {
        bool hidden = true;
        if (search_re.isEmpty() || (*it)->text(0).contains(regex)) {
            hidden = false;
        }
        (*it)->setHidden(hidden);
        if (!hidden && (*it)->parent()) {
            (*it)->parent()->setHidden(false);
        }
        ++it;
    }
}
