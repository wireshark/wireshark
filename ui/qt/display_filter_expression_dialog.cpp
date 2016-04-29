/* display_filter_expression_dialog.cpp
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

#include <algorithm>

#include "display_filter_expression_dialog.h"
#include <ui_display_filter_expression_dialog.h>

#include <epan/proto.h>
#include <epan/range.h>
#include <epan/tfs.h>
#include <epan/value_string.h>

#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QPushButton>
#include <QDialogButtonBox>
#include <QListWidgetItem>
#include <QTreeWidgetItem>

// To do:
// - Speed up initialization.
// - Speed up search.

enum {
    proto_type_ = 1000,
    field_type_
};

enum {
    present_op_ = 1000,
    eq_op_,
    ne_op_,
    gt_op_,
    lt_op_,
    ge_op_,
    le_op_,
    contains_op_,
    matches_op_
};

Q_DECLARE_METATYPE(header_field_info *)

DisplayFilterExpressionDialog::DisplayFilterExpressionDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::DisplayFilterExpressionDialog),
    ftype_(FT_NONE),
    field_(NULL)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height());

    setWindowTitle(wsApp->windowTitleString(tr("Display Filter Expression")));
    setWindowIcon(wsApp->normalIcon());

    proto_initialize_all_prefixes();

    ui->fieldTreeWidget->setToolTip(ui->fieldLabel->toolTip());
    ui->searchLineEdit->setToolTip(ui->searchLabel->toolTip());
    ui->relationListWidget->setToolTip(ui->relationLabel->toolTip());
    ui->valueLineEdit->setToolTip(ui->valueLabel->toolTip());
    ui->enumListWidget->setToolTip(ui->enumLabel->toolTip());
    ui->rangeLineEdit->setToolTip(ui->rangeLabel->toolTip());

    // Relation list
    new QListWidgetItem("is present", ui->relationListWidget, present_op_);
    new QListWidgetItem("==", ui->relationListWidget, eq_op_);
    new QListWidgetItem("!=", ui->relationListWidget, ne_op_);
    new QListWidgetItem(">", ui->relationListWidget, gt_op_);
    new QListWidgetItem("<", ui->relationListWidget, lt_op_);
    new QListWidgetItem(">=", ui->relationListWidget, ge_op_);
    new QListWidgetItem("<=", ui->relationListWidget, le_op_);
    new QListWidgetItem("contains", ui->relationListWidget, contains_op_);
    new QListWidgetItem("matches", ui->relationListWidget, matches_op_);

    value_label_pfx_ = ui->valueLabel->text();

    connect(ui->valueLineEdit, SIGNAL(textEdited(QString)), this, SLOT(updateWidgets()));
    connect(ui->rangeLineEdit, SIGNAL(textEdited(QString)), this, SLOT(updateWidgets()));

    // Trigger updateWidgets
    ui->fieldTreeWidget->selectionModel()->clear();

    QTimer::singleShot(0, this, SLOT(fillTree()));
}

DisplayFilterExpressionDialog::~DisplayFilterExpressionDialog()
{
    delete ui;
}

// Nearly identical to SupportedProtocolsDialog::fillTree.
void DisplayFilterExpressionDialog::fillTree()
{
    void *proto_cookie;
    QList <QTreeWidgetItem *> proto_list;

    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
         proto_id = proto_get_next_protocol(&proto_cookie)) {
        protocol_t *protocol = find_protocol_by_id(proto_id);
        if (!proto_is_protocol_enabled(protocol)) continue;

        QTreeWidgetItem *proto_ti = new QTreeWidgetItem(proto_type_);
        QString label = QString("%1 " UTF8_MIDDLE_DOT " %3")
                .arg(proto_get_protocol_short_name(protocol))
                .arg(proto_get_protocol_long_name(protocol));
        proto_ti->setText(0, label);
        proto_ti->setData(0, Qt::UserRole, qVariantFromValue(proto_id));
        proto_list << proto_ti;
    }

    wsApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers, 1);

    ui->fieldTreeWidget->invisibleRootItem()->addChildren(proto_list);
    ui->fieldTreeWidget->sortByColumn(0, Qt::AscendingOrder);

    int field_count = 0;
    foreach (QTreeWidgetItem *proto_ti, proto_list) {
        void *field_cookie;
        int proto_id = proto_ti->data(0, Qt::UserRole).toInt();

        QList <QTreeWidgetItem *> field_list;
        for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL;
             hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
            if (hfinfo->same_name_prev_id != -1) continue; // Ignore duplicate names.

            QTreeWidgetItem *field_ti = new QTreeWidgetItem(field_type_);
            QString label = QString("%1 " UTF8_MIDDLE_DOT " %3").arg(hfinfo->abbrev).arg(hfinfo->name);
            field_ti->setText(0, label);
            field_ti->setData(0, Qt::UserRole, qVariantFromValue(hfinfo));
            field_list << field_ti;

            field_count++;
            if (field_count % 10000 == 0) {
                wsApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers, 1);
            }
        }
        std::sort(field_list.begin(), field_list.end());
        proto_ti->addChildren(field_list);
    }

    wsApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers, 1);
    ui->fieldTreeWidget->sortByColumn(0, Qt::AscendingOrder);
}

void DisplayFilterExpressionDialog::updateWidgets()
{
    bool rel_enable = field_ != NULL;

    ui->relationLabel->setEnabled(rel_enable);
    ui->relationListWidget->setEnabled(rel_enable);
    ui->hintLabel->clear();

    bool value_enable = false;
    bool enum_enable = false;
    bool range_enable = false;

    QString filter;
    if (field_ && rel_enable) {
        filter = field_;
        QListWidgetItem *rli = ui->relationListWidget->currentItem();
        if (rli && rli->type() != present_op_) {
            value_enable = true;
            if (ftype_can_slice(ftype_)) {
                range_enable = true;
            }
            enum_enable = ui->enumListWidget->count() > 0;
            filter.append(QString(" %1").arg(rli->text()));
        }
        if (value_enable && !ui->valueLineEdit->text().isEmpty()) {
            if (ftype_ == FT_STRING) {
                filter.append(QString(" \"%1\"").arg(ui->valueLineEdit->text()));
            } else {
                filter.append(QString(" %1").arg(ui->valueLineEdit->text()));
            }
        }
    }

    ui->valueLabel->setEnabled(value_enable);
    ui->valueLineEdit->setEnabled(value_enable);

    ui->enumLabel->setEnabled(enum_enable);
    ui->enumListWidget->setEnabled(enum_enable);

    ui->rangeLabel->setEnabled(range_enable);
    ui->rangeLineEdit->setEnabled(range_enable);

    ui->displayFilterLineEdit->setText(filter);

    QString hint = "<small><i>";
    if (ui->fieldTreeWidget->selectedItems().count() < 1) {
        hint.append(tr("Select a field name to get started"));
    } else if (ui->displayFilterLineEdit->syntaxState() != SyntaxLineEdit::Valid) {
        hint.append(ui->displayFilterLineEdit->syntaxErrorMessage());
    } else {
        hint.append(tr("Click OK to insert this filter"));
    }
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);

    QPushButton *ok_bt = ui->buttonBox->button(QDialogButtonBox::Ok);
    if (ok_bt) {
        bool ok_enable = !(ui->displayFilterLineEdit->text().isEmpty()
                || (ui->displayFilterLineEdit->syntaxState() == SyntaxLineEdit::Invalid));
        ok_bt->setEnabled(ok_enable);
    }
}

void DisplayFilterExpressionDialog::fillEnumBooleanValues(const true_false_string *tfs)
{
    if (!tfs) tfs = &tfs_true_false;
    QListWidgetItem *eli = new QListWidgetItem(tfs->true_string, ui->enumListWidget);
    eli->setData(Qt::UserRole, QString("1"));
    eli = new QListWidgetItem(tfs->false_string, ui->enumListWidget);
    eli->setData(Qt::UserRole, QString("0"));
}

void DisplayFilterExpressionDialog::fillEnumIntValues(const _value_string *vals, int base)
{
    if (!vals) return;

    for (int i = 0; vals[i].strptr != NULL; i++) {
        QListWidgetItem *eli = new QListWidgetItem(vals[i].strptr, ui->enumListWidget);
        eli->setData(Qt::UserRole, int_to_qstring(vals[i].value, 0, base));
    }
}

void DisplayFilterExpressionDialog::fillEnumInt64Values(const _val64_string *vals64, int base)
{
    if (!vals64) return;

    for (int i = 0; vals64[i].strptr != NULL; i++) {
        QListWidgetItem *eli = new QListWidgetItem(vals64[i].strptr, ui->enumListWidget);
        eli->setData(Qt::UserRole, int_to_qstring(vals64[i].value, 0, base));
    }
}

void DisplayFilterExpressionDialog::fillEnumRangeValues(const _range_string *rvals)
{
    if (!rvals) return;

    for (int i = 0; rvals[i].strptr != NULL; i++) {
        QString range_text = rvals[i].strptr;

        // Tell the user which values are valid here. Default to value_min below.
        if (rvals[i].value_min != rvals[i].value_max) {
            range_t range;
            range.nranges = 1;
            range.ranges[0].low = rvals[i].value_min;
            range.ranges[0].high = rvals[i].value_max;
            range_text.append(QString(" (%1 valid)").arg(range_to_qstring(&range)));
        }

        QListWidgetItem *eli = new QListWidgetItem(range_text, ui->enumListWidget);
        eli->setData(Qt::UserRole, QString::number(rvals[i].value_min));
    }
}

void DisplayFilterExpressionDialog::on_fieldTreeWidget_itemSelectionChanged()
{
    ftype_ = FT_NONE;
    field_ = NULL;
    QTreeWidgetItem *cur_fti = NULL;

    if (ui->fieldTreeWidget->selectedItems().count() > 0) {
        cur_fti = ui->fieldTreeWidget->selectedItems()[0];
    }
    ui->valueLineEdit->clear();
    ui->enumListWidget->clear();
    ui->rangeLineEdit->clear();

    if (cur_fti && cur_fti->type() == proto_type_) {
        ftype_ = FT_PROTOCOL;
        field_ = proto_get_protocol_filter_name(cur_fti->data(0, Qt::UserRole).toInt());
    } else if (cur_fti && cur_fti->type() == field_type_) {
        header_field_info *hfinfo = cur_fti->data(0, Qt::UserRole).value<header_field_info*>();
        if (hfinfo) {
            ftype_ = hfinfo->type;
            field_ = hfinfo->abbrev;

            switch(ftype_) {
            case FT_BOOLEAN:
                // Let the user select the "True" and "False" values.
                fillEnumBooleanValues((const true_false_string *)hfinfo->strings);
                break;
            case FT_UINT8:
            case FT_UINT16:
            case FT_UINT24:
            case FT_UINT32:
            case FT_INT8:
            case FT_INT16:
            case FT_INT24:
            case FT_INT32:
            {
                int base;

                switch (hfinfo->display & FIELD_DISPLAY_E_MASK) {
                case BASE_HEX:
                case BASE_HEX_DEC:
                    base = 16;
                    break;
                case BASE_OCT:
                    base = 8;
                    break;
                default:
                    base = 10;
                    break;
                }
                // Let the user select from a list of value_string or range_string values.
                if (hfinfo->strings && ! ((hfinfo->display & FIELD_DISPLAY_E_MASK) == BASE_CUSTOM)) {
                    if (hfinfo->display & BASE_RANGE_STRING) {
                        fillEnumRangeValues((const range_string *)hfinfo->strings);
                    } else if (hfinfo->display & BASE_VAL64_STRING) {
                        const val64_string *vals = (const val64_string *)hfinfo->strings;
                        fillEnumInt64Values(vals, base);
                    } else { // Plain old value_string / VALS
                        const value_string *vals = (const value_string *)hfinfo->strings;
                        if (hfinfo->display & BASE_EXT_STRING)
                            vals = VALUE_STRING_EXT_VS_P((value_string_ext *)vals);
                        fillEnumIntValues(vals, base);
                    }
                }
                break;
            }
            default:
                break;
            }
        }
    }
    if (ui->enumListWidget->count() > 0) {
        ui->enumListWidget->setCurrentRow(0);
    }

    bool all_show = field_ != NULL;
    for (int i = 0; i < ui->relationListWidget->count(); i++) {
        QListWidgetItem *li = ui->relationListWidget->item(i);
        switch (li->type()) {
        case eq_op_:
            li->setHidden(!ftype_can_eq(ftype_) && !(ftype_can_slice(ftype_) && ftype_can_eq(FT_BYTES)));
            break;
        case ne_op_:
            li->setHidden(!ftype_can_ne(ftype_) && !(ftype_can_slice(ftype_) && ftype_can_ne(FT_BYTES)));
            break;
        case gt_op_:
            li->setHidden(!ftype_can_gt(ftype_) && !(ftype_can_slice(ftype_) && ftype_can_gt(FT_BYTES)));
            break;
        case lt_op_:
            li->setHidden(!ftype_can_lt(ftype_) && !(ftype_can_slice(ftype_) && ftype_can_lt(FT_BYTES)));
            break;
        case ge_op_:
            li->setHidden(!ftype_can_ge(ftype_) && !(ftype_can_slice(ftype_) && ftype_can_ge(FT_BYTES)));
            break;
        case le_op_:
            li->setHidden(!ftype_can_le(ftype_) && !(ftype_can_slice(ftype_) && ftype_can_le(FT_BYTES)));
            break;
        case contains_op_:
            li->setHidden(!ftype_can_contains(ftype_) && !(ftype_can_slice(ftype_) && ftype_can_contains(FT_BYTES)));
            break;
        case matches_op_:
            li->setHidden(!ftype_can_matches(ftype_) && !(ftype_can_slice(ftype_) && ftype_can_matches(FT_BYTES)));
            break;
        default:
            li->setHidden(!all_show);
            break;
        }
    }
    if (all_show) {
        // Select "==" if it's present and we have a value, "is present" otherwise
        int row = ui->relationListWidget->count() > 1 && ui->enumListWidget->count() > 0 ? 1 : 0;
        ui->relationListWidget->setCurrentRow(row);
    }

    if (ftype_ != FT_NONE) {
        ui->valueLabel->setText(QString("%1 (%2)")
                                .arg(value_label_pfx_)
                                .arg(ftype_pretty_name(ftype_)));
    } else {
        ui->valueLabel->setText(value_label_pfx_);
    }

    updateWidgets();
}

void DisplayFilterExpressionDialog::on_relationListWidget_itemSelectionChanged()
{
    updateWidgets();
}

void DisplayFilterExpressionDialog::on_enumListWidget_itemSelectionChanged()
{
    if (ui->enumListWidget->selectedItems().count() > 0) {
        QListWidgetItem *eli = ui->enumListWidget->selectedItems()[0];
        ui->valueLineEdit->setText(eli->data(Qt::UserRole).toString());
    }
    updateWidgets();
}

void DisplayFilterExpressionDialog::on_searchLineEdit_textChanged(const QString &search_re)
{
    ui->fieldTreeWidget->setUpdatesEnabled(false);
    QTreeWidgetItemIterator it(ui->fieldTreeWidget);
    QRegExp regex(search_re, Qt::CaseInsensitive);
    while (*it) {
        bool hidden = true;
        if (search_re.isEmpty() || (*it)->text(0).contains(regex)) {
            hidden = false;
            if ((*it)->type() == field_type_) {
                (*it)->parent()->setHidden(false);
            }
        }
        (*it)->setHidden(hidden);
        ++it;
    }
    ui->fieldTreeWidget->setUpdatesEnabled(true);
}

void DisplayFilterExpressionDialog::on_buttonBox_accepted()
{
    emit insertDisplayFilter(ui->displayFilterLineEdit->text());
}

void DisplayFilterExpressionDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_FILTER_EXPRESSION_DIALOG);
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
