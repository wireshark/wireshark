/* column_editor_frame.cpp
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

#include "config.h"

#include <glib.h>

#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/prefs.h>

#include <ui/preference_utils.h>

#include "column_editor_frame.h"
#include <ui_column_editor_frame.h>

#include <QComboBox>

ColumnEditorFrame::ColumnEditorFrame(QWidget *parent) :
    AccordionFrame(parent),
    ui(new Ui::ColumnEditorFrame),
    cur_column_(-1)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif

    for (int i = 0; i < NUM_COL_FMTS; i++) {
        ui->typeComboBox->addItem(col_format_desc(i), QVariant(i));
    }
}

ColumnEditorFrame::~ColumnEditorFrame()
{
    delete ui;
}

void ColumnEditorFrame::editColumn(int column)
{
    cur_column_ = column;
    ui->titleLineEdit->setText(get_column_title(column));
    saved_field_ = get_column_custom_field(column);
    saved_occurrence_ = get_column_custom_occurrence(column);
    ui->typeComboBox->setCurrentIndex(get_column_format(column));
}

void ColumnEditorFrame::on_typeComboBox_activated(int index)
{
    if (index == COL_CUSTOM) {
        ui->fieldNameLineEdit->setText(saved_field_);
        ui->occurrenceLineEdit->setText(saved_occurrence_);
    } else {
        ui->fieldNameLineEdit->clear();
        ui->occurrenceLineEdit->clear();
    }
}

void ColumnEditorFrame::on_fieldNameLineEdit_textEdited(const QString &field)
{
    ui->fieldNameLineEdit->checkFieldName(field);
    if (ui->typeComboBox->currentIndex() != COL_CUSTOM) {
        ui->typeComboBox->setCurrentIndex(COL_CUSTOM);
        ui->occurrenceLineEdit->setText(saved_occurrence_);
    }

    bool ok = true;
    if (ui->fieldNameLineEdit->syntaxState() == SyntaxLineEdit::Invalid) ok = false;
    ui->okButton->setEnabled(ok);

    saved_field_ = field;
}

void ColumnEditorFrame::on_occurrenceLineEdit_textEdited(const QString &occurrence)
{
    ui->occurrenceLineEdit->checkInteger(occurrence);
    if (ui->typeComboBox->currentIndex() != COL_CUSTOM) {
        ui->typeComboBox->setCurrentIndex(COL_CUSTOM);
        ui->fieldNameLineEdit->setText(saved_field_);
    }

    bool ok = true;
    if (ui->occurrenceLineEdit->syntaxState() == SyntaxLineEdit::Invalid) ok = false;
    ui->okButton->setEnabled(ok);

    saved_occurrence_ = occurrence;
}

void ColumnEditorFrame::on_cancelButton_clicked()
{
    cur_column_ = -1;
    animatedHide();
}

void ColumnEditorFrame::on_okButton_clicked()
{
    QByteArray col_str;
    if (cur_column_ >= 0) {
        col_str = ui->titleLineEdit->text().toUtf8();
        set_column_title(cur_column_, col_str.constData());
        set_column_format(cur_column_, ui->typeComboBox->currentIndex());
        if (ui->typeComboBox->currentIndex() == COL_CUSTOM) {
            col_str = ui->fieldNameLineEdit->text().toUtf8();
            set_column_custom_field(cur_column_, col_str.constData());
            if (!ui->occurrenceLineEdit->text().isEmpty()) {
                set_column_custom_occurrence(cur_column_, ui->occurrenceLineEdit->text().toInt());
            }
        }
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
        }
        emit columnEdited();
    }
    on_cancelButton_clicked();
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
