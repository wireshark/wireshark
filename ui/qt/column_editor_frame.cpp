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

#include <QPushButton>
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

void ColumnEditorFrame::setFields(int index)
{
    bool ok = true;

    if (index == COL_CUSTOM) {
        ui->fieldsNameLineEdit->setText(saved_fields_);
        ui->fieldsNameLineEdit->checkCustomColumn(saved_fields_);
        ui->occurrenceLineEdit->setText(saved_occurrence_);
        ui->occurrenceLineEdit->checkInteger(saved_occurrence_);
        if ((ui->fieldsNameLineEdit->syntaxState() != SyntaxLineEdit::Valid) ||
            (ui->occurrenceLineEdit->syntaxState() != SyntaxLineEdit::Valid)) {
            ok = false;
        }
    } else {
        ui->fieldsNameLineEdit->clear();
        ui->fieldsNameLineEdit->setSyntaxState(SyntaxLineEdit::Empty);
        ui->occurrenceLineEdit->clear();
        ui->occurrenceLineEdit->setSyntaxState(SyntaxLineEdit::Empty);
    }
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok);
}

void ColumnEditorFrame::editColumn(int column)
{
    cur_column_ = column;
    ui->titleLineEdit->setText(get_column_title(column));
    saved_fields_ = get_column_custom_fields(column);
    saved_occurrence_ = QString::number(get_column_custom_occurrence(column));
    ui->typeComboBox->setCurrentIndex(get_column_format(column));
    setFields(ui->typeComboBox->currentIndex());
}

void ColumnEditorFrame::on_typeComboBox_activated(int index)
{
    setFields(index);
}

void ColumnEditorFrame::on_fieldsNameLineEdit_textEdited(const QString &fields)
{
    ui->fieldsNameLineEdit->checkCustomColumn(fields);
    if (ui->typeComboBox->currentIndex() != COL_CUSTOM) {
        ui->typeComboBox->setCurrentIndex(COL_CUSTOM);
        ui->occurrenceLineEdit->setText(saved_occurrence_);
    }

    bool ok = true;
    if ((ui->fieldsNameLineEdit->syntaxState() == SyntaxLineEdit::Invalid) ||
        ((ui->typeComboBox->currentIndex() == COL_CUSTOM) &&
        (ui->occurrenceLineEdit->syntaxState() == SyntaxLineEdit::Empty)))
        ok = false;
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok);

    saved_fields_ = fields;
}

void ColumnEditorFrame::on_occurrenceLineEdit_textEdited(const QString &occurrence)
{
    ui->occurrenceLineEdit->checkInteger(occurrence);
    if (ui->typeComboBox->currentIndex() != COL_CUSTOM) {
        ui->typeComboBox->setCurrentIndex(COL_CUSTOM);
        ui->fieldsNameLineEdit->setText(saved_fields_);
    }

    bool ok = true;
    if ((ui->occurrenceLineEdit->syntaxState() == SyntaxLineEdit::Invalid) ||
        ((ui->typeComboBox->currentIndex() == COL_CUSTOM) &&
        (ui->occurrenceLineEdit->syntaxState() == SyntaxLineEdit::Empty)))
        ok = false;
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok);

    saved_occurrence_ = occurrence;
}

void ColumnEditorFrame::on_buttonBox_rejected()
{
    cur_column_ = -1;
    animatedHide();
}

void ColumnEditorFrame::on_buttonBox_accepted()
{
    QByteArray col_str;
    if (cur_column_ >= 0) {
        col_str = ui->titleLineEdit->text().toUtf8();
        set_column_title(cur_column_, col_str.constData());
        set_column_format(cur_column_, ui->typeComboBox->currentIndex());
        if (ui->typeComboBox->currentIndex() == COL_CUSTOM) {
            col_str = ui->fieldsNameLineEdit->text().toUtf8();
            set_column_custom_fields(cur_column_, col_str.constData());
            if (!ui->occurrenceLineEdit->text().isEmpty()) {
                set_column_custom_occurrence(cur_column_, ui->occurrenceLineEdit->text().toInt());
            }
        }
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
        }
        emit columnEdited();
    }

    on_buttonBox_rejected();
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
