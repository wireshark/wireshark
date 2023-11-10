/* column_editor_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/column.h>
#include <epan/prefs.h>
#include <ui/recent.h>

#include <ui/preference_utils.h>

#include "main_application.h"

#include "column_editor_frame.h"
#include <ui_column_editor_frame.h>

#include <QPushButton>
#include <QComboBox>
#include <QKeyEvent>

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

    connect(ui->fieldsNameLineEdit, &FieldFilterEdit::textChanged,
            ui->fieldsNameLineEdit, &FieldFilterEdit::checkCustomColumn);
    connect(ui->fieldsNameLineEdit, &FieldFilterEdit::textChanged,
            this, &ColumnEditorFrame::checkCanResolve);
}

ColumnEditorFrame::~ColumnEditorFrame()
{
    delete ui;
}

bool ColumnEditorFrame::syntaxIsValid(void)
{
    // Fields must be a valid filter.
    // Occurrence must be empty or valid.
    return ((ui->fieldsNameLineEdit->syntaxState() == SyntaxLineEdit::Valid) &&
            (ui->occurrenceLineEdit->syntaxState() != SyntaxLineEdit::Invalid));
}

void ColumnEditorFrame::setFields(int index)
{
    bool ok = true;

    if (index == COL_CUSTOM) {
        ui->fieldsNameLineEdit->setText(saved_fields_);
        ui->fieldsNameLineEdit->checkCustomColumn(saved_fields_);
        ui->occurrenceLineEdit->setText(saved_occurrence_);
        ui->occurrenceLineEdit->checkInteger(saved_occurrence_);
        ok = syntaxIsValid();
    } else {
        ui->fieldsNameLineEdit->clear();
        ui->fieldsNameLineEdit->setSyntaxState(SyntaxLineEdit::Empty);
        ui->occurrenceLineEdit->clear();
        ui->occurrenceLineEdit->setSyntaxState(SyntaxLineEdit::Empty);
        ui->resolvedCheckBox->setEnabled(false);
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
    ui->resolvedCheckBox->setChecked(get_column_resolved(column));
    setFields(ui->typeComboBox->currentIndex());
}

void ColumnEditorFrame::showEvent(QShowEvent *event)
{
    ui->titleLineEdit->setFocus();
    ui->titleLineEdit->selectAll();

    AccordionFrame::showEvent(event);
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

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(syntaxIsValid());

    saved_fields_ = fields;
}

void ColumnEditorFrame::on_occurrenceLineEdit_textEdited(const QString &occurrence)
{
    ui->occurrenceLineEdit->checkInteger(occurrence);
    if (ui->typeComboBox->currentIndex() != COL_CUSTOM) {
        ui->typeComboBox->setCurrentIndex(COL_CUSTOM);
        ui->fieldsNameLineEdit->setText(saved_fields_);
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(syntaxIsValid());

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
            gint width = recent_get_column_width(cur_column_);
            gchar xalign = recent_get_column_xalign(cur_column_);
            col_str = ui->fieldsNameLineEdit->text().toUtf8();
            set_column_custom_fields(cur_column_, col_str.constData());
            recent_set_column_width(cur_column_, width);
            recent_set_column_xalign(cur_column_, xalign);
            if (!ui->occurrenceLineEdit->text().isEmpty()) {
                set_column_custom_occurrence(cur_column_, ui->occurrenceLineEdit->text().toInt());
            }
            if (ui->resolvedCheckBox->isEnabled()) {
                set_column_resolved(cur_column_, ui->resolvedCheckBox->isChecked());
            }
        }
        prefs_main_write();
        emit columnEdited();
    }

    on_buttonBox_rejected();
}

void ColumnEditorFrame::keyPressEvent(QKeyEvent *event)
{
    if (event->modifiers() == Qt::NoModifier) {
        if (event->key() == Qt::Key_Escape) {
            on_buttonBox_rejected();
        } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            if (ui->buttonBox->button(QDialogButtonBox::Ok)->isEnabled()) {
                on_buttonBox_accepted();
            } else if (ui->fieldsNameLineEdit->syntaxState() == SyntaxLineEdit::Empty) {
                mainApp->pushStatus(MainApplication::FilterSyntax, tr("Missing fields."));
            } else if (ui->fieldsNameLineEdit->syntaxState() != SyntaxLineEdit::Valid) {
                mainApp->pushStatus(MainApplication::FilterSyntax, tr("Invalid fields."));
            } else if (ui->occurrenceLineEdit->syntaxState() == SyntaxLineEdit::Invalid) {
                mainApp->pushStatus(MainApplication::FilterSyntax, tr("Invalid occurrence value."));
            }
        }
    }

    AccordionFrame::keyPressEvent(event);
}

void ColumnEditorFrame::checkCanResolve()
{
    if (ui->fieldsNameLineEdit->syntaxState() == SyntaxLineEdit::Valid && column_prefs_custom_resolve(ui->fieldsNameLineEdit->text().toUtf8().constData())) {
        ui->resolvedCheckBox->setEnabled(true);
    } else  {
        ui->resolvedCheckBox->setEnabled(false);
        ui->resolvedCheckBox->setChecked(false);
    }
}
