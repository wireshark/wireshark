/* column_editor_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

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
#include <QAbstractItemView>

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

    // We want a behavior where the occurrenceLineEdit and type line edit
    // will shrink, but where they won't expand past their needed space.
    // Setting a stretch factor will make them expand (ignoring their
    // SizePolicy) unless we also set the maximum width to their size hints.
    //
    ui->horizontalLayout->setStretchFactor(ui->titleLineEdit, 2);
    ui->horizontalLayout->setStretchFactor(ui->occurrenceLineEdit, 1);
    ui->occurrenceLineEdit->setMaximumWidth(ui->occurrenceLineEdit->sizeHint().width());
    // On Windows, this is necessary to make the popup be the width of the
    // longest item, instead of the width matching the combobox and using
    // ellipses. (Linux has the popup wider by default.)
    ui->typeComboBox->view()->setMinimumWidth(ui->typeComboBox->sizeHint().width());
    // This lets the typeComboBox shrink a bit if the width is very small.
    ui->typeComboBox->setMinimumContentsLength(20);

    connect(ui->fieldsNameLineEdit, &FieldFilterEdit::textChanged,
            ui->fieldsNameLineEdit, &FieldFilterEdit::checkCustomColumn);
    connect(ui->fieldsNameLineEdit, &FieldFilterEdit::textChanged,
            this, &ColumnEditorFrame::checkCanResolve);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    connect(ui->typeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &ColumnEditorFrame::typeChanged);
#else
    connect(ui->typeComboBox, &QComboBox::currentIndexChanged, this,
            &ColumnEditorFrame::typeChanged);
#endif
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

void ColumnEditorFrame::typeChanged(int index)
{
    // The fieldsNameLineEdit and occurrenceLineEdit are only relevant if the
    // typeComboBox is COL_CUSTOM. The text for "Custom" is small. So when
    // COL_CUSTOM is selected, shrink the size of the typeComboBox to what is
    // necessary for "Custom" and give extra space to the fieldsNameLineEdit.
    // For any other column type, do the reverse.
    if (index == COL_CUSTOM) {
        int width = fontMetrics().boundingRect(ui->typeComboBox->currentText()).width();
        if (!ui->typeComboBox->itemIcon(index).isNull()) {
            width += ui->typeComboBox->iconSize().width() + 4;
        }
        QStyleOptionComboBox opt;
        opt.initFrom(ui->typeComboBox);
        QSize sh(width, ui->typeComboBox->height());
        width = ui->typeComboBox->style()->sizeFromContents(QStyle::CT_ComboBox, &opt, sh, ui->typeComboBox).width();
        ui->typeComboBox->setMaximumWidth(width);
        ui->fieldsNameLineEdit->setMaximumWidth(16777215); // Default (no) maximum
        ui->horizontalLayout->setStretchFactor(ui->typeComboBox, 1);
        ui->horizontalLayout->setStretchFactor(ui->fieldsNameLineEdit, 4);
    } else {
        ui->typeComboBox->setMaximumWidth(ui->typeComboBox->sizeHint().width());
        ui->fieldsNameLineEdit->setMaximumWidth(ui->fieldsNameLineEdit->sizeHint().width());
        ui->horizontalLayout->setStretchFactor(ui->typeComboBox, 2);
        ui->horizontalLayout->setStretchFactor(ui->fieldsNameLineEdit, 1);
    }
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
            col_str = ui->fieldsNameLineEdit->text().toUtf8();
            set_column_custom_fields(cur_column_, col_str.constData());
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
