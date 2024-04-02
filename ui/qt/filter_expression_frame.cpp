/* filter_expression_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "filter_expression_frame.h"
#include <ui_filter_expression_frame.h>

#include <epan/filter_expressions.h>
#include <ui/preference_utils.h>

#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/pref_models.h>
#include <ui/qt/main_application.h>

#include <QPushButton>
#include <QKeyEvent>

// To do:
// - Add the ability to edit current expressions.

FilterExpressionFrame::FilterExpressionFrame(QWidget *parent) :
    AccordionFrame(parent),
    ui(new Ui::FilterExpressionFrame)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif

    editExpression_ = -1;
    updateWidgets();
}

FilterExpressionFrame::~FilterExpressionFrame()
{
    delete ui;
}

void FilterExpressionFrame::addExpression(const QString filter_text)
{
    if (isVisible()) {
        on_buttonBox_rejected();
        return;
    }

    editExpression_ = -1;
    ui->displayFilterLineEdit->setText(filter_text);

    if (! isVisible())
        animatedShow();
}

void FilterExpressionFrame::editExpression(int exprIdx)
{
    if (isVisible())
    {
        ui->labelLineEdit->clear();
        ui->displayFilterLineEdit->clear();
        ui->commentLineEdit->clear();
        editExpression_ = -1;
    }

    UatModel * uatModel = new UatModel(this, "Display expressions");
    if (! uatModel->index(exprIdx, 1).isValid())
        return;

    editExpression_ = exprIdx;

    ui->labelLineEdit->setText(uatModel->data(uatModel->index(exprIdx, 1), Qt::DisplayRole).toString());
    ui->displayFilterLineEdit->setText(uatModel->data(uatModel->index(exprIdx, 2), Qt::DisplayRole).toString());
    ui->commentLineEdit->setText(uatModel->data(uatModel->index(exprIdx, 3), Qt::DisplayRole).toString());

    delete(uatModel);

    if (! isVisible())
        animatedShow();
}

void FilterExpressionFrame::showEvent(QShowEvent *event)
{
    ui->labelLineEdit->setFocus();
    ui->labelLineEdit->selectAll();

    AccordionFrame::showEvent(event);
}

void FilterExpressionFrame::updateWidgets()
{
    bool ok_enable = true;

    if (ui->labelLineEdit->text().isEmpty() ||
        ((ui->displayFilterLineEdit->syntaxState() != SyntaxLineEdit::Valid) &&
         (ui->displayFilterLineEdit->syntaxState() != SyntaxLineEdit::Deprecated)))
        ok_enable = false;

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok_enable);
}

void FilterExpressionFrame::on_filterExpressionPreferencesPushButton_clicked()
{
    on_buttonBox_rejected();
    emit showPreferencesDialog(PrefsModel::typeToString(PrefsModel::FilterButtons));
}

void FilterExpressionFrame::on_labelLineEdit_textChanged(const QString)
{
    updateWidgets();
}

void FilterExpressionFrame::on_displayFilterLineEdit_textChanged(const QString)
{
    updateWidgets();
}

void FilterExpressionFrame::on_buttonBox_accepted()
{
    QByteArray label_ba = ui->labelLineEdit->text().toUtf8();
    QByteArray expr_ba = ui->displayFilterLineEdit->text().toUtf8();
    QByteArray comment_ba = ui->commentLineEdit->text().toUtf8();

    if (ui->labelLineEdit->text().length() == 0 || ui->displayFilterLineEdit->text().length() == 0)
        return;

    if (! ui->displayFilterLineEdit->checkFilter())
        return;

    if (editExpression_ >= 0)
    {
        UatModel * uatModel = new UatModel(this, "Display expressions");
        if (! uatModel->index(editExpression_, 1).isValid())
            return;

        uatModel->setData(uatModel->index(editExpression_, 1), QVariant::fromValue(label_ba));
        uatModel->setData(uatModel->index(editExpression_, 2), QVariant::fromValue(expr_ba));
        uatModel->setData(uatModel->index(editExpression_, 3), QVariant::fromValue(comment_ba));
    }
    else
    {
        filter_expression_new(label_ba.constData(), expr_ba.constData(), comment_ba.constData(), true);
    }

    save_migrated_uat("Display expressions", &prefs.filter_expressions_old);
    on_buttonBox_rejected();
    emit filterExpressionsChanged();
}

void FilterExpressionFrame::on_buttonBox_rejected()
{
    ui->labelLineEdit->clear();
    ui->displayFilterLineEdit->clear();
    ui->commentLineEdit->clear();
    editExpression_ = -1;
    animatedHide();
}

void FilterExpressionFrame::keyPressEvent(QKeyEvent *event)
{
    if (event->modifiers() == Qt::NoModifier) {
        if (event->key() == Qt::Key_Escape) {
            on_buttonBox_rejected();
        } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            if (ui->buttonBox->button(QDialogButtonBox::Ok)->isEnabled()) {
                on_buttonBox_accepted();
            } else if (ui->labelLineEdit->text().length() == 0) {
                mainApp->pushStatus(MainApplication::FilterSyntax, tr("Missing label."));
            } else if (ui->displayFilterLineEdit->syntaxState() == SyntaxLineEdit::Empty) {
                mainApp->pushStatus(MainApplication::FilterSyntax, tr("Missing filter expression."));
            } else if (ui->displayFilterLineEdit->syntaxState() != SyntaxLineEdit::Valid) {
                mainApp->pushStatus(MainApplication::FilterSyntax, tr("Invalid filter expression."));
            }
        }
    }

    AccordionFrame::keyPressEvent(event);
}
