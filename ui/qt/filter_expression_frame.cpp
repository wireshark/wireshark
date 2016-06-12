/* filter_expression_frame.cpp
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

#include "filter_expression_frame.h"
#include <ui_filter_expression_frame.h>

#include <epan/filter_expressions.h>
#include <ui/preference_utils.h>

#include <QPushButton>

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

    ui->labelLineEdit->setText(tr("Apply this filter"));
    ui->displayFilterLineEdit->setText(filter_text);
}

void FilterExpressionFrame::showEvent(QShowEvent *event)
{
    ui->labelLineEdit->setFocus();
    ui->labelLineEdit->selectAll();

    AccordionFrame::showEvent(event);
}

void FilterExpressionFrame::updateWidgets()
{
    bool ok_enable = false;

    if (!ui->labelLineEdit->text().isEmpty()) {
        ok_enable = true;
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok_enable);
}

void FilterExpressionFrame::on_filterExpressionPreferencesToolButton_clicked()
{
    on_buttonBox_rejected();
    emit showPreferencesDialog(PreferencesDialog::ppFilterExpressions);
}

void FilterExpressionFrame::on_labelLineEdit_textChanged(const QString)
{
    updateWidgets();
}

void FilterExpressionFrame::on_buttonBox_accepted()
{
    QByteArray label_ba = ui->labelLineEdit->text().toUtf8();
    QByteArray expr_ba = ui->displayFilterLineEdit->text().toUtf8();

    filter_expression_new(label_ba.constData(), expr_ba.constData(), TRUE);

    on_buttonBox_rejected();
    emit filterExpressionsChanged();
    prefs_main_write();
}

void FilterExpressionFrame::on_buttonBox_rejected()
{
    ui->labelLineEdit->clear();
    ui->displayFilterLineEdit->clear();
    animatedHide();
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
