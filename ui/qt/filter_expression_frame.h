/* filter_expression_frame.h
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

#ifndef FILTER_EXPRESSION_FRAME_H
#define FILTER_EXPRESSION_FRAME_H

#include "accordion_frame.h"
#include "preferences_dialog.h"

namespace Ui {
class FilterExpressionFrame;
}

class FilterExpressionFrame : public AccordionFrame
{
    Q_OBJECT

public:
    explicit FilterExpressionFrame(QWidget *parent = 0);
    ~FilterExpressionFrame();

    void addExpression(const QString filter_text);

signals:
    void showPreferencesDialog(PreferencesDialog::PreferencesPane start_pane);
    void filterExpressionsChanged();

protected:
    virtual void showEvent(QShowEvent *event);

private:
    Ui::FilterExpressionFrame *ui;

private slots:
    void updateWidgets();
    void on_filterExpressionPreferencesToolButton_clicked();
    void on_labelLineEdit_textChanged(const QString);
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
};

#endif // FILTER_EXPRESSION_FRAME_H

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
