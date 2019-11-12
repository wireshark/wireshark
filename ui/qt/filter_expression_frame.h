/* filter_expression_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_EXPRESSION_FRAME_H
#define FILTER_EXPRESSION_FRAME_H

#include "accordion_frame.h"

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
    void editExpression(int exprIdx);

signals:
    void showPreferencesDialog(QString pane_name);
    void filterExpressionsChanged();

protected:
    virtual void showEvent(QShowEvent *event);
    virtual void keyPressEvent(QKeyEvent *event);

private:
    Ui::FilterExpressionFrame *ui;

    int editExpression_;

private slots:
    void updateWidgets();
    void on_filterExpressionPreferencesPushButton_clicked();
    void on_labelLineEdit_textChanged(const QString);
    void on_displayFilterLineEdit_textChanged(const QString);
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
