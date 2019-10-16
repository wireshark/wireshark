/* stock_icon_tool_button.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STOCKICONTOOLBUTTON_H
#define STOCKICONTOOLBUTTON_H

#include <QToolButton>

class StockIconToolButton : public QToolButton
{
    Q_OBJECT
public:
    explicit StockIconToolButton(QWidget * parent = 0, QString stock_icon_name = QString());

    void setIconMode(QIcon::Mode mode = QIcon::Normal);
    void setStockIcon(QString icon_name = QString());

protected:
    virtual bool event(QEvent *event);

private:
    QIcon base_icon_;
    QString icon_name_;
    int leave_timer_;
    static const int leave_interval_ = 500; // ms
};

#endif // STOCKICONTOOLBUTTON_H

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
