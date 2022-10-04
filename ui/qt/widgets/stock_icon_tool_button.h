/** @file
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
public:
    explicit StockIconToolButton(QWidget * parent = 0, QString stock_icon_name = QString());

    void setIconMode(QIcon::Mode mode = QIcon::Normal);
    void setStockIcon(QString icon_name = QString());

protected:
    virtual bool event(QEvent *event);

private:
    QIcon base_icon_;
    QString icon_name_;
};

#endif // STOCKICONTOOLBUTTON_H
