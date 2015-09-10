/* stock_icon_tool_button.h
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

#ifndef STOCKICONTOOLBUTTON_H
#define STOCKICONTOOLBUTTON_H

#include <QToolButton>

class StockIconToolButton : public QToolButton
{
    Q_OBJECT
public:
    explicit StockIconToolButton(QWidget * parent = 0, QString stock_icon_name = QString());

    void setIconMode(QIcon::Mode mode = QIcon::Normal);
    void setStockIcon(QString icon_name);

protected:
    virtual bool event(QEvent *event);

private:
    QIcon base_icon_;
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
