/* pluginifdemo_about.h
 *
 * Author: Roland Knall <rknall@gmail.com>
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

#ifndef PLUGINIFDEMO_ABOUT_H_
#define PLUGINIFDEMO_ABOUT_H_

#include <QWidget>
#include <QDialog>
#include <QAbstractButton>
#include <QPixmap>
#include <QGraphicsScene>

namespace Ui {
class PluginIFDemo_About;
}

class PluginIFDemo_About : public QDialog
{
    Q_OBJECT

public:
    explicit PluginIFDemo_About(QWidget *parent = 0);
    ~PluginIFDemo_About();

private slots:
    void on_buttonBox_clicked(QAbstractButton *button);

private:
    Ui::PluginIFDemo_About *ui;
};

#endif /* PLUGINIFDEMO_ABOUT_H_ */

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
