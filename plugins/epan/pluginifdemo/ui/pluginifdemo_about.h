/* pluginifdemo_about.h
 *
 * Author: Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
