/* pluginifdemo_about.cpp
 *
 * Author: Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <plugins/epan/pluginifdemo/ui/pluginifdemo_about.h>
#include <ui_pluginifdemo_about.h>

#include <config.h>

#include <QDialog>
#include <QWidget>
#include <QAbstractButton>

PluginIFDemo_About::PluginIFDemo_About(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PluginIFDemo_About)
{
    ui->setupUi(this);
}

PluginIFDemo_About::~PluginIFDemo_About()
{
    delete ui;
}

void PluginIFDemo_About::on_buttonBox_clicked(QAbstractButton *)
{
    this->close();
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
