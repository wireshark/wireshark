/* extcap_options_dialog.h
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


#ifndef EXTCAP_OPTIONS_DIALOG_H
#define EXTCAP_OPTIONS_DIALOG_H

#include <config.h>

#ifdef HAVE_EXTCAP

#include <QWidget>
#include <QDialog>
#include <QPushButton>
#include <QList>

#include "interface_tree.h"

#include "ui/qt/extcap_argument.h"

#include <extcap.h>
#include <extcap_parser.h>

namespace Ui {
class ExtcapOptionsDialog;
}

typedef QList<ExtcapArgument *> ExtcapArgumentList;

class ExtcapOptionsDialog : public QDialog
{
    Q_OBJECT

public:
    ~ExtcapOptionsDialog();
    static ExtcapOptionsDialog * createForDevice(QString &device_name, QWidget *parent = 0);

private Q_SLOTS:
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_helpRequested();
    void updateWidgets();
    void anyValueChanged();

private:
    explicit ExtcapOptionsDialog(QWidget *parent = 0);

    Ui::ExtcapOptionsDialog *ui;
    QString device_name;
    guint device_idx;

    ExtcapArgumentList extcapArguments;

    void loadArguments();

    bool saveOptionToCaptureInfo();
    void storeValues();
    void resetValues();
};

#endif /* HAVE_EXTCAP */

#endif // EXTCAP_OPTIONS_DIALOG_H

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
