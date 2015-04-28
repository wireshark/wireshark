/* extcap_argument_file.h
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

#ifndef UI_QT_EXTCAP_ARGUMENT_FILE_H_
#define UI_QT_EXTCAP_ARGUMENT_FILE_H_

#include <QObject>
#include <QWidget>
#include <QLineEdit>

#include <extcap_parser.h>
#include <extcap_argument.h>

class ExtcapArgumentFileSelection : public ExtcapArgument
{
    Q_OBJECT

public:
    ExtcapArgumentFileSelection    (extcap_arg * argument);

    virtual QWidget * createEditor(QWidget * parent);

    virtual QString value();

protected:
    QLineEdit * textBox;

private slots:
    /* opens the file dialog */
    void openFileDialog();

};

#endif /* UI_QT_EXTCAP_ARGUMENT_FILE_H_ */

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
