/* address_editor_frame.h
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

#ifndef ADDRESS_EDITOR_FRAME_H
#define ADDRESS_EDITOR_FRAME_H

#include "accordion_frame.h"

#include "capture_file.h"

namespace Ui {
class AddressEditorFrame;
}

struct epan_column_info;

class AddressEditorFrame : public AccordionFrame
{
    Q_OBJECT

public:
    explicit AddressEditorFrame(QWidget *parent = 0);
    ~AddressEditorFrame();

public slots:
    void editAddresses(CaptureFile &cf, int column = -1);

signals:
    void showNameResolutionPreferences(const QString module_name);
    void editAddressStatus(const QString &status);
    void redissectPackets();

private slots:
    void updateWidgets();
    void on_nameResolutionPreferencesToolButton_clicked();
    void on_addressComboBox_currentIndexChanged(const QString &);
    void on_nameLineEdit_textEdited(const QString &);
    void on_nameLineEdit_returnPressed();
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();

private:
    Ui::AddressEditorFrame *ui;
    capture_file *cap_file_;

    bool isAddressColumn(struct epan_column_info *cinfo, int column);
};

#endif // ADDRESS_EDITOR_FRAME_H

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
