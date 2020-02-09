/* address_editor_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
    void redissectPackets();

protected:
    virtual void showEvent(QShowEvent *event);
    virtual void keyPressEvent(QKeyEvent *event);

private slots:
    void displayPreviousUserDefinedHostname();
    void updateWidgets();
    void on_nameResolutionPreferencesToolButton_clicked();
    void on_addressComboBox_currentIndexChanged(const QString &);
    void on_nameLineEdit_textEdited(const QString &);
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
