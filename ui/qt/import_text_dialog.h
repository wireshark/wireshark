/* import_text_dialog.h
 *
 * $Id$
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

#ifndef IMPORT_TEXT_DIALOG_H
#define IMPORT_TEXT_DIALOG_H

#include "config.h"

#include <stdio.h>

#include <glib.h>

#include "ui/text_import.h"

#include <syntax_line_edit.h>

#include <QDialog>
#include <QPushButton>
#include <QRadioButton>

namespace Ui {
class ImportTextDialog;
}

class ImportTextDialog : public QDialog
{
    Q_OBJECT
    
public:
    explicit ImportTextDialog(QWidget *parent = 0);
    ~ImportTextDialog();
    QString &capfileName();
    
private:
    void convertTextFile();
    void enableHeaderWidgets(bool enable_buttons = true);
    void check_line_edit(SyntaxLineEdit *le, const QString &num_str, int base, guint max_val, bool is_short, guint *val_ptr);

    Ui::ImportTextDialog *ti_ui_;

    QPushButton *ok_button_;
    QList<QRadioButton *>encap_buttons_;
    text_import_info_t import_info_;
    QString capfile_name_;

public slots:
    int exec();

private slots:
    void on_textFileBrowseButton_clicked();
    void on_textFileLineEdit_textChanged(const QString &arg1);
    void on_encapComboBox_currentIndexChanged(int index);
    void on_dateTimeLineEdit_textChanged(const QString &arg1);
    void on_noDummyButton_toggled(bool checked);
    void on_ethernetButton_toggled(bool checked);
    void on_ipv4Button_toggled(bool checked);
    void on_udpButton_toggled(bool checked);
    void on_tcpButton_toggled(bool checked);
    void on_sctpButton_toggled(bool checked);
    void on_sctpDataButton_toggled(bool checked);
    void on_ethertypeLineEdit_textChanged(const QString &ethertype_str);
    void on_protocolLineEdit_textChanged(const QString &protocol_str);
    void on_sourcePortLineEdit_textChanged(const QString &source_port_str);
    void on_destinationPortLineEdit_textChanged(const QString &destination_port_str);
    void on_tagLineEdit_textChanged(const QString &tag_str);
    void on_ppiLineEdit_textChanged(const QString &ppi_str);
    void on_maxLengthLineEdit_textChanged(const QString &max_frame_len_str);
    void on_buttonBox_helpRequested();
};


#endif // IMPORT_TEXT_DIALOG_H

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
