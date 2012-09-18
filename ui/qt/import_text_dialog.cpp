/* import_text_dialog.cpp
 *
 * $Id: capture_file_dialog.cpp 44864 2012-09-10 23:03:22Z gerald $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include <import_text_dialog.h>

#include "wiretap/wtap.h"
#include "wiretap/pcap-encap.h"

#include <epan/prefs.h>

#include "ui/text_import_scanner.h"
#include "ui/last_open_dir.h"
#include "ui/alert_box.h"
#include "ui/help_url.h"

#include "file.h"
#include "wsutil/file_util.h"
#include "tempfile.h"

#include <ui_import_text_dialog.h>
#include <wireshark_application.h>

#include <QFileDialog>
#include <QDebug>
#include <QFile>
#include <QMessageBox>
#include <QDesktopServices>
#include <QUrl>

ImportTextDialog::ImportTextDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportTextDialog),
    import_info_()
{
    int encap;
    int i;

    ui->setupUi(this);
    memset(&import_info_, 0, sizeof(import_info_));

    ok_button_ = ui->buttonBox->button(QDialogButtonBox::Ok);
    ok_button_->setEnabled(false);

#ifdef Q_WS_MAC
    // The grid layout squishes each line edit otherwise.
    int le_height = ui->textFileLineEdit->sizeHint().height();
    ui->ethertypeLineEdit->setMinimumHeight(le_height);
    ui->protocolLineEdit->setMinimumHeight(le_height);
    ui->sourcePortLineEdit->setMinimumHeight(le_height);
    ui->destinationPortLineEdit->setMinimumHeight(le_height);
    ui->tagLineEdit->setMinimumHeight(le_height);
    ui->ppiLineEdit->setMinimumHeight(le_height);
#endif

    on_dateTimeLineEdit_textChanged(ui->dateTimeLineEdit->text());

    for (i = 0; i < ui->headerGridLayout->count(); i++) {
        QRadioButton *rb = qobject_cast<QRadioButton *>(ui->headerGridLayout->itemAt(i)->widget());

        if (rb) encap_buttons_.append(rb);
    }

    /* Scan all Wiretap encapsulation types */
    import_info_.encapsulation = WTAP_ENCAP_ETHERNET;
    for (encap = import_info_.encapsulation; encap < wtap_get_num_encap_types(); encap++)
    {
        /* Check if we can write to a PCAP file
         *
         * Exclude wtap encapsulations that require a pseudo header,
         * because we won't setup one from the text we import and
         * wiretap doesn't allow us to write 'raw' frames
         */
        if ((wtap_wtap_encap_to_pcap_encap(encap) > 0) && !wtap_encap_requires_phdr(encap)) {
            const char *name;
            /* If it has got a name */
            if ((name = wtap_encap_string(encap)))
            {
                ui->encapComboBox->addItem(name, QVariant(encap));
            }
        }
    }
}

ImportTextDialog::~ImportTextDialog()
{
    delete ui;
}

QString &ImportTextDialog::capfileName() {
    return capfile_name_;
}

void ImportTextDialog::convertTextFile() {
    int import_file_fd;
    char *tmpname;
    int err;

    capfile_name_.clear();
    /* Choose a random name for the temporary import buffer */
    import_file_fd = create_tempfile(&tmpname, "import");
    capfile_name_.append(tmpname);

    import_info_.wdh = wtap_dump_fdopen(import_file_fd, WTAP_FILE_PCAP, import_info_.encapsulation, import_info_.max_frame_length, FALSE, &err);
    qDebug() << capfile_name_ << ":" << import_info_.wdh << import_info_.encapsulation << import_info_.max_frame_length;
    if (import_info_.wdh == NULL) {
        open_failure_alert_box(capfile_name_.toUtf8().constData(), err, TRUE);
        fclose(import_info_.import_text_file);
        setResult(QDialog::Rejected);
        return;
    }

    text_import_setup(&import_info_);

    text_importin = import_info_.import_text_file;

    text_importlex();

    text_import_cleanup();

    if (fclose(import_info_.import_text_file))
    {
        read_failure_alert_box(import_info_.import_text_filename, errno);
    }

    if (!wtap_dump_close(import_info_.wdh, &err))
    {
        write_failure_alert_box(capfile_name_.toUtf8().constData(), err);
    }
}


void ImportTextDialog::enableHeaderWidgets(bool enable_buttons) {
    bool ethertype = false;
    bool ipv4_proto = false;
    bool port = false;
    bool sctp_tag = false;
    bool sctp_ppi = false;

    if (enable_buttons) {
        if (ui->ethernetButton->isChecked()) {
            ethertype = true;
            on_ethertypeLineEdit_textChanged(ui->ethertypeLabel->text());
        } else  if (ui->ipv4Button->isChecked()) {
            ipv4_proto = true;
            on_protocolLineEdit_textChanged(ui->protocolLineEdit->text());
        } else if (ui->udpButton->isChecked() || ui->tcpButton->isChecked()) {
            port = true;
            on_sourcePortLineEdit_textChanged(ui->sourcePortLineEdit->text());
            on_destinationPortLineEdit_textChanged(ui->destinationPortLineEdit->text());
        } else if (ui->sctpButton->isChecked()) {
            port = true;
            sctp_tag = true;
            on_sourcePortLineEdit_textChanged(ui->sourcePortLineEdit->text());
            on_destinationPortLineEdit_textChanged(ui->destinationPortLineEdit->text());
            on_tagLineEdit_textChanged(ui->tagLineEdit->text());
        }
        if (ui->sctpDataButton->isChecked()) {
            port = true;
            sctp_ppi = true;
            on_sourcePortLineEdit_textChanged(ui->sourcePortLineEdit->text());
            on_destinationPortLineEdit_textChanged(ui->destinationPortLineEdit->text());
            on_ppiLineEdit_textChanged(ui->ppiLineEdit->text());
        }
    }

    foreach (QRadioButton *rb, encap_buttons_) {
        rb->setEnabled(enable_buttons);
    }

    ui->ethertypeLabel->setEnabled(ethertype);
    ui->ethertypeLineEdit->setEnabled(ethertype);
    ui->protocolLabel->setEnabled(ipv4_proto);
    ui->protocolLineEdit->setEnabled(ipv4_proto);
    ui->sourcePortLabel->setEnabled(port);
    ui->sourcePortLineEdit->setEnabled(port);
    ui->destinationPortLabel->setEnabled(port);
    ui->destinationPortLineEdit->setEnabled(port);
    ui->tagLabel->setEnabled(sctp_tag);
    ui->tagLineEdit->setEnabled(sctp_tag);
    ui->ppiLabel->setEnabled(sctp_ppi);
    ui->ppiLineEdit->setEnabled(sctp_ppi);
}

void ImportTextDialog::exec() {
    QVariant encap_val;

    QDialog::exec();

    if (result() != QDialog::Accepted) {
        return;
    }

    import_info_.import_text_filename = ui->textFileLineEdit->text().toUtf8().data();
    import_info_.import_text_file = ws_fopen(import_info_.import_text_filename, "rb");
    if (!import_info_.import_text_file) {
        open_failure_alert_box(import_info_.import_text_filename, errno, FALSE);
        setResult(QDialog::Rejected);
        return;
    }

    import_info_.offset_type =
        ui->hexOffsetButton->isChecked()     ? OFFSET_HEX :
        ui->decimalOffsetButton->isChecked() ? OFFSET_DEC :
        ui->octalOffsetButton->isChecked()   ? OFFSET_OCT :
        OFFSET_NONE;
    import_info_.date_timestamp = ui->dateTimeLineEdit->text().length() > 0;
    import_info_.date_timestamp_format = ui->dateTimeLineEdit->text().toUtf8().data();

    encap_val = ui->encapComboBox->itemData(ui->encapComboBox->currentIndex());
    import_info_.dummy_header_type = HEADER_NONE;
    if (encap_val.isValid() && encap_val.toUInt() == WTAP_ENCAP_ETHERNET && !ui->noDummyButton->isChecked()) {
        // Inputs were validated in the on_xxx_textChanged slots.
        if (ui->ethernetButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_ETH;
        } else if (ui->ipv4Button->isChecked()) {
            import_info_.dummy_header_type = HEADER_IPV4;
        } else if(ui->udpButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_UDP;
        } else if(ui->tcpButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_TCP;
        } else if(ui->sctpButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_SCTP;
        } else if(ui->sctpDataButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_SCTP_DATA;
        }
    }
    if (import_info_.max_frame_length == 0) {
        import_info_.max_frame_length = IMPORT_MAX_PACKET;
    }

    convertTextFile();
}

void ImportTextDialog::on_textFileBrowseButton_clicked()
{
    char *open_dir = NULL;

    switch (prefs.gui_fileopen_style) {

    case FO_STYLE_LAST_OPENED:
        /* The user has specified that we should start out in the last directory
           we looked in.  If we've already opened a file, use its containing
           directory, if we could determine it, as the directory, otherwise
           use the "last opened" directory saved in the preferences file if
           there was one. */
        /* This is now the default behaviour in file_selection_new() */
        open_dir = get_last_open_dir();
        break;

    case FO_STYLE_SPECIFIED:
        /* The user has specified that we should always start out in a
           specified directory; if they've specified that directory,
           start out by showing the files in that dir. */
        if (prefs.gui_fileopen_dir[0] != '\0')
            open_dir = prefs.gui_fileopen_dir;
        break;
    }

    QString file_name = QFileDialog::getOpenFileName(this, "Wireshark: Import text file", open_dir);
    ui->textFileLineEdit->setText(file_name);
}

void ImportTextDialog::on_textFileLineEdit_textChanged(const QString &file_name)
{
    QFile *text_file;

    text_file = new QFile(file_name);
    if (text_file->open(QIODevice::ReadOnly)) {
        ok_button_->setEnabled(true);
        text_file->close();
    } else {
        ok_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_encapComboBox_currentIndexChanged(int index)
{
    QVariant val = ui->encapComboBox->itemData(index);
    bool enabled = false;

    if (val != QVariant::Invalid) {
        import_info_.encapsulation = val.toUInt();

        if (import_info_.encapsulation == WTAP_ENCAP_ETHERNET) enabled = true;
    }

    enableHeaderWidgets(enabled);
}

void ImportTextDialog::on_dateTimeLineEdit_textChanged(const QString &time_format)
{
    if (time_format.length() > 0) {
        time_t cur_time;
        struct tm *cur_tm;
        char time_str[100];

        time(&cur_time);
        cur_tm = localtime(&cur_time);
        strftime(time_str, 100, ui->dateTimeLineEdit->text().toUtf8().constData(), cur_tm);
        ui->timestampExampleLabel->setText(QString("Example: %1").arg(time_str));
    } else {
        ui->timestampExampleLabel->setText("<i>(No format will be applied)</i>");
    }
}

void ImportTextDialog::on_noDummyButton_toggled(bool checked)
{
    if (checked) enableHeaderWidgets();
}

void ImportTextDialog::on_ethernetButton_toggled(bool checked)
{
    on_noDummyButton_toggled(checked);
}

void ImportTextDialog::on_ipv4Button_toggled(bool checked)
{
    on_noDummyButton_toggled(checked);
}

void ImportTextDialog::on_udpButton_toggled(bool checked)
{
    on_noDummyButton_toggled(checked);
}

void ImportTextDialog::on_tcpButton_toggled(bool checked)
{
    on_noDummyButton_toggled(checked);
}

void ImportTextDialog::on_sctpButton_toggled(bool checked)
{
    on_noDummyButton_toggled(checked);
}

void ImportTextDialog::on_sctpDataButton_toggled(bool checked)
{
    on_noDummyButton_toggled(checked);
}

void ImportTextDialog::on_ethertypeLineEdit_textChanged(const QString &ethertype_str)
{
    bool conv_ok;

    import_info_.pid = ethertype_str.toUShort(&conv_ok, 16);
    if (conv_ok && import_info_.pid <= 0xffff) {
        ok_button_->setEnabled(true);
    } else {
        ok_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_protocolLineEdit_textChanged(const QString &protocol_str)
{
    bool conv_ok;

    import_info_.protocol = protocol_str.toUShort(&conv_ok, 10);
    if (conv_ok && import_info_.protocol <= 0xff) {
        ok_button_->setEnabled(true);
    } else {
        ok_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_sourcePortLineEdit_textChanged(const QString &source_port_str)
{
    bool conv_ok;

    import_info_.src_port = source_port_str.toUShort(&conv_ok, 10);
    if (conv_ok && import_info_.src_port <= 0xffff) {
        ok_button_->setEnabled(true);
    } else {
        ok_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_destinationPortLineEdit_textChanged(const QString &destination_port_str)
{
    bool conv_ok;

    import_info_.dst_port = destination_port_str.toUShort(&conv_ok, 10);
    if (conv_ok && import_info_.dst_port <= 0xffff) {
        ok_button_->setEnabled(true);
    } else {
        ok_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_tagLineEdit_textChanged(const QString &tag_str)
{
    bool conv_ok;

    import_info_.tag = tag_str.toULong(&conv_ok, 10);
    if (conv_ok && import_info_.tag <= 0xffffffff) {
        ok_button_->setEnabled(true);
    } else {
        ok_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_ppiLineEdit_textChanged(const QString &ppi_str)
{
    bool conv_ok;

    import_info_.ppi = ppi_str.toULong(&conv_ok, 10);
    if (conv_ok && import_info_.ppi <= 0xffffffff) {
        ok_button_->setEnabled(true);
    } else {
        ok_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_maxLengthLineEdit_textChanged(const QString &max_frame_len_str)
{
    bool conv_ok;

    import_info_.max_frame_length = max_frame_len_str.toUShort(&conv_ok, 10);
    if (conv_ok && import_info_.max_frame_length <= IMPORT_MAX_PACKET) {
        ok_button_->setEnabled(true);
    } else {
        ok_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_buttonBox_helpRequested()
{
    gchar *url = topic_action_url(HELP_IMPORT_DIALOG);

    if(url != NULL) {
        QDesktopServices::openUrl(QUrl(url));
        g_free(url);
    }
}
