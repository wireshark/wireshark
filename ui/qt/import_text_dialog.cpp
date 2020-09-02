/* import_text_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <time.h>

#include "import_text_dialog.h"

#include "wiretap/wtap.h"
#include "wiretap/pcap-encap.h"

#include <epan/prefs.h>

#include "ui/text_import_scanner.h"
#include "ui/last_open_dir.h"
#include "ui/alert_box.h"
#include "ui/help_url.h"

#include "file.h"
#include "wsutil/file_util.h"
#include "wsutil/tempfile.h"

#include <ui_import_text_dialog.h>
#include "wireshark_application.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QDebug>
#include <QFile>

ImportTextDialog::ImportTextDialog(QWidget *parent) :
    QDialog(parent),
    ti_ui_(new Ui::ImportTextDialog),
    import_info_(),
    file_ok_(false),
    time_format_ok_(true),
    ether_type_ok_(true),
    proto_ok_(true),
    source_port_ok_(true),
    dest_port_ok_(true),
    tag_ok_(true),
    ppi_ok_(true),
    payload_ok_(true),
    max_len_ok_(true)
{
    int encap;
    int i;

    ti_ui_->setupUi(this);
    setWindowTitle(wsApp->windowTitleString(tr("Import From Hex Dump")));
    memset(&import_info_, 0, sizeof(import_info_));

    import_button_ = ti_ui_->buttonBox->button(QDialogButtonBox::Open);
    import_button_->setText(tr("Import"));
    import_button_->setEnabled(false);

#ifdef Q_OS_MAC
    // The grid layout squishes each line edit otherwise.
    int le_height = ti_ui_->textFileLineEdit->sizeHint().height();
    ti_ui_->ethertypeLineEdit->setMinimumHeight(le_height);
    ti_ui_->protocolLineEdit->setMinimumHeight(le_height);
    ti_ui_->sourcePortLineEdit->setMinimumHeight(le_height);
    ti_ui_->destinationPortLineEdit->setMinimumHeight(le_height);
    ti_ui_->tagLineEdit->setMinimumHeight(le_height);
    ti_ui_->ppiLineEdit->setMinimumHeight(le_height);
    ti_ui_->payloadLineEdit->setMinimumHeight(le_height);
#endif

    on_dateTimeLineEdit_textChanged(ti_ui_->dateTimeLineEdit->text());

    for (i = 0; i < ti_ui_->headerGridLayout->count(); i++) {
        QRadioButton *rb = qobject_cast<QRadioButton *>(ti_ui_->headerGridLayout->itemAt(i)->widget());

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
            if ((name = wtap_encap_description(encap)))
            {
                ti_ui_->encapComboBox->addItem(name, QVariant(encap));
            }
        }
    }
    ti_ui_->encapComboBox->model()->sort(0);
}

ImportTextDialog::~ImportTextDialog()
{
    g_free (import_info_.import_text_filename);
    g_free (import_info_.date_timestamp_format);
    g_free (import_info_.payload);
    delete ti_ui_;
}

QString &ImportTextDialog::capfileName() {
    return capfile_name_;
}

void ImportTextDialog::convertTextFile() {
    char *tmpname;
    int err;
    wtap_dump_params params;

    capfile_name_.clear();
    wtap_dump_params_init(&params, NULL);
    params.encap = import_info_.encapsulation;
    params.snaplen = import_info_.max_frame_length;
    params.tsprec = WTAP_TSPREC_USEC; /* XXX - support other precisions? */
    /* Use a random name for the temporary import buffer */
    import_info_.wdh = wtap_dump_open_tempfile(&tmpname, "import", WTAP_FILE_TYPE_SUBTYPE_PCAPNG, WTAP_UNCOMPRESSED, &params, &err);
    capfile_name_.append(tmpname ? tmpname : "temporary file");
    g_free(tmpname);
    qDebug() << capfile_name_ << ":" << import_info_.wdh << import_info_.encapsulation << import_info_.max_frame_length;
    if (import_info_.wdh == NULL) {
        cfile_dump_open_failure_alert_box(capfile_name_.toUtf8().constData(), err, WTAP_FILE_TYPE_SUBTYPE_PCAP);
        fclose(import_info_.import_text_file);
        setResult(QDialog::Rejected);
        return;
    }

    err = text_import(&import_info_);
    if (err != 0) {
        failure_alert_box("Can't initialize scanner: %s", g_strerror(err));
        fclose(import_info_.import_text_file);
        setResult(QDialog::Rejected);
        return;
    }

    if (fclose(import_info_.import_text_file))
    {
        read_failure_alert_box(import_info_.import_text_filename, errno);
    }

    if (!wtap_dump_close(import_info_.wdh, &err))
    {
        cfile_close_failure_alert_box(capfile_name_.toUtf8().constData(), err);
    }
}


void ImportTextDialog::enableHeaderWidgets(bool enable_ethernet_buttons, bool enable_export_pdu_buttons) {
    bool ethertype = false;
    bool ipv4_proto = false;
    bool port = false;
    bool sctp_tag = false;
    bool sctp_ppi = false;
    bool export_pdu = false;

    if (enable_ethernet_buttons) {
        if (ti_ui_->ethernetButton->isChecked()) {
            ethertype = true;
            on_ethertypeLineEdit_textChanged(ti_ui_->ethertypeLineEdit->text());
        } else if (ti_ui_->ipv4Button->isChecked()) {
            ipv4_proto = true;
            on_protocolLineEdit_textChanged(ti_ui_->protocolLineEdit->text());
        } else if (ti_ui_->udpButton->isChecked() || ti_ui_->tcpButton->isChecked()) {
            port = true;
            on_sourcePortLineEdit_textChanged(ti_ui_->sourcePortLineEdit->text());
            on_destinationPortLineEdit_textChanged(ti_ui_->destinationPortLineEdit->text());
        } else if (ti_ui_->sctpButton->isChecked()) {
            port = true;
            sctp_tag = true;
            on_sourcePortLineEdit_textChanged(ti_ui_->sourcePortLineEdit->text());
            on_destinationPortLineEdit_textChanged(ti_ui_->destinationPortLineEdit->text());
            on_tagLineEdit_textChanged(ti_ui_->tagLineEdit->text());
        }
        if (ti_ui_->sctpDataButton->isChecked()) {
            port = true;
            sctp_ppi = true;
            on_sourcePortLineEdit_textChanged(ti_ui_->sourcePortLineEdit->text());
            on_destinationPortLineEdit_textChanged(ti_ui_->destinationPortLineEdit->text());
            on_ppiLineEdit_textChanged(ti_ui_->ppiLineEdit->text());
        }
    }

    if (enable_export_pdu_buttons) {
        if (ti_ui_->exportPduButton->isChecked()) {
            export_pdu = true;
            on_payloadLineEdit_textChanged(ti_ui_->payloadLineEdit->text());
        }
    }

    foreach (QRadioButton *rb, encap_buttons_) {
        rb->setEnabled(enable_ethernet_buttons);
    }

    ti_ui_->exportPduButton->setEnabled(enable_export_pdu_buttons);
    ti_ui_->noDummyButton->setEnabled(enable_export_pdu_buttons || enable_ethernet_buttons);

    ti_ui_->ethertypeLabel->setEnabled(ethertype);
    ti_ui_->ethertypeLineEdit->setEnabled(ethertype);
    ti_ui_->protocolLabel->setEnabled(ipv4_proto);
    ti_ui_->protocolLineEdit->setEnabled(ipv4_proto);
    ti_ui_->sourcePortLabel->setEnabled(port);
    ti_ui_->sourcePortLineEdit->setEnabled(port);
    ti_ui_->destinationPortLabel->setEnabled(port);
    ti_ui_->destinationPortLineEdit->setEnabled(port);
    ti_ui_->tagLabel->setEnabled(sctp_tag);
    ti_ui_->tagLineEdit->setEnabled(sctp_tag);
    ti_ui_->ppiLabel->setEnabled(sctp_ppi);
    ti_ui_->ppiLineEdit->setEnabled(sctp_ppi);
    ti_ui_->payloadLabel->setEnabled(export_pdu);
    ti_ui_->payloadLineEdit->setEnabled(export_pdu);
}

int ImportTextDialog::exec() {
    QVariant encap_val;

    QDialog::exec();

    if (result() != QDialog::Accepted) {
        return result();
    }

    import_info_.import_text_filename = qstring_strdup(ti_ui_->textFileLineEdit->text());
    import_info_.import_text_file = ws_fopen(import_info_.import_text_filename, "rb");
    if (!import_info_.import_text_file) {
        open_failure_alert_box(import_info_.import_text_filename, errno, FALSE);
        setResult(QDialog::Rejected);
        return QDialog::Rejected;
    }

    import_info_.offset_type =
        ti_ui_->hexOffsetButton->isChecked()     ? OFFSET_HEX :
        ti_ui_->decimalOffsetButton->isChecked() ? OFFSET_DEC :
        ti_ui_->octalOffsetButton->isChecked()   ? OFFSET_OCT :
        OFFSET_NONE;
    import_info_.date_timestamp = ti_ui_->dateTimeLineEdit->text().length() > 0;
    import_info_.date_timestamp_format = qstring_strdup(ti_ui_->dateTimeLineEdit->text());

    encap_val = ti_ui_->encapComboBox->itemData(ti_ui_->encapComboBox->currentIndex());
    import_info_.dummy_header_type = HEADER_NONE;
    if (encap_val.isValid() && (encap_val.toUInt() == WTAP_ENCAP_ETHERNET || encap_val.toUInt() == WTAP_ENCAP_WIRESHARK_UPPER_PDU)
            && !ti_ui_->noDummyButton->isChecked()) {
        // Inputs were validated in the on_xxx_textChanged slots.
        if (ti_ui_->ethernetButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_ETH;
        } else if (ti_ui_->ipv4Button->isChecked()) {
            import_info_.dummy_header_type = HEADER_IPV4;
        } else if (ti_ui_->udpButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_UDP;
        } else if (ti_ui_->tcpButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_TCP;
        } else if (ti_ui_->sctpButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_SCTP;
        } else if (ti_ui_->sctpDataButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_SCTP_DATA;
        } else if (ti_ui_->exportPduButton->isChecked()) {
            import_info_.dummy_header_type = HEADER_EXPORT_PDU;
        }
    }
    if (import_info_.max_frame_length == 0) {
        import_info_.max_frame_length = WTAP_MAX_PACKET_SIZE_STANDARD;
    }

    convertTextFile();
    return QDialog::Accepted;
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

    QString file_name = WiresharkFileDialog::getOpenFileName(this, wsApp->windowTitleString(tr("Import Text File")), open_dir);
    ti_ui_->textFileLineEdit->setText(file_name);
}

void ImportTextDialog::updateImportButtonState()
{
    if (file_ok_ && time_format_ok_ && ether_type_ok_ &&
        proto_ok_ && source_port_ok_ && dest_port_ok_ &&
        tag_ok_ && ppi_ok_ && payload_ok_ && max_len_ok_) {
        import_button_->setEnabled(true);
    } else {
        import_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_textFileLineEdit_textChanged(const QString &file_name)
{
    QFile *text_file;

    text_file = new QFile(file_name);
    if (text_file->open(QIODevice::ReadOnly)) {
        file_ok_ = true;
        text_file->close();
    } else {
        file_ok_ = false;
    }
    updateImportButtonState();
}

void ImportTextDialog::on_noOffsetButton_toggled(bool checked)
{
    if (checked) {
        ti_ui_->noOffsetLabel->setText("(only one packet will be created)");
    } else {
        ti_ui_->noOffsetLabel->setText("");
    }
}

void ImportTextDialog::on_encapComboBox_currentIndexChanged(int index)
{
    QVariant val = ti_ui_->encapComboBox->itemData(index);
    bool enabled_ethernet = false;
    bool enabled_export_pdu = false;

    if (val != QVariant::Invalid) {
        import_info_.encapsulation = val.toUInt();

        if (import_info_.encapsulation == WTAP_ENCAP_ETHERNET) enabled_ethernet = true;
        if (import_info_.encapsulation == WTAP_ENCAP_WIRESHARK_UPPER_PDU) enabled_export_pdu = true;
    }

    enableHeaderWidgets(enabled_ethernet, enabled_export_pdu);
}

bool ImportTextDialog::checkDateTimeFormat(const QString &time_format)
{
    const QString valid_code = "aAbBcdDFHIjmMpsSTUwWxXyYzZ%";
    int idx = 0;
    int ret = false;

    while ((idx = time_format.indexOf("%", idx)) != -1) {
        idx++;
        if ((idx == time_format.size()) || !valid_code.contains(time_format[idx])) {
            return false;
        }
        idx++;
        ret = true;
    }
    return ret;
}

void ImportTextDialog::on_dateTimeLineEdit_textChanged(const QString &time_format)
{
    if (time_format.length() > 0) {
        if (checkDateTimeFormat(time_format)) {
            struct timespec timenow;
            struct tm *cur_tm;
            char time_str[100];
            QString timefmt = QString(time_format);

#ifdef _WIN32
            timespec_get(&timenow, TIME_UTC); /* supported by Linux and Windows */
#else
            clock_gettime(CLOCK_REALTIME, &timenow); /* supported by Linux and MacOS */
#endif
            /* On windows strftime/wcsftime does not support %s yet, this works on all OSs */
            timefmt.replace(QString("%s"), QString::number(timenow.tv_sec));
            /* subsecond example as usec */
            timefmt.replace(QString("."),  QString(".%1").arg(timenow.tv_nsec/1000, 6, 10, QChar('0')));

            cur_tm = localtime(&timenow.tv_sec);
            if (cur_tm != NULL)
                strftime(time_str, sizeof time_str, timefmt.toUtf8(), cur_tm);
            else
                g_strlcpy(time_str, "Not representable", sizeof time_str);
            ti_ui_->timestampExampleLabel->setText(QString(tr("Example: %1")).arg(time_str));
            time_format_ok_ = true;
        }
        else {
            ti_ui_->timestampExampleLabel->setText(tr("<i>(Wrong date format)</i>"));
            time_format_ok_ = false;
        }
    } else {
        ti_ui_->timestampExampleLabel->setText(tr("<i>(No format will be applied)</i>"));
        time_format_ok_ = true;
    }
    updateImportButtonState();
}

void ImportTextDialog::on_directionIndicationCheckBox_toggled(bool checked)
{
    import_info_.has_direction = checked;
}

void ImportTextDialog::on_noDummyButton_toggled(bool checked)
{
    bool enabled_ethernet = false;
    bool enabled_export_pdu = false;

    if (import_info_.encapsulation == WTAP_ENCAP_ETHERNET) enabled_ethernet = true;
    if (import_info_.encapsulation == WTAP_ENCAP_WIRESHARK_UPPER_PDU) enabled_export_pdu = true;

    if (checked) enableHeaderWidgets(enabled_ethernet, enabled_export_pdu);
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

void ImportTextDialog::on_exportPduButton_toggled(bool checked)
{
    on_noDummyButton_toggled(checked);
}

void ImportTextDialog::check_line_edit(SyntaxLineEdit *le, bool &ok_enabled, const QString &num_str, int base, guint max_val, bool is_short, guint *val_ptr) {
    bool conv_ok;
    SyntaxLineEdit::SyntaxState syntax_state = SyntaxLineEdit::Empty;

    if (!le || !val_ptr)
        return;

    ok_enabled = true;
    if (num_str.length() < 1) {
        *val_ptr = 0;
    } else {
        if (is_short) {
            *val_ptr = num_str.toUShort(&conv_ok, base);
        } else {
            *val_ptr = (guint)num_str.toULong(&conv_ok, base);
        }
        if (conv_ok && *val_ptr <= max_val) {
            syntax_state = SyntaxLineEdit::Valid;
        } else {
            syntax_state = SyntaxLineEdit::Invalid;
            ok_enabled = false;
        }
    }
    le->setSyntaxState(syntax_state);
    updateImportButtonState();
}

void ImportTextDialog::on_ethertypeLineEdit_textChanged(const QString &ethertype_str)
{
    check_line_edit(ti_ui_->ethertypeLineEdit, ether_type_ok_, ethertype_str, 16, 0xffff, true, &import_info_.pid);
}

void ImportTextDialog::on_protocolLineEdit_textChanged(const QString &protocol_str)
{
    check_line_edit(ti_ui_->protocolLineEdit, proto_ok_, protocol_str, 10, 0xff, true, &import_info_.protocol);
}

void ImportTextDialog::on_sourcePortLineEdit_textChanged(const QString &source_port_str)
{
    check_line_edit(ti_ui_->sourcePortLineEdit, source_port_ok_, source_port_str, 10, 0xffff, true, &import_info_.src_port);
}

void ImportTextDialog::on_destinationPortLineEdit_textChanged(const QString &destination_port_str)
{
    check_line_edit(ti_ui_->destinationPortLineEdit, dest_port_ok_, destination_port_str, 10, 0xffff, true, &import_info_.dst_port);
}

void ImportTextDialog::on_tagLineEdit_textChanged(const QString &tag_str)
{
    check_line_edit(ti_ui_->tagLineEdit, tag_ok_, tag_str, 10, 0xffffffff, false, &import_info_.tag);
}

void ImportTextDialog::on_ppiLineEdit_textChanged(const QString &ppi_str)
{
    check_line_edit(ti_ui_->ppiLineEdit, ppi_ok_, ppi_str, 10, 0xffffffff, false, &import_info_.ppi);
}

void ImportTextDialog::on_payloadLineEdit_textChanged(const QString &payload)
{
    payload_ok_ = true;
    import_info_.payload = g_strdup(payload.toStdString().c_str());
    updateImportButtonState();
}

void ImportTextDialog::on_maxLengthLineEdit_textChanged(const QString &max_frame_len_str)
{
    check_line_edit(ti_ui_->maxLengthLineEdit, max_len_ok_, max_frame_len_str, 10, WTAP_MAX_PACKET_SIZE_STANDARD, true, &import_info_.max_frame_length);
}

void ImportTextDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_IMPORT_DIALOG);
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
