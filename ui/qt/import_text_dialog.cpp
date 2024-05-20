/* import_text_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "import_text_dialog.h"

#include "wiretap/wtap.h"
#include "wiretap/pcap-encap.h"

#include "ui/text_import_scanner.h"
#include "ui/util.h"
#include "ui/alert_box.h"
#include "ui/help_url.h"
#include "ui/capture_globals.h"

#include "file.h"
#include "wsutil/file_util.h"
#include "wsutil/inet_addr.h"
#include "wsutil/time_util.h"
#include "wsutil/tempfile.h"
#include "wsutil/filesystem.h"

#include <ui_import_text_dialog.h>
#include "main_application.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>

#define HINT_BEGIN "<small><i>"
#define HINT_END "</i></small>"
#define HTML_LT "&lt;"
#define HTML_GT "&gt;"

static const QString default_regex_hint = ImportTextDialog::tr("Supported fields are data, dir, time, seqno");
static const QString missing_data_hint = ImportTextDialog::tr("Missing capturing group data (use (?" HTML_LT "data" HTML_GT "(...)) )");

#define SETTINGS_FILE "import_hexdump.json"

ImportTextDialog::ImportTextDialog(QWidget *parent) :
    QDialog(parent),
    ti_ui_(new Ui::ImportTextDialog),
    import_info_(),
    file_ok_(false),
    timestamp_format_ok_(true),
    regex_ok_(false),
    re_has_dir_(false),
    in_indication_ok_(false),
    out_indication_ok_(false),
    re_has_time_(false),
    ether_type_ok_(true),
    proto_ok_(true),
    source_addr_ok_(true),
    dest_addr_ok_(true),
    source_port_ok_(true),
    dest_port_ok_(true),
    tag_ok_(true),
    ppi_ok_(true),
    payload_ok_(true),
    max_len_ok_(true)
{
    int encap;
    int i;
    int file_type_subtype;

    ti_ui_->setupUi(this);
    setWindowTitle(mainApp->windowTitleString(tr("Import From Hex Dump")));
    memset(&import_info_, 0, sizeof(import_info_));

    import_button_ = ti_ui_->buttonBox->button(QDialogButtonBox::Open);
    import_button_->setText(tr("Import"));
    import_button_->setEnabled(false);

    ti_ui_->regexHintLabel->setSmallText(true);

#ifdef Q_OS_MAC
    // The grid layout squishes each line edit otherwise.
    int le_height = ti_ui_->textFileLineEdit->sizeHint().height();
    ti_ui_->ethertypeLineEdit->setMinimumHeight(le_height);
    ti_ui_->protocolLineEdit->setMinimumHeight(le_height);
    ti_ui_->sourceAddressLineEdit->setMinimumHeight(le_height);
    ti_ui_->destinationAddressLineEdit->setMinimumHeight(le_height);
    ti_ui_->sourcePortLineEdit->setMinimumHeight(le_height);
    ti_ui_->destinationPortLineEdit->setMinimumHeight(le_height);
    ti_ui_->tagLineEdit->setMinimumHeight(le_height);
    ti_ui_->ppiLineEdit->setMinimumHeight(le_height);
#endif

    on_timestampFormatLineEdit_textChanged(ti_ui_->timestampFormatLineEdit->text());

    encap_buttons = new QButtonGroup(this);
    for (i = 0; i < ti_ui_->headerGridLayout->count(); i++) {
        QRadioButton *rb = qobject_cast<QRadioButton *>(ti_ui_->headerGridLayout->itemAt(i)->widget());

        if (rb) encap_buttons->addButton(rb);
    }
    /* There are two QButtonGroup::buttonToggled signals from Qt 5.2-5.15 with
     * different parameters. This breaks connectSlotsByName, which only finds
     * the deprecated one that doesn't exist in Qt 6. So we have to connect it
     * manually, and avoid naming the slot in the normal way.
     */
    connect(encap_buttons, SIGNAL(buttonToggled(QAbstractButton*, bool)), this, SLOT(encap_buttonsToggled(QAbstractButton*, bool)));

    /* fill the IP version combobox */
    ti_ui_->ipVersionComboBox->addItem("IPv4", QVariant(4));
    ti_ui_->ipVersionComboBox->addItem("IPv6", QVariant(6));

    /* fill the data encoding dropdown in regex tab*/
    struct {
        const char* name;
        enum data_encoding id;
    } encodings[] = {
        {"Plain hex", ENCODING_PLAIN_HEX},
        {"Plain oct", ENCODING_PLAIN_OCT},
        {"Plain bin", ENCODING_PLAIN_BIN},
        {"Base 64", ENCODING_BASE64}
    };
    for (i = 0; i < (int)array_length(encodings); ++i) {
        ti_ui_->dataEncodingComboBox->addItem(encodings[i].name, QVariant(encodings[i].id));
    }

    /*
     * Scan all Wiretap encapsulation types.
     *
     * XXX - this "knows" that WTAP_ENCAP_ETHERNET is the first encapsulation
     * type, skipping the special non-types WTAP_ENCAP_PER_PACKET and
     * WTAP_ENCAP_UNKNOWN.  We need a better way to express the notion
     * of "for (all encapsulation types)".
     */
    import_info_.encapsulation = WTAP_ENCAP_ETHERNET;
    file_type_subtype = wtap_pcapng_file_type_subtype();
    for (encap = import_info_.encapsulation; encap < wtap_get_num_encap_types(); encap++)
    {
        /* Check if we can write to a pcapng file
         *
         * Exclude wtap encapsulations that require a pseudo header,
         * because we won't setup one from the text we import and
         * wiretap doesn't allow us to write 'raw' frames
         */
        if (wtap_dump_can_write_encap(file_type_subtype, encap) &&
            !wtap_encap_requires_phdr(encap)) {
            const char *name;
            /* If it has got a name */
            if ((name = wtap_encap_description(encap)))
            {
                ti_ui_->encapComboBox->addItem(name, QVariant(encap));
            }
        }
    }
    ti_ui_->encapComboBox->model()->sort(0);

    /* fill the dissector combo box */
    GList* dissector_names = get_dissector_names();
    for (GList* l = dissector_names; l != NULL; l = l->next) {
         const char* name = (const char*) l->data;
         ti_ui_->dissectorComboBox->addItem(name, QVariant(name));
    }
    ti_ui_->dissectorComboBox->model()->sort(0);
    g_list_free(dissector_names);

    ti_ui_->regexHintLabel->setText(default_regex_hint);

    applyDialogSettings();
    updateImportButtonState();
}

ImportTextDialog::~ImportTextDialog()
{
    storeDialogSettings();

    delete ti_ui_;
}

void ImportTextDialog::loadSettingsFile()
{
    QFileInfo fileInfo(gchar_free_to_qstring(get_profile_dir(get_profile_name(), false)), QString(SETTINGS_FILE));
    QFile loadFile(fileInfo.filePath());

    if (!fileInfo.exists() || !fileInfo.isFile()) {
        return;
    }

    if (loadFile.open(QIODevice::ReadOnly)) {
        QByteArray loadData = loadFile.readAll();
        QJsonDocument document = QJsonDocument::fromJson(loadData);

        settings = document.object().toVariantMap();
    }
}

void ImportTextDialog::saveSettingsFile()
{
    QFileInfo fileInfo(gchar_free_to_qstring(get_profile_dir(get_profile_name(), false)), QString(SETTINGS_FILE));
    QFile saveFile(fileInfo.filePath());

    if (fileInfo.exists() && !fileInfo.isFile()) {
        return;
    }

    if (saveFile.open(QIODevice::WriteOnly)) {
        QJsonDocument document = QJsonDocument::fromVariant(settings);
        QByteArray saveData = document.toJson();

        saveFile.write(saveData);
    }
}

void ImportTextDialog::applyDialogSettings()
{
    loadSettingsFile();

    // Hex Dump
    QString offsetType = settings["hexdump.offsets"].toString();
    if (offsetType == "hex") {
        ti_ui_->hexOffsetButton->setChecked(true);
    } else if (offsetType == "dec") {
        ti_ui_->decimalOffsetButton->setChecked(true);
    } else if (offsetType == "oct") {
        ti_ui_->octalOffsetButton->setChecked(true);
    } else if (offsetType == "none") {
        ti_ui_->noOffsetButton->setChecked(true);
    }
    ti_ui_->directionIndicationCheckBox->setChecked(settings["hexdump.hasDirection"].toBool());
    ti_ui_->asciiIdentificationCheckBox->setChecked(settings["hexdump.identifyAscii"].toBool());

    // Regular Expression
    ti_ui_->regexTextEdit->setText(settings["regex.format"].toString());
    QString encoding = settings["regex.encoding"].toString();
    if (encoding == "plainHex") {
        ti_ui_->dataEncodingComboBox->setCurrentIndex(0);
    } else if (encoding == "plainOct") {
        ti_ui_->dataEncodingComboBox->setCurrentIndex(1);
    } else if (encoding == "plainBin") {
        ti_ui_->dataEncodingComboBox->setCurrentIndex(2);
    } else if (encoding == "base64") {
        ti_ui_->dataEncodingComboBox->setCurrentIndex(3);
    }
    ti_ui_->dirInIndicationLineEdit->setText(settings["regex.inIndication"].toString());
    ti_ui_->dirOutIndicationLineEdit->setText(settings["regex.outIndication"].toString());

    // Import info
    ti_ui_->timestampFormatLineEdit->setText(settings["timestampFormat"].toString());

    const char *name = wtap_encap_description(settings["encapsulation"].toInt());
    ti_ui_->encapComboBox->setCurrentText(name);

    QString dummyHeader = settings["dummyHeader"].toString();
    if (dummyHeader == "ethernet") {
        ti_ui_->ethernetButton->setChecked(true);
    } else if (dummyHeader == "ipv4") {
        ti_ui_->ipv4Button->setChecked(true);
    } else if (dummyHeader == "udp") {
        ti_ui_->udpButton->setChecked(true);
    } else if (dummyHeader == "tcp") {
        ti_ui_->tcpButton->setChecked(true);
    } else if (dummyHeader == "sctp") {
        ti_ui_->sctpButton->setChecked(true);
    } else if (dummyHeader == "sctpData") {
        ti_ui_->sctpDataButton->setChecked(true);
    } else if (dummyHeader == "exportPDU") {
        ti_ui_->exportPduButton->setChecked(true);
    } else if (dummyHeader == "none") {
        ti_ui_->noDummyButton->setChecked(true);
    }

    if (settings["ipVersion"].toUInt() == 6) {
        ti_ui_->ipVersionComboBox->setCurrentIndex(1);
    } else {
        ti_ui_->ipVersionComboBox->setCurrentIndex(0);
    }
    ti_ui_->ethertypeLineEdit->setText(settings["ethertype"].toString());
    ti_ui_->protocolLineEdit->setText(settings["ipProtocol"].toString());
    ti_ui_->sourceAddressLineEdit->setText(settings["sourceAddress"].toString());
    ti_ui_->destinationAddressLineEdit->setText(settings["destinationAddress"].toString());
    ti_ui_->sourcePortLineEdit->setText(settings["sourcePort"].toString());
    ti_ui_->destinationPortLineEdit->setText(settings["destinationPort"].toString());
    ti_ui_->tagLineEdit->setText(settings["sctpTag"].toString());
    ti_ui_->ppiLineEdit->setText(settings["sctpPPI"].toString());

    if (settings.contains("pduPayload")) {
        ti_ui_->dissectorComboBox->setCurrentText(settings["pduPayload"].toString());
    } else {
        // Default to the data dissector when not previously set
        ti_ui_->dissectorComboBox->setCurrentText("data");
    }

    ti_ui_->interfaceLineEdit->setText(settings["interfaceName"].toString());
    ti_ui_->maxLengthLineEdit->setText(settings["maxFrameLength"].toString());

    // Select mode tab last to enableFieldWidgets()
    QString mode(settings["mode"].toString());
    int modeIndex = (mode == "regex") ? 1 : 0;
    ti_ui_->modeTabWidget->setCurrentIndex(modeIndex);
    on_modeTabWidget_currentChanged(modeIndex);
}

void ImportTextDialog::storeDialogSettings()
{
    int modeIndex = ti_ui_->modeTabWidget->currentIndex();
    if (modeIndex == 0) {
        settings["mode"] = "hexdump";
    } else {
        settings["mode"] = "regex";
    }

    // Hex Dump
    if (ti_ui_->hexOffsetButton->isChecked()) {
        settings["hexdump.offsets"] = "hex";
    } else if (ti_ui_->decimalOffsetButton->isChecked()) {
        settings["hexdump.offsets"] = "dec";
    } else if (ti_ui_->octalOffsetButton->isChecked()) {
        settings["hexdump.offsets"] = "oct";
    } else {
        settings["hexdump.offsets"] = "none";
    }
    settings["hexdump.hasDirection"] = ti_ui_->directionIndicationCheckBox->isChecked();
    settings["hexdump.identifyAscii"] = ti_ui_->asciiIdentificationCheckBox->isChecked();

    // Regular Expression
    settings["regex.format"] = ti_ui_->regexTextEdit->toPlainText();
    QVariant encodingVal = ti_ui_->dataEncodingComboBox->itemData(ti_ui_->dataEncodingComboBox->currentIndex());
    if (encodingVal.isValid()) {
        enum data_encoding encoding = (enum data_encoding) encodingVal.toUInt();
        switch (encoding) {
        case ENCODING_PLAIN_HEX:
            settings["regex.encoding"] = "plainHex";
            break;
        case ENCODING_PLAIN_OCT:
            settings["regex.encoding"] = "plainOct";
            break;
        case ENCODING_PLAIN_BIN:
            settings["regex.encoding"] = "plainBin";
            break;
        case ENCODING_BASE64:
            settings["regex.encoding"] = "base64";
            break;
        }
    } else {
        settings["regex.encoding"] = "plainHex";
    }
    settings["regex.inIndication"] = ti_ui_->dirInIndicationLineEdit->text();
    settings["regex.outIndication"] = ti_ui_->dirOutIndicationLineEdit->text();

    // Import info
    settings["timestampFormat"] = ti_ui_->timestampFormatLineEdit->text();

    QVariant encapVal = ti_ui_->encapComboBox->itemData(ti_ui_->encapComboBox->currentIndex());
    if (encapVal.isValid()) {
        settings["encapsulation"] = encapVal.toUInt();
    } else {
        settings["encapsulation"] = WTAP_ENCAP_ETHERNET;
    }

    if (ti_ui_->ethernetButton->isChecked()) {
        settings["dummyHeader"] = "ethernet";
    } else if (ti_ui_->ipv4Button->isChecked()) {
        settings["dummyHeader"] = "ipv4";
    } else if (ti_ui_->udpButton->isChecked()) {
        settings["dummyHeader"] = "udp";
    } else if (ti_ui_->tcpButton->isChecked()) {
        settings["dummyHeader"] = "tcp";
    } else if (ti_ui_->sctpButton->isChecked()) {
        settings["dummyHeader"] = "sctp";
    } else if (ti_ui_->sctpDataButton->isChecked()) {
        settings["dummyHeader"] = "sctpData";
    } else if (ti_ui_->exportPduButton->isChecked()) {
        settings["dummyHeader"] = "exportPDU";
    } else {
        settings["dummyHeader"] = "none";
    }

    settings["ipVersion"] = ti_ui_->ipVersionComboBox->currentData().toUInt();
    settings["ethertype"] = ti_ui_->ethertypeLineEdit->text();
    settings["ipProtocol"] = ti_ui_->protocolLineEdit->text();
    settings["sourceAddress"] = ti_ui_->sourceAddressLineEdit->text();
    settings["destinationAddress"] = ti_ui_->destinationAddressLineEdit->text();
    settings["sourcePort"] = ti_ui_->sourcePortLineEdit->text();
    settings["destinationPort"] = ti_ui_->destinationPortLineEdit->text();
    settings["sctpTag"] = ti_ui_->tagLineEdit->text();
    settings["sctpPPI"] = ti_ui_->ppiLineEdit->text();
    settings["pduPayload"] = ti_ui_->dissectorComboBox->currentData().toString();

    settings["interfaceName"] = ti_ui_->interfaceLineEdit->text();
    settings["maxFrameLength"] = ti_ui_->maxLengthLineEdit->text();

    saveSettingsFile();
}

QString &ImportTextDialog::capfileName() {
    return capfile_name_;
}

int ImportTextDialog::exec() {
    QVariant encap_val;
    char* tmp;
    GError* gerror = NULL;
    int err;
    char *err_info;
    wtap_dump_params params;
    int file_type_subtype;
    QString interface_name;

    QDialog::exec();

    if (result() != QDialog::Accepted) {
        return result();
    }

    /* from here on the cleanup labels are used to free allocated resources in
     * reverse order.
     * naming is cleanup_<step_where_something_failed>
     * Don't Declare new variables from here on
     */

    import_info_.import_text_filename = qstring_strdup(ti_ui_->textFileLineEdit->text());
    import_info_.timestamp_format = qstring_strdup(ti_ui_->timestampFormatLineEdit->text());
    if (strlen(import_info_.timestamp_format) == 0) {
        g_free((void *) import_info_.timestamp_format);
        import_info_.timestamp_format = NULL;
    }

    mainApp->setLastOpenDirFromFilename(QString(import_info_.import_text_filename));

    switch (import_info_.mode) {
      default: /* should never happen */
        setResult(QDialog::Rejected);
        return QDialog::Rejected;
      case TEXT_IMPORT_HEXDUMP:
        import_info_.hexdump.import_text_FILE = ws_fopen(import_info_.import_text_filename, "rb");
        if (!import_info_.hexdump.import_text_FILE) {
            open_failure_alert_box(import_info_.import_text_filename, errno, false);
            setResult(QDialog::Rejected);
            goto cleanup_mode;
        }

        import_info_.hexdump.offset_type =
            ti_ui_->hexOffsetButton->isChecked()     ? OFFSET_HEX :
            ti_ui_->decimalOffsetButton->isChecked() ? OFFSET_DEC :
            ti_ui_->octalOffsetButton->isChecked()   ? OFFSET_OCT :
            OFFSET_NONE;
        break;
      case TEXT_IMPORT_REGEX:
        import_info_.regex.import_text_GMappedFile = g_mapped_file_new(import_info_.import_text_filename, true, &gerror);
        if (gerror) {
            open_failure_alert_box(import_info_.import_text_filename, gerror->code, false);
            g_error_free(gerror);
            setResult(QDialog::Rejected);
            goto cleanup_mode;
        }
        tmp = qstring_strdup(ti_ui_->regexTextEdit->toPlainText());
        import_info_.regex.format = g_regex_new(tmp, (GRegexCompileFlags) (G_REGEX_DUPNAMES | G_REGEX_OPTIMIZE | G_REGEX_MULTILINE), G_REGEX_MATCH_NOTEMPTY, &gerror);
        g_free(tmp);
        if (re_has_dir_) {
            import_info_.regex.in_indication = qstring_strdup(ti_ui_->dirInIndicationLineEdit->text());
            import_info_.regex.out_indication = qstring_strdup(ti_ui_->dirOutIndicationLineEdit->text());
        } else {
            import_info_.regex.in_indication = NULL;
            import_info_.regex.out_indication = NULL;
        }
        break;
    }

    encap_val = ti_ui_->encapComboBox->itemData(ti_ui_->encapComboBox->currentIndex());
    import_info_.dummy_header_type = HEADER_NONE;
    if (encap_val.isValid() && (encap_buttons->checkedButton()->isEnabled())
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

    import_info_.payload = qstring_strdup(ti_ui_->dissectorComboBox->currentData().toString());

    capfile_name_.clear();
    wtap_dump_params_init(&params, NULL);
    params.encap = import_info_.encapsulation;
    params.snaplen = import_info_.max_frame_length;
    params.tsprec = WTAP_TSPREC_NSEC; /* XXX - support other precisions? */
    /* Write a pcapng temporary file */
    file_type_subtype = wtap_pcapng_file_type_subtype();
    if (ti_ui_->interfaceLineEdit->text().length()) {
        interface_name = ti_ui_->interfaceLineEdit->text();
    } else {
        interface_name = ti_ui_->interfaceLineEdit->placeholderText();
    }
    text_import_pre_open(&params, file_type_subtype, import_info_.import_text_filename, interface_name.toUtf8().constData());
    /* Use a random name for the temporary import buffer */
    import_info_.wdh = wtap_dump_open_tempfile(global_capture_opts.temp_dir, &tmp, "import", file_type_subtype, WTAP_UNCOMPRESSED, &params, &err, &err_info);
    capfile_name_.append(tmp ? tmp : "temporary file");
    import_info_.output_filename = tmp;

    if (import_info_.wdh == NULL) {
        cfile_dump_open_failure_alert_box(capfile_name_.toUtf8().constData(), err, err_info, file_type_subtype);
        setResult(QDialog::Rejected);
        goto cleanup_wtap;
    }

    err = text_import(&import_info_);

    if (err != 0) {
        failure_alert_box("Import failed");
        setResult(QDialog::Rejected);
        goto cleanup;
    }

  cleanup: /* free in reverse order of allocation */
    if (!wtap_dump_close(import_info_.wdh, NULL, &err, &err_info))
    {
        cfile_close_failure_alert_box(capfile_name_.toUtf8().constData(), err, err_info);
    }
  cleanup_wtap:
    /* g_free checks for null */
    wtap_free_idb_info(params.idb_inf);
    wtap_dump_params_cleanup(&params);
    g_free(tmp);
    g_free((void *) import_info_.payload);
    switch (import_info_.mode) {
      case TEXT_IMPORT_HEXDUMP:
        fclose(import_info_.hexdump.import_text_FILE);
        break;
      case TEXT_IMPORT_REGEX:
        g_mapped_file_unref(import_info_.regex.import_text_GMappedFile);
        g_regex_unref((GRegex*) import_info_.regex.format);
        g_free((void *) import_info_.regex.in_indication);
        g_free((void *) import_info_.regex.out_indication);
        break;
    }
  cleanup_mode:
    g_free((void *) import_info_.import_text_filename);
    g_free((void *) import_info_.timestamp_format);
    return result();
}

/*******************************************************************************
 * General Input
 */

void ImportTextDialog::updateImportButtonState()
{
    /* XXX: This requires even buttons that aren't being used to have valid
     * entries (addresses, ports, etc.) Fixing that can mean changing the
     * encapsulation type in order to enable the line edits, which is a little
     * awkward for the user.
     */
    if (file_ok_ && timestamp_format_ok_ && ether_type_ok_ &&
        proto_ok_ && source_addr_ok_ && dest_addr_ok_ &&
        source_port_ok_ && dest_port_ok_ &&
        tag_ok_ && ppi_ok_ && payload_ok_ && max_len_ok_ &&
        (
            (
                import_info_.mode == TEXT_IMPORT_REGEX && regex_ok_ &&
                (!re_has_dir_  || (in_indication_ok_ && out_indication_ok_))
            ) || (
                import_info_.mode == TEXT_IMPORT_HEXDUMP
            )
        )
      ) {
          import_button_->setEnabled(true);
    } else {
        import_button_->setEnabled(false);
    }
}

void ImportTextDialog::on_textFileLineEdit_textChanged(const QString &file_name)
{
    QFile text_file(file_name);

    if (file_name.length() > 0 && text_file.open(QIODevice::ReadOnly)) {
        file_ok_ = true;
        text_file.close();
    } else {
        file_ok_ = false;
    }
    updateImportButtonState();
}

void ImportTextDialog::on_textFileBrowseButton_clicked()
{
    QString open_dir;
    if (ti_ui_->textFileLineEdit->text().length() > 0) {
        open_dir = ti_ui_->textFileLineEdit->text();
    } else {
        open_dir = get_open_dialog_initial_dir();
    }

    QString file_name = WiresharkFileDialog::getOpenFileName(this, mainApp->windowTitleString(tr("Import Text File")), open_dir);
    ti_ui_->textFileLineEdit->setText(file_name);
}

bool ImportTextDialog::checkDateTimeFormat(const QString &time_format)
{
    /* nonstandard is f for fractions of seconds */
    const QString valid_code = "aAbBcdDFfHIjmMpsSTUwWxXyYzZ%";
    int idx = 0;
    int ret = false;

    /* XXX: Temporary(?) hack to allow ISO format time, a checkbox is
     * probably better */
    if (time_format == "ISO") {
        ret = true;
    } else while ((idx = static_cast<int>(time_format.indexOf("%", idx))) != -1) {
        idx++;
        if ((idx == time_format.size()) || !valid_code.contains(time_format[idx])) {
            return false;
        }
        idx++;
        ret = true;
    }
    return ret;
}

void ImportTextDialog::on_timestampFormatLineEdit_textChanged(const QString &time_format)
{
    if (time_format.length() > 0) {
        if (checkDateTimeFormat(time_format)) {
            struct timespec timenow;
            struct tm *cur_tm;
            struct tm fallback;
            char time_str[100];
            QString timefmt = QString(time_format);

            ws_clock_get_realtime(&timenow);

            /* On windows strftime/wcsftime does not support %s yet, this works on all OSs */
            timefmt.replace(QString("%s"), QString::number(timenow.tv_sec));
            /* subsecond example as usec */
            timefmt.replace(QString("%f"),  QString("%1").arg(timenow.tv_nsec, 6, 10, QChar('0')));

            cur_tm = localtime(&timenow.tv_sec);
            if (cur_tm == NULL) {
              memset(&fallback, 0, sizeof(fallback));
              cur_tm = &fallback;
            }
            strftime(time_str, sizeof time_str, timefmt.toUtf8(), cur_tm);
            ti_ui_->timestampExampleLabel->setText(QString(tr(HINT_BEGIN "Example: %1" HINT_END)).arg(QString(time_str).toHtmlEscaped()));
            timestamp_format_ok_ = true;
        }
        else {
            ti_ui_->timestampExampleLabel->setText(tr(HINT_BEGIN "(Wrong date format)" HINT_END));
            timestamp_format_ok_ = false;
        }
    } else {
        ti_ui_->timestampExampleLabel->setText(tr(HINT_BEGIN "(No format will be applied)" HINT_END));
        timestamp_format_ok_ = true;
    }
    updateImportButtonState();
}

void ImportTextDialog::on_modeTabWidget_currentChanged(int index) {
    switch (index) {
      default:
        ti_ui_->modeTabWidget->setCurrentIndex(0);
        /* fall through */
      case 0: /* these numbers depend on the UI */
        import_info_.mode = TEXT_IMPORT_HEXDUMP;
        memset(&import_info_.hexdump, 0, sizeof(import_info_.hexdump));
        on_directionIndicationCheckBox_toggled(ti_ui_->directionIndicationCheckBox->isChecked());
        on_asciiIdentificationCheckBox_toggled(ti_ui_->asciiIdentificationCheckBox->isChecked());
        enableFieldWidgets(false, true);
        break;
      case 1:
        import_info_.mode = TEXT_IMPORT_REGEX;
        memset(&import_info_.regex, 0, sizeof(import_info_.regex));
        on_dataEncodingComboBox_currentIndexChanged(ti_ui_->dataEncodingComboBox->currentIndex());
        enableFieldWidgets(re_has_dir_, re_has_time_);
        break;
    }
    on_textFileLineEdit_textChanged(ti_ui_->textFileLineEdit->text());
}

/*******************************************************************************
 * Hex Dump Tab
 */

void ImportTextDialog::on_noOffsetButton_toggled(bool checked)
{
    if (checked) {
        ti_ui_->noOffsetLabel->setText("(only one packet will be created)");
    } else {
        ti_ui_->noOffsetLabel->setText("");
    }
}

void ImportTextDialog::on_directionIndicationCheckBox_toggled(bool checked)
{
    import_info_.hexdump.has_direction = checked;
}

void ImportTextDialog::on_asciiIdentificationCheckBox_toggled(bool checked)
{
    import_info_.hexdump.identify_ascii = checked;
}

/*******************************************************************************
 * Regex Tab
 */

void ImportTextDialog::on_regexTextEdit_textChanged()
{
    char* regex_gchar_p = qstring_strdup(ti_ui_->regexTextEdit->toPlainText());
    GError* gerror = NULL;
    /* TODO: Use GLib's c++ interface or enable C++ int to enum casting
     * because the flags are declared as enum, so we can't pass 0 like
     * the specification recommends. These options don't hurt.
     */
    GRegex* regex = g_regex_new(regex_gchar_p, G_REGEX_DUPNAMES, G_REGEX_MATCH_NOTEMPTY, &gerror);
    if (gerror) {
        regex_ok_ = false;
        ti_ui_->regexHintLabel->setText(QString(gerror->message).toHtmlEscaped());
        g_error_free(gerror);
    } else {
        regex_ok_ = 0 <= g_regex_get_string_number(regex, "data");
        if (regex_ok_)
            ti_ui_->regexHintLabel->setText(default_regex_hint);
        else
            ti_ui_->regexHintLabel->setText(missing_data_hint);
        re_has_dir_ = 0 <= g_regex_get_string_number(regex, "dir");
        re_has_time_ = 0 <= g_regex_get_string_number(regex, "time");
        //re_has_seqno = 0 <= g_regex_get_string_number(regex, "seqno");
        g_regex_unref(regex);
    }
    g_free(regex_gchar_p);
    enableFieldWidgets(re_has_dir_, re_has_time_);
    updateImportButtonState();
}

void ImportTextDialog::enableFieldWidgets(bool enable_direction_input, bool enable_time_input) {
    ti_ui_->dirIndicationLabel->setEnabled(enable_direction_input);
    ti_ui_->dirInIndicationLineEdit->setEnabled(enable_direction_input);
    ti_ui_->dirOutIndicationLineEdit->setEnabled(enable_direction_input);
    ti_ui_->timestampLabel->setEnabled(enable_time_input);
    ti_ui_->timestampFormatLineEdit->setEnabled(enable_time_input);
    ti_ui_->timestampExampleLabel->setEnabled(enable_time_input);
}

void ImportTextDialog::on_dataEncodingComboBox_currentIndexChanged(int index)
{
    QVariant val = ti_ui_->dataEncodingComboBox->itemData(index);
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    if (val.canConvert<int>())
#else
    if (val != QVariant::Invalid)
#endif
    {
        // data_encoding_ok = true;
        import_info_.regex.encoding = (enum data_encoding) val.toUInt();
        switch (import_info_.regex.encoding) {
          case ENCODING_PLAIN_HEX:
            ti_ui_->encodingRegexExample->setText(HINT_BEGIN "(?" HTML_LT "data" HTML_GT "[0-9a-fA-F:\\s]+)" HINT_END);
            break;
          case ENCODING_PLAIN_BIN:
            ti_ui_->encodingRegexExample->setText(HINT_BEGIN "(?" HTML_LT "data" HTML_GT "[0-1\\s]+)" HINT_END);
            break;
          case ENCODING_PLAIN_OCT:
            ti_ui_->encodingRegexExample->setText(HINT_BEGIN "(?" HTML_LT "data" HTML_GT "[0-8:\\s]+)" HINT_END);
            break;
          case ENCODING_BASE64:
            ti_ui_->encodingRegexExample->setText(HINT_BEGIN "(?" HTML_LT "data" HTML_GT "[0-9a-zA-Z+\\/\\s]+=*)" HINT_END);
            break;
          default:
            ti_ui_->encodingRegexExample->setText(HINT_BEGIN HTML_LT "no example" HTML_GT HINT_END);
            break;
        }
        /* for some reason this breaks when changing the text */
        ti_ui_->encodingRegexExample->setTextInteractionFlags(Qt::TextSelectableByMouse);
    }
    updateImportButtonState();
}

void ImportTextDialog::on_dirInIndicationLineEdit_textChanged(const QString &in_indication)
{
    in_indication_ok_ = in_indication.length() > 0;
    updateImportButtonState();
}

void ImportTextDialog::on_dirOutIndicationLineEdit_textChanged(const QString &out_indication)
{
    out_indication_ok_ = out_indication.length() > 0;
    updateImportButtonState();
}

/*******************************************************************************
 * Encapsulation input
 */

void ImportTextDialog::enableHeaderWidgets(uint encapsulation) {
    bool ethertype = false;
    bool ipv4_proto = false;
    bool ip_address = false;
    bool port = false;
    bool sctp_tag = false;
    bool sctp_ppi = false;
    bool export_pdu = false;
    bool enable_ethernet_buttons = (encapsulation == WTAP_ENCAP_ETHERNET);
    bool enable_ip_buttons = (encapsulation == WTAP_ENCAP_RAW_IP || encapsulation == WTAP_ENCAP_RAW_IP4 || encapsulation == WTAP_ENCAP_RAW_IP6);
    bool enable_export_pdu_buttons = (encapsulation == WTAP_ENCAP_WIRESHARK_UPPER_PDU);

    if (enable_ethernet_buttons) {
        if (ti_ui_->ethernetButton->isChecked()) {
            ethertype = true;
            on_ethertypeLineEdit_textChanged(ti_ui_->ethertypeLineEdit->text());
        }
        enable_ip_buttons = true;
    }

    if (enable_ip_buttons) {
        if (ti_ui_->ipv4Button->isChecked()) {
            ipv4_proto = true;
            ip_address = true;
            on_protocolLineEdit_textChanged(ti_ui_->protocolLineEdit->text());
        } else if (ti_ui_->udpButton->isChecked() || ti_ui_->tcpButton->isChecked()) {
            ip_address = true;
            port = true;
            on_sourcePortLineEdit_textChanged(ti_ui_->sourcePortLineEdit->text());
            on_destinationPortLineEdit_textChanged(ti_ui_->destinationPortLineEdit->text());
        } else if (ti_ui_->sctpButton->isChecked()) {
            ip_address = true;
            port = true;
            sctp_tag = true;
            on_sourcePortLineEdit_textChanged(ti_ui_->sourcePortLineEdit->text());
            on_destinationPortLineEdit_textChanged(ti_ui_->destinationPortLineEdit->text());
            on_tagLineEdit_textChanged(ti_ui_->tagLineEdit->text());
        }
        if (ti_ui_->sctpDataButton->isChecked()) {
            ip_address = true;
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
        }
    }

    foreach (auto &&rb, encap_buttons->buttons()) {
        rb->setEnabled(enable_ip_buttons);
    }

    ti_ui_->ethernetButton->setEnabled(enable_ethernet_buttons);
    ti_ui_->exportPduButton->setEnabled(enable_export_pdu_buttons);
    ti_ui_->noDummyButton->setEnabled(enable_export_pdu_buttons || enable_ip_buttons);

    ti_ui_->ethertypeLabel->setEnabled(ethertype);
    ti_ui_->ethertypeLineEdit->setEnabled(ethertype);
    ti_ui_->protocolLabel->setEnabled(ipv4_proto);
    ti_ui_->protocolLineEdit->setEnabled(ipv4_proto);
    ti_ui_->ipVersionLabel->setEnabled(ip_address);
    if (encapsulation == WTAP_ENCAP_RAW_IP4) {
        ti_ui_->ipVersionComboBox->setEnabled(false);
        ti_ui_->ipVersionComboBox->setCurrentIndex(0);
    } else if (encapsulation == WTAP_ENCAP_RAW_IP6) {
        ti_ui_->ipVersionComboBox->setEnabled(false);
        ti_ui_->ipVersionComboBox->setCurrentIndex(1);
    } else {
        ti_ui_->ipVersionComboBox->setEnabled(ip_address);
    }
    ti_ui_->sourceAddressLabel->setEnabled(ip_address);
    ti_ui_->sourceAddressLineEdit->setEnabled(ip_address);
    ti_ui_->destinationAddressLabel->setEnabled(ip_address);
    ti_ui_->destinationAddressLineEdit->setEnabled(ip_address);
    ti_ui_->sourcePortLabel->setEnabled(port);
    ti_ui_->sourcePortLineEdit->setEnabled(port);
    ti_ui_->destinationPortLabel->setEnabled(port);
    ti_ui_->destinationPortLineEdit->setEnabled(port);
    ti_ui_->tagLabel->setEnabled(sctp_tag);
    ti_ui_->tagLineEdit->setEnabled(sctp_tag);
    ti_ui_->ppiLabel->setEnabled(sctp_ppi);
    ti_ui_->ppiLineEdit->setEnabled(sctp_ppi);
    ti_ui_->payloadLabel->setEnabled(export_pdu);
    ti_ui_->dissectorComboBox->setEnabled(export_pdu);

    if (ti_ui_->noDummyButton->isEnabled() && !(encap_buttons->checkedButton()->isEnabled())) {
        ti_ui_->noDummyButton->toggle();
    }
}

void ImportTextDialog::on_encapComboBox_currentIndexChanged(int index)
{
    QVariant val = ti_ui_->encapComboBox->itemData(index);
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    if (val.canConvert<int>())
#else
    if (val != QVariant::Invalid)
#endif
    {
        import_info_.encapsulation = val.toUInt();
    } else {
        import_info_.encapsulation = WTAP_ENCAP_UNKNOWN;
    }

    enableHeaderWidgets(import_info_.encapsulation);
}

void ImportTextDialog::encap_buttonsToggled(QAbstractButton *button _U_, bool checked)
{
    if (checked) enableHeaderWidgets(import_info_.encapsulation);
}

void ImportTextDialog::on_ipVersionComboBox_currentIndexChanged(int index)
{
    import_info_.ipv6 = (index == 1) ? 1 : 0;
    on_sourceAddressLineEdit_textChanged(ti_ui_->sourceAddressLineEdit->text());
    on_destinationAddressLineEdit_textChanged(ti_ui_->destinationAddressLineEdit->text());
}

void ImportTextDialog::check_line_edit(SyntaxLineEdit *le, bool &ok_enabled, const QString &num_str, int base, unsigned max_val, bool is_short, unsigned *val_ptr) {
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
            *val_ptr = (unsigned)num_str.toULong(&conv_ok, base);
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

void ImportTextDialog::checkAddress(SyntaxLineEdit *le, bool &ok_enabled, const QString &addr_str, ws_in4_addr *val_ptr) {
    bool conv_ok;
    SyntaxLineEdit::SyntaxState syntax_state = SyntaxLineEdit::Empty;

    if (!le || !val_ptr)
        return;

    ok_enabled = true;
    if (addr_str.length() < 1) {
        *val_ptr = 0;
    } else {
        conv_ok = ws_inet_pton4(addr_str.toUtf8().data(), (ws_in4_addr*)val_ptr);
        if (conv_ok) {
            syntax_state= SyntaxLineEdit::Valid;
        } else {
            syntax_state = SyntaxLineEdit::Invalid;
            ok_enabled = false;
        }
    }
    le->setSyntaxState(syntax_state);
    updateImportButtonState();
}

void ImportTextDialog::checkIPv6Address(SyntaxLineEdit *le, bool &ok_enabled, const QString &addr_str, ws_in6_addr *val_ptr) {
    bool conv_ok;
    SyntaxLineEdit::SyntaxState syntax_state = SyntaxLineEdit::Empty;

    if (!le || !val_ptr)
        return;

    ok_enabled = true;
    if (addr_str.length() < 1) {
        *val_ptr = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    } else {
        conv_ok = ws_inet_pton6(addr_str.toUtf8().data(), (ws_in6_addr*)val_ptr);
        if (conv_ok) {
            syntax_state= SyntaxLineEdit::Valid;
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

void ImportTextDialog::on_sourceAddressLineEdit_textChanged(const QString &source_addr_str)
{
    if (ti_ui_->ipVersionComboBox->currentIndex() == 1) {
        checkIPv6Address(ti_ui_->sourceAddressLineEdit, source_addr_ok_, source_addr_str, &import_info_.ip_src_addr.ipv6);
    } else {
        checkAddress(ti_ui_->sourceAddressLineEdit, source_addr_ok_, source_addr_str, &import_info_.ip_src_addr.ipv4);
    }
}

void ImportTextDialog::on_destinationAddressLineEdit_textChanged(const QString &destination_addr_str)
{
    if (ti_ui_->ipVersionComboBox->currentIndex() == 1) {
        checkIPv6Address(ti_ui_->destinationAddressLineEdit, dest_addr_ok_, destination_addr_str, &import_info_.ip_dest_addr.ipv6);
    } else {
        checkAddress(ti_ui_->destinationAddressLineEdit, dest_addr_ok_, destination_addr_str, &import_info_.ip_dest_addr.ipv4);
    }
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

/*******************************************************************************
* Footer
*/

void ImportTextDialog::on_maxLengthLineEdit_textChanged(const QString &max_frame_len_str)
{
    check_line_edit(ti_ui_->maxLengthLineEdit, max_len_ok_, max_frame_len_str, 10, WTAP_MAX_PACKET_SIZE_STANDARD, true, &import_info_.max_frame_length);
}

void ImportTextDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_IMPORT_DIALOG);
}
