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
#if !defined(_WIN32) && !defined(HAVE_CLOCK_GETTIME)
// For gettimeofday()
#include <sys/time.h>
#endif

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

#define HINT_BEGIN "<small><i>"
#define HINT_END "</i></small>"
#define HTML_LT "&lt;"
#define HTML_GT "&gt;"

static const QString default_regex_hint = ImportTextDialog::tr("Supported fields are data, dir, time, seqno");
static const QString missing_data_hint = ImportTextDialog::tr("Missing capturing group data (use (?" HTML_LT "data" HTML_GT "(...)) )");

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
    source_port_ok_(true),
    dest_port_ok_(true),
    tag_ok_(true),
    ppi_ok_(true),
    payload_ok_(true),
    max_len_ok_(true)
{
    int encap;
    int i;
    int pcap_file_type_subtype;

    ti_ui_->setupUi(this);
    setWindowTitle(wsApp->windowTitleString(tr("Import From Hex Dump")));
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
    ti_ui_->sourcePortLineEdit->setMinimumHeight(le_height);
    ti_ui_->destinationPortLineEdit->setMinimumHeight(le_height);
    ti_ui_->tagLineEdit->setMinimumHeight(le_height);
    ti_ui_->ppiLineEdit->setMinimumHeight(le_height);
#endif

    on_timestampFormatLineEdit_textChanged(ti_ui_->timestampFormatLineEdit->text());

    for (i = 0; i < ti_ui_->headerGridLayout->count(); i++) {
        QRadioButton *rb = qobject_cast<QRadioButton *>(ti_ui_->headerGridLayout->itemAt(i)->widget());

        if (rb) encap_buttons_.append(rb);
    }

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
    for (i = 0; i < (int) (sizeof(encodings) / sizeof(encodings[0])); ++i) {
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
    pcap_file_type_subtype = wtap_pcap_file_type_subtype();
    for (encap = import_info_.encapsulation; encap < wtap_get_num_encap_types(); encap++)
    {
        /* Check if we can write to a PCAP file
         *
         * Exclude wtap encapsulations that require a pseudo header,
         * because we won't setup one from the text we import and
         * wiretap doesn't allow us to write 'raw' frames
         */
        if (wtap_dump_can_write_encap(pcap_file_type_subtype, encap) &&
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

    import_info_.mode = TEXT_IMPORT_HEXDUMP;

    on_modeTabWidget_currentChanged(0);
    updateImportButtonState();
}

ImportTextDialog::~ImportTextDialog()
{
    delete ti_ui_;
}

QString &ImportTextDialog::capfileName() {
    return capfile_name_;
}

int ImportTextDialog::exec() {
    QVariant encap_val;
    char* tmp;
    GError* gerror = NULL;
    int err;
    gchar *err_info;
    wtap_dump_params params;
    int file_type_subtype;

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
        g_free((gpointer) import_info_.timestamp_format);
        import_info_.timestamp_format = NULL;
    }

    switch (import_info_.mode) {
      default: /* should never happen */
        setResult(QDialog::Rejected);
        return QDialog::Rejected;
      case TEXT_IMPORT_HEXDUMP:
        import_info_.hexdump.import_text_FILE = ws_fopen(import_info_.import_text_filename, "rb");
        if (!import_info_.hexdump.import_text_FILE) {
            open_failure_alert_box(import_info_.import_text_filename, errno, FALSE);
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
            open_failure_alert_box(import_info_.import_text_filename, gerror->code, FALSE);
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

    import_info_.payload = qstring_strdup(ti_ui_->dissectorComboBox->currentData().toString());

    capfile_name_.clear();
    wtap_dump_params_init(&params, NULL);
    params.encap = import_info_.encapsulation;
    params.snaplen = import_info_.max_frame_length;
    params.tsprec = WTAP_TSPREC_USEC; /* XXX - support other precisions? */
    /* Write a pcapng temporary file */
    file_type_subtype = wtap_pcapng_file_type_subtype();
    /* Use a random name for the temporary import buffer */
    import_info_.wdh = wtap_dump_open_tempfile(&tmp, "import", file_type_subtype, WTAP_UNCOMPRESSED, &params, &err, &err_info);
    capfile_name_.append(tmp ? tmp : "temporary file");
    g_free(tmp);

    if (import_info_.wdh == NULL) {
        cfile_dump_open_failure_alert_box(capfile_name_.toUtf8().constData(), err, err_info, file_type_subtype);
        setResult(QDialog::Rejected);
        goto cleanup_wtap;
    }

    err = text_import(&import_info_);

    if (err < 0) {
        failure_alert_box("Can't initialize scanner: %s", g_strerror(err));
        setResult(QDialog::Rejected);
        goto cleanup;
    }

  cleanup: /* free in reverse order of allocation */
    if (!wtap_dump_close(import_info_.wdh, &err, &err_info))
    {
        cfile_close_failure_alert_box(capfile_name_.toUtf8().constData(), err, err_info);
    }
  cleanup_wtap:
    /* g_free checks for null */
    g_free((gpointer) import_info_.payload);
    switch (import_info_.mode) {
      case TEXT_IMPORT_HEXDUMP:
        fclose(import_info_.hexdump.import_text_FILE);
        break;
      case TEXT_IMPORT_REGEX:
        g_mapped_file_unref(import_info_.regex.import_text_GMappedFile);
        g_regex_unref((GRegex*) import_info_.regex.format);
        g_free((gpointer) import_info_.regex.in_indication);
        g_free((gpointer) import_info_.regex.out_indication);
        break;
    }
  cleanup_mode:
    g_free((gpointer) import_info_.import_text_filename);
    g_free((gpointer) import_info_.timestamp_format);
    return result();
}

/*******************************************************************************
 * General Input
 */

void ImportTextDialog::updateImportButtonState()
{
    if (file_ok_ && timestamp_format_ok_ && ether_type_ok_ &&
        proto_ok_ && source_port_ok_ && dest_port_ok_ &&
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
    }

    QString file_name = WiresharkFileDialog::getOpenFileName(this, wsApp->windowTitleString(tr("Import Text File")), open_dir);
    ti_ui_->textFileLineEdit->setText(file_name);
}

bool ImportTextDialog::checkDateTimeFormat(const QString &time_format)
{
    /* nonstandard is f for fractions of seconds */
    const QString valid_code = "aAbBcdDFfHIjmMpsSTUwWxXyYzZ%";
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

void ImportTextDialog::on_timestampFormatLineEdit_textChanged(const QString &time_format)
{
    if (time_format.length() > 0) {
        if (checkDateTimeFormat(time_format)) {
            struct timespec timenow;
            struct tm *cur_tm;
            struct tm fallback;
            char time_str[100];
            QString timefmt = QString(time_format);

#if defined(_WIN32)
            // At least some Windows C libraries have this.
            // Some UN*X C libraries do, as well, but they might not
            // show it unless you're requesting C11 - or C++17.
            timespec_get(&timenow, TIME_UTC);
#elif defined(HAVE_CLOCK_GETTIME)
            // Newer POSIX API.  Some UN*Xes whose C libraries lack
            // timespec_get() (C11) have this.
            clock_gettime(CLOCK_REALTIME, &timenow);
#else
            // Fall back on gettimeofday().
            struct timeval usectimenow;
            gettimeofday(&usectimenow, NULL);
            timenow.tv_sec = usectimenow.tv_sec;
            timenow.tv_nsec = usectimenow.tv_usec*1000;
#endif
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

/*******************************************************************************
 * Regex Tab
 */

void ImportTextDialog::on_regexTextEdit_textChanged()
{
    gchar* regex_gchar_p = qstring_strdup(ti_ui_->regexTextEdit->toPlainText());;
    GError* gerror = NULL;
    /* TODO: Use GLib's c++ interface or enable C++ int to enum casting
     * because the flags are declared as enum, so we can't pass 0 like
     * the specificaion reccomends. These options don't hurt.
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
    if (val != QVariant::Invalid) {
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
    ti_ui_->dissectorComboBox->setEnabled(export_pdu);
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

/*******************************************************************************
* Footer
*/

void ImportTextDialog::on_maxLengthLineEdit_textChanged(const QString &max_frame_len_str)
{
    check_line_edit(ti_ui_->maxLengthLineEdit, max_len_ok_, max_frame_len_str, 10, WTAP_MAX_PACKET_SIZE_STANDARD, true, &import_info_.max_frame_length);
}

void ImportTextDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_IMPORT_DIALOG);
}
