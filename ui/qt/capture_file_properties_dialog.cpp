/* capture_file_properties_dialog.cpp
 *
 * GSoC 2013 - QtShark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "capture_file_properties_dialog.h"
#include <ui_capture_file_properties_dialog.h>

#include "ui/simple_dialog.h"
#include "ui/summary.h"

#include "wiretap/secrets-types.h"

#include "wsutil/filesystem.h"
#include "wsutil/str_util.h"
#include "wsutil/utf8_entities.h"
#include "wsutil/version_info.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"
#include "capture_comment_dialog.h"

#include <QPushButton>
#include <QScrollBar>
#include <QTextStream>

// To do:
// - Add file hashes
// - Add formats (HTML, plain text, YAML)?

CaptureFilePropertiesDialog::CaptureFilePropertiesDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui(new Ui::CaptureFilePropertiesDialog)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 2 / 3, parent.height());

    ui->detailsTextEdit->setAcceptRichText(true);

    QPushButton *button = ui->buttonBox->button(QDialogButtonBox::Reset);
    if (button) {
        button->setText(tr("Refresh"));
    }

    button = ui->buttonBox->button(QDialogButtonBox::Apply);
    if (button) {
        button->setText(tr("Copy To Clipboard"));
    }

    button = ui->buttonBox->button(QDialogButtonBox::Close);
    if (button) {
        button->setDefault(true);
    }

    ui->buttonBox->addButton(ui->actionEditButton, QDialogButtonBox::ActionRole);
    connect(ui->actionEditButton, &QPushButton::clicked, this, &CaptureFilePropertiesDialog::addCaptureComment);

    setWindowSubtitle(tr("Capture File Properties"));
    QTimer::singleShot(0, this, SLOT(updateWidgets()));
}

/*
 * Slots
 */

CaptureFilePropertiesDialog::~CaptureFilePropertiesDialog()
{
    delete ui;
}

/**/

void CaptureFilePropertiesDialog::updateWidgets()
{
    QPushButton *refresh_bt = ui->buttonBox->button(QDialogButtonBox::Reset);

    if (file_closed_ || !cap_file_.isValid()) {
        if (refresh_bt) {
            refresh_bt->setEnabled(false);
        }
        WiresharkDialog::updateWidgets();
        return;
    }

    fillDetails();

    WiresharkDialog::updateWidgets();
}

static const QString section_tmpl_ = "<p><strong>%1</strong></p>\n";
static const QString para_tmpl_ = "<p>%1</p>\n";

QString CaptureFilePropertiesDialog::summaryToHtml()
{
    summary_tally summary;
    double seconds = 0.0;
    double disp_seconds = 0.0;
    double marked_seconds = 0.0;

    memset(&summary, 0, sizeof(summary_tally));

    QString table_begin, table_end;
    QString table_row_begin, table_ul_row_begin, table_row_end;
    QString table_vheader_tmpl, table_hheader20_tmpl, table_hheader25_tmpl;
    QString table_data_tmpl;

    table_begin = "<p><table>\n";
    table_end = "</table></p>\n";
    table_row_begin = "<tr>\n";
    table_ul_row_begin = "<tr style=\"border-bottom: 1px solid gray;\">\n";
    table_row_end = "</tr>\n";
    table_vheader_tmpl = "<td width=\"20%\">%1:</td>"; // <th align="left"> looked odd
    table_hheader20_tmpl = "<td width=\"20%\"><u>%1</u></td>";
    table_hheader25_tmpl = "<td width=\"25%\"><u>%1</u></td>";
    table_data_tmpl = "<td>%1</td>";

    if (!file_closed_) {
        /* initial computations */
        summary_fill_in(cap_file_.capFile(), &summary);
#ifdef HAVE_LIBPCAP
        summary_fill_in_capture(cap_file_.capFile(), &global_capture_opts, &summary);
#endif
    }

    seconds = summary.stop_time - summary.start_time;
    disp_seconds = summary.filtered_stop - summary.filtered_start;
    marked_seconds = summary.marked_stop - summary.marked_start;

    QString summary_str;
    QTextStream out(&summary_str);
    QString unknown = tr("Unknown");

    // File Section
    out << section_tmpl_.arg(tr("File"));
    out << table_begin;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Name"))
        << table_data_tmpl.arg(summary.filename)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Length"))
        << table_data_tmpl.arg(file_size_to_qstring(summary.file_length))
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Hash (SHA256)"))
        << table_data_tmpl.arg(summary.file_sha256)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Hash (SHA1)"))
        << table_data_tmpl.arg(summary.file_sha1)
        << table_row_end;

    QString format_str = wtap_file_type_subtype_description(summary.file_type);
    const char *compression_type_description = wtap_compression_type_description(summary.compression_type);
    if (compression_type_description != nullptr) {
        format_str += QString(" (%1)").arg(compression_type_description);
    }
    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Format"))
        << table_data_tmpl.arg(format_str)
        << table_row_end;

    QString encaps_str;
    if (summary.file_encap_type == WTAP_ENCAP_PER_PACKET) {
        for (unsigned i = 0; i < summary.packet_encap_types->len; i++)
        {
            encaps_str = QString(wtap_encap_description(g_array_index(summary.packet_encap_types, int, i)));
        }
    } else {
        encaps_str = QString(wtap_encap_description(summary.file_encap_type));
    }
    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Encapsulation"))
        << table_data_tmpl.arg(encaps_str)
        << table_row_end;

    if (summary.snap != 0) {
        out << table_row_begin
            << table_vheader_tmpl.arg(tr("Snapshot length"))
            << table_data_tmpl.arg(summary.snap)
            << table_row_end;
    }

    out << table_end;

    // Time Section
    if (summary.packet_count_ts == summary.packet_count &&
            summary.packet_count >= 1)
    {
        out << section_tmpl_.arg(tr("Time"));
        out << table_begin;

        // start time
        out << table_row_begin;
        if (is_packet_configuration_namespace()) {
            out << table_vheader_tmpl.arg(tr("First packet"));
        } else {
            out << table_vheader_tmpl.arg(tr("First event"));
        }
        out << table_data_tmpl.arg(time_t_to_qstring((time_t)summary.start_time))
            << table_row_end;

        // stop time
        out << table_row_begin;
        if (is_packet_configuration_namespace()) {
            out << table_vheader_tmpl.arg(tr("Last packet"));
        } else {
            out << table_vheader_tmpl.arg(tr("Last event"));
        }
        out << table_data_tmpl.arg(time_t_to_qstring((time_t)summary.stop_time))
            << table_row_end;

        // elapsed seconds (capture duration)
        if (summary.packet_count_ts >= 2)
        {
            /* elapsed seconds */
            QString elapsed_str;
            unsigned int elapsed_time = (unsigned int)summary.elapsed_time;
            if (elapsed_time/86400)
            {
                elapsed_str = QString("%1 days ").arg(elapsed_time / 86400);
            }

            elapsed_str += QString("%1:%2:%3")
                    .arg(elapsed_time % 86400 / 3600, 2, 10, QChar('0'))
                    .arg(elapsed_time % 3600 / 60, 2, 10, QChar('0'))
                    .arg(elapsed_time % 60, 2, 10, QChar('0'));
            out << table_row_begin
                << table_vheader_tmpl.arg(tr("Elapsed"))
                << table_data_tmpl.arg(elapsed_str)
                << table_row_end;
        }

        out << table_end;
    }

    // Information from file sections.
    for (unsigned section_number = 0;
         section_number < wtap_file_get_num_shbs(cap_file_.capFile()->provider.wth);
         section_number++) {

        // If we have more than one section, add headers for each section.
        if (wtap_file_get_num_shbs(cap_file_.capFile()->provider.wth) > 1)
            out << section_tmpl_.arg(QString(tr("Section %1"))
                                     .arg(section_number + 1));

        wtap_block_t shb_inf = wtap_file_get_shb(cap_file_.capFile()->provider.wth, section_number);

        // Capture Section
        out << section_tmpl_.arg(tr("Capture"));
        out << table_begin;

        char *str;

        if (shb_inf != nullptr) {
            QString capture_hardware(unknown);
            if (wtap_block_get_string_option_value(shb_inf, OPT_SHB_HARDWARE, &str) == WTAP_OPTTYPE_SUCCESS) {
                if (str[0] != '\0') {
                    capture_hardware = str;
                }
            }
            // capture HW
            out << table_row_begin
                << table_vheader_tmpl.arg(tr("Hardware"))
                << table_data_tmpl.arg(capture_hardware)
                << table_row_end;

            QString capture_os(unknown);
            if (wtap_block_get_string_option_value(shb_inf, OPT_SHB_OS, &str) == WTAP_OPTTYPE_SUCCESS) {
                if (str[0] != '\0') {
                    capture_os = str;
                }
            }
            out << table_row_begin
                << table_vheader_tmpl.arg(tr("OS"))
                << table_data_tmpl.arg(capture_os)
                << table_row_end;

            QString capture_app(unknown);
            if (wtap_block_get_string_option_value(shb_inf, OPT_SHB_USERAPPL, &str) == WTAP_OPTTYPE_SUCCESS) {
                if (str[0] != '\0') {
                    capture_app = str;
                }
            }
            out << table_row_begin
                << table_vheader_tmpl.arg(tr("Application"))
                << table_data_tmpl.arg(capture_app)
                << table_row_end;
        }

        out << table_end;

        // capture interfaces info
        if (summary.ifaces->len > 0) {
            out << section_tmpl_.arg(tr("Interfaces"));
            out << table_begin;

            out << table_ul_row_begin
                << table_hheader20_tmpl.arg(tr("Interface"));
            if (is_packet_configuration_namespace()) {
                out << table_hheader20_tmpl.arg(tr("Dropped packets"));
            } else {
                out << table_hheader20_tmpl.arg(tr("Dropped events"));
            }
            out << table_hheader20_tmpl.arg(tr("Capture filter"))
                << table_hheader20_tmpl.arg(tr("Link type"));
            if (is_packet_configuration_namespace()) {
                out << table_hheader20_tmpl.arg(tr("Packet size limit (snaplen)"));
            } else {
                out << table_hheader20_tmpl.arg(tr("Event size limit (snaplen)"));
            }
            out << table_row_end;
        }

        // XXX: The mapping of interfaces to different SHBs isn't
        // handled correctly here or elsewhere
        for (unsigned i = 0; i < summary.ifaces->len; i++) {
            iface_summary_info iface;
            iface = g_array_index(summary.ifaces, iface_summary_info, i);

            /* interface */
            QString interface_name(unknown);
            if (iface.descr) {
                interface_name = iface.descr;
            } else if (iface.name) {
                interface_name = iface.name;
            }

            /* Dropped count */
            QString interface_drops(unknown);
            if (iface.drops_known) {
                interface_drops = QString("%1 (%2%)").arg(iface.drops).arg(QString::number(
                    /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
                    summary.packet_count ? (100.0 * (int64_t)iface.drops)/summary.packet_count : 0, 'f', 1));
            }

            /* Capture filter */
            QString interface_cfilter(unknown);
            if (iface.cfilter && iface.cfilter[0] != '\0') {
                interface_cfilter = iface.cfilter;
            } else if (iface.name) {
                interface_cfilter = QString(tr("none"));
            }

            QString interface_snaplen = QString(tr("%1 bytes").arg(iface.snap));

            out << table_row_begin
                << table_data_tmpl.arg(interface_name)
                << table_data_tmpl.arg(interface_drops)
                << table_data_tmpl.arg(interface_cfilter)
                << table_data_tmpl.arg(wtap_encap_description(iface.encap_type))
                << table_data_tmpl.arg(interface_snaplen)
                << table_row_end;
        }
        if (summary.ifaces->len > 0) {
            out << table_end;
        }

        unsigned num_comments = wtap_block_count_option(shb_inf, OPT_COMMENT);
        if (num_comments > 0) {
            out << section_tmpl_.arg(tr("Comments"));
            char *shb_comment;
            for (unsigned i = 0; i < num_comments; i++) {
                if (wtap_block_get_nth_string_option_value(shb_inf, OPT_COMMENT, i,
                                                           &shb_comment) == WTAP_OPTTYPE_SUCCESS) {
                    QString section_comment = shb_comment;
                    QString section_comment_html;
                    if (num_comments > 1) {
                        out << tr("Comment %1: ").arg(i+1);
                    }

                    QString comment_escaped = html_escape(section_comment).replace('\n', "<br>");
                    out << para_tmpl_.arg(comment_escaped);
                }
            }
        }
    }

    // Done with the interfaces
    for (unsigned i = 0; i < summary.ifaces->len; i++) {
        iface_summary_info iface;
        iface = g_array_index(summary.ifaces, iface_summary_info, i);

        g_free(iface.descr);
        g_free(iface.name);
        g_free(iface.cfilter);
    }
    g_array_free(summary.ifaces, true);

    if (wtap_file_get_num_dsbs(cap_file_.capFile()->provider.wth) > 0) {
        out << section_tmpl_.arg(tr("Decryption Secrets"));
        out << table_begin;
        out << table_ul_row_begin
            << table_hheader20_tmpl.arg(tr("Type"))
            << table_hheader20_tmpl.arg(tr("Size"))
            << table_row_end;
        // XXX: A DSB can have (multiple) comments, we could add that too.
        for (unsigned section_number = 0;
            section_number < wtap_file_get_num_dsbs(cap_file_.capFile()->provider.wth);
            section_number++) {
                wtap_block_t dsb = wtap_file_get_dsb(cap_file_.capFile()->provider.wth, section_number);
                wtapng_dsb_mandatory_t *dsb_mand = (wtapng_dsb_mandatory_t*)wtap_block_get_mandatory_data(dsb);
                out << table_row_begin
                    << table_data_tmpl.arg(secrets_type_description(dsb_mand->secrets_type))
                    << table_data_tmpl.arg(tr("%1 bytes").arg(dsb_mand->secrets_len))
                    << table_row_end;
            }
        out << table_end;
    }

    // Statistics Section
    out << section_tmpl_.arg(tr("Statistics"));
    out << table_begin;

    out << table_ul_row_begin
        << table_hheader25_tmpl.arg(tr("Measurement"))
        << table_hheader25_tmpl.arg(tr("Captured"))
        << table_hheader25_tmpl.arg(tr("Displayed"))
        << table_hheader25_tmpl.arg(tr("Marked"))
        << table_row_end;

    QString n_a = UTF8_EM_DASH;
    QString captured_str, displayed_str, marked_str;

    // Packets
    displayed_str = marked_str = n_a;
    if (summary.filtered_count > 0 && summary.packet_count > 0) {
            displayed_str = QString("%1 (%2%)")
            .arg(summary.filtered_count)
            .arg(100.0 * summary.filtered_count / summary.packet_count, 1, 'f', 1);
    }
    if (summary.packet_count > 0 && summary.marked_count > 0) {
            marked_str = QString("%1 (%2%)")
            .arg(summary.marked_count)
            .arg(100.0 * summary.marked_count / summary.packet_count, 1, 'f', 1);
    }

    out << table_row_begin;
    if (is_packet_configuration_namespace()) {
        out << table_data_tmpl.arg(tr("Packets"));
    } else {
        out << table_data_tmpl.arg(tr("Events"));
    }
    out << table_data_tmpl.arg(summary.packet_count)
        << table_data_tmpl.arg(displayed_str)
        << table_data_tmpl.arg(marked_str)
        << table_row_end;

    // Time between first and last
    captured_str = displayed_str = marked_str = n_a;
    if (seconds > 0) {
            captured_str = QString("%1").arg(seconds, 1, 'f', 3);
    }
    if (disp_seconds > 0) {
            displayed_str = QString("%1").arg(disp_seconds, 1, 'f', 3);
    }
    if (marked_seconds > 0) {
            marked_str = QString("%1").arg(marked_seconds, 1, 'f', 3);
    }
    out << table_row_begin
        << table_data_tmpl.arg(tr("Time span, s"))
        << table_data_tmpl.arg(captured_str)
        << table_data_tmpl.arg(displayed_str)
        << table_data_tmpl.arg(marked_str)
        << table_row_end;

    // Average packets per second
    captured_str = displayed_str = marked_str = n_a;
    if (seconds > 0) {
            captured_str = QString("%1").arg(summary.packet_count/seconds, 1, 'f', 1);
    }
    if (disp_seconds > 0) {
            displayed_str = QString("%1").arg(summary.filtered_count/disp_seconds, 1, 'f', 1);
    }
    if (marked_seconds > 0) {
            marked_str = QString("%1").arg(summary.marked_count/marked_seconds, 1, 'f', 1);
    }
    out << table_row_begin
        << table_data_tmpl.arg(tr("Average pps"))
        << table_data_tmpl.arg(captured_str)
        << table_data_tmpl.arg(displayed_str)
        << table_data_tmpl.arg(marked_str)
        << table_row_end;

    // Average packet size
    captured_str = displayed_str = marked_str = n_a;
    if (summary.packet_count > 0) {
            captured_str = QString::number((uint64_t) ((double)summary.bytes/summary.packet_count + 0.5));
    }
    if (summary.filtered_count > 0) {
            displayed_str = QString::number((uint64_t) ((double)summary.filtered_bytes/summary.filtered_count + 0.5));
    }
    if (summary.marked_count > 0) {
            marked_str = QString::number((uint64_t) ((double)summary.marked_bytes/summary.marked_count + 0.5));
    }
    out << table_row_begin;
    if (is_packet_configuration_namespace()) {
        out << table_data_tmpl.arg(tr("Average packet size, B"));
    } else {
        out << table_data_tmpl.arg(tr("Average event size, B"));
    }
    out << table_data_tmpl.arg(captured_str)
        << table_data_tmpl.arg(displayed_str)
        << table_data_tmpl.arg(marked_str)
        << table_row_end;

    // Byte count
    displayed_str = marked_str = "0";
    if (summary.bytes > 0 && summary.filtered_bytes > 0) {
        displayed_str = QString("%1 (%2%)")
                .arg(summary.filtered_bytes)
                .arg(100.0 * summary.filtered_bytes / summary.bytes, 1, 'f', 1);
    }
    if (summary.bytes > 0 && summary.marked_bytes > 0) {
        marked_str = QString("%1 (%2%)")
                .arg(summary.marked_bytes)
                .arg(100.0 * summary.marked_bytes / summary.bytes, 1, 'f', 1);
    }
    out << table_row_begin
        << table_data_tmpl.arg(tr("Bytes"))
        << table_data_tmpl.arg(summary.bytes)
        << table_data_tmpl.arg(displayed_str)
        << table_data_tmpl.arg(marked_str)
        << table_row_end;

    // Bytes per second
    captured_str = displayed_str = marked_str = n_a;
    if (seconds > 0) {
        captured_str =
                gchar_free_to_qstring(format_size(summary.bytes / seconds, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI));
    }
    if (disp_seconds > 0) {
        displayed_str =
                gchar_free_to_qstring(format_size(summary.filtered_bytes / disp_seconds, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI));
    }
    if (marked_seconds > 0) {
        marked_str =
                gchar_free_to_qstring(format_size(summary.marked_bytes / marked_seconds, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI));
    }
    out << table_row_begin
        << table_data_tmpl.arg(tr("Average bytes/s"))
        << table_data_tmpl.arg(captured_str)
        << table_data_tmpl.arg(displayed_str)
        << table_data_tmpl.arg(marked_str)
        << table_row_end;

    // Bits per second
    captured_str = displayed_str = marked_str = n_a;
    if (seconds > 0) {
            captured_str =
                    gchar_free_to_qstring(format_size(summary.bytes * 8 / seconds, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI));
    }
    if (disp_seconds > 0) {
            displayed_str =
                    gchar_free_to_qstring(format_size(summary.filtered_bytes * 8 / disp_seconds, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI));
    }
    if (marked_seconds > 0) {
            marked_str =
                    gchar_free_to_qstring(format_size(summary.marked_bytes * 8 / marked_seconds, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI));
    }
    out << table_row_begin
        << table_data_tmpl.arg(tr("Average bits/s"))
        << table_data_tmpl.arg(captured_str)
        << table_data_tmpl.arg(displayed_str)
        << table_data_tmpl.arg(marked_str)
        << table_row_end;

    out << table_end;

    return summary_str;
}

void CaptureFilePropertiesDialog::fillDetails()
{
    if (!cap_file_.isValid()) return;

    ui->detailsTextEdit->clear();

    QTextCursor cursor = ui->detailsTextEdit->textCursor();
    QString summary = summaryToHtml();
    cursor.insertHtml(summary);
    cursor.insertBlock(); // Work around rendering oddity.

    if (cap_file_.capFile()->packet_comment_count > 0) {
        cursor.insertBlock();
        if (is_packet_configuration_namespace()) {
            cursor.insertHtml(section_tmpl_.arg(tr("Packet Comments")));
        } else {
            cursor.insertHtml(section_tmpl_.arg(tr("Event Comments")));
        }

        for (uint32_t framenum = 1; framenum <= cap_file_.capFile()->count ; framenum++) {
            frame_data *fdata = frame_data_sequence_find(cap_file_.capFile()->provider.frames, framenum);
            wtap_block_t pkt_block = cf_get_packet_block(cap_file_.capFile(), fdata);

            if (pkt_block) {
                unsigned n_comments = wtap_block_count_option(pkt_block, OPT_COMMENT);
                for (unsigned i = 0; i < n_comments; i++) {
                    char *comment_text;
                    if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_nth_string_option_value(pkt_block, OPT_COMMENT, i, &comment_text)) {
                        QString frame_comment_html = tr("<p>Frame %1: ").arg(framenum);
                        QString raw_comment = comment_text;

                        frame_comment_html += html_escape(raw_comment).replace('\n', "<br>");
                        frame_comment_html += "</p>\n";
                        cursor.insertBlock();
                        cursor.insertHtml(frame_comment_html);
                    }
                }
            }
            wtap_block_unref(pkt_block);
        }
    }
    ui->detailsTextEdit->verticalScrollBar()->setValue(0);
}

void CaptureFilePropertiesDialog::changeEvent(QEvent* event)
{
    if (event != nullptr)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            ui->retranslateUi(this);
            updateWidgets();
            break;
        default:
            break;
        }
    }
    QDialog::changeEvent(event);
}

void CaptureFilePropertiesDialog::addCaptureComment()
{
    CaptureCommentDialog* cc_dialog;
    cc_dialog = new CaptureCommentDialog(*this, cap_file_);
    connect(cc_dialog, &CaptureCommentDialog::captureCommentChanged, this, &CaptureFilePropertiesDialog::updateWidgets);
    //cc_dialog->setWindowModality(Qt::ApplicationModal);
    cc_dialog->setAttribute(Qt::WA_DeleteOnClose);
    cc_dialog->show();
}

void CaptureFilePropertiesDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STATS_SUMMARY_DIALOG);
}

void CaptureFilePropertiesDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == ui->buttonBox->button(QDialogButtonBox::Apply)) {
        QClipboard *clipboard = QApplication::clipboard();
        QString details;
        if (is_packet_configuration_namespace()) {
            details = tr("Created by Wireshark %1\n\n").arg(get_ws_vcs_version_info());
        } else {
            details = tr("Created by Logray %1\n\n").arg(get_lr_vcs_version_info());
        }
        details.append(ui->detailsTextEdit->toPlainText());
        clipboard->setText(details);
    } else if (button == ui->buttonBox->button(QDialogButtonBox::Reset)) {
        updateWidgets();
    }
}

void CaptureFilePropertiesDialog::on_buttonBox_rejected()
{
    reject();
}
