/* follow_stream_dialog.cpp
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

#include "follow_stream_dialog.h"
#include <ui_follow_stream_dialog.h>

#include "main_window.h"
#include "wireshark_application.h"

#include "epan/follow.h"
#include "epan/dissectors/packet-tcp.h"
#include "epan/dissectors/packet-udp.h"
#include "epan/prefs.h"
#include "epan/addr_resolv.h"
#include "epan/charsets.h"
#include "epan/epan_dissect.h"
#include "epan/tap.h"

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include <wsutil/utf8_entities.h>

#include "wsutil/file_util.h"
#include "wsutil/str_util.h"
#include "ws_version_info.h"

#include "ws_symbol_export.h"

#include "color_utils.h"

#include "progress_frame.h"
#include "qt_ui_utils.h"

#include <QElapsedTimer>
#include <QKeyEvent>
#include <QMessageBox>
#include <QPrintDialog>
#include <QPrinter>
#include <QScrollBar>
#include <QTextEdit>
#include <QTextStream>

// To do:
// - Show text while tapping.
// - Instead of calling QMessageBox, display the error message in the text
//   box and disable the appropriate controls.
// - Add a progress bar and connect captureCaptureUpdateContinue to it

// Matches SplashOverlay.
static int info_update_freq_ = 100;

FollowStreamDialog::FollowStreamDialog(QWidget &parent, CaptureFile &cf, follow_type_t type) :
    WiresharkDialog(parent, cf),
    ui(new Ui::FollowStreamDialog),
    b_find_(NULL),
    follow_type_(type),
    follower_(NULL),
    show_type_(SHOW_ASCII),
    truncated_(false),
    client_buffer_count_(0),
    server_buffer_count_(0),
    client_packet_count_(0),
    server_packet_count_(0),
    last_packet_(0),
    last_from_server_(0),
    turns_(0),
    save_as_(false),
    use_regex_find_(false)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 2 / 3, parent.height());

    switch(type)
    {
    case FOLLOW_TCP:
        follower_ = get_follow_by_name("TCP");
        break;
    case FOLLOW_SSL:
        follower_ = get_follow_by_name("SSL");
        break;
    case FOLLOW_UDP:
        follower_ = get_follow_by_name("UDP");
        break;
    case FOLLOW_HTTP:
        follower_ = get_follow_by_name("HTTP");
        break;
    default :
        g_assert_not_reached();
    }

    memset(&follow_info_, 0, sizeof(follow_info_));
    follow_info_.show_stream = BOTH_HOSTS;

    ui->teStreamContent->installEventFilter(this);

    connect(ui->leFind, SIGNAL(useRegexFind(bool)), this, SLOT(useRegexFind(bool)));

    QComboBox *cbcs = ui->cbCharset;
    cbcs->blockSignals(true);
    cbcs->addItem(tr("ASCII"), SHOW_ASCII);
    cbcs->addItem(tr("C Arrays"), SHOW_CARRAY);
    cbcs->addItem(tr("EBCDIC"), SHOW_EBCDIC);
    cbcs->addItem(tr("Hex Dump"), SHOW_HEXDUMP);
    cbcs->addItem(tr("UTF-8"), SHOW_UTF8);
    cbcs->addItem(tr("UTF-16"), SHOW_UTF16);
    cbcs->addItem(tr("YAML"), SHOW_YAML);
    cbcs->addItem(tr("Raw"), SHOW_RAW);
    cbcs->blockSignals(false);

    b_filter_out_ = ui->buttonBox->addButton(tr("Filter Out This Stream"), QDialogButtonBox::ActionRole);
    connect(b_filter_out_, SIGNAL(clicked()), this, SLOT(filterOut()));

    b_print_ = ui->buttonBox->addButton(tr("Print"), QDialogButtonBox::ActionRole);
    connect(b_print_, SIGNAL(clicked()), this, SLOT(printStream()));

    b_save_ = ui->buttonBox->addButton(tr("Save as" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ActionRole);
    connect(b_save_, SIGNAL(clicked()), this, SLOT(saveAs()));

    b_back_ = ui->buttonBox->addButton(tr("Back"), QDialogButtonBox::ActionRole);
    connect(b_back_, SIGNAL(clicked()), this, SLOT(backButton()));

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    connect(ui->buttonBox, SIGNAL(helpRequested()), this, SLOT(helpButton()));
    connect(ui->teStreamContent, SIGNAL(mouseMovedToTextCursorPosition(int)),
            this, SLOT(fillHintLabel(int)));
    connect(ui->teStreamContent, SIGNAL(mouseClickedOnTextCursorPosition(int)),
            this, SLOT(goToPacketForTextPos(int)));
    connect(&cap_file_, SIGNAL(captureFileClosing()), this, SLOT(captureFileClosing()));

    fillHintLabel(-1);
}

FollowStreamDialog::~FollowStreamDialog()
{
    delete ui;
    resetStream(); // Frees payload
}

void FollowStreamDialog::printStream()
{
#ifndef QT_NO_PRINTER
    QPrinter printer(QPrinter::HighResolution);
    QPrintDialog dialog(&printer, this);
    if (dialog.exec() == QDialog::Accepted)
        ui->teStreamContent->print(&printer);
#endif
}

void FollowStreamDialog::fillHintLabel(int text_pos)
{
    QString hint;
    int pkt = -1;

    if (text_pos >= 0) {
        QMap<int, guint32>::iterator it = text_pos_to_packet_.upperBound(text_pos);
        if (it != text_pos_to_packet_.end()) {
            pkt = it.value();
        }
    }

    if (pkt > 0) {
        hint = QString(tr("Packet %1. ")).arg(pkt);
    }

    hint += tr("%Ln <span style=\"color: %1; background-color:%2\">client</span> pkt(s), ", "", client_packet_count_)
            .arg(ColorUtils::fromColorT(prefs.st_client_fg).name())
            .arg(ColorUtils::fromColorT(prefs.st_client_bg).name())
            + tr("%Ln <span style=\"color: %1; background-color:%2\">server</span> pkt(s), ", "", server_packet_count_)
            .arg(ColorUtils::fromColorT(prefs.st_server_fg).name())
            .arg(ColorUtils::fromColorT(prefs.st_server_bg).name())
            + tr("%Ln turn(s).", "", turns_);

    if (pkt > 0) {
        hint.append(QString(tr(" Click to select.")));
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void FollowStreamDialog::goToPacketForTextPos(int text_pos)
{
    int pkt = -1;
    if (file_closed_) {
        return;
    }

    if (text_pos >= 0) {
        QMap<int, guint32>::iterator it = text_pos_to_packet_.upperBound(text_pos);
        if (it != text_pos_to_packet_.end()) {
            pkt = it.value();
        }
    }

    if (pkt > 0) {
        emit goToPacket(pkt);
    }
}

void FollowStreamDialog::updateWidgets(bool follow_in_progress)
{
    bool enable = !follow_in_progress;
    if (file_closed_) {
        ui->teStreamContent->setEnabled(true);
        enable = false;
    }

    ui->cbDirections->setEnabled(enable);
    ui->cbCharset->setEnabled(enable);
    ui->streamNumberSpinBox->setEnabled(enable);
    ui->leFind->setEnabled(enable);
    ui->bFind->setEnabled(enable);
    b_filter_out_->setEnabled(enable);
    b_print_->setEnabled(enable);
    b_save_->setEnabled(enable);

    WiresharkDialog::updateWidgets();
}

void FollowStreamDialog::useRegexFind(bool use_regex)
{
    use_regex_find_ = use_regex;
    if (use_regex_find_)
        ui->lFind->setText("Regex Find:");
    else
        ui->lFind->setText("Find:");
}

void FollowStreamDialog::findText(bool go_back)
{
    if (ui->leFind->text().isEmpty()) return;

#if (QT_VERSION >= QT_VERSION_CHECK(5, 3, 0))
    bool found;
    if (use_regex_find_) {
        QRegExp regex(ui->leFind->text());
        found = ui->teStreamContent->find(regex);
    } else {
        found = ui->teStreamContent->find(ui->leFind->text());
    }
#else
    bool found = ui->teStreamContent->find(ui->leFind->text());
#endif

    if (found) {
        ui->teStreamContent->setFocus();
    } else if (go_back) {
        ui->teStreamContent->moveCursor(QTextCursor::Start);
        findText(false);
    }
}

void FollowStreamDialog::saveAs()
{
    QString file_name = QFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Stream Content As" UTF8_HORIZONTAL_ELLIPSIS)));
    if (!file_name.isEmpty()) {
        QTextStream out(&file_);

        file_.setFileName(file_name);
        if (!file_.open(QIODevice::WriteOnly)) {
            open_failure_alert_box(file_name.toUtf8().constData(), errno, TRUE);
            return;
        }

        save_as_ = true;

        readStream();

        if ((show_type_ != SHOW_RAW) && (show_type_ != SHOW_UTF8))
        {
            out << ui->teStreamContent->toPlainText();
        }

        save_as_ = false;

        file_.close();
    }
}

void FollowStreamDialog::helpButton()
{
    wsApp->helpTopicAction(HELP_FOLLOW_STREAM_DIALOG);
}

void FollowStreamDialog::backButton()
{
    output_filter_ = previous_filter_;

    close();
}

void FollowStreamDialog::filterOut()
{
    output_filter_ = filter_out_filter_;

    close();
}

void FollowStreamDialog::close()
{
    // Update filter - Use:
    //     previous_filter if 'Close' (passed in follow() method)
    //     filter_out_filter_ if 'Filter Out This Stream' (built by appending !current_stream to previous_filter)
    //     leave filter alone if window closed. (current stream)
    emit updateFilter(output_filter_, TRUE);

    WiresharkDialog::close();
}

void FollowStreamDialog::on_cbDirections_currentIndexChanged(int idx)
{
    switch(idx)
    {
    case 0 :
        follow_info_.show_stream = BOTH_HOSTS;
        break;
    case 1 :
        follow_info_.show_stream = FROM_SERVER;
        break;
    case 2 :
        follow_info_.show_stream = FROM_CLIENT;
        break;
    default:
        return;
    }

    readStream();
}

void FollowStreamDialog::on_cbCharset_currentIndexChanged(int idx)
{
    if (idx < 0) return;
    show_type_ = static_cast<show_type_t>(ui->cbCharset->itemData(idx).toInt());
    readStream();
}

void FollowStreamDialog::on_bFind_clicked()
{
    findText();
}

void FollowStreamDialog::on_leFind_returnPressed()
{
    findText();
}

void FollowStreamDialog::on_streamNumberSpinBox_valueChanged(int stream_num)
{
    if (file_closed_) return;

    if (stream_num >= 0) {
        follow(previous_filter_, true, stream_num);
    }
}

// Not sure why we have to do this manually.
void FollowStreamDialog::on_buttonBox_rejected()
{
    WiresharkDialog::reject();
}

void FollowStreamDialog::removeStreamControls()
{
    ui->horizontalLayout->removeItem(ui->streamNumberSpacer);
    ui->streamNumberLabel->setVisible(false);
    ui->streamNumberSpinBox->setVisible(false);
}

void FollowStreamDialog::resetStream()
{
    GList *cur;
    follow_record_t *follow_record;

    filter_out_filter_.clear();
    text_pos_to_packet_.clear();
    if (!data_out_filename_.isEmpty()) {
        ws_unlink(data_out_filename_.toUtf8().constData());
    }
    for (cur = follow_info_.payload; cur; cur = g_list_next(cur)) {
        follow_record = (follow_record_t *)cur->data;
        if(follow_record->data) {
            g_byte_array_free(follow_record->data, TRUE);
        }
        g_free(follow_record);
    }
    g_list_free(follow_info_.payload);

    //Only TCP stream uses fragments
    if (follow_type_ == FOLLOW_TCP) {
        for (cur = follow_info_.fragments[0]; cur; cur = g_list_next(cur)) {
            follow_record = (follow_record_t *)cur->data;
            if(follow_record->data) {
                g_byte_array_free(follow_record->data, TRUE);
            }
            g_free(follow_record);
        }
        follow_info_.fragments[0] = NULL;
        for (cur = follow_info_.fragments[1]; cur; cur = g_list_next(cur)) {
            follow_record = (follow_record_t *)cur->data;
            if(follow_record->data) {
                g_byte_array_free(follow_record->data, TRUE);
            }
            g_free(follow_record);
        }
        follow_info_.fragments[1] = NULL;
    }

    follow_info_.payload = NULL;
    follow_info_.client_port = 0;
}

frs_return_t
FollowStreamDialog::readStream()
{

    // Only clear the display if we're going to refill it
    if (save_as_ == false)
        ui->teStreamContent->clear();

    truncated_ = false;
    frs_return_t ret;

    client_buffer_count_ = 0;
    server_buffer_count_ = 0;
    client_packet_count_ = 0;
    server_packet_count_ = 0;
    last_packet_ = 0;
    turns_ = 0;

    switch(follow_type_) {

    case FOLLOW_TCP :
    case FOLLOW_UDP :
    case FOLLOW_HTTP :
    case FOLLOW_SSL :
        ret = readFollowStream();
        break;

    default :
        g_assert_not_reached();
        ret = (frs_return_t)0;
        break;
    }

    if (save_as_ == false)
        ui->teStreamContent->moveCursor(QTextCursor::Start);

    return ret;
}

void
FollowStreamDialog::followStream()
{
    readStream();
}

const int FollowStreamDialog::max_document_length_ = 500 * 1000 * 1000; // Just a guess
void FollowStreamDialog::addText(QString text, gboolean is_from_server, guint32 packet_num)
{
    if (save_as_ == true)
    {
        size_t nwritten;
        int FileDescriptor = file_.handle();
        int fd_new = ws_dup(FileDescriptor);
        if (fd_new == -1)
            return;
        FILE* fh = ws_fdopen(fd_new, "wb");
        if (show_type_ == SHOW_RAW) {
            QByteArray binstream = QByteArray::fromHex(text.toUtf8());
            nwritten = fwrite(binstream.constData(), binstream.length(), 1, fh);
        } else {
            nwritten = fwrite(text.toUtf8().constData(), text.length(), 1, fh);
        }
        fclose(fh);
        if ((int)nwritten != text.length()) {
#if 0
            report_an_error_maybe();
#endif
        }
        return;
    }

    if (truncated_) {
        return;
    }

    int char_count = ui->teStreamContent->document()->characterCount();
    if (char_count + text.length() > max_document_length_) {
        text.truncate(max_document_length_ - char_count);
        truncated_ = true;
    }

    setUpdatesEnabled(false);
    int cur_pos = ui->teStreamContent->verticalScrollBar()->value();
    ui->teStreamContent->moveCursor(QTextCursor::End);
    QTextCharFormat tcf = ui->teStreamContent->currentCharFormat();
    if (is_from_server) {
        tcf.setForeground(ColorUtils::fromColorT(prefs.st_server_fg));
        tcf.setBackground(ColorUtils::fromColorT(prefs.st_server_bg));
    } else {
        tcf.setForeground(ColorUtils::fromColorT(prefs.st_client_fg));
        tcf.setBackground(ColorUtils::fromColorT(prefs.st_client_bg));
    }
    ui->teStreamContent->setCurrentCharFormat(tcf);

    ui->teStreamContent->insertPlainText(text);
    text_pos_to_packet_[ui->teStreamContent->textCursor().anchor()] = packet_num;

    if (truncated_) {
        tcf = ui->teStreamContent->currentCharFormat();
        tcf.setBackground(palette().window().color());
        tcf.setForeground(palette().windowText().color());
        ui->teStreamContent->insertPlainText(tr("\n[Stream output truncated]"));
        ui->teStreamContent->moveCursor(QTextCursor::End);
    } else {
        ui->teStreamContent->verticalScrollBar()->setValue(cur_pos);
    }
    setUpdatesEnabled(true);
}

// The following keyboard shortcuts should work (although
// they may not work consistently depending on focus):
// / (slash), Ctrl-F - Focus and highlight the search box
// Ctrl-G, Ctrl-N, F3 - Find next
// Should we make it so that typing any text starts searching?
bool FollowStreamDialog::eventFilter(QObject *, QEvent *event)
{
    if (ui->teStreamContent->hasFocus() && event->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent*>(event);
        if (keyEvent->matches(QKeySequence::SelectAll) || keyEvent->matches(QKeySequence::Copy)
                || keyEvent->text().isEmpty()) {
            return false;
        }
        ui->leFind->setFocus();
        if (keyEvent->matches(QKeySequence::Find)) {
            return true;
        } else if (keyEvent->matches(QKeySequence::FindNext)) {
            findText();
            return true;
        }
    }

    return false;
}

void FollowStreamDialog::keyPressEvent(QKeyEvent *event)
{
    if (ui->leFind->hasFocus()) {
        if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            findText();
            return;
        }
    } else {
        if (event->key() == Qt::Key_Slash || event->matches(QKeySequence::Find)) {
            ui->leFind->setFocus();
            ui->leFind->selectAll();
        }
        return;
    }

    if (event->key() == Qt::Key_F3 || (event->key() == Qt::Key_N && event->modifiers() & Qt::ControlModifier)) {
        findText();
        return;
    }

    QDialog::keyPressEvent(event);
}

static inline void sanitize_buffer(char *buffer, size_t nchars) {
    for (size_t i = 0; i < nchars; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r' || buffer[i] == '\t')
            continue;
        if (! g_ascii_isprint((guchar)buffer[i])) {
            buffer[i] = '.';
        }
    }
}

frs_return_t
FollowStreamDialog::showBuffer(char *buffer, size_t nchars, gboolean is_from_server, guint32 packet_num,
                                guint32 *global_pos)
{
    gchar initbuf[256];
    guint32 current_pos;
    static const gchar hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    switch (show_type_) {

    case SHOW_EBCDIC:
    {
        /* If our native arch is ASCII, call: */
        EBCDIC_to_ASCII((guint8*)buffer, (guint) nchars);
        sanitize_buffer(buffer, nchars);
        QByteArray ba = QByteArray(buffer, (int)nchars);
        addText(ba, is_from_server, packet_num);
        break;
    }

    case SHOW_ASCII:
    {
        /* If our native arch is EBCDIC, call:
         * ASCII_TO_EBCDIC(buffer, nchars);
         */
        sanitize_buffer(buffer, nchars);
        QByteArray ba = QByteArray(buffer, (int)nchars);
        addText(ba, is_from_server, packet_num);
        break;
    }

    case SHOW_UTF8:
    {
        // The QString docs say that invalid characters will be replaced with
        // replacement characters or removed. It would be nice if we could
        // explicitly choose one or the other.
        QString utf8 = QString::fromUtf8(buffer, (int)nchars);
        addText(utf8, is_from_server, packet_num);
        break;
    }

    case SHOW_UTF16:
    {
        // QString::fromUtf16 calls QUtf16::convertToUnicode, casting buffer
        // back to a const char * and doubling nchars.
        QString utf16 = QString::fromUtf16((const unsigned short *)buffer, (int)nchars / 2);
        addText(utf16, is_from_server, packet_num);
        break;
    }

    case SHOW_HEXDUMP:
        current_pos = 0;
        while (current_pos < nchars) {
            gchar hexbuf[256];
            int i;
            gchar *cur = hexbuf, *ascii_start;

            /* is_from_server indentation : put 4 spaces at the
             * beginning of the string */
            /* XXX - We might want to prepend each line with "C" or "S" instead. */
            if (is_from_server && follow_info_.show_stream == BOTH_HOSTS) {
                memset(cur, ' ', 4);
                cur += 4;
            }
            cur += g_snprintf(cur, 20, "%08X  ", *global_pos);
            /* 49 is space consumed by hex chars */
            ascii_start = cur + 49 + 2;
            for (i = 0; i < 16 && current_pos + i < nchars; i++) {
                *cur++ =
                        hexchars[(buffer[current_pos + i] & 0xf0) >> 4];
                *cur++ =
                        hexchars[buffer[current_pos + i] & 0x0f];
                *cur++ = ' ';
                if (i == 7)
                    *cur++ = ' ';
            }
            /* Fill it up if column isn't complete */
            while (cur < ascii_start)
                *cur++ = ' ';

            /* Now dump bytes as text */
            for (i = 0; i < 16 && current_pos + i < nchars; i++) {
                *cur++ =
                        (g_ascii_isprint((guchar)buffer[current_pos + i]) ?
                            buffer[current_pos + i] : '.');
                if (i == 7) {
                    *cur++ = ' ';
                }
            }
            current_pos += i;
            (*global_pos) += i;
            *cur++ = '\n';
            *cur = 0;

            addText(hexbuf, is_from_server, packet_num);
        }
        break;

    case SHOW_CARRAY:
        current_pos = 0;
        g_snprintf(initbuf, sizeof(initbuf), "char peer%d_%d[] = { /* Packet %u */\n",
                   is_from_server ? 1 : 0,
                   is_from_server ? server_buffer_count_++ : client_buffer_count_++,
                   packet_num);
        addText(initbuf, is_from_server, packet_num);

        while (current_pos < nchars) {
            gchar hexbuf[256];
            int i, cur;

            cur = 0;
            for (i = 0; i < 8 && current_pos + i < nchars; i++) {
                /* Prepend entries with "0x" */
                hexbuf[cur++] = '0';
                hexbuf[cur++] = 'x';
                hexbuf[cur++] =
                        hexchars[(buffer[current_pos + i] & 0xf0) >> 4];
                hexbuf[cur++] =
                        hexchars[buffer[current_pos + i] & 0x0f];

                /* Delimit array entries with a comma */
                if (current_pos + i + 1 < nchars)
                    hexbuf[cur++] = ',';

                hexbuf[cur++] = ' ';
            }

            /* Terminate the array if we are at the end */
            if (current_pos + i == nchars) {
                hexbuf[cur++] = '}';
                hexbuf[cur++] = ';';
            }

            current_pos += i;
            (*global_pos) += i;
            hexbuf[cur++] = '\n';
            hexbuf[cur] = 0;
            addText(hexbuf, is_from_server, packet_num);
        }
        break;

    case SHOW_YAML:
    {
        QString yaml_text;

        const int base64_raw_len = 57; // Encodes to 76 bytes, common in RFCs
        current_pos = 0;

        if (packet_num != last_packet_) {
            yaml_text.append(QString("# Packet %1\npeer%2_%3: !!binary |\n")
                    .arg(packet_num)
                    .arg(is_from_server ? 1 : 0)
                    .arg(is_from_server ? server_buffer_count_++ : client_buffer_count_++));
        }
        while (current_pos < nchars) {
            int len = current_pos + base64_raw_len < nchars ? base64_raw_len : (int) nchars - current_pos;
            QByteArray base64_data(&buffer[current_pos], len);

            yaml_text += "  " + base64_data.toBase64() + "\n";

            current_pos += len;
            (*global_pos) += len;
        }
        addText(yaml_text, is_from_server, packet_num);
        break;
    }

    case SHOW_RAW:
    {
        QByteArray ba = QByteArray(buffer, (int)nchars).toHex();
        ba += '\n';
        addText(ba, is_from_server, packet_num);
        break;
    }
    }

    if (last_packet_ == 0) {
        last_from_server_ = is_from_server;
    }

    if (packet_num != last_packet_) {
        last_packet_ = packet_num;
        if (is_from_server) {
            server_packet_count_++;
        } else {
            client_packet_count_++;
        }
        if (last_from_server_ != is_from_server) {
            last_from_server_ = is_from_server;
            turns_++;
        }
    }

    return FRS_OK;
}

bool FollowStreamDialog::follow(QString previous_filter, bool use_stream_index, int stream_num)
{
    QString             follow_filter;
    const char          *hostname0 = NULL, *hostname1 = NULL;
    char                *port0 = NULL, *port1 = NULL;
    QString             server_to_client_string;
    QString             client_to_server_string;
    QString             both_directions_string;
    gboolean            is_follower = FALSE;

    resetStream();

    if (file_closed_)
    {
        QMessageBox::warning(this, tr("No capture file."), tr("Please make sure you have a capture file opened."));
        return false;
    }

    if (cap_file_.capFile()->edt == NULL)
    {
        QMessageBox::warning(this, tr("Error following stream."), tr("Capture file invalid."));
        return false;
    }

    is_follower = proto_is_frame_protocol(cap_file_.capFile()->edt->pi.layers, proto_get_protocol_filter_name(get_follow_proto_id(follower_)));
    if (!is_follower) {
        QMessageBox::warning(this, tr("Error following stream."), tr("Please make sure you have a %1 packet selected.").arg
                                (proto_get_protocol_short_name(find_protocol_by_id(get_follow_proto_id(follower_)))));
        return false;
    }

    if (follow_type_ == FOLLOW_SSL || follow_type_ == FOLLOW_HTTP)
    {
        /* we got ssl/http so we can follow */
        removeStreamControls();
    }

    follow_reset_stream(&follow_info_);

    /* Create a new filter that matches all packets in the TCP stream,
        and set the display filter entry accordingly */
    if (use_stream_index) {
        follow_filter = gchar_free_to_qstring(get_follow_index_func(follower_)(stream_num));
    } else {
        follow_filter = gchar_free_to_qstring(get_follow_conv_func(follower_)(&cap_file_.capFile()->edt->pi, &stream_num));
    }
    if (follow_filter.isEmpty()) {
        QMessageBox::warning(this,
                             tr("Error creating filter for this stream."),
                             tr("A transport or network layer header is needed."));
        return false;
    }

    previous_filter_ = previous_filter;
    /* append the negation */
    if(!previous_filter.isEmpty()) {
        filter_out_filter_ = QString("%1 and !(%2)")
                .arg(previous_filter).arg(follow_filter);
    }
    else
    {
        filter_out_filter_ = QString("!(%1)").arg(follow_filter);
    }

    /* data will be passed via tap callback*/
    if (!registerTapListener(get_follow_tap_string(follower_), &follow_info_,
                                follow_filter.toUtf8().constData(),
                                0, NULL, get_follow_tap_handler(follower_), NULL)) {
        return false;
    }

    switch (follow_type_)
    {
    case FOLLOW_TCP:
    {
        int stream_count = get_tcp_stream_count();
        ui->streamNumberSpinBox->blockSignals(true);
        ui->streamNumberSpinBox->setMaximum(stream_count-1);
        ui->streamNumberSpinBox->setValue(stream_num);
        ui->streamNumberSpinBox->blockSignals(false);
        ui->streamNumberSpinBox->setToolTip(tr("%Ln total stream(s).", "", stream_count));
        ui->streamNumberLabel->setToolTip(ui->streamNumberSpinBox->toolTip());

        break;
    }
    case FOLLOW_UDP:
    {
        int stream_count = get_udp_stream_count();
        ui->streamNumberSpinBox->blockSignals(true);
        ui->streamNumberSpinBox->setMaximum(stream_count-1);
        ui->streamNumberSpinBox->setValue(stream_num);
        ui->streamNumberSpinBox->blockSignals(false);
        ui->streamNumberSpinBox->setToolTip(tr("%Ln total stream(s).", "", stream_count));
        ui->streamNumberLabel->setToolTip(ui->streamNumberSpinBox->toolTip());

        break;
    }
    case FOLLOW_SSL:
    case FOLLOW_HTTP:
        /* No extra handling */
        break;
    }

    beginRetapPackets();
    updateWidgets(true);

    /* Run the display filter so it goes in effect - even if it's the
       same as the previous display filter. */
    emit updateFilter(follow_filter, TRUE);

    removeTapListeners();

    hostname0 = address_to_name(&follow_info_.client_ip);
    hostname1 = address_to_name(&follow_info_.server_ip);

    port0 = get_follow_port_to_display(follower_)(NULL, follow_info_.client_port);
    port1 = get_follow_port_to_display(follower_)(NULL, follow_info_.server_port);

    server_to_client_string =
            QString("%1:%2 %3 %4:%5 (%6)")
            .arg(hostname0).arg(port0)
            .arg(UTF8_RIGHTWARDS_ARROW)
            .arg(hostname1).arg(port1)
            .arg(gchar_free_to_qstring(format_size(
                                            follow_info_.bytes_written[0],
                                        format_size_unit_bytes|format_size_prefix_si)));

    client_to_server_string =
            QString("%1:%2 %3 %4:%5 (%6)")
            .arg(hostname1).arg(port1)
            .arg(UTF8_RIGHTWARDS_ARROW)
            .arg(hostname0).arg(port0)
            .arg(gchar_free_to_qstring(format_size(
                                            follow_info_.bytes_written[1],
                                        format_size_unit_bytes|format_size_prefix_si)));

    wmem_free(NULL, port0);
    wmem_free(NULL, port1);

    both_directions_string = QString("Entire conversation (%1)")
            .arg(gchar_free_to_qstring(format_size(
                                            follow_info_.bytes_written[0] + follow_info_.bytes_written[1],
                    format_size_unit_bytes|format_size_prefix_si)));
    setWindowSubtitle(tr("Follow %1 Stream (%2)").arg(proto_get_protocol_short_name(find_protocol_by_id(get_follow_proto_id(follower_))))
                                                 .arg(follow_filter));

    ui->cbDirections->blockSignals(true);
    ui->cbDirections->clear();
    ui->cbDirections->addItem(both_directions_string);
    ui->cbDirections->addItem(client_to_server_string);
    ui->cbDirections->addItem(server_to_client_string);
    ui->cbDirections->blockSignals(false);

    followStream();
    fillHintLabel(-1);

    updateWidgets(false);
    endRetapPackets();
    return true;
}

void FollowStreamDialog::captureFileClosing()
{
    QString tooltip = tr("File closed.");
    ui->streamNumberSpinBox->setToolTip(tooltip);
    ui->streamNumberLabel->setToolTip(tooltip);
    WiresharkDialog::captureFileClosing();
}

/*
 * XXX - the routine pointed to by "print_line_fcn_p" doesn't get handed lines,
 * it gets handed bufferfuls.  That's fine for "follow_write_raw()"
 * and "follow_add_to_gtk_text()", but, as "follow_print_text()" calls
 * the "print_line()" routine from "print.c", and as that routine might
 * genuinely expect to be handed a line (if, for example, it's using
 * some OS or desktop environment's printing API, and that API expects
 * to be handed lines), "follow_print_text()" should probably accumulate
 * lines in a buffer and hand them "print_line()".  (If there's a
 * complete line in a buffer - i.e., there's nothing of the line in
 * the previous buffer or the next buffer - it can just hand that to
 * "print_line()" after filtering out non-printables, as an
 * optimization.)
 *
 * This might or might not be the reason why C arrays display
 * correctly but get extra blank lines very other line when printed.
 */
frs_return_t
FollowStreamDialog::readFollowStream()
{
    guint32 global_client_pos = 0, global_server_pos = 0;
    guint32 *global_pos;
    gboolean skip;
    GList* cur;
    frs_return_t frs_return;
    follow_record_t *follow_record;
    QElapsedTimer elapsed_timer;

    elapsed_timer.start();

    for (cur = follow_info_.payload; cur; cur = g_list_next(cur)) {
        if (dialogClosed()) break;

        follow_record = (follow_record_t *)cur->data;
        skip = FALSE;
        if (!follow_record->is_server) {
            global_pos = &global_client_pos;
            if(follow_info_.show_stream == FROM_SERVER) {
                skip = TRUE;
            }
        } else {
            global_pos = &global_server_pos;
            if (follow_info_.show_stream == FROM_CLIENT) {
                skip = TRUE;
            }
        }

        QByteArray buffer;
        if (!skip) {
            // We want a deep copy.
            buffer.clear();
            buffer.append((const char *) follow_record->data->data,
                                     follow_record->data->len);
            frs_return = showBuffer(
                        buffer.data(),
                        follow_record->data->len,
                        follow_record->is_server,
                        follow_record->packet_num,
                        global_pos);
            if(frs_return == FRS_PRINT_ERROR)
                return frs_return;
            if (elapsed_timer.elapsed() > info_update_freq_) {
                fillHintLabel(ui->teStreamContent->textCursor().position());
                wsApp->processEvents();
                elapsed_timer.start();
            }
        }
    }

    return FRS_OK;
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
