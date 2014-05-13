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
#include "ui_follow_stream_dialog.h"

#include "main_window.h"
#include "wireshark_application.h"

#include "epan/follow.h"
#include "epan/dissectors/packet-tcp.h"
#include "epan/prefs.h"
#include "epan/addr_resolv.h"
#include "epan/charsets.h"
#include "epan/epan_dissect.h"
#include "epan/tap.h"

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "ui/utf8_entities.h"

#include "wsutil/tempfile.h"
#include "wsutil/file_util.h"
#include "wsutil/str_util.h"

#include "ws_symbol_export.h"

#include "color_utils.h"

#include "file.h"

#include "version_info.h"

#include "ui/follow.h"

#include <QKeyEvent>
#include <QMessageBox>
#include <QPrintDialog>
#include <QPrinter>
#include <QTextEdit>
#include <QTextStream>

// To do:
// - Instead of calling QMessageBox, display the error message in the text
//   box and disable the appropriate controls.

FollowStreamDialog::FollowStreamDialog(QWidget *parent, follow_type_t type, capture_file *cf) :
    QDialog(parent),
    ui(new Ui::FollowStreamDialog),
    cap_file_(cf),
    follow_type_(type),
    save_as_(false)
{
    ui->setupUi(this);

    setAttribute(Qt::WA_DeleteOnClose, true);
    memset(&follow_info_, 0, sizeof(follow_info_));

    ui->teStreamContent->installEventFilter(this);

    // XXX Use recent settings instead
    if (parent) {
        resize(parent->width() * 2 / 3, parent->height());
    }

    QComboBox *cbcs = ui->cbCharset;
    cbcs->blockSignals(true);
    cbcs->addItem("ASCII", SHOW_ASCII);
    cbcs->addItem("C Arrays", SHOW_CARRAY);
    cbcs->addItem("EBCDIC", SHOW_EBCDIC);
    cbcs->addItem("Hex Dump", SHOW_HEXDUMP);
    cbcs->addItem("UTF-8", SHOW_RAW);
    cbcs->addItem("YAML", SHOW_YAML);
    cbcs->blockSignals(false);

    b_filter_out_ = ui->buttonBox->addButton(tr("Hide this stream"), QDialogButtonBox::ActionRole);
    connect(b_filter_out_, SIGNAL(clicked()), this, SLOT(filterOut()));

    b_print_ = ui->buttonBox->addButton(tr("Print"), QDialogButtonBox::ActionRole);
    connect(b_print_, SIGNAL(clicked()), this, SLOT(printStream()));

    b_save_ = ui->buttonBox->addButton(tr("Save as..."), QDialogButtonBox::ActionRole);
    connect(b_save_, SIGNAL(clicked()), this, SLOT(saveAs()));

    connect(ui->buttonBox, SIGNAL(helpRequested()), this, SLOT(helpButton()));
    connect(ui->teStreamContent, SIGNAL(mouseMovedToTextCursorPosition(int)),
            this, SLOT(fillHintLabel(int)));
    connect(ui->teStreamContent, SIGNAL(mouseClickedOnTextCursorPosition(int)),
            this, SLOT(goToPacketForTextPos(int)));

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
    if ( dialog.exec() == QDialog::Accepted)
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
        hint = QString("Packet %1. ").arg(pkt);
    }

    hint += tr("%Ln client pkt(s), ", "", client_packet_count_)
            + tr("%Ln server pkt(s), ", "", server_packet_count_)
            + tr("%Ln turn(s).", "", turns_);

    if (pkt > 0) {
        hint.append(QString(" Click to select."));
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void FollowStreamDialog::goToPacketForTextPos(int text_pos)
{
    int pkt = -1;

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

void FollowStreamDialog::findText(bool go_back)
{
    if (ui->leFind->text().isEmpty()) return;

    bool found = ui->teStreamContent->find(ui->leFind->text());

    if (found) {
        ui->teStreamContent->setFocus();
    } else if (go_back) {
        ui->teStreamContent->moveCursor(QTextCursor::Start);
        findText(false);
    }
}

void FollowStreamDialog::saveAs()
{
    QString file_name = QFileDialog::getSaveFileName(this, "Wireshark: Save stream content as");
    file_.setFileName(file_name);
    file_.open( QIODevice::WriteOnly );
    QTextStream out(&file_);

    save_as_ = true;

    follow_read_stream();

    if (follow_info_.show_type != SHOW_RAW)
    {
        out << ui->teStreamContent->toPlainText();
    }

    save_as_ = false;

    file_.close();
}

void FollowStreamDialog::helpButton()
{
    wsApp->helpTopicAction(HELP_FOLLOW_STREAM_DIALOG);
}

void FollowStreamDialog::filterOut()
{

    emit updateFilter(filter_out_filter_, TRUE);

    this->close();
}

void FollowStreamDialog::on_cbDirections_currentIndexChanged(int index)
{
    switch(index)
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

    follow_read_stream();
}

void FollowStreamDialog::on_cbCharset_currentIndexChanged(int index)
{
    if (index < 0) return;
    follow_info_.show_type = static_cast<show_type_t>(ui->cbCharset->itemData(index).toInt());
    follow_read_stream();
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
    if (stream_num >= 0) {
                    follow_tcp_index(stream_num);
        follow(QString(), true);
    }
}

// Not sure why we have to do this manually.
void FollowStreamDialog::on_buttonBox_rejected()
{
    reject();
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

    filter_out_filter_.clear();
    text_pos_to_packet_.clear();
    if (!data_out_filename_.isEmpty()) {
        ws_unlink(data_out_filename_.toUtf8().constData());
    }
    if (data_out_file) {
        fclose(data_out_file);
        data_out_file = NULL;
    }
    for (cur = follow_info_.payload; cur; cur = g_list_next(cur)) {
        g_free(cur->data);
    }
    g_list_free(follow_info_.payload);
    follow_info_.payload = NULL;
}

frs_return_t
FollowStreamDialog::follow_read_stream()
{
    ui->teStreamContent->clear();
    frs_return_t ret;

    client_buffer_count_ = 0;
    server_buffer_count_ = 0;
    client_packet_count_ = 0;
    server_packet_count_ = 0;
    last_packet_ = 0;
    turns_ = 0;

    switch(follow_type_) {

    case FOLLOW_TCP :
        ret = follow_read_tcp_stream();
        break;

    case FOLLOW_UDP :
        ret = follow_read_udp_stream();
        break;

    case FOLLOW_SSL :
        ret = follow_read_ssl_stream();
        break;

    default :
        g_assert_not_reached();
        ret = (frs_return_t)0;
        break;
    }
    ui->teStreamContent->moveCursor(QTextCursor::Start);
    return ret;
}

//Copy from ui/gtk/follow_udp.c
static int
udp_queue_packet_data(void *tapdata, packet_info *pinfo,
                      epan_dissect_t *edt, const void *data)
{
    Q_UNUSED(edt);

    follow_record_t *follow_record;
    follow_info_t *follow_info = (follow_info_t *)tapdata;
    tvbuff_t *next_tvb = (tvbuff_t *)data;

    follow_record = g_new(follow_record_t,1);

    follow_record->data = g_byte_array_sized_new(tvb_length(next_tvb));
    follow_record->data = g_byte_array_append(follow_record->data,
                                              tvb_get_ptr(next_tvb, 0, -1),
                                              tvb_length(next_tvb));
    follow_record->packet_num = pinfo->fd->num;

    if (follow_info->client_port == 0) {
        follow_info->client_port = pinfo->srcport;
        copy_address(&follow_info->client_ip, &pinfo->src);
    }

    if (addresses_equal(&follow_info->client_ip, &pinfo->src) && follow_info->client_port == pinfo->srcport)
        follow_record->is_server = FALSE;
    else
        follow_record->is_server = TRUE;

    /* update stream counter */
    follow_info->bytes_written[follow_record->is_server] += follow_record->data->len;

    follow_info->payload = g_list_append(follow_info->payload, follow_record);
    return 0;
}

//Copy from ui/gtk/follow_ssl.c
static int
ssl_queue_packet_data(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *ssl)
{
    Q_UNUSED(edt);

    follow_info_t *      follow_info = (follow_info_t*) tapdata;
    SslDecryptedRecord * rec = NULL;
    SslDataInfo *        appl_data = NULL;
    int                  proto_ssl = GPOINTER_TO_INT(ssl);
    SslPacketInfo *      pi = NULL;
    show_stream_t        from = FROM_CLIENT;

    /* Skip packets without decrypted payload data. */
    pi = (SslPacketInfo*) p_get_proto_data(wmem_file_scope(), pinfo, proto_ssl, 0);
    if (!pi || !pi->appl_data) return 0;

    /* Compute the packet's sender. */
    if (follow_info->client_port == 0) {
        follow_info->client_port = pinfo->srcport;
        copy_address(&follow_info->client_ip, &pinfo->src);
    }
    if (ADDRESSES_EQUAL(&follow_info->client_ip, &pinfo->src) &&
            follow_info->client_port == pinfo->srcport) {
        from = FROM_CLIENT;
    } else {
        from = FROM_SERVER;
    }

    for (appl_data = pi->appl_data; appl_data != NULL; appl_data = appl_data->next) {

        /* TCP segments that contain the end of two or more SSL PDUs will be
           queued to SSL taps for each of those PDUs. Therefore a single
           packet could be processed by this SSL tap listener multiple times.
           The following test handles that scenario by treating the
           follow_info->bytes_written[] values as the next expected
           appl_data->seq. Any appl_data instances that fall below that have
           already been processed and must be skipped. */
        if (appl_data->seq < follow_info->bytes_written[from]) continue;

        /* Allocate a SslDecryptedRecord to hold the current appl_data
           instance's decrypted data. Even though it would be possible to
           consolidate multiple appl_data instances into a single rec, it is
           beneficial to use a one-to-one mapping. This affords the Follow
           Stream dialog view modes (ASCII, EBCDIC, Hex Dump, C Arrays, Raw)
           the opportunity to accurately reflect SSL PDU boundaries. Currently
           the Hex Dump view does by starting a new line, and the C Arrays
           view does by starting a new array declaration. */
        rec = (SslDecryptedRecord*) g_malloc(sizeof(SslDecryptedRecord) + appl_data->plain_data.data_len);
        rec->is_from_server = from == FROM_SERVER;
        rec->packet_num = pinfo->fd->num;
        rec->data.data = (guchar*) (rec + 1);
        rec->data.data_len = appl_data->plain_data.data_len;
        memcpy(rec->data.data, appl_data->plain_data.data, appl_data->plain_data.data_len);

        /* Append the record to the follow_info structure. */
        follow_info->payload = g_list_append(follow_info->payload, rec);
        follow_info->bytes_written[from] += rec->data.data_len;
    }

    return 0;
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
FollowStreamDialog::follow_read_ssl_stream()
{
    guint32      global_client_pos = 0, global_server_pos = 0;
    guint32 *    global_pos;
    GList *      cur;
    frs_return_t frs_return;

    for (cur = follow_info_.payload; cur; cur = g_list_next(cur)) {
        SslDecryptedRecord * rec = (SslDecryptedRecord*) cur->data;
        gboolean             include_rec = FALSE;

        if (rec->is_from_server) {
            global_pos = &global_server_pos;
            include_rec = (follow_info_.show_stream == BOTH_HOSTS) ||
                    (follow_info_.show_stream == FROM_SERVER);
        } else {
            global_pos = &global_client_pos;
            include_rec = (follow_info_.show_stream == BOTH_HOSTS) ||
                    (follow_info_.show_stream == FROM_CLIENT);
        }

        if (include_rec) {
            size_t nchars = rec->data.data_len;
            gchar *buffer = (gchar *)g_memdup(rec->data.data, (guint) nchars);

            frs_return = follow_show(buffer, nchars,
                                     rec->is_from_server, rec->packet_num, global_pos);
            g_free(buffer);
            if (frs_return == FRS_PRINT_ERROR)
                return frs_return;
        }
    }

    return FRS_OK;
}

void
FollowStreamDialog::follow_stream()
{
    follow_stats_t stats;

    follow_info_.show_type = SHOW_ASCII;
    follow_info_.show_stream = BOTH_HOSTS;

    /* Stream to show */
    follow_stats(&stats);

    follow_info_.is_ipv6 = stats.is_ipv6;

    follow_read_stream();
}




void FollowStreamDialog::add_text(QString text, gboolean is_from_server, guint32 packet_num)
{
    if (save_as_ == true)
    {
        //FILE *fh = (FILE *)arg;
        size_t nwritten;
        int FileDescriptor = file_.handle();
        FILE* fh = fdopen(dup(FileDescriptor), "wb");
        nwritten = fwrite(text.toUtf8().constData(), text.length(), 1, fh);
        fclose(fh);
        if ((int)nwritten != text.length()) {
#if 0
            report_an_error_maybe();
#endif
        }
        return;
    }

    QColor tagserver_fg = ColorUtils::fromColorT(prefs.st_server_fg);
    QColor tagserver_bg = ColorUtils::fromColorT(prefs.st_server_bg);

    QColor tagclient_fg = ColorUtils::fromColorT(prefs.st_client_fg);
    QColor tagclient_bg = ColorUtils::fromColorT(prefs.st_client_bg);

    ui->teStreamContent->moveCursor(QTextCursor::End);
    ui->teStreamContent->setCurrentFont(wsApp->monospaceFont());
    if (is_from_server)
    {
        ui->teStreamContent->setTextColor(tagserver_fg);
        ui->teStreamContent->setTextBackgroundColor(tagserver_bg);
    }
    else
    {
        ui->teStreamContent->setTextColor(tagclient_fg);
        ui->teStreamContent->setTextBackgroundColor(tagclient_bg);
    }
    ui->teStreamContent->insertPlainText(text);
    ui->teStreamContent->moveCursor(QTextCursor::End);
    text_pos_to_packet_[ui->teStreamContent->textCursor().anchor()] = packet_num;
}

void FollowStreamDialog::setCaptureFile(capture_file *cf)
{
    if (!cf) { // We only want to know when the file closes.
        cap_file_ = NULL;
        ui->streamNumberSpinBox->setEnabled(false);
        ui->streamNumberSpinBox->setToolTip(QString());
        ui->streamNumberLabel->setToolTip(QString());
    }
}

// The following keyboard shortcuts should work (although
// they may not work consistently depending on focus):
// / (slash), Ctrl-F - Focus and highlight the search box
// Ctrl-G, Ctrl-N, F3 - Find next
// Should we make it so that typing any text starts searching?
#include <QDebug>
bool FollowStreamDialog::eventFilter(QObject *obj, QEvent *event)
{
    Q_UNUSED(obj);
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
FollowStreamDialog::follow_show(char *buffer, size_t nchars, gboolean is_from_server, guint32 packet_num,
                                guint32 *global_pos)
{
    gchar initbuf[256];
    guint32 current_pos;
    static const gchar hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    switch (follow_info_.show_type) {

    case SHOW_EBCDIC:
    {
        /* If our native arch is ASCII, call: */
        EBCDIC_to_ASCII((guint8*)buffer, (guint) nchars);
        sanitize_buffer(buffer, nchars);
        QByteArray ba = QByteArray(buffer, (int)nchars);
        add_text(ba, is_from_server, packet_num);
        break;
    }

    case SHOW_ASCII:
    {
        /* If our native arch is EBCDIC, call:
         * ASCII_TO_EBCDIC(buffer, nchars);
         */
        sanitize_buffer(buffer, nchars);
        sanitize_buffer(buffer, nchars);
        QByteArray ba = QByteArray(buffer, (int)nchars);
        add_text(ba, is_from_server, packet_num);
        break;
    }

    case SHOW_RAW: // UTF-8
    {
        // The QString docs say that invalid characters will be replaced with
        // replacement characters or removed. It would be nice if we could
        // explicitly choose one or the other.
        QString utf8 = QString::fromUtf8(buffer, (int)nchars);
        add_text(utf8, is_from_server, packet_num);
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
            ascii_start = cur + 49;
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
                            buffer[current_pos + i] : '.' );
                if (i == 7) {
                    *cur++ = ' ';
                }
            }
            current_pos += i;
            (*global_pos) += i;
            *cur++ = '\n';
            *cur = 0;

            add_text(hexbuf, is_from_server, packet_num);
        }
        break;

    case SHOW_CARRAY:
        current_pos = 0;
        g_snprintf(initbuf, sizeof(initbuf), "char peer%d_%d[] = { /* Packet %u */\n",
                   is_from_server ? 1 : 0,
                   is_from_server ? server_buffer_count_++ : client_buffer_count_++,
                   packet_num);
        add_text(initbuf, is_from_server, packet_num);

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
            add_text(hexbuf, is_from_server, packet_num);
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
        add_text(yaml_text, is_from_server, packet_num);
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

bool FollowStreamDialog::follow(QString previous_filter, bool use_tcp_index)
{
    int                 tmp_fd;
    QString             follow_filter;
    const char          *hostname0 = NULL, *hostname1 = NULL;
    char                *port0 = NULL, *port1 = NULL;
    QString             server_to_client_string;
    QString             client_to_server_string;
    QString             both_directions_string;
    follow_stats_t      stats;
    tcp_stream_chunk    sc;
    size_t              nchars;
    GString *           msg;
    gboolean is_tcp = FALSE, is_udp = FALSE;

    resetStream();

    if (cap_file_ == NULL)
    {
        QMessageBox::warning(this, tr("No capture file."), tr("Please make sure you have a capture file opened."));
        return false;
    }

    if (cap_file_->edt == NULL)
    {
        QMessageBox::warning(this, tr("Error following stream."), tr("Capture file invalid."));
        return false;
    }

    proto_get_frame_protocols(cap_file_->edt->pi.layers, NULL, &is_tcp, &is_udp, NULL, NULL);

    switch (follow_type_)
    {
    case FOLLOW_TCP:
        if (!is_tcp) {
            QMessageBox::warning(this, tr("Error following stream."), tr("Please make sure you have a TCP packet selected."));
            return false;
        }
        break;
    case FOLLOW_UDP:
        removeStreamControls();
        if (!is_udp) {
            QMessageBox::warning(this, tr("Error following stream."), tr("Please make sure you have a UDP packet selected."));
            return false;
        }
        break;
    case FOLLOW_SSL:
        /* we got ssl so we can follow */
        removeStreamControls();
        if (!epan_dissect_packet_contains_field(cap_file_->edt, "ssl")) {
            QMessageBox::critical(this, tr("Error following stream."),
                               tr("Please make sure you have an SSL packet selected."));
            return false;
        }
        break;
    }

    if (follow_type_ == FOLLOW_TCP || follow_type_ == FOLLOW_SSL)
    {
        /* Create a new filter that matches all packets in the TCP stream,
           and set the display filter entry accordingly */
        reset_tcp_reassembly();
    }

    if (use_tcp_index) {
        follow_filter = gchar_free_to_qstring(build_follow_index_filter());
    } else {
        follow_filter = gchar_free_to_qstring(build_follow_conv_filter(&cap_file_->edt->pi));
    }
    if (follow_filter.isEmpty()) {
        QMessageBox::warning(this,
                             tr("Error creating filter for this stream."),
                             tr("A transport or network layer header is needed."));
        return false;
    }

    if (follow_type_ == FOLLOW_TCP || follow_type_ == FOLLOW_SSL)
    {
        /* Create a temporary file into which to dump the reassembled data
           from the TCP stream, and set "data_out_file" to refer to it, so
           that the TCP code will write to it.

           XXX - it might be nicer to just have the TCP code directly
           append stuff to the text widget for the TCP stream window,
           if we can arrange that said window not pop up until we're
           done. */
        gchar *data_out_filename;
        tmp_fd = create_tempfile(&data_out_filename, "follow");
        data_out_filename_ = data_out_filename;

        if (tmp_fd == -1) {
            QMessageBox::warning(this, "Error",
                                 "Could not create temporary file %1: %2",
                                 data_out_filename_, g_strerror(errno));
            data_out_filename_.clear();
            return false;
        }

        data_out_file = fdopen(tmp_fd, "w+b");
        if (data_out_file == NULL) {
            QMessageBox::warning(this, "Error",
                                 "Could not create temporary file %1: %2",
                                 data_out_filename_, g_strerror(errno));
            //ws_close(tmp_fd);
            ws_unlink(data_out_filename_.toUtf8().constData());
            data_out_filename_.clear();
            return false;
        }
    }

    /* append the negation */
    if(!previous_filter.isEmpty()) {
        filter_out_filter_ = QString("%1 and !(%2)")
                .arg(previous_filter).arg(follow_filter);
    }
    else
    {
        filter_out_filter_ = QString("!(%1)").arg(follow_filter);
    }

    switch (follow_type_)
    {
    case FOLLOW_TCP:
    {
        int stream_count = get_tcp_stream_count() - 1;
        ui->streamNumberSpinBox->blockSignals(true);
        ui->streamNumberSpinBox->setMaximum(stream_count);
        ui->streamNumberSpinBox->setValue(get_follow_tcp_index());
        ui->streamNumberSpinBox->blockSignals(false);
        ui->streamNumberSpinBox->setToolTip(tr("%Ln total stream(s).", "", stream_count));
        ui->streamNumberLabel->setToolTip(ui->streamNumberSpinBox->toolTip());

        break;
    }
    case FOLLOW_UDP:
        /* data will be passed via tap callback*/
        msg = register_tap_listener("udp_follow", &follow_info_,
                                    follow_filter.toUtf8().constData(),
                                    0, NULL, udp_queue_packet_data, NULL);
        if (msg) {
            QMessageBox::critical(this, "Error",
                               "Can't register udp_follow tap: %1",
                               msg->str);
            return false;
        }
        break;
    case FOLLOW_SSL:
        /* we got ssl so we can follow */
        msg = register_tap_listener("ssl", &follow_info_,
                                    follow_filter.toUtf8().constData(), 0,
                                    NULL, ssl_queue_packet_data, NULL);
        if (msg)
        {
            QMessageBox::critical(this, "Error",
                          "Can't register ssl tap: %1", msg->str);
            return false;
        }
        break;
    }

    /* Run the display filter so it goes in effect - even if it's the
       same as the previous display filter. */
    emit updateFilter(follow_filter, TRUE);

    switch (follow_type_)
    {
    case FOLLOW_TCP:

        break;
    case FOLLOW_UDP:
        remove_tap_listener(&follow_info_);
        break;
    case FOLLOW_SSL:
        remove_tap_listener(&follow_info_);
        break;
    }

    if (follow_type_ == FOLLOW_TCP)
    {
        /* Check whether we got any data written to the file. */
        if (empty_tcp_stream) {
            QMessageBox::warning(this, "Error",
                                 "The packets in the capture file for that stream have no data.");
            //ws_close(tmp_fd);
            ws_unlink(data_out_filename_.toUtf8().constData());
            data_out_filename_.clear();
            return false;
        }

        /* Go back to the top of the file and read the first tcp_stream_chunk
         * to ensure that the IP addresses and port numbers in the drop-down
         * list are tied to the correct lines displayed by follow_read_stream()
         * later on (which also reads from this file).  Close the file when
         * we're done.
         *
         * We read the data now, before we pop up a window, in case the
         * read fails.  We use the data later.
         */

        rewind(data_out_file);
        nchars=fread(&sc, 1, sizeof(sc), data_out_file);
        if (nchars != sizeof(sc)) {
            if (ferror(data_out_file)) {
                QMessageBox::warning(this, "Error",
                                     QString(tr("Could not read from temporary file %1: %2"))
                                     .arg(data_out_filename_)
                                     .arg(g_strerror(errno)));
            } else {
                QMessageBox::warning(this, "Error",
                                     QString(tr("Short read from temporary file %1: expected %2, got %3"))
                                     .arg(data_out_filename_)
                                     .arg((unsigned long)sizeof(sc))
                                     .arg((unsigned long)nchars));

            }
            //ws_close(tmp_fd);
            ws_unlink(data_out_filename_.toUtf8().constData());
            data_out_filename_.clear();
            return false;
        }
        fclose(data_out_file);
        data_out_file = NULL;
    }

    /* Stream to show */
    follow_stats(&stats);

    if (stats.is_ipv6) {
        struct e_in6_addr ipaddr;
        memcpy(&ipaddr, stats.ip_address[0], 16);
        hostname0 = get_hostname6(&ipaddr);
        memcpy(&ipaddr, stats.ip_address[1], 16);
        hostname1 = get_hostname6(&ipaddr);
    } else {
        guint32 ipaddr;
        memcpy(&ipaddr, stats.ip_address[0], 4);
        hostname0 = get_hostname(ipaddr);
        memcpy(&ipaddr, stats.ip_address[1], 4);
        hostname1 = get_hostname(ipaddr);
    }

    switch (follow_type_)
    {
    case FOLLOW_TCP:
        port0 = ep_tcp_port_to_display(stats.port[0]);
        port1 = ep_tcp_port_to_display(stats.port[1]);
        break;
    case FOLLOW_UDP:
        port0 = ep_udp_port_to_display(stats.port[0]);
        port1 = ep_udp_port_to_display(stats.port[1]);
        break;
    case FOLLOW_SSL:
        port0 = ep_tcp_port_to_display(stats.port[0]);
        port1 = ep_tcp_port_to_display(stats.port[1]);
        break;
    }

    follow_info_.is_ipv6 = stats.is_ipv6;

    if (follow_type_ == FOLLOW_TCP)
    {
        /* Host 0 --> Host 1 */
        if ((sc.src_port == stats.port[0]) &&
            ((stats.is_ipv6 && (memcmp(sc.src_addr, stats.ip_address[0], 16) == 0)) ||
             (!stats.is_ipv6 && (memcmp(sc.src_addr, stats.ip_address[0], 4) == 0)))) {
            server_to_client_string =
                    QString("%1:%2 %3 %4:%5 (%6)")
                    .arg(hostname0).arg(port0)
                    .arg(UTF8_RIGHTWARDS_ARROW)
                    .arg(hostname1).arg(port1)
                    .arg(gchar_free_to_qstring(format_size(
                                                   stats.bytes_written[0],
                                               format_size_unit_bytes|format_size_prefix_si)));
        } else {
            server_to_client_string =
                    QString("%1:%2 %3 %4:%5 (%6)")
                    .arg(hostname1).arg(port1)
                    .arg(UTF8_RIGHTWARDS_ARROW)
                    .arg(hostname0).arg(port0)
                    .arg(gchar_free_to_qstring(format_size(
                                                   stats.bytes_written[0],
                                               format_size_unit_bytes|format_size_prefix_si)));
        }

        /* Host 1 --> Host 0 */
        if ((sc.src_port == stats.port[1]) &&
            ((stats.is_ipv6 && (memcmp(sc.src_addr, stats.ip_address[1], 16) == 0)) ||
             (!stats.is_ipv6 && (memcmp(sc.src_addr, stats.ip_address[1], 4) == 0)))) {
            client_to_server_string =
                    QString("%1:%2 %3 %4:%5 (%6)")
                    .arg(hostname0).arg(port0)
                    .arg(UTF8_RIGHTWARDS_ARROW)
                    .arg(hostname1).arg(port1)
                    .arg(gchar_free_to_qstring(format_size(
                                                   stats.bytes_written[1],
                                               format_size_unit_bytes|format_size_prefix_si)));
        } else {
            client_to_server_string =
                    QString("%1:%2 %3 %4:%5 (%6)")
                    .arg(hostname1).arg(port1)
                    .arg(UTF8_RIGHTWARDS_ARROW)
                    .arg(hostname0).arg(port0)
                    .arg(gchar_free_to_qstring(format_size(
                                                   stats.bytes_written[1],
                                               format_size_unit_bytes|format_size_prefix_si)));
        }

    }
    else
    {
        if ((follow_info_.client_port == stats.port[0]) &&
            ((stats.is_ipv6 && (memcmp(follow_info_.client_ip.data, stats.ip_address[0], 16) == 0)) ||
             (!stats.is_ipv6 && (memcmp(follow_info_.client_ip.data, stats.ip_address[0], 4) == 0)))) {
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
        } else {
            server_to_client_string =
                    QString("%1:%2 %3 %4:%5 (%6)")
                    .arg(hostname1).arg(port1)
                    .arg(UTF8_RIGHTWARDS_ARROW)
                    .arg(hostname0).arg(port0)
                    .arg(gchar_free_to_qstring(format_size(
                                                   follow_info_.bytes_written[0],
                                               format_size_unit_bytes|format_size_prefix_si)));

            client_to_server_string =
                    QString("%1:%2 %3 %4:%5 (%6)")
                    .arg(hostname0).arg(port0)
                    .arg(UTF8_RIGHTWARDS_ARROW)
                    .arg(hostname1).arg(port1)
                    .arg(gchar_free_to_qstring(format_size(
                                                   follow_info_.bytes_written[1],
                                               format_size_unit_bytes|format_size_prefix_si)));
        }
    }

    /* Both Stream Directions */
    switch (follow_type_)
    {
    case FOLLOW_TCP:
        both_directions_string = QString("Entire conversation (%1)")
                .arg(gchar_free_to_qstring(format_size(
                                               stats.bytes_written[0] + stats.bytes_written[1],
                     format_size_unit_bytes|format_size_prefix_si)));
        this->setWindowTitle(QString("Follow TCP Stream (%1)").arg(follow_filter));
        break;
    case FOLLOW_UDP:
        both_directions_string = QString("Entire conversation (%1)")
                .arg(gchar_free_to_qstring(format_size(
                                               follow_info_.bytes_written[0] + follow_info_.bytes_written[1],
                     format_size_unit_bytes|format_size_prefix_si)));
        this->setWindowTitle(QString("Follow UDP Stream (%1)").arg(follow_filter));
        break;
    case FOLLOW_SSL:
        both_directions_string = QString("Entire conversation (%1)")
                .arg(gchar_free_to_qstring(format_size(
                                               follow_info_.bytes_written[0] + follow_info_.bytes_written[1],
                     format_size_unit_bytes|format_size_prefix_si)));
        this->setWindowTitle(QString("Follow SSL Stream (%1)").arg(follow_filter));
        break;
    }

    ui->cbDirections->clear();
    this->ui->cbDirections->addItem(both_directions_string);
    this->ui->cbDirections->addItem(client_to_server_string);
    this->ui->cbDirections->addItem(server_to_client_string);

    follow_stream();
    fillHintLabel(-1);

    data_out_file = NULL;

    return true;
}

#define FLT_BUF_SIZE 1024

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
FollowStreamDialog::follow_read_tcp_stream()
{
    FILE *data_out_fp;
    tcp_stream_chunk    sc;
    size_t              bcount;
    size_t              bytes_read;
    int                 iplen;
    guint8              client_addr[MAX_IPADDR_LEN];
    guint16             client_port = 0;
    gboolean            is_server;
    guint32             global_client_pos = 0, global_server_pos = 0;
    guint32             *global_pos;
    gboolean            skip;
    char                buffer[FLT_BUF_SIZE+1]; /* +1 to fix ws bug 1043 */
    size_t              nchars;
    frs_return_t        frs_return;

    iplen = (follow_info_.is_ipv6) ? 16 : 4;

    data_out_fp = ws_fopen(data_out_filename_.toUtf8().constData(), "rb");
    if (data_out_fp == NULL) {
        QMessageBox::critical(this, "Error",
                      "Could not open temporary file %1: %2", data_out_filename_,
                      g_strerror(errno));
        return FRS_OPEN_ERROR;
    }

    while ((nchars=fread(&sc, 1, sizeof(sc), data_out_fp))) {
        if (nchars != sizeof(sc)) {
            QMessageBox::critical(this, "Error",
                          QString(tr("Short read from temporary file %1: expected %2, got %3"))
                          .arg(data_out_filename_)
                          .arg(sizeof(sc))
                          .arg(nchars));
            fclose(data_out_fp);
            data_out_fp = NULL;
            return FRS_READ_ERROR;
        }
        if (client_port == 0) {
            memcpy(client_addr, sc.src_addr, iplen);
            client_port = sc.src_port;
        }
        skip = FALSE;
        if (memcmp(client_addr, sc.src_addr, iplen) == 0 &&
                client_port == sc.src_port) {
            is_server = FALSE;
            global_pos = &global_client_pos;
            if (follow_info_.show_stream == FROM_SERVER) {
                skip = TRUE;
            }
        } else {
            is_server = TRUE;
            global_pos = &global_server_pos;
            if (follow_info_.show_stream == FROM_CLIENT) {
                skip = TRUE;
            }
        }

        bytes_read = 0;
        while (bytes_read < sc.dlen) {
            bcount = ((sc.dlen-bytes_read) < FLT_BUF_SIZE) ? (sc.dlen-bytes_read) : FLT_BUF_SIZE;
            nchars = fread(buffer, 1, bcount, data_out_fp);
            if (nchars == 0)
                break;
            /* XXX - if we don't get "bcount" bytes, is that an error? */
            bytes_read += nchars;

            if (!skip)
            {
                frs_return = follow_show(buffer,
                                         nchars, is_server, sc.packet_num, global_pos);
                if(frs_return == FRS_PRINT_ERROR) {
                    fclose(data_out_fp);
                    data_out_fp = NULL;
                    return frs_return;
                }

            }
        }
    }

    if (ferror(data_out_fp)) {
        QMessageBox::critical(this, tr("Error reading temporary file"),
                           QString("%1: %2").arg(data_out_filename_).arg(g_strerror(errno)));
        fclose(data_out_fp);
        data_out_fp = NULL;
        return FRS_READ_ERROR;
    }

    fclose(data_out_fp);
    data_out_fp = NULL;
    return FRS_OK;
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
FollowStreamDialog::follow_read_udp_stream()
{
    guint32 global_client_pos = 0, global_server_pos = 0;
    guint32 *global_pos;
    gboolean skip;
    GList* cur;
    frs_return_t frs_return;
    follow_record_t *follow_record;
    char *buffer;

    for (cur = follow_info_.payload; cur; cur = g_list_next(cur)) {
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

        if (!skip) {
            buffer = (char *)g_memdup(follow_record->data->data,
                                      follow_record->data->len);

            frs_return = follow_show(
                        buffer,
                        follow_record->data->len,
                        follow_record->is_server,
                        follow_record->packet_num,
                        global_pos);
            g_free(buffer);
            if(frs_return == FRS_PRINT_ERROR)
                return frs_return;
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
