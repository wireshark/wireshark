/* follow_stream_dialog.cpp
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

#include "follow_stream_dialog.h"
#include "ui_follow_stream_dialog.h"

#include "main_window.h"
#include "wireshark_application.h"

#include "epan/follow.h"
#include "epan/dissectors/packet-ipv6.h"
#include "epan/prefs.h"
#include "epan/charsets.h"
#include "epan/epan_dissect.h"
#include "epan/ipproto.h"
#include "epan/tap.h"

#include "file.h"
#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "ui/utf8_entities.h"
#include "wsutil/tempfile.h"
#include "wsutil/file_util.h"
#include "ws_symbol_export.h"

#include "color_utils.h"
#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include "globals.h"
#include "file.h"

#include "version_info.h"

#include "ui/follow.h"

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#include <QKeyEvent>
#include <QMessageBox>
#include <QPrintDialog>
#include <QPrinter>
#include <QTextEdit>
#include <QTextStream>

FollowStreamDialog::FollowStreamDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FollowStreamDialog)
{
    follow_info = NULL;
    ui->setupUi(this);

    ui->teStreamContent->installEventFilter(this);

    connect(ui->buttonBox, SIGNAL(helpRequested()), this, SLOT(HelpButton()));

    bFilterOut = ui->buttonBox->addButton(tr("Hide this stream"), QDialogButtonBox::ActionRole);
    connect(bFilterOut, SIGNAL(clicked()), this, SLOT(FilterOut()));

    bPrint = ui->buttonBox->addButton(tr("Print"), QDialogButtonBox::ActionRole);
    connect(bPrint, SIGNAL(clicked()), this, SLOT(Print()));

    bSave = ui->buttonBox->addButton(tr("Save as..."), QDialogButtonBox::ActionRole);
    connect(bSave, SIGNAL(clicked()), this, SLOT(SaveAs()));

    save_as = false;
}

void FollowStreamDialog::Print()
{
#ifndef QT_NO_PRINTER
    QPrinter printer(QPrinter::HighResolution);
    QPrintDialog dialog(&printer, this);
    if ( dialog.exec() == QDialog::Accepted)
        ui->teStreamContent->print(&printer);
#endif
}

void FollowStreamDialog::FindText(bool go_back)
{
    if (ui->leFind->text().isEmpty()) return;

    bool found = ui->teStreamContent->find(ui->leFind->text());

    if (found) {
        ui->teStreamContent->setFocus();
    } else if (go_back) {
        ui->teStreamContent->moveCursor(QTextCursor::Start);
        FindText(false);
    }
}

void FollowStreamDialog::SaveAs()
{
    QString file_name = QFileDialog::getSaveFileName(this, "Wireshark: Save stream content as");
    file.setFileName(file_name);
    file.open( QIODevice::WriteOnly );
    QTextStream out(&file);

    save_as = true;

    follow_read_stream();

    if (follow_info->show_type != SHOW_RAW)
    {
        out << ui->teStreamContent->toPlainText();
    }

    save_as = false;

    file.close();
}

void FollowStreamDialog::HelpButton()
{
    wsApp->helpTopicAction(HELP_FOLLOW_STREAM_DIALOG);
}

void FollowStreamDialog::FilterOut()
{

    QString filter = QString(follow_info->filter_out_filter);
    emit updateFilter(filter, TRUE);

    this->close();
}

void FollowStreamDialog::on_cbDirections_currentIndexChanged(int index)
{
    if (!follow_info)
        return;

    switch(index)
    {
    case 0 :
        follow_info->show_stream = BOTH_HOSTS;
        break;
    case 1 :
        follow_info->show_stream = FROM_SERVER;
        break;
    case 2 :
        follow_info->show_stream = FROM_CLIENT;
        break;
    default:
        return;
    }

    follow_read_stream();
}

void FollowStreamDialog::on_cbCharset_currentIndexChanged(int index)
{
    switch (index)
    {
    case 0:
        follow_info->show_type = SHOW_ASCII;
        break;

    case 1:
        follow_info->show_type = SHOW_EBCDIC;
        break;

    case 2:
        follow_info->show_type = SHOW_CARRAY;
        break;

    case 3:
        follow_info->show_type = SHOW_HEXDUMP;
        break;

    case 4:
        follow_info->show_type = SHOW_RAW;
        break;

    default:
        return;
    }

    follow_read_stream();
}

void FollowStreamDialog::on_bFind_clicked()
{
    FindText();
}

void FollowStreamDialog::on_leFind_returnPressed()
{
    FindText();
}

void FollowStreamDialog::on_buttonBox_rejected()
{
    hide();
}

frs_return_t
FollowStreamDialog::follow_read_stream()
{
    ui->teStreamContent->clear();

    switch(follow_info->follow_type) {

    case FOLLOW_TCP :
        return follow_read_tcp_stream();

    case FOLLOW_UDP :
        return follow_read_udp_stream();

    case FOLLOW_SSL :
        return follow_read_ssl_stream();

    default :
        g_assert_not_reached();
        return (frs_return_t)0;
    }
}

//Copy from ui/gtk/follow_udp.c
static int
udp_queue_packet_data(void *tapdata, packet_info *pinfo,
                      epan_dissect_t *edt, const void *data)
{
    Q_UNUSED(edt)

    follow_record_t *follow_record;
    follow_info_t *follow_info = (follow_info_t *)tapdata;
    tvbuff_t *next_tvb = (tvbuff_t *)data;

    follow_record = g_new(follow_record_t,1);

    follow_record->data = g_byte_array_sized_new(tvb_length(next_tvb));
    follow_record->data = g_byte_array_append(follow_record->data,
                                              tvb_get_ptr(next_tvb, 0, -1),
                                              tvb_length(next_tvb));

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
    Q_UNUSED(edt)

    follow_info_t *      follow_info = (follow_info_t*) tapdata;
    SslDecryptedRecord * rec = NULL;
    SslDataInfo *        appl_data = NULL;
    int                  proto_ssl = GPOINTER_TO_INT(ssl);
    SslPacketInfo *      pi = NULL;
    show_stream_t        from = FROM_CLIENT;

    /* Skip packets without decrypted payload data. */
    pi = (SslPacketInfo*) p_get_proto_data(pinfo->fd, proto_ssl, 0);
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
    guint32      server_packet_count = 0;
    guint32      client_packet_count = 0;
    guint32 *    global_pos;
    GList *      cur;
    frs_return_t frs_return;

    for (cur = follow_info->payload; cur; cur = g_list_next(cur)) {
        SslDecryptedRecord * rec = (SslDecryptedRecord*) cur->data;
        gboolean             include_rec = FALSE;

        if (rec->is_from_server) {
            global_pos = &global_server_pos;
            include_rec = (follow_info->show_stream == BOTH_HOSTS) ||
                    (follow_info->show_stream == FROM_SERVER);
        } else {
            global_pos = &global_client_pos;
            include_rec = (follow_info->show_stream == BOTH_HOSTS) ||
                    (follow_info->show_stream == FROM_CLIENT);
        }

        if (include_rec) {
            size_t nchars = rec->data.data_len;
            gchar *buffer = (gchar *)g_memdup(rec->data.data, (guint) nchars);

            frs_return = follow_show(buffer, nchars,
                                     rec->is_from_server, global_pos,
                                     &server_packet_count, &client_packet_count);
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

    follow_info->show_type = SHOW_RAW;
    follow_info->show_stream = BOTH_HOSTS;

    /* Stream to show */
    follow_stats(&stats);

    follow_info->is_ipv6 = stats.is_ipv6;

    follow_read_stream();
    ui->teStreamContent->moveCursor(QTextCursor::Start);
}




void FollowStreamDialog::add_text(char *buffer, size_t nchars, gboolean is_from_server)
{
    size_t i;
    QString buf;
    gchar *str;

    if (save_as == true)
    {
        //FILE *fh = (FILE *)arg;
        size_t nwritten;
        int FileDescriptor = file.handle();
        FILE* fh = fdopen(dup(FileDescriptor), "wb");
        nwritten = fwrite(buffer, 1, nchars, fh);
        fclose(fh);
        return;
        if (nwritten != nchars)
            return;
    }

    QColor tagserver_fg = ColorUtils::fromColorT(prefs.st_server_fg);
    QColor tagserver_bg = ColorUtils::fromColorT(prefs.st_server_bg);

    QColor tagclient_fg = ColorUtils::fromColorT(prefs.st_client_fg);
    QColor tagclient_bg = ColorUtils::fromColorT(prefs.st_client_bg);

    for (i = 0; i < nchars; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r')
            continue;
        if (! isprint((guchar)buffer[i])) {
            buffer[i] = '.';
        }
    }

    /* convert unterminated char array to a zero terminated string */
    str = (char *)g_malloc(nchars + 1);
    memcpy(str, buffer, nchars);
    str[nchars] = 0;
    buf = QString(str);
    g_free(str);

    ui->teStreamContent->moveCursor(QTextCursor::End);
    ui->teStreamContent->setCurrentFont(wsApp->monospaceFont());
    if (is_from_server)
    {
        ui->teStreamContent->setTextColor(tagserver_fg);
        ui->teStreamContent->setTextBackgroundColor(tagserver_bg);
        ui->teStreamContent->insertPlainText(buf);
    }
    else
    {
        ui->teStreamContent->setTextColor(tagclient_fg);
        ui->teStreamContent->setTextBackgroundColor(tagclient_bg);
        ui->teStreamContent->insertPlainText(buf);
    }
}

// The following keyboard shortcuts should work (although
// they may not work consistently depending on focus):
// / (slash), Ctrl-F - Focus and highlight the search box
// Ctrl-G, Ctrl-N, F3 - Find next
// Should we make it so that typing any text starts searching?
bool FollowStreamDialog::eventFilter(QObject *obj, QEvent *event)
{
    Q_UNUSED(obj)
    if (ui->teStreamContent->hasFocus() && event->type() == QEvent::KeyPress) {
        ui->leFind->setFocus();
        QKeyEvent *keyEvent = static_cast<QKeyEvent*>(event);
        if (keyEvent->matches(QKeySequence::Find)) {
            return true;
        } else if (keyEvent->matches(QKeySequence::FindNext)) {
            FindText();
            return true;
        }
    }

    return false;
}

void FollowStreamDialog::keyPressEvent(QKeyEvent *event)
{
    if (ui->leFind->hasFocus()) {
        if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            FindText();
            return;
        }
    } else {
        if (event->key() == Qt::Key_Slash || event->matches(QKeySequence::Find)) {
            ui->leFind->setFocus();
            ui->leFind->selectAll();
        }
        return;
    }

    if (event->key() == Qt::Key_F3 || event->key() == Qt::Key_N && (event->modifiers() & Qt::ControlModifier)) {
        FindText();
        return;
    }

    QDialog::keyPressEvent(event);
}

void FollowStreamDialog::closeEvent(QCloseEvent *event)
{
    Q_UNUSED(event)
    hide();
}


frs_return_t
FollowStreamDialog::follow_show(char *buffer, size_t nchars, gboolean is_from_server,
                                guint32 *global_pos, guint32 *server_packet_count,
                                guint32 *client_packet_count)
{
    gchar initbuf[256];
    guint32 current_pos;
    static const gchar hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    switch (follow_info->show_type) {

    case SHOW_EBCDIC:
        /* If our native arch is ASCII, call: */
        EBCDIC_to_ASCII((guint8*)buffer, (guint) nchars);
        add_text(buffer, nchars, is_from_server);
        break;

    case SHOW_ASCII:
        /* If our native arch is EBCDIC, call:
         * ASCII_TO_EBCDIC(buffer, nchars);
         */
        add_text(buffer, nchars, is_from_server);
        break;

    case SHOW_RAW:
        /* Don't translate, no matter what the native arch
         * is.
         */
        add_text(buffer, nchars, is_from_server);
        break;

    case SHOW_HEXDUMP:
        current_pos = 0;
        while (current_pos < nchars) {
            gchar hexbuf[256];
            int i;
            gchar *cur = hexbuf, *ascii_start;

            /* is_from_server indentation : put 4 spaces at the
             * beginning of the string */
            /* XXX - We might want to prepend each line with "C" or "S" instead. */
            if (is_from_server && follow_info->show_stream == BOTH_HOSTS) {
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
                        (isprint((guchar)buffer[current_pos + i]) ?
                            buffer[current_pos + i] : '.' );
                if (i == 7) {
                    *cur++ = ' ';
                }
            }
            current_pos += i;
            (*global_pos) += i;
            *cur++ = '\n';
            *cur = 0;

            add_text(hexbuf, strlen(hexbuf), is_from_server);
        }
        break;

    case SHOW_CARRAY:
        current_pos = 0;
        g_snprintf(initbuf, sizeof(initbuf), "char peer%d_%d[] = {\n",
                   is_from_server ? 1 : 0,
                   is_from_server ? (*server_packet_count)++ : (*client_packet_count)++);
        add_text(initbuf, strlen(initbuf), is_from_server);

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
            add_text(hexbuf, strlen(hexbuf), is_from_server);
        }
        break;
    }

    return FRS_OK;
}



bool FollowStreamDialog::Follow(QString previous_filter_, follow_type_t type)
{
    int                 tmp_fd;
    gchar               *follow_filter;
    const gchar         *previous_filter = previous_filter_.toStdString().c_str();
    int                 filter_out_filter_len, previous_filter_len;
    const char          *hostname0 = NULL, *hostname1 = NULL;
    char                *port0 = NULL, *port1 = NULL;
    gchar               *server_to_client_string = NULL;
    gchar               *client_to_server_string = NULL;
    gchar               *both_directions_string = NULL;
    follow_stats_t      stats;
    tcp_stream_chunk    sc;
    size_t              nchars;
    gchar               *data_out_filename;
    GString *           msg;

    if (cfile.edt == NULL)
    {
        QMessageBox::warning(this, tr("Error following stream."), tr("Capture file invalid."));
        return false;
    }

    switch (type)
    {
    case FOLLOW_TCP:
        if (cfile.edt->pi.ipproto != IP_PROTO_TCP) {
            QMessageBox::warning(this, tr("Error following stream."), tr("Please make sure you have a TCP packet selected."));
            return false;
        }
        break;
    case FOLLOW_UDP:
        if (cfile.edt->pi.ipproto != IP_PROTO_UDP) {
            QMessageBox::warning(this, tr("Error following stream."), tr("Please make sure you have a UDP packet selected."));
            return false;
        }
        break;
    case FOLLOW_SSL:
        /* we got ssl so we can follow */
        if (!epan_dissect_packet_contains_field(cfile.edt, "ssl")) {
            QMessageBox::critical(this, tr("Error following stream"),
                               tr("Please make sure you have an SSL packet selected."));
            return false;
        }
        break;
    }

    follow_info = g_new0(follow_info_t, 1);
    follow_info->follow_type = type;

    if (type == FOLLOW_TCP || type == FOLLOW_SSL)
    {
        /* Create a new filter that matches all packets in the TCP stream,
           and set the display filter entry accordingly */
        reset_tcp_reassembly();
    }

    follow_filter = build_follow_filter(&cfile.edt->pi);
    if (!follow_filter) {
        QMessageBox::warning(this,
                             tr("Error creating filter for this stream."),
                             tr("A transport or network layer header is needed."));
        g_free(follow_info);
        return false;
    }

    if (type == FOLLOW_TCP || type == FOLLOW_SSL)
    {
        /* Create a temporary file into which to dump the reassembled data
           from the TCP stream, and set "data_out_file" to refer to it, so
           that the TCP code will write to it.

           XXX - it might be nicer to just have the TCP code directly
           append stuff to the text widget for the TCP stream window,
           if we can arrange that said window not pop up until we're
           done. */
        tmp_fd = create_tempfile(&data_out_filename, "follow");
        follow_info->data_out_filename = g_strdup(data_out_filename);

        if (tmp_fd == -1) {
            QMessageBox::warning(this, "Error",
                                 "Could not create temporary file %1: %2",
                                 follow_info->data_out_filename, g_strerror(errno));
            g_free(follow_info->data_out_filename);
            g_free(follow_info);
            g_free(follow_filter);
            return false;
        }

        data_out_file = fdopen(tmp_fd, "w+b");
        if (data_out_file == NULL) {
            QMessageBox::warning(this, "Error",
                                 "Could not create temporary file %1: %2",
                                 follow_info->data_out_filename, g_strerror(errno));
            //ws_close(tmp_fd);
            ws_unlink(follow_info->data_out_filename);
            g_free(follow_info->data_out_filename);
            g_free(follow_info);
            g_free(follow_filter);
            return false;
        }
    }


    /* allocate our new filter. API claims g_malloc terminates program on failure */
    /* my calc for max alloc needed is really +10 but when did a few extra bytes hurt ? */
    previous_filter_len = previous_filter?(int)strlen(previous_filter):0;
    filter_out_filter_len = (int)(strlen(follow_filter) + strlen(previous_filter) + 16);
    follow_info->filter_out_filter = (gchar *)g_malloc(filter_out_filter_len);

    /* append the negation */
    if(previous_filter_len) {
        g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
                   "%s and !(%s)", previous_filter, follow_filter);
    }
    else
    {
        g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
                   "!(%s)", follow_filter);
    }

    switch (type)
    {
    case FOLLOW_TCP:

        break;
    case FOLLOW_UDP:
        /* data will be passed via tap callback*/
        msg = register_tap_listener("udp_follow", follow_info, follow_filter,
                                    0, NULL, udp_queue_packet_data, NULL);
        if (msg) {
            QMessageBox::critical(this, "Error",
                               "Can't register udp_follow tap: %1",
                               msg->str);
            g_free(follow_info->filter_out_filter);
            g_free(follow_info);
            g_free(follow_filter);
            return false;
        }
        break;
    case FOLLOW_SSL:
        /* we got ssl so we can follow */
        msg = register_tap_listener("ssl", follow_info, follow_filter, 0,
                                    NULL, ssl_queue_packet_data, NULL);
        if (msg)
        {
            QMessageBox::critical(this, "Error",
                          "Can't register ssl tap: %1", msg->str);
            g_free(follow_info->filter_out_filter);
            g_free(follow_info);
            g_free(follow_filter);
            return false;
        }
        break;
    }



    /* Run the display filter so it goes in effect - even if it's the
       same as the previous display filter. */
    QString filter = QString(follow_filter);
    emit updateFilter(filter, TRUE);

    switch (type)
    {
    case FOLLOW_TCP:

        break;
    case FOLLOW_UDP:
        remove_tap_listener(follow_info);
        break;
    case FOLLOW_SSL:
        remove_tap_listener(follow_info);
        break;
    }


    if (type == FOLLOW_TCP)
    {
        /* Check whether we got any data written to the file. */
        if (empty_tcp_stream) {
            QMessageBox::warning(this, "Error",
                                 "The packets in the capture file for that stream have no data.");
            //ws_close(tmp_fd);
            ws_unlink(follow_info->data_out_filename);
            g_free(follow_info->data_out_filename);
            g_free(follow_info->filter_out_filter);
            g_free(follow_info);
            return false;
        }

        rewind(data_out_file);
        nchars=fread(&sc, 1, sizeof(sc), data_out_file);
        if (nchars != sizeof(sc)) {
            if (ferror(data_out_file)) {
                QMessageBox::warning(this, "Error",
                                     QString(tr("Could not read from temporary file %1: %2"))
                                     .arg(follow_info->data_out_filename)
                                     .arg(g_strerror(errno)));
            } else {
                QMessageBox::warning(this, "Error",
                                     QString(tr("Short read from temporary file %1: expected %2, got %3"))
                                     .arg(follow_info->data_out_filename)
                                     .arg((unsigned long)sizeof(sc))
                                     .arg((unsigned long)nchars));

            }
            //ws_close(tmp_fd);
            ws_unlink(follow_info->data_out_filename);
            g_free(follow_info->data_out_filename);
            g_free(follow_info->filter_out_filter);
            g_free(follow_info);
            return false;
        }
        fclose(data_out_file);
    }

    /* Stream to show */
    follow_stats(&stats);

    if (stats.is_ipv6) {
        struct e_in6_addr ipaddr;
        memcpy(&ipaddr, stats.ip_address[0], 16);
        hostname0 = get_hostname6(&ipaddr);
        memcpy(&ipaddr, (type == FOLLOW_TCP) ? stats.ip_address[1] : stats.ip_address[0], 16);
        hostname1 = get_hostname6(&ipaddr);
    } else {
        guint32 ipaddr;
        memcpy(&ipaddr, stats.ip_address[0], 4);
        hostname0 = get_hostname(ipaddr);
        memcpy(&ipaddr, stats.ip_address[1], 4);
        hostname1 = get_hostname(ipaddr);
    }

    switch (type)
    {
    case FOLLOW_TCP:
        port0 = get_tcp_port(stats.port[0]);
        port1 = get_tcp_port(stats.port[1]);
        break;
    case FOLLOW_UDP:
        port0 = get_udp_port(stats.port[0]);
        port1 = get_udp_port(stats.port[1]);
        break;
    case FOLLOW_SSL:
        port0 = get_tcp_port(stats.port[0]);
        port1 = get_tcp_port(stats.port[1]);
        break;
    }

    follow_info->is_ipv6 = stats.is_ipv6;

    if (type == FOLLOW_TCP)
    {
        /* Host 0 --> Host 1 */
        if(sc.src_port == stats.port[0]) {
            server_to_client_string =
                    g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                                    hostname0, port0,
                                    hostname1, port1,
                                    stats.bytes_written[0]);
        } else {
            server_to_client_string =
                    g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                                    hostname1, port1,
                                    hostname0,port0,
                                    stats.bytes_written[0]);
        }

        /* Host 1 --> Host 0 */
        if(sc.src_port == stats.port[1]) {
            client_to_server_string =
                g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                                hostname0, port0,
                                hostname1, port1,
                                stats.bytes_written[1]);
        } else {
            client_to_server_string =
                g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                                hostname1, port1,
                                hostname0, port0,
                                stats.bytes_written[1]);
        }

    }
    else
    {
        if(follow_info->client_port == stats.port[0]) {
            server_to_client_string =
                    g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                                    hostname0, port0,
                                    hostname1, port1,
                                    follow_info->bytes_written[0]);

            client_to_server_string =
                    g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                                    hostname1, port1,
                                    hostname0, port0,
                                    follow_info->bytes_written[1]);
        } else {
            server_to_client_string =
                    g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                                    hostname1, port1,
                                    hostname0, port0,
                                    follow_info->bytes_written[0]);

            client_to_server_string =
                    g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                                    hostname0, port0,
                                    hostname1, port1,
                                    follow_info->bytes_written[1]);
        }
    }

    /* Both Stream Directions */
    switch (type)
    {
    case FOLLOW_TCP:
        both_directions_string = g_strdup_printf("Entire conversation (%u bytes)", stats.bytes_written[0] + stats.bytes_written[1]);
        this->setWindowTitle(QString("Follow TCP Stream (%1)").arg(follow_filter));
        break;
    case FOLLOW_UDP:
        both_directions_string = g_strdup_printf("Entire conversation (%u bytes)", follow_info->bytes_written[0] + follow_info->bytes_written[1]);
        this->setWindowTitle(QString("Follow UDP Stream (%1)").arg(follow_filter));
        break;
    case FOLLOW_SSL:
        both_directions_string = g_strdup_printf("Entire conversation (%u bytes)", follow_info->bytes_written[0] + follow_info->bytes_written[1]);
        this->setWindowTitle(QString("Follow SSL Stream (%1)").arg(follow_filter));
        break;
    }


    ui->cbDirections->clear();
    this->ui->cbDirections->addItem(QString(both_directions_string));
    this->ui->cbDirections->addItem(QString(client_to_server_string));
    this->ui->cbDirections->addItem(QString(server_to_client_string));


    follow_stream();

    /* Free the filter string, as we're done with it. */
    g_free(follow_filter);

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
    FILE *data_out_file;
    tcp_stream_chunk    sc;
    size_t              bcount;
    size_t              bytes_read;
    int                 iplen;
    guint8              client_addr[MAX_IPADDR_LEN];
    guint16             client_port = 0;
    gboolean            is_server;
    guint32             global_client_pos = 0, global_server_pos = 0;
    guint32             server_packet_count = 0;
    guint32             client_packet_count = 0;
    guint32             *global_pos;
    gboolean            skip;
    char                buffer[FLT_BUF_SIZE+1]; /* +1 to fix ws bug 1043 */
    size_t              nchars;
    frs_return_t        frs_return;
#ifdef HAVE_LIBZ
    char                outbuffer[FLT_BUF_SIZE+1];
    z_stream            strm;
    gboolean            gunzip = FALSE;
    int                 ret;
#endif


    iplen = (follow_info->is_ipv6) ? 16 : 4;

    data_out_file = ws_fopen(follow_info->data_out_filename, "rb");
    if (data_out_file == NULL) {
        QMessageBox::critical(this, "Error",
                      "Could not open temporary file %1: %2", follow_info->data_out_filename,
                      g_strerror(errno));
        return FRS_OPEN_ERROR;
    }

    while ((nchars=fread(&sc, 1, sizeof(sc), data_out_file))) {
        if (nchars != sizeof(sc)) {
            QMessageBox::critical(this, "Error",
                          QString(tr("Short read from temporary file %1: expected %2, got %3"))
                          .arg(follow_info->data_out_filename)
                          .arg(sizeof(sc))
                          .arg(nchars));
            fclose(data_out_file);
            data_out_file = NULL;
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
            if (follow_info->show_stream == FROM_SERVER) {
                skip = TRUE;
            }
        }
        else {
            is_server = TRUE;
            global_pos = &global_server_pos;
            if (follow_info->show_stream == FROM_CLIENT) {
                skip = TRUE;
            }
        }

        bytes_read = 0;
        while (bytes_read < sc.dlen) {
            bcount = ((sc.dlen-bytes_read) < FLT_BUF_SIZE) ? (sc.dlen-bytes_read) : FLT_BUF_SIZE;
            nchars = fread(buffer, 1, bcount, data_out_file);
            if (nchars == 0)
                break;
            /* XXX - if we don't get "bcount" bytes, is that an error? */
            bytes_read += nchars;

#ifdef HAVE_LIBZ
            /* If we are on the first packet of an HTTP response, check if data is gzip
            * compressed.
            */
            if (is_server && bytes_read == nchars && !memcmp(buffer, "HTTP", 4)) {
                size_t header_len;
                gunzip = parse_http_header(buffer, nchars, &header_len);
                if (gunzip) {
                    /* show header (which is not gzipped)*/
                    frs_return = follow_show(buffer,
                                             header_len, is_server, global_pos,
                                             &server_packet_count, &client_packet_count);
                    if (frs_return == FRS_PRINT_ERROR) {
                        fclose(data_out_file);
                        data_out_file = NULL;
                        return frs_return;
                    }

                    /* init gz_stream*/
                    strm.next_in = Z_NULL;
                    strm.avail_in = 0;
                    strm.next_out = Z_NULL;
                    strm.avail_out = 0;
                    strm.zalloc = Z_NULL;
                    strm.zfree = Z_NULL;
                    strm.opaque = Z_NULL;
                    ret = inflateInit2(&strm, MAX_WBITS+16);
                    if (ret != Z_OK) {
                        fclose(data_out_file);
                        data_out_file = NULL;
                        return FRS_READ_ERROR;
                    }

                    /* prepare remainder of buffer to be inflated below */
                    memmove(buffer, buffer+header_len, nchars-header_len);
                    nchars -= header_len;
                }
            }

            if (gunzip) {
                strm.next_in = (Bytef*)buffer;
                strm.avail_in = (int)nchars;
                do {
                    strm.next_out = (Bytef*)outbuffer;
                    strm.avail_out = FLT_BUF_SIZE;

                    ret = inflate(&strm, Z_NO_FLUSH);
                    if (ret < 0 || ret == Z_NEED_DICT) {
                        inflateEnd(&strm);
                        fclose(data_out_file);
                        data_out_file = NULL;
                        return FRS_READ_ERROR;
                    } else if (ret == Z_STREAM_END) {
                        inflateEnd(&strm);
                    }

                    frs_return = follow_show(outbuffer,
                                             FLT_BUF_SIZE-strm.avail_out, is_server,
                                             global_pos,
                                             &server_packet_count,
                                             &client_packet_count);
                    if(frs_return == FRS_PRINT_ERROR) {
                        inflateEnd(&strm);
                        fclose(data_out_file);
                        data_out_file = NULL;
                        return frs_return;
                    }
                } while (strm.avail_out == 0);
                skip = TRUE;
            }
#endif
            if (!skip)
            {
                frs_return = follow_show(buffer,
                                         nchars, is_server, global_pos,
                                         &server_packet_count,
                                         &client_packet_count);
                if(frs_return == FRS_PRINT_ERROR) {
                    fclose(data_out_file);
                    data_out_file = NULL;
                    return frs_return;
                }

            }
        }
    }

    if (ferror(data_out_file)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Error reading temporary file %s: %s", follow_info->data_out_filename,
                      g_strerror(errno));
        fclose(data_out_file);
        data_out_file = NULL;
        return FRS_READ_ERROR;
    }

    fclose(data_out_file);
    data_out_file = NULL;
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
    guint32 server_packet_count = 0;
    guint32 client_packet_count = 0;
    guint32 *global_pos;
    gboolean skip;
    GList* cur;
    frs_return_t frs_return;
    follow_record_t *follow_record;
    char *buffer;


    for (cur = follow_info->payload; cur; cur = g_list_next(cur)) {
        follow_record = (follow_record_t *)cur->data;
        skip = FALSE;
        if (!follow_record->is_server) {
            global_pos = &global_client_pos;
            if(follow_info->show_stream == FROM_SERVER) {
                skip = TRUE;
            }
        } else {
            global_pos = &global_server_pos;
            if (follow_info->show_stream == FROM_CLIENT) {
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
                        global_pos,
                        &server_packet_count,
                        &client_packet_count);
            g_free(buffer);
            if(frs_return == FRS_PRINT_ERROR)
                return frs_return;
        }
    }

    return FRS_OK;
}


FollowStreamDialog::~FollowStreamDialog()
{
    delete ui;
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
