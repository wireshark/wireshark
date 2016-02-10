/* show_packet_bytes_dialog.cpp
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

#include "show_packet_bytes_dialog.h"
#include <ui_show_packet_bytes_dialog.h>

#include "main_window.h"
#include "wireshark_application.h"

#include "epan/charsets.h"
#include <wsutil/utf8_entities.h>

#include <QImage>
#include <QKeyEvent>
#include <QPrintDialog>
#include <QPrinter>
#include <QTextStream>

// To do:
// - Add show as custom protocol in a Packet Details view
// - Add show as PDF or handle PDF as Image
// - Add decode from BASE64
// - Use ByteViewText to ShowAsHexDump and supplementary view for custom protocol
// - Handle large data blocks

ShowPacketBytesDialog::ShowPacketBytesDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::ShowPacketBytesDialog),
    show_as_(ShowAsASCII)
{
    ui->setupUi(this);

    field_info *finfo = cf.capFile()->finfo_selected;
    QString field_name = QString("%1 (%2)").arg(finfo->hfinfo->name, finfo->hfinfo->abbrev);
    setWindowSubtitle (field_name);

    const guint8 *bytes = tvb_get_ptr(finfo->ds_tvb, 0, -1) + finfo->start;
    field_bytes_ = QByteArray((const char *)bytes, finfo->length);

    QString hint = tr("Frame %1, %2, %Ln byte(s).", "", finfo->length)
                      .arg(cf.capFile()->current_frame->num)
                      .arg(field_name);
    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);

    // Try loading as image
    if (image_.loadFromData(field_bytes_)) {
        show_as_ = ShowAsImage;
    }

    ui->tePacketBytes->installEventFilter(this);

    // XXX Use recent settings instead
    resize(parent.width() * 2 / 3, parent.height());

    ui->cbShowAs->blockSignals(true);
    ui->cbShowAs->addItem(tr("ASCII"), ShowAsASCII);
    ui->cbShowAs->addItem(tr("EBCDIC"), ShowAsEBCDIC);
    ui->cbShowAs->addItem(tr("Hex Dump"), ShowAsHexDump);
    ui->cbShowAs->addItem(tr("HTML"), ShowAsHTML);
    ui->cbShowAs->addItem(tr("Image"), ShowAsImage);
    ui->cbShowAs->addItem(tr("ISO 8859-1"), ShowAsISO8859_1);
    ui->cbShowAs->addItem(tr("Raw"), ShowAsRAW);
    ui->cbShowAs->addItem(tr("UTF-8"), ShowAsUTF8);
    ui->cbShowAs->setCurrentIndex(show_as_);
    ui->cbShowAs->blockSignals(false);

    print_button_ = ui->buttonBox->addButton(tr("Print"), QDialogButtonBox::ActionRole);
    connect(print_button_, SIGNAL(clicked()), this, SLOT(printBytes()));

    copy_button_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect(copy_button_, SIGNAL(clicked()), this, SLOT(copyBytes()));

    save_as_button_ = ui->buttonBox->addButton(tr("Save as" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ActionRole);
    connect(save_as_button_, SIGNAL(clicked()), this, SLOT(saveAs()));

    connect(ui->buttonBox, SIGNAL(helpRequested()), this, SLOT(helpButton()));
    connect(&cap_file_, SIGNAL(captureFileClosing()), this, SLOT(captureFileClosing()));

    updatePacketBytes();
}

ShowPacketBytesDialog::~ShowPacketBytesDialog()
{
    delete ui;
}

void ShowPacketBytesDialog::updateWidgets()
{
    WiresharkDialog::updateWidgets();
}

void ShowPacketBytesDialog::on_cbShowAs_currentIndexChanged(int idx)
{
    if (idx < 0) return;
    show_as_ = static_cast<ShowAsType>(ui->cbShowAs->itemData(idx).toInt());

    ui->lFind->setEnabled(true);
    ui->leFind->setEnabled(true);
    ui->bFind->setEnabled(true);
    print_button_->setEnabled(true);
    copy_button_->setEnabled(true);
    save_as_button_->setEnabled(true);

    updatePacketBytes();
}

void ShowPacketBytesDialog::findText(bool go_back)
{
    if (ui->leFind->text().isEmpty()) return;

    bool found = ui->tePacketBytes->find(ui->leFind->text());

    if (found) {
        ui->tePacketBytes->setFocus();
    } else if (go_back) {
        ui->tePacketBytes->moveCursor(QTextCursor::Start);
        findText(false);
    }
}

void ShowPacketBytesDialog::printBytes()
{
#ifndef QT_NO_PRINTER
    QPrinter printer(QPrinter::HighResolution);
    QPrintDialog dialog(&printer, this);
    if (dialog.exec() == QDialog::Accepted)
        ui->tePacketBytes->print(&printer);
#endif
}

void ShowPacketBytesDialog::copyBytes()
{
    switch (show_as_) {

    case ShowAsASCII:
    case ShowAsEBCDIC:
    case ShowAsHexDump:
    case ShowAsISO8859_1:
    case ShowAsRAW:
        wsApp->clipboard()->setText(ui->tePacketBytes->toPlainText());
        break;

    case ShowAsHTML:
        wsApp->clipboard()->setText(ui->tePacketBytes->toHtml());
        break;

    case ShowAsImage:
        wsApp->clipboard()->setImage(image_);
        break;

    case ShowAsUTF8:
        wsApp->clipboard()->setText(ui->tePacketBytes->toPlainText().toUtf8());
        break;
    }
}

void ShowPacketBytesDialog::saveAs()
{
    QString file_name = QFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Selected Packet Bytes As" UTF8_HORIZONTAL_ELLIPSIS)));

    if (file_name.isEmpty())
        return;

    QFile file(file_name);
    file.open(QIODevice::WriteOnly);

    switch (show_as_) {

    case ShowAsASCII:
    case ShowAsEBCDIC:
    case ShowAsHexDump:
    case ShowAsISO8859_1:
    {
        QTextStream out(&file);
        out << ui->tePacketBytes->toPlainText();
        break;
    }

    case ShowAsHTML:
    {
        QTextStream out(&file);
        out << ui->tePacketBytes->toHtml();
        break;
    }

    case ShowAsUTF8:
    {
        QTextStream out(&file);
        out << ui->tePacketBytes->toPlainText().toUtf8();
        break;
    }

    case ShowAsImage:
    case ShowAsRAW:
        file.write(field_bytes_);
        break;
    }

    file.close();
}

void ShowPacketBytesDialog::helpButton()
{
    wsApp->helpTopicAction(HELP_SHOW_PACKET_BYTES_DIALOG);
}

void ShowPacketBytesDialog::on_bFind_clicked()
{
    findText();
}

void ShowPacketBytesDialog::on_leFind_returnPressed()
{
    findText();
}

// Not sure why we have to do this manually.
void ShowPacketBytesDialog::on_buttonBox_rejected()
{
    WiresharkDialog::reject();
}

// The following keyboard shortcuts should work (although
// they may not work consistently depending on focus):
// / (slash), Ctrl-F - Focus and highlight the search box
// Ctrl-G, Ctrl-N, F3 - Find next
// Should we make it so that typing any text starts searching?
bool ShowPacketBytesDialog::eventFilter(QObject *, QEvent *event)
{
    if (ui->tePacketBytes->hasFocus() && event->type() == QEvent::KeyPress) {
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

void ShowPacketBytesDialog::keyPressEvent(QKeyEvent *event)
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

static inline void sanitize_buffer(QByteArray &ba)
{
    for (int i = 0; i < ba.length(); i++) {
        if (!g_ascii_isspace(ba[i]) && !g_ascii_isprint(ba[i])) {
            ba[i] = '.';
        }
    }
}

void ShowPacketBytesDialog::updatePacketBytes(void)
{
    ui->tePacketBytes->clear();
    ui->tePacketBytes->setCurrentFont(wsApp->monospaceFont());
    ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);

    switch (show_as_) {

    case ShowAsASCII:
    {
        QByteArray ba(field_bytes_);
        sanitize_buffer(ba);
        ui->tePacketBytes->setPlainText(ba);
        break;
    }

    case ShowAsEBCDIC:
    {
        QByteArray ba(field_bytes_);
        EBCDIC_to_ASCII((guint8*)ba.data(), ba.length());
        sanitize_buffer(ba);
        ui->tePacketBytes->setPlainText(ba);
        break;
    }

    case ShowAsHexDump:
    {
        static const gchar hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
        int pos = 0;

        while (pos < field_bytes_.length()) {
            char hexbuf[256];
            char *cur = hexbuf;
            int i;

            // Dump offset
            cur += g_snprintf(cur, 20, "%08X  ", pos);

            // Dump bytes as hex
            for (i = 0; i < 16 && pos + i < field_bytes_.length(); i++) {
                *cur++ = hexchars[(field_bytes_[pos + i] & 0xf0) >> 4];
                *cur++ = hexchars[field_bytes_[pos + i] & 0x0f];
                *cur++ = ' ';
                if (i == 7)
                    *cur++ = ' ';
            }

            while (cur < hexbuf + 61)
                *cur++ = ' '; // Fill it up with space to column 61

            // Dump bytes as text
            for (i = 0; i < 16 && pos + i < field_bytes_.length(); i++) {
                if (g_ascii_isprint(field_bytes_[pos + i]))
                    *cur++ = field_bytes_[pos + i];
                else
                    *cur++ = '.';
                if (i == 7)
                    *cur++ = ' ';
            }
            pos += i;
            *cur++ = '\n';
            *cur = 0;

            ui->tePacketBytes->insertPlainText(hexbuf);
        }
        ui->tePacketBytes->setLineWrapMode(QTextEdit::NoWrap);
        break;
    }

    case ShowAsHTML:
        ui->tePacketBytes->setHtml(field_bytes_);
        break;

    case ShowAsImage:
    {
        ui->lFind->setEnabled(false);
        ui->leFind->setEnabled(false);
        ui->bFind->setEnabled(false);

        if (!image_.isNull()) {
            ui->tePacketBytes->textCursor().insertImage(image_);
        } else {
            print_button_->setEnabled(false);
            copy_button_->setEnabled(false);
            save_as_button_->setEnabled(false);
        }
        break;
    }

    case ShowAsISO8859_1:
    {
        guint8 *bytes = get_8859_1_string(NULL, (const guint8 *)field_bytes_.constData(), field_bytes_.length());
        ui->tePacketBytes->setPlainText((const char *)bytes);
        wmem_free (NULL, bytes);
        break;
    }

    case ShowAsUTF8:
    {
        // The QString docs say that invalid characters will be replaced with
        // replacement characters or removed. It would be nice if we could
        // explicitly choose one or the other.
        QString utf8 = QString::fromUtf8(field_bytes_);
        ui->tePacketBytes->setPlainText(utf8);
        break;
    }

    case ShowAsRAW:
        ui->tePacketBytes->setPlainText(field_bytes_.toHex());
        break;
    }
}

void ShowPacketBytesDialog::captureFileClosing()
{
    WiresharkDialog::captureFileClosing();
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
