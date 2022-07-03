/* show_packet_bytes_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "show_packet_bytes_dialog.h"
#include <ui_show_packet_bytes_dialog.h>

#include "main_window.h"
#include "main_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include "epan/charsets.h"

#include "wsutil/utf8_entities.h"

#include <QAction>
#include <QClipboard>
#include <QImage>
#include <QJsonDocument>
#include <QKeyEvent>
#include <QMenu>
#include <QPrintDialog>
#include <QPrinter>
#include <QTextCodec>
#include <QTextStream>

// To do:
// - Add show as custom protocol in a Packet Details view
// - Use ByteViewText to ShowAsHexDump and supplementary view for custom protocol
// - Handle large data blocks

ShowPacketBytesDialog::ShowPacketBytesDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::ShowPacketBytesDialog),
    finfo_(cf.capFile()->finfo_selected),
    decode_as_(DecodeAsNone),
    show_as_(ShowAsASCII),
    use_regex_find_(false)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 2 / 3, parent.height() * 3 / 4);

    QString field_name = QString("%1 (%2)").arg(finfo_->hfinfo->name, finfo_->hfinfo->abbrev);
    setWindowSubtitle (field_name);

    hint_label_ = tr("Frame %1, %2, %Ln byte(s).", "", finfo_->length)
                     .arg(cf.capFile()->current_frame->num)
                     .arg(field_name);

    ui->tePacketBytes->installEventFilter(this);

    connect(ui->tePacketBytes, SIGNAL(showSelected(int,int)), this, SLOT(showSelected(int,int)));
    connect(ui->leFind, SIGNAL(useRegexFind(bool)), this, SLOT(useRegexFind(bool)));

    ui->cbDecodeAs->blockSignals(true);
    ui->cbDecodeAs->addItem(tr("None"), DecodeAsNone);
    ui->cbDecodeAs->addItem(tr("Base64"), DecodeAsBASE64);
    ui->cbDecodeAs->addItem(tr("Compressed"), DecodeAsCompressed);
    ui->cbDecodeAs->addItem(tr("Hex Digits"), DecodeAsHexDigits);
    ui->cbDecodeAs->addItem(tr("Quoted-Printable"), DecodeAsQuotedPrintable);
    ui->cbDecodeAs->addItem(tr("ROT13"), DecodeAsROT13);
    ui->cbDecodeAs->blockSignals(false);

    ui->cbShowAs->blockSignals(true);
    ui->cbShowAs->addItem(tr("ASCII"), ShowAsASCII);
    ui->cbShowAs->addItem(tr("ASCII & Control"), ShowAsASCIIandControl);
    ui->cbShowAs->addItem(tr("C Array"), ShowAsCArray);
    ui->cbShowAs->addItem(tr("EBCDIC"), ShowAsEBCDIC);
    ui->cbShowAs->addItem(tr("Hex Dump"), ShowAsHexDump);
    ui->cbShowAs->addItem(tr("HTML"), ShowAsHTML);
    ui->cbShowAs->addItem(tr("Image"), ShowAsImage);
    ui->cbShowAs->addItem(tr("JSON"), ShowAsJson);
    ui->cbShowAs->addItem(tr("Raw"), ShowAsRAW);
    ui->cbShowAs->addItem(tr("Rust Array"), ShowAsRustArray);
    // UTF-8 is guaranteed to exist as a QTextCodec
    ui->cbShowAs->addItem(tr("UTF-8"), ShowAsCodec);
    ui->cbShowAs->addItem(tr("YAML"), ShowAsYAML);
    ui->cbShowAs->setCurrentIndex(show_as_);
    ui->cbShowAs->blockSignals(false);

    ui->sbStart->setMinimum(0);
    ui->sbEnd->setMaximum(finfo_->length - 1);

    print_button_ = ui->buttonBox->addButton(tr("Print"), QDialogButtonBox::ActionRole);
    connect(print_button_, SIGNAL(clicked()), this, SLOT(printBytes()));

    copy_button_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect(copy_button_, SIGNAL(clicked()), this, SLOT(copyBytes()));

    save_as_button_ = ui->buttonBox->addButton(tr("Save as…"), QDialogButtonBox::ActionRole);
    connect(save_as_button_, SIGNAL(clicked()), this, SLOT(saveAs()));

    connect(ui->buttonBox, SIGNAL(helpRequested()), this, SLOT(helpButton()));

    setStartAndEnd(0, (finfo_->length - 1));
    updateFieldBytes(true);
}

ShowPacketBytesDialog::~ShowPacketBytesDialog()
{
    delete ui;
}

void ShowPacketBytesDialog::addCodecs(const QMap<QString, QTextCodec *> &codecMap)
{
    ui->cbShowAs->blockSignals(true);
    // Make the combobox respect max visible items?
    //ui->cbShowAs->setStyleSheet("QComboBox { combobox-popup: 0;}");
    ui->cbShowAs->insertSeparator(ui->cbShowAs->count());
    for (const auto &codec : qAsConst(codecMap)) {
        // This is already placed in the menu and handled separately
        if (codec->name() != "US-ASCII" && codec->name() != "UTF-8")
            ui->cbShowAs->addItem(tr(codec->name()), ShowAsCodec);
    }
    ui->cbShowAs->blockSignals(false);
}

void ShowPacketBytesDialog::showSelected(int start, int end)
{
    if (end == -1) {
        // end set to -1 means show all packet bytes
        setStartAndEnd(0, (finfo_->length - 1));
    } else {
        if (show_as_ == ShowAsRAW) {
            start /= 2;
            end = (end + 1) / 2;
        }
        setStartAndEnd(start_ + start, start_ + end - 1);
    }
    updateFieldBytes();
}

void ShowPacketBytesDialog::setStartAndEnd(int start, int end)
{
    start_ = start;
    end_ = end;

    ui->sbStart->blockSignals(true);
    ui->sbStart->setMaximum(end_);
    ui->sbStart->setValue(start_);
    ui->sbStart->blockSignals(false);

    ui->sbEnd->blockSignals(true);
    ui->sbEnd->setMinimum(start_);
    ui->sbEnd->setValue(end_);
    ui->sbEnd->blockSignals(false);

    updateHintLabel();
}

bool ShowPacketBytesDialog::enableShowSelected()
{
    // "Show Selected" only works when showing all bytes:
    // - DecodeAs must not alter the number of bytes in the buffer
    // - ShowAs must show all bytes in the buffer

    return (((decode_as_ == DecodeAsNone) ||
             (decode_as_ == DecodeAsROT13)) &&
            ((show_as_ == ShowAsASCII) ||
             (show_as_ == ShowAsASCIIandControl) ||
             (show_as_ == ShowAsEBCDIC) ||
             (show_as_ == ShowAsRAW)));
}

void ShowPacketBytesDialog::updateWidgets()
{
    WiresharkDialog::updateWidgets();
}

void ShowPacketBytesDialog::updateHintLabel()
{
    QString hint = hint_label_;

    if (start_ > 0 || end_ < (finfo_->length - 1)) {
        hint.append(" <span style=\"color: red\">" +
                    tr("Displaying %Ln byte(s).", "", end_ - start_ + 1) +
                    "</span>");
    }

    ui->hintLabel->setText("<small><i>" + hint + "</i></small>");
}

void ShowPacketBytesDialog::on_sbStart_valueChanged(int value)
{
    start_ = value;
    ui->sbEnd->setMinimum(value);

    updateHintLabel();
    updateFieldBytes();
}

void ShowPacketBytesDialog::on_sbEnd_valueChanged(int value)
{
    end_ = value;
    ui->sbStart->setMaximum(value);

    updateHintLabel();
    updateFieldBytes();
}

void ShowPacketBytesDialog::on_cbDecodeAs_currentIndexChanged(int idx)
{
    if (idx < 0) return;
    decode_as_ = static_cast<DecodeAsType>(ui->cbDecodeAs->itemData(idx).toInt());

    ui->tePacketBytes->setShowSelectedEnabled(enableShowSelected());

    updateFieldBytes();
}

void ShowPacketBytesDialog::on_cbShowAs_currentIndexChanged(int idx)
{
    if (idx < 0) return;
    show_as_ = static_cast<ShowAsType>(ui->cbShowAs->itemData(idx).toInt());

    ui->tePacketBytes->setShowSelectedEnabled(enableShowSelected());
    ui->lFind->setEnabled(true);
    ui->leFind->setEnabled(true);
    ui->bFind->setEnabled(true);
    print_button_->setEnabled(true);
    copy_button_->setEnabled(true);
    save_as_button_->setEnabled(true);

    updatePacketBytes();
}

void ShowPacketBytesDialog::useRegexFind(bool use_regex)
{
    use_regex_find_ = use_regex;
    if (use_regex_find_)
        ui->lFind->setText(tr("Regex Find:"));
    else
        ui->lFind->setText(tr("Find:"));
}

void ShowPacketBytesDialog::findText(bool go_back)
{
    if (ui->leFind->text().isEmpty()) return;

    bool found;
    if (use_regex_find_) {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 13, 0))
        QRegularExpression regex(ui->leFind->text(), QRegularExpression::UseUnicodePropertiesOption);
#else
        QRegExp regex(ui->leFind->text());
#endif
        found = ui->tePacketBytes->find(regex);
    } else {
        found = ui->tePacketBytes->find(ui->leFind->text());
    }

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
    {
        QByteArray ba(field_bytes_);
        sanitizeBuffer(ba, true);
        mainApp->clipboard()->setText(ba);
        break;
    }

    case ShowAsASCIIandControl:
    case ShowAsCArray:
    case ShowAsRustArray:
    case ShowAsEBCDIC:
    case ShowAsHexDump:
    case ShowAsJson:
    case ShowAsRAW:
    case ShowAsYAML:
        mainApp->clipboard()->setText(ui->tePacketBytes->toPlainText());
        break;

    case ShowAsHTML:
        mainApp->clipboard()->setText(ui->tePacketBytes->toHtml());
        break;

    case ShowAsImage:
        mainApp->clipboard()->setImage(image_);
        break;

    case ShowAsCodec:
        mainApp->clipboard()->setText(ui->tePacketBytes->toPlainText().toUtf8());
        break;
    }
}

void ShowPacketBytesDialog::saveAs()
{
    QString file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Selected Packet Bytes As…")));

    if (file_name.isEmpty())
        return;

    QFile::OpenMode open_mode = QFile::WriteOnly;
    switch (show_as_) {
    case ShowAsASCII:
    case ShowAsASCIIandControl:
    case ShowAsCArray:
    case ShowAsRustArray:
    // We always save as UTF-8, so set text mode as we would for UTF-8
    case ShowAsCodec:
    case ShowAsHexDump:
    case ShowAsJson:
    case ShowAsYAML:
    case ShowAsHTML:
        open_mode |= QFile::Text;
    default:
        break;
    }

    QFile file(file_name);
    file.open(open_mode);

    switch (show_as_) {

    case ShowAsASCII:
    {
        QByteArray ba(field_bytes_);
        sanitizeBuffer(ba, true);
        file.write(ba);
        break;
    }

    case ShowAsASCIIandControl:
    case ShowAsCArray:
    case ShowAsRustArray:
    case ShowAsEBCDIC:
    case ShowAsHexDump:
    case ShowAsJson:
    case ShowAsYAML:
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

    case ShowAsCodec:
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
    mainApp->helpTopicAction(HELP_SHOW_PACKET_BYTES_DIALOG);
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

void ShowPacketBytesDialog::sanitizeBuffer(QByteArray &ba, bool keep_CR)
{
    for (int i = 0; i < ba.length(); i++) {
        if (ba[i] == '\n' || (keep_CR && ba[i] == '\r'))
            // Keep LF and optionally CR
            continue;

        if (ba[i] == '\0' || g_ascii_isspace(ba[i])) {
            ba[i] = ' ';
        } else if (!g_ascii_isprint(ba[i])) {
            ba.replace(i, 1, UTF8_MIDDLE_DOT);
            i += sizeof(UTF8_MIDDLE_DOT) - 2;
        }
    }
}

void ShowPacketBytesDialog::symbolizeBuffer(QByteArray &ba)
{
    for (int i = 0; i < ba.length(); i++) {
        if ((ba[i] < '\0' || ba[i] >= ' ') && ba[i] != (char)0x7f && !g_ascii_isprint(ba[i])) {
            ba.replace(i, 1, UTF8_MIDDLE_DOT);
            i += sizeof(UTF8_MIDDLE_DOT) - 2;
        }
    }

    QByteArray symbol(UTF8_SYMBOL_FOR_NULL);
    for (char i = 0; i < ' '; i++) {
        ba.replace(i, symbol);
        symbol[2] = symbol[2] + 1;
    }
    symbol[2] = symbol[2] + 1;      // Skip SP
    ba.replace((char)0x7f, symbol); // DEL
}

QByteArray ShowPacketBytesDialog::decodeQuotedPrintable(const guint8 *bytes, int length)
{
    QByteArray ba;

    for (int i = 0; i < length; i++) {
        if (bytes[i] == '=' && i + 1 < length) {
            if (bytes[i+1] == '\n') {
                i++;     // Soft line break LF
            } else if (bytes[i+1] == '\r' && i + 2 < length && bytes[i+2] == '\n') {
                i += 2;  // Soft line break CRLF
            } else if (g_ascii_isxdigit(bytes[i+1]) && i + 2 < length && g_ascii_isxdigit(bytes[i+2])) {
                ba.append(QByteArray::fromHex(QByteArray((const char *)&bytes[i+1], 2)));
                i += 2;  // Valid Quoted-Printable sequence
            } else {
                // Illegal Quoted-Printable, just add byte
                ba.append(bytes[i]);
            }
        } else {
            ba.append(bytes[i]);
        }
    }

    return ba;
}

void ShowPacketBytesDialog::rot13(QByteArray &ba)
{
    for (int i = 0; i < ba.length(); i++) {
        gchar upper = g_ascii_toupper(ba[i]);
        if (upper >= 'A' && upper <= 'M') ba[i] = ba[i] + 13;
        else if (upper >= 'N' && upper <= 'Z') ba[i] = ba[i] - 13;
    }
}

void ShowPacketBytesDialog::updateFieldBytes(bool initialization)
{
    int start = finfo_->start + start_;
    int length = end_ - start_ + 1;
    const guint8 *bytes;
    gsize new_length = 0;

    if (!finfo_->ds_tvb)
        return;

    switch (decode_as_) {

    case DecodeAsNone:
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
        field_bytes_ = QByteArray((const char *)bytes, length);
        break;

    case DecodeAsBASE64:
    {
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
        field_bytes_ = QByteArray((const char *)bytes, length);
        if (field_bytes_.size() > 1) {
            g_base64_decode_inplace(field_bytes_.data(), &new_length);
        }
        field_bytes_.resize((int)new_length);
        break;
    }

    case DecodeAsCompressed:
    {
        tvbuff *uncompr_tvb = tvb_uncompress(finfo_->ds_tvb, start, length);
        if (uncompr_tvb) {
            bytes = tvb_get_ptr(uncompr_tvb, 0, -1);
            field_bytes_ = QByteArray((const char *)bytes, tvb_reported_length(uncompr_tvb));
            tvb_free(uncompr_tvb);
        } else {
            field_bytes_.clear();
        }
        break;
    }

    case DecodeAsHexDigits:
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
        field_bytes_ = QByteArray::fromHex(QByteArray::fromRawData((const char *)bytes, length));
        break;

    case DecodeAsQuotedPrintable:
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
        field_bytes_ = decodeQuotedPrintable(bytes, length);
        break;

    case DecodeAsROT13:
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
        field_bytes_ = QByteArray((const char *)bytes, length);
        rot13(field_bytes_);
        break;
    }

    // Try loading as image at startup
    if (initialization && image_.loadFromData(field_bytes_)) {
        show_as_ = ShowAsImage;
        ui->cbShowAs->blockSignals(true);
        ui->cbShowAs->setCurrentIndex(ShowAsImage);
        ui->cbShowAs->blockSignals(false);
    }

    updatePacketBytes();
}

void ShowPacketBytesDialog::updatePacketBytes(void)
{
    static const gchar hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    ui->tePacketBytes->clear();
    ui->tePacketBytes->setCurrentFont(mainApp->monospaceFont());

    switch (show_as_) {

    case ShowAsASCII:
    {
        QByteArray ba(field_bytes_);
        sanitizeBuffer(ba, false);
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setPlainText(ba);
        break;
    }

    case ShowAsASCIIandControl:
    {
        QByteArray ba(field_bytes_);
        symbolizeBuffer(ba);
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setPlainText(ba);
        break;
    }

    case ShowAsCArray:
    {
        int pos = 0, len = static_cast<int>(field_bytes_.length());
        QString text("char packet_bytes[] = {\n");

        while (pos < len) {
            gchar hexbuf[256];
            char *cur = hexbuf;
            int i;

            *cur++ = ' ';
            for (i = 0; i < 8 && pos + i < len; i++) {
                // Prepend entries with " 0x"
                *cur++ = ' ';
                *cur++ = '0';
                *cur++ = 'x';
                *cur++ = hexchars[(field_bytes_[pos + i] & 0xf0) >> 4];
                *cur++ = hexchars[field_bytes_[pos + i] & 0x0f];

                // Delimit array entries with a comma
                if (pos + i + 1 < len)
                    *cur++ = ',';
            }

            pos += i;
            *cur++ = '\n';
            *cur = 0;

            text.append(hexbuf);
        }

        text.append("};\n");
        ui->tePacketBytes->setLineWrapMode(QTextEdit::NoWrap);
        ui->tePacketBytes->setPlainText(text);
        break;
    }

    case ShowAsRustArray:
    {
        int pos = 0, len = static_cast<int>(field_bytes_.length());
        QString text("let packet_bytes: [u8; _] = [\n");

        while (pos < len) {
            gchar hexbuf[256];
            char *cur = hexbuf;
            int i;

            *cur++ = ' ';
            for (i = 0; i < 8 && pos + i < len; i++) {
                // Prepend entries with " 0x"
                *cur++ = ' ';
                *cur++ = '0';
                *cur++ = 'x';
                *cur++ = hexchars[(field_bytes_[pos + i] & 0xf0) >> 4];
                *cur++ = hexchars[field_bytes_[pos + i] & 0x0f];

                // Delimit array entries with a comma
                if (pos + i + 1 < len)
                    *cur++ = ',';
            }

            pos += i;
            *cur++ = '\n';
            *cur = 0;

            text.append(hexbuf);
        }

        text.append("];\n");
        ui->tePacketBytes->setLineWrapMode(QTextEdit::NoWrap);
        ui->tePacketBytes->setPlainText(text);
        break;
    }

    case ShowAsCodec:
    {
        // The QTextCodecs docs say that there's a flag to cause invalid
        // characters to be replaced with null. It's unclear what happens
        // in the default case; it might depend on the codec though it
        // seems that in practice replacement characters are used.
        QTextCodec *codec = QTextCodec::codecForName(ui->cbShowAs->currentText().toUtf8());
        QByteArray ba(field_bytes_);
        QString decoded = codec->toUnicode(ba);
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setPlainText(decoded);
        break;
    }

    case ShowAsEBCDIC:
    {
        QByteArray ba(field_bytes_);
        EBCDIC_to_ASCII((guint8*)ba.data(), static_cast<int>(ba.length()));
        sanitizeBuffer(ba, false);
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setPlainText(ba);
        break;
    }

    case ShowAsHexDump:
    {
        int pos = 0, len = static_cast<int>(field_bytes_.length());
        // Use 16-bit offset if there are <= 65536 bytes, 32-bit offset if there are more
        unsigned int offset_chars = (len - 1 <= 0xFFFF) ? 4 : 8;
        QString text;
        text.reserve((len / 16) * 80);

        while (pos < len) {
            char hexbuf[256];
            char *cur = hexbuf;
            int i;

            // Dump offset
            cur += snprintf(cur, 20, "%0*X  ", offset_chars, pos);

            // Dump bytes as hex
            for (i = 0; i < 16 && pos + i < len; i++) {
                *cur++ = hexchars[(field_bytes_[pos + i] & 0xf0) >> 4];
                *cur++ = hexchars[field_bytes_[pos + i] & 0x0f];
                *cur++ = ' ';
                if (i == 7)
                    *cur++ = ' ';
            }

            while (cur < hexbuf + offset_chars + 53)
                *cur++ = ' '; // Fill it up with space to ascii column

            // Dump bytes as text
            for (i = 0; i < 16 && pos + i < len; i++) {
                if (g_ascii_isprint(field_bytes_[pos + i])) {
                    *cur++ = field_bytes_[pos + i];
                } else {
                    memcpy(cur, UTF8_MIDDLE_DOT, sizeof(UTF8_MIDDLE_DOT) - 1);
                    cur += sizeof(UTF8_MIDDLE_DOT) - 1;
                }
                if (i == 7)
                    *cur++ = ' ';
            }

            pos += i;
            *cur++ = '\n';
            *cur = 0;

            text.append(hexbuf);
        }

        ui->tePacketBytes->setLineWrapMode(QTextEdit::NoWrap);
        ui->tePacketBytes->setPlainText(text);
        break;
    }

    case ShowAsHTML:
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setHtml(field_bytes_);
        break;

    case ShowAsImage:
    {
        ui->lFind->setEnabled(false);
        ui->leFind->setEnabled(false);
        ui->bFind->setEnabled(false);

        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        if (image_.loadFromData(field_bytes_)) {
            ui->tePacketBytes->textCursor().insertImage(image_);
        }

        print_button_->setEnabled(!image_.isNull());
        copy_button_->setEnabled(!image_.isNull());
        save_as_button_->setEnabled(!image_.isNull());
        break;
    }

    case ShowAsJson:
        ui->tePacketBytes->setLineWrapMode(QTextEdit::NoWrap);
        ui->tePacketBytes->setPlainText(QJsonDocument::fromJson(field_bytes_).toJson());
        break;

    case ShowAsYAML:
    {
        const int base64_raw_len = 57; // Encodes to 76 bytes, common in RFCs
        int pos = 0, len = static_cast<int>(field_bytes_.length());
        QString text("# Packet Bytes: !!binary |\n");

        while (pos < len) {
            QByteArray base64_data = field_bytes_.mid(pos, base64_raw_len);
            pos += base64_data.length();
            /* XXX: GCC 12.1 has a bogus stringop-overread warning using the Qt
             * conversions from QByteArray to QString at -O2 and higher due to
             * computing a branch that will never be taken.
             */
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_OFF(stringop-overread)
#endif
            text.append("  " + base64_data.toBase64() + "\n");
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_ON(stringop-overread)
#endif
        }

        ui->tePacketBytes->setLineWrapMode(QTextEdit::NoWrap);
        ui->tePacketBytes->setPlainText(text);
        break;
    }

    case ShowAsRAW:
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setPlainText(field_bytes_.toHex());
        break;
    }
}

void ShowPacketBytesDialog::captureFileClosing()
{
    finfo_ = NULL;  // This will invalidate the source backend

    WiresharkDialog::captureFileClosing();
}

void ShowPacketBytesDialog::captureFileClosed()
{
    // We have lost the source backend and must disable all functions
    // for manipulating decoding and displayed range.

    ui->tePacketBytes->setMenusEnabled(false);
    ui->lDecodeAs->setEnabled(false);
    ui->cbDecodeAs->setEnabled(false);
    ui->lStart->setEnabled(false);
    ui->sbStart->setEnabled(false);
    ui->lEnd->setEnabled(false);
    ui->sbEnd->setEnabled(false);

    WiresharkDialog::captureFileClosed();
}

void ShowPacketBytesTextEdit::contextMenuEvent(QContextMenuEvent *event)
{
    QMenu *menu = createStandardContextMenu();
    QAction *action;

    menu->setAttribute(Qt::WA_DeleteOnClose);
    menu->addSeparator();

    action = menu->addAction(tr("Show Selected"));
    action->setEnabled(menus_enabled_ && show_selected_enabled_ && textCursor().hasSelection());
    connect(action, SIGNAL(triggered()), this, SLOT(showSelected()));

    action = menu->addAction(tr("Show All"));
    action->setEnabled(menus_enabled_);
    connect(action, SIGNAL(triggered()), this, SLOT(showAll()));

    menu->popup(event->globalPos());
}

void ShowPacketBytesTextEdit::showSelected()
{
    QTextCursor cursor = textCursor();
    int start = cursor.selectionStart();
    int end = cursor.selectionEnd();

    emit showSelected(start, end);
}

void ShowPacketBytesTextEdit::showAll()
{
    emit showSelected(0, -1);
}
