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
#include "ui/recent.h"

#include "epan/strutil.h"

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

Q_DECLARE_METATYPE(bytes_show_type)
Q_DECLARE_METATYPE(bytes_decode_type)

ShowPacketBytesDialog::ShowPacketBytesDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::ShowPacketBytesDialog),
    finfo_(cf.capFile()->finfo_selected),
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
    ui->cbDecodeAs->addItem(tr("Percent-Encoding"), DecodeAsPercentEncoding);
    ui->cbDecodeAs->addItem(tr("Quoted-Printable"), DecodeAsQuotedPrintable);
    ui->cbDecodeAs->addItem(tr("ROT13"), DecodeAsROT13);
    ui->cbDecodeAs->setCurrentIndex(ui->cbDecodeAs->findData(recent.gui_show_bytes_decode));
    ui->cbDecodeAs->blockSignals(false);

    ui->cbShowAs->blockSignals(true);
    ui->cbShowAs->addItem(tr("ASCII"), SHOW_ASCII);
    ui->cbShowAs->addItem(tr("ASCII & Control"), SHOW_ASCII_CONTROL);
    ui->cbShowAs->addItem(tr("C Array"), SHOW_CARRAY);
    ui->cbShowAs->addItem(tr("EBCDIC"), SHOW_EBCDIC);
    ui->cbShowAs->addItem(tr("Hex Dump"), SHOW_HEXDUMP);
    ui->cbShowAs->addItem(tr("HTML"), SHOW_HTML);
    ui->cbShowAs->addItem(tr("Image"), SHOW_IMAGE);
    ui->cbShowAs->addItem(tr("JSON"), SHOW_JSON);
    ui->cbShowAs->addItem(tr("Raw"), SHOW_RAW);
    ui->cbShowAs->addItem(tr("Rust Array"), SHOW_RUSTARRAY);
    // UTF-8 is guaranteed to exist as a QTextCodec
    ui->cbShowAs->addItem(tr("UTF-8"), SHOW_CODEC);
    ui->cbShowAs->addItem(tr("YAML"), SHOW_YAML);
    ui->cbShowAs->setCurrentIndex(ui->cbShowAs->findData(recent.gui_show_bytes_show));
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
    for (const auto &codec : codecMap) {
        // This is already placed in the menu and handled separately
        if (codec->name() != "US-ASCII" && codec->name() != "UTF-8")
            ui->cbShowAs->addItem(tr(codec->name()), SHOW_CODEC);
    }
    ui->cbShowAs->blockSignals(false);
}

void ShowPacketBytesDialog::showSelected(int start, int end)
{
    if (end == -1) {
        // end set to -1 means show all packet bytes
        setStartAndEnd(0, (finfo_->length - 1));
    } else {
        if (recent.gui_show_bytes_show == SHOW_RAW) {
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

    return (((recent.gui_show_bytes_decode == DecodeAsNone) ||
             (recent.gui_show_bytes_decode == DecodeAsROT13)) &&
            ((recent.gui_show_bytes_show == SHOW_ASCII) ||
             (recent.gui_show_bytes_show == SHOW_ASCII_CONTROL) ||
             (recent.gui_show_bytes_show == SHOW_EBCDIC) ||
             (recent.gui_show_bytes_show == SHOW_RAW)));
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
                    tr("Using %Ln byte(s).", "", end_ - start_ + 1) +
                    "</span>");
    }

    if (!decode_as_name_.isEmpty()) {
        hint.append(" " + tr("Decoded as %1.").arg(decode_as_name_));
    }

    ui->hintLabel->setText("<small><i>" + hint + "</i></small>");
}

void ShowPacketBytesDialog::on_sbStart_valueChanged(int value)
{
    start_ = value;
    ui->sbEnd->setMinimum(value);

    updateFieldBytes();
}

void ShowPacketBytesDialog::on_sbEnd_valueChanged(int value)
{
    end_ = value;
    ui->sbStart->setMaximum(value);

    updateFieldBytes();
}

void ShowPacketBytesDialog::on_cbDecodeAs_currentIndexChanged(int idx)
{
    if (idx < 0) return;
    recent.gui_show_bytes_decode = ui->cbDecodeAs->currentData().value<bytes_decode_type>();

    ui->tePacketBytes->setShowSelectedEnabled(enableShowSelected());

    updateFieldBytes();
}

void ShowPacketBytesDialog::on_cbShowAs_currentIndexChanged(int idx)
{
    if (idx < 0) return;
    recent.gui_show_bytes_show = ui->cbShowAs->currentData().value<bytes_show_type>();

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

// This only calls itself with go_back false, so never recurses more than once.
// NOLINTNEXTLINE(misc-no-recursion)
void ShowPacketBytesDialog::findText(bool go_back)
{
    if (ui->leFind->text().isEmpty()) return;

    bool found;

    QTextDocument::FindFlags options;
    if (ui->caseCheckBox->isChecked()) {
        options |= QTextDocument::FindCaseSensitively;
    }
    if (use_regex_find_) {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 13, 0))
        // https://bugreports.qt.io/browse/QTBUG-88721
        // QPlainTextEdit::find() searches case-insensitively unless
        // QTextDocument::FindCaseSensitively is explicitly given.
        // This *does* apply to QRegularExpression (overriding
        // CaseInsensitiveOption), but not QRegExp.
        //
        // QRegularExpression and QRegExp do not support Perl's /i, but
        // the former at least does support the mode modifiers (?i) and
        // (?-i), which can override QTextDocument::FindCaseSensitively.
        //
        // To make matters worse, while the QTextDocument::find() documentation
        // is correct, QPlainTextEdit::find() claims that QRegularExpression
        // works like QRegExp, which is incorrect.
        QRegularExpression regex(ui->leFind->text(), QRegularExpression::UseUnicodePropertiesOption);
#else
        QRegExp regex(ui->leFind->text(), (options & QTextDocument::FindCaseSensitively) ? Qt::CaseSensitive : Qt::CaseInsensitive);
#endif
        found = ui->tePacketBytes->find(regex, std::move(options));
    } else {
        found = ui->tePacketBytes->find(ui->leFind->text(), std::move(options));
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
    switch (recent.gui_show_bytes_show) {

    case SHOW_ASCII:
    {
        QByteArray ba(field_bytes_);
        sanitizeBuffer(ba, true);
        mainApp->clipboard()->setText(ba);
        break;
    }

    case SHOW_ASCII_CONTROL:
    case SHOW_CARRAY:
    case SHOW_RUSTARRAY:
    case SHOW_EBCDIC:
    case SHOW_HEXDUMP:
    case SHOW_JSON:
    case SHOW_RAW:
    case SHOW_YAML:
        mainApp->clipboard()->setText(ui->tePacketBytes->toPlainText());
        break;

    case SHOW_HTML:
        mainApp->clipboard()->setText(ui->tePacketBytes->toHtml());
        break;

    case SHOW_IMAGE:
        mainApp->clipboard()->setImage(image_);
        break;

    case SHOW_CODEC:
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
    switch (recent.gui_show_bytes_show) {
    case SHOW_ASCII:
    case SHOW_ASCII_CONTROL:
    case SHOW_CARRAY:
    case SHOW_RUSTARRAY:
    case SHOW_EBCDIC:
    // We always save as UTF-8, so set text mode as we would for UTF-8
    case SHOW_CODEC:
    case SHOW_HEXDUMP:
    case SHOW_JSON:
    case SHOW_YAML:
    case SHOW_HTML:
        open_mode |= QFile::Text;
    default:
        break;
    }

    QFile file(file_name);
    file.open(open_mode);

    switch (recent.gui_show_bytes_show) {

    case SHOW_ASCII:
    {
        QByteArray ba(field_bytes_);
        sanitizeBuffer(ba, true);
        file.write(ba);
        break;
    }

    case SHOW_ASCII_CONTROL:
    case SHOW_CARRAY:
    case SHOW_RUSTARRAY:
    case SHOW_EBCDIC:
    case SHOW_HEXDUMP:
    case SHOW_JSON:
    case SHOW_YAML:
    {
        QTextStream out(&file);
        out << ui->tePacketBytes->toPlainText();
        break;
    }

    case SHOW_HTML:
    {
        QTextStream out(&file);
        out << ui->tePacketBytes->toHtml();
        break;
    }

    case SHOW_CODEC:
    {
        QTextStream out(&file);
        out << ui->tePacketBytes->toPlainText().toUtf8();
        break;
    }

    case SHOW_IMAGE:
    case SHOW_RAW:
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
    // Replace all octets that don't correspond to an ASCII
    // character with MIDDLE DOT.  An octet corresponds to an
    // ASCII character iff the 0x80 bit isn't set in its
    // value; if char is signed (which it is *not* guaranteed
    // to be; it is, for example, unsigned on non-Apple ARM
    // platforms), sign-extension won't affect that bit, so
    // simply testing the 0x80 bit suffices on all platforms.
    for (int i = 0; i < ba.length(); i++) {
        if (ba[i] & 0x80) {
            ba.replace(i, 1, UTF8_MIDDLE_DOT);
            i += sizeof(UTF8_MIDDLE_DOT) - 2;
        }
    }

    // Replace all control characters (NUL through US, i.e. [0, ' '),
    // and DEL, i.e. 0x7f) with the code point for the symbol for that
    // character, i.e. the character's abbreviation in small letters.
    //
    // The UTF-8 encodings for those code points are all three octets
    // long, from 0xe2 0x90 0x80 through 0xe2 0x90 0xa1, so we initialize
    // a QByteArray with the octets for the symbol for NUL and, for
    // each of the octets from 0x00 through 0x1f, replace all
    // occurrences of that value with that sequence, and then add 1 to
    // the last octet of the sequence to get the symbol for the next
    // value and continue.
    //
    QByteArray symbol(UTF8_SYMBOL_FOR_NULL);
    for (char i = 0; i < ' '; i++) {
    	// Replace all occurrences of that value with that symbol.
        ba.replace(i, symbol);
        // Get the symbol for the next value.
        symbol[2] = symbol[2] + 1;
    }
    // symbol now has the UTF-8 for the symbol for SP, as that follows
    // the symbol for US; skip it - the next code point is for the
    // symbol for DEL.
    symbol[2] = symbol[2] + 1;
    ba.replace((char)0x7f, symbol); // DEL
}

QByteArray ShowPacketBytesDialog::decodeQuotedPrintable(const uint8_t *bytes, int length)
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
        char upper = g_ascii_toupper(ba[i]);
        if (upper >= 'A' && upper <= 'M') ba[i] = ba[i] + 13;
        else if (upper >= 'N' && upper <= 'Z') ba[i] = ba[i] - 13;
    }
}

void ShowPacketBytesDialog::updateFieldBytes(bool initialization)
{
    int start = finfo_->start + start_;
    int length = end_ - start_ + 1;
    const uint8_t *bytes;

    if (!finfo_->ds_tvb)
        return;

    decode_as_name_.clear();

    switch (recent.gui_show_bytes_decode) {

    case DecodeAsNone:
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
        field_bytes_ = QByteArray((const char *)bytes, length);
        break;

    case DecodeAsBASE64:
    {
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
        QByteArray ba = QByteArray::fromRawData((const char *)bytes, length);
        if (ba.contains('-') || ba.contains('_')) {
            field_bytes_ = QByteArray::fromBase64(ba, QByteArray::Base64UrlEncoding);
            decode_as_name_ = "base64url";
        } else {
            field_bytes_ = QByteArray::fromBase64(ba, QByteArray::Base64Encoding);
            decode_as_name_ = "base64";
        }
        break;
    }

    case DecodeAsCompressed:
    {
        static const QList<uncompress_list_t> tvb_uncompress_list = {
            { "lz77", tvb_uncompress_lz77 },
            { "lz77huff", tvb_uncompress_lz77huff },
            { "lznt1", tvb_uncompress_lznt1 },
            { "snappy", tvb_uncompress_snappy },
            { "zlib", tvb_uncompress_zlib },
            { "zstd", tvb_uncompress_zstd },
        };
        tvbuff_t *uncompr_tvb = NULL;

        for (auto &tvb_uncompress : tvb_uncompress_list) {
            uncompr_tvb = tvb_uncompress.function(finfo_->ds_tvb, start, length);
            if (uncompr_tvb && tvb_reported_length(uncompr_tvb) > 0) {
                bytes = tvb_get_ptr(uncompr_tvb, 0, -1);
                field_bytes_ = QByteArray((const char *)bytes, tvb_reported_length(uncompr_tvb));
                decode_as_name_ = tr("compressed %1").arg(tvb_uncompress.name);
                tvb_free(uncompr_tvb);
                break;
            }
        }
        if (!uncompr_tvb) {
            field_bytes_.clear();
        }
        break;
    }

    case DecodeAsHexDigits:
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
        field_bytes_ = QByteArray::fromHex(QByteArray::fromRawData((const char *)bytes, length));
        break;

    case DecodeAsPercentEncoding:
    {
        bytes = tvb_get_ptr(finfo_->ds_tvb, start, -1);
#if GLIB_CHECK_VERSION(2, 66, 0)
        GBytes *ba = g_uri_unescape_bytes((const char*)bytes, length, NULL, NULL);
        if (ba != NULL) {
            size_t size;
            const char* data = (const char *)g_bytes_unref_to_data(ba, &size);
            field_bytes_ = QByteArray(data, (int)size);
        }
#else
        GByteArray *ba = g_byte_array_new();
        if (uri_to_bytes((const char*)bytes, ba, length)) {
            field_bytes_ = QByteArray((const char *)ba->data, ba->len);
        }
        g_byte_array_free(ba, true);
#endif
        break;
    }

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
        recent.gui_show_bytes_show = SHOW_IMAGE;
        ui->cbShowAs->blockSignals(true);
        ui->cbShowAs->setCurrentIndex(ui->cbShowAs->findData(SHOW_IMAGE));
        ui->cbShowAs->blockSignals(false);
    }

    updatePacketBytes();
    updateHintLabel();
}

void ShowPacketBytesDialog::updatePacketBytes(void)
{
    static const char hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    ui->tePacketBytes->clear();
    ui->tePacketBytes->setCurrentFont(mainApp->monospaceFont());

    switch (recent.gui_show_bytes_show) {

    case SHOW_ASCII:
    {
        QByteArray ba(field_bytes_);
        sanitizeBuffer(ba, false);
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setPlainText(ba);
        break;
    }

    case SHOW_ASCII_CONTROL:
    {
        QByteArray ba(field_bytes_);
        symbolizeBuffer(ba);
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setPlainText(ba);
        break;
    }

    case SHOW_CARRAY:
    {
        int pos = 0, len = static_cast<int>(field_bytes_.length());
        QString text("char packet_bytes[] = {\n");

        while (pos < len) {
            char hexbuf[256];
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

    case SHOW_RUSTARRAY:
    {
        int pos = 0, len = static_cast<int>(field_bytes_.length());
        QString text("let packet_bytes: [u8; _] = [\n");

        while (pos < len) {
            char hexbuf[256];
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

    case SHOW_CODEC:
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

    case SHOW_EBCDIC:
    {
        QByteArray ba(field_bytes_);
        EBCDIC_to_ASCII((uint8_t*)ba.data(), static_cast<int>(ba.length()));
        sanitizeBuffer(ba, false);
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setPlainText(ba);
        break;
    }

    case SHOW_HEXDUMP:
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

    case SHOW_HTML:
        ui->tePacketBytes->setLineWrapMode(QTextEdit::WidgetWidth);
        ui->tePacketBytes->setHtml(field_bytes_);
        break;

    case SHOW_IMAGE:
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

    case SHOW_JSON:
        ui->tePacketBytes->setLineWrapMode(QTextEdit::NoWrap);
        ui->tePacketBytes->setPlainText(QJsonDocument::fromJson(field_bytes_).toJson());
        break;

    case SHOW_YAML:
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

    case SHOW_RAW:
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
