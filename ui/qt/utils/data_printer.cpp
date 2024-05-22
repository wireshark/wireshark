/* data_printer.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/data_printer.h>
#include <ui/qt/utils/variant_pointer.h>

#include <ui/recent.h>

#include <wsutil/utf8_entities.h>

#include <stdint.h>

#include <QApplication>
#include <QClipboard>
#include <QString>
#include <QMimeData>

DataPrinter::DataPrinter(QObject * parent)
: QObject(parent),
  byteLineLength_(16)
{}

void DataPrinter::toClipboard(DataPrinter::DumpType type, IDataPrintable * printable)
{
    const QByteArray printData = printable->printableData();

    QString clipboard_text;

    switch(type)
    {
    case DP_GoLiteral:
        clipboard_text += QString("[]byte{");
        for (int i = 0; i < printData.length(); i++) {
        if (i>0) clipboard_text += ", ";
            clipboard_text += QString("0x%1").arg((uint8_t) printData[i], 1, 16, QChar('0'));
        }
        clipboard_text += QString("}");
        break;
    case DP_CArray:
        clipboard_text += QString("unsigned char bytes[] = {");
        for (int i = 0; i < printData.length(); i++) {
        if (i>0) clipboard_text += ", ";
            clipboard_text += QString("0x%1").arg((uint8_t) printData[i], 1, 16, QChar('0'));
        }
        clipboard_text += QString("};");
        break;
    case DP_CString:
        // Beginning quote
        clipboard_text += QString("\"");
        for (int i = 0; i < printData.length(); i++) {
            // backslash and double quote are printable but
            // must be escaped in a C string.
            char ch = printData[i];
            switch (ch) {
            case '\"':
                clipboard_text += QString("\\\"");
                break;
            case '\\':
                clipboard_text += QString("\\\\");
                break;
            case '\a':
                clipboard_text += QString("\\a");
                break;
            case '\b':
                clipboard_text += QString("\\b");
                break;
            case '\f':
                clipboard_text += QString("\\f");
                break;
            case '\n':
                clipboard_text += QString("\\n");
                break;
            case '\r':
                clipboard_text += QString("\\r");
                break;
            case '\t':
                clipboard_text += QString("\\t");
                break;
            case '\v':
                clipboard_text += QString("\\v");
                break;
            default:
                // ASCII printable
                if (ch >= 32 && ch <= 126) {
                    clipboard_text += QChar(ch);
                }
                else {
                    clipboard_text += QString("\\%1").arg((uint8_t) printData[i], 3, 8, QChar('0'));
                }
            }
        }
        // End quote
        clipboard_text += QString("\"");
        break;
    case DP_HexStream:
        for (int i = 0; i < printData.length(); i++)
            clipboard_text += QString("%1").arg((uint8_t) printData[i], 2, 16, QChar('0'));
        break;
    case DP_UTF8Text:
        // This automatically compensates for invalid UTF-8 in the input
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_OFF(stringop-overread)
#endif
        clipboard_text += QString::fromUtf8(printData);
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_ON(stringop-overread)
#endif
        break;
    case DP_ASCIIText:
        // Copy valid 7-bit printable ASCII bytes, skip the rest
        for (int i = 0; i < printData.length(); i++) {
            QChar ch(printData[i]);
            if (ch.isSpace() || (ch > (char)0x20 && ch < (char)0x7F)) {
                clipboard_text += ch;
            }
        }
        break;
    case DP_Base64:
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_OFF(stringop-overread)
#endif
        clipboard_text = printData.toBase64();
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_ON(stringop-overread)
#endif
        break;
    case DP_MimeData:
        binaryDump(printData);
        break;
    case DP_HexDump:
        clipboard_text = hexTextDump(printData, true);
        break;
    case DP_HexOnly:
        clipboard_text = hexTextDump(printData, false);
        break;
    default:
        break;
    }

    if (!clipboard_text.isEmpty()) {
        qApp->clipboard()->setText(clipboard_text);
    }
}

void DataPrinter::binaryDump(const QByteArray printData)
{
    if (!printData.isEmpty()) {
        QMimeData *mime_data = new QMimeData;
        // gtk/gui_utils.c:copy_binary_to_clipboard says:
        /* XXX - this is not understood by most applications,
         * but can be pasted into the better hex editors - is
         * there something better that we can do?
         */
        // As of 2015-07-30, pasting into Frhed works on Windows. Pasting into
        // Hex Editor Neo and HxD does not.
        mime_data->setData("application/octet-stream", printData);
        qApp->clipboard()->setMimeData(mime_data);
    }
}

void DataPrinter::setByteLineLength(int bll)
{
    byteLineLength_ = bll;
}

int DataPrinter::byteLineLength() const
{
    return byteLineLength_;
}

int DataPrinter::hexChars()
{
    int row_width, chars_per_byte;

    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        row_width = 16;
        chars_per_byte = 3;
        break;
    case BYTES_BITS:
        row_width = 8;
        chars_per_byte = 9;
        break;
    case BYTES_DEC:
    case BYTES_OCT:
        row_width = 16;
        chars_per_byte = 4;
        break;
    default:
        ws_assert_not_reached();
    }
    return (row_width * chars_per_byte) + ((row_width - 1) / separatorInterval());
}

QString DataPrinter::hexTextDump(const QByteArray printData, bool showASCII)
{
    QString clipboard_text;

    QString byteStr;
    QString dataStr;

    int cnt = 0;
    while (cnt < printData.length())
    {
        byteStr += QString(" %1").arg((uint8_t) printData[cnt], 2, 16, QChar('0'));
        if (showASCII)
        {
            QChar ch(printData[cnt]);
            if (g_ascii_isprint(printData[cnt]))
                dataStr += printData[cnt];
            else
                dataStr += '.';
        }
        cnt++;
    }

    int lines = static_cast<int>(printData.length()) / byteLineLength_;
    if (printData.length() % byteLineLength_ > 0)
        lines++;

    for (cnt = 0; cnt < lines; cnt++)
    {
        int offset = cnt * 0x10;

        clipboard_text += QString("%1  ").arg(offset, 4, 16, QChar('0'));
        clipboard_text += byteStr.mid(offset * 3, byteLineLength_ * 3);

        if (showASCII)
        {
            /* separation bytes for byte and text */
            clipboard_text += QString(3, ' ');

            /* separation bytes last line */
            if (cnt == (lines - 1) )
            {
                int remSpace = byteLineLength_ - static_cast<int>(dataStr.mid(offset, byteLineLength_).length());
                clipboard_text += QString(remSpace * 3, ' ');
            }

            /* text representation */
            clipboard_text += dataStr.mid(offset, byteLineLength_);
        }

        clipboard_text += "\n";
    }

    return clipboard_text;
}

DataPrinter * DataPrinter::instance()
{
    static DataPrinter * inst = Q_NULLPTR;
    if (inst == Q_NULLPTR)
        inst = new DataPrinter();
    return inst;
}

QActionGroup * DataPrinter::copyActions(QObject * copyClass, QObject * data)
{
    QActionGroup * actions = new QActionGroup(copyClass);

    if (! data && ! dynamic_cast<IDataPrintable *>(copyClass))
        return actions;

    DataPrinter * dpi = DataPrinter::instance();

    if (data)
        actions->setProperty("idataprintable", VariantPointer<QObject>::asQVariant(data));
    else
        actions->setProperty("idataprintable", VariantPointer<QObject>::asQVariant(copyClass));

    // Mostly duplicated from main_window.ui
    QAction * action = new QAction(tr("Copy Bytes as Hex + ASCII Dump"), actions);
    action->setToolTip(tr("Copy packet bytes as a hex and ASCII dump."));
    action->setProperty("printertype", DataPrinter::DP_HexDump);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as Hex Dump"), actions);
    action->setToolTip(tr("Copy packet bytes as a hex dump."));
    action->setProperty("printertype", DataPrinter::DP_HexOnly);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as UTF-8 Text"), actions);
    action->setToolTip(tr("Copy packet bytes as text, treating as UTF-8."));
    action->setProperty("printertype", DataPrinter::DP_UTF8Text);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as ASCII Text"), actions);
    action->setToolTip(tr("Copy packet bytes as text, treating as ASCII."));
    action->setProperty("printertype", DataPrinter::DP_ASCIIText);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as a Hex Stream"), actions);
    action->setToolTip(tr("Copy packet bytes as a stream of hex."));
    action->setProperty("printertype", DataPrinter::DP_HexStream);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as a Base64 String"), actions);
    action->setToolTip(tr("Copy packet bytes as a base64 encoded string."));
    action->setProperty("printertype", DataPrinter::DP_Base64);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as MIME Data"), actions);
    action->setToolTip(tr("Copy packet bytes as application/octet-stream MIME data."));
    action->setProperty("printertype", DataPrinter::DP_MimeData);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as C String"), actions);
    action->setToolTip(tr("Copy packet bytes as printable ASCII characters and escape sequences."));
    action->setProperty("printertype", DataPrinter::DP_CString);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as Go literal"), actions);
    action->setToolTip(tr("Copy packet bytes as Go literal."));
    action->setProperty("printertype", DataPrinter::DP_GoLiteral);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    action = new QAction(tr("…as C Array"), actions);
    action->setToolTip(tr("Copy packet bytes as C Array."));
    action->setProperty("printertype", DataPrinter::DP_CArray);
    connect(action, &QAction::triggered, dpi, &DataPrinter::copyIDataBytes);

    return actions;
}

void DataPrinter::copyIDataBytes(bool /* state */)
{
    if (! dynamic_cast<QAction*>(sender()))
        return;

    QAction * sendingAction = dynamic_cast<QAction *>(sender());
    if (! sendingAction->actionGroup() || ! sendingAction->actionGroup()->property("idataprintable").isValid())
        return;

    QObject * dataObject = VariantPointer<QObject>::asPtr(sendingAction->actionGroup()->property("idataprintable"));
    if (! dataObject || ! dynamic_cast<IDataPrintable *>(dataObject))
        return;

    int dump_type = sendingAction->property("printertype").toInt();

    if (dump_type >= 0 && dump_type <= DataPrinter::DP_Base64) {
        DataPrinter printer;
        printer.toClipboard((DataPrinter::DumpType) dump_type, dynamic_cast<IDataPrintable *>(dataObject));
    }
}
