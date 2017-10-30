/* data_printer.cpp
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

#include <ui/qt/utils/data_printer.h>

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
    QByteArray printData = printable->printableData();

    QString clipboard_text;

    switch(type)
    {
    case DP_PrintableText:
        for (int i = 0; i < printData.length(); i++) {
            if (QChar::isSpace(printData[i]) || QChar::isLetter(printData[i])) {
                clipboard_text += QChar(printData[i]);
            }
        }
        break;
    case DP_HexStream:
        for (int i = 0; i < printData.length(); i++)
            clipboard_text += QString("%1").arg(printData[i], 2, 16, QChar('0'));
        break;
    case DP_EscapedString:
        // Beginning quote
        clipboard_text += QString("\"");

        for (int i = 0; i < printData.length(); i++) {
            // Terminate this line if it has reached 16 bytes,
            // unless it is also the very last byte in the data,
            // as the termination after this for loop will take
            // care of that.
            if (i % 16 == 0 && i != 0 && i != printData.length() - 1) {
                clipboard_text += QString("\" \\\n\"");
            }
            clipboard_text += QString("\\x%1").arg(printData[i], 2, 16, QChar('0'));
        }
        // End quote
        clipboard_text += QString("\"\n");
        break;
    case DP_Binary:
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

void DataPrinter::binaryDump(QByteArray printData)
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

QString DataPrinter::hexTextDump(QByteArray printData, bool showText)
{
    QString clipboard_text;

    QString byteStr;
    QString dataStr;

    int cnt = 0;
    while ( cnt < printData.length() )
    {
        byteStr += QString(" %1").arg((uint8_t) printData[cnt], 2, 16, QChar('0'));
        if ( showText )
        {
            char ch = '.';
            if ( QChar::isPrint(printData[cnt]) )
                ch = (char) printData[cnt];
            dataStr += QChar( ch );
        }
        cnt++;
    }

    int lines = printData.length() / byteLineLength_;
    if ( printData.length() % byteLineLength_ > 0 )
        lines++;

    for ( cnt = 0; cnt < lines; cnt++ )
    {
        int offset = cnt * 0x10;

        clipboard_text += QString("%1  ").arg(offset, 4, 16, QChar('0'));
        clipboard_text += byteStr.mid(offset * 3, byteLineLength_ * 3);

        if ( showText )
        {
            /* separation bytes for byte and text */
            clipboard_text += QString(3, ' ');

            /* separation bytes last line */
            if ( cnt == ( lines - 1 ) )
            {
                int remSpace = byteLineLength_ - dataStr.mid(offset, byteLineLength_).length();
                clipboard_text += QString(remSpace * 3, ' ');
            }

            /* text representation */
            clipboard_text += dataStr.mid(offset, byteLineLength_);
        }

        clipboard_text += "\n";
    }

    return clipboard_text;
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
