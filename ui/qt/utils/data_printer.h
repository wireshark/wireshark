/** @file
 *
 * Used by ByteView and others, to create data dumps in printable
 * form
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DATA_PRINTER_H
#define DATA_PRINTER_H

#include <config.h>

#include <QObject>
#include <QActionGroup>

#include <ui/qt/utils/idata_printable.h>

class DataPrinter : public QObject
{
    Q_OBJECT
public:
    explicit DataPrinter(QObject *parent = 0);

    enum DumpType {
        DP_HexDump,
        DP_HexOnly,
        DP_HexStream,
        DP_UTF8Text,
        DP_ASCIIText,
        DP_CString,
        DP_GoLiteral,
        DP_CArray,
        DP_MimeData,
        DP_Base64
    };

    void toClipboard(DataPrinter::DumpType type, IDataPrintable * printable);

    void setByteLineLength(int);
    int byteLineLength() const;
    // Insert a space after this many bytes
    static int separatorInterval() { return 8; }
    // The number of hexadecimal characters per line
    static int hexChars();

    static QActionGroup * copyActions(QObject * copyClass, QObject * data = Q_NULLPTR);
    static DataPrinter * instance();

protected slots:
    void copyIDataBytes(bool);

private:
    QString hexTextDump(const QByteArray printData, bool showASCII);
    void binaryDump(const QByteArray printData);

    int byteLineLength_;
};

#endif // DATA_PRINTER_H
