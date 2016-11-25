/* data_printer.h
 *
 * Used by ByteView and others, to create data dumps in printable
 * form
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef DATA_PRINTER_H
#define DATA_PRINTER_H

#include <config.h>

#include <QObject>


class IDataPrintable
{
public:
    virtual ~IDataPrintable() {}

    virtual QByteArray printableData() = 0;
};

class DataPrinter : public QObject
{
    Q_OBJECT
public:
    explicit DataPrinter(QObject *parent = 0);

    enum DumpType {
        DP_HexDump,
        DP_HexOnly,
        DP_HexStream,
        DP_PrintableText,
        DP_EscapedString,
        DP_Binary
    };

    void toClipboard(DataPrinter::DumpType type, IDataPrintable * printable);

    void setByteLineLength(int);
    int byteLineLength() const;
    // Insert a space after this many bytes
    static int separatorInterval() { return 8; }
    // The number of hexadecimal characters per line
    static int hexChars();

private:
    QString hexTextDump(QByteArray printData, bool append_text);
    void binaryDump(QByteArray printData);

    int byteLineLength_;
};

#define IDataPrintable_iid "org.wireshark.Qt.UI.IDataPrintable"

Q_DECLARE_INTERFACE(IDataPrintable, IDataPrintable_iid)

#endif // DATA_PRINTER_H

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
