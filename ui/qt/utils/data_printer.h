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

/**
 * @brief Utility class for formatting and exporting byte data in various text formats.
 */
class DataPrinter : public QObject
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new DataPrinter.
     * @param parent The parent QObject, defaults to 0.
     */
    explicit DataPrinter(QObject *parent = 0);

    /**
     * @brief Enumeration of supported data dump formats.
     */
    enum DumpType {
        DP_HexDump,     /**< Standard hex dump with ASCII representation. */
        DP_HexOnly,     /**< Formatted hexadecimal characters only. */
        DP_HexStream,   /**< Continuous stream of hexadecimal characters. */
        DP_UTF8Text,    /**< UTF-8 encoded text. */
        DP_ASCIIText,   /**< ASCII encoded text. */
        DP_CString,     /**< C-style escaped string. */
        DP_GoLiteral,   /**< Go language byte slice literal. */
        DP_CArray,      /**< C-style byte array definition. */
        DP_MimeData,    /**< Formatted MIME data. */
        DP_Base64       /**< Base64 encoded string. */
    };

    /**
     * @brief Formats the printable data and copies it to the system clipboard.
     * @param type The desired dump format.
     * @param printable Pointer to the interface providing the data.
     */
    void toClipboard(DataPrinter::DumpType type, IDataPrintable * printable);

    /**
     * @brief Sets the number of bytes displayed per line in formatted dumps.
     * @param bll The byte length per line.
     */
    void setByteLineLength(int bll);

    /**
     * @brief Retrieves the current number of bytes displayed per line.
     * @return The byte line length.
     */
    int byteLineLength() const;

    /**
     * @brief Number of bytes after which to insert an extra separator space in a hex dump.
     * @return The separator interval (defaults to 8).
     */
    static int separatorInterval() { return 8; }

    /**
     * @brief Calculates the total number of hexadecimal characters per line based on settings.
     * @return The character count.
     */
    static int hexChars();

    /**
     * @brief Generates a QActionGroup containing copy actions for all supported formats.
     * @param copyClass The parent object to own the actions.
     * @param data Optional context data to associate with the actions, defaults to Q_NULLPTR.
     * @return A pointer to the created QActionGroup.
     */
    static QActionGroup * copyActions(QObject * copyClass, QObject * data = Q_NULLPTR);

    /**
     * @brief Retrieves the singleton instance of DataPrinter.
     * @return Pointer to the global DataPrinter instance.
     */
    static DataPrinter * instance();

protected slots:
    /**
     * @brief Slot triggered to copy bytes from a printable interface.
     */
    void copyIDataBytes(bool);

private:
    /**
     * @brief Generates a hex dump string from the provided data.
     * @param printData The raw byte array to format.
     * @param showASCII True to include the ASCII representation alongside hex.
     * @return The formatted text dump.
     */
    QString hexTextDump(const QByteArray printData, bool showASCII);

    /**
     * @brief Handles raw binary dumping (e.g., MIME data copying).
     * @param printData The raw byte array to process.
     */
    void binaryDump(const QByteArray printData);

    /** The configured number of bytes displayed per line. */
    int byteLineLength_;
};

#endif // DATA_PRINTER_H
