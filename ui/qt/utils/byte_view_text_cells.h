/** @file
 *
 * Decodes packet bytes into the character cells shown in the text panel
 * of the byte view.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BYTE_VIEW_TEXT_CELLS_H
#define BYTE_VIEW_TEXT_CELLS_H

#include <config.h>

#include <QByteArray>
#include <QString>
#include <QVector>

/**
 * @brief Maps packet bytes to the character cells drawn in the text panel.
 *
 * Every byte of the data belongs to exactly one cell. Single-byte encodings
 * produce one cell per byte; those cells are computed on demand and take no
 * memory. UTF-8 produces one cell per grapheme cluster, so combining marks,
 * emoji modifier and ZWJ sequences, flags and keycap sequences stay together
 * and their cell covers all of their bytes; those cells are decoded once
 * and stored compactly.
 *
 * Cells are listed in byte order. No bidirectional reordering or shaping
 * is applied, so that the text panel keeps lining up with the hex panel.
 */
class ByteViewTextCells
{
public:
    /** @brief Character encoding of the data. */
    enum Encoding {
        Ascii,  /**< 7-bit ASCII; bytes >= 0x80 are not printable. */
        Ebcdic, /**< EBCDIC, mapped to ASCII before display. */
        Utf8    /**< UTF-8, one cell per grapheme cluster. */
    };

    /** @brief How a cell is displayed. */
    enum CellKind {
        Printable,    /**< Drawn as-is. */
        NonPrintable, /**< Control, format or whitespace character; drawn as a dot. */
        Invalid       /**< Bytes that are not valid in the encoding; drawn as a dot. */
    };

    /** @brief One displayed unit of text and the bytes it stands for. */
    struct Cell {
        int start;     /**< Offset of the first byte. */
        int length;    /**< Number of bytes. */
        CellKind kind; /**< Display kind. */
        QString text;  /**< Text to draw. */
    };

    /**
     * @brief Longest run of bytes kept as a single cell.
     *
     * Grapheme clusters longer than this are split into one cell per
     * code point.
     */
    static const int max_cell_bytes = 32;

    ByteViewTextCells();

    /**
     * @brief Replace the cells with a decoding of @p data.
     * @param data     The bytes to decode.
     * @param encoding The character encoding to decode them with.
     */
    void decode(const QByteArray &data, Encoding encoding);

    /** @brief Remove all cells. */
    void clear();

    /** @return The number of cells. */
    int cellCount() const;

    /**
     * @brief Return the cell at @p cell_index.
     * @param cell_index A cell index in [0, cellCount()).
     */
    Cell cellAt(int cell_index) const;

    /**
     * @brief Return the index of the cell that contains @p offset.
     * @param offset A byte offset.
     * @return The cell index, or -1 if @p offset is out of range.
     */
    int cellIndexForByte(int offset) const;

    /**
     * @brief Return the cell that contains @p offset.
     * @param offset A byte offset.
     * @param cell   Receives the cell.
     * @return true if @p offset is in range.
     */
    bool cellForByte(int offset, Cell &cell) const;

private:
    /** @brief A stored UTF-8 cell; its text is a slice of @c text_. */
    struct StoredCell {
        int start;         /**< Offset of the first byte. */
        int text_pos;      /**< Start of the text in @c text_. */
        uint16_t length;   /**< Number of bytes. */
        uint16_t text_len; /**< Length of the text in UTF-16 code units. */
        uint8_t kind;      /**< A @c CellKind. */
    };

    /** @brief A decoded code point and the bytes it came from. */
    struct CodePoint {
        int start;   /**< Offset of the first byte. */
        int length;  /**< Number of bytes. */
        uint32_t uc; /**< The code point. */
    };

    Cell singleByteCell(int offset) const;

    void decodeUtf8();

    /** @brief Split a run of valid code points into grapheme cluster cells. */
    void appendRun(const QVector<CodePoint> &run);

    /** @brief Append the cells for code points [@p first, @p last) of @p run. */
    void appendCluster(const QVector<CodePoint> &run, int first, int last);

    /** @brief Append one cell per code point for code points [@p first, @p last). */
    void appendCodePoints(const QVector<CodePoint> &run, int first, int last);

    void appendCell(int start, int length, CellKind kind, const QString &text);
    void appendDotCell(int start, int length, CellKind kind);

    static bool isDisplayable(uint32_t uc);
    static bool isMark(uint32_t uc);
    static QString textFor(const QVector<CodePoint> &run, int first, int last);

    QByteArray data_;           /**< The decoded data. */
    Encoding encoding_;         /**< Its encoding. */
    QVector<StoredCell> cells_; /**< UTF-8 cells in byte order; empty for single-byte encodings. */
    QString text_;              /**< Text of all UTF-8 cells; starts with the dot shared by non-printable cells. */
};

#endif // BYTE_VIEW_TEXT_CELLS_H
