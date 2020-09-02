/* byte_view_text.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BYTE_VIEW_TEXT_H
#define BYTE_VIEW_TEXT_H

#include <config.h>

#include "ui/recent.h"

#include <QAbstractScrollArea>
#include <QFont>
#include <QVector>
#include <QMenu>
#include <QSize>
#include <QString>
#include <QTextLayout>
#include <QVector>

#include <ui/qt/utils/data_printer.h>
#include <ui/qt/utils/idata_printable.h>

// XXX - Is there any reason we shouldn't add ByteViewImage, etc?

class ByteViewText : public QAbstractScrollArea, public IDataPrintable
{
    Q_OBJECT
    Q_INTERFACES(IDataPrintable)

public:
    explicit ByteViewText(const QByteArray &data, packet_char_enc encoding = PACKET_CHAR_ENC_CHAR_ASCII, QWidget *parent = 0);
    ~ByteViewText();

    virtual QSize minimumSizeHint() const;

    void setFormat(bytes_view_type format);
    bool isEmpty() const;

signals:
    void byteHovered(int pos);
    void byteSelected(int pos);
    void byteViewSettingsChanged();

public slots:
    void setMonospaceFont(const QFont &mono_font);
    void updateByteViewSettings();

    void markProtocol(int start, int length);
    void markField(int start, int length, bool scroll_to = true);
    void markAppendix(int start, int length);

protected:
    virtual void paintEvent(QPaintEvent *);
    virtual void resizeEvent(QResizeEvent *);
    virtual void mousePressEvent (QMouseEvent * event);
    virtual void mouseMoveEvent (QMouseEvent * event);
    virtual void leaveEvent(QEvent *event);
    virtual void contextMenuEvent(QContextMenuEvent *event);

private:
    // Text highlight modes.
    typedef enum {
        ModeNormal,
        ModeField,
        ModeProtocol,
        ModeOffsetNormal,
        ModeOffsetField,
        ModeNonPrintable
    } HighlightMode;

    QTextLayout *layout_;
    const QByteArray data_;

    void drawLine(QPainter *painter, const int offset, const int row_y);
    bool addFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int start, int length, HighlightMode mode);
    bool addHexFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, HighlightMode mode);
    bool addAsciiFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, HighlightMode mode);
    void scrollToByte(int byte);
    void updateScrollbars();
    int byteOffsetAtPixel(QPoint pos);

    void createContextMenu();
    void updateContextMenu();

    int offsetChars(bool include_pad = true);
    int offsetPixels();
    int hexPixels();
    int asciiPixels();
    int totalPixels();
    const QByteArray printableData() { return data_; }

    static const int separator_interval_;

    // Colors
    QColor offset_normal_fg_;
    QColor offset_field_fg_;

    // Data
    packet_char_enc encoding_;  // ASCII or EBCDIC
    QMenu ctx_menu_;

    // Data highlight
    int hovered_byte_offset_;
    int marked_byte_offset_;
    int proto_start_;
    int proto_len_;
    int field_start_;
    int field_len_;
    int field_a_start_;
    int field_a_len_;

    bool show_offset_;          // Should we show the byte offset?
    bool show_hex_;             // Should we show the hex display?
    bool show_ascii_;           // Should we show the ASCII display?
    int row_width_;             // Number of bytes per line
    qreal font_width_;          // Single character width and text margin. NOTE: Use fontMetrics::width for multiple characters.
    int line_height_;           // Font line spacing
    QList<QRect> hover_outlines_; // Hovered byte outlines.

    // Data selection
    QVector<int> x_pos_to_column_;

    // Context menu actions
    QAction *action_bytes_hex_;
    QAction *action_bytes_bits_;
    QAction *action_bytes_enc_from_packet_;
    QAction *action_bytes_enc_ascii_;
    QAction *action_bytes_enc_ebcdic_;

private slots:
    void copyBytes(bool);
    void setHexDisplayFormat(QAction *action);
    void setCharacterEncoding(QAction *action);

};

#endif // BYTE_VIEW_TEXT_H

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
