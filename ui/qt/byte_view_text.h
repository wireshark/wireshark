/* byte_view_text.h
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

#ifndef BYTE_VIEW_TEXT_H
#define BYTE_VIEW_TEXT_H

#include <config.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

#include "proto_tree.h"
#include "ui/recent.h"

#include <QAbstractScrollArea>
#include <QMenu>

class QActionGroup;

// XXX - Is there any reason we shouldn't add ByteViewImage, etc?

class ByteViewText : public QAbstractScrollArea
{
    Q_OBJECT
public:
    explicit ByteViewText(QWidget *parent = 0, tvbuff_t *tvb = NULL, proto_tree *tree = NULL, QTreeWidget *protoTree = NULL, packet_char_enc encoding = PACKET_CHAR_ENC_CHAR_ASCII);
    ~ByteViewText();

    bool hasDataSource(const tvbuff_t *ds_tvb = NULL);
    void setFormat(bytes_view_type format);
    void setHighlightStyle(bool bold) { bold_highlight_ = bold; }
    void setProtocolHighlight(int start, int end);
    void setFieldHighlight(int start, int end, guint32 mask = 0, int mask_le = 0);
    void setFieldAppendixHighlight(int start, int end);
    bool isEmpty() { return tvb_ == NULL || proto_tree_ == NULL; }
    const guint8 *dataAndLength(guint *data_len_ptr);

signals:
    void byteFieldHovered(const QString &);

public slots:
    void setMonospaceFont(const QFont &mono_font);

protected:
    virtual void paintEvent(QPaintEvent *);
    virtual void resizeEvent(QResizeEvent *);
    virtual void mousePressEvent (QMouseEvent * event);
    virtual void mouseMoveEvent (QMouseEvent * event);
    virtual void leaveEvent(QEvent *event);
    virtual void contextMenuEvent(QContextMenuEvent *event);

private:
    typedef enum {
        StateNormal,
        StateField,
        StateProtocol,
        StateOffsetNormal,
        StateOffsetField
    } highlight_state;

    void drawOffsetLine(QPainter &painter, const guint offset, const int row_y);
    qreal flushOffsetFragment(QPainter &painter, qreal x, int y, highlight_state state, gboolean extra_highlight, QString &text);
    void scrollToByte(int byte);
    int offsetChars();
    int offsetPixels();
    int hexPixels();
    int asciiPixels();
    int totalPixels();
    void updateScrollbars();
    int byteOffsetAtPixel(QPoint &pos);
    field_info *fieldAtPixel(QPoint &pos);

    static const int separator_interval_;
    tvbuff_t *tvb_;
    proto_tree *proto_tree_;
    QTreeWidget *tree_widget_;

    // Fonts and colors
    QFont mono_font_;
//    QFont mono_bold_font_;
    QBrush offset_normal_fg_;
    QBrush offset_field_fg_;

    gboolean bold_highlight_;

    // Data
    QActionGroup *format_actions_;
    QActionGroup *encoding_actions_;
    packet_char_enc encoding_;  // ASCII or EBCDIC
    QMenu ctx_menu_;

    // Data highlight
    guint hovered_byte_offset;
    QPair<guint,guint> p_bound_;
    QPair<guint,guint> f_bound_;
    QPair<guint,guint> fa_bound_;
    QPair<guint,guint> p_bound_save_;
    QPair<guint,guint> f_bound_save_;
    QPair<guint,guint> fa_bound_save_;

    bool show_offset_;          // Should we show the byte offset?
    bool show_hex_;             // Should we show the hex display?
    bool show_ascii_;           // Should we show the ASCII display?
    guint row_width_;           // Number of bytes per line
    int one_em_;                // Font character height
    qreal font_width_;          // Font character width
    int line_spacing_;          // Font line spacing
    int margin_;                // Text margin

    // Data selection
    QMap<int,int> x_pos_to_column_;

private slots:
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
