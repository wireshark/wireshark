/* byte_view_text.h
 *
 * $Id$
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

#include "config.h"

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

#include "proto_tree.h"
#include <QTextEdit>

// XXX - Is there any reason we shouldn't add ByteViewImage, etc?

// XXX Copied from gtk/packet_panes.h
typedef enum {
  BYTES_HEX,
  BYTES_BITS
} bytes_view_type;

class ByteViewText : public QTextEdit
{
    Q_OBJECT
public:
    explicit ByteViewText(QWidget *parent = 0, tvbuff_t *tvb = NULL, proto_tree *tree = NULL, QTreeWidget *protoTree = NULL, packet_char_enc encoding = PACKET_CHAR_ENC_CHAR_ASCII);
    bool hasDataSource(tvbuff_t *ds_tvb = NULL);
    void setEncoding(packet_char_enc encoding);
    void setFormat(bytes_view_type format);
    void setHighlightStyle(bool bold);
    void setProtocolHighlight(int start, int end);
    void setFieldHighlight(int start, int end, guint32 mask = 0, int mask_le = 0);
    void setFieldAppendixHighlight(int start, int end);
    void renderBytes();

private:
    typedef enum {
        StateNormal,
        StateField,
        StateProtocol
    } highlight_state;

    void lineCommon(const int org_off);
    void setState(highlight_state state);
    int flushBytes(QString &str);
    void scrollToByte(int byte);

    int byteFromRowCol(int row, int col);
    void mousePressEvent (QMouseEvent * event);

    tvbuff_t *tvb_;
    proto_tree *proto_tree_;
    QTreeWidget *tree_widget_;

    gboolean bold_highlight_;

/* data */
    packet_char_enc encoding_;	/* ASCII or EBCDIC */
    bytes_view_type format_;	/* bytes in hex or bytes as bits */

/* data-highlight */
    int p_start_, p_end_;       /* Protocol */
    int f_start_, f_end_;       /* Field */
    int fa_start_, fa_end_;     /* Field appendix */

    int per_line_;      		/* Number of bytes per line */
    int offset_width_;			/* Byte offset field width */

signals:

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
