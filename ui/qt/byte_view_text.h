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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

class ByteViewText : public QTextEdit
{
    Q_OBJECT
public:
    explicit ByteViewText(QWidget *parent = 0, tvbuff_t *tvb = NULL, proto_tree *tree = NULL, QTreeWidget *protoTree = NULL, unsigned int encoding = PACKET_CHAR_ENC_CHAR_ASCII);
    void hexPrintCommon();
    bool hasDataSource(tvbuff_t *ds_tvb = NULL);
    void highlight(int start, int len, bool is_root = false);

private:
    tvbuff_t *m_tvb;
    proto_tree *m_tree;
    QTreeWidget *m_protoTree;
    int m_encoding;
    unsigned int m_useDigits;
    int m_start, m_len;
    void mousePressEvent (QMouseEvent * event);

signals:

public slots:

};

#endif // BYTE_VIEW_TEXT_H
