/* byte_view_tab.h
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

#ifndef BYTE_VIEW_TAB_H
#define BYTE_VIEW_TAB_H

#include <config.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

#include "cfile.h"

#include <QTabWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <ui/qt/byte_view_text.h>

class ByteViewTab : public QTabWidget
{
    Q_OBJECT
public:
    enum copyDataType {
        copyDataHexTextDump,
        copyDataHexDump,
        copyDataPrintableText,
        copyDataHexStream,
        copyDataBinary,
        copyDataEscapedString
    };

    explicit ByteViewTab(QWidget *parent = 0);

    void copyData(copyDataType copy_type, field_info *fi = NULL);

public slots:
    /* Set the capture file */
    void setCaptureFile(capture_file *cf);
    /* Creates the tabs and data, depends on an dissection which has already run */
    void packetSelectionChanged();

    void protoTreeItemChanged(QTreeWidgetItem *current);
    void setMonospaceFont(const QFont &mono_font);

signals:
    void monospaceFontChanged(const QFont &mono_font);
    void byteFieldHovered(const QString &);

    void tvbOffsetHovered(tvbuff_t *, int);
    void tvbOffsetMarked(tvbuff_t *, int);

private:
    capture_file *cap_file_;
    QFont mono_font_;

    void setTabsVisible();
    void copyHexTextDump(QByteArray data, bool append_text);
    void copyPrintableText(QByteArray data);
    void copyHexStream(QByteArray data);
    void copyBinary(QByteArray data);
    void copyEscapedString(QByteArray data);

    ByteViewText * findByteViewTextForTvb(tvbuff_t * search, int * idx = 0);

    void addTab(const char *name = "", tvbuff_t *tvb = NULL);

protected:
    void tabInserted(int index);
    void tabRemoved(int index);

private slots:
    void byteViewTextHovered(int);
    void byteViewTextMarked(int);
};

#endif // BYTE_VIEW_TAB_H

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
