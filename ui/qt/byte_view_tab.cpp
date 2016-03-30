/* byte_view_tab.cpp
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

#include "byte_view_tab.h"
#include "byte_view_text.h"

#include <QApplication>
#include <QClipboard>
#include <QMimeData>
#include <QTabBar>
#include <QTreeWidgetItem>

// To do:
// - We might want to add a callback to free_data_sources in so that we
//   don't have to blindly call clear().

ByteViewTab::ByteViewTab(QWidget *parent) :
    QTabWidget(parent)
{
    setAccessibleName(tr("Packet bytes"));
    setTabPosition(QTabWidget::South);
    setDocumentMode(true);
    addTab();
}

void ByteViewTab::addTab(const char *name, tvbuff_t *tvb, proto_tree *tree, QTreeWidget *protoTree, packet_char_enc encoding) {
    if (count() == 1) { // Remove empty placeholder.
        ByteViewText *cur_text = qobject_cast<ByteViewText *>(currentWidget());
        if (cur_text && cur_text->isEmpty()) delete currentWidget();
    }

    ByteViewText *byte_view_text = new ByteViewText(this, tvb, tree, protoTree, encoding);
    byte_view_text->setAccessibleName(name);
    byte_view_text->setMonospaceFont(mono_font_);
    connect(this, SIGNAL(monospaceFontChanged(QFont)), byte_view_text, SLOT(setMonospaceFont(QFont)));
    connect(byte_view_text, SIGNAL(byteFieldHovered(const QString&)), this, SIGNAL(byteFieldHovered(const QString&)));
    QTabWidget::addTab(byte_view_text, name);
}

void ByteViewTab::clear()
{
    bool visible = isVisible();
    if (visible) {
        hide();
    }
    while (currentWidget()) {
        delete currentWidget();
    }
    addTab();
    if (visible) {
        show();
    }
}

// XXX How many hex dump routines do we have?
const int byte_line_length_ = 16; // Print out data for 16 bytes on one line
void ByteViewTab::copyHexTextDump(const guint8 *data_p, int data_len, bool append_text)
{
    QString clipboard_text;
    /* Write hex data for a line, then ascii data, then concatenate and add to buffer */
    QString hex_str, char_str;
    int i;
    bool end_of_line = true; /* Initial state is end of line */
    int byte_line_part_length;

    i = 0;
    while (i < data_len) {
        if(end_of_line) {
            hex_str += QString("%1  ").arg(i, 4, 16, QChar('0')); /* Offset - note that we _append_ here */
        }

        hex_str += QString(" %1").arg(*data_p, 2, 16, QChar('0'));
        if(append_text) {
            char_str += QString("%1").arg(g_ascii_isprint(*data_p) ? QChar(*data_p) : '.');
        }

        ++data_p;

        /* Look ahead to see if this is the end of the data */
        byte_line_part_length = (++i) % byte_line_length_;
        if(i >= data_len){
            /* End of data - need to fill in spaces in hex string and then do "end of line".
             *
             */
            if (append_text) {
                int fill_len = byte_line_part_length == 0 ?
                            0 : byte_line_length_ - byte_line_part_length;
                /* Add three spaces for each missing byte */
                hex_str += QString(fill_len * 3, ' ');
            }
            end_of_line = true;
        } else {
            end_of_line = (byte_line_part_length == 0);
        }

        if (end_of_line){
            /* End of line */
            clipboard_text += hex_str;
            if(append_text) {
                /* Two spaces between hex and text */
                clipboard_text += "  ";
                clipboard_text += char_str;
            }
            /* Setup ready for next line */
            hex_str = "\n";
            char_str.clear();
        }
    }

    if (!clipboard_text.isEmpty()) {
        qApp->clipboard()->setText(clipboard_text);
    }
}

void ByteViewTab::copyPrintableText(const guint8 *data_p, int data_len)
{
    QString clipboard_text;

    for (int i = 0; i < data_len; i++) {
        const guint8 c = data_p[i];
        if (g_ascii_isprint(c) || g_ascii_isspace(c)) {
            clipboard_text += QChar(c);
        }
    }

    if (!clipboard_text.isEmpty()) {
        qApp->clipboard()->setText(clipboard_text);
    }
}

void ByteViewTab::copyHexStream(const guint8 *data_p, int data_len)
{
    QString clipboard_text;

    for (int i = 0; i < data_len; i++) {
        clipboard_text += QString("%1").arg(data_p[i], 2, 16, QChar('0'));
    }

    if (!clipboard_text.isEmpty()) {
        qApp->clipboard()->setText(clipboard_text);
    }
}
void ByteViewTab::copyBinary(const guint8 *data_p, int data_len)
{
    QByteArray clipboard_bytes = QByteArray::fromRawData((const char *) data_p, data_len);

    if (!clipboard_bytes.isEmpty()) {
        QMimeData *mime_data = new QMimeData;
        // gtk/gui_utils.c:copy_binary_to_clipboard says:
        /* XXX - this is not understood by most applications,
         * but can be pasted into the better hex editors - is
         * there something better that we can do?
         */
        // As of 2015-07-30, pasting into Frhed works on Windows. Pasting into
        // Hex Editor Neo and HxD does not.
        mime_data->setData("application/octet-stream", clipboard_bytes);
        qApp->clipboard()->setMimeData(mime_data);
    }
}

void ByteViewTab::copyData(ByteViewTab::copyDataType copy_type, field_info *fi)
{
    int i = 0;
    ByteViewText *byte_view_text = qobject_cast<ByteViewText*>(widget(i));

    if (fi) {
        while (byte_view_text) {
            if (byte_view_text->hasDataSource(fi->ds_tvb)) break;
            byte_view_text = qobject_cast<ByteViewText*>(widget(++i));
        }
    }

    if (!byte_view_text) return;

    guint data_len = 0;
    const guint8 *data_p;

    data_p = byte_view_text->dataAndLength(&data_len);
    if (!data_p) return;

    if (fi && fi->start >= 0 && fi->length > 0 && fi->length <= (int) data_len) {
        data_len = fi->length;
        data_p += fi->start;
    }

    if (!data_len) return;

    switch (copy_type) {
    case copyDataHexTextDump:
        copyHexTextDump(data_p, data_len, true);
        break;
    case copyDataHexDump:
        copyHexTextDump(data_p, data_len, false);
        break;
    case copyDataPrintableText:
        copyPrintableText(data_p, data_len);
        break;
    case copyDataHexStream:
        copyHexStream(data_p, data_len);
        break;
    case copyDataBinary:
        copyBinary(data_p, data_len);
        break;
    default:
        break;
    }
}

void ByteViewTab::tabInserted(int index) {
    setTabsVisible();
    QTabWidget::tabInserted(index);
}

void ByteViewTab::tabRemoved(int index) {
    setTabsVisible();
    QTabWidget::tabRemoved(index);
}

void ByteViewTab::setTabsVisible() {
    if (count() > 1)
        tabBar()->show();
    else
        tabBar()->hide();
}

void ByteViewTab::protoTreeItemChanged(QTreeWidgetItem *current) {
    if (current && cap_file_) {
        field_info *fi;

        fi = current->data(0, Qt::UserRole).value<field_info *>();

        int i = 0;
        ByteViewText *byte_view_text = qobject_cast<ByteViewText*>(widget(i));
        while (byte_view_text) {
            if (byte_view_text->hasDataSource(fi->ds_tvb)) {
                QTreeWidgetItem *parent = current->parent();
                field_info *parent_fi = NULL;
                int f_start = -1, f_end = -1, f_len = -1;
                int fa_start = -1, fa_end = -1, fa_len = -1;
                int p_start = -1, p_end = -1, p_len = -1;
                guint len = tvb_captured_length(fi->ds_tvb);

                // Find and highlight the protocol bytes
                while (parent && parent->parent()) {
                    parent = parent->parent();
                }
                if (parent) {
                    parent_fi = parent->data(0, Qt::UserRole).value<field_info *>();
                }
                if (parent_fi && parent_fi->ds_tvb == fi->ds_tvb) {
                    p_start = parent_fi->start;
                    p_len = parent_fi->length;
                }

                if (cap_file_->search_in_progress && (cap_file_->hex || (cap_file_->string && cap_file_->packet_data))) {
                    // In the hex view, only highlight the target bytes or string. The entire
                    // field can then be displayed by clicking on any of the bytes in the field.
                    f_start = cap_file_->search_pos - cap_file_->search_len + 1;
                    f_len = cap_file_->search_len;
                } else {
                    f_start = fi->start;
                    f_len = fi->length;
                }

                /* bmask = finfo->hfinfo->bitmask << hfinfo_bitshift(finfo->hfinfo); */ /* (value & mask) >> shift */
                fa_start = fi->appendix_start;
                fa_len = fi->appendix_length;

                if (p_start >= 0 && p_len > 0 && (guint)p_start < len) {
                    p_end = p_start + p_len;
                }
                if (f_start >= 0 && f_len > 0 && (guint)f_start < len) {
                    f_end = f_start + f_len;
                }
                if (fa_start >= 0 && fa_len > 0 && (guint)fa_start < len) {
                    fa_end = fa_start + fa_len;
                }

                if (f_end == -1 && fa_end != -1) {
                    f_start = fa_start;
                    f_end = fa_end;
                    fa_start = fa_end = -1;
                }

                /* don't exceed the end of available data */
                if (p_end != -1 && (guint)p_end > len) p_end = len;
                if (f_end != -1 && (guint)f_end > len) f_end = len;
                if (fa_end != -1 && (guint)fa_end > len) fa_end = len;

                // Protocol
                byte_view_text->setProtocolHighlight(p_start, p_end);

                // Field bytes
                byte_view_text->setFieldHighlight(f_start, f_end);

                // Appendix (trailer) bytes
                byte_view_text->setFieldAppendixHighlight(fa_start, fa_end);

                setCurrentIndex(i);
            }
            byte_view_text = qobject_cast<ByteViewText*>(widget(++i));
        }
    }
}

void ByteViewTab::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
}

void ByteViewTab::setMonospaceFont(const QFont &mono_font)
{
    mono_font_ = mono_font;
    emit monospaceFontChanged(mono_font_);
    update();
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
