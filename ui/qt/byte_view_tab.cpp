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

#include <QApplication>
#include <QClipboard>
#include <QMimeData>
#include <QTabBar>
#include <QTreeWidgetItem>

#include "cfile.h"
#include "epan/epan_dissect.h"

#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/byte_view_text.h>

#define tvb_data_property "tvb_data_property"

// To do:
// - We might want to add a callback to free_data_sources in so that we
//   don't have to blindly call clear().

ByteViewTab::ByteViewTab(QWidget *parent) :
    QTabWidget(parent),
    cap_file_(0)
{
    setAccessibleName(tr("Packet bytes"));
    setTabPosition(QTabWidget::South);
    setDocumentMode(true);
    addTab();
}

void ByteViewTab::addTab(const char *name, tvbuff_t *tvb) {
    if ( ! tvb || ! cap_file_ )
        return;

    if (count() == 1) { // Remove empty placeholder.
        ByteViewText *cur_text = qobject_cast<ByteViewText *>(currentWidget());
        if (cur_text && cur_text->isEmpty()) delete currentWidget();
    }

    packet_char_enc encoding = (packet_char_enc)cap_file_->current_frame->flags.encoding;

    QByteArray data((const char *) tvb_memdup(wmem_file_scope(), tvb, 0, -1), tvb_captured_length(tvb));

    ByteViewText * byte_view_text = new ByteViewText(data, encoding, this);
    byte_view_text->setAccessibleName(name);
    byte_view_text->setMonospaceFont(mono_font_);

    byte_view_text->setProperty(tvb_data_property, VariantPointer<tvbuff_t>::asQVariant(tvb));

    connect(this, SIGNAL(monospaceFontChanged(QFont)), byte_view_text, SLOT(setMonospaceFont(QFont)));

    connect(byte_view_text, SIGNAL(byteHovered(int)), this, SLOT(byteViewTextHovered(int)));
    connect(byte_view_text, SIGNAL(byteSelected(int)), this, SLOT(byteViewTextMarked(int)));

    int idx = QTabWidget::addTab(byte_view_text, name);

    QTabWidget::setTabToolTip(idx, name);
}

void ByteViewTab::packetSelectionChanged()
{
    if ( ! cap_file_ || ! cap_file_->edt )
        return;

    clear();

    GSList *src_le;
    for (src_le = cap_file_->edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
        struct data_source *source;
        char* source_name;
        source = (struct data_source *)src_le->data;
        source_name = get_data_source_name(source);
        addTab(source_name, get_data_source_tvb(source));
        wmem_free(NULL, source_name);
    }
    setCurrentIndex(0);
}

void ByteViewTab::byteViewTextHovered(int idx)
{
    if ( idx < 0 )
    {
        emit tvbOffsetHovered((tvbuff_t *)0, idx);
        return;
    }

    tvbuff_t * tvb = VariantPointer<tvbuff_t>::asPtr(sender()->property(tvb_data_property));

    emit tvbOffsetHovered(tvb, idx);
}

void ByteViewTab::byteViewTextMarked(int idx)
{
    if ( idx < 0 )
    {
        emit tvbOffsetMarked((tvbuff_t *)0, idx);
        return;
    }

    tvbuff_t * tvb = VariantPointer<tvbuff_t>::asPtr(sender()->property(tvb_data_property));

    emit tvbOffsetMarked(tvb, idx);
}

// XXX How many hex dump routines do we have?
const int byte_line_length_ = 16; // Print out data for 16 bytes on one line
void ByteViewTab::copyHexTextDump(QByteArray data, bool append_text)
{
    QString clipboard_text;
    /* Write hex data for a line, then ascii data, then concatenate and add to buffer */
    QString hex_str, char_str;
    int i;
    bool end_of_line = true; /* Initial state is end of line */
    int byte_line_part_length;

    i = 0;
    while (i < data.count()) {
        if(end_of_line) {
            hex_str += QString("%1  ").arg(i, 4, 16, QChar('0')); /* Offset - note that we _append_ here */
        }

        hex_str += QString(" %1").arg(data[i], 2, 16, QChar('0'));
        if(append_text) {
            char_str += QString("%1").arg(g_ascii_isprint(data[i]) ? QChar(data[i]) : '.');
        }

        /* Look ahead to see if this is the end of the data */
        byte_line_part_length = (++i) % byte_line_length_;
        if(i >= data.count()){
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

void ByteViewTab::copyPrintableText(QByteArray data)
{
    QString clipboard_text;

    for (int i = 0; i < data.count(); i++)
    {
        if ( QChar(data[i]).toLatin1() != 0 )
            clipboard_text += QChar(data[i]);
    }

    if (!clipboard_text.isEmpty()) {
        qApp->clipboard()->setText(clipboard_text);
    }
}

void ByteViewTab::copyHexStream(QByteArray data)
{
    if (!data.isEmpty()) {
        qApp->clipboard()->setText(data.toHex().toUpper());
    }
}
void ByteViewTab::copyBinary(QByteArray data)
{
    if (!data.isEmpty()) {
        QMimeData *mime_data = new QMimeData;
        // gtk/gui_utils.c:copy_binary_to_clipboard says:
        /* XXX - this is not understood by most applications,
         * but can be pasted into the better hex editors - is
         * there something better that we can do?
         */
        // As of 2015-07-30, pasting into Frhed works on Windows. Pasting into
        // Hex Editor Neo and HxD does not.
        mime_data->setData("application/octet-stream", data);
        qApp->clipboard()->setMimeData(mime_data);
    }
}

void ByteViewTab::copyEscapedString(QByteArray data)
{
    QString clipboard_text;

    // Beginning quote
    clipboard_text += QString("\"");

    for (int i = 0; i < data.count(); i++)
    {
        // Terminate this line if it has reached 16 bytes,
        // unless it is also the very last byte in the data,
        // as the termination after this for loop will take
        // care of that.
        if (i % 16 == 0 && i != 0 && i != data.count() - 1) {
            clipboard_text += QString("\" \\\n\"");
        }
        clipboard_text += QString("\\x%1").arg(data[i], 2, 16, QChar('0'));
    }
    // End quote
    clipboard_text += QString("\"\n");

    if (!clipboard_text.isEmpty()) {
        qApp->clipboard()->setText(clipboard_text);
    }
}

ByteViewText * ByteViewTab::findByteViewTextForTvb(tvbuff_t * search_tvb, int * idx)
{
    int cnt = 0;
    ByteViewText * item = 0;

    if ( ! search_tvb )
        return item;

    item = qobject_cast<ByteViewText*>(widget(cnt));

    while ( item ) {
        if ( ! item->property(tvb_data_property).isNull() )
        {
            tvbuff_t * stored = VariantPointer<tvbuff_t>::asPtr(item->property(tvb_data_property));
            if ( stored && stored == search_tvb )
            {
                if ( idx )
                    *idx = cnt;
                break;
            }
        }
        item = qobject_cast<ByteViewText*>(widget(++cnt));
    }

    return item;
}

void ByteViewTab::copyData(ByteViewTab::copyDataType copy_type, field_info *fi)
{
    ByteViewText *byte_view_text = 0;

    if ( fi )
        byte_view_text = findByteViewTextForTvb(fi->ds_tvb);

    if (!byte_view_text) return;

    QByteArray data = byte_view_text->viewData();

    if ( data.isEmpty() == 0 )
        return;

    if ( fi && fi->start >= 0 && fi->length > 0 && fi->length <= data.count() )
        data = data.right(fi->length);

    if ( data.isEmpty() ) return;

    switch (copy_type) {
    case copyDataHexTextDump:
        copyHexTextDump(data, true);
        break;
    case copyDataHexDump:
        copyHexTextDump(data, false);
        break;
    case copyDataPrintableText:
        copyPrintableText(data);
        break;
    case copyDataHexStream:
        copyHexStream(data);
        break;
    case copyDataBinary:
        copyBinary(data);
        break;
    case copyDataEscapedString:
        copyEscapedString(data);
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

        fi = VariantPointer<field_info>::asPtr(current->data(0, Qt::UserRole));

        ByteViewText *byte_view_text = 0;
        int idx = 0;

        if ( fi )
            byte_view_text = findByteViewTextForTvb(fi->ds_tvb, &idx);

        if (byte_view_text) {
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
                parent_fi = VariantPointer<field_info>::asPtr(parent->data(0, Qt::UserRole));
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
            byte_view_text->markProtocol(p_start, p_end);

            // Field bytes
            byte_view_text->markField(f_start, f_end);

            // Appendix (trailer) bytes
            byte_view_text->markAppendix(fa_start, fa_end);

            setCurrentIndex(idx);
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
