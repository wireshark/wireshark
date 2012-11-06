/* byte_view_tab.cpp
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

#include "byte_view_tab.h"
#include "byte_view_text.h"
#include <QTabBar>
#include <QTreeWidgetItem>

ByteViewTab::ByteViewTab(QWidget *parent) :
    QTabWidget(parent)
{
    setAccessibleName(tr("Packet bytes"));
    addTab();
}

#include <QDebug>
void ByteViewTab::addTab(const char *name, tvbuff_t *tvb, proto_tree *tree, QTreeWidget *protoTree, packet_char_enc encoding) {
    ByteViewText *byte_view_text = new ByteViewText(this, tvb, tree, protoTree, encoding);

    byte_view_text->setAccessibleName(name);
    QTabWidget::addTab(byte_view_text, name);
}

void ByteViewTab::clear()
{
    while (currentWidget()) {
        delete currentWidget();
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
                guint32 bmask = 0x00;
                int fa_start = -1, fa_end = -1, fa_len = -1;
                int p_start = -1, p_end = -1, p_len = -1;
                guint len = tvb_length(fi->ds_tvb);

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
                    /* In the hex view, only highlight the target bytes or string. The entire
                       field can then be displayed by clicking on any of the bytes in the field. */
                    if (cap_file_->hex) {
                        f_len = (int)strlen(cap_file_->sfilter)/2;
                    } else {
                        f_len = (int)strlen(cap_file_->sfilter);
                    }
                    f_start = cap_file_->search_pos - (f_len-1);
                } else {
                    f_start = fi->start;
                    f_len = fi->length;
                }

                /* bmask = finfo->hfinfo->bitmask << finfo->hfinfo->bitshift; */ /* (value & mask) >> shift */
                if (fi->hfinfo) bmask = fi->hfinfo->bitmask;
                fa_start = fi->appendix_start;
                fa_len = fi->appendix_length;

                if (!FI_GET_FLAG(fi, FI_LITTLE_ENDIAN) &&
                    !FI_GET_FLAG(fi, FI_BIG_ENDIAN)) {
                    /* unknown endianess - disable mask */
                    bmask = 0x00;
                }

                if (bmask == 0x00) {
                    int bito = FI_GET_BITS_OFFSET(fi);
                    int bitc = FI_GET_BITS_SIZE(fi);
                    int bitt = bito + bitc;

                    /* construct mask using bito & bitc */
                    /* XXX, mask has only 32 bit, later we can store bito&bitc, and use them (which should be faster) */
                    if (bitt > 0 && bitt < 32) {

                        bmask = ((1 << bitc) - 1) << ((8-bitt) & 7);
                    }
                }

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
                    bmask = 0x00;
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

                byte_view_text->renderBytes();

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
