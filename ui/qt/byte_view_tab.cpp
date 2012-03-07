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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

void ByteViewTab::addTab(const char *name, tvbuff_t *tvb, proto_tree *tree, QTreeWidget *protoTree, unsigned int encoding) {
    ByteViewText *byteViewText = new ByteViewText(this, tvb, tree, protoTree, encoding);

    byteViewText->setAccessibleName(name);
    QTabWidget::addTab(byteViewText, name);
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
    if (current) {
        field_info *fi;

        QVariant v = current->data(0, Qt::UserRole);
        fi = (field_info *) v.value<void *>();
//        g_log(NULL, G_LOG_LEVEL_DEBUG, "fi selected %p", fi);

        int i = 0;
        ByteViewText *byteViewText = dynamic_cast<ByteViewText*>(widget(i));
        while (byteViewText) {
            if (byteViewText->hasDataSource(fi->ds_tvb)) {
                QTreeWidgetItem *parent = current->parent();
                field_info *parent_fi = NULL;
                while (parent && parent->parent()) {
                    parent = parent->parent();
                }
                if (parent) {
                    v = parent->data(0, Qt::UserRole);
                    parent_fi = (field_info *) v.value<void *>();
                }
                if (parent_fi && parent_fi->ds_tvb == fi->ds_tvb) {
                    byteViewText->highlight(parent_fi->start, parent_fi->length, true);
                } else {
                    byteViewText->highlight(0, 0, true);
                }
                byteViewText->highlight(fi->start, fi->length);
                setCurrentIndex(i);
            }
            byteViewText = dynamic_cast<ByteViewText*>(widget(++i));
        }
    }
}
