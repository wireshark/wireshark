/* main_welcome.cpp
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

#include <glib.h>

#include "config.h"

#include <epan/prefs.h>

#include "version_info.h"

#include "main_welcome.h"

#include "wireshark_application.h"
#include "interface_tree.h"

#include <QWidget>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QPainter>
#include <QPen>
#include <QResizeEvent>
#include <QGraphicsBlurEffect>
#include <QLabel>
#include <QHeaderView>
#include <QFont>

//MWOverlay::MWOverlay(QWidget *parent) : QWidget(parent)
//{
//    setPalette(Qt::transparent);
//    setAttribute(Qt::WA_TransparentForMouseEvents);

//    QGraphicsBlurEffect *blur = new QGraphicsBlurEffect(this);
//    setGraphicsEffect(blur);
//}

//void MWOverlay::paintEvent(QPaintEvent *event)
//{
//    QPainter painter(this);
//    painter.setRenderHint(QPainter::Antialiasing);

//    QRect border = rect();
////    g_log(NULL, G_LOG_LEVEL_DEBUG, "rect pre: %d %d %d %d", border.top(), border.left(), border.bottom(), border.right());
//    border.setWidth(border.width() - 8);
//    border.moveLeft(4);
//    border.setHeight(border.height() - 8);
//    border.moveTop(4);
////    g_log(NULL, G_LOG_LEVEL_DEBUG, "rect post: %d %d %d %d", border.top(), border.left(), border.bottom(), border.right());
//    QPen pen;
//    pen.setWidth(8);
//    pen.setColor(QColor(60, 60, 60, 80));
//    painter.setPen(pen);
////    painter.setBrush(Qt::blue);
//    painter.drawRect(border);
//}


MainWelcome::MainWelcome(QWidget *parent) :
    QFrame(parent)
{
    QGridLayout *grid = new QGridLayout(this);
    QVBoxLayout *column;
    QLabel *heading;
    InterfaceTree *iface_tree;

    setStyleSheet(
            "QFrame {"
            "  background: palette(base);"
            " }"
            );

//    grid->setContentsMargins (0, 0, 0, 0);
    grid->setColumnStretch(0, 60);

    // Banner row, 3 column span
    QString banner = QString("Wireshark");
    heading = new QLabel(banner);
    grid->addWidget(heading, 0, 0, 1, 3);

    // Column 1: Capture
    column = new QVBoxLayout();
    grid->addLayout(column, 1, 0, Qt::AlignTop);

    heading = new QLabel("<h1>Capture</h1>");
    column->addWidget(heading);

    iface_tree = new InterfaceTree(this);
    column->addWidget(iface_tree);

    heading = new QLabel("<h1>Capture Help</h1>");
    column->addWidget(heading);

    // Column 2: Files
    column = new QVBoxLayout();
    grid->addLayout(column, 1, 1, Qt::AlignTop);
    grid->setColumnStretch(1, 70);

    heading = new QLabel("<h1>Files</h1>");
    column->addWidget(heading);

    m_recent_files.setStyleSheet(
            "QListWidget {"
            "  border: 0;"
            "}"
            );
    column->addWidget(&m_recent_files);
    connect(wsApp, SIGNAL(updateRecentItemStatus(const QString &, qint64, bool)), this, SLOT(updateRecentFiles()));
    connect(&m_recent_files, SIGNAL(itemActivated(QListWidgetItem *)), this, SLOT(openRecentItem(QListWidgetItem *)));
    updateRecentFiles();

    // Column 3: Online Resources
    column = new QVBoxLayout();
    grid->addLayout(column, 1, 2, Qt::AlignTop);
    grid->setColumnStretch(2, 50);

    heading = new QLabel("<h1>Online</h1>");
    column->addWidget(heading);

    // Sigh. This doesn't work in Qt 4.7 on OS X.
//    QGraphicsBlurEffect *effect = new QGraphicsBlurEffect(this) ;
//    effect->setBlurRadius(10);
//    effect->setBlurHints(QGraphicsBlurEffect::QualityHint);
//    setGraphicsEffect( effect );
//    overlay = new MWOverlay(this);

}


void MainWelcome::updateRecentFiles() {
    QString itemLabel;
    QListWidgetItem *rfItem;
    QFont rfFont;

    int rfRow = 0;
    foreach (recent_item_status *ri, wsApp->recent_item_list()) {
        itemLabel = ri->filename;

        if (rfRow >= m_recent_files.count()) {
            m_recent_files.addItem(itemLabel);
        }

        itemLabel.append(" (");
        if (ri->accessible) {
            if (ri->size/1024/1024/1024 > 10) {
                itemLabel.append(QString("%1 GB)").arg(ri->size/1024/1024/1024));
            } else if (ri->size/1024/1024 > 10) {
                itemLabel.append(QString("%1 MB)").arg(ri->size/1024/1024));
            } else if (ri->size/1024 > 10) {
                itemLabel.append(QString("%1 KB)").arg(ri->size/1024));
            } else {
                itemLabel.append(QString("%1 Bytes").arg(ri->size));
            }
        } else {
            itemLabel.append("not found)");
        }
        rfFont.setItalic(!ri->accessible);
        rfItem = m_recent_files.item(rfRow);
        rfItem->setText(itemLabel);
        rfItem->setData(Qt::UserRole, ri->filename);
        rfItem->setFlags(ri->accessible ? Qt::ItemIsSelectable | Qt::ItemIsEnabled : Qt::NoItemFlags);
        rfItem->setFont(rfFont);
        rfRow++;
    }

    while (m_recent_files.count() > prefs.gui_recent_files_count_max) {
        m_recent_files.takeItem(m_recent_files.count());
    }
}

void MainWelcome::openRecentItem(QListWidgetItem *item) {
    QString cfPath = item->data(Qt::UserRole).toString();
    emit recentFileActivated(cfPath);
}

//void MainWelcome::resizeEvent(QResizeEvent *event)
//{
//    overlay->resize(event->size());
////    event->accept();

//    QFrame::resizeEvent(event);
//}
