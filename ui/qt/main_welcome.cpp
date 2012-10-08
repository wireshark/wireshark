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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib.h>

#include "config.h"

#include <epan/prefs.h>

#include "version_info.h"

#include "main_welcome.h"
#include "ui_main_welcome.h"
#include "tango_colors.h"

#include "wireshark_application.h"
#include "interface_tree.h"

#include <QWidget>

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
    QFrame(parent),
    welcome_ui_(new Ui::MainWelcome)

{
//    QGridLayout *grid = new QGridLayout(this);
//    QVBoxLayout *column;
//    QLabel *heading;
#ifdef Q_WS_MAC
    InterfaceTree *iface_tree;
#endif

    welcome_ui_->setupUi(this);
    task_list_ = welcome_ui_->taskList;
#ifdef Q_WS_MAC
    iface_tree = welcome_ui_->interfaceTree;
#endif
    recent_files_ = welcome_ui_->recentList;

    setStyleSheet(QString(
                      "MainWelcome {"
                      "  padding: 2em;"
                      " }"
                      "QWidget {"
                      "  background-color: white;"
                      "  color: #%1;"
                      " }"
                      "QListWidget {"
                      "  border: 0;"
//                      "  border: 1px dotted blue;"
                      "}"
//                      "QListWidget::focus {"
//                      "  border: 1px dotted palette(mid);"
//                      "}"
                      "QListWidget::item::hover {"
                      "  background-color: #%3;"
                      "  color: #%4;"
                      "}"
                      "QListWidget::item:selected {"
                      "  background-color: #%2;"
                      "  color: white;"
                      "}"
                      "QTreeWidget {"
                      "  border: 0;"
//                      "  border: 1px dotted green;"
                      "}"
//                      "QTreeWidget::focus {"
//                      "  border: 1px dotted palette(mid);"
//                      "  background-color: palette(midlight);"
//                      "}"
                      )
                      .arg(tango_aluminium_6, 6, 16, QChar('0'))   // Text color
                      .arg(tango_sky_blue_4,  6, 16, QChar('0'))   // Selected background
                      .arg(tango_aluminium_2, 6, 16, QChar('0'))   // Hover background
                      .arg(tango_aluminium_6, 6, 16, QChar('0'))   // Hover foreground
                );

#ifdef Q_WS_MAC
    recent_files_->setAttribute(Qt::WA_MacShowFocusRect, false);
    welcome_ui_->taskList->setAttribute(Qt::WA_MacShowFocusRect, false);
    iface_tree->setAttribute(Qt::WA_MacShowFocusRect, false);
#endif

    task_list_->setStyleSheet(
                "QListWidget {"
                "  margin-right: 2em;"
                "}"
                "QListWidget::item {"
                "  padding: 1.5em;"
                "  margin-bottom: 1em;"
                "  border-radius: 0.5em;"
                "}"
//                "QListWidget::item:hover {"
//                "  background-color: palette(midlight);"
//                "  background-color: palette(midlight);"
//                "}"
                );

    recent_files_->setStyleSheet(
            "QListWidget::item {"
            "  padding-top: 0.2em;"
            "  padding-bottom: 0.2em;"
            "}"
            "QListWidget::item::first {"
            "  padding-top: 0;"
            "}"
            "QListWidget::item::last {"
            "  padding-bottom: 0;"
            "}"
            );
    recent_files_->setTextElideMode(Qt::ElideLeft);

    connect(wsApp, SIGNAL(updateRecentItemStatus(const QString &, qint64, bool)), this, SLOT(updateRecentFiles()));
    connect(task_list_, SIGNAL(itemSelectionChanged()), this, SLOT(showTask()));
    connect(recent_files_, SIGNAL(itemActivated(QListWidgetItem *)), this, SLOT(openRecentItem(QListWidgetItem *)));
    updateRecentFiles();

    task_list_->setCurrentRow(0);
}

void MainWelcome::showTask() {
    welcome_ui_->taskStack->setCurrentIndex(task_list_->currentRow());
}

void MainWelcome::updateRecentFiles() {
    QString itemLabel;
    QListWidgetItem *rfItem;
    QFont rfFont;

    int rfRow = 0;
    foreach (recent_item_status *ri, wsApp->recent_item_list()) {
        itemLabel = ri->filename;

        if (rfRow >= recent_files_->count()) {
            recent_files_->addItem(itemLabel);
        }

        itemLabel.append(" (");
        if (ri->accessible) {
            if (ri->size/1024/1024/1024 > 10) {
                itemLabel.append(QString("%1 GB").arg(ri->size/1024/1024/1024));
            } else if (ri->size/1024/1024 > 10) {
                itemLabel.append(QString("%1 MB").arg(ri->size/1024/1024));
            } else if (ri->size/1024 > 10) {
                itemLabel.append(QString("%1 KB").arg(ri->size/1024));
            } else {
                itemLabel.append(QString("%1 Bytes").arg(ri->size));
            }
        } else {
            itemLabel.append(tr("not found"));
        }
        itemLabel.append(")");
        rfFont.setItalic(!ri->accessible);
        rfItem = recent_files_->item(rfRow);
        rfItem->setText(itemLabel);
        rfItem->setData(Qt::UserRole, ri->filename);
        rfItem->setFlags(ri->accessible ? Qt::ItemIsSelectable | Qt::ItemIsEnabled : Qt::NoItemFlags);
        rfItem->setFont(rfFont);
        rfRow++;
    }

    while (recent_files_->count() > (int) prefs.gui_recent_files_count_max) {
        recent_files_->takeItem(recent_files_->count());
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
