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
#include <QResizeEvent>
#ifndef Q_WS_MAC
#include <QGraphicsBlurEffect>
#endif

MainWelcome::MainWelcome(QWidget *parent) :
    QFrame(parent),
    welcome_ui_(new Ui::MainWelcome),
    splash_overlay_(NULL)

{
//    QGridLayout *grid = new QGridLayout(this);
//    QVBoxLayout *column;
//    QLabel *heading;

    welcome_ui_->setupUi(this);

    welcome_ui_->mainWelcomeBanner->setText("Wireshark<br><small>" VERSION "</small>");

    task_list_ = welcome_ui_->taskList;
    recent_files_ = welcome_ui_->recentList;

    setStyleSheet(QString(
                      "MainWelcome {"
                      "  padding: 2em;"
                      " }"
                      "MainWelcome, QAbstractItemView {"
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
    welcome_ui_->interfaceTree->setAttribute(Qt::WA_MacShowFocusRect, false);
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
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(destroySplashOverlay()));
    connect(task_list_, SIGNAL(itemSelectionChanged()), this, SLOT(showTask()));
    connect(welcome_ui_->interfaceTree, SIGNAL(itemDoubleClicked(QTreeWidgetItem*,int)),
            this, SLOT(interfaceDoubleClicked(QTreeWidgetItem*,int)));
    connect(recent_files_, SIGNAL(itemActivated(QListWidgetItem *)), this, SLOT(openRecentItem(QListWidgetItem *)));
    updateRecentFiles();

    task_list_->setCurrentRow(0);

#ifndef Q_WS_MAC
    // This crashes with Qt 4.8.3 on OS X.
    QGraphicsBlurEffect *blur = new QGraphicsBlurEffect(welcome_ui_->childContainer);
    blur->setBlurRadius(1.3);
    welcome_ui_->childContainer->setGraphicsEffect(blur);
#endif

    splash_overlay_ = new SplashOverlay(this);
}

void MainWelcome::destroySplashOverlay()
{
#ifndef Q_WS_MAC
    welcome_ui_->childContainer->setGraphicsEffect(NULL);
#endif
    delete splash_overlay_;
    splash_overlay_ = NULL;
}

void MainWelcome::showTask() {
    welcome_ui_->taskStack->setCurrentIndex(task_list_->currentRow());
}

void MainWelcome::interfaceDoubleClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column);

    if (item) {
        emit startCapture();
    }
}

void MainWelcome::updateRecentFiles() {
    QString itemLabel;
    QListWidgetItem *rfItem;
    QFont rfFont;

    int rfRow = 0;
    foreach (recent_item_status *ri, wsApp->recentItems()) {
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

void MainWelcome::resizeEvent(QResizeEvent *event)
{
    if (splash_overlay_)
        splash_overlay_->resize(event->size());
//    event->accept();

    QFrame::resizeEvent(event);
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
