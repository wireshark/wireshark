/* interface_frame.h
 * Display of interfaces, including their respective data, and the
 * capability to filter interfaces by type
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

#ifndef INTERFACE_FRAME_H
#define INTERFACE_FRAME_H

#include <config.h>

#include <glib.h>

#include "ui/qt/accordion_frame.h"

#include "ui/qt/interface_tree_model.h"
#include "ui/qt/interface_sort_filter_model.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QAbstractButton>
#include <QTimer>
#include <QMenu>
#include <QPushButton>

namespace Ui {
class InterfaceFrame;
}

class InterfaceFrame : public AccordionFrame
{
    Q_OBJECT
public:
    explicit InterfaceFrame(QWidget *parent = 0);
    ~InterfaceFrame();

    int interfacesHidden();

    QMenu * getSelectionMenu();
    int interfacesPresent();
    void ensureSelectedInterface();

Q_SIGNALS:
    void showExtcapOptions(QString device_name);
    void startCapture();
    void itemSelectionChanged();
    void typeSelectionChanged();

public slots:
    void updateSelectedInterfaces();
    void interfaceListChanged();
    void toggleHiddenInterfaces();
#ifdef HAVE_PCAP_REMOTE
    void toggleRemoteInterfaces();
#endif
    void getPoints(int idx, PointList *pts);

protected:
    void hideEvent(QHideEvent *evt);
    void showEvent(QShowEvent *evt);

private:

    void resetInterfaceTreeDisplay();

    Ui::InterfaceFrame *ui;

    InterfaceSortFilterModel * proxyModel;
    InterfaceTreeModel * sourceModel;

    QMap<int, QString> ifTypeDescription;

#ifdef HAVE_LIBPCAP
    QTimer *stat_timer_;
#endif // HAVE_LIBPCAP

private slots:
    void interfaceTreeSelectionChanged(const QItemSelection & selected, const QItemSelection & deselected);

    void on_interfaceTree_doubleClicked(const QModelIndex &index);
#if defined(HAVE_EXTCAP) && defined(HAVE_LIBPCAP)
    void on_interfaceTree_clicked(const QModelIndex &index);
#endif

    void updateStatistics(void);
    void actionButton_toggled(bool checked);
    void triggeredIfTypeButton();
};

#endif // INTERFACE_FRAME_H

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
