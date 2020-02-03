/* interface_frame.h
 * Display of interfaces, including their respective data, and the
 * capability to filter interfaces by type
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_FRAME_H
#define INTERFACE_FRAME_H

#include <config.h>

#include <glib.h>

#include <ui/qt/models/info_proxy_model.h>
#include <ui/qt/models/interface_tree_model.h>
#include <ui/qt/models/interface_sort_filter_model.h>

#include <QFrame>
#include <QHBoxLayout>
#include <QAbstractButton>
#include <QTimer>
#include <QMenu>
#include <QPushButton>

namespace Ui {
class InterfaceFrame;
}

class InterfaceFrame : public QFrame
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
    void showRunOnFile();
    void showContextMenu(QPoint pos);

protected:
    void hideEvent(QHideEvent *evt);
    void showEvent(QShowEvent *evt);

private:

    void resetInterfaceTreeDisplay();
    bool haveLocalCapturePermissions() const;

    Ui::InterfaceFrame *ui;

    InterfaceSortFilterModel proxy_model_;
    InterfaceTreeModel source_model_;
    InfoProxyModel info_model_;

    QMap<int, QString> ifTypeDescription;

#ifdef HAVE_LIBPCAP
    QTimer *stat_timer_;
#endif // HAVE_LIBPCAP

private slots:
    void interfaceTreeSelectionChanged(const QItemSelection & selected, const QItemSelection & deselected);

    void on_interfaceTree_doubleClicked(const QModelIndex &index);
#ifdef HAVE_LIBPCAP
    void on_interfaceTree_clicked(const QModelIndex &index);
#endif

    void updateStatistics(void);
    void actionButton_toggled(bool checked);
    void triggeredIfTypeButton();
    void on_warningLabel_linkActivated(const QString &link);
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
