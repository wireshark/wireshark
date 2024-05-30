/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef CAPTURE_OPTIONS_DIALOG_H
#define CAPTURE_OPTIONS_DIALOG_H

#include <config.h>

#ifdef HAVE_LIBPCAP

#include <ui/qt/models/interface_tree_model.h>

#include "geometry_state_dialog.h"
#include <QPushButton>
#include <QTreeWidget>

typedef struct if_stat_cache_s if_stat_cache_t;

namespace Ui {
class CaptureOptionsDialog;
}

#include <QStyledItemDelegate>

class InterfaceTreeDelegate : public QStyledItemDelegate
{
    Q_OBJECT
private:
    QTreeWidget* tree_;

public:
    InterfaceTreeDelegate(QObject *parent = 0);
    ~InterfaceTreeDelegate();

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &idx) const;
    void setTree(QTreeWidget* tree) { tree_ = tree; }
    bool eventFilter(QObject *object, QEvent *event);

signals:
    void filterChanged(const QString filter);

private slots:
    void linkTypeChanged(const QString selected_link_type);
    void snapshotLengthChanged(int value);
    void bufferSizeChanged(int value);
};

class CaptureOptionsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit CaptureOptionsDialog(QWidget *parent = 0);
    ~CaptureOptionsDialog();

    void updateInterfaces();

public slots:
    void interfaceSelected();

protected:
    virtual void showEvent(QShowEvent *);

private slots:
    void on_capturePromModeCheckBox_toggled(bool checked);
    void on_captureMonitorModeCheckBox_toggled(bool checked);
    void on_gbStopCaptureAuto_toggled(bool checked);
    void on_cbUpdatePacketsRT_toggled(bool checked);
    void on_cbAutoScroll_toggled(bool checked);
    void on_gbNewFileAuto_toggled(bool checked);
    void on_cbExtraCaptureInfo_toggled(bool checked);
    void on_cbResolveMacAddresses_toggled(bool checked);
    void on_compileBPF_clicked();
    void on_manageButton_clicked();
    void on_cbResolveNetworkNames_toggled(bool checked);
    void on_cbResolveTransportNames_toggled(bool checked);
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_buttonBox_helpRequested();
    void filterEdited();
    void updateWidgets();
    void updateStatistics(void);
    void refreshInterfaceList();
    void updateLocalInterfaces();
    void browseButtonClicked();
    void interfaceItemChanged(QTreeWidgetItem *item, int column);
    void itemClicked(QTreeWidgetItem *item, int column);
    void itemDoubleClicked(QTreeWidgetItem *item, int column);
    void changeEvent(QEvent* event);
    void tempDirBrowseButtonClicked();
    void MBComboBoxIndexChanged(int index);
    void stopMBComboBoxIndexChanged(int index);

signals:
    void startCapture();
    void stopCapture();
    void setSelectedInterfaces();
    void setFilterValid(bool valid, const QString capture_filter);
    void interfacesChanged();
    void ifsChanged();
    void interfaceListChanged();
    void captureFilterTextEdited(const QString & text);
    void showExtcapOptions(QString &device_name, bool startCaptureOnClose);

private:
    Ui::CaptureOptionsDialog *ui;

    if_stat_cache_t *stat_cache_;
    QTimer *stat_timer_;
    InterfaceTreeDelegate interface_item_delegate_;

    interface_t *getDeviceByName(const QString device_name);
    bool saveOptionsToPreferences();
    void updateSelectedFilter();

    void updateGlobalDeviceSelections();
    void updateFromGlobalDeviceSelections();
};

#endif /* HAVE_LIBPCAP */

#endif // CAPTURE_OPTIONS_DIALOG_H
