/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#pragma once

#include <config.h>

#ifdef HAVE_LIBPCAP

#include <ui/qt/models/interface_tree_model.h>
#include <ui/qt/models/interface_tree_cache_model.h>
#include <ui/qt/models/interface_sort_filter_model.h>

#include "geometry_state_dialog.h"
#include <QPushButton>
#include <QTreeView>

namespace Ui {
class CaptureOptionsDialog;
}

#include <QStyledItemDelegate>

/**
 * @brief Provides editors for the interface tree's editable columns (link-layer
 * header, snapshot length, buffer size, capture filter).
 *
 * Unlike a stock QStyledItemDelegate, editor commits are written straight to
 * @c cache_model_ rather than through the view's bound model: the cache model
 * doesn't (yet) surface Qt::EditRole for these columns, so createEditor()
 * populates editors directly from the underlying interface_t, and
 * setEditorData() is a no-op to avoid clobbering that.
 */
class InterfaceTreeDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    InterfaceTreeDelegate(InterfaceTreeCacheModel *cache_model, InterfaceSortFilterModel *proxy_model, QObject *parent = nullptr);

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &idx) const override;
    void setEditorData(QWidget *editor, const QModelIndex &idx) const override;
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &idx) const override;
    bool eventFilter(QObject *object, QEvent *event) override;

signals:
    void filterChanged(const QString filter);

private:
    InterfaceTreeCacheModel *cache_model_;
    InterfaceSortFilterModel *proxy_model_;
};

class CaptureOptionsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit CaptureOptionsDialog(QWidget *parent = 0);
    ~CaptureOptionsDialog();

    void updateInterfaces(capture_options* capture_opts);

public slots:
    void interfaceSelected();

protected:
    virtual void showEvent(QShowEvent *) override;

private slots:
    /** @brief Subscribes to the window's InterfaceListManager's statistics updates. */
    void connectInterfaceListManager();
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
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_cbResolveNetworkNames_toggled(bool checked);
    void on_cbResolveTransportNames_toggled(bool checked);
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_buttonBox_helpRequested();
    /**
     * @brief Enable the choice of process information and show its warning as appropriate.
     */
    void updateProcessInfoWidgets();
    void filterEdited();
    void updateWidgets();
    void refreshInterfaceList();
    void browseButtonClicked();
    void itemClicked(const QModelIndex &index);
    void itemDoubleClicked(const QModelIndex &index);
    void changeEvent(QEvent* event) override;
    void tempDirBrowseButtonClicked();
    void MBComboBoxIndexChanged(int index);
    void stopMBComboBoxIndexChanged(int index);

signals:
    void startCapture();
    void stopCapture();
    void setSelectedInterfaces();
    void setFilterValid(bool valid, const QString capture_filter);
    void interfacesChanged();
    void captureFilterTextEdited(const QString & text);
    void showExtcapOptions(QString &device_name, bool startCaptureOnClose);

private:
    Ui::CaptureOptionsDialog *ui;

    InterfaceTreeCacheModel *cache_model_;
    InterfaceSortFilterModel *proxy_model_;
    InterfaceTreeModel *source_model_;
    InterfaceTreeDelegate *interface_item_delegate_;

    /* Proxy model column indices. Fixed for the dialog's lifetime. */
    int col_extcap_;
    int col_interface_;
    int col_traffic_;
    int col_link_;
    int col_pmode_;
    int col_snaplen_;
    int col_buffer_;
    int col_monitor_;
    int col_optimize_;
    int col_filter_;

    bool saveOptionsToPreferences(capture_options* capture_opts);
    void updateSelectedFilter();

    void updateGlobalDeviceSelections();
    void updateFromGlobalDeviceSelections();
};

#endif /* HAVE_LIBPCAP */
