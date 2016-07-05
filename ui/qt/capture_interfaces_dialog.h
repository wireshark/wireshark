/* capture_interfaces_dialog.h
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


#ifndef CAPTURE_INTERFACES_DIALOG_H
#define CAPTURE_INTERFACES_DIALOG_H

#include <config.h>

#ifdef HAVE_LIBPCAP

#include "geometry_state_dialog.h"
#include <QPushButton>

typedef struct if_stat_cache_s if_stat_cache_t;

#include "interface_tree.h"
#include "preferences_dialog.h"

namespace Ui {
class CaptureInterfacesDialog;
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

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    void setTree(QTreeWidget* tree) { tree_ = tree; }
    bool eventFilter(QObject *object, QEvent *event);

signals:
    void filterChanged(const QString filter);

private slots:
    void linkTypeChanged(QString selected_link_type);
    void snapshotLengthChanged(int value);
    void bufferSizeChanged(int value);
};

class CaptureInterfacesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit CaptureInterfacesDialog(QWidget *parent = 0);
    ~CaptureInterfacesDialog();

    void setTab(int index);
    void updateInterfaces();

protected:
    virtual void showEvent(QShowEvent *);

private slots:
    void on_capturePromModeCheckBox_toggled(bool checked);
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
    void interfaceSelected();
    void filterEdited();
    void updateWidgets();
    void updateStatistics(void);
    void refreshInterfaceList();
    void updateLocalInterfaces();
    void browseButtonClicked();
    void interfaceItemChanged(QTreeWidgetItem *item, int column);
    void changeEvent(QEvent* event);

signals:
    void startCapture();
    void stopCapture();
    void getPoints(int row, PointList *pts);
    void setSelectedInterfaces();
    void setFilterValid(bool valid, const QString capture_filter);
    void interfacesChanged();
    void ifsChanged();
    void interfaceListChanged();
    void captureFilterTextEdited(const QString & text);

private:
    Ui::CaptureInterfacesDialog *ui;

    if_stat_cache_t *stat_cache_;
    QTimer *stat_timer_;
    InterfaceTreeDelegate interface_item_delegate_;

    interface_t *getDeviceByName(const QString device_name);
    bool saveOptionsToPreferences();
    void updateSelectedFilter();
};

#endif /* HAVE_LIBPCAP */

#endif // CAPTURE_INTERFACES_DIALOG_H

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
