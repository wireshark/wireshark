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

#include "config.h"

#ifdef HAVE_LIBPCAP

#include <QDialog>
#include <QPushButton>
#include <QTableWidget>

typedef struct if_stat_cache_s if_stat_cache_t;

#include "interface_tree.h"
#include "preferences_dialog.h"

/*
 * Symbolic names for column indices.
 */
enum
{
    INTERFACE = 0,
    TRAFFIC,
    LINK,
    PMODE,
    SNAPLEN,
    BUFFER,
    MONITOR,
    FILTER,
    NUM_COLUMNS
};


namespace Ui {
class CaptureInterfacesDialog;
}

#include <QStyledItemDelegate>

class TbInterfacesDelegate : public QStyledItemDelegate
{
    Q_OBJECT
private:
    QTableWidget* table;

public:
    TbInterfacesDelegate(QObject *parent = 0);
    ~TbInterfacesDelegate();

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    void setTable(QTableWidget* tb) { table = tb; };
    bool eventFilter(QObject *object, QEvent *event);

private slots:
    void pmode_changed(QString index);
#if defined (HAVE_PCAP_CREATE)
    void monitor_changed(QString index);
#endif
    void link_changed(QString index);
    void snaplen_changed(int value);
    void buffer_changed(int value);
};

class CaptureInterfacesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CaptureInterfacesDialog(QWidget *parent = 0);
    ~CaptureInterfacesDialog();

    void SetTab(int index);
    void UpdateInterfaces();

private slots:
    void on_capturePromModeCheckBox_toggled(bool checked);
    void on_gbStopCaptureAuto_toggled(bool checked);
    void on_cbUpdatePacketsRT_toggled(bool checked);
    void on_cbAutoScroll_toggled(bool checked);
    void on_gbNewFileAuto_toggled(bool checked);
    void on_cbExtraCaptureInfo_toggled(bool checked);
    void on_cbResolveMacAddresses_toggled(bool checked);
    void on_compileBPF_clicked();
    void on_cbResolveNetworkNames_toggled(bool checked);
    void on_cbResolveTransportNames_toggled(bool checked);
    void start_button_clicked();
    void on_buttonBox_rejected();
    void on_buttonBox_helpRequested();
    void tableItemClicked(QTableWidgetItem * item);
    void tableSelected();
    void updateStatistics(void);
    void allFilterChanged();

signals:
    void startCapture();
    void stopCapture();
    void getPoints(int row, PointList *pts);
    void setSelectedInterfaces();
    void setFilterValid(bool valid);
    void interfacesChanged();

private:
    Ui::CaptureInterfacesDialog *ui;
    Qt::CheckState m_pressedItemState;

    QPushButton *start_bt_;
    QPushButton *stop_bt_;
    if_stat_cache_t *stat_cache_;
    QTimer *stat_timer_;
    TbInterfacesDelegate combobox_item_delegate_;
    QMap<int, int> deviceMap;

    void saveOptionsToPreferences();
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
