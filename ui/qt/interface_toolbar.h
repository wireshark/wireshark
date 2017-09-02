/* interface_toolbar.h
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

#ifndef INTERFACE_TOOLBAR_H
#define INTERFACE_TOOLBAR_H

#include <glib.h>

#include "ui/iface_toolbar.h"
#include "funnel_text_dialog.h"
#include "interface_toolbar_reader.h"

#include <QFrame>
#include <QList>
#include <QMap>
#include <QString>


namespace Ui {
class InterfaceToolbar;
}

struct interface_values
{
    QThread *reader_thread;
    int out_fd;
    QMap<int, QByteArray> value;
    QMap<int, bool> value_changed;
    QMap<int, QList<QByteArray> > list;
    QMap<int, FunnelTextDialog *> log_dialog;
    QMap<int, QString> log_text;
    QMap<int, bool> widget_disabled;
};

class InterfaceToolbar : public QFrame
{
    Q_OBJECT

public:
    explicit InterfaceToolbar(QWidget *parent = 0, const iface_toolbar *toolbar = NULL);
    ~InterfaceToolbar();

    void startCapture(GArray *ifaces);
    void stopCapture();
    bool hasInterface(QString ifname);

public slots:
    void interfaceListChanged();
    void controlReceived(QString ifname, int num, int command, QByteArray message);

signals:
    void closeReader();

private slots:
    void startReaderThread(QString ifname, void *control_in);
    void updateWidgets();

    void onControlButtonPressed();
    void onLogButtonPressed();
    void onHelpButtonPressed();
    void onRestoreButtonPressed();
    void onCheckBoxChanged(int state);
    void onComboBoxChanged(int idx);
    void onLineEditChanged();

    void closeLog();

    void on_interfacesComboBox_currentIndexChanged(const QString &ifname);

private:
    void initializeControls(const iface_toolbar *toolbar);
    void setDefaultValue(int num, const QByteArray &value);
    void sendChangedValues(QString ifname);
    QWidget *createCheckbox(iface_toolbar_control *control);
    QWidget *createButton(iface_toolbar_control *control);
    QWidget *createSelector(iface_toolbar_control *control);
    QWidget *createString(iface_toolbar_control *control);
    void controlSend(QString ifname, int num, int type, const QByteArray &payload);
    void setWidgetValue(QWidget *widget, int type, QByteArray payload);
    void setInterfaceValue(QString ifname, QWidget *widget, int num, int type, QByteArray payload);

    Ui::InterfaceToolbar *ui;
    QMap<QString, struct interface_values> interface_;
    QMap<int, QByteArray> default_value_;
    QMap<int, QList<QByteArray> > default_list_;
    QMap<int, QWidget *> control_widget_;
    QMap<int, QWidget *> label_widget_;
    QString help_link_;
    bool use_spacer_;
};

#endif // INTERFACE_TOOLBAR_H

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
