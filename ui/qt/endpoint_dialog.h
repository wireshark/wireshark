/* endpoint_dialog.h
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

#ifndef ENDPOINT_DIALOG_H
#define ENDPOINT_DIALOG_H

#include "traffic_table_dialog.h"

Q_DECLARE_METATYPE(hostlist_talker_t *)

class EndpointTreeWidget : public TrafficTableTreeWidget
{
    Q_OBJECT
public:
    explicit EndpointTreeWidget(QWidget *parent, register_ct_t* table);
    ~EndpointTreeWidget();

#ifdef HAVE_GEOIP
    bool hasGeoIPData() const { return has_geoip_data_; }
#endif

    static void tapReset(void *conv_hash_ptr);
    static void tapDraw(void *conv_hash_ptr);

#ifdef HAVE_GEOIP
public:
    const QList<int> columnToDb(int column) const { return col_to_db_.value(column, QList<int>()); }

signals:
    void geoIPStatusChanged();

private:
    QMap<int, QList<int> > col_to_db_; // Map tree columns to GeoIP databases
    bool has_geoip_data_;
#endif

private:
    void updateItems();

private slots:
    void filterActionTriggered();
};

class EndpointDialog : public TrafficTableDialog
{
    Q_OBJECT
public:
    /** Create a new endpoint window.
     *
     * @param parent Parent widget.
     * @param cf Capture file. No statistics will be calculated if this is NULL.
     * @param cli_proto_id If valid, add this protocol and bring it to the front.
     * @param filter Display filter to apply.
     */
    explicit EndpointDialog(QWidget &parent, CaptureFile &cf, int cli_proto_id = -1, const char *filter = NULL);
    ~EndpointDialog();

signals:

public slots:
    void captureFileClosing();

private:
#ifdef HAVE_GEOIP
    QPushButton *map_bt_;
#endif

    bool addTrafficTable(register_ct_t* table);

private slots:
#ifdef HAVE_GEOIP
    void tabChanged();
    void createMap();
#endif
    void on_buttonBox_helpRequested();
};

void init_endpoint_table(struct register_ct* ct, const char *filter);

#endif // ENDPOINT_DIALOG_H

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
