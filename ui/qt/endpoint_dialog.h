/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ENDPOINT_DIALOG_H
#define ENDPOINT_DIALOG_H

#include <QFile>

#include "traffic_table_dialog.h"

#include <ui/qt/models/atap_data_model.h>

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

protected:
    void captureFileClosing();
    void captureFileClosed();

private:
#ifdef HAVE_MAXMINDDB
    QPushButton * map_bt_;
#endif

private slots:
#ifdef HAVE_MAXMINDDB
    void openMap();
    void saveMap();
#endif
    void tabChanged(int idx);
    void on_buttonBox_helpRequested();
};

void init_endpoint_table(struct register_ct* ct, const char *filter);

#endif // ENDPOINT_DIALOG_H
