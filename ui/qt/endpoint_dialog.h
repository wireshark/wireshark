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

/**
 * @brief A dialog window displaying active endpoints in a capture file.
 */
class EndpointDialog : public TrafficTableDialog
{
    Q_OBJECT
public:
    /**
     * @brief Create a new endpoint window.
     *
     * @param parent Parent widget.
     * @param cf Capture file. No statistics will be calculated if this is NULL.
     */
    explicit EndpointDialog(QWidget &parent, CaptureFile &cf);

signals:

protected:
    /**
     * @brief Slot triggered when the underlying capture file is closing.
     */
    void captureFileClosing() override;

private:
    /** Checkbox used to toggle the aggregation of certain endpoint data. */
    QCheckBox *aggregated_ck_;

#ifdef HAVE_MAXMINDDB
    /** Button used to display MaxMind-based GeoIP mapping data, if supported. */
    QPushButton * map_bt_;
#endif

private slots:
#ifdef HAVE_MAXMINDDB
    /**
     * @brief Slot triggered to open the GeoIP map view.
     */
    void openMap();

    /**
     * @brief Slot triggered to save the current GeoIP map view.
     */
    void saveMap();
#endif

    /**
     * @brief Slot triggered when the active protocol tab is changed.
     * @param idx The index of the newly active tab.
     */
    void tabChanged(int idx);

    /**
     * @brief Slot triggered when help is requested from the dialog's button box.
     */
    void on_buttonBox_helpRequested() override;

    /**
     * @brief Slot triggered when the aggregation checkbox is toggled.
     * @param checked True if aggregation is enabled, false otherwise.
     */
    void aggregationToggled(bool checked);
};

/**
 * @brief Initialize the endpoint table with a filter.
 *
 * @param ct Pointer to the conversation table structure.
 * @param filter Filter string for the endpoints.
 */
void init_endpoint_table(struct register_ct* ct, const char *filter);

#endif // ENDPOINT_DIALOG_H
