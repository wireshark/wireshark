/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MULTICASTSTATISTICSDIALOG_H
#define MULTICASTSTATISTICSDIALOG_H

#include "tap_parameter_dialog.h"
#include "ui/mcast_stream.h"

class SyntaxLineEdit;

/**
 * @brief Dialog for displaying multicast stream statistics.
 */
class MulticastStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new MulticastStatisticsDialog.
     * @param parent The parent widget.
     * @param cf The capture file associated with the dialog.
     * @param filter Optional filter string to apply, defaults to NULL.
     */
    MulticastStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter = NULL);

    /**
     * @brief Destroys the MulticastStatisticsDialog.
     */
    ~MulticastStatisticsDialog();

protected:
    /**
     * @brief Handles the event when the capture file is closing.
     */
    void captureFileClosing();

private:
    /** Pointer to the multicast stream tap information structure. */
    struct _mcaststream_tapinfo *tapinfo_;

    /** Line edit for configuring the burst measurement interval. */
    SyntaxLineEdit *burst_measurement_interval_le_;

    /** Line edit for configuring the burst alarm threshold. */
    SyntaxLineEdit *burst_alarm_threshold_le_;

    /** Line edit for configuring the buffer alarm threshold. */
    SyntaxLineEdit *buffer_alarm_threshold_le_;

    /** Line edit for configuring the stream empty speed. */
    SyntaxLineEdit *stream_empty_speed_le_;

    /** Line edit for configuring the total empty speed. */
    SyntaxLineEdit *total_empty_speed_le_;

    /** List tracking the dynamically managed line edit widgets. */
    QList<QWidget *> line_edits_;

    /**
     * @brief Callback to reset the multicast tap data.
     * @param tapinfo Pointer to the multicast stream tap info.
     */
    static void tapReset(mcaststream_tapinfo_t *tapinfo);

    /**
     * @brief Callback to draw the tap results.
     * @param tapinfo Pointer to the multicast stream tap info.
     */
    static void tapDraw(mcaststream_tapinfo_t *tapinfo);

    /**
     * @brief Rescans the current capture data to refresh statistics.
     */
    void rescan();

    /**
     * @brief Retrieves the data associated with a tree item.
     * @param ti The tree widget item to process.
     * @return A list of variants containing the data for the item.
     */
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *ti) const;

    /**
     * @brief Gets the current filter expression.
     * @return The filter expression string.
     */
    virtual const QString filterExpression();

private slots:
    /**
     * @brief Updates the states of the UI widgets.
     */
    void updateWidgets();

    /**
     * @brief Updates the multicast processing parameters based on UI inputs.
     */
    void updateMulticastParameters();

    /**
     * @brief Fills the tree view with multicast statistics data.
     */
    virtual void fillTree();
};

#endif // MULTICASTSTATISTICSDIALOG_H
