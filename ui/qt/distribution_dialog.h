/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISTRIBUTIONDIALOG_H
#define DISTRIBUTIONDIALOG_H

#include <config.h>

#include <epan/stat_tap_ui.h>

#include "filter_action.h"
#include "wireshark_dialog.h"
#include <ui/qt/utils/stat_table_exporter.h>

class DistributionModel;
class QCPAbstractPlottable;
class QCPBars;
class PercentBarDelegate;
class QLabel;
class QPoint;
class QPushButton;
class QSortFilterProxyModel;

namespace Ui {
class DistributionDialog;
}

/**
 * @brief Dialog counting the value combinations of up to four fields over
 *        the packets that match an optional display filter.
 *
 * The counts are shown in a sortable table with a count, a percentage of the
 * packets and a summary with the normalized Shannon entropy. The tap listener
 * is registered only when fields are applied.
 */
class DistributionDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Distribution dialog.
     * @param parent The parent widget.
     * @param cf     Capture file whose packets are counted.
     * @param fields Comma-separated field list to fill in, may be empty. Valid
     *               fields are applied once the dialog is shown.
     */
    DistributionDialog(QWidget &parent, CaptureFile &cf, const QString &fields);

    /**
     * @brief Destroys the dialog.
     */
    ~DistributionDialog();

signals:
    /**
     * @brief Emitted when a filter action of the context menu is triggered.
     * @param filter The display filter of the row under the cursor.
     * @param action The filter action.
     * @param type   The filter action type.
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /**
     * @brief Emitted to open an I/O Graph with one graph per selected row.
     * @param displayFilter The display filter limit that was applied, may be empty.
     * @param filters       Display filter of each graph, the row filter combined
     *                      with the limit when one was applied.
     * @param names         Legend name of each graph, the row values.
     */
    void showIOGraph(const QString &displayFilter, const QVector<QString> &filters,
                     const QVector<QString> &names);

protected:
    /**
     * @brief Updates the enabled state of the inputs, buttons and actions
     *        from the field list, the display filter, the file and the
     *        retap state.
     */
    void updateWidgets() override;

    /**
     * @brief Disables the inputs while a retap runs.
     */
    void beginRetapPackets() override;

    /**
     * @brief Publishes the final counts of a retap, also when no packet
     *        matched and therefore no draw happened.
     */
    void endRetapPackets() override;

    /**
     * @brief Relayouts the chart when the plot is resized.
     *
     * The bar labels and the x-axis tick count depend on the plot width.
     */
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    /** @brief The sentences that differ between Wireshark and Stratoshark. */
    enum class FlavorText {
        SummaryOneField,        /**< Summary line for a single field. */
        SummaryAllFields,       /**< Summary line for several fields. */
        MultipleObservations,   /**< Note that the percentages add up to more than 100 %. */
        EmptyHint,              /**< Hint shown before fields were applied. */
        ApplyToolTip            /**< Tooltip of the Apply button. */
    };

    /**
     * @brief Returns a sentence in its Wireshark or Stratoshark variant.
     * @param id The sentence.
     * @return The translated sentence, with placeholders where it has values.
     */
    static QString flavorText(FlavorText id);

    /**
     * @brief Returns the summary lines of the last completed result.
     * @return No lines while there is no result, else the summary line and,
     *         when a packet counted more than one observation, the note
     *         about percentages over 100 %.
     */
    QStringList summaryTexts() const;

    /**
     * @brief Collects the table in view order for copying and saving.
     * @param selected_only True to collect only the selected rows.
     * @return The table with the window subtitle as title.
     */
    StatTableExporter::Table table(bool selected_only);

    /**
     * @brief Returns source model rows in view order.
     * @param selected_only True to return only the selected rows.
     * @return The rows of the source model, in the order the view shows them.
     */
    QList<int> sourceRows(bool selected_only) const;

    /**
     * @brief Puts the percent bar delegate on the current Percent column.
     */
    void updatePercentDelegate();

    /**
     * @brief Redraws the bar chart of the rows with the highest counts.
     *
     * Does nothing while the chart is hidden.
     */
    void updateChart();

    /**
     * @brief Selects the table row of a clicked bar.
     * @param plottable The clicked plottable.
     * @param dataIndex Index of the clicked bar.
     */
    void chartBarClicked(QCPAbstractPlottable *plottable, int dataIndex);

    /**
     * @brief Tap callback: removes all counts at the start of a retap.
     * @param tapdata Pointer to the DistributionDialog.
     */
    static void tapReset(void *tapdata);

    /**
     * @brief Tap callback: counts the field values of one packet.
     * @param tapdata Pointer to the DistributionDialog.
     * @param pinfo   Packet information (unused).
     * @param edt     Dissection of the packet.
     * @param data    Tap data (unused).
     * @param flags   Tap flags (unused).
     * @return TAP_PACKET_REDRAW when the packet was counted,
     *         TAP_PACKET_DONT_REDRAW when it was skipped,
     *         TAP_PACKET_FAILED without a dissection.
     */
    static tap_packet_status tapPacket(void *tapdata, struct _packet_info *pinfo,
                                       struct epan_dissect *edt, const void *data,
                                       tap_flags_t flags);

    /**
     * @brief Tap callback: makes the new counts visible.
     * @param tapdata Pointer to the DistributionDialog.
     */
    static void tapDraw(void *tapdata);

    Ui::DistributionDialog *ui;
    DistributionModel *model_;
    QSortFilterProxyModel *proxy_;
    PercentBarDelegate *percent_delegate_;
    int percent_column_;
    QLabel *empty_hint_label_;
    QPushButton *copy_button_;
    QPushButton *save_button_;
    QPushButton *io_graph_button_;
    QString applied_limit_;
    QCPBars *chart_bars_;
    QList<int> chart_rows_;
    bool chart_sized_;
    /** True once the value and count columns were sized for the current result. */
    bool columns_sized_;

    /**
     * @brief Sizes the value and Count columns to their contents, once per result.
     *
     * The Percent column is the stretched last section and keeps the rest.
     */
    void sizeColumns();

    /** @brief Number of rows with the highest counts that the chart shows. */
    static constexpr int chartRows = 10;

private slots:
    /**
     * @brief Combines the field list check of the Fields edit with the
     *        counting check of the model and shows the message below Fields.
     */
    void checkFields();

    /**
     * @brief Registers the tap listener for the entered fields and display
     *        filter and retaps the packets.
     */
    void apply();

    /**
     * @brief Shows the summary of the last completed result.
     */
    void updateSummary();

    /**
     * @brief Shows the context menu of the row under the cursor.
     * @param pos Position in viewport coordinates.
     */
    void showContextMenu(const QPoint &pos);

    /**
     * @brief Copies the whole table as plain text.
     */
    void copyTable();

    /**
     * @brief Copies the selected rows as plain text.
     */
    void on_actionCopy_triggered();

    /**
     * @brief Saves the whole table in a format chosen by the user.
     */
    void on_actionSaveAs_triggered();

    /**
     * @brief Emits showIOGraph() for the selected rows in view order, at
     *        most MainWindow::maxIOGraphFilters of them.
     */
    void on_actionShowInIOGraph_triggered();

    /**
     * @brief Shows resolved labels instead of the raw values.
     * @param checked True to show the resolved labels.
     */
    void on_resolveCheckBox_toggled(bool checked);

    /**
     * @brief Shows or hides the chart beside the table.
     * @param checked True to show the chart.
     */
    void on_chartCheckBox_toggled(bool checked);

    /**
     * @brief Opens the Distribution section of the user guide.
     */
    void on_buttonBox_helpRequested();
};

#endif // DISTRIBUTIONDIALOG_H
