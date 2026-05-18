/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_IO_GRAPH_DIALOG_H
#define STRATOSHARK_IO_GRAPH_DIALOG_H

#include <config.h>
#include "io_graph_dialog.h"


/**
 * @brief Stratoshark-specific I/O graph dialog, overriding axis labels,
 *        default graphs, and hint strings to use Stratoshark terminology
 *        (e.g. "events" in place of "packets").
 */
class StratosharkIOGraphDialog : public IOGraphDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a StratosharkIOGraphDialog.
     *
     * Call initialize() after construction to complete setup, allowing
     * polymorphic virtual dispatch during initialisation.
     *
     * @param parent Parent widget reference.
     * @param cf     Capture file to graph.
     */
    explicit StratosharkIOGraphDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Destroys the dialog.
     */
    virtual ~StratosharkIOGraphDialog();

    /**
     * @brief Completes dialog initialization after construction.
     *
     * Overloaded to supply Stratoshark-appropriate default io_graph_fields.
     * Must be called once after the object is fully constructed so that
     * virtual method dispatch works correctly during setup.
     *
     * @param parent          Parent widget reference.
     * @param displayFilter   Initial display-filter string; empty for no filter.
     * @param value_units     Y-axis unit type for the initial graph.
     * @param yfield          Y-axis field name; empty uses the unit-specific default.
     * @param is_sibling_dialog @c true when this dialog is opened alongside an
     *                        existing I/O graph dialog rather than as the primary instance.
     * @param convFilters     Optional per-graph conversation filters to pre-populate.
     */
    void initialize(QWidget &parent,
                    QString displayFilter = QString(),
                    io_graph_item_unit_t value_units = IOG_ITEM_UNIT_PACKETS,
                    QString yfield = QString(),
                    bool is_sibling_dialog = false,
                    const QVector<QString> convFilters = QVector<QString>());

    /**
     * @brief Adds a Stratoshark-appropriate default graph to the dialog.
     * @param enabled @c true if the graph should be visible immediately.
     * @param idx     Zero-based index controlling which default graph preset to add.
     */
    virtual void addDefaultGraph(bool enabled, int idx = 0) override;

protected:
    /**
     * @brief Returns the display name used when saving filtered graph data.
     * @return Stratoshark-specific filtered name string.
     */
    virtual QString getFilteredName() const override;

    /**
     * @brief Returns the localised X-axis label for the graph.
     * @return X-axis name string (e.g. "Time (s)").
     */
    virtual QString getXAxisName() const override;

    /**
     * @brief Returns the localised Y-axis label for the given unit type.
     * @param value_units The io_graph_item_unit_t controlling the Y-axis metric.
     * @return NUL-terminated Y-axis name string appropriate for @p value_units.
     */
    virtual const char *getYAxisName(io_graph_item_unit_t value_units) const override;

    /**
     * @brief Returns the default Y-axis field name for the given unit and explicit field override.
     * @param value_units The io_graph_item_unit_t for which the field name is needed.
     * @param yfield      Explicit field name; if non-empty, may be returned as-is or transformed.
     * @return Resolved Y-axis field name string.
     */
    virtual QString getYFieldName(io_graph_item_unit_t value_units, const QString &yfield) const override;

    /**
     * @brief Parses a Y-axis value from a raw data string in the graph model.
     * @param data Raw data string to parse.
     * @return Integer Y value extracted from @p data.
     */
    virtual int getYAxisValue(const QString &data) override;

    /**
     * @brief Returns the hint string displayed when the graph contains no data.
     * @return Localised no-data hint string.
     */
    virtual QString getNoDataHint() const override;

    /**
     * @brief Returns the status-bar hint string summarising the graph contents.
     * @param num_items Number of items (events) currently plotted.
     * @return Localised hint string incorporating @p num_items.
     */
    virtual QString getHintText(unsigned num_items) const override;
};

#endif // STRATOSHARK_IO_GRAPH_DIALOG_H
