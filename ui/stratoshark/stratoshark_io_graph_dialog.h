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


class StratosharkIOGraphDialog : public IOGraphDialog
{
    Q_OBJECT

public:
    explicit StratosharkIOGraphDialog(QWidget &parent, CaptureFile &cf);
    virtual ~StratosharkIOGraphDialog();
    // Initialize the dialog after construction to allow polymorphic behavior.
    // Overloaded to provide default io_graph_fields.
    void initialize(QWidget& parent, QString displayFilter = QString(),
        io_graph_item_unit_t value_units = IOG_ITEM_UNIT_PACKETS,
        QString yfield = QString(),
        bool is_sibling_dialog = false,
        const QVector<QString> convFilters = QVector<QString>());

    virtual void addDefaultGraph(bool enabled, int idx = 0) override;

protected:
    virtual QString getFilteredName() const override;
    virtual QString getXAxisName() const override;
    virtual const char* getYAxisName(io_graph_item_unit_t value_units) const override;
    virtual QString getYFieldName(io_graph_item_unit_t value_units, const QString& yfield) const override;
    virtual int getYAxisValue(const QString& data) override;
    virtual QString getNoDataHint() const override;
    virtual QString getHintText(unsigned num_items) const override;

};

#endif // STRATOSHARK_IO_GRAPH_DIALOG_H
