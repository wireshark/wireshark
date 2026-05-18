/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SUPPORTED_PROTOCOLS_DIALOG_H
#define SUPPORTED_PROTOCOLS_DIALOG_H

#include "geometry_state_dialog.h"
#include <ui/qt/models/supported_protocols_model.h>

namespace Ui {
class SupportedProtocolsDialog;
}

/**
 * @brief Dialog that displays all registered Wireshark protocols and their
 *        fields in a searchable, sortable tree, with debounced filtering and
 *        a summary of total protocol and field counts.
 */
class SupportedProtocolsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Supported Protocols dialog and begins populating the tree.
     * @param parent Optional parent widget.
     */
    explicit SupportedProtocolsDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the dialog and releases all associated resources.
     */
    ~SupportedProtocolsDialog();

private:
    Ui::SupportedProtocolsDialog *ui; /**< Qt Designer-generated UI object. */

    SupportedProtocolsModel      *supported_protocols_model_; /**< Source model holding all protocol and field data. */
    SupportedProtocolsProxyModel *proxyModel_;                /**< Sort/filter proxy applied on top of the source model. */
    QTimer                       *searchLineEditTimer;        /**< Debounce timer that delays filter application after the user stops typing. */
    QString                       searchLineEditText;         /**< Pending filter text buffered until the debounce timer fires. */

    /**
     * @brief Updates the status label with the current count of visible protocols
     *        and fields relative to the total.
     */
    void updateStatistics();

private slots:
    /**
     * @brief Populates the model with all registered protocols and fields and
     *        resets the tree view; called once during construction.
     */
    void fillTree();

    /**
     * @brief Applies the buffered search text to the proxy model filter.
     *
     * Called by the debounce timer after a short idle period following the last
     * keystroke, rather than on every text-changed event, to avoid filtering on
     * every intermediate character when typing quickly.
     */
    void updateSearchLineEdit();

    /**
     * @brief Stores the new search text and (re)starts the debounce timer.
     * @param search_re The current text of the search line edit.
     */
    void on_searchLineEdit_textChanged(const QString &search_re);
};

#endif // SUPPORTED_PROTOCOLS_DIALOG_H
