/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef GRAPH_DIALOG_H
#define GRAPH_DIALOG_H

#include <config.h>

#include <ui/qt/models/uat_model.h>

#include "wireshark_dialog.h"

#include <QColor>
#include <QPointer>
#include <QVector>

/**
 * @brief Base class of the dialogs that draw one series per UAT table row
 * (I/O Graph and Plot).
 *
 * Every row has an index into the theme's graph palette. A new row takes its
 * row number as index, so the first series uses palette color 0, the second
 * color 1 and so on. The index stays with the row when other rows are moved
 * or removed. When the theme changes, every row gets the new theme's color
 * for its index, except rows whose color the user picked while the dialog
 * was open. Rows loaded from the profile and copied rows follow the theme too,
 * so a saved or copied custom color is replaced on the next theme change. The
 * user-picked state lives only in memory.
 */
class GraphDialog : public WiresharkDialog
{
    Q_OBJECT

protected:
    /**
     * @brief Constructs the dialog and follows theme changes.
     * @param parent The parent widget.
     * @param cf The associated capture file.
     * @param colorColumn The UAT column that holds the series color.
     */
    GraphDialog(QWidget &parent, CaptureFile &cf, int colorColumn);

    /**
     * @brief Set the uat_model_ and start tracking the rows.
     *
     * Call before connecting the subclass's own model handlers, so the palette
     * indexes are current when those run. Pass nullptr when the capture file
     * closes, after disconnecting the old model from this dialog.
     * @param model The UAT table model, or nullptr to stop using one.
     */
    void setUatModel(UatModel *model);

    /**
     * @brief The color for the row about to be appended to uat_model_.
     * @return The current theme's palette color for that row's index, or an
     *         invalid QColor if the theme has no graph colors.
     */
    QColor newGraphColor() const;

    /**
     * @brief Apply a model rowsMoved signal to a list kept in model row order.
     *
     * Rows moved up land at @p destinationRow; rows moved down land before it.
     * @param list The list to reorder.
     * @param sourceStart First moved row.
     * @param sourceEnd Last moved row (inclusive).
     * @param destinationRow The destination row reported by the model.
     */
    template <typename List>
    static void moveListRows(List &list, int sourceStart, int sourceEnd, int destinationRow)
    {
        for (int i = 0; i <= sourceEnd - sourceStart; i++) {
            if (destinationRow < sourceStart) {
                // When moving up, moving an earlier item doesn't change the row.
                list.move(sourceStart + i, destinationRow + i);
            } else {
                // When moving down, the next items move up, so the moved rows
                // are always at sourceStart.
                list.move(sourceStart, destinationRow - 1);
            }
        }
    }

    QPointer<UatModel> uat_model_;  /**< UAT-backed table model, one row per series. Written only by setUatModel(). */

private slots:
    void onThemeChanged();
    void colorRowsReset();
    void colorRowsInserted(const QModelIndex &parent, int first, int last);
    void colorRowsRemoved(const QModelIndex &parent, int first, int last);
    void colorRowsMoved(const QModelIndex &source, int sourceStart, int sourceEnd,
                        const QModelIndex &dest, int destinationRow);
    void colorDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight,
                          const QVector<int> &roles);

private:
    /** Index of a row whose color the user picked; the row keeps that color. */
    static constexpr int user_color_ = -1;
    /** Role of the theme refresh's own writes, so they are not taken for a user choice. */
    static constexpr int theme_color_role_ = Qt::DecorationRole;

    const int color_column_;        /**< UAT column of the series color. */
    QVector<int> color_indexes_;    /**< Palette index per model row, or user_color_. */
};

#endif // GRAPH_DIALOG_H
