/* graph_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "graph_dialog.h"

#include <ui/qt/utils/theme_manager.h>

GraphDialog::GraphDialog(QWidget &parent, CaptureFile &cf, int colorColumn) :
    WiresharkDialog(parent, cf),
    color_column_(colorColumn)
{
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &GraphDialog::onThemeChanged);
}

void GraphDialog::setUatModel(UatModel *model)
{
    uat_model_ = model;
    colorRowsReset();

    if (!uat_model_)
        return;

    connect(uat_model_, &UatModel::modelReset, this, &GraphDialog::colorRowsReset);
    connect(uat_model_, &UatModel::rowsInserted, this, &GraphDialog::colorRowsInserted);
    connect(uat_model_, &UatModel::rowsRemoved, this, &GraphDialog::colorRowsRemoved);
    connect(uat_model_, &UatModel::rowsMoved, this, &GraphDialog::colorRowsMoved);
    connect(uat_model_, &UatModel::dataChanged, this, &GraphDialog::colorDataChanged);
}

QColor GraphDialog::newGraphColor() const
{
    // colorRowsInserted() gives the new row its row number as palette index.
    return ThemeManager::instance()->graphColor(uat_model_ ? uat_model_->rowCount() : 0);
}

void GraphDialog::onThemeChanged()
{
    if (!uat_model_)
        return;

    for (int row = 0; row < uat_model_->rowCount(); row++) {
        const int index = color_indexes_.value(row, row);
        if (index == user_color_)
            continue;

        const QColor color = ThemeManager::instance()->graphColor(index);
        if (!color.isValid())
            continue;

        // The model's dataChanged signal makes the subclass resync and
        // redraw the series.
        uat_model_->setData(uat_model_->index(row, color_column_), color, theme_color_role_);
    }
}

void GraphDialog::colorRowsReset()
{
    color_indexes_.clear();
    if (!uat_model_)
        return;

    for (int row = 0; row < uat_model_->rowCount(); row++) {
        color_indexes_.append(row);
    }
}

void GraphDialog::colorRowsInserted(const QModelIndex &, int first, int last)
{
    // first to last is inclusive
    for (int row = first; row <= last; row++) {
        color_indexes_.insert(row, row);
    }
}

void GraphDialog::colorRowsRemoved(const QModelIndex &, int first, int last)
{
    // first to last is inclusive
    for (int row = last; row >= first; row--) {
        color_indexes_.removeAt(row);
    }
}

void GraphDialog::colorRowsMoved(const QModelIndex &, int sourceStart, int sourceEnd,
                                 const QModelIndex &, int destinationRow)
{
    moveListRows(color_indexes_, sourceStart, sourceEnd, destinationRow);
}

void GraphDialog::colorDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight,
                                   const QVector<int> &roles)
{
    if (!uat_model_ || roles.contains(theme_color_role_))
        return;
    // Only an edit of the color cell itself counts. UatModel also reports
    // validity changes of other fields as a column range, which can span the
    // color column without the color having changed.
    if (topLeft.column() != color_column_ || bottomRight.column() != color_column_)
        return;

    // A color that differs from the row's palette color was picked by the
    // user; the row keeps it when the theme changes.
    for (int row = topLeft.row(); row <= bottomRight.row() && row < color_indexes_.size(); row++) {
        const int index = color_indexes_.at(row);
        if (index == user_color_)
            continue;

        const QColor color = uat_model_->data(uat_model_->index(row, color_column_),
                                              Qt::DecorationRole).value<QColor>();
        if (color != ThemeManager::instance()->graphColor(index))
            color_indexes_[row] = user_color_;
    }
}
