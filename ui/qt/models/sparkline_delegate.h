/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SPARKLINE_DELEGATE_H
#define SPARKLINE_DELEGATE_H

#include <QStyledItemDelegate>

/**
 * @brief Item delegate that renders a spark-line (miniature inline chart)
 *        for cells whose model data contains a series of numeric values.
 */
class SparkLineDelegate : public QStyledItemDelegate
{
public:
    /**
     * @brief Constructs a SparkLineDelegate.
     * @param parent Optional parent widget.
     */
    SparkLineDelegate(QWidget *parent = 0) : QStyledItemDelegate(parent) {}

    /**
     * @brief Optional second value series, drawn over the primary one.
     *
     * The primary series is read from Qt::UserRole (unchanged). A model may
     * additionally provide a second QList<int> at this role (e.g. dropped
     * packets); when present it is drawn on the same scale in a distinct theme
     * color. Models that don't provide it render exactly one line as before.
     */
    static constexpr int SecondaryPointsRole = Qt::UserRole + 1;

    /**
     * @brief A negative value in either series marks a gap (a line break with a
     *        dashed bridge), used to show an interval where no data was sampled.
     */
    static constexpr int GapValue = -1;

protected:
    /**
     * @brief Renders the spark-line chart for the cell at @p index.
     * @param painter Painter to draw with.
     * @param option  Style option providing geometry, palette, and state.
     * @param index   Model index of the cell being painted.
     */
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

    /**
     * @brief Returns the preferred size for a spark-line cell.
     * @param option Style option providing font metrics and state.
     * @param index  Model index of the cell being measured.
     * @return Recommended QSize for the cell.
     */
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override;

    /**
     * @brief Suppresses inline editing by returning @c nullptr.
     *
     * Spark-line cells are display-only; no editor widget is created.
     *
     * @param parent  Unused parent widget.
     * @param option  Unused style option.
     * @param index   Unused model index.
     * @return Always @c nullptr.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

signals:

public slots:

};

Q_DECLARE_METATYPE(QList<int>)

#endif // SPARKLINE_DELEGATE_H
