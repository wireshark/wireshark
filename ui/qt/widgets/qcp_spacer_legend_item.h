/** @file
 *
 * QCustomPlot QCPAbstractLegendItem subclass representing an empty space.
 * This is used to separate elements in QCPLegend.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QCP_SPACER_LEGEND_ITEM_H
#define QCP_SPACER_LEGEND_ITEM_H

#include <ui/qt/widgets/qcustomplot.h>

/**
 * @brief A spacer item for legends to create empty space between other legend items.
 */
class QCPSpacerLegendItem : public QCPAbstractLegendItem
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new QCPSpacerLegendItem object.
     * @param pParent The parent legend this item belongs to.
     * @param size The size of the spacer in pixels.
     * @param horizontal True if the spacer is horizontal, false if vertical.
     */
    explicit QCPSpacerLegendItem(QCPLegend* pParent, int size = 10, bool horizontal = false);

    /**
     * @brief Gets the size of the spacer.
     * @return The size of the spacer in pixels.
     */
    int size() const { return m_size; }

    /**
     * @brief Sets the size of the spacer.
     * @param size The new size of the spacer in pixels.
     */
    void setSize(int size) { m_size = size; }

    /**
     * @brief Checks if the spacer is horizontal.
     * @return True if the spacer is horizontal, false if it is vertical.
     */
    bool isHorizontal() const { return m_horiz; }

    /**
     * @brief Sets the orientation of the spacer.
     * @param horiz True to set the spacer to horizontal, false for vertical.
     */
    void setIsHorizontal(bool horiz) { m_horiz = horiz; }

protected:
    /**
     * @brief Draws the spacer item (intentionally does nothing).
     */
    virtual void draw(QCPPainter*) override {}

    /**
     * @brief Calculates the minimum outer size hint required for the spacer.
     * @return A QSize representing the minimum outer size.
     */
    virtual QSize minimumOuterSizeHint() const override;

private:
    /** @brief The size of the spacer in pixels. */
    int m_size;

    /** @brief True if the spacer is horizontal, false if vertical. */
    bool m_horiz;
};

#endif // QCP_SPACER_LEGEND_ITEM_H
