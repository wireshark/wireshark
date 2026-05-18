/** @file
 *
 * QCustomPlot QCPAbstractLegendItem subclass containing a string.
 * This is used to add a title to a QCPLegend.
 *
 * This file is from https://www.qcustomplot.com/index.php/support/forum/443
 * where the author David said "I thought I would share in case any one else
 * is needing the same functionality." Accordingly, this file is in the
 * public domain.
 */

#ifndef QCP_STRING_LEGEND_ITEM_H
#define QCP_STRING_LEGEND_ITEM_H

#include <ui/qt/widgets/qcustomplot.h>

/**
 * @brief A legend item that displays a static text string.
 */
class QCPStringLegendItem : public QCPAbstractLegendItem
{
  Q_OBJECT

public:
    /**
     * @brief Constructs a new QCPStringLegendItem object.
     * @param pParent The parent legend this item belongs to.
     * @param strText The text string to display.
     */
    explicit QCPStringLegendItem(QCPLegend *pParent, const QString& strText);

    /**
     * @brief Retrieves the text string displayed by this legend item.
     * @return The current text string.
     */
    QString text() const;

    /**
     * @brief Sets the text string to be displayed.
     * @param strText The new text string.
     */
    void setText(const QString& strText);

protected:
    /**
     * @brief Draws the string legend item.
     * @param painter The painter used for drawing.
     */
    virtual void draw(QCPPainter *painter) override;

    /**
     * @brief Calculates the minimum outer size hint required for the text.
     * @return A QSize representing the minimum outer size.
     */
    virtual QSize minimumOuterSizeHint() const override;

private:
    /** @brief The text string displayed by the legend item. */
    QString m_strText;
};

#endif
