/** @file
 *
 * QCustomPlot QCPAbstractLegendItem subclass representing an empty space.
 * This is used to separate elements in QCPLegend.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QCP_SPACER_LEGEND_ITEM_H
#define QCP_SPACER_LEGEND_ITEM_H

#include <ws_attributes.h>  // _U_

class QCPAbstractLegendItem;

class QCPSpacerLegendItem : public QCPAbstractLegendItem
{
    Q_OBJECT

public:
    explicit QCPSpacerLegendItem(QCPLegend* pParent, int size = 10, bool horizontal = false);
    int size() const { return m_size; }
    void setSize(int size) { m_size = size; }
    bool isHorizontal() const { return m_horiz; }
    void setIsHorizontal(bool horiz) { m_horiz = horiz; }

protected:
    virtual void draw(QCPPainter* painter _U_) override {}
    virtual QSize minimumOuterSizeHint() const override;

private:
    int m_size;
    bool m_horiz;
};

#endif // QCP_SPACER_LEGEND_ITEM_H
