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

class QCPStringLegendItem : public QCPAbstractLegendItem
{
  Q_OBJECT

public:
    explicit QCPStringLegendItem(QCPLegend *pParent, const QString& strText);

    QString text() const;
    void setText(const QString& strText);

protected:
    virtual void draw(QCPPainter *painter) override;
    virtual QSize minimumOuterSizeHint() const override;

private:
    QString m_strText;
};

#endif
