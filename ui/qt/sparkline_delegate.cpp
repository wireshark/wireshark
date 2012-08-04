#include "sparkline_delegate.h"

#include <QPainter>

#include <QDebug>

#define MIN_WIDTH 10

// XXX - Should we use a style sheet for this?
#define SL_MARGIN 2

void SparkLineDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const
{
    QList<int> *points = qvariant_cast<QList<int> *>(index.data(Qt::UserRole));
    int max = 1;
    int content_w = option.rect.width() - (SL_MARGIN * 2);
    int content_h = option.rect.height() - (SL_MARGIN * 2);
    int val;
    qreal idx = 0.0;
    QVector<QPointF> fpoints;

    QStyledItemDelegate::paint(painter, option, index);

    if (!points || points->isEmpty() || content_w <= 0 || content_h <= 0) {
        return;
    }

    while(points->length() > content_w) {
        points->removeFirst();
    }

    foreach (val, *points) {
        if (val > max) max = val;
    }

    foreach (val, *points) {
        fpoints.append(QPointF(idx, (qreal) content_h - (val * content_h / max) ));
        idx = idx + 1;
    }

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->translate(option.rect.x() + SL_MARGIN, option.rect.y() + SL_MARGIN);

    // XXX Handle disabled
    if (option.state & QStyle::State_Selected) {
        painter->setPen(option.palette.color(QPalette::HighlightedText));
        qDebug() << "sel";
    } else {
        painter->setPen(option.palette.color(QPalette::WindowText));
    }
    painter->drawPolyline(QPolygonF(fpoints));

//    painter->setPen(Qt::NoPen);
//    painter->setBrush(option.palette.foreground());
//    painter->drawEllipse(fpoints.first(), 2, 2);

//    painter->setBrush(Qt::red);
//    painter->drawEllipse(fpoints.last(), 2, 2);

    painter->restore();
}

QSize SparkLineDelegate::sizeHint(const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const {
    return QSize(MIN_WIDTH, QStyledItemDelegate::sizeHint(option, index).height());
}
