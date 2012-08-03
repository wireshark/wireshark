#ifndef SPARKLINE_DELEGATE_H
#define SPARKLINE_DELEGATE_H

#include <QStyledItemDelegate>

class SparkLineDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    SparkLineDelegate(QWidget *parent = 0) : QStyledItemDelegate(parent) {}

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const;

signals:
    
public slots:
    
};

Q_DECLARE_METATYPE(QList<int> *)

#endif // SPARKLINE_DELEGATE_H
