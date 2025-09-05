/** customplot.h
 * Field Values Plotting Chart (Header file)
 * By Hamdi Miladi <hamdi.miladi@technica-engineering.de>
 * Copyright 2025 Hamdi Miladi
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CUSTOMPLOT_H
#define CUSTOMPLOT_H
#include <ui/qt/widgets/qcustomplot.h>
#include "ui/qt/marker_dialog.h"

class QCustomPlot;

class CustomPlot : public QCustomPlot {
    Q_OBJECT
public:
    explicit CustomPlot(QWidget* widget);
    ~CustomPlot();
    void showMarkerDifferences();
    void setDataPointVisibility(const bool visible);
    QString currentValue() const { return QString::number(tracer()->position->value(), 'g', 4); }
    void mouseReleased();
    bool mousePressed(QPoint);
    void clearMarkerDifferences();
    inline int selectedMarker() const { return selected_marker_idx_; }
    void markerVisibilityChanged(const Marker* m);
    void showMarkersDifference(bool show) { marker_diff_visible_ = show; }
    void addMarkerElements(const Marker*);
    void deleteMarkersElements();
    void deleteMarkerElements(const int);
    void addDataPointsMarker(QCPGraph* graph);
    QString selectedMarker(const int ignoreIdx);
    QVector<Marker*> markers() const { return markers_; }
    Marker* addMarker(double x, bool isPosMarker);
    void deleteMarker(Marker* m);
    void deleteAllMarkers();
    QList<const Marker*> visibleMarkers() const;
    Marker* marker(const QString&);
    Marker* marker(const int);
    Marker* posMarker();
    void markerMoved(const Marker*);

protected:
    void mouseMoveEvent(QMouseEvent* event) override;
    void axisRemoved(QCPAxis*) override;

private:
    void markerMoved(const int, const double, const bool);
    QList<const Marker*> orderedMarkers(QList<const Marker*>) const;
    void addTitleMarker(const Marker*);
    QCPItemTracer* tracer() const { return findChild<QCPItemTracer*>(); }
    void resetSelectedMarker() { selected_marker_idx_ = -1; }
    void deleteMarkerDataPoint(const int marker_idx);
    QCPItemText* markerTitle(const int markerIdx, const bool = false);
    QCPItemText* markerDataPoint(const QString& idx, const bool = false);
    QCPItemStraightLine* markerLine(const int mIdx, const int rectIdx, const bool = false);
    void updateQCPItemText(QCPItemText* item, const QString& txt, const QPointF pos, QCPAxis* y_axis = Q_NULLPTR);
    void updateDataPointMarker(QCPItemText* item, const double, QCPGraph*, bool visible);
    QString dataPointMarker(const double) const;
    inline QString itemIndex(int markerIdx, int graphIdx) const { return QString("%1_%2").arg(markerIdx).arg(graphIdx); }
    void addDataPointsMarker(QCPGraph* graph, int graph_idx, const int marker_idx, const double x, bool visible);
    bool canAddDataPoint(const QCPGraph* graph, const double x) const;
    Marker* marker(const std::function<bool(const Marker&)>& predicate);
    template <typename T>
    typename std::enable_if<std::is_base_of<QCPAbstractItem, T>::value, T*>::type
        getOrAddQCPItem(QCustomPlot* plot, const QString& objName, const bool create);

    int selected_marker_idx_;
    bool data_point_visible_;
    bool marker_diff_visible_;
    bool dragging_;
    QVector<Marker*> markers_;
};

template <typename T>
typename std::enable_if<std::is_base_of<QCPAbstractItem, T>::value, T*>::type
inline CustomPlot::getOrAddQCPItem(QCustomPlot* plot, const QString& objName, const bool create)
{
    T* item = plot->findChild<T*>(objName);
    if (create && item == nullptr) {
        item = new T(plot);
        item->setObjectName(objName);
    }
    return item;
}
#endif // CUSTOMPLOT_H
