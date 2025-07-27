/** customplot.cpp
 * Field Values Plotting Chart
 * By Hamdi Miladi <hamdi.miladi@technica-engineering.de>
 * Copyright 2025 Hamdi Miladi
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wsutil/utf8_entities.h>

#include <ui/qt/widgets/customplot.h>

static const QString marker_title_object_name_ = "marker_title_%1";
static const QString marker_label_object_name_ = "marker_label_%1";
static const QString marker_line_object_name_ = "marker_line_%1";
static const QString marker_diff_line_object_name_ = "marker_diff_line_";
static const QString marker_diff_label_object_name_ = "marker_diff_label_";
CustomPlot::CustomPlot(QWidget* widget):
    QCustomPlot(widget),
    selected_marker_idx_(-1),
    data_point_visible_(true),
    marker_diff_visible_(false),
    dragging_(false)
{}

CustomPlot::~CustomPlot()
{
    deleteAllMarkers();
}

void CustomPlot::setDataPointVisibility(const bool visible)
{
    data_point_visible_ = visible;
    for (const Marker* m : markers()) {
        if (!data_point_visible_) {
            deleteMarkerDataPoint(m->index());
            continue;
        }
        if (const QCPItemStraightLine* line = markerLine(m->index(), 0)) {
            for (int graphIdx = 0; graphIdx < graphCount(); graphIdx++) {
                addDataPointsMarker(graph(graphIdx), graphIdx, m->index(), line->point1->coords().x(), line->visible());
            }
        }
    }
    replot();
}

QString CustomPlot::selectedMarker(const int)
{
    if (const QCPItemText* title = markerTitle(selected_marker_idx_)) {
        return title->text();
    }
    return QString();
}

void CustomPlot::clearMarkerDifferences()
{
    for (QCPAbstractItem* item : findChildren<QCPAbstractItem*>(marker_diff_line_object_name_)) {
        removeItem(item);
    }
    for (QCPAbstractItem* item : findChildren<QCPAbstractItem*>(marker_diff_label_object_name_)) {
        removeItem(item);
    }
}

void CustomPlot::showMarkerDifferences()
{
    const QList<const Marker*> ordered = orderedMarkers(visibleMarkers());
    int next;
    double x1;
    double x2;
    for (int i = 0; i < ordered.count(); i++) {
        x1 = ordered.at(i)->xCoord();
        next = i + 1;
        if (next < ordered.count()) {
            x2 = ordered.at(next)->xCoord();
            QCPItemLine* line = new QCPItemLine(this);
            line->setObjectName(marker_diff_line_object_name_);
            double y_diff = 2.5;
            line->start->setCoords(x1, y_diff);
            line->end->setCoords(x2, y_diff);
            line->setHead(QCPLineEnding(QCPLineEnding::esSpikeArrow, 10, 5));
            line->setTail(QCPLineEnding(QCPLineEnding::esSpikeArrow, 10, 5));
            line->setPen(QPen(Qt::gray));

            QCPItemText* label = new QCPItemText(this);
            label->setObjectName(marker_diff_label_object_name_);
            label->setPositionAlignment(Qt::AlignVCenter | Qt::AlignHCenter);
            label->setFont(QFont(font().family(), 8, QFont::DemiBold));
            label->setColor(Qt::black);
            label->setBrush(QBrush(Qt::transparent));

            double difference = qAbs(x2 - x1);
            auto old_clipaxisrect = tracer()->clipAxisRect();
            tracer()->setClipAxisRect(xAxis->axisRect());
            updateQCPItemText(label,
                QString("%1 " UTF8_RIGHTWARDS_ARROW " %2 \n %3 %4")
                .arg(ordered.at(i)->name())
                .arg(ordered.at(next)->name())
                .arg(difference)
                .arg("s"),
                QPointF((x1 + x2) / 2, y_diff));
            if (old_clipaxisrect) {
                tracer()->setClipAxisRect(old_clipaxisrect);
            }
        }
    }
}

QList<const Marker*> CustomPlot::orderedMarkers(QList<const Marker*> list) const
{
    std::sort(list.begin(), list.end(),
        [](const Marker* a, const Marker* b) {
            return a->xCoord() < b->xCoord();
        });
    return list;
}

void CustomPlot::addTitleMarker(const Marker* marker)
{
    QCPItemText* mTitle =  markerTitle(marker->index(), true);
    mTitle->setVisible(marker->visible());
    tracer()->setClipAxisRect(axisRect(0));
    updateQCPItemText(mTitle, marker->name(), QPointF(marker->xCoord(), axisRect(0)->axis(QCPAxis::AxisType::atLeft)->range().upper));
    mTitle->setFont(QFont(font().family(), 10, QFont::Bold));
    mTitle->setPadding(QMargins(3, 0, 3, 0));
    mTitle->setColor(Qt::lightGray);
    mTitle->setPositionAlignment(Qt::AlignHCenter | Qt::AlignTop);
    mTitle->setBrush(QBrush(Qt::darkBlue));
    mTitle->pen().setWidth(150);
    mTitle->setObjectName(marker_title_object_name_.arg(marker->index()));
}

QString CustomPlot::dataPointMarker(const double x) const
{
    tracer()->setGraphKey(x);
    tracer()->updatePosition();
    QString value = currentValue();
    return QString("(%1, %2)").arg(x).arg(value);
}

void CustomPlot::updateQCPItemText(QCPItemText* item, const QString& txt, const QPointF pos)
{
    item->position->setAxes(tracer()->clipAxisRect()->axis(QCPAxis::atBottom), tracer()->clipAxisRect()->axis(QCPAxis::atLeft));
    item->position->setCoords(pos);
    item->setClipToAxisRect(true);
    item->setClipAxisRect(tracer()->clipAxisRect());
    item->setText(txt);
    replot();
}

void CustomPlot::updateDataPointMarker(QCPItemText* item, const double x, QCPGraph* graph, bool visible)
{
    item->setVisible(visible);
    if (!item->visible()) {
        return;
    }
    tracer()->setGraph(graph);
    tracer()->setClipAxisRect(graph->valueAxis()->axisRect());
    const QString dataPoint = dataPointMarker(x);
    const double value = tracer()->position->value();
    updateQCPItemText(item, dataPoint, QPointF(x, value));
}

void CustomPlot::addMarkerElements(const Marker* marker)
{
    bool visible = marker->visible();
    for (int i = 0; i < axisRectCount() -1; i++) {
        const QCPAxis* axis = axisRect(i)->axis(QCPAxis::AxisType::atLeft);
        QCPItemStraightLine* mLine = markerLine(marker->index(), i, true);
        mLine->setVisible(visible);
        QPen pen(Qt::darkGray);
        pen.setStyle(Qt::DashLine);
        pen.setWidth(1);
        mLine->setPen(pen);
        mLine->setClipToAxisRect(true);
        mLine->setClipAxisRect(axisRect(i));
        mLine->point1->setCoords(marker->xCoord(), axis->range().lower);
        mLine->point2->setCoords(marker->xCoord(), axis->range().upper);
    }
    addTitleMarker(marker);
    replot();
}

void CustomPlot::markerMoved(const int idx, const double newPos, const bool visible)
{
    if (QCPItemText* title = markerTitle(idx)) {
        title->position->setCoords(newPos, yAxis->range().upper);
        title->setVisible(visible);
    }
    for (int i = 0; i < axisRectCount(); i++) {
        if (QCPItemStraightLine* line = markerLine(idx, i)) {
            line->point1->setCoords(newPos, line->point1->coords().y());
            line->point2->setCoords(newPos, line->point2->coords().y());
            line->setVisible(visible);
        }
    }
    for (int graphIdx = 0; graphIdx < graphCount(); graphIdx++) {
        if (QCPItemText* dataPoint = markerDataPoint(itemIndex(idx, graphIdx))) {
            QCPGraph* graph = this->graph(graphIdx);
            dataPoint->setPositionAlignment(Qt::AlignRight | Qt::AlignTop);
            updateDataPointMarker(dataPoint, newPos, graph, visible && canAddDataPoint(graph, newPos));
        }
    }
    replot();
}

void CustomPlot::deleteMarkerElements(const int index)
{
    QCPAbstractItem* item;
    deleteMarkerDataPoint(index);
    for (int i = 0; i < axisRectCount(); i++) {
        if ((item = markerLine(index, i))) {
            removeItem(item);
        }
    }
    if ((item = markerTitle(index))) {
        removeItem(item);
    }
    resetSelectedMarker();
    replot();
}

void CustomPlot::deleteMarkersElements()
{
    clearMarkerDifferences();
    for (const Marker* m : markers()) {
        deleteMarkerElements(m->index());
    }
}

void CustomPlot::addDataPointsMarker(QCPGraph* graph, int graph_idx, const int marker_idx, const double x, bool visible)
{
    QCPItemText* dataPoint = markerDataPoint(itemIndex(marker_idx, graph_idx), true);
    visible = visible && canAddDataPoint(graph, x);
    dataPoint->setFont(QFont(font().family(), 8, QFont::Medium));
    dataPoint->setColor(Qt::black);
    updateDataPointMarker(dataPoint, x, graph, visible);
}

bool CustomPlot::canAddDataPoint(const QCPGraph* graph, const double x) const
{
    if (graph->dataCount() > 0 && graph->visible()) {
        double firstKey = graph->data()->constBegin()->key;
        double lastKey = (graph->data()->constEnd() - 1)->key;
        if (lastKey > x && x > firstKey) {
            return true;
        }
    }
    return false;
}

void CustomPlot::addDataPointsMarker(QCPGraph* graph)
{
    for (int graph_idx = 0; graph_idx < graphCount(); graph_idx++) {
        if (this->graph(graph_idx) != graph) continue;

        for (const Marker* m : markers_) {
            if (QCPItemText* dataPoint = markerDataPoint(itemIndex(m->index(), graph_idx))) {
                updateDataPointMarker(dataPoint, m->xCoord(), graph, m->visible() && canAddDataPoint(graph, m->xCoord()));
            }
            else {
                addDataPointsMarker(graph, graph_idx, m->index(), m->xCoord(), m->visible());
            }
        }
    }
}

void CustomPlot::deleteMarker(Marker* m)
{
    // indexOf returns (and takeAt takes) a qsizetype in Qt 6 but
    // an int in Qt5. Cast to an int for now (we don't expect more
    // than 2^32 items) and avoid shortening warnings on 64-bit.
    int i = (int)markers_.indexOf(m);
    if (i >= 0) {
        Marker* mToDelete = markers_.takeAt(i);
        delete mToDelete;
    }
}

void CustomPlot::deleteAllMarkers()
{
    qDeleteAll(markers_);
    markers_.clear();
}

Marker* CustomPlot::addMarker(double x, bool isPosMarker) {
    Marker* m;
    if (isPosMarker) {
        m = posMarker();
        if (m) return m;
    }
    int index = markers_.isEmpty() ? 0 : markers_.last()->index() + 1;
    m = new Marker(x, index, isPosMarker);
    markers_.append(m);
    return m;
}

Marker* CustomPlot::marker(const QString& name)
{
    return marker([&](const Marker& m) { return m.name() == name; });
}

Marker* CustomPlot::marker(const int idx)
{
    return marker([=](const Marker& m) { return m.index() == idx; });
}

Marker* CustomPlot::posMarker()
{
    return marker([=](const Marker& m) { return m.isPosMarker(); });
}

Marker* CustomPlot::marker(const std::function<bool(const Marker& m)>& predicate)
{
    for (Marker* m : markers()) {
        if (predicate(*m)) {
            return m;
        }
    }
    return nullptr;
}

void CustomPlot::markerMoved(const Marker* m)
{
    markerMoved(m->index(), m->xCoord(), m->visible());
    clearMarkerDifferences();
    showMarkerDifferences();
}

QList<const Marker*> CustomPlot::visibleMarkers() const
{
    QList<const Marker*> markersList;
    for (const Marker* m : this->markers()) {
        if (m->visible()) {
            markersList.append(m);
        }
    }
    return markersList;
}

void CustomPlot::mouseMoveEvent(QMouseEvent* event)
{
    if (dragging_ && selected_marker_idx_ >= 0) {
        if (Marker* m = marker(selected_marker_idx_)) {
            double x = xAxis->pixelToCoord(event->pos().x());
            m->setXCoord(x);
            markerMoved(m);
            replot();
        }
    }
    QCustomPlot::mouseMoveEvent(event);
}

QCPItemStraightLine* CustomPlot::markerLine(const int mIdx, const int rectIdx, const bool create)
{
    return getOrAddQCPItem<QCPItemStraightLine>(this, marker_line_object_name_.arg(itemIndex(mIdx, rectIdx)), create);
}

QCPItemText* CustomPlot::markerTitle(const int idx, const bool create)
{
    return getOrAddQCPItem<QCPItemText>(this, marker_title_object_name_.arg(idx), create);
}

QCPItemText* CustomPlot::markerDataPoint(const QString& idx, const bool create)
{
    return getOrAddQCPItem<QCPItemText>(this, marker_label_object_name_.arg(idx), create);
}

void CustomPlot::deleteMarkerDataPoint(const int marker_idx)
{
    for (int graphIdx = 0; graphIdx < graphCount(); graphIdx++) {
        if (QCPAbstractItem* item = markerDataPoint(itemIndex(marker_idx, graphIdx))) {
            removeItem(item);
        }
    }
}

void CustomPlot::markerVisibilityChanged(const Marker* m)
{
    QCPAbstractItem* item;
    for (int idx = 0; idx < graphCount(); idx++) {
        if ((item = markerDataPoint(itemIndex(m->index(), idx)))) {
            item->setVisible(m->visible());
        }
    }
    for (int i = 0; i < axisRectCount(); i++) {
        if ((item = markerLine(m->index(), i))) {
            item->setVisible(m->visible());
        }
    }
    if ((item = markerTitle(m->index()))) {
        item->setVisible(m->visible());
    }
    replot();
}

void CustomPlot::mouseReleased()
{
    if (cursor().shape() == Qt::ClosedHandCursor) {
        setCursor(QCursor(Qt::OpenHandCursor));
    }
    dragging_ = false;
}

bool CustomPlot::mousePressed(QPoint pos)
{
    resetSelectedMarker();
    for (const Marker* m : markers()) {
        const QCPItemText* title = markerTitle(m->index());
        if (title && title->visible())
        {
            double distance = this->selectionTolerance();
            if (title->selectTest(pos, false) < distance) {
                selected_marker_idx_ = m->index();
                dragging_ = true;
            }
        }
    }
    return dragging_;
}
