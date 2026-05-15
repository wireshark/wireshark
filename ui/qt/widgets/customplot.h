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

/**
 * @brief An extended QCustomPlot widget supporting markers, data points, and their interactions.
 */
class CustomPlot : public QCustomPlot {
    Q_OBJECT
public:
    /**
     * @brief Constructs a new CustomPlot.
     * @param widget The parent widget.
     */
    explicit CustomPlot(QWidget* widget);

    /**
     * @brief Destroys the CustomPlot.
     */
    ~CustomPlot();

    /**
     * @brief Shows the calculated differences between visible markers.
     */
    void showMarkerDifferences();

    /**
     * @brief Sets the visibility of data points on the plot.
     * @param visible True to show data points, false to hide them.
     */
    void setDataPointVisibility(const bool visible);

    /**
     * @brief Retrieves the current value traced by the plot.
     * @return The value formatted as a string.
     */
    QString currentValue() const { return QString::number(tracer()->position->value(), 'g', 4); }

    /**
     * @brief Handles mouse release logic specific to the plot markers and interactions.
     */
    void mouseReleased();

    /**
     * @brief Handles mouse press logic, returning whether interaction was captured.
     * @param pos The position of the mouse press.
     * @return True if a plot interaction was handled, false otherwise.
     */
    bool mousePressed(QPoint pos);

    /**
     * @brief Clears any displayed marker differences.
     */
    void clearMarkerDifferences();

    /**
     * @brief Retrieves the index of the currently selected marker.
     * @return The selected marker index.
     */
    inline int selectedMarker() const { return selected_marker_idx_; }

    /**
     * @brief Handles a visibility change for a specific marker.
     * @param m The marker whose visibility changed.
     */
    void markerVisibilityChanged(const Marker* m);

    /**
     * @brief Toggles the visibility of the difference between markers.
     * @param show True to show the difference, false to hide it.
     */
    void showMarkersDifference(bool show) { marker_diff_visible_ = show; }

    /**
     * @brief Adds plot elements (lines, labels) associated with a marker.
     * @param marker The marker.
     */
    void addMarkerElements(const Marker* marker);

    /**
     * @brief Deletes visual elements for all markers.
     */
    void deleteMarkersElements();

    /**
     * @brief Deletes visual elements for a specific marker.
     * @param index The index of the marker.
     */
    void deleteMarkerElements(const int index);

    /**
     * @brief Adds data point markers along a specific graph.
     * @param graph The graph to add data points to.
     */
    void addDataPointsMarker(QCPGraph* graph);

    /**
     * @brief Retrieves a string identifying the selected marker, optionally ignoring one index.
     * @param ignoreIdx The index to ignore.
     * @return The marker identification string.
     */
    QString selectedMarker(const int ignoreIdx);

    /**
     * @brief Retrieves all markers currently in the plot.
     * @return A vector of marker pointers.
     */
    QVector<Marker*> markers() const { return markers_; }

    /**
     * @brief Adds a new marker at the specified X coordinate.
     * @param x The X coordinate.
     * @param isPosMarker True if the marker represents the current tracer position.
     * @return A pointer to the newly created marker.
     */
    Marker* addMarker(double x, bool isPosMarker);

    /**
     * @brief Deletes a specific marker.
     * @param m The marker to delete.
     */
    void deleteMarker(Marker* m);

    /**
     * @brief Deletes all markers from the plot.
     */
    void deleteAllMarkers();

    /**
     * @brief Retrieves a list of all currently visible markers.
     * @return A list of visible marker pointers.
     */
    QList<const Marker*> visibleMarkers() const;

    /**
     * @brief Retrieves a marker by its name/identifier.
     * @param name The identifier of the marker.
     * @return A pointer to the marker, or nullptr if not found.
     */
    Marker* marker(const QString& name);

    /**
     * @brief Retrieves a marker by its index.
     * @param idx The index of the marker.
     * @return A pointer to the marker, or nullptr if not found.
     */
    Marker* marker(const int idx);

    /**
     * @brief Retrieves the special position marker linked to the tracer.
     * @return A pointer to the position marker.
     */
    Marker* posMarker();

    /**
     * @brief Updates plot visuals when a marker has been moved.
     * @param m The marker that moved.
     */
    void markerMoved(const Marker* m);

protected:
    /**
     * @brief Handles mouse movement events for tracking and dragging.
     * @param event The mouse event.
     */
    void mouseMoveEvent(QMouseEvent* event) override;

    /**
     * @brief Handles cleanup when an axis is removed from the plot.
     * @param axis The axis being removed.
     */
    void axisRemoved(QCPAxis* axis) override;

private:
    /**
     * @brief Handles internal logic when a marker moves.
     * @param idx The marker index.
     * @param newPos The new position.
     * @param visible whether the marker is visible.
     */
    void markerMoved(const int idx, const double newPos, const bool visible);

    /**
     * @brief Sorts and returns a list of markers by their X position.
     * @param list The input list.
     * @return The ordered list of markers.
     */
    QList<const Marker*> orderedMarkers(QList<const Marker*> list) const;

    /**
     * @brief Adds title visual elements for a marker.
     * @param marker The marker.
     */
    void addTitleMarker(const Marker* marker);

    /**
     * @brief Finds and returns the plot's QCPItemTracer.
     * @return A pointer to the tracer.
     */
    QCPItemTracer* tracer() const { return findChild<QCPItemTracer*>(); }

    /**
     * @brief Resets the current selected marker index to none.
     */
    void resetSelectedMarker() { selected_marker_idx_ = -1; }

    /**
     * @brief Deletes the data point text item for a marker.
     * @param marker_idx The marker index.
     */
    void deleteMarkerDataPoint(const int marker_idx);

    /**
     * @brief Retrieves or creates a title text item for a marker.
     * @param idx The marker index.
     * @param create True to create if it doesn't exist, defaults to false.
     * @return A pointer to the text item.
     */
    QCPItemText* markerTitle(const int idx, const bool create = false);

    /**
     * @brief Retrieves or creates a data point text item by identifier.
     * @param idx The identifier string.
     * @param create True to create if it doesn't exist, defaults to false.
     * @return A pointer to the text item.
     */
    QCPItemText* markerDataPoint(const QString& idx, const bool create = false);

    /**
     * @brief Retrieves or creates a straight line item for a marker constraint.
     * @param mIdx The marker index.
     * @param rectIdx The rectangle constraint index.
     * @param create True to create if it doesn't exist, defaults to false.
     * @return A pointer to the straight line item.
     */
    QCPItemStraightLine* markerLine(const int mIdx, const int rectIdx, const bool create = false);

    /**
     * @brief Updates the properties of a QCPItemText element.
     * @param item The text item to update.
     * @param txt The new text.
     * @param pos The new position.
     * @param y_axis Optional Y axis to bind to, defaults to Q_NULLPTR.
     */
    void updateQCPItemText(QCPItemText* item, const QString& txt, const QPointF pos, QCPAxis* y_axis = Q_NULLPTR);

    /**
     * @brief Updates a data point marker element along a graph.
     * @param item The text item representing the point.
     * @param x The X coordinate.
     * @param graph The graph it belongs to.
     * @param visible The visibility state.
     */
    void updateDataPointMarker(QCPItemText* item, const double x, QCPGraph* graph, bool visible);

    /**
     * @brief Retrieves formatted text for a data point at a given X coordinate.
     * @param x The X coordinate.
     * @return The formatted text.
     */
    QString dataPointMarker(const double x) const;

    /**
     * @brief Generates a composite string key for an item belonging to a marker and graph.
     * @param markerIdx The marker index.
     * @param graphIdx The graph index.
     * @return The formatted key string.
     */
    inline QString itemIndex(int markerIdx, int graphIdx) const { return QString("%1_%2").arg(markerIdx).arg(graphIdx); }

    /**
     * @brief Adds a specific data point marker element.
     * @param graph The target graph.
     * @param graph_idx The target graph's index.
     * @param marker_idx The marker index.
     * @param x The X coordinate.
     * @param visible The initial visibility.
     */
    void addDataPointsMarker(QCPGraph* graph, int graph_idx, const int marker_idx, const double x, bool visible);

    /**
     * @brief Checks whether a data point can be validly added at the X coordinate on the graph.
     * @param graph The graph to check.
     * @param x The X coordinate.
     * @return True if valid, false otherwise.
     */
    bool canAddDataPoint(const QCPGraph* graph, const double x) const;

    /**
     * @brief Finds a marker using a lambda predicate.
     * @param predicate The function evaluating markers.
     * @return A pointer to the first matching marker, or nullptr.
     */
    Marker* marker(const std::function<bool(const Marker&)>& predicate);

    /**
     * @brief Template function to retrieve or create a specific type of QCPAbstractItem.
     * @tparam T The QCPAbstractItem subtype.
     * @param plot The parent plot.
     * @param objName The object name to search for or assign.
     * @param create True to create if not found.
     * @return A pointer to the item.
     */
    template <typename T>
    typename std::enable_if<std::is_base_of<QCPAbstractItem, T>::value, T*>::type
        getOrAddQCPItem(QCustomPlot* plot, const QString& objName, const bool create);

    /** Index of the currently selected marker. */
    int selected_marker_idx_;

    /** Flag indicating if data points are globally visible. */
    bool data_point_visible_;

    /** Flag indicating if marker differences are visible. */
    bool marker_diff_visible_;

    /** Flag indicating if a drag operation is ongoing. */
    bool dragging_;

    /** Collection of all markers attached to the plot. */
    QVector<Marker*> markers_;
};

/**
 * @brief Template function to retrieve or create a specific type of QCPAbstractItem.
 * @tparam T The QCPAbstractItem subtype.
 * @param plot The parent plot.
 * @param objName The object name to search for or assign.
 * @param create True to create if not found.
 * @return A pointer to the item.
 */
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
