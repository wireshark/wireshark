/** marker_dialog.h
 * Marker of customplot (Header file)
 * By Hamdi Miladi <hamdi.miladi@technica-engineering.de>
 * Copyright 2025 Hamdi Miladi
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qobject.h"
#include "qdialog.h"

#ifndef CUSTOMPLOT_MARKER_H
#define CUSTOMPLOT_MARKER_H

/**
 * @brief A widget representing a marker on a graph or timeline.
 */
class Marker : public QWidget {
    Q_OBJECT
public:
    /**
     * @brief Constructs a new Marker.
     * @param x The initial X coordinate of the marker.
     * @param index The index identifier of the marker.
     * @param isPosMarker True if this is a position marker, false otherwise.
     */
    Marker(const double x, const int index, const bool isPosMarker);

    /**
     * @brief Gets the formatted name of the marker.
     * @return The name string.
     */
    QString name() const { return isPosMarker() ? QString("P") : QString("M%1").arg(index()); }

    /**
     * @brief Gets the index of the marker.
     * @return The index value.
     */
    int index() const { return index_; }

    /**
     * @brief Retrieves the index of a given marker pointer.
     * @param m Pointer to the marker.
     * @return The index of the marker, or -1 if the pointer is null.
     */
    static int index(const Marker* m) { return m ? m->index() : -1; }

    /**
     * @brief Converts a value to its hexadecimal string representation.
     * @param value The value to convert.
     * @return The hexadecimal string.
     */
    static QString toHex(long long value);

    /**
     * @brief Gets the X coordinate of the marker.
     * @return The X coordinate.
     */
    double xCoord() const { return x_coord_; }

    /**
     * @brief Sets the X coordinate of the marker.
     * @param value The new X coordinate.
     */
    void setXCoord(double value);

    /**
     * @brief Checks if this is a position marker.
     * @return True if it is a position marker, false otherwise.
     */
    bool isPosMarker() const { return is_pos_marker_; }

    /**
     * @brief Sets the visibility of the marker.
     * @param v True to make visible, false to hide.
     */
    void setVisibility(const bool v) { visible_ = v; }

    /**
     * @brief Checks if the marker is visible.
     * @return True if visible, false otherwise.
     */
    bool visible() const { return visible_; }
private:
    /** The index identifier of the marker. */
    int index_;

    /** The X coordinate of the marker. */
    double x_coord_;

    /** Flag indicating if this is a position marker. */
    bool is_pos_marker_;

    /** Flag indicating the visibility state of the marker. */
    bool visible_;
};

/**
 * @brief A dialog for interacting with and selecting markers.
 */
class MarkerDialog final : public QDialog{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new MarkerDialog.
     * @param parent The parent widget.
     * @param showToMove True to show options for moving markers.
     * @param markers The collection of available markers.
     */
    MarkerDialog(QWidget* parent, bool showToMove, const QVector<Marker*>& markers);

    /**
     * @brief Destroys the MarkerDialog.
     */
    ~MarkerDialog() final;

    /**
     * @brief Gets the resulting text input from the dialog.
     * @return The result string.
     */
    QString getText() const { return result_; }

    /**
     * @brief Gets the currently selected marker's identifier.
     * @return The selected marker string.
     */
    QString selectedMarker() const { return selected_marker_; }
private slots:
    /**
     * @brief Slot triggered when the combo box selection changes.
     * @param text The newly selected text.
     */
    void comboItemChanged(const QString& text);

private:
    /** The resulting text from the dialog interaction. */
    QString result_;

    /** The identifier of the selected marker. */
    QString selected_marker_;

    /**
     * @brief Handles the rejection (cancel/close) event of the dialog.
     */
    void reject() override;
};
#endif //CUSTOMPLOT_MARKER_H
