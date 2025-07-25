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

class Marker : public QWidget {
    Q_OBJECT
public:
    Marker(const double x, const int, const bool isPosMarker);
    QString name() const { return isPosMarker() ? QString("P") : QString("M%1").arg(index()); }
    int index() const { return index_; }
    static int index(const Marker* m) { return m ? m->index() : -1; }
    static QString toHex(long long);
    double xCoord() const { return x_coord_; }
    void setXCoord(double value);
    bool isPosMarker() const { return is_pos_marker_; }
    void setVisibility(const bool v) { visible_ = v; }
    bool visible() const { return visible_; }
private:
    int index_;
    double x_coord_;
    bool is_pos_marker_;
    bool visible_;
};

class MarkerDialog final : public QDialog{
    Q_OBJECT

public:
    MarkerDialog(QWidget* parent, bool showToMove, const QVector<Marker*>& markers);
    ~MarkerDialog() final;
    QString getText() const { return result_; }
    QString selectedMarker() const { return selected_marker_; }
private slots:
    void comboItemChanged(const QString& text);

private:
    QString result_;
    QString selected_marker_;
    void reject() override;
};
#endif //CUSTOMPLOT_MARKER_H
