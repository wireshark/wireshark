/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAY_FILTER_COMBO_H
#define DISPLAY_FILTER_COMBO_H

#include <QComboBox>
#include <QList>

class DisplayFilterCombo : public QComboBox
{
    Q_OBJECT
public:
    explicit DisplayFilterCombo(QWidget *parent = 0);
    bool addRecentCapture(const char *filter);
    void writeRecent(FILE *rf);
    void updateStyleSheet();

protected:
#if QT_VERSION < QT_VERSION_CHECK(5, 15, 0)
    void rowsAboutToBeInserted(const QModelIndex&, int, int);
    void rowsInserted(const QModelIndex&, int, int);
#endif
    virtual bool event(QEvent *event);

private:
#if QT_VERSION < QT_VERSION_CHECK(5, 15, 0)
    bool clear_state_;
#endif

public slots:
    bool checkDisplayFilter();
    void applyDisplayFilter();
    void setDisplayFilter(QString filter);

private slots:
    void updateMaxCount();
    void onActivated(int index);
};

#endif // DISPLAY_FILTER_COMBO_H
