/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IN_PACKET_FIND_BAR_H
#define IN_PACKET_FIND_BAR_H

#include <QModelIndex>
#include <QPropertyAnimation>
#include <QTimer>
#include <QWidget>

class InPacketSearch;
class ProtoTree;

namespace Ui {
class InPacketFindBar;
}

/**
 * @brief Find bar widget for the single-packet dialog only.
 *
 * Uses InPacketFindEdit (FilterEdit) for search-field syntax tinting. The
 * main-window Find Packet toolbar keeps DisplayFilterEdit for cross-packet find.
 */
class InPacketFindBar : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(int barHeight READ barHeight WRITE setBarHeight)

public:
    explicit InPacketFindBar(ProtoTree *tree, QWidget *parent = nullptr);
    ~InPacketFindBar();

    static int openInstances() { return open_instances_; }

    void showAnimated();
    void hideAnimated();
    void focusSearchField();

    bool isOpen() const { return is_open_; }

    bool isMatch(const QModelIndex &model_index) const;
    bool isCurrentMatch(const QModelIndex &model_index) const;

    int barHeight() const;
    void setBarHeight(int h);

signals:
    void matchesChanged();
    void openChanged(bool open);

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;

private slots:
    void onTextChanged(const QString &text);
    void performSearch();
    void executeFind();
    void closeBar();
    void onToggleChanged();

private:
    void advanceSearch(bool backward);
    void updateFindButtonState();
    void updateStyleSheet();
    void recalculateNaturalHeight();
    void updateCounterLabel();

    ProtoTree *proto_tree_;
    InPacketSearch *search_;
    Ui::InPacketFindBar *ui_ = nullptr;

    QTimer *debounce_timer_;
    QPropertyAnimation *animation_;
    QString last_search_pattern_;

    bool is_open_;
    static int open_instances_;
    int natural_height_;
};

#endif // IN_PACKET_FIND_BAR_H
