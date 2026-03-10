/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LEARN_CARD_WIDGET_H
#define LEARN_CARD_WIDGET_H

#include <QWidget>
#include <QFrame>
#include <QVBoxLayout>
#include <QColor>

#include "clickable_label.h"

class QPushButton;

struct learn_link_t {
    QString url;
    QString label;
    QString short_label;
    QString tooltip;
};

class LearnCardWidget : public QFrame {
    Q_OBJECT
public:
    explicit LearnCardWidget(QWidget *parent = nullptr);
    void updateStyleSheets(const QColor &header_text_color, const QColor &header_hover_color);
    void setLinksCollapsed(bool collapsed);
    bool isLinksCollapsed() const;

private:
    QVBoxLayout *main_layout_;
    ClickableLabel *header_label_;
    QFrame *header_separator_;
    QWidget *link_container_;
    QWidget *compact_link_container_;
    QPushButton *discord_button_;
    QPushButton *donate_button_;
    QList<learn_link_t> links_;
    bool links_collapsed_;

    void setupHeader();
    void setupLinks();
    void setupActionButtons();
};

#endif //LEARN_CARD_WIDGET_H
