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

class LearnCardWidget : public QFrame {
    Q_OBJECT
public:
    explicit LearnCardWidget(QWidget *parent = nullptr);
    void updateStyleSheets(const QColor &header_text_color, const QColor &header_hover_color);
    void setLinksCollapsed(bool collapsed);
    bool isLinksCollapsed() const;

private:

    enum ValidityType {
        AllVersions,
        ReleaseOnly,
        DevOnly
    };

    struct LinkType {
        QString url;
        QString label;
        QString short_label;
        QString tooltip;
        ValidityType validity;
    };

    struct ButtonType {
        QString url;
        QString label;
        QString tooltip;
        QColor color;
        QColor hover_color;
        ValidityType validity;
    };


    QVBoxLayout *main_layout_;
    QWidget *link_container_;
    QList<LinkType> links_;
    QList<ButtonType> buttons_;
    bool links_collapsed_;

    void loadLinksFromRessource();

    void setupLayout();
    void setupHeader();
    void setupLinks();
    void setupActionButtons();


};

#endif //LEARN_CARD_WIDGET_H
