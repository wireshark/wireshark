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
#include <QColor>

class QPushButton;

namespace Ui {
class LearnCardWidget;
}

/**
 * @brief A card widget displaying learning resources, links, and action buttons.
 */
class LearnCardWidget : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Construct a LearnCardWidget.
     * @param parent The parent widget; may be nullptr.
     */
    explicit LearnCardWidget(QWidget *parent = nullptr);

    /** @brief Destroy the widget and its UI form. */
    ~LearnCardWidget();

    /**
     * @brief Collapse or expand the links section.
     *
     * @param collapsed true to hide the links list; false to show it.
     */
    void setLinksCollapsed(bool collapsed);

    /**
     * @brief Return whether the links section is currently collapsed.
     * @return true if the link list is hidden; false if it is visible.
     */
    bool isLinksCollapsed() const;

protected:
    /**
     * @brief Handle widget events, including palette and style changes.
     *
     * @param event The event to handle.
     * @return true if the event was consumed; false to allow further
     *         processing by the base class.
     */
    bool event(QEvent *event) override;

private:
    /**
     * @brief Scope of application version in which a link or button is shown.
     */
    enum ValidityType {
        AllVersions, /**< Shown in every build. */
        ReleaseOnly, /**< Shown only in release (non-development) builds. */
        DevOnly      /**< Shown only in development builds. */
    };

    /**
     * @brief Data for a single hyperlink entry in the links section.
     */
    struct LinkType {
        QString url;          /**< Target URL opened when the link is activated. */
        QString label;        /**< Full display text used when the links section is expanded. */
        QString short_label;  /**< Abbreviated display text used in compact or collapsed layouts. */
        QString tooltip;      /**< Tooltip shown on hover, providing additional context. */
        ValidityType validity; /**< Build scope in which this link is displayed. */
    };

    /**
     * @brief Data for a single action button.
     */
    struct ButtonType {
        QString url;           /**< URL opened when the button is clicked. */
        QString label;         /**< Button face text. */
        QString tooltip;       /**< Tooltip shown on hover. */
        QColor color;          /**< Normal background colour of the button. */
        QColor hover_color;    /**< Background colour applied when the button is hovered. */
        ValidityType validity; /**< Build scope in which this button is displayed. */
    };

    Ui::LearnCardWidget *ui_; /**< Qt Designer–generated UI form. */
    QList<LinkType> links_;   /**< Links loaded from the resource, filtered by validity. */
    QList<ButtonType> buttons_; /**< Action buttons loaded from the resource, filtered by validity. */
    bool links_collapsed_;    /**< true when the links section is in its collapsed state. */

    /**
     * @brief Load link and button definitions from the embedded resource file.
     */
    void loadLinksFromRessource();

    /**
     * @brief Create and insert link label widgets from @c links_.
     */
    void setupLinks();

    /**
     * @brief Create and insert action button widgets from @c buttons_.
     */
    void setupActionButtons();

    /**
     * @brief Reapply dynamic stylesheets to all links and action buttons.
     */
    void updateStyleSheet();
};

#endif //LEARN_CARD_WIDGET_H
