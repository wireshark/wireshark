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

    /**
     * @brief Leave the card's styling to an ancestor's style sheet.
     *
     * By default the card sets the live learn-card style sheet on itself and
     * renews it on every theme change.  A widget's own sheet wins over its
     * ancestors', so a preview that styles the card from its own sheet (the
     * Theme Designer's draft preview) turns this off.
     *
     * @param styled_by_parent true to clear the card's own sheet and keep it clear.
     */
    void setStyledByParent(bool styled_by_parent);

    /**
     * @brief Set the link color of the card (normally CardLink of the live
     * theme).  A card styled by its parent keeps this color across theme
     * changes, so the parent can set the color of the theme it shows.
     *
     * @param color the link color.
     */
    void setCardLinkColor(const QColor &color);

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
        /** "#RRGGBB" seed or ThemeToken name, resolved when the
         *  buttons are styled. */
        QString color;
        ValidityType validity; /**< Build scope in which this button is displayed. */
    };

    Ui::LearnCardWidget *ui_; /**< Qt Designer–generated UI form. */
    QList<LinkType> links_;   /**< Links loaded from the resource, filtered by validity. */
    /** Action buttons loaded from the resource, filtered by validity. */
    QList<ButtonType> buttons_;
    bool links_collapsed_;    /**< true when the links section is in its collapsed state. */
    bool styled_by_parent_ = false; /**< true when an ancestor's style sheet styles the card. */
    QColor card_link_color_;        /**< Link color of the link labels, see setCardLinkColor(). */

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
     * @brief Re-apply everything the theme drives: the card style
     * sheet, the action buttons (their fill can come from a theme
     * token) and the card link color.
     */
    void applyTheme();

    /**
     * @brief Set the card link color (CardLink, or the color given to
     * setCardLinkColor()) as QPalette::Link of every link label.
     */
    void applyCardLinkPalette();

    /**
     * @brief Resolve a button color spec for the current theme and mode.
     * @param spec "#RRGGBB" or a ThemeToken name.
     * @return The color, or an invalid QColor if @p spec cannot be
     * resolved.
     */
    static QColor resolveButtonColor(const QString &spec);

    /** @brief Set the live learn-card sheet unless styled by a parent. */
    void applyStyleSheet();
};

#endif //LEARN_CARD_WIDGET_H
