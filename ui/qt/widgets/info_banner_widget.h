/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INFO_BANNER_WIDGET_H
#define INFO_BANNER_WIDGET_H

#include <QFrame>
#include <QColor>
#include <QDate>
#include <QString>
#include <QList>
#include <QMap>
#include <QPair>
#include <QTimer>

/**
 * @brief A widget that displays informational banners on the Welcome screen and elsewhere.
 */
class QJsonObject;

    enum BannerSlideType {
            BannerEvents,
            BannerSponsorship,
            BannerTips,
            BannerSeasonal,
    };
    Q_DECLARE_METATYPE(BannerSlideType)

    struct BannerSlide {
            BannerSlideType type;
            QString tag;              // type label shown as subheader, e.g. "Tip of the Day"
            QString title;            // main heading, e.g. "Quick Filter Shortcut"
            QString description;      // primary text shown in highlight box
            QString description_sub;  // secondary line in highlight box
            QString body_text;        // additional text below the highlight box
            QString button_label;     // action button text, e.g. "More Tips"
            QString url;              // click/button target
            QString image;            // banner image filename, resolved under :/json/banners/
            int date_month;           // optional month for seasonal slides (1-12)
            int date_day;             // optional day for seasonal slides (1-31)
            QString application;      // optional application filter (e.g. "tshark"), empty = all
            QDate date_from;          // slide visible from this date (inclusive), invalid = always
            QDate date_until;         // slide visible until this date (inclusive), invalid = always
    };

    struct SlideTypeConfig {
            bool randomized = false;
            int maxdisplay = 0;       // 0 = show all (no limit)
            bool only = false;        // only slides from this file for this type
            bool hidden = false;      // suppress this type entirely (custom files only)
            QColor color_start;       // gradient start color for this type, default if not specified in file
            QColor color_end;         // gradient end color for this type, default if not specified in file
            int color_gradient;       // optional gradient angle in degrees (0 = left-to-right, 90 = top-to-bottom, etc.)
            QList<QColor> steps;      // optional discrete gradient steps (overrides color_start/color_end if specified)
    };

/**
 * @brief A custom-painted rotating banner widget that cycles through
 *        informational slides.
 */
class InfoBannerWidget : public QFrame
{
    Q_OBJECT
public:
    /**
     * @brief Construct an InfoBannerWidget.
     * @param parent The parent widget; may be nullptr.
     */
    explicit InfoBannerWidget(QWidget *parent = nullptr);

    /**
     * @brief Switch between full-height and compact-height layout modes.
     *
     * In compact mode the widget uses @c kCardHeightCompact instead of
     * @c kCardHeight and suppresses the illustration area. The change
     * triggers a layout recalculation and repaint.
     *
     * @param compact true to enable compact mode; false for full mode.
     */
    void setCompactMode(bool compact);

    /**
     * @brief Return whether compact mode is currently active.
     * @return true if the widget is in compact mode.
     */
    bool isCompactMode() const;

    /**
     * @brief Freeze or unfreeze slide deck processing in case of changing
     *        preference settings.
     * @param freeze true to freeze slide deck processing; false to unfreeze
     *               and trigger slide deck processing.
     */
    void setSlideDeckFreeze(bool freeze);

    /**
     * @brief Show or hide all slides of a given type.
     *
     * @param type    The slide type to configure.
     * @param visible true to include slides of @p type in the rotation;
     *                false to suppress them.
     */
    void setSlideTypeVisible(BannerSlideType type, bool visible);

    /**
     * @brief Enable or disable automatic slide advancement.
     *
     * @param advance true to enable auto-advance; false to disable it.
     */
    void setAutoAdvance(bool advance);

    /**
     * @brief Set the auto-advance interval.
     * @param seconds Number of seconds between automatic slide transitions.
     *                Values are converted to milliseconds and stored in
     *                @c auto_advance_ms_. The timer is restarted if
     *                auto-advance is currently enabled.
     */
    void setAutoAdvanceInterval(unsigned seconds);

    /**
     * @brief Enable or disable slide test mode.
     * @param test true to enable test mode; false to restore normal operation.
     */
    void setSlidesTest(bool test);

    /**
     * @brief Return whether any slides are currently visible.
     * @return true if @c slides_ is non-empty after filtering; false if the
     *         widget has nothing to display and should be hidden.
     */
    bool hasVisibleSlides() const;

    /**
     * @brief Return the preferred size for the widget.
     *
     * @return The preferred @c QSize.
     */
    QSize sizeHint() const override;

    /**
     * @brief Return the minimum acceptable size for the widget.
     * @return The minimum @c QSize.
     */
    QSize minimumSizeHint() const override;

protected:
    /**
     * @brief Paint the current slide onto the widget surface.
     *
     * @param event The paint event (used to obtain the dirty rect).
     */
    void paintEvent(QPaintEvent *event) override;

    /**
     * @brief Handle mouse press events for dot navigation and button clicks.
     * @param event The mouse press event.
     */
    void mousePressEvent(QMouseEvent *event) override;

    /**
     * @brief Track the hovered dot and update the cursor.
     *
     * @param event The mouse move event.
     */
    void mouseMoveEvent(QMouseEvent *event) override;

    /**
     * @brief Clear the hover state when the pointer leaves the widget.
     *
     * @param event The leave event.
     */
    void leaveEvent(QEvent *event) override;

    /**
     * @brief Respond to widget state changes such as palette or font updates.
     *
     * @param event The change event; inspect @c event->type() to determine
     *              what changed.
     */
    void changeEvent(QEvent *event) override;

    /**
     * @brief Handle miscellaneous events, including tooltip queries.
     *
     * @param event The event to handle.
     * @return true if the event was consumed; false otherwise.
     */
    bool event(QEvent *event) override;

private:
    QList<BannerSlide> slides_;      /**< Ordered, filtered list of slides to display. */
    int current_slide_;              /**< Index into @c slides_ of the currently shown slide. */
    bool compact_mode_;              /**< true when the compact (half-height) layout is active. */
    bool hovered_;                   /**< true while the pointer is inside the widget bounds. */

    /** Per-type visibility flags, consulted by @c applySlideFilter(). */
    QMap<BannerSlideType, bool> slide_type_visible_;
    QTimer *auto_advance_timer_;     /**< Timer driving automatic slide rotation; nullptr when disabled. */
    int auto_advance_ms_;            /**< Current auto-advance interval in milliseconds. */
    bool slides_test_;               /**< true when slide test mode is active. */

    /** Merged per-type display configuration (predefined defaults + custom overrides). */
    QMap<BannerSlideType, SlideTypeConfig> type_config_;

    /** Date-filtered, visibility-processed slide lists keyed by type. */
    QMap<BannerSlideType, QList<BannerSlide>> slides_by_type_;

    /** Per-type rotation offsets used to implement @c maxdisplay windowing. */
    QMap<BannerSlideType, int> type_offsets_;

    QColor default_color_start_; /**< Gradient start colour for types with no entry in @c type_config_. */
    QColor default_color_end_;   /**< Gradient end colour for types with no entry in @c type_config_. */

    /**
     * @brief Initialise slide data by loading resources and building the sequence.
     */
    void setupSlides();

    /**
     * @brief Resolve a potentially internationalised text field from a JSON object.
     *
     * @param obj       The JSON object containing the field.
     * @param field     The base field name (e.g. @c "title").
     * @param is_custom true if the object originates from a custom (user)
     *                  resource; affects warning verbosity on missing fields.
     * @return The resolved string, or an empty string if the field is absent.
     */
    QString resolveI18nField(const QJsonObject &obj,
                             const QString &field,
                             bool is_custom) const;

    /**
     * @brief Parse a JSON resource file and populate configuration and slide maps.
     *
     * @param resource_path The Qt resource path (e.g. @c ":/slides/news.json").
     * @param is_custom     true if this is a user-supplied custom resource;
     *                      controls error reporting and merge priority.
     * @param file_config   Output map to receive per-type configuration from
     *                      this file.
     * @param file_slides   Output map to receive parsed slides from this file.
     */
    void loadSlidesFromResource(const QString &resource_path,
                                bool is_custom,
                                QMap<BannerSlideType, SlideTypeConfig> &file_config,
                                QMap<BannerSlideType, QList<BannerSlide>> &file_slides);

    /**
     * @brief Rebuild the active slide list from the current visibility map.
     */
    void applySlideFilter();

    /**
     * @brief Merge per-type slide lists into the final @c slides_ sequence.
     */
    void buildSlideSequence();

    /**
     * @brief Advance to the next slide in sequential order.
     */
    void advanceSlide();

    /**
     * @brief Advance to a randomly selected slide.
     */
    void advanceRandomSlide();

    /**
     * @brief Sync the widget's accessible name/description to the current slide.
     *
     * Updates accessibleName/Description to reflect the current slide and
     * notifies the platform AT via QAccessible::NameChanged. Must be called
     * whenever current_slide_ changes, because this widget is fully
     * custom-painted — there are no child widgets for AT to interrogate.
     */
    void updateAccessibility();

    /**
     * @brief Return the slide index whose dot contains @p pos, or -1.
     * @param pos A point in widget-local coordinates.
     * @return The zero-based slide index of the hit dot, or -1 if @p pos
     *         does not intersect any dot's hit area.
     */
    int dotHitTest(const QPoint &pos) const;

    /**
     * @brief Return the bounding rectangle of the dot indicator for a slide.
     * @param index Zero-based slide index.
     * @return The @c QRect of the dot in widget-local coordinates, centred
     *         on a circle of radius @c kDotRadius.
     */
    QRect dotRect(int index) const;

    /**
     * @brief Return the bounding rectangle of the action button.
     * @return The @c QRect of the CTA button in widget-local coordinates.
     */
    QRect buttonRect() const;

    /**
     * @brief Convert a type name string from JSON to a @c BannerSlideType.
     *
     * @param type_str The raw type string from JSON (e.g. @c "news").
     * @return The corresponding @c BannerSlideType enum value.
     */
    static BannerSlideType typeFromString(const QString &type_str);

    /**
     * @brief Convert a type string to @c BannerSlideType with error reporting.
     *
     * @param type_str      The raw type string from JSON.
     * @param resource_path The resource file being parsed (for the warning message).
     * @param context       A human-readable context label (e.g. the slide title).
     * @param is_custom     true if the resource is a custom user file.
     * @return The corresponding @c BannerSlideType, or a default on failure.
     */
    static BannerSlideType validTypeFromString(const QString &type_str,
                                               const QString &resource_path,
                                               const QString &context,
                                               bool is_custom);

    // ── Layout constants ──────────────────────────────────────────────────

    static constexpr int kCardWidth          = 300;  /**< Fixed widget width in pixels. */
    static constexpr int kCardHeight         = 360;  /**< Full-mode widget height in pixels. */
    static constexpr int kCardHeightCompact  = 180;  /**< Compact-mode widget height in pixels. */
    static constexpr int kIllustrationHeight = 120;  /**< Height reserved for the slide illustration in full mode. */
    static constexpr int kContentLeftMargin  = 16;   /**< Left padding for text and button content. */
    static constexpr int kContentRightMargin = 16;   /**< Right padding for text and button content. */
    static constexpr int kDotRadius          = 4;    /**< Radius of each dot indicator in pixels. */
    static constexpr int kDotSpacing         = 12;   /**< Centre-to-centre spacing between dot indicators. */
    static constexpr int kDotBottomMargin    = 14;   /**< Distance from the widget bottom edge to the dot row centre. */
    static constexpr int kDefaultAutoAdvanceMs = 8000; /**< Default auto-advance interval: 8 seconds. */
};

#endif // INFO_BANNER_WIDGET_H
