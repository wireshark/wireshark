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

class QJsonObject;

enum BannerSlideType {
    BannerEvents,
    BannerSponsorship,
    BannerTips,
};

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
    QDate date_from;          // slide visible from this date (inclusive), invalid = always
    QDate date_until;         // slide visible until this date (inclusive), invalid = always
};

struct SlideTypeConfig {
    bool randomized = false;
    int maxdisplay = 0;       // 0 = show all (no limit)
    bool only = false;        // only slides from this file for this type
    bool hidden = false;      // suppress this type entirely (custom files only)
    QColor color_start;
    QColor color_end;
};

class InfoBannerWidget : public QFrame {
    Q_OBJECT
public:
    explicit InfoBannerWidget(QWidget *parent = nullptr);

    void updateStyleSheets();
    void setCompactMode(bool compact);
    bool isCompactMode() const;
    void setSlideTypeVisible(BannerSlideType type, bool visible);
    void setAutoAdvanceInterval(unsigned seconds);
    void applySlideFilter();

    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void changeEvent(QEvent *event) override;

private:
    QList<BannerSlide> all_slides_;
    QList<BannerSlide> slides_;
    int current_slide_;
    bool compact_mode_;
    QMap<BannerSlideType, bool> slide_type_visible_;
    QTimer *auto_advance_timer_;
    int auto_advance_ms_;

    // Per-type configuration (merged from predefined + custom)
    QMap<BannerSlideType, SlideTypeConfig> type_config_;
    // Per-type slide lists (date-filtered, after only/hidden processing)
    QMap<BannerSlideType, QList<BannerSlide>> slides_by_type_;
    // Per-type rotation offset for maxdisplay windowing
    QMap<BannerSlideType, int> type_offsets_;
    // Default gradient colors (for types not in config)
    QColor default_color_start_;
    QColor default_color_end_;

    void setupSlides();
    QString resolveI18nField(const QJsonObject &obj,
                             const QString &field,
                             bool is_custom) const;
    void loadSlidesFromResource(const QString &resource_path,
                                bool is_custom,
                                QMap<BannerSlideType, SlideTypeConfig> &file_config,
                                QMap<BannerSlideType, QList<BannerSlide>> &file_slides);
    void buildSlideSequence();
    void advanceSlide();
    // Updates accessibleName/Description to reflect the current slide and
    // notifies the platform AT via QAccessible::NameChanged. Must be called
    // whenever current_slide_ changes, because this widget is fully
    // custom-painted — there are no child widgets for AT to interrogate.
    void updateAccessibility();
    QPair<QColor, QColor> gradientForType(BannerSlideType type) const;
    int dotHitTest(const QPoint &pos) const;
    QRect dotRect(int index) const;
    QRect buttonRect() const;
    static BannerSlideType typeFromString(const QString &type_str);

    // Layout constants
    static constexpr int kCardWidth = 300;
    static constexpr int kCardHeight = 360;
    static constexpr int kCardHeightCompact = 180;
    static constexpr int kIllustrationHeight = 120;
    static constexpr int kContentLeftMargin = 16;
    static constexpr int kContentRightMargin = 16;
    static constexpr int kDotRadius = 4;
    static constexpr int kDotSpacing = 12;
    static constexpr int kDotBottomMargin = 14;
    static constexpr int kDefaultAutoAdvanceMs = 8000;
};

#endif // INFO_BANNER_WIDGET_H
