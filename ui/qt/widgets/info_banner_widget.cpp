/* info_banner_widget.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/info_banner_widget.h>

#include <QEvent>
#include <QLocale>
#include <QPainter>
#include <QPainterPath>
#include <QLinearGradient>
#include <QMouseEvent>
#include <QDesktopServices>
#include <QUrl>
#include <QFont>
#include <QFontMetrics>
#include <QPixmap>
#include <QtMath>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QAccessible>

#include <ui/recent.h>

#include <algorithm>
#include <random>

InfoBannerWidget::InfoBannerWidget(QWidget *parent) :
    QFrame(parent)
    , current_slide_(0)
    , compact_mode_(false)
    , auto_advance_timer_(new QTimer(this))
    , auto_advance_ms_(kDefaultAutoAdvanceMs)
    , default_color_start_(QColor(0x33, 0x33, 0x33))
    , default_color_end_(QColor(0x22, 0x22, 0x22))
{
    slide_type_visible_[BannerEvents] = true;
    slide_type_visible_[BannerSponsorship] = true;
    slide_type_visible_[BannerTips] = true;
    setupSlides();
    applySlideFilter();

    setMouseTracking(true);
    setCursor(Qt::PointingHandCursor);
    setFrameShape(QFrame::NoFrame);
    setFixedWidth(kCardWidth);
    setMinimumHeight(kCardHeight);
    setMaximumHeight(kCardHeight);

    connect(auto_advance_timer_, &QTimer::timeout, this, &InfoBannerWidget::advanceSlide);
    auto_advance_timer_->start(auto_advance_ms_);
}

BannerSlideType InfoBannerWidget::typeFromString(const QString &type_str)
{
    if (type_str == QLatin1String("events"))
        return BannerEvents;
    if (type_str == QLatin1String("sponsorship"))
        return BannerSponsorship;
    if (type_str == QLatin1String("tips"))
        return BannerTips;
    return static_cast<BannerSlideType>(-1);
}

QString InfoBannerWidget::resolveI18nField(const QJsonObject &obj,
                                            const QString &field,
                                            bool is_custom) const
{
    QString value = obj.value(field).toString();
    if (value.isEmpty())
        return value;

    if (!is_custom) {
        // Predefined slides: use Qt translation system
        return tr(value.toUtf8().constData());
    }

    // Custom slides: check _i18n map for current locale
    QString i18n_key = field + QStringLiteral("_i18n");
    QJsonObject i18n_map = obj.value(i18n_key).toObject();
    if (!i18n_map.isEmpty()) {
        QString locale = QLocale().name();           // e.g. "de_DE"
        QString lang = locale.section('_', 0, 0);    // e.g. "de"
        if (i18n_map.contains(locale))
            return i18n_map.value(locale).toString();
        if (i18n_map.contains(lang))
            return i18n_map.value(lang).toString();
    }
    return value;  // English fallback
}

void InfoBannerWidget::changeEvent(QEvent *event)
{
    if (event && event->type() == QEvent::LanguageChange) {
        setupSlides();
        applySlideFilter();
    }
    QFrame::changeEvent(event);
}

QPair<QColor, QColor> InfoBannerWidget::gradientForType(BannerSlideType type) const
{
    if (type_config_.contains(type)) {
        const SlideTypeConfig &cfg = type_config_[type];
        if (cfg.color_start.isValid() && cfg.color_end.isValid())
            return { cfg.color_start, cfg.color_end };
    }
    return { default_color_start_, default_color_end_ };
}

void InfoBannerWidget::setupSlides()
{
    all_slides_.clear();
    type_config_.clear();
    slides_by_type_.clear();
    type_offsets_.clear();

    // Load predefined slides and config
    QMap<BannerSlideType, SlideTypeConfig> predefined_config;
    QMap<BannerSlideType, QList<BannerSlide>> predefined_slides;
    loadSlidesFromResource(QStringLiteral(":/json/slides.json"), false,
                           predefined_config, predefined_slides);

    // Load custom slides and config
    QMap<BannerSlideType, SlideTypeConfig> custom_config;
    QMap<BannerSlideType, QList<BannerSlide>> custom_slides;
    loadSlidesFromResource(QStringLiteral(":/json/slides_custom.json"), true,
                           custom_config, custom_slides);

    // Merge config: start with predefined, overlay custom per type
    type_config_ = predefined_config;
    for (auto it = custom_config.constBegin(); it != custom_config.constEnd(); ++it) {
        BannerSlideType type = it.key();
        const SlideTypeConfig &cc = it.value();
        if (type_config_.contains(type)) {
            SlideTypeConfig &merged = type_config_[type];
            merged.randomized = cc.randomized;
            merged.maxdisplay = cc.maxdisplay;
            // hidden is only valid from custom files
            merged.hidden = cc.hidden;
            // Custom colors override if valid
            if (cc.color_start.isValid())
                merged.color_start = cc.color_start;
            if (cc.color_end.isValid())
                merged.color_end = cc.color_end;
            // only: custom can only set it if predefined didn't
            if (!merged.only)
                merged.only = cc.only;
        } else {
            type_config_[type] = cc;
        }
    }

    // Merge slides per type, respecting only and hidden flags
    const QList<BannerSlideType> all_types = { BannerEvents, BannerSponsorship, BannerTips };
    for (BannerSlideType type : all_types) {
        const SlideTypeConfig &cfg = type_config_[type];

        // hidden: suppress this type entirely
        if (cfg.hidden)
            continue;

        QList<BannerSlide> merged;
        bool pred_only = predefined_config.contains(type) && predefined_config[type].only;
        bool cust_only = custom_config.contains(type) && custom_config[type].only;

        if (pred_only) {
            // slides.json says only: use only predefined slides
            merged = predefined_slides.value(type);
        } else if (cust_only) {
            // custom says only (and predefined didn't): use only custom slides
            merged = custom_slides.value(type);
        } else {
            // Normal merge: predefined + custom
            merged = predefined_slides.value(type);
            merged.append(custom_slides.value(type));
        }

        if (!merged.isEmpty()) {
            slides_by_type_[type] = merged;
        }
    }

    // Randomize per type if configured
    std::random_device rd;
    std::mt19937 rng(rd());
    for (auto it = slides_by_type_.begin(); it != slides_by_type_.end(); ++it) {
        if (type_config_.value(it.key()).randomized) {
            std::shuffle(it.value().begin(), it.value().end(), rng);
        }
    }

    // Initialize per-type offsets
    for (auto it = slides_by_type_.constBegin(); it != slides_by_type_.constEnd(); ++it) {
        type_offsets_[it.key()] = 0;
    }

    // Populate all_slides_ for backward compat (used by applySlideFilter)
    for (auto it = slides_by_type_.constBegin(); it != slides_by_type_.constEnd(); ++it) {
        all_slides_.append(it.value());
    }
}

void InfoBannerWidget::loadSlidesFromResource(const QString &resource_path,
                                               bool is_custom,
                                               QMap<BannerSlideType, SlideTypeConfig> &file_config,
                                               QMap<BannerSlideType, QList<BannerSlide>> &file_slides)
{
    QFile file(resource_path);
    if (!file.exists())
        return;
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning("InfoBannerWidget: cannot open %s", qUtf8Printable(resource_path));
        return;
    }

    QJsonParseError parse_error;
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parse_error);
    file.close();

    if (parse_error.error != QJsonParseError::NoError) {
        qWarning("InfoBannerWidget: JSON parse error in %s: %s",
                 qUtf8Printable(resource_path),
                 qUtf8Printable(parse_error.errorString()));
        return;
    }

    QJsonObject root = doc.object();
    if (root.value(QStringLiteral("schema_version")).toInt() < 1) {
        qWarning("InfoBannerWidget: unsupported schema_version in %s",
                 qUtf8Printable(resource_path));
        return;
    }

    // Parse config section
    QJsonObject config_obj = root.value(QStringLiteral("config")).toObject();
    if (!config_obj.isEmpty()) {
        // Parse default colors
        QJsonObject colors_obj = config_obj.value(QStringLiteral("colors")).toObject();
        if (colors_obj.contains(QStringLiteral("default"))) {
            QJsonObject def = colors_obj.value(QStringLiteral("default")).toObject();
            QColor start(def.value(QStringLiteral("start")).toString());
            QColor end(def.value(QStringLiteral("end")).toString());
            if (start.isValid())
                default_color_start_ = start;
            if (end.isValid())
                default_color_end_ = end;
        }

        // Parse per-type colors
        const QStringList color_types = { QStringLiteral("events"), QStringLiteral("sponsorship"), QStringLiteral("tips") };
        for (const QString &type_name : color_types) {
            if (!colors_obj.contains(type_name))
                continue;
            BannerSlideType type = typeFromString(type_name);
            if (static_cast<int>(type) < 0)
                continue;
            QJsonObject cobj = colors_obj.value(type_name).toObject();
            SlideTypeConfig &cfg = file_config[type];
            QColor start(cobj.value(QStringLiteral("start")).toString());
            QColor end(cobj.value(QStringLiteral("end")).toString());
            if (start.isValid())
                cfg.color_start = start;
            if (end.isValid())
                cfg.color_end = end;
        }

        // Parse per-type settings
        QJsonObject types_obj = config_obj.value(QStringLiteral("types")).toObject();
        for (auto it = types_obj.constBegin(); it != types_obj.constEnd(); ++it) {
            BannerSlideType type = typeFromString(it.key());
            if (static_cast<int>(type) < 0) {
                qWarning("InfoBannerWidget: unknown type \"%s\" in config.types of %s",
                         qUtf8Printable(it.key()), qUtf8Printable(resource_path));
                continue;
            }
            QJsonObject tobj = it.value().toObject();
            SlideTypeConfig &cfg = file_config[type];
            if (tobj.contains(QStringLiteral("randomized")))
                cfg.randomized = tobj.value(QStringLiteral("randomized")).toBool();
            if (tobj.contains(QStringLiteral("maxdisplay")))
                cfg.maxdisplay = tobj.value(QStringLiteral("maxdisplay")).toInt();
            if (tobj.contains(QStringLiteral("only")))
                cfg.only = tobj.value(QStringLiteral("only")).toBool();
            if (is_custom && tobj.contains(QStringLiteral("hidden")))
                cfg.hidden = tobj.value(QStringLiteral("hidden")).toBool();
        }
    }

    // Parse slides
    QJsonArray slides_array = root.value(QStringLiteral("slides")).toArray();
    for (const QJsonValue &val : slides_array) {
        QJsonObject obj = val.toObject();
        QString type_str = obj.value(QStringLiteral("type")).toString();

        BannerSlideType type = typeFromString(type_str);
        if (static_cast<int>(type) < 0) {
            qWarning("InfoBannerWidget: unknown slide type \"%s\" in %s, skipping",
                     qUtf8Printable(type_str),
                     qUtf8Printable(resource_path));
            continue;
        }

        // Sponsorship slides in custom files are not allowed
        if (is_custom && type == BannerSponsorship) {
            qWarning("InfoBannerWidget: sponsorship slides not allowed in custom file %s, skipping",
                     qUtf8Printable(resource_path));
            continue;
        }

        // Validate required fields before translation (check raw JSON values)
        QString raw_title = obj.value(QStringLiteral("title")).toString();
        QString raw_description = obj.value(QStringLiteral("description")).toString();
        QString raw_url = obj.value(QStringLiteral("url")).toString();
        if (raw_title.isEmpty() || raw_description.isEmpty() || raw_url.isEmpty()) {
            qWarning("InfoBannerWidget: slide missing required field (title, description, or url) in %s, skipping",
                     qUtf8Printable(resource_path));
            continue;
        }

        BannerSlide slide;
        slide.type = type;
        slide.tag = resolveI18nField(obj, QStringLiteral("tag"), is_custom);
        slide.title = resolveI18nField(obj, QStringLiteral("title"), is_custom);
        slide.description = resolveI18nField(obj, QStringLiteral("description"), is_custom);
        slide.description_sub = resolveI18nField(obj, QStringLiteral("description_sub"), is_custom);
        slide.body_text = resolveI18nField(obj, QStringLiteral("body_text"), is_custom);
        slide.button_label = resolveI18nField(obj, QStringLiteral("button_label"), is_custom);
        slide.url = resolveI18nField(obj, QStringLiteral("url"), is_custom);
        slide.image = obj.value(QStringLiteral("image")).toString();
        QString date_from_str = obj.value(QStringLiteral("date_from")).toString();
        if (!date_from_str.isEmpty())
            slide.date_from = QDate::fromString(date_from_str, Qt::ISODate);
        QString date_until_str = obj.value(QStringLiteral("date_until")).toString();
        if (!date_until_str.isEmpty())
            slide.date_until = QDate::fromString(date_until_str, Qt::ISODate);
        file_slides[type].append(slide);
    }
}

void InfoBannerWidget::setSlideTypeVisible(BannerSlideType type, bool visible)
{
    slide_type_visible_[type] = visible;
    applySlideFilter();
}

void InfoBannerWidget::setAutoAdvanceInterval(unsigned seconds)
{
    int ms = static_cast<int>(seconds) * 1000;
    if (ms < 1000)
        ms = 1000;
    auto_advance_ms_ = ms;
    if (auto_advance_timer_->isActive())
        auto_advance_timer_->start(auto_advance_ms_);
}

void InfoBannerWidget::applySlideFilter()
{
    // Rebuild date-filtered per-type lists, then build the windowed sequence
    buildSlideSequence();
    if (current_slide_ >= slides_.size()) {
        current_slide_ = 0;
    }
    setVisible(recent.gui_welcome_page_sidebar_tips_visible && !slides_.isEmpty());
    updateAccessibility();
    update();
}

void InfoBannerWidget::buildSlideSequence()
{
    slides_.clear();
    QDate today = QDate::currentDate();

    // Ordered type iteration for deterministic slide ordering
    const QList<BannerSlideType> type_order = { BannerEvents, BannerSponsorship, BannerTips };

    for (BannerSlideType type : type_order) {
        if (!slide_type_visible_.value(type, true))
            continue;
        if (!slides_by_type_.contains(type))
            continue;

        const QList<BannerSlide> &type_slides = slides_by_type_[type];

        // Date-filter
        QList<BannerSlide> active;
        for (const BannerSlide &slide : type_slides) {
            if (slide.date_from.isValid() && today < slide.date_from)
                continue;
            if (slide.date_until.isValid() && today > slide.date_until)
                continue;
            active.append(slide);
        }

        if (active.isEmpty())
            continue;

        int maxdisplay = type_config_.value(type).maxdisplay;
        if (maxdisplay <= 0 || maxdisplay >= active.size()) {
            // Show all slides of this type
            slides_.append(active);
        } else {
            // Windowed: take maxdisplay slides starting at offset
            int offset = type_offsets_.value(type, 0) % active.size();
            for (int i = 0; i < maxdisplay; ++i) {
                slides_.append(active[(offset + i) % active.size()]);
            }
        }
    }
}

void InfoBannerWidget::advanceSlide()
{
    if (slides_.isEmpty()) return;

    int next = current_slide_ + 1;
    if (next >= static_cast<int>(slides_.size())) {
        // Cycle complete — advance per-type offsets and rebuild
        for (auto it = type_offsets_.begin(); it != type_offsets_.end(); ++it) {
            BannerSlideType type = it.key();
            int maxdisplay = type_config_.value(type).maxdisplay;
            if (maxdisplay > 0) {
                it.value() += maxdisplay;
            }
        }
        buildSlideSequence();
        current_slide_ = 0;
    } else {
        current_slide_ = next;
    }
    updateAccessibility();
    update();
}

void InfoBannerWidget::updateStyleSheets()
{
    update();
}

void InfoBannerWidget::updateAccessibility()
{
    if (slides_.isEmpty()) {
        setAccessibleName(tr("Tips and announcements"));
        setAccessibleDescription(QString());
    } else {
        const BannerSlide &slide = slides_[current_slide_];

        // Include carousel position so screen reader users know they can
        // navigate between slides (e.g. "Tip of the Day: Quick Filter (2 of 5)").
        setAccessibleName(tr("%1: %2 (%3 of %4)")
            .arg(slide.tag, slide.title)
            .arg(current_slide_ + 1)
            .arg(slides_.size()));

        // Build a spoken summary of the slide content in reading order:
        // highlight text, optional sub-line, body text, action button.
        QStringList parts;
        if (!slide.description.isEmpty())
            parts << slide.description;
        if (!slide.description_sub.isEmpty())
            parts << slide.description_sub;
        if (!slide.body_text.isEmpty())
            parts << slide.body_text;
        if (!slide.button_label.isEmpty())
            parts << tr("Action: %1").arg(slide.button_label);
        setAccessibleDescription(parts.join(QLatin1Char(' ')));
    }

    QAccessibleEvent event(this, QAccessible::NameChanged);
    QAccessible::updateAccessibility(&event);
}

void InfoBannerWidget::setCompactMode(bool compact)
{
    if (compact_mode_ == compact)
        return;
    compact_mode_ = compact;
    int h = compact_mode_ ? kCardHeightCompact : kCardHeight;
    setMinimumHeight(h);
    setMaximumHeight(h);
    updateGeometry();
    update();
}

bool InfoBannerWidget::isCompactMode() const
{
    return compact_mode_;
}

QSize InfoBannerWidget::sizeHint() const
{
    return QSize(kCardWidth, compact_mode_ ? kCardHeightCompact : kCardHeight);
}

void InfoBannerWidget::paintEvent(QPaintEvent * /* event */)
{
    if (slides_.isEmpty()) return;

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setRenderHint(QPainter::TextAntialiasing);

    const BannerSlide &slide = slides_[current_slide_];
    const QRectF r = rect();
    const int content_width = static_cast<int>(r.width()) - kContentLeftMargin - kContentRightMargin;

    QPair<QColor, QColor> colors = gradientForType(slide.type);

    // --- Card background gradient (145 degrees) ---
    double angle_rad = qDegreesToRadians(145.0);
    double cx = r.width() / 2.0;
    double cy = r.height() / 2.0;
    double dx = qCos(angle_rad - M_PI / 2.0) * r.width();
    double dy = qSin(angle_rad - M_PI / 2.0) * r.height();

    QLinearGradient gradient(
        QPointF(cx - dx / 2.0, cy - dy / 2.0),
        QPointF(cx + dx / 2.0, cy + dy / 2.0)
    );
    gradient.setColorAt(0, colors.first);
    gradient.setColorAt(1, colors.second);

    painter.setPen(Qt::NoPen);
    painter.setBrush(gradient);
    painter.drawRoundedRect(r, 8, 8);

    int y;
    if (!compact_mode_) {
        // --- Illustration area ---
        QRectF illus_rect(0, 0, r.width(), kIllustrationHeight);

        // Top-rounded, flat-bottom clip shape
        QPainterPath clip_path;
        clip_path.moveTo(8, 0);
        clip_path.arcTo(QRectF(0, 0, 16, 16), 90, 90);
        clip_path.lineTo(0, kIllustrationHeight);
        clip_path.lineTo(r.width(), kIllustrationHeight);
        clip_path.lineTo(r.width(), 8);
        clip_path.arcTo(QRectF(r.width() - 16, 0, 16, 16), 0, 90);
        clip_path.closeSubpath();

        bool has_image = false;
        if (!slide.image.isEmpty()) {
            QString image_path = QStringLiteral(":/json/banners/") + slide.image;
            QPixmap pixmap(image_path);
            if (!pixmap.isNull()) {
                has_image = true;
                painter.save();
                painter.setClipPath(clip_path);
                QPixmap scaled = pixmap.scaled(
                    static_cast<int>(illus_rect.width()) * devicePixelRatio(),
                    static_cast<int>(illus_rect.height()) * devicePixelRatio(),
                    Qt::KeepAspectRatioByExpanding,
                    Qt::SmoothTransformation);
                scaled.setDevicePixelRatio(devicePixelRatio());
                int offset_x = static_cast<int>((illus_rect.width() - scaled.width() / devicePixelRatio()) / 2.0);
                int offset_y = static_cast<int>((illus_rect.height() - scaled.height() / devicePixelRatio()) / 2.0);
                painter.drawPixmap(offset_x, offset_y, scaled);
                painter.restore();
            }
        }

        if (!has_image) {
            // Generic semi-transparent overlay as fallback
            painter.setBrush(QColor(255, 255, 255, 15));
            painter.setPen(Qt::NoPen);
            painter.drawPath(clip_path);

            QFont illus_font = font();
            illus_font.setPixelSize(11);
            illus_font.setCapitalization(QFont::AllUppercase);
            illus_font.setLetterSpacing(QFont::AbsoluteSpacing, 2.0);
            painter.setFont(illus_font);
            painter.setPen(QColor(255, 255, 255, 80));
            painter.drawText(illus_rect, Qt::AlignCenter, slide.tag.toUpper());
        }

        y = kIllustrationHeight + 12;
    } else {
        y = 12;
    }

    // Tag / subheader pill
    QFont tag_font = font();
    tag_font.setPixelSize(9);
    tag_font.setBold(true);
    tag_font.setCapitalization(QFont::AllUppercase);
    tag_font.setLetterSpacing(QFont::AbsoluteSpacing, 0.5);
    painter.setFont(tag_font);

    QString tag_text = slide.tag.toUpper();
    QFontMetrics tag_fm(tag_font);
    int pill_h = tag_fm.height() + 6;
    int pill_w = tag_fm.horizontalAdvance(tag_text) + 14;
    QRectF pill_rect(kContentLeftMargin, y, pill_w, pill_h);

    painter.setBrush(QColor(0, 0, 0, 60));
    painter.setPen(Qt::NoPen);
    painter.drawRoundedRect(pill_rect, 3, 3);

    painter.setPen(QColor(255, 255, 255, 200));
    painter.drawText(pill_rect, Qt::AlignCenter, tag_text);

    y += pill_h + 8;

    // --- Title ---
    QFont title_font = font();
    title_font.setPixelSize(15);
    title_font.setBold(true);
    painter.setFont(title_font);
    painter.setPen(Qt::white);

    QRectF title_rect(kContentLeftMargin, y, content_width, 20);
    painter.drawText(title_rect, Qt::AlignLeft | Qt::AlignVCenter, slide.title);

    y += 24;

    // --- Description highlight box ---
    QFont desc_font = font();
    desc_font.setPixelSize(11);
    painter.setFont(desc_font);
    QFontMetrics desc_fm(desc_font);

    int box_padding = 10;
    int box_inner_width = content_width - box_padding * 2;
    int line1_h = desc_fm.height();
    int line2_h = slide.description_sub.isEmpty() ? 0 : desc_fm.height();
    int box_h = box_padding * 2 + line1_h + (line2_h > 0 ? line2_h + 3 : 0);

    QRectF desc_box(kContentLeftMargin, y, content_width, box_h);
    painter.setBrush(QColor(255, 255, 255, 25));
    painter.setPen(Qt::NoPen);
    painter.drawRoundedRect(desc_box, 6, 6);

    painter.setPen(QColor(255, 255, 255, 230));
    int text_y = y + box_padding;
    painter.drawText(QRectF(kContentLeftMargin + box_padding, text_y, box_inner_width, line1_h),
                     Qt::AlignLeft | Qt::AlignVCenter,
                     desc_fm.elidedText(slide.description, Qt::ElideRight, box_inner_width));
    if (line2_h > 0) {
        painter.setPen(QColor(255, 255, 255, 170));
        text_y += line1_h + 3;
        painter.drawText(QRectF(kContentLeftMargin + box_padding, text_y, box_inner_width, line2_h),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         desc_fm.elidedText(slide.description_sub, Qt::ElideRight, box_inner_width));
    }

    y += box_h + 8;

    // --- Body text (skip in compact mode) ---
    if (!compact_mode_ && !slide.body_text.isEmpty()) {
        QFont body_font = font();
        body_font.setPixelSize(10);
        painter.setFont(body_font);
        painter.setPen(QColor(255, 255, 255, 160));

        QRectF body_rect(kContentLeftMargin, y, content_width, 48);
        painter.drawText(body_rect, Qt::AlignLeft | Qt::TextWordWrap, slide.body_text);

        y += 52;
    }

    // --- Action button ---
    if (!slide.button_label.isEmpty()) {
        QFont btn_font = font();
        btn_font.setPixelSize(11);
        btn_font.setBold(true);
        painter.setFont(btn_font);
        QFontMetrics btn_fm(btn_font);

        int btn_h = btn_fm.height() + 12;
        int btn_w = btn_fm.horizontalAdvance(slide.button_label) + 24;
        QRectF btn_rect(kContentLeftMargin, y, btn_w, btn_h);

        painter.setBrush(Qt::NoBrush);
        painter.setPen(QPen(QColor(255, 255, 255, 180), 1.0));
        painter.drawRoundedRect(btn_rect, 4, 4);

        painter.setPen(QColor(255, 255, 255, 220));
        painter.drawText(btn_rect, Qt::AlignCenter, slide.button_label);
    }

    // --- Navigation dots ---
    int num_slides = static_cast<int>(slides_.size());
    int total_dots_width = num_slides * (kDotRadius * 2) + (num_slides - 1) * (kDotSpacing - kDotRadius * 2);
    int dots_x = (static_cast<int>(r.width()) - total_dots_width) / 2;
    int dots_y = static_cast<int>(r.height()) - kDotBottomMargin;

    for (int i = 0; i < num_slides; ++i) {
        QRectF dot(dots_x + i * kDotSpacing, dots_y - kDotRadius, kDotRadius * 2, kDotRadius * 2);
        if (i == current_slide_) {
            painter.setBrush(QColor(255, 255, 255, 230));
        } else {
            painter.setBrush(QColor(255, 255, 255, 100));
        }
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(dot);
    }
}

QRect InfoBannerWidget::buttonRect() const
{
    if (slides_.isEmpty() || current_slide_ < 0) return QRect();

    const BannerSlide &slide = slides_[current_slide_];
    if (slide.button_label.isEmpty()) return QRect();

    // Approximate button position by replaying the layout logic
    QFont tag_font = font();
    tag_font.setPixelSize(9);
    tag_font.setBold(true);
    QFontMetrics tag_fm(tag_font);
    int pill_h = tag_fm.height() + 6;

    int y_start = compact_mode_ ? 12 : (kIllustrationHeight + 12);
    int y = y_start + pill_h + 8 + 24; // after tag + title

    QFont desc_font = font();
    desc_font.setPixelSize(11);
    QFontMetrics desc_fm(desc_font);
    int line1_h = desc_fm.height();
    int line2_h = slide.description_sub.isEmpty() ? 0 : desc_fm.height();
    int box_h = 10 * 2 + line1_h + (line2_h > 0 ? line2_h + 3 : 0);
    y += box_h + 8;

    if (!compact_mode_ && !slide.body_text.isEmpty()) {
        y += 52;
    }

    QFont btn_font = font();
    btn_font.setPixelSize(11);
    btn_font.setBold(true);
    QFontMetrics btn_fm(btn_font);
    int btn_h = btn_fm.height() + 12;
    int btn_w = btn_fm.horizontalAdvance(slide.button_label) + 24;

    return QRect(kContentLeftMargin, y, btn_w, btn_h);
}

QRect InfoBannerWidget::dotRect(int index) const
{
    const QRectF r = rect();
    int num_slides = static_cast<int>(slides_.size());
    int total_dots_width = num_slides * (kDotRadius * 2) + (num_slides - 1) * (kDotSpacing - kDotRadius * 2);
    int dots_x = (static_cast<int>(r.width()) - total_dots_width) / 2;
    int dots_y = static_cast<int>(r.height()) - kDotBottomMargin;

    int hit_margin = 6;
    return QRect(
        dots_x + index * kDotSpacing - hit_margin,
        dots_y - kDotRadius - hit_margin,
        kDotRadius * 2 + hit_margin * 2,
        kDotRadius * 2 + hit_margin * 2
    );
}

int InfoBannerWidget::dotHitTest(const QPoint &pos) const
{
    int num_slides = static_cast<int>(slides_.size());
    for (int i = 0; i < num_slides; ++i) {
        if (dotRect(i).contains(pos)) {
            return i;
        }
    }
    return -1;
}

void InfoBannerWidget::mousePressEvent(QMouseEvent *event)
{
    if (event->button() != Qt::LeftButton) {
        QFrame::mousePressEvent(event);
        return;
    }

    // Check navigation dots first
    int dot_index = dotHitTest(event->pos());
    if (dot_index >= 0 && dot_index != current_slide_) {
        current_slide_ = dot_index;
        auto_advance_timer_->start(auto_advance_ms_);
        updateAccessibility();
        update();
        return;
    }

    // Check button
    QRect btn = buttonRect();
    if (btn.isValid() && btn.contains(event->pos())) {
        if (current_slide_ >= 0 && current_slide_ < static_cast<int>(slides_.size())) {
            const QString &url = slides_[current_slide_].url;
            if (!url.isEmpty()) {
                QDesktopServices::openUrl(QUrl(url));
            }
        }
        return;
    }

    // Click anywhere else also opens the URL
    if (current_slide_ >= 0 && current_slide_ < static_cast<int>(slides_.size())) {
        const QString &url = slides_[current_slide_].url;
        if (!url.isEmpty()) {
            QDesktopServices::openUrl(QUrl(url));
        }
    }
}

void InfoBannerWidget::mouseMoveEvent(QMouseEvent *event)
{
    QRect btn = buttonRect();
    if ((btn.isValid() && btn.contains(event->pos())) || dotHitTest(event->pos()) >= 0) {
        setCursor(Qt::PointingHandCursor);
    } else {
        setCursor(Qt::PointingHandCursor);
    }
    QFrame::mouseMoveEvent(event);
}
