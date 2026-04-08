/* learn_card_widget.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/prefs.h>

#include <ui/qt/widgets/learn_card_widget.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/workspace_state.h>
#include <ui/qt/main_application.h>

#include <QApplication>
#include <QLabel>
#include <QPushButton>
#include <QDesktopServices>
#include <QUrl>
#include <QHBoxLayout>
#include <QFrame>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>

#include "ui/urls.h"

LearnCardWidget::LearnCardWidget(QWidget *parent) :
    QFrame(parent)
    , main_layout_(nullptr)
    , link_container_(nullptr)
    , links_collapsed_(false)
{
    connect(mainApp, &MainApplication::appInitialized, this, &LearnCardWidget::setupLayout);

    setupLayout();
}

void LearnCardWidget::loadLinksFromRessource()
{
    const QString resource_path = QStringLiteral(":/json/learn_card.json");
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

    QJsonObject root = doc.object();
    if (root.value(QStringLiteral("schema_version")).toInt() < 1) {
        qWarning("LearnCardWidget: unsupported schema_version in %s",
                 qUtf8Printable(resource_path));
        return;
    }

    links_.clear();
    QJsonArray links_array = root.value(QStringLiteral("links")).toArray();
    for (const QJsonValue &link_value : links_array) {
        QJsonObject link_obj = link_value.toObject();
        LinkType link;
        link.url = link_obj.value(QStringLiteral("url")).toString();
        link.label = link_obj.value(QStringLiteral("label")).toString();
        link.short_label = link_obj.value(QStringLiteral("short_label")).toString();
        link.tooltip = link_obj.value(QStringLiteral("tooltip")).toString();
        link.validity = LearnCardWidget::AllVersions;
        if (link_obj.contains(QStringLiteral("scheme"))) {
            QString scheme_str = link_obj.value(QStringLiteral("scheme")).toString();
            if (scheme_str.toLower() == QStringLiteral("stable"))
                link.validity = LearnCardWidget::ReleaseOnly;
            else if (scheme_str.toLower() == QStringLiteral("dev"))
                link.validity = LearnCardWidget::DevOnly;
        }
        links_.append(link);
    }

    buttons_.clear();
    QJsonArray buttons_array = root.value(QStringLiteral("buttons")).toArray();
    for (const QJsonValue &button_value : buttons_array) {
        QJsonObject button_obj = button_value.toObject();
        ButtonType button;
        button.url = button_obj.value(QStringLiteral("url")).toString();
        button.label = button_obj.value(QStringLiteral("label")).toString();
        button.tooltip = button_obj.value(QStringLiteral("tooltip")).toString();
        button.color = button_obj.value(QStringLiteral("color")).toString();
        button.hover_color = button_obj.value(QStringLiteral("hover_color")).toString();
        button.validity = LearnCardWidget::AllVersions;
        if (button_obj.contains(QStringLiteral("scheme"))) {
            QString scheme_str = button_obj.value(QStringLiteral("scheme")).toString();
            if (scheme_str.toLower() == QStringLiteral("stable"))
                button.validity = LearnCardWidget::ReleaseOnly;
            else if (scheme_str.toLower() == QStringLiteral("dev"))
                button.validity = LearnCardWidget::DevOnly;
        }
        buttons_.append(button);
    }
}

void LearnCardWidget::setupLayout()
{
    if (main_layout_) {
        delete main_layout_;
        qDeleteAll(findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly));

        main_layout_ = nullptr;
    }

    main_layout_ = new QVBoxLayout(this);
    setLayout(main_layout_);
    main_layout_->setContentsMargins(0, 0, 0, 0);
    main_layout_->setSpacing(0);

    setupHeader();
    setupLinks();
    setupActionButtons();
}

void LearnCardWidget::setupHeader()
{
    ClickableLabel * header_label_ = new ClickableLabel(this);
    header_label_->setObjectName("learnHeader");
    header_label_->setText(tr("<h2>Learn</h2>"));
    header_label_->setAccessibleName(tr("Learn"));
    header_label_->setAccessibleDescription(tr("Opens the Wireshark documentation website"));
    header_label_->setContentsMargins(16, 12, 16, 12);
    header_label_->setCursor(Qt::PointingHandCursor);
    connect(header_label_, &ClickableLabel::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(WS_DOCS_URL));
    });
    main_layout_->addWidget(header_label_);

    QFrame * header_separator_ = new QFrame(this);
    header_separator_->setObjectName("learnHeaderSeparator");
    header_separator_->setFrameShape(QFrame::HLine);
    header_separator_->setFrameShadow(QFrame::Plain);
    header_separator_->setFixedHeight(1);
    main_layout_->addWidget(header_separator_);
}

void LearnCardWidget::setupLinks()
{
    QWidget * link_container_ = findChild<QWidget*>("learnLinkContainer");
    if (!link_container_) {
        loadLinksFromRessource();

        link_container_ = new QWidget(this);
        link_container_->setObjectName("learnLinkContainer");

        auto *link_layout = new QVBoxLayout(link_container_);
        link_layout->setObjectName("learnLinkLayout");
        link_layout->setContentsMargins(16, 4, 16, 4);
        link_layout->setSpacing(0);

        main_layout_->addWidget(link_container_);
        main_layout_->addStretch(1);
    } else {
        qDeleteAll(link_container_->findChildren<QLabel*>(QString("learnLink"), Qt::FindDirectChildrenOnly));
    }
    auto *link_layout = qobject_cast<QVBoxLayout*>(link_container_->layout());

    foreach (const LinkType &link, links_) {
        if (link.validity != LearnCardWidget::AllVersions)
        {
            if (link.validity == LearnCardWidget::ReleaseOnly && WorkspaceState::isDevelopmentBuild())
                continue;
            if (link.validity == LearnCardWidget::DevOnly && !WorkspaceState::isDevelopmentBuild())
                continue;
        }
        auto *link_label = new QLabel(this);
        QString labelText = links_collapsed_ ? link.short_label : link.label;
        int contentMargin = links_collapsed_ ? 4 : 10;

        link_label->setObjectName("learnLink");
        link_label->setTextFormat(Qt::RichText);
        link_label->setTextInteractionFlags(Qt::TextBrowserInteraction);
        link_label->setOpenExternalLinks(true);
        link_label->setText(QString("<a href=\"%1\" title=\"%2\">%3</a>")
                           .arg(link.url, link.tooltip, labelText));
        /** Accessible name needs to be the full label for screen readers */
        link_label->setAccessibleName(link.label);
        link_label->setAccessibleDescription(link.tooltip);
        link_label->setContentsMargins(contentMargin, 4, contentMargin, 4);
        link_layout->addWidget(link_label);
    }
}

void LearnCardWidget::setupActionButtons()
{
    QWidget * button_container = findChild<QWidget*>("learnButtonContainer");
    if (!link_container_) {
        loadLinksFromRessource();

        button_container = new QWidget(this);
        button_container->setObjectName("learnButtonContainer");

        auto *button_layout = new QHBoxLayout(button_container);
        button_layout->setObjectName("learnButtonLayout");
        button_layout->setContentsMargins(16, 12, 16, 12);
        button_layout->setSpacing(8);

        main_layout_->addWidget(button_container);
    } else {
        qDeleteAll(button_container->findChildren<QPushButton*>(QString("learnButton"), Qt::FindDirectChildrenOnly));
    }
    auto *button_layout = qobject_cast<QHBoxLayout*>(button_container->layout());

    auto defColor = QColor("#5865F2");
    auto defHoverColor = QColor("#4752C4");

    foreach (const ButtonType &button, buttons_) {
        if (button.validity != LearnCardWidget::AllVersions)
        {
            if (button.validity == LearnCardWidget::ReleaseOnly && WorkspaceState::isDevelopmentBuild())
                continue;
            if (button.validity == LearnCardWidget::DevOnly && !WorkspaceState::isDevelopmentBuild())
                continue;
        }

        QColor button_color = button.color.isValid() ? button.color : defColor;
        QColor button_hover_color = button.hover_color.isValid() ? button.hover_color : defHoverColor;
        QString styleSheet =  QStringLiteral(
            "QPushButton {"
            "  background-color: %1;"
            "  color: white;"
            "  border: none;"
            "  border-radius: 6px;"
            "  padding: 10px 12px;"
            "  font-weight: 500;"
            "}"
            "QPushButton:hover {"
            "  background-color: %2;"
            "}"
            ).arg(button_color.name(), button_hover_color.name());

        QPushButton * action_button = new QPushButton(button.label, this);
        action_button->setObjectName("learnButton");
        action_button->setToolTip(button.tooltip);
        action_button->setAccessibleDescription(button.tooltip);
        action_button->setCursor(Qt::PointingHandCursor);
        action_button->setStyleSheet(styleSheet);
        connect(action_button, &QPushButton::clicked, this, [url = button.url]() {
            QDesktopServices::openUrl(QUrl(url));
        });
        button_layout->addWidget(action_button);
    }
}

void LearnCardWidget::setLinksCollapsed(bool collapsed)
{
    if (links_collapsed_ == collapsed)
        return;
    links_collapsed_ = collapsed;

    setupLinks();
}

bool LearnCardWidget::isLinksCollapsed() const
{
    return links_collapsed_;
}

void LearnCardWidget::updateStyleSheets(const QColor &header_text_color, const QColor &header_hover_color)
{
    QPalette palette = QApplication::palette();
    QColor base_color = palette.color(QPalette::Base);
    QColor border_color = ColorUtils::themeIsDark()
        ? base_color.lighter(200)
        : base_color.darker(120);
    QColor card_bg = ColorUtils::themeIsDark()
        ? base_color.lighter(120)
        : base_color.darker(105);
    QColor hover_bg = ColorUtils::hoverBackground();
    QString link_style = ColorUtils::themeLinkStyle();

    QString styleSheet;

    styleSheet.append(QStringLiteral(
            "LearnCardWidget {"
            "  background-color: %1;"
            "  border: 1px solid %2;"
            "  border-radius: 6px;"
            "}"
            )
            .arg(card_bg.name(), border_color.name()));

    styleSheet.append(QStringLiteral(
            "QLabel#learnHeader {"
            "  color: %1;"
            "  padding: 10px 12px;"
            "}"
            "QLabel#learnHeader:hover {"
            "  color: %2;"
            "}"
            )
            .arg(header_text_color.name(), header_hover_color.name()));

    styleSheet.append(QStringLiteral(
            "QFrame#learnHeaderSeparator {"
            "  color: %1;"
            "}"
            )
            .arg(border_color.name()));

    styleSheet.append(QStringLiteral(
            "QLabel#learnLink {"
            "  border-radius: 4px;"
            "}"
            "QLabel#learnLink:hover {"
            "  background-color: %1;"
            "}"
            "%2"
            )
            .arg(hover_bg.name(QColor::HexArgb), link_style));

    // Update button: brand purple #5865F2
    styleSheet.append(QStringLiteral(
            "QPushButton#learnUpdateButton {"
            "  background-color: #5865F2;"
            "  color: white;"
            "  border: none;"
            "  border-radius: 6px;"
            "  padding: 10px 12px;"
            "  font-weight: 500;"
            "}"
            "QPushButton#learnUpdateButton:hover {"
            "  background-color: #4752C4;"
            "}"
            ));


    // Button container top border (separator)
    styleSheet.append(QStringLiteral(
                "QWidget#learnButtonContainer {"
                "  border-top: 1px solid %1;"
                "}"
                )
                .arg(border_color.name()));

    setStyleSheet(styleSheet);
}

