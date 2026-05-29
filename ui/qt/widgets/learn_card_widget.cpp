/* learn_card_widget.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/learn_card_widget.h>
#include <ui_learn_card_widget.h>

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/theme_styler.h>
#include <ui/qt/utils/workspace_state.h>

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
#include <QEvent>

#include "ui/urls.h"

LearnCardWidget::LearnCardWidget(QWidget *parent) :
    QFrame(parent),
    ui_(new Ui::LearnCardWidget),
    links_collapsed_(false)
{
    ui_->setupUi(this);

    loadLinksFromRessource();
    setupLinks();
    setupActionButtons();
    setStyleSheet(ThemeManager::styleSheet(QStringLiteral("widgets/learn-card")));

    // Reload the stylesheet whenever the theme (or its light/dark
    // selection) changes.  QEvent::ApplicationPaletteChange alone isn't
    // reliable — a mode flip on a theme with no palette overrides may
    // not produce a palette delta large enough for Qt to propagate.
    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, [this]() {
        setStyleSheet(ThemeManager::styleSheet(QStringLiteral("widgets/learn-card")));
    });

    connect(ui_->learnHeader, &ClickableLabel::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(WS_DOCS_URL));
    });
}

LearnCardWidget::~LearnCardWidget()
{
    delete ui_;
}

void LearnCardWidget::loadLinksFromRessource()
{
    const QString resource_path = QStringLiteral(":/json/learn_card.json");
    QFile file(resource_path);
    if (!file.exists())
        return;
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning("LearnCardWidget: cannot open %s", qUtf8Printable(resource_path));
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

void LearnCardWidget::setupLinks()
{
    // Clear existing layout and link labels
    if (auto *old_layout = ui_->learnLinkContainer->layout()) {
        qDeleteAll(ui_->learnLinkContainer->findChildren<QLabel*>(
            QStringLiteral("learnLink"), Qt::FindDirectChildrenOnly));
        delete old_layout;
    }

    // Use horizontal layout in collapsed mode, vertical in expanded
    QBoxLayout *link_layout;
    if (links_collapsed_) {
        link_layout = new QHBoxLayout(ui_->learnLinkContainer);
        link_layout->setContentsMargins(16, 4, 16, 4);
        link_layout->setSpacing(4);
    } else {
        link_layout = new QVBoxLayout(ui_->learnLinkContainer);
        link_layout->setContentsMargins(16, 4, 16, 4);
        link_layout->setSpacing(0);
    }

    for (const LinkType &link : links_) {
        if (link.validity != LearnCardWidget::AllVersions) {
            if (link.validity == LearnCardWidget::ReleaseOnly && WorkspaceState::isDevelopmentBuild())
                continue;
            if (link.validity == LearnCardWidget::DevOnly && !WorkspaceState::isDevelopmentBuild())
                continue;
        }

        auto *link_label = new QLabel(ui_->learnLinkContainer);
        QString labelText = links_collapsed_ ? link.short_label : link.label;
        int contentMargin = links_collapsed_ ? 4 : 10;

        link_label->setObjectName(QStringLiteral("learnLink"));
        link_label->setTextFormat(Qt::RichText);
        link_label->setTextInteractionFlags(Qt::TextBrowserInteraction);
        link_label->setOpenExternalLinks(true);
        link_label->setText(QStringLiteral("<a href=\"%1\" title=\"%2\">%3</a>")
                           .arg(link.url, link.tooltip, labelText));
        /* Accessible name needs to be the full label for screen readers */
        link_label->setAccessibleName(link.label);
        link_label->setAccessibleDescription(link.tooltip);
        link_label->setContentsMargins(contentMargin, 4, contentMargin, 4);
        link_layout->addWidget(link_label);
    }

    if (links_collapsed_)
        link_layout->addStretch(1);
}

void LearnCardWidget::setupActionButtons()
{
    // Clear any existing buttons
    qDeleteAll(ui_->learnButtonContainer->findChildren<QPushButton*>(
        QStringLiteral("learnButton"), Qt::FindDirectChildrenOnly));

    auto *button_layout = ui_->learnButtonLayout;

    auto defColor = QApplication::palette().color(QPalette::Button);

    for (const ButtonType &button : buttons_) {
        if (button.validity != LearnCardWidget::AllVersions) {
            if (button.validity == LearnCardWidget::ReleaseOnly && WorkspaceState::isDevelopmentBuild())
                continue;
            if (button.validity == LearnCardWidget::DevOnly && !WorkspaceState::isDevelopmentBuild())
                continue;
        }

        QColor button_color = button.color.isValid() ? button.color : defColor;

        auto *action_button = new QPushButton(button.label, ui_->learnButtonContainer);
        action_button->setObjectName(QStringLiteral("learnButton"));
        action_button->setToolTip(button.tooltip);
        action_button->setAccessibleDescription(button.tooltip);
        action_button->setCursor(Qt::PointingHandCursor);
        action_button->setStyleSheet(ThemeStyler::buttonStyleSheet(QStringLiteral("learnButton"), button_color));
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

    // Collapsed: shrink to content. Expanded: fill available space.
    if (links_collapsed_) {
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    } else {
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::MinimumExpanding);
    }

    setupLinks();
}

bool LearnCardWidget::isLinksCollapsed() const
{
    return links_collapsed_;
}

bool LearnCardWidget::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        setStyleSheet(ThemeManager::styleSheet(QStringLiteral("widgets/learn-card")));
        break;
    case QEvent::LanguageChange:
        ui_->retranslateUi(this);
        break;
    default:
        break;
    }
    return QFrame::event(event);
}
