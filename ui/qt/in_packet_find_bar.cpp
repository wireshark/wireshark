/* in_packet_find_bar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "in_packet_find_bar.h"
#include <ui_in_packet_find_bar.h>
#include "in_packet_search.h"
#include "proto_tree.h"

#include <QKeyEvent>
#include <QPalette>
#include <QPushButton>
#include <QRegularExpression>
#include "widgets/in_packet_find_edit.h"
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/font_manager.h>

int InPacketFindBar::open_instances_ = 0;

InPacketFindBar::~InPacketFindBar()
{
    if (is_open_) {
        --open_instances_;
        is_open_ = false;
    }
    delete ui_;
}

InPacketFindBar::InPacketFindBar(ProtoTree *tree, QWidget *parent) :
    QWidget(parent),
    proto_tree_(tree),
    search_(new InPacketSearch(tree, this)),
    is_open_(false),
    natural_height_(0)
{
    ui_ = new Ui::InPacketFindBar();
    ui_->setupUi(this);
    updateStyleSheet();

    search_->installDelegate();
    connect(search_, &InPacketSearch::matchesChanged, this, &InPacketFindBar::matchesChanged);
    connect(search_, &InPacketSearch::matchesChanged, this, &InPacketFindBar::updateCounterLabel);

    ui_->search_edit_->setPlaceholderText(QString());
    ui_->search_edit_->updateSearchSyntax(true, false);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif

    QPalette pal = palette();
    pal.setColor(QPalette::Window, pal.color(QPalette::Base));
    setPalette(pal);
    setAutoFillBackground(true);

    animation_ = new QPropertyAnimation(this, "barHeight", this);
    animation_->setDuration(120);
    animation_->setEasingCurve(QEasingCurve::OutCubic);

    debounce_timer_ = new QTimer(this);
    debounce_timer_->setSingleShot(true);
    debounce_timer_->setInterval(50);
    connect(debounce_timer_, &QTimer::timeout, this, &InPacketFindBar::performSearch);

    connect(ui_->search_edit_, &QLineEdit::textChanged, this, &InPacketFindBar::onTextChanged);
    connect(ui_->search_type_combo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &InPacketFindBar::onToggleChanged);
    connect(ui_->case_checkbox_, &QCheckBox::toggled, this, &InPacketFindBar::onToggleChanged);

    connect(ui_->find_button_, &QPushButton::clicked, this, &InPacketFindBar::executeFind);
    connect(ui_->cancel_button_, &QPushButton::clicked, this, &InPacketFindBar::closeBar);

    ui_->find_button_->setAutoDefault(false);
    ui_->cancel_button_->setAutoDefault(false);

    ui_->search_edit_->installEventFilter(this);
    ui_->find_button_->installEventFilter(this);
    ui_->case_checkbox_->installEventFilter(this);

    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, [this]() {
        updateStyleSheet();
        recalculateNaturalHeight();
    });

    connect(FontManager::instance(), &FontManager::zoomChanged,
            this, [this]() { recalculateNaturalHeight(); });

    updateFindButtonState();
    setVisible(false);
    setMaximumHeight(0);
}

int InPacketFindBar::barHeight() const
{
    return maximumHeight();
}

void InPacketFindBar::setBarHeight(int h)
{
    setMaximumHeight(h);
}

void InPacketFindBar::showAnimated()
{
    if (isVisible() && maximumHeight() > 0) {
        ui_->search_edit_->setFocus();
        ui_->search_edit_->selectAll();
        return;
    }

    if (natural_height_ == 0) {
        setMaximumHeight(QWIDGETSIZE_MAX);
        adjustSize();
        natural_height_ = sizeHint().height();
        setMaximumHeight(0);
    }

    setVisible(true);
    search_->setHighlightEnabled(true);
    if (ui_->search_edit_->text().isEmpty()) {
        ui_->search_edit_->updateSearchSyntax(true, false);
    } else {
        performSearch();
    }
    animation_->stop();
    animation_->setStartValue(0);
    animation_->setEndValue(natural_height_);
    animation_->start();

    if (!is_open_) {
        ++open_instances_;
        is_open_ = true;
        emit openChanged(true);
    }

    updateFindButtonState();
    ui_->search_edit_->setFocus();
    ui_->search_edit_->selectAll();
}

void InPacketFindBar::hideAnimated()
{
    animation_->stop();
    animation_->setStartValue(maximumHeight());
    animation_->setEndValue(0);

    if (is_open_) {
        --open_instances_;
        is_open_ = false;
        emit openChanged(false);
    }

    QMetaObject::Connection *conn = new QMetaObject::Connection();
    *conn = connect(animation_, &QPropertyAnimation::finished, this, [this, conn]() {
        setVisible(false);
        search_->setHighlightEnabled(false);
        search_->clearMatches();
        ui_->counter_label_->clear();
        ui_->search_edit_->clearSearchSyntax();
        emit matchesChanged();
        disconnect(*conn);
        delete conn;
    });
    animation_->start();
}

void InPacketFindBar::focusSearchField()
{
    if (isVisible()) {
        ui_->search_edit_->setFocus();
        ui_->search_edit_->selectAll();
    }
}

bool InPacketFindBar::isMatch(const QModelIndex &index) const
{
    return search_->isMatch(index);
}

bool InPacketFindBar::isCurrentMatch(const QModelIndex &index) const
{
    return search_->isCurrentMatch(index);
}

bool InPacketFindBar::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_Escape && obj == ui_->search_edit_) {
            closeBar();
            return true;
        }
        if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
            if (obj == ui_->search_edit_ || obj == ui_->find_button_
                    || obj == ui_->case_checkbox_) {
                advanceSearch(ke->modifiers() & Qt::ShiftModifier);
                return true;
            }
        }
    }
    return QWidget::eventFilter(obj, event);
}

void InPacketFindBar::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
        advanceSearch(event->modifiers() & Qt::ShiftModifier);
        event->accept();
        return;
    }
    if (event->key() == Qt::Key_Escape) {
        closeBar();
        event->accept();
        return;
    }
    QWidget::keyPressEvent(event);
}

void InPacketFindBar::onTextChanged(const QString &)
{
    debounce_timer_->start();
    updateFindButtonState();
}

void InPacketFindBar::performSearch()
{
    const QString pattern = ui_->search_edit_->text();
    last_search_pattern_ = pattern;

    if (pattern.isEmpty()) {
        search_->clearMatches();
        ui_->search_edit_->updateSearchSyntax(true, false);
        updateCounterLabel();
        updateFindButtonState();
        return;
    }

    const bool case_sensitive = ui_->case_checkbox_->isChecked();
    const bool use_regex = (ui_->search_type_combo_->currentIndex() == 1);
    search_->search(pattern, case_sensitive, use_regex);

    ui_->search_edit_->updateSearchSyntax(false, search_->isRegexInvalid());
    updateCounterLabel();
    updateFindButtonState();
}

void InPacketFindBar::onToggleChanged()
{
    if (!ui_->search_edit_->text().isEmpty()) {
        performSearch();
    } else {
        updateFindButtonState();
    }
}

void InPacketFindBar::updateCounterLabel()
{
    if (ui_->search_edit_->text().isEmpty()) {
        ui_->counter_label_->clear();
        return;
    }
    if (search_->matchCount() == 0) {
        if (search_->isRegexInvalid()) {
            ui_->counter_label_->setText(tr("invalid pattern"));
        } else {
            ui_->counter_label_->setText(tr("no matches"));
        }
        return;
    }
    ui_->counter_label_->setText(tr("%1 of %2")
            .arg(search_->currentMatchIndex() + 1)
            .arg(search_->matchCount()));
}

void InPacketFindBar::executeFind()
{
    advanceSearch(false);
}

void InPacketFindBar::advanceSearch(bool backward)
{
    const QString pattern = ui_->search_edit_->text();
    if (pattern != last_search_pattern_ || debounce_timer_->isActive()) {
        debounce_timer_->stop();
        performSearch();
    }
    if (search_->matchCount() > 0) {
        if (backward) {
            search_->findPrevious();
        } else {
            search_->findNext();
        }
        updateCounterLabel();
    }
    ui_->search_edit_->setFocus();
}

void InPacketFindBar::updateFindButtonState()
{
    bool can_find = !ui_->search_edit_->text().trimmed().isEmpty();
    if (can_find && ui_->search_type_combo_->currentIndex() == 1) {
        const bool case_sensitive = ui_->case_checkbox_->isChecked();
        QRegularExpression::PatternOptions opts = QRegularExpression::NoPatternOption;
        if (!case_sensitive) {
            opts |= QRegularExpression::CaseInsensitiveOption;
        }
        QRegularExpression re(ui_->search_edit_->text(), opts);
        can_find = re.isValid();
    }
    ui_->find_button_->setEnabled(can_find);
}

void InPacketFindBar::closeBar()
{
    hideAnimated();
}

void InPacketFindBar::updateStyleSheet()
{
    setStyleSheet(ThemeManager::instance()->styleSheet(QStringLiteral("widgets/accordion-frame")));
}

void InPacketFindBar::recalculateNaturalHeight()
{
    natural_height_ = 0;
    if (!isVisible() || maximumHeight() <= 0) {
        return;
    }

    setMaximumHeight(QWIDGETSIZE_MAX);
    adjustSize();
    natural_height_ = sizeHint().height();
    setMaximumHeight(natural_height_);
}
