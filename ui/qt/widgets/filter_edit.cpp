/* filter_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/widgets/filter_edit.h>

#include <ui/qt/models/filter_validator.h>
#include <ui/qt/models/filter_completer.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

#include <QApplication>
#include <QStyle>
#include <QTimer>
#include <cmath>
#include <limits>
#include <utility>

// Debounce before running the (synchronous) validator after a text change.
static const int validation_debounce_ms_ = 150;

FilterEdit::FilterEdit(QWidget *parent) :
    QLineEdit(parent),
    validator_(nullptr),
    completer_(nullptr),
    state_(SyntaxState::Empty),
    debounce_(new QTimer(this))
{
    setMaxLength(std::numeric_limits<quint32>::max());

    debounce_->setSingleShot(true);
    debounce_->setInterval(validation_debounce_ms_);
    connect(debounce_, &QTimer::timeout, this, &FilterEdit::validateNow);
    connect(this, &QLineEdit::textChanged, this, &FilterEdit::onTextChanged);
}

QString FilterEdit::syntaxStateName() const
{
    switch (state_) {
    case SyntaxState::Empty:        return QStringLiteral("empty");
    case SyntaxState::Busy:         return QStringLiteral("busy");
    case SyntaxState::Intermediate: return QStringLiteral("intermediate");
    case SyntaxState::Invalid:      return QStringLiteral("invalid");
    case SyntaxState::Deprecated:   return QStringLiteral("deprecated");
    case SyntaxState::Valid:        return QStringLiteral("valid");
    }
    return QStringLiteral("empty");
}

void FilterEdit::setValidator(FilterValidator *validator)
{
    if (validator_ == validator)
        return;
    delete validator_;
    validator_ = validator;
    if (validator_)
        validator_->setParent(this);
    validateNow();
}

void FilterEdit::setCompleter(FilterCompleter *completer)
{
    if (completer_ == completer)
        return;
    // Detach the old completer from QLineEdit before deleting it so the line
    // edit never holds a dangling pointer.
    QLineEdit::setCompleter(nullptr);
    delete completer_;
    completer_ = completer;
    if (completer_) {
        completer_->setParent(this);
        QLineEdit::setCompleter(completer_);
    }
}

QString FilterEdit::lastError() const
{
    return validator_ ? validator_->lastError() : QString();
}

QString FilterEdit::lastErrorFull() const
{
    return validator_ ? validator_->lastErrorFull(text()) : QString();
}

QString FilterEdit::deprecatedToken() const
{
    return validator_ ? validator_->deprecatedToken() : QString();
}

void FilterEdit::insertFilter(const QString &filter)
{
    if (hasSelectedText()) {
        backspace();
    }

    if (filter.isEmpty()) {
        return;
    }

    QStringList newText = { text() };
    if ( cursorPosition() > 0) {
        newText.prepend(filter);
    } else {
        newText.append(filter);
    }

    setText(newText.join(' '));
}

void FilterEdit::onTextChanged()
{
    debounce_->start();
}

void FilterEdit::setState(SyntaxState state)
{
    if (std::exchange(state_, state) == state) {
        // "All happy [filters] are alike; each unhappy [filter] is unhappy
        // in its own way." If the state is unchanged but unhappy, still
        // emit the status because the precise error message may have changed.
        switch (state_) {
        case SyntaxState::Invalid:
        case SyntaxState::Deprecated:
            emit syntaxStateChanged(state_);
            break;
        default:
            break;
        }
        return;
    }

    // The background tint comes from the global QSS (theme tokens). A single
    // fixed text color can't serve all tints — valid/invalid are dark, the
    // deprecated tint is bright — so compute the contrasting foreground from the
    // active background and apply it via the palette. Non-tinted states restore
    // the inherited text color.
    const ThemeManager *theme = ThemeManager::instance();
    QPalette pal = palette();
    QColor fg;
    switch (state_) {
    case SyntaxState::Valid:
        fg = ColorMath::contrastingText(theme->color(ThemeManager::FilterValid));
        break;
    case SyntaxState::Invalid:
        fg = ColorMath::contrastingText(theme->color(ThemeManager::FilterInvalid));
        break;
    case SyntaxState::Deprecated:
        fg = ColorMath::contrastingText(theme->color(ThemeManager::FilterDeprecated));
        break;
    default:
        fg = qApp->palette().color(QPalette::Text); // inherited/base text
        break;
    }
    pal.setColor(QPalette::Text, fg);
    setPalette(pal);

    // The syntaxState QSS property changed; re-evaluate the stylesheet so the
    // new tint applies. addAction-based chrome reflows itself, so there is no
    // geometry to recompute here.
    style()->unpolish(this);
    style()->polish(this);
    update();
    emit syntaxStateChanged(state_);
}

void FilterEdit::validateNow()
{
    const QString current = text();

    // No validator, or nothing typed: never tinted.
    if (!validator_ || current.isEmpty()) {
        setState(SyntaxState::Empty);
        return;
    }

    QString input = current;
    int pos = cursorPosition();
    const QValidator::State result = validator_->validate(input, pos);
    const FilterValidator::Detail detail = validator_->lastDetail();

    // State mapping — the semantic core of the tinting. QValidator only
    // distinguishes Invalid / Intermediate / Acceptable; the deprecation split
    // comes from the validator's Detail, read immediately after validate().
    SyntaxState mapped;
    switch (result) {
    case QValidator::Invalid:
        mapped = SyntaxState::Invalid;
        break;
    case QValidator::Intermediate:
        // "Still typing, not wrong yet" — neutral, must never read as an error.
        mapped = SyntaxState::Intermediate;
        break;
    case QValidator::Acceptable:
    default:
        mapped = detail.deprecatedToken.isEmpty() ? SyntaxState::Valid
                                                  : SyntaxState::Deprecated;
        break;
    }
    setState(mapped);
}
