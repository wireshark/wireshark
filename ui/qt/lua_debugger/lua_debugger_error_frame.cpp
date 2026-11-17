/* lua_debugger_error_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Inline error details bar for the Lua debugger code editor.
 */

#include "lua_debugger_error_frame.h"
#include <ui_lua_debugger_error_frame.h>

#include <QApplication>
#include <QKeyEvent>
#include <QResizeEvent>
#include <QSizePolicy>
#include <QShowEvent>
#include <QTextEdit>
#include <QTextDocument>
#include <QAbstractTextDocumentLayout>
#include <QTimer>

#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

#include <cmath>

namespace
{

/* Paint the text box with a theme background token and a contrasting text colour. */
void applyFramePalette(QTextEdit *textEdit, ThemeManager::ThemeToken bgToken)
{
    if (!textEdit)
    {
        return;
    }

    const QColor bg = ThemeManager::instance()->color(bgToken);
    const QColor fg = ColorMath::contrastingText(bg);

    QPalette pal = textEdit->palette();
    pal.setColor(QPalette::Base, bg);
    pal.setColor(QPalette::Text, fg);
    pal.setColor(QPalette::Window, bg);
    pal.setColor(QPalette::WindowText, fg);
    textEdit->setPalette(pal);
}

} // namespace

LuaDebuggerErrorFrame::LuaDebuggerErrorFrame(QWidget *parent)
    : QFrame(parent), ui_(new Ui::LuaDebuggerErrorFrame)
{
    ui_->setupUi(this);
    /* Pinned to the application font so the dialog's monospace font does not
     * leak into the bar; re-set on every application font change (zoom). */
    setFont(FontManager::zoomedFont());
    connect(FontManager::instance(), &FontManager::applicationFontChanged, this,
            &QWidget::setFont);

    /* Keep the frame as compact as possible; height follows text content. */
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    ui_->errorTextEdit->setReadOnly(true);
    ui_->errorTextEdit->setUndoRedoEnabled(false);
    ui_->errorTextEdit->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    ui_->errorTextEdit->setCursorWidth(0);
    ui_->errorTextEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    ui_->errorTextEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    ui_->errorTextEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    ui_->errorTextEdit->setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    applyFramePalette(ui_->errorTextEdit, ThemeManager::FilterInvalid);

    clearErrorContent();
}

LuaDebuggerErrorFrame::~LuaDebuggerErrorFrame()
{
    delete ui_;
}

void LuaDebuggerErrorFrame::setWarningMessage(const QString &message)
{
    applyFramePalette(ui_->errorTextEdit, ThemeManager::FilterDeprecated);
    ui_->errorTextEdit->setPlainText(message);
    updateCompactHeight();
}

void LuaDebuggerErrorFrame::setErrorMessage(const QString &message)
{
    applyFramePalette(ui_->errorTextEdit, ThemeManager::FilterInvalid);
    ui_->errorTextEdit->setPlainText(message);
    updateCompactHeight();
}

void LuaDebuggerErrorFrame::setEditorStyleFont(const QFont &font)
{
    ui_->errorTextEdit->setFont(font);
    updateCompactHeight();
}

void LuaDebuggerErrorFrame::clearErrorContent()
{
    ui_->errorTextEdit->clear();
    updateCompactHeight();
}

void LuaDebuggerErrorFrame::focusPrimaryControl()
{
    if (QWidget *win = window())
    {
        win->activateWindow();
    }
    setFocus(Qt::TabFocusReason);
}

void LuaDebuggerErrorFrame::schedulePrimaryFocus()
{
    const auto apply = [this]() { focusPrimaryControl(); };
    QTimer::singleShot(0, this, apply);
    QTimer::singleShot(50, this, apply);
    QTimer::singleShot(210, this, apply);
}

void LuaDebuggerErrorFrame::keyPressEvent(QKeyEvent *event)
{
    QFrame::keyPressEvent(event);
}

void LuaDebuggerErrorFrame::resizeEvent(QResizeEvent *event)
{
    QFrame::resizeEvent(event);
    updateCompactHeight();
}

void LuaDebuggerErrorFrame::showEvent(QShowEvent *event)
{
    QFrame::showEvent(event);
    updateCompactHeight();
    /* First show can still have stale pre-layout metrics; recompute once
     * on the next event-loop turn with a settled viewport width. */
    QTimer::singleShot(0, this, [this]() { updateCompactHeight(); });
}

void LuaDebuggerErrorFrame::updateCompactHeight()
{
    QTextDocument *doc = ui_->errorTextEdit->document();
    if (!doc)
    {
        return;
    }

    const int framePixels = ui_->errorTextEdit->frameWidth() * 2;
    const QMargins textMargins = ui_->errorTextEdit->contentsMargins();
    const int viewportWidth = ui_->errorTextEdit->viewport()->width();
    const int fallbackWidth = ui_->errorTextEdit->width() - framePixels - textMargins.left() - textMargins.right();
    const int textWidth = qMax(1, viewportWidth > 0 ? viewportWidth : fallbackWidth);
    doc->setTextWidth(textWidth);

    const qreal docHeight = doc->documentLayout()->documentSize().height();
    const int frameAndMargins = framePixels + textMargins.top() + textMargins.bottom();
    const int targetTextHeight = qMax(1, static_cast<int>(std::ceil(docHeight)) + frameAndMargins);

    ui_->errorTextEdit->setMinimumHeight(targetTextHeight);
    ui_->errorTextEdit->setMaximumHeight(targetTextHeight);

    const QMargins frameMargins = layout()->contentsMargins();
    const int targetFrameHeight = frameMargins.top() + targetTextHeight + frameMargins.bottom();
    setMinimumHeight(targetFrameHeight);
    setMaximumHeight(targetFrameHeight);
    updateGeometry();
}
