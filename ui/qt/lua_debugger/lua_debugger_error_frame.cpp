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
#include "lua_debugger_utils.h"
#include <ui_lua_debugger_error_frame.h>

#include <QApplication>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QResizeEvent>
#include <QSizePolicy>
#include <QShowEvent>
#include <QTextEdit>
#include <QTextDocument>
#include <QAbstractTextDocumentLayout>
#include <QTimer>

#include <cmath>

namespace
{

void applyWatchErrorPalette(QTextEdit *textEdit)
{
    if (!textEdit)
    {
        return;
    }

    const LuaDebuggerPath::LuaDbgInvalidFilterColors colors =
        LuaDebuggerPath::invalidFilterColors();

    QPalette pal = textEdit->palette();
    pal.setColor(QPalette::Base, colors.bg);
    pal.setColor(QPalette::Text, colors.fg);
    pal.setColor(QPalette::Window, colors.bg);
    pal.setColor(QPalette::WindowText, colors.fg);
    textEdit->setPalette(pal);
}

} // namespace

LuaDebuggerErrorFrame::LuaDebuggerErrorFrame(QWidget *parent)
    : QFrame(parent), ui_(new Ui::LuaDebuggerErrorFrame)
{
    ui_->setupUi(this);
    setFont(QGuiApplication::font());

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
    applyWatchErrorPalette(ui_->errorTextEdit);

    clearErrorContent();
}

LuaDebuggerErrorFrame::~LuaDebuggerErrorFrame()
{
    delete ui_;
}

void LuaDebuggerErrorFrame::setErrorMessage(const QString &message)
{
    applyWatchErrorPalette(ui_->errorTextEdit);
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
