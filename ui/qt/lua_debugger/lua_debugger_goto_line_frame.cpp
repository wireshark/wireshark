/* lua_debugger_goto_line_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Inline go-to-line bar for the Lua debugger code editor.
 */

#include "lua_debugger_goto_line_frame.h"
#include <ui_lua_debugger_goto_line_frame.h>

#include <QApplication>
#include <QIntValidator>
#include <QKeyEvent>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTextBlock>
#include <QTextCursor>
#include <QTimer>

#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/zoom_scaling.h>

#include "lua_debugger_code_editor.h"

LuaDebuggerGoToLineFrame::LuaDebuggerGoToLineFrame(QWidget *parent)
    : AccordionFrame(parent), ui_(new Ui::LuaDebuggerGoToLineFrame)
{
    ui_->setupUi(this);
    /* Pinned to the application font so the dialog's monospace font does not
     * leak into the bar; re-set on every application font change (zoom). */
    setFont(FontManager::zoomedFont());
    connect(FontManager::instance(), &FontManager::applicationFontChanged, this,
            &QWidget::setFont);
    /* The .ui caps the field width in pixels; scale the cap with the text so a long line number stays visible. */
    ZoomScaling::scaleSizeLimits(ui_->lineLineEdit);
    ui_->lineLineEdit->setValidator(new QIntValidator(1, 999999999, ui_->lineLineEdit));
    updateStyleSheet();

    connect(ui_->goButton, &QPushButton::clicked, this, &LuaDebuggerGoToLineFrame::on_goButton_clicked);
    connect(ui_->cancelButton, &QPushButton::clicked, this, &LuaDebuggerGoToLineFrame::on_cancelButton_clicked);
    connect(ui_->lineLineEdit, &QLineEdit::returnPressed, this, &LuaDebuggerGoToLineFrame::on_goButton_clicked);

    ui_->goButton->setDefault(true);
    ui_->goButton->setAutoDefault(true);
    ui_->cancelButton->setDefault(false);
    ui_->cancelButton->setAutoDefault(false);
}

LuaDebuggerGoToLineFrame::~LuaDebuggerGoToLineFrame() { delete ui_; }

void LuaDebuggerGoToLineFrame::setTargetEditor(QPlainTextEdit *editor)
{
    editor_ = editor;
}

void LuaDebuggerGoToLineFrame::focusLineField()
{
    if (QWidget *win = window())
    {
        win->activateWindow();
    }
    ui_->goButton->setDefault(true);
    ui_->lineLineEdit->setFocus(Qt::TabFocusReason);
    if (editor_ && QApplication::focusWidget() == editor_.data())
    {
        editor_->clearFocus();
        ui_->lineLineEdit->setFocus(Qt::TabFocusReason);
    }
    ui_->lineLineEdit->selectAll();
}

void LuaDebuggerGoToLineFrame::syncLineFieldFromEditor()
{
    if (editor_)
    {
        const QTextCursor cur = editor_->textCursor();
        ui_->lineLineEdit->setText(QString::number(cur.blockNumber() + 1));
    }
    else
    {
        ui_->lineLineEdit->clear();
    }
}

void LuaDebuggerGoToLineFrame::scheduleLineFieldFocus()
{
    const auto apply = [this]() { focusLineField(); };
    QTimer::singleShot(0, this, apply);
    QTimer::singleShot(50, this, apply);
    QTimer::singleShot(210, this, apply);
}

void LuaDebuggerGoToLineFrame::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Escape)
    {
        animatedHide();
        event->accept();
        return;
    }
    if (event->modifiers() == Qt::NoModifier && (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter))
    {
        on_goButton_clicked();
        event->accept();
        return;
    }
    AccordionFrame::keyPressEvent(event);
}

void LuaDebuggerGoToLineFrame::on_goButton_clicked()
{
    if (!editor_)
    {
        animatedHide();
        return;
    }
    bool ok = false;
    const int line = ui_->lineLineEdit->text().toInt(&ok);
    if (!ok || line < 1)
    {
        return;
    }
    const int maxLine = editor_->blockCount();
    const int target = qMin(line, maxLine);

    if (auto *codeView = qobject_cast<LuaDebuggerCodeView *>(editor_))
    {
        codeView->moveCaretToLineStart(static_cast<qint32>(target));
        codeView->centerCursor();
        animatedHide();
        /* Focus was on the line field; move it to the editor so the caret blinks. */
        codeView->setFocus(Qt::ShortcutFocusReason);
        if (QWidget *win = codeView->window())
        {
            win->activateWindow();
        }
        return;
    }

    QTextBlock block = editor_->document()->findBlockByNumber(static_cast<int>(target - 1));
    if (!block.isValid())
    {
        return;
    }
    QTextCursor cursor(block);
    cursor.movePosition(QTextCursor::StartOfBlock);
    editor_->setTextCursor(cursor);
    editor_->centerCursor();
    animatedHide();
    editor_->setFocus(Qt::ShortcutFocusReason);
    if (QWidget *win = editor_->window())
    {
        win->activateWindow();
    }
}

void LuaDebuggerGoToLineFrame::on_cancelButton_clicked()
{
    animatedHide();
}
