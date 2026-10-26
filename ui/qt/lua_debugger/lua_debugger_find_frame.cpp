/* lua_debugger_find_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Inline find / replace bar for the Lua debugger code editor.
 */

#include "lua_debugger_find_frame.h"
#include <ui_lua_debugger_find_frame.h>

#include <QApplication>
#include <QEvent>
#include <QKeyEvent>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QTextCursor>
#include <QTextDocument>
#include <QTimer>

#include <ui/qt/utils/font_manager.h>

LuaDebuggerFindFrame::LuaDebuggerFindFrame(QWidget *parent) : AccordionFrame(parent), ui_(new Ui::LuaDebuggerFindFrame)
{
    ui_->setupUi(this);
    /* Share one stretch column so both line edits align left and right edges. */
    ui_->findReplaceGrid->setColumnStretch(0, 0);
    ui_->findReplaceGrid->setColumnStretch(1, 1);
    ui_->findReplaceGrid->setColumnStretch(2, 0);
    /* Pinned to the application font so the dialog's monospace font does not
     * leak into the bar; re-set on every application font change (zoom). */
    setFont(FontManager::zoomedFont());
    connect(FontManager::instance(), &FontManager::applicationFontChanged, this,
            &QWidget::setFont);
    updateStyleSheet();

    /* No manual button connects (connectSlotsByName). Enter: filter Return — returnPressed can double-fire. */
    ui_->findLineEdit->installEventFilter(this);

    ui_->findNextButton->setDefault(false);
    ui_->findNextButton->setAutoDefault(false);
    ui_->findPreviousButton->setDefault(false);
    ui_->findPreviousButton->setAutoDefault(false);
    ui_->replaceButton->setDefault(false);
    ui_->replaceButton->setAutoDefault(false);
    ui_->replaceAllButton->setDefault(false);
    ui_->replaceAllButton->setAutoDefault(false);
    ui_->closeButton->setDefault(false);
    ui_->closeButton->setAutoDefault(false);
}

bool LuaDebuggerFindFrame::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == ui_->findLineEdit && event->type() == QEvent::KeyPress)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        if (ke->modifiers() == Qt::NoModifier && (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter))
        {
            on_findNextButton_clicked();
            return true;
        }
    }
    return AccordionFrame::eventFilter(watched, event);
}

LuaDebuggerFindFrame::~LuaDebuggerFindFrame() { delete ui_; }

void LuaDebuggerFindFrame::setTargetEditor(QPlainTextEdit *editor)
{
    editor_ = editor;
}

void LuaDebuggerFindFrame::focusFindField()
{
    if (QWidget *win = window())
    {
        win->activateWindow();
    }
    ui_->findLineEdit->setFocus(Qt::TabFocusReason);
    if (editor_ && QApplication::focusWidget() == editor_.data())
    {
        editor_->clearFocus();
        ui_->findLineEdit->setFocus(Qt::TabFocusReason);
    }
    ui_->findLineEdit->selectAll();
}

void LuaDebuggerFindFrame::scheduleFindFieldFocus()
{
    /*
     * AccordionFrame animates maximumHeight over 150ms; line edits cannot take
     * focus reliably until layout has a non-zero height — schedule retries
     * (matches duration in ui/qt/accordion_frame.cpp).
     */
    const auto apply = [this]() { focusFindField(); };
    QTimer::singleShot(0, this, apply);
    QTimer::singleShot(50, this, apply);
    QTimer::singleShot(210, this, apply);
}

void LuaDebuggerFindFrame::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Escape)
    {
        animatedHide();
        event->accept();
        return;
    }
    if (event->modifiers() == Qt::NoModifier && (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter))
    {
        on_findNextButton_clicked();
        event->accept();
        return;
    }
    AccordionFrame::keyPressEvent(event);
}

bool LuaDebuggerFindFrame::selectionMatchesFind() const
{
    if (!editor_ || !editor_->textCursor().hasSelection())
    {
        return false;
    }
    QString findText = ui_->findLineEdit->text();
    if (findText.isEmpty())
    {
        return false;
    }
    /* QTextDocument::find normalizes NBSP to space in each block; match that. */
    QString sel = editor_->textCursor().selectedText();
    sel.replace(QChar::Nbsp, u' ');
    findText.replace(QChar::Nbsp, u' ');
    /*
     * Multi-line selections use U+2029 between fragments; single-line find
     * cannot match those — only compare when lengths align after newline fix.
     */
    sel.replace(QChar::ParagraphSeparator, QLatin1Char('\n'));

    return findText == sel;
}

void LuaDebuggerFindFrame::findNext(bool backward)
{
    if (!editor_)
    {
        return;
    }
    const QString findText = ui_->findLineEdit->text();
    if (findText.isEmpty())
    {
        return;
    }

    QTextDocument::FindFlags flags = QTextDocument::FindCaseSensitively;
    if (backward)
    {
        flags |= QTextDocument::FindBackward;
    }

    if (editor_->find(findText, flags))
    {
        editor_->centerCursor();
        return;
    }

    QTextCursor c = editor_->textCursor();
    if (backward)
    {
        c.movePosition(QTextCursor::End);
    }
    else
    {
        c.movePosition(QTextCursor::Start);
    }
    editor_->setTextCursor(c);
    if (editor_->find(findText, flags))
    {
        editor_->centerCursor();
    }
}

void LuaDebuggerFindFrame::on_findNextButton_clicked()
{
    findNext(false);
}

void LuaDebuggerFindFrame::on_findPreviousButton_clicked()
{
    findNext(true);
}

void LuaDebuggerFindFrame::on_replaceButton_clicked()
{
    if (!editor_)
    {
        return;
    }
    const QString findText = ui_->findLineEdit->text();
    if (findText.isEmpty())
    {
        return;
    }

    if (selectionMatchesFind())
    {
        QTextCursor c = editor_->textCursor();
        c.insertText(ui_->replaceLineEdit->text());
        editor_->setTextCursor(c);
        findNext(false);
        return;
    }
    findNext(false);
    if (selectionMatchesFind())
    {
        QTextCursor c = editor_->textCursor();
        c.insertText(ui_->replaceLineEdit->text());
        editor_->setTextCursor(c);
    }
}

void LuaDebuggerFindFrame::replaceAll()
{
    if (!editor_)
    {
        return;
    }
    const QString findText = ui_->findLineEdit->text();
    if (findText.isEmpty())
    {
        return;
    }
    const QString replaceText = ui_->replaceLineEdit->text();
    QTextDocument *const doc = editor_->document();
    const QTextDocument::FindFlags flags = QTextDocument::FindCaseSensitively;

    QTextCursor edit(doc);
    edit.beginEditBlock();
    QTextCursor cursor(doc);
    while (!(cursor = doc->find(findText, cursor, flags)).isNull())
    {
        cursor.insertText(replaceText);
    }
    edit.endEditBlock();
}

void LuaDebuggerFindFrame::on_replaceAllButton_clicked()
{
    replaceAll();
}

void LuaDebuggerFindFrame::on_closeButton_clicked()
{
    animatedHide();
}
