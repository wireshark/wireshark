/* lua_debugger_evaluate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Evaluate panel: run Lua expressions while paused.
 */

#include "lua_debugger_evaluate.h"

#include <QHBoxLayout>
#include <QKeySequence>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTextCursor>
#include <QVBoxLayout>
#include <QWidget>

#include <glib.h>

#include "lua_debugger_dialog.h"
#include "lua_debugger_utils.h"
#include "widgets/collapsible_section.h"
#include <epan/wslua/wslua_debugger.h>

/* ===== eval_controller ===== */

void LuaDebuggerEvalController::attach(QPlainTextEdit *input, QPlainTextEdit *output, QPushButton *evalBtn,
                                       QPushButton *clearBtn)
{
    input_ = input;
    output_ = output;
    evalBtn_ = evalBtn;
    clearBtn_ = clearBtn;
}

LuaDebuggerEvalController::LuaDebuggerEvalController(LuaDebuggerDialog *host) : QObject(host), host_(host) {}

void LuaDebuggerEvalController::updatePanelState() const
{
    const bool canEvaluate = host_->isDebuggerPaused() && wslua_debugger_is_paused();
    if (input_)
    {
        input_->setEnabled(canEvaluate);
    }
    if (evalBtn_)
    {
        evalBtn_->setEnabled(canEvaluate);
    }

    if (!input_)
    {
        return;
    }
    if (!canEvaluate)
    {
        input_->setPlaceholderText(host_->tr("Evaluation available when debugger is paused"));
    }
    else
    {
        input_->setPlaceholderText(host_->tr("Enter Lua expression"));
    }
}

void LuaDebuggerEvalController::appendOutputLines(const QStringList &lines)
{
    if (!output_ || lines.isEmpty())
    {
        return;
    }
    for (const QString &m : lines)
    {
        output_->appendPlainText(m);
    }

    QTextCursor cursor = output_->textCursor();
    cursor.movePosition(QTextCursor::End);
    output_->setTextCursor(cursor);
}

void LuaDebuggerEvalController::onEvaluate()
{
    if (!host_->isDebuggerPaused() || !wslua_debugger_is_paused() || !input_ || !output_)
    {
        return;
    }

    QString expression = input_->toPlainText().trimmed();
    if (expression.isEmpty())
    {
        return;
    }

    char *error_msg = nullptr;
    char *result = wslua_debugger_evaluate(expression.toUtf8().constData(), &error_msg);

    QString output;
    if (result)
    {
        output = QString::fromUtf8(result);
        g_free(result);
    }
    else if (error_msg)
    {
        output = host_->tr("Error: %1").arg(QString::fromUtf8(error_msg));
        g_free(error_msg);
    }
    else
    {
        output = host_->tr("Error: Unknown error");
    }

    output_->appendPlainText(QStringLiteral("> %1").arg(expression));
    output_->appendPlainText(output);

    QTextCursor cursor = output_->textCursor();
    cursor.movePosition(QTextCursor::End);
    output_->setTextCursor(cursor);

    host_->stackController().updateFromEngine();
    host_->variablesController().rebuildFromEngine();
    host_->filesController().refreshAvailableScripts();
    host_->watchController().refreshDisplay();
}

void LuaDebuggerEvalController::onEvalClear()
{
    if (output_)
    {
        output_->clear();
    }
}

/* ===== dialog_evaluate (LuaDebuggerDialog members) ===== */

CollapsibleSection *LuaDebuggerDialog::createEvaluateSection(QWidget *parent)
{
    evalSection = new CollapsibleSection(tr("Evaluate"), parent);
    evalSection->setToolTip(tr("<b>Lua Expression Evaluation</b><br><br>"
                                 "Code runs in a protected environment: runtime errors are "
                                 "caught and shown in the output instead of propagating.<br><br>"
                                 "<b>What works:</b><ul>"
                                 "<li>Read/modify global variables (<code>_G.x = 42</code>)</li>"
                                 "<li>Modify table contents (<code>my_table.field = 99</code>)</li>"
                                 "<li>Call functions and inspect return values</li>"
                                 "</ul>"
                                 "<b>Limitations:</b><ul>"
                                 "<li>Local variables cannot be modified directly (use "
                                 "<code>debug.setlocal()</code>) unless there is an associated "
                                 "<i>assign</i> method (<code>pinfo.src_port</code>)</li>"
                                 "<li>Long-running expressions are automatically aborted</li>"
                                 "<li><b>Warning:</b> Changes to globals persist and can affect "
                                 "ongoing dissection</li>"
                                 "</ul>"));
    QWidget *evalWidget = new QWidget();
    QVBoxLayout *evalMainLayout = new QVBoxLayout(evalWidget);
    evalMainLayout->setContentsMargins(0, 0, 0, 0);
    evalMainLayout->setSpacing(4);

    /* Held as a member so the input/output split (including either pane
     * being collapsed to zero by the user) persists via
     * storeDialogSettings()/applyDialogSettings(). */
    evalSplitter_ = new QSplitter(Qt::Vertical);
    evalInputEdit = new QPlainTextEdit();
    /* Same cap as the output pane: a giant paste shouldn't grow
     * the input buffer without bound either, and the document's
     * per-line layout cost climbs linearly with size. */
    evalInputEdit->setMaximumBlockCount(kLuaDbgEvalOutputMaxLines);
    evalInputEdit->setPlaceholderText(tr("Enter Lua expression"));
    evalOutputEdit = new QPlainTextEdit();
    evalOutputEdit->setReadOnly(true);
    evalOutputEdit->setPlaceholderText(tr("Output"));
    /* Bound the output buffer. With per-packet logpoints the line
     * count grows without limit otherwise, and QPlainTextEdit's
     * per-line layout cost climbs linearly with the document size.
     * QPlainTextEdit auto-evicts the oldest blocks once the cap is
     * reached. */
    evalOutputEdit->setMaximumBlockCount(kLuaDbgEvalOutputMaxLines);
    evalSplitter_->addWidget(evalInputEdit);
    evalSplitter_->addWidget(evalOutputEdit);
    evalMainLayout->addWidget(evalSplitter_, 1);

    QHBoxLayout *evalButtonLayout = new QHBoxLayout();
    evalButton = new QPushButton(tr("Evaluate"));
    evalButton->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Return));
    evalButton->setToolTip(tr("Execute the Lua code (Ctrl+Return)"));
    evalClearButton = new QPushButton(tr("Clear"));
    evalClearButton->setToolTip(tr("Clear output"));
    evalButtonLayout->addWidget(evalButton);
    evalButtonLayout->addWidget(evalClearButton);
    evalButtonLayout->addStretch();
    evalMainLayout->addLayout(evalButtonLayout);

    evalSection->setContentWidget(evalWidget);
    evalSection->setExpanded(false);
    return evalSection;
}

void LuaDebuggerDialog::wireEvaluatePanel()
{
    evalController_.attach(evalInputEdit, evalOutputEdit, evalButton, evalClearButton);
    connect(evalButton, &QPushButton::clicked, &evalController_, &LuaDebuggerEvalController::onEvaluate);
    connect(evalClearButton, &QPushButton::clicked, &evalController_, &LuaDebuggerEvalController::onEvalClear);
}
