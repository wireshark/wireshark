/* lua_debugger_evaluate.h
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

#ifndef LUA_DEBUGGER_EVALUATE_H
#define LUA_DEBUGGER_EVALUATE_H

#include <QObject>
#include <QStringList>

class LuaDebuggerDialog;
class QPlainTextEdit;
class QPushButton;

/**
 * @brief Manages the debugger's eval panel: enabling/disabling controls based on pause state,
 *        executing Lua expressions, clearing I/O, and appending batched logpoint output lines.
 */
class LuaDebuggerEvalController : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the controller with a reference to the host dialog.
     * @param host The owning LuaDebuggerDialog instance.
     */
    explicit LuaDebuggerEvalController(LuaDebuggerDialog *host);

    /**
     * @brief Binds the controller to the panel's UI widgets.
     * @param input The text edit used for expression input.
     * @param output The text edit used to display evaluation results.
     * @param evalBtn The button that triggers expression evaluation.
     * @param clearBtn The button that clears the input and output fields.
     */
    void attach(QPlainTextEdit *input, QPlainTextEdit *output, QPushButton *evalBtn, QPushButton *clearBtn);

    /**
     * @brief Updates the enabled/disabled state of panel widgets based on the current debugger pause state.
     */
    void updatePanelState() const;

    /**
     * @brief Appends one or more lines to the output panel and scrolls to the end.
     * @param lines The lines to append, typically drained from a logpoint buffer.
     */
    void appendOutputLines(const QStringList &lines);

public slots:
    /**
     * @brief Slot that reads the input expression and submits it to the Lua debugger for evaluation.
     */
    void onEvaluate();

    /**
     * @brief Slot that clears both the input and output text fields.
     */
    void onEvalClear();

private:
    /** @brief The host dialog that owns and coordinates this controller. */
    LuaDebuggerDialog *host_ = nullptr;

    /** @brief Text edit widget for entering Lua expressions. */
    QPlainTextEdit *input_ = nullptr;

    /** @brief Text edit widget for displaying evaluation output. */
    QPlainTextEdit *output_ = nullptr;

    /** @brief Button that triggers expression evaluation. */
    QPushButton *evalBtn_ = nullptr;

    /** @brief Button that clears the input and output fields. */
    QPushButton *clearBtn_ = nullptr;
};

#endif
