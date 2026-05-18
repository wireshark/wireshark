/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SYNTAX_LINE_EDIT_H
#define SYNTAX_LINE_EDIT_H

#include <QLineEdit>

class QCompleter;
class QStringListModel;

/**
 * @brief QLineEdit subclass that adds syntax-state colouring, error messaging,
 *        and partial token-based autocompletion for display filters, field names,
 *        custom columns, and integer inputs.
 *
 * Autocompletion is partially implemented. Subclasses must:
 * - Provide buildCompletionList()
 * - Call setCompletionTokenChars()
 */
class SyntaxLineEdit : public QLineEdit
{
    Q_OBJECT
    Q_PROPERTY(SyntaxState syntaxState READ syntaxState)
    Q_ENUMS(SyntaxState)

public:
    /**
     * @brief Constructs the SyntaxLineEdit in the Empty state with no completer.
     * @param parent Optional parent widget.
     */
    explicit SyntaxLineEdit(QWidget *parent = 0);

    /**
     * @brief Visual and semantic state of the text currently in the editor.
     */
    enum SyntaxState {
        Empty,      /**< The field is empty; no validation has been performed. */
        Busy,       /**< Validation is in progress (e.g. asynchronous lookup). */
        Invalid,    /**< The current text fails validation. */
        Deprecated, /**< The current text is valid but uses a deprecated construct. */
        Valid       /**< The current text passes validation. */
    };

    /**
     * @brief Returns the current syntax validation state.
     * @return Current SyntaxState value.
     */
    SyntaxState syntaxState() const { return syntax_state_; }

    /**
     * @brief Sets the syntax state and updates the widget's style sheet to reflect it.
     * @param state New syntax state; defaults to Empty.
     */
    void setSyntaxState(SyntaxState state = Empty);

    /**
     * @brief Returns a short, human-readable description of the current syntax error.
     * @return Error message string, or an empty string if the state is not Invalid.
     */
    QString syntaxErrorMessage();

    /**
     * @brief Returns a full error message that includes the filter expression and
     *        the location of the error within it.
     * @return Full error message string, or an empty string if there is no error.
     */
    QString syntaxErrorMessageFull();

    /**
     * @brief Returns the base style sheet, excluding any state-driven overrides.
     * @return Base style sheet string.
     */
    QString styleSheet() const;

    /**
     * @brief Returns the deprecated token string when the state is Deprecated.
     * @return The deprecated token, or an empty string if the state is not Deprecated.
     */
    QString deprecatedToken();

    /**
     * @brief Installs a QCompleter for token-based autocompletion.
     * @param c Completer to install; pass @c nullptr to remove the current completer.
     */
    void setCompleter(QCompleter *c);

    /**
     * @brief Returns the currently installed completer.
     * @return Pointer to the QCompleter, or @c nullptr if none is installed.
     */
    QCompleter *completer() const { return completer_; }

    /**
     * @brief Enables or disables autocompletion without removing the completer.
     * @param enabled @c true to allow completion popups; @c false to suppress them.
     */
    void allowCompletion(bool enabled);

    /**
     * @brief Builds a full syntax error message string combining the filter expression
     *        with a location-annotated error description.
     * @param filter      The filter expression that failed validation.
     * @param err_msg     Short error message returned by the validator.
     * @param loc_start   Zero-based character offset where the error begins.
     * @param loc_length  Number of characters the error spans.
     * @return Formatted full error message string.
     */
    static QString createSyntaxErrorMessageFull(const QString &filter,
                                                const QString &err_msg,
                                                qsizetype loc_start,
                                                size_t loc_length);

public slots:
    /**
     * @brief Sets the base style sheet; the state-driven style is composited on top.
     * @param style_sheet New base style sheet string.
     */
    void setStyleSheet(const QString &style_sheet);

    /**
     * @brief Inserts filter text at the cursor position, adding surrounding spaces
     *        where necessary to keep the expression well-formed.
     * @param filter Filter text to insert.
     */
    void insertFilter(const QString &filter);

    /**
     * @brief Validates @p filter as a Wireshark display filter and updates the
     *        syntax state and error message accordingly.
     * @param filter Display filter expression to check.
     * @return @c true if the filter is valid or empty; @c false if invalid.
     */
    bool checkDisplayFilter(QString filter);

    /**
     * @brief Validates @p field as a protocol field name and updates the syntax state.
     * @param field Field name string to check (e.g. "tcp.port").
     */
    void checkFieldName(QString field);

    /**
     * @brief Validates @p fields as a custom-column field expression and updates
     *        the syntax state.
     * @param fields Custom column field expression to check.
     */
    void checkCustomColumn(QString fields);

    /**
     * @brief Validates @p number as a well-formed integer and updates the syntax state.
     * @param number String to validate as an integer.
     */
    void checkInteger(QString number);

protected:
    QCompleter       *completer_;         /**< Installed autocompletion provider; may be @c nullptr. */
    QStringListModel *completion_model_;  /**< String list model backing the completer. */

    /**
     * @brief Sets the characters that may appear in a completion token (e.g. letters,
     *        digits, underscores, dots). Must be called by subclasses before completion
     *        is used.
     * @param token_chars String of characters valid within a single completion token.
     */
    void setCompletionTokenChars(const QString &token_chars) { token_chars_ = token_chars; }

    /**
     * @brief Returns @c true if @p filter contains operators or structure that make
     *        it too complex for token-level autocompletion.
     * @param filter Filter expression to inspect.
     * @return @c true if the filter is considered complex.
     */
    bool isComplexFilter(const QString &filter);

    /**
     * @brief Builds the list of completion candidates based on the current token and filter context.
     *        Subclasses must override this to provide context-appropriate completions.
     * @param field_word The current token under the cursor that is being completed.
     * @param preamble The portion of the filter before the current token, which may provide context for filtering the completion list.
     */
    virtual void buildCompletionList(const QString &field_word, const QString &preamble)
    {
        Q_UNUSED(field_word);
        Q_UNUSED(preamble);
    }

    /**
     * @brief Returns the start position and length of the token under the cursor.
     * @return QPoint where x is the start character offset and y is the token length.
     */
    QPoint getTokenUnderCursor();

    /**
     * @brief Splits the line at the cursor into the preamble and the current token.
     * @return QStringList of exactly two elements: { preamble, token }.
     */
    QStringList splitLineUnderCursor();

    /**
     * @brief Intercepts Tab and other keys to trigger or dismiss the completer.
     * @param event The event to inspect.
     * @return @c true if the event was consumed; @c false to pass it on.
     */
    virtual bool event(QEvent *event);

    /**
     * @brief Handles key press events while the completer popup is visible,
     *        forwarding navigation keys to the popup and committing on Enter/Tab.
     * @param event The key press event.
     */
    void completionKeyPressEvent(QKeyEvent *event);

    /**
     * @brief Triggers a completion refresh when the widget gains focus.
     * @param event The focus-in event.
     */
    void completionFocusInEvent(QFocusEvent *event);

    /**
     * @brief Hides the completer popup when the widget loses focus.
     * @param event The focus-out event.
     */
    virtual void focusOutEvent(QFocusEvent *event);

    /**
     * @brief Paints the widget, overlaying a state-appropriate background colour.
     * @param event The paint event.
     */
    virtual void paintEvent(QPaintEvent *event);

private:
    SyntaxState syntax_state_;              /**< Current validation state. */
    QString     style_sheet_;               /**< Base style sheet provided by the caller. */
    QString     state_style_sheet_;         /**< State-driven style sheet composited over the base. */
    QString     syntax_error_message_;      /**< Short error description for the current invalid state. */
    QString     syntax_error_message_full_; /**< Full error message including expression and location. */
    QString     token_chars_;               /**< Characters valid within a completion token. */
    bool        completion_enabled_;        /**< @c true if completion popups are permitted. */

private slots:
    /**
     * @brief Replaces the token under the cursor with the selected completion text.
     * @param completion_text The completion string chosen by the user.
     */
    void insertFieldCompletion(const QString &completion_text);

signals:
};

#endif // SYNTAX_LINE_EDIT_H
