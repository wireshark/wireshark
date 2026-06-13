/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_EDIT_H
#define FILTER_EDIT_H

#include <QLineEdit>

class FilterValidator;
class FilterCompleter;
class QTimer;

/**
 * @brief QLineEdit with validation-state tinting plus an injected filter
 *        validator and completer.
 *
 * FilterEdit has exactly two responsibilities: drive the @c syntaxState QSS
 * property from a FilterValidator, and hold the FilterValidator / FilterCompleter
 * so any QLineEdit-shaped site gets filter validation and completion without the
 * toolbar affordances. It is light enough to serve as an item-view delegate
 * editor.
 *
 * It deliberately does *not* install the validator on QLineEdit: a QLineEdit
 * rejects keystrokes while its validator returns Invalid, but a filter is
 * routinely invalid mid-typing. Instead the validator runs on a debounce purely
 * to colour the field. The completer *is* installed on QLineEdit so the native
 * typeahead popup works.
 *
 * Buttons, menus, history, bookmarks, drag-drop and statusbar coupling live in
 * the FilterExpressionEdit subclass and below, never here.
 */
class FilterEdit : public QLineEdit
{
    Q_OBJECT
    /** String-valued for QSS selectors, e.g. FilterEdit[syntaxState="invalid"]. */
    Q_PROPERTY(QString syntaxState READ syntaxStateName)

public:
    /**
     * @brief Visual/semantic state of the current text, mapped from the validator.
     */
    enum class SyntaxState {
        Empty,        /**< Field empty; no validation performed. Base palette. */
        Busy,         /**< Asynchronous validation in progress (reserved; see note). */
        Intermediate, /**< Still typing, not wrong yet. Neutral, never red. */
        Invalid,      /**< Fails validation. Red tint. */
        Deprecated,   /**< Valid but uses a deprecated construct. Amber tint. */
        Valid         /**< Passes validation. Green tint. */
    };
    Q_ENUM(SyntaxState)

    explicit FilterEdit(QWidget *parent = nullptr);

    /** @brief Current syntax state. */
    SyntaxState state() const { return state_; }

    /** @brief Lowercase state name used for QSS property matching. */
    QString syntaxStateName() const;

    /**
     * @brief Installs the filter validator. Widget-owned (deleted with the
     *        widget, and replaces any previous validator).
     *
     * The validator is *not* handed to QLineEdit::setValidator(); it is run on
     * the debounce only, to drive @c syntaxState. With no validator set the
     * state stays Empty and the field is never tinted.
     */
    void setValidator(FilterValidator *validator);

    /** @brief The installed filter validator, or nullptr. */
    FilterValidator *validator() const { return validator_; }

    /**
     * @brief Installs the filter completer. Widget-owned, and also set as the
     *        QLineEdit completer so the native typeahead popup works.
     */
    void setCompleter(FilterCompleter *completer);

    /** @brief The installed filter completer, or nullptr. */
    FilterCompleter *completer() const { return completer_; }

    /** @brief Short error message from the last validation, or empty. */
    QString lastError() const;

    /** @brief Full, location-annotated error message, or empty. */
    QString lastErrorFull() const;

    /** @brief Deprecated token from the last validation, or empty. */
    QString deprecatedToken() const;

public slots:
    /**
     * @brief Inserts @p filter at the cursor, padding with spaces as needed to
     *        keep the expression well-formed. Replaces a current selection.
     */
    void insertFilter(const QString &filter);

signals:
    /** @brief Emitted whenever the syntax state changes. */
    void syntaxStateChanged(FilterEdit::SyntaxState state);

protected:
    /**
     * @brief Sets the state, re-polishes the style for the new QSS property, and
     *        emits syntaxStateChanged() if it changed.
     */
    void setState(SyntaxState state);

    void paintEvent(QPaintEvent *event) override;

    /**
     * @brief Runs the validator against the current text and updates the state.
     *
     * Synchronous: validate() returns immediately and lastDetail() is read right
     * after. Used both by the debounce and by subclasses that must validate
     * before committing.
     */
    void validateNow();

private:
    FilterValidator *validator_; /**< Widget-owned; drives tint only. */
    FilterCompleter *completer_; /**< Widget-owned; native typeahead. */
    SyntaxState      state_;     /**< Current syntax state. */
    QTimer          *debounce_;  /**< ~150 ms debounce before validateNow(). */

private slots:
    /** @brief Restarts the debounce timer on every text change. */
    void onTextChanged();
};

#endif // FILTER_EDIT_H
