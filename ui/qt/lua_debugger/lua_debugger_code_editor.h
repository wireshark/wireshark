/* lua_debugger_code_editor.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Code editor stack: editor view, gutter, syntax highlighter, theme
 * palette, font policy and the script-tabs controller.
 */

#ifndef LUA_DEBUGGER_CODE_EDITOR_H
#define LUA_DEBUGGER_CODE_EDITOR_H

#include <QColor>
#include <QFont>
#include <QObject>
#include <QPlainTextEdit>
#include <QPoint>
#include <QRegularExpression>
#include <QString>
#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QVector>
#include <QtGlobal>

class LuaDebuggerCodeView;
class LuaDebuggerDialog;
class QContextMenuEvent;
class QEvent;
class QPlainTextEdit;
class QStandardItemModel;
class QSyntaxHighlighter;
class QTabWidget;
class QTextDocument;
class QTreeView;

/* ===== code_palette ===== */

/**
 * @brief Single source of truth for the script editor's theme-aware colours.
 *
 * Used by @ref LuaDebuggerCodeView to seed both its @c QPalette
 * (@c applyEditorPalette) and the gutter painter
 * (@c lineNumberAreaPaintEvent), and by @c rebuildLineHighlights for the
 * paused-line stripe. Centralising the table here keeps the editor and
 * gutter from drifting apart.
 */
struct LuaDebuggerEditorPalette
{
    QColor editorBackground;
    QColor editorText;
    QColor selection;
    QColor selectionText;

    QColor gutterBackground;
    QColor gutterText;

    /** @brief Background for the line the debugger is paused on. */
    QColor pausedLine;
};

/** @brief Resolve the effective theme based on the debugger preference and
 *  Wireshark's current colour scheme when set to AUTO. */
bool luaDebuggerThemeIsDark();

/**
 * @brief Return the editor palette for the requested theme.
 * @param isDark Indicates whether the dark theme should be used.
 * @return LuaDebuggerEditorPalette The editor palette for the specified theme.
 */
LuaDebuggerEditorPalette luaDebuggerEditorPaletteFor(bool isDark);

/* ===== lua_highlighter ===== */

/**
 * @brief Syntax highlighter tuned for Lua keywords, strings, numbers,
 *        comments and Lua's long-bracket strings/comments.
 *
 * Theme-agnostic: takes a @c bool isDark at construction (and at
 * @ref setTheme) and pulls the matching colour table from a private
 * helper. No coupling to @c LuaDebuggerCodeView or @c LuaDebuggerDialog.
 */
class LuaSyntaxHighlighter : public QSyntaxHighlighter
{
  public:
    /** @brief Build the rule set for @p isDark and bind to @p parent's document. */
    explicit LuaSyntaxHighlighter(QTextDocument *parent, bool isDark);

    /** @brief Rebuild the rule set for the new theme and rehighlight. */
    void setTheme(bool isDark);

  protected:
    /** @brief Apply highlighting to a single text block. */
    void highlightBlock(const QString &text) override;

  private:
    /**
     * @brief A single syntax highlighting rule pairing a regex pattern with a text format.
     */
    struct Rule
    {
        QRegularExpression pattern;  /**< Regular expression used to match tokens in source text. */
        QTextCharFormat format;      /**< Text character format applied to matched tokens. */
    };


    QVector<Rule> rules_;                    /**< Ordered list of syntax highlighting rules applied in sequence. */
    QTextCharFormat stringFormat_;           /**< Text format applied to string literals. */
    QTextCharFormat commentFormat_;          /**< Text format applied to comment text. */
    QRegularExpression singleLineComment_;   /**< Regular expression used to detect single-line comments. */

    /** @brief Highlight multi-line strings or comments, preserving parser state. */
    bool highlightLongBlock(const QString &text, bool isComment, bool continuingPrevious, qint32 eqCountFromState,
                            qint32 &nextStateEqCount);
    /** @brief Locate the beginning of a Lua long bracket token. */
    qint32 findLongBlockStart(const QString &text, qint32 from, bool isComment, qint32 &eqCount,
                              qint32 &tokenLength) const;
    /** @brief Locate the closing delimiter for a Lua long bracket token. */
    qint32 findLongBlockEnd(const QString &text, qint32 from, qint32 eqCount) const;

    /**
     * @brief Build the syntax-highlighting rules for @p isDark and store them in @c rules_.
     * @param isDark Indicates whether the dark theme should be used.
     */
    void buildRules(bool isDark);
};

/* ===== code_view ===== */

/**
 * @brief Editable code editor supporting gutter breakpoints and highlighting.
 */
class LuaDebuggerCodeView : public QPlainTextEdit
{
    Q_OBJECT

  public:
    /**
     * @brief Create the code view and configure the line number gutter.
     * @param parent Optional parent widget for ownership.
     */
    LuaDebuggerCodeView(QWidget *parent = nullptr);

    /**
     * @brief Paint the custom gutter that hosts line numbers and breakpoints.
     * @param event Exposes the area to repaint.
     */
    void lineNumberAreaPaintEvent(QPaintEvent *event);
    /**
     * @brief Compute the width required for the gutter, including icons.
     * @return Width in device-independent pixels.
     */
    qint32 lineNumberAreaWidth();

    /**
     * @brief Set the file path this editor is currently hosting, for use in
     *        breakpoint management and the "edited" tab marker. The path is
     *        opaque to the editor and can be set to an empty string for
     *        unsaved buffers or those not hosting files on disk.
     * @param f The file path to associate with this editor.
     */
    void setFilename(const QString &f) { filename = f; }

    /**
     * @brief Get the file path associated with this editor.
     * @return The file path.
     */
    QString getFilename() const { return filename; }

    /**
     * @brief Set the debugger "execution paused" line (amber bar) and move the
     *        caret to that line. Pass @<= 0 to clear only the paused-line bar.
     */
    void setCurrentLine(qint32 line);
    /** @brief Clear the debugger paused-line highlight (caret stripe unchanged). */
    void clearCurrentLineHighlight();
    /**
     * @brief Move the caret to the start of a line without changing the paused
     *        line (e.g. go-to-line).
     */
    void moveCaretToLineStart(qint32 line);
    /**
     * @brief Apply a monospace font to both editor text and gutter.
     * @param font The font to apply.
     */
    void setEditorFont(const QFont &font);

    /** @brief Refresh breakpoint markers in the gutter area. */
    void updateBreakpointMarkers();

    /** @brief Re-apply theme colors from the current preference. */
    void applyTheme();

    /**
     * @brief Return the Lua identifier under the given cursor position, or
     *        an empty string if the position is not on an identifier.
     *
     * Lua identifiers are `[A-Za-z_][A-Za-z0-9_]*`. The bracket grammar that
     * the Watch panel accepts (`a.b[1]`, `a.b["k"]`) is not synthesized here
     * — only the bare identifier at @a cursor's position is returned, mirroring the
     * "double-click to select word" affordance Qt's text editors offer.
     */
    QString luaIdentifierUnderCursor(const QTextCursor &cursor) const;

    /**
     * @brief Watch text for the editor context menu: trimmed selection if any,
     *        otherwise the Lua identifier at @a viewportPos (viewport coordinates).
     */
    QString watchExpressionForContextMenu(const QPoint &viewportPos) const;

  signals:
    /**
     * @brief Emitted when a breakpoint icon is clicked within the gutter
     *        (right margin).
     * @param toggleActive If true, the click should enable/disable the
     *        breakpoint without removing it (currently mapped to Shift+click);
     *        otherwise add or remove on plain click.
     */
    void breakpointToggled(const QString &filename, qint32 line, bool toggleActive);

    /**
     * @brief Request moving a breakpoint in @a filename from @a fromLine
     *        to @a toLine after a gutter drag-and-drop gesture.
     */
    void breakpointMoveRequested(const QString &filename, qint32 fromLine, qint32 toLine);

    /**
     * @brief Request an Edit / Disable (Enable) / Remove popup for the
     *        breakpoint at @a filename:@a line, anchored at
     *        @a globalPos.
     *
     * Emitted in two cases:
     *   1. A plain left-click on the gutter that lands on a "rich"
     *      breakpoint (one carrying a condition, hit-count target, or
     *      log message). The popup guards those user-typed extras
     *      against accidental loss; plain breakpoints keep the
     *      original add-or-remove-on-click behaviour and emit
     *      @ref breakpointToggled instead.
     *   2. A context-menu gesture (right-click on Win/Linux, Ctrl-
     *      click or two-finger trackpad tap on macOS) on any
     *      existing breakpoint, regardless of whether it carries
     *      extras. The same popup is offered, so the destructive
     *      Remove always sits behind an explicit menu choice.
     */
    void breakpointGutterMenuRequested(const QString &filename, qint32 line, const QPoint &globalPos);

  protected:
    /** @brief Update margins whenever Qt reports a size change. */
    void resizeEvent(QResizeEvent *event) override;
    /** @brief Forward Esc to LuaDebuggerDialog (keys go to viewport, not the dialog). */
    bool eventFilter(QObject *watched, QEvent *event) override;

  private slots:
    /** @brief Update margins to accommodate new block digits. */
    void updateLineNumberAreaWidth(int newBlockCount);
    /** @brief Rebuild debugger + caret line extra selections. */
    void rebuildLineHighlights();
    /** @brief Repaint the gutter when Qt issues update requests. */
    void updateLineNumberArea(const QRect &rect, int dy);

  private:
  /** @brief The widget displaying line numbers. */
    QWidget *lineNumberArea;
    /** @brief The syntax highlighter for the code editor. */
    QSyntaxHighlighter *syntaxHighlighter;
    /** 1-based line where the debugger is paused, or -1 if none. */
    qint32 pausedExecutionLine_ = -1;

    /** @brief Friend class allowing access to private members. */
    friend class LineNumberArea;

    /** @brief The filename associated with the code editor. */
    QString filename;
    /** @brief Apply editor and gutter @c QPalette for the active light/dark theme. */
    void applyEditorPalette();
};

/**
 * @brief A widget for displaying line numbers in the code editor.
 */
class LineNumberArea : public QWidget
{
  public:
    /**
     * @brief Construct the helper widget bound to a specific code view.
     * @param editor Owning code editor responsible for painting content.
     */
    LineNumberArea(LuaDebuggerCodeView *editor) : QWidget(editor), codeEditor(editor) {}

    /** @brief Size the gutter according to the editor's width requirements.
     *  @return The recommended size for the line number area.
     */
    QSize sizeHint() const override { return QSize(codeEditor->lineNumberAreaWidth(), 0); }

    /** @brief True if a breakpoint drag-and-drop is currently in progress.
     *  @return True if dragging a breakpoint, false otherwise.
     */
    bool isDraggingBreakpoint() const { return draggingBreakpoint_; }

    /** @brief Current drag target line, or -1 if not dragging.
     *  @return The target line number, or -1.
     */
    qint32 dragTargetLine() const { return dragTargetLine_; }

    /** @brief Source line being dragged, or -1 if not dragging.
     *  @return The source line number, or -1.
     */
    qint32 dragSourceLine() const { return pressedLine_; }

  protected:
    /** @brief Delegate painting back to the code view.
     *  @param event The paint event.
     */
    void paintEvent(QPaintEvent *event) override { codeEditor->lineNumberAreaPaintEvent(event); }

    /** @brief Toggle breakpoints when the gutter is clicked.
     *  @param event The mouse press event.
     */
    void mousePressEvent(QMouseEvent *event) override;

    /** @brief Track drag gestures in the breakpoint gutter.
     *  @param event The mouse move event.
     */
    void mouseMoveEvent(QMouseEvent *event) override;

    /** @brief Commit click vs drag-drop action on mouse release.
     *  @param event The mouse release event.
     */
    void mouseReleaseEvent(QMouseEvent *event) override;

    /**
     * @brief Right-click / Ctrl-click / two-finger trackpad tap on
     *        the breakpoint gutter: always pop the
     *        Edit / Disable / Remove menu when the click lands on an
     *        existing breakpoint, regardless of whether it carries
     *        extras. Clicks on bare lines are ignored.
     * @param event The context menu event.
     */
    void contextMenuEvent(QContextMenuEvent *event) override;

  private:
    /** @brief Pointer to the code editor. */
    LuaDebuggerCodeView *codeEditor;

    /**
     * @brief Map a gutter-local Y coordinate to the 1-based line
     *        number of the block under it, or @c -1 if none.
     *
     * Walks the visible-blocks geometry the same way the gutter
     * painter does. Defined as a member so it can reach through
     * @c codeEditor into @c QPlainTextEdit's protected geometry
     * accessors (legal because @c LineNumberArea is a friend of
     * @ref LuaDebuggerCodeView).
     * @param yPx The Y coordinate in pixels.
     * @return The 1-based line number, or -1.
     */
    qint32 lineAtY(qint32 yPx) const;

    /**
     * @brief Checks if there is a breakpoint at the given line.
     * @param line The line number to check.
     * @return True if a breakpoint exists, false otherwise.
     */
    bool hasBreakpointAtLine(qint32 line) const;

    /**
     * @brief Finds the nearest visible line for dropping a dragged breakpoint.
     * @param yPx The Y coordinate in pixels.
     * @param sourceLine The source line being dragged.
     * @return The nearest valid drop line number.
     */
    qint32 nearestVisibleDropLine(qint32 yPx, qint32 sourceLine) const;

    /** @brief The initial position of the mouse press. */
    QPoint pressPos_;

    /** @brief The line number where the mouse was pressed. */
    qint32 pressedLine_ = -1;

    /** @brief The current target line during a drag operation. */
    qint32 dragTargetLine_ = -1;

    /** @brief Flag indicating if a left mouse press is currently armed. */
    bool leftPressArmed_ = false;

    /** @brief Flag indicating if a breakpoint is actively being dragged. */
    bool draggingBreakpoint_ = false;

    /** @brief Flag indicating if the shift key was held during the press. */
    bool pressShiftToggle_ = false;

    /** @brief Flag indicating if a breakpoint existed at the pressed line. */
    bool pressHadBreakpoint_ = false;
};

/* ===== font_policy ===== */

/**
 * @brief Owns the dialog's font story end-to-end.
 *
 * One place to ask: "what monospace + header font should the panels use,
 * and how do we re-seat them across the open code-view tabs and watch
 * model?". Construction is widget-pointer-free so the dialog can declare
 * the policy as a value member; @ref attach is called once the
 * panel widgets exist.
 *
 * The watch widget keeps a pointer to this so it can call
 * @ref applyToPanels after a row reorder without needing a back-pointer
 * to the dialog.
 */
class LuaDebuggerFontPolicy
{
  public:
    /** @brief Default constructor for the font policy. */
    LuaDebuggerFontPolicy() = default;

    /**
     * @brief Seed the policy with the dialog's panel widgets. Idempotent.
     * @param codeTabs The code tabs widget.
     * @param variablesTree The variables tree view.
     * @param watchTree The watch tree view.
     * @param watchModel The watch standard item model.
     * @param stackTree The stack trace tree view.
     * @param fileTree The files tree view.
     * @param breakpointsTree The breakpoints tree view.
     * @param evalInputEdit The evaluation input plain text edit.
     * @param evalOutputEdit The evaluation output plain text edit.
     */
    void attach(QTabWidget *codeTabs, QTreeView *variablesTree, QTreeView *watchTree, QStandardItemModel *watchModel,
                QTreeView *stackTree, QTreeView *fileTree, QTreeView *breakpointsTree,
                QPlainTextEdit *evalInputEdit, QPlainTextEdit *evalOutputEdit);

    /** @brief Apply zoomed monospace to code editors and panel mono + regular header
     *  fonts to the side panels. Single entry point for "font preference changed".
     */
    void applyAll();

    /** @brief Apply the (optionally explicit) monospace to all open code-view tabs.
     *  When @p font is empty, falls back to the current zoomed monospace.
     *  @param font The specific font to apply, or default to current.
     */
    void applyToCodeEditors(const QFont &font = QFont());

    /** @brief Apply panel-mono bodies + regular headers to all side panels and
     *  re-sync watch QStandardItem fonts. Public so layout-changing widgets
     *  (e.g. the watch tree after a DnD reorder) can request a re-seat.
     */
    void applyToPanels();

    /** @brief Re-walk the watch model and seed each item's font to panel-mono,
     *  preserving its current bold flag (used by change-highlight).
     */
    void reapplyToWatchItemModel();

    /** @brief Effective monospace font; respects the main-app preference and the
     *  optional zoom step. Falls back to the system fixed font before main-app
     *  init.
     *  @param zoomed True to return the zoomed variant.
     *  @return The evaluated monospace font.
     */
    QFont monospaceFont(bool zoomed) const;

    /** @brief Effective regular UI font for tree-column headers.
     *  @return The standard UI font.
     */
    QFont regularFont() const;

  private:
    /** @brief Pointer to the code tabs. */
    QTabWidget *codeTabs_ = nullptr;
    /** @brief Pointer to the variables tree. */
    QTreeView *variablesTree_ = nullptr;
    /** @brief Pointer to the watch tree. */
    QTreeView *watchTree_ = nullptr;
    /** @brief Pointer to the watch model. */
    QStandardItemModel *watchModel_ = nullptr;
    /** @brief Pointer to the stack trace tree. */
    QTreeView *stackTree_ = nullptr;
    /** @brief Pointer to the files tree. */
    QTreeView *fileTree_ = nullptr;
    /** @brief Pointer to the breakpoints tree. */
    QTreeView *breakpointsTree_ = nullptr;
    /** @brief Pointer to the evaluation input editor. */
    QPlainTextEdit *evalInputEdit_ = nullptr;
    /** @brief Pointer to the evaluation output editor. */
    QPlainTextEdit *evalOutputEdit_ = nullptr;
};

/* ===== code_tabs_controller ===== */

/**
 * @brief Owns the script tab strip and the documents inside it.
 *
 * Concretely, this controller is the one place that:
 *
 *   - Creates / finds / closes script tabs (@ref loadFile, @ref onTabCloseRequested).
 *   - Tracks which buffers are dirty (@ref hasUnsavedChanges,
 *     @ref unsavedOpenScriptTabCount, @ref updateTabTextForCodeView,
 *     @ref updateWindowModifiedState).
 *   - Drives the save flow (@ref onSaveFile, @ref saveCodeView,
 *     @ref saveAllModified) and the unsaved-changes prompt
 *     (@ref ensureUnsavedChangesHandled, @ref clearAllDocumentModified).
 *   - Iterates open editors for cross-cutting passes
 *     (@ref clearAllCodeHighlights, @ref applyThemeToAllTabs).
 *
 * The dialog itself only constructs the @c QTabWidget and hands it over via
 * @ref attach; everything document-shaped lives here. Cross-controller
 * call-backs (breakpoint toggles, "Add Watch", run-to-line, the editor
 * context menu) flow through the host pointer to keep the controller's
 * public surface focused on documents.
 */
class LuaDebuggerCodeTabsController : public QObject
{
    Q_OBJECT

  public:
    /**
     * @brief Constructs a new LuaDebuggerCodeTabsController object.
     * @param host Pointer to the hosting Lua debugger dialog.
     */
    explicit LuaDebuggerCodeTabsController(LuaDebuggerDialog *host);

    /**
     * @brief Attaches the controller to the given tab widget.
     * @param tabs Pointer to the QTabWidget managing code views.
     */
    void attach(QTabWidget *tabs);

    /** @brief Borrowed reference to the tab strip. Exposed so other
     *  controllers (breakpoints, reload coordinator) can iterate the open
     *  editors without friending the dialog. The pointer lives as long
     *  as the dialog.
     *  @return Pointer to the tab widget.
     */
    QTabWidget *tabs() const { return tabs_; }

    /** @brief Directory to seed the next "Open Lua Script" dialog with.
     *  Lazily resolves to @c Documents (or @c $HOME) on first call so the
     *  controller doesn't depend on construct-time path availability.
     *  @return The last open directory path string.
     */
    QString lastOpenDirectory();

    /** @brief Remember the directory the user last opened a script from.
     *  Persists for the lifetime of the controller.
     *  @param dir The directory path.
     */
    void setLastOpenDirectory(const QString &dir);

    /**
     * @brief Load @p file_path into a code tab, creating one if necessary.
     * @param file_path The path to the file to open.
     * @return The view now hosting the file, or @c nullptr if the file does
     *         not exist on disk (no tab is created in that case).
     *
     * Wires up the signal connections the dialog needs from each new code
     * view (context menu, gutter menu, breakpoint toggle, modification,
     * cursor moves) so callers do not have to. Existing tabs are reused
     * and brought to front.
     */
    LuaDebuggerCodeView *loadFile(const QString &file_path);

    /** @brief The code editor in the active tab, or @c nullptr.
     *  @return Pointer to the currently active code view.
     */
    LuaDebuggerCodeView *currentCodeView() const;

    /** @brief How many open code tabs currently have unsaved edits.
     *  @return The number of unsaved open tabs.
     */
    qint32 unsavedOpenScriptTabCount() const;

    /** @brief True if any open tab has unsaved edits.
     *  @return True if unsaved changes exist, false otherwise.
     */
    bool hasUnsavedChanges() const;

    /**
     * @brief If any tab is modified, prompt to save / discard / cancel.
     * @param title The title for the prompt dialog.
     * @return @c false only if the user picked Cancel; @c true otherwise.
     */
    bool ensureUnsavedChangesHandled(const QString &title);

    /** @brief Mark every open document as unmodified without saving. */
    void clearAllDocumentModified();

    /** @brief Persist one editor buffer to its file path.
     *  @param view Pointer to the code view to save.
     *  @return True if saved successfully, false otherwise.
     */
    bool saveCodeView(LuaDebuggerCodeView *view);

    /** @brief Save every tab that has unsaved edits.
     *  @return @c false on the first failed write.
     */
    bool saveAllModified();

    /** @brief Update the tab label (e.g. trailing @c " *") for one editor.
     *  @param view Pointer to the code view to update.
     */
    void updateTabTextForCodeView(LuaDebuggerCodeView *view);

    /** @brief Enable Save when the current tab has unsaved edits. */
    void updateSaveActionState();

    /** @brief Reflect unsaved scripts in the window title (e.g. close hint). */
    void updateWindowModifiedState();

    /** @brief Open each initial breakpoint file once tabs are ready.
     *  @param files List of file paths to open.
     */
    void openInitialBreakpointFiles(const QVector<QString> &files);

    /** @brief Drop the current-line stripe on every open editor. */
    void clearAllCodeHighlights();

    /** @brief Re-apply the active syntax-highlight theme to every open editor. */
    void applyThemeToAllTabs();

  public slots:
    /**
     * @brief Handles a request to close a specific tab.
     * @param index The index of the tab to close.
     */
    void onTabCloseRequested(int index);

    /**
     * @brief Handles a change in the active tab.
     * @param index The new current tab index.
     */
    void onCurrentTabChanged(int index);

    /** @brief Save the active script tab (toolbar action). */
    void onSaveFile();

  private:
    /** @brief Slot wired on every new code view: bridges the gutter
     *  click / Shift-click / middle-click into the breakpoints controller
     *  and refreshes the breakpoint markers across all open tabs.
     *  @param file_path The path to the file containing the breakpoint.
     *  @param line The line number of the breakpoint.
     *  @param toggleActive True to activate the breakpoint, false to deactivate.
     */
    void onCodeViewBreakpointToggled(const QString &file_path, qint32 line, bool toggleActive);

    /** @brief The host dialog that owns this code editor. */
    LuaDebuggerDialog *host_ = nullptr;

    /** @brief The tab strip containing the code views. */
    QTabWidget *tabs_ = nullptr;

    /** @brief The directory to seed the next "Open Lua Script" dialog with. */
    QString lastOpenDirectory_;
};

#endif
