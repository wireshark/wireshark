/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <epan/prefs.h>
#include <epan/stat_groups.h>
#include <epan/frame_data.h>

// frame_data also available with this include in the original wireshark_main_window code
//#include "follow_stream_dialog.h"


#include "capture_file.h"
#include "filter_action.h"
#include "io_graph_action.h"

#include <QMainWindow>
#include <QSplitter>

class QAction;
class QMenu;
class QSplitter;
class QStackedWidget;

class DataSourceTab;
class DisplayFilterEntry;
class FieldInformation;
class FunnelAction;
class InterfaceListManager;
class MainStatusBar;
class PacketDiagram;
class PacketList;
class ProfileSwitcher;
class ProtoTree;
class WelcomePage;

typedef struct _capture_file capture_file;

/**
 * @brief The main window of the application.
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new MainWindow.
     * @param parent The parent widget, defaults to nullptr.
     */
    explicit MainWindow(QWidget *parent = nullptr);

    /**
     * @brief Destroys the MainWindow.
     */
    ~MainWindow();

    /**
     * @brief Sets the title of the main window.
     * @param title The title string to set, defaults to an empty string.
     */
    void setMainWindowTitle(QString title = QString());

    /**
     * @brief Checks if there is a current selection.
     * @return True if there is a selection, false otherwise.
     */
    bool hasSelection();

    /**
     * @brief Checks if the current selection is unique.
     * @return True if the selection is unique, false otherwise.
     */
    bool hasUniqueSelection();

    /**
     * @brief Retrieves the selected rows.
     * @param useFrameNum True to return frame numbers, false for row indices.
     * @return A list of selected row numbers or frame numbers.
     */
    QList<int> selectedRows(bool useFrameNum = false);

    /**
     * @brief Inserts a column into the view.
     * @param name The name of the column.
     * @param abbrev The abbreviation of the column.
     * @param pos The position to insert at, defaults to -1 (append).
     */
    void insertColumn(QString name, QString abbrev, int pos = -1);

    /**
     * @brief Navigates to a specific frame number.
     * @param packet_num The packet number to jump to.
     */
    void gotoFrame(int packet_num);

    /**
     * @brief Retrieves frame data for a specific row.
     * @param row The index of the row.
     * @return Pointer to the frame data for the specified row.
     */
    frame_data* frameDataForRow(int row) const;

    /**
     * @brief Retrieves the current display filter.
     * @return The filter string.
     */
    QString getFilter();

    /**
     * @brief Retrieves the main status bar.
     * @return Pointer to the MainStatusBar.
     */
    MainStatusBar *statusBar();

    /**
     * @brief Returns the local interface enumeration/statistics coordinator.
     *
     * The manager owns the live InterfaceStatistics; reach it via
     * interfaceListManager()->statistics().
     * @return Pointer to the InterfaceListManager owned by this window.
     */
    InterfaceListManager *interfaceListManager() const;

    // Used for managing custom packet menus

    /**
     * @brief Appends a custom packet menu action.
     * @param funnel_action Pointer to the funnel action to append.
     */
    void appendPacketMenu(FunnelAction *funnel_action);

    /**
     * @brief Retrieves the list of custom packet menu actions.
     * @return A list of QAction pointers representing the packet menus.
     */
    QList<QAction*> getPacketMenuActions();

    /**
     * @brief Clears the recently added custom packet menus.
     */
    void clearAddedPacketMenus();

    /**
     * @brief Adds packet menus to the given context menu.
     * @param ctx_menu The context menu to add to.
     * @param finfo_array Array of field information.
     * @return True if menus were successfully added, false otherwise.
     */
    bool addPacketMenus(QMenu * ctx_menu, GPtrArray *finfo_array);

public slots:
    /**
     * @brief Sets the display filter and performs an action.
     * @param filter The filter string.
     * @param action The filter action to perform.
     * @param filterType The type of the filter action.
     */
    void setDisplayFilter(QString filter, FilterAction::Action action, FilterAction::ActionType filterType);

    /**
     * @brief Sets and applies a new display filter to the open capture file.
     * @param new_filter New filter expression; empty string shows all packets.
     * @param force      @c true to reapply even if the filter is unchanged.
     *
     * @note The force parameter is currently ignored.
     */
    void filterPackets(QString new_filter = QString(), bool force = true);

    /**
     * @brief Shows the preferences dialog for a specific module.
     * @param module_name The name of the module.
     */
    virtual void showPreferencesDialog(QString module_name) = 0;

    /**
     * @brief Shows the IO graph dialog.
     * @param value_units The unit for the IO graph.
     * @param yfield The field to display on the y-axis.
     */
    virtual void showIOGraphDialog(io_graph_item_unit_t value_units, QString yfield) = 0;

    /**
     * @brief Shows a plot dialog.
     * @param y_field The field to display on the y-axis.
     * @param filtered True if the plot should be filtered.
     */
    virtual void showPlotDialog(const QString& y_field, bool filtered) = 0;

    /**
     * @brief Recalculates and lays out the panes.
     */
    void layoutPanes();

    /**
     * @brief Applies the most recent pane geometry settings.
     */
    void applyRecentPaneGeometry();

    /**
     * @brief Updates the UI to reflect unsaved changes.
     */
    void updateForUnsavedChanges();

    /**
     * @brief Cycles the focus through the available panes.
     * @param reverse True to cycle in reverse order.
     */
    void cyclePane(bool reverse = false);

protected:
    /**
     * @brief Enumeration for determining what to copy when items are selected.
     */
    enum CopySelected {
        /** @brief Copy all visible items. */
        CopyAllVisibleItems,
        /** @brief Copy all visible items within the selected tree. */
        CopyAllVisibleSelectedTreeItems,
        /** @brief Copy the selected description. */
        CopySelectedDescription,
        /** @brief Copy the selected field name. */
        CopySelectedFieldName,
        /** @brief Copy the selected value. */
        CopySelectedValue,
        /** @brief Copy the list formatted as text. */
        CopyListAsText,
        /** @brief Copy the list formatted as CSV. */
        CopyListAsCSV,
        /** @brief Copy the list formatted as YAML. */
        CopyListAsYAML,
        /** @brief Copy the list formatted as HTML. */
        CopyListAsHTML,
    };

    /**
     * @brief Context under which a capture file is being closed.
     */
    enum FileCloseContext {
        /** @brief Default closing context. */
        Default,
        /** @brief Closing because the application is quitting. */
        Quit,
        /** @brief Closing because the application is restarting. */
        Restart,
        /** @brief Closing to reload the file. */
        Reload,
        /** @brief Closing as part of an update. */
        Update,
        /** @brief Closing to export the file. */
        Export
    };

    /**
     * @brief Displays the welcome screen.
     */
    void showWelcome();

    /**
     * @brief Displays the main capture view.
     */
    void showCapture();

    /**
     * @brief Sets the title bar text for when a capture is in progress.
     */
    void setTitlebarForCaptureInProgress();

    /**
     * @brief Sets the window icon to indicate if a capture is in progress.
     * @param capture_in_progress True if a capture is active.
     */
    void setIconForCaptureInProgress(bool capture_in_progress);

    /**
     * @brief Sets up the menus for the active capture file.
     * @param force_disable True to force menus to be disabled.
     */
    virtual void setMenusForCaptureFile(bool force_disable = false) = 0;

    /** The active capture file. */
    CaptureFile capture_file_;

    /** List of register stat groups for the menu. */
    QList<register_stat_group_t> menu_groups_;

    /**
     * @brief Retrieves the widget corresponding to a layout pane content type.
     * @param type The layout pane content type.
     * @return Pointer to the layout widget.
     */
    QWidget* getLayoutWidget(layout_pane_content_e type);

    /** Main stacked widget for central views. */
    QStackedWidget *main_stack_;

    /** Pointer to the welcome page widget. */
    WelcomePage *welcome_page_;

    /** Master splitter for the main layout. */
    QSplitter master_split_;

    /** Extra splitter for additional pane layout. */
    QSplitter extra_split_;

    /** An empty pane widget used as a placeholder. */
    QWidget empty_pane_;

    /** Vector storing the current layout configuration. */
    QVector<unsigned> cur_layout_;

    /** Pointer to the packet list widget. */
    PacketList *packet_list_;

    /** Pointer to the protocol tree widget. */
    ProtoTree *proto_tree_;

    /** Pointer to the data source tab widget. */
    DataSourceTab *data_source_tab_;

    /** Pointer to the packet diagram widget. */
    PacketDiagram *packet_diagram_;

    /** Pointer to the display filter combo box. */
    DisplayFilterEntry *df_combo_box_;

    /** Pointer to the main status bar. */
    MainStatusBar *main_status_bar_;

    /** Pointer to the profile switcher widget. */
    ProfileSwitcher *profile_switcher_;

    /** Coordinator for local interface enumeration; owns the live statistics. */
    InterfaceListManager *interface_list_manager_;

    /** Flag indicating if the capturing title is used. */
    bool use_capturing_title_;

    /** Map of display name to iconv encoding name. */
    QMap<QString, const char *> text_codec_map_;

    // Recent captures menu support - set by subclasses

    /** Menu containing recently opened capture files. */
    QMenu *recent_captures_menu_;

    /** Action representing no recent files available. */
    QAction *no_recent_files_action_;
#if defined(Q_OS_MAC)
    /** The dock menu specific to macOS. */
    QMenu *dock_menu_;
#endif

    /**
     * @brief Populate the recent captures menu.
     * Calls openRecentCaptureFile() for each menu item action.
     */
    void populateRecentCapturesMenu();

    /**
     * @brief Handle retranslation of UI elements in MainWindow.
     *
     * This function is called when the application language changes and usually
     * handles elements like menu items and labels that need to be updated to reflect
     * the new language.
     */
    void retranslateUiElements();

    /**
     * @brief Open a capture file from the recent files menu.
     * @param filename Path to the file to open.
     */
    virtual void openRecentCaptureFile(const QString &filename) = 0;

    /**
     * @brief Tries to safely close the current capture file.
     * @param before_what Description of the operation occurring after the close.
     * @param context Context of the file closure.
     * @return True if the file closed successfully, false if the user canceled.
     */
    virtual bool tryClosingCaptureFile(QString before_what, FileCloseContext context = Default) = 0;

protected slots:
    /**
     * @brief Adds translation actions for the display filter to a menu.
     * @param copy_menu The menu to add the actions to.
     */
    void addDisplayFilterTranslationActions(QMenu *copy_menu);

    /**
     * @brief Updates the available translation actions based on filter text.
     * @param df_text The current display filter text.
     */
    void updateDisplayFilterTranslationActions(const QString &df_text);

    /**
     * @brief Updates the main title bar text.
     */
    void updateTitlebar();

    /**
     * @brief Applies a new display filter to the open capture file.
     * @param new_filter New filter expression; empty string shows all packets.
     * @param force      @c true to reapply even if the filter is unchanged.
     */
    virtual void applyFilter(QString new_filter, bool force) = 0;

private:
    /**
     * @brief Replaces variables within the window title string.
     * @param title The title containing variables.
     * @return The formatted title string.
     */
    QString replaceWindowTitleVariables(QString title);

    /**
     * @brief Finds and populates available text codecs.
     */
    void findTextCodecs();

    /** Actions for translating display filters. */
    QVector<QAction *> df_translate_actions_;

    /** The translator identifier. */
    static const char *translator_;

    /** The translated filter string. */
    static const char *translated_filter_;

private slots:
    /**
     * @brief Copies the translated display filter to the clipboard.
     */
    void copyDisplayFilterTranslation(void);

signals:
    /**
     * @brief Signal emitted to set a new capture file.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf);

    /**
     * @brief Signal emitted when a capture becomes active.
     * @param active Indicator of capture activity.
     */
    void captureActive(int active);

    /**
     * @brief Signal emitted when a field is selected.
     * @param finfo Pointer to the field information.
     */
    void fieldSelected(FieldInformation *finfo);

    /**
     * @brief Signal emitted when a field is highlighted.
     * @param finfo Pointer to the highlighted field information.
     */
    void fieldHighlight(FieldInformation *finfo);

    /**
     * @brief Signal emitted when frames are selected.
     * @param frames List of selected frame numbers.
     */
    void framesSelected(QList<int> frames);

    /**
     * @brief Signal emitted to perform a filter action.
     * @param filter The filter string.
     * @param action The filter action.
     * @param type The filter action type.
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /**
     * @brief Signal emitted when a display filter is successfully applied.
     * @param success True if the display filter was valid and applied.
     */
    void displayFilterSuccess(bool success);
};

#endif // MAINWINDOW_H
