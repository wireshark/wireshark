/********************************************************************************
** Form generated from reading UI file 'main_window.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAIN_WINDOW_H
#define UI_MAIN_WINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include "accordion_frame.h"
#include "address_editor_frame.h"
#include "column_editor_frame.h"
#include "filter_expression_frame.h"
#include "main_status_bar.h"
#include "preference_editor_frame.h"
#include "search_frame.h"
#include "welcome_page.h"
#include "wireless_timeline.h"

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QAction *actionFileOpen;
    QAction *actionFileQuit;
    QAction *actionCaptureStart;
    QAction *actionCaptureStop;
    QAction *actionFileClose;
    QAction *actionDummyNoFilesFound;
    QAction *actionHelpContents;
    QAction *actionHelpMPWireshark;
    QAction *actionHelpMPWireshark_Filter;
    QAction *actionHelpMPTShark;
    QAction *actionHelpMPRawShark;
    QAction *actionHelpMPDumpcap;
    QAction *actionHelpMPMergecap;
    QAction *actionHelpMPEditcap;
    QAction *actionHelpMPText2cap;
    QAction *actionHelpWebsite;
    QAction *actionHelpFAQ;
    QAction *actionHelpDownloads;
    QAction *actionHelpWiki;
    QAction *actionHelpSampleCaptures;
    QAction *actionHelpAbout;
    QAction *actionHelpAsk;
    QAction *actionGoNextPacket;
    QAction *actionGoPreviousPacket;
    QAction *actionGoNextConversationPacket;
    QAction *actionGoPreviousConversationPacket;
    QAction *actionGoNextHistoryPacket;
    QAction *actionGoPreviousHistoryPacket;
    QAction *actionGoFirstPacket;
    QAction *actionGoLastPacket;
    QAction *actionViewExpandSubtrees;
    QAction *actionViewCollapseSubtrees;
    QAction *actionViewExpandAll;
    QAction *actionViewCollapseAll;
    QAction *actionGoGoToPacket;
    QAction *actionFileMerge;
    QAction *actionFileImportFromHexDump;
    QAction *actionFileSave;
    QAction *actionFileSaveAs;
    QAction *actionFileExportPackets;
    QAction *actionFileExportPacketBytes;
    QAction *actionFileExportTLSSessionKeys;
    QAction *actionFilePrint;
    QAction *actionFileSetListFiles;
    QAction *actionFileSetNextFile;
    QAction *actionFileSetPreviousFile;
    QAction *actionViewReload;
    QAction *actionViewReload_as_File_Format_or_Capture;
    QAction *actionCaptureOptions;
    QAction *actionCaptureCaptureFilters;
    QAction *actionCaptureRefreshInterfaces;
    QAction *actionCaptureRestart;
    QAction *actionFileExportAsPlainText;
    QAction *actionFileExportAsCSV;
    QAction *actionFileExportAsCArrays;
    QAction *actionFileExportAsPSML;
    QAction *actionFileExportAsPDML;
    QAction *actionFileExportAsJSON;
    QAction *actionEditCopyDescription;
    QAction *actionCopyAllVisibleItems;
    QAction *actionCopyAllVisibleSelectedTreeItems;
    QAction *actionEditCopyFieldName;
    QAction *actionEditCopyValue;
    QAction *actionEditCopyAsFilter;
    QAction *actionAnalyzeAAFSelected;
    QAction *actionAnalyzeAAFNotSelected;
    QAction *actionAnalyzeAAFAndSelected;
    QAction *actionAnalyzeAAFOrSelected;
    QAction *actionAnalyzeAAFAndNotSelected;
    QAction *actionAnalyzeAAFOrNotSelected;
    QAction *actionAnalyzePAFSelected;
    QAction *actionAnalyzePAFNotSelected;
    QAction *actionAnalyzePAFAndSelected;
    QAction *actionAnalyzePAFOrSelected;
    QAction *actionAnalyzePAFAndNotSelected;
    QAction *actionAnalyzePAFOrNotSelected;
    QAction *actionAnalyzeDisplayFilters;
    QAction *actionAnalyzeDisplayFilterMacros;
    QAction *actionAnalyzeCreateAColumn;
    QAction *actionEditFindPacket;
    QAction *actionEditFindNext;
    QAction *actionEditFindPrevious;
    QAction *actionEditMarkPacket;
    QAction *actionEditMarkAllDisplayed;
    QAction *actionEditUnmarkAllDisplayed;
    QAction *actionEditNextMark;
    QAction *actionEditPreviousMark;
    QAction *actionEditIgnorePacket;
    QAction *actionEditIgnoreAllDisplayed;
    QAction *actionEditUnignoreAllDisplayed;
    QAction *actionEditSetTimeReference;
    QAction *actionEditUnsetAllTimeReferences;
    QAction *actionEditNextTimeReference;
    QAction *actionEditPreviousTimeReference;
    QAction *actionEditTimeShift;
    QAction *actionEditPacketComment;
    QAction *actionDeleteAllPacketComments;
    QAction *actionEditConfigurationProfiles;
    QAction *actionEditPreferences;
    QAction *actionStatisticsCaptureFileProperties;
    QAction *actionStatisticsProtocolHierarchy;
    QAction *actionHelpMPCapinfos;
    QAction *actionHelpMPReordercap;
    QAction *actionStatisticsTcpStreamStevens;
    QAction *actionStatisticsTcpStreamThroughput;
    QAction *actionStatisticsTcpStreamRoundTripTime;
    QAction *actionStatisticsTcpStreamWindowScaling;
    QAction *actionAnalyzeFollowTCPStream;
    QAction *actionAnalyzeFollowUDPStream;
    QAction *actionAnalyzeFollowTLSStream;
    QAction *actionAnalyzeFollowHTTPStream;
    QAction *actionStatisticsTcpStreamTcptrace;
    QAction *actionSCTPAnalyseThisAssociation;
    QAction *actionSCTPShowAllAssociations;
    QAction *actionStatisticsFlowGraph;
    QAction *actionStatisticsANCP;
    QAction *actionStatisticsBACappInstanceId;
    QAction *actionStatisticsBACappIP;
    QAction *actionStatisticsBACappObjectId;
    QAction *actionStatisticsBACappService;
    QAction *actionStatisticsCollectd;
    QAction *actionStatisticsDNS;
    QAction *actionStatisticsHART_IP;
    QAction *actionStatisticsHpfeeds;
    QAction *actionStatisticsHTTP2;
    QAction *actionStatisticsHTTPPacketCounter;
    QAction *actionStatisticsHTTPRequests;
    QAction *actionStatisticsHTTPLoadDistribution;
    QAction *actionStatisticsHTTPRequestSequences;
    QAction *actionStatisticsPacketLengths;
    QAction *actionStatisticsSametime;
    QAction *actionTelephonyISUPMessages;
    QAction *actionTelephonyOsmuxPacketCounter;
    QAction *actionTelephonyRTSPPacketCounter;
    QAction *actionTelephonySMPPOperations;
    QAction *actionTelephonyUCPMessages;
    QAction *actionAnalyzeDecodeAs;
    QAction *actionAnalyzeReloadLuaPlugins;
    QAction *action29West;
    QAction *actionStatistics29WestTopics_Advertisements_by_Topic;
    QAction *actionStatistics29WestTopics_Advertisements_by_Source;
    QAction *actionStatistics29WestTopics_Advertisements_by_Transport;
    QAction *actionStatistics29WestTopics_Queries_by_Topic;
    QAction *actionStatistics29WestTopics_Queries_by_Receiver;
    QAction *actionStatistics29WestTopics_Wildcard_Queries_by_Pattern;
    QAction *actionStatistics29WestTopics_Wildcard_Queries_by_Receiver;
    QAction *actionStatistics29WestQueues_Advertisements_by_Queue;
    QAction *actionStatistics29WestQueues_Advertisements_by_Source;
    QAction *actionStatistics29WestQueues_Queries_by_Queue;
    QAction *actionStatistics29WestQueues_Queries_by_Receiver;
    QAction *actionStatistics29WestUIM_Streams;
    QAction *actionStatistics29WestLBTRM;
    QAction *actionStatistics29WestLBTRU;
    QAction *actionSCTPFilterThisAssociation;
    QAction *actionFileExportPDU;
    QAction *actionStatisticsIOGraph;
    QAction *actionViewMainToolbar;
    QAction *actionViewFilterToolbar;
    QAction *actionStatisticsConversations;
    QAction *actionStatisticsEndpoints;
    QAction *actionViewColorizePacketList;
    QAction *actionViewZoomIn;
    QAction *actionViewZoomOut;
    QAction *actionViewNormalSize;
    QAction *actionViewResetLayout;
    QAction *actionViewResizeColumns;
    QAction *actionViewTimeDisplayFormatDateYMDandTimeOfDay;
    QAction *actionViewTimeDisplayFormatDateYDOYandTimeOfDay;
    QAction *actionViewTimeDisplayFormatTimeOfDay;
    QAction *actionViewTimeDisplayFormatSecondsSinceEpoch;
    QAction *actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture;
    QAction *actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket;
    QAction *actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket;
    QAction *actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay;
    QAction *actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay;
    QAction *actionViewTimeDisplayFormatUTCTimeOfDay;
    QAction *actionViewTimeDisplayFormatPrecisionAutomatic;
    QAction *actionViewTimeDisplayFormatPrecisionSeconds;
    QAction *actionViewTimeDisplayFormatPrecisionDeciseconds;
    QAction *actionViewTimeDisplayFormatPrecisionCentiseconds;
    QAction *actionViewTimeDisplayFormatPrecisionMilliseconds;
    QAction *actionViewTimeDisplayFormatPrecisionMicroseconds;
    QAction *actionViewTimeDisplayFormatPrecisionNanoseconds;
    QAction *actionViewTimeDisplaySecondsWithHoursAndMinutes;
    QAction *actionViewNameResolutionPhysical;
    QAction *actionViewNameResolutionNetwork;
    QAction *actionViewNameResolutionTransport;
    QAction *actionViewWirelessToolbar;
    QAction *actionViewStatusBar;
    QAction *actionViewPacketList;
    QAction *actionViewPacketDetails;
    QAction *actionViewPacketBytes;
    QAction *actionViewInternalsConversationHashTables;
    QAction *actionViewInternalsDissectorTables;
    QAction *actionViewInternalsSupportedProtocols;
    QAction *actionTelephonyGsmMapSummary;
    QAction *actionTelephonyLteMacStatistics;
    QAction *actionTelephonyLteRlcStatistics;
    QAction *actionTelephonyLteRlcGraph;
    QAction *actionTelephonyMtp3Summary;
    QAction *actionTelephonyVoipCalls;
    QAction *actionTelephonySipFlows;
    QAction *actionTelephonyRTPStreams;
    QAction *actionViewColoringRules;
    QAction *actionBluetoothATT_Server_Attributes;
    QAction *actionBluetoothDevices;
    QAction *actionBluetoothHCI_Summary;
    QAction *actionViewShowPacketInNewWindow;
    QAction *actionContextShowLinkedPacketInNewWindow;
    QAction *actionGoAutoScroll;
    QAction *actionAnalyzeExpertInfo;
    QAction *actionDisplayFilterExpression;
    QAction *actionStatistics_REGISTER_STAT_GROUP_UNSORTED;
    QAction *actionTelephonyANSIPlaceholder;
    QAction *actionTelephonyGSMPlaceholder;
    QAction *actionTelephonyLTEPlaceholder;
    QAction *actionTelephonyMTP3Placeholder;
    QAction *actionStatisticsResolvedAddresses;
    QAction *actionViewColorizeConversation1;
    QAction *actionViewColorizeConversation2;
    QAction *actionViewColorizeConversation3;
    QAction *actionViewColorizeConversation4;
    QAction *actionViewColorizeConversation5;
    QAction *actionViewColorizeConversation6;
    QAction *actionViewColorizeConversation7;
    QAction *actionViewColorizeConversation8;
    QAction *actionViewColorizeConversation9;
    QAction *actionViewColorizeConversation10;
    QAction *actionViewColorizeNewColoringRule;
    QAction *actionViewColorizeResetColorization;
    QAction *actionTelephonyRTPStreamAnalysis;
    QAction *actionTelephonyIax2StreamAnalysis;
    QAction *actionViewEditResolvedName;
    QAction *actionAnalyzeEnabledProtocols;
    QAction *actionAnalyzeShowPacketBytes;
    QAction *actionContextWikiProtocolPage;
    QAction *actionContextFilterFieldReference;
    QAction *actionGoGoToLinkedPacket;
    QAction *actionStatisticsUdpMulticastStreams;
    QAction *actionWirelessWlanStatistics;
    QAction *actionNewDisplayFilterExpression;
    QAction *actionToolsFirewallAclRules;
    QAction *actionViewFullScreen;
    QWidget *centralWidget;
    QVBoxLayout *verticalLayout;
    AccordionFrame *goToFrame;
    QHBoxLayout *goToHB;
    QSpacerItem *horizontalSpacer;
    QLabel *goToPacketLabel;
    QLineEdit *goToLineEdit;
    QPushButton *goToGo;
    QPushButton *goToCancel;
    SearchFrame *searchFrame;
    AddressEditorFrame *addressEditorFrame;
    ColumnEditorFrame *columnEditorFrame;
    PreferenceEditorFrame *preferenceEditorFrame;
    FilterExpressionFrame *filterExpressionFrame;
    WirelessTimeline *wirelessTimelineWidget;
    QStackedWidget *mainStack;
    WelcomePage *welcomePage;
    QMenuBar *menuBar;
    QMenu *menuFile;
    QMenu *menuOpenRecentCaptureFile;
    QMenu *menuFileSet;
    QMenu *menuFileExportPacketDissections;
    QMenu *menuFileExportObjects;
    QMenu *menuCapture;
    QMenu *menuHelp;
    QMenu *menuHelpManualPages;
    QMenu *menuGo;
    QMenu *menuView;
    QMenu *menuInterfaceToolbars;
    QMenu *menuZoom;
    QMenu *menuTime_Display_Format;
    QMenu *menuName_Resolution;
    QMenu *menuColorizeConversation;
    QMenu *menuInternals;
    QMenu *menuAdditionalToolbars;
    QMenu *menuAnalyze;
    QMenu *menuApplyAsFilter;
    QMenu *menuPrepareAFilter;
    QMenu *menuSCTP;
    QMenu *menuFollow;
    QMenu *menuConversationFilter;
    QMenu *menuStatistics;
    QMenu *menuTcpStreamGraphs;
    QMenu *menuBACnet;
    QMenu *menuHTTP;
    QMenu *menu29West;
    QMenu *menu29WestTopics;
    QMenu *menu29WestQueues;
    QMenu *menu29WestUIM;
    QMenu *menuServiceResponseTime;
    QMenu *menuTelephony;
    QMenu *menuRTSP;
    QMenu *menuRTP;
    QMenu *menuTelephonySCTP;
    QMenu *menuANSI;
    QMenu *menuGSM;
    QMenu *menuLTE;
    QMenu *menuMTP3;
    QMenu *menuOsmux;
    QMenu *menuEdit;
    QMenu *menuEditCopy;
    QMenu *menuWireless;
    QMenu *menuTools;
    QToolBar *mainToolBar;
    MainStatusBar *statusBar;
    QToolBar *displayFilterToolBar;
    QToolBar *wirelessToolBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(960, 768);
        MainWindow->setAcceptDrops(true);
        MainWindow->setUnifiedTitleAndToolBarOnMac(true);
        actionFileOpen = new QAction(MainWindow);
        actionFileOpen->setObjectName(QString::fromUtf8("actionFileOpen"));
#ifndef QT_NO_SHORTCUT
        actionFileOpen->setShortcut(QString::fromUtf8("Ctrl+O"));
#endif // QT_NO_SHORTCUT
        actionFileOpen->setIconVisibleInMenu(false);
        actionFileQuit = new QAction(MainWindow);
        actionFileQuit->setObjectName(QString::fromUtf8("actionFileQuit"));
#ifndef QT_NO_SHORTCUT
        actionFileQuit->setShortcut(QString::fromUtf8("Ctrl+Q"));
#endif // QT_NO_SHORTCUT
        actionFileQuit->setMenuRole(QAction::QuitRole);
        actionCaptureStart = new QAction(MainWindow);
        actionCaptureStart->setObjectName(QString::fromUtf8("actionCaptureStart"));
        actionCaptureStart->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionCaptureStart->setShortcut(QString::fromUtf8("Ctrl+E"));
#endif // QT_NO_SHORTCUT
        actionCaptureStop = new QAction(MainWindow);
        actionCaptureStop->setObjectName(QString::fromUtf8("actionCaptureStop"));
#ifndef QT_NO_SHORTCUT
        actionCaptureStop->setShortcut(QString::fromUtf8("Ctrl+E"));
#endif // QT_NO_SHORTCUT
        actionFileClose = new QAction(MainWindow);
        actionFileClose->setObjectName(QString::fromUtf8("actionFileClose"));
#ifndef QT_NO_SHORTCUT
        actionFileClose->setShortcut(QString::fromUtf8("Ctrl+W"));
#endif // QT_NO_SHORTCUT
        actionFileClose->setIconVisibleInMenu(false);
        actionDummyNoFilesFound = new QAction(MainWindow);
        actionDummyNoFilesFound->setObjectName(QString::fromUtf8("actionDummyNoFilesFound"));
        actionDummyNoFilesFound->setEnabled(false);
        actionHelpContents = new QAction(MainWindow);
        actionHelpContents->setObjectName(QString::fromUtf8("actionHelpContents"));
#ifndef QT_NO_SHORTCUT
        actionHelpContents->setShortcut(QString::fromUtf8("F1"));
#endif // QT_NO_SHORTCUT
        actionHelpContents->setIconVisibleInMenu(true);
        actionHelpMPWireshark = new QAction(MainWindow);
        actionHelpMPWireshark->setObjectName(QString::fromUtf8("actionHelpMPWireshark"));
        actionHelpMPWireshark_Filter = new QAction(MainWindow);
        actionHelpMPWireshark_Filter->setObjectName(QString::fromUtf8("actionHelpMPWireshark_Filter"));
        actionHelpMPTShark = new QAction(MainWindow);
        actionHelpMPTShark->setObjectName(QString::fromUtf8("actionHelpMPTShark"));
        actionHelpMPRawShark = new QAction(MainWindow);
        actionHelpMPRawShark->setObjectName(QString::fromUtf8("actionHelpMPRawShark"));
        actionHelpMPDumpcap = new QAction(MainWindow);
        actionHelpMPDumpcap->setObjectName(QString::fromUtf8("actionHelpMPDumpcap"));
        actionHelpMPMergecap = new QAction(MainWindow);
        actionHelpMPMergecap->setObjectName(QString::fromUtf8("actionHelpMPMergecap"));
        actionHelpMPEditcap = new QAction(MainWindow);
        actionHelpMPEditcap->setObjectName(QString::fromUtf8("actionHelpMPEditcap"));
        actionHelpMPText2cap = new QAction(MainWindow);
        actionHelpMPText2cap->setObjectName(QString::fromUtf8("actionHelpMPText2cap"));
        actionHelpWebsite = new QAction(MainWindow);
        actionHelpWebsite->setObjectName(QString::fromUtf8("actionHelpWebsite"));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/menu/help/wsicon16.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionHelpWebsite->setIcon(icon);
        actionHelpFAQ = new QAction(MainWindow);
        actionHelpFAQ->setObjectName(QString::fromUtf8("actionHelpFAQ"));
        actionHelpDownloads = new QAction(MainWindow);
        actionHelpDownloads->setObjectName(QString::fromUtf8("actionHelpDownloads"));
        actionHelpWiki = new QAction(MainWindow);
        actionHelpWiki->setObjectName(QString::fromUtf8("actionHelpWiki"));
        actionHelpWiki->setIcon(icon);
        actionHelpWiki->setIconVisibleInMenu(true);
        actionHelpSampleCaptures = new QAction(MainWindow);
        actionHelpSampleCaptures->setObjectName(QString::fromUtf8("actionHelpSampleCaptures"));
        actionHelpAbout = new QAction(MainWindow);
        actionHelpAbout->setObjectName(QString::fromUtf8("actionHelpAbout"));
        actionHelpAbout->setMenuRole(QAction::AboutRole);
        actionHelpAsk = new QAction(MainWindow);
        actionHelpAsk->setObjectName(QString::fromUtf8("actionHelpAsk"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/menu/help/wsicon-ask.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionHelpAsk->setIcon(icon1);
        actionHelpAsk->setIconVisibleInMenu(true);
        actionGoNextPacket = new QAction(MainWindow);
        actionGoNextPacket->setObjectName(QString::fromUtf8("actionGoNextPacket"));
#ifndef QT_NO_SHORTCUT
        actionGoNextPacket->setShortcut(QString::fromUtf8("Ctrl+Down"));
#endif // QT_NO_SHORTCUT
        actionGoPreviousPacket = new QAction(MainWindow);
        actionGoPreviousPacket->setObjectName(QString::fromUtf8("actionGoPreviousPacket"));
#ifndef QT_NO_SHORTCUT
        actionGoPreviousPacket->setShortcut(QString::fromUtf8("Ctrl+Up"));
#endif // QT_NO_SHORTCUT
        actionGoNextConversationPacket = new QAction(MainWindow);
        actionGoNextConversationPacket->setObjectName(QString::fromUtf8("actionGoNextConversationPacket"));
#ifndef QT_NO_SHORTCUT
        actionGoNextConversationPacket->setShortcut(QString::fromUtf8("Ctrl+."));
#endif // QT_NO_SHORTCUT
        actionGoPreviousConversationPacket = new QAction(MainWindow);
        actionGoPreviousConversationPacket->setObjectName(QString::fromUtf8("actionGoPreviousConversationPacket"));
#ifndef QT_NO_SHORTCUT
        actionGoPreviousConversationPacket->setShortcut(QString::fromUtf8("Ctrl+,"));
#endif // QT_NO_SHORTCUT
        actionGoNextHistoryPacket = new QAction(MainWindow);
        actionGoNextHistoryPacket->setObjectName(QString::fromUtf8("actionGoNextHistoryPacket"));
#ifndef QT_NO_SHORTCUT
        actionGoNextHistoryPacket->setShortcut(QString::fromUtf8("Alt+Right"));
#endif // QT_NO_SHORTCUT
        actionGoPreviousHistoryPacket = new QAction(MainWindow);
        actionGoPreviousHistoryPacket->setObjectName(QString::fromUtf8("actionGoPreviousHistoryPacket"));
#ifndef QT_NO_SHORTCUT
        actionGoPreviousHistoryPacket->setShortcut(QString::fromUtf8("Alt+Left"));
#endif // QT_NO_SHORTCUT
        actionGoFirstPacket = new QAction(MainWindow);
        actionGoFirstPacket->setObjectName(QString::fromUtf8("actionGoFirstPacket"));
#ifndef QT_NO_SHORTCUT
        actionGoFirstPacket->setShortcut(QString::fromUtf8("Ctrl+Home"));
#endif // QT_NO_SHORTCUT
        actionGoLastPacket = new QAction(MainWindow);
        actionGoLastPacket->setObjectName(QString::fromUtf8("actionGoLastPacket"));
#ifndef QT_NO_SHORTCUT
        actionGoLastPacket->setShortcut(QString::fromUtf8("Ctrl+End"));
#endif // QT_NO_SHORTCUT
        actionViewExpandSubtrees = new QAction(MainWindow);
        actionViewExpandSubtrees->setObjectName(QString::fromUtf8("actionViewExpandSubtrees"));
        actionViewExpandSubtrees->setEnabled(false);
#ifndef QT_NO_SHORTCUT
        actionViewExpandSubtrees->setShortcut(QString::fromUtf8("Shift+Right"));
#endif // QT_NO_SHORTCUT
        actionViewCollapseSubtrees = new QAction(MainWindow);
        actionViewCollapseSubtrees->setObjectName(QString::fromUtf8("actionViewCollapseSubtrees"));
        actionViewCollapseSubtrees->setEnabled(false);
#ifndef QT_NO_SHORTCUT
        actionViewCollapseSubtrees->setShortcut(QString::fromUtf8("Shift+Left"));
#endif // QT_NO_SHORTCUT
        actionViewExpandAll = new QAction(MainWindow);
        actionViewExpandAll->setObjectName(QString::fromUtf8("actionViewExpandAll"));
#ifndef QT_NO_SHORTCUT
        actionViewExpandAll->setShortcut(QString::fromUtf8("Ctrl+Right"));
#endif // QT_NO_SHORTCUT
        actionViewCollapseAll = new QAction(MainWindow);
        actionViewCollapseAll->setObjectName(QString::fromUtf8("actionViewCollapseAll"));
#ifndef QT_NO_SHORTCUT
        actionViewCollapseAll->setShortcut(QString::fromUtf8("Ctrl+Left"));
#endif // QT_NO_SHORTCUT
        actionGoGoToPacket = new QAction(MainWindow);
        actionGoGoToPacket->setObjectName(QString::fromUtf8("actionGoGoToPacket"));
        actionGoGoToPacket->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionGoGoToPacket->setShortcut(QString::fromUtf8("Ctrl+G"));
#endif // QT_NO_SHORTCUT
        actionFileMerge = new QAction(MainWindow);
        actionFileMerge->setObjectName(QString::fromUtf8("actionFileMerge"));
        actionFileImportFromHexDump = new QAction(MainWindow);
        actionFileImportFromHexDump->setObjectName(QString::fromUtf8("actionFileImportFromHexDump"));
        actionFileSave = new QAction(MainWindow);
        actionFileSave->setObjectName(QString::fromUtf8("actionFileSave"));
#ifndef QT_NO_SHORTCUT
        actionFileSave->setShortcut(QString::fromUtf8("Ctrl+S"));
#endif // QT_NO_SHORTCUT
        actionFileSave->setIconVisibleInMenu(false);
        actionFileSaveAs = new QAction(MainWindow);
        actionFileSaveAs->setObjectName(QString::fromUtf8("actionFileSaveAs"));
#ifndef QT_NO_SHORTCUT
        actionFileSaveAs->setShortcut(QString::fromUtf8("Ctrl+Shift+S"));
#endif // QT_NO_SHORTCUT
        actionFileExportPackets = new QAction(MainWindow);
        actionFileExportPackets->setObjectName(QString::fromUtf8("actionFileExportPackets"));
        actionFileExportPacketBytes = new QAction(MainWindow);
        actionFileExportPacketBytes->setObjectName(QString::fromUtf8("actionFileExportPacketBytes"));
#ifndef QT_NO_SHORTCUT
        actionFileExportPacketBytes->setShortcut(QString::fromUtf8("Ctrl+Shift+X"));
#endif // QT_NO_SHORTCUT
        actionFileExportTLSSessionKeys = new QAction(MainWindow);
        actionFileExportTLSSessionKeys->setObjectName(QString::fromUtf8("actionFileExportTLSSessionKeys"));
        actionFilePrint = new QAction(MainWindow);
        actionFilePrint->setObjectName(QString::fromUtf8("actionFilePrint"));
#ifndef QT_NO_SHORTCUT
        actionFilePrint->setShortcut(QString::fromUtf8("Ctrl+P"));
#endif // QT_NO_SHORTCUT
        actionFileSetListFiles = new QAction(MainWindow);
        actionFileSetListFiles->setObjectName(QString::fromUtf8("actionFileSetListFiles"));
        actionFileSetNextFile = new QAction(MainWindow);
        actionFileSetNextFile->setObjectName(QString::fromUtf8("actionFileSetNextFile"));
        actionFileSetPreviousFile = new QAction(MainWindow);
        actionFileSetPreviousFile->setObjectName(QString::fromUtf8("actionFileSetPreviousFile"));
        actionViewReload = new QAction(MainWindow);
        actionViewReload->setObjectName(QString::fromUtf8("actionViewReload"));
#ifndef QT_NO_SHORTCUT
        actionViewReload->setShortcut(QString::fromUtf8("Ctrl+R"));
#endif // QT_NO_SHORTCUT
        actionViewReload->setIconVisibleInMenu(true);
        actionViewReload_as_File_Format_or_Capture = new QAction(MainWindow);
        actionViewReload_as_File_Format_or_Capture->setObjectName(QString::fromUtf8("actionViewReload_as_File_Format_or_Capture"));
#ifndef QT_NO_SHORTCUT
        actionViewReload_as_File_Format_or_Capture->setShortcut(QString::fromUtf8("Ctrl+Shift+F"));
#endif // QT_NO_SHORTCUT
        actionCaptureOptions = new QAction(MainWindow);
        actionCaptureOptions->setObjectName(QString::fromUtf8("actionCaptureOptions"));
#ifndef QT_NO_SHORTCUT
        actionCaptureOptions->setShortcut(QString::fromUtf8("Ctrl+K"));
#endif // QT_NO_SHORTCUT
        actionCaptureOptions->setMenuRole(QAction::NoRole);
        actionCaptureCaptureFilters = new QAction(MainWindow);
        actionCaptureCaptureFilters->setObjectName(QString::fromUtf8("actionCaptureCaptureFilters"));
        actionCaptureRefreshInterfaces = new QAction(MainWindow);
        actionCaptureRefreshInterfaces->setObjectName(QString::fromUtf8("actionCaptureRefreshInterfaces"));
#ifndef QT_NO_SHORTCUT
        actionCaptureRefreshInterfaces->setShortcut(QString::fromUtf8("F5"));
#endif // QT_NO_SHORTCUT
        actionCaptureRestart = new QAction(MainWindow);
        actionCaptureRestart->setObjectName(QString::fromUtf8("actionCaptureRestart"));
#ifndef QT_NO_SHORTCUT
        actionCaptureRestart->setShortcut(QString::fromUtf8("Ctrl+R"));
#endif // QT_NO_SHORTCUT
        actionFileExportAsPlainText = new QAction(MainWindow);
        actionFileExportAsPlainText->setObjectName(QString::fromUtf8("actionFileExportAsPlainText"));
        actionFileExportAsCSV = new QAction(MainWindow);
        actionFileExportAsCSV->setObjectName(QString::fromUtf8("actionFileExportAsCSV"));
        actionFileExportAsCArrays = new QAction(MainWindow);
        actionFileExportAsCArrays->setObjectName(QString::fromUtf8("actionFileExportAsCArrays"));
        actionFileExportAsPSML = new QAction(MainWindow);
        actionFileExportAsPSML->setObjectName(QString::fromUtf8("actionFileExportAsPSML"));
        actionFileExportAsPDML = new QAction(MainWindow);
        actionFileExportAsPDML->setObjectName(QString::fromUtf8("actionFileExportAsPDML"));
        actionFileExportAsJSON = new QAction(MainWindow);
        actionFileExportAsJSON->setObjectName(QString::fromUtf8("actionFileExportAsJSON"));
        actionEditCopyDescription = new QAction(MainWindow);
        actionEditCopyDescription->setObjectName(QString::fromUtf8("actionEditCopyDescription"));
#ifndef QT_NO_SHORTCUT
        actionEditCopyDescription->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+D"));
#endif // QT_NO_SHORTCUT
        actionCopyAllVisibleItems = new QAction(MainWindow);
        actionCopyAllVisibleItems->setObjectName(QString::fromUtf8("actionCopyAllVisibleItems"));
#ifndef QT_NO_SHORTCUT
        actionCopyAllVisibleItems->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+A"));
#endif // QT_NO_SHORTCUT
        actionCopyAllVisibleSelectedTreeItems = new QAction(MainWindow);
        actionCopyAllVisibleSelectedTreeItems->setObjectName(QString::fromUtf8("actionCopyAllVisibleSelectedTreeItems"));
        actionEditCopyFieldName = new QAction(MainWindow);
        actionEditCopyFieldName->setObjectName(QString::fromUtf8("actionEditCopyFieldName"));
#ifndef QT_NO_SHORTCUT
        actionEditCopyFieldName->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+F"));
#endif // QT_NO_SHORTCUT
        actionEditCopyValue = new QAction(MainWindow);
        actionEditCopyValue->setObjectName(QString::fromUtf8("actionEditCopyValue"));
#ifndef QT_NO_SHORTCUT
        actionEditCopyValue->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+V"));
#endif // QT_NO_SHORTCUT
        actionEditCopyAsFilter = new QAction(MainWindow);
        actionEditCopyAsFilter->setObjectName(QString::fromUtf8("actionEditCopyAsFilter"));
#ifndef QT_NO_SHORTCUT
        actionEditCopyAsFilter->setShortcut(QString::fromUtf8("Ctrl+Shift+C"));
#endif // QT_NO_SHORTCUT
        actionAnalyzeAAFSelected = new QAction(MainWindow);
        actionAnalyzeAAFSelected->setObjectName(QString::fromUtf8("actionAnalyzeAAFSelected"));
        actionAnalyzeAAFNotSelected = new QAction(MainWindow);
        actionAnalyzeAAFNotSelected->setObjectName(QString::fromUtf8("actionAnalyzeAAFNotSelected"));
        actionAnalyzeAAFAndSelected = new QAction(MainWindow);
        actionAnalyzeAAFAndSelected->setObjectName(QString::fromUtf8("actionAnalyzeAAFAndSelected"));
        actionAnalyzeAAFOrSelected = new QAction(MainWindow);
        actionAnalyzeAAFOrSelected->setObjectName(QString::fromUtf8("actionAnalyzeAAFOrSelected"));
        actionAnalyzeAAFAndNotSelected = new QAction(MainWindow);
        actionAnalyzeAAFAndNotSelected->setObjectName(QString::fromUtf8("actionAnalyzeAAFAndNotSelected"));
        actionAnalyzeAAFOrNotSelected = new QAction(MainWindow);
        actionAnalyzeAAFOrNotSelected->setObjectName(QString::fromUtf8("actionAnalyzeAAFOrNotSelected"));
        actionAnalyzePAFSelected = new QAction(MainWindow);
        actionAnalyzePAFSelected->setObjectName(QString::fromUtf8("actionAnalyzePAFSelected"));
        actionAnalyzePAFNotSelected = new QAction(MainWindow);
        actionAnalyzePAFNotSelected->setObjectName(QString::fromUtf8("actionAnalyzePAFNotSelected"));
        actionAnalyzePAFAndSelected = new QAction(MainWindow);
        actionAnalyzePAFAndSelected->setObjectName(QString::fromUtf8("actionAnalyzePAFAndSelected"));
        actionAnalyzePAFOrSelected = new QAction(MainWindow);
        actionAnalyzePAFOrSelected->setObjectName(QString::fromUtf8("actionAnalyzePAFOrSelected"));
        actionAnalyzePAFAndNotSelected = new QAction(MainWindow);
        actionAnalyzePAFAndNotSelected->setObjectName(QString::fromUtf8("actionAnalyzePAFAndNotSelected"));
        actionAnalyzePAFOrNotSelected = new QAction(MainWindow);
        actionAnalyzePAFOrNotSelected->setObjectName(QString::fromUtf8("actionAnalyzePAFOrNotSelected"));
        actionAnalyzeDisplayFilters = new QAction(MainWindow);
        actionAnalyzeDisplayFilters->setObjectName(QString::fromUtf8("actionAnalyzeDisplayFilters"));
        actionAnalyzeDisplayFilterMacros = new QAction(MainWindow);
        actionAnalyzeDisplayFilterMacros->setObjectName(QString::fromUtf8("actionAnalyzeDisplayFilterMacros"));
        actionAnalyzeCreateAColumn = new QAction(MainWindow);
        actionAnalyzeCreateAColumn->setObjectName(QString::fromUtf8("actionAnalyzeCreateAColumn"));
#ifndef QT_NO_SHORTCUT
        actionAnalyzeCreateAColumn->setShortcut(QString::fromUtf8("Ctrl+Shift+I"));
#endif // QT_NO_SHORTCUT
        actionEditFindPacket = new QAction(MainWindow);
        actionEditFindPacket->setObjectName(QString::fromUtf8("actionEditFindPacket"));
#ifndef QT_NO_SHORTCUT
        actionEditFindPacket->setShortcut(QString::fromUtf8("Ctrl+F"));
#endif // QT_NO_SHORTCUT
        actionEditFindNext = new QAction(MainWindow);
        actionEditFindNext->setObjectName(QString::fromUtf8("actionEditFindNext"));
#ifndef QT_NO_SHORTCUT
        actionEditFindNext->setShortcut(QString::fromUtf8("Ctrl+N"));
#endif // QT_NO_SHORTCUT
        actionEditFindPrevious = new QAction(MainWindow);
        actionEditFindPrevious->setObjectName(QString::fromUtf8("actionEditFindPrevious"));
#ifndef QT_NO_SHORTCUT
        actionEditFindPrevious->setShortcut(QString::fromUtf8("Ctrl+B"));
#endif // QT_NO_SHORTCUT
        actionEditMarkPacket = new QAction(MainWindow);
        actionEditMarkPacket->setObjectName(QString::fromUtf8("actionEditMarkPacket"));
#ifndef QT_NO_SHORTCUT
        actionEditMarkPacket->setShortcut(QString::fromUtf8("Ctrl+M"));
#endif // QT_NO_SHORTCUT
        actionEditMarkAllDisplayed = new QAction(MainWindow);
        actionEditMarkAllDisplayed->setObjectName(QString::fromUtf8("actionEditMarkAllDisplayed"));
#ifndef QT_NO_SHORTCUT
        actionEditMarkAllDisplayed->setShortcut(QString::fromUtf8("Ctrl+Shift+M"));
#endif // QT_NO_SHORTCUT
        actionEditUnmarkAllDisplayed = new QAction(MainWindow);
        actionEditUnmarkAllDisplayed->setObjectName(QString::fromUtf8("actionEditUnmarkAllDisplayed"));
#ifndef QT_NO_SHORTCUT
        actionEditUnmarkAllDisplayed->setShortcut(QString::fromUtf8("Ctrl+Alt+M"));
#endif // QT_NO_SHORTCUT
        actionEditNextMark = new QAction(MainWindow);
        actionEditNextMark->setObjectName(QString::fromUtf8("actionEditNextMark"));
#ifndef QT_NO_SHORTCUT
        actionEditNextMark->setShortcut(QString::fromUtf8("Ctrl+Shift+N"));
#endif // QT_NO_SHORTCUT
        actionEditPreviousMark = new QAction(MainWindow);
        actionEditPreviousMark->setObjectName(QString::fromUtf8("actionEditPreviousMark"));
#ifndef QT_NO_SHORTCUT
        actionEditPreviousMark->setShortcut(QString::fromUtf8("Ctrl+Shift+B"));
#endif // QT_NO_SHORTCUT
        actionEditIgnorePacket = new QAction(MainWindow);
        actionEditIgnorePacket->setObjectName(QString::fromUtf8("actionEditIgnorePacket"));
#ifndef QT_NO_SHORTCUT
        actionEditIgnorePacket->setShortcut(QString::fromUtf8("Ctrl+D"));
#endif // QT_NO_SHORTCUT
        actionEditIgnoreAllDisplayed = new QAction(MainWindow);
        actionEditIgnoreAllDisplayed->setObjectName(QString::fromUtf8("actionEditIgnoreAllDisplayed"));
#ifndef QT_NO_SHORTCUT
        actionEditIgnoreAllDisplayed->setShortcut(QString::fromUtf8("Ctrl+Shift+D"));
#endif // QT_NO_SHORTCUT
        actionEditUnignoreAllDisplayed = new QAction(MainWindow);
        actionEditUnignoreAllDisplayed->setObjectName(QString::fromUtf8("actionEditUnignoreAllDisplayed"));
#ifndef QT_NO_SHORTCUT
        actionEditUnignoreAllDisplayed->setShortcut(QString::fromUtf8("Ctrl+Alt+D"));
#endif // QT_NO_SHORTCUT
        actionEditSetTimeReference = new QAction(MainWindow);
        actionEditSetTimeReference->setObjectName(QString::fromUtf8("actionEditSetTimeReference"));
#ifndef QT_NO_SHORTCUT
        actionEditSetTimeReference->setShortcut(QString::fromUtf8("Ctrl+T"));
#endif // QT_NO_SHORTCUT
        actionEditUnsetAllTimeReferences = new QAction(MainWindow);
        actionEditUnsetAllTimeReferences->setObjectName(QString::fromUtf8("actionEditUnsetAllTimeReferences"));
#ifndef QT_NO_SHORTCUT
        actionEditUnsetAllTimeReferences->setShortcut(QString::fromUtf8("Ctrl+Alt+T"));
#endif // QT_NO_SHORTCUT
        actionEditNextTimeReference = new QAction(MainWindow);
        actionEditNextTimeReference->setObjectName(QString::fromUtf8("actionEditNextTimeReference"));
#ifndef QT_NO_SHORTCUT
        actionEditNextTimeReference->setShortcut(QString::fromUtf8("Ctrl+Alt+N"));
#endif // QT_NO_SHORTCUT
        actionEditPreviousTimeReference = new QAction(MainWindow);
        actionEditPreviousTimeReference->setObjectName(QString::fromUtf8("actionEditPreviousTimeReference"));
#ifndef QT_NO_SHORTCUT
        actionEditPreviousTimeReference->setShortcut(QString::fromUtf8("Ctrl+Alt+B"));
#endif // QT_NO_SHORTCUT
        actionEditTimeShift = new QAction(MainWindow);
        actionEditTimeShift->setObjectName(QString::fromUtf8("actionEditTimeShift"));
#ifndef QT_NO_SHORTCUT
        actionEditTimeShift->setShortcut(QString::fromUtf8("Ctrl+Shift+T"));
#endif // QT_NO_SHORTCUT
        actionEditPacketComment = new QAction(MainWindow);
        actionEditPacketComment->setObjectName(QString::fromUtf8("actionEditPacketComment"));
#ifndef QT_NO_SHORTCUT
        actionEditPacketComment->setShortcut(QString::fromUtf8("Ctrl+Alt+C"));
#endif // QT_NO_SHORTCUT
        actionDeleteAllPacketComments = new QAction(MainWindow);
        actionDeleteAllPacketComments->setObjectName(QString::fromUtf8("actionDeleteAllPacketComments"));
        actionEditConfigurationProfiles = new QAction(MainWindow);
        actionEditConfigurationProfiles->setObjectName(QString::fromUtf8("actionEditConfigurationProfiles"));
        actionEditConfigurationProfiles->setCheckable(false);
#ifndef QT_NO_SHORTCUT
        actionEditConfigurationProfiles->setShortcut(QString::fromUtf8("Ctrl+Shift+A"));
#endif // QT_NO_SHORTCUT
        actionEditConfigurationProfiles->setMenuRole(QAction::NoRole);
        actionEditPreferences = new QAction(MainWindow);
        actionEditPreferences->setObjectName(QString::fromUtf8("actionEditPreferences"));
#ifndef QT_NO_SHORTCUT
        actionEditPreferences->setShortcut(QString::fromUtf8("Ctrl+Shift+P"));
#endif // QT_NO_SHORTCUT
        actionEditPreferences->setMenuRole(QAction::PreferencesRole);
        actionStatisticsCaptureFileProperties = new QAction(MainWindow);
        actionStatisticsCaptureFileProperties->setObjectName(QString::fromUtf8("actionStatisticsCaptureFileProperties"));
        actionStatisticsCaptureFileProperties->setEnabled(false);
#ifndef QT_NO_SHORTCUT
        actionStatisticsCaptureFileProperties->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+C"));
#endif // QT_NO_SHORTCUT
        actionStatisticsProtocolHierarchy = new QAction(MainWindow);
        actionStatisticsProtocolHierarchy->setObjectName(QString::fromUtf8("actionStatisticsProtocolHierarchy"));
        actionStatisticsProtocolHierarchy->setEnabled(false);
        actionHelpMPCapinfos = new QAction(MainWindow);
        actionHelpMPCapinfos->setObjectName(QString::fromUtf8("actionHelpMPCapinfos"));
        actionHelpMPReordercap = new QAction(MainWindow);
        actionHelpMPReordercap->setObjectName(QString::fromUtf8("actionHelpMPReordercap"));
        actionStatisticsTcpStreamStevens = new QAction(MainWindow);
        actionStatisticsTcpStreamStevens->setObjectName(QString::fromUtf8("actionStatisticsTcpStreamStevens"));
        actionStatisticsTcpStreamThroughput = new QAction(MainWindow);
        actionStatisticsTcpStreamThroughput->setObjectName(QString::fromUtf8("actionStatisticsTcpStreamThroughput"));
        actionStatisticsTcpStreamRoundTripTime = new QAction(MainWindow);
        actionStatisticsTcpStreamRoundTripTime->setObjectName(QString::fromUtf8("actionStatisticsTcpStreamRoundTripTime"));
        actionStatisticsTcpStreamWindowScaling = new QAction(MainWindow);
        actionStatisticsTcpStreamWindowScaling->setObjectName(QString::fromUtf8("actionStatisticsTcpStreamWindowScaling"));
        actionAnalyzeFollowTCPStream = new QAction(MainWindow);
        actionAnalyzeFollowTCPStream->setObjectName(QString::fromUtf8("actionAnalyzeFollowTCPStream"));
        actionAnalyzeFollowTCPStream->setEnabled(false);
#ifndef QT_NO_SHORTCUT
        actionAnalyzeFollowTCPStream->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+T"));
#endif // QT_NO_SHORTCUT
        actionAnalyzeFollowUDPStream = new QAction(MainWindow);
        actionAnalyzeFollowUDPStream->setObjectName(QString::fromUtf8("actionAnalyzeFollowUDPStream"));
        actionAnalyzeFollowUDPStream->setEnabled(false);
#ifndef QT_NO_SHORTCUT
        actionAnalyzeFollowUDPStream->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+U"));
#endif // QT_NO_SHORTCUT
        actionAnalyzeFollowTLSStream = new QAction(MainWindow);
        actionAnalyzeFollowTLSStream->setObjectName(QString::fromUtf8("actionAnalyzeFollowTLSStream"));
        actionAnalyzeFollowTLSStream->setEnabled(false);
#ifndef QT_NO_SHORTCUT
        actionAnalyzeFollowTLSStream->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+S"));
#endif // QT_NO_SHORTCUT
        actionAnalyzeFollowHTTPStream = new QAction(MainWindow);
        actionAnalyzeFollowHTTPStream->setObjectName(QString::fromUtf8("actionAnalyzeFollowHTTPStream"));
        actionAnalyzeFollowHTTPStream->setEnabled(false);
#ifndef QT_NO_SHORTCUT
        actionAnalyzeFollowHTTPStream->setShortcut(QString::fromUtf8("Ctrl+Alt+Shift+H"));
#endif // QT_NO_SHORTCUT
        actionStatisticsTcpStreamTcptrace = new QAction(MainWindow);
        actionStatisticsTcpStreamTcptrace->setObjectName(QString::fromUtf8("actionStatisticsTcpStreamTcptrace"));
        actionSCTPAnalyseThisAssociation = new QAction(MainWindow);
        actionSCTPAnalyseThisAssociation->setObjectName(QString::fromUtf8("actionSCTPAnalyseThisAssociation"));
        actionSCTPShowAllAssociations = new QAction(MainWindow);
        actionSCTPShowAllAssociations->setObjectName(QString::fromUtf8("actionSCTPShowAllAssociations"));
        actionStatisticsFlowGraph = new QAction(MainWindow);
        actionStatisticsFlowGraph->setObjectName(QString::fromUtf8("actionStatisticsFlowGraph"));
        actionStatisticsANCP = new QAction(MainWindow);
        actionStatisticsANCP->setObjectName(QString::fromUtf8("actionStatisticsANCP"));
        actionStatisticsBACappInstanceId = new QAction(MainWindow);
        actionStatisticsBACappInstanceId->setObjectName(QString::fromUtf8("actionStatisticsBACappInstanceId"));
        actionStatisticsBACappIP = new QAction(MainWindow);
        actionStatisticsBACappIP->setObjectName(QString::fromUtf8("actionStatisticsBACappIP"));
        actionStatisticsBACappObjectId = new QAction(MainWindow);
        actionStatisticsBACappObjectId->setObjectName(QString::fromUtf8("actionStatisticsBACappObjectId"));
        actionStatisticsBACappService = new QAction(MainWindow);
        actionStatisticsBACappService->setObjectName(QString::fromUtf8("actionStatisticsBACappService"));
        actionStatisticsCollectd = new QAction(MainWindow);
        actionStatisticsCollectd->setObjectName(QString::fromUtf8("actionStatisticsCollectd"));
        actionStatisticsDNS = new QAction(MainWindow);
        actionStatisticsDNS->setObjectName(QString::fromUtf8("actionStatisticsDNS"));
        actionStatisticsHART_IP = new QAction(MainWindow);
        actionStatisticsHART_IP->setObjectName(QString::fromUtf8("actionStatisticsHART_IP"));
        actionStatisticsHpfeeds = new QAction(MainWindow);
        actionStatisticsHpfeeds->setObjectName(QString::fromUtf8("actionStatisticsHpfeeds"));
        actionStatisticsHTTP2 = new QAction(MainWindow);
        actionStatisticsHTTP2->setObjectName(QString::fromUtf8("actionStatisticsHTTP2"));
        actionStatisticsHTTPPacketCounter = new QAction(MainWindow);
        actionStatisticsHTTPPacketCounter->setObjectName(QString::fromUtf8("actionStatisticsHTTPPacketCounter"));
        actionStatisticsHTTPRequests = new QAction(MainWindow);
        actionStatisticsHTTPRequests->setObjectName(QString::fromUtf8("actionStatisticsHTTPRequests"));
        actionStatisticsHTTPLoadDistribution = new QAction(MainWindow);
        actionStatisticsHTTPLoadDistribution->setObjectName(QString::fromUtf8("actionStatisticsHTTPLoadDistribution"));
        actionStatisticsHTTPRequestSequences = new QAction(MainWindow);
        actionStatisticsHTTPRequestSequences->setObjectName(QString::fromUtf8("actionStatisticsHTTPRequestSequences"));
        actionStatisticsPacketLengths = new QAction(MainWindow);
        actionStatisticsPacketLengths->setObjectName(QString::fromUtf8("actionStatisticsPacketLengths"));
        actionStatisticsSametime = new QAction(MainWindow);
        actionStatisticsSametime->setObjectName(QString::fromUtf8("actionStatisticsSametime"));
        actionTelephonyISUPMessages = new QAction(MainWindow);
        actionTelephonyISUPMessages->setObjectName(QString::fromUtf8("actionTelephonyISUPMessages"));
        actionTelephonyOsmuxPacketCounter = new QAction(MainWindow);
        actionTelephonyOsmuxPacketCounter->setObjectName(QString::fromUtf8("actionTelephonyOsmuxPacketCounter"));
        actionTelephonyRTSPPacketCounter = new QAction(MainWindow);
        actionTelephonyRTSPPacketCounter->setObjectName(QString::fromUtf8("actionTelephonyRTSPPacketCounter"));
        actionTelephonySMPPOperations = new QAction(MainWindow);
        actionTelephonySMPPOperations->setObjectName(QString::fromUtf8("actionTelephonySMPPOperations"));
        actionTelephonyUCPMessages = new QAction(MainWindow);
        actionTelephonyUCPMessages->setObjectName(QString::fromUtf8("actionTelephonyUCPMessages"));
        actionAnalyzeDecodeAs = new QAction(MainWindow);
        actionAnalyzeDecodeAs->setObjectName(QString::fromUtf8("actionAnalyzeDecodeAs"));
        actionAnalyzeReloadLuaPlugins = new QAction(MainWindow);
        actionAnalyzeReloadLuaPlugins->setObjectName(QString::fromUtf8("actionAnalyzeReloadLuaPlugins"));
#ifndef QT_NO_SHORTCUT
        actionAnalyzeReloadLuaPlugins->setShortcut(QString::fromUtf8("Ctrl+Shift+L"));
#endif // QT_NO_SHORTCUT
        action29West = new QAction(MainWindow);
        action29West->setObjectName(QString::fromUtf8("action29West"));
        actionStatistics29WestTopics_Advertisements_by_Topic = new QAction(MainWindow);
        actionStatistics29WestTopics_Advertisements_by_Topic->setObjectName(QString::fromUtf8("actionStatistics29WestTopics_Advertisements_by_Topic"));
        actionStatistics29WestTopics_Advertisements_by_Source = new QAction(MainWindow);
        actionStatistics29WestTopics_Advertisements_by_Source->setObjectName(QString::fromUtf8("actionStatistics29WestTopics_Advertisements_by_Source"));
        actionStatistics29WestTopics_Advertisements_by_Transport = new QAction(MainWindow);
        actionStatistics29WestTopics_Advertisements_by_Transport->setObjectName(QString::fromUtf8("actionStatistics29WestTopics_Advertisements_by_Transport"));
        actionStatistics29WestTopics_Queries_by_Topic = new QAction(MainWindow);
        actionStatistics29WestTopics_Queries_by_Topic->setObjectName(QString::fromUtf8("actionStatistics29WestTopics_Queries_by_Topic"));
        actionStatistics29WestTopics_Queries_by_Receiver = new QAction(MainWindow);
        actionStatistics29WestTopics_Queries_by_Receiver->setObjectName(QString::fromUtf8("actionStatistics29WestTopics_Queries_by_Receiver"));
        actionStatistics29WestTopics_Wildcard_Queries_by_Pattern = new QAction(MainWindow);
        actionStatistics29WestTopics_Wildcard_Queries_by_Pattern->setObjectName(QString::fromUtf8("actionStatistics29WestTopics_Wildcard_Queries_by_Pattern"));
        actionStatistics29WestTopics_Wildcard_Queries_by_Receiver = new QAction(MainWindow);
        actionStatistics29WestTopics_Wildcard_Queries_by_Receiver->setObjectName(QString::fromUtf8("actionStatistics29WestTopics_Wildcard_Queries_by_Receiver"));
        actionStatistics29WestQueues_Advertisements_by_Queue = new QAction(MainWindow);
        actionStatistics29WestQueues_Advertisements_by_Queue->setObjectName(QString::fromUtf8("actionStatistics29WestQueues_Advertisements_by_Queue"));
        actionStatistics29WestQueues_Advertisements_by_Source = new QAction(MainWindow);
        actionStatistics29WestQueues_Advertisements_by_Source->setObjectName(QString::fromUtf8("actionStatistics29WestQueues_Advertisements_by_Source"));
        actionStatistics29WestQueues_Queries_by_Queue = new QAction(MainWindow);
        actionStatistics29WestQueues_Queries_by_Queue->setObjectName(QString::fromUtf8("actionStatistics29WestQueues_Queries_by_Queue"));
        actionStatistics29WestQueues_Queries_by_Receiver = new QAction(MainWindow);
        actionStatistics29WestQueues_Queries_by_Receiver->setObjectName(QString::fromUtf8("actionStatistics29WestQueues_Queries_by_Receiver"));
        actionStatistics29WestUIM_Streams = new QAction(MainWindow);
        actionStatistics29WestUIM_Streams->setObjectName(QString::fromUtf8("actionStatistics29WestUIM_Streams"));
        actionStatistics29WestLBTRM = new QAction(MainWindow);
        actionStatistics29WestLBTRM->setObjectName(QString::fromUtf8("actionStatistics29WestLBTRM"));
        actionStatistics29WestLBTRU = new QAction(MainWindow);
        actionStatistics29WestLBTRU->setObjectName(QString::fromUtf8("actionStatistics29WestLBTRU"));
        actionSCTPFilterThisAssociation = new QAction(MainWindow);
        actionSCTPFilterThisAssociation->setObjectName(QString::fromUtf8("actionSCTPFilterThisAssociation"));
        actionFileExportPDU = new QAction(MainWindow);
        actionFileExportPDU->setObjectName(QString::fromUtf8("actionFileExportPDU"));
        actionStatisticsIOGraph = new QAction(MainWindow);
        actionStatisticsIOGraph->setObjectName(QString::fromUtf8("actionStatisticsIOGraph"));
        actionViewMainToolbar = new QAction(MainWindow);
        actionViewMainToolbar->setObjectName(QString::fromUtf8("actionViewMainToolbar"));
        actionViewMainToolbar->setCheckable(true);
        actionViewMainToolbar->setChecked(true);
        actionViewFilterToolbar = new QAction(MainWindow);
        actionViewFilterToolbar->setObjectName(QString::fromUtf8("actionViewFilterToolbar"));
        actionViewFilterToolbar->setCheckable(true);
        actionViewFilterToolbar->setChecked(true);
        actionStatisticsConversations = new QAction(MainWindow);
        actionStatisticsConversations->setObjectName(QString::fromUtf8("actionStatisticsConversations"));
        actionStatisticsEndpoints = new QAction(MainWindow);
        actionStatisticsEndpoints->setObjectName(QString::fromUtf8("actionStatisticsEndpoints"));
        actionViewColorizePacketList = new QAction(MainWindow);
        actionViewColorizePacketList->setObjectName(QString::fromUtf8("actionViewColorizePacketList"));
        actionViewColorizePacketList->setCheckable(true);
        actionViewZoomIn = new QAction(MainWindow);
        actionViewZoomIn->setObjectName(QString::fromUtf8("actionViewZoomIn"));
#ifndef QT_NO_SHORTCUT
        actionViewZoomIn->setShortcut(QString::fromUtf8("Ctrl++"));
#endif // QT_NO_SHORTCUT
        actionViewZoomOut = new QAction(MainWindow);
        actionViewZoomOut->setObjectName(QString::fromUtf8("actionViewZoomOut"));
#ifndef QT_NO_SHORTCUT
        actionViewZoomOut->setShortcut(QString::fromUtf8("Ctrl+-"));
#endif // QT_NO_SHORTCUT
        actionViewNormalSize = new QAction(MainWindow);
        actionViewNormalSize->setObjectName(QString::fromUtf8("actionViewNormalSize"));
#ifndef QT_NO_SHORTCUT
        actionViewNormalSize->setShortcut(QString::fromUtf8("Ctrl+0"));
#endif // QT_NO_SHORTCUT
        actionViewResetLayout = new QAction(MainWindow);
        actionViewResetLayout->setObjectName(QString::fromUtf8("actionViewResetLayout"));
#ifndef QT_NO_SHORTCUT
        actionViewResetLayout->setShortcut(QString::fromUtf8("Ctrl+Shift+W"));
#endif // QT_NO_SHORTCUT
        actionViewResizeColumns = new QAction(MainWindow);
        actionViewResizeColumns->setObjectName(QString::fromUtf8("actionViewResizeColumns"));
#ifndef QT_NO_SHORTCUT
        actionViewResizeColumns->setShortcut(QString::fromUtf8("Ctrl+Shift+R"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatDateYMDandTimeOfDay = new QAction(MainWindow);
        actionViewTimeDisplayFormatDateYMDandTimeOfDay->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatDateYMDandTimeOfDay"));
        actionViewTimeDisplayFormatDateYMDandTimeOfDay->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionViewTimeDisplayFormatDateYMDandTimeOfDay->setShortcut(QString::fromUtf8("Ctrl+Alt+1"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatDateYDOYandTimeOfDay = new QAction(MainWindow);
        actionViewTimeDisplayFormatDateYDOYandTimeOfDay->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatDateYDOYandTimeOfDay"));
        actionViewTimeDisplayFormatDateYDOYandTimeOfDay->setCheckable(true);
        actionViewTimeDisplayFormatTimeOfDay = new QAction(MainWindow);
        actionViewTimeDisplayFormatTimeOfDay->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatTimeOfDay"));
        actionViewTimeDisplayFormatTimeOfDay->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionViewTimeDisplayFormatTimeOfDay->setShortcut(QString::fromUtf8("Ctrl+Alt+2"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatSecondsSinceEpoch = new QAction(MainWindow);
        actionViewTimeDisplayFormatSecondsSinceEpoch->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatSecondsSinceEpoch"));
        actionViewTimeDisplayFormatSecondsSinceEpoch->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionViewTimeDisplayFormatSecondsSinceEpoch->setShortcut(QString::fromUtf8("Ctrl+Alt+3"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture = new QAction(MainWindow);
        actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture"));
        actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture->setShortcut(QString::fromUtf8("Ctrl+Alt+4"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket = new QAction(MainWindow);
        actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket"));
        actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket->setShortcut(QString::fromUtf8("Ctrl+Alt+5"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket = new QAction(MainWindow);
        actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket"));
        actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket->setShortcut(QString::fromUtf8("Ctrl+Alt+6"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay = new QAction(MainWindow);
        actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay"));
        actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay->setShortcut(QString::fromUtf8("Ctrl+Alt+7"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay = new QAction(MainWindow);
        actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay"));
        actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay->setCheckable(true);
        actionViewTimeDisplayFormatUTCTimeOfDay = new QAction(MainWindow);
        actionViewTimeDisplayFormatUTCTimeOfDay->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatUTCTimeOfDay"));
        actionViewTimeDisplayFormatUTCTimeOfDay->setCheckable(true);
#ifndef QT_NO_SHORTCUT
        actionViewTimeDisplayFormatUTCTimeOfDay->setShortcut(QString::fromUtf8("Ctrl+Alt+8"));
#endif // QT_NO_SHORTCUT
        actionViewTimeDisplayFormatPrecisionAutomatic = new QAction(MainWindow);
        actionViewTimeDisplayFormatPrecisionAutomatic->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatPrecisionAutomatic"));
        actionViewTimeDisplayFormatPrecisionAutomatic->setCheckable(true);
        actionViewTimeDisplayFormatPrecisionSeconds = new QAction(MainWindow);
        actionViewTimeDisplayFormatPrecisionSeconds->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatPrecisionSeconds"));
        actionViewTimeDisplayFormatPrecisionSeconds->setCheckable(true);
        actionViewTimeDisplayFormatPrecisionDeciseconds = new QAction(MainWindow);
        actionViewTimeDisplayFormatPrecisionDeciseconds->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatPrecisionDeciseconds"));
        actionViewTimeDisplayFormatPrecisionDeciseconds->setCheckable(true);
        actionViewTimeDisplayFormatPrecisionCentiseconds = new QAction(MainWindow);
        actionViewTimeDisplayFormatPrecisionCentiseconds->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatPrecisionCentiseconds"));
        actionViewTimeDisplayFormatPrecisionCentiseconds->setCheckable(true);
        actionViewTimeDisplayFormatPrecisionMilliseconds = new QAction(MainWindow);
        actionViewTimeDisplayFormatPrecisionMilliseconds->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatPrecisionMilliseconds"));
        actionViewTimeDisplayFormatPrecisionMilliseconds->setCheckable(true);
        actionViewTimeDisplayFormatPrecisionMicroseconds = new QAction(MainWindow);
        actionViewTimeDisplayFormatPrecisionMicroseconds->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatPrecisionMicroseconds"));
        actionViewTimeDisplayFormatPrecisionMicroseconds->setCheckable(true);
        actionViewTimeDisplayFormatPrecisionNanoseconds = new QAction(MainWindow);
        actionViewTimeDisplayFormatPrecisionNanoseconds->setObjectName(QString::fromUtf8("actionViewTimeDisplayFormatPrecisionNanoseconds"));
        actionViewTimeDisplayFormatPrecisionNanoseconds->setCheckable(true);
        actionViewTimeDisplaySecondsWithHoursAndMinutes = new QAction(MainWindow);
        actionViewTimeDisplaySecondsWithHoursAndMinutes->setObjectName(QString::fromUtf8("actionViewTimeDisplaySecondsWithHoursAndMinutes"));
        actionViewTimeDisplaySecondsWithHoursAndMinutes->setCheckable(true);
        actionViewNameResolutionPhysical = new QAction(MainWindow);
        actionViewNameResolutionPhysical->setObjectName(QString::fromUtf8("actionViewNameResolutionPhysical"));
        actionViewNameResolutionPhysical->setCheckable(true);
        actionViewNameResolutionNetwork = new QAction(MainWindow);
        actionViewNameResolutionNetwork->setObjectName(QString::fromUtf8("actionViewNameResolutionNetwork"));
        actionViewNameResolutionNetwork->setCheckable(true);
        actionViewNameResolutionTransport = new QAction(MainWindow);
        actionViewNameResolutionTransport->setObjectName(QString::fromUtf8("actionViewNameResolutionTransport"));
        actionViewNameResolutionTransport->setCheckable(true);
        actionViewWirelessToolbar = new QAction(MainWindow);
        actionViewWirelessToolbar->setObjectName(QString::fromUtf8("actionViewWirelessToolbar"));
        actionViewWirelessToolbar->setCheckable(true);
        actionViewStatusBar = new QAction(MainWindow);
        actionViewStatusBar->setObjectName(QString::fromUtf8("actionViewStatusBar"));
        actionViewStatusBar->setCheckable(true);
        actionViewStatusBar->setChecked(true);
        actionViewPacketList = new QAction(MainWindow);
        actionViewPacketList->setObjectName(QString::fromUtf8("actionViewPacketList"));
        actionViewPacketList->setCheckable(true);
        actionViewPacketList->setChecked(true);
        actionViewPacketDetails = new QAction(MainWindow);
        actionViewPacketDetails->setObjectName(QString::fromUtf8("actionViewPacketDetails"));
        actionViewPacketDetails->setCheckable(true);
        actionViewPacketDetails->setChecked(true);
        actionViewPacketBytes = new QAction(MainWindow);
        actionViewPacketBytes->setObjectName(QString::fromUtf8("actionViewPacketBytes"));
        actionViewPacketBytes->setCheckable(true);
        actionViewPacketBytes->setChecked(true);
        actionViewInternalsConversationHashTables = new QAction(MainWindow);
        actionViewInternalsConversationHashTables->setObjectName(QString::fromUtf8("actionViewInternalsConversationHashTables"));
        actionViewInternalsDissectorTables = new QAction(MainWindow);
        actionViewInternalsDissectorTables->setObjectName(QString::fromUtf8("actionViewInternalsDissectorTables"));
        actionViewInternalsSupportedProtocols = new QAction(MainWindow);
        actionViewInternalsSupportedProtocols->setObjectName(QString::fromUtf8("actionViewInternalsSupportedProtocols"));
        actionTelephonyGsmMapSummary = new QAction(MainWindow);
        actionTelephonyGsmMapSummary->setObjectName(QString::fromUtf8("actionTelephonyGsmMapSummary"));
        actionTelephonyLteMacStatistics = new QAction(MainWindow);
        actionTelephonyLteMacStatistics->setObjectName(QString::fromUtf8("actionTelephonyLteMacStatistics"));
        actionTelephonyLteRlcStatistics = new QAction(MainWindow);
        actionTelephonyLteRlcStatistics->setObjectName(QString::fromUtf8("actionTelephonyLteRlcStatistics"));
        actionTelephonyLteRlcGraph = new QAction(MainWindow);
        actionTelephonyLteRlcGraph->setObjectName(QString::fromUtf8("actionTelephonyLteRlcGraph"));
        actionTelephonyMtp3Summary = new QAction(MainWindow);
        actionTelephonyMtp3Summary->setObjectName(QString::fromUtf8("actionTelephonyMtp3Summary"));
        actionTelephonyVoipCalls = new QAction(MainWindow);
        actionTelephonyVoipCalls->setObjectName(QString::fromUtf8("actionTelephonyVoipCalls"));
        actionTelephonySipFlows = new QAction(MainWindow);
        actionTelephonySipFlows->setObjectName(QString::fromUtf8("actionTelephonySipFlows"));
        actionTelephonyRTPStreams = new QAction(MainWindow);
        actionTelephonyRTPStreams->setObjectName(QString::fromUtf8("actionTelephonyRTPStreams"));
        actionViewColoringRules = new QAction(MainWindow);
        actionViewColoringRules->setObjectName(QString::fromUtf8("actionViewColoringRules"));
        actionBluetoothATT_Server_Attributes = new QAction(MainWindow);
        actionBluetoothATT_Server_Attributes->setObjectName(QString::fromUtf8("actionBluetoothATT_Server_Attributes"));
        actionBluetoothDevices = new QAction(MainWindow);
        actionBluetoothDevices->setObjectName(QString::fromUtf8("actionBluetoothDevices"));
        actionBluetoothHCI_Summary = new QAction(MainWindow);
        actionBluetoothHCI_Summary->setObjectName(QString::fromUtf8("actionBluetoothHCI_Summary"));
        actionViewShowPacketInNewWindow = new QAction(MainWindow);
        actionViewShowPacketInNewWindow->setObjectName(QString::fromUtf8("actionViewShowPacketInNewWindow"));
        actionContextShowLinkedPacketInNewWindow = new QAction(MainWindow);
        actionContextShowLinkedPacketInNewWindow->setObjectName(QString::fromUtf8("actionContextShowLinkedPacketInNewWindow"));
        actionGoAutoScroll = new QAction(MainWindow);
        actionGoAutoScroll->setObjectName(QString::fromUtf8("actionGoAutoScroll"));
        actionGoAutoScroll->setCheckable(true);
        actionAnalyzeExpertInfo = new QAction(MainWindow);
        actionAnalyzeExpertInfo->setObjectName(QString::fromUtf8("actionAnalyzeExpertInfo"));
        actionDisplayFilterExpression = new QAction(MainWindow);
        actionDisplayFilterExpression->setObjectName(QString::fromUtf8("actionDisplayFilterExpression"));
        actionStatistics_REGISTER_STAT_GROUP_UNSORTED = new QAction(MainWindow);
        actionStatistics_REGISTER_STAT_GROUP_UNSORTED->setObjectName(QString::fromUtf8("actionStatistics_REGISTER_STAT_GROUP_UNSORTED"));
        actionStatistics_REGISTER_STAT_GROUP_UNSORTED->setVisible(false);
        actionStatistics_REGISTER_STAT_GROUP_UNSORTED->setMenuRole(QAction::NoRole);
        actionTelephonyANSIPlaceholder = new QAction(MainWindow);
        actionTelephonyANSIPlaceholder->setObjectName(QString::fromUtf8("actionTelephonyANSIPlaceholder"));
        actionTelephonyANSIPlaceholder->setEnabled(false);
        actionTelephonyGSMPlaceholder = new QAction(MainWindow);
        actionTelephonyGSMPlaceholder->setObjectName(QString::fromUtf8("actionTelephonyGSMPlaceholder"));
        actionTelephonyGSMPlaceholder->setEnabled(false);
        actionTelephonyLTEPlaceholder = new QAction(MainWindow);
        actionTelephonyLTEPlaceholder->setObjectName(QString::fromUtf8("actionTelephonyLTEPlaceholder"));
        actionTelephonyLTEPlaceholder->setEnabled(false);
        actionTelephonyMTP3Placeholder = new QAction(MainWindow);
        actionTelephonyMTP3Placeholder->setObjectName(QString::fromUtf8("actionTelephonyMTP3Placeholder"));
        actionTelephonyMTP3Placeholder->setEnabled(false);
        actionStatisticsResolvedAddresses = new QAction(MainWindow);
        actionStatisticsResolvedAddresses->setObjectName(QString::fromUtf8("actionStatisticsResolvedAddresses"));
        actionViewColorizeConversation1 = new QAction(MainWindow);
        actionViewColorizeConversation1->setObjectName(QString::fromUtf8("actionViewColorizeConversation1"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation1->setShortcut(QString::fromUtf8("Ctrl+1"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation2 = new QAction(MainWindow);
        actionViewColorizeConversation2->setObjectName(QString::fromUtf8("actionViewColorizeConversation2"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation2->setShortcut(QString::fromUtf8("Ctrl+2"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation3 = new QAction(MainWindow);
        actionViewColorizeConversation3->setObjectName(QString::fromUtf8("actionViewColorizeConversation3"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation3->setShortcut(QString::fromUtf8("Ctrl+3"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation4 = new QAction(MainWindow);
        actionViewColorizeConversation4->setObjectName(QString::fromUtf8("actionViewColorizeConversation4"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation4->setShortcut(QString::fromUtf8("Ctrl+4"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation5 = new QAction(MainWindow);
        actionViewColorizeConversation5->setObjectName(QString::fromUtf8("actionViewColorizeConversation5"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation5->setShortcut(QString::fromUtf8("Ctrl+5"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation6 = new QAction(MainWindow);
        actionViewColorizeConversation6->setObjectName(QString::fromUtf8("actionViewColorizeConversation6"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation6->setShortcut(QString::fromUtf8("Ctrl+6"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation7 = new QAction(MainWindow);
        actionViewColorizeConversation7->setObjectName(QString::fromUtf8("actionViewColorizeConversation7"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation7->setShortcut(QString::fromUtf8("Ctrl+7"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation8 = new QAction(MainWindow);
        actionViewColorizeConversation8->setObjectName(QString::fromUtf8("actionViewColorizeConversation8"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation8->setShortcut(QString::fromUtf8("Ctrl+8"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation9 = new QAction(MainWindow);
        actionViewColorizeConversation9->setObjectName(QString::fromUtf8("actionViewColorizeConversation9"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeConversation9->setShortcut(QString::fromUtf8("Ctrl+9"));
#endif // QT_NO_SHORTCUT
        actionViewColorizeConversation10 = new QAction(MainWindow);
        actionViewColorizeConversation10->setObjectName(QString::fromUtf8("actionViewColorizeConversation10"));
        actionViewColorizeNewColoringRule = new QAction(MainWindow);
        actionViewColorizeNewColoringRule->setObjectName(QString::fromUtf8("actionViewColorizeNewColoringRule"));
        actionViewColorizeResetColorization = new QAction(MainWindow);
        actionViewColorizeResetColorization->setObjectName(QString::fromUtf8("actionViewColorizeResetColorization"));
#ifndef QT_NO_SHORTCUT
        actionViewColorizeResetColorization->setShortcut(QString::fromUtf8("Ctrl+Space"));
#endif // QT_NO_SHORTCUT
        actionTelephonyRTPStreamAnalysis = new QAction(MainWindow);
        actionTelephonyRTPStreamAnalysis->setObjectName(QString::fromUtf8("actionTelephonyRTPStreamAnalysis"));
        actionTelephonyIax2StreamAnalysis = new QAction(MainWindow);
        actionTelephonyIax2StreamAnalysis->setObjectName(QString::fromUtf8("actionTelephonyIax2StreamAnalysis"));
        actionViewEditResolvedName = new QAction(MainWindow);
        actionViewEditResolvedName->setObjectName(QString::fromUtf8("actionViewEditResolvedName"));
        actionAnalyzeEnabledProtocols = new QAction(MainWindow);
        actionAnalyzeEnabledProtocols->setObjectName(QString::fromUtf8("actionAnalyzeEnabledProtocols"));
#ifndef QT_NO_SHORTCUT
        actionAnalyzeEnabledProtocols->setShortcut(QString::fromUtf8("Ctrl+Shift+E"));
#endif // QT_NO_SHORTCUT
        actionAnalyzeShowPacketBytes = new QAction(MainWindow);
        actionAnalyzeShowPacketBytes->setObjectName(QString::fromUtf8("actionAnalyzeShowPacketBytes"));
#ifndef QT_NO_SHORTCUT
        actionAnalyzeShowPacketBytes->setShortcut(QString::fromUtf8("Ctrl+Shift+O"));
#endif // QT_NO_SHORTCUT
        actionContextWikiProtocolPage = new QAction(MainWindow);
        actionContextWikiProtocolPage->setObjectName(QString::fromUtf8("actionContextWikiProtocolPage"));
        actionContextFilterFieldReference = new QAction(MainWindow);
        actionContextFilterFieldReference->setObjectName(QString::fromUtf8("actionContextFilterFieldReference"));
        actionGoGoToLinkedPacket = new QAction(MainWindow);
        actionGoGoToLinkedPacket->setObjectName(QString::fromUtf8("actionGoGoToLinkedPacket"));
        actionStatisticsUdpMulticastStreams = new QAction(MainWindow);
        actionStatisticsUdpMulticastStreams->setObjectName(QString::fromUtf8("actionStatisticsUdpMulticastStreams"));
        actionWirelessWlanStatistics = new QAction(MainWindow);
        actionWirelessWlanStatistics->setObjectName(QString::fromUtf8("actionWirelessWlanStatistics"));
        actionNewDisplayFilterExpression = new QAction(MainWindow);
        actionNewDisplayFilterExpression->setObjectName(QString::fromUtf8("actionNewDisplayFilterExpression"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/stock/plus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionNewDisplayFilterExpression->setIcon(icon2);
        actionToolsFirewallAclRules = new QAction(MainWindow);
        actionToolsFirewallAclRules->setObjectName(QString::fromUtf8("actionToolsFirewallAclRules"));
        actionViewFullScreen = new QAction(MainWindow);
        actionViewFullScreen->setObjectName(QString::fromUtf8("actionViewFullScreen"));
        actionViewFullScreen->setCheckable(true);
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(centralWidget->sizePolicy().hasHeightForWidth());
        centralWidget->setSizePolicy(sizePolicy);
        verticalLayout = new QVBoxLayout(centralWidget);
        verticalLayout->setSpacing(0);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout->setContentsMargins(0, 0, 0, 0);
        goToFrame = new AccordionFrame(centralWidget);
        goToFrame->setObjectName(QString::fromUtf8("goToFrame"));
        goToHB = new QHBoxLayout(goToFrame);
        goToHB->setSpacing(6);
        goToHB->setContentsMargins(11, 11, 11, 11);
        goToHB->setObjectName(QString::fromUtf8("goToHB"));
        goToHB->setContentsMargins(-1, 0, -1, 0);
        horizontalSpacer = new QSpacerItem(40, 10, QSizePolicy::Expanding, QSizePolicy::Minimum);

        goToHB->addItem(horizontalSpacer);

        goToPacketLabel = new QLabel(goToFrame);
        goToPacketLabel->setObjectName(QString::fromUtf8("goToPacketLabel"));

        goToHB->addWidget(goToPacketLabel);

        goToLineEdit = new QLineEdit(goToFrame);
        goToLineEdit->setObjectName(QString::fromUtf8("goToLineEdit"));

        goToHB->addWidget(goToLineEdit);

        goToGo = new QPushButton(goToFrame);
        goToGo->setObjectName(QString::fromUtf8("goToGo"));
        goToGo->setMaximumSize(QSize(16777215, 27));

        goToHB->addWidget(goToGo);

        goToCancel = new QPushButton(goToFrame);
        goToCancel->setObjectName(QString::fromUtf8("goToCancel"));
        goToCancel->setMaximumSize(QSize(16777215, 27));

        goToHB->addWidget(goToCancel);


        verticalLayout->addWidget(goToFrame);

        searchFrame = new SearchFrame(centralWidget);
        searchFrame->setObjectName(QString::fromUtf8("searchFrame"));

        verticalLayout->addWidget(searchFrame);

        addressEditorFrame = new AddressEditorFrame(centralWidget);
        addressEditorFrame->setObjectName(QString::fromUtf8("addressEditorFrame"));

        verticalLayout->addWidget(addressEditorFrame);

        columnEditorFrame = new ColumnEditorFrame(centralWidget);
        columnEditorFrame->setObjectName(QString::fromUtf8("columnEditorFrame"));

        verticalLayout->addWidget(columnEditorFrame);

        preferenceEditorFrame = new PreferenceEditorFrame(centralWidget);
        preferenceEditorFrame->setObjectName(QString::fromUtf8("preferenceEditorFrame"));

        verticalLayout->addWidget(preferenceEditorFrame);

        filterExpressionFrame = new FilterExpressionFrame(centralWidget);
        filterExpressionFrame->setObjectName(QString::fromUtf8("filterExpressionFrame"));

        verticalLayout->addWidget(filterExpressionFrame);

        wirelessTimelineWidget = new WirelessTimeline(centralWidget);
        wirelessTimelineWidget->setObjectName(QString::fromUtf8("wirelessTimelineWidget"));

        verticalLayout->addWidget(wirelessTimelineWidget);

        mainStack = new QStackedWidget(centralWidget);
        mainStack->setObjectName(QString::fromUtf8("mainStack"));
        mainStack->setEnabled(true);
        welcomePage = new WelcomePage();
        welcomePage->setObjectName(QString::fromUtf8("welcomePage"));
        mainStack->addWidget(welcomePage);

        verticalLayout->addWidget(mainStack);

        MainWindow->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MainWindow);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 960, 22));
        menuFile = new QMenu(menuBar);
        menuFile->setObjectName(QString::fromUtf8("menuFile"));
        menuOpenRecentCaptureFile = new QMenu(menuFile);
        menuOpenRecentCaptureFile->setObjectName(QString::fromUtf8("menuOpenRecentCaptureFile"));
        menuFileSet = new QMenu(menuFile);
        menuFileSet->setObjectName(QString::fromUtf8("menuFileSet"));
        menuFileExportPacketDissections = new QMenu(menuFile);
        menuFileExportPacketDissections->setObjectName(QString::fromUtf8("menuFileExportPacketDissections"));
        menuFileExportObjects = new QMenu(menuFile);
        menuFileExportObjects->setObjectName(QString::fromUtf8("menuFileExportObjects"));
        menuCapture = new QMenu(menuBar);
        menuCapture->setObjectName(QString::fromUtf8("menuCapture"));
        menuHelp = new QMenu(menuBar);
        menuHelp->setObjectName(QString::fromUtf8("menuHelp"));
        menuHelpManualPages = new QMenu(menuHelp);
        menuHelpManualPages->setObjectName(QString::fromUtf8("menuHelpManualPages"));
        menuGo = new QMenu(menuBar);
        menuGo->setObjectName(QString::fromUtf8("menuGo"));
        menuView = new QMenu(menuBar);
        menuView->setObjectName(QString::fromUtf8("menuView"));
        menuInterfaceToolbars = new QMenu(menuView);
        menuInterfaceToolbars->setObjectName(QString::fromUtf8("menuInterfaceToolbars"));
        menuZoom = new QMenu(menuView);
        menuZoom->setObjectName(QString::fromUtf8("menuZoom"));
        menuTime_Display_Format = new QMenu(menuView);
        menuTime_Display_Format->setObjectName(QString::fromUtf8("menuTime_Display_Format"));
        menuName_Resolution = new QMenu(menuView);
        menuName_Resolution->setObjectName(QString::fromUtf8("menuName_Resolution"));
        menuColorizeConversation = new QMenu(menuView);
        menuColorizeConversation->setObjectName(QString::fromUtf8("menuColorizeConversation"));
        menuInternals = new QMenu(menuView);
        menuInternals->setObjectName(QString::fromUtf8("menuInternals"));
        menuAdditionalToolbars = new QMenu(menuView);
        menuAdditionalToolbars->setObjectName(QString::fromUtf8("menuAdditionalToolbars"));
        menuAnalyze = new QMenu(menuBar);
        menuAnalyze->setObjectName(QString::fromUtf8("menuAnalyze"));
        menuApplyAsFilter = new QMenu(menuAnalyze);
        menuApplyAsFilter->setObjectName(QString::fromUtf8("menuApplyAsFilter"));
        menuPrepareAFilter = new QMenu(menuAnalyze);
        menuPrepareAFilter->setObjectName(QString::fromUtf8("menuPrepareAFilter"));
        menuSCTP = new QMenu(menuAnalyze);
        menuSCTP->setObjectName(QString::fromUtf8("menuSCTP"));
        menuFollow = new QMenu(menuAnalyze);
        menuFollow->setObjectName(QString::fromUtf8("menuFollow"));
        menuConversationFilter = new QMenu(menuAnalyze);
        menuConversationFilter->setObjectName(QString::fromUtf8("menuConversationFilter"));
        menuStatistics = new QMenu(menuBar);
        menuStatistics->setObjectName(QString::fromUtf8("menuStatistics"));
        menuStatistics->setEnabled(true);
        menuTcpStreamGraphs = new QMenu(menuStatistics);
        menuTcpStreamGraphs->setObjectName(QString::fromUtf8("menuTcpStreamGraphs"));
        menuBACnet = new QMenu(menuStatistics);
        menuBACnet->setObjectName(QString::fromUtf8("menuBACnet"));
        menuHTTP = new QMenu(menuStatistics);
        menuHTTP->setObjectName(QString::fromUtf8("menuHTTP"));
        menu29West = new QMenu(menuStatistics);
        menu29West->setObjectName(QString::fromUtf8("menu29West"));
        menu29WestTopics = new QMenu(menu29West);
        menu29WestTopics->setObjectName(QString::fromUtf8("menu29WestTopics"));
        menu29WestQueues = new QMenu(menu29West);
        menu29WestQueues->setObjectName(QString::fromUtf8("menu29WestQueues"));
        menu29WestUIM = new QMenu(menu29West);
        menu29WestUIM->setObjectName(QString::fromUtf8("menu29WestUIM"));
        menuServiceResponseTime = new QMenu(menuStatistics);
        menuServiceResponseTime->setObjectName(QString::fromUtf8("menuServiceResponseTime"));
        menuTelephony = new QMenu(menuBar);
        menuTelephony->setObjectName(QString::fromUtf8("menuTelephony"));
        menuRTSP = new QMenu(menuTelephony);
        menuRTSP->setObjectName(QString::fromUtf8("menuRTSP"));
        menuRTP = new QMenu(menuTelephony);
        menuRTP->setObjectName(QString::fromUtf8("menuRTP"));
        menuTelephonySCTP = new QMenu(menuTelephony);
        menuTelephonySCTP->setObjectName(QString::fromUtf8("menuTelephonySCTP"));
        menuANSI = new QMenu(menuTelephony);
        menuANSI->setObjectName(QString::fromUtf8("menuANSI"));
        menuGSM = new QMenu(menuTelephony);
        menuGSM->setObjectName(QString::fromUtf8("menuGSM"));
        menuLTE = new QMenu(menuTelephony);
        menuLTE->setObjectName(QString::fromUtf8("menuLTE"));
        menuMTP3 = new QMenu(menuTelephony);
        menuMTP3->setObjectName(QString::fromUtf8("menuMTP3"));
        menuOsmux = new QMenu(menuTelephony);
        menuOsmux->setObjectName(QString::fromUtf8("menuOsmux"));
        menuEdit = new QMenu(menuBar);
        menuEdit->setObjectName(QString::fromUtf8("menuEdit"));
        menuEditCopy = new QMenu(menuEdit);
        menuEditCopy->setObjectName(QString::fromUtf8("menuEditCopy"));
        menuWireless = new QMenu(menuBar);
        menuWireless->setObjectName(QString::fromUtf8("menuWireless"));
        menuTools = new QMenu(menuBar);
        menuTools->setObjectName(QString::fromUtf8("menuTools"));
        MainWindow->setMenuBar(menuBar);
        mainToolBar = new QToolBar(MainWindow);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(mainToolBar->sizePolicy().hasHeightForWidth());
        mainToolBar->setSizePolicy(sizePolicy1);
        mainToolBar->setMovable(false);
        mainToolBar->setIconSize(QSize(32, 32));
        mainToolBar->setToolButtonStyle(Qt::ToolButtonIconOnly);
        MainWindow->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new MainStatusBar(MainWindow);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        MainWindow->setStatusBar(statusBar);
        displayFilterToolBar = new QToolBar(MainWindow);
        displayFilterToolBar->setObjectName(QString::fromUtf8("displayFilterToolBar"));
        displayFilterToolBar->setMovable(false);
        displayFilterToolBar->setIconSize(QSize(14, 14));
        MainWindow->addToolBar(Qt::TopToolBarArea, displayFilterToolBar);
        MainWindow->insertToolBarBreak(displayFilterToolBar);
        wirelessToolBar = new QToolBar(MainWindow);
        wirelessToolBar->setObjectName(QString::fromUtf8("wirelessToolBar"));
        wirelessToolBar->setMovable(false);
        MainWindow->addToolBar(Qt::TopToolBarArea, wirelessToolBar);
        MainWindow->insertToolBarBreak(wirelessToolBar);

        menuBar->addAction(menuFile->menuAction());
        menuBar->addAction(menuEdit->menuAction());
        menuBar->addAction(menuView->menuAction());
        menuBar->addAction(menuGo->menuAction());
        menuBar->addAction(menuCapture->menuAction());
        menuBar->addAction(menuAnalyze->menuAction());
        menuBar->addAction(menuStatistics->menuAction());
        menuBar->addAction(menuTelephony->menuAction());
        menuBar->addAction(menuWireless->menuAction());
        menuBar->addAction(menuTools->menuAction());
        menuBar->addAction(menuHelp->menuAction());
        menuFile->addAction(actionFileOpen);
        menuFile->addAction(menuOpenRecentCaptureFile->menuAction());
        menuFile->addAction(actionFileMerge);
        menuFile->addAction(actionFileImportFromHexDump);
        menuFile->addAction(actionFileClose);
        menuFile->addSeparator();
        menuFile->addAction(actionFileSave);
        menuFile->addAction(actionFileSaveAs);
        menuFile->addSeparator();
        menuFile->addAction(menuFileSet->menuAction());
        menuFile->addSeparator();
        menuFile->addAction(actionFileExportPackets);
        menuFile->addAction(menuFileExportPacketDissections->menuAction());
        menuFile->addAction(actionFileExportPacketBytes);
        menuFile->addAction(actionFileExportPDU);
        menuFile->addAction(actionFileExportTLSSessionKeys);
        menuFile->addAction(menuFileExportObjects->menuAction());
        menuFile->addSeparator();
        menuFile->addAction(actionFilePrint);
        menuFile->addSeparator();
        menuFile->addAction(actionFileQuit);
        menuOpenRecentCaptureFile->addAction(actionDummyNoFilesFound);
        menuFileSet->addAction(actionFileSetListFiles);
        menuFileSet->addAction(actionFileSetNextFile);
        menuFileSet->addAction(actionFileSetPreviousFile);
        menuFileExportPacketDissections->addAction(actionFileExportAsPlainText);
        menuFileExportPacketDissections->addAction(actionFileExportAsCSV);
        menuFileExportPacketDissections->addAction(actionFileExportAsCArrays);
        menuFileExportPacketDissections->addSeparator();
        menuFileExportPacketDissections->addAction(actionFileExportAsPSML);
        menuFileExportPacketDissections->addAction(actionFileExportAsPDML);
        menuFileExportPacketDissections->addAction(actionFileExportAsJSON);
        menuCapture->addAction(actionCaptureOptions);
        menuCapture->addAction(actionCaptureStart);
        menuCapture->addAction(actionCaptureStop);
        menuCapture->addAction(actionCaptureRestart);
        menuCapture->addAction(actionCaptureCaptureFilters);
        menuCapture->addAction(actionCaptureRefreshInterfaces);
        menuCapture->addSeparator();
        menuHelp->addAction(actionHelpContents);
        menuHelp->addAction(menuHelpManualPages->menuAction());
        menuHelp->addSeparator();
        menuHelp->addAction(actionHelpWebsite);
        menuHelp->addAction(actionHelpFAQ);
        menuHelp->addAction(actionHelpAsk);
        menuHelp->addAction(actionHelpDownloads);
        menuHelp->addSeparator();
        menuHelp->addAction(actionHelpWiki);
        menuHelp->addAction(actionHelpSampleCaptures);
        menuHelp->addSeparator();
        menuHelp->addAction(actionHelpAbout);
        menuHelpManualPages->addAction(actionHelpMPWireshark);
        menuHelpManualPages->addAction(actionHelpMPWireshark_Filter);
        menuHelpManualPages->addSeparator();
        menuHelpManualPages->addAction(actionHelpMPCapinfos);
        menuHelpManualPages->addAction(actionHelpMPDumpcap);
        menuHelpManualPages->addAction(actionHelpMPEditcap);
        menuHelpManualPages->addAction(actionHelpMPMergecap);
        menuHelpManualPages->addAction(actionHelpMPRawShark);
        menuHelpManualPages->addAction(actionHelpMPReordercap);
        menuHelpManualPages->addAction(actionHelpMPText2cap);
        menuHelpManualPages->addAction(actionHelpMPTShark);
        menuGo->addAction(actionGoGoToPacket);
        menuGo->addAction(actionGoGoToLinkedPacket);
        menuGo->addSeparator();
        menuGo->addAction(actionGoNextPacket);
        menuGo->addAction(actionGoPreviousPacket);
        menuGo->addAction(actionGoFirstPacket);
        menuGo->addAction(actionGoLastPacket);
        menuGo->addAction(actionGoNextConversationPacket);
        menuGo->addAction(actionGoPreviousConversationPacket);
        menuGo->addAction(actionGoNextHistoryPacket);
        menuGo->addAction(actionGoPreviousHistoryPacket);
        menuGo->addSeparator();
        menuGo->addAction(actionGoAutoScroll);
        menuView->addAction(actionViewMainToolbar);
        menuView->addAction(actionViewFilterToolbar);
        menuView->addAction(actionViewWirelessToolbar);
        menuView->addAction(menuInterfaceToolbars->menuAction());
        menuView->addAction(menuAdditionalToolbars->menuAction());
        menuView->addAction(actionViewStatusBar);
        menuView->addSeparator();
        menuView->addAction(actionViewFullScreen);
        menuView->addSeparator();
        menuView->addAction(actionViewPacketList);
        menuView->addAction(actionViewPacketDetails);
        menuView->addAction(actionViewPacketBytes);
        menuView->addSeparator();
        menuView->addAction(menuTime_Display_Format->menuAction());
        menuView->addAction(menuName_Resolution->menuAction());
        menuView->addSeparator();
        menuView->addAction(menuZoom->menuAction());
        menuView->addSeparator();
        menuView->addAction(actionViewExpandSubtrees);
        menuView->addAction(actionViewCollapseSubtrees);
        menuView->addAction(actionViewExpandAll);
        menuView->addAction(actionViewCollapseAll);
        menuView->addSeparator();
        menuView->addAction(actionViewColorizePacketList);
        menuView->addAction(actionViewColoringRules);
        menuView->addAction(menuColorizeConversation->menuAction());
        menuView->addSeparator();
        menuView->addAction(actionViewResetLayout);
        menuView->addAction(actionViewResizeColumns);
        menuView->addSeparator();
        menuView->addAction(menuInternals->menuAction());
        menuView->addSeparator();
        menuView->addAction(actionViewShowPacketInNewWindow);
        menuView->addAction(actionViewReload_as_File_Format_or_Capture);
        menuView->addAction(actionViewReload);
        menuZoom->addAction(actionViewZoomIn);
        menuZoom->addAction(actionViewZoomOut);
        menuZoom->addAction(actionViewNormalSize);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatDateYMDandTimeOfDay);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatDateYDOYandTimeOfDay);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatTimeOfDay);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatSecondsSinceEpoch);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatUTCTimeOfDay);
        menuTime_Display_Format->addSeparator();
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatPrecisionAutomatic);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatPrecisionSeconds);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatPrecisionDeciseconds);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatPrecisionCentiseconds);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatPrecisionMilliseconds);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatPrecisionMicroseconds);
        menuTime_Display_Format->addAction(actionViewTimeDisplayFormatPrecisionNanoseconds);
        menuTime_Display_Format->addSeparator();
        menuTime_Display_Format->addAction(actionViewTimeDisplaySecondsWithHoursAndMinutes);
        menuName_Resolution->addAction(actionViewEditResolvedName);
        menuName_Resolution->addSeparator();
        menuName_Resolution->addAction(actionViewNameResolutionPhysical);
        menuName_Resolution->addAction(actionViewNameResolutionNetwork);
        menuName_Resolution->addAction(actionViewNameResolutionTransport);
        menuColorizeConversation->addAction(actionViewColorizeConversation1);
        menuColorizeConversation->addAction(actionViewColorizeConversation2);
        menuColorizeConversation->addAction(actionViewColorizeConversation3);
        menuColorizeConversation->addAction(actionViewColorizeConversation4);
        menuColorizeConversation->addAction(actionViewColorizeConversation5);
        menuColorizeConversation->addAction(actionViewColorizeConversation6);
        menuColorizeConversation->addAction(actionViewColorizeConversation7);
        menuColorizeConversation->addAction(actionViewColorizeConversation8);
        menuColorizeConversation->addAction(actionViewColorizeConversation9);
        menuColorizeConversation->addAction(actionViewColorizeConversation10);
        menuColorizeConversation->addSeparator();
        menuColorizeConversation->addAction(actionViewColorizeResetColorization);
        menuColorizeConversation->addAction(actionViewColorizeNewColoringRule);
        menuInternals->addAction(actionViewInternalsConversationHashTables);
        menuInternals->addAction(actionViewInternalsDissectorTables);
        menuInternals->addAction(actionViewInternalsSupportedProtocols);
        menuAnalyze->addAction(actionAnalyzeDisplayFilters);
        menuAnalyze->addAction(actionAnalyzeDisplayFilterMacros);
        menuAnalyze->addSeparator();
        menuAnalyze->addAction(actionAnalyzeCreateAColumn);
        menuAnalyze->addAction(menuApplyAsFilter->menuAction());
        menuAnalyze->addAction(menuPrepareAFilter->menuAction());
        menuAnalyze->addAction(menuConversationFilter->menuAction());
        menuAnalyze->addSeparator();
        menuAnalyze->addAction(actionAnalyzeEnabledProtocols);
        menuAnalyze->addAction(actionAnalyzeDecodeAs);
        menuAnalyze->addAction(actionAnalyzeReloadLuaPlugins);
        menuAnalyze->addSeparator();
        menuAnalyze->addAction(menuSCTP->menuAction());
        menuAnalyze->addAction(menuFollow->menuAction());
        menuAnalyze->addSeparator();
        menuAnalyze->addAction(actionAnalyzeShowPacketBytes);
        menuAnalyze->addAction(actionAnalyzeExpertInfo);
        menuApplyAsFilter->addAction(actionAnalyzeAAFSelected);
        menuApplyAsFilter->addAction(actionAnalyzeAAFNotSelected);
        menuApplyAsFilter->addAction(actionAnalyzeAAFAndSelected);
        menuApplyAsFilter->addAction(actionAnalyzeAAFOrSelected);
        menuApplyAsFilter->addAction(actionAnalyzeAAFAndNotSelected);
        menuApplyAsFilter->addAction(actionAnalyzeAAFOrNotSelected);
        menuPrepareAFilter->addAction(actionAnalyzePAFSelected);
        menuPrepareAFilter->addAction(actionAnalyzePAFNotSelected);
        menuPrepareAFilter->addAction(actionAnalyzePAFAndSelected);
        menuPrepareAFilter->addAction(actionAnalyzePAFOrSelected);
        menuPrepareAFilter->addAction(actionAnalyzePAFAndNotSelected);
        menuPrepareAFilter->addAction(actionAnalyzePAFOrNotSelected);
        menuSCTP->addAction(actionSCTPAnalyseThisAssociation);
        menuSCTP->addAction(actionSCTPShowAllAssociations);
        menuFollow->addAction(actionAnalyzeFollowTCPStream);
        menuFollow->addAction(actionAnalyzeFollowUDPStream);
        menuFollow->addAction(actionAnalyzeFollowTLSStream);
        menuFollow->addAction(actionAnalyzeFollowHTTPStream);
        menuStatistics->addAction(actionStatisticsCaptureFileProperties);
        menuStatistics->addAction(actionStatisticsResolvedAddresses);
        menuStatistics->addAction(actionStatisticsProtocolHierarchy);
        menuStatistics->addAction(actionStatisticsConversations);
        menuStatistics->addAction(actionStatisticsEndpoints);
        menuStatistics->addAction(actionStatisticsPacketLengths);
        menuStatistics->addAction(actionStatisticsIOGraph);
        menuStatistics->addAction(menuServiceResponseTime->menuAction());
        menuStatistics->addSeparator();
        menuStatistics->addAction(actionStatistics_REGISTER_STAT_GROUP_UNSORTED);
        menuStatistics->addAction(menu29West->menuAction());
        menuStatistics->addAction(actionStatisticsANCP);
        menuStatistics->addAction(menuBACnet->menuAction());
        menuStatistics->addAction(actionStatisticsCollectd);
        menuStatistics->addAction(actionStatisticsDNS);
        menuStatistics->addAction(actionStatisticsFlowGraph);
        menuStatistics->addAction(actionStatisticsHART_IP);
        menuStatistics->addAction(actionStatisticsHpfeeds);
        menuStatistics->addAction(menuHTTP->menuAction());
        menuStatistics->addAction(actionStatisticsHTTP2);
        menuStatistics->addAction(actionStatisticsSametime);
        menuStatistics->addAction(menuTcpStreamGraphs->menuAction());
        menuStatistics->addAction(actionStatisticsUdpMulticastStreams);
        menuTcpStreamGraphs->addAction(actionStatisticsTcpStreamStevens);
        menuTcpStreamGraphs->addAction(actionStatisticsTcpStreamTcptrace);
        menuTcpStreamGraphs->addAction(actionStatisticsTcpStreamThroughput);
        menuTcpStreamGraphs->addAction(actionStatisticsTcpStreamRoundTripTime);
        menuTcpStreamGraphs->addAction(actionStatisticsTcpStreamWindowScaling);
        menuBACnet->addAction(actionStatisticsBACappInstanceId);
        menuBACnet->addAction(actionStatisticsBACappIP);
        menuBACnet->addAction(actionStatisticsBACappObjectId);
        menuBACnet->addAction(actionStatisticsBACappService);
        menuHTTP->addAction(actionStatisticsHTTPPacketCounter);
        menuHTTP->addAction(actionStatisticsHTTPRequests);
        menuHTTP->addAction(actionStatisticsHTTPLoadDistribution);
        menuHTTP->addAction(actionStatisticsHTTPRequestSequences);
        menu29West->addAction(menu29WestTopics->menuAction());
        menu29West->addAction(menu29WestQueues->menuAction());
        menu29West->addAction(menu29WestUIM->menuAction());
        menu29West->addAction(actionStatistics29WestLBTRM);
        menu29West->addAction(actionStatistics29WestLBTRU);
        menu29WestTopics->addAction(actionStatistics29WestTopics_Advertisements_by_Topic);
        menu29WestTopics->addAction(actionStatistics29WestTopics_Advertisements_by_Source);
        menu29WestTopics->addAction(actionStatistics29WestTopics_Advertisements_by_Transport);
        menu29WestTopics->addAction(actionStatistics29WestTopics_Queries_by_Topic);
        menu29WestTopics->addAction(actionStatistics29WestTopics_Queries_by_Receiver);
        menu29WestTopics->addAction(actionStatistics29WestTopics_Wildcard_Queries_by_Pattern);
        menu29WestTopics->addAction(actionStatistics29WestTopics_Wildcard_Queries_by_Receiver);
        menu29WestQueues->addAction(actionStatistics29WestQueues_Advertisements_by_Queue);
        menu29WestQueues->addAction(actionStatistics29WestQueues_Advertisements_by_Source);
        menu29WestQueues->addAction(actionStatistics29WestQueues_Queries_by_Queue);
        menu29WestQueues->addAction(actionStatistics29WestQueues_Queries_by_Receiver);
        menu29WestUIM->addAction(actionStatistics29WestUIM_Streams);
        menuTelephony->addAction(actionTelephonyVoipCalls);
        menuTelephony->addAction(menuANSI->menuAction());
        menuTelephony->addAction(menuGSM->menuAction());
        menuTelephony->addAction(actionTelephonyIax2StreamAnalysis);
        menuTelephony->addAction(actionTelephonyISUPMessages);
        menuTelephony->addAction(menuLTE->menuAction());
        menuTelephony->addAction(menuMTP3->menuAction());
        menuTelephony->addAction(menuOsmux->menuAction());
        menuTelephony->addAction(menuRTP->menuAction());
        menuTelephony->addAction(menuRTSP->menuAction());
        menuTelephony->addAction(menuTelephonySCTP->menuAction());
        menuTelephony->addAction(actionTelephonySMPPOperations);
        menuTelephony->addAction(actionTelephonyUCPMessages);
        menuRTSP->addAction(actionTelephonyRTSPPacketCounter);
        menuRTP->addAction(actionTelephonyRTPStreams);
        menuRTP->addAction(actionTelephonyRTPStreamAnalysis);
        menuTelephonySCTP->addAction(actionSCTPAnalyseThisAssociation);
        menuTelephonySCTP->addAction(actionSCTPShowAllAssociations);
        menuANSI->addAction(actionTelephonyANSIPlaceholder);
        menuGSM->addAction(actionTelephonyGSMPlaceholder);
        menuLTE->addAction(actionTelephonyLTEPlaceholder);
        menuMTP3->addAction(actionTelephonyMTP3Placeholder);
        menuOsmux->addAction(actionTelephonyOsmuxPacketCounter);
        menuEdit->addAction(menuEditCopy->menuAction());
        menuEdit->addAction(actionEditFindPacket);
        menuEdit->addAction(actionEditFindNext);
        menuEdit->addAction(actionEditFindPrevious);
        menuEdit->addSeparator();
        menuEdit->addAction(actionEditMarkPacket);
        menuEdit->addAction(actionEditMarkAllDisplayed);
        menuEdit->addAction(actionEditUnmarkAllDisplayed);
        menuEdit->addAction(actionEditNextMark);
        menuEdit->addAction(actionEditPreviousMark);
        menuEdit->addSeparator();
        menuEdit->addAction(actionEditIgnorePacket);
        menuEdit->addAction(actionEditIgnoreAllDisplayed);
        menuEdit->addAction(actionEditUnignoreAllDisplayed);
        menuEdit->addSeparator();
        menuEdit->addAction(actionEditSetTimeReference);
        menuEdit->addAction(actionEditUnsetAllTimeReferences);
        menuEdit->addAction(actionEditNextTimeReference);
        menuEdit->addAction(actionEditPreviousTimeReference);
        menuEdit->addSeparator();
        menuEdit->addAction(actionEditTimeShift);
        menuEdit->addSeparator();
        menuEdit->addAction(actionEditPacketComment);
        menuEdit->addAction(actionDeleteAllPacketComments);
        menuEdit->addSeparator();
        menuEdit->addAction(actionEditConfigurationProfiles);
        menuEdit->addAction(actionEditPreferences);
        menuEditCopy->addAction(actionCopyAllVisibleItems);
        menuEditCopy->addAction(actionCopyAllVisibleSelectedTreeItems);
        menuEditCopy->addAction(actionEditCopyDescription);
        menuEditCopy->addAction(actionEditCopyFieldName);
        menuEditCopy->addAction(actionEditCopyValue);
        menuEditCopy->addSeparator();
        menuEditCopy->addAction(actionEditCopyAsFilter);
        menuWireless->addAction(actionBluetoothATT_Server_Attributes);
        menuWireless->addAction(actionBluetoothDevices);
        menuWireless->addAction(actionBluetoothHCI_Summary);
        menuWireless->addSeparator();
        menuWireless->addAction(actionWirelessWlanStatistics);
        menuTools->addAction(actionToolsFirewallAclRules);
        mainToolBar->addAction(actionCaptureStart);
        mainToolBar->addAction(actionCaptureStop);
        mainToolBar->addAction(actionCaptureRestart);
        mainToolBar->addAction(actionCaptureOptions);
        mainToolBar->addSeparator();
        mainToolBar->addAction(actionFileOpen);
        mainToolBar->addAction(actionFileSave);
        mainToolBar->addAction(actionFileClose);
        mainToolBar->addAction(actionViewReload);
        mainToolBar->addSeparator();
        mainToolBar->addAction(actionEditFindPacket);
        mainToolBar->addAction(actionGoPreviousPacket);
        mainToolBar->addAction(actionGoNextPacket);
        mainToolBar->addAction(actionGoGoToPacket);
        mainToolBar->addAction(actionGoFirstPacket);
        mainToolBar->addAction(actionGoLastPacket);
        mainToolBar->addAction(actionGoAutoScroll);
        mainToolBar->addSeparator();
        mainToolBar->addAction(actionViewColorizePacketList);
        mainToolBar->addSeparator();
        mainToolBar->addAction(actionViewZoomIn);
        mainToolBar->addAction(actionViewZoomOut);
        mainToolBar->addAction(actionViewNormalSize);
        mainToolBar->addAction(actionViewResizeColumns);
        displayFilterToolBar->addAction(actionDisplayFilterExpression);
        displayFilterToolBar->addSeparator();
        displayFilterToolBar->addAction(actionNewDisplayFilterExpression);

        retranslateUi(MainWindow);
        QObject::connect(actionFileQuit, SIGNAL(triggered()), MainWindow, SLOT(close()));

        goToGo->setDefault(true);


        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "Wireshark", nullptr));
        actionFileOpen->setText(QApplication::translate("MainWindow", "&Open", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFileOpen->setToolTip(QApplication::translate("MainWindow", "Open a capture file", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileQuit->setText(QApplication::translate("MainWindow", "&Quit", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFileQuit->setToolTip(QApplication::translate("MainWindow", "Quit Wireshark", nullptr));
#endif // QT_NO_TOOLTIP
        actionCaptureStart->setText(QApplication::translate("MainWindow", "&Start", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCaptureStart->setToolTip(QApplication::translate("MainWindow", "Start capturing packets", nullptr));
#endif // QT_NO_TOOLTIP
        actionCaptureStop->setText(QApplication::translate("MainWindow", "S&top", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCaptureStop->setToolTip(QApplication::translate("MainWindow", "Stop capturing packets", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileClose->setText(QApplication::translate("MainWindow", "&Close", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFileClose->setToolTip(QApplication::translate("MainWindow", "Close this capture file", nullptr));
#endif // QT_NO_TOOLTIP
        actionDummyNoFilesFound->setText(QApplication::translate("MainWindow", "No files found", nullptr));
        actionHelpContents->setText(QApplication::translate("MainWindow", "&Contents", nullptr));
#ifndef QT_NO_TOOLTIP
        actionHelpContents->setToolTip(QApplication::translate("MainWindow", "Help contents", nullptr));
#endif // QT_NO_TOOLTIP
        actionHelpMPWireshark->setText(QApplication::translate("MainWindow", "Wireshark", nullptr));
        actionHelpMPWireshark_Filter->setText(QApplication::translate("MainWindow", "Wireshark Filter", nullptr));
        actionHelpMPTShark->setText(QApplication::translate("MainWindow", "TShark", nullptr));
        actionHelpMPRawShark->setText(QApplication::translate("MainWindow", "RawShark", nullptr));
        actionHelpMPDumpcap->setText(QApplication::translate("MainWindow", "Dumpcap", nullptr));
        actionHelpMPMergecap->setText(QApplication::translate("MainWindow", "Mergecap", nullptr));
        actionHelpMPEditcap->setText(QApplication::translate("MainWindow", "Editcap", nullptr));
        actionHelpMPText2cap->setText(QApplication::translate("MainWindow", "Text2cap", nullptr));
        actionHelpWebsite->setText(QApplication::translate("MainWindow", "Website", nullptr));
        actionHelpFAQ->setText(QApplication::translate("MainWindow", "FAQ's", nullptr));
        actionHelpDownloads->setText(QApplication::translate("MainWindow", "Downloads", nullptr));
        actionHelpWiki->setText(QApplication::translate("MainWindow", "Wiki", nullptr));
        actionHelpSampleCaptures->setText(QApplication::translate("MainWindow", "Sample Captures", nullptr));
        actionHelpAbout->setText(QApplication::translate("MainWindow", "&About Wireshark", nullptr));
        actionHelpAsk->setText(QApplication::translate("MainWindow", "Ask (Q&&A)", nullptr));
        actionGoNextPacket->setText(QApplication::translate("MainWindow", "Next Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoNextPacket->setToolTip(QApplication::translate("MainWindow", "Go to the next packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoPreviousPacket->setText(QApplication::translate("MainWindow", "Previous Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoPreviousPacket->setToolTip(QApplication::translate("MainWindow", "Go to the previous packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoNextConversationPacket->setText(QApplication::translate("MainWindow", "Next Packet in Conversation", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoNextConversationPacket->setToolTip(QApplication::translate("MainWindow", "Go to the next packet in this conversation", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoPreviousConversationPacket->setText(QApplication::translate("MainWindow", "Previous Packet in Conversation", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoPreviousConversationPacket->setToolTip(QApplication::translate("MainWindow", "Go to the previous packet in this conversation", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoNextHistoryPacket->setText(QApplication::translate("MainWindow", "Next Packet In History", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoNextHistoryPacket->setToolTip(QApplication::translate("MainWindow", "Go to the next packet in your selection history", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoPreviousHistoryPacket->setText(QApplication::translate("MainWindow", "Previous Packet In History", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoPreviousHistoryPacket->setToolTip(QApplication::translate("MainWindow", "Go to the previous packet in your selection history", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoFirstPacket->setText(QApplication::translate("MainWindow", "First Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoFirstPacket->setToolTip(QApplication::translate("MainWindow", "Go to the first packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoLastPacket->setText(QApplication::translate("MainWindow", "Last Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoLastPacket->setToolTip(QApplication::translate("MainWindow", "Go to the last packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewExpandSubtrees->setText(QApplication::translate("MainWindow", "E&xpand Subtrees", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewExpandSubtrees->setToolTip(QApplication::translate("MainWindow", "Expand the current packet detail", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewCollapseSubtrees->setText(QApplication::translate("MainWindow", "Collapse Subtrees", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewCollapseSubtrees->setToolTip(QApplication::translate("MainWindow", "Collapse the current packet detail", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewExpandAll->setText(QApplication::translate("MainWindow", "&Expand All", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewExpandAll->setToolTip(QApplication::translate("MainWindow", "Expand packet details", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewCollapseAll->setText(QApplication::translate("MainWindow", "Collapse &All", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewCollapseAll->setToolTip(QApplication::translate("MainWindow", "Collapse all packet details", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoGoToPacket->setText(QApplication::translate("MainWindow", "Go to Packet\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoGoToPacket->setToolTip(QApplication::translate("MainWindow", "Go to specified packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileMerge->setText(QApplication::translate("MainWindow", "&Merge\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFileMerge->setToolTip(QApplication::translate("MainWindow", "Merge one or more files", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileImportFromHexDump->setText(QApplication::translate("MainWindow", "&Import from Hex Dump\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFileImportFromHexDump->setToolTip(QApplication::translate("MainWindow", "Import a file", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileSave->setText(QApplication::translate("MainWindow", "&Save", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFileSave->setToolTip(QApplication::translate("MainWindow", "Save this capture file", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileSaveAs->setText(QApplication::translate("MainWindow", "Save &As\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFileSaveAs->setToolTip(QApplication::translate("MainWindow", "Save as a different file", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileExportPackets->setText(QApplication::translate("MainWindow", "Export Specified Packets\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFileExportPackets->setToolTip(QApplication::translate("MainWindow", "Export specified packets", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileExportPacketBytes->setText(QApplication::translate("MainWindow", "Export Packet &Bytes\342\200\246", nullptr));
        actionFileExportTLSSessionKeys->setText(QApplication::translate("MainWindow", "Export TLS Session Keys\342\200\246", nullptr));
        actionFilePrint->setText(QApplication::translate("MainWindow", "&Print\342\200\246", nullptr));
        actionFileSetListFiles->setText(QApplication::translate("MainWindow", "List Files", nullptr));
        actionFileSetNextFile->setText(QApplication::translate("MainWindow", "Next File", nullptr));
        actionFileSetPreviousFile->setText(QApplication::translate("MainWindow", "Previous File", nullptr));
        actionViewReload->setText(QApplication::translate("MainWindow", "&Reload", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewReload->setToolTip(QApplication::translate("MainWindow", "Reload this file", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewReload_as_File_Format_or_Capture->setText(QApplication::translate("MainWindow", "Reload as File Format/Capture", nullptr));
        actionCaptureOptions->setText(QApplication::translate("MainWindow", "&Options\342\200\246", nullptr));
        actionCaptureOptions->setIconText(QApplication::translate("MainWindow", "Options", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCaptureOptions->setToolTip(QApplication::translate("MainWindow", "Capture options", nullptr));
#endif // QT_NO_TOOLTIP
        actionCaptureCaptureFilters->setText(QApplication::translate("MainWindow", "Capture &Filters\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCaptureCaptureFilters->setToolTip(QApplication::translate("MainWindow", "Capture filters", nullptr));
#endif // QT_NO_TOOLTIP
        actionCaptureRefreshInterfaces->setText(QApplication::translate("MainWindow", "Refresh Interfaces", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCaptureRefreshInterfaces->setToolTip(QApplication::translate("MainWindow", "Refresh interfaces", nullptr));
#endif // QT_NO_TOOLTIP
        actionCaptureRestart->setText(QApplication::translate("MainWindow", "&Restart", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCaptureRestart->setToolTip(QApplication::translate("MainWindow", "Restart current capture", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileExportAsPlainText->setText(QApplication::translate("MainWindow", "As Plain &Text\342\200\246", nullptr));
        actionFileExportAsCSV->setText(QApplication::translate("MainWindow", "As &CSV\342\200\246", nullptr));
        actionFileExportAsCArrays->setText(QApplication::translate("MainWindow", "As \"C\" &Arrays\342\200\246", nullptr));
        actionFileExportAsPSML->setText(QApplication::translate("MainWindow", "As P&SML XML\342\200\246", nullptr));
        actionFileExportAsPDML->setText(QApplication::translate("MainWindow", "As P&DML XML\342\200\246", nullptr));
        actionFileExportAsJSON->setText(QApplication::translate("MainWindow", "As &JSON\342\200\246", nullptr));
        actionEditCopyDescription->setText(QApplication::translate("MainWindow", "Description", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditCopyDescription->setToolTip(QApplication::translate("MainWindow", "Copy this item's description", nullptr));
#endif // QT_NO_TOOLTIP
        actionCopyAllVisibleItems->setText(QApplication::translate("MainWindow", "All Visible Items", nullptr));
        actionCopyAllVisibleSelectedTreeItems->setText(QApplication::translate("MainWindow", "All Visible Selected Tree Items", nullptr));
        actionEditCopyFieldName->setText(QApplication::translate("MainWindow", "Field Name", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditCopyFieldName->setToolTip(QApplication::translate("MainWindow", "Copy this item's field name", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditCopyValue->setText(QApplication::translate("MainWindow", "Value", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditCopyValue->setToolTip(QApplication::translate("MainWindow", "Copy this item's value", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditCopyAsFilter->setText(QApplication::translate("MainWindow", "As Filter", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditCopyAsFilter->setToolTip(QApplication::translate("MainWindow", "Copy this item as a display filter", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeAAFSelected->setText(QApplication::translate("MainWindow", "&Selected", nullptr));
        actionAnalyzeAAFNotSelected->setText(QApplication::translate("MainWindow", "&Not Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeAAFNotSelected->setToolTip(QApplication::translate("MainWindow", "Not Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeAAFAndSelected->setText(QApplication::translate("MainWindow", "\342\200\246&and Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeAAFAndSelected->setToolTip(QApplication::translate("MainWindow", "\342\200\246and Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeAAFOrSelected->setText(QApplication::translate("MainWindow", "\342\200\246&or Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeAAFOrSelected->setToolTip(QApplication::translate("MainWindow", "\342\200\246or Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeAAFAndNotSelected->setText(QApplication::translate("MainWindow", "\342\200\246a&nd not Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeAAFAndNotSelected->setToolTip(QApplication::translate("MainWindow", "\342\200\246and not Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeAAFOrNotSelected->setText(QApplication::translate("MainWindow", "\342\200\246o&r not Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeAAFOrNotSelected->setToolTip(QApplication::translate("MainWindow", "\342\200\246or not Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzePAFSelected->setText(QApplication::translate("MainWindow", "&Selected", nullptr));
        actionAnalyzePAFNotSelected->setText(QApplication::translate("MainWindow", "&Not Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzePAFNotSelected->setToolTip(QApplication::translate("MainWindow", "Not Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzePAFAndSelected->setText(QApplication::translate("MainWindow", "\342\200\246&and Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzePAFAndSelected->setToolTip(QApplication::translate("MainWindow", "\342\200\246and Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzePAFOrSelected->setText(QApplication::translate("MainWindow", "\342\200\246&or Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzePAFOrSelected->setToolTip(QApplication::translate("MainWindow", "\342\200\246or Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzePAFAndNotSelected->setText(QApplication::translate("MainWindow", "\342\200\246a&nd not Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzePAFAndNotSelected->setToolTip(QApplication::translate("MainWindow", "\342\200\246and not Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzePAFOrNotSelected->setText(QApplication::translate("MainWindow", "\342\200\246o&r not Selected", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzePAFOrNotSelected->setToolTip(QApplication::translate("MainWindow", "\342\200\246or not Selected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeDisplayFilters->setText(QApplication::translate("MainWindow", "Display &Filters\342\200\246", nullptr));
        actionAnalyzeDisplayFilterMacros->setText(QApplication::translate("MainWindow", "Display Filter &Macros\342\200\246", nullptr));
        actionAnalyzeCreateAColumn->setText(QApplication::translate("MainWindow", "Apply as Column", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeCreateAColumn->setToolTip(QApplication::translate("MainWindow", "Create a packet list column from the selected field.", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditFindPacket->setText(QApplication::translate("MainWindow", "&Find Packet\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditFindPacket->setToolTip(QApplication::translate("MainWindow", "Find a packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditFindNext->setText(QApplication::translate("MainWindow", "Find Ne&xt", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditFindNext->setToolTip(QApplication::translate("MainWindow", "Find the next packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditFindPrevious->setText(QApplication::translate("MainWindow", "Find Pre&vious", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditFindPrevious->setToolTip(QApplication::translate("MainWindow", "Find the previous packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditMarkPacket->setText(QApplication::translate("MainWindow", "&Mark/Unmark Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditMarkPacket->setToolTip(QApplication::translate("MainWindow", "Mark or unmark this packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditMarkAllDisplayed->setText(QApplication::translate("MainWindow", "Mark All Displayed", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditMarkAllDisplayed->setToolTip(QApplication::translate("MainWindow", "Mark all displayed packets", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditUnmarkAllDisplayed->setText(QApplication::translate("MainWindow", "&Unmark All Displayed", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditUnmarkAllDisplayed->setToolTip(QApplication::translate("MainWindow", "Unmark all displayed packets", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditNextMark->setText(QApplication::translate("MainWindow", "Next Mark", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditNextMark->setToolTip(QApplication::translate("MainWindow", "Go to the next marked packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditPreviousMark->setText(QApplication::translate("MainWindow", "Previous Mark", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditPreviousMark->setToolTip(QApplication::translate("MainWindow", "Go to the previous marked packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditIgnorePacket->setText(QApplication::translate("MainWindow", "&Ignore/Unignore Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditIgnorePacket->setToolTip(QApplication::translate("MainWindow", "Ignore or unignore this packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditIgnoreAllDisplayed->setText(QApplication::translate("MainWindow", "Ignore All Displayed", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditIgnoreAllDisplayed->setToolTip(QApplication::translate("MainWindow", "Ignore all displayed packets", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditUnignoreAllDisplayed->setText(QApplication::translate("MainWindow", "Unignore All Displayed", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditUnignoreAllDisplayed->setToolTip(QApplication::translate("MainWindow", "U&nignore all displayed packets", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditSetTimeReference->setText(QApplication::translate("MainWindow", "Set/Unset Time Reference", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditSetTimeReference->setToolTip(QApplication::translate("MainWindow", "Set or unset a time reference for this packet", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditUnsetAllTimeReferences->setText(QApplication::translate("MainWindow", "Unset All Time References", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditUnsetAllTimeReferences->setToolTip(QApplication::translate("MainWindow", "Remove all time references", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditNextTimeReference->setText(QApplication::translate("MainWindow", "Next Time Reference", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditNextTimeReference->setToolTip(QApplication::translate("MainWindow", "Go to the next time reference", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditPreviousTimeReference->setText(QApplication::translate("MainWindow", "Previous Time Reference", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditPreviousTimeReference->setToolTip(QApplication::translate("MainWindow", "Go to the previous time reference", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditTimeShift->setText(QApplication::translate("MainWindow", "Time Shift\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditTimeShift->setToolTip(QApplication::translate("MainWindow", "Shift or change packet timestamps", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditPacketComment->setText(QApplication::translate("MainWindow", "Packet Comment\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditPacketComment->setToolTip(QApplication::translate("MainWindow", "Add or change a packet comment", nullptr));
#endif // QT_NO_TOOLTIP
        actionDeleteAllPacketComments->setText(QApplication::translate("MainWindow", "Delete All Packet Comments", nullptr));
#ifndef QT_NO_TOOLTIP
        actionDeleteAllPacketComments->setToolTip(QApplication::translate("MainWindow", "Remove all packet comments in the capture file", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditConfigurationProfiles->setText(QApplication::translate("MainWindow", "&Configuration Profiles\342\200\246", nullptr));
        actionEditConfigurationProfiles->setIconText(QApplication::translate("MainWindow", "Configuration profiles", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditConfigurationProfiles->setToolTip(QApplication::translate("MainWindow", "Manage your configuration profiles", nullptr));
#endif // QT_NO_TOOLTIP
        actionEditPreferences->setText(QApplication::translate("MainWindow", "&Preferences\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionEditPreferences->setToolTip(QApplication::translate("MainWindow", "Manage Wireshark's preferences", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsCaptureFileProperties->setText(QApplication::translate("MainWindow", "Capture File Properties", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsCaptureFileProperties->setToolTip(QApplication::translate("MainWindow", "Capture file properties", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsProtocolHierarchy->setText(QApplication::translate("MainWindow", "&Protocol Hierarchy", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsProtocolHierarchy->setToolTip(QApplication::translate("MainWindow", "Show a summary of protocols present in the capture file.", nullptr));
#endif // QT_NO_TOOLTIP
        actionHelpMPCapinfos->setText(QApplication::translate("MainWindow", "Capinfos", nullptr));
        actionHelpMPReordercap->setText(QApplication::translate("MainWindow", "Reordercap", nullptr));
        actionStatisticsTcpStreamStevens->setText(QApplication::translate("MainWindow", "Time Sequence (Stevens)", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsTcpStreamStevens->setToolTip(QApplication::translate("MainWindow", "TCP time sequence graph (Stevens)", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsTcpStreamThroughput->setText(QApplication::translate("MainWindow", "Throughput", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsTcpStreamThroughput->setToolTip(QApplication::translate("MainWindow", "TCP througput", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsTcpStreamRoundTripTime->setText(QApplication::translate("MainWindow", "Round Trip Time", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsTcpStreamRoundTripTime->setToolTip(QApplication::translate("MainWindow", "TCP round trip time", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsTcpStreamWindowScaling->setText(QApplication::translate("MainWindow", "Window Scaling", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsTcpStreamWindowScaling->setToolTip(QApplication::translate("MainWindow", "TCP window scaling", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeFollowTCPStream->setText(QApplication::translate("MainWindow", "TCP Stream", nullptr));
        actionAnalyzeFollowUDPStream->setText(QApplication::translate("MainWindow", "UDP Stream", nullptr));
        actionAnalyzeFollowTLSStream->setText(QApplication::translate("MainWindow", "TLS Stream", nullptr));
        actionAnalyzeFollowHTTPStream->setText(QApplication::translate("MainWindow", "HTTP Stream", nullptr));
        actionStatisticsTcpStreamTcptrace->setText(QApplication::translate("MainWindow", "Time Sequence (tcptrace)", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsTcpStreamTcptrace->setToolTip(QApplication::translate("MainWindow", "TCP time sequence graph (tcptrace)", nullptr));
#endif // QT_NO_TOOLTIP
        actionSCTPAnalyseThisAssociation->setText(QApplication::translate("MainWindow", "Analyse this Association", nullptr));
        actionSCTPShowAllAssociations->setText(QApplication::translate("MainWindow", "Show All Associations", nullptr));
        actionStatisticsFlowGraph->setText(QApplication::translate("MainWindow", "Flow Graph", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsFlowGraph->setToolTip(QApplication::translate("MainWindow", "Flow sequence diagram", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsANCP->setText(QApplication::translate("MainWindow", "ANCP", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsANCP->setToolTip(QApplication::translate("MainWindow", "ANCP statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsBACappInstanceId->setText(QApplication::translate("MainWindow", "Packets sorted by Instance ID", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsBACappInstanceId->setToolTip(QApplication::translate("MainWindow", "BACapp statistics sorted by instance ID", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsBACappIP->setText(QApplication::translate("MainWindow", "Packets sorted by IP", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsBACappIP->setToolTip(QApplication::translate("MainWindow", "BACapp statistics sorted by IP", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsBACappObjectId->setText(QApplication::translate("MainWindow", "Packets sorted by object type", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsBACappObjectId->setToolTip(QApplication::translate("MainWindow", "BACapp statistics sorted by object type", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsBACappService->setText(QApplication::translate("MainWindow", "Packets sorted by service", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsBACappService->setToolTip(QApplication::translate("MainWindow", "BACapp statistics sorted by service", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsCollectd->setText(QApplication::translate("MainWindow", "Collectd", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsCollectd->setToolTip(QApplication::translate("MainWindow", "Collectd statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsDNS->setText(QApplication::translate("MainWindow", "DNS", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsDNS->setToolTip(QApplication::translate("MainWindow", "DNS statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsHART_IP->setText(QApplication::translate("MainWindow", "HART-IP", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsHART_IP->setToolTip(QApplication::translate("MainWindow", "HART-IP statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsHpfeeds->setText(QApplication::translate("MainWindow", "HPFEEDS", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsHpfeeds->setToolTip(QApplication::translate("MainWindow", "hpfeeds statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsHTTP2->setText(QApplication::translate("MainWindow", "HTTP2", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsHTTP2->setToolTip(QApplication::translate("MainWindow", "HTTP2 statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsHTTPPacketCounter->setText(QApplication::translate("MainWindow", "Packet Counter", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsHTTPPacketCounter->setToolTip(QApplication::translate("MainWindow", "HTTP packet counter", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsHTTPRequests->setText(QApplication::translate("MainWindow", "Requests", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsHTTPRequests->setToolTip(QApplication::translate("MainWindow", "HTTP requests", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsHTTPLoadDistribution->setText(QApplication::translate("MainWindow", "Load Distribution", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsHTTPLoadDistribution->setToolTip(QApplication::translate("MainWindow", "HTTP load distribution", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsHTTPRequestSequences->setText(QApplication::translate("MainWindow", "Request Sequences", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsHTTPRequestSequences->setToolTip(QApplication::translate("MainWindow", "HTTP Request Sequences", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsPacketLengths->setText(QApplication::translate("MainWindow", "Packet Lengths", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsPacketLengths->setToolTip(QApplication::translate("MainWindow", "Packet length statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsSametime->setText(QApplication::translate("MainWindow", "Sametime", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsSametime->setToolTip(QApplication::translate("MainWindow", "Sametime statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyISUPMessages->setText(QApplication::translate("MainWindow", "&ISUP Messages", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyISUPMessages->setToolTip(QApplication::translate("MainWindow", "ISUP message statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyOsmuxPacketCounter->setText(QApplication::translate("MainWindow", "Packet Counter", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyOsmuxPacketCounter->setToolTip(QApplication::translate("MainWindow", "Osmux packet counts", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyRTSPPacketCounter->setText(QApplication::translate("MainWindow", "Packet Counter", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyRTSPPacketCounter->setToolTip(QApplication::translate("MainWindow", "RTSP packet counts", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonySMPPOperations->setText(QApplication::translate("MainWindow", "SM&PP Operations", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonySMPPOperations->setToolTip(QApplication::translate("MainWindow", "SMPP operation statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyUCPMessages->setText(QApplication::translate("MainWindow", "&UCP Messages", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyUCPMessages->setToolTip(QApplication::translate("MainWindow", "UCP message statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeDecodeAs->setText(QApplication::translate("MainWindow", "Decode &As\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeDecodeAs->setToolTip(QApplication::translate("MainWindow", "Change the way packets are dissected", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeReloadLuaPlugins->setText(QApplication::translate("MainWindow", "Reload Lua Plugins", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeReloadLuaPlugins->setToolTip(QApplication::translate("MainWindow", "Reload Lua plugins", nullptr));
#endif // QT_NO_TOOLTIP
        action29West->setText(QApplication::translate("MainWindow", "29West", nullptr));
        actionStatistics29WestTopics_Advertisements_by_Topic->setText(QApplication::translate("MainWindow", "Advertisements by Topic", nullptr));
        actionStatistics29WestTopics_Advertisements_by_Source->setText(QApplication::translate("MainWindow", "Advertisements by Source", nullptr));
        actionStatistics29WestTopics_Advertisements_by_Transport->setText(QApplication::translate("MainWindow", "Advertisements by Transport", nullptr));
        actionStatistics29WestTopics_Queries_by_Topic->setText(QApplication::translate("MainWindow", "Queries by Topic", nullptr));
        actionStatistics29WestTopics_Queries_by_Receiver->setText(QApplication::translate("MainWindow", "Queries by Receiver", nullptr));
        actionStatistics29WestTopics_Wildcard_Queries_by_Pattern->setText(QApplication::translate("MainWindow", "Wildcard Queries by Pattern", nullptr));
        actionStatistics29WestTopics_Wildcard_Queries_by_Receiver->setText(QApplication::translate("MainWindow", "Wildcard Queries by Receiver", nullptr));
        actionStatistics29WestQueues_Advertisements_by_Queue->setText(QApplication::translate("MainWindow", "Advertisements by Queue", nullptr));
        actionStatistics29WestQueues_Advertisements_by_Source->setText(QApplication::translate("MainWindow", "Advertisements by Source", nullptr));
        actionStatistics29WestQueues_Queries_by_Queue->setText(QApplication::translate("MainWindow", "Queries by Queue", nullptr));
        actionStatistics29WestQueues_Queries_by_Receiver->setText(QApplication::translate("MainWindow", "Queries by Receiver", nullptr));
        actionStatistics29WestUIM_Streams->setText(QApplication::translate("MainWindow", "Streams", nullptr));
        actionStatistics29WestLBTRM->setText(QApplication::translate("MainWindow", "LBT-RM", nullptr));
        actionStatistics29WestLBTRU->setText(QApplication::translate("MainWindow", "LBT-RU", nullptr));
        actionSCTPFilterThisAssociation->setText(QApplication::translate("MainWindow", "Filter this Association", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSCTPFilterThisAssociation->setToolTip(QApplication::translate("MainWindow", "Filter this Association", nullptr));
#endif // QT_NO_TOOLTIP
        actionFileExportPDU->setText(QApplication::translate("MainWindow", "Export PDUs to File\342\200\246", nullptr));
        actionStatisticsIOGraph->setText(QApplication::translate("MainWindow", "&I/O Graph", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsIOGraph->setToolTip(QApplication::translate("MainWindow", "Create graphs based on display filter fields", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewMainToolbar->setText(QApplication::translate("MainWindow", "&Main Toolbar", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewMainToolbar->setToolTip(QApplication::translate("MainWindow", "Show or hide the main toolbar", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewFilterToolbar->setText(QApplication::translate("MainWindow", "&Filter Toolbar", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewFilterToolbar->setToolTip(QApplication::translate("MainWindow", "Show or hide the display filter toolbar", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsConversations->setText(QApplication::translate("MainWindow", "&Conversations", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsConversations->setToolTip(QApplication::translate("MainWindow", "Conversations at different protocol levels", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsEndpoints->setText(QApplication::translate("MainWindow", "&Endpoints", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsEndpoints->setToolTip(QApplication::translate("MainWindow", "Endpoints at different protocol levels", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizePacketList->setText(QApplication::translate("MainWindow", "Colorize Packet List", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizePacketList->setToolTip(QApplication::translate("MainWindow", "Draw packets using your coloring rules", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewZoomIn->setText(QApplication::translate("MainWindow", "&Zoom In", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewZoomIn->setToolTip(QApplication::translate("MainWindow", "Enlarge the main window text", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewZoomOut->setText(QApplication::translate("MainWindow", "Zoom Out", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewZoomOut->setToolTip(QApplication::translate("MainWindow", "Shrink the main window text", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewNormalSize->setText(QApplication::translate("MainWindow", "Normal Size", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewNormalSize->setToolTip(QApplication::translate("MainWindow", "Return the main window text to its normal size", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewResetLayout->setText(QApplication::translate("MainWindow", "Reset Layout", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewResetLayout->setToolTip(QApplication::translate("MainWindow", "Reset appearance layout to default size", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewResizeColumns->setText(QApplication::translate("MainWindow", "Resize Columns", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewResizeColumns->setToolTip(QApplication::translate("MainWindow", "Resize packet list columns to fit contents", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatDateYMDandTimeOfDay->setText(QApplication::translate("MainWindow", "Date and Time of Day", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatDateYMDandTimeOfDay->setToolTip(QApplication::translate("MainWindow", "Show packet times as the date and time of day.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatDateYDOYandTimeOfDay->setText(QApplication::translate("MainWindow", "Year, Day of Year, and Time of Day", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatDateYDOYandTimeOfDay->setToolTip(QApplication::translate("MainWindow", "Show packet times as the year, day of the year and time of day.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatTimeOfDay->setText(QApplication::translate("MainWindow", "Time of Day", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatTimeOfDay->setToolTip(QApplication::translate("MainWindow", "Show packet times as the date and time of day.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatSecondsSinceEpoch->setText(QApplication::translate("MainWindow", "Seconds Since 1970-01-01", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatSecondsSinceEpoch->setToolTip(QApplication::translate("MainWindow", "Show packet times as the seconds since the UNIX / POSIX epoch (1970-01-01).", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture->setText(QApplication::translate("MainWindow", "Seconds Since Beginning of Capture", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture->setToolTip(QApplication::translate("MainWindow", "Show packet times as the date and time of day.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket->setText(QApplication::translate("MainWindow", "Seconds Since Previous Captured Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket->setToolTip(QApplication::translate("MainWindow", "Show packet times as the seconds since the previous captured packet.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket->setText(QApplication::translate("MainWindow", "Seconds Since Previous Displayed Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket->setToolTip(QApplication::translate("MainWindow", "Show packet times as the seconds since the previous displayed packet.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay->setText(QApplication::translate("MainWindow", "UTC Date and Time of Day", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay->setToolTip(QApplication::translate("MainWindow", "Show packet times as the UTC date and time of day.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay->setText(QApplication::translate("MainWindow", "UTC Year, Day of Year, and Time of Day (1970/001 01:02:03.123456)", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay->setToolTip(QApplication::translate("MainWindow", "Show packet times as the UTC year, day of the year and time of day.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatUTCTimeOfDay->setText(QApplication::translate("MainWindow", "UTC Time of Day", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatUTCTimeOfDay->setToolTip(QApplication::translate("MainWindow", "Show packet times as the UTC time of day.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatPrecisionAutomatic->setText(QApplication::translate("MainWindow", "Automatic (from capture file)", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplayFormatPrecisionAutomatic->setToolTip(QApplication::translate("MainWindow", "Use the time precision indicated in the capture file.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewTimeDisplayFormatPrecisionSeconds->setText(QApplication::translate("MainWindow", "Seconds", nullptr));
        actionViewTimeDisplayFormatPrecisionDeciseconds->setText(QApplication::translate("MainWindow", "Tenths of a second", nullptr));
        actionViewTimeDisplayFormatPrecisionCentiseconds->setText(QApplication::translate("MainWindow", "Hundredths of a second", nullptr));
        actionViewTimeDisplayFormatPrecisionMilliseconds->setText(QApplication::translate("MainWindow", "Milliseconds", nullptr));
        actionViewTimeDisplayFormatPrecisionMicroseconds->setText(QApplication::translate("MainWindow", "Microseconds", nullptr));
        actionViewTimeDisplayFormatPrecisionNanoseconds->setText(QApplication::translate("MainWindow", "Nanoseconds", nullptr));
        actionViewTimeDisplaySecondsWithHoursAndMinutes->setText(QApplication::translate("MainWindow", "Display Seconds With Hours and Minutes", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewTimeDisplaySecondsWithHoursAndMinutes->setToolTip(QApplication::translate("MainWindow", "Display seconds with hours and minutes", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewNameResolutionPhysical->setText(QApplication::translate("MainWindow", "Resolve &Physical Addresses", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewNameResolutionPhysical->setToolTip(QApplication::translate("MainWindow", "Show names for known MAC addresses. Lookups use a local database.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewNameResolutionNetwork->setText(QApplication::translate("MainWindow", "Resolve &Network Addresses", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewNameResolutionNetwork->setToolTip(QApplication::translate("MainWindow", "Show names for known IPv4, IPv6, and IPX addresses. Lookups can generate network traffic.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewNameResolutionTransport->setText(QApplication::translate("MainWindow", "Resolve &Transport Addresses", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewNameResolutionTransport->setToolTip(QApplication::translate("MainWindow", "Show names for known TCP, UDP, and SCTP services. Lookups can generate traffic on some systems.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewWirelessToolbar->setText(QApplication::translate("MainWindow", "Wire&less Toolbar", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewWirelessToolbar->setToolTip(QApplication::translate("MainWindow", "Show or hide the wireless toolbar", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewStatusBar->setText(QApplication::translate("MainWindow", "&Status Bar", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewStatusBar->setToolTip(QApplication::translate("MainWindow", "Show or hide the status bar", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewPacketList->setText(QApplication::translate("MainWindow", "Packet &List", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewPacketList->setToolTip(QApplication::translate("MainWindow", "Show or hide the packet list", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewPacketDetails->setText(QApplication::translate("MainWindow", "Packet &Details", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewPacketDetails->setToolTip(QApplication::translate("MainWindow", "Show or hide the packet details", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewPacketBytes->setText(QApplication::translate("MainWindow", "Packet &Bytes", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewPacketBytes->setToolTip(QApplication::translate("MainWindow", "Show or hide the packet bytes", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewInternalsConversationHashTables->setText(QApplication::translate("MainWindow", "&Conversation Hash Tables", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewInternalsConversationHashTables->setToolTip(QApplication::translate("MainWindow", "Show each conversation hash table", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewInternalsDissectorTables->setText(QApplication::translate("MainWindow", "&Dissector Tables", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewInternalsDissectorTables->setToolTip(QApplication::translate("MainWindow", "Show each dissector table and its entries", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewInternalsSupportedProtocols->setText(QApplication::translate("MainWindow", "&Supported Protocols", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewInternalsSupportedProtocols->setToolTip(QApplication::translate("MainWindow", "Show the currently supported protocols and display filter fields", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyGsmMapSummary->setText(QApplication::translate("MainWindow", "MAP Summary", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyGsmMapSummary->setToolTip(QApplication::translate("MainWindow", "GSM MAP summary statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyLteMacStatistics->setText(QApplication::translate("MainWindow", "MAC Statistics", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyLteMacStatistics->setToolTip(QApplication::translate("MainWindow", "LTE MAC statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyLteRlcStatistics->setText(QApplication::translate("MainWindow", "RLC Statistics", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyLteRlcStatistics->setToolTip(QApplication::translate("MainWindow", "LTE RLC statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyLteRlcGraph->setText(QApplication::translate("MainWindow", "RLC &Graph", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyLteRlcGraph->setToolTip(QApplication::translate("MainWindow", "LTE RLC graph", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyMtp3Summary->setText(QApplication::translate("MainWindow", "MTP3 Summary", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyMtp3Summary->setToolTip(QApplication::translate("MainWindow", "MTP3 summary statistics", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyVoipCalls->setText(QApplication::translate("MainWindow", "&VoIP Calls", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyVoipCalls->setToolTip(QApplication::translate("MainWindow", "All VoIP Calls", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonySipFlows->setText(QApplication::translate("MainWindow", "SIP &Flows", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonySipFlows->setToolTip(QApplication::translate("MainWindow", "SIP Flows", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyRTPStreams->setText(QApplication::translate("MainWindow", "RTP Streams", nullptr));
        actionViewColoringRules->setText(QApplication::translate("MainWindow", "&Coloring Rules\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColoringRules->setToolTip(QApplication::translate("MainWindow", "Edit the packet list coloring rules.", nullptr));
#endif // QT_NO_TOOLTIP
        actionBluetoothATT_Server_Attributes->setText(QApplication::translate("MainWindow", "Bluetooth ATT Server Attributes", nullptr));
        actionBluetoothDevices->setText(QApplication::translate("MainWindow", "Bluetooth Devices", nullptr));
        actionBluetoothHCI_Summary->setText(QApplication::translate("MainWindow", "Bluetooth HCI Summary", nullptr));
        actionViewShowPacketInNewWindow->setText(QApplication::translate("MainWindow", "Show Packet in New &Window", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewShowPacketInNewWindow->setToolTip(QApplication::translate("MainWindow", "Show this packet in a separate window.", nullptr));
#endif // QT_NO_TOOLTIP
        actionContextShowLinkedPacketInNewWindow->setText(QApplication::translate("MainWindow", "Show Linked Packet in New Window", nullptr));
#ifndef QT_NO_TOOLTIP
        actionContextShowLinkedPacketInNewWindow->setToolTip(QApplication::translate("MainWindow", "Show the linked packet in a separate window.", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoAutoScroll->setText(QApplication::translate("MainWindow", "Auto Scroll in Li&ve Capture", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoAutoScroll->setToolTip(QApplication::translate("MainWindow", "Automatically scroll to the last packet during a live capture.", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeExpertInfo->setText(QApplication::translate("MainWindow", "Expert Information", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeExpertInfo->setToolTip(QApplication::translate("MainWindow", "Show expert notifications", nullptr));
#endif // QT_NO_TOOLTIP
        actionDisplayFilterExpression->setText(QApplication::translate("MainWindow", "&Expression\342\200\246", nullptr));
        actionDisplayFilterExpression->setIconText(QApplication::translate("MainWindow", "Expression\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionDisplayFilterExpression->setToolTip(QApplication::translate("MainWindow", "Add an expression to the display filter.", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatistics_REGISTER_STAT_GROUP_UNSORTED->setText(QApplication::translate("MainWindow", "REGISTER_STAT_GROUP_UNSORTED", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatistics_REGISTER_STAT_GROUP_UNSORTED->setToolTip(QApplication::translate("MainWindow", "Start of \"REGISTER_STAT_GROUP_UNSORTED\"", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyANSIPlaceholder->setText(QApplication::translate("MainWindow", "No ANSI statistics registered", nullptr));
        actionTelephonyGSMPlaceholder->setText(QApplication::translate("MainWindow", "No GSM statistics registered", nullptr));
        actionTelephonyLTEPlaceholder->setText(QApplication::translate("MainWindow", "No LTE statistics registered", nullptr));
        actionTelephonyMTP3Placeholder->setText(QApplication::translate("MainWindow", "No MTP3 statistics registered", nullptr));
        actionStatisticsResolvedAddresses->setText(QApplication::translate("MainWindow", "Resolved Addresses", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsResolvedAddresses->setToolTip(QApplication::translate("MainWindow", "Show each table of resolved addresses as copyable text.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation1->setText(QApplication::translate("MainWindow", "Color &1", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation1->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation2->setText(QApplication::translate("MainWindow", "Color &2", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation2->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation3->setText(QApplication::translate("MainWindow", "Color &3", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation3->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation4->setText(QApplication::translate("MainWindow", "Color &4", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation4->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation5->setText(QApplication::translate("MainWindow", "Color &5", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation5->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation6->setText(QApplication::translate("MainWindow", "Color &6", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation6->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation7->setText(QApplication::translate("MainWindow", "Color &7", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation7->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation8->setText(QApplication::translate("MainWindow", "Color &8", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation8->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation9->setText(QApplication::translate("MainWindow", "Color &9", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation9->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeConversation10->setText(QApplication::translate("MainWindow", "Color 1&0", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeConversation10->setToolTip(QApplication::translate("MainWindow", "Mark the current conversation with its own color.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeNewColoringRule->setText(QApplication::translate("MainWindow", "New Coloring Rule\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeNewColoringRule->setToolTip(QApplication::translate("MainWindow", "Create a new coloring rule based on this field.", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewColorizeResetColorization->setText(QApplication::translate("MainWindow", "Reset Colorization", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewColorizeResetColorization->setToolTip(QApplication::translate("MainWindow", "Reset colorized conversations.", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyRTPStreamAnalysis->setText(QApplication::translate("MainWindow", "Stream Analysis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyRTPStreamAnalysis->setToolTip(QApplication::translate("MainWindow", "RTP Stream Analysis", nullptr));
#endif // QT_NO_TOOLTIP
        actionTelephonyIax2StreamAnalysis->setText(QApplication::translate("MainWindow", "IA&X2 Stream Analysis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTelephonyIax2StreamAnalysis->setToolTip(QApplication::translate("MainWindow", "IAX2 Stream Analysis", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewEditResolvedName->setText(QApplication::translate("MainWindow", "Edit Resolved Name", nullptr));
#ifndef QT_NO_TOOLTIP
        actionViewEditResolvedName->setToolTip(QApplication::translate("MainWindow", "Manually edit a name resolution entry.", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeEnabledProtocols->setText(QApplication::translate("MainWindow", "Enabled Protocols\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyzeEnabledProtocols->setToolTip(QApplication::translate("MainWindow", "Enable and disable specific protocols", nullptr));
#endif // QT_NO_TOOLTIP
        actionAnalyzeShowPacketBytes->setText(QApplication::translate("MainWindow", "Show Packet Bytes\342\200\246", nullptr));
        actionContextWikiProtocolPage->setText(QApplication::translate("MainWindow", "Wiki Protocol Page", nullptr));
#ifndef QT_NO_TOOLTIP
        actionContextWikiProtocolPage->setToolTip(QApplication::translate("MainWindow", "Open the Wireshark wiki page for this protocol.", nullptr));
#endif // QT_NO_TOOLTIP
        actionContextFilterFieldReference->setText(QApplication::translate("MainWindow", "Filter Field Reference", nullptr));
#ifndef QT_NO_TOOLTIP
        actionContextFilterFieldReference->setToolTip(QApplication::translate("MainWindow", "Open the display filter reference page for this filter field.", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoGoToLinkedPacket->setText(QApplication::translate("MainWindow", "Go to &Linked Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoGoToLinkedPacket->setToolTip(QApplication::translate("MainWindow", "Go to the packet referenced by the selected field.", nullptr));
#endif // QT_NO_TOOLTIP
        actionStatisticsUdpMulticastStreams->setText(QApplication::translate("MainWindow", "UDP Multicast Streams", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStatisticsUdpMulticastStreams->setToolTip(QApplication::translate("MainWindow", "Show UTP multicast stream statistics.", nullptr));
#endif // QT_NO_TOOLTIP
        actionWirelessWlanStatistics->setText(QApplication::translate("MainWindow", "WLAN Traffic", nullptr));
#ifndef QT_NO_TOOLTIP
        actionWirelessWlanStatistics->setToolTip(QApplication::translate("MainWindow", "Show IEEE 802.11 wireless LAN statistics.", nullptr));
#endif // QT_NO_TOOLTIP
        actionNewDisplayFilterExpression->setText(QApplication::translate("MainWindow", "Add a filter button", nullptr));
        actionNewDisplayFilterExpression->setIconText(QApplication::translate("MainWindow", "Expression\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        actionNewDisplayFilterExpression->setToolTip(QApplication::translate("MainWindow", "Add a display filter button.", nullptr));
#endif // QT_NO_TOOLTIP
        actionToolsFirewallAclRules->setText(QApplication::translate("MainWindow", "Firewall ACL Rules", nullptr));
#ifndef QT_NO_TOOLTIP
        actionToolsFirewallAclRules->setToolTip(QApplication::translate("MainWindow", "Create firewall ACL rules", nullptr));
#endif // QT_NO_TOOLTIP
        actionViewFullScreen->setText(QApplication::translate("MainWindow", "&Full Screen", nullptr));
        goToPacketLabel->setText(QApplication::translate("MainWindow", "Packet:", nullptr));
        goToLineEdit->setInputMask(QApplication::translate("MainWindow", "900000000", nullptr));
        goToGo->setText(QApplication::translate("MainWindow", "Go to packet", nullptr));
        goToCancel->setText(QApplication::translate("MainWindow", "Cancel", nullptr));
        menuFile->setTitle(QApplication::translate("MainWindow", "&File", nullptr));
        menuOpenRecentCaptureFile->setTitle(QApplication::translate("MainWindow", "Open &Recent", nullptr));
        menuFileSet->setTitle(QApplication::translate("MainWindow", "File Set", nullptr));
        menuFileExportPacketDissections->setTitle(QApplication::translate("MainWindow", "Export Packet Dissections", nullptr));
        menuFileExportObjects->setTitle(QApplication::translate("MainWindow", "Export Objects", nullptr));
        menuCapture->setTitle(QApplication::translate("MainWindow", "&Capture", nullptr));
        menuHelp->setTitle(QApplication::translate("MainWindow", "&Help", nullptr));
        menuHelpManualPages->setTitle(QApplication::translate("MainWindow", "Manual pages", nullptr));
        menuGo->setTitle(QApplication::translate("MainWindow", "&Go", nullptr));
        menuView->setTitle(QApplication::translate("MainWindow", "&View", nullptr));
        menuInterfaceToolbars->setTitle(QApplication::translate("MainWindow", "Interface Toolbars", nullptr));
        menuZoom->setTitle(QApplication::translate("MainWindow", "&Zoom", nullptr));
        menuTime_Display_Format->setTitle(QApplication::translate("MainWindow", "&Time Display Format", nullptr));
        menuName_Resolution->setTitle(QApplication::translate("MainWindow", "Name Resol&ution", nullptr));
        menuColorizeConversation->setTitle(QApplication::translate("MainWindow", "Colorize Conversation", nullptr));
        menuInternals->setTitle(QApplication::translate("MainWindow", "Internals", nullptr));
        menuAdditionalToolbars->setTitle(QApplication::translate("MainWindow", "Additional Toolbars", nullptr));
        menuAnalyze->setTitle(QApplication::translate("MainWindow", "&Analyze", nullptr));
        menuApplyAsFilter->setTitle(QApplication::translate("MainWindow", "Apply as Filter", nullptr));
        menuPrepareAFilter->setTitle(QApplication::translate("MainWindow", "Prepare a Filter", nullptr));
        menuSCTP->setTitle(QApplication::translate("MainWindow", "SCTP", nullptr));
        menuFollow->setTitle(QApplication::translate("MainWindow", "Follow", nullptr));
        menuConversationFilter->setTitle(QApplication::translate("MainWindow", "Conversation Filter", nullptr));
        menuStatistics->setTitle(QApplication::translate("MainWindow", "&Statistics", nullptr));
        menuTcpStreamGraphs->setTitle(QApplication::translate("MainWindow", "TCP Stream Graphs", nullptr));
        menuBACnet->setTitle(QApplication::translate("MainWindow", "BACnet", nullptr));
        menuHTTP->setTitle(QApplication::translate("MainWindow", "HTTP", nullptr));
        menu29West->setTitle(QApplication::translate("MainWindow", "29West", nullptr));
        menu29WestTopics->setTitle(QApplication::translate("MainWindow", "Topics", nullptr));
        menu29WestQueues->setTitle(QApplication::translate("MainWindow", "Queues", nullptr));
        menu29WestUIM->setTitle(QApplication::translate("MainWindow", "UIM", nullptr));
        menuServiceResponseTime->setTitle(QApplication::translate("MainWindow", "Service &Response Time", nullptr));
        menuTelephony->setTitle(QApplication::translate("MainWindow", "Telephon&y", nullptr));
        menuRTSP->setTitle(QApplication::translate("MainWindow", "RTSP", nullptr));
        menuRTP->setTitle(QApplication::translate("MainWindow", "&RTP", nullptr));
        menuTelephonySCTP->setTitle(QApplication::translate("MainWindow", "S&CTP", nullptr));
        menuANSI->setTitle(QApplication::translate("MainWindow", "&ANSI", nullptr));
        menuGSM->setTitle(QApplication::translate("MainWindow", "&GSM", nullptr));
        menuLTE->setTitle(QApplication::translate("MainWindow", "&LTE", nullptr));
        menuMTP3->setTitle(QApplication::translate("MainWindow", "&MTP3", nullptr));
        menuOsmux->setTitle(QApplication::translate("MainWindow", "Osmux", nullptr));
        menuEdit->setTitle(QApplication::translate("MainWindow", "&Edit", nullptr));
        menuEditCopy->setTitle(QApplication::translate("MainWindow", "Copy", nullptr));
        menuWireless->setTitle(QApplication::translate("MainWindow", "&Wireless", nullptr));
        menuTools->setTitle(QApplication::translate("MainWindow", "&Tools", nullptr));
        mainToolBar->setWindowTitle(QApplication::translate("MainWindow", "Main Toolbar", nullptr));
        displayFilterToolBar->setWindowTitle(QApplication::translate("MainWindow", "Display Filter Toolbar", nullptr));
        wirelessToolBar->setWindowTitle(QApplication::translate("MainWindow", "Wireless Toolbar", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAIN_WINDOW_H
