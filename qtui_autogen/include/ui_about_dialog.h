/********************************************************************************
** Form generated from reading UI file 'about_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_ABOUT_DIALOG_H
#define UI_ABOUT_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_AboutDialog
{
public:
    QVBoxLayout *verticalLayout_6;
    QTabWidget *tabWidget;
    QWidget *tab_wireshark;
    QVBoxLayout *verticalLayout;
    QLabel *label_logo;
    QLabel *label_title;
    QTextBrowser *pte_wireshark;
    QWidget *tab_authors;
    QVBoxLayout *verticalLayout_2;
    QLineEdit *searchAuthors;
    QTreeView *tblAuthors;
    QWidget *tab_folders;
    QVBoxLayout *verticalLayout_3;
    QLineEdit *searchFolders;
    QTreeView *tblFolders;
    QWidget *tab_plugins;
    QVBoxLayout *verticalLayout_4;
    QLabel *label_no_plugins;
    QHBoxLayout *horizontalLayout_3;
    QLineEdit *searchPlugins;
    QLabel *label;
    QComboBox *cmbType;
    QTreeView *tblPlugins;
    QWidget *tab_shortcuts;
    QVBoxLayout *verticalLayout_shortcuts;
    QLineEdit *searchShortcuts;
    QTreeView *tblShortcuts;
    QWidget *tab_AboutBox;
    QVBoxLayout *verticalLayout_AboutBox;
    QPlainTextEdit *tblAboutBox;
    QWidget *tab_acknowledgements;
    QVBoxLayout *verticalLayout_8;
    QPlainTextEdit *pte_Authors;
    QWidget *tab_license;
    QVBoxLayout *verticalLayout_5;
    QPlainTextEdit *pte_License;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *AboutDialog)
    {
        if (AboutDialog->objectName().isEmpty())
            AboutDialog->setObjectName(QString::fromUtf8("AboutDialog"));
        AboutDialog->resize(740, 650);
        verticalLayout_6 = new QVBoxLayout(AboutDialog);
        verticalLayout_6->setObjectName(QString::fromUtf8("verticalLayout_6"));
        tabWidget = new QTabWidget(AboutDialog);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setMinimumSize(QSize(371, 231));
        tabWidget->setDocumentMode(false);
        tab_wireshark = new QWidget();
        tab_wireshark->setObjectName(QString::fromUtf8("tab_wireshark"));
        tab_wireshark->setEnabled(true);
        verticalLayout = new QVBoxLayout(tab_wireshark);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        label_logo = new QLabel(tab_wireshark);
        label_logo->setObjectName(QString::fromUtf8("label_logo"));
        label_logo->setPixmap(QPixmap(QString::fromUtf8(":/about/wssplash.png")));
        label_logo->setScaledContents(false);
        label_logo->setAlignment(Qt::AlignHCenter|Qt::AlignTop);

        verticalLayout->addWidget(label_logo);

        label_title = new QLabel(tab_wireshark);
        label_title->setObjectName(QString::fromUtf8("label_title"));
        label_title->setMaximumSize(QSize(16777215, 20));
        label_title->setAlignment(Qt::AlignCenter);

        verticalLayout->addWidget(label_title);

        pte_wireshark = new QTextBrowser(tab_wireshark);
        pte_wireshark->setObjectName(QString::fromUtf8("pte_wireshark"));
        pte_wireshark->setReadOnly(true);
        pte_wireshark->setTextInteractionFlags(Qt::TextBrowserInteraction);
        pte_wireshark->setOpenExternalLinks(true);

        verticalLayout->addWidget(pte_wireshark);

        verticalLayout->setStretch(1, 1);
        tabWidget->addTab(tab_wireshark, QString());
        tab_authors = new QWidget();
        tab_authors->setObjectName(QString::fromUtf8("tab_authors"));
        verticalLayout_2 = new QVBoxLayout(tab_authors);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        searchAuthors = new QLineEdit(tab_authors);
        searchAuthors->setObjectName(QString::fromUtf8("searchAuthors"));

        verticalLayout_2->addWidget(searchAuthors);

        tblAuthors = new QTreeView(tab_authors);
        tblAuthors->setObjectName(QString::fromUtf8("tblAuthors"));
        tblAuthors->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tblAuthors->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tblAuthors->setSelectionBehavior(QAbstractItemView::SelectRows);
        tblAuthors->header()->setMinimumSectionSize(100);
        tblAuthors->header()->setStretchLastSection(true);

        verticalLayout_2->addWidget(tblAuthors);

        tabWidget->addTab(tab_authors, QString());
        tab_folders = new QWidget();
        tab_folders->setObjectName(QString::fromUtf8("tab_folders"));
        verticalLayout_3 = new QVBoxLayout(tab_folders);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        searchFolders = new QLineEdit(tab_folders);
        searchFolders->setObjectName(QString::fromUtf8("searchFolders"));

        verticalLayout_3->addWidget(searchFolders);

        tblFolders = new QTreeView(tab_folders);
        tblFolders->setObjectName(QString::fromUtf8("tblFolders"));
        tblFolders->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tblFolders->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tblFolders->setSelectionBehavior(QAbstractItemView::SelectRows);

        verticalLayout_3->addWidget(tblFolders);

        tabWidget->addTab(tab_folders, QString());
        tab_plugins = new QWidget();
        tab_plugins->setObjectName(QString::fromUtf8("tab_plugins"));
        verticalLayout_4 = new QVBoxLayout(tab_plugins);
        verticalLayout_4->setObjectName(QString::fromUtf8("verticalLayout_4"));
        label_no_plugins = new QLabel(tab_plugins);
        label_no_plugins->setObjectName(QString::fromUtf8("label_no_plugins"));

        verticalLayout_4->addWidget(label_no_plugins);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        searchPlugins = new QLineEdit(tab_plugins);
        searchPlugins->setObjectName(QString::fromUtf8("searchPlugins"));

        horizontalLayout_3->addWidget(searchPlugins);

        label = new QLabel(tab_plugins);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout_3->addWidget(label);

        cmbType = new QComboBox(tab_plugins);
        cmbType->setObjectName(QString::fromUtf8("cmbType"));

        horizontalLayout_3->addWidget(cmbType);


        verticalLayout_4->addLayout(horizontalLayout_3);

        tblPlugins = new QTreeView(tab_plugins);
        tblPlugins->setObjectName(QString::fromUtf8("tblPlugins"));
        tblPlugins->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tblPlugins->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tblPlugins->setSelectionBehavior(QAbstractItemView::SelectRows);

        verticalLayout_4->addWidget(tblPlugins);

        tabWidget->addTab(tab_plugins, QString());
        tab_shortcuts = new QWidget();
        tab_shortcuts->setObjectName(QString::fromUtf8("tab_shortcuts"));
        verticalLayout_shortcuts = new QVBoxLayout(tab_shortcuts);
        verticalLayout_shortcuts->setObjectName(QString::fromUtf8("verticalLayout_shortcuts"));
        searchShortcuts = new QLineEdit(tab_shortcuts);
        searchShortcuts->setObjectName(QString::fromUtf8("searchShortcuts"));

        verticalLayout_shortcuts->addWidget(searchShortcuts);

        tblShortcuts = new QTreeView(tab_shortcuts);
        tblShortcuts->setObjectName(QString::fromUtf8("tblShortcuts"));
        tblShortcuts->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tblShortcuts->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tblShortcuts->setSelectionBehavior(QAbstractItemView::SelectRows);
        tblShortcuts->setTextElideMode(Qt::ElideRight);
        tblShortcuts->setWordWrap(true);

        verticalLayout_shortcuts->addWidget(tblShortcuts);
        
        
        tabWidget->addTab(tab_shortcuts, QString());
        tab_AboutBox = new QWidget();
        tab_AboutBox->setObjectName(QString::fromUtf8("tab_AboutBox"));
        verticalLayout_AboutBox = new QVBoxLayout(tab_AboutBox);
        verticalLayout_AboutBox->setObjectName(QString::fromUtf8("verticalLayout_AboutBox"));
        
        tblAboutBox = new QPlainTextEdit(tab_AboutBox);
        tblAboutBox->setObjectName(QString::fromUtf8("tblAboutBox"));
        tblAboutBox->setReadOnly(true);
        
        verticalLayout_AboutBox->addWidget(tblAboutBox);
        
        tabWidget->addTab(tab_AboutBox, QString());
        tab_acknowledgements = new QWidget();
        tab_acknowledgements->setObjectName(QString::fromUtf8("tab_acknowledgements"));
        verticalLayout_8 = new QVBoxLayout(tab_acknowledgements);
        verticalLayout_8->setObjectName(QString::fromUtf8("verticalLayout_8"));
        pte_Authors = new QPlainTextEdit(tab_acknowledgements);
        pte_Authors->setObjectName(QString::fromUtf8("pte_Authors"));
        pte_Authors->setReadOnly(true);

        verticalLayout_8->addWidget(pte_Authors);

        tabWidget->addTab(tab_acknowledgements, QString());
        tab_license = new QWidget();
        tab_license->setObjectName(QString::fromUtf8("tab_license"));
        verticalLayout_5 = new QVBoxLayout(tab_license);
        verticalLayout_5->setObjectName(QString::fromUtf8("verticalLayout_5"));
        pte_License = new QPlainTextEdit(tab_license);
        pte_License->setObjectName(QString::fromUtf8("pte_License"));
        pte_License->setReadOnly(true);

        verticalLayout_5->addWidget(pte_License);

        tabWidget->addTab(tab_license, QString());

        verticalLayout_6->addWidget(tabWidget);

        buttonBox = new QDialogButtonBox(AboutDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Ok);

        verticalLayout_6->addWidget(buttonBox);


        retranslateUi(AboutDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), AboutDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), AboutDialog, SLOT(reject()));

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(AboutDialog);
    } // setupUi

    void retranslateUi(QDialog *AboutDialog)
    {
        AboutDialog->setWindowTitle(QApplication::translate("AboutDialog", "About Wireshark", nullptr));
        label_logo->setText(QString());
        label_title->setText(QApplication::translate("AboutDialog", "<span size=\\\"x-large\\\" weight=\\\"bold\\\">Network Protocol Analyzer</span>", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_wireshark), QApplication::translate("AboutDialog", "Wireshark", nullptr));
        searchAuthors->setPlaceholderText(QApplication::translate("AboutDialog", "Search Authors", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_authors), QApplication::translate("AboutDialog", "Authors", nullptr));
        searchFolders->setPlaceholderText(QApplication::translate("AboutDialog", "Filter by path", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_folders), QApplication::translate("AboutDialog", "Folders", nullptr));
        label_no_plugins->setText(QApplication::translate("AboutDialog", "No plugins found.", nullptr));
        searchPlugins->setPlaceholderText(QApplication::translate("AboutDialog", "Search Plugins", nullptr));
        label->setText(QApplication::translate("AboutDialog", "Filter by type:", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_plugins), QApplication::translate("AboutDialog", "Plugins", nullptr));
        searchShortcuts->setPlaceholderText(QApplication::translate("AboutDialog", "Search Shortcuts", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_shortcuts), QApplication::translate("AboutDialog", "Keyboard Shortcuts", nullptr));
        tblAboutBox->setPlaceholderText(QApplication::translate("AboutDialog", "Contributers\n\nStian Hagboe Olsen\nZachary Holcomb\nLuke Lynch\nMarley Scott", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_AboutBox), QApplication::translate("AboutDialog", "AboutBox", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_acknowledgements), QApplication::translate("AboutDialog", "Acknowledgments", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_license), QApplication::translate("AboutDialog", "License", nullptr));
    } // retranslateUi

};

namespace Ui {
    class AboutDialog: public Ui_AboutDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_ABOUT_DIALOG_H
