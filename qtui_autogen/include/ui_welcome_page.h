/********************************************************************************
** Form generated from reading UI file 'welcome_page.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_WELCOME_PAGE_H
#define UI_WELCOME_PAGE_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include "accordion_frame.h"
#include "interface_frame.h"
#include "widgets/capture_filter_combo.h"
#include "widgets/clickable_label.h"

QT_BEGIN_NAMESPACE

class Ui_WelcomePage
{
public:
    QHBoxLayout *horizontalLayout_2;
    QSpacerItem *horizontalSpacer;
    QWidget *childContainer;
    QVBoxLayout *verticalLayout_2;
    QWidget *bannerLayout;
    QHBoxLayout *horizontalLayout_3;
    QLabel *mainWelcomeBanner;
    QSpacerItem *bannerSpacer;
    QLabel *flavorBanner;
    AccordionFrame *openFrame;
    QVBoxLayout *verticalLayout;
    ClickableLabel *recentLabel;
    QListWidget *recentList;
    ClickableLabel *captureLabel;
    QWidget *captureFilterLayout;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    CaptureFilterCombo *captureFilterComboBox;
    QPushButton *btnInterfaceType;
    InterfaceFrame *interfaceFrame;
    ClickableLabel *helpLabel;
    QLabel *helpLinks;
    QLabel *fullReleaseLabel;
    QSpacerItem *horizontalSpacer_2;

    void setupUi(QWidget *WelcomePage)
    {
        if (WelcomePage->objectName().isEmpty())
            WelcomePage->setObjectName(QString::fromUtf8("WelcomePage"));
        WelcomePage->resize(811, 663);
        horizontalLayout_2 = new QHBoxLayout(WelcomePage);
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        horizontalSpacer = new QSpacerItem(44, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        childContainer = new QWidget(WelcomePage);
        childContainer->setObjectName(QString::fromUtf8("childContainer"));
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(childContainer->sizePolicy().hasHeightForWidth());
        childContainer->setSizePolicy(sizePolicy);
        verticalLayout_2 = new QVBoxLayout(childContainer);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        bannerLayout = new QWidget(childContainer);
        bannerLayout->setObjectName(QString::fromUtf8("bannerLayout"));
        bannerLayout->setMinimumSize(QSize(550, 0));
        horizontalLayout_3 = new QHBoxLayout(bannerLayout);
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        horizontalLayout_3->setContentsMargins(0, 0, 0, 0);
        mainWelcomeBanner = new QLabel(bannerLayout);
        mainWelcomeBanner->setObjectName(QString::fromUtf8("mainWelcomeBanner"));

        horizontalLayout_3->addWidget(mainWelcomeBanner);

        bannerSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(bannerSpacer);

        flavorBanner = new QLabel(bannerLayout);
        flavorBanner->setObjectName(QString::fromUtf8("flavorBanner"));
        flavorBanner->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        horizontalLayout_3->addWidget(flavorBanner);

        horizontalLayout_3->setStretch(1, 1);

        verticalLayout_2->addWidget(bannerLayout);

        openFrame = new AccordionFrame(childContainer);
        openFrame->setObjectName(QString::fromUtf8("openFrame"));
        QSizePolicy sizePolicy1(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(2);
        sizePolicy1.setHeightForWidth(openFrame->sizePolicy().hasHeightForWidth());
        openFrame->setSizePolicy(sizePolicy1);
        openFrame->setFrameShape(QFrame::NoFrame);
        openFrame->setFrameShadow(QFrame::Plain);
        openFrame->setLineWidth(0);
        verticalLayout = new QVBoxLayout(openFrame);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout->setContentsMargins(0, 0, 0, 0);
        recentLabel = new ClickableLabel(openFrame);
        recentLabel->setObjectName(QString::fromUtf8("recentLabel"));
        QSizePolicy sizePolicy2(QSizePolicy::Fixed, QSizePolicy::Preferred);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(recentLabel->sizePolicy().hasHeightForWidth());
        recentLabel->setSizePolicy(sizePolicy2);

        verticalLayout->addWidget(recentLabel);

        recentList = new QListWidget(openFrame);
        recentList->setObjectName(QString::fromUtf8("recentList"));
        QSizePolicy sizePolicy3(QSizePolicy::MinimumExpanding, QSizePolicy::Expanding);
        sizePolicy3.setHorizontalStretch(1);
        sizePolicy3.setVerticalStretch(2);
        sizePolicy3.setHeightForWidth(recentList->sizePolicy().hasHeightForWidth());
        recentList->setSizePolicy(sizePolicy3);
        recentList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

        verticalLayout->addWidget(recentList);


        verticalLayout_2->addWidget(openFrame);

        captureLabel = new ClickableLabel(childContainer);
        captureLabel->setObjectName(QString::fromUtf8("captureLabel"));
        sizePolicy2.setHeightForWidth(captureLabel->sizePolicy().hasHeightForWidth());
        captureLabel->setSizePolicy(sizePolicy2);

        verticalLayout_2->addWidget(captureLabel);

        captureFilterLayout = new QWidget(childContainer);
        captureFilterLayout->setObjectName(QString::fromUtf8("captureFilterLayout"));
        horizontalLayout = new QHBoxLayout(captureFilterLayout);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalLayout->setContentsMargins(0, 0, 0, -1);
        label = new QLabel(captureFilterLayout);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        captureFilterComboBox = new CaptureFilterCombo(captureFilterLayout);
        captureFilterComboBox->setObjectName(QString::fromUtf8("captureFilterComboBox"));
        QSizePolicy sizePolicy4(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed);
        sizePolicy4.setHorizontalStretch(0);
        sizePolicy4.setVerticalStretch(0);
        sizePolicy4.setHeightForWidth(captureFilterComboBox->sizePolicy().hasHeightForWidth());
        captureFilterComboBox->setSizePolicy(sizePolicy4);
        captureFilterComboBox->setEditable(true);

        horizontalLayout->addWidget(captureFilterComboBox);

        btnInterfaceType = new QPushButton(captureFilterLayout);
        btnInterfaceType->setObjectName(QString::fromUtf8("btnInterfaceType"));

        horizontalLayout->addWidget(btnInterfaceType);


        verticalLayout_2->addWidget(captureFilterLayout);

        interfaceFrame = new InterfaceFrame(childContainer);
        interfaceFrame->setObjectName(QString::fromUtf8("interfaceFrame"));
        QSizePolicy sizePolicy5(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
        sizePolicy5.setHorizontalStretch(0);
        sizePolicy5.setVerticalStretch(1);
        sizePolicy5.setHeightForWidth(interfaceFrame->sizePolicy().hasHeightForWidth());
        interfaceFrame->setSizePolicy(sizePolicy5);
        interfaceFrame->setFrameShape(QFrame::StyledPanel);
        interfaceFrame->setFrameShadow(QFrame::Raised);

        verticalLayout_2->addWidget(interfaceFrame);

        helpLabel = new ClickableLabel(childContainer);
        helpLabel->setObjectName(QString::fromUtf8("helpLabel"));
        sizePolicy2.setHeightForWidth(helpLabel->sizePolicy().hasHeightForWidth());
        helpLabel->setSizePolicy(sizePolicy2);

        verticalLayout_2->addWidget(helpLabel);

        helpLinks = new QLabel(childContainer);
        helpLinks->setObjectName(QString::fromUtf8("helpLinks"));
        helpLinks->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignTop);
        helpLinks->setOpenExternalLinks(true);
        helpLinks->setTextInteractionFlags(Qt::LinksAccessibleByKeyboard|Qt::LinksAccessibleByMouse|Qt::TextBrowserInteraction|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        verticalLayout_2->addWidget(helpLinks);

        fullReleaseLabel = new QLabel(childContainer);
        fullReleaseLabel->setObjectName(QString::fromUtf8("fullReleaseLabel"));

        verticalLayout_2->addWidget(fullReleaseLabel);


        horizontalLayout_2->addWidget(childContainer);

        horizontalSpacer_2 = new QSpacerItem(43, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);

        horizontalLayout_2->setStretch(0, 10);
        horizontalLayout_2->setStretch(1, 80);
        horizontalLayout_2->setStretch(2, 10);

        retranslateUi(WelcomePage);

        QMetaObject::connectSlotsByName(WelcomePage);
    } // setupUi

    void retranslateUi(QWidget *WelcomePage)
    {
        WelcomePage->setWindowTitle(QApplication::translate("WelcomePage", "Form", nullptr));
        mainWelcomeBanner->setText(QApplication::translate("WelcomePage", "<html><head/><body><p><span style=\" font-size:large;\">Welcome to Wireshark</span></p></body></html>", nullptr));
#ifndef QT_NO_TOOLTIP
        recentLabel->setToolTip(QApplication::translate("WelcomePage", "<html><head/><body><p>Open a file on your file system</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        recentLabel->setText(QApplication::translate("WelcomePage", "<h2>Open</h2>", nullptr));
#ifndef QT_NO_ACCESSIBILITY
        recentList->setAccessibleName(QApplication::translate("WelcomePage", "Recent capture files", nullptr));
#endif // QT_NO_ACCESSIBILITY
#ifndef QT_NO_ACCESSIBILITY
        recentList->setAccessibleDescription(QApplication::translate("WelcomePage", "Capture files that have been opened previously", nullptr));
#endif // QT_NO_ACCESSIBILITY
#ifndef QT_NO_TOOLTIP
        captureLabel->setToolTip(QApplication::translate("WelcomePage", "<html><head/><body><p>Capture live packets from your network.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        captureLabel->setText(QApplication::translate("WelcomePage", "<h2>Capture</h2>", nullptr));
        label->setText(QApplication::translate("WelcomePage", "\342\200\246using this filter:", nullptr));
        btnInterfaceType->setText(QString());
#ifndef QT_NO_ACCESSIBILITY
        interfaceFrame->setAccessibleName(QApplication::translate("WelcomePage", "Interface list", nullptr));
#endif // QT_NO_ACCESSIBILITY
#ifndef QT_NO_ACCESSIBILITY
        interfaceFrame->setAccessibleDescription(QApplication::translate("WelcomePage", "List of available capture interfaces", nullptr));
#endif // QT_NO_ACCESSIBILITY
        helpLabel->setText(QApplication::translate("WelcomePage", "<h2>Learn</h2>", nullptr));
        helpLinks->setText(QApplication::translate("WelcomePage", "<html><head>\n"
"<style>\n"
"a:link {\n"
"  color: inherit;\n"
"  text-decoration: none;\n"
"}\n"
"a:hover {\n"
"  color: inherit;\n"
"  text-decoration: underline;\n"
"}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"\n"
"<table><tr>\n"
"<th><a href=\"https://www.wireshark.org/docs/wsug_html_chunked/\">User's Guide</a></th>\n"
"\n"
"<td style=\"padding-left: 8px; padding-right: 8px;\">\302\267</td>\n"
"\n"
"<th><a href=\"https://wiki.wireshark.org/\">Wiki</a></th>\n"
"\n"
"<td style=\"padding-left: 8px; padding-right: 8px;\">\302\267</td>\n"
"\n"
"<th><a href=\"https://ask.wireshark.org/\">Questions and Answers</a></th>\n"
"\n"
"<td style=\"padding-left: 8px; padding-right: 8px;\">\302\267</td>\n"
"\n"
"<th><a href=\"https://www.wireshark.org/lists/\">Mailing Lists</a></th>\n"
"\n"
"</tr></table>\n"
"</body></html>", nullptr));
        fullReleaseLabel->setText(QString());
    } // retranslateUi

};

namespace Ui {
    class WelcomePage: public Ui_WelcomePage {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_WELCOME_PAGE_H
