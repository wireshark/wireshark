/********************************************************************************
** Form generated from reading UI file 'main_window_preferences_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAIN_WINDOW_PREFERENCES_FRAME_H
#define UI_MAIN_WINDOW_PREFERENCES_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_MainWindowPreferencesFrame
{
public:
    QVBoxLayout *verticalLayout;
    QCheckBox *geometryCheckBox;
    QLabel *label;
    QGridLayout *gridLayout;
    QRadioButton *foStyleSpecifiedRadioButton;
    QLineEdit *foStyleSpecifiedLineEdit;
    QPushButton *foStyleSpecifiedPushButton;
    QRadioButton *foStyleLastOpenedRadioButton;
    QLabel *label_2;
    QHBoxLayout *horizontalLayout_2;
    QLineEdit *maxFilterLineEdit;
    QLabel *label_3;
    QSpacerItem *horizontalSpacer;
    QHBoxLayout *horizontalLayout_3;
    QLineEdit *maxRecentLineEdit;
    QLabel *label_4;
    QSpacerItem *horizontalSpacer_2;
    QCheckBox *confirmUnsavedCheckBox;
    QCheckBox *displayAutoCompleteCheckBox;
    QHBoxLayout *horizontalLayout;
    QLabel *label_5;
    QComboBox *mainToolbarComboBox;
    QSpacerItem *horizontalSpacer_4;
    QHBoxLayout *horizontalLayout_6;
    QLabel *label_7;
    QComboBox *languageComboBox;
    QSpacerItem *horizontalSpacer_6;
    QSpacerItem *verticalSpacer;
    QButtonGroup *openInButtonGroup;

    void setupUi(QFrame *MainWindowPreferencesFrame)
    {
        if (MainWindowPreferencesFrame->objectName().isEmpty())
            MainWindowPreferencesFrame->setObjectName(QString::fromUtf8("MainWindowPreferencesFrame"));
        MainWindowPreferencesFrame->resize(405, 416);
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MainWindowPreferencesFrame->sizePolicy().hasHeightForWidth());
        MainWindowPreferencesFrame->setSizePolicy(sizePolicy);
        MainWindowPreferencesFrame->setMinimumSize(QSize(0, 384));
        MainWindowPreferencesFrame->setFrameShape(QFrame::NoFrame);
        MainWindowPreferencesFrame->setFrameShadow(QFrame::Plain);
        MainWindowPreferencesFrame->setLineWidth(0);
        verticalLayout = new QVBoxLayout(MainWindowPreferencesFrame);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        geometryCheckBox = new QCheckBox(MainWindowPreferencesFrame);
        geometryCheckBox->setObjectName(QString::fromUtf8("geometryCheckBox"));

        verticalLayout->addWidget(geometryCheckBox);

        label = new QLabel(MainWindowPreferencesFrame);
        label->setObjectName(QString::fromUtf8("label"));

        verticalLayout->addWidget(label);

        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        foStyleSpecifiedRadioButton = new QRadioButton(MainWindowPreferencesFrame);
        openInButtonGroup = new QButtonGroup(MainWindowPreferencesFrame);
        openInButtonGroup->setObjectName(QString::fromUtf8("openInButtonGroup"));
        openInButtonGroup->addButton(foStyleSpecifiedRadioButton);
        foStyleSpecifiedRadioButton->setObjectName(QString::fromUtf8("foStyleSpecifiedRadioButton"));

        gridLayout->addWidget(foStyleSpecifiedRadioButton, 1, 0, 1, 1);

        foStyleSpecifiedLineEdit = new QLineEdit(MainWindowPreferencesFrame);
        foStyleSpecifiedLineEdit->setObjectName(QString::fromUtf8("foStyleSpecifiedLineEdit"));

        gridLayout->addWidget(foStyleSpecifiedLineEdit, 1, 1, 1, 1);

        foStyleSpecifiedPushButton = new QPushButton(MainWindowPreferencesFrame);
        foStyleSpecifiedPushButton->setObjectName(QString::fromUtf8("foStyleSpecifiedPushButton"));

        gridLayout->addWidget(foStyleSpecifiedPushButton, 1, 2, 1, 1);

        foStyleLastOpenedRadioButton = new QRadioButton(MainWindowPreferencesFrame);
        openInButtonGroup->addButton(foStyleLastOpenedRadioButton);
        foStyleLastOpenedRadioButton->setObjectName(QString::fromUtf8("foStyleLastOpenedRadioButton"));

        gridLayout->addWidget(foStyleLastOpenedRadioButton, 0, 0, 1, 3);


        verticalLayout->addLayout(gridLayout);

        label_2 = new QLabel(MainWindowPreferencesFrame);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        verticalLayout->addWidget(label_2);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        maxFilterLineEdit = new QLineEdit(MainWindowPreferencesFrame);
        maxFilterLineEdit->setObjectName(QString::fromUtf8("maxFilterLineEdit"));

        horizontalLayout_2->addWidget(maxFilterLineEdit);

        label_3 = new QLabel(MainWindowPreferencesFrame);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        horizontalLayout_2->addWidget(label_3);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        horizontalLayout_2->setStretch(2, 1);

        verticalLayout->addLayout(horizontalLayout_2);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        maxRecentLineEdit = new QLineEdit(MainWindowPreferencesFrame);
        maxRecentLineEdit->setObjectName(QString::fromUtf8("maxRecentLineEdit"));

        horizontalLayout_3->addWidget(maxRecentLineEdit);

        label_4 = new QLabel(MainWindowPreferencesFrame);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        horizontalLayout_3->addWidget(label_4);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer_2);

        horizontalLayout_3->setStretch(2, 1);

        verticalLayout->addLayout(horizontalLayout_3);

        confirmUnsavedCheckBox = new QCheckBox(MainWindowPreferencesFrame);
        confirmUnsavedCheckBox->setObjectName(QString::fromUtf8("confirmUnsavedCheckBox"));

        verticalLayout->addWidget(confirmUnsavedCheckBox);

        displayAutoCompleteCheckBox = new QCheckBox(MainWindowPreferencesFrame);
        displayAutoCompleteCheckBox->setObjectName(QString::fromUtf8("displayAutoCompleteCheckBox"));

        verticalLayout->addWidget(displayAutoCompleteCheckBox);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label_5 = new QLabel(MainWindowPreferencesFrame);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        horizontalLayout->addWidget(label_5);

        mainToolbarComboBox = new QComboBox(MainWindowPreferencesFrame);
        mainToolbarComboBox->addItem(QString());
        mainToolbarComboBox->addItem(QString());
        mainToolbarComboBox->addItem(QString());
        mainToolbarComboBox->setObjectName(QString::fromUtf8("mainToolbarComboBox"));

        horizontalLayout->addWidget(mainToolbarComboBox);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_4);


        verticalLayout->addLayout(horizontalLayout);

        horizontalLayout_6 = new QHBoxLayout();
        horizontalLayout_6->setObjectName(QString::fromUtf8("horizontalLayout_6"));
        label_7 = new QLabel(MainWindowPreferencesFrame);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        horizontalLayout_6->addWidget(label_7);

        languageComboBox = new QComboBox(MainWindowPreferencesFrame);
        languageComboBox->addItem(QString());
        languageComboBox->setObjectName(QString::fromUtf8("languageComboBox"));
        languageComboBox->setEnabled(true);
        languageComboBox->setMaximumSize(QSize(16777215, 16777215));

        horizontalLayout_6->addWidget(languageComboBox);

        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_6->addItem(horizontalSpacer_6);


        verticalLayout->addLayout(horizontalLayout_6);

        verticalSpacer = new QSpacerItem(20, 1, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);


        retranslateUi(MainWindowPreferencesFrame);

        QMetaObject::connectSlotsByName(MainWindowPreferencesFrame);
    } // setupUi

    void retranslateUi(QFrame *MainWindowPreferencesFrame)
    {
        MainWindowPreferencesFrame->setWindowTitle(QApplication::translate("MainWindowPreferencesFrame", "Frame", nullptr));
#ifndef QT_NO_TOOLTIP
        geometryCheckBox->setToolTip(QApplication::translate("MainWindowPreferencesFrame", "Checking this will save the size, position, and maximized state of the main window.", nullptr));
#endif // QT_NO_TOOLTIP
        geometryCheckBox->setText(QApplication::translate("MainWindowPreferencesFrame", "Remember main window size and placement", nullptr));
        label->setText(QApplication::translate("MainWindowPreferencesFrame", "Open files in", nullptr));
        foStyleSpecifiedRadioButton->setText(QApplication::translate("MainWindowPreferencesFrame", "This folder:", nullptr));
        foStyleSpecifiedPushButton->setText(QApplication::translate("MainWindowPreferencesFrame", "Browse\342\200\246", nullptr));
        foStyleLastOpenedRadioButton->setText(QApplication::translate("MainWindowPreferencesFrame", "The most recently used folder", nullptr));
        label_2->setText(QApplication::translate("MainWindowPreferencesFrame", "Show up to", nullptr));
        label_3->setText(QApplication::translate("MainWindowPreferencesFrame", "filter entries", nullptr));
        label_4->setText(QApplication::translate("MainWindowPreferencesFrame", "recent files", nullptr));
        confirmUnsavedCheckBox->setText(QApplication::translate("MainWindowPreferencesFrame", "Confirm unsaved capture files", nullptr));
        displayAutoCompleteCheckBox->setText(QApplication::translate("MainWindowPreferencesFrame", "Display autocompletion for filter text", nullptr));
        label_5->setText(QApplication::translate("MainWindowPreferencesFrame", "Main toolbar style:", nullptr));
        mainToolbarComboBox->setItemText(0, QApplication::translate("MainWindowPreferencesFrame", "Icons only", nullptr));
        mainToolbarComboBox->setItemText(1, QApplication::translate("MainWindowPreferencesFrame", "Text only", nullptr));
        mainToolbarComboBox->setItemText(2, QApplication::translate("MainWindowPreferencesFrame", "Icons & Text", nullptr));

        label_7->setText(QApplication::translate("MainWindowPreferencesFrame", "Language: ", nullptr));
        languageComboBox->setItemText(0, QApplication::translate("MainWindowPreferencesFrame", "Use system setting", nullptr));

    } // retranslateUi

};

namespace Ui {
    class MainWindowPreferencesFrame: public Ui_MainWindowPreferencesFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAIN_WINDOW_PREFERENCES_FRAME_H
