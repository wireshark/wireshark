/*
    Platypus - create MacOS X application bundles that execute scripts
        This is the executable that goes into Platypus apps
    Copyright (C) 2003 Sveinbjorn Thordarson <sveinbt@hi.is>

    With modifications by Aaron Voisine for gimp.app
    With modifications by Marianne gagnon for Wilber-loves-apple
    With modifications by Michael Wybrow for Inkscape.app
    With modifications by Gerald Combs for Wireshark.app

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
    USA.

    main.c - main program file

*/

/*
 * This app laucher basically takes care of:
 * - launching Wireshark and X11 when double-clicked
 * - bringing X11 to the top when its icon is clicked in the dock (via a small applescript)
 * - catch file dropped on icon events (and double-clicked gimp documents) and notify gimp.
 * - catch quit events performed outside gimp, e.g. on the dock icon.
 */

///////////////////////////////////////
// Includes
///////////////////////////////////////
#pragma mark Includes

// Apple stuff
#include <Carbon/Carbon.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>

// Unix stuff
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include <stdio.h>

///////////////////////////////////////
// Definitions
///////////////////////////////////////
#pragma mark Definitions

// name length limits
#define	kMaxPathLength 1024

// names of files bundled with app
#define	kScriptFileName "script"
#define kOpenDocFileName "openDoc"

// custom carbon events
#define kEventClassRedFatalAlert 911
#define kEventKindX11Failed 911
#define kEventKindFCCacheFailed 912

//maximum arguments the script accepts
#define	kMaxArgumentsToScript 252

///////////////////////////////////////
// Prototypes
///////////////////////////////////////
#pragma mark Prototypes

static void *Execute(void *arg);
static void *OpenDoc(void *arg);
static OSErr ExecuteScript(char *script, pid_t *pid);

static void  GetParameters(void);
static char* GetScript(void);
static char* GetOpenDoc(void);

OSErr LoadMenuBar(char *appName);

static OSStatus FSMakePath(FSSpec file, char *path, long maxPathSize);
static void RedFatalAlert(Str255 errorString, Str255 expStr);
static short DoesFileExist(char *path);

static OSErr AppQuitAEHandler(const AppleEvent *theAppleEvent,
                              AppleEvent *reply, long refCon);
static OSErr AppOpenDocAEHandler(const AppleEvent *theAppleEvent,
                                 AppleEvent *reply, long refCon);
static OSErr AppOpenAppAEHandler(const AppleEvent *theAppleEvent,
                                 AppleEvent *reply, long refCon);
static OSStatus X11FailedHandler(EventHandlerCallRef theHandlerCall,
                                 EventRef theEvent, void *userData);
static OSStatus FCCacheFailedHandler(EventHandlerCallRef theHandlerCall,
                                 EventRef theEvent, void *userData);
static OSErr AppReopenAppAEHandler(const AppleEvent *theAppleEvent,
                                   AppleEvent *reply, long refCon);

static OSStatus CompileAppleScript(const void* text, long textLength,
                                  AEDesc *resultData);
static OSStatus SimpleCompileAppleScript(const char* theScript);
static OSErr runScript();

///////////////////////////////////////
// Globals
///////////////////////////////////////
#pragma mark Globals

// process id of forked process
pid_t pid = 0;

// thread id of threads that start scripts
pthread_t odtid = 0, tid = 0;

// indicator of whether the script has completed executing
short taskDone = true;

// execution parameters
char scriptPath[kMaxPathLength];
char openDocPath[kMaxPathLength];

//arguments to the script
char *arguments[kMaxArgumentsToScript+3];
char *fileArgs[kMaxArgumentsToScript];
short numArgs = 0;

extern char **environ;

#pragma mark -

///////////////////////////////////////
// Program entrance point
///////////////////////////////////////
int main(int argc, char* argv[])
{
    OSErr err = noErr;
    EventTypeSpec X11events = { kEventClassRedFatalAlert, kEventKindX11Failed };
    EventTypeSpec FCCacheEvents = { kEventClassRedFatalAlert, kEventKindFCCacheFailed };

    InitCursor();

    //install Apple Event handlers
    err += AEInstallEventHandler(kCoreEventClass, kAEQuitApplication,
                                 NewAEEventHandlerUPP(AppQuitAEHandler),
                                 0, false);
    err += AEInstallEventHandler(kCoreEventClass, kAEOpenDocuments,
                                 NewAEEventHandlerUPP(AppOpenDocAEHandler),
                                 0, false);
    err += AEInstallEventHandler(kCoreEventClass, kAEOpenApplication,
                                 NewAEEventHandlerUPP(AppOpenAppAEHandler),
                                 0, false);

    err += AEInstallEventHandler(kCoreEventClass, kAEReopenApplication,
                                 NewAEEventHandlerUPP(AppReopenAppAEHandler),
                                 0, false);

    err += InstallEventHandler(GetApplicationEventTarget(),
                               NewEventHandlerUPP(X11FailedHandler), 1,
                               &X11events, NULL, NULL);
    err += InstallEventHandler(GetApplicationEventTarget(),
                               NewEventHandlerUPP(FCCacheFailedHandler), 1,
                               &FCCacheEvents, NULL, NULL);

    if (err) RedFatalAlert("\pInitialization Error",
                           "\pError initing Apple Event handlers.");

    //create the menu bar
    if (err = LoadMenuBar(NULL)) RedFatalAlert("\pInitialization Error",
                                               "\pError loading MenuBar.nib.");

    GetParameters(); //load data from files containing exec settings

    // compile "icon clicked" script so it's ready to execute
    SimpleCompileAppleScript("tell application \"X11\" to activate");

    RunApplicationEventLoop(); //Run the event loop
    return 0;
}

#pragma mark -


static void RequestUserAttention(void)
{
    NMRecPtr notificationRequest = (NMRecPtr) NewPtr(sizeof(NMRec));

    memset(notificationRequest, 0, sizeof(*notificationRequest));
    notificationRequest->qType = nmType;
    notificationRequest->nmMark = 1;
    notificationRequest->nmIcon = 0;
    notificationRequest->nmSound = 0;
    notificationRequest->nmStr = NULL;
    notificationRequest->nmResp = NULL;

    verify_noerr(NMInstall(notificationRequest));
}


static void ShowFirstStartWarningDialog(void)
{
    SInt16 itemHit;

    AlertStdAlertParamRec params;
    params.movable = true;
    params.helpButton = false;
    params.filterProc = NULL;
    params.defaultText = (void *) kAlertDefaultOKText;
    params.cancelText = NULL;
    params.otherText = NULL;
    params.defaultButton = kAlertStdAlertOKButton;
    params.cancelButton = kAlertStdAlertCancelButton;
    params.position = kWindowDefaultPosition;

    StandardAlert(kAlertNoteAlert, "\pWireshark on Mac OS X",
            "\pWhile Wireshark is open, its windows can be displayed or hidden by displaying or hiding the X11 application.\n\nThe first time this version of Wireshark is run it may take several minutes before the main window is displayed while font caches are built.",
            &params, &itemHit);
}


//////////////////////////////////
// Handler for when fontconfig caches need to be generated
//////////////////////////////////
static OSStatus FCCacheFailedHandler(EventHandlerCallRef theHandlerCall,
                                 EventRef theEvent, void *userData)
{

    pthread_join(tid, NULL);
    if (odtid) pthread_join(odtid, NULL);

    // Bounce Wireshark Dock icon
    RequestUserAttention();
    // Need to show warning to the user, then carry on.
    ShowFirstStartWarningDialog();

    // Note that we've seen the warning.
    system("test -d \"$HOME/.wireshark\" || mkdir \"$HOME/.wireshark\"; "
           "touch \"$HOME/.wireshark/.fccache-new\"");
    // Rerun now.
    OSErr err = ExecuteScript(scriptPath, &pid);
    ExitToShell();

    return noErr;
}

///////////////////////////////////
// Execution thread starts here
///////////////////////////////////
static void *Execute (void *arg)
{
    EventRef event;

    taskDone = false;

    OSErr err = ExecuteScript(scriptPath, &pid);
    if (err == (OSErr)11) {
        CreateEvent(NULL, kEventClassRedFatalAlert, kEventKindX11Failed, 0,
                    kEventAttributeNone, &event);
        PostEventToQueue(GetMainEventQueue(), event, kEventPriorityStandard);
    }
    else if (err == (OSErr)12) {
        CreateEvent(NULL, kEventClassRedFatalAlert, kEventKindFCCacheFailed, 0,
                    kEventAttributeNone, &event);
        PostEventToQueue(GetMainEventQueue(), event, kEventPriorityHigh);
    }
    else ExitToShell();
    return 0;
}

///////////////////////////////////
// Open additional documents thread starts here
///////////////////////////////////
static void *OpenDoc (void *arg)
{
    ExecuteScript(openDocPath, NULL);
    return 0;
}

///////////////////////////////////////
// Run a script via the system command
///////////////////////////////////////
static OSErr ExecuteScript (char *script, pid_t *pid)
{
    pid_t wpid = 0, p = 0;
    int status, i;

    if (! pid) pid = &p;

    // Generate the array of argument strings before we do any executing
    arguments[0] = script;
    for (i = 0; i < numArgs; i++) arguments[i + 1] = fileArgs[i];
    arguments[i + 1] = NULL;

    *pid = fork(); //open fork

    if (*pid == (pid_t)-1) exit(13); //error
    else if (*pid == 0) { //child process started
        execve(arguments[0], arguments, environ);
        exit(13); //if we reach this point, there's an error
    }

    wpid = waitpid(*pid, &status, 0); //wait while child process finishes

    if (wpid == (pid_t)-1) return wpid;
    return (OSErr)WEXITSTATUS(status);
}

#pragma mark -

///////////////////////////////////////
// This function loads all the neccesary settings
// from config files in the Resources folder
///////////////////////////////////////
static void GetParameters (void)
{
    char *str;
    if (! (str = (char *)GetScript())) //get path to script to be executed
        RedFatalAlert("\pInitialization Error",
                      "\pError getting script from application bundle.");
    strcpy((char *)&scriptPath, str);

    if (! (str = (char *)GetOpenDoc())) //get path to openDoc
        RedFatalAlert("\pInitialization Error",
                      "\pError getting openDoc from application bundle.");
    strcpy((char *)&openDocPath, str);
}

///////////////////////////////////////
// Get path to the script in Resources folder
///////////////////////////////////////
static char* GetScript (void)
{
    CFStringRef fileName;
    CFBundleRef appBundle;
    CFURLRef scriptFileURL;
    FSRef fileRef;
    FSSpec fileSpec;
    char *path;

    //get CF URL for script
    if (! (appBundle = CFBundleGetMainBundle())) return NULL;
    if (! (fileName = CFStringCreateWithCString(NULL, kScriptFileName,
                                                kCFStringEncodingASCII)))
        return NULL;
    if (! (scriptFileURL = CFBundleCopyResourceURL(appBundle, fileName, NULL,
                                                   NULL))) return NULL;

    //Get file reference from Core Foundation URL
    if (! CFURLGetFSRef(scriptFileURL, &fileRef)) return NULL;

    //dispose of the CF variables
    CFRelease(scriptFileURL);
    CFRelease(fileName);

    //convert FSRef to FSSpec
    if (FSGetCatalogInfo(&fileRef, kFSCatInfoNone, NULL, NULL, &fileSpec,
                         NULL)) return NULL;

    //create path string
    if (! (path = malloc(kMaxPathLength))) return NULL;
    if (FSMakePath(fileSpec, path, kMaxPathLength)) return NULL;
    if (! DoesFileExist(path)) return NULL;

    return path;
}

///////////////////////////////////////
// Gets the path to openDoc in Resources folder
///////////////////////////////////////
static char* GetOpenDoc (void)
{
    CFStringRef fileName;
    CFBundleRef appBundle;
    CFURLRef openDocFileURL;
    FSRef fileRef;
    FSSpec fileSpec;
    char *path;

    //get CF URL for openDoc
    if (! (appBundle = CFBundleGetMainBundle())) return NULL;
    if (! (fileName = CFStringCreateWithCString(NULL, kOpenDocFileName,
                                                kCFStringEncodingASCII)))
        return NULL;
    if (! (openDocFileURL = CFBundleCopyResourceURL(appBundle, fileName, NULL,
                                                    NULL))) return NULL;

    //Get file reference from Core Foundation URL
    if (! CFURLGetFSRef( openDocFileURL, &fileRef )) return NULL;

    //dispose of the CF variables
    CFRelease(openDocFileURL);
    CFRelease(fileName);

    //convert FSRef to FSSpec
    if (FSGetCatalogInfo(&fileRef, kFSCatInfoNone, NULL, NULL, &fileSpec,
                         NULL)) return NULL;

    //create path string
    if (! (path = malloc(kMaxPathLength))) return NULL;
    if (FSMakePath(fileSpec, path, kMaxPathLength)) return NULL;
    if (! DoesFileExist(path)) return NULL;

    return path;
}

#pragma mark -

/////////////////////////////////////
// Load menu bar from nib
/////////////////////////////////////
OSErr LoadMenuBar (char *appName)
{
    OSErr err;
    IBNibRef nibRef;

    if (err = CreateNibReference(CFSTR("MenuBar"), &nibRef)) return err;
    if (err = SetMenuBarFromNib(nibRef, CFSTR("MenuBar"))) return err;
    DisposeNibReference(nibRef);

    return noErr;
}

#pragma mark -

///////////////////////////////////////
// Generate path string from FSSpec record
///////////////////////////////////////
static OSStatus FSMakePath(FSSpec file, char *path, long maxPathSize)
{
    OSErr err = noErr;
    FSRef fileRef;

    //create file reference from file spec
    if (err = FSpMakeFSRef(&file, &fileRef)) return err;

    // and then convert the FSRef to a path
    return FSRefMakePath(&fileRef, path, maxPathSize);
}

////////////////////////////////////////
// Standard red error alert, then exit application
////////////////////////////////////////
static void RedFatalAlert (Str255 errorString, Str255 expStr)
{
    StandardAlert(kAlertStopAlert, errorString,  expStr, NULL, NULL);
    ExitToShell();
}

///////////////////////////////////////
// Determines whether file exists at path or not
///////////////////////////////////////
static short DoesFileExist (char *path)
{
    if (access(path, F_OK) == -1) return false;
    return true;
}

#pragma mark -

///////////////////////////////////////
// Apple Event handler for Quit i.e. from
// the dock or Application menu item
///////////////////////////////////////
static OSErr AppQuitAEHandler(const AppleEvent *theAppleEvent,
                              AppleEvent *reply, long refCon)
{
    #pragma unused (reply, refCon, theAppleEvent)

    while (numArgs > 0) free(fileArgs[numArgs--]);

    if (! taskDone && pid) { //kill the script process brutally
        kill(pid, 9);
        printf("Platypus App: PID %d killed brutally\n", pid);
    }

    pthread_cancel(tid);
    if (odtid) pthread_cancel(odtid);

    ExitToShell();

    return noErr;
}

/////////////////////////////////////
// Handler for docs dragged on app icon
/////////////////////////////////////
static OSErr AppOpenDocAEHandler(const AppleEvent *theAppleEvent,
                                 AppleEvent *reply, long refCon)
{
    #pragma unused (reply, refCon)

    OSErr err = noErr;
    AEDescList fileSpecList;
    AEKeyword keyword;
    DescType type;

    short i;
    long count, actualSize;

    FSSpec fileSpec;
    char path[kMaxPathLength];

    while (numArgs > 0) free(fileArgs[numArgs--]);

    //Read the AppleEvent
    err = AEGetParamDesc(theAppleEvent, keyDirectObject, typeAEList,
                         &fileSpecList);

    err = AECountItems(&fileSpecList, &count); //Count number of files

    for (i = 1; i <= count; i++) { //iteratively process each file
        //get fsspec from apple event
        if (! (err = AEGetNthPtr(&fileSpecList, i, typeFSS, &keyword, &type,
                                 (Ptr)&fileSpec, sizeof(FSSpec), &actualSize)))
        {
            //get path from file spec
            if ((err = FSMakePath(fileSpec, (unsigned char *)&path,
                                  kMaxPathLength))) return err;

            if (numArgs == kMaxArgumentsToScript) break;

            if (! (fileArgs[numArgs] = malloc(kMaxPathLength))) return true;

            strcpy(fileArgs[numArgs++], (char *)&path);
        }
        else return err;
    }

    if (! taskDone) pthread_create(&odtid, NULL, OpenDoc, NULL);
    else pthread_create(&tid, NULL, Execute, NULL);

    return err;
}

///////////////////////////////
// Handler for clicking on app icon
///////////////////////////////
// if app is already open
static OSErr AppReopenAppAEHandler(const AppleEvent *theAppleEvent,
                                 AppleEvent *reply, long refCon)
{
    return runScript();
}

// if app is being opened
static OSErr AppOpenAppAEHandler(const AppleEvent *theAppleEvent,
                                 AppleEvent *reply, long refCon)
{
    #pragma unused (reply, refCon, theAppleEvent)

    // the app has been opened without any items dragged on to it
    pthread_create(&tid, NULL, Execute, NULL);

    return noErr;
}


static void OpenURL(Str255 url)
{
	// Use Internet Config to hand the URL to the appropriate application, as
	// set by the user in the Internet Preferences pane.
	ICInstance icInstance;
	// Applications creator code:
	OSType signature = 'Inks';
	OSStatus error = ICStart( &icInstance, signature );
	if ( error == noErr )
	{
		ConstStr255Param hint = 0x0;
		const char* data = url;
		long length = strlen(url);
		long start =  0;
		long end = length;
		// Don't bother testing return value (error); launched application will
		// report problems.
		ICLaunchURL( icInstance, hint, data, length, &start, &end );
		ICStop( icInstance );
	}
}


//////////////////////////////////
// Handler for when X11 fails to start
//////////////////////////////////
static OSStatus X11FailedHandler(EventHandlerCallRef theHandlerCall,
                                 EventRef theEvent, void *userData)
{
    #pragma unused(theHanderCall, theEvent, userData)

    pthread_join(tid, NULL);
    if (odtid) pthread_join(odtid, NULL);

	SInt16 itemHit;
	const unsigned char *getX11 = "\pGet X11 for Panther";

	AlertStdAlertParamRec params;
	params.movable = true;
	params.helpButton = false;
	params.filterProc = NULL;
	params.defaultText = (StringPtr) kAlertDefaultOKText;
	params.cancelText = getX11;
	params.otherText = NULL;
	params.defaultButton = kAlertStdAlertOKButton;
	params.cancelButton = kAlertStdAlertCancelButton;
	params.position = kWindowDefaultPosition;

	StandardAlert(kAlertStopAlert, "\pFailed to start X11",
			"\pWireshark.app requires Apple's X11, which is freely downloadable from Apple's website for Panther (10.3.x) users and available as an optional install from the installation DVD for Tiger (10.4.x) users.\n\nPlease install X11 and restart Wireshark.",
			&params, &itemHit);

	if (itemHit == kAlertStdAlertCancelButton)
	{
		OpenURL("http://www.apple.com/downloads/macosx/apple/macosx_updates/x11formacosx.html");
	}

    ExitToShell();


    return noErr;
}


// Compile and run a small AppleScript. The code below does no cleanup and no proper error checks
// but since it's there until the app is shut down, and since we know the script is okay,
// there should not be any problems.
ComponentInstance theComponent;
AEDesc scriptTextDesc;
OSStatus err;
OSAID scriptID, resultID;

static OSStatus CompileAppleScript(const void* text, long textLength,
                                  AEDesc *resultData) {

    resultData = NULL;
    /* set up locals to a known state */
    theComponent = NULL;
    AECreateDesc(typeNull, NULL, 0, &scriptTextDesc);
    scriptID = kOSANullScript;
    resultID = kOSANullScript;

    /* open the scripting component */
    theComponent = OpenDefaultComponent(kOSAComponentType,
                                        typeAppleScript);
    if (theComponent == NULL) { err = paramErr; return err; }

    /* put the script text into an aedesc */
    err = AECreateDesc(typeChar, text, textLength, &scriptTextDesc);
    if (err != noErr) return err;

    /* compile the script */
    err = OSACompile(theComponent, &scriptTextDesc,
                     kOSAModeNull, &scriptID);

    return err;
}

/* runs the compiled applescript */
static OSErr runScript()
{
    /* run the script */
    err = OSAExecute(theComponent, scriptID, kOSANullScript,
                     kOSAModeNull, &resultID);
    return err;
}


/* Simple shortcut to the function that actually compiles the applescript. */
static OSStatus SimpleCompileAppleScript(const char* theScript) {
    return CompileAppleScript(theScript, strlen(theScript), NULL);
}
