@echo off

rem Directions:

rem Download the latest source archive from
rem http://qt.nokia.com/downloads/downloads#qt-lib

rem Unpack the archive and run this script from the archive directory.

rem The default installation prefix is c:\Qt\5.1.1-... You can change
rem it below.

echo "%PATH%" | find "cygwin"
if errorlevel 1 set PATH=%PATH%;c:\cygwin\bin

set VS_VERSION=""
set API_BITS=""

rem Visual Studio version

if not "%VCINSTALLDIR%"=="" (
  echo "%VCINSTALLDIR%" | find "10.0"
  if not errorlevel 1 (
    set VS_VERSION=2010
  ) else (
    echo "%VCINSTALLDIR%" | find "9.0"
    if not errorlevel 1 (
      set VS_VERSION=2008
    )
  )
)

if "%VS_VERSION%"=="" goto no_vs_version

rem Target API

if not "%FrameworkDir64%"=="" (
  set API_BITS=64
) else (
  if not "%FrameworkDir%"=="" (
    echo %FrameworkDir% | find "64"
    if not errorlevel 1 (
      set API_BITS=64
    ) else (
      set API_BITS=32
    )
  )
)

if "%API_BITS%"=="" goto no_api_bits

set QT_PLATFORM=win32-msvc%VS_VERSION%
set QT_PREFIX=c:\Qt\5.1.1-MSVC%VS_VERSION%-win%API_BITS%

nmake confclean || echo ...and that's probably OK.

echo.
echo ========
echo Building using mkspec %QT_PLATFORM% (%API_BITS% bit)
echo Installing in %QT_PREFIX%
echo ========

rem We could probably get away with skipping several other modules, e.g.
rem qtsensors and qtserialport
configure -opensource -confirm-license -platform %QT_PLATFORM% -prefix %QT_PREFIX% ^
    -no-dbus ^
    -no-opengl -no-angle ^
    -no-sql-sqlite ^
    -no-cetest ^
    -mp ^
    -nomake examples ^
    -skip qtdoc ^
    -skip qtquickcontrols ^
    -skip qtwebkit ^
    -skip qtwebkit-examples ^
    -skip qtxmlpatterns ^


nmake

echo.
echo You'll have to run nmake install yourself.

goto end

:no_vs_version
echo "Unable to find your Visual Studio version. Did you run vcvarsall.bat?"
goto end

:no_api_bits
echo "Unable to find your target API. Did you run vcvarsall.bat?"
goto end

:end
