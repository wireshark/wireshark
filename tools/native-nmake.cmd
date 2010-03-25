@echo off

rem 
set WIRESHARK_TARGET_PLATFORM=

if NOT DEFINED VCINSTALLDIR goto RUN_NMAKE

if NOT EXIST "%VCINSTALLDIR%\vcvarsall.bat" goto RUN_NMAKE

call "%VCINSTALLDIR%\vcvarsall.bat"

:RUN_NMAKE
%1 %2 %3 %4 %5 %6 %7 %8 %9
