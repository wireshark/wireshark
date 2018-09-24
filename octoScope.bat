@echo off

:: Description: This script executes one of two cross-probing Python scripts based on the
:: file extension of the filename passed to it.
:: ".iqvsa" = Litepoint
:: ".tdms" = National Instruments

:: Usage: >> octoScope.bat <IQ Source> <Packet Number>

::py -3.6 "C:\Users\Andrew.McGarry\workspace\Litepoint_SCPI_Example\analyzePacketLitepoint.py" %1 --address 10.100.100.130
SET iqSource=%1

for /F "tokens=1,2,3,4 delims=:" %%a in ("%iqSource%") do (
SET system=%%a
SET equipment=%%b
SET filename=%%c
SET packetnum=%%d
)
SET system=%system:~1%
SET packetnum=%packetnum:~0,-1%
if [%iqSource%]==[] (
ECHO "Usage: octoScope.bat <IQ Source>"
exit /b 1
)
if [%2] NEQ [] (
ECHO "Usage: octoScope.bat <IQ Source>"
exit /b 1
)

ECHO This is a %system% frame from %equipment%
ECHO Looking for frame %packetnum% in %filename%
SET file_ext=%filename:~-5%
SET found=1
if %file_ext%==.tdms (
ECHO TDMS File type indicated
SET found=0
)
if %file_ext%==iqvsa (
ECHO IQVSA File type indicated
SET found=0
py -3.6 "C:\Users\Andrew.McGarry\workspace\Triathlon_Litepoint_Project_Trunk\analyzePacketLitepoint.py" %packetnum% --address 10.100.100.130
)
if %found%==1 (
ECHO Invalid filetype indicated
)
cmd /k
exit /b %found%
