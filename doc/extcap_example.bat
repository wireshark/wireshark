@echo off
setlocal
set PYTHONPATH=%~dp0
set PYTHON=py
WHERE %PYTHON% >nul 2>&1
IF %ERRORLEVEL% NEQ 0 set PYTHON=python
REM Replace "%~dp0" with the path to the script if located elsewhere.
REM Note that the current working directory is likely the Wireshark directory,
REM not the extcap directory.
%PYTHON% %~dp0extcap_example.py %*
