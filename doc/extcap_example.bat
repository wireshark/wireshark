@echo off
setlocal
set PYTHONPATH=%~dp0
set PYTHON=py
WHERE %PYTHON% >nul 2>&1
IF %ERRORLEVEL% NEQ 0 set PYTHON=python
%PYTHON% extcap_example.py %*