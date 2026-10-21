@echo off
setlocal
if not defined CHAT_VCVARS exit /b 1
call "%CHAT_VCVARS%" >nul
if errorlevel 1 exit /b 1
pushd "%~dp0bin"
cl /nologo /std:c++17 /EHsc /W4 /utf-8 /O2 /MT /Fe:chat_server.exe ..\src\server.cpp ws2_32.lib
if errorlevel 1 (popd & exit /b 1)
cl /nologo /std:c++17 /EHsc /W4 /utf-8 /O2 /MT /Fe:chat_client.exe ..\src\client.cpp ws2_32.lib
if errorlevel 1 (popd & exit /b 1)
del /q *.obj
popd
