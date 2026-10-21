@echo off
setlocal
if not defined LAB03_VCVARS exit /b 1
call "%LAB03_VCVARS%" >nul
if errorlevel 1 exit /b 1
pushd "%~dp0bin"
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /O2 /MT /Fe:rudp.exe ..\src\main.cpp ..\src\transfer.cpp ..\src\relay.cpp ws2_32.lib
if errorlevel 1 (popd & exit /b 1)
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /O2 /MT /I..\src /Fe:protocol_tests.exe ..\tests\protocol_tests.cpp
if errorlevel 1 (popd & exit /b 1)
del /q *.obj
popd
