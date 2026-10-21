@echo off
setlocal
if not defined LAB02_VCVARS exit /b 1
if not defined LAB02_SDK exit /b 1
call "%LAB02_VCVARS%" >nul
if errorlevel 1 exit /b 1
pushd "%~dp0bin"
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /O2 /MT /I"%LAB02_SDK%\Include" /Fe:packet_capture.exe ..\src\main.cpp ws2_32.lib
if errorlevel 1 (popd & exit /b 1)
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /O2 /MT /I..\src /Fe:parser_tests.exe ..\tests\parser_tests.cpp
if errorlevel 1 (popd & exit /b 1)
del /q *.obj
popd
