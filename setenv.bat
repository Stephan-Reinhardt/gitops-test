@echo off
rem ------------------------------------------------------------------
rem  Start Launch4j with a specific Java - no admin rights needed.
rem
rem    launch4j.bat                 -> opens the Launch4j GUI
rem    launch4j.bat myapp.xml       -> builds the exe from that config
rem
rem  Variables only apply to this script (setlocal).
rem ------------------------------------------------------------------
setlocal

rem === adjust these two paths ========================================
set "JAVA_HOME=%USERPROFILE%\tools\jdk8"
set "LAUNCH4J_HOME=%USERPROFILE%\tools\launch4j"
rem ==================================================================

set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"
set "JAVAW_EXE=%JAVA_HOME%\bin\javaw.exe"
set "L4J_JAR=%LAUNCH4J_HOME%\launch4j.jar"

rem Also put this Java first on PATH, in case Launch4j looks there
set "PATH=%JAVA_HOME%\bin;%PATH%"

rem --- sanity checks -------------------------------------------------
if not exist "%JAVA_EXE%" (
    echo [ERROR] Java not found: "%JAVA_EXE%"
    echo         Check JAVA_HOME at the top of this file.
    pause
    exit /b 1
)
if not exist "%L4J_JAR%" (
    echo [ERROR] Launch4j not found: "%L4J_JAR%"
    echo         Check LAUNCH4J_HOME at the top of this file.
    pause
    exit /b 1
)

echo Java:     "%JAVA_EXE%"
"%JAVA_EXE%" -version
echo Launch4j: "%L4J_JAR%"
echo.

rem --- no argument: open the GUI ------------------------------------
if "%~1"=="" (
    rem javaw = no extra console window; start = this window can close
    start "Launch4j" "%JAVAW_EXE%" -jar "%L4J_JAR%"
    exit /b 0
)

rem --- argument given: build from config ----------------------------
if not exist "%~f1" (
    echo [ERROR] Config file not found: "%~f1"
    pause
    exit /b 1
)

echo Building from "%~f1" ...
"%JAVA_EXE%" -jar "%L4J_JAR%" "%~f1"
if errorlevel 1 (
    echo.
    echo [FAILED] Launch4j returned an error.
    pause
    exit /b 1
)

echo.
echo [OK] Done.
endlocal
exit /b 0
