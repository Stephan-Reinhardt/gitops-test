@echo off
rem ------------------------------------------------------------------
rem  Build the Launch4j exe without admin rights.
rem  Env vars set here only live for this script (setlocal),
rem  nothing is changed on the system.
rem ------------------------------------------------------------------
setlocal

rem === adjust these paths to where you unzipped the tools ===========
set "TOOLS=%USERPROFILE%\tools"
set "JAVA_HOME=%TOOLS%\jdk8"
set "LAUNCH4J_HOME=%TOOLS%\launch4j"
set "ANT_HOME=%TOOLS%\apache-ant"
rem set "MAVEN_HOME=%TOOLS%\apache-maven"

rem Launch4j config, relative to this .bat file
set "L4J_CONFIG=%~dp0launch4j.xml"
rem ==================================================================

set "PATH=%JAVA_HOME%\bin;%ANT_HOME%\bin;%PATH%"
rem set "PATH=%MAVEN_HOME%\bin;%PATH%"

rem --- sanity checks -------------------------------------------------
if not exist "%JAVA_HOME%\bin\java.exe" (
    echo [ERROR] java.exe not found in "%JAVA_HOME%\bin" - check JAVA_HOME
    goto :error
)
if not exist "%LAUNCH4J_HOME%\launch4j.jar" (
    echo [ERROR] launch4j.jar not found in "%LAUNCH4J_HOME%" - check LAUNCH4J_HOME
    goto :error
)
if not exist "%L4J_CONFIG%" (
    echo [ERROR] Launch4j config not found: "%L4J_CONFIG%"
    goto :error
)

echo Using Java:
java -version
echo.

rem --- work from the project folder (where this .bat lives) ---------
cd /d "%~dp0"

rem --- 1. build the jar (uncomment what the project uses) -----------
rem call ant jar || goto :error
rem call mvn -q package || goto :error

rem --- 2. wrap it into the exe -------------------------------------
rem Calling launch4j.jar directly with our java avoids launch4jc.exe
rem having to search for a Java runtime on its own.
java -jar "%LAUNCH4J_HOME%\launch4j.jar" "%L4J_CONFIG%" || goto :error

echo.
echo [OK] Build finished.
endlocal
exit /b 0

:error
echo.
echo [FAILED] Build aborted.
endlocal
exit /b 1
