@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"
set "TOOL_JAR=%REPO_ROOT%\web-starter-tooling\target\web-starter-tooling.jar"

rem Repackage on each Windows invocation so an existing target JAR can never hide
rem newer source files. Maven is incremental, so unchanged classes are reused.
call "%REPO_ROOT%\mvnw.cmd" -B -ntp -pl web-starter-tooling -am package -DskipTests
if errorlevel 1 exit /b %errorlevel%

java -jar "%TOOL_JAR%" %*
exit /b %errorlevel%
