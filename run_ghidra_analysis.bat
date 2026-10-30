@echo off
set JAVA_HOME="C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot"
set PATH=%JAVA_HOME%\bin;%PATH%

cd /d "C:\HK\COOP\coop-anything\tools\ghidra\ghidra_12.2_PUBLIC\support"

echo Starting Ghidra analysis at %DATE% %TIME%
analyzeHeadless.bat "C:/HK/COOP/coop-anything/tools/ghidra_projects" "SleepingDogs" -import "C:/HK/COOP/coop-anything/local/sleeping-dogs-test/sdhdship.exe" -scriptPath "C:/HK/COOP/coop-anything/tools/ghidra_scripts" -postScript analyze_ue3.py -deleteProject > "C:/HK/COOP/coop-anything/local/sleeping-dogs-test/ghidra_log.txt" 2>&1
echo Finished Ghidra analysis at %DATE% %TIME%
echo Exit code: %ERRORLEVEL%

pause