cd /d "C:\Users\zz\source\repos\ProcessProtect\ProcessProtect" &msbuild "ProcessProtect.vcxproj" /t:sdvViewer /p:configuration="Release" /p:platform="x64" /p:SolutionDir="C:\Users\zz\source\repos\ProcessProtect" 
exit %errorlevel% 