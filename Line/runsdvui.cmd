cd /d "F:\project\FileFilter\Line" &msbuild "Line.vcxproj" /t:sdvViewer /p:configuration="Debug" /p:platform=Win32
exit %errorlevel% 