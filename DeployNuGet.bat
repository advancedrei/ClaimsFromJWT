@echo off
echo Would you like to push the packages to NuGet when finished?
set /p choice="Enter y/n: "

del *.nupkg
@echo on
".nuget/nuget.exe" pack ClaimsFromJwt.nuspec
if /i %choice% equ y (
    ".nuget/nuget.exe" push *.nupkg
)
pause