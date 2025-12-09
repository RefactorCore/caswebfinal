@echo off
set /p dbname=Enter database name to delete: 
echo You are about to delete "%dbname%". This action is permanent.
pause

"C:\Program Files\MariaDB 12.1\bin\mysql.exe" -u root -p -e "DROP DATABASE IF EXISTS %dbname%;"

echo.
echo Done.
pause
