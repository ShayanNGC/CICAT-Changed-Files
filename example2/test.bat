:: This test file runs example2 100 times and puts the output in test_output.txt.
:: if 'End of run' appears in test_output.txt 100 times, every run executed to completion. 
:: This file must be run in the 'example2' folder

:: The command below runs CICAT a single time
:: python ../generator/scenGEN.py -i INFRASTRUCTURE.ex2.xlsx -s SCENARIOS.ex2.xlsx


:: Begin test
@ECHO OFF
ECHO Creating test_output.txt...
echo. > test_output.txt

:: write the contents of the output into the file 100 times
FOR /L %%i IN (0, 1, 99) DO (
    echo Running test %%i...
    python ../generator/scenGEN.py -i INFRASTRUCTURE.ex2.xlsx -s SCENARIOS.ex2.xlsx >> test_output.txt )

echo Tests complete, check test_output.txt!

