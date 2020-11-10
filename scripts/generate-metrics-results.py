#!/usr/bin/env python
import os
import sys

"""
	This script generates a CSV file containing software metrics from a given source code's root directory. The Understand command
	line interface must be present in the PATH variable (i.e. the 'und' command must work).

	Usage:
		generate-metrics-results.py <Mandatory Source Code Path>
"""

script_name = sys.argv[0]
num_args = len(sys.argv) - 1

if num_args != 1:
	print(f'Wrong number of arguments. Usage: {script_name} <Source Code Path>')
	sys.exit(1)

source_code_path = sys.argv[1]
print(f'Generating the metrics from the source code in "{source_code_path}"...')

METRICS_RESULTS_DIRECTORY = 'metrics-results'
os.makedirs(METRICS_RESULTS_DIRECTORY, exist_ok=True)

understand_database_path = os.path.join(METRICS_RESULTS_DIRECTORY, 'metrics.udb')
output_metrics_path = os.path.join(METRICS_RESULTS_DIRECTORY, 'metrics.csv')

"""
	Understand Metrics Settings:
	- WriteColumnTitles				on/off (default on)
	- ShowFunctionParameterTypes	on/off (default off)
	- ShowDeclaredInFile			on/off (default off)
	- FileNameDisplayMode			NoPath/FullPath/RelativePath (default NoPath)
	- DeclaredInFileDisplayMode		NoPath/FullPath/RelativePath (default NoPath)
	- OutputFile					<CSV File Path> (default "<Database Filename>.csv")

	These were listed using the command: und list -all settings <Database Filename>
"""

command = (
	f'und -quiet -db "{understand_database_path}" '
	f'create -languages c++ '
	f'settings -metrics all -metricsOutputFile "{output_metrics_path}" -metricsFileNameDisplayMode NoPath -metricsShowFunctionParameterTypes on -metricsShowDeclaredInFile on -metricsDeclaredInFileDisplayMode RelativePath '
	f'add "{source_code_path}" '
	f'analyze '
	f'metrics '
)

print(f'> {command}')
print()

os.system(command)

print()
print('Finished running.')
