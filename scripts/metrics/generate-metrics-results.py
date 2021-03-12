#!/usr/bin/env python3
import os
import sys

import numpy as np
import pandas as pd

"""
	This script generates a CSV file containing software metrics from a given source code's root directory. The Understand command
	line interface must be present in the PATH variable (i.e. the 'und' command must work).

	Usage:
		generate-metrics-results.py <Mandatory Source Code Path>
"""

DEBUG_MODE = False
if DEBUG_MODE:
	print('Debug mode is enabled!')

script_name = sys.argv[0]
num_args = len(sys.argv) - 1

if num_args != 1:
	print(f'Wrong number of arguments. Usage: {script_name} <Source Code Path>')
	sys.exit(1)

source_code_path = sys.argv[1]
print(f'Generating the metrics from the source code in "{source_code_path}"...')
print()

understand_database_filename = 'project.und'
output_metrics_filename = 'metrics.csv'

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
	f'und -quiet -db "{understand_database_filename}" '
	f'create -languages c++ '
	f'settings -metrics all -metricsOutputFile "{output_metrics_filename}" -metricsFileNameDisplayMode NoPath -metricsShowFunctionParameterTypes on -metricsShowDeclaredInFile on -metricsDeclaredInFileDisplayMode RelativePath '
	f'add "{source_code_path}" '
	f'analyze '
	f'metrics '
)

print(f'> {command}')
print()

os.system(command)

print(f'Updating the file "{output_metrics_filename}" with aggregated metrics...')
print()

results = pd.read_csv(output_metrics_filename)

# Convert all numeric values to integers and leave any N/As with None.
results.iloc[:, 3:] = results.iloc[:, 3:].fillna(-1.0).astype(int)
results = results.replace({np.nan: None, -1: None})

# Inserts a new column after another one.
def insert_new_column(new_column, after_column):
	after_index = results.columns.get_loc(after_column) + 1
	results.insert(after_index, new_column, None)

insert_new_column('SumCountPath', 'CountPath')

insert_new_column('MaxCountInput', 'CountInput')
insert_new_column('AvgCountInput', 'CountInput')
insert_new_column('SumCountInput', 'CountInput')

insert_new_column('MaxCountOutput', 'CountOutput')
insert_new_column('AvgCountOutput', 'CountOutput')
insert_new_column('SumCountOutput', 'CountOutput')

insert_new_column('MaxMaxNesting', 'MaxNesting')
insert_new_column('AvgMaxNesting', 'MaxNesting')
insert_new_column('SumMaxNesting', 'MaxNesting')

insert_new_column('HenryKafura', 'MaxMaxNesting')

# For testing purposes: only insert some metrics.
if DEBUG_MODE:
	results = results[::1]

for index, row in results.iterrows():

	kind = row['Kind']
	name = row['Name']
	original_file_path = row['File']

	if original_file_path is not None:
		file_path = original_file_path.replace('\\', '/')

	if kind == 'File':

		# Aggregate a few metrics that are not computed by Understand.
		"""
		UPDATE 	software.FILES_1_dom AS TB1,
				(SELECT ID_File,

					SUM(CountPath) AS CountPath,
					
					SUM(CountInput) AS FanIn,
					SUM(CountOutput) AS FanOut,
					
					AVG(CountInput) AS AvgFanIn,
					AVG(CountOutput) AS AvgFanOut,
					
					MAX(CountInput) AS MaxFanIn,
					MAX(CountOutput) AS MaxFanOut,
					
					MAX(MaxNesting) AS MaxMaxNesting,
					AVG(MaxNesting) AS AvgMaxNesting,
					SUM(MaxNesting) AS SumMaxNesting,
					
					SUM(CountLineCodeExe*(CountInput*CountOutput)*(CountInput*CountOutput)) AS HK

				FROM software.FUNCTIONS_1_dom group by ID_File) AS TB2
		"""

		# Find functions contained in this file.
		results_in_this_file = results.loc[ (results['Kind'].str.contains('Function')) & (results['File'] == original_file_path) ]

		# Aggregates various function-level metrics by applying the sum, average, or maximum operations to a given column.
		def aggregate_metric(source_column, aggregation_type, destination_column):
			
			res = 0
			metrics_in_this_file = results_in_this_file[source_column]

			if not metrics_in_this_file.empty:

				if aggregation_type == 'Sum':
					res = metrics_in_this_file.sum()
				elif aggregation_type == 'Avg':
					res = metrics_in_this_file.mean()
				elif aggregation_type == 'Max':
					res = metrics_in_this_file.max()
				else:
					assert False

				# Every value in the output file must be an integer.
				res = round(res)

			results.loc[index, destination_column] = res

		aggregate_metric('CountPath', 'Sum', 'SumCountPath')

		aggregate_metric('CountInput', 'Max', 'MaxCountInput')
		aggregate_metric('CountInput', 'Avg', 'AvgCountInput')
		aggregate_metric('CountInput', 'Sum', 'SumCountInput')

		aggregate_metric('CountOutput', 'Max', 'MaxCountOutput')
		aggregate_metric('CountOutput', 'Avg', 'AvgCountOutput')
		aggregate_metric('CountOutput', 'Sum', 'SumCountOutput')

		aggregate_metric('MaxNesting', 'Max', 'MaxMaxNesting')
		aggregate_metric('MaxNesting', 'Avg', 'AvgMaxNesting')
		aggregate_metric('MaxNesting',  'Sum', 'SumMaxNesting')

		# Henry Kafura Size: SUM( CountLineCodeExe x (CountInput x CountOutput)^2 )
		count_line_code_exe = results_in_this_file['CountLineCodeExe']
		count_input = results_in_this_file['CountInput']
		count_output = results_in_this_file['CountOutput']

		results.loc[index, 'HenryKafura'] = int( ( count_line_code_exe * (count_input * count_output) ** 2 ).sum() )

results.to_csv(output_metrics_filename, index=False)

print('Finished running.')
