#!/usr/bin/env python3

"""
	This script splits the previously generated software metrics according to their code units (files, functions, or classes),
	and computes new ones.
	
	This information includes the file's path, whether it was vulnerable or not, the associated Git commit where this specific
	file version originated from, and various different software metrics generated by the Understand tool and by the scraping
	module.

	This script uses each CSV file generated after running "generate_metrics.py" to create three CSV files, one for each code unit.
"""

import numpy as np # type: ignore
import pandas as pd # type: ignore

from modules.common import log, replace_in_filename
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:

	for input_csv_path in project.find_output_csv_files('metrics'):

		log.info(f'Splitting and updating metrics for the project "{project}" using the information in "{input_csv_path}".')

		metrics = pd.read_csv(input_csv_path)

		# Convert all numeric values to integers and leave any N/As with None.
		first_metric_index = metrics.columns.get_loc('File') + 1
		metrics.iloc[:, first_metric_index:] = metrics.iloc[:, first_metric_index:].fillna(-1.0).astype(int)
		metrics = metrics.replace({np.nan: None, -1: None})

		def insert_new_column(new_column: str, after_column: str):
			""" Inserts a new column after another one. """
			after_index = metrics.columns.get_loc(after_column) + 1
			metrics.insert(after_index, new_column, None)

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

		for row in metrics.itertuples():

			kind = row.Kind

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
				metrics_in_this_file = metrics.loc[ (metrics['Kind'].str.contains('Function')) & (metrics['File'] == row.File) ]

				def aggregate_metric(source_column: str, aggregation_type: str, destination_column: str) -> None:
					""" Aggregates various function-level metrics by applying the sum, average, or maximum operations to a given column. """

					result = 0
					metrics_in_column = metrics_in_this_file[source_column]

					if not metrics_in_column.empty:

						if aggregation_type == 'Sum':
							result = metrics_in_column.sum()
						elif aggregation_type == 'Avg':
							result = metrics_in_column.mean()
						elif aggregation_type == 'Max':
							result = metrics_in_column.max()
						else:
							assert False, f'Unhandled aggregation function "{aggregation_type}".'

						# Every value in the output file must be an integer.
						result = round(result)

					metrics.at[row.Index, destination_column] = result

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
				count_line_code_exe = metrics_in_this_file['CountLineCodeExe']
				count_input = metrics_in_this_file['CountInput']
				count_output = metrics_in_this_file['CountOutput']

				metrics.at[row.Index, 'HenryKafura'] = int( ( count_line_code_exe * (count_input * count_output) ** 2 ).sum() )

			elif 'Function' in kind:
				pass
			elif 'Class' in kind or 'Struct' in kind or 'Union' in kind:
				pass
			else:
				assert False, f'Unhandled code unit kind "{kind}".'

		##########

		def write_code_unit_csv(kind_regex: str, replacement_csv_prefix: str) -> None:
			""" Writes the rows of a specific kind of code unit to a CSV file. """
			
			is_code_unit = metrics['Kind'].str.contains(kind_regex)
			code_unit_metrics = metrics.loc[is_code_unit]
			code_unit_metrics = code_unit_metrics.dropna(axis=1, how='all')
			
			output_csv_path = replace_in_filename(input_csv_path, 'metrics', replacement_csv_prefix)
			code_unit_metrics.to_csv(output_csv_path, index=False)

		write_code_unit_csv(r'File', 'file-metrics')
		write_code_unit_csv(r'Function', 'function-metrics')
		write_code_unit_csv(r'Class|Struct|Union', 'class-metrics')

	log.info(f'Finished running for the project "{project}".')
	
print('Finished running.')
