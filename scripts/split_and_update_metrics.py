#!/usr/bin/env python3

"""
	This script splits the previously generated software metrics according to their code units (files, functions, or classes),
	and computes new ones.
	
	This information includes the file's path, whether it was vulnerable or not, the associated Git commit where this specific
	file version originated from, and various different software metrics generated by the Understand tool and by the scraping
	module.

	This script uses each CSV file generated after running "generate_metrics.py" to create three CSV files, one for each code unit.
"""

import os
import re
from typing import Tuple

import numpy as np # type: ignore
import pandas as pd # type: ignore

from modules.common import log, replace_in_filename
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

OUTPUT_SUBDIRECTORIES = {
	'file': 'file_metrics',
	'function': 'function_metrics',
	'class': 'class_metrics',
}

for project in project_list:

	for output_subdirectory in OUTPUT_SUBDIRECTORIES.values():
		project.create_output_subdirectory(output_subdirectory)

	for input_csv_path in project.find_output_csv_files('metrics', subdirectory='metrics'):

		log.info(f'Splitting and updating metrics for the project "{project}" using the information in "{input_csv_path}".')

		metrics = pd.read_csv(input_csv_path)

		# Convert all numeric values to integers and leave any N/As with None.
		first_metric_index = metrics.columns.get_loc('File') + 1
		metrics.iloc[:, first_metric_index:] = metrics.iloc[:, first_metric_index:].fillna(-1.0).astype(int)
		metrics = metrics.replace({np.nan: None, -1: None})

		affected_commit = metrics['Affected Commit'].iloc[0] == 'Yes'
		vulnerable_commit = metrics['Vulnerable Commit'].iloc[0] == 'Yes'

		def insert_new_column(new_column: str, after_column: str) -> None:
			""" Inserts a new column after another one. """
			after_index = metrics.columns.get_loc(after_column) + 1
			metrics.insert(after_index, new_column, None)

		def extract_visibility_and_complement_from_code_unit(kind: str) -> Tuple[str, str]:
			""" Retrieves a function or class' visibility and complement in a way that's consistent with the values in the original database. """

			"""
			In the database:

			SELECT DISTINCT Visibility FROM FUNCTIONS_1;
			- default, public, private, protected

			SELECT DISTINCT Visibility FROM CLASSES_1;
			- default, public, private, protected

			SELECT DISTINCT Complement FROM FUNCTIONS_1;
			- none, Virtual, Static, Const, Template, VirtualConst, Explicit, ConstTemplate, StaticTemplate, ExplicitTemplate, ConstVolatile, Volatile

			SELECT DISTINCT Complement FROM CLASSES_1;
			- none, Struct, StructTemplate, Abstract, Union, Template, AbstractStruct, AbstractTemplate, UnionTemplate, AbstractStructTemplate
			
			Some examples from Understand:

			Function
			Static Function Template
			Public Virtual Function
			Private Const Function
			Explicit Protected Function

			Class
			Struct
			Union
			Public Class
			Protected Struct
			Abstract Class
			Struct Template
			"""

			visibility = 'default'
			complement = 'none'

			tokens = kind.split()
			
			for unit_type in ['Function', 'Class']:
				if unit_type in tokens:
					tokens.remove(unit_type)

			for visibility_type in ['Public', 'Private', 'Protected']:
				if visibility_type in tokens:
					tokens.remove(visibility_type)
					visibility = visibility_type.lower()
					break

			if tokens:
				complement = ''.join(tokens)

			return (visibility, complement)

		insert_new_column('Patched', 'Vulnerable Code Unit')

		vulnerable_metrics = None

		if not affected_commit or vulnerable_commit:
			metrics['Patched'] = metrics['Vulnerable Code Unit']
		else:
			try:
				topological_index = int(re.findall(r'-t(\d+)-', input_csv_path)[0])
				vulnerable_input_csv_path = input_csv_path.replace('-v0-', '-v1-')
				vulnerable_input_csv_path = re.sub(r'-t\d+-', f'-t{topological_index - 1}-', vulnerable_input_csv_path)
				
				vulnerable_metrics = pd.read_csv(vulnerable_input_csv_path, usecols=['Vulnerable Code Unit', 'Kind', 'Name', 'File'], dtype=str)
			except FileNotFoundError as error:
				metrics['Patched'] = 'Unknown'
				log.warning(f'Could not find the vulnerable metrics CSV file "{vulnerable_input_csv_path}".')

		insert_new_column('Complement', 'Code Unit Lines')
		insert_new_column('Visibility', 'Code Unit Lines')

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

		# Remove column name spaces for itertuples().
		metrics.columns = metrics.columns.str.replace(' ', '')

		for row in metrics.itertuples():

			kind = row.Kind

			if vulnerable_metrics is not None:
				
				is_vulnerable_code_unit = (vulnerable_metrics['Kind'] == kind) & (vulnerable_metrics['Name'] == row.Name) & (vulnerable_metrics['File'] == row.File)
				if is_vulnerable_code_unit.any():

					"""
					Possible Cases:

					Vulnerable -> Neutral (current row) -> Expected Patched Value
					
					Yes 	-> No 		-> Yes
					No 		-> No 		-> No
					'' 		-> No 		-> ''
					Unknown -> No 		-> Unknown
					Unknown -> Unknown	-> Unknown
					Unknown -> ''		-> Unknown
					"""

					vulnerable_row = vulnerable_metrics[is_vulnerable_code_unit].iloc[0]
					metrics.at[row.Index, 'Patched'] = vulnerable_row['Vulnerable Code Unit']

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

			else:

				visibility, complement = extract_visibility_and_complement_from_code_unit(kind)
				metrics.at[row.Index, 'Visibility'] = visibility
				metrics.at[row.Index, 'Complement'] = complement

		##########

		def write_code_unit_csv(kind_regex: str, kind_name: str) -> None:
			""" Writes the rows of a specific kind of code unit to a CSV file. """
			
			is_code_unit = metrics['Kind'].str.contains(kind_regex)
			code_unit_metrics = metrics.loc[is_code_unit]
			code_unit_metrics = code_unit_metrics.dropna(axis=1, how='all')
			
			directory_path, filename = os.path.split(input_csv_path)
			filename = replace_in_filename(filename, 'metrics', f'{kind_name}-metrics')
			output_csv_path = os.path.join(directory_path, '..', OUTPUT_SUBDIRECTORIES[kind_name], filename)

			code_unit_metrics.to_csv(output_csv_path, index=False)

		write_code_unit_csv(r'File', 'file')
		write_code_unit_csv(r'Function', 'function')
		write_code_unit_csv(r'Class|Struct|Union', 'class')

	log.info(f'Finished running for the project "{project}".')
	
print('Finished running.')
