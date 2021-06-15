#!/usr/bin/env python3

"""
	This script generates the software metrics for any files affected by vulnerabilities associated with the five C/C++ projects.
	
	This information includes the file's path, whether it was vulnerable or not, the associated Git commit where this specific
	file version originated from, and various different software metrics generated by the Understand tool (at a file, function,
	and class level).

	This script uses the CSV files generated after running "create_file_timeline.py" to creates its own CSVs.
"""

import os
from typing import Tuple

import pandas as pd # type: ignore

from modules.common import log, delete_file, replace_in_filename, serialize_json_container
from modules.sats import UnderstandSat
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

OUTPUT_SUBDIRECTORY = 'metrics'

for project in project_list:

	project.create_output_subdirectory(OUTPUT_SUBDIRECTORY)
	understand = UnderstandSat(project)

	for input_csv_path in project.find_output_csv_files('file-timeline'):

		log.info(f'Generating metrics for the project "{project}" using the information in "{input_csv_path}".')

		for changed_files in project.iterate_and_checkout_file_timeline_in_repository(input_csv_path):

			affected_commit = 1 if changed_files.Affected else 0
			vulnerable_commit = 1 if changed_files.Vulnerable else 0

			# We should be careful when using the topological index here since it may be repeated for different affected values.
			output_path = os.path.join(OUTPUT_SUBDIRECTORY, f'metrics-t{changed_files.TopologicalIndex}-a{affected_commit}-v{vulnerable_commit}')
			output_csv_path = replace_in_filename(input_csv_path, 'file-timeline', output_path)
			
			success = understand.generate_project_metrics(changed_files.AbsoluteFilePaths, output_csv_path)

			if success:

				metrics = pd.read_csv(output_csv_path, dtype=str)

				metrics.insert(0, 'Topological Index', None)
				metrics.insert(1, 'Affected Commit', None)
				metrics.insert(2, 'Vulnerable Commit', None)
				metrics.insert(3, 'Commit Hash', None)
				metrics.insert(4, 'CVEs', None)
				metrics.insert(5, 'Vulnerable Code Unit', None)
				metrics.insert(6, 'Code Unit Lines', None)

				metrics['Topological Index'] = changed_files.TopologicalIndex
				metrics['Affected Commit'] = 'Yes' if changed_files.Affected else 'No'
				metrics['Vulnerable Commit'] = 'Yes' if changed_files.Vulnerable else 'No'
				metrics['Commit Hash'] = changed_files.CommitHash
				metrics['CVEs'] = changed_files.Cves
				
				# This will exclude functions and classes without a file which are sometimes generated by Understand.
				grouped_files = metrics.groupby(by=['Commit Hash', 'File'])
				for (_, file_path), group_df in grouped_files:

					function_list = changed_files.FilePathToFunctions[file_path]
					class_list = changed_files.FilePathToClasses[file_path]

					def get_code_unit_status(signature: str, code_unit_list: list) -> Tuple[str, list]:
						""" Checks if a code unit is vulnerable given its name/signature and retrieves its line numbers. """
						status = 'No'
						lines = []

						# E.g. "EventStateManager::SetPointerLock(nsIWidget *,nsIContent *)" -> "setpointerlock".
						# E.g. "Action::~Action()" -> "~action".
						# The function names in the function list don't have the "::" operator, but the destructors
						# do start with "~".
						name = signature.lower().split('(', 1)[0]
						name = name.rsplit('::', 1)[-1]

						for unit in code_unit_list:
							if name == unit['Name'].lower():
								status = unit['Vulnerable']
								lines = unit['Lines']
								break

						return (status, lines)

					for row in group_df.itertuples():

						# Exclude any code units that are associated with a file that was not changed in this commit.
						if row.File not in changed_files.RelativeFilePaths:
							continue

						kind = row.Kind

						if kind == 'File':

							metrics.at[row.Index, 'Vulnerable Code Unit'] = row[3]

						elif 'Function' in kind:

							status, lines = get_code_unit_status(row.Name, function_list)									
							metrics.at[row.Index, 'Vulnerable Code Unit'] = status
							metrics.at[row.Index, 'Code Unit Lines'] = serialize_json_container(lines)

						elif 'Class' in kind or 'Struct' in kind or 'Union' in kind:
							
							status, lines = get_code_unit_status(row.Name, class_list)									
							metrics.at[row.Index, 'Vulnerable Code Unit'] = status
							metrics.at[row.Index, 'Code Unit Lines'] = serialize_json_container(lines)

						else:
							assert False, f'Unhandled code unit kind "{kind}".'

				log.info(f'Generated the metrics to "{output_csv_path}".')
				metrics.to_csv(output_csv_path, index=False)
			else:
				log.error(f'Failed to generate the metrics to "{output_csv_path}".')
				delete_file(output_csv_path)
				
	log.info(f'Finished running for the project "{project}".')
	
print('Finished running.')
