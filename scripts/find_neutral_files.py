#!/usr/bin/env python3

"""
	This script finds any files that are not affected by vulnerabilities associated with the five C/C++ projects by querying their version control systems.
	
	This information includes the file's path and the neutral commit hash.

	This script uses the CSV files generated after running "find_affected_files.py" to creates its own CSVs.
"""

from typing import Any

import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, check_range_overlap, replace_in_filename, serialize_json_container
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:

	CSV_WRITE_FREQUENCY = GLOBAL_CONFIG['neutral_files_csv_write_frequency']

	for input_csv_path in project.find_output_csv_files('affected-files'):

		output_csv_path = replace_in_filename(input_csv_path, 'affected-files', f'neutral-files')

		log.info(f'Finding affected neutral files for the project "{project}" using the information in "{input_csv_path}".')
		
		affected_commits = pd.read_csv(input_csv_path, usecols=['Neutral Commit Hash'], dtype=str)
		affected_commits.drop_duplicates(inplace=True)

		commit_list = project.list_all_source_file_git_commit_hashes()
		log.info(f'Found {len(commit_list)} total commits.')
		
		commit_series = pd.Series(commit_list)
		is_neutral_commit = ~commit_series.isin(affected_commits['Neutral Commit Hash'])
		commit_list = commit_series[is_neutral_commit].tolist()
		log.info(f'Processing {len(commit_list)} neutral commits.')

		neutral_files = pd.DataFrame(columns=[	'File Path', 'Topological Index',
												'Neutral Commit Hash', 'Neutral Tag Name', 'Neutral Author Date',
												'Neutral Changed Lines', 'Neutral File Functions', 'Neutral File Classes'])
		
		for topological_index, commit_hash in enumerate(commit_list):

			tag_name = project.find_tag_name_from_git_commit_hash(commit_hash)
			author_date = project.find_author_date_from_git_commit_hash(commit_hash)

			checkout_success = project.checkout_entire_git_commit(commit_hash)
			if not checkout_success:
				log.error(f'Failed to checkout the commit {commit_hash}.')

			changed_lines: Any
			for file_path, _, changed_lines in project.find_changed_source_files_and_lines_since_parent_git_commit(commit_hash):

				function_list: Any = []
				class_list: Any = []

				if checkout_success:
					function_list, class_list = project.find_code_units_in_file(file_path)

					for unit in function_list + class_list:
						was_unit_changed = any(check_range_overlap(unit['Lines'], line_range) for line_range in changed_lines)
						unit.update({'Changed': 'Yes' if was_unit_changed else 'No'})

				changed_lines = serialize_json_container(changed_lines)
				function_list = serialize_json_container(function_list)
				class_list = serialize_json_container(class_list)

				row = {
							'File Path': file_path,
							'Topological Index': topological_index,
							'Neutral Commit Hash': commit_hash,
							'Neutral Tag Name': tag_name,
							'Neutral Author Date': author_date,
							'Neutral Changed Lines': changed_lines,
							'Neutral File Functions': function_list,
							'Neutral File Classes': class_list
				}

				neutral_files = neutral_files.append(row, ignore_index=True)

			if topological_index % CSV_WRITE_FREQUENCY == 0:
				log.info(f'Updating the results for topological index {topological_index} in "{output_csv_path}"...')
				neutral_files.to_csv(output_csv_path, index=False)

		neutral_files.to_csv(output_csv_path, index=False)
		project.hard_reset_git_head()

	log.info(f'Finished running for the project "{project}".')

print('Finished running.')
