#!/usr/bin/env python3

"""
	This script generates the security alerts for any files affected by vulnerabilities associated with the five C/C++ projects.
	
	This information includes the file's path, whether it was vulnerable or not, the associated Git commit where this specific
	file version originated from, and various different security alerts generated by SATs (at a file, function, and class level).

	This script uses the CSV files generated after running "find_affected_files.py" to creates its own CSVs.
"""

from common_scraping import Project

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:
	project.generate_and_save_alerts_to_csv_file()

print('Finished running')
