#!/usr/bin/env python3

"""
	This script splits the previously generated software metrics according to their code units (files, functions, or classes),
	and computes new ones.
	
	This information includes the file's path, whether it was vulnerable or not, the associated Git commit where this specific
	file version originated from, and various different software metrics generated by the Understand tool and by the scraping
	module.

	This script uses each CSV file generated after running "generate_metrics.py" to create three CSV files, one for each code unit.
"""

from common_scraping import Project

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:
	project.split_and_update_metrics_in_csv_files()
	
print('Finished running')
