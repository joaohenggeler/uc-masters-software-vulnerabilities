#!/usr/bin/env python3

"""
	This script finds any files affected by vulnerabilities associated with the five C/C++ projects by querying their version control systems.
	
	This information includes the file's path, a list of CVEs, the Git commit where the vulnerability was patched (neutral), and the commit
	immediately before (vulnerable).

	This script uses the CSV files generated after running "collect_vulnerabilities.py" to creates its own CSVs.
"""

from common_scraping import Project

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:
	project.find_and_save_affected_files_to_csv_file()

print('Finished running')
