#!/usr/bin/env python3

"""
	This script exports a raw dataset from the database and uses it to create a specific version that can be parsed by the Propheticus tool.
	This is done for all three code unit kinds (file, functions, and classes) for each project.

	Before running this script, the follow scripts must be first run:
	- "insert_metrics_in_database.py" to insert the previously collected metrics into the database;
	- "aggregate_ck_file_metrics_in_database.py" to aggregate and add any missing metrics to the database;
	- "collect_and_insert_alerts_in_database.py" to download and insert the previously collected alerts into the database.
"""

import json
from collections import namedtuple

import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, get_list_index_or_default, get_path_in_data_directory, replace_in_filename
from modules.database import Database
from modules.project import Project

####################################################################################################

def build_dataset_from_database() -> None:

	with Database() as db:

		CodeUnit = namedtuple('CodeUnit', ['Kind', 'MetricsTablePrefix', 'ProcedureName', 'ProcedureScriptPath'])

		FILE_UNIT_INFO = 	 CodeUnit('file', 		'FILES_', 		'BUILD_FILE_DATASET', 		get_path_in_data_directory('create_build_file_dataset_procedure.sql'))
		FUNCTION_UNIT_INFO = CodeUnit('function', 	'FUNCTIONS_', 	'BUILD_FUNCTION_DATASET', 	get_path_in_data_directory('create_build_function_dataset_procedure.sql'))
		CLASS_UNIT_INFO = 	 CodeUnit('class', 		'CLASSES_', 	'BUILD_CLASS_DATASET', 		get_path_in_data_directory('create_build_class_dataset_procedure.sql'))

		UNIT_INFO_LIST = [FILE_UNIT_INFO, FUNCTION_UNIT_INFO, CLASS_UNIT_INFO]

		for unit_info in UNIT_INFO_LIST:
			success, _ = db.execute_script(unit_info.ProcedureScriptPath)
			if not success:
				log.error(f'Failed to create the procedure "{unit_info.ProcedureName}" using the script "{unit_info.ProcedureScriptPath}".')
				return

		project_list = Project.get_project_list_from_config()
		for project in project_list:
			
			for unit_info in UNIT_INFO_LIST:

				unit_metrics_table = unit_info.MetricsTablePrefix + str(project.database_id)
				output_csv_path = project.get_base_output_csv_path('raw-dataset-' + unit_info.Kind)

				escaped_output_csv_path = output_csv_path.replace('\\', '\\\\')
				success, _ = db.call_procedure(unit_info.ProcedureName, unit_metrics_table, escaped_output_csv_path)

				if success:
					log.info(f'Built the raw dataset to "{output_csv_path}" successfully.')

					"""
					We need to create the following text files. Taken from: https://eden.dei.uc.pt/~josep/EDCC2021/
					1. Info (suffix .info.txt): contains the number of samples per dataset;
					2. Headers (suffix: .headers.txt): contains a JSON object with all the features of the dataset, and its data type;
					3. Data (suffix: .data.txt): contains the samples separated by a space.

					Each sample contains:
					1. A description of the file instance;
					2. All the 54 software metrics;
					3. All the 228 alert types reported by Cppcheck;
					4. All the 123 alert types reported by Flawfinder;
					5. A label indicating if the files is non-vulnerable (0) or vulnerable (value > 0).
					
					Regarding the label in the multiclass dataset:
					- 0 represents non-vulnerable;
					- 1 represents vulnerable without an assigned category;
					- 2 represents memory management, followed by the remaining categories of Table 1 of the paper.
					"""
					
					vulnerability_categories = list(GLOBAL_CONFIG['vulnerability_categories'].keys())

					def assign_label(row: pd.Series) -> int:
						""" Assigns each sample a label given the rules above. """
						label = int(row['Affected'])

						if label == 1:
							category_index = get_list_index_or_default(vulnerability_categories, row['VULNERABILITY_CATEGORY'])
							if category_index is not None:
								label = category_index + 2

						return label

					dataset = pd.read_csv(output_csv_path, dtype=str)

					dataset['label'] = dataset.apply(assign_label, axis=1)

					columns_to_remove = [	'ID_File', 'ID_Function', 'ID_Class', 'P_ID', 'FilePath',
											'Patched', 'Occurrence', 'Affected', 'R_ID', 'Visibility',
											'Complement', 'BeginLine', 'EndLine', 'NameMethod', 'NameClass',
											'COMMIT_HASH', 'COMMIT_DATE', 'COMMIT_YEAR', 'VULNERABILITY_CVE',
											'VULNERABILITY_YEAR', 'VULNERABILITY_CWE', 'VULNERABILITY_CATEGORY',
											'TOTAL_ALERTS']

					dataset.drop(columns=columns_to_remove, errors='ignore', inplace=True)

					output_propheticus_path = replace_in_filename(output_csv_path, 'raw', 'propheticus')
					output_info_path = replace_in_filename(output_propheticus_path, '.csv', '.info.txt')
					output_headers_path = replace_in_filename(output_propheticus_path, '.csv', '.headers.txt')
					output_data_path = replace_in_filename(output_propheticus_path, '.csv', '.data.txt')

					with open(output_info_path, 'w') as info_file:
						num_samples = str(len(dataset))
						info_file.write(num_samples)

					column_types = {'Description': 'string', 'RatioCommentToCode': 'float64'}
					headers = [{'name': column, 'type': column_types.get(column, 'int64')} for column in dataset.columns]

					with open(output_headers_path, 'w') as headers_file:
						json_headers = json.dumps(headers)
						headers_file.write(json_headers)

					dataset.to_csv(output_data_path, sep=' ', header=False, index=False)

					log.info(f'Built the Propheticus dataset to "{output_data_path}" successfully (plus the info and header files).')

				else:
					log.error(f'Failed to build the raw dataset to "{output_csv_path}".')

##################################################

build_dataset_from_database()

log.info('Finished running.')
print('Finished running.')