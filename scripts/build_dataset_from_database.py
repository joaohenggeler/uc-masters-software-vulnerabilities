#!/usr/bin/env python3

"""
	This script exports a raw dataset as a CSV file from the database and uses it to create a specific version that can be parsed by the Propheticus tool.
	This is done for all three code unit kinds (files, functions, and classes) for each project.

	Before running this script, the follow scripts must be first run:
	- "insert_metrics_in_database.py" to insert the previously collected metrics into the database;
	- "aggregate_ck_file_metrics_in_database.py" to aggregate and add any missing metrics to the database;
	- "collect_and_insert_alerts_in_database.py" to download and insert the previously collected alerts into the database.
"""

import json
import os
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

				if not GLOBAL_CONFIG['allowed_code_units'].get(unit_info.Kind):
					log.info(f'Skipping the {unit_info.Kind} metrics for the project "{project}" at the user\'s request')
					continue

				log.info(f'Building the {unit_info.Kind} dataset for the project "{project}".')

				unit_metrics_table = unit_info.MetricsTablePrefix + str(project.database_id)
				output_csv_path = project.get_base_output_csv_path('raw-dataset-' + unit_info.Kind)

				escaped_output_csv_path = output_csv_path.replace('\\', '\\\\')
				success, _ = db.call_procedure(unit_info.ProcedureName, unit_metrics_table, escaped_output_csv_path)

				if success:
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

					dataset['multiclass_label'] = dataset.apply(assign_label, axis=1)
	
					dataset['binary_label'] = dataset['multiclass_label']
					is_category = dataset['multiclass_label'] > 1
					dataset.loc[is_category, 'binary_label'] = 1

					dataset['grouped_multiclass_label'] = dataset['multiclass_label']
					# The next value after the non-vulnerable (0), vulnerable (1), and the category (2 to N) labels.
					grouped_class_label = len(vulnerability_categories) + 2
					label_threshold = GLOBAL_CONFIG['dataset_label_threshold']

					label_ratio = dataset['multiclass_label'].value_counts(normalize=True)
					log.info(f'The label ratio is: {label_ratio.tolist()}')

					for label, ratio in label_ratio.items():

						# The non-vulnerable and vulnerable (no category) should not be grouped.
						if label <= 1:
							continue

						if ratio < label_threshold:
							has_label = dataset['multiclass_label'] == label
							dataset.loc[has_label, 'grouped_multiclass_label'] = grouped_class_label
							log.info(f'Grouped the label {label} since its ratio {ratio} falls under the threshold {label_threshold}.')

					# Add the label columns to the original CSV file.
					dataset.to_csv(output_csv_path, index=False)
					log.info(f'Built the raw dataset to "{output_csv_path}" successfully.')

					if GLOBAL_CONFIG['dataset_filter_samples_uneligible_for_alerts'] and 'ELIGIBLE_FOR_ALERTS' in dataset.columns:
						is_eligible_for_alerts = dataset['ELIGIBLE_FOR_ALERTS'] == '1'
						num_removed = len(dataset) - len(dataset[is_eligible_for_alerts])
						dataset = dataset[is_eligible_for_alerts]
						log.info(f'Removed {num_removed} samples that were uneligible for alerts. {len(dataset)} samples remain.')

					columns_to_remove = [	'ID_File', 'ID_Function', 'ID_Class', 'P_ID', 'FilePath',
											'Patched', 'Occurrence', 'Affected', 'R_ID', 'Visibility',
											'Complement', 'BeginLine', 'EndLine', 'NameMethod', 'NameClass',
											'COMMIT_HASH', 'COMMIT_DATE', 'COMMIT_YEAR', 'VULNERABILITY_CVE',
											'VULNERABILITY_YEAR', 'VULNERABILITY_CWE', 'VULNERABILITY_CATEGORY',
											'ELIGIBLE_FOR_ALERTS', 'TOTAL_ALERTS', 'multiclass_label']

					dataset.drop(columns=columns_to_remove, errors='ignore', inplace=True)

					output_path_prefix = os.path.join(project.output_directory_path, f'{project.short_name}.{unit_info.Kind}')
					output_info_path = output_path_prefix + '.info.txt'
					output_headers_path = output_path_prefix + '.headers.txt'
					output_data_path = output_path_prefix + '.data.txt'

					with open(output_info_path, 'w') as info_file:
						num_samples = str(len(dataset))
						info_file.write(num_samples)

					column_types = {'Description': 'string', 'RatioCommentToCode': 'float64'}
					headers = [{'name': column, 'type': column_types.get(column, 'int64')} for column in dataset.columns]

					with open(output_headers_path, 'w') as headers_file:
						json_headers = json.dumps(headers, indent=4)
						headers_file.write(json_headers)

					dataset.to_csv(output_data_path, sep=' ', header=False, index=False)

					log.info(f'Built the Propheticus dataset to "{output_data_path}" successfully (including the info and header files).')

				else:
					log.error(f'Failed to build the raw dataset to "{output_csv_path}".')

##################################################

build_dataset_from_database()

log.info('Finished running.')
print('Finished running.')