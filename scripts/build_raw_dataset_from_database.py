#!/usr/bin/env python3

"""
	This script exports a raw dataset as a CSV file for each project and code unit kind in the database.
	
	Before running this script, the follow scripts must be first run:
	- "insert_metrics_in_database.py" to insert the previously collected metrics into the database;
	- "aggregate_ck_file_metrics_in_database.py" to aggregate and add any missing metrics to the database;
	- "insert_alerts_in_database.py" to download and insert the previously collected alerts into the database.
"""

import os
import sys
from collections import namedtuple

import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, get_list_index_or_default, get_path_in_data_directory
from modules.database import Database
from modules.project import Project

####################################################################################################

def build_raw_dataset_from_database() -> None:

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

					# @Hack: Change the resulting CSV file's permissions and owner since it would
					# otherwise be associated with the user running the MySQL Daemon process (mysqld).
					if sys.platform != 'win32':
						username = GLOBAL_CONFIG['account_username']
						password = GLOBAL_CONFIG['account_password']
						log.info(f'Changing the raw dataset\'s file permissions and owner to "{username}".')
						os.system(f'echo "{password}" | sudo -S chmod 0664 "{output_csv_path}"')
						os.system(f'echo "{password}" | sudo -S chown "{username}:{username}" "{output_csv_path}"')

					# Add some class label columns to the dataset. These include:
					# 1. Binary - neutral (0) or vulnerable (1). In this case, vulnerable samples belong to any category.
					# 2. Multiclass - neutral (0), vulnerable without a category (1), or vulnerability with a specific category (2 to N).
					# 3. Grouped Multiclass - same as the multiclass label, but any vulnerability category (2 to N) is set to a new
					# label if the number of samples in each category falls below a given threshold.
					
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

					if GLOBAL_CONFIG['dataset_filter_column_names']:

						total_columns = len(dataset.columns)
						
						for column_regex in GLOBAL_CONFIG['dataset_filter_column_names']:
							log.info(f'Removing any columns that match "{column_regex}" at the user\'s request.')
							columns_to_remove = list(dataset.filter(regex=column_regex, axis='columns'))
							dataset.drop(columns=columns_to_remove, inplace=True)

						num_removed = total_columns - len(dataset.columns)
						log.info(f'Removed {num_removed} columns at the user\'s request. {len(dataset.columns)} columns remain.')

					if GLOBAL_CONFIG['dataset_filter_samples_ineligible_for_alerts'] and 'ELIGIBLE_FOR_ALERTS' in dataset.columns:
						is_eligible_for_alerts = dataset['ELIGIBLE_FOR_ALERTS'] == '1'
						num_removed = len(dataset) - len(dataset[is_eligible_for_alerts])
						dataset = dataset[is_eligible_for_alerts]
						log.info(f'Removed {num_removed} samples that were ineligible for alerts. {len(dataset)} samples remain.')

					if GLOBAL_CONFIG['dataset_filter_commits_without_alerts']:
						commit_without_alerts = dataset['COMMIT_HAS_ALERTS'] == '1'
						num_removed = len(dataset) - len(dataset[commit_without_alerts])
						dataset = dataset[commit_without_alerts]
						log.info(f'Removed {num_removed} samples whose commits did not have any alerts. {len(dataset)} samples remain.')

					dataset['multiclass_label'] = dataset.apply(assign_label, axis=1)
	
					dataset['binary_label'] = dataset['multiclass_label']
					is_category = dataset['multiclass_label'] > 1
					dataset.loc[is_category, 'binary_label'] = 1

					dataset['grouped_multiclass_label'] = dataset['multiclass_label']
					# The next value (N + 1) after the non-vulnerable (0), vulnerable (1), and the category labels (2 to N).
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

					# Overwrite the dataset on disk.
					dataset.to_csv(output_csv_path, index=False)
					log.info(f'Built the raw dataset to "{output_csv_path}" successfully.')

				else:
					log.error(f'Failed to build the raw dataset to "{output_csv_path}".')

##################################################

build_raw_dataset_from_database()

log.info('Finished running.')
print('Finished running.')