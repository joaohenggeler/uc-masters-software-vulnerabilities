#!/usr/bin/env python3

"""
	@TODO
"""

import re
from typing import Union

import pandas as pd # type: ignore
from sklearn import __version__ as sklearn_version, metrics # type: ignore
from sklearn.ensemble import BaggingClassifier # type: ignore

from modules.common import log, GLOBAL_CONFIG, dict_list_cartesian_product, find_output_csv_files, replace_in_filename

####################################################################################################

log.info(f'Using scikit-learn version {sklearn_version}.')

ML_PARAMS = GLOBAL_CONFIG['temporal_window']

# Create an abbreviated name for each class.
prediction_classes: Union[list, dict]
prediction_classes = ['Neutral', 'Vulnerable (No Category)'] + list(GLOBAL_CONFIG['vulnerability_categories'].keys()) + ['Vulnerable (With Category)']
prediction_classes = [re.sub(r'[a-z ]', '', class_) for class_ in prediction_classes]
prediction_classes = {value: name for value, name in enumerate(prediction_classes)}

label_values = list(prediction_classes.keys())
label_names = list(prediction_classes.values())

for input_csv_path in find_output_csv_files('raw-dataset-merged'):

	dataset = pd.read_csv(input_csv_path)

	columns_to_remove = [	'ID_File', 'ID_Function', 'ID_Class', 'P_ID', 'FilePath',
							'Patched', 'Occurrence', 'Affected', 'R_ID', 'Visibility',
							'Complement', 'BeginLine', 'EndLine', 'NameMethod', 'NameClass',
							'COMMIT_HASH', 'COMMIT_DATE', 'COMMIT_YEAR', 'VULNERABILITY_CVE',
							'VULNERABILITY_CWE', 'VULNERABILITY_CATEGORY', 'ELIGIBLE_FOR_ALERTS',
							'COMMIT_HAS_ALERTS', 'TOTAL_ALERTS', 'multiclass_label']

	dataset.drop(columns=columns_to_remove, errors='ignore', inplace=True)

	year_count = dataset['VULNERABILITY_YEAR'].value_counts()
	year_ratio = dataset['VULNERABILITY_YEAR'].value_counts(normalize=True)
	log.info(f'The vulnerability year count is: {year_count.to_dict()}')
	log.info(f'The vulnerability year ratio is: {year_ratio.to_dict()}')

	# Train and test each classifier using the following temporal window (train subset, test subset):
	# (2002-2012, 2013), (2002-2013, 2014), ..., (2002-2018, 2019)

	year_list = sorted(dataset['VULNERABILITY_YEAR'].unique().tolist())
	window_list = [(year_list[:i+1], next_year) for i, (year, next_year) in enumerate(zip(year_list, year_list[1:])) if year >= ML_PARAMS['begin_year_for_data_split']]
	window_list = list(reversed(window_list))

	for train_years, test_year in window_list:

		is_train = dataset['VULNERABILITY_YEAR'].isin(train_years)
		is_test = dataset['VULNERABILITY_YEAR'] == test_year

		log.info(f'Using the following temporal window: Train({train_years}) and Test({test_year}).')

		for target_label in ML_PARAMS['labels']:
			
			excluded_column_list = ['Description', 'VULNERABILITY_YEAR'] + GLOBAL_CONFIG['target_labels']
			X_train = dataset[is_train].drop(columns=excluded_column_list)
			y_train = dataset.loc[is_train, target_label]
			
			X_test = dataset[is_test].drop(columns=excluded_column_list)
			y_test = dataset.loc[is_test, target_label]

			for dimensionality_reduction in ML_PARAMS['dimensionality_reduction']:
				
				for data_balancing in ML_PARAMS['data_balancing']:
					
					for classification_algorithm, raw_algorithm_parameter_list in ML_PARAMS['classification_algorithms'].items():

						algorithm_parameter_list = []

						for raw_algorithm_parameter in raw_algorithm_parameter_list:
							
							if isinstance(raw_algorithm_parameter, dict):
								dict_list = dict_list_cartesian_product(**raw_algorithm_parameter)
								algorithm_parameter_list.extend(dict_list)
							elif raw_algorithm_parameter is None:
								algorithm_parameter_list.append({})
							else:
								assert False, f'Unhandled algorithm parameter type {type(raw_algorithm_parameter)}: {raw_algorithm_parameter}.'

						for algorithm_parameter in algorithm_parameter_list:

							if classification_algorithm == 'bagging':
								classifier = BaggingClassifier(**algorithm_parameter)
								classifier.fit(X_train, y_train)
								y_pred = classifier.predict(X_test)

								confusion_matrix = metrics.confusion_matrix(y_test, y_pred)
								confusion_matrix_display = metrics.ConfusionMatrixDisplay(confusion_matrix)
								confusion_matrix_display.plot()
								confusion_matrix_display.figure_.savefig('foo.png')

								report = metrics.classification_report(y_test, y_pred, labels=label_values, target_names=label_names, output_dict=True)
								
								log.info(f'Confusion Matrix: {confusion_matrix}')
								log.info(f'Report: {report}')
							else:
								log.critical(f'Skipping the unsupported "{classification_algorithm}" classification algorithm.')
	
##################################################

log.info('Finished running.')
print('Finished running.')