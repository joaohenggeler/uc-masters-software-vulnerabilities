#!/usr/bin/env python3

"""
	Validates any merged raw datasets by rerunning the best Propheticus configurations with a new data partitioning
	strategy: use a range of vulnerability years as the training subset, and the next year as the testing subset.
	For example: (2008-2012, 2013), (2009-2013, 2014), ..., (2014-2018, 2019) for a window size of 5.

	Only the following machine learning techniques are supported:
	- Classification Algorithms: Random Forests, Bagging.
	- Dimensionality Reduction: Variance.
	- Data Balancing: RandomUnderSampler.

	Before running this script, the raw datasets must be merged using "merge_raw_datasets.py" and the best classifier
	parameter configurations must be determined using Propheticus.
"""

import os
import re
from hashlib import sha256
from typing import Any, Union

import matplotlib.pyplot as plt # type: ignore
import numpy as np # type: ignore
import pandas as pd # type: ignore
from imblearn.under_sampling import RandomUnderSampler # type: ignore
from sklearn import __version__ as sklearn_version, metrics # type: ignore
from sklearn.ensemble import BaggingClassifier, RandomForestClassifier # type: ignore
from sklearn.feature_selection import VarianceThreshold # type: ignore

from modules.common import log, GLOBAL_CONFIG, create_output_subdirectory, find_output_csv_files, replace_in_filename, serialize_json_container

####################################################################################################

log.info(f'Using scikit-learn version {sklearn_version}.')

ML_PARAMS = GLOBAL_CONFIG['temporal_window']
num_runs = ML_PARAMS['num_runs']

# Create an abbreviated name for each class.
prediction_classes: Union[list, dict]
prediction_classes = ['Neutral', 'Vulnerable (No Category)'] + list(GLOBAL_CONFIG['vulnerability_categories'].keys()) + ['Vulnerable (With Category)']
prediction_classes = [re.sub(r'[a-z ]', '', class_) for class_ in prediction_classes]
prediction_classes = {value: name for value, name in enumerate(prediction_classes)}

label_values = list(prediction_classes.keys())
label_names = list(prediction_classes.values())

output_directory_path = create_output_subdirectory('validation')

for input_csv_path in find_output_csv_files('raw-dataset-merged'):

	log.info(f'Validating the dataset in "{input_csv_path}" using a temporal window.')
	output_csv_path = replace_in_filename(input_csv_path, 'raw-dataset-merged', 'temporal-validation', remove_extra_extensions=True)

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

	year_list = sorted(dataset['VULNERABILITY_YEAR'].unique().tolist())
	
	results = pd.DataFrame(columns=['Experiment', 'Window Size', 'Training Years', 'Testing Year',
									'Training Samples', 'Training Percentage', 'Testing Samples', 'Testing Percentage',
									'Index', 'Name', 'Runs', 'Algorithm', 'Target Label',
									'Data Balancing', 'Algorithm Parameters', 'Dimensionality Reduction',
									'Weighted Avg - Precision', 'Weighted Avg - Recall', 'Weighted Avg - F-Score'])

	for window_size in ML_PARAMS['data_split']['window_size']:

		window_size_name = window_size if window_size is not None else 'Variable'
		begin_test_year = ML_PARAMS['data_split']['begin_test_year']

		if window_size is None:
			# E.g. (2002-2012, 2013), (2002-2013, 2014), ..., (2002-2018, 2019).
			window_list = [(year_list[:i+1], next_year) for i, (year, next_year) in enumerate(zip(year_list, year_list[1:])) if next_year >= begin_test_year]
		else:
			# E.g. (2008-2012, 2013), (2009-2013, 2014), ..., (2014-2018, 2019) for a window size of 5.
			window_list = [(year_list[i-window_size:i], year) for i, year in enumerate(year_list) if year >= begin_test_year]
		
		window_list.reverse()

		for w, (train_years, test_year) in enumerate(window_list):

			is_train = dataset['VULNERABILITY_YEAR'].isin(train_years)
			is_test = dataset['VULNERABILITY_YEAR'] == test_year

			num_train = is_train.sum()
			num_test = is_test.sum()

			# Note that there is a third subset of the data that may not be used since it falls outside the year range.
			train_ratio = num_train / (num_train + num_test)
			test_ratio = num_test / (num_train + num_test)

			log.info(f'Using temporal window {w+1} of {len(window_list)} ({window_size_name}): Train({train_years}) with {num_train} samples ({train_ratio}) and Test({test_year}) with {num_test} samples ({test_ratio}).')

			default_algorithm_parameters = ML_PARAMS['default_algorithm_parameters']
			configuration_list = ML_PARAMS['configurations']

			for c, configuration in enumerate(configuration_list):

				name = configuration['name']
				log.info(f'Training and testing using the configuration {c+1} of {len(configuration_list)}: "{name}".')
				print(f'Window {w+1} of {len(window_list)} ({window_size_name}) - Configuration {c+1} of {len(configuration_list)}:')

				target_label = configuration['target_label']
				dimensionality_reduction = configuration['dimensionality_reduction']
				data_balancing = configuration['data_balancing']
				classification_algorithm = configuration['classification_algorithm']
				algorithm_parameters = configuration['algorithm_parameters']

				default_parameters = default_algorithm_parameters.get(classification_algorithm, {})
				algorithm_parameters.update(default_parameters)

				experiment = (train_years, test_year, target_label, dimensionality_reduction, data_balancing, classification_algorithm, algorithm_parameters)

				experiment_hash: Any = sha256()
				for value in experiment:
					experiment_hash.update(str(value).encode())
				experiment_hash = experiment_hash.hexdigest()

				confusion_matrix_file_path = os.path.join(output_directory_path, f'{experiment_hash}_cm.png')

				if os.path.isfile(confusion_matrix_file_path):
					log.info(f'Skipping configuration {c+1} with the hash "{experiment_hash}" since it was already executed.')
					print(f'- Skipping configuration "{experiment_hash}" since it was already executed.')
					continue

				real_label_values = sorted(dataset[target_label].unique().tolist())
				real_label_names = [label_names[label] for label in real_label_values]

				excluded_column_list = ['Description', 'VULNERABILITY_YEAR'] + GLOBAL_CONFIG['target_labels']
				X_train = dataset[is_train].drop(columns=excluded_column_list)
				y_train = dataset.loc[is_train, target_label]
				
				X_test = dataset[is_test].drop(columns=excluded_column_list)
				y_test = dataset.loc[is_test, target_label]

				total_y_pred = np.empty(shape=(0, 0), dtype=y_test.dtype)
				total_y_test = np.empty(shape=(0, 0), dtype=y_test.dtype)

				critical_error = False

				for r in range(num_runs):

					log.info(f'Executing run {r+1} of {num_runs} for configuration {c+1}.')
					print(f'-> Run {r+1} of {num_runs}...')

					for method in dimensionality_reduction:

						if method == 'variance':

							# Specified in "propheticus/preprocessing/variance.py".
							VARIANCE_THRESHOLD = 0.0

							original_columns = X_train.columns

							selector = VarianceThreshold(VARIANCE_THRESHOLD)
							selector.fit(X_train)
							selected_indexes = selector.get_support(indices=True)

							X_train = X_train[X_train.columns[selected_indexes]]
							X_test = X_test[X_test.columns[selected_indexes]]

							removed_indexes = np.setdiff1d(np.arange(len(original_columns)), selected_indexes)
							removed_features = original_columns[removed_indexes]

							log.info(f'Removed the following {len(removed_features)} features with a variance less or equal to {VARIANCE_THRESHOLD}: {removed_features}')
						else:
							log.critical(f'Skipping configuration due to the unsupported "{method}" dimensionality reduction technique.')
							critical_error = True
							break

					if critical_error:
						break

					train_label_count = y_train.value_counts().to_dict()

					for method in data_balancing:

						if method == 'RandomUnderSampler':

							majority_label = max(train_label_count, key=lambda x: train_label_count[x])
							second_majority_label = max(train_label_count, key=lambda x: train_label_count[x] if x != majority_label else -1)
							second_majority_count = train_label_count[second_majority_label]

							# Specified in "propheticus/configs/Sampling.py".
							UNDERSAMPLING_MAJORITY_TO_MINORITY_RATIO = 1.0

							log.info(f'Label count before undersampling: {train_label_count}')

							desired_label_count = {}
							for label, count in train_label_count.items():
								desired_label_count[label] = int(second_majority_count * UNDERSAMPLING_MAJORITY_TO_MINORITY_RATIO) if label == majority_label else count

							log.info(f'Label count after undersampling: {desired_label_count}')
							
							sampler = RandomUnderSampler(sampling_strategy=desired_label_count)
						else:
							log.critical(f'Skipping configuration due to the unsupported "{method}" sampling technique.')
							critical_error = True
							break

						X_train, y_train = sampler.fit_resample(X_train, y_train)

					if critical_error:
						break

					if classification_algorithm == 'random_forests':
						classifier = RandomForestClassifier(**algorithm_parameters)
					elif classification_algorithm == 'bagging':
						classifier = BaggingClassifier(**algorithm_parameters)
					else:
						log.critical(f'Skipping configuration due to the unsupported "{classification_algorithm}" classification algorithm.')
						break
			
					classifier.fit(X_train, y_train)
					y_pred = classifier.predict(X_test)

					total_y_test = np.append(total_y_test, y_test)
					total_y_pred = np.append(total_y_pred, y_pred)

				##################################################

				if critical_error:
					continue

				confusion_matrix = metrics.confusion_matrix(total_y_test, total_y_pred)
				confusion_matrix_display = metrics.ConfusionMatrixDisplay(confusion_matrix, display_labels=real_label_names)
				confusion_matrix_display.plot()
				
				axis = plt.gca()
				figure = plt.gcf()
				
				train_year_range = str(train_years[0]) + ' to ' + str(train_years[-1])
				axis.set(title=f'Configuration {c+1}: Window({window_size_name}), Train({train_year_range}), Test({test_year})')
				
				figure.savefig(confusion_matrix_file_path)

				report = metrics.classification_report(total_y_test, total_y_pred, output_dict=True)

				row = {
					'Experiment': experiment_hash,
					'Window Size': window_size_name,
					'Training Years': serialize_json_container(train_years),
					'Testing Year': test_year,
					'Training Samples': num_train,
					'Training Percentage': f'{train_ratio:.4f}',
					'Testing Samples': num_test,
					'Testing Percentage': f'{test_ratio:.4f}',
					'Index': c+1,
					'Name': name,
					'Runs': num_runs,
					'Algorithm': classification_algorithm,
					'Target Label': target_label,
					'Data Balancing': data_balancing,
					'Algorithm Parameters': algorithm_parameters,
					'Dimensionality Reduction': dimensionality_reduction,
					'Weighted Avg - Precision': report['weighted avg']['precision'],
					'Weighted Avg - Recall': report['weighted avg']['recall'],
					'Weighted Avg - F-Score': report['weighted avg']['f1-score'],
				}

				results = results.append(row, ignore_index=True)
				results.to_csv(output_csv_path, index=False)

##################################################

log.info('Finished running.')
print('Finished running.')