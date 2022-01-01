#!/usr/bin/env python3

"""
	Plots the performance metrics generated after rerunning the best Propheticus configurations using temporal
	sliding windows. For each configuration, the following two files are created: 1) a text file containing part
	of a Latex table with the performance metrics; 2) an image containing nine lines (for three metrics and window
	sizes).

	Before running this script, the temporal window results must be generated using "validate_datasets_using_temporal_windows.py".
"""

import itertools

import matplotlib.pyplot as plt
import pandas as pd # type: ignore
from matplotlib.ticker import AutoMinorLocator, MultipleLocator

from modules.common import log, deserialize_json_container ,find_output_csv_files, get_path_in_output_directory

####################################################################################################

for input_csv_path in find_output_csv_files('temporal-validation'):

	log.info(f'Plotting figures using the results in "{input_csv_path}".')

	results = pd.read_csv(input_csv_path)
	results.sort_values(['Index', 'Window Size', 'Testing Year'], inplace=True)

	grouped_configs = results.groupby(by=['Index'])
	for index, config_df in grouped_configs:

		figure, axis = plt.subplots()

		colors = itertools.cycle(['firebrick', 'green', 'mediumblue', 'darkorange', 'aquamarine', 'blueviolet', 'gold', 'teal', 'hotpink'])

		grouped_windows = config_df.groupby(by=['Window Size'])
		for window_size, window_df in grouped_windows:

			window_size_label = f'{window_size} Years' if window_size != 'Variable' else window_size

			for metric_column in ['Weighted Avg - Precision', 'Weighted Avg - Recall', 'Weighted Avg - F-Score']:

				_, metric_name = metric_column.rsplit(maxsplit=1)
				x_data = window_df['Testing Year'].tolist()
				y_data = window_df[metric_column].tolist()

				axis.plot(x_data, y_data, label=f'{metric_name} ({window_size_label})', color=next(colors))
		
		axis.set(xlabel=f'Testing Year', ylabel='Performance Metric', title=f'Configuration {index} Results Per Window Size')
		axis.legend(ncol=3, fontsize=8)

		axis.yaxis.set_major_locator(MultipleLocator(0.1))
		axis.yaxis.set_minor_locator(AutoMinorLocator(4))

		axis.set_ylim(top=1)

		figure.tight_layout()

		output_plot_path = get_path_in_output_directory(f'c{index}-tw.png', 'validation')
		figure.savefig(output_plot_path)

		table_text = ''

		"""
		\begin{table}[ht]
			\centering
			\scalebox{1.0}
			{
				\begin{tabular}{|c|c|c|c|c|c|c|}
				\hline
				\thead{Window} & \thead{Training} & \thead{Testing} & \thead{Training \%} & \thead{Precision} & \thead{Recall} & \thead{F-score} \\
				\hline

				Variable & 2002-2018 & 2019 & 96\% & 0.9022 & 0.4771 & 0.5887 \\
				[...]

				\hline

				5 & 2014-2018 & 2019 & 95\% & 0.9035 & 0.4719 & 0.5835 \\
				[...]

				\hline

				10 & 2009-2018 & 2019 & 96\% & 0.9027 & 0.4638 & 0.5756 \\
				[...]

				\hline
				\end{tabular}
			}
			\caption{The best results for configuration $C_1$ using the three temporal sliding windows.}
			\label{tab:ml-results-temporal-c1}
		\end{table}
		"""

		for _, row in config_df.iterrows():

			window_size = row['Window Size']
			training_years = deserialize_json_container(row['Training Years'])
			testing_year = row['Testing Year']
			training_percentage = round(row['Training Percentage'] * 100)
			precision = row['Weighted Avg - Precision']
			recall = row['Weighted Avg - Recall']
			f_score = row['Weighted Avg - F-Score']

			training_years = str(training_years[0]) + '-' + str(training_years[-1])

			table_text += f'{window_size} & {training_years} & {testing_year} & {training_percentage}\\% & {precision:.4f} & {recall:.4f} & {f_score:.4f} \\\\\n'

		output_table_path = get_path_in_output_directory(f'c{index}-tw.txt', 'validation')
		with open(output_table_path, 'w', encoding='utf-8') as file:
			file.write(table_text)

		log.info(f'Saved the plot for configuration {index} to "{output_plot_path}".')

log.info('Finished running.')
print('Finished running.')