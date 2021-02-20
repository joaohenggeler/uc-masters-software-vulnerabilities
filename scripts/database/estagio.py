#!/usr/bin/env python3

"""
	This module contains utility functions or classes that are used by multiple scripts.
"""

def load_database_config():

	database_config = {}
	try:
		with open('database.config') as file:
			for line in file:
				key, value = line.split('=')
				database_config[key] = value.rstrip()
	except Exception as error:
		error_string = repr(error)
		print(f'Failed to open the database configuration file with the error: {error_string}')

	return database_config
