#!/usr/bin/env python3

"""
	This script explores the information available in the CVE Details website by scraping every page related to the Mozilla vendor,
	and by storing the information about each CVE in a CSV file. No connections to the software vulnerabilities database are made.

	Requirements:

	pip install requests
"""

import locale
from datetime import datetime

import requests

HTTP_HEADERS = {
	'Accept-Language': 'en-US',
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
}

def download_page(url, params=None, timeout=5.0):

	try:
		response = requests.get(url, params=params, headers=HTTP_HEADERS, timeout=timeout)
		response.raise_for_status()
	except Exception as error:
		response = None
		error_string = repr(error)
		print(f'Failed to download the page "{url}" with the error: {error_string}')
	
	return response

def get_current_timestamp():
	return datetime.now().strftime("%Y%m%d%H%M%S")

def change_datetime_string_format(datetime_string, source_format, destination_format, desired_locale):
	previous_locale = locale.getlocale(locale.LC_TIME)
	locale.setlocale(locale.LC_TIME, desired_locale)
	
	datetime_string = datetime.strptime(datetime_string, source_format).strftime(destination_format)
	locale.setlocale(locale.LC_TIME, previous_locale)

	return datetime_string
