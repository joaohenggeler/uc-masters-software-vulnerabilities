#!/usr/bin/env python3

"""
	This script explores the information available in the CVE Details website by scraping every page related to the Mozilla vendor,
	and by storing the information about each CVE in a CSV file. No connections to the software vulnerabilities database are made.
"""

import json
import locale
from datetime import datetime
from typing import Optional, Union

import requests
from requests.adapters import HTTPAdapter

def load_scraping_config() -> Optional[dict]:

	try:
		with open('config.json') as file:
			database_config = json.loads(file.read())
	except json.decoder.JSONDecodeError as error:
		database_config = None
		print(f'Failed to parse the JSON configuration file with the error: {repr(error)}')
		
	return database_config

class ScrapingManager():

	session: requests.Session
	connect_timeout: float
	read_timeout: float

	HTTP_HEADERS: dict = {
		'Accept-Language': 'en-US',
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
	}

	def __init__(	self, url_prefixes: Union[str, list] = [],
					connect_timeout: float = 10.0, read_timeout: float = 5.0, max_retries: int = 5,
					headers: dict = HTTP_HEADERS):
		
		session = requests.Session()
		adapter = HTTPAdapter(max_retries=max_retries)
	
		if isinstance(url_prefixes, str):
			url_prefixes = [url_prefixes]

		for prefix in url_prefixes:
			session.mount(prefix, adapter)

		session.headers.update(headers)
		
		self.session = session
		self.connect_timeout = connect_timeout
		self.read_timeout = read_timeout

		print(f'Created a session with an adapter for "{url_prefixes}".')

	def download_page(self, url: str, params: Optional[dict] = None) -> Optional[requests.Response]:

		response: Optional[requests.Response]

		try:
			response = self.session.get(url, params=params, timeout=(self.connect_timeout, self.read_timeout))
			response.raise_for_status()
		except Exception as error:
			response = None
			print(f'Failed to download the page "{url}" with the error: {repr(error)}')
		
		return response

def get_current_timestamp() -> str:
	return datetime.now().strftime("%Y%m%d%H%M%S")

def change_datetime_string_format(datetime_string: str, source_format: str, destination_format: str, desired_locale: str) -> str:
	previous_locale = locale.getlocale(locale.LC_TIME)
	locale.setlocale(locale.LC_TIME, desired_locale)
	
	datetime_string = datetime.strptime(datetime_string, source_format).strftime(destination_format)
	locale.setlocale(locale.LC_TIME, previous_locale)

	return datetime_string
