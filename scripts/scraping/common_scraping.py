#!/usr/bin/env python3

"""
	This module defines any methods and classes that are used by different scripts to scrape vulnerability metadata
	from websites and to generated software metrics and security alerts using third-party programs.

	@Future:
	- Maybe the functionality in "split_and_update_metrics.py" should be merged with "generate_metrics.py".
"""

import csv
import glob
import json
import locale
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import time
from copy import deepcopy
from datetime import datetime
from string import Template
from typing import Callable, Iterator, List, Optional, Pattern, Tuple, Union
from urllib.parse import urlsplit, parse_qsl

import bs4 # type: ignore
import clang.cindex # type: ignore
import git # type: ignore
import numpy as np # type: ignore
import pandas as pd # type: ignore
import requests

####################################################################################################

def add_log_file_handler(log: logging.Logger):
	""" Creates and adds a handle for logging information to a file. """

	handler = logging.FileHandler('scraping.log', 'w', 'utf-8')
	handler.setLevel(logging.DEBUG)
	formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(funcName)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
	handler.setFormatter(formatter)

	log.addHandler(handler)

def add_log_stream_handler(log: logging.Logger):
	""" Creates and adds a handle for logging information to a stream. """

	handler = logging.StreamHandler()
	handler.setLevel(logging.ERROR)
	formatter = logging.Formatter('%(funcName)s: %(message)s\n')
	handler.setFormatter(formatter)

	log.addHandler(handler)

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
add_log_file_handler(log)
add_log_stream_handler(log)

log.info(f'Initializing "{__name__}"...')

####################################################################################################

def load_config_file(config_path: str) -> dict:
	""" Loads a JSON configuration file. """

	try:
		with open(config_path) as file:
			config = json.loads(file.read())
	except json.decoder.JSONDecodeError as error:
		config = {}
		log.error(f'Failed to parse the JSON configuration file with the error: {repr(error)}')
		
	return config

def load_scraping_config() -> dict:
	""" Creates the main configuration dictionary by loading and merging the static and dynamic JSON configuration files. """

	static_config = load_config_file('static_config.json')
	dynamic_config = load_config_file('dynamic_config.json')

	def merge_dictionaries(dict_1: dict, dict_2: dict) -> dict:
		""" Merges two dictionaries, including any nested ones. """

		result = deepcopy(dict_1)

		for key, value_2 in dict_2.items():

			value_1 = result.get(key)

			if isinstance(value_1, dict) and isinstance(value_2, dict):
				result[key] = merge_dictionaries(value_1, value_2)
			else:
				result[key] = deepcopy(value_2)

		return result

	return merge_dictionaries(static_config, dynamic_config)

SCRAPING_CONFIG = load_scraping_config()
if not SCRAPING_CONFIG:
	log.critical(f'The module will terminate since no configurations were found.')
	sys.exit(1)

DEBUG_OPTIONS = SCRAPING_CONFIG['debug_options']
DEBUG_ENABLED = DEBUG_OPTIONS['enabled']

if DEBUG_ENABLED:
	log.setLevel(logging.DEBUG)
	log.debug(f'Debug mode is enabled with the following options: {DEBUG_OPTIONS}')

try:
	clang_bin_path = SCRAPING_CONFIG['clang_bin_path']
	log.info(f'Loading libclang from "{clang_bin_path}".')
	
	clang.cindex.Config.set_library_path(clang_bin_path)
	CLANG_INDEX = clang.cindex.Index.create()
except Exception as error:
	log.error(f'Failed to load libclang with the error: {repr(error)}')

####################################################################################################

def get_current_timestamp() -> str:
	""" Gets the current timestamp as a string using the format "YYYYMMDDhhmmss". """

	return datetime.now().strftime("%Y%m%d%H%M%S")

def change_datetime_string_format(datetime_string: str, source_format: str, destination_format: str, desired_locale: str) -> str:
	""" Changes the format of a datetime string. """

	previous_locale = locale.getlocale(locale.LC_TIME)
	locale.setlocale(locale.LC_TIME, desired_locale)
	
	datetime_string = datetime.strptime(datetime_string, source_format).strftime(destination_format)
	locale.setlocale(locale.LC_TIME, previous_locale)

	return datetime_string

def serialize_json_container(container: Union[list, dict]) -> Optional[str]:
	""" Serializes a list or dictionary as a JSON object. """

	return json.dumps(container) if container else None

def deserialize_json_container(container_str: Optional[str]) -> Union[list, dict, None]:
	""" Deserializes a JSON object to a list or dictionary. """

	return json.loads(container_str) if pd.notna(container_str) else None # type: ignore[arg-type]

def has_file_extension(file_path: str, file_extension: str) -> bool:
	""" Checks if a file path ends with a given file extension. """

	return file_path.lower().endswith('.' + file_extension)

def replace_in_filename(file_path: str, old: str, new: str) -> str:
	""" Replaces a substring in a path's filename. """

	directory_path, filename = os.path.split(file_path)
	filename = filename.replace(old, new)
	return os.path.join(directory_path, filename)

def join_and_normalize_paths(*component_list) -> str:
	""" Joins and normalizes one or more components into a single path. """

	joined_paths = os.path.join(*component_list)
	return os.path.normpath(joined_paths)

def delete_file(file_path: str) -> bool:
	""" Deletes a file, whether it exists or not. """

	success = False

	try:
		os.remove(file_path)
		success = True
	except OSError:
		pass

	return success

def delete_directory(directory_path: str) -> bool:
	""" Deletes a directory and its contents, whether it exists or not. """

	success = False
	
	try:
		shutil.rmtree(directory_path)
		success = True
	except OSError:
		pass

	return success

def append_dataframe_to_csv(df: pd.DataFrame, csv_path: str) -> None:
	""" Creates or appends a dataframe to a CSV file depending on whether it already exists. """

	add_header = not os.path.exists(csv_path)
	df.to_csv(csv_path, mode='a', header=add_header, index=False)

def append_file_to_csv(file_path: str, csv_path: str, **kwargs) -> None:
	""" Creates or appends a file to another CSV file depending on whether it already exists. """

	df = pd.read_csv(file_path, dtype=str, **kwargs)
	append_dataframe_to_csv(df, csv_path)

def check_range_overlap(range_1: Union[List[int], Tuple[int, int]], range_2: Union[List[int], Tuple[int, int]]) -> bool:
	""" Checks whether two integer ranges overlap. Each range is either a list or tuple with two elements that represent
	the beginning and ending points respectively. This second value cannot be smaller than the first one."""

	"""
		# E.g. A function defined from lines 10 to 20 and two Git diffs that show changes from lines 5 to 9, and from 19 to 21.
		# - A) 5 <= 20 and 10 <= 9 = True and False = False
		# - B) 19 <= 20 and 10 <= 21 = True and True = True
	"""

	assert range_1[0] <= range_1[1]
	assert range_2[0] <= range_2[1]
	return range_1[0] <= range_2[1] and range_2[0] <= range_1[1]

####################################################################################################

class ScrapingManager():
	""" Manages the connection and downloads for one or more websites. """

	session: requests.Session
	connect_timeout: float
	read_timeout: float
	
	use_random_headers: bool
	sleep_random_amounts: bool

	DEFAULT_HEADERS: dict = {
		'Accept-Language': 'en-US',
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
	}

	BROWSER_HEADERS: list = list( SCRAPING_CONFIG['http_headers'].values() )

	def __init__(	self, url_prefixes: Union[str, list] = [],
					connect_timeout: float = 10.0, read_timeout: float = 5.0,
					max_retries: int = 5, headers: dict = DEFAULT_HEADERS,
					use_random_headers: bool = True,sleep_random_amounts: bool = True):
		
		session = requests.Session()
		adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)
	
		if isinstance(url_prefixes, str):
			url_prefixes = [url_prefixes]

		for prefix in url_prefixes:
			session.mount(prefix, adapter)

		session.headers.update(headers)
		
		self.session = session
		self.connect_timeout = connect_timeout
		self.read_timeout = read_timeout
		self.use_random_headers = use_random_headers
		self.sleep_random_amounts = sleep_random_amounts

	def download_page(self, url: str, params: Optional[dict] = None) -> Optional[requests.Response]:
		""" Downloads a web page givens its URL and query parameters. """

		response: Optional[requests.Response]

		try:

			if self.use_random_headers:
				headers = random.choice(ScrapingManager.BROWSER_HEADERS)
				self.session.headers.update(headers)
			
			if self.sleep_random_amounts:
				sleep_amount = random.uniform(1.0, 3.0)
				time.sleep(sleep_amount)

			response = self.session.get(url, params=params, timeout=(self.connect_timeout, self.read_timeout))
			response.raise_for_status()
		except Exception as error:
			response = None
			log.error(f'Failed to download the page "{url}" with the error: {repr(error)}')
		
		return response

####################################################################################################

PAGE_TITLE_REGEX = re.compile(r'Go to page \d+', re.IGNORECASE)
CVE_REGEX = re.compile(r'(CVE-\d+-\d+)', re.IGNORECASE)

# BUG TRACKERS
BUGZILLA_URL_REGEX = re.compile(r'https?://.*bugzilla.*', re.IGNORECASE)

"""
Examples:
- Mozilla: https://bugzilla.mozilla.org/show_bug.cgi?id=1580506
- Apache: https://bz.apache.org/bugzilla/show_bug.cgi?id=57531
- Glibc: https://sourceware.org/bugzilla/show_bug.cgi?id=24114
"""

# SECURITY ADVISORIES
MFSA_URL_REGEX = re.compile(r'https?://.*mozilla.*security.*mfsa.*', re.IGNORECASE)
MFSA_ID_REGEX = re.compile(r'(mfsa\d+-\d+)', re.IGNORECASE)

XSA_URL_REGEX = re.compile(r'https?://.*xen.*xsa.*advisory.*', re.IGNORECASE)
XSA_ID_REGEX = re.compile(r'advisory-(\d+)', re.IGNORECASE)

APACHE_SECURITY_URL_REGEX = re.compile(r'https?://.*apache.*security.*vulnerabilities.*', re.IGNORECASE)
APACHE_SECURITY_ID_REGEX = re.compile(r'vulnerabilities_(\d+)', re.IGNORECASE)

"""
Examples:
- Mozilla: https://www.mozilla.org/security/advisories/mfsa2019-31/
- Mozilla: http://www.mozilla.org/security/announce/mfsa2005-58.html 
- Xen: https://xenbits.xen.org/xsa/advisory-300.html
- Apache: https://httpd.apache.org/security/vulnerabilities_24.html
"""

# VERSION CONTROL
GIT_URL_REGEX = re.compile(r'https?://.*git.*commit.*', re.IGNORECASE)
GITHUB_URL_REGEX = re.compile(r'https?://.*github\.com.*commit.*', re.IGNORECASE)
SVN_URL_REGEX = re.compile(r'https?://.*svn.*rev.*', re.IGNORECASE)

GIT_COMMIT_HASH_LENGTH = 40
GIT_COMMIT_HASH_REGEX = re.compile(r'([A-Fa-f0-9]{40})', re.IGNORECASE)
SVN_REVISION_NUMBER_REGEX = re.compile(r'(\d+)', re.IGNORECASE)

"""
Examples:
- Linux: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eff73de2b1600ad8230692f00bc0ab49b166512a
- Glibc: https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9

- Linux: https://github.com/torvalds/linux/commit/6ef36ab967c71690ebe7e5ef997a8be4da3bc844
- Apache: https://github.com/apache/httpd/commit/e427c41257957b57036d5a549b260b6185d1dd73 

- Apache: http://svn.apache.org/viewcvs?rev=292949&view=rev
"""

####################################################################################################

class Cve:
	""" Represents a vulnerability (CVE) scraped from the CVE Details website. """

	CVE_DETAILS_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://www.cvedetails.com')

	id: str
	url: str
	project: 'Project'

	publish_date: Optional[str]
	last_update_date: Optional[str]

	cvss_score: 				Optional[str]
	confidentiality_impact: 	Optional[str]
	integrity_impact: 			Optional[str]
	availability_impact: 		Optional[str]
	access_complexity: 			Optional[str]
	authentication: 			Optional[str]
	gained_access: 				Optional[str]
	vulnerability_types: 		Optional[list]
	cwe: 						Optional[str]

	affected_products: dict

	bugzilla_urls: list
	bugzilla_ids: list
	advisory_urls: list
	advisory_ids: list

	advisory_info: dict

	git_urls: list
	git_commit_hashes: list
	svn_urls: list
	svn_revision_numbers: list

	def __init__(self, id: str, project: 'Project'):
		self.id = id
		self.url = f'https://www.cvedetails.com/cve/{self.id}'
		self.project = project

		self.cve_details_soup = None

		self.publish_date = None
		self.last_update_date = None

		self.cvss_score = None
		self.confidentiality_impact = None
		self.integrity_impact = None
		self.availability_impact = None
		self.access_complexity = None
		self.authentication = None
		self.gained_access = None
		self.vulnerability_types = None
		self.cwe = None

		self.affected_products = {}

		self.bugzilla_urls = []
		self.bugzilla_ids = []
		self.advisory_urls = []
		self.advisory_ids = []

		self.advisory_info = {}

		self.git_urls = []
		self.git_commit_hashes = []
		self.svn_urls = []
		self.svn_revision_numbers = []

	def __str__(self):
		return self.id

	def download_cve_details_page(self) -> bool:
		""" Downloads the CVE's page from the CVE Details website. """

		response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(self.url)
		if response is not None:
			self.cve_details_soup = bs4.BeautifulSoup(response.text, 'html.parser')
		
		return response is not None

	def scrape_dates_from_page(self):
		""" Scrapes any date values from the CVE's page. """

		"""
		<div class="cvedetailssummary">
			Memory safety bugs were reported in Firefox 57 and Firefox ESR 52.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Thunderbird &lt; 52.6, Firefox ESR &lt; 52.6, and Firefox &lt; 58.	<br>
			<span class="datenote">Publish Date : 2018-06-11	Last Update Date : 2018-08-03</span>
		</div>
		"""

		dates_span = self.cve_details_soup.find('span', class_='datenote')
		if dates_span is None:
			log.warning(f'--> No dates span found for {self}.')

		dates_text = dates_span.get_text(strip=True)
		
		cve_dates = {}
		for date in re.split(r'\t+', dates_text):
			key, value = date.split(' : ')
			cve_dates[key] = value

		self.publish_date = cve_dates.get('Publish Date')
		self.last_update_date = cve_dates.get('Last Update Date')

	def scrape_basic_attributes_from_page(self):
		""" Scrapes any basic attributes from the CVE's page. """

		"""
		<table id="cvssscorestable" class="details">
			<tbody>
				<tr>
					<th>CVSS Score</th>
					<td><div class="cvssbox" style="background-color:#ff9c20">7.5</div></td>
				</tr>
				<tr>
					<th>Confidentiality Impact</th>
					<td><span style="color:orange">Partial</span>
					<span class="cvssdesc">(There is considerable informational disclosure.)</span></td>
				</tr>
				<tr>
					<th>Access Complexity</th>
					<td><span style="color:red">Low</span>
					<span class="cvssdesc">(Specialized access conditions or extenuating circumstances do not exist. Very little knowledge or skill is required to exploit. )</span></td>
				</tr>
				<tr>
					<th>Authentication</th>
					<td><span style="color:red">Not required</span>
					<span class="cvssdesc">(Authentication is not required to exploit the vulnerability.)</span></td>
				</tr>
				<tr>
					<th>Gained Access</th>
					<td><span style="color:green;">None</span></td>
				</tr>
				<tr>
					<th>Vulnerability Type(s)</th>
					<td><span class="vt_overflow">Overflow</span><span class="vt_memc">Memory corruption</span></td>
				</tr>
				<tr>
					<th>CWE ID</th>
					<td><a href="//www.cvedetails.com/cwe-details/119/cwe.html" title="CWE-119 - CWE definition">119</a></td>
				</tr>
			</tbody>
		</table>
		"""

		scores_table = self.cve_details_soup.find('table', id='cvssscorestable')
		if scores_table is None:
			log.warning(f'--> No scores table found for {self}.')
			return

		scores_th_list = scores_table.find_all('th')
		scores_td_list = scores_table.find_all('td')

		cve_attributes = {}
		for th, td in zip(scores_th_list, scores_td_list):

			key = th.get_text(strip=True)
			value = None

			if key == 'Vulnerability Type(s)':
				value = [span.get_text(strip=True) for span in td.find_all('span')]
			else:
				span = td.find('span')
				if span is not None:
					value = span.get_text(strip=True)
				else:
					value = td.get_text(strip=True)
			
			cve_attributes[key] = value

		self.cvss_score 			= cve_attributes.get('CVSS Score')
		self.confidentiality_impact = cve_attributes.get('Confidentiality Impact')
		self.integrity_impact 		= cve_attributes.get('Integrity Impact')
		self.availability_impact 	= cve_attributes.get('Availability Impact')
		self.access_complexity 		= cve_attributes.get('Access Complexity')
		self.authentication 		= cve_attributes.get('Authentication')
		self.gained_access 			= cve_attributes.get('Gained Access')
		self.vulnerability_types 	= cve_attributes.get('Vulnerability Type(s)')

		cwe = cve_attributes.get('CWE ID')
		if cwe is not None and not cwe.isnumeric():
			cwe = None
		self.cwe = cwe

	def scrape_affected_product_versions_from_page(self):
		""" Scrapes any affected products and their versions from the CVE's page. """

		"""
		<table class="listtable" id="vulnprodstable">
			<tbody>
				<tr>
					<th class="num">#</th>
					<th>Product Type</th>
					<th>Vendor</th>
					<th>Product</th>
					<th>Version</th>
					<th>Update</th>
					<th>Edition</th>
					<th>Language</th>
					<th></th>
				</tr>
				<tr>
					<td class="num">1</td>
					<td>Application </td>
					<td><a href="//www.cvedetails.com/vendor/452/Mozilla.html" title="Details for Mozilla">Mozilla</a></td>
					<td><a href="//www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452" title="Product Details Mozilla Firefox">Firefox</a></td>
					<td></td>
					<td></td>
					<td></td>
					<td></td>
					<td><a href="/version/12613/Mozilla-Firefox-.html" title="Mozilla Firefox ">Version Details</a>&nbsp;<a href="/vulnerability-list/vendor_id-452/product_id-3264/version_id-12613/Mozilla-Firefox-.html" title="Vulnerabilities of Mozilla Firefox ">Vulnerabilities</a></td>
				</tr>
				<tr>
					<td class="num">2 </td>
					<td>Application </td>
					<td><a href="//www.cvedetails.com/vendor/44/Netscape.html" title="Details for Netscape">Netscape</a></td>
					<td><a href="//www.cvedetails.com/product/64/Netscape-Navigator.html?vendor_id=44" title="Product Details Netscape Navigator">Navigator</a></td>
					<td>7.0.2 </td>
					<td></td>
					<td></td>
					<td></td>
					<td><a href="/version/11359/Netscape-Navigator-7.0.2.html" title="Netscape Navigator 7.0.2">Version Details</a>&nbsp;<a href="/vulnerability-list/vendor_id-44/product_id-64/version_id-11359/Netscape-Navigator-7.0.2.html" title="Vulnerabilities of Netscape Navigator 7.0.2">Vulnerabilities</a></td>
				</tr>
			</tbody>
		</table>
		"""

		products_table = self.cve_details_soup.find('table', id='vulnprodstable')
		if products_table is None:
			log.warning(f'--> No products table found for {self}.')
			return

		# Parse each row in the product table.
		th_list = products_table.find_all('th')
		th_list = [th.get_text(strip=True) for th in th_list]
		column_indexes = {	'vendor': 	th_list.index('Vendor'),
							'product': 	th_list.index('Product'),
							'version': 	th_list.index('Version')}

		tr_list = products_table.find_all('tr')
		for tr in tr_list:

			# Skip the header row.
			if tr.find('th'):
				continue

			td_list = tr.find_all('td')

			def get_column_value_and_url(name):
				""" Gets a specific cell value and any URL it references from the current row given its column name.. """

				idx = column_indexes[name]
				td = td_list[idx]

				value = td.get_text(strip=True)
				url = td.find('a', href=True)

				if value in ['', '-']:
					value = None

				if url is not None:
					url = url['href']

				return value, url

			_, vendor_url  = get_column_value_and_url('vendor')
			product, product_url = get_column_value_and_url('product')
			version, _ = get_column_value_and_url('version')

			vendor_pattern = f'/{self.project.vendor_id}/'
			product_pattern = f'/{self.project.product_id}/' if self.project.product_id is not None else ''
			
			# Check if the vendor and product belong to the current project.
			if vendor_pattern in vendor_url and product_pattern in product_url:

				if product not in self.affected_products:
					self.affected_products[product] = []
				
				if version is not None and version not in self.affected_products[product]:
					self.affected_products[product].append(version)

	def scrape_references_from_page(self):
		""" Scrapes any references and links from the CVE's page. """

		"""
		<table class="listtable" id="vulnrefstable">
			<tbody>
				<tr>
					<td class="r_average">
						<a href="https://github.com/torvalds/linux/commit/09ccfd238e5a0e670d8178cf50180ea81ae09ae1" target="_blank" title="External url">https://github.com/torvalds/linux/commit/09ccfd238e5a0e670d8178cf50180ea81ae09ae1</a>
						CONFIRM
						<br>
					</td>
				</tr>
				<tr>
					<td class="r_average">
						<a href="https://bugzilla.redhat.com/show_bug.cgi?id=1292045" target="_blank" title="External url">https://bugzilla.redhat.com/show_bug.cgi?id=1292045</a>
						CONFIRM
						<br>
					</td>
				</tr>
			</tbody>
		</table>
		"""

		references_table = self.cve_details_soup.find('table', id='vulnrefstable')
		if references_table is None:
			log.warning(f'--> No references table found for {self}.')
			return

		def list_all_urls(url_regex: str, url_handler: Callable = None):
			""" Creates a list of URL that match a regex (or a list of regexes). If a handler method is passed as the second argument, then it
			will be called for each URL in order to create and return a secondary list. This may be used to extract specific parts of the URL."""

			a_list = references_table.find_all('a', href=url_regex)
			
			url_list = []
			for a in a_list:
				url = a['href']
				if re.search(self.project.url_pattern, url, re.IGNORECASE):
					url_list.append(url)

			secondary_list = []
			if url_handler is not None:
				for url in url_list:
					secondary_value = url_handler(url)
					if secondary_value is not None:
						secondary_list.append(secondary_value)

			return url_list, secondary_list

		def get_query_param(url: str, query_key_list: list) -> Optional[str]:
			""" Gets the value of the first parameter in a URL's query segment given a list of keys to check. """

			split_url = urlsplit(url)
			params = dict(parse_qsl(split_url.query))
			result = None
			
			for query_key in query_key_list:
				result = params.get(query_key)
				if result is not None:
					break

			return result

		"""
			Various helper methods to handle specific URLs from different sources.
		"""

		def handle_bugzilla_urls(url: str) -> Optional[str]:
			id = get_query_param(url, ['id', 'bug_id'])
			
			if id is None:
				log.error(f'--> Could not find a valid Bugzilla ID in "{url}".')

			return id

		def handle_advisory_urls(url: str) -> Optional[str]:
			split_url = urlsplit(url)
			id = None

			for regex in [MFSA_ID_REGEX, XSA_ID_REGEX, APACHE_SECURITY_ID_REGEX]:
				match = regex.search(split_url.path)
				if match is not None:
					id = match.group(1)

					if regex is MFSA_ID_REGEX:
						id = id.upper()
						id = id.replace('MFSA', 'MFSA-')
					elif regex is XSA_ID_REGEX:
						id = 'XSA-' + id
					elif regex is APACHE_SECURITY_ID_REGEX:
						id = 'APACHE-' + id[0] + '.' + id[1:]

					break

			if id is None:
				log.error(f'--> Could not find a valid advisory ID in "{url}".')

			return id

		def handle_git_urls(url: str) -> Optional[str]:
			commit_hash = get_query_param(url, ['id', 'h'])

			if commit_hash is None:
				split_url = urlsplit(url)
				path_components = split_url.path.rsplit('/')
				commit_hash = path_components[-1]

			# If the hash length is less than 40, we need to refer to the repository
			# to get the full hash.
			if commit_hash is not None and len(commit_hash) < GIT_COMMIT_HASH_LENGTH:
				commit_hash = self.project.find_full_git_commit_hash(commit_hash)

			if commit_hash is not None and not GIT_COMMIT_HASH_REGEX.match(commit_hash):
				commit_hash = None
			
			if commit_hash is None:
				log.error(f'--> Could not find a valid commit hash in "{url}".')
			
			return commit_hash

		def handle_svn_urls(url: str) -> Optional[str]:
			revision_number = get_query_param(url, ['rev', 'revision', 'pathrev'])

			if revision_number is not None:

				# In some rare cases, the revision number can be prefixed with 'r'.
				# As such, we'll only extract the numeric part of this value.
				match = SVN_REVISION_NUMBER_REGEX.search(revision_number)
				if match is not None:
					# For most cases, this is the same value.
					revision_number = match.group(1)
				else:
					# For cases where the query parameter was not a valid number.
					revision_number = None

			if revision_number is None:
				log.error(f'--> Could not find a valid revision number in "{url}".')

			return revision_number

		self.bugzilla_urls, self.bugzilla_ids 		= list_all_urls(BUGZILLA_URL_REGEX, handle_bugzilla_urls)
		self.advisory_urls, self.advisory_ids 		= list_all_urls([MFSA_URL_REGEX, XSA_URL_REGEX, APACHE_SECURITY_URL_REGEX], handle_advisory_urls)

		self.git_urls, self.git_commit_hashes 		= list_all_urls([GIT_URL_REGEX, GITHUB_URL_REGEX], handle_git_urls)
		self.svn_urls, self.svn_revision_numbers 	= list_all_urls(SVN_URL_REGEX, handle_svn_urls)

	def remove_duplicated_values(self):
		""" Removes any duplicated values from specific CVE attributes that contain lists. """

		def remove_duplicates_from_list(value_list: list) -> list:
			""" Removes any duplicated values from a list. """
			return list(dict.fromkeys(value_list))

		self.vulnerability_types 	= remove_duplicates_from_list(self.vulnerability_types)

		self.bugzilla_urls 			= remove_duplicates_from_list(self.bugzilla_urls)
		self.bugzilla_ids 			= remove_duplicates_from_list(self.bugzilla_ids)
		self.advisory_urls 			= remove_duplicates_from_list(self.advisory_urls)
		self.advisory_ids 			= remove_duplicates_from_list(self.advisory_ids)

		self.git_urls 				= remove_duplicates_from_list(self.git_urls)
		self.git_commit_hashes 		= remove_duplicates_from_list(self.git_commit_hashes)
		self.svn_urls 				= remove_duplicates_from_list(self.svn_urls)
		self.svn_revision_numbers 	= remove_duplicates_from_list(self.svn_revision_numbers)

	def serialize_containers(self):
		""" Serializes specific CVE attributes that contain lists or dictionaries using JSON. """

		self.vulnerability_types 	= serialize_json_container(self.vulnerability_types)

		self.affected_products 		= serialize_json_container(self.affected_products)

		self.bugzilla_urls 			= serialize_json_container(self.bugzilla_urls)
		self.bugzilla_ids 			= serialize_json_container(self.bugzilla_ids)
		self.advisory_urls 			= serialize_json_container(self.advisory_urls)
		self.advisory_ids 			= serialize_json_container(self.advisory_ids)

		self.advisory_info 			= serialize_json_container(self.advisory_info)

		self.git_urls 				= serialize_json_container(self.git_urls)
		self.git_commit_hashes 		= serialize_json_container(self.git_commit_hashes)
		self.svn_urls 				= serialize_json_container(self.svn_urls)
		self.svn_revision_numbers 	= serialize_json_container(self.svn_revision_numbers)

####################################################################################################

class Project:
	""" Represents a software project, its repository, and the vulnerabilities it's affected by. """

	TIMESTAMP: str = get_current_timestamp()

	full_name: str
	short_name: str
	database_id: int
	vendor_id: int
	product_id: int
	url_pattern: str
	repository_path: str
	repository_base_name: str
	master_branch: str
	language: str
	include_directory_path: Optional[str]

	SOURCE_FILE_EXTENSIONS: list = ['c', 'cpp', 'cc', 'cxx', 'c++', 'cp', 'h', 'hpp', 'hh', 'hxx']

	repository: git.Repo

	output_directory_path: str
	scrape_all_branches: bool

	csv_prefix_template: Template
	csv_file_path_template: Template

	def __init__(self, project_name: str, project_info: dict):
		
		self.full_name = project_name
		for key, value in project_info.items():
			setattr(self, key, value)

		self.repository_base_name = os.path.basename(self.repository_path)

		self.output_directory_path = os.path.join(self.output_directory_path, self.short_name)
		self.output_directory_path = os.path.abspath(self.output_directory_path)

		try:
			self.repository = git.Repo(self.repository_path)
			log.info(f'Loaded the project "{self}" located in "{self.repository_path}".')
		except Exception as error:
			self.repository = None
			log.error(f'Failed to get the repository for the project "{self}"" with the error: {repr(error)}')
		
		if self.include_directory_path is not None:
			self.include_directory_path = join_and_normalize_paths(self.repository_path, self.include_directory_path)

		csv_prefix = os.path.join(self.output_directory_path, f'$prefix-{self.database_id}-')
		self.csv_prefix_template = Template(csv_prefix)

		used_branches = 'all-branches' if self.scrape_all_branches else 'master-branch'

		csv_file_path = csv_prefix + f'{self.short_name}-{used_branches}-{Project.TIMESTAMP}.csv'
		self.csv_file_path_template = Template(csv_file_path)

	def __str__(self):
		return self.full_name

	####################################################################################################

	"""
		Methods used to initialize or perform basic operations used by all projects.
	"""

	@staticmethod
	def get_project_list_from_config(config: dict = SCRAPING_CONFIG) -> list:
		""" Creates a list of projects given the current configuration. """

		output_directory_path = config['output_directory_path']
		scrape_all_branches = config['scrape_all_branches']
		project_config = config['projects']

		log.info(f'Scraping all branches? {scrape_all_branches}')

		project_list = []
		for full_name, info in project_config.items():

			short_name = info['short_name']

			if short_name in SCRAPING_CONFIG['ignored_projects']:
				log.info(f'Ignoring project "{short_name}".')
				continue

			info['output_directory_path'] = output_directory_path
			info['scrape_all_branches'] = scrape_all_branches
			project: Project
		
			if short_name == 'mozilla':
				project = MozillaProject(full_name, info)
			elif short_name == 'xen':
				project = XenProject(full_name, info)
			elif short_name == 'apache':
				project = ApacheProject(full_name, info)
			elif short_name == 'glibc':
				project = GlibcProject(full_name, info)
			else:
				project = Project(full_name, info)

			project_list.append(project)

		return project_list

	@staticmethod
	def debug_ensure_all_project_repositories_were_loaded(project_list: list):
		""" Terminates the program if one or more projects are missing their repositories. This method does nothing outside debug mode. """

		if DEBUG_ENABLED:
			for project in project_list:
				if project.repository is None:
					log.critical(f'The repository for project "{project}" was not loaded correctly.')
					sys.exit(1)

	def find_output_csv_files(self, prefix: str) -> Iterator[str]:
		""" Finds the paths to any CSV files that belong to this project by looking at their prefix. """
		csv_path = self.csv_prefix_template.substitute(prefix=prefix) + '*'
		yield from glob.iglob(csv_path)

	####################################################################################################

	"""
		Methods used to interface with a project's repository.
	"""

	def get_absolute_path_in_repository(self, relative_path: str) -> str:
		""" Converts the relative path of a file in the project's repository into an absolute one. """
		full_path = os.path.join(self.repository_path, relative_path)
		return os.path.normpath(full_path)

	def get_relative_path_in_repository(self, full_path: str) -> str:
		""" Converts the absolute path of a file in the project's repository into a relative one. """

		path = full_path.replace('\\', '/')

		try:
			_, path = path.split(self.repository_base_name + '/', maxsplit=1)			
		except ValueError:
			pass

		return path

	def find_full_git_commit_hash(self, short_commit_hash: str) -> Optional[str]:
		""" Finds the full Git commit hash given the short hash. """

		if self.repository is None:
			return None

		try:
			# git show --format="%H" --no-patch [SHORT HASH]
			full_commit_hash = self.repository.git.show(short_commit_hash, format='%H', no_patch=True)
		except git.exc.GitCommandError as error:
			full_commit_hash = None
			log.error(f'Failed to find the full version of the commit hash "{short_commit_hash}" with the error: {repr(error)}')

		return full_commit_hash

	def find_git_commit_hashes_from_pattern(self, grep_pattern: str) -> list:
		""" Finds any Git commit hashes whose title and message match a given regex pattern. """

		if self.repository is None:
			return []

		hash_list = []

		# git log --all --format=oneline --grep="[REGEX]" --regexp-ignore-case --extended-regexp
		# The --extended-regexp option enables the following special characters: ? + { | ( )
		log_result = self.repository.git.log(all=True, format='oneline', grep=grep_pattern, regexp_ignore_case=True, extended_regexp=True)
		
		for line in log_result.splitlines():
			hash, title = line.split(maxsplit=1)
			hash_list.append(hash)

		return hash_list

	def is_git_commit_hash_valid(self, commit_hash: str) -> bool:
		""" Checks if a Git commit hash exists in the repository. """

		if self.repository is None:
			return False

		try:
			# git branch --contains [HASH]
			self.repository.git.branch(contains=commit_hash)
			is_valid = True
		except git.exc.GitCommandError as error:
			is_valid = False

		return is_valid	

	def remove_invalid_git_commit_hashes(self, cve: Cve):
		""" Removes any invalid Git commit hashes from a CVE. """

		if self.repository is not None:
			cve.git_commit_hashes = [hash for hash in cve.git_commit_hashes if self.is_git_commit_hash_valid(hash)]

	def is_git_commit_hash_in_master_branch(self, commit_hash: str) -> bool:
		""" Checks if a Git commit hash exists in the repository's master branch. """

		if self.repository is None:
			return False

		is_master = False

		try:
			# git branch --contains [HASH] --format="%(refname:short)"
			branch_result = self.repository.git.branch(contains=commit_hash, format='%(refname:short)')
			is_master = self.master_branch in branch_result.splitlines()

		except git.exc.GitCommandError as error:
			# If there's no such commit in the repository.
			pass

		return is_master
	
	def remove_git_commit_hashes_by_branch(self, cve: Cve):
		""" Removes any Git commit hashes from a CVE that do not exist in the master branch. If the configuration file specified every branch,
		this method does nothing. """

		if self.repository is not None and not self.scrape_all_branches:
			cve.git_commit_hashes = [hash for hash in cve.git_commit_hashes if self.is_git_commit_hash_in_master_branch(hash)]

	def sort_git_commit_hashes_topologically(self, hash_list: list) -> list:
		""" Sorts a list of Git commit hashes topologically. """

		if self.repository is None or not hash_list:
			return []

		try:
			# git rev-list --topo-order --reverse --no-walk=sorted [HASH 1] [HASH 2] [...] [HASH N]
			rev_list_result = self.repository.git.rev_list(*hash_list, topo_order=True, reverse=True, no_walk='sorted')
			sorted_hash_list = [commit_hash for commit_hash in rev_list_result.splitlines()]

		except git.exc.GitCommandError as error:
			# If there's no such commit in the repository.
			log.error('Found one or more invalid commits while trying to sort the commit hashes topologically.')
			sorted_hash_list = []

		return sorted_hash_list

	GIT_DIFF_LINE_NUMBERS_REGEX: Pattern = re.compile(r'^@@ -(\d+)(,\d+)? \+(?:\d+)(?:,\d+)? @@.*')

	def find_changed_files_in_git_commit(self, commit_hash: str) -> Iterator[ Tuple[str, List[List[int]]] ]:
		""" Finds the paths and modified lines of any C/C++ source files that were changed in a given Git commit. """

		if self.repository is None:
			return

		# git diff --unified=0 [HASH] [HASH]^
		diff_result = self.repository.git.diff(commit_hash, commit_hash + '^', unified=0)
		last_file_path: Optional[str] = None
		last_changed_line_list: List[List[int]] = []
	
		def yield_last_file_if_it_exists() -> Iterator[ Tuple[str, List[List[int]]] ]:
			""" Yields the previously found file path and its changed lines. """

			nonlocal last_file_path, last_changed_line_list

			if last_file_path is not None:			
				yield (last_file_path, last_changed_line_list)
				last_file_path = None
				last_changed_line_list = []

		for line in diff_result.splitlines():

			# E.g. "+++ b/embedding/components/windowwatcher/src/nsPrompt.cpp"
			if line.startswith('+++'):

				yield from yield_last_file_if_it_exists()

				_, last_file_path = line.split('/', maxsplit=1)
				is_source_file = any(has_file_extension(last_file_path, file_extension) for file_extension in Project.SOURCE_FILE_EXTENSIONS) # type: ignore[arg-type]

				if not is_source_file:
					last_file_path = None
				
			# E.g. "@@ -451,2 +428,2 @@ MakeDialogText(nsIChannel* aChannel, nsIAuthInformation* aAuthInfo,"
			# E.g. "@@ -263 +255,0 @@ do_test (int argc, char *argv[])"
			elif last_file_path is not None and line.startswith('@@'):

				match = Project.GIT_DIFF_LINE_NUMBERS_REGEX.search(line)
				if match:

					deletion_line_begin = int(match.group(1))

					deletion_num_lines = match.group(2)
					if deletion_num_lines is not None:
						_, deletion_num_lines = deletion_num_lines.split(',', maxsplit=1)
						deletion_num_lines = int(deletion_num_lines)
					else:
						deletion_num_lines = 0

					deletion_line_end = deletion_line_begin + max(deletion_num_lines - 1, 0)
					last_changed_line_list.append( [deletion_line_begin, deletion_line_end] )

				else:
					log.error(f'Could not find the line number information for the file "{last_file_path}" ({commit_hash}) in the diff line: "{line}".')

		yield from yield_last_file_if_it_exists()

		"""
			E.g. for Mozilla: git diff --unified=0 a714da4a56957c826a7cafa381c4d8df832172f2 a714da4a56957c826a7cafa381c4d8df832172f2^

			diff --git a/embedding/components/windowwatcher/src/nsPrompt.cpp b/embedding/components/windowwatcher/src/nsPrompt.cpp
			index a782689cc853..f95e19ed7c97 100644
			--- a/embedding/components/windowwatcher/src/nsPrompt.cpp
			+++ b/embedding/components/windowwatcher/src/nsPrompt.cpp
			@@ -58,3 +57,0 @@
			-#include "nsIPrefService.h"
			-#include "nsIPrefLocalizedString.h"
			-
			@@ -424,20 +420,0 @@ MakeDialogText(nsIChannel* aChannel, nsIAuthInformation* aAuthInfo,
			-  // Trim obnoxiously long realms.
			-  if (realm.Length() > 150) {
			- [...]
			-  }
			@@ -451,2 +428,2 @@ MakeDialogText(nsIChannel* aChannel, nsIAuthInformation* aAuthInfo,
			-  NS_NAMED_LITERAL_STRING(proxyText, "EnterLoginForProxy");
			-  NS_NAMED_LITERAL_STRING(originText, "EnterLoginForRealm");
			+  NS_NAMED_LITERAL_STRING(proxyText, "EnterUserPasswordForProxy");
			+  NS_NAMED_LITERAL_STRING(originText, "EnterUserPasswordForRealm");
		"""

	def find_last_changed_git_commit_hash(self, commit_hash: str, file_path: str) -> Optional[str]:
		""" Finds the previous Git commit hash where a given file was last changed. """

		if self.repository is None:
			return None

		try:
			# git log [HASH] --parents --max-count=1 --format="%P" -- [FILE PATH]
			parent_commit_hash = self.repository.git.log(commit_hash, '--', file_path, parents=True, max_count=1, format='%P')
		except git.exc.GitCommandError as error:
			parent_commit_hash = None
			log.error(f'Failed to find the parent of the commit hash "{commit_hash}" with the error: {repr(error)}')

		return parent_commit_hash

	def find_parent_git_commit_hash(self, commit_hash: str) -> Optional[str]:
		""" Finds the previous Git commit hash. """
		return self.find_last_changed_git_commit_hash(commit_hash, '.')

	def checkout_files_in_git_commit(self, commit_hash: str, file_path_list: list) -> bool:
		""" Performs the Git checkout operation on a specific list of files in a given Git commit. """

		if self.repository is None:
			return False

		success = False

		try:
			# git checkout [COMMIT] -- [FILE PATH 1] [FILE PATH 2] [...] [FILE PATH N]
			self.repository.git.checkout(commit_hash, '--', *file_path_list)
			success = True
		except git.exc.GitCommandError as error:
			log.error(f'Failed to checkout the files in commit "{commit_hash}" with the error: {repr(error)}')
			
		return success

	def checkout_entire_git_commit(self, commit_hash: str) -> bool:
		""" Performs the Git checkout operation for every file in a given Git commit. """
		return self.checkout_files_in_git_commit(commit_hash, ['.'])

	def hard_reset_git_head(self):
		""" Performs a hard reset operation to the project's repository. """

		if self.repository is None:
			return

		try:
			# git reset --hard
			self.repository.git.reset(hard=True)
		except git.exc.GitCommandError as error:
			log.error(f'Failed to hard reset the current HEAD with the error: {repr(error)}')

	####################################################################################################

	"""
		Methods used to scrape vulnerability metadata from sources like online databases, bug trackers,
		security advisories, and the project's version control system.
	"""

	def scrape_additional_information_from_security_advisories(self, cve: Cve):
		""" Scrapes any additional information from the project's security advisories. This method should be overriden by a project's subclass. """
		pass

	def scrape_additional_information_from_version_control(self, cve: Cve):
		""" Scrapes any additional information from the project's version control system. This method should be overriden by a project's subclass. """
		pass

	def scrape_vulnerabilities_from_cve_details(self) -> Iterator[Cve]:
		""" Scrapes any vulnerabilities related to this project from the CVE Details website. """

		log.info(f'Collecting the vulnerabilities for the "{self}" project ({self.vendor_id}, {self.product_id}):')
		response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page('https://www.cvedetails.com/vulnerability-list.php', {'vendor_id': self.vendor_id, 'product_id': self.product_id})

		if response is None:
			log.error('Could not download the first hub page. No vulnerabilities will be scraped for this project.')
			return
		
		main_soup = bs4.BeautifulSoup(response.text, 'html.parser')

		page_div = main_soup.find('div', id='pagingb')
		page_a_list = page_div.find_all('a', title=PAGE_TITLE_REGEX)
		page_url_list = ['https://www.cvedetails.com' + page_a['href'] for page_a in page_a_list]

		if DEBUG_ENABLED:
			previous_len = len(page_url_list)
			if previous_len > DEBUG_OPTIONS['min_hub_pages']:
				page_url_list = page_url_list[::DEBUG_OPTIONS['hub_page_step']]
			
			log.debug(f'Reduced the number of hub pages from {previous_len} to {len(page_url_list)}.')

		else:
			first_page = SCRAPING_CONFIG.get('start_at_cve_hub_page')
			if first_page is not None:
				log.info(f'Starting at hub page {first_page} at the user''s request.')
				page_url_list = page_url_list[first_page-1:]

		for i, page_url in enumerate(page_url_list):

			log.info(f'Scraping hub page {i+1} of {len(page_url_list)}...')
			page_response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(page_url)
			if page_response is None:
				log.error(f'Failed to download hub page {i+1}.')
				continue
	
			page_soup = bs4.BeautifulSoup(page_response.text, 'html.parser')
			vulnerability_table = page_soup.find('table', id='vulnslisttable')
			cve_a_list = vulnerability_table.find_all('a', title=CVE_REGEX)
			
			# Test a random sample of CVEs from each page.
			if DEBUG_ENABLED:
				previous_len = len(cve_a_list)
				if DEBUG_OPTIONS['use_random_sampling']:
					cve_a_list = random.sample(cve_a_list, DEBUG_OPTIONS['max_cves_per_hub_page'])
				else:
					cve_a_list = cve_a_list[:DEBUG_OPTIONS['max_cves_per_hub_page']]
				log.debug(f'Reduced the number of CVE pages from {previous_len} to {len(cve_a_list)}.')

			for j, cve_a in enumerate(cve_a_list):

				cve_id = cve_a.get_text(strip=True)
				cve = Cve(cve_id, self)

				log.info(f'Scraping the CVE page {j+1} of {len(cve_a_list)}: "{cve.id}" from "{cve.url}"...')
				download_success = cve.download_cve_details_page()
				
				if download_success:
					cve.scrape_dates_from_page()
					cve.scrape_basic_attributes_from_page()
					cve.scrape_affected_product_versions_from_page()
					cve.scrape_references_from_page()

					self.scrape_additional_information_from_security_advisories(cve)
					self.scrape_additional_information_from_version_control(cve)

					cve.remove_duplicated_values()
					self.remove_invalid_git_commit_hashes(cve)
					self.remove_git_commit_hashes_by_branch(cve)
				else:
					log.error(f'Failed to download the page for {cve}.')

				yield cve

	def collect_and_save_vulnerabilities_to_csv_file(self):
		""" Collects any vulnerabilities related to this project and saves them to a CSV file. """

		CSV_HEADER = [
			'CVE', 'CVE URL',
			
			'Publish Date', 'Last Update Date',

			'CVSS Score', 'Confidentiality Impact', 'Integrity Impact',
			'Availability Impact', 'Access Complexity', 'Authentication',
			'Gained Access', 'Vulnerability Types', 'CWE',
			
			'Affected Product Versions',

			'Bugzilla URLs', 'Bugzilla IDs',
			'Advisory URLs', 'Advisory IDs', 'Advisory Info',
			'Git URLs', 'Git Commit Hashes',
			'SVN URLs', 'SVN Revision Numbers'
		]
		
		os.makedirs(self.output_directory_path, exist_ok=True)

		csv_file_path = self.csv_file_path_template.substitute(prefix='cve')

		with open(csv_file_path, 'w', newline='') as csv_file:

			csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADER)
			csv_writer.writeheader()

			for cve in self.scrape_vulnerabilities_from_cve_details():

				cve.serialize_containers()
				csv_row = {
					'CVE': cve.id, 'CVE URL': cve.url,

					'Publish Date': cve.publish_date, 'Last Update Date': cve.last_update_date,

					'CVSS Score': cve.cvss_score, 'Confidentiality Impact': cve.confidentiality_impact, 'Integrity Impact': cve.integrity_impact,
					'Availability Impact': cve.availability_impact, 'Access Complexity': cve.access_complexity, 'Authentication': cve.authentication,
					'Gained Access': cve.gained_access, 'Vulnerability Types': cve.vulnerability_types, 'CWE': cve.cwe,

					'Affected Product Versions': cve.affected_products,

					'Bugzilla URLs': cve.bugzilla_urls, 'Bugzilla IDs': cve.bugzilla_ids,
					'Advisory URLs': cve.advisory_urls, 'Advisory IDs': cve.advisory_ids, 'Advisory Info': cve.advisory_info,
					'Git URLs': cve.git_urls, 'Git Commit Hashes': cve.git_commit_hashes,
					'SVN URLs': cve.svn_urls, 'SVN Revision Numbers': cve.svn_revision_numbers
				}

				csv_writer.writerow(csv_row)

	####################################################################################################

	"""
		Methods used to find any files affected by a project's vulnerabilities.
	"""

	def find_and_save_affected_files_to_csv_file(self):
		""" Finds any files affected by this project's vulnerabilities and saves them to a CSV file. """

		for csv_path in self.find_output_csv_files('cve'):

			log.info(f'Finding affected files for the project "{self}" using the information in "{csv_path}".')

			cves = pd.read_csv(csv_path, usecols=['CVE', 'Git Commit Hashes'], dtype=str)
			cves = cves.dropna()
			cves['Git Commit Hashes'] = cves['Git Commit Hashes'].map(deserialize_json_container)

			git_commit_hashes = cves['Git Commit Hashes'].tolist()
			hash_list = [commit_hash for hash_list in git_commit_hashes for commit_hash in hash_list]
			hash_list = self.sort_git_commit_hashes_topologically(hash_list)
			
			affected_files = pd.DataFrame(columns=[	'File Path', 'Topological Index', 'Neutral Git Commit Hash', 'Changed Lines',
													'Vulnerable Git Commit Hash', 'CVEs', 'Last Change Git Commit Hash'])

			topological_index = 0
			for commit_hash in hash_list:

				parent_commit_hash = self.find_parent_git_commit_hash(commit_hash)

				has_source_file = False
				for file_path, changed_lines in self.find_changed_files_in_git_commit(commit_hash):

					has_source_file = True

					changed_lines = serialize_json_container(changed_lines)

					is_commit = cves['Git Commit Hashes'].map(lambda hash_list: commit_hash in hash_list)
					cve_list = cves.loc[is_commit, 'CVE'].tolist()
					cve_list = serialize_json_container(cve_list)

					last_change_commit_hash = self.find_last_changed_git_commit_hash(commit_hash, file_path)

					row = {
							'File Path': file_path,
							'Topological Index': topological_index,
							'Neutral Git Commit Hash': commit_hash,
							'Changed Lines': changed_lines,
							'Vulnerable Git Commit Hash': parent_commit_hash,
							'CVEs': cve_list,
							'Last Change Git Commit Hash': last_change_commit_hash
					}

					affected_files = affected_files.append(row, ignore_index=True)		

				if has_source_file:
					topological_index += 1

			csv_file_path = replace_in_filename(csv_path, 'cve', 'affected-files')

			affected_files.to_csv(csv_file_path, index=False)

	def iterate_and_checkout_affected_files_in_repository(self, csv_file_path: str) -> Iterator[ Tuple[str, bool, list, list] ]:
		""" Iterates over and performs a Git checkout operation on a list of files affected by the project's vulnerabilities. """

		affected_files = pd.read_csv(csv_file_path, usecols=['File Path', 'Topological Index', 'Neutral Git Commit Hash', 'Changed Lines', 'Vulnerable Git Commit Hash'], dtype=str)
		grouped_files = affected_files.groupby(by=['Topological Index', 'Neutral Git Commit Hash', 'Vulnerable Git Commit Hash'])

		for (topological_index, neutral_commit_hash, vulnerable_commit_hash), group_df in grouped_files:

			group_df = group_df.replace({np.nan: None})

			def checkout_affected_files(commit_hash: str, is_vulnerable: bool, file_path_list: list, changed_lines_list: list) -> Iterator[ Tuple[str, bool, list, list] ]:
				""" A helper method that performs the checkout. """

				# For files that were added in the neutral commit and don't have a previous vulnerable commit.
				if commit_hash is None:
					return

				checkout_success = self.checkout_entire_git_commit(commit_hash)

				if checkout_success:
					yield (commit_hash, is_vulnerable, file_path_list, changed_lines_list)
				else:
					status = 'Vulnerable' if is_vulnerable else 'Neutral'
					log.error(f'Failed to checkout commit {commit_hash} ({status}) for the files: {file_path_list}')


			file_path_list = group_df['File Path'].tolist()
			file_path_list = [self.get_absolute_path_in_repository(file_path) for file_path in file_path_list]
			
			changed_lines_list = group_df['Changed Lines'].tolist()
			changed_lines_list = [deserialize_json_container(lines) for lines in changed_lines_list]

			yield from checkout_affected_files(neutral_commit_hash, False, file_path_list, changed_lines_list)
			yield from checkout_affected_files(vulnerable_commit_hash, True, file_path_list, changed_lines_list)

		self.hard_reset_git_head()

	####################################################################################################

	"""
		Methods used to generate software metrics using any files affected by a project's vulnerabilities.
	"""

	def generate_and_save_metrics_to_csv_file(self):
		""" Generates the software metrics of any files affected by this project's vulnerabilities and saves them to a CSV file. """

		understand = UnderstandSat(self)
	
		for affected_csv_path in self.find_output_csv_files('affected-files'):

			log.info(f'Generating metrics for the project "{self}" using the information in "{affected_csv_path}".')

			affected_files = pd.read_csv(affected_csv_path, usecols=['File Path', 'Topological Index', 'Neutral Git Commit Hash', 'Vulnerable Git Commit Hash'], dtype=str)
			grouped_files = affected_files.groupby(by=['Topological Index', 'Neutral Git Commit Hash'])
			
			final_csv_file_path = replace_in_filename(affected_csv_path, 'affected-files', 'metrics')
			temp_csv_file_path = replace_in_filename(affected_csv_path, 'affected-files', 'temp-metrics')

			delete_file(temp_csv_file_path)
			delete_file(final_csv_file_path)

			for (commit_hash, is_vulnerable, file_path_list, changed_lines_list) in self.iterate_and_checkout_affected_files_in_repository(affected_csv_path):

				success = understand.generate_project_metrics(file_path_list, temp_csv_file_path)

				if success:

					metrics = pd.read_csv(temp_csv_file_path, dtype=str)

					metrics.insert(0, 'Vulnerable', None)
					metrics.insert(1, 'Git Commit Hash', None)

					metrics['Vulnerable'] = 'Yes' if is_vulnerable else 'No'
					metrics['Git Commit Hash'] = commit_hash
				
					append_dataframe_to_csv(metrics, final_csv_file_path)

				delete_file(temp_csv_file_path)

	def split_and_update_metrics_in_csv_files(self):
		""" Splits the metrics of any files affected by this project's vulnerabilities, updates them with new metrics, and saves them to a CSV file. """

		for csv_path in self.find_output_csv_files('metrics'):

			log.info(f'Splitting and updating metrics for the project "{self}" using the information in "{csv_path}".')

			metrics = pd.read_csv(csv_path)

			# Convert all numeric values to integers and leave any N/As with None.
			first_metric_index = metrics.columns.get_loc('File') + 1
			metrics.iloc[:, first_metric_index:] = metrics.iloc[:, first_metric_index:].fillna(-1.0).astype(int)
			metrics = metrics.replace({np.nan: None, -1: None})

			def insert_new_column(new_column: str, after_column: str):
				""" Inserts a new column after another one. """
				after_index = metrics.columns.get_loc(after_column) + 1
				metrics.insert(after_index, new_column, None)

			insert_new_column('SumCountPath', 'CountPath')

			insert_new_column('MaxCountInput', 'CountInput')
			insert_new_column('AvgCountInput', 'CountInput')
			insert_new_column('SumCountInput', 'CountInput')

			insert_new_column('MaxCountOutput', 'CountOutput')
			insert_new_column('AvgCountOutput', 'CountOutput')
			insert_new_column('SumCountOutput', 'CountOutput')

			insert_new_column('MaxMaxNesting', 'MaxNesting')
			insert_new_column('AvgMaxNesting', 'MaxNesting')
			insert_new_column('SumMaxNesting', 'MaxNesting')

			insert_new_column('HenryKafura', 'MaxMaxNesting')

			for row in metrics.itertuples():

				kind = row.Kind

				if kind == 'File':

					# Aggregate a few metrics that are not computed by Understand.
					"""
					UPDATE 	software.FILES_1_dom AS TB1,
							(SELECT ID_File,
								SUM(CountPath) AS CountPath,
								
								SUM(CountInput) AS FanIn,
								SUM(CountOutput) AS FanOut,
								
								AVG(CountInput) AS AvgFanIn,
								AVG(CountOutput) AS AvgFanOut,
								
								MAX(CountInput) AS MaxFanIn,
								MAX(CountOutput) AS MaxFanOut,
								
								MAX(MaxNesting) AS MaxMaxNesting,
								AVG(MaxNesting) AS AvgMaxNesting,
								SUM(MaxNesting) AS SumMaxNesting,
								
								SUM(CountLineCodeExe*(CountInput*CountOutput)*(CountInput*CountOutput)) AS HK
							FROM software.FUNCTIONS_1_dom group by ID_File) AS TB2
					"""

					# Find functions contained in this file.
					metrics_in_this_file = metrics.loc[ (metrics['Kind'].str.contains('Function')) & (metrics['File'] == row.File) ]

					def aggregate_metric(source_column: str, aggregation_type: str, destination_column: str):
						""" Aggregates various function-level metrics by applying the sum, average, or maximum operations to a given column. """

						result = 0
						metrics_in_column = metrics_in_this_file[source_column]

						if not metrics_in_column.empty:

							if aggregation_type == 'Sum':
								result = metrics_in_column.sum()
							elif aggregation_type == 'Avg':
								result = metrics_in_column.mean()
							elif aggregation_type == 'Max':
								result = metrics_in_column.max()
							else:
								assert False, f'Unhandled aggregation function "{aggregation_type}".'

							# Every value in the output file must be an integer.
							result = round(result)

						metrics.at[row.Index, destination_column] = result

					aggregate_metric('CountPath', 'Sum', 'SumCountPath')

					aggregate_metric('CountInput', 'Max', 'MaxCountInput')
					aggregate_metric('CountInput', 'Avg', 'AvgCountInput')
					aggregate_metric('CountInput', 'Sum', 'SumCountInput')

					aggregate_metric('CountOutput', 'Max', 'MaxCountOutput')
					aggregate_metric('CountOutput', 'Avg', 'AvgCountOutput')
					aggregate_metric('CountOutput', 'Sum', 'SumCountOutput')

					aggregate_metric('MaxNesting', 'Max', 'MaxMaxNesting')
					aggregate_metric('MaxNesting', 'Avg', 'AvgMaxNesting')
					aggregate_metric('MaxNesting',  'Sum', 'SumMaxNesting')

					# Henry Kafura Size: SUM( CountLineCodeExe x (CountInput x CountOutput)^2 )
					count_line_code_exe = metrics_in_this_file['CountLineCodeExe']
					count_input = metrics_in_this_file['CountInput']
					count_output = metrics_in_this_file['CountOutput']

					metrics.at[row.Index, 'HenryKafura'] = int( ( count_line_code_exe * (count_input * count_output) ** 2 ).sum() )

				elif 'Function' in kind:
					pass
				elif 'Class' in kind or 'Struct' in kind or 'Union' in kind:
					pass
				else:
					assert False, f'Unhandled code unit kind "{kind}".'

			##########

			def write_code_unit_csv(kind_regex: str, replacement_csv_prefix: str):
				""" Writes the rows of a specific kind of code unit to a CSV file. """
				
				is_code_unit = metrics['Kind'].str.contains(kind_regex)
				code_unit_metrics = metrics.loc[is_code_unit]
				code_unit_metrics = code_unit_metrics.dropna(axis=1, how='all')
				
				csv_file_path = replace_in_filename(csv_path, 'metrics', replacement_csv_prefix)

				code_unit_metrics.to_csv(csv_file_path, index=False)

			write_code_unit_csv('File', 'file-metrics')
			write_code_unit_csv('Function', 'function-metrics')
			write_code_unit_csv('Class|Struct|Union', 'class-metrics')

	####################################################################################################
	
	"""
		Methods used to generate security alerts using any files affected by a project's vulnerabilities.
	"""

	def find_code_units_from_line(self, file_path: str, line_arg: Union[ int, List[List[int]] ]) -> Tuple[ List[dict], List[dict] ]:
		""" Lists any functions and classes in a source file that overlap with a specific line number or ranges of lines.

		Use cases:
		- Single line number (for security alerts).
		- Multiple ranges of lines (for Git diffs, e.g. 10 to 20, 45 to 70).
		"""

		if isinstance(line_arg, int):

			if line_arg <= 0:
				log.warning(f'Clamping the line number {line_arg} to a minimum of one.')
				line_arg = 1

			lines = [[line_arg, line_arg]]

		elif isinstance(line_arg, list):

			for line_range in line_arg:

				if line_range[0] <= 0 or line_range[1] <= 0:
					log.warning(f'Clamping the line range {line_range} to a minimum of one.')
					line_range[0] = max(line_range[0], 1)
					line_range[1] = max(line_range[1], 1)

				if line_range[0] > line_range[1]:
					log.warning(f'Clamping the first line in range {line_range} to the second line.')
					line_range[0] = line_range[1]

			lines = line_arg

		else:
			assert False, f'Unhandled line argument type "{type(line_arg)}".'

		function_list: List[dict] = []
		class_list: List[dict] = []

		from clang.cindex import CursorKind, TranslationUnitLoadError

		source_file_path = self.get_absolute_path_in_repository(file_path)
		source_file_name = os.path.basename(source_file_path)

		try:

			with open(source_file_path, 'r') as source_file:
				source_contents = source_file.read()
				if self.language == 'c++':
					# @Hack: This is a hacky way of getting clang to report C++ methods that belong to a class
					# that is not defined in the file that we're processing. Although we tell clang where to
					# look for the header files that define these classes, this wouldn't work for the Mozilla's
					# repository structure. By removing the "<Class Name>::" pattern from a function's definition,
					# we're essentially telling clang to consider them regular C-style functions. This works for
					# our purposes since we only care about a function's name and its beginning and ending line
					# numbers.
					source_contents = re.sub(r'\S+::', '', source_contents)

			clang_arguments = ['--language', self.language]
			
			if self.include_directory_path is not None:
				clang_arguments.extend(['--include-directory', self.include_directory_path])

			global CLANG_INDEX
			tu = CLANG_INDEX.parse(source_file_name, args=clang_arguments, unsaved_files=[ (source_file_name, source_contents) ])
			
			for diagnostic in tu.diagnostics:
				log.info(f'Diagnostic: {diagnostic}')

			FUNCTION_KINDS = [	CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD, CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR,
								CursorKind.CONVERSION_FUNCTION, CursorKind.FUNCTION_TEMPLATE]

			CLASS_KINDS = [CursorKind.STRUCT_DECL, CursorKind.UNION_DECL, CursorKind.CLASS_DECL, CursorKind.CLASS_TEMPLATE]

			for node in tu.cursor.walk_preorder():

				# This should have the same behavior as clang_Location_isFromMainFile().
				if node.location.file is not None and node.location.file.name == source_file_name:

					def add_to_list(code_unit_list: List[dict]):
						""" Helper method that checks whether the line number belonds to the current code unit. """						
						
						unit_lines = [node.extent.start.line, node.extent.end.line]
						ranges_overlap = any(check_range_overlap(unit_lines, line_range) for line_range in lines)

						if ranges_overlap:
							code_unit_info = {'Name': node.displayname, 'Lines': unit_lines}
							code_unit_list.append(code_unit_info)

					if node.kind in FUNCTION_KINDS:
						add_to_list(function_list)
					elif node.kind in CLASS_KINDS:
						add_to_list(class_list)

		except TranslationUnitLoadError as error:
			log.error(f'Failed to parse the source file "{source_file_path}" with the error: {repr(error)}')

		return (function_list, class_list)

	def generate_and_save_alerts_to_csv_file(self):
		""" Generates the security alerts of any files affected by this project's vulnerabilities and saves them to a CSV file. """

		cppcheck = CppcheckSat(self)

		for affected_csv_path in self.find_output_csv_files('affected-files'):

			log.info(f'Generating the alerts for the project "{self}" using the information in "{affected_csv_path}".')

			temp_csv_path = replace_in_filename(affected_csv_path, 'affected-files', 'temp-cppcheck')
			final_csv_path = replace_in_filename(affected_csv_path, 'affected-files', 'alerts-cppcheck')

			delete_file(temp_csv_path)
			delete_file(final_csv_path)

			for (commit_hash, is_file_vulnerable, file_path_list, changed_lines_list) in self.iterate_and_checkout_affected_files_in_repository(affected_csv_path):

				# For each neutral-vulnerable commit pair, the commit hash and vulnerability status are different, but the file list and
				# changed lines are the same since it only uses the information from the neutral commit, even for the vulnerable one.

				cppcheck_success = cppcheck.generate_project_alerts(file_path_list, temp_csv_path)

				if cppcheck_success:
					alerts = pd.read_csv(temp_csv_path, dtype=str)

					alerts.insert(0, 'Vulnerable File', None)
					alerts.insert(1, 'Changed Lines', None)
					alerts.insert(2, 'Git Commit Hash', None)
					alerts.insert(3, 'Affected Functions', None)
					alerts.insert(4, 'Affected Classes', None)

					alerts['Vulnerable File'] = 'Yes' if is_file_vulnerable else 'No'
					alerts['Git Commit Hash'] = commit_hash

					file_path_to_lines = {self.get_relative_path_in_repository(file_path): lines for file_path, lines in zip(file_path_list, changed_lines_list)}

					for row in alerts.itertuples():
						
						if pd.notna(row.File) and pd.notna(row.Line):
							function_list, class_list = self.find_code_units_from_line(row.File, int(row.Line))
						
							def set_code_unit_vulnerability_status(code_unit_list):
								""" Sets the vulnerability status of any functions or classes found after parsing the affected files. This is done by checking
								if the lines modified from the vulnerable to neutral commit overlap with these code units. For example, a vulnerable file may
								have five functions, but only one of them was actually changed when a vulnerability was patched. For neutral commits, nothing
								is done since we'll assume that the file and its code units are on longer vulnerable (at least for this neutral-vulnerable
								commit pair). """

								if is_file_vulnerable:

									# It's possible that the SAT generates alerts related to files that we're not currently iterating over (e.g. the header
									# files of the current C/C++ source file). In those cases, we won't have a list of vulnerable lines.
									vulnerable_lines = file_path_to_lines.get(row.File, [])
									alerts.at[row.Index, 'Changed Lines'] = serialize_json_container(vulnerable_lines)
									
									for unit in code_unit_list:
										is_unit_vulnerable = any(check_range_overlap(unit['Lines'], vulnerable_range) for vulnerable_range in vulnerable_lines)	
										unit['Vulnerable'] = 'Yes' if is_unit_vulnerable else 'No'										
								else:

									alerts.at[row.Index, 'Changed Lines'] = None
									for unit in code_unit_list:
										unit['Vulnerable'] = 'No'

							set_code_unit_vulnerability_status(function_list)
							set_code_unit_vulnerability_status(class_list)

							alerts.at[row.Index, 'Affected Functions'] = serialize_json_container(function_list)
							alerts.at[row.Index, 'Affected Classes'] = serialize_json_container(class_list)
						else:
							log.warning('The following alert is missing its file or line number: ' + row)

					append_dataframe_to_csv(alerts, final_csv_path)

				delete_file(temp_csv_path)

####################################################################################################

class MozillaProject(Project):
	""" Represents the Mozilla project. """

	MOZILLA_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://www.mozilla.org')

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_security_advisories(self, cve: Cve):

		# Download and extract information from any referenced Mozilla Foundation Security Advisories (MFSA) pages.
		for mfsa_id, mfsa_url in zip(cve.advisory_ids, cve.advisory_urls):

			mfsa_info = {}
			log.info(f'Scraping additional information from advisory page {mfsa_id}: "{mfsa_url}"...')

			mfsa_response = MozillaProject.MOZILLA_SCRAPING_MANAGER.download_page(mfsa_url)
			if mfsa_response is None:
				log.error(f'Could not download the page for {mfsa_id}.')
				continue

			mfsa_soup = bs4.BeautifulSoup(mfsa_response.text, 'html.parser')

			"""
			[MFSA 2005-01 until (present)]
			<dl class="summary">
				<dt>Announced</dt>
				<dd>November 20, 2012</dd>
				<dt>Reporter</dt>
				<dd>Mariusz Mlynski</dd>
				<dt>Impact</dt>
				<dd><span class="level critical">Critical</span></dd>
				<dt>Products</dt>
				<dd>Firefox, Firefox ESR</dd>
				<dt>Fixed in</dt>
				<dd>
					<ul>
						<li>Firefox 17</li>
						<li>Firefox ESR 10.0.11</li>
					</ul>
				</dd>
			</dl>

			MFSA 2005-01 until MFSA 2016-84]
			<h3>References</h3>

			<p>Crashes referencing removed nodes (Jesse Ruderman, Martijn Wargers)</p>
			<ul>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=338391">https://bugzilla.mozilla.org/show_bug.cgi?id=338391</a></li>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=340733">https://bugzilla.mozilla.org/show_bug.cgi?id=340733</a></li>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=338129">https://bugzilla.mozilla.org/show_bug.cgi?id=338129</a></li>
			</ul>

			<p>crypto.generateCRMFRequest callback can run on deleted context (shutdown)</p>
			<ul>
				<li>
					<a href="https://bugzilla.mozilla.org/show_bug.cgi?id=337462">https://bugzilla.mozilla.org/show_bug.cgi?id=337462</a>
					<br>CVE-2006-3811
				</li>
			</ul>

			[MFSA 2016-85 until (present)]
			<section class="cve">
				<h4 id="CVE-2018-12359" class="level-heading">
					<a href="#CVE-2018-12359"><span class="anchor">#</span>CVE-2018-12359: Buffer overflow using computed size of canvas element</a>
				</h4>
				<dl class="summary">
					<dt>Reporter</dt>
					<dd>Nils</dd>
					<dt>Impact</dt>
					<dd><span class="level critical">critical</span></dd>
				</dl>
				<h5>Description</h5>
				<p>A buffer overflow can occur when rendering canvas content while adjusting the height and width of the <code>&lt;canvas&gt;</code> element dynamically, causing data to be written outside of the currently computed boundaries. This results in a potentially exploitable crash.</p>
				<h5>References</h5>
				<ul>
					<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=1459162">Bug 1459162</a></li>
				</ul>
			</section>

			<section class="cve">
				[...]
			</section>								
			"""

			# Get the basic information for all MFSA layout versions.
			dl_summary = mfsa_soup.find('dl', class_='summary')
			if dl_summary is not None:

				dt_list = dl_summary.find_all('dt')
				dd_list = dl_summary.find_all('dd')
				for dt, dd in zip(dt_list, dd_list):

					key = dt.get_text(strip=True)
					value = dd.get_text(strip=True)

					# Change the format of specific fields so they're consistent with the rest of the CSV file.
					if key == 'Announced':
						value = change_datetime_string_format(value, '%B %d, %Y', '%Y-%m-%d', 'en_US.UTF-8')
					elif key == 'Impact':
						value = value.title()
					elif key == 'Products':
						value = [product.strip() for product in value.split(',')]
					elif key == 'Fixed in':
						value = [li.get_text(strip=True) for li in dd.find_all('li')]
					
					key = key.title()
					mfsa_info[key] = value
			else:
				log.warning(f'No summary description list found for {mfsa_id}.')

			# Get the CVE information for all MFSA layout versions.
			cve_list = []

			# --> For MFSA 2005-01 until MFSA 2016-84.
			h3_list = mfsa_soup.find_all('h3')
			for h3 in h3_list:

				h3_text = h3.get_text(strip=True)
				if h3_text == 'References':

					for li in h3.find_all_next('li'):
						
						li_text = li.get_text(strip=True)
						match = CVE_REGEX.search(li_text)
						if match:
							cve_list.append(match.group(1))

			# --> For MFSA 2005-01 until the latest page.
			section_list = mfsa_soup.find_all('section', class_='cve')
			for section in section_list:
				h4_cve = section.find('h4', id=CVE_REGEX)
				if h4_cve is not None:
					cve_list.append(h4_cve['id'])

			if cve_list:
				mfsa_info['CVEs'] = cve_list

			cve.advisory_info[mfsa_id] = mfsa_info

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.bugzilla_ids:
			# E.g. " Bug 945192 - Followup to support Older SDKs in loaddlls.cpp. r=bbondy a=Sylvestre"
			regex_id = re.escape(id)
			grep_pattern = fr'^Bug \b{regex_id}\b'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

class XenProject(Project):
	""" Represents the Xen project. """

	XEN_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://xenbits.xen.org')

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_security_advisories(self, cve: Cve):

		# Download and extract information from any referenced Xen Security Advisories (XSA) pages.
		for xsa_full_id, xsa_url in zip(cve.advisory_ids, cve.advisory_urls):
			
			xsa_info = {}
			xsa_id = xsa_full_id.rsplit('-')[-1]
			log.info(f'Scraping additional information from advisory page {xsa_full_id}: "{xsa_url}"...')
			
			xsa_response = XenProject.XEN_SCRAPING_MANAGER.download_page(xsa_url)
			if xsa_response is not None:

				xsa_soup = bs4.BeautifulSoup(xsa_response.text, 'html.parser')

				"""
				<table>
					<tbody>
						<tr>
							<th>Advisory</th>
							<td><a href="advisory-55.html">XSA-55</a></td>
						</tr>
						<tr>
							<th>Public release</th>
							<td>2013-06-03 16:18</td>
						</tr>
						<tr>
							<th>Updated</th>
							<td>2013-06-20 10:26</td>
						</tr>
						<tr>
							<th>Version</th>
							<td>5</td>
						</tr>
						<tr>
							<th>CVE(s)</th>
							<td><a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2194">CVE-2013-2194</a> <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2195">CVE-2013-2195</a> <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2196">CVE-2013-2196</a></td>
						</tr>
						<tr>
							<th>Title</th>
							<td>Multiple vulnerabilities in libelf PV kernel handling</td>
						</tr>
					</tbody>
				</table>
				"""

				xsa_info_table = xsa_soup.find('table')
				if xsa_info_table is not None:

					xsa_info_th = xsa_info_table.find_all('th')
					xsa_info_td = xsa_info_table.find_all('td')
					for th, td in zip(xsa_info_th, xsa_info_td):

						key = th.get_text(strip=True)
						value = td.get_text(strip=True)

						# Change the format of specific fields so they're consistent with the rest of the CSV file.
						if key == 'Advisory':
							continue
						elif key == 'CVE(s)':
							key = 'CVEs'
							value = [cve_a.get_text(strip=True) for cve_a in td.find_all('a')]
						else:
							key = key.title()
							
						xsa_info[key] = value

					cve.advisory_info[xsa_full_id] = xsa_info

				else:
					log.warning(f'No information table found for {xsa_full_id}.')

			else:
				log.error(f'Could not download the page for {xsa_full_id}.')

			##################################################

			# Download an additional page that contains this XSA's Git commit hashes.
			xsa_meta_url = f'https://xenbits.xen.org/xsa/xsa{xsa_id}.meta'
			log.info(f'Scraping commit hashes from the metadata file related to {xsa_full_id}: "{xsa_meta_url}"...')
			
			xsa_meta_response = XenProject.XEN_SCRAPING_MANAGER.download_page(xsa_meta_url)
			if xsa_meta_response is not None:

				"""
				"Recipes":
				{
					"4.5":
					{
						"XenVersion": "4.5",
						"Recipes":
						{
							"xen":
							{
								"StableRef": "83724d9f3ae21a3b96362742e2f052b19d9f559a",
								"Prereqs": [],
								"Patches": ["xsa237-4.5/*"]
							}
						}
					},

					[...]
				}
				"""

				try:
					xsa_metadata = json.loads(xsa_meta_response.text)
				except json.decoder.JSONDecodeError as error:
					xsa_metadata = None
					log.error(f'Failed to parse the JSON metadata for {xsa_full_id} with the error: {repr(error)}')

				def nested_get(dictionary: dict, key_list: list):
					""" Tries to get a value from variously nested dictionaries by following a sequence of keys in a given order.
					If any intermediate dictionary doesn't exist, this method returns None. """

					value = None
					for key in key_list:
						value = dictionary.get(key)
						
						if value is None:
							break
						elif isinstance(value, dict):
							dictionary = value

					return value

				if xsa_metadata is not None:

					# Find every commit hash in the 'Recipes' dictionary.
					for reciple_key, recipe_value in xsa_metadata['Recipes'].items():

						commit_hash = nested_get(recipe_value, ['Recipes', 'xen', 'StableRef'])

						if commit_hash is not None:
							cve.git_commit_hashes.append(commit_hash)
						else:
							log.error(f'Could not find any commit hash for {xsa_full_id} in the "{reciple_key}" branch.')

			else:
				log.error(f'Could not download the metadata file for {xsa_full_id}.')

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.advisory_ids:
			# E.g. "This is CVE-2015-4164 / XSA-136."
			# E.g. "This is XSA-136 / CVE-2015-4164."
			# E.g. "This is XSA-215."
			regex_cve = re.escape(str(cve))
			regex_id = re.escape(id)
			grep_pattern = fr'This is.*\b({regex_cve}|{regex_id})\b'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

class ApacheProject(Project):
	""" Represents the Apache HTTP Server project. """

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_version_control(self, cve: Cve):
		# E.g. "SECURITY: CVE-2017-3167 (cve.mitre.org)"
		# E.g. "Merge r1642499 from trunk: *) SECURITY: CVE-2014-8109 (cve.mitre.org)"
		regex_cve = re.escape(str(cve))
		grep_pattern = fr'SECURITY:.*\b{regex_cve}\b'
		hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
		cve.git_commit_hashes.extend(hashes)

####################################################################################################

class GlibcProject(Project):
	""" Represents the GNU C Library (glibc) project. """

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.bugzilla_ids:
			# E.g. "Don't ignore too long lines in nss_files (BZ #17079)"
			# E.g. "Fix integer overflows in internal memalign and malloc [BZ #22343] [BZ #22774]"
			# E.g. "Fix nan functions handling of payload strings (bug 16961, bug 16962)."
			# E.g.  Don't ignore too long lines in nss_files (BZ17079, CVE-2015-5277) Tested:
			regex_id = re.escape(id)
			grep_pattern = fr'((BZ|Bug).*\b{regex_id}\b)|(\bBZ{regex_id}\b)'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

class Sat():
	""" Represents a third-party static analysis tool (SAT) and allows the execution of its commands. """

	config: dict

	name: str
	executable_path: str
	version: Optional[str]

	project: Project

	def __init__(self, name: str, project: Project):

		self.config = SCRAPING_CONFIG['sats'][name]
		self.name = name
		self.executable_path = self.config['executable_path']
		self.version = None
		self.project = project

	def __str__(self):
		return self.name

	def get_version(self) -> str:
		""" Gets the tool's version number. """
		return self.version or 'Unknown'

	def run(self, *args) -> Tuple[bool, str]:
		""" Runs the tool with a series of command line arguments. """

		arguments = [self.executable_path] + [arg for arg in args]
		result = subprocess.run(arguments, capture_output=True, text=True)
		success = result.returncode == 0

		if not success:
			command_linesuments = ' '.join(arguments)
			error_message = result.stderr or result.stdout
			log.error(f'Failed to run the command "{command_linesuments}" with the error code {result.returncode} and the error message "{error_message}".')

		return (success, result.stdout)

####################################################################################################

class UnderstandSat(Sat):
	""" Represents the Understand tool, which is used to generate software metrics given a project's source files. """

	def __init__(self, project: Project):
		super().__init__('Understand', project)
		
		version_success, build_number = self.run('version')
		if version_success:
			build_number = re.findall(r'\d+', build_number)[0]
			self.version = build_number

	def generate_project_metrics(self, file_path_list: list, output_csv_path: str) -> bool:
		""" Generates the project's metrics using the files and any other options defined in the database directory. """
	
		"""
			Understand Metrics Settings:
			- WriteColumnTitles				on/off (default on)
			- ShowFunctionParameterTypes	on/off (default off)
			- ShowDeclaredInFile			on/off (default off)
			- FileNameDisplayMode			NoPath/FullPath/RelativePath (default NoPath)
			- DeclaredInFileDisplayMode		NoPath/FullPath/RelativePath (default NoPath)
			- OutputFile					<CSV File Path> (default "<Database Name>.csv")
			
			These were listed using the command: und list -all settings <Database Name>
		"""

		database_path = os.path.join(self.project.output_directory_path, self.project.short_name + '.und')

		success, _ = self.run	(
									'-quiet', '-db', database_path,
									'create', '-languages', 'c++', # This value cannot be self.project.language since only "c++" is accepted.
									'settings', '-metrics', 'all',
												'-metricsWriteColumnTitles', 'on',
												'-metricsShowFunctionParameterTypes', 'on',
												'-metricsShowDeclaredInFile', 'on',
												'-metricsFileNameDisplayMode', 'NoPath',
												'-metricsDeclaredInFileDisplayMode', 'RelativePath',
												'-metricsOutputFile', output_csv_path,

									'add', *file_path_list,
									'analyze',
									'metrics'
								)

		if success:
			
			metrics = pd.read_csv(output_csv_path, dtype=str)

			metrics['File'] = metrics['File'].map(lambda x: x.replace('\\', '/') if pd.notna(x) else x)

			metrics.to_csv(output_csv_path, index=False)

		delete_directory(database_path)

		return success

####################################################################################################

class CppcheckSat(Sat):
	""" Represents the Cppcheck tool, which is used to generate security alerts given a project's source files. """

	RULE_TO_CWE: dict = {}
	mapped_rules_to_cwes: bool = False

	def __init__(self, project: Project):
		super().__init__('Cppcheck', project)

		version_success, version_number = self.run('--version')
		if version_success:
			version_number = re.findall(r'\d+\.\d+', version_number)[0]
			self.version = version_number

		if not CppcheckSat.mapped_rules_to_cwes:
			CppcheckSat.mapped_rules_to_cwes = True

			with open('cppcheck_error_list.xml') as xml_file:
				error_soup = bs4.BeautifulSoup(xml_file, 'xml')

			if error_soup is not None:
				error_list = error_soup.find_all('error', id=True, cwe=True)				
				CppcheckSat.RULE_TO_CWE = {error['id']: error['cwe'] for error in error_list}
			else:
				log.error(f'Failed to map a list of SAT rules to their CWE values.')

	def generate_project_alerts(self, file_path_list: list, output_csv_path: str) -> bool:
		""" Generates the project's alerts given list of files. """

		if self.project.include_directory_path is not None:
			include_arguments = ['-I', self.project.include_directory_path]
		else:
			include_arguments = ['--suppress=missingInclude']

		# The argument "--enable=error" is not necessary since it's enabled by default.
		# @Future: Should "--force" be used? If so, remove "--suppress=toomanyconfigs".
		success, _ = self.run	(
									'--quiet',
									'--enable=warning,portability', '--inconclusive',
									f'--language={self.project.language}', *include_arguments,
									'--suppress=toomanyconfigs', '--suppress=unknownMacro', '--suppress=unmatchedSuppression',
									
									'--template="{file}","{line}","{column}","{severity}","{id}","{cwe}","{message}"',
									f'--output-file={output_csv_path}',
									*file_path_list
								)

		if success:
			alerts = pd.read_csv(output_csv_path, header=None, names=['File', 'Line', 'Column', 'Severity', 'Rule', 'CWE', 'Message'], dtype=str)

			alerts['File'] = alerts['File'].map(lambda x: None if x == 'nofile' else self.project.get_relative_path_in_repository(x))
			alerts['Line'] = alerts['Line'].replace({'0': None})
			alerts['Column'] = alerts['Column'].replace({'0': None})
			alerts['CWE'] = alerts['CWE'].replace({'0': None})

			alerts.to_csv(output_csv_path, index=False)

		return success

	def read_and_convert_output_csv_in_default_format(self, csv_path: str) -> pd.DataFrame:
		""" Reads a CSV file generated using Cppcheck's default output parameters and converts it to a more convenient format. """

		# The default CSV files generated by Cppcheck don't quote values with commas correctly.
		# This means that pd.read_csv() would fail because some lines have more columns than others.
		# We'll read each line ourselves and interpret anything after the fourth column as being part
		# of the "Message" column.
		dictionary_list = []
		with open(csv_path, 'r') as csv_file:
			
			for line in csv_file:
				filepath_and_line, severity, rule, message = line.split(',', 3)
				file_path, line = filepath_and_line.rsplit(':', 1)
				message = message.rstrip()

				dictionary_list.append({'File': file_path, 'Line': line, 'Severity': severity, 'Rule': rule, 'Message': message})

		alerts = pd.DataFrame.from_dict(dictionary_list, dtype=str)

		alerts['File'] = alerts['File'].map(lambda x: None if x == 'nofile' else self.project.get_relative_path_in_repository(x))
		alerts['CWE'] = alerts['Rule'].map(lambda x: CppcheckSat.RULE_TO_CWE.get(x, ''))
		
		return alerts


####################################################################################################

if __name__ == '__main__':
	project_list = Project.get_project_list_from_config()

	Project.debug_ensure_all_project_repositories_were_loaded(project_list)

	for project in project_list:
		if project.short_name == 'mozilla':

			cppcheck = CppcheckSat(project)
			alerts = cppcheck.read_and_convert_output_csv_in_default_format(os.path.join('test_cases', 'cppcheck-1-f40f923a0a09ab1d0e28a308364a924893c5fd02.csv'))
			alerts.to_csv(os.path.join('test_cases', 'converted-cppcheck.csv'), index=False)
