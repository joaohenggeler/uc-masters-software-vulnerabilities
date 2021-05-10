#!/usr/bin/env python3
import sys
import requests
import bs4
import re
import csv

"""
	This script explores the information available in the Mozilla Foundation Security Advisories (MFSA) website by scraping all of
	its pages, and storing the information about each CVE in a CSV file. No connections to the software vulnerabilities database
	are made.

	Requirements:

	pip install requests
	pip install beautifulsoup4

"""

HTTP_HEADERS = {
	'Accept-Language': 'en-US',
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
}

try:
	main_cve_details_url = 'https://www.mozilla.org/en-US/security/advisories/'
	print(f'Downloading the main MFSA page from "{main_cve_details_url}"...')
	response = requests.get(main_cve_details_url, headers=HTTP_HEADERS)
	response.raise_for_status()
except Exception as error:
	error_string = repr(error)
	print(f'Failed to download the main MFSA page with the error: {error_string}')
	sys.exit(1)

print()

"""
<ul>
	<li class="level-item">
	<a href="/en-US/security/advisories/mfsa2020-22/"><span class="level high">MFSA 2020-22</span> Security Vulnerabilities fixed in Thunderbird 68.9.0</a></li>

	<li class="level-item">
	<a href="/en-US/security/advisories/mfsa2020-21/"><span class="level high">MFSA 2020-21</span> Security Vulnerabilities fixed in Firefox ESR 68.9</a></li>

	<li class="level-item">
	<a href="/en-US/security/advisories/mfsa2020-20/"><span class="level high">MFSA 2020-20</span> Security Vulnerabilities fixed in Firefox 77</a></li>
</ul>
"""

CVE_REGEX = re.compile(r'(CVE-\d*-\d*)', re.IGNORECASE)
BUGZILLA_URL_REGEX = re.compile(r'https?://bugzilla.*', re.IGNORECASE)
MFSA_URL_REGEX = re.compile(r'/en-US/security/advisories/mfsa*', re.IGNORECASE)

main_soup = bs4.BeautifulSoup(response.text, 'html.parser')

mfsa_a_list = main_soup.find_all('a', href=MFSA_URL_REGEX)

with open('mfsa-results.csv', 'w', newline='') as csv_file:

	csv_writer = csv.DictWriter(csv_file, fieldnames=['CVE', 'MFSA', 'Exists In CVE Details', 'MFSA URL', 'CVE Details URL', 'Bugzilla URL'])
	csv_writer.writeheader()

	for i, mfsa_a in enumerate(mfsa_a_list):

		mfsa_href = mfsa_a['href']
		mfsa_url = f'https://www.mozilla.org{mfsa_href}'

		#mfsa_name = mfsa_href.rsplit('/', 2)[-2]
		mfsa_name = mfsa_a.find('span').get_text(strip=True)

		print(f'MFSA {i+1} of {len(mfsa_a_list)}: "{mfsa_name}" from "{mfsa_url}"...')

		try:
			response = requests.get(mfsa_url, headers=HTTP_HEADERS)
			response.raise_for_status()
		except Exception as error:
			error_string = repr(error)
			print(f'Failed to download the {mfsa_name} page with the error: {error_string}')
			continue

		mfsa_soup = bs4.BeautifulSoup(response.text, 'html.parser')
		
		"""
		[MFSA 2016-85 until MFSA 2020-44 (present)]
		<section class="cve">
			<h4 id="CVE-2020-15677" class="level-heading">
				<a href="#CVE-2020-15677"><span class="anchor">#</span>CVE-2020-15677: Download origin spoofing via redirect</a>
			</h4>
			
			<dl class="summary">
				<dt>Reporter</dt>
				<dd>Richard Thomas and Tom Chothia of University of Birmingham</dd>
				
				<dt>Impact</dt>
				<dd><span class="level moderate">moderate</span></dd>
			</dl>
			
			<h5>Description</h5>
			<p>By exploiting an Open Redirect vulnerability on a website, an attacker could have spoofed the site displayed in the download file dialog to show the original site (the one suffering from the open redirect) rather than the site the file was actually downloaded from.</p>

			<h5>References</h5>
			<ul>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=1641487">Bug 1641487</a></li>
			</ul>
		</section>
		"""

		"""
		[MFSA 2005-01 until MFSA 2016-84]
		<h3>References</h3>
		
		<ul>
			<li>
				<a href="https://bugzilla.mozilla.org/show_bug.cgi?id=1190038">HTML injection on homescreen app (with bypassing DOM sanitizer)</a>
				(<a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8510" class="ex-ref">CVE-2015-8510</a>)
			</li>
		</ul>

		<ul>
			<li>
				<a href="https://bugzilla.mozilla.org/show_bug.cgi?id=773207">Heap-use-after-free in nsObjectLoadingContent::LoadObject</a>
			</li>
			<li>
				<a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-1973" class="ex-ref">CVE-2012-1973</a>
			</li>
		</ul>
		"""

		cve_list = []

		# [MFSA 2016-85 until MFSA 2020-44 (present)]
		cve_section_list = mfsa_soup.find_all('section', class_='cve')
		for cve_section in cve_section_list:

			cve_header = cve_section.find('h4', id=CVE_REGEX)
			if cve_header is not None:

				cve = cve_header['id']

				bugzilla_a = cve_section.find('a', href=BUGZILLA_URL_REGEX)
				bugzilla_url = bugzilla_a['href'] if bugzilla_a is not None else None

				cve_list.append((cve, bugzilla_url))

		# [MFSA 2005-01 until MFSA 2016-84]
		header_list = mfsa_soup.find_all('h3')
		for header in header_list:

			header_text = header.get_text(strip=True)
			if header_text == 'References':

				for header_sibling in header.next_siblings:

					if header_sibling.name == 'ul':

						references_list = header_sibling.find_all('a')
						previous_bugzilla_url = None

						for reference in references_list:

							reference_url = reference.get('href')
							reference_text = reference.get_text(strip=True)

							if BUGZILLA_URL_REGEX.match(reference_url):

								previous_bugzilla_url = reference_url
							
							else:

								cve_search = CVE_REGEX.search(reference_text)
								if cve_search is not None:

									# In some rare cases, we'd get the CVE plus some trailing characters.
									# This ensures that we only get the CVE pattern we specified earlier
									# in the regular expression.
									cve = cve_search.group(1)
									cve_list.append((cve, previous_bugzilla_url))

								previous_bugzilla_url = None

				# There's only one References section.
				break

		if not cve_list:
			print('-> No CVEs.')

		for j, (cve, bugzilla_url) in enumerate(cve_list):

			cve_details_url = f'https://www.cvedetails.com/cve/{cve}'
			exists_in_cve_details = None

			try:
				print(f'-> CVE {j+1} of {len(cve_list)}: "{cve}" from "{cve_details_url}"...')
				response = requests.get(cve_details_url, headers=HTTP_HEADERS)
				response.raise_for_status()

				cve_details_soup = bs4.BeautifulSoup(response.text, 'html.parser')
				error_message_div = cve_details_soup.find('div', class_='errormsg')
				exists_in_cve_details = error_message_div is None

			except Exception as error:
				error_string = repr(error)
				print(f'Failed to download the CVE Details page for {cve} with the error: {error_string}')

			if not exists_in_cve_details:
				cve_details_url = None

			exists_in_cve_details = 'Yes' if exists_in_cve_details else 'No'

			# Some Bugzilla URLs have newlines in the middle, so we'll remove them.
			if bugzilla_url is not None:
				# This URL sometimes doesn't exist for a given CVE.
				# For example, MFSA 2013-116 includes two CVEs but only one Bugzilla reference.
				bugzilla_url = bugzilla_url.replace('\r', '')
				bugzilla_url = bugzilla_url.replace('\n', '')

			csv_writer.writerow({'CVE': cve, 'MFSA': mfsa_name, 'Exists In CVE Details': exists_in_cve_details,
								'MFSA URL': mfsa_url, 'CVE Details URL': cve_details_url, 'Bugzilla URL': bugzilla_url})

		print()

print()
print('Finished running.')
