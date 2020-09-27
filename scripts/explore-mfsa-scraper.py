#!/usr/bin/env python
import sys
import requests
import bs4
import re

"""
	This script explores the information available in the Mozilla Foundation Security Advisories (MFSA) website by scraping some of its pages.
	No connections to the software vulnerabilities database are made.

	Requirements:

	pip install requests
	pip install beautifulsoup4

"""

HTTP_HEADERS = {
	'Accept-Language': 'en-US',
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
}

CVE_REGEX = re.compile('CVE-\d*-\d*', re.IGNORECASE)

try:
	main_page_url = 'https://www.mozilla.org/en-US/security/advisories/'
	print(f'Downloading the main MFSA page from "{main_page_url}"...')
	response = requests.get(main_page_url, headers=HTTP_HEADERS)
	response.raise_for_status()
except Exception as error:
	error_string = repr(error)
	print(f'Failed to download the main MFSA page with the error: {error_string}')
	sys.exit(1)

main_soup = bs4.BeautifulSoup(response.text, 'html.parser')

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

mfsa_a_list = main_soup.find_all('a', href=re.compile('/en-US/security/advisories/mfsa*'))
total_num_mfsa = len(mfsa_a_list)
print(f'Found {total_num_mfsa} security advisories. Only one for each year will be shown below.')
print()

years_checked = []

for i, mfsa_a in enumerate(mfsa_a_list):

	mfsa_href = mfsa_a['href']
	mfsa_url = f'https://www.mozilla.org/{mfsa_href}'
	mfsa_name = mfsa_href.rsplit('/', 2)[-2]
	assert mfsa_name
	mfsa_year = mfsa_name[4:8]

	# For testing purposes.
	if mfsa_year in years_checked:
		continue
	else:
		years_checked.append(mfsa_year)

	print(f'#{i}: "{mfsa_name}" from "{mfsa_url}"')
	print()

	try:
		response = requests.get(mfsa_url, headers=HTTP_HEADERS)
		response.raise_for_status()
	except Exception as error:
		error_string = repr(error)
		print(f'Failed to download the {mfsa_name} page with the error: {error_string}')
		continue

	mfsa_soup = bs4.BeautifulSoup(response.text, 'html.parser')
	
	"""
	<dl class="summary">
		<dt>Announced</dt>
		<dd>September 22, 2020</dd>

		<dt>Impact</dt>
		<dd><span class="level moderate">moderate</span></dd>

		<dt>Products</dt>
		<dd>Thunderbird</dd>
		
		<dt>Fixed in</dt>
		<dd><ul><li>Thunderbird 78.3</li></ul></dd>
	</dl>
	"""

	print('\t-> Summary:')
	summary_dl = mfsa_soup.find('dl', class_='summary')
	if summary_dl is not None:

		summary_name_list = summary_dl.find_all('dt')
		summary_value_list = summary_dl.find_all('dd')
		assert len(summary_name_list) == len(summary_value_list)

		for name_dt, value_dd in zip(summary_name_list, summary_value_list):
			
			name = name_dt.get_text(strip=True)
			value = value_dd.get_text(strip=True)
			print(f'\t\t---> "{name}" : "{value}"')

	else:
		print(f'\t\tMissing summary for {mfsa_name}.')

	print()

	"""
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
	[2015 and older]
	<h3>References</h3>
	<ul>
		<li>
			<a href="https://bugzilla.mozilla.org/show_bug.cgi?id=1190038">HTML injection on homescreen app (with bypassing DOM sanitizer)</a>
			(<a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8510" class="ex-ref">CVE-2015-8510</a>)
		</li>
	</ul>
	"""

	print('\t-> CVE List:')

	cve_section_list = mfsa_soup.find_all('section', class_='cve')
	for cve_section in cve_section_list:

		cve_header = cve_section.find('h4', id=CVE_REGEX)
		if cve_header is not None:

			cve = cve_header['id']
			cve_description = cve_header.get_text(strip=True)
			cve_description = cve_description.split(' ', 1)[1]

			print(f'\t\t---> "{cve}" : "{cve_description}"')

	h3_list = mfsa_soup.find_all('h3')
	for h3 in h3_list:

		h3_text = h3.get_text(strip=True)
		if h3_text == 'References':

			references_ul = h3.next_sibling.next_sibling
			references_list = references_ul.find_all('a', href=True)
			for reference in references_list:

				reference_url = reference['href']
				reference_text = reference.get_text(strip=True)

				if CVE_REGEX.match(reference_text):

					print(f'\t\t---> "{reference_text}" from "{reference_url}"')

	print()
	print()
	print()

print('Finished running.')
