from matplotlib_venn import venn2
import matplotlib.pyplot as plt

venn2(subsets = (576, 171, 1623), set_labels = ('CVE Details', 'MFSA'))
plt.title('CVEs in the CVE Details and MFSA Websites (2000 to 2020)')
plt.tight_layout()
plt.savefig('venn-cve-details-and-mfsa.svg')
