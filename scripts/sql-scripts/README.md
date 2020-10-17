# SQL Scripts

This directory is meant to store any useful SQL scripts that are used to add test data to the software vulnerabilities database.

It includes the following SQL scripts:

* `load-extra-time-files-for-patch-pct4mlz.sql` inserts the (ID_File, P_ID) values for the patch ID 'pct4mlz' (Mozilla, commit `f40f923a0a09ab1d0e28a308364a924893c5fd02`) into the 'extra_time_files' table. This is useful since the complete Mozilla 'extra_time_files' import scripts (`EXTRA-TIME-FILES1000.sql` and `EXTRA-TIME-FILES1001.sql`) are over 700 MB of text data, and would take a very long time to add to a local database. The 'extra_time_files' table must have been previously created using the import scripts specified in the main Python scripts directory.
