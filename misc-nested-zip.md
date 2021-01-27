# Zip Scripting
* **Event:** ForeverCTF
* **Problem Type:** Misc
* **Difficulty:** Medium
* **(Optional) Tools Required / Used:** Python

## Solution
This is just a lot of nested ZIP files. Use a script to open them up. There's an example script:
```import os
from zipfile import ZipFile

ZIP_NAME = 'flag.zip'
TMP_ZIP_NAME = 'tmp_' + ZIP_NAME

done = False

while not done:
	# rename to a temporary file
	# extraction will result in creating a file of the same name
	# (this is an assumption, but it holds true for this problem)
	# (if the assumption were wrong, the script would fail after unzipping some number of layers)
	os.rename(ZIP_NAME, TMP_ZIP_NAME)
	with ZipFile(TMP_ZIP_NAME, 'r') as zp:
		zp.namelist()
		zp.extractall()
		
		# quit if there is more than one file in the archive
		# quite if the file in the archive is not the name we expect
		if len(zp.namelist()) != 1 or zp.namelist()[0] != ZIP_NAME:
			done = True
	os.remove(TMP_ZIP_NAME)```
