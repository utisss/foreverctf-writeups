# reversing-strings
* **Event:** ForeverCTF
* **Problem Type:** Crypto
* **Point Value / Difficulty:** Easy
* **(Optional) Tools Required / Used:** GNU strings

## Background
All data in an exectuable format is binary. Most of this data is unreadable to humans, however, GNU strings will filter through any binary file and attempt to view the binary data as ASCII characters. Sometimes, developers hardcode secrets that can be abused later on. 
## Steps
#### Step 1
Log into a linux box and download the challenge. 

#### Step 2
Run strings on the binary like so: `strings reversing-strings` and the flag should pop out.