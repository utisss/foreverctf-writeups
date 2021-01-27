# HTTP Objects
* **Event:** ForeverCTF
* **Problem Type:** Networking
* **Point Value / Difficulty:** Medium
* **(Optional) Tools Used:** Wireshark


## Steps
#### Step 1
Open the file in Wireshark.

#### Step 2
Observe that there is HTTP data. Isolate it with the filter display `http`.

#### Step 3
Notice that there is a GET request for `/flag.jpeg`. File > Export Objects > HTTP. Select `flag.jpeg`, save the image, and open it in an image viewer.

The flag should be present in the image.
