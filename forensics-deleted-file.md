# Dr. Doom's Devious Deletion Dilemma
* **Event:** ForeverCTF
* **Problem Type:** Forensics
* **Point Value / Difficulty:** Medium

## Walkthrough
"Deleting" a file doesn't always get rid of it in a manner that is permanent. In this case, it simply moved the file to the Trash folder.
#### Step 1
You'll want to unzip the disk image and then mount it so you can look around the file contents. To mount, you can do
`> mkdir mntpnt`
`> sudo mount disk.img mntpnt`

#### Step 2
Now you can explore Dr. Doom's home directory. The Trash folder is located in `.local/share/Trash` (which you can either look up or stumble upon accidentally after wandering around aimlessly for a while). 
Travel to that directory and you will find just one file in the Trash folder, `flag`, and from there you can simply run `cat flag`.
