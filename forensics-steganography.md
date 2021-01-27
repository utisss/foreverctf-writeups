# Not Very Significant Message
* **Event:** ForeverCTF
* **Problem Type:** Forensics
* **Point Value / Difficulty:** Easy
* **(Optional) Tools Required / Used:** an LSB Steganography solver ([this one](https://stylesuxx.github.io/steganography/) in particular should do the trick)

## Explanation
Stegonagraphy is the practice of hiding messages by embedding them within another message or an object (like an image). There are many different techniques for doing this, but one popular is [Least Signifcant Bit steganography](https://www.boiteaklou.fr/Steganography-Least-Significant-Bit.html). This technique changes the least significant bit in the bytes that describe RBG color values for a pixel in an image. There are several online steganography tools that you can use, such as [this one](https://stylesuxx.github.io/steganography/). The thing to keep in mind is that steganography implementations differ even within a particular technique, so not ever steganography tool will work to decipher an image with a hidden message. If you're feeling up to it, you could always write your own implementation of an LSB tool!
