---
layout: post
title:  "BMP Fileformat Trick"
date:   2023-11-05 16:07:25 +0100
categories: ctf
---
Greetings!
In my first event blog post I'll show you some BMP trick that might be helpful in some CTF challenges.
Let's say that we are provided with such an image:
![Image](../images/post1/level2.bmp)

What might be helpful to do is to open image in Hexeditor to check if someone hide something from us.
I've used online '[hexed.it](https://hexed.it)' editor.

![Alt text](../images/post1/hexed-preview1.png)

Based on BMP format specification (from [wikipedia](https://en.wikipedia.org/wiki/BMP_file_format) for example) we know that integers are represented in little-endian convention.

Our first 2 bytes are: `42 4D` which are magic bytes for BMP format.

Then we have 4 bytes representing file size in bytes. In our image it is: `F6 1E 03 00`, which is `0x31EF6` - `204534` in decimal.

Next we have two reserved fields: 2 bytes on offset 0x6 and 2 bytes on offset 0x8.

What is most interesting to us is next value: 4 bytes representing data offset (starting address of data).
In our example it is: `00 0C 03 00` which means that actual data stars at offset `0x30C00`. Interesting question is now: why it is starting at `0x30C00` and not on `0x0000E` which is right after bitmap file header. Let's change our data offset to `0x0000E` and see what happens.

![Alt text](../images/post1/hexed-preview2.png)

After saving edited image on disk we see:

![Alt text](../images/post1/level2-flag.png)

Summing up: editing offsets in BMP file might be a good idea to hide something from unwanted eyes.