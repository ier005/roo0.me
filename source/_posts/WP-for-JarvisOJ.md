---
title: WP for JarvisOJ
categories: [CTF]
tags: [CTF, Writeup, WEB, JarvisOJ, raw md5, SQL注入, 哈希长度扩展攻击]
---

## Login

此题可以在Response Header中看到有提示

	Hint:"select * from `admin` where password='".md5($pass,true)."'"
可以看到，`md5`函数的第二个参数为`true`，即为**Raw 16 character binary format**，已经不仅仅局限于0~F这几个字符，这就有了注入的可能性。通过特殊的`$pass`值，可以构造出一个能够注入的字符串。例如：

	ffifdyop
上述字符串的MD5结果为

	'or'6�]��!r,��b
这就可以注入成功，得到结果。



## IN A Mess



## flag在管理员手里



## PHPINFO





