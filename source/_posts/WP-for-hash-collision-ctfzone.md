---
title: WP for hash_collision_ctfzone
categories: [CTF]
tags: [CTF, WEB, Writeup, ctfzone, hash_collision]
---

### 题目源码分析

打开题目链接，可以看到题目给出了php源码链接，内容如下：

``` php
<html>
<head>
	<title>level1</title>
    <link rel='stylesheet' href='style.css' type='text/css'>
</head>
<body>

<?php
require 'flag.php';

if (isset($_GET['name']) and isset($_GET['password'])) {
    $name = (string)$_GET['name'];
    $password = (string)$_GET['password'];

    if ($name == $password) {
        print 'Your password can not be your name.';
    } else if (sha1($name) === sha1($password)) {
      die('Flag: '.$flag);
    } else {
        print '<p class="alert">Invalid password.</p>';
    }
}
?>

<section class="login">
	<div class="title">
		<a href="./index.txt">Level 1</a>
	</div>

	<form method="get">
		<input type="text" required name="name" placeholder="Name"/><br/>
		<input type="text" required name="password" placeholder="Password" /><br/>
		<input type="submit"/>
	</form>
</section>
</body>
</html>
```

可以看到，题目的关键就是构造不同的`$name`与`$password`，使得其**sha1**后的hash值相同。

### 设法绕过

最初想来构造hash值碰撞是不可能的，将精力放在了php的[弱类型](http://zjw.dropsec.xyz/2016/10/09/php%E5%BC%B1%E7%B1%BB%E5%9E%8B/)上，以期能够绕过判断检测。但是最终发现，上述代码首先对传入的参数进行了强制类型转换，所以使用传入数组的方法是无法绕过参数相等的判断的（在传入不同数组的情况下，首先过去相等检测这一关，然后sha1函数对数组进行运算，是会返回`null`的，所以`null === null`，可以绕过），另外对hash值得相等判断使用的是`===`，所以也没有办法采用`0e\d+`这种科学记数法的方式来绕过（传入两个字符串，它们的hash值为'0e\d+'，如果使用`==`进行相等判断，则会认为引号内的数据为科学记数法表示的数字，结果均为零）。

此路不通。。。

### SHA1 collision

最终找到谷歌发现的[sha1碰撞](https://shattered.io/)，若是把两个pdf的文件内容全部上传作为参数，是超过了URI的长度限制的。查阅资料发现，关键在于两个pdf文件的前**0x140**个字节，后面的数据只要内容一样，其sha1值均相同，因此可以只上传前0x140，也就是前320个字节即可，然后可以拿到FALG。

python代码如下：

``` python
#!/usr/bin/python

from urllib import quote
import requests

with open('shattered-1.pdf') as f:
    coll1 = f.read(0x140)

with open('shattered-2.pdf') as f:
    coll2 = f.read(0x140)

print requests.get('http://.../?name={}&password={}'.format(quote(coll1), quote(coll2))).text
```

最终拿到FLAG：

	FLAG{hash_shattered_2333}