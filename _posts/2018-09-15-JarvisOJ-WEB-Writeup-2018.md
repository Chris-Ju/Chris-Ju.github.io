---
layout:     post                    # 使用的布局（不需要改）
title:      JarvisOJ-WEB-Writeup    # 标题
subtitle:   日就完事了               #副标题
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