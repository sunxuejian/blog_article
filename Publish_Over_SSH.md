# 简介
> publish over ssh是jenkins上一个插件,可以在jenkins系统管理->插件管理->可选插件中搜索到,然后安装,其主要的作用就是用于,远程登录到目标主机上.并且可以在目标主机上执行一些脚本.

# 如何做到远程持续集成.

---
## 场景
> 我们的java项目在Jenkins上编译打包,可是我们想让Jenkins上打包出来的程序在另一台机器上执行,那么我们如何做到呢,首先你总得ssh到目标机器上,然后执行相应的脚本吧,所以我们用到了 <font color=red>publish over ssh</font> 我们需要在jenkins上安装这个插件.

# 安装插件
>点击系统管理

![系统管理](image/jm.jpg)

> 点击插件管理

![插件管理](image/jpm.jpg)

> 搜索插件,并安装

![install](image/sp.jpg)

>下载好插件后,进入到系统管理中的系统设置中,然后往下拉,找到 Publish over SSH这一栏进行配置

![ssh配置](image/sshset.jpg)

## 如何生成ssh密匙

> 如果需要jenkins远程登录到目标主机,需要在目标主机对应的用户下面生存ssh密匙

1. 首先检查该用户有没有生成过ssh密匙

```sh
#如果发现有存在 .ssh目录就不需要生成了,可以直接用
ls -al ~/

#如果不存在执行以下命令生成
ssh-keygen -t rsa -C "xxxx@email.com"
```
2. 使用 ls -al ~/ 就能看到生成的ssh密匙了,将对应的目录配置到jenkins上就行了

> 执行TestConfiguration测试ssh是否成功生效,如果不成功,请检查ssh配置是否有误(基本没有任何问题这一步)

![测试](image/test.jpg)

> 到此安装和配置ssh结束,接下来要具体配置我们的jenkins job

# Jenkins Job中使用Publish over SSH

1. 点开你的jenkins job 拉倒构建后操作这一栏,选择我们安装好的publish over ssh

![SSH配置](image/job1.png)

2. 配置说明

![SSH配置](image/set.png)

到这所有的配置都结束了,非常简单,这个<font color=red>Transfer Set</font>可以配置很多个,非常灵活.<font color=red>Exec command<font> 执行块可以在文件上传后的一些操作.

> <font color=red>注意:</font> Exec command这个里面所写的脚本一定要确保正常退出,不然jenkins会编译不过,可能引发超时,如果遇到该问题,请参考这篇文章:[Publish over SSH 超时问题](https://blog.csdn.net/u013066244/article/details/52788407)
