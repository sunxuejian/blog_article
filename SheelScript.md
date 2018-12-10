# 常用的shee脚本语法

### 比较符

#### 数字比较

| 关键字 | 例子 | 说明 |
| ----- | ----- | ----- |
| `-eq` | x `-eq` y | 检查x是否等于y |
| `-ge` | x `-ge` y | 检查x是否大于等于y |
| `-gt` | x `-gt` y | 检查x是否大于y |
| `-le` | x `-le` y | 检查x是否小于等于y |
| `-lt` | x `-lt` y | 检查x是否小于y |
| `-ne` | x `-ne` y | 检查x是否不等于y |

#### 字符串比较

```
字符串大小比较底层使用ASII
```

| 关键字 | 例子 | 说明 |
| :-----: | :-----: | :----- |
| `=` | string_x `=` string_y | 检查string_x是否和string_y相同 |
| `!=` | string_x `!=` string_y | 检查string_x是否和string_y不同 |
| `<` | string_x `<` string_y | 检查string_x是否比string_x小 |
| `>` | string_x `>` string_y | 检查string_x是否比string_y大 |
| `-n` | string_x `-n` string_y | 检查string_x的长度是否非0 |
| `-z` | string_x `-z` string_y | 检查string_x的长度是否为0 |

#### 文件比较

| 关键字 | 例子 | 说明 |
| :-----: | :-----: | :----- |
| `-d` | `-d` file | 检查file是否存在并且是一个目录 |
| `-e` | `-e` file | 检查file是否存在 |
| `-f` | `-f` file | 检查file是否存在并且是一个文件 |
| `-r` | `-r` file | 检查file是否存在并且可读 |
| `-s` | `-s` file | 检查file是否存在并且非空 |
| `-w` | `-w` file | 检查file是否存在并且可写 |
| `-x` | `-x` file | 检查file是否存在并且可被执行 |
| `-O` | `-O` file | 检查file是否存在并且属于当前用户所有 |
| `-G` | `-G` file | 检查file是否存在并且默认组与当前用户相同 |
| `-nt` | file1 `-nt` file2 | file2检查file1是否比file2新 |
| `-ot` | file1 `-ot` file2 | file2	检查file1是否比file2旧 |

---

### 在执行./xx.sh的时候传递一个或多个参数
```
在linux中执行任何操作,每一段指令都会被解析成一个占位符
如 `echo "a"`,echo被解析为$0, a被解析为$1,所以如果想要在运行某个脚本的时候将参数传递进去就可以做到这样
`./x.sh a b c`, 对应的我们在x.sh中分别使用$1,$2,$3,就可以获得a,b,c的值了.
```

---

### 流程控制语法

```
流程控制语法在任何一种语言中都不可或缺,在shell中有个坑与要注意,在判断条件表达式内部 [ condition ] 中括号 前后必须加空格否则会报语法错误!
```

#### IF语句

语法:
```shell
if [[ condition ]]; then
  #statements
elif [[ condition ]]; then
  #statements
else
  #statements
fi # if语句结束位置
```
例子:
> vim if.sh
```shell
if [[ "$1" = "a" ]]; then
  echo "$1 = a"
elif [[ "$1" = "b" ]]; then
  echo "$1 = b"
else
  echo $1
fi # if语句结束位置
```

执行结果:
> ./if.sh a
```shell
a = a
```

#### CASE IN语句(类似java中`swatch case`语法)
语法:
```shell
case word in
  pattern )
    ;;
  * )
esac
```

例子:
> vim casein.sh
```shell
case "$1" in
  'stop' )
    echo "stop ..."
    ;;
  'start' )
  echo "start ..."
  ;;
  * )
  echo "Usage: $0 { start | stop }"
esac
```

执行结果:

> ./casein.sh
```
Usage: ./casein.sh { start | stop }
```
>> ./casein.sh start
```
start ...
```
>>> ./casein.sh stop
```
stop ...
```

***

### 循环函数

#### WHILE 函数

语法
```shell
while [[ condition ]]; do
  #statements
done
```

例子:
> vim while.sh
```shell
num=10
while [ $num -gt 0 ]; do
printf "current num %d \n" $num
num=$(expr $num - 1)
done
```

执行结果:
> ./while.sh
```shell
current num 10
current num 9
current num 8
current num 7
current num 6
current num 5
current num 4
current num 3
current num 2
current num 1
```

####  FOR 函数
语法1:

```shell
for (( i = 0; i < 3; i++ )); do
  #statements
done
```

语法2:
```shell
for x in (); do
  #statements
done
```

例子:
> vim for.sh
```shell
for var in $(seq 1 5); do
  printf "$var "
done
```

执行结果:
> ./for.sh
```
1 2 3 4 5
```
