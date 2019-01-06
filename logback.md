title: logback的快速应用
date: 2018-10-14 11:39:48
tags:
  - logback
  - 日志框架
---
logback是当下最受欢迎的log记录工具，高性能，功能全，文档全，作者是log4j的作者，
本文从logback常用的组件和功能点进行介绍，并提供了简单的例子参考，[logback官网](https://logback.qos.ch/)

<!-- more -->

## java中如何使用logback

>在pom中引入关键的两个包

```xml
 <!-- https://mvnrepository.com/artifact/ch.qos.logback/logback-core -->
        <dependency>
            <groupId>ch.qos.logback</groupId>
            <artifactId>logback-core</artifactId>
            <version>1.2.3</version>
        </dependency>

        <!-- https://mvnrepository.com/artifact/ch.qos.logback/logback-classic -->
        <dependency>
            <groupId>ch.qos.logback</groupId>
            <artifactId>logback-classic</artifactId>
            <version>1.2.3</version>
            <scope>test</scope>
        </dependency>
```
然后在resources目录下创建一个logback.xml就可以了,请参考[*logback.xml详细的例子*]这个章节


## 日志级别
> 推荐使用以下几种,级别从高到低排列

Level |描述
---|---
ERROR | 错误事件可能仍然允许应用程序继续运行
WARN | 指定具有潜在危害的情况
INFO | 指定能够突出在粗粒度级别的应用程序运行情况的信息的消息
DEBUG | 指定细粒度信息事件是最有用的应用程序调试
***
## Appender级别

> [What is an Appender?](https://logback.qos.ch/manual/appenders.html)

<center> Appender class dependency </center>

![appender](/image/appender.jpg)

### **<font color='red' size=5>ConsoleAppender</font>** (将日志输出到控制台)

> 将日志信息打印在控制台中

配置|类型|描述
---|---|---
encoder |[Encoder](https://logback.qos.ch/xref/ch/qos/logback/core/encoder/Encoder.html)| 日志输出格式
target|String|日志输出目标，可以是System.out或者System.err，默认是System.out
withJansi|boolean|默认是false，这个使用不到，好像是开启后输出的ANSI会有颜色，具体看官网介绍

**<font color='red'>sample</font>**:
```xml
<configuration>
  <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
    <!-- encoders are assigned the type
         ch.qos.logback.classic.encoder.PatternLayoutEncoder by default -->
    <encoder>
      <pattern>%-4relative [%thread] %-5level %logger{35} - %msg %n</pattern>
    </encoder>
  </appender>

  <root level="DEBUG">
    <appender-ref ref="STDOUT" />
  </root>
</configuration>
```
---

### **<font color='red' size=5>FileAppender</font>**(将日志输出到文件中)

> FileAppender OutputStreamAppender的子类,将日志输出到指定文件中。如果文件已经存在,根据配置属性来判断在末尾追加或者重新生成文件

配置|类型|描述
---|---|---
append|boolean|默认为true,会将日志追加到现有文件末尾
encoder |[Encoder](https://logback.qos.ch/xref/ch/qos/logback/core/encoder/Encoder.html)| 日志输出格式
file|String|文件名，可以带路径，如不过文件或目录不存在则会创建，例如: logs/info.log,该属性没有默认值
immediateFlush|boolean|一旦有日志产生立即刷新到文件，通过情况下把它设为false，以提高性能，因为会频繁的flush buffer;


**<font color='red'>sample</font>**:
```xml
<configuration>
  <!-- 使用时间戳作为文件名 -->
  <timestamp key="bySecond" datePattern="yyyyMMdd'T'HHmmss"/>

  <appender name="FILE" class="ch.qos.logback.core.FileAppender">
    <file>testFile-${bySecond}.log</file>
    <append>true</append>
    <!-- set immediateFlush to false for much higher logging throughput -->
    <immediateFlush>true</immediateFlush>
    <!-- encoders are assigned the type
         ch.qos.logback.classic.encoder.PatternLayoutEncoder by default -->
    <encoder>
      <pattern>%-4relative [%thread] %-5level %logger{35} - %msg%n</pattern>
    </encoder>
  </appender>

  <root level="DEBUG">
    <appender-ref ref="FILE" />
  </root>
</configuration>
```
---

### **<font color='red' size=5>RollingFileAppender</font>**(滚动式输出)

>[RollingFileAppender](https://logback.qos.ch/xref/ch/qos/logback/core/rolling/RollingFileAppender.html)继承于FileAppender, 按照一些特定策略生成滚动文件，例如与TimeBasedRollingPolicy策略搭配时，当文件到达指定时间，会重新生成一个新的文件，关于策略，后面章节会有具体详细介绍。

配置|类型|描述
---|---|---
append|boolean|看FileAppender配置
encoder |[Encoder](https://logback.qos.ch/xref/ch/qos/logback/core/encoder/Encoder.html)| 看FileAppender配置
file|String|看FileAppender配置
rollingPolicy|RollingPolicy|日志滚动策略：配置这个选项会让日志文件按照指定策略进行滚动
triggeringPolicy|TriggeringPolicy|触发滚动策略：通常搭配rollingPolicy一起使用，用于设置滚动的触发条件

**<font color='red'>sample</font>**:

```xml
<appender name="errorAppender" class="ch.qos.logback.core.RollingFileAppender">
    <file>logs/error.log</file>
    <!-- 设置滚动策略 TimeBasedRollingPolicy 按日期滚动 -->
    <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
        <!--设置日志命名模式-->
        <fileNamePattern>errorFile.%d{yyyy-MM-dd}.log</fileNamePattern>
        <!--最多保留30天log-->
        <maxHistory>30</maxHistory>
    </rollingPolicy>
    <!-- 超过150MB时，立即触发滚动策略，生成新的文件 -->
    <triggeringPolicy class="ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy">
        <maxFileSize>150</maxFileSize>
    </triggeringPolicy>
    <encoder>
        <pattern>%d [%p] %-5level %logger - %msg%newline</pattern>
    </encoder>
</appender>
```

---

## 日志文件策略 *Policy(常用)

### **<font color='red' size=5>TimeBasedRollingPolicy</font>**(按日期滚动策略)

> [TimeBasedRollingPolicy](https://logback.qos.ch/xref/ch/qos/logback/core/rolling/TimeBasedRollingPolicy.html) 可能是logback最受欢迎的滚动策略，基于时间的滚动，可以是一天也可以是一个月，这个较为常用，通常我们可以设置一天生成一个新的文件，很好归纳，统计

配置|类型|描述
---|---|---
fileNamePattern|String|log文件命名规则，通常使用%d来按天或按月输出，例如errorFile.%d{yyyy-MM-dd}.log，生成出来的文件类似于errorFile.2018-10-09.log，带上日期后这样每天生成的文件就不会名字重复了，这个还支持选择时区，例如%d{yyyy-MM-dd,UTC}
maxHistory|int|日志保留天数，超过该天数的历史日志文件将会被logback<font color='red'>异步删除</font>
totalSizeCap|int|归档文件的总大小，优先应用maxHistory的策略。
cleanHistoryOnStart|boolean|默认为false,触发归档文件立即删除的动作。

> *滚动输出支持自动压缩*,文件名以.gz或者.zip结尾即可，例如：/wombat/foo.%d.gz

**<font color='red'>sample</font>**:
```xml
<configuration>
  <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>logFile.log</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
      <!-- daily rollover -->
      <fileNamePattern>logFile.%d{yyyy-MM-dd}.log</fileNamePattern>

      <!-- keep 30 days' worth of history capped at 3GB total size -->
      <maxHistory>30</maxHistory>
      <totalSizeCap>3GB</totalSizeCap>

    </rollingPolicy>

    <encoder>
      <pattern>%-4relative [%thread] %-5level %logger{35} - %msg%n</pattern>
    </encoder>
  </appender>

  <root level="DEBUG">
    <appender-ref ref="FILE" />
  </root>
</configuration>
```

---

### **<font color='red' size=5>SizeAndTimeBasedRollingPolicy</font>**(按大小和时间滚动策略)

> 这个应该是最常用的吧，按照指定时间和文件大小的策略来滚动日志。废话不多说看下面的例子

```xml
<configuration>
  <appender name="ROLLING" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>mylog.txt</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
      <!-- rollover daily -->
      <fileNamePattern>mylog-%d{yyyy-MM-dd}.%i.txt</fileNamePattern>
       <!-- each file should be at most 100MB, keep 60 days worth of history, but at most 20GB -->
       <maxFileSize>100MB</maxFileSize>    
       <maxHistory>60</maxHistory>
       <totalSizeCap>20GB</totalSizeCap>
    </rollingPolicy>
    <encoder>
      <pattern>%msg%n</pattern>
    </encoder>
  </appender>


  <root level="DEBUG">
    <appender-ref ref="ROLLING" />
  </root>

</configuration>
```

> 请注意除“％d”之外的“％i”转换标记。 ％i和％d令牌都是强制性的。 每当当前日志文件在当前时间段结束之前达到maxFileSize时，它将以增加的索引存档，从0开始

---

### **<font color='red' size=5>FixedWindowRollingPolicy</font>**(以固定的算法策略生成滚动文件 不常用)

>这个策略不常用，咱就不多bb了,属性和其他滚动策略是一样的，通常文件命名规范是这样的：tests.%i.log，当到达条件触发滚动时会生成文件test1.log,test2.log,test3.log ...

---

### **<font color='red' size=5>SizeBasedTriggeringPolicy</font>**(根据大小触发滚动的策略)

>这个<triggeringPolicy/>标签里的配置，用来触发滚动时间的，例如文件大小到了指定值，就是触发滚动

**<font color='red'>sample</font>**:

```xml
<configuration>
  <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>test.log</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.FixedWindowRollingPolicy">
      <fileNamePattern>test.%i.log.zip</fileNamePattern>
      <minIndex>1</minIndex>
      <maxIndex>3</maxIndex>
    </rollingPolicy>

    <triggeringPolicy class="ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy">
      <maxFileSize>5MB</maxFileSize>
    </triggeringPolicy>
    <encoder>
      <pattern>%-4relative [%thread] %-5level %logger{35} - %msg%n</pattern>
    </encoder>
  </appender>

  <root level="DEBUG">
    <appender-ref ref="FILE" />
  </root>
</configuration>
```

---

## fileNamePatten的一些规则(例子，按年，月，日，天，时，分，秒滚动)

例子|描述
---|---|
/wombat/foo.%d|按天滚动，格式 年-月-日，都生成在一个文件夹中
/wombat/%d{yyyy/MM}/foo.txt|按月滚动，每个月生成一个相同的文件，在不同的月份文件夹中，例如first: /wombat/2018/09/foo.txt，next: /wombat/2018/10/foo.txt
/wombat/foo.%d{yyyy-ww}.log|每周生成一次，每周的第一天开始重新生成
/wombat/foo%d{yyyy-MM-dd_HH}.log|每小时生成一次
/wombat/foo%d{yyyy-MM-dd_HH-mm}.log|每分钟生成一次
/wombat/foo%d{yyyy-MM-dd_HH-mm, UTC}.log|按指定时区每分钟生成一次
/foo/%d{yyyy-MM,aux}/%d.log|每天生成一次，按照年和月区分，例如，/foo/2018-09/中存在一个月的log，log名是每天的日期

---

## encoder规则(日志输出格式)

格式|描述
---|---|
%m|输出代码中指定的消息
%p|输出优先级，即DEBUG，INFO，WARN，ERROR，FATAL
%r|输出自应用启动到输出该log信息耗费的毫秒数
%c|输出所属的类目，通常就是所在类的全名
%t|输出产生该日志事件的线程名
%n|输出一个回车换行符，Windows平台为“/r/n”，Unix平台为“/n”
%d|输出日志时间点的日期或时间，默认格式为ISO8601，也可以在其后指定格式，比如：%d{yyy MMM dd HH:mm:ss , SSS}，输出类似：2002年10月18日 22:10：28，921
%l|输出日志事件的发生位置，包括类目名、发生的线程，以及在代码中的行数。举例：Testlog4.main(TestLog4.java: 10 )

### 配置：

```xml
<configuration>
    　　　　　　　　　　
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <!-- 日期 [线程] [class类]-[日志级别] log内容 回车符号 -->
            <pattern>%d{yyyy-MM-dd HH:mm:ss,SSS} [%t] [%c]-[%p] %m%n</pattern>　　　　　　　　　
        </encoder>
        　　　　　　　　　　
    </appender>

    <!-- 输出INFO及以上的日志 -->　　　　　　
    <root level="INFO">
        <!-- 让自定义的appender生效 -->　　　　　　　　　　　
        <appender-ref ref="STDOUT"/>　　　　　　　　　　
    </root>
    　　　　　　　　
</configuration>

```

---

### 控制台输出：

```
2018-10-09 14:27:55 [main] [org.springframework.web.servlet.handler.SimpleUrlHandlerMapping]-[INFO] Mapped URL path [/**] onto handler of type [class org.springframework.web.servlet.resource.ResourceHttpRequestHandler]
2018-10-09 14:27:55 [main] [org.springframework.jmx.export.annotation.AnnotationMBeanExporter]-[INFO] Registering beans for JMX exposure on startup
2018-10-09 14:27:55 [main] [org.apache.coyote.http11.Http11NioProtocol]-[INFO] Starting ProtocolHandler ["http-nio-6677"]
2018-10-09 14:27:55 [main] [org.apache.tomcat.util.net.NioSelectorPool]-[INFO] Using a shared selector for servlet write/read
2018-10-09 14:27:55 [main] [org.springframework.boot.web.embedded.tomcat.TomcatWebServer]-[INFO] Tomcat started on port(s): 6677 (http) with context path ''
2018-10-09 14:27:55 [main] [com.xj.plugins.Springboot2AnalyzeApplication]-[INFO] Started Springboot2AnalyzeApplication in 2.014 seconds (JVM running for 3.949)

```

> 在控制输出的log还可以进行颜色设置，更方便查看log，区分log级别

---


## 控制台输出的log配置颜色


格式|描述
---|---|
%black|黑色
%red|红色
%green|绿色
%yellow|黄色
%blue|蓝色
%magenta|品红
%cyan|青色
%white|白色
%gray|灰色
%highlight|高亮色
%bold|更鲜艳色颜色，强化以上所有的颜色，例如%boldRed,%boldBlack

### 例子：

```xml
<configuration>
    　　　　　　　　　　
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <!-- 日期 [线程] [class类]-[日志级别] log内容 回车符号 -->
            <pattern>%blue(%d{yyyy-MM-dd HH:mm:ss,SSS}) [%cyan(%t)] [%yellow(%c)]-[%highlight(%p)] %m%n</pattern>　　　　　　　　　
        </encoder>
        　　　　　　　　　　
    </appender>

    <!-- 输出INFO及以上的日志 -->　　　　　　
    <root level="INFO">
        <!-- 让自定义的appender生效 -->　　　　　　　　　　　
        <appender-ref ref="STDOUT"/>　　　　　　　　　　
    </root>
    　　　　　　　　
</configuration>
```


> 配置过后的控制台输出

![增加色彩输出](/image/log.jpg)

---

## 完整的logback.xml文件

> 该样例文件主要是配置了比较通用的三种模式
> 1. 定向输出，控制台输出，全量的日志文件
> 2. 将error日志输出到error.log,warn日志输出到warn.log,将全量日志输出到main.log文件中

```xml
<configuration>

    <property name="LOG_HOME" value="logs"/>

    <!-- 输出到控制台 -->　　
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <!-- 日期 [线程] [class类]-[日志级别] log内容 回车符号 -->
            <pattern>%blue(%d{yyyy-MM-dd HH:mm:ss.SSS}) %cyan(%t) %yellow(%c)-%highlight(%p) %m%n</pattern>　　　　　　　　　
        </encoder>
    </appender>

    <!-- 所有信息输出到main.log 按天和大小滚动 -->
    <appender name="MAIN" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] [%c]-[%p] %m%n</pattern>
        </encoder>

        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <!-- rollover daily -->
            <fileNamePattern>${LOG_HOME}/main-%d{yyyy-MM-dd}.%i.txt</fileNamePattern>
            <!-- 文件最大30MB,保留60天，总大小20GB -->
            <maxFileSize>30MB</maxFileSize>
            <maxHistory>60</maxHistory>
            <totalSizeCap>20GB</totalSizeCap>
        </rollingPolicy>
    </appender>

    <appender name="ERROR" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] [%c]-[%p] %m%n</pattern>
        </encoder>

        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <!-- rollover daily -->
            <fileNamePattern>${LOG_HOME}/error-%d{yyyy-MM-dd}.%i.txt</fileNamePattern>
            <!-- 文件最大30MB,保留60天，总大小20GB -->
            <maxFileSize>30MB</maxFileSize>
            <maxHistory>60</maxHistory>
            <totalSizeCap>20GB</totalSizeCap>
        </rollingPolicy>

        <!-- 过滤器,只写入error级别log -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>ERROR</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>

    </appender>

    <appender name="WARN" class="ch.qos.logback.core.rolling.RollingFileAppender">

        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <!-- rollover daily -->
            <fileNamePattern>${LOG_HOME}/warn-%d{yyyy-MM-dd}.%i.txt</fileNamePattern>
            <!-- 文件最大30MB,保留60天，总大小20GB -->
            <maxFileSize>30MB</maxFileSize>
            <maxHistory>60</maxHistory>
            <totalSizeCap>20GB</totalSizeCap>
        </rollingPolicy>


        <!-- 过滤器,只写入warn级别，log -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>WARN</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>

        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] [%c]-[%p] %m%n</pattern>
        </encoder>


    </appender>


    <!-- 输出INFO及以上的日志 -->　　　　　　
    <root level="INFO">
        <!-- 让自定义的appender生效 -->　　　　　　　　　　　
        <appender-ref ref="STDOUT"/>　　

        <appender-ref ref="MAIN"/>　　　　　　　　　　

        <appender-ref ref="ERROR"/>　　　　　　　　　　

        <appender-ref ref="WARN"/>　　　　　　　　　　
    </root>
    　　　　　　　　
</configuration>
```

---

## 关于日志定向输出和读取环境变量的问题

### 定向输出

> logback.xml中如何需要将某中日志输出到文件中可以使用过滤器,类似于以下这个例子

<font color=red> xml配置过滤器,例如将error日志输出到error.log中

 ```xml
     <appender name="ERROR" class="ch.qos.logback.core.rolling.RollingFileAppender">
            <encoder>
                <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] [%c]-[%p] %m%n</pattern>
            </encoder>

            <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
                <!-- rollover daily -->
                <fileNamePattern>${LOG_HOME}/error-%d{yyyy-MM-dd}.%i.txt</fileNamePattern>
                <!-- 文件最大30MB,保留60天，总大小20GB -->
                <maxFileSize>30MB</maxFileSize>
                <maxHistory>60</maxHistory>
                <totalSizeCap>20GB</totalSizeCap>
            </rollingPolicy>

            <!-- 过滤器,只写入error级别log -->
            <filter class="ch.qos.logback.classic.filter.LevelFilter">
                <level>ERROR</level>
                <onMatch>ACCEPT</onMatch>
                <onMismatch>DENY</onMismatch>
            </filter>

        </appender>
```

> 如果有需要特殊log需要定向输出的话可以重写 Filter<ILoggingEvent>方法

 ```java
public class MyLogFilter extends Filter<ILoggingEvent> {   
        @Override   

        public FilterReply decide(ILoggingEvent event) {
                   
            if(event.getMessage() != null
                    && (event.getMessage().startsWith("test")
                    || event.getMessage().startsWith("demo"))) {
                return FilterReply.ACCEPT;
            } else {
                return FilterReply.DENY;
            }       
        }
    }
```

> 然后将filter加入到你的appender中

```xml
            <!-- 过滤器,写入test和demo开头的日志 -->
            <filter class="xx.xxx.xxxx.MyLogFilter" />
```

### logback.xml读取环境变量
> logback.xml支持两种读取方式,从系统环境中读取，从spring配置文件中读取

> 读取系统环境变量 通过${envName}方式获取

```xml
<!-- 从系统环境变量读取日志输出目录 -->
<property name="LOG_HOME" value="${log.dir}"/>
```

> 读取spring配置文件的方式

```xml
<!-- 从context中读取所以不需要使用${}获取 -->
<springProperty scope="context" name="LOG_HOME" source="logback.dir"/>
```

---

### 关闭某个类中某个级别的log输出

在logback.xml中加入以下配置
```xml
<logger name="xx.xx.class" level="OFF" />
```
