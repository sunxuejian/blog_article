
# 本章目标

1. 掌握springboot启动时事件传递机制
2. 基于springboot定制自己的事件

---

# Application Events and Listeners

---


除了一般的Spring Framework事件,比如ContextRefreshedEvent,SpringApplication还会发送一些额外的应用程序事件.

> 实际上在ApplicationContext创建之前会触发一些事件,所以不能再监听器上使用`@Bean`或者`@Componect`等注解,就算你加了也不会生效,但是你可以通过以下两种方式来添加监听器

> `SpringApplication.addListeners(...)` 或者`SpringApplicationBuilder.listeners(…​)`

例子:

```java
@Slf4j
@SpringBootApplication
public class BootDemoApplication {

    public static void main(String[] args) {
        SpringApplication
                .run(BootDemoApplication.class, args)
                .addApplicationListener(new MethodControl());
    }
}
```
<span id="jumpHelp" />

> 如果你希望spring自动注册这个监听器可以在你的`resources`目录下添加`META-INF/spring.factories` 文件,使用`org.springframework.context.ApplicationListener`作为key,你的类路径作为value

例子:
```java
org.springframework.context.ApplicationListener=\ com.example.project.MethodControl
```

---

# SpringBoot事件启动顺序

---

1. `ApplicationStartingEvent `: 除了注册监听器和初始化器的动作,他会在运行开始时,任何处理动作之前触发.

2. `ApplicationEnvironmentPreparedEvent` 在创建上下文之前触发,但是所有的环境变量,包括配置文件环境都已经准备好了.

3. `ApplicationPreparedEvent` 在上下文刷新之前,IOC初始化完毕,所有的bean定义结束后发送.

4. `ApplicationStartedEvent` 在刷新上下文之后但在调用任何应用程序和命令行运行程序之前发送

5. `ApplicationReadyEvent` 在调用任何应用程序和命令行运行程序之后发送。它表示应用程序已准备好为请求提供服务。

6. `ApplicationFailedEvent` 启动过程出现异常导致启动失败时触发


为了测试执行顺序,创建了以下几个类:

```java
@Slf4j
public class TestStartingEvent implements ApplicationListener<ApplicationStartingEvent> {

    @Override
    public void onApplicationEvent(ApplicationStartingEvent applicationStartingEvent) {
        log.info("starting event publish .....");
    }
}
```

```java
@Slf4j
public class TestEnvironmentPreparedEvent implements ApplicationListener<ApplicationEnvironmentPreparedEvent> {

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent applicationEnvironmentPreparedEvent) {
        log.info("environmentPrepared event publish .....");
    }
}
```

```java
@Slf4j
public class TestPreparedEvent implements ApplicationListener<ApplicationPreparedEvent> {

    @Override
    public void onApplicationEvent(ApplicationPreparedEvent applicationPreparedEvent) {
        log.info("prepared event publish .....");
    }
}
```

```java
@Slf4j
public class TestStartedEvent implements ApplicationListener<ApplicationStartedEvent> {

    @Override
    public void onApplicationEvent(ApplicationStartedEvent applicationStartedEvent) {
        log.info("started event publish .....");
    }
}
```

```java
@Slf4j
public class TestReadyEvent implements ApplicationListener<ApplicationReadyEvent> {

    @Override
    public void onApplicationEvent(ApplicationReadyEvent applicationReadyEvent) {
        log.info("ready event publish .....");
    }
}
```

> 我选择在`META-INF/spring.factories`文件中注册它们 [help](#jumpHelp)

![spring.factories](/image/boot-event/factories.png)


执行结果:

![spring.factories](/image/boot-event/log.png)

所有事件按顺序执行了,因为`ApplicationStartingEvent` 是在初始化时执行的,所以日志捕捉不到,`ApplicationFailedEvent` 这种情况我们就不演示了,通常很常见的错误,就是web服务多次启动,端口被占用就会在启动时触发这个event. 根据执行顺序,我们可以在这任意一个事件点做一些事情,例如上面我输出log.

---

# 在SpringBoot中定制自己的ApplicationEvent

---

<font color=red>目标:</font>
1. 将自己写的监听器注册到`SpringBoot`中
2. 自定义的事件在`ApplicationStartedEvent`后触发

创建事件:

```java
public class MyEvent extends ApplicationEvent {

    @Getter
    private String message;

    public MyEvent(Object source,String message) {
        super(source);
        this.message = message;
    }
}
```

创建监听器:

```java
@Slf4j
public class MyListener implements ApplicationListener<MyEvent> {

    @Override
    public void onApplicationEvent(MyEvent myEvent) {
      log.info("{}",myEvent.getMessage());
    }
}
```

将自定义监听器加入到`spring.factories`

```java
org.springframework.context.ApplicationListener=\
com.example.article.boot.demo.event.MyListener
```

在`ApplicationStartedEvent`事件中发送我们的事件

```java
@Slf4j
public class TestStartedEvent implements ApplicationListener<ApplicationStartedEvent> {

    @Override
    public void onApplicationEvent(ApplicationStartedEvent applicationStartedEvent) {
        log.info("started event publish .....");
        ConfigurableApplicationContext applicationContext = applicationStartedEvent.getApplicationContext();
        applicationContext.publishEvent(new MyEvent("","自定义事件触发啦!"));
    }
}
```

执行程序,控制台输出

![输出](/image/boot-event/my.png)

到此自定义事件监听器结束了,你学明白了吗?

# `@EventListener`注解的使用

>SpringBoot中有个`@EventListener`注解,这个和自己去实现`ApplicationListener`的作用是一模一样的
并且在我们业务中配置`@Async`来使用可以达到异步监听解耦业务逻辑的作用

自定义业务类
```java
@Data
public class Demo {
    private String message;
}
```

创建事件:
```java
public class DemoEvent extends ApplicationEvent {
    @Getter
    private Demo demo;

    public DemoEvent(Demo demo) {
        super(demo);
        this.demo = demo;
    }
}
```
事件发送类:

```java
@Component
public class DemoHandler {

    @Autowired
    private ApplicationContext applicationContext;

    public void publish(Demo demo){
        applicationContext.publishEvent(new DemoEvent(demo));
    }
}
```

异步监听处理事件:

```java
@Slf4j
@Service
public class DemoService {

    @Async
    @EventListener
    public void onEvent(DemoEvent demoEvent){
        Demo demo = demoEvent.getDemo();
        log.info("{}",demo.getMessage());
    }
}
```

启动类中触发事件发送:

```java
@SpringBootApplication
public class BootDemoApplication implements CommandLineRunner {

    @Autowired
    private DemoHandler demoHandler;

    public static void main(String[] args) {
        SpringApplication
                .run(BootDemoApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        Demo demo = new Demo();
        demo.setMessage("测试@EventListener");
        demoHandler.publish(demo);
    }
}
```

控制台输出:

![输出](/image/boot-event/event.jpg)

和预期结果一致,`@EventListener`等同于自己实现`ApplicationListener`,这样更方便了.到此整篇文章结束了,希望你能学到点有用的东西!
