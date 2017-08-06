# 关于数据安全问题的若干看法

https://github.com/CJMaxWell2013/EncryptionIntroduced.git

# 一、关于web或者app应用目前大致主要面临的安全问题

1、数据篡改（签名）

2、重放攻击 （时间戳）

3、非法参数提交 （校验参数）

4、数据偷窥（https）


# 二、原理分析和解决方案

服务器域名：http://www.jescard.com

端口号：resumeManager/getResumeInfo

假设基础参数列表：resumeId、detailType，其中

resumeId代表简历唯一标识

detailType代表简历页面的基本模块，0代表基本信息、1代表工作经历、2代表教育经历等等

基本示例：

``` objc
http://www.jescard.com/user/getUserInfo?resumeId=1&detailType=0
```
## 2.1数据篡改攻防

目前这种情况下有一个显著的安全隐患就是我们可以修改

``` objc
resumeId=2、3、4......
```

来遍历得到其余的所有简历信息，主要原因由于我们resumeId是真实的数据库的主键，主键一般都是正整数类型的数字，所以爬虫可以通过修改这个参数的值来进行爬取。

**解决办法1：避免主键来作为参数传递，这种方式多用于三方授权，三方授权通常都不会给用户直接
的数据库中的主键，而是通过一种不可逆的算法来生成一个token来给客户端使用，防止通过这种直接遍历主键id获取别的用户的信息。**

**解决办法2：采用签名的方法，前后端约定一个秘钥，假设privateKey=“123456”，用这个privateKey来给resumeId做签名(mySign)**
假设使用目前计算机主流使用的md5，则过程如下
前端通过resumeId+privateKey生成签名字符串mySign
``` objc
1 + 123456 ——经过md5——>  ASDFHGGGASDFHGGGASDFHGGGASDFHGGG
```

客户端发送请求为

``` objc
http://www.jescard.com/user/getUserInfo?resumeId=1&detailType=0&mySign=ASDFHGGGASDFHGGGASDFHGGGASDFHGGG
```
服务端在接受resumeId参数以后，以后也按照约定resumeId+privateKey来生成签名severSign，如果爬虫resumeId被修改了为了2，那么由于md5加密的唯一性

``` objc
2 + 123456 ——经过md5——>  EFGFHGGGASDFHGKKKKKGGGASDFHGGGKKK
```

则服务端通过生成的severSign和mySign的对比就可以发现不同，从而拒绝爬虫提取数据。

但是这个签名只是对了resumeId做了签名，并没有对detail签名，所以detail并未受到签名的保护

爬虫依然可以通过修改detail的值来爬取它已知简历下的简历各个模块的信息。

这也可以算是一个潜在的危险。

综述：签名防止数据篡改，保证了访问的合法性，建议

``` objc
将整个请求参数按照一定的排列顺序（ASCII）+ privateKey来签名
```

这样爬虫只要篡改了其中任何一段信息都会导致severSign和客户端传来的mySign不匹配，从而达到拒止作用。

## 2.2重放攻击

现在数据篡改解决了，但是爬虫着急了

``` objc
http://www.jescard.com/user/getUserInfo?resumeId=1&detailType=0&mySign=ASDFHGGGASDFHGGGASDFHGGGASDFHGGG
```
简历标识为resumeId=2、3、4…..不能被直接网络请求提取了。

但是，如果仔细观察就会发现，我每次都可拿这个签名验证过的url，可以重复的不断的调用获取该指定简历的信息即resumeId=1的那个简历。
**邪恶的爬虫者就可能会无限制、高频率的发起这个请求来让你服务器不断的响应该请求，从而达到拖累你服务器来搞破坏。**这个就是一个重放攻击的过程。

**解决办法1：ip或者deviceId（客户端的设备id）来限制访问频率，这个比较常见，在反爬虫中常见的手段，但是这种手段也是可以被破解的比如我使用多个代理ip缓存池就可以绕过你的ip防火墙达到目的。**

**解决办法2：添加时间戳timestamp字段，UNIX时间戳用的是世界协调时定义的是时间间隔，注意是时间间隔，避免了时区的问题！排除早期的32位存储争议，现在的多为double类型的64位存储。**详见

http://www.cnblogs.com/yangqi/archive/2010/07/16/1778675.html

客户端传递timestamp=1503333333.6669(单位秒)
服务端收到该时间戳的时候要获取自己机器上的unix时间戳
``` objc
severTimestamp=1503333334.4567
```
那么我们就可以对比这两个时间戳的差值，是否小于我们响应预定义超时的最大时间
``` objc
maxOvertime = 10.0
```

``` objc
绝对值(severTimestamp-timestamp) < maxOvertime
```

如果验证通过则放行，如果验证不通过则说明超过了时效。
即使是2.1中签名过的合法的访问，超过了有效时间间隔也是不被允许的。

通过前两个在http时代已经攻防基本上也就这样了。

成熟的算法参考

![snapshot](https://raw.githubusercontent.com/CJMaxWell2013/EncryptionIntroduced/master/Snapshots/mySign.png)



主要过程如上图所示，关于友盟消息系统的加密过程详细参考文档

http://dev.umeng.com/push/ios/api-doc#4_10

他的加密原理也是按照上面2.1和2.2分析的思路来的。


## 2.3非法提交参数
这个服务端开发的打交道比较多，比如SQL注入，XSS攻击很多…
我本人对SQL注入略有了解，简单来说，咱们在web表单中提交的参数最终转化成sql语句，而条件过滤基本是借助where后面的条件来实现的，
正常情况下如果where后面的条件为真就可以提取到对应的信息。

**一些游手好闲的黑客就设法通过提交表单的时候会注入一些扩大搜索范围的sql关键字，
来使得where后面的条件和你传入的意图条件取并集这样扩大你的搜索范围或者让where后的条件始终是真的**

这样一下子就获取了很多额外的大量数据。

注：我这个在自己的mysql下随便写的示例，表结构如下

![snapshot](https://raw.githubusercontent.com/CJMaxWell2013/EncryptionIntroduced/master/Snapshots/jobsTable.png)

假设我们要查询数据库中工作id值为1的工作信息
``` objc
http://localhost:8080/queryJob?jobid=1
```
sql示意代码如下：

``` objc
SELECT     job_id, job_describle, job_name, job_salary
FROM        jobs
WHERE     job_id = 1
```
所谓sql注入

``` objc
http://localhost:8080/queryJob?jobid=1or1=1
```
假设我们要获取jobs表中的所有数据，而且必须保留WHERE语句，那我们只要确保WHERE为TRUE就OK了，sql示意代码如下：

``` objc
SELECT     job_id, job_describle, job_name, job_salary
FROM        jobs
WHERE     job_id=1 OR 1=1
```
上面我们使得WHERE恒真，所以该查询中WHERE已经不起作用了，其查询结果等同于以下sql语句：

``` objc
SELECT    job_id, job_describle, job_name, job_salary
FROM       jobs
```

这样我们一下子就提取了jobs中的所有信息。

解决方案：对于这种方式的话我觉得后端那边对查询的条件做检查判断更为合适。

对于别的攻击，我也没有实验过不敢乱说，我也自己找了几篇博客看了看
http://netsecurity.51cto.com/art/201405/440233.htm
http://netsecurity.51cto.com/art/201408/448305_all.htm

大家有兴趣可以自己研究研究吧。

## 2.4数据偷窥

前面说的http协议传输层传输的数据基本上都是明文的，这个虽然可以在服务端签名验证或者验证合法性和时效性，
但是没办法保证用户的数据不被偷窥或者嗅探，如果通过一些抓包工具依然是可以抓到你的请求body部分等数据传输的数据信息，比如用户名密码等。

http阶段解决方案：对密码等信息进行加密传输,不能进行明文传递密码，
但是这个任然无法避免被抓包观察。如果你想试验，安卓和iOS都可以使用”青花瓷“软件抓包，教程如下：

http://www.jianshu.com/p/6b241a35813f

升级https解决方案：https出现就是在传输层对数据进行加密防止三方偷窥，一般都是采用权威机构授权根证书的形式来给web端和app使用，不过费用也比较昂贵。

iOS 10以后受信任证书存储区中包含三类证书，详细可参考这边官方链接

https://support.apple.com/zh-cn/HT207177

具体比较http和https的不同可参考

http://www.mahaixiang.cn/internet/1233.html

# 三、小结

以上是本人对数据安全的一些理解，如果您觉得过程中有任何不正确的地方，请在github上给我留言。

# License  
MIT
