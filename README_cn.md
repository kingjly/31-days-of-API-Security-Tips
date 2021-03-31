# 31天API安全挑战Tips

### This challenge is Inon Shkedy's 31 days API Security Tips

#### -API TIP: 1/31-

*老版本的API往往比较脆弱，它们缺乏安全机制。
利用REST API的可预测性来寻找老版本。
看到类似 `api/v3/login`的请求? 检查 `api/v1/login` 这样的请求是否也存在. 它可能更容易存在漏洞.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP: 2/31-

*千万不要认为只有一种方法可以对API进行身份认证!
当代应用程序有很多API入口进行身份认证，例如: `/api/mobile/login` | `/api/v3/login` | `/api/magic_link`等等.
找到所有这些API并测试其身份认证问题.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:3/31-

*还记得在5-10年前，SQL注入曾经是极其常见的，几乎可以用来攻破所有的公司吗?
BOLA (IDOR) 是API安全的一种新的流行趋势.
作为一名渗透测试人员, 如果你懂得如何利用它, 那么会所嫩模在向你招手.*

> 通过以下链接进一步了解BOLA : [https://medium.com/@inonst/a-deep-dive-on-the-most-critical-api-vulnerability-bola-1342224ec3f2](https://medium.com/@inonst/a-deep-dive-on-the-most-critical-api-vulnerability-bola-1342224ec3f2)
--------------------------------------------------------------------------------------------------------------------------

#### -API TIP: 4/31-

当测试Ruby on Rails应用的时候发现HTTP参数中包含了一段URL？
开发者有时会使用 "Kernel#open"函数来访问URL，这意味着已经可以收工了。
只需发送一个管道符（|）作为第一个字符，然后发送一个shell命令(特定的命令注入)

> 通过以下链接进一步了解open函数: [https://apidock.com/ruby/Kernel/open](https://apidock.com/ruby/Kernel/open)
--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:5/31-

*发现了SSRF? 可以用它来干这些事:*
* 内部端口扫描
* 借助云服务(例如 169.254.169.254)
* 使用 http://webhook.site 来反查IP地址和HTTP库
* 下载非常大的文件 (7层DoS)
* 反射型SSRF? 揭露本地管理控制台

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP: 6/31-

*批量作业是真实存在的.
现代框架鼓励开发人员在不了解安全影响的情况下使用批量作业.
在利用过程中, 不用猜测对象的属性名, 只要简单找到一个能够返回所有属性名的GET入口就可以了.*
![Infographic](https://pbs.twimg.com/media/ENpsW25XYAAjEJE?format=jpg)

--------------------------------------------------------------------------------------------------------------------------

#### - API TIP: 7/31 -

*一家公司向开发者公开了一个API?
在移动端和Web端所使用的API是不同的. 一定要分开测试它们.
不要以为它们实施了同等的安全机制.*

--------------------------------------------------------------------------------------------------------------------------

#### - API TIP: 8/31 -

对REST API进行渗透测试? 可以尝试API是不是同样支持SOAP.
将content-type更改为"application/xml", 在请求体中增加一段简单的XML, 然后观察API是如何处理这个请求的.

> 有时认证是在不同的组件中完成的，该组件在REST和SOAP APIs之间共享，意味着SOAP API可能支持JWT

> 如果API返回堆栈跟踪信息, 那它可能就存在漏洞**

--------------------------------------------------------------------------------------------------------------------------

#### - API TIP: 9/31 -

*对API进行渗透测试?  尝试发现BOLA (IDOR)漏洞? HTTP body/headers中的ID往往比URL中的ID更容易受到攻击。尽量先关注它们.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP: 10/31-

*利用 BFLA (Broken Function Level Authorization)?
利用REST的可预测性来寻找管理API入口!
例如: 你发现了如下API请求 `GET /api/v1/users/<id>`
尝试改成`DELETE / POST 来删除或创建用户.`*

--------------------------------------------------------------------------------------------------------------------------

#### - API TIP: 11/31 - 

*API使用了Authorization 请求头? 忘掉CSRF吧!
如果认证机制不支持cookies, 该API在设计上对CSRF进行了保护.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP : 12/31-

*测试BOLA (IDOR)?
即使ID是GUID或非数字，也要尝试发送一个数字值.
例如: `/?user_id=111` 而不是 `user_id=inon@traceable.ai`
有时候身份认证机制同时支持以上两种形式，使用数字更容易进行暴力破解.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP: 13/31-

*Use Mass Assignment to bypass security mechanisms.
E.g., "enter password" mechanism:
- `POST /api/reset_pass` requires old password.
- `PUT /api/update_user` is vulnerable to MA == can be used to update pass without sending the old one (For CSRF)*

--------------------------------------------------------------------------------------------------------------------------

#### - API TIP: 14/31 -

*在做API渗透的时候卡壳了? 扩大你的攻击面! 使用http://Virustotal.com 和 http://Censys.io 查找子域名/同级域名. 
这些域名中的一些域名可能会暴露相同的API的的不同配置或版本.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:15/31-

*静态资源==图片,视频,..
Web服务(IIS, Apache)在获得身份授权后对静态资源的处理方式是有区别的.
即使开发者实现了合适的授权，你也很有可能访问其他用户的静态资源.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP: 16/31-

即使你使用其他网络代理，也要在后台使用Burp. 
@PortSwigger的这帮人在帮助你管理自己的渗透测试方面做得非常好.
使用 "树状视图"（免费版）功能来查看你访问过的所有API端点.

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:17/31-

*移动端证书绑定?
在你开始逆向工程和加固APP之前，请检查iOS和Android客户端以及它们的旧版本.
很有可能，其中的某个版本没有启用证书绑定。这能节省时间.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP: 18/31-

*公司和开发者倾向于将更多的资源（包括安全）投入到主要的API中.
尽可能最小众的功能，没人用的功能，来发现有趣的漏洞.
`POST /api/profile/upload_christmas_voice_greeting`*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:19/31-

*你觉得哪些功能更有可能存在漏洞?*
*我通常从以下几点着手:*
* 组织的用户管理 
* 导出为CSV/HTML/PDF 
* 自定义仪表盘视图 
* 子用户创建和管理 
* 对象共享 (照片, 帖子，等等)

--------------------------------------------------------------------------------------------------------------------------

#### - API TIP:20/31- 

*测试身份认证API?
如果你在生产环境中进行测试，很有可能身份认证API存在防暴破功能.
无论如何，DevOps工程师倾向于在非生产环境中禁用频率限制。不要忘记测试它们 :)*


> 这个问题的一个很好的例子是: Facebook Breach (Found by @sehacure) [http://www.anandpraka.sh/2016/03/how-i-could-have-hacked-your-facebook.html](http://www.anandpraka.sh/2016/03/how-i-could-have-hacked-your-facebook.html)
--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:21/30-

*Got stuck during an API pentest? Expand the attack surface! 
Use http://archive.com, find old versions of the web-app and explore new API endpoints. 
Can't use the client? scan the .js files for URLs. Some of them are API endpoints.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:22/31-

*APIs tend to leak PII by design.
BE engineers return raw JSON objects and rely on FE engineers to filter out sensitive data.
Found a sensitive resource (e.g, `receipt`)? Find all the EPs that return it: `/download_receipt`,`/export_receipt`, etc..*

> Some of the endpoints might leak excessive data that should not be accessible by the user.

> This is an example for OWASP Top 10 For APIs - #3 - Excessive Data Exposure
--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:23/31-

*Found a way to download arbitrary files from a web server? 
Shift the test from black-box to white-box.
Download the source code of the app (DLL files: use IL-spy; Compiled Java - use Luyten)
Read the code and find new issues!*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:24/31-

*Got stuck during an API pentest? Expand your attack surface!
Remember: developers often disable security mechanisms in non-production environments (qa/staging/etc); 
Leverage this fact to bypass AuthZ, AuthN, rate limiting & input validation.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:25/31-

*Found an "export to PDF" feature? 
There's a good chance the developers use an external library to convert HTML --> PDF behind the scenes.
Try to inject HTML elements and cause "Export Injection".*

> Learn more about Export Injection: [https://medium.com/@inonst/export-injection-2eebc4f17117](https://medium.com/@inonst/export-injection-2eebc4f17117) 
--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:26/31-

*Looking for BOLA (IDOR) in APIs? got 401/403 errors?
AuthZ bypass tricks:*
* Wrap ID with an array` {“id”:111}` --> `{“id”:[111]}`
* JSON wrap `{“id”:111}` --> `{“id”:{“id”:111}}`
* Send ID twice `URL?id=<LEGIT>&id=<VICTIM>`
* Send wildcard `{"user_id":"*"}`
 
> In some cases, the AuthZ mechanism expects a plain string (an ID in this case), and if it receives a JSON instead it won't perform the AuthZ checks. Then, when the input goes to the data fetching component, it might be okay with a JSON instead of string(e.g: it flattens the JSON)
--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:27/31-

*BE Servers no longer responsible for protecting against XSS.
APIs don't return HTML, but JSON instead.
If API returns XSS payload? - 
E.g: `{"name":"In<script>alert(21)</script>on}`
That's fine! The protection always needs to be on the client side*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:28/31-

*Pentest for .NET apps? Found a param containing file path/name? Developers sometimes use "Path.Combine(path_1,path_2)" to create full path. Path.Combine has weird behavior: if param#2 is absolute path, then param#1 is ignored.*
##### Leverage it to control the path

> Learn more: [https://www.praetorian.com/blog/pathcombine-security-issues-in-aspnet-applications](https://www.praetorian.com/blog/pathcombine-security-issues-in-aspnet-applications)
--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:29/30-

*APIs expose the underlying implementation of the app.
Pentesters should leverage this fact to better understand users, roles, resources & correlations between them and find cool vulnerabilities & exploits.
Always be curious about the API responses.*

--------------------------------------------------------------------------------------------------------------------------

#### -API TIP:30/31-

*Got stuck during an API pentest? Expand your attack surface! 
If the API has mobile clients, download old versions of the APK file to explore old/legacy functionality and discover new API endpoints.*

> Remember: companies don’t always implement security mechanisms from day one && DevOps engineers don’t often deprecate old APIs. Leverage these facts to find shadow API endpoints that don’t implement security mechanism (authorization, input filtering & rate limiting)

> Download old APK versions of android apps: [https://apkpure.com](https://apkpure.com)
--------------------------------------------------------------------------------------------------------------------------

#### -API TIP: 31/31-

*Found a `limit` / `page` param? (e.g: `/api/news?limit=100`) It might be vulnerable to Layer 7 DoS. Try to send a long value (e.g: `limit=999999999`) and see what happens :)*

--------------------------------------------------------------------------------------------------------------------------

## Source

#### All of this information is taken from twitter of Inon Shkedy
##### Links: 
* [Inon Shkedy](https://twitter.com/inonshkedy)
* [Traceableai](https://twitter.com/traceableai/)
* [OWASP API PROJECT](https://github.com/OWASP/API-Security)

