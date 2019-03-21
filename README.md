问题记录：

1.在加入黑名单后启用图片验证，没有把静态页面比如图片，js等排除，导致输入验证码时跳到静态图片页面，经常遇到跳到favicon.ico页面。
2.需要保护的连接是正则匹配，需要注意；如果是保护登录页面，建议在config中配置 urlMatchMode = "requestUri",然后在保护url中录入完成的登录页面。

function Guard:captchaAction(ip,reqUri)
        -- 访问验证码超过一定次数使用iptables封锁
        if _Conf.captchaToIptablesIsOn then
                local captchaReqKey = ip.."captchareqkey" --定义captcha req key
                local reqTimes = _Conf.dict:get(captchaReqKey) --获取此ip验证码请求的次数
                --增加一次请求记录
                if reqTimes then
                        _Conf.dict:incr(captchaReqKey, 1)
                else
                        _Conf.dict:set(captchaReqKey, 1, _Conf.captchaToIptables.amongTime)
                        reqTimes = 0
                end

                local newReqTimes  = reqTimes + 1
                self:debug("[captchaToIptables] newReqTimes "..newReqTimes,ip,reqUri)
                --判断请求数是否大于阀值,大于则iptables封锁
                if newReqTimes > _Conf.captchaToIptables.maxReqs then --判断是否请求数大于阀值
                        self:debug("[captchaToIptables] ip "..ip.. " request exceed ".._Conf.captchaToIptables.maxReqs,ip,reqUri)
                        ngx.thread.spawn(Guard.addToIptables,Guard,ip) -- iptables封锁
                        self:log("[captchaToIptables] IP "..ip.." visit "..newReqTimes.." times,iptables block it.")
                end

        end
        local reqUri = "/MOBAN/index.php"   --定义输入验证码后跳转的页面url,此处有bug，如果不定义，有可能会返回静态图片页面。
        ngx.header.content_type = "text/html"
        ngx.header['Set-Cookie'] = table.concat({"preurl=",reqUri,"; path=/"})
        ngx.print(_Conf.captchaPage)
        ngx.exit(200)
end


# http-guard

HttpGuard是基于openresty,以lua脚本语言开发的防cc攻击软件。而openresty是集成了高性能web服务器Nginx，以及一系列的Nginx模块，这其中最重要的，也是我们主要用到的nginx lua模块。HttpGuard基于nginx lua开发，继承了nginx高并发，高性能的特点，可以以非常小的性能损耗来防范大规模的cc攻击。

下面介绍HttpGuard防cc的一些特性：

1. 限制单个IP或者UA在一定时间内的请求次数
2. 向访客发送302转向响应头来识别恶意用户,并阻止其再次访问
3. 向访客发送带有跳转功能的js代码来识别恶意用户，并阻止其再次访问
4. 向访客发送cookie来识别恶意用户,并阻止其再次访问
5. 支持向访客发送带有验证码的页面，来进一步识别，以免误伤
6. 支持直接断开恶意访客的连接
7. 支持结合iptables来阻止恶意访客再次连接
8. 支持白名单/黑名单功能
9. 支持根据统计特定端口的连接数来自动开启或关闭防cc模式

## 部署HttpGuard
### 安装openresty或者nginx lua

按照openresty官网手动安装[http://openresty.com](http://openresty.com)

### 安装HttpGuard

假设我们把HttpGuard安装到/data/www/waf/，当然你可以选择安装在任意目录。

```
cd /data/www
wget --no-check-certificate https://github.com/wenjun1055/HttpGuard/archive/master.zip
unzip master.zip
mv HttpGuard-master waf
```

### 生成验证码图片

为了支持验证码识别用户，我们需要先生成验证码图片。生成验证码图片需要系统安装有php，以及php-gd模块。
用以下命令执行getImg.php文件生成验证码

```
cd /data/www/waf/captcha/
/usr/local/php/bin/php getImg.php
```

大概要生成一万个图片，可能需要花几分钟的时间。

### 修改nginx.conf配置文件

向http区块输入如下代码：

```
lua_package_path "/data/www/waf/?.lua";
lua_shared_dict guard_dict 100m;
lua_shared_dict dict_captcha 70m;
init_by_lua_file '/data/www/waf/init.lua';
access_by_lua_file '/data/www/waf/runtime.lua';
lua_max_running_timers 1;
```

### 配置HttpGuard

详细配置说明在[config.lua](https://github.com/wenjun1055/HttpGuard/blob/master/guard.lua)中，请根据需求进行配置
