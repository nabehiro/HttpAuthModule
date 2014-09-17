# Http Auth Module
This is Simple Http Authentication HttpModule for ASP.NET (MVC).
- Basic Authentication
- Digest Authentication 
- Restrict IP Address (ip4 or ip6)
- Basic or Digest Authentication don't tounch HttpContext.Current.User.

** Http Auth Module targets the .NET Framework 4.5 **

# Quick start
Get Nuget package.
https://www.nuget.org/packages/HttpAuthModule/

```
PM> Install-Package HttpAuthModule
``` 

After Getting, configure Web.config file.
It's all you do for using HttpAuthModule.

# Configuration
Modify Web.config file.

```XML
<configuration>
  <configSections>
    <section name="httpAuthModule" type="System.Configuration.NameValueFileSectionHandler" />
  </configSections>

  <httpAuthModule>
    <!--
      [required] Http Authentication Mode.
      - Basic: Basic authentication
      - Digest: Digest authentication
      - None: No authentication -->
    <add key="AuthMode" value="Digest"/>
    <!-- [optional] default is "SecureZone" -->
    <add key="Realm" value="SecureZone"/>
    <!-- [required if http auth on] user1:pass1;user2:pass2;... -->
    <add key="Credentials" value="hoge:hogepass;foo:foopass;"/>
    <!-- [optional] Digest Auth Nonce Valid Duration Minutes. default is 120 -->
    <add key="DigestNonceValidDuration" value="120"/>
    <!-- [required if digest auth on] Digest Auth Nonce Salt -->
    <add key="DigestNonceSalt" value="uht9987bbbSAX" />
    <!--
      [optional] If set, specified IPs are only allowed: otherwize All IPs are allowed.
      value is joined IP Range Combination as following.
      - 10.23.0.0/24
      - 127.0.0.1 (equals to 127.0.0.1/32)
      - 2001:0db8:bd05:01d2:288a:1fc0:0001:0000/16
      - ::1 (equals to ::1/128)
      
      e.g) 127.0.0.1;182.249.0.0/16;182.248.112.128/26;::1 -->
    <add key="RestrictIPAddresses" value="127.0.0.1;::1"/>
    <!-- [optional] If set, specified pattern url request skip http auth and IP Restriction. -->
    <add key="IgnorePathRegex" value="^/Home/Ignore$|^/Ignore\.aspx$"/>
  </httpAuthModule>

  <system.webServer>
    <modules>
      <add type="HttpAuthModule.HttpAuthModule" name="HttpAuthModule"/>
    </modules> 
  </system.webServer>
</configuration>
```


If you apply only http requests for ASP.NET Resource(default.aspx /controller/action, but image.gif, index.html), change "modules -> add" element. 
```XML
  <modules>
    <!-- add preCondition="managedHandler" -->
    <add type="HttpAuthModule.HttpAuthModule" name="HttpAuthModule" preCondition="managedHandler" />
  </modules> 
```

# Disable HttpAuthModule by AppSettings
if you add HttpAuthModuleEnabled=false to appSettings, HttpAUthModule doesn't run.
```XML
  <appSettings>
    <add key="HttpAuthModuleEnabled" value="false" />   
  </appSettings>
```



# Usage for PHP
1. create bin dir(ectory) into root dir.
2. put HttpAuthModule.dll into bin dir.
3. put Web.config into root dir.

HttpAuthModule.dll and Web.config is here, https://github.com/nabehiro/HttpAuthModule/PHPResources

please see detail, http://blogs.gine.jp/taka/archives/2753

