# Spring Security 整合 JWT

**目录**

[TOC]



## 1. JWT 概述

Json Web Token 本质上就是一种 JSON 的开放标准，核心是将 token 设计为紧凑且安全。

JWT 实际上就是一个字符串，由三部分组成，头部(header)，荷载(Payload) 和 签名(Signature)，每部分用 " . " 分隔。

其中头部和荷载使用了 base64 编码，

**头部：**

```json
{
  "alg": "[算法]",
  "typ": "JWT"
}
```

说明该串使用了某某算法对 JWT 进行签名

**荷载：**

```json
{
 "sub": "1234567890",
 "name": "John Doe",
 "iat": 1516239022
}
```

字段含义：

- sub：面向用户
- name：用户名
- iat：签发时间（常用于超时校验）

除了上面这些字段，你还可以把任意数据声明在这里

> 事实上 JWT 不限制荷载部分内容

**签名**

用于验证头部和荷载数据的完整性，一般为 hash 值



## 2. JWT 的简单使用

通过简单使用我们可以更加深入理解到， JWT 不过就是 JSON 字符串基础上进行签名算法生成的字符串而已

#### JWT 令牌工作原理

![7790cc3aade467c985e2e4a8105b89f1.png](https://img2018.cnblogs.com/blog/1104426/201906/1104426-20190602203732908-2090758359.png)

#### 模拟服务端接收到POST后根据用户名生成 （access）token

**示例代码：**

```java
public static void main(String[] args) {
    String token = Jwts.builder()
            // 用户名
            .setSubject("1546131654")
            // 自定义属性
            .claim("authorities", "admin")
            // 失效时间（单位毫秒）
            .setExpiration(new Date(System.currentTimeMillis() + 7 * 60 * 1000))
            // 签名算法和密钥
            .signWith(SignatureAlgorithm.HS256, "tmax")
            .compact();
    // 输出签名后的密文
    System.out.println(token);
}
```

上面的示例模拟服务器接收到用户名1546131654的请求参数后，生成ak的过程

**运行结果：**

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxNTQ2MTMxNjU0IiwiYXV0aG9yaXRpZXMiOiJhZG1pbiIsImV4cCI6MTYxMzc1NTkyOH0.QoxdoepX9OALvmefNDeUsZntDZ5uxZg3-Eh9VAMhm_g
```

不难发现是按照 JWT 标准的三部分，之间用 “ . ” 分隔

#### 模拟服务端根据用户发回来的 token 进行鉴权

**示例代码：**

```java
public static void main(String[] args) {
    Claims claims = Jwts.parser()
            .setSigningKey("tmax")
            .parseClaimsJws("[上面那一串 token]")
            .getBody();
    // Claims 是一个 JSON 对象，相当于荷载，严格来说是荷载中的数据声明
    System.out.println(claims);
    // 获取用户名
    System.out.println(claims.getSubject());
    // 获取权限
    System.out.println(claims.get("authorities").toString());
}
```

**运行结果：**

```
{sub=1546131654, authorities=admin, exp=1613756525}   # 输出的 Claims
1546131654  # 输出用户名
admin  # 权限
```

我们可以看到在 JWT 中，服务器赋予客户端临时访问权限和校验权限，不过就是生成一串密文和反解密文的过程罢了，那么现在我们将它集成到 Spring Security 中。



## 3. Spring Security 使用 JWT 令牌

集成 JWT 的过程很好理解，就是将上面那部分加密（登录）和解密（鉴权）嵌入我们的 Spring Security，那么嵌入的核心是在



### 3.1 添加依赖

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

### 3.2 实现 JWT 加密解密工具类

这个工具类其实相当于将上面的简单使用封装为一个工具类

```java
public class JwtTokenUtil {
    /**
     * token 请求头
     */
    public static final String TOKEN_HEADER = "Authorization";
    /**
     * token 前缀
     */
    public static final String TOKEN_PREFIX = "imitee ";
    /**
     * token 有效时间
     */
    public static final long EXPIRITION = 1000 * 24 * 60 * 60 * 7;
    /**
     * 签名密钥
     */
    public static final String APPSECRET_KEY = "imitee";
    /**
     * 权限声明 key
     */
    private static final String ROLE_CLAIMS = "role";
    
    /**
     * 生成Token（加密）
     */
    public static String createToken(String username,String role) {
        // 用 Map 来装载想要额外发送的数据，可以自定义
        Map<String,Object> map = new HashMap<>();
        map.put(ROLE_CLAIMS, role);

        // 生成 token
        String token = Jwts
                .builder()
                .setSubject(username)
                // 数据声明
                .setClaims(map)
                .claim("username",username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRITION))
                .signWith(SignatureAlgorithm.HS256, APPSECRET_KEY).compact();
        return token;
    }

    /**
     * 校验Token（解密）
     */
    public static Claims checkJWT(String token) {
        try {
            final Claims claims = Jwts.parser().setSigningKey(APPSECRET_KEY).parseClaimsJws(token).getBody();
            return claims;
        } catch (Exception e) {
            // TODO 异常处理，出现异常即解密失败
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 从 Token 中获取 username
     */
    public static String getUsername(String token){
        Claims claims = Jwts.parser().setSigningKey(APPSECRET_KEY).parseClaimsJws(token).getBody();
        return claims.get("username").toString();
    }

    /**
     * 从 Token 中获取用户角色
     */
    public static String getUserRole(String token){
        Claims claims = Jwts.parser().setSigningKey(APPSECRET_KEY).parseClaimsJws(token).getBody();
        return claims.get("role").toString();
    }

    /**
     * 校验 Token 是否过期
     */
    public static boolean isExpiration(String token){
        Claims claims = Jwts.parser().setSigningKey(APPSECRET_KEY).parseClaimsJws(token).getBody();
        // 使用 data before() 方法判断当前时间是否位于有效时间之前
        return claims.getExpiration().before(new Date());
    }
}
```

### 3.3 实现一个登录过滤器

通过实现过滤器的好处可以充分利用 Spring Security 框架，减少我们写的多余代码。

核心是调用 authenticationManager 的 authenticate() 方法

```java
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    /**
     * 用于与 Spring Security 框架协作
     */
    private final AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    /**
     * 验证操作 接收并解析用户凭证
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 从输入流中获取到登录的信息
        // 创建一个 token 并调用authenticationManager.authenticate() 让Spring security进行验证
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getParameter("username"), request.getParameter("password")));
    }

    /**
     * 验证【成功】后调用的方法
     * 若验证成功 生成token并返回
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        User user = (User) authResult.getPrincipal();

        // 从User中获取权限信息
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
        // 创建Token
        String token = JwtTokenUtil.createToken(user.getUsername(), authorities.toString());

        // 设置编码 防止乱码问题
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        // 在请求头里返回创建成功的token
        // 设置请求头为带有"Bearer "前缀的token字符串
        response.setHeader("token", JwtTokenUtil.TOKEN_PREFIX + token);

        // 处理编码方式 防止中文乱码
        response.setContentType("text/json;charset=utf-8");
        // 将反馈塞到HttpServletResponse中返回给前台
        response.getWriter().write(JSON.toJSONString("登录成功"));
    }

    /**
     * 验证【失败】调用的方法
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        String returnData = "";
        // 账号过期
        if (failed instanceof AccountExpiredException) {
            returnData = "账号过期";
        }
        // 密码错误
        else if (failed instanceof BadCredentialsException) {
            returnData = "密码错误";
        }
        // 密码过期
        else if (failed instanceof CredentialsExpiredException) {
            returnData = "密码过期";
        }
        // 账号不可用
        else if (failed instanceof DisabledException) {
            returnData = "账号不可用";
        }
        //账号锁定
        else if (failed instanceof LockedException) {
            returnData = "账号锁定";
        }
        // 用户不存在
        else if (failed instanceof InternalAuthenticationServiceException) {
            returnData = "用户不存在";
        }
        // 其他错误
        else {
            returnData = "未知异常";
        }

        // 处理编码方式 防止中文乱码
        response.setContentType("text/json;charset=utf-8");
        // 将反馈塞到HttpServletResponse中返回给前台
        response.getWriter().write(JSON.toJSONString(returnData));
    }
}
```

### 3.4 实现一个鉴权过滤器

鉴权过滤器用于登录成功之后使用 API

```java
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /**
     * 在过滤之前和之后执行的事件
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String tokenHeader = request.getHeader(JwtTokenUtil.TOKEN_HEADER);

        // 若请求头中没有Authorization信息 或是Authorization不以Bearer开头 则直接放行
        if (tokenHeader == null || !tokenHeader.startsWith(JwtTokenUtil.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        // 若请求头中有token 则调用下面的方法进行解析 并设置认证信息
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(tokenHeader));
        super.doFilterInternal(request, response, chain);
    }

    /**
     * 从token中获取用户信息并新建一个token
     *
     * @param tokenHeader 字符串形式的 token 请求头
     * @return 带用户名和密码以及权限的 Authentication
     */
    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) {
        // 去掉前缀 获取Token字符串
        String token = tokenHeader.replace(JwtTokenUtil.TOKEN_PREFIX, "");
        // 从Token中解密获取用户名
        String username = JwtTokenUtil.getUsername(token);
        // 从Token中解密获取用户角色
        String role = JwtTokenUtil.getUserRole(token);
        // 将[ROLE_XXX,ROLE_YYY]格式的角色字符串转换为数组
        // StringUtils 是 org.apache.commons 依赖，读者也可以使用别的工具
        String[] roles = StringUtils.strip(role, "[]").split(", ");
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (String s : roles) {
            authorities.add(new SimpleGrantedAuthority(s));
        }
        if (username != null) {
            return new UsernamePasswordAuthenticationToken(username, null, authorities);
        }
        return null;
    }
}
```

### 3.5 配置多一个类，用于进行无权限的处理

```java
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        response.setCharacterEncoding("utf-8");
        response.setContentType("text/javascript;charset=utf-8");
        response.getWriter().print(JSONObject.toJSONString("您未登录，没有访问权限"));
    }
}
```

### 3.6 最后我们只需要在配置中添加上面的定义的组件即可

```java
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private UserDetailsServiceImp userDetailsService;

    // 推荐使用 Setter 注入
    @Autowired
    public void setUserDetailsService(UserDetailsServiceImp userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * 可以通过数据库方式校验
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 绑定验证
        auth.userDetailsService(userDetailsService)
                // 配置密码编码器
                .passwordEncoder(NoOpPasswordEncoder.getInstance());
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                // 跨域共享
                .cors()
                .and()
                // 跨域伪造请求限制无效
                .csrf().disable()
                .authorizeRequests()
                // 访问/data需要ADMIN角色
                .antMatchers("/data").hasRole("ADMIN")
                // 其余资源任何人都可访问
                .anyRequest().permitAll()
                .and()

                // 和之前相比主要多的这一点
                // 添加 JWT 登录拦截器
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                // 添加 JWT 鉴权拦截器
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                .sessionManagement()

                // 设置Session的创建策略为：Spring Security永不创建HttpSession 不使用HttpSession来获取SecurityContext
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // 异常处理
                .exceptionHandling()
                // 匿名用户访问无权限资源时的异常
                .authenticationEntryPoint(new JWTAuthenticationEntryPoint());
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 注册跨域配置
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }
}
```

### 3.7 最后进行测试

测试采用工具 postman

#### 3.7.1 添加一个 UserController

```java
@Controller
public class UserController {

    // 配置映射路径（路由）
    @RequestMapping("index")
    @ResponseBody
    public String index() {
        return "index";
    }

    @GetMapping("data")
    @ResponseBody
    private String data() {
        return "This is data.";
    }
}
```

对于这样的 Controller, data 接口我们之前通过下面的代码：

```java
http..antMatchers("/data").hasRole("ADMIN")
```

要求了鉴权，而 index 接口则不需要鉴权

#### 3.7.2 测试 index

![](https://i.loli.net/2021/02/20/iHJECIuO64vbQPe.png)

index 不需要鉴权

#### 3.7.3 测试 data

![](https://i.loli.net/2021/02/20/oY6M2JHIX3usSFC.png)

data 需要鉴权

#### 3.7.4 通过之前设置的 /api/login 登录获取 token

**可以看到已经登录成功了！**

![](https://i.loli.net/2021/02/20/CFzuZlAJLNP2Qhv.png)

**在 Header 中我们可以找到我们需要的 token**

![](https://i.loli.net/2021/02/20/Or1AiVskxPSyZvn.png)

```
Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiW2FkbWluXSIsImV4cCI6MTYxNDQxOTgwMiwiaWF0IjoxNjEzODE1MDAyLCJ1c2VybmFtZSI6Imx3aiJ9.19keJo0RuaFKpJndasbyPp9NNV3v_ywl6Dc3uGIkokg
```

- Bearer：前缀



#### 3.7.5 利用 token 访问 data 接口

添加 Authorization 字段访问后我们发现成功访问到 API 接口了

![](https://i.loli.net/2021/02/20/GZNj6r3tXDF75Yc.png)



## JWT 踩坑日志

#### Java 8 之后的版本调用签名方法可能会出现 `NoClassDefFoundError`

**错误示例：**

```
Exception in thread "main" java.lang.NoClassDefFoundError: javax/xml/bind/DatatypeConverter
	at io.jsonwebtoken.impl.Base64Codec.encode(Base64Codec.java:21)
	at io.jsonwebtoken.impl.Base64UrlCodec.encode(Base64UrlCodec.java:22)
	at io.jsonwebtoken.impl.DefaultJwtBuilder.base64UrlEncode(DefaultJwtBuilder.java:349)
	at io.jsonwebtoken.impl.DefaultJwtBuilder.compact(DefaultJwtBuilder.java:295)
	at com.tk.riskanalysis.utils.JwtUtils.createToken(JwtUtils.java:32)
	at com.tk.riskanalysis.test.main(test.java:19)
Caused by: java.lang.ClassNotFoundException: javax.xml.bind.DatatypeConverter
	at java.base/jdk.internal.loader.BuiltinClassLoader.loadClass(BuiltinClassLoader.java:582)
	at java.base/jdk.internal.loader.ClassLoaders$AppClassLoader.loadClass(ClassLoaders.java:185)
	at java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:496)
	... 6 more
```

**解决办法：**

1. 安装 jdk 1.8 （Java 8）
2. Ctrl+Alt+Shift+S 打开工程结构
3. Project 视图将 Project SDK 和 Project language level 修改为 jdk 1.8 和 Java 8
   ![](https://i.loli.net/2021/02/20/l6JrSj8MVBiEcob.png)

**深坑,问题可能会继续出现,那么只好用杀手锏了:**

在 pom.xml 引入:

```xml
<dependency>
    <groupId>javax.xml.bind</groupId>
    <artifactId>jaxb-api</artifactId>
    <version>2.3.0</version>
</dependency>
```