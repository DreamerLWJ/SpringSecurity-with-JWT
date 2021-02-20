package com.imitee.springsecurtydemo.demo.util;




import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtTokenUtil {
    /**
     * token 请求头
     */
    public static final String TOKEN_HEADER = "Authorization";
    /**
     * token 前缀
     */
    public static final String TOKEN_PREFIX = "Bearer ";
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
     * 生成Token
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
     * 校验Token
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