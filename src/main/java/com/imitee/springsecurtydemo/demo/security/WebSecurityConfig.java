package com.imitee.springsecurtydemo.demo.security;

import com.imitee.springsecurtydemo.demo.filter.JWTAuthenticationEntryPoint;
import com.imitee.springsecurtydemo.demo.filter.JWTAuthenticationFilter;
import com.imitee.springsecurtydemo.demo.filter.JWTAuthorizationFilter;
import com.imitee.springsecurtydemo.demo.service.UserDetailsServiceImp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * @author 罗文俊
 * 2021/2/18
 */
@Configuration
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

    /**
     * 也可以通过 Java 代码来进行配置权限
     *
     * @param auth
     * @throws Exception
     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("lwj")
//                // 密码不是以明文形式存储，所以要提供一个编码器
//                .password(new BCryptPasswordEncoder().encode("123"))
//                .roles("admin");
//    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                // 跨域共享
                .cors()
                .and()
                // 跨域伪造请求限制无效
                .csrf().disable()
                .authorizeRequests()
                // TODO 在这里添加你要求鉴权的
                .antMatchers("data").hasRole("ADMIN")
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
