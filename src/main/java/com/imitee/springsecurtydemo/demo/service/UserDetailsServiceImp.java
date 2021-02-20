package com.imitee.springsecurtydemo.demo.service;


import com.imitee.springsecurtydemo.demo.security.SecurityUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author 罗文俊
 * 2021/2/18
 * 处理用户信息获取逻辑
 */
@Service
public class UserDetailsServiceImp implements UserDetailsService {
    private final UserService userService;

    // 推荐使用构造注入
    @Autowired
    public UserDetailsServiceImp(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 通过用户名获取用户
        User user = userService.findByUsername(username);
        return new SecurityUserDetails(user);
    }
}
