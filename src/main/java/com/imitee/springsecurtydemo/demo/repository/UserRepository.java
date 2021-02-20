package com.imitee.springsecurtydemo.demo.repository;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Repository;

/**
 * @author 罗文俊
 * 2021/2/19
 */
@Repository
public class UserRepository {

    public User findByUsername(String username) {
        // 这里模拟从数据库中获取用户
        // TODO 请自己修改定义数据库查询
        return new User("lwj", "123", AuthorityUtils.commaSeparatedStringToAuthorityList("admin") );
    }
}
