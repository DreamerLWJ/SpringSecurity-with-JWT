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
        return new User("lwj", "123", AuthorityUtils.commaSeparatedStringToAuthorityList("admin") );
    }
}
