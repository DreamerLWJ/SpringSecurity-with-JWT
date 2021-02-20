package com.imitee.springsecurtydemo.demo.service;


import com.imitee.springsecurtydemo.demo.repository.UserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

/**
 * @author 罗文俊
 * 2021/2/18
 */
@Service
public class UserService {
    private UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
