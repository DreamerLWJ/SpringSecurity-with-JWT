package com.imitee.springsecurtydemo.demo.controller;

import org.apache.tomcat.util.http.ResponseUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author 罗文俊
 * 2021/2/18
 */

// Spring 会根据这个注解在 Spring 容器中生成一个实例，并且自动注入到生成的 Servlet 中
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
