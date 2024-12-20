package com.example.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/public")
public class Test {
    @RequestMapping("/test")
    public String test(){
        return "test成功";
    }
}
