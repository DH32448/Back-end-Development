package com.example.entity;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserAccount {
    Integer user_id;
    String username;
    String password;
    String role;
    //后续添加邮箱发送验证码
}
