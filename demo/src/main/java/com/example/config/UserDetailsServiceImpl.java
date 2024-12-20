package com.example.config;

import com.example.entity.UserAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class UserDetailsServiceImpl implements UserDetailsService {
    Logger logger = LoggerFactory.getLogger(this.getClass());
    @Resource
    SecurityConfig securityConfig;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount userAccount = new UserAccount(1, "admin", "123456", "adm");
            logger.info(username);
            // 返回一个用户详情对象
            return User
                    .withUsername(username)
                    .password(securityConfig.passwordEncoder().encode(userAccount.getPassword()))//加密
                    .roles(userAccount.getRole()) // 设置用户角色
                    .build();

    }
}
