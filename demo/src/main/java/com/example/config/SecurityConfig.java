package com.example.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.annotation.Resource;

@Configuration  //注入ioc
@EnableWebSecurity //注解声名拦截器 由过滤器实现 只会拦截登录请求，自动找bean -> UserDetailsService  找到主动调用 loadUserByUsername
public class SecurityConfig {
    @Resource
    AuthenticationConfiguration authConfig;
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests()
                .antMatchers("/api/public").permitAll()
                .antMatchers(("/api/adm")).hasRole("adm")
                .and()
                .formLogin()
                .loginPage("/api/login")//设置登录的路径aip
                .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtLoginFilter(authConfig.getAuthenticationManager()))
                .addFilter(new JwtAuthFilter(authConfig.getAuthenticationManager()))
                .exceptionHandling().authenticationEntryPoint(new JwtAuthEntryPoint())
                .and()
        .build();
    }
    @Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
