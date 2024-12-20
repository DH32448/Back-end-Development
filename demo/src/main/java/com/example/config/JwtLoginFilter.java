package com.example.config;

import com.example.utils.JwtUtils;
import com.example.utils.PackJsn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

//继承重写 Spring Security 已经存在的账号密码认证过滤器
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtLoginFilter.class);

    private final AuthenticationManager authenticationManager;

    // 构造函数注入认证管理器
    public JwtLoginFilter(AuthenticationManager manager) {
        LOGGER.debug("初始化 JwtLoginFilter，获取到认证管理器: {}", manager);
        this.authenticationManager = manager;
        // 设置登录的处理路径
        super.setFilterProcessesUrl("/api/login");
    }

    /**
     * 尝试认证
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        LOGGER.debug("尝试认证，账号: {}", username);
        LOGGER.debug("尝试认证，密码: {}", password);

        // 创建认证令牌
        UsernamePasswordAuthenticationToken loginToken = new UsernamePasswordAuthenticationToken(username, password);

        // 调用认证管理器进行认证
        Authentication authentication = authenticationManager.authenticate(loginToken);

        LOGGER.debug("认证成功，返回对象: {}", authentication);
        return authentication;
    }

    /**
     * 认证成功执行的方法
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        LOGGER.info("认证成功: {}", authResult);

        // 获取用户信息
        User user = (User) authResult.getPrincipal();
        LOGGER.info("登录成功，用户名: {}", user.getUsername());
        LOGGER.info("用户角色: {}", user.getAuthorities());

        // 获取用户角色
        List<String> roles = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        LOGGER.debug("用户角色列表: {}", roles);

        // 创建 JWT Token
        String token = JwtUtils.createToken(user.getUsername(), roles);

        // 封装返回值
        Map<String, Object> tokenMap = new HashMap<>();
        tokenMap.put("token", token);

        String json = PackJsn.packM(201, "登录成功", tokenMap);

        // 设置响应
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(json);
        response.flushBuffer();
    }

    /**
     * 认证失败执行的方法
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        LOGGER.warn("认证失败: {}", failed.getMessage());

        String json = PackJsn.packM(401, "认证失败,账号或密码错误", "");

        // 设置响应
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(json);
        response.flushBuffer();
    }
}
