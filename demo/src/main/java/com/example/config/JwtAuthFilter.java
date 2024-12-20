package com.example.config;

import com.example.utils.JwtUtils;
import com.example.utils.PackJsn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class JwtAuthFilter extends BasicAuthenticationFilter {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    // 认证管理器
    public JwtAuthFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        // 获取请求头中的 Authorization 字段
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization: " + bearerToken);

        // 如果没有 Token 或者 Token 不以 Bearer 开头，直接放行
        if (bearerToken == null || !bearerToken.startsWith("Bearer")) {
            logger.info("没有 Token 或者 Token 不合法，直接放行");
            chain.doFilter(request, response);
            return;
        }

        // 提取 Token
        String token = bearerToken.substring(7);
        logger.debug("Token: " + token);

        // 校验 Token 是否有效
        if (!JwtUtils.isValid(token)) {
            logger.info("Token 非法或过期");
            response.setStatus(403);
            response.setContentType("application/json;charset=utf-8");
            String ret = PackJsn.packM(40304, "Token 非法", "");
            response.getWriter().write(ret);
            response.flushBuffer();
            return;
        }

        // 从 Token 中获取用户名和角色
        String username = JwtUtils.getUsername(token);
        List<String> roles = JwtUtils.getRoles(token);
        logger.debug("用户名: " + username);
        logger.debug("角色: " + roles);

        // 创建权限列表
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }

        // 创建用户对象
        User user = new User(username, "", authorities);
        logger.debug("用户对象: " + user);

        // 创建认证对象
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(user, null, authorities);

        // 将认证对象放入 SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authentication);
        logger.info("认证成功，用户信息已存入 SecurityContextHolder");

        // 继续过滤链
        chain.doFilter(request, response);
    }
}