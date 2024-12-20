package com.example.config;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)  // 把过滤器前置，优先级最高，放行跨域访问
public class CorsFilter2 extends HttpFilter {
    // 跨域过滤器

    @Override
    protected void doFilter(HttpServletRequest request,
                            HttpServletResponse response,
                            FilterChain chain) throws IOException, ServletException {
        this.addCorsHeader(request, response);  // 添加跨域头
        chain.doFilter(request, response);  // 放行请求
    }

    private void addCorsHeader(HttpServletRequest request,
                               HttpServletResponse response) {
        response.addHeader("Access-Control-Allow-Origin", request.getHeader("Origin"));  // 允许的跨域来源
        response.addHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");  // 允许的跨域方法
        response.addHeader("Access-Control-Allow-Headers", "Authorization,Content-Type");  // 允许的跨域头
    }
}