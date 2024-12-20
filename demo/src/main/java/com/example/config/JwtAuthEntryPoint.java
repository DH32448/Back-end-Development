package com.example.config;

import com.example.utils.PackJsn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthEntryPoint implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        // 使用日志记录错误信息
        logger.error("Authentication error: {}", authException.getMessage());

        // 设置响应类型和状态码
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);  // 使用 HttpServletResponse.SC_FORBIDDEN 常量

        // 封装错误信息
        String responseBody = PackJsn.packM(403, "访问权限异常...", "");

        // 写入响应
        response.getWriter().write(responseBody);
        response.flushBuffer();

        // 记录日志
        logger.warn("发送的响应包括 403 状态和消息: {}", responseBody);
    }
}