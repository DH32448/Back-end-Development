package com.example.utils;

import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * JWT 工具类，用于生成、校验、解析 JWT Token
 */
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    // Token 的请求头字段
    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    // 签名的加密密钥，只需要服务器端知道就行
    private static final String JWT_SECRET = "qwer1234";

    // Token 的过期时间（7天）
    private static final long EXPIRE_TIME = 7 * 24 * 60 * 60 * 1000;

    /**
     * 生成签名（Token），设置过期时间
     *
     * @param username 用户名
     * @param roleList 用户角色列表
     * @return 加密后的 Token
     */
    public static String createToken(String username, List<String> roleList) {
        Date expireDate = new Date(System.currentTimeMillis() + EXPIRE_TIME);
        StringBuilder roles = new StringBuilder();

        // 拼接角色信息
        for (String role : roleList) {
            roles.append(role).append(",");
        }

        try {
            // 使用 HMAC256 算法和密钥生成 Token
            Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);
            return JWT.create()
                    .withClaim("username", username) // 将用户名存入 Token
                    .withClaim("roles", roles.toString()) // 将用户角色存入 Token
                    .withExpiresAt(expireDate) // 设置过期时间
                    .sign(algorithm); // 签名生成 Token
        } catch (Exception e) {
            logger.error("Token 生成失败", e);
            return null;
        }
    }

    /**
     * 验证 Token 是否有效（是否过期、是否可解析）
     *
     * @param token Token 字符串
     * @return Token 是否有效
     */
    public static boolean isValid(String token) {
        if (token != null && token.length() > 1) {
            try {
                // 使用相同的加密算法和密钥验证 Token
                JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(JWT_SECRET)).build();
                DecodedJWT decodedJwt = jwtVerifier.verify(token);

                // 检查当前时间是否在 Token 的过期时间之前
                return new Date().before(decodedJwt.getExpiresAt());
            } catch (Exception e) {
                logger.error("Token 验证失败", e);
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * 校验 Token 是否正确
     *
     * @param token    Token 字符串
     * @param username 用户名
     * @return Token 是否正确
     */
    public static boolean verify(String token, String username) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("username", username) // 校验用户名
                    .build();
            verifier.verify(token); // 验证 Token
            return true;
        } catch (Exception e) {
            logger.error("Token 校验失败", e);
            return false;
        }
    }

    /**
     * 获取 Token 中的用户名信息（无需解密密钥即可获取）
     *
     * @param token Token 字符串
     * @return Token 中包含的用户名
     */
    public static String getUsername(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        } catch (JWTDecodeException e) {
            logger.warn("无法从 Token 中解析用户名", e);
            return null;
        }
    }

    /**
     * 获取 Token 中包含的角色列表
     *
     * @param token Token 字符串
     * @return 角色列表
     */
    public static List<String> getRoles(String token) {
        List<String> roles = new ArrayList<>();
        try {
            DecodedJWT jwt = JWT.decode(token);
            String rolesString = jwt.getClaim("roles").asString();

            // 按逗号分割角色信息
            String[] roleArray = rolesString.split(",");
            for (String role : roleArray) {
                if (role != null && role.length() > 0) {
                    roles.add(role);
                }
            }
        } catch (JWTDecodeException e) {
            logger.warn("无法从 Token 中解析角色信息", e);
        }
        return roles;
    }
}
