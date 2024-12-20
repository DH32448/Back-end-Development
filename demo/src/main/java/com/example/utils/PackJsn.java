package com.example.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class PackJsn {
        public static XJson pack(int code, String msg, Object data) {
            return new XJson(code, msg, data);
        }

        static Logger logger = LoggerFactory.getLogger(PackJsn.class);
        static ObjectMapper objectMapper = new ObjectMapper();

        public static String packM(int code, String msg, Object data) {
            Map<String, Object> m = new HashMap<>();
            m.put("code", code);
            m.put("msg", msg);
            m.put("data", data);
            String json = "";
            try {
                json = objectMapper.writeValueAsString(m);
            } catch (Exception e) {
                logger.error(e.getMessage());
            }
            logger.debug("JSON=" + json);
            return json;
        }

        private String pack2(int code, String msg, String data) {
            String strJson = "{" +
                    "\"" + "code" + "\"" + ":" + code + "," +
                    "\"" + "msg" + "\"" + ":" + "\"" + msg + "\"" + "," +
                    "\"" + "data" + "\"" + ":" + "\"" + data + "\"" +
                    "}";
            return strJson;
        }
}
