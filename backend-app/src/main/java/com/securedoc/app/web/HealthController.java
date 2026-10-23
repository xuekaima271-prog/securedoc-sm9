package com.securedoc.app.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 健康检查：对应设计文档 §2.10 GET /api/health。
 * 顺带探测数据库连通与演示账号数量，验证 schema/init_data 已正确加载。
 */
@RestController
@RequestMapping("/api")
public class HealthController {

    private static final Logger log = LoggerFactory.getLogger(HealthController.class);

    private final JdbcTemplate jdbcTemplate;

    public HealthController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "UP");
        body.put("service", "securedoc-backend-app");
        body.put("time", OffsetDateTime.now().toString());
        try {
            Integer users = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
            Integer roles = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM roles", Integer.class);
            body.put("db", "UP");
            body.put("userCount", users);
            body.put("roleCount", roles);
        } catch (Exception e) {
            log.error("健康检查数据库探测失败", e);   // SEC-2：内部记录，不向外暴露异常细节
            body.put("db", "DOWN");
        }
        return body;
    }
}
