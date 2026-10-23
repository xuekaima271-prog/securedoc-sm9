package com.securedoc.kgc.web;

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
 * KGC 健康检查：设计文档 §2.4 GET /kgc/health。
 * 顺带探测数据库连通与签发记录数，便于运维确认 KGC 状态。
 */
@RestController
@RequestMapping("/kgc")
public class KgcHealthController {

    private static final Logger log = LoggerFactory.getLogger(KgcHealthController.class);

    private final JdbcTemplate jdbcTemplate;

    public KgcHealthController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "UP");
        body.put("service", "securedoc-kgc-service");
        body.put("time", OffsetDateTime.now().toString());
        try {
            Integer issues = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM kgc_private_key_issues", Integer.class);
            Integer users = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
            body.put("db", "UP");
            body.put("userCount", users);
            body.put("issueCount", issues);
        } catch (Exception e) {
            log.error("KGC 健康检查数据库探测失败", e);   // 内部记录，不向外暴露异常细节
            body.put("db", "DOWN");
        }
        return body;
    }
}
