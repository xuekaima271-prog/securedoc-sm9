package com.securedoc.app.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.Map;

/**
 * KGC 服务客户端（Step 6 代理）。令牌只存在于本服务端，浏览器永远拿不到。
 * 仅做两件事：取 SM9 主公钥（公开，可缓存）、按身份签发用户私钥（带令牌）。
 * 应用服务器不持久化任何私钥包，仅作中转返回给浏览器（浏览器存 IndexedDB）。
 */
@Component
public class KgcClient {

    private static final Logger log = LoggerFactory.getLogger(KgcClient.class);

    private final RestClient rest;
    private final String token;

    /** 主公钥不变，首次取到后缓存（volatile 保证可见性）。 */
    private volatile String cachedMasterPublicKey;

    public KgcClient(@Value("${securedoc.kgc.base-url:http://localhost:8081}") String baseUrl,
                     @Value("${securedoc.kgc.token}") String token,
                     @Value("${securedoc.kgc.connect-timeout-ms:2000}") int connectTimeoutMs,
                     @Value("${securedoc.kgc.read-timeout-ms:5000}") int readTimeoutMs) {
        this.token = token;
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofMillis(connectTimeoutMs));
        factory.setReadTimeout(Duration.ofMillis(readTimeoutMs));
        this.rest = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(factory)
                .build();
        log.info("KGC 客户端初始化: baseUrl={}", baseUrl);
    }

    /** 取 SM9 主公钥（Base64, 64B）。缓存。 */
    public String getMasterPublicKey() {
        String cached = cachedMasterPublicKey;
        if (cached != null) return cached;
        JsonNode data = getData(() -> rest.get().uri("/kgc/sm9/master-public-key")
                .header("X-KGC-Token", token)
                .retrieve().body(JsonNode.class), "取主公钥");
        String mpk = text(data, "masterPublicKey");
        if (mpk == null || mpk.isBlank()) {
            throw new BusinessException(ErrorCode.KGC_UNAVAILABLE, "KGC 未返回主公钥");
        }
        cachedMasterPublicKey = mpk;
        return mpk;
    }

    /** 登记新用户 SM9 身份（新用户开通）。KGC 侧幂等；失败抛 KGC_UNAVAILABLE 由调用方决定回滚。 */
    public void registerIdentity(Long userId, String identity) {
        Map<String, Object> body = Map.of("userId", userId, "identity", identity);
        getData(() -> rest.post().uri("/kgc/sm9/register-identity")
                .header("X-KGC-Token", token)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve().body(JsonNode.class), "登记身份");
    }

    /** 按身份首次签发用户私钥。返回 KGC 的 data 节点（含 privateKeyPackage/identity/issueId/issuedAt）。 */
    public JsonNode issuePrivateKey(Long userId, String identity, String deviceFingerprint) {
        return issueInternal("/kgc/sm9/issue-private-key", userId, identity, deviceFingerprint, null, "签发私钥");
    }

    /** 重新签发（换设备/恢复，§2.4）。KGC 侧落 issue_type=REISSUE 审计，与首次签发区分。 */
    public JsonNode reissuePrivateKey(Long userId, String identity, String deviceFingerprint, String reason) {
        return issueInternal("/kgc/sm9/reissue-private-key", userId, identity, deviceFingerprint, reason, "重签发私钥");
    }

    private JsonNode issueInternal(String uri, Long userId, String identity,
                                   String deviceFingerprint, String reason, String op) {
        Map<String, Object> body = new java.util.HashMap<>();
        body.put("userId", userId);
        body.put("identity", identity);
        body.put("deviceFingerprint", deviceFingerprint == null ? "" : deviceFingerprint);
        if (reason != null) body.put("reason", reason);
        return getData(() -> rest.post().uri(uri)
                .header("X-KGC-Token", token)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve().body(JsonNode.class), op);
    }

    /** 分页查询 KGC 签发记录（审计用，带令牌）。返回 KGC 的 data 节点 {total,page,size,records}。 */
    public JsonNode listIssues(long page, long size, Long userId) {
        String uri = "/kgc/sm9/issues?page=" + page + "&size=" + size
                + (userId != null ? "&userId=" + userId : "");
        return getData(() -> rest.get().uri(uri)
                .header("X-KGC-Token", token)
                .retrieve().body(JsonNode.class), "查询签发记录");
    }

    /** 统一处理 KGC 响应：网络异常→KGC_UNAVAILABLE；业务 success=false→透传消息。 */
    private JsonNode getData(java.util.function.Supplier<JsonNode> call, String op) {
        JsonNode root;
        try {
            root = call.get();
        } catch (Exception e) {
            log.error("调用 KGC 失败({}): {}", op, e.getMessage());
            throw new BusinessException(ErrorCode.KGC_UNAVAILABLE, "KGC 服务不可用");
        }
        if (root == null || !root.path("success").asBoolean(false)) {
            String msg = root == null ? "空响应" : root.path("message").asText("KGC 返回失败");
            log.warn("KGC 业务失败({}): {}", op, msg);
            throw new BusinessException(ErrorCode.KGC_UNAVAILABLE, "KGC " + op + "失败: " + msg);
        }
        return root.path("data");
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() ? null : v.asText();
    }
}
