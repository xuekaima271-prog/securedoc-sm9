package com.securedoc.app;

import com.securedoc.app.common.AuditChainResult;
import com.securedoc.app.crypto.Sm3;
import com.securedoc.app.entity.AuditLog;
import com.securedoc.app.mapper.AuditLogMapper;
import com.securedoc.app.service.AuditService;
import com.securedoc.app.service.SecurityEventService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * M-3 审计链 HMAC 化单测（纯 Mockito，不起 Spring）：新写入恒 v2、存量 v1 双模式校验、
 * 整链无钥重写（降级）在默认边界下被检出、v2 之后插入 v1 被版本单调规则检出、内容篡改被检出。
 * 链数据由测试按 AuditService 的规范化口径手工构造（Sm3 本身已由 Sm3Test 的独立向量锁定）。
 */
class AuditHmacChainTest {

    private static final String KEY = "unit-test-hmac-key";
    private static final LocalDateTime TS = LocalDateTime.of(2026, 1, 1, 10, 0, 5);

    private final AuditLogMapper mapper = mock(AuditLogMapper.class);
    private final SecurityEventService events = mock(SecurityEventService.class);

    private AuditService service(long legacyMaxId) {
        return new AuditService(mapper, events, KEY, legacyMaxId);
    }

    private static AuditLog row(long id, String action, String detail) {
        AuditLog a = new AuditLog();
        a.setId(id);
        a.setActorId(10001L);
        a.setAction(action);
        a.setResourceType("AUTH");
        a.setResourceId("alice");
        a.setClientIp("1.1.1.1");
        a.setDetail(detail);
        a.setCreatedAt(TS);
        return a;
    }

    /** 与 AuditService.canonicalContent 同口径（字段序/null 处理/秒级时间戳）。 */
    private static String canonical(AuditLog a) {
        return String.join("|",
                a.getActorId() == null ? "" : a.getActorId().toString(),
                a.getAction(), a.getResourceType(), a.getResourceId(), a.getClientIp(), a.getDetail(),
                a.getCreatedAt().truncatedTo(ChronoUnit.SECONDS).toString());
    }

    private static String legacyHash(String prev, AuditLog a) {
        return Sm3.digestBase64((prev + "|" + canonical(a)).getBytes(StandardCharsets.UTF_8));
    }

    private static String v2Hash(String prev, AuditLog a) {
        return "v2$" + Sm3.hmacBase64(KEY.getBytes(StandardCharsets.UTF_8),
                (prev + "|" + canonical(a)).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void 写入的新记录是v2_HMAC且逐条衔接_校验通过() {
        AuditService svc = service(0);
        when(mapper.selectLastHash()).thenReturn(null);

        svc.record(10001L, "LOGIN", "AUTH", "alice", "1.1.1.1", "ua", "登录成功");
        ArgumentCaptor<AuditLog> cap = ArgumentCaptor.forClass(AuditLog.class);
        verify(mapper).insert(cap.capture());
        AuditLog first = cap.getValue();
        assertThat(first.getPreviousHash()).isEqualTo("GENESIS");
        assertThat(first.getCurrentHash()).startsWith("v2$");
        first.setId(1L);

        when(mapper.selectLastHash()).thenReturn(first.getCurrentHash());
        svc.record(10001L, "LOGOUT", "AUTH", "alice", "1.1.1.1", "ua", "登出");
        verify(mapper, org.mockito.Mockito.times(2)).insert(cap.capture());
        AuditLog second = cap.getValue();
        assertThat(second.getPreviousHash()).isEqualTo(first.getCurrentHash());
        second.setId(2L);

        when(mapper.selectList(any())).thenReturn(List.of(first, second));
        AuditChainResult r = svc.verifyChain();
        assertThat(r.valid()).isTrue();
    }

    @Test
    void 存量v1在兼容边界内_与v2混合链校验通过() {
        AuditLog r1 = row(1, "LOGIN", "升级前记录");
        r1.setPreviousHash("GENESIS");
        r1.setCurrentHash(legacyHash("GENESIS", r1));
        AuditLog r2 = row(2, "LOGOUT", "升级后记录");
        r2.setPreviousHash(r1.getCurrentHash());
        r2.setCurrentHash(v2Hash(r1.getCurrentHash(), r2));

        when(mapper.selectList(any())).thenReturn(List.of(r1, r2));
        AuditChainResult r = service(1).verifyChain();   // legacyMaxId=1：id<=1 的 v1 是认可存量
        assertThat(r.valid()).isTrue();
    }

    @Test
    void 整链被无钥重写为v1_默认边界下检出() {
        // 攻击者有 DB 写权限但无 HMAC 密钥：篡改内容后用无钥 SM3 把整条链重算得完全自洽
        AuditLog r1 = row(1, "LOGIN", "被篡改的详情");
        r1.setPreviousHash("GENESIS");
        r1.setCurrentHash(legacyHash("GENESIS", r1));
        AuditLog r2 = row(2, "FILE_DOWNLOAD", "被篡改的下载");
        r2.setPreviousHash(r1.getCurrentHash());
        r2.setCurrentHash(legacyHash(r1.getCurrentHash(), r2));

        when(mapper.selectList(any())).thenReturn(List.of(r1, r2));
        AuditChainResult r = service(0).verifyChain();   // 默认 0：不接受任何 v1 记录
        assertThat(r.valid()).isFalse();
        assertThat(r.brokenAtId()).isEqualTo(1L);
    }

    @Test
    void v2之后降级插入自洽v1_被版本单调规则检出() {
        AuditLog r1 = row(1, "LOGIN", "正常记录");
        r1.setPreviousHash("GENESIS");
        r1.setCurrentHash(v2Hash("GENESIS", r1));
        AuditLog r2 = row(2, "LOGOUT", "降级伪造");
        r2.setPreviousHash(r1.getCurrentHash());
        r2.setCurrentHash(legacyHash(r1.getCurrentHash(), r2));   // v1 公式自洽，但出现在 v2 之后

        when(mapper.selectList(any())).thenReturn(List.of(r1, r2));
        // legacyMaxId 放大到 100：单靠 id 边界拦不住，必须由版本单调规则检出
        AuditChainResult r = service(100).verifyChain();
        assertThat(r.valid()).isFalse();
        assertThat(r.brokenAtId()).isEqualTo(2L);
    }

    @Test
    void 篡改v2记录内容_重算不一致被检出() {
        AuditLog r1 = row(1, "LOGIN", "原始详情");
        r1.setPreviousHash("GENESIS");
        r1.setCurrentHash(v2Hash("GENESIS", r1));
        r1.setDetail("被篡改的详情");   // 只改内容、无密钥无法补出正确 HMAC

        when(mapper.selectList(any())).thenReturn(List.of(r1));
        AuditChainResult r = service(0).verifyChain();
        assertThat(r.valid()).isFalse();
        assertThat(r.brokenAtId()).isEqualTo(1L);
    }
}
