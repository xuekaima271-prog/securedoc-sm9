package com.securedoc.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.securedoc.app.client.KgcClient;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** KGC 签发记录代理 GET /api/admin/kgc-issues：admin/auditor/KGC_ADMIN 200 数据透传、员工与 DEPT_ADMIN 403、令牌不出服务端。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class KgcIssuesProxyTest {

    @Autowired MockMvc mvc;
    @MockitoBean KgcClient kgcClient;
    private final ObjectMapper om = new ObjectMapper();

    private void mockPage() {
        ObjectNode data = om.createObjectNode();
        data.put("total", 1).put("page", 1).put("size", 20);
        data.putArray("records").addObject()
                .put("id", "ISSUE-1").put("userId", 10002)
                .put("sm9Identity", "user:corp001:10002:bob@example.com")
                .put("issueType", "REISSUE").put("auditStatus", "RECORDED");
        Mockito.when(kgcClient.listIssues(anyLong(), anyLong(), any())).thenReturn(data);
    }

    @Test
    @WithUserDetails("admin")
    void 管理员查签发记录_透传KGC分页数据() throws Exception {
        mockPage();
        mvc.perform(get("/api/admin/kgc-issues?page=1&size=20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(1))
                .andExpect(jsonPath("$.data.records[0].issueType").value("REISSUE"))
                .andExpect(jsonPath("$.data.records[0].sm9Identity").value("user:corp001:10002:bob@example.com"));
    }

    @Test
    @WithUserDetails("auditor")
    void 审计员查签发记录_200() throws Exception {
        mockPage();
        mvc.perform(get("/api/admin/kgc-issues")).andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("alice")
    void 员工查签发记录_403() throws Exception {
        mvc.perform(get("/api/admin/kgc-issues"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }

    /** KGC_ADMIN 接入鉴权（2026-10-23 权限分级）：该接口不依赖登录用户实体，用模拟角色验证注解放行。 */
    @Test
    @WithMockUser(username = "kgcadmin", roles = {"KGC_ADMIN"})
    void KGC管理员查签发记录_200() throws Exception {
        mockPage();
        mvc.perform(get("/api/admin/kgc-issues"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(1));
    }

    @Test
    @WithMockUser(username = "dept", roles = {"DEPT_ADMIN"})
    void 部门管理员查签发记录_403() throws Exception {
        mvc.perform(get("/api/admin/kgc-issues"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }
}
