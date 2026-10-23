package com.securedoc.app;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M-2 上传总量上限集成测试：init-upload 的分块数/总大小/单块大小上限与三者一致性。
 * 阈值为 application.yml 默认值：max-chunk-count=10000、max-total-size=2147483648(2GB)、单块 8MB。
 * 每个用例的三个数值都经过设计：除被测维度外，其余维度均在合法范围内，确保命中的是目标校验。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FileUploadLimitsTest {

    @Autowired MockMvc mvc;

    /** 与 FileInitUploadTest 相同的合法接收人（bob），只变三个数值维度。 */
    private String body(long chunkSize, long chunkCount, long totalSize) {
        return """
            {
              "encryptedMetadata": {"algorithm":"SM4","mode":"CBC","iv":"aXY=","ciphertext":"Y3Q=","digest":"ZA=="},
              "chunkSize": %d, "chunkCount": %d, "totalSize": %d,
              "recipients": [
                {"recipientId":10002,"recipientIdentity":"user:corp001:10002:bob@example.com",
                 "keyEnvelope":{"algorithm":"SM9","wrappedKey":"d2s=","keyDigest":"a2Q="}}
              ]
            }""".formatted(chunkSize, chunkCount, totalSize);
    }

    private void expectRejected(long chunkSize, long chunkCount, long totalSize) throws Exception {
        mvc.perform(post("/api/files/init-upload")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(chunkSize, chunkCount, totalSize)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @WithUserDetails("alice")
    void 分块数超上限_400() throws Exception {
        // chunkCount=10001>10000；totalSize 与之严格一致且 <2GB，单块合法 → 只命中分块数上限
        expectRejected(200_000, 10_001, 2_000_200_000L);
    }

    @Test
    @WithUserDetails("alice")
    void 总大小超上限_400() throws Exception {
        // totalSize=2GB+1；chunkCount=ceil(totalSize/2MB)=1025 与之一致且 ≤10000，单块合法 → 只命中总大小上限
        expectRejected(2_097_152, 1_025, 2_147_483_649L);
    }

    @Test
    @WithUserDetails("alice")
    void 单块声明超8MB_400() throws Exception {
        // chunkSize=8MB+1；chunkCount=1 与 totalSize=100 一致，总量合法 → 只命中单块上限
        expectRejected(8_388_609, 1, 100);
    }

    @Test
    @WithUserDetails("alice")
    void 分块数与总大小不一致_400() throws Exception {
        // ceil(20/10)=2，但声明 chunkCount=3；三个维度各自都在上限内 → 只命中一致性校验
        expectRejected(10, 3, 20);
    }

    @Test
    @WithUserDetails("alice")
    void 恰在分块数上限_成功() throws Exception {
        // chunkCount 恰为 10000，totalSize=10000×200000 严格一致且 <2GB → 应放行
        mvc.perform(post("/api/files/init-upload")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(200_000, 10_000, 2_000_000_000L)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("INIT"));
    }

    @Test
    @WithUserDetails("alice")
    void 恰在总大小上限_成功() throws Exception {
        // totalSize 恰为 2GB，chunkCount=ceil(2GB/2MB)=1024 一致 → 应放行
        mvc.perform(post("/api/files/init-upload")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(2_097_152, 1_024, 2_147_483_648L)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("INIT"));
    }

    @Test
    @WithUserDetails("alice")
    void 空文件单块_成功() throws Exception {
        // totalSize=0 时前端记 chunkCount=1（sealFile 口径），后端一致性校验须同样放行
        mvc.perform(post("/api/files/init-upload")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(1024, 1, 0)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("INIT"));
    }
}
