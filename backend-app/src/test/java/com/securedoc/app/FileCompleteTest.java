package com.securedoc.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedoc.app.crypto.Sm3;
import com.securedoc.app.entity.FileChunk;
import com.securedoc.app.mapper.FileChunkMapper;
import com.securedoc.app.mapper.FileRecordMapper;
import com.securedoc.app.storage.StorageService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** complete 集成测试：全块齐→AVAILABLE、缺块→400。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FileCompleteTest {

    @Autowired MockMvc mvc;
    @Autowired FileRecordMapper fileMapper;
    @Autowired FileChunkMapper chunkMapper;
    @Autowired StorageService storage;
    private final ObjectMapper om = new ObjectMapper();

    private static final String INIT_BODY = """
        {"encryptedMetadata":{"algorithm":"SM4"},"chunkSize":8,"chunkCount":2,"totalSize":16,
         "recipients":[{"recipientId":10002,"recipientIdentity":"user:corp001:10002:bob@example.com",
                        "keyEnvelope":{"algorithm":"SM9"}}]}""";

    private String init() throws Exception {
        MvcResult res = mvc.perform(post("/api/files/init-upload")
                .contentType(MediaType.APPLICATION_JSON).content(INIT_BODY))
                .andExpect(status().isOk()).andReturn();
        return om.readTree(res.getResponse().getContentAsString()).path("data").path("fileId").asText();
    }

    private void upload(String fileId, int idx) throws Exception {
        byte[] body = ("CHUNK-" + idx + "-DATA").getBytes(StandardCharsets.UTF_8);
        mvc.perform(put("/api/files/" + fileId + "/chunks/" + idx)
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header("X-Chunk-Digest", Sm3.digestBase64(body)).content(body))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("alice")
    void 全部分块上传后complete_AVAILABLE() throws Exception {
        String fileId = init();
        upload(fileId, 0);
        upload(fileId, 1);
        mvc.perform(post("/api/files/" + fileId + "/complete"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("AVAILABLE"));
        assertThat(fileMapper.selectById(fileId).getStatus()).isEqualTo("AVAILABLE");
        storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
        storage.delete("encrypted-files/" + fileId + "/chunk-1.bin");
    }

    @Test
    @WithUserDetails("alice")
    void 缺分块complete_400_UPLOAD_INCOMPLETE() throws Exception {
        String fileId = init();
        upload(fileId, 0);   // 只传 1/2
        mvc.perform(post("/api/files/" + fileId + "/complete"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("UPLOAD_INCOMPLETE"));
        storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
    }

    @Test
    @WithUserDetails("alice")
    void FILE2_数量够但index不连续_complete拒绝() throws Exception {
        String fileId = init();
        upload(fileId, 0);
        // 绕过 uploadChunk 直插一条越界 index=5 的 UPLOADED 记录（模拟脏数据/直改库）：
        // 数量 2/2 满足，但集合 {0,5} ≠ {0,1} → 必须拒绝
        FileChunk dirty = new FileChunk();
        dirty.setFileId(fileId); dirty.setChunkIndex(5);
        dirty.setObjectKey("encrypted-files/" + fileId + "/chunk-5.bin");
        dirty.setChunkSize(1); dirty.setSm3Digest("x"); dirty.setUploadStatus("UPLOADED");
        chunkMapper.insert(dirty);

        mvc.perform(post("/api/files/" + fileId + "/complete"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("UPLOAD_INCOMPLETE"));
        storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
    }
}
