package com.securedoc.app;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedoc.app.crypto.Sm3;
import com.securedoc.app.entity.FileChunk;
import com.securedoc.app.entity.FileRecord;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** 分块上传集成测试：正确摘要→UPLOADED、错摘要→400、非发送人→403。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FileChunkUploadTest {

    @Autowired MockMvc mvc;
    @Autowired FileRecordMapper fileMapper;
    @Autowired FileChunkMapper chunkMapper;
    @Autowired StorageService storage;
    private final ObjectMapper om = new ObjectMapper();

    private static final byte[] CHUNK0 = "CIPHERTEXT-CHUNK-0-BYTES".getBytes(StandardCharsets.UTF_8);

    private static final String INIT_BODY = """
        {"encryptedMetadata":{"algorithm":"SM4","iv":"aXY=","ciphertext":"Y3Q=","digest":"ZA=="},
         "chunkSize":24,"chunkCount":2,"totalSize":48,
         "recipients":[{"recipientId":10002,"recipientIdentity":"user:corp001:10002:bob@example.com",
                        "keyEnvelope":{"algorithm":"SM9","wrappedKey":"d2s="}}]}""";

    private String initAsAlice() throws Exception {
        MvcResult res = mvc.perform(post("/api/files/init-upload")
                        .contentType(MediaType.APPLICATION_JSON).content(INIT_BODY))
                .andExpect(status().isOk()).andReturn();
        return om.readTree(res.getResponse().getContentAsString()).path("data").path("fileId").asText();
    }

    @Test
    @WithUserDetails("alice")
    void 正确摘要上传_UPLOADED且落盘() throws Exception {
        String fileId = initAsAlice();
        String digest = Sm3.digestBase64(CHUNK0);

        mvc.perform(put("/api/files/" + fileId + "/chunks/0")
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .header("X-Chunk-Digest", digest).header("X-Chunk-IV", "aXY=")
                        .content(CHUNK0))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("UPLOADED"))
                .andExpect(jsonPath("$.data.chunkIndex").value(0));

        FileChunk c = chunkMapper.selectOne(new LambdaQueryWrapper<FileChunk>()
                .eq(FileChunk::getFileId, fileId).eq(FileChunk::getChunkIndex, 0));
        assertThat(c).isNotNull();
        assertThat(c.getUploadStatus()).isEqualTo("UPLOADED");
        assertThat(c.getSm3Digest()).isEqualTo(digest);
        assertThat(storage.exists("encrypted-files/" + fileId + "/chunk-0.bin")).isTrue();
        assertThat(fileMapper.selectById(fileId).getStatus()).isEqualTo("UPLOADING");
        // 清理本地对象（@Transactional 不回滚文件系统）
        storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
    }

    @Test
    @WithUserDetails("alice")
    void 摘要不匹配_400() throws Exception {
        String fileId = initAsAlice();
        mvc.perform(put("/api/files/" + fileId + "/chunks/0")
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .header("X-Chunk-Digest", "WRONGDIGEST==")
                        .content(CHUNK0))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @WithUserDetails("bob")
    void 非发送人上传_403() throws Exception {
        // 直接造一个 alice(10001) 的文件，bob 尝试上传
        String fileId = UUID.randomUUID().toString();
        FileRecord f = new FileRecord();
        f.setId(fileId); f.setSenderId(10001L);
        f.setEncryptedMetadata("{}"); f.setCiphertextRootPath("encrypted-files/" + fileId);
        f.setTotalSize(24L); f.setChunkSize(24); f.setChunkCount(1); f.setStatus("INIT");
        fileMapper.insert(f);

        mvc.perform(put("/api/files/" + fileId + "/chunks/0")
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .header("X-Chunk-Digest", Sm3.digestBase64(CHUNK0))
                        .content(CHUNK0))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }
}
