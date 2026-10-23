package com.securedoc.app;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.app.crypto.Sm3;
import com.securedoc.app.entity.FileChunk;
import com.securedoc.app.entity.FileRecipient;
import com.securedoc.app.entity.FileRecord;
import com.securedoc.app.mapper.FileChunkMapper;
import com.securedoc.app.mapper.FileRecipientMapper;
import com.securedoc.app.mapper.FileRecordMapper;
import com.securedoc.app.storage.StorageService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 下载密文分块（§2.10 / §18.13 必做接收闭环）集成测试：
 * 接收人成功(200/octet-stream/X-Chunk-Digest/字节一致/标记DOWNLOADED)、非接收人403、
 * 未就绪400、越界400、**存储被篡改→完整性校验失败(强负例，证明 SM9-4 下载侧生效)**。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FileDownloadTest {

    @Autowired MockMvc mvc;
    @Autowired FileRecordMapper fileMapper;
    @Autowired FileRecipientMapper recipientMapper;
    @Autowired FileChunkMapper chunkMapper;
    @Autowired StorageService storage;

    private static final byte[] CHUNK0 = "CIPHERTEXT-CHUNK-0-DOWNLOAD".getBytes(StandardCharsets.UTF_8);

    /** alice(10001) → bob(10002)，AVAILABLE，1 块密文已落盘且摘要正确。返回 fileId。 */
    private String seedAvailableAliceToBob(String status) {
        String fileId = UUID.randomUUID().toString();
        FileRecord f = new FileRecord();
        f.setId(fileId); f.setSenderId(10001L);
        f.setEncryptedMetadata("{\"algorithm\":\"SM4\"}");
        f.setCiphertextRootPath("encrypted-files/" + fileId);
        f.setTotalSize((long) CHUNK0.length); f.setChunkSize(CHUNK0.length);
        f.setChunkCount(1); f.setStatus(status);
        fileMapper.insert(f);

        FileRecipient r = new FileRecipient();
        r.setFileId(fileId); r.setRecipientId(10002L);
        r.setRecipientIdentity("user:corp001:10002:bob@example.com");
        r.setKeyEnvelope("{\"algorithm\":\"SM9\",\"wrappedKey\":\"d2s=\"}");
        r.setReceiveStatus("PENDING"); r.setDownloadStatus("NONE");
        recipientMapper.insert(r);

        String objectKey = "encrypted-files/" + fileId + "/chunk-0.bin";
        FileChunk c = new FileChunk();
        c.setFileId(fileId); c.setChunkIndex(0); c.setObjectKey(objectKey);
        c.setChunkSize(CHUNK0.length); c.setSm3Digest(Sm3.digestBase64(CHUNK0));
        c.setIvNonce("aXY="); c.setUploadStatus("UPLOADED");
        chunkMapper.insert(c);
        storage.put(objectKey, CHUNK0);
        return fileId;
    }

    @Test
    @WithUserDetails("bob")
    void 接收人下载成功_摘要头与字节一致_标记DOWNLOADED() throws Exception {
        String fileId = seedAvailableAliceToBob("AVAILABLE");
        try {
            MvcResult res = mvc.perform(get("/api/files/" + fileId + "/chunks/0/download"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Content-Type", "application/octet-stream"))
                    .andExpect(header().string("X-Chunk-Digest", Sm3.digestBase64(CHUNK0)))
                    .andExpect(header().string("X-Chunk-IV", "aXY="))
                    .andReturn();
            byte[] body = res.getResponse().getContentAsByteArray();
            assertThat(body).isEqualTo(CHUNK0);

            FileRecipient r = recipientMapper.selectOne(new LambdaQueryWrapper<FileRecipient>()
                    .eq(FileRecipient::getFileId, fileId).eq(FileRecipient::getRecipientId, 10002L));
            assertThat(r.getDownloadStatus()).isEqualTo("DOWNLOADED");
            assertThat(r.getDownloadedAt()).isNotNull();
        } finally {
            storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
        }
    }

    @Test
    @WithUserDetails("carol")
    void 非接收人下载_403_NOT_RECIPIENT() throws Exception {
        String fileId = seedAvailableAliceToBob("AVAILABLE");
        try {
            mvc.perform(get("/api/files/" + fileId + "/chunks/0/download"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code").value("NOT_RECIPIENT"));
        } finally {
            storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
        }
    }

    @Test
    @WithUserDetails("bob")
    void 文件未就绪下载_400() throws Exception {
        String fileId = seedAvailableAliceToBob("UPLOADING");
        try {
            mvc.perform(get("/api/files/" + fileId + "/chunks/0/download"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        } finally {
            storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
        }
    }

    @Test
    @WithUserDetails("bob")
    void 分块越界下载_400() throws Exception {
        String fileId = seedAvailableAliceToBob("AVAILABLE");
        try {
            mvc.perform(get("/api/files/" + fileId + "/chunks/9/download"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        } finally {
            storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
        }
    }

    @Test
    @WithUserDetails("bob")
    void 存储被篡改_完整性校验失败_500() throws Exception {
        String fileId = seedAvailableAliceToBob("AVAILABLE");
        // 篡改对象存储里的密文字节（摘要仍是原文摘要）→ 下载时服务端重算 SM3 不匹配 → 拒绝
        storage.put("encrypted-files/" + fileId + "/chunk-0.bin",
                "TAMPERED-BYTES".getBytes(StandardCharsets.UTF_8));
        try {
            mvc.perform(get("/api/files/" + fileId + "/chunks/0/download"))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.code").value("INTERNAL_ERROR"));
        } finally {
            storage.delete("encrypted-files/" + fileId + "/chunk-0.bin");
        }
    }
}
