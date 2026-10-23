package com.securedoc.app;

import com.securedoc.app.entity.FileRecipient;
import com.securedoc.app.entity.FileRecord;
import com.securedoc.app.mapper.FileRecipientMapper;
import com.securedoc.app.mapper.FileRecordMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** 收件箱/发件箱集成测试：发送人见 outbox、接收人见 inbox(仅 AVAILABLE)、无关人皆空。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FileInboxOutboxTest {

    @Autowired MockMvc mvc;
    @Autowired FileRecordMapper fileMapper;
    @Autowired FileRecipientMapper recipientMapper;

    /** 造一份 alice(10001)→bob(10002) 的文件，返回 fileId。 */
    private String seed(String status) {
        String fileId = UUID.randomUUID().toString();
        FileRecord f = new FileRecord();
        f.setId(fileId); f.setSenderId(10001L);
        f.setEncryptedMetadata("{\"algorithm\":\"SM4\",\"fileNameLen\":1}");
        f.setCiphertextRootPath("encrypted-files/" + fileId);
        f.setTotalSize(10L); f.setChunkSize(10); f.setChunkCount(1); f.setStatus(status);
        fileMapper.insert(f);
        FileRecipient r = new FileRecipient();
        r.setFileId(fileId); r.setRecipientId(10002L);
        r.setRecipientIdentity("user:corp001:10002:bob@example.com");
        r.setKeyEnvelope("{\"algorithm\":\"SM9\"}");
        r.setReceiveStatus("PENDING"); r.setDownloadStatus("NONE");
        recipientMapper.insert(r);
        return fileId;
    }

    @Test
    @WithUserDetails("alice")
    void Alice发件箱含其发出的文件() throws Exception {
        String fileId = seed("AVAILABLE");
        mvc.perform(get("/api/files/outbox"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[?(@.fileId=='" + fileId + "')]").exists())
                .andExpect(jsonPath("$.data[0].encryptedMetadata.algorithm").value("SM4"));
    }

    @Test
    @WithUserDetails("alice")
    void Alice发件箱条目带接收人Ids() throws Exception {   // FileSummary.recipientIds（发件箱「接收人」列数据源）
        String fileId = seed("AVAILABLE");
        mvc.perform(get("/api/files/outbox"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[?(@.fileId=='" + fileId + "')].recipientIds[0]").value(10002));
    }

    @Test
    @WithUserDetails("bob")
    void Bob收件箱含发给他的AVAILABLE文件() throws Exception {
        String fileId = seed("AVAILABLE");
        mvc.perform(get("/api/files/inbox"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[?(@.fileId=='" + fileId + "')]").exists());
    }

    @Test
    @WithUserDetails("bob")
    void Bob收件箱不含未完成文件() throws Exception {
        seed("UPLOADING");   // 未 AVAILABLE
        mvc.perform(get("/api/files/inbox"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(0));
    }

    @Test
    @WithUserDetails("carol")
    void 无关人Carol收发件箱皆空() throws Exception {
        seed("AVAILABLE");   // 发给 bob，与 carol 无关
        mvc.perform(get("/api/files/inbox"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.length()").value(0));
        mvc.perform(get("/api/files/outbox"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.length()").value(0));
    }
}
