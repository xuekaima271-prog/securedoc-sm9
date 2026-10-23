package com.securedoc.app;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** 取密钥信封：接收人本人 200、非接收人 403、发送人(非接收人) 403。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FileKeyEnvelopeTest {

    @Autowired MockMvc mvc;
    @Autowired FileRecordMapper fileMapper;
    @Autowired FileRecipientMapper recipientMapper;

    private String seedAliceToBob() {
        String fileId = UUID.randomUUID().toString();
        FileRecord f = new FileRecord();
        f.setId(fileId); f.setSenderId(10001L);
        f.setEncryptedMetadata("{\"algorithm\":\"SM4\"}");
        f.setCiphertextRootPath("encrypted-files/" + fileId);
        f.setTotalSize(10L); f.setChunkSize(10); f.setChunkCount(1); f.setStatus("AVAILABLE");
        fileMapper.insert(f);
        FileRecipient r = new FileRecipient();
        r.setFileId(fileId); r.setRecipientId(10002L);
        r.setRecipientIdentity("user:corp001:10002:bob@example.com");
        r.setKeyEnvelope("{\"algorithm\":\"SM9\",\"wrappedKey\":\"d2s=\",\"keyDigest\":\"a2Q=\"}");
        r.setReceiveStatus("PENDING"); r.setDownloadStatus("NONE");
        recipientMapper.insert(r);
        return fileId;
    }

    @Test
    @WithUserDetails("bob")
    void 接收人取到信封并标记READ() throws Exception {
        String fileId = seedAliceToBob();
        mvc.perform(get("/api/files/" + fileId + "/recipients/me/key-envelope"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.recipientIdentity").value("user:corp001:10002:bob@example.com"))
                .andExpect(jsonPath("$.data.keyEnvelope.algorithm").value("SM9"))
                .andExpect(jsonPath("$.data.keyEnvelope.wrappedKey").value("d2s="));
        FileRecipient r = recipientMapper.selectOne(new LambdaQueryWrapper<FileRecipient>()
                .eq(FileRecipient::getFileId, fileId).eq(FileRecipient::getRecipientId, 10002L));
        assertThat(r.getReceiveStatus()).isEqualTo("READ");
    }

    @Test
    @WithUserDetails("carol")
    void 非接收人取信封_403_NOT_RECIPIENT() throws Exception {
        String fileId = seedAliceToBob();
        mvc.perform(get("/api/files/" + fileId + "/recipients/me/key-envelope"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("NOT_RECIPIENT"));
    }

    @Test
    @WithUserDetails("alice")
    void 发送人非接收人取信封_403() throws Exception {
        String fileId = seedAliceToBob();
        mvc.perform(get("/api/files/" + fileId + "/recipients/me/key-envelope"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("NOT_RECIPIENT"));
    }
}
