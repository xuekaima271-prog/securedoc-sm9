package com.securedoc.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 管理员密文记录页（§2.10 GET /api/admin/files，必做）：
 * 管理员见密文记录（含分块数/接收人数/**密文元数据**），普通员工 403；
 * 证明「管理员可审计、不可解密」——视图不含任何明文/SM4密钥/SM9私钥/信封内容。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminFileTest {

    @Autowired MockMvc mvc;
    @Autowired FileRecordMapper fileMapper;
    @Autowired FileRecipientMapper recipientMapper;
    private final ObjectMapper om = new ObjectMapper();

    /** alice 发给 bob+carol、2 块的 AVAILABLE 文件。 */
    private String seedFile() {
        String fileId = UUID.randomUUID().toString();
        FileRecord f = new FileRecord();
        f.setId(fileId); f.setSenderId(10001L);
        f.setEncryptedMetadata("{\"algorithm\":\"SM4\",\"ciphertext\":\"Y3Q=\"}");
        f.setCiphertextRootPath("encrypted-files/" + fileId);
        f.setTotalSize(48L); f.setChunkSize(24); f.setChunkCount(2); f.setStatus("AVAILABLE");
        fileMapper.insert(f);
        for (long rid : new long[]{10002L, 10003L}) {
            FileRecipient r = new FileRecipient();
            r.setFileId(fileId); r.setRecipientId(rid);
            r.setRecipientIdentity("user:corp001:" + rid + ":x@example.com");
            r.setKeyEnvelope("{\"algorithm\":\"SM9\",\"wrappedKey\":\"d2s=\"}");
            r.setReceiveStatus("PENDING"); r.setDownloadStatus("NONE");
            recipientMapper.insert(r);
        }
        return fileId;
    }

    @Test
    @WithUserDetails("admin")
    void 管理员看到密文记录_含统计与密文元数据_不含密钥() throws Exception {
        String fileId = seedFile();
        MvcResult res = mvc.perform(get("/api/admin/files"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode data = om.readTree(res.getResponse().getContentAsString()).path("data");
        assertThat(data.isArray()).isTrue();

        JsonNode mine = null;
        for (JsonNode n : data) {
            if (fileId.equals(n.path("fileId").asText())) { mine = n; break; }
        }
        assertThat(mine).as("应能查到刚 seed 的文件密文记录").isNotNull();
        assertThat(mine.path("chunkCount").asInt()).isEqualTo(2);
        assertThat(mine.path("recipientCount").asInt()).isEqualTo(2);
        assertThat(mine.path("status").asText()).isEqualTo("AVAILABLE");
        // 密文元数据可见（证明是密文，非明文文件名）
        assertThat(mine.path("encryptedMetadata").path("algorithm").asText()).isEqualTo("SM4");
        // 安全红线：视图不得出现任何密钥/信封字段
        assertThat(mine.has("keyEnvelope")).isFalse();
        assertThat(mine.toString()).doesNotContain("wrappedKey");
    }

    @Test
    @WithUserDetails("alice")
    void 普通员工查密文记录_403() throws Exception {
        mvc.perform(get("/api/admin/files"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }
}
