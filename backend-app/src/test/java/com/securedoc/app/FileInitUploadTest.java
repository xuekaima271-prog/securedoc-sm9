package com.securedoc.app;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
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
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** init-upload 集成测试。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FileInitUploadTest {

    @Autowired MockMvc mvc;
    @Autowired FileRecordMapper fileMapper;
    @Autowired FileRecipientMapper recipientMapper;
    private final ObjectMapper om = new ObjectMapper();

    private static final String BODY_BOB = """
        {
          "encryptedMetadata": {"algorithm":"SM4","mode":"CBC_OR_CTR_WITH_SM3","iv":"aXY=","ciphertext":"Y3Q=","digest":"ZA=="},
          "chunkSize": 10, "chunkCount": 2, "totalSize": 20,
          "recipients": [
            {"recipientId":10002,"recipientIdentity":"user:corp001:10002:bob@example.com",
             "keyEnvelope":{"algorithm":"SM9","wrappedKey":"d2s=","keyDigest":"a2Q="}}
          ]
        }""";

    @Test
    @WithUserDetails("alice")
    void Alice发起上传_落库文件与接收人() throws Exception {
        MvcResult res = mvc.perform(post("/api/files/init-upload")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY_BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.status").value("INIT"))
                .andExpect(jsonPath("$.data.fileId").isNotEmpty())
                .andReturn();

        JsonNode root = om.readTree(res.getResponse().getContentAsString());
        String fileId = root.path("data").path("fileId").asText();

        FileRecord f = fileMapper.selectById(fileId);
        assertThat(f).isNotNull();
        assertThat(f.getSenderId()).isEqualTo(10001L);   // alice
        assertThat(f.getChunkCount()).isEqualTo(2);
        assertThat(f.getStatus()).isEqualTo("INIT");

        Long recips = recipientMapper.selectCount(
                new LambdaQueryWrapper<FileRecipient>().eq(FileRecipient::getFileId, fileId));
        assertThat(recips).isEqualTo(1L);
    }

    @Test
    @WithUserDetails("alice")
    void 接收人身份不匹配_400() throws Exception {
        String bad = BODY_BOB.replace("bob@example.com", "wrong@example.com");
        mvc.perform(post("/api/files/init-upload")
                        .contentType(MediaType.APPLICATION_JSON).content(bad))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    void 未登录_401() throws Exception {
        mvc.perform(post("/api/files/init-upload")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY_BOB))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }
}
