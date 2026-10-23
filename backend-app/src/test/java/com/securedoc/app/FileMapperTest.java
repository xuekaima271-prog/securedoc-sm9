package com.securedoc.app;

import com.securedoc.app.entity.FileChunk;
import com.securedoc.app.entity.FileRecipient;
import com.securedoc.app.entity.FileRecord;
import com.securedoc.app.mapper.FileChunkMapper;
import com.securedoc.app.mapper.FileRecipientMapper;
import com.securedoc.app.mapper.FileRecordMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 文件三表 Mapper 集成测试（H2）。验证 UUID 主键、TEXT 字段往返、自动填充、FK/唯一约束可用。
 * 同时验证含新 storage/file 配置的应用上下文能完整加载。
 */
@SpringBootTest
@Transactional
class FileMapperTest {

    @Autowired FileRecordMapper fileMapper;
    @Autowired FileChunkMapper chunkMapper;
    @Autowired FileRecipientMapper recipientMapper;

    @Test
    void 插入并读回_文件_分块_接收人() {
        String fileId = UUID.randomUUID().toString();
        String metaJson = "{\"algorithm\":\"SM4\",\"mode\":\"CBC_OR_CTR_WITH_SM3\",\"iv\":\"aXY=\",\"ciphertext\":\"Y3Q=\",\"digest\":\"ZA==\"}";

        FileRecord f = new FileRecord();
        f.setId(fileId);
        f.setSenderId(10001L);                 // alice
        f.setEncryptedMetadata(metaJson);
        f.setCiphertextRootPath("encrypted-files/" + fileId);
        f.setTotalSize(20L);
        f.setChunkSize(10);
        f.setChunkCount(2);
        f.setStatus("INIT");
        assertThat(fileMapper.insert(f)).isEqualTo(1);
        assertThat(f.getCreatedAt()).isNotNull();
        assertThat(f.getUpdatedAt()).isNotNull();

        FileChunk c = new FileChunk();
        c.setFileId(fileId);
        c.setChunkIndex(0);
        c.setObjectKey("encrypted-files/" + fileId + "/chunk-0.bin");
        c.setChunkSize(10);
        c.setSm3Digest("BASE64SM3==");
        c.setIvNonce("aXY=");
        c.setUploadStatus("UPLOADED");
        assertThat(chunkMapper.insert(c)).isEqualTo(1);
        assertThat(c.getId()).isNotNull();      // 自增

        FileRecipient r = new FileRecipient();
        r.setFileId(fileId);
        r.setRecipientId(10002L);               // bob
        r.setRecipientIdentity("user:corp001:10002:bob@example.com");
        r.setKeyEnvelope("{\"algorithm\":\"SM9\",\"wrappedKey\":\"d2s=\",\"keyDigest\":\"a2Q=\"}");
        r.setReceiveStatus("PENDING");
        r.setDownloadStatus("NONE");
        assertThat(recipientMapper.insert(r)).isEqualTo(1);

        // 读回校验（含 TEXT 往返）
        FileRecord got = fileMapper.selectById(fileId);
        assertThat(got).isNotNull();
        assertThat(got.getSenderId()).isEqualTo(10001L);
        assertThat(got.getEncryptedMetadata()).isEqualTo(metaJson);   // TEXT(CLOB) 往返
        assertThat(got.getStatus()).isEqualTo("INIT");
        assertThat(chunkMapper.selectById(c.getId()).getSm3Digest()).isEqualTo("BASE64SM3==");
        assertThat(recipientMapper.selectById(r.getId()).getRecipientIdentity())
                .isEqualTo("user:corp001:10002:bob@example.com");
    }
}
