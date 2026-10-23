package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.crypto.Sm3;
import com.securedoc.app.entity.FileChunk;
import com.securedoc.app.entity.FileRecipient;
import com.securedoc.app.entity.FileRecord;
import com.securedoc.app.mapper.FileChunkMapper;
import com.securedoc.app.mapper.FileRecipientMapper;
import com.securedoc.app.mapper.FileRecordMapper;
import com.securedoc.app.storage.StorageService;
import com.securedoc.app.web.dto.ChunkDownload;
import com.securedoc.app.web.dto.KeyEnvelopeResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * 文件接收（接收人侧）：取密钥信封、下载密文分块（含 SM3 防篡改校验）。
 * 所有操作均校验「当前用户是该文件的接收人」，并写审计。
 */
@Service
public class FileDownloadService {

    private static final Logger log = LoggerFactory.getLogger(FileDownloadService.class);

    private final FileRecordMapper fileMapper;
    private final FileRecipientMapper recipientMapper;
    private final FileChunkMapper chunkMapper;
    private final StorageService storage;
    private final AuditService auditService;
    private final ObjectMapper om = new ObjectMapper();

    private final SecurityEventService securityEvents;

    public FileDownloadService(FileRecordMapper fileMapper,
                               FileRecipientMapper recipientMapper,
                               FileChunkMapper chunkMapper,
                               StorageService storage,
                               AuditService auditService,
                               SecurityEventService securityEvents) {
        this.fileMapper = fileMapper;
        this.recipientMapper = recipientMapper;
        this.chunkMapper = chunkMapper;
        this.storage = storage;
        this.auditService = auditService;
        this.securityEvents = securityEvents;
    }

    /** 校验并取出「当前用户在该文件下」的接收人记录；非接收人抛 NOT_RECIPIENT + 记安全事件（§2.2.12）。 */
    FileRecipient requireRecipient(Long userId, String fileId) {
        FileRecipient r = recipientMapper.selectOne(new LambdaQueryWrapper<FileRecipient>()
                .eq(FileRecipient::getFileId, fileId)
                .eq(FileRecipient::getRecipientId, userId));
        if (r == null) {
            securityEvents.record("UNAUTHORIZED_FILE_ACCESS", SecurityEventService.HIGH, userId,
                    null, fileId, "非接收人尝试访问文件（密钥信封/密文分块）");
            throw new BusinessException(ErrorCode.NOT_RECIPIENT);
        }
        return r;
    }

    /** 取密钥信封：仅接收人本人；标记 receive_status=READ；审计。 */
    @Transactional
    public KeyEnvelopeResponse getKeyEnvelope(Long userId, String fileId, String clientIp) {
        FileRecipient r = requireRecipient(userId, fileId);
        if (!"READ".equals(r.getReceiveStatus())) {
            r.setReceiveStatus("READ");
            recipientMapper.updateById(r);
        }
        JsonNode env = null;
        try {
            if (r.getKeyEnvelope() != null) env = om.readTree(r.getKeyEnvelope());
        } catch (Exception ignore) {
            // 信封非法 JSON 不应发生（写入时为对象），回传 null 以免 500
        }
        auditService.record(userId, "FILE_ENVELOPE", "FILE", fileId, clientIp, null, "获取密钥信封");
        log.info("key-envelope: fileId={} recipient={}", fileId, userId);
        return new KeyEnvelopeResponse(fileId, r.getRecipientIdentity(), env);
    }

    /**
     * 下载一个密文分块（§2.10 / §18.13 必做接收闭环）：仅接收人本人；文件须 AVAILABLE；
     * 服务端从对象存储取出后**重算 SM3 与入库摘要比对**（SM9-4 下载侧：防对象存储被篡改/损坏），
     * 通过后回传不透明密文字节 + 摘要 + IV，浏览器解密前再次校验。标记下载状态并写审计。
     */
    @Transactional
    public ChunkDownload downloadChunk(Long userId, String fileId, int chunkIndex, String clientIp) {
        FileRecipient r = requireRecipient(userId, fileId);

        FileRecord f = fileMapper.selectById(fileId);
        if (f == null) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
        }
        if (!"AVAILABLE".equals(f.getStatus())) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "文件尚未就绪（未完成上传）");
        }
        if (chunkIndex < 0 || chunkIndex >= f.getChunkCount()) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "分块序号越界");
        }

        FileChunk c = chunkMapper.selectOne(new LambdaQueryWrapper<FileChunk>()
                .eq(FileChunk::getFileId, fileId)
                .eq(FileChunk::getChunkIndex, chunkIndex));
        if (c == null) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND, "密文分块不存在");
        }

        byte[] data = storage.get(c.getObjectKey());

        // SM9-4 下载侧完整性：服务端重算 SM3，与入库摘要比对，发现存储被篡改/损坏即拒绝
        String recomputed = Sm3.digestBase64(data);
        if (!recomputed.equals(c.getSm3Digest())) {
            log.error("分块完整性校验失败 fileId={} index={} 存储摘要={} 实算={}",
                    fileId, chunkIndex, c.getSm3Digest(), recomputed);
            securityEvents.record("CHUNK_TAMPER_DETECTED", SecurityEventService.HIGH, userId, clientIp,
                    fileId + "#chunk-" + chunkIndex, "对象存储密文分块 SM3 与入库摘要不符（疑似被篡改/损坏）");
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "密文分块完整性校验失败");
        }

        // 标记下载状态（任一分块下载即视为已下载，简化版；下载日志见审计）
        if (!"DOWNLOADED".equals(r.getDownloadStatus())) {
            r.setDownloadStatus("DOWNLOADED");
            r.setDownloadedAt(LocalDateTime.now());
            recipientMapper.updateById(r);
        }
        auditService.record(userId, "FILE_DOWNLOAD", "FILE", fileId, clientIp, null,
                "下载密文分块 index=" + chunkIndex);
        log.info("download-chunk: fileId={} recipient={} index={} bytes={}",
                fileId, userId, chunkIndex, data.length);
        return new ChunkDownload(chunkIndex, data, c.getSm3Digest(), c.getIvNonce());
    }
}
