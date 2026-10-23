package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.crypto.Sm3;
import com.securedoc.app.entity.FileChunk;
import com.securedoc.app.entity.FileRecipient;
import com.securedoc.app.entity.FileRecord;
import com.securedoc.app.entity.UserKey;
import com.securedoc.app.mapper.FileChunkMapper;
import com.securedoc.app.mapper.FileRecipientMapper;
import com.securedoc.app.mapper.FileRecordMapper;
import com.securedoc.app.mapper.UserKeyMapper;
import com.securedoc.app.storage.StorageService;
import com.securedoc.app.web.dto.ChunkUploadResponse;
import com.securedoc.app.web.dto.InitUploadRequest;
import com.securedoc.app.web.dto.InitUploadResponse;
import com.securedoc.app.web.dto.RecipientInput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * 文件投递（写侧）：初始化上传任务、接收密文分块、完成上传。
 * 应用服务器盲存储：只存 SM4 加密元数据、SM9 密钥信封、密文分块（不透明字节），无法解密。
 * 每块上传时服务端重算 SM3 并核对客户端声明摘要（账本 SM9-4 上传完整性）。
 */
@Service
public class FileUploadService {

    private static final Logger log = LoggerFactory.getLogger(FileUploadService.class);

    private final FileRecordMapper fileMapper;
    private final FileRecipientMapper recipientMapper;
    private final FileChunkMapper chunkMapper;
    private final UserKeyMapper userKeyMapper;
    private final StorageService storage;
    private final AuditService auditService;
    private final SecurityEventService securityEvents;
    private final long maxChunkSize;
    private final int maxChunkCount;
    private final long maxTotalSize;

    public FileUploadService(FileRecordMapper fileMapper,
                             FileRecipientMapper recipientMapper,
                             FileChunkMapper chunkMapper,
                             UserKeyMapper userKeyMapper,
                             StorageService storage,
                             AuditService auditService,
                             SecurityEventService securityEvents,
                             @Value("${securedoc.file.max-chunk-size:8388608}") long maxChunkSize,
                             @Value("${app.upload.max-chunk-count:10000}") int maxChunkCount,
                             @Value("${app.upload.max-total-size:2147483648}") long maxTotalSize) {
        this.fileMapper = fileMapper;
        this.recipientMapper = recipientMapper;
        this.chunkMapper = chunkMapper;
        this.userKeyMapper = userKeyMapper;
        this.storage = storage;
        this.auditService = auditService;
        this.securityEvents = securityEvents;
        this.maxChunkSize = maxChunkSize;
        this.maxChunkCount = maxChunkCount;
        this.maxTotalSize = maxTotalSize;
    }

    @Transactional
    public InitUploadResponse init(Long senderId, InitUploadRequest req) {
        // M-2 总量上限：分块数/声明总量/单块大小均设业务上限（阈值见 app.upload.* 配置），
        // 防单个账号声明海量分块逐块写满对象存储磁盘；先于接收人校验拦截，失败不落任何数据。
        if (req.chunkCount() > maxChunkCount) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST,
                    "分块数超过上限 " + maxChunkCount);
        }
        if (req.totalSize() > maxTotalSize) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST,
                    "文件总大小超过上限 " + maxTotalSize + " 字节");
        }
        if (req.chunkSize() > maxChunkSize) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST,
                    "单块大小超过上限 " + maxChunkSize + " 字节");
        }
        // 一致性：chunkCount 必须恰为 ceil(totalSize/chunkSize)（空文件记 1 块，与前端 sealFile 口径一致），
        // 防声明的分块数与总大小脱节（评审 M-2 附带项）。
        long expectedChunks = req.totalSize() == 0 ? 1
                : (req.totalSize() + req.chunkSize() - 1) / req.chunkSize();
        if (req.chunkCount() != expectedChunks) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST,
                    "分块数与文件总大小不一致");
        }
        for (RecipientInput r : req.recipients()) {
            UserKey uk = userKeyMapper.selectByUserId(r.recipientId());
            if (uk == null || !uk.getSm9Identity().equals(r.recipientIdentity())) {
                throw new BusinessException(ErrorCode.INVALID_REQUEST,
                        "接收人不存在或身份标识不匹配: userId=" + r.recipientId());
            }
        }

        String fileId = UUID.randomUUID().toString();
        FileRecord f = new FileRecord();
        f.setId(fileId);
        f.setSenderId(senderId);
        f.setEncryptedMetadata(req.encryptedMetadata().toString());
        f.setCiphertextRootPath("encrypted-files/" + fileId);
        f.setTotalSize(req.totalSize());
        f.setChunkSize(req.chunkSize());
        f.setChunkCount(req.chunkCount());
        f.setStatus("INIT");
        fileMapper.insert(f);

        for (RecipientInput r : req.recipients()) {
            FileRecipient fr = new FileRecipient();
            fr.setFileId(fileId);
            fr.setRecipientId(r.recipientId());
            fr.setRecipientIdentity(r.recipientIdentity());
            fr.setKeyEnvelope(r.keyEnvelope().toString());
            fr.setReceiveStatus("PENDING");
            fr.setDownloadStatus("NONE");
            recipientMapper.insert(fr);
        }

        log.info("init-upload: fileId={} sender={} recipients={} chunks={}",
                fileId, senderId, req.recipients().size(), req.chunkCount());
        return new InitUploadResponse(fileId, "INIT");
    }

    /** 接收一个密文分块：仅发送人本人；服务端 SM3 核对声明摘要；存对象 + 落 file_chunks。 */
    @Transactional
    public ChunkUploadResponse uploadChunk(Long senderId, String fileId, int chunkIndex,
                                           byte[] body, String declaredDigestB64, String ivB64) {
        FileRecord f = fileMapper.selectById(fileId);
        if (f == null) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
        }
        if (!f.getSenderId().equals(senderId)) {
            throw new BusinessException(ErrorCode.PERMISSION_DENIED, "只能上传自己发起的文件");
        }
        if (!("INIT".equals(f.getStatus()) || "UPLOADING".equals(f.getStatus()))) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "当前文件状态不允许上传分块");
        }
        if (chunkIndex < 0 || chunkIndex >= f.getChunkCount()) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "分块序号越界");
        }
        if (body == null || body.length == 0) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "分块内容为空");
        }
        if (body.length > maxChunkSize) {
            securityEvents.record("OVERSIZED_CHUNK", SecurityEventService.MEDIUM, senderId, null,
                    fileId + "#chunk-" + chunkIndex,
                    "分块 " + body.length + "B 超过上限 " + maxChunkSize + "B（§2.2.12 超大上传异常）");
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "分块超过大小上限");
        }

        // SM9-4 上传完整性：服务端重算 SM3，必须与客户端声明摘要一致
        String serverDigest = Sm3.digestBase64(body);
        if (declaredDigestB64 != null && !declaredDigestB64.isBlank()
                && !serverDigest.equals(declaredDigestB64)) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "分块 SM3 摘要不匹配（疑似传输损坏/篡改）");
        }

        String objectKey = "encrypted-files/" + fileId + "/chunk-" + chunkIndex + ".bin";
        storage.put(objectKey, body);

        FileChunk existing = chunkMapper.selectOne(new LambdaQueryWrapper<FileChunk>()
                .eq(FileChunk::getFileId, fileId).eq(FileChunk::getChunkIndex, chunkIndex));
        FileChunk c = existing != null ? existing : new FileChunk();
        c.setFileId(fileId);
        c.setChunkIndex(chunkIndex);
        c.setObjectKey(objectKey);
        c.setChunkSize(body.length);
        c.setSm3Digest(serverDigest);
        c.setIvNonce(ivB64);
        c.setUploadStatus("UPLOADED");
        if (existing != null) chunkMapper.updateById(c); else chunkMapper.insert(c);

        if ("INIT".equals(f.getStatus())) {
            f.setStatus("UPLOADING");
            fileMapper.updateById(f);
        }
        return new ChunkUploadResponse(fileId, chunkIndex, "UPLOADED");
    }

    /** 完成上传：校验所有分块已上传且数量匹配 → 文件置 AVAILABLE；仅发送人；写审计。 */
    @Transactional
    public InitUploadResponse complete(Long senderId, String fileId, String clientIp) {
        FileRecord f = fileMapper.selectById(fileId);
        if (f == null) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
        }
        if (!f.getSenderId().equals(senderId)) {
            throw new BusinessException(ErrorCode.PERMISSION_DENIED, "只能完成自己发起的文件");
        }
        // FILE-2：显式校验已上传 index 集合恰为 0..chunkCount-1（数量+连续性，防直插库造成空洞/越界）
        java.util.Set<Integer> uploadedIdx = chunkMapper.selectList(new LambdaQueryWrapper<FileChunk>()
                        .eq(FileChunk::getFileId, fileId).eq(FileChunk::getUploadStatus, "UPLOADED"))
                .stream().map(FileChunk::getChunkIndex)
                .collect(java.util.stream.Collectors.toSet());
        if (uploadedIdx.size() != f.getChunkCount()) {
            throw new BusinessException(ErrorCode.UPLOAD_INCOMPLETE,
                    "分块未全部上传：已上传 " + uploadedIdx.size() + " / 应有 " + f.getChunkCount());
        }
        for (int i = 0; i < f.getChunkCount(); i++) {
            if (!uploadedIdx.contains(i)) {
                throw new BusinessException(ErrorCode.UPLOAD_INCOMPLETE, "分块序号不连续：缺少 index=" + i);
            }
        }
        f.setStatus("AVAILABLE");
        fileMapper.updateById(f);
        auditService.record(senderId, "FILE_UPLOAD", "FILE", fileId, clientIp, null,
                "完成密文文件上传，分块数=" + f.getChunkCount());
        log.info("complete: fileId={} sender={} → AVAILABLE", fileId, senderId);
        return new InitUploadResponse(fileId, "AVAILABLE");
    }
}
