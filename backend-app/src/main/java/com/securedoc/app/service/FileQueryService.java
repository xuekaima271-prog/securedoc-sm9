package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedoc.app.entity.FileRecipient;
import com.securedoc.app.entity.FileRecord;
import com.securedoc.app.mapper.FileRecipientMapper;
import com.securedoc.app.mapper.FileRecordMapper;
import com.securedoc.app.web.dto.FileSummary;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 文件投递（读侧）：收件箱 / 发件箱。只回传密文元数据与状态，绝不含明文/密钥。
 * 接收人 id 列表用一次 IN 查询批量装配（与 AdminFileService 同模式），避免逐文件 N+1。
 */
@Service
public class FileQueryService {

    private final FileRecordMapper fileMapper;
    private final FileRecipientMapper recipientMapper;
    private final ObjectMapper om = new ObjectMapper();

    public FileQueryService(FileRecordMapper fileMapper, FileRecipientMapper recipientMapper) {
        this.fileMapper = fileMapper;
        this.recipientMapper = recipientMapper;
    }

    /** 发件箱：当前用户发起的文件（任意状态，按时间倒序）。 */
    public List<FileSummary> outbox(Long userId) {
        return assemble(fileMapper.selectList(new LambdaQueryWrapper<FileRecord>()
                .eq(FileRecord::getSenderId, userId)
                .orderByDesc(FileRecord::getCreatedAt)));
    }

    /** 收件箱：当前用户作为接收人、且已 AVAILABLE 的文件。 */
    public List<FileSummary> inbox(Long userId) {
        List<FileRecipient> rs = recipientMapper.selectList(new LambdaQueryWrapper<FileRecipient>()
                .eq(FileRecipient::getRecipientId, userId));
        if (rs.isEmpty()) return List.of();
        List<String> fileIds = rs.stream().map(FileRecipient::getFileId).distinct().toList();
        return assemble(fileMapper.selectList(new LambdaQueryWrapper<FileRecord>()
                .in(FileRecord::getId, fileIds)
                .eq(FileRecord::getStatus, "AVAILABLE")
                .orderByDesc(FileRecord::getCreatedAt)));
    }

    /** 批量补齐每个文件的接收人 id 列表后逐个装配摘要。 */
    private List<FileSummary> assemble(List<FileRecord> files) {
        if (files.isEmpty()) return List.of();
        List<String> ids = files.stream().map(FileRecord::getId).toList();
        Map<String, List<Long>> recipientsByFile = recipientMapper.selectList(
                        new LambdaQueryWrapper<FileRecipient>().in(FileRecipient::getFileId, ids))
                .stream()
                .collect(Collectors.groupingBy(FileRecipient::getFileId,
                        Collectors.mapping(FileRecipient::getRecipientId, Collectors.toList())));
        return files.stream()
                .map(f -> toSummary(f, recipientsByFile.getOrDefault(f.getId(), List.of())))
                .toList();
    }

    private FileSummary toSummary(FileRecord f, List<Long> recipientIds) {
        JsonNode meta = null;
        try {
            if (f.getEncryptedMetadata() != null) meta = om.readTree(f.getEncryptedMetadata());
        } catch (Exception ignore) {
            // 元数据非法 JSON 时回传 null，不影响列表
        }
        return new FileSummary(f.getId(), f.getSenderId(), meta, f.getStatus(),
                f.getTotalSize(), f.getChunkSize(), f.getChunkCount(),
                f.getCreatedAt() == null ? null : f.getCreatedAt().toString(),
                recipientIds);
    }
}
