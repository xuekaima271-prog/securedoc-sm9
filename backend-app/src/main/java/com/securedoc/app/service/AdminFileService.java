package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedoc.app.entity.FileRecipient;
import com.securedoc.app.entity.FileRecord;
import com.securedoc.app.mapper.FileRecipientMapper;
import com.securedoc.app.mapper.FileRecordMapper;
import com.securedoc.app.web.dto.AdminFileView;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 管理员密文记录装配（§2.9）。只暴露密文视角（密文元数据 + 分块/接收人统计），
 * 绝不含明文/SM4密钥/SM9私钥/信封内容。用 2 次查询装配，避免逐文件 N+1。
 */
@Service
public class AdminFileService {

    private final FileRecordMapper fileMapper;
    private final FileRecipientMapper recipientMapper;
    private final ObjectMapper om = new ObjectMapper();

    public AdminFileService(FileRecordMapper fileMapper, FileRecipientMapper recipientMapper) {
        this.fileMapper = fileMapper;
        this.recipientMapper = recipientMapper;
    }

    /** 列出全部文件密文记录（按时间倒序）。 */
    public List<AdminFileView> listFiles() {
        List<FileRecord> files = fileMapper.selectList(new LambdaQueryWrapper<FileRecord>()
                .orderByDesc(FileRecord::getCreatedAt));
        if (files.isEmpty()) return List.of();

        List<String> ids = files.stream().map(FileRecord::getId).toList();
        Map<String, List<Long>> recipientsByFile = recipientMapper.selectList(
                        new LambdaQueryWrapper<FileRecipient>().in(FileRecipient::getFileId, ids))
                .stream()
                .collect(Collectors.groupingBy(FileRecipient::getFileId,
                        Collectors.mapping(FileRecipient::getRecipientId, Collectors.toList())));

        return files.stream().map(f -> {
            List<Long> recs = recipientsByFile.getOrDefault(f.getId(), List.of());
            return new AdminFileView(
                    f.getId(), f.getSenderId(), f.getStatus(),
                    f.getTotalSize(), f.getChunkSize(), f.getChunkCount(),
                    recs.size(), recs, parse(f.getEncryptedMetadata()),
                    f.getCreatedAt() == null ? null : f.getCreatedAt().toString());
        }).toList();
    }

    private JsonNode parse(String json) {
        try {
            return json == null ? null : om.readTree(json);
        } catch (Exception ignore) {
            return null;   // 非法 JSON 不阻断列表
        }
    }
}
