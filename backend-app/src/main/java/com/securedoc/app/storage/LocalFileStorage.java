package com.securedoc.app.storage;

import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 本地文件系统对象存储（dev，零安装，仿 H2 思路）。
 * 根目录由 securedoc.storage.local-root 配置（默认 data/object-store，已 gitignore）。
 * 防路径穿越：objectKey 解析后必须仍位于根目录内。
 */
@Service
@ConditionalOnProperty(name = "securedoc.storage.type", havingValue = "local", matchIfMissing = true)
public class LocalFileStorage implements StorageService {

    private static final Logger log = LoggerFactory.getLogger(LocalFileStorage.class);

    private final Path root;

    public LocalFileStorage(@Value("${securedoc.storage.local-root:data/object-store}") String root) {
        this.root = Path.of(root).toAbsolutePath().normalize();
        log.info("本地对象存储根目录: {}", this.root);
    }

    private Path resolve(String objectKey) {
        if (objectKey == null || objectKey.isBlank()) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "对象键不能为空");
        }
        Path p = root.resolve(objectKey).normalize();
        if (!p.startsWith(root)) {   // 防 ../ 路径穿越
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "非法对象键");
        }
        return p;
    }

    @Override
    public void put(String objectKey, byte[] data) {
        Path p = resolve(objectKey);
        try {
            if (p.getParent() != null) Files.createDirectories(p.getParent());
            Files.write(p, data);
        } catch (IOException e) {
            log.error("写对象失败 key={}", objectKey, e);
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "对象写入失败");
        }
    }

    @Override
    public byte[] get(String objectKey) {
        Path p = resolve(objectKey);
        try {
            return Files.readAllBytes(p);
        } catch (IOException e) {
            log.error("读对象失败 key={}", objectKey, e);
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND, "密文分块不存在");
        }
    }

    @Override
    public boolean exists(String objectKey) {
        return Files.exists(resolve(objectKey));
    }

    @Override
    public void delete(String objectKey) {
        try {
            Files.deleteIfExists(resolve(objectKey));
        } catch (IOException e) {
            log.error("删除对象失败 key={}", objectKey, e);
        }
    }
}
