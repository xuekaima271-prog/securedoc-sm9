package com.securedoc.app.storage;

import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import io.minio.BucketExistsArgs;
import io.minio.GetObjectArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import io.minio.StatObjectArgs;
import io.minio.errors.ErrorResponseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * MinIO 对象存储实现（设计文档 §2.6 可替换组件）。
 * 启用方式：securedoc.storage.type=minio（默认 local 本地文件系统，零安装）。
 * 与 LocalFileStorage 完全同语义：只存取不透明密文字节；get 不存在 → FILE_NOT_FOUND。
 * 桶不存在时启动自动创建（幂等）。
 */
@Service
@ConditionalOnProperty(name = "securedoc.storage.type", havingValue = "minio")
public class MinioStorage implements StorageService {

    private static final Logger log = LoggerFactory.getLogger(MinioStorage.class);

    private final MinioClient client;
    private final String bucket;

    public MinioStorage(
            @Value("${securedoc.storage.minio.endpoint:http://127.0.0.1:9000}") String endpoint,
            @Value("${securedoc.storage.minio.access-key:minioadmin}") String accessKey,
            @Value("${securedoc.storage.minio.secret-key:minioadmin}") String secretKey,
            @Value("${securedoc.storage.minio.bucket:securedoc}") String bucket) {
        this.bucket = bucket;
        this.client = MinioClient.builder().endpoint(endpoint).credentials(accessKey, secretKey).build();
        ensureBucket(endpoint);
    }

    private void ensureBucket(String endpoint) {
        try {
            if (!client.bucketExists(BucketExistsArgs.builder().bucket(bucket).build())) {
                client.makeBucket(MakeBucketArgs.builder().bucket(bucket).build());
                log.info("MinIO 桶已创建: {}", bucket);
            }
            log.info("MinIO 对象存储就绪: endpoint={} bucket={}", endpoint, bucket);
        } catch (Exception e) {
            // 启动即失败：MinIO 档必须有可用的 MinIO，避免运行中才发现存储不可用
            throw new IllegalStateException("MinIO 不可用（endpoint=" + endpoint + "）: " + e.getMessage(), e);
        }
    }

    @Override
    public void put(String objectKey, byte[] data) {
        try (InputStream in = new ByteArrayInputStream(data)) {
            client.putObject(PutObjectArgs.builder()
                    .bucket(bucket).object(objectKey)
                    .stream(in, data.length, -1)
                    .contentType("application/octet-stream")
                    .build());
        } catch (Exception e) {
            log.error("MinIO 写对象失败 key={}", objectKey, e);
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "对象写入失败");
        }
    }

    @Override
    public byte[] get(String objectKey) {
        try (InputStream in = client.getObject(GetObjectArgs.builder().bucket(bucket).object(objectKey).build())) {
            return in.readAllBytes();
        } catch (ErrorResponseException e) {
            if ("NoSuchKey".equals(e.errorResponse().code())) {
                throw new BusinessException(ErrorCode.FILE_NOT_FOUND, "密文分块不存在");
            }
            log.error("MinIO 读对象失败 key={}", objectKey, e);
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "对象读取失败");
        } catch (Exception e) {
            log.error("MinIO 读对象失败 key={}", objectKey, e);
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "对象读取失败");
        }
    }

    @Override
    public boolean exists(String objectKey) {
        try {
            client.statObject(StatObjectArgs.builder().bucket(bucket).object(objectKey).build());
            return true;
        } catch (ErrorResponseException e) {
            if ("NoSuchKey".equals(e.errorResponse().code())) return false;
            log.error("MinIO stat 失败 key={}", objectKey, e);
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "对象查询失败");
        } catch (Exception e) {
            log.error("MinIO stat 失败 key={}", objectKey, e);
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "对象查询失败");
        }
    }

    @Override
    public void delete(String objectKey) {
        try {
            client.removeObject(RemoveObjectArgs.builder().bucket(bucket).object(objectKey).build());
        } catch (Exception e) {
            log.error("MinIO 删除对象失败 key={}", objectKey, e);
        }
    }
}
