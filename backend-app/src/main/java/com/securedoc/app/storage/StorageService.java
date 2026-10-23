package com.securedoc.app.storage;

/**
 * 对象存储抽象（盲存储密文分块）。dev 用本地文件系统(LocalFileStorage)，
 * prod 可替换为 MinIO/S3 实现而不改业务层（设计文档 §2.6 对象存储职责）。
 * 只存取不透明字节（密文），不关心内容语义。
 */
public interface StorageService {

    /** 写入对象（覆盖）。 */
    void put(String objectKey, byte[] data);

    /** 读取对象字节。 */
    byte[] get(String objectKey);

    /** 对象是否存在。 */
    boolean exists(String objectKey);

    /** 删除对象（不存在则忽略）。 */
    void delete(String objectKey);
}
