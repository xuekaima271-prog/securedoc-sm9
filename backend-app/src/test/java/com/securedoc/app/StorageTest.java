package com.securedoc.app;

import com.securedoc.app.common.BusinessException;
import com.securedoc.app.storage.LocalFileStorage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 本地对象存储：put/get 往返 + 存在/删除 + 路径穿越防护。 */
class StorageTest {

    @Test
    void putGetExistsDelete(@TempDir Path tmp) {
        LocalFileStorage s = new LocalFileStorage(tmp.toString());
        String key = "encrypted-files/abc-123/chunk-0.bin";
        byte[] data = {1, 2, 3, 4, 5};

        assertThat(s.exists(key)).isFalse();
        s.put(key, data);
        assertThat(s.exists(key)).isTrue();
        assertThat(s.get(key)).containsExactly(data);
        s.delete(key);
        assertThat(s.exists(key)).isFalse();
    }

    @Test
    void rejectsPathTraversal(@TempDir Path tmp) {
        LocalFileStorage s = new LocalFileStorage(tmp.toString());
        assertThrows(BusinessException.class, () -> s.put("../escape.bin", new byte[]{0}));
        assertThrows(BusinessException.class, () -> s.get("../../etc/passwd"));
    }
}
