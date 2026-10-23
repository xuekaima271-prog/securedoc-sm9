package com.securedoc.kgc;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
        // 测试专用 keystore: 与 kgc-service/data/ 下的真实主密钥解耦——真实钥已轮换为随机口令
        // (旧钥按已泄露处置), 测试不得依赖它, 更不得用仓库默认口令在 data/ 里再生一把。
        "kgc.master-key.passphrase=test-only-kgc-master-passphrase",
        "kgc.master-key.file=target/test-keystore/sm9-master.key"
})
class KgcServiceApplicationTests {

	@Test
	void contextLoads() {
	}

}
