package com.securedoc.app;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 企业级端到端加密文档投递系统 —— 应用服务器入口。
 * 职责：认证、RBAC、文件密文索引、投递关系、审计；不接触文件明文与 SM4 密钥明文。
 */
@SpringBootApplication
@MapperScan("com.securedoc.app.mapper")
public class BackendAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendAppApplication.class, args);
	}

}
