package com.securedoc.kgc;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * SM9 KGC 密钥中心（独立可信组件，端口 8081）。
 * 职责：SM9 主密钥管理、按身份签发用户私钥、签发审计。不接触文件明文与 DEK。
 */
@SpringBootApplication
@MapperScan("com.securedoc.kgc.mapper")
public class KgcServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(KgcServiceApplication.class, args);
	}

}
