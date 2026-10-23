package com.securedoc.app;

import com.securedoc.app.entity.User;
import com.securedoc.app.entity.UserKey;
import com.securedoc.app.mapper.RoleMapper;
import com.securedoc.app.mapper.UserKeyMapper;
import com.securedoc.app.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Step 3.2 集成测试：验证实体/Mapper、种子数据、自动填充(DB-4)、自增主键策略。
 * @Transactional 每个测试结束回滚，保证用例相互独立（插入测试不污染计数测试）。
 */
@SpringBootTest
@Transactional
class MapperIntegrationTests {

    @Autowired UserMapper userMapper;
    @Autowired RoleMapper roleMapper;
    @Autowired UserKeyMapper userKeyMapper;

    @Test
    void 种子数据已加载_5个账号() {
        assertThat(userMapper.selectCount(null)).isEqualTo(5L);
    }

    @Test
    void 按用户名查到alice() {
        User alice = userMapper.selectByUsername("alice");
        assertThat(alice).isNotNull();
        assertThat(alice.getId()).isEqualTo(10001L);
        assertThat(alice.getEmail()).isEqualTo("alice@example.com");
        assertThat(alice.getStatus()).isEqualTo("ACTIVE");
        assertThat(alice.getPasswordHash()).startsWith("$2b$");   // BCrypt 哈希
        assertThat(alice.getCreatedAt()).isNotNull();             // DATETIME->LocalDateTime 映射
    }

    @Test
    void alice拥有EMPLOYEE角色() {
        User alice = userMapper.selectByUsername("alice");
        List<String> roles = roleMapper.selectRoleCodesByUserId(alice.getId());
        assertThat(roles).containsExactly("EMPLOYEE");
    }

    @Test
    void admin拥有SYS_ADMIN角色() {
        User admin = userMapper.selectByUsername("admin");
        assertThat(roleMapper.selectRoleCodesByUserId(admin.getId())).containsExactly("SYS_ADMIN");
    }

    @Test
    void alice的SM9身份未初始化() {
        User alice = userMapper.selectByUsername("alice");
        UserKey key = userKeyMapper.selectByUserId(alice.getId());
        assertThat(key).isNotNull();
        assertThat(key.getSm9Identity()).isEqualTo("user:corp001:10001:alice@example.com");
        assertThat(key.getKeyStatus()).isEqualTo("UNINITIALIZED");
        assertThat(key.getDeviceBound()).isFalse();   // BOOLEAN 映射
    }

    @Test
    void 插入新用户_自动填充时间戳且自增ID大于等于10006() {
        User u = new User();
        u.setUsername("tmp_" + System.nanoTime());
        u.setPasswordHash("$2b$10$placeholderplaceholderplaceholderplaceholder");
        u.setStatus("ACTIVE");

        int rows = userMapper.insert(u);

        assertThat(rows).isEqualTo(1);
        assertThat(u.getId()).isNotNull();                        // 自增ID回填
        assertThat(u.getId()).isGreaterThanOrEqualTo(10006L);     // 演示账号之后
        assertThat(u.getCreatedAt()).isNotNull();                 // DB-4 自动填充
        assertThat(u.getUpdatedAt()).isNotNull();
    }

    // ---- TEST-1：负路径覆盖 ----

    @Test
    void 查不存在的用户返回null() {
        assertThat(userMapper.selectByUsername("no_such_user")).isNull();
    }

    @Test
    void 无角色用户的角色列表为空() {
        User u = new User();
        u.setUsername("norole_" + System.nanoTime());
        u.setPasswordHash("$2b$10$placeholderplaceholderplaceholderplaceholder");
        u.setStatus("ACTIVE");
        userMapper.insert(u);
        assertThat(roleMapper.selectRoleCodesByUserId(u.getId())).isEmpty();
    }
}
