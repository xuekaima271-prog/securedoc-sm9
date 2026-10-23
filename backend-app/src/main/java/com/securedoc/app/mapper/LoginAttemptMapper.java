package com.securedoc.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.securedoc.app.entity.LoginAttempt;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.time.LocalDateTime;

public interface LoginAttemptMapper extends BaseMapper<LoginAttempt> {

    /** M-5：锁定维度是「账号×来源IP」组合行（uk_login_user_ip），不再按账号全局取行。 */
    @Select("SELECT * FROM login_attempts WHERE username = #{username} AND client_ip = #{clientIp}")
    LoginAttempt selectByUsernameAndIp(@Param("username") String username, @Param("clientIp") String clientIp);

    /**
     * 原子自增失败计数（M-5 附带修复原「先查后写绝对值」的读改写竞态：并发失败不再互相覆盖少计）。
     * 锁定已过期 → 本次失败开新窗口：计数重置为 1 且清掉旧锁定；未过期则 fail_count+1。
     * 返回受影响行数（0 = 组合行不存在，调用方走插入路径）。
     */
    @Update("""
            UPDATE login_attempts
            SET fail_count = CASE WHEN locked_until IS NOT NULL AND locked_until < #{now}
                                  THEN 1 ELSE fail_count + 1 END,
                locked_until = CASE WHEN locked_until IS NOT NULL AND locked_until < #{now}
                                    THEN NULL ELSE locked_until END,
                last_failed_at = #{now},
                updated_at = #{now}
            WHERE username = #{username} AND client_ip = #{clientIp}
            """)
    int incrementFailure(@Param("username") String username, @Param("clientIp") String clientIp,
                         @Param("now") LocalDateTime now);

    /**
     * 达阈值且当前未锁定时才落锁（条件更新保证并发下只有一个调用者真正落锁并触发安全事件）。
     * 返回受影响行数：1 = 本次新落锁；0 = 未达阈值或已被并发落锁。
     */
    @Update("""
            UPDATE login_attempts
            SET locked_until = #{lockedUntil}, updated_at = #{now}
            WHERE username = #{username} AND client_ip = #{clientIp}
              AND fail_count >= #{maxFailures}
              AND (locked_until IS NULL OR locked_until < #{now})
            """)
    int lockIfThresholdReached(@Param("username") String username, @Param("clientIp") String clientIp,
                               @Param("lockedUntil") LocalDateTime lockedUntil,
                               @Param("maxFailures") int maxFailures,
                               @Param("now") LocalDateTime now);
}
