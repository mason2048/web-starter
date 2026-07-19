package dev.webstarter.system.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import dev.webstarter.system.domain.SysPermission;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Collection;
import java.util.List;

@Mapper
public interface PermissionMapper extends BaseMapper<SysPermission> {

    @Select("""
            SELECT DISTINCT p.code
            FROM sys_permission p
            JOIN sys_role_permission rp ON rp.permission_id = p.id
            JOIN sys_user_role ur ON ur.role_id = rp.role_id
            JOIN sys_role r ON r.id = ur.role_id
            WHERE ur.user_id = #{userId}
              AND p.status = 'ENABLED'
              AND p.deleted = 0
              AND r.status = 'ENABLED'
              AND r.deleted = 0
            """)
    List<String> selectCodesByUserId(@Param("userId") Long userId);

    @Select("""
            <script>
            SELECT DISTINCT p.code
            FROM sys_permission p
            JOIN sys_role_permission rp ON rp.permission_id = p.id
            JOIN sys_role r ON r.id = rp.role_id
            WHERE rp.role_id IN
            <foreach collection="roleIds" item="id" open="(" separator="," close=")">#{id}</foreach>
              AND p.status = 'ENABLED'
              AND p.deleted = 0
              AND r.status = 'ENABLED'
              AND r.deleted = 0
            </script>
            """)
    List<String> selectCodesByRoleIds(@Param("roleIds") Collection<Long> roleIds);

    @Select("""
            <script>
            SELECT DISTINCT p.code
            FROM sys_permission p
            WHERE p.code IN
            <foreach collection="codes" item="code" open="(" separator="," close=")">#{code}</foreach>
              AND p.status = 'ENABLED'
              AND p.deleted = 0
            </script>
            """)
    List<String> selectEnabledCodes(@Param("codes") Collection<String> codes);
}
