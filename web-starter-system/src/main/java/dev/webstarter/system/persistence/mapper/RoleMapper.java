package dev.webstarter.system.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import dev.webstarter.system.domain.SysRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Collection;
import java.util.List;

@Mapper
public interface RoleMapper extends BaseMapper<SysRole> {

    @Select("""
            SELECT id
              FROM sys_role
             WHERE code = #{code}
               AND deleted = 0
             FOR UPDATE
            """)
    Long selectIdByCodeForUpdate(@Param("code") String code);

    @Select("""
            SELECT DISTINCT r.code
            FROM sys_role r
            JOIN sys_user_role ur ON ur.role_id = r.id
            WHERE ur.user_id = #{userId}
              AND r.status = 'ENABLED'
              AND r.deleted = 0
            """)
    List<String> selectCodesByUserId(@Param("userId") Long userId);

    @Select("""
            <script>
            SELECT DISTINCT r.code
            FROM sys_role r
            WHERE r.id IN
            <foreach collection="roleIds" item="id" open="(" separator="," close=")">#{id}</foreach>
              AND r.status = 'ENABLED'
              AND r.deleted = 0
            </script>
            """)
    List<String> selectCodesByIds(@Param("roleIds") Collection<Long> roleIds);
}
