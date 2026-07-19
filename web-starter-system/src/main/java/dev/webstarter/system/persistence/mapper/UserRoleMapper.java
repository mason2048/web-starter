package dev.webstarter.system.persistence.mapper;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Collection;
import java.util.List;

@Mapper
public interface UserRoleMapper {

    @Select("""
            SELECT COUNT(DISTINCT u.id)
              FROM sys_user u
              JOIN sys_user_role ur ON ur.user_id = u.id
              JOIN sys_role r ON r.id = ur.role_id
             WHERE r.code = #{roleCode}
               AND r.status = 'ENABLED'
               AND r.deleted = 0
               AND u.status = 'ENABLED'
               AND u.deleted = 0
            """)
    long countEnabledUsersByRoleCode(@Param("roleCode") String roleCode);

    @Select("SELECT role_id FROM sys_user_role WHERE user_id = #{userId}")
    List<Long> selectRoleIds(@Param("userId") Long userId);

    @Select("SELECT COUNT(*) FROM sys_user_role WHERE role_id = #{roleId}")
    long countUsersByRoleId(@Param("roleId") Long roleId);

    @Delete("DELETE FROM sys_user_role WHERE user_id = #{userId}")
    int deleteByUserId(@Param("userId") Long userId);

    @Insert("""
            <script>
            INSERT INTO sys_user_role (user_id, role_id) VALUES
            <foreach collection="roleIds" item="roleId" separator=",">(#{userId}, #{roleId})</foreach>
            </script>
            """)
    int insertBatch(@Param("userId") Long userId, @Param("roleIds") Collection<Long> roleIds);
}
