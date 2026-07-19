package dev.webstarter.system.persistence.mapper;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Collection;
import java.util.List;

@Mapper
public interface RolePermissionMapper {

    @Select("SELECT COUNT(*) FROM sys_role_permission WHERE permission_id = #{permissionId}")
    long countRolesByPermissionId(@Param("permissionId") Long permissionId);

    @Select("""
            SELECT COUNT(*)
              FROM sys_role_permission rp
              JOIN sys_role r ON r.id = rp.role_id
             WHERE rp.permission_id = #{permissionId}
               AND r.code = #{roleCode}
               AND r.deleted = 0
            """)
    long countByPermissionAndRoleCode(
            @Param("permissionId") Long permissionId,
            @Param("roleCode") String roleCode);

    @Select("SELECT permission_id FROM sys_role_permission WHERE role_id = #{roleId}")
    List<Long> selectPermissionIds(@Param("roleId") Long roleId);

    @Delete("DELETE FROM sys_role_permission WHERE role_id = #{roleId}")
    int deleteByRoleId(@Param("roleId") Long roleId);

    @Insert("""
            <script>
            INSERT INTO sys_role_permission (role_id, permission_id) VALUES
            <foreach collection="permissionIds" item="permissionId" separator=",">(#{roleId}, #{permissionId})</foreach>
            </script>
            """)
    int insertBatch(@Param("roleId") Long roleId, @Param("permissionIds") Collection<Long> permissionIds);
}
