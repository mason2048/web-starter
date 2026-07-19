package dev.webstarter.system.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import dev.webstarter.system.domain.SysMenu;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Collection;
import java.util.List;

@Mapper
public interface MenuMapper extends BaseMapper<SysMenu> {

    @Select("""
            SELECT DISTINCT m.id
            FROM sys_menu m
            JOIN sys_role_menu rm ON rm.menu_id = m.id
            JOIN sys_user_role ur ON ur.role_id = rm.role_id
            JOIN sys_role r ON r.id = ur.role_id
            WHERE ur.user_id = #{userId}
              AND m.status = 'ENABLED'
              AND m.visible = TRUE
              AND m.deleted = 0
              AND r.status = 'ENABLED'
              AND r.deleted = 0
            """)
    List<Long> selectVisibleIdsByUserId(@Param("userId") Long userId);

    @Select("""
            <script>
            SELECT DISTINCT m.id
            FROM sys_menu m
            JOIN sys_role_menu rm ON rm.menu_id = m.id
            JOIN sys_role r ON r.id = rm.role_id
            WHERE rm.role_id IN
            <foreach collection="roleIds" item="id" open="(" separator="," close=")">#{id}</foreach>
              AND m.status = 'ENABLED'
              AND m.visible = TRUE
              AND m.deleted = 0
              AND r.status = 'ENABLED'
              AND r.deleted = 0
            </script>
            """)
    List<Long> selectVisibleIdsByRoleIds(@Param("roleIds") Collection<Long> roleIds);
}
