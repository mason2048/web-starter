package dev.webstarter.security.persistence.mapper;

import java.time.Instant;
import java.util.List;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import dev.webstarter.security.persistence.model.ServiceAccountRecord;

@Mapper
public interface ServiceAccountMapper {

    @Insert("""
            INSERT INTO sec_service_account
                (id, code, display_name, description, enabled, role_ids, created_by, created_at,
                 updated_by, updated_at)
            VALUES
                (#{id}, #{code}, #{displayName}, #{description}, #{enabled}, #{roleIds},
                 #{createdBy}, #{createdAt}, #{updatedBy}, #{updatedAt})
            """)
    int insert(ServiceAccountRecord record);

    @Select("""
            SELECT id, code, display_name, description, enabled, role_ids,
                   created_by, created_at, updated_by, updated_at
              FROM sec_service_account
             WHERE id = #{id}
            """)
    ServiceAccountRecord findById(Long id);

    @Select("""
            SELECT id, code, display_name, description, enabled, role_ids,
                   created_by, created_at, updated_by, updated_at
              FROM sec_service_account
             WHERE code = #{code}
            """)
    ServiceAccountRecord findByCode(String code);

    @Select("""
            SELECT id, code, display_name, description, enabled, role_ids,
                   created_by, created_at, updated_by, updated_at
              FROM sec_service_account
             ORDER BY id DESC
            """)
    List<ServiceAccountRecord> findAll();

    @Select("SELECT COUNT(*) FROM sec_service_account WHERE FIND_IN_SET(CAST(#{roleId} AS CHAR), role_ids) > 0")
    long countByRoleId(@Param("roleId") Long roleId);

    @Update("""
            UPDATE sec_service_account
               SET display_name = #{displayName}, description = #{description},
                   enabled = #{enabled}, role_ids = #{roleIds},
                   updated_by = #{updatedBy}, updated_at = #{updatedAt}
             WHERE id = #{id}
            """)
    int update(ServiceAccountRecord record);

    @Update("""
            UPDATE sec_service_account
               SET enabled = FALSE, updated_by = #{updatedBy}, updated_at = #{updatedAt}
             WHERE id = #{id}
            """)
    int disable(
            @Param("id") Long id,
            @Param("updatedBy") Long updatedBy,
            @Param("updatedAt") Instant updatedAt);
}
