package dev.webstarter.project.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import dev.webstarter.project.domain.Project;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Update;

import java.time.LocalDateTime;

@Mapper
public interface ProjectMapper extends BaseMapper<Project> {

    @Update("""
            UPDATE biz_project
            SET deleted = 1, version = version + 1, updated_at = #{updatedAt}
            WHERE id = #{id} AND version = #{version} AND deleted = 0
            """)
    int logicalDeleteWithVersion(@Param("id") Long id, @Param("version") Integer version,
                                 @Param("updatedAt") LocalDateTime updatedAt);
}
