package dev.webstarter.system.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import dev.webstarter.system.domain.SysMcpCallLog;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface McpCallLogMapper extends BaseMapper<SysMcpCallLog> {
}
