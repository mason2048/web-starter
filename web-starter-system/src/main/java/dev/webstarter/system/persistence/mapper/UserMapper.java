package dev.webstarter.system.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import dev.webstarter.system.domain.SysUser;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<SysUser> {
}
