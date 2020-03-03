package sysservice.sysservice.mapper;

import org.apache.ibatis.annotations.Param;
import sysservice.sysservice.bean.UserBean;

/**
 * @author liutf
 * @date 2020-02-28
 */
public interface UserMapper {
    UserBean getUserDetail(@Param("username") String username);
}
