package sysservice.sysservice.service;

import sysservice.sysservice.dto.UserDto;

/**
 * @author liutf
 * @date 2020-02-28
 */
public interface UserService {
    UserDto findUsersByLoginName(String username);
}
