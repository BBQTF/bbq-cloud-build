package sysservice.sysservice.service.impl;

import org.springframework.stereotype.Service;
import sysservice.sysservice.bean.UserBean;
import sysservice.sysservice.dto.UserDto;
import sysservice.sysservice.mapper.UserMapper;
import sysservice.sysservice.service.UserService;

import javax.annotation.Resource;

/**
 * @author liutf
 * @date 2020-02-28
 */
@Service
public class UserServiceImpl implements UserService {
    @Resource
    private UserMapper mapper;

    @Override
    public UserDto findUsersByLoginName(String username){
        UserBean bean = mapper.getUserDetail(username);
        if (bean != null)
        {
            return bean.transToDto(bean);
        }
        return null;
    }
}
