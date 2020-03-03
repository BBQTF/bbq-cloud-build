package springsecurityoauth2server.springsecurityoauth2server.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import springsecurityoauth2server.springsecurityoauth2server.common.Result;
import springsecurityoauth2server.springsecurityoauth2server.dto.UserDto;
import springsecurityoauth2server.springsecurityoauth2server.feign.UserFeignService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;


/**
 * @author liutf
 * @date 2020-02-27
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserFeignService userFeignService;

    @Override
    public UserDetails loadUserByUsername(String loginName) throws UsernameNotFoundException {

        Result result = userFeignService.findUsersByLoginname(loginName);
        if(result.getData() == null){
            throw new UsernameNotFoundException("该用户未找到");
        }
        // UserDto userDto = (UserDto)result.getData(); TODO Dto映射失败
        Map userMap = (Map)result.getData();
        // 获取用户成功
        if (!"1".equals(userMap.get("state"))){
            throw new UsernameNotFoundException("该用户处于锁定状态");
        }
        // 权限集合，可以存储用户角色
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority((String)userMap.get("role")));
        return new User(loginName, (String)userMap.get("password"), authorities);
    }
}
