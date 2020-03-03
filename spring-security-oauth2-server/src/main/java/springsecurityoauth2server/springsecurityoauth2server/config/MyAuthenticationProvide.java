package springsecurityoauth2server.springsecurityoauth2server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import springsecurityoauth2server.springsecurityoauth2server.service.CustomUserDetailsService;

/**
 * @author liutf
 * @date 2020-02-27
 */
@Component
public class MyAuthenticationProvide implements AuthenticationProvider {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    public static final Logger logger = LoggerFactory.getLogger(MyAuthenticationProvide.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
        if(userDetails==null){
            throw new BadCredentialsException("用户名不存在");
        }

        if(!password.equals(userDetails.getPassword())){
            throw new BadCredentialsException("用户名或密码错误");
        }
        /*用户名密码认证成功*/
        return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
