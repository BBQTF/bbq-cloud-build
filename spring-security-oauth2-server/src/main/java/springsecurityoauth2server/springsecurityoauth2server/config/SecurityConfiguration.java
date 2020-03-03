package springsecurityoauth2server.springsecurityoauth2server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author liutf
 * @date 2020-02-27
 */

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationProvide myAuthenticationProvide;
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.debug("SecurityConfiguration中配置HttpSecurity对象执行");
        http
                .authorizeRequests() //配置拦截路径
                    .antMatchers("/resources/**", "/signup", "/about").permitAll()
                    .antMatchers("/sys/system/user/**").permitAll()
                    .antMatchers("/admin/**").hasRole("admin")
                    .anyRequest().authenticated()
                    .and()
                .formLogin() //表单认证
                    .and()
                .httpBasic();// 开启http基础认证
    }

    /**定义认证用户信息获取来源，密码校验规则等**/
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());//密码加密方式
        //将验证过程交给自定义验证工具
        auth.authenticationProvider(myAuthenticationProvide);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 解决静态资源被拦截的问题
        web.ignoring().antMatchers("/theme/**", "/js/**", "/css/**", "/images/**", "**/favicon.ico");
        // swagger start
        web.ignoring().antMatchers("/doc.html");
        web.ignoring().antMatchers("/swagger-ui.html");
        web.ignoring().antMatchers("/swagger-resources/**");
        web.ignoring().antMatchers("/static/images/**");
        web.ignoring().antMatchers("/webjars/**");
        web.ignoring().antMatchers("/v2/api-docs");
        web.ignoring().antMatchers("/configuration/ui");
        web.ignoring().antMatchers("/configuration/security");
        // swagger end
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
