package springsecurityoauth2server.springsecurityoauth2server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

/**
 * @author liutf
 * @date 2020-03-02
 */

@Configuration
@EnableResourceServer   //注解来开启资源服务器
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(ResourceServerConfiguration.class);

    public static final String RESOURCE_ID = "tdf-cloud-oauth2-server";

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        super.configure(resources);
        resources.resourceId(RESOURCE_ID);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        logger.debug("ResourceServerConfig中配置HttpSecurity对象执行");
        // 此处配置的端口作为资源服务器的资源端口,其他端口采用SecurityConfiguration类的配置规则
        http.cors();
        http.requestMatchers().antMatchers("/me"
                , "/oauthClients/**", "/oauthClientList/**", "/roles/**", "/actuator/**",
                "/sys/system/user/**")
                .and()
                .authorizeRequests()
                .antMatchers("/actuator/hystrix.stream").permitAll()
                .anyRequest().authenticated();
        // TODO  http.csrf().ignoringAntMatchers("/actuator/**"); 可以被tdf-cloud-admin-server监控，需要禁用csrf .post 类型请求csrf临时禁用http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http.csrf().disable();
    }
}