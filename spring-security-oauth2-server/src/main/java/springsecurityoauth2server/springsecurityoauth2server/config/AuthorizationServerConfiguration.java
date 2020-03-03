package springsecurityoauth2server.springsecurityoauth2server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import springsecurityoauth2server.springsecurityoauth2server.service.CustomUserDetailsService;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @author liutf
 * @date 2020-03-02
 *
 *  身份授权认证服务配置
 *  配置客户端、token存储方式等
 */
@Configuration
@EnableAuthorizationServer
//  注解开启验证服务器 提供/oauth/authorize,/oauth/token,/oauth/check_token,/oauth/confirm_access,/oauth/error
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    private static final String REDIRECT_URL = "https://www.baidu.com/";
    private static final String CLIEN_ID_THREE = "client_3";  //客户端3
    private static final String CLIENT_SECRET = "secret";   //secret客户端安全码
    private static final String GRANT_TYPE_PASSWORD = "password";   // 密码模式授权模式
    private static final String AUTHORIZATION_CODE = "authorization_code"; //授权码模式  授权码模式使用到了回调地址，是最为复杂的方式，通常网站中经常出现的微博，qq第三方登录，都会采用这个形式。
    private static final String REFRESH_TOKEN = "refresh_token";  //
    private static final String IMPLICIT = "implicit"; //简化授权模式
    private static final String GRANT_TYPE = "client_credentials";  //客户端模式
    private static final String SCOPE_READ = "read";
    private static final String SCOPE_WRITE = "write";
    private static final String TRUST = "trust";
    private static final int ACCESS_TOKEN_VALIDITY_SECONDS = 1*60*60;          //
    private static final int FREFRESH_TOKEN_VALIDITY_SECONDS = 6*60*60;        //
    private static final String RESOURCE_ID = "resource_id";    //指定哪些资源是需要授权验证的



    /**
     * 注入authenticationManager来支持 password grant_type
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
        String secret = new BCryptPasswordEncoder().encode(CLIENT_SECRET);  // 用 BCrypt 对密码编码
        //配置3个个客户端,一个用于password认证、一个用于client认证、一个用于authorization_code认证
        configurer.inMemory()  // 使用in-memory存储
                .withClient(CLIEN_ID_THREE)    //client_id用来标识客户的Id  客户端3
                .resourceIds(RESOURCE_ID)
                .authorizedGrantTypes(AUTHORIZATION_CODE,GRANT_TYPE, REFRESH_TOKEN,GRANT_TYPE_PASSWORD,IMPLICIT)  //允许授权类型
                .scopes(SCOPE_READ,SCOPE_WRITE,TRUST)  //允许授权范围
                .authorities("ROLE_CLIENT")  //客户端可以使用的权限
                .secret(secret)  //secret客户端安全码
                //.redirectUris(REDIRECT_URL)  //指定可以接受令牌和授权码的重定向URIs
                .autoApprove(true) // 为true 则不会被重定向到授权的页面，也不需要手动给请求授权,直接自动授权成功返回code
                .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)   //token 时间秒
                .refreshTokenValiditySeconds(FREFRESH_TOKEN_VALIDITY_SECONDS);//刷新token 时间 秒

    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        super.configure(oauthServer);
        //支持post形式的client认证
        oauthServer.allowFormAuthenticationForClients();
        // 默认tokenKeyAccess和checkTokenAccess对应端口权限是denyAll(),如果允许资源服务器调用这些端口，则需要覆盖默认配置
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
        // 解决OPTION /oauth/token 请求跨域问题
        oauthServer.addTokenEndpointAuthenticationFilter(new CorsFilter(corsConfigurationSource()));
    }


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore()).authenticationManager(authenticationManager)
                .accessTokenConverter(accessTokenConverter())
                .userDetailsService(customUserDetailsService) //必须注入userDetailsService否则根据refresh_token无法加载用户信息
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST,HttpMethod.OPTIONS)  //支持GET  POST  请求获取token
                .reuseRefreshTokens(true) //开启刷新token
                .tokenServices(tokenServices());

    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter() {
            /**
             * 自定义一些token返回的信息
             * @param accessToken
             * @param authentication
             * @return
             */
            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
                String grantType = authentication.getOAuth2Request().getGrantType();
                //只有如下两种模式才能获取到当前用户信息
                if("authorization_code".equals(grantType) || "password".equals(grantType)) {
                    String userName = authentication.getUserAuthentication().getName();
                    // 自定义一些token 信息 会在获取token返回结果中展示出来
                    final Map<String, Object> additionalInformation = new HashMap<>();
                    additionalInformation.put("user_name", userName);
                    ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
                }
                OAuth2AccessToken token = super.enhance(accessToken, authentication);
                return token;
            }
        };
        converter.setSigningKey("bcrypt");
        return converter;
    }

    @Bean
    public TokenStore tokenStore() {
        //基于jwt实现令牌（Access Token）
        return new JwtTokenStore(accessTokenConverter());
    }

    /**
     * 重写默认的资源服务token
     * @return
     */
    @Bean
    public DefaultTokenServices tokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenEnhancer(accessTokenConverter());
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setAccessTokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(30)); // 30天
        return defaultTokenServices;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("*"); // 1
        corsConfiguration.addAllowedHeader("*"); // 2
        corsConfiguration.addAllowedMethod("*"); // 允许所有方法包括"GET", "POST", "DELETE", "PUT"等等
        corsConfiguration.setMaxAge(1800l);//30分钟
        //使用setAllowCredentials的方式解决跨域问题只支持ie10以上。
        //如果使用默认的配合CookierHttpSessionStrategy的session方式
        // 前后端一起开启，开启之后就能够读写浏览器的Cookies。该字段可选。它的值是一个布尔值，表示是否允许发送Cookie。
        // 默认情况下，Cookie不包括在CORS请求之中。设为true，即表示服务器明确许可，
        // Cookie可以包含在请求中，一起发给服务器。这个值也只能设为true，如果服务器不要浏览器发送Cookie，删除该字段即可。
        corsConfiguration.setAllowCredentials(true);
        //配合HeaderHttpSessionStrategy的session方式。token的方式解决跨域问题。
        // CORS请求时。XMLHttpRequest对象的getResponseHeader()方法只能拿到6个基本字段：Cache-Control、Content-Language、Content-Type、Expires、Last-Modified、Pragma。如果想拿到其他字段，
        // 就必须在Access-Control-Expose-Headers里面指定。上面的例子指定，getResponseHeader(‘FooBar’)可以返回FooBar字段的值。
        //允许clienHeaderWriterFiltert-site取得自定义得header值
        corsConfiguration.addExposedHeader(HttpHeaders.AUTHORIZATION);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
}