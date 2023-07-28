package com.example.security.config;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.security.mapper.UserMapper;
import com.example.security.po.User;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * security配置
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

    /**
     * 自定义安全策略
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception { // 配置策略
        http.csrf().disable();
        http.authorizeRequests().antMatchers("/static/**").permitAll().anyRequest().authenticated().and().formLogin()
                        .loginPage("/login").permitAll().successHandler(loginSuccessHandler()).and().logout()
                        .permitAll().invalidateHttpSession(true).deleteCookies("JSESSIONID")
                        .logoutSuccessHandler(logoutSuccessHandler()).and().rememberMe().and().sessionManagement()
                        .maximumSessions(10).expiredUrl("/login");
    }

    /**
     * 全局认证管理器
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
        auth.eraseCredentials(false);
    }

    /**
     * 基于令牌的Remember Me服务，用于记住用户的身份
     */
    @Bean
    public TokenBasedRememberMeServices tokenBasedRememberMeServices() {
        return new TokenBasedRememberMeServices("springRocks", userDetailsService());
    }

    /**
     * 密码加密
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() { // 密码加密
        return new BCryptPasswordEncoder(4);
    }

    /**
     * 登出成功处理器
     */
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() { // 登出处理
        return new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                            Authentication authentication) throws IOException, ServletException {
                try {
                    SecurityUser user = (SecurityUser) authentication.getPrincipal();
                    logger.info("USER : {} LOGOUT SUCCESS ! ", user.getUsername());
                } catch (Exception e) {
                    logger.error("printStackTrace", e);
                }
                httpServletResponse.sendRedirect("/login");
            }
        };
    }

    /**
     * 登录成功处理器
     */
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler loginSuccessHandler() { // 登入处理
        return new SavedRequestAwareAuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                            Authentication authentication) throws IOException, ServletException {
                User userDetails = (User) authentication.getPrincipal();
                logger.info("USER : " + userDetails.getUsername() + " LOGIN SUCCESS !  ");
                super.onAuthenticationSuccess(request, response, authentication);
            }
        };
    }

    /**
     * 加载用户信息
     */
    @Bean
    @Override
    public UserDetailsService userDetailsService() { // 用户登录实现
        return new UserDetailsService() {
            @Autowired
            private UserMapper userMapper;

            @Override
            public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
                LambdaQueryWrapper<User> lqw = new LambdaQueryWrapper<User>().eq(User::getUsername, s);
                User user = null;
                try {
                    user = userMapper.selectOne(lqw);
                } catch (Exception e) {
                    log.error("there is dirty data in the database ,{}", e.getLocalizedMessage());
                    throw new UsernameNotFoundException("there is dirty data in the database ,Username=" + s);
                }
                if (user == null)
                    throw new UsernameNotFoundException("Username " + s + " not found");
                return new SecurityUser(user);
            }
        };
    }

}
