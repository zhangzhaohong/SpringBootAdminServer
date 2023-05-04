package com.admin.server.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/**
 * @author koala
 * @version 1.0
 * @date 2023/5/3 21:55
 * @description
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final String adminContextPath;

    public SecurityConfiguration(AdminServerProperties adminServerProperties) {
        this.adminContextPath = adminServerProperties.getContextPath();
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl(adminContextPath + "/");
        return http.authorizeHttpRequests((authorizeRequests) -> {
                    try {
                        authorizeRequests
                                .requestMatchers(adminContextPath + "/instances").permitAll()
                                .requestMatchers(adminContextPath + "/actuator/**").permitAll()
                                .requestMatchers(adminContextPath + "/assets/**").permitAll()
                                .requestMatchers(adminContextPath + "/login").permitAll()
                                .anyRequest().authenticated()
                                .and().formLogin().loginPage(adminContextPath + "/login").successHandler(successHandler)
                                .and().logout().logoutUrl(adminContextPath + "/logout")
                                .and().httpBasic()
                                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).disable();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .build();
    }

}