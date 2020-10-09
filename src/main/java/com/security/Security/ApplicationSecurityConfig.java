package com.security.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.security.Security.ApplicationUserRole.*;
//59:15 hours of lecture
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
@Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    public ApplicationSecurityConfig(boolean disableDefaults, PasswordEncoder passwordEncoder) {
        super(disableDefaults);
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()


                .authorizeRequests()
                .antMatchers("/"," index","/css/**", "/js/**").permitAll()
                .antMatchers("/api/**").hasAnyRole(ADMIN.name())
                .antMatchers("/api/**").hasAnyRole(ADMINTRAINEE.name())
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
                .antMatchers(HttpMethod.GET,"/managemet/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())



                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    //59:15
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annasmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("anna"))
                .roles(STUDENT.name())
                .authorities(STUDENT.GrantedAuthority())
                .build();

        UserDetails LindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("linda123"))
                .roles(ADMIN.name())
                .authorities(ADMIN.GrantedAuthority())
                .build();


        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("tom123"))
                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.GrantedAuthority())
                .build();


        return new InMemoryUserDetailsManager(


                annasmithUser,
                LindaUser,
                tomUser
        );

    }}

