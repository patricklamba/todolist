package com.lamba.todolist.security;

import com.lamba.todolist.repositories.UserRepository;
import com.lamba.todolist.security.jwt.JwtAuthenticationFilter;
import com.lamba.todolist.security.jwt.JwtAuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.servlet.http.HttpServletResponse;

import static com.lamba.todolist.models.Role.ADMIN;
import static com.lamba.todolist.models.Role.USER;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().authorizeRequests()
                // mapping
                .antMatchers(HttpMethod.DELETE, "/**").hasAnyAuthority(ADMIN.getAuthority())

                .antMatchers(HttpMethod.POST, "/admin/**").hasAuthority(ADMIN.getAuthority())
                .antMatchers(HttpMethod.GET, "/admin/**").hasAnyAuthority(ADMIN.getAuthority(), USER.getAuthority())

                .antMatchers(HttpMethod.GET, "/user/**").hasAuthority(USER.getAuthority())
                .antMatchers(HttpMethod.POST, "/user/**").hasAuthority(USER.getAuthority())

                .antMatchers(HttpMethod.GET, "/proxy/**").hasAuthority(ADMIN.getAuthority())
                .antMatchers(HttpMethod.POST, "/proxy/**").hasAuthority(ADMIN.getAuthority())
                .antMatchers(HttpMethod.PUT, "/proxy/**").hasAuthority(ADMIN.getAuthority())

                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                .anyRequest().permitAll()

                // csrf
                .and().csrf().disable()

                // http basic
                .httpBasic()
                .realmName("login")

                // exception handling
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, e) -> resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED))

                .and()
                .formLogin().disable()

                // jwt filter
                .addFilter(new JwtAuthenticationFilter(authenticationManager(), env))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(),env))

                // stateless
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth, BCryptPasswordEncoder passwordEncoder) throws Exception {
        auth.userDetailsService(userRepository).passwordEncoder(passwordEncoder);
    }

    @Autowired
    UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @Autowired
    Environment env;


}