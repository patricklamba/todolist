package com.lamba.todolist.security.jwt;


import com.lamba.todolist.models.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public class JwtAuthenticationFilter extends BasicAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final Environment env;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, Environment env) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager;
        this.env = env;
    }

    @Override
    protected void onSuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response, Authentication auth)  {

        User user = (User) auth.getPrincipal();

        List<String> roles = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        byte[] signingKey = requireNonNull(env.getProperty("jwt.secret")).getBytes();

        String token = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS512)
                .setHeaderParam("typ", env.getProperty("jwt.type"))
                .setIssuer(env.getProperty("jwt.issuer"))
                .setAudience(env.getProperty("jwt.audience"))
                .setSubject(user.getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + env.getProperty("jwt.expireAfter", Long.class)))
                .claim("rol", roles)
                .compact();

        response.addHeader(env.getProperty("jwt.header"), env.getProperty("jwt.prefix") + " " + token);
    }
}

