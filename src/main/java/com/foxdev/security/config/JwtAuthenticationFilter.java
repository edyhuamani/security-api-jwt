package com.foxdev.security.config;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *  class OncePerRequestFilter
 */
@Component
@RequiredArgsConstructor
@Log4j2
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

            log.info(" request URi "+request.getRequestURI());
            log.info(" remote host  "+request.getRemoteHost());

            final String authHeader = request.getHeader("Authorization");
            final String jwt;
            final String userEmail;
            if (authHeader==null || authHeader.startsWith("Bearer ")){
                filterChain.doFilter(request,response);
                return;
            }

            jwt = authHeader.substring(7);
            userEmail = jwtService.extractUserName(jwt); // todo extract suer email;


    }
}
