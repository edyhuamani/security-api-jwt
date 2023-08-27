package com.foxdev.security.filter;

import com.foxdev.security.service.JwtService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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

    private final UserDetailsService userDetailsService; // Una clase propia de spring para Obtener

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

            if (userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null){
                // Verificar que el userDetailService ha sido customizado
                UserDetails userDetails =this.userDetailsService.loadUserByUsername(userEmail);
                if  (jwtService.isTokenValid(jwt, userDetails)){
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    // Se le añade detalles de la autenticacion
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );
                    // Se actualiza el contexto con la informacion del token valido
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                }

            }

            filterChain.doFilter(request,response);

    }
}
