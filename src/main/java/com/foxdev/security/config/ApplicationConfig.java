package com.foxdev.security.config;

import com.foxdev.security.model.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    /**
     * En este bean estamos customizando el detailsService usado en el filter
     * estamos pasando un function que obtendra datos del usuario del repositorio
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService(){
        return username -> userRepository.findByEmail(username)
                .orElseThrow((()->new UsernameNotFoundException("user not found")));
    }

}
