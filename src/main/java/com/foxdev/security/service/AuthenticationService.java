package com.foxdev.security.service;

import com.foxdev.security.auth.controller.AuthenticationRequest;
import com.foxdev.security.auth.controller.AuthenticationResponse;
import com.foxdev.security.auth.controller.RegisterRequest;
import com.foxdev.security.model.user.beans.Role;
import com.foxdev.security.model.user.beans.User;
import com.foxdev.security.model.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Log4j2
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtSecurityService jwtSecurityService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest){
        var user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        var jwtToken = jwtSecurityService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();


    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest){
        //authentica las credenciales
        String jwtToken="";
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authenticationRequest.getEmail(),
                            authenticationRequest.getPassword())
            );
            // busca el usuario
            var user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
            // genera el token user es una implementacion de user details
            jwtToken = jwtSecurityService.generateToken(user);
            log.info("user "+user.toString());
            log.info("jwttoken "+jwtToken);
        }catch(Exception ex){
            log.info(ex.getMess   age());


        }
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

}
