package com.springsecurityjwt.service.impl;

import com.springsecurityjwt.UserRepository;
import com.springsecurityjwt.dto.LoginDto;
import com.springsecurityjwt.dto.RegisterDto;
import com.springsecurityjwt.dto.TokenResponseDto;
import com.springsecurityjwt.exception.InvalidTokenException;
import com.springsecurityjwt.model.User;
import com.springsecurityjwt.service.AuthService;
import com.springsecurityjwt.utils.JWTUtils;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final JWTUtils jwtUtils;

    private final UserDetailsService userDetailsService;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    @Override
    public TokenResponseDto login(LoginDto loginDto) {
        User user = userRepository.findByUsername(loginDto.username())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!user.isAccountNonLocked()) {
            throw new LockedException("Account is locked");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDto.username(),
                            loginDto.password()
                    )
            );

            user.setFailedAttempts(0);
            userRepository.save(user);

            UserDetails userDetails = userDetailsService.loadUserByUsername(loginDto.username());

            return new TokenResponseDto(
                    jwtUtils.generateToken(userDetails),
                    jwtUtils.generateRefreshToken(new HashMap<>(), userDetails)
            );
        } catch (BadCredentialsException e) {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);

            if (attempts >= 5) {
                user.setAccountNonLocked(false);
            }

            userRepository.save(user);
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    @Override
    public void register(RegisterDto registerDto) {
        if (userRepository.existsByUsername(registerDto.username())) {
            throw new IllegalArgumentException("User already exists");
        }

        User user = new User();
        user.setUsername(registerDto.username());
        user.setPassword(passwordEncoder.encode(registerDto.password()));
        user.setAccountNonLocked(true);
        user.setName(registerDto.name());
        user.setRoles(registerDto.roles());
        user.setFailedAttempts(0);
        userRepository.save(user);
    }

    @Override
    public String refreshAccessToken(String refreshToken) {
        String username = jwtUtils.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if(!jwtUtils.isTokenValid(refreshToken, userDetails)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        return jwtUtils.generateToken(userDetails);
    }
}
