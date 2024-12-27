package com.springsecurityjwt.service;

import com.springsecurityjwt.dto.LoginDto;
import com.springsecurityjwt.dto.RegisterDto;
import com.springsecurityjwt.dto.TokenResponseDto;

public interface AuthService {
    TokenResponseDto login(LoginDto loginDto);

    void register(RegisterDto registerDto);

    String refreshAccessToken(String refreshToken);
}
