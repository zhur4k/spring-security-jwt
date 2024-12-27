package com.springsecurityjwt.dto;

public record TokenResponseDto(
        String accessToken,
        String refreshToken
) {}
