package com.springsecurityjwt.dto;


import javax.validation.constraints.NotNull;

public record LoginDto(
        @NotNull(message = "Username cannot be empty")
        String username,
        @NotNull(message = "Username cannot be empty")
        String password
) {
}
