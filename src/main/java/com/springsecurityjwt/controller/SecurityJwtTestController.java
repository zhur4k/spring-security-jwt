package com.springsecurityjwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/security/test")
public class SecurityJwtTestController {

    @GetMapping("/user")
    public String testUser() {
        return "User";
    }

    @GetMapping("/moderator")
    public String testModerator() {
        return "Moderator";
    }

    @GetMapping("/super_admin")
    public String testSuperAdmin() {
        return "SuperAdmin";
    }
}
