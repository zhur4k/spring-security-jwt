package com.springsecurityjwt.service.impl;

import com.springsecurityjwt.UserRepository;
import com.springsecurityjwt.model.User;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public void resetFailedAttempts(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
        user.setAccountNonLocked(true);
        user.setFailedAttempts(0);
        userRepository.save(user);
    }
}
