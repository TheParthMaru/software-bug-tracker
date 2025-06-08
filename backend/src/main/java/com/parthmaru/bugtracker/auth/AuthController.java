package com.parthmaru.bugtracker.auth;

import com.parthmaru.bugtracker.common.dto.AuthResponse;
import com.parthmaru.bugtracker.common.dto.LoginRequest;
import com.parthmaru.bugtracker.common.dto.RegisterRequest;
import com.parthmaru.bugtracker.security.JwtTokenProvider;
import com.parthmaru.bugtracker.user.Role;
import com.parthmaru.bugtracker.user.UserEntity;
import com.parthmaru.bugtracker.user.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserService userService, JwtTokenProvider jwtTokenProvider, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        userService.RegisterUser(request);
        return new ResponseEntity<>("User registered successfully.", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        UserEntity user = userService.findByUsername(request.getUsername());

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        String token = jwtTokenProvider.generateToken(user.getUsername(), user.getRole());
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
