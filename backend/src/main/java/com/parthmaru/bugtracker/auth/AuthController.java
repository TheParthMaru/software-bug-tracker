package com.parthmaru.bugtracker.auth;

import com.parthmaru.bugtracker.common.dto.RegisterRequest;
import com.parthmaru.bugtracker.user.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        userService.RegisterUser(request);
        return new ResponseEntity<>("User registered successfully.", HttpStatus.CREATED);
    }

    // Login endpoint will be implemented after JWT is ready
}
