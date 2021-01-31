package com.lamba.todolist.controllers;

import com.lamba.todolist.models.User;
import com.lamba.todolist.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@CrossOrigin(value = "*", allowedHeaders = "*")
@RequestMapping("/user")
public class UserRestController {
    private final UserRepository userRepository;

    @Autowired
    public UserRestController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostMapping("/info")
    public User info(Principal principal) {
        return userRepository.principalToUser(principal);
    }
}
