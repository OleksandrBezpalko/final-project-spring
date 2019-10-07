package com.training.java.controller;

import com.training.java.entity.Role;
import com.training.java.entity.User;
import com.training.java.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Controller
public class RegistrationController {
    private final UserService userService;

    public RegistrationController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/registration")
    public String registration() {
        return "register";
    }

    @PostMapping("/registration")
    public String addUser(User user, Model model) {
        user.setActive(true);
        user.setRoles(Collections.singleton(Role.USER));
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        user.setPassword(encoder.encode(user.getPassword()));
        log.info("{}", user.getUsername()+ " new user");
        try {
            userService.saveNewUser(user);
        } catch (DataIntegrityViolationException e) {
            Map<String, String> map = new ConcurrentHashMap<>();
            map.put("spring", "mvc");
            model.addAttribute("message", "user already exists");
            model.mergeAttributes(map);
            log.info("username already exists "+user.getUsername());
            return "register.html";
        }
        return "redirect:/login";
    }
}