package com.training.java.controller;


import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import com.training.java.entity.Role;
import com.training.java.entity.User;
import com.training.java.service.UserService;

import lombok.extern.slf4j.Slf4j;

@Controller
@PreAuthorize("hasAuthority('ADMIN')")
@RequestMapping("/user")
@Slf4j
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public String userList(Model model) {
        model.addAttribute("users", userService.getAllUsers());

        return "userList";
    }

    @GetMapping("{user}")
    public String userEditForm(@PathVariable User user, Model model) {
        model.addAttribute("user", user);
        model.addAttribute("roles", Role.values());
        return "userEdit";
    }

    @PostMapping
    public String userSave(
            @RequestParam String username,
            @RequestParam Map<String, String> form,
            @RequestParam ("userId") User user
    ) {
        user.setUsername(username);
        Set<String> roles = Arrays.stream(Role.values())
                .map(Role::name)
                .collect(Collectors.toSet());
        user.getRoles().clear();
        user.getRoles().add(Role.USER);
        form.keySet().stream().filter(roles::contains).forEach(s -> user.getRoles().add(Role.valueOf(s)));
        log.info("{}", user.getUsername() + " " + user.getRoles());
        userService.saveNewUser(user);
        return "redirect:/user";
    }
}