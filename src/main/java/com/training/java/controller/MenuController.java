package com.training.java.controller;

import com.training.java.entity.Dish;
import com.training.java.service.DishService;
import com.training.java.service.UserService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Slf4j
@Controller
@RequestMapping("/")
@AllArgsConstructor
public class MenuController {
    private final DishService dishService;
    private final UserService userService;

    @GetMapping
    public String menuPage(Model model,  @RequestParam("page") Optional<Integer> page
    ) {
        int currentPage = page.orElse(1);
        int pageSize = 4;
        Page<Dish> dishPage = dishService.getAllDishes(PageRequest.of(currentPage - 1, pageSize));

        model.addAttribute("dishes", dishPage);
        model.addAttribute("title", "Menu of restaurant");
        int totalPages = dishPage.getTotalPages();
        if (totalPages > 0) {
            List<Integer> pageNumbers = IntStream.rangeClosed(1, totalPages)
                    .boxed()
                    .collect(Collectors.toList());
            model.addAttribute("pageNumbers", pageNumbers);
        }




        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (userService.findByUsername(authentication.getName()) != null) {
            model.addAttribute("moneyBalance", userService.findByUsername(authentication.getName())
                    .getMoneyHave());
        }

        return "menu/menu.html";
    }


}
