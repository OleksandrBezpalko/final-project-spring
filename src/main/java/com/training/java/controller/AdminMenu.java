package com.training.java.controller;

import com.training.java.entity.Dish;
import com.training.java.entity.Product;
import com.training.java.service.DishService;
import com.training.java.service.ProductService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;


import javax.validation.Valid;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@Controller
@PreAuthorize("hasAuthority('ADMIN')")
public class AdminMenu {
    private final DishService dishService;
    private final ProductService productService;

    @Value("${upload.path}")
    private String uploadPath;

    public AdminMenu(DishService dishService, ProductService productService) {
        this.dishService = dishService;
        this.productService = productService;
    }

    @GetMapping(value = "/add")
    public String addDish(Model model) {
        model.addAttribute(new Dish());
        model.addAttribute("dishes", dishService.getAllDishes());
        model.addAttribute("products", productService.getAllProducts());
        return "menu/addDish.html";
    }

    @PostMapping(value = "/add")
    public String processDish(@ModelAttribute @Valid Dish dish, Errors errors,
                              @RequestParam(required = false) Optional<ArrayList<String>> prod,
                              @RequestParam("file") Optional<MultipartFile> file,
                              Model model) throws IOException {
        if (errors.hasErrors()) {
            model.addAttribute("dishes", dishService.getAllDishes());
            model.addAttribute("products", productService.getAllProducts());
            return "menu/addDish.html";
        }
        if (file.isPresent()) {
            File uploadDir = new File(uploadPath);
            if (!uploadDir.exists()) {
                uploadDir.mkdir();
            }
            String uuidFile = UUID.randomUUID().toString();
            String resultFilename = uuidFile + "." + file.get().getOriginalFilename();
            file.get().transferTo(new File(uploadPath + "/" + resultFilename));
            dish.setFileName(resultFilename);
        }
        if (prod.isPresent()) {
            List<Product> prodTemp = new CopyOnWriteArrayList<>();
            prod.get().forEach(s -> prodTemp.add(productService.getByProductName(s)));

            dish.setProductsForDish(prodTemp);
        }
        try {
            dishService.saveDish(dish);
        } catch (DataIntegrityViolationException e) {
            model.addAttribute("error", "existing dish");
            model.addAttribute(new Dish());
            model.addAttribute("dishes", dishService.getAllDishes());
            model.addAttribute("products", productService.getAllProducts());
            return "menu/addDish.html";

        }
        dishService.saveDish(dish);
        return "redirect:/add";
    }

    @PostMapping(value = "/remove")
    public String removeDish(@RequestParam ArrayList<Long> ds) {
        ds.forEach(dishService::deleteByID);
        return "redirect:/add";
    }


}
