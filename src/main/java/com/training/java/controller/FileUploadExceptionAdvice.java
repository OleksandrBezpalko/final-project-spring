package com.training.java.controller;

import com.training.java.entity.Dish;
import com.training.java.service.DishService;
import com.training.java.service.ProductService;
import lombok.AllArgsConstructor;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@ControllerAdvice
@AllArgsConstructor
public class FileUploadExceptionAdvice {
    private DishService dishService;
    private ProductService productService;

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public String handleMaxSizeException(
            MaxUploadSizeExceededException exc,
            HttpServletRequest request,
            HttpServletResponse response, Model model) {
        model.addAttribute("error1","to huge data of image");
        model.addAttribute(new Dish());
        model.addAttribute("dishes", dishService.getAllDishes());
        model.addAttribute("products", productService.getAllProducts());
        return "menu/addDish.html";
    }
}