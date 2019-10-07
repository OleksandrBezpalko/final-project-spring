package com.training.java.controller;


import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.training.java.entity.Dish;
import com.training.java.entity.OrderDish;
import com.training.java.service.DishService;
import com.training.java.service.OrderService;
import com.training.java.service.ProductService;
import com.training.java.service.UserService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/order")
public class OrderController {
    private final DishService dishService;
    private final UserService userService;
    private final OrderService orderService;
    private final ProductService productService;

    private Optional<OrderDish> orderDish = Optional.empty();

    public OrderController(DishService dishService, UserService userService,
                           OrderService orderService, ProductService productService) {
        this.dishService = dishService;
        this.userService = userService;
        this.orderService = orderService;
        this.productService = productService;
    }

    @GetMapping()
    public String orderPage(Model model) {
        if (!orderDish.isPresent()||orderDish.get().getPriceAll().equals(BigInteger.ZERO)) {
            return "redirect:/";
        }
        Map<Dish, Long> orderClient = new ConcurrentSkipListMap<>();
        dishService.findByOrderID(orderDish.get().getId())
                .stream().distinct().forEach(s -> orderClient.put(s, dishService
                .findByOrderID(orderDish.get().getId()).stream()
                .filter(x -> x.equals(s)).count()));

        model.addAttribute("orderId", orderDish.get().getId());
        model.addAttribute("map", orderClient);
        model.addAttribute("amount", dishService.findByOrderID(orderDish.get().getId()).stream()
                .map(Dish::getPrice).mapToInt(BigInteger::intValue).sum());
        List<String> products = productService.getAllProductsFromOrder(orderDish.get().getId());
        Map<String, Integer> enoughtProducts = enoughtProducts(products);
        if (products.stream().distinct().map(productService::getByProductName)
                .anyMatch(s -> (s.getAmountHave() - enoughtProducts.get(s.getProduct())) < 0)) {
            model.addAttribute("notEnought", "we dont have enought products");
        }
        return "menu/order.html";
    }

    private Map<String, Integer> enoughtProducts(List<String> products) {
        Map<String, Integer> enoughtProducts = new HashMap<>();
        products
                .stream()
                .map(productService::getByProductName)
                .map(s -> enoughtProducts.containsKey(s.getProduct()) ?
                        enoughtProducts.put(s.getProduct(), enoughtProducts.get(s.getProduct()) + 1)
                        : enoughtProducts.put(s.getProduct(), 1)).collect(Collectors.toList());
        return enoughtProducts;
    }

    @PostMapping(value = "/removeD")
    public String deleteDishFromOrder(@RequestParam String name) {
        if (!orderDish.isPresent())return "redirect:/";
        IntStream.range(0, orderDish.get().getDishes().size())
                .filter(s -> orderDish.get().getDishes().get(s).getName().equals(name)).limit(1)
                .forEach(s -> {
                    orderDish.get().setPriceAll(orderDish.get().getPriceAll().subtract(orderDish.get().getDishes()
                            .get(s).getPrice()));
                    orderDish.get().getDishes().remove(s);
                });
        orderService.saveOrder(orderDish.get());
        return "redirect:/order";
    }

    @PostMapping(value = "/addToCard")
    public String addOrder(@RequestParam String dish) {
        if (!orderDish.isPresent()) {
            orderDish = Optional.of(new OrderDish());;
            orderDish.get().setDishes(new CopyOnWriteArrayList<>());
            orderDish.get().setPayed(false);
            orderDish.get().setChecked(false);
            orderDish.get().setToAdmin(false);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            orderDish.get().setUser(userService.findByUsername(authentication.getName()));
        }
        orderDish.get().addDish(dishService.findByDishName(dish));
        orderDish.get().setPriceAll(BigInteger.valueOf(orderDish.get().getDishes().stream()
                .map(Dish::getPrice).mapToInt(BigInteger::intValue).sum()));
        orderService.saveOrder(orderDish.get());
        return "redirect:/";
    }

    @PostMapping(value = "/addedOrder")
    public String addToAdmin() {
        if (!orderDish.isPresent())return "redirect:/";
        List<String> products = productService.getAllProductsFromOrder(orderDish.get().getId());
        Map<String, Integer> enoughtProducts = enoughtProducts(products);
        if (products.stream().distinct().map(productService::getByProductName)
                .anyMatch(s -> s.getAmountHave() - enoughtProducts.get(s.getProduct()) < 0)) {
            return "redirect:/order";
        }
        orderDish.get().setToAdmin(true);
        orderService.saveOrder(orderDish.get());
        orderDish = Optional.empty();
        return "redirect:/";
    }
}
