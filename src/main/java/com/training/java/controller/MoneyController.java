package com.training.java.controller;

import com.training.java.dto.BalanceDto;
import com.training.java.entity.Dish;
import com.training.java.entity.User;
import com.training.java.service.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.stream.Collectors;

@Controller
@Slf4j
public class MoneyController {
    private final
    UserService userService;
    private final
    OrderService orderService;
    private final
    DishService dishService;
    private final
    ProductService productService;

    public MoneyController(UserService userService, OrderService orderService, DishService dishService, ProductService productService) {
        this.userService = userService;
        this.orderService = orderService;
        this.dishService = dishService;
        this.productService = productService;
    }

    @GetMapping("/addMoney")
    public String addMoney(Model model) {
        model.addAttribute(new BalanceDto());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("moneyBalance", userService.findByUsername(authentication.getName())
                .getMoneyHave());
        return "menu/addBalance.html";
    }

    @PostMapping(value = "/addBalance")
    public String addMoneyBase(@ModelAttribute @Valid BalanceDto balanceDto, Errors errors,
                               Model model) {
        if (errors.hasErrors()) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            model.addAttribute("moneyBalance", userService.findByUsername(authentication.getName())
                    .getMoneyHave());
            return "menu/addBalance.html";
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = userService.findByUsername(authentication.getName());
        user.setMoneyHave(user.getMoneyHave().add(balanceDto.getMoneyToAdd()));
        userService.saveNewUser(user);
        return "redirect:/addMoney";
    }

    @GetMapping("/user_confirm")
    public String userConfirm(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("ind", orderService.confirmToUser
                (userService.getUserIdByUsername(authentication.getName())));
        return "menu/PayOrder.html";
    }

    private Map<String, Integer> prodNeeded(List<String> products) {
        Map<String, Integer> enoughtProducts = new HashMap<>();
        products
                .stream()
                .map(productService::getByProductName)
                .map(s -> enoughtProducts.containsKey(s.getProduct()) ?
                        enoughtProducts.put(s.getProduct(), enoughtProducts.get(s.getProduct()) + 1)
                        : enoughtProducts.put(s.getProduct(), 1)).collect(Collectors.toSet());
        return enoughtProducts;
    }

    @GetMapping("/checkOrderUser")
    public String checkOrderUSer(@RequestParam Long ind, Model model) {
        model.addAttribute("index", ind);
        Map<Dish, Long> orderClient = new ConcurrentSkipListMap<>();
        dishService.findByOrderIDToUSer(ind)
                .stream().distinct().forEach(s -> orderClient.put(s, dishService
                .findByOrderIDToUSer(ind).stream()
                .filter(x -> x.equals(s)).count()));
        List<String> products = productService.getAllProductsFromOrder(ind);
        Map<String, Integer> enoughtProducts = prodNeeded(products);
        if (products.stream().distinct().map(productService::getByProductName)
                .anyMatch(s -> s.getAmountHave() - enoughtProducts.get(s.getProduct()) < 0)) {
            model.addAttribute("notEnought", ind);
        }
        model.addAttribute("map", orderClient);
        model.addAttribute("price", orderService.getByOrderId(ind).getPriceAll());
        return "menu/checkPageUser.html";
    }

    @GetMapping("/checkOrderUser/Confirm")
    public String notEnoughtMoney(){
        return "redirect:/user_confirm";
    }

    @PostMapping("/checkOrderUser/Confirm")
    public String confirm(@RequestParam Long ind,
                          @RequestParam BigInteger price, Model model) {
        if (orderService.getByOrderId(ind).isPayed()){
            return "redirect:/user_confirm";
        }
        List<String> products = productService.getAllProductsFromOrder(ind);
        Map<String, Integer> enoughtProducts = prodNeeded(products);
        List<String> best = enoughtProducts.keySet().stream().filter(s -> enoughtProducts.get(s)
                .equals(enoughtProducts.keySet().stream()
                        .map(enoughtProducts::get).max(Integer::compareTo).get())).collect(Collectors.toList());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = userService.findByUsername(authentication.getName());
        user.setProdLikeNow(productService.getByProductName(best.get(0)));
        userService.saveNewUser(user);

        if (products.stream().distinct().map(productService::getByProductName)
                .anyMatch(s -> s.getAmountHave() - enoughtProducts.get(s.getProduct()) < 0)) {
            model.addAttribute("ind", orderService.confirmToUser
                    (userService.getUserIdByUsername(authentication.getName())));
            model.addAttribute("notEnought",  ind);
            return "menu/PayOrder.html";
        }
        try {
            userService.payTheOrder(price);
        } catch (BankTransactionException e) {

            model.addAttribute(new BalanceDto());
            model.addAttribute("moneyBalance", userService.findByUsername(authentication.getName())
                    .getMoneyHave());
            model.addAttribute("notEnoughtMoney", "nEnought");
            return "menu/addBalance.html";
        }
        productService.getAllProductsFromOrder(ind).stream().map(productService::getByProductName)
                .forEach(s -> {
                    s.setAmountHave(s.getAmountHave() - 1);
                    productService.saveProduct(s);
                });

        orderService.payed(ind);
        return "redirect:/";
    }


}
