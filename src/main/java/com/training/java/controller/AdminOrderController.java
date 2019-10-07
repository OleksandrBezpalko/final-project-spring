package com.training.java.controller;

import com.training.java.entity.Dish;
import com.training.java.entity.Product;
import com.training.java.service.DishService;
import com.training.java.service.OrderService;
import com.training.java.service.ProductService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.stream.Collectors;


@Controller
@PreAuthorize("hasAuthority('ADMIN')")
public class AdminOrderController {
    private final DishService dishService;
    private final OrderService orderService;
    private final ProductService productService;

    public AdminOrderController(DishService dishService, OrderService orderService, ProductService productService) {
        this.dishService = dishService;
        this.orderService = orderService;
        this.productService = productService;
    }

    @GetMapping("/adminOrder")
    public String adminOrder(Model model) {
        model.addAttribute("ind", orderService.confirmToAdmin());
        model.addAttribute("products", productService.getAllProducts());
        if (productService.getAllProducts().stream()
                .filter(s -> s.getAmountHave() < s.getMinAmount()).count() > 0) {
            return replenish();
        }
        return "menu/adminOrder.html";
    }

    @PostMapping("/replenish_stock_of_products")
    public String replenish() {
        List<Product> products = productService.getAllProducts();
        for (Product product : products) {

            product.setAmountHave(product.getAmountHave() + product.getProductInBox() *
                    ((product.getMaxAmount() - product.getAmountHave()) / product.getProductInBox()));

            productService.saveProduct(product);
        }
        return "redirect:/adminOrder";
    }


    @GetMapping("/checkOrder")
    public String checkorder(@RequestParam Long ind, Model model) {
        model.addAttribute("index", ind);
        Map<Dish, Long> orderClient = new ConcurrentSkipListMap<>();
        dishService.findByOrderID(ind)
                .stream().distinct().forEach(s -> orderClient.put(s, dishService
                .findByOrderID(ind).stream()
                .filter(x -> x.equals(s)).count()));

        model.addAttribute("map", orderClient);
        Map<String, Long> neededProducts = new ConcurrentSkipListMap<>();
        productService.getAllProductsFromOrder(ind).stream().map(s -> neededProducts.containsKey(s) ?
                neededProducts.put(s, neededProducts.get(s) + 1L)
                : neededProducts.put(s, 1L)).collect(Collectors.toList());

        model.addAttribute("map2", neededProducts);
        return "menu/checkPage.html";
    }

    @PostMapping("/checkOrder/Confirm")
    public String confirm(@RequestParam Long ind) {

        orderService.confirm(ind);
        return "redirect:/adminOrder";
    }
}
