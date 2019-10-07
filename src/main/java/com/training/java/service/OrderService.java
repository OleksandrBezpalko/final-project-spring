package com.training.java.service;


import com.training.java.entity.OrderDish;
import com.training.java.repository.OrderDishRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@AllArgsConstructor
public class OrderService {

    private final OrderDishRepository orderDishRepository;

    public void saveOrder(OrderDish orderDish) {
        orderDishRepository.save(orderDish);
    }

    public OrderDish getByOrderId(Long id) {
        return orderDishRepository.getByOrderID(id);
    }

    public List<Long> confirmToAdmin() {
        return orderDishRepository.findOrderUncheckedIndex();
    }

    public List<Long> confirmToUser(Long id) {
        return orderDishRepository.findUnConfirmed(id);
    }

    public void confirm(Long indOrder) {
        orderDishRepository.setChecked(indOrder);
    }

    public void payed(Long indOrder) {
        orderDishRepository.setPayed(indOrder);
    }

}
