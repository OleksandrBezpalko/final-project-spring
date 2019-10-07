package com.training.java.entity;


import lombok.*;
import javax.persistence.*;
import javax.validation.constraints.Digits;
import javax.validation.constraints.NotNull;

import java.math.BigInteger;
import java.util.List;


@AllArgsConstructor
@Getter
@Setter
@ToString
@NoArgsConstructor
@Entity
public class OrderDish {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @NotNull
    @ManyToMany
    List<Dish> dishes;
    private boolean checked;
    private boolean toAdmin;
    private boolean payed;
    @Digits(integer=5, fraction=0)
    private BigInteger priceAll;
    @ManyToOne
    private User user;
    public void addDish(Dish dish){
        dishes.add(dish);
    }
}
