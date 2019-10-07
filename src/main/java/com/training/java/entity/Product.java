package com.training.java.entity;


import lombok.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import javax.persistence.*;

import java.util.List;
import java.util.Set;


@AllArgsConstructor
@Getter
@Setter
@ToString
@NoArgsConstructor
@Entity
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String product;
    private int amountHave;
    private int maxAmount;
    private int minAmount;
    private int productInBox;
    @OneToMany(mappedBy="prodLikeNow")
    private Set<User> userLike;

    @ManyToMany(mappedBy = "productsForDish", fetch = FetchType.LAZY)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private List<Dish> dishes;
}
