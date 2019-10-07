package com.training.java.entity;


import lombok.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import javax.persistence.*;
import javax.validation.constraints.Digits;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.math.BigInteger;
import java.util.List;


@AllArgsConstructor
@Getter
@Setter
@ToString
@NoArgsConstructor
@Entity
@Table(uniqueConstraints = {@UniqueConstraint(columnNames = {"name"})})
public class Dish implements Comparable<Dish> {
    /**
     * id getted from db of dish
     */
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    /**
     * file name of dish to load from html
     */
    private String fileName;
    /**
     * name of dish must be in size if min 5 to max 25 symblos
     * used in default locale
     */
    @Size(min = 4, max = 25)
    @NotNull(message = "please enter name of dish")
    private String name;
    /**
     * name of dish must be in size if min 5 to max 25 symblos
     * used in ukr locale
     */
    @Size(min = 4, max = 25)
    @NotNull(message = "please enter name of dish")
    private String nameUkr;
    /**
     * price of dish max length of 5 symbols
     * @since 1.0
     */
    @NotNull
    @Digits(integer=5, fraction=0, message = "please not more then 5 symbols")
    private BigInteger price;
    /**
     * orders with this dish
     * many to many relation in db
     */
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToMany(mappedBy = "dishes", fetch = FetchType.LAZY)
    List<OrderDish> ordersWithDish;
    /**
     * products which this dish contains
     */
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToMany
    private List<Product> productsForDish;

    /**
     * @param o
     * used to compare to dishes in their alfabetical order
     * @return int of compare 0 if simular
     * less zero if first less
     * more then zero if second arg less
     */
    @Override
    public int compareTo(Dish o) {
        return this.name.compareTo(o.getName());
    }
}
