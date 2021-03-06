package com.training.java.repository;

import com.training.java.entity.Dish;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.List;

@Transactional
@Repository
public interface DishRepository extends JpaRepository<Dish, Long> {
    Dish findByName(String name);
    Page<Dish> findAll(Pageable pageable);

    @Query(value = "select  d.id,d.file_name, d.name,d.price,d.name_ukr \n" +
            "from dish d,order_dish_dishes o,order_dish o2\n" +
            "where d.id=o.dishes_id && o.orders_with_dish_id=o2.id && o2.checked=0&&o2.id=:id",
            nativeQuery = true)
    List<Dish> findByOrder(@Param("id") Long longN);

    @Query(value = "select  d.id,d.file_name, d.name,d.price,d.name_ukr \n" +
            "from dish d,order_dish_dishes o,order_dish o2\n" +
            "where d.id=o.dishes_id && o.orders_with_dish_id=o2.id && o2.checked=1&&o2.id=:id",
            nativeQuery = true)
    List<Dish> findByOrderToUser(@Param("id") Long longN);
}
