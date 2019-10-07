package com.training.java.repository;

import com.training.java.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.List;

@Repository
@Transactional
public interface ProductRepository extends JpaRepository<Product, Long> {
    Product findByProduct(String product);

    @Modifying
    @Query(value = "select p.product\n" +
            "    from dish d,order_dish o,dish_products_for_dish dp,product p,order_dish_dishes od\n" +
            "    where o.id=:id&&dp.dishes_id=d.id&&p.id=dp.products_for_dish_id\n" +
            "    &&od.dishes_id=d.id&&od.orders_with_dish_id=:id",
            nativeQuery = true)
    List<String> getProductsFromOrder(@Param("id") Long longn);
}
