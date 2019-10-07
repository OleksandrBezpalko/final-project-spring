package tests;

import com.training.java.entity.Dish;
import org.junit.*;
import org.junit.Test;

import java.math.BigInteger;

public class TestDish {
    final private static String DISH_NAME = "DishTEST";
    final private static String FILE_NAME1 = "File1";
    final private static String FILE_NAME2 = "File2";
    private Dish dish;



    @Before
    public void constr() {
        dish = new Dish();
    }

    @Test(expected = NumberFormatException.class)
    public void testSetPrice() {
        dish.setPrice(BigInteger.valueOf(Integer.valueOf("123,23")));
    }


    @Test(timeout = 1000)
    public void testSetName() {
        dish.setName(null);
        Assert.assertNull(dish.getName());
    }

    @Test
    public void testCompare() {
        dish.setName(DISH_NAME);
        dish.setFileName(FILE_NAME1);
        Dish dish1 = new Dish();
        dish1.setName(DISH_NAME);
        dish1.setFileName(FILE_NAME2);
        Assert.assertEquals(dish1.compareTo(dish), 0);
    }

    @Test
    public void testEquals() {
        dish.setName(DISH_NAME);
        dish.setFileName(FILE_NAME1);
        Dish dish1 = new Dish();
        dish1.setName(DISH_NAME);
        dish1.setFileName(FILE_NAME2);
        Assert.assertNotSame(dish1, dish);
    }

    @After
    public void postmethod() {
        dish = null;
    }
}
