package com.training.java.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Digits;
import java.math.BigInteger;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class BalanceDto {
    @Digits(integer=5, fraction=0, message = "Please not more then 5 symbols")
    private BigInteger moneyToAdd;

    public void setMoneyToAdd(BigInteger moneyToAdd) {
        if (moneyToAdd.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("Please only positive numbers");
        }
        this.moneyToAdd = moneyToAdd;
    }
}
