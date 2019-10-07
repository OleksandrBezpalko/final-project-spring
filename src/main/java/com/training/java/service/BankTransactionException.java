package com.training.java.service;

public class BankTransactionException extends Exception {

    private static final long serialVersionUID = 1111L;

    BankTransactionException(String message) {
        super(message);
    }
}