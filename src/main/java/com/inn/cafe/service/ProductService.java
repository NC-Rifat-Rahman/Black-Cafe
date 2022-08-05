package com.inn.cafe.service;

import org.springframework.http.ResponseEntity;

import java.util.Map;

public interface ProductService
{
    ResponseEntity<String> addNewProduct(Map<String,String> requestMap);
}
