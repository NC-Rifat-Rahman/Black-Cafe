package com.inn.cafe.service;

import com.inn.cafe.wrapper.ProductWrapper;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

public interface ProductService
{
    ResponseEntity<String> addNewProduct(Map<String,String> requestMap);

    ResponseEntity<List<ProductWrapper>> getAllProduct();

    ResponseEntity<String> updateProduct(Map<String,String> requestMap);
    //ResponseEntity<String> deleteProduct(Map<String,String> requestMap);
}
