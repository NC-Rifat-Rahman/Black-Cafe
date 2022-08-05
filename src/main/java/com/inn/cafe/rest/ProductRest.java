package com.inn.cafe.rest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RequestMapping(path = "/product")
public interface ProductRest
{
    @PostMapping(path = "/add")
    ResponseEntity<String> addNewProduct(@RequestBody Map<String,String> requestMap);
}
