package com.inn.cafe.rest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RequestMapping(path = "/bill")
public interface BillRest
{
    @PostMapping(path = "/generateReport")
    ResponseEntity<String> generateReport(@RequestBody Map<String,Object> requestMap);
}
