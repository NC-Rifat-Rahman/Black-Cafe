package com.inn.cafe.restImpl;

import com.inn.cafe.constents.CafeConstants;
import com.inn.cafe.rest.ProductRest;
import com.inn.cafe.service.ProductService;
import com.inn.cafe.utils.CafeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ProductRestImpl implements ProductRest {

    @Autowired
    ProductService productService;

    @Override
    public ResponseEntity<String> addNewProduct(Map<String, String> requestMap) {
        try
        {
            return productService.addNewProduct(requestMap);
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG, HttpStatus.BAD_REQUEST);
    }
}
