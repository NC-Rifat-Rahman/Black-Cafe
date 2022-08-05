package com.inn.cafe.serviceimpl;

import com.inn.cafe.JWT.JwtFilter;
import com.inn.cafe.POJO.Product;
import com.inn.cafe.constents.CafeConstants;
import com.inn.cafe.dao.ProductDao;
import com.inn.cafe.service.ProductService;
import com.inn.cafe.utils.CafeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class ProductServiceImpl implements ProductService
{

    @Autowired
    ProductDao productDao;

    @Autowired
    JwtFilter jwtFilter;

    @Override
    public ResponseEntity<String> addNewProduct(Map<String, String> requestMap) {
        try
        {
            if(jwtFilter.isAdmin())
            {
                if(validateProductMap(requestMap,false))
                {
                    
                }
            }
            else
                return CafeUtils.getResponseEntity(CafeConstants.UNAUTHORIZED_ACCESS,HttpStatus.UNAUTHORIZED);
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private boolean validateProductMap(Map<String, String> requestMap, boolean b) {
    }
}
