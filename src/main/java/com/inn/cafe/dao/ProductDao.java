package com.inn.cafe.dao;

import com.inn.cafe.POJO.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductDao extends JpaRepository<Product,Integer>
{

}
