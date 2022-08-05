package com.inn.cafe.wrapper;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// Get and update users
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserWrapper
{
    private Integer id;
    private String name;
    private String email;
    private String contactNumber;
    private String status;
}
