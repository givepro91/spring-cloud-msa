package com.example.userservice.vo;

import lombok.Data;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
public class RequestUserUpdate {
    @NotNull
    private String userId;
    @NotNull
    @Size(min = 2, message = "Name not be less than two characters")
    private String name;
    @Size(min = 8, message = "Password must be equal or grater than 8 characters")
    private String pwd;
}
