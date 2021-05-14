package com.supportportal.resource;

import com.supportportal.domain.User;
import com.supportportal.exception.domain.EmailExistException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/user")
public class UserResource {

    @GetMapping("/home")
    public String showUser() throws EmailExistException {
        // return "Application works";
        throw new EmailExistException(("This email address is already taken"));
    }

}
