package com.photoapp.users.controllers;

import com.photoapp.users.data.UserEntity;
import com.photoapp.users.models.requests.CreateUserRequest;
import com.photoapp.users.models.responses.CreateUserResponses;
import com.photoapp.users.services.UsersService;
import com.photoapp.users.shared.UserDto;
import jakarta.validation.Valid;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.print.attribute.standard.Media;

@RestController
@RequestMapping("/users")
public class UsersController {
    @Autowired
    UsersService usersService;
    @Autowired
    private Environment env;
    @GetMapping(path="/status/check")
    public String status()
    {
        return "Working hard on my new api gateway route on port " + env.getProperty("local.server.port");
    }
    @PostMapping()
    public ResponseEntity<CreateUserResponses> createUser(@Valid @RequestBody CreateUserRequest userDetails){

        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
        UserDto userDto = modelMapper.map(userDetails, UserDto.class);
        UserDto createdUserDto = usersService.createUser(userDto);

        CreateUserResponses returnValue = modelMapper.map(createdUserDto,CreateUserResponses.class);
        return ResponseEntity.status(HttpStatus.CREATED).body(returnValue);
    }

}
