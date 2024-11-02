package com.photoapp.users.services;

import com.photoapp.users.data.UserEntity;
import com.photoapp.users.data.UsersRepository;
import com.photoapp.users.shared.UserDto;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.modelmapper.spi.MatchingStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.UUID;
@Service
public class UserServiceImpl implements  UsersService {

     UsersRepository usersRepository;
     BCryptPasswordEncoder bCryptPasswordEncoder;

     @Autowired
    public UserServiceImpl(UsersRepository usersRepository, BCryptPasswordEncoder bCryptPasswordEncoder){
        this.usersRepository = usersRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }
    @Override
    public UserDto createUser(UserDto userDetails) {

        userDetails.setUserId(UUID.randomUUID().toString());
        userDetails.setEncryptedPassword(bCryptPasswordEncoder.encode(userDetails.getPassword()));
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
        UserEntity userEntity = modelMapper.map(userDetails, UserEntity.class);
        usersRepository.save(userEntity);

        UserDto returnValue = modelMapper.map(userEntity, UserDto.class);
        return returnValue;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

       UserEntity userEntity = usersRepository.findByEmail(username);
       if(userEntity == null) throw new UsernameNotFoundException(username);

       return new User(userEntity.getEmail(), userEntity.getEncryptedPassword(), true,
                true, true, true,
                new ArrayList<>());
    }

    @Override
    public UserDto getUserDetailsByEmail(String email) {

        UserEntity userEntity = usersRepository.findByEmail(email);
        if(userEntity == null) throw new UsernameNotFoundException(email);
        return new ModelMapper().map(userEntity,UserDto.class );
    }
}
