package com.photoapp.users.models.requests;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class CreateUserRequest {
    @NotNull(message ="First name cannot be null")
    @Size(min = 2,message = "First name cant be less than two characters")
    private String firstName;
    private String lastName;
    @NotNull(message ="Password cannot be null")
    @Size(min = 3, max = 10, message = "Password must be between 3 and 10 characters !!")
    private String password;
    @Email
    private String email;

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
