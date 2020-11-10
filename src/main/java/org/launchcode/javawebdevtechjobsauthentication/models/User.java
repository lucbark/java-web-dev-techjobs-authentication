package org.launchcode.javawebdevtechjobsauthentication.models;
import javax.persistence.Entity;
import javax.validation.constraints.NotBlank;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
@Entity
public class User extends AbstractEntity{ //made it an entity
    @NotNull
    private String username; //username

    @NotNull
    private String pwHash; //encrypted password field

    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(); //static encoder variable

    public User() {}

    public User(String username, String password) { //encode the password field
        this.username = username;
        this.pwHash = encoder.encode(password);
    }

    public String getUsername() {
        return username;
    }

    public boolean isMatchingPassword(String password) { //method to check pw value/hashes
        return encoder.matches(password, pwHash);
    }

}
