package mate.academy.service.impl;

import java.util.Optional;
import mate.academy.exception.AuthenticationException;
import mate.academy.exception.RegistrationException;
import mate.academy.lib.Inject;
import mate.academy.lib.Service;
import mate.academy.model.User;
import mate.academy.service.AuthenticationService;
import mate.academy.service.UserService;
import mate.academy.util.HashUtil;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    @Inject
    private UserService userService;

    @Override
    public User login(String email, String password) throws AuthenticationException {
        validateData(email, password);
        Optional<User> userFromDbOptional = userService.findByEmail(email);

        if (userFromDbOptional.isPresent()) {
            User user = userFromDbOptional.get();
            String hashedPassword = HashUtil.hashPassword(password, user.getSalt());
            if (user.getPassword().equals(hashedPassword)) {
                return user;
            }
        }
        throw new AuthenticationException("Can't authenticate User");
    }

    @Override
    public User register(String email, String password) throws RegistrationException {
        validateData(email, password);
        Optional<User> userFromDbOptional = userService.findByEmail(email);
        if (userFromDbOptional.isEmpty()) {
            User user = new User();
            user.setEmail(email);
            user.setPassword(password);
            return userService.add(user);
        }
        throw new RegistrationException("User with this email already exists");
    }

    private void validateData(String email, String password) {
        if (email.isEmpty() || password.isEmpty()) {
            throw new RuntimeException("Email or Password are empty");
        }
    }
}
