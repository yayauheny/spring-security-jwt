package by.yayauheny.security.dto;

public record RegisterRequest(
        String firstname,
        String lastname,
        String email,
        String password,
        String role) {
}
