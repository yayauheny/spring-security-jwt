package by.yayauheny.security.dto;

public record AuthenticationRequest(
        String token,
        String password) {
}
