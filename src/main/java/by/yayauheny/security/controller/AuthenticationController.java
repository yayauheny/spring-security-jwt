package by.yayauheny.security.controller;

import by.yayauheny.security.dto.AuthenticationResponse;
import by.yayauheny.security.dto.RegisterRequest;
import by.yayauheny.security.service.AuthenticationService;
import by.yayauheny.security.utils.ControllerUtils;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request,
            HttpServletResponse response
    ) {
        AuthenticationResponse authenticationResponse = authenticationService.register(request);
        ControllerUtils.setHttpOnlySecureCookie(response, "token", authenticationResponse.token());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody RegisterRequest request,
            HttpServletResponse response
    ) {
        AuthenticationResponse authenticationResponse = authenticationService.authenticate(request);
        ControllerUtils.setHttpOnlySecureCookie(response, "token", authenticationResponse.token());
        return ResponseEntity.ok().build();
    }
}
