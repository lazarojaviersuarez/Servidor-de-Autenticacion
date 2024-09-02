package com.lazarojavier.Oauth_cliente.ControllerClient;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController

public class ClientController {
    @GetMapping("/hello")
    public ResponseEntity<String> Hello(){
        return ResponseEntity.ok("Todo Ok");
    }

    @GetMapping("/authorized")
    public Map<String,String>Authorized(@RequestParam String authorizationCode){
  return Collections.singletonMap("authorizationCode",authorizationCode);
    }
}
