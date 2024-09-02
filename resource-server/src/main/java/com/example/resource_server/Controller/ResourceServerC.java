package com.example.resource_server.Controller;


import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping(path = "/server")
@RestController
public class ResourceServerC {
    @GetMapping("/read")
    public ResponseEntity<String>read_user(Authentication authentication){
          return   ResponseEntity.ok("Todo esta bien leer"+authentication.getAuthorities());
    }
    @PostMapping("/write")
    public ResponseEntity<String>write_user(Authentication authentication){
          return   ResponseEntity.ok("Todo esta bien escribir"+authentication.getAuthorities());
    }
}
