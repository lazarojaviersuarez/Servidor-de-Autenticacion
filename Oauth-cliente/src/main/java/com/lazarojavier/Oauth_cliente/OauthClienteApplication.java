package com.lazarojavier.Oauth_cliente;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

//@EnableWebSecurity
@SpringBootApplication
public class OauthClienteApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthClienteApplication.class, args);
	}
	//Documentacion
//	https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html#oauth2-client
}
