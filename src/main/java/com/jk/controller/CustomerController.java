package com.jk.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.jk.entity.Customer;
import com.jk.repo.CustomerRepository;
import com.jk.service.JWTService;

@RestController
public class CustomerController {
	@Autowired
	private CustomerRepository customerRepository;

	@Autowired
	private PasswordEncoder encoder;

	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private JWTService jwtService;

	@PostMapping("/register")
	public ResponseEntity<String> register(@RequestBody Customer customer) {
		String encodedPwd = encoder.encode(customer.getPwd());
		customer.setPwd(encodedPwd);
		customerRepository.save(customer);
		return new ResponseEntity<String>("Record Added", HttpStatus.CREATED);
	}
	
	@GetMapping("/welcome")
	public String welcome() {
		return "Welcome to JK Infotech";
	}

	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody Customer customer) {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(customer.getEmail(),
				customer.getPwd());
		try {
			Authentication authentication = authManager.authenticate(token);
			if (authentication.isAuthenticated()) {
				String jwtToken = jwtService.generateToken(customer.getEmail());
				System.out.println(jwtToken);
				return new ResponseEntity<>(jwtToken, HttpStatus.OK);
			}
		} catch (Exception e) {
			return new ResponseEntity<>("Unable to login", HttpStatus.BAD_REQUEST);
		}
		return new ResponseEntity<String>("Invalid Credentials", HttpStatus.BAD_REQUEST);

	}
}
