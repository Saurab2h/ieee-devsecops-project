package com.ieee.vulnapp.controller;

import org.springframework.web.bind.annotation.*;

@RestController
public class TestController {

    @GetMapping("/")
    public String home() {
        return "IEEE DevSecOps Test App";
    }

    @GetMapping("/search")
    public String search(@RequestParam String q) {
        return "Search result for: " + q;
    }
}
