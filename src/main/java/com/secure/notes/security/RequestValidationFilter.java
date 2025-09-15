package com.secure.notes.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RequestValidationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String validationHeader = request.getHeader("X-Valid-Request");
        if (validationHeader == null || !validationHeader.equals("true")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing or invalid X-Valid-Request header");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
