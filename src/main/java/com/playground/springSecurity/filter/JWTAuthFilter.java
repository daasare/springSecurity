package com.playground.springSecurity.filter;

import com.playground.springSecurity.security.AppUserDetails;
import com.playground.springSecurity.security.AppUserDetailsService;
import com.playground.springSecurity.security.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 1. Why OncePerRequestFilter?
 * If the standard javax.servlet.Filter interface is used, JWT validation logic might run multiple times for the same user request.
 *     The Problem: Re-validating a JWT multiple times is computationally expensive (cryptographic signatures) and unnecessary.
 *     The Solution: OncePerRequestFilter guarantees that the filter is executed exactly once per request thread. Even if the request is forwarded internally, Spring identifies that this filter has already done its job.
 * 2. Why doFilterInternal?
 * When you extend OncePerRequestFilter, you don't override the standard doFilter. Instead, you override doFilterInternal.
 *     Spring handles the "once per request" logic in its own doFilter method.
 *     Once Spring confirms this is the first time the filter is hitting this request, it calls your doFilterInternal.
 *     It provides you with HttpServletRequest and HttpServletResponse directly, so you don't have to manually cast them (as you would with the standard ServletRequest).
 * What usually goes inside that method?
 * For JWT setup, the logic follows a very predictable pattern:
 *     Extract: Look for the Authorization header and pull out the "Bearer <token>".
 *     Validate: Check if the token is expired or has been tampered with.
 *     Identify: Get the username (or email) from the token.
 *     Set Context: If the user is valid, tell Spring Security "This user is authenticated" by updating the SecurityContextHolder.
 *     Continue: Always call filterChain.doFilter(request, response) at the end so the request can move to the next filter or your Controller.
 * **/

@Component
@RequiredArgsConstructor
public class JWTAuthFilter extends OncePerRequestFilter {

    private final JWTUtils jwtUtils;
    private final AppUserDetailsService userDetailsService;

    // TODO
    /**
     * 1. Extract token from request header (Authorization)
     * 2. Verify if our server generated this token and the expiration date
     * 3. Extract username from the token
     * 4. Put or insert authenticated user info into the security context
     * **/

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
        if (authHeader != null && authHeader.startsWith("Bearer")) {

            // the authHeader will contain value of "Bearer + the actual token"
            // so since we need the actual token, we remove the "Bearer" word from
            // the real token
            token = authHeader.substring(7);
            username = jwtUtils.extractUsernameFromToken(token);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtUtils.verifyToken((AppUserDetails) userDetails, token)) {
                // "UsernamePasswordAuthenticationToken" is needed so we pass detailed info
                // about the authenticated user to "SecurityContextHolder"
                // also "SecurityContext" authentication object as a parameter
                // authUserDetails is "UsernamePasswordAuthenticationToken" coz we will
                // get the option to add more info to our object.
                UsernamePasswordAuthenticationToken authUserDetails = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                // "WebAuthenticationDetailsSource" gets more info from the request so
                // we can put into the security context
                // it's also help in auditing
                authUserDetails.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authUserDetails);
            }
        }
        filterChain.doFilter(request, response);
    }
}
