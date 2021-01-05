package com.example.springsecurityjwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.springsecurityjwt.config.MyUserDetailsService;
import com.example.springsecurityjwt.util.JwtUtils;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
	
	
	@Autowired
	private MyUserDetailsService myUserDetailsService;
	
	@Autowired
	private JwtUtils jwtUtils;
	
	/**
	 * this is actual method which responsible to filter
	 * 
	 * this will intercept request & look for jwt in header (Authorization bearer)
	 * see that jwt is valid
	 * if it is valid jwt it get user details & save in security context
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authorizationHeader = request.getHeader("Authorization");
		
		String username = null;
		String jwt = null;
		
		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			jwt = authorizationHeader.substring(7);
			username = jwtUtils.extractUsername(jwt);
		}
		
		//check for username is present & verifying any authentication principle is not already gone in security context
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			//getting UserDetails object 
			UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(username);
			
			//checking jwt is valid for this user
			if (jwtUtils.validateToken(jwt, userDetails)) {
				
				/**
				 * creating default token 
				 * (by default spring security used this )
				 * i.e. 'UsernamePasswordAuthenticationToken' for managing authentication in terms of username & password scenario
				 * 
				 * Tip: below steps automatally done spring security for in authentication but here we are overriding it for jwt
				 */
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = 
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		//handover control to the next filter in filter chain
		filterChain.doFilter(request, response);		
	}
}
