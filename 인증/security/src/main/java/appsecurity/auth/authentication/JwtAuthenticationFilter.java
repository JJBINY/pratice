package appsecurity.auth.authentication;


import appsecurity.auth.config.AuthProps;
import appsecurity.auth.jwt.JwtProvider;
import appsecurity.auth.jwt.JwtValidationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.substringAfter;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AuthProps authProps;
    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(authProps.header);
        log.info("JwtAuthenticationFilter: authHeader = {}",authHeader);
        if (authHeader == null || !authHeader.startsWith(authProps.scheme)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = substringAfter(authHeader, authProps.scheme).trim();
        log.info("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ accessToken = {}",accessToken);
        try {
            JwtProvider.Claims claims = jwtProvider.validate(accessToken);
            log.info("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@claims = {}",claims);
            Authentication authentication = JwtAuthenticationToken.authenticated(claims.userId(), null, List.of(new SimpleGrantedAuthority(claims.role().role())));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtValidationException e) {
            log.warn("jwt verification failure : {}", e.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
