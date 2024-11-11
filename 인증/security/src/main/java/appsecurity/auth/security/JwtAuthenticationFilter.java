package appsecurity.auth.security;


import appsecurity.auth.config.AuthProps;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.apache.commons.lang3.StringUtils.substringAfter;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AuthProps authProps;
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JwtAuthenticationFilter in progress");
        String authHeader = request.getHeader(authProps.header);

        log.info("JwtAuthenticationFilter: authHeader = {}", authHeader);
        if (authHeader == null || !authHeader.startsWith(authProps.scheme)) {
            request.setAttribute("msg", "인증 헤더가 올바르지 않습니다");
            filterChain.doFilter(request, response);
            return;
        }

        var accessToken = substringAfter(authHeader, authProps.scheme).trim();
        var unauthenticated = JwtAuthentication.unauthenticated(accessToken);
        var authentication = authenticationManager.authenticate(unauthenticated);

        if(!authentication.isAuthenticated()){
            request.setAttribute("msg", "인증 토큰이 유효하지 않습니다");
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("인증 성공 !! AuthUser = {}",authentication.getPrincipal());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
