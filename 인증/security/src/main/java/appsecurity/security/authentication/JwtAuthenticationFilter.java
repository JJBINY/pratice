package appsecurity.security.authentication;


import appsecurity.security.AuthProps;
import appsecurity.security.jwt.Jwt;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
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
    private final AuthProps props;
    private final Jwt jwt;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = resolveToken(request);

        if (token != null) {
            try {
                Jwt.Claims claims = jwt.verify(token);
                //todo 여기서 authorities 포함한 Authentication을 넘겨 줘야 권한 체크 가능
                Authentication authentication = JwtAuthenticationToken.authenticated(claims.userId(), null, List.of());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }catch (Exception e){
                log.warn("jwt verification failure : {}",e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String tokenHeader = request.getHeader(props.header);

        if (tokenHeader != null && tokenHeader.startsWith(props.scheme)) {
            return substringAfter(tokenHeader, props.scheme).trim();
        }
        return null;
    }
}
