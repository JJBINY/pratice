package appsecurity.auth.authentication;

import appsecurity.auth.Role;
import appsecurity.auth.exception.UnauthenticatedException;
import appsecurity.auth.jwt.JwtValidationException;
import appsecurity.auth.repository.AuthTokenRepository;
import appsecurity.auth.TokenType;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.config.AuthProps;
import appsecurity.auth.jwt.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import static org.apache.commons.lang3.StringUtils.substringAfter;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticateUserResolver implements HandlerMethodArgumentResolver {
    private final JwtProvider jwtProvider;
    private final AuthProps authProps;
    private final AuthTokenRepository authTokenRepository;

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        boolean hasAnnotation = parameter.hasParameterAnnotation(AuthenticateUser.class);
        boolean hasType = UserPrincipal.class.isAssignableFrom(parameter.getParameterType());
        return hasAnnotation && hasType;
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        String refreshHeader = request.getHeader(authProps.refreshHeader);
        String token = substringAfter(refreshHeader, authProps.scheme).trim();
        log.info("refreshHeader = {}, token = {}", refreshHeader, token);
        try {
            JwtProvider.Claims claims = jwtProvider.validate(token, TokenType.REFRESH);
            //todo blacklist로 변경
            authTokenRepository.findByUserId(claims.userId())
                    .orElseThrow(() -> new UnauthenticatedException())
                    .validate(token, ()->new UnauthenticatedException());

            return new UserPrincipal(claims.userId(), Role.roleOf(claims.roles().get(0))); //todo roles 처리 방법 변경
        }catch (JwtValidationException e){
            throw new UnauthenticatedException(e.getMessage());
        }
    }
}
