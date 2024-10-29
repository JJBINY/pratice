package appsecurity.auth.authentication;

import appsecurity.exception.type.UnauthenticatedException;
import appsecurity.auth.repository.AuthTokenRepository;
import appsecurity.auth.TokenType;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.config.AuthProps;
import appsecurity.auth.jwt.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import static org.apache.commons.lang3.StringUtils.substringAfter;

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
        JwtProvider.Claims claims = jwtProvider.validate(token, TokenType.REFRESH);

        //todo blacklist로 변경
        authTokenRepository.findByUserId(claims.userId())
                .orElseThrow(() -> new UnauthenticatedException())
                .validate(token, ()->new UnauthenticatedException());

        return new UserPrincipal(claims.userId(), claims.role());
    }
}
