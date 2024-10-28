package appsecurity.security.authentication;

import appsecurity.exception.type.UnauthenticatedException;
import appsecurity.security.AuthProps;
import appsecurity.security.UserPrincipal;
import appsecurity.security.jwt.Jwt;
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
    private final Jwt jwt;
    private final AuthProps props;
    private final RefreshRepository refreshRepository;

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        boolean hasAnnotation = parameter.hasParameterAnnotation(AuthenticateUser.class);
        boolean hasType = UserPrincipal.class.isAssignableFrom(parameter.getParameterType());
        return hasAnnotation && hasType;
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {

        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        String refreshHeader = request.getHeader(props.refreshHeader);
        String token = substringAfter(refreshHeader, props.scheme).trim();
        Jwt.Claims claims = jwt.verify(token, TokenType.REFRESH);
        Refresh refresh = refreshRepository.findByUserId(claims.userId()).orElseThrow(() -> new UnauthenticatedException());
        if (!token.equals(refresh.getToken())) {
            throw new UnauthenticatedException();
        }
        return new UserPrincipal(claims.userId(), claims.role());
    }
}
