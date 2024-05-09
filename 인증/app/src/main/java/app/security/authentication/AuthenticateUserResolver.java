package app.security.authentication;

import app.exception.type.UnauthenticatedException;
import app.security.Refresh;
import app.security.RefreshRepository;
import app.user.User;
import app.user.UserRepository;
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
    private final UserRepository userRepository;
    private final JwtConfigProps jwtConfigProps;
    private final RefreshRepository refreshRepository;
    private final Jwt jwt;

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        boolean hasLoginAnnotation = parameter.hasParameterAnnotation(AuthenticateUser.class);
        boolean hasMemberType = User.class.isAssignableFrom(parameter.getParameterType());
        return hasLoginAnnotation && hasMemberType;
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {

        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        String refreshHeader = request.getHeader(jwtConfigProps.getRefreshHeader());
        String token = substringAfter(refreshHeader, jwtConfigProps.scheme).trim();
        Jwt.Claims claims = jwt.verify(token, TokenType.REFRESH);
        Refresh refresh = refreshRepository.findByUserId(claims.userId()).orElseThrow(() -> new UnauthenticatedException());
        if (!token.equals(refresh.getToken())) {
            throw new UnauthenticatedException();
        }
        return userRepository.findById(claims.userId()).orElseThrow(() -> new UnauthenticatedException());
    }
}
