package appsecurity.auth.jwt;

import org.springframework.stereotype.Component;

@Component
public class UniqueIdGenerator {
    private static long seq;
    public long generate(){
        return seq++; //todo timestamp:serverId:seq 형태의 유일 아이디 생성
    };
}
