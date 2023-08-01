package com.ark.center.auth.infra.authentication.token.cache;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public abstract class AbstractSecurityContextRepository implements SecurityContextRepository {

    public AbstractSecurityContextRepository() {
    }

}
