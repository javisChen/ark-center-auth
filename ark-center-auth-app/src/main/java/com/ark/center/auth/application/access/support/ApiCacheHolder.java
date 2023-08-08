//package com.ark.center.auth.application.access.support;
//
//import com.ark.center.auth.domain.api.AuthApi;
//import com.ark.center.auth.domain.user.gateway.ApiGateway;
//import com.ark.center.auth.infra.api.support.ApiCommonUtils;
//import org.jetbrains.annotations.NotNull;
//import org.springframework.beans.factory.InitializingBean;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//
//import java.util.List;
//import java.util.Map;
//import java.util.stream.Collector;
//import java.util.stream.Collectors;
//
///**
// * Api缓存
// */
//@Component
//public class ApiCacheHolder implements InitializingBean {
//
//    @Autowired
//    private ApiGateway apiGateway;
//
//    /**
//     * 无需授权api缓存
//     */
//    private Map<String, String> noNeedAuthApiCache;
//
//    /**
//     * 无需授权api缓存
//     */
//    private Map<String, String> needAuthorizationApiCache;
//
//    /**
//     * 无需认证api缓存
//     */
//    private Map<String, String> needAuthenticationApiCache;
//
//    /**
//     * 包含路径参数的api缓存
//     */
//    private List<String> hasPathVariableApiCache;
//
//    public void init() {
//        List<AuthApi> apis = apiGateway.retrieveApis();
//        noNeedAuthApiCache = collectNoNeedAuthApis(apis);
//        needAuthorizationApiCache = collectNeedAuthorizationApis(apis);
//        needAuthenticationApiCache = collectNeedAuthenticationApis(apis);
//        hasPathVariableApiCache = collectHasPathVariableApis(apis);
//    }
//
//    /**
//     * 过滤不要认证和授权的Api
//     * @param apis 全量Api
//     * @return 返回的是过滤不要认证和授权的Api
//     */
//    private Map<String, String> collectNoNeedAuthApis(List<AuthApi> apis) {
//        return apis.stream()
//                .filter(AuthApi::isNoNeedAuth)
//                .collect(collectMatchApi());
//    }
//
//    /**
//     * 过滤需要认证和授权的Api
//     * @param apis 全量Api
//     * @return 返回的是需要认证和授权的Api
//     */
//    private Map<String, String> collectNeedAuthorizationApis(List<AuthApi> apis) {
//        return apis.stream()
//                .filter(AuthApi::isNeedAuthentication)
//                .collect(collectMatchApi());
//    }
//
//
//    /**
//     * 过滤只需要认证的Api
//     * @param apis 全量Api
//     * @return 返回的是只需要认证的Api
//     */
//    private Map<String, String> collectNeedAuthenticationApis(List<AuthApi> apis) {
//        return apis.stream()
//                .filter(AuthApi::isNeedAuthorization)
//                .collect(collectMatchApi());
//    }
//
//    @NotNull
//    private Collector<AuthApi, ?, Map<String, String>> collectMatchApi() {
//        return Collectors.toMap(api -> ApiCommonUtils.createKey(api.getUri(), api.getMethod()), AuthApi::getUri);
//    }
//
//    private List<String> collectHasPathVariableApis(List<AuthApi> apis) {
//        return apis.stream()
//                .filter(item -> item.getHasPathVariable().equals(true))
//                .map(AuthApi::getUri)
//                .collect(Collectors.toList());
//    }
//
//    public Map<String, String> getNeedAuthorizationApiCache() {
//        return needAuthorizationApiCache;
//    }
//
//    public Map<String, String> getNoNeedAuthApiCache() {
//        return noNeedAuthApiCache;
//    }
//
//    public Map<String, String> getNeedAuthenticationApiCache() {
//        return needAuthenticationApiCache;
//    }
//
//    public List<String> getHasPathVariableApiCache() {
//        return hasPathVariableApiCache;
//    }
//
//    @Override
//    public void afterPropertiesSet() throws Exception {
//        init();
//    }
//
//    public void update() {
//        init();
//    }
//}
