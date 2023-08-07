package com.ark.center.auth.adapter.web;

import com.ark.component.web.base.BaseController;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController extends BaseController {

    public static void main(String[] args) {
        String id = convertToUUID("F1C539DC61424F7A9F2CB3EF9E73C93B");
        System.out.println(id);
    }

    private static String convertToUUID(String uuidStr) {
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append(uuidStr, 0, 8).append("-")
                .append(uuidStr, 8, 12).append("-")
                .append(uuidStr, 12, 16).append("-")
                .append(uuidStr, 16, 20).append("-")
                .append(uuidStr.substring(20));
        return stringBuffer.toString();
    }

    @GetMapping("/admin/test")
//    @PreAuthorize("hasRole('ROLE_S')")
    public String testAdmin() {
        return "testAdmin";
    }

    @GetMapping("/test")
//    @PreAuthorize("hasRole('ROLE_DEV')")
    public Object test() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
