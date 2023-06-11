package com.ark.center.iam.client.route.command;

import com.ark.component.validator.ValidateGroup;
import lombok.Data;
import org.hibernate.validator.constraints.Range;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.List;

@Data
public class RouteCmd implements Serializable {

    private static final long serialVersionUID = 1L;

    @NotNull(message = "id 不能为空", groups = ValidateGroup.Update.class)
    private Long id;

    @NotBlank(message = "name 不能为空")
    private String name;

    @NotNull(message = "pid 不能为空")
    private Long pid;

    @NotNull(message = "applicationId 不能为空")
    private Long applicationId;

    @NotBlank(message = "code 不能为空")
    private String code;

    @NotNull(message = "status 不能为空")
    @Range(min = 1, max = 2)
    private Integer status;

    private String component;

    private Boolean hideChildren;

    private String path;

    private Integer type;

    private String icon;

    private Integer sequence;

    private List<Element> elements;

    @Data
    public static class Element {
        private String name;
        private Integer type;
    }

}
