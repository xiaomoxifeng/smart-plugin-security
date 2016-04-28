package org.json.smart4j.plugin.security.aspect;

import com.json.smart4j.framework.annotation.Aspect;
import com.json.smart4j.framework.annotation.Controller;
import com.json.smart4j.framework.proxy.AspectProxy;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.json.smart4j.plugin.security.annotation.*;
import org.json.smart4j.plugin.security.exception.AuthzException;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

/**
 * 授权注解切面
 * Created by wh on 16/4/28.
 */
@Aspect(Controller.class)
public class AuthzAnnotationAspect extends AspectProxy {
    /**
     * 定义一个基于授权功能的注解类数组
     */
    private static final Class[] ANNOTATION_CLASS_ARRAY = {
            Authenticated.class, User.class, Guest.class, HasRoles.class, HasPermissions.class
    };

    @Override
    public void before(Class<?> cls, Method method, Object[] params) throws Throwable {
        Annotation annotation =getAnnotation(cls,method);
        if (annotation !=null){
            Class<?> annotationType =annotation.annotationType();
            if (annotationType.equals(Authenticated.class)) {
                handleAuthenticated();
            } else if (annotationType.equals(User.class)) {
                handleUser();
            } else if (annotationType.equals(Guest.class)) {
                handleGuest();
            } else if (annotationType.equals(HasRoles.class)) {
                handleHasRoles((HasRoles) annotation);
            } else if (annotationType.equals(HasPermissions.class)) {
                handleHasPermissions((HasPermissions) annotation);
            }
        }

    }
    private void handleUser(){
        Subject currentUser = SecurityUtils.getSubject();
        PrincipalCollection principals = currentUser.getPrincipals();
        if (principals ==null || principals.isEmpty()){
            throw new AuthzException("当前用户未登陆");
        }
    }
    private void handleAuthenticated() {
        Subject currentUser = SecurityUtils.getSubject();
        if (!currentUser.isAuthenticated()) {
            throw new AuthzException("当前用户尚未认证");
        }
    }
    private void handleGuest() {
        Subject currentUser = SecurityUtils.getSubject();
        PrincipalCollection principals = currentUser.getPrincipals();
        if (principals != null && !principals.isEmpty()) {
            throw new AuthzException("当前用户不是访客");
        }
    }
    private void handleHasRoles(HasRoles hasRoles) {
        String roleName = hasRoles.value();
        Subject currentUser = SecurityUtils.getSubject();
        if (!currentUser.hasRole(roleName)) {
            throw new AuthzException("当前用户没有指定角色，角色名：" + roleName);
        }
    }

    private void handleHasPermissions(HasPermissions hasPermissions) {
        String permissionName = hasPermissions.value();
        Subject currentUser = SecurityUtils.getSubject();
        if (!currentUser.isPermitted(permissionName)) {
            throw new AuthzException("当前用户没有指定权限，权限名：" + permissionName);
        }
    }


    public Annotation getAnnotation(Class<?> cls, Method method) {
        for (Class<? extends Annotation> annotationClass:ANNOTATION_CLASS_ARRAY){
            if (method.isAnnotationPresent(annotationClass)){
                return method.getAnnotation(annotationClass);
            }
            if (cls.isAnnotationPresent(annotationClass)){
                return cls.getAnnotation(annotationClass);
            }
        }
        return null;
    }
}
