package org.json.smart4j.plugin.security.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.json.smart4j.plugin.security.SecurityConstant;
import org.json.smart4j.plugin.security.SmartSecurity;
import org.json.smart4j.plugin.security.password.Md5CredentialsMatcher;

import java.util.HashSet;
import java.util.Set;

/**
 * 基于 Smart 的自定义 Realm（需要实现 SmartSecurity 接口）
 * Created by wh on 16/4/27.
 */
public class SmartCustomRealm extends AuthorizingRealm {
    private final SmartSecurity smartSecurity;
    public SmartCustomRealm(SmartSecurity smartSecurity) {
        this.smartSecurity = smartSecurity;
        super.setName(SecurityConstant.REALMS_CUSTOM);
        super.setCredentialsMatcher(new Md5CredentialsMatcher());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        if (principals == null){
            throw new AuthenticationException("parameter principals isnull");
        }
        String username = (String)super.getAvailablePrincipal(principals);
        Set<String> roleNameSet =smartSecurity.getRoleName(username);
        Set<String> permissionNameSet = new HashSet<String>();
        if (roleNameSet!=null &&roleNameSet.size()>0){
            for (String roleName:roleNameSet){
                Set<String> currentPermissionNameSet =smartSecurity.getPermissionNameSet(roleName);
                permissionNameSet.addAll(currentPermissionNameSet);
            }
        }
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.setRoles(roleNameSet);
        authorizationInfo.setStringPermissions(permissionNameSet);
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        if (token == null){
            throw new AuthenticationException("parameter token isnull");
        }
        //通过AuthenticationToken获取从表单提交过来的用户名
        String username=((UsernamePasswordToken)token).getUsername();
        //通过smartSecurity接口根据用户名获取数据库中的存放的密码
        String password  =smartSecurity.getPassword(username);
        //将用户名与密码放入authenticationInfo中,便于后续认证操作
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo();
        authenticationInfo.setPrincipals(new SimplePrincipalCollection(username,super.getName()));
        authenticationInfo.setCredentials(password);
        return authenticationInfo;
    }
}
