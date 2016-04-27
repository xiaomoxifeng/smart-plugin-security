package org.json.smart4j.plugin.security;

import java.util.Set;

/**
 * Created by wh on 16/4/20.
 */
public interface SmartSecurity {
    /**
     * 根据用户名获取密码
     * @param username 用户名
     * @return 密码
     */
    String getPassword(String username);

    /**
     * 根据用户名获取角色名集合
     * @param username 用户名
     * @return 角色名集合
     */
    Set<String> getRoleName(String username);

    /**
     * 根据角色名获取权限名集合
     * @param role 角色名
     * @return 权限名集合
     */
    Set<String> getPermissionNameSet(String role);
}
