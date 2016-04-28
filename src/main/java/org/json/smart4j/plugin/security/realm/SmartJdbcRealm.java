package org.json.smart4j.plugin.security.realm;

import com.json.smart4j.framework.helper.DatabaseHelper;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.json.smart4j.plugin.security.SecurityConfig;
import org.json.smart4j.plugin.security.password.Md5CredentialsMatcher;

/**
 * 基于 Smart 的 JDBC Realm（需要提供相关 smart.plugin.security.jdbc.* 配置项）
 * Created by wh on 16/4/27.
 */
public class SmartJdbcRealm extends JdbcRealm {
    public SmartJdbcRealm(){
        super.setDataSource(DatabaseHelper.getDataSource());
        super.setAuthenticationQuery(SecurityConfig.getJdbcAuthcQuery());
        super.setUserRolesQuery(SecurityConfig.getJdbcRolesQuery());
        super.setPermissionsQuery(SecurityConfig.getJdbcPermissionsQuery());
        super.setPermissionsLookupEnabled(true);
        super.setCredentialsMatcher(new Md5CredentialsMatcher());
    }
}
