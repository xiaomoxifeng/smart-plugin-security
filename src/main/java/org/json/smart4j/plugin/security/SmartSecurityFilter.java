package org.json.smart4j.plugin.security;

import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.json.smart4j.plugin.security.realm.SmartJdbcRealm;

import java.util.Set;

/**
 * Created by wh on 16/4/27.
 */
public class SmartSecurityFilter extends ShiroFilter {
    @Override
    public void init() throws Exception {
        super.init();
        WebSecurityManager webSecurityManager =super.getSecurityManager();

    }

    /**
     * 设置Realm,可同时支持多个Realm,并按照先后顺序用逗号分隔
     * @param webSecurityManager
     */
    private void setRealm(WebSecurityManager webSecurityManager){

    }
    private void addJdbcRealm(Set<Realm> realms){
        SmartJdbcRealm smartJdbcRealm = new SmartJdbcRealm();
        realms.add(smartJdbcRealm);
    }
    private void addCustomRealm(Set<Realm> realms){
        SmartSecurity smartSecurity = SecurityConfig.getSmartSecurity();
    }
}
