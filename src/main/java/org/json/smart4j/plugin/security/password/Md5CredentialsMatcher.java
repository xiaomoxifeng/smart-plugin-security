package org.json.smart4j.plugin.security.password;

import com.json.smart4j.framework.util.CodecUtil;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

/**
 * MD5密码匹配
 * Created by wh on 16/4/28.
 */
public class Md5CredentialsMatcher implements CredentialsMatcher {
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        //获取从表单提交过来的密码,密文,未被加密
        String submitted = String.valueOf(((UsernamePasswordToken) token).getPassword());
        //获取数据库中存储的密码,已通过MD5加密
        String encrypted = String.valueOf(info.getCredentials());
        return CodecUtil.md5(submitted).equals(encrypted);
    }
}
