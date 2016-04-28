package org.json.smart4j.plugin.security.exception;

/**
 * 授权异常（当权限无效时抛出）
 * Created by wh on 16/4/28.
 */
public class AuthzException extends RuntimeException{

    public AuthzException() {
        super();
    }

    public AuthzException(String message) {
        super(message);
    }

    public AuthzException(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthzException(Throwable cause) {
        super(cause);
    }
}
