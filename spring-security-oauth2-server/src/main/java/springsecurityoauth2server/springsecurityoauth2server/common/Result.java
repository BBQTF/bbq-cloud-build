package springsecurityoauth2server.springsecurityoauth2server.common;

import java.io.Serializable;

/**
 * @author liutf
 * @date 2020-02-28
 */
public class Result<T> implements Serializable {
    private static final long serialVersionUID = 2783377098145240357L;
    private Integer code;
    private String message;
    private T data;

    public Result() {
    }

    public Result(Integer code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    public Integer getCode() {
        return this.code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public T getData() {
        return this.data;
    }

    public void setData(T data) {
        this.data = data;
    }

}
