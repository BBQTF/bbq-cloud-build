package sysservice.sysservice.dto;

/**
 * @author liutf
 * @date 2020-02-28
 */
public class UserDto {

    private String id;
    private String loginName;
    private String userName;
    private String password;
    private String state;
    private String role;

    public String getId() {
        return id;
    }

    public String getLoginName() {
        return loginName;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public String getState() {
        return state;
    }

    public String getRole() {
        return role;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setState(String state) {
        this.state = state;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
