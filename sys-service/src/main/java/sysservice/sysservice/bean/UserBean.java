package sysservice.sysservice.bean;

import sysservice.sysservice.dto.UserDto;

/**
 * @author liutf
 * @date 2020-02-27
 */
public class UserBean {
    private String id;
    private String loginName;
    private String userName;
    private String password;
    private String state;
    private String role;

    public String getId() {
        return id;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public String getLoginName() {
        return loginName;
    }

    public void setId(String id) {
        this.id = id;
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

    public String getState() {
        return state;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public UserDto transToDto(UserBean bean){
        UserDto dto = new UserDto();
        dto.setId(bean.getId());
        dto.setLoginName(bean.getLoginName());
        dto.setPassword(bean.getPassword());
        dto.setRole(bean.getRole());
        dto.setState(bean.getState());
        dto.setUserName(bean.getUserName());
        return dto;
    }
}
