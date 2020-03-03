package springsecurityoauth2server.springsecurityoauth2server.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import springsecurityoauth2server.springsecurityoauth2server.common.Result;

/**
 * @author liutf
 * @date 2020-02-28
 */
@FeignClient(value = "sys")
public interface UserFeignService {

    @GetMapping(value = "/system/user/queryByLoginName",
            produces = "application/json;charset=UTF-8", consumes = "application/json;charset=UTF-8")
    @ResponseBody
    Result findUsersByLoginname(@RequestParam(value = "username", required = true) String username);
}
