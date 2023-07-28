package com.example.security.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@TableName("user")
@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;

    /**
     * 用户UUID
     */
    private String userUuid;

    /**
     * 用户名
     */
    private String username;

    /**
     * 用户密码
     */
    private String password;

    /**
     * 用户邮箱
     */
    private String email;

    /**
     * 电话号码
     */
    private String telephone;

    /**
     * 用户角色
     */
    private String role;

    /**
     * 用户头像
     */
    private String image;

    /**
     * 上次登录IP
     */
    private String lastIp;

    /**
     * 上次登录时间
     */
    private String lastTime;
}
