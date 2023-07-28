package com.example.security;

import com.example.security.mapper.UserMapper;
import com.example.security.po.User;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

@SpringBootTest
@Slf4j
@RunWith(SpringRunner.class)
public class TestEncoder {
    @Autowired
    private UserMapper userMapper;

    @Test
    public void encoder() {
        String username = "root";
        String password = "admin";
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
        String enPassword = encoder.encode(password);
        System.out.println(enPassword);

        User user = User.builder().userUuid(UUID.randomUUID().toString().replace("-", "")).username(username)
                        .password(enPassword).email("root.gmail").telephone("123123123").role("1")
                        .image("111111111111111111111").lastIp(getIpAddressList().get(0))
                        .lastTime(getNowDate("yyyy-MM-dd HH:mm:ss")).build();

        userMapper.insert(user);
    }

    private String getNowDate(String format) {
        SimpleDateFormat dateFormat = new SimpleDateFormat(format);
        return dateFormat.format(new Date());
    }

    /**
     * 获取本机ip
     */
    private List<String> getIpAddressList() {
        List<String> ipAddressList = new ArrayList<>();

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (networkInterface.isUp() && !networkInterface.isLoopback()) {
                    Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress address = addresses.nextElement();
                        if (address instanceof Inet4Address) {
                            // 获取IPv4地址
                            ipAddressList.add(address.getHostAddress());
                        }
                    }
                }
            }
        } catch (SocketException e) {
            log.error("get ip error", e);
        }

        return ipAddressList;
    }
}
