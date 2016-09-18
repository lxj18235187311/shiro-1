package com.atguigu.shiro.helloworld;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);

    public static void main(String[] args) {
    	System.out.println("1111111111111111111111");
    	System.out.println("0000000000000000000000");
    	System.out.println("update01");
        // The easiest way to create a Shiro SecurityManager with configured
        // realms, users, roles and permissions is to use the simple INI config.
        // We'll do that by using a factory that can ingest a .ini file and
        // return a SecurityManager instance:

        // Use the shiro.ini file at the root of the classpath
        // (file: and url: prefixes load from files and urls respectively):
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();

        // for this simple example quickstart, make the SecurityManager
        // accessible as a JVM singleton.  Most applications wouldn't do this
        // and instead rely on their container configuration or web.xml for
        // webapps.  That is outside the scope of this simple quickstart, so
        // we'll just do the bare minimum so you can continue to get a feel
        // for things.
        SecurityUtils.setSecurityManager(securityManager);

        // Now that a simple Shiro environment is set up, let's see what you can do:

        // get the currently executing user:
        // 获取当前和 Shiro 交互的用户对象. 即获取 Subject 对象.
        // 调用 SecurityUtils.getSubject() 方法来获取. 
        Subject currentUser = SecurityUtils.getSubject();

        // Do some stuff with a Session (no need for a web or EJB container!!!)
        // 测试使用 Session. 
        // 1. 获取 Session 对象. 调用 Subject 的 getSession() 方法来获取
        Session session = currentUser.getSession();
        // 2. 向 Session 中放入属性. 实际上也是键值对. 
        session.setAttribute("someKey", "aValue");
        // 3. 从 Session 中获取指定的属性. 
        String value = (String) session.getAttribute("someKey");
        if (value.equals("aValue")) {
            log.info("--> Retrieved the correct value! [" + value + "]");
        }

        // let's login the current user so we can check against roles and permissions:
        // 检验用户是否已经被认证. 即是否已经登录. 
        if (!currentUser.isAuthenticated()) {
        	// 把用户名和密码封装为一个 UsernamePasswordToken
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
            token.setRememberMe(true);
            try {
            	// 指定登录. 即执行认证. 
                currentUser.login(token);
            } 
            // 若 username 不存在, 则会抛出 UnknownAccountException 异常. 
            catch (UnknownAccountException uae) {
                log.info("--> There is no user with username of " + token.getPrincipal());
                return;
            } 
            // 若 username 存在, 但密码不匹配, 则会抛出 IncorrectCredentialsException 异常.
            catch (IncorrectCredentialsException ice) {
                log.info("--> Password for account " + token.getPrincipal() + " was incorrect!");
                return;
            } 
            // 若账户被锁定, 则会抛出 LockedAccountException
            catch (LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            // 登录时所有异常的父类. 
            catch (AuthenticationException ae) {
                //unexpected condition?  error?
            }
        }

        //say who they are:
        //print their identifying principal (in this case, a username):
        log.info("--> User [" + currentUser.getPrincipal() + "] logged in successfully.");

        //test a role:
        // 测试用户是否具有某一个角色. 
        if (currentUser.hasRole("schwartz")) {
            log.info("--> May the Schwartz be with you!");
        } else {
            log.info("--> Hello, mere mortal.");
            return;
        }

        //test a typed permission (not instance-level)
        // 测试用户是否具有某一个具体的行为
        if (currentUser.isPermitted("lightsaber:weild")) {
            log.info("--> You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        // 验证更加具体的权限. 
        if (currentUser.isPermitted("user:delete:1005")) {
            log.info("--> You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                    "Here are the keys - have fun!");
        } else {
            log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //all done - log out!
        // 登出. 
        currentUser.logout();

        System.exit(0);
    }
}
