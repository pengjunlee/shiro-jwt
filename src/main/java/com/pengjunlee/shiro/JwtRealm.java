package com.pengjunlee.shiro;

import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import com.pengjunlee.domain.UserEntity;
import com.pengjunlee.jwt.JwtToken;

/**
 * JwtRealm 只负责校验 JwtToken
 */
public class JwtRealm extends AuthorizingRealm {

	/**
	 * 限定这个 Realm 只处理我们自定义的 JwtToken
	 */
	@Override
	public boolean supports(AuthenticationToken token) {
		return token instanceof JwtToken;
	}

	/**
	 * 此处的 SimpleAuthenticationInfo 可返回任意值，密码校验时不会用到它
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authcToken)
			throws AuthenticationException {
		JwtToken jwtToken = (JwtToken) authcToken;
		if (jwtToken.getPrincipal() == null) {
			throw new AccountException("JWT token参数异常！");
		}
		// 从 JwtToken 中获取当前用户
		String username = jwtToken.getPrincipal().toString();
		// 查询数据库获取用户信息，此处使用 Map 来模拟数据库
		UserEntity user = ShiroRealm.userMap.get(username);

		// 用户不存在
		if (user == null) {
			throw new UnknownAccountException("用户不存在！");
		}

		// 用户被锁定
		if (user.getLocked()) {
			throw new LockedAccountException("该用户已被锁定,暂时无法登录！");
		}

		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user, username, getName());
		return info;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// 获取当前用户
		UserEntity currentUser = (UserEntity) SecurityUtils.getSubject().getPrincipal();
		// UserEntity currentUser = (UserEntity) principals.getPrimaryPrincipal();
		// 查询数据库，获取用户的角色信息
		Set<String> roles = ShiroRealm.roleMap.get(currentUser.getName());
		// 查询数据库，获取用户的权限信息
		Set<String> perms = ShiroRealm.permMap.get(currentUser.getName());
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.setRoles(roles);
		info.setStringPermissions(perms);
		return info;
	}

}
