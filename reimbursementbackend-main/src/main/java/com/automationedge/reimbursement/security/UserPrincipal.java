package com.automationedge.reimbursement.security;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserPrincipal implements UserDetails {

  private final String username;
  private final long tenantId;
  private final long userId;

  public UserPrincipal(String username, long userId, long tenantId) {
    this.username = username;
    this.userId = userId;
    this.tenantId = tenantId;
  }

  public long getTenantId() {
    return tenantId;
  }

  public long getUserId() {
      return userId;
  }

  @Override
  public String getPassword() {
    return "";
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return null;
  }


  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
