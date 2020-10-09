package com.security.Repository;

public interface PasswordEncoder {

    String encode(CharSequence var1);

    boolean matches(CharSequence var1 , String var2);

    default boolean upgradEncoding(String encodedPassword){

        return false;
    }

}
